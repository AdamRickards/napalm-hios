"""
SNMP protocol handler for NAPALM HiOS driver.

Uses SNMPv3 (authPriv, MD5/DES) by default — compatible with HiOS factory
defaults where SNMPv1/v2c are disabled. Falls back to SNMPv2c if password
is empty (community-only mode).

Standard MIBs: SNMPv2-MIB, IF-MIB, IP-MIB, BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB.
Hirschmann private MIBs: HM2-DEVMGMT-MIB, HM2-PWRMGMT-MIB, HM2-FAN-MIB,
HM2-DIAGNOSTIC-MIB. Uses raw OID strings — no MIB files needed.
"""

import asyncio
import ipaddress
import re
import logging

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd, set_cmd, bulk_walk_cmd,
    usmHMACMD5AuthProtocol, usmDESPrivProtocol,
)
from pysnmp.proto.rfc1902 import Integer32, Unsigned32, OctetString
from pysnmp.proto.secmod.rfc3414.localkey import hash_passphrase_md5
from pysnmp.entity.config import USM_KEY_TYPE_MASTER
from napalm.base.exceptions import ConnectionException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OID constants — raw numeric strings
# ---------------------------------------------------------------------------

# SNMPv2-MIB  1.3.6.1.2.1.1.*
OID_sysDescr    = '1.3.6.1.2.1.1.1'
OID_sysUpTime   = '1.3.6.1.2.1.1.3'
OID_sysContact  = '1.3.6.1.2.1.1.4'
OID_sysName     = '1.3.6.1.2.1.1.5'
OID_sysLocation = '1.3.6.1.2.1.1.6'

# IF-MIB ifTable  1.3.6.1.2.1.2.2.1.*
OID_ifIndex       = '1.3.6.1.2.1.2.2.1.1'
OID_ifDescr       = '1.3.6.1.2.1.2.2.1.2'
OID_ifMtu         = '1.3.6.1.2.1.2.2.1.4'
OID_ifSpeed       = '1.3.6.1.2.1.2.2.1.5'
OID_ifPhysAddress = '1.3.6.1.2.1.2.2.1.6'
OID_ifAdminStatus = '1.3.6.1.2.1.2.2.1.7'
OID_ifOperStatus  = '1.3.6.1.2.1.2.2.1.8'
OID_ifInDiscards  = '1.3.6.1.2.1.2.2.1.13'
OID_ifInErrors    = '1.3.6.1.2.1.2.2.1.14'
OID_ifOutDiscards = '1.3.6.1.2.1.2.2.1.19'
OID_ifOutErrors   = '1.3.6.1.2.1.2.2.1.20'

# IF-MIB ifXTable  1.3.6.1.2.1.31.1.1.1.*
OID_ifName              = '1.3.6.1.2.1.31.1.1.1.1'
OID_ifHCInOctets        = '1.3.6.1.2.1.31.1.1.1.6'
OID_ifHCInUcastPkts     = '1.3.6.1.2.1.31.1.1.1.7'
OID_ifHCInMulticastPkts = '1.3.6.1.2.1.31.1.1.1.8'
OID_ifHCInBroadcastPkts = '1.3.6.1.2.1.31.1.1.1.9'
OID_ifHCOutOctets       = '1.3.6.1.2.1.31.1.1.1.10'
OID_ifHCOutUcastPkts    = '1.3.6.1.2.1.31.1.1.1.11'
OID_ifHCOutMulticastPkts = '1.3.6.1.2.1.31.1.1.1.12'
OID_ifHCOutBroadcastPkts = '1.3.6.1.2.1.31.1.1.1.13'
OID_ifHighSpeed         = '1.3.6.1.2.1.31.1.1.1.15'
OID_ifAlias             = '1.3.6.1.2.1.31.1.1.1.18'

# IP-MIB ipAddrTable  1.3.6.1.2.1.4.20.1.*
OID_ipAdEntAddr    = '1.3.6.1.2.1.4.20.1.1'
OID_ipAdEntIfIndex = '1.3.6.1.2.1.4.20.1.2'
OID_ipAdEntNetMask = '1.3.6.1.2.1.4.20.1.3'

# IP-MIB ipNetToMediaTable (ARP)  1.3.6.1.2.1.4.22.1.*
OID_ipNetToMediaIfIndex      = '1.3.6.1.2.1.4.22.1.1'
OID_ipNetToMediaPhysAddress  = '1.3.6.1.2.1.4.22.1.2'
OID_ipNetToMediaNetAddress   = '1.3.6.1.2.1.4.22.1.3'
OID_ipNetToMediaType         = '1.3.6.1.2.1.4.22.1.4'

# BRIDGE-MIB  1.3.6.1.2.1.17.1.4.1.2
OID_dot1dBasePortIfIndex = '1.3.6.1.2.1.17.1.4.1.2'

# Q-BRIDGE-MIB FDB  1.3.6.1.2.1.17.7.1.2.2.1.*
OID_dot1qTpFdbPort   = '1.3.6.1.2.1.17.7.1.2.2.1.2'
OID_dot1qTpFdbStatus = '1.3.6.1.2.1.17.7.1.2.2.1.3'

# Q-BRIDGE-MIB VLAN  1.3.6.1.2.1.17.7.1.4.3.1.*
OID_dot1qVlanStaticName        = '1.3.6.1.2.1.17.7.1.4.3.1.1'
OID_dot1qVlanStaticEgressPorts = '1.3.6.1.2.1.17.7.1.4.3.1.2'
OID_dot1qVlanStaticForbiddenEgressPorts = '1.3.6.1.2.1.17.7.1.4.3.1.3'
OID_dot1qVlanStaticUntaggedPorts = '1.3.6.1.2.1.17.7.1.4.3.1.4'
OID_dot1qVlanStaticRowStatus = '1.3.6.1.2.1.17.7.1.4.3.1.5'

# Q-BRIDGE-MIB port VLAN  1.3.6.1.2.1.17.7.1.4.5.1.*
OID_dot1qPvid = '1.3.6.1.2.1.17.7.1.4.5.1.1'
OID_dot1qPortAcceptableFrameTypes = '1.3.6.1.2.1.17.7.1.4.5.1.2'
OID_dot1qPortIngressFiltering = '1.3.6.1.2.1.17.7.1.4.5.1.3'

# LLDP-MIB remote table  1.0.8802.1.1.2.1.4.1.1.*
OID_lldpRemChassisIdSubtype = '1.0.8802.1.1.2.1.4.1.1.4'
OID_lldpRemChassisId        = '1.0.8802.1.1.2.1.4.1.1.5'
OID_lldpRemPortIdSubtype    = '1.0.8802.1.1.2.1.4.1.1.6'
OID_lldpRemPortId           = '1.0.8802.1.1.2.1.4.1.1.7'
OID_lldpRemPortDesc         = '1.0.8802.1.1.2.1.4.1.1.8'
OID_lldpRemSysName          = '1.0.8802.1.1.2.1.4.1.1.9'
OID_lldpRemSysDesc          = '1.0.8802.1.1.2.1.4.1.1.10'
OID_lldpRemSysCapSupported  = '1.0.8802.1.1.2.1.4.1.1.11'
OID_lldpRemSysCapEnabled    = '1.0.8802.1.1.2.1.4.1.1.12'

# LLDP-MIB local port  1.0.8802.1.1.2.1.3.7.1.3
OID_lldpLocPortId = '1.0.8802.1.1.2.1.3.7.1.3'

# LLDP-MIB management address — walk column 3 (ifSubtype) to get suffixes
# without the column number prefix: timeMark.localPort.remIndex.addrSubtype.addrLen.addr...
OID_lldpRemManAddrIfSubtype = '1.0.8802.1.1.2.1.4.2.1.3'

# LLDP capability bit positions (from MSB of first octet)
LLDP_CAPABILITIES = [
    'other',            # bit 0
    'repeater',         # bit 1
    'bridge',           # bit 2
    'wlan-access-point', # bit 3
    'router',           # bit 4
    'telephone',        # bit 5
    'docsis-cable-device', # bit 6
    'station',          # bit 7
]

# ---------------------------------------------------------------------------
# Hirschmann private MIB OIDs (HM2-*)
# ---------------------------------------------------------------------------

# HM2-DEVMGMT-MIB — device identity (scalars, append .0)
OID_hm2ProductDescr  = '1.3.6.1.4.1.248.11.10.1.1.2'
OID_hm2SerialNumber  = '1.3.6.1.4.1.248.11.10.1.1.3'

# HM2-DEVMGMT-MIB — firmware version (table row: ram.firmware.1 = 1.1.1)
# These are already fully qualified with the table index — do NOT append .0
OID_hm2FwVersionRAM  = '1.3.6.1.4.1.248.11.10.1.3.1.10.1.5.1.1.1'

# HM2-DEVMGMT-MIB — temperature
OID_hm2Temperature      = '1.3.6.1.4.1.248.11.10.1.5.1'
OID_hm2TempUpperLimit    = '1.3.6.1.4.1.248.11.10.1.5.2'
OID_hm2TempLowerLimit    = '1.3.6.1.4.1.248.11.10.1.5.3'

# HM2-PWRMGMT-MIB — power supply state (table, walk)
OID_hm2PSState = '1.3.6.1.4.1.248.11.11.1.1.1.1.2'
# Values: present(1), defective(2), notInstalled(3), unknown(4)

# HM2-FAN-MIB — fan status (table, walk)
OID_hm2FanModuleStatus = '1.3.6.1.4.1.248.11.13.1.1.2.1.2'
OID_hm2FanStatus       = '1.3.6.1.4.1.248.11.13.1.1.3.1.2'
# Values: not-available(1), available-and-ok(2), available-but-failure(3)

# HM2-DIAGNOSTIC-MIB — CPU and memory
OID_hm2CpuUtil    = '1.3.6.1.4.1.248.11.22.1.8.10.1'
OID_hm2MemAlloc   = '1.3.6.1.4.1.248.11.22.1.8.11.1'
OID_hm2MemFree    = '1.3.6.1.4.1.248.11.22.1.8.11.2'

# HM2-DEVMGMT-MIB — SFP diagnostics (hm2SfpDiagTable)
OID_hm2SfpDiagTxPower = '1.3.6.1.4.1.248.11.10.1.7.2.1.5'
OID_hm2SfpDiagRxPower = '1.3.6.1.4.1.248.11.10.1.7.2.1.6'

# HM2-USERMGMT-MIB — user config table  1.3.6.1.4.1.248.11.24.1.1.1.1.*
OID_hm2UserAccessRole = '1.3.6.1.4.1.248.11.24.1.1.1.1.3'
OID_hm2UserStatus     = '1.3.6.1.4.1.248.11.24.1.1.1.1.9'

# HM2-L2REDUNDANCY-MIB — MRP  1.3.6.1.4.1.248.11.40.1.1.*
OID_hm2MrpDomainName          = '1.3.6.1.4.1.248.11.40.1.1.1.1.2'
OID_hm2MrpRingport1IfIndex    = '1.3.6.1.4.1.248.11.40.1.1.1.1.4'
OID_hm2MrpRingport1OperState  = '1.3.6.1.4.1.248.11.40.1.1.1.1.5'
OID_hm2MrpRingport2IfIndex    = '1.3.6.1.4.1.248.11.40.1.1.1.1.7'
OID_hm2MrpRingport2OperState  = '1.3.6.1.4.1.248.11.40.1.1.1.1.8'
OID_hm2MrpRoleAdminState      = '1.3.6.1.4.1.248.11.40.1.1.1.1.9'
OID_hm2MrpRoleOperState       = '1.3.6.1.4.1.248.11.40.1.1.1.1.10'
OID_hm2MrpRecoveryDelay       = '1.3.6.1.4.1.248.11.40.1.1.1.1.11'
OID_hm2MrpVlanID              = '1.3.6.1.4.1.248.11.40.1.1.1.1.13'
OID_hm2MrpMRMPriority         = '1.3.6.1.4.1.248.11.40.1.1.1.1.14'
OID_hm2MrpMRMReactOnLinkChange = '1.3.6.1.4.1.248.11.40.1.1.1.1.15'
OID_hm2MrpMRMRingOpenCount    = '1.3.6.1.4.1.248.11.40.1.1.1.1.16'
OID_hm2MrpMRCBlockedSupported = '1.3.6.1.4.1.248.11.40.1.1.1.1.22'
OID_hm2MrpRingOperState       = '1.3.6.1.4.1.248.11.40.1.1.1.1.23'
OID_hm2MrpRedundancyOperState = '1.3.6.1.4.1.248.11.40.1.1.1.1.24'
OID_hm2MrpConfigOperState     = '1.3.6.1.4.1.248.11.40.1.1.1.1.25'
OID_hm2MrpRowStatus           = '1.3.6.1.4.1.248.11.40.1.1.1.1.26'
OID_hm2MrpRingport2FixedBackup = '1.3.6.1.4.1.248.11.40.1.1.1.1.27'
OID_hm2MrpRecoveryDelaySupported = '1.3.6.1.4.1.248.11.40.1.1.1.1.12'
OID_hm2MrpFastMrp             = '1.3.6.1.4.1.248.11.40.1.1.3'

# HM2-L2REDUNDANCY-MIB — SRM (Sub-Ring Manager)  1.3.6.1.4.1.248.11.40.1.4.*
OID_hm2SrmGlobalAdminState     = '1.3.6.1.4.1.248.11.40.1.4.1'
OID_hm2SrmMaxInstances         = '1.3.6.1.4.1.248.11.40.1.4.2'
OID_hm2SrmAdminState           = '1.3.6.1.4.1.248.11.40.1.4.3.1.2'
OID_hm2SrmOperState            = '1.3.6.1.4.1.248.11.40.1.4.3.1.3'
OID_hm2SrmVlanID               = '1.3.6.1.4.1.248.11.40.1.4.3.1.4'
OID_hm2SrmMRPDomainID          = '1.3.6.1.4.1.248.11.40.1.4.3.1.5'
OID_hm2SrmPartnerMAC           = '1.3.6.1.4.1.248.11.40.1.4.3.1.6'
OID_hm2SrmSubRingProtocol      = '1.3.6.1.4.1.248.11.40.1.4.3.1.7'
OID_hm2SrmSubRingName          = '1.3.6.1.4.1.248.11.40.1.4.3.1.8'
OID_hm2SrmSubRingPortIfIndex   = '1.3.6.1.4.1.248.11.40.1.4.3.1.9'
OID_hm2SrmSubRingPortOperState = '1.3.6.1.4.1.248.11.40.1.4.3.1.10'
OID_hm2SrmSubRingOperState     = '1.3.6.1.4.1.248.11.40.1.4.3.1.11'
OID_hm2SrmRedundancyOperState  = '1.3.6.1.4.1.248.11.40.1.4.3.1.12'
OID_hm2SrmConfigOperState      = '1.3.6.1.4.1.248.11.40.1.4.3.1.13'
OID_hm2SrmRowStatus            = '1.3.6.1.4.1.248.11.40.1.4.3.1.20'

# HM2-DEVMGMT-MIB — Auto-Disable  1.3.6.1.4.1.248.11.10.1.9.*
OID_hm2AutoDisableIntfTimer         = '1.3.6.1.4.1.248.11.10.1.9.1.1.4'
OID_hm2AutoDisableIntfRemainingTime = '1.3.6.1.4.1.248.11.10.1.9.1.1.1'
OID_hm2AutoDisableIntfComponentName = '1.3.6.1.4.1.248.11.10.1.9.1.1.2'
OID_hm2AutoDisableIntfErrorReason   = '1.3.6.1.4.1.248.11.10.1.9.1.1.3'
OID_hm2AutoDisableIntfReset         = '1.3.6.1.4.1.248.11.10.1.9.1.1.5'
OID_hm2AutoDisableIntfOperState     = '1.3.6.1.4.1.248.11.10.1.9.1.1.6'
OID_hm2AutoDisableIntfErrorTime     = '1.3.6.1.4.1.248.11.10.1.9.1.1.7'
OID_hm2AutoDisableReasonOperation   = '1.3.6.1.4.1.248.11.10.1.9.2.1.2'
OID_hm2AutoDisableReasonCategory    = '1.3.6.1.4.1.248.11.10.1.9.2.1.3'

# HM2-PLATFORM-SWITCHING-MIB — Loop Protection (Keepalive)  1.3.6.1.4.1.248.12.1.2.*
OID_hm2KeepaliveState              = '1.3.6.1.4.1.248.12.1.2.8.43.1'
OID_hm2KeepaliveTransmitInterval   = '1.3.6.1.4.1.248.12.1.2.8.43.2'
OID_hm2KeepaliveRxThreshold        = '1.3.6.1.4.1.248.12.1.2.8.43.248'
OID_hm2KeepalivePortState          = '1.3.6.1.4.1.248.12.1.2.31.1.1'
OID_hm2KeepalivePortLoopDetected   = '1.3.6.1.4.1.248.12.1.2.31.1.2'
OID_hm2KeepalivePortLoopCount      = '1.3.6.1.4.1.248.12.1.2.31.1.3'
OID_hm2KeepalivePortRxAction       = '1.3.6.1.4.1.248.12.1.2.31.1.5'
OID_hm2KeepalivePortLastLoopTime   = '1.3.6.1.4.1.248.12.1.2.31.1.7'
OID_hm2KeepalivePortTpidType       = '1.3.6.1.4.1.248.12.1.2.31.1.8'
OID_hm2KeepalivePortVlanId         = '1.3.6.1.4.1.248.12.1.2.31.1.9'
OID_hm2KeepalivePortMode           = '1.3.6.1.4.1.248.12.1.2.31.1.248'
OID_hm2KeepalivePortTxFrames       = '1.3.6.1.4.1.248.12.1.2.31.1.249'
OID_hm2KeepalivePortRxFrames       = '1.3.6.1.4.1.248.12.1.2.31.1.250'
OID_hm2KeepalivePortDiscardFrames  = '1.3.6.1.4.1.248.12.1.2.31.1.251'

# HM2-TRAFFICMGMT-MIB — Storm Control  1.3.6.1.4.1.248.11.31.1.*
# hm2TrafficMgmtIfEntry (indexed by ifIndex)  .1.1.1.{col}.{ifIndex}
OID_hm2StormCtlThresholdUnit  = '1.3.6.1.4.1.248.11.31.1.1.1.4'
OID_hm2StormCtlBcastMode      = '1.3.6.1.4.1.248.11.31.1.1.1.5'
OID_hm2StormCtlBcastThreshold = '1.3.6.1.4.1.248.11.31.1.1.1.6'
OID_hm2StormCtlMcastMode      = '1.3.6.1.4.1.248.11.31.1.1.1.7'
OID_hm2StormCtlMcastThreshold = '1.3.6.1.4.1.248.11.31.1.1.1.8'
OID_hm2StormCtlUcastMode      = '1.3.6.1.4.1.248.11.31.1.1.1.9'
OID_hm2StormCtlUcastThreshold = '1.3.6.1.4.1.248.11.31.1.1.1.10'
# Global scalar
OID_hm2StormBucketType         = '1.3.6.1.4.1.248.11.31.1.3'

# SFLOW-MIB (RFC 3176)  1.3.6.1.4.1.14706.1.1.* (sFlowMIB.sFlowAgent)
# Agent scalars
OID_sFlowVersion          = '1.3.6.1.4.1.14706.1.1.1'
OID_sFlowAgentAddressType = '1.3.6.1.4.1.14706.1.1.2'
OID_sFlowAgentAddress     = '1.3.6.1.4.1.14706.1.1.3'
# Receiver table  .1.4.1.{col}.{rcvr_index}
OID_sFlowRcvrOwner        = '1.3.6.1.4.1.14706.1.1.4.1.2'
OID_sFlowRcvrTimeout      = '1.3.6.1.4.1.14706.1.1.4.1.3'
OID_sFlowRcvrMaxDgramSize = '1.3.6.1.4.1.14706.1.1.4.1.4'
OID_sFlowRcvrAddressType  = '1.3.6.1.4.1.14706.1.1.4.1.5'
OID_sFlowRcvrAddress      = '1.3.6.1.4.1.14706.1.1.4.1.6'
OID_sFlowRcvrPort         = '1.3.6.1.4.1.14706.1.1.4.1.7'
OID_sFlowRcvrDgramVersion = '1.3.6.1.4.1.14706.1.1.4.1.8'
# Flow sampler table  .1.5.1.{col}.{ds_suffix}
OID_sFlowFsReceiver       = '1.3.6.1.4.1.14706.1.1.5.1.3'
OID_sFlowFsPacketRate     = '1.3.6.1.4.1.14706.1.1.5.1.4'
OID_sFlowFsMaxHeaderSize  = '1.3.6.1.4.1.14706.1.1.5.1.5'
# Counter poller table  .1.6.1.{col}.{ds_suffix}
OID_sFlowCpReceiver       = '1.3.6.1.4.1.14706.1.1.6.1.3'
OID_sFlowCpInterval       = '1.3.6.1.4.1.14706.1.1.6.1.4'

# HM2-PLATFORM-QOS-COS-MIB — QoS  1.3.6.1.4.1.248.12.3.3.*
# Trust mode (indexed by ifIndex)
OID_hm2CosMapIntfTrustMode  = '1.3.6.1.4.1.248.12.3.3.1.3.1.2'
# Queue scalars
OID_hm2CosQueueNumQueuesPerPort = '1.3.6.1.4.1.248.12.3.3.2.1'
# Queue control (indexed by ifIndex)
OID_hm2CosQueueIntfShapingRate  = '1.3.6.1.4.1.248.12.3.3.2.3.1.2'
# Queue table (indexed by ifIndex.queueIndex)
OID_hm2CosQueueSchedulerType   = '1.3.6.1.4.1.248.12.3.3.2.4.1.2'
OID_hm2CosQueueMinBandwidth    = '1.3.6.1.4.1.248.12.3.3.2.4.1.3'
OID_hm2CosQueueMaxBandwidth    = '1.3.6.1.4.1.248.12.3.3.2.4.1.4'

# P-BRIDGE-MIB — Port default priority (indexed by dot1dBasePort)
OID_dot1dPortDefaultUserPriority = '1.3.6.1.2.1.17.6.1.3.1.1'

# HM2-L2FORWARDING-MIB — Traffic Class Mapping  1.3.6.1.4.1.248.11.30.1.2.*
# dot1p → TC (indexed by priority 0-7)
OID_hm2TrafficClass             = '1.3.6.1.4.1.248.11.30.1.2.1.1.2'
# DSCP → TC (indexed by dscp value 0-63)
OID_hm2CosMapIpDscpTrafficClass = '1.3.6.1.4.1.248.11.30.1.2.2.1.2'

# HM2-NETCONFIG-MIB — Management Network  1.3.6.1.4.1.248.11.20.1.1.*
OID_hm2NetConfigProtocol     = '1.3.6.1.4.1.248.11.20.1.1.1'
OID_hm2NetLocalIPAddr        = '1.3.6.1.4.1.248.11.20.1.1.3'
OID_hm2NetPrefixLength       = '1.3.6.1.4.1.248.11.20.1.1.4'
OID_hm2NetGatewayIPAddr      = '1.3.6.1.4.1.248.11.20.1.1.6'
OID_hm2NetVlanID             = '1.3.6.1.4.1.248.11.20.1.1.7'
OID_hm2NetVlanPriority       = '1.3.6.1.4.1.248.11.20.1.1.8'
OID_hm2NetIpDscpPriority     = '1.3.6.1.4.1.248.11.20.1.1.9'
OID_hm2NetMgmtPort           = '1.3.6.1.4.1.248.11.20.1.1.10'
OID_hm2NetDHCPClientId       = '1.3.6.1.4.1.248.11.20.1.1.11'
OID_hm2NetDHCPClientConfigLoad = '1.3.6.1.4.1.248.11.20.1.1.20'
OID_hm2NetDHCPClientLeaseTime = '1.3.6.1.4.1.248.11.20.1.1.21'
OID_hm2NetIPv6AdminStatus    = '1.3.6.1.4.1.248.11.20.1.1.30'
OID_hm2NetIPv6ConfigProtocol = '1.3.6.1.4.1.248.11.20.1.1.31'
OID_hm2NetAction             = '1.3.6.1.4.1.248.11.20.1.1.50'

# HM2-PLATFORM-SWITCHING-MIB — STP/RSTP  1.3.6.1.4.1.248.12.1.2.15.*
# Global config (hm2AgentStpSwitchConfigGroup)
OID_hm2AgentStpForceVersion       = '1.3.6.1.4.1.248.12.1.2.15.5'
OID_hm2AgentStpAdminMode          = '1.3.6.1.4.1.248.12.1.2.15.6'
OID_hm2AgentStpBpduGuardMode      = '1.3.6.1.4.1.248.12.1.2.15.13'
OID_hm2AgentStpBpduFilterDefault  = '1.3.6.1.4.1.248.12.1.2.15.14'
# CST config (hm2AgentStpCstConfigGroup)
OID_hm2AgentStpCstHelloTime         = '1.3.6.1.4.1.248.12.1.2.15.8.1'
OID_hm2AgentStpCstMaxAge            = '1.3.6.1.4.1.248.12.1.2.15.8.2'
OID_hm2AgentStpCstRootFwdDelay      = '1.3.6.1.4.1.248.12.1.2.15.8.5'
OID_hm2AgentStpCstBridgeFwdDelay    = '1.3.6.1.4.1.248.12.1.2.15.8.6'
OID_hm2AgentStpCstBridgeHelloTime   = '1.3.6.1.4.1.248.12.1.2.15.8.7'
OID_hm2AgentStpCstBridgeMaxAge      = '1.3.6.1.4.1.248.12.1.2.15.8.9'
OID_hm2AgentStpCstBridgeMaxHops     = '1.3.6.1.4.1.248.12.1.2.15.8.10'
OID_hm2AgentStpCstBridgePriority    = '1.3.6.1.4.1.248.12.1.2.15.8.11'
OID_hm2AgentStpCstBridgeHoldCount   = '1.3.6.1.4.1.248.12.1.2.15.8.12'
# MST entry (hm2AgentStpMstEntry) — instance 0 = CIST
OID_hm2AgentStpMstBridgeIdentifier  = '1.3.6.1.4.1.248.12.1.2.15.10.1.3'
OID_hm2AgentStpMstDesignatedRootId  = '1.3.6.1.4.1.248.12.1.2.15.10.1.4'
OID_hm2AgentStpMstRootPathCost      = '1.3.6.1.4.1.248.12.1.2.15.10.1.5'
OID_hm2AgentStpMstRootPortId        = '1.3.6.1.4.1.248.12.1.2.15.10.1.6'
OID_hm2AgentStpMstTimeSinceTopologyChange = '1.3.6.1.4.1.248.12.1.2.15.10.1.7'
OID_hm2AgentStpMstTopologyChangeCount     = '1.3.6.1.4.1.248.12.1.2.15.10.1.8'
# Port entry (hm2AgentStpPortEntry)
OID_hm2AgentStpPortState           = '1.3.6.1.4.1.248.12.1.2.15.7.1.1'
OID_hm2AgentStpPortStatsRstpBpduRx = '1.3.6.1.4.1.248.12.1.2.15.7.1.4'
OID_hm2AgentStpPortStatsRstpBpduTx = '1.3.6.1.4.1.248.12.1.2.15.7.1.5'
OID_hm2AgentStpPortStatsStpBpduRx  = '1.3.6.1.4.1.248.12.1.2.15.7.1.6'
OID_hm2AgentStpPortStatsStpBpduTx  = '1.3.6.1.4.1.248.12.1.2.15.7.1.7'
# CST port entry (hm2AgentStpCstPortEntry)
OID_hm2AgentStpCstPortOperEdge         = '1.3.6.1.4.1.248.12.1.2.15.9.1.1'
OID_hm2AgentStpCstPortOperPointToPoint = '1.3.6.1.4.1.248.12.1.2.15.9.1.2'
OID_hm2AgentStpCstPortEdge             = '1.3.6.1.4.1.248.12.1.2.15.9.1.4'
OID_hm2AgentStpCstPortForwardingState  = '1.3.6.1.4.1.248.12.1.2.15.9.1.5'
OID_hm2AgentStpCstPortPathCost         = '1.3.6.1.4.1.248.12.1.2.15.9.1.7'
OID_hm2AgentStpCstPortPriority         = '1.3.6.1.4.1.248.12.1.2.15.9.1.8'
OID_hm2AgentStpCstPortBpduGuardEffect  = '1.3.6.1.4.1.248.12.1.2.15.9.1.13'
OID_hm2AgentStpCstPortBpduFilter       = '1.3.6.1.4.1.248.12.1.2.15.9.1.14'
OID_hm2AgentStpCstPortBpduFlood        = '1.3.6.1.4.1.248.12.1.2.15.9.1.15'
OID_hm2AgentStpCstPortAutoEdge         = '1.3.6.1.4.1.248.12.1.2.15.9.1.16'
OID_hm2AgentStpCstPortRootGuard        = '1.3.6.1.4.1.248.12.1.2.15.9.1.17'
OID_hm2AgentStpCstPortTCNGuard         = '1.3.6.1.4.1.248.12.1.2.15.9.1.18'
OID_hm2AgentStpCstPortLoopGuard        = '1.3.6.1.4.1.248.12.1.2.15.9.1.19'

# HIRSCHMANN-DISCOVERY-MGMT-MIB  1.3.6.1.4.1.248.16.100.*
# HM2-NETCONFIG-MIB hm2NetHiDiscoveryGroup  1.3.6.1.4.1.248.11.20.1.4.*
OID_hm2HiDiscOper     = '1.3.6.1.4.1.248.11.20.1.4.1'   # HmEnabledStatus
OID_hm2HiDiscMode     = '1.3.6.1.4.1.248.11.20.1.4.2'   # 1=readWrite, 2=readOnly
OID_hm2HiDiscBlinking = '1.3.6.1.4.1.248.11.20.1.4.3'   # HmEnabledStatus
OID_hm2HiDiscProtocol = '1.3.6.1.4.1.248.11.20.1.4.4'   # BITS {none(0),v1(1),v2(2)}
OID_hm2HiDiscRelay    = '1.3.6.1.4.1.248.11.20.1.4.5'   # HmEnabledStatus

# HM2-FILEMGMT-MIB — config status + save action  1.3.6.1.4.1.248.11.21.*
OID_hm2FMNvmState       = '1.3.6.1.4.1.248.11.21.1.3.1'
OID_hm2FMEnvmState      = '1.3.6.1.4.1.248.11.21.1.3.2'
OID_hm2FMBootParamState  = '1.3.6.1.4.1.248.11.21.1.3.3'
OID_hm2FMActionActivateKey = '1.3.6.1.4.1.248.11.21.1.2.18'
OID_hm2FMActionParameter   = '1.3.6.1.4.1.248.11.21.1.2.20'
# Table entry: copy(2).config(10).runningConfig(10).nvm(2) — fully indexed, >=14 parts
OID_hm2FMActionActivate_save         = '1.3.6.1.4.1.248.11.21.1.2.1.1.5.2.10.10.2'
# clear(3).config(10).runningConfig(10).runningConfig(10) — clear running config
OID_hm2FMActionActivate_clear_config = '1.3.6.1.4.1.248.11.21.1.2.1.1.5.3.10.10.10'
# clear(3).config(10).nvm(2).nvm(2) — factory reset
OID_hm2FMActionActivate_clear_factory = '1.3.6.1.4.1.248.11.21.1.2.1.1.5.3.10.2.2'

# HM2-FILEMGMT-MIB — profile table  1.3.6.1.4.1.248.11.21.1.1.1.1.*
# Indexed by (storageType, profileIndex): nvm=1, envm=2
OID_hm2FMProfileStorageType      = '1.3.6.1.4.1.248.11.21.1.1.1.1.1'
OID_hm2FMProfileIndex            = '1.3.6.1.4.1.248.11.21.1.1.1.1.2'
OID_hm2FMProfileName             = '1.3.6.1.4.1.248.11.21.1.1.1.1.3'
OID_hm2FMProfileDateTime         = '1.3.6.1.4.1.248.11.21.1.1.1.1.4'
OID_hm2FMProfileActive           = '1.3.6.1.4.1.248.11.21.1.1.1.1.5'
OID_hm2FMProfileAction           = '1.3.6.1.4.1.248.11.21.1.1.1.1.6'
OID_hm2FMProfileEncryptionActive = '1.3.6.1.4.1.248.11.21.1.1.1.1.8'
OID_hm2FMProfileEncryptionVerified = '1.3.6.1.4.1.248.11.21.1.1.1.1.9'
OID_hm2FMProfileSwMajorRelNum    = '1.3.6.1.4.1.248.11.21.1.1.1.1.10'
OID_hm2FMProfileSwMinorRelNum    = '1.3.6.1.4.1.248.11.21.1.1.1.1.11'
OID_hm2FMProfileSwBugfixRelNum   = '1.3.6.1.4.1.248.11.21.1.1.1.1.12'
OID_hm2FMProfileFingerprint      = '1.3.6.1.4.1.248.11.21.1.1.1.1.13'
OID_hm2FMProfileFingerprintVerified = '1.3.6.1.4.1.248.11.21.1.1.1.1.14'

# HM2-FILEMGMT-MIB — config watchdog  1.3.6.1.4.1.248.11.21.1.4.1.*
OID_hm2ConfigWatchdogAdminStatus  = '1.3.6.1.4.1.248.11.21.1.4.1.1'
OID_hm2ConfigWatchdogOperStatus   = '1.3.6.1.4.1.248.11.21.1.4.1.2'
OID_hm2ConfigWatchdogTimeInterval = '1.3.6.1.4.1.248.11.21.1.4.1.3'
OID_hm2ConfigWatchdogTimerValue   = '1.3.6.1.4.1.248.11.21.1.4.1.4'

# HM2-TIMESYNC-MIB — SNTP client  1.3.6.1.4.1.248.11.50.1.2.3.*
OID_hm2SntpRequestInterval = '1.3.6.1.4.1.248.11.50.1.2.3.4'
OID_hm2SntpClientStatus    = '1.3.6.1.4.1.248.11.50.1.2.3.5'
OID_hm2SntpServerAddr      = '1.3.6.1.4.1.248.11.50.1.2.3.10.1.3'
OID_hm2SntpServerStatus    = '1.3.6.1.4.1.248.11.50.1.2.3.10.1.6'

# LLDP-EXT-DOT3-MIB  1.0.8802.1.1.2.1.5.4623.1.*
OID_lldpXdot3RemPortAutoNegSupported = '1.0.8802.1.1.2.1.5.4623.1.3.1.1.1'
OID_lldpXdot3RemPortAutoNegEnabled   = '1.0.8802.1.1.2.1.5.4623.1.3.1.1.2'
OID_lldpXdot3RemPortOperMauType      = '1.0.8802.1.1.2.1.5.4623.1.3.1.1.4'
OID_lldpXdot3RemLinkAggStatus        = '1.0.8802.1.1.2.1.5.4623.1.3.3.1.1'
OID_lldpXdot3RemLinkAggPortId        = '1.0.8802.1.1.2.1.5.4623.1.3.3.1.2'

# LLDP-EXT-DOT1-MIB  1.0.8802.1.1.2.1.5.32962.1.*
OID_lldpXdot1RemPortVlanId = '1.0.8802.1.1.2.1.5.32962.1.3.1.1.1'
OID_lldpXdot1RemVlanId     = '1.0.8802.1.1.2.1.5.32962.1.3.3.1.1'


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _format_mac(raw):
    """Format raw MAC bytes to xx:xx:xx:xx:xx:xx string.

    Handles pysnmp OctetString, raw bytes, and hex strings.
    """
    # Convert pysnmp OctetString to bytes
    if hasattr(raw, 'hasValue'):
        if not raw.hasValue():
            return ''
        raw = bytes(raw)
    if isinstance(raw, bytes):
        if len(raw) == 0:
            return ''
        return ':'.join(f'{b:02x}' for b in raw)
    # Handle hex string from prettyPrint like '0x001b1e...'
    s = str(raw)
    if s.startswith('0x'):
        s = s[2:]
        if len(s) == 12:
            return ':'.join(s[i:i+2] for i in range(0, 12, 2))
    # Already formatted or empty
    return s


def _mask_to_prefix(mask_str):
    """Convert dotted subnet mask to prefix length. e.g. '255.255.255.0' -> 24."""
    try:
        parts = [int(p) for p in mask_str.split('.')]
        bits = ''.join(f'{p:08b}' for p in parts)
        return bits.count('1')
    except (ValueError, AttributeError):
        return 32


def _prefix_to_mask(prefix):
    """Convert prefix length to dotted subnet mask. 24 -> '255.255.255.0'"""
    prefix = int(prefix)
    if prefix < 0 or prefix > 32:
        return '0.0.0.0'
    bits = ('1' * prefix).ljust(32, '0')
    return '.'.join(str(int(bits[i:i+8], 2)) for i in range(0, 32, 8))


def _parse_sysDescr(text):
    """Parse sysDescr to extract model and os_version.

    Expected format: 'Hirschmann GRS1042 HiOS-3A-09.4.04 ...'
    Returns (model, os_version) or ('Unknown', 'Unknown').
    """
    parts = str(text).split()
    if len(parts) >= 3 and parts[0].lower() == 'hirschmann':
        return parts[1], parts[2]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return 'Unknown', 'Unknown'


def _snmp_str(val):
    """Convert an SNMP value to a clean string.

    Uses prettyPrint() for types like IpAddress that render as raw bytes
    via str(), falls back to str() for simple types.
    """
    if hasattr(val, 'prettyPrint'):
        return val.prettyPrint()
    return str(val)


def _parse_fw_version(text):
    """Extract clean firmware version from hm2DevMgmtSwVersion.

    Input like 'HiOS-2A-10.3.04 2025-12-08 16:54'.
    Returns 'HiOS-2A-10.3.04' (first token).
    """
    s = str(text).strip()
    if ' ' in s:
        return s.split()[0]
    return s


def _decode_capabilities(raw):
    """Decode LLDP capability bitmap to list of capability names."""
    caps = []
    # Convert pysnmp OctetString to bytes
    if hasattr(raw, 'hasValue'):
        if not raw.hasValue():
            return caps
        octets = bytes(raw)
    elif isinstance(raw, bytes):
        octets = raw
    else:
        s = str(raw)
        if s.startswith('0x'):
            try:
                octets = bytes.fromhex(s[2:])
            except ValueError:
                return caps
        else:
            return caps

    if not octets:
        return caps

    # Capabilities are in the first two octets as a 16-bit field
    # but only 8 capabilities defined; first octet is sufficient
    byte0 = octets[0]
    for i, name in enumerate(LLDP_CAPABILITIES):
        if byte0 & (0x80 >> i):
            caps.append(name)
    return caps


def _decode_portlist(octets, bridge_port_to_name):
    """Decode Q-BRIDGE PortList bitmap to interface names.

    Each bit in the octet string represents a bridge port number (1-based,
    MSB of first octet = port 1).
    """
    interfaces = []
    if isinstance(octets, str):
        if octets.startswith('0x'):
            try:
                octets = bytes.fromhex(octets[2:])
            except ValueError:
                return interfaces
        else:
            try:
                octets = octets.encode('latin-1')
            except (UnicodeDecodeError, AttributeError):
                return interfaces

    for byte_idx, byte_val in enumerate(octets):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                port_num = byte_idx * 8 + bit_idx + 1
                name = bridge_port_to_name.get(str(port_num), f'port{port_num}')
                interfaces.append(name)
    return interfaces


def _encode_portlist(interfaces, name_to_bp, total_ports=None):
    """Encode interface names to Q-BRIDGE PortList bitmap (bytes).

    Reverse of _decode_portlist(). Each bit = bridge port number (1-based,
    MSB of first octet = port 1).
    """
    # Determine bitmap size
    bp_nums = []
    for iface in interfaces:
        bp = name_to_bp.get(iface)
        if bp is None:
            raise ValueError(f"Unknown interface '{iface}'")
        bp_nums.append(int(bp))
    max_port = total_ports or (max(bp_nums) if bp_nums else 0)
    num_bytes = (max_port + 7) // 8 if max_port else 0
    bitmap = bytearray(num_bytes)
    for bp in bp_nums:
        byte_idx = (bp - 1) // 8
        bit_idx = (bp - 1) % 8
        bitmap[byte_idx] |= (0x80 >> bit_idx)
    return bytes(bitmap)


# MRP enum mappings
_MRP_PORT_OPER_STATE = {1: 'disabled', 2: 'blocked', 3: 'forwarding', 4: 'notConnected'}
_MRP_ROLE = {1: 'client', 2: 'manager', 3: 'undefined'}
_MRP_RECOVERY_DELAY = {1: '500ms', 2: '200ms', 3: '30ms', 4: '10ms'}
_MRP_RING_OPER_STATE = {1: 'open', 2: 'closed', 3: 'undefined'}
_MRP_CONFIG_OPER_STATE = {1: 'noError', 2: 'linkError', 3: 'multipleMRM'}
_MRP_CONFIG_INFO = {1: 'no error', 2: 'ring port link error', 3: 'multiple MRM detected'}
_MRP_RECOVERY_DELAY_REV = {'500ms': 1, '200ms': 2, '30ms': 3, '10ms': 4}
_MRP_ROLE_REV = {'client': 1, 'manager': 2}

# SRM (Sub-Ring Manager) enum mappings
_SRM_ADMIN_STATE = {1: 'manager', 2: 'redundantManager', 3: 'singleManager'}
_SRM_OPER_STATE = {1: 'manager', 2: 'redundantManager', 3: 'singleManager', 4: 'disabled'}
_SRM_PORT_OPER_STATE = {1: 'disabled', 2: 'blocked', 3: 'forwarding', 4: 'not-connected'}
_SRM_RING_OPER_STATE = {1: 'undefined', 2: 'open', 3: 'closed'}
_SRM_REDUNDANCY = {1: True, 2: False}
_SRM_CONFIG_INFO = {
    1: 'no error', 2: 'ring port link error', 3: 'multiple SRM',
    4: 'no partner manager', 5: 'concurrent VLAN', 6: 'concurrent port',
    7: 'concurrent redundancy', 8: 'trunk member', 9: 'shared VLAN',
}
_SRM_ADMIN_STATE_REV = {'manager': 1, 'redundantManager': 2, 'singleManager': 3}

# Auto-disable reason enum
_AUTO_DISABLE_REASONS = {
    0: 'none', 1: 'link-flap', 2: 'crc-error', 3: 'duplex-mismatch',
    4: 'dhcp-snooping', 5: 'arp-rate', 6: 'bpdu-rate',
    7: 'mac-based-port-security', 8: 'overload-detection',
    9: 'speed-duplex', 10: 'loop-protection',
}
_AUTO_DISABLE_REASONS_REV = {v: k for k, v in _AUTO_DISABLE_REASONS.items() if v != 'none'}
_AUTO_DISABLE_CATEGORY = {1: 'other', 2: 'port-monitor', 3: 'network-security', 4: 'l2-redundancy'}

# Loop protection enums
_LOOP_PROT_ACTION = {10: 'trap', 11: 'auto-disable', 12: 'all'}
_LOOP_PROT_ACTION_REV = {'trap': 10, 'auto-disable': 11, 'all': 12}
_LOOP_PROT_MODE = {1: 'active', 2: 'passive'}
_LOOP_PROT_MODE_REV = {'active': 1, 'passive': 2}
_LOOP_PROT_TPID = {0: 'none', 1: 'dot1q', 2: 'dot1ad'}

# STP/RSTP enums (int keys for SNMP)
_STP_VERSION = {1: 'stp', 2: 'rstp', 3: 'mstp'}
_STP_VERSION_REV = {'stp': 1, 'rstp': 2, 'mstp': 3}
_STP_FWD_STATE = {1: 'discarding', 2: 'learning', 3: 'forwarding',
                  4: 'disabled', 5: 'manualFwd', 6: 'notParticipate'}


def _decode_snmp_date_time(val):
    """Decode SNMP DateAndTime OctetString to ISO string.

    DateAndTime is 8 or 11 bytes: year(2) month day hour min sec decisec [utc_dir utc_h utc_m].
    Returns '' for zero/epoch values.
    """
    if val is None:
        return ''
    try:
        raw = bytes(val)
    except (TypeError, ValueError):
        return ''
    if len(raw) < 8:
        return ''
    year = (raw[0] << 8) | raw[1]
    month, day, hour, minute, sec = raw[2], raw[3], raw[4], raw[5], raw[6]
    if year <= 1970:
        return ''
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"

# Default MRP domain UUID (all 0xFF) — used as table index suffix
MRP_DEFAULT_DOMAIN_SUFFIX = '.255.255.255.255.255.255.255.255.255.255.255.255.255.255.255.255'

# MAU type OID suffix → human-readable string
_MAU_TYPES = {
    # IANA dot3MauType assignments — names match HiOS CLI format
    '10': '10BaseTHD', '11': '10BaseTFD',
    '15': '100BaseTXHD', '16': '100BaseTXFD',
    '17': '100BaseFXHD', '18': '100BaseFXFD',
    '29': '1000BaseTHD', '30': '1000BaseTFD',
    '32': '1000BaseSXHD', '33': '1000BaseSXFD',
    '34': '1000BaseLXHD', '35': '1000BaseLXFD',
    '110': '2p5GbaseX',
}


def _format_mrp_domain_id(suffix_str):
    """Format MRP domain UUID from 16-part OID suffix to dotted string.

    The suffix is 16 dot-separated decimal octets (e.g. '255.255.255...255').
    Returns formatted string with '(Default)' suffix if all octets are 255.
    """
    parts = suffix_str.split('.')
    if len(parts) < 16:
        return suffix_str
    domain = '.'.join(parts[:16])
    if all(p == '255' for p in parts[:16]):
        domain += ' (Default)'
    return domain


def _snmp_int(val, default=0):
    """Safely convert an SNMP value to int.

    Handles pysnmp Integer32, OctetString (single byte), and string values.
    Returns default if conversion fails.
    """
    if val is None or val == '':
        return default
    # pysnmp Integer types have int() support directly
    try:
        return int(val)
    except (ValueError, TypeError):
        pass
    # OctetString with raw bytes (e.g. TruthValue as b'\x01')
    if hasattr(val, 'hasValue') and val.hasValue():
        raw = bytes(val)
        if raw:
            # Single byte → interpret as unsigned int
            result = 0
            for b in raw:
                result = (result << 8) | b
            return result
    return default


def _snmp_ip(val):
    """Convert an SNMP InetAddress / IpAddress value to a clean IP string.

    pysnmp may render InetAddress (OCTET STRING) as '0xc0a80301' instead of
    '192.168.3.1'. Detect this and convert. Also handles raw 4/16-byte values.
    """
    s = _snmp_str(val).strip()
    # Hex-encoded IPv4: 0x + 8 hex chars
    if s.startswith('0x') and len(s) == 10:
        try:
            octets = bytes.fromhex(s[2:])
            return '.'.join(str(b) for b in octets)
        except ValueError:
            pass
    # Raw 4-byte value
    if hasattr(val, 'hasValue') and val.hasValue():
        raw = bytes(val)
        if len(raw) == 4:
            return '.'.join(str(b) for b in raw)
        if len(raw) == 16:
            # IPv6 — use standard compressed notation
            return str(ipaddress.IPv6Address(raw))
    return s


def _decode_implied_string(suffix_str):
    """Decode an IMPLIED SnmpAdminString index.

    IMPLIED means the OID suffix is just the raw ASCII codes with NO length
    prefix (e.g. 'admin' = '97.100.109.105.110'). The length is determined
    by the remaining OID components.
    """
    parts = suffix_str.split('.')
    if not parts:
        return ''
    try:
        return ''.join(chr(int(c)) for c in parts)
    except (ValueError, IndexError):
        return suffix_str


# ---------------------------------------------------------------------------
# SNMP HiOS class
# ---------------------------------------------------------------------------

class SNMPHIOS:
    """SNMP protocol handler for HiOS devices.

    Uses SNMPv3 (authPriv, MD5/DES) when a password is provided — this is
    the default for HiOS where SNMPv1/v2c are disabled out of the box.
    CLI users on HiOS are the SNMPv3 users (same username/password).

    Falls back to SNMPv2c when password is empty (community-only mode).

    Short passwords (< 8 chars, e.g. HiOS default "private") are handled
    by pre-computing the MD5 master key, bypassing pysnmp's RFC 3414
    minimum length enforcement.

    Each public getter runs in its own asyncio.run() with a fresh
    SnmpEngine, because pysnmp engines are bound to the event loop
    that created them and cannot be reused across asyncio.run() calls.
    """

    def __init__(self, hostname, username, password, timeout, port=161):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self._connected = False
        self._ifindex_map = None  # cached ifIndex -> name mapping

    def _build_auth(self):
        """Build pysnmp auth object (SNMPv3 or SNMPv2c).

        SNMPv3 authPriv when password is set (uses MD5/DES, pre-computed
        master key to handle passwords shorter than 8 chars).
        SNMPv2c when password is empty (community = username).
        """
        if self.password:
            # SNMPv3 authPriv — pre-compute master key to bypass 8-char limit
            master_key = hash_passphrase_md5(self.password.encode())
            return UsmUserData(
                self.username,
                authKey=master_key, privKey=master_key,
                authProtocol=usmHMACMD5AuthProtocol,
                privProtocol=usmDESPrivProtocol,
                authKeyType=USM_KEY_TYPE_MASTER,
                privKeyType=USM_KEY_TYPE_MASTER,
            )
        else:
            # SNMPv2c — community string from username
            return CommunityData(self.username, mpModel=1)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def open(self):
        """Validate SNMP connectivity with a sysDescr GET."""
        try:
            result = asyncio.run(self._get_scalar(OID_sysDescr))
            if OID_sysDescr not in result:
                raise ConnectionException(f"No sysDescr response from {self.hostname}")
            self._connected = True
        except ConnectionException:
            raise
        except Exception as e:
            raise ConnectionException(f"Cannot set up SNMP for {self.hostname}: {e}")

    def close(self):
        """Close SNMP session."""
        self._connected = False
        self._ifindex_map = None

    # ------------------------------------------------------------------
    # Core SNMP plumbing (async)
    # ------------------------------------------------------------------

    async def _get_scalar(self, *oids):
        """GET scalar values. Appends .0 to each OID unless it already
        contains a table index (detected by having 12+ dot-separated parts).

        Returns {base_oid: value, ...}.
        """
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (self.hostname, self.port), timeout=self.timeout, retries=1,
        )
        auth = self._build_auth()
        object_types = []
        for oid in oids:
            # Table row OIDs (like fw version 1.1.1 index) are already fully qualified
            if len(oid.split('.')) >= 14:
                object_types.append(ObjectType(ObjectIdentity(oid)))
            else:
                object_types.append(ObjectType(ObjectIdentity(oid + '.0')))
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            engine, auth, transport, ContextData(), *object_types,
        )
        if errorIndication:
            raise ConnectionException(f"SNMP error: {errorIndication}")
        if errorStatus:
            raise ConnectionException(
                f"SNMP error: {errorStatus.prettyPrint()} at "
                f"{varBinds[int(errorIndex) - 1][0] if errorIndex else '?'}"
            )
        result = {}
        for oid_obj, val in varBinds:
            oid_str = str(oid_obj)
            # Strip trailing .0 to get base OID for scalar OIDs
            if oid_str.endswith('.0'):
                base = oid_str[:-2]
                # Only strip .0 if the base matches one of the requested OIDs
                if base in oids:
                    oid_str = base
            result[oid_str] = val
        return result

    async def _walk(self, base_oid, engine=None):
        """GETBULK walk of a single column.

        Returns {suffix: value, ...} where suffix is the OID part
        after base_oid (e.g. '.1' for ifIndex row 1).

        Accepts an optional engine to share across parallel walks
        within the same asyncio.run() call.
        """
        if engine is None:
            engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (self.hostname, self.port), timeout=self.timeout, retries=1,
        )
        auth = self._build_auth()
        result = {}
        base_prefix = base_oid + '.'
        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            engine, auth, transport, ContextData(),
            0, 25,  # nonRepeaters=0, maxRepetitions=25
            ObjectType(ObjectIdentity(base_oid)),
            lookupMib=False,
        ):
            if errorIndication:
                logger.warning("SNMP walk error for %s: %s", base_oid, errorIndication)
                break
            if errorStatus:
                logger.warning("SNMP walk status error for %s: %s", base_oid, errorStatus)
                break
            for oid_obj, val in varBinds:
                oid_str = str(oid_obj)
                if not oid_str.startswith(base_prefix):
                    break
                suffix = oid_str[len(base_prefix):]
                result[suffix] = val
            else:
                # Inner for completed without break — all OIDs still in tree
                continue
            # Inner for hit break (out-of-tree OID) — stop outer loop too
            break
        return result

    async def _walk_columns(self, oid_map, engine=None):
        """Walk multiple columns in parallel, merge by row index.

        Args:
            oid_map: {'col_name': oid_string, ...}
            engine: shared SnmpEngine for this event loop scope

        Returns:
            {row_idx: {'col_name': value, ...}, ...}
        """
        if engine is None:
            engine = SnmpEngine()
        names = list(oid_map.keys())
        oids = [oid_map[n] for n in names]
        results = await asyncio.gather(*(self._walk(oid, engine) for oid in oids))

        merged = {}
        for col_name, col_data in zip(names, results):
            for suffix, val in col_data.items():
                merged.setdefault(suffix, {})[col_name] = val
        return merged

    async def _build_ifindex_map(self, engine=None):
        """Build and cache ifIndex -> interface name mapping.

        Uses ifName (returns '1/1' format) rather than ifDescr
        (which returns verbose 'Module: 1 Port: 1 - 2.5 Gbit' on HiOS).
        """
        if self._ifindex_map is not None:
            return self._ifindex_map
        data = await self._walk(OID_ifName, engine)
        self._ifindex_map = {idx: str(val) for idx, val in data.items()}
        return self._ifindex_map

    # ------------------------------------------------------------------
    # Getters — standard MIBs
    # ------------------------------------------------------------------

    def get_facts(self):
        """Return device facts from standard + Hirschmann private MIBs."""
        return asyncio.run(self._get_facts_async())

    async def _get_facts_async(self):
        engine = SnmpEngine()
        scalars, ifmap = await asyncio.gather(
            self._get_scalar(
                OID_sysName, OID_sysUpTime, OID_sysDescr,
                OID_hm2ProductDescr, OID_hm2SerialNumber,
                OID_hm2FwVersionRAM,
            ),
            self._build_ifindex_map(engine),
        )

        # Prefer private MIB data, fall back to sysDescr parsing
        product_descr = str(scalars.get(OID_hm2ProductDescr, '')).strip()
        serial = str(scalars.get(OID_hm2SerialNumber, '')).strip()
        fw_version_raw = str(scalars.get(OID_hm2FwVersionRAM, ''))

        if product_descr:
            model = product_descr  # full product code, e.g. 'BRS50-00122Q2Q-SFCZ99HHSEA'
        else:
            model, _ = _parse_sysDescr(str(scalars.get(OID_sysDescr, '')))

        if fw_version_raw:
            os_version = _parse_fw_version(fw_version_raw)
        else:
            _, os_version = _parse_sysDescr(str(scalars.get(OID_sysDescr, '')))

        # sysUpTime is in centiseconds (TimeTicks)
        uptime_raw = scalars.get(OID_sysUpTime, 0)
        try:
            uptime = int(uptime_raw) // 100
        except (ValueError, TypeError):
            uptime = -1

        return {
            'uptime': uptime,
            'vendor': 'Belden',
            'model': model,
            'hostname': str(scalars.get(OID_sysName, '')),
            'fqdn': str(scalars.get(OID_sysName, '')),
            'os_version': os_version,
            'serial_number': serial,
            'interface_list': sorted(ifmap.values()),
        }

    def get_interfaces(self):
        """Return interface details from IF-MIB ifTable + ifXTable."""
        return asyncio.run(self._get_interfaces_async())

    async def _get_interfaces_async(self):
        engine = SnmpEngine()
        rows = await self._walk_columns({
            'name': OID_ifName,
            'oper': OID_ifOperStatus,
            'admin': OID_ifAdminStatus,
            'highspeed': OID_ifHighSpeed,
            'mtu': OID_ifMtu,
            'mac': OID_ifPhysAddress,
            'alias': OID_ifAlias,
        }, engine)
        interfaces = {}
        for idx, cols in rows.items():
            name = str(cols.get('name', f'if{idx}'))
            oper = int(cols.get('oper', 2))
            admin = int(cols.get('admin', 2))
            try:
                speed = int(cols.get('highspeed', 0)) * 1_000_000
            except (ValueError, TypeError):
                speed = 0
            try:
                mtu = int(cols.get('mtu', 0))
            except (ValueError, TypeError):
                mtu = 0
            mac_val = cols.get('mac', b'')
            mac_str = _format_mac(mac_val)

            interfaces[name] = {
                'is_up': oper == 1,
                'is_enabled': admin == 1,
                'description': str(cols.get('alias', '')),
                'last_flapped': -1.0,
                'speed': speed,
                'mtu': mtu,
                'mac_address': mac_str,
            }
        return interfaces

    def get_interfaces_ip(self):
        """Return interface IP addresses from IP-MIB ipAddrTable."""
        return asyncio.run(self._get_interfaces_ip_async())

    async def _get_interfaces_ip_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        rows = await self._walk_columns({
            'ifindex': OID_ipAdEntIfIndex,
            'mask': OID_ipAdEntNetMask,
        }, engine)
        # rows keyed by IP address suffix (e.g. '192.168.1.4')
        result = {}
        for ip_suffix, cols in rows.items():
            ifindex = str(cols.get('ifindex', ''))
            iface = ifmap.get(ifindex, f'if{ifindex}')
            mask = _snmp_str(cols.get('mask', '255.255.255.255'))
            prefix = _mask_to_prefix(mask)

            if iface not in result:
                result[iface] = {'ipv4': {}, 'ipv6': {}}
            result[iface]['ipv4'][ip_suffix] = {'prefix_length': prefix}
        return result

    def get_interfaces_counters(self):
        """Return interface counters from IF-MIB HC counters."""
        return asyncio.run(self._get_interfaces_counters_async())

    async def _get_interfaces_counters_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        rows = await self._walk_columns({
            'rx_octets': OID_ifHCInOctets,
            'tx_octets': OID_ifHCOutOctets,
            'rx_unicast': OID_ifHCInUcastPkts,
            'tx_unicast': OID_ifHCOutUcastPkts,
            'rx_multicast': OID_ifHCInMulticastPkts,
            'tx_multicast': OID_ifHCOutMulticastPkts,
            'rx_broadcast': OID_ifHCInBroadcastPkts,
            'tx_broadcast': OID_ifHCOutBroadcastPkts,
            'rx_discards': OID_ifInDiscards,
            'tx_discards': OID_ifOutDiscards,
            'rx_errors': OID_ifInErrors,
            'tx_errors': OID_ifOutErrors,
        }, engine)
        counters = {}
        for idx, cols in rows.items():
            name = ifmap.get(idx, f'if{idx}')
            counters[name] = {
                'tx_errors': int(cols.get('tx_errors', 0)),
                'rx_errors': int(cols.get('rx_errors', 0)),
                'tx_discards': int(cols.get('tx_discards', 0)),
                'rx_discards': int(cols.get('rx_discards', 0)),
                'tx_octets': int(cols.get('tx_octets', 0)),
                'rx_octets': int(cols.get('rx_octets', 0)),
                'tx_unicast_packets': int(cols.get('tx_unicast', 0)),
                'rx_unicast_packets': int(cols.get('rx_unicast', 0)),
                'tx_multicast_packets': int(cols.get('tx_multicast', 0)),
                'rx_multicast_packets': int(cols.get('rx_multicast', 0)),
                'tx_broadcast_packets': int(cols.get('tx_broadcast', 0)),
                'rx_broadcast_packets': int(cols.get('rx_broadcast', 0)),
            }
        return counters

    def get_arp_table(self, vrf=''):
        """Return ARP table from IP-MIB ipNetToMediaTable."""
        return asyncio.run(self._get_arp_table_async())

    async def _get_arp_table_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        rows = await self._walk_columns({
            'mac': OID_ipNetToMediaPhysAddress,
            'type': OID_ipNetToMediaType,
        }, engine)
        # Index format: ifIndex.ipAddress (e.g. '100.192.168.1.1')
        arp_table = []
        for suffix, cols in rows.items():
            parts = suffix.split('.', 1)
            if len(parts) != 2:
                continue
            ifindex, ip = parts[0], parts[1]
            iface = ifmap.get(ifindex, f'if{ifindex}')
            mac_val = cols.get('mac', b'')
            arp_table.append({
                'interface': iface,
                'mac': _format_mac(mac_val),
                'ip': ip,
                'age': 0.0,  # not available in standard MIB
            })
        return arp_table

    def get_mac_address_table(self):
        """Return MAC address table from Q-BRIDGE-MIB + BRIDGE-MIB."""
        return asyncio.run(self._get_mac_address_table_async())

    async def _get_mac_address_table_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        # Get bridge port -> ifIndex mapping
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        bp_to_name = {}
        for bp_num, ifindex_val in bp_data.items():
            ifindex = str(ifindex_val)
            bp_to_name[bp_num] = ifmap.get(ifindex, f'if{ifindex}')

        # Walk FDB table
        rows = await self._walk_columns({
            'port': OID_dot1qTpFdbPort,
            'status': OID_dot1qTpFdbStatus,
        }, engine)

        # Index format: fdbId.mac[6 octets as decimal] (e.g. '1.0.27.30.200.128.0')
        mac_table = []
        for suffix, cols in rows.items():
            parts = suffix.split('.')
            if len(parts) < 7:
                continue
            vlan_id = parts[0]
            mac_octets = parts[1:7]
            try:
                mac_str = ':'.join(f'{int(o):02x}' for o in mac_octets)
            except ValueError:
                continue

            bridge_port = str(cols.get('port', '0'))
            status = int(cols.get('status', 0))
            iface = bp_to_name.get(bridge_port, f'port{bridge_port}')

            mac_table.append({
                'mac': mac_str,
                'interface': iface,
                'vlan': int(vlan_id),
                'static': status != 3,  # 3 = learned
                'active': True,
                'moves': 0,
                'last_move': 0.0,
            })
        return mac_table

    def get_lldp_neighbors(self):
        """Return LLDP neighbors from LLDP-MIB."""
        return asyncio.run(self._get_lldp_neighbors_async())

    async def _get_lldp_neighbors_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        # Get local port number -> ifIndex mapping
        loc_ports = await self._walk(OID_lldpLocPortId, engine)

        rows = await self._walk_columns({
            'sysname': OID_lldpRemSysName,
            'portid': OID_lldpRemPortId,
            'portdesc': OID_lldpRemPortDesc,
            'chassisid': OID_lldpRemChassisId,
        }, engine)

        # Index: timeMark.localPortNum.remIndex
        neighbors = {}
        for suffix, cols in rows.items():
            parts = suffix.split('.')
            if len(parts) < 3:
                continue
            local_port_num = parts[1]

            # Map local port num -> interface name
            local_iface = ifmap.get(local_port_num)
            if not local_iface:
                # Try via lldpLocPortId
                loc_val = loc_ports.get(local_port_num)
                local_iface = str(loc_val) if loc_val else f'port{local_port_num}'

            sysname = str(cols.get('sysname', ''))
            chassisid_raw = cols.get('chassisid', b'')
            chassisid = _format_mac(chassisid_raw) or str(chassisid_raw)
            hostname = sysname if sysname else chassisid
            portid_raw = cols.get('portid', b'')
            portid = str(portid_raw)
            # If portid looks like binary (non-printable), format as MAC
            if portid_raw and hasattr(portid_raw, 'hasValue') and portid_raw.hasValue():
                raw_bytes = bytes(portid_raw)
                if raw_bytes and not all(0x20 <= b < 0x7f for b in raw_bytes):
                    portid = _format_mac(portid_raw)
            portdesc = str(cols.get('portdesc', ''))
            port = portid if portid else portdesc

            neighbors.setdefault(local_iface, []).append({
                'hostname': hostname,
                'port': port,
            })
        return neighbors

    def get_lldp_neighbors_detail(self, interface=''):
        """Return detailed LLDP neighbor info from LLDP-MIB."""
        return asyncio.run(self._get_lldp_neighbors_detail_async(interface))

    async def _get_lldp_neighbors_detail_async(self, interface=''):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        loc_ports = await self._walk(OID_lldpLocPortId, engine)

        rows = await self._walk_columns({
            'chassisid_subtype': OID_lldpRemChassisIdSubtype,
            'chassisid': OID_lldpRemChassisId,
            'portid_subtype': OID_lldpRemPortIdSubtype,
            'portid': OID_lldpRemPortId,
            'portdesc': OID_lldpRemPortDesc,
            'sysname': OID_lldpRemSysName,
            'sysdesc': OID_lldpRemSysDesc,
            'caps_supported': OID_lldpRemSysCapSupported,
            'caps_enabled': OID_lldpRemSysCapEnabled,
        }, engine)

        # Walk management addresses
        mgmt_data = await self._walk(OID_lldpRemManAddrIfSubtype, engine)

        neighbors = {}
        for suffix, cols in rows.items():
            parts = suffix.split('.')
            if len(parts) < 3:
                continue
            time_mark = parts[0]
            local_port_num = parts[1]
            rem_index = parts[2]

            local_iface = ifmap.get(local_port_num)
            if not local_iface:
                loc_val = loc_ports.get(local_port_num)
                local_iface = str(loc_val) if loc_val else f'port{local_port_num}'

            if interface and local_iface != interface:
                continue

            sysname = str(cols.get('sysname', ''))
            chassisid_raw = cols.get('chassisid', b'')
            chassisid = _format_mac(chassisid_raw) or str(chassisid_raw)
            portid_raw = cols.get('portid', b'')
            portid = str(portid_raw)
            # If portid looks like binary (non-printable), format as MAC
            if portid_raw and hasattr(portid_raw, 'hasValue') and portid_raw.hasValue():
                raw_bytes = bytes(portid_raw)
                if raw_bytes and not all(0x20 <= b < 0x7f for b in raw_bytes):
                    portid = _format_mac(portid_raw)
            portdesc = str(cols.get('portdesc', ''))

            caps_sup = _decode_capabilities(cols.get('caps_supported', b''))
            caps_en = _decode_capabilities(cols.get('caps_enabled', b''))

            # Find management addresses for this neighbor
            mgmt_addresses = []
            prefix = f'{time_mark}.{local_port_num}.{rem_index}.'
            for mgmt_suffix, mgmt_val in mgmt_data.items():
                if mgmt_suffix.startswith(prefix):
                    # The address is encoded in the OID suffix after the prefix
                    addr_part = mgmt_suffix[len(prefix):]
                    # Format: addrSubtype.addrLen.addr... -- try to extract IPv4
                    addr_parts = addr_part.split('.')
                    if len(addr_parts) >= 6 and addr_parts[0] == '1':
                        # IPv4: subtype=1, len=4, then 4 octets
                        ip = '.'.join(addr_parts[2:6])
                        mgmt_addresses.append(ip)

            detail = {
                'parent_interface': local_iface,
                'remote_chassis_id': chassisid,
                'remote_system_name': sysname,
                'remote_system_description': str(cols.get('sysdesc', '')),
                'remote_port': portid,
                'remote_port_description': portdesc,
                'remote_system_capab': caps_sup,
                'remote_system_enable_capab': caps_en,
                'remote_management_address': mgmt_addresses[0] if mgmt_addresses else '',
            }

            neighbors.setdefault(local_iface, []).append(detail)
        return neighbors

    def get_vlans(self):
        """Return VLAN info from Q-BRIDGE-MIB + BRIDGE-MIB."""
        return asyncio.run(self._get_vlans_async())

    async def _get_vlans_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        # Bridge port -> interface name mapping
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        bp_to_name = {}
        for bp_num, ifindex_val in bp_data.items():
            ifindex = str(ifindex_val)
            bp_to_name[bp_num] = ifmap.get(ifindex, f'if{ifindex}')

        rows = await self._walk_columns({
            'name': OID_dot1qVlanStaticName,
            'egress': OID_dot1qVlanStaticEgressPorts,
        }, engine)

        vlans = {}
        for vlan_id_str, cols in rows.items():
            try:
                vlan_id = int(vlan_id_str)
            except ValueError:
                continue
            name = str(cols.get('name', f'VLAN{vlan_id}'))
            egress_raw = cols.get('egress', b'')
            interfaces = _decode_portlist(egress_raw, bp_to_name)
            vlans[vlan_id] = {
                'name': name,
                'interfaces': interfaces,
            }
        return vlans

    def get_vlan_ingress(self, *ports):
        """Return per-port ingress settings from Q-BRIDGE-MIB."""
        return asyncio.run(self._get_vlan_ingress_async(*ports))

    async def _get_vlan_ingress_async(self, *ports):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        bp_to_name = {}
        for bp_num, ifindex_val in bp_data.items():
            bp_to_name[bp_num] = ifmap.get(str(ifindex_val), f'if{ifindex_val}')

        rows = await self._walk_columns({
            'pvid': OID_dot1qPvid,
            'frame_types': OID_dot1qPortAcceptableFrameTypes,
            'ingress_filtering': OID_dot1qPortIngressFiltering,
        }, engine)

        port_set = set(ports) if ports else None
        result = {}
        for bp_str, cols in rows.items():
            name = bp_to_name.get(bp_str, f'port{bp_str}')
            if port_set and name not in port_set:
                continue
            ft_val = int(cols.get('frame_types', 1))
            filt_val = int(cols.get('ingress_filtering', 2))
            result[name] = {
                'pvid': int(cols.get('pvid', 1)),
                'frame_types': 'admit_only_tagged' if ft_val == 2 else 'admit_all',
                'ingress_filtering': filt_val == 1,
            }
        return result

    def get_vlan_egress(self, *ports):
        """Return per-VLAN-per-port membership (T/U/F) from Q-BRIDGE-MIB."""
        return asyncio.run(self._get_vlan_egress_async(*ports))

    async def _get_vlan_egress_async(self, *ports):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        bp_to_name = {}
        for bp_num, ifindex_val in bp_data.items():
            bp_to_name[bp_num] = ifmap.get(str(ifindex_val), f'if{ifindex_val}')

        rows = await self._walk_columns({
            'name': OID_dot1qVlanStaticName,
            'egress': OID_dot1qVlanStaticEgressPorts,
            'untagged': OID_dot1qVlanStaticUntaggedPorts,
            'forbidden': OID_dot1qVlanStaticForbiddenEgressPorts,
        }, engine)

        port_set = set(ports) if ports else None
        vlans = {}
        for vlan_id_str, cols in rows.items():
            try:
                vlan_id = int(vlan_id_str)
            except ValueError:
                continue
            name = str(cols.get('name', f'VLAN{vlan_id}'))
            egress_ifaces = set(_decode_portlist(cols.get('egress', b''), bp_to_name))
            untagged_ifaces = set(_decode_portlist(cols.get('untagged', b''), bp_to_name))
            forbidden_ifaces = set(_decode_portlist(cols.get('forbidden', b''), bp_to_name))

            port_modes = {}
            for iface in egress_ifaces:
                if port_set and iface not in port_set:
                    continue
                if iface in untagged_ifaces:
                    port_modes[iface] = 'untagged'
                else:
                    port_modes[iface] = 'tagged'
            for iface in forbidden_ifaces:
                if iface not in egress_ifaces:
                    if port_set and iface not in port_set:
                        continue
                    port_modes[iface] = 'forbidden'

            if port_modes or not port_set:
                vlans[vlan_id] = {'name': name, 'ports': port_modes}
        return vlans

    def set_vlan_ingress(self, port, pvid=None, frame_types=None,
                         ingress_filtering=None):
        """Set ingress parameters on one or more ports via SNMP.

        Args:
            port: port name (str) or list of port names
        """
        return asyncio.run(self._set_vlan_ingress_async(
            port, pvid, frame_types, ingress_filtering))

    async def _set_vlan_ingress_async(self, port, pvid, frame_types,
                                       ingress_filtering):
        ports = [port] if isinstance(port, str) else list(port)
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        name_to_bp = {}
        for bp_num, ifindex_val in bp_data.items():
            name = ifmap.get(str(ifindex_val), f'if{ifindex_val}')
            name_to_bp[name] = bp_num

        # Validate frame_types once
        ft_val = None
        if frame_types is not None:
            if frame_types == 'admit_only_tagged':
                ft_val = 2
            elif frame_types == 'admit_all':
                ft_val = 1
            else:
                raise ValueError(
                    f"Invalid frame_types '{frame_types}': "
                    f"use 'admit_all' or 'admit_only_tagged'")

        sets = []
        for p in ports:
            bp = name_to_bp.get(p)
            if bp is None:
                raise ValueError(f"Unknown interface '{p}'")
            if pvid is not None:
                sets.append((f"{OID_dot1qPvid}.{bp}",
                             Unsigned32(int(pvid))))
            if ft_val is not None:
                sets.append((f"{OID_dot1qPortAcceptableFrameTypes}.{bp}",
                             Integer32(ft_val)))
            if ingress_filtering is not None:
                sets.append((f"{OID_dot1qPortIngressFiltering}.{bp}",
                             Integer32(1 if ingress_filtering else 2)))
        if sets:
            await self._set_oids(*sets)

    def set_vlan_egress(self, vlan_id, port, mode):
        """Set port(s) VLAN membership via SNMP.

        Args:
            port: port name (str) or list of port names
        """
        return asyncio.run(self._set_vlan_egress_async(vlan_id, port, mode))

    async def _set_vlan_egress_async(self, vlan_id, port, mode):
        if mode not in ('tagged', 'untagged', 'forbidden', 'none'):
            raise ValueError(
                f"Invalid mode '{mode}': use 'tagged', 'untagged', "
                f"'forbidden', or 'none'")

        ports = [port] if isinstance(port, str) else list(port)
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        name_to_bp = {}
        for bp_num, ifindex_val in bp_data.items():
            name = ifmap.get(str(ifindex_val), f'if{ifindex_val}')
            name_to_bp[name] = bp_num

        # Validate all ports up front
        bp_ints = []
        for p in ports:
            bp = name_to_bp.get(p)
            if bp is None:
                raise ValueError(f"Unknown interface '{p}'")
            bp_ints.append(int(bp))

        # Read current bitmaps for this VLAN
        vid = str(vlan_id)
        rows = await self._walk_columns({
            'egress': OID_dot1qVlanStaticEgressPorts,
            'untagged': OID_dot1qVlanStaticUntaggedPorts,
            'forbidden': OID_dot1qVlanStaticForbiddenEgressPorts,
        }, engine)

        if vid not in rows:
            raise ValueError(f"VLAN {vlan_id} does not exist")

        egress_raw = rows[vid].get('egress', b'')
        untagged_raw = rows[vid].get('untagged', b'')
        forbidden_raw = rows[vid].get('forbidden', b'')

        # Convert to mutable bytearrays (handle pysnmp OctetString)
        def _to_bytearray(val):
            if isinstance(val, (bytes, bytearray)):
                return bytearray(val)
            if hasattr(val, 'asOctets'):
                return bytearray(val.asOctets())
            return bytearray(bytes(val))

        egress = _to_bytearray(egress_raw)
        untagged = _to_bytearray(untagged_raw)
        forbidden = _to_bytearray(forbidden_raw)

        # Modify bitmaps for ALL target ports
        for bp_int in bp_ints:
            byte_idx = (bp_int - 1) // 8
            bit_mask = 0x80 >> ((bp_int - 1) % 8)
            for arr in (egress, untagged, forbidden):
                while len(arr) <= byte_idx:
                    arr.append(0)

            if mode == 'tagged':
                egress[byte_idx] |= bit_mask
                untagged[byte_idx] &= ~bit_mask
                forbidden[byte_idx] &= ~bit_mask
            elif mode == 'untagged':
                egress[byte_idx] |= bit_mask
                untagged[byte_idx] |= bit_mask
                forbidden[byte_idx] &= ~bit_mask
            elif mode == 'forbidden':
                egress[byte_idx] &= ~bit_mask
                untagged[byte_idx] &= ~bit_mask
                forbidden[byte_idx] |= bit_mask
            elif mode == 'none':
                egress[byte_idx] &= ~bit_mask
                untagged[byte_idx] &= ~bit_mask
                forbidden[byte_idx] &= ~bit_mask

        await self._set_oids(
            (f"{OID_dot1qVlanStaticEgressPorts}.{vid}",
             OctetString(bytes(egress))),
            (f"{OID_dot1qVlanStaticUntaggedPorts}.{vid}",
             OctetString(bytes(untagged))),
            (f"{OID_dot1qVlanStaticForbiddenEgressPorts}.{vid}",
             OctetString(bytes(forbidden))),
        )

    def create_vlan(self, vlan_id, name=''):
        """Create a VLAN in the VLAN database via SNMP."""
        return asyncio.run(self._create_vlan_async(vlan_id, name))

    async def _create_vlan_async(self, vlan_id, name):
        sets = [(f"{OID_dot1qVlanStaticRowStatus}.{vlan_id}",
                 Integer32(4))]  # createAndGo
        if name:
            sets.append((f"{OID_dot1qVlanStaticName}.{vlan_id}",
                         OctetString(name)))
        await self._set_oids(*sets)

    def update_vlan(self, vlan_id, name):
        """Rename an existing VLAN via SNMP."""
        return asyncio.run(self._set_oids(
            (f"{OID_dot1qVlanStaticName}.{vlan_id}",
             OctetString(name)),
        ))

    def delete_vlan(self, vlan_id):
        """Delete a VLAN from the VLAN database via SNMP."""
        return asyncio.run(self._set_oids(
            (f"{OID_dot1qVlanStaticRowStatus}.{vlan_id}",
             Integer32(6)),  # destroy
        ))

    def get_snmp_information(self):
        """Return SNMP information from SNMPv2-MIB.

        Note: SNMP community strings cannot be queried via SNMP for
        security reasons, so community dict is always empty.
        """
        return asyncio.run(self._get_snmp_information_async())

    async def _get_snmp_information_async(self):
        scalars = await self._get_scalar(OID_sysName, OID_sysContact, OID_sysLocation)
        return {
            'chassis_id': str(scalars.get(OID_sysName, '')).strip(),
            'community': {},
            'contact': str(scalars.get(OID_sysContact, '')).strip(),
            'location': str(scalars.get(OID_sysLocation, '')).strip(),
        }

    # ------------------------------------------------------------------
    # Getters — Hirschmann private MIBs
    # ------------------------------------------------------------------

    def get_environment(self):
        """Return environment data from HM2-DEVMGMT, HM2-PWRMGMT, HM2-FAN,
        HM2-DIAGNOSTIC MIBs.

        NAPALM format:
        {
            'fans': {'fan1': {'status': True}},
            'temperature': {'board': {'temperature': 43.0, 'is_alert': False, 'is_critical': False}},
            'power': {'PSU1': {'status': True, 'capacity': -1.0, 'output': -1.0}},
            'cpu': {'0': {'%usage': 23.0}},
            'memory': {'available_ram': 253076, 'used_ram': 128424},
        }
        """
        return asyncio.run(self._get_environment_async())

    async def _get_environment_async(self):
        engine = SnmpEngine()

        # Fetch scalars and walks in parallel
        scalars_task = self._get_scalar(
            OID_hm2Temperature, OID_hm2TempUpperLimit, OID_hm2TempLowerLimit,
            OID_hm2CpuUtil, OID_hm2MemAlloc, OID_hm2MemFree,
        )
        psu_task = self._walk(OID_hm2PSState, engine)
        fan_mod_task = self._walk(OID_hm2FanModuleStatus, engine)
        fan_task = self._walk(OID_hm2FanStatus, engine)

        scalars, psu_data, fan_mod_data, fan_data = await asyncio.gather(
            scalars_task, psu_task, fan_mod_task, fan_task,
        )

        # Temperature
        try:
            temp = float(int(scalars.get(OID_hm2Temperature, 0)))
        except (ValueError, TypeError):
            temp = 0.0
        try:
            temp_upper = float(int(scalars.get(OID_hm2TempUpperLimit, 70)))
        except (ValueError, TypeError):
            temp_upper = 70.0
        try:
            temp_lower = float(int(scalars.get(OID_hm2TempLowerLimit, 0)))
        except (ValueError, TypeError):
            temp_lower = 0.0

        temperature = {
            'chassis': {
                'temperature': temp,
                'is_alert': temp >= temp_upper or temp <= temp_lower,
                'is_critical': temp >= temp_upper,
            },
        }

        # Power supplies — present(1)=OK, defective(2)=bad, notInstalled(3)=skip
        power = {}
        for suffix, state_val in sorted(psu_data.items()):
            try:
                state = int(state_val)
            except (ValueError, TypeError):
                continue
            if state == 3:  # notInstalled
                continue
            psu_name = f'Power Supply P{suffix}'
            power[psu_name] = {
                'status': state == 1,  # present = OK
                'capacity': -1.0,
                'output': -1.0,
            }

        # Fans — check individual fans first, fall back to fan modules
        fans = {}
        if fan_data:
            for suffix, status_val in sorted(fan_data.items()):
                try:
                    status = int(status_val)
                except (ValueError, TypeError):
                    continue
                if status == 1:  # not-available
                    continue
                # suffix is unit.module.fan — use as label
                parts = suffix.split('.')
                if len(parts) == 3:
                    fan_name = f'fan{parts[1]}/{parts[2]}'
                else:
                    fan_name = f'fan{suffix}'
                fans[fan_name] = {
                    'status': status == 2,  # available-and-ok
                }
        elif fan_mod_data:
            for suffix, status_val in sorted(fan_mod_data.items()):
                try:
                    status = int(status_val)
                except (ValueError, TypeError):
                    continue
                if status == 1:  # not-available
                    continue
                parts = suffix.split('.')
                if len(parts) == 2:
                    fan_name = f'fan{parts[1]}'
                else:
                    fan_name = f'fan{suffix}'
                fans[fan_name] = {
                    'status': status == 2,  # available-and-ok
                }

        # CPU
        try:
            cpu_pct = float(int(scalars.get(OID_hm2CpuUtil, 0)))
        except (ValueError, TypeError):
            cpu_pct = 0.0
        cpu = {'0': {'%usage': cpu_pct}}

        # Memory (values in kBytes)
        # HiOS "Allocated RAM" = total memory pool, "Free RAM" = unused portion
        # Match SSH driver: available_ram = allocated, used_ram = allocated - free
        try:
            mem_alloc = int(scalars.get(OID_hm2MemAlloc, 0))
        except (ValueError, TypeError):
            mem_alloc = 0
        try:
            mem_free = int(scalars.get(OID_hm2MemFree, 0))
        except (ValueError, TypeError):
            mem_free = 0
        memory = {
            'available_ram': mem_alloc,
            'used_ram': mem_alloc - mem_free,
        }

        return {
            'fans': fans,
            'temperature': temperature,
            'power': power,
            'cpu': cpu,
            'memory': memory,
        }

    # ------------------------------------------------------------------
    # Getters — optics, users, NTP (Hirschmann private MIBs)
    # ------------------------------------------------------------------

    def get_optics(self):
        """Return SFP optical power from HM2-DEVMGMT-MIB hm2SfpDiagTable."""
        return asyncio.run(self._get_optics_async())

    async def _get_optics_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        rows = await self._walk_columns({
            'tx_power': OID_hm2SfpDiagTxPower,
            'rx_power': OID_hm2SfpDiagRxPower,
        }, engine)

        optics = {}
        for idx, cols in rows.items():
            name = ifmap.get(idx, f'if{idx}')
            try:
                tx = float(str(cols.get('tx_power', '0')))
            except (ValueError, TypeError):
                tx = 0.0
            try:
                rx = float(str(cols.get('rx_power', '0')))
            except (ValueError, TypeError):
                rx = 0.0
            optics[name] = {
                'physical_channels': {
                    'channel': [{
                        'index': 0,
                        'state': {
                            'input_power': {
                                'instant': rx, 'avg': 0.0, 'min': 0.0, 'max': 0.0,
                            },
                            'output_power': {
                                'instant': tx, 'avg': 0.0, 'min': 0.0, 'max': 0.0,
                            },
                            'laser_bias_current': {
                                'instant': 0.0, 'avg': 0.0, 'min': 0.0, 'max': 0.0,
                            },
                        },
                    }],
                },
            }
        return optics

    def get_users(self):
        """Return user accounts from HM2-USERMGMT-MIB hm2UserConfigTable."""
        return asyncio.run(self._get_users_async())

    async def _get_users_async(self):
        engine = SnmpEngine()
        rows = await self._walk_columns({
            'role': OID_hm2UserAccessRole,
            'status': OID_hm2UserStatus,
        }, engine)

        users = {}
        for suffix, cols in rows.items():
            status = int(cols.get('status', 0))
            if status != 1:  # only active users
                continue
            username = _decode_implied_string(suffix)
            if not username:
                continue
            role = int(cols.get('role', 0))
            # HiOS AccessRole value IS the NAPALM level (15=admin, 1=user/guest)
            level = role
            users[username] = {
                'level': level,
                'password': '',
                'sshkeys': [],
            }
        return users

    def get_ntp_servers(self):
        """Return NTP server list from HM2-TIMESYNC-MIB."""
        return asyncio.run(self._get_ntp_servers_async())

    async def _get_ntp_servers_async(self):
        engine = SnmpEngine()
        addrs = await self._walk(OID_hm2SntpServerAddr, engine)
        result = {}
        for suffix, val in addrs.items():
            addr = _snmp_ip(val)
            if addr:
                result[addr] = {}
        return result

    def get_ntp_stats(self):
        """Return NTP statistics from HM2-TIMESYNC-MIB."""
        return asyncio.run(self._get_ntp_stats_async())

    async def _get_ntp_stats_async(self):
        engine = SnmpEngine()
        scalars_task = self._get_scalar(
            OID_hm2SntpRequestInterval, OID_hm2SntpClientStatus,
        )
        rows_task = self._walk_columns({
            'addr': OID_hm2SntpServerAddr,
            'status': OID_hm2SntpServerStatus,
        }, engine)
        scalars, rows = await asyncio.gather(scalars_task, rows_task)

        try:
            interval = int(scalars.get(OID_hm2SntpRequestInterval, 0))
        except (ValueError, TypeError):
            interval = 0

        stats = []
        for suffix, cols in rows.items():
            addr = _snmp_ip(cols.get('addr', ''))
            if not addr:
                continue
            server_status = int(cols.get('status', 0))
            # status 2 = success (synchronized)
            synchronized = server_status == 2
            addr_type = 'ipv6' if ':' in addr else 'ipv4'
            stats.append({
                'remote': addr,
                'referenceid': '',
                'synchronized': synchronized,
                'stratum': 0,
                'type': addr_type,
                'when': '',
                'hostpoll': interval,
                'reachability': 0,
                'delay': 0.0,
                'offset': 0.0,
                'jitter': 0.0,
            })
        return stats

    # ------------------------------------------------------------------
    # Getters — vendor-specific (MRP, HiDiscovery, extended LLDP)
    # ------------------------------------------------------------------

    def get_mrp(self):
        """Return MRP ring redundancy config from HM2-L2REDUNDANCY-MIB."""
        return asyncio.run(self._get_mrp_async())

    async def _get_mrp_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        rows = await self._walk_columns({
            'domain_name': OID_hm2MrpDomainName,
            'rp1_ifindex': OID_hm2MrpRingport1IfIndex,
            'rp1_oper': OID_hm2MrpRingport1OperState,
            'rp2_ifindex': OID_hm2MrpRingport2IfIndex,
            'rp2_oper': OID_hm2MrpRingport2OperState,
            'role_admin': OID_hm2MrpRoleAdminState,
            'role_oper': OID_hm2MrpRoleOperState,
            'recovery_delay': OID_hm2MrpRecoveryDelay,
            'delay_supported': OID_hm2MrpRecoveryDelaySupported,
            'vlan': OID_hm2MrpVlanID,
            'priority': OID_hm2MrpMRMPriority,
            'react_on_link': OID_hm2MrpMRMReactOnLinkChange,
            'ring_open_count': OID_hm2MrpMRMRingOpenCount,
            'blocked_support': OID_hm2MrpMRCBlockedSupported,
            'ring_oper': OID_hm2MrpRingOperState,
            'redundancy_oper': OID_hm2MrpRedundancyOperState,
            'config_oper': OID_hm2MrpConfigOperState,
            'row_status': OID_hm2MrpRowStatus,
            'fixed_backup': OID_hm2MrpRingport2FixedBackup,
        }, engine)

        if not rows:
            return {'configured': False}

        # Find first active row
        active_suffix = None
        active_cols = None
        for suffix, cols in rows.items():
            row_status = int(cols.get('row_status', 0))
            if row_status == 1:  # active
                active_suffix = suffix
                active_cols = cols
                break

        if active_cols is None:
            return {'configured': False}

        # Map ifIndex to interface name
        rp1_idx = str(active_cols.get('rp1_ifindex', ''))
        rp2_idx = str(active_cols.get('rp2_ifindex', ''))
        rp1_name = ifmap.get(rp1_idx, f'if{rp1_idx}')
        rp2_name = ifmap.get(rp2_idx, f'if{rp2_idx}')

        role_admin = int(active_cols.get('role_admin', 1))
        role_oper = int(active_cols.get('role_oper', 3))
        rp1_oper = int(active_cols.get('rp1_oper', 4))
        rp2_oper = int(active_cols.get('rp2_oper', 4))
        recovery = int(active_cols.get('recovery_delay', 2))
        config_oper = int(active_cols.get('config_oper', 1))

        # Domain UUID
        domain_id = _format_mrp_domain_id(active_suffix)

        # Try to get Fast MRP scalar
        try:
            fast_mrp_data = await self._get_scalar(OID_hm2MrpFastMrp)
            fast_mrp = int(fast_mrp_data.get(OID_hm2MrpFastMrp, 0)) == 1
        except Exception:
            fast_mrp = False

        result = {
            'configured': True,
            'operation': 'enabled',
            'mode': _MRP_ROLE.get(role_admin, 'undefined'),
            'mode_actual': _MRP_ROLE.get(role_oper, 'undefined'),
            'port_primary': rp1_name,
            'port_secondary': rp2_name,
            'port_primary_state': _MRP_PORT_OPER_STATE.get(rp1_oper, 'unknown'),
            'port_secondary_state': _MRP_PORT_OPER_STATE.get(rp2_oper, 'unknown'),
            'domain_id': domain_id,
            'domain_name': str(active_cols.get('domain_name', '')),
            'vlan': int(active_cols.get('vlan', 0)),
            'recovery_delay': _MRP_RECOVERY_DELAY.get(recovery, f'{recovery}'),
            'recovery_delay_supported': (
                list(_MRP_RECOVERY_DELAY.values())
                if int(active_cols.get('delay_supported', 2)) == 1
                else ['500ms', '200ms']
            ),
            'advanced_mode': int(active_cols.get('react_on_link', 0)) == 1,
            'manager_priority': int(active_cols.get('priority', 0)),
            'fixed_backup': int(active_cols.get('fixed_backup', 0)) == 1,
            'fast_mrp': fast_mrp,
            'info': _MRP_CONFIG_INFO.get(config_oper, 'unknown'),
        }

        # Manager-specific fields
        if role_admin == 2:
            ring_oper = int(active_cols.get('ring_oper', 3))
            result['ring_state'] = _MRP_RING_OPER_STATE.get(ring_oper, 'undefined')
            result['redundancy'] = int(active_cols.get('redundancy_oper', 0)) == 1
            result['ring_open_count'] = int(active_cols.get('ring_open_count', 0))

        # Client-specific fields
        if role_admin == 1:
            result['blocked_support'] = int(active_cols.get('blocked_support', 0)) == 1

        return result

    def get_hidiscovery(self):
        """Return HiDiscovery config from HM2-NETCONFIG-MIB."""
        return asyncio.run(self._get_hidiscovery_async())

    async def _get_hidiscovery_async(self):
        try:
            scalars = await self._get_scalar(
                OID_hm2HiDiscOper, OID_hm2HiDiscMode, OID_hm2HiDiscBlinking,
                OID_hm2HiDiscProtocol, OID_hm2HiDiscRelay,
            )
        except Exception:
            return {'enabled': False}

        # HmEnabledStatus: 1=enable, 2=disable
        oper_val = _snmp_int(scalars.get(OID_hm2HiDiscOper, 2))
        if oper_val != 1:
            return {'enabled': False}

        mode_val = _snmp_int(scalars.get(OID_hm2HiDiscMode, 2))
        blink_val = _snmp_int(scalars.get(OID_hm2HiDiscBlinking, 2))

        # Protocol is BITS { none(0), v1(1), v2(2) }
        # MSB-first: bit 0=0x80 (none), bit 1=0x40 (v1), bit 2=0x20 (v2)
        proto_bits = _snmp_int(scalars.get(OID_hm2HiDiscProtocol, 0))
        protocols = []
        if proto_bits & 0x40:
            protocols.append('v1')
        if proto_bits & 0x20:
            protocols.append('v2')

        result = {
            'enabled': True,
            'mode': 'read-write' if mode_val == 1 else 'read-only',
            'blinking': blink_val == 1,
            'protocols': protocols,
        }

        # Relay is only present on L3 devices — omit on L2 (matches MOPS/SSH).
        # L2 devices return NoSuchInstance for this OID.
        relay_raw = scalars.get(OID_hm2HiDiscRelay)
        if relay_raw is not None and 'NoSuch' not in type(relay_raw).__name__:
            result['relay'] = _snmp_int(relay_raw) == 1

        return result

    # ------------------------------------------------------------------
    # Config status and save (HM2-FILEMGMT-MIB)
    # ------------------------------------------------------------------

    # SNMP integer → SSH-matching string
    _NVM_STATE = {1: 'ok', 2: 'out of sync', 3: 'busy'}
    _ENVM_STATE = {1: 'ok', 2: 'out of sync', 3: 'absent'}
    _BOOT_STATE = {1: 'ok', 2: 'out of sync'}

    def get_config_status(self):
        """Check if running config is saved to NVM.

        Returns::

            {
                'saved': True,            # running-config matches NVM
                'nvm': 'ok',              # 'ok' | 'out of sync' | 'busy'
                'aca': 'absent',          # 'ok' | 'out of sync' | 'absent'
                'boot': 'ok',             # 'ok' | 'out of sync'
            }
        """
        return asyncio.run(self._get_config_status_async())

    async def _get_config_status_async(self):
        scalars = await self._get_scalar(
            OID_hm2FMNvmState, OID_hm2FMEnvmState, OID_hm2FMBootParamState,
        )
        nvm_int = int(scalars.get(OID_hm2FMNvmState, 1))
        envm_int = int(scalars.get(OID_hm2FMEnvmState, 1))
        boot_int = int(scalars.get(OID_hm2FMBootParamState, 1))

        nvm = self._NVM_STATE.get(nvm_int, f'unknown({nvm_int})')
        aca = self._ENVM_STATE.get(envm_int, f'unknown({envm_int})')
        boot = self._BOOT_STATE.get(boot_int, f'unknown({boot_int})')

        return {
            'saved': nvm == 'ok',
            'nvm': nvm,
            'aca': aca,
            'boot': boot,
        }

    def save_config(self):
        """Save running config to non-volatile memory via SNMP SET.

        Uses hm2FMActionTable: GET the advisory lock key, then SET
        the action entry to trigger copy(2) config(10) running(10) → nvm(2).
        Polls NVM state until no longer busy (up to 10s).
        Returns the post-save config status.
        """
        return asyncio.run(self._save_config_async())

    async def _save_config_async(self):
        # 1. GET the advisory lock key
        scalars = await self._get_scalar(OID_hm2FMActionActivateKey)
        key = int(scalars.get(OID_hm2FMActionActivateKey, 0))

        # 2. SET the action entry with the key to trigger save
        await self._set_scalar(OID_hm2FMActionActivate_save, Integer32(key))

        # 3. Poll until NVM is no longer busy (up to 10s)
        for _ in range(10):
            status = await self._get_config_status_async()
            if status['nvm'] != 'busy':
                return status
            await asyncio.sleep(1)

        return await self._get_config_status_async()

    def clear_config(self, keep_ip=False):
        """Clear running config (back to default) via SNMP.

        WARNING: Device warm-restarts. Connection will drop.

        Args:
            keep_ip: If True, preserve management IP address.
        """
        return asyncio.run(self._clear_config_async(keep_ip))

    async def _clear_config_async(self, keep_ip=False):
        scalars = await self._get_scalar(OID_hm2FMActionActivateKey)
        key = int(scalars.get(OID_hm2FMActionActivateKey, 0))

        param = 11 if keep_ip else 1
        await self._set_scalar(OID_hm2FMActionParameter, Integer32(param))

        try:
            await self._set_scalar(OID_hm2FMActionActivate_clear_config, Integer32(key))
        except Exception:
            pass  # device warm-restarts before responding

        return {"restarting": True}

    def clear_factory(self, erase_all=False):
        """Factory reset via SNMP. Device will reboot.

        Args:
            erase_all: If True, also regenerate factory.cfg from firmware.
                Use when factory defaults file may be corrupted.
        """
        return asyncio.run(self._clear_factory_async(erase_all))

    async def _clear_factory_async(self, erase_all=False):
        scalars = await self._get_scalar(OID_hm2FMActionActivateKey)
        key = int(scalars.get(OID_hm2FMActionActivateKey, 0))

        param = 2 if erase_all else 1
        await self._set_scalar(OID_hm2FMActionParameter, Integer32(param))

        try:
            await self._set_scalar(OID_hm2FMActionActivate_clear_factory, Integer32(key))
        except Exception:
            pass  # device reboots before responding

        return {"rebooting": True}

    def is_factory_default(self):
        """Not implemented for SNMP — factory gate blocks SNMP access.

        When the device is factory-default, hm2UserForcePasswordStatus=enable(1)
        gates all SNMP operations. Use MOPS or SSH to check/onboard instead.
        """
        raise NotImplementedError(
            "is_factory_default not available via SNMP — "
            "SNMP is gated on factory-default devices. Use MOPS or SSH.")

    def onboard(self, new_password):
        """Not implemented for SNMP — factory gate blocks SNMP access."""
        raise NotImplementedError(
            "onboard not available via SNMP — "
            "SNMP is gated on factory-default devices. Use MOPS or SSH.")

    async def _set_scalar(self, oid, value):
        """SET a single OID value.

        Appends .0 unless the OID is already fully qualified (>=14 parts).
        """
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (self.hostname, self.port), timeout=self.timeout, retries=1,
        )
        auth = self._build_auth()
        if len(oid.split('.')) >= 14:
            oid_obj = ObjectIdentity(oid)
        else:
            oid_obj = ObjectIdentity(oid + '.0')
        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            engine, auth, transport, ContextData(),
            ObjectType(oid_obj, value),
        )
        if errorIndication:
            raise ConnectionException(f"SNMP SET error: {errorIndication}")
        if errorStatus:
            raise ConnectionException(
                f"SNMP SET error: {errorStatus.prettyPrint()} at "
                f"{varBinds[int(errorIndex) - 1][0] if errorIndex else '?'}"
            )

    async def _set_oids(self, *oid_value_pairs):
        """SET multiple OID/value pairs in a single SNMP PDU.

        Each argument is a (oid_string, value) tuple.  OIDs are used
        as-is (no .0 appended) — caller must supply fully qualified OIDs.
        """
        engine = SnmpEngine()
        transport = await UdpTransportTarget.create(
            (self.hostname, self.port), timeout=self.timeout, retries=1,
        )
        auth = self._build_auth()
        object_types = [
            ObjectType(ObjectIdentity(oid), val) for oid, val in oid_value_pairs
        ]
        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            engine, auth, transport, ContextData(), *object_types,
        )
        if errorIndication:
            raise ConnectionException(f"SNMP SET error: {errorIndication}")
        if errorStatus:
            raise ConnectionException(
                f"SNMP SET error: {errorStatus.prettyPrint()} at "
                f"{varBinds[int(errorIndex) - 1][0] if errorIndex else '?'}"
            )

    # ------------------------------------------------------------------
    # Write operations — vendor-specific (MRP, HiDiscovery)
    # ------------------------------------------------------------------

    def set_interface(self, interface, enabled=None, description=None):
        """Set interface admin state and/or description via SNMP.

        Args:
            interface: port name (str) or list of port names
            enabled: True (admin up) or False (admin down), None to skip
            description: port description string, None to skip
        """
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        ifindex_map = asyncio.run(self._build_ifindex_map())
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            if enabled is not None:
                sets.append((f"{OID_ifAdminStatus}.{ifidx}",
                             Integer32(1 if enabled else 2)))
            if description is not None:
                sets.append((f"{OID_ifAlias}.{ifidx}",
                             OctetString(description)))
        if sets:
            asyncio.run(self._set_oids(*sets))

    def set_hidiscovery(self, status, blinking=None):
        """Set HiDiscovery operating mode via SNMP.

        Args:
            status: 'on' (read-write), 'off' (disabled), or 'ro' (read-only)
            blinking: True to enable, False to disable, 'toggle' to flip,
                      or None to leave unchanged
        """
        status = status.lower().strip()
        if status not in ('on', 'off', 'ro'):
            raise ValueError(f"Invalid status '{status}': use 'on', 'off', or 'ro'")
        return asyncio.run(self._set_hidiscovery_async(status, blinking))

    async def _set_hidiscovery_async(self, status, blinking=None):
        if status == 'off':
            await self._set_scalar(OID_hm2HiDiscOper, Integer32(2))  # disable
        elif status == 'on':
            await self._set_scalar(OID_hm2HiDiscOper, Integer32(1))  # enable
            await self._set_scalar(OID_hm2HiDiscMode, Integer32(1))  # readWrite
        elif status == 'ro':
            await self._set_scalar(OID_hm2HiDiscOper, Integer32(1))  # enable
            await self._set_scalar(OID_hm2HiDiscMode, Integer32(2))  # readOnly
        if blinking is not None:
            if blinking == 'toggle':
                current = await self._get_hidiscovery_async()
                blinking = not current.get('blinking', False)
            await self._set_scalar(OID_hm2HiDiscBlinking,
                                   Integer32(1 if blinking else 2))
        return await self._get_hidiscovery_async()

    def set_mrp(self, operation='enable', mode='client', port_primary=None,
                port_secondary=None, vlan=None, recovery_delay=None):
        """Configure MRP ring on the default domain via SNMP.

        Args:
            operation: 'enable' or 'disable'
            mode: 'manager' or 'client'
            port_primary: primary ring port (e.g. '1/3')
            port_secondary: secondary ring port (e.g. '1/4')
            vlan: VLAN ID for MRP domain (0-4042)
            recovery_delay: '200ms', '500ms', '30ms', or '10ms'

        Creates the default domain if none exists.
        """
        if operation not in ('enable', 'disable'):
            raise ValueError(f"operation must be 'enable' or 'disable', got '{operation}'")
        if mode not in ('manager', 'client'):
            raise ValueError(f"mode must be 'manager' or 'client', got '{mode}'")
        return asyncio.run(self._set_mrp_async(
            operation, mode, port_primary, port_secondary, vlan, recovery_delay,
        ))

    async def _set_mrp_async(self, operation, mode, port_primary, port_secondary,
                             vlan, recovery_delay):
        engine = SnmpEngine()
        sfx = MRP_DEFAULT_DOMAIN_SUFFIX

        # Build reverse ifName → ifIndex map for port resolution
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: int(idx) for idx, name in ifmap.items()}

        # Check if domain already exists
        existing = await self._walk_columns({
            'row_status': OID_hm2MrpRowStatus,
            'delay_supported': OID_hm2MrpRecoveryDelaySupported,
        }, engine)
        sfx_key = sfx.lstrip('.')
        domain_exists = sfx_key in existing

        # Validate recovery delay against device capability
        if recovery_delay and recovery_delay in ('30ms', '10ms'):
            if domain_exists:
                supported = int(existing[sfx_key].get('delay_supported', 2))
            else:
                supported = 2  # assume 200/500 only until we can check
            if supported != 1:  # supportedAll(1)
                raise ValueError(
                    f"Recovery delay '{recovery_delay}' not supported by this device "
                    f"(only 200ms and 500ms available)"
                )

        if not domain_exists:
            # Create domain in notInService state
            await self._set_oids(
                (OID_hm2MrpRowStatus + sfx, Integer32(5)),  # createAndWait
            )

        if operation == 'disable':
            # Set row to notInService (keeps config but disables)
            await self._set_oids(
                (OID_hm2MrpRowStatus + sfx, Integer32(2)),  # notInService
            )
        else:
            # Ensure row is notInService for modification
            if domain_exists:
                await self._set_oids(
                    (OID_hm2MrpRowStatus + sfx, Integer32(2)),  # notInService
                )

            # Build SET pairs for requested parameters
            sets = []
            sets.append((OID_hm2MrpRoleAdminState + sfx,
                         Integer32(_MRP_ROLE_REV[mode])))
            if port_primary:
                idx = name_to_idx.get(port_primary)
                if idx is None:
                    raise ValueError(f"Unknown port '{port_primary}'")
                sets.append((OID_hm2MrpRingport1IfIndex + sfx, Integer32(idx)))
            if port_secondary:
                idx = name_to_idx.get(port_secondary)
                if idx is None:
                    raise ValueError(f"Unknown port '{port_secondary}'")
                sets.append((OID_hm2MrpRingport2IfIndex + sfx, Integer32(idx)))
            if vlan is not None:
                sets.append((OID_hm2MrpVlanID + sfx, Integer32(int(vlan))))
            if recovery_delay:
                delay_val = _MRP_RECOVERY_DELAY_REV.get(recovery_delay)
                if delay_val is None:
                    raise ValueError(f"Invalid recovery_delay '{recovery_delay}'")
                sets.append((OID_hm2MrpRecoveryDelay + sfx, Integer32(delay_val)))

            # SET all parameters
            for oid, val in sets:
                await self._set_oids((oid, val))

            # Activate
            await self._set_oids(
                (OID_hm2MrpRowStatus + sfx, Integer32(1)),  # active
            )

        return await self._get_mrp_async()

    def delete_mrp(self):
        """Delete the MRP default domain via SNMP.

        Returns the post-deletion MRP state (should show configured=False).
        """
        return asyncio.run(self._delete_mrp_async())

    async def _delete_mrp_async(self):
        sfx = MRP_DEFAULT_DOMAIN_SUFFIX
        # First try to set notInService, then destroy
        try:
            await self._set_oids(
                (OID_hm2MrpRowStatus + sfx, Integer32(2)),  # notInService
            )
        except ConnectionException:
            pass  # Row might already be notInService or not exist
        try:
            await self._set_oids(
                (OID_hm2MrpRowStatus + sfx, Integer32(6)),  # destroy
            )
        except ConnectionException:
            pass  # Row might not exist
        return await self._get_mrp_async()

    def get_mrp_sub_ring(self):
        """Return MRP sub-ring (SRM) configuration and operating state."""
        return asyncio.run(self._get_mrp_sub_ring_async())

    async def _get_mrp_sub_ring_async(self):
        engine = SnmpEngine()

        # Global scalars
        enabled = False
        max_instances = 8
        try:
            scalar_data = await self._get_scalar(
                OID_hm2SrmGlobalAdminState, OID_hm2SrmMaxInstances)
            enabled = int(scalar_data.get(OID_hm2SrmGlobalAdminState, 2)) == 1
            max_instances = int(scalar_data.get(OID_hm2SrmMaxInstances, 8))
        except Exception:
            pass

        # Table walk
        rows = await self._walk_columns({
            'admin_state': OID_hm2SrmAdminState,
            'oper_state': OID_hm2SrmOperState,
            'vlan': OID_hm2SrmVlanID,
            'domain_id': OID_hm2SrmMRPDomainID,
            'partner_mac': OID_hm2SrmPartnerMAC,
            'protocol': OID_hm2SrmSubRingProtocol,
            'name': OID_hm2SrmSubRingName,
            'port_ifindex': OID_hm2SrmSubRingPortIfIndex,
            'port_oper': OID_hm2SrmSubRingPortOperState,
            'ring_oper': OID_hm2SrmSubRingOperState,
            'redundancy_oper': OID_hm2SrmRedundancyOperState,
            'config_oper': OID_hm2SrmConfigOperState,
            'row_status': OID_hm2SrmRowStatus,
        }, engine)

        instances = []
        if rows:
            ifmap = await self._build_ifindex_map(engine)
            for suffix, cols in rows.items():
                row_status = int(cols.get('row_status', 0))
                if row_status != 1:  # active only
                    continue

                # Index suffix is the ring_id (single integer)
                ring_id = int(suffix.lstrip('.'))
                port_idx = str(cols.get('port_ifindex', ''))
                port_name = ifmap.get(port_idx, f'if{port_idx}')

                admin_state = int(cols.get('admin_state', 1))
                oper_state = int(cols.get('oper_state', 4))
                port_oper = int(cols.get('port_oper', 4))
                ring_oper = int(cols.get('ring_oper', 1))
                redundancy = int(cols.get('redundancy_oper', 2))
                config_oper = int(cols.get('config_oper', 1))

                # Format domain ID from SNMP OctetString
                domain_raw = cols.get('domain_id', '')
                if domain_raw:
                    try:
                        domain_bytes = bytes(domain_raw)
                        domain_id = ':'.join(f'{b:02x}' for b in domain_bytes)
                    except (TypeError, ValueError):
                        domain_id = str(domain_raw)
                else:
                    domain_id = 'ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff'

                # Format partner MAC
                partner_raw = cols.get('partner_mac', '')
                if partner_raw:
                    try:
                        mac_bytes = bytes(partner_raw)
                        partner_mac = ':'.join(f'{b:02X}' for b in mac_bytes)
                    except (TypeError, ValueError):
                        partner_mac = str(partner_raw)
                else:
                    partner_mac = ''

                instances.append({
                    'ring_id': ring_id,
                    'mode': _SRM_ADMIN_STATE.get(admin_state, 'manager'),
                    'mode_actual': _SRM_OPER_STATE.get(oper_state, 'disabled'),
                    'vlan': int(cols.get('vlan', 0)),
                    'domain_id': domain_id,
                    'partner_mac': partner_mac,
                    'protocol': 'mrp' if str(
                        cols.get('protocol', 4)) == '4' else 'unknown',
                    'name': str(cols.get('name', '')),
                    'port': port_name,
                    'port_state': _SRM_PORT_OPER_STATE.get(port_oper, 'not-connected'),
                    'ring_state': _SRM_RING_OPER_STATE.get(ring_oper, 'undefined'),
                    'redundancy': _SRM_REDUNDANCY.get(redundancy, False),
                    'info': _SRM_CONFIG_INFO.get(config_oper, 'no error'),
                })

        return {
            'enabled': enabled,
            'max_instances': max_instances,
            'instances': instances,
        }

    def set_mrp_sub_ring(self, ring_id=None, enabled=None, mode='manager',
                         port=None, vlan=None, name=None):
        """Configure MRP sub-ring (SRM) via SNMP.

        Args:
            ring_id:  int — sub-ring instance ID (None = global only)
            enabled:  bool — global SRM enable/disable
            mode:     'manager', 'redundantManager', or 'singleManager'
            port:     interface name (e.g. '1/3') — single sub-ring port
            vlan:     VLAN for sub-ring (0-4042)
            name:     sub-ring name string (optional)
        """
        if mode not in _SRM_ADMIN_STATE_REV:
            raise ValueError(f"mode must be one of {list(_SRM_ADMIN_STATE_REV)}, got '{mode}'")
        return asyncio.run(self._set_mrp_sub_ring_async(
            ring_id, enabled, mode, port, vlan, name))

    async def _set_mrp_sub_ring_async(self, ring_id, enabled, mode, port, vlan, name):
        engine = SnmpEngine()

        # Global enable/disable
        if enabled is not None:
            try:
                await self._set_oids(
                    (OID_hm2SrmGlobalAdminState + '.0', Integer32(1 if enabled else 2)),
                )
            except ConnectionException:
                pass

        if ring_id is None:
            return await self._get_mrp_sub_ring_async()

        # Auto-enable global SRM when creating an instance
        if enabled is None:
            try:
                await self._set_oids(
                    (OID_hm2SrmGlobalAdminState + '.0', Integer32(1)),
                )
            except ConnectionException:
                pass

        sfx = f'.{ring_id}'

        # Check if instance exists
        existing = await self._walk_columns({
            'row_status': OID_hm2SrmRowStatus,
        }, engine)
        sfx_key = str(ring_id)
        instance_exists = sfx_key in existing

        if not instance_exists:
            try:
                await self._set_oids(
                    (OID_hm2SrmRowStatus + sfx, Integer32(5)),  # createAndWait
                )
            except ConnectionException:
                # OID doesn't exist (e.g. L2S) — can't create
                return await self._get_mrp_sub_ring_async()

        # notInService for modification
        await self._set_oids(
            (OID_hm2SrmRowStatus + sfx, Integer32(2)),
        )

        # Build SET pairs
        sets = []
        sets.append((OID_hm2SrmAdminState + sfx,
                     Integer32(_SRM_ADMIN_STATE_REV[mode])))

        if port:
            ifmap = await self._build_ifindex_map(engine)
            name_to_idx = {n: int(i) for i, n in ifmap.items()}
            pidx = name_to_idx.get(port)
            if pidx is None:
                raise ValueError(f"Unknown port '{port}'")
            sets.append((OID_hm2SrmSubRingPortIfIndex + sfx, Integer32(pidx)))

        if vlan is not None:
            sets.append((OID_hm2SrmVlanID + sfx, Integer32(int(vlan))))

        if name is not None:
            from pysnmp.proto.rfc1902 import OctetString
            sets.append((OID_hm2SrmSubRingName + sfx, OctetString(name)))

        for oid, val in sets:
            await self._set_oids((oid, val))

        # Activate
        await self._set_oids(
            (OID_hm2SrmRowStatus + sfx, Integer32(1)),  # active
        )

        return await self._get_mrp_sub_ring_async()

    def delete_mrp_sub_ring(self, ring_id=None):
        """Delete sub-ring instance or disable SRM globally via SNMP.

        Args:
            ring_id: int — specific instance to delete (None = disable globally)
        """
        return asyncio.run(self._delete_mrp_sub_ring_async(ring_id))

    async def _delete_mrp_sub_ring_async(self, ring_id):
        if ring_id is None:
            # Disable SRM globally
            try:
                await self._set_oids(
                    (OID_hm2SrmGlobalAdminState + '.0', Integer32(2)),
                )
            except ConnectionException:
                pass
            return await self._get_mrp_sub_ring_async()

        sfx = f'.{ring_id}'
        try:
            await self._set_oids(
                (OID_hm2SrmRowStatus + sfx, Integer32(2)),  # notInService
            )
        except ConnectionException:
            pass
        try:
            await self._set_oids(
                (OID_hm2SrmRowStatus + sfx, Integer32(6)),  # destroy
            )
        except ConnectionException:
            pass
        return await self._get_mrp_sub_ring_async()

    def get_lldp_neighbors_detail_extended(self, interface=''):
        """Return extended LLDP detail with 802.1/802.3 extension data."""
        return asyncio.run(self._get_lldp_neighbors_detail_extended_async(interface))

    async def _get_lldp_neighbors_detail_extended_async(self, interface=''):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        loc_ports = await self._walk(OID_lldpLocPortId, engine)

        # Walk standard LLDP columns + management address table
        # and extension tables in parallel
        std_task = self._walk_columns({
            'chassisid_subtype': OID_lldpRemChassisIdSubtype,
            'chassisid': OID_lldpRemChassisId,
            'portid_subtype': OID_lldpRemPortIdSubtype,
            'portid': OID_lldpRemPortId,
            'portdesc': OID_lldpRemPortDesc,
            'sysname': OID_lldpRemSysName,
            'sysdesc': OID_lldpRemSysDesc,
            'caps_supported': OID_lldpRemSysCapSupported,
            'caps_enabled': OID_lldpRemSysCapEnabled,
        }, engine)
        mgmt_task = self._walk(OID_lldpRemManAddrIfSubtype, engine)

        # 802.3 extension walks (may not exist on older firmware)
        async def _safe_walk_columns(oid_map):
            try:
                return await self._walk_columns(oid_map, engine)
            except Exception:
                return {}

        async def _safe_walk(oid):
            try:
                return await self._walk(oid, engine)
            except Exception:
                return {}

        dot3_autoneg_task = _safe_walk_columns({
            'autoneg_sup': OID_lldpXdot3RemPortAutoNegSupported,
            'autoneg_en': OID_lldpXdot3RemPortAutoNegEnabled,
            'mau_type': OID_lldpXdot3RemPortOperMauType,
        })
        dot3_agg_task = _safe_walk_columns({
            'agg_status': OID_lldpXdot3RemLinkAggStatus,
            'agg_port_id': OID_lldpXdot3RemLinkAggPortId,
        })
        dot1_pvid_task = _safe_walk(OID_lldpXdot1RemPortVlanId)
        dot1_vlan_task = _safe_walk(OID_lldpXdot1RemVlanId)

        std_rows, mgmt_data, dot3_autoneg, dot3_agg, dot1_pvid, dot1_vlans = (
            await asyncio.gather(
                std_task, mgmt_task,
                dot3_autoneg_task, dot3_agg_task,
                dot1_pvid_task, dot1_vlan_task,
            )
        )

        # Re-index extension data by localPort.remIndex (timeMarks differ
        # between standard and extension tables)
        def _reindex_by_port_rem(data):
            """Re-key {timeMark.localPort.remIndex: val} → {localPort.remIndex: val}."""
            result = {}
            for suffix, val in data.items():
                parts = suffix.split('.', 1)
                if len(parts) >= 2:
                    result[parts[1]] = val  # localPort.remIndex...
            return result

        dot3_autoneg = _reindex_by_port_rem(dot3_autoneg)
        dot3_agg = _reindex_by_port_rem(dot3_agg)
        dot1_pvid = _reindex_by_port_rem(dot1_pvid)
        dot1_vlans = _reindex_by_port_rem(dot1_vlans)

        neighbors = {}
        for suffix, cols in std_rows.items():
            parts = suffix.split('.')
            if len(parts) < 3:
                continue
            time_mark = parts[0]
            local_port_num = parts[1]
            rem_index = parts[2]

            local_iface = ifmap.get(local_port_num)
            if not local_iface:
                loc_val = loc_ports.get(local_port_num)
                local_iface = str(loc_val) if loc_val else f'port{local_port_num}'

            if interface and local_iface != interface:
                continue

            sysname = str(cols.get('sysname', ''))
            chassisid_raw = cols.get('chassisid', b'')
            chassisid = _format_mac(chassisid_raw) or str(chassisid_raw)
            portid_raw = cols.get('portid', b'')
            portid = str(portid_raw)
            if portid_raw and hasattr(portid_raw, 'hasValue') and portid_raw.hasValue():
                raw_bytes = bytes(portid_raw)
                if raw_bytes and not all(0x20 <= b < 0x7f for b in raw_bytes):
                    portid = _format_mac(portid_raw)
            portdesc = str(cols.get('portdesc', ''))

            caps_sup = _decode_capabilities(cols.get('caps_supported', b''))
            caps_en = _decode_capabilities(cols.get('caps_enabled', b''))

            # Management addresses
            mgmt_addresses = []
            mgmt_ipv4 = ''
            mgmt_ipv6 = ''
            prefix = f'{time_mark}.{local_port_num}.{rem_index}.'
            for mgmt_suffix, mgmt_val in mgmt_data.items():
                if mgmt_suffix.startswith(prefix):
                    addr_part = mgmt_suffix[len(prefix):]
                    addr_parts = addr_part.split('.')
                    if len(addr_parts) >= 6 and addr_parts[0] == '1':
                        ip = '.'.join(addr_parts[2:6])
                        mgmt_addresses.append(ip)
                        if not mgmt_ipv4:
                            mgmt_ipv4 = ip
                    elif len(addr_parts) >= 18 and addr_parts[0] == '2':
                        # IPv6: subtype=2, len=16, then 16 octets
                        octets = addr_parts[2:18]
                        try:
                            raw = bytes(int(o) for o in octets)
                            ipv6 = str(ipaddress.IPv6Address(raw))
                            mgmt_addresses.append(ipv6)
                            if not mgmt_ipv6:
                                mgmt_ipv6 = ipv6
                        except (ValueError, IndexError):
                            pass

            # Extension data keyed by localPort.remIndex (timeMarks stripped)
            port_rem_key = f'{local_port_num}.{rem_index}'

            # 802.3 autoneg data
            autoneg = dot3_autoneg.get(port_rem_key, {})
            autoneg_sup_raw = autoneg.get('autoneg_sup', None)
            autoneg_en_raw = autoneg.get('autoneg_en', None)
            mau_type_raw = str(autoneg.get('mau_type', ''))

            # Parse MAU type OID to human-readable
            mau_type_str = ''
            if mau_type_raw:
                mau_suffix = mau_type_raw.rsplit('.', 1)[-1] if '.' in mau_type_raw else mau_type_raw
                mau_type_str = _MAU_TYPES.get(mau_suffix, mau_type_raw)

            # TruthValue: 1=true, 2=false (may come as bytes from pysnmp)
            # Use yes/no to match SSH output format
            autoneg_sup_str = ''
            if autoneg_sup_raw is not None:
                autoneg_sup_str = 'yes' if _snmp_int(autoneg_sup_raw) == 1 else 'no'
            autoneg_en_str = ''
            if autoneg_en_raw is not None:
                autoneg_en_str = 'yes' if _snmp_int(autoneg_en_raw) == 1 else 'no'

            # 802.3 link aggregation
            agg = dot3_agg.get(port_rem_key, {})
            agg_status_raw = agg.get('agg_status', None)
            agg_port_id = str(agg.get('agg_port_id', '0'))
            agg_status_str = ''
            if agg_status_raw is not None:
                agg_bits = _snmp_int(agg_status_raw)
                # BITS encoding: bit 0 (MSB, 0x80) = aggregationCapable
                #                bit 1 (0x40) = aggregationPortStatus (active)
                if agg_bits & 0xC0 == 0xC0:
                    agg_status_str = 'agg. active'
                elif agg_bits & 0x80:
                    agg_status_str = 'agg. capable'
                else:
                    agg_status_str = 'not capable'

            # 802.1 PVID
            pvid_val = dot1_pvid.get(port_rem_key, '')
            pvid_str = str(pvid_val) if pvid_val != '' else '0'

            # 802.1 VLAN membership — collect all VLANs for this neighbor
            vlan_membership = []
            vlan_prefix = f'{local_port_num}.{rem_index}.'
            for vlan_suffix, vlan_val in dot1_vlans.items():
                if vlan_suffix.startswith(vlan_prefix):
                    vlan_part = vlan_suffix[len(vlan_prefix):]
                    try:
                        vlan_membership.append(int(vlan_part))
                    except ValueError:
                        pass
            vlan_membership.sort()

            detail = {
                'parent_interface': local_iface,
                'remote_chassis_id': chassisid,
                'remote_system_name': sysname,
                'remote_system_description': str(cols.get('sysdesc', '')),
                'remote_port': portid,
                'remote_port_description': portdesc,
                'remote_system_capab': caps_sup,
                'remote_system_enable_capab': caps_en,
                'remote_management_ipv4': mgmt_ipv4,
                'remote_management_ipv6': mgmt_ipv6,
                'management_addresses': mgmt_addresses,
                'autoneg_support': autoneg_sup_str,
                'autoneg_enabled': autoneg_en_str,
                'port_oper_mau_type': mau_type_str,
                'port_vlan_id': pvid_str,
                'vlan_membership': vlan_membership,
                'link_agg_status': agg_status_str,
                'link_agg_port_id': agg_port_id,
            }
            neighbors.setdefault(local_iface, []).append(detail)
        return neighbors

    # ------------------------------------------------------------------
    # Profile management (HM2-FILEMGMT-MIB profile table)
    # ------------------------------------------------------------------

    _STORAGE_TYPE = {'nvm': 1, 'envm': 2}

    def get_profiles(self, storage='nvm'):
        """List config profiles on the device.

        Args:
            storage: 'nvm' (internal flash) or 'envm' (external memory card)

        Returns list of dicts::

            [{
                'index': 1,
                'name': 'config',
                'active': True,
                'datetime': '2026-02-13 13:25:16',
                'firmware': '09.4.04',
                'fingerprint': '9244C58F...',
                'fingerprint_verified': True,
                'encrypted': False,
                'encryption_verified': False,
            }]
        """
        storage_int = self._STORAGE_TYPE.get(storage)
        if storage_int is None:
            raise ValueError(f"Invalid storage '{storage}': use 'nvm' or 'envm'")
        return asyncio.run(self._get_profiles_async(storage_int))

    async def _get_profiles_async(self, storage_filter):
        from datetime import datetime, timezone
        rows = await self._walk_columns({
            'storage': OID_hm2FMProfileStorageType,
            'index': OID_hm2FMProfileIndex,
            'name': OID_hm2FMProfileName,
            'datetime': OID_hm2FMProfileDateTime,
            'active': OID_hm2FMProfileActive,
            'enc_active': OID_hm2FMProfileEncryptionActive,
            'enc_verified': OID_hm2FMProfileEncryptionVerified,
            'sw_major': OID_hm2FMProfileSwMajorRelNum,
            'sw_minor': OID_hm2FMProfileSwMinorRelNum,
            'sw_bugfix': OID_hm2FMProfileSwBugfixRelNum,
            'fingerprint': OID_hm2FMProfileFingerprint,
            'fp_verified': OID_hm2FMProfileFingerprintVerified,
        })

        profiles = []
        for suffix, cols in rows.items():
            storage_type = _snmp_int(cols.get('storage', 0))
            if storage_type != storage_filter:
                continue

            # Parse epoch timestamp
            epoch = _snmp_int(cols.get('datetime', 0))
            if epoch > 0:
                dt_str = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
                    '%Y-%m-%d %H:%M:%S'
                )
            else:
                dt_str = ''

            # Build firmware version string
            major = _snmp_int(cols.get('sw_major', 0))
            minor = _snmp_int(cols.get('sw_minor', 0))
            bugfix = _snmp_int(cols.get('sw_bugfix', 0))
            fw = f'{major:02d}.{minor}.{bugfix:02d}' if major else ''

            fp_raw = str(cols.get('fingerprint', '')).strip()
            # Clean up hex prefixes
            if fp_raw.startswith('0x'):
                fp_raw = fp_raw[2:]

            profiles.append({
                'index': _snmp_int(cols.get('index', 0)),
                'name': str(cols.get('name', '')).strip(),
                'active': _snmp_int(cols.get('active', 2)) == 1,
                'datetime': dt_str,
                'firmware': fw,
                'fingerprint': fp_raw.upper(),
                'fingerprint_verified': _snmp_int(cols.get('fp_verified', 2)) == 1,
                'encrypted': _snmp_int(cols.get('enc_active', 2)) == 1,
                'encryption_verified': _snmp_int(cols.get('enc_verified', 2)) == 1,
            })

        profiles.sort(key=lambda p: p['index'])
        return profiles

    def get_config_fingerprint(self):
        """Return the SHA1 fingerprint of the active NVM profile.

        Returns::

            {'fingerprint': '9244C58FEA7549A1...', 'verified': True}
        """
        profiles = self.get_profiles('nvm')
        for p in profiles:
            if p['active']:
                return {
                    'fingerprint': p['fingerprint'],
                    'verified': p['fingerprint_verified'],
                }
        return {'fingerprint': '', 'verified': False}

    def activate_profile(self, storage='nvm', index=1):
        """Activate a config profile. Note: causes a warm restart.

        Args:
            storage: 'nvm' or 'envm'
            index: profile index (1-100)

        Returns the updated profile list.
        """
        storage_int = self._STORAGE_TYPE.get(storage)
        if storage_int is None:
            raise ValueError(f"Invalid storage '{storage}': use 'nvm' or 'envm'")
        return asyncio.run(self._activate_profile_async(storage_int, index))

    async def _activate_profile_async(self, storage_int, index):
        oid = f'{OID_hm2FMProfileActive}.{storage_int}.{index}'
        await self._set_oids((oid, Integer32(1)))
        return await self._get_profiles_async(storage_int)

    def delete_profile(self, storage='nvm', index=1):
        """Delete a config profile. Cannot delete the active profile.

        Args:
            storage: 'nvm' or 'envm'
            index: profile index (1-100)

        Returns the updated profile list.
        """
        storage_int = self._STORAGE_TYPE.get(storage)
        if storage_int is None:
            raise ValueError(f"Invalid storage '{storage}': use 'nvm' or 'envm'")
        # Check the profile is not active
        profiles = self.get_profiles(storage)
        for p in profiles:
            if p['index'] == index and p['active']:
                raise ValueError(f"Cannot delete active profile {index}")
        return asyncio.run(self._delete_profile_async(storage_int, index))

    async def _delete_profile_async(self, storage_int, index):
        oid = f'{OID_hm2FMProfileAction}.{storage_int}.{index}'
        await self._set_oids((oid, Integer32(2)))  # delete(2)
        return await self._get_profiles_async(storage_int)

    # ------------------------------------------------------------------
    # Config watchdog (HM2-FILEMGMT-MIB)
    # ------------------------------------------------------------------

    def start_watchdog(self, seconds):
        """Start the config watchdog timer.

        If the timer expires before stop_watchdog() is called, the device
        reverts to the saved config (NVM) automatically.

        Args:
            seconds: timer interval (30-600)
        """
        if not (30 <= seconds <= 600):
            raise ValueError(f"Watchdog interval must be 30-600, got {seconds}")
        return asyncio.run(self._start_watchdog_async(seconds))

    async def _start_watchdog_async(self, seconds):
        await self._set_scalar(OID_hm2ConfigWatchdogTimeInterval, Integer32(seconds))
        await self._set_scalar(OID_hm2ConfigWatchdogAdminStatus, Integer32(1))  # enable

    def stop_watchdog(self):
        """Stop (disable) the config watchdog timer."""
        return asyncio.run(self._stop_watchdog_async())

    async def _stop_watchdog_async(self):
        await self._set_scalar(OID_hm2ConfigWatchdogAdminStatus, Integer32(2))  # disable

    def get_watchdog_status(self):
        """Read config watchdog state.

        Returns::

            {
                'enabled': True,
                'oper_status': 1,
                'interval': 60,
                'remaining': 45,
            }
        """
        return asyncio.run(self._get_watchdog_status_async())

    async def _get_watchdog_status_async(self):
        scalars = await self._get_scalar(
            OID_hm2ConfigWatchdogAdminStatus,
            OID_hm2ConfigWatchdogOperStatus,
            OID_hm2ConfigWatchdogTimeInterval,
            OID_hm2ConfigWatchdogTimerValue,
        )
        return {
            'enabled': _snmp_int(scalars.get(OID_hm2ConfigWatchdogAdminStatus, 2)) == 1,
            'oper_status': _snmp_int(scalars.get(OID_hm2ConfigWatchdogOperStatus, 2)),
            'interval': _snmp_int(scalars.get(OID_hm2ConfigWatchdogTimeInterval, 0)),
            'remaining': _snmp_int(scalars.get(OID_hm2ConfigWatchdogTimerValue, 0)),
        }

    # ------------------------------------------------------------------
    # Auto-Disable
    # ------------------------------------------------------------------

    def get_auto_disable(self):
        """Return auto-disable state: per-port table + per-reason table."""
        return asyncio.run(self._get_auto_disable_async())

    async def _get_auto_disable_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        intf_rows = await self._walk_columns({
            'timer': OID_hm2AutoDisableIntfTimer,
            'remaining_time': OID_hm2AutoDisableIntfRemainingTime,
            'component': OID_hm2AutoDisableIntfComponentName,
            'reason': OID_hm2AutoDisableIntfErrorReason,
            'oper_state': OID_hm2AutoDisableIntfOperState,
            'error_time': OID_hm2AutoDisableIntfErrorTime,
        }, engine)

        reason_rows = await self._walk_columns({
            'operation': OID_hm2AutoDisableReasonOperation,
            'category': OID_hm2AutoDisableReasonCategory,
        }, engine)

        interfaces = {}
        for suffix, cols in intf_rows.items():
            name = ifmap.get(suffix, '')
            if not name or name.startswith('cpu') or name.startswith('vlan'):
                continue
            component = str(cols.get('component', ''))
            if component == '-':
                component = ''
            reason_code = _snmp_int(cols.get('reason', 0))
            interfaces[name] = {
                'timer': _snmp_int(cols.get('timer', 0)),
                'remaining_time': _snmp_int(cols.get('remaining_time', 0)),
                'component': component,
                'reason': _AUTO_DISABLE_REASONS.get(reason_code, 'none'),
                'active': _snmp_int(cols.get('oper_state', 2)) == 1,
                'error_time': _snmp_int(cols.get('error_time', 0)),
            }

        reasons = {}
        for suffix, cols in reason_rows.items():
            reason_idx = int(suffix)
            reason_name = _AUTO_DISABLE_REASONS.get(reason_idx, '')
            if not reason_name or reason_name == 'none':
                continue
            cat_code = _snmp_int(cols.get('category', 1))
            reasons[reason_name] = {
                'enabled': _snmp_int(cols.get('operation', 2)) == 1,
                'category': _AUTO_DISABLE_CATEGORY.get(cat_code, 'other'),
            }

        return {'interfaces': interfaces, 'reasons': reasons}

    def set_auto_disable(self, interface, timer=0):
        """Set auto-disable recovery timer for one or more ports.

        Args:
            interface: port name (str) or list of port names
        """
        return asyncio.run(self._set_auto_disable_async(interface, timer))

    async def _set_auto_disable_async(self, interface, timer):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: idx for idx, name in ifmap.items()}

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            sets.append((f"{OID_hm2AutoDisableIntfTimer}.{ifidx}",
                         Unsigned32(int(timer))))
        if sets:
            await self._set_oids(*sets)

    def reset_auto_disable(self, interface):
        """Manually re-enable one or more auto-disabled ports.

        Args:
            interface: port name (str) or list of port names
        """
        return asyncio.run(self._reset_auto_disable_async(interface))

    async def _reset_auto_disable_async(self, interface):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: idx for idx, name in ifmap.items()}

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            sets.append((f"{OID_hm2AutoDisableIntfReset}.{ifidx}",
                         Integer32(1)))
        if sets:
            await self._set_oids(*sets)

    def set_auto_disable_reason(self, reason, enabled=True):
        """Enable or disable auto-disable recovery for a specific reason type."""
        return asyncio.run(self._set_auto_disable_reason_async(reason, enabled))

    async def _set_auto_disable_reason_async(self, reason, enabled):
        reason_idx = _AUTO_DISABLE_REASONS_REV.get(reason)
        if reason_idx is None:
            raise ValueError(
                f"Unknown reason '{reason}': use one of "
                f"{list(_AUTO_DISABLE_REASONS_REV.keys())}")
        await self._set_oids(
            (f"{OID_hm2AutoDisableReasonOperation}.{reason_idx}",
             Integer32(1 if enabled else 2)),
        )

    # ------------------------------------------------------------------
    # Loop Protection (Keepalive)
    # ------------------------------------------------------------------

    def get_loop_protection(self):
        """Return loop protection configuration and state."""
        return asyncio.run(self._get_loop_protection_async())

    async def _get_loop_protection_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        scalars = await self._get_scalar(
            OID_hm2KeepaliveState,
            OID_hm2KeepaliveTransmitInterval,
            OID_hm2KeepaliveRxThreshold,
        )

        port_rows = await self._walk_columns({
            'state': OID_hm2KeepalivePortState,
            'mode': OID_hm2KeepalivePortMode,
            'action': OID_hm2KeepalivePortRxAction,
            'vlan_id': OID_hm2KeepalivePortVlanId,
            'tpid_type': OID_hm2KeepalivePortTpidType,
            'loop_detected': OID_hm2KeepalivePortLoopDetected,
            'loop_count': OID_hm2KeepalivePortLoopCount,
            'last_loop_time': OID_hm2KeepalivePortLastLoopTime,
            'tx_frames': OID_hm2KeepalivePortTxFrames,
            'rx_frames': OID_hm2KeepalivePortRxFrames,
            'discard_frames': OID_hm2KeepalivePortDiscardFrames,
        }, engine)

        interfaces = {}
        for suffix, cols in port_rows.items():
            name = ifmap.get(suffix, '')
            if not name or name.startswith('cpu') or name.startswith('vlan'):
                continue
            action_code = _snmp_int(cols.get('action', 11))
            mode_code = _snmp_int(cols.get('mode', 2))
            tpid_code = _snmp_int(cols.get('tpid_type', 0))

            # DateAndTime is OctetString — decode to ISO string
            last_time_raw = cols.get('last_loop_time', None)
            last_time = _decode_snmp_date_time(last_time_raw)

            interfaces[name] = {
                'enabled': _snmp_int(cols.get('state', 2)) == 1,
                'mode': _LOOP_PROT_MODE.get(mode_code, 'passive'),
                'action': _LOOP_PROT_ACTION.get(action_code, 'auto-disable'),
                'vlan_id': _snmp_int(cols.get('vlan_id', 0)),
                'tpid_type': _LOOP_PROT_TPID.get(tpid_code, 'none'),
                'loop_detected': _snmp_int(cols.get('loop_detected', 2)) == 1,
                'loop_count': _snmp_int(cols.get('loop_count', 0)),
                'last_loop_time': last_time,
                'tx_frames': _snmp_int(cols.get('tx_frames', 0)),
                'rx_frames': _snmp_int(cols.get('rx_frames', 0)),
                'discard_frames': _snmp_int(cols.get('discard_frames', 0)),
            }

        return {
            'enabled': _snmp_int(scalars.get(OID_hm2KeepaliveState, 2)) == 1,
            'transmit_interval': _snmp_int(
                scalars.get(OID_hm2KeepaliveTransmitInterval, 5)),
            'receive_threshold': _snmp_int(
                scalars.get(OID_hm2KeepaliveRxThreshold, 1)),
            'interfaces': interfaces,
        }

    def set_loop_protection(self, interface=None, enabled=None, mode=None,
                            action=None, vlan_id=None,
                            transmit_interval=None, receive_threshold=None):
        """Set loop protection configuration.

        Args:
            interface: port name (str), list of port names, or None for global
        """
        return asyncio.run(self._set_loop_protection_async(
            interface, enabled, mode, action, vlan_id,
            transmit_interval, receive_threshold,
        ))

    async def _set_loop_protection_async(self, interface, enabled, mode,
                                          action, vlan_id,
                                          transmit_interval, receive_threshold):
        if interface is not None:
            interfaces = ([interface] if isinstance(interface, str)
                          else list(interface))
            engine = SnmpEngine()
            ifmap = await self._build_ifindex_map(engine)
            name_to_idx = {name: idx for idx, name in ifmap.items()}

            # Validate mode/action once
            mode_val = None
            if mode is not None:
                mode_val = _LOOP_PROT_MODE_REV.get(mode)
                if mode_val is None:
                    raise ValueError(
                        f"Invalid mode '{mode}': use 'active' or 'passive'")
            action_val = None
            if action is not None:
                action_val = _LOOP_PROT_ACTION_REV.get(action)
                if action_val is None:
                    raise ValueError(
                        f"Invalid action '{action}': use 'trap', "
                        f"'auto-disable', or 'all'")

            sets = []
            for iface in interfaces:
                ifidx = name_to_idx.get(iface)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{iface}'")
                if enabled is not None:
                    sets.append((f"{OID_hm2KeepalivePortState}.{ifidx}",
                                 Integer32(1 if enabled else 2)))
                if mode_val is not None:
                    sets.append((f"{OID_hm2KeepalivePortMode}.{ifidx}",
                                 Integer32(mode_val)))
                if action_val is not None:
                    sets.append((f"{OID_hm2KeepalivePortRxAction}.{ifidx}",
                                 Integer32(action_val)))
                if vlan_id is not None:
                    sets.append((f"{OID_hm2KeepalivePortVlanId}.{ifidx}",
                                 Integer32(int(vlan_id))))

            if sets:
                await self._set_oids(*sets)
        else:
            sets = []
            if enabled is not None:
                sets.append((OID_hm2KeepaliveState,
                             Integer32(1 if enabled else 2)))
            if transmit_interval is not None:
                sets.append((OID_hm2KeepaliveTransmitInterval,
                             Integer32(int(transmit_interval))))
            if receive_threshold is not None:
                sets.append((OID_hm2KeepaliveRxThreshold,
                             Integer32(int(receive_threshold))))

            if sets:
                await self._set_oids(*sets)

    # ── Storm Control ─────────────────────────────────────────────

    _STORM_UNIT = {1: 'percent', 2: 'pps'}
    _STORM_UNIT_REV = {'percent': 1, 'pps': 2}
    _STORM_BUCKET = {1: 'single-bucket', 2: 'multi-bucket'}

    def get_storm_control(self):
        """Return per-port storm control configuration."""
        return asyncio.run(self._get_storm_control_async())

    async def _get_storm_control_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        scalars = await self._get_scalar(OID_hm2StormBucketType)
        bucket_code = _snmp_int(scalars.get(OID_hm2StormBucketType, 1))

        port_rows = await self._walk_columns({
            'unit': OID_hm2StormCtlThresholdUnit,
            'bcast_mode': OID_hm2StormCtlBcastMode,
            'bcast_threshold': OID_hm2StormCtlBcastThreshold,
            'mcast_mode': OID_hm2StormCtlMcastMode,
            'mcast_threshold': OID_hm2StormCtlMcastThreshold,
            'ucast_mode': OID_hm2StormCtlUcastMode,
            'ucast_threshold': OID_hm2StormCtlUcastThreshold,
        }, engine)

        interfaces = {}
        for suffix, cols in port_rows.items():
            name = ifmap.get(suffix, '')
            if not name or name.startswith('cpu') or name.startswith('vlan'):
                continue
            interfaces[name] = {
                'unit': self._STORM_UNIT.get(
                    _snmp_int(cols.get('unit', 1)), 'percent'),
                'broadcast': {
                    'enabled': _snmp_int(cols.get('bcast_mode', 2)) == 1,
                    'threshold': _snmp_int(cols.get('bcast_threshold', 0)),
                },
                'multicast': {
                    'enabled': _snmp_int(cols.get('mcast_mode', 2)) == 1,
                    'threshold': _snmp_int(cols.get('mcast_threshold', 0)),
                },
                'unicast': {
                    'enabled': _snmp_int(cols.get('ucast_mode', 2)) == 1,
                    'threshold': _snmp_int(cols.get('ucast_threshold', 0)),
                },
            }

        return {
            'bucket_type': self._STORM_BUCKET.get(bucket_code,
                                                   'single-bucket'),
            'interfaces': interfaces,
        }

    def set_storm_control(self, interface, unit=None,
                          broadcast_enabled=None, broadcast_threshold=None,
                          multicast_enabled=None, multicast_threshold=None,
                          unicast_enabled=None, unicast_threshold=None):
        """Set per-port storm control configuration."""
        return asyncio.run(self._set_storm_control_async(
            interface, unit, broadcast_enabled, broadcast_threshold,
            multicast_enabled, multicast_threshold,
            unicast_enabled, unicast_threshold,
        ))

    async def _set_storm_control_async(self, interface, unit,
                                        broadcast_enabled, broadcast_threshold,
                                        multicast_enabled, multicast_threshold,
                                        unicast_enabled, unicast_threshold):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: idx for idx, name in ifmap.items()}

        if unit is not None:
            unit_val = self._STORM_UNIT_REV.get(unit)
            if unit_val is None:
                raise ValueError(
                    f"Invalid unit '{unit}': use 'percent' or 'pps'")

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            if unit is not None:
                sets.append((f"{OID_hm2StormCtlThresholdUnit}.{ifidx}",
                             Integer32(unit_val)))
            if broadcast_enabled is not None:
                sets.append((f"{OID_hm2StormCtlBcastMode}.{ifidx}",
                             Integer32(1 if broadcast_enabled else 2)))
            if broadcast_threshold is not None:
                sets.append((f"{OID_hm2StormCtlBcastThreshold}.{ifidx}",
                             Unsigned32(int(broadcast_threshold))))
            if multicast_enabled is not None:
                sets.append((f"{OID_hm2StormCtlMcastMode}.{ifidx}",
                             Integer32(1 if multicast_enabled else 2)))
            if multicast_threshold is not None:
                sets.append((f"{OID_hm2StormCtlMcastThreshold}.{ifidx}",
                             Unsigned32(int(multicast_threshold))))
            if unicast_enabled is not None:
                sets.append((f"{OID_hm2StormCtlUcastMode}.{ifidx}",
                             Integer32(1 if unicast_enabled else 2)))
            if unicast_threshold is not None:
                sets.append((f"{OID_hm2StormCtlUcastThreshold}.{ifidx}",
                             Unsigned32(int(unicast_threshold))))

        if sets:
            await self._set_oids(*sets)

    # ── sFlow ────────────────────────────────────────────────────

    # DataSource OID prefix for ifTable: 1.3.6.1.2.1.2.2.1.1
    # When used as a table index, encoded with length prefix:
    #   suffix = {oid_len}.1.3.6.1.2.1.2.2.1.1.{ifIndex}.{instance}
    _SFLOW_DS_PREFIX = '1.3.6.1.2.1.2.2.1.1'
    _SFLOW_DS_PARTS = 10  # number of components in the prefix

    @staticmethod
    def _sflow_suffix_to_ifindex(suffix):
        """Extract ifIndex from sFlow sampler/poller table suffix.

        Suffix format: {oid_len}.1.3.6.1.2.1.2.2.1.1.{ifIndex}.{instance}
        The OID length (11 for standard ifTable DataSource) is the first
        element. ifIndex is the last component of the DataSource OID,
        at position oid_len in the parts array (1-indexed within OID).
        """
        parts = suffix.split('.')
        if len(parts) < 3:
            return None
        try:
            oid_len = int(parts[0])
        except ValueError:
            return None
        # ifIndex is at parts[oid_len] (last OID component)
        if len(parts) > oid_len:
            return parts[oid_len]
        return None

    @staticmethod
    def _sflow_ds_suffix(ifidx, instance=1):
        """Build sFlow DataSource table suffix for SET.

        Returns: '11.1.3.6.1.2.1.2.2.1.1.{ifidx}.{instance}'
        """
        ds_oid = f'1.3.6.1.2.1.2.2.1.1.{ifidx}'
        ds_len = len(ds_oid.split('.'))
        return f'{ds_len}.{ds_oid}.{instance}'

    def get_sflow(self):
        """Return sFlow agent info and receiver table."""
        return asyncio.run(self._get_sflow_async())

    async def _get_sflow_async(self):
        engine = SnmpEngine()

        scalars = await self._get_scalar(
            OID_sFlowVersion, OID_sFlowAgentAddress)

        rcvr_rows = await self._walk_columns({
            'owner': OID_sFlowRcvrOwner,
            'timeout': OID_sFlowRcvrTimeout,
            'max_datagram_size': OID_sFlowRcvrMaxDgramSize,
            'address_type': OID_sFlowRcvrAddressType,
            'address': OID_sFlowRcvrAddress,
            'port': OID_sFlowRcvrPort,
            'datagram_version': OID_sFlowRcvrDgramVersion,
        }, engine)

        receivers = {}
        for suffix, cols in rcvr_rows.items():
            idx = _snmp_int(suffix)
            if idx < 1:
                continue
            receivers[idx] = {
                'owner': _snmp_str(cols.get('owner', '')),
                'timeout': _snmp_int(cols.get('timeout', 0)),
                'max_datagram_size': _snmp_int(
                    cols.get('max_datagram_size', 1400)),
                'address_type': _snmp_int(
                    cols.get('address_type', 1)),
                'address': _snmp_ip(cols.get('address', '')),
                'port': _snmp_int(cols.get('port', 6343)),
                'datagram_version': _snmp_int(
                    cols.get('datagram_version', 5)),
            }

        return {
            'agent_version': _snmp_str(
                scalars.get(OID_sFlowVersion, '')),
            'agent_address': _snmp_ip(
                scalars.get(OID_sFlowAgentAddress, '')),
            'receivers': receivers,
        }

    def set_sflow(self, receiver, address=None, port=None, owner=None,
                  timeout=None, max_datagram_size=None):
        """Configure an sFlow receiver."""
        return asyncio.run(self._set_sflow_async(
            receiver, address, port, owner, timeout, max_datagram_size))

    async def _set_sflow_async(self, receiver, address, port, owner,
                               timeout, max_datagram_size):
        if not 1 <= receiver <= 8:
            raise ValueError(f"receiver must be 1-8, got {receiver}")

        idx = str(receiver)

        # Owner + timeout must be set atomically (RFC 3176).
        # Send as one PDU when both provided, or owner alone if
        # timeout is omitted.
        if owner is not None:
            owner_sets = [
                (f"{OID_sFlowRcvrOwner}.{idx}",
                 OctetString(owner.encode('utf-8')))]
            if timeout is not None:
                owner_sets.append(
                    (f"{OID_sFlowRcvrTimeout}.{idx}",
                     Integer32(int(timeout))))
                timeout = None  # already sent
            await self._set_oids(*owner_sets)

        sets = []
        if address is not None:
            raw = bytes(int(o) for o in address.split('.'))
            sets.append((f"{OID_sFlowRcvrAddress}.{idx}",
                         OctetString(raw)))
            sets.append((f"{OID_sFlowRcvrAddressType}.{idx}",
                         Integer32(1)))  # ipv4
        if port is not None:
            sets.append((f"{OID_sFlowRcvrPort}.{idx}",
                         Integer32(int(port))))
        if timeout is not None:
            sets.append((f"{OID_sFlowRcvrTimeout}.{idx}",
                         Integer32(int(timeout))))
        if max_datagram_size is not None:
            sets.append((f"{OID_sFlowRcvrMaxDgramSize}.{idx}",
                         Integer32(int(max_datagram_size))))

        if sets:
            await self._set_oids(*sets)

    def get_sflow_port(self, interfaces=None, type=None):
        """Return sFlow sampler and poller config per port."""
        return asyncio.run(self._get_sflow_port_async(interfaces, type))

    async def _get_sflow_port_async(self, interfaces, type_filter):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        iface_set = set(interfaces) if interfaces else None

        result = {}

        if type_filter is None or type_filter == 'sampler':
            fs_rows = await self._walk_columns({
                'receiver': OID_sFlowFsReceiver,
                'sample_rate': OID_sFlowFsPacketRate,
                'max_header_size': OID_sFlowFsMaxHeaderSize,
            }, engine)
            for suffix, cols in fs_rows.items():
                ifidx = self._sflow_suffix_to_ifindex(suffix)
                if ifidx is None:
                    continue
                name = ifmap.get(ifidx, '')
                if not name or name.startswith('cpu'):
                    continue
                if iface_set and name not in iface_set:
                    continue
                if name not in result:
                    result[name] = {}
                result[name]['sampler'] = {
                    'receiver': _snmp_int(cols.get('receiver', 0)),
                    'sample_rate': _snmp_int(
                        cols.get('sample_rate', 0)),
                    'max_header_size': _snmp_int(
                        cols.get('max_header_size', 128)),
                }

        if type_filter is None or type_filter == 'poller':
            cp_rows = await self._walk_columns({
                'receiver': OID_sFlowCpReceiver,
                'interval': OID_sFlowCpInterval,
            }, engine)
            for suffix, cols in cp_rows.items():
                ifidx = self._sflow_suffix_to_ifindex(suffix)
                if ifidx is None:
                    continue
                name = ifmap.get(ifidx, '')
                if not name or name.startswith('cpu'):
                    continue
                if iface_set and name not in iface_set:
                    continue
                if name not in result:
                    result[name] = {}
                result[name]['poller'] = {
                    'receiver': _snmp_int(cols.get('receiver', 0)),
                    'interval': _snmp_int(cols.get('interval', 0)),
                }

        return result

    def set_sflow_port(self, interfaces, receiver, sample_rate=None,
                       interval=None, max_header_size=None):
        """Configure sFlow sampling/polling on ports."""
        return asyncio.run(self._set_sflow_port_async(
            interfaces, receiver, sample_rate, interval,
            max_header_size))

    async def _set_sflow_port_async(self, interfaces, receiver,
                                    sample_rate, interval,
                                    max_header_size):
        if sample_rate is None and interval is None:
            raise ValueError(
                "At least one of sample_rate or interval must be provided")

        interfaces = ([interfaces] if isinstance(interfaces, str)
                      else list(interfaces))
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: idx for idx, name in ifmap.items()}

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")

            ds_suffix = self._sflow_ds_suffix(ifidx)

            if sample_rate is not None:
                if receiver == 0:
                    sets.append((
                        f"{OID_sFlowFsReceiver}.{ds_suffix}",
                        Integer32(0)))
                else:
                    sets.append((
                        f"{OID_sFlowFsReceiver}.{ds_suffix}",
                        Integer32(int(receiver))))
                    sets.append((
                        f"{OID_sFlowFsPacketRate}.{ds_suffix}",
                        Integer32(int(sample_rate))))
                    if max_header_size is not None:
                        sets.append((
                            f"{OID_sFlowFsMaxHeaderSize}.{ds_suffix}",
                            Integer32(int(max_header_size))))

            if interval is not None:
                if receiver == 0:
                    sets.append((
                        f"{OID_sFlowCpReceiver}.{ds_suffix}",
                        Integer32(0)))
                else:
                    sets.append((
                        f"{OID_sFlowCpReceiver}.{ds_suffix}",
                        Integer32(int(receiver))))
                    sets.append((
                        f"{OID_sFlowCpInterval}.{ds_suffix}",
                        Integer32(int(interval))))

        if sets:
            await self._set_oids(*sets)

    # ── QoS ──────────────────────────────────────────────────────
    _QOS_TRUST_MODE = {
        1: 'untrusted', 2: 'dot1p',
        3: 'ip-precedence', 4: 'ip-dscp',
    }
    _QOS_TRUST_MODE_REV = {
        'untrusted': 1, 'dot1p': 2,
        'ip-precedence': 3, 'ip-dscp': 4,
    }
    _QOS_SCHEDULER = {1: 'strict', 2: 'weighted'}
    _QOS_SCHEDULER_REV = {'strict': 1, 'weighted': 2}

    def get_qos(self):
        """Return per-port QoS trust mode and queue scheduling."""
        return asyncio.run(self._get_qos_async())

    async def _get_qos_async(self):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        scalars = await self._get_scalar(OID_hm2CosQueueNumQueuesPerPort)
        num_queues = _snmp_int(
            scalars.get(OID_hm2CosQueueNumQueuesPerPort, 8))

        trust_rows = await self._walk_columns({
            'trust': OID_hm2CosMapIntfTrustMode,
        }, engine)

        shaping_rows = await self._walk_columns({
            'shaping': OID_hm2CosQueueIntfShapingRate,
        }, engine)

        queue_rows = await self._walk_columns({
            'scheduler': OID_hm2CosQueueSchedulerType,
            'min_bw': OID_hm2CosQueueMinBandwidth,
            'max_bw': OID_hm2CosQueueMaxBandwidth,
        }, engine)

        # Default priority (indexed by dot1dBasePort — need bridge-port→ifIndex map)
        bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
        priority_data = await self._walk(OID_dot1dPortDefaultUserPriority, engine)
        priority_by_idx = {}
        for bp_num, prio_val in priority_data.items():
            ifindex_val = bp_data.get(bp_num)
            if ifindex_val is not None:
                priority_by_idx[str(ifindex_val)] = _snmp_int(prio_val)

        # Build per-port queue dict from compound suffix ifIndex.queueIndex
        queues_by_idx = {}
        for suffix, cols in queue_rows.items():
            parts = suffix.split('.')
            if len(parts) != 2:
                continue
            ifidx, qidx = parts[0], int(parts[1])
            if ifidx == '0':
                continue
            if ifidx not in queues_by_idx:
                queues_by_idx[ifidx] = {}
            queues_by_idx[ifidx][qidx] = {
                'scheduler': self._QOS_SCHEDULER.get(
                    _snmp_int(cols.get('scheduler', 1)), 'strict'),
                'min_bw': _snmp_int(cols.get('min_bw', 0)),
                'max_bw': _snmp_int(cols.get('max_bw', 0)),
            }

        interfaces = {}
        for suffix, cols in trust_rows.items():
            if suffix == '0':
                continue
            name = ifmap.get(suffix, '')
            if not name or name.startswith('cpu') or name.startswith('vlan'):
                continue
            shaping_cols = shaping_rows.get(suffix, {})
            interfaces[name] = {
                'trust_mode': self._QOS_TRUST_MODE.get(
                    _snmp_int(cols.get('trust', 2)), 'dot1p'),
                'default_priority': priority_by_idx.get(suffix, 0),
                'shaping_rate': _snmp_int(
                    shaping_cols.get('shaping', 0)),
                'queues': queues_by_idx.get(suffix, {}),
            }

        return {
            'num_queues': num_queues,
            'interfaces': interfaces,
        }

    def set_qos(self, interface, trust_mode=None, shaping_rate=None,
                queue=None, scheduler=None, min_bw=None, max_bw=None,
                default_priority=None):
        """Set per-port QoS trust mode, shaping rate, or queue scheduling."""
        return asyncio.run(self._set_qos_async(
            interface, trust_mode, shaping_rate,
            queue, scheduler, min_bw, max_bw,
            default_priority,
        ))

    async def _set_qos_async(self, interface, trust_mode, shaping_rate,
                              queue, scheduler, min_bw, max_bw,
                              default_priority=None):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: idx for idx, name in ifmap.items()}

        if trust_mode is not None:
            val = self._QOS_TRUST_MODE_REV.get(trust_mode)
            if val is None:
                raise ValueError(
                    f"Invalid trust_mode '{trust_mode}': use "
                    "'untrusted', 'dot1p', 'ip-precedence', 'ip-dscp'")

        if scheduler is not None:
            val = self._QOS_SCHEDULER_REV.get(scheduler)
            if val is None:
                raise ValueError(
                    f"Invalid scheduler '{scheduler}': "
                    "use 'strict' or 'weighted'")

        queue_needed = (scheduler is not None or min_bw is not None
                        or max_bw is not None)
        if queue_needed and queue is None:
            raise ValueError(
                "queue index (0-7) required when setting "
                "scheduler, min_bw, or max_bw")

        # Build ifIndex→bridgePort reverse map for default_priority
        idx_to_bp = {}
        if default_priority is not None:
            bp_data = await self._walk(OID_dot1dBasePortIfIndex, engine)
            idx_to_bp = {str(ifidx_val): bp_num
                         for bp_num, ifidx_val in bp_data.items()}

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            if trust_mode is not None:
                sets.append((
                    f"{OID_hm2CosMapIntfTrustMode}.{ifidx}",
                    Integer32(self._QOS_TRUST_MODE_REV[trust_mode])))
            if shaping_rate is not None:
                sets.append((
                    f"{OID_hm2CosQueueIntfShapingRate}.{ifidx}",
                    Unsigned32(int(shaping_rate))))
            if default_priority is not None:
                bp = idx_to_bp.get(ifidx)
                if bp is not None:
                    sets.append((
                        f"{OID_dot1dPortDefaultUserPriority}.{bp}",
                        Integer32(int(default_priority))))
            if queue_needed:
                q_suffix = f"{ifidx}.{int(queue)}"
                if scheduler is not None:
                    sets.append((
                        f"{OID_hm2CosQueueSchedulerType}.{q_suffix}",
                        Integer32(self._QOS_SCHEDULER_REV[scheduler])))
                if min_bw is not None:
                    sets.append((
                        f"{OID_hm2CosQueueMinBandwidth}.{q_suffix}",
                        Unsigned32(int(min_bw))))
                if max_bw is not None:
                    sets.append((
                        f"{OID_hm2CosQueueMaxBandwidth}.{q_suffix}",
                        Unsigned32(int(max_bw))))

        if sets:
            await self._set_oids(*sets)

    def get_qos_mapping(self):
        """Return global dot1p and DSCP to traffic class mapping tables."""
        return asyncio.run(self._get_qos_mapping_async())

    async def _get_qos_mapping_async(self):
        engine = SnmpEngine()

        dot1p_rows = await self._walk_columns({
            'tc': OID_hm2TrafficClass,
        }, engine)

        dscp_rows = await self._walk_columns({
            'tc': OID_hm2CosMapIpDscpTrafficClass,
        }, engine)

        dot1p = {}
        for suffix, cols in dot1p_rows.items():
            prio = int(suffix)
            dot1p[prio] = _snmp_int(cols.get('tc', 0))

        dscp = {}
        for suffix, cols in dscp_rows.items():
            dval = int(suffix)
            dscp[dval] = _snmp_int(cols.get('tc', 0))

        return {'dot1p': dot1p, 'dscp': dscp}

    def set_qos_mapping(self, dot1p=None, dscp=None):
        """Set global dot1p and/or DSCP to traffic class mappings."""
        return asyncio.run(self._set_qos_mapping_async(dot1p, dscp))

    async def _set_qos_mapping_async(self, dot1p, dscp):
        sets = []

        if dot1p is not None:
            for prio, tc in dot1p.items():
                sets.append((
                    f"{OID_hm2TrafficClass}.{int(prio)}",
                    Integer32(int(tc))))

        if dscp is not None:
            for dval, tc in dscp.items():
                sets.append((
                    f"{OID_hm2CosMapIpDscpTrafficClass}.{int(dval)}",
                    Integer32(int(tc))))

        if sets:
            await self._set_oids(*sets)

    def get_management_priority(self):
        """Return management frame priority settings."""
        return asyncio.run(self._get_management_priority_async())

    async def _get_management_priority_async(self):
        scalars = await self._get_scalar(
            OID_hm2NetVlanPriority, OID_hm2NetIpDscpPriority)
        return {
            'dot1p': _snmp_int(
                scalars.get(OID_hm2NetVlanPriority, 0)),
            'ip_dscp': _snmp_int(
                scalars.get(OID_hm2NetIpDscpPriority, 0)),
        }

    def set_management_priority(self, dot1p=None, ip_dscp=None):
        """Set management frame priority."""
        return asyncio.run(self._set_management_priority_async(
            dot1p, ip_dscp))

    async def _set_management_priority_async(self, dot1p, ip_dscp):
        sets = []
        if dot1p is not None:
            sets.append((
                f"{OID_hm2NetVlanPriority}.0",
                Integer32(int(dot1p))))
        if ip_dscp is not None:
            sets.append((
                f"{OID_hm2NetIpDscpPriority}.0",
                Integer32(int(ip_dscp))))
        if sets:
            await self._set_oids(*sets)

    def get_management(self):
        """Return management network configuration via SNMP."""
        return asyncio.run(self._get_management_async())

    async def _get_management_async(self):
        _PROTOCOL_MAP = {1: 'local', 2: 'bootp', 3: 'dhcp'}
        _IPV6_PROTOCOL_MAP = {1: 'none', 2: 'auto', 3: 'dhcpv6', 4: 'all'}

        scalars = await self._get_scalar(
            OID_hm2NetConfigProtocol, OID_hm2NetLocalIPAddr,
            OID_hm2NetPrefixLength, OID_hm2NetGatewayIPAddr,
            OID_hm2NetVlanID, OID_hm2NetMgmtPort,
            OID_hm2NetDHCPClientId, OID_hm2NetDHCPClientLeaseTime,
            OID_hm2NetDHCPClientConfigLoad,
            OID_hm2NetVlanPriority, OID_hm2NetIpDscpPriority,
            OID_hm2NetIPv6AdminStatus, OID_hm2NetIPv6ConfigProtocol,
        )

        proto_val = _snmp_int(scalars.get(OID_hm2NetConfigProtocol, 1))
        prefix_len = _snmp_int(scalars.get(OID_hm2NetPrefixLength, 0))
        ipv6_proto = _snmp_int(
            scalars.get(OID_hm2NetIPv6ConfigProtocol, 2))

        return {
            'protocol': _PROTOCOL_MAP.get(proto_val, 'local'),
            'vlan_id': _snmp_int(scalars.get(OID_hm2NetVlanID, 1)),
            'ip_address': _snmp_ip(scalars.get(OID_hm2NetLocalIPAddr, '')),
            'netmask': _prefix_to_mask(prefix_len),
            'gateway': _snmp_ip(scalars.get(OID_hm2NetGatewayIPAddr, '')),
            'mgmt_port': _snmp_int(scalars.get(OID_hm2NetMgmtPort, 0)),
            'dhcp_client_id': _snmp_str(
                scalars.get(OID_hm2NetDHCPClientId, '')),
            'dhcp_lease_time': _snmp_int(
                scalars.get(OID_hm2NetDHCPClientLeaseTime, 0)),
            'dhcp_option_66_67': _snmp_int(
                scalars.get(OID_hm2NetDHCPClientConfigLoad, 1)) == 1,
            'dot1p': _snmp_int(scalars.get(OID_hm2NetVlanPriority, 0)),
            'ip_dscp': _snmp_int(scalars.get(OID_hm2NetIpDscpPriority, 0)),
            'ipv6_enabled': _snmp_int(
                scalars.get(OID_hm2NetIPv6AdminStatus, 1)) == 1,
            'ipv6_protocol': _IPV6_PROTOCOL_MAP.get(ipv6_proto, 'auto'),
        }

    def set_management(self, protocol=None, vlan_id=None, ip_address=None,
                       netmask=None, gateway=None, mgmt_port=None,
                       dhcp_option_66_67=None, ipv6_enabled=None):
        """Set management network configuration via SNMP."""
        if vlan_id is not None:
            vlan_id = int(vlan_id)
            if vlan_id < 1 or vlan_id > 4042:
                raise ValueError(f"vlan_id must be 1-4042, got {vlan_id}")
            vlans = self.get_vlans()
            if vlan_id not in vlans:
                raise ValueError(
                    f"VLAN {vlan_id} does not exist on device — "
                    f"create it first to avoid management lockout")
        return asyncio.run(self._set_management_async(
            protocol, vlan_id, ip_address, netmask, gateway,
            mgmt_port, dhcp_option_66_67, ipv6_enabled))

    async def _set_management_async(self, protocol, vlan_id, ip_address,
                                     netmask, gateway, mgmt_port,
                                     dhcp_option_66_67, ipv6_enabled):
        _PROTOCOL_REV = {'local': 1, 'bootp': 2, 'dhcp': 3}

        sets = []
        need_activate = False

        if protocol is not None:
            proto = protocol.lower().strip()
            if proto not in _PROTOCOL_REV:
                raise ValueError(
                    f"protocol must be 'local', 'bootp', or 'dhcp', "
                    f"got '{protocol}'")
            sets.append((
                f"{OID_hm2NetConfigProtocol}.0",
                Integer32(_PROTOCOL_REV[proto])))

        if vlan_id is not None:
            sets.append((
                f"{OID_hm2NetVlanID}.0",
                Integer32(int(vlan_id))))

        if ip_address is not None:
            ip_bytes = bytes(int(o) for o in ip_address.split('.'))
            sets.append((
                f"{OID_hm2NetLocalIPAddr}.0",
                OctetString(ip_bytes)))
            need_activate = True

        if netmask is not None:
            sets.append((
                f"{OID_hm2NetPrefixLength}.0",
                Integer32(_mask_to_prefix(netmask))))
            need_activate = True

        if gateway is not None:
            gw_bytes = bytes(int(o) for o in gateway.split('.'))
            sets.append((
                f"{OID_hm2NetGatewayIPAddr}.0",
                OctetString(gw_bytes)))
            need_activate = True

        if mgmt_port is not None:
            sets.append((
                f"{OID_hm2NetMgmtPort}.0",
                Integer32(int(mgmt_port))))

        if dhcp_option_66_67 is not None:
            sets.append((
                f"{OID_hm2NetDHCPClientConfigLoad}.0",
                Integer32(1 if dhcp_option_66_67 else 2)))

        if ipv6_enabled is not None:
            sets.append((
                f"{OID_hm2NetIPv6AdminStatus}.0",
                Integer32(1 if ipv6_enabled else 2)))

        if need_activate:
            sets.append((
                f"{OID_hm2NetAction}.0",
                Integer32(2)))  # activate

        if sets:
            await self._set_oids(*sets)

    # ── RSTP ─────────────────────────────────────────────────────

    def get_rstp(self):
        """Return global STP/RSTP configuration and state."""
        return asyncio.run(self._get_rstp_async())

    async def _get_rstp_async(self):
        # Global scalars — batch into one _get_scalar call
        global_oids = (
            OID_hm2AgentStpForceVersion, OID_hm2AgentStpAdminMode,
            OID_hm2AgentStpBpduGuardMode, OID_hm2AgentStpBpduFilterDefault,
            OID_hm2AgentStpCstHelloTime, OID_hm2AgentStpCstMaxAge,
            OID_hm2AgentStpCstRootFwdDelay,
            OID_hm2AgentStpCstBridgeFwdDelay, OID_hm2AgentStpCstBridgeHelloTime,
            OID_hm2AgentStpCstBridgeMaxAge, OID_hm2AgentStpCstBridgeMaxHops,
            OID_hm2AgentStpCstBridgePriority, OID_hm2AgentStpCstBridgeHoldCount,
        )
        scalars = await self._get_scalar(*global_oids)

        # MST entry — instance 0 (CIST)
        mst_keys = (
            ('bridge_id', OID_hm2AgentStpMstBridgeIdentifier),
            ('root_id', OID_hm2AgentStpMstDesignatedRootId),
            ('root_port_id', OID_hm2AgentStpMstRootPortId),
            ('root_path_cost', OID_hm2AgentStpMstRootPathCost),
            ('topo_changes', OID_hm2AgentStpMstTopologyChangeCount),
            ('time_since_topo', OID_hm2AgentStpMstTimeSinceTopologyChange),
        )
        mst_oids = [f"{oid}.0" for _, oid in mst_keys]
        mst_vals = await self._get_scalar(*mst_oids)
        mst = {key: mst_vals.get(oid) for (key, _), oid in zip(mst_keys, mst_oids)}

        def _format_bridge_id(val):
            if isinstance(val, bytes):
                return ':'.join(f'{b:02x}' for b in val)
            if hasattr(val, 'prettyPrint'):
                raw = val.prettyPrint()
                if raw.startswith('0x'):
                    hex_str = raw[2:]
                    return ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            return str(val)

        def _root_port_num(val):
            try:
                if isinstance(val, bytes) and len(val) == 2:
                    return ((val[0] << 8) | val[1]) & 0x0FFF
                v = _snmp_int(val)
                return v & 0x0FFF
            except (ValueError, TypeError):
                return 0

        return {
            'enabled': _snmp_int(scalars.get(OID_hm2AgentStpAdminMode, 2)) == 1,
            'mode': _STP_VERSION.get(
                _snmp_int(scalars.get(OID_hm2AgentStpForceVersion, 2)), 'rstp'),
            'bridge_id': _format_bridge_id(mst.get('bridge_id', '')),
            'priority': _snmp_int(scalars.get(OID_hm2AgentStpCstBridgePriority, 32768)),
            'hello_time': _snmp_int(scalars.get(OID_hm2AgentStpCstBridgeHelloTime, 2)),
            'max_age': _snmp_int(scalars.get(OID_hm2AgentStpCstBridgeMaxAge, 20)),
            'forward_delay': _snmp_int(scalars.get(OID_hm2AgentStpCstBridgeFwdDelay, 15)),
            'hold_count': _snmp_int(scalars.get(OID_hm2AgentStpCstBridgeHoldCount, 10)),
            'max_hops': _snmp_int(scalars.get(OID_hm2AgentStpCstBridgeMaxHops, 0)),
            'root_id': _format_bridge_id(mst.get('root_id', '')),
            'root_port': _root_port_num(mst.get('root_port_id', 0)),
            'root_path_cost': _snmp_int(mst.get('root_path_cost', 0)),
            'topology_changes': _snmp_int(mst.get('topo_changes', 0)),
            'time_since_topology_change': _snmp_int(
                mst.get('time_since_topo', 0)) // 100,
            'root_hello_time': _snmp_int(scalars.get(OID_hm2AgentStpCstHelloTime, 2)),
            'root_max_age': _snmp_int(scalars.get(OID_hm2AgentStpCstMaxAge, 20)),
            'root_forward_delay': _snmp_int(scalars.get(
                OID_hm2AgentStpCstRootFwdDelay, 15)),
            'bpdu_guard': _snmp_int(scalars.get(OID_hm2AgentStpBpduGuardMode, 2)) == 1,
            'bpdu_filter': _snmp_int(
                scalars.get(OID_hm2AgentStpBpduFilterDefault, 2)) == 1,
        }

    def get_rstp_port(self, interface=None):
        """Return per-port STP/RSTP state."""
        return asyncio.run(self._get_rstp_port_async(interface))

    async def _get_rstp_port_async(self, interface):
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)

        # Walk STP port table + CST port table
        stp_rows = await self._walk_columns({
            'port_state': OID_hm2AgentStpPortState,
            'rstp_rx': OID_hm2AgentStpPortStatsRstpBpduRx,
            'rstp_tx': OID_hm2AgentStpPortStatsRstpBpduTx,
            'stp_rx': OID_hm2AgentStpPortStatsStpBpduRx,
            'stp_tx': OID_hm2AgentStpPortStatsStpBpduTx,
        }, engine)

        cst_rows = await self._walk_columns({
            'edge': OID_hm2AgentStpCstPortEdge,
            'oper_edge': OID_hm2AgentStpCstPortOperEdge,
            'auto_edge': OID_hm2AgentStpCstPortAutoEdge,
            'fwd_state': OID_hm2AgentStpCstPortForwardingState,
            'path_cost': OID_hm2AgentStpCstPortPathCost,
            'priority': OID_hm2AgentStpCstPortPriority,
            'p2p': OID_hm2AgentStpCstPortOperPointToPoint,
            'root_guard': OID_hm2AgentStpCstPortRootGuard,
            'loop_guard': OID_hm2AgentStpCstPortLoopGuard,
            'tcn_guard': OID_hm2AgentStpCstPortTCNGuard,
            'bpdu_guard': OID_hm2AgentStpCstPortBpduGuardEffect,
            'bpdu_filter': OID_hm2AgentStpCstPortBpduFilter,
            'bpdu_flood': OID_hm2AgentStpCstPortBpduFlood,
        }, engine)

        ports = {}
        for ifidx, name in ifmap.items():
            if name.startswith('cpu'):
                continue
            if interface and name != interface:
                continue

            stp = stp_rows.get(ifidx, {})
            cst = cst_rows.get(ifidx, {})

            fwd_state = _snmp_int(cst.get('fwd_state', 4))
            ports[name] = {
                'enabled': _snmp_int(stp.get('port_state', 2)) == 1,
                'state': _STP_FWD_STATE.get(fwd_state, 'disabled'),
                'edge_port': _snmp_int(cst.get('edge', 2)) == 1,
                'edge_port_oper': _snmp_int(cst.get('oper_edge', 2)) == 1,
                'auto_edge': _snmp_int(cst.get('auto_edge', 2)) == 1,
                'point_to_point': _snmp_int(cst.get('p2p', 2)) == 1,
                'path_cost': _snmp_int(cst.get('path_cost', 0)),
                'priority': _snmp_int(cst.get('priority', 128)),
                'root_guard': _snmp_int(cst.get('root_guard', 2)) == 1,
                'loop_guard': _snmp_int(cst.get('loop_guard', 2)) == 1,
                'tcn_guard': _snmp_int(cst.get('tcn_guard', 2)) == 1,
                'bpdu_guard': _snmp_int(cst.get('bpdu_guard', 2)) == 1,
                'bpdu_filter': _snmp_int(cst.get('bpdu_filter', 2)) == 1,
                'bpdu_flood': _snmp_int(cst.get('bpdu_flood', 2)) == 1,
                'rstp_bpdu_rx': _snmp_int(stp.get('rstp_rx', 0)),
                'rstp_bpdu_tx': _snmp_int(stp.get('rstp_tx', 0)),
                'stp_bpdu_rx': _snmp_int(stp.get('stp_rx', 0)),
                'stp_bpdu_tx': _snmp_int(stp.get('stp_tx', 0)),
            }

        return ports

    def set_rstp(self, enabled=None, mode=None, priority=None,
                 hello_time=None, max_age=None, forward_delay=None,
                 hold_count=None, bpdu_guard=None, bpdu_filter=None):
        """Set global STP/RSTP configuration."""
        return asyncio.run(self._set_rstp_async(
            enabled, mode, priority, hello_time, max_age,
            forward_delay, hold_count, bpdu_guard, bpdu_filter))

    async def _set_rstp_async(self, enabled, mode, priority, hello_time,
                               max_age, forward_delay, hold_count,
                               bpdu_guard, bpdu_filter):
        sets = []
        if enabled is not None:
            sets.append((OID_hm2AgentStpAdminMode,
                         Integer32(1 if enabled else 2)))
        if mode is not None:
            val = _STP_VERSION_REV.get(mode)
            if val is None:
                raise ValueError(
                    f"Invalid mode '{mode}': use 'stp', 'rstp', or 'mstp'")
            sets.append((OID_hm2AgentStpForceVersion, Integer32(val)))
        if bpdu_guard is not None:
            sets.append((OID_hm2AgentStpBpduGuardMode,
                         Integer32(1 if bpdu_guard else 2)))
        if bpdu_filter is not None:
            sets.append((OID_hm2AgentStpBpduFilterDefault,
                         Integer32(1 if bpdu_filter else 2)))
        if priority is not None:
            sets.append((OID_hm2AgentStpCstBridgePriority,
                         Unsigned32(int(priority))))
        if hello_time is not None:
            sets.append((OID_hm2AgentStpCstBridgeHelloTime,
                         Unsigned32(int(hello_time))))
        if max_age is not None:
            sets.append((OID_hm2AgentStpCstBridgeMaxAge,
                         Unsigned32(int(max_age))))
        if forward_delay is not None:
            sets.append((OID_hm2AgentStpCstBridgeFwdDelay,
                         Unsigned32(int(forward_delay))))
        if hold_count is not None:
            sets.append((OID_hm2AgentStpCstBridgeHoldCount,
                         Unsigned32(int(hold_count))))

        for oid, val in sets:
            await self._set_scalar(oid, val)

        return await self._get_rstp_async()

    def set_rstp_port(self, interface, enabled=None, edge_port=None,
                      auto_edge=None, path_cost=None, priority=None,
                      root_guard=None, loop_guard=None, tcn_guard=None,
                      bpdu_filter=None, bpdu_flood=None):
        """Set per-port STP/RSTP configuration.

        Args:
            interface: port name (str) or list of port names
        """
        return asyncio.run(self._set_rstp_port_async(
            interface, enabled, edge_port, auto_edge, path_cost, priority,
            root_guard, loop_guard, tcn_guard, bpdu_filter, bpdu_flood))

    async def _set_rstp_port_async(self, interface, enabled, edge_port,
                                    auto_edge, path_cost, priority,
                                    root_guard, loop_guard, tcn_guard,
                                    bpdu_filter, bpdu_flood):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        engine = SnmpEngine()
        ifmap = await self._build_ifindex_map(engine)
        name_to_idx = {name: idx for idx, name in ifmap.items()}

        sets = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")

            # Port enable/disable (hm2AgentStpPortEntry)
            if enabled is not None:
                sets.append((f"{OID_hm2AgentStpPortState}.{ifidx}",
                             Integer32(1 if enabled else 2)))
            # CST port settings
            if edge_port is not None:
                sets.append((f"{OID_hm2AgentStpCstPortEdge}.{ifidx}",
                             Integer32(1 if edge_port else 2)))
            if auto_edge is not None:
                sets.append((f"{OID_hm2AgentStpCstPortAutoEdge}.{ifidx}",
                             Integer32(1 if auto_edge else 2)))
            if path_cost is not None:
                sets.append((f"{OID_hm2AgentStpCstPortPathCost}.{ifidx}",
                             Unsigned32(int(path_cost))))
            if priority is not None:
                sets.append((f"{OID_hm2AgentStpCstPortPriority}.{ifidx}",
                             Unsigned32(int(priority))))
            if root_guard is not None:
                sets.append((f"{OID_hm2AgentStpCstPortRootGuard}.{ifidx}",
                             Integer32(1 if root_guard else 2)))
            if loop_guard is not None:
                sets.append((f"{OID_hm2AgentStpCstPortLoopGuard}.{ifidx}",
                             Integer32(1 if loop_guard else 2)))
            if tcn_guard is not None:
                sets.append((f"{OID_hm2AgentStpCstPortTCNGuard}.{ifidx}",
                             Integer32(1 if tcn_guard else 2)))
            if bpdu_filter is not None:
                sets.append((f"{OID_hm2AgentStpCstPortBpduFilter}.{ifidx}",
                             Integer32(1 if bpdu_filter else 2)))
            if bpdu_flood is not None:
                sets.append((f"{OID_hm2AgentStpCstPortBpduFlood}.{ifidx}",
                             Integer32(1 if bpdu_flood else 2)))

        if sets:
            await self._set_oids(*sets)
