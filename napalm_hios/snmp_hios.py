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
from pysnmp.proto.rfc1902 import Integer32, OctetString
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
OID_dot1qVlanStaticUntaggedPorts = '1.3.6.1.2.1.17.7.1.4.3.1.4'

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


# MRP enum mappings
_MRP_PORT_OPER_STATE = {1: 'disabled', 2: 'blocked', 3: 'forwarding', 4: 'notConnected'}
_MRP_ROLE = {1: 'client', 2: 'manager', 3: 'undefined'}
_MRP_RECOVERY_DELAY = {1: '500ms', 2: '200ms', 3: '30ms', 4: '10ms'}
_MRP_RING_OPER_STATE = {1: 'open', 2: 'closed', 3: 'undefined'}
_MRP_CONFIG_OPER_STATE = {1: 'noError', 2: 'linkError', 3: 'multipleMRM'}
_MRP_CONFIG_INFO = {1: 'no error', 2: 'ring port link error', 3: 'multiple MRM detected'}
_MRP_RECOVERY_DELAY_REV = {'500ms': 1, '200ms': 2, '30ms': 3, '10ms': 4}
_MRP_ROLE_REV = {'client': 1, 'manager': 2}

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
            interface: port name (e.g. '1/5')
            enabled: True (admin up) or False (admin down), None to skip
            description: port description string, None to skip
        """
        ifindex_map = asyncio.run(self._build_ifindex_map())
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}
        ifidx = name_to_idx.get(interface)
        if ifidx is None:
            raise ValueError(f"Unknown interface '{interface}'")

        sets = []
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
