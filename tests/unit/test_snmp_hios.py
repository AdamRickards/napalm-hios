"""Unit tests for SNMPHIOS — mock _get_scalar and _walk to test parsing logic."""

import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio

from napalm_hios.snmp_hios import (
    SNMPHIOS, _format_mac, _mask_to_prefix, _parse_sysDescr,
    _parse_fw_version, _snmp_str, _snmp_int, _snmp_ip,
    _decode_capabilities, _decode_portlist,
    _format_mrp_domain_id, _decode_implied_string,
    _decode_bits_snmp, _encode_bits_snmp,
    _TLS_VERSIONS, _SSH_HMAC,
    OID_hm2FMNvmState, OID_hm2FMEnvmState, OID_hm2FMBootParamState,
    OID_hm2FMActionActivateKey, OID_hm2FMActionActivate_save,
    OID_sysDescr, OID_sysName, OID_sysUpTime, OID_sysContact, OID_sysLocation,
    OID_ifDescr, OID_ifOperStatus, OID_ifAdminStatus, OID_ifHighSpeed,
    OID_ifMtu, OID_ifPhysAddress, OID_ifAlias,
    OID_ipAdEntIfIndex, OID_ipAdEntNetMask,
    OID_ifHCInOctets, OID_ifHCOutOctets,
    OID_ifHCInUcastPkts, OID_ifHCOutUcastPkts,
    OID_ifHCInMulticastPkts, OID_ifHCOutMulticastPkts,
    OID_ifHCInBroadcastPkts, OID_ifHCOutBroadcastPkts,
    OID_ifInDiscards, OID_ifOutDiscards, OID_ifInErrors, OID_ifOutErrors,
    OID_ipNetToMediaPhysAddress, OID_ipNetToMediaType,
    OID_dot1dBasePortIfIndex,
    OID_dot1qTpFdbPort, OID_dot1qTpFdbStatus,
    OID_dot1qVlanStaticName, OID_dot1qVlanStaticEgressPorts,
    OID_lldpRemSysName, OID_lldpRemPortId, OID_lldpRemPortDesc,
    OID_lldpRemChassisId, OID_lldpLocPortId,
    OID_lldpRemChassisIdSubtype, OID_lldpRemPortIdSubtype,
    OID_lldpRemSysDesc, OID_lldpRemSysCapSupported, OID_lldpRemSysCapEnabled,
    OID_lldpRemManAddrIfSubtype,
    OID_hm2ProductDescr, OID_hm2SerialNumber, OID_hm2FwVersionRAM,
    OID_hm2Temperature, OID_hm2TempUpperLimit, OID_hm2TempLowerLimit,
    OID_hm2CpuUtil, OID_hm2MemAlloc, OID_hm2MemFree,
    OID_hm2PSState, OID_hm2FanModuleStatus, OID_hm2FanStatus,
    OID_hm2SfpDiagTxPower, OID_hm2SfpDiagRxPower,
    OID_hm2UserAccessRole, OID_hm2UserStatus,
    OID_hm2SntpRequestInterval, OID_hm2SntpClientStatus,
    OID_hm2SntpServerAddr, OID_hm2SntpServerStatus,
    OID_hm2MrpDomainName, OID_hm2MrpRingport1IfIndex,
    OID_hm2MrpRingport1OperState, OID_hm2MrpRingport2IfIndex,
    OID_hm2MrpRingport2OperState, OID_hm2MrpRoleAdminState,
    OID_hm2MrpRoleOperState, OID_hm2MrpRecoveryDelay,
    OID_hm2MrpVlanID, OID_hm2MrpMRMPriority,
    OID_hm2MrpMRMReactOnLinkChange, OID_hm2MrpMRMRingOpenCount,
    OID_hm2MrpMRCBlockedSupported, OID_hm2MrpRingOperState,
    OID_hm2MrpRedundancyOperState, OID_hm2MrpConfigOperState,
    OID_hm2MrpRowStatus, OID_hm2MrpRingport2FixedBackup,
    OID_hm2MrpRecoveryDelaySupported, OID_hm2MrpFastMrp,
    MRP_DEFAULT_DOMAIN_SUFFIX, _MRP_ROLE_REV, _MRP_RECOVERY_DELAY_REV,
    OID_hm2SrmGlobalAdminState, OID_hm2SrmMaxInstances,
    OID_hm2SrmAdminState, OID_hm2SrmOperState, OID_hm2SrmVlanID,
    OID_hm2SrmSubRingPortIfIndex, OID_hm2SrmSubRingPortOperState,
    OID_hm2SrmSubRingOperState, OID_hm2SrmRedundancyOperState,
    OID_hm2SrmConfigOperState, OID_hm2SrmRowStatus,
    OID_hm2HiDiscOper, OID_hm2HiDiscMode, OID_hm2HiDiscBlinking,
    OID_hm2HiDiscProtocol, OID_hm2HiDiscRelay,
    OID_lldpXdot3RemPortAutoNegSupported, OID_lldpXdot3RemPortAutoNegEnabled,
    OID_lldpXdot3RemPortOperMauType,
    OID_lldpXdot3RemLinkAggStatus, OID_lldpXdot3RemLinkAggPortId,
    OID_lldpXdot1RemPortVlanId, OID_lldpXdot1RemVlanId,
    OID_hm2FMProfileStorageType, OID_hm2FMProfileIndex,
    OID_hm2FMProfileName, OID_hm2FMProfileDateTime,
    OID_hm2FMProfileActive, OID_hm2FMProfileAction,
    OID_hm2FMProfileEncryptionActive, OID_hm2FMProfileEncryptionVerified,
    OID_hm2FMProfileSwMajorRelNum, OID_hm2FMProfileSwMinorRelNum,
    OID_hm2FMProfileSwBugfixRelNum, OID_hm2FMProfileFingerprint,
    OID_hm2FMProfileFingerprintVerified,
    OID_hm2ConfigWatchdogAdminStatus, OID_hm2ConfigWatchdogOperStatus,
    OID_hm2ConfigWatchdogTimeInterval, OID_hm2ConfigWatchdogTimerValue,
    OID_hm2StormBucketType,
    OID_sFlowVersion, OID_sFlowAgentAddress,
    OID_sFlowRcvrOwner, OID_sFlowRcvrTimeout, OID_sFlowRcvrMaxDgramSize,
    OID_sFlowRcvrAddressType, OID_sFlowRcvrAddress, OID_sFlowRcvrPort,
    OID_sFlowRcvrDgramVersion,
    OID_hm2CosMapIntfTrustMode, OID_hm2CosQueueNumQueuesPerPort,
    OID_hm2CosQueueIntfShapingRate, OID_hm2CosQueueSchedulerType,
    OID_hm2CosQueueMinBandwidth, OID_hm2CosQueueMaxBandwidth,
    OID_hm2TrafficClass, OID_hm2CosMapIpDscpTrafficClass,
    OID_hm2NetVlanPriority, OID_hm2NetIpDscpPriority,
    OID_hm2NetConfigProtocol, OID_hm2NetLocalIPAddr,
    OID_hm2NetPrefixLength, OID_hm2NetGatewayIPAddr,
    OID_hm2NetVlanID, OID_hm2NetMgmtPort,
    OID_hm2NetDHCPClientId, OID_hm2NetDHCPClientLeaseTime,
    OID_hm2NetDHCPClientConfigLoad,
    OID_hm2NetIPv6AdminStatus, OID_hm2NetIPv6ConfigProtocol,
    OID_hm2FMServerUserName, OID_hm2FMServerPassword,
    OID_hm2FMConfigRemoteSaveAdminStatus,
    OID_hm2FMConfigRemoteSaveDestination,
    OID_hm2FMConfigRemoteSaveUsername,
    OID_hm2FMConfigRemoteSavePassword,
    OID_hm2FMActionSourceData, OID_hm2FMActionDestinationData,
    OID_hm2PwdMgmtMinLength, OID_hm2PwdMgmtLoginAttempts,
    OID_hm2PwdMgmtLoginAttemptsTimePeriod,
    OID_hm2PwdMgmtMinUpperCase, OID_hm2PwdMgmtMinLowerCase,
    OID_hm2PwdMgmtMinNumericNumbers, OID_hm2PwdMgmtMinSpecialCharacters,
    OID_hm2LogSyslogAdminStatus, OID_hm2LogSyslogServerIPAddr,
    OID_hm2LogSyslogServerUdpPort, OID_hm2LogSyslogServerLevelUpto,
    OID_hm2LogSyslogServerTransport,
    OID_hm2SntpClientAdminState,
    OID_hm2NtpServerAdminState, OID_hm2NtpServerLocalClockStratum,
    OID_hm2WebHttpAdminStatus, OID_hm2WebHttpsAdminStatus,
    OID_hm2WebHttpPortNumber, OID_hm2WebHttpsPortNumber,
    OID_hm2SshAdminStatus, OID_hm2TelnetServerAdminStatus,
    OID_hm2SnmpV1AdminStatus, OID_hm2SnmpV2AdminStatus,
    OID_hm2SnmpV3AdminStatus, OID_hm2SnmpPortNumber,
    OID_hm2Iec61850MmsServerAdminStatus, OID_hm2PNIOAdminStatus,
    OID_hm2EtherNetIPAdminStatus, OID_hm2Iec62541OpcUaAdminStatus,
    OID_hm2ModbusTcpServerAdminStatus,
    OID_hm2DevMgmtSwVersAllowUnsigned,
    OID_hm2ExtNvmTableIndex,
    OID_hm2ExtNvmAutomaticSoftwareLoad,
    OID_hm2ExtNvmConfigLoadPriority, OID_hm2ExtNvmConfigSave,
    OID_hm2AgentDot1qBridgeMvrpMode, OID_hm2AgentDot1qBridgeMmrpMode,
    _OID_DEVSEC_ALL,
    OID_hm2PreLoginBannerAdminStatus, OID_hm2PreLoginBannerText,
    OID_hm2CliLoginBannerAdminStatus, OID_hm2CliLoginBannerText,
    OID_hm2SshSessionTimeout, OID_hm2SshMaxSessionsCount,
    OID_hm2SshSessionsCount,
    OID_hm2SshOutboundSessionTimeout, OID_hm2SshOutboundMaxSessionsCount,
    OID_hm2SshOutboundSessionsCount,
    OID_hm2TelnetServerSessionsTimeOut, OID_hm2TelnetServerMaxSessions,
    OID_hm2TelnetServerSessionsCount,
    OID_hm2WebIntfTimeOut, OID_hm2CliLoginTimeoutSerial,
    OID_hm2NetconfSessionTimeout, OID_hm2NetconfMaxSessions,
    OID_hm2NetconfSessionsCount,
    OID_hm2RmaOperation, OID_hm2RmaLoggingGlobal,
    OID_hm2SnmpTrapServiceAdminStatus,
    OID_hm2UserSnmpAuthType, OID_hm2UserSnmpEncType,
    OID_hm2DnsClientAdminState, OID_hm2DnsClientConfigSource,
    OID_hm2DnsClientDefaultDomainName, OID_hm2DnsClientRequestTimeout,
    OID_hm2DnsClientRequestRetransmits, OID_hm2DnsClientCacheAdminState,
    OID_hm2DnsClientServerAddressType, OID_hm2DnsClientServerAddress,
    OID_hm2DnsClientServerRowStatus,
    OID_hm2DnsClientServerDiagAddressType, OID_hm2DnsClientServerDiagAddress,
    OID_hm2PoeMgmtAdminStatus, OID_hm2PoeMgmtReservedPower,
    OID_hm2PoeMgmtDeliveredCurrent,
    OID_hm2PoeMgmtPortAdminEnable, OID_hm2PoeMgmtPortConsumptionPower,
    OID_hm2PoeMgmtPortDetectionStatus, OID_hm2PoeMgmtPortPowerPriority,
    OID_hm2PoeMgmtPortPowerClassification, OID_hm2PoeMgmtPortName,
    OID_hm2PoeMgmtPortClassValid, OID_hm2PoeMgmtPortFastStartup,
    OID_hm2PoeMgmtPortPowerLimit,
    OID_hm2PoeMgmtModulePower, OID_hm2PoeMgmtModuleMaximumPower,
    OID_hm2PoeMgmtModuleReservedPower, OID_hm2PoeMgmtModuleDeliveredPower,
    OID_hm2PoeMgmtModulePowerSource, OID_hm2PoeMgmtModuleUsageThreshold,
    OID_hm2PoeMgmtModuleNotifCtlEnable,
    OID_hm2AgentRadiusServerRowStatus,
    OID_hm2AgentTacacsServerStatus,
    OID_hm2LdapClientAdminState,
    OID_hm2UserLockoutStatus, OID_hm2UserPwdPolicyChk,
    OID_hm2UserPassword,
    OID_hm2AgentGlobalPortSecurityMode,
    OID_hm2AgentPortSecurityOperationMode,
    OID_hm2AgentPortSecurityMode,
    OID_hm2AgentPortSecurityDynamicLimit,
    OID_hm2AgentPortSecurityStaticLimit,
    OID_hm2AgentPortSecurityAutoDisable,
    OID_hm2AgentPortSecurityViolationTrapMode,
    OID_hm2AgentPortSecurityViolationTrapFrequency,
    OID_hm2AgentPortSecurityDynamicCount,
    OID_hm2AgentPortSecurityStaticCount,
    OID_hm2AgentPortSecurityStaticIpCount,
    OID_hm2AgentPortSecurityLastDiscardedMAC,
    OID_hm2AgentPortSecurityStaticMACs,
    OID_hm2AgentPortSecurityStaticIPs,
    OID_hm2AgentPortSecurityMACAddressAdd,
    OID_hm2AgentPortSecurityMACAddressRemove,
    OID_hm2AgentPortSecurityIPAddressAdd,
    OID_hm2AgentPortSecurityIPAddressRemove,
    OID_hm2AgentDhcpSnoopingAdminMode,
    OID_hm2AgentDhcpSnoopingVerifyMac,
    OID_hm2AgentDhcpSnoopingVlanIndex,
    OID_hm2AgentDhcpSnoopingVlanEnable,
    OID_hm2AgentDhcpSnoopingIfTrustEnable,
    OID_hm2AgentDhcpSnoopingIfLogEnable,
    OID_hm2AgentDhcpSnoopingIfRateLimit,
    OID_hm2AgentDhcpSnoopingIfBurstInterval,
    OID_hm2AgentDhcpSnoopingIfAutoDisable,
    OID_hm2AgentDaiSrcMacValidate,
    OID_hm2AgentDaiDstMacValidate,
    OID_hm2AgentDaiIPValidate,
    OID_hm2AgentDaiVlanDynArpInspEnable,
    OID_hm2AgentDaiVlanLoggingEnable,
    OID_hm2AgentDaiVlanBindingCheckEnable,
    OID_hm2AgentDaiIfTrustEnable,
    OID_hm2AgentDaiIfRateLimit,
    OID_hm2AgentDaiIfBurstInterval,
    OID_hm2AgentDaiIfAutoDisable,
)
from napalm.base.exceptions import ConnectionException


class TestHelpers(unittest.TestCase):
    """Test helper functions in isolation."""

    def test_format_mac_bytes(self):
        self.assertEqual(_format_mac(b'\x00\x1b\x1e\xc8\x80\x00'), '00:1b:1e:c8:80:00')

    def test_format_mac_hex_string(self):
        self.assertEqual(_format_mac('0x001b1ec88000'), '00:1b:1e:c8:80:00')

    def test_format_mac_empty(self):
        self.assertEqual(_format_mac(b''), '')

    def test_mask_to_prefix_24(self):
        self.assertEqual(_mask_to_prefix('255.255.255.0'), 24)

    def test_mask_to_prefix_16(self):
        self.assertEqual(_mask_to_prefix('255.255.0.0'), 16)

    def test_mask_to_prefix_32(self):
        self.assertEqual(_mask_to_prefix('255.255.255.255'), 32)

    def test_mask_to_prefix_25(self):
        self.assertEqual(_mask_to_prefix('255.255.255.128'), 25)

    def test_mask_to_prefix_invalid(self):
        self.assertEqual(_mask_to_prefix('bad'), 32)

    def test_parse_sysDescr_hirschmann(self):
        model, ver = _parse_sysDescr(
            'Hirschmann GRS1042 HiOS-3A-09.4.04 Manager Switch'
        )
        self.assertEqual(model, 'GRS1042')
        self.assertEqual(ver, 'HiOS-3A-09.4.04')

    def test_parse_sysDescr_brs(self):
        model, ver = _parse_sysDescr('Hirschmann BRS50 HiOS-2S-09.4.02')
        self.assertEqual(model, 'BRS50')
        self.assertEqual(ver, 'HiOS-2S-09.4.02')

    def test_parse_sysDescr_short(self):
        model, ver = _parse_sysDescr('X')
        self.assertEqual(model, 'Unknown')
        self.assertEqual(ver, 'Unknown')

    def test_snmp_str_ip_address(self):
        """_snmp_str uses prettyPrint for IpAddress-like objects."""
        class FakeIpAddress:
            def prettyPrint(self):
                return '255.255.255.0'
            def __str__(self):
                return '\xff\xff\xff\x00'
        self.assertEqual(_snmp_str(FakeIpAddress()), '255.255.255.0')
        self.assertEqual(_snmp_str('plain string'), 'plain string')

    def test_parse_fw_version(self):
        self.assertEqual(_parse_fw_version('HiOS-2A-10.3.04 2025-12-08 16:54'), 'HiOS-2A-10.3.04')
        self.assertEqual(_parse_fw_version('HiOS-3A-09.4.04'), 'HiOS-3A-09.4.04')

    def test_decode_capabilities_bridge_router(self):
        # bit 2 (bridge) + bit 4 (router) set = 0b00101000 = 0x28
        caps = _decode_capabilities(b'\x28')
        self.assertIn('bridge', caps)
        self.assertIn('router', caps)
        self.assertNotIn('repeater', caps)

    def test_decode_capabilities_empty(self):
        self.assertEqual(_decode_capabilities(b''), [])

    def test_decode_portlist(self):
        # Port 1 and 3: byte 0 = 0b10100000 = 0xa0
        bp_map = {'1': '1/1', '2': '1/2', '3': '1/3'}
        result = _decode_portlist(b'\xa0', bp_map)
        self.assertEqual(result, ['1/1', '1/3'])

    def test_decode_portlist_hex_string(self):
        bp_map = {'1': '1/1', '2': '1/2'}
        result = _decode_portlist('0xc0', bp_map)
        self.assertEqual(result, ['1/1', '1/2'])

    def test_format_mrp_domain_id_default(self):
        suffix = '.'.join(['255'] * 16)
        result = _format_mrp_domain_id(suffix)
        self.assertIn('(Default)', result)
        self.assertTrue(result.startswith('255.255.255'))

    def test_format_mrp_domain_id_custom(self):
        suffix = '.'.join(['1', '2', '3', '4'] + ['0'] * 12)
        result = _format_mrp_domain_id(suffix)
        self.assertNotIn('(Default)', result)
        self.assertTrue(result.startswith('1.2.3.4'))

    def test_decode_implied_string_admin(self):
        # IMPLIED: no length prefix, just raw ASCII codes
        self.assertEqual(_decode_implied_string('97.100.109.105.110'), 'admin')

    def test_decode_implied_string_guest(self):
        self.assertEqual(_decode_implied_string('103.117.101.115.116'), 'guest')

    def test_decode_implied_string_empty(self):
        self.assertEqual(_decode_implied_string(''), '')

    def test_snmp_int_bytes(self):
        """_snmp_int handles raw bytes (e.g. TruthValue as b'\\x01')."""
        class FakeOctetString:
            def hasValue(self): return True
            def __bytes__(self): return b'\x01'
            def __int__(self): raise ValueError
        self.assertEqual(_snmp_int(FakeOctetString()), 1)
        self.assertEqual(_snmp_int(None, 99), 99)
        self.assertEqual(_snmp_int('', 42), 42)
        self.assertEqual(_snmp_int(128), 128)

    def test_snmp_ip_hex(self):
        """_snmp_ip converts hex InetAddress to dotted notation."""
        class FakeAddr:
            def prettyPrint(self): return '0xc0a80301'
            def hasValue(self): return True
            def __bytes__(self): return b'\xc0\xa8\x03\x01'
        self.assertEqual(_snmp_ip(FakeAddr()), '192.168.3.1')


class TestSNMPHIOSAuth(unittest.TestCase):
    """Test authentication mode selection."""

    def test_snmpv3_auth_with_password(self):
        snmp = SNMPHIOS('192.168.1.4', 'admin', 'private', 10)
        auth = snmp._build_auth()
        # Should be UsmUserData for SNMPv3
        from pysnmp.hlapi.v3arch.asyncio import UsmUserData
        self.assertIsInstance(auth, UsmUserData)
        self.assertEqual(auth.security_level, 'authPriv')

    def test_snmpv2c_auth_without_password(self):
        snmp = SNMPHIOS('192.168.1.4', 'public', '', 10)
        auth = snmp._build_auth()
        from pysnmp.hlapi.v3arch.asyncio import CommunityData
        self.assertIsInstance(auth, CommunityData)

    def test_snmpv3_short_password(self):
        """Verify 7-char password 'private' works (pre-computed master key)."""
        snmp = SNMPHIOS('192.168.1.4', 'admin', 'private', 10)
        # Should not raise — master key bypasses 8-char constraint
        auth = snmp._build_auth()
        self.assertEqual(auth.security_level, 'authPriv')

    def test_snmpv3_long_password(self):
        """Verify normal-length passwords also work."""
        snmp = SNMPHIOS('192.168.1.4', 'admin', 'longpassword123', 10)
        auth = snmp._build_auth()
        self.assertEqual(auth.security_level, 'authPriv')


class TestSNMPHIOS(unittest.TestCase):
    """Test SNMPHIOS getter methods by mocking _get_scalar and _walk."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    # ------------------------------------------------------------------
    # get_facts
    # ------------------------------------------------------------------

    def test_get_facts_with_private_mibs(self):
        async def mock_scalar(*oids):
            return {
                OID_sysName: 'GRS1042-CORE',
                OID_sysUpTime: 8640000,  # 86400 seconds = 1 day
                OID_sysDescr: 'Hirschmann GREYHOUND',
                OID_hm2ProductDescr: 'GRS1042-6T6ZTHH00V9HHSE3AMR',
                OID_hm2SerialNumber: '942135999000101022',
                OID_hm2FwVersionRAM: 'HiOS-3A-09.4.04 2024-06-19 12:08',
            }

        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2', '3': '2/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
                facts = self.snmp.get_facts()

        self.assertEqual(facts['hostname'], 'GRS1042-CORE')
        self.assertEqual(facts['vendor'], 'Belden')
        self.assertEqual(facts['model'], 'GRS1042-6T6ZTHH00V9HHSE3AMR')  # full product code
        self.assertEqual(facts['os_version'], 'HiOS-3A-09.4.04')  # from fw version
        self.assertEqual(facts['uptime'], 86400)
        self.assertEqual(facts['serial_number'], '942135999000101022')
        self.assertEqual(facts['interface_list'], ['1/1', '1/2', '2/1'])

    def test_get_facts_fallback_to_sysdescr(self):
        """When private MIBs return empty, fall back to sysDescr parsing."""
        async def mock_scalar(*oids):
            return {
                OID_sysName: 'SWITCH1',
                OID_sysUpTime: 100,
                OID_sysDescr: 'Hirschmann BRS50 HiOS-2S-09.4.02',
                OID_hm2ProductDescr: '',
                OID_hm2SerialNumber: '',
                OID_hm2FwVersionRAM: '',
            }

        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
                facts = self.snmp.get_facts()

        self.assertEqual(facts['model'], 'BRS50')
        self.assertEqual(facts['os_version'], 'HiOS-2S-09.4.02')

    # ------------------------------------------------------------------
    # get_interfaces
    # ------------------------------------------------------------------

    def test_get_interfaces(self):
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {
                    'name': '1/1',
                    'oper': 1,
                    'admin': 1,
                    'highspeed': 1000,
                    'mtu': 1500,
                    'mac': b'\x00\x1b\x1e\xc8\x80\x01',
                    'alias': 'Uplink',
                },
                '2': {
                    'name': '1/2',
                    'oper': 2,
                    'admin': 2,
                    'highspeed': 100,
                    'mtu': 1500,
                    'mac': b'\x00\x1b\x1e\xc8\x80\x02',
                    'alias': '',
                },
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            ifaces = self.snmp.get_interfaces()

        self.assertIn('1/1', ifaces)
        self.assertIn('1/2', ifaces)
        self.assertTrue(ifaces['1/1']['is_up'])
        self.assertTrue(ifaces['1/1']['is_enabled'])
        self.assertEqual(ifaces['1/1']['speed'], 1_000_000_000)
        self.assertEqual(ifaces['1/1']['mtu'], 1500)
        self.assertEqual(ifaces['1/1']['mac_address'], '00:1b:1e:c8:80:01')
        self.assertEqual(ifaces['1/1']['description'], 'Uplink')
        self.assertFalse(ifaces['1/2']['is_up'])
        self.assertFalse(ifaces['1/2']['is_enabled'])
        self.assertEqual(ifaces['1/2']['speed'], 100_000_000)
        self.assertAlmostEqual(ifaces['1/1']['last_flapped'], -1.0)

    # ------------------------------------------------------------------
    # get_interfaces_ip
    # ------------------------------------------------------------------

    def test_get_interfaces_ip(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'100': 'vlan/1'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '192.168.1.254': {
                    'ifindex': '100',
                    'mask': '255.255.255.0',
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                ips = self.snmp.get_interfaces_ip()

        self.assertIn('vlan/1', ips)
        self.assertIn('192.168.1.254', ips['vlan/1']['ipv4'])
        self.assertEqual(ips['vlan/1']['ipv4']['192.168.1.254']['prefix_length'], 24)

    # ------------------------------------------------------------------
    # get_interfaces_counters
    # ------------------------------------------------------------------

    def test_get_interfaces_counters(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {
                    'rx_octets': 1000000,
                    'tx_octets': 2000000,
                    'rx_unicast': 500,
                    'tx_unicast': 600,
                    'rx_multicast': 50,
                    'tx_multicast': 60,
                    'rx_broadcast': 10,
                    'tx_broadcast': 20,
                    'rx_discards': 1,
                    'tx_discards': 2,
                    'rx_errors': 3,
                    'tx_errors': 4,
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                counters = self.snmp.get_interfaces_counters()

        self.assertIn('1/1', counters)
        c = counters['1/1']
        self.assertEqual(c['rx_octets'], 1000000)
        self.assertEqual(c['tx_octets'], 2000000)
        self.assertEqual(c['rx_unicast_packets'], 500)
        self.assertEqual(c['tx_unicast_packets'], 600)
        self.assertEqual(c['rx_multicast_packets'], 50)
        self.assertEqual(c['tx_multicast_packets'], 60)
        self.assertEqual(c['rx_broadcast_packets'], 10)
        self.assertEqual(c['tx_broadcast_packets'], 20)
        self.assertEqual(c['rx_discards'], 1)
        self.assertEqual(c['tx_discards'], 2)
        self.assertEqual(c['rx_errors'], 3)
        self.assertEqual(c['tx_errors'], 4)

    # ------------------------------------------------------------------
    # get_arp_table
    # ------------------------------------------------------------------

    def test_get_arp_table(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'100': 'vlan/1'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '100.192.168.1.1': {
                    'mac': b'\x00\x1b\x1e\xaa\xbb\xcc',
                    'type': 3,  # dynamic
                },
                '100.192.168.1.2': {
                    'mac': b'\x00\x1b\x1e\xdd\xee\xff',
                    'type': 4,  # static
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                arp = self.snmp.get_arp_table()

        self.assertEqual(len(arp), 2)
        entry = next(e for e in arp if e['ip'] == '192.168.1.1')
        self.assertEqual(entry['interface'], 'vlan/1')
        self.assertEqual(entry['mac'], '00:1b:1e:aa:bb:cc')
        self.assertEqual(entry['age'], 0.0)

    # ------------------------------------------------------------------
    # get_mac_address_table
    # ------------------------------------------------------------------

    def test_get_mac_address_table(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_dot1dBasePortIfIndex:
                return {'1': '1', '2': '2'}
            return {}

        async def mock_walk_columns(oid_map, engine=None):
            # FDB walk
            return {
                # VLAN 1, MAC 00:1b:1e:c8:80:00
                '1.0.27.30.200.128.0': {
                    'port': '1',
                    'status': 3,  # learned
                },
                # VLAN 10, MAC 00:1b:1e:c8:80:01
                '10.0.27.30.200.128.1': {
                    'port': '2',
                    'status': 5,  # mgmt
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                    mac_table = self.snmp.get_mac_address_table()

        self.assertEqual(len(mac_table), 2)
        learned = next(e for e in mac_table if e['vlan'] == 1)
        self.assertEqual(learned['mac'], '00:1b:1e:c8:80:00')
        self.assertEqual(learned['interface'], '1/1')
        self.assertFalse(learned['static'])
        self.assertTrue(learned['active'])

        mgmt = next(e for e in mac_table if e['vlan'] == 10)
        self.assertTrue(mgmt['static'])  # status != 3

    # ------------------------------------------------------------------
    # get_lldp_neighbors
    # ------------------------------------------------------------------

    def test_get_lldp_neighbors(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_lldpLocPortId:
                return {'1': '1/1', '2': '1/2'}
            return {}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                # timeMark.localPortNum.remIndex
                '0.1.1': {
                    'sysname': 'BRS50-LOUNGE',
                    'portid': '1/3',
                    'portdesc': 'Port 3',
                    'chassisid': '00:1b:1e:ff:00:01',
                },
                '0.2.1': {
                    'sysname': '',  # empty — should fall back to chassisid
                    'portid': '',
                    'portdesc': 'Uplink',
                    'chassisid': '00:1b:1e:ff:00:02',
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                    neighbors = self.snmp.get_lldp_neighbors()

        self.assertIn('1/1', neighbors)
        self.assertEqual(neighbors['1/1'][0]['hostname'], 'BRS50-LOUNGE')
        self.assertEqual(neighbors['1/1'][0]['port'], '1/3')

        # Fallback: empty sysname -> chassisid, empty portid -> portdesc
        self.assertIn('1/2', neighbors)
        self.assertEqual(neighbors['1/2'][0]['hostname'], '00:1b:1e:ff:00:02')
        self.assertEqual(neighbors['1/2'][0]['port'], 'Uplink')

    # ------------------------------------------------------------------
    # get_lldp_neighbors_detail
    # ------------------------------------------------------------------

    def test_get_lldp_neighbors_detail(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_lldpLocPortId:
                return {'1': '1/1'}
            if base_oid == OID_lldpRemManAddrIfSubtype:
                # timeMark.localPortNum.remIndex.subtype.len.addr
                return {
                    '0.1.1.1.4.192.168.1.4': MagicMock(),
                }
            return {}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '0.1.1': {
                    'chassisid_subtype': 4,
                    'chassisid': '00:1b:1e:c8:80:00',
                    'portid_subtype': 5,
                    'portid': '1/1',
                    'portdesc': 'Port 1',
                    'sysname': 'GRS1042-CORE',
                    'sysdesc': 'Hirschmann GRS1042 HiOS-3A-09.4.04',
                    'caps_supported': b'\x28',  # bridge + router
                    'caps_enabled': b'\x20',    # bridge only
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                    detail = self.snmp.get_lldp_neighbors_detail()

        self.assertIn('1/1', detail)
        d = detail['1/1'][0]
        self.assertEqual(d['parent_interface'], '1/1')
        self.assertEqual(d['remote_system_name'], 'GRS1042-CORE')
        self.assertEqual(d['remote_chassis_id'], '00:1b:1e:c8:80:00')
        self.assertEqual(d['remote_port'], '1/1')
        self.assertEqual(d['remote_port_description'], 'Port 1')
        self.assertIn('bridge', d['remote_system_capab'])
        self.assertIn('router', d['remote_system_capab'])
        self.assertIn('bridge', d['remote_system_enable_capab'])
        self.assertNotIn('router', d['remote_system_enable_capab'])
        self.assertIn('remote_management_address', d)

    # ------------------------------------------------------------------
    # get_vlans
    # ------------------------------------------------------------------

    def test_get_vlans(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2', '3': '1/3'}
            return self.snmp._ifindex_map

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_dot1dBasePortIfIndex:
                return {'1': '1', '2': '2', '3': '3'}
            return {}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {
                    'name': 'default',
                    'egress': b'\xe0',  # ports 1,2,3
                },
                '10': {
                    'name': 'MGMT',
                    'egress': b'\x80',  # port 1 only
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                    vlans = self.snmp.get_vlans()

        self.assertIn(1, vlans)
        self.assertEqual(vlans[1]['name'], 'default')
        self.assertEqual(vlans[1]['interfaces'], ['1/1', '1/2', '1/3'])

        self.assertIn(10, vlans)
        self.assertEqual(vlans[10]['name'], 'MGMT')
        self.assertEqual(vlans[10]['interfaces'], ['1/1'])

    # ------------------------------------------------------------------
    # get_snmp_information
    # ------------------------------------------------------------------

    def test_get_snmp_information(self):
        async def mock_scalar(*oids):
            return {
                OID_sysName: 'GRS1042-CORE',
                OID_sysContact: 'admin@example.com',
                OID_sysLocation: 'Lab Rack 3',
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            info = self.snmp.get_snmp_information()

        self.assertEqual(info['chassis_id'], 'GRS1042-CORE')
        self.assertEqual(info['contact'], 'admin@example.com')
        self.assertEqual(info['location'], 'Lab Rack 3')
        self.assertEqual(info['community'], {})

    # ------------------------------------------------------------------
    # get_environment
    # ------------------------------------------------------------------

    def test_get_environment_full(self):
        """Test environment with temp, PSU, fans, CPU, memory."""
        async def mock_scalar(*oids):
            return {
                OID_hm2Temperature: 48,
                OID_hm2TempUpperLimit: 70,
                OID_hm2TempLowerLimit: 0,
                OID_hm2CpuUtil: 21,
                OID_hm2MemAlloc: 358592,
                OID_hm2MemFree: 148920,
            }

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_hm2PSState:
                return {
                    '1': 1,  # present
                    '2': 2,  # defective
                }
            if base_oid == OID_hm2FanModuleStatus:
                return {}
            if base_oid == OID_hm2FanStatus:
                return {
                    '1.1.1': 2,  # available-and-ok
                    '1.1.2': 2,  # available-and-ok
                }
            return {}

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                env = self.snmp.get_environment()

        # Temperature
        self.assertIn('chassis', env['temperature'])
        self.assertEqual(env['temperature']['chassis']['temperature'], 48.0)
        self.assertFalse(env['temperature']['chassis']['is_alert'])
        self.assertFalse(env['temperature']['chassis']['is_critical'])

        # Power
        self.assertIn('Power Supply P1', env['power'])
        self.assertTrue(env['power']['Power Supply P1']['status'])
        self.assertIn('Power Supply P2', env['power'])
        self.assertFalse(env['power']['Power Supply P2']['status'])  # defective

        # Fans
        self.assertIn('fan1/1', env['fans'])
        self.assertTrue(env['fans']['fan1/1']['status'])
        self.assertIn('fan1/2', env['fans'])
        self.assertTrue(env['fans']['fan1/2']['status'])

        # CPU
        self.assertEqual(env['cpu']['0']['%usage'], 21.0)

        # Memory — available=allocated, used=allocated-free (matches SSH driver)
        self.assertEqual(env['memory']['available_ram'], 358592)
        self.assertEqual(env['memory']['used_ram'], 358592 - 148920)

    def test_get_environment_temp_alert(self):
        """Test temperature alert triggers."""
        async def mock_scalar(*oids):
            return {
                OID_hm2Temperature: 75,  # above 70 upper limit
                OID_hm2TempUpperLimit: 70,
                OID_hm2TempLowerLimit: 0,
                OID_hm2CpuUtil: 10,
                OID_hm2MemAlloc: 100000,
                OID_hm2MemFree: 50000,
            }

        async def mock_walk(base_oid, engine=None):
            return {}

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                env = self.snmp.get_environment()

        self.assertTrue(env['temperature']['chassis']['is_alert'])
        self.assertTrue(env['temperature']['chassis']['is_critical'])

    def test_get_environment_no_fans(self):
        """Test fanless device (e.g. BRS50, GRS1042)."""
        async def mock_scalar(*oids):
            return {
                OID_hm2Temperature: 43,
                OID_hm2TempUpperLimit: 70,
                OID_hm2TempLowerLimit: 0,
                OID_hm2CpuUtil: 23,
                OID_hm2MemAlloc: 128424,
                OID_hm2MemFree: 124652,
            }

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_hm2PSState:
                return {'1': 1, '2': 3}  # PSU1 present, PSU2 not installed
            return {}

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                env = self.snmp.get_environment()

        self.assertEqual(env['fans'], {})
        self.assertIn('Power Supply P1', env['power'])
        self.assertNotIn('Power Supply P2', env['power'])  # notInstalled filtered out

    def test_get_environment_fan_failure(self):
        """Test fan failure detection."""
        async def mock_scalar(*oids):
            return {
                OID_hm2Temperature: 60,
                OID_hm2TempUpperLimit: 70,
                OID_hm2TempLowerLimit: 0,
                OID_hm2CpuUtil: 50,
                OID_hm2MemAlloc: 200000,
                OID_hm2MemFree: 100000,
            }

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_hm2PSState:
                return {}
            if base_oid == OID_hm2FanModuleStatus:
                return {}
            if base_oid == OID_hm2FanStatus:
                return {
                    '1.1.1': 2,  # ok
                    '1.1.2': 3,  # failure!
                }
            return {}

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                env = self.snmp.get_environment()

        self.assertTrue(env['fans']['fan1/1']['status'])
        self.assertFalse(env['fans']['fan1/2']['status'])  # failure

    # ------------------------------------------------------------------
    # get_optics
    # ------------------------------------------------------------------

    def test_get_optics(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'3': '1/3', '5': '1/5'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '3': {'tx_power': '-4.2', 'rx_power': '-4.4'},
                '5': {'tx_power': '-3.1', 'rx_power': '-5.8'},
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                optics = self.snmp.get_optics()

        self.assertIn('1/3', optics)
        self.assertIn('1/5', optics)
        ch = optics['1/3']['physical_channels']['channel'][0]
        self.assertEqual(ch['index'], 0)
        self.assertAlmostEqual(ch['state']['output_power']['instant'], -4.2)
        self.assertAlmostEqual(ch['state']['input_power']['instant'], -4.4)
        self.assertEqual(ch['state']['laser_bias_current']['instant'], 0.0)

    # ------------------------------------------------------------------
    # get_users
    # ------------------------------------------------------------------

    def test_get_users(self):
        async def mock_walk_columns(oid_map, engine=None):
            return {
                # admin: a=97 d=100 m=109 i=105 n=110 (IMPLIED, no length prefix)
                '.97.100.109.105.110': {
                    'role': 15, 'locked': 2, 'policy_check': 2,
                    'snmp_auth': 1, 'snmp_enc': 1, 'row_status': 1,
                },
                # guest: g=103 u=117 e=101 s=115 t=116
                '.103.117.101.115.116': {
                    'role': 1, 'locked': 2, 'policy_check': 2,
                    'snmp_auth': 1, 'snmp_enc': 1, 'row_status': 1,
                },
                # inactive user 'test'
                '.116.101.115.116': {
                    'role': 15, 'locked': 2, 'policy_check': 2,
                    'snmp_auth': 1, 'snmp_enc': 1, 'row_status': 2,
                },
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            users = self.snmp.get_users()

        names = {u['name'] for u in users}
        self.assertIn('admin', names)
        self.assertIn('guest', names)
        self.assertIn('test', names)
        admin = next(u for u in users if u['name'] == 'admin')
        self.assertEqual(admin['role'], 'administrator')
        self.assertTrue(admin['active'])
        guest = next(u for u in users if u['name'] == 'guest')
        self.assertEqual(guest['role'], 'guest')
        test = next(u for u in users if u['name'] == 'test')
        self.assertFalse(test['active'])  # notInService

    # ------------------------------------------------------------------
    # get_ntp_servers
    # ------------------------------------------------------------------

    def test_get_ntp_servers(self):
        async def mock_walk(base_oid, engine=None):
            return {'1': '192.168.3.1', '2': '10.0.0.1'}

        with patch.object(self.snmp, '_walk', side_effect=mock_walk):
            servers = self.snmp.get_ntp_servers()

        self.assertIn('192.168.3.1', servers)
        self.assertIn('10.0.0.1', servers)
        self.assertEqual(servers['192.168.3.1'], {})
        self.assertEqual(servers['10.0.0.1'], {})

    # ------------------------------------------------------------------
    # get_ntp_stats
    # ------------------------------------------------------------------

    def test_get_ntp_stats(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2SntpRequestInterval: 64,
                OID_hm2SntpClientStatus: 1,
            }

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {'addr': '192.168.3.1', 'status': 2},  # 2=success
                '2': {'addr': '10.0.0.1', 'status': 1},     # 1=not synced
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                stats = self.snmp.get_ntp_stats()

        self.assertEqual(len(stats), 2)
        synced = next(s for s in stats if s['remote'] == '192.168.3.1')
        self.assertTrue(synced['synchronized'])
        self.assertEqual(synced['hostpoll'], 64)
        self.assertEqual(synced['type'], 'ipv4')

        not_synced = next(s for s in stats if s['remote'] == '10.0.0.1')
        self.assertFalse(not_synced['synchronized'])

    # ------------------------------------------------------------------
    # get_mrp
    # ------------------------------------------------------------------

    def test_get_mrp_not_configured(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {}  # empty — no MRP configured

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                mrp = self.snmp.get_mrp()

        self.assertEqual(mrp, {'configured': False})

    def test_get_mrp_client(self):
        domain_suffix = '.'.join(['255'] * 16)

        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'3': '1/3', '4': '1/4'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {
                domain_suffix: {
                    'domain_name': '',
                    'rp1_ifindex': '3',
                    'rp1_oper': 3,  # forwarding
                    'rp2_ifindex': '4',
                    'rp2_oper': 2,  # blocked
                    'role_admin': 1,  # client
                    'role_oper': 1,   # client
                    'recovery_delay': 2,  # 200ms
                    'vlan': 1,
                    'priority': 32768,
                    'react_on_link': 1,  # advanced mode
                    'ring_open_count': 0,
                    'blocked_support': 1,
                    'ring_oper': 2,  # closed
                    'redundancy_oper': 1,
                    'config_oper': 1,  # noError
                    'row_status': 1,  # active
                    'fixed_backup': 0,
                },
            }

        async def mock_scalar(*oids):
            return {OID_hm2MrpFastMrp: 0}

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
                    mrp = self.snmp.get_mrp()

        self.assertTrue(mrp['configured'])
        self.assertEqual(mrp['mode'], 'client')
        self.assertEqual(mrp['port_primary'], '1/3')
        self.assertEqual(mrp['port_secondary'], '1/4')
        self.assertEqual(mrp['port_primary_state'], 'forwarding')
        self.assertEqual(mrp['port_secondary_state'], 'blocked')
        self.assertIn('(Default)', mrp['domain_id'])
        self.assertEqual(mrp['vlan'], 1)
        self.assertEqual(mrp['recovery_delay'], '200ms')
        self.assertTrue(mrp['advanced_mode'])
        self.assertEqual(mrp['info'], 'no error')
        self.assertTrue(mrp['blocked_support'])
        self.assertNotIn('ring_state', mrp)  # client doesn't have ring_state

    def test_get_mrp_manager(self):
        domain_suffix = '.'.join(['255'] * 16)

        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk_columns(oid_map, engine=None):
            return {
                domain_suffix: {
                    'domain_name': 'RING-A',
                    'rp1_ifindex': '1',
                    'rp1_oper': 3,  # forwarding
                    'rp2_ifindex': '2',
                    'rp2_oper': 3,  # forwarding
                    'role_admin': 2,  # manager
                    'role_oper': 2,
                    'recovery_delay': 2,
                    'vlan': 1,
                    'priority': 32768,
                    'react_on_link': 1,
                    'ring_open_count': 5,
                    'blocked_support': 0,
                    'ring_oper': 2,  # closed
                    'redundancy_oper': 1,  # available
                    'config_oper': 1,
                    'row_status': 1,
                    'fixed_backup': 0,
                },
            }

        async def mock_scalar(*oids):
            return {OID_hm2MrpFastMrp: 1}

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
                    mrp = self.snmp.get_mrp()

        self.assertTrue(mrp['configured'])
        self.assertEqual(mrp['mode'], 'manager')
        self.assertEqual(mrp['ring_state'], 'closed')
        self.assertTrue(mrp['redundancy'])
        self.assertEqual(mrp['ring_open_count'], 5)
        self.assertTrue(mrp['fast_mrp'])
        self.assertNotIn('blocked_support', mrp)  # manager doesn't have this

    # ------------------------------------------------------------------
    # get_hidiscovery
    # ------------------------------------------------------------------

    def test_get_hidiscovery_readonly(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2HiDiscOper: 1,        # enabled (HmEnabledStatus)
                OID_hm2HiDiscMode: 2,        # read-only
                OID_hm2HiDiscBlinking: 2,    # disabled (HmEnabledStatus)
                OID_hm2HiDiscProtocol: 0x60, # BITS: v1(0x40)+v2(0x20)
                OID_hm2HiDiscRelay: 2,       # disabled (HmEnabledStatus)
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            disc = self.snmp.get_hidiscovery()

        self.assertTrue(disc['enabled'])
        self.assertEqual(disc['mode'], 'read-only')
        self.assertFalse(disc['blinking'])
        self.assertEqual(disc['protocols'], ['v1', 'v2'])
        self.assertFalse(disc['relay'])

    def test_get_hidiscovery_readwrite_blinking(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2HiDiscOper: 1,        # enabled (HmEnabledStatus)
                OID_hm2HiDiscMode: 1,        # read-write
                OID_hm2HiDiscBlinking: 1,    # enabled (HmEnabledStatus)
                OID_hm2HiDiscProtocol: 0x60, # BITS: v1(0x40)+v2(0x20)
                OID_hm2HiDiscRelay: 1,       # enabled (HmEnabledStatus)
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            disc = self.snmp.get_hidiscovery()

        self.assertTrue(disc['enabled'])
        self.assertEqual(disc['mode'], 'read-write')
        self.assertTrue(disc['blinking'])
        self.assertEqual(disc['protocols'], ['v1', 'v2'])
        self.assertTrue(disc['relay'])

    def test_get_hidiscovery_l2_no_relay(self):
        """L2 devices return NoSuchInstance for relay — field should be omitted."""
        from pysnmp.proto.rfc1905 import NoSuchInstance as _NoSuchInstance
        no_such = _NoSuchInstance()

        async def mock_scalar(*oids):
            return {
                OID_hm2HiDiscOper: 1,
                OID_hm2HiDiscMode: 2,
                OID_hm2HiDiscBlinking: 2,
                OID_hm2HiDiscProtocol: 0x60,
                OID_hm2HiDiscRelay: no_such,
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            disc = self.snmp.get_hidiscovery()

        self.assertTrue(disc['enabled'])
        self.assertEqual(disc['mode'], 'read-only')
        self.assertNotIn('relay', disc)

    # ------------------------------------------------------------------
    # get_config_status
    # ------------------------------------------------------------------

    def test_get_config_status_saved(self):
        """All states ok — config is saved."""
        async def mock_scalar(*oids):
            return {
                OID_hm2FMNvmState: 1,       # ok
                OID_hm2FMEnvmState: 1,      # ok
                OID_hm2FMBootParamState: 1,  # ok
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            status = self.snmp.get_config_status()

        self.assertTrue(status['saved'])
        self.assertEqual(status['nvm'], 'ok')
        self.assertEqual(status['aca'], 'ok')
        self.assertEqual(status['boot'], 'ok')

    def test_get_config_status_unsaved(self):
        """NVM out of sync, ExtNVM absent, boot ok — config is NOT saved."""
        async def mock_scalar(*oids):
            return {
                OID_hm2FMNvmState: 2,       # out of sync
                OID_hm2FMEnvmState: 3,      # absent
                OID_hm2FMBootParamState: 1,  # ok
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            status = self.snmp.get_config_status()

        self.assertFalse(status['saved'])
        self.assertEqual(status['nvm'], 'out of sync')
        self.assertEqual(status['aca'], 'absent')
        self.assertEqual(status['boot'], 'ok')

    # ------------------------------------------------------------------
    # save_config
    # ------------------------------------------------------------------

    def test_save_config(self):
        """save_config GETs key, SETs action, polls until ok."""
        # Mock GET for activate key
        scalar_calls = []
        async def mock_scalar(*oids):
            scalar_calls.append(oids)
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 42}
            # Poll calls: return ok immediately
            return {
                OID_hm2FMNvmState: 1,
                OID_hm2FMEnvmState: 3,
                OID_hm2FMBootParamState: 1,
            }

        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, value))

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                result = self.snmp.save_config()

        # Verify SET was called with correct OID and key value
        self.assertEqual(len(set_calls), 1)
        self.assertEqual(set_calls[0][0], OID_hm2FMActionActivate_save)
        self.assertEqual(int(set_calls[0][1]), 42)

        # Verify result is the config status
        self.assertTrue(result['saved'])
        self.assertEqual(result['nvm'], 'ok')

    # ------------------------------------------------------------------
    # get_lldp_neighbors_detail_extended
    # ------------------------------------------------------------------

    def test_get_lldp_neighbors_detail_extended(self):
        async def mock_ifindex_map(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        call_count = [0]

        async def mock_walk(base_oid, engine=None):
            if base_oid == OID_lldpLocPortId:
                return {'1': '1/1'}
            if base_oid == OID_lldpRemManAddrIfSubtype:
                return {'0.1.1.1.4.192.168.1.4': MagicMock()}
            # 802.1 walks
            if base_oid == OID_lldpXdot1RemPortVlanId:
                return {'0.1.1': 10}
            if base_oid == OID_lldpXdot1RemVlanId:
                return {'0.1.1.10': 1, '0.1.1.20': 1}
            return {}

        async def mock_walk_columns(oid_map, engine=None):
            call_count[0] += 1
            # First call: standard LLDP columns
            if call_count[0] == 1:
                return {
                    '0.1.1': {
                        'chassisid_subtype': 4,
                        'chassisid': '00:1b:1e:c8:80:00',
                        'portid_subtype': 5,
                        'portid': '1/1',
                        'portdesc': 'Port 1',
                        'sysname': 'GRS1042-CORE',
                        'sysdesc': 'Hirschmann GRS1042',
                        'caps_supported': b'\x28',
                        'caps_enabled': b'\x20',
                    },
                }
            # Second call: 802.3 autoneg
            if call_count[0] == 2:
                return {
                    '0.1.1': {
                        'autoneg_sup': 1,   # TruthValue: true
                        'autoneg_en': 1,
                        'mau_type': '1.3.6.1.2.1.26.4.15.30',  # 1000BaseTFD
                    },
                }
            # Third call: 802.3 link-agg
            if call_count[0] == 3:
                return {
                    '0.1.1': {
                        'agg_status': 0x80,  # BITS: aggregationCapable (bit 0 MSB)
                        'agg_port_id': 3,
                    },
                }
            return {}

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifindex_map):
            with patch.object(self.snmp, '_walk', side_effect=mock_walk):
                with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
                    detail = self.snmp.get_lldp_neighbors_detail_extended()

        self.assertIn('1/1', detail)
        d = detail['1/1'][0]
        self.assertEqual(d['parent_interface'], '1/1')
        self.assertEqual(d['remote_system_name'], 'GRS1042-CORE')
        self.assertEqual(d['remote_chassis_id'], '00:1b:1e:c8:80:00')
        self.assertIn('bridge', d['remote_system_capab'])
        # Management address
        self.assertEqual(d['remote_management_ipv4'], '192.168.1.4')
        # 802.3 extensions
        self.assertEqual(d['autoneg_support'], 'yes')
        self.assertEqual(d['autoneg_enabled'], 'yes')
        self.assertEqual(d['port_oper_mau_type'], '1000BaseTFD')
        self.assertEqual(d['link_agg_status'], 'agg. capable')
        self.assertEqual(d['link_agg_port_id'], '3')
        # 802.1 extensions
        self.assertEqual(d['port_vlan_id'], '10')
        self.assertEqual(d['vlan_membership'], [10, 20])

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def test_close_clears_state(self):
        self.snmp._ifindex_map = {'1': '1/1'}
        self.snmp.close()
        self.assertFalse(self.snmp._connected)
        self.assertIsNone(self.snmp._ifindex_map)

    def test_open_success(self):
        async def mock_scalar(*oids):
            return {OID_sysDescr: 'Hirschmann BRS50 HiOS-2S-09.4.02'}

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            self.snmp._connected = False
            self.snmp.open()
            self.assertTrue(self.snmp._connected)

    def test_open_failure(self):
        async def mock_scalar(*oids):
            raise Exception("timeout")

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            self.snmp._connected = False
            with self.assertRaises(ConnectionException):
                self.snmp.open()


    # ------------------------------------------------------------------
    # Write operations — set_interface, set_hidiscovery, set_mrp, delete_mrp
    # ------------------------------------------------------------------

    def test_set_interface_disable(self):
        """SET ifAdminStatus=2 (down) for a port."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        async def mock_ifmap(engine=None):
            return {'5': '1/5', '6': '1/6'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            self.snmp.set_interface('1/5', enabled=False)
            self.assertEqual(len(set_calls), 1)
            self.assertIn(OID_ifAdminStatus, set_calls[0][0])
            self.assertIn('.5', set_calls[0][0])
            self.assertEqual(int(set_calls[0][1]), 2)

    def test_set_interface_enable_with_description(self):
        """SET ifAdminStatus=1 + ifAlias in one PDU."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        async def mock_ifmap(engine=None):
            return {'5': '1/5'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            self.snmp.set_interface('1/5', enabled=True, description='Uplink')
            self.assertEqual(len(set_calls), 2)
            # First: admin up
            self.assertIn(OID_ifAdminStatus, set_calls[0][0])
            self.assertEqual(int(set_calls[0][1]), 1)
            # Second: description
            self.assertIn(OID_ifAlias, set_calls[1][0])
            self.assertEqual(str(set_calls[1][1]), 'Uplink')

    def test_set_interface_unknown_port(self):
        """Unknown interface raises ValueError."""
        async def mock_ifmap(engine=None):
            return {'5': '1/5'}
        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.set_interface('99/99', enabled=True)
            self.assertIn("Unknown interface", str(ctx.exception))

    def test_clear_config(self):
        """Clear running config: SET parameter=1, then trigger clear action."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {OID_hm2FMActionActivateKey: 42}

        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.clear_config()
            self.assertTrue(result['restarting'])
            # parameter=1 (none), then activate with key
            self.assertEqual(set_calls[0][1], 1)   # param
            self.assertEqual(set_calls[1][1], 42)   # key
            self.assertIn('3.10.10.10', set_calls[1][0])  # clear_config OID

    def test_clear_config_keep_ip(self):
        """Clear config with keep_ip: parameter=11."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {OID_hm2FMActionActivateKey: 42}

        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.clear_config(keep_ip=True)
            self.assertTrue(result['restarting'])
            self.assertEqual(set_calls[0][1], 11)  # keep-ip param

    def test_clear_factory(self):
        """Factory reset: SET parameter=1, then trigger clear action."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {OID_hm2FMActionActivateKey: 42}

        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.clear_factory()
            self.assertTrue(result['rebooting'])
            self.assertEqual(set_calls[0][1], 1)   # param=none
            self.assertEqual(set_calls[1][1], 42)   # key
            self.assertIn('3.10.2.2', set_calls[1][0])  # clear_factory OID

    def test_clear_factory_erase_all(self):
        """Factory reset with erase_all: parameter=2."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {OID_hm2FMActionActivateKey: 42}

        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.clear_factory(erase_all=True)
            self.assertTrue(result['rebooting'])
            self.assertEqual(set_calls[0][1], 2)  # erase-all param

    def test_set_hidiscovery_off(self):
        """SET hm2HiDiscOper=2 (disable) when status='off'."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {
                OID_hm2HiDiscOper: 2,
                OID_hm2HiDiscMode: 2,
                OID_hm2HiDiscBlinking: 2,
                OID_hm2HiDiscProtocol: 6,
                OID_hm2HiDiscRelay: 1,
            }
        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.set_hidiscovery('off')
            self.assertFalse(result['enabled'])
            # Should have SET operation=disable(2)
            self.assertEqual(len(set_calls), 1)
            self.assertIn(OID_hm2HiDiscOper, set_calls[0][0])
            self.assertEqual(set_calls[0][1], 2)

    def test_set_hidiscovery_on(self):
        """SET hm2HiDiscOper=1 + hm2HiDiscMode=1 when status='on'."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {
                OID_hm2HiDiscOper: 1,
                OID_hm2HiDiscMode: 1,
                OID_hm2HiDiscBlinking: 2,
                OID_hm2HiDiscProtocol: 6,
                OID_hm2HiDiscRelay: 1,
            }
        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.set_hidiscovery('on')
            self.assertTrue(result['enabled'])
            self.assertEqual(result['mode'], 'read-write')
            # Should have SET operation=enable(1) then mode=readWrite(1)
            self.assertEqual(len(set_calls), 2)

    def test_set_hidiscovery_ro(self):
        """SET hm2HiDiscOper=1 + hm2HiDiscMode=2 when status='ro'."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))
        async def mock_scalar(*oids):
            return {
                OID_hm2HiDiscOper: 1,
                OID_hm2HiDiscMode: 2,
                OID_hm2HiDiscBlinking: 2,
                OID_hm2HiDiscProtocol: 6,
                OID_hm2HiDiscRelay: 1,
            }
        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.set_hidiscovery('ro')
            self.assertTrue(result['enabled'])
            self.assertEqual(result['mode'], 'read-only')
            self.assertEqual(len(set_calls), 2)

    def test_set_hidiscovery_invalid(self):
        """Invalid status raises ValueError."""
        with self.assertRaises(ValueError):
            self.snmp.set_hidiscovery('banana')

    def test_set_mrp_create_enable(self):
        """Create new MRP domain via SNMP and enable as client."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))
        async def mock_walk_columns(oid_map, engine=None):
            return {}  # no existing domain
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2', '3': '1/3', '4': '1/4',
                    '5': '1/5', '6': '1/6'}

        # Mock _get_mrp_async for return value
        async def mock_mrp():
            return {'configured': True, 'mode': 'client'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_get_mrp_async', side_effect=mock_mrp):
            result = self.snmp.set_mrp(
                operation='enable', mode='client',
                port_primary='1/3', port_secondary='1/4',
                vlan=1, recovery_delay='200ms',
            )
            self.assertTrue(result['configured'])

            # Should: createAndWait, set role, set port1, set port2, set vlan,
            #         set recovery, activate
            oid_suffixes = [oid for oid, _ in set_calls]
            sfx = MRP_DEFAULT_DOMAIN_SUFFIX
            # First call: createAndWait(5)
            self.assertIn(OID_hm2MrpRowStatus + sfx, oid_suffixes[0])
            self.assertEqual(set_calls[0][1], 5)
            # Last call: active(1)
            self.assertIn(OID_hm2MrpRowStatus + sfx, oid_suffixes[-1])
            self.assertEqual(set_calls[-1][1], 1)

    def test_set_mrp_unsupported_recovery_delay(self):
        """Rejects 30ms/10ms recovery delay on devices that only support 200/500."""
        async def mock_walk_columns(oid_map, engine=None):
            sfx = MRP_DEFAULT_DOMAIN_SUFFIX.lstrip('.')
            return {sfx: {'row_status': 1, 'delay_supported': 2}}  # supported200500
        async def mock_ifmap(engine=None):
            return {'3': '1/3', '4': '1/4'}
        mock_interfaces = {'1/3': {'is_up': False}, '1/4': {'is_up': False}}

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, 'get_interfaces', return_value=mock_interfaces):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.set_mrp(
                    operation='enable', mode='client',
                    port_primary='1/3', port_secondary='1/4',
                    recovery_delay='30ms',
                )
            self.assertIn('not supported', str(ctx.exception))

    def test_delete_mrp(self):
        """Delete MRP domain: notInService(2) then destroy(6)."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))

        async def mock_mrp():
            return {'configured': False}
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_get_mrp_async', side_effect=mock_mrp):
            result = self.snmp.delete_mrp()
            self.assertFalse(result['configured'])
            # Should: notInService(2) then destroy(6)
            self.assertEqual(len(set_calls), 2)
            self.assertEqual(set_calls[0][1], 2)  # notInService
            self.assertEqual(set_calls[1][1], 6)  # destroy

    # ------------------------------------------------------------------
    # MRP sub-ring (SRM)
    # ------------------------------------------------------------------

    def test_get_mrp_sub_ring_empty(self):
        """No SRM instances configured."""
        async def mock_scalar(*oids):
            return {OID_hm2SrmGlobalAdminState: 2, OID_hm2SrmMaxInstances: 8}
        async def mock_walk_columns(oid_map, engine=None):
            return {}

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.get_mrp_sub_ring()

        self.assertFalse(result['enabled'])
        self.assertEqual(result['max_instances'], 8)
        self.assertEqual(result['instances'], [])

    def test_get_mrp_sub_ring_one_instance(self):
        """One SRM instance configured and active."""
        async def mock_scalar(*oids):
            return {OID_hm2SrmGlobalAdminState: 1, OID_hm2SrmMaxInstances: 8}
        async def mock_ifmap(engine=None):
            return {'3': '1/3', '4': '1/4'}
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {
                    'admin_state': 1,  # manager
                    'oper_state': 1,   # manager
                    'vlan': 200,
                    'domain_id': b'\xff' * 16,
                    'partner_mac': b'\x00\x80\x63\xa1\xb2\xc3',
                    'protocol': 'mrp',
                    'name': 'sub1',
                    'port_ifindex': '3',
                    'port_oper': 3,    # forwarding
                    'ring_oper': 3,    # closed
                    'redundancy_oper': 1,  # True
                    'config_oper': 1,  # no error
                    'row_status': 1,   # active
                },
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_mrp_sub_ring()

        self.assertTrue(result['enabled'])
        self.assertEqual(len(result['instances']), 1)
        inst = result['instances'][0]
        self.assertEqual(inst['ring_id'], 1)
        self.assertEqual(inst['mode'], 'manager')
        self.assertEqual(inst['vlan'], 200)
        self.assertEqual(inst['port'], '1/3')
        self.assertEqual(inst['port_state'], 'forwarding')
        self.assertEqual(inst['ring_state'], 'closed')
        self.assertTrue(inst['redundancy'])
        self.assertEqual(inst['name'], 'sub1')

    def test_set_mrp_sub_ring_global_enable(self):
        """Global SRM enable only."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))
        async def mock_scalar(*oids):
            return {OID_hm2SrmGlobalAdminState: 1, OID_hm2SrmMaxInstances: 8}
        async def mock_walk_columns(oid_map, engine=None):
            return {}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.set_mrp_sub_ring(enabled=True)

        self.assertEqual(set_calls[0][1], 1)  # enable
        self.assertTrue(result['enabled'])

    def test_set_mrp_sub_ring_create_instance(self):
        """Create SRM instance: auto-enable, createAndWait, notInService, SET, active."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))
        async def mock_walk_columns(oid_map, engine=None):
            return {}  # no existing instance
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2', '3': '1/3', '4': '1/4'}
        async def mock_srm():
            return {'enabled': True, 'max_instances': 8, 'instances': []}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_get_mrp_sub_ring_async', side_effect=mock_srm):
            result = self.snmp.set_mrp_sub_ring(
                ring_id=1, mode='manager', port='1/3', vlan=200)

        oids = [oid for oid, _ in set_calls]
        # First: auto-enable global SRM (value=1)
        self.assertEqual(set_calls[0][1], 1)
        # Second: createAndWait(5)
        self.assertIn(OID_hm2SrmRowStatus, oids[1])
        self.assertEqual(set_calls[1][1], 5)
        # Third: notInService(2)
        self.assertEqual(set_calls[2][1], 2)
        # Last: activate(1)
        self.assertIn(OID_hm2SrmRowStatus, oids[-1])
        self.assertEqual(set_calls[-1][1], 1)

    def test_set_mrp_sub_ring_unknown_port(self):
        """Unknown port raises ValueError."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))
        async def mock_walk_columns(oid_map, engine=None):
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.set_mrp_sub_ring(ring_id=1, port='9/9')
            self.assertIn("Unknown port", str(ctx.exception))

    def test_delete_mrp_sub_ring(self):
        """Delete SRM instance: notInService(2) then destroy(6)."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))
        async def mock_srm():
            return {'enabled': True, 'max_instances': 8, 'instances': []}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_get_mrp_sub_ring_async', side_effect=mock_srm):
            result = self.snmp.delete_mrp_sub_ring(ring_id=1)

        self.assertEqual(len(set_calls), 2)
        self.assertEqual(set_calls[0][1], 2)  # notInService
        self.assertEqual(set_calls[1][1], 6)  # destroy

    # ------------------------------------------------------------------
    # get_profiles
    # ------------------------------------------------------------------

    def test_get_profiles_nvm(self):
        """Walk profile table, filter by NVM, format timestamps and firmware."""
        async def mock_walk_columns(oid_map, engine=None):
            return {
                # NVM profile 1 (active)
                '1.1': {
                    'storage': 1,  # nvm
                    'index': 1,
                    'name': 'config',
                    'datetime': 1739451916,  # 2025-02-13 13:25:16 UTC
                    'active': 1,
                    'enc_active': 2,   # false
                    'enc_verified': 2,
                    'sw_major': 9,
                    'sw_minor': 4,
                    'sw_bugfix': 4,
                    'fingerprint': '9244C58FEA7549A1E2C80DB7608B8D75CF068A66',
                    'fp_verified': 1,
                },
                # NVM profile 2 (inactive)
                '1.2': {
                    'storage': 1,  # nvm
                    'index': 2,
                    'name': 'backup',
                    'datetime': 1739000000,
                    'active': 2,   # inactive
                    'enc_active': 2,
                    'enc_verified': 2,
                    'sw_major': 9,
                    'sw_minor': 4,
                    'sw_bugfix': 2,
                    'fingerprint': 'ABCDEF1234567890ABCDEF1234567890ABCDEF12',
                    'fp_verified': 2,  # not verified
                },
                # ENVM profile 1 (should be filtered out)
                '2.1': {
                    'storage': 2,  # envm
                    'index': 1,
                    'name': 'external',
                    'datetime': 1739000000,
                    'active': 2,
                    'enc_active': 2,
                    'enc_verified': 2,
                    'sw_major': 9,
                    'sw_minor': 4,
                    'sw_bugfix': 2,
                    'fingerprint': '0000000000000000000000000000000000000000',
                    'fp_verified': 2,
                },
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            profiles = self.snmp.get_profiles('nvm')

        self.assertEqual(len(profiles), 2)

        # Profile 1 — active
        p1 = profiles[0]
        self.assertEqual(p1['index'], 1)
        self.assertEqual(p1['name'], 'config')
        self.assertTrue(p1['active'])
        self.assertIn('2025-02-13', p1['datetime'])
        self.assertEqual(p1['firmware'], '09.4.04')
        self.assertEqual(p1['fingerprint'], '9244C58FEA7549A1E2C80DB7608B8D75CF068A66')
        self.assertTrue(p1['fingerprint_verified'])
        self.assertFalse(p1['encrypted'])
        self.assertFalse(p1['encryption_verified'])

        # Profile 2 — inactive
        p2 = profiles[1]
        self.assertEqual(p2['index'], 2)
        self.assertEqual(p2['name'], 'backup')
        self.assertFalse(p2['active'])
        self.assertFalse(p2['fingerprint_verified'])

    def test_get_profiles_envm(self):
        """get_profiles('envm') filters by storage type 2."""
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1.1': {'storage': 1, 'index': 1, 'name': 'nvm-config',
                         'datetime': 0, 'active': 1, 'enc_active': 2,
                         'enc_verified': 2, 'sw_major': 9, 'sw_minor': 4,
                         'sw_bugfix': 4, 'fingerprint': '', 'fp_verified': 2},
                '2.1': {'storage': 2, 'index': 1, 'name': 'sd-card',
                         'datetime': 0, 'active': 2, 'enc_active': 2,
                         'enc_verified': 2, 'sw_major': 9, 'sw_minor': 4,
                         'sw_bugfix': 2, 'fingerprint': '', 'fp_verified': 2},
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            profiles = self.snmp.get_profiles('envm')

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]['name'], 'sd-card')

    def test_get_profiles_invalid_storage(self):
        with self.assertRaises(ValueError):
            self.snmp.get_profiles('usb')

    # ------------------------------------------------------------------
    # get_config_fingerprint
    # ------------------------------------------------------------------

    def test_get_config_fingerprint(self):
        """Returns fingerprint of the active NVM profile."""
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1.1': {
                    'storage': 1, 'index': 1, 'name': 'config',
                    'datetime': 1739451916, 'active': 1,
                    'enc_active': 2, 'enc_verified': 2,
                    'sw_major': 9, 'sw_minor': 4, 'sw_bugfix': 4,
                    'fingerprint': '9244C58FEA7549A1E2C80DB7608B8D75CF068A66',
                    'fp_verified': 1,
                },
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            fp = self.snmp.get_config_fingerprint()

        self.assertEqual(fp['fingerprint'], '9244C58FEA7549A1E2C80DB7608B8D75CF068A66')
        self.assertTrue(fp['verified'])

    def test_get_config_fingerprint_no_active(self):
        """No active profile → empty fingerprint."""
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1.1': {
                    'storage': 1, 'index': 1, 'name': 'config',
                    'datetime': 0, 'active': 2,  # inactive
                    'enc_active': 2, 'enc_verified': 2,
                    'sw_major': 0, 'sw_minor': 0, 'sw_bugfix': 0,
                    'fingerprint': '', 'fp_verified': 2,
                },
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            fp = self.snmp.get_config_fingerprint()

        self.assertEqual(fp['fingerprint'], '')
        self.assertFalse(fp['verified'])

    # ------------------------------------------------------------------
    # activate_profile
    # ------------------------------------------------------------------

    def test_activate_profile(self):
        """SET hm2FMProfileActive.1.2 = 1 to activate profile 2."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1.2': {
                    'storage': 1, 'index': 2, 'name': 'backup',
                    'datetime': 0, 'active': 1,  # now active after SET
                    'enc_active': 2, 'enc_verified': 2,
                    'sw_major': 9, 'sw_minor': 4, 'sw_bugfix': 2,
                    'fingerprint': 'AABB', 'fp_verified': 1,
                },
            }

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.activate_profile('nvm', 2)

        self.assertEqual(len(set_calls), 1)
        self.assertIn(f'{OID_hm2FMProfileActive}.1.2', set_calls[0][0])
        self.assertEqual(set_calls[0][1], 1)
        self.assertEqual(len(result), 1)

    # ------------------------------------------------------------------
    # delete_profile
    # ------------------------------------------------------------------

    def test_delete_profile(self):
        """SET hm2FMProfileAction.1.2 = 2 (delete) for inactive profile."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, int(val)))

        walk_call_count = [0]
        async def mock_walk_columns(oid_map, engine=None):
            walk_call_count[0] += 1
            if walk_call_count[0] == 1:
                # First call: check if active (from get_profiles in delete_profile)
                return {
                    '1.1': {
                        'storage': 1, 'index': 1, 'name': 'config',
                        'datetime': 0, 'active': 1,
                        'enc_active': 2, 'enc_verified': 2,
                        'sw_major': 9, 'sw_minor': 4, 'sw_bugfix': 4,
                        'fingerprint': '', 'fp_verified': 2,
                    },
                    '1.2': {
                        'storage': 1, 'index': 2, 'name': 'backup',
                        'datetime': 0, 'active': 2,  # inactive — can delete
                        'enc_active': 2, 'enc_verified': 2,
                        'sw_major': 9, 'sw_minor': 4, 'sw_bugfix': 2,
                        'fingerprint': '', 'fp_verified': 2,
                    },
                }
            # Second call: after delete, return updated list
            return {
                '1.1': {
                    'storage': 1, 'index': 1, 'name': 'config',
                    'datetime': 0, 'active': 1,
                    'enc_active': 2, 'enc_verified': 2,
                    'sw_major': 9, 'sw_minor': 4, 'sw_bugfix': 4,
                    'fingerprint': '', 'fp_verified': 2,
                },
            }

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.delete_profile('nvm', 2)

        self.assertEqual(len(set_calls), 1)
        self.assertIn(f'{OID_hm2FMProfileAction}.1.2', set_calls[0][0])
        self.assertEqual(set_calls[0][1], 2)  # delete action
        self.assertEqual(len(result), 1)  # only profile 1 remains

    def test_delete_active_profile_raises(self):
        """Cannot delete the active profile."""
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1.1': {
                    'storage': 1, 'index': 1, 'name': 'config',
                    'datetime': 0, 'active': 1,  # active — cannot delete
                    'enc_active': 2, 'enc_verified': 2,
                    'sw_major': 9, 'sw_minor': 4, 'sw_bugfix': 4,
                    'fingerprint': '', 'fp_verified': 2,
                },
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.delete_profile('nvm', 1)
            self.assertIn('active', str(ctx.exception))

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    def test_start_watchdog(self):
        """SET interval then enable."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))

        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
            self.snmp.start_watchdog(60)

        self.assertEqual(len(set_calls), 2)
        # First: set interval
        self.assertIn(OID_hm2ConfigWatchdogTimeInterval, set_calls[0][0])
        self.assertEqual(set_calls[0][1], 60)
        # Second: enable
        self.assertIn(OID_hm2ConfigWatchdogAdminStatus, set_calls[1][0])
        self.assertEqual(set_calls[1][1], 1)

    def test_start_watchdog_invalid_interval(self):
        with self.assertRaises(ValueError):
            self.snmp.start_watchdog(10)  # < 30
        with self.assertRaises(ValueError):
            self.snmp.start_watchdog(700)  # > 600

    def test_stop_watchdog(self):
        """SET disable."""
        set_calls = []
        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))

        with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
            self.snmp.stop_watchdog()

        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2ConfigWatchdogAdminStatus, set_calls[0][0])
        self.assertEqual(set_calls[0][1], 2)

    def test_get_watchdog_status(self):
        """GET all 4 watchdog scalars."""
        async def mock_scalar(*oids):
            return {
                OID_hm2ConfigWatchdogAdminStatus: 1,   # enabled
                OID_hm2ConfigWatchdogOperStatus: 1,
                OID_hm2ConfigWatchdogTimeInterval: 60,
                OID_hm2ConfigWatchdogTimerValue: 45,
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            status = self.snmp.get_watchdog_status()

        self.assertTrue(status['enabled'])
        self.assertEqual(status['oper_status'], 1)
        self.assertEqual(status['interval'], 60)
        self.assertEqual(status['remaining'], 45)

    def test_get_watchdog_status_disabled(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2ConfigWatchdogAdminStatus: 2,   # disabled
                OID_hm2ConfigWatchdogOperStatus: 2,
                OID_hm2ConfigWatchdogTimeInterval: 0,
                OID_hm2ConfigWatchdogTimerValue: 0,
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            status = self.snmp.get_watchdog_status()

        self.assertFalse(status['enabled'])
        self.assertEqual(status['remaining'], 0)


    # ------------------------------------------------------------------
    # VLAN ingress/egress getters
    # ------------------------------------------------------------------

    def test_get_vlan_ingress(self):
        """get_vlan_ingress returns PVID, frame_types, ingress_filtering per port."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2', '5': '1/5'}
            return self.snmp._ifindex_map

        async def mock_walk(oid, engine=None):
            if oid == OID_dot1dBasePortIfIndex:
                return {'1': '1', '2': '2', '5': '5'}
            return {}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {'pvid': 1, 'frame_types': 1, 'ingress_filtering': 2},
                '2': {'pvid': 5, 'frame_types': 2, 'ingress_filtering': 1},
                '5': {'pvid': 3, 'frame_types': 1, 'ingress_filtering': 2},
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.get_vlan_ingress()

        self.assertEqual(result['1/1']['pvid'], 1)
        self.assertEqual(result['1/1']['frame_types'], 'admit_all')
        self.assertFalse(result['1/1']['ingress_filtering'])
        self.assertEqual(result['1/2']['pvid'], 5)
        self.assertEqual(result['1/2']['frame_types'], 'admit_only_tagged')
        self.assertTrue(result['1/2']['ingress_filtering'])
        self.assertEqual(result['1/5']['pvid'], 3)

    def test_get_vlan_ingress_port_filter(self):
        """get_vlan_ingress with port args filters to those ports only."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk(oid, engine=None):
            return {'1': '1', '2': '2'}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {'pvid': 1, 'frame_types': 1, 'ingress_filtering': 2},
                '2': {'pvid': 5, 'frame_types': 2, 'ingress_filtering': 1},
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.get_vlan_ingress('1/2')

        self.assertEqual(len(result), 1)
        self.assertIn('1/2', result)

    def test_get_vlan_egress(self):
        """get_vlan_egress classifies T/U/F correctly."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2', '3': '1/3'}
            return self.snmp._ifindex_map

        async def mock_walk(oid, engine=None):
            return {'1': '1', '2': '2', '3': '3'}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '1': {
                    'name': 'default',
                    'egress': b'\xe0',     # 1/1, 1/2, 1/3
                    'untagged': b'\x60',   # 1/2, 1/3
                    'forbidden': b'\x00',
                },
                '100': {
                    'name': 'MRP',
                    'egress': b'\xc0',     # 1/1, 1/2
                    'untagged': b'\x00',
                    'forbidden': b'\x00',
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.get_vlan_egress()

        self.assertEqual(result[1]['ports']['1/1'], 'tagged')
        self.assertEqual(result[1]['ports']['1/2'], 'untagged')
        self.assertEqual(result[1]['ports']['1/3'], 'untagged')
        self.assertEqual(result[100]['ports']['1/1'], 'tagged')
        self.assertEqual(result[100]['ports']['1/2'], 'tagged')

    def test_get_vlan_egress_forbidden(self):
        """Ports in forbidden bitmap show as 'forbidden'."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk(oid, engine=None):
            return {'1': '1', '2': '2'}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '10': {
                    'name': 'TEST',
                    'egress': b'\x80',     # 1/1 only
                    'untagged': b'\x80',
                    'forbidden': b'\x40',  # 1/2 forbidden
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.get_vlan_egress()

        self.assertEqual(result[10]['ports']['1/1'], 'untagged')
        self.assertEqual(result[10]['ports']['1/2'], 'forbidden')

    def test_get_vlan_egress_empty_vlan_included(self):
        """VLANs with zero port membership are included when unfiltered."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        async def mock_walk(oid, engine=None):
            return {'1': '1'}

        async def mock_walk_columns(oid_map, engine=None):
            return {
                '999': {
                    'name': 'Empty',
                    'egress': b'\x00',
                    'untagged': b'\x00',
                    'forbidden': b'\x00',
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            result = self.snmp.get_vlan_egress()

        self.assertIn(999, result)
        self.assertEqual(result[999]['ports'], {})

    # ------------------------------------------------------------------
    # VLAN ingress/egress setters
    # ------------------------------------------------------------------

    def test_set_vlan_ingress_pvid(self):
        """SET dot1qPvid for a bridge port."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        async def mock_ifmap(engine=None):
            return {'3': '1/3'}
        async def mock_walk(oid, engine=None):
            return {'3': '3'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk):
            self.snmp.set_vlan_ingress('1/3', pvid=100)

        self.assertEqual(len(set_calls), 1)
        from napalm_hios.snmp_hios import OID_dot1qPvid
        self.assertIn(OID_dot1qPvid, set_calls[0][0])
        self.assertEqual(int(set_calls[0][1]), 100)

    def test_set_vlan_ingress_all_params(self):
        """SET PVID + frame_types + ingress_filtering."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        async def mock_ifmap(engine=None):
            return {'3': '1/3'}
        async def mock_walk(oid, engine=None):
            return {'3': '3'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk):
            self.snmp.set_vlan_ingress('1/3', pvid=5,
                                       frame_types='admit_only_tagged',
                                       ingress_filtering=True)

        self.assertEqual(len(set_calls), 3)
        from napalm_hios.snmp_hios import OID_dot1qPortAcceptableFrameTypes, OID_dot1qPortIngressFiltering
        oid_strs = [c[0] for c in set_calls]
        self.assertTrue(any(OID_dot1qPortAcceptableFrameTypes in o for o in oid_strs))
        self.assertTrue(any(OID_dot1qPortIngressFiltering in o for o in oid_strs))

    def test_set_vlan_ingress_unknown_port(self):
        async def mock_ifmap(engine=None):
            return {'3': '1/3'}
        async def mock_walk(oid, engine=None):
            return {'3': '3'}
        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk):
            with self.assertRaises(ValueError):
                self.snmp.set_vlan_ingress('99/99', pvid=1)

    def test_set_vlan_egress_tagged(self):
        """SET egress bitmap with port added as tagged."""
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '3': '1/3'}
        async def mock_walk(oid, engine=None):
            return {'1': '1', '3': '3'}
        async def mock_walk_columns(oid_map, engine=None):
            return {
                '10': {
                    'egress': b'\x00\x00',
                    'untagged': b'\xff\xff',
                    'forbidden': b'\x00\x00',
                },
            }

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            self.snmp.set_vlan_egress(10, '1/3', 'tagged')

        # Should have set egress, untagged, forbidden
        self.assertEqual(len(set_calls), 3)
        from napalm_hios.snmp_hios import OID_dot1qVlanStaticEgressPorts
        egress_oid = [c for c in set_calls if OID_dot1qVlanStaticEgressPorts in c[0]]
        self.assertEqual(len(egress_oid), 1)
        # Port 3 bit should be set in egress (0x20 at byte 0)
        egress_bytes = bytes(egress_oid[0][1])
        self.assertTrue(egress_bytes[0] & 0x20)

    def test_set_vlan_egress_nonexistent_vlan(self):
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_walk(oid, engine=None):
            return {'1': '1'}
        async def mock_walk_columns(oid_map, engine=None):
            return {'1': {'egress': b'\xff', 'untagged': b'\xff', 'forbidden': b'\x00'}}

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.set_vlan_egress(999, '1/1', 'tagged')
            self.assertIn('does not exist', str(ctx.exception))

    def test_set_vlan_egress_invalid_mode(self):
        with self.assertRaises(ValueError):
            self.snmp.set_vlan_egress(10, '1/1', 'invalid')

    # ------------------------------------------------------------------
    # VLAN CRUD
    # ------------------------------------------------------------------

    def test_create_vlan(self):
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids):
            self.snmp.create_vlan(100, 'MGMT')
        self.assertEqual(len(set_calls), 2)
        from napalm_hios.snmp_hios import OID_dot1qVlanStaticRowStatus, OID_dot1qVlanStaticName
        # RowStatus=4 (createAndGo)
        row_status = [c for c in set_calls if OID_dot1qVlanStaticRowStatus in c[0]]
        self.assertEqual(int(row_status[0][1]), 4)
        # Name
        name_set = [c for c in set_calls if OID_dot1qVlanStaticName in c[0]]
        self.assertEqual(str(name_set[0][1]), 'MGMT')

    def test_create_vlan_no_name(self):
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids):
            self.snmp.create_vlan(200)
        self.assertEqual(len(set_calls), 1)

    def test_update_vlan(self):
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids):
            self.snmp.update_vlan(100, 'NEW-NAME')
        from napalm_hios.snmp_hios import OID_dot1qVlanStaticName
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_dot1qVlanStaticName, set_calls[0][0])

    def test_delete_vlan(self):
        set_calls = []
        async def mock_set_oids(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids):
            self.snmp.delete_vlan(100)
        from napalm_hios.snmp_hios import OID_dot1qVlanStaticRowStatus
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_dot1qVlanStaticRowStatus, set_calls[0][0])
        self.assertEqual(int(set_calls[0][1]), 6)  # destroy


    # ------------------------------------------------------------------
    # Storm Control
    # ------------------------------------------------------------------

    def test_get_storm_control_default(self):
        """All ports disabled, percent unit, multi-bucket."""
        async def mock_scalar(*oids):
            return {OID_hm2StormBucketType: 2}

        async def mock_walk(oid_map, engine=None):
            return {
                '1': {'unit': 1, 'bcast_mode': 2, 'bcast_threshold': 0,
                      'mcast_mode': 2, 'mcast_threshold': 0,
                      'ucast_mode': 2, 'ucast_threshold': 0},
                '2': {'unit': 1, 'bcast_mode': 2, 'bcast_threshold': 0,
                      'mcast_mode': 2, 'mcast_threshold': 0,
                      'ucast_mode': 2, 'ucast_threshold': 0},
            }

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_storm_control()

        self.assertEqual(result['bucket_type'], 'multi-bucket')
        self.assertEqual(sorted(result['interfaces'].keys()), ['1/1', '1/2'])
        p = result['interfaces']['1/1']
        self.assertEqual(p['unit'], 'percent')
        self.assertFalse(p['broadcast']['enabled'])
        self.assertEqual(p['broadcast']['threshold'], 0)

    def test_get_storm_control_active_port(self):
        """Port with broadcast enabled at 100 pps."""
        async def mock_scalar(*oids):
            return {OID_hm2StormBucketType: 2}

        async def mock_walk(oid_map, engine=None):
            return {
                '11': {'unit': 2, 'bcast_mode': 1, 'bcast_threshold': 100,
                       'mcast_mode': 2, 'mcast_threshold': 0,
                       'ucast_mode': 2, 'ucast_threshold': 0},
            }

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'11': '1/11'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_storm_control()

        p = result['interfaces']['1/11']
        self.assertEqual(p['unit'], 'pps')
        self.assertTrue(p['broadcast']['enabled'])
        self.assertEqual(p['broadcast']['threshold'], 100)

    def test_get_storm_control_single_bucket(self):
        async def mock_scalar(*oids):
            return {OID_hm2StormBucketType: 1}

        async def mock_walk(oid_map, engine=None):
            return {'1': {'unit': 1, 'bcast_mode': 2, 'bcast_threshold': 0,
                          'mcast_mode': 2, 'mcast_threshold': 0,
                          'ucast_mode': 2, 'ucast_threshold': 0}}

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_storm_control()

        self.assertEqual(result['bucket_type'], 'single-bucket')

    def test_get_storm_control_skips_cpu(self):
        async def mock_scalar(*oids):
            return {OID_hm2StormBucketType: 2}

        async def mock_walk(oid_map, engine=None):
            return {
                '1': {'unit': 1, 'bcast_mode': 2, 'bcast_threshold': 0,
                      'mcast_mode': 2, 'mcast_threshold': 0,
                      'ucast_mode': 2, 'ucast_threshold': 0},
                '25': {'unit': 1, 'bcast_mode': 2, 'bcast_threshold': 0,
                       'mcast_mode': 2, 'mcast_threshold': 0,
                       'ucast_mode': 2, 'ucast_threshold': 0},
            }

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '25': 'cpu/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_storm_control()

        self.assertEqual(list(result['interfaces'].keys()), ['1/1'])

    def test_set_storm_control_bad_unit(self):
        with self.assertRaises(ValueError):
            self.snmp.set_storm_control('1/1', unit='bps')

    def test_set_storm_control_bad_port(self):
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_storm_control('9/9', broadcast_enabled=True)

    # ── sFlow ────────────────────────────────────────────────────

    def test_get_sflow_default(self):
        """All receivers unconfigured, agent info parsed."""
        async def mock_scalar(*oids):
            return {
                OID_sFlowVersion: '1.3;Hirschmann;10.3.04',
                OID_sFlowAgentAddress: '192.168.1.4',
            }

        async def mock_walk(oid_map, engine=None):
            rows = {}
            for i in range(1, 9):
                rows[str(i)] = {
                    'owner': '', 'timeout': 0,
                    'max_datagram_size': 1400,
                    'address_type': 1,
                    'address': '0.0.0.0',
                    'port': 6343, 'datagram_version': 5,
                }
            return rows

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_sflow()

        self.assertEqual(result['agent_version'], '1.3;Hirschmann;10.3.04')
        self.assertEqual(result['agent_address'], '192.168.1.4')
        self.assertEqual(len(result['receivers']), 8)
        r1 = result['receivers'][1]
        self.assertEqual(r1['owner'], '')
        self.assertEqual(r1['timeout'], 0)
        self.assertEqual(r1['address'], '0.0.0.0')
        self.assertEqual(r1['port'], 6343)

    def test_get_sflow_configured_receiver(self):
        """Receiver with owner and address parsed correctly."""
        async def mock_scalar(*oids):
            return {
                OID_sFlowVersion: '1.3;Hirschmann;10.3.04',
                OID_sFlowAgentAddress: '192.168.1.4',
            }

        async def mock_walk(oid_map, engine=None):
            return {
                '1': {
                    'owner': 'snoop', 'timeout': -1,
                    'max_datagram_size': 1400,
                    'address_type': 1,
                    'address': '192.168.1.100',
                    'port': 6343, 'datagram_version': 5,
                },
                '2': {
                    'owner': '', 'timeout': 0,
                    'max_datagram_size': 1400,
                    'address_type': 1,
                    'address': '0.0.0.0',
                    'port': 6343, 'datagram_version': 5,
                },
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_sflow()

        r1 = result['receivers'][1]
        self.assertEqual(r1['owner'], 'snoop')
        self.assertEqual(r1['timeout'], -1)
        self.assertEqual(r1['address'], '192.168.1.100')
        r2 = result['receivers'][2]
        self.assertEqual(r2['owner'], '')

    def test_get_sflow_port_default(self):
        """All ports unconfigured."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk(oid_map, engine=None):
            # Compound suffix: 11.1.3.6.1.2.1.2.2.1.1.{ifIndex}.1
            return {
                '11.1.3.6.1.2.1.2.2.1.1.1.1': {
                    'receiver': 0, 'sample_rate': 0,
                    'max_header_size': 128,
                },
                '11.1.3.6.1.2.1.2.2.1.1.2.1': {
                    'receiver': 0, 'sample_rate': 0,
                    'max_header_size': 128,
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_sflow_port()

        self.assertEqual(len(result), 2)
        self.assertEqual(result['1/1']['sampler']['receiver'], 0)
        self.assertEqual(result['1/1']['sampler']['sample_rate'], 0)

    def test_get_sflow_port_configured(self):
        """Port with sampler and poller active."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '11': '1/11'}
            return self.snmp._ifindex_map

        call_count = [0]

        async def mock_walk(oid_map, engine=None):
            call_count[0] += 1
            if call_count[0] == 1:  # sampler
                return {
                    '11.1.3.6.1.2.1.2.2.1.1.1.1': {
                        'receiver': 0, 'sample_rate': 0,
                        'max_header_size': 128,
                    },
                    '11.1.3.6.1.2.1.2.2.1.1.11.1': {
                        'receiver': 1, 'sample_rate': 256,
                        'max_header_size': 128,
                    },
                }
            else:  # poller
                return {
                    '11.1.3.6.1.2.1.2.2.1.1.1.1': {
                        'receiver': 0, 'interval': 0,
                    },
                    '11.1.3.6.1.2.1.2.2.1.1.11.1': {
                        'receiver': 1, 'interval': 20,
                    },
                }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_sflow_port()

        p11 = result['1/11']
        self.assertEqual(p11['sampler']['receiver'], 1)
        self.assertEqual(p11['sampler']['sample_rate'], 256)
        self.assertEqual(p11['poller']['receiver'], 1)
        self.assertEqual(p11['poller']['interval'], 20)

    def test_get_sflow_port_filter(self):
        """Interface filter returns only requested ports."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        async def mock_walk(oid_map, engine=None):
            return {
                '11.1.3.6.1.2.1.2.2.1.1.1.1': {
                    'receiver': 0, 'sample_rate': 0,
                    'max_header_size': 128,
                },
                '11.1.3.6.1.2.1.2.2.1.1.2.1': {
                    'receiver': 0, 'sample_rate': 0,
                    'max_header_size': 128,
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_sflow_port(interfaces=['1/1'])

        self.assertEqual(list(result.keys()), ['1/1'])

    def test_get_sflow_port_skips_cpu(self):
        """CPU interfaces filtered out."""
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '100': 'cpu/1'}
            return self.snmp._ifindex_map

        async def mock_walk(oid_map, engine=None):
            return {
                '11.1.3.6.1.2.1.2.2.1.1.1.1': {
                    'receiver': 0, 'sample_rate': 0,
                    'max_header_size': 128,
                },
                '11.1.3.6.1.2.1.2.2.1.1.100.1': {
                    'receiver': 0, 'sample_rate': 0,
                    'max_header_size': 128,
                },
            }

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_sflow_port()

        self.assertIn('1/1', result)
        self.assertNotIn('cpu/1', result)

    def test_set_sflow_bad_receiver(self):
        with self.assertRaises(ValueError):
            self.snmp.set_sflow(0, owner='test')
        with self.assertRaises(ValueError):
            self.snmp.set_sflow(9, owner='test')

    def test_set_sflow_port_bad_port(self):
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_sflow_port('9/9', receiver=1, sample_rate=256)

    def test_set_sflow_port_no_rate_or_interval(self):
        with self.assertRaises(ValueError):
            self.snmp.set_sflow_port('1/1', receiver=1)


    # ── QoS ──────────────────────────────────────────────────────

    def test_get_qos_default(self):
        """All ports dot1p trust, strict scheduling, no shaping."""
        async def mock_scalar(*oids):
            return {OID_hm2CosQueueNumQueuesPerPort: 8}

        walk_call_count = [0]
        async def mock_walk_columns(oid_map, engine=None):
            walk_call_count[0] += 1
            if walk_call_count[0] == 1:  # trust
                return {'1': {'trust': 2}, '2': {'trust': 2}}
            elif walk_call_count[0] == 2:  # shaping
                return {'1': {'shaping': 0}, '2': {'shaping': 0}}
            else:  # queues
                return {
                    '1.0': {'scheduler': 1, 'min_bw': 0, 'max_bw': 0},
                    '1.1': {'scheduler': 1, 'min_bw': 0, 'max_bw': 0},
                    '2.0': {'scheduler': 1, 'min_bw': 0, 'max_bw': 0},
                    '2.1': {'scheduler': 1, 'min_bw': 0, 'max_bw': 0},
                }

        walk_raw_count = [0]
        async def mock_walk(oid, engine=None):
            walk_raw_count[0] += 1
            if walk_raw_count[0] == 1:  # bridge port → ifIndex
                return {'1': 1, '2': 2}
            else:  # default priority
                return {'1': 0, '2': 0}

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '2': '1/2'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_qos()

        self.assertEqual(result['num_queues'], 8)
        self.assertEqual(sorted(result['interfaces'].keys()), ['1/1', '1/2'])
        p = result['interfaces']['1/1']
        self.assertEqual(p['trust_mode'], 'dot1p')
        self.assertEqual(p['default_priority'], 0)
        self.assertEqual(p['shaping_rate'], 0)
        self.assertEqual(p['queues'][0]['scheduler'], 'strict')

    def test_get_qos_configured(self):
        """Port with ip-dscp trust, weighted queue, shaping, PCP 5."""
        async def mock_scalar(*oids):
            return {OID_hm2CosQueueNumQueuesPerPort: 8}

        walk_call_count = [0]
        async def mock_walk_columns(oid_map, engine=None):
            walk_call_count[0] += 1
            if walk_call_count[0] == 1:
                return {'5': {'trust': 4}}  # ip-dscp
            elif walk_call_count[0] == 2:
                return {'5': {'shaping': 50}}
            else:
                return {
                    '5.0': {'scheduler': 2, 'min_bw': 10, 'max_bw': 80},
                    '5.7': {'scheduler': 1, 'min_bw': 0, 'max_bw': 0},
                }

        walk_raw_count = [0]
        async def mock_walk(oid, engine=None):
            walk_raw_count[0] += 1
            if walk_raw_count[0] == 1:  # bridge port → ifIndex
                return {'5': 5}
            else:  # default priority
                return {'5': 5}

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'5': '1/5'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_qos()

        p = result['interfaces']['1/5']
        self.assertEqual(p['trust_mode'], 'ip-dscp')
        self.assertEqual(p['default_priority'], 5)
        self.assertEqual(p['shaping_rate'], 50)
        self.assertEqual(p['queues'][0]['scheduler'], 'weighted')
        self.assertEqual(p['queues'][0]['min_bw'], 10)
        self.assertEqual(p['queues'][0]['max_bw'], 80)
        self.assertEqual(p['queues'][7]['scheduler'], 'strict')

    def test_get_qos_skips_cpu(self):
        """CPU interfaces are excluded."""
        async def mock_scalar(*oids):
            return {OID_hm2CosQueueNumQueuesPerPort: 8}

        walk_call_count = [0]
        async def mock_walk_columns(oid_map, engine=None):
            walk_call_count[0] += 1
            if walk_call_count[0] == 1:
                return {'1': {'trust': 2}, '100': {'trust': 2}}
            elif walk_call_count[0] == 2:
                return {'1': {'shaping': 0}, '100': {'shaping': 0}}
            else:
                return {}

        async def mock_walk(oid, engine=None):
            return {'1': 1}  # only physical port

        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1', '100': 'cpu0'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_qos()

        self.assertIn('1/1', result['interfaces'])
        self.assertNotIn('cpu0', result['interfaces'])

    def test_set_qos_bad_trust_mode(self):
        with self.assertRaises(ValueError):
            self.snmp.set_qos('1/1', trust_mode='badval')

    def test_set_qos_bad_scheduler(self):
        with self.assertRaises(ValueError):
            self.snmp.set_qos('1/1', scheduler='round-robin')

    def test_set_qos_queue_needed_no_index(self):
        with self.assertRaises(ValueError):
            self.snmp.set_qos('1/1', min_bw=50)

    def test_set_qos_bad_port(self):
        async def mock_ifmap(engine=None):
            self.snmp._ifindex_map = {'1': '1/1'}
            return self.snmp._ifindex_map

        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_qos('9/9', trust_mode='dot1p')

    def test_get_qos_mapping(self):
        """dot1p and DSCP mapping tables."""
        walk_call_count = [0]
        async def mock_walk(oid_map, engine=None):
            walk_call_count[0] += 1
            if walk_call_count[0] == 1:  # dot1p
                return {
                    '0': {'tc': 2}, '1': {'tc': 0}, '2': {'tc': 1},
                    '3': {'tc': 3}, '4': {'tc': 4}, '5': {'tc': 5},
                    '6': {'tc': 6}, '7': {'tc': 7},
                }
            else:  # dscp
                return {
                    '0': {'tc': 0}, '8': {'tc': 1}, '46': {'tc': 5},
                }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_qos_mapping()

        self.assertEqual(result['dot1p'][0], 2)
        self.assertEqual(result['dot1p'][7], 7)
        self.assertEqual(result['dscp'][0], 0)
        self.assertEqual(result['dscp'][46], 5)

    def test_get_management_priority(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2NetVlanPriority: 3,
                OID_hm2NetIpDscpPriority: 46,
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_management_priority()

        self.assertEqual(result['dot1p'], 3)
        self.assertEqual(result['ip_dscp'], 46)


    def test_get_management(self):
        def _mock_ip(ip_bytes):
            """Create a mock that behaves like pysnmp InetAddress."""
            m = MagicMock()
            m.prettyPrint.return_value = '0x' + ip_bytes.hex()
            return m

        async def mock_scalar(*oids):
            return {
                OID_hm2NetConfigProtocol: 1,  # local
                OID_hm2NetLocalIPAddr: _mock_ip(b'\xc0\xa8\x01\x04'),
                OID_hm2NetPrefixLength: 24,
                OID_hm2NetGatewayIPAddr: _mock_ip(b'\xc0\xa8\x01\xfe'),
                OID_hm2NetVlanID: 1,
                OID_hm2NetMgmtPort: 0,
                OID_hm2NetDHCPClientId: '',
                OID_hm2NetDHCPClientLeaseTime: 0,
                OID_hm2NetDHCPClientConfigLoad: 1,  # enabled
                OID_hm2NetVlanPriority: 0,
                OID_hm2NetIpDscpPriority: 0,
                OID_hm2NetIPv6AdminStatus: 1,  # enabled
                OID_hm2NetIPv6ConfigProtocol: 2,  # auto
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_management()

        self.assertEqual(result['protocol'], 'local')
        self.assertEqual(result['vlan_id'], 1)
        self.assertEqual(result['ip_address'], '192.168.1.4')
        self.assertEqual(result['netmask'], '255.255.255.0')
        self.assertEqual(result['mgmt_port'], 0)
        self.assertTrue(result['dhcp_option_66_67'])
        self.assertTrue(result['ipv6_enabled'])
        self.assertEqual(result['ipv6_protocol'], 'auto')

    def test_set_management_vlan_validation(self):
        """Rejects VLAN that doesn't exist."""
        self.snmp.get_vlans = lambda: {
            1: {'name': 'default', 'interfaces': []}}
        with self.assertRaises(ValueError):
            self.snmp.set_management(vlan_id=999)

    def test_set_management_bad_vlan_range(self):
        """Rejects out-of-range VLAN."""
        with self.assertRaises(ValueError):
            self.snmp.set_management(vlan_id=0)


class TestSNMPConfigRemote(unittest.TestCase):
    """Test SNMP set_snmp_information, get_config_remote, set_config_remote."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    # --- set_snmp_information ---

    def test_set_snmp_information_hostname(self):
        """SET sysName only."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set), \
             patch.object(self.snmp, 'get_snmp_information',
                          return_value={'chassis_id': 'TEST', 'contact': '',
                                        'location': '', 'community': {}}):
            result = self.snmp.set_snmp_information(hostname='TEST')
            self.assertEqual(len(set_calls), 1)
            self.assertIn(OID_sysName, set_calls[0][0])

    def test_set_snmp_information_all(self):
        """SET sysName + sysContact + sysLocation."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set), \
             patch.object(self.snmp, 'get_snmp_information',
                          return_value={'chassis_id': 'H', 'contact': 'C',
                                        'location': 'L', 'community': {}}):
            self.snmp.set_snmp_information(
                hostname='H', contact='C', location='L')
            self.assertEqual(len(set_calls), 3)
            oids = [c[0] for c in set_calls]
            self.assertTrue(any(OID_sysName in o for o in oids))
            self.assertTrue(any(OID_sysContact in o for o in oids))
            self.assertTrue(any(OID_sysLocation in o for o in oids))

    def test_set_snmp_information_no_args(self):
        """No args returns None without SET."""
        result = self.snmp.set_snmp_information()
        self.assertIsNone(result)

    # --- get_config_remote ---

    def test_get_config_remote(self):
        """Parse remote backup settings from SNMP scalars."""
        async def mock_scalar(*oids):
            return {
                OID_hm2FMServerUserName: 'admin',
                OID_hm2FMConfigRemoteSaveAdminStatus: 1,
                OID_hm2FMConfigRemoteSaveDestination:
                    'tftp://10.2.1.4/test.xml',
                OID_hm2FMConfigRemoteSaveUsername: 'backup',
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_config_remote()
            self.assertEqual(result['server_username'], 'admin')
            self.assertTrue(result['auto_backup']['enabled'])
            self.assertEqual(result['auto_backup']['destination'],
                             'tftp://10.2.1.4/test.xml')
            self.assertEqual(result['auto_backup']['username'], 'backup')

    def test_get_config_remote_disabled(self):
        """Auto-backup disabled."""
        async def mock_scalar(*oids):
            return {
                OID_hm2FMServerUserName: '',
                OID_hm2FMConfigRemoteSaveAdminStatus: 2,
                OID_hm2FMConfigRemoteSaveDestination: '',
                OID_hm2FMConfigRemoteSaveUsername: '',
            }

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_config_remote()
            self.assertFalse(result['auto_backup']['enabled'])

    # --- set_config_remote ---

    def test_set_config_remote_auto_backup(self):
        """Set auto-backup URL and enable."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, str(val)))

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set), \
             patch.object(self.snmp, 'get_config_remote',
                          return_value={'server_username': '',
                                        'auto_backup': {'enabled': True,
                                                         'destination': 'x',
                                                         'username': ''}}):
            self.snmp.set_config_remote(
                auto_backup=True,
                auto_backup_url='tftp://10.2.1.4/test.xml')
            oids_set = [c[0] for c in set_calls]
            self.assertTrue(any(
                OID_hm2FMConfigRemoteSaveAdminStatus in o for o in oids_set))
            self.assertTrue(any(
                OID_hm2FMConfigRemoteSaveDestination in o for o in oids_set))

    def test_set_config_remote_server_creds(self):
        """Set server username and password."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, str(val)))

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set), \
             patch.object(self.snmp, 'get_config_remote',
                          return_value={'server_username': 'admin',
                                        'auto_backup': {'enabled': False,
                                                         'destination': '',
                                                         'username': ''}}):
            self.snmp.set_config_remote(username='admin', password='secret')
            oids_set = [c[0] for c in set_calls]
            self.assertTrue(any(
                OID_hm2FMServerUserName in o for o in oids_set))
            self.assertTrue(any(
                OID_hm2FMServerPassword in o for o in oids_set))

    # --- _build_bp_to_name ---

    def test_build_bp_to_name(self):
        """Bridge-port → interface name mapping."""
        ifmap = {'1': '1/1', '2': '1/2', '5': '1/5'}
        async def mock_walk(oid, engine):
            return {'1': 1, '2': 2, '5': 5}

        with patch.object(self.snmp, '_walk', side_effect=mock_walk):
            result = asyncio.run(
                self.snmp._build_bp_to_name(ifmap, engine=None))
            self.assertEqual(result['1'], '1/1')
            self.assertEqual(result['2'], '1/2')
            self.assertEqual(result['5'], '1/5')

    def test_build_bp_to_name_unknown_ifindex(self):
        """Unknown ifindex gets fallback name."""
        ifmap = {'1': '1/1'}
        async def mock_walk(oid, engine):
            return {'1': 1, '2': 99}  # 99 not in ifmap

        with patch.object(self.snmp, '_walk', side_effect=mock_walk):
            result = asyncio.run(
                self.snmp._build_bp_to_name(ifmap, engine=None))
            self.assertEqual(result['1'], '1/1')
            self.assertEqual(result['2'], 'if99')


class TestEncodePortlist(unittest.TestCase):
    """Test _encode_portlist helper."""

    def test_encode_single_port(self):
        from napalm_hios.snmp_hios import _encode_portlist
        name_to_bp = {'1/1': '1', '1/2': '2'}
        result = _encode_portlist(['1/1'], name_to_bp)
        self.assertEqual(result, b'\x80')

    def test_encode_multiple_ports(self):
        from napalm_hios.snmp_hios import _encode_portlist
        name_to_bp = {'1/1': '1', '1/2': '2', '1/3': '3'}
        result = _encode_portlist(['1/1', '1/3'], name_to_bp)
        self.assertEqual(result, b'\xa0')  # 10100000

    def test_encode_empty(self):
        from napalm_hios.snmp_hios import _encode_portlist
        result = _encode_portlist([], {'1/1': '1'})
        self.assertEqual(result, b'')

    def test_encode_unknown_port_raises(self):
        from napalm_hios.snmp_hios import _encode_portlist
        with self.assertRaises(ValueError):
            _encode_portlist(['99/99'], {'1/1': '1'})

    def test_roundtrip(self):
        """encode → decode should return the same ports."""
        from napalm_hios.snmp_hios import _encode_portlist
        bp_to_name = {'1': '1/1', '2': '1/2', '3': '1/3', '5': '1/5'}
        name_to_bp = {v: k for k, v in bp_to_name.items()}
        original = ['1/1', '1/3', '1/5']
        encoded = _encode_portlist(original, name_to_bp)
        decoded = _decode_portlist(encoded, bp_to_name)
        self.assertEqual(sorted(decoded), sorted(original))


class TestSNMPWatchdog(unittest.TestCase):
    """Test SNMP watchdog methods."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_watchdog_status_disabled(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2ConfigWatchdogAdminStatus: 2,
                OID_hm2ConfigWatchdogOperStatus: 2,
                OID_hm2ConfigWatchdogTimeInterval: 0,
                OID_hm2ConfigWatchdogTimerValue: 0,
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_watchdog_status()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['interval'], 0)

    def test_get_watchdog_status_enabled(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2ConfigWatchdogAdminStatus: 1,
                OID_hm2ConfigWatchdogOperStatus: 1,
                OID_hm2ConfigWatchdogTimeInterval: 60,
                OID_hm2ConfigWatchdogTimerValue: 45,
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_watchdog_status()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['interval'], 60)
        self.assertEqual(result['remaining'], 45)

    def test_start_watchdog_invalid(self):
        with self.assertRaises(ValueError):
            self.snmp.start_watchdog(10)


class TestSNMPLoginPolicy(unittest.TestCase):
    """Test SNMP login policy methods."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_login_policy(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2PwdMgmtMinLength: 8,
                OID_hm2PwdMgmtLoginAttempts: 5,
                OID_hm2PwdMgmtLoginAttemptsTimePeriod: 300,
                OID_hm2PwdMgmtMinUpperCase: 2,
                OID_hm2PwdMgmtMinLowerCase: 2,
                OID_hm2PwdMgmtMinNumericNumbers: 1,
                OID_hm2PwdMgmtMinSpecialCharacters: 1,
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_login_policy()
        self.assertEqual(result['min_password_length'], 8)
        self.assertEqual(result['max_login_attempts'], 5)
        self.assertEqual(result['lockout_duration'], 300)
        self.assertEqual(result['min_uppercase'], 2)

    def test_set_login_policy(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_login_policy(min_password_length=10)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2PwdMgmtMinLength, set_calls[0][0])


class TestSNMPSyslog(unittest.TestCase):
    """Test SNMP syslog methods."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_syslog_disabled_no_servers(self):
        async def mock_scalar(*oids):
            return {OID_hm2LogSyslogAdminStatus: 2}
        async def mock_walk(oid_map, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_syslog()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['servers'], [])

    def test_get_syslog_with_server(self):
        async def mock_scalar(*oids):
            return {OID_hm2LogSyslogAdminStatus: 1}
        async def mock_walk(oid_map, engine=None):
            return {
                '1': {'ip': '10.2.1.4', 'port': 514,
                       'severity': 6, 'transport': 1},
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_syslog()
        self.assertTrue(result['enabled'])
        self.assertEqual(len(result['servers']), 1)
        self.assertEqual(result['servers'][0]['ip'], '10.2.1.4')
        self.assertEqual(result['servers'][0]['severity'], 'informational')


class TestSNMPNtp(unittest.TestCase):
    """Test SNMP NTP methods."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_ntp_disabled(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2SntpClientAdminState: 2,
                OID_hm2SntpRequestInterval: 30,
                OID_hm2NtpServerAdminState: 2,
                OID_hm2NtpServerLocalClockStratum: 1,
            }
        async def mock_walk(oid_map, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_ntp()
        self.assertFalse(result['client']['enabled'])
        self.assertEqual(result['client']['mode'], 'sntp')
        self.assertEqual(result['client']['servers'], [])
        self.assertFalse(result['server']['enabled'])
        self.assertEqual(result['server']['stratum'], 1)

    def test_get_ntp_enabled_with_server(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2SntpClientAdminState: 1,
                OID_hm2SntpRequestInterval: 30,
                OID_hm2NtpServerAdminState: 2,
                OID_hm2NtpServerLocalClockStratum: 12,
            }
        async def mock_walk(oid_map, engine=None):
            return {
                '1': {'addr': '10.2.1.1', 'status': 2},
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_ntp()
        self.assertTrue(result['client']['enabled'])
        self.assertEqual(len(result['client']['servers']), 1)
        self.assertEqual(result['client']['servers'][0]['address'], '10.2.1.1')
        self.assertEqual(result['client']['servers'][0]['status'], 'success')
        self.assertFalse(result['server']['enabled'])
        self.assertEqual(result['server']['stratum'], 12)


class TestSNMPServices(unittest.TestCase):
    """Test SNMP services methods."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def _base_scalar_dict(self, **overrides):
        d = {
            OID_hm2WebHttpAdminStatus: 1,
            OID_hm2WebHttpsAdminStatus: 1,
            OID_hm2WebHttpPortNumber: 80,
            OID_hm2WebHttpsPortNumber: 443,
            OID_hm2SshAdminStatus: 1,
            OID_hm2TelnetServerAdminStatus: 2,
            OID_hm2SnmpV1AdminStatus: 2,
            OID_hm2SnmpV2AdminStatus: 2,
            OID_hm2SnmpV3AdminStatus: 1,
            OID_hm2SnmpPortNumber: 161,
            OID_hm2Iec61850MmsServerAdminStatus: 2,
            OID_hm2PNIOAdminStatus: 2,
            OID_hm2EtherNetIPAdminStatus: 2,
            OID_hm2Iec62541OpcUaAdminStatus: 2,
            OID_hm2ModbusTcpServerAdminStatus: 2,
            OID_hm2DevMgmtSwVersAllowUnsigned: 2,
            OID_hm2AgentDot1qBridgeMvrpMode: 2,
            OID_hm2AgentDot1qBridgeMmrpMode: 2,
        }
        for oid in _OID_DEVSEC_ALL:
            d[oid] = 1
        d.update(overrides)
        return d

    def test_get_services(self):
        async def mock_scalar(*oids):
            return self._base_scalar_dict()
        async def mock_walk_cols(oid_map, engine=None):
            return {
                '1': {'auto': 2, 'save': 2, 'load': 0},
                '2': {'auto': 2, 'save': 2, 'load': 0},
            }
        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk_cols):
            result = self.snmp.get_services()
        self.assertTrue(result['http']['enabled'])
        self.assertEqual(result['http']['port'], 80)
        self.assertTrue(result['ssh']['enabled'])
        self.assertFalse(result['telnet']['enabled'])
        self.assertTrue(result['snmp']['v3'])
        self.assertFalse(result['industrial']['modbus'])
        self.assertFalse(result['unsigned_sw'])
        self.assertFalse(result['mvrp'])
        self.assertFalse(result['mmrp'])
        self.assertTrue(result['devsec_monitors'])
        self.assertFalse(result['aca_auto_update'])
        self.assertFalse(result['aca_config_write'])
        self.assertFalse(result['aca_config_load'])
        self.assertFalse(result['gvrp'])
        self.assertFalse(result['gmrp'])

    def test_get_services_unsigned_enabled(self):
        async def mock_scalar(*oids):
            return self._base_scalar_dict(
                **{OID_hm2DevMgmtSwVersAllowUnsigned: 1})
        async def mock_walk_cols(oid_map, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk_cols):
            result = self.snmp.get_services()
        self.assertTrue(result['unsigned_sw'])

    def test_get_services_aca_enabled(self):
        async def mock_scalar(*oids):
            return self._base_scalar_dict()
        async def mock_walk_cols(oid_map, engine=None):
            return {
                '1': {'auto': 1, 'save': 1, 'load': 1},
            }
        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk_cols):
            result = self.snmp.get_services()
        self.assertTrue(result['aca_auto_update'])
        self.assertTrue(result['aca_config_write'])
        self.assertTrue(result['aca_config_load'])

    def test_get_services_devsec_some_disabled(self):
        d = self._base_scalar_dict()
        d[_OID_DEVSEC_ALL[5]] = 2  # disable one
        async def mock_scalar(*oids):
            return d
        async def mock_walk_cols(oid_map, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk_cols):
            result = self.snmp.get_services()
        self.assertFalse(result['devsec_monitors'])

    def test_set_services_telnet(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_services(telnet=True)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2TelnetServerAdminStatus, set_calls[0][0])

    def test_set_services_unsigned_sw(self):
        set_calls = []
        async def mock_set(*pairs):
            set_calls.extend(pairs)
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set):
            self.snmp.set_services(unsigned_sw=False)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2DevMgmtSwVersAllowUnsigned,
                      set_calls[0][0])

    def test_set_services_devsec_monitors(self):
        """set_services(devsec_monitors=True) sets all 19 DevSec OIDs."""
        set_calls = []
        async def mock_set(*pairs):
            set_calls.extend(pairs)
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set):
            self.snmp.set_services(devsec_monitors=True)
        # 19 DevSec OIDs in one SET
        self.assertEqual(len(set_calls), 19)

    def test_set_services_aca(self):
        set_calls = []
        async def mock_set(*pairs):
            set_calls.extend(pairs)
        async def mock_walk(base_oid):
            return {'1': 1, '2': 2}
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set), \
             patch.object(self.snmp, '_walk',
                          side_effect=mock_walk):
            self.snmp.set_services(aca_auto_update=False)
        # 2 rows, 1 OID each
        self.assertEqual(len(set_calls), 2)


class TestSNMPSnmpConfig(unittest.TestCase):
    """Test SNMP snmp_config methods."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_snmp_config(self):
        async def mock_scalar(*oids):
            return {
                OID_hm2SnmpV1AdminStatus: 2,
                OID_hm2SnmpV2AdminStatus: 2,
                OID_hm2SnmpV3AdminStatus: 1,
                OID_hm2SnmpPortNumber: 161,
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_snmp_config()
        self.assertFalse(result['versions']['v1'])
        self.assertTrue(result['versions']['v3'])
        self.assertEqual(result['port'], 161)
        self.assertEqual(result['communities'], [])

    def test_set_snmp_config_v1_enable(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_snmp_config(v1=True)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2SnmpV1AdminStatus, set_calls[0][0])


class TestSNMPSignalContact(unittest.TestCase):
    """Test SNMP signal contact getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_signal_contact(self):
        """get_signal_contact returns correct shape from BRS50 data."""
        async def mock_walk_columns(oid_map, engine=None):
            # Check which table we're querying by checking OID prefixes
            keys = list(oid_map.keys())
            if 'mode' in oid_map or 'trap_en' in oid_map:
                # Common entry — indexed by SigConID
                return {'.1': {
                    'trap_en': 2, 'trap_cause': 10, 'trap_cause_idx': 0,
                    'mode': 2, 'oper_state': 1, 'oper_ts': 1773134373,
                    'manual': 2,
                    'link_failure': 2, 'temperature': 1,
                    'envm_removal': 2, 'envm_not_in_sync': 2,
                    'ring_redundancy': 2,
                }}
            elif 'ts' in oid_map:
                # Status table
                return {'.1.6': {
                    'ts': 1773135114, 'cause': 2, 'cause_idx': 2,
                }}
            return {}
        async def mock_walk(oid, engine=None):
            if 'PSState' in str(oid) or '.2.1.1' in str(oid):
                return {'.1.1': 1, '.1.2': 1}
            elif 'LinkAlarm' in str(oid) or '.3.1.1' in str(oid):
                return {'.1.1': 2, '.1.2': 2, '.1.3': 2}
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2', '3': '1/3'}
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_signal_contact()
        self.assertIn(1, result)
        sc1 = result[1]
        self.assertEqual(sc1['mode'], 'monitor')
        self.assertFalse(sc1['trap_enabled'])
        self.assertTrue(sc1['monitoring']['temperature'])
        self.assertFalse(sc1['monitoring']['link_failure'])
        self.assertTrue(sc1['power_supply'][1])
        self.assertFalse(sc1['link_alarm']['1/1'])
        self.assertEqual(sc1['status']['oper_state'], 'open')

    def test_set_signal_contact_mode(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_signal_contact(contact_id=1, mode='deviceSecurity')
        self.assertEqual(len(set_calls), 1)
        self.assertIn('.5.', set_calls[0][0])  # mode OID


class TestSNMPDeviceMonitor(unittest.TestCase):
    """Test SNMP device monitor getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_device_monitor(self):
        """get_device_monitor returns correct shape via _walk_columns."""
        async def mock_walk_columns(oid_map, engine=None):
            keys = list(oid_map.keys())
            if 'trap_en' in oid_map:
                return {'.1': {
                    'trap_en': 1, 'trap_cause': 2, 'trap_cause_idx': 2,
                    'oper_state': 2, 'oper_ts': 1773132810,
                    'link_failure': 2, 'temperature': 1,
                    'envm_removal': 2, 'envm_not_in_sync': 2,
                    'ring_redundancy': 2,
                }}
            elif 'ts' in oid_map:
                return {'.1': {
                    'ts': 1773132810, 'cause': 2, 'cause_idx': 2,
                }}
            return {}
        async def mock_walk(oid, engine=None):
            if '.2.1.1' in str(oid):
                return {'.1.1': 1, '.1.2': 1}
            elif '.3.1.1' in str(oid):
                return {'.1.1': 2, '.1.2': 2}
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_device_monitor()
        self.assertTrue(result['trap_enabled'])
        self.assertTrue(result['monitoring']['temperature'])
        self.assertFalse(result['monitoring']['link_failure'])
        self.assertEqual(result['status']['oper_state'], 'error')
        self.assertEqual(result['status']['cause'], 'power-supply')
        self.assertEqual(result['status']['cause_index'], 2)
        self.assertTrue(result['power_supply'][1])

    def test_set_device_monitor_trap(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_device_monitor(trap_enabled=False)
        self.assertEqual(len(set_calls), 1)


class TestSNMPDevSecStatus(unittest.TestCase):
    """Test SNMP device security status getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_devsec_status(self):
        """get_devsec_status returns 19 monitors via _walk_columns(.0)."""
        async def mock_walk_columns(oid_map, engine=None):
            keys = list(oid_map.keys())
            if 'trap_en' in oid_map:
                return {'.0': {
                    'trap_en': 2, 'trap_cause': 17, 'trap_cause_idx': 0,
                    'oper_state': 2, 'oper_ts': 1773135123,
                    'password_change': 1, 'password_min_length': 1,
                    'password_policy_not_configured': 1,
                    'password_policy_bypass': 1,
                    'telnet_enabled': 1, 'http_enabled': 1,
                    'snmp_unsecure': 1, 'sysmon_enabled': 1,
                    'envm_update_enabled': 1, 'no_link_enabled': 1,
                    'hidiscovery_enabled': 1,
                    'envm_config_load_unsecure': 1,
                    'iec61850_mms_enabled': 1,
                    'https_cert_warning': 1,
                    'modbus_tcp_enabled': 1, 'ethernet_ip_enabled': 1,
                    'profinet_enabled': 1,
                    'secure_boot_disabled': 1, 'dev_mode_enabled': 1,
                }}
            elif 'ts' in oid_map:
                return {
                    '.1': {'ts': 1773056467, 'cause': 13, 'cause_idx': 0},
                    '.4': {'ts': 1773056470, 'cause': 10, 'cause_idx': 0},
                }
            return {}
        async def mock_walk(oid, engine=None):
            return {'.1': 2, '.2': 2, '.3': 2}
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2', '3': '1/3'}
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_walk', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_devsec_status()
        self.assertFalse(result['trap_enabled'])
        self.assertEqual(len(result['monitoring']), 19)
        self.assertTrue(result['monitoring']['password_change'])
        self.assertTrue(result['monitoring']['sysmon_enabled'])
        self.assertEqual(result['status']['oper_state'], 'error')
        self.assertEqual(result['status']['cause'], 'sysmon-enabled')
        self.assertEqual(len(result['status']['events']), 2)
        self.assertFalse(result['no_link']['1/1'])

    def test_set_devsec_status_monitoring(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_devsec_status(monitoring={'sysmon_enabled': False})
        self.assertEqual(len(set_calls), 1)


class TestSNMPBanner(unittest.TestCase):
    """Test SNMP banner getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_banner_defaults(self):
        """get_banner factory defaults — both disabled, empty."""
        async def mock_scalar(*oids):
            return {
                OID_hm2PreLoginBannerAdminStatus: 2,
                OID_hm2PreLoginBannerText: '',
                OID_hm2CliLoginBannerAdminStatus: 2,
                OID_hm2CliLoginBannerText: '',
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_banner()
        self.assertFalse(result['pre_login']['enabled'])
        self.assertEqual(result['pre_login']['text'], '')
        self.assertFalse(result['cli_login']['enabled'])

    def test_get_banner_with_text(self):
        """get_banner with enabled pre-login banner."""
        async def mock_scalar(*oids):
            return {
                OID_hm2PreLoginBannerAdminStatus: 1,
                OID_hm2PreLoginBannerText: 'Hello World',
                OID_hm2CliLoginBannerAdminStatus: 2,
                OID_hm2CliLoginBannerText: '',
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_banner()
        self.assertTrue(result['pre_login']['enabled'])
        self.assertEqual(result['pre_login']['text'], 'Hello World')

    def test_set_banner_pre_login(self):
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_banner(pre_login_enabled=True,
                                 pre_login_text='Test')
        self.assertEqual(len(set_calls), 2)  # enabled + text


class TestSNMPSessionConfig(unittest.TestCase):
    """Test SNMP session config getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_session_config(self):
        """get_session_config returns all protocol groups."""
        async def mock_scalar(*oids):
            return {
                OID_hm2SshSessionTimeout: 5,
                OID_hm2SshMaxSessionsCount: 5,
                OID_hm2SshSessionsCount: 0,
                OID_hm2SshOutboundSessionTimeout: 0,
                OID_hm2SshOutboundMaxSessionsCount: 0,
                OID_hm2SshOutboundSessionsCount: 0,
                OID_hm2TelnetServerSessionsTimeOut: 5,
                OID_hm2TelnetServerMaxSessions: 5,
                OID_hm2TelnetServerSessionsCount: 0,
                OID_hm2WebIntfTimeOut: 5,
                OID_hm2CliLoginTimeoutSerial: 5,
                OID_hm2NetconfSessionTimeout: 3600,
                OID_hm2NetconfMaxSessions: 5,
                OID_hm2NetconfSessionsCount: 0,
            }
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            result = self.snmp.get_session_config()
        self.assertEqual(result['ssh']['timeout'], 5)
        self.assertEqual(result['ssh']['max_sessions'], 5)
        self.assertEqual(result['telnet']['timeout'], 5)
        self.assertEqual(result['web']['timeout'], 5)
        self.assertEqual(result['serial']['timeout'], 5)
        self.assertEqual(result['netconf']['timeout'], 60)

    def test_set_session_config_ssh(self):
        """set_session_config sets SSH timeout via SNMP."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_session_config(ssh_timeout=10)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2SshSessionTimeout, set_calls[0][0])


class TestSNMPIpRestrict(unittest.TestCase):
    """Test SNMP IP restrict getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_ip_restrict(self):
        """get_ip_restrict returns scalars + rules."""
        async def mock_scalar(*oids):
            return {
                OID_hm2RmaOperation: 2,
                OID_hm2RmaLoggingGlobal: 2,
            }
        async def mock_walk(columns, engine=None):
            return {}  # no rules
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_ip_restrict()
        self.assertFalse(result['enabled'])
        self.assertFalse(result['logging'])
        self.assertEqual(result['rules'], [])

    def test_set_ip_restrict_enable(self):
        """set_ip_restrict enables RMA via SNMP."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_ip_restrict(enabled=True)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2RmaOperation, set_calls[0][0])


class TestSNMPSnmpConfigExtended(unittest.TestCase):
    """Test SNMP extended snmp_config (trap_service, v3_users)."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    def test_get_snmp_config_with_users(self):
        """get_snmp_config returns v3_users and trap_service."""
        async def mock_scalar(*oids):
            return {
                OID_hm2SnmpV1AdminStatus: 2,
                OID_hm2SnmpV2AdminStatus: 2,
                OID_hm2SnmpV3AdminStatus: 1,
                OID_hm2SnmpPortNumber: 161,
                OID_hm2SnmpTrapServiceAdminStatus: 1,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                # v3 user walk — IMPLIED string suffix (no length prefix)
                return {
                    '97.100.109.105.110': {
                        'auth': 1, 'enc': 1, 'status': 1,
                    }
                }
            # trap walks return empty
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_snmp_config()
        self.assertTrue(result['trap_service'])
        self.assertEqual(len(result['v3_users']), 1)
        self.assertEqual(result['v3_users'][0]['name'], 'admin')
        self.assertEqual(result['v3_users'][0]['auth_type'], 'md5')
        self.assertEqual(result['v3_users'][0]['enc_type'], 'des')

    def test_set_snmp_config_trap_service(self):
        """set_snmp_config enables trap service."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_snmp_config(trap_service=True)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2SnmpTrapServiceAdminStatus, set_calls[0][0])


class TestSNMPDns(unittest.TestCase):
    """Test SNMP DNS client getter/setter/CRUD."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    # --- get_dns ---

    def test_get_dns_factory_defaults(self):
        """get_dns factory defaults — disabled, no servers."""
        async def mock_scalar(*oids):
            return {
                OID_hm2DnsClientAdminState: 2,
                OID_hm2DnsClientConfigSource: 2,
                OID_hm2DnsClientDefaultDomainName: '',
                OID_hm2DnsClientRequestTimeout: 3,
                OID_hm2DnsClientRequestRetransmits: 2,
                OID_hm2DnsClientCacheAdminState: 1,
            }
        async def mock_walk(columns, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_dns()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['config_source'], 'mgmt-dhcp')
        self.assertEqual(result['domain_name'], '')
        self.assertEqual(result['timeout'], 3)
        self.assertEqual(result['retransmits'], 2)
        self.assertTrue(result['cache_enabled'])
        self.assertEqual(result['servers'], [])
        self.assertEqual(result['active_servers'], [])

    def test_get_dns_with_server(self):
        """get_dns with DNS enabled and a configured server."""
        async def mock_scalar(*oids):
            return {
                OID_hm2DnsClientAdminState: 1,
                OID_hm2DnsClientConfigSource: 1,
                OID_hm2DnsClientDefaultDomainName: 'test.local',
                OID_hm2DnsClientRequestTimeout: 5,
                OID_hm2DnsClientRequestRetransmits: 3,
                OID_hm2DnsClientCacheAdminState: 2,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                # cfg table
                return {
                    '1': {
                        'addr_type': 1,
                        'addr': '0xc0a80301',
                        'row_status': 1,
                    },
                }
            elif walk_calls[0] == 2:
                # diag table
                return {
                    '1': {
                        'addr_type': 1,
                        'addr': '0xc0a80301',
                    },
                }
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_dns()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['config_source'], 'user')
        self.assertEqual(result['domain_name'], 'test.local')
        self.assertEqual(result['timeout'], 5)
        self.assertEqual(result['retransmits'], 3)
        self.assertFalse(result['cache_enabled'])
        self.assertEqual(result['servers'], ['192.168.3.1'])
        self.assertEqual(result['active_servers'], ['192.168.3.1'])

    def test_get_dns_skips_inactive_rows(self):
        """get_dns ignores servers with RowStatus=6 (destroyed)."""
        async def mock_scalar(*oids):
            return {
                OID_hm2DnsClientAdminState: 1,
                OID_hm2DnsClientConfigSource: 1,
                OID_hm2DnsClientDefaultDomainName: '',
                OID_hm2DnsClientRequestTimeout: 3,
                OID_hm2DnsClientRequestRetransmits: 2,
                OID_hm2DnsClientCacheAdminState: 1,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                return {
                    '1': {
                        'addr_type': 1,
                        'addr': '0xc0a80301',
                        'row_status': 6,
                    },
                }
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_dns()
        self.assertEqual(result['servers'], [])

    def test_get_dns_multiple_servers(self):
        """get_dns returns multiple configured servers."""
        async def mock_scalar(*oids):
            return {
                OID_hm2DnsClientAdminState: 1,
                OID_hm2DnsClientConfigSource: 1,
                OID_hm2DnsClientDefaultDomainName: '',
                OID_hm2DnsClientRequestTimeout: 3,
                OID_hm2DnsClientRequestRetransmits: 2,
                OID_hm2DnsClientCacheAdminState: 1,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                return {
                    '1': {
                        'addr_type': 1,
                        'addr': '0xc0a80301',
                        'row_status': 1,
                    },
                    '2': {
                        'addr_type': 1,
                        'addr': '0x0a000001',
                        'row_status': 1,
                    },
                }
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_dns()
        self.assertEqual(result['servers'], ['192.168.3.1', '10.0.0.1'])

    # --- set_dns ---

    def test_set_dns_enable(self):
        """set_dns enables DNS client via SNMP."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_dns(enabled=True)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2DnsClientAdminState, set_calls[0][0])

    def test_set_dns_multiple_fields(self):
        """set_dns sets multiple scalar fields."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_dns(
                cache_enabled=False, timeout=10, retransmits=5)
        self.assertEqual(len(set_calls), 3)
        oids_set = [c[0] for c in set_calls]
        self.assertTrue(any(
            OID_hm2DnsClientRequestTimeout in o for o in oids_set))
        self.assertTrue(any(
            OID_hm2DnsClientRequestRetransmits in o for o in oids_set))
        self.assertTrue(any(
            OID_hm2DnsClientCacheAdminState in o for o in oids_set))

    def test_set_dns_invalid_config_source(self):
        """set_dns raises ValueError for invalid config_source."""
        with self.assertRaises(ValueError):
            self.snmp.set_dns(config_source='invalid')

    # --- add_dns_server ---

    def test_add_dns_server_empty_table(self):
        """add_dns_server picks index 1 when table is empty."""
        set_calls = []
        async def mock_walk(columns, engine=None):
            return {}
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.add_dns_server('192.168.3.1')
        # Should use index 1
        oids_set = [c[0] for c in set_calls]
        self.assertTrue(any('.1' in o and 'RowStatus' not in o
                            for o in oids_set)
                        or any(o.endswith('.1') for o in oids_set))
        # RowStatus=4 (createAndGo)
        rs_calls = [(o, v) for o, v in set_calls
                     if OID_hm2DnsClientServerRowStatus in o]
        self.assertEqual(len(rs_calls), 1)

    def test_add_dns_server_picks_next_free(self):
        """add_dns_server skips used index 1, picks 2."""
        set_calls = []
        async def mock_walk(columns, engine=None):
            return {'1': {'row_status': 1}}
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.add_dns_server('10.0.0.1')
        # Check index 2 used
        rs_calls = [(o, v) for o, v in set_calls
                     if OID_hm2DnsClientServerRowStatus in o]
        self.assertTrue(rs_calls[0][0].endswith('.2'))

    def test_add_dns_server_full_table(self):
        """add_dns_server raises ValueError when all 4 slots used."""
        async def mock_walk(columns, engine=None):
            return {
                '1': {'row_status': 1},
                '2': {'row_status': 1},
                '3': {'row_status': 1},
                '4': {'row_status': 1},
            }
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.add_dns_server('10.0.0.5')
        self.assertIn('4 DNS server slots', str(ctx.exception))

    # --- delete_dns_server ---

    def test_delete_dns_server(self):
        """delete_dns_server destroys correct row."""
        set_calls = []
        async def mock_walk(columns, engine=None):
            return {
                '2': {
                    'addr': '0xc0a80301',
                    'row_status': 1,
                },
            }
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.delete_dns_server('192.168.3.1')
        self.assertEqual(len(set_calls), 1)
        self.assertTrue(set_calls[0][0].endswith('.2'))

    def test_delete_dns_server_not_found(self):
        """delete_dns_server raises ValueError when IP not in table."""
        async def mock_walk(columns, engine=None):
            return {
                '1': {
                    'addr': '0xc0a80301',
                    'row_status': 1,
                },
            }
        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.delete_dns_server('10.10.10.10')
        self.assertIn('not found', str(ctx.exception))


class TestSNMPPoe(unittest.TestCase):
    """Test SNMP PoE getter/setter."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    # --- get_poe ---

    def test_get_poe_factory_defaults(self):
        """get_poe factory defaults — disabled, empty ports/modules."""
        async def mock_scalar(*oids):
            return {
                OID_hm2PoeMgmtAdminStatus: 2,
                OID_hm2PoeMgmtReservedPower: 0,
                OID_hm2PoeMgmtDeliveredCurrent: 0,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_poe()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['power_w'], 0)
        self.assertEqual(result['delivered_current_ma'], 0)
        self.assertEqual(result['modules'], {})
        self.assertEqual(result['ports'], {})

    def test_get_poe_with_port_and_module(self):
        """get_poe with enabled PoE, ports, and modules."""
        async def mock_scalar(*oids):
            return {
                OID_hm2PoeMgmtAdminStatus: 1,
                OID_hm2PoeMgmtReservedPower: 30,
                OID_hm2PoeMgmtDeliveredCurrent: 250,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                # Port table
                return {
                    '1': {
                        'admin': 1,
                        'consumption': 5300,
                        'status': 3,
                        'priority': 2,
                        'classification': 5,
                        'name': 'AP',
                        'class_valid': 1,
                        'fast_startup': 1,
                        'power_limit': 15400,
                    },
                }
            elif walk_calls[0] == 2:
                # Module table
                return {
                    '1.1': {
                        'unit': 1, 'slot': 1,
                        'power': 370, 'max_power': 370,
                        'reserved': 30, 'delivered': 5,
                        'source': 0, 'threshold': 90,
                        'notif': 1,
                    },
                }
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_poe()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['power_w'], 30)
        # Module
        self.assertIn('1/1', result['modules'])
        mod = result['modules']['1/1']
        self.assertEqual(mod['budget_w'], 370)
        self.assertEqual(mod['source'], 'internal')
        self.assertTrue(mod['notifications'])
        # Port
        self.assertIn('1/1', result['ports'])
        port = result['ports']['1/1']
        self.assertTrue(port['enabled'])
        self.assertEqual(port['status'], 'delivering')
        self.assertEqual(port['priority'], 'high')
        self.assertEqual(port['classification'], 'class4')
        self.assertEqual(port['consumption_mw'], 5300)
        self.assertEqual(port['power_limit_mw'], 15400)
        self.assertTrue(port['fast_startup'])

    def test_get_poe_class_invalid(self):
        """get_poe classification is None when class_valid=0."""
        async def mock_scalar(*oids):
            return {
                OID_hm2PoeMgmtAdminStatus: 1,
                OID_hm2PoeMgmtReservedPower: 0,
                OID_hm2PoeMgmtDeliveredCurrent: 0,
            }
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                return {
                    '1': {
                        'admin': 1, 'consumption': 0,
                        'status': 2, 'priority': 3,
                        'classification': 1, 'name': '',
                        'class_valid': 0, 'fast_startup': 2,
                        'power_limit': 0,
                    },
                }
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_poe()
        self.assertIsNone(result['ports']['1/1']['classification'])

    # --- set_poe ---

    def test_set_poe_global_enable(self):
        """set_poe(enabled=True) sends correct SNMP OID."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set):
            self.snmp.set_poe(enabled=True)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2PoeMgmtAdminStatus, set_calls[0][0])

    def test_set_poe_per_port_disable(self):
        """set_poe per-port disable sends correct OIDs."""
        set_calls = []
        async def mock_set(*pairs):
            for oid, val in pairs:
                set_calls.append((oid, val))
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            self.snmp.set_poe(interface='1/1', enabled=False)
        self.assertEqual(len(set_calls), 1)
        self.assertIn(OID_hm2PoeMgmtPortAdminEnable, set_calls[0][0])

    def test_set_poe_invalid_priority(self):
        """set_poe raises ValueError for invalid priority."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_poe(
                    interface='1/1', priority='invalid')


    # --- get_remote_auth ---

    def test_get_remote_auth_all_disabled(self):
        """get_remote_auth factory defaults — nothing configured."""
        async def mock_scalar(*oids):
            return {OID_hm2LdapClientAdminState: 2}
        async def mock_walk(columns, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_radius_active(self):
        """get_remote_auth with one active RADIUS server."""
        async def mock_scalar(*oids):
            return {OID_hm2LdapClientAdminState: 2}
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                # RADIUS — one active server
                return {'1': {'row_status': 1}}
            return {}  # TACACS+ — empty
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_remote_auth()
        self.assertTrue(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_ldap_enabled(self):
        """get_remote_auth with LDAP globally enabled."""
        async def mock_scalar(*oids):
            return {OID_hm2LdapClientAdminState: 1}
        async def mock_walk(columns, engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertTrue(result['ldap']['enabled'])

    def test_get_remote_auth_tacacs_active(self):
        """get_remote_auth with one active TACACS+ server."""
        async def mock_scalar(*oids):
            return {OID_hm2LdapClientAdminState: 2}
        walk_calls = [0]
        async def mock_walk(columns, engine=None):
            walk_calls[0] += 1
            if walk_calls[0] == 1:
                return {}  # RADIUS — empty
            return {'1.4.10.0.0.1': {'row_status': 1}}  # TACACS+ active
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk):
            result = self.snmp.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertTrue(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])


    # --- get_users ---

    def test_get_users_single_admin(self):
        """get_users with single admin user."""
        async def mock_walk(columns, engine=None):
            return {
                '.97.100.109.105.110': {
                    'role': 15, 'locked': 2,
                    'policy_check': 2, 'snmp_auth': 1,
                    'snmp_enc': 1, 'row_status': 1,
                },
            }
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk):
            result = self.snmp.get_users()
        self.assertEqual(len(result), 1)
        u = result[0]
        self.assertEqual(u['name'], 'admin')
        self.assertEqual(u['role'], 'administrator')
        self.assertFalse(u['locked'])
        self.assertFalse(u['policy_check'])
        self.assertEqual(u['snmp_auth'], 'md5')
        self.assertEqual(u['snmp_enc'], 'des')
        self.assertTrue(u['active'])

    def test_get_users_multiple(self):
        """get_users with multiple users."""
        async def mock_walk(columns, engine=None):
            return {
                '.97.100.109.105.110': {
                    'role': 15, 'locked': 2, 'policy_check': 2,
                    'snmp_auth': 2, 'snmp_enc': 2, 'row_status': 1,
                },
                '.111.112.101.114.97.116.111.114': {
                    'role': 13, 'locked': 2, 'policy_check': 1,
                    'snmp_auth': 1, 'snmp_enc': 0, 'row_status': 2,
                },
            }
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk):
            result = self.snmp.get_users()
        self.assertEqual(len(result), 2)
        names = {u['name'] for u in result}
        self.assertIn('admin', names)
        self.assertIn('operator', names)
        oper = next(u for u in result if u['name'] == 'operator')
        self.assertEqual(oper['role'], 'operator')
        self.assertTrue(oper['policy_check'])
        self.assertEqual(oper['snmp_enc'], 'none')
        self.assertFalse(oper['active'])

    def test_set_user_create_new(self):
        """set_user creates new user via SNMP with 3-step sequence."""
        async def mock_walk(columns, engine=None):
            return {}  # No existing users
        async def mock_set(*pairs):
            pass
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as mock_s:
            self.snmp.set_user('newuser', password='Test1234!',
                               role='operator')
        calls = mock_s.call_args_list
        # Step 1: createAndWait
        self.assertEqual(calls[0][0][0][1].hasValue(), True)
        # Step 2: password
        self.assertEqual(len(calls[1][0]), 1)
        # Step 3: activate + role
        self.assertEqual(len(calls), 3)

    def test_set_user_requires_password_for_new(self):
        """set_user raises ValueError for new user without password."""
        async def mock_walk(columns, engine=None):
            return {}
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk):
            with self.assertRaises(ValueError):
                self.snmp.set_user('newuser', role='guest')

    def test_set_user_update_existing(self):
        """set_user updates existing user (single SET, no create)."""
        async def mock_walk(columns, engine=None):
            return {
                '.97.100.109.105.110': {
                    'role': 15, 'locked': 2, 'policy_check': 2,
                    'snmp_auth': 1, 'snmp_enc': 1, 'row_status': 1,
                },
            }
        async def mock_set(*pairs):
            pass
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as mock_s:
            self.snmp.set_user('admin', role='operator')
        # Update = single SET call (no createAndWait sequence)
        self.assertEqual(len(mock_s.call_args_list), 1)

    def test_set_user_invalid_role(self):
        """set_user raises ValueError for invalid role."""
        async def mock_walk(columns, engine=None):
            return {
                '.97.100.109.105.110': {'row_status': 1},
            }
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk):
            with self.assertRaises(ValueError):
                self.snmp.set_user('admin', role='superadmin')

    def test_delete_user(self):
        """delete_user sends destroy(6) via SNMP."""
        async def mock_set(*pairs):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as mock_s:
            self.snmp.delete_user('testuser')
        call_args = mock_s.call_args[0]
        self.assertIn('.9.', call_args[0][0])  # status column
        self.assertEqual(int(call_args[0][1]), 6)  # destroy


class TestSNMPBitsCodec(unittest.TestCase):
    """Test SNMP BITS OctetString decode/encode."""

    def test_decode_bits_snmp_bytes(self):
        """Decode raw bytes to algorithm names."""
        # Bit 2 = 0x20
        result = _decode_bits_snmp(b'\x20', _TLS_VERSIONS)
        self.assertEqual(result, ['tlsv1.2'])

    def test_decode_bits_snmp_octetstring(self):
        """Decode pysnmp-like OctetString."""
        class FakeOctet:
            def __bytes__(self):
                return b'\xd8'  # bits 0,1,3,4
        result = _decode_bits_snmp(FakeOctet(), _SSH_HMAC)
        self.assertEqual(result, [
            'hmac-sha1', 'hmac-sha2-256',
            'hmac-sha1-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com',
        ])

    def test_decode_bits_snmp_empty(self):
        self.assertEqual(_decode_bits_snmp(b'', _TLS_VERSIONS), [])
        self.assertEqual(_decode_bits_snmp(None, _TLS_VERSIONS), [])

    def test_encode_bits_snmp_roundtrip(self):
        """Encode then decode gives same list."""
        names = ['hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com']
        encoded = _encode_bits_snmp(names, _SSH_HMAC)
        decoded = _decode_bits_snmp(encoded, _SSH_HMAC)
        self.assertEqual(decoded, names)


class TestSNMPTrapDestCRUD(unittest.TestCase):
    """Test SNMP add/delete SNMP trap destination."""

    def setUp(self):
        self.snmp = SNMPHIOS.__new__(SNMPHIOS)
        self.snmp.hostname = '198.51.100.1'
        self.snmp.port = 161
        self.snmp.username = 'admin'
        self.snmp.password = 'private'
        self.snmp._auth_proto = 'sha'
        self.snmp._priv_proto = 'aes128'
        self.snmp._context_name = ''
        self.snmp.timeout = 10

    def test_add_snmp_trap_dest_v3(self):
        """add_snmp_trap_dest creates params and addr entries via SNMP."""
        async def mock_set(*pairs):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as mock_s:
            self.snmp.add_snmp_trap_dest(
                'nms1', '192.168.1.100', port=162,
                security_model='v3', security_name='admin',
                security_level='authpriv')
        # 6 SET calls: params create/set/activate + addr create/set/activate
        self.assertEqual(len(mock_s.call_args_list), 6)

    def test_add_snmp_trap_dest_v1_forces_noauth(self):
        """v1 security_level forced to noauth regardless of input."""
        set_calls = []
        async def mock_set(*pairs):
            set_calls.append(pairs)
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set):
            self.snmp.add_snmp_trap_dest(
                'trap1', '10.0.0.1', security_model='v1',
                security_name='public', security_level='authpriv')
        # Params step 2 (index 1): security_level should be noauth(1)
        params_set = set_calls[1]
        # Find the security level OID value
        level_vals = [int(v) for oid, v in params_set
                      if '.5.' in str(oid)]  # secLevel column
        self.assertIn(1, level_vals)  # 1 = noauth

    def test_add_snmp_trap_dest_invalid_model(self):
        """Raises ValueError for invalid security_model."""
        with self.assertRaises(ValueError):
            self.snmp.add_snmp_trap_dest(
                'bad', '10.0.0.1', security_model='v4')

    def test_delete_snmp_trap_dest(self):
        """delete_snmp_trap_dest destroys both addr and params."""
        async def mock_set(*pairs):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as mock_s:
            self.snmp.delete_snmp_trap_dest('nms1')
        self.assertEqual(len(mock_s.call_args_list), 2)

    def test_decode_taddress_snmp_bytes(self):
        """_decode_taddress_snmp handles raw bytes."""
        result = SNMPHIOS._decode_taddress_snmp(
            b'\xc0\xa8\x01\x64\x00\xa2')
        self.assertEqual(result, '192.168.1.100:162')

    def test_decode_taddress_snmp_octetstring(self):
        """_decode_taddress_snmp handles pysnmp OctetString."""
        class FakeOctetString:
            def __bytes__(self):
                return b'\x0a\x00\x00\x01\x00\xa2'
            def __str__(self):
                return 'garbage'
        result = SNMPHIOS._decode_taddress_snmp(FakeOctetString())
        self.assertEqual(result, '10.0.0.1:162')

    def test_get_trap_dest_v1_normalises_level(self):
        """Getter normalises security_level to noauth for v1/v2c."""
        # Mock OctetString that behaves like pysnmp's:
        # str() gives decoded text, bytes() gives raw bytes
        class FakeStr:
            def __init__(self, s):
                self._s = s
            def __str__(self):
                return self._s

        class FakeTAddr:
            def __bytes__(self):
                return b'\x0a\x00\x00\x01\x00\xa2'

        # Suffix: IMPLIED string = ASCII codes, no length prefix
        # nms1 = 110.109.115.49
        suffix = '110.109.115.49'
        async def mock_walk(columns, engine=None):
            if 'model' in columns:
                # params table
                return {suffix: {
                    'model': 1, 'sec_name': FakeStr('pub'),
                    'sec_level': 3}}
            else:
                # addr table
                return {suffix: {
                    'taddr': FakeTAddr(),
                    'params': FakeStr('nms1')}}
        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk):
            import asyncio
            from pysnmp.hlapi.v3arch.asyncio import SnmpEngine
            result = asyncio.run(
                self.snmp._get_trap_dests_async(SnmpEngine()))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['security_model'], 'v1')
        self.assertEqual(result[0]['security_level'], 'noauth')


class TestSNMPPortSecurity(unittest.TestCase):
    """Test SNMP port security getter/setter/CRUD."""

    def setUp(self):
        self.snmp = SNMPHIOS('192.168.1.254', 'admin', 'private', 10)
        self.snmp._connected = True

    # --- _parse_portsec_macs / _parse_portsec_ips ---

    def test_parse_portsec_macs(self):
        result = self.snmp._parse_portsec_macs(
            '1 aa:bb:cc:dd:ee:ff,2 11:22:33:44:55:66')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'})
        self.assertEqual(result[1], {'vlan': 2, 'mac': '11:22:33:44:55:66'})

    def test_parse_portsec_macs_empty(self):
        self.assertEqual(self.snmp._parse_portsec_macs(''), [])
        self.assertEqual(self.snmp._parse_portsec_macs(None), [])

    def test_parse_portsec_ips(self):
        result = self.snmp._parse_portsec_ips(
            '1 192.168.1.1,2 10.0.0.1')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {'vlan': 1, 'ip': '192.168.1.1'})
        self.assertEqual(result[1], {'vlan': 2, 'ip': '10.0.0.1'})

    def test_parse_portsec_ips_empty(self):
        self.assertEqual(self.snmp._parse_portsec_ips(''), [])

    # --- get_port_security ---

    def test_get_port_security_all(self):
        """get_port_security() returns global + per-port data."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentGlobalPortSecurityMode: 1,
                OID_hm2AgentPortSecurityOperationMode: 1,
            }
        async def mock_walk(columns, engine=None):
            return {
                '.1': {
                    'mode': 1, 'dyn_limit': 10, 'static_limit': 5,
                    'auto_disable': 1, 'trap_mode': 2, 'trap_freq': 0,
                    'dyn_count': 3, 'static_count': 1,
                    'static_ip_count': 0,
                    'last_mac': '', 'static_macs': '1 aa:bb:cc:dd:ee:ff',
                    'static_ips': '',
                },
            }
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_port_security()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['mode'], 'mac-based')
        self.assertIn('1/1', result['ports'])
        port = result['ports']['1/1']
        self.assertTrue(port['enabled'])
        self.assertEqual(port['dynamic_limit'], 10)
        self.assertEqual(port['static_limit'], 5)
        self.assertEqual(port['dynamic_count'], 3)
        self.assertEqual(port['static_count'], 1)
        self.assertTrue(port['auto_disable'])
        self.assertFalse(port['violation_trap_mode'])
        self.assertEqual(len(port['static_macs']), 1)

    def test_get_port_security_disabled(self):
        """get_port_security() with global disabled."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentGlobalPortSecurityMode: 2,
                OID_hm2AgentPortSecurityOperationMode: 1,
            }
        async def mock_walk(columns, engine=None):
            return {}
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_port_security()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['ports'], {})

    def test_get_port_security_ip_mode(self):
        """get_port_security() with ip-based mode."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentGlobalPortSecurityMode: 1,
                OID_hm2AgentPortSecurityOperationMode: 2,
            }
        async def mock_walk(columns, engine=None):
            return {}
        async def mock_ifmap(engine=None):
            return {}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_port_security()
        self.assertEqual(result['mode'], 'ip-based')

    def test_get_port_security_filter_interface(self):
        """get_port_security(interface='1/2') filters to that port."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentGlobalPortSecurityMode: 1,
                OID_hm2AgentPortSecurityOperationMode: 1,
            }
        async def mock_walk(columns, engine=None):
            return {
                '.1': {
                    'mode': 2, 'dyn_limit': 600, 'static_limit': 64,
                    'auto_disable': 1, 'trap_mode': 2, 'trap_freq': 0,
                    'dyn_count': 0, 'static_count': 0,
                    'static_ip_count': 0, 'last_mac': '',
                    'static_macs': '', 'static_ips': '',
                },
                '.2': {
                    'mode': 1, 'dyn_limit': 200, 'static_limit': 32,
                    'auto_disable': 1, 'trap_mode': 2, 'trap_freq': 0,
                    'dyn_count': 0, 'static_count': 0,
                    'static_ip_count': 0, 'last_mac': '',
                    'static_macs': '', 'static_ips': '',
                },
            }
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_port_security(interface='1/2')
        self.assertEqual(list(result['ports'].keys()), ['1/2'])
        self.assertTrue(result['ports']['1/2']['enabled'])

    def test_get_port_security_skips_cpu_vlan(self):
        """get_port_security() skips cpu/vlan pseudo-interfaces."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentGlobalPortSecurityMode: 1,
                OID_hm2AgentPortSecurityOperationMode: 1,
            }
        async def mock_walk(columns, engine=None):
            return {
                '.1': {
                    'mode': 2, 'dyn_limit': 600, 'static_limit': 64,
                    'auto_disable': 1, 'trap_mode': 2, 'trap_freq': 0,
                    'dyn_count': 0, 'static_count': 0,
                    'static_ip_count': 0, 'last_mac': '',
                    'static_macs': '', 'static_ips': '',
                },
                '.100': {
                    'mode': 2, 'dyn_limit': 600, 'static_limit': 64,
                    'auto_disable': 1, 'trap_mode': 2, 'trap_freq': 0,
                    'dyn_count': 0, 'static_count': 0,
                    'static_ip_count': 0, 'last_mac': '',
                    'static_macs': '', 'static_ips': '',
                },
            }
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '100': 'cpu0'}
        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap):
            result = self.snmp.get_port_security()
        self.assertIn('1/1', result['ports'])
        self.assertNotIn('cpu0', result['ports'])

    # --- set_port_security ---

    def test_set_port_security_global_enable(self):
        """set_port_security(enabled=True) sets global scalar."""
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_set_oids', side_effect=mock_set) as m:
            self.snmp.set_port_security(enabled=True, mode='ip-based')
        self.assertEqual(m.call_count, 1)
        args = m.call_args[0]
        oids_set = [a[0] for a in args]
        self.assertTrue(any(OID_hm2AgentGlobalPortSecurityMode in o
                            for o in oids_set))
        self.assertTrue(any(OID_hm2AgentPortSecurityOperationMode in o
                            for o in oids_set))

    def test_set_port_security_invalid_mode(self):
        """set_port_security(mode='invalid') raises ValueError."""
        with self.assertRaises(ValueError):
            self.snmp.set_port_security(mode='invalid')

    def test_set_port_security_per_port(self):
        """set_port_security('1/1', dynamic_limit=10) per-port."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_port_security('1/1', dynamic_limit=10)
        self.assertEqual(m.call_count, 1)
        oid_str = m.call_args[0][0][0]
        self.assertIn(OID_hm2AgentPortSecurityDynamicLimit, oid_str)
        self.assertIn('.1', oid_str)  # ifIndex 1

    def test_set_port_security_unknown_interface(self):
        """set_port_security with unknown interface raises ValueError."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_port_security('9/9', enabled=True)

    # --- add_port_security ---

    def test_add_port_security_mac(self):
        """add_port_security sends OctetString with 'VLAN MAC'."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.add_port_security('1/1', vlan=1,
                                        mac='aa:bb:cc:dd:ee:ff')
        self.assertEqual(m.call_count, 1)
        oid_str = m.call_args[0][0][0]
        self.assertIn(OID_hm2AgentPortSecurityMACAddressAdd, oid_str)
        val = m.call_args[0][0][1]
        self.assertEqual(bytes(val), b'1 aa:bb:cc:dd:ee:ff')

    def test_add_port_security_ip(self):
        """add_port_security with IP entry."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.add_port_security('1/1', vlan=5, ip='10.0.0.1')
        oid_str = m.call_args[0][0][0]
        self.assertIn(OID_hm2AgentPortSecurityIPAddressAdd, oid_str)
        val = m.call_args[0][0][1]
        self.assertEqual(bytes(val), b'5 10.0.0.1')

    def test_add_port_security_bulk(self):
        """Bulk add sends one _set_oids per entry."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.add_port_security('1/1', entries=[
                {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'},
                {'vlan': 2, 'mac': '11:22:33:44:55:66'},
            ])
        self.assertEqual(m.call_count, 2)

    def test_add_port_security_no_args(self):
        """add_port_security with no mac/ip/entries raises ValueError."""
        with self.assertRaises(ValueError):
            self.snmp.add_port_security('1/1')

    def test_add_port_security_unknown_interface(self):
        """add_port_security with unknown interface raises ValueError."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.add_port_security('9/9', vlan=1,
                                            mac='aa:bb:cc:dd:ee:ff')

    # --- delete_port_security ---

    def test_delete_port_security_mac(self):
        """delete_port_security sends MACAddressRemove OID."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.delete_port_security('1/1', vlan=1,
                                           mac='aa:bb:cc:dd:ee:ff')
        oid_str = m.call_args[0][0][0]
        self.assertIn(OID_hm2AgentPortSecurityMACAddressRemove, oid_str)

    def test_delete_port_security_ip(self):
        """delete_port_security sends IPAddressRemove OID."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.delete_port_security('1/1', vlan=1,
                                           ip='10.0.0.1')
        oid_str = m.call_args[0][0][0]
        self.assertIn(OID_hm2AgentPortSecurityIPAddressRemove, oid_str)

    def test_delete_port_security_no_args(self):
        """delete_port_security with no mac/ip/entries raises ValueError."""
        with self.assertRaises(ValueError):
            self.snmp.delete_port_security('1/1')


class TestSNMPDhcpSnooping(unittest.TestCase):
    """Tests for get_dhcp_snooping / set_dhcp_snooping via SNMP."""

    def setUp(self):
        self.snmp = SNMPHIOS.__new__(SNMPHIOS)
        self.snmp._target = None
        self.snmp._auth = None
        self.snmp._context = None

    def test_get_dhcp_snooping_all(self):
        """get_dhcp_snooping() returns global + vlans + ports."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentDhcpSnoopingAdminMode: 1,
                OID_hm2AgentDhcpSnoopingVerifyMac: 2,
            }

        async def mock_walk(columns, engine=None):
            # Determine table by checking columns
            if 'trust' in columns:
                # Per-port table
                return {
                    '.1': {
                        'trust': 1, 'log': 2, 'rate_limit': 15,
                        'burst_interval': 1, 'auto_disable': 1,
                    },
                    '.2': {
                        'trust': 2, 'log': 1, 'rate_limit': -1,
                        'burst_interval': 5, 'auto_disable': 2,
                    },
                }
            else:
                # VLAN table (suffix IS the VID)
                return {
                    '.1': {'enable': 1},
                    '.100': {'enable': 2},
                }

        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}

        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_dhcp_snooping()

        self.assertTrue(result['enabled'])
        self.assertFalse(result['verify_mac'])
        self.assertEqual(len(result['vlans']), 2)
        self.assertTrue(result['vlans'][1]['enabled'])
        self.assertFalse(result['vlans'][100]['enabled'])
        self.assertEqual(len(result['ports']), 2)
        p1 = result['ports']['1/1']
        self.assertTrue(p1['trusted'])
        self.assertFalse(p1['log'])
        self.assertEqual(p1['rate_limit'], 15)
        self.assertTrue(p1['auto_disable'])
        p2 = result['ports']['1/2']
        self.assertFalse(p2['trusted'])
        self.assertTrue(p2['log'])
        self.assertEqual(p2['rate_limit'], -1)
        self.assertFalse(p2['auto_disable'])

    def test_get_dhcp_snooping_single_interface(self):
        """get_dhcp_snooping('1/1') filters to one port."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentDhcpSnoopingAdminMode: 2,
                OID_hm2AgentDhcpSnoopingVerifyMac: 2,
            }

        async def mock_walk(columns, engine=None):
            if 'trust' in columns:
                return {
                    '.1': {'trust': 1, 'log': 2, 'rate_limit': -1,
                           'burst_interval': 1, 'auto_disable': 1},
                    '.2': {'trust': 2, 'log': 2, 'rate_limit': -1,
                           'burst_interval': 1, 'auto_disable': 1},
                }
            return {}

        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}

        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_dhcp_snooping('1/1')

        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_get_dhcp_snooping_skips_cpu_vlan(self):
        """CPU and VLAN interfaces are excluded."""
        async def mock_scalar(*oids):
            return {OID_hm2AgentDhcpSnoopingAdminMode: 2,
                    OID_hm2AgentDhcpSnoopingVerifyMac: 2}

        async def mock_walk(columns, engine=None):
            if 'trust' in columns:
                return {
                    '.100': {'trust': 2, 'log': 2, 'rate_limit': -1,
                             'burst_interval': 1, 'auto_disable': 1},
                    '.200': {'trust': 2, 'log': 2, 'rate_limit': -1,
                             'burst_interval': 1, 'auto_disable': 1},
                }
            return {}

        async def mock_ifmap(engine=None):
            return {'100': 'cpu0', '200': 'vlan1'}

        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_dhcp_snooping()

        self.assertEqual(len(result['ports']), 0)

    def test_set_dhcp_snooping_global(self):
        """set_dhcp_snooping(enabled=True) sets global admin mode."""
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_dhcp_snooping(enabled=True)
        oid, val = m.call_args[0][0]
        self.assertIn(OID_hm2AgentDhcpSnoopingAdminMode, oid)
        self.assertEqual(int(val), 1)

    def test_set_dhcp_snooping_verify_mac(self):
        """set_dhcp_snooping(verify_mac=False) disables MAC verify."""
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_dhcp_snooping(verify_mac=False)
        oid, val = m.call_args[0][0]
        self.assertIn(OID_hm2AgentDhcpSnoopingVerifyMac, oid)
        self.assertEqual(int(val), 2)

    def test_set_dhcp_snooping_vlan(self):
        """set_dhcp_snooping(vlan=1, vlan_enabled=True)."""
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_dhcp_snooping(vlan=1, vlan_enabled=True)
        oid, val = m.call_args[0][0]
        self.assertIn(OID_hm2AgentDhcpSnoopingVlanEnable, oid)
        self.assertTrue(oid.endswith('.1'))
        self.assertEqual(int(val), 1)

    def test_set_dhcp_snooping_port(self):
        """set_dhcp_snooping('1/1', trusted=True) sets per-port."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_dhcp_snooping('1/1', trusted=True,
                                        rate_limit=15)
        calls = m.call_args[0]
        oids_set = [c[0] for c in calls]
        self.assertTrue(any(OID_hm2AgentDhcpSnoopingIfTrustEnable in o
                            for o in oids_set))
        self.assertTrue(any(OID_hm2AgentDhcpSnoopingIfRateLimit in o
                            for o in oids_set))

    def test_set_dhcp_snooping_multi_port(self):
        """set_dhcp_snooping(['1/1', '1/2'], trusted=True)."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_dhcp_snooping(['1/1', '1/2'], trusted=True)
        # Should set trust OID for both ports
        calls = m.call_args[0]
        trust_oids = [c[0] for c in calls
                      if OID_hm2AgentDhcpSnoopingIfTrustEnable in c[0]]
        self.assertEqual(len(trust_oids), 2)

    def test_set_dhcp_snooping_unknown_interface(self):
        """set_dhcp_snooping('9/9', ...) raises ValueError."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_dhcp_snooping('9/9', trusted=True)


class TestSNMPArpInspection(unittest.TestCase):
    """Tests for get_arp_inspection / set_arp_inspection via SNMP."""

    def setUp(self):
        self.snmp = SNMPHIOS.__new__(SNMPHIOS)
        self.snmp._target = None
        self.snmp._auth = None
        self.snmp._context = None

    def test_get_arp_inspection_all(self):
        """get_arp_inspection() returns globals + vlans + ports."""
        async def mock_scalar(*oids):
            return {
                OID_hm2AgentDaiSrcMacValidate: 1,
                OID_hm2AgentDaiDstMacValidate: 2,
                OID_hm2AgentDaiIPValidate: 1,
            }

        async def mock_walk(columns, engine=None):
            if 'trust' in columns:
                return {
                    '.1': {'trust': 1, 'rate_limit': 15,
                           'burst_interval': 1, 'auto_disable': 1},
                    '.2': {'trust': 2, 'rate_limit': -1,
                           'burst_interval': 5, 'auto_disable': 2},
                }
            else:
                return {
                    '.1': {'enable': 1, 'log': 2, 'acl_name': '',
                           'acl_static': 2, 'binding_check': 1},
                    '.100': {'enable': 2, 'log': 1, 'acl_name': '',
                             'acl_static': 2, 'binding_check': 2},
                }

        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}

        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_arp_inspection()

        self.assertTrue(result['validate_src_mac'])
        self.assertFalse(result['validate_dst_mac'])
        self.assertTrue(result['validate_ip'])
        self.assertEqual(len(result['vlans']), 2)
        self.assertTrue(result['vlans'][1]['enabled'])
        self.assertTrue(result['vlans'][1]['binding_check'])
        self.assertFalse(result['vlans'][100]['enabled'])
        self.assertEqual(len(result['ports']), 2)
        self.assertTrue(result['ports']['1/1']['trusted'])
        self.assertFalse(result['ports']['1/2']['trusted'])

    def test_get_arp_inspection_single_interface(self):
        """get_arp_inspection('1/1') filters to one port."""
        async def mock_scalar(*oids):
            return {OID_hm2AgentDaiSrcMacValidate: 2,
                    OID_hm2AgentDaiDstMacValidate: 2,
                    OID_hm2AgentDaiIPValidate: 2}

        async def mock_walk(columns, engine=None):
            if 'trust' in columns:
                return {
                    '.1': {'trust': 1, 'rate_limit': -1,
                           'burst_interval': 1, 'auto_disable': 1},
                    '.2': {'trust': 2, 'rate_limit': -1,
                           'burst_interval': 1, 'auto_disable': 1},
                }
            return {}

        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}

        with patch.object(self.snmp, '_get_scalar',
                          side_effect=mock_scalar), \
             patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_arp_inspection('1/1')

        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_set_arp_inspection_global(self):
        """set_arp_inspection(validate_src_mac=True)."""
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_arp_inspection(validate_src_mac=True)
        oid, val = m.call_args[0][0]
        self.assertIn(OID_hm2AgentDaiSrcMacValidate, oid)
        self.assertEqual(int(val), 1)

    def test_set_arp_inspection_vlan(self):
        """set_arp_inspection(vlan=1, vlan_enabled=True)."""
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_arp_inspection(vlan=1, vlan_enabled=True)
        oid, val = m.call_args[0][0]
        self.assertIn(OID_hm2AgentDaiVlanDynArpInspEnable, oid)
        self.assertEqual(int(val), 1)

    def test_set_arp_inspection_port(self):
        """set_arp_inspection('1/1', trusted=True)."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        async def mock_set(*args):
            pass
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids',
                          side_effect=mock_set) as m:
            self.snmp.set_arp_inspection('1/1', trusted=True,
                                         rate_limit=15)
        calls = m.call_args[0]
        oids_set = [c[0] for c in calls]
        self.assertTrue(any(OID_hm2AgentDaiIfTrustEnable in o
                            for o in oids_set))
        self.assertTrue(any(OID_hm2AgentDaiIfRateLimit in o
                            for o in oids_set))

    def test_set_arp_inspection_unknown_interface(self):
        """set_arp_inspection('9/9', ...) raises ValueError."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}
        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_arp_inspection('9/9', trusted=True)


class TestSNMPIpSourceGuard(unittest.TestCase):
    """Tests for get_ip_source_guard / set_ip_source_guard via SNMP."""

    def setUp(self):
        self.snmp = SNMPHIOS.__new__(SNMPHIOS)
        self.snmp._target = None
        self.snmp._auth = None
        self.snmp._context = None

    def test_get_ip_source_guard_all(self):
        """get_ip_source_guard() returns ports + bindings."""
        call_count = [0]

        async def mock_walk(columns, engine=None):
            call_count[0] += 1
            if 'verify_source' in columns:
                return {
                    '.1': {'verify_source': 1, 'port_security': 1},
                    '.2': {'verify_source': 2, 'port_security': 2},
                }
            else:
                return {}

        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}

        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_ip_source_guard()

        self.assertEqual(len(result['ports']), 2)
        self.assertTrue(result['ports']['1/1']['verify_source'])
        self.assertTrue(result['ports']['1/1']['port_security'])
        self.assertFalse(result['ports']['1/2']['verify_source'])
        self.assertEqual(result['static_bindings'], [])
        self.assertEqual(result['dynamic_bindings'], [])

    def test_get_ip_source_guard_single_interface(self):
        """get_ip_source_guard('1/1') filters to one port."""
        async def mock_walk(columns, engine=None):
            if 'verify_source' in columns:
                return {
                    '.1': {'verify_source': 1, 'port_security': 2},
                    '.2': {'verify_source': 2, 'port_security': 2},
                }
            return {}

        async def mock_ifmap(engine=None):
            return {'1': '1/1', '2': '1/2'}

        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_ip_source_guard('1/1')

        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_get_ip_source_guard_skips_cpu(self):
        """CPU interfaces excluded."""
        async def mock_walk(columns, engine=None):
            if 'verify_source' in columns:
                return {
                    '.100': {'verify_source': 2, 'port_security': 2},
                }
            return {}

        async def mock_ifmap(engine=None):
            return {'100': 'cpu0'}

        with patch.object(self.snmp, '_walk_columns',
                          side_effect=mock_walk), \
             patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            result = self.snmp.get_ip_source_guard()

        self.assertEqual(len(result['ports']), 0)

    def test_set_ip_source_guard_enable(self):
        """set_ip_source_guard('1/1', verify_source=True)."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}

        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap), \
             patch.object(self.snmp, '_set_oids') as m:
            m.return_value = None
            self.snmp.set_ip_source_guard('1/1', verify_source=True)
            oid, val = m.call_args[0][0]
            self.assertIn('5.1.1', oid)  # VerifySource column
            self.assertEqual(int(val), 1)

    def test_set_ip_source_guard_unknown_interface(self):
        """set_ip_source_guard('9/9', ...) raises ValueError."""
        async def mock_ifmap(engine=None):
            return {'1': '1/1'}

        with patch.object(self.snmp, '_build_ifindex_map',
                          side_effect=mock_ifmap):
            with self.assertRaises(ValueError):
                self.snmp.set_ip_source_guard('9/9', verify_source=True)

    def test_set_ip_source_guard_no_interface(self):
        """set_ip_source_guard(interface=None) is no-op."""
        self.snmp.set_ip_source_guard()


if __name__ == '__main__':
    unittest.main()
