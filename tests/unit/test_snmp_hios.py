"""Unit tests for SNMPHIOS — mock _get_scalar and _walk to test parsing logic."""

import unittest
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio

from napalm_hios.snmp_hios import (
    SNMPHIOS, _format_mac, _mask_to_prefix, _parse_sysDescr,
    _parse_fw_version, _snmp_str, _snmp_int, _snmp_ip,
    _decode_capabilities, _decode_portlist,
    _format_mrp_domain_id, _decode_implied_string,
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
    OID_hm2HiDiscOper, OID_hm2HiDiscMode, OID_hm2HiDiscBlinking,
    OID_hm2HiDiscProtocol, OID_hm2HiDiscRelay,
    OID_lldpXdot3RemPortAutoNegSupported, OID_lldpXdot3RemPortAutoNegEnabled,
    OID_lldpXdot3RemPortOperMauType,
    OID_lldpXdot3RemLinkAggStatus, OID_lldpXdot3RemLinkAggPortId,
    OID_lldpXdot1RemPortVlanId, OID_lldpXdot1RemVlanId,
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
                '97.100.109.105.110': {'role': 15, 'status': 1},
                # guest: g=103 u=117 e=101 s=115 t=116
                '103.117.101.115.116': {'role': 1, 'status': 1},
                # inactive user 'test' — should be filtered
                '116.101.115.116': {'role': 15, 'status': 6},
            }

        with patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns):
            users = self.snmp.get_users()

        self.assertIn('admin', users)
        self.assertEqual(users['admin']['level'], 15)
        self.assertEqual(users['admin']['password'], '')
        self.assertEqual(users['admin']['sshkeys'], [])
        self.assertIn('guest', users)
        self.assertEqual(users['guest']['level'], 1)
        self.assertNotIn('test', users)  # inactive user filtered

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
    # Write operations — set_hidiscovery, set_mrp, delete_mrp
    # ------------------------------------------------------------------

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

        # Mock _get_interfaces_async for safety check (ports down)
        async def mock_ifaces():
            return {
                '1/3': {'is_up': False, 'is_enabled': True},
                '1/4': {'is_up': False, 'is_enabled': True},
            }
        # Mock _get_mrp_async for return value
        async def mock_mrp():
            return {'configured': True, 'mode': 'client'}

        with patch.object(self.snmp, '_set_oids', side_effect=mock_set_oids), \
             patch.object(self.snmp, '_walk_columns', side_effect=mock_walk_columns), \
             patch.object(self.snmp, '_build_ifindex_map', side_effect=mock_ifmap), \
             patch.object(self.snmp, '_get_interfaces_async', side_effect=mock_ifaces), \
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

    def test_set_mrp_safety_rejects_linkup(self):
        """Refuses to configure MRP on link-up ports."""
        async def mock_ifaces():
            return {
                '1/3': {'is_up': True, 'is_enabled': True},
                '1/4': {'is_up': False, 'is_enabled': True},
            }
        with patch.object(self.snmp, '_get_interfaces_async', side_effect=mock_ifaces):
            with self.assertRaises(ValueError) as ctx:
                self.snmp.set_mrp(
                    operation='enable', mode='client',
                    port_primary='1/3', port_secondary='1/4',
                )
            self.assertIn('link-up', str(ctx.exception))

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


if __name__ == '__main__':
    unittest.main()
