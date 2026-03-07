"""Tests for SSH parsers using real HiOS CLI output fixtures.

These test the parsing logic directly without needing a live device.
Fixtures were captured from a GRS1042 running HiOS-3A-09.4.04.
"""
import os
import unittest
from napalm_hios.ssh_hios import SSHHIOS
from napalm_hios.utils import parse_dot_keys, parse_table, parse_multiline_table

FIXTURES = os.path.join(os.path.dirname(__file__), '..', 'fixtures')


def load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


class TestParseDotKeys(unittest.TestCase):
    def test_system_info(self):
        data = parse_dot_keys(load_fixture('show_system_info.txt'))
        self.assertEqual(data['System name'], 'GRS1042-CORE')
        self.assertEqual(data['System location'], 'Kitchen')
        self.assertEqual(data['Serial number'], '942135999000101022')
        self.assertEqual(data['Device hardware description'], 'GRS1042-6T6ZTHH00V9HHSE3AMR')
        self.assertIn('HiOS-3A-09.4.04', data['Firmware software release (RAM)'])

    def test_temperature(self):
        data = parse_dot_keys(load_fixture('show_system_temperature_limits.txt'))
        self.assertEqual(data['Current temperature'], '50 C')
        self.assertEqual(data['Temperature upper limit'], '70 C')
        self.assertEqual(data['Temperature lower limit'], '0 C')

    def test_resources(self):
        data = parse_dot_keys(load_fixture('show_system_resources.txt'))
        self.assertEqual(data['CPU utilization'], '26%')
        self.assertEqual(data['Allocated RAM'], '358548 kBytes')
        self.assertEqual(data['Free RAM'], '148964 kBytes')


class TestParseTable(unittest.TestCase):
    def test_counters(self):
        rows = parse_table(load_fixture('show_interface_counters.txt'), min_fields=1)
        # Should have raw rows — 3 lines per interface
        self.assertGreater(len(rows), 0)
        # First row should be interface 1/1's RX data
        self.assertEqual(rows[0][0], '1/1')

    def test_arp_table(self):
        rows = parse_table(load_fixture('show_ip_arp_table.txt'), min_fields=6)
        self.assertGreater(len(rows), 0)
        # First entry should be vlan/1 192.168.1.4
        self.assertEqual(rows[0][0], 'vlan/1')
        self.assertEqual(rows[0][1], '192.168.1.4')


class TestInterfaceListParser(unittest.TestCase):
    """Test that _parse_interface_list correctly handles 2-line show port."""

    def setUp(self):
        # We only need the parser, not a real connection
        self.ssh = SSHHIOS.__new__(SSHHIOS)

    def test_no_dashes_in_list(self):
        output = load_fixture('show_port.txt')
        interfaces = self.ssh._parse_interface_list(output)
        self.assertNotIn('-', interfaces)
        self.assertNotIn('--', interfaces)
        self.assertNotIn('---------', interfaces)

    def test_all_interfaces_present(self):
        output = load_fixture('show_port.txt')
        interfaces = self.ssh._parse_interface_list(output)
        # GRS1042: 12 + 8 + 8 physical + 6 VLANs = 34
        self.assertEqual(len(interfaces), 34)
        self.assertIn('1/1', interfaces)
        self.assertIn('3/8', interfaces)
        self.assertIn('vlan/1', interfaces)
        self.assertIn('vlan/99', interfaces)

    def test_no_duplicates(self):
        output = load_fixture('show_port.txt')
        interfaces = self.ssh._parse_interface_list(output)
        self.assertEqual(len(interfaces), len(set(interfaces)))


class TestShowPortParser(unittest.TestCase):
    """Test parse_show_port with real 2-line format."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)

    def test_parses_all_interfaces(self):
        output = load_fixture('show_port.txt')
        interfaces = self.ssh.parse_show_port(output)
        self.assertEqual(len(interfaces), 34)

    def test_link_status(self):
        output = load_fixture('show_port.txt')
        interfaces = self.ssh.parse_show_port(output)
        self.assertTrue(interfaces['1/1']['is_up'])
        self.assertFalse(interfaces['1/2']['is_up'])
        self.assertTrue(interfaces['vlan/1']['is_up'])

    def test_speed_parsing(self):
        output = load_fixture('show_port.txt')
        interfaces = self.ssh.parse_show_port(output)
        # 1/1 has phys mode "2500 full" and phys stat "2500 full"
        self.assertEqual(interfaces['1/1']['speed'], 2500000000)
        # 2/7 has auto mode but "100 full" phys stat
        self.assertEqual(interfaces['2/7']['speed'], 100000000)

    def test_speed_10g(self):
        """10G format (e.g. GRS106) must be handled by _parse_speed."""
        # Simulated show port line with 10G speed format
        output = (
            "Interface   Role   Admin mode  Phys. mode   Cross  Phys. stat  Link  STP state\n"
            "Name\n"
            "----------  -----  ----------  -----------  -----  ----------  ----  ----------\n"
            " 1/1        none   Enabled     10G full     mdi    10G full    up    forwarding\n"
            "            -\n"
            " 1/2        none   Enabled     2500 full    mdi    2500 full   up    forwarding\n"
            "            -\n"
            " 1/3        none   Enabled     auto         mdix   1000 full   up    forwarding\n"
            "            -\n"
        )
        interfaces = self.ssh.parse_show_port(output)
        self.assertEqual(interfaces['1/1']['speed'], 10000000000)
        self.assertEqual(interfaces['1/2']['speed'], 2500000000)
        self.assertEqual(interfaces['1/3']['speed'], 1000000000)

    def test_mac_address_populated(self):
        """Base MAC should be passed through to all interfaces."""
        output = load_fixture('show_port.txt')
        mac = 'EC:74:BA:35:75:70'
        interfaces = self.ssh.parse_show_port(output, base_mac=mac)
        for name, data in interfaces.items():
            self.assertEqual(data['mac_address'], mac, f'{name} missing mac_address')

    def test_no_dash_interfaces(self):
        """Continuation lines should not create spurious interfaces."""
        output = load_fixture('show_port.txt')
        interfaces = self.ssh.parse_show_port(output)
        for name in interfaces:
            self.assertIn('/', name, f"Interface name '{name}' missing /")
            self.assertNotEqual(name, '-')


class TestArpParser(unittest.TestCase):
    """Test ARP table parsing with real L3 output."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)

    def test_parse_ip_arp_table(self):
        output = load_fixture('show_ip_arp_table.txt')
        entries = self.ssh._parse_show_ip_arp_table(output)
        self.assertEqual(len(entries), 29)

    def test_first_entry(self):
        output = load_fixture('show_ip_arp_table.txt')
        entries = self.ssh._parse_show_ip_arp_table(output)
        first = entries[0]
        self.assertEqual(first['interface'], 'vlan/1')
        self.assertEqual(first['ip'], '192.168.1.4')
        self.assertEqual(first['mac'], '64:60:38:3f:4a:a1')
        self.assertGreater(first['age'], 0)

    def test_all_have_required_keys(self):
        output = load_fixture('show_ip_arp_table.txt')
        entries = self.ssh._parse_show_ip_arp_table(output)
        for entry in entries:
            self.assertIn('interface', entry)
            self.assertIn('ip', entry)
            self.assertIn('mac', entry)
            self.assertIn('age', entry)
            # MAC should be valid format
            self.assertRegex(entry['mac'], r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')


class TestLldpParser(unittest.TestCase):
    """Test LLDP parsing with real output."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None  # satisfy hasattr checks
        self.output = load_fixture('show_lldp_remote_data.txt')

    def _call_parser(self, method_name):
        """Call an LLDP parser by injecting the fixture via cli mock."""
        original_cli = getattr(self.ssh, 'cli', None)
        self.ssh.cli = lambda cmd: {'show lldp remote-data': self.output}
        try:
            return getattr(self.ssh, method_name)()
        finally:
            if original_cli:
                self.ssh.cli = original_cli

    def test_basic_neighbors_count(self):
        neighbors = self._call_parser('get_lldp_neighbors')
        # All 7 entries should appear — chassis_id fallback for FDB-only neighbors
        self.assertEqual(len(neighbors), 7)
        self.assertIn('1/7', neighbors)
        self.assertIn('1/1', neighbors)
        self.assertIn('3/3', neighbors)
        self.assertIn('1/3', neighbors)
        self.assertIn('2/7', neighbors)
        self.assertIn('1/8', neighbors)
        self.assertIn('1/6', neighbors)

    def test_basic_neighbors_fallback(self):
        """Chassis_id used as hostname when system_name is missing."""
        neighbors = self._call_parser('get_lldp_neighbors')
        # 1/3 has no system name — should fall back to chassis_id
        entry = neighbors['1/3'][0]
        self.assertEqual(entry['hostname'], '90:EC:77:1B:6C:2B')
        self.assertEqual(entry['port'], 'FDB')
        # 1/8 has no system name — chassis_id fallback, port_id fallback
        entry = neighbors['1/8'][0]
        self.assertEqual(entry['hostname'], 'D8:CB:8A:C0:37:C8')

    def test_detail_gets_all_entries(self):
        detail = self._call_parser('get_lldp_neighbors_detail')
        # All 7 entries should appear in detail (including chassis-id-only ones)
        self.assertEqual(len(detail), 7)
        self.assertIn('1/3', detail)
        self.assertIn('1/8', detail)
        self.assertIn('2/7', detail)
        self.assertIn('1/6', detail)

    def test_detail_parent_interface_set(self):
        detail = self._call_parser('get_lldp_neighbors_detail')
        for port, entries in detail.items():
            for entry in entries:
                self.assertEqual(entry['parent_interface'], port)

    def test_detail_management_address_first(self):
        """First IPv4 management address stored, not last."""
        detail = self._call_parser('get_lldp_neighbors_detail')
        # GRS1042-CORE has 5 IPv4 mgmt addresses — first should be stored
        grs = detail['1/6'][0]
        self.assertEqual(grs['remote_management_address'], '192.168.1.254')

    def test_extended_management_addresses(self):
        extended = self._call_parser('get_lldp_neighbors_detail_extended')
        # BRS50-Office has both IPv4 and IPv6 management
        office = extended['1/1'][0]
        self.assertEqual(office['remote_management_ipv4'], '192.168.1.4')
        self.assertEqual(office['remote_management_ipv6'], 'fe80::6660:38ff:fe3f:4aa1')
        self.assertEqual(office['management_addresses'], ['192.168.1.4', 'fe80::6660:38ff:fe3f:4aa1'])
        # GRS1042-CORE has 5 IPv4 + 1 IPv6 — all collected
        grs = extended['1/6'][0]
        self.assertEqual(grs['remote_management_ipv4'], '192.168.1.254')
        self.assertEqual(len(grs['management_addresses']), 6)
        self.assertEqual(grs['management_addresses'][0], '192.168.1.254')
        self.assertEqual(grs['management_addresses'][4], '192.168.99.254')
        self.assertEqual(grs['management_addresses'][5], 'fe80::ee74:baff:fe35:7570')

    def test_capabilities_parsed(self):
        """System capabilities should be empty — HiOS CLI doesn't expose them.

        The 'autoneg. cap. bits' field contains 802.3 MAU types (10baseT, etc.),
        NOT LLDP system capabilities (bridge, router, etc.).
        """
        extended = self._call_parser('get_lldp_neighbors_detail_extended')
        lounge = extended['1/7'][0]
        self.assertEqual(lounge['remote_system_capab'], [])
        entry = extended['1/8'][0]
        self.assertEqual(entry['remote_system_capab'], [])

    def test_extended_vlan_membership(self):
        extended = self._call_parser('get_lldp_neighbors_detail_extended')
        lounge = extended['1/7'][0]
        self.assertEqual(lounge['vlan_membership'], [1, 2, 3, 4, 5, 6, 7])
        # eero has <n/a> VLAN membership
        eero = extended['3/3'][0]
        self.assertEqual(eero['vlan_membership'], [])


class TestCountersParser(unittest.TestCase):
    """Test interface counters parsing."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None

    def test_parse_counters(self):
        output = load_fixture('show_interface_counters.txt')
        self.ssh.cli = lambda cmd: {'show interface counters': output}
        counters = self.ssh.get_interfaces_counters()
        self.assertIn('1/1', counters)
        self.assertIn('2/7', counters)
        self.assertEqual(counters['1/1']['rx_unicast_packets'], 3257252743)
        self.assertEqual(counters['1/1']['tx_unicast_packets'], 1302371024)
        # Down interface should have zeros
        self.assertEqual(counters['1/2']['rx_unicast_packets'], 0)


class TestEnvironmentParser(unittest.TestCase):
    """Test environment parsing with shared parsers."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None
        fan_out = "Error: Invalid command 'fan'"
        temp_out = load_fixture('show_system_temperature_limits.txt')
        sysinfo = load_fixture('show_system_info.txt')
        resources = load_fixture('show_system_resources.txt')

        def mock_cli(cmd):
            if isinstance(cmd, list):
                cmd = cmd[0]
            mapping = {
                'show fan': fan_out,
                'show system temperature limits': temp_out,
                'show system info': sysinfo,
                'show system resources': resources,
            }
            return {cmd: mapping.get(cmd, '')}

        self.ssh.cli = mock_cli

    def test_fanless_device(self):
        env = self.ssh.get_environment()
        # Should be empty dict, not {"Error": ...}
        self.assertEqual(env['fans'], {})

    def test_temperature_nested(self):
        env = self.ssh.get_environment()
        self.assertIn('chassis', env['temperature'])
        self.assertEqual(env['temperature']['chassis']['temperature'], 50.0)
        self.assertFalse(env['temperature']['chassis']['is_alert'])

    def test_power_supply_named(self):
        env = self.ssh.get_environment()
        self.assertIn('Power Supply P1', env['power'])
        self.assertTrue(env['power']['Power Supply P1']['status'])
        self.assertIn('Power Supply P2', env['power'])
        self.assertFalse(env['power']['Power Supply P2']['status'])

    def test_cpu_napalm_format(self):
        env = self.ssh.get_environment()
        self.assertIn('0', env['cpu'])
        self.assertEqual(env['cpu']['0']['%usage'], 26.0)

    def test_memory_available_is_total(self):
        env = self.ssh.get_environment()
        self.assertEqual(env['memory']['available_ram'], 358548)
        self.assertEqual(env['memory']['used_ram'], 358548 - 148964)
        # available > used (was backwards before)
        self.assertGreater(env['memory']['available_ram'], env['memory']['used_ram'])


class TestFactsParser(unittest.TestCase):
    """Test get_facts parsing."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None
        sysinfo = load_fixture('show_system_info.txt')
        port = load_fixture('show_port.txt')
        lookup = {'show system info': sysinfo, 'show port': port}
        self.ssh.cli = lambda cmd: {cmd: lookup.get(cmd, '')}

    def test_facts_fields(self):
        facts = self.ssh.get_facts()
        self.assertEqual(facts['vendor'], 'Belden')
        self.assertEqual(facts['hostname'], 'GRS1042-CORE')
        self.assertEqual(facts['model'], 'GRS1042-6T6ZTHH00V9HHSE3AMR')
        self.assertEqual(facts['serial_number'], '942135999000101022')
        self.assertEqual(facts['os_version'], 'HiOS-3A-09.4.04')

    def test_uptime_parsed(self):
        facts = self.ssh.get_facts()
        # 43 days, 03:26:31
        expected = 43 * 86400 + 3 * 3600 + 26 * 60 + 31
        self.assertEqual(facts['uptime'], expected)

    def test_interface_list_clean(self):
        facts = self.ssh.get_facts()
        self.assertNotIn('-', facts['interface_list'])
        self.assertEqual(len(facts['interface_list']), 34)


class TestOpticsParser(unittest.TestCase):
    """Test SFP optics parsing — regex-based, not positional."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None
        sfp = load_fixture('show_sfp.txt')
        self.ssh.cli = lambda cmd: {cmd: sfp}

    def test_finds_all_sfps(self):
        optics = self.ssh.get_optics()
        self.assertEqual(len(optics), 2)
        self.assertIn('1/1', optics)
        self.assertIn('1/2', optics)

    def test_tx_rx_values(self):
        optics = self.ssh.get_optics()
        ch = optics['1/1']['physical_channels']['channel'][0]['state']
        self.assertAlmostEqual(ch['output_power']['instant'], -4.2)
        self.assertAlmostEqual(ch['input_power']['instant'], -4.4)

    def test_temp_column_not_confused_with_power(self):
        """Temperature 46/115 must not appear as a power reading."""
        optics = self.ssh.get_optics()
        for intf, data in optics.items():
            ch = data['physical_channels']['channel'][0]['state']
            # TX and RX should be negative dBm, not 46.0
            self.assertLess(ch['output_power']['instant'], 0)
            self.assertLess(ch['input_power']['instant'], 0)

    def test_napalm_structure(self):
        optics = self.ssh.get_optics()
        for intf, data in optics.items():
            self.assertIn('physical_channels', data)
            channels = data['physical_channels']['channel']
            self.assertEqual(len(channels), 1)
            state = channels[0]['state']
            for key in ['input_power', 'output_power', 'laser_bias_current']:
                self.assertIn(key, state)
                for stat in ['instant', 'avg', 'min', 'max']:
                    self.assertIn(stat, state[key])


class TestInterfacesIpL2Fallback(unittest.TestCase):
    """Test get_interfaces_ip L2 fallback to show network parms."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None

    def test_l2_returns_management_ip(self):
        """L2 switch returns management IP from show network parms."""
        net_parms = load_fixture('show_network_parms.txt')

        def mock_cli(cmd):
            if cmd == 'show ip interface':
                return {cmd: "Error: Invalid command 'interface'"}
            if cmd == 'show network parms':
                return {cmd: net_parms}
            return {cmd: ''}

        self.ssh.cli = mock_cli
        result = self.ssh.get_interfaces_ip()
        self.assertIn('vlan/1', result)
        self.assertEqual(result['vlan/1']['ipv4']['192.168.1.4']['prefix_length'], 24)

    def test_l2_no_ip_returns_empty(self):
        """L2 switch with 0.0.0.0 returns empty dict."""
        no_ip = "Local IP address............................0.0.0.0\nSubnetmask..................................0.0.0.0\nManagement VLAN ID..........................1\n"

        def mock_cli(cmd):
            if cmd == 'show ip interface':
                return {cmd: "Error: Invalid command 'interface'"}
            if cmd == 'show network parms':
                return {cmd: no_ip}
            return {cmd: ''}

        self.ssh.cli = mock_cli
        result = self.ssh.get_interfaces_ip()
        self.assertEqual(result, {})

    def test_l3_still_uses_show_ip_interface(self):
        """L3 switch ignores network parms, uses show ip interface."""
        ip_intf = load_fixture('show_ip_arp_table.txt')  # just need non-Error output
        # Simulate a minimal show ip interface
        ip_intf = (
            "Interface   IP Address       IP Mask\n"
            "----------  ---------------- ----------\n"
            "vlan/1      192.168.1.254    255.255.255.0\n"
        )

        def mock_cli(cmd):
            if cmd == 'show ip interface':
                return {cmd: ip_intf}
            return {cmd: ''}

        self.ssh.cli = mock_cli
        result = self.ssh.get_interfaces_ip()
        self.assertIn('vlan/1', result)
        self.assertEqual(result['vlan/1']['ipv4']['192.168.1.254']['prefix_length'], 24)


class TestHiDiscoveryParser(unittest.TestCase):
    """Test HiDiscovery getter."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None

    def test_get_hidiscovery_l3(self):
        """L3 switch with relay status."""
        fixture = load_fixture('show_network_hidiscovery.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_hidiscovery()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['mode'], 'read-only')
        self.assertFalse(result['blinking'])
        self.assertEqual(result['protocols'], ['v1', 'v2'])
        self.assertTrue(result['relay'])

    def test_get_hidiscovery_l2_no_relay(self):
        """L2 switch without relay status field."""
        fixture = (
            "HiDiscovery settings\n"
            "--------------------\n"
            "Operating status............................enabled\n"
            "Operating mode..............................read-write\n"
            "Blinking status.............................disabled\n"
            "Supported protocols.........................v1,v2\n"
        )
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_hidiscovery()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['mode'], 'read-write')
        self.assertNotIn('relay', result)

    def test_get_hidiscovery_disabled(self):
        """Disabled HiDiscovery."""
        fixture = (
            "HiDiscovery settings\n"
            "--------------------\n"
            "Operating status............................disabled\n"
            "Operating mode..............................read-only\n"
            "Blinking status.............................disabled\n"
            "Supported protocols.........................v1,v2\n"
        )
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_hidiscovery()
        self.assertFalse(result['enabled'])


class TestMRPParser(unittest.TestCase):
    """Test MRP getter/parser."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None

    def test_unconfigured(self):
        """No MRP domain returns configured=False."""
        fixture = load_fixture('show_mrp_unconfigured.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_mrp()
        self.assertFalse(result['configured'])
        self.assertEqual(len(result), 1)

    def test_configured_client(self):
        """Client mode returns all expected fields."""
        fixture = load_fixture('show_mrp_configured.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_mrp()
        self.assertTrue(result['configured'])
        self.assertEqual(result['operation'], 'enabled')
        self.assertEqual(result['mode'], 'client')
        self.assertEqual(result['port_primary'], '1/2')
        self.assertEqual(result['port_secondary'], '1/5')
        self.assertEqual(result['port_primary_state'], 'not connected')
        self.assertEqual(result['vlan'], 1)
        self.assertEqual(result['recovery_delay'], '200ms')
        self.assertEqual(result['recovery_delay_supported'], ['200ms', '500ms'])
        self.assertTrue(result['advanced_mode'])
        self.assertEqual(result['manager_priority'], 32768)
        self.assertFalse(result['fixed_backup'])
        self.assertFalse(result['fast_mrp'])
        self.assertEqual(result['ring_state'], 'undefined')
        self.assertFalse(result['redundancy'])
        self.assertTrue(result['blocked_support'])

    def test_manager_with_ring_state(self):
        """Manager mode shows ring state and open count."""
        fixture = load_fixture('show_mrp_manager.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_mrp()
        self.assertTrue(result['configured'])
        self.assertEqual(result['mode'], 'manager')
        self.assertEqual(result['recovery_delay'], '500ms')
        self.assertEqual(result['ring_state'], 'closed')
        self.assertTrue(result['redundancy'])
        self.assertEqual(result['ring_open_count'], 2)
        self.assertEqual(result['port_primary_state'], 'forwarding')
        self.assertEqual(result['port_secondary_state'], 'blocked')
        self.assertEqual(result['info'], 'no error')

class TestConfigStatus(unittest.TestCase):
    """Test config status getter."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None

    def test_synced(self):
        """All in sync — saved is True."""
        fixture = load_fixture('show_config_status_synced.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_config_status()
        self.assertTrue(result['saved'])
        self.assertEqual(result['nvm'], 'ok')
        self.assertEqual(result['aca'], 'ok')
        self.assertEqual(result['boot'], 'ok')

    def test_unsaved(self):
        """Running config differs from NVM — saved is False."""
        fixture = load_fixture('show_config_status_unsaved.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_config_status()
        self.assertFalse(result['saved'])
        self.assertEqual(result['nvm'], 'out of sync')
        self.assertEqual(result['aca'], 'absent')

    def test_busy_is_not_saved(self):
        """Busy NVM write counts as not saved."""
        fixture = (
            "Configuration storage sync state\n"
            "--------------------------------\n"
            "running-config to NVM.......................busy\n"
            "NVM to ACA..................................absent\n"
            "Boot parameters.............................ok\n"
        )
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_config_status()
        self.assertFalse(result['saved'])
        self.assertEqual(result['nvm'], 'busy')


class TestProfileParser(unittest.TestCase):
    """Test SSH config profile parser."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None

    def test_single_profile(self):
        """Parse single active profile from live GRS1042 output."""
        fixture = load_fixture('show_config_profiles_nvm.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_profiles('nvm')
        self.assertEqual(len(result), 1)
        p = result[0]
        self.assertEqual(p['index'], 1)
        self.assertEqual(p['name'], 'config')
        self.assertTrue(p['active'])
        self.assertEqual(p['datetime'], '2026-02-13 13:25:16')
        self.assertEqual(p['firmware'], '09.4.4')
        self.assertEqual(p['fingerprint'], '9244C58FEA7549A1E2C80DB7608B8D75CF068A66')
        self.assertTrue(p['fingerprint_verified'])
        self.assertFalse(p['encrypted'])
        self.assertFalse(p['encryption_verified'])

    def test_multi_profile(self):
        """Parse two profiles — one active, one inactive."""
        fixture = load_fixture('show_config_profiles_nvm_multi.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_profiles('nvm')
        self.assertEqual(len(result), 2)
        # Active
        self.assertTrue(result[0]['active'])
        self.assertEqual(result[0]['name'], 'config')
        self.assertTrue(result[0]['fingerprint_verified'])
        # Inactive
        self.assertFalse(result[1]['active'])
        self.assertEqual(result[1]['name'], 'backup')
        self.assertFalse(result[1]['fingerprint_verified'])
        self.assertEqual(result[1]['fingerprint'], 'ABCDEF1234567890ABCDEF1234567890ABCDEF12')

    def test_invalid_storage_raises(self):
        """Reject invalid storage type."""
        with self.assertRaises(ValueError):
            self.ssh.get_profiles('invalid')

    def test_fingerprint(self):
        """get_config_fingerprint returns active profile SHA1."""
        fixture = load_fixture('show_config_profiles_nvm.txt')
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_config_fingerprint()
        self.assertEqual(result['fingerprint'], '9244C58FEA7549A1E2C80DB7608B8D75CF068A66')
        self.assertTrue(result['verified'])

    def test_fingerprint_no_active(self):
        """Empty fingerprint when no active profile."""
        # Create fixture with no [x] marker
        fixture = (
            "Index   Name                                      Date & Time (UTC)    SW-Rel.\n"
            "Active  Fingerprint                               FP verified\n"
            "        Encrypted    Key verified\n"
            "------  -----------  ---------------------------  -------------------  ---------\n"
            "  1     config                                    2026-02-13 13:25:16  09.4.4\n"
            " [ ]    9244C58FEA7549A1E2C80DB7608B8D75CF068A66  yes\n"
            "        no           no\n"
        )
        self.ssh.cli = lambda cmd: {cmd: fixture}
        result = self.ssh.get_config_fingerprint()
        self.assertEqual(result['fingerprint'], '')
        self.assertFalse(result['verified'])


class TestProfileWriteSSH(unittest.TestCase):
    """Test SSH profile activate/delete methods."""

    def setUp(self):
        self.ssh = SSHHIOS.__new__(SSHHIOS)
        self.ssh.connection = None
        self.ssh._in_config_mode = False
        # Mock config mode and CLI
        self.ssh._config_mode = lambda: setattr(self.ssh, '_in_config_mode', True)
        self.ssh._exit_config_mode = lambda: setattr(self.ssh, '_in_config_mode', False)

        # Default: two profiles, index 1 active, index 2 inactive
        self.multi_fixture = load_fixture('show_config_profiles_nvm_multi.txt')
        self.ssh.cli = lambda cmd: {cmd: self.multi_fixture}

    def test_delete_inactive_profile(self):
        """Delete inactive profile index 2."""
        self.cli_calls = []
        fixture = self.multi_fixture
        def mock_cli(cmd):
            self.cli_calls.append(cmd)
            if 'show config profiles' in cmd:
                return {cmd: fixture}
            return {cmd: ''}
        self.ssh.cli = mock_cli

        self.ssh.delete_profile('nvm', 2)
        self.assertIn('config profile delete nvm num 2', self.cli_calls)

    def test_delete_active_profile_raises(self):
        """Refuse to delete the active profile."""
        with self.assertRaises(ValueError) as ctx:
            self.ssh.delete_profile('nvm', 1)
        self.assertIn('active', str(ctx.exception).lower())

    def test_delete_nonexistent_raises(self):
        """Refuse to delete a profile that doesn't exist."""
        with self.assertRaises(ValueError) as ctx:
            self.ssh.delete_profile('nvm', 99)
        self.assertIn('not found', str(ctx.exception).lower())

    def test_activate_inactive_profile(self):
        """Activate inactive profile index 2."""
        self.cli_calls = []
        fixture = self.multi_fixture
        def mock_cli(cmd):
            self.cli_calls.append(cmd)
            if 'show config profiles' in cmd:
                return {cmd: fixture}
            return {cmd: ''}
        self.ssh.cli = mock_cli

        self.ssh.activate_profile('nvm', 2)
        self.assertIn('config profile select nvm 2', self.cli_calls)

    def test_activate_already_active_raises(self):
        """Refuse to activate a profile that's already active."""
        with self.assertRaises(ValueError) as ctx:
            self.ssh.activate_profile('nvm', 1)
        self.assertIn('already active', str(ctx.exception).lower())

    def test_activate_envm_raises(self):
        """HiOS only supports select from NVM."""
        with self.assertRaises(ValueError) as ctx:
            self.ssh.activate_profile('envm', 1)
        self.assertIn('nvm', str(ctx.exception).lower())

    def test_delete_invalid_storage_raises(self):
        """Reject invalid storage type."""
        with self.assertRaises(ValueError):
            self.ssh.delete_profile('invalid', 1)


class TestStormControlParser(unittest.TestCase):
    """Test storm control CLI output parsing."""

    def setUp(self):
        self.ssh = SSHHIOS("192.0.2.1", "admin", "test", 10)
        self.ssh.connection = True

    def test_get_storm_control_mixed(self):
        """Parse mix of percent (disabled) and pps (enabled) ports."""
        output = """\
        Broadcasts              Known Multicasts        Unknown Frames
Intf    Mode      Level         Mode      Level         Mode      Level
------  ----------------------  ----------------------  ---------------------
1/1     disabled            0%  disabled            0%  disabled            0%
1/2     disabled            0%  disabled            0%  disabled            0%
1/11    enabled        100 pps  disabled         0 pps  disabled         0 pps
1/12    disabled            0%  disabled            0%  disabled            0%"""
        self.ssh.cli = lambda cmd: {'show storm-control ingress': output}
        result = self.ssh.get_storm_control()

        self.assertEqual(result['bucket_type'], '')
        self.assertEqual(len(result['interfaces']), 4)

        # Default port (percent, all disabled)
        p1 = result['interfaces']['1/1']
        self.assertEqual(p1['unit'], 'percent')
        self.assertFalse(p1['broadcast']['enabled'])
        self.assertEqual(p1['broadcast']['threshold'], 0)
        self.assertFalse(p1['multicast']['enabled'])
        self.assertFalse(p1['unicast']['enabled'])

        # Active port (pps, broadcast enabled)
        p11 = result['interfaces']['1/11']
        self.assertEqual(p11['unit'], 'pps')
        self.assertTrue(p11['broadcast']['enabled'])
        self.assertEqual(p11['broadcast']['threshold'], 100)
        self.assertFalse(p11['multicast']['enabled'])
        self.assertEqual(p11['multicast']['threshold'], 0)
        self.assertFalse(p11['unicast']['enabled'])

    def test_get_storm_control_all_types_enabled(self):
        """Parse port with all three storm types active."""
        output = """\
        Broadcasts              Known Multicasts        Unknown Frames
Intf    Mode      Level         Mode      Level         Mode      Level
------  ----------------------  ----------------------  ---------------------
1/5     enabled         50 pps  enabled        200 pps  enabled        300 pps"""
        self.ssh.cli = lambda cmd: {'show storm-control ingress': output}
        result = self.ssh.get_storm_control()
        p = result['interfaces']['1/5']
        self.assertEqual(p['unit'], 'pps')
        self.assertTrue(p['broadcast']['enabled'])
        self.assertEqual(p['broadcast']['threshold'], 50)
        self.assertTrue(p['multicast']['enabled'])
        self.assertEqual(p['multicast']['threshold'], 200)
        self.assertTrue(p['unicast']['enabled'])
        self.assertEqual(p['unicast']['threshold'], 300)

    def test_get_storm_control_all_percent(self):
        """Parse ports with percent thresholds."""
        output = """\
        Broadcasts              Known Multicasts        Unknown Frames
Intf    Mode      Level         Mode      Level         Mode      Level
------  ----------------------  ----------------------  ---------------------
1/1     enabled           50%  enabled           25%  disabled            0%"""
        self.ssh.cli = lambda cmd: {'show storm-control ingress': output}
        result = self.ssh.get_storm_control()
        p = result['interfaces']['1/1']
        self.assertEqual(p['unit'], 'percent')
        self.assertTrue(p['broadcast']['enabled'])
        self.assertEqual(p['broadcast']['threshold'], 50)
        self.assertTrue(p['multicast']['enabled'])
        self.assertEqual(p['multicast']['threshold'], 25)
        self.assertFalse(p['unicast']['enabled'])
        self.assertEqual(p['unicast']['threshold'], 0)

    def test_set_storm_control_bad_unit(self):
        """Invalid unit raises ValueError before CLI call."""
        with self.assertRaises(ValueError):
            self.ssh.set_storm_control('1/1', unit='bps')


class TestSFlowParser(unittest.TestCase):
    """Test sFlow CLI output parsing."""

    def setUp(self):
        self.ssh = SSHHIOS("192.0.2.1", "admin", "test", 10)
        self.ssh.connection = True

    def test_get_sflow_agent(self):
        """Parse agent dot-key output."""
        output = """\
sFlow Information
-----------------
sFlow version...............................1.3;Hirschmann;10.3.04
IP address..................................192.168.1.4"""
        self.ssh.cli = lambda cmd: {'show sflow agent': output,
                                    'show sflow receivers': self._empty_receivers()}
        result = self.ssh.get_sflow()
        self.assertEqual(result['agent_version'], '1.3;Hirschmann;10.3.04')
        self.assertEqual(result['agent_address'], '192.168.1.4')

    def _empty_receivers(self):
        return """\
Recv Owner string                                                                    Timeout    Max dgram Port  IP address
indx                                                                                            size
---- ------------------------------------------------------------------------------- ---------- --------- ----- ---------------
1                                                                                    0          1400      6343  0.0.0.0
2                                                                                    0          1400      6343  0.0.0.0
3                                                                                    0          1400      6343  0.0.0.0
4                                                                                    0          1400      6343  0.0.0.0
5                                                                                    0          1400      6343  0.0.0.0
6                                                                                    0          1400      6343  0.0.0.0
7                                                                                    0          1400      6343  0.0.0.0
8                                                                                    0          1400      6343  0.0.0.0"""

    def test_get_sflow_receivers_empty(self):
        """Parse receiver table with all defaults."""
        def mock_cli(cmd):
            return {cmd: self._empty_receivers() if 'receivers' in cmd
                    else "sFlow version...............................1.3\n"
                         "IP address..................................10.0.0.1"}
        self.ssh.cli = mock_cli
        result = self.ssh.get_sflow()
        self.assertEqual(len(result['receivers']), 8)
        for idx in range(1, 9):
            r = result['receivers'][idx]
            self.assertEqual(r['owner'], '')
            self.assertEqual(r['timeout'], 0)
            self.assertEqual(r['address'], '0.0.0.0')

    def test_get_sflow_receivers_configured(self):
        """Parse receiver with owner and permanent timeout."""
        rcvr_out = """\
Recv Owner string                                                                    Timeout    Max dgram Port  IP address
indx                                                                                            size
---- ------------------------------------------------------------------------------- ---------- --------- ----- ---------------
1    snoop                                                                           -          1400      6343  192.168.1.100
2                                                                                    0          1400      6343  0.0.0.0"""

        def mock_cli(cmd):
            return {cmd: rcvr_out if 'receivers' in cmd
                    else "sFlow version...............................1.3\n"
                         "IP address..................................10.0.0.1"}
        self.ssh.cli = mock_cli
        result = self.ssh.get_sflow()
        r1 = result['receivers'][1]
        self.assertEqual(r1['owner'], 'snoop')
        self.assertEqual(r1['timeout'], -1)
        self.assertEqual(r1['address'], '192.168.1.100')
        r2 = result['receivers'][2]
        self.assertEqual(r2['owner'], '')
        self.assertEqual(r2['timeout'], 0)

    def test_get_sflow_port_samplers_pollers(self):
        """Parse sampler and poller tables."""
        sampler_out = """\
Interface  Rcvr  Rate  Max Hdr
---------- ----- ----- -------
1/1        0     0     128
1/2        1     256   128
1/11       1     512   256"""

        poller_out = """\
Interface  Rcvr  Interval
---------- ----- --------
1/1        0     0
1/2        1     20
1/11       1     30"""

        def mock_cli(cmd):
            if 'samplers' in cmd:
                return {cmd: sampler_out}
            return {cmd: poller_out}
        self.ssh.cli = mock_cli

        result = self.ssh.get_sflow_port()
        self.assertEqual(len(result), 3)

        p2 = result['1/2']
        self.assertEqual(p2['sampler']['receiver'], 1)
        self.assertEqual(p2['sampler']['sample_rate'], 256)
        self.assertEqual(p2['poller']['receiver'], 1)
        self.assertEqual(p2['poller']['interval'], 20)

        p11 = result['1/11']
        self.assertEqual(p11['sampler']['sample_rate'], 512)
        self.assertEqual(p11['sampler']['max_header_size'], 256)
        self.assertEqual(p11['poller']['interval'], 30)

    def test_get_sflow_port_filter(self):
        """Interface filter returns only requested ports."""
        sampler_out = """\
Interface  Rcvr  Rate  Max Hdr
---------- ----- ----- -------
1/1        0     0     128
1/2        1     256   128"""

        poller_out = """\
Interface  Rcvr  Interval
---------- ----- --------
1/1        0     0
1/2        1     20"""

        def mock_cli(cmd):
            if 'samplers' in cmd:
                return {cmd: sampler_out}
            return {cmd: poller_out}
        self.ssh.cli = mock_cli

        result = self.ssh.get_sflow_port(interfaces=['1/2'])
        self.assertEqual(list(result.keys()), ['1/2'])

    def test_set_sflow_bad_receiver(self):
        """Invalid receiver raises ValueError."""
        with self.assertRaises(ValueError):
            self.ssh.set_sflow(0, owner='test')
        with self.assertRaises(ValueError):
            self.ssh.set_sflow(9, owner='test')

    def test_set_sflow_port_no_rate_or_interval(self):
        """Missing both rate and interval raises ValueError."""
        with self.assertRaises(ValueError):
            self.ssh.set_sflow_port('1/1', receiver=1)


class TestQoSParser(unittest.TestCase):
    """Test SSH QoS parser methods."""

    def setUp(self):
        self.ssh = SSHHIOS("192.0.2.1", "admin", "test", 10)
        self.ssh.connection = True
        self.ssh._in_config_mode = False

    def test_get_qos_trust(self):
        """Parse trust mode per port."""
        trust_output = (
            'Intf  Trust Mode\n'
            '----  ----------\n'
            '1/1   dot1p\n'
            '1/2   untrusted\n'
            '1/3   ip-dscp\n'
        )
        queue_output = (
            'Queue Id  Min BW  Max BW  Scheduler\n'
            '--------  ------  ------  ---------\n'
            '0         0       0       strict\n'
            '1         0       0       strict\n'
            '7         0       0       strict\n'
        )

        def mock_cli(cmd, **kw):
            if 'trust' in cmd:
                return {'show classofservice trust': trust_output}
            return {'show cos-queue': queue_output}

        self.ssh.cli = mock_cli
        result = self.ssh.get_qos()

        self.assertEqual(result['interfaces']['1/1']['trust_mode'], 'dot1p')
        self.assertEqual(result['interfaces']['1/2']['trust_mode'], 'untrusted')
        self.assertEqual(result['interfaces']['1/3']['trust_mode'], 'ip-dscp')
        self.assertEqual(result['num_queues'], 3)

    def test_get_qos_mapping_dot1p(self):
        """Parse dot1p mapping table."""
        dot1p_output = (
            'Prio  TC\n'
            '----  --\n'
            '0     2\n'
            '1     0\n'
            '2     1\n'
            '3     3\n'
            '4     4\n'
            '5     5\n'
            '6     6\n'
            '7     7\n'
        )
        dscp_output = (
            'DSCP  TC\n'
            '----  --\n'
            '0     0\n'
            '8     1\n'
            '46    5\n'
        )

        def mock_cli(cmd, **kw):
            if 'dot1p' in cmd:
                return {'show classofservice dot1p-mapping': dot1p_output}
            return {'show classofservice ip-dscp-mapping': dscp_output}

        self.ssh.cli = mock_cli
        result = self.ssh.get_qos_mapping()

        self.assertEqual(result['dot1p'][0], 2)
        self.assertEqual(result['dot1p'][7], 7)
        self.assertEqual(result['dscp'][0], 0)
        self.assertEqual(result['dscp'][46], 5)

    def test_get_management_priority(self):
        """Parse management priority from show network parms."""
        output = (
            'Management VLAN ID......... 1\n'
            'VLAN Priority.............. 3\n'
            'IP DSCP Priority........... 46\n'
            'Management IP.............. 192.168.1.4\n'
        )

        def mock_cli(cmd, **kw):
            return {'show network parms': output}

        self.ssh.cli = mock_cli
        result = self.ssh.get_management_priority()

        self.assertEqual(result['dot1p'], 3)
        self.assertEqual(result['ip_dscp'], 46)

    def test_set_qos_bad_trust_mode(self):
        """Invalid trust mode raises ValueError."""
        with self.assertRaises(ValueError):
            self.ssh.set_qos('1/1', trust_mode='badval')

    def test_set_qos_bad_scheduler(self):
        with self.assertRaises(ValueError):
            self.ssh.set_qos('1/1', scheduler='round-robin')

    def test_set_qos_queue_needed_no_index(self):
        with self.assertRaises(ValueError):
            self.ssh.set_qos('1/1', min_bw=50)


class TestManagementSSH(unittest.TestCase):
    """Test SSH get_management parser."""

    def setUp(self):
        self.ssh = SSHHIOS("192.0.2.1", "admin", "test", 10)
        self.ssh.connection = True
        self.ssh._in_config_mode = False

    def test_get_management(self):
        """Parse management network config from show network parms."""
        net_output = (
            'IPv4 Network\n'
            '------------\n'
            'Local IP address............................192.168.1.4\n'
            'Subnetmask..................................255.255.255.0\n'
            'Gateway address.............................192.168.1.254\n'
            'Burned in MAC address.......................64:60:38:3f:4a:a1\n'
            'Protocol....................................none\n'
            'Management VLAN ID..........................1\n'
            'Management VLAN priority....................0\n'
            'Management IP-DSCP value....................0\n'
            'DHCP/BOOTP client ID........................\n'
            'DHCP/BOOTP client config load...............enabled(options 4, 42, 66, 67)\n'
        )
        ipv6_output = (
            'IPv6 status.................................enable\n'
            'Type of protocol............................autoconf\n'
            'Gateway address.............................::\n'
            'Number of DAD transmits.....................1\n'
        )

        def mock_cli(cmd, **kw):
            if 'ipv6' in cmd:
                return {'show network ipv6 global': ipv6_output}
            return {'show network parms': net_output}

        self.ssh.cli = mock_cli
        result = self.ssh.get_management()

        self.assertEqual(result['protocol'], 'local')
        self.assertEqual(result['vlan_id'], 1)
        self.assertEqual(result['ip_address'], '192.168.1.4')
        self.assertEqual(result['netmask'], '255.255.255.0')
        self.assertEqual(result['gateway'], '192.168.1.254')
        self.assertTrue(result['dhcp_option_66_67'])
        self.assertTrue(result['ipv6_enabled'])
        self.assertEqual(result['ipv6_protocol'], 'auto')

    def test_get_management_dhcp_disabled(self):
        """Parse management config with DHCP and IPv6 disabled."""
        net_output = (
            'Local IP address............................10.0.0.50\n'
            'Subnetmask..................................255.255.0.0\n'
            'Gateway address.............................10.0.0.1\n'
            'Protocol....................................dhcp\n'
            'Management VLAN ID..........................100\n'
            'Management VLAN priority....................5\n'
            'Management IP-DSCP value....................46\n'
            'DHCP/BOOTP client config load...............disabled\n'
        )
        ipv6_output = (
            'IPv6 status.................................disable\n'
            'Type of protocol............................none\n'
        )

        def mock_cli(cmd, **kw):
            if 'ipv6' in cmd:
                return {'show network ipv6 global': ipv6_output}
            return {'show network parms': net_output}

        self.ssh.cli = mock_cli
        result = self.ssh.get_management()

        self.assertEqual(result['protocol'], 'dhcp')
        self.assertEqual(result['vlan_id'], 100)
        self.assertFalse(result['dhcp_option_66_67'])
        self.assertEqual(result['dot1p'], 5)
        self.assertEqual(result['ip_dscp'], 46)
        self.assertFalse(result['ipv6_enabled'])

    def test_set_management_bad_vlan(self):
        """Rejects out-of-range VLAN."""
        with self.assertRaises(ValueError):
            self.ssh.set_management(vlan_id=0)

    def test_set_management_nonexistent_vlan(self):
        """Rejects VLAN not in VLAN table."""
        self.ssh.get_vlans = lambda: {1: {'name': 'default', 'interfaces': []}}
        with self.assertRaises(ValueError):
            self.ssh.set_management(vlan_id=99)


if __name__ == '__main__':
    unittest.main()
