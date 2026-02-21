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
        # 6 remote entries but only 4 have system name + port description
        # (1/3 and 1/8 lack system name)
        self.assertGreaterEqual(len(neighbors), 3)
        self.assertIn('1/7', neighbors)
        self.assertIn('1/1', neighbors)
        self.assertIn('3/3', neighbors)

    def test_detail_gets_all_entries(self):
        detail = self._call_parser('get_lldp_neighbors_detail')
        # All 6 entries should appear in detail (including chassis-id-only ones)
        self.assertEqual(len(detail), 6)
        self.assertIn('1/3', detail)
        self.assertIn('1/8', detail)
        self.assertIn('2/7', detail)

    def test_detail_parent_interface_set(self):
        detail = self._call_parser('get_lldp_neighbors_detail')
        for port, entries in detail.items():
            for entry in entries:
                self.assertEqual(entry['parent_interface'], port)

    def test_extended_management_addresses(self):
        extended = self._call_parser('get_lldp_neighbors_detail_extended')
        # BRS50-Office has both IPv4 and IPv6 management
        office = extended['1/1'][0]
        self.assertEqual(office['remote_management_ipv4'], '192.168.1.4')
        self.assertEqual(office['remote_management_ipv6'], 'fe80::6660:38ff:fe3f:4aa1')

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


if __name__ == '__main__':
    unittest.main()
