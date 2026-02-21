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

    def test_set_mrp_rejects_link_up_port(self):
        """set_mrp refuses to configure on link-up ports."""
        self.ssh.get_interfaces = lambda: {
            '1/1': {'is_up': True, 'is_enabled': True},
            '1/2': {'is_up': False, 'is_enabled': True},
        }
        with self.assertRaises(ValueError) as ctx:
            self.ssh.set_mrp(
                operation='enable', mode='client',
                port_primary='1/1', port_secondary='1/2'
            )
        self.assertIn('link-up', str(ctx.exception))
        self.assertIn('1/1', str(ctx.exception))


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


if __name__ == '__main__':
    unittest.main()
