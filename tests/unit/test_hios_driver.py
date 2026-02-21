import unittest
from unittest.mock import Mock, patch
from napalm_hios.hios import HIOSDriver
from napalm.base.exceptions import ConnectionException, CommandErrorException


class TestHIOSDriver(unittest.TestCase):

    def setUp(self):
        self.device = HIOSDriver('localhost', 'username', 'password')
        # Simulate an open connection so the dispatcher routes to our mock
        self.device.active_protocol = 'ssh'
        self.mock_connection = Mock()
        self.device._get_active_connection = Mock(return_value=self.mock_connection)

    # --- Connection lifecycle ---

    def test_open_localhost_uses_mock(self):
        """localhost hostname should route to MockHIOSDevice."""
        device = HIOSDriver('localhost', 'user', 'pass')
        device.open()
        self.assertTrue(device._is_alive)
        self.assertEqual(device.active_protocol, 'ssh')
        self.assertIsNotNone(device.mock_device)

    @patch('napalm_hios.hios.SSHHIOS')
    def test_open_ssh(self, mock_ssh_cls):
        """Non-localhost should attempt SSH connection."""
        device = HIOSDriver('192.168.1.1', 'admin', 'private')
        mock_ssh_cls.return_value.open.return_value = None
        device.open()
        mock_ssh_cls.assert_called_once()
        self.assertEqual(device.active_protocol, 'ssh')
        self.assertTrue(device._is_alive)

    @patch('napalm_hios.hios.SSHHIOS')
    def test_open_all_protocols_fail(self, mock_ssh_cls):
        """Should raise ConnectionException when all protocols fail."""
        device = HIOSDriver('192.168.1.1', 'admin', 'private',
                            optional_args={'protocol_preference': ['ssh']})
        mock_ssh_cls.return_value.open.side_effect = Exception("SSH failed")
        with self.assertRaises(ConnectionException):
            device.open()

    def test_close(self):
        mock_ssh = Mock()
        self.device.ssh = mock_ssh
        self.device.mock_device = None  # not localhost mock path
        self.device.close()
        mock_ssh.close.assert_called_once()
        self.assertFalse(self.device._is_alive)
        self.assertIsNone(self.device.active_protocol)

    def test_close_mock_device(self):
        """Close should clear mock_device for localhost connections."""
        device = HIOSDriver('localhost', 'user', 'pass')
        device.open()
        device.close()
        self.assertFalse(device._is_alive)
        self.assertIsNone(device.active_protocol)
        self.assertIsNone(device.mock_device)

    def test_is_alive(self):
        self.device._is_alive = True
        self.assertTrue(self.device.is_alive()['is_alive'])
        self.device._is_alive = False
        self.assertFalse(self.device.is_alive()['is_alive'])

    # --- CLI ---

    def test_cli(self):
        self.mock_connection.cli.return_value = {
            "show version": "HiOS-3A-09.4.04",
            "show interfaces status": "1/1 up 2500M"
        }
        result = self.device.cli(["show version", "show interfaces status"])
        self.assertEqual(result["show version"], "HiOS-3A-09.4.04")
        self.assertIn("show interfaces status", result)

    def test_cli_no_connection(self):
        """CLI should raise NotImplementedError when no protocol is active."""
        self.device.active_protocol = None
        with self.assertRaises(NotImplementedError):
            self.device.cli(["show version"])

    # --- get_facts ---

    def test_get_facts(self):
        self.mock_connection.get_facts.return_value = {
            "vendor": "Belden",
            "uptime": 1036800,
            "os_version": "HiOS-3A-09.4.04",
            "model": "GRS1042-6T6ZTHH00V9HHSE3AMR",
            "serial_number": "942135999000101022"
        }
        facts = self.device.get_facts()
        self.assertEqual(facts['vendor'], "Belden")
        self.assertEqual(facts['os_version'], "HiOS-3A-09.4.04")
        self.assertEqual(facts['model'], "GRS1042-6T6ZTHH00V9HHSE3AMR")
        # Missing keys should be filled with empty string
        self.assertEqual(facts['hostname'], '')
        self.assertEqual(facts['fqdn'], '')
        self.assertEqual(facts['interface_list'], '')

    # --- get_interfaces ---

    def test_get_interfaces(self):
        self.mock_connection.get_interfaces.return_value = {
            "1/1": {
                "is_up": False,
                "is_enabled": True,
                "description": "",
                "last_flapped": -1.0,
                "speed": 2500000000,
                "mtu": 1518,
                "mac_address": ""
            }
        }
        interfaces = self.device.get_interfaces()
        self.assertIn("1/1", interfaces)
        self.assertEqual(interfaces["1/1"]["speed"], 2500000000)
        self.assertEqual(interfaces["1/1"]["mtu"], 1518)

    def test_get_interfaces_fills_missing_keys(self):
        """Missing keys should get default values."""
        self.mock_connection.get_interfaces.return_value = {
            "1/1": {"is_up": True}
        }
        interfaces = self.device.get_interfaces()
        self.assertEqual(interfaces["1/1"]["description"], '')
        self.assertEqual(interfaces["1/1"]["speed"], 0)

    def test_get_interfaces_empty(self):
        self.mock_connection.get_interfaces.return_value = {}
        interfaces = self.device.get_interfaces()
        self.assertEqual(interfaces, {})

    # --- get_interfaces_ip ---

    def test_get_interfaces_ip(self):
        self.mock_connection.get_interfaces_ip.return_value = {
            "vlan/1": {
                "ipv4": {
                    "192.168.1.254": {"prefix_length": 24}
                }
            }
        }
        interfaces_ip = self.device.get_interfaces_ip()
        self.assertIn("vlan/1", interfaces_ip)
        self.assertIn("192.168.1.254", interfaces_ip["vlan/1"]["ipv4"])
        self.assertEqual(interfaces_ip["vlan/1"]["ipv4"]["192.168.1.254"]["prefix_length"], 24)

    def test_get_interfaces_ip_fills_missing_protos(self):
        """Should add empty ipv4/ipv6 dicts if missing."""
        self.mock_connection.get_interfaces_ip.return_value = {
            "vlan/1": {}
        }
        result = self.device.get_interfaces_ip()
        self.assertEqual(result["vlan/1"]["ipv4"], {})
        self.assertEqual(result["vlan/1"]["ipv6"], {})

    # --- get_interfaces_counters ---

    def test_get_interfaces_counters(self):
        self.mock_connection.get_interfaces_counters.return_value = {
            "1/1": {
                "rx_unicast_packets": 1000,
                "tx_unicast_packets": 2000,
            }
        }
        counters = self.device.get_interfaces_counters()
        self.assertEqual(counters["1/1"]["rx_unicast_packets"], 1000)
        # Missing keys should default to 0
        self.assertEqual(counters["1/1"]["rx_errors"], 0)
        self.assertEqual(counters["1/1"]["tx_errors"], 0)

    # --- LLDP ---

    def test_get_lldp_neighbors(self):
        self.mock_connection.get_lldp_neighbors.return_value = {
            "1/7": [{"hostname": "BRS50-LOUNGE", "port": "Module: 1 Port: 5 - 1 Gbit"}]
        }
        neighbors = self.device.get_lldp_neighbors()
        self.assertIn("1/7", neighbors)
        self.assertEqual(neighbors["1/7"][0]["hostname"], "BRS50-LOUNGE")

    def test_get_lldp_neighbors_fills_missing_keys(self):
        self.mock_connection.get_lldp_neighbors.return_value = {
            "1/1": [{}]
        }
        neighbors = self.device.get_lldp_neighbors()
        self.assertEqual(neighbors["1/1"][0]["hostname"], '')
        self.assertEqual(neighbors["1/1"][0]["port"], '')

    # --- MAC address table ---

    def test_get_mac_address_table(self):
        self.mock_connection.get_mac_address_table.return_value = [
            {"mac": "12:dd:6e:60:34:4b", "interface": "1/7", "vlan": 1,
             "static": False, "active": True, "moves": 0, "last_move": 0.0}
        ]
        mac_table = self.device.get_mac_address_table()
        self.assertEqual(len(mac_table), 1)
        self.assertEqual(mac_table[0]["mac"], "12:dd:6e:60:34:4b")

    # --- NTP ---

    def test_get_ntp_servers(self):
        self.mock_connection.get_ntp_servers.return_value = {"192.168.3.1": {}}
        ntp = self.device.get_ntp_servers()
        self.assertIn("192.168.3.1", ntp)

    def test_get_ntp_stats(self):
        self.mock_connection.get_ntp_stats.return_value = [
            {"remote": "192.168.3.1", "synchronized": True, "stratum": 0}
        ]
        stats = self.device.get_ntp_stats()
        self.assertEqual(stats[0]["remote"], "192.168.3.1")
        # Missing keys should be filled
        self.assertEqual(stats[0]["delay"], 0)
        self.assertEqual(stats[0]["referenceid"], '')

    # --- Optics ---

    def test_get_optics(self):
        self.mock_connection.get_optics.return_value = {
            "1/1": {"physical_channels": {"channel": [{"index": 0}]}}
        }
        optics = self.device.get_optics()
        self.assertIn("1/1", optics)
        self.assertEqual(len(optics["1/1"]["physical_channels"]["channel"]), 1)

    # --- Users ---

    def test_get_users(self):
        self.mock_connection.get_users.return_value = {
            "admin": {"level": 15, "password": "", "sshkeys": []},
            "user": {"level": 1, "password": "", "sshkeys": []}
        }
        users = self.device.get_users()
        self.assertIn("admin", users)
        self.assertEqual(users["admin"]["level"], 15)

    # --- VLANs ---

    def test_get_vlans(self):
        self.mock_connection.get_vlans.return_value = {
            1: {"name": "HOME", "interfaces": ["1/1", "1/2"]}
        }
        vlans = self.device.get_vlans()
        self.assertIn(1, vlans)
        self.assertEqual(vlans[1]["name"], "HOME")

    # --- ARP ---

    def test_get_arp_table(self):
        self.mock_connection.get_arp_table.return_value = [
            {"interface": "cpu/1", "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "age": 120.0}
        ]
        arp = self.device.get_arp_table()
        self.assertEqual(arp[0]["ip"], "192.168.1.1")

    # --- SNMP information ---

    def test_get_snmp_information(self):
        self.mock_connection.get_snmp_information.return_value = {
            "chassis_id": "GRS1042-CORE",
            "contact": "admin@example.com",
            "location": "Lab",
            "community": {"public": "read-only"}
        }
        snmp = self.device.get_snmp_information()
        self.assertEqual(snmp["chassis_id"], "GRS1042-CORE")
        self.assertIn("public", snmp["community"])

    # --- Ping ---

    def test_ping(self):
        self.mock_connection.ping.return_value = {
            "success": {
                "probes_sent": 3, "packet_loss": 0.0,
                "rtt_min": 0.741, "rtt_max": 0.923, "rtt_avg": 0.804,
                "rtt_stddev": 0.0,
                "results": [{"ip_address": "192.168.3.1", "rtt": 0.75}]
            }
        }
        result = self.device.ping('192.168.3.1', count=3)
        self.assertIn("success", result)
        self.assertEqual(result["success"]["probes_sent"], 3)

    # --- Config ---

    def test_get_config(self):
        self.mock_connection.get_config.return_value = {
            "running": "! GRS1042 Config\n",
            "startup": "",
            "candidate": ""
        }
        config = self.device.get_config()
        self.assertIn("running", config)
        self.assertIn("GRS1042", config["running"])

    # --- Environment ---

    def test_get_environment(self):
        self.mock_connection.get_environment.return_value = {
            "fans": {},
            "temperature": {
                "chassis": {"temperature": 47.0, "is_alert": False, "is_critical": False}
            },
            "power": {
                "Power Supply P1": {"status": True, "capacity": -1.0, "output": -1.0}
            },
            "cpu": {"0": {"%usage": 23.0}},
            "memory": {"available_ram": 358548, "used_ram": 209584}
        }
        env = self.device.get_environment()
        self.assertEqual(env["temperature"]["chassis"]["temperature"], 47.0)
        self.assertEqual(env["cpu"]["0"]["%usage"], 23.0)
        self.assertGreater(env["memory"]["available_ram"], env["memory"]["used_ram"])

    # --- Config management (intentionally not implemented) ---

    def test_config_management_not_implemented(self):
        for method_name in ['load_merge_candidate', 'load_replace_candidate',
                            'compare_config', 'commit_config',
                            'discard_config', 'rollback']:
            with self.assertRaises(NotImplementedError, msg=f"{method_name} should raise"):
                getattr(self.device, method_name)()

    # --- Error handling ---

    def test_connection_error_propagates(self):
        self.mock_connection.get_facts.side_effect = ConnectionException("Connection lost")
        with self.assertRaises(ConnectionException):
            self.device.get_facts()

    def test_command_error_propagates(self):
        self.mock_connection.cli.side_effect = CommandErrorException("Invalid command")
        with self.assertRaises(CommandErrorException):
            self.device.cli(["invalid command"])

    def test_no_protocol_raises(self):
        """All data methods should raise when active_protocol is not set."""
        self.device.active_protocol = None
        methods = ['get_facts', 'get_interfaces', 'get_interfaces_ip',
                   'get_lldp_neighbors', 'get_environment', 'get_config',
                   'get_users', 'get_vlans', 'get_snmp_information',
                   'get_optics', 'get_mac_address_table', 'get_ntp_servers',
                   'get_ntp_stats', 'get_interfaces_counters']
        for name in methods:
            with self.assertRaises((NotImplementedError, ConnectionException), msg=f"{name}"):
                getattr(self.device, name)()


if __name__ == '__main__':
    unittest.main()
