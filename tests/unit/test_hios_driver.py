import unittest
from unittest.mock import Mock, patch
from napalm_hios.hios import HIOSDriver
from napalm.base.exceptions import ConnectionException, CommandErrorException

class TestHIOSDriver(unittest.TestCase):

    def setUp(self):
        self.device = HIOSDriver('localhost', 'username', 'password')
        self.device._get_active_connection = Mock()

    @patch('napalm_hios.hios.SSHHIOS')
    def test_open(self, mock_ssh):
        # Test SSH connection
        self.device.open()
        mock_ssh.assert_called_once()
        self.assertEqual(self.device.active_protocol, 'ssh')

        # Test when SSH connection fails
        mock_ssh.side_effect = ConnectionException("SSH connection failed")
        with self.assertRaises(ConnectionException):
            self.device.open()

    def test_close(self):
        mock_connection = Mock()
        self.device.ssh = mock_connection

        self.device.close()

        mock_connection.close.assert_called_once()
        self.assertFalse(self.device._is_alive)
        self.assertIsNone(self.device.active_protocol)

    def test_is_alive(self):
        self.device._is_alive = True
        self.assertTrue(self.device.is_alive()['is_alive'])

        self.device._is_alive = False
        self.assertFalse(self.device.is_alive()['is_alive'])

    def test_cli(self):
        mock_connection = Mock()
        mock_connection.cli.return_value = {
            "show version": "HiOS-3A-09.4.04",
            "show interfaces status": "1/1 up 2500M"
        }
        self.device._get_active_connection.return_value = mock_connection

        result = self.device.cli(["show version", "show interfaces status"])

        self.assertIn("show version", result)
        self.assertIn("show interfaces status", result)
        self.assertEqual(result["show version"], "HiOS-3A-09.4.04")

    def test_get_facts(self):
        mock_connection = Mock()
        mock_connection.get_facts.return_value = {
            "vendor": "Belden",
            "uptime": "12 days, 07:31:03",
            "os_version": "HiOS-3A-09.4.04",
            "model": "GRS1042-6T6ZTHH00V9HHSE3AMR",
            "serial_number": "942135999000101022"
        }
        self.device._get_active_connection.return_value = mock_connection

        facts = self.device.get_facts()

        self.assertEqual(facts['vendor'], "Belden")
        self.assertEqual(facts['os_version'], "HiOS-3A-09.4.04")
        self.assertEqual(facts['model'], "GRS1042-6T6ZTHH00V9HHSE3AMR")
        self.assertEqual(facts['serial_number'], "942135999000101022")

    def test_get_interfaces(self):
        mock_connection = Mock()
        mock_connection.get_interfaces.return_value = {
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
        self.device._get_active_connection.return_value = mock_connection

        interfaces = self.device.get_interfaces()

        self.assertIn("1/1", interfaces)
        self.assertEqual(interfaces["1/1"]["speed"], 2500000000)
        self.assertEqual(interfaces["1/1"]["mtu"], 1518)

    def test_get_lldp_neighbors(self):
        mock_connection = Mock()
        mock_connection.get_lldp_neighbors.return_value = {
            "1/7": [
                {
                    "hostname": "BRS50-LOUNGE",
                    "port": "Module: 1 Port: 5 - 1 Gbit"
                }
            ]
        }
        self.device._get_active_connection.return_value = mock_connection

        neighbors = self.device.get_lldp_neighbors()

        self.assertIn("1/7", neighbors)
        self.assertEqual(neighbors["1/7"][0]["hostname"], "BRS50-LOUNGE")

    def test_ping(self):
        mock_connection = Mock()
        mock_connection.ping.return_value = {
            "success": {
                "probes_sent": 3,
                "packet_loss": 0.0,
                "rtt_min": 0.741,
                "rtt_max": 0.923,
                "rtt_avg": 0.804,
                "rtt_stddev": 0.0,
                "results": [
                    {
                        "ip_address": "192.168.3.1",
                        "rtt": 0.75
                    }
                ]
            }
        }
        self.device._get_active_connection.return_value = mock_connection

        result = self.device.ping('192.168.3.1', count=3)

        self.assertIn("success", result)
        self.assertEqual(result["success"]["probes_sent"], 3)
        self.assertEqual(result["success"]["packet_loss"], 0.0)

    def test_get_interfaces_ip(self):
        mock_connection = Mock()
        mock_connection.get_interfaces_ip.return_value = {
            "vlan/1": {
                "ipv4": {
                    "192.168.1.254": {
                        "prefix_length": 24
                    }
                }
            }
        }
        self.device._get_active_connection.return_value = mock_connection

        interfaces_ip = self.device.get_interfaces_ip()

        self.assertIn("vlan/1", interfaces_ip)
        self.assertIn("192.168.1.254", interfaces_ip["vlan/1"]["ipv4"])
        self.assertEqual(interfaces_ip["vlan/1"]["ipv4"]["192.168.1.254"]["prefix_length"], 24)

    def test_get_config(self):
        mock_connection = Mock()
        mock_connection.get_config.return_value = {
            "running": "! GRS1042-6T6Z Configuration\n\n! Version: HiOS-3A-09.4.04\n\n",
            "startup": "",
            "candidate": ""
        }
        self.device._get_active_connection.return_value = mock_connection

        config = self.device.get_config()

        self.assertIn("running", config)
        self.assertIn("startup", config)
        self.assertIn("candidate", config)
        self.assertIn("GRS1042-6T6Z Configuration", config["running"])

    def test_get_environment(self):
        mock_connection = Mock()
        mock_connection.get_environment.return_value = {
            "fans": {"Error": {"status": False}},
            "temperature": {"temperature": 47.0, "is_alert": False, "is_critical": False},
            "power": {"status": True},
            "cpu": {"usage": 23.0},
            "memory": {"available_ram": 150592, "used_ram": 206328}
        }
        self.device._get_active_connection.return_value = mock_connection

        environment = self.device.get_environment()

        self.assertIn("fans", environment)
        self.assertIn("temperature", environment)
        self.assertIn("power", environment)
        self.assertIn("cpu", environment)
        self.assertIn("memory", environment)
        self.assertEqual(environment["temperature"]["temperature"], 47.0)
        self.assertEqual(environment["cpu"]["usage"], 23.0)

    def test_get_users(self):
        mock_connection = Mock()
        mock_connection.get_users.return_value = {
            "admin": {"level": 15, "password": "", "sshkeys": []},
            "user": {"level": 1, "password": "", "sshkeys": []}
        }
        self.device._get_active_connection.return_value = mock_connection

        users = self.device.get_users()

        self.assertIn("admin", users)
        self.assertIn("user", users)
        self.assertEqual(users["admin"]["level"], 15)
        self.assertEqual(users["user"]["level"], 1)

    def test_empty_response(self):
        mock_connection = Mock()
        mock_connection.get_interfaces.return_value = {}
        self.device._get_active_connection.return_value = mock_connection

        interfaces = self.device.get_interfaces()

        self.assertEqual(interfaces, {})

    def test_unexpected_data_format(self):
        mock_connection = Mock()
        mock_connection.get_facts.return_value = "Unexpected string instead of dict"
        self.device._get_active_connection.return_value = mock_connection

        with self.assertRaises(TypeError):
            self.device.get_facts()

    def test_connection_error_handling(self):
        mock_connection = Mock()
        mock_connection.get_facts.side_effect = ConnectionException("Connection lost")
        self.device._get_active_connection.return_value = mock_connection

        with self.assertRaises(ConnectionException):
            self.device.get_facts()

    def test_command_error_handling(self):
        mock_connection = Mock()
        mock_connection.cli.side_effect = CommandErrorException("Invalid command")
        self.device._get_active_connection.return_value = mock_connection

        with self.assertRaises(CommandErrorException):
            self.device.cli(["invalid command"])

if __name__ == '__main__':
    unittest.main()
