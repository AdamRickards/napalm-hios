import unittest
from unittest.mock import Mock, patch
from napalm_hios.hios import HIOSDriver
from napalm.base.exceptions import ConnectionException
from napalm_hios.mock_hios_device import MockHIOSDevice

class TestHIOSDriver(unittest.TestCase):
    def setUp(self):
        self.driver = HIOSDriver('mock-device.example.com', 'username', 'password')

    @patch('napalm_hios.hios.NetconfHIOS')
    @patch('napalm_hios.hios.SSHHIOS')
    @patch('napalm_hios.hios.SNMPHIOS')
    def test_open_with_protocol_preference(self, mock_snmp, mock_ssh, mock_netconf):
        # Create mock instances
        mock_netconf_instance = Mock()
        mock_ssh_instance = Mock()
        mock_snmp_instance = Mock()

        # Set the return values for the mocked classes
        mock_netconf.return_value = mock_netconf_instance
        mock_ssh.return_value = mock_ssh_instance
        mock_snmp.return_value = mock_snmp_instance

        # Test NETCONF preference
        self.driver.optional_args = {'protocol_preference': ['netconf', 'ssh', 'snmp']}
        self.driver.open()
        mock_netconf_instance.open.assert_called_once()
        self.assertEqual(self.driver.active_protocol, 'netconf')

        # Test SSH preference
        self.driver.optional_args = {'protocol_preference': ['ssh', 'netconf', 'snmp']}
        self.driver.open()
        mock_ssh_instance.open.assert_called_once()
        self.assertEqual(self.driver.active_protocol, 'ssh')

        # Test SNMP preference
        self.driver.optional_args = {'protocol_preference': ['snmp', 'ssh', 'netconf']}
        self.driver.open()
        mock_snmp_instance.open.assert_called_once()
        self.assertEqual(self.driver.active_protocol, 'snmp')

    def test_close(self):
        self.driver.netconf = Mock()
        self.driver.ssh = Mock()
        self.driver.snmp = Mock()
        self.driver.active_protocol = 'netconf'
        self.driver.close()
        self.driver.netconf.close.assert_called_once()
        self.driver.ssh.close.assert_called_once()
        self.driver.snmp.close.assert_called_once()
        self.assertIsNone(self.driver.active_protocol)

    @patch('napalm_hios.hios.NetconfHIOS')
    def test_get_facts(self, mock_netconf):
        mock_netconf_instance = Mock()
        mock_netconf.return_value = mock_netconf_instance
        mock_facts = {
            'vendor': 'Belden',
            'model': 'HiOS-MockDevice',
            'serial_number': 'SN12345',
            'os_version': '1.0',
            'hostname': 'mock-device',
            'uptime': 3600,
            'interface_list': ['GigabitEthernet1/0/1', 'GigabitEthernet1/0/2']
        }
        mock_netconf_instance.get_facts.return_value = mock_facts
        self.driver.netconf = mock_netconf_instance
        self.driver.active_protocol = 'netconf'
        
        facts = self.driver.get_facts()
        mock_netconf_instance.get_facts.assert_called_once()
        self.assertEqual(facts, mock_facts)

    @patch('napalm_hios.hios.SSHHIOS')
    def test_get_interfaces(self, mock_ssh):
        mock_ssh_instance = Mock()
        mock_interfaces = {
            'GigabitEthernet1/0/1': {
                'is_up': True,
                'is_enabled': True,
                'description': 'Interface 1',
                'speed': 1000,
                'mtu': 1500
            },
            'GigabitEthernet1/0/2': {
                'is_up': False,
                'is_enabled': True,
                'description': 'Interface 2',
                'speed': 1000,
                'mtu': 1500
            }
        }
        mock_ssh_instance.get_interfaces.return_value = mock_interfaces
        self.driver.ssh = mock_ssh_instance
        self.driver.active_protocol = 'ssh'
        
        interfaces = self.driver.get_interfaces()
        mock_ssh_instance.get_interfaces.assert_called_once()
        self.assertEqual(interfaces, mock_interfaces)

    @patch('napalm_hios.hios.SNMPHIOS')
    def test_get_snmp_information(self, mock_snmp):
        mock_snmp_instance = Mock()
        mock_snmp_info = {
            'chassis_id': 'SNMP-CHASSIS-ID',
            'contact': 'admin@example.com',
            'location': 'SNMP Lab',
            'community': {'public': 'read-only', 'private': 'read-write'}
        }
        mock_snmp_instance.get_snmp_information.return_value = mock_snmp_info
        self.driver.snmp = mock_snmp_instance
        self.driver.active_protocol = 'snmp'
        
        snmp_info = self.driver.get_snmp_information()
        mock_snmp_instance.get_snmp_information.assert_called_once()
        self.assertEqual(snmp_info, mock_snmp_info)

    def test_mock_device(self):
        mock_driver = HIOSDriver('localhost', 'username', 'password')
        mock_driver.mock_device = MockHIOSDevice()
        mock_driver.open()
        
        self.assertIsNotNone(mock_driver.mock_device)
        
        facts = mock_driver.get_facts()
        self.assertEqual(facts['vendor'], 'Belden')
        self.assertEqual(facts['model'], 'HiOS-MockDevice')
        
        interfaces = mock_driver.get_interfaces()
        self.assertIn('GigabitEthernet1/0/1', interfaces)
        self.assertIn('GigabitEthernet1/0/2', interfaces)
        
        snmp_info = mock_driver.get_snmp_information()
        self.assertIn('chassis_id', snmp_info)
        self.assertIn('community', snmp_info)

    @patch('napalm_hios.hios.SSHHIOS')
    def test_cli_command_output(self, mock_ssh):
        mock_ssh_instance = Mock()
        mock_cli_output = {
            'show version': 'HiOS (Hirschmann Open Source) Software Version 1.0\nCopyright (C) 2023 Belden, Inc.',
            'show interfaces status': 'Interface    Status    VLAN    Duplex    Speed    Type\n'
                                      'Gi1/0/1      Up        1       Full      1000     Copper\n'
                                      'Gi1/0/2      Down      1       Auto      Auto     Copper'
        }
        mock_ssh_instance.cli.return_value = mock_cli_output
        self.driver.ssh = mock_ssh_instance
        self.driver.active_protocol = 'ssh'
        
        cli_output = self.driver.cli(['show version', 'show interfaces status'])
        mock_ssh_instance.cli.assert_called_once_with(['show version', 'show interfaces status'])
        self.assertEqual(cli_output, mock_cli_output)
        self.assertIn('HiOS (Hirschmann Open Source) Software', cli_output['show version'])
        self.assertIn('Interface    Status    VLAN    Duplex    Speed    Type', cli_output['show interfaces status'])

if __name__ == '__main__':
    unittest.main()
