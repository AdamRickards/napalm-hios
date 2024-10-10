import unittest
from napalm import get_network_driver

class TestHIOSIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Replace with actual device information
        cls.hostname = 'hios-switch.example.com'
        cls.username = 'admin'
        cls.password = 'password'

        cls.driver = get_network_driver('hios')
        cls.device = cls.driver(
            hostname=cls.hostname,
            username=cls.username,
            password=cls.password
        )
        cls.device.open()

    @classmethod
    def tearDownClass(cls):
        cls.device.close()

    def test_get_facts(self):
        facts = self.device.get_facts()
        self.assertIsInstance(facts, dict)
        self.assertIn('vendor', facts)
        self.assertEqual(facts['vendor'], 'Belden')

    def test_get_interfaces(self):
        interfaces = self.device.get_interfaces()
        self.assertIsInstance(interfaces, dict)
        self.assertTrue(len(interfaces) > 0)

    def test_get_snmp_information(self):
        snmp_info = self.device.get_snmp_information()
        self.assertIsInstance(snmp_info, dict)
        self.assertIn('system_description', snmp_info)

if __name__ == '__main__':
    unittest.main()
