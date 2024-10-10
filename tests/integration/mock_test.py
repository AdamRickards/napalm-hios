import unittest
from napalm.base.exceptions import ConnectionException
from napalm_hios.hios import HIOSDriver

class TestMockHIOSDevice(unittest.TestCase):

    def setUp(self):
        self.optional_args = {'protocol_preference': ['ssh', 'snmp', 'netconf']}
        self.driver = HIOSDriver('localhost', 'username', 'password', optional_args=self.optional_args)
        self.driver.open()

    def test_get_facts(self):
        facts = self.driver.get_facts()
        self.assertEqual(facts['vendor'], 'Belden')
        self.assertEqual(facts['model'], 'GRS1042-6T6ZTHH00V9HHSE3AMR')

    def test_get_interfaces(self):
        interfaces = self.driver.get_interfaces()
        self.assertIn('1/1', interfaces)
        self.assertEqual(interfaces['1/1']['speed'], 2500000000)

    def test_get_lldp_neighbors(self):
        neighbors = self.driver.get_lldp_neighbors()
        self.assertIn('1/7', neighbors)
        self.assertEqual(neighbors['1/7'][0]['hostname'], 'BRS50-LOUNGE')

    def test_get_environment(self):
        env = self.driver.get_environment()
        self.assertIn('cpu', env)
        self.assertIn('memory', env)
        self.assertEqual(env['temperature']['temperature'], 47.0)

    def test_get_interfaces_ip(self):
        interfaces_ip = self.driver.get_interfaces_ip()
        self.assertIn('vlan/1', interfaces_ip)
        self.assertEqual(interfaces_ip['vlan/1']['ipv4']['192.168.1.254']['prefix_length'], 24)

    def test_get_users(self):
        users = self.driver.get_users()
        self.assertIn('admin', users)
        self.assertEqual(users['admin']['level'], 15)

    def test_get_vlans(self):
        vlans = self.driver.get_vlans()
        self.assertIn(1, vlans)
        self.assertEqual(vlans[1]['name'], 'HOME')

    def tearDown(self):
        self.driver.close()

if __name__ == '__main__':
    unittest.main()
