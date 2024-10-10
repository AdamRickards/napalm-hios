import unittest
from unittest.mock import Mock, patch
from napalm_hios.netconf_hios import NetconfHIOS
from napalm.base.exceptions import ConnectionException

class TestNetconfHIOS(unittest.TestCase):
    def setUp(self):
        self.netconf = NetconfHIOS('144.6.66.129', 'admin', 'private', 60, port=11830)

    @patch('napalm_hios.netconf_hios.manager.connect')
    def test_open(self, mock_connect):
        self.netconf.open()
        mock_connect.assert_called_once_with(
            host='144.6.66.129',
            port=11830,
            username='admin',
            password='private',
            timeout=60,
            hostkey_verify=False
        )

    def test_close(self):
        self.netconf.connection = Mock()
        self.netconf.close()
        self.netconf.connection.close_session.assert_called_once()

    @patch('napalm_hios.netconf_hios.manager.connect')
    def test_get_facts(self, mock_connect):
        mock_connection = Mock()
        mock_connect.return_value = mock_connection
        mock_connection.get.return_value.data_xml = '<system-info><hostname>test-switch</hostname></system-info>'

        self.netconf.open()
        facts = self.netconf.get_facts()

        self.assertEqual(facts['vendor'], 'Belden')
        self.assertEqual(facts['model'], 'HiOS')

    def test_get_facts_no_connection(self):
        with self.assertRaises(ConnectionException):
            self.netconf.get_facts()

if __name__ == '__main__':
    unittest.main()
