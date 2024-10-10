import unittest
from unittest.mock import Mock, patch, AsyncMock
import asyncio
from napalm_hios.snmp_hios import SNMPHIOS
from napalm.base.exceptions import ConnectionException
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd

class TestSNMPHIOS(unittest.TestCase):
    def setUp(self):
        self.snmp = SNMPHIOS('144.6.66.129', 'admin', 'private', 60, port=11161)

    @patch('napalm_hios.snmp_hios.SnmpEngine')
    def test_open(self, mock_engine):
        self.snmp.open()
        mock_engine.assert_called_once()
        self.assertIsNotNone(self.snmp.engine)
        self.assertIsInstance(self.snmp.context, ContextData)

    def test_close(self):
        self.snmp.engine = Mock()
        self.snmp.close()
        self.assertIsNone(self.snmp.engine)

    @patch('napalm_hios.snmp_hios.getCmd', new_callable=AsyncMock)
    @patch('napalm_hios.snmp_hios.UdpTransportTarget.create', new_callable=AsyncMock)
    @patch('napalm_hios.snmp_hios.SnmpEngine')
    def test_get_snmp_information(self, mock_engine, mock_udp_create, mock_get_cmd):
        mock_get_cmd.return_value = (None, None, None, [('1.3.6.1.2.1.1.1.0', 'HiOS Switch')])
        mock_udp_create.return_value = Mock()

        self.snmp.open()
        info = self.snmp.get_snmp_information()

        self.assertIn('system_description', info)
        self.assertEqual(info['system_description'], 'HiOS Switch')

    def test_get_snmp_information_no_connection(self):
        with self.assertRaises(ConnectionException):
            self.snmp.get_snmp_information()

if __name__ == '__main__':
    unittest.main()
