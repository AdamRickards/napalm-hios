import unittest
from unittest.mock import Mock, patch, AsyncMock
import asyncio
from napalm_hios.snmp_hios import SNMPHIOS
from napalm.base.exceptions import ConnectionException
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, get_cmd,
)


class TestSNMPHIOS(unittest.TestCase):
    def setUp(self):
        self.snmp = SNMPHIOS('144.6.66.129', 'admin', 'private', 60, port=11161)

    @patch('napalm_hios.snmp_hios.SnmpEngine')
    def test_open(self, mock_engine):
        # open() calls asyncio.run which hits the network; patch _get_snmp_data_with_timeout
        with patch.object(self.snmp, '_get_snmp_data_with_timeout', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {'sysDescr': 'HiOS Switch'}
            self.snmp.open()
        mock_engine.assert_called_once()
        self.assertIsNotNone(self.snmp.engine)
        self.assertIsInstance(self.snmp.context, ContextData)

    def test_close(self):
        self.snmp.engine = Mock()
        self.snmp.close()
        self.assertIsNone(self.snmp.engine)

    @patch('napalm_hios.snmp_hios.SnmpEngine')
    def test_get_snmp_information(self, mock_engine):
        """Test get_snmp_information by mocking _get_snmp_data_with_timeout."""
        # Patch out the open() network call
        with patch.object(self.snmp, '_get_snmp_data_with_timeout', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {'sysDescr': 'HiOS Switch'}
            self.snmp.open()

        # Now mock the actual data fetch for get_snmp_information
        with patch('asyncio.run') as mock_run:
            mock_run.return_value = {
                'sysDescr': 'HiOS Switch',
                'sysName': 'GRS1042-CORE',
                'sysLocation': 'Lab',
                'sysContact': 'admin@example.com',
            }
            info = self.snmp.get_snmp_information()

        self.assertIn('system_description', info)
        self.assertEqual(info['system_description'], 'HiOS Switch')
        self.assertEqual(info['chassis_id'], 'GRS1042-CORE')

    def test_get_snmp_information_no_connection(self):
        with self.assertRaises(ConnectionException):
            self.snmp.get_snmp_information()


if __name__ == '__main__':
    unittest.main()
