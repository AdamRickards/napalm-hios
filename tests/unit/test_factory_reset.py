"""Unit tests for factory reset methods — clear_config / clear_factory."""

import unittest
from unittest.mock import Mock, patch, MagicMock

from napalm_hios.mops_hios import MOPSHIOS
from napalm_hios.snmp_hios import (
    SNMPHIOS,
    OID_hm2FMActionActivateKey, OID_hm2FMActionParameter,
    OID_hm2FMActionActivate_clear_config, OID_hm2FMActionActivate_clear_factory,
    OID_hm2FMNvmState, OID_hm2FMEnvmState, OID_hm2FMBootParamState,
)
from napalm_hios.hios import HIOSDriver
from napalm.base.exceptions import ConnectionException


# ======================================================================
# MOPS backend tests
# ======================================================================

class TestMOPSClearConfig(unittest.TestCase):
    """Test clear_config via MOPS backend."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_clear_config_default(self):
        """clear_config() delegates to client, returns restarting."""
        self.backend.client.clear_config.return_value = {"restarting": True}

        result = self.backend.clear_config()
        self.backend.client.clear_config.assert_called_once_with(keep_ip=False)
        self.assertTrue(result["restarting"])

    def test_clear_config_keep_ip(self):
        """clear_config(keep_ip=True) passes keep_ip to client."""
        self.backend.client.clear_config.return_value = {"restarting": True}

        result = self.backend.clear_config(keep_ip=True)
        self.backend.client.clear_config.assert_called_once_with(keep_ip=True)
        self.assertTrue(result["restarting"])

    def test_clear_config_returns_client_result(self):
        """Returns whatever the client returns."""
        self.backend.client.clear_config.return_value = {"restarting": True}

        result = self.backend.clear_config()
        self.assertIn("restarting", result)


class TestMOPSClearFactory(unittest.TestCase):
    """Test clear_factory via MOPS backend."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_clear_factory_default(self):
        """clear_factory() delegates to client."""
        self.backend.client.clear_factory.return_value = {"rebooting": True}

        result = self.backend.clear_factory()
        self.backend.client.clear_factory.assert_called_once_with(erase_all=False)
        self.assertTrue(result["rebooting"])

    def test_clear_factory_erase_all(self):
        """clear_factory(erase_all=True) passes flag to client."""
        self.backend.client.clear_factory.return_value = {"rebooting": True}

        result = self.backend.clear_factory(erase_all=True)
        self.backend.client.clear_factory.assert_called_once_with(erase_all=True)
        self.assertTrue(result["rebooting"])

    def test_clear_factory_returns_client_result(self):
        """Return whatever the client returns (device may reboot mid-response)."""
        self.backend.client.clear_factory.return_value = {
            "hm2FMActionActivateResult": "1",
            "hm2FMActionStatus": "1",
        }

        result = self.backend.clear_factory()
        self.assertIn("hm2FMActionActivateResult", result)


# ======================================================================
# SNMP backend tests
# ======================================================================

class TestSNMPClearConfig(unittest.TestCase):
    """Test clear_config via SNMP backend."""

    def setUp(self):
        self.snmp = SNMPHIOS("198.51.100.1", "admin", "private", timeout=10)

    def test_clear_config_default(self):
        """clear_config GETs key, SETs parameter + action, returns restarting."""
        async def mock_scalar(*oids):
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 42}
            return {}

        set_calls = []

        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                result = self.snmp.clear_config()

        # Verify parameter SET: none(1)
        self.assertEqual(set_calls[0], (OID_hm2FMActionParameter, 1))
        # Verify action SET with key
        self.assertEqual(set_calls[1], (OID_hm2FMActionActivate_clear_config, 42))
        # Verify result
        self.assertTrue(result['restarting'])

    def test_clear_config_keep_ip(self):
        """clear_config(keep_ip=True) SETs parameter to 11."""
        async def mock_scalar(*oids):
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 99}
            return {}

        set_calls = []

        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                result = self.snmp.clear_config(keep_ip=True)

        # Parameter should be keep-ip(11)
        self.assertEqual(set_calls[0], (OID_hm2FMActionParameter, 11))
        # Action should use key 99
        self.assertEqual(set_calls[1], (OID_hm2FMActionActivate_clear_config, 99))
        self.assertTrue(result['restarting'])

    def test_clear_config_set_sequence(self):
        """Verify correct order: key GET, parameter SET, action SET."""
        call_order = []

        async def mock_scalar(*oids):
            call_order.append(('get', oids))
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 7}
            return {}

        async def mock_set(oid, value):
            call_order.append(('set', oid))

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                self.snmp.clear_config()

        # Order: GET key → SET param → SET action (no status poll — device restarts)
        self.assertEqual(call_order[0][0], 'get')   # GET key
        self.assertEqual(call_order[1][0], 'set')   # SET parameter
        self.assertEqual(call_order[2][0], 'set')   # SET action
        self.assertEqual(len(call_order), 3)         # No status poll


class TestSNMPClearFactory(unittest.TestCase):
    """Test clear_factory via SNMP backend."""

    def setUp(self):
        self.snmp = SNMPHIOS("198.51.100.1", "admin", "private", timeout=10)

    def test_clear_factory_default(self):
        """clear_factory SETs parameter=none(1), then triggers factory reset."""
        async def mock_scalar(*oids):
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 55}
            return {}

        set_calls = []

        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                result = self.snmp.clear_factory()

        # Parameter: none(1)
        self.assertEqual(set_calls[0], (OID_hm2FMActionParameter, 1))
        # Action: factory reset OID with key
        self.assertEqual(set_calls[1], (OID_hm2FMActionActivate_clear_factory, 55))
        self.assertTrue(result["rebooting"])

    def test_clear_factory_erase_all(self):
        """clear_factory(erase_all=True) SETs parameter=all(2)."""
        async def mock_scalar(*oids):
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 33}
            return {}

        set_calls = []

        async def mock_set(oid, value):
            set_calls.append((oid, int(value)))

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                result = self.snmp.clear_factory(erase_all=True)

        # Parameter: all(2)
        self.assertEqual(set_calls[0], (OID_hm2FMActionParameter, 2))
        self.assertTrue(result["rebooting"])

    def test_clear_factory_handles_timeout(self):
        """Device may reboot before SNMP response — should return rebooting."""
        async def mock_scalar(*oids):
            if OID_hm2FMActionActivateKey in oids:
                return {OID_hm2FMActionActivateKey: 1}
            return {}

        async def mock_set(oid, value):
            if oid == OID_hm2FMActionActivate_clear_factory:
                raise ConnectionException("SNMP timeout")

        with patch.object(self.snmp, '_get_scalar', side_effect=mock_scalar):
            with patch.object(self.snmp, '_set_scalar', side_effect=mock_set):
                result = self.snmp.clear_factory()

        self.assertTrue(result["rebooting"])


# ======================================================================
# SSH backend tests
# ======================================================================

class TestSSHClearConfig(unittest.TestCase):
    """Test clear_config via SSH backend."""

    def setUp(self):
        self.ssh = MagicMock(spec=['write_channel', 'read_channel', 'send_command'])
        self.backend = object.__new__(type('SSHHIOS', (), {}))
        # Build a minimal SSHHIOS-like object for testing
        from napalm_hios.ssh_hios import SSHHIOS
        self.backend = SSHHIOS.__new__(SSHHIOS)
        self.backend.connection = self.ssh

    def test_clear_config_default(self):
        """clear_config sends 'clear config', handles Y/N, returns restarting."""
        read_responses = iter(['', 'clear config (Y/N) ?'])
        self.ssh.read_channel.side_effect = lambda: next(read_responses, '')
        self.ssh.send_command.return_value = ''

        with patch.object(type(self.backend), '_enable'):
            result = self.backend.clear_config()

        # Verify the command was written
        self.ssh.write_channel.assert_any_call('clear config\n')
        # Verify Y was sent
        self.ssh.write_channel.assert_any_call('y\n')
        self.assertTrue(result['restarting'])

    def test_clear_config_keep_ip(self):
        """clear_config(keep_ip=True) sends 'clear config keep-ip'."""
        read_responses = iter(['', 'clear config keep-ip (Y/N) ?'])
        self.ssh.read_channel.side_effect = lambda: next(read_responses, '')
        self.ssh.send_command.return_value = ''

        with patch.object(type(self.backend), '_enable'):
            result = self.backend.clear_config(keep_ip=True)

        self.ssh.write_channel.assert_any_call('clear config keep-ip\n')
        self.assertTrue(result['restarting'])

    def test_clear_config_no_connection_raises(self):
        """clear_config raises ConnectionException when SSH is not connected."""
        self.backend.connection = None
        with self.assertRaises(ConnectionException):
            self.backend.clear_config()


class TestSSHClearFactory(unittest.TestCase):
    """Test clear_factory via SSH backend."""

    def setUp(self):
        self.ssh = MagicMock(spec=['write_channel', 'read_channel', 'send_command'])
        from napalm_hios.ssh_hios import SSHHIOS
        self.backend = SSHHIOS.__new__(SSHHIOS)
        self.backend.connection = self.ssh

    def test_clear_factory_default(self):
        """clear_factory sends 'clear factory', confirms, returns rebooting."""
        read_responses = iter(['', 'clear factory (Y/N) ?'])
        self.ssh.read_channel.side_effect = lambda: next(read_responses, '')
        self.ssh.send_command.return_value = ''

        with patch.object(type(self.backend), '_enable'):
            result = self.backend.clear_factory()

        self.ssh.write_channel.assert_any_call('clear factory\n')
        self.ssh.write_channel.assert_any_call('y\n')
        self.assertTrue(result["rebooting"])

    def test_clear_factory_erase_all(self):
        """clear_factory(erase_all=True) sends 'clear factory erase-all'."""
        read_responses = iter(['', 'clear factory erase-all (Y/N) ?'])
        self.ssh.read_channel.side_effect = lambda: next(read_responses, '')
        self.ssh.send_command.return_value = ''

        with patch.object(type(self.backend), '_enable'):
            result = self.backend.clear_factory(erase_all=True)

        self.ssh.write_channel.assert_any_call('clear factory erase-all\n')
        self.assertTrue(result["rebooting"])

    def test_clear_factory_no_connection_raises(self):
        """clear_factory raises ConnectionException when SSH is not connected."""
        self.backend.connection = None
        with self.assertRaises(ConnectionException):
            self.backend.clear_factory()


# ======================================================================
# HIOSDriver dispatch tests
# ======================================================================

class TestDriverClearConfig(unittest.TestCase):
    """Test clear_config dispatch in HIOSDriver."""

    def setUp(self):
        self.device = HIOSDriver('localhost', 'admin', 'private')
        self.mock_connection = Mock()
        self.device._get_active_connection = Mock(return_value=self.mock_connection)

    def test_dispatch_mops(self):
        """MOPS protocol dispatches clear_config to MOPS backend."""
        self.device.active_protocol = 'mops'
        self.device.mops = self.mock_connection
        self.mock_connection.clear_config.return_value = {"restarting": True}

        result = self.device.clear_config()
        self.mock_connection.clear_config.assert_called_once_with(keep_ip=False)
        self.assertTrue(result['restarting'])
        self.assertTrue(result['disconnected'])

    def test_dispatch_ssh(self):
        """SSH protocol dispatches clear_config to SSH backend."""
        self.device.active_protocol = 'ssh'
        self.device.ssh = self.mock_connection
        self.mock_connection.clear_config.return_value = {"restarting": True}

        result = self.device.clear_config(keep_ip=True)
        self.mock_connection.clear_config.assert_called_once_with(keep_ip=True)
        self.assertTrue(result['restarting'])
        self.assertTrue(result['disconnected'])

    def test_dispatch_snmp(self):
        """SNMP protocol dispatches clear_config to SNMP backend."""
        self.device.active_protocol = 'snmp'
        self.device.snmp = self.mock_connection
        self.mock_connection.clear_config.return_value = {"restarting": True}

        result = self.device.clear_config()
        self.mock_connection.clear_config.assert_called_once_with(keep_ip=False)
        self.assertTrue(result['restarting'])
        self.assertTrue(result['disconnected'])

    def test_invalidates_connections(self):
        """clear_config invalidates all connections — driver is disconnected."""
        self.device.active_protocol = 'mops'
        self.device.mops = self.mock_connection
        self.mock_connection.clear_config.return_value = {"restarting": True}

        self.device.clear_config()
        self.assertIsNone(self.device.mops)
        self.assertIsNone(self.device.active_protocol)

    def test_dispatch_unsupported_protocol(self):
        """Unsupported protocol raises NotImplementedError."""
        self.device.active_protocol = 'netconf'
        with self.assertRaises(NotImplementedError):
            self.device.clear_config()


class TestDriverClearFactory(unittest.TestCase):
    """Test clear_factory dispatch in HIOSDriver."""

    def setUp(self):
        self.device = HIOSDriver('localhost', 'admin', 'private')
        self.mock_connection = Mock()
        self.device._get_active_connection = Mock(return_value=self.mock_connection)

    def test_dispatch_mops(self):
        """MOPS protocol dispatches clear_factory to MOPS backend."""
        self.device.active_protocol = 'mops'
        self.device.mops = self.mock_connection
        self.mock_connection.clear_factory.return_value = {"rebooting": True}

        result = self.device.clear_factory()
        self.mock_connection.clear_factory.assert_called_once_with(erase_all=False)
        self.assertTrue(result["rebooting"])
        self.assertTrue(result['disconnected'])

    def test_dispatch_ssh(self):
        """SSH protocol dispatches clear_factory to SSH backend."""
        self.device.active_protocol = 'ssh'
        self.device.ssh = self.mock_connection
        self.mock_connection.clear_factory.return_value = {"rebooting": True}

        result = self.device.clear_factory(erase_all=True)
        self.mock_connection.clear_factory.assert_called_once_with(erase_all=True)
        self.assertTrue(result['disconnected'])

    def test_dispatch_snmp(self):
        """SNMP protocol dispatches clear_factory to SNMP backend."""
        self.device.active_protocol = 'snmp'
        self.device.snmp = self.mock_connection
        self.mock_connection.clear_factory.return_value = {"rebooting": True}

        result = self.device.clear_factory()
        self.mock_connection.clear_factory.assert_called_once_with(erase_all=False)
        self.assertTrue(result['disconnected'])

    def test_invalidates_connections(self):
        """clear_factory invalidates all connections — driver is disconnected."""
        self.device.active_protocol = 'mops'
        self.device.mops = self.mock_connection
        self.mock_connection.clear_factory.return_value = {"rebooting": True}

        self.device.clear_factory()
        self.assertIsNone(self.device.mops)
        self.assertIsNone(self.device.active_protocol)

    def test_dispatch_unsupported_protocol(self):
        """Unsupported protocol raises NotImplementedError."""
        self.device.active_protocol = 'netconf'
        with self.assertRaises(NotImplementedError):
            self.device.clear_factory()


if __name__ == '__main__':
    unittest.main()
