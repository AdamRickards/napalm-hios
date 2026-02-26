"""Unit tests for factory onboarding across all protocols.

Tests cover:
- SSH: open() factory detection, is_factory_default(), onboard()
- SNMP: is_factory_default(), onboard()
- MOPS: tested in test_mops_client.py and test_mops_hios.py
- HIOSDriver: tested in test_hios_driver.py
"""

import unittest
from unittest.mock import Mock, patch, MagicMock

from napalm_hios.ssh_hios import SSHHIOS
from napalm_hios.snmp_hios import SNMPHIOS
from napalm.base.exceptions import ConnectionException


class TestSSHFactoryDetection(unittest.TestCase):
    """Test SSH open() catching the factory-fresh password prompt."""

    @patch('napalm_hios.ssh_hios.ConnectHandler')
    def test_open_factory_prompt_raises(self, mock_handler):
        """open() should raise ConnectionException with guidance when factory prompt detected."""
        mock_handler.side_effect = Exception(
            "Pattern not detected: 'Enter new password'"
        )
        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(ConnectionException) as ctx:
            ssh.open()
        self.assertIn("Factory-fresh device", str(ctx.exception))
        self.assertIn("onboard", str(ctx.exception))

    @patch('napalm_hios.ssh_hios.ConnectHandler')
    def test_open_factory_prompt_case_insensitive(self, mock_handler):
        """Factory detection should work with lowercase 'new password'."""
        mock_handler.side_effect = Exception(
            "got: 'enter new password for admin'"
        )
        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(ConnectionException) as ctx:
            ssh.open()
        self.assertIn("Factory-fresh device", str(ctx.exception))

    @patch('napalm_hios.ssh_hios.ConnectHandler')
    def test_open_normal_error_raises_generic(self, mock_handler):
        """Non-factory SSH errors should raise generic ConnectionException."""
        mock_handler.side_effect = Exception("Connection refused")
        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(ConnectionException) as ctx:
            ssh.open()
        self.assertIn("Cannot connect", str(ctx.exception))
        self.assertNotIn("Factory-fresh", str(ctx.exception))


class TestSSHIsFactoryDefault(unittest.TestCase):
    """Test SSH is_factory_default() — paramiko banner probe."""

    @patch('paramiko.SSHClient')
    def test_factory_default_true(self, mock_ssh_cls):
        """Banner containing 'Enter new password' → True."""
        mock_client = mock_ssh_cls.return_value
        mock_chan = Mock()
        mock_client.invoke_shell.return_value = mock_chan
        mock_chan.recv_ready.side_effect = [True, False]
        mock_chan.recv.return_value = b"\r\nEnter new password: "

        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.assertTrue(ssh.is_factory_default())
        mock_client.close.assert_called_once()

    @patch('paramiko.SSHClient')
    def test_factory_default_false(self, mock_ssh_cls):
        """Normal CLI prompt → False."""
        mock_client = mock_ssh_cls.return_value
        mock_chan = Mock()
        mock_client.invoke_shell.return_value = mock_chan
        mock_chan.recv_ready.side_effect = [True, False]
        mock_chan.recv.return_value = b"\r\nBRS50-Lab >"

        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.assertFalse(ssh.is_factory_default())
        mock_client.close.assert_called_once()

    @patch('paramiko.SSHClient')
    def test_factory_default_connection_failure(self, mock_ssh_cls):
        """Connection failure returns False (can't determine state)."""
        mock_ssh_cls.return_value.connect.side_effect = Exception("refused")

        ssh = SSHHIOS("198.51.100.1", "admin", "wrong", timeout=10)
        self.assertFalse(ssh.is_factory_default())


class TestSSHOnboard(unittest.TestCase):
    """Test SSH onboard() — interactive password change prompt handling."""

    @patch.object(SSHHIOS, 'open')
    @patch('paramiko.SSHClient')
    def test_onboard_success(self, mock_ssh_cls, mock_open):
        """Full prompt sequence → password changed → reconnect."""
        mock_client = mock_ssh_cls.return_value
        mock_chan = Mock()
        mock_client.invoke_shell.return_value = mock_chan

        # Banner with factory prompt
        mock_chan.recv_ready.side_effect = [True, False, True, False, True, False]
        mock_chan.recv.side_effect = [
            b"\r\nEnter new password: ",          # initial banner
            b"Confirm new password: ",             # after first send
            b"Password changed\r\nPlease login again",  # after confirm
        ]

        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        result = ssh.onboard("Private1")

        self.assertTrue(result)
        self.assertEqual(ssh.password, "Private1")
        mock_open.assert_called_once()  # should reconnect
        # Verify both password sends
        self.assertEqual(mock_chan.send.call_count, 2)

    @patch('paramiko.SSHClient')
    def test_onboard_no_factory_prompt(self, mock_ssh_cls):
        """If banner doesn't show factory prompt, raise ConnectionException."""
        mock_client = mock_ssh_cls.return_value
        mock_chan = Mock()
        mock_client.invoke_shell.return_value = mock_chan
        mock_chan.recv_ready.side_effect = [True, False]
        mock_chan.recv.return_value = b"\r\nBRS50-Lab >"

        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(ConnectionException) as ctx:
            ssh.onboard("Private1")
        self.assertIn("Expected factory password prompt", str(ctx.exception))
        mock_client.close.assert_called()

    @patch('paramiko.SSHClient')
    def test_onboard_connection_failure(self, mock_ssh_cls):
        """Connection failure during onboarding raises ConnectionException."""
        mock_ssh_cls.return_value.connect.side_effect = Exception("refused")

        ssh = SSHHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(ConnectionException) as ctx:
            ssh.onboard("Private1")
        self.assertIn("SSH onboarding failed", str(ctx.exception))


class TestSNMPIsFactoryDefault(unittest.TestCase):
    """Test SNMP is_factory_default() — agent-based detection."""

    def test_connected_returns_false(self):
        """If SNMP is connected, device is definitely onboarded."""
        snmp = SNMPHIOS("198.51.100.1", "admin", "private", timeout=10)
        snmp._connected = True
        self.assertFalse(snmp.is_factory_default())

    def test_not_connected_raises(self):
        """If SNMP not connected, raise with helpful message."""
        snmp = SNMPHIOS("198.51.100.1", "admin", "private", timeout=10)
        snmp._connected = False
        with self.assertRaises(ConnectionException) as ctx:
            snmp.is_factory_default()
        self.assertIn("not responding", str(ctx.exception))
        self.assertIn("factory-fresh", str(ctx.exception))


class TestSNMPOnboard(unittest.TestCase):
    """Test SNMP onboard() — always raises NotImplementedError."""

    def test_onboard_raises(self):
        """SNMP cannot onboard — agent is dead on factory devices."""
        snmp = SNMPHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(NotImplementedError) as ctx:
            snmp.onboard("Private1")
        self.assertIn("SNMP agent is disabled", str(ctx.exception))
        self.assertIn("MOPS or SSH", str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
