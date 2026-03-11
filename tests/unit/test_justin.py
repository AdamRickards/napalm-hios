"""Tests for JUSTIN interactive harden input collection and harden dispatch."""

import sys
import os
import unittest
from unittest.mock import MagicMock, patch, call

# Add tools/ to path so we can import justin
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'justin'))

from justin import (
    _prompt_value, _collect_harden_inputs, HARDEN_PROMPTS,
    harden_default_passwords, harden_snmpv3_auth, harden_snmpv3_encrypt,
    harden_snmpv3_traps, harden_crypto_ciphers, check_crypto_ciphers,
    check_port_security, check_dhcp_snooping, check_dai, check_ipsg,
    check_unused_ports, check_console_port, _resolve_hw_profile,
    HARDEN_DISPATCH, CHECK_FNS, _make_finding,
    _WEAK_TLS_VERSIONS, _WEAK_TLS_CIPHERS, _WEAK_SSH_KEX, _WEAK_SSH_HOST_KEY,
)


class _FakeFinding:
    """Minimal Finding stub for testing."""
    def __init__(self, check_id, passed=False, fix_cmd=None):
        self.check_id = check_id
        self.passed = passed
        self.fix_cmd = fix_cmd


# ---------------------------------------------------------------------------
# _prompt_value tests
# ---------------------------------------------------------------------------

class TestPromptValue(unittest.TestCase):

    @patch('justin.input', return_value='192.168.1.100')
    def test_plain_text_returns_value(self, mock_input):
        val = _prompt_value('NTP server', secret=False)
        self.assertEqual(val, '192.168.1.100')

    @patch('justin.input', return_value='')
    def test_plain_text_empty_returns_none(self, mock_input):
        val = _prompt_value('NTP server', secret=False)
        self.assertIsNone(val)

    @patch('justin.getpass.getpass', side_effect=['SecurePass!', 'SecurePass!'])
    def test_secret_matching_returns_value(self, mock_gp):
        val = _prompt_value('Password', secret=True)
        self.assertEqual(val, 'SecurePass!')
        self.assertEqual(mock_gp.call_count, 2)

    @patch('justin.getpass.getpass', side_effect=['', ])
    def test_secret_empty_returns_none(self, mock_gp):
        val = _prompt_value('Password', secret=True)
        self.assertIsNone(val)

    @patch('justin.getpass.getpass',
           side_effect=['pass1', 'wrong',   # first attempt: mismatch
                        'pass2', 'pass2'])   # retry: match
    def test_secret_mismatch_retries_once(self, mock_gp):
        val = _prompt_value('Password', secret=True)
        self.assertEqual(val, 'pass2')
        self.assertEqual(mock_gp.call_count, 4)

    @patch('justin.getpass.getpass',
           side_effect=['pass1', 'wrong',    # first attempt: mismatch
                        'pass2', 'also_wrong'])  # retry: still mismatch
    def test_secret_double_mismatch_skips(self, mock_gp):
        val = _prompt_value('Password', secret=True)
        self.assertIsNone(val)


# ---------------------------------------------------------------------------
# _collect_harden_inputs tests
# ---------------------------------------------------------------------------

class TestCollectHardenInputs(unittest.TestCase):

    def test_no_prompts_needed_returns_empty(self):
        """Checks with no HARDEN_PROMPTS entry need no input."""
        findings = [_FakeFinding('sec-hidiscovery')]
        config = {}
        skip, per_dev = _collect_harden_inputs(findings, config)
        self.assertEqual(skip, set())
        self.assertEqual(per_dev, {})

    def test_already_has_config_key_skips_prompt(self):
        """If config already has the key, no prompt needed."""
        findings = [_FakeFinding('sys-default-passwords')]
        config = {'harden_password': 'already-set'}
        skip, per_dev = _collect_harden_inputs(findings, config)
        self.assertEqual(skip, set())
        self.assertEqual(per_dev, {})

    @patch('justin._prompt_value', return_value='NewPass123!')
    def test_single_device_populates_config(self, mock_pv):
        """Single device mode stores value in config dict."""
        findings = [_FakeFinding('sys-default-passwords')]
        config = {}
        skip, per_dev = _collect_harden_inputs(findings, config)
        self.assertEqual(skip, set())
        self.assertEqual(config.get('harden_password'), 'NewPass123!')
        self.assertEqual(per_dev, {})

    @patch('justin._prompt_value', return_value=None)
    def test_single_device_skip_on_empty(self, mock_pv):
        """Single device: empty value skips the check."""
        findings = [_FakeFinding('sys-default-passwords')]
        config = {}
        skip, per_dev = _collect_harden_inputs(findings, config)
        self.assertIn('sys-default-passwords', skip)
        self.assertNotIn('harden_password', config)

    @patch('justin._prompt_value', return_value='SnmpPass!')
    def test_shared_key_prompted_once(self, mock_pv):
        """snmpv3-auth and snmpv3-encrypt share snmp_password — prompt once."""
        findings = [
            _FakeFinding('sec-snmpv3-auth'),
            _FakeFinding('sec-snmpv3-encrypt'),
        ]
        config = {}
        skip, per_dev = _collect_harden_inputs(findings, config)
        self.assertEqual(skip, set())
        self.assertEqual(config.get('snmp_password'), 'SnmpPass!')
        # _prompt_value called only once (shared key)
        mock_pv.assert_called_once()

    @patch('justin._prompt_value', return_value=None)
    def test_shared_key_skip_affects_both(self, mock_pv):
        """Skipping shared key skips all related checks."""
        findings = [
            _FakeFinding('sec-snmpv3-auth'),
            _FakeFinding('sec-snmpv3-encrypt'),
        ]
        config = {}
        skip, per_dev = _collect_harden_inputs(findings, config)
        self.assertIn('sec-snmpv3-auth', skip)
        self.assertIn('sec-snmpv3-encrypt', skip)

    @patch('justin._prompt_value', side_effect=['pw1', 'pw2', None])
    @patch('justin.input', return_value='p')  # per-device
    def test_fleet_per_device_collects_values(self, mock_input, mock_pv):
        """Fleet per-device mode: collect per-IP values."""
        findings = [_FakeFinding('sys-default-passwords')]
        config = {}
        ips = ['192.168.1.80', '192.168.1.81', '192.168.1.82']
        skip, per_dev = _collect_harden_inputs(
            findings, config, device_ips=ips)
        self.assertEqual(skip, set())
        self.assertEqual(per_dev.get('192.168.1.80', {}).get('harden_password'), 'pw1')
        self.assertEqual(per_dev.get('192.168.1.81', {}).get('harden_password'), 'pw2')
        self.assertNotIn('192.168.1.82', per_dev)  # skipped (None)

    @patch('justin.input', return_value='q')  # quit
    def test_fleet_quit_skips_check(self, mock_input):
        """Fleet Q skips the check entirely."""
        findings = [_FakeFinding('sys-default-passwords')]
        config = {}
        ips = ['192.168.1.80', '192.168.1.81']
        skip, per_dev = _collect_harden_inputs(
            findings, config, device_ips=ips)
        self.assertIn('sys-default-passwords', skip)

    @patch('justin._prompt_value', return_value='10.0.0.1')
    @patch('justin.input', return_value='s')  # site-wide
    def test_fleet_sitewide_stores_in_config(self, mock_input, mock_pv):
        """Fleet S stores in config dict."""
        findings = [_FakeFinding('sec-logging')]
        config = {}
        ips = ['192.168.1.80', '192.168.1.81']
        skip, per_dev = _collect_harden_inputs(
            findings, config, device_ips=ips)
        self.assertEqual(skip, set())
        self.assertEqual(config.get('syslog_server'), '10.0.0.1')
        self.assertEqual(per_dev, {})

    def test_string_check_ids_accepted(self):
        """Fleet mode passes check_id strings, not Finding objects."""
        config = {'syslog_server': 'already'}
        skip, per_dev = _collect_harden_inputs(
            ['sec-logging'], config)
        self.assertEqual(skip, set())


# ---------------------------------------------------------------------------
# Harden dispatch function tests
# ---------------------------------------------------------------------------

class TestHardenDefaultPasswords(unittest.TestCase):

    def test_registered(self):
        self.assertIn('sys-default-passwords', HARDEN_DISPATCH)

    def test_returns_none_without_config_key(self):
        device = MagicMock()
        result = harden_default_passwords(device, {}, {})
        self.assertIsNone(result)
        device.set_user.assert_not_called()

    def test_changes_default_password_users(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'default_password': True, 'active': True},
            {'name': 'operator', 'default_password': False, 'active': True},
        ]
        config = {'harden_password': 'N3wP@ss!'}
        result = harden_default_passwords(device, {}, config)
        device.set_user.assert_called_once_with('admin', password='N3wP@ss!')
        self.assertIn('admin', result)
        self.assertNotIn('operator', result)

    def test_no_defaults_found(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'default_password': False, 'active': True},
        ]
        config = {'harden_password': 'N3wP@ss!'}
        result = harden_default_passwords(device, {}, config)
        self.assertIn('no default', result)
        device.set_user.assert_not_called()

    def test_multiple_defaults(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'default_password': True, 'active': True},
            {'name': 'guest', 'default_password': True, 'active': True},
        ]
        config = {'harden_password': 'S3cure!'}
        result = harden_default_passwords(device, {}, config)
        self.assertEqual(device.set_user.call_count, 2)
        self.assertIn('admin', result)
        self.assertIn('guest', result)


class TestHardenSnmpv3Auth(unittest.TestCase):

    def test_registered(self):
        self.assertIn('sec-snmpv3-auth', HARDEN_DISPATCH)

    def test_returns_none_without_config_key(self):
        device = MagicMock()
        result = harden_snmpv3_auth(device, {}, {})
        self.assertIsNone(result)

    def test_upgrades_md5_users(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'snmp_auth': 'md5', 'active': True},
            {'name': 'monitor', 'snmp_auth': 'sha', 'active': True},
        ]
        config = {'snmp_password': 'AuthP@ss!'}
        result = harden_snmpv3_auth(device, {}, config)
        device.set_user.assert_called_once_with(
            'admin', snmp_auth_type='sha', snmp_auth_password='AuthP@ss!')
        self.assertIn('admin', result)
        self.assertNotIn('monitor', result)

    def test_all_already_sha(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'snmp_auth': 'sha', 'active': True},
        ]
        config = {'snmp_password': 'AuthP@ss!'}
        result = harden_snmpv3_auth(device, {}, config)
        self.assertIn('already', result)
        device.set_user.assert_not_called()

    def test_skips_inactive_users(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'snmp_auth': 'md5', 'active': False},
        ]
        config = {'snmp_password': 'AuthP@ss!'}
        result = harden_snmpv3_auth(device, {}, config)
        self.assertIn('already', result)
        device.set_user.assert_not_called()


class TestHardenSnmpv3Encrypt(unittest.TestCase):

    def test_registered(self):
        self.assertIn('sec-snmpv3-encrypt', HARDEN_DISPATCH)

    def test_returns_none_without_config_key(self):
        device = MagicMock()
        result = harden_snmpv3_encrypt(device, {}, {})
        self.assertIsNone(result)

    def test_upgrades_des_users(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'snmp_enc': 'des', 'active': True},
            {'name': 'monitor', 'snmp_enc': 'aes128', 'active': True},
        ]
        config = {'snmp_password': 'EncP@ss!'}
        result = harden_snmpv3_encrypt(device, {}, config)
        device.set_user.assert_called_once_with(
            'admin', snmp_enc_type='aes128', snmp_enc_password='EncP@ss!')
        self.assertIn('admin', result)

    def test_upgrades_none_enc_users(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'snmp_enc': 'none', 'active': True},
        ]
        config = {'snmp_password': 'EncP@ss!'}
        result = harden_snmpv3_encrypt(device, {}, config)
        device.set_user.assert_called_once()

    def test_all_already_aes(self):
        device = MagicMock()
        device.get_users.return_value = [
            {'name': 'admin', 'snmp_enc': 'aes128', 'active': True},
        ]
        config = {'snmp_password': 'EncP@ss!'}
        result = harden_snmpv3_encrypt(device, {}, config)
        self.assertIn('already', result)
        device.set_user.assert_not_called()


# ---------------------------------------------------------------------------
# HARDEN_PROMPTS registry tests
# ---------------------------------------------------------------------------

class TestHardenPrompts(unittest.TestCase):

    def test_all_prompted_checks_have_dispatch(self):
        """Every check in HARDEN_PROMPTS must also be in HARDEN_DISPATCH."""
        for cid in HARDEN_PROMPTS:
            self.assertIn(cid, HARDEN_DISPATCH,
                          f'{cid} in HARDEN_PROMPTS but not HARDEN_DISPATCH')

    def test_prompt_entries_have_required_keys(self):
        """Each prompt entry needs config_key, label, secret."""
        for cid, prompts in HARDEN_PROMPTS.items():
            for p in prompts:
                self.assertIn('config_key', p, f'{cid} missing config_key')
                self.assertIn('label', p, f'{cid} missing label')
                self.assertIn('secret', p, f'{cid} missing secret')

    def test_snmp_checks_share_key(self):
        """snmpv3-auth and snmpv3-encrypt share the snmp_password key."""
        auth_key = HARDEN_PROMPTS['sec-snmpv3-auth'][0]['config_key']
        enc_key = HARDEN_PROMPTS['sec-snmpv3-encrypt'][0]['config_key']
        self.assertEqual(auth_key, enc_key)
        self.assertEqual(auth_key, 'snmp_password')


class TestHardenSnmpv3Traps(unittest.TestCase):

    def test_registered(self):
        self.assertIn('sec-snmpv3-traps', HARDEN_DISPATCH)

    def test_returns_none_without_config_key(self):
        device = MagicMock()
        result = harden_snmpv3_traps(device, {}, {})
        self.assertIsNone(result)

    def test_adds_v3_trap_dest(self):
        """Creates v3 authpriv trap dest and enables trap service."""
        device = MagicMock()
        device.get_snmp_config.return_value = {
            'trap_service': False,
            'trap_destinations': [],
        }
        config = {'trap_dest_ip': '10.0.0.1'}
        result = harden_snmpv3_traps(device, {}, config)
        device.set_snmp_config.assert_called_once_with(trap_service=True)
        device.add_snmp_trap_dest.assert_called_once_with(
            'justin_10_0_0_1', '10.0.0.1',
            security_model='v3', security_name='admin',
            security_level='authpriv')
        self.assertIn('10.0.0.1', result)
        self.assertIn('trap service', result)

    def test_skips_existing_v3_dest(self):
        """Skips if v3 authpriv dest already exists for that IP."""
        device = MagicMock()
        device.get_snmp_config.return_value = {
            'trap_service': True,
            'trap_destinations': [{
                'name': 'nms1', 'address': '10.0.0.1:162',
                'security_model': 'v3', 'security_name': 'admin',
                'security_level': 'authpriv',
            }],
        }
        config = {'trap_dest_ip': '10.0.0.1'}
        result = harden_snmpv3_traps(device, {}, config)
        device.add_snmp_trap_dest.assert_not_called()
        self.assertIn('already exists', result)

    def test_adds_when_only_v1_exists(self):
        """Adds v3 dest even if v1 dest exists to same IP."""
        device = MagicMock()
        device.get_snmp_config.return_value = {
            'trap_service': True,
            'trap_destinations': [{
                'name': 'legacy', 'address': '10.0.0.1:162',
                'security_model': 'v1', 'security_name': 'public',
                'security_level': 'noauth',
            }],
        }
        config = {'trap_dest_ip': '10.0.0.1'}
        result = harden_snmpv3_traps(device, {}, config)
        device.add_snmp_trap_dest.assert_called_once()
        self.assertIn('add_snmp_trap_dest', result)

    def test_prompt_registered(self):
        """HARDEN_PROMPTS has trap_dest_ip config key."""
        prompts = HARDEN_PROMPTS.get('sec-snmpv3-traps', [])
        self.assertTrue(prompts)
        self.assertEqual(prompts[0]['config_key'], 'trap_dest_ip')
        self.assertFalse(prompts[0]['secret'])


class TestCheckCryptoCiphers(unittest.TestCase):

    def _make_spec(self):
        return {
            'id': 'sec-crypto-ciphers', 'severity': 'warning',
            'clause': 'CR 4.3', 'clause_title': 'Use of cryptography',
            'getter': 'get_services', 'desc': 'test',
        }

    def test_registered(self):
        self.assertIn('sec-crypto-ciphers', CHECK_FNS)
        self.assertIn('sec-crypto-ciphers', HARDEN_DISPATCH)

    def test_unable_when_no_data(self):
        finding = check_crypto_ciphers({'get_services': None}, self._make_spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_empty_cipher_lists_ssh_backend(self):
        """SSH backend returns empty cipher lists — reports unavailable."""
        svc = {
            'https': {'enabled': True, 'tls_versions': [], 'tls_cipher_suites': []},
            'ssh': {'enabled': True, 'hmac_algorithms': [], 'kex_algorithms': [],
                    'encryption_algorithms': [], 'host_key_algorithms': []},
        }
        finding = check_crypto_ciphers({'get_services': svc}, self._make_spec(), {})
        self.assertIn('unavailable', finding.desc.lower())

    def test_pass_strong_config(self):
        """All strong algorithms — should pass."""
        svc = {
            'https': {'enabled': True, 'tls_versions': ['tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'enabled': True, 'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ecdsa-sha2-nistp256', 'ssh-ed25519']},
        }
        finding = check_crypto_ciphers({'get_services': svc}, self._make_spec(), {})
        self.assertTrue(finding.passed)

    def test_fail_weak_tls_version(self):
        """TLS 1.0 enabled — should fail."""
        svc = {
            'https': {'enabled': True, 'tls_versions': ['tlsv1.0', 'tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'enabled': True, 'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ecdsa-sha2-nistp256']},
        }
        finding = check_crypto_ciphers({'get_services': svc}, self._make_spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('tlsv1.0', finding.desc)

    def test_fail_weak_tls_cipher(self):
        """RC4 cipher enabled — should fail."""
        svc = {
            'https': {'enabled': True, 'tls_versions': ['tlsv1.2'],
                      'tls_cipher_suites': ['tls-rsa-with-rc4-128-sha',
                                            'tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'enabled': True, 'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ecdsa-sha2-nistp256']},
        }
        finding = check_crypto_ciphers({'get_services': svc}, self._make_spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('rc4', finding.desc)

    def test_fail_weak_ssh_kex(self):
        """DH group1-sha1 — should fail."""
        svc = {
            'https': {'enabled': True, 'tls_versions': ['tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'enabled': True,
                    'kex_algorithms': ['diffie-hellman-group1-sha1', 'ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ecdsa-sha2-nistp256']},
        }
        finding = check_crypto_ciphers({'get_services': svc}, self._make_spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('group1', finding.desc)

    def test_fail_weak_ssh_host_key(self):
        """ssh-dss host key — should fail."""
        svc = {
            'https': {'enabled': True, 'tls_versions': ['tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'enabled': True, 'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ssh-dss', 'ecdsa-sha2-nistp256']},
        }
        finding = check_crypto_ciphers({'get_services': svc}, self._make_spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('ssh-dss', finding.desc)


class TestHardenCryptoCiphers(unittest.TestCase):

    def test_removes_weak_tls_versions(self):
        device = MagicMock()
        device.get_services.return_value = {
            'https': {'tls_versions': ['tlsv1.0', 'tlsv1.1', 'tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ecdsa-sha2-nistp256']},
        }
        result = harden_crypto_ciphers(device, {}, {})
        device.set_services.assert_called_once()
        kwargs = device.set_services.call_args[1]
        self.assertEqual(kwargs['tls_versions'], ['tlsv1.2'])
        self.assertNotIn('tls_cipher_suites', kwargs)

    def test_removes_weak_ssh_host_key(self):
        device = MagicMock()
        device.get_services.return_value = {
            'https': {'tls_versions': ['tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256']},
        }
        result = harden_crypto_ciphers(device, {}, {})
        kwargs = device.set_services.call_args[1]
        self.assertEqual(kwargs['ssh_host_key'], ['ecdsa-sha2-nistp256'])

    def test_noop_when_already_strong(self):
        device = MagicMock()
        device.get_services.return_value = {
            'https': {'tls_versions': ['tlsv1.2'],
                      'tls_cipher_suites': ['tls-ecdhe-rsa-with-aes-128-gcm-sha256']},
            'ssh': {'kex_algorithms': ['ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ecdsa-sha2-nistp256']},
        }
        result = harden_crypto_ciphers(device, {}, {})
        self.assertIsNone(result)
        device.set_services.assert_not_called()

    def test_removes_multiple_weak(self):
        """Removes weak from multiple categories at once."""
        device = MagicMock()
        device.get_services.return_value = {
            'https': {'tls_versions': ['tlsv1.0', 'tlsv1.2'],
                      'tls_cipher_suites': ['tls-rsa-with-rc4-128-sha',
                                            'tls-ecdhe-rsa-with-aes-256-gcm-sha384']},
            'ssh': {'kex_algorithms': ['diffie-hellman-group1-sha1', 'ecdh-sha2-nistp256'],
                    'host_key_algorithms': ['ssh-dss', 'ecdsa-sha2-nistp256']},
        }
        result = harden_crypto_ciphers(device, {}, {})
        kwargs = device.set_services.call_args[1]
        self.assertEqual(kwargs['tls_versions'], ['tlsv1.2'])
        self.assertEqual(kwargs['tls_cipher_suites'],
                         ['tls-ecdhe-rsa-with-aes-256-gcm-sha384'])
        self.assertEqual(kwargs['ssh_kex'], ['ecdh-sha2-nistp256'])
        self.assertEqual(kwargs['ssh_host_key'], ['ecdsa-sha2-nistp256'])
        self.assertIn('set_services', result)

    def test_empty_lists_noop(self):
        """Empty cipher lists (SSH backend) — nothing to harden."""
        device = MagicMock()
        device.get_services.return_value = {
            'https': {'tls_versions': [], 'tls_cipher_suites': []},
            'ssh': {'kex_algorithms': [], 'host_key_algorithms': []},
        }
        result = harden_crypto_ciphers(device, {}, {})
        self.assertIsNone(result)
        device.set_services.assert_not_called()


# ---------------------------------------------------------------------------
# ns-port-security check tests
# ---------------------------------------------------------------------------

class TestCheckPortSecurity(unittest.TestCase):

    def _spec(self):
        return {
            'id': 'ns-port-security', 'severity': 'warning',
            'clause': 'CR 7.1', 'clause_title': 'Denial of service protection',
            'getter': 'get_port_security', 'desc': 'test',
        }

    def test_registered(self):
        self.assertIn('ns-port-security', CHECK_FNS)

    def test_unable_when_no_data(self):
        finding = check_port_security(
            {'get_port_security': None}, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_unable_when_no_ports(self):
        finding = check_port_security(
            {'get_port_security': {'enabled': True, 'ports': {}}},
            self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_all_access_ports_enabled(self):
        """All access ports have port security enabled — PASS."""
        state = {
            'get_port_security': {
                'enabled': True, 'mode': 'mac-based',
                'ports': {
                    '1/1': {'enabled': True},
                    '1/2': {'enabled': True},
                    '1/3': {'enabled': True},
                },
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertTrue(finding.passed)
        self.assertIn('3 access', finding.desc)

    def test_some_ports_disabled(self):
        """Some access ports disabled — FAIL with port list."""
        state = {
            'get_port_security': {
                'enabled': True, 'mode': 'mac-based',
                'ports': {
                    '1/1': {'enabled': True},
                    '1/2': {'enabled': False},
                    '1/3': {'enabled': False},
                },
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('2/3', finding.desc)
        self.assertIn('1/2', finding.desc)

    def test_skips_lldp_uplinks(self):
        """Ports with LLDP neighbors are skipped (uplinks)."""
        state = {
            'get_port_security': {
                'enabled': True, 'mode': 'mac-based',
                'ports': {
                    '1/1': {'enabled': False},  # uplink — skip
                    '1/2': {'enabled': True},    # access — check
                },
            },
            'get_lldp_neighbors': {
                '1/1': [{'hostname': 'switch2'}],
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertTrue(finding.passed)
        self.assertIn('1 access', finding.desc)

    def test_skips_mrp_ring_ports(self):
        """MRP ring ports are skipped."""
        state = {
            'get_port_security': {
                'enabled': True, 'mode': 'mac-based',
                'ports': {
                    '1/5': {'enabled': False},  # ring — skip
                    '1/6': {'enabled': False},  # ring — skip
                    '1/1': {'enabled': True},   # access
                },
            },
            'get_mrp': {
                'default': {
                    'ring_port_1': {'interface': '1/5'},
                    'ring_port_2': {'interface': '1/6'},
                },
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertTrue(finding.passed)
        self.assertIn('1 access', finding.desc)

    def test_all_ports_are_uplinks(self):
        """All ports are uplinks/ring — PASS (no access ports to check)."""
        state = {
            'get_port_security': {
                'enabled': False, 'mode': 'mac-based',
                'ports': {
                    '1/1': {'enabled': False},
                    '1/2': {'enabled': False},
                },
            },
            'get_lldp_neighbors': {
                '1/1': [{'hostname': 'sw1'}],
                '1/2': [{'hostname': 'sw2'}],
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertTrue(finding.passed)
        self.assertIn('No access ports', finding.desc)

    def test_no_lldp_or_mrp_data(self):
        """Without LLDP/MRP data, all ports are treated as access."""
        state = {
            'get_port_security': {
                'enabled': True, 'mode': 'mac-based',
                'ports': {
                    '1/1': {'enabled': False},
                    '1/2': {'enabled': True},
                },
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('1/2', finding.desc)  # wait, 1/1 is the disabled one
        self.assertIn('1/1', finding.desc)

    def test_truncates_long_port_list(self):
        """More than 5 unprotected ports truncates with '+N more'."""
        ports = {f'1/{i}': {'enabled': False} for i in range(1, 9)}
        state = {
            'get_port_security': {
                'enabled': True, 'mode': 'mac-based', 'ports': ports,
            },
        }
        finding = check_port_security(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('+3 more', finding.desc)

    def test_no_harden_registered(self):
        """Harden is deferred — no entry in HARDEN_DISPATCH."""
        self.assertNotIn('ns-port-security', HARDEN_DISPATCH)


class TestCheckDhcpSnooping(unittest.TestCase):
    """Tests for ns-dhcp-snooping check."""

    def _spec(self, **overrides):
        s = {
            'id': 'ns-dhcp-snooping', 'clause': 'CR 3.1',
            'clause_title': 'Communication integrity',
            'severity': 'warning', 'sl': 1, 'source': 'vendor',
            'desc': 'DHCP snooping test',
        }
        s.update(overrides)
        return s

    def test_registered(self):
        self.assertIn('ns-dhcp-snooping', CHECK_FNS)

    def test_unable_no_data(self):
        finding = check_dhcp_snooping({}, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_unable_no_ports(self):
        state = {'get_dhcp_snooping': {'enabled': True, 'ports': {}}}
        finding = check_dhcp_snooping(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_globally_disabled(self):
        state = {'get_dhcp_snooping': {
            'enabled': False,
            'ports': {'1/1': {'trusted': False}},
        }}
        finding = check_dhcp_snooping(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('globally disabled', finding.desc)

    def test_correct_trust_model(self):
        """Uplinks trusted, access untrusted => PASS."""
        state = {
            'get_dhcp_snooping': {
                'enabled': True,
                'ports': {
                    '1/1': {'trusted': True},    # uplink
                    '1/2': {'trusted': False},   # access
                    '1/3': {'trusted': False},   # access
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_dhcp_snooping(state, self._spec(), {})
        self.assertTrue(finding.passed)
        self.assertIn('correct trust model', finding.desc)

    def test_untrusted_uplink(self):
        """Uplink not trusted => FAIL."""
        state = {
            'get_dhcp_snooping': {
                'enabled': True,
                'ports': {
                    '1/1': {'trusted': False},   # uplink but untrusted
                    '1/2': {'trusted': False},
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_dhcp_snooping(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('uplink 1/1 not trusted', finding.desc)

    def test_trusted_access_port(self):
        """Access port trusted => FAIL."""
        state = {
            'get_dhcp_snooping': {
                'enabled': True,
                'ports': {
                    '1/1': {'trusted': True},    # uplink
                    '1/2': {'trusted': True},    # access but trusted!
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_dhcp_snooping(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('access port(s) trusted', finding.desc)
        self.assertIn('1/2', finding.desc)

    def test_skips_mrp_ring_ports(self):
        """MRP ring ports treated as uplinks (should be trusted)."""
        state = {
            'get_dhcp_snooping': {
                'enabled': True,
                'ports': {
                    '1/5': {'trusted': True},    # ring port
                    '1/6': {'trusted': True},    # ring port
                    '1/1': {'trusted': False},   # access
                },
            },
            'get_mrp': {'domain1': {
                'ring_port_1': {'interface': '1/5'},
                'ring_port_2': {'interface': '1/6'},
            }},
        }
        finding = check_dhcp_snooping(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_no_harden_registered(self):
        """Harden is deferred — no entry in HARDEN_DISPATCH."""
        self.assertNotIn('ns-dhcp-snooping', HARDEN_DISPATCH)


class TestCheckDai(unittest.TestCase):
    """Tests for ns-dai check."""

    def _spec(self, **overrides):
        s = {
            'id': 'ns-dai', 'clause': 'CR 3.1',
            'clause_title': 'Communication integrity',
            'severity': 'warning', 'sl': 1, 'source': 'vendor',
            'desc': 'DAI test',
        }
        s.update(overrides)
        return s

    def test_registered(self):
        self.assertIn('ns-dai', CHECK_FNS)

    def test_unable_no_data(self):
        finding = check_dai({}, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_unable_no_ports(self):
        state = {'get_arp_inspection': {'vlans': {}, 'ports': {}}}
        finding = check_dai(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_no_vlan_enabled(self):
        """DAI not enabled on any VLAN => FAIL."""
        state = {'get_arp_inspection': {
            'vlans': {1: {'enabled': False}},
            'ports': {'1/1': {'trusted': False}},
        }}
        finding = check_dai(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('not enabled on any VLAN', finding.desc)

    def test_correct_trust_model(self):
        """Uplinks trusted, access untrusted => PASS."""
        state = {
            'get_arp_inspection': {
                'vlans': {1: {'enabled': True}},
                'ports': {
                    '1/1': {'trusted': True},    # uplink
                    '1/2': {'trusted': False},   # access
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_dai(state, self._spec(), {})
        self.assertTrue(finding.passed)
        self.assertIn('correct trust model', finding.desc)

    def test_untrusted_uplink(self):
        """Uplink not trusted => FAIL."""
        state = {
            'get_arp_inspection': {
                'vlans': {1: {'enabled': True}},
                'ports': {
                    '1/1': {'trusted': False},
                    '1/2': {'trusted': False},
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_dai(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('uplink 1/1 not trusted', finding.desc)

    def test_trusted_access_port(self):
        """Access port trusted => FAIL."""
        state = {
            'get_arp_inspection': {
                'vlans': {1: {'enabled': True}},
                'ports': {
                    '1/1': {'trusted': True},    # uplink
                    '1/2': {'trusted': True},    # access but trusted
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_dai(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('access port(s) trusted', finding.desc)

    def test_no_harden_registered(self):
        self.assertNotIn('ns-dai', HARDEN_DISPATCH)


class TestCheckIpsg(unittest.TestCase):
    """Tests for ns-ipsg check."""

    def _spec(self, **kw):
        return {'id': 'ns-ipsg', 'clause': 'CR 3.1',
                'clause_title': 'Communication integrity',
                'severity': 'warning', **kw}

    def test_registered(self):
        self.assertIn('ns-ipsg', CHECK_FNS)

    def test_unable_no_data(self):
        finding = check_ipsg({}, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_unable_no_ports(self):
        state = {'get_ip_source_guard': {'ports': {}}}
        finding = check_ipsg(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_all_access_unprotected(self):
        state = {
            'get_ip_source_guard': {
                'ports': {
                    '1/1': {'verify_source': False, 'port_security': False},
                    '1/2': {'verify_source': False, 'port_security': False},
                },
            },
        }
        finding = check_ipsg(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('IPSG disabled', finding.desc)

    def test_all_access_protected(self):
        state = {
            'get_ip_source_guard': {
                'ports': {
                    '1/1': {'verify_source': True, 'port_security': False},
                    '1/2': {'verify_source': True, 'port_security': False},
                },
            },
        }
        finding = check_ipsg(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_uplinks_excluded(self):
        """Uplinks (LLDP neighbors) don't need IPSG — only access ports."""
        state = {
            'get_ip_source_guard': {
                'ports': {
                    '1/1': {'verify_source': False, 'port_security': False},
                    '1/2': {'verify_source': True, 'port_security': False},
                },
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_ipsg(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_skips_mrp_ring_ports(self):
        """MRP ring ports excluded from check."""
        state = {
            'get_ip_source_guard': {
                'ports': {
                    '1/5': {'verify_source': False, 'port_security': False},
                    '1/6': {'verify_source': False, 'port_security': False},
                    '1/1': {'verify_source': True, 'port_security': False},
                },
            },
            'get_mrp': {'domain0': {
                'ring_port_1': {'interface': '1/5'},
                'ring_port_2': {'interface': '1/6'},
            }},
        }
        finding = check_ipsg(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_no_harden_registered(self):
        self.assertNotIn('ns-ipsg', HARDEN_DISPATCH)


# ---------------------------------------------------------------------------
# sec-unused-ports check
# ---------------------------------------------------------------------------

class TestCheckUnusedPorts(unittest.TestCase):
    """Tests for sec-unused-ports check."""

    def _spec(self, **kw):
        return {'id': 'sec-unused-ports', 'clause': 'CR 7.7',
                'clause_title': 'Least functionality',
                'severity': 'warning', **kw}

    def test_registered(self):
        self.assertIn('sec-unused-ports', CHECK_FNS)

    def test_unable_no_data(self):
        finding = check_unused_ports({}, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_all_ports_linked(self):
        """All ports have link — none unused."""
        state = {
            'get_interfaces': {
                '1/1': {'is_enabled': True, 'is_up': True},
                '1/2': {'is_enabled': True, 'is_up': True},
            },
        }
        finding = check_unused_ports(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_unused_ports_detected(self):
        """Admin-enabled ports with no link are flagged."""
        state = {
            'get_interfaces': {
                '1/1': {'is_enabled': True, 'is_up': False},
                '1/2': {'is_enabled': True, 'is_up': True},
                '1/3': {'is_enabled': True, 'is_up': False},
            },
        }
        finding = check_unused_ports(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('2 unused', finding.desc)
        self.assertIn('1/1', finding.desc)
        self.assertIn('1/3', finding.desc)

    def test_already_disabled_not_counted(self):
        """Admin-disabled ports are already secured — not flagged."""
        state = {
            'get_interfaces': {
                '1/1': {'is_enabled': False, 'is_up': False},
                '1/2': {'is_enabled': True, 'is_up': True},
            },
        }
        finding = check_unused_ports(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_lldp_neighbors_excluded(self):
        """Ports with LLDP neighbors are uplinks — excluded."""
        state = {
            'get_interfaces': {
                '1/1': {'is_enabled': True, 'is_up': False},
                '1/2': {'is_enabled': True, 'is_up': False},
            },
            'get_lldp_neighbors': {'1/1': [{'hostname': 'sw2'}]},
        }
        finding = check_unused_ports(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('1 unused', finding.desc)
        self.assertIn('1/2', finding.desc)
        self.assertNotIn('1/1', finding.desc)

    def test_mrp_ring_ports_excluded(self):
        """MRP ring ports are excluded from unused check."""
        state = {
            'get_interfaces': {
                '1/5': {'is_enabled': True, 'is_up': False},
                '1/6': {'is_enabled': True, 'is_up': False},
                '1/1': {'is_enabled': True, 'is_up': True},
            },
            'get_mrp': {'domain0': {
                'ring_port_1': {'interface': '1/5'},
                'ring_port_2': {'interface': '1/6'},
            }},
        }
        finding = check_unused_ports(state, self._spec(), {})
        self.assertTrue(finding.passed)

    def test_no_harden_registered(self):
        self.assertNotIn('sec-unused-ports', HARDEN_DISPATCH)


# ---------------------------------------------------------------------------
# sec-console-port check
# ---------------------------------------------------------------------------

class TestCheckConsolePort(unittest.TestCase):
    """Tests for sec-console-port check."""

    def _spec(self, **kw):
        return {'id': 'sec-console-port', 'clause': 'EDR 2.13',
                'clause_title': 'Physical diagnostic port control',
                'severity': 'warning', **kw}

    def test_registered(self):
        self.assertIn('sec-console-port', CHECK_FNS)

    def test_unable_no_data(self):
        finding = check_console_port({}, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Unable', finding.desc)

    def test_pass_serial_timeout_envm_disabled(self):
        """PASS when serial timeout set and ENVM disabled."""
        state = {
            'get_session_config': {
                'serial': {'timeout': 5, 'enabled': True, 'oper_status': True},
                'envm': {'enabled': False, 'oper_status': False},
            },
        }
        config = {'_device_info': {'model': 'BRS50-8TX'}}
        finding = check_console_port(state, self._spec(), config)
        self.assertTrue(finding.passed)
        self.assertIn('serial timeout=5m', finding.desc)

    def test_fail_serial_timeout_zero(self):
        """FAIL when serial timeout is 0 (infinite session)."""
        state = {
            'get_session_config': {
                'serial': {'timeout': 0, 'enabled': True},
                'envm': {'enabled': False},
            },
        }
        finding = check_console_port(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Serial timeout disabled', finding.desc)

    def test_fail_envm_enabled(self):
        """FAIL when external storage is enabled."""
        state = {
            'get_session_config': {
                'serial': {'timeout': 5},
                'envm': {'enabled': True},
            },
        }
        config = {'_device_info': {'model': 'GRS1042-AT'}}
        finding = check_console_port(state, self._spec(), config)
        self.assertFalse(finding.passed)
        self.assertIn('External storage enabled', finding.desc)
        self.assertIn('usb_a_sd', finding.desc)

    def test_fail_both_issues(self):
        """FAIL with both serial timeout and ENVM issues."""
        state = {
            'get_session_config': {
                'serial': {'timeout': 0},
                'envm': {'enabled': True},
            },
        }
        finding = check_console_port(state, self._spec(), {})
        self.assertFalse(finding.passed)
        self.assertIn('Serial timeout disabled', finding.desc)
        self.assertIn('external storage enabled', finding.desc)

    def test_hw_profile_resolve_brs(self):
        hw = _resolve_hw_profile('BRS50-8TX')
        self.assertEqual(hw['console'], 'usb_c')
        self.assertEqual(hw['aca'], 'usb_c')

    def test_hw_profile_resolve_grs1042(self):
        hw = _resolve_hw_profile('GRS1042-AT')
        self.assertEqual(hw['console'], 'v24_rj45')
        self.assertEqual(hw['aca'], 'usb_a_sd')
        self.assertEqual(hw['oob'], 'ethernet_rj45')

    def test_hw_profile_resolve_dragon(self):
        hw = _resolve_hw_profile('DRAGON M12')
        self.assertEqual(hw['console'], 'v24_rj45')

    def test_hw_profile_resolve_unknown(self):
        hw = _resolve_hw_profile('UNKNOWN-SW')
        self.assertIsNone(hw)

    def test_hw_profile_resolve_empty(self):
        hw = _resolve_hw_profile('')
        self.assertIsNone(hw)

    def test_model_in_pass_desc(self):
        """Model name appears in the pass description."""
        state = {
            'get_session_config': {
                'serial': {'timeout': 5},
                'envm': {'enabled': False},
            },
        }
        config = {'_device_info': {'model': 'BRS50-8TX'}}
        finding = check_console_port(state, self._spec(), config)
        self.assertTrue(finding.passed)
        self.assertIn('BRS50-8TX', finding.desc)


if __name__ == '__main__':
    unittest.main()
