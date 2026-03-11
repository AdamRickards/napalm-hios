import unittest
from unittest.mock import Mock
import os
import logging
import re
import time
from napalm_hios.ssh_hios import SSHHIOS
from napalm.base.exceptions import ConnectionException

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@unittest.skipUnless(os.environ.get('HIOS_HOSTNAME'),
                     "Live SSH test — set HIOS_HOSTNAME to run")
class TestSSHHIOS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hostname = os.environ['HIOS_HOSTNAME']
        cls.username = os.environ.get('HIOS_USERNAME', 'admin')
        cls.password = os.environ.get('HIOS_PASSWORD', 'private')
        cls.port = int(os.environ.get('HIOS_SSH_PORT', 22))
        cls.ssh = SSHHIOS(cls.hostname, cls.username, cls.password, 180, port=cls.port)
        cls.test_results = []
        try:
            logger.info(f"Attempting to connect to {cls.hostname}:{cls.port}")
            cls.ssh.open()
            logger.info("Successfully connected to the device")
        except Exception as e:
            raise unittest.SkipTest(f"Device not reachable: {e}")

    @classmethod
    def tearDownClass(cls):
        if cls.ssh.connection:
            cls.ssh.close()
            logger.info("Closed the SSH connection")
        cls.write_test_results()

    @classmethod
    def write_test_results(cls):
        with open('testresults.md', 'w') as f:
            f.write("# SSH HIOS Test Results\n\n")
            for result in cls.test_results:
                f.write(f"## {result['test_name']}\n")
                f.write(f"Status: {'Passed' if result['passed'] else 'Failed'}\n")
                f.write(f"Details: {result['details']}\n\n")
                f.write(f"Prompt: {result['find_prompt']}\n\n")

    def test_basic_connectivity(self):
        try:
            self.assertIsNotNone(self.ssh.connection, "Failed to establish SSH connection")
            logger.info("Connection established successfully")

            logger.info("Attempting to find initial prompt")
            initial_prompt = self.ssh.connection.find_prompt()
            logger.info(f"Initial prompt: {initial_prompt}")
            self.assertTrue(initial_prompt.endswith('>') or initial_prompt.endswith('#'),
                            "Initial prompt should end with '>' or '#'")

            logger.info("Attempting to enter privileged mode")
            try:
                # Try entering enable mode directly
                self.ssh.connection.enable()
                logger.info("Sent enable command successfully")
                time.sleep(2)  # Add a small delay after enable command
            except Exception as enable_error:
                # Log the error and try with password
                logger.error(f"Error during enable: {str(enable_error)}")
                logger.info("Attempting to enter privileged mode with password")
                try:
                    self.ssh.connection.enable(cmd='enable', pattern='Password:', re_flags=re.IGNORECASE)
                    self.ssh.connection.send_command(self.ssh.password, expect_string=r'#')
                    logger.info("Entered privileged mode with password successfully")
                    time.sleep(2)
                except Exception as second_error:
                    logger.error(f"Failed to enter privileged mode: {str(second_error)}")
                    raise second_error  # Raise the exception to log it in the outer block

            # Check prompt after entering enable mode
            enabled_prompt = self.ssh.connection.find_prompt()
            logger.info(f"Prompt after enable: {enabled_prompt}")

            # Check if the prompt is in privileged mode (i.e., ends with '#')
            self.assertTrue(enabled_prompt.endswith('#'), "Enabled prompt should end with '#'")

            logger.info("Basic connectivity test passed successfully")
            self.test_results.append({
                'test_name': 'Basic Connectivity',
                'passed': True,
                'details': f"Initial prompt: {initial_prompt}, Enabled prompt: {enabled_prompt}"
            })
        except Exception as e:
            logger.error(f"Basic connectivity test failed with error: {str(e)}")
            self.test_results.append({
                'test_name': 'Basic Connectivity',
                'passed': False,
                'details': f"Error: {str(e)}"
            })
            self.fail(f"Basic connectivity test failed with error: {str(e)}")

    def test_get_interfaces(self):
        try:
            logger.info("Attempting to get interfaces")
            interfaces, port_count = self.ssh.get_interfaces()
            self.assertIsInstance(interfaces, dict)
            self.assertGreater(len(interfaces), 0)
            self.assertGreater(port_count, 0)
            logger.info(f"Retrieved {port_count} interfaces successfully")
            logger.debug(f"Interfaces: {interfaces}")
            self.test_results.append({
                'test_name': 'Get Interfaces',
                'passed': True,
                'details': f"Retrieved {port_count} interfaces"
            })
        except Exception as e:
            logger.error(f"get_interfaces test failed with error: {str(e)}")
            self.test_results.append({
                'test_name': 'Get Interfaces',
                'passed': False,
                'details': f"Error: {str(e)}"
            })
            self.fail(f"get_interfaces test failed with error: {str(e)}")

class TestSSHDns(unittest.TestCase):
    """Test SSH DNS client getter/setter/CRUD with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        """Helper: set up cli mock that returns dict keyed by command."""
        def cli_fn(cmds):
            if isinstance(cmds, str):
                cmds = [cmds]
            return {cmd: responses.get(cmd, '') for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)

    # --- get_dns ---

    def test_get_dns_factory_defaults(self):
        """get_dns factory defaults — disabled, no servers."""
        self._mock_cli({
            'show dns client info': (
                'DNS client status...........................disabled\n'
                'DNS client cache status.....................enabled\n'
                'DNS client configuration source.............mgmt-dhcp\n'
                'DNS client default domain name..............\n'
                'DNS client timeout (seconds)................3\n'
                'DNS client request retransmits number.......2\n'
            ),
            'show dns client servers': (
                'No.                  IP address                Active            \n'
                '---  ----------------------------------------  ------\n'
                '\n'
                'No entry.\n'
            ),
            'show dns client servers extern': (
                'No.  Address  \n'
                '---  ----------------------------------------\n'
            ),
        })
        result = self.ssh.get_dns()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['config_source'], 'mgmt-dhcp')
        self.assertEqual(result['domain_name'], '')
        self.assertEqual(result['timeout'], 3)
        self.assertEqual(result['retransmits'], 2)
        self.assertTrue(result['cache_enabled'])
        self.assertEqual(result['servers'], [])
        self.assertEqual(result['active_servers'], [])

    def test_get_dns_with_server(self):
        """get_dns with DNS enabled and a configured server."""
        self._mock_cli({
            'show dns client info': (
                'DNS client status...........................enabled\n'
                'DNS client cache status.....................disabled\n'
                'DNS client configuration source.............user\n'
                'DNS client default domain name..............test.local\n'
                'DNS client timeout (seconds)................5\n'
                'DNS client request retransmits number.......3\n'
            ),
            'show dns client servers': (
                'No.                  IP address                Active            \n'
                '---  ----------------------------------------  ------\n'
                '  1  192.168.3.1                               [x]\n'
            ),
            'show dns client servers extern': (
                'No.  Address  \n'
                '---  ----------------------------------------\n'
            ),
        })
        result = self.ssh.get_dns()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['config_source'], 'user')
        self.assertEqual(result['domain_name'], 'test.local')
        self.assertEqual(result['timeout'], 5)
        self.assertEqual(result['retransmits'], 3)
        self.assertFalse(result['cache_enabled'])
        self.assertEqual(result['servers'], ['192.168.3.1'])
        self.assertEqual(result['active_servers'], ['192.168.3.1'])

    def test_get_dns_multiple_servers(self):
        """get_dns returns multiple servers, only active ones marked."""
        self._mock_cli({
            'show dns client info': (
                'DNS client status...........................enabled\n'
                'DNS client cache status.....................enabled\n'
                'DNS client configuration source.............user\n'
                'DNS client default domain name..............\n'
                'DNS client timeout (seconds)................3\n'
                'DNS client request retransmits number.......2\n'
            ),
            'show dns client servers': (
                'No.                  IP address                Active            \n'
                '---  ----------------------------------------  ------\n'
                '  1  192.168.3.1                               [x]\n'
                '  2  10.0.0.1                                  [ ]\n'
            ),
            'show dns client servers extern': (
                'No.  Address  \n'
                '---  ----------------------------------------\n'
            ),
        })
        result = self.ssh.get_dns()
        self.assertEqual(result['servers'],
                         ['192.168.3.1', '10.0.0.1'])
        self.assertEqual(result['active_servers'], ['192.168.3.1'])

    # --- set_dns ---

    def test_set_dns_enable(self):
        """set_dns enables DNS client via CLI."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_dns(enabled=True)
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any('dns client adminstate' in c
                            and 'no ' not in c for c in cli_calls))

    def test_set_dns_disable(self):
        """set_dns disables DNS client via CLI."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_dns(enabled=False)
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any('no dns client adminstate' in c
                            for c in cli_calls))

    def test_set_dns_multiple_fields(self):
        """set_dns sends correct CLI commands for multiple fields."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_dns(timeout=10, cache_enabled=False)
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any('dns client timeout 10' in c
                            for c in cli_calls))
        self.assertTrue(any('no dns client cache adminstate' in c
                            for c in cli_calls))

    def test_set_dns_invalid_config_source(self):
        """set_dns raises ValueError for invalid config_source."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        with self.assertRaises(ValueError):
            self.ssh.set_dns(config_source='invalid')

    # --- add_dns_server ---

    def test_add_dns_server_empty_table(self):
        """add_dns_server picks index 1 when table is empty."""
        table_empty = (
            'No.                  IP address                Active            \n'
            '---  ----------------------------------------  ------\n'
            '\n'
            'No entry.\n'
        )
        call_log = []
        def cli_fn(cmds):
            if isinstance(cmds, str):
                call_log.append(cmds)
                if 'show' in cmds:
                    return {cmds: table_empty}
                return {cmds: ''}
            return {cmd: table_empty if 'show' in cmd else ''
                    for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)
        self.ssh._in_config_mode = False
        self.ssh.add_dns_server('192.168.3.1')
        self.assertTrue(any(
            'dns client servers add 1 ip 192.168.3.1' in c
            for c in call_log))

    def test_add_dns_server_picks_next_free(self):
        """add_dns_server skips used index 1, picks 2."""
        table_one = (
            'No.                  IP address                Active            \n'
            '---  ----------------------------------------  ------\n'
            '  1  192.168.3.1                               [x]\n'
        )
        call_log = []
        def cli_fn(cmds):
            if isinstance(cmds, str):
                call_log.append(cmds)
                if 'show' in cmds:
                    return {cmds: table_one}
                return {cmds: ''}
            return {cmd: table_one if 'show' in cmd else ''
                    for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)
        self.ssh._in_config_mode = False
        self.ssh.add_dns_server('10.0.0.1')
        self.assertTrue(any(
            'dns client servers add 2 ip 10.0.0.1' in c
            for c in call_log))

    def test_add_dns_server_full_table(self):
        """add_dns_server raises ValueError when all 4 slots used."""
        table_full = (
            'No.                  IP address                Active            \n'
            '---  ----------------------------------------  ------\n'
            '  1  192.168.3.1                               [x]\n'
            '  2  10.0.0.1                                  [ ]\n'
            '  3  10.0.0.2                                  [ ]\n'
            '  4  10.0.0.3                                  [ ]\n'
        )
        def cli_fn(cmds):
            if isinstance(cmds, str):
                if 'show' in cmds:
                    return {cmds: table_full}
                return {cmds: ''}
            return {cmd: table_full if 'show' in cmd else ''
                    for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)
        self.ssh._in_config_mode = False
        with self.assertRaises(ValueError) as ctx:
            self.ssh.add_dns_server('10.0.0.5')
        self.assertIn('4 DNS server slots', str(ctx.exception))

    # --- delete_dns_server ---

    def test_delete_dns_server(self):
        """delete_dns_server finds correct index and deletes."""
        table_two = (
            'No.                  IP address                Active            \n'
            '---  ----------------------------------------  ------\n'
            '  1  192.168.3.1                               [x]\n'
            '  2  10.0.0.1                                  [ ]\n'
        )
        call_log = []
        def cli_fn(cmds):
            if isinstance(cmds, str):
                call_log.append(cmds)
                if 'show' in cmds:
                    return {cmds: table_two}
                return {cmds: ''}
            return {cmd: table_two if 'show' in cmd else ''
                    for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)
        self.ssh._in_config_mode = False
        self.ssh.delete_dns_server('10.0.0.1')
        self.assertTrue(any(
            'dns client servers delete 2' in c for c in call_log))

    def test_delete_dns_server_not_found(self):
        """delete_dns_server raises ValueError when IP not in table."""
        table_one = (
            'No.                  IP address                Active            \n'
            '---  ----------------------------------------  ------\n'
            '  1  192.168.3.1                               [x]\n'
        )
        def cli_fn(cmds):
            if isinstance(cmds, str):
                if 'show' in cmds:
                    return {cmds: table_one}
                return {cmds: ''}
            return {cmd: table_one if 'show' in cmd else ''
                    for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)
        self.ssh._in_config_mode = False
        with self.assertRaises(ValueError) as ctx:
            self.ssh.delete_dns_server('10.10.10.10')
        self.assertIn('not found', str(ctx.exception))


class TestSSHPoe(unittest.TestCase):
    """Test SSH PoE getter/setter with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        """Helper: set up cli mock that returns dict keyed by command."""
        def cli_fn(cmds):
            if isinstance(cmds, str):
                cmds = [cmds]
            return {cmd: responses.get(cmd, '') for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)

    # --- get_poe ---

    def test_get_poe_factory_defaults(self):
        """get_poe factory defaults — disabled, no ports/modules."""
        self._mock_cli({
            'show inlinepower global': (
                'Power over Ethernet system information\n'
                '--------------------------------------\n'
                '\n'
                'Admin mode..................................disabled\n'
                'System power [W]............................0\n'
                'Reserved system power [W]...................0\n'
                'Delivered system power [W]..................0\n'
                'Delivered system current [mA]...............0\n'
                'Send traps (notification)...................enabled\n'
                'Power threshold [%].........................90\n'
            ),
            'show inlinepower port': (
                'Intf   PoE enable  Class  Status\n'
                '-----  ----------  -----  ------\n'
                '\n'
                'No entry.\n'
            ),
            'show inlinepower slot': (
                'Slot  budget[W]  budget[W]  power[W]\n'
                '----  ---------  ---------  --------\n'
            ),
        })
        result = self.ssh.get_poe()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['power_w'], 0)
        self.assertEqual(result['delivered_current_ma'], 0)
        self.assertEqual(result['modules'], {})
        self.assertEqual(result['ports'], {})

    def test_get_poe_enabled_with_port(self):
        """get_poe with PoE enabled, one port delivering."""
        self._mock_cli({
            'show inlinepower global': (
                'Power over Ethernet system information\n'
                '--------------------------------------\n'
                '\n'
                'Admin mode..................................enabled\n'
                'System power [W]............................30\n'
                'Reserved system power [W]...................30\n'
                'Delivered system power [W]..................5\n'
                'Delivered system current [mA]...............250\n'
                'Send traps (notification)...................enabled\n'
                'Power threshold [%].........................90\n'
            ),
            'show inlinepower port': (
                'Intf   PoE enable  Class  Status          Allowed class   Auto shutdown    Start\n'
                '       Fast-start  Prio.  Consumption[W]  Power limit[W]  Max observed[W]  End\n'
                '                          Current[mA]\n'
                '-----  ----------  -----  --------------  --------------  ---------------  -----\n'
                '1/1    enable      4      Delivering      0,1,2,3,4       disable          00:00\n'
                '       disable     low    5.3             15.4            5.3              00:00\n'
                '                          117\n'
            ),
            'show inlinepower slot': (
                'Slot  budget[W]  budget[W]  power[W]  power[W]   current[mA]  source  traps  threshold[%]\n'
                '----  ---------  ---------  --------  ---------  -----------  ------  -----  ------------\n'
                '1     370        370        30        5          250          int.    ena.   90\n'
            ),
        })
        result = self.ssh.get_poe()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['delivered_current_ma'], 250)
        # Port
        self.assertIn('1/1', result['ports'])
        port = result['ports']['1/1']
        self.assertTrue(port['enabled'])
        self.assertEqual(port['status'], 'delivering')
        self.assertEqual(port['priority'], 'low')
        self.assertEqual(port['consumption_mw'], 5300)
        self.assertEqual(port['power_limit_mw'], 15400)
        self.assertFalse(port['fast_startup'])
        # Module
        self.assertIn('1/1', result['modules'])
        mod = result['modules']['1/1']
        self.assertEqual(mod['budget_w'], 370)

    def test_get_poe_disabled_port(self):
        """get_poe with PoE port disabled shows status=disabled."""
        self._mock_cli({
            'show inlinepower global': (
                'Admin mode..................................enabled\n'
                'Reserved system power [W]...................0\n'
                'Delivered system current [mA]...............0\n'
            ),
            'show inlinepower port': (
                'Intf   PoE enable  Class  Status          Allowed class   Auto shutdown    Start\n'
                '       Fast-start  Prio.  Consumption[W]  Power limit[W]  Max observed[W]  End\n'
                '                          Current[mA]\n'
                '-----  ----------  -----  --------------  --------------  ---------------  -----\n'
                '1/1    disable     0      Disabled        0,1,2,3,4       disable          00:00\n'
                '       disable     low    0.0             0               0.0              00:00\n'
                '                          0\n'
            ),
            'show inlinepower slot': (
                'Slot  budget[W]\n'
                '----  ---------\n'
            ),
        })
        result = self.ssh.get_poe()
        port = result['ports']['1/1']
        self.assertFalse(port['enabled'])
        self.assertEqual(port['status'], 'disabled')
        self.assertIsNone(port['classification'])

    # --- set_poe ---

    def test_set_poe_global_enable(self):
        """set_poe(enabled=True) sends correct CLI command."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_poe(enabled=True)
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any(
            'inlinepower operation enable' in c for c in cli_calls))

    def test_set_poe_global_disable(self):
        """set_poe(enabled=False) sends no inlinepower operation."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_poe(enabled=False)
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any(
            'no inlinepower operation' in c for c in cli_calls))

    def test_set_poe_per_port_disable(self):
        """set_poe per-port sends interface context commands."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_poe(interface='1/1', enabled=False)
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any(
            'interface 1/1' in c for c in cli_calls))
        self.assertTrue(any(
            'no inlinepower operation' in c for c in cli_calls))

    def test_set_poe_per_port_priority(self):
        """set_poe per-port priority sends correct command."""
        self.ssh.cli = Mock(return_value={})
        self.ssh._in_config_mode = False
        self.ssh.set_poe(interface='1/1', priority='critical')
        cli_calls = [str(c) for c in self.ssh.cli.call_args_list]
        self.assertTrue(any(
            'inlinepower priority critical' in c for c in cli_calls))


class TestSSHRemoteAuth(unittest.TestCase):
    """Test SSH remote auth getter with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        """Helper: set up cli mock that returns dict keyed by command."""
        def cli_fn(cmds):
            if isinstance(cmds, str):
                cmds = [cmds]
            return {cmd: responses.get(cmd, '') for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)

    def test_get_remote_auth_all_disabled(self):
        """get_remote_auth factory defaults — no servers, LDAP disabled."""
        self._mock_cli({
            'show radius auth servers': (
                'Idx  IP address         Port  Secret  Primary   Server name\n'
                '     Active\n'
                '---  ---------------  ------  ------  --------  '
                '--------------------------------\n'
                '\n'
                'No entry.\n'
            ),
            'show tacacs server': "Error: Invalid command 'tacacs'\x07",
            'show ldap global': (
                'LDAP configuration parameters and information\n'
                '---------------------------------------------\n'
                'LDAP operation..............................disabled\n'
            ),
        })
        result = self.ssh.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_radius_active(self):
        """get_remote_auth with one RADIUS auth server configured."""
        self._mock_cli({
            'show radius auth servers': (
                'Idx  IP address         Port  Secret  Primary   Server name\n'
                '     Active\n'
                '---  ---------------  ------  ------  --------  '
                '--------------------------------\n'
                '  1  10.0.0.1           1812  ******  Yes       \n'
                '     Yes\n'
            ),
            'show tacacs server': "Error: Invalid command 'tacacs'\x07",
            'show ldap global': (
                'LDAP configuration parameters and information\n'
                '---------------------------------------------\n'
                'LDAP operation..............................disabled\n'
            ),
        })
        result = self.ssh.get_remote_auth()
        self.assertTrue(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_ldap_enabled(self):
        """get_remote_auth with LDAP globally enabled."""
        self._mock_cli({
            'show radius auth servers': (
                'Idx  IP address         Port  Secret  Primary   Server name\n'
                '     Active\n'
                '---  ---------------  ------  ------  --------  '
                '--------------------------------\n'
                '\n'
                'No entry.\n'
            ),
            'show tacacs server': "Error: Invalid command 'tacacs'\x07",
            'show ldap global': (
                'LDAP configuration parameters and information\n'
                '---------------------------------------------\n'
                'LDAP operation..............................enabled\n'
            ),
        })
        result = self.ssh.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertTrue(result['ldap']['enabled'])

    def test_get_remote_auth_no_ldap_support(self):
        """get_remote_auth on L2S without LDAP/TACACS+ CLI support."""
        self._mock_cli({
            'show radius auth servers': (
                'Idx  IP address         Port  Secret  Primary   Server name\n'
                '     Active\n'
                '---  ---------------  ------  ------  --------  '
                '--------------------------------\n'
                '\n'
                'No entry.\n'
            ),
            'show tacacs server': "Error: Invalid command 'tacacs'\x07",
            'show ldap global': "Error: Invalid command 'ldap'\x07",
        })
        result = self.ssh.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])


class TestSSHUserManagement(unittest.TestCase):
    """Test SSH user management getter/setter with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        def cli_fn(cmds):
            if isinstance(cmds, str):
                cmds = [cmds]
            return {cmd: responses.get(cmd, '') for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)

    SHOW_USERS_SINGLE = (
        '(SNMPv3-)    (Password-)\n'
        'User Name                         Authentication  PolicyCheck  Status\n'
        'Access Mode                         Encryption                 Locked\n'
        '--------------------------------  --------------  -----------  ------\n'
        'admin                             md5             false        [x]   \n'
        'administrator                     des                          [ ]'
    )

    SHOW_USERS_MULTI = (
        '(SNMPv3-)    (Password-)\n'
        'User Name                         Authentication  PolicyCheck  Status\n'
        'Access Mode                         Encryption                 Locked\n'
        '--------------------------------  --------------  -----------  ------\n'
        'admin                             md5             false        [x]   \n'
        'administrator                     des                          [ ]\n'
        '\n'
        'testuser                          sha             true         [x]   \n'
        'operator                          aescfb128                    [ ]\n'
        '\n'
        'inactive                          md5             false        [ ]   \n'
        'guest                             des                          [x]'
    )

    def test_get_users_single(self):
        """get_users with single admin user."""
        self._mock_cli({'show users': self.SHOW_USERS_SINGLE})
        result = self.ssh.get_users()
        self.assertEqual(len(result), 1)
        u = result[0]
        self.assertEqual(u['name'], 'admin')
        self.assertEqual(u['role'], 'administrator')
        self.assertFalse(u['locked'])
        self.assertFalse(u['policy_check'])
        self.assertEqual(u['snmp_auth'], 'md5')
        self.assertEqual(u['snmp_enc'], 'des')
        self.assertTrue(u['active'])

    def test_get_users_multiple(self):
        """get_users with multiple users including inactive."""
        self._mock_cli({'show users': self.SHOW_USERS_MULTI})
        result = self.ssh.get_users()
        self.assertEqual(len(result), 3)
        tu = next(u for u in result if u['name'] == 'testuser')
        self.assertEqual(tu['role'], 'operator')
        self.assertEqual(tu['snmp_auth'], 'sha')
        self.assertEqual(tu['snmp_enc'], 'aes128')
        self.assertTrue(tu['policy_check'])
        self.assertTrue(tu['active'])
        self.assertFalse(tu['locked'])
        iu = next(u for u in result if u['name'] == 'inactive')
        self.assertEqual(iu['role'], 'guest')
        self.assertFalse(iu['active'])
        self.assertTrue(iu['locked'])

    def test_set_user_create_new(self):
        """set_user creates new user with correct CLI commands."""
        self._mock_cli({'show users': self.SHOW_USERS_SINGLE})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.set_user('newuser', password='Test1234!',
                          role='operator', snmp_auth_type='sha')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('users add newuser', calls)
        self.assertIn('users password newuser Test1234!', calls)
        self.assertIn('users enable newuser', calls)
        self.assertIn('users access-role newuser operator', calls)
        self.assertIn('users snmpv3 authentication newuser sha1',
                       calls)

    def test_set_user_update_existing(self):
        """set_user updates existing user without re-creating."""
        self._mock_cli({'show users': self.SHOW_USERS_SINGLE})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.set_user('admin', snmp_auth_type='sha',
                          snmp_enc_type='aes128')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertNotIn('users add admin', calls)
        self.assertIn('users snmpv3 authentication admin sha1',
                       calls)
        self.assertIn('users snmpv3 encryption admin aescfb128',
                       calls)

    def test_set_user_requires_password_for_new(self):
        """set_user raises ValueError for new user without password."""
        self._mock_cli({'show users': self.SHOW_USERS_SINGLE})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        with self.assertRaises(ValueError):
            self.ssh.set_user('newuser', role='guest')

    def test_delete_user(self):
        """delete_user sends correct CLI command."""
        self._mock_cli({})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.delete_user('testuser')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('users delete testuser', calls)


class TestSSHTrapDest(unittest.TestCase):
    """Test SSH trap destination parsing and CRUD."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        def cli_fn(cmds):
            if isinstance(cmds, str):
                cmds = [cmds]
            return {cmd: responses.get(cmd, '') for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)

    def test_parse_trap_v1v2c(self):
        """_parse_trap_v1v2c parses show snmp trap table."""
        text = (
            'SNMP trap name                   IP address'
            '                               Status\n'
            '-------------------------------- ----------'
            '------------------------------ ------\n'
            'hivision                         192.168.4.3:162'
            '                          [x]\n'
            'monitor                          10.0.0.1:162'
            '                             [x]\n'
        )
        result = self.ssh._parse_trap_v1v2c(text)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'hivision')
        self.assertEqual(result[0]['address'], '192.168.4.3:162')
        self.assertEqual(result[0]['security_model'], 'v1')
        self.assertEqual(result[0]['security_level'], 'noauth')
        self.assertEqual(result[1]['name'], 'monitor')

    def test_parse_trap_v1v2c_with_preamble(self):
        """_parse_trap_v1v2c skips status preamble section."""
        text = (
            'SNMP Trap Status\n'
            '----------------\n'
            'SNMP trap operation.........................enabled\n'
            'SNMP trap community.........................trap\n'
            '\n'
            'SNMP trap name                   IP address'
            '                               Status\n'
            '-------------------------------- ----------'
            '------------------------------ ------\n'
            'nms1                             192.168.1.100:162'
            '                        [x]\n'
        )
        result = self.ssh._parse_trap_v1v2c(text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'nms1')
        self.assertEqual(result[0]['address'], '192.168.1.100:162')

    def test_parse_trap_v3(self):
        """_parse_trap_v3 parses two-line v3 format."""
        text = (
            'SNMPv3 Notification Name         IP address'
            '                               Status\n'
            'SNMPv3 Notification User Name    Security Level'
            '                           Type\n'
            '-------------------------------- ----------'
            '------------------------------ ------\n'
            'testTrap1                        10.99.99.99:162'
            '                          [x]\n'
            'admin                            authPriv'
            '                                 trap\n'
        )
        result = self.ssh._parse_trap_v3(text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'testTrap1')
        self.assertEqual(result[0]['address'], '10.99.99.99:162')
        self.assertEqual(result[0]['security_model'], 'v3')
        self.assertEqual(result[0]['security_name'], 'admin')
        self.assertEqual(result[0]['security_level'], 'authpriv')

    def test_parse_trap_v3_empty(self):
        """_parse_trap_v3 returns empty list for header-only output."""
        text = (
            'SNMPv3 Notification Name         IP address\n'
            'SNMPv3 Notification User Name    Security Level\n'
            '-------------------------------- ------\n'
        )
        result = self.ssh._parse_trap_v3(text)
        self.assertEqual(result, [])

    def test_add_snmp_trap_dest_v3(self):
        """add_snmp_trap_dest v3 uses snmp notification host add."""
        self._mock_cli({})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.add_snmp_trap_dest(
            'nms1', '10.0.0.1', security_model='v3',
            security_name='admin', security_level='authpriv')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        found = [c for c in calls
                 if 'snmp notification host add' in c]
        self.assertTrue(found)
        self.assertIn('nms1', found[0])
        self.assertIn('auth-priv', found[0])

    def test_add_snmp_trap_dest_v1(self):
        """add_snmp_trap_dest v1 uses snmp trap add."""
        self._mock_cli({})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.add_snmp_trap_dest(
            'trap1', '10.0.0.1', security_model='v1',
            security_name='public')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        found = [c for c in calls if 'snmp trap add' in c]
        self.assertTrue(found)
        self.assertIn('trap1', found[0])

    def test_delete_snmp_trap_dest(self):
        """delete_snmp_trap_dest tries notification host first."""
        self._mock_cli({})
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.delete_snmp_trap_dest('nms1')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('delete' in c and 'nms1' in c
                            for c in calls))


class TestSSHPortSecurity(unittest.TestCase):
    """Test SSH port security getter/setter/CRUD with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        def cli_fn(cmds):
            if isinstance(cmds, str):
                cmds = [cmds]
            return {cmd: responses.get(cmd, '') for cmd in cmds}
        self.ssh.cli = Mock(side_effect=cli_fn)

    # --- _parse_port_security_table ---

    def test_parse_table_two_ports(self):
        """Two-line-per-port table format."""
        text = (
            'Port   Admin   Dynamic Static  Violation Violation\n'
            '       Mode    Limit   Limit   Trap Mode Trap Freq\n'
            '------------------------------------------------------------\n'
            '1/1    enabled  600     64      disabled  0\n'
            '       3        1        0       00:11:22:33:44:55\n'
            '1/2    disabled 200     32      enabled   30\n'
            '       0        0        0       \n'
        )
        result = self.ssh._parse_port_security_table(text)
        self.assertEqual(len(result), 2)
        self.assertIn('1/1', result)
        self.assertIn('1/2', result)
        p1 = result['1/1']
        self.assertTrue(p1['enabled'])
        self.assertEqual(p1['dynamic_limit'], 600)
        self.assertEqual(p1['static_limit'], 64)
        self.assertFalse(p1['violation_trap_mode'])
        self.assertEqual(p1['violation_trap_frequency'], 0)
        self.assertEqual(p1['dynamic_count'], 3)
        self.assertEqual(p1['static_count'], 1)
        self.assertEqual(p1['last_discarded_mac'], '00:11:22:33:44:55')
        p2 = result['1/2']
        self.assertFalse(p2['enabled'])
        self.assertEqual(p2['dynamic_limit'], 200)

    def test_parse_table_empty(self):
        """No ports in output."""
        result = self.ssh._parse_port_security_table('')
        self.assertEqual(result, {})

    def test_parse_table_no_separator(self):
        """Output without separator line."""
        result = self.ssh._parse_port_security_table('Port Admin\n1/1 enabled\n')
        self.assertEqual(result, {})

    # --- _parse_port_security_detail ---

    def test_parse_detail_single_port(self):
        """Key-value format from 'show port-security interface 1/1'."""
        text = (
            'Interface.............................. 1/1\n'
            'Admin Mode............................. enabled\n'
            'Dynamic Limit.......................... 600\n'
            'Static Limit........................... 64\n'
            'Automatic Disable...................... enabled\n'
            'Violation Trap Mode.................... disabled\n'
            'Violation Trap Frequency............... 0\n'
            'Current Dynamic........................ 3\n'
            'Current Static......................... 1\n'
            'Last Violating VLAN ID/MAC............. 1 00:11:22:33:44:55\n'
        )
        result = self.ssh._parse_port_security_detail(text)
        self.assertIn('1/1', result)
        p = result['1/1']
        self.assertTrue(p['enabled'])
        self.assertEqual(p['dynamic_limit'], 600)
        self.assertEqual(p['static_limit'], 64)
        self.assertTrue(p['auto_disable'])
        self.assertFalse(p['violation_trap_mode'])
        self.assertEqual(p['violation_trap_frequency'], 0)
        self.assertEqual(p['dynamic_count'], 3)
        self.assertEqual(p['static_count'], 1)
        self.assertEqual(p['last_discarded_mac'], '1 00:11:22:33:44:55')

    def test_parse_detail_disabled(self):
        """Detail view with disabled port."""
        text = (
            'Interface.............................. 1/3\n'
            'Admin Mode............................. disabled\n'
            'Dynamic Limit.......................... 200\n'
            'Static Limit........................... 32\n'
            'Automatic Disable...................... disabled\n'
            'Violation Trap Mode.................... enabled\n'
            'Violation Trap Frequency............... 60\n'
            'Current Dynamic........................ 0\n'
            'Current Static......................... 0\n'
            'Last Violating VLAN ID/MAC............. \n'
        )
        result = self.ssh._parse_port_security_detail(text)
        p = result['1/3']
        self.assertFalse(p['enabled'])
        self.assertFalse(p['auto_disable'])
        self.assertTrue(p['violation_trap_mode'])
        self.assertEqual(p['violation_trap_frequency'], 60)
        self.assertEqual(p['last_discarded_mac'], '')

    def test_parse_detail_empty(self):
        """Empty output returns empty dict."""
        self.assertEqual(self.ssh._parse_port_security_detail(''), {})

    # --- get_port_security ---

    def test_get_port_security_all(self):
        """get_port_security() returns global + all ports."""
        self._mock_cli({
            'show port-security global': 'Port Security Global Admin Mode: enabled\n',
            'show port-security interface': (
                'Port   Admin   Dynamic Static  Violation Violation\n'
                '       Mode    Limit   Limit   Trap Mode Trap Freq\n'
                '------------------------------------------------------------\n'
                '1/1    enabled  600     64      disabled  0\n'
                '       0        0                         \n'
                '1/2    disabled 600     64      disabled  0\n'
                '       0        0                         \n'
            ),
        })
        result = self.ssh.get_port_security()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['mode'], 'mac-based')
        self.assertEqual(len(result['ports']), 2)

    def test_get_port_security_disabled(self):
        """get_port_security() with global disabled."""
        self._mock_cli({
            'show port-security global': 'Port Security Global Admin Mode: disabled\n',
            'show port-security interface': (
                'Port   Admin   Dynamic Static  Violation Violation\n'
                '       Mode    Limit   Limit   Trap Mode Trap Freq\n'
                '------------------------------------------------------------\n'
                '1/1    disabled 600     64      disabled  0\n'
                '       0        0                         \n'
            ),
        })
        result = self.ssh.get_port_security()
        self.assertFalse(result['enabled'])

    def test_get_port_security_single_port(self):
        """get_port_security(interface='1/1') uses detail view."""
        self._mock_cli({
            'show port-security global': 'Port Security Global Admin Mode: enabled\n',
            'show port-security interface 1/1': (
                'Interface.............................. 1/1\n'
                'Admin Mode............................. enabled\n'
                'Dynamic Limit.......................... 10\n'
                'Static Limit........................... 5\n'
                'Automatic Disable...................... enabled\n'
                'Violation Trap Mode.................... disabled\n'
                'Violation Trap Frequency............... 0\n'
                'Current Dynamic........................ 2\n'
                'Current Static......................... 1\n'
                'Last Violating VLAN ID/MAC............. \n'
            ),
        })
        result = self.ssh.get_port_security(interface='1/1')
        self.assertTrue(result['enabled'])
        self.assertEqual(list(result['ports'].keys()), ['1/1'])
        self.assertEqual(result['ports']['1/1']['dynamic_limit'], 10)

    def test_get_port_security_filter_list(self):
        """get_port_security(interface=['1/2']) filters from table."""
        self._mock_cli({
            'show port-security global': 'Port Security Global Admin Mode: enabled\n',
            'show port-security interface': (
                'Port   Admin   Dynamic Static  Violation Violation\n'
                '       Mode    Limit   Limit   Trap Mode Trap Freq\n'
                '------------------------------------------------------------\n'
                '1/1    enabled  600     64      disabled  0\n'
                '       0        0                         \n'
                '1/2    disabled 600     64      disabled  0\n'
                '       0        0                         \n'
            ),
        })
        result = self.ssh.get_port_security(interface=['1/2'])
        self.assertEqual(list(result['ports'].keys()), ['1/2'])

    # --- set_port_security ---

    def test_set_port_security_global_enable(self):
        """set_port_security(enabled=True) at global level."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_port_security(enabled=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('port-security operation' in c for c in calls))

    def test_set_port_security_per_port(self):
        """set_port_security('1/1', dynamic_limit=10) per-port."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_port_security('1/1', dynamic_limit=10)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('interface 1/1' in c for c in calls))
        self.assertTrue(any('max-dynamic 10' in c for c in calls))

    def test_set_port_security_all_per_port_params(self):
        """set_port_security with all per-port parameters."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_port_security(
            '1/1', enabled=True, dynamic_limit=10, static_limit=5,
            auto_disable=False, violation_trap_mode=True,
            violation_trap_frequency=30, move_macs=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('port-security operation' in c for c in calls))
        self.assertTrue(any('max-dynamic 10' in c for c in calls))
        self.assertTrue(any('max-static 5' in c for c in calls))
        self.assertTrue(any('no port-security auto-disable' in c for c in calls))
        self.assertTrue(any('violation-traps operation' in c for c in calls))
        self.assertTrue(any('violation-traps frequency 30' in c for c in calls))
        self.assertTrue(any('mac-address move' in c for c in calls))

    def test_set_port_security_multi_interface(self):
        """set_port_security with list of interfaces."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_port_security(['1/1', '1/2'], enabled=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('interface 1/1' in c for c in calls))
        self.assertTrue(any('interface 1/2' in c for c in calls))

    # --- add_port_security ---

    def test_add_port_security_mac(self):
        """add_port_security with single MAC entry."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.add_port_security('1/1', vlan=1, mac='aa:bb:cc:dd:ee:ff')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('interface 1/1' in c for c in calls))
        self.assertTrue(any('mac-address add aa:bb:cc:dd:ee:ff 1' in c
                            for c in calls))

    def test_add_port_security_ip(self):
        """add_port_security with single IP entry."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.add_port_security('1/1', vlan=1, ip='192.168.1.1')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('ip-address add 192.168.1.1 1' in c
                            for c in calls))

    def test_add_port_security_bulk(self):
        """add_port_security with multiple entries."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.add_port_security('1/1', entries=[
            {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'},
            {'vlan': 2, 'mac': '11:22:33:44:55:66'},
        ])
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        mac_adds = [c for c in calls if 'mac-address add' in c]
        self.assertEqual(len(mac_adds), 2)

    def test_add_port_security_no_args(self):
        """add_port_security with no mac/ip/entries raises ValueError."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        with self.assertRaises(ValueError):
            self.ssh.add_port_security('1/1')

    # --- delete_port_security ---

    def test_delete_port_security_mac(self):
        """delete_port_security removes a MAC entry."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.delete_port_security('1/1', vlan=1, mac='aa:bb:cc:dd:ee:ff')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('mac-address delete aa:bb:cc:dd:ee:ff 1' in c
                            for c in calls))

    def test_delete_port_security_ip(self):
        """delete_port_security removes an IP entry."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.delete_port_security('1/1', vlan=1, ip='192.168.1.1')
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertTrue(any('ip-address delete 192.168.1.1 1' in c
                            for c in calls))

    def test_delete_port_security_no_args(self):
        """delete_port_security with no mac/ip/entries raises ValueError."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        with self.assertRaises(ValueError):
            self.ssh.delete_port_security('1/1')


class TestSSHDhcpSnooping(unittest.TestCase):
    """Test SSH DHCP snooping getter/setter with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        def side_effect(cmds):
            if isinstance(cmds, list):
                return {cmd: responses.get(cmd, '') for cmd in cmds}
            return responses.get(cmds, '')
        self.ssh.cli = Mock(side_effect=side_effect)

    def test_get_dhcp_snooping_all(self):
        """get_dhcp_snooping() returns global + vlans + ports."""
        self._mock_cli({
            'show ip dhcp-snooping global':
                'DHCP Snooping Configuration\n'
                '---------------------------\n'
                'DHCP Snooping Mode..........................enabled\n'
                'Source MAC Verification.....................enabled\n',
            'show ip dhcp-snooping vlan':
                'VLAN  DHCP Snooping\n'
                '----  -------------\n'
                '1     yes\n'
                '100   no\n',
            'show ip dhcp-snooping interfaces':
                'Interface  Trust  Auto-    Log   Rate Limit  Burst Interval\n'
                '                  Disable        [pps]       [sec]\n'
                '---------  -----  -------  ----  ----------  --------------\n'
                '1/1        yes    yes      no    15          1\n'
                '1/2        no     yes      yes   -1          1\n',
        })
        result = self.ssh.get_dhcp_snooping()
        self.assertTrue(result['enabled'])
        self.assertTrue(result['verify_mac'])
        self.assertEqual(len(result['vlans']), 2)
        self.assertTrue(result['vlans'][1]['enabled'])
        self.assertFalse(result['vlans'][100]['enabled'])
        self.assertEqual(len(result['ports']), 2)
        p1 = result['ports']['1/1']
        self.assertTrue(p1['trusted'])
        self.assertFalse(p1['log'])
        self.assertEqual(p1['rate_limit'], 15)
        self.assertEqual(p1['burst_interval'], 1)
        self.assertTrue(p1['auto_disable'])
        p2 = result['ports']['1/2']
        self.assertFalse(p2['trusted'])
        self.assertTrue(p2['log'])
        self.assertEqual(p2['rate_limit'], -1)
        self.assertEqual(p2['burst_interval'], 1)

    def test_get_dhcp_snooping_disabled(self):
        """get_dhcp_snooping() with everything disabled."""
        self._mock_cli({
            'show ip dhcp-snooping global':
                'DHCP Snooping Configuration\n'
                '---------------------------\n'
                'DHCP Snooping Mode..........................disabled\n'
                'Source MAC Verification.....................disabled\n',
            'show ip dhcp-snooping vlan':
                'VLAN  DHCP Snooping\n'
                '----  -------------\n',
            'show ip dhcp-snooping interfaces':
                'Interface  Trust  Auto-    Log   Rate Limit  Burst Interval\n'
                '                  Disable        [pps]       [sec]\n'
                '---------  -----  -------  ----  ----------  --------------\n',
        })
        result = self.ssh.get_dhcp_snooping()
        self.assertFalse(result['enabled'])
        self.assertFalse(result['verify_mac'])
        self.assertEqual(result['vlans'], {})
        self.assertEqual(result['ports'], {})

    def test_get_dhcp_snooping_single_interface(self):
        """get_dhcp_snooping('1/1') filters to one port."""
        self._mock_cli({
            'show ip dhcp-snooping global':
                'DHCP Snooping Configuration\n'
                '---------------------------\n'
                'DHCP Snooping Mode..........................disabled\n',
            'show ip dhcp-snooping vlan':
                'VLAN  DHCP Snooping\n----  -------------\n',
            'show ip dhcp-snooping interfaces':
                'Interface  Trust  Auto-    Log   Rate Limit  Burst Interval\n'
                '                  Disable        [pps]       [sec]\n'
                '---------  -----  -------  ----  ----------  --------------\n'
                '1/1        yes    yes      no    15          1\n'
                '1/2        no     yes      no    -1          1\n',
        })
        result = self.ssh.get_dhcp_snooping('1/1')
        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_set_dhcp_snooping_global_enable(self):
        """set_dhcp_snooping(enabled=True) sends CLI command."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping(enabled=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('ip dhcp-snooping mode', calls)

    def test_set_dhcp_snooping_global_disable(self):
        """set_dhcp_snooping(enabled=False) sends no prefix."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping(enabled=False)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('no ip dhcp-snooping mode', calls)

    def test_set_dhcp_snooping_verify_mac(self):
        """set_dhcp_snooping(verify_mac=True) enables MAC verify."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping(verify_mac=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('ip dhcp-snooping verify-mac', calls)

    def test_set_dhcp_snooping_vlan(self):
        """set_dhcp_snooping(vlan=1, vlan_enabled=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping(vlan=1, vlan_enabled=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('vlan 1', calls)
        self.assertIn('ip dhcp-snooping', calls)

    def test_set_dhcp_snooping_port_trust(self):
        """set_dhcp_snooping('1/1', trusted=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping('1/1', trusted=True, log=False,
                                   rate_limit=15, burst_interval=1,
                                   auto_disable=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('interface 1/1', calls)
        self.assertIn('ip dhcp-snooping trust', calls)
        self.assertIn('no ip dhcp-snooping log', calls)
        self.assertIn('ip dhcp-snooping limit 15 1', calls)
        self.assertIn('ip dhcp-snooping auto-disable', calls)

    def test_set_dhcp_snooping_port_rate_unlimited(self):
        """set_dhcp_snooping('1/1', rate_limit=-1) disables limit."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping('1/1', rate_limit=-1)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('no ip dhcp-snooping limit', calls)

    def test_set_dhcp_snooping_multi_port(self):
        """set_dhcp_snooping(['1/1', '1/2'], trusted=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_dhcp_snooping(['1/1', '1/2'], trusted=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('interface 1/1', calls)
        self.assertIn('interface 1/2', calls)
        trust_calls = [c for c in calls
                       if c == 'ip dhcp-snooping trust']
        self.assertEqual(len(trust_calls), 2)


class TestSSHArpInspection(unittest.TestCase):
    """Test SSH ARP inspection getter/setter with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        def side_effect(cmds):
            if isinstance(cmds, list):
                return {cmd: responses.get(cmd, '') for cmd in cmds}
            return responses.get(cmds, '')
        self.ssh.cli = Mock(side_effect=side_effect)

    def test_get_arp_inspection_all(self):
        """get_arp_inspection() returns globals + vlans + ports."""
        self._mock_cli({
            'show ip arp-inspection global':
                'Dynamic ARP Inspection Configuration\n'
                '------------------------------------\n'
                'IP Address Verification.....................enabled\n'
                'Source MAC Verification.....................enabled\n'
                'Destination MAC Verification................disabled\n',
            'show ip arp-inspection vlan':
                'VLAN  ARP         Log  Bind   ACL     ARP\n'
                '      Inspection       Check  Strict  ACL\n'
                '----  ----------  ---  -----  ------  ----------\n'
                '1     yes         no   yes    no\n'
                '100   no          yes  no     no\n',
            'show ip arp-inspection interfaces':
                'Interface  Trust  Auto-    Rate Limit  Burst Interval\n'
                '                  Disable  [pps]       [sec]\n'
                '---------  -----  -------  ----------  --------------\n'
                '1/1        yes    yes      15          1\n'
                '1/2        no     yes      -1          1\n',
        })
        result = self.ssh.get_arp_inspection()
        self.assertTrue(result['validate_src_mac'])
        self.assertFalse(result['validate_dst_mac'])
        self.assertTrue(result['validate_ip'])
        self.assertEqual(len(result['vlans']), 2)
        self.assertTrue(result['vlans'][1]['enabled'])
        self.assertTrue(result['vlans'][1]['binding_check'])
        self.assertFalse(result['vlans'][100]['enabled'])
        self.assertTrue(result['vlans'][100]['log'])
        self.assertEqual(len(result['ports']), 2)
        self.assertTrue(result['ports']['1/1']['trusted'])
        self.assertEqual(result['ports']['1/1']['rate_limit'], 15)
        self.assertFalse(result['ports']['1/2']['trusted'])

    def test_get_arp_inspection_disabled(self):
        """get_arp_inspection() with everything off."""
        self._mock_cli({
            'show ip arp-inspection global':
                'Dynamic ARP Inspection Configuration\n'
                '------------------------------------\n'
                'IP Address Verification.....................disabled\n'
                'Source MAC Verification.....................disabled\n'
                'Destination MAC Verification................disabled\n',
            'show ip arp-inspection vlan':
                'VLAN  ARP         Log  Bind   ACL     ARP\n'
                '      Inspection       Check  Strict  ACL\n'
                '----  ----------  ---  -----  ------  ----------\n',
            'show ip arp-inspection interfaces':
                'Interface  Trust  Auto-    Rate Limit  Burst Interval\n'
                '                  Disable  [pps]       [sec]\n'
                '---------  -----  -------  ----------  --------------\n',
        })
        result = self.ssh.get_arp_inspection()
        self.assertFalse(result['validate_src_mac'])
        self.assertFalse(result['validate_dst_mac'])
        self.assertFalse(result['validate_ip'])
        self.assertEqual(result['vlans'], {})
        self.assertEqual(result['ports'], {})

    def test_get_arp_inspection_single_interface(self):
        """get_arp_inspection('1/1') filters to one port."""
        self._mock_cli({
            'show ip arp-inspection global':
                'Dynamic ARP Inspection Configuration\n'
                '------------------------------------\n'
                'IP Address Verification.....................disabled\n'
                'Source MAC Verification.....................disabled\n'
                'Destination MAC Verification................disabled\n',
            'show ip arp-inspection vlan':
                'VLAN  ARP         Log  Bind   ACL     ARP\n'
                '      Inspection       Check  Strict  ACL\n'
                '----  ----------  ---  -----  ------  ----------\n',
            'show ip arp-inspection interfaces':
                'Interface  Trust  Auto-    Rate Limit  Burst Interval\n'
                '                  Disable  [pps]       [sec]\n'
                '---------  -----  -------  ----------  --------------\n'
                '1/1        yes    yes      15          1\n'
                '1/2        no     yes      -1          1\n',
        })
        result = self.ssh.get_arp_inspection('1/1')
        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_set_arp_inspection_global(self):
        """set_arp_inspection(validate_src_mac=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_arp_inspection(validate_src_mac=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('ip arp-inspection verify src-mac', calls)

    def test_set_arp_inspection_vlan(self):
        """set_arp_inspection(vlan=1, vlan_enabled=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_arp_inspection(vlan=1, vlan_enabled=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('vlan 1', calls)
        self.assertIn('ip arp-inspection', calls)

    def test_set_arp_inspection_port_trust(self):
        """set_arp_inspection('1/1', trusted=True, rate_limit=15)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_arp_inspection('1/1', trusted=True, rate_limit=15,
                                    burst_interval=1,
                                    auto_disable=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('interface 1/1', calls)
        self.assertIn('ip arp-inspection trust', calls)
        self.assertIn('ip arp-inspection limit 15 1', calls)
        self.assertIn('ip arp-inspection auto-disable', calls)

    def test_set_arp_inspection_rate_unlimited(self):
        """set_arp_inspection('1/1', rate_limit=-1) disables limit."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_arp_inspection('1/1', rate_limit=-1)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('no ip arp-inspection limit', calls)

    def test_set_arp_inspection_multi_port(self):
        """set_arp_inspection(['1/1', '1/2'], trusted=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_arp_inspection(['1/1', '1/2'], trusted=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('interface 1/1', calls)
        self.assertIn('interface 1/2', calls)
        trust_calls = [c for c in calls
                       if c == 'ip arp-inspection trust']
        self.assertEqual(len(trust_calls), 2)


class TestSSHIpSourceGuard(unittest.TestCase):
    """Test SSH IP Source Guard getter/setter with mocked CLI output."""

    def setUp(self):
        self.ssh = SSHHIOS('198.51.100.1', 'admin', 'private', 10)
        self.ssh._connected = True
        self.ssh.connection = Mock()

    def _mock_cli(self, responses):
        def side_effect(cmds):
            if isinstance(cmds, list):
                return {cmd: responses.get(cmd, '') for cmd in cmds}
            return responses.get(cmds, '')
        self.ssh.cli = Mock(side_effect=side_effect)

    def test_get_ip_source_guard_all(self):
        """get_ip_source_guard() returns ports + bindings."""
        self._mock_cli({
            'show ip source-guard interfaces':
                'Interface  Mode  Verify MAC\n'
                '---------  ----  ----------\n'
                '1/1        yes   yes\n'
                '1/2        no    no\n',
            'show ip source-guard bindings static': '',
            'show ip source-guard bindings dynamic': '',
        })
        result = self.ssh.get_ip_source_guard()
        self.assertEqual(len(result['ports']), 2)
        self.assertTrue(result['ports']['1/1']['verify_source'])
        self.assertTrue(result['ports']['1/1']['port_security'])
        self.assertFalse(result['ports']['1/2']['verify_source'])
        self.assertFalse(result['ports']['1/2']['port_security'])
        self.assertEqual(result['static_bindings'], [])
        self.assertEqual(result['dynamic_bindings'], [])

    def test_get_ip_source_guard_single_interface(self):
        """get_ip_source_guard('1/1') filters to one port."""
        self._mock_cli({
            'show ip source-guard interfaces':
                'Interface  Mode  Verify MAC\n'
                '---------  ----  ----------\n'
                '1/1        yes   no\n'
                '1/2        no    no\n',
            'show ip source-guard bindings static': '',
            'show ip source-guard bindings dynamic': '',
        })
        result = self.ssh.get_ip_source_guard('1/1')
        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_get_ip_source_guard_with_bindings(self):
        """get_ip_source_guard() parses binding tables."""
        self._mock_cli({
            'show ip source-guard interfaces':
                'Interface  Mode  Verify MAC\n'
                '---------  ----  ----------\n'
                '1/1        yes   yes\n',
            'show ip source-guard bindings static':
                'MAC Address        IP Address      Interface  VLAN  Status\n'
                '-----------------  --------------  ---------  ----  ------\n'
                'AA:BB:CC:DD:EE:FF  10.0.0.1        1/1        1     active\n',
            'show ip source-guard bindings dynamic':
                'MAC Address        IP Address      Interface  VLAN  HW\n'
                '-----------------  --------------  ---------  ----  ------\n'
                '11:22:33:44:55:66  10.0.0.2        1/1        1     active\n',
        })
        result = self.ssh.get_ip_source_guard()
        self.assertEqual(len(result['static_bindings']), 1)
        sb = result['static_bindings'][0]
        self.assertEqual(sb['interface'], '1/1')
        self.assertEqual(sb['vlan_id'], 1)
        self.assertEqual(sb['mac_address'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(sb['ip_address'], '10.0.0.1')
        self.assertTrue(sb['active'])
        self.assertEqual(len(result['dynamic_bindings']), 1)
        db = result['dynamic_bindings'][0]
        self.assertEqual(db['interface'], '1/1')
        self.assertEqual(db['ip_address'], '10.0.0.2')

    def test_set_ip_source_guard_enable(self):
        """set_ip_source_guard('1/1', verify_source=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_ip_source_guard('1/1', verify_source=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('interface 1/1', calls)
        self.assertIn('ip source-guard mode', calls)

    def test_set_ip_source_guard_disable(self):
        """set_ip_source_guard('1/1', verify_source=False)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_ip_source_guard('1/1', verify_source=False)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('no ip source-guard mode', calls)

    def test_set_ip_source_guard_verify_mac(self):
        """set_ip_source_guard('1/1', port_security=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_ip_source_guard('1/1', port_security=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('ip source-guard verify-mac', calls)

    def test_set_ip_source_guard_multi(self):
        """set_ip_source_guard(['1/1', '1/2'], verify_source=True)."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_ip_source_guard(['1/1', '1/2'], verify_source=True)
        calls = [c[0][0] for c in self.ssh.cli.call_args_list
                 if isinstance(c[0][0], str)]
        self.assertIn('interface 1/1', calls)
        self.assertIn('interface 1/2', calls)

    def test_set_ip_source_guard_no_interface(self):
        """set_ip_source_guard(interface=None) is no-op."""
        self.ssh._config_mode = Mock()
        self.ssh._exit_config_mode = Mock()
        self.ssh.cli = Mock()
        self.ssh.set_ip_source_guard()
        self.ssh._config_mode.assert_not_called()


if __name__ == '__main__':
    unittest.main()
