import unittest
import os
import logging
import re
import time
from napalm_hios.ssh_hios import SSHHIOS
from napalm.base.exceptions import ConnectionException

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class TestSSHHIOS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hostname = os.environ.get('HIOS_HOSTNAME', '192.168.1.126')
        cls.username = os.environ.get('HIOS_USERNAME', 'admin')
        cls.password = os.environ.get('HIOS_PASSWORD', 'private')
        cls.port = int(os.environ.get('HIOS_SSH_PORT', 22))
        cls.ssh = SSHHIOS(cls.hostname, cls.username, cls.password, 180, port=cls.port)  # Increased timeout to 180 seconds
        cls.test_results = []
        try:
            logger.info(f"Attempting to connect to {cls.hostname}:{cls.port}")
            cls.ssh.open()
            logger.info("Successfully connected to the device")
        except ConnectionException as e:
            logger.error(f"Failed to connect to the device: {str(e)}")
            raise

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

if __name__ == '__main__':
    unittest.main()
