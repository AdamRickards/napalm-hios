import sys
import os
import unittest
import logging
import time
from paramiko.ssh_exception import SSHException
from ncclient.transport.errors import SSHError
from napalm.base.exceptions import ConnectionException

# Add the project root directory to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

from napalm_hios.hios import HIOSDriver

class TestHiOSConnectivity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hostname = '192.168.1.126'
        cls.username = 'admin'
        cls.password = 'private'
        cls.timeout = 60
        cls.ssh_port = 22
        cls.snmp_port = 161
        cls.netconf_port = 830
        cls.max_retries = 3
        cls.retry_delay = 5
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        cls.logger = logging.getLogger(__name__)

        # Create HIOSDriver instance
        cls.driver = HIOSDriver(
            hostname=cls.hostname,
            username=cls.username,
            password=cls.password,
            timeout=cls.timeout,
            optional_args={
                'ssh_port': cls.ssh_port,
                'snmp_port': cls.snmp_port,
                'netconf_port': cls.netconf_port
            }
        )

    @classmethod
    def tearDownClass(cls):
        if cls.driver:
            cls.driver.close()

    def setUp(self):
        self.logger.info(f"Attempting to open connection to {self.hostname}")
        for attempt in range(self.max_retries):
            try:
                self.driver.open()
                self.logger.info("Connection opened successfully")
                break
            except (ConnectionException, SSHException, SSHError) as e:
                self.logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.max_retries - 1:
                    self.logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    self.logger.error(f"Failed to open connection after {self.max_retries} attempts")
                    self.fail(f"Failed to open connection: {str(e)}")

    def tearDown(self):
        self.logger.info("Closing connection")
        self.driver.close()

    def test_open_close(self):
        self.logger.info("Testing open and close methods")
        try:
            self.assertTrue(self.driver.is_alive()['is_alive'])
            self.driver.close()
            self.assertFalse(self.driver.is_alive()['is_alive'])
            self.logger.info("Open/close test passed")
        except (ConnectionException, SSHException, SSHError) as e:
            self.logger.error(f"Open/close test failed: {str(e)}")
            self.fail(f"Open/close test failed: {str(e)}")

    def test_get_facts(self):
        self.logger.info("Testing get_facts method")
        try:
            facts = self.driver.get_facts()
            self.assertIsInstance(facts, dict)
            self.assertIn('vendor', facts)
            self.assertEqual(facts['vendor'], 'Belden')
            self.logger.info("get_facts test passed")
        except (ConnectionException, SSHException, SSHError) as e:
            self.logger.error(f"get_facts test failed: {str(e)}")
            self.fail(f"get_facts test failed: {str(e)}")

    def test_get_interfaces(self):
        self.logger.info("Testing get_interfaces method")
        try:
            interfaces = self.driver.get_interfaces()
            self.assertIsInstance(interfaces, dict)
            self.assertTrue(len(interfaces) > 0)
            for interface, details in interfaces.items():
                self.assertIn('is_up', details)
                self.assertIn('is_enabled', details)
            self.logger.info("get_interfaces test passed")
        except (ConnectionException, SSHException, SSHError) as e:
            self.logger.error(f"get_interfaces test failed: {str(e)}")
            self.fail(f"get_interfaces test failed: {str(e)}")

    def test_get_snmp_information(self):
        self.logger.info("Testing get_snmp_information method")
        try:
            snmp_info = self.driver.get_snmp_information()
            self.assertIsInstance(snmp_info, dict)
            self.assertIn('system_description', snmp_info)
            self.logger.info("get_snmp_information test passed")
        except (ConnectionException, SSHException, SSHError) as e:
            self.logger.error(f"get_snmp_information test failed: {str(e)}")
            self.fail(f"get_snmp_information test failed: {str(e)}")

    def test_ssh_protocol_preference(self):
        self.logger.info("Testing SSH connection with protocol_preference set to ssh")
        ssh_driver = HIOSDriver(
            hostname=self.hostname,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            optional_args={
                'protocol_preference': 'ssh'
            }
        )
        try:
            ssh_driver.close()
            ssh_driver.open()
            self.assertTrue(ssh_driver.is_alive()['is_alive'])
            facts = ssh_driver.get_facts()
            self.assertIsInstance(facts, dict)
            self.assertIn('vendor', facts)
            self.assertEqual(facts['vendor'], 'Belden')
            self.logger.info("SSH protocol preference test passed")
        except (ConnectionException, SSHException, SSHError) as e:
            self.logger.error(f"SSH protocol preference test failed: {str(e)}")
            self.fail(f"SSH protocol preference test failed: {str(e)}")
        finally:
            ssh_driver.close()

if __name__ == '__main__':
    unittest.main()
