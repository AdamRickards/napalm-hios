from ncclient import manager
from napalm.base.exceptions import ConnectionException
from napalm_hios.utils import log_error
from lxml import etree

import logging

logger = logging.getLogger(__name__)

class NetconfHIOS:
    def __init__(self, hostname, username, password, timeout, port=830):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.connection = None

    def open(self):
        try:
            self.connection = manager.connect(
                host=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                hostkey_verify=False
            )
        except Exception as e:
            log_error(logger, f"Error opening NETCONF connection: {str(e)}")
            raise ConnectionException(f"Cannot connect to {self.hostname} using NETCONF")

    def close(self):
        if self.connection:
            self.connection.close_session()

    def get_facts(self):
        if not self.connection:
            raise ConnectionException("NETCONF connection is not open")

        facts = {}
        try:
            system_info = self._get_netconf_data('<system-info></system-info>')
            facts['vendor'] = 'Belden'
            facts['model'] = 'HiOS'
            facts['hostname'] = self._get_text_value(system_info, './/hostname')
            facts['os_version'] = self._get_text_value(system_info, './/os-version')
            facts['serial_number'] = self._get_text_value(system_info, './/serial-number')
            facts['uptime'] = int(self._get_text_value(system_info, './/uptime', '0'))
        except Exception as e:
            log_error(logger, f"Error retrieving facts via NETCONF: {str(e)}")
            raise

        return facts

    def get_interfaces(self):
        if not self.connection:
            raise ConnectionException("NETCONF connection is not open")

        interfaces = {}
        try:
            interfaces_info = self._get_netconf_data('<interfaces></interfaces>')
            for interface in interfaces_info.findall('.//interface'):
                name = self._get_text_value(interface, 'name')
                interfaces[name] = {
                    'is_up': self._get_text_value(interface, 'admin-status') == 'up',
                    'is_enabled': self._get_text_value(interface, 'oper-status') == 'up',
                    'description': self._get_text_value(interface, 'description'),
                    'speed': int(self._get_text_value(interface, 'speed', '0')),
                    'mtu': int(self._get_text_value(interface, 'mtu', '1500'))
                }
        except Exception as e:
            log_error(logger, f"Error retrieving interfaces via NETCONF: {str(e)}")
            raise

        return interfaces

    def get_snmp_information(self):
        if not self.connection:
            raise ConnectionException("NETCONF connection is not open")

        snmp_info = {}
        try:
            snmp_data = self._get_netconf_data('<snmp></snmp>')
            snmp_info['chassis_id'] = self._get_text_value(snmp_data, './/chassis-id')
            snmp_info['contact'] = self._get_text_value(snmp_data, './/contact')
            snmp_info['location'] = self._get_text_value(snmp_data, './/location')
            snmp_info['community'] = {}
            for community in snmp_data.findall('.//community'):
                name = self._get_text_value(community, 'name')
                access = self._get_text_value(community, 'access')
                snmp_info['community'][name] = access
        except Exception as e:
            log_error(logger, f"Error retrieving SNMP information via NETCONF: {str(e)}")
            raise

        return snmp_info

    def _get_netconf_data(self, filter_string):
        netconf_reply = self.connection.get(('subtree', filter_string))
        return etree.fromstring(netconf_reply.data_xml)

    def _get_text_value(self, element, xpath, default=''):
        try:
            return element.find(xpath).text
        except AttributeError:
            return default

    # Implement other NETCONF-specific methods as needed
