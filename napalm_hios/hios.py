from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException

from napalm_hios.netconf_hios import NetconfHIOS
from napalm_hios.ssh_hios import SSHHIOS
from napalm_hios.snmp_hios import SNMPHIOS
from napalm_hios.mock_hios_device import MockHIOSDevice
from napalm_hios.utils import log_error

import logging

logger = logging.getLogger(__name__)

class HIOSDriver(NetworkDriver):
    """
    NAPALM driver implementation for HIOS devices.
    Supports multiple protocols: NETCONF, SSH, and SNMPv3.
    
    This driver implements the NAPALM base interface and provides
    connectivity to HIOS devices using various protocols based on availability
    and user preference.
    """

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """
        Initialize the HIOS driver.
        
        Args:
            hostname (str): Device hostname or IP address
            username (str): Authentication username
            password (str): Authentication password
            timeout (int): Connection timeout in seconds (default: 60)
            optional_args (dict): Additional arguments for configuration
                                Can include protocol_preference, ports, etc.
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args or {}
        
        # Initialize connection handlers for different protocols
        self.netconf = None
        self.ssh = None
        self.snmp = None
        self.mock_device = None
        self._is_alive = False
        self.active_protocol = None

    def open(self):
        """
        Open a connection to the device using the preferred protocol.
        
        If hostname is 'localhost', uses a mock device for testing.
        Otherwise attempts to connect using protocols in the order specified
        in protocol_preference (defaults to ['ssh', 'snmp', 'netconf']).
        
        Raises:
            ConnectionException: If unable to connect using any protocol
        """
        try:
            if self.hostname == 'localhost':
                self.mock_device = MockHIOSDevice(self.optional_args)
                self.mock_device.open()
                self._is_alive = True
                self.active_protocol = 'ssh'  # Assume SSH for mock device
                logger.info("Using mock HiOS device")
                return

            # Get protocol preference from optional args or use default
            protocol_preference = self.optional_args.get('protocol_preference', ['ssh', 'snmp','netconf'])
            
            # Try each protocol in order of preference
            for protocol in protocol_preference:
                if self._try_connect(protocol):
                    self.active_protocol = protocol
                    self._is_alive = True
                    logger.info(f"Connected to {self.hostname} using {protocol.upper()}")
                    return

            raise ConnectionException(f"Failed to connect to {self.hostname} using any available protocol")

        except Exception as e:
            log_error(logger, f"Error opening connection: {str(e)}")
            raise ConnectionException(f"Cannot connect to {self.hostname}")

    def _try_connect(self, protocol):
        """
        Attempt to connect using a specific protocol.
        
        Args:
            protocol (str): Protocol to try ('netconf', 'ssh', or 'snmp')
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if protocol == 'netconf':
                # Try NETCONF connection
                netconf_port = self.optional_args.get('netconf_port', 830)
                self.netconf = NetconfHIOS(self.hostname, self.username, self.password, self.timeout, port=netconf_port)
                self.netconf.open()
                return True
            elif protocol == 'ssh':
                # Try SSH connection
                ssh_port = self.optional_args.get('ssh_port', 22)
                self.ssh = SSHHIOS(self.hostname, self.username, self.password, self.timeout, port=ssh_port)
                self.ssh.open()
                return True
            elif protocol == 'snmp':
                # Try SNMPv3 connection
                snmp_port = self.optional_args.get('snmp_port', 161)
                self.snmp = SNMPHIOS(self.hostname, self.username, self.password, self.timeout, port=snmp_port)
                self.snmp.open()
                return True
        except Exception as e:
            log_error(logger, f"Failed to connect using {protocol}: {str(e)}")
        return False

    def close(self):
        """
        Close all active connections to the device.
        Attempts to gracefully close each protocol connection that was established.
        """
        if self.mock_device:
            self.mock_device = None
        else:
            # Try to close all active connections
            for conn in [self.netconf, self.ssh, self.snmp]:
                if conn:
                    try:
                        conn.close()
                    except Exception as e:
                        log_error(logger, f"Error closing connection: {str(e)}")
        self._is_alive = False
        self.active_protocol = None

    def is_alive(self):
        """
        Check if the connection to the device is still alive.
        
        Returns:
            dict: Contains 'is_alive' key with boolean value
        """
        return {"is_alive": self._is_alive}

    def _get_active_connection(self):
        if self.mock_device:
            return self.mock_device
        elif self.active_protocol == 'netconf':
            return self.netconf
        elif self.active_protocol == 'ssh':
            return self.ssh
        elif self.active_protocol == 'snmp':
            return self.snmp
        else:
            raise ConnectionException("No active connection")

    def get_facts(self):
        if self.active_protocol == 'ssh':
            facts = self._get_active_connection().get_facts()
            # Ensure all required keys are present
            required_keys = ['uptime', 'vendor', 'model', 'hostname', 'fqdn', 'os_version', 'serial_number', 'interface_list']
            for key in required_keys:
                if key not in facts:
                    facts[key] = ''
            return facts
        raise NotImplementedError("get_facts is not implemented for this protocol")
    
    def get_interfaces_counters(self):
        if self.active_protocol == 'ssh':
            counters = self._get_active_connection().get_interfaces_counters()
            required_keys = ['tx_errors', 'rx_errors', 'tx_discards', 'rx_discards', 'tx_octets', 'rx_octets', 'tx_unicast_packets', 'rx_unicast_packets', 'tx_multicast_packets', 'rx_multicast_packets', 'tx_broadcast_packets', 'rx_broadcast_packets']
            for interface in counters.values():
                for key in required_keys:
                    if key not in interface:
                        interface[key] = 0
            return counters
        raise NotImplementedError("get_interfaces_counters is not implemented for this protocol")
    
    def get_interfaces_ip(self):
        if self.active_protocol == 'ssh':
            interfaces_ip = self._get_active_connection().get_interfaces_ip()
            for interface in interfaces_ip.values():
                if 'ipv4' not in interface:
                    interface['ipv4'] = {}
                if 'ipv6' not in interface:
                    interface['ipv6'] = {}
            return interfaces_ip
        raise NotImplementedError("get_interfaces_ip is not implemented for this protocol")
    
    def get_lldp_neighbors(self):
        if self.active_protocol == 'ssh':
            neighbors = self._get_active_connection().get_lldp_neighbors()
            # Ensure correct format: {local_port: [{'hostname': x, 'port': y}, ...]}
            for local_port, neighbor_list in neighbors.items():
                for neighbor in neighbor_list:
                    if 'hostname' not in neighbor:
                        neighbor['hostname'] = ''
                    if 'port' not in neighbor:
                        neighbor['port'] = ''
            return neighbors
        raise NotImplementedError("get_lldp_neighbors is not implemented for this protocol")
    
    def get_lldp_neighbors_detail(self, interface=""):
        if self.active_protocol == 'ssh':
            neighbors_detail = self._get_active_connection().get_lldp_neighbors_detail(interface)
            required_keys = ['parent_interface', 'remote_port', 'remote_port_description', 'remote_chassis_id', 'remote_system_name', 'remote_system_description', 'remote_system_capab', 'remote_system_enable_capab']
            for interface_neighbors in neighbors_detail.values():
                for neighbor in interface_neighbors:
                    for key in required_keys:
                        if key not in neighbor:
                            neighbor[key] = '' if key != 'remote_system_capab' and key != 'remote_system_enable_capab' else []
            return neighbors_detail
        raise NotImplementedError("get_lldp_neighbors_detail is not implemented for this protocol")
    
    def get_lldp_neighbors_detail_extended(self, interface=""):
        if self.active_protocol == 'ssh':
            extended_lldp_details = self._get_active_connection().get_lldp_neighbors_detail_extended(interface)
            required_keys = [
                'parent_interface', 'remote_port', 'remote_port_description', 'remote_chassis_id',
                'remote_system_name', 'remote_system_description', 'remote_system_capab',
                'remote_system_enable_capab', 'remote_management_ipv4', 'remote_management_ipv6',
                'autoneg_support', 'autoneg_enabled', 'port_oper_mau_type', 'port_vlan_id',
                'vlan_membership', 'link_agg_status', 'link_agg_port_id'
            ]
            
            for interface_neighbors in extended_lldp_details.values():
                for neighbor in interface_neighbors:
                    for key in required_keys:
                        if key not in neighbor:
                            if key in ['remote_system_capab', 'remote_system_enable_capab', 'vlan_membership']:
                                neighbor[key] = []
                            elif key in ['port_vlan_id', 'link_agg_port_id']:
                                neighbor[key] = '0'  # Default to '0' for numeric ID fields
                            else:
                                neighbor[key] = ''
            
            return extended_lldp_details
        raise NotImplementedError("get_lldp_neighbors_detail_extended is not implemented for this protocol")

    def get_mac_address_table(self):
        if self.active_protocol == 'ssh':
            mac_table = self._get_active_connection().get_mac_address_table()
            required_keys = ['mac', 'interface', 'vlan', 'static', 'active', 'moves', 'last_move']
            for entry in mac_table:
                for key in required_keys:
                    if key not in entry:
                        entry[key] = '' if key in ['mac', 'interface'] else 0
            return mac_table
        raise NotImplementedError("get_mac_address_table is not implemented for this protocol")
    
    def get_ntp_servers(self):
        if self.active_protocol == 'ssh':
            ntp_servers = self._get_active_connection().get_ntp_servers()
            return {server: {} for server in ntp_servers}
        raise NotImplementedError("get_ntp_servers is not implemented for this protocol")
    
    def get_ntp_stats(self):
        if self.active_protocol == 'ssh':
            ntp_stats = self._get_active_connection().get_ntp_stats()
            required_keys = ['remote', 'referenceid', 'synchronized', 'stratum', 'type', 'when', 'hostpoll', 'reachability', 'delay', 'offset', 'jitter']
            for stat in ntp_stats:
                for key in required_keys:
                    if key not in stat:
                        stat[key] = '' if key in ['remote', 'referenceid', 'type'] else 0
            return ntp_stats
        raise NotImplementedError("get_ntp_stats is not implemented for this protocol")

    def get_optics(self):
        if self.active_protocol == 'ssh':
            optics = self._get_active_connection().get_optics()
            required_keys = ['physical_channels']
            for interface in optics.values():
                for key in required_keys:
                    if key not in interface:
                        interface[key] = {'channel': []}
            return optics
        raise NotImplementedError("get_optics is not implemented for this protocol")
    
    def get_users(self):
        if self.active_protocol == 'ssh':
            users = self._get_active_connection().get_users()
            required_keys = ['level', 'password', 'sshkeys']
            for user in users.values():
                for key in required_keys:
                    if key not in user:
                        user[key] = [] if key == 'sshkeys' else ''
            return users
        raise NotImplementedError("get_users is not implemented for this protocol")
    
    def get_vlans(self):
        if self.active_protocol == 'ssh':
            vlans = self._get_active_connection().get_vlans()
            required_keys = ['name', 'interfaces']
            for vlan in vlans.values():
                for key in required_keys:
                    if key not in vlan:
                        vlan[key] = [] if key == 'interfaces' else ''
            return vlans
        raise NotImplementedError("get_vlans is not implemented for this protocol")

    def ping(self, destination, source='', ttl=255, timeout=2, size=100, count=5, vrf='', source_interface=''):
        if self.active_protocol == 'ssh':
            result = self._get_active_connection().ping(destination, source, ttl, timeout, size, count, vrf, source_interface)
            if 'success' in result:
                required_keys = ['probes_sent', 'packet_loss', 'rtt_min', 'rtt_max', 'rtt_avg', 'rtt_stddev', 'results']
                for key in required_keys:
                    if key not in result['success']:
                        result['success'][key] = [] if key == 'results' else 0
            return result
        raise NotImplementedError("ping is not implemented for this protocol")

    
        
    def cli(self, commands: list[str], encoding: str = 'text') -> dict[str, str]:
        """ Execute a list of commands and return the output in a dictionary format. """
        if self.active_protocol == 'ssh':
            # Call the SSHHIOS cli method
            return self._get_active_connection().cli(commands, encoding)
        else:
            raise NotImplementedError(f"Protocol {self.active_protocol} not supported for CLI.")
        
    def get_environment(self):
        if self.active_protocol == 'ssh':
            env = self._get_active_connection().get_environment()
            # Ensure all required sections are present
            required_sections = ['fans', 'temperature', 'power', 'cpu', 'memory']
            for section in required_sections:
                if section not in env:
                    env[section] = {}
            return env
        raise NotImplementedError("get_environment is not implemented for this protocol")

    def get_arp_table(self, vrf=""):
        if self.active_protocol == 'ssh':
            arp_table = self._get_active_connection().get_arp_table(vrf)
            required_keys = ['interface', 'mac', 'ip', 'age']
            for entry in arp_table:
                for key in required_keys:
                    if key not in entry:
                        entry[key] = '' if key in ['interface', 'mac', 'ip'] else 0.0
            return arp_table
        raise NotImplementedError("get_arp_table is not implemented for this protocol")
    
    def get_config(self, retrieve='all', full=False, sanitized=False, format='text'):
        if self.active_protocol == 'ssh':
            config = self._get_active_connection().get_config(retrieve, full, sanitized, format)
            # Ensure all config types are present
            for config_type in ['running', 'startup', 'candidate']:
                if config_type not in config:
                    config[config_type] = ''
            return config
        raise NotImplementedError("get_config is not implemented for this protocol")
    
    def get_interfaces(self):
        if self.active_protocol == 'ssh':
            interfaces = self._get_active_connection().get_interfaces()
            # Ensure all required keys are present for each interface
            required_keys = ['is_up', 'is_enabled', 'description', 'last_flapped', 'speed', 'mtu', 'mac_address']
            for interface in interfaces.values():
                for key in required_keys:
                    if key not in interface:
                        interface[key] = '' if key in ['description', 'mac_address'] else 0
            return interfaces
        raise NotImplementedError("get_interfaces is not implemented for this protocol")
        
    def load_merge_candidate(self, filename=None, config=None):
        raise NotImplementedError("load_merge_candidate is not implemented for this device")
    
    def load_replace_candidate(self, filename=None, config=None):
        raise NotImplementedError("load_replace_candidate is not implemented for this device")
    
    def compare_config(self):
        raise NotImplementedError("compare_config is not implemented for this device")
    
    def commit_config(self):
        raise NotImplementedError("commit_config is not implemented for this device")
    
    def discard_config(self):
        raise NotImplementedError("discard_config is not implemented for this device")
    
    def rollback(self):
        raise NotImplementedError("rollback is not implemented for this device")

    def get_snmp_information(self):
        if self.active_protocol == 'ssh':
            snmp_info = self._get_active_connection().get_snmp_information()
            required_keys = ['chassis_id', 'community', 'contact', 'location']
            for key in required_keys:
                if key not in snmp_info:
                    snmp_info[key] = '' if key != 'community' else {}
            return snmp_info
        raise NotImplementedError("get_snmp_information is not implemented for this protocol")

    # Additional NAPALM methods can be implemented here
    # Each should use _get_active_connection() to delegate to the appropriate protocol handler
