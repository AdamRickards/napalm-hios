from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException, MergeConfigException, CommitError

from napalm_hios.netconf_hios import NetconfHIOS
from napalm_hios.ssh_hios import SSHHIOS
from napalm_hios.snmp_hios import SNMPHIOS
from napalm_hios.mops_hios import MOPSHIOS
from napalm_hios.mock_hios_device import MockHIOSDevice
from napalm_hios.utils import log_error

import logging
import time

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
        self.mops = None
        self.mock_device = None
        self._is_alive = False
        self.active_protocol = None

        # Candidate config state (in-memory staging)
        self._merge_candidate = ''
        self._loaded = False
        self._changed = False

    def open(self):
        """
        Open a connection to the device using the preferred protocol.
        
        If hostname is 'localhost', uses a mock device for testing.
        Otherwise attempts to connect using protocols in the order specified
        in protocol_preference (defaults to ['snmp', 'ssh', 'netconf']).
        
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
            protocol_preference = self.optional_args.get('protocol_preference', ['mops', 'snmp', 'ssh'])
            
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
            elif protocol == 'mops':
                # Try MOPS (HTTPS/XML) connection
                mops_port = self.optional_args.get('mops_port', 443)
                self.mops = MOPSHIOS(self.hostname, self.username, self.password, self.timeout, port=mops_port)
                self.mops.open()
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
            for conn in [self.netconf, self.ssh, self.snmp, self.mops]:
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
        elif self.active_protocol == 'mops':
            return self.mops
        else:
            raise ConnectionException("No active connection")

    def _ensure_ssh(self):
        """Lazy-connect SSH when active protocol is SNMP but SSH is needed.

        Returns True if SSH is available, False otherwise.
        """
        if self.ssh:
            return True
        if self._try_connect('ssh'):
            logger.info(f"Lazy-connected SSH to {self.hostname} for SSH-only method")
            return True
        return False

    def get_facts(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            facts = self._get_active_connection().get_facts()
            # Ensure all required keys are present
            required_keys = ['uptime', 'vendor', 'model', 'hostname', 'fqdn', 'os_version', 'serial_number', 'interface_list']
            for key in required_keys:
                if key not in facts:
                    facts[key] = ''
            return facts
        raise NotImplementedError("get_facts is not implemented for this protocol")
    
    def get_interfaces_counters(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            counters = self._get_active_connection().get_interfaces_counters()
            required_keys = ['tx_errors', 'rx_errors', 'tx_discards', 'rx_discards', 'tx_octets', 'rx_octets', 'tx_unicast_packets', 'rx_unicast_packets', 'tx_multicast_packets', 'rx_multicast_packets', 'tx_broadcast_packets', 'rx_broadcast_packets']
            for interface in counters.values():
                for key in required_keys:
                    if key not in interface:
                        interface[key] = 0
            return counters
        raise NotImplementedError("get_interfaces_counters is not implemented for this protocol")
    
    def get_interfaces_ip(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            interfaces_ip = self._get_active_connection().get_interfaces_ip()
            for interface in interfaces_ip.values():
                if 'ipv4' not in interface:
                    interface['ipv4'] = {}
                if 'ipv6' not in interface:
                    interface['ipv6'] = {}
            return interfaces_ip
        raise NotImplementedError("get_interfaces_ip is not implemented for this protocol")
    
    def get_lldp_neighbors(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
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
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
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
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
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
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            mac_table = self._get_active_connection().get_mac_address_table()
            required_keys = ['mac', 'interface', 'vlan', 'static', 'active', 'moves', 'last_move']
            for entry in mac_table:
                for key in required_keys:
                    if key not in entry:
                        entry[key] = '' if key in ['mac', 'interface'] else 0
            return mac_table
        raise NotImplementedError("get_mac_address_table is not implemented for this protocol")
    
    def get_ntp_servers(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            ntp_servers = self._get_active_connection().get_ntp_servers()
            if self.active_protocol == 'ssh':
                return {server: {} for server in ntp_servers}
            return ntp_servers
        raise NotImplementedError("get_ntp_servers is not implemented for this protocol")
    
    def get_ntp_stats(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            ntp_stats = self._get_active_connection().get_ntp_stats()
            required_keys = ['remote', 'referenceid', 'synchronized', 'stratum', 'type', 'when', 'hostpoll', 'reachability', 'delay', 'offset', 'jitter']
            for stat in ntp_stats:
                for key in required_keys:
                    if key not in stat:
                        stat[key] = '' if key in ['remote', 'referenceid', 'type'] else 0
            return ntp_stats
        raise NotImplementedError("get_ntp_stats is not implemented for this protocol")

    def get_optics(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            optics = self._get_active_connection().get_optics()
            required_keys = ['physical_channels']
            for interface in optics.values():
                for key in required_keys:
                    if key not in interface:
                        interface[key] = {'channel': []}
            return optics
        raise NotImplementedError("get_optics is not implemented for this protocol")
    
    def get_users(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            users = self._get_active_connection().get_users()
            required_keys = ['level', 'password', 'sshkeys']
            for user in users.values():
                for key in required_keys:
                    if key not in user:
                        user[key] = [] if key == 'sshkeys' else ''
            return users
        raise NotImplementedError("get_users is not implemented for this protocol")
    
    def get_vlans(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            vlans = self._get_active_connection().get_vlans()
            required_keys = ['name', 'interfaces']
            for vlan in vlans.values():
                for key in required_keys:
                    if key not in vlan:
                        vlan[key] = [] if key == 'interfaces' else ''
            return vlans
        raise NotImplementedError("get_vlans is not implemented for this protocol")

    def get_vlan_ingress(self, *ports):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().get_vlan_ingress(*ports)
        raise NotImplementedError("get_vlan_ingress requires SSH, MOPS or SNMP")

    def get_vlan_egress(self, *ports):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().get_vlan_egress(*ports)
        raise NotImplementedError("get_vlan_egress requires SSH, MOPS or SNMP")

    def set_vlan_ingress(self, port, pvid=None, frame_types=None,
                         ingress_filtering=None):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().set_vlan_ingress(
                port, pvid=pvid, frame_types=frame_types,
                ingress_filtering=ingress_filtering)
        raise NotImplementedError("set_vlan_ingress requires SSH, MOPS or SNMP")

    def set_vlan_egress(self, vlan_id, port, mode):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().set_vlan_egress(
                vlan_id, port, mode)
        raise NotImplementedError("set_vlan_egress requires SSH, MOPS or SNMP")

    def create_vlan(self, vlan_id, name=''):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().create_vlan(vlan_id, name=name)
        raise NotImplementedError("create_vlan requires SSH, MOPS or SNMP")

    def update_vlan(self, vlan_id, name):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().update_vlan(vlan_id, name)
        raise NotImplementedError("update_vlan requires SSH, MOPS or SNMP")

    def delete_vlan(self, vlan_id):
        if self.active_protocol in ('ssh', 'mops', 'snmp'):
            return self._get_active_connection().delete_vlan(vlan_id)
        raise NotImplementedError("delete_vlan requires SSH, MOPS or SNMP")

    def ping(self, destination, source='', ttl=255, timeout=2, size=100, count=5, vrf='', source_interface=''):
        if self.active_protocol == 'ssh' or self._ensure_ssh():
            result = self.ssh.ping(destination, source, ttl, timeout, size, count, vrf, source_interface)
            if 'success' in result:
                required_keys = ['probes_sent', 'packet_loss', 'rtt_min', 'rtt_max', 'rtt_avg', 'rtt_stddev', 'results']
                for key in required_keys:
                    if key not in result['success']:
                        result['success'][key] = [] if key == 'results' else 0
            return result
        raise NotImplementedError("ping requires SSH but SSH connection unavailable")

    
        
    def cli(self, commands: list[str], encoding: str = 'text') -> dict[str, str]:
        """Execute a list of commands and return the output in a dictionary format."""
        if self.active_protocol == 'ssh' or self._ensure_ssh():
            return self.ssh.cli(commands, encoding)
        raise NotImplementedError("cli requires SSH but SSH connection unavailable")
        
    def get_environment(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            env = self._get_active_connection().get_environment()
            # Ensure all required sections are present
            required_sections = ['fans', 'temperature', 'power', 'cpu', 'memory']
            for section in required_sections:
                if section not in env:
                    env[section] = {}
            return env
        raise NotImplementedError("get_environment is not implemented for this protocol")

    def get_arp_table(self, vrf=""):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            arp_table = self._get_active_connection().get_arp_table(vrf)
            required_keys = ['interface', 'mac', 'ip', 'age']
            for entry in arp_table:
                for key in required_keys:
                    if key not in entry:
                        entry[key] = '' if key in ['interface', 'mac', 'ip'] else 0.0
            return arp_table
        raise NotImplementedError("get_arp_table is not implemented for this protocol")
    
    def get_config(self, retrieve='all', full=False, sanitized=False, format='text'):
        if self.active_protocol == 'ssh' or self._ensure_ssh():
            config = self.ssh.get_config(retrieve, full, sanitized, format)
            # Ensure all config types are present
            for config_type in ['running', 'startup', 'candidate']:
                if config_type not in config:
                    config[config_type] = ''
            return config
        raise NotImplementedError("get_config requires SSH but SSH connection unavailable")
    
    def get_interfaces(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
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
        """Stage CLI commands for later commit.

        HiOS has no native candidate config — commands apply immediately.
        We stage them in Python and execute via SSH on commit.

        Args:
            filename: path to file containing CLI commands (one per line)
            config: string of CLI commands (newline-separated)
        """
        if filename:
            with open(filename, 'r') as f:
                self._merge_candidate = f.read()
        elif config:
            self._merge_candidate = config
        else:
            raise MergeConfigException("filename or config must be provided")
        self._loaded = True

    def load_replace_candidate(self, filename=None, config=None):
        raise NotImplementedError(
            "HiOS does not support config replacement. Use load_merge_candidate() instead."
        )

    def compare_config(self):
        """Return the staged candidate commands.

        No real diff is possible — HiOS applies commands immediately.
        Returns the commands that will be sent on commit.
        """
        return self._merge_candidate

    def commit_config(self, message='', revert_in=None):
        """Execute staged commands via SSH, then save to NVM.

        Safety workflow:
        1. Verify nothing loaded raises error
        2. Check NVM is in sync (no one else has unsaved changes)
        3. Optionally start config watchdog for auto-revert
        4. Execute commands in enable mode
        5. Save to NVM
        6. Stop watchdog on successful save

        Args:
            message: commit message (logged, not stored on device)
            revert_in: seconds for auto-revert timer (30-600, requires SNMP)
        """
        if not self._loaded:
            raise CommitError("No config loaded. Call load_merge_candidate() first.")

        # Ensure SSH is available
        if self.active_protocol != 'ssh' and not self._ensure_ssh():
            raise CommitError("commit_config requires SSH but SSH connection unavailable")

        # Check NVM sync — refuse if someone else has unsaved changes
        # Poll through transient "busy" state (NVM write from a recent save)
        try:
            for _attempt in range(5):
                status = self.get_config_status()
                if status['nvm'] != 'busy':
                    break
                time.sleep(1)
            if not status['saved']:
                raise CommitError(
                    f"Running config not saved to NVM (nvm: {status['nvm']}). "
                    "Another user may have unsaved changes. Save or discard first."
                )
        except NotImplementedError:
            pass  # No config status available, proceed anyway

        # Start watchdog if requested
        watchdog_started = False
        if revert_in and self.snmp:
            try:
                self.snmp.start_watchdog(revert_in)
                watchdog_started = True
                logger.info(f"Config watchdog started: {revert_in}s auto-revert")
            except Exception as e:
                logger.warning(f"Failed to start config watchdog: {e}")

        # Execute commands via SSH in configure mode
        try:
            self.ssh._config_mode()
            lines = [l.strip() for l in self._merge_candidate.splitlines() if l.strip()]
            errors = []
            for line in lines:
                result = self.ssh.cli(line)
                output = list(result.values())[0]
                if output.startswith('Error:'):
                    errors.append(f"{line}: {output}")
            self.ssh._exit_config_mode()
            if errors:
                raise CommitError(
                    f"Command errors during commit:\n" + "\n".join(errors)
                )
        except CommitError:
            raise
        except Exception as e:
            if watchdog_started:
                logger.info("Commit failed — watchdog will auto-revert on timer expiry")
            raise CommitError(f"Failed to execute commands: {e}")

        # Save to NVM
        try:
            self.ssh.save_config()
        except Exception as e:
            if watchdog_started:
                logger.info("Save failed — watchdog will auto-revert on timer expiry")
            raise CommitError(f"Commands executed but save failed: {e}")

        # Stop watchdog on successful save
        if watchdog_started:
            try:
                self.snmp.stop_watchdog()
                logger.info("Config watchdog stopped (save succeeded)")
            except Exception as e:
                logger.warning(f"Failed to stop config watchdog: {e}")

        # Clear state
        self._changed = True
        self._merge_candidate = ''
        self._loaded = False

        if message:
            logger.info(f"Config committed: {message}")

    def discard_config(self):
        """Clear staged candidate commands."""
        self._merge_candidate = ''
        self._loaded = False

    def rollback(self):
        raise NotImplementedError(
            "HiOS has no non-disruptive rollback. "
            "Use activate_profile() for atomic profile switching (causes warm restart)."
        )

    def get_mrp(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_mrp()
        raise NotImplementedError("get_mrp is not implemented for this protocol")

    def get_hidiscovery(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_hidiscovery()
        raise NotImplementedError("get_hidiscovery is not implemented for this protocol")

    def get_config_status(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_config_status()
        raise NotImplementedError("get_config_status is not implemented for this protocol")

    def save_config(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().save_config()
        raise NotImplementedError("save_config is not implemented for this protocol")

    def is_factory_default(self):
        if self.active_protocol in ('ssh', 'mops'):
            return self._get_active_connection().is_factory_default()
        if self.active_protocol == 'snmp':
            # SNMP is gated on factory-default devices — if we're connected, it's not factory-default
            return False
        raise NotImplementedError("is_factory_default is not implemented for this protocol")

    def onboard(self, new_password):
        if self.active_protocol in ('ssh', 'mops'):
            return self._get_active_connection().onboard(new_password)
        raise NotImplementedError(
            "onboard not available via SNMP — "
            "SNMP is gated on factory-default devices. Use MOPS or SSH.")

    def clear_config(self, keep_ip=False):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().clear_config(keep_ip=keep_ip)
        raise NotImplementedError("clear_config is not implemented for this protocol")

    def clear_factory(self, erase_all=False):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().clear_factory(erase_all=erase_all)
        raise NotImplementedError("clear_factory is not implemented for this protocol")

    def set_mrp(self, operation='enable', mode='client', port_primary=None,
                port_secondary=None, vlan=None, recovery_delay=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().set_mrp(
                operation, mode, port_primary, port_secondary, vlan, recovery_delay,
            )
        raise NotImplementedError("set_mrp is not implemented for this protocol")

    def delete_mrp(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().delete_mrp()
        raise NotImplementedError("delete_mrp is not implemented for this protocol")

    def get_mrp_sub_ring(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_mrp_sub_ring()
        raise NotImplementedError("get_mrp_sub_ring is not implemented for this protocol")

    def set_mrp_sub_ring(self, ring_id=None, enabled=None, mode='manager',
                         port=None, vlan=None, name=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().set_mrp_sub_ring(
                ring_id, enabled, mode, port, vlan, name,
            )
        raise NotImplementedError("set_mrp_sub_ring is not implemented for this protocol")

    def delete_mrp_sub_ring(self, ring_id=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().delete_mrp_sub_ring(ring_id)
        raise NotImplementedError("delete_mrp_sub_ring is not implemented for this protocol")

    def set_interface(self, interface, enabled=None, description=None):
        if enabled is None and description is None:
            return
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().set_interface(interface, enabled=enabled, description=description)
        raise NotImplementedError("set_interface is not implemented for this protocol")

    def set_hidiscovery(self, status, blinking=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().set_hidiscovery(status, blinking=blinking)
        raise NotImplementedError("set_hidiscovery is not implemented for this protocol")

    def get_sflow(self):
        if self.active_protocol == 'mops':
            return self._get_active_connection().get_sflow()
        raise NotImplementedError("get_sflow is only implemented for MOPS")

    def set_sflow(self, receiver, address=None, port=None, owner=None,
                  timeout=None, max_datagram_size=None):
        if self.active_protocol == 'mops':
            return self._get_active_connection().set_sflow(
                receiver, address=address, port=port, owner=owner,
                timeout=timeout, max_datagram_size=max_datagram_size)
        raise NotImplementedError("set_sflow is only implemented for MOPS")

    def get_sflow_port(self, interfaces=None, type=None):
        if self.active_protocol == 'mops':
            return self._get_active_connection().get_sflow_port(
                interfaces=interfaces, type=type)
        raise NotImplementedError("get_sflow_port is only implemented for MOPS")

    def set_sflow_port(self, interfaces, receiver, sample_rate=None,
                       interval=None, max_header_size=None):
        if self.active_protocol == 'mops':
            return self._get_active_connection().set_sflow_port(
                interfaces, receiver, sample_rate=sample_rate,
                interval=interval, max_header_size=max_header_size)
        raise NotImplementedError("set_sflow_port is only implemented for MOPS")

    def get_snmp_information(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            snmp_info = self._get_active_connection().get_snmp_information()
            required_keys = ['chassis_id', 'community', 'contact', 'location']
            for key in required_keys:
                if key not in snmp_info:
                    snmp_info[key] = '' if key != 'community' else {}
            return snmp_info
        raise NotImplementedError("get_snmp_information is not implemented for this protocol")

    def get_profiles(self, storage='nvm'):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_profiles(storage)
        raise NotImplementedError("get_profiles is not implemented for this protocol")

    def get_config_fingerprint(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_config_fingerprint()
        raise NotImplementedError("get_config_fingerprint is not implemented for this protocol")

    def activate_profile(self, storage='nvm', index=1):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().activate_profile(storage, index)
        raise NotImplementedError("activate_profile is not implemented for this protocol")

    def delete_profile(self, storage='nvm', index=1):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().delete_profile(storage, index)
        raise NotImplementedError("delete_profile is not implemented for this protocol")

    def get_rstp(self):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_rstp()
        raise NotImplementedError("get_rstp is not implemented for this protocol")

    def get_rstp_port(self, interface=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().get_rstp_port(interface)
        raise NotImplementedError("get_rstp_port is not implemented for this protocol")

    def set_rstp(self, enabled=None, mode=None, priority=None,
                 hello_time=None, max_age=None, forward_delay=None,
                 hold_count=None, bpdu_guard=None, bpdu_filter=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().set_rstp(
                enabled, mode, priority, hello_time, max_age, forward_delay,
                hold_count, bpdu_guard, bpdu_filter,
            )
        raise NotImplementedError("set_rstp is not implemented for this protocol")

    def set_rstp_port(self, interface, enabled=None, edge_port=None,
                      auto_edge=None, path_cost=None, priority=None,
                      root_guard=None, loop_guard=None, tcn_guard=None,
                      bpdu_filter=None, bpdu_flood=None):
        if self.active_protocol in ('ssh', 'snmp', 'mops'):
            return self._get_active_connection().set_rstp_port(
                interface, enabled, edge_port, auto_edge, path_cost, priority,
                root_guard, loop_guard, tcn_guard, bpdu_filter, bpdu_flood,
            )
        raise NotImplementedError("set_rstp_port is not implemented for this protocol")

    def get_auto_disable(self):
        if self.active_protocol in ('mops', 'snmp', 'ssh'):
            return self._get_active_connection().get_auto_disable()
        raise NotImplementedError("get_auto_disable is not implemented for this protocol")

    def set_auto_disable(self, interface, timer=0):
        if self.active_protocol in ('mops', 'snmp', 'ssh'):
            return self._get_active_connection().set_auto_disable(interface, timer)
        raise NotImplementedError("set_auto_disable is not implemented for this protocol")

    def reset_auto_disable(self, interface):
        if self.active_protocol in ('mops', 'snmp', 'ssh'):
            return self._get_active_connection().reset_auto_disable(interface)
        raise NotImplementedError("reset_auto_disable is not implemented for this protocol")

    def set_auto_disable_reason(self, reason, enabled=True):
        if self.active_protocol in ('mops', 'snmp', 'ssh'):
            return self._get_active_connection().set_auto_disable_reason(reason, enabled)
        raise NotImplementedError("set_auto_disable_reason is not implemented for this protocol")

    def get_loop_protection(self):
        if self.active_protocol in ('mops', 'snmp', 'ssh'):
            return self._get_active_connection().get_loop_protection()
        raise NotImplementedError("get_loop_protection is not implemented for this protocol")

    def set_loop_protection(self, interface=None, enabled=None, mode=None,
                            action=None, vlan_id=None,
                            transmit_interval=None, receive_threshold=None):
        if self.active_protocol in ('mops', 'snmp', 'ssh'):
            return self._get_active_connection().set_loop_protection(
                interface, enabled, mode, action, vlan_id,
                transmit_interval, receive_threshold,
            )
        raise NotImplementedError("set_loop_protection is not implemented for this protocol")

    # ------------------------------------------------------------------
    # MOPS staging (atomic multi-setter batching)
    # ------------------------------------------------------------------

    def start_staging(self):
        """Enter staging mode — MOPS mutations are queued, not sent.

        Staging batches mutations into one atomic POST. The driver does
        not validate dependencies between staged operations. Operations
        that depend on prior state (e.g. set_vlan_egress requires the
        VLAN to exist) must have their prerequisites committed first.
        Tool layer is responsible for operation ordering.

        VLAN CRUD (create/update/delete_vlan) always fires immediately
        regardless of staging mode.

        Raises NotImplementedError for SNMP/SSH (use load_merge_candidate
        for SSH CLI staging).
        """
        if self.active_protocol == 'mops':
            return self.mops.start_staging()
        raise NotImplementedError(
            "start_staging is only available via MOPS. "
            "Use load_merge_candidate() for SSH CLI staging.")

    def commit_staging(self):
        """Fire all queued MOPS mutations in one atomic POST.

        Does NOT save to NVM — call save_config() separately when ready.
        """
        if self.active_protocol == 'mops':
            return self.mops.commit_staging()
        raise NotImplementedError("commit_staging is only available via MOPS")

    def discard_staging(self):
        """Clear queued MOPS mutations without sending."""
        if self.active_protocol == 'mops':
            return self.mops.discard_staging()
        raise NotImplementedError("discard_staging is only available via MOPS")

    def get_staged_mutations(self):
        """Return list of staged mutation tuples for inspection."""
        if self.active_protocol == 'mops':
            return self.mops.get_staged_mutations()
        raise NotImplementedError("get_staged_mutations is only available via MOPS")
