from netmiko import ConnectHandler
from napalm.base.exceptions import ConnectionException
from napalm_hios.utils import log_error, parse_dot_keys, parse_table, parse_multiline_table
from typing import List, Dict, Any

import logging
import re
import time

logger = logging.getLogger(__name__)


def _safe_int(val, default=0):
    """Safely convert string to int."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


# Auto-disable reason → category mapping (CLI doesn't show category)
_AD_REASON_CATEGORY = {
    'link-flap': 'port-monitor', 'crc-error': 'port-monitor',
    'duplex-mismatch': 'port-monitor', 'dhcp-snooping': 'network-security',
    'arp-rate': 'network-security', 'bpdu-rate': 'l2-redundancy',
    'port-security': 'network-security', 'overload-detection': 'port-monitor',
    'speed-duplex': 'port-monitor', 'loop-protection': 'l2-redundancy',
}

# Signal Contact / Device Monitor: CLI mode → MOPS mode name
_SC_CLI_MODE = {
    'manual': 'manual', 'monitor': 'monitor',
    'device-status': 'deviceState',
    'security-status': 'deviceSecurity',
    'dev-sec-status': 'deviceStateAndSecurity',
}
_SC_CLI_MODE_REV = {v: k for k, v in _SC_CLI_MODE.items()}

# Signal Contact / Device Monitor: CLI display name → dict key
_SC_CLI_SENSE = {
    'Link Failure': 'link_failure',
    'Temperature': 'temperature',
    'Fan Failure': 'fan',
    'Module Removal': 'module_removal',
    'ACA not present': 'envm_removal',
    'ACA not in sync': 'envm_not_in_sync',
    'Ring Redundancy': 'ring_redundancy',
    'Ethernet Loops': 'ethernet_loops',
    'Humidity': 'humidity',
    'STP Port Block': 'stp_port_block',
}

# Dict key → CLI config command suffix (signal-contact + device-status)
_SENSE_CLI_CMD = {
    'link_failure': 'link-failure',
    'temperature': 'temperature',
    'fan': 'fan-failure',
    'module_removal': 'module-removal',
    'envm_removal': 'envm-removal',
    'envm_not_in_sync': 'envm-not-in-sync',
    'ring_redundancy': 'ring-redundancy',
    'ethernet_loops': 'ethernet-loops',
    'humidity': 'humidity',
    'stp_port_block': 'stp-blocking',
}

# Security status: CLI display name → dict key
_DEVSEC_CLI_SENSE = {
    'Password default settings unchanged': 'password_change',
    'Minimum password length less than 8': 'password_min_length',
    'Password policy settings deactivated': 'password_policy_not_configured',
    'User password policy check deactivated': 'password_policy_bypass',
    'Telnet server active': 'telnet_enabled',
    'HTTP server active': 'http_enabled',
    'SNMP unencrypted': 'snmp_unsecure',
    'Access to System Monitor possible': 'sysmon_enabled',
    'Saving the config on the ENVM possible': 'envm_update_enabled',
    'Link interrupted on enabled device ports': 'no_link_enabled',
    'Access with HiDiscovery is possible': 'hidiscovery_enabled',
    'Loading unencrypted configuration from ENVM': 'envm_config_load_unsecure',
    'IEC 61850 MMS is enabled': 'iec61850_mms_enabled',
    'Auto generated HTTPS certificate in use': 'https_cert_warning',
    'Modbus TCP/IP server active': 'modbus_tcp_enabled',
    'EtherNet/IP protocol active': 'ethernet_ip_enabled',
    'PROFINET protocol active': 'profinet_enabled',
    'PML LLDP Protocol is disabled': 'pml_disabled',
    'Secure Boot is inactive': 'secure_boot_disabled',
    'Support Mode is active': 'dev_mode_enabled',
}

# Dict key → CLI config command suffix for security-status
_DEVSEC_SENSE_CLI_CMD = {
    'password_change': 'pwd-change',
    'password_min_length': 'pwd-min-length',
    'password_policy_not_configured': 'pwd-str-not-config',
    'password_policy_bypass': 'bypass-pwd-strength',
    'telnet_enabled': 'telnet-enabled',
    'http_enabled': 'http-enabled',
    'snmp_unsecure': 'snmp-unsecure',
    'sysmon_enabled': 'sysmon-enabled',
    'envm_update_enabled': 'extnvm-upd-enabled',
    'no_link_enabled': 'no-link-enabled',
    'hidiscovery_enabled': 'hidisc-enabled',
    'envm_config_load_unsecure': 'extnvm-load-unsecure',
    'iec61850_mms_enabled': 'iec61850-mms-enabled',
    'https_cert_warning': 'https-certificate',
    'modbus_tcp_enabled': 'modbus-tcp-enabled',
    'ethernet_ip_enabled': 'ethernet-ip-enabled',
    'profinet_enabled': 'profinet-io-enabled',
    'pml_disabled': 'pml-disabled',
    'secure_boot_disabled': 'secure-boot-disabled',
    'dev_mode_enabled': 'support-mode-enabled',
}

class SSHHIOS:
    def __init__(self, hostname, username, password, timeout, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.connection = None
        self.pagination_disabled = False  # Track the pagination state
        self._in_config_mode = False      # Track global config mode
        self._factory_default = False     # True if password gate detected on open

    def open(self):
        try:
            self.connection = ConnectHandler(
                device_type='generic',
                host=self.hostname,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                port=self.port
            )
            # Check for factory-default password gate
            time.sleep(1)
            output = self.connection.read_channel()
            if 'Enter new password' in output:
                self._factory_default = True
                logger.info("Factory-default password gate detected on %s", self.hostname)
                return  # Don't try CLI commands — device is at password prompt
            self.disable_pagination()
        except Exception as e:
            log_error(logger, f"Error opening SSH connection: {str(e)}")
            raise ConnectionException(f"Cannot connect to {self.hostname} using SSH")

    def close(self):
        if self.connection:
            try:
                status = self.get_config_status()
                if not status['saved']:
                    logger.warning(
                        "Closing with unsaved config (NVM: %s). "
                        "Call save_config() before close() to persist changes.",
                        status['nvm']
                    )
            except Exception:
                pass  # best-effort check — don't block close
            self.connection.disconnect()
            self._in_config_mode = False

    def cli(self, commands: list[str] | str, encoding: str = 'text') -> dict[str, str]:
        """Execute a command or list of commands and return the output in a dictionary format."""
        if not self.connection:
            raise ConnectionException("SSH connection is not open")

        # Convert single command to list if string is passed
        if isinstance(commands, str):
            commands = [commands]

        output_dict = {}
        
        for command in commands:
            try:
                output = self.connection.send_command(
                    command,
                    expect_string=r'[>#]\s*$',
                    strip_prompt=True,
                    strip_command=True
                )
                output_dict[command] = output.strip()
            except Exception as e:
                logger.error(f"Failed to execute command '{command}': {e}")
                output_dict[command] = f"Error: {str(e)}"

        return output_dict

    def get_interfaces(self):
        """Get interface details from the device."""
        port_output = self.cli('show port')['show port']
        mtu_output = self.cli('show mtu')['show mtu']

        # Get base MAC for interface mac_address field
        sys_output = self.cli('show system info')['show system info']
        sys_data = parse_dot_keys(sys_output)
        base_mac = sys_data.get('MAC address (management)', '')

        # Parse MTU table — format: Interface  MTU (with ---- separator)
        mtu_dict = {}
        for fields in parse_table(mtu_output, min_fields=2):
            try:
                mtu_dict[fields[0]] = int(fields[1])
            except (ValueError, IndexError):
                continue

        return self.parse_show_port(port_output, mtu_dict, base_mac)

    def parse_show_port(self, output, mtu_dict=None, base_mac=''):
        """Parse the 'show port' command output from HIOS device.

        HiOS show port has 2 lines per interface.  The first line has:
            Interface  Role  Admin mode  Phys. Mode  Cross  Phys. Stat  Link  STP state
        Multi-word values like '2500 full' make fixed-index parsing unreliable,
        so we parse Link (up/down) and STP state from the right, then extract
        speed from whatever sits between Cross and Link.
        """
        interfaces = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            fields = stripped.split()
            if len(fields) < 6:
                continue
            name = fields[0]
            if '/' not in name or re.match(r'^-+$', name):
                continue
            if name.startswith('Interface'):
                continue

            # Parse from the right:  ... Link  STP_state
            link_status = fields[-2]
            admin_mode = fields[2]

            # Speed: look for a speed value anywhere after admin_mode.
            # Prefer Phys. Stat (actual negotiated) over Phys. Mode (configured).
            # Phys. Stat sits between Cross and Link — scan right-to-left for
            # the first value that looks like a speed (handles 10G, 2500, etc.).
            speed = 0
            for f in reversed(fields[3:-2]):
                if f in ('-', 'full', 'half'):
                    continue
                parsed = self._parse_speed(f)
                if parsed > 0:
                    speed = parsed
                    break

            mtu = mtu_dict.get(name, 1500) if mtu_dict else 1500

            interfaces[name] = {
                "is_up": link_status.lower() == 'up',
                "is_enabled": admin_mode.lower() == 'enabled',
                "description": "",
                "last_flapped": -1.0,
                "speed": speed * 1000000,
                "mtu": mtu,
                "mac_address": base_mac
            }

        return interfaces

    def count_ports(self, interfaces):
        return len(interfaces)

    
    def _parse_uptime(self, uptime_str: str) -> int:
        """Convert uptime string to seconds."""
        # Log the input string for debugging
        logger.debug(f"Parsing uptime string: {uptime_str}")
        
        # Regular expression to match the format "X days, HH:MM:SS"
        match = re.match(r'(\d+) days, (\d{2}):(\d{2}):(\d{2})', uptime_str)
        
        if match:
            days, hours, minutes, seconds = map(int, match.groups())
            total_seconds = (days * 24 * 3600) + (hours * 3600) + (minutes * 60) + seconds
            return total_seconds
        else:
            logger.warning(f"Unable to parse uptime string: {uptime_str}")
            return 0  # Return 0 if unable to parse

    def get_facts(self):
        facts = {
            'uptime': 0,
            'vendor': 'Belden',
            'model': '',
            'hostname': '',
            'fqdn': '',
            'os_version': '',
            'serial_number': '',
            'interface_list': []
        }

        try:
            output = self.cli('show system info')['show system info']
            data = parse_dot_keys(output)

            facts['model'] = data.get('Device hardware description', '')
            facts['serial_number'] = data.get('Serial number', '')
            facts['hostname'] = data.get('System name', '')
            facts['fqdn'] = facts['hostname']

            if 'Firmware software release (RAM)' in data:
                facts['os_version'] = data['Firmware software release (RAM)'].split()[0]

            if 'System uptime' in data:
                facts['uptime'] = self._parse_uptime(data['System uptime'])

            # Get interface list
            interfaces_output = self.cli('show port')['show port']
            facts['interface_list'] = self._parse_interface_list(interfaces_output)

        except Exception as e:
            log_error(logger, f"Error retrieving system facts via SSH: {str(e)}")

        return facts

    def _parse_interface_list(self, interfaces_output: str) -> List[str]:
        """Parse the interface list from 'show port' output.

        show port has 2 lines per interface — the second line is a
        continuation row with just dashes.  We only want the first line
        of each pair, identified by having a '/' in the interface name.
        """
        interfaces = []
        for line in interfaces_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            fields = stripped.split()
            if not fields:
                continue
            name = fields[0]
            # Skip header, separator, and continuation lines
            if name.startswith('Interface') or name.startswith('Name'):
                continue
            if re.match(r'^-+$', name):
                continue
            # Must look like an interface name (contains /)
            if '/' not in name:
                continue
            interfaces.append(name)
        return interfaces

    def get_environment(self):
        """Get device environmental stats.

        Returns data in NAPALM standard format:
          fans:        {name: {status: bool}}
          temperature: {name: {temperature: float, is_alert: bool, is_critical: bool}}
          power:       {name: {status: bool, capacity: float, output: float}}
          cpu:         {name: {%usage: float}}
          memory:      {available_ram: int, used_ram: int}
        """
        env_data = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {}
        }

        fan_status_output = self.cli('show fan')['show fan']
        temperature_output = self.cli('show system temperature limits')['show system temperature limits']
        system_info_output = self.cli('show system info')['show system info']
        resources_output = self.cli('show system resources')['show system resources']

        # Parse fan status — not all devices have fans (e.g. GRS1042)
        if 'Error' not in fan_status_output and 'Invalid' not in fan_status_output:
            for line in fan_status_output.splitlines():
                if ':' not in line:
                    continue
                try:
                    location, status = line.split(':', 1)
                    env_data['fans'][location.strip()] = {
                        'status': 'ok' in status.lower()
                    }
                except ValueError:
                    continue

        # Parse temperature using dot-key parser
        temp_data = parse_dot_keys(temperature_output)
        current_temp = None
        upper_limit = None
        lower_limit = None
        if 'Current temperature' in temp_data:
            current_temp = float(temp_data['Current temperature'].replace(' C', ''))
        if 'Temperature upper limit' in temp_data:
            upper_limit = float(temp_data['Temperature upper limit'].replace(' C', ''))
        if 'Temperature lower limit' in temp_data:
            lower_limit = float(temp_data['Temperature lower limit'].replace(' C', ''))

        is_alert = False
        if current_temp is not None and upper_limit is not None and lower_limit is not None:
            is_alert = current_temp > upper_limit or current_temp < lower_limit

        env_data['temperature']['chassis'] = {
            'temperature': current_temp if current_temp is not None else 0.0,
            'is_alert': is_alert,
            'is_critical': is_alert
        }

        # Parse power supply from system info
        info_data = parse_dot_keys(system_info_output)
        for key in ['Power Supply P1, state', 'Power Supply P2, state']:
            if key in info_data:
                psu_name = key.split(',')[0]  # "Power Supply P1"
                env_data['power'][psu_name] = {
                    'status': 'present' in info_data[key].lower(),
                    'capacity': -1.0,
                    'output': -1.0
                }

        # Parse CPU and memory from system resources
        res_data = parse_dot_keys(resources_output)
        if 'CPU utilization' in res_data:
            usage = float(res_data['CPU utilization'].replace('%', ''))
            env_data['cpu']['0'] = {'%usage': usage}

        allocated_ram = 0
        free_ram = 0
        if 'Allocated RAM' in res_data:
            allocated_ram = int(res_data['Allocated RAM'].replace(' kBytes', ''))
        if 'Free RAM' in res_data:
            free_ram = int(res_data['Free RAM'].replace(' kBytes', ''))

        env_data['memory'] = {
            'available_ram': allocated_ram,
            'used_ram': allocated_ram - free_ram
        }

        return env_data

    def convert_age_to_float(self, age_str: str) -> float:
        """Converts an age string to a float representing total seconds."""
        days, time = age_str.split("days,") if "days" in age_str else (0, age_str)
        days = int(days.strip()) if days else 0
        try:
            hours, minutes, seconds = map(int, re.split('[:,]', time.strip()))
        except ValueError:
            hours, minutes, seconds = 0, 0, 0
        total_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
        return float(total_seconds)

    def get_arp_table(self, vrf: str = '') -> List[Dict[str, Any]]:
        """Returns a list of dictionaries with ARP table entries.

        Tries L3 command first (show ip arp table), then falls back to
        the agent-level command (show arp) for L2-only switches.
        """
        commands = ['show ip arp table', 'show arp']
        arp_entries = []

        for command in commands:
            try:
                arp_output = self.cli(command)[command]

                # Check for error messages
                if 'Error' in arp_output:
                    logger.debug(f"Command '{command}' failed. Trying next command.")
                    continue

                if command == 'show ip arp table':
                    arp_entries = self._parse_show_ip_arp_table(arp_output)
                else:
                    arp_entries = self._parse_show_arp(arp_output)

                if arp_entries:
                    break

            except Exception as e:
                logger.error(f"Error executing '{command}': {str(e)}")
                continue

        return arp_entries

    def _parse_show_ip_arp_table(self, arp_output: str) -> List[Dict[str, Any]]:
        """Parse the output of 'show ip arp table' command.

        Format:
            Intf      IP Address      Last updated       MAC Address       Type    Active
            --------- --------------- ------------------ ----------------- ------- ------
            vlan/1    192.168.1.4      43 days, 03:27:31 64:60:38:3f:4a:a1 Dynamic [x]
        """
        entries = []
        rows = parse_table(arp_output, min_fields=6)
        for fields in rows:
            # Fields: intf, ip, <age: "N days, HH:MM:SS">, mac, type, active
            # The age span is variable width — find the MAC by pattern
            interface = fields[0]
            ip_addr = fields[1]

            # Find MAC address field (xx:xx:xx:xx:xx:xx pattern)
            mac = ''
            mac_idx = None
            for idx, f in enumerate(fields[2:], start=2):
                if re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', f, re.I):
                    mac = f
                    mac_idx = idx
                    break

            if not mac:
                continue

            # Age is everything between ip and mac
            age_parts = fields[2:mac_idx]
            age_str = ' '.join(age_parts)
            age = self.convert_age_to_float(age_str)

            entries.append({
                'interface': interface,
                'ip': ip_addr,
                'mac': mac,
                'age': age
            })
        return entries

    def _parse_show_arp(self, arp_output: str) -> List[Dict[str, Any]]:
        """Parse ``show arp`` (L2 switches).

        2-line-per-record format::

            Intf   IP Address          Age    Type    Active
                   MAC Address
            -----  -----               -----  -----   ------
            cpu/1  192.168.1.4         0      Local   [x]
                   64:60:38:3f:4a:a1
        """
        rows = parse_table(arp_output, min_fields=1)
        entries = []
        i = 0
        while i < len(rows):
            fields = rows[i]
            if '/' in fields[0] and len(fields) >= 4:
                interface = fields[0]
                ip_addr = fields[1]
                # Skip IPv6 entries — NAPALM ARP is IPv4-only
                if ':' in ip_addr:
                    i += 2
                    continue
                try:
                    age = float(fields[2])
                except ValueError:
                    age = 0.0

                # MAC is on the next line
                mac = ''
                if i + 1 < len(rows) and len(rows[i + 1]) >= 1:
                    candidate = rows[i + 1][0]
                    if re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$', candidate, re.I):
                        mac = candidate
                    i += 2
                else:
                    i += 1

                if mac:
                    entries.append({
                        'interface': interface,
                        'ip': ip_addr,
                        'mac': mac,
                        'age': age
                    })
            else:
                i += 1

        return entries

    def disable_pagination(self):
        """Disable CLI pagination for the session."""
        if not self.pagination_disabled:
            try:
                self.cli('cli numlines 0')
                self.pagination_disabled = True
                logger.debug("Pagination disabled successfully")
            except Exception as e:
                logger.warning(f"Failed to disable pagination: {str(e)}")

    def _get_active_profile_index(self):
        """Helper method to find the active profile index."""
        try:
            output = self.cli('show config profiles nvm')['show config profiles nvm']
            lines = output.splitlines()
            
            # Initialize previous line and index
            prev_line = None
            
            for line in lines:
                if '[x]' in line and prev_line:
                    # Extract the index from the previous line
                    parts = prev_line.split()
                    if parts:
                        # Return the first part which should be the index number
                        return parts[0].strip()
                prev_line = line
                
            logger.warning("No active profile found in configuration profiles")
            return None
            
        except Exception as e:
            log_error(logger, f"Error getting active profile index: {str(e)}")
            raise

    def _get_xml_config(self, profile_index):
        """Helper method to retrieve XML configuration for a specific profile."""
        if not self.connection:
            raise ConnectionException("SSH connection is not open")
            
        try:
            # First command to initiate XML retrieval
            cmd = f'show config profiles nvm {profile_index}'
            self.connection.write_channel(cmd + '\n')
            time.sleep(0.5)
            
            # Wait for the Y/N prompt
            output = ""
            max_attempts = 20
            for _ in range(max_attempts):
                new_data = self.connection.read_channel()
                output += new_data
                if '(Y/N) ?' in output:
                    break
                time.sleep(0.5)
            
            if '(Y/N) ?' not in output:
                raise Exception("Did not receive expected Y/N prompt")
                
            # Send 'y' and collect XML
            self.connection.write_channel('y\n')
            time.sleep(0.5)
            
            xml_output = ""
            xml_started = False
            max_attempts = 50  # Adjust based on typical response time
            
            for _ in range(max_attempts):
                new_data = self.connection.read_channel()
                
                if not xml_started and '<?xml' in new_data:
                    xml_started = True
                    xml_output = new_data[new_data.find('<?xml'):]
                elif xml_started:
                    xml_output += new_data
                
                # Check if we've reached the end of XML
                if xml_started and '</Config>' in new_data:
                    # Only keep up to </Config>
                    xml_output = xml_output[:xml_output.find('</Config>') + 9]
                    break
                    
                time.sleep(0.5)
            
            if not xml_started or '</Config>' not in xml_output:
                raise Exception("Failed to retrieve complete XML configuration")
            
            return xml_output.strip()
            
        except Exception as e:
            log_error(logger, f"Error retrieving XML configuration: {str(e)}")
            raise

    def get_config(self, retrieve: str = 'all', full: bool = False, sanitized: bool = True, format: str = 'text'):
        config_dict = {
            'running': '',
            'startup': '',
            'candidate': ''
        }

        try:
            if format == 'text':
                command = 'show running-config script all' if full else 'show running-config script'
                output = self.cli(command)
                config_dict['running'] = output[command].strip()
            else:
                # Handle other formats if needed
                log_error(logger, f"Unsupported config format: {format}")
        except Exception as e:
            log_error(logger, f"Error retrieving configuration: {str(e)}")

        return config_dict

    def get_config_status(self):
        """Check if running config is saved to NVM.

        Returns::

            {
                'saved': True,            # running-config matches NVM
                'nvm': 'ok',              # 'ok' | 'out of sync' | 'busy'
                'aca': 'absent',          # 'ok' | 'out of sync' | 'absent'
                'boot': 'ok',
            }
        """
        output = self.cli('show config status')['show config status']
        data = parse_dot_keys(output)

        nvm = data.get('running-config to NVM', '').lower()
        aca = data.get('NVM to ACA', '').lower()
        boot = data.get('Boot parameters', '').lower()

        return {
            'saved': nvm == 'ok',
            'nvm': nvm,
            'aca': aca,
            'boot': boot,
        }

    def save_config(self):
        """Save running config to non-volatile memory.

        Equivalent to ``copy config running-config nvm`` in enable mode.
        Waits for the NVM write to complete (up to 10s) before returning.
        Returns the post-save config status.
        """
        self._enable()
        try:
            self.cli('copy config running-config nvm')
        finally:
            self._disable()

        # NVM write is async — poll until settled (not "busy")
        for _ in range(10):
            status = self.get_config_status()
            if status['nvm'] != 'busy':
                return status
            time.sleep(1)

        return self.get_config_status()

    def get_config_remote(self):
        """Return remote config backup settings via SSH CLI.

        Parses ``show config remote-backup`` output. Server username
        is not available via CLI — returned as empty string.
        """
        output = self.cli('show config remote-backup')
        data = parse_dot_keys(output.get('show config remote-backup', ''))

        enabled_str = data.get('Remote backup', '').lower()
        destination = data.get('Destination URL', '')
        username = data.get('User name', '')

        return {
            'server_username': '',  # not available via CLI
            'auto_backup': {
                'enabled': enabled_str in ('enabled', 'enable', 'on'),
                'destination': destination,
                'username': username,
            },
        }

    def set_config_remote(self, action=None, server=None, profile=None,
                          source='nvm', destination='nvm',
                          auto_backup=None, auto_backup_url=None,
                          auto_backup_username=None, auto_backup_password=None,
                          username=None, password=None):
        """Configure remote config transfer and/or auto-backup via SSH CLI.

        Server credentials (username/password) are not settable via CLI
        for file transfers — use MOPS or SNMP for those.
        """
        # Auto-backup config
        if (auto_backup is not None or auto_backup_url is not None
                or auto_backup_username is not None
                or auto_backup_password is not None):
            self._config_mode()
            try:
                if auto_backup_url is not None:
                    self.cli(f'config remote-backup destination {auto_backup_url}')
                if auto_backup_username is not None:
                    self.cli(f'config remote-backup username {auto_backup_username}')
                if auto_backup_password is not None:
                    self.cli(f'config remote-backup password {auto_backup_password}')
                if auto_backup is True:
                    self.cli('config remote-backup operation')
                elif auto_backup is False:
                    self.cli('no config remote-backup operation')
            finally:
                self._exit_config_mode()

        # One-shot transfer
        if action and server:
            self._enable()
            try:
                if action == 'pull':
                    cmd = f'copy config remote {server} {destination}'
                    if profile:
                        cmd += f' profile {profile}'
                    self.cli(cmd)
                elif action == 'push':
                    cmd = f'copy config running-config remote {server}'
                    self.cli(cmd)
                else:
                    raise ValueError(
                        f"Invalid action '{action}': use 'pull' or 'push'")
            finally:
                self._disable()

        return self.get_config_remote()

    def get_interfaces_ip(self):
        """Get IP addresses configured on interfaces.

        Uses ``show ip interface`` on L3 switches.  Falls back to
        ``show network parms`` on L2-only devices to return the
        management IP.
        """
        output = self.cli('show ip interface')['show ip interface']

        # L2 switches don't support this command — fall back to management IP
        if 'Error' in output:
            return self._parse_network_parms()

        interfaces = {}
        for fields in parse_table(output, min_fields=3):
            interface, ip_address, subnet_mask = fields[0], fields[1], fields[2]

            if ip_address == '0.0.0.0' and subnet_mask == '0.0.0.0':
                continue

            prefix_length = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))

            if interface not in interfaces:
                interfaces[interface] = {'ipv4': {}}

            interfaces[interface]['ipv4'][ip_address] = {
                'prefix_length': prefix_length
            }

        return interfaces

    def _parse_network_parms(self):
        """Parse ``show network parms`` for L2 management IP."""
        output = self.cli('show network parms')['show network parms']
        data = parse_dot_keys(output)
        ip = data.get('Local IP address', '0.0.0.0')
        mask = data.get('Subnetmask', '0.0.0.0')
        vlan_id = data.get('Management VLAN ID', '1')

        if ip == '0.0.0.0':
            return {}

        prefix_length = sum(bin(int(x)).count('1') for x in mask.split('.'))
        return {
            f'vlan/{vlan_id}': {
                'ipv4': {
                    ip: {'prefix_length': prefix_length}
                }
            }
        }

    def _calculate_prefix_length(self, subnet_mask):
        """Helper method to calculate prefix length from subnet mask."""
        return sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
    
    def get_interfaces_counters(self):
        """Get interface counters.

        ``show interface counters`` has 3 lines per interface::

            Intf  RxUcast  RxMcast  RxBcast  RxOctets  RxDiscard  RxErrors
                  TxUcast  TxMcast  TxBcast  TxOctets  TxDiscard  TxErrors
                  RxUnknPro

        We detect the ``-----`` separator (not a hard-coded line count),
        then group rows by looking for interface names (contain ``/``).
        """
        output = self.cli('show interface counters')['show interface counters']
        interfaces = {}

        rows = parse_table(output, min_fields=1)
        current_interface = None
        line_in_record = 0

        for fields in rows:
            if '/' in fields[0]:
                # RX line — first line of a new record
                current_interface = fields[0]
                interfaces[current_interface] = {
                    'rx_unicast_packets': 0, 'rx_multicast_packets': 0, 'rx_broadcast_packets': 0,
                    'rx_octets': 0, 'rx_discards': 0, 'rx_errors': 0,
                    'tx_unicast_packets': 0, 'tx_multicast_packets': 0, 'tx_broadcast_packets': 0,
                    'tx_octets': 0, 'tx_discards': 0, 'tx_errors': 0
                }
                if len(fields) >= 7:
                    try:
                        interfaces[current_interface].update({
                            'rx_unicast_packets': int(fields[1]),
                            'rx_multicast_packets': int(fields[2]),
                            'rx_broadcast_packets': int(fields[3]),
                            'rx_octets': int(fields[4]),
                            'rx_discards': int(fields[5]),
                            'rx_errors': int(fields[6])
                        })
                    except ValueError:
                        pass
                line_in_record = 1

            elif current_interface and line_in_record == 1 and len(fields) >= 6:
                # TX line — second line of the record
                try:
                    interfaces[current_interface].update({
                        'tx_unicast_packets': int(fields[0]),
                        'tx_multicast_packets': int(fields[1]),
                        'tx_broadcast_packets': int(fields[2]),
                        'tx_octets': int(fields[3]),
                        'tx_discards': int(fields[4]),
                        'tx_errors': int(fields[5])
                    })
                except ValueError:
                    pass
                line_in_record = 2

            else:
                # Third line (RxUnknPro) — ignored
                line_in_record = 0

        return interfaces
    
    def _parse_lldp_remote_data(self, output):
        """Parse 'show lldp remote-data' into structured neighbor data.

        Returns dict[str, list[dict]] keyed by local port.  Each entry is
        the full extended neighbor dict.  Handles continuation lines (lines
        without ``....`` are appended to the previous key) and collects ALL
        management addresses into lists.
        """
        result = {}
        sections = output.split('Remote data,')[1:]

        for section in sections:
            lines = section.strip().split('\n')
            local_port = None

            if lines:
                local_port = lines[0].split('-')[0].strip().split(',')[-1].strip()
            if not local_port:
                continue

            # Parse dot-key lines with continuation line support
            parsed = {}
            last_key = None
            mgmt_ipv4 = []
            mgmt_ipv6 = []

            for line in lines[1:]:
                stripped = line.strip()
                if not stripped:
                    continue

                if '....' in stripped:
                    key, value = [p.strip() for p in stripped.split('....', 1)]
                    value = value.lstrip('.')
                    key_lower = key.lower()
                    last_key = key_lower

                    if key_lower == 'ipv4 management address':
                        mgmt_ipv4.append(value)
                    elif key_lower == 'ipv6 management address':
                        mgmt_ipv6.append(value)
                    else:
                        parsed[key_lower] = value
                else:
                    # Continuation line — append to previous key's value
                    if last_key and last_key in parsed:
                        parsed[last_key] += ' ' + stripped

            # Build neighbor dict
            neighbor = {
                'parent_interface': local_port,
                'remote_port': '',
                'remote_port_description': '',
                'remote_chassis_id': '',
                'remote_system_name': '',
                'remote_system_description': '',
                'remote_system_capab': [],
                'remote_system_enable_capab': [],
                'remote_management_ipv4': mgmt_ipv4[0] if mgmt_ipv4 else '',
                'remote_management_ipv6': mgmt_ipv6[0] if mgmt_ipv6 else '',
                'management_addresses': mgmt_ipv4 + mgmt_ipv6,
                'autoneg_support': '',
                'autoneg_enabled': '',
                'port_oper_mau_type': '',
                'port_vlan_id': '',
                'vlan_membership': [],
                'link_agg_status': '',
                'link_agg_port_id': '',
            }

            if 'chassis id' in parsed:
                neighbor['remote_chassis_id'] = parsed['chassis id'].split('(')[0].strip()
            if 'port id' in parsed:
                neighbor['remote_port'] = parsed['port id'].split('(')[0].strip()
            if 'system name' in parsed:
                neighbor['remote_system_name'] = parsed['system name']
            if 'port description' in parsed:
                neighbor['remote_port_description'] = parsed['port description']
            if 'system description' in parsed:
                neighbor['remote_system_description'] = parsed['system description']
            if 'autoneg. supp./enabled' in parsed:
                parts = parsed['autoneg. supp./enabled'].split('/')
                if len(parts) == 2:
                    neighbor['autoneg_support'] = parts[0].strip()
                    neighbor['autoneg_enabled'] = parts[1].strip()
            # Note: 'autoneg. cap. bits' contains 802.3 PHY-level MAU types
            # (e.g. 10baseT, 1000baseTFD), NOT LLDP system capabilities
            # (bridge, router, etc.).  HiOS CLI does not expose the system
            # capabilities TLV, so remote_system_capab stays empty.
            if 'port oper. mau type' in parsed:
                val = parsed['port oper. mau type']
                neighbor['port_oper_mau_type'] = val.split('(')[-1].strip(')') if '(' in val else val
            if 'port vlan id' in parsed:
                neighbor['port_vlan_id'] = parsed['port vlan id']
            if 'vlan membership' in parsed:
                neighbor['vlan_membership'] = self._parse_vlan_membership(parsed['vlan membership'])
            if 'link agg. status' in parsed:
                neighbor['link_agg_status'] = parsed['link agg. status']
            if 'link agg. port id' in parsed:
                neighbor['link_agg_port_id'] = parsed['link agg. port id']

            if local_port not in result:
                result[local_port] = []
            result[local_port].append(neighbor)

        return result

    def get_lldp_neighbors(self):
        output = self.cli('show lldp remote-data')['show lldp remote-data']
        parsed = self._parse_lldp_remote_data(output)
        result = {}
        for port, neighbors in parsed.items():
            for n in neighbors:
                hostname = n['remote_system_name'] or n['remote_chassis_id']
                port_name = n['remote_port_description'] or n['remote_port']
                if not hostname:
                    continue
                if port not in result:
                    result[port] = []
                result[port].append({'hostname': hostname, 'port': port_name})
        return result

    def get_lldp_neighbors_detail(self, interface: str = '') -> Dict[str, List[Dict[str, Any]]]:
        output = self.cli('show lldp remote-data')['show lldp remote-data']
        parsed = self._parse_lldp_remote_data(output)
        result = {}
        for port, neighbors in parsed.items():
            result[port] = [{
                'parent_interface': n['parent_interface'],
                'remote_port': n['remote_port'],
                'remote_port_description': n['remote_port_description'],
                'remote_chassis_id': n['remote_chassis_id'],
                'remote_system_name': n['remote_system_name'],
                'remote_system_description': n['remote_system_description'],
                'remote_system_capab': n['remote_system_capab'],
                'remote_system_enable_capab': n['remote_system_enable_capab'],
                'remote_management_address': n['remote_management_ipv4'],
            } for n in neighbors]
        if interface:
            return {interface: result.get(interface, [])}
        return result

    def get_lldp_neighbors_detail_extended(self, interface: str = '') -> Dict[str, List[Dict[str, Any]]]:
        output = self.cli('show lldp remote-data')['show lldp remote-data']
        parsed = self._parse_lldp_remote_data(output)
        if interface:
            return {interface: parsed.get(interface, [])}
        return parsed

    def _parse_vlan_membership(self, value: str) -> List[int]:
        if value == '<n/a>' or not value:
            return []
        try:
            return [int(vlan.strip()) for vlan in value.split(',') if vlan.strip()]
        except ValueError:
            print(f"Warning: Unable to parse VLAN membership value: {value}")
            return []

    def _map_capability(self, cap: str) -> str:
        # List of recognized capabilities
        recognized_caps = [
            'repeater', 'bridge', 'wlan-access-point', 'router',
            'telephone', 'docsis-cable-device', 'station'
        ]
        
        # Check if the capability is in the recognized list
        for recognized_cap in recognized_caps:
            if recognized_cap in cap.lower():
                return recognized_cap
        
        # If not recognized, return 'other'
        return 'other'
    
    def get_mac_address_table(self) -> List[Dict[str, Any]]:
        """Get MAC address table.

        Format::

            VLAN  Mac Address        Interface  IfIndex  Status
            ----  -----------------  ---------  -------  ------------
            1     16:5f:8d:ba:75:cc  3/3        23       learned
        """
        output = self.cli('show mac-addr-table')['show mac-addr-table']
        mac_address_table = []

        for fields in parse_table(output, min_fields=5):
            try:
                mac_address_table.append({
                    'mac': fields[1],
                    'interface': fields[2],
                    'vlan': int(fields[0]),
                    'static': fields[4].lower() != 'learned',
                    'active': True,
                    'moves': 0,
                    'last_move': 0.0
                })
            except (ValueError, IndexError):
                continue

        return mac_address_table
    

    def _parse_ntp_server_info(self, server_output, status_output):
        """Parse NTP/SNTP server info from ``show sntp client server`` + ``show sntp client status``.

        Server table is 2-line-per-record::

            Idx  Address type  Port  Address
                 Status        Active  Description
            ---  ----------    ------  ----------
              1  ipv4            123  192.168.3.1
                 success         [x]  Pool NTP
        """
        # Parse SNTP client status (dot-key format)
        status_data = parse_dot_keys(status_output)
        hostpoll = 0
        global_synchronized = False
        if 'Request-interval [s]' in status_data:
            try:
                hostpoll = int(status_data['Request-interval [s]'])
            except ValueError:
                pass
        if 'Status' in status_data:
            global_synchronized = 'synchronized to remote server' in status_data['Status'].lower()

        # Parse server table — 2 lines per entry
        rows = parse_table(server_output, min_fields=1)
        servers = []
        i = 0
        while i < len(rows):
            fields = rows[i]
            # First line starts with a numeric index
            if fields and fields[0].isdigit() and len(fields) >= 4:
                address = fields[3]
                addr_type = fields[1]

                # Second line has status
                synced = False
                if i + 1 < len(rows):
                    status_line = ' '.join(rows[i + 1])
                    synced = global_synchronized and 'success' in status_line.lower()
                    i += 2
                else:
                    i += 1

                servers.append({
                    'remote': address,
                    'referenceid': '',
                    'synchronized': synced,
                    'stratum': 0,
                    'type': addr_type,
                    'when': '',
                    'hostpoll': hostpoll,
                    'reachability': 0,
                    'delay': 0.0,
                    'offset': 0.0,
                    'jitter': 0.0
                })
            else:
                i += 1

        return servers

    def get_ntp_servers(self):
        """
        Returns the NTP servers configuration as dictionary.
        """
        server_output = self.cli('show sntp client server')['show sntp client server']
        status_output = self.cli('show sntp client status')['show sntp client status']
        servers = self._parse_ntp_server_info(server_output, status_output)
        
        return {server['remote']: {} for server in servers}

    def get_ntp_stats(self):
        """
        Returns a list of NTP synchronization statistics.
        """
        server_output = self.cli('show sntp client server')['show sntp client server']
        status_output = self.cli('show sntp client status')['show sntp client status']
        return self._parse_ntp_server_info(server_output, status_output)
    
    def get_optics(self):
        """Fetches SFP transceiver power levels.

        HiOS ``show sfp`` has 2 lines per SFP.  Line 1 layout::

            Intf  Part-ID...  ModType  Temp   TxPower [dBm/mW]  RxPower [dBm/mW]
            1/1   M-SFP-2.5-MM EEC  SFP  46/115  -4.2 /0.3763  -4.4 /0.3606

        Part ID and module type are variable-width, so we locate power
        values by scanning for ``<float> /<float>`` pairs (dBm / mW).
        """
        sfp_output = self.cli('show sfp')['show sfp']
        optics_dict = {}

        # Match power pairs:  -4.2 /0.3763  (dBm / mW).
        # Require a decimal point in the dBm value to skip the Temp column (46/115).
        power_re = re.compile(r'(-?\d+\.\d+)\s*/\s*(\d+\.\d+)')

        for line in sfp_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            fields = stripped.split()
            if not fields or '/' not in fields[0]:
                continue
            # Skip separator lines
            if re.match(r'^-+$', fields[0]):
                continue

            intf_name = fields[0]
            powers = power_re.findall(stripped)
            if len(powers) < 2:
                continue

            # First pair = TX power, second pair = RX power (both in dBm)
            try:
                tx_power = float(powers[0][0])
                rx_power = float(powers[1][0])
            except (ValueError, IndexError):
                continue

            optics_dict[intf_name] = {
                'physical_channels': {
                    'channel': [
                        {
                            'index': 0,
                            'state': {
                                'input_power': {
                                    'instant': rx_power,
                                    'avg': 0.0,
                                    'min': 0.0,
                                    'max': 0.0,
                                },
                                'output_power': {
                                    'instant': tx_power,
                                    'avg': 0.0,
                                    'min': 0.0,
                                    'max': 0.0,
                                },
                                'laser_bias_current': {
                                    'instant': 0.0,
                                    'avg': 0.0,
                                    'min': 0.0,
                                    'max': 0.0,
                                },
                            }
                        }
                    ]
                }
            }

        return optics_dict

    def get_users(self):
        """Get configured users.

        ``show users`` has 2 lines per user::

            User Name          Authentication  PolicyCheck  Status
            Access Mode          Encryption                 Locked
            ----               ----            ----         ----
            admin              md5             false        [x]
            administrator      des                          [ ]
        """
        users_output = self.cli('show users')['show users']
        users_dict = {}

        # Use parse_table to skip everything before the ---- separator
        rows = parse_table(users_output, min_fields=1)

        # Group into 2-line records: username line then access-mode line
        i = 0
        while i < len(rows):
            user_fields = rows[i]
            username = user_fields[0]

            # Determine access level from the next line
            level = 0
            if i + 1 < len(rows):
                access_mode = rows[i + 1][0].lower()
                if access_mode == 'administrator':
                    level = 15
                elif access_mode in ('guest', 'auditor', 'operator'):
                    level = 1
                i += 2
            else:
                i += 1

            users_dict[username] = {
                'level': level,
                'password': '',
                'sshkeys': []
            }

        return users_dict
    
    def get_vlans(self):
        """Get VLANs with names and assigned interfaces.

        ``show vlan brief`` table::

            VLAN ID VLAN Name     VLAN Type   VLAN Creation Time
            ------- ----------    ----------  ------------------
                  1 HOME          default       0 days, 00:00:13

        ``show vlan port`` table::

            Interface VLAN ID Frame Types  Filtering Priority
            --------- ------- ------------ --------- --------
            1/1       1       admit all    disable   0
        """
        vlan_brief_output = self.cli('show vlan brief')['show vlan brief']
        vlan_port_output = self.cli('show vlan port')['show vlan port']

        vlans_dict = {}

        # Parse VLAN names — fields[0]=ID, fields[1]=name
        for fields in parse_table(vlan_brief_output, min_fields=2):
            try:
                vlan_id = int(fields[0])
                vlans_dict[vlan_id] = {"name": fields[1], "interfaces": []}
            except ValueError:
                continue

        # Parse interface-to-VLAN assignments — fields[0]=intf, fields[1]=vlan
        for fields in parse_table(vlan_port_output, min_fields=2):
            try:
                interface = fields[0]
                vlan_id = int(fields[1])
                if vlan_id in vlans_dict:
                    vlans_dict[vlan_id]["interfaces"].append(interface)
            except ValueError:
                continue

        return vlans_dict
    
    def ping(self, destination, source='', ttl=255, timeout=2, size=100, count=5, vrf='', source_interface=''):
        """
        Execute ping on the device and return the results.
        """
        # Construct the ping command
        command = f"ping {destination}"
        if count and count != 5:
            command += f" count {count}"  # Ensure count is specified correctly based on device syntax

        try:
            output = self.cli(command)[command]
            logger.debug(f"Ping output: {output}")
        except Exception as e:
            logger.error(f"Error executing ping command: {str(e)}")
            return {'error': str(e)}

        # Check for DNS lookup failure
        if "DNS lookup failed" in output:
            logger.warning(f"DNS lookup failed for {destination}")
            return {'error': f"DNS lookup failed for {destination}"}

        # Split the output into lines for easier processing
        lines = output.strip().split('\n')
        if not lines:
            logger.warning("Empty ping output")
            return {'error': 'Empty ping output'}

        # Initialize statistics
        stats = {
            'probes_sent': 0,
            'packet_loss': 100,  # Assume 100% loss initially
            'rtt_min': float('inf'),
            'rtt_max': float('-inf'),
            'rtt_avg': 0,
            'rtt_stddev': 0,
            'results': []  # This will only hold one entry since we only ping one IP
        }

        # Extract statistics from the output
        stats_line = next((line for line in lines if "packets transmitted" in line), None)
        if stats_line:
            match = re.search(r'(\d+) packets transmitted, (\d+) packets received', stats_line)
            if match:
                transmitted, received = map(int, match.groups())
                stats['probes_sent'] = transmitted
                stats['packet_loss'] = 100 - (received / transmitted * 100)
            else:
                logger.warning(f"Could not parse packet statistics from: {stats_line}")

        # Extract RTT values from round-trip statistics
        rtt_line = next((line for line in lines if "round-trip" in line), None)
        if rtt_line:
            match = re.search(r'min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+)', rtt_line)
            if match:
                stats['rtt_min'], stats['rtt_avg'], stats['rtt_max'] = map(float, match.groups())
            else:
                logger.warning(f"Could not parse RTT statistics from: {rtt_line}")

        # Extract individual ping result (only one expected)
        for line in lines:
            if "bytes from" in line:
                match = re.search(r'(\d+) bytes from ([\d.]+): seq=(\d+) ttl=(\d+) time=([\d.]+) ms', line)
                if match:
                    _, ip_address, _, _, rtt = match.groups()
                    # Store the result for this IP address
                    stats['results'].append({'ip_address': ip_address, 'rtt': float(rtt)})
                    break  # We only expect one result, so break after finding it
                else:
                    logger.warning(f"Could not parse ping result from: {line}")

        # Calculate standard deviation if there's a result
        if stats['results']:
            rtts = [result['rtt'] for result in stats['results']]
            mean = sum(rtts) / len(rtts)
            variance = sum((rtt - mean) ** 2 for rtt in rtts) / len(rtts)
            stats['rtt_stddev'] = variance ** 0.5

        logger.info(f"Ping to {destination} successful. Results: {stats}")
        return {'success': stats}


    def get_snmp_information(self):
        """Get SNMP information from the device.

        Uses 'show system info' for contact/location/name and
        'show snmp community' for community strings.
        """
        snmp_info = {
            'chassis_id': '',
            'contact': '',
            'location': '',
            'community': {}
        }

        try:
            # Get system info for contact/location
            sys_output = self.cli('show system info')['show system info']
            sys_data = parse_dot_keys(sys_output)
            snmp_info['chassis_id'] = sys_data.get('System name', '')
            snmp_info['contact'] = sys_data.get('System contact', '')
            snmp_info['location'] = sys_data.get('System location', '')

            # Get community strings — NAPALM standard: {name: {acl: str, mode: str}}
            comm_output = self.cli('show snmp community')['show snmp community']
            if 'Error' not in comm_output:
                rows = parse_table(comm_output, min_fields=2)
                for fields in rows:
                    community = fields[0]
                    mode = 'ro' if 'read-only' in ' '.join(fields[1:]).lower() else 'rw'
                    snmp_info['community'][community] = {
                        'acl': '',
                        'mode': mode
                    }

        except Exception as e:
            log_error(logger, f"Error retrieving SNMP information: {str(e)}")

        return snmp_info

    def set_snmp_information(self, hostname=None, contact=None, location=None):
        """Set sysName, sysContact, and/or sysLocation via SSH CLI.

        Args:
            hostname: system name, None to skip
            contact: system contact, None to skip
            location: system location, None to skip
        """
        if hostname is None and contact is None and location is None:
            return None
        self._config_mode()
        try:
            if hostname is not None:
                self.cli(f'system name {hostname}')
            if contact is not None:
                self.cli(f'system contact {contact}')
            if location is not None:
                self.cli(f'system location {location}')
        finally:
            self._exit_config_mode()
        return self.get_snmp_information()

    def get_hidiscovery(self):
        """Get HiDiscovery protocol status.

        Returns::

            {
                'enabled': True,
                'mode': 'read-only',      # 'read-only' | 'read-write'
                'blinking': False,
                'protocols': ['v1', 'v2'],
                'relay': True              # only present on L3/managed switches
            }
        """
        output = self.cli('show network hidiscovery')['show network hidiscovery']
        data = parse_dot_keys(output)

        result = {
            'enabled': data.get('Operating status', '').lower() == 'enabled',
            'mode': data.get('Operating mode', ''),
            'blinking': data.get('Blinking status', '').lower() == 'enabled',
            'protocols': [p.strip() for p in data.get('Supported protocols', '').split(',') if p.strip()],
        }

        if 'Relay status' in data:
            result['relay'] = data['Relay status'].lower() == 'enabled'

        return result

    def _enable(self):
        """Enter enable (privileged) mode.  Prompt changes from > to #."""
        self.connection.send_command(
            'enable', expect_string=r'[>#]\s*$',
            strip_prompt=True, strip_command=True
        )

    def _disable(self):
        """Exit enable mode back to user mode."""
        self.connection.send_command(
            'disable', expect_string=r'[>#]\s*$',
            strip_prompt=True, strip_command=True
        )

    def _config_mode(self):
        """Enter global config mode (enable → configure).

        Safe to call multiple times — no-ops if already in config mode.
        """
        if self._in_config_mode:
            return
        self._enable()
        self.cli('configure')
        self._in_config_mode = True

    def _exit_config_mode(self):
        """Exit global config mode back to user mode.

        Safe to call even if not in config mode.
        """
        if not self._in_config_mode:
            return
        self.cli('exit')
        self._disable()
        self._in_config_mode = False

    def _enter_interface(self, iface):
        """Enter interface config context with validation.

        Raises ValueError if the interface doesn't exist.
        Must be in config mode already.  Call self.cli('exit')
        when done with the interface.
        """
        output = self.cli(f'interface {iface}')
        resp = output.get(f'interface {iface}', '')
        if 'Error' in resp or 'Invalid' in resp:
            raise ValueError(f"Unknown interface '{iface}'")

    def get_mrp(self):
        """Get MRP (Media Redundancy Protocol) ring status.

        Returns::

            {
                'configured': True,
                'operation': 'enabled',
                'mode': 'client',
                'port_primary': '1/3',
                'port_secondary': '1/4',
                'port_primary_state': 'forwarding',
                'port_secondary_state': 'blocked',
                'domain_id': '255.255.255...255 (Default)',
                'domain_name': '',
                'vlan': 1,
                'recovery_delay': '200ms',
                'recovery_delay_supported': ['200ms', '500ms'],
                'advanced_mode': True,
                'manager_priority': 32768,
                'fixed_backup': False,
                'fast_mrp': False,          # only on some models
                'info': 'ring port link error',
                'ring_state': 'closed',     # manager only
                'redundancy': True,         # manager only
                'ring_open_count': 0,
                'blocked_support': True,    # client field
            }

        Returns ``{'configured': False}`` when no MRP domain exists.
        """
        output = self.cli('show mrp')['show mrp']
        data = parse_dot_keys(output)

        if '(MRP not configured)' in output:
            return {'configured': False}

        result = {'configured': True}

        result['operation'] = data.get('Operation', 'disabled')
        result['mode'] = data.get('Mode (administrative setting)', '')
        result['mode_actual'] = data.get('Mode (real operating state)', '')
        result['port_primary'] = data.get('Port number, Primary', '')
        result['port_secondary'] = data.get('Port number, Secondary', '')
        result['port_primary_state'] = data.get('Port oper state, Primary', '')
        result['port_secondary_state'] = data.get('Port oper state, Secondary', '')
        result['domain_id'] = data.get('Domain ID', '')
        result['domain_name'] = data.get('Domain name', '')

        try:
            result['vlan'] = int(data.get('VLAN ID', '0'))
        except ValueError:
            result['vlan'] = 0

        result['recovery_delay'] = data.get('Recovery delay', '')
        supported = data.get('Recovery delay supported', '')
        result['recovery_delay_supported'] = [s.strip() for s in supported.split(',') if s.strip()]

        result['advanced_mode'] = data.get('Advanced mode (react on link change)', '').lower() == 'enabled'

        try:
            result['manager_priority'] = int(data.get('Manager priority', '32768'))
        except ValueError:
            result['manager_priority'] = 32768

        result['fixed_backup'] = data.get('Fixed backup port (manager only)', '').lower() == 'enabled'

        if 'FastMRP supported' in data:
            result['fast_mrp'] = data['FastMRP supported'].lower() == 'yes'

        # General operating states
        result['info'] = data.get('Configuration info', '')

        # Manager states
        result['ring_state'] = data.get('Ring state', '')
        result['redundancy'] = data.get('Redundancy exists', '').lower() == 'yes'
        try:
            result['ring_open_count'] = int(data.get('Ring open count', '0'))
        except ValueError:
            result['ring_open_count'] = 0

        # Client states
        result['blocked_support'] = data.get('Blocked support', '').lower() == 'enabled'

        return result

    def set_mrp(self, operation='enable', mode='client', port_primary=None,
                port_secondary=None, vlan=None, recovery_delay=None,
                advanced_mode=None):
        """Configure MRP ring on the default domain.

        Args:
            operation: 'enable' or 'disable'
            mode: 'manager' or 'client'
            port_primary: primary ring port (e.g. '1/3')
            port_secondary: secondary ring port (e.g. '1/4')
            vlan: VLAN ID for MRP domain (0-4042)
            recovery_delay: '200ms', '500ms', '30ms', or '10ms'
            advanced_mode: True/False — react on link change (faster failover)

        Creates the default domain if none exists.
        """
        if operation not in ('enable', 'disable'):
            raise ValueError(f"operation must be 'enable' or 'disable', got '{operation}'")
        if mode not in ('manager', 'client'):
            raise ValueError(f"mode must be 'manager' or 'client', got '{mode}'")

        self._config_mode()
        try:
            # Ensure default domain exists (harmless if already present)
            current = self.cli('show mrp')['show mrp']
            if '(MRP not configured)' in current:
                self.cli('mrp domain add default-domain')

            if operation == 'disable':
                self.cli('no mrp operation')
                self.cli('mrp domain modify operation disable')
            else:
                self.cli('mrp domain modify mode ' + mode)
                if port_primary:
                    self.cli(f'mrp domain modify port primary {port_primary}')
                if port_secondary:
                    self.cli(f'mrp domain modify port secondary {port_secondary}')
                if vlan is not None:
                    self.cli(f'mrp domain modify vlan {vlan}')
                if recovery_delay:
                    self.cli(f'mrp domain modify recovery-delay {recovery_delay}')
                if advanced_mode is not None:
                    val = 'enable' if advanced_mode else 'disable'
                    self.cli(f'mrp domain modify advanced-mode {val}')
                self.cli('mrp domain modify operation enable')
                self.cli('mrp operation')
        finally:
            self._exit_config_mode()

        return self.get_mrp()

    def delete_mrp(self):
        """Delete the MRP domain and disable MRP globally.

        Returns the post-deletion MRP state (should show configured=False).
        """
        self._config_mode()
        try:
            self.cli('no mrp operation')
            self.cli('mrp domain modify operation disable')
            self.cli('mrp domain delete')
        finally:
            self._exit_config_mode()

        return self.get_mrp()

    # SRM CLI mode values → API values
    _SRM_MODE_MAP = {
        'manager': 'manager',
        'redundant-manager': 'redundantManager',
        'redundantmanager': 'redundantManager',
        'single-manager': 'singleManager',
        'singlemanager': 'singleManager',
    }
    _SRM_MODE_REV = {
        'manager': 'manager',
        'redundantManager': 'redundant-manager',
        'singleManager': 'single-manager',
    }
    _SRM_REDUNDANCY_MAP = {
        'redguaranteed': True,
        'rednotguaranteed': False,
    }
    _SRM_CONFIG_INFO_MAP = {
        'noerror': 'no error',
        'ringportlinkerror': 'ring port link error',
        'multiplesrm': 'multiple SRM',
        'nopartnermanager': 'no partner manager',
        'concurrentvlan': 'concurrent VLAN',
        'concurrentport': 'concurrent port',
        'concurrentredundancy': 'concurrent redundancy',
        'trunkmember': 'trunk member',
        'sharedvlan': 'shared VLAN',
    }

    def get_mrp_sub_ring(self):
        """Return MRP sub-ring (SRM) configuration and operating state."""
        # Global scalars
        global_out = self.cli('show sub-ring global')['show sub-ring global']
        gdata = parse_dot_keys(global_out)
        enabled = gdata.get('Global admin state', 'disabled').lower() == 'enabled'
        try:
            max_instances = int(gdata.get('Max instances', '8'))
        except ValueError:
            max_instances = 8

        # Instance table
        ring_out = self.cli('show sub-ring ring')['show sub-ring ring']
        if 'No entry' in ring_out:
            return {'enabled': enabled, 'max_instances': max_instances, 'instances': []}

        # Extract ring IDs from the table — first number on data lines
        ring_ids = []
        for line in ring_out.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('Index') or stripped.startswith('--') or stripped.startswith('Active'):
                continue
            # Data line 1 starts with the index number
            parts = stripped.split()
            if parts and parts[0].isdigit():
                ring_ids.append(int(parts[0]))

        instances = []
        for rid in ring_ids:
            detail_out = self.cli(f'show sub-ring ring {rid}')[f'show sub-ring ring {rid}']
            d = parse_dot_keys(detail_out)

            # Mode mapping
            admin_raw = d.get('Administrative state', '').lower().replace(' ', '')
            mode = self._SRM_MODE_MAP.get(admin_raw, admin_raw)
            oper_raw = d.get('Operational state', '').lower().replace(' ', '')
            mode_actual = self._SRM_MODE_MAP.get(oper_raw, oper_raw)
            if oper_raw == 'disabled':
                mode_actual = 'disabled'

            # Domain ID: "255.255.255..." decimal dotted → "ff:ff:ff..." hex colon
            domain_raw = d.get('MRP domain id', '')
            if domain_raw:
                try:
                    domain_id = ':'.join(f'{int(b):02x}' for b in domain_raw.split('.'))
                except (ValueError, AttributeError):
                    domain_id = domain_raw
            else:
                domain_id = 'ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff'

            # Redundancy
            red_raw = d.get('Redundancy operational state', '').lower().replace(' ', '')
            redundancy = self._SRM_REDUNDANCY_MAP.get(red_raw, False)

            # Config info
            info_raw = d.get('Configuration operational state', '').lower().replace(' ', '')
            info = self._SRM_CONFIG_INFO_MAP.get(info_raw, d.get('Configuration operational state', ''))

            # Active field: "[ ]" = False, "[X]" = True
            active_raw = d.get('Active', '[ ]').strip()
            # active = active_raw == '[X]'  # not used in return — global 'enabled' covers it

            try:
                vlan = int(d.get('Vlan id', '0'))
            except ValueError:
                vlan = 0

            instances.append({
                'ring_id': rid,
                'mode': mode,
                'mode_actual': mode_actual,
                'vlan': vlan,
                'domain_id': domain_id,
                'partner_mac': d.get('Partner MAC', ''),
                'protocol': d.get('Protocol', ''),
                'name': d.get('Name', ''),
                'port': d.get('Port', ''),
                'port_state': d.get('Port operational state', ''),
                'ring_state': d.get('Sub-ring operational state', ''),
                'redundancy': redundancy,
                'info': info,
            })

        return {'enabled': enabled, 'max_instances': max_instances, 'instances': instances}

    def set_mrp_sub_ring(self, ring_id=None, enabled=None, mode='manager',
                         port=None, vlan=None, name=None):
        """Configure MRP sub-ring (SRM) via SSH.

        Global operation (ring_id=None):
            set_mrp_sub_ring(enabled=True)   — enable SRM globally
            set_mrp_sub_ring(enabled=False)  — disable SRM globally

        Instance operation (ring_id provided):
            Creates/modifies an SRM instance. Auto-enables global SRM.
        """
        if mode not in self._SRM_MODE_REV:
            raise ValueError(f"mode must be one of {list(self._SRM_MODE_REV)}, got '{mode}'")

        self._config_mode()
        try:
            # Global enable/disable
            if enabled is not None:
                if enabled:
                    self.cli('sub-ring operation')
                else:
                    self.cli('no sub-ring operation')

            if ring_id is not None:
                # Auto-enable global SRM
                if enabled is None:
                    self.cli('sub-ring operation')

                # Check if instance already exists
                instance_exists = False
                try:
                    check = self.cli(f'show sub-ring ring {ring_id}')[f'show sub-ring ring {ring_id}']
                    if 'No entry' not in check and 'Index' in check:
                        instance_exists = True
                except Exception:
                    pass

                mode_cli = self._SRM_MODE_REV.get(mode, mode)
                if instance_exists:
                    # Modify existing
                    cmd = f'sub-ring modify {ring_id}'
                    if mode:
                        cmd += f' mode {mode_cli}'
                    if vlan is not None:
                        cmd += f' vlan {vlan}'
                    if port:
                        cmd += f' port {port}'
                    if name:
                        cmd += f' name {name}'
                    self.cli(cmd)
                else:
                    # Create new
                    cmd = f'sub-ring add {ring_id}'
                    cmd += f' mode {mode_cli}'
                    if vlan is not None:
                        cmd += f' vlan {vlan}'
                    if port:
                        cmd += f' port {port}'
                    if name:
                        cmd += f' name {name}'
                    self.cli(cmd)

                # Enable the instance
                self.cli(f'sub-ring enable {ring_id}')
        finally:
            self._exit_config_mode()

        return self.get_mrp_sub_ring()

    def delete_mrp_sub_ring(self, ring_id=None):
        """Delete sub-ring instance or disable SRM globally."""
        self._config_mode()
        try:
            if ring_id is None:
                self.cli('no sub-ring operation')
            else:
                try:
                    self.cli(f'sub-ring disable {ring_id}')
                except Exception:
                    pass
                self.cli(f'sub-ring delete {ring_id}')
        finally:
            self._exit_config_mode()

        return self.get_mrp_sub_ring()

    def set_interface(self, interface, enabled=None, description=None):
        """Set interface admin state and/or description via SSH.

        Args:
            interface: port name (str) or list of port names
            enabled: True (admin up) or False (admin down), None to skip
            description: port description string, None to skip
        """
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        self._config_mode()
        try:
            for iface in interfaces:
                self._enter_interface(iface)
                if enabled is not None:
                    self.cli('no shutdown' if enabled else 'shutdown')
                if description is not None:
                    self.cli(f'name {description}' if description else 'no name')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def _send_confirm(self, cmd):
        """Send a command that requires Y/N confirmation, answer 'y'.

        Used by clear config / clear factory which prompt before executing.
        Returns the output after confirmation.
        """
        self.connection.write_channel(cmd + '\n')
        time.sleep(0.5)

        output = ""
        for _ in range(20):
            output += self.connection.read_channel()
            if '(Y/N)' in output or '(y/n)' in output:
                break
            time.sleep(0.5)

        self.connection.write_channel('y\n')
        time.sleep(0.5)

        # Read remaining output
        for _ in range(10):
            new_data = self.connection.read_channel()
            output += new_data
            if not new_data:
                break
            time.sleep(0.3)

        return output

    def clear_config(self, keep_ip=False):
        """Clear running config (back to default) via SSH.

        WARNING: Device warm-restarts. Connection will drop.

        Args:
            keep_ip: If True, preserve management IP address.
        """
        self._enable()
        cmd = 'clear config keep-ip' if keep_ip else 'clear config'
        try:
            self._send_confirm(cmd)
        except Exception:
            pass  # device warm-restarts, connection drops
        return {"restarting": True}

    def clear_factory(self, erase_all=False):
        """Factory reset via SSH. Device will reboot.

        Args:
            erase_all: If True, also regenerate factory.cfg from firmware.
                Use when factory defaults file may be corrupted.
        """
        self._enable()
        cmd = 'clear factory erase-all' if erase_all else 'clear factory'
        try:
            self._send_confirm(cmd)
        except Exception:
            pass  # device reboots, connection drops
        return {"rebooting": True}

    def is_factory_default(self):
        """Check if device is in factory-default password state.

        Detected during open() — if the SSH banner contained
        'Enter new password' instead of a CLI prompt, the factory
        gate is active.

        Returns: True if factory gate is active, False otherwise.
        """
        return self._factory_default

    def onboard(self, new_password):
        """Onboard a factory-fresh device by setting the initial password.

        Responds to the 'Enter new password' / 'Confirm new password'
        prompts shown on factory-default SSH login. After successful
        onboarding, the connection is ready for normal CLI use.

        Args:
            new_password: Password to set.

        Returns: True on success.
        Raises: ConnectionException if not factory-default.
        """
        if not self._factory_default:
            raise ConnectionException(
                "Device is already onboarded — onboard() must only be "
                "called on factory-fresh devices")
        # Send password to 'Enter new password:' prompt
        self.connection.write_channel(new_password + '\n')
        time.sleep(1)
        # Send password to 'Confirm new password:' prompt
        output = self.connection.read_channel()
        if 'Confirm' in output:
            self.connection.write_channel(new_password + '\n')
            time.sleep(2)
        # Read remaining output — should get normal CLI prompt
        output = self.connection.read_channel()
        self._factory_default = False
        # Now set up pagination
        self.disable_pagination()
        return True

    def set_hidiscovery(self, status, blinking=None):
        """Set HiDiscovery operating mode.

        Args:
            status: 'on', 'off', or 'ro' (read-only)
            blinking: True to enable, False to disable, 'toggle' to flip,
                      or None to leave unchanged

        'on' enables HiDiscovery in read-write mode.
        'off' disables HiDiscovery entirely.
        'ro' enables HiDiscovery in read-only mode (recommended for production).

        Enters enable mode to execute config commands, then exits.
        """
        status = status.lower().strip()
        if status not in ('on', 'off', 'ro'):
            raise ValueError(f"Invalid status '{status}': use 'on', 'off', or 'ro'")

        if blinking == 'toggle':
            current = self.get_hidiscovery()
            blinking = not current.get('blinking', False)

        self._enable()
        try:
            if status == 'off':
                self.cli('no network hidiscovery operation')
            elif status == 'on':
                self.cli('network hidiscovery operation')
                self.cli('network hidiscovery mode read-write')
            elif status == 'ro':
                self.cli('network hidiscovery operation')
                self.cli('network hidiscovery mode read-only')
            if blinking is not None:
                if blinking:
                    self.cli('network hidiscovery blinking')
                else:
                    self.cli('no network hidiscovery blinking')
        finally:
            self._disable()

        return self.get_hidiscovery()

    def get_profiles(self, storage='nvm'):
        """List config profiles from 'show config profiles {nvm|envm}'.

        Output format (3 lines per profile):
            Index   Name           Date & Time (UTC)    SW-Rel.
            Active  Fingerprint    FP verified
                    Encrypted      Key verified
            ------  ...
              1     config         2026-02-13 13:25:16  09.4.4
             [x]    9244C58F...    yes
                    no             no
        """
        if storage not in ('nvm', 'envm'):
            raise ValueError(f"Invalid storage type '{storage}'. Use 'nvm' or 'envm'.")

        cmd = f'show config profiles {storage}'
        output = self.cli(cmd)[cmd]
        profiles = []

        # Find the separator line, then parse 3-line groups after it
        lines = output.strip().splitlines()
        sep_idx = None
        for i, line in enumerate(lines):
            if line.startswith('------'):
                sep_idx = i
                break

        if sep_idx is None:
            return profiles

        data_lines = lines[sep_idx + 1:]
        i = 0
        while i + 2 < len(data_lines):
            line1 = data_lines[i]      # Index, Name, DateTime, SW-Rel
            line2 = data_lines[i + 1]  # Active, Fingerprint, FP verified
            line3 = data_lines[i + 2]  # Encrypted, Key verified
            i += 3

            # Skip blank lines
            if not line1.strip():
                i -= 2
                continue

            # Line 1: parse index, name, datetime, firmware
            # Format: "  1     config                                    2026-02-13 13:25:16  09.4.4"
            m1 = re.match(r'\s*(\d+)\s+(\S+)\s+([\d-]+\s+[\d:]+)\s+(\S+)', line1)
            if not m1:
                continue

            index = int(m1.group(1))
            name = m1.group(2)
            datetime_str = m1.group(3)
            firmware = m1.group(4)

            # Line 2: parse active marker, fingerprint, fp verified
            # Format: " [x]    9244C58F...  yes" or " [ ]    ABCDEF...  no"
            active = '[x]' in line2
            m2 = re.match(r'\s*\[.\]\s+([A-F0-9]+)\s+(\S+)', line2)
            fingerprint = m2.group(1) if m2 else ''
            fp_verified = (m2.group(2).lower() == 'yes') if m2 else False

            # Line 3: parse encrypted, key verified
            # Format: "        no           no"
            parts3 = line3.split()
            encrypted = (parts3[0].lower() == 'yes') if len(parts3) >= 1 else False
            key_verified = (parts3[1].lower() == 'yes') if len(parts3) >= 2 else False

            profiles.append({
                'index': index,
                'name': name,
                'active': active,
                'datetime': datetime_str,
                'firmware': firmware,
                'fingerprint': fingerprint,
                'fingerprint_verified': fp_verified,
                'encrypted': encrypted,
                'encryption_verified': key_verified,
            })

        return profiles

    def get_config_fingerprint(self):
        """Return SHA1 fingerprint of the active NVM profile."""
        profiles = self.get_profiles('nvm')
        for p in profiles:
            if p['active']:
                return {'fingerprint': p['fingerprint'], 'verified': p['fingerprint_verified']}
        return {'fingerprint': '', 'verified': False}

    def activate_profile(self, storage='nvm', index=1):
        """Activate a config profile (causes warm restart).

        CLI: ``config profile select nvm <index>`` in configure mode.
        Only NVM storage is supported by HiOS for profile selection.

        Warning: this triggers a warm restart — the SSH connection will drop.
        """
        if storage != 'nvm':
            raise ValueError("HiOS only supports 'config profile select nvm'. "
                             "Cannot select from envm.")

        # Verify profile exists and is not already active
        profiles = self.get_profiles(storage)
        target = None
        for p in profiles:
            if p['index'] == index:
                target = p
                break
        if target is None:
            raise ValueError(f"Profile index {index} not found in {storage}.")
        if target['active']:
            raise ValueError(f"Profile {index} ('{target['name']}') is already active.")

        self._config_mode()
        try:
            result = self.cli(f'config profile select nvm {index}')
            output = list(result.values())[0]
            if output.startswith('Error:'):
                raise RuntimeError(f"Failed to activate profile: {output}")
        finally:
            try:
                self._exit_config_mode()
            except Exception:
                pass  # Connection may drop due to warm restart

    def delete_profile(self, storage='nvm', index=1):
        """Delete an inactive config profile.

        CLI: ``config profile delete {nvm|envm} num <index>`` in configure mode.
        Refuses to delete the active profile.
        """
        if storage not in ('nvm', 'envm'):
            raise ValueError(f"Invalid storage type '{storage}'. Use 'nvm' or 'envm'.")

        # Verify profile exists and is not active
        profiles = self.get_profiles(storage)
        target = None
        for p in profiles:
            if p['index'] == index:
                target = p
                break
        if target is None:
            raise ValueError(f"Profile index {index} not found in {storage}.")
        if target['active']:
            raise ValueError(f"Cannot delete active profile {index} ('{target['name']}').")

        self._config_mode()
        try:
            result = self.cli(f'config profile delete {storage} num {index}')
            output = list(result.values())[0]
            if output.startswith('Error:'):
                raise RuntimeError(f"Failed to delete profile: {output}")
        finally:
            self._exit_config_mode()

    # ── Auto-Disable ─────────────────────────────────────────────

    def get_auto_disable(self):
        output_brief = self.cli('show auto-disable brief')['show auto-disable brief']
        output_reasons = self.cli('show auto-disable reasons')['show auto-disable reasons']

        # Parse per-interface table (2 lines per record)
        # Line 1: Intf  Reason  Remaining_time  Error_time  State
        # Line 2:       Component  Reset_timer
        interfaces = {}
        rows = parse_table(output_brief, min_fields=1)
        current_intf = None
        for fields in rows:
            if '/' in fields[0]:
                # First line of record
                current_intf = fields[0]
                reason = fields[1] if len(fields) > 1 else 'none'
                remaining = int(fields[2]) if len(fields) > 2 else 0
                error_time = fields[3] if len(fields) > 3 else '-'
                # State may be split if error_time contains spaces, but from live
                # output error_time is either '-' or a date string — state is last field
                state = fields[-1] if len(fields) >= 5 else 'inactive'
                interfaces[current_intf] = {
                    'timer': 0,
                    'reason': reason,
                    'active': state == 'active',
                    'component': '',
                    'remaining_time': remaining,
                    'error_time': '' if error_time == '-' else error_time,
                }
            elif current_intf and '/' not in fields[0]:
                # Second line of record: component and timer
                component = fields[0] if fields[0] != '-' else ''
                timer = int(fields[1]) if len(fields) > 1 else 0
                interfaces[current_intf]['component'] = component
                interfaces[current_intf]['timer'] = timer

        # Parse reasons table
        reasons = {}
        reason_rows = parse_table(output_reasons, min_fields=2)
        for fields in reason_rows:
            name = fields[0]
            state = fields[1] if len(fields) > 1 else 'disabled'
            reasons[name] = {
                'enabled': state == 'enabled',
                'category': _AD_REASON_CATEGORY.get(name, 'other'),
            }

        return {'interfaces': interfaces, 'reasons': reasons}

    def set_auto_disable(self, interface, timer=0):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        timer = int(timer)
        self._config_mode()
        try:
            for iface in interfaces:
                self._enter_interface(iface)
                self.cli(f'auto-disable timer {timer}')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def reset_auto_disable(self, interface):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        self._config_mode()
        try:
            for iface in interfaces:
                self._enter_interface(iface)
                self.cli('auto-disable reset')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def set_auto_disable_reason(self, reason, enabled=True):
        valid = ('link-flap', 'crc-error', 'duplex-mismatch', 'dhcp-snooping',
                 'arp-rate', 'bpdu-rate', 'port-security', 'overload-detection',
                 'speed-duplex', 'loop-protection')
        if reason not in valid:
            raise ValueError(f"Unknown reason '{reason}'. Valid: {valid}")
        self._config_mode()
        try:
            if enabled:
                self.cli(f'auto-disable reason {reason}')
            else:
                self.cli(f'no auto-disable reason {reason}')
        finally:
            self._exit_config_mode()

    # ── Loop Protection ──────────────────────────────────────────

    def get_loop_protection(self):
        output_global = self.cli('show loop-protection global')['show loop-protection global']

        # Check for L2S "Invalid command" error
        if 'Invalid command' in output_global or 'Error' in output_global:
            return {
                'enabled': False,
                'transmit_interval': 0,
                'receive_threshold': 0,
                'interfaces': {},
            }

        # Parse global settings (dot-key format)
        gdata = parse_dot_keys(output_global)
        enabled = gdata.get('Operational State', 'disabled') != 'disabled'
        tx_interval = int(gdata.get('Transmit Timeout (sec)', '5'))
        rx_threshold = int(gdata.get('Receive PDU threshold', '1'))

        # Parse per-interface table
        output_intf = self.cli('show loop-protection interface')['show loop-protection interface']
        interfaces = {}
        rows = parse_table(output_intf, min_fields=7)
        for fields in rows:
            if '/' not in fields[0]:
                continue
            intf = fields[0]
            # Intf  Admin  Mode  Action  VLAN  Loop  Last-Timestamp
            # Last-Timestamp is "1970-01-01 00:00:00.0" (3 tokens when split)
            admin = fields[1]
            mode = fields[2]
            action = fields[3]
            vlan = int(fields[4])
            loop = fields[5] == 'yes'
            # Timestamp: reassemble remaining fields
            ts_parts = fields[6:]
            timestamp = ' '.join(ts_parts) if ts_parts else ''
            # Treat 1970 epoch as empty (same as MOPS/SNMP)
            if timestamp.startswith('1970'):
                timestamp = ''
            # Strip trailing .0 deciseconds
            if timestamp.endswith('.0'):
                timestamp = timestamp[:-2]
            interfaces[intf] = {
                'enabled': admin != 'disabled',
                'mode': mode,
                'action': action,
                'vlan_id': vlan,
                'loop_detected': loop,
                'last_loop_time': timestamp,
                'tpid_type': 'none',  # not shown in CLI output
            }

        return {
            'enabled': enabled,
            'transmit_interval': tx_interval,
            'receive_threshold': rx_threshold,
            'interfaces': interfaces,
        }

    def set_loop_protection(self, interface=None, enabled=None, mode=None,
                            action=None, vlan_id=None,
                            transmit_interval=None, receive_threshold=None):
        self._config_mode()
        try:
            if interface is None:
                # Global settings
                if enabled is not None:
                    if enabled:
                        self.cli('loop-protection operation')
                    else:
                        self.cli('no loop-protection operation')
                if transmit_interval is not None:
                    self.cli(f'loop-protection tx-interval {int(transmit_interval)}')
                if receive_threshold is not None:
                    self.cli(f'loop-protection rx-threshold {int(receive_threshold)}')
            else:
                # Per-interface settings — accept single string or list
                interfaces = ([interface] if isinstance(interface, str)
                              else list(interface))
                if mode is not None and mode not in ('active', 'passive'):
                    raise ValueError(f"mode must be 'active' or 'passive', got '{mode}'")
                if action is not None and action not in ('trap', 'auto-disable', 'all'):
                    raise ValueError(f"action must be 'trap', 'auto-disable', or 'all', got '{action}'")
                for iface in interfaces:
                    self._enter_interface(iface)
                    if enabled is not None:
                        if enabled:
                            self.cli('loop-protection operation')
                        else:
                            self.cli('no loop-protection operation')
                    if mode is not None:
                        self.cli(f'loop-protection mode {mode}')
                    if action is not None:
                        self.cli(f'loop-protection action {action}')
                    if vlan_id is not None:
                        self.cli(f'loop-protection vlan {int(vlan_id)}')
                    self.cli('exit')
        finally:
            self._exit_config_mode()

    # ── Storm Control ────────────────────────────────────────────

    def get_storm_control(self):
        """Return per-port storm control configuration.

        Parses 'show storm-control ingress' output:
            Intf  Mode  Level  Mode  Level  Mode  Level
            1/1   disabled  0%  disabled  0%  disabled  0%
            1/11  enabled  100 pps  disabled  0 pps  disabled  0 pps
        Level is "N%" (one token) or "N pps" (two tokens).
        """
        output = self.cli('show storm-control ingress')[
            'show storm-control ingress']

        interfaces = {}
        rows = parse_table(output, min_fields=5)
        for fields in rows:
            if '/' not in fields[0]:
                continue
            intf = fields[0]
            # Parse 3 groups of (mode, level) from remaining tokens.
            # Level: "0%" = one token (percent), "100 pps" = two tokens.
            tokens = fields[1:]
            groups = []
            i = 0
            while i < len(tokens) and len(groups) < 3:
                mode = tokens[i].lower()
                i += 1
                if i >= len(tokens):
                    groups.append((mode, 0, 'percent'))
                    break
                level_str = tokens[i]
                i += 1
                if level_str.endswith('%'):
                    threshold = int(level_str[:-1])
                    unit = 'percent'
                else:
                    threshold = int(level_str)
                    unit = 'pps'
                    if i < len(tokens) and tokens[i] == 'pps':
                        i += 1
                groups.append((mode, threshold, unit))

            # All 3 groups share the same unit per port
            port_unit = groups[0][2] if groups else 'percent'
            bc = groups[0] if len(groups) > 0 else ('disabled', 0, 'percent')
            mc = groups[1] if len(groups) > 1 else ('disabled', 0, 'percent')
            uc = groups[2] if len(groups) > 2 else ('disabled', 0, 'percent')

            interfaces[intf] = {
                'unit': port_unit,
                'broadcast': {
                    'enabled': bc[0] in ('enabled', 'enable', 'active'),
                    'threshold': bc[1],
                },
                'multicast': {
                    'enabled': mc[0] in ('enabled', 'enable', 'active'),
                    'threshold': mc[1],
                },
                'unicast': {
                    'enabled': uc[0] in ('enabled', 'enable', 'active'),
                    'threshold': uc[1],
                },
            }

        return {
            'bucket_type': '',  # not available via CLI
            'interfaces': interfaces,
        }

    def set_storm_control(self, interface, unit=None,
                          broadcast_enabled=None, broadcast_threshold=None,
                          multicast_enabled=None, multicast_threshold=None,
                          unicast_enabled=None, unicast_threshold=None):
        """Set per-port storm control configuration."""
        if unit is not None and unit not in ('percent', 'pps'):
            raise ValueError(
                f"Invalid unit '{unit}': use 'percent' or 'pps'")
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        self._config_mode()
        try:
            for iface in interfaces:
                self._enter_interface(iface)
                if unit is not None:
                    self.cli(f'storm-control ingress unit {unit}')
                if broadcast_enabled is not None:
                    if broadcast_enabled:
                        self.cli('storm-control ingress broadcast operation')
                    else:
                        self.cli(
                            'no storm-control ingress broadcast operation')
                if broadcast_threshold is not None:
                    self.cli('storm-control ingress broadcast threshold '
                             f'{int(broadcast_threshold)}')
                if multicast_enabled is not None:
                    if multicast_enabled:
                        self.cli('storm-control ingress multicast operation')
                    else:
                        self.cli(
                            'no storm-control ingress multicast operation')
                if multicast_threshold is not None:
                    self.cli('storm-control ingress multicast threshold '
                             f'{int(multicast_threshold)}')
                if unicast_enabled is not None:
                    if unicast_enabled:
                        self.cli('storm-control ingress unicast operation')
                    else:
                        self.cli(
                            'no storm-control ingress unicast operation')
                if unicast_threshold is not None:
                    self.cli('storm-control ingress unicast threshold '
                             f'{int(unicast_threshold)}')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    # ── sFlow ─────────────────────────────────────────────────────

    def get_sflow(self):
        """Return sFlow agent info and receiver table."""
        # Agent info — dot-key format
        agent_out = self.cli('show sflow agent')['show sflow agent']
        agent = parse_dot_keys(agent_out)
        version = agent.get('sFlow version', '').strip()
        address = agent.get('IP address', '').strip()

        # Receivers — table format with wide variable-width owner column.
        # Parse from the right: ip, port, max_dgram, timeout are fixed,
        # owner is everything between index and timeout (may be empty).
        rcvr_out = self.cli('show sflow receivers')['show sflow receivers']
        receivers = {}
        rows = parse_table(rcvr_out, min_fields=4)
        for fields in rows:
            try:
                idx = int(fields[0])
            except (ValueError, IndexError):
                continue
            if idx < 1:
                continue
            # Last 4 fields are always: timeout, max_dgram, port, ip
            # Timeout: '-' means permanent (-1)
            addr = fields[-1]
            port = int(fields[-2])
            max_dg = int(fields[-3])
            tout_raw = fields[-4]
            tout = -1 if tout_raw == '-' else int(tout_raw)
            # Owner is everything between index and the 4 right fields
            owner_parts = fields[1:-4]
            owner = ' '.join(owner_parts)
            receivers[idx] = {
                'owner': owner,
                'timeout': tout,
                'max_datagram_size': max_dg,
                'address_type': 1,
                'address': addr,
                'port': port,
                'datagram_version': 5,  # not shown in CLI table
            }

        return {
            'agent_version': version,
            'agent_address': address,
            'receivers': receivers,
        }

    def set_sflow(self, receiver, address=None, port=None, owner=None,
                  timeout=None, max_datagram_size=None):
        """Configure an sFlow receiver."""
        if not 1 <= receiver <= 8:
            raise ValueError(f"receiver must be 1-8, got {receiver}")
        self._config_mode()
        try:
            # Owner+timeout can be combined; other params need separate cmds
            if owner is not None:
                cmd = f'sflow receiver {receiver} owner {owner}'
                if timeout is not None:
                    cmd += f' timeout {int(timeout)}'
                    timeout = None  # already sent
                self.cli(cmd)
            if timeout is not None:
                self.cli(f'sflow receiver {receiver} timeout {int(timeout)}')
            if address is not None:
                self.cli(f'sflow receiver {receiver} ip {address}')
            if port is not None:
                self.cli(f'sflow receiver {receiver} port {int(port)}')
            if max_datagram_size is not None:
                self.cli(f'sflow receiver {receiver} maxdatagram '
                         f'{int(max_datagram_size)}')
        finally:
            self._exit_config_mode()

    def get_sflow_port(self, interfaces=None, type=None):
        """Return sFlow sampler and poller config per port."""
        iface_set = set(interfaces) if interfaces else None
        result = {}

        if type is None or type == 'sampler':
            out = self.cli('show sflow samplers')['show sflow samplers']
            rows = parse_table(out, min_fields=4)
            for fields in rows:
                if '/' not in fields[0]:
                    continue
                name = fields[0]
                if iface_set and name not in iface_set:
                    continue
                if name not in result:
                    result[name] = {}
                result[name]['sampler'] = {
                    'receiver': int(fields[1]) if len(fields) > 1 else 0,
                    'sample_rate': int(fields[2]) if len(fields) > 2 else 0,
                    'max_header_size': int(fields[3]) if len(fields) > 3 else 128,
                }

        if type is None or type == 'poller':
            out = self.cli('show sflow pollers')['show sflow pollers']
            rows = parse_table(out, min_fields=3)
            for fields in rows:
                if '/' not in fields[0]:
                    continue
                name = fields[0]
                if iface_set and name not in iface_set:
                    continue
                if name not in result:
                    result[name] = {}
                result[name]['poller'] = {
                    'receiver': int(fields[1]) if len(fields) > 1 else 0,
                    'interval': int(fields[2]) if len(fields) > 2 else 0,
                }

        return result

    def set_sflow_port(self, interfaces, receiver, sample_rate=None,
                       interval=None, max_header_size=None):
        """Configure sFlow sampling/polling on ports."""
        if sample_rate is None and interval is None:
            raise ValueError(
                "At least one of sample_rate or interval must be provided")
        interfaces = ([interfaces] if isinstance(interfaces, str)
                      else list(interfaces))
        self._config_mode()
        try:
            for iface in interfaces:
                self._enter_interface(iface)
                if sample_rate is not None:
                    if receiver == 0:
                        self.cli('sflow sampler receiver 0')
                    else:
                        cmd = (f'sflow sampler receiver {int(receiver)}'
                               f' rate {int(sample_rate)}')
                        self.cli(cmd)
                    if max_header_size is not None and receiver != 0:
                        self.cli(
                            f'sflow sampler maxheadersize '
                            f'{int(max_header_size)}')
                if interval is not None:
                    if receiver == 0:
                        self.cli('sflow poller receiver 0')
                    else:
                        self.cli(
                            f'sflow poller receiver {int(receiver)}'
                            f' interval {int(interval)}')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    # ── QoS ───────────────────────────────────────────────────────

    _QOS_TRUST_CLI = {
        'untrusted': 'untrusted', 'dot1p': 'dot1p',
        'ip-dscp': 'ip-dscp', 'ip-precedence': 'ip-precedence',
    }

    def get_qos(self):
        """Return per-port QoS trust mode and queue scheduling.

        Parses 'show classofservice trust' and 'show cos-queue'.
        """
        # Trust mode per port
        trust_out = self.cli('show classofservice trust')[
            'show classofservice trust']
        trust_rows = parse_table(trust_out, min_fields=2)

        trust_by_port = {}
        for fields in trust_rows:
            if '/' not in fields[0]:
                continue
            port = fields[0]
            mode = fields[1].lower().strip()
            # Normalise: "trustdot1p" → "dot1p", "trustipdscp" → "ip-dscp"
            if mode == 'trustdot1p':
                mode = 'dot1p'
            elif mode == 'trustipdscp':
                mode = 'ip-dscp'
            elif mode == 'trustipprecedence':
                mode = 'ip-precedence'
            trust_by_port[port] = mode

        # Queue scheduling (global — applies to all ports)
        queue_out = self.cli('show cos-queue')['show cos-queue']
        queue_rows = parse_table(queue_out, min_fields=2)

        queues = {}
        for fields in queue_rows:
            try:
                qidx = int(fields[0])
            except (ValueError, IndexError):
                continue
            # Fields vary: queue_id, min_bw, max_bw, scheduler_type
            scheduler = 'strict'
            min_bw = 0
            max_bw = 0
            for f in fields[1:]:
                fl = f.lower()
                if fl in ('strict', 'weighted'):
                    scheduler = fl
                elif '%' not in fl:
                    try:
                        val = int(fl)
                        if min_bw == 0 and max_bw == 0:
                            min_bw = val
                        else:
                            max_bw = val
                    except ValueError:
                        pass
            queues[qidx] = {
                'scheduler': scheduler,
                'min_bw': min_bw,
                'max_bw': max_bw,
            }

        # Default priority per port from 'show vlan port' Priority column
        priority_by_port = {}
        vlan_port_out = self.cli('show vlan port')['show vlan port']
        for fields in parse_table(vlan_port_out, min_fields=5):
            if '/' not in fields[0]:
                continue
            try:
                priority_by_port[fields[0]] = int(fields[-1])
            except (ValueError, IndexError):
                pass

        # Build interfaces dict
        interfaces = {}
        for port, mode in trust_by_port.items():
            interfaces[port] = {
                'trust_mode': mode,
                'default_priority': priority_by_port.get(port, 0),
                'shaping_rate': 0,  # not available via CLI
                'queues': dict(queues),  # same for all ports in CLI
            }

        return {
            'num_queues': len(queues) if queues else 8,
            'interfaces': interfaces,
        }

    def set_qos(self, interface, trust_mode=None, shaping_rate=None,
                queue=None, scheduler=None, min_bw=None, max_bw=None,
                default_priority=None):
        """Set per-port QoS trust mode or queue scheduling."""
        if trust_mode is not None and trust_mode not in self._QOS_TRUST_CLI:
            raise ValueError(
                f"Invalid trust_mode '{trust_mode}': use "
                "'untrusted', 'dot1p', 'ip-precedence', 'ip-dscp'")
        if scheduler is not None and scheduler not in ('strict', 'weighted'):
            raise ValueError(
                f"Invalid scheduler '{scheduler}': "
                "use 'strict' or 'weighted'")
        queue_needed = (scheduler is not None or min_bw is not None
                        or max_bw is not None)
        if queue_needed and queue is None:
            raise ValueError(
                "queue index (0-7) required when setting "
                "scheduler, min_bw, or max_bw")

        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))

        self._config_mode()
        try:
            # Trust mode is per-interface
            if trust_mode is not None:
                for iface in interfaces:
                    self._enter_interface(iface)
                    self.cli(f'classofservice trust {trust_mode}')
                    self.cli('exit')

            # Default priority is per-interface
            if default_priority is not None:
                for iface in interfaces:
                    self._enter_interface(iface)
                    self.cli(f'vlan priority {int(default_priority)}')
                    self.cli('exit')

            # Queue scheduling is global
            if scheduler is not None:
                self.cli(f'cos-queue {scheduler} {int(queue)}')
            if min_bw is not None:
                self.cli(
                    f'cos-queue min-bandwidth {int(queue)} {int(min_bw)}')
            if max_bw is not None:
                self.cli(
                    f'cos-queue max-bandwidth {int(queue)} {int(max_bw)}')
        finally:
            self._exit_config_mode()

    def get_qos_mapping(self):
        """Return global dot1p and DSCP to traffic class mapping tables."""
        # dot1p mapping
        dot1p_out = self.cli('show classofservice dot1p-mapping')[
            'show classofservice dot1p-mapping']
        dot1p_rows = parse_table(dot1p_out, min_fields=2)

        dot1p = {}
        for fields in dot1p_rows:
            try:
                prio = int(fields[0])
                tc = int(fields[1])
                dot1p[prio] = tc
            except (ValueError, IndexError):
                continue

        # DSCP mapping
        dscp_out = self.cli('show classofservice ip-dscp-mapping')[
            'show classofservice ip-dscp-mapping']
        dscp_rows = parse_table(dscp_out, min_fields=2)

        dscp = {}
        for fields in dscp_rows:
            try:
                dval = int(fields[0])
                tc = int(fields[1])
                dscp[dval] = tc
            except (ValueError, IndexError):
                continue

        return {'dot1p': dot1p, 'dscp': dscp}

    def set_qos_mapping(self, dot1p=None, dscp=None):
        """Set global dot1p and/or DSCP to traffic class mappings."""
        self._config_mode()
        try:
            if dot1p is not None:
                for prio, tc in dot1p.items():
                    self.cli(f'classofservice dot1p-mapping '
                             f'{int(prio)} {int(tc)}')
            if dscp is not None:
                for dval, tc in dscp.items():
                    self.cli(f'classofservice ip-dscp-mapping '
                             f'{int(dval)} {int(tc)}')
        finally:
            self._exit_config_mode()

    def get_management_priority(self):
        """Return management frame priority settings."""
        output = self.cli('show network parms')['show network parms']
        d = parse_dot_keys(output)

        dot1p = 0
        ip_dscp = 0
        for key, val in d.items():
            kl = key.lower()
            if 'vlan' in kl and 'prio' in kl:
                try:
                    dot1p = int(val.strip())
                except ValueError:
                    pass
            elif 'dscp' in kl and 'prio' in kl:
                try:
                    ip_dscp = int(val.strip())
                except ValueError:
                    pass

        return {'dot1p': dot1p, 'ip_dscp': ip_dscp}

    def set_management_priority(self, dot1p=None, ip_dscp=None):
        """Set management frame priority."""
        self._enable()
        try:
            if dot1p is not None:
                self.cli(f'network management priority dot1p {int(dot1p)}')
            if ip_dscp is not None:
                self.cli(
                    f'network management priority ip-dscp {int(ip_dscp)}')
        finally:
            self._disable()

    def get_management(self):
        """Return management network configuration from CLI.

        Parses ``show network parms`` output.
        """
        output = self.cli('show network parms')['show network parms']
        d = parse_dot_keys(output)

        # Protocol: "none" / "bootp" / "dhcp"
        proto_raw = d.get('Protocol', 'none').strip().lower()
        if proto_raw in ('none', 'local'):
            proto_raw = 'local'

        # DHCP config load: "enabled(options 4, 42, 66, 67)" or "disabled"
        dhcp_load_raw = d.get('DHCP/BOOTP client config load',
                             d.get('DHCP client config load', '')).strip()
        dhcp_option = dhcp_load_raw.lower().startswith('enabled')

        # DHCP client ID
        dhcp_client_id = d.get('DHCP/BOOTP client ID',
                              d.get('DHCP client ID', '')).strip()

        # DHCP lease time — may not be present
        lease_raw = d.get('DHCP/BOOTP lease time',
                         d.get('DHCP lease time', '0')).strip()
        try:
            dhcp_lease = int(lease_raw)
        except ValueError:
            dhcp_lease = 0

        # IPv6 — separate CLI command
        ipv6_enabled = False
        ipv6_proto = 'none'
        try:
            ipv6_output = self.cli(
                'show network ipv6 global')['show network ipv6 global']
            ipv6_d = parse_dot_keys(ipv6_output)
            ipv6_status = ipv6_d.get('IPv6 status', '').strip().lower()
            ipv6_enabled = ipv6_status in ('enable', 'enabled')
            ipv6_proto_raw = ipv6_d.get(
                'Type of protocol', '').strip().lower()
            if ipv6_proto_raw == 'autoconf':
                ipv6_proto = 'auto'
            elif ipv6_proto_raw:
                ipv6_proto = ipv6_proto_raw
        except Exception:
            pass

        return {
            'protocol': proto_raw,
            'vlan_id': int(d.get('Management VLAN ID', '1').strip()),
            'ip_address': d.get('Local IP address', '0.0.0.0').strip(),
            'netmask': d.get('Subnetmask', '0.0.0.0').strip(),
            'gateway': d.get('Gateway address', '0.0.0.0').strip(),
            'mgmt_port': 0,  # not in show output, always 0 on BRS50
            'dhcp_client_id': dhcp_client_id,
            'dhcp_lease_time': dhcp_lease,
            'dhcp_option_66_67': dhcp_option,
            'dot1p': int(d.get('Management VLAN priority', '0').strip()),
            'ip_dscp': int(d.get('Management IP-DSCP value', '0').strip()),
            'ipv6_enabled': ipv6_enabled,
            'ipv6_protocol': ipv6_proto,
        }

    def set_management(self, protocol=None, vlan_id=None, ip_address=None,
                       netmask=None, gateway=None, mgmt_port=None,
                       dhcp_option_66_67=None, ipv6_enabled=None):
        """Set management network configuration via CLI.

        Args:
            protocol: 'local', 'bootp', or 'dhcp'
            vlan_id: int 1-4042 (validated against VLAN table)
            ip_address: str dotted quad
            netmask: str dotted quad (required with ip_address)
            gateway: str dotted quad
            mgmt_port: int (0 = all, or slot/port number)
            dhcp_option_66_67: bool
            ipv6_enabled: bool
        """
        if vlan_id is not None:
            vlan_id = int(vlan_id)
            if vlan_id < 1 or vlan_id > 4042:
                raise ValueError(f"vlan_id must be 1-4042, got {vlan_id}")
            vlans = self.get_vlans()
            if vlan_id not in vlans:
                raise ValueError(
                    f"VLAN {vlan_id} does not exist on device — "
                    f"create it first to avoid management lockout")

        self._enable()
        try:
            if protocol is not None:
                proto = protocol.lower().strip()
                if proto == 'local':
                    proto = 'none'
                if proto not in ('none', 'bootp', 'dhcp'):
                    raise ValueError(
                        f"protocol must be 'local', 'bootp', or 'dhcp', "
                        f"got '{protocol}'")
                self.cli(f'network protocol {proto}')

            if ip_address is not None:
                mask = netmask or '255.255.255.0'
                if gateway:
                    self.cli(f'network parms {ip_address} {mask} {gateway}')
                else:
                    self.cli(f'network parms {ip_address} {mask}')
            elif gateway is not None:
                # Gateway-only change — need current IP/mask
                current = self.get_management()
                self.cli(
                    f'network parms {current["ip_address"]} '
                    f'{current["netmask"]} {gateway}')

            if vlan_id is not None:
                self.cli(f'network management vlan {vlan_id}')

            if mgmt_port is not None:
                port_val = 'all' if int(mgmt_port) == 0 else str(mgmt_port)
                self.cli(f'network management port {port_val}')

            if dhcp_option_66_67 is not None:
                val = 'enable' if dhcp_option_66_67 else 'disable'
                self.cli(f'network dhcp config-load {val}')

            if ipv6_enabled is not None:
                if ipv6_enabled:
                    self.cli('network ipv6 operation')
                else:
                    self.cli('no network ipv6 operation')
        finally:
            self._disable()

    # ── Config Watchdog ───────────────────────────────────────────

    def get_watchdog_status(self):
        """Read config watchdog state via CLI.

        Returns::

            {
                'enabled': True,
                'oper_status': 1,
                'interval': 60,
                'remaining': 45,
            }
        """
        output = self.cli('show config watchdog')['show config watchdog']
        d = parse_dot_keys(output)
        admin_raw = d.get('Admin State', '').strip().lower()
        oper_raw = d.get('Operating State', '').strip().lower()
        try:
            interval = int(d.get('Timeout Interval (seconds)', '0').strip())
        except ValueError:
            interval = 0
        try:
            remaining = int(
                d.get('Current Timer Value (seconds)', '0').strip())
        except ValueError:
            remaining = 0
        oper_map = {'disabled': 2, 'enabled': 1, 'active': 1}
        return {
            'enabled': admin_raw in ('enable', 'enabled', 'active'),
            'oper_status': oper_map.get(oper_raw, 2),
            'interval': interval,
            'remaining': remaining,
        }

    def start_watchdog(self, seconds):
        """Start the config watchdog timer via CLI.

        Args:
            seconds: timer interval (30-600)
        """
        if not (30 <= seconds <= 600):
            raise ValueError(
                f"Watchdog interval must be 30-600, got {seconds}")
        self._config_mode()
        try:
            self.cli(f'config watchdog timeout {seconds}')
            self.cli('config watchdog admin-state')
        finally:
            self._exit_config_mode()

    def stop_watchdog(self):
        """Stop (disable) the config watchdog timer via CLI."""
        self._config_mode()
        try:
            self.cli('no config watchdog admin-state')
        finally:
            self._exit_config_mode()

    # ── RSTP ──────────────────────────────────────────────────────

    def get_rstp(self):
        output = self.cli('show spanning-tree global')['show spanning-tree global']
        d = parse_dot_keys(output)

        # Mode: "RSTP", "STP", "MSTP", "Disabled"
        mode_raw = d.get('Spanning Tree Mode', 'rstp').strip().lower()
        enabled = mode_raw != 'disabled'
        if not enabled:
            mode_raw = 'rstp'  # default underlying mode when disabled

        # Bridge/root IDs — already colon-separated hex from CLI
        bridge_id = d.get('Bridge identifier', '').lower()
        root_id = d.get('Root identifier', '').lower()

        # Root port identifier: "80:0C" → extract port number
        root_port_hex = d.get('Root port identifier', '00:00')
        try:
            parts = root_port_hex.split(':')
            root_port = ((int(parts[0], 16) << 8) | int(parts[1], 16)) & 0x0FFF
        except (ValueError, IndexError):
            root_port = 0

        # Time since topology change: "1 days 8 h 22 min 10 sec"
        time_str = d.get('Time since topology change', '0 sec')
        time_since = self._parse_stp_time(time_str)

        return {
            'enabled': enabled,
            'mode': mode_raw,
            'bridge_id': bridge_id,
            'priority': int(d.get('Bridge priority', 32768)),
            'hello_time': int(d.get('Bridge hello time', 2)),
            'max_age': int(d.get('Bridge max age', 20)),
            'forward_delay': int(d.get('Bridge forward delay', 15)),
            'hold_count': int(d.get('Bridge hold count', 10)),
            'max_hops': int(d.get('Bridge max hops', 0)),
            'root_id': root_id,
            'root_port': root_port,
            'root_path_cost': int(d.get('Root path cost', 0)),
            'topology_changes': int(d.get('Topology change count', 0)),
            'time_since_topology_change': time_since,
            'root_hello_time': int(d.get('Root hello time', 2)),
            'root_max_age': int(d.get('Root max age', 20)),
            'root_forward_delay': int(d.get('Root forward delay', 15)),
            'bpdu_guard': d.get('BPDU-Guard mode', 'disabled').lower() == 'enabled',
            'bpdu_filter': d.get('BPDU-Filter for edge ports', 'disabled').lower() == 'enabled',
        }

    def _parse_stp_time(self, time_str):
        """Parse '1 days 8 h 22 min 10 sec' → seconds."""
        total = 0
        for match in re.finditer(r'(\d+)\s*(days?|h|min|sec)', time_str):
            val = int(match.group(1))
            unit = match.group(2)
            if unit.startswith('day'):
                total += val * 86400
            elif unit == 'h':
                total += val * 3600
            elif unit == 'min':
                total += val * 60
            else:
                total += val
        return total

    def get_rstp_port(self, interface=None):
        # Get forwarding state from MST port table (one command for all ports)
        mst_output = self.cli('show spanning-tree mst port 0')['show spanning-tree mst port 0']
        fwd_states = {}
        for fields in parse_table(mst_output, min_fields=3):
            intf = fields[1]
            state = fields[2].lower() if len(fields) > 2 else 'disabled'
            fwd_states[intf] = state

        # Determine which ports to query
        if interface:
            port_list = [interface]
        else:
            port_list = list(fwd_states.keys())

        ports = {}
        for port in port_list:
            cmd = f'show spanning-tree port {port}'
            output = self.cli(cmd)[cmd]
            d = parse_dot_keys(output)
            if not d:
                continue

            ports[port] = {
                'enabled': d.get('Port mode', 'disabled').lower() == 'enabled',
                'state': fwd_states.get(port, 'disabled'),
                'edge_port': d.get('Edge Port', 'false').lower() == 'true',
                'edge_port_oper': d.get('Edge port status', 'disabled').lower() == 'enabled',
                'auto_edge': d.get('Auto edge', 'true').lower() == 'true',
                'point_to_point': d.get('Point to point MAC status', 'true').lower() == 'true',
                'path_cost': int(d.get('Port path cost', 0)),
                'priority': int(d.get('Port priority', 128)),
                'root_guard': d.get('Root guard', 'false').lower() == 'true',
                'loop_guard': d.get('Loop guard', 'false').lower() == 'true',
                'tcn_guard': d.get('TCN guard', 'false').lower() == 'true',
                'bpdu_guard': d.get('BPDU guard effect', 'disabled').lower() == 'enabled',
                'bpdu_filter': d.get('BPDU filter mode', 'disabled').lower() == 'enabled',
                'bpdu_flood': d.get('BPDU flood mode', 'disabled').lower() == 'enabled',
                'rstp_bpdu_rx': int(d.get('RSTP BPDUs received', 0)),
                'rstp_bpdu_tx': int(d.get('RSTP BPDUs transmitted', 0)),
                'stp_bpdu_rx': int(d.get('STP BPDUs received', 0)),
                'stp_bpdu_tx': int(d.get('STP BPDUs transmitted', 0)),
            }

        return ports

    def set_rstp(self, enabled=None, mode=None, priority=None,
                 hello_time=None, max_age=None, forward_delay=None,
                 hold_count=None, bpdu_guard=None, bpdu_filter=None):
        self._config_mode()
        try:
            if enabled is not None:
                if enabled:
                    self.cli('spanning-tree operation')
                else:
                    self.cli('no spanning-tree operation')
            if mode is not None:
                if mode not in ('stp', 'rstp', 'mstp'):
                    raise ValueError(f"mode must be 'stp', 'rstp', or 'mstp', got '{mode}'")
                self.cli(f'spanning-tree forceversion {mode}')
            if priority is not None:
                self.cli(f'spanning-tree mst priority 0 {int(priority)}')
            if hello_time is not None:
                self.cli(f'spanning-tree hello-time {int(hello_time)}')
            if max_age is not None:
                self.cli(f'spanning-tree max-age {int(max_age)}')
            if forward_delay is not None:
                self.cli(f'spanning-tree forward-time {int(forward_delay)}')
            if hold_count is not None:
                self.cli(f'spanning-tree hold-count {int(hold_count)}')
            if bpdu_guard is not None:
                if bpdu_guard:
                    self.cli('spanning-tree bpdu-guard')
                else:
                    self.cli('no spanning-tree bpdu-guard')
            if bpdu_filter is not None:
                if bpdu_filter:
                    self.cli('spanning-tree bpdu-filter')
                else:
                    self.cli('no spanning-tree bpdu-filter')
        finally:
            self._exit_config_mode()
        return self.get_rstp()

    def set_rstp_port(self, interface, enabled=None, edge_port=None,
                      auto_edge=None, path_cost=None, priority=None,
                      root_guard=None, loop_guard=None, tcn_guard=None,
                      bpdu_filter=None, bpdu_flood=None):
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        self._config_mode()
        try:
            for iface in interfaces:
                self._enter_interface(iface)
                if enabled is not None:
                    if enabled:
                        self.cli('spanning-tree mode')
                    else:
                        self.cli('no spanning-tree mode')
                if edge_port is not None:
                    if edge_port:
                        self.cli('spanning-tree edge-port')
                    else:
                        self.cli('no spanning-tree edge-port')
                if auto_edge is not None:
                    if auto_edge:
                        self.cli('spanning-tree edge-auto')
                    else:
                        self.cli('no spanning-tree edge-auto')
                if path_cost is not None:
                    self.cli(f'spanning-tree cost {int(path_cost)}')
                if priority is not None:
                    self.cli(f'spanning-tree priority {int(priority)}')
                if root_guard is not None:
                    if root_guard:
                        self.cli('spanning-tree guard-root')
                    else:
                        self.cli('no spanning-tree guard-root')
                if loop_guard is not None:
                    if loop_guard:
                        self.cli('spanning-tree guard-loop')
                    else:
                        self.cli('no spanning-tree guard-loop')
                if tcn_guard is not None:
                    if tcn_guard:
                        self.cli('spanning-tree guard-tcn')
                    else:
                        self.cli('no spanning-tree guard-tcn')
                if bpdu_filter is not None:
                    if bpdu_filter:
                        self.cli('spanning-tree bpdu-filter')
                    else:
                        self.cli('no spanning-tree bpdu-filter')
                if bpdu_flood is not None:
                    if bpdu_flood:
                        self.cli('spanning-tree bpdu-flood')
                    else:
                        self.cli('no spanning-tree bpdu-flood')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def get_vlan_ingress(self, *ports):
        """Get per-port ingress settings via ``show vlan port``.

        Returns::

            {'1/1': {'pvid': 1, 'frame_types': 'admit_all', 'ingress_filtering': False}}
        """
        output = self.cli('show vlan port')['show vlan port']
        result = {}
        for fields in parse_table(output, min_fields=4):
            interface = fields[0]
            if ports and interface not in ports:
                continue
            try:
                pvid = int(fields[1])
            except ValueError:
                continue
            frame_raw = ' '.join(fields[2:-2])  # "admit all" or "vlan only"
            if 'vlan only' in frame_raw.lower():
                frame_types = 'admit_only_tagged'
            else:
                frame_types = 'admit_all'
            filt_raw = fields[-2].lower()
            ingress_filtering = filt_raw == 'enable'
            result[interface] = {
                'pvid': pvid,
                'frame_types': frame_types,
                'ingress_filtering': ingress_filtering,
            }
        return result

    def get_vlan_egress(self, *ports):
        """Get per-VLAN-per-port egress membership via ``show vlan id N``.

        Returns::

            {1: {'name': 'default', 'ports': {'1/1': 'untagged', '1/2': 'tagged'}}}
        """
        brief_output = self.cli('show vlan brief')['show vlan brief']
        vlan_ids = []
        for fields in parse_table(brief_output, min_fields=2):
            try:
                vlan_ids.append(int(fields[0]))
            except ValueError:
                continue

        result = {}
        for vlan_id in vlan_ids:
            cmd = f'show vlan id {vlan_id}'
            output = self.cli(cmd)[cmd]
            # Parse VLAN name from header: "VLAN Name...................................ADAM"
            name = ''
            for line in output.splitlines():
                if line.startswith('VLAN Name'):
                    name = line.split('.')[-1].strip() if '...' in line else ''
                    break
            vlan_ports = {}
            for fields in parse_table(output, min_fields=4):
                interface = fields[0]
                if ports and interface not in ports:
                    continue
                current = fields[1]
                configured = fields[2]
                tagging = fields[3].lower()
                if current == 'Include':
                    mode = 'tagged' if tagging == 'tagged' else 'untagged'
                    vlan_ports[interface] = mode
                elif configured == 'Exclude':
                    vlan_ports[interface] = 'forbidden'
            if vlan_ports or not ports:
                result[vlan_id] = {'name': name, 'ports': vlan_ports}
        return result

    def set_vlan_ingress(self, port, pvid=None, frame_types=None,
                         ingress_filtering=None):
        """Set ingress parameters on one or more ports.

        Args:
            port: interface name (str) or list of interface names
            pvid: PVID integer, or None to skip
            frame_types: ``'admit_all'`` or ``'admit_only_tagged'``, or None
            ingress_filtering: True/False, or None to skip
        """
        ports = [port] if isinstance(port, str) else list(port)
        self._config_mode()
        try:
            for p in ports:
                self._enter_interface(p)
                if pvid is not None:
                    self.cli(f'vlan pvid {pvid}')
                if frame_types is not None:
                    if frame_types == 'admit_only_tagged':
                        self.cli('vlan acceptframe vlanonly')
                    else:
                        self.cli('vlan acceptframe all')
                if ingress_filtering is not None:
                    if ingress_filtering:
                        self.cli('vlan ingressfilter enable')
                    else:
                        self.cli('vlan ingressfilter disable')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def set_vlan_egress(self, vlan_id, port, mode):
        """Set port(s) egress membership for one VLAN.

        Args:
            vlan_id: VLAN ID integer
            port: interface name (str) or list of interface names
            mode: ``'tagged'``, ``'untagged'``, ``'forbidden'``, or ``'none'``
        """
        ports = [port] if isinstance(port, str) else list(port)
        self._config_mode()
        try:
            for p in ports:
                self._enter_interface(p)
                if mode == 'tagged':
                    self.cli(f'vlan participation include {vlan_id}')
                    self.cli(f'vlan tagging {vlan_id}')
                elif mode == 'untagged':
                    self.cli(f'vlan participation include {vlan_id}')
                    self.cli(f'no vlan tagging {vlan_id}')
                elif mode == 'forbidden':
                    self.cli(f'vlan participation exclude {vlan_id}')
                elif mode == 'none':
                    self.cli(f'vlan participation auto {vlan_id}')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def _vlan_database(self):
        """Enter VLAN database context from enable mode.

        Prompt changes from ``#`` to ``(Vlan)#``.
        """
        self._enable()
        self.cli('vlan database')

    def _exit_vlan_database(self):
        """Exit VLAN database context back to enable mode."""
        self.cli('exit')
        self._disable()

    def create_vlan(self, vlan_id, name=''):
        """Create a VLAN in the VLAN database.

        Args:
            vlan_id: VLAN ID integer
            name: optional VLAN name string
        """
        self._vlan_database()
        try:
            self.cli(f'vlan add {vlan_id}')
            if name:
                self.cli(f'name {vlan_id} {name}')
        finally:
            self._exit_vlan_database()

    def update_vlan(self, vlan_id, name):
        """Rename an existing VLAN.

        Args:
            vlan_id: VLAN ID integer
            name: new VLAN name string
        """
        self._vlan_database()
        try:
            self.cli(f'name {vlan_id} {name}')
        finally:
            self._exit_vlan_database()

    def delete_vlan(self, vlan_id):
        """Delete a VLAN from the VLAN database.

        Args:
            vlan_id: VLAN ID integer
        """
        self._vlan_database()
        try:
            self.cli(f'vlan delete {vlan_id}')
        finally:
            self._exit_vlan_database()

    def set_access_port(self, port, vlan_id):
        """Not available via SSH — no atomic multi-command."""
        raise NotImplementedError(
            "SSH has no atomic multi-command — use MOPS, SNMP, or Offline")

    # ── Syslog ───────────────────────────────────────────────────

    def get_syslog(self):
        """Read syslog configuration via CLI."""
        output = self.cli('show logging syslog')['show logging syslog']
        d = parse_dot_keys(output)
        enabled = d.get('Syslog logging settings', '').strip().lower()
        return {
            'enabled': enabled in ('enable', 'enabled'),
            'servers': [],
        }

    def set_syslog(self, enabled=None, servers=None):
        """Set syslog configuration via CLI."""
        self._config_mode()
        try:
            if enabled is not None:
                if enabled:
                    self.cli('logging syslog operation')
                else:
                    self.cli('no logging syslog operation')
        finally:
            self._exit_config_mode()

    # ── NTP / SNTP ───────────────────────────────────────────────

    def get_ntp(self):
        """Read SNTP client configuration via CLI."""
        output = self.cli('show sntp client status')[
            'show sntp client status']
        d = parse_dot_keys(output)
        enabled = d.get('Operation', '').strip().lower()
        server_output = self.cli('show sntp client server')[
            'show sntp client server']
        rows = parse_table(server_output, min_fields=4)
        servers = []
        i = 0
        while i < len(rows):
            fields = rows[i]
            if fields and fields[0].isdigit() and len(fields) >= 4:
                addr = fields[3]
                status = ''
                if i + 1 < len(rows):
                    status = rows[i + 1][0] if rows[i + 1] else ''
                    i += 2
                else:
                    i += 1
                servers.append({
                    'address': addr,
                    'port': 123,
                    'status': status,
                })
            else:
                i += 1
        return {
            'client': {
                'enabled': enabled in ('enable', 'enabled'),
                'mode': 'sntp',
                'servers': servers,
            },
            'server': {'enabled': False, 'stratum': 1},
        }

    def set_ntp(self, client_enabled=None, server_enabled=None):
        """Set SNTP client enable/disable via CLI."""
        self._config_mode()
        try:
            if client_enabled is not None:
                if client_enabled:
                    self.cli('sntp client operation')
                else:
                    self.cli('no sntp client operation')
        finally:
            self._exit_config_mode()

    # ── Services ─────────────────────────────────────────────────

    def get_services(self, *fields):
        """Read service enable/disable state via CLI."""
        _all = not fields

        def _parse_enabled(key, text):
            d = parse_dot_keys(text)
            for k, v in d.items():
                if key.lower() in k.lower():
                    return v.strip().lower() in (
                        'enable', 'enabled')
            return False

        def _parse_port(key, text, default):
            d = parse_dot_keys(text)
            for k, v in d.items():
                if key.lower() in k.lower() and 'port' in k.lower():
                    try:
                        return int(v.strip())
                    except ValueError:
                        pass
            return default

        out = {}
        cmds = []
        if _all or any(f in fields for f in
                       ('http', 'https', 'ssh', 'telnet', 'snmp')):
            cmds += ['show http', 'show https', 'show ssh server',
                     'show telnet', 'show snmp access']
        if _all or 'industrial' in fields:
            cmds += ['show iec61850-mms', 'show profinet global',
                     'show ethernet-ip', 'show modbus-tcp']
        if _all or 'unsigned_sw' in fields:
            cmds.append('show firmware allow-unsigned')
        if _all or 'mvrp' in fields:
            cmds.append('show mrp-ieee mvrp global')
        if _all or 'mmrp' in fields:
            cmds.append('show mrp-ieee mmrp global')
        if _all or any(f in fields for f in
                       ('aca_auto_update', 'aca_config_write',
                        'aca_config_load')):
            cmds.append('show config envm settings')
        if _all or 'devsec_monitors' in fields:
            cmds.append('show security-status monitor')

        results = self.cli(cmds) if cmds else {}

        if _all or any(f in fields for f in
                       ('http', 'https', 'ssh', 'telnet', 'snmp')):
            http_out = results.get('show http', '')
            https_out = results.get('show https', '')
            ssh_out = results.get('show ssh server', '')
            tel_out = results.get('show telnet', '')
            snmp_out = results.get('show snmp access', '')
            snmp_d = parse_dot_keys(snmp_out)
            out.update({
                'http': {
                    'enabled': _parse_enabled(
                        'HTTP status', http_out),
                    'port': _parse_port('HTTP', http_out, 80),
                },
                'https': {
                    'enabled': _parse_enabled(
                        'HTTPS status', https_out),
                    'port': _parse_port('HTTPS', https_out, 443),
                    'tls_versions': [],
                    'tls_cipher_suites': [],
                },
                'ssh': {
                    'enabled': _parse_enabled(
                        'SSH server status', ssh_out),
                    'hmac_algorithms': [],
                    'kex_algorithms': [],
                    'encryption_algorithms': [],
                    'host_key_algorithms': [],
                },
                'telnet': {
                    'enabled': _parse_enabled(
                        'Telnet server status', tel_out),
                },
                'snmp': {
                    'v1': snmp_d.get(
                        'Access by SNMP v1',
                        '').strip().lower() == 'enabled',
                    'v2': snmp_d.get(
                        'Access by SNMP v2',
                        '').strip().lower() == 'enabled',
                    'v3': snmp_d.get(
                        'Access by SNMP v3',
                        '').strip().lower() == 'enabled',
                    'port': int(snmp_d.get(
                        'SNMP port number', '161').strip()),
                },
            })

        if _all or 'industrial' in fields:
            iec_out = results.get('show iec61850-mms', '')
            pn_out = results.get('show profinet global', '')
            eip_out = results.get('show ethernet-ip', '')
            mb_out = results.get('show modbus-tcp', '')
            out['industrial'] = {
                'iec61850': _parse_enabled(
                    'MMS server operation', iec_out),
                'profinet': _parse_enabled(
                    'PROFINET operation', pn_out),
                'ethernet_ip': _parse_enabled(
                    'EtherNet/IP operation', eip_out),
                'opcua': False,
                'modbus': _parse_enabled(
                    'Modbus TCP/IP server operation', mb_out),
            }

        if _all or 'unsigned_sw' in fields:
            fw_out = results.get('show firmware allow-unsigned', '')
            out['unsigned_sw'] = _parse_enabled(
                'allow-unsigned', fw_out)

        if _all or 'mvrp' in fields:
            mvrp_out = results.get(
                'show mrp-ieee mvrp global', '')
            out['mvrp'] = _parse_enabled('operation', mvrp_out)

        if _all or 'mmrp' in fields:
            mmrp_out = results.get(
                'show mrp-ieee mmrp global', '')
            out['mmrp'] = _parse_enabled('operation', mmrp_out)

        if _all or any(f in fields for f in
                       ('aca_auto_update', 'aca_config_write',
                        'aca_config_load')):
            envm_out = results.get('show config envm settings', '')
            envm_d = parse_dot_keys(envm_out)
            out['aca_auto_update'] = any(
                v.strip().lower() in ('enable', 'enabled')
                for k, v in envm_d.items()
                if 'auto-update' in k.lower())
            out['aca_config_write'] = any(
                v.strip().lower() in ('enable', 'enabled')
                for k, v in envm_d.items()
                if 'config-save' in k.lower())
            out['aca_config_load'] = any(
                v.strip().lower() not in ('disable', 'disabled', '0')
                for k, v in envm_d.items()
                if 'load-priority' in k.lower()
                and v.strip() != '0')

        if _all or 'devsec_monitors' in fields:
            sec_out = results.get(
                'show security-status monitor', '')
            sec_d = parse_dot_keys(sec_out)
            out['devsec_monitors'] = all(
                v.strip().lower() in ('enable', 'enabled')
                for v in sec_d.values()) if sec_d else False

        if _all or 'gvrp' in fields:
            out['gvrp'] = False
        if _all or 'gmrp' in fields:
            out['gmrp'] = False

        return out

    def set_services(self, http=None, https=None, ssh=None,
                     telnet=None, snmp_v1=None, snmp_v2=None,
                     snmp_v3=None, iec61850=None, profinet=None,
                     ethernet_ip=None, opcua=None, modbus=None,
                     unsigned_sw=None, aca_auto_update=None,
                     aca_config_write=None, aca_config_load=None,
                     mvrp=None, mmrp=None, devsec_monitors=None,
                     **kwargs):
        """Set service enable/disable via CLI.

        Cipher kwargs (tls_versions, tls_cipher_suites, ssh_hmac,
        ssh_kex, ssh_encryption, ssh_host_key) are silently ignored —
        no CLI equivalent exists. Use MOPS or SNMP for cipher config.
        """
        self._config_mode()
        try:
            if http is not None:
                self.cli('http server' if http
                         else 'no http server')
            if https is not None:
                self.cli('https server' if https
                         else 'no https server')
            if ssh is not None:
                self.cli('ssh server' if ssh
                         else 'no ssh server')
            if telnet is not None:
                self.cli('telnet server' if telnet
                         else 'no telnet server')
            if snmp_v1 is not None:
                self.cli('snmp access version v1'
                         if snmp_v1
                         else 'no snmp access version v1')
            if snmp_v2 is not None:
                self.cli('snmp access version v2'
                         if snmp_v2
                         else 'no snmp access version v2')
            if snmp_v3 is not None:
                self.cli('snmp access version v3'
                         if snmp_v3
                         else 'no snmp access version v3')
            if iec61850 is not None:
                self.cli('iec61850-mms operation'
                         if iec61850
                         else 'no iec61850-mms operation')
            if profinet is not None:
                self.cli('profinet operation'
                         if profinet
                         else 'no profinet operation')
            if ethernet_ip is not None:
                self.cli('ethernet-ip operation'
                         if ethernet_ip
                         else 'no ethernet-ip operation')
            if modbus is not None:
                self.cli('modbus-tcp operation'
                         if modbus
                         else 'no modbus-tcp operation')
            if unsigned_sw is not None:
                self.cli('firmware allow-unsigned enable'
                         if unsigned_sw
                         else 'firmware allow-unsigned disable')
            if mvrp is not None:
                self.cli('mrp-ieee mvrp operation'
                         if mvrp
                         else 'no mrp-ieee mvrp operation')
            if mmrp is not None:
                self.cli('mrp-ieee mmrp operation'
                         if mmrp
                         else 'no mrp-ieee mmrp operation')
            if aca_auto_update is not None:
                _s = 'enable' if aca_auto_update else 'disable'
                self.cli(f'config envm auto-update {_s}')
            if aca_config_write is not None:
                _s = 'enable' if aca_config_write else 'disable'
                self.cli(f'config envm config-save {_s}')
            if aca_config_load is not None:
                _s = ('first' if aca_config_load
                      else 'disable')
                self.cli(f'config envm load-priority {_s}')
            if devsec_monitors is not None:
                _s = '' if devsec_monitors else 'no '
                _monitors = [
                    'pwd-change', 'pwd-min-length',
                    'pwd-str-not-config',
                    'bypass-pwd-strength',
                    'telnet-enabled', 'http-enabled',
                    'snmp-unsecure', 'sysmon-enabled',
                    'extnvm-upd-enabled',
                    'no-link-enabled',
                    'hidisc-enabled',
                    'extnvm-load-unsecure',
                    'iec61850-mms-enabled',
                    'https-certificate',
                    'modbus-tcp-enabled',
                    'ethernet-ip-enabled',
                    'profinet-io-enabled',
                    'secure-boot-disabled',
                    'support-mode-enabled',
                ]
                for mon in _monitors:
                    self.cli(
                        f'{_s}security-status monitor {mon}')
        finally:
            self._exit_config_mode()

    # ── SNMP Config ──────────────────────────────────────────────

    def get_snmp_config(self):
        """Read SNMP configuration via CLI."""
        output = self.cli('show snmp access')['show snmp access']
        d = parse_dot_keys(output)

        # Trap service status
        trap_service = d.get(
            'SNMP trap service',
            d.get('Trap service', 'disabled')
        ).strip().lower() in ('enable', 'enabled')

        # v3 user auth/enc — parse 'show snmp notification users'
        v3_users = []
        try:
            users_out = self.cli(
                'show snmp notification users')[
                'show snmp notification users']
            v3_users = self._parse_snmp_v3_users(users_out)
        except Exception:
            pass

        # Trap destinations — v1/v2c from 'show snmp trap',
        # v3 from 'show snmp notification hosts'
        trap_destinations = []
        try:
            trap_out = self.cli(
                'show snmp trap')['show snmp trap']
            trap_destinations.extend(
                self._parse_trap_v1v2c(trap_out))
        except Exception:
            pass
        try:
            hosts_out = self.cli(
                'show snmp notification hosts')[
                'show snmp notification hosts']
            trap_destinations.extend(
                self._parse_trap_v3(hosts_out))
        except Exception:
            pass

        return {
            'versions': {
                'v1': d.get(
                    'Access by SNMP v1', '').strip().lower() == 'enabled',
                'v2': d.get(
                    'Access by SNMP v2', '').strip().lower() == 'enabled',
                'v3': d.get(
                    'Access by SNMP v3', '').strip().lower() == 'enabled',
            },
            'port': int(d.get('SNMP port number', '161').strip()),
            'communities': [],
            'trap_service': trap_service,
            'v3_users': v3_users,
            'trap_destinations': trap_destinations,
        }

    def _parse_snmp_v3_users(self, text):
        """Parse v3 user auth/enc from 'show snmp notification users'."""
        users = []
        lines = text.splitlines()
        past_header = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if '---' in stripped:
                past_header = True
                continue
            if not past_header:
                continue
            parts = stripped.split()
            if len(parts) < 3:
                continue
            name = parts[0]
            auth = parts[1].lower() if len(parts) > 1 else ''
            enc = parts[2].lower() if len(parts) > 2 else 'none'
            if auth in ('none', '-', ''):
                auth = ''
            if enc in ('-',):
                enc = 'none'
            users.append({
                'name': name,
                'auth_type': auth,
                'enc_type': enc,
            })
        return users

    def _parse_trap_v1v2c(self, text):
        """Parse v1/v2c trap dests from 'show snmp trap'.

        Output has two sections separated by '---' lines:
        1. Status/community (after first ---)
        2. Trap table (after last ---)
        We want the table section (last ---).
        """
        destinations = []
        lines = text.splitlines()
        # Find last separator line index
        last_sep = -1
        for i, line in enumerate(lines):
            if '---' in line:
                last_sep = i
        if last_sep < 0:
            return destinations
        for line in lines[last_sep + 1:]:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            # Format: name  ip:port  [x]
            name = parts[0]
            address = parts[1]
            destinations.append({
                'name': name,
                'address': address,
                'security_model': 'v1',
                'security_name': '',
                'security_level': 'noauth',
            })
        return destinations

    def _parse_trap_v3(self, text):
        """Parse v3 trap dests from 'show snmp notification hosts'.

        Two-line format per entry:
          Line 1: name  ip:port  status
          Line 2: user  secLevel  type
        """
        destinations = []
        lines = text.splitlines()
        past_header = False
        data_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if '---' in stripped:
                past_header = True
                continue
            if not past_header:
                continue
            data_lines.append(stripped)
        # Process in pairs
        for i in range(0, len(data_lines) - 1, 2):
            line1 = data_lines[i].split()
            line2 = data_lines[i + 1].split()
            if len(line1) < 2 or len(line2) < 2:
                continue
            name = line1[0]
            address = line1[1]
            sec_name = line2[0]
            sec_level = line2[1].lower()
            # Normalise HiOS level names
            level_map = {
                'noauthnopriv': 'noauth',
                'authnopriv': 'auth',
                'authpriv': 'authpriv',
            }
            sec_level = level_map.get(
                sec_level.replace('-', '').replace('_', ''),
                sec_level)
            destinations.append({
                'name': name,
                'address': address,
                'security_model': 'v3',
                'security_name': sec_name,
                'security_level': sec_level,
            })
        return destinations

    def set_snmp_config(self, v1=None, v2=None, v3=None,
                        trap_service=None):
        """Set SNMP version enable/disable and trap service via CLI."""
        self._config_mode()
        try:
            if v1 is not None:
                self.cli('snmp access version v1'
                         if v1 else 'no snmp access version v1')
            if v2 is not None:
                self.cli('snmp access version v2'
                         if v2 else 'no snmp access version v2')
            if v3 is not None:
                self.cli('snmp access version v3'
                         if v3 else 'no snmp access version v3')
            if trap_service is not None:
                self.cli('snmp trap operation'
                         if trap_service
                         else 'no snmp trap operation')
        finally:
            self._exit_config_mode()

    _SSH_SEC_LEVEL_MAP = {
        'noauth': 'no-auth',
        'auth': 'auth-no-priv',
        'authpriv': 'auth-priv',
    }

    def add_snmp_trap_dest(self, name, address, port=162,
                           security_model='v3', security_name='admin',
                           security_level='authpriv'):
        """Add an SNMP trap destination via CLI.

        v1/v2c: snmp trap add <name> <ip>:<port>
        v3:     snmp notification host add <name> <ip>:<port>
                user <username> <level>
        """
        if security_model not in ('v1', 'v2c', 'v3'):
            raise ValueError(
                f"Invalid security_model '{security_model}': "
                f"use 'v1', 'v2c', or 'v3'")
        if security_level not in self._SSH_SEC_LEVEL_MAP:
            raise ValueError(
                f"Invalid security_level '{security_level}': "
                f"use 'noauth', 'auth', or 'authpriv'")

        addr = f'{address}:{port}' if port != 162 else address
        self._config_mode()
        try:
            if security_model in ('v1', 'v2c'):
                self.cli(f'snmp trap add {name} {addr}')
            else:
                level = self._SSH_SEC_LEVEL_MAP[security_level]
                self.cli(
                    f'snmp notification host add {name} {addr} '
                    f'user {security_name} {level}')
        finally:
            self._exit_config_mode()

    def delete_snmp_trap_dest(self, name):
        """Delete an SNMP trap destination via CLI."""
        self._config_mode()
        try:
            # Try both — v3 notification host first, then v1/v2c trap
            try:
                self.cli(
                    f'snmp notification host delete {name}')
            except Exception:
                self.cli(f'snmp trap delete {name}')
        finally:
            self._exit_config_mode()

    # ── Login Policy ─────────────────────────────────────────────

    def get_login_policy(self):
        """Read password and login lockout policy via CLI."""
        output = self.cli('show passwords')['show passwords']
        d = parse_dot_keys(output)
        # CLI shows lockout period in minutes; convert to seconds
        try:
            lockout_min = int(d.get(
                'Login attempts period [min]', '0').strip())
        except ValueError:
            lockout_min = 0
        return {
            'min_password_length': int(d.get(
                'Minimum password length', '6').strip()),
            'max_login_attempts': int(d.get(
                'Maximum login attempts', '0').strip()),
            'lockout_duration': lockout_min * 60,
            'min_uppercase': int(d.get(
                'Minimum upper case characters', '1').strip()),
            'min_lowercase': int(d.get(
                'Minimum lower case characters', '1').strip()),
            'min_numeric': int(d.get(
                'Minimum numeric characters', '1').strip()),
            'min_special': int(d.get(
                'Minimum special characters', '1').strip()),
        }

    def set_login_policy(self, min_password_length=None,
                         max_login_attempts=None, lockout_duration=None,
                         min_uppercase=None, min_lowercase=None,
                         min_numeric=None, min_special=None):
        """Set password and login lockout policy via CLI."""
        self._config_mode()
        try:
            if min_password_length is not None:
                self.cli(
                    f'passwords min-length {int(min_password_length)}')
            if max_login_attempts is not None:
                self.cli(
                    f'passwords max-login-attempts '
                    f'{int(max_login_attempts)}')
            if lockout_duration is not None:
                # CLI takes minutes; API takes seconds
                minutes = int(lockout_duration) // 60
                self.cli(
                    f'passwords login-attempt-period {minutes}')
            if min_uppercase is not None:
                self.cli(
                    f'passwords min-uppercase-chars {int(min_uppercase)}')
            if min_lowercase is not None:
                self.cli(
                    f'passwords min-lowercase-chars {int(min_lowercase)}')
            if min_numeric is not None:
                self.cli(
                    f'passwords min-numeric-chars {int(min_numeric)}')
            if min_special is not None:
                self.cli(
                    f'passwords min-special-chars {int(min_special)}')
        finally:
            self._exit_config_mode()

    # ── Signal Contact ────────────────────────────────────────────

    @staticmethod
    def _extract_table_rows(text, header_pattern):
        """Extract data rows from a CLI table identified by header
        line pattern.  Returns list of whitespace-split field lists."""
        rows = []
        lines = text.splitlines()
        header_found = False
        sep_found = False
        for line in lines:
            stripped = line.strip()
            if not header_found:
                if re.search(header_pattern, stripped):
                    header_found = True
                continue
            if not sep_found:
                if (re.match(r'^[-\s]+$', stripped)
                        and '---' in stripped):
                    sep_found = True
                continue
            if not stripped:
                break
            if (stripped.endswith(':')
                    and '....' not in stripped
                    and len(stripped) < 50):
                break
            fields = stripped.split()
            if fields:
                rows.append(fields)
        return rows

    @staticmethod
    def _parse_events_section(text):
        """Parse events table (Time stamp / Event / Info) from CLI."""
        events = []
        in_events = False
        past_sep = False
        for line in text.splitlines():
            stripped = line.strip()
            if not in_events:
                if re.search(r'Time stamp\s+Event', stripped):
                    in_events = True
                continue
            if not past_sep:
                if (re.match(r'^[-\s]+$', stripped)
                        and '---' in stripped):
                    past_sep = True
                continue
            if not stripped:
                break
            m = re.match(
                r'\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                r'\s+(\S+)\s*(.*)', line)
            if m:
                info_text = m.group(3).strip()
                info_num = 0
                if info_text and info_text != '-':
                    nums = re.findall(r'\d+', info_text)
                    if nums:
                        info_num = int(nums[-1])
                events.append({
                    'cause': m.group(2),
                    'info': info_num,
                    'timestamp': m.group(1).strip(),
                })
        return events

    def get_signal_contact(self):
        """Read signal contact configuration and status via CLI."""
        result = {}
        for cid in (1, 2):
            cmd = f'show signal-contact {cid} all'
            output = self.cli(cmd)[cmd]
            if 'Error' in output or 'Invalid' in output:
                continue
            d = parse_dot_keys(output)
            cli_mode = d.get('Mode', 'monitor').strip()
            manual_raw = d.get(
                'State (Manual Setting)', 'close').strip()

            monitoring = {}
            for cli_name, key in _SC_CLI_SENSE.items():
                val = d.get(cli_name)
                if val is not None:
                    monitoring[key] = (
                        val.strip().lower() == 'monitored')

            power_supply = {}
            for row in self._extract_table_rows(
                    output, r'Power Supply\s+Status'):
                try:
                    power_supply[int(row[0])] = (
                        row[1].lower() == 'monitored')
                except (ValueError, IndexError):
                    pass

            link_alarm = {}
            for row in self._extract_table_rows(
                    output, r'Intf\s+Status'):
                if len(row) >= 2 and '/' in row[0]:
                    link_alarm[row[0]] = row[1].lower() in (
                        'monitored', 'enable', 'enabled')

            trap_raw = d.get(
                'Trap Status', 'disabled').strip().lower()

            result[cid] = {
                'mode': _SC_CLI_MODE.get(cli_mode, cli_mode),
                'manual_state': manual_raw.split()[0],
                'trap_enabled': trap_raw in (
                    'enable', 'enabled'),
                'monitoring': monitoring,
                'power_supply': power_supply,
                'link_alarm': link_alarm,
                'status': {
                    'oper_state': d.get(
                        'Operating State (current)',
                        'close').strip(),
                    'last_change': d.get(
                        'Time of last state change',
                        '').strip(),
                    'cause': d.get(
                        'Trap Cause', 'none').strip(),
                    'cause_index': int(d.get(
                        'Trap Cause Index', '0').strip()),
                    'events': self._parse_events_section(
                        output),
                },
            }
        return result

    def set_signal_contact(self, contact_id=1, mode=None,
                           manual_state=None, trap_enabled=None,
                           monitoring=None, power_supply=None,
                           link_alarm=None):
        """Configure signal contact relay via CLI."""
        n = contact_id
        self._config_mode()
        try:
            if mode is not None:
                cli_mode = _SC_CLI_MODE_REV.get(mode)
                if cli_mode is None:
                    raise ValueError(
                        f"Invalid mode '{mode}'. Valid: "
                        f"{', '.join(sorted(_SC_CLI_MODE_REV))}")
                self.cli(
                    f'signal-contact {n} mode {cli_mode}')
            if manual_state is not None:
                self.cli(
                    f'signal-contact {n} state {manual_state}')
            if trap_enabled is not None:
                prefix = '' if trap_enabled else 'no '
                self.cli(f'{prefix}signal-contact {n} trap')
            if monitoring:
                for key, enabled in monitoring.items():
                    cli_cmd = _SENSE_CLI_CMD.get(key)
                    if cli_cmd is None:
                        raise ValueError(
                            f"Unknown sense flag '{key}'")
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}signal-contact {n} '
                        f'monitor {cli_cmd}')
            if power_supply:
                for ps_id, enabled in power_supply.items():
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}signal-contact {n} '
                        f'monitor power-supply {ps_id}')
            if link_alarm:
                for port, enabled in link_alarm.items():
                    self._enter_interface(port)
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}signal-contact {n} '
                        f'link-alarm')
                    self.cli('exit')
        finally:
            self._exit_config_mode()

    # ── Device Monitor ────────────────────────────────────────────

    def get_device_monitor(self):
        """Read device status monitoring via CLI."""
        output = self.cli(
            'show device-status all')['show device-status all']
        d = parse_dot_keys(output)

        monitoring = {}
        for cli_name, key in _SC_CLI_SENSE.items():
            val = d.get(cli_name)
            if val is not None:
                monitoring[key] = (
                    val.strip().lower() == 'monitored')

        power_supply = {}
        for row in self._extract_table_rows(
                output, r'Power Supply\s+Status'):
            try:
                power_supply[int(row[0])] = (
                    row[1].lower() == 'monitored')
            except (ValueError, IndexError):
                pass

        link_alarm = {}
        for row in self._extract_table_rows(
                output, r'Intf\s+Status'):
            if len(row) >= 2 and '/' in row[0]:
                link_alarm[row[0]] = row[1].lower() in (
                    'monitored', 'enable', 'enabled')

        trap_raw = d.get(
            'Trap Status', 'disabled').strip().lower()

        return {
            'trap_enabled': trap_raw in (
                'enable', 'enabled'),
            'monitoring': monitoring,
            'power_supply': power_supply,
            'link_alarm': link_alarm,
            'status': {
                'oper_state': d.get(
                    'Operating State (current)',
                    'ok').strip(),
                'last_change': d.get(
                    'Time of last state change',
                    '').strip(),
                'cause': d.get(
                    'Trap Cause', 'none').strip(),
                'cause_index': int(d.get(
                    'Trap Cause Index', '0').strip()),
                'events': self._parse_events_section(output),
            },
        }

    def set_device_monitor(self, trap_enabled=None,
                           monitoring=None, power_supply=None,
                           link_alarm=None):
        """Configure device status monitoring via CLI."""
        self._config_mode()
        try:
            if trap_enabled is not None:
                prefix = '' if trap_enabled else 'no '
                self.cli(f'{prefix}device-status trap')
            if monitoring:
                for key, enabled in monitoring.items():
                    cli_cmd = _SENSE_CLI_CMD.get(key)
                    if cli_cmd is None:
                        raise ValueError(
                            f"Unknown sense flag '{key}'")
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}device-status monitor '
                        f'{cli_cmd}')
            if power_supply:
                for ps_id, enabled in power_supply.items():
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}device-status monitor '
                        f'power-supply {ps_id}')
            if link_alarm:
                for port, enabled in link_alarm.items():
                    self._enter_interface(port)
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}device-status link-alarm')
                    self.cli('exit')
        finally:
            self._exit_config_mode()

    # ── Device Security Status ────────────────────────────────────

    def get_devsec_status(self):
        """Read security status monitoring via CLI."""
        output = self.cli(
            'show security-status all')[
            'show security-status all']
        d = parse_dot_keys(output)

        monitoring = {}
        for cli_name, key in _DEVSEC_CLI_SENSE.items():
            val = d.get(cli_name)
            if val is not None:
                monitoring[key] = (
                    val.strip().lower() == 'monitored')
            else:
                # Fallback: long keys may lack enough dots
                # for parse_dot_keys (e.g. "Loading ... ENVM")
                for line in output.splitlines():
                    if cli_name in line:
                        monitoring[key] = (
                            'monitored' in line.lower())
                        break

        no_link = {}
        for row in self._extract_table_rows(
                output, r'Intf\s+Status'):
            if len(row) >= 2 and '/' in row[0]:
                no_link[row[0]] = row[1].lower() in (
                    'enable', 'enabled')

        trap_raw = d.get(
            'Trap', d.get('Trap Status', 'disabled')
        ).strip().lower()

        return {
            'trap_enabled': trap_raw in (
                'enable', 'enabled'),
            'monitoring': monitoring,
            'no_link': no_link,
            'status': {
                'oper_state': d.get(
                    'OperState', 'ok').strip(),
                'last_change': d.get(
                    'Time of last state change',
                    '').strip(),
                'cause': d.get(
                    'Trap Cause', 'none').strip(),
                'cause_index': int(d.get(
                    'Trap Cause Index', '0').strip()),
                'events': self._parse_events_section(output),
            },
        }

    def set_devsec_status(self, trap_enabled=None,
                          monitoring=None, no_link=None):
        """Configure security status monitoring via CLI."""
        self._config_mode()
        try:
            if trap_enabled is not None:
                prefix = '' if trap_enabled else 'no '
                self.cli(f'{prefix}security-status trap')
            if monitoring:
                for key, enabled in monitoring.items():
                    cli_cmd = _DEVSEC_SENSE_CLI_CMD.get(key)
                    if cli_cmd is None:
                        raise ValueError(
                            f"Unknown sense flag '{key}'")
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}security-status monitor '
                        f'{cli_cmd}')
            if no_link:
                for port, enabled in no_link.items():
                    self._enter_interface(port)
                    prefix = '' if enabled else 'no '
                    self.cli(
                        f'{prefix}security-status no-link')
                    self.cli('exit')
        finally:
            self._exit_config_mode()

    # ── Banner ────────────────────────────────────────────────────

    @staticmethod
    def _parse_banner_text(output, key_prefix):
        """Extract banner text that may appear on continuation
        line(s) below the dot-key header."""
        lines = output.splitlines()
        capture = False
        text_lines = []
        for line in lines:
            if capture:
                stripped = line.strip()
                # Stop at next dot-key or separator or empty
                if ('....' in stripped or not stripped
                        or re.match(r'^[-=]+$', stripped)):
                    break
                text_lines.append(stripped)
            elif key_prefix in line and '....' in line:
                # Check inline value after dots
                _, _, val = line.partition('....')
                val = val.strip().lstrip('.')
                if val:
                    return val
                capture = True
        return '\n'.join(text_lines)

    def get_banner(self):
        """Read pre-login and CLI login banner via CLI."""
        pre_out = self.cli(
            'show system pre-login-banner')[
            'show system pre-login-banner']
        cli_out = self.cli(
            'show cli global')['show cli global']
        pre_d = parse_dot_keys(pre_out)
        cli_d = parse_dot_keys(cli_out)

        return {
            'pre_login': {
                'enabled': pre_d.get(
                    'Login banner status',
                    'disabled').strip().lower()
                    in ('enable', 'enabled'),
                'text': self._parse_banner_text(
                    pre_out, 'Login banner text'),
            },
            'cli_login': {
                'enabled': cli_d.get(
                    'CLI banner status',
                    'disabled').strip().lower()
                    in ('enable', 'enabled'),
                'text': self._parse_banner_text(
                    cli_out, 'CLI banner text'),
            },
        }

    def set_banner(self, pre_login_enabled=None,
                   pre_login_text=None,
                   cli_login_enabled=None,
                   cli_login_text=None):
        """Set pre-login and/or CLI login banner via CLI."""
        self._config_mode()
        try:
            if pre_login_enabled is not None:
                if pre_login_enabled:
                    self.cli(
                        'system pre-login-banner operation')
                else:
                    self.cli(
                        'no system pre-login-banner operation')
            if pre_login_text is not None:
                self.cli(
                    f'system pre-login-banner text '
                    f'{pre_login_text}')
            if cli_login_enabled is not None:
                if cli_login_enabled:
                    self.cli('cli banner operation')
                else:
                    self.cli('no cli banner operation')
            if cli_login_text is not None:
                self.cli(f'cli banner text {cli_login_text}')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # Session Config
    # ------------------------------------------------------------------

    def get_session_config(self):
        """Read session timeouts and max-sessions via CLI."""
        ssh_out = self.cli(
            'show sessions ssh')['show sessions ssh']
        tel_out = self.cli(
            'show sessions telnet')['show sessions telnet']
        web_out = self.cli(
            'show sessions web')['show sessions web']
        cli_out = self.cli(
            'show cli global')['show cli global']
        serial_phys = self.cli(
            'show physical-interfaces serial'
        )['show physical-interfaces serial']
        envm_phys = self.cli(
            'show physical-interfaces envm'
        )['show physical-interfaces envm']

        ssh_d = parse_dot_keys(ssh_out)
        tel_d = parse_dot_keys(tel_out)
        web_d = parse_dot_keys(web_out)
        cli_d = parse_dot_keys(cli_out)
        ser_d = parse_dot_keys(serial_phys)
        envm_d = parse_dot_keys(envm_phys)

        def _is_enabled(d, *keys):
            for k in keys:
                v = d.get(k, '')
                if v:
                    return v.strip().lower() in (
                        'enabled', 'enable', 'active', 'on')
            return True  # default enabled

        return {
            'ssh': {
                'timeout': int(ssh_d.get(
                    'SSH session timeout [min]',
                    ssh_d.get('Timeout [min]', '0')).strip()),
                'max_sessions': int(ssh_d.get(
                    'SSH max sessions',
                    ssh_d.get('Max sessions', '0')).strip()),
                'active_sessions': int(ssh_d.get(
                    'SSH active sessions',
                    ssh_d.get('Active sessions', '0')).strip()),
            },
            'ssh_outbound': {
                'timeout': int(ssh_d.get(
                    'SSH outbound timeout [min]',
                    ssh_d.get('Outbound timeout [min]', '0')).strip()),
                'max_sessions': int(ssh_d.get(
                    'SSH outbound max sessions',
                    ssh_d.get('Outbound max sessions', '0')).strip()),
                'active_sessions': int(ssh_d.get(
                    'SSH outbound active sessions',
                    ssh_d.get('Outbound active sessions', '0')).strip()),
            },
            'telnet': {
                'timeout': int(tel_d.get(
                    'Telnet session timeout [min]',
                    tel_d.get('Timeout [min]', '0')).strip()),
                'max_sessions': int(tel_d.get(
                    'Telnet max sessions',
                    tel_d.get('Max sessions', '0')).strip()),
                'active_sessions': int(tel_d.get(
                    'Telnet active sessions',
                    tel_d.get('Active sessions', '0')).strip()),
            },
            'web': {
                'timeout': int(web_d.get(
                    'Web interface timeout [min]',
                    web_d.get('Timeout [min]', '0')).strip()),
            },
            'serial': {
                'timeout': int(cli_d.get(
                    'CLI serial timeout [min]',
                    cli_d.get('Serial timeout [min]', '0')).strip()),
                'enabled': _is_enabled(
                    ser_d, 'State after next reboot',
                    'Admin state', 'Operation'),
                'oper_status': _is_enabled(
                    ser_d, 'Current state', 'Oper state',
                    'Operation'),
            },
            'envm': {
                'enabled': _is_enabled(
                    envm_d, 'State after next reboot',
                    'Admin state', 'Operation'),
                'oper_status': _is_enabled(
                    envm_d, 'Current state', 'Oper state',
                    'Operation'),
            },
            'netconf': {
                'timeout': 0,
                'max_sessions': 0,
                'active_sessions': 0,
            },
        }

    def set_session_config(self, ssh_timeout=None, ssh_max_sessions=None,
                           ssh_outbound_timeout=None,
                           ssh_outbound_max_sessions=None,
                           telnet_timeout=None, telnet_max_sessions=None,
                           web_timeout=None, serial_timeout=None,
                           netconf_timeout=None,
                           netconf_max_sessions=None,
                           serial_enabled=None, envm_enabled=None):
        """Set session timeouts and max-sessions via CLI."""
        self._config_mode()
        try:
            if ssh_timeout is not None:
                self.cli(f'ssh timeout {ssh_timeout}')
            if ssh_max_sessions is not None:
                self.cli(f'ssh max-sessions {ssh_max_sessions}')
            if ssh_outbound_timeout is not None:
                self.cli(
                    f'ssh outbound timeout {ssh_outbound_timeout}')
            if ssh_outbound_max_sessions is not None:
                self.cli(
                    f'ssh outbound max-sessions '
                    f'{ssh_outbound_max_sessions}')
            if telnet_timeout is not None:
                self.cli(f'telnet timeout {telnet_timeout}')
            if telnet_max_sessions is not None:
                self.cli(
                    f'telnet max-sessions {telnet_max_sessions}')
            if web_timeout is not None:
                self.cli(
                    f'network management access web timeout '
                    f'{web_timeout}')
            if serial_timeout is not None:
                self.cli(f'cli serial-timeout {serial_timeout}')
            if serial_enabled is not None:
                self.cli('physical-interfaces serial operation'
                         if serial_enabled
                         else 'no physical-interfaces serial operation')
            if envm_enabled is not None:
                self.cli('physical-interfaces envm operation'
                         if envm_enabled
                         else 'no physical-interfaces envm operation')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # IP Restrict
    # ------------------------------------------------------------------

    def get_ip_restrict(self):
        """Read restricted management access via CLI."""
        global_out = self.cli(
            'show network management access global')[
            'show network management access global']
        g = parse_dot_keys(global_out)

        rules_out = self.cli(
            'show network management access rules')[
            'show network management access rules']

        rules = self._parse_rma_rules(rules_out)

        return {
            'enabled': g.get(
                'Restricted management access',
                g.get('Operation', 'disabled')
            ).strip().lower() in ('enable', 'enabled'),
            'logging': g.get(
                'Logging', 'disabled'
            ).strip().lower() in ('enable', 'enabled'),
            'rules': rules,
        }

    def _parse_rma_rules(self, text):
        """Parse RMA rules table output."""
        rules = []
        lines = text.splitlines()
        past_header = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if '---' in stripped and not past_header:
                past_header = True
                continue
            if not past_header:
                continue
            # Table rows: Index IP/Mask HTTP HTTPS SNMP ...
            parts = stripped.split()
            if len(parts) < 3:
                continue
            try:
                idx = int(parts[0])
            except ValueError:
                continue
            # Parse IP/mask
            ip_mask = parts[1] if len(parts) > 1 else '0.0.0.0/0'
            if '/' in ip_mask:
                ip, prefix = ip_mask.rsplit('/', 1)
                try:
                    prefix_len = int(prefix)
                except ValueError:
                    prefix_len = 0
            else:
                ip = ip_mask
                prefix_len = 0

            def _svc(val):
                return val.strip().lower() in (
                    'enable', 'enabled', 'yes', 'active')

            services = {}
            svc_names = [
                'http', 'https', 'snmp', 'telnet', 'ssh',
                'iec61850', 'modbus', 'ethernet_ip', 'profinet']
            for i, sname in enumerate(svc_names):
                if 2 + i < len(parts):
                    services[sname] = _svc(parts[2 + i])
                else:
                    services[sname] = True

            rules.append({
                'index': idx,
                'ip': ip,
                'prefix_length': prefix_len,
                'services': services,
                'interface': '',
                'per_rule_logging': False,
                'log_counter': 0,
            })
        return rules

    def set_ip_restrict(self, enabled=None, logging=None):
        """Set global RMA enable/logging via CLI."""
        self._config_mode()
        try:
            if enabled is not None:
                if enabled:
                    self.cli(
                        'network management access operation')
                else:
                    self.cli(
                        'no network management access operation')
            if logging is not None:
                if logging:
                    self.cli(
                        'network management access logging')
                else:
                    self.cli(
                        'no network management access logging')
        finally:
            self._exit_config_mode()

    def add_ip_restrict_rule(self, index, ip='0.0.0.0',
                             prefix_length=0,
                             http=True, https=True, snmp=True,
                             telnet=True, ssh=True, iec61850=True,
                             modbus=True, ethernet_ip=True,
                             profinet=True,
                             interface='',
                             per_rule_logging=False):
        """Create RMA rule via CLI."""
        svc_parts = []
        for name, val in [
            ('http', http), ('https', https), ('snmp', snmp),
            ('telnet', telnet), ('ssh', ssh),
            ('iec61850-mms', iec61850),
            ('modbus-tcp', modbus),
            ('ethernet-ip', ethernet_ip),
            ('profinet-io', profinet),
        ]:
            svc_parts.append(
                f'{name} enable' if val else f'{name} disable')
        svc_str = ' '.join(svc_parts)
        cmd = (f'network management access add {index} '
               f'ip {ip} mask {prefix_length} {svc_str}')
        self._config_mode()
        try:
            self.cli(cmd)
        finally:
            self._exit_config_mode()

    def delete_ip_restrict_rule(self, index):
        """Delete RMA rule by index via CLI."""
        self._config_mode()
        try:
            self.cli(
                f'network management access delete {index}')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # DNS Client
    # ------------------------------------------------------------------

    _DNS_SOURCE_MAP = {
        'user': 'user', 'mgmt-dhcp': 'mgmt-dhcp',
        'provider': 'provider',
    }

    def get_dns(self):
        """Read DNS client configuration via CLI."""
        results = self.cli([
            'show dns client info',
            'show dns client servers',
            'show dns client servers extern',
        ])

        # Scalars from dot-key output
        info = parse_dot_keys(
            results['show dns client info'])

        enabled = False
        for k, v in info.items():
            if 'client status' in k.lower():
                enabled = v.strip().lower() in (
                    'enable', 'enabled')
                break

        cache_enabled = False
        for k, v in info.items():
            if 'cache status' in k.lower():
                cache_enabled = v.strip().lower() in (
                    'enable', 'enabled')
                break

        config_source = 'mgmt-dhcp'
        for k, v in info.items():
            if 'configuration source' in k.lower():
                config_source = v.strip().lower()
                break

        domain_name = ''
        for k, v in info.items():
            if 'domain name' in k.lower():
                domain_name = v.strip()
                break

        timeout = 3
        for k, v in info.items():
            if 'timeout' in k.lower():
                try:
                    timeout = int(v.strip())
                except ValueError:
                    pass
                break

        retransmits = 2
        for k, v in info.items():
            if 'retransmit' in k.lower():
                try:
                    retransmits = int(v.strip())
                except ValueError:
                    pass
                break

        # Server table: "No. | IP address | Active"
        servers = []
        active_servers = []
        srv_out = results['show dns client servers']
        for fields in parse_table(srv_out, min_fields=2):
            try:
                int(fields[0])  # index column
            except (ValueError, IndexError):
                continue
            addr = fields[1]
            if addr and addr != '0.0.0.0':
                servers.append(addr)
                # Active column: [x] = active
                if len(fields) >= 3 and '[x]' in fields[2]:
                    active_servers.append(addr)

        # Extern servers (DHCP-provided) — also active
        ext_out = results['show dns client servers extern']
        for fields in parse_table(ext_out, min_fields=2):
            try:
                int(fields[0])
            except (ValueError, IndexError):
                continue
            addr = fields[1]
            if (addr and addr != '0.0.0.0'
                    and addr not in active_servers):
                active_servers.append(addr)

        return {
            'enabled': enabled,
            'config_source': config_source,
            'domain_name': domain_name,
            'timeout': timeout,
            'retransmits': retransmits,
            'cache_enabled': cache_enabled,
            'servers': servers,
            'active_servers': active_servers,
        }

    def set_dns(self, enabled=None, config_source=None,
                domain_name=None, timeout=None, retransmits=None,
                cache_enabled=None):
        """Set DNS client global configuration via CLI."""
        self._config_mode()
        try:
            if enabled is not None:
                if enabled:
                    self.cli('dns client adminstate')
                else:
                    self.cli('no dns client adminstate')
            if config_source is not None:
                if config_source not in self._DNS_SOURCE_MAP:
                    raise ValueError(
                        f"config_source must be one of "
                        f"{list(self._DNS_SOURCE_MAP)}, "
                        f"got '{config_source}'")
                self.cli(
                    f'dns client source {config_source}')
            if domain_name is not None:
                self.cli(
                    f'dns client domain-name {domain_name}')
            if timeout is not None:
                self.cli(f'dns client timeout {int(timeout)}')
            if retransmits is not None:
                self.cli(f'dns client retry {int(retransmits)}')
            if cache_enabled is not None:
                if cache_enabled:
                    self.cli('dns client cache adminstate')
                else:
                    self.cli('no dns client cache adminstate')
        finally:
            self._exit_config_mode()

    def add_dns_server(self, address):
        """Add a DNS server via CLI. Auto-picks next free index."""
        # Find used indices
        srv_out = self.cli(
            'show dns client servers')['show dns client servers']
        used = set()
        for fields in parse_table(srv_out, min_fields=2):
            try:
                used.add(int(fields[0]))
            except (ValueError, IndexError):
                continue
        free_idx = None
        for i in range(1, 5):
            if i not in used:
                free_idx = i
                break
        if free_idx is None:
            raise ValueError("All 4 DNS server slots are in use")
        self._config_mode()
        try:
            self.cli(
                f'dns client servers add {free_idx} ip '
                f'{address}')
        finally:
            self._exit_config_mode()

    def delete_dns_server(self, address):
        """Delete a DNS server by IP address via CLI."""
        srv_out = self.cli(
            'show dns client servers')['show dns client servers']
        target_idx = None
        for fields in parse_table(srv_out, min_fields=2):
            try:
                idx = int(fields[0])
            except (ValueError, IndexError):
                continue
            if fields[1] == address:
                target_idx = idx
                break
        if target_idx is None:
            raise ValueError(
                f"DNS server '{address}' not found")
        self._config_mode()
        try:
            self.cli(
                f'dns client servers delete {target_idx}')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # PoE (Power over Ethernet)
    # ------------------------------------------------------------------

    _POE_STATUS_MAP = {
        'disabled': 'disabled', 'searching': 'searching',
        'delivering': 'delivering', 'deliveringpower': 'delivering',
        'fault': 'fault', 'test': 'test',
        'otherfault': 'other-fault', 'other-fault': 'other-fault',
    }
    _POE_PRIORITY_REV = {'critical': 'critical', 'high': 'high', 'low': 'low'}

    def get_poe(self):
        """Read PoE configuration via CLI."""
        results = self.cli([
            'show inlinepower global',
            'show inlinepower port',
            'show inlinepower slot',
        ])

        # --- global (dot-key) ---
        info = parse_dot_keys(results['show inlinepower global'])
        enabled = False
        power_w = 0
        delivered_ma = 0
        for k, v in info.items():
            kl = k.lower()
            if 'admin mode' in kl:
                enabled = v.strip().lower() in ('enable', 'enabled')
            elif kl.startswith('reserved system power') or (
                    'reserved' in kl and 'power' in kl
                    and 'delivered' not in kl):
                try:
                    power_w = int(v.strip())
                except ValueError:
                    pass
            elif 'delivered' in kl and 'current' in kl:
                try:
                    delivered_ma = int(v.strip())
                except ValueError:
                    pass

        # --- modules (slot table) ---
        modules = {}
        slot_out = results['show inlinepower slot']
        for fields in parse_table(slot_out, min_fields=5):
            try:
                slot = fields[0]
                int(slot)  # must be numeric
            except (ValueError, IndexError):
                continue
            src_raw = fields[5].strip().lower() if len(fields) > 5 else ''
            modules[f"1/{slot}"] = {
                'budget_w': _safe_int(fields[1]),
                'max_w': _safe_int(fields[2]),
                'reserved_w': _safe_int(fields[3]),
                'delivered_w': _safe_int(fields[4]),
                'source': 'external' if 'ext' in src_raw else 'internal',
                'threshold_pct': _safe_int(
                    fields[7]) if len(fields) > 7 else 90,
                'notifications': (
                    fields[6].strip().lower() in ('enable', 'enabled')
                    if len(fields) > 6 else True),
            }

        # --- ports (multi-line: 3 lines per record) ---
        ports = {}
        port_out = results['show inlinepower port']
        for record in parse_multiline_table(
                port_out, lines_per_record=3, min_fields_first=3):
            line1, line2, line3 = record
            if not line1:
                continue
            iface = line1[0]  # e.g. '1/1'
            poe_en = (line1[1].strip().lower() in ('enable', 'enabled')
                      if len(line1) > 1 else True)

            # line1: Intf  PoE-enable  Class  Status  Allowed-class  Auto-shutdown  Start
            status_raw = (line1[3].strip().lower()
                          if len(line1) > 3 else 'disabled')
            status = self._POE_STATUS_MAP.get(
                status_raw.replace(' ', ''), 'disabled')

            class_raw = line1[2].strip() if len(line1) > 2 else ''
            class_valid = status == 'delivering'
            classification = None
            if class_valid and class_raw:
                try:
                    classification = f"class{int(class_raw)}"
                except ValueError:
                    pass

            # line2: Fast-start  Prio  Consumption[W]  Power-limit[W]  Max-observed[W]  End
            fast_startup = False
            priority = 'low'
            consumption_mw = 0
            power_limit_mw = 0
            port_name = ''
            if line2:
                fast_startup = (line2[0].strip().lower() in (
                    'enable', 'enabled') if line2 else False)
                priority = line2[1].strip().lower() if len(
                    line2) > 1 else 'low'
                if priority not in ('critical', 'high', 'low'):
                    priority = 'low'
                # Consumption is in watts with decimals — convert to mW
                try:
                    consumption_mw = int(
                        float(line2[2].strip()) * 1000
                    ) if len(line2) > 2 else 0
                except (ValueError, IndexError):
                    consumption_mw = 0
                try:
                    power_limit_mw = int(
                        float(line2[3].strip()) * 1000
                    ) if len(line2) > 3 else 0
                except (ValueError, IndexError):
                    power_limit_mw = 0

            ports[iface] = {
                'enabled': poe_en,
                'status': status,
                'priority': priority,
                'classification': classification,
                'consumption_mw': consumption_mw,
                'power_limit_mw': power_limit_mw,
                'name': '',  # SSH port table doesn't show device name
                'fast_startup': fast_startup,
            }

        return {
            'enabled': enabled,
            'power_w': power_w,
            'delivered_current_ma': delivered_ma,
            'modules': modules,
            'ports': ports,
        }

    def set_poe(self, interface=None, enabled=None, priority=None,
                power_limit_mw=None, name=None, fast_startup=None):
        """Set PoE configuration via CLI.

        Note: CLI power-limit is in watts; power_limit_mw is divided
        by 1000 before sending (matching MOPS/SNMP milliwatt API).
        """
        self._config_mode()
        try:
            if interface is not None:
                interfaces = ([interface] if isinstance(interface, str)
                              else list(interface))
                for iface in interfaces:
                    self.cli(f'interface {iface}')
                    if enabled is not None:
                        self.cli(
                            'inlinepower operation enable'
                            if enabled
                            else 'no inlinepower operation')
                    if priority is not None:
                        self.cli(
                            f'inlinepower priority {priority}')
                    if power_limit_mw is not None:
                        watts = int(power_limit_mw) // 1000
                        if watts == 0:
                            self.cli(
                                'inlinepower power-limit 0')
                        else:
                            self.cli(
                                f'inlinepower power-limit '
                                f'{watts}')
                    if name is not None:
                        self.cli(
                            f'inlinepower name "{name}"'
                            if name
                            else 'inlinepower name " "')
                    if fast_startup is not None:
                        self.cli(
                            'inlinepower fast-startup enable'
                            if fast_startup
                            else 'no inlinepower fast-startup')
                    self.cli('exit')  # exit interface context
            else:
                if enabled is not None:
                    self.cli(
                        'inlinepower operation enable'
                        if enabled
                        else 'no inlinepower operation')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # Remote Authentication
    # ------------------------------------------------------------------

    def get_remote_auth(self):
        """Check whether remote authentication services are configured.

        Returns::

            {
                'radius': {'enabled': True},
                'tacacs': {'enabled': False},
                'ldap': {'enabled': False},
            }
        """
        # RADIUS — check if any auth servers are configured
        radius_enabled = False
        try:
            output = self.cli(
                'show radius auth servers')['show radius auth servers']
            # If servers exist, output contains table rows with server data
            for line in output.splitlines():
                line = line.strip()
                # Server lines start with an index number
                if line and line[0].isdigit():
                    radius_enabled = True
                    break
        except Exception:
            pass

        # TACACS+ — only available on 10.3+
        tacacs_enabled = False
        try:
            output = self.cli(
                'show tacacs server')['show tacacs server']
            for line in output.splitlines():
                line = line.strip()
                if line and line[0].isdigit():
                    tacacs_enabled = True
                    break
        except Exception:
            pass

        # LDAP — global admin state
        ldap_enabled = False
        try:
            output = self.cli(
                'show ldap global')['show ldap global']
            for line in output.splitlines():
                lower = line.strip().lower()
                if 'operation' in lower or 'admin' in lower:
                    if 'enable' in lower:
                        ldap_enabled = True
                    break
        except Exception:
            pass

        return {
            'radius': {'enabled': radius_enabled},
            'tacacs': {'enabled': tacacs_enabled},
            'ldap': {'enabled': ldap_enabled},
        }

    # ------------------------------------------------------------------
    # User Management
    # ------------------------------------------------------------------

    _SSH_ROLE_MAP = {
        'administrator': 'administrator',
        'operator': 'operator',
        'guest': 'guest',
        'auditor': 'auditor',
        'unauthorized': 'unauthorized',
        'custom1': 'custom1', 'custom2': 'custom2', 'custom3': 'custom3',
    }

    def get_users(self):
        """Get local user accounts.

        Parses ``show users`` output::

            (SNMPv3-)    (Password-)
            User Name                         Authentication  PolicyCheck  Status
            Access Mode                         Encryption                 Locked
            --------------------------------  --------------  -----------  ------
            admin                             md5             false        [x]
            administrator                     des                          [ ]

        Each user spans two lines: line 1 = name/auth/policy/status,
        line 2 = role/encryption/blank/locked.
        """
        output = self.cli('show users')['show users']
        lines = output.splitlines()

        # Find the separator line (dashes)
        data_start = None
        for i, line in enumerate(lines):
            if line.strip().startswith('---'):
                data_start = i + 1
                break
        if data_start is None:
            return []

        data_lines = lines[data_start:]
        users = []
        i = 0
        while i + 1 < len(data_lines):
            line1 = data_lines[i]
            line2 = data_lines[i + 1]
            if not line1.strip():
                i += 1
                continue

            # Parse using column positions from the header
            # Columns are fixed-width, aligned to header positions
            # Name: 0-33, Auth: 34-49, PolicyCheck: 50-61, Status: 62+
            name = line1[:34].strip()
            auth = line1[34:50].strip().lower()
            policy_str = line1[50:62].strip().lower()
            status_str = line1[62:].strip()

            role = line2[:34].strip().lower()
            enc = line2[34:50].strip().lower()
            # locked is at position 62+
            locked_str = line2[62:].strip()

            if not name:
                i += 2
                continue

            active = status_str == '[x]'
            locked = locked_str == '[x]'
            policy_check = policy_str == 'true'

            # Map auth/enc strings
            if auth in ('md5', 'sha', 'sha1'):
                snmp_auth = 'sha' if auth == 'sha1' else auth
            else:
                snmp_auth = 'md5'
            enc_map = {
                'none': 'none', 'des': 'des',
                'aescfb128': 'aes128', 'aes128': 'aes128',
                'aes256': 'aes256',
            }
            snmp_enc = enc_map.get(enc, 'des')

            # Normalize role
            role_normalized = self._SSH_ROLE_MAP.get(role, role)

            users.append({
                'name': name,
                'role': role_normalized,
                'locked': locked,
                'policy_check': policy_check,
                'snmp_auth': snmp_auth,
                'snmp_enc': snmp_enc,
                'active': active,
                'default_password': False,  # SSH can't detect this
            })
            i += 2

        return users

    def set_user(self, name, password=None, role=None,
                 snmp_auth_type=None, snmp_enc_type=None,
                 snmp_auth_password=None, snmp_enc_password=None,
                 policy_check=None, locked=None):
        """Create or update a local user account via CLI."""
        # Check if user exists by listing current users
        existing_names = {u['name'] for u in self.get_users()}
        is_new = name not in existing_names

        self._config_mode()
        try:
            if is_new:
                if password is None:
                    raise ValueError(
                        "password is required when creating a new user")
                self.cli(f'users add {name}')
                self.cli(f'users password {name} {password}')
                self.cli(f'users enable {name}')
            else:
                if password is not None:
                    self.cli(f'users password {name} {password}')

            if role is not None:
                self.cli(f'users access-role {name} {role}')
            if snmp_auth_type is not None:
                auth_str = 'sha1' if snmp_auth_type == 'sha' else snmp_auth_type
                self.cli(f'users snmpv3 authentication {name} {auth_str}')
            if snmp_enc_type is not None:
                enc_map = {'none': 'none', 'des': 'des',
                           'aes128': 'aescfb128', 'aes256': 'aes256'}
                enc_str = enc_map.get(snmp_enc_type, snmp_enc_type)
                self.cli(f'users snmpv3 encryption {name} {enc_str}')
            if snmp_auth_password is not None:
                self.cli(
                    f'users snmpv3 password authentication '
                    f'{name} {snmp_auth_password}')
            if snmp_enc_password is not None:
                self.cli(
                    f'users snmpv3 password encryption '
                    f'{name} {snmp_enc_password}')
            if policy_check is not None:
                val = 'enable' if policy_check else 'disable'
                self.cli(f'users password-policy-check {name} {val}')
            if locked is not None and not locked:
                self.cli(f'users lock-status {name} unlock')
        finally:
            self._exit_config_mode()

    def delete_user(self, name):
        """Delete a local user account via CLI."""
        self._config_mode()
        try:
            self.cli(f'users delete {name}')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # Port Security
    # ------------------------------------------------------------------

    def _parse_port_security_table(self, output):
        """Parse 'show port-security interface' two-line-per-port table."""
        ports = {}
        lines = output.strip().splitlines()
        # Find the separator line
        data_start = None
        for i, line in enumerate(lines):
            if line.startswith('------'):
                data_start = i + 1
                break
        if data_start is None:
            return ports

        # Process pairs of lines
        i = data_start
        while i + 1 < len(lines):
            line1 = lines[i].strip()
            line2 = lines[i + 1].strip() if i + 1 < len(lines) else ''
            if not line1:
                i += 1
                continue
            parts1 = line1.split()
            parts2 = line2.split()
            if len(parts1) < 6 or not parts1[0].count('/'):
                i += 1
                continue
            name = parts1[0]
            ports[name] = {
                'enabled': parts1[1] == 'enabled',
                'dynamic_limit': int(parts1[2]),
                'static_limit': int(parts1[3]),
                'violation_trap_mode': parts1[4] == 'enabled',
                'violation_trap_frequency': int(parts1[5]),
                'dynamic_count': int(parts2[0]) if len(parts2) > 0 else 0,
                'static_count': int(parts2[1]) if len(parts2) > 1 else 0,
                'static_ip_count': 0,
                'last_discarded_mac': (
                    f"{parts2[3]}" if len(parts2) > 3 else ''),
                'auto_disable': True,  # not in table view
                'static_macs': [],
                'static_ips': [],
            }
            i += 2
        return ports

    def _parse_port_security_detail(self, output):
        """Parse 'show port-security interface X/Y' key-value format."""
        d = {}
        for line in output.strip().splitlines():
            if '...' not in line:
                continue
            key, _, val = line.partition('...')
            key = key.strip().lower()
            val = val.strip('. ')
            d[key] = val

        if not d.get('interface'):
            return {}

        name = d['interface']
        return {
            name: {
                'enabled': d.get('admin mode', 'disabled') == 'enabled',
                'dynamic_limit': int(d.get('dynamic limit', '600')),
                'static_limit': int(d.get('static limit', '64')),
                'auto_disable': d.get('automatic disable',
                                      'enabled') == 'enabled',
                'violation_trap_mode': d.get(
                    'violation trap mode', 'disabled') == 'enabled',
                'violation_trap_frequency': int(
                    d.get('violation trap frequency', '0')),
                'dynamic_count': int(d.get('current dynamic', '0')),
                'static_count': int(d.get('current static', '0')),
                'static_ip_count': 0,
                'last_discarded_mac': d.get(
                    'last violating vlan id/mac', ''),
                'static_macs': [],
                'static_ips': [],
            }
        }

    def get_port_security(self, interface=None):
        """Return port security configuration via CLI."""
        # Global state
        glb_out = self.cli(['show port-security global'])
        glb_text = glb_out.get('show port-security global', '')
        enabled = 'enabled' in glb_text and 'disabled' not in glb_text

        if interface is not None and isinstance(interface, str):
            # Single port — use detailed view
            cmd = f'show port-security interface {interface}'
            out = self.cli([cmd])
            ports = self._parse_port_security_detail(out.get(cmd, ''))
        else:
            # All ports or list — use table view
            cmd = 'show port-security interface'
            out = self.cli([cmd])
            ports = self._parse_port_security_table(out.get(cmd, ''))
            if interface is not None:
                want = set(interface)
                ports = {k: v for k, v in ports.items() if k in want}

        return {
            'enabled': enabled,
            'mode': 'mac-based',  # CLI doesn't show mode in output
            'ports': ports,
        }

    def set_port_security(self, interface=None, enabled=None, mode=None,
                          dynamic_limit=None, static_limit=None,
                          auto_disable=None, violation_trap_mode=None,
                          violation_trap_frequency=None, move_macs=None,
                          **kwargs):
        """Set port security configuration via CLI."""
        self._config_mode()
        try:
            if interface is not None:
                interfaces = ([interface] if isinstance(interface, str)
                              else list(interface))
                for iface in interfaces:
                    self.cli(f'interface {iface}')
                    if enabled is not None:
                        self.cli('port-security operation' if enabled
                                 else 'no port-security operation')
                    if dynamic_limit is not None:
                        self.cli(
                            f'port-security max-dynamic {int(dynamic_limit)}')
                    if static_limit is not None:
                        self.cli(
                            f'port-security max-static {int(static_limit)}')
                    if auto_disable is not None:
                        self.cli('port-security auto-disable' if auto_disable
                                 else 'no port-security auto-disable')
                    if violation_trap_mode is not None:
                        self.cli(
                            'port-security violation-traps operation'
                            if violation_trap_mode
                            else 'no port-security violation-traps operation')
                    if violation_trap_frequency is not None:
                        self.cli(
                            'port-security violation-traps frequency '
                            f'{int(violation_trap_frequency)}')
                    if move_macs:
                        self.cli('port-security mac-address move')
                    self.cli('exit')
            else:
                if enabled is not None:
                    self.cli('port-security operation' if enabled
                             else 'no port-security operation')
                if mode is not None:
                    self.cli(f'port-security mode {mode}')
        finally:
            self._exit_config_mode()

    def add_port_security(self, interface, vlan=None, mac=None, ip=None,
                          entries=None):
        """Add static MAC/IP entries to port security via CLI."""
        if entries is None:
            if mac is not None:
                entries = [{'vlan': vlan, 'mac': mac}]
            elif ip is not None:
                entries = [{'vlan': vlan, 'ip': ip}]
            else:
                raise ValueError("Provide mac=, ip=, or entries=")

        self._config_mode()
        try:
            self.cli(f'interface {interface}')
            for entry in entries:
                v = entry.get('vlan', vlan)
                if 'mac' in entry:
                    self.cli(
                        f"port-security mac-address add {entry['mac']} {v}")
                elif 'ip' in entry:
                    self.cli(
                        f"port-security ip-address add {entry['ip']} {v}")
            self.cli('exit')
        finally:
            self._exit_config_mode()

    def delete_port_security(self, interface, vlan=None, mac=None, ip=None,
                             entries=None):
        """Remove static MAC/IP entries from port security via CLI."""
        if entries is None:
            if mac is not None:
                entries = [{'vlan': vlan, 'mac': mac}]
            elif ip is not None:
                entries = [{'vlan': vlan, 'ip': ip}]
            else:
                raise ValueError("Provide mac=, ip=, or entries=")

        self._config_mode()
        try:
            self.cli(f'interface {interface}')
            for entry in entries:
                v = entry.get('vlan', vlan)
                if 'mac' in entry:
                    self.cli(
                        f"port-security mac-address delete {entry['mac']} {v}")
                elif 'ip' in entry:
                    self.cli(
                        f"port-security ip-address delete {entry['ip']} {v}")
            self.cli('exit')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # DHCP Snooping
    # ------------------------------------------------------------------

    def get_dhcp_snooping(self, interface=None):
        """Return DHCP snooping configuration via CLI."""
        # Global settings
        glb_out = self.cli(
            ['show ip dhcp-snooping global']
        ).get('show ip dhcp-snooping global', '')
        gdata = parse_dot_keys(glb_out)
        enabled = gdata.get('DHCP Snooping Mode',
                            'disabled').strip() == 'enabled'
        verify_mac = gdata.get('Source MAC Verification',
                               'disabled').strip() == 'enabled'

        # VLAN table
        vlan_out = self.cli(
            ['show ip dhcp-snooping vlan']
        ).get('show ip dhcp-snooping vlan', '')
        vlans = {}
        for fields in parse_table(vlan_out, min_fields=2):
            try:
                vid = int(fields[0])
            except (ValueError, IndexError):
                continue
            vlans[vid] = {
                'enabled': fields[1].lower() in ('yes', 'enable',
                                                  'enabled'),
            }

        # Per-interface table
        intf_out = self.cli(
            ['show ip dhcp-snooping interfaces']
        ).get('show ip dhcp-snooping interfaces', '')

        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for fields in parse_table(intf_out, min_fields=6):
            if '/' not in fields[0]:
                continue
            name = fields[0]
            if want is not None and name not in want:
                continue
            # Interface  Trust  Auto-Disable  Log  RateLimit  BurstInterval
            # Values: yes/no or enable/disable
            def _is_on(v):
                return v.lower() in ('yes', 'enable', 'enabled')
            ports[name] = {
                'trusted': _is_on(fields[1]),
                'log': _is_on(fields[3]),
                'rate_limit': int(fields[4]) if fields[4] != '-' else -1,
                'burst_interval': int(fields[5]) if fields[5] != '-' else 1,
                'auto_disable': _is_on(fields[2]),
            }

        return {
            'enabled': enabled,
            'verify_mac': verify_mac,
            'vlans': vlans,
            'ports': ports,
        }

    def set_dhcp_snooping(self, interface=None, enabled=None,
                          verify_mac=None, vlan=None, vlan_enabled=None,
                          trusted=None, log=None, rate_limit=None,
                          burst_interval=None, auto_disable=None,
                          **kwargs):
        """Set DHCP snooping configuration via CLI."""
        self._config_mode()
        try:
            # Global settings
            if enabled is not None:
                self.cli('ip dhcp-snooping mode' if enabled
                         else 'no ip dhcp-snooping mode')
            if verify_mac is not None:
                self.cli('ip dhcp-snooping verify-mac' if verify_mac
                         else 'no ip dhcp-snooping verify-mac')

            # Per-VLAN
            if vlan is not None and vlan_enabled is not None:
                vlans = [vlan] if isinstance(vlan, int) else list(vlan)
                for vid in vlans:
                    self.cli(f'vlan {vid}')
                    self.cli('ip dhcp-snooping' if vlan_enabled
                             else 'no ip dhcp-snooping')
                    self.cli('exit')

            # Per-port
            if interface is not None:
                interfaces = ([interface] if isinstance(interface, str)
                              else list(interface))
                for iface in interfaces:
                    self.cli(f'interface {iface}')
                    if trusted is not None:
                        self.cli('ip dhcp-snooping trust' if trusted
                                 else 'no ip dhcp-snooping trust')
                    if log is not None:
                        self.cli('ip dhcp-snooping log' if log
                                 else 'no ip dhcp-snooping log')
                    if rate_limit is not None:
                        if int(rate_limit) < 0:
                            self.cli('no ip dhcp-snooping limit')
                        else:
                            cmd = f'ip dhcp-snooping limit {int(rate_limit)}'
                            if burst_interval is not None:
                                cmd += f' {int(burst_interval)}'
                            self.cli(cmd)
                    elif burst_interval is not None:
                        # burst_interval alone — need current rate_limit
                        self.cli(
                            f'ip dhcp-snooping limit 15 {int(burst_interval)}')
                    if auto_disable is not None:
                        self.cli('ip dhcp-snooping auto-disable'
                                 if auto_disable
                                 else 'no ip dhcp-snooping auto-disable')
                    self.cli('exit')
        finally:
            self._exit_config_mode()

    # ------------------------------------------------------------------
    # ARP Inspection (DAI)
    # ------------------------------------------------------------------

    def get_arp_inspection(self, interface=None):
        """Return Dynamic ARP Inspection configuration via CLI."""
        # Global settings
        glb_out = self.cli(
            ['show ip arp-inspection global']
        ).get('show ip arp-inspection global', '')
        gdata = parse_dot_keys(glb_out)
        validate_src_mac = gdata.get(
            'Source MAC Verification', 'disabled').strip() == 'enabled'
        validate_dst_mac = gdata.get(
            'Destination MAC Verification', 'disabled').strip() == 'enabled'
        validate_ip = gdata.get(
            'IP Address Verification', 'disabled').strip() == 'enabled'

        # VLAN table
        vlan_out = self.cli(
            ['show ip arp-inspection vlan']
        ).get('show ip arp-inspection vlan', '')
        vlans = {}
        for fields in parse_table(vlan_out, min_fields=5):
            try:
                vid = int(fields[0])
            except (ValueError, IndexError):
                continue
            def _is_on(v):
                return v.lower() in ('yes', 'enable', 'enabled')
            vlans[vid] = {
                'enabled': _is_on(fields[1]),
                'log': _is_on(fields[2]),
                'binding_check': _is_on(fields[3]),
                'acl_static': _is_on(fields[4]),
                'acl_name': fields[5] if len(fields) > 5 else '',
            }

        # Per-interface table
        intf_out = self.cli(
            ['show ip arp-inspection interfaces']
        ).get('show ip arp-inspection interfaces', '')

        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for fields in parse_table(intf_out, min_fields=5):
            if '/' not in fields[0]:
                continue
            name = fields[0]
            if want is not None and name not in want:
                continue
            # Interface  Trust  Auto-Disable  RateLimit  BurstInterval
            def _is_on(v):
                return v.lower() in ('yes', 'enable', 'enabled')
            ports[name] = {
                'trusted': _is_on(fields[1]),
                'rate_limit': int(fields[3]) if fields[3] != '-' else -1,
                'burst_interval': int(fields[4]) if fields[4] != '-' else 1,
                'auto_disable': _is_on(fields[2]),
            }

        return {
            'validate_src_mac': validate_src_mac,
            'validate_dst_mac': validate_dst_mac,
            'validate_ip': validate_ip,
            'vlans': vlans,
            'ports': ports,
        }

    def set_arp_inspection(self, interface=None,
                           validate_src_mac=None, validate_dst_mac=None,
                           validate_ip=None,
                           vlan=None, vlan_enabled=None, vlan_log=None,
                           vlan_binding_check=None,
                           trusted=None, rate_limit=None,
                           burst_interval=None, auto_disable=None,
                           **kwargs):
        """Set Dynamic ARP Inspection configuration via CLI."""
        self._config_mode()
        try:
            # Global validation flags
            if validate_src_mac is not None:
                self.cli('ip arp-inspection verify src-mac'
                         if validate_src_mac
                         else 'no ip arp-inspection verify src-mac')
            if validate_dst_mac is not None:
                self.cli('ip arp-inspection verify dst-mac'
                         if validate_dst_mac
                         else 'no ip arp-inspection verify dst-mac')
            if validate_ip is not None:
                self.cli('ip arp-inspection verify ip'
                         if validate_ip
                         else 'no ip arp-inspection verify ip')

            # Per-VLAN
            if vlan is not None:
                vlans_list = [vlan] if isinstance(vlan, int) else list(vlan)
                for vid in vlans_list:
                    self.cli(f'vlan {vid}')
                    if vlan_enabled is not None:
                        self.cli('ip arp-inspection' if vlan_enabled
                                 else 'no ip arp-inspection')
                    if vlan_log is not None:
                        self.cli(f'ip arp-inspection log {vid}'
                                 if vlan_log
                                 else f'no ip arp-inspection log {vid}')
                    if vlan_binding_check is not None:
                        # binding-check is a global per-VLAN toggle
                        pass  # set via MOPS/SNMP only
                    self.cli('exit')

            # Per-port
            if interface is not None:
                interfaces = ([interface] if isinstance(interface, str)
                              else list(interface))
                for iface in interfaces:
                    self.cli(f'interface {iface}')
                    if trusted is not None:
                        self.cli('ip arp-inspection trust' if trusted
                                 else 'no ip arp-inspection trust')
                    if rate_limit is not None:
                        if int(rate_limit) < 0:
                            self.cli('no ip arp-inspection limit')
                        else:
                            cmd = f'ip arp-inspection limit {int(rate_limit)}'
                            if burst_interval is not None:
                                cmd += f' {int(burst_interval)}'
                            self.cli(cmd)
                    elif burst_interval is not None:
                        self.cli(
                            f'ip arp-inspection limit 15 '
                            f'{int(burst_interval)}')
                    if auto_disable is not None:
                        self.cli('ip arp-inspection auto-disable'
                                 if auto_disable
                                 else 'no ip arp-inspection auto-disable')
                    self.cli('exit')
        finally:
            self._exit_config_mode()

    # -------------------------------------------------------------------
    # IP Source Guard
    # -------------------------------------------------------------------

    def get_ip_source_guard(self, interface=None):
        """Return IP Source Guard configuration and bindings via CLI."""
        # Per-interface table
        intf_out = self.cli(
            ['show ip source-guard interfaces']
        ).get('show ip source-guard interfaces', '')

        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for fields in parse_table(intf_out, min_fields=3):
            if '/' not in fields[0]:
                continue
            name = fields[0]
            if want is not None and name not in want:
                continue
            def _is_on(v):
                return v.lower() in ('yes', 'enable', 'enabled')
            ports[name] = {
                'verify_source': _is_on(fields[1]),
                'port_security': _is_on(fields[2]) if len(fields) > 2
                                 else False,
            }

        # Static bindings
        static_out = self.cli(
            ['show ip source-guard bindings static']
        ).get('show ip source-guard bindings static', '')
        static_bindings = []
        for fields in parse_table(static_out, min_fields=5):
            if '/' not in fields[2]:
                continue
            iface = fields[2]
            if want is not None and iface not in want:
                continue
            static_bindings.append({
                'interface': iface,
                'vlan_id': int(fields[3]) if fields[3].isdigit() else 0,
                'mac_address': fields[0],
                'ip_address': fields[1],
                'active': fields[4].lower() in ('active', 'yes')
                          if len(fields) > 4 else True,
                'hw_status': fields[5].lower() in ('active', 'yes')
                             if len(fields) > 5 else False,
            })

        # Dynamic bindings
        dynamic_out = self.cli(
            ['show ip source-guard bindings dynamic']
        ).get('show ip source-guard bindings dynamic', '')
        dynamic_bindings = []
        for fields in parse_table(dynamic_out, min_fields=4):
            if '/' not in fields[2]:
                continue
            iface = fields[2]
            if want is not None and iface not in want:
                continue
            dynamic_bindings.append({
                'interface': iface,
                'vlan_id': int(fields[3]) if fields[3].isdigit() else 0,
                'mac_address': fields[0],
                'ip_address': fields[1],
                'hw_status': fields[4].lower() in ('active', 'yes')
                             if len(fields) > 4 else False,
            })

        return {
            'ports': ports,
            'static_bindings': static_bindings,
            'dynamic_bindings': dynamic_bindings,
        }

    def set_ip_source_guard(self, interface=None,
                            verify_source=None, port_security=None,
                            **kwargs):
        """Set IP Source Guard configuration via CLI."""
        if interface is None:
            return

        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        self._config_mode()
        try:
            for iface in interfaces:
                self.cli(f'interface {iface}')
                if verify_source is not None:
                    self.cli('ip source-guard mode' if verify_source
                             else 'no ip source-guard mode')
                if port_security is not None and port_security:
                    self.cli('ip source-guard verify-mac')
                self.cli('exit')
        finally:
            self._exit_config_mode()

    def _parse_speed(self, speed_str):
        speed_map = {
            '10': 10,
            '100': 100,
            '1000': 1000,
            '2.5g': 2500,
            '10g': 10000,
            '25g': 25000,
            '40g': 40000,
            '100g': 100000
        }
        speed_str = speed_str.lower()
        if speed_str in speed_map:
            return speed_map[speed_str]
        try:
            if 'g' in speed_str:
                return int(float(speed_str.rstrip('g')) * 1000)
            return int(speed_str)
        except ValueError:
            return 0
