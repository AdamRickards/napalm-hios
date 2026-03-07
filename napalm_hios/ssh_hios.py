from netmiko import ConnectHandler
from napalm.base.exceptions import ConnectionException
from napalm_hios.utils import log_error, parse_dot_keys, parse_table, parse_multiline_table
from typing import List, Dict, Any

import logging
import re
import time

logger = logging.getLogger(__name__)

# Auto-disable reason → category mapping (CLI doesn't show category)
_AD_REASON_CATEGORY = {
    'link-flap': 'port-monitor', 'crc-error': 'port-monitor',
    'duplex-mismatch': 'port-monitor', 'dhcp-snooping': 'network-security',
    'arp-rate': 'network-security', 'bpdu-rate': 'l2-redundancy',
    'port-security': 'network-security', 'overload-detection': 'port-monitor',
    'speed-duplex': 'port-monitor', 'loop-protection': 'l2-redundancy',
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
                port_secondary=None, vlan=None, recovery_delay=None):
        """Configure MRP ring on the default domain.

        Args:
            operation: 'enable' or 'disable'
            mode: 'manager' or 'client'
            port_primary: primary ring port (e.g. '1/3')
            port_secondary: secondary ring port (e.g. '1/4')
            vlan: VLAN ID for MRP domain (0-4042)
            recovery_delay: '200ms', '500ms', '30ms', or '10ms'

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
                output = self.cli(f'interface {iface}')
                resp = output.get(f'interface {iface}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{iface}'")
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
                output = self.cli(f'interface {iface}')
                resp = output.get(f'interface {iface}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{iface}'")
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
                output = self.cli(f'interface {iface}')
                resp = output.get(f'interface {iface}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{iface}'")
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
                    output = self.cli(f'interface {iface}')
                    resp = output.get(f'interface {iface}', '')
                    if 'Error' in resp or 'Invalid' in resp:
                        raise ValueError(f"Unknown interface '{iface}'")
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
                output = self.cli(f'interface {iface}')
                resp = output.get(f'interface {iface}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{iface}'")
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
                self.cli(f'interface {iface}')
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

        # Build interfaces dict
        interfaces = {}
        for port, mode in trust_by_port.items():
            interfaces[port] = {
                'trust_mode': mode,
                'shaping_rate': 0,  # not available via CLI
                'queues': dict(queues),  # same for all ports in CLI
            }

        return {
            'num_queues': len(queues) if queues else 8,
            'interfaces': interfaces,
        }

    def set_qos(self, interface, trust_mode=None, shaping_rate=None,
                queue=None, scheduler=None, min_bw=None, max_bw=None):
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
                    output = self.cli(f'interface {iface}')
                    resp = output.get(f'interface {iface}', '')
                    if 'Error' in resp or 'Invalid' in resp:
                        raise ValueError(f"Unknown interface '{iface}'")
                    self.cli(f'classofservice trust {trust_mode}')
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
                output = self.cli(f'interface {iface}')
                resp = output.get(f'interface {iface}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{iface}'")
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
            if vlan_ports:
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
                output = self.cli(f'interface {p}')
                resp = output.get(f'interface {p}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{p}'")
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
                output = self.cli(f'interface {p}')
                resp = output.get(f'interface {p}', '')
                if 'Error' in resp or 'Invalid' in resp:
                    raise ValueError(f"Unknown interface '{p}'")
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
