from netmiko import ConnectHandler
from napalm.base.exceptions import ConnectionException
from napalm_hios.utils import log_error, parse_dot_keys, parse_table, parse_multiline_table
from typing import List, Dict, Any

import logging
import re
import time

logger = logging.getLogger(__name__)

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

        output = self._send_command(f'show config profiles {storage}')
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
