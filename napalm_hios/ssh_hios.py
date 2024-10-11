from netmiko import ConnectHandler
from napalm.base.exceptions import ConnectionException
from napalm_hios.utils import log_error
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
            self.connection.disconnect()

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
                    expect_string=r'[>#]',
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
        
        # Parse MTU information into a dictionary
        mtu_dict = {}
        for line in mtu_output.splitlines():
            # Skip headers and empty lines
            if not line.strip() or 'Interface' in line or '---' in line:
                continue
            try:
                interface, mtu = line.split()
                mtu_dict[interface] = int(mtu)
            except (ValueError, IndexError):
                continue
                
        return self.parse_show_port(port_output, mtu_dict)

    def parse_show_port(self, output, mtu_dict=None):
        """Parse the 'show port' command output from HIOS device."""
        interfaces = {}
        lines = [line.strip() for line in output.split('\n') 
                if line.strip() and not line.startswith('!') 
                and not line.startswith('--More--')]
        data_lines = [line for line in lines if not line.startswith('Interface')]
        
        for line in data_lines:
            fields = line.split()
            if len(fields) < 7 or re.match(r'-+', fields[0]):
                continue
            
            interface_name = fields[0]
            admin_mode = fields[2]
            phys_mode = fields[3]
            link_status = fields[6]
            
            speed = 0
            if 'auto' not in phys_mode.lower():
                try:
                    speed = int(phys_mode.split()[0])
                except (ValueError, IndexError):
                    speed = 0
                    
            if speed == 0 and len(fields) > 5 and fields[5] != '-':
                try:
                    speed = int(fields[5].split()[0])
                except (ValueError, IndexError):
                    speed = 0
            
            # Get MTU for this interface from mtu_dict if available, otherwise use default
            mtu = mtu_dict.get(interface_name, 1500) if mtu_dict else 1500
            
            interfaces[interface_name] = {
                "is_up": link_status.lower() == 'up',
                "is_enabled": admin_mode.lower() == 'enabled',
                "description": "",  # Description not available in current command output
                "last_flapped": -1.0,  # Last flapped time not available
                "speed": speed * 1000000,
                "mtu": mtu,
                "mac_address": ""  # MAC address not available in current command output
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
            lines = output.splitlines()
            
            for line in lines:
                line = line.strip()
                if line.startswith("Device hardware description"):
                    facts['model'] = line.split('....')[-1].strip().lstrip(".")
                elif line.startswith("Firmware software release (RAM)"):
                    facts['os_version'] = line.split('....')[-1].split()[0].strip().lstrip(".")
                elif line.startswith("System uptime"):
                    uptime_str = line.split('....')[-1].strip().lstrip(".")
                    facts['uptime'] = self._parse_uptime(uptime_str)
                elif line.startswith("Serial number"):
                    facts['serial_number'] = line.split('....')[-1].strip().lstrip(".")
                elif line.startswith("System Name"):
                    facts['hostname'] = line.split('....')[-1].strip().lstrip(".")
                    facts['fqdn'] = facts['hostname']  # Use hostname as FQDN if no specific FQDN is available

            # Get interface list
            interfaces_output = self.cli('show port')['show port']
            facts['interface_list'] = self._parse_interface_list(interfaces_output)

        except Exception as e:
            log_error(logger, f"Error retrieving system facts via SSH: {str(e)}")

        return facts

    def _parse_interface_list(self, interfaces_output: str) -> List[str]:
        """Parse the interface list from 'show port' output."""
        interfaces = []
        for line in interfaces_output.splitlines():
            if line.strip() and not line.startswith('Interface') and not '----' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        return interfaces

    def get_environment(self):
        """Get device environmental stats."""
        env_data = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {}
        }

        fan_status_output = self.cli(['show fan'])
        temperature_output = self.cli(['show system temperature limits'])
        power_status_output = self.cli(['show system info'])
        cpu_usage_output = self.cli(['show system resources'])

        # Parse fan status
        if 'show fan' in fan_status_output:
            for line in fan_status_output['show fan'].splitlines():
                location, status = line.split(':')
                env_data['fans'][location.strip()] = {
                    'status': True if 'ok' in status.lower() else False
                }
        else:
            env_data['fans'] = {'status': True}

        # Parse temperature
        current_temp, upper_limit, lower_limit = None, None, None
        for line in temperature_output['show system temperature limits'].splitlines():
            line = line.strip()
            if line.startswith("Current temperature"):
                current_temp_str = line.split('...')[-1].strip().replace(' C', '')
                current_temp = float(current_temp_str.lstrip('.'))
            elif line.startswith("Temperature upper limit"):
                upper_limit_str = line.split('...')[-1].strip().replace(' C', '')
                upper_limit = float(upper_limit_str.lstrip('.'))
            elif line.startswith("Temperature lower limit"):
                lower_limit_str = line.split('...')[-1].strip().replace(' C', '')
                lower_limit = float(lower_limit_str.lstrip('.'))

        env_data['temperature'] = {
            'temperature': current_temp if current_temp is not None else 0.0,
            'is_alert': current_temp > upper_limit or current_temp < lower_limit if current_temp is not None else False,
            'is_critical': current_temp > upper_limit or current_temp < lower_limit if current_temp is not None else False
        }

        # Parse power supply
        psu_status = {'P1': False, 'P2': False}
        for line in power_status_output['show system info'].splitlines():
            if 'Power Supply P1, state' in line:
                psu1_state = line.split('..')[-1].strip()
                psu_status['P1'] = True if 'present' in psu1_state.lower() else False
            elif 'Power Supply P2, state' in line:
                psu2_state = line.split('..')[-1].strip()
                psu_status['P2'] = True if 'present' in psu2_state.lower() else False
        env_data['power']['status'] = psu_status['P1'] or psu_status['P2']

        # Parse CPU usage
        for line in cpu_usage_output['show system resources'].splitlines():
            if 'CPU utilization' in line:
                usage_str = line.split('...')[-1].strip().replace('%', '')
                env_data['cpu'] = {
                    'usage': float(usage_str.lstrip('.'))
                }

        # Parse memory usage
        free_ram, allocated_ram = 0, 0
        for line in cpu_usage_output['show system resources'].splitlines():
            if 'Free RAM' in line:
                free_ram_str = line.split('...')[-1].strip().replace(' kBytes', '')
                free_ram = int(free_ram_str.lstrip('.'))
            elif 'Allocated RAM' in line:
                allocated_ram_str = line.split('...')[-1].strip().replace(' kBytes', '')
                allocated_ram = int(allocated_ram_str.lstrip('.'))

        env_data['memory'] = {
            'available_ram': free_ram if free_ram is not None else 0,
            'used_ram': (allocated_ram - free_ram) if allocated_ram is not None and free_ram is not None else 0
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
        """Returns a list of dictionaries with ARP table entries."""
        commands = ['show ip arp', 'show arp']
        arp_entries = []

        for command in commands:
            try:
                arp_output = self.cli(command)[command]
                
                # Check for error messages
                if "Error: Invalid command" in arp_output or "Error: Incomplete command" in arp_output:
                    logger.debug(f"Command '{command}' failed. Trying next command.")
                    continue

                # Parse the output based on the command
                if command == 'show ip arp':
                    arp_entries = self._parse_show_ip_arp(arp_output)
                else:  # 'show arp'
                    arp_entries = self._parse_show_arp(arp_output)

                # If we successfully parsed entries, exit the loop
                if arp_entries:
                    break

            except Exception as e:
                logger.error(f"Error executing '{command}': {str(e)}")
                continue

        return arp_entries

    def _parse_show_ip_arp(self, arp_output: str) -> List[Dict[str, Any]]:
        """Parse the output of 'show ip arp' command."""
        entries = []
        for line in arp_output.splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[0] in ["Intf", "---------"]:
                continue
            entries.append({
                'interface': parts[0],
                'ip': parts[1],
                'mac': parts[5],
                'age': self.convert_age_to_float(f"{parts[2]} {parts[3]} {parts[4]}")
            })
        return entries

    def _parse_show_arp(self, arp_output: str) -> List[Dict[str, Any]]:
        """Parse the output of 'show arp' command."""
        entries = []
        last_interface = last_ip = None
        for line in arp_output.splitlines():
            line = line.strip()
            if line.startswith("Intf") or line.startswith("MAC Address") or line.startswith("-----") or not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                last_interface, last_ip = parts[0], parts[1]
                entries.append({
                    'interface': last_interface,
                    'ip': last_ip,
                    'mac': None,
                    'age': float(parts[2])
                })
            elif len(parts) == 1 and last_ip:
                entries[-1]['mac'] = parts[0]
        return [entry for entry in entries if entry['mac'] is not None]

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
    
    def get_interfaces_ip(self):
        """
        Get IP addresses configured on the interfaces.
        
        Returns a dictionary of dictionaries. The keys of the main dictionary represent
        the name of the interface. Values of the main dictionary are dictionaries with
        IP addresses as keys.
        """
        output = self.cli('show ip interface')['show ip interface']
        interfaces = {}

        for line in output.splitlines():
            if line.startswith('Interface') or '-' in line:
                continue  # Skip header and separator lines
            
            parts = line.split()
            if len(parts) != 3:
                continue  # Skip lines that don't have exactly 3 parts
            
            interface, ip_address, subnet_mask = parts
            
            if ip_address == '0.0.0.0' and subnet_mask == '0.0.0.0':
                continue  # Skip interfaces without IP configuration
            
            # Calculate prefix length from subnet mask
            prefix_length = sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
            
            if interface not in interfaces:
                interfaces[interface] = {'ipv4': {}}
            
            interfaces[interface]['ipv4'][ip_address] = {
                'prefix_length': prefix_length
            }
        
        return interfaces

    def _calculate_prefix_length(self, subnet_mask):
        """Helper method to calculate prefix length from subnet mask."""
        return sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
    
    def get_interfaces_counters(self):
        """
        Get interface counters from device.
        
        Returns a dictionary of dictionaries where the first key is an interface name and the
        inner dictionary contains interface counter statistics.
        """
        output = self.cli('show interface counters')['show interface counters']
        interfaces = {}
        
        # Split output into lines, preserving original structure
        lines = output.split('\n')
        
        # Skip the header lines (first four lines)
        data_lines = lines[4:]
        
        current_interface = None
        
        for line in data_lines:
            parts = line.split()
            if not parts:
                continue
            
            if '/' in parts[0]:  # This is an interface name
                current_interface = parts[0]
                interfaces[current_interface] = {
                    'rx_unicast_packets': 0, 'rx_multicast_packets': 0, 'rx_broadcast_packets': 0,
                    'rx_octets': 0, 'rx_discards': 0, 'rx_errors': 0,
                    'tx_unicast_packets': 0, 'tx_multicast_packets': 0, 'tx_broadcast_packets': 0,
                    'tx_octets': 0, 'tx_discards': 0, 'tx_errors': 0
                }
                
                # Parse RX data
                if len(parts) >= 7:
                    try:
                        interfaces[current_interface].update({
                            'rx_unicast_packets': int(parts[1]),
                            'rx_multicast_packets': int(parts[2]),
                            'rx_broadcast_packets': int(parts[3]),
                            'rx_octets': int(parts[4]),
                            'rx_discards': int(parts[5]),
                            'rx_errors': int(parts[6])
                        })
                    except ValueError:
                        pass  # If conversion fails, we keep the default 0 values
            
            elif current_interface and len(parts) >= 6:
                # This is likely the TX data for the current interface
                try:
                    interfaces[current_interface].update({
                        'tx_unicast_packets': int(parts[0]),
                        'tx_multicast_packets': int(parts[1]),
                        'tx_broadcast_packets': int(parts[2]),
                        'tx_octets': int(parts[3]),
                        'tx_discards': int(parts[4]),
                        'tx_errors': int(parts[5])
                    })
                except ValueError:
                    pass  # If conversion fails, we keep the default 0 values
            
            # We ignore the third line (Rx UnknPro) as it's not used in NAPALM stats
        
        return interfaces
    
    def get_lldp_neighbors(self):
        lldp_neighbors = {}
        
        # Get LLDP remote data
        output = self.cli('show lldp remote-data')['show lldp remote-data']
        
        # Split the output into individual remote data sections
        remote_data_sections = output.split('Remote data,')[1:]
        
        for section in remote_data_sections:
            lines = section.strip().split('\n')
            neighbor = {}
            local_port = None
            
            # Extract local port from the first line
            if lines:
                port_info = lines[0].split('-')[0].strip()
                local_port = port_info.split(',')[-1].strip()  # This will get '1/6' from ' 1/6 - #1'
            
            for line in lines[1:]:  # Skip the first line as we've already processed it
                line = line.strip()
                if '....' in line:
                    key, value = [part.strip() for part in line.split('....', 1)]
                    key = key.lower()
                    value = value.lstrip('.')  # Remove leading dots
                    
                    if key == 'system name':
                        neighbor['hostname'] = value
                    elif key == 'port description':
                        neighbor['port'] = value
            
            if local_port and 'hostname' in neighbor and 'port' in neighbor:
                if local_port not in lldp_neighbors:
                    lldp_neighbors[local_port] = []
                lldp_neighbors[local_port].append(neighbor)
        
        return lldp_neighbors
    
    def get_lldp_neighbors_detail(self, interface: str = '') -> Dict[str, List[Dict[str, Any]]]:
        lldp_neighbors_detail = {}
        
        # Get LLDP remote data
        output = self.cli('show lldp remote-data')['show lldp remote-data']
        
        # Split the output into individual remote data sections
        remote_data_sections = output.split('Remote data,')[1:]
        
        for section in remote_data_sections:
            lines = section.strip().split('\n')
            neighbor = {
                'parent_interface': '',
                'remote_port': '',
                'remote_port_description': '',
                'remote_chassis_id': '',
                'remote_system_name': '',
                'remote_system_description': '',
                'remote_system_capab': [],
                'remote_system_enable_capab': []
            }
            local_port = None
            
            # Extract local port from the first line
            if lines:
                port_info = lines[0].split('-')[0].strip()
                local_port = port_info.split(',')[-1].strip()  # This will get '1/10' from ' 1/10 - #8'
            
            for line in lines[1:]:  # Skip the first line as we've already processed it
                line = line.strip()
                if '....' in line:
                    key, value = [part.strip() for part in line.split('....', 1)]
                    key = key.lower()
                    value = value.lstrip('.')  # Remove leading dots
                    
                    if key == 'system name':
                        neighbor['remote_system_name'] = value
                    elif key == 'port description':
                        neighbor['remote_port_description'] = value
                    elif key == 'system description':
                        neighbor['remote_system_description'] = value
                    elif key == 'chassis id':
                        neighbor['remote_chassis_id'] = value.split('(')[0].strip()  # Get the ID without the subtype
                    elif key == 'port id':
                        neighbor['remote_port'] = value.split('(')[0].strip()  # Get the ID without the subtype
                    elif key == 'autoneg. cap. bits':
                        if '(' in value:
                            caps = value.split('(')[1].split(')')[0].split(',')
                            neighbor['remote_system_capab'] = [self._map_capability(cap.strip()) for cap in caps if self._map_capability(cap.strip()) != 'other']
                            neighbor['remote_system_enable_capab'] = neighbor['remote_system_capab'].copy()
                        if not neighbor['remote_system_capab']:
                            neighbor['remote_system_capab'] = []
                            neighbor['remote_system_enable_capab'] = []
            
            if local_port:
                neighbor['parent_interface'] = local_port
                if local_port not in lldp_neighbors_detail:
                    lldp_neighbors_detail[local_port] = []
                lldp_neighbors_detail[local_port].append(neighbor)
        
        # If an interface is specified, filter the results
        if interface:
            return {interface: lldp_neighbors_detail.get(interface, [])}
        
        return lldp_neighbors_detail
    
    def get_lldp_neighbors_detail_extended(self, interface: str = '') -> Dict[str, List[Dict[str, Any]]]:
        extended_lldp_details = {}
        print("test")
        output = self.cli('show lldp remote-data')['show lldp remote-data']
        remote_data_sections = output.split('Remote data,')[1:]
        
        for section in remote_data_sections:
            lines = section.strip().split('\n')
            neighbor = {
                'parent_interface': '',
                'remote_port': '',
                'remote_port_description': '',
                'remote_chassis_id': '',
                'remote_system_name': '',
                'remote_system_description': '',
                'remote_system_capab': [],
                'remote_system_enable_capab': [],
                'remote_management_ipv4': '',
                'remote_management_ipv6': '',
                'autoneg_support': '',
                'autoneg_enabled': '',
                'port_oper_mau_type': '',
                'port_vlan_id': '',
                'vlan_membership': [],
                'link_agg_status': '',
                'link_agg_port_id': ''
            }
            local_port = None
            
            if lines:
                port_info = lines[0].split('-')[0].strip()
                local_port = port_info.split(',')[-1].strip()
            print("lines")
            print(lines)
            for line in lines[1:]:
                line = line.strip()
                if '....' in line:
                    key, value = [part.strip() for part in line.split('....', 1)]
                    key = key.lower()
                    value = value.lstrip('.')
                    print("test output")
                    print(key)
                    print(value)
                    if key == 'ipv4 management address':
                        neighbor['remote_management_ipv4'] = value
                    elif key == 'ipv6 management address':
                        neighbor['remote_management_ipv6'] = value
                    elif key == 'system name':
                        neighbor['remote_system_name'] = value
                    elif key == 'port description':
                        neighbor['remote_port_description'] = value
                    elif key == 'system description':
                        neighbor['remote_system_description'] = value
                    elif key == 'chassis id':
                        neighbor['remote_chassis_id'] = value.split('(')[0].strip()
                    elif key == 'port id':
                        neighbor['remote_port'] = value.split('(')[0].strip()
                    elif key == 'autoneg. supp./enabled':
                        supp, enabled = value.split('/')
                        neighbor['autoneg_support'] = supp.strip()
                        neighbor['autoneg_enabled'] = enabled.strip()
                    elif key == 'autoneg. cap. bits':
                        if '(' in value:
                            caps = value.split('(')[1].split(')')[0].split(',')
                            neighbor['remote_system_capab'] = [self._map_capability(cap.strip()) for cap in caps if self._map_capability(cap.strip()) != 'other']
                            neighbor['remote_system_enable_capab'] = neighbor['remote_system_capab'].copy()
                        if not neighbor['remote_system_capab']:
                            neighbor['remote_system_capab'] = []
                            neighbor['remote_system_enable_capab'] = []
                    elif key == 'port oper. mau type':
                        neighbor['port_oper_mau_type'] = value.split('(')[-1].strip(')')
                    elif key == 'port vlan id':
                        neighbor['port_vlan_id'] = value
                    elif key == 'vlan membership':
                        neighbor['vlan_membership'] = self._parse_vlan_membership(value)
                    elif key == 'link agg. status':
                        neighbor['link_agg_status'] = value
                    elif key == 'link agg. port id':
                        neighbor['link_agg_port_id'] = value
            
            if local_port:
                neighbor['parent_interface'] = local_port
                if local_port not in extended_lldp_details:
                    extended_lldp_details[local_port] = []
                extended_lldp_details[local_port].append(neighbor)
        
        if interface:
            return {interface: extended_lldp_details.get(interface, [])}
        
        return extended_lldp_details

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
        """
        Returns a list of dictionaries. Each dictionary represents an entry in the MAC Address Table,
        having the following keys:
        * mac (string)
        * interface (string)
        * vlan (int)
        * active (boolean)
        * static (boolean)
        * moves (int or None)
        * last_move (float or None)
        """
        mac_address_table = []
        
        # Get MAC address table data
        output = self.cli('show mac-addr-table')['show mac-addr-table']
        
        # Split the output into lines and remove the header
        lines = output.strip().split('\n')[2:]  # Skip the first two lines (header)
        
        for line in lines:
            # Split the line into fields
            fields = line.split()
            if len(fields) >= 5:
                vlan, mac, interface, ifindex, status = fields[:5]
                
                # Create a dictionary for this entry
                entry = {
                    'mac': mac,
                    'interface': interface,
                    'vlan': int(vlan),
                    'static': status.lower() != 'learned',  # True for any status except 'learned'
                    'active': True,  # Assuming all entries in the table are active
                    'moves': None,  # HIOS doesn't provide this information
                    'last_move': None  # HIOS doesn't provide this information
                }
                
                mac_address_table.append(entry)
        
        return mac_address_table
    

    def _parse_ntp_server_info(self, server_output, status_output):
        """
        Helper function to parse NTP server information.
        Returns a list of dictionaries containing server info, strictly adhering to NAPALM fields.
        """
        servers = []
        server_lines = server_output.strip().split('\n')
        status_lines = status_output.strip().split('\n')
        
        # Parse SNTP client status
        hostpoll = 0
        global_synchronized = False
        for line in status_lines:
            if 'Request-interval [s]' in line:
                hostpoll = int(line.split('.')[-1].strip())
            elif 'Status' in line:
                global_synchronized = 'synchronized to remote server' in line.lower()

        # Skip header lines in server output
        data_lines = server_lines[3:]  # Start from the 4th line (index 3)
        
        for i in range(0, len(data_lines), 2):
            if i + 1 < len(data_lines):
                server_line = data_lines[i]
                status_line = data_lines[i + 1]
                
                server_fields = server_line.split()
                
                if len(server_fields) >= 4 and server_fields[0].isdigit():
                    server = {
                        'remote': server_fields[3],
                        'referenceid': '',
                        'synchronized': global_synchronized and 'success' in status_line.lower(),
                        'stratum': 0,
                        'type': server_fields[1],
                        'when': '',
                        'hostpoll': hostpoll,
                        'reachability': 0,
                        'delay': 0.0,
                        'offset': 0.0,
                        'jitter': 0.0
                    }
                    servers.append(server)

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
        """
        Fetches the power usage on the various transceivers installed on the switch.
        """
        sfp_output = self.cli('show sfp')['show sfp']
        optics_dict = {}

        lines = sfp_output.strip().split('\n')
        
        # Remove the header lines
        data_lines = [line for line in lines if not line.startswith('Part ID') and not line.startswith('Intf') and not line.startswith('----')]

        for i in range(0, len(data_lines), 2):  # Process two lines at a time
            if i + 1 < len(data_lines):
                line1 = data_lines[i].split()
                line2 = data_lines[i+1].split()

                if len(line1) >= 6:
                    intf_name = line1[0]
                    try:
                        # Find the index of 'SFP' to locate the correct positions for TX and RX power
                        sfp_index = line1.index('SFP')
                        tx_power = float(line1[sfp_index + 2])
                        rx_power = float(line1[sfp_index + 4])
                    except (ValueError, IndexError):
                        # If conversion fails or index is out of range, skip this entry
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
        """
        Returns a dictionary with the configured users.
        """
        users_output = self.cli('show users')['show users']
        users_dict = {}

        lines = users_output.strip().split('\n')
        
        # Remove header lines and empty lines
        data_lines = [line.strip() for line in lines if line.strip() and not line.startswith('User Name') and not line.startswith('----') and not line.startswith('(SNMPv3-')]

        # Remove the 'Access Mode' line if it's present
        if data_lines and data_lines[0].startswith('Access Mode'):
            data_lines.pop(0)

        for i in range(0, len(data_lines), 2):
            if i + 1 < len(data_lines):
                user_line = data_lines[i]
                access_line = data_lines[i+1]

                user_parts = user_line.split()
                access_parts = access_line.split()

                if len(user_parts) >= 1 and len(access_parts) >= 1:
                    username = user_parts[0]
                    access_mode = access_parts[0].lower()

                    # Determine level based on access mode
                    if access_mode == 'administrator':
                        level = 15
                    elif access_mode == 'guest':
                        level = 1
                    else:
                        level = 0  # Default level for unknown access modes

                    users_dict[username] = {
                        'level': level,
                        'password': '',  # Empty string as per requirement
                        'sshkeys': []    # Empty list as per requirement
                    }

        return users_dict
    
    def get_vlans(self):
        """
        Return a dictionary of VLANs with their names and assigned interfaces.
        """
        vlan_brief_output = self.cli('show vlan brief')['show vlan brief']
        vlan_port_output = self.cli('show vlan port')['show vlan port']
        
        vlans_dict = {}

        # Parse VLAN names from 'show vlan brief'
        vlan_brief_lines = vlan_brief_output.split('\n')
        start_parsing = False
        for line in vlan_brief_lines:
            if 'VLAN ID VLAN Name' in line:
                start_parsing = True
                continue
            if start_parsing and line.strip() and not line.startswith('------'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        vlan_id = int(parts[0])
                        vlan_name = parts[1]
                        vlans_dict[vlan_id] = {
                            "name": vlan_name,
                            "interfaces": []
                        }
                    except ValueError:
                        # Skip lines that can't be parsed as expected
                        continue

        # Parse interface assignments from 'show vlan port'
        vlan_port_lines = vlan_port_output.split('\n')
        start_parsing = False
        for line in vlan_port_lines:
            if 'Interface VLAN ID' in line:
                start_parsing = True
                continue
            if start_parsing and line.strip() and not line.startswith('-----'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        interface = parts[0]
                        vlan_id = int(parts[1])
                        if vlan_id in vlans_dict:
                            vlans_dict[vlan_id]["interfaces"].append(interface)
                    except ValueError:
                        # Skip lines that can't be parsed as expected
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
        snmp_info = {
            'chassis_id': '',
            'contact': '',
            'location': '',
            'community': {}
        }

        try:
            output = self.cli("show snmp")['show snmp']
            lines = output.splitlines()
            
            for line in lines:
                if 'System ID' in line:
                    snmp_info['chassis_id'] = line.split(':')[-1].strip()
                elif 'System Contact' in line:
                    snmp_info['contact'] = line.split(':')[-1].strip()
                elif 'System Location' in line:
                    snmp_info['location'] = line.split(':')[-1].strip()
                elif 'Community' in line and 'Status' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        community = parts[1]
                        access = 'ro' if 'readOnly' in line else 'rw'
                        snmp_info['community'][community] = access

        except Exception as e:
            log_error(logger, f"Error retrieving SNMP information: {str(e)}")

        return snmp_info

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
