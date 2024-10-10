from napalm.base.exceptions import ConnectionException
from typing import Dict, List, Any

class MockHIOSDevice:
    def __init__(self, optional_args=None):
        self.facts = {
            'uptime': 1036800,
            'vendor': 'Belden',
            'model': 'GRS1042-6T6ZTHH00V9HHSE3AMR',
            'hostname': 'GRS1042-CORE',
            'fqdn': 'GRS1042-CORE',
            'os_version': 'HiOS-3A-09.4.04',
            'serial_number': '942135999000101022',
            'interface_list': ['1/1', '1/2', '1/3', '1/4', '1/5', '1/6', '1/7', '1/8', '1/9', '1/10', '1/11', '1/12',
                               '2/1', '2/2', '2/3', '2/4', '2/5', '2/6', '2/7', '2/8',
                               '3/1', '3/2', '3/3', '3/4', '3/5', '3/6', '3/7', '3/8',
                               'vlan/1', 'vlan/2', 'vlan/3', 'vlan/6', 'vlan/9']
        }
        self.optional_args = optional_args or {}
        self.active_protocol = None

    def open(self):
        protocol_preference = self.optional_args.get('protocol_preference', ['ssh', 'snmp', 'netconf'])
        for protocol in protocol_preference:
            if self._try_connect(protocol):
                self.active_protocol = protocol
                return
        raise ConnectionException("Failed to connect using any protocol")

    def _try_connect(self, protocol):
        # In a real device, this would attempt to connect.
        # For our mock, we'll just return True for 'ssh' and False for others.
        return protocol == 'ssh'

    def _check_protocol(self):
        if self.active_protocol != 'ssh':
            raise NotImplementedError(f"{self.active_protocol} protocol is not supported for this operation")

    def get_facts(self):
        self._check_protocol()
        return self.facts

    def get_interfaces(self):
        self._check_protocol()
        return {
            '1/1': {
                'is_up': False,
                'is_enabled': True,
                'description': '',
                'last_flapped': -1.0,
                'speed': 2500000000,
                'mtu': 1518,
                'mac_address': ''
            },
            '1/2': {
                'is_up': False,
                'is_enabled': True,
                'description': '',
                'last_flapped': -1.0,
                'speed': 2500000000,
                'mtu': 1518,
                'mac_address': ''
            },
            # ... (add more interfaces as needed)
        }

    def get_environment(self):
        self._check_protocol()
        return {
            'fans': {
                'Error': {
                    'status': False
                }
            },
            'temperature': {
                'temperature': 47.0,
                'is_alert': False,
                'is_critical': False
            },
            'power': {
                'status': True
            },
            'cpu': {
                'usage': 23.0
            },
            'memory': {
                'available_ram': 150592,
                'used_ram': 206328
            }
        }

    def get_arp_table(self, vrf=""):
        self._check_protocol()
        return [
            {
                'interface': 'cpu/1',
                'ip': '0.0.0.0',
                'mac': 'ec:74:ba:35:75:70',
                'age': 0.0
            }
        ]

    def get_interfaces_counters(self):
        self._check_protocol()
        return {
            '1/1': {
                'rx_unicast_packets': 1358611135,
                'rx_multicast_packets': 629480,
                'rx_broadcast_packets': 26574,
                'rx_octets': 242339760,
                'rx_discards': 2501,
                'rx_errors': 0,
                'tx_unicast_packets': 1008406913,
                'tx_multicast_packets': 541987,
                'tx_broadcast_packets': 498466,
                'tx_octets': 1579498827,
                'tx_discards': 0,
                'tx_errors': 0
            },
            # ... (add more interfaces as needed)
        }

    def get_interfaces_ip(self):
        self._check_protocol()
        return {
            'vlan/1': {
                'ipv4': {
                    '192.168.1.254': {
                        'prefix_length': 24
                    }
                }
            },
            'vlan/2': {
                'ipv4': {
                    '192.168.10.254': {
                        'prefix_length': 24
                    }
                }
            },
            # ... (add more VLANs as needed)
        }

    def get_lldp_neighbors(self):
        self._check_protocol()
        return {
            '1/7': [
                {
                    'hostname': 'BRS50-LOUNGE',
                    'port': 'Module: 1 Port: 5 - 1 Gbit'
                }
            ],
            '3/3': [
                {
                    'hostname': 'eero',
                    'port': 'eth1'
                }
            ],
            '1/1': [
                {
                    'hostname': 'BRS50-Office',
                    'port': 'Module: 1 Port: 1 - 2.5 Gbit'
                }
            ]
        }

    def get_lldp_neighbors_detail(self, interface=""):
        self._check_protocol()
        neighbors = {
            '1/1': [
                {
                    'parent_interface': '',
                    'remote_port': '64:60:38:3F:4A:A6',
                    'remote_port_description': 'Module: 1 Port: 1 - 2.5 Gbit',
                    'remote_chassis_id': '64:60:38:3F:4A:A1',
                    'remote_system_name': 'BRS50-Office',
                    'remote_system_description': 'Hirschmann BOBCAT - SW: HiOS-2A-10.0.00',
                    'remote_system_capab': [],
                    'remote_system_enable_capab': []
                }
            ],
            # ... (add more interfaces as needed)
        }
        if interface:
            return {interface: neighbors.get(interface, [])}
        return neighbors

    def get_mac_address_table(self):
        self._check_protocol()
        return [
            {
                'mac': '12:dd:6e:60:34:4b',
                'interface': '1/7',
                'vlan': 1,
                'static': False,
                'active': True,
                'moves': None,
                'last_move': None
            },
            # ... (add more entries as needed)
        ]

    def get_ntp_servers(self):
        self._check_protocol()
        return {
            '192.168.3.1': {}
        }

    def get_ntp_stats(self):
        self._check_protocol()
        return [
            {
                'remote': '192.168.3.1',
                'referenceid': '',
                'synchronized': True,
                'stratum': 0,
                'type': 'ipv4',
                'when': '',
                'hostpoll': 30,
                'reachability': 0,
                'delay': 0.0,
                'offset': 0.0,
                'jitter': 0.0
            }
        ]

    def get_optics(self):
        self._check_protocol()
        return {
            '1/1': {
                'physical_channels': {
                    'channel': [
                        {
                            'index': 0,
                            'state': {
                                'input_power': {
                                    'instant': -4.4,
                                    'avg': 0.0,
                                    'min': 0.0,
                                    'max': 0.0
                                },
                                'output_power': {
                                    'instant': -4.2,
                                    'avg': 0.0,
                                    'min': 0.0,
                                    'max': 0.0
                                },
                                'laser_bias_current': {
                                    'instant': 0.0,
                                    'avg': 0.0,
                                    'min': 0.0,
                                    'max': 0.0
                                }
                            }
                        }
                    ]
                }
            }
        }

    def get_users(self):
        self._check_protocol()
        return {
            'admin': {
                'level': 15,
                'password': '',
                'sshkeys': []
            },
            'snmpuser': {
                'level': 1,
                'password': '',
                'sshkeys': []
            },
            'user': {
                'level': 1,
                'password': '',
                'sshkeys': []
            }
        }

    def get_vlans(self):
        self._check_protocol()
        return {
            1: {
                'name': 'HOME',
                'interfaces': [
                    '1/1', '1/2', '1/6', '1/7', '1/8', '1/9', '1/10',
                    '3/2', '3/3', '3/4', '3/5', '3/6', '3/7', '3/8'
                ]
            },
            2: {
                'name': 'WLAN',
                'interfaces': ['2/1', '2/2', '2/3', '2/4', '2/5', '2/6', '2/7', '2/8']
            },
            # ... (add more VLANs as needed)
        }

    def ping(self, destination, source='', ttl=255, timeout=2, size=100, count=5, vrf='', source_interface=''):
        self._check_protocol()
        return {
            'success': {
                'probes_sent': 3,
                'packet_loss': 0.0,
                'rtt_min': 0.741,
                'rtt_max': 0.923,
                'rtt_avg': 0.804,
                'rtt_stddev': 0.0,
                'results': [
                    {
                        'ip_address': '192.168.3.1',
                        'rtt': 0.75
                    }
                ]
            }
        }

    def get_config(self, retrieve='all', full=False, sanitized=False, format='text'):
        self._check_protocol()
        return {
            'running': '! GRS1042-6T6Z Configuration\n\n! Version: HiOS-3A-09.4.04\n\n! Build Date: 2024-06-19 12:08\n\n...',
            'startup': '',
            'candidate': ''
        }

    def get_snmp_information(self):
        self._check_protocol()
        return {
            'chassis_id': 'SSH-CHASSIS-ID',
            'contact': 'admin@example.com',
            'location': 'SSH Lab',
            'community': {
                'public': 'read-only',
                'private': 'read-write'
            }
        }

    def cli(self, commands, encoding='text'):
        self._check_protocol()
        # This method would need to be implemented to handle specific CLI commands
        # For now, we'll just return a placeholder response
        return {
            'show vlan brief': 'VLAN Brief output...',
            'show telnet': 'Telnet server information...'
        }