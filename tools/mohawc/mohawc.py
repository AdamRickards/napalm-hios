"""
MOHAWC — Management, Onboarding, HiDiscovery, And Wipe Configuration

Unified CLI tool for common HiOS switch commissioning tasks:
onboarding factory-fresh devices, controlling HiDiscovery, saving
configs, and resetting to defaults.

Usage:
    python mohawc.py -d 192.168.1.4 -i               # interactive mode
    python mohawc.py status
    python mohawc.py -d 192.168.1.4 status
    python mohawc.py onboard --new-password NewPass1 --save
    python mohawc.py hidiscovery --off --save
    python mohawc.py save
    python mohawc.py reset --yes
    python mohawc.py reset --factory --erase-all --yes
    python mohawc.py profiles
    python mohawc.py activate --index 2
    python mohawc.py activate --name rollback
    python mohawc.py delete --index 3
    python mohawc.py download --profile CLAMPS -o config.xml
"""

import sys
import os
import logging
import ipaddress
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), relative_path)
    return os.path.abspath(relative_path)


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def display_name(ip_or_path):
    """Short display name for device identifier (basename for XML paths)."""
    if ip_or_path.endswith('.xml'):
        return os.path.basename(ip_or_path)
    return ip_or_path


def format_uptime(seconds):
    """Format uptime seconds into human-readable string."""
    if not seconds or seconds < 0:
        return ''
    days = int(seconds) // 86400
    hours = (int(seconds) % 86400) // 3600
    mins = (int(seconds) % 3600) // 60
    if days > 0:
        return f'{days}d {hours}h'
    if hours > 0:
        return f'{hours}h {mins}m'
    return f'{mins}m'


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='MOHAWC — Management, Onboarding, HiDiscovery, And Wipe Configuration'
    )

    # Global args
    parser.add_argument('-c', default='script.cfg',
                        help='config file (default: script.cfg)')
    parser.add_argument('-d', metavar='IP',
                        help='single device IP — no config file needed')
    parser.add_argument('-u', metavar='USER', default=None,
                        help='username override (default: admin)')
    parser.add_argument('-p', metavar='PASS', default=None,
                        help='password override (default: private)')
    parser.add_argument('--protocol', default=None,
                        choices=['mops', 'snmp', 'ssh', 'offline'],
                        help='protocol (default: mops)')
    parser.add_argument('-b', action='store_true',
                        help='toggle HiDiscovery blink (read current, invert)')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='interactive guided mode')
    parser.add_argument('-s', '--silent', action='store_true',
                        help='suppress console output (log file + exit codes only)')
    parser.add_argument('--debug', action='store_true',
                        help='verbose logging')
    parser.add_argument('--dry-run', action='store_true',
                        help='show plan, don\'t connect')

    subparsers = parser.add_subparsers(dest='command')

    # status (default)
    subparsers.add_parser('status', help='show device status (default)')

    # onboard
    p_onboard = subparsers.add_parser('onboard', help='onboard factory-default devices')
    p_onboard.add_argument('--new-password', required=True,
                           help='new password for onboarded device')
    p_onboard.add_argument('--save', action='store_true',
                           help='save config to NVM after onboarding')

    # hidiscovery
    p_hidisc = subparsers.add_parser('hidiscovery', help='control HiDiscovery protocol')
    mode_group = p_hidisc.add_mutually_exclusive_group()
    mode_group.add_argument('--on', action='store_true', help='enable HiDiscovery (read-write)')
    mode_group.add_argument('--off', action='store_true', help='disable HiDiscovery')
    mode_group.add_argument('--ro', action='store_true', help='set HiDiscovery read-only')
    blink_group = p_hidisc.add_mutually_exclusive_group()
    blink_group.add_argument('--blink', action='store_true', help='enable blinking')
    blink_group.add_argument('--no-blink', action='store_true', help='disable blinking')
    p_hidisc.add_argument('--save', action='store_true',
                          help='save config to NVM after change')

    # save
    subparsers.add_parser('save', help='save running config to NVM')

    # reset
    p_reset = subparsers.add_parser('reset', help='reset device configuration')
    p_reset.add_argument('--keep-ip', action='store_true',
                         help='preserve management IP (soft reset only)')
    p_reset.add_argument('--factory', action='store_true',
                         help='full factory reset (clear_factory)')
    p_reset.add_argument('--erase-all', action='store_true',
                         help='wipe NVM completely (requires --factory)')
    p_reset.add_argument('--yes', action='store_true',
                         help='skip confirmation prompt')
    p_reset.add_argument('--entry', metavar='IP',
                         help='your entry switch — resets furthest-first using LLDP topology')

    # diff
    subparsers.add_parser('diff', help='show unsaved config changes (MOPS-only)')

    # save-rollback
    p_sr = subparsers.add_parser('save-rollback',
                                  help='save with rollback profile (MOPS-only)')
    p_sr.add_argument('--name', default='rollback',
                       help='rollback profile name (default: "rollback")')
    p_sr.add_argument('--yes', action='store_true',
                       help='skip confirmation prompt')

    # profiles
    subparsers.add_parser('profiles', help='list config profiles')

    # activate
    p_act = subparsers.add_parser('activate', help='activate a config profile (warm restart)')
    p_act.add_argument('--index', type=int, help='profile index')
    p_act.add_argument('--name', help='profile name')
    p_act.add_argument('--yes', action='store_true',
                        help='skip confirmation prompt')

    # delete (profile)
    p_del = subparsers.add_parser('delete', help='delete a config profile')
    p_del.add_argument('--index', type=int, help='profile index')
    p_del.add_argument('--name', help='profile name')
    p_del.add_argument('--yes', action='store_true',
                        help='skip confirmation prompt')

    # download
    p_dl = subparsers.add_parser('download',
                                  help='download config XML from device')
    p_dl.add_argument('--profile', default=None,
                       help='profile name (default: active profile)')
    p_dl.add_argument('-o', '--output', default=None,
                       help='output file (default: stdout)')

    # interactive (subcommand alias for -i)
    subparsers.add_parser('interactive', help='interactive guided mode')

    return parser.parse_args()


def parse_config(config_file: str) -> dict:
    """Parse script.cfg into settings and device list."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found")

    config = {
        'username': 'admin',
        'password': 'private',
        'protocol': 'mops',
        'devices': [],
    }

    with open(config_file, 'r') as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            # Key = value pairs
            if '=' in line:
                key, _, val = line.partition('=')
                key = key.strip().lower()
                val = val.strip()

                if key == 'username':
                    config['username'] = val
                elif key == 'password':
                    config['password'] = val
                elif key == 'protocol':
                    config['protocol'] = val.lower()
                else:
                    logging.warning(f"Line {line_num}: unknown setting '{key}'")
                continue

            # Device lines — bare IP or .xml path
            ip = line.split()[0]
            if ip.endswith('.xml'):
                # Offline config file — resolve relative paths, auto-set protocol
                if not os.path.isabs(ip):
                    ip = os.path.join(os.path.dirname(os.path.abspath(config_file)), ip)
                if not config.get('_offline_detected'):
                    config['protocol'] = 'offline'
                    config['_offline_detected'] = True
                config['devices'].append(ip)
            elif is_valid_ipv4(ip):
                config['devices'].append(ip)
            else:
                logging.warning(f"Line {line_num}: skipping invalid IP '{ip}'")

    return config


def resolve_config(args) -> dict:
    """Build final config from config file + CLI overrides + -d mode."""
    if args.d:
        # Single-device mode — no config file needed
        is_xml = args.d.endswith('.xml')
        config = {
            'username': args.u or 'admin',
            'password': args.p or 'private',
            'protocol': args.protocol or ('offline' if is_xml else 'mops'),
            'devices': [args.d],
        }
    else:
        config_path = get_resource_path(args.c)
        config = parse_config(config_path)
        # CLI overrides
        if args.u:
            config['username'] = args.u
        if args.p:
            config['password'] = args.p
        if args.protocol:
            config['protocol'] = args.protocol

    if not config['devices']:
        raise ValueError("No devices specified — use -d <ip> or add IPs to config file")

    return config


# ---------------------------------------------------------------------------
# Per-device worker functions (run in threads)
# ---------------------------------------------------------------------------

def worker_connect(driver, config, ip, timeout=30):
    """Thread worker: open connection to one device, return (ip, device, error)."""
    is_offline = config['protocol'] == 'offline'
    try:
        device = driver(
            hostname=ip,
            username=config['username'] if not is_offline else '',
            password=config['password'] if not is_offline else '',
            timeout=timeout,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()
        return ip, device, None
    except Exception as e:
        return ip, None, str(e)


def worker_status(device, ip, protocol):
    """Gather status data from one device."""
    try:
        facts = device.get_facts()
        factory = device.is_factory_default()
        config_status = device.get_config_status()
        hidiscovery = device.get_hidiscovery()
        return ip, {
            'facts': facts,
            'factory': factory,
            'config_status': config_status,
            'hidiscovery': hidiscovery,
            'protocol': protocol,
        }, None
    except Exception as e:
        return ip, None, str(e)


def worker_onboard(device, ip, new_password, save):
    """Onboard one device: check factory default, onboard, optionally save."""
    try:
        factory = device.is_factory_default()
        if not factory:
            return ip, 'SKIP', 'not factory-default'

        device.onboard(new_password)
        msg = 'onboarded'

        if save:
            device.save_config()
            msg += ', saved'

        return ip, 'OK', msg
    except Exception as e:
        return ip, 'FAIL', str(e)


def worker_hidiscovery(device, ip, status, blinking, save):
    """Set HiDiscovery on one device, return before/after state."""
    try:
        before = device.get_hidiscovery()

        # If no mode specified, preserve current status (only changing blink)
        effective_status = status if status else _hidiscovery_status_str(before)
        device.set_hidiscovery(effective_status, blinking=blinking)

        if save:
            device.save_config()

        after = device.get_hidiscovery()
        return ip, 'OK', {'before': before, 'after': after}
    except Exception as e:
        return ip, 'FAIL', str(e)


def _hidiscovery_status_str(hd):
    """Convert get_hidiscovery() dict to set_hidiscovery() status string."""
    if not hd.get('enabled', False):
        return 'off'
    return 'ro' if hd.get('mode') == 'read-only' else 'on'


def worker_blink_toggle(device, ip):
    """Read HiDiscovery blink, invert it."""
    try:
        before = device.get_hidiscovery()
        current_blink = before.get('blinking', False)
        new_blink = not current_blink
        current_status = _hidiscovery_status_str(before)
        device.set_hidiscovery(current_status, blinking=new_blink)
        after = device.get_hidiscovery()
        return ip, 'OK', {'before': before, 'after': after}
    except Exception as e:
        return ip, 'FAIL', str(e)


def worker_save(device, ip):
    """Save config on one device. No exception = success."""
    try:
        device.save_config()
        return ip, 'OK', 'saved'
    except Exception as e:
        return ip, 'FAIL', str(e)


def worker_reset(device, ip, factory, keep_ip, erase_all):
    """Reset one device. Connection drop is expected success."""
    try:
        if factory:
            device.clear_factory(erase_all=erase_all)
        else:
            device.clear_config(keep_ip=keep_ip)
        return ip, 'OK', 'reset complete'
    except Exception as e:
        err = str(e).lower()
        # Connection drop after reset is expected — treat as success
        if any(term in err for term in ('closed', 'reset', 'timeout', 'eof',
                                         'broken pipe', 'connection')):
            return ip, 'OK', 'reset sent (connection dropped — expected)'
        return ip, 'FAIL', str(e)


# ---------------------------------------------------------------------------
# LLDP topology for safe reset ordering
# ---------------------------------------------------------------------------

def build_lldp_graph(connections, device_ips):
    """Build adjacency graph from LLDP. Returns {ip: set(neighbor_ips)}, hostnames."""
    # Step 1: get facts + LLDP from all devices in parallel
    hostnames = {}  # ip -> hostname
    lldp_data = {}  # ip -> lldp dict

    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        def gather(ip, device):
            facts = device.get_facts()
            lldp = device.get_lldp_neighbors_detail()
            return ip, facts.get('hostname', ''), lldp

        futures = {pool.submit(gather, ip, dev): ip for ip, dev in connections.items()}
        for future in as_completed(futures):
            ip, hostname, lldp = future.result()
            hostnames[ip] = hostname
            lldp_data[ip] = lldp

    # Step 2: reverse map — hostname -> ip (for matching LLDP neighbors)
    name_to_ip = {}
    for ip, name in hostnames.items():
        if name:
            name_to_ip[name.lower()] = ip

    # Step 3: build adjacency from LLDP
    graph = {ip: set() for ip in device_ips}
    for ip, lldp in lldp_data.items():
        for iface, neighbors in lldp.items():
            for neighbor in neighbors:
                remote_name = neighbor.get('remote_system_name', '').lower()
                if remote_name in name_to_ip:
                    peer_ip = name_to_ip[remote_name]
                    if peer_ip != ip and peer_ip in graph:
                        graph[ip].add(peer_ip)
                        graph[peer_ip].add(ip)

    return graph, hostnames


def compute_reset_order(graph, entry_ip):
    """BFS from entry, return IPs sorted furthest-first."""
    distances = {entry_ip: 0}
    queue = [entry_ip]
    while queue:
        current = queue.pop(0)
        for neighbor in graph.get(current, []):
            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)

    # Devices not reachable via LLDP get max distance (reset them first)
    max_dist = max(distances.values(), default=0) + 1
    all_ips = list(graph.keys())
    for ip in all_ips:
        if ip not in distances:
            distances[ip] = max_dist

    return sorted(all_ips, key=lambda ip: -distances[ip]), distances


# ---------------------------------------------------------------------------
# Config diff — compare running-config vs saved NVM profile
# ---------------------------------------------------------------------------

# Human-readable labels for config XML table names
TABLE_LABELS = {
    # VLAN
    'dot1qVlanStaticEntry': 'VLAN membership',
    'dot1qPortVlanEntry': 'Port VLAN settings (PVID)',
    'ieee8021QBridgeVlanStaticEntry': 'VLAN membership (802.1Q)',
    'ieee8021QBridgePortVlanEntry': 'Port VLAN settings (802.1Q)',
    'ieee8021QBridgeEntry': 'Bridge VLAN config',
    'ieee8021QBridgeForwardAllEntry': 'VLAN forward-all',
    # Interfaces
    'ifEntry': 'Interface settings',
    'ifXEntry': 'Interface extended settings',
    'hm2IfaceEntry': 'Port admin config',
    'hm2IfaceLayoutEntry': 'Port layout',
    'hm2AgentPortConfigEntry': 'Port switching config',
    'ifMauEntry': 'MAU settings (speed/duplex)',
    'ifMauAutoNegEntry': 'Auto-negotiation',
    # STP/RSTP
    'hm2AgentStpPortEntry': 'RSTP port config',
    'hm2AgentStpCstPortEntry': 'CST port config',
    'hm2AgentStpMstEntry': 'MST instance',
    'hm2AgentStpMstPortEntry': 'MST port config',
    'hm2AgentStpMstVlanEntry': 'MST VLAN mapping',
    # MRP
    'hm2MrpEntry': 'MRP ring config',
    'hm2SrmEntry': 'MRP sub-ring (SRM)',
    'hm2RingCouplingEntry': 'Ring coupling',
    # IGMP / Multicast
    'hm2AgentSwitchSnoopingVlanEntry': 'IGMP snooping (VLAN)',
    'hm2AgentSwitchSnoopingIntfEntry': 'IGMP snooping (port)',
    'hm2AgentSwitchSnoopingCfgEntry': 'IGMP snooping config',
    'hm2AgentSwitchSnoopingQuerierVlanEntry': 'IGMP querier (VLAN)',
    'hm2AgentSwitchSnoopingQuerierCfgEntry': 'IGMP querier config',
    'hm2L2McastFilteringEntry': 'Multicast filtering',
    'hm2L2McastSnoopingForwardAllEntry': 'Multicast forward-all',
    'hm2L2McastSnoopingQuerierEntry': 'Multicast querier',
    # DHCP
    'hm2AgentDhcpSnoopingIfConfigEntry': 'DHCP snooping (port)',
    'hm2AgentDhcpSnoopingVlanConfigEntry': 'DHCP snooping (VLAN)',
    'hm2AgentDhcpL2RelayIfConfigEntry': 'DHCP L2 relay (port)',
    'hm2AgentDhcpL2RelayVlanConfigEntry': 'DHCP L2 relay (VLAN)',
    'hm2DHCPServerPoolEntry': 'DHCP server pool',
    'hm2DHCPServerIfConfigEntry': 'DHCP server interface',
    # QoS
    'hm2AgentCosMapIntfTrustEntry': 'QoS trust mode',
    'hm2AgentCosQueueEntry': 'QoS queue scheduling',
    'hm2CosMapIpDscpEntry': 'DSCP→TC mapping',
    'hm2TrafficClassEntry': 'Traffic class config',
    'dot1dPortPriorityEntry': 'Port default priority (PCP)',
    'hm2TrafficMgmtIfEntry': 'Traffic management (shaping)',
    # LLDP
    'lldpPortConfigEntry': 'LLDP port config',
    'lldpConfigManAddrEntry': 'LLDP management address',
    # Security
    'hm2AgentPortSecurityEntry': 'Port security',
    'hm2AgentPortSecurityStaticEntry': 'Port security static MACs',
    'dot1xAuthConfigEntry': '802.1X auth config',
    'dot1xPaePortEntry': '802.1X PAE port',
    'hm2AgentDot1xPortConfigEntry': '802.1X port config',
    'hm2DevSecInterfaceEntry': 'Device security (port)',
    # Auto-disable / Loop protection
    'hm2AutoDisableIntfEntry': 'Auto-disable (port)',
    'hm2AutoDisableReasonEntry': 'Auto-disable reasons',
    'hm2AgentKeepalivePortEntry': 'Loop protection (port)',
    # sFlow
    'sFlowRcvrEntry': 'sFlow receiver',
    'sFlowFsEntry': 'sFlow flow sampler',
    'sFlowCpEntry': 'sFlow counter poller',
    # SNMP
    'usmUserEntry': 'SNMPv3 users',
    'vacmSecurityToGroupEntry': 'SNMP security-to-group',
    'vacmAccessEntry': 'SNMP access control',
    'vacmViewTreeFamilyEntry': 'SNMP view tree',
    'snmpCommunityEntry': 'SNMP communities',
    'snmpTargetAddrEntry': 'SNMP trap targets',
    'snmpNotifyEntry': 'SNMP notifications',
    # Management
    'hm2RmaEntry': 'Remote management access',
    'hm2UserConfigEntry': 'User accounts',
    # NTP / Time
    'hm2SntpClientServerAddrEntry': 'NTP server config',
    # Logging
    'hm2LogSyslogServerEntry': 'Syslog servers',
    # Diagnostics
    'hm2DevMonInterfaceEntry': 'Port monitoring',
    'hm2PortMonitorIntfEntry': 'Port monitor config',
    'hm2DiagIfaceUtilizationEntry': 'Interface utilization',
    # Link aggregation
    'dot3adAggEntry': 'LAG config',
    'dot3adAggPortEntry': 'LAG port membership',
    'hm2AgentLagSummaryConfigEntry': 'LAG summary',
    'hm2AgentLagDetailedConfigEntry': 'LAG detailed config',
    # GARP/MRP protocol
    'dot1dPortGarpEntry': 'GARP port config',
    'dot1dPortGmrpEntry': 'GMRP port config',
    'hm2AgentDot1qPortMrpEntry': 'MRP port config',
    'hm2AgentDot1qPortMvrpEntry': 'MVRP port config',
    # File management
    'hm2ExtNvmEntry': 'External NVM config',
    # HiDiscovery
    'hm2LinkBackupInterfaceConfigEntry': 'Link backup config',
    # ACL
    'hm2AgentAclEntry': 'ACL config',
    'hm2AgentAclRuleEntry': 'ACL rules',
    'hm2AgentAclIfEntry': 'ACL interface binding',
    # Mirror
    'hm2AgentPortMirrorEntry': 'Port mirroring',
    # DAI / IP Source Guard
    'hm2AgentDaiVlanConfigEntry': 'Dynamic ARP Inspection (VLAN)',
    'hm2AgentDaiIfConfigEntry': 'Dynamic ARP Inspection (port)',
    'hm2AgentIpsgIfConfigEntry': 'IP Source Guard (port)',
    # Private VLAN
    'hm2AgentPrivateVlanEntry': 'Private VLAN',
    'hm2AgentPrivateVlanIntfAssocEntry': 'Private VLAN port association',
    # mDNS-SD
    'hm2MDnsSdInventoryXstatusMonitorPortEntry': 'mDNS-SD monitor port',
    # ACL VLAN
    'hm2AgentAclVlanEntry': 'ACL VLAN binding',
    'hm2AgentAclMacEntry': 'MAC ACL config',
    'hm2AgentAclMacRuleEntry': 'MAC ACL rules',
    # Tracking
    'hm2TrackingConfigEntry': 'Object tracking config',
    'hm2TrackingInterfaceEntry': 'Object tracking interface',
    'hm2TrackingPingEntry': 'Object tracking ping',
    'hm2TrackInterfaceStatusEntry': 'Track interface status',
    'hm2TrackLogicalInstanceEntry': 'Track logical instance',
    # QoS (additional)
    'hm2AgentCosQueueCfgGroup': 'QoS queue global config',
    'hm2AgentCosQueueControlEntry': 'QoS queue control',
    # STP/RSTP (additional)
    'hm2AgentStpCstConfigGroup': 'RSTP global config',
    'hm2AgentStpSwitchConfigGroup': 'STP switch config',
    # Loop protection (additional)
    'hm2AgentSwitchKeepaliveGroup': 'Loop protection global',
    # HiDiscovery
    'hm2NetHiDiscoveryGroup': 'HiDiscovery config',
    # Management / Network
    'hm2NetStaticGroup': 'Management network config',
    # Device management
    'hm2DeviceMgmtGroup': 'Device management',
    'hm2DeviceMgmtTemperatureGroup': 'Temperature thresholds',
    'hm2DevMgmtSwVersEntry': 'Firmware versions',
    # File management
    'hm2FMProfileEntry': 'Config profiles',
    'hm2FileMgmtActionGroup': 'File transfer action table',
    'hm2FileMgmtConfigRemoteSaveGroup': 'Remote config auto-backup',
    'hm2FileMgmtServerAccessGroup': 'File transfer server credentials',
    # Hardware
    'hm2PSEntry': 'Power supply status',
    'hm2FanEntry': 'Fan status',
    'hm2SfpDiagEntry': 'SFP diagnostics',
    # SRM global
    'hm2SrmMibGroup': 'MRP sub-ring global',
    # NTP
    'hm2SntpClientGroup': 'NTP client config',
    # Traffic management
    'hm2TrafficMgmtMibObjects': 'Traffic management global',
    # SNMPv2 system
    'system': 'System info (sysName/sysContact/sysLocation)',
    # sFlow agent
    'sFlowAgent': 'sFlow agent config',
    # 802.1X (additional)
    'hm2AgentDot1xPortConfigEntry': '802.1X port config',
    # Industrial protocols
    'hm2PNIODcpModeEntry': 'PROFINET DCP mode',
    'hm2Iec62541OpcUaUserConfigEntry': 'OPC UA user config',
    # RADIUS / TACACS
    'hm2AgentRadiusServerConfigEntry': 'RADIUS server config',
    'hm2AgentRadiusAccountingConfigEntry': 'RADIUS accounting',
    'hm2AgentTacacsServerEntry': 'TACACS+ server config',
    # PTP / IEEE 1588
    'hm2Ptp2PortEntry': 'PTP port config',
    'hm2Ptp2TCPortEntry': 'PTP transparent clock port',
    # Email / Logging
    'hm2LogEmailMailServerEntry': 'Email alert server',
    'hm2LogEmailSubjectEntry': 'Email alert subject',
    'hm2LogEmailToAddressEntry': 'Email alert recipients',
    # SNMP (additional)
    'snmpTargetParamsEntry': 'SNMP target parameters',
    'snmpNotifyFilterProfileEntry': 'SNMP notify filter profile',
    'snmpNotifyFilterEntry': 'SNMP notify filters',
    # User management (additional)
    'hm2UserAuthListEntry': 'User auth list',
    'hm2UserApplicationListEntry': 'User application access',
    'hm2UserIasEntry': 'User IAS config',
    'hm2UserCustomAccessRole2NameEntry': 'Custom access roles',
    'hm2UserCustomCliCmdEntry': 'Custom CLI commands',
    'hm2UserCustomCliCmdInheritEntry': 'Custom CLI inheritance',
    # LDAP
    'hm2LdapClientServerAddrEntry': 'LDAP server config',
    'hm2LdapRoleMappingEntry': 'LDAP role mapping',
    # Remote auth
    'hm2SshKnownHostEntry': 'SSH known hosts',
    # DOS mitigation
    'hm2DosMitigationEntry': 'DoS mitigation',
    # Diagnostics (additional)
    'hm2DiagCpuResourcesGroup': 'CPU resources',
    'hm2DiagMemoryResourcesGroup': 'Memory resources',
    'hm2DiagSelftestActionEntry': 'Self-test config',
    'hm2DevMonCommonEntry': 'Device monitor common',
    'hm2DevMonPSEntry': 'Power supply monitor',
    'hm2SigConCommonEntry': 'Signal contact common',
    'hm2SigConInterfaceEntry': 'Signal contact interface',
    'hm2SigConPSEntry': 'Signal contact power supply',
    'hm2PortMonitorConditionIntfEntry': 'Port monitor conditions',
    'hm2PortMonitorConditionCrcFragmentsIntfEntry': 'Port monitor CRC/fragments',
    'hm2PortMonitorConditionLinkFlapIntfEntry': 'Port monitor link flap',
    'hm2PortMonitorConditionOvldDetIntfEntry': 'Port monitor overload',
    'hm2PortMonitorConditionSpeedDuplexEntry': 'Port monitor speed/duplex',
    # I/O module
    'hm2IOModConfigDigInputEntry': 'Digital input config',
    # License
    'hm2LicenseMgmtEntry': 'License management',
    # IEC 62439-3 (PRP/HSR)
    'lreInterfaceConfigEntry': 'PRP/HSR interface config',
    # IEEE 802.1AS (gPTP)
    'ieee8021AsV2PortDSEntry': 'gPTP port config',
    'ieee8021AsV2DefaultDSEntry': 'gPTP default dataset',
    'ieee8021AsV2ExternalPortConfigurationPortDSEntry': 'gPTP external port config',
    'ieee8021AsV2CommonMeanLinkDelayServiceLinkPortDSEntry': 'gPTP link delay',
    'ieee8021AsV2AsymMeasurementModeDSEntry': 'gPTP asymmetry measurement',
    # IEEE 802.1 bridge (additional)
    'ieee8021BridgeBaseEntry': '802.1 bridge base',
    'ieee8021BridgeBasePortEntry': '802.1 bridge port',
    'ieee8021BridgePortMrpEntry': '802.1 MRP port (IEEE)',
    'ieee8021BridgePortMmrpEntry': '802.1 MMRP port',
    # IEEE 802.1Qbv (TSN)
    'ieee8021STMaxSDUEntry': 'TSN max SDU',
    'ieee8021STParametersEntry': 'TSN stream parameters',
    # LLDP (additional)
    'lldpXdot1ConfigPortVlanEntry': 'LLDP 802.1 port VLAN TLV',
    'lldpXdot1ConfigProtoVlanEntry': 'LLDP 802.1 proto VLAN TLV',
    'lldpXdot1ConfigProtocolEntry': 'LLDP 802.1 protocol TLV',
    'lldpXdot1ConfigVlanNameEntry': 'LLDP 802.1 VLAN name TLV',
    'lldpXdot3PortConfigEntry': 'LLDP 802.3 port TLV',
    'lldpXHmConfigIGMPEntry': 'LLDP Hirschmann IGMP TLV',
    'lldpXHmConfigPTPEntry': 'LLDP Hirschmann PTP TLV',
    'lldpXHmConfigPortSecEntry': 'LLDP Hirschmann port security TLV',
    'lldpXMedLocMediaPolicyEntry': 'LLDP-MED media policy',
    'lldpXMedPortConfigEntry': 'LLDP-MED port config',
    'lldpXMedRemMediaPolicyEntry': 'LLDP-MED remote media policy',
    'lldpXPnoConfigEntry': 'LLDP PROFINET config',
    # MAC notification
    'hm2MACNotifyInterfaceEntry': 'MAC notification port',
    # Port security (additional)
    'hm2AgentStaticDsBindingEntry': 'Static DS binding',
    'hm2AgentStaticIpsgBindingEntry': 'Static IPSG binding',
    # Static MAC
    'hm2AgentSwitchStaticMacFilteringEntry': 'Static MAC filtering',
    # NTP broadcast
    'hm2SntpServerBroadcastVlanEntry': 'NTP broadcast VLAN',
    # RMON
    'alarmEntry': 'RMON alarm',
    # Time range
    'hm2AgentTimeRangeEntry': 'Time range config',
    'hm2AgentTimeRangeAbsoluteEntry': 'Time range absolute',
    'hm2AgentTimeRangePeriodicEntry': 'Time range periodic',
    # Timezone
    'hm2TimezoneEntry': 'Timezone config',
    # --- Standard MIB scalars ---
    'dot1dExtBase': 'Bridge extended base',
    'dot1dTp': 'Bridge transparent bridging',
    'dot1qBase': '802.1Q bridge base',
    'dot1qForwardAllEntry': 'VLAN forward-all ports',
    'dot1xPaeSystem': '802.1X PAE system config',
    'snmp': 'SNMP engine config',
    'lldpConfiguration': 'LLDP global config',
    'lldpXMedConfig': 'LLDP-MED global config',
    # --- Routing (L3) ---
    'hm2AgentBootpDhcpRelayGroup': 'BOOTP/DHCP relay',
    'hm2AgentECMPGroup': 'ECMP routing',
    'hm2AgentIpHelperGroup': 'IP helper global',
    'hm2AgentSwitchIpGroup': 'IP routing global',
    'hm2AgentSwitchArpGroup': 'ARP config',
    'hm2AgentSwitchIpIcmpControlGroup': 'ICMP control',
    'hm2AgentSwitchIpInterfaceEntry': 'L3 interface (IP)',
    'hm2AgentSwitchIpVlanEntry': 'L3 VLAN interface',
    'hm2AgentSwitchSecondaryAddressEntry': 'Secondary IP address',
    'hm2AgentSwitchIpRouterDiscoveryEntry': 'Router discovery',
    'hm2AgentSwitchIntfIpHelperAddressEntry': 'IP helper per-interface',
    'hm2AgentSwitchIpHelperAddressEntry': 'IP helper address',
    'hm2AgentStaticNeighbourEntry': 'Static ARP/neighbour',
    'hm2AgentLoopbackEntry': 'Loopback interface',
    'inetCidrRouteEntry': 'Static routes',
    # --- OSPF ---
    'hm2AgentRouterOspfConfigGroup': 'OSPF global config',
    'hm2AgentOspfIfEntry': 'OSPF interface',
    'hm2AgentOspfAreaNSSAEntry': 'OSPF NSSA area',
    'hm2AgentOspfVirtIfEntry': 'OSPF virtual interface',
    'hm2AgentOspfRouteRedistEntry': 'OSPF route redistribution',
    'ospfGeneralGroup': 'OSPF general config',
    'ospfAreaEntry': 'OSPF area',
    'ospfStubAreaEntry': 'OSPF stub area',
    'ospfIfEntry': 'OSPF interface (standard)',
    'ospfIfMetricEntry': 'OSPF interface metric',
    'ospfVirtIfEntry': 'OSPF virtual interface (standard)',
    'ospfAreaAggregateEntry': 'OSPF area aggregate',
    'ospfTrapControl': 'OSPF trap control',
    # --- RIP ---
    'hm2AgentRouterRipConfigGroup': 'RIP global config',
    'hm2AgentRip2IfConfEntry': 'RIP interface',
    'hm2AgentRipRouteRedistEntry': 'RIP route redistribution',
    'rip2IfConfEntry': 'RIP interface (standard)',
    # --- VRRP ---
    'hm2AgentRouterVrrpConfigGroup': 'VRRP global config',
    'hm2AgentVrrpDomainEntry': 'VRRP domain',
    'hm2AgentVrrpExtEntry': 'VRRP extended config',
    'hm2AgentVrrpTrackingEntry': 'VRRP tracking',
    'vrrpOperEntry': 'VRRP router',
    'vrrpAssoIpAddrEntry': 'VRRP associated IP',
    # --- Multicast routing ---
    'hm2AgentMulticastRoutingConfigGroup': 'Multicast routing global',
    'hm2AgentMulticastIGMPConfigGroup': 'IGMP routing config',
    'hm2AgentMulticastMgmdExtEntry': 'Multicast MGMD extended',
    'hm2AgentIpStaticMRouteEntry': 'Static multicast route',
    'ipMRoute': 'IP multicast routing',
    'ipMRouteBoundaryEntry': 'Multicast boundary',
    'ipMRouteInterfaceEntry': 'Multicast routing interface',
    'mgmdHostInterfaceEntry': 'MGMD host interface',
    'mgmdRouterInterfaceEntry': 'MGMD router interface',
    # --- DiffServ ---
    'hm2AgentDiffServGenStatusGroup': 'DiffServ global',
    'hm2AgentDiffServClassEntry': 'DiffServ class',
    'hm2AgentDiffServClassRuleEntry': 'DiffServ class rule',
    'hm2AgentDiffServPolicyEntry': 'DiffServ policy',
    'hm2AgentDiffServPolicyAttrEntry': 'DiffServ policy attribute',
    'hm2AgentDiffServPolicyInstEntry': 'DiffServ policy instance',
    'hm2AgentDiffServServiceEntry': 'DiffServ service',
    # --- Protocol-based VLAN ---
    'hm2AgentProtocolGroupEntry': 'Protocol group',
    'hm2AgentProtocolGroupProtocolEntry': 'Protocol group protocol',
    'hm2AgentProtocolGroupPortEntry': 'Protocol group port',
    # --- Double VLAN tagging ---
    'hm2AgentSwitchDVlanTagInterfaceEntry': 'Double VLAN tag (Q-in-Q)',
    # --- VLAN associations ---
    'hm2AgentSwitchVlanMacAssociationEntry': 'VLAN MAC association',
    'hm2AgentSwitchVlanSubnetAssociationEntry': 'VLAN subnet association',
    # --- Voice VLAN ---
    'hm2AgentSwitchVoiceVLANGroup': 'Voice VLAN',
    # --- ARP ACL ---
    'hm2AgentArpAclEntry': 'ARP ACL',
    'hm2AgentArpAclRuleEntry': 'ARP ACL rule',
    # --- DHCP global scalars ---
    'hm2AgentDaiConfigGroup': 'DAI global config',
    'hm2AgentDhcpL2RelayConfigGroup': 'DHCP L2 relay global',
    'hm2AgentDhcpSnoopingConfigGroup': 'DHCP snooping global',
    'hm2DHCPServerConfigGroup': 'DHCP server global',
    # --- MMRP / MVRP (IEEE MRP) ---
    'hm2AgentDot1qMmrp': 'MMRP global config',
    'hm2AgentDot1qMvrp': 'MVRP global config',
    'hm2AgentDot1qPortMmrpEntry': 'MMRP port config',
    # --- 802.1X extended ---
    'hm2AgentDot1xEnhancementConfigGroup': '802.1X enhancement config',
    'hm2AgentDot1xMonitorModeConfigGroup': '802.1X monitor mode',
    # --- LAG extended ---
    'hm2AgentLagConfigGroup': 'LAG global config',
    'hm2AgentDot3adAggPortEntry': 'LAG port extended config',
    # --- Port mirroring extended ---
    'hm2AgentPortMirroringGroup': 'Port mirroring global',
    'hm2AgentPortMirrorTypeEntry': 'Port mirror type config',
    # --- Port security global ---
    'hm2AgentPortSecurityGroup': 'Port security global',
    # --- RADIUS / TACACS extended ---
    'hm2AgentRadiusConfigGroup': 'RADIUS global config',
    'hm2AgentTacacsGlobalConfigGroup': 'TACACS+ global config',
    'hm2AgentTacacsAccountingGroup': 'TACACS+ accounting',
    'hm2AgentTacacsCmdAuthorizationGroup': 'TACACS+ command authorization',
    # --- SNMP trap flags (L3) ---
    'hm2AgentSnmpTrapFlagsConfigGroupLayer3': 'SNMP trap flags (L3)',
    # --- Address conflict ---
    'hm2AgentSwitchAddressConflictGroup': 'Address conflict detection',
    # --- GARP global ---
    'hm2AgentSwitchGARPGroup': 'GARP global config',
    # --- SDM template ---
    'hm2AgentSdmPreferConfigGroup': 'SDM template',
    # --- Summer time / timezone ---
    'hm2AgentSummerTimeGroup': 'Summer time config',
    'hm2AgentSummerTimeRecurringGroup': 'Summer time recurring',
    'hm2AgentTimeZoneGroup': 'Timezone global',
    # --- DNS ---
    'hm2DnsCacheGroup': 'DNS cache config',
    'hm2DnsClientGlobalGroup': 'DNS client global',
    'hm2DnsClientGroup': 'DNS client config',
    'hm2DnsClientServerCfgEntry': 'DNS server entry',
    'hm2DnsClientStaticHostConfigEntry': 'DNS static host',
    # --- DoS mitigation extended ---
    'hm2DosMitigationIcmpChecks': 'DoS ICMP checks',
    'hm2DosMitigationTcpHdrChecks': 'DoS TCP header checks',
    # --- Device management extended ---
    'hm2DeviceMgmtSoftwareVersionGroup': 'Firmware version info',
    'hm2DevSecConfigGroup': 'Device security config',
    'hm2DiagBootGroup': 'Boot diagnostics',
    'hm2DiagResourcesGroup': 'Resource diagnostics',
    'hm2DiagSelftestGroup': 'Self-test global',
    'hm2LedControlGroup': 'LED control',
    'hm2DevMonModuleEntry': 'Module monitoring',
    'hm2ModuleEntry': 'Module info',
    # --- File management extended ---
    'hm2FileMgmtConfigGroup': 'File management config',
    'hm2ExtNvmGeneralGroup': 'External NVM global',
    # --- Industrial protocols ---
    'hm2EthernetIPConfigGroup': 'EtherNet/IP config',
    'hm2EthernetIPQoSObjectGroup': 'EtherNet/IP QoS',
    'hm2EthernetIPTCPIPObjectGroup': 'EtherNet/IP TCP/IP',
    'hm2Iec61850ConfigGroup': 'IEC 61850 config',
    'hm2Iec62541ConfigGroup': 'OPC UA config',
    'hm2ModbusConfigGroup': 'Modbus TCP config',
    'hm2ProfinetIOConfigGroup': 'PROFINET IO config',
    # --- gPTP / PTP extended ---
    'hm2Dot1asGlobal': 'gPTP global config',
    'hm2PtpGlobal': 'PTP global config',
    'hm2Ptp2Configuration': 'PTP v2 config',
    'hm2Ptp2TCConfiguration': 'PTP transparent clock config',
    # --- L2 forwarding ---
    'hm2L2ForwGeneralGroup': 'L2 forwarding global',
    # --- L2 multicast global ---
    'hm2L2McastFilteringGroup': 'Multicast filtering global',
    # --- License ---
    'hm2LMSwLvlGroup': 'Software level',
    # --- LDAP extended ---
    'hm2LdapConfigGroup': 'LDAP global config',
    'hm2LdapMappingGroup': 'LDAP mapping global',
    # --- Link backup ---
    'hm2LinkBackupGeneralGroup': 'Link backup global',
    # --- Logging extended ---
    'hm2LogBufferedLoggingGroup': 'Buffered logging',
    'hm2LogCliCommandsLoggingGroup': 'CLI command logging',
    'hm2LogConsoleLoggingGroup': 'Console logging',
    'hm2LogEmailAlertGroup': 'Email alert global',
    'hm2LogPersistentGroup': 'Persistent logging',
    'hm2LogSnmpLoggingGroup': 'SNMP logging',
    'hm2LogSyslogGroup': 'Syslog global',
    # --- LLDP extended ---
    'hm2LLDPConfigGroup': 'LLDP Hirschmann config',
    'hm2LLDPIfEntry': 'LLDP Hirschmann interface',
    # --- MAC notification ---
    'hm2MACNotifyMibObjects': 'MAC notification global',
    # --- mDNS-SD global ---
    'hm2MDnsSdConfigGroup': 'mDNS-SD global config',
    # --- Management access ---
    'hm2MgmtAccessCliGroup': 'CLI access config',
    'hm2MgmtAccessPreLoginBannerGroup': 'Pre-login banner',
    'hm2MgmtAccessSnmpGroup': 'SNMP access config',
    'hm2MgmtAccessSshGroup': 'SSH access config',
    'hm2MgmtAccessTelnetGroup': 'Telnet access config',
    'hm2MgmtAccessWebGroup': 'Web access config',
    'hm2RestrictedMgmtAccessGroup': 'Restricted management access',
    # --- Network config extended ---
    'hm2NetACDGroup': 'Address conflict detection (ACD)',
    'hm2NetMacACDGroup': 'MAC address conflict detection',
    'hm2NetOobMgmtGroup': 'Out-of-band management',
    'hm2NetOobUsbMgmtGroup': 'USB management',
    'hm2NetIPv6LocalAddrEntry': 'IPv6 local address',
    # --- PoE ---
    'hm2PoeMgmtGlobalGroup': 'PoE global config',
    'hm2PoeMgmtModuleEntry': 'PoE module config',
    'hm2PoeMgmtPortEntry': 'PoE port config',
    'pethMainPseEntry': 'PoE PSE config (standard)',
    'pethNotificationControlEntry': 'PoE notification control',
    # --- Port monitor global ---
    'hm2PortMonitorGroup': 'Port monitor global',
    # --- Redundancy globals ---
    'hm2RedundantCplConfigMibGroup': 'Redundant coupling config',
    'hm2RingRedMibGroup': 'Ring redundancy global',
    # --- Signal contact extended ---
    'hm2SigConModuleEntry': 'Signal contact module',
    # --- NTP extended ---
    'hm2SntpServerBroadcastGroup': 'NTP broadcast global',
    'hm2SntpServerGroup': 'NTP server config',
    'hm2SystemTimeGroup': 'System time config',
    # --- Tracking extended ---
    'hm2TrackStaticRouteEntry': 'Track static route',
    # --- TSN ---
    'hm2TsnGroup': 'TSN global config',
    # --- User management extended ---
    'hm2PwdMgmtGroup': 'Password management',
    'hm2UserStatusGroup': 'User status config',
    # --- I/O module global ---
    'hm2IOModConfigCommon': 'I/O module global',
}


def _parse_config_diff(nvm_xml, run_xml):
    """Parse two config XMLs and return structured diff summary.

    Returns list of dicts:
        {'mib': str, 'section': str, 'label': str, 'indices': list}
    """
    import re
    from difflib import unified_diff

    nvm_lines = nvm_xml.splitlines()
    run_lines = run_xml.splitlines()
    diff_lines = list(unified_diff(nvm_lines, run_lines, lineterm=''))

    if not diff_lines:
        return []

    def _build_context(lines):
        """Map each line index to (mib, section) where section is
        a Table, Group, or Scalar name."""
        ctx = {}
        mib = ''
        section = ''
        for i, line in enumerate(lines):
            m = re.search(r'<MIB name="([^"]*)"', line)
            if m:
                mib = m.group(1)
                section = ''
            for tag in ('Table', 'Group', 'Scalar'):
                t = re.search(rf'<{tag} name="([^"]*)"', line)
                if t:
                    section = t.group(1)
            ctx[i] = (mib, section)
        return ctx

    context_map = _build_context(nvm_lines)
    run_context = _build_context(run_lines)

    # Parse unified diff hunks to find which sections have changes
    changed = {}  # (mib, section) -> set of index values
    nvm_line = 0
    run_line = 0

    for diff_line in diff_lines:
        hunk = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)', diff_line)
        if hunk:
            nvm_line = int(hunk.group(1)) - 1
            run_line = int(hunk.group(2)) - 1
            continue

        if diff_line.startswith('---') or diff_line.startswith('+++'):
            continue

        if diff_line.startswith('-'):
            ctx = context_map.get(nvm_line, ('', ''))
            nvm_line += 1
        elif diff_line.startswith('+'):
            ctx = run_context.get(run_line, ('', ''))
            run_line += 1
        else:
            nvm_line += 1
            run_line += 1
            continue

        # Skip Footer checksum changes — not real config drift
        if 'Checksum' in diff_line:
            continue

        if ctx[1]:
            key = ctx
            if key not in changed:
                changed[key] = set()
            idx = re.search(r'name="(\w*Index\w*)"[^>]*>([^<]+)', diff_line)
            if not idx:
                idx = re.search(r'name="(\w*[Ii]d\w*)"[^>]*>([^<]+)',
                                diff_line)
            if idx:
                changed[key].add(idx.group(2).strip())

    # Build summary
    results = []
    for (mib, section), indices in sorted(changed.items()):
        label = TABLE_LABELS.get(section, section)
        results.append({
            'mib': mib,
            'section': section,
            'label': label,
            'indices': sorted(indices) if indices else [],
        })

    return results


def worker_diff(device, ip):
    """Download running-config and NVM profile, return diff data."""
    try:
        status = device.get_config_status()
        if status.get('saved', True):
            return ip, 'OK', {'saved': True, 'changes': [], 'diff_lines': 0}

        profiles = device.get_profiles()
        active = [p for p in profiles if p.get('active')]
        profile_name = active[0]['name'] if active else 'config'

        nvm = device.get_config(profile=profile_name, source='nvm')
        running = device.get_config(
            profile='running-config', source='running-config')

        from difflib import unified_diff
        diff = [d for d in unified_diff(
            nvm['running'].splitlines(), running['running'].splitlines(),
            fromfile='nvm', tofile='running', lineterm='')
            if d.startswith(('+', '-'))
            and not d.startswith(('---', '+++'))
            and 'Checksum' not in d]

        changes = _parse_config_diff(nvm['running'], running['running'])

        return ip, 'OK', {
            'saved': False,
            'changes': changes,
            'diff_lines': len(diff),
            'profile': profile_name,
        }
    except Exception as e:
        return ip, 'FAIL', str(e)


def worker_save_rollback(device, ip, rollback_name):
    """Backup active profile as rollback, then save running to NVM."""
    try:
        # 1. Find active profile
        profiles = device.get_profiles()
        active = [p for p in profiles if p.get('active')]
        if not active:
            return ip, 'FAIL', 'no active profile found'
        active_name = active[0]['name']
        active_idx = active[0]['index']

        # 2. Pick rollback profile name (avoid collisions)
        existing_names = {p['name'] for p in profiles}
        name = rollback_name
        if name in existing_names:
            n = 1
            while f'{rollback_name}-{n}' in existing_names:
                n += 1
            name = f'{rollback_name}-{n}'

        # 3. Download current saved config
        nvm_cfg = device.get_config(profile=active_name, source='nvm')
        xml_data = nvm_cfg['running']

        # 4. Upload as rollback profile
        device.load_config(xml_data, profile=name, destination='nvm')

        # 5. Save running config to NVM (overwrites active profile)
        device.save_config()

        return ip, 'OK', {
            'active': active_name,
            'rollback': name,
            'profiles_before': len(profiles),
        }
    except Exception as e:
        return ip, 'FAIL', str(e)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_banner(command, config):
    """Print the standard MOHAWC banner."""
    label = command.upper() if command else 'STATUS'
    print("\n" + "=" * 60)
    print(f"  MOHAWC \u2014 {label}")
    print("=" * 60)
    print(f"  Protocol:  {config['protocol'].upper()} | Devices: {len(config['devices'])}")
    print("-" * 60)


def print_footer(total, reached, elapsed):
    """Print the standard MOHAWC footer."""
    print("\n" + "=" * 60)
    print(f"  {reached}/{total} devices reached | Done in {elapsed:.1f}s")
    print("=" * 60 + "\n")


def format_hidiscovery(hd):
    """Format HiDiscovery dict for display."""
    status = _hidiscovery_status_str(hd)
    blink = hd.get('blinking', 'unknown')
    if isinstance(blink, bool):
        blink = 'on' if blink else 'off'
    return f"{status}  blink={blink}"


def print_status_device(ip, data):
    """Print status output for one device."""
    facts = data['facts']
    model = facts.get('model', 'unknown')
    version = facts.get('os_version', '?')
    uptime = format_uptime(facts.get('uptime', 0))
    hostname = facts.get('hostname', '')
    label = display_name(ip)

    uptime_str = f'  (up {uptime})' if uptime else ''
    name_str = f'  [{hostname}]' if hostname and hostname != label else ''

    print(f"\n  {label:<17s}{model:<25s}{version}{uptime_str}{name_str}")

    # Factory default
    factory = data['factory']
    protocol = data['protocol']
    if factory:
        print(f"    Factory default:  YES \u2014 needs onboarding")
    elif protocol == 'snmp':
        print(f"    Factory default:  No  (SNMP: always reports No)")
    else:
        print(f"    Factory default:  No")

    # Config status
    cs = data['config_status']
    nvm = cs.get('nvm', '?')
    aca = cs.get('aca', '?')
    boot = cs.get('boot', '?')
    saved = cs.get('saved', None)
    saved_tag = '  [SAVED]' if saved else '  [UNSAVED]' if saved is False else ''
    print(f"    Config:           nvm={nvm}  aca={aca}  boot={boot}{saved_tag}")

    # HiDiscovery
    hd = data['hidiscovery']
    print(f"    HiDiscovery:      {format_hidiscovery(hd)}")


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def cmd_status(args, config, driver):
    """Execute the status subcommand."""
    connections = connect_all(driver, config)
    if not connections:
        return 0

    results = {}
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_status, device, ip, config['protocol']): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, data, err = future.result()
            if data:
                results[ip] = data
            else:
                print(f"\n  {display_name(ip):<17s}[FAIL] {err}")

    # Print in config order
    for ip in config['devices']:
        if ip in results:
            print_status_device(ip, results[ip])

    close_all(connections)
    return len(results)


def cmd_onboard(args, config, driver):
    """Execute the onboard subcommand."""
    if config['protocol'] == 'offline':
        print("\n  ERROR: onboard not available offline\n", file=sys.stderr)
        sys.exit(1)
    if config['protocol'] == 'snmp':
        print("\n  ERROR: onboard not available via SNMP —", file=sys.stderr)
        print("  SNMP is gated on factory-default devices. Use MOPS or SSH.\n", file=sys.stderr)
        sys.exit(1)

    connections = connect_all(driver, config)
    if not connections:
        return 0

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_onboard, device, ip, args.new_password, args.save): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, status, msg = future.result()
            results.append((ip, status, msg))

    # Print in config order
    result_map = {ip: (status, msg) for ip, status, msg in results}
    for ip in config['devices']:
        if ip in result_map:
            status, msg = result_map[ip]
            tag = status
            print(f"\n  [{tag:4s}] {display_name(ip):<17s}{msg}")

    close_all(connections)
    return sum(1 for _, s, _ in results if s == 'OK')


def cmd_hidiscovery(args, config, driver):
    """Execute the hidiscovery subcommand."""
    # Resolve target status (None = preserve current)
    if args.on:
        status = 'on'
    elif args.off:
        status = 'off'
    elif args.ro:
        status = 'read-only'
    else:
        status = None

    # Resolve blinking
    blinking = None
    if args.blink:
        blinking = True
    elif args.no_blink:
        blinking = False

    if status is None and blinking is None:
        print("\n  ERROR: specify at least one of --on/--off/--ro or --blink/--no-blink\n", file=sys.stderr)
        sys.exit(1)

    connections = connect_all(driver, config)
    if not connections:
        return 0

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_hidiscovery, device, ip, status, blinking, args.save): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, tag, detail = future.result()
            results.append((ip, tag, detail))

    result_map = {ip: (tag, detail) for ip, tag, detail in results}
    for ip in config['devices']:
        if ip in result_map:
            tag, detail = result_map[ip]
            if tag == 'OK':
                before = format_hidiscovery(detail['before'])
                after = format_hidiscovery(detail['after'])
                print(f"\n  [OK  ] {display_name(ip):<17s}{before}  ->  {after}")
            else:
                print(f"\n  [FAIL] {display_name(ip):<17s}{detail}")

    close_all(connections)
    return sum(1 for _, s, _ in results if s == 'OK')


def cmd_save(args, config, driver):
    """Execute the save subcommand."""
    connections = connect_all(driver, config)
    if not connections:
        return 0

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_save, device, ip): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, tag, msg = future.result()
            results.append((ip, tag, msg))

    result_map = {ip: (tag, msg) for ip, tag, msg in results}
    for ip in config['devices']:
        if ip in result_map:
            tag, msg = result_map[ip]
            print(f"\n  [{tag:4s}] {display_name(ip):<17s}{msg}")

    close_all(connections)
    return sum(1 for _, s, _ in results if s == 'OK')


def cmd_reset(args, config, driver):
    """Execute the reset subcommand."""
    if config['protocol'] == 'offline':
        print("\n  ERROR: reset not available offline\n", file=sys.stderr)
        sys.exit(1)
    if args.erase_all and not args.factory:
        print("\n  ERROR: --erase-all requires --factory\n", file=sys.stderr)
        sys.exit(1)

    # Describe what we're about to do
    if args.factory:
        if args.erase_all:
            action = "FACTORY RESET + ERASE ALL NVM"
        else:
            action = "FACTORY RESET"
    else:
        if args.keep_ip:
            action = "SOFT RESET (keep management IP)"
        else:
            action = "SOFT RESET"

    print(f"\n  Action: {action}")
    if args.entry:
        print(f"  Order:  furthest-first (entry: {args.entry})")
    print(f"  Devices: {', '.join(config['devices'])}")

    if not args.yes:
        print(f"\n  WARNING: This will reset {len(config['devices'])} device(s).")
        print("  Type 'yes' to continue: ", end='', flush=True)
        confirm = input().strip()
        if confirm != 'yes':
            print("  Aborted.\n")
            return 0

    connections = connect_all(driver, config)
    if not connections:
        return 0

    # --- Safe ordering via LLDP topology ---
    if args.entry and config['protocol'] == 'offline':
        print("\n  WARNING: --entry ignored for offline protocol (no LLDP)")
        args.entry = None
    if args.entry:
        print("\n  Building LLDP topology...")
        graph, hostnames = build_lldp_graph(connections, list(connections.keys()))
        order, distances = compute_reset_order(graph, args.entry)

        print(f"  Reset order (furthest-first):")
        for ip in order:
            name = hostnames.get(ip, '')
            dist = distances.get(ip, '?')
            label = f"  [{name}]" if name else ""
            print(f"    {dist} hop{'s' if dist != 1 else ' '}  {display_name(ip):<17s}{label}")

        # Sequential reset — furthest first
        results = []
        for ip in order:
            device = connections.get(ip)
            if not device:
                continue
            print(f"\n  Resetting {ip}...", end='', flush=True)
            _, tag, msg = worker_reset(device, ip,
                                       args.factory, args.keep_ip, args.erase_all)
            results.append((ip, tag, msg))
            print(f" [{tag}] {msg}")
    else:
        # Parallel reset (no --entry)
        results = []
        with ThreadPoolExecutor(max_workers=len(connections)) as pool:
            futures = {
                pool.submit(worker_reset, device, ip,
                            args.factory, args.keep_ip, args.erase_all): ip
                for ip, device in connections.items()
            }
            for future in as_completed(futures):
                ip, tag, msg = future.result()
                results.append((ip, tag, msg))

        result_map = {ip: (tag, msg) for ip, tag, msg in results}
        for ip in config['devices']:
            if ip in result_map:
                tag, msg = result_map[ip]
                print(f"\n  [{tag:4s}] {display_name(ip):<17s}{msg}")

    # Don't close — connections are likely already dead after reset
    for ip, device in connections.items():
        try:
            device.close()
        except Exception:
            pass

    return sum(1 for _, s, _ in results if s == 'OK')


def cmd_diff(args, config, driver):
    """Execute the diff subcommand."""
    if config['protocol'] != 'mops':
        print("\n  ERROR: diff requires MOPS protocol (HTTPS config download)\n",
              file=sys.stderr)
        sys.exit(1)

    connections = connect_all(driver, config)
    if not connections:
        return 0

    results = {}
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_diff, device, ip): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, status, data = future.result()
            if status == 'OK':
                results[ip] = data
            else:
                print(f"\n  {display_name(ip):<17s}[FAIL] {data}")

    # Print in config order
    for ip in config['devices']:
        if ip not in results:
            continue
        data = results[ip]
        label = display_name(ip)

        if data['saved']:
            print(f"\n  {label:<17s}[SAVED] No unsaved changes")
            continue

        changes = data['changes']
        diff_lines = data['diff_lines']
        profile = data.get('profile', 'config')

        print(f"\n  {label:<17s}[UNSAVED] {diff_lines} diff lines "
              f"(running vs '{profile}')")

        if changes:
            for c in changes:
                idx_str = ''
                if c['indices']:
                    idx_str = ': ' + ', '.join(c['indices'])
                print(f"    {c['label']}{idx_str}")
        else:
            print(f"    (diff detected but no table-level changes parsed)")

    close_all(connections)
    return len(results)


def cmd_save_rollback(args, config, driver):
    """Execute the save-rollback subcommand."""
    if config['protocol'] != 'mops':
        print("\n  ERROR: save-rollback requires MOPS protocol "
              "(HTTPS config download/upload)\n", file=sys.stderr)
        sys.exit(1)

    rollback_name = args.name

    if not args.yes:
        print(f"\n  Action: Save running config to NVM")
        print(f"  Backup: Current NVM saved as '{rollback_name}' profile")
        print(f"  Devices: {', '.join(config['devices'])}")
        print(f"\n  Type 'yes' to continue: ", end='', flush=True)
        confirm = input().strip()
        if confirm != 'yes':
            print("  Aborted.\n")
            return 0

    connections = connect_all(driver, config)
    if not connections:
        return 0

    results = {}
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_save_rollback, device, ip, rollback_name): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, status, data = future.result()
            results[ip] = (status, data)

    # Print in config order
    for ip in config['devices']:
        if ip not in results:
            continue
        status, data = results[ip]
        label = display_name(ip)

        if status == 'FAIL':
            print(f"\n  {label:<17s}[FAIL] {data}")
            continue

        rollback = data['rollback']
        active = data['active']
        print(f"\n  {label:<17s}[SAVED] rollback profile: '{rollback}'")
        print(f"    Running config saved to '{active}'")

    close_all(connections)
    return sum(1 for s, _ in results.values() if s == 'OK')


def cmd_profiles(args, config, driver):
    """List config profiles on all devices."""
    connections = connect_all(driver, config)
    if not connections:
        return 0

    reached = 0
    for ip in config['devices']:
        device = connections.get(ip)
        if not device:
            continue
        try:
            profiles = device.get_profiles()
            reached += 1
            label = display_name(ip)
            print(f"\n  {label}")
            if not profiles:
                print("    (no profiles)")
                continue
            for p in profiles:
                active = ' *' if p.get('active') else '  '
                name = p.get('name', '?')
                idx = p.get('index', '?')
                fp = p.get('fingerprint', '')
                fp_str = f'  [{fp[:12]}]' if fp else ''
                print(f"    {active} {idx:>2}  {name:<20s}{fp_str}")
        except Exception as e:
            print(f"\n  {display_name(ip):<17s}[FAIL] {e}")

    close_all(connections)
    return reached


def cmd_activate(args, config, driver):
    """Activate a config profile (triggers warm restart)."""
    if args.index is None and args.name is None:
        print("\n  ERROR: specify --index or --name\n", file=sys.stderr)
        sys.exit(1)

    connections = connect_all(driver, config)
    if not connections:
        return 0

    # Resolve profile index from name if needed
    target_index = args.index
    target_name = args.name

    if not args.yes:
        if target_name:
            print(f"\n  Action: Activate profile '{target_name}' (warm restart)")
        else:
            print(f"\n  Action: Activate profile index {target_index} (warm restart)")
        print(f"  WARNING: This triggers a warm restart — devices will reboot.")
        print(f"  Type 'yes' to continue: ", end='', flush=True)
        confirm = input().strip()
        if confirm != 'yes':
            print("  Aborted.\n")
            close_all(connections)
            return 0

    reached = 0
    for ip in config['devices']:
        device = connections.get(ip)
        if not device:
            continue
        try:
            idx = target_index
            if target_name and idx is None:
                profiles = device.get_profiles()
                match = [p for p in profiles if p.get('name') == target_name]
                if not match:
                    print(f"\n  [FAIL] {display_name(ip):<17s}profile '{target_name}' not found")
                    continue
                idx = match[0]['index']
            device.activate_profile('nvm', idx)
            reached += 1
            print(f"\n  [OK  ] {display_name(ip):<17s}profile {idx} activated (rebooting)")
        except Exception as e:
            err = str(e).lower()
            if any(t in err for t in ('closed', 'reset', 'timeout', 'eof',
                                       'broken pipe', 'connection')):
                reached += 1
                print(f"\n  [OK  ] {display_name(ip):<17s}activated (connection dropped — expected)")
            else:
                print(f"\n  [FAIL] {display_name(ip):<17s}{e}")

    for ip, device in connections.items():
        try:
            device.close()
        except Exception:
            pass
    return reached


def cmd_delete(args, config, driver):
    """Delete a config profile."""
    if args.index is None and args.name is None:
        print("\n  ERROR: specify --index or --name\n", file=sys.stderr)
        sys.exit(1)

    connections = connect_all(driver, config)
    if not connections:
        return 0

    target_index = args.index
    target_name = args.name

    if not args.yes:
        if target_name:
            print(f"\n  Action: Delete profile '{target_name}'")
        else:
            print(f"\n  Action: Delete profile index {target_index}")
        print(f"  Type 'yes' to continue: ", end='', flush=True)
        confirm = input().strip()
        if confirm != 'yes':
            print("  Aborted.\n")
            close_all(connections)
            return 0

    reached = 0
    for ip in config['devices']:
        device = connections.get(ip)
        if not device:
            continue
        try:
            profiles = device.get_profiles()
            idx = target_index
            if target_name and idx is None:
                match = [p for p in profiles if p.get('name') == target_name]
                if not match:
                    print(f"\n  [FAIL] {display_name(ip):<17s}profile '{target_name}' not found")
                    continue
                idx = match[0]['index']
            # Refuse active profile
            active_match = [p for p in profiles if p.get('index') == idx and p.get('active')]
            if active_match:
                print(f"\n  [SKIP] {display_name(ip):<17s}cannot delete active profile")
                continue
            device.delete_profile('nvm', idx)
            reached += 1
            print(f"\n  [OK  ] {display_name(ip):<17s}profile {idx} deleted")
        except Exception as e:
            print(f"\n  [FAIL] {display_name(ip):<17s}{e}")

    close_all(connections)
    return reached


def cmd_download(args, config, driver):
    """Download config XML from device."""
    connections = connect_all(driver, config)
    if not connections:
        return 0

    reached = 0
    for ip in config['devices']:
        device = connections.get(ip)
        if not device:
            continue
        try:
            profile = args.profile
            if not profile:
                profiles = device.get_profiles()
                active = [p for p in profiles if p.get('active')]
                profile = active[0]['name'] if active else 'config'

            cfg = device.get_config(profile=profile, source='nvm')
            xml = cfg.get('running', '')
            reached += 1

            if args.output:
                # Multi-device: append IP suffix
                out_path = args.output
                if len(config['devices']) > 1:
                    base, ext = os.path.splitext(args.output)
                    out_path = f"{base}_{ip.replace('.', '_')}{ext or '.xml'}"
                with open(out_path, 'w') as f:
                    f.write(xml)
                print(f"\n  [OK  ] {display_name(ip):<17s}saved to {out_path}")
            else:
                if len(config['devices']) > 1:
                    print(f"\n--- {display_name(ip)} ({profile}) ---")
                print(xml)
        except Exception as e:
            print(f"\n  [FAIL] {display_name(ip):<17s}{e}")

    close_all(connections)
    return reached


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def connect_all(driver, config):
    """Connect to all devices in parallel, return {ip: device} dict."""
    print("\n  Connecting...")
    connections = {}
    failures = []

    with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
        futures = {
            pool.submit(worker_connect, driver, config, ip): ip
            for ip in config['devices']
        }
        for future in as_completed(futures):
            ip, device, err = future.result()
            if device:
                connections[ip] = device
                logging.info(f"[{ip}] Connected")
            else:
                failures.append((ip, err))
                logging.error(f"[{ip}] Connection failed: {err}")

    if failures:
        for ip, err in failures:
            print(f"  [FAIL] {display_name(ip)} \u2014 {err}")
    if not connections:
        print("\n  FATAL: No devices reachable.\n", file=sys.stderr)
        return {}

    print(f"  {len(connections)} device(s) connected")
    return connections


def close_all(connections):
    """Close all device connections, suppressing errors."""
    for ip, device in connections.items():
        try:
            device.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def interactive_mode(args, config, driver):
    """REPL-style guided session for MOHAWC.

    Connect once, stay connected, run multiple operations in a loop.
    """

    # ANSI
    CY = '\033[36m'; MG = '\033[35m'; YL = '\033[33m'
    GR = '\033[32m'; BD = '\033[1m'; DM = '\033[2m'; RS = '\033[0m'

    def cls():
        print('\033[2J\033[H', end='', flush=True)

    def banner():
        print(f"""
  {MG}{BD}╔╦╗╔═╗╦ ╦╔═╗╦ ╦╔═╗{RS}
  {MG}{BD}║║║║ ║╠═╣╠═╣║║║║  {RS}
  {MG}{BD}╩ ╩╚═╝╩ ╩╩ ╩╚╩╝╚═╝{RS}
  {DM}Management, Onboarding, HiDiscovery, And Wipe Configuration{RS}
  {CY}{'━' * 58}{RS}
""")

    def step(title):
        cls()
        banner()
        print(f'  {BD}{title}{RS}\n')

    def pick(text, options, default=1):
        for i, (label, _) in enumerate(options, 1):
            mark = f'{YL}▸{RS}' if i == default else ' '
            print(f'  {mark} {CY}{i}{RS}) {label}')
        print()
        while True:
            raw = input(f'  {GR}▸{RS} {text} [{default}]: ').strip()
            if not raw:
                return options[default - 1][1]
            try:
                idx = int(raw)
                if 1 <= idx <= len(options):
                    return options[idx - 1][1]
            except ValueError:
                pass
            print(f'  {YL}Pick 1–{len(options)}{RS}')

    def ask(text, default=''):
        hint = f' {DM}[{default}]{RS}' if default else ''
        return input(f'  {GR}▸{RS} {text}{hint}: ').strip() or default

    def yesno(text, default=False):
        hint = 'Y/n' if default else 'y/N'
        val = input(f'  {GR}▸{RS} {text} {DM}[{hint}]{RS}: ').strip().lower()
        return val in ('y', 'yes') if val else default

    def pause():
        input(f'\n  {DM}Press Enter...{RS}')

    def show_profiles(device, ip):
        """Display profiles for one device, return the list."""
        profiles = device.get_profiles()
        label = display_name(ip)
        print(f"\n  {BD}{label}{RS}")
        if not profiles:
            print("    (no profiles)")
            return profiles
        for p in profiles:
            active = f'{GR}*{RS}' if p.get('active') else ' '
            name = p.get('name', '?')
            idx = p.get('index', '?')
            fp = p.get('fingerprint', '')
            fp_str = f'  {DM}[{fp[:12]}]{RS}' if fp else ''
            print(f"    {active} {idx:>2}  {name:<20s}{fp_str}")
        return profiles

    def refresh_state(connections):
        """Re-fetch profiles + config status from all devices."""
        state = {}
        for ip, device in connections.items():
            try:
                state[ip] = {
                    'profiles': device.get_profiles(),
                    'config_status': device.get_config_status(),
                }
            except Exception as e:
                state[ip] = {'error': str(e)}
        return state

    connections = {}

    try:
        # ── CONNECT ──
        cls()
        banner()
        print(f'  {BD}CONNECTING{RS}\n')

        connections = connect_all(driver, config)
        if not connections:
            print(f'\n  {YL}No devices reachable. Exiting.{RS}\n')
            return

        protocol = config['protocol']
        is_mops = protocol == 'mops'
        is_offline = protocol == 'offline'

        # Initial gather
        print(f"  {DM}Gathering initial state...{RS}")
        state = refresh_state(connections)

        for ip in config['devices']:
            if ip in state and 'error' not in state[ip]:
                cs = state[ip]['config_status']
                n_prof = len(state[ip]['profiles'])
                saved = cs.get('saved')
                tag = f'{GR}saved{RS}' if saved else f'{YL}unsaved{RS}' if saved is False else ''
                print(f"    {display_name(ip):<17s}{n_prof} profile(s)  {tag}")
            elif ip in state:
                print(f"    {display_name(ip):<17s}{YL}{state[ip]['error']}{RS}")

        pause()

        # ── MAIN MENU LOOP ──
        while True:
            cls()
            banner()
            n_dev = len(connections)
            print(f'  {BD}SESSION{RS}  {CY}{n_dev}{RS} device(s) via {protocol.upper()}\n')

            ops = [
                ('Status',              'status'),
                ('List profiles',       'profiles'),
            ]
            if is_mops:
                ops.append(('Diff (unsaved changes)', 'diff'))
            ops.append(('Save',                 'save'))
            if is_mops:
                ops.append(('Save with rollback',   'save-rollback'))
            ops.append(('Activate profile',     'activate'))
            ops.append(('Delete profile',       'delete'))
            ops.append(('HiDiscovery',          'hidiscovery'))
            if not is_offline:
                ops.append(('Reset',            'reset'))
            if not is_offline and protocol != 'snmp':
                ops.append(('Onboard',          'onboard'))
            ops.append(('Quit',                 'quit'))

            op = pick('What next?', ops)

            if op == 'quit':
                break

            print()

            # ── STATUS ──
            if op == 'status':
                results = {}
                with ThreadPoolExecutor(max_workers=len(connections)) as pool:
                    futures = {
                        pool.submit(worker_status, device, ip, protocol): ip
                        for ip, device in connections.items()
                    }
                    for future in as_completed(futures):
                        ip, data, err = future.result()
                        if data:
                            results[ip] = data
                        else:
                            print(f"  {display_name(ip):<17s}{YL}[FAIL] {err}{RS}")

                for ip in config['devices']:
                    if ip in results:
                        print_status_device(ip, results[ip])
                pause()

            # ── LIST PROFILES ──
            elif op == 'profiles':
                for ip in config['devices']:
                    device = connections.get(ip)
                    if device:
                        try:
                            show_profiles(device, ip)
                        except Exception as e:
                            print(f"  {display_name(ip):<17s}{YL}{e}{RS}")
                pause()

            # ── DIFF ──
            elif op == 'diff':
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    ip_r, status_r, data = worker_diff(device, ip)
                    label = display_name(ip)
                    if status_r == 'FAIL':
                        print(f"  {label:<17s}{YL}[FAIL] {data}{RS}")
                        continue
                    if data['saved']:
                        print(f"  {label:<17s}{GR}No unsaved changes{RS}")
                    else:
                        changes = data['changes']
                        diff_lines = data['diff_lines']
                        profile = data.get('profile', 'config')
                        print(f"  {label:<17s}{YL}{diff_lines} diff lines{RS} "
                              f"(running vs '{profile}')")
                        for c in changes:
                            idx_str = ''
                            if c['indices']:
                                idx_str = ': ' + ', '.join(c['indices'])
                            print(f"    {c['label']}{idx_str}")
                pause()

            # ── SAVE ──
            elif op == 'save':
                if not yesno('Save running config to NVM on all devices?'):
                    continue
                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    _, tag, msg = worker_save(device, ip)
                    print(f"  [{tag:4s}] {display_name(ip):<17s}{msg}")
                print(f'\n  {DM}Refreshing...{RS}')
                state = refresh_state(connections)
                pause()

            # ── SAVE WITH ROLLBACK ──
            elif op == 'save-rollback':
                name = ask('Rollback profile name', 'rollback')
                if not yesno(f"Save with rollback profile '{name}'?"):
                    continue
                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    _, tag, data = worker_save_rollback(device, ip, name)
                    label = display_name(ip)
                    if tag == 'FAIL':
                        print(f"  [FAIL] {label:<17s}{data}")
                    else:
                        print(f"  [OK  ] {label:<17s}rollback: '{data['rollback']}'")
                print(f'\n  {DM}Refreshing...{RS}')
                state = refresh_state(connections)
                pause()

            # ── ACTIVATE PROFILE ──
            elif op == 'activate':
                # Show profiles first
                all_profiles = {}
                for ip in config['devices']:
                    device = connections.get(ip)
                    if device:
                        try:
                            all_profiles[ip] = show_profiles(device, ip)
                        except Exception as e:
                            print(f"  {display_name(ip):<17s}{YL}{e}{RS}")

                print()
                raw = ask('Profile index or name to activate')
                if not raw:
                    continue

                # Parse as index or name
                try:
                    target_idx = int(raw)
                    target_name = None
                except ValueError:
                    target_idx = None
                    target_name = raw

                print(f"\n  {YL}WARNING: Activating a profile triggers a warm restart.{RS}")
                print(f"  {YL}Connection will drop and the device will reboot.{RS}")
                if not yesno('Continue?'):
                    continue

                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    try:
                        idx = target_idx
                        if target_name and idx is None:
                            profiles = all_profiles.get(ip, [])
                            match = [p for p in profiles if p.get('name') == target_name]
                            if not match:
                                print(f"  [FAIL] {display_name(ip):<17s}profile '{target_name}' not found")
                                continue
                            idx = match[0]['index']
                        device.activate_profile('nvm', idx)
                        print(f"  {GR}[OK  ]{RS} {display_name(ip):<17s}profile {idx} activated (rebooting)")
                    except Exception as e:
                        err = str(e).lower()
                        if any(t in err for t in ('closed', 'reset', 'timeout', 'eof',
                                                   'broken pipe', 'connection')):
                            print(f"  {GR}[OK  ]{RS} {display_name(ip):<17s}activated (connection dropped)")
                        else:
                            print(f"  {YL}[FAIL]{RS} {display_name(ip):<17s}{e}")

                # Connections are likely dead after activate
                if len(connections) == 1:
                    ip = list(connections.keys())[0]
                    print(f"\n  {DM}Waiting for reboot...{RS}")
                    time.sleep(15)
                    try:
                        device = driver(
                            hostname=ip,
                            username=config['username'],
                            password=config['password'],
                            timeout=30,
                            optional_args={'protocol_preference': [protocol]},
                        )
                        device.open()
                        connections[ip] = device
                        print(f"  {GR}Reconnected to {ip}{RS}")
                        state = refresh_state(connections)
                        show_profiles(device, ip)
                    except Exception as e:
                        print(f"  {YL}Reconnect failed: {e}{RS}")
                        print(f"  {DM}Exiting interactive mode.{RS}")
                        return
                else:
                    print(f"\n  {YL}Devices are rebooting. Exiting interactive mode.{RS}")
                    return
                pause()

            # ── DELETE PROFILE ──
            elif op == 'delete':
                all_profiles = {}
                for ip in config['devices']:
                    device = connections.get(ip)
                    if device:
                        try:
                            all_profiles[ip] = show_profiles(device, ip)
                        except Exception as e:
                            print(f"  {display_name(ip):<17s}{YL}{e}{RS}")

                print()
                raw = ask('Profile index or name to delete')
                if not raw:
                    continue

                try:
                    target_idx = int(raw)
                    target_name = None
                except ValueError:
                    target_idx = None
                    target_name = raw

                if not yesno(f"Delete profile '{raw}'?"):
                    continue

                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    try:
                        profiles = all_profiles.get(ip, [])
                        idx = target_idx
                        if target_name and idx is None:
                            match = [p for p in profiles if p.get('name') == target_name]
                            if not match:
                                print(f"  {YL}[FAIL]{RS} {display_name(ip):<17s}profile '{target_name}' not found")
                                continue
                            idx = match[0]['index']
                        # Refuse active
                        active_match = [p for p in profiles if p.get('index') == idx and p.get('active')]
                        if active_match:
                            print(f"  {YL}[SKIP]{RS} {display_name(ip):<17s}cannot delete active profile")
                            continue
                        device.delete_profile('nvm', idx)
                        print(f"  {GR}[OK  ]{RS} {display_name(ip):<17s}profile {idx} deleted")
                    except Exception as e:
                        print(f"  {YL}[FAIL]{RS} {display_name(ip):<17s}{e}")

                print(f'\n  {DM}Refreshing...{RS}')
                state = refresh_state(connections)
                pause()

            # ── HIDISCOVERY ──
            elif op == 'hidiscovery':
                # Show current state first
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    try:
                        hd = device.get_hidiscovery()
                        print(f"  {display_name(ip):<17s}{format_hidiscovery(hd)}")
                    except Exception as e:
                        print(f"  {display_name(ip):<17s}{YL}{e}{RS}")

                print()
                mode = pick('HiDiscovery mode', [
                    ('On (read-write)',  'on'),
                    ('Read-only',        'read-only'),
                    ('Off',              'off'),
                    ('Skip (no change)', None),
                ])

                blink = pick('Blinking', [
                    ('On',               True),
                    ('Off',              False),
                    ('Skip (no change)', None),
                ])

                if mode is None and blink is None:
                    continue

                save_nvm = yesno('Save to NVM?')

                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    _, tag, detail = worker_hidiscovery(device, ip, mode, blink, save_nvm)
                    if tag == 'OK':
                        before = format_hidiscovery(detail['before'])
                        after = format_hidiscovery(detail['after'])
                        print(f"  {GR}[OK  ]{RS} {display_name(ip):<17s}{before}  ->  {after}")
                    else:
                        print(f"  {YL}[FAIL]{RS} {display_name(ip):<17s}{detail}")
                pause()

            # ── RESET ──
            elif op == 'reset':
                mode = pick('Reset type', [
                    ('Soft reset',                         'soft'),
                    ('Soft reset (keep management IP)',     'soft-keep'),
                    ('Factory reset',                      'factory'),
                    ('Factory reset + erase all NVM',      'factory-erase'),
                ])

                factory = mode in ('factory', 'factory-erase')
                keep_ip = mode == 'soft-keep'
                erase_all = mode == 'factory-erase'

                print(f"\n  {YL}WARNING: This will reset {len(connections)} device(s).{RS}")
                if not yesno('Continue?'):
                    continue

                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    _, tag, msg = worker_reset(device, ip, factory, keep_ip, erase_all)
                    print(f"  [{tag:4s}] {display_name(ip):<17s}{msg}")

                print(f"\n  {DM}Devices resetting. Exiting interactive mode.{RS}")
                return

            # ── ONBOARD ──
            elif op == 'onboard':
                new_pw = ask('New password for onboarded device')
                if not new_pw:
                    print(f"  {YL}Password required.{RS}")
                    pause()
                    continue
                save_nvm = yesno('Save after onboarding?', default=True)

                print()
                for ip in config['devices']:
                    device = connections.get(ip)
                    if not device:
                        continue
                    _, tag, msg = worker_onboard(device, ip, new_pw, save_nvm)
                    print(f"  [{tag:4s}] {display_name(ip):<17s}{msg}")

                print(f'\n  {DM}Refreshing...{RS}')
                state = refresh_state(connections)
                pause()

        # ── QUIT ──
        close_all(connections)
        print(f'\n  {DM}Later.{RS}\n')

    except KeyboardInterrupt:
        close_all(connections)
        print(f'\n\n  {DM}Interrupted.{RS}\n')
    except EOFError:
        close_all(connections)
        print(f'\n\n  {DM}Bye.{RS}\n')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    # Interactive mode entry points:
    # 1. Explicit -i flag or 'interactive' subcommand
    # 2. No subcommand given AND no script.cfg → auto-enter interactive
    enter_interactive = (
        args.interactive
        or args.command == 'interactive'
        or (not args.command and not args.b
            and not os.path.exists(get_resource_path(args.c)))
    )

    # Default to status if no subcommand (and not interactive)
    if not args.command and not enter_interactive:
        args.command = 'status'

    # Silent mode — suppress stdout, errors still go to stderr
    if args.silent:
        sys.stdout = open(os.devnull, 'w')

    # Logging setup
    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir, f'mohawc_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        filename=log_filename,
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if args.debug else logging.WARNING)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger().addHandler(console)

    lib_level = logging.DEBUG if args.debug else logging.WARNING
    for lib in ('paramiko', 'napalm', 'netmiko', 'urllib3', 'requests'):
        logging.getLogger(lib).setLevel(lib_level)
    if args.debug:
        logging.getLogger('napalm_hios.mops_client').setLevel(logging.DEBUG)

    start_time = time.time()

    try:
        config = resolve_config(args)

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        # ── Interactive mode ──
        if enter_interactive:
            return interactive_mode(args, config, driver)

        # Validate --entry is in device list (catch early, even in dry-run)
        if args.command == 'reset' and args.entry and args.entry not in config['devices']:
            print(f"\n  ERROR: --entry {args.entry} is not in the device list\n", file=sys.stderr)
            sys.exit(1)

        print_banner('BLINK TOGGLE' if args.b else args.command, config)

        if args.dry_run:
            print("\n  Devices:")
            for ip in config['devices']:
                print(f"    {display_name(ip)}")
            print("\n  [DRY RUN] No connections will be made.\n")
            return

        # -b shortcut: toggle blink and exit
        if args.b:
            connections = connect_all(driver, config)
            if not connections:
                sys.exit(1)

            results = []
            with ThreadPoolExecutor(max_workers=len(connections)) as pool:
                futures = {
                    pool.submit(worker_blink_toggle, device, ip): ip
                    for ip, device in connections.items()
                }
                for future in as_completed(futures):
                    ip, tag, detail = future.result()
                    results.append((ip, tag, detail))

            for ip in config['devices']:
                result = next((r for r in results if r[0] == ip), None)
                if not result:
                    continue
                _, tag, detail = result
                if tag == 'OK':
                    before = format_hidiscovery(detail['before'])
                    after = format_hidiscovery(detail['after'])
                    print(f"\n  [OK  ] {display_name(ip):<17s}{before}  ->  {after}")
                else:
                    print(f"\n  [FAIL] {display_name(ip):<17s}{detail}")

            close_all(connections)
            reached = sum(1 for _, s, _ in results if s == 'OK')
            elapsed = time.time() - start_time
            print_footer(len(config['devices']), reached, elapsed)
            return

        dispatch = {
            'status': cmd_status,
            'onboard': cmd_onboard,
            'hidiscovery': cmd_hidiscovery,
            'save': cmd_save,
            'reset': cmd_reset,
            'diff': cmd_diff,
            'save-rollback': cmd_save_rollback,
            'profiles': cmd_profiles,
            'activate': cmd_activate,
            'delete': cmd_delete,
            'download': cmd_download,
        }

        handler = dispatch[args.command]
        reached = handler(args, config, driver)

        elapsed = time.time() - start_time
        print_footer(len(config['devices']), reached, elapsed)

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"\n  FATAL: {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
