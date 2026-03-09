#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""ADAM — Automated Device Audit Model

Parse HiOS XML config exports, classify ports, audit for correctness,
compare against template/site. Zero external dependencies.
"""

from __future__ import print_function
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NS = 'urn:xml:ns:mibconf:base:1.0'
NS_PREFIX = '{%s}' % NS

SW_LEVELS = ['L2S', 'L2E', 'L2A', 'L3S', 'L3A_UR', 'L3A_MR']

# HiOS enum mappings (from napalm-hios mops_hios.py)
MRP_ROLE = {1: 'client', 2: 'manager'}
SRM_ROLE = {1: 'manager', 2: 'redundant-manager', 3: 'single-manager'}
MRP_RING_STATE = {1: 'open', 2: 'closed'}
STP_VERSION = {1: 'stp', 2: 'rstp', 3: 'mstp'}
AUTO_DISABLE_REASONS = {
    1: 'link-flap', 2: 'crc-error', 3: 'overload-detection',
    4: 'speed-duplex', 5: 'link-change', 6: 'bpdu-rate',
    7: 'dhcp', 8: 'arp-rate', 9: 'port-security',
    10: 'loop-protection',
}
LOOP_PROT_MODE = {1: 'active', 2: 'passive'}
LOOP_PROT_ACTION = {10: 'trap', 11: 'auto-disable', 12: 'all'}
HIOS_BOOL = {1: True, 2: False}

SEVERITY_ORDER = {'critical': 0, 'warning': 1, 'info': 2}

# ANSI color codes
class C:
    RED = '\033[91m'
    YEL = '\033[93m'
    GRN = '\033[92m'
    CYN = '\033[96m'
    WHT = '\033[97m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    RST = '\033[0m'

NO_COLOR = type('NC', (), {k: '' for k in dir(C) if not k.startswith('_')})()

# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def decode_hex_string(val):
    """Decode hex-encoded ASCII string like '41 44 41 4D' -> 'ADAM'."""
    if not val or not val.strip():
        return ''
    try:
        return bytes(int(b, 16) for b in val.split()).decode('ascii', errors='replace').strip()
    except (ValueError, TypeError):
        return val.strip()


def decode_hex_ip(val):
    """Decode hex IP like 'C0 A8 01 04' -> '192.168.1.4'."""
    if not val or not val.strip():
        return '0.0.0.0'
    parts = val.split()
    if len(parts) != 4:
        return val.strip()
    try:
        return '.'.join(str(int(b, 16)) for b in parts)
    except ValueError:
        return val.strip()


def parse_portlist(val):
    """Parse portlist string 'cpu/1,1/1,1/2,vlan/1' -> list of port strings."""
    if not val or not val.strip():
        return []
    return [p.strip() for p in val.split(',') if p.strip()]


def physical_ports_only(ports):
    """Filter to physical ports only (N/M format, exclude cpu/N, vlan/N, lag/N)."""
    return [p for p in ports if '/' in p and not any(
        p.startswith(pfx) for pfx in ('cpu/', 'vlan/', 'lag/'))]


def port_sort_key(port):
    """Sort key for port strings like '1/1', '2/8'."""
    parts = port.split('/')
    try:
        return (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        return (999, 999)


def _mask_to_prefix(mask):
    """Convert dotted netmask to prefix length: '255.255.255.0' -> 24."""
    try:
        parts = [int(x) for x in mask.split('.')]
        bits = ''.join(format(p, '08b') for p in parts)
        return bits.count('1')
    except (ValueError, AttributeError):
        return 0


def sw_level_ge(level, required):
    """Check if level >= required in the SW level hierarchy."""
    if level not in SW_LEVELS or required not in SW_LEVELS:
        return False
    return SW_LEVELS.index(level) >= SW_LEVELS.index(required)


# ---------------------------------------------------------------------------
# XML Parser
# ---------------------------------------------------------------------------

def parse_config(xml_path):
    """Parse HiOS XML config into structured dict.

    Returns {'header': {...}, 'mibs': {'MIB-NAME': {'scalars': {...}, 'tables': {...}}}}
    Handles duplicate MIB names by merging.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Parse header
    header = {}
    header_el = root.find(NS_PREFIX + 'Header')
    if header_el is not None:
        for var in header_el.findall(NS_PREFIX + 'Variable'):
            header[var.get('name', '')] = var.text or ''

    # Parse MIB data
    mibs = {}
    mibdata = root.find(NS_PREFIX + 'MibData')
    if mibdata is None:
        return {'header': header, 'mibs': mibs}

    for mib_el in mibdata.findall(NS_PREFIX + 'MIB'):
        mib_name = mib_el.get('name', '')
        if not mib_name:
            continue

        # Merge into existing if duplicate MIB name
        if mib_name not in mibs:
            mibs[mib_name] = {'scalars': {}, 'tables': {}}

        mib = mibs[mib_name]

        for child in mib_el:
            tag = child.tag.replace(NS_PREFIX, '')

            if tag == 'Scalar':
                scalar_name = child.get('name', '')
                attrs = {}
                for attr in child.findall(NS_PREFIX + 'Attribute'):
                    name = attr.get('name', '')
                    convert = attr.get('convert', '')
                    val = attr.text or ''
                    attrs[name] = _convert_attr(val, convert)
                # Merge into existing scalar group
                if scalar_name in mib['scalars']:
                    mib['scalars'][scalar_name].update(attrs)
                else:
                    mib['scalars'][scalar_name] = attrs

            elif tag == 'Table':
                table_name = child.get('name', '')
                entries = []
                for entry_el in child.findall(NS_PREFIX + 'Entry'):
                    entry = {}
                    for attr in entry_el.findall(NS_PREFIX + 'Attribute'):
                        name = attr.get('name', '')
                        convert = attr.get('convert', '')
                        val = attr.text or ''
                        entry[name] = _convert_attr(val, convert)
                    entries.append(entry)
                # Merge: append entries to existing table
                if table_name in mib['tables']:
                    mib['tables'][table_name].extend(entries)
                else:
                    mib['tables'][table_name] = entries

    return {'header': header, 'mibs': mibs}


def _convert_attr(val, convert):
    """Convert attribute value based on convert type."""
    val = val.strip() if val else ''
    if convert == 'ascii':
        return val
    if convert == 'ifname':
        return val
    if convert == 'portlist':
        return val  # stored raw, parsed on demand
    if convert == 'scrambled':
        return '<scrambled>'
    if convert == 'ipv6':
        return val
    # Default: try integer, fall back to string
    if val:
        try:
            return int(val)
        except ValueError:
            pass
    return val


# ---------------------------------------------------------------------------
# Fact Extraction
# ---------------------------------------------------------------------------

def get_facts(config):
    """Extract device identity and port inventory from parsed config."""
    h = config['header']
    mibs = config['mibs']

    product_id = h.get('productId', '')
    fw_major = h.get('swMajorRelNum', '0')
    fw_minor = h.get('swMinorRelNum', '0')
    fw_bug = h.get('swBugfixRelNum', '0')
    firmware = '%s.%s.%02d' % (fw_major, fw_minor, int(fw_bug))

    # Hostname from SNMPv2-MIB
    hostname = ''
    location = ''
    snmpv2 = mibs.get('SNMPv2-MIB', {})
    system_scalar = snmpv2.get('scalars', {}).get('system', {})
    hostname = system_scalar.get('sysName', '')
    location = system_scalar.get('sysLocation', '')

    # Management IP from HM2-NETCONFIG-MIB
    mgmt_ip = '0.0.0.0'
    netcfg = mibs.get('HM2-NETCONFIG-MIB', {})
    static_group = netcfg.get('scalars', {}).get('hm2NetStaticGroup', {})
    ip_raw = static_group.get('hm2NetLocalIPAddr', '')
    if isinstance(ip_raw, str) and ' ' in ip_raw:
        mgmt_ip = decode_hex_ip(ip_raw)
    elif isinstance(ip_raw, str):
        mgmt_ip = ip_raw

    prefix_len = static_group.get('hm2NetPrefixLength', 0)
    gw_raw = static_group.get('hm2NetGatewayIPAddr', '')
    if isinstance(gw_raw, str) and ' ' in gw_raw:
        gateway = decode_hex_ip(gw_raw)
    elif isinstance(gw_raw, str):
        gateway = gw_raw
    else:
        gateway = '0.0.0.0'

    # Collect all VLAN interface IPs from HM2-PLATFORM-ROUTING-MIB
    vlan_ips = {}  # 'vlan/N' -> {'ip': x, 'mask': y, 'prefix': z}
    routing_mib = mibs.get('HM2-PLATFORM-ROUTING-MIB', {})
    ip_intf_table = routing_mib.get('tables', {}).get(
        'hm2AgentSwitchIpInterfaceEntry', [])
    for entry in ip_intf_table:
        ifidx = entry.get('hm2AgentSwitchIpInterfaceIfIndex', '')
        if not str(ifidx).startswith('vlan/'):
            continue
        ip_val = entry.get('hm2AgentSwitchIpInterfaceIpAddress', '')
        if isinstance(ip_val, str) and ' ' in ip_val:
            ip_val = decode_hex_ip(ip_val)
        if not ip_val or ip_val == '0.0.0.0':
            continue
        mask = entry.get('hm2AgentSwitchIpInterfaceNetMask', '0.0.0.0')
        vlan_ips[ifidx] = {
            'ip': ip_val,
            'mask': mask,
            'prefix': _mask_to_prefix(mask) if mask != '0.0.0.0' else 0,
        }

    # L3 devices may have 0.0.0.0 flat mgmt IP — VLAN IPs serve that role
    # Both are reported; a system check flags 0.0.0.0 with no VLAN IPs

    # Ports from IF-MIB
    ports = []
    port_admin = {}
    if_mib = mibs.get('IF-MIB', {})
    if_entries = if_mib.get('tables', {}).get('ifEntry', [])
    for entry in if_entries:
        ifname = entry.get('ifIndex', '')
        iftype = entry.get('ifType', 0)
        admin = entry.get('ifAdminStatus', 1)
        if iftype == 6:  # ethernetCsmacd = physical port
            ports.append(ifname)
            port_admin[ifname] = HIOS_BOOL.get(admin, admin == 1)

    # Also collect vlan/N interfaces for L3 visibility
    vlan_interfaces = []
    for entry in if_entries:
        ifname = entry.get('ifIndex', '')
        iftype = entry.get('ifType', 0)
        if iftype == 135:  # l2vlan
            vlan_interfaces.append(ifname)

    ports.sort(key=port_sort_key)

    # SW level inference
    sw_level = _infer_sw_level(product_id, mibs)

    # Product family from product_id
    family = product_id.split('_')[0].upper() if product_id else ''

    return {
        'product_id': product_id,
        'family': family,
        'firmware': firmware,
        'hostname': hostname,
        'location': location,
        'mgmt_ip': mgmt_ip,
        'prefix_len': prefix_len,
        'gateway': gateway,
        'sw_level': sw_level,
        'ports': ports,
        'port_admin': port_admin,
        'vlan_interfaces': vlan_interfaces,
        'vlan_ips': vlan_ips,
    }


def _infer_sw_level(product_id, mibs):
    """Infer software level from product ID or MIB presence."""
    pid = product_id.lower()

    # Check for L3 routing MIB presence
    has_routing = 'HM2-PLATFORM-ROUTING-MIB' in mibs
    has_ospf = 'OSPF-MIB' in mibs
    has_vrrp = 'VRRP-MIB' in mibs

    if has_routing:
        # Check for multicast routing (MR indicator)
        has_mcast = 'HM2-PLATFORM-MULTICAST-MIB' in mibs or 'IPMROUTE-STD-MIB' in mibs
        if has_mcast:
            return 'L3A_MR'
        if has_ospf or has_vrrp:
            return 'L3A_UR'
        return 'L3S'

    # L2 levels: check for advanced features
    # L2A has more MIBs than L2E/L2S
    has_acl = 'HM2-PLATFORM-QOS-ACL-MIB' in mibs
    has_dot1x = 'IEEE8021-PAE-MIB' in mibs

    if has_acl and has_dot1x:
        return 'L2A'
    if has_dot1x:
        return 'L2E'
    return 'L2S'


# ---------------------------------------------------------------------------
# Component Discovery
# ---------------------------------------------------------------------------

def discover_components(config, facts):
    """Discover active logical and physical components from MIB sections."""
    mibs = config['mibs']
    components = {}

    # VLANs from Q-BRIDGE-MIB
    components['vlans'] = _discover_vlans(mibs)

    # PVID per port
    components['pvid'] = _discover_pvid(mibs)

    # MRP rings
    components['mrp'] = _discover_mrp(mibs)

    # Sub-rings (SRM)
    components['srm_global'] = _discover_srm_global(mibs)
    components['srm'] = _discover_srm(mibs)

    # RSTP / STP
    components['rstp_global'] = _discover_rstp_global(mibs)
    components['rstp_ports'] = _discover_rstp_ports(mibs)
    components['stp_port_state'] = _discover_stp_port_state(mibs)

    # Loop protection
    components['loop_prot_global'] = _discover_loop_prot_global(mibs)
    components['loop_prot_ports'] = _discover_loop_prot_ports(mibs)

    # Auto-disable
    components['auto_disable_reasons'] = _discover_auto_disable_reasons(mibs)
    components['auto_disable_timers'] = _discover_auto_disable_timers(mibs)

    # SNMP communities
    components['snmp_communities'] = _discover_snmp_communities(mibs)

    # Users
    components['users'] = _discover_users(mibs)

    # LAG
    components['lag_members'] = _discover_lag_members(mibs)

    # Security settings
    components['security'] = _discover_security(mibs)

    # Network security features (Ch.3)
    components['net_security'] = _discover_network_security(mibs)

    return components


def _discover_vlans(mibs):
    qbridge = mibs.get('Q-BRIDGE-MIB', {})
    entries = qbridge.get('tables', {}).get('dot1qVlanStaticEntry', [])
    vlans = {}
    for e in entries:
        vid = e.get('dot1qVlanIndex', 0)
        if isinstance(vid, str):
            try:
                vid = int(vid)
            except ValueError:
                continue
        name_raw = e.get('dot1qVlanStaticName', '')
        name = decode_hex_string(name_raw) if name_raw and ' ' in str(name_raw) else str(name_raw)
        egress = parse_portlist(e.get('dot1qVlanStaticEgressPorts', ''))
        untagged = parse_portlist(e.get('dot1qVlanStaticUntaggedPorts', ''))
        vlans[vid] = {
            'name': name,
            'egress': egress,
            'untagged': untagged,
            'egress_phys': physical_ports_only(egress),
            'untagged_phys': physical_ports_only(untagged),
        }
    return vlans


def _discover_pvid(mibs):
    qbridge = mibs.get('Q-BRIDGE-MIB', {})
    entries = qbridge.get('tables', {}).get('dot1qPortVlanEntry', [])
    pvid = {}
    for e in entries:
        port = e.get('dot1dBasePort', '')
        vid = e.get('dot1qPvid', 1)
        if isinstance(vid, str):
            try:
                vid = int(vid)
            except ValueError:
                vid = 1
        pvid[port] = vid
    return pvid


def _discover_mrp(mibs):
    l2red = mibs.get('HM2-L2REDUNDANCY-MIB', {})
    entries = l2red.get('tables', {}).get('hm2MrpEntry', [])
    rings = []
    for e in entries:
        row_status = e.get('hm2MrpRowStatus', 0)
        if row_status not in (1, 4):  # active or createAndGo
            continue
        domain_raw = e.get('hm2MrpDomainName', '')
        domain = decode_hex_string(domain_raw) if ' ' in str(domain_raw) else str(domain_raw)
        domain_id = e.get('hm2MrpDomainID', '')
        rings.append({
            'domain': domain,
            'domain_id': domain_id,
            'port1': e.get('hm2MrpRingport1IfIndex', ''),
            'port2': e.get('hm2MrpRingport2IfIndex', ''),
            'role': MRP_ROLE.get(e.get('hm2MrpRoleAdminState', 0), 'unknown'),
            'vlan': e.get('hm2MrpVlanID', 0),
        })
    return rings


def _discover_srm_global(mibs):
    l2red = mibs.get('HM2-L2REDUNDANCY-MIB', {})
    cfg = l2red.get('scalars', {}).get('hm2SrmMibGroup', {})
    if not cfg:
        return None
    return {
        'enabled': HIOS_BOOL.get(cfg.get('hm2SrmGlobalAdminState', 2), False),
    }


def _discover_srm(mibs):
    l2red = mibs.get('HM2-L2REDUNDANCY-MIB', {})
    entries = l2red.get('tables', {}).get('hm2SrmEntry', [])
    subrings = []
    for e in entries:
        row_status = e.get('hm2SrmRowStatus', 0)
        if row_status not in (1, 2, 4):  # active, notInService, createAndGo
            continue
        subrings.append({
            'ring_id': e.get('hm2SrmRingID', 0),
            'vlan': e.get('hm2SrmVlanID', 0),
            'role': SRM_ROLE.get(e.get('hm2SrmAdminState', 0), 'unknown'),
            'port': e.get('hm2SrmSubRingPortIfIndex', ''),
            'row_status': row_status,
        })
    return subrings


def _discover_rstp_global(mibs):
    switching = mibs.get('HM2-PLATFORM-SWITCHING-MIB', {})
    cfg = switching.get('scalars', {}).get('hm2AgentStpSwitchConfigGroup', {})
    if not cfg:
        return None
    return {
        'admin_mode': HIOS_BOOL.get(cfg.get('hm2AgentStpAdminMode', 2), False),
        'force_version': STP_VERSION.get(cfg.get('hm2AgentStpForceVersion', 2), 'rstp'),
        'bpdu_guard': HIOS_BOOL.get(cfg.get('hm2AgentStpBpduGuardMode', 2), False),
        'bpdu_filter_default': HIOS_BOOL.get(cfg.get('hm2AgentStpBpduFilterDefault', 2), False),
    }


def _discover_rstp_ports(mibs):
    switching = mibs.get('HM2-PLATFORM-SWITCHING-MIB', {})
    entries = switching.get('tables', {}).get('hm2AgentStpCstPortEntry', [])
    ports = {}
    for e in entries:
        port = e.get('ifIndex', '')
        ports[port] = {
            'edge': HIOS_BOOL.get(e.get('hm2AgentStpCstPortEdge', 2), False),
            'auto_edge': HIOS_BOOL.get(e.get('hm2AgentStpCstPortAutoEdge', 2), False),
            'bpdu_filter': HIOS_BOOL.get(e.get('hm2AgentStpCstPortBpduFilter', 2), False),
            'root_guard': HIOS_BOOL.get(e.get('hm2AgentStpCstPortRootGuard', 2), False),
            'loop_guard': HIOS_BOOL.get(e.get('hm2AgentStpCstPortLoopGuard', 2), False),
        }
    return ports


def _discover_stp_port_state(mibs):
    switching = mibs.get('HM2-PLATFORM-SWITCHING-MIB', {})
    entries = switching.get('tables', {}).get('hm2AgentStpPortEntry', [])
    states = {}
    for e in entries:
        port = e.get('ifIndex', '')
        states[port] = HIOS_BOOL.get(e.get('hm2AgentStpPortState', 2), False)
    return states


def _discover_loop_prot_global(mibs):
    switching = mibs.get('HM2-PLATFORM-SWITCHING-MIB', {})
    cfg = switching.get('scalars', {}).get('hm2AgentSwitchKeepaliveGroup', {})
    if not cfg:
        return None
    return {
        'enabled': HIOS_BOOL.get(cfg.get('hm2AgentSwitchKeepaliveState', 2), False),
        'tx_interval': cfg.get('hm2AgentSwitchKeepaliveTransmitInterval', 5),
    }


def _discover_loop_prot_ports(mibs):
    switching = mibs.get('HM2-PLATFORM-SWITCHING-MIB', {})
    entries = switching.get('tables', {}).get('hm2AgentKeepalivePortEntry', [])
    ports = {}
    for e in entries:
        port = e.get('ifIndex', '')
        ports[port] = {
            'enabled': HIOS_BOOL.get(e.get('hm2AgentKeepalivePortState', 2), False),
            'mode': LOOP_PROT_MODE.get(e.get('hm2AgentKeepalivePortMode', 0), 'unknown'),
            'action': LOOP_PROT_ACTION.get(e.get('hm2AgentKeepalivePortRxAction', 0), 'unknown'),
        }
    return ports


def _discover_auto_disable_reasons(mibs):
    devmgmt = mibs.get('HM2-DEVMGMT-MIB', {})
    entries = devmgmt.get('tables', {}).get('hm2AutoDisableReasonEntry', [])
    reasons = {}
    for e in entries:
        reason_id = e.get('hm2AutoDisableReasons', 0)
        if isinstance(reason_id, str):
            try:
                reason_id = int(reason_id)
            except ValueError:
                continue
        op = e.get('hm2AutoDisableReasonOperation', 2)
        name = AUTO_DISABLE_REASONS.get(reason_id, 'reason-%d' % reason_id)
        reasons[name] = HIOS_BOOL.get(op, False)
    return reasons


def _discover_auto_disable_timers(mibs):
    devmgmt = mibs.get('HM2-DEVMGMT-MIB', {})
    entries = devmgmt.get('tables', {}).get('hm2AutoDisableIntfEntry', [])
    timers = {}
    for e in entries:
        port = e.get('ifIndex', '')
        timer = e.get('hm2AutoDisableIntfTimer', 0)
        if isinstance(timer, str):
            try:
                timer = int(timer)
            except ValueError:
                timer = 0
        timers[port] = timer
    return timers


def _discover_snmp_communities(mibs):
    comm_mib = mibs.get('SNMP-COMMUNITY-MIB', {})
    entries = comm_mib.get('tables', {}).get('snmpCommunityEntry', [])
    communities = []
    for e in entries:
        name = e.get('snmpCommunityName', '')
        status = e.get('snmpCommunityStatus', 0)
        if status == 1:  # active
            communities.append(name)
    return communities


def _discover_users(mibs):
    usermgmt = mibs.get('HM2-USERMGMT-MIB', {})
    entries = usermgmt.get('tables', {}).get('hm2UserConfigEntry', [])
    users = []
    for e in entries:
        name = e.get('hm2UserName', '')
        role = e.get('hm2UserAccessRole', 0)
        status = e.get('hm2UserStatus', 0)
        if isinstance(role, str):
            try:
                role = int(role)
            except ValueError:
                role = 0
        users.append({
            'name': name,
            'role': 'admin' if role >= 8 else 'read-only',
            'role_id': role,
            'active': status == 1,
        })
    return users


def _discover_lag_members(mibs):
    lag_mib = mibs.get('LAG-MIB', {})
    entries = lag_mib.get('tables', {}).get('dot3adAggPortEntry', [])
    members = {}  # port -> lag_key
    for e in entries:
        port = e.get('dot3adAggPortIndex', '')
        key = e.get('dot3adAggPortActorAdminKey', 0)
        if isinstance(key, str):
            try:
                key = int(key)
            except ValueError:
                key = 0
        if key > 0:
            members[port] = key
    return members


def _discover_security(mibs):
    """Extract security-related settings from multiple MIBs."""
    sec = {}

    # HiDiscovery — HM2-NETWORK-MIB
    net_mib = mibs.get('HM2-NETWORK-MIB', {})
    hidisc = net_mib.get('scalars', {}).get('hm2NetHiDiscoveryGroup', {})
    HIDISC_MODE = {1: 'readWrite', 2: 'readOnly', 3: 'off'}
    sec['hidiscovery_operation'] = HIOS_BOOL.get(hidisc.get('hm2NetHiDiscoveryOperation', 2), False)
    sec['hidiscovery_mode'] = HIDISC_MODE.get(hidisc.get('hm2NetHiDiscoveryMode', 1), 'readWrite')

    # Management protocols — HM2-MGMTACCESS-MIB
    mgmt = mibs.get('HM2-MGMTACCESS-MIB', {})
    mgmt_s = mgmt.get('scalars', {})

    web = mgmt_s.get('hm2MgmtAccessWebGroup', {})
    sec['http_enabled'] = HIOS_BOOL.get(web.get('hm2WebHttpAdminStatus', 2), False)
    sec['https_enabled'] = HIOS_BOOL.get(web.get('hm2WebHttpsAdminStatus', 2), False)
    sec['web_timeout'] = web.get('hm2WebIntfTimeOut', 0)

    telnet = mgmt_s.get('hm2MgmtAccessTelnetGroup', {})
    sec['telnet_enabled'] = HIOS_BOOL.get(telnet.get('hm2TelnetServerAdminStatus', 2), False)
    sec['telnet_timeout'] = telnet.get('hm2TelnetServerSessionsTimeOut', 0)

    ssh = mgmt_s.get('hm2MgmtAccessSshGroup', {})
    sec['ssh_enabled'] = HIOS_BOOL.get(ssh.get('hm2SshAdminStatus', 2), False)
    sec['ssh_timeout'] = ssh.get('hm2SshSessionTimeout', 0)

    snmp = mgmt_s.get('hm2MgmtAccessSnmpGroup', {})
    sec['snmpv1_enabled'] = HIOS_BOOL.get(snmp.get('hm2SnmpV1AdminStatus', 2), False)
    sec['snmpv2_enabled'] = HIOS_BOOL.get(snmp.get('hm2SnmpV2AdminStatus', 2), False)
    sec['snmpv3_enabled'] = HIOS_BOOL.get(snmp.get('hm2SnmpV3AdminStatus', 2), False)

    # Login banner — HM2-MGMTACCESS-MIB
    cli = mgmt_s.get('hm2MgmtAccessCliGroup', {})
    sec['cli_timeout'] = cli.get('hm2CliLoginTimeoutSerial', 0)
    sec['cli_banner_enabled'] = HIOS_BOOL.get(cli.get('hm2CliLoginBannerAdminStatus', 2), False)
    sec['cli_banner_text'] = cli.get('hm2CliLoginBannerText', '')

    prelogin = mgmt_s.get('hm2MgmtAccessPreLoginBannerGroup', {})
    sec['prelogin_banner_enabled'] = HIOS_BOOL.get(prelogin.get('hm2PreLoginBannerAdminStatus', 2), False)
    sec['prelogin_banner_text'] = prelogin.get('hm2PreLoginBannerText', '')

    # IP access restrictions — HM2-MGMTACCESS-MIB
    rma = mgmt_s.get('hm2RestrictedMgmtAccessGroup', {})
    sec['rma_enabled'] = HIOS_BOOL.get(rma.get('hm2RmaOperation', 2), False)
    rma_entries = mgmt.get('tables', {}).get('hm2RmaEntry', [])
    sec['rma_rules'] = sum(1 for e in rma_entries if e.get('hm2RmaRowStatus', 0) == 1)

    # Industrial protocols — HM2-INDUSTRIAL-PROTOCOLS-MIB
    indust = mibs.get('HM2-INDUSTRIAL-PROTOCOLS-MIB', {})
    indust_s = indust.get('scalars', {})

    modbus = indust_s.get('hm2ModbusConfigGroup', {})
    sec['modbus_enabled'] = HIOS_BOOL.get(modbus.get('hm2ModbusTcpServerAdminStatus', 2), False)

    eip = indust_s.get('hm2EthernetIPConfigGroup', {})
    sec['ethernetip_enabled'] = HIOS_BOOL.get(eip.get('hm2EtherNetIPAdminStatus', 2), False)

    pnio = indust_s.get('hm2ProfinetIOConfigGroup', {})
    sec['profinet_enabled'] = HIOS_BOOL.get(pnio.get('hm2PNIOAdminStatus', 2), False)

    iec = indust_s.get('hm2Iec61850ConfigGroup', {})
    sec['iec61850_enabled'] = HIOS_BOOL.get(iec.get('hm2Iec61850MmsServerAdminStatus', 2), False)

    # Unsigned SW / ACA — HM2-DEVICE-MGMT-MIB (may be HM2-DEVMGMT-MIB)
    for mib_name in ('HM2-DEVICE-MGMT-MIB', 'HM2-DEVMGMT-MIB'):
        dm = mibs.get(mib_name, {})
        sw_grp = dm.get('scalars', {}).get('hm2DeviceMgmtSoftwareVersionGroup', {})
        if sw_grp:
            sec['allow_unsigned_sw'] = HIOS_BOOL.get(sw_grp.get('hm2DevMgmtSwVersAllowUnsigned', 2), False)
            break
    else:
        sec['allow_unsigned_sw'] = None  # MIB not found

    # Login policy + password policy — HM2-USER-MGMT-MIB (may be HM2-USERMGMT-MIB)
    for mib_name in ('HM2-USER-MGMT-MIB', 'HM2-USERMGMT-MIB'):
        um = mibs.get(mib_name, {})
        pwd = um.get('scalars', {}).get('hm2PwdMgmtGroup', {})
        if pwd:
            sec['pwd_min_length'] = pwd.get('hm2PwdMgmtMinLength', 0)
            sec['login_attempts'] = pwd.get('hm2PwdMgmtLoginAttempts', 0)
            sec['login_lockout'] = pwd.get('hm2PwdMgmtLoginAttemptsTimePeriod', 0)
            sec['pwd_min_upper'] = pwd.get('hm2PwdMgmtMinUpperCase', 0)
            sec['pwd_min_lower'] = pwd.get('hm2PwdMgmtMinLowerCase', 0)
            sec['pwd_min_digits'] = pwd.get('hm2PwdMgmtMinNumericNumbers', 0)
            sec['pwd_min_special'] = pwd.get('hm2PwdMgmtMinSpecialCharacters', 0)
            break
    else:
        sec['pwd_min_length'] = None

    # Time sync — HM2-TIMESYNC-MIB
    ts = mibs.get('HM2-TIMESYNC-MIB', {})
    sntp_srv = ts.get('scalars', {}).get('hm2SntpServerGroup', {})
    sec['sntp_enabled'] = HIOS_BOOL.get(sntp_srv.get('hm2SntpServerAdminState', 2), False)

    # Syslog — HM2-LOG-MIB
    log_mib = mibs.get('HM2-LOG-MIB', {})
    syslog = log_mib.get('scalars', {}).get('hm2LogSyslogGroup', {})
    sec['syslog_enabled'] = HIOS_BOOL.get(syslog.get('hm2LogSyslogAdminStatus', 2), False)
    syslog_entries = log_mib.get('tables', {}).get('hm2LogSyslogServerEntry', [])
    sec['syslog_servers'] = sum(1 for e in syslog_entries if e.get('hm2LogSyslogServerRowStatus', 0) == 1)

    # ACA / External memory — HM2-DEVMGMT-MIB
    for mib_name in ('HM2-DEVICE-MGMT-MIB', 'HM2-DEVMGMT-MIB'):
        dm = mibs.get(mib_name, {})
        nvm_entries = dm.get('tables', {}).get('hm2ExtNvmEntry', [])
        if nvm_entries:
            # Take first entry (index 2 = ACA slot)
            nvm = nvm_entries[0]
            sec['aca_auto_sw_load'] = HIOS_BOOL.get(nvm.get('hm2ExtNvmAutomaticSoftwareLoad', 2), False)
            sec['aca_config_save'] = HIOS_BOOL.get(nvm.get('hm2ExtNvmConfigSave', 2), False)
            sec['aca_config_load_priority'] = HIOS_BOOL.get(nvm.get('hm2ExtNvmConfigLoadPriority', 2), False)
            break
    else:
        sec['aca_auto_sw_load'] = None
        sec['aca_config_save'] = None
        sec['aca_config_load_priority'] = None

    # Management VLAN — HM2-NETCONFIG-MIB
    netcfg = mibs.get('HM2-NETCONFIG-MIB', {})
    net_static = netcfg.get('scalars', {}).get('hm2NetStaticGroup', {})
    sec['mgmt_vlan'] = net_static.get('hm2NetVlanID', 1)

    # Session timeouts — already extracted above (web_timeout, ssh_timeout,
    # telnet_timeout, cli_timeout), add the SNMP trap timeout
    sec['snmp_trap_enabled'] = HIOS_BOOL.get(snmp.get('hm2SnmpTrapServiceAdminStatus', 2), False)

    # SNMPv1 trap detection — SNMP-TARGET-MIB
    target_mib = mibs.get('SNMP-TARGET-MIB', {})
    # Check params for v1 (MPModel=0) or v2c (MPModel=1) trap configs
    params_entries = target_mib.get('tables', {}).get('snmpTargetParamsEntry', [])
    v1_params = set()
    for e in params_entries:
        if e.get('snmpTargetParamsRowStatus', 0) == 1:
            mp = e.get('snmpTargetParamsMPModel', -1)
            if mp == 0:  # SNMPv1
                v1_params.add(e.get('snmpTargetParamsName', ''))
    v3_params = set()
    for e in params_entries:
        if e.get('snmpTargetParamsRowStatus', 0) == 1:
            mp = e.get('snmpTargetParamsMPModel', -1)
            if mp == 3:  # SNMPv3
                v3_params.add(e.get('snmpTargetParamsName', ''))
    # Check if any active target address uses v1 or v3 params
    addr_entries = target_mib.get('tables', {}).get('snmpTargetAddrEntry', [])
    sec['snmpv1_traps_active'] = False
    sec['snmpv3_traps_active'] = False
    for e in addr_entries:
        if e.get('snmpTargetAddrRowStatus', 0) == 1:
            pname = e.get('snmpTargetAddrParams', '')
            if pname in v1_params:
                sec['snmpv1_traps_active'] = True
            if pname in v3_params:
                sec['snmpv3_traps_active'] = True

    # SNMPv1/v2 write access — SNMP-VIEW-BASED-ACM-MIB (VACM)
    vacm = mibs.get('SNMP-VIEW-BASED-ACM-MIB', {})
    vacm_entries = vacm.get('tables', {}).get('vacmAccessEntry', [])
    sec['snmpv1v2_write_groups'] = []
    for e in vacm_entries:
        if e.get('vacmAccessStatus', 0) != 1:
            continue
        sm = e.get('vacmAccessSecurityModel', 0)
        if sm in (1, 2):  # 1=SNMPv1, 2=SNMPv2c
            write_view = e.get('vacmAccessWriteViewName', 'none')
            if write_view and write_view != 'none':
                group = e.get('vacmGroupName', 'unknown')
                sec['snmpv1v2_write_groups'].append({
                    'group': group,
                    'model': 'SNMPv1' if sm == 1 else 'SNMPv2c',
                    'write_view': write_view,
                })

    # Device security sense monitors — HM2-DEVSEC-MIB (in HM2-DEVMGMT-MIB)
    DEVSEC_MONITORS = {
        'hm2DevSecSensePasswordChange': 'Password default unchanged',
        'hm2DevSecSensePasswordMinLength': 'Min password length < 8',
        'hm2DevSecSensePasswordStrengthNotConfigured': 'Password policy deactivated',
        'hm2DevSecSenseBypassPasswordStrength': 'User policy check deactivated',
        'hm2DevSecSenseTelnetEnabled': 'Telnet server active',
        'hm2DevSecSenseHttpEnabled': 'HTTP server active',
        'hm2DevSecSenseSnmpUnsecure': 'SNMP unencrypted',
        'hm2DevSecSenseSysmonEnabled': 'System monitor accessible',
        'hm2DevSecSenseExtNvmUpdateEnabled': 'ENVM config save enabled',
        'hm2DevSecSenseNoLinkEnabled': 'Link down on enabled ports',
        'hm2DevSecSenseHiDiscoveryEnabled': 'HiDiscovery accessible',
        'hm2DevSecSenseExtNvmConfigLoadUnsecure': 'ENVM config load unsecure',
        'hm2DevSecSenseIec61850MmsEnabled': 'IEC 61850 MMS enabled',
        'hm2DevSecSenseHttpsCertificateWarning': 'Auto-generated HTTPS cert',
        'hm2DevSecSenseModbusTcpEnabled': 'Modbus TCP active',
        'hm2DevSecSenseEtherNetIpEnabled': 'EtherNet/IP active',
        'hm2DevSecSenseProfinetIOEnabled': 'PROFINET active',
    }
    for mib_name in ('HM2-DIAGNOSTIC-MIB', 'HM2-DEVICE-MGMT-MIB', 'HM2-DEVMGMT-MIB'):
        dm = mibs.get(mib_name, {})
        devsec = dm.get('scalars', {}).get('hm2DevSecConfigGroup', {})
        if devsec:
            monitored = []
            ignored = []
            for attr, label in DEVSEC_MONITORS.items():
                val = devsec.get(attr, 0)
                if HIOS_BOOL.get(val, False):
                    monitored.append(label)
                else:
                    ignored.append(label)
            sec['devsec_monitored'] = monitored
            sec['devsec_ignored'] = ignored
            break
    else:
        sec['devsec_monitored'] = None
        sec['devsec_ignored'] = None

    # Module slots — HM2-DEVMGMT-MIB (3A only, modular chassis)
    sec['modules'] = []
    for mib_name in ('HM2-DEVICE-MGMT-MIB', 'HM2-DEVMGMT-MIB'):
        dm = mibs.get(mib_name, {})
        mod_entries = dm.get('tables', {}).get('hm2ModuleEntry', [])
        if mod_entries:
            for e in mod_entries:
                desc_raw = e.get('hm2ModuleDescription', '')
                desc = decode_hex_string(desc_raw) if ' ' in str(desc_raw) else str(desc_raw)
                sec['modules'].append({
                    'index': e.get('hm2ModuleIndex', 0),
                    'desc': desc,
                    'admin_state': HIOS_BOOL.get(e.get('hm2ModuleAdminState', 2), False),
                    'internal_id': e.get('hm2ModuleInternalID', 0),
                })
            break

    # DNS client — HM2-DNS-MIB
    dns_mib = mibs.get('HM2-DNS-MIB', {})
    dns_client = dns_mib.get('scalars', {}).get('hm2DnsClientGroup', {})
    sec['dns_client_enabled'] = HIOS_BOOL.get(dns_client.get('hm2DnsClientAdminState', 2), False)

    # PoE — HM2-POE-MIB (hardware-dependent, only on PoE models)
    poe_mib = mibs.get('HM2-POE-MIB', {})
    poe_global = poe_mib.get('scalars', {}).get('hm2PoeMgmtGlobalGroup', {})
    if poe_global:
        sec['poe_enabled'] = HIOS_BOOL.get(poe_global.get('hm2PoeMgmtAdminStatus', 2), False)
    else:
        sec['poe_enabled'] = None  # No PoE hardware

    # SNMPv3 auth/encryption — SNMP-USER-BASED-SM-MIB
    usm = mibs.get('SNMP-USER-BASED-SM-MIB', {})
    usm_entries = usm.get('tables', {}).get('usmUserEntry', [])
    sec['snmpv3_users'] = []
    # OID suffix mappings
    AUTH_OIDS = {
        '1.3.6.1.6.3.10.1.1.1': 'none',
        '1.3.6.1.6.3.10.1.1.2': 'hmacmd5',
        '1.3.6.1.6.3.10.1.1.3': 'hmacsha',
    }
    PRIV_OIDS = {
        '1.3.6.1.6.3.10.1.2.1': 'none',
        '1.3.6.1.6.3.10.1.2.2': 'des',
        '1.3.6.1.6.3.10.1.2.4': 'aesCfb128',
    }
    for e in usm_entries:
        if e.get('usmUserStatus', 0) != 1:
            continue
        auth_oid = str(e.get('usmUserAuthProtocol', ''))
        priv_oid = str(e.get('usmUserPrivProtocol', ''))
        sec['snmpv3_users'].append({
            'name': e.get('usmUserSecurityName', e.get('usmUserName', '')),
            'auth': AUTH_OIDS.get(auth_oid, auth_oid),
            'priv': PRIV_OIDS.get(priv_oid, priv_oid),
        })

    return sec


def _discover_network_security(mibs):
    """Discover network security features (Ch.3): GVRP, GMRP, port security, DHCP snooping, DAI, IPSG, DoS, LLDP."""
    ns = {}

    # GVRP — Q-BRIDGE-MIB
    qbridge = mibs.get('Q-BRIDGE-MIB', {})
    qb_base = qbridge.get('scalars', {}).get('dot1qBase', {})
    ns['gvrp_enabled'] = HIOS_BOOL.get(qb_base.get('dot1qGvrpStatus', 2), False)

    # MVRP — HM2-PLATFORM-MVRP-MIB
    mvrp_mib = mibs.get('HM2-PLATFORM-MVRP-MIB', {})
    mvrp_s = mvrp_mib.get('scalars', {}).get('hm2AgentDot1qMvrp', {})
    ns['mvrp_enabled'] = HIOS_BOOL.get(mvrp_s.get('hm2AgentDot1qBridgeMvrpMode', 2), False)

    # GMRP — BRIDGE-MIB
    bridge = mibs.get('BRIDGE-MIB', {})
    bridge_ext = bridge.get('scalars', {}).get('dot1dExtBase', {})
    ns['gmrp_enabled'] = HIOS_BOOL.get(bridge_ext.get('dot1dGmrpStatus', 2), False)

    # MMRP — HM2-PLATFORM-MMRP-MIB
    mmrp_mib = mibs.get('HM2-PLATFORM-MMRP-MIB', {})
    mmrp_s = mmrp_mib.get('scalars', {}).get('hm2AgentDot1qMmrp', {})
    ns['mmrp_enabled'] = HIOS_BOOL.get(mmrp_s.get('hm2AgentDot1qBridgeMmrpMode', 2), False)

    # Port Security — HM2-PLATFORM-PORTSECURITY-MIB
    portsec = mibs.get('HM2-PLATFORM-PORTSECURITY-MIB', {})
    portsec_g = portsec.get('scalars', {}).get('hm2AgentPortSecurityGroup', {})
    ns['port_security_enabled'] = HIOS_BOOL.get(
        portsec_g.get('hm2AgentGlobalPortSecurityMode', 2), False)

    # DHCP Snooping, IPSG, DAI — may be in dedicated MIBs or merged into HM2-PLATFORM-SWITCHING-MIB
    def _find_scalar(name):
        for mib_name in ('HM2-PLATFORM-DHCP-SNOOPING-MIB', 'HM2-PLATFORM-SWITCHING-MIB'):
            s = mibs.get(mib_name, {}).get('scalars', {}).get(name, {})
            if s:
                return s
        return {}

    def _find_table(name):
        for mib_name in ('HM2-PLATFORM-DHCP-SNOOPING-MIB', 'HM2-PLATFORM-IPSG-MIB',
                         'HM2-PLATFORM-DAI-MIB', 'HM2-PLATFORM-SWITCHING-MIB'):
            t = mibs.get(mib_name, {}).get('tables', {}).get(name, [])
            if t:
                return t
        return []

    dhcp_g = _find_scalar('hm2AgentDhcpSnoopingConfigGroup')
    ns['dhcp_snooping_enabled'] = HIOS_BOOL.get(
        dhcp_g.get('hm2AgentDhcpSnoopingAdminMode', 2), False)

    # IP Source Guard (per-port only, no global toggle)
    ipsg_entries = _find_table('hm2AgentIpsgIfConfigEntry')
    ns['ipsg_any_enabled'] = any(
        HIOS_BOOL.get(e.get('hm2AgentIpsgIfVerifySource', 2), False)
        for e in ipsg_entries)
    ns['ipsg_present'] = bool(ipsg_entries)

    # Dynamic ARP Inspection
    dai_vlans = _find_table('hm2AgentDaiVlanConfigEntry')
    ns['dai_any_enabled'] = any(
        HIOS_BOOL.get(e.get('hm2AgentDaiVlanDynArpInspEnable', 2), False)
        for e in dai_vlans)
    ns['dai_present'] = bool(dai_vlans)

    # DoS Mitigation — HM2-DOS-MITIGATION-MIB
    dos = mibs.get('HM2-DOS-MITIGATION-MIB', {})
    dos_tcp = dos.get('scalars', {}).get('hm2DosMitigationTcpHdrChecks', {})
    dos_icmp = dos.get('scalars', {}).get('hm2DosMitigationIcmpChecks', {})
    dos_checks = {}
    DOS_TCP_ATTRS = {
        'hm2DosMitigationTcpNullScan': 'TCP Null Scan',
        'hm2DosMitigationTcpXmasScan': 'TCP Xmas Scan',
        'hm2DosMitigationTcpSynFinScan': 'TCP SYN/FIN Scan',
        'hm2DosMitigationTcpMinimalHeader': 'TCP Minimal Header',
        'hm2DosMitigationLandAttack': 'LAND Attack',
        'hm2DosMitigationTcpOffsetEqu1': 'TCP Offset=1',
        'hm2DosMitigationTcpPrivilegedSrcPort': 'TCP Privileged Src Port',
        'hm2DosMitigationTcpSrcDstPortEqu': 'TCP Src=Dst Port',
    }
    DOS_ICMP_ATTRS = {
        'hm2DosMitigationIcmpFrags': 'ICMP Fragments',
        'hm2DosMitigationIcmpPacketSizeMode': 'ICMP Packet Size',
        'hm2DosMitigationIcmpSmurfAttack': 'ICMP Smurf Attack',
    }
    for attr, label in DOS_TCP_ATTRS.items():
        val = dos_tcp.get(attr, 0)
        if val:
            dos_checks[label] = HIOS_BOOL.get(val, False)
    for attr, label in DOS_ICMP_ATTRS.items():
        val = dos_icmp.get(attr, 0)
        if val:
            dos_checks[label] = HIOS_BOOL.get(val, False)
    ns['dos_checks'] = dos_checks
    ns['dos_present'] = bool(dos_tcp or dos_icmp)

    # LLDP — LLDP-MIB
    lldp = mibs.get('LLDP-MIB', {})
    lldp_cfg = lldp.get('scalars', {}).get('lldpConfiguration', {})
    ns['lldp_tx_interval'] = lldp_cfg.get('lldpMessageTxInterval', 0)
    lldp_ports = lldp.get('tables', {}).get('lldpPortConfigEntry', [])
    # AdminStatus: 1=txOnly, 2=rxOnly, 3=txAndRx, 4=disabled
    ns['lldp_disabled_ports'] = [
        e.get('lldpPortConfigPortNum', '')
        for e in lldp_ports
        if e.get('lldpPortConfigAdminStatus', 3) == 4]
    ns['lldp_present'] = bool(lldp_ports)

    return ns


# ---------------------------------------------------------------------------
# Port Classification
# ---------------------------------------------------------------------------

def classify_ports(facts, components):
    """Classify each physical port by role. Priority-ordered, first match wins.

    Returns dict: port -> {role, vlans_tagged, vlans_untagged, pvid, ...}
    """
    ports = facts['ports']
    mrp = components['mrp']
    srm = components['srm']
    lag_members = components['lag_members']
    vlans = components['vlans']
    pvid_map = components['pvid']

    # Build sets for fast lookup
    ring_ports = set()
    for ring in mrp:
        ring_ports.add(ring['port1'])
        ring_ports.add(ring['port2'])

    subring_ports = set()
    for sr in srm:
        subring_ports.add(sr['port'])

    # Compute tagged VLANs per port (in egress but NOT in untagged)
    port_tagged = {}
    port_untagged_vlans = {}
    for vid, vdata in vlans.items():
        for p in vdata['egress_phys']:
            if p not in vdata['untagged_phys']:
                port_tagged.setdefault(p, []).append(vid)
            else:
                port_untagged_vlans.setdefault(p, []).append(vid)

    classified = {}
    for port in ports:
        pvid = pvid_map.get(port, 1)
        tagged = sorted(port_tagged.get(port, []))
        untagged = sorted(port_untagged_vlans.get(port, []))

        if port in ring_ports:
            role = 'ring'
        elif port in subring_ports:
            role = 'sub-ring'
        elif port in lag_members:
            role = 'lag'
        elif len(tagged) >= 2:
            role = 'trunk'
        else:
            role = 'edge'

        classified[port] = {
            'role': role,
            'pvid': pvid,
            'tagged': tagged,
            'untagged': untagged,
            'admin_up': facts['port_admin'].get(port, True),
        }

    return classified


# ---------------------------------------------------------------------------
# Check Engine
# ---------------------------------------------------------------------------

def load_checks(checks_dir):
    """Load all check JSON files from directory."""
    checks = []
    if not os.path.isdir(checks_dir):
        return checks
    for fn in sorted(os.listdir(checks_dir)):
        if fn.endswith('.json'):
            path = os.path.join(checks_dir, fn)
            with open(path, 'r') as f:
                try:
                    check_def = json.load(f)
                    checks.append(check_def)
                except (json.JSONDecodeError, ValueError):
                    pass
    return checks


# Check function registry: check_id -> function(facts, components, classified, check_def)
# Each returns list of Finding dicts
CHECK_REGISTRY = {}


def register_check(check_id):
    """Decorator to register a check function."""
    def decorator(fn):
        CHECK_REGISTRY[check_id] = fn
        return fn
    return decorator


class Finding(object):
    """A single audit finding."""
    def __init__(self, check_id, severity, desc, port=None, detail=None,
                 passed=False, scope='device'):
        self.check_id = check_id
        self.severity = severity
        self.desc = desc
        self.port = port
        self.detail = detail
        self.passed = passed
        self.scope = scope

    def to_dict(self):
        d = {
            'check_id': self.check_id,
            'severity': self.severity,
            'scope': self.scope,
            'desc': self.desc,
            'passed': self.passed,
        }
        if self.port:
            d['port'] = self.port
        if self.detail:
            d['detail'] = self.detail
        return d


def run_checks(check_defs, facts, components, classified):
    """Run all loaded checks, respecting SW level gating."""
    findings = []
    for check_def in check_defs:
        req_sw = check_def.get('requiresSW', 'L2S')
        if not sw_level_ge(facts['sw_level'], req_sw):
            # Visible skip — don't silently swallow
            layer = check_def.get('name', '')
            findings.append(Finding(
                'sw-level-gate', 'info',
                '%s checks skipped — requires %s (device is %s)' % (
                    layer, req_sw, facts['sw_level']),
                passed=True))
            continue
        for check_spec in check_def.get('checks', []):
            check_id = check_spec['id']
            scope = check_spec.get('scope', 'device')
            fn = CHECK_REGISTRY.get(check_id)
            if fn:
                results = fn(facts, components, classified, check_spec)
                for r in results:
                    r.scope = scope
                findings.extend(results)
    return findings


# ---------------------------------------------------------------------------
# MRP Checks
# ---------------------------------------------------------------------------

@register_check('mrp-rstp-conflict')
def check_mrp_rstp_conflict(facts, components, classified, spec):
    """RSTP must be disabled on MRP ring ports."""
    findings = []
    rstp = components['rstp_global']
    if not rstp or not rstp['admin_mode']:
        return findings  # RSTP disabled globally, no conflict
    stp_states = components['stp_port_state']
    for ring in components['mrp']:
        for port in (ring['port1'], ring['port2']):
            stp_on = stp_states.get(port, False)
            if stp_on:
                findings.append(Finding(
                    spec['id'], spec['severity'],
                    'RSTP enabled on MRP ring port', port=port,
                    detail='MRP domain: %s' % ring['domain']))
            else:
                findings.append(Finding(
                    spec['id'], spec['severity'],
                    'RSTP correctly disabled on MRP ring port', port=port,
                    passed=True))
    return findings


@register_check('mrp-vlan-exists')
def check_mrp_vlan_exists(facts, components, classified, spec):
    """MRP VLAN must exist and ring ports must be members."""
    findings = []
    vlans = components['vlans']
    for ring in components['mrp']:
        vid = ring['vlan']
        if vid not in vlans:
            findings.append(Finding(
                spec['id'], spec['severity'],
                'MRP VLAN %d does not exist' % vid,
                detail='MRP domain: %s' % ring['domain']))
        else:
            vdata = vlans[vid]
            for port in (ring['port1'], ring['port2']):
                if port not in vdata['egress_phys']:
                    findings.append(Finding(
                        spec['id'], spec['severity'],
                        'MRP ring port not in VLAN %d egress' % vid,
                        port=port,
                        detail='MRP domain: %s' % ring['domain']))
                else:
                    findings.append(Finding(
                        spec['id'], spec['severity'],
                        'MRP ring port in VLAN %d egress' % vid,
                        port=port, passed=True))
    return findings


@register_check('mrp-ring-count')
def check_mrp_ring_count(facts, components, classified, spec):
    """Check for exactly one RM per MRP domain (site-level, but flag locally)."""
    findings = []
    for ring in components['mrp']:
        if ring['role'] == 'manager':
            findings.append(Finding(
                spec['id'], 'info',
                'Device is ring manager for MRP domain',
                detail='Domain: %s, ports: %s, %s' % (
                    ring['domain'], ring['port1'], ring['port2'])))
        else:
            findings.append(Finding(
                spec['id'], 'info',
                'Device is ring client for MRP domain',
                detail='Domain: %s, ports: %s, %s' % (
                    ring['domain'], ring['port1'], ring['port2']),
                passed=True))
    return findings


@register_check('srm-rstp-conflict')
def check_srm_rstp_conflict(facts, components, classified, spec):
    """RSTP must be disabled on SRM sub-ring ports."""
    findings = []
    rstp = components['rstp_global']
    if not rstp or not rstp['admin_mode']:
        return findings  # RSTP disabled globally, no conflict
    stp_states = components['stp_port_state']
    for sr in components['srm']:
        port = sr['port']
        stp_on = stp_states.get(port, False)
        if stp_on:
            findings.append(Finding(
                spec['id'], spec['severity'],
                'RSTP enabled on SRM sub-ring port', port=port,
                detail='Sub-ring ID: %s' % sr['ring_id']))
        else:
            findings.append(Finding(
                spec['id'], spec['severity'],
                'RSTP correctly disabled on SRM sub-ring port', port=port,
                passed=True))
    return findings


@register_check('srm-global-state')
def check_srm_global_state(facts, components, classified, spec):
    """SRM global state and instance consistency."""
    findings = []
    srm_global = components['srm_global']
    srm = components['srm']

    if not srm:
        return findings  # No SRM instances — nothing to check

    active_instances = [s for s in srm if s['row_status'] == 1]
    parked_instances = [s for s in srm if s['row_status'] == 2]

    if srm_global and not srm_global['enabled']:
        findings.append(Finding(
            spec['id'], spec['severity'],
            'SRM globally disabled but %d instance(s) configured' % len(srm),
            detail='Sub-ring instances will not operate until SRM is globally enabled'))

    for s in parked_instances:
        findings.append(Finding(
            spec['id'], 'info',
            'SRM sub-ring %d notInService (VLAN %d, %s, port %s)' % (
                s['ring_id'], s['vlan'], s['role'], s['port']),
            detail='Row exists but is parked — activate or remove'))

    if srm_global and srm_global['enabled'] and active_instances:
        for s in active_instances:
            findings.append(Finding(
                spec['id'], spec['severity'],
                'SRM sub-ring %d active (%s, VLAN %d, port %s)' % (
                    s['ring_id'], s['role'], s['vlan'], s['port']),
                passed=True))

    return findings


@register_check('redundancy-posture')
def check_redundancy_posture(facts, components, classified, spec):
    """Summarize redundancy protocol posture."""
    rstp = components['rstp_global']
    lp_global = components['loop_prot_global']
    mrp = components['mrp']
    srm = components['srm']

    stp_states = components['stp_port_state']
    phys_ports = facts['ports']

    active = []
    rstp_ineffective = False
    if rstp and rstp['admin_mode']:
        any_stp_port = any(stp_states.get(p, False) for p in phys_ports)
        if any_stp_port:
            active.append('RSTP')
        else:
            rstp_ineffective = True
    if lp_global and lp_global['enabled']:
        active.append('Loop-prot')
    if mrp:
        roles = set(r['role'] for r in mrp)
        active.append('MRP (%s)' % '/'.join(sorted(roles)))
    srm_global = components['srm_global']
    srm_ineffective = False
    if srm:
        if srm_global and srm_global['enabled']:
            roles = set(s['role'] for s in srm)
            active.append('SRM (%s)' % '/'.join(sorted(roles)))
        else:
            srm_ineffective = True

    findings = []
    if rstp_ineffective:
        findings.append(Finding(spec['id'], spec['severity'],
                                'RSTP global on but all ports STP off — false confidence',
                                detail='Worse than RSTP off — appears protected but no ports participate'))
    if srm_ineffective:
        findings.append(Finding(spec['id'], spec['severity'],
                                'SRM global off but %d sub-ring(s) configured — inactive' % len(srm),
                                detail='Sub-ring instances exist but SRM is globally disabled'))
    if not active:
        findings.append(Finding(spec['id'], spec['severity'],
                                'No effective redundancy protocols configured',
                                detail='No RSTP, MRP, SRM, or loop-prot — no protection against loops or failures'))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Redundancy: %s' % ', '.join(active),
                                passed=True))
    return findings


# ---------------------------------------------------------------------------
# RSTP Checks
# ---------------------------------------------------------------------------

@register_check('rstp-bpdu-guard')
def check_rstp_bpdu_guard(facts, components, classified, spec):
    """BPDU guard should be enabled globally."""
    findings = []
    rstp = components['rstp_global']
    if not rstp or not rstp['admin_mode']:
        return findings  # RSTP off globally — nothing to check
    if rstp['bpdu_guard']:
        findings.append(Finding(spec['id'], spec['severity'],
                                'BPDU guard enabled globally', passed=True))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'BPDU guard disabled globally',
                                detail='Should be enabled to protect against rogue switches'))
    return findings


@register_check('rstp-global-state')
def check_rstp_global_state(facts, components, classified, spec):
    """RSTP global state sanity check."""
    findings = []
    rstp = components['rstp_global']
    stp_states = components['stp_port_state']
    lp_global = components['loop_prot_global']
    lp_ports = components['loop_prot_ports']

    if not rstp or not rstp['admin_mode']:
        # RSTP off globally — check if loop-prot covers edges instead
        edge_ports = [p for p, i in classified.items() if i['role'] == 'edge']
        lp_on = lp_global and lp_global['enabled']
        lp_edge_count = sum(1 for p in edge_ports
                            if lp_on and lp_ports.get(p, {}).get('enabled', False))
        if lp_edge_count == len(edge_ports) and edge_ports:
            findings.append(Finding(spec['id'], 'info',
                                    'RSTP globally disabled — loop-prot covers all %d edge ports' % len(edge_ports)))
        elif lp_edge_count > 0:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'RSTP globally disabled — loop-prot covers %d of %d edge ports' % (
                                        lp_edge_count, len(edge_ports)),
                                    detail='Remaining edge ports have no STP protection'))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'RSTP globally disabled — no STP protection on any port',
                                    detail='Enable RSTP or loop-prot for edge protection'))
        return findings

    # RSTP on — check if all ports have STP disabled (false confidence)
    phys_ports = facts['ports']
    stp_on_count = sum(1 for p in phys_ports if stp_states.get(p, False))
    if stp_on_count == 0:
        findings.append(Finding(spec['id'], spec['severity'],
                                'RSTP globally enabled but ALL %d ports have STP disabled' % len(phys_ports),
                                detail='BPDU filtering with extra steps — worse than RSTP off (false confidence)'))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'RSTP enabled on %d of %d ports' % (stp_on_count, len(phys_ports)),
                                passed=True))
    return findings


@register_check('rstp-edge-on-edge')
def check_rstp_edge_on_edge(facts, components, classified, spec):
    """Edge ports with RSTP should have edge mode or auto-edge enabled."""
    findings = []
    rstp = components['rstp_global']
    if not rstp or not rstp['admin_mode']:
        return findings
    rstp_ports = components['rstp_ports']
    stp_states = components['stp_port_state']
    for port, info in classified.items():
        if info['role'] != 'edge':
            continue
        if not stp_states.get(port, False):
            continue  # STP disabled on this port — edge/auto-edge irrelevant
        rp = rstp_ports.get(port, {})
        if rp.get('edge') or rp.get('auto_edge'):
            findings.append(Finding(spec['id'], spec['severity'],
                                    'RSTP edge/auto-edge enabled', port=port,
                                    passed=True))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'RSTP edge/auto-edge disabled on edge port',
                                    port=port,
                                    detail='Edge ports should use edge mode for fast convergence'))
    return findings


@register_check('rstp-trunk-not-edge')
def check_rstp_trunk_not_edge(facts, components, classified, spec):
    """Trunk/ring/sub-ring ports: check RSTP is appropriate for their role."""
    findings = []
    rstp = components['rstp_global']
    if not rstp or not rstp['admin_mode']:
        return findings
    rstp_ports = components['rstp_ports']
    stp_states = components['stp_port_state']
    has_mrp = len(components['mrp']) > 0
    has_srm = len(components['srm']) > 0

    for port, info in classified.items():
        role = info['role']
        stp_on = stp_states.get(port, False)

        if role in ('ring', 'sub-ring'):
            # Ring/sub-ring ports should never have STP enabled
            if stp_on:
                findings.append(Finding(spec['id'], 'warning',
                                        'STP enabled on %s port' % role, port=port,
                                        detail='MRP/SRM handles redundancy — disable STP'))
            # mrp-rstp-conflict covers ring ports specifically, skip pass here

        elif role == 'trunk':
            rp = rstp_ports.get(port, {})
            # Trunk forced as RSTP edge = always wrong
            if rp.get('edge') and not rp.get('auto_edge'):
                findings.append(Finding(spec['id'], spec['severity'],
                                        'Trunk port forced as RSTP edge (no auto-edge)',
                                        port=port,
                                        detail='Trunk ports should not be edge — risk of loops'))
            # STP on trunk with MRP/SRM = questionable (MRP handles redundancy)
            elif stp_on and (has_mrp or has_srm):
                findings.append(Finding(spec['id'], 'info',
                                        'STP enabled on trunk port (MRP/SRM present)',
                                        port=port,
                                        detail='MRP handles ring redundancy — verify STP needed'))
            elif stp_on:
                findings.append(Finding(spec['id'], spec['severity'],
                                        'Trunk port RSTP config OK', port=port,
                                        passed=True))
    return findings


# ---------------------------------------------------------------------------
# VLAN Checks
# ---------------------------------------------------------------------------

@register_check('vlan-pvid-mismatch')
def check_vlan_pvid_mismatch(facts, components, classified, spec):
    """Port PVID should match an untagged VLAN membership."""
    findings = []
    vlans = components['vlans']
    pvid_map = components['pvid']
    for port in facts['ports']:
        pvid = pvid_map.get(port, 1)
        if pvid in vlans:
            vdata = vlans[pvid]
            if port in vdata['untagged_phys']:
                findings.append(Finding(spec['id'], spec['severity'],
                                        'PVID %d matches untagged membership' % pvid,
                                        port=port, passed=True))
            else:
                findings.append(Finding(spec['id'], spec['severity'],
                                        'PVID %d but port not untagged member of VLAN %d' % (pvid, pvid),
                                        port=port,
                                        detail='Frames may be dropped or misclassified'))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'PVID %d references non-existent VLAN' % pvid,
                                    port=port))
    return findings


@register_check('vlan-orphan')
def check_vlan_orphan(facts, components, classified, spec):
    """VLANs with no physical port members are orphans."""
    findings = []
    for vid, vdata in components['vlans'].items():
        if not vdata['egress_phys']:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'VLAN %d "%s" has no physical port members' % (vid, vdata['name']),
                                    detail='Orphan VLAN — consider removing'))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'VLAN %d "%s" has %d physical ports' % (
                                        vid, vdata['name'], len(vdata['egress_phys'])),
                                    passed=True))
    return findings


@register_check('vlan-dirty-access')
def check_vlan_dirty_access(facts, components, classified, spec):
    """Edge ports should have exactly one untagged VLAN (clean access)."""
    findings = []
    for port, info in classified.items():
        if info['role'] != 'edge':
            continue
        if len(info['untagged']) > 1:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Edge port untagged in %d VLANs' % len(info['untagged']),
                                    port=port,
                                    detail='VLANs: %s — should be single untagged VLAN' % (
                                        ', '.join(str(v) for v in info['untagged']))))
    return findings


@register_check('vlan-name-empty')
def check_vlan_name_empty(facts, components, classified, spec):
    """VLANs should have descriptive names."""
    findings = []
    for vid, vdata in components['vlans'].items():
        if vid == 1:
            continue  # default VLAN name is OK
        if not vdata['name'] or vdata['name'] == 'VLAN %d' % vid:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'VLAN %d has no descriptive name' % vid,
                                    detail='Name: "%s"' % vdata['name']))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'VLAN %d named "%s"' % (vid, vdata['name']),
                                    passed=True))
    return findings


# ---------------------------------------------------------------------------
# System Checks
# ---------------------------------------------------------------------------

@register_check('sys-hostname-default')
def check_sys_hostname_default(facts, components, classified, spec):
    """Hostname should not be default."""
    findings = []
    h = facts['hostname']
    if not h or h.lower().startswith('switch') or h.lower() == 'hm2-system':
        findings.append(Finding(spec['id'], spec['severity'],
                                'Hostname appears to be default',
                                detail='Hostname: "%s"' % h))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Hostname set: %s' % h, passed=True))
    return findings


@register_check('sys-mgmt-ip')
def check_sys_mgmt_ip(facts, components, classified, spec):
    """Management IP should be configured."""
    findings = []
    mgmt = facts['mgmt_ip']
    vlan_ips = facts.get('vlan_ips', {})
    if mgmt == '0.0.0.0' and not vlan_ips:
        findings.append(Finding(spec['id'], spec['severity'],
                                'No management IP configured',
                                detail='Flat mgmt IP is 0.0.0.0 and no VLAN interface IPs'))
    elif mgmt == '0.0.0.0' and vlan_ips:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Flat mgmt IP is 0.0.0.0 (L3 device uses VLAN interface IPs)',
                                passed=True))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Management IP: %s/%s' % (mgmt, facts['prefix_len']),
                                passed=True))
    return findings


@register_check('sys-snmp-communities')
def check_sys_snmp_communities(facts, components, classified, spec):
    """Default SNMP communities should be removed."""
    findings = []
    comms = components['snmp_communities']
    defaults = {'public', 'private', 'trap'}
    found = [c for c in comms if c in defaults]
    if found:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Default SNMP communities present: %s' % ', '.join(found),
                                detail='Remove default communities for security'))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'No default SNMP communities', passed=True))
    return findings


@register_check('sys-default-passwords')
def check_sys_default_passwords(facts, components, classified, spec):
    """Check for users with default-looking configurations."""
    findings = []
    for user in components['users']:
        if not user['active']:
            continue
        # We can't check actual passwords (scrambled), but flag default users
        if user['name'] in ('admin', 'user') and user['role'] == 'admin':
            findings.append(Finding(spec['id'], 'info',
                                    'Default admin user "%s" exists' % user['name'],
                                    detail='Verify password has been changed'))
    return findings


# ---------------------------------------------------------------------------
# Edge Protection Checks
# ---------------------------------------------------------------------------

@register_check('edge-loop-protection')
def check_edge_loop_protection(facts, components, classified, spec):
    """Edge ports should have exactly one protection strategy: RSTP or loop-prot."""
    findings = []
    lp_global = components['loop_prot_global']
    lp_ports = components['loop_prot_ports']
    rstp = components['rstp_global']
    stp_states = components['stp_port_state']

    rstp_global_on = rstp and rstp['admin_mode']

    for port, info in classified.items():
        if info['role'] != 'edge':
            continue

        has_loop_prot = (lp_global and lp_global['enabled'] and
                         lp_ports.get(port, {}).get('enabled', False))
        has_rstp = rstp_global_on and stp_states.get(port, False)

        if has_loop_prot and has_rstp:
            findings.append(Finding(spec['id'], 'warning',
                                    'Edge port has BOTH loop-prot and RSTP',
                                    port=port,
                                    detail='Use one strategy per port — disable the other'))
        elif has_rstp:
            strategy = 'rstp-full' if rstp.get('bpdu_guard') else 'rstp'
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Edge protection: %s' % strategy,
                                    port=port, passed=True))
        elif has_loop_prot:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Edge protection: loop-prot',
                                    port=port, passed=True))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Edge port has no protection',
                                    port=port,
                                    detail='Enable loop-prot or RSTP on edge ports'))
    return findings


@register_check('non-edge-loop-prot')
def check_non_edge_loop_prot(facts, components, classified, spec):
    """Loop protection should only be on edge ports."""
    findings = []
    lp_global = components['loop_prot_global']
    if not lp_global or not lp_global['enabled']:
        return findings  # Loop-prot off globally — nothing to check
    lp_ports = components['loop_prot_ports']
    for port, info in classified.items():
        if info['role'] == 'edge':
            continue
        if lp_ports.get(port, {}).get('enabled', False):
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Loop protection enabled on %s port' % info['role'],
                                    port=port,
                                    detail='Loop protection is for edge ports only'))
    return findings


@register_check('edge-auto-disable-reasons')
def check_edge_auto_disable_reasons(facts, components, classified, spec):
    """Auto-disable should have multiple reasons enabled."""
    findings = []
    reasons = components['auto_disable_reasons']
    enabled = [r for r, on in reasons.items() if on]

    recommended = {'link-flap', 'loop-protection', 'bpdu-rate'}
    missing = recommended - set(enabled)

    if not enabled:
        findings.append(Finding(spec['id'], spec['severity'],
                                'No auto-disable reasons enabled',
                                detail='Recommended: %s' % ', '.join(sorted(recommended))))
    elif missing:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Auto-disable missing recommended reasons: %s' % ', '.join(sorted(missing)),
                                detail='Enabled: %s' % ', '.join(sorted(enabled))))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Auto-disable reasons configured',
                                detail='Enabled: %s' % ', '.join(sorted(enabled)),
                                passed=True))
    return findings


@register_check('edge-auto-disable-timer')
def check_edge_auto_disable_timer(facts, components, classified, spec):
    """Edge ports should have auto-disable timer > 0."""
    findings = []
    timers = components['auto_disable_timers']
    for port, info in classified.items():
        if info['role'] != 'edge':
            continue
        timer = timers.get(port, 0)
        if timer > 0:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Auto-disable timer: %ds' % timer,
                                    port=port, passed=True))
        else:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Auto-disable timer is 0 (disabled)',
                                    port=port,
                                    detail='Set a recovery timer for auto-disabled ports'))
    return findings


# ---------------------------------------------------------------------------
# Security Checks (Vendor Hardening Guide §2.11)
# ---------------------------------------------------------------------------

@register_check('sec-hidiscovery')
def check_hidiscovery(facts, components, classified, spec):
    """HiDiscovery should be off in production."""
    sec = components['security']
    mode = sec['hidiscovery_mode']
    enabled = sec['hidiscovery_operation']
    if not enabled or mode == 'off':
        return [Finding(spec['id'], spec['severity'],
                        'HiDiscovery disabled', passed=True)]
    if mode == 'readWrite':
        return [Finding(spec['id'], 'critical',
                        'HiDiscovery set to read/write',
                        detail='Anyone on the network can change IP and settings via MARCO/HiDiscovery')]
    # readOnly
    return [Finding(spec['id'], 'warning',
                    'HiDiscovery set to read-only',
                    detail='Device is discoverable but not writable — disable for production')]


@register_check('sec-insecure-protocols')
def check_insecure_protocols(facts, components, classified, spec):
    """HTTP, Telnet, SNMPv1/v2 should be disabled."""
    sec = components['security']
    findings = []
    insecure = []
    if sec['http_enabled']:
        insecure.append('HTTP')
    if sec['telnet_enabled']:
        insecure.append('Telnet')
    if sec['snmpv1_enabled']:
        insecure.append('SNMPv1')
    if sec['snmpv2_enabled']:
        insecure.append('SNMPv2')
    if insecure:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Insecure protocols enabled: %s' % ', '.join(insecure),
                                detail='Disable — use HTTPS, SSHv2, SNMPv3 instead'))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'No insecure management protocols enabled', passed=True))
    # Also check secure protocols are ON
    missing_secure = []
    if not sec['https_enabled']:
        missing_secure.append('HTTPS')
    if not sec['ssh_enabled']:
        missing_secure.append('SSH')
    if not sec['snmpv3_enabled']:
        missing_secure.append('SNMPv3')
    if missing_secure:
        findings.append(Finding(spec['id'], 'warning',
                                'Secure protocols disabled: %s' % ', '.join(missing_secure),
                                detail='At least HTTPS and SSH should be enabled'))
    return findings


@register_check('sec-industrial-protocols')
def check_industrial_protocols(facts, components, classified, spec):
    """Modbus TCP, EtherNet/IP, PROFINET, IEC 61850 should be off unless needed."""
    sec = components['security']
    enabled = []
    if sec['modbus_enabled']:
        enabled.append('Modbus TCP')
    if sec['ethernetip_enabled']:
        enabled.append('EtherNet/IP')
    if sec['profinet_enabled']:
        enabled.append('PROFINET')
    if sec['iec61850_enabled']:
        enabled.append('IEC 61850 MMS')
    if enabled:
        return [Finding(spec['id'], spec['severity'],
                        'Industrial protocols enabled: %s' % ', '.join(enabled),
                        detail='Disable unless required by connected automation systems')]
    return [Finding(spec['id'], spec['severity'],
                    'No industrial protocols enabled', passed=True)]


@register_check('sec-unsigned-sw')
def check_unsigned_sw(facts, components, classified, spec):
    """Unsigned firmware upload should be rejected."""
    sec = components['security']
    if sec['allow_unsigned_sw'] is None:
        return []  # MIB not found
    if sec['allow_unsigned_sw']:
        return [Finding(spec['id'], spec['severity'],
                        'Unsigned firmware upload allowed',
                        detail='Enable secure boot or reject unsigned images')]
    return [Finding(spec['id'], spec['severity'],
                    'Unsigned firmware upload rejected', passed=True)]


@register_check('sec-login-policy')
def check_login_policy(facts, components, classified, spec):
    """Login policy: max attempts, lockout period, min password length."""
    sec = components['security']
    if sec['pwd_min_length'] is None:
        return []  # MIB not found
    findings = []
    issues = []
    if sec['login_attempts'] == 0:
        issues.append('no login attempt limit')
    if sec['login_lockout'] == 0:
        issues.append('no lockout period')
    if sec['pwd_min_length'] < 8:
        issues.append('min password length %d (recommend 8+)' % sec['pwd_min_length'])
    if issues:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Login policy weak: %s' % ', '.join(issues)))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Login policy configured', passed=True,
                                detail='Max attempts: %d, lockout: %d min, min pw len: %d' % (
                                    sec['login_attempts'], sec['login_lockout'],
                                    sec['pwd_min_length'])))
    return findings


@register_check('sec-password-policy')
def check_password_policy(facts, components, classified, spec):
    """Password policy should require upper+lower+digits+special."""
    sec = components['security']
    if sec['pwd_min_length'] is None:
        return []
    missing = []
    if sec['pwd_min_upper'] == 0:
        missing.append('uppercase')
    if sec['pwd_min_lower'] == 0:
        missing.append('lowercase')
    if sec['pwd_min_digits'] == 0:
        missing.append('digits')
    if sec['pwd_min_special'] == 0:
        missing.append('special characters')
    if missing:
        return [Finding(spec['id'], spec['severity'],
                        'Password policy missing requirements: %s' % ', '.join(missing),
                        detail='Set minimum 1 for each character class')]
    return [Finding(spec['id'], spec['severity'],
                    'Password complexity requirements configured', passed=True)]


@register_check('sec-ip-restrict')
def check_ip_restrict(facts, components, classified, spec):
    """Management IP access restrictions should be configured."""
    sec = components['security']
    if sec['rma_enabled'] and sec['rma_rules'] > 0:
        return [Finding(spec['id'], spec['severity'],
                        'IP access restrictions configured (%d rules)' % sec['rma_rules'],
                        passed=True)]
    if sec['rma_enabled']:
        return [Finding(spec['id'], spec['severity'],
                        'IP restrictions enabled but no active rules',
                        detail='Add at least one IP restriction rule')]
    return [Finding(spec['id'], spec['severity'],
                    'No management IP access restrictions',
                    detail='Unrestricted access from any IP on all management protocols')]


@register_check('sec-time-sync')
def check_time_sync(facts, components, classified, spec):
    """Time synchronization (SNTP/PTP) should be configured."""
    sec = components['security']
    if sec['sntp_enabled']:
        return [Finding(spec['id'], spec['severity'],
                        'SNTP time synchronization enabled', passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'No time synchronization configured',
                    detail='Logs and certificates need accurate time — configure SNTP or PTP')]


@register_check('sec-logging')
def check_logging(facts, components, classified, spec):
    """Remote syslog should be configured."""
    sec = components['security']
    if sec['syslog_enabled'] and sec['syslog_servers'] > 0:
        return [Finding(spec['id'], spec['severity'],
                        'Syslog configured (%d server(s))' % sec['syslog_servers'],
                        passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'No remote syslog configured',
                    detail='Configure syslog destination for audit trail and monitoring')]


@register_check('sec-login-banner')
def check_login_banner(facts, components, classified, spec):
    """Pre-login banner should be set."""
    sec = components['security']
    if sec['prelogin_banner_enabled'] and sec['prelogin_banner_text']:
        return [Finding(spec['id'], spec['severity'],
                        'Pre-login banner configured', passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'No pre-login banner set',
                    detail='Set a legal/authorization warning banner')]


@register_check('sec-mgmt-vlan')
def check_mgmt_vlan(facts, components, classified, spec):
    """Management should not be on default VLAN 1."""
    sec = components['security']
    vid = sec.get('mgmt_vlan', 1)
    if isinstance(vid, str):
        try:
            vid = int(vid)
        except ValueError:
            vid = 1
    if vid == 1:
        return [Finding(spec['id'], spec['severity'],
                        'Management on default VLAN 1',
                        detail='Use a dedicated management VLAN for isolation')]
    return [Finding(spec['id'], spec['severity'],
                    'Management on VLAN %d' % vid, passed=True)]


@register_check('sec-aca-auto-update')
def check_aca_auto_update(facts, components, classified, spec):
    """ACA auto software update should be disabled."""
    sec = components['security']
    if sec['aca_auto_sw_load'] is None:
        return []
    if sec['aca_auto_sw_load']:
        return [Finding(spec['id'], spec['severity'],
                        'Auto software load from external memory enabled',
                        detail='Disable to prevent unauthorized firmware changes via ACA')]
    return [Finding(spec['id'], spec['severity'],
                    'Auto software load from external memory disabled', passed=True)]


@register_check('sec-aca-config-write')
def check_aca_config_write(facts, components, classified, spec):
    """Config write to external memory should be disabled."""
    sec = components['security']
    if sec['aca_config_save'] is None:
        return []
    if sec['aca_config_save']:
        return [Finding(spec['id'], spec['severity'],
                        'Config save to external memory enabled',
                        detail='Disable to prevent config exfiltration via ACA removal')]
    return [Finding(spec['id'], spec['severity'],
                    'Config save to external memory disabled', passed=True)]


@register_check('sec-aca-config-load')
def check_aca_config_load(facts, components, classified, spec):
    """Config load from external memory should be disabled."""
    sec = components['security']
    if sec['aca_config_load_priority'] is None:
        return []
    if sec['aca_config_load_priority']:
        return [Finding(spec['id'], spec['severity'],
                        'Config load from external memory enabled',
                        detail='Disable to prevent unauthorized config replacement via ACA')]
    return [Finding(spec['id'], spec['severity'],
                    'Config load from external memory disabled', passed=True)]


@register_check('sec-session-timeouts')
def check_session_timeouts(facts, components, classified, spec):
    """Session timeouts should not be excessive."""
    sec = components['security']
    findings = []
    MAX_TIMEOUT = 15  # minutes — vendor default is 5, delivery is 160 for web
    checks = [
        ('Web', sec.get('web_timeout', 0)),
        ('SSH', sec.get('ssh_timeout', 0)),
        ('Telnet', sec.get('telnet_timeout', 0)),
        ('Serial', sec.get('cli_timeout', 0)),
    ]
    excessive = []
    for name, val in checks:
        if isinstance(val, str):
            try:
                val = int(val)
            except ValueError:
                val = 0
        if val > MAX_TIMEOUT or val == 0:
            excessive.append('%s=%dmin' % (name, val) if val else '%s=never' % name)
    if excessive:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Excessive session timeouts: %s' % ', '.join(excessive),
                                detail='Recommend %d min max to limit idle sessions' % MAX_TIMEOUT))
    else:
        findings.append(Finding(spec['id'], spec['severity'],
                                'Session timeouts within limits', passed=True))
    return findings


@register_check('sec-snmpv1-traps')
def check_snmpv1_traps(facts, components, classified, spec):
    """SNMPv1 traps should be disabled (unencrypted)."""
    sec = components['security']
    if sec.get('snmpv1_traps_active', False):
        return [Finding(spec['id'], spec['severity'],
                        'SNMPv1 trap targets configured',
                        detail='SNMPv1 traps are unencrypted — use SNMPv3 inform/trap')]
    return [Finding(spec['id'], spec['severity'],
                    'No SNMPv1 trap targets', passed=True)]


@register_check('sec-snmpv3-traps')
def check_snmpv3_traps(facts, components, classified, spec):
    """SNMPv3 traps should be configured if monitoring is needed."""
    sec = components['security']
    if sec.get('snmpv3_traps_active', False):
        return [Finding(spec['id'], spec['severity'],
                        'SNMPv3 trap/inform targets configured', passed=True)]
    if sec.get('snmpv1_traps_active', False):
        return [Finding(spec['id'], spec['severity'],
                        'No SNMPv3 traps configured (only SNMPv1)',
                        detail='Migrate trap targets to SNMPv3 for encrypted notifications')]
    return [Finding(spec['id'], spec['severity'],
                    'No SNMP trap targets configured',
                    detail='Configure SNMPv3 inform/trap targets for monitoring')]


@register_check('sec-snmpv1v2-write')
def check_snmpv1v2_write(facts, components, classified, spec):
    """SNMPv1/v2 write access should be disabled."""
    sec = components['security']
    groups = sec.get('snmpv1v2_write_groups', [])
    if not groups:
        return [Finding(spec['id'], spec['severity'],
                        'No SNMPv1/v2 write access configured', passed=True)]
    descs = ['%s (%s → %s)' % (g['group'], g['model'], g['write_view']) for g in groups]
    return [Finding(spec['id'], spec['severity'],
                    'SNMPv1/v2 write access enabled: %s' % ', '.join(descs),
                    detail='Disable write access for SNMPv1/v2c — use SNMPv3 for write operations')]


@register_check('sec-snmpv3-auth')
def check_snmpv3_auth(facts, components, classified, spec):
    """SNMPv3 users should use HMAC-SHA, not HMAC-MD5."""
    sec = components['security']
    users = sec.get('snmpv3_users', [])
    if not users:
        return []
    weak = [u['name'] for u in users if u['auth'] == 'hmacmd5']
    if weak:
        return [Finding(spec['id'], spec['severity'],
                        'SNMPv3 users with HMAC-MD5 auth: %s' % ', '.join(weak),
                        detail='Use HMAC-SHA for stronger authentication')]
    return [Finding(spec['id'], spec['severity'],
                    'All SNMPv3 users use HMAC-SHA or better', passed=True)]


@register_check('sec-snmpv3-encrypt')
def check_snmpv3_encrypt(facts, components, classified, spec):
    """SNMPv3 users should use AES-128, not DES."""
    sec = components['security']
    users = sec.get('snmpv3_users', [])
    if not users:
        return []
    weak = [u['name'] for u in users if u['priv'] == 'des']
    no_enc = [u['name'] for u in users if u['priv'] == 'none']
    findings = []
    if no_enc:
        findings.append(Finding(spec['id'], 'warning',
                                'SNMPv3 users with no encryption: %s' % ', '.join(no_enc),
                                detail='Enable privacy (AES-128) for encrypted SNMP'))
    if weak:
        findings.append(Finding(spec['id'], spec['severity'],
                                'SNMPv3 users with DES encryption: %s' % ', '.join(weak),
                                detail='Use AES-128 (aesCfb128) instead of DES'))
    if not weak and not no_enc:
        findings.append(Finding(spec['id'], spec['severity'],
                                'All SNMPv3 users use AES-128 or better', passed=True))
    return findings


@register_check('sec-devsec-monitors')
def check_devsec_monitors(facts, components, classified, spec):
    """Device security sense monitors should all be enabled."""
    sec = components['security']
    if sec.get('devsec_monitored') is None:
        return []  # MIB not found
    monitored = sec['devsec_monitored']
    ignored = sec['devsec_ignored']
    total = len(monitored) + len(ignored)
    if not ignored:
        return [Finding(spec['id'], spec['severity'],
                        'All %d device security monitors active' % total,
                        passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    '%d of %d security monitors disabled' % (len(ignored), total),
                    detail='Ignored: %s' % ', '.join(ignored))]


@register_check('sec-unused-ports')
def check_unused_ports(facts, components, classified, spec):
    """Unused ports should be admin-disabled."""
    admin_down = [p for p in facts['ports'] if not facts['port_admin'].get(p, True)]
    total = len(facts['ports'])
    if admin_down:
        return [Finding(spec['id'], spec['severity'],
                        '%d of %d ports admin-disabled' % (len(admin_down), total),
                        passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'All %d ports admin-enabled — no ports disabled' % total,
                    detail='Disable unused ports to reduce attack surface')]


@register_check('sec-poe')
def check_poe(facts, components, classified, spec):
    """PoE should be disabled if not required."""
    sec = components['security']
    if sec['poe_enabled'] is None:
        return []  # No PoE hardware
    if sec['poe_enabled']:
        return [Finding(spec['id'], spec['severity'],
                        'PoE globally enabled',
                        detail='Disable if not powering connected devices')]
    return [Finding(spec['id'], spec['severity'],
                    'PoE globally disabled', passed=True)]


@register_check('sec-dns-client')
def check_dns_client(facts, components, classified, spec):
    """DNS client configuration review."""
    sec = components['security']
    if sec.get('dns_client_enabled'):
        return [Finding(spec['id'], spec['severity'],
                        'DNS client enabled',
                        detail='Verify DNS server is trusted — DNS can be used for exfiltration')]
    return [Finding(spec['id'], spec['severity'],
                    'DNS client disabled', passed=True)]


@register_check('sec-module-slots')
def check_module_slots(facts, components, classified, spec):
    """Unused media module slots should be disabled (3A modular chassis)."""
    sec = components['security']
    modules = sec.get('modules', [])
    if not modules:
        return []  # Not a modular device
    findings = []
    for mod in modules:
        if mod['desc'].lower().startswith('fixed'):
            continue  # Fixed module — can't disable
        if mod['admin_state'] and mod['internal_id'] == 0:
            # Slot enabled but no module installed (ID=0)
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Empty module slot %d enabled' % mod['index'],
                                    detail='Disable unused media module slots'))
        elif mod['admin_state']:
            findings.append(Finding(spec['id'], spec['severity'],
                                    'Module slot %d enabled: %s' % (mod['index'], mod['desc']),
                                    passed=True))
    return findings


# ---------------------------------------------------------------------------
# Network Security Checks (Security Manual Ch.3)
# ---------------------------------------------------------------------------

@register_check('ns-gvrp-mvrp')
def check_gvrp_mvrp(facts, components, classified, spec):
    """GVRP/MVRP should be disabled — dynamic VLAN registration is a security risk."""
    ns = components['net_security']
    enabled = []
    if ns.get('gvrp_enabled'):
        enabled.append('GVRP')
    if ns.get('mvrp_enabled'):
        enabled.append('MVRP')
    if enabled:
        return [Finding(spec['id'], spec['severity'],
                        '%s enabled — dynamic VLAN registration active' % '/'.join(enabled),
                        detail='Disable to prevent rogue VLAN creation on the network')]
    return [Finding(spec['id'], spec['severity'],
                    'GVRP/MVRP disabled', passed=True)]


@register_check('ns-gmrp-mmrp')
def check_gmrp_mmrp(facts, components, classified, spec):
    """GMRP/MMRP should be disabled — dynamic multicast registration is a security risk."""
    ns = components['net_security']
    enabled = []
    if ns.get('gmrp_enabled'):
        enabled.append('GMRP')
    if ns.get('mmrp_enabled'):
        enabled.append('MMRP')
    if enabled:
        return [Finding(spec['id'], spec['severity'],
                        '%s enabled — dynamic multicast registration active' % '/'.join(enabled),
                        detail='Disable to prevent rogue multicast group manipulation')]
    return [Finding(spec['id'], spec['severity'],
                    'GMRP/MMRP disabled', passed=True)]


@register_check('ns-port-security')
def check_port_security(facts, components, classified, spec):
    """Port security limits MAC addresses per port — defense in depth."""
    ns = components['net_security']
    if ns.get('port_security_enabled'):
        return [Finding(spec['id'], spec['severity'],
                        'Port security globally enabled', passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'Port security not enabled',
                    detail='Consider enabling to limit MAC addresses per port (§3.3.3)')]


@register_check('ns-dhcp-snooping')
def check_dhcp_snooping(facts, components, classified, spec):
    """DHCP snooping prevents rogue DHCP servers — defense in depth."""
    ns = components['net_security']
    if ns.get('dhcp_snooping_enabled'):
        return [Finding(spec['id'], spec['severity'],
                        'DHCP snooping globally enabled', passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'DHCP snooping not enabled',
                    detail='Consider enabling to prevent rogue DHCP servers (§3.3.4)')]


@register_check('ns-ipsg')
def check_ipsg(facts, components, classified, spec):
    """IP Source Guard prevents IP spoofing — works with DHCP snooping."""
    ns = components['net_security']
    if not ns.get('ipsg_present'):
        return []
    if ns.get('ipsg_any_enabled'):
        return [Finding(spec['id'], spec['severity'],
                        'IP Source Guard enabled on some ports', passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'IP Source Guard not enabled on any port',
                    detail='Consider enabling with DHCP snooping to prevent IP spoofing (§3.3.5)')]


@register_check('ns-dai')
def check_dai(facts, components, classified, spec):
    """Dynamic ARP Inspection prevents ARP spoofing — works with DHCP snooping."""
    ns = components['net_security']
    if not ns.get('dai_present'):
        return []
    if ns.get('dai_any_enabled'):
        return [Finding(spec['id'], spec['severity'],
                        'Dynamic ARP Inspection enabled on some VLANs', passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'Dynamic ARP Inspection not enabled on any VLAN',
                    detail='Consider enabling with DHCP snooping to prevent ARP spoofing (§3.3.6)')]


@register_check('ns-dos-protection')
def check_dos_protection(facts, components, classified, spec):
    """DoS mitigation checks should be enabled."""
    ns = components['net_security']
    dos = ns.get('dos_checks', {})
    if not dos and not ns.get('dos_present'):
        return []  # MIB not available
    enabled = [k for k, v in dos.items() if v]
    disabled = [k for k, v in dos.items() if not v]
    if not disabled:
        return [Finding(spec['id'], spec['severity'],
                        'All %d DoS mitigation checks enabled' % len(enabled), passed=True)]
    if not enabled:
        return [Finding(spec['id'], spec['severity'],
                        'All %d DoS mitigation checks disabled' % len(disabled),
                        detail='Enable DoS protection: %s' % ', '.join(disabled))]
    return [Finding(spec['id'], spec['severity'],
                    '%d of %d DoS checks disabled' % (len(disabled), len(dos)),
                    detail='Disabled: %s' % ', '.join(disabled))]


@register_check('ns-lldp')
def check_lldp(facts, components, classified, spec):
    """LLDP state awareness — review which ports advertise device info."""
    ns = components['net_security']
    if not ns.get('lldp_present'):
        return []
    disabled = ns.get('lldp_disabled_ports', [])
    total_ports = len(facts['ports'])
    if disabled:
        return [Finding(spec['id'], spec['severity'],
                        'LLDP disabled on %d of %d ports' % (len(disabled), total_ports),
                        passed=True)]
    return [Finding(spec['id'], spec['severity'],
                    'LLDP enabled on all %d ports' % total_ports,
                    detail='Consider disabling LLDP on edge ports to limit topology exposure (§3.10)')]


# ---------------------------------------------------------------------------
# Template Generation and Comparison
# ---------------------------------------------------------------------------

def make_template(facts, components, classified):
    """Generate a reference template from a known-good config."""
    template = {
        '_meta': {
            'source': facts['hostname'],
            'product_id': facts['product_id'],
            'firmware': facts['firmware'],
            'generated_by': 'adam --make-template',
        },
        'match_rules': {},
        'values': {},
    }

    # Hardware identity (identical across fleet)
    template['values']['sw_level'] = facts['sw_level']
    template['values']['firmware'] = facts['firmware']

    # System settings (identical across fleet)
    template['values']['snmp_communities'] = components['snmp_communities']
    template['values']['auto_disable_reasons'] = components['auto_disable_reasons']

    # RSTP global
    if components['rstp_global']:
        template['values']['rstp_global'] = components['rstp_global']

    # Loop protection global
    if components['loop_prot_global']:
        template['values']['loop_prot_global'] = components['loop_prot_global']

    # VLANs (identical across fleet)
    vlan_summary = {}
    for vid, vdata in components['vlans'].items():
        vlan_summary[str(vid)] = {'name': vdata['name']}
    template['values']['vlans'] = vlan_summary

    # MRP config (role-dependent)
    if components['mrp']:
        mrp_summary = []
        for ring in components['mrp']:
            mrp_summary.append({
                'domain': ring['domain'],
                'role': ring['role'],
                'vlan': ring['vlan'],
            })
        template['values']['mrp'] = mrp_summary
        template['match_rules']['mrp_role'] = 'role'

    # Users
    template['values']['users'] = [u['name'] for u in components['users'] if u['active']]

    # Match rules
    template['match_rules']['sw_level'] = 'identical'
    template['match_rules']['firmware'] = 'identical'
    template['match_rules']['hostname'] = 'unique'
    template['match_rules']['snmp_communities'] = 'identical'
    template['match_rules']['auto_disable_reasons'] = 'identical'
    template['match_rules']['vlans'] = 'identical'
    template['match_rules']['rstp_global'] = 'identical'
    template['match_rules']['loop_prot_global'] = 'identical'

    return template


def compare_template(facts, components, classified, template):
    """Compare device config against reference template. Returns findings."""
    findings = []
    tvals = template.get('values', {})
    rules = template.get('match_rules', {})

    # SW level
    if 'sw_level' in tvals:
        ref = tvals['sw_level']
        actual = facts['sw_level']
        if ref != actual:
            findings.append(Finding(
                'template-sw-level', 'warning',
                'SW level differs: ref=%s, actual=%s' % (ref, actual)))
        else:
            findings.append(Finding(
                'template-sw-level', 'info',
                'SW level matches template: %s' % actual, passed=True))

    # Firmware
    if 'firmware' in tvals:
        ref = tvals['firmware']
        actual = facts['firmware']
        if ref != actual:
            findings.append(Finding(
                'template-firmware', 'info',
                'Firmware differs: ref=%s, actual=%s' % (ref, actual)))
        else:
            findings.append(Finding(
                'template-firmware', 'info',
                'Firmware matches template: %s' % actual, passed=True))

    # SNMP communities
    if 'snmp_communities' in tvals:
        ref = set(tvals['snmp_communities'])
        actual = set(components['snmp_communities'])
        if ref != actual:
            extra = actual - ref
            missing = ref - actual
            parts = []
            if extra:
                parts.append('extra: %s' % ', '.join(sorted(extra)))
            if missing:
                parts.append('missing: %s' % ', '.join(sorted(missing)))
            findings.append(Finding(
                'template-snmp-communities', 'warning',
                'SNMP communities differ from template',
                detail='; '.join(parts)))
        else:
            findings.append(Finding(
                'template-snmp-communities', 'info',
                'SNMP communities match template', passed=True))

    # Auto-disable reasons
    if 'auto_disable_reasons' in tvals:
        ref = tvals['auto_disable_reasons']
        actual = components['auto_disable_reasons']
        if ref != actual:
            diff_parts = []
            for reason, enabled in ref.items():
                if actual.get(reason) != enabled:
                    diff_parts.append('%s: ref=%s, actual=%s' % (
                        reason, enabled, actual.get(reason, 'missing')))
            findings.append(Finding(
                'template-auto-disable', 'warning',
                'Auto-disable reasons differ from template',
                detail='; '.join(diff_parts)))
        else:
            findings.append(Finding(
                'template-auto-disable', 'info',
                'Auto-disable reasons match template', passed=True))

    # RSTP global
    if 'rstp_global' in tvals and components['rstp_global']:
        ref = tvals['rstp_global']
        actual = components['rstp_global']
        diffs = []
        for k, v in ref.items():
            if actual.get(k) != v:
                diffs.append('%s: ref=%s, actual=%s' % (k, v, actual.get(k)))
        if diffs:
            findings.append(Finding(
                'template-rstp', 'warning',
                'RSTP global config differs from template',
                detail='; '.join(diffs)))
        else:
            findings.append(Finding(
                'template-rstp', 'info',
                'RSTP global config matches template', passed=True))

    # Loop protection global
    if 'loop_prot_global' in tvals and components['loop_prot_global']:
        ref = tvals['loop_prot_global']
        actual = components['loop_prot_global']
        diffs = []
        for k, v in ref.items():
            if actual.get(k) != v:
                diffs.append('%s: ref=%s, actual=%s' % (k, v, actual.get(k)))
        if diffs:
            findings.append(Finding(
                'template-loop-prot', 'warning',
                'Loop protection global config differs from template',
                detail='; '.join(diffs)))
        else:
            findings.append(Finding(
                'template-loop-prot', 'info',
                'Loop protection config matches template', passed=True))

    # VLANs — names must match
    if 'vlans' in tvals:
        ref_vlans = tvals['vlans']
        actual_vlans = components['vlans']
        ref_ids = set(int(k) for k in ref_vlans.keys())
        actual_ids = set(actual_vlans.keys())
        extra = actual_ids - ref_ids
        missing = ref_ids - actual_ids
        if extra:
            findings.append(Finding(
                'template-vlans', 'info',
                'Extra VLANs not in template: %s' % ', '.join(str(v) for v in sorted(extra))))
        if missing:
            findings.append(Finding(
                'template-vlans', 'warning',
                'Missing VLANs from template: %s' % ', '.join(str(v) for v in sorted(missing))))
        # Check names
        for vid_str, vref in ref_vlans.items():
            vid = int(vid_str)
            if vid in actual_vlans:
                if actual_vlans[vid]['name'] != vref['name']:
                    findings.append(Finding(
                        'template-vlans', 'info',
                        'VLAN %d name mismatch: ref="%s", actual="%s"' % (
                            vid, vref['name'], actual_vlans[vid]['name'])))
        if not extra and not missing:
            findings.append(Finding(
                'template-vlans', 'info',
                'VLAN set matches template', passed=True))

    # MRP
    if 'mrp' in tvals:
        ref_mrp = tvals['mrp']
        actual_mrp = components['mrp']
        if not actual_mrp and ref_mrp:
            findings.append(Finding(
                'template-mrp', 'warning',
                'Template has MRP configured but device does not'))
        for ref_ring in ref_mrp:
            for act_ring in actual_mrp:
                if ref_ring['domain'] == act_ring['domain']:
                    if ref_ring['role'] != act_ring['role']:
                        rule = rules.get('mrp_role', 'identical')
                        sev = 'info' if rule == 'role' else 'warning'
                        findings.append(Finding(
                            'template-mrp', sev,
                            'MRP role differs: ref=%s, actual=%s' % (
                                ref_ring['role'], act_ring['role']),
                            detail='Domain: %s (match rule: %s)' % (
                                ref_ring['domain'], rule)))

    # All template findings are compliance scope
    for f in findings:
        f.scope = 'compliance'
    return findings


# ---------------------------------------------------------------------------
# Site Analysis
# ---------------------------------------------------------------------------

def analyze_site(all_results):
    """Cross-device site analysis. Returns site-level findings."""
    findings = []

    if len(all_results) < 2:
        return findings

    # Check hostname uniqueness
    hostnames = {}
    for r in all_results:
        h = r['facts']['hostname']
        hostnames.setdefault(h, []).append(r['facts']['mgmt_ip'])
    for h, ips in hostnames.items():
        if len(ips) > 1:
            findings.append(Finding(
                'site-hostname-unique', 'warning',
                'Duplicate hostname "%s" on %d devices' % (h, len(ips)),
                detail='IPs: %s' % ', '.join(ips)))

    # Collect VLANs used by MRP/SRM — name differences are topology info, not errors
    ring_vlans = set()
    for r in all_results:
        for ring in r['components']['mrp']:
            ring_vlans.add(ring['vlan'])
        for sr in r['components']['srm']:
            ring_vlans.add(sr['vlan'])

    # Check VLAN name consistency (skip ring/sub-ring VLANs)
    all_vlans = {}
    for r in all_results:
        for vid, vdata in r['components']['vlans'].items():
            all_vlans.setdefault(vid, {}).setdefault(vdata['name'], []).append(
                r['facts']['hostname'])
    for vid, names in all_vlans.items():
        if len(names) > 1 and vid not in ring_vlans:
            parts = ['"%s" on %s' % (n, ', '.join(hosts)) for n, hosts in names.items()]
            findings.append(Finding(
                'site-vlan-name-consistency', 'info',
                'VLAN %d has inconsistent names' % vid,
                detail='; '.join(parts)))

    # Collect SRM VLANs with active managers (needed for MRP RM resolution)
    srm_managed_vlans = {}  # vid -> list of SRM manager hostnames
    for r in all_results:
        srm_global = r['components']['srm_global']
        srm_on = srm_global['enabled'] if srm_global else False
        if not srm_on:
            continue
        for sr in r['components']['srm']:
            if sr['row_status'] == 1 and sr['role'] in ('manager', 'single-manager'):
                srm_managed_vlans.setdefault(sr['vlan'], []).append(r['facts']['hostname'])

    # Check MRP: group by UUID+VLAN (the actual ring identity)
    mrp_rings = {}
    for r in all_results:
        for ring in r['components']['mrp']:
            key = (ring['domain_id'] or '(none)', ring['vlan'])
            mrp_rings.setdefault(key, [])
            mrp_rings[key].append({
                'hostname': r['facts']['hostname'],
                'role': ring['role'],
                'domain_name': ring['domain'],
            })
    for (domain_id, vid), members in mrp_rings.items():
        name = next((m['domain_name'] for m in members if m['domain_name']), '')
        is_default = domain_id.replace(' ', '').replace('F', '') == ''
        if name:
            label = name
        elif is_default:
            label = '(default)'
        else:
            label = domain_id[:23]

        managers = [m['hostname'] for m in members if m['role'] == 'manager']
        clients = [m['hostname'] for m in members if m['role'] != 'manager']
        mgr_count = len(managers)
        if mgr_count == 0:
            # Check if SRM provides the manager role on this VLAN
            srm_mgrs = srm_managed_vlans.get(vid, [])
            if srm_mgrs:
                findings.append(Finding(
                    'site-mrp-rm-count', 'info',
                    'MRP ring "%s" VLAN %d: managed by SRM (%s), %d MRP clients' % (
                        label, vid, ', '.join(srm_mgrs), len(clients)),
                    passed=True))
            else:
                findings.append(Finding(
                    'site-mrp-rm-count', 'critical',
                    'MRP ring "%s" VLAN %d has no ring manager' % (label, vid),
                    detail='Clients: %s' % ', '.join(clients)))
        elif mgr_count > 1:
            findings.append(Finding(
                'site-mrp-rm-count', 'critical',
                'MRP ring "%s" VLAN %d has %d ring managers' % (label, vid, mgr_count),
                detail='Managers: %s' % ', '.join(managers)))
        else:
            findings.append(Finding(
                'site-mrp-rm-count', 'info',
                'MRP ring "%s" VLAN %d: 1 RM (%s), %d clients' % (
                    label, vid, managers[0], len(clients)),
                passed=True))

    # Check SRM: sub-ring membership across site
    # Group by ring_id + VLAN (same logic as MRP — VLAN is the real identity)
    srm_rings = {}
    for r in all_results:
        srm_global = r['components']['srm_global']
        srm_enabled = srm_global['enabled'] if srm_global else False
        for sr in r['components']['srm']:
            key = (sr['ring_id'], sr['vlan'])
            srm_rings.setdefault(key, [])
            vlan_name = r['components']['vlans'].get(sr['vlan'], {}).get('name', '')
            srm_rings[key].append({
                'hostname': r['facts']['hostname'],
                'role': sr['role'],
                'port': sr['port'],
                'ip': r['facts']['mgmt_ip'],
                'vlan_name': vlan_name,
                'row_active': sr['row_status'] == 1,
                'global_on': srm_enabled,
            })
    for (rid, vid), members in srm_rings.items():
        # VLAN name from any member that has it
        vlan_name = next((m['vlan_name'] for m in members if m['vlan_name']), '')
        vlan_label = 'VLAN %d "%s"' % (vid, vlan_name) if vlan_name else 'VLAN %d' % vid

        # Build detail showing all members, role, and effective state
        member_parts = []
        for m in members:
            flags = []
            if not m['row_active']:
                flags.append('notInService')
            if not m['global_on']:
                flags.append('SRM global off')
            suffix = ' [%s]' % ', '.join(flags) if flags else ''
            member_parts.append('%s port %s (%s%s)' % (m['hostname'], m['port'], m['role'], suffix))
        member_detail = ', '.join(member_parts)

        # Effective members = row active + SRM global on
        effective = [m for m in members if m['row_active'] and m['global_on']]

        # Check configured topology (all members regardless of state)
        config_roles = set(m['role'] for m in members)
        if len(members) == 1 and members[0]['role'] == 'single-manager':
            topology_ok = True
            topo_desc = 'single-manager on %s' % members[0]['hostname']
        elif len(members) == 2 and config_roles == {'manager', 'redundant-manager'}:
            topology_ok = True
            topo_desc = 'manager + redundant-manager'
        elif len(members) == 1:
            topology_ok = False
            m = members[0]
            candidates = []
            for r in all_results:
                h = r['facts']['hostname']
                if h != m['hostname'] and vid in r['components']['vlans']:
                    candidates.append(h)
            partner_hint = ''
            if candidates:
                partner_hint = ' — no SRM config on %s (but %s exists there)' % (
                    ', '.join(candidates), vlan_label)
            topo_desc = 'only %s configured (%s)%s' % (m['hostname'], m['role'], partner_hint)
        else:
            topology_ok = False
            topo_desc = '%d members, roles: %s' % (len(members), ', '.join(sorted(config_roles)))

        # Check effective state
        if topology_ok and len(effective) == len(members):
            findings.append(Finding(
                'site-srm-topology', 'info',
                'SRM sub-ring %d %s: %s' % (rid, vlan_label, topo_desc),
                detail=member_detail,
                passed=True))
        elif topology_ok and len(effective) < len(members):
            inactive = [m for m in members if m not in effective]
            reasons = []
            for m in inactive:
                if not m['global_on']:
                    reasons.append('%s: SRM global off' % m['hostname'])
                elif not m['row_active']:
                    reasons.append('%s: notInService' % m['hostname'])
            findings.append(Finding(
                'site-srm-topology', 'warning',
                'SRM sub-ring %d %s: configured correctly but %d/%d effective' % (
                    rid, vlan_label, len(effective), len(members)),
                detail='%s | Inactive: %s' % (member_detail, ', '.join(reasons))))
        else:
            findings.append(Finding(
                'site-srm-topology', 'warning',
                'SRM sub-ring %d %s: %s' % (rid, vlan_label, topo_desc),
                detail=member_detail))

    return findings


# ---------------------------------------------------------------------------
# Report Output
# ---------------------------------------------------------------------------

def format_report(facts, components, classified, findings, c, show_passes=False):
    """Format human-readable report."""
    lines = []

    # Device header
    lines.append('')
    lines.append('%s%sDEVICE: %s%s (%s, %s, %s)' % (
        c.BOLD, c.WHT, facts['hostname'], c.RST,
        facts['family'], facts['sw_level'], facts['firmware']))
    lines.append('  IP: %s/%s | VLANs: %d | Ports: %d' % (
        facts['mgmt_ip'], facts['prefix_len'],
        len(components['vlans']), len(facts['ports'])))
    if facts.get('vlan_ips'):
        for vif in sorted(facts['vlan_ips'].keys(), key=port_sort_key):
            vi = facts['vlan_ips'][vif]
            lines.append('  %s: %s/%s' % (vif, vi['ip'], vi['prefix']))
    lines.append('')

    # Split findings: device-scope vs compliance/site-scope, port vs global
    dev_global = []
    dev_port = {}
    comp_global = []
    comp_port = {}
    for f in findings:
        is_comp = f.scope in ('site', 'compliance')
        bucket_global = comp_global if is_comp else dev_global
        bucket_port = comp_port if is_comp else dev_port
        if f.port:
            bucket_port.setdefault(f.port, []).append(f)
        else:
            bucket_global.append(f)

    # --- DEVICE AUDIT ---
    lines.append('  %s%sDEVICE AUDIT%s' % (c.BOLD, c.WHT, c.RST))

    # Device-level findings
    shown = [f for f in dev_global if show_passes or not f.passed]
    if shown:
        for f in sorted(shown, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            lines.append('    %s' % _format_finding(f, c))
        lines.append('')

    # Per-port output (device scope)
    for port in sorted(classified.keys(), key=port_sort_key):
        info = classified[port]
        pf = dev_port.get(port, [])
        shown = [f for f in pf if show_passes or not f.passed]

        desc_parts = _port_desc_parts(info, components)
        port_desc = ' | '.join(desc_parts)

        if shown or show_passes:
            lines.append('  %sPORT %s%s — role: %s%s%s (%s)' % (
                c.BOLD, port, c.RST,
                _role_color(info['role'], c), info['role'], c.RST,
                port_desc))
            for f in sorted(shown, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
                lines.append('    %s' % _format_finding(f, c))
            lines.append('')

    # --- COMPLIANCE (if any compliance/site-scope findings exist) ---
    comp_shown = [f for f in comp_global if show_passes or not f.passed]
    comp_port_shown = any(
        any(show_passes or not f.passed for f in pf)
        for pf in comp_port.values())
    if comp_shown or comp_port_shown:
        lines.append('  %s%sCOMPLIANCE%s' % (c.BOLD, c.WHT, c.RST))
        for f in sorted(comp_shown, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            lines.append('    %s' % _format_finding(f, c))
        for port in sorted(comp_port.keys(), key=port_sort_key):
            pf = comp_port[port]
            shown = [f for f in pf if show_passes or not f.passed]
            if shown:
                for f in sorted(shown, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
                    lines.append('    %s [%s]' % (_format_finding(f, c), port))
        lines.append('')

    # --- MANUAL CHECKS (live-only, not checkable from XML) ---
    lines.append('  %s%sMANUAL CHECKS%s %s(requires SSH to device)%s' % (
        c.BOLD, c.WHT, c.RST, c.DIM, c.RST))
    for mc in MANUAL_CHECKS:
        lines.append('    %s[CHECK]%s %s (§%s)' % (c.CYN, c.RST, mc['desc'], mc['ref']))
        lines.append('      %s$ %s%s' % (c.DIM, mc['command'], c.RST))
        lines.append('      %sPass: %s%s' % (c.DIM, mc['expect'], c.RST))
        lines.append('      %sFail: %s%s' % (c.DIM, mc['fail'], c.RST))
    lines.append('')

    return '\n'.join(lines)


# Live-only checks: can't be determined from XML config export
MANUAL_CHECKS = [
    # --- §2.11 Device Security ---
    {
        'ref': '2.11.3',
        'desc': 'Verify device security status and secure boot',
        'command': 'show security-status state',
        'expect': 'OperState = noerror, no Events listed',
        'fail': 'OperState = error, Events show specific violations',
    },
    {
        'ref': '2.11.6',
        'desc': 'Signal contact mode should match intended use',
        'command': 'show signal-contact',
        'expect': 'Mode and monitoring settings match site policy',
        'fail': 'Unexpected mode or monitoring items enabled/disabled',
    },
    {
        'ref': '2.11.7',
        'desc': 'Digital input should be disabled if unused',
        'command': 'show digital-input config',
        'expect': 'Admin-state disabled (if no external sensors connected)',
        'fail': 'Digital input polling active with no connected sensors',
    },
    {
        'ref': '2.11.18',
        'desc': 'HTTPS certificate should not be auto-generated self-signed',
        'command': 'show https',
        'expect': 'Certificate fingerprint matches known CA-signed cert',
        'fail': '"Auto generated HTTPS certificate in use" in security-status events',
    },
    {
        'ref': '2.11.19',
        'desc': 'Verify SSH host key fingerprint is expected',
        'command': 'show ssh server',
        'expect': 'RSA key fingerprint matches documented value',
        'fail': 'Fingerprint differs from expected (key was regenerated or replaced)',
    },
    {
        'ref': '2.11.20',
        'desc': 'SSH known hosts should be configured for SFTP/SCP servers',
        'command': 'show ssh',
        'expect': 'Known hosts list contains expected server fingerprints',
        'fail': 'No known hosts configured — device cannot verify SFTP/SCP servers',
    },
    {
        'ref': '2.11.26',
        'desc': 'Verify certificates and revocation lists',
        'command': 'show security-status monitor',
        'expect': 'HTTPS certificate warning monitor enabled, no alerts',
        'fail': 'Certificate warnings present or monitors disabled',
    },
    {
        'ref': '2.11.32',
        'desc': 'CLI service shell should be permanently disabled',
        'command': 'show serviceshell',
        'expect': 'Service shell status: Deactivated',
        'fail': 'Service shell active — run: serviceshell-f deactivate (irreversible)',
    },
    # --- §3 Network Security ---
    {
        'ref': '3.6.3',
        'desc': 'Management MAC conflict detection should be enabled',
        'command': 'show address-conflict global',
        'expect': 'Operation: enabled, detection-mode: active-and-passive',
        'fail': 'Address conflict detection disabled',
    },
    {
        'ref': '3.9.1',
        'desc': 'Persistent logging to external memory for audit trail',
        'command': 'show logging persistent',
        'expect': 'Operation: enabled, target: ENVM',
        'fail': 'Persistent logging disabled — log history lost on reboot',
    },
    # --- Operational ---
    {
        'ref': 'ops',
        'desc': 'Running config should be saved to NVM',
        'command': 'show config status (or check CLI prompt)',
        'expect': 'Clean prompt: (BRS)# or (GRS)#',
        'fail': 'Prompt shows ! or * — unsaved changes exist',
    },
]


def format_site_report(site_findings, c, show_passes=False):
    """Format site-level findings."""
    lines = []
    shown = [f for f in site_findings if show_passes or not f.passed]
    if not shown:
        return ''

    lines.append('')
    lines.append('%s%sSITE ANALYSIS%s' % (c.BOLD, c.WHT, c.RST))
    for f in sorted(shown, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
        lines.append('  %s' % _format_finding(f, c))
    lines.append('')
    return '\n'.join(lines)


def _port_desc_parts(info, components):
    """Build description parts for a port."""
    parts = []
    if info['tagged']:
        parts.append('tagged: VLAN %s' % ','.join(str(v) for v in info['tagged']))
    if info['untagged']:
        for vid in info['untagged']:
            vdata = components['vlans'].get(vid, {})
            vname = vdata.get('name', '')
            if vname:
                parts.append('VLAN %d "%s" untagged' % (vid, vname))
            else:
                parts.append('VLAN %d untagged' % vid)
    parts.append('PVID: %d' % info['pvid'])
    if not info['admin_up']:
        parts.append('ADMIN DOWN')
    return parts


def _format_finding(f, c):
    if f.passed:
        label = '%s[PASS]%s' % (c.GRN, c.RST)
    else:
        sev = f.severity
        if sev == 'critical':
            label = '%s[CRIT]%s' % (c.RED, c.RST)
        elif sev == 'warning':
            label = '%s[WARN]%s' % (c.YEL, c.RST)
        else:
            label = '%s[INFO]%s' % (c.CYN, c.RST)
    line = '%s %s' % (label, f.desc)
    if f.detail and not f.passed:
        line += ' %s— %s%s' % (c.DIM, f.detail, c.RST)
    return line


def _role_color(role, c):
    return {
        'ring': c.RED,
        'sub-ring': c.RED,
        'trunk': c.YEL,
        'lag': c.CYN,
        'edge': c.GRN,
    }.get(role, c.WHT)


def format_json(facts, components, classified, findings):
    """Format JSON output."""
    result = {
        'device': {
            'hostname': facts['hostname'],
            'product_id': facts['product_id'],
            'family': facts['family'],
            'firmware': facts['firmware'],
            'sw_level': facts['sw_level'],
            'mgmt_ip': facts['mgmt_ip'],
            'vlan_ips': facts.get('vlan_ips', {}),
            'port_count': len(facts['ports']),
            'vlan_count': len(components['vlans']),
        },
        'ports': {},
        'findings': [f.to_dict() for f in findings],
    }
    for port, info in classified.items():
        result['ports'][port] = info
    return json.dumps(result, indent=2, sort_keys=True)


def format_html(plain_text, title='ADAM Report'):
    """Convert plain text report to styled HTML."""
    import html as html_mod

    # Map severity tags to CSS classes
    def style_line(line):
        escaped = html_mod.escape(line)
        # Findings
        escaped = escaped.replace('[CRIT]', '<span class="crit">[CRIT]</span>')
        escaped = escaped.replace('[WARN]', '<span class="warn">[WARN]</span>')
        escaped = escaped.replace('[INFO]', '<span class="info">[INFO]</span>')
        escaped = escaped.replace('[PASS]', '<span class="pass">[PASS]</span>')
        escaped = escaped.replace('[CHECK]', '<span class="check">[CHECK]</span>')
        # Headers
        if escaped.startswith('DEVICE:'):
            escaped = '<span class="device-header">%s</span>' % escaped
        elif escaped.startswith('SITE ANALYSIS'):
            escaped = '<span class="site-header">%s</span>' % escaped
        elif '  DEVICE AUDIT' in escaped:
            escaped = escaped.replace('DEVICE AUDIT', '<span class="section">DEVICE AUDIT</span>')
        elif '  COMPLIANCE' in escaped:
            escaped = escaped.replace('COMPLIANCE', '<span class="section">COMPLIANCE</span>')
        elif '  MANUAL CHECKS' in escaped:
            escaped = escaped.replace('MANUAL CHECKS', '<span class="section">MANUAL CHECKS</span>')
        elif escaped.strip().startswith('PORT '):
            escaped = '<span class="port-header">%s</span>' % escaped
        return escaped

    lines = plain_text.split('\n')
    styled = '\n'.join(style_line(l) for l in lines)

    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s</title>
<style>
body { background: #1a1a2e; color: #e0e0e0; font-family: "Cascadia Code", "Fira Code", monospace; font-size: 13px; padding: 20px 40px; line-height: 1.6; }
pre { white-space: pre-wrap; word-wrap: break-word; }
.device-header { color: #fff; font-weight: bold; font-size: 15px; }
.site-header { color: #fff; font-weight: bold; font-size: 15px; border-top: 1px solid #444; padding-top: 12px; display: inline-block; margin-top: 8px; }
.section { color: #ccc; font-weight: bold; }
.port-header { color: #88c0d0; }
.crit { color: #ff5555; font-weight: bold; }
.warn { color: #f1c40f; }
.info { color: #3498db; }
.pass { color: #2ecc71; }
.check { color: #88c0d0; }
.meta { color: #888; font-size: 11px; border-top: 1px solid #333; padding-top: 8px; margin-top: 20px; }
</style>
</head>
<body>
<pre>%s</pre>
<div class="meta">Generated by ADAM (Automated Device Audit Model)</div>
</body>
</html>''' % (html_mod.escape(title), styled)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def process_single(xml_path, checks_dir, template=None, show_passes=False,
                   json_output=False, severity_filter=None, c=C):
    """Process a single XML config file. Returns result dict."""
    config = parse_config(xml_path)
    facts = get_facts(config)
    components = discover_components(config, facts)
    classified = classify_ports(facts, components)
    check_defs = load_checks(checks_dir)
    findings = run_checks(check_defs, facts, components, classified)

    # Severity filter
    if severity_filter:
        min_sev = SEVERITY_ORDER.get(severity_filter, 9)
        findings = [f for f in findings if f.passed or SEVERITY_ORDER.get(f.severity, 9) <= min_sev]

    # Template comparison — merge into findings (scope='compliance')
    if template:
        drift = compare_template(facts, components, classified, template)
        if severity_filter:
            min_sev = SEVERITY_ORDER.get(severity_filter, 9)
            drift = [f for f in drift if f.passed or SEVERITY_ORDER.get(f.severity, 9) <= min_sev]
        findings.extend(drift)

    if json_output:
        return {
            'facts': facts, 'components': components, 'classified': classified,
            'findings': findings,
            'json_str': format_json(facts, components, classified, findings),
        }

    output = format_report(facts, components, classified, findings, c, show_passes)

    return {
        'facts': facts, 'components': components, 'classified': classified,
        'findings': findings, 'output': output,
    }


def main():
    parser = argparse.ArgumentParser(
        description='ADAM — Automated Device Audit Model',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  adam.py config.xml              Device report\n'
               '  adam.py config.xml -t ref.json   Device + compliance\n'
               '  adam.py configs/                 Device + site\n'
               '  adam.py good.xml --make-template Generate reference\n')
    parser.add_argument('path', help='XML config file or directory of configs')
    parser.add_argument('-t', '--template', help='Template JSON for compliance comparison')
    parser.add_argument('-s', '--severity', choices=['critical', 'warning', 'info'],
                        help='Minimum severity to show')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show passing checks')
    parser.add_argument('-j', '--json', action='store_true', help='JSON output')
    parser.add_argument('--no-color', action='store_true', help='Disable color output')
    parser.add_argument('-o', '--output', help='Write report to file (.txt, .html, or .json)')
    parser.add_argument('--make-template', action='store_true',
                        help='Generate reference template from this config')
    args = parser.parse_args()

    # When writing to file, force no-color for plain text generation
    out_file = args.output
    out_ext = os.path.splitext(out_file)[1].lower() if out_file else ''
    if out_ext == '.json':
        args.json = True
    file_color = NO_COLOR  # always plain for file output
    c = NO_COLOR if args.no_color or not sys.stdout.isatty() else C

    # Resolve checks directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    checks_dir = os.path.join(script_dir, 'checks')

    # Template mode
    if args.make_template:
        config = parse_config(args.path)
        facts = get_facts(config)
        components = discover_components(config, facts)
        classified = classify_ports(facts, components)
        template = make_template(facts, components, classified)
        print(json.dumps(template, indent=2, sort_keys=True))
        return

    # Load template if specified
    template = None
    if args.template:
        with open(args.template, 'r') as f:
            template = json.load(f)

    target = args.path

    # Choose color scheme: file output always plain, stdout may have color
    report_c = file_color if out_file else c

    if os.path.isdir(target):
        # Directory mode: process all XML files
        xml_files = sorted(f for f in os.listdir(target) if f.endswith('.xml'))
        if not xml_files:
            print('No XML files found in %s' % target, file=sys.stderr)
            sys.exit(1)

        all_results = []
        for fn in xml_files:
            path = os.path.join(target, fn)
            result = process_single(path, checks_dir, template, args.verbose,
                                    args.json, args.severity, report_c)
            all_results.append(result)

        if args.json:
            combined = {
                'devices': [format_json(r['facts'], r['components'], r['classified'],
                                        r['findings'], r.get('drift'))
                            for r in all_results],
            }
            site_findings = analyze_site(all_results)
            combined['site'] = [f.to_dict() for f in site_findings]
            final_output = json.dumps(combined, indent=2)
        else:
            parts = [r['output'] for r in all_results]
            site_findings = analyze_site(all_results)
            if args.severity:
                min_sev = SEVERITY_ORDER.get(args.severity, 9)
                site_findings = [f for f in site_findings
                                 if f.passed or SEVERITY_ORDER.get(f.severity, 9) <= min_sev]
            site_report = format_site_report(site_findings, report_c, args.verbose)
            if site_report:
                parts.append(site_report)
            final_output = '\n'.join(parts)

    elif os.path.isfile(target):
        result = process_single(target, checks_dir, template, args.verbose,
                                args.json, args.severity, report_c)
        if args.json:
            final_output = result.get('json_str', '')
        else:
            final_output = result['output']
    else:
        print('Path not found: %s' % target, file=sys.stderr)
        sys.exit(1)
        return

    # Output: file or stdout
    if out_file:
        if out_ext == '.html':
            final_output = format_html(final_output)
        with open(out_file, 'w') as f:
            f.write(final_output)
            f.write('\n')
        print('Report written to %s' % out_file, file=sys.stderr)
    else:
        print(final_output)


if __name__ == '__main__':
    main()
