"""
VIKTOR — VLAN Intent, Knowledgeable Topology-Optimized Rules

Fleet-wide VLAN provisioning for Hirschmann HiOS switches.
Consumes the napalm-hios VLAN API (get/set ingress/egress, create/update/delete)
to manage VLANs across multiple switches from one command.

Usage:
    python viktor.py vlan list
    python viktor.py vlan create 5 --name "Cameras"
    python viktor.py vlan delete 5
    python viktor.py vlan rename 5 "Cameras-v2"
    python viktor.py access 1/1-1/8 5
    python viktor.py access 1/1-1/8 5 --name "Cameras"
    python viktor.py trunk 1/8 5,6,3
    python viktor.py auto-trunk 5 --name "Cameras"
    python viktor.py -m100 auto-trunk 5
    python viktor.py --audit
    python viktor.py --names
    python viktor.py --export vlans.csv
    python viktor.py --import vlans.csv
"""

import sys
import os
import re
import csv
import logging
import ipaddress
import argparse
import time
from collections import Counter
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


def natural_sort_key(interface: str):
    """Sort key that handles '1/1', '1/10', '2/3' naturally."""
    return [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', interface)]


def log_print(msg, level='info'):
    """Print to console and log."""
    print(msg)
    getattr(logging, level)(msg.strip())


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='VIKTOR — VLAN Intent, Knowledgeable Topology-Optimized Rules'
    )

    # Global args
    parser.add_argument('-c', default='script.cfg',
                        help='config file (default: script.cfg)')
    parser.add_argument('-d', metavar='IP',
                        help='single device IP')
    parser.add_argument('--ips', metavar='TARGETS',
                        help='comma list, last-octet range, or CIDR')
    parser.add_argument('-m', metavar='VLAN', type=int, default=None,
                        help='ring selector — filter by MRP VLAN egress')
    parser.add_argument('-u', metavar='USER', default=None,
                        help='username override')
    parser.add_argument('-p', metavar='PASS', default=None,
                        help='password override')
    parser.add_argument('--protocol', default=None,
                        choices=['mops', 'snmp', 'ssh'],
                        help='protocol (default: mops)')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='80s-style guided wizard')
    parser.add_argument('--debug', action='store_true',
                        help='verbose logging')
    parser.add_argument('--dry-run', action='store_true',
                        help='show plan only')
    parser.add_argument('--save', action='store_true',
                        help='save to NVM after changes')

    # Fleet-wide flags (no subcommand)
    parser.add_argument('--audit', action='store_true',
                        help='read-only VLAN health check')
    parser.add_argument('--names', action='store_true',
                        help='VLAN name consistency audit + fix')
    parser.add_argument('--export', metavar='FILE',
                        help='export fleet VLAN state to CSV')
    # --import is a Python keyword, use dest
    parser.add_argument('--import', metavar='FILE', dest='import_file',
                        help='import VLAN state from CSV')

    subparsers = parser.add_subparsers(dest='command')

    # vlan CRUD
    p_vlan = subparsers.add_parser('vlan', help='VLAN CRUD operations')
    vlan_sub = p_vlan.add_subparsers(dest='vlan_action')

    p_vlan_list = vlan_sub.add_parser('list', help='list VLANs on all devices')

    p_vlan_create = vlan_sub.add_parser('create', help='create a VLAN')
    p_vlan_create.add_argument('vlan_id', type=int, help='VLAN ID')
    p_vlan_create.add_argument('--name', default='', help='VLAN name')

    p_vlan_delete = vlan_sub.add_parser('delete', help='delete a VLAN')
    p_vlan_delete.add_argument('vlan_id', type=int, help='VLAN ID')

    p_vlan_rename = vlan_sub.add_parser('rename', help='rename a VLAN')
    p_vlan_rename.add_argument('vlan_id', type=int, help='VLAN ID')
    p_vlan_rename.add_argument('name', help='new VLAN name')

    # access
    p_access = subparsers.add_parser('access', help='set ports to strict access mode')
    p_access.add_argument('ports', help='port spec (e.g. 1/1-1/8,2/1)')
    p_access.add_argument('vlan_id', type=int, help='access VLAN ID')
    p_access.add_argument('--name', default=None,
                          help='create VLAN with this name if missing')

    # trunk
    p_trunk = subparsers.add_parser('trunk', help='tag ports for VLANs (additive)')
    p_trunk.add_argument('ports', help='port spec (e.g. 1/5,1/6)')
    p_trunk.add_argument('vlan_ids', help='comma-separated VLAN IDs (e.g. 5,6,3)')

    # auto-trunk
    p_autotrunk = subparsers.add_parser('auto-trunk',
                                         help='tag inter-switch links for a VLAN')
    p_autotrunk.add_argument('vlan_id', type=int, help='VLAN ID to trunk')
    p_autotrunk.add_argument('--name', default=None,
                              help='create VLAN with this name if missing')

    # qos
    p_qos = subparsers.add_parser('qos',
                                    help='set default PCP on ports carrying a VLAN')
    p_qos.add_argument('vlan_ids',
                        help='VLAN ID or comma-separated list (e.g. 5 or 5,6,10)')
    p_qos.add_argument('--pcp', type=int, required=True,
                        help='default PCP value (0-7)')
    p_qos.add_argument('--include-trunk', action='store_true',
                        help='also set PCP on inter-switch trunk ports (default: edge only)')

    return parser.parse_args()


def parse_config(config_file: str) -> dict:
    """Parse script.cfg into settings and device list."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found")

    _BOOL_TRUE = {'true', 'yes', '1', 'on'}

    config = {
        'username': 'admin',
        'password': 'private',
        'protocol': 'mops',
        'devices': [],
        'ring': None,
        'save': False,
        'debug': False,
    }

    _KNOWN_KEYS = {
        'username', 'password', 'protocol', 'ring', 'save', 'debug',
    }

    with open(config_file, 'r') as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            if '=' in line:
                key, _, val = line.partition('=')
                key = key.strip().lower()
                val = val.strip()

                if key not in _KNOWN_KEYS:
                    logging.warning(f"Line {line_num}: unknown setting '{key}'")
                    continue

                if key == 'username':
                    config['username'] = val
                elif key == 'password':
                    config['password'] = val
                elif key == 'protocol':
                    config['protocol'] = val.lower()
                elif key == 'ring':
                    config['ring'] = int(val)
                elif key == 'save':
                    config['save'] = val.lower() in _BOOL_TRUE
                elif key == 'debug':
                    config['debug'] = val.lower() in _BOOL_TRUE
                continue

            ip = line.split()[0]
            if is_valid_ipv4(ip):
                config['devices'].append(ip)
            else:
                logging.warning(f"Line {line_num}: skipping invalid IP '{ip}'")

    return config


def parse_ips(spec: str) -> list:
    """Parse --ips spec into list of IPs.

    Formats:
      Comma: 192.168.1.1,192.168.1.5
      Last-octet range: 192.168.1.1-20
      CIDR: 192.168.1.0/24
    """
    ips = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue

        # CIDR
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                ips.extend(str(h) for h in net.hosts())
            except ValueError:
                raise ValueError(f"Invalid CIDR: {part}")
            continue

        # Last-octet range: 192.168.1.1-20
        m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', part)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            if start > end:
                raise ValueError(f"Invalid range: {part} (start > end)")
            for i in range(start, end + 1):
                ip = f"{prefix}{i}"
                if is_valid_ipv4(ip):
                    ips.append(ip)
            continue

        # Single IP
        if is_valid_ipv4(part):
            ips.append(part)
        else:
            raise ValueError(f"Invalid IP: {part}")

    return ips


def parse_port_spec(spec: str) -> list:
    """Parse port specification into list of port names.

    Examples:
      '1/1'       → ['1/1']
      '1/1-1/8'   → ['1/1', '1/2', ..., '1/8']
      '1/1-1/4,2/1-2/4' → ['1/1', ..., '1/4', '2/1', ..., '2/4']
    """
    ports = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue

        # Range: 1/1-1/8
        m = re.match(r'^(\d+)/(\d+)-(\d+)/(\d+)$', part)
        if m:
            slot1, port1, slot2, port2 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            if slot1 != slot2:
                raise ValueError(f"Cross-slot range not supported: {part}")
            if port1 > port2:
                raise ValueError(f"Invalid range: {part} (start > end)")
            for p in range(port1, port2 + 1):
                ports.append(f"{slot1}/{p}")
            continue

        # Single: 1/5
        m = re.match(r'^(\d+)/(\d+)$', part)
        if m:
            ports.append(part)
            continue

        raise ValueError(f"Invalid port spec: {part}")

    return ports


def parse_vlan_list(spec: str) -> list:
    """Parse comma-separated VLAN IDs. '5,6,3' → [5, 6, 3]."""
    vlans = []
    for part in spec.split(','):
        part = part.strip()
        if part:
            try:
                vlans.append(int(part))
            except ValueError:
                raise ValueError(f"Invalid VLAN ID: {part}")
    return vlans


def resolve_config(args) -> dict:
    """Build final config from config file + CLI overrides."""
    config = None

    if args.d:
        config = {
            'username': args.u or 'admin',
            'password': args.p or 'private',
            'protocol': args.protocol or 'mops',
            'devices': [args.d],
            'ring': None,
            'save': False,
            'debug': False,
        }
    elif args.ips:
        # Parse --ips, but still read script.cfg for credentials if it exists
        devices = parse_ips(args.ips)
        cfg_path = get_resource_path(args.c)
        if os.path.exists(cfg_path):
            config = parse_config(cfg_path)
            config['devices'] = devices
        else:
            config = {
                'username': args.u or 'admin',
                'password': args.p or 'private',
                'protocol': args.protocol or 'mops',
                'devices': devices,
                'ring': None,
                'save': False,
                'debug': False,
            }
    else:
        cfg_path = get_resource_path(args.c)
        config = parse_config(cfg_path)

    # CLI overrides (CLI wins over cfg)
    if args.u:
        config['username'] = args.u
    if args.p:
        config['password'] = args.p
    if args.protocol:
        config['protocol'] = args.protocol
    if args.m is not None:
        config['ring'] = args.m
    if args.save:
        config['save'] = True
    if args.debug:
        config['debug'] = True

    if not config['devices']:
        raise ValueError("No devices specified — use -d <ip>, --ips, or add IPs to config file")

    return config


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def worker_connect(driver, config, ip, timeout=30):
    """Thread worker: open connection to one device, return (ip, device, error)."""
    try:
        device = driver(
            hostname=ip,
            username=config['username'],
            password=config['password'],
            timeout=timeout,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()
        return ip, device, None
    except Exception as e:
        return ip, None, str(e)


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
            print(f"  [FAIL] {ip} — {err}")
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
# Gathering
# ---------------------------------------------------------------------------

def worker_gather_vlan(device, ip):
    """Gather VLAN data from one device."""
    try:
        facts = device.get_facts()
        ingress = device.get_vlan_ingress()
        egress = device.get_vlan_egress()
        return ip, {
            'hostname': facts.get('hostname', ip),
            'interfaces': facts.get('interface_list', []),
            'ingress': ingress,
            'egress': egress,
        }, None
    except Exception as e:
        return ip, None, str(e)


def worker_gather_full(device, ip):
    """Gather VLAN + LLDP data from one device."""
    try:
        facts = device.get_facts()
        ingress = device.get_vlan_ingress()
        egress = device.get_vlan_egress()
        lldp = device.get_lldp_neighbors_detail()
        return ip, {
            'hostname': facts.get('hostname', ip),
            'interfaces': facts.get('interface_list', []),
            'ingress': ingress,
            'egress': egress,
            'lldp': lldp,
        }, None
    except Exception as e:
        return ip, None, str(e)


def gather_fleet(connections, need_lldp=False):
    """Parallel gather from all connected devices."""
    fleet = {}
    worker = worker_gather_full if need_lldp else worker_gather_vlan

    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker, device, ip): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            ip, data, err = future.result()
            if data:
                fleet[ip] = data
                logging.info(f"[{ip}] Gathered: {data['hostname']}")
            else:
                print(f"  [FAIL] {ip} — gather error: {err}")

    return fleet


# ---------------------------------------------------------------------------
# Ring selector
# ---------------------------------------------------------------------------

def filter_ring_members(fleet_data, ring_vlan):
    """Filter fleet to devices where ring_vlan exists in egress table.
    Adds 'ring_ports' set to each device — ports tagged for ring_vlan."""
    filtered = {}
    for ip, data in fleet_data.items():
        egress = data['egress']
        if ring_vlan in egress:
            vlan_ports = egress[ring_vlan].get('ports', {})
            ring_ports = set()
            for port, mode in vlan_ports.items():
                if mode in ('tagged', 'untagged'):
                    ring_ports.add(port)
            if ring_ports:
                data['ring_ports'] = ring_ports
                filtered[ip] = data
    return filtered


# ---------------------------------------------------------------------------
# LLDP link building
# ---------------------------------------------------------------------------

def _normalize_port_desc(desc):
    """Normalize HiOS LLDP port description to slot/port format.
    'Module: 1 Port: 6 - 1 Gbit' → '1/6'
    Already-normalized '1/6' passes through unchanged.
    """
    m = re.match(r'Module:\s*(\d+)\s+Port:\s*(\d+)', desc)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return desc


def build_lldp_links(fleet_data):
    """Build list of inter-switch links from LLDP data.
    Returns [(local_ip, local_port, remote_ip, remote_port), ...]
    """
    # Build hostname→ip map
    name_to_ip = {}
    for ip, data in fleet_data.items():
        name = data.get('hostname', '')
        if name:
            name_to_ip[name.lower()] = ip

    # Build IP→IP map from management addresses
    mgmt_to_ip = {}
    for ip in fleet_data:
        mgmt_to_ip[ip] = ip

    links = []
    seen = set()

    for ip, data in fleet_data.items():
        lldp = data.get('lldp', {})
        for local_port, neighbors in lldp.items():
            for neighbor in neighbors:
                # Try management address first (most reliable)
                remote_ip = None
                mgmt_addr = neighbor.get('remote_management_address', '')
                if mgmt_addr and mgmt_addr in mgmt_to_ip:
                    remote_ip = mgmt_addr

                # Fallback: match by system name
                if not remote_ip:
                    remote_name = neighbor.get('remote_system_name', '').lower()
                    if remote_name and remote_name in name_to_ip:
                        remote_ip = name_to_ip[remote_name]

                if not remote_ip or remote_ip == ip:
                    continue
                if remote_ip not in fleet_data:
                    continue

                raw_port = (neighbor.get('remote_port_description', '')
                            or neighbor.get('remote_port', ''))
                remote_port = _normalize_port_desc(raw_port)

                # Deduplicate (A→B == B→A) using IP pair + sorted ports
                link_key = frozenset([(ip, local_port), (remote_ip, remote_port)])
                if link_key not in seen:
                    seen.add(link_key)
                    links.append((ip, local_port, remote_ip, remote_port))

    return links


# ---------------------------------------------------------------------------
# VLAN CRUD workers
# ---------------------------------------------------------------------------

def worker_vlan_create(device, ip, vlan_id, name):
    """Create a VLAN on one device."""
    try:
        device.create_vlan(vlan_id, name=name)
        label = f"VLAN {vlan_id}"
        if name:
            label += f" ({name})"
        return ip, True, f"created {label}"
    except Exception as e:
        return ip, False, str(e)


def worker_vlan_delete(device, ip, vlan_id):
    """Delete a VLAN from one device."""
    try:
        device.delete_vlan(vlan_id)
        return ip, True, f"deleted VLAN {vlan_id}"
    except Exception as e:
        return ip, False, str(e)


def worker_vlan_rename(device, ip, vlan_id, name):
    """Rename a VLAN on one device."""
    try:
        device.update_vlan(vlan_id, name)
        return ip, True, f"renamed VLAN {vlan_id} → {name}"
    except Exception as e:
        return ip, False, str(e)


# ---------------------------------------------------------------------------
# Port operation workers
# ---------------------------------------------------------------------------

def worker_set_access(device, ip, ports, vlan_id, current_egress, use_staging):
    """Set ports to strict access mode for a VLAN.

    Logic:
      1. Add ports as untagged on target VLAN
      2. Remove ports from all other VLANs
      3. Set PVID to target VLAN
    """
    try:
        # Determine which VLANs to remove from
        remove_vlans = []
        for vid, vdata in current_egress.items():
            if vid == vlan_id:
                continue
            vlan_ports = vdata.get('ports', {})
            overlap = [p for p in ports if p in vlan_ports]
            if overlap:
                remove_vlans.append((vid, overlap))

        # Stage if MOPS
        if use_staging:
            try:
                device.start_staging()
            except (NotImplementedError, AttributeError):
                use_staging = False

        # Add first (avoid moment with no VLAN membership)
        device.set_vlan_egress(vlan_id, ports, 'untagged')

        # Remove from other VLANs
        for vid, overlap_ports in remove_vlans:
            device.set_vlan_egress(vid, overlap_ports, 'none')

        if use_staging:
            device.commit_staging()

        # Set PVID (separate call — different MIB table)
        device.set_vlan_ingress(ports, pvid=vlan_id)

        return ip, True, f"access VLAN {vlan_id} on {', '.join(ports)}"
    except Exception as e:
        if use_staging:
            try:
                device.discard_staging()
            except Exception:
                pass
        return ip, False, str(e)


def worker_set_trunk(device, ip, ports, vlan_ids, use_staging):
    """Tag ports for VLANs (additive — doesn't touch PVID or other VLANs)."""
    try:
        if use_staging:
            try:
                device.start_staging()
            except (NotImplementedError, AttributeError):
                use_staging = False

        for vid in vlan_ids:
            device.set_vlan_egress(vid, ports, 'tagged')

        if use_staging:
            device.commit_staging()

        vlan_str = ', '.join(str(v) for v in vlan_ids)
        return ip, True, f"tagged VLANs {vlan_str} on {', '.join(ports)}"
    except Exception as e:
        if use_staging:
            try:
                device.discard_staging()
            except Exception:
                pass
        return ip, False, str(e)


# ---------------------------------------------------------------------------
# Audit checks
# ---------------------------------------------------------------------------

def check_lldp_crosscheck(fleet_data, links):
    """Check VLAN mismatch across inter-switch links."""
    findings = []
    for local_ip, local_port, remote_ip, remote_port in links:
        local_egress = fleet_data[local_ip]['egress']
        remote_egress = fleet_data[remote_ip]['egress']

        local_vlans = set()
        remote_vlans = set()

        for vid, vdata in local_egress.items():
            if local_port in vdata.get('ports', {}):
                local_vlans.add(vid)

        for vid, vdata in remote_egress.items():
            if remote_port in vdata.get('ports', {}):
                remote_vlans.add(vid)

        only_local = local_vlans - remote_vlans
        only_remote = remote_vlans - local_vlans

        if only_local or only_remote:
            findings.append({
                'check': 'lldp_crosscheck',
                'severity': 'warning',
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'only_local': sorted(only_local),
                'only_remote': sorted(only_remote),
            })

    return findings


def check_dirty_access(fleet_data):
    """Find access ports that are members of VLANs beyond their PVID."""
    findings = []
    for ip, data in fleet_data.items():
        ingress = data['ingress']
        egress = data['egress']

        for port, idata in ingress.items():
            pvid = idata.get('pvid', 1)
            # Count how many VLANs this port is a member of
            member_vlans = []
            for vid, vdata in egress.items():
                port_mode = vdata.get('ports', {}).get(port)
                if port_mode in ('tagged', 'untagged'):
                    member_vlans.append(vid)

            # An access port should only be in its PVID VLAN
            # If it has tagged VLANs, it's likely intentional (trunk)
            tagged_vlans = [vid for vid in member_vlans if vid != pvid]
            has_tagged = any(
                egress[vid].get('ports', {}).get(port) == 'tagged'
                for vid in tagged_vlans
                if vid in egress
            )
            if has_tagged:
                continue  # Looks like an intentional trunk port

            # Untagged in multiple VLANs = dirty
            untagged_vlans = [
                vid for vid in member_vlans
                if vid != pvid and egress.get(vid, {}).get('ports', {}).get(port) == 'untagged'
            ]
            if untagged_vlans:
                findings.append({
                    'check': 'dirty_access',
                    'severity': 'warning',
                    'ip': ip,
                    'hostname': data['hostname'],
                    'port': port,
                    'pvid': pvid,
                    'extra_vlans': sorted(untagged_vlans),
                })

    return findings


def check_pvid_egress_mismatch(fleet_data):
    """Find ports where PVID doesn't match untagged membership."""
    findings = []
    for ip, data in fleet_data.items():
        ingress = data['ingress']
        egress = data['egress']

        for port, idata in ingress.items():
            pvid = idata.get('pvid', 1)
            # Check if port is untagged member of its PVID VLAN
            pvid_vlan = egress.get(pvid, {})
            port_mode = pvid_vlan.get('ports', {}).get(port)
            if port_mode != 'untagged':
                findings.append({
                    'check': 'pvid_egress_mismatch',
                    'severity': 'error',
                    'ip': ip,
                    'hostname': data['hostname'],
                    'port': port,
                    'pvid': pvid,
                    'egress_mode': port_mode or 'not member',
                })

    return findings


def check_orphan_vlans(fleet_data, links):
    """Find VLANs trunked on one side of a link but not the neighbor."""
    findings = []
    for local_ip, local_port, remote_ip, remote_port in links:
        local_egress = fleet_data[local_ip]['egress']
        remote_egress = fleet_data[remote_ip]['egress']

        for vid, vdata in local_egress.items():
            if vid == 1:
                continue  # Default VLAN, always everywhere
            local_mode = vdata.get('ports', {}).get(local_port)
            if local_mode != 'tagged':
                continue
            # Check if remote side has this VLAN on the link port
            remote_mode = remote_egress.get(vid, {}).get('ports', {}).get(remote_port)
            if not remote_mode:
                findings.append({
                    'check': 'orphan_vlan',
                    'severity': 'info',
                    'vlan_id': vid,
                    'present_ip': local_ip,
                    'present_port': local_port,
                    'missing_ip': remote_ip,
                    'missing_port': remote_port,
                })

    return findings


def check_name_mismatches(fleet_data):
    """Find same VLAN ID with different names across devices."""
    # Collect all (vlan_id, name) pairs
    vlan_names = {}  # vid → {name: [ips]}
    for ip, data in fleet_data.items():
        for vid, vdata in data['egress'].items():
            name = vdata.get('name', '')
            vlan_names.setdefault(vid, {}).setdefault(name, []).append(ip)

    findings = []
    for vid, names in sorted(vlan_names.items()):
        if len(names) > 1:
            findings.append({
                'check': 'name_mismatch',
                'severity': 'info',
                'vlan_id': vid,
                'names': {name: ips for name, ips in names.items()},
            })

    return findings


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_banner(label, config):
    """Print the standard VIKTOR banner."""
    print("\n" + "=" * 60)
    print(f"  VIKTOR — {label}")
    print("=" * 60)
    print(f"  Protocol:  {config['protocol'].upper()} | Devices: {len(config['devices'])}")
    print("-" * 60)


def print_footer(total, reached, elapsed):
    """Print the standard VIKTOR footer."""
    print("\n" + "=" * 60)
    print(f"  {reached}/{total} devices reached | Done in {elapsed:.1f}s")
    print("=" * 60 + "\n")


def format_results(results, config):
    """Print results in config device order."""
    result_map = {ip: (ok, msg) for ip, ok, msg in results}
    ok_count = 0
    for ip in config['devices']:
        if ip in result_map:
            ok, msg = result_map[ip]
            tag = 'OK  ' if ok else 'FAIL'
            print(f"  [{tag}] {ip:<17s}{msg}")
            if ok:
                ok_count += 1
    return ok_count


# ---------------------------------------------------------------------------
# Subcommand: vlan list
# ---------------------------------------------------------------------------

def cmd_vlan_list(args, config, connections, fleet_data):
    """List VLANs across the fleet."""
    for ip in config['devices']:
        if ip not in fleet_data:
            continue
        data = fleet_data[ip]
        egress = data['egress']
        ingress = data['ingress']

        print(f"\n  {data['hostname']} ({ip})")
        print(f"  {'VLAN':<8s}{'Name':<20s}{'Ports'}")
        print(f"  {'-'*6:<8s}{'-'*18:<20s}{'-'*30}")

        for vid in sorted(egress.keys()):
            vdata = egress[vid]
            name = vdata.get('name', '')
            ports = vdata.get('ports', {})

            tagged = sorted([p for p, m in ports.items() if m == 'tagged'],
                            key=natural_sort_key)
            untagged = sorted([p for p, m in ports.items() if m == 'untagged'],
                              key=natural_sort_key)

            port_parts = []
            if untagged:
                port_parts.append(f"U:{','.join(untagged)}")
            if tagged:
                port_parts.append(f"T:{','.join(tagged)}")
            port_str = '  '.join(port_parts) if port_parts else '(no ports)'

            print(f"  {vid:<8d}{name:<20s}{port_str}")

    return len(fleet_data)


# ---------------------------------------------------------------------------
# Subcommand: vlan create / delete / rename
# ---------------------------------------------------------------------------

def cmd_vlan_create(args, config, connections, fleet_data):
    """Create a VLAN on all devices."""
    vlan_id = args.vlan_id
    name = args.name

    label = f"VLAN {vlan_id}"
    if name:
        label += f" ({name})"
    print(f"\n  Creating {label} on {len(connections)} device(s)...")

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_vlan_create, device, ip, vlan_id, name): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


def cmd_vlan_delete(args, config, connections, fleet_data):
    """Delete a VLAN from all devices."""
    vlan_id = args.vlan_id

    if vlan_id == 1:
        print("\n  ERROR: Cannot delete VLAN 1 (default VLAN)\n", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Deleting VLAN {vlan_id} from {len(connections)} device(s)...")

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_vlan_delete, device, ip, vlan_id): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


def cmd_vlan_rename(args, config, connections, fleet_data):
    """Rename a VLAN on all devices."""
    vlan_id = args.vlan_id
    name = args.name

    print(f"\n  Renaming VLAN {vlan_id} → \"{name}\" on {len(connections)} device(s)...")

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_vlan_rename, device, ip, vlan_id, name): ip
            for ip, device in connections.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


# ---------------------------------------------------------------------------
# Subcommand: access
# ---------------------------------------------------------------------------

def ensure_vlan_exists(connections, fleet_data, vlan_id, name):
    """Create VLAN on devices where it doesn't exist. Returns updated fleet_data."""
    created = 0
    for ip, device in connections.items():
        if ip not in fleet_data:
            continue
        egress = fleet_data[ip]['egress']
        if vlan_id not in egress:
            try:
                device.create_vlan(vlan_id, name=name or '')
                created += 1
                logging.info(f"[{ip}] Created VLAN {vlan_id}")
            except Exception as e:
                print(f"  [FAIL] {ip} — create VLAN {vlan_id}: {e}")
    if created:
        print(f"  Created VLAN {vlan_id} on {created} device(s)")
    return fleet_data


def cmd_access(args, config, connections, fleet_data):
    """Set ports to strict access mode."""
    ports = parse_port_spec(args.ports)
    vlan_id = args.vlan_id
    use_staging = config['protocol'] == 'mops'

    print(f"\n  Setting access VLAN {vlan_id} on ports {', '.join(ports)}...")

    if args.dry_run:
        if args.name is not None:
            print(f"  Would create VLAN {vlan_id} ({args.name}) if missing")
        print("  [DRY RUN] No changes applied.")
        return len(fleet_data)

    if args.name is not None:
        ensure_vlan_exists(connections, fleet_data, vlan_id, args.name)

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_set_access, device, ip, ports, vlan_id,
                        fleet_data[ip]['egress'], use_staging): ip
            for ip, device in connections.items()
            if ip in fleet_data
        }
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


# ---------------------------------------------------------------------------
# Subcommand: trunk
# ---------------------------------------------------------------------------

def cmd_trunk(args, config, connections, fleet_data):
    """Tag ports for VLANs (additive)."""
    ports = parse_port_spec(args.ports)
    vlan_ids = parse_vlan_list(args.vlan_ids)
    use_staging = config['protocol'] == 'mops'

    vlan_str = ', '.join(str(v) for v in vlan_ids)
    print(f"\n  Tagging VLANs {vlan_str} on ports {', '.join(ports)}...")

    if args.dry_run:
        print("  [DRY RUN] No changes applied.")
        return len(fleet_data)

    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_set_trunk, device, ip, ports, vlan_ids,
                        use_staging): ip
            for ip, device in connections.items()
            if ip in fleet_data
        }
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


# ---------------------------------------------------------------------------
# Subcommand: auto-trunk
# ---------------------------------------------------------------------------

def cmd_auto_trunk(args, config, connections, fleet_data):
    """Tag inter-switch links for a VLAN using LLDP discovery."""
    vlan_id = args.vlan_id
    use_staging = config['protocol'] == 'mops'

    if 'lldp' not in next(iter(fleet_data.values())):
        print("\n  ERROR: auto-trunk requires LLDP data (internal error)\n",
              file=sys.stderr)
        sys.exit(1)

    links = build_lldp_links(fleet_data)
    if not links:
        print("\n  No inter-switch links found via LLDP.")
        return len(fleet_data)

    print(f"\n  Auto-trunk: VLAN {vlan_id} on {len(links)} inter-switch link(s)")
    for local_ip, local_port, remote_ip, remote_port in links:
        local_name = fleet_data[local_ip]['hostname']
        remote_name = fleet_data[remote_ip]['hostname']
        print(f"    {local_name} {local_port} ↔ {remote_name} {remote_port}")

    if args.dry_run:
        if args.name is not None:
            print(f"  Would create VLAN {vlan_id} ({args.name}) if missing")
        print("\n  [DRY RUN] No changes applied.")
        return len(fleet_data)

    if args.name is not None:
        ensure_vlan_exists(connections, fleet_data, vlan_id, args.name)

    # Group by device: {ip: [ports_to_tag]}
    device_ports = {}
    for local_ip, local_port, remote_ip, remote_port in links:
        device_ports.setdefault(local_ip, []).append(local_port)
        device_ports.setdefault(remote_ip, []).append(remote_port)

    results = []
    with ThreadPoolExecutor(max_workers=len(device_ports)) as pool:
        futures = {}
        for ip, ports in device_ports.items():
            if ip in connections and ip in fleet_data:
                futures[pool.submit(worker_set_trunk, connections[ip], ip,
                                    ports, [vlan_id], use_staging)] = ip
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


# ---------------------------------------------------------------------------
# Subcommand: --audit
# ---------------------------------------------------------------------------

def cmd_audit(args, config, connections, fleet_data):
    """Run all audit checks and print findings."""
    links = build_lldp_links(fleet_data)

    print(f"\n  Audit: {len(fleet_data)} devices, {len(links)} inter-switch links")
    print("-" * 60)

    all_findings = []

    # Run all checks
    findings = check_pvid_egress_mismatch(fleet_data)
    all_findings.extend(findings)

    findings = check_dirty_access(fleet_data)
    all_findings.extend(findings)

    findings = check_lldp_crosscheck(fleet_data, links)
    all_findings.extend(findings)

    findings = check_orphan_vlans(fleet_data, links)
    all_findings.extend(findings)

    findings = check_name_mismatches(fleet_data)
    all_findings.extend(findings)

    if not all_findings:
        print("\n  All checks passed — no issues found.")
        return len(fleet_data)

    # Group by check type
    by_check = {}
    for f in all_findings:
        by_check.setdefault(f['check'], []).append(f)

    # Print findings
    check_labels = {
        'pvid_egress_mismatch': 'PVID / Egress Mismatch',
        'dirty_access': 'Dirty Access Ports',
        'lldp_crosscheck': 'LLDP Cross-Check (VLAN mismatch across links)',
        'orphan_vlan': 'Orphan VLANs (trunk one side only)',
        'name_mismatch': 'VLAN Name Inconsistencies',
    }

    for check, findings in by_check.items():
        label = check_labels.get(check, check)
        severity = findings[0].get('severity', 'info').upper()
        print(f"\n  [{severity}] {label} ({len(findings)})")

        if check == 'pvid_egress_mismatch':
            for f in findings:
                print(f"    {f['hostname']} ({f['ip']}) {f['port']}: "
                      f"PVID={f['pvid']} but egress={f['egress_mode']}")

        elif check == 'dirty_access':
            for f in findings:
                extras = ', '.join(str(v) for v in f['extra_vlans'])
                print(f"    {f['hostname']} ({f['ip']}) {f['port']}: "
                      f"PVID={f['pvid']} + untagged in VLANs {extras}")

        elif check == 'lldp_crosscheck':
            for f in findings:
                parts = []
                if f['only_local']:
                    parts.append(f"only on {f['local_ip']}: {f['only_local']}")
                if f['only_remote']:
                    parts.append(f"only on {f['remote_ip']}: {f['only_remote']}")
                detail = '; '.join(parts)
                print(f"    {f['local_ip']} {f['local_port']} ↔ "
                      f"{f['remote_ip']} {f['remote_port']}: {detail}")

        elif check == 'orphan_vlan':
            for f in findings:
                print(f"    VLAN {f['vlan_id']}: on {f['present_ip']} {f['present_port']} "
                      f"but NOT on {f['missing_ip']} {f['missing_port']}")

        elif check == 'name_mismatch':
            for f in findings:
                parts = []
                for name, ips in f['names'].items():
                    label = f'"{name}"' if name else '(empty)'
                    parts.append(f"{label} on {', '.join(ips)}")
                print(f"    VLAN {f['vlan_id']}: {' vs '.join(parts)}")

    total = len(all_findings)
    errors = sum(1 for f in all_findings if f.get('severity') == 'error')
    warnings = sum(1 for f in all_findings if f.get('severity') == 'warning')
    infos = total - errors - warnings
    print(f"\n  Total: {total} findings ({errors} errors, {warnings} warnings, {infos} info)")

    return len(fleet_data)


# ---------------------------------------------------------------------------
# Subcommand: --names
# ---------------------------------------------------------------------------

def cmd_names(args, config, connections, fleet_data):
    """Audit and fix VLAN name consistency (majority vote)."""
    # Collect all (vlan_id → name → count)
    vlan_names = {}  # vid → Counter(name)
    for ip, data in fleet_data.items():
        for vid, vdata in data['egress'].items():
            name = vdata.get('name', '')
            vlan_names.setdefault(vid, Counter())[name] += 1

    # Find mismatches
    fixes = []
    for vid in sorted(vlan_names.keys()):
        names = vlan_names[vid]
        if len(names) <= 1:
            continue
        # Majority wins
        winner, _ = names.most_common(1)[0]
        # Find devices that need fixing
        for ip, data in fleet_data.items():
            vdata = data['egress'].get(vid, {})
            current = vdata.get('name', '')
            if current != winner:
                fixes.append((ip, vid, current, winner))

    if not fixes:
        print("\n  VLAN names are consistent across all devices.")
        return len(fleet_data)

    print(f"\n  Name consistency: {len(fixes)} fix(es) needed")
    for ip, vid, current, winner in fixes:
        hostname = fleet_data[ip]['hostname']
        cur_label = f'"{current}"' if current else '(empty)'
        print(f"    {hostname} ({ip}): VLAN {vid} {cur_label} → \"{winner}\"")

    if args.dry_run:
        print("\n  [DRY RUN] No changes applied.")
        return len(fleet_data)

    # Apply fixes
    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {}
        for ip, vid, current, winner in fixes:
            if ip in connections:
                futures[pool.submit(worker_vlan_rename, connections[ip],
                                    ip, vid, winner)] = ip
        for future in as_completed(futures):
            results.append(future.result())

    ok = sum(1 for _, success, _ in results if success)
    fail = len(results) - ok
    print(f"\n  Applied: {ok} OK, {fail} failed")

    return len(fleet_data)


# ---------------------------------------------------------------------------
# Subcommand: --export
# ---------------------------------------------------------------------------

CSV_HEADERS = ['device_ip', 'hostname', 'port', 'pvid', 'tagged_vlans', 'untagged_vlans']


def cmd_export(args, config, connections, fleet_data):
    """Export fleet VLAN state to CSV."""
    output_file = args.export

    rows = []
    for ip in config['devices']:
        if ip not in fleet_data:
            continue
        data = fleet_data[ip]
        hostname = data['hostname']
        ingress = data['ingress']
        egress = data['egress']

        # Get all physical ports from ingress table
        for port in sorted(ingress.keys(), key=natural_sort_key):
            if port.startswith('cpu') or port.startswith('mgmt'):
                continue

            pvid = ingress[port].get('pvid', 1)

            tagged = []
            untagged = []
            for vid, vdata in egress.items():
                mode = vdata.get('ports', {}).get(port)
                if mode == 'tagged':
                    tagged.append(vid)
                elif mode == 'untagged':
                    untagged.append(vid)

            rows.append({
                'device_ip': ip,
                'hostname': hostname,
                'port': port,
                'pvid': pvid,
                'tagged_vlans': ','.join(str(v) for v in sorted(tagged)),
                'untagged_vlans': ','.join(str(v) for v in sorted(untagged)),
            })

    output_path = get_resource_path(output_file)
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n  Exported {len(rows)} rows to {output_file}")
    return len(fleet_data)


# ---------------------------------------------------------------------------
# Subcommand: --import
# ---------------------------------------------------------------------------

def cmd_import(args, config, connections, fleet_data):
    """Import VLAN state from CSV, diff against current, and apply changes."""
    import_file = args.import_file
    import_path = get_resource_path(import_file)

    if not os.path.exists(import_path):
        print(f"\n  ERROR: File not found: {import_file}\n", file=sys.stderr)
        sys.exit(1)

    # Read CSV
    with open(import_path, 'r') as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)

    if not csv_rows:
        print("\n  ERROR: CSV file is empty\n", file=sys.stderr)
        sys.exit(1)

    # Build desired state from CSV: {ip: {port: {pvid, tagged, untagged}}}
    desired = {}
    for row in csv_rows:
        ip = row['device_ip']
        port = row['port']
        pvid = int(row['pvid'])
        tagged = set(int(v) for v in row['tagged_vlans'].split(',') if v.strip())
        untagged = set(int(v) for v in row['untagged_vlans'].split(',') if v.strip())
        desired.setdefault(ip, {})[port] = {
            'pvid': pvid, 'tagged': tagged, 'untagged': untagged,
        }

    # Build current state from fleet_data
    current = {}
    for ip, data in fleet_data.items():
        ingress = data['ingress']
        egress = data['egress']
        for port in ingress:
            if port.startswith('cpu') or port.startswith('mgmt'):
                continue
            pvid = ingress[port].get('pvid', 1)
            tagged = set()
            untagged = set()
            for vid, vdata in egress.items():
                mode = vdata.get('ports', {}).get(port)
                if mode == 'tagged':
                    tagged.add(vid)
                elif mode == 'untagged':
                    untagged.add(vid)
            current.setdefault(ip, {})[port] = {
                'pvid': pvid, 'tagged': tagged, 'untagged': untagged,
            }

    # Diff
    changes = []  # (ip, port, field, current_val, desired_val)
    for ip, ports in desired.items():
        if ip not in current:
            print(f"  [SKIP] {ip} — not in fleet")
            continue
        for port, d_state in ports.items():
            c_state = current.get(ip, {}).get(port)
            if not c_state:
                print(f"  [SKIP] {ip} port {port} — not in current state")
                continue

            if d_state['pvid'] != c_state['pvid']:
                changes.append((ip, port, 'pvid', c_state['pvid'], d_state['pvid']))
            if d_state['tagged'] != c_state['tagged']:
                changes.append((ip, port, 'tagged', c_state['tagged'], d_state['tagged']))
            if d_state['untagged'] != c_state['untagged']:
                changes.append((ip, port, 'untagged', c_state['untagged'], d_state['untagged']))

    if not changes:
        print("\n  No changes needed — fleet matches CSV.")
        return len(fleet_data)

    print(f"\n  Import diff: {len(changes)} change(s)")
    for ip, port, field, cur, des in changes:
        hostname = fleet_data.get(ip, {}).get('hostname', ip)
        if field in ('tagged', 'untagged'):
            cur_str = ','.join(str(v) for v in sorted(cur)) or '(none)'
            des_str = ','.join(str(v) for v in sorted(des)) or '(none)'
        else:
            cur_str, des_str = str(cur), str(des)
        print(f"    {hostname} ({ip}) {port}: {field} {cur_str} → {des_str}")

    if args.dry_run:
        print("\n  [DRY RUN] No changes applied.")
        return len(fleet_data)

    # Apply changes
    use_staging = config['protocol'] == 'mops'
    ok_count = 0
    fail_count = 0

    # Group changes by device
    by_device = {}
    for ip, port, field, cur, des in changes:
        by_device.setdefault(ip, []).append((port, field, cur, des))

    for ip, device_changes in by_device.items():
        if ip not in connections:
            continue
        device = connections[ip]

        try:
            if use_staging:
                try:
                    device.start_staging()
                except (NotImplementedError, AttributeError):
                    pass

            for port, field, cur, des in device_changes:
                if field == 'tagged':
                    # Add new tagged VLANs
                    to_add = des - cur
                    for vid in to_add:
                        device.set_vlan_egress(vid, port, 'tagged')
                    # Remove old tagged VLANs
                    to_remove = cur - des
                    for vid in to_remove:
                        device.set_vlan_egress(vid, port, 'none')

                elif field == 'untagged':
                    # Add new untagged VLANs
                    to_add = des - cur
                    for vid in to_add:
                        device.set_vlan_egress(vid, port, 'untagged')
                    # Remove old untagged VLANs
                    to_remove = cur - des
                    for vid in to_remove:
                        device.set_vlan_egress(vid, port, 'none')

            if use_staging:
                try:
                    device.commit_staging()
                except (NotImplementedError, AttributeError):
                    pass

            # PVID changes (separate — different MIB table)
            for port, field, cur, des in device_changes:
                if field == 'pvid':
                    device.set_vlan_ingress(port, pvid=des)

            ok_count += 1
            hostname = fleet_data.get(ip, {}).get('hostname', ip)
            n = len(device_changes)
            print(f"  [OK  ] {ip:<17s}{hostname} — {n} change(s)")

        except Exception as e:
            fail_count += 1
            print(f"  [FAIL] {ip:<17s}{e}")
            if use_staging:
                try:
                    device.discard_staging()
                except Exception:
                    pass

    print(f"\n  Applied: {ok_count} devices OK, {fail_count} failed")
    return len(fleet_data)


# ---------------------------------------------------------------------------
# QoS — set default PCP on ports carrying a VLAN
# ---------------------------------------------------------------------------

def worker_set_qos(device, ip, ports, pcp, use_staging):
    """Set default PCP on ports."""
    try:
        if use_staging:
            try:
                device.start_staging()
            except (NotImplementedError, AttributeError):
                use_staging = False

        device.set_qos(ports, default_priority=pcp)

        if use_staging:
            device.commit_staging()

        return ip, True, f"PCP {pcp} on {', '.join(ports)}"
    except Exception as e:
        if use_staging:
            try:
                device.discard_staging()
            except Exception:
                pass
        return ip, False, str(e)


def cmd_qos(args, config, connections, fleet_data):
    """Set default PCP on edge ports carrying specified VLANs."""
    vlan_ids = parse_vlan_list(args.vlan_ids)
    pcp = args.pcp
    include_trunk = args.include_trunk
    use_staging = config['protocol'] == 'mops'

    if pcp < 0 or pcp > 7:
        print(f"  [ERROR] PCP must be 0-7, got {pcp}")
        return 0

    # Build trunk port set from LLDP
    trunk_ports = {}  # {ip: set(port_names)}
    if not include_trunk:
        links = build_lldp_links(fleet_data)
        for local_ip, local_port, remote_ip, remote_port in links:
            trunk_ports.setdefault(local_ip, set()).add(local_port)
            trunk_ports.setdefault(remote_ip, set()).add(remote_port)

    # For each device, find ports carrying any of the target VLANs
    plan = {}  # {ip: [ports_to_set]}
    for ip, data in fleet_data.items():
        egress = data.get('egress', {})
        device_trunk = trunk_ports.get(ip, set())
        ports = set()
        for vid in vlan_ids:
            if vid in egress:
                vlan_ports = egress[vid].get('ports', {})
                for port, mode in vlan_ports.items():
                    if mode in ('tagged', 'untagged'):
                        if include_trunk or port not in device_trunk:
                            ports.add(port)
        if ports:
            plan[ip] = sorted(ports, key=natural_sort_key)

    # Display plan
    mode_label = "all" if include_trunk else "edge"
    vlan_str = ', '.join(str(v) for v in vlan_ids)
    print(f"\n  Setting PCP {pcp} on {mode_label} ports carrying VLAN(s) {vlan_str}:")
    for ip in config['devices']:
        if ip in plan:
            hostname = fleet_data[ip].get('hostname', ip)
            print(f"    {ip:<17s}{hostname:<21s}{', '.join(plan[ip])}")
    if not plan:
        print("    (no matching ports found)")
        return 0

    if args.dry_run:
        print("\n  [DRY RUN] No changes applied.")
        return len(plan)

    # Deploy
    results = []
    with ThreadPoolExecutor(max_workers=len(connections)) as pool:
        futures = {
            pool.submit(worker_set_qos, device, ip, plan[ip], pcp,
                        use_staging): ip
            for ip, device in connections.items()
            if ip in plan
        }
        for future in as_completed(futures):
            results.append(future.result())

    return format_results(results, config)


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------

def interactive_mode():
    """REPL-style multi-turn session for VIKTOR.

    Connect once, stay connected, run multiple operations in a loop.
    Save prompt at quit — single NVM write for the whole session.
    """

    # ANSI
    CY = '\033[36m'; MG = '\033[35m'; YL = '\033[33m'
    GR = '\033[32m'; BD = '\033[1m'; DM = '\033[2m'; RS = '\033[0m'

    def cls():
        print('\033[2J\033[H', end='', flush=True)

    def banner():
        print(f"""
  {MG}{BD}╦  ╦╦╦╔═╔╦╗╔═╗╦═╗{RS}
  {MG}{BD}╚╗╔╝║╠╩╗ ║ ║ ║╠╦╝{RS}
  {MG}{BD} ╚╝ ╩╩ ╩ ╩ ╚═╝╩╚═{RS}
  {DM}VLAN Intent, Knowledgeable Topology-Optimized Rules{RS}
  {CY}{'━' * 52}{RS}
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

    connections = {}
    try:
        # ── 1. Credentials & Protocol ──
        step('STEP 1 ─── CREDENTIALS')
        username = ask('Username', 'admin')
        password = ask('Password', 'private')
        protocol = pick('Protocol', [
            ('MOPS — HTTPS, atomic writes (recommended)', 'mops'),
            ('SNMP — SNMPv3, no session state', 'snmp'),
            ('SSH — CLI parsing', 'ssh'),
        ])

        # ── 2. Devices ──
        step('STEP 2 ─── DEVICES')

        cfg_path = get_resource_path('script.cfg')
        cfg_devices = []
        use_cfg = False

        if os.path.exists(cfg_path):
            try:
                cfg = parse_config(cfg_path)
                cfg_devices = cfg.get('devices', [])
            except Exception:
                pass

        if cfg_devices:
            print(f'  Found {CY}script.cfg{RS} with {len(cfg_devices)} device(s):')
            for ip in cfg_devices:
                print(f'    {CY}{ip}{RS}')
            print()
            if yesno('Use these?', default=True):
                devices = cfg_devices
                use_cfg = True
            else:
                devices = []
        else:
            devices = []

        if not devices:
            raw = ask('Enter IPs (comma, range, or CIDR)')
            if raw:
                devices = parse_ips(raw)

        if not devices:
            print(f'\n  {YL}No devices. Exiting.{RS}\n')
            return

        # ── 3. Ring filter ──
        step('STEP 3 ─── RING FILTER')
        print(f'  {DM}Limit operations to devices in a specific MRP ring?{RS}\n')
        ring = None
        if yesno('Filter by ring VLAN?'):
            ring_str = ask('Ring VLAN ID')
            ring = int(ring_str)

        # Build config
        config = {
            'username': username,
            'password': password,
            'protocol': protocol,
            'devices': devices,
            'ring': ring,
            'save': False,
            'debug': False,
        }

        # ── Connect ──
        cls()
        banner()
        print(f'  {BD}CONNECTING{RS}\n')

        from napalm import get_network_driver
        driver = get_network_driver('hios')
        connections = connect_all(driver, config)
        if not connections:
            print(f'\n  {YL}No devices reachable. Exiting.{RS}\n')
            return

        # Initial gather (always with LLDP for max flexibility)
        print("  Gathering VLAN data...")
        fleet_data = gather_fleet(connections, need_lldp=True)
        if not fleet_data:
            print(f'\n  {YL}No data gathered. Exiting.{RS}\n')
            close_all(connections)
            return

        for ip in config['devices']:
            if ip in fleet_data:
                d = fleet_data[ip]
                n_vlans = len(d['egress'])
                print(f"    {ip:<17s}{d['hostname']:<21s}{n_vlans} VLANs")

        # Ring filter
        if ring:
            fleet_data = filter_ring_members(fleet_data, ring)
            if not fleet_data:
                print(f'\n  {YL}No devices have VLAN {ring} in egress table.{RS}\n')
                close_all(connections)
                return
            connections = {ip: dev for ip, dev in connections.items()
                          if ip in fleet_data}
            print(f"\n  Ring {ring}: {len(fleet_data)} member(s)")
            for ip, data in fleet_data.items():
                rp = ', '.join(sorted(data.get('ring_ports', set()),
                                      key=natural_sort_key))
                print(f"    {ip:<17s}{data['hostname']:<21s}ring ports: {rp}")

        pause()

        changed = False

        # ── REPL loop ──
        while True:
            cls()
            banner()
            n_dev = len(connections)
            ring_tag = f'  ring {ring}' if ring else ''
            print(f'  {BD}SESSION{RS}  {CY}{n_dev}{RS} device(s) via {protocol.upper()}{ring_tag}\n')

            ops = [
                ('List VLANs',            'list'),
                ('Create VLAN',           'create'),
                ('Delete VLAN',           'delete'),
                ('Rename VLAN',           'rename'),
                ('Set access ports',      'access'),
                ('Set trunk ports',       'trunk'),
                ('Auto-trunk (LLDP)',     'auto-trunk'),
                ('QoS — set default PCP', 'qos'),
                ('Audit',                 'audit'),
                ('Name consistency',      'names'),
                ('Quit',                  'quit'),
            ]
            op = pick('What next?', ops)

            if op == 'quit':
                break

            # ── Gather parameters ──
            print()
            mock = argparse.Namespace(dry_run=False)
            cmd_func = None

            if op == 'list':
                cmd_func = cmd_vlan_list

            elif op == 'create':
                vid = ask('VLAN ID')
                name = ask('VLAN name (optional)')
                mock.vlan_id = int(vid)
                mock.name = name
                cmd_func = cmd_vlan_create

            elif op == 'delete':
                vid = ask('VLAN ID')
                mock.vlan_id = int(vid)
                if mock.vlan_id == 1:
                    print(f'\n  {YL}Cannot delete VLAN 1 (default VLAN).{RS}')
                    pause()
                    continue
                cmd_func = cmd_vlan_delete

            elif op == 'rename':
                vid = ask('VLAN ID')
                name = ask('New name')
                mock.vlan_id = int(vid)
                mock.name = name
                cmd_func = cmd_vlan_rename

            elif op == 'access':
                ports = ask('Ports (e.g. 1/1-1/8)')
                vid = ask('Access VLAN ID')
                name = ask('Auto-create VLAN name (optional)')
                mock.ports = ports
                mock.vlan_id = int(vid)
                mock.name = name if name else None
                cmd_func = cmd_access

            elif op == 'trunk':
                ports = ask('Ports (e.g. 1/5,1/6)')
                vids = ask('VLAN IDs (comma-separated)')
                mock.ports = ports
                mock.vlan_ids = vids
                cmd_func = cmd_trunk

            elif op == 'auto-trunk':
                vid = ask('VLAN ID')
                name = ask('Auto-create VLAN name (optional)')
                mock.vlan_id = int(vid)
                mock.name = name if name else None
                cmd_func = cmd_auto_trunk

            elif op == 'qos':
                vids = ask('VLAN ID(s)')
                pcp = ask('PCP value (0-7)')
                inc_trunk = yesno('Include trunk ports?')
                mock.vlan_ids = vids
                mock.pcp = int(pcp)
                mock.include_trunk = inc_trunk
                cmd_func = cmd_qos

            elif op == 'audit':
                cmd_func = cmd_audit

            elif op == 'names':
                cmd_func = cmd_names

            if not cmd_func:
                continue

            # ── Execute ──
            is_readonly = op in ('list', 'audit')

            if is_readonly:
                try:
                    cmd_func(mock, config, connections, fleet_data)
                except SystemExit:
                    pass
                except Exception as e:
                    print(f'\n  {YL}Error: {e}{RS}')
                pause()
                continue

            # Mutating — offer dry/live/back
            has_dry_run = op in ('access', 'trunk', 'auto-trunk', 'qos', 'names')

            if has_dry_run:
                action = pick('Go', [
                    ('Dry run — preview only', 'dry'),
                    ('Run live',               'live'),
                    ('Back',                   'back'),
                ])
            else:
                # Simple mutations (create/delete/rename) — confirm or back
                n = len(connections)
                if op == 'create':
                    label = f'VLAN {mock.vlan_id}'
                    if mock.name:
                        label += f' ({mock.name})'
                    print(f'  Will create {label} on {n} device(s)')
                elif op == 'delete':
                    print(f'  Will delete VLAN {mock.vlan_id} from {n} device(s)')
                elif op == 'rename':
                    print(f'  Will rename VLAN {mock.vlan_id} → "{mock.name}" on {n} device(s)')
                print()
                action = pick('Go', [
                    ('Run live', 'live'),
                    ('Back',     'back'),
                ])

            if action == 'back':
                continue

            if action == 'dry':
                mock.dry_run = True
                try:
                    cmd_func(mock, config, connections, fleet_data)
                except SystemExit:
                    pass
                except Exception as e:
                    print(f'\n  {YL}Error: {e}{RS}')
                print()
                if not yesno('Run live?'):
                    pause()
                    continue
                mock.dry_run = False

            # Live run
            print()
            try:
                cmd_func(mock, config, connections, fleet_data)
                changed = True
            except SystemExit:
                pass
            except Exception as e:
                print(f'\n  {YL}Error: {e}{RS}')

            # Re-gather after mutation
            print(f'\n  {DM}Refreshing fleet data...{RS}')
            fleet_data = gather_fleet(connections, need_lldp=True)

            pause()

        # ── Quit ──
        if changed:
            print()
            if yesno('Save all changes to NVM?'):
                print()
                save_ok = 0
                for ip, device in connections.items():
                    try:
                        device.save_config()
                        save_ok += 1
                        print(f'  {GR}[OK]{RS}   {ip}')
                    except Exception as e:
                        print(f'  {YL}[FAIL]{RS} {ip} — {e}')
                print(f'\n  {save_ok}/{len(connections)} saved to NVM')

        if not use_cfg and devices:
            print()
            if yesno('Save devices to script.cfg for next time?'):
                with open(cfg_path, 'w') as f:
                    f.write('# VIKTOR — VLAN Intent, Knowledgeable Topology-Optimized Rules\n')
                    f.write(f'username = {username}\n')
                    f.write(f'password = {password}\n')
                    f.write(f'protocol = {protocol}\n')
                    if ring:
                        f.write(f'ring = {ring}\n')
                    f.write('\n# Devices\n')
                    for ip in devices:
                        f.write(f'{ip}\n')
                print(f'\n  {GR}Saved to {cfg_path}{RS}')

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

    # Interactive mode: explicit -i flag, or no args at all with no script.cfg
    if args.interactive:
        return interactive_mode()
    if (not args.d and not args.ips and not args.command
            and not args.audit and not args.names
            and not args.export and not args.import_file):
        cfg_path = get_resource_path(args.c)
        if not os.path.exists(cfg_path):
            return interactive_mode()

    # Logging setup
    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir,
                                f'viktor_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

    # Resolve config first so debug/save/ring come from cfg + CLI
    try:
        config = resolve_config(args)
    except Exception as e:
        print(f"\n  FATAL: {e}\n", file=sys.stderr)
        sys.exit(1)

    is_debug = config.get('debug', False)

    log_level = logging.DEBUG if is_debug else logging.INFO
    logging.basicConfig(
        filename=log_filename,
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if is_debug else logging.WARNING)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger().addHandler(console)

    lib_level = logging.DEBUG if is_debug else logging.WARNING
    for lib in ('paramiko', 'napalm', 'netmiko', 'urllib3', 'requests'):
        logging.getLogger(lib).setLevel(lib_level)
    if is_debug:
        logging.getLogger('napalm_hios.mops_client').setLevel(logging.DEBUG)

    start_time = time.time()

    try:

        # Determine label for banner
        if args.audit:
            label = 'AUDIT'
        elif args.names:
            label = 'NAME CONSISTENCY'
        elif args.export:
            label = 'EXPORT'
        elif args.import_file:
            label = 'IMPORT'
        elif args.command == 'vlan':
            label = f"VLAN {(args.vlan_action or 'LIST').upper()}"
        elif args.command == 'access':
            label = 'ACCESS'
        elif args.command == 'trunk':
            label = 'TRUNK'
        elif args.command == 'auto-trunk':
            label = 'AUTO-TRUNK'
        elif args.command == 'qos':
            label = 'QOS'
        else:
            label = 'VLAN LIST'

        if config['ring']:
            label += f" (ring {config['ring']})"

        print_banner(label, config)

        if args.dry_run and not args.command and not args.audit and not args.names \
                and not args.export and not args.import_file:
            print("\n  Devices:")
            for ip in config['devices']:
                print(f"    {ip}")
            print("\n  [DRY RUN] No connections will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        connections = connect_all(driver, config)
        if not connections:
            sys.exit(1)

        # Determine if we need LLDP data
        need_lldp = (args.audit or args.command in ('auto-trunk', 'qos'))

        # Gather fleet data
        print("  Gathering VLAN data...")
        fleet_data = gather_fleet(connections, need_lldp=need_lldp)

        if not fleet_data:
            print("\n  FATAL: No VLAN data gathered.\n", file=sys.stderr)
            close_all(connections)
            sys.exit(1)

        for ip in config['devices']:
            if ip in fleet_data:
                d = fleet_data[ip]
                n_vlans = len(d['egress'])
                print(f"    {ip:<17s}{d['hostname']:<21s}{n_vlans} VLANs")

        # Ring selector filter
        if config['ring']:
            ring_vlan = config['ring']
            fleet_data = filter_ring_members(fleet_data, ring_vlan)
            if not fleet_data:
                print(f"\n  No devices have VLAN {ring_vlan} in egress table.")
                close_all(connections)
                return
            # Also filter connections to match
            connections = {ip: dev for ip, dev in connections.items()
                          if ip in fleet_data}
            print(f"\n  Ring {ring_vlan}: {len(fleet_data)} member(s)")
            for ip, data in fleet_data.items():
                ring_ports = ', '.join(sorted(data.get('ring_ports', set()),
                                              key=natural_sort_key))
                print(f"    {ip:<17s}{data['hostname']:<21s}ring ports: {ring_ports}")

        # Dispatch
        if args.audit:
            reached = cmd_audit(args, config, connections, fleet_data)
        elif args.names:
            reached = cmd_names(args, config, connections, fleet_data)
        elif args.export:
            reached = cmd_export(args, config, connections, fleet_data)
        elif args.import_file:
            reached = cmd_import(args, config, connections, fleet_data)
        elif args.command == 'vlan':
            action = args.vlan_action or 'list'
            if action == 'list':
                reached = cmd_vlan_list(args, config, connections, fleet_data)
            elif action == 'create':
                reached = cmd_vlan_create(args, config, connections, fleet_data)
            elif action == 'delete':
                reached = cmd_vlan_delete(args, config, connections, fleet_data)
            elif action == 'rename':
                reached = cmd_vlan_rename(args, config, connections, fleet_data)
            else:
                print(f"\n  Unknown vlan action: {action}\n", file=sys.stderr)
                close_all(connections)
                sys.exit(1)
        elif args.command == 'access':
            reached = cmd_access(args, config, connections, fleet_data)
        elif args.command == 'trunk':
            reached = cmd_trunk(args, config, connections, fleet_data)
        elif args.command == 'auto-trunk':
            reached = cmd_auto_trunk(args, config, connections, fleet_data)
        elif args.command == 'qos':
            reached = cmd_qos(args, config, connections, fleet_data)
        else:
            # Default: vlan list
            reached = cmd_vlan_list(args, config, connections, fleet_data)

        # Save if requested
        if config['save'] and not args.dry_run:
            if args.audit or args.export:
                print("\n  --save ignored for read-only operations")
            else:
                print("\n  Saving to NVM...")
                save_ok = 0
                for ip, device in connections.items():
                    try:
                        device.save_config()
                        save_ok += 1
                    except Exception as e:
                        print(f"  [FAIL] {ip} save: {e}")
                print(f"  {save_ok}/{len(connections)} saved")

        close_all(connections)

        elapsed = time.time() - start_time
        print_footer(len(config['devices']), reached, elapsed)

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"\n  FATAL: {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
