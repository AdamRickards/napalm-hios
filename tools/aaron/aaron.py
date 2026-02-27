"""
AARON — Automated Asset Recognition On Network

Connects to a list of HiOS switches, gathers MAC tables + LLDP,
cross-references MACs across all devices, and classifies every port
as uplink / edge / indirect / empty.

Outputs a flat CSV (one row per interface per switch, IP repeated
for Excel auto-filtering).

Usage:
    python aaron.py
    python aaron.py -c my_site.cfg
    python aaron.py --dry-run
    python aaron.py --debug
"""

import sys
import os
import re
import csv
import json
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


def natural_sort_key(interface: str):
    """Sort key that handles '1/1', '1/10', '2/3' naturally."""
    return [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', interface)]


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='AARON — Automated Asset Recognition On Network'
    )
    parser.add_argument('-c', default='script.cfg',
                        help='config file (default: script.cfg)')
    parser.add_argument('-o', default=None,
                        help='output file (default: aaron_output.csv/.json)')
    parser.add_argument('-j', action='store_true',
                        help='output JSON instead of CSV')
    parser.add_argument('--dry-run', action='store_true',
                        help='show plan without connecting')
    parser.add_argument('--debug', action='store_true',
                        help='verbose MOPS/protocol logging')
    return parser.parse_args()


def parse_config(config_file: str) -> dict:
    """Parse script.cfg into settings and device list."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found")

    config = {
        'username': '',
        'password': '',
        'protocol': 'mops',
        'edge_threshold': 3,
        'hide_empty': False,
        'hide_uplinks': False,
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
                elif key == 'edge_threshold':
                    config['edge_threshold'] = int(val)
                elif key == 'hide_empty':
                    config['hide_empty'] = val.lower() in ('true', 'yes', '1')
                elif key == 'hide_uplinks':
                    config['hide_uplinks'] = val.lower() in ('true', 'yes', '1')
                else:
                    logging.warning(f"Line {line_num}: unknown setting '{key}'")
                continue

            # Device lines — bare IP
            ip = line.split()[0]
            if is_valid_ipv4(ip):
                config['devices'].append(ip)
            else:
                logging.warning(f"Line {line_num}: skipping invalid IP '{ip}'")

    if not config['username'] or not config['password']:
        raise ValueError("Configuration must contain both username and password")
    if not config['devices']:
        raise ValueError("No valid device IPs found in configuration")

    return config


# ---------------------------------------------------------------------------
# Per-device data gathering (runs in threads)
# ---------------------------------------------------------------------------

def worker_gather(driver, config, ip, timeout):
    """Connect to one device and collect facts, MAC table, and LLDP."""
    device = None
    try:
        t0 = time.time()

        device = driver(
            hostname=ip,
            username=config['username'],
            password=config['password'],
            timeout=timeout,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()

        facts = device.get_facts()
        mac_table = device.get_mac_address_table()
        lldp = device.get_lldp_neighbors_detail_extended()

        device.close()
        device = None

        dt = time.time() - t0
        return ip, {
            'hostname': facts.get('hostname', ip),
            'interfaces': facts.get('interface_list', []),
            'mac_table': mac_table,
            'lldp': lldp,
            'ports': len(facts.get('interface_list', [])),
            'mac_count': len(mac_table),
            'lldp_count': len(lldp),
            'time': dt,
        }, None

    except Exception as e:
        return ip, None, str(e)
    finally:
        if device:
            try:
                device.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Phase 2: Build global MAC index
# ---------------------------------------------------------------------------

def build_mac_index(device_data: dict) -> dict:
    """Build {mac: [(ip, interface, vlan), ...]} from all devices.

    Skips static MACs and cpu/management interfaces.
    """
    mac_locations = {}
    for ip, data in device_data.items():
        for entry in data['mac_table']:
            if entry['static']:
                continue
            iface = entry['interface']
            if iface.startswith('cpu') or iface.startswith('mgmt'):
                continue
            mac = entry['mac']
            mac_locations.setdefault(mac, []).append((ip, iface, entry['vlan']))
    return mac_locations


# ---------------------------------------------------------------------------
# Phase 3: Classify ports
# ---------------------------------------------------------------------------

def classify_ports(device_data: dict, mac_index: dict, threshold: int) -> list:
    """Classify every port on every device. Returns list of row dicts."""
    rows = []

    # First pass: identify all uplink ports (have real LLDP neighbors)
    uplink_ports = set()  # (ip, interface) tuples
    for ip, data in device_data.items():
        for iface, neighbors in data['lldp'].items():
            real = [n for n in neighbors if n.get('remote_port', '').upper() != 'FDB']
            if real:
                uplink_ports.add((ip, iface))

    for ip, data in device_data.items():
        hostname = data['hostname']
        lldp = data['lldp']

        # Build per-interface MAC lists (dynamic only, skip cpu/mgmt)
        iface_macs = {}   # interface -> [(mac, vlan), ...]
        for entry in data['mac_table']:
            if entry['static']:
                continue
            iface = entry['interface']
            if iface.startswith('cpu') or iface.startswith('mgmt'):
                continue
            iface_macs.setdefault(iface, []).append((entry['mac'], entry['vlan']))

        for iface in data['interfaces']:
            if iface.startswith('cpu') or iface.startswith('mgmt'):
                continue

            row = {
                'switch_ip': ip,
                'switch_name': hostname,
                'interface': iface,
                'type': '',
                'vlan': '',
                'mac_count': 0,
                'macs': '',
                'lldp_neighbor_ip': '',
                'lldp_neighbor_name': '',
                'lldp_neighbor_port': '',
            }

            # Check LLDP (skip FDB-sourced entries — not real LLDP)
            neighbors = [n for n in lldp.get(iface, [])
                         if n.get('remote_port', '').upper() != 'FDB']
            if neighbors:
                n = neighbors[0]
                row['type'] = 'uplink'
                row['lldp_neighbor_ip'] = n.get('remote_management_ipv4', '')
                row['lldp_neighbor_name'] = (n.get('remote_system_name', '')
                                             or n.get('remote_chassis_id', ''))
                row['lldp_neighbor_port'] = (n.get('remote_port_description', '')
                                             or n.get('remote_port', ''))
                macs = iface_macs.get(iface, [])
                row['mac_count'] = len(macs)
                if macs:
                    vlans = sorted(set(str(v) for _, v in macs))
                    row['vlan'] = vlans[0] if len(vlans) == 1 else '|'.join(vlans)
                    row['macs'] = '|'.join(m for m, _ in macs)
                rows.append(row)
                continue

            # No LLDP — check MACs
            macs = iface_macs.get(iface, [])
            if not macs:
                row['type'] = 'empty'
                row['mac_count'] = 0
                rows.append(row)
                continue

            row['mac_count'] = len(macs)
            vlans = sorted(set(str(v) for _, v in macs))
            row['vlan'] = vlans[0] if len(vlans) == 1 else '|'.join(vlans)
            row['macs'] = '|'.join(m for m, _ in macs)

            # Any MAC seen on a non-uplink port on another device?
            # (MACs on uplink ports are just normal L2 transit)
            seen_elsewhere = False
            for mac, _ in macs:
                locations = mac_index.get(mac, [])
                for loc_ip, loc_iface, _ in locations:
                    if loc_ip != ip and (loc_ip, loc_iface) not in uplink_ports:
                        seen_elsewhere = True
                        break
                if seen_elsewhere:
                    break

            if seen_elsewhere:
                row['type'] = 'indirect'
            else:
                row['type'] = 'edge'

            rows.append(row)

    # Sort: by IP, then natural interface order
    rows.sort(key=lambda r: (r['switch_ip'], natural_sort_key(r['interface'])))
    return rows


# ---------------------------------------------------------------------------
# Phase 4: Output
# ---------------------------------------------------------------------------

CSV_HEADERS = [
    'switch_ip', 'switch_name', 'interface', 'type', 'vlan',
    'mac_count', 'macs', 'lldp_neighbor_ip', 'lldp_neighbor_name',
    'lldp_neighbor_port',
]

TYPE_LABELS = {
    'uplink': 'uplink',
    'edge': 'edge',
    'indirect': 'indirect',
    'empty': 'empty',
}


def print_summary(device_data: dict, rows: list):
    """Print per-device console summary."""
    by_device = {}
    for row in rows:
        by_device.setdefault(row['switch_ip'], []).append(row)

    for ip in sorted(device_data.keys()):
        data = device_data[ip]
        device_rows = by_device.get(ip, [])
        print(f"\n  {data['hostname']} ({ip})")

        for row in device_rows:
            port_type = row['type']
            mac_count = row['mac_count']
            iface = row['interface']

            if port_type == 'uplink':
                neighbor = row['lldp_neighbor_name'] or row['lldp_neighbor_ip'] or '?'
                detail = f"{mac_count:>3} MACs  \u2192 {neighbor}"
            elif port_type == 'empty':
                detail = ''
            elif port_type == 'indirect':
                detail = f"{mac_count:>3} MACs  (unmanaged?)"
            else:
                # edge
                mac_str = row['macs'].split('|')[0] if mac_count == 1 else f"{mac_count} MACs"
                detail = f"{mac_count:>3} MAC{'s' if mac_count != 1 else ' '}  {mac_str}"

            print(f"    {iface:<8s} {port_type:<12s} {detail}")


def write_csv(rows: list, output_path: str):
    """Write rows to CSV."""
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(rows: list, output_path: str):
    """Write rows to JSON."""
    with open(output_path, 'w') as f:
        json.dump(rows, f, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    # Logging setup
    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir, f'aaron_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        filename=log_filename,
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger().addHandler(console)

    lib_level = logging.DEBUG if args.debug else logging.WARNING
    for lib in ('paramiko', 'napalm', 'netmiko', 'urllib3', 'requests'):
        logging.getLogger(lib).setLevel(lib_level)
    if args.debug:
        logging.getLogger('napalm_hios.mops_client').setLevel(logging.DEBUG)

    start_time = time.time()

    try:
        config_path = get_resource_path(args.c)
        config = parse_config(config_path)

        # Resolve output path: -o overrides, -j switches extension
        ext = '.json' if args.j else '.csv'
        if args.o:
            output_file = args.o
        else:
            output_file = 'aaron_output' + ext

        # --- Print header ---
        fmt_label = 'JSON' if args.j else 'CSV'
        print("\n" + "=" * 60)
        print("  AARON \u2014 Automated Asset Recognition On Network")
        print("=" * 60)
        print(f"  Config: {args.c} | Protocol: {config['protocol']}"
              f" | Devices: {len(config['devices'])} | Edge threshold: \u2264{config['edge_threshold']}")
        print("=" * 60)

        if args.dry_run:
            print("\n  Devices:")
            for ip in config['devices']:
                print(f"    {ip}")
            print(f"\n  Output: {output_file} ({fmt_label})")
            print("\n  [DRY RUN] No connections will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        # --- Phase 1: Gather data from all devices in parallel ---
        print(f"\n  Gathering data...")
        device_data = {}
        failures = []

        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {
                pool.submit(worker_gather, driver, config, ip, 30): ip
                for ip in config['devices']
            }
            for future in as_completed(futures):
                ip, data, err = future.result()
                if data:
                    device_data[ip] = data
                    print(f"  [{data['time']:5.1f}s] {ip:<17s}"
                          f"{data['hostname']:<21s}"
                          f"{data['ports']:>3} ports  "
                          f"{data['mac_count']:>3} MACs  "
                          f"{data['lldp_count']:>2} LLDP")
                else:
                    failures.append((ip, err))
                    print(f"  [FAIL ] {ip:<17s}{err}")

        if not device_data:
            print("\n  FATAL: No devices reachable.\n")
            sys.exit(1)

        if failures:
            print(f"\n  {len(failures)} device(s) unreachable — continuing with {len(device_data)}")

        # --- Phase 2: Build global MAC index ---
        mac_index = build_mac_index(device_data)
        all_macs = set()
        for data in device_data.values():
            for entry in data['mac_table']:
                if not entry['static'] and not entry['interface'].startswith('cpu'):
                    all_macs.add(entry['mac'])
        multi_device_macs = sum(
            1 for mac, locs in mac_index.items()
            if len(set(loc_ip for loc_ip, _, _ in locs)) > 1
        )

        print(f"\n  Cross-referencing MACs across {len(device_data)} devices...")
        print(f"  Unique MACs: {len(all_macs)} | Seen on multiple devices: {multi_device_macs}")

        # --- Phase 3: Classify ports ---
        rows = classify_ports(device_data, mac_index, config['edge_threshold'])

        # --- Phase 4: Output ---
        print_summary(device_data, rows)

        # Filter rows for output
        out_rows = rows
        hidden = []
        if config['hide_empty']:
            hidden.append('empty')
        if config['hide_uplinks']:
            hidden.append('uplink')
        if hidden:
            out_rows = [r for r in rows if r['type'] not in hidden]

        output_path = get_resource_path(output_file)
        if args.j:
            write_json(out_rows, output_path)
        else:
            write_csv(out_rows, output_path)

        elapsed = time.time() - start_time
        hide_note = f" (hiding {'+'.join(hidden)})" if hidden else ""
        print(f"\n  Output: {output_file} ({len(out_rows)} rows, {fmt_label}){hide_note}")
        print(f"  Log: {log_filename}")
        print(f"  Done in {elapsed:.1f}s\n")

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"\n  FATAL: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
