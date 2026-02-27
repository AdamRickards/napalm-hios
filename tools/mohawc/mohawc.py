"""
MOHAWC — Management, Onboarding, HiDiscovery, And Wipe Configuration

Unified CLI tool for common HiOS switch commissioning tasks:
onboarding factory-fresh devices, controlling HiDiscovery, saving
configs, and resetting to defaults.

Usage:
    python mohawc.py status
    python mohawc.py -d 192.168.1.4 status
    python mohawc.py onboard --new-password NewPass1 --save
    python mohawc.py hidiscovery --off --save
    python mohawc.py save
    python mohawc.py reset --yes
    python mohawc.py reset --factory --erase-all --yes
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
                        choices=['mops', 'snmp', 'ssh'],
                        help='protocol (default: mops)')
    parser.add_argument('-b', action='store_true',
                        help='toggle HiDiscovery blink (read current, invert)')
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

            # Device lines — bare IP
            ip = line.split()[0]
            if is_valid_ipv4(ip):
                config['devices'].append(ip)
            else:
                logging.warning(f"Line {line_num}: skipping invalid IP '{ip}'")

    return config


def resolve_config(args) -> dict:
    """Build final config from config file + CLI overrides + -d mode."""
    if args.d:
        # Single-device mode — no config file needed
        config = {
            'username': args.u or 'admin',
            'password': args.p or 'private',
            'protocol': args.protocol or 'mops',
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

    uptime_str = f'  (up {uptime})' if uptime else ''
    name_str = f'  [{hostname}]' if hostname and hostname != ip else ''

    print(f"\n  {ip:<17s}{model:<25s}{version}{uptime_str}{name_str}")

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
                print(f"\n  {ip:<17s}[FAIL] {err}")

    # Print in config order
    for ip in config['devices']:
        if ip in results:
            print_status_device(ip, results[ip])

    close_all(connections)
    return len(results)


def cmd_onboard(args, config, driver):
    """Execute the onboard subcommand."""
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
            print(f"\n  [{tag:4s}] {ip:<17s}{msg}")

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
                print(f"\n  [OK  ] {ip:<17s}{before}  ->  {after}")
            else:
                print(f"\n  [FAIL] {ip:<17s}{detail}")

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
            print(f"\n  [{tag:4s}] {ip:<17s}{msg}")

    close_all(connections)
    return sum(1 for _, s, _ in results if s == 'OK')


def cmd_reset(args, config, driver):
    """Execute the reset subcommand."""
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
    if args.entry:
        print("\n  Building LLDP topology...")
        graph, hostnames = build_lldp_graph(connections, list(connections.keys()))
        order, distances = compute_reset_order(graph, args.entry)

        print(f"  Reset order (furthest-first):")
        for ip in order:
            name = hostnames.get(ip, '')
            dist = distances.get(ip, '?')
            label = f"  [{name}]" if name else ""
            print(f"    {dist} hop{'s' if dist != 1 else ' '}  {ip:<17s}{label}")

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
                print(f"\n  [{tag:4s}] {ip:<17s}{msg}")

    # Don't close — connections are likely already dead after reset
    for ip, device in connections.items():
        try:
            device.close()
        except Exception:
            pass

    return sum(1 for _, s, _ in results if s == 'OK')


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
            print(f"  [FAIL] {ip} \u2014 {err}")
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
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    # Default to status if no subcommand
    if not args.command:
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

        # Validate --entry is in device list (catch early, even in dry-run)
        if args.command == 'reset' and args.entry and args.entry not in config['devices']:
            print(f"\n  ERROR: --entry {args.entry} is not in the device list\n", file=sys.stderr)
            sys.exit(1)

        print_banner('BLINK TOGGLE' if args.b else args.command, config)

        if args.dry_run:
            print("\n  Devices:")
            for ip in config['devices']:
                print(f"    {ip}")
            print("\n  [DRY RUN] No connections will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

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
                    print(f"\n  [OK  ] {ip:<17s}{before}  ->  {after}")
                else:
                    print(f"\n  [FAIL] {ip:<17s}{detail}")

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
