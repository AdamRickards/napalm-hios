"""
deploy_mrp — Configure MRP rings across multiple HiOS switches.

Reads a script.cfg file with global defaults and per-device overrides,
configures MRP on each device in parallel, verifies ring health on the
manager, disables RSTP on ring ports, and optionally saves configs.

Usage:
    python deploy_mrp.py
    python deploy_mrp.py -c my_ring.cfg
    python deploy_mrp.py --debug
    python deploy_mrp.py --dry-run
"""

import sys
import os
import logging
import ipaddress
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), relative_path)
    return os.path.abspath(relative_path)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Deploy MRP ring across HiOS switches')
    parser.add_argument('-c', '--config', default='script.cfg',
                        help='Path to configuration file (default: script.cfg)')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging (MOPS XML detail)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse config and show plan without executing')
    return parser.parse_args()


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_port(s: str) -> bool:
    """Check if a token looks like a port name (contains /)."""
    return '/' in s


def parse_config(config_file: str) -> dict:
    """Parse script.cfg into global settings and device list."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found")

    config = {
        'username': '',
        'password': '',
        'port1': '',
        'port2': '',
        'vlan': '1',
        'recovery_delay': '200ms',
        'save': False,
        'debug': False,
        'protocol': 'mops',
        'devices': [],
    }

    with open(config_file, 'r') as f:
        for line_num, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('username '):
                config['username'] = line.split(None, 1)[1]
            elif line.startswith('password '):
                config['password'] = line.split(None, 1)[1]
            elif line.startswith('port1 '):
                config['port1'] = line.split(None, 1)[1]
            elif line.startswith('port2 '):
                config['port2'] = line.split(None, 1)[1]
            elif line.startswith('vlan '):
                config['vlan'] = line.split(None, 1)[1]
            elif line.startswith('recovery_delay '):
                config['recovery_delay'] = line.split(None, 1)[1]
            elif line.startswith('save '):
                config['save'] = line.split(None, 1)[1].lower() in ('true', 'yes', '1')
            elif line.startswith('protocol '):
                config['protocol'] = line.split(None, 1)[1].lower().strip()
            elif line.startswith('debug '):
                config['debug'] = line.split(None, 1)[1].lower() in ('true', 'yes', '1')
            else:
                tokens = line.split()
                if not tokens:
                    continue

                ip = tokens[0]
                if not is_valid_ipv4(ip):
                    logging.warning(f"Line {line_num}: skipping invalid IP '{ip}'")
                    continue

                ports = []
                role = 'client'
                for token in tokens[1:]:
                    if token.upper() == 'RM':
                        role = 'manager'
                    elif is_port(token):
                        ports.append(token)
                    else:
                        logging.warning(f"Line {line_num}: ignoring unknown token '{token}'")

                config['devices'].append({
                    'ip': ip,
                    'port1': ports[0] if len(ports) >= 1 else '',
                    'port2': ports[1] if len(ports) >= 2 else '',
                    'role': role,
                })

    if not config['username'] or not config['password']:
        raise ValueError("Configuration must contain both username and password")
    if not config['devices']:
        raise ValueError("No valid device IPs found in configuration")

    for dev in config['devices']:
        if not dev['port1']:
            dev['port1'] = config['port1']
        if not dev['port2']:
            dev['port2'] = config['port2']
        if not dev['port1'] or not dev['port2']:
            raise ValueError(f"Device {dev['ip']}: no ring ports specified and no global defaults")

    managers = [d for d in config['devices'] if d['role'] == 'manager']
    if len(managers) == 0:
        config['devices'][0]['role'] = 'manager'
        logging.warning(
            f"No RM specified — auto-assigning {config['devices'][0]['ip']} as ring manager"
        )
    elif len(managers) > 1:
        ips = ', '.join(d['ip'] for d in managers)
        logging.warning(f"Multiple ring managers ({ips}) — MRP rings should have exactly one")

    return config


def print_plan(config: dict):
    """Print the deployment plan."""
    print("\n" + "=" * 60)
    print("  MRP DEPLOYMENT PLAN")
    print("=" * 60)
    print(f"  Protocol:        {config['protocol'].upper()}")
    print(f"  VLAN:            {config['vlan']}")
    print(f"  Recovery delay:  {config['recovery_delay']}")
    print(f"  Save to NVM:     {'Yes (after ring verified)' if config['save'] else 'No (RAM only)'}")
    print(f"  Devices:         {len(config['devices'])}")
    print("-" * 60)

    for i, dev in enumerate(config['devices'], 1):
        role_str = "MANAGER" if dev['role'] == 'manager' else "client"
        print(f"  {i}. {dev['ip']:20s}  {dev['port1']} + {dev['port2']}  [{role_str}]")

    print("=" * 60)
    print()


# ---------------------------------------------------------------------------
# Per-device worker functions (run in threads)
# ---------------------------------------------------------------------------

def worker_connect(driver, config, dev, timeout):
    """Thread worker: open connection to one device."""
    ip = dev['ip']
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


def worker_configure_mrp(device, dev, vlan, recovery_delay):
    """Thread worker: configure MRP on one device."""
    ip = dev['ip']
    try:
        t0 = time.time()
        logging.info(f"[{ip}] Setting MRP: {dev['role']}, {dev['port1']}+{dev['port2']}, vlan={vlan}")
        device.set_mrp(
            operation='enable',
            mode=dev['role'],
            port_primary=dev['port1'],
            port_secondary=dev['port2'],
            vlan=vlan,
            recovery_delay=recovery_delay,
        )
        dt = time.time() - t0
        logging.info(f"[{ip}] set_mrp done in {dt:.1f}s")
        return ip, True, None, f"configured ({dt:.1f}s)"

    except Exception as e:
        return ip, False, None, str(e)


def worker_disable_rstp(device, dev):
    """Thread worker: disable RSTP on ring ports for one device."""
    ip = dev['ip']
    try:
        for port in [dev['port1'], dev['port2']]:
            device.set_rstp_port(port, enabled=False)
        return ip, True, "RSTP disabled"
    except (AttributeError, NotImplementedError):
        return ip, False, "set_rstp_port not available"
    except Exception as e:
        return ip, False, str(e)


def worker_save(device, dev):
    """Thread worker: save config on one device."""
    ip = dev['ip']
    try:
        status = device.save_config()
        if status.get('saved'):
            return ip, True, f"nvm={status.get('nvm')}"
        return ip, False, f"saved=False, nvm={status.get('nvm')}"
    except Exception as e:
        return ip, False, str(e)


# ---------------------------------------------------------------------------
# Parallel executors
# ---------------------------------------------------------------------------

def run_parallel(fn, items, label):
    """Run fn for each item in parallel, collect results in order."""
    results = {}
    with ThreadPoolExecutor(max_workers=len(items)) as pool:
        futures = {pool.submit(fn, item): item for item in items}
        for future in as_completed(futures):
            ip, *rest = future.result()
            results[ip] = rest
    return results


def print_results(phase_name: str, results: list):
    """Print phase results summary."""
    print(f"\n  {phase_name}")
    print("  " + "-" * 55)
    for ip, success, msg in results:
        tag = "OK" if success else "FAIL"
        print(f"  [{tag:4s}] {ip:20s} {msg}")


def main():
    args = parse_arguments()

    # Logging setup
    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir, f'deploy_mrp_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

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
        config_path = get_resource_path(args.config)
        config = parse_config(config_path)
        if args.debug:
            config['debug'] = True

        print_plan(config)

        if args.dry_run:
            print("  [DRY RUN] No changes will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        # --- Connect all devices in parallel ---
        print("  Connecting...")
        connections = {}
        connect_failures = []

        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {
                pool.submit(worker_connect, driver, config, dev, args.timeout): dev
                for dev in config['devices']
            }
            for future in as_completed(futures):
                ip, device, err = future.result()
                if device:
                    connections[ip] = device
                    logging.info(f"[{ip}] Connected")
                else:
                    connect_failures.append((ip, err))
                    logging.error(f"[{ip}] Connection failed: {err}")

        if connect_failures:
            for ip, err in connect_failures:
                print(f"  FAIL: {ip} — {err}")
        if not connections:
            print("\n  FATAL: No devices reachable.\n")
            sys.exit(1)

        try:
            # --- Phase 1: Configure MRP in parallel ---
            print("\n  Phase 1: Configuring MRP...")
            vlan = int(config['vlan'])
            recovery_delay = config['recovery_delay']
            mrp_results = []

            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(
                            worker_configure_mrp, device, dev, vlan, recovery_delay
                        )] = dev
                    else:
                        mrp_results.append((dev['ip'], False, "no connection"))

                for future in as_completed(futures):
                    ip, ok, _mrp_data, detail = future.result()
                    mrp_results.append((ip, ok, f"MRP {[d for d in config['devices'] if d['ip'] == ip][0]['role']}, {detail}"))

            print_results("Phase 1 — MRP Configuration", mrp_results)

            failures = [r for r in mrp_results if not r[1]]
            if failures:
                print(f"\n  {len(failures)} device(s) failed. Configs NOT saved — power cycle to rollback.\n")
                sys.exit(1)

            # --- Phase 2: Verify ring on manager ---
            print("\n  Phase 2: Verifying ring...")
            managers = [d for d in config['devices'] if d['role'] == 'manager']
            rm_ip = managers[0]['ip']
            rm_device = connections.get(rm_ip)

            if not rm_device:
                print(f"\n  FATAL: No connection to ring manager {rm_ip}\n")
                sys.exit(1)

            mrp = rm_device.get_mrp()
            ring_state = mrp.get('ring_state', 'unknown')
            redundancy = mrp.get('redundancy', False)
            healthy = ring_state == 'closed' and redundancy

            status_tag = "HEALTHY" if healthy else "UNHEALTHY"
            print(f"  Ring: [{status_tag}] state={ring_state}, redundancy={redundancy}")

            if not healthy:
                print("\n  Ring NOT healthy. Configs NOT saved — power cycle to rollback.\n")
                sys.exit(1)

            # --- Disable RSTP on ring ports in parallel ---
            print("\n  Disabling RSTP on ring ports...")
            rstp_results = []

            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_disable_rstp, device, dev)] = dev

                for future in as_completed(futures):
                    ip, ok, detail = future.result()
                    rstp_results.append((ip, ok, detail))

            rstp_failures = [r for r in rstp_results if not r[1]]
            if rstp_failures:
                # Not fatal — just warn
                for ip, _, detail in rstp_failures:
                    logging.warning(f"[{ip}] {detail}")
                print(f"  RSTP: {len(rstp_failures)} device(s) need manual RSTP disable")
            else:
                print("  RSTP: disabled on all ring ports")

            # --- Phase 3: Save ---
            if config['save']:
                print("\n  Phase 3: Saving configs...")
                save_results = []

                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        device = connections.get(dev['ip'])
                        if device:
                            futures[pool.submit(worker_save, device, dev)] = dev

                    for future in as_completed(futures):
                        ip, ok, detail = future.result()
                        save_results.append((ip, ok, detail))

                print_results("Phase 3 — Config Save", save_results)

                save_failures = [r for r in save_results if not r[1]]
                if save_failures:
                    print(f"\n  WARNING: {len(save_failures)} device(s) failed to save.")
            else:
                print("\n  Phase 3: Skipped (save=false)")
                print("  Configs in RAM only — power cycle to rollback.")

            elapsed = time.time() - start_time
            print(f"\n  Done in {elapsed:.1f}s")
            print(f"  Log: {log_filename}\n")

        finally:
            for ip, device in connections.items():
                try:
                    device.close()
                except Exception:
                    pass

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"\n  FATAL: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
