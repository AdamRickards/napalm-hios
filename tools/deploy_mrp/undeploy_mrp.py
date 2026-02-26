"""
undeploy_mrp — Reverse an MRP deployment using the same script.cfg.

1. Re-enable RSTP on ring ports (so loop protection is active)
2. Delete MRP config on all devices
3. Optionally save

Designed for testing: deploy → time → undeploy → deploy (next protocol)
"""

import sys
import os
import logging
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Reuse config parsing from deploy_mrp
from deploy_mrp import (
    get_resource_path, parse_config, print_plan, is_valid_ipv4, is_port,
)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Reverse MRP ring deployment')
    parser.add_argument('-c', '--config', default='script.cfg',
                        help='Path to configuration file (default: script.cfg)')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse config and show plan without executing')
    return parser.parse_args()


def worker_connect(driver, config, dev, timeout):
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


def worker_enable_rstp(device, dev):
    """Re-enable RSTP on ring ports."""
    ip = dev['ip']
    try:
        for port in [dev['port1'], dev['port2']]:
            device.set_rstp_port(port, enabled=True)
        return ip, True, "RSTP enabled"
    except (AttributeError, NotImplementedError):
        return ip, False, "set_rstp_port not available"
    except Exception as e:
        return ip, False, str(e)


def worker_delete_mrp(device, dev):
    """Delete MRP config."""
    ip = dev['ip']
    try:
        device.delete_mrp()
        return ip, True, "MRP deleted"
    except Exception as e:
        return ip, False, str(e)


def worker_save(device, dev):
    ip = dev['ip']
    try:
        status = device.save_config()
        if status.get('saved'):
            return ip, True, f"nvm={status.get('nvm')}"
        return ip, False, f"saved=False, nvm={status.get('nvm')}"
    except Exception as e:
        return ip, False, str(e)


def print_results(phase_name, results):
    print(f"\n  {phase_name}")
    print("  " + "-" * 55)
    for ip, success, msg in results:
        tag = "OK" if success else "FAIL"
        print(f"  [{tag:4s}] {ip:20s} {msg}")


def main():
    args = parse_arguments()

    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir, f'undeploy_mrp_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

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

        print("\n" + "=" * 60)
        print("  MRP UNDEPLOY")
        print("=" * 60)
        print(f"  Protocol:  {config['protocol'].upper()}")
        print(f"  Devices:   {len(config['devices'])}")
        print("-" * 60)
        for i, dev in enumerate(config['devices'], 1):
            role_str = "MANAGER" if dev['role'] == 'manager' else "client"
            print(f"  {i}. {dev['ip']:20s}  {dev['port1']} + {dev['port2']}  [{role_str}]")
        print("=" * 60)

        if args.dry_run:
            print("\n  [DRY RUN] No changes will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        # Connect all
        print("\n  Connecting...")
        connections = {}
        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {
                pool.submit(worker_connect, driver, config, dev, args.timeout): dev
                for dev in config['devices']
            }
            for future in as_completed(futures):
                ip, device, err = future.result()
                if device:
                    connections[ip] = device
                else:
                    print(f"  FAIL: {ip} — {err}")

        if not connections:
            print("\n  FATAL: No devices reachable.\n")
            sys.exit(1)

        try:
            # Step 1: Re-enable RSTP on ring ports (parallel)
            print("\n  Step 1: Re-enabling RSTP on ring ports...")
            rstp_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_enable_rstp, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_results.append(future.result())

            print_results("Step 1 — RSTP", rstp_results)

            rstp_ok = all(r[1] for r in rstp_results)
            if not rstp_ok:
                print("\n  WARNING: RSTP not re-enabled on all devices.")
                print("  Proceeding with MRP delete — ports may go down if loops exist.")

            # Step 2: Delete MRP on all devices (parallel)
            print("\n  Step 2: Deleting MRP...")
            mrp_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_delete_mrp, device, dev)] = dev
                for future in as_completed(futures):
                    mrp_results.append(future.result())

            print_results("Step 2 — MRP Delete", mrp_results)

            # Step 3: Save if configured
            if config['save']:
                print("\n  Step 3: Saving configs...")
                save_results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        device = connections.get(dev['ip'])
                        if device:
                            futures[pool.submit(worker_save, device, dev)] = dev
                    for future in as_completed(futures):
                        save_results.append(future.result())
                print_results("Step 3 — Config Save", save_results)
            else:
                print("\n  Step 3: Skipped (save=false)")
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
