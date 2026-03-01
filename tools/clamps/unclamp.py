"""
unclamp — Reverse an MRP deployment using the same script.cfg.

Gathers current state from each switch, then unconditionally cleans
everything back to factory default redundancy configuration:
  - Tear down loop protection + auto-disable (if detected)
  - Tear down RSTP Full: BPDU Guard, admin edge, auto-disable (if detected)
  - Delete MRP
  - Restore RSTP globally + per-port on ring ports

The config file is only used for device IPs, credentials, ports, and
save preference. The switches themselves tell us what needs cleaning.

Designed for testing: deploy → time → undeploy → deploy (next config)
"""

import sys
import os
import logging
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Reuse from clamp
from clamp import (
    get_resource_path, parse_config, is_valid_ipv4, is_port, log_print,
    worker_connect, worker_gather_facts, worker_save,
    worker_enable_rstp_global, worker_teardown_loop_protection,
    worker_teardown_auto_disable, worker_teardown_rstp_full,
    worker_delete_sub_ring, worker_disable_srm_global,
    print_results, run_phase0, rm_ring_needs_breaking,
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


def worker_enable_rstp_ports(device, dev):
    """Re-enable RSTP on ring ports (belt and suspenders with global enable)."""
    ip = dev['ip']
    try:
        for port in [dev['port1'], dev['port2']]:
            device.set_rstp_port(port, enabled=True)
        return ip, True, "RSTP enabled on ring ports"
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


def main():
    args = parse_arguments()

    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir, f'unclamp_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

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
        print(f"  Protocol:        {config['protocol'].upper()}")
        print(f"  Save to NVM:     {'Yes' if config['save'] else 'No (RAM only)'}")
        print(f"  Devices:         {len(config['devices'])}")
        print("-" * 60)
        for i, dev in enumerate(config['devices'], 1):
            role_str = "MANAGER" if dev['role'] == 'manager' else "client"
            print(f"  {i}. {dev['ip']:20s}  {dev['port1']} + {dev['port2']}  [{role_str}]")
        print("=" * 60)

        if args.dry_run:
            log_print("\n  [DRY RUN] No changes will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        # Connect all
        log_print("\n  Connecting...")
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
                    log_print(f"  FAIL: {ip} — {err}")

        if not connections:
            log_print("\n  FATAL: No devices reachable.\n")
            sys.exit(1)

        try:
            managers = [d for d in config['devices'] if d['role'] == 'manager']
            rm_ip = managers[0]['ip']
            rm_device = connections.get(rm_ip)
            rm_dev = managers[0]

            if not rm_device:
                log_print(f"\n  FATAL: No connection to ring manager {rm_ip}\n")
                sys.exit(1)

            # --- Phase 0: Gather facts ---
            device_facts, l2s_devices = run_phase0(config, connections)

            # Detect what needs cleaning based on actual switch state
            has_loop_prot = any(
                f.get('loop_protection', {}).get('enabled', False) if f.get('loop_protection') else False
                for f in device_facts.values()
            )
            has_bpdu_guard = any(
                f.get('rstp', {}).get('bpdu_guard', False) if f.get('rstp') else False
                for f in device_facts.values()
            )
            has_mrp = any(
                f.get('mrp', {}).get('configured', False) if f.get('mrp') else False
                for f in device_facts.values()
            )

            # Detect sub-ring instances on any device
            srm_instances = {}  # {ip: [(ring_id, device), ...]}
            sub_ring_rc_ips = set()
            main_vlan = int(config.get('vlan', '1'))
            sub_ring_vlans = sorted(
                v for v in config.get('rings', {}) if v != main_vlan)

            for dev in config['devices']:
                ip = dev['ip']
                device = connections.get(ip)
                if not device:
                    continue
                try:
                    srm = device.get_mrp_sub_ring()
                    if srm.get('enabled') and srm.get('instances'):
                        srm_instances[ip] = [
                            (inst['ring_id'], device) for inst in srm['instances']]
                except (NotImplementedError, Exception) as e:
                    logging.debug(f"[{ip}] get_mrp_sub_ring: {e}")

            # Collect sub-ring RC IPs from config
            for sv in sub_ring_vlans:
                ring = config['rings'].get(sv, {})
                for dev in ring.get('devices', []):
                    sub_ring_rc_ips.add(dev['ip'])

            has_sub_rings = bool(srm_instances)

            # --- Step 1: Delete sub-rings (before touching main ring) ---
            if has_sub_rings:
                log_print("\n  Step 1: Deleting sub-rings...")

                # 1a: Delete SRM instances
                srm_results = []
                with ThreadPoolExecutor(max_workers=max(1, len(srm_instances))) as pool:
                    futures = {}
                    for ip, instances in srm_instances.items():
                        device = connections[ip]
                        for ring_id, _ in instances:
                            futures[pool.submit(
                                worker_delete_sub_ring, device, ip, ring_id
                            )] = (ip, ring_id)
                    for future in as_completed(futures):
                        srm_results.append(future.result())
                print_results("Step 1a — Delete SRM Instances", srm_results)

                # 1b: Disable SRM globally on those devices
                disable_results = []
                with ThreadPoolExecutor(max_workers=max(1, len(srm_instances))) as pool:
                    futures = {}
                    for ip in srm_instances:
                        device = connections[ip]
                        futures[pool.submit(
                            worker_disable_srm_global, device, ip
                        )] = ip
                    for future in as_completed(futures):
                        disable_results.append(future.result())
                print_results("Step 1b — Disable SRM Global", disable_results)

                # 1c: Delete MRP on sub-ring RCs
                if sub_ring_rc_ips:
                    rc_results = []
                    with ThreadPoolExecutor(max_workers=max(1, len(sub_ring_rc_ips))) as pool:
                        futures = {}
                        for ip in sub_ring_rc_ips:
                            device = connections.get(ip)
                            if device:
                                dev = next((d for d in config['devices'] if d['ip'] == ip), None)
                                if dev:
                                    futures[pool.submit(worker_delete_mrp, device, dev)] = ip
                        for future in as_completed(futures):
                            rc_results.append(future.result())
                    print_results("Step 1c — Delete Sub-Ring RC MRP", rc_results)
            else:
                log_print("\n  Step 1: Skipped (no sub-rings detected)")

            # --- Step 2: Break ring (RM port2 DOWN) ---
            broke_ring = rm_ring_needs_breaking(device_facts, rm_dev)
            if broke_ring:
                log_print(f"\n  Step 2: Unclamping ring — RM port2 ({rm_dev['port2']}) on {rm_ip}...")
                try:
                    rm_device.set_interface(rm_dev['port2'], enabled=False)
                    log_print(f"  [{rm_ip}] port {rm_dev['port2']} admin DOWN — ring unclamped")
                except Exception as e:
                    log_print(f"  WARNING: Cannot disable RM port2: {e}")
                    log_print("  Proceeding anyway...")
            else:
                log_print(f"\n  Step 2: Skipped (ring ports not both up — no ring to break)")

            # --- Step 3: Tear down loop protection (if detected) ---
            if has_loop_prot:
                log_print("\n  Step 3: Tearing down loop protection...")

                ad_results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        ip = dev['ip']
                        device = connections.get(ip)
                        if not device or ip in l2s_devices:
                            continue
                        all_ports = device_facts.get(ip, {}).get('all_ports', [])
                        futures[pool.submit(
                            worker_teardown_auto_disable, device, dev, all_ports, 'loop-protection'
                        )] = dev
                    for future in as_completed(futures):
                        ad_results.append(future.result())
                if ad_results:
                    print_results("Step 3a — Auto-Disable Teardown (loop-protection)", ad_results)

                lp_results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        ip = dev['ip']
                        device = connections.get(ip)
                        if not device or ip in l2s_devices:
                            continue
                        all_ports = device_facts.get(ip, {}).get('all_ports', [])
                        futures[pool.submit(
                            worker_teardown_loop_protection, device, dev, all_ports
                        )] = dev
                    for future in as_completed(futures):
                        lp_results.append(future.result())
                if lp_results:
                    print_results("Step 3b — Loop Protection Teardown", lp_results)

            # --- Step 4: Tear down RSTP Full (if detected) ---
            if has_bpdu_guard:
                log_print("\n  Step 4: Tearing down RSTP Full...")
                results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        ip = dev['ip']
                        device = connections.get(ip)
                        if not device or ip in l2s_devices:
                            continue
                        all_ports = device_facts.get(ip, {}).get('all_ports', [])
                        ring_ports = [dev['port1'], dev['port2']]
                        futures[pool.submit(
                            worker_teardown_rstp_full, device, dev, all_ports, ring_ports
                        )] = dev
                    for future in as_completed(futures):
                        results.append(future.result())
                if results:
                    print_results("Step 4 — RSTP Full Teardown", results)

            if not has_loop_prot and not has_bpdu_guard:
                log_print("\n  Steps 3-4: Skipped (no loop protection or BPDU Guard detected)")

            # --- Step 5: Delete MRP ---
            if has_mrp:
                log_print("\n  Step 5: Deleting MRP...")
                mrp_results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        device = connections.get(dev['ip'])
                        if device:
                            futures[pool.submit(worker_delete_mrp, device, dev)] = dev
                    for future in as_completed(futures):
                        mrp_results.append(future.result())
                print_results("Step 5 — MRP Delete", mrp_results)
            else:
                log_print("\n  Step 5: Skipped (no MRP configured)")

            # --- Step 6: Restore RSTP to factory default ---
            log_print("\n  Step 6: Restoring RSTP...")

            rstp_global_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_enable_rstp_global, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_global_results.append(future.result())
            print_results("Step 6a — RSTP Global Enable", rstp_global_results)

            rstp_port_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_enable_rstp_ports, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_port_results.append(future.result())
            print_results("Step 6b — RSTP Ring Ports Enable", rstp_port_results)

            # --- Step 7: Restore RM port2 ---
            if broke_ring:
                log_print(f"\n  Step 7: Enabling RM port2 ({rm_dev['port2']}) on {rm_ip}...")
                try:
                    rm_device.set_interface(rm_dev['port2'], enabled=True)
                    log_print(f"  [{rm_ip}] port {rm_dev['port2']} admin UP")
                except Exception as e:
                    log_print(f"  WARNING: Cannot re-enable RM port2: {e}")
            else:
                log_print("\n  Step 7: Skipped (ring was not broken in Step 2)")

            # --- Step 8: Save if configured ---
            if config['save']:
                log_print("\n  Step 8: Saving configs...")
                save_results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        device = connections.get(dev['ip'])
                        if device:
                            futures[pool.submit(worker_save, device, dev)] = dev
                    for future in as_completed(futures):
                        save_results.append(future.result())
                print_results("Step 8 — Config Save", save_results)
            else:
                log_print("\n  Step 8: Skipped (save=false)")
                log_print("  Configs in RAM only — power cycle to rollback.")

            elapsed = time.time() - start_time
            log_print(f"\n  Done in {elapsed:.1f}s")
            log_print(f"  Log: {log_filename}\n")

        finally:
            for ip, device in connections.items():
                try:
                    device.close()
                except Exception:
                    pass

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        log_print(f"\n  FATAL: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
