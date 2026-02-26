#!/usr/bin/env python3
"""Compare SSH vs SNMP getter output on live HiOS devices.

Usage: compare_snmp_ssh.py <hostname> <username> <password>
   Or: compare_snmp_ssh.py   (runs against both BRS50 + GRS1042 with defaults)
"""

import json
import sys
import time
import traceback
from napalm_hios.hios import HIOSDriver


# Getters that both SSH and SNMP support
COMMON_GETTERS = [
    'get_facts',
    'get_interfaces',
    'get_interfaces_ip',
    'get_interfaces_counters',
    'get_lldp_neighbors',
    'get_lldp_neighbors_detail',
    'get_mac_address_table',
    'get_arp_table',
    'get_vlans',
    'get_snmp_information',
    'get_environment',
    'get_optics',
    'get_users',
    'get_ntp_servers',
    'get_ntp_stats',
    'get_mrp',
    'get_hidiscovery',
    'get_lldp_neighbors_detail_extended',
]


def connect(hostname, username, password, protocol):
    """Connect and return driver."""
    d = HIOSDriver(
        hostname=hostname,
        username=username,
        password=password,
        timeout=30,
        optional_args={'protocol_preference': [protocol]},
    )
    d.open()
    return d


def run_getter(driver, name):
    """Run a single getter, return (result, error, duration_ms)."""
    t0 = time.time()
    try:
        result = getattr(driver, name)()
        return result, None, round((time.time() - t0) * 1000)
    except Exception as e:
        return None, f'{type(e).__name__}: {e}', round((time.time() - t0) * 1000)


def compare_values(ssh_val, snmp_val, path=''):
    """Recursively compare two values, return list of difference strings."""
    diffs = []
    if type(ssh_val) != type(snmp_val):
        # Allow int/float mismatch
        if isinstance(ssh_val, (int, float)) and isinstance(snmp_val, (int, float)):
            if ssh_val != snmp_val:
                diffs.append(f'{path}: {ssh_val!r} vs {snmp_val!r}')
        else:
            diffs.append(f'{path}: type {type(ssh_val).__name__} vs {type(snmp_val).__name__}')
        return diffs

    if isinstance(ssh_val, dict):
        all_keys = set(ssh_val) | set(snmp_val)
        for k in sorted(all_keys, key=str):
            subpath = f'{path}.{k}' if path else str(k)
            if k not in ssh_val:
                diffs.append(f'{subpath}: SNMP-only key')
            elif k not in snmp_val:
                diffs.append(f'{subpath}: SSH-only key')
            else:
                diffs.extend(compare_values(ssh_val[k], snmp_val[k], subpath))
    elif isinstance(ssh_val, list):
        if len(ssh_val) != len(snmp_val):
            diffs.append(f'{path}: list len {len(ssh_val)} vs {len(snmp_val)}')
        for i, (a, b) in enumerate(zip(ssh_val, snmp_val)):
            diffs.extend(compare_values(a, b, f'{path}[{i}]'))
    else:
        if ssh_val != snmp_val:
            diffs.append(f'{path}: {ssh_val!r} vs {snmp_val!r}')
    return diffs


def compare_device(hostname, username, password):
    """Run SSH and SNMP getters on one device, compare and report."""
    print(f'\n{"="*70}')
    print(f'DEVICE: {hostname}')
    print(f'{"="*70}')

    # Connect both protocols
    print(f'\nConnecting SSH...', end=' ', flush=True)
    try:
        ssh = connect(hostname, username, password, 'ssh')
        print('OK')
    except Exception as e:
        print(f'FAILED: {e}')
        return

    print(f'Connecting SNMP...', end=' ', flush=True)
    try:
        snmp = connect(hostname, username, password, 'snmp')
        print('OK')
    except Exception as e:
        print(f'FAILED: {e}')
        ssh.close()
        return

    results = {}
    for getter in COMMON_GETTERS:
        print(f'\n--- {getter} ---')

        ssh_result, ssh_err, ssh_ms = run_getter(ssh, getter)
        snmp_result, snmp_err, snmp_ms = run_getter(snmp, getter)

        status = {}
        if ssh_err and snmp_err:
            print(f'  SSH:  ERROR ({ssh_ms}ms) {ssh_err}')
            print(f'  SNMP: ERROR ({snmp_ms}ms) {snmp_err}')
            status['status'] = 'both_failed'
        elif ssh_err:
            print(f'  SSH:  ERROR ({ssh_ms}ms) {ssh_err}')
            print(f'  SNMP: OK    ({snmp_ms}ms)')
            status['status'] = 'ssh_failed'
        elif snmp_err:
            print(f'  SSH:  OK    ({ssh_ms}ms)')
            print(f'  SNMP: ERROR ({snmp_ms}ms) {snmp_err}')
            status['status'] = 'snmp_failed'
        else:
            print(f'  SSH:  OK ({ssh_ms}ms)  |  SNMP: OK ({snmp_ms}ms)')
            diffs = compare_values(ssh_result, snmp_result)
            if diffs:
                print(f'  DIFFERENCES ({len(diffs)}):')
                for d in diffs[:30]:  # cap output
                    print(f'    {d}')
                if len(diffs) > 30:
                    print(f'    ... and {len(diffs) - 30} more')
                status['status'] = 'differs'
                status['diff_count'] = len(diffs)
            else:
                print(f'  MATCH')
                status['status'] = 'match'

        status['ssh_ms'] = ssh_ms
        status['snmp_ms'] = snmp_ms
        status['ssh_result'] = ssh_result
        status['snmp_result'] = snmp_result
        status['ssh_error'] = ssh_err
        status['snmp_error'] = snmp_err
        results[getter] = status

    ssh.close()
    snmp.close()

    # Summary
    print(f'\n{"="*70}')
    print(f'SUMMARY: {hostname}')
    print(f'{"="*70}')
    match = sum(1 for r in results.values() if r['status'] == 'match')
    differs = sum(1 for r in results.values() if r['status'] == 'differs')
    ssh_fail = sum(1 for r in results.values() if r['status'] == 'ssh_failed')
    snmp_fail = sum(1 for r in results.values() if r['status'] == 'snmp_failed')
    both_fail = sum(1 for r in results.values() if r['status'] == 'both_failed')
    total = len(results)
    print(f'  Match: {match}/{total}  |  Differs: {differs}  |  SSH-fail: {ssh_fail}  |  SNMP-fail: {snmp_fail}  |  Both-fail: {both_fail}')

    for name, r in results.items():
        icon = {'match': '+', 'differs': '~', 'ssh_failed': 'S', 'snmp_failed': 'X', 'both_failed': '!'}
        print(f'  [{icon.get(r["status"], "?")}] {name}')

    return results


def main():
    if len(sys.argv) == 4:
        hostname, username, password = sys.argv[1:4]
        compare_device(hostname, username, password)
    else:
        # Default: both lab devices
        devices = [
            ('192.168.1.4', 'admin', 'private'),     # BRS50
            ('192.168.1.254', 'admin', 'private'),    # GRS1042
        ]
        all_results = {}
        for hostname, username, password in devices:
            try:
                all_results[hostname] = compare_device(hostname, username, password)
            except Exception as e:
                print(f'\nFATAL error on {hostname}: {e}')
                traceback.print_exc()

        # Final cross-device summary
        print(f'\n{"="*70}')
        print(f'CROSS-DEVICE SUMMARY')
        print(f'{"="*70}')
        for host, results in all_results.items():
            if results:
                match = sum(1 for r in results.values() if r['status'] == 'match')
                total = len(results)
                print(f'  {host}: {match}/{total} match')


if __name__ == '__main__':
    main()
