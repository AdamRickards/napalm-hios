#!/usr/bin/env python3
"""Compare MOPS vs SNMP vs SSH getter output on live HiOS devices.

Runs all read-only getters with each protocol forced independently,
captures results, errors, and timing, then diffs every protocol pair.

Usage:
    compare_all_protocols.py <hostname> <username> <password>
    compare_all_protocols.py   (runs against BRS50 + GRS1042 with defaults)

Output:
    - Console: live progress + summary table
    - compare_results_<hostname>.json: full raw results for offline analysis
"""

import json
import sys
import time
import traceback
from collections import OrderedDict
from datetime import datetime

from napalm_hios.hios import HIOSDriver


PROTOCOLS = ['mops', 'snmp', 'ssh']

# All read-only getters shared across all 3 protocols
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
    'get_config_status',
    'get_lldp_neighbors_detail_extended',
]

# Getters only available on SSH (won't count as failures for MOPS/SNMP)
SSH_ONLY_GETTERS = [
    'get_config',
    'ping',
    'cli',
]

# Protocol pairs for comparison
PAIRS = [
    ('mops', 'snmp'),
    ('mops', 'ssh'),
    ('snmp', 'ssh'),
]


def connect(hostname, username, password, protocol):
    """Connect with a single forced protocol. Returns (driver, error)."""
    try:
        d = HIOSDriver(
            hostname=hostname,
            username=username,
            password=password,
            timeout=30,
            optional_args={'protocol_preference': [protocol]},
        )
        d.open()
        return d, None
    except Exception as e:
        return None, f'{type(e).__name__}: {e}'


def run_getter(driver, name):
    """Run a single getter. Returns (result, error_string, duration_ms)."""
    t0 = time.time()
    try:
        result = getattr(driver, name)()
        return result, None, round((time.time() - t0) * 1000)
    except Exception as e:
        return None, f'{type(e).__name__}: {e}', round((time.time() - t0) * 1000)


def compare_values(val_a, val_b, path=''):
    """Recursively compare two values. Returns list of difference strings."""
    diffs = []
    if type(val_a) != type(val_b):
        # Allow int/float mismatch
        if isinstance(val_a, (int, float)) and isinstance(val_b, (int, float)):
            if val_a != val_b:
                diffs.append(f'{path}: {val_a!r} vs {val_b!r}')
        else:
            diffs.append(f'{path}: type {type(val_a).__name__} vs {type(val_b).__name__}')
        return diffs

    if isinstance(val_a, dict):
        all_keys = set(val_a) | set(val_b)
        for k in sorted(all_keys, key=str):
            subpath = f'{path}.{k}' if path else str(k)
            if k not in val_a:
                diffs.append(f'{subpath}: only in B')
            elif k not in val_b:
                diffs.append(f'{subpath}: only in A')
            else:
                diffs.extend(compare_values(val_a[k], val_b[k], subpath))
    elif isinstance(val_a, list):
        if len(val_a) != len(val_b):
            diffs.append(f'{path}: list len {len(val_a)} vs {len(val_b)}')
        for i, (a, b) in enumerate(zip(val_a, val_b)):
            diffs.extend(compare_values(a, b, f'{path}[{i}]'))
    else:
        if val_a != val_b:
            diffs.append(f'{path}: {val_a!r} vs {val_b!r}')
    return diffs


def diff_pair(result_a, result_b, label_a, label_b):
    """Compare two getter results. Returns (status, diff_count, diffs_list)."""
    err_a = result_a.get('error')
    err_b = result_b.get('error')

    if err_a and err_b:
        return 'both_failed', 0, []
    if err_a:
        return f'{label_a}_failed', 0, []
    if err_b:
        return f'{label_b}_failed', 0, []

    diffs = compare_values(result_a['result'], result_b['result'])
    if diffs:
        return 'differs', len(diffs), diffs
    return 'match', 0, []


def compare_device(hostname, username, password):
    """Run all getters on all protocols for one device, compare and report."""
    print(f'\n{"="*78}')
    print(f' DEVICE: {hostname}')
    print(f' Time:   {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'{"="*78}')

    # Connect each protocol
    drivers = {}
    for proto in PROTOCOLS:
        print(f'  Connecting {proto.upper():4s} ...', end=' ', flush=True)
        driver, err = connect(hostname, username, password, proto)
        if err:
            print(f'FAILED: {err}')
        else:
            print(f'OK  (active: {driver.active_protocol})')
        drivers[proto] = driver

    connected = [p for p in PROTOCOLS if drivers[p] is not None]
    if not connected:
        print('\n  No protocols connected — skipping device.\n')
        return None

    print(f'\n  Connected protocols: {", ".join(p.upper() for p in connected)}')
    print(f'  Running {len(COMMON_GETTERS)} getters...\n')

    # Run all getters on all connected protocols
    all_results = {}  # getter -> proto -> {result, error, ms}
    for getter in COMMON_GETTERS:
        print(f'  {getter:42s}', end='  ', flush=True)
        all_results[getter] = {}
        status_parts = []

        for proto in PROTOCOLS:
            if drivers[proto] is None:
                all_results[getter][proto] = {
                    'result': None,
                    'error': f'Not connected',
                    'ms': 0,
                }
                status_parts.append(f'{proto.upper()}:SKIP')
            else:
                result, err, ms = run_getter(drivers[proto], getter)
                all_results[getter][proto] = {
                    'result': result,
                    'error': err,
                    'ms': ms,
                }
                if err:
                    status_parts.append(f'{proto.upper()}:ERR({ms}ms)')
                else:
                    status_parts.append(f'{proto.upper()}:OK({ms}ms)')

        print('  '.join(status_parts))

    # Close connections
    for proto in PROTOCOLS:
        if drivers[proto]:
            try:
                drivers[proto].close()
            except Exception:
                pass

    # Pairwise comparison
    print(f'\n{"─"*78}')
    print(f' PAIRWISE COMPARISON')
    print(f'{"─"*78}')

    pair_summaries = {}  # (proto_a, proto_b) -> getter -> {status, diffs, diff_count}
    for proto_a, proto_b in PAIRS:
        pair_key = f'{proto_a}_vs_{proto_b}'
        pair_summaries[pair_key] = {}
        print(f'\n  ┌── {proto_a.upper()} vs {proto_b.upper()} ──┐')

        for getter in COMMON_GETTERS:
            ra = all_results[getter][proto_a]
            rb = all_results[getter][proto_b]
            status, diff_count, diffs = diff_pair(ra, rb, proto_a.upper(), proto_b.upper())

            pair_summaries[pair_key][getter] = {
                'status': status,
                'diff_count': diff_count,
            }

            icon = {
                'match': '+',
                'differs': '~',
                'both_failed': '!',
            }
            # For single-protocol failures, use first letter of failed proto
            if status.endswith('_failed'):
                ic = status[0].upper()
            else:
                ic = icon.get(status, '?')

            line = f'  [{ic}] {getter:42s}'
            if status == 'differs':
                line += f'  {diff_count} diff(s)'
            elif status != 'match':
                line += f'  ({status})'
            print(line)

            # Show first few diffs inline
            if diffs:
                for d in diffs[:10]:
                    print(f'        {d}')
                if len(diffs) > 10:
                    print(f'        ... and {len(diffs) - 10} more')

    # Summary table
    print(f'\n{"="*78}')
    print(f' SUMMARY TABLE: {hostname}')
    print(f'{"="*78}')

    # Header
    pair_labels = [f'{a.upper()}/{b.upper()}' for a, b in PAIRS]
    header = f'  {"Getter":42s}  {"MOPS":>6s}  {"SNMP":>6s}  {"SSH":>6s}  '
    header += '  '.join(f'{l:>10s}' for l in pair_labels)
    print(header)
    print(f'  {"─"*42}  {"─"*6}  {"─"*6}  {"─"*6}  ' + '  '.join('─'*10 for _ in PAIRS))

    for getter in COMMON_GETTERS:
        # Per-protocol status
        proto_cells = []
        for proto in PROTOCOLS:
            r = all_results[getter][proto]
            if r['error']:
                proto_cells.append(f'{"ERR":>6s}')
            else:
                proto_cells.append(f'{r["ms"]:>4d}ms')

        # Per-pair status
        pair_cells = []
        for proto_a, proto_b in PAIRS:
            pair_key = f'{proto_a}_vs_{proto_b}'
            ps = pair_summaries[pair_key][getter]
            st = ps['status']
            if st == 'match':
                pair_cells.append(f'{"MATCH":>10s}')
            elif st == 'differs':
                pair_cells.append(f'{ps["diff_count"]:>7d} df')
            elif st == 'both_failed':
                pair_cells.append(f'{"BOTH ERR":>10s}')
            else:
                pair_cells.append(f'{st:>10s}')

        row = f'  {getter:42s}  {"  ".join(proto_cells)}  {"  ".join(pair_cells)}'
        print(row)

    # Totals
    print(f'  {"─"*42}  {"─"*6}  {"─"*6}  {"─"*6}  ' + '  '.join('─'*10 for _ in PAIRS))
    for proto_a, proto_b in PAIRS:
        pair_key = f'{proto_a}_vs_{proto_b}'
        summaries = pair_summaries[pair_key]
        match = sum(1 for s in summaries.values() if s['status'] == 'match')
        differs = sum(1 for s in summaries.values() if s['status'] == 'differs')
        failed = sum(1 for s in summaries.values() if s['status'] not in ('match', 'differs'))
        total = len(summaries)
        print(f'  {proto_a.upper()}/{proto_b.upper()}: {match}/{total} match, {differs} differ, {failed} error')

    # Per-protocol error summary
    print(f'\n  Per-protocol errors:')
    for proto in PROTOCOLS:
        errors = [(g, all_results[g][proto]['error'])
                  for g in COMMON_GETTERS if all_results[g][proto]['error']]
        if errors:
            print(f'    {proto.upper()}: {len(errors)} error(s)')
            for getter, err in errors:
                print(f'      {getter}: {err}')
        else:
            print(f'    {proto.upper()}: all OK')

    # Save raw results to JSON
    json_file = f'compare_results_{hostname.replace(".", "_")}.json'
    export = {
        'hostname': hostname,
        'timestamp': datetime.now().isoformat(),
        'protocols_connected': connected,
        'getters': {},
    }
    for getter in COMMON_GETTERS:
        export['getters'][getter] = {}
        for proto in PROTOCOLS:
            r = all_results[getter][proto]
            export['getters'][getter][proto] = {
                'ms': r['ms'],
                'error': r['error'],
                'result': r['result'],
            }
        # Add pairwise diff counts
        export['getters'][getter]['_pairs'] = {}
        for proto_a, proto_b in PAIRS:
            pair_key = f'{proto_a}_vs_{proto_b}'
            ps = pair_summaries[pair_key][getter]
            export['getters'][getter]['_pairs'][pair_key] = ps['status']

    try:
        with open(json_file, 'w') as f:
            json.dump(export, f, indent=2, default=str)
        print(f'\n  Raw results saved to: {json_file}')
    except Exception as e:
        print(f'\n  Could not save JSON: {e}')

    return {'all_results': all_results, 'pair_summaries': pair_summaries}


def main():
    if len(sys.argv) == 4:
        hostname, username, password = sys.argv[1:4]
        compare_device(hostname, username, password)
    elif len(sys.argv) == 1:
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
                print(f'\n  FATAL error on {hostname}: {e}')
                traceback.print_exc()

        # Cross-device summary
        print(f'\n{"="*78}')
        print(f' CROSS-DEVICE SUMMARY')
        print(f'{"="*78}')
        for host, results in all_results.items():
            if results:
                pairs = results['pair_summaries']
                for pair_key, summaries in pairs.items():
                    match = sum(1 for s in summaries.values() if s['status'] == 'match')
                    total = len(summaries)
                    print(f'  {host} {pair_key}: {match}/{total} match')
    else:
        print('Usage: compare_all_protocols.py [<hostname> <username> <password>]')
        print('       No args = run against BRS50 + GRS1042 with defaults')
        sys.exit(1)


if __name__ == '__main__':
    main()
