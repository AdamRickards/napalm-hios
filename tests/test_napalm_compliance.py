"""
Live NAPALM compliance test — runs against a real device.

Verifies all 18 NAPALM standard getters return correct top-level types,
expected keys, and correct value types. Also verifies napalm_compat=False
returns canonical (non-NAPALM) output.

Usage:
    python3 tests/test_napalm_compliance.py 192.168.1.4
    python3 tests/test_napalm_compliance.py 192.168.1.4 -u admin -p private --protocol mops
"""
import argparse
import sys


NAPALM_SPECS = {
    'get_facts': {
        'type': dict,
        'keys': {
            'hostname': str, 'vendor': str, 'model': str,
            'serial_number': str, 'os_version': str,
            'uptime': (int, float), 'interface_list': list,
        },
    },
    'get_interfaces': {
        'type': dict,
        'row': {
            'is_up': bool, 'is_enabled': bool, 'description': str,
            'last_flapped': (int, float), 'speed': (int, float),
            'mtu': int, 'mac_address': str,
        },
        'canonical_row': {
            'oper_status': str, 'admin_status': str, 'alias': str,
            'speed': (int, float), 'mtu': int, 'phys_address': str,
        },
    },
    'get_interfaces_counters': {
        'type': dict,
        'row': {
            'tx_errors': int, 'rx_errors': int, 'tx_discards': int,
            'rx_discards': int, 'tx_octets': int, 'rx_octets': int,
            'tx_unicast_packets': int, 'rx_unicast_packets': int,
            'tx_multicast_packets': int, 'rx_multicast_packets': int,
            'tx_broadcast_packets': int, 'rx_broadcast_packets': int,
        },
    },
    'get_interfaces_ip': {'type': dict},
    'get_lldp_neighbors': {
        'type': dict,
        'row_list': {'hostname': str, 'port': str},
        'canonical_row_list': {'sys_name': str, 'port_id': str},
    },
    'get_lldp_neighbors_detail': {
        'type': dict,
        'row_list': {
            'remote_hostname': str, 'remote_port': str,
            'remote_port_description': str, 'remote_chassis_id': str,
            'remote_system_description': str,
        },
        'canonical_row_list': {
            'sys_name': str, 'port_id': str, 'port_description': str,
            'chassis_id': str, 'sys_description': str,
        },
    },
    'get_mac_address_table': {
        'type': list,
        'row': {
            'mac': str, 'interface': str, 'vlan': int,
            'active': bool, 'static': bool,
            'moves': int, 'last_move': (int, float),
        },
        'canonical_row': {
            'mac': str, 'interface': str, 'vlan': int, 'status': str,
        },
    },
    'get_arp_table': {
        'type': list,
        'row': {'interface': str, 'mac': str, 'ip': str, 'age': (int, float)},
    },
    'get_ntp_servers': {'type': dict},
    'get_ntp_stats': {'type': list},
    'get_users': {'type': dict},
    'get_snmp_information': {'type': dict},
    'get_optics': {'type': dict},
    'get_config': {
        'type': dict,
        'keys': {'running': str, 'startup': str},
    },
    'get_environment': {'type': dict},
    'get_vlans': {'type': dict},
    'get_route_to': {'type': dict},
    'get_ipv6_neighbors_table': {'type': dict},
}


def check_row(method, label, row, expected_keys, errors):
    """Verify a row dict has expected keys with correct types."""
    for k, expected_type in expected_keys.items():
        if k not in row:
            errors.append(f'{method} {label}: missing key "{k}"')
        elif not isinstance(row[k], expected_type):
            errors.append(
                f'{method} {label}.{k}: expected {expected_type}, '
                f'got {type(row[k]).__name__} = {repr(row[k])[:50]}')


def run_compliance(device):
    errors = []
    total = 0

    for method, spec in NAPALM_SPECS.items():
        total += 1
        method_errors = []

        # Test napalm_compat=True (default)
        try:
            result = getattr(device, method)()
        except Exception as e:
            errors.append(f'{method}: CALL FAILED: {e}')
            print(f'  {method:40s} FAIL (call failed)')
            continue

        if not isinstance(result, spec['type']):
            method_errors.append(
                f'{method}: expected {spec["type"].__name__}, '
                f'got {type(result).__name__}')

        if 'keys' in spec and result:
            check_row(method, 'top', result, spec['keys'], method_errors)

        if 'row' in spec and isinstance(result, dict) and result:
            first_key = next(iter(result))
            check_row(method, f'[{first_key}]', result[first_key],
                      spec['row'], method_errors)

        if 'row' in spec and isinstance(result, list) and result:
            check_row(method, '[0]', result[0], spec['row'], method_errors)

        if 'row_list' in spec and isinstance(result, dict) and result:
            first_key = next(iter(result))
            entries = result[first_key]
            if not isinstance(entries, list):
                method_errors.append(
                    f'{method}[{first_key}]: expected list, '
                    f'got {type(entries).__name__}')
            elif entries:
                check_row(method, f'[{first_key}][0]', entries[0],
                          spec['row_list'], method_errors)

        # Test napalm_compat=False (canonical)
        try:
            canonical = getattr(device, method)(napalm_compat=False)
        except TypeError:
            canonical = None  # method doesn't accept napalm_compat

        if canonical is not None:
            canonical_spec = spec.get('canonical_row') or spec.get('canonical_row_list')
            if canonical_spec:
                if isinstance(canonical, dict) and canonical:
                    first_key = next(iter(canonical))
                    sample = canonical[first_key]
                    if isinstance(sample, list) and sample:
                        sample = sample[0]
                    if isinstance(sample, dict):
                        check_row(method, 'canonical', sample,
                                  canonical_spec, method_errors)

        errors.extend(method_errors)
        status = 'OK' if not method_errors else 'FAIL'
        print(f'  {method:40s} {status}')

    return errors, total


def main():
    parser = argparse.ArgumentParser(description='NAPALM compliance test')
    parser.add_argument('host', help='Device IP')
    parser.add_argument('-u', default='admin', help='Username')
    parser.add_argument('-p', default='private', help='Password')
    parser.add_argument('--protocol', default=None,
                        choices=['mops', 'snmp', 'ssh'])
    args = parser.parse_args()

    from napalm import get_network_driver
    driver = get_network_driver('hios')
    optional = {}
    if args.protocol:
        optional['protocol'] = args.protocol
    device = driver(args.host, args.u, args.p, optional_args=optional)
    device.open()

    print(f'NAPALM Compliance Test — {args.host}')
    print('=' * 50)

    errors, total = run_compliance(device)
    device.close()

    print(f'\n{"=" * 50}')
    if errors:
        print(f'{len(errors)} errors in {total} methods:')
        for e in errors:
            print(f'  {e}')
        sys.exit(1)
    else:
        print(f'ALL PASS — {total}/{total} methods compliant')


if __name__ == '__main__':
    main()
