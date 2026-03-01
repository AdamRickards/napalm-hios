"""
Live test: validate get/set/delete_mrp_sub_ring against real devices.

Tests L2A (.80, .81, .82) and L2S (.85) with no sub-rings configured.
Checks MIB node names, value encodings, and graceful L2S behavior.

Usage:
    python test_srm_live.py
    python test_srm_live.py --protocol snmp
    python test_srm_live.py --debug
"""

import sys
import os
import argparse
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from napalm import get_network_driver

DEVICES = {
    '192.168.1.80': 'L2A',
    '192.168.1.81': 'L2A',
    '192.168.1.82': 'L2A',
    '192.168.1.85': 'L2S',
}

USERNAME = 'admin'
PASSWORD = 'private'


def test_device(ip, sw_level, protocol, debug):
    driver = get_network_driver('hios')
    device = driver(
        hostname=ip,
        username=USERNAME,
        password=PASSWORD,
        timeout=15,
        optional_args={'protocol_preference': [protocol]},
    )

    print(f"\n{'='*60}")
    print(f"  {ip}  [{sw_level}]  protocol={protocol}")
    print(f"{'='*60}")

    device.open()
    try:
        # --- 1. get_mrp_sub_ring (empty state) ---
        print(f"\n  1. get_mrp_sub_ring()...")
        try:
            result = device.get_mrp_sub_ring()
            print(f"     enabled:        {result.get('enabled')}")
            print(f"     max_instances:  {result.get('max_instances')}")
            print(f"     instances:      {result.get('instances')}")
            if result.get('instances'):
                for inst in result['instances']:
                    print(f"       ring_id={inst['ring_id']} mode={inst['mode']} "
                          f"vlan={inst['vlan']} port={inst['port']} "
                          f"state={inst['ring_state']}")
            print(f"     [OK] get works")
        except NotImplementedError as e:
            print(f"     [SKIP] {e}")
            return
        except Exception as e:
            print(f"     [FAIL] {e}")
            if debug:
                traceback.print_exc()
            # Continue — want to see what fails

        # --- 2. set_mrp_sub_ring (global enable) ---
        print(f"\n  2. set_mrp_sub_ring(enabled=True)...")
        try:
            result = device.set_mrp_sub_ring(enabled=True)
            print(f"     enabled:        {result.get('enabled')}")
            print(f"     [OK] global enable works")
        except Exception as e:
            print(f"     [FAIL] {e}")
            if debug:
                traceback.print_exc()

        # --- 3. set_mrp_sub_ring (create instance, no real ports) ---
        # Use port 1/3 which should exist on BRS50
        print(f"\n  3. set_mrp_sub_ring(ring_id=1, mode='manager', port='1/3', vlan=200)...")
        try:
            result = device.set_mrp_sub_ring(
                ring_id=1, mode='manager', port='1/3', vlan=200)
            print(f"     enabled:        {result.get('enabled')}")
            print(f"     instances:      {len(result.get('instances', []))}")
            for inst in result.get('instances', []):
                print(f"       ring_id={inst['ring_id']} mode={inst['mode']} "
                      f"vlan={inst['vlan']} port={inst['port']} "
                      f"state={inst['ring_state']} info={inst['info']}")
            print(f"     [OK] create instance works")
        except Exception as e:
            print(f"     [FAIL] {e}")
            if debug:
                traceback.print_exc()

        # --- 4. get_mrp_sub_ring (should now show instance) ---
        print(f"\n  4. get_mrp_sub_ring() — verify instance exists...")
        try:
            result = device.get_mrp_sub_ring()
            print(f"     enabled:        {result.get('enabled')}")
            print(f"     instances:      {len(result.get('instances', []))}")
            for inst in result.get('instances', []):
                print(f"       ring_id={inst['ring_id']} mode={inst['mode']} "
                      f"mode_actual={inst['mode_actual']} vlan={inst['vlan']} "
                      f"port={inst['port']} port_state={inst['port_state']} "
                      f"ring_state={inst['ring_state']} redundancy={inst['redundancy']} "
                      f"info={inst['info']} domain_id={inst['domain_id']} "
                      f"partner_mac={inst['partner_mac']} name={inst['name']}")
            if result.get('instances'):
                print(f"     [OK] instance visible")
            else:
                print(f"     [WARN] no instances after create — check MIB node names")
        except Exception as e:
            print(f"     [FAIL] {e}")
            if debug:
                traceback.print_exc()

        # --- 5. delete_mrp_sub_ring (instance) ---
        print(f"\n  5. delete_mrp_sub_ring(ring_id=1)...")
        try:
            result = device.delete_mrp_sub_ring(ring_id=1)
            print(f"     instances:      {len(result.get('instances', []))}")
            if not result.get('instances'):
                print(f"     [OK] instance deleted")
            else:
                print(f"     [WARN] instance still present after delete")
        except Exception as e:
            print(f"     [FAIL] {e}")
            if debug:
                traceback.print_exc()

        # --- 6. delete_mrp_sub_ring (global disable) ---
        print(f"\n  6. delete_mrp_sub_ring(ring_id=None) — global disable...")
        try:
            result = device.delete_mrp_sub_ring(ring_id=None)
            print(f"     enabled:        {result.get('enabled')}")
            if not result.get('enabled'):
                print(f"     [OK] global disable works")
            else:
                print(f"     [WARN] still enabled after global disable")
        except Exception as e:
            print(f"     [FAIL] {e}")
            if debug:
                traceback.print_exc()

    finally:
        device.close()


def main():
    parser = argparse.ArgumentParser(description='Live SRM test')
    parser.add_argument('--protocol', default='mops', choices=['mops', 'snmp', 'ssh'],
                        help='Protocol to test (default: mops)')
    parser.add_argument('--debug', action='store_true',
                        help='Print full tracebacks')
    parser.add_argument('-d', '--device', help='Test single device IP')
    args = parser.parse_args()

    devices = DEVICES
    if args.device:
        if args.device in DEVICES:
            devices = {args.device: DEVICES[args.device]}
        else:
            devices = {args.device: '??'}

    print(f"\nSRM Live Test — protocol={args.protocol}")
    print(f"Devices: {', '.join(f'{ip} [{sw}]' for ip, sw in devices.items())}")

    for ip, sw_level in devices.items():
        try:
            test_device(ip, sw_level, args.protocol, args.debug)
        except Exception as e:
            print(f"\n  [{ip}] FATAL: {e}")
            if args.debug:
                traceback.print_exc()

    print(f"\n{'='*60}")
    print("  Done")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()
