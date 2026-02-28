"""
clamp — Configure MRP rings across multiple HiOS switches.

Reads a script.cfg file with global defaults and per-device overrides,
configures MRP on each device in parallel, verifies ring health on the
manager, configures edge protection, and optionally saves configs.

Edge protection strategies:
  loop       — Loop protection (default, recommended). Passive on ring,
               active on edge. Auto-disable timer. Catches cross-ring loops.
  rstp-full  — BPDU Guard + admin edge + auto-disable. RSTP stays on,
               ring ports RSTP off. Catches cross-ring loops via BPDUs.
  rstp       — Legacy per-port RSTP disable on ring ports only. Minimal
               protection — blind to loops that traverse the MRP ring.

Usage:
    python clamp.py
    python clamp.py -c my_ring.cfg
    python clamp.py --edge rstp-full
    python clamp.py --migrate-edge rstp-full
    python clamp.py --migrate-edge rstp
    python clamp.py --debug
    python clamp.py --dry-run
"""

import sys
import os
import logging
import ipaddress
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

EDGE_MODES = ('loop', 'rstp-full', 'rstp')


def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), relative_path)
    return os.path.abspath(relative_path)


def log_print(msg: str):
    """Print to console and log to file simultaneously."""
    print(msg)
    logging.info(msg)


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
    parser.add_argument('--edge', choices=EDGE_MODES,
                        help='Edge protection strategy (overrides config)')
    parser.add_argument('--migrate-edge', nargs='?', const='auto',
                        metavar='MODE', default=None,
                        help='Migrate edge strategy (auto-toggles, or specify: loop, rstp-full, rstp)')
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
        'edge_protection': 'rstp-full',
        'auto_disable_timer': None,
        'force': False,
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
            elif line.startswith('edge_protection '):
                val = line.split(None, 1)[1].lower().strip()
                if val in EDGE_MODES:
                    config['edge_protection'] = val
                else:
                    logging.warning(f"Line {line_num}: unknown edge_protection '{val}', using 'loop'")
            elif line.startswith('auto_disable_timer '):
                config['auto_disable_timer'] = int(line.split(None, 1)[1])
            elif line.startswith('force '):
                config['force'] = line.split(None, 1)[1].lower() in ('true', 'yes', '1')
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

    # Mode-aware auto-disable timer default (if not explicitly set in config)
    if config['auto_disable_timer'] is None:
        if config['edge_protection'] == 'loop':
            config['auto_disable_timer'] = 0   # kill and stay dead
        else:
            config['auto_disable_timer'] = 30  # recover + BPDU Guard catches instantly

    return config


def edge_str(config: dict) -> str:
    """Human-readable edge protection description for banners."""
    mode = config['edge_protection']
    timer = config['auto_disable_timer']
    if mode == 'loop':
        return f"Loop Protection (timer={timer}s)" if timer else "Loop Protection (no auto-recovery)"
    elif mode == 'rstp-full':
        return f"RSTP Full (BPDU Guard + Edge + timer={timer}s)" if timer else "RSTP Full (BPDU Guard + Edge)"
    else:
        return "RSTP (per-port disable on ring ports)"


def print_plan(config: dict):
    """Print the deployment plan."""
    print("\n" + "=" * 60)
    print("  MRP DEPLOYMENT PLAN")
    print("=" * 60)
    print(f"  Protocol:        {config['protocol'].upper()}")
    print(f"  VLAN:            {config['vlan']}")
    print(f"  Recovery delay:  {config['recovery_delay']}")
    print(f"  Edge protection: {edge_str(config)}")
    print(f"  Save to NVM:     {'Yes (after ring verified)' if config['save'] else 'No (RAM only)'}")
    print(f"  Devices:         {len(config['devices'])}")
    print("-" * 60)

    for i, dev in enumerate(config['devices'], 1):
        role_str = "MANAGER" if dev['role'] == 'manager' else "client"
        print(f"  {i}. {dev['ip']:20s}  {dev['port1']} + {dev['port2']}  [{role_str}]")

    print("=" * 60)
    print()


# ---------------------------------------------------------------------------
# Utility: extract SW level from get_facts()
# ---------------------------------------------------------------------------

def get_sw_level(facts: dict) -> str:
    """Extract SW level string (L2S, L2A, L3S, etc.) from facts.

    os_version format: 'HiOS-2A-10.3.04' where '2A' maps to L2A.
    """
    os_ver = facts.get('os_version', '')
    # Match the level code after 'HiOS-' (e.g. '2A', '2S', '3S', '3A')
    for code, level in [('3A', 'L3A'), ('3S', 'L3S'), ('2A', 'L2A'), ('2E', 'L2E'), ('2S', 'L2S')]:
        if f'-{code}-' in os_ver or os_ver.endswith(f'-{code}'):
            return level
    return 'unknown'


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


def worker_gather_facts(device, dev, is_l2s_possible=True):
    """Thread worker: gather current state from one device.

    Returns: (ip, facts_dict, error_str)
    facts_dict has keys: sw_level, mrp, rstp, auto_disable, loop_protection, all_ports
    """
    ip = dev['ip']
    result = {
        'sw_level': 'unknown',
        'mrp': None,
        'rstp': None,
        'auto_disable': None,
        'loop_protection': None,
        'all_ports': [],
        'interfaces': {},
    }
    try:
        facts = device.get_facts()
        result['sw_level'] = get_sw_level(facts)
        is_l2s = result['sw_level'] == 'L2S'

        result['mrp'] = device.get_mrp()
        result['rstp'] = device.get_rstp()

        if not is_l2s:
            try:
                result['auto_disable'] = device.get_auto_disable()
            except Exception as e:
                logging.warning(f"[{ip}] get_auto_disable failed: {e}")

            try:
                result['loop_protection'] = device.get_loop_protection()
            except Exception as e:
                logging.warning(f"[{ip}] get_loop_protection failed: {e}")

        # Get interface states (needed for ring port up/down check + all_ports list)
        try:
            result['interfaces'] = device.get_interfaces()
        except Exception as e:
            logging.warning(f"[{ip}] get_interfaces failed: {e}")

        # Build all_ports list from loop_protection interfaces or get_interfaces
        if result['loop_protection'] and result['loop_protection'].get('interfaces'):
            result['all_ports'] = sorted(result['loop_protection']['interfaces'].keys())
        elif result['interfaces']:
            result['all_ports'] = sorted(result['interfaces'].keys())
        else:
            result['all_ports'] = []

        return ip, result, None

    except Exception as e:
        return ip, result, str(e)


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


# -- RSTP workers --

def worker_disable_rstp(device, dev):
    """Thread worker: disable RSTP on ring ports for one device."""
    ip = dev['ip']
    try:
        for port in [dev['port1'], dev['port2']]:
            device.set_rstp_port(port, enabled=False)
        return ip, True, "RSTP disabled on ring ports"
    except (AttributeError, NotImplementedError):
        return ip, False, "set_rstp_port not available"
    except Exception as e:
        return ip, False, str(e)


def worker_disable_rstp_global(device, dev):
    """Thread worker: disable RSTP globally on one device."""
    ip = dev['ip']
    try:
        device.set_rstp(enabled=False)
        return ip, True, "RSTP disabled globally"
    except (AttributeError, NotImplementedError):
        return ip, False, "set_rstp not available"
    except Exception as e:
        return ip, False, str(e)


def worker_enable_rstp_global(device, dev):
    """Thread worker: enable RSTP globally on one device."""
    ip = dev['ip']
    try:
        device.set_rstp(enabled=True)
        return ip, True, "RSTP enabled globally"
    except (AttributeError, NotImplementedError):
        return ip, False, "set_rstp not available"
    except Exception as e:
        return ip, False, str(e)


# -- Loop protection workers --

def worker_setup_loop_protection(device, dev, all_ports, ring_ports):
    """Thread worker: enable loop protection on one device.

    Ring ports get passive mode with action=auto-disable. Detects
    cross-ring loops via keepalives traversing the ring. MRP prio 7
    with strict QoS keeps ring control frames alive during detection.

    Edge ports get active mode with action=auto-disable (detect and
    kill same-switch loops).

    Transmit interval set to 1s (minimum) to minimize storm window.
    """
    ip = dev['ip']
    try:
        # Global enable + fastest detection
        device.set_loop_protection(enabled=True, transmit_interval=1)

        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        # Ring ports: passive + auto-disable on loop detection
        for port in ring_ports:
            device.set_loop_protection(
                interface=port,
                enabled=True,
                mode='passive',
                action='auto-disable',
            )

        # Edge ports: active + auto-disable (detect and kill loops)
        for port in edge_ports:
            device.set_loop_protection(
                interface=port,
                enabled=True,
                mode='active',
                action='auto-disable',
            )

        return ip, True, f"loop protection on {len(edge_ports)} edge + {len(ring_ports)} ring ports (tx=1s)"
    except Exception as e:
        return ip, False, str(e)


def worker_setup_auto_disable(device, dev, all_ports, timer, reason='loop-protection',
                              exclude_ports=None):
    """Thread worker: enable auto-disable for a reason on ports.

    exclude_ports: set of ports to skip (e.g. ring ports for loop-protection
    reason — avoid auto-disable engaging independently of loop prot action).
    """
    ip = dev['ip']
    try:
        device.set_auto_disable_reason(reason, enabled=True)
        exclude = set(exclude_ports) if exclude_ports else set()
        ports = [p for p in all_ports if p not in exclude]
        for port in ports:
            device.set_auto_disable(interface=port, timer=timer)

        return ip, True, f"auto-disable ({reason}) timer={timer}s on {len(ports)} ports"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_loop_protection(device, dev, all_ports):
    """Thread worker: disable loop protection on all ports of one device."""
    ip = dev['ip']
    try:
        for port in all_ports:
            device.set_loop_protection(interface=port, enabled=False)
        device.set_loop_protection(enabled=False)
        return ip, True, f"loop protection disabled on {len(all_ports)} ports"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_auto_disable(device, dev, all_ports, reason='loop-protection'):
    """Thread worker: reset auto-disable for a reason on all ports.

    Also clears any ports still held down by auto-disable (reset_auto_disable).
    """
    ip = dev['ip']
    try:
        for port in all_ports:
            device.set_auto_disable(interface=port, timer=0)
        device.set_auto_disable_reason(reason, enabled=False)

        # Clear any ports still stuck in auto-disabled state
        ad = device.get_auto_disable()
        released = []
        for port, state in ad.get('interfaces', {}).items():
            if state.get('active') and state.get('reason') == reason:
                device.reset_auto_disable(port)
                released.append(port)

        detail = f"auto-disable ({reason}) reset on {len(all_ports)} ports"
        if released:
            detail += f", released {','.join(released)}"
        return ip, True, detail
    except Exception as e:
        return ip, False, str(e)


# -- RSTP-Full workers --

def worker_setup_rstp_full(device, dev, all_ports, ring_ports, timer):
    """Thread worker: set up RSTP Full protection on one device.

    - RSTP off on ring ports (MRP owns them)
    - BPDU Guard on globally
    - Admin edge port on all edge ports
    - Auto-disable reason bpdu-rate enabled
    - Auto-disable timer on all ports
    """
    ip = dev['ip']
    try:
        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        # Disable RSTP on ring ports
        for port in ring_ports:
            device.set_rstp_port(port, enabled=False)

        # Enable BPDU Guard globally
        device.set_rstp(bpdu_guard=True)

        # Force admin edge on all edge ports
        for port in edge_ports:
            device.set_rstp_port(port, edge_port=True)

        # Auto-disable for bpdu-rate
        device.set_auto_disable_reason('bpdu-rate', enabled=True)
        for port in all_ports:
            device.set_auto_disable(interface=port, timer=timer)

        return ip, True, f"RSTP Full on {len(edge_ports)} edge ports, BPDU Guard on, timer={timer}s"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_rstp_full(device, dev, all_ports, ring_ports):
    """Thread worker: tear down RSTP Full protection on one device.

    Reverses: admin edge, BPDU Guard, auto-disable for bpdu-rate,
    releases stuck ports, re-enables RSTP on ring ports.
    """
    ip = dev['ip']
    try:
        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        # Reset auto-disable timers
        for port in all_ports:
            device.set_auto_disable(interface=port, timer=0)
        device.set_auto_disable_reason('bpdu-rate', enabled=False)

        # Clear stuck ports
        ad = device.get_auto_disable()
        released = []
        for port, state in ad.get('interfaces', {}).items():
            if state.get('active') and state.get('reason') == 'bpdu-rate':
                device.reset_auto_disable(port)
                released.append(port)

        # Remove admin edge on edge ports
        for port in edge_ports:
            device.set_rstp_port(port, edge_port=False)

        # Disable BPDU Guard globally
        device.set_rstp(bpdu_guard=False)

        # Re-enable RSTP on ring ports
        for port in ring_ports:
            device.set_rstp_port(port, enabled=True)

        detail = f"RSTP Full torn down on {len(edge_ports)} edge ports"
        if released:
            detail += f", released {','.join(released)}"
        return ip, True, detail
    except Exception as e:
        return ip, False, str(e)


# -- Save worker --

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
    log_print(f"\n  {phase_name}")
    log_print("  " + "-" * 55)
    for ip, success, msg in results:
        tag = "OK" if success else "FAIL"
        log_print(f"  [{tag:4s}] {ip:20s} {msg}")


# ---------------------------------------------------------------------------
# Verify ring health with retries
# ---------------------------------------------------------------------------

def verify_ring(rm_device, max_attempts=3, delay=1):
    """Check ring health on RM with retries.

    Returns: (healthy: bool, ring_state: str, redundancy: bool)
    """
    for attempt in range(1, max_attempts + 1):
        time.sleep(delay)
        mrp = rm_device.get_mrp()
        ring_state = mrp.get('ring_state', 'unknown')
        redundancy = mrp.get('redundancy', False)
        healthy = ring_state == 'closed' and redundancy

        if healthy:
            return True, ring_state, redundancy

        if attempt < max_attempts:
            log_print(f"  Attempt {attempt}/{max_attempts}: ring not ready (state={ring_state}), retrying...")

    return False, ring_state, redundancy


# ---------------------------------------------------------------------------
# L2S safety check
# ---------------------------------------------------------------------------

def check_l2s_safety(config, device_facts, l2s_devices):
    """Abort if edge protection mode requires L2A+ and L2S devices are present.

    Only 'loop' mode requires L2A+ (loop protection + auto-disable).
    'rstp-full' works on L2S (BPDU Guard + admin edge are RSTP features).
    'rstp' works on L2S.
    """
    mode = config['edge_protection']
    if mode != 'loop':
        return True  # rstp and rstp-full work on L2S

    if not l2s_devices:
        return True

    if config['force']:
        log_print(f"\n  WARNING: {len(l2s_devices)} L2S device(s) detected — skipping loop protection on them (force=true)")
        return True

    log_print("")
    log_print("  FATAL: Loop Protection requested but these devices are L2S")
    log_print("  and do not support Loop Protection or Auto-Disable:")
    log_print("")
    for lip in l2s_devices:
        sw = device_facts[lip]['sw_level']
        log_print(f"    {lip:22s} [{sw}]")
    log_print("")
    log_print("  Options:")
    log_print("    1. Use 'edge_protection rstp-full' (BPDU Guard — works on L2S)")
    log_print("    2. Upgrade firmware on L2S devices to L2A or higher")
    log_print("    3. Add 'force true' to config to proceed anyway (partial protection)")
    log_print("")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Phase 0: Gather facts (shared between deploy/migrate)
# ---------------------------------------------------------------------------

def rm_ring_needs_breaking(device_facts, rm_dev):
    """Check if RM ring ports are both up (ring formed → needs breaking).

    Returns True only if both ring ports are link-up. If either or both
    are down, the ring is already broken (or never formed) — no safety
    gate needed.
    """
    rm_facts = device_facts.get(rm_dev['ip'], {})
    interfaces = rm_facts.get('interfaces', {})
    if not interfaces:
        return True  # can't tell — be safe, assume ring is up
    p1_up = interfaces.get(rm_dev['port1'], {}).get('is_up', False)
    p2_up = interfaces.get(rm_dev['port2'], {}).get('is_up', False)
    return p1_up and p2_up


def run_phase0(config, connections):
    """Gather facts from all devices. Returns (device_facts, l2s_devices)."""
    log_print("\n  Phase 0: Gathering current state...")
    device_facts = {}
    l2s_devices = []

    with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
        futures = {}
        for dev in config['devices']:
            device = connections.get(dev['ip'])
            if device:
                futures[pool.submit(worker_gather_facts, device, dev)] = dev

        for future in as_completed(futures):
            ip, facts, err = future.result()
            device_facts[ip] = facts
            if err:
                logging.warning(f"[{ip}] gather_facts partial failure: {err}")

    log_print("\n  Phase 0: Current State")
    log_print("  " + "-" * 55)
    for dev in config['devices']:
        ip = dev['ip']
        if ip not in device_facts:
            log_print(f"  {ip:22s} [no connection]")
            continue
        facts = device_facts[ip]
        sw = facts['sw_level']
        mrp_state = 'none'
        if facts['mrp'] and facts['mrp'].get('configured'):
            mrp_state = facts['mrp'].get('operation', 'unknown')
        rstp_state = 'unknown'
        if facts['rstp']:
            rstp_state = 'on' if facts['rstp'].get('enabled') else 'off'
        lp_state = '?'
        if facts['loop_protection'] is not None:
            lp_state = 'on' if facts['loop_protection'].get('enabled') else 'off'
        bg_state = '?'
        if facts['rstp']:
            bg_state = 'on' if facts['rstp'].get('bpdu_guard') else 'off'
        role_tag = 'RM' if dev['role'] == 'manager' else 'RC'
        log_print(f"  {ip:22s} [{sw}] MRP={mrp_state}, RSTP={rstp_state}, LP={lp_state}, BG={bg_state}  ({role_tag})")

        if sw == 'L2S':
            l2s_devices.append(ip)

    return device_facts, l2s_devices


# ---------------------------------------------------------------------------
# Phase 3: Deploy edge protection
# ---------------------------------------------------------------------------

def deploy_edge_protection(config, connections, device_facts, l2s_devices):
    """Deploy edge protection based on config['edge_protection']."""
    mode = config['edge_protection']
    timer = config['auto_disable_timer']

    if mode == 'rstp':
        # Legacy: just disable RSTP on ring ports
        log_print("\n  Phase 3: Disabling RSTP on ring ports...")
        results = []
        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {}
            for dev in config['devices']:
                device = connections.get(dev['ip'])
                if device:
                    futures[pool.submit(worker_disable_rstp, device, dev)] = dev
            for future in as_completed(futures):
                results.append(future.result())

        failures = [r for r in results if not r[1]]
        if failures:
            for ip, _, detail in failures:
                logging.warning(f"[{ip}] {detail}")
            log_print(f"  RSTP: {len(failures)} device(s) need manual RSTP disable")
        else:
            log_print("  RSTP: disabled on all ring ports")

    elif mode == 'loop':
        # Phase 3a: Disable RSTP globally
        log_print("\n  Phase 3a: Disabling RSTP globally...")
        rstp_results = []
        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {}
            for dev in config['devices']:
                device = connections.get(dev['ip'])
                if device:
                    futures[pool.submit(worker_disable_rstp_global, device, dev)] = dev
            for future in as_completed(futures):
                rstp_results.append(future.result())
        print_results("Phase 3a — RSTP (global off)", rstp_results)

        # Phase 3b: Loop protection
        log_print("\n  Phase 3b: Enabling loop protection...")
        lp_results = []
        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {}
            for dev in config['devices']:
                ip = dev['ip']
                device = connections.get(ip)
                if not device:
                    continue
                if ip in l2s_devices:
                    lp_results.append((ip, False, "L2S — skipped"))
                    continue
                all_ports = device_facts.get(ip, {}).get('all_ports', [])
                ring_ports = [dev['port1'], dev['port2']]
                futures[pool.submit(
                    worker_setup_loop_protection, device, dev, all_ports, ring_ports
                )] = dev
            for future in as_completed(futures):
                lp_results.append(future.result())
        print_results("Phase 3b — Loop Protection", lp_results)

        # Phase 3c: Auto-disable
        if timer > 0:
            log_print(f"\n  Phase 3c: Enabling auto-disable (timer={timer}s)...")
            ad_results = []
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
                        worker_setup_auto_disable, device, dev, all_ports, timer,
                        'loop-protection'
                    )] = dev
                for future in as_completed(futures):
                    ad_results.append(future.result())
            print_results("Phase 3c — Auto-Disable", ad_results)
        else:
            log_print("\n  Phase 3c: Skipped (auto_disable_timer=0)")

    elif mode == 'rstp-full':
        # RSTP Full: BPDU Guard + admin edge + auto-disable (works on L2S)
        log_print("\n  Phase 3: Setting up RSTP Full protection...")
        results = []
        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {}
            for dev in config['devices']:
                ip = dev['ip']
                device = connections.get(ip)
                if not device:
                    continue
                all_ports = device_facts.get(ip, {}).get('all_ports', [])
                ring_ports = [dev['port1'], dev['port2']]
                futures[pool.submit(
                    worker_setup_rstp_full, device, dev, all_ports, ring_ports, timer
                )] = dev
            for future in as_completed(futures):
                results.append(future.result())
        print_results("Phase 3 — RSTP Full", results)


# ---------------------------------------------------------------------------
# Main deploy flow
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    # Logging setup
    log_dir = os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(),
        'logs'
    )
    os.makedirs(log_dir, exist_ok=True)
    log_filename = os.path.join(log_dir, f'clamp_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

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

        # CLI override
        if args.edge:
            config['edge_protection'] = args.edge

        # Route to migrate-edge mode if requested
        if args.migrate_edge is not None:
            if args.migrate_edge != 'auto' and args.migrate_edge not in EDGE_MODES:
                log_print(f"\n  FATAL: Unknown edge mode '{args.migrate_edge}'. Use: {', '.join(EDGE_MODES)}\n")
                sys.exit(1)
            config['edge_protection'] = args.migrate_edge
            return run_migrate_edge(args, config, log_filename)

        print_plan(config)

        if args.dry_run:
            log_print("  [DRY RUN] No changes will be made.\n")
            return

        from napalm import get_network_driver
        driver = get_network_driver('hios')

        # --- Connect all devices in parallel ---
        log_print("  Connecting...")
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

            # L2S safety check
            check_l2s_safety(config, device_facts, l2s_devices)

            # --- Phase 1: Disable RM port2 (break ring before configuring) ---
            broke_ring = rm_ring_needs_breaking(device_facts, rm_dev)
            if broke_ring:
                log_print(f"\n  Phase 1: Disabling RM port2 ({rm_dev['port2']}) on {rm_ip}...")
                try:
                    rm_device.set_interface(rm_dev['port2'], enabled=False)
                    log_print(f"  [{rm_ip}] port {rm_dev['port2']} admin DOWN")
                except Exception as e:
                    log_print(f"  FATAL: Cannot disable RM port2: {e}\n")
                    sys.exit(1)
            else:
                log_print(f"\n  Phase 1: Skipped (ring ports not both up — no ring to break)")

            # --- Phase 2: Configure MRP in parallel ---
            log_print("\n  Phase 2: Configuring MRP...")
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
                    role = [d for d in config['devices'] if d['ip'] == ip][0]['role']
                    mrp_results.append((ip, ok, f"MRP {role}, {detail}"))

            print_results("Phase 2 — MRP Configuration", mrp_results)

            failures = [r for r in mrp_results if not r[1]]
            if failures:
                log_print(f"\n  {len(failures)} device(s) failed.")
                log_print(f"  Re-enabling RM port2 ({rm_dev['port2']})...")
                try:
                    rm_device.set_interface(rm_dev['port2'], enabled=True)
                except Exception:
                    pass
                log_print("  Configs NOT saved — power cycle to rollback.\n")
                sys.exit(1)

            # --- Phase 3: Edge protection ---
            deploy_edge_protection(config, connections, device_facts, l2s_devices)

            # --- Phase 4: Enable RM port2 (close the ring) ---
            # Wait for RSTP hello timeout (2s) so edge protection settles
            # before the ring closes. Admin-down doesn't trigger L1 link-loss
            # — neighbors need hello time to process the topology change.
            if broke_ring:
                time.sleep(2)
                log_print(f"\n  Phase 4: Clamping ring closed — RM port2 ({rm_dev['port2']}) on {rm_ip}...")
                try:
                    rm_device.set_interface(rm_dev['port2'], enabled=True)
                    log_print(f"  [{rm_ip}] port {rm_dev['port2']} admin UP — ring clamped")
                except Exception as e:
                    log_print(f"  WARNING: Cannot re-enable RM port2: {e}")
            else:
                log_print("\n  Phase 4: Skipped (ring was not broken in Phase 1)")

            # --- Phase 5: Verify ring on manager (3x retry) ---
            log_print("\n  Phase 5: Verifying ring...")
            healthy, ring_state, redundancy = verify_ring(rm_device, max_attempts=3, delay=1)

            status_tag = "HEALTHY" if healthy else "UNHEALTHY"
            log_print(f"  Ring: [{status_tag}] state={ring_state}, redundancy={redundancy}")

            if not healthy:
                log_print("\n  Ring NOT healthy. Configs NOT saved — power cycle to rollback.\n")
                sys.exit(1)

            # --- Phase 6: Save ---
            if config['save']:
                log_print("\n  Phase 6: Saving configs...")
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

                print_results("Phase 6 — Config Save", save_results)

                save_failures = [r for r in save_results if not r[1]]
                if save_failures:
                    log_print(f"\n  WARNING: {len(save_failures)} device(s) failed to save.")
            else:
                log_print("\n  Phase 6: Skipped (save=false)")
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

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        log_print(f"\n  FATAL: {e}\n")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Migrate edge protection on existing MRP ring
# ---------------------------------------------------------------------------

def run_migrate_edge(args, config, log_filename):
    """Migrate edge protection strategy on an existing MRP ring.

    --migrate-edge loop:      current → loop protection
    --migrate-edge rstp-full: current → RSTP Full
    --migrate-edge rstp:      current → RSTP legacy

    Safety: new protection goes up before old comes down.
    """
    target = config['edge_protection']

    target_str = "Auto-detect (toggle)" if target == 'auto' else edge_str(config)

    print("\n" + "=" * 60)
    print("  MRP EDGE PROTECTION MIGRATION")
    print("=" * 60)
    print(f"  Target:          {target_str}")
    print(f"  Protocol:        {config['protocol'].upper()}")
    print(f"  Save to NVM:     {'Yes' if config['save'] else 'No (RAM only)'}")
    print(f"  Devices:         {len(config['devices'])}")
    print("-" * 60)
    for i, dev in enumerate(config['devices'], 1):
        role_str = "MANAGER" if dev['role'] == 'manager' else "client"
        print(f"  {i}. {dev['ip']:20s}  {dev['port1']} + {dev['port2']}  [{role_str}]")
    print("=" * 60)
    print()

    if args.dry_run:
        log_print("  [DRY RUN] No changes will be made.\n")
        return

    from napalm import get_network_driver
    driver = get_network_driver('hios')

    start_time = time.time()

    # Connect
    log_print("  Connecting...")
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

        if not rm_device:
            log_print(f"\n  FATAL: No connection to ring manager {rm_ip}\n")
            sys.exit(1)

        # Phase 0: Gather facts
        device_facts, l2s_devices = run_phase0(config, connections)

        # Verify MRP is configured
        rm_facts = device_facts.get(rm_ip, {})
        rm_mrp = rm_facts.get('mrp', {})
        if not rm_mrp or not rm_mrp.get('configured'):
            log_print("\n  FATAL: MRP is not configured on the ring manager.")
            log_print("  Migration requires an existing MRP deployment. Use clamp.py instead.\n")
            sys.exit(1)

        # Detect current edge protection state
        has_loop_prot = any(
            f.get('loop_protection', {}).get('enabled', False) if f.get('loop_protection') else False
            for f in device_facts.values()
        )
        has_bpdu_guard = any(
            f.get('rstp', {}).get('bpdu_guard', False) if f.get('rstp') else False
            for f in device_facts.values()
        )

        # Auto-detect target: toggle to the other strategy
        if target == 'auto':
            if has_loop_prot:
                target = 'rstp-full'  # loop → rstp-full
                log_print("\n  Detected: Loop Protection → migrating to RSTP Full")
            elif has_bpdu_guard:
                target = 'loop'       # rstp-full → loop
                log_print("\n  Detected: RSTP Full → migrating to Loop Protection")
            else:
                target = 'loop'       # no edge protection → deploy loop
                log_print("\n  Detected: No edge protection — deploying Loop Protection")
            config['edge_protection'] = target

        # L2S safety check
        check_l2s_safety(config, device_facts, l2s_devices)

        timer = config['auto_disable_timer']

        # Phase 1: Deploy NEW protection first
        log_print("\n  Phase 1: Deploying new edge protection...")

        if target == 'loop':
            # Deploy loop protection
            lp_results = []
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
                        worker_setup_loop_protection, device, dev, all_ports, ring_ports
                    )] = dev
                for future in as_completed(futures):
                    lp_results.append(future.result())
            print_results("Phase 1a — Loop Protection", lp_results)

            if timer > 0:
                ad_results = []
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
                            worker_setup_auto_disable, device, dev, all_ports, timer,
                            'loop-protection'
                        )] = dev
                    for future in as_completed(futures):
                        ad_results.append(future.result())
                print_results("Phase 1b — Auto-Disable (loop-protection)", ad_results)

            # Then disable RSTP globally
            log_print("\n  Disabling RSTP globally...")
            rstp_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_disable_rstp_global, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_results.append(future.result())
            print_results("RSTP Disable (global)", rstp_results)

        elif target == 'rstp-full':
            # Deploy RSTP Full (BPDU Guard goes on, ring ports RSTP off, edge ports get admin edge)
            results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    ip = dev['ip']
                    device = connections.get(ip)
                    if not device:
                        continue
                    all_ports = device_facts.get(ip, {}).get('all_ports', [])
                    ring_ports = [dev['port1'], dev['port2']]
                    futures[pool.submit(
                        worker_setup_rstp_full, device, dev, all_ports, ring_ports, timer
                    )] = dev
                for future in as_completed(futures):
                    results.append(future.result())
            print_results("Phase 1 — RSTP Full", results)

            # Ensure RSTP is on globally (it should be, but be explicit)
            rstp_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_enable_rstp_global, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_results.append(future.result())
            print_results("RSTP Global Enable", rstp_results)

        elif target == 'rstp':
            # Enable RSTP globally first, then disable on ring ports
            rstp_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_enable_rstp_global, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_results.append(future.result())
            print_results("Phase 1a — RSTP Global Enable", rstp_results)

            rstp_ring_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_disable_rstp, device, dev)] = dev
                for future in as_completed(futures):
                    rstp_ring_results.append(future.result())
            print_results("Phase 1b — RSTP Ring Ports Off", rstp_ring_results)

        # Wait for RSTP to settle if we just deployed an RSTP-based strategy.
        # Admin-state changes don't trigger L1 link-loss — neighbors need
        # hello timeout (2s) to process BPDUs before we tear down old protection.
        if target in ('rstp-full', 'rstp'):
            time.sleep(2)

        # Phase 2: Tear down OLD protection
        log_print("\n  Phase 2: Tearing down old edge protection...")

        if has_loop_prot and target != 'loop':
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
                print_results("Auto-Disable Teardown (loop-protection)", ad_results)

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
                print_results("Loop Protection Teardown", lp_results)

        if has_bpdu_guard and target != 'rstp-full':
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
                print_results("RSTP Full Teardown", results)

        if not has_loop_prot and not has_bpdu_guard:
            log_print("  No old edge protection detected to tear down")

        # Phase 3: Verify ring
        log_print("\n  Phase 3: Verifying ring...")
        healthy, ring_state, redundancy = verify_ring(rm_device, max_attempts=3, delay=1)

        status_tag = "HEALTHY" if healthy else "UNHEALTHY"
        log_print(f"  Ring: [{status_tag}] state={ring_state}, redundancy={redundancy}")

        if not healthy:
            log_print("\n  WARNING: Ring not healthy after migration. Check manually.\n")

        # Phase 4: Save
        if config['save']:
            log_print("\n  Phase 4: Saving configs...")
            save_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(worker_save, device, dev)] = dev
                for future in as_completed(futures):
                    save_results.append(future.result())
            print_results("Phase 4 — Config Save", save_results)
        else:
            log_print("\n  Phase 4: Skipped (save=false)")
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


if __name__ == "__main__":
    main()
