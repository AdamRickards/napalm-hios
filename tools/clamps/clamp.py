"""
clamp — Configure MRP rings across multiple HiOS switches.

Reads a script.cfg file with global defaults and per-device overrides,
configures MRP on each device in parallel, verifies ring health on the
manager, configures edge protection, and optionally saves configs.

Supports live (MOPS/SNMP/SSH) and offline (config XML files) modes.
Offline mode auto-detected from .xml device paths in script.cfg.

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
import re
import csv
import logging
import ipaddress
import argparse
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

EDGE_MODES = ('loop', 'rstp-full', 'rstp')

PROTECTION_CSV_HEADERS = [
    'device_ip', 'hostname', 'port',
    'rstp_enabled', 'rstp_edge', 'rstp_auto_edge', 'rstp_priority', 'rstp_path_cost',
    'rstp_root_guard', 'rstp_loop_guard', 'rstp_tcn_guard', 'rstp_bpdu_filter', 'rstp_bpdu_flood',
    'loop_enabled', 'loop_mode', 'loop_action',
    'storm_unit', 'storm_bc_enabled', 'storm_bc_threshold',
    'storm_mc_enabled', 'storm_mc_threshold',
    'storm_uc_enabled', 'storm_uc_threshold',
    'auto_disable_timer',
]


def natural_sort_key(interface: str):
    """Sort key that handles '1/1', '1/10', '2/3' naturally."""
    return [int(x) if x.isdigit() else x for x in re.split(r'(\d+)', interface)]


def is_switchport(p):
    """Filter out non-switchports (cpu/, vlan/)."""
    return not (p.startswith('cpu/') or p.startswith('vlan/'))


def get_resource_path(relative_path: str) -> str:
    """Get absolute path to resource, works for dev and for PyInstaller."""
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(sys.executable), relative_path)
    return os.path.abspath(relative_path)


def log_print(msg: str):
    """Print to console and log to file simultaneously."""
    print(msg)
    logging.info(msg)


def log_device_state_json(label, device_facts):
    """Dump full device state to logfile as JSON (not console)."""
    def _json_default(obj):
        if isinstance(obj, set):
            return sorted(obj)
        return str(obj)
    logging.info(f"--- {label} ---")
    for ip, facts in sorted(device_facts.items()):
        logging.info(f"[{ip}] {label}: {json.dumps(facts, default=_json_default, indent=2)}")


def interactive_mode():
    """80s warez-patcher-style guided wizard for CLAMPS."""
    import subprocess

    # ANSI
    CY = '\033[36m'; MG = '\033[35m'; YL = '\033[33m'
    GR = '\033[32m'; BD = '\033[1m'; DM = '\033[2m'; RS = '\033[0m'

    def cls():
        print('\033[2J\033[H', end='', flush=True)

    def banner():
        print(f"""
  {MG}{BD}╔═╗╦  ╔═╗╔╦╗╔═╗╔═╗{RS}
  {MG}{BD}║  ║  ╠═╣║║║╠═╝╚═╗{RS}
  {MG}{BD}╚═╝╩═╝╩ ╩╩ ╩╩  ╚═╝{RS}
  {DM}Configuration of Loops, Access, MRP, Protection, and Sub-rings{RS}
  {CY}{'━' * 62}{RS}
""")

    def step(title):
        cls()
        banner()
        print(f'  {BD}{title}{RS}\n')

    def pick(text, options, default=1):
        for i, (label, _) in enumerate(options, 1):
            mark = f'{YL}▸{RS}' if i == default else ' '
            print(f'  {mark} {CY}{i}{RS}) {label}')
        print()
        while True:
            raw = input(f'  {GR}▸{RS} {text} [{default}]: ').strip()
            if not raw:
                return options[default - 1][1]
            try:
                idx = int(raw)
                if 1 <= idx <= len(options):
                    return options[idx - 1][1]
            except ValueError:
                pass
            print(f'  {YL}Pick 1–{len(options)}{RS}')

    def ask(text, default=''):
        hint = f' {DM}[{default}]{RS}' if default else ''
        return input(f'  {GR}▸{RS} {text}{hint}: ').strip() or default

    def yesno(text, default=False):
        hint = 'Y/n' if default else 'y/N'
        val = input(f'  {GR}▸{RS} {text} {DM}[{hint}]{RS}: ').strip().lower()
        return val in ('y', 'yes') if val else default

    try:
        # ── Mode picker ──
        step('MODE')
        mode = pick('What do you want to do?', [
            ('Deploy MRP ring',              'deploy'),
            ('Export protection config',     'export'),
            ('Import protection config',     'import'),
        ])

        if mode in ('export', 'import'):
            # Simplified flow — just devices, credentials, filename
            step('DEVICES')
            print(f'  {DM}Enter device IPs (comma-separated, range, or CIDR).{RS}\n')
            raw = ask('Device IPs')
            if not raw:
                print(f'\n  {YL}No devices. Exiting.{RS}\n')
                return
            devices = []
            for part in raw.split(','):
                part = part.strip()
                if part.endswith('.xml'):
                    devices.append(part)
                elif is_valid_ipv4(part):
                    devices.append(part)
                elif '-' in part.split('.')[-1]:
                    # Last-octet range: 192.168.1.80-85
                    base = '.'.join(part.split('.')[:-1])
                    last = part.split('.')[-1]
                    lo, hi = last.split('-')
                    for i in range(int(lo), int(hi) + 1):
                        devices.append(f'{base}.{i}')
                else:
                    try:
                        net = ipaddress.ip_network(part, strict=False)
                        devices.extend(str(h) for h in net.hosts())
                    except ValueError:
                        print(f'  {YL}Skipping invalid: {part}{RS}')
            if not devices:
                print(f'\n  {YL}No valid devices. Exiting.{RS}\n')
                return

            is_offline = any(d.endswith('.xml') for d in devices)
            if is_offline:
                protocol = 'offline'
                username = ''
                password = ''
                print(f'\n  {DM}Offline mode — no credentials needed.{RS}\n')
            else:
                step('CREDENTIALS')
                username = ask('Username', 'admin')
                password = ask('Password', 'private')
                protocol = pick('Protocol', [
                    ('MOPS — HTTPS, atomic writes (recommended)', 'mops'),
                    ('SNMP — SNMPv3, no session state', 'snmp'),
                    ('SSH — CLI parsing', 'ssh'),
                ])

            step('EXPORT' if mode == 'export' else 'IMPORT')
            default_file = 'protection.csv'
            filepath = ask('CSV file path', default_file)

            # Build minimal config and shell out
            cfg_lines = []
            if not is_offline:
                cfg_lines.append(f'username {username}')
                cfg_lines.append(f'password {password}')
            cfg_lines.append(f'protocol {protocol}')
            # Dummy ring settings (required by parse_config but unused for export/import)
            cfg_lines.append('port1 1/1')
            cfg_lines.append('port2 1/2')
            cfg_lines.append('vlan 1')
            cfg_lines.append('edge_protection rstp-full')
            cfg_lines.append('')
            for ip in devices:
                cfg_lines.append(ip)

            tmp_cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.interactive.cfg')
            with open(tmp_cfg, 'w') as f:
                f.write('\n'.join(cfg_lines) + '\n')

            flag = '--export' if mode == 'export' else '--import'
            cmd = [sys.executable, os.path.abspath(__file__), '-c', tmp_cfg, flag, filepath]

            if mode == 'import':
                action = pick('Go', [
                    ('Dry run — preview only', 'dry'),
                    ('Apply changes',          'live'),
                    ('Quit',                   'quit'),
                ])
                if action == 'quit':
                    try:
                        os.remove(tmp_cfg)
                    except OSError:
                        pass
                    return
                if action == 'dry':
                    cmd.append('--dry-run')
                    print()
                    subprocess.run(cmd)
                    print()
                    if not yesno('Apply changes?'):
                        try:
                            os.remove(tmp_cfg)
                        except OSError:
                            pass
                        print(f'\n  {DM}Done.{RS}\n')
                        return
                    # Run live
                    cmd = [sys.executable, os.path.abspath(__file__), '-c', tmp_cfg, flag, filepath]
                    if yesno('Save to NVM after applying?'):
                        cmd.append('--save')

            print()
            subprocess.run(cmd)

            try:
                os.remove(tmp_cfg)
            except OSError:
                pass
            print(f'\n  {DM}Done.{RS}\n')
            return

        # ── 1. Main ring devices ──
        step('STEP 1 ─── MAIN RING DEVICES')
        print(f'  {DM}Enter devices one at a time. First device = Ring Manager by default.{RS}')
        print(f'  {DM}Default ring ports: 1/5 + 1/6. Override per device if needed.{RS}\n')

        default_p1 = ask('Default ring port 1', '1/5')
        default_p2 = ask('Default ring port 2', '1/6')
        print()

        main_devices = []
        while True:
            ip = ask(f'Device IP (enter to finish)' if main_devices else 'Ring Manager IP')
            if not ip:
                if len(main_devices) < 2:
                    print(f'  {YL}Need at least 2 devices for a ring.{RS}')
                    continue
                break
            if not (is_valid_ipv4(ip) or ip.endswith('.xml')):
                print(f'  {YL}Invalid IP or XML path.{RS}')
                continue

            p1 = ask(f'  Ports for {ip}', f'{default_p1} {default_p2}')
            ports = p1.split()
            port1 = ports[0] if len(ports) >= 1 else default_p1
            port2 = ports[1] if len(ports) >= 2 else default_p2

            role = 'manager' if not main_devices else 'client'
            main_devices.append({'ip': ip, 'port1': port1, 'port2': port2, 'role': role})
            tag = f' {YL}[RM]{RS}' if role == 'manager' else ''
            print(f'  {GR}+{RS} {ip} {port1} ↔ {port2}{tag}\n')

        # Auto-detect offline from .xml devices
        is_offline = any(d['ip'].endswith('.xml') for d in main_devices)

        # ── 2. Credentials ──
        if is_offline:
            protocol = 'offline'
            username = ''
            password = ''
            print(f'\n  {DM}Offline mode — no credentials needed.{RS}\n')
        else:
            step('STEP 2 ─── CREDENTIALS')
            username = ask('Username', 'admin')
            password = ask('Password', 'private')
            protocol = pick('Protocol', [
                ('MOPS — HTTPS, atomic writes (recommended)', 'mops'),
                ('SNMP — SNMPv3, no session state', 'snmp'),
                ('SSH — CLI parsing', 'ssh'),
            ])

        # ── 3. Sub-rings ──
        step('STEP 3 ─── SUB-RINGS')
        print(f'  {DM}Sub-rings branch off the main ring at two points (SRM + RSRM).{RS}')
        print(f'  {DM}Each sub-ring needs its own VLAN and at least the two branch points.{RS}\n')

        sub_rings = []
        while yesno('Add a sub-ring?'):
            print()
            sr_vlan = ask('Sub-ring VLAN ID')

            main_ips = [d['ip'] for d in main_devices]
            print(f'\n  {DM}Main ring devices: {", ".join(main_ips)}{RS}')

            srm_ip = ask('SRM (sub-ring manager) IP')
            srm_port = ask(f'  SRM port on {srm_ip}')

            rsrm_ip = ask('RSRM (redundant sub-ring manager) IP')
            rsrm_port = ask(f'  RSRM port on {rsrm_ip}')

            sr_clients = []
            print(f'\n  {DM}Add sub-ring clients (devices on the sub-ring, not branch points).{RS}')
            while True:
                rc_ip = ask('  RC IP (enter to finish)')
                if not rc_ip:
                    break
                if not (is_valid_ipv4(rc_ip) or rc_ip.endswith('.xml')):
                    print(f'  {YL}Invalid IP or XML path.{RS}')
                    continue
                rc_ports = ask(f'    Ports for {rc_ip}', f'{default_p1} {default_p2}')
                parts = rc_ports.split()
                sr_clients.append({
                    'ip': rc_ip,
                    'port1': parts[0] if len(parts) >= 1 else default_p1,
                    'port2': parts[1] if len(parts) >= 2 else default_p2,
                })
                print(f'  {GR}+{RS} RC {rc_ip}')

            sub_rings.append({
                'vlan': sr_vlan,
                'srm': {'ip': srm_ip, 'port': srm_port},
                'rsrm': {'ip': rsrm_ip, 'port': rsrm_port},
                'clients': sr_clients,
            })
            print(f'\n  {GR}Sub-ring VLAN {sr_vlan}: SRM={srm_ip}:{srm_port} RSRM={rsrm_ip}:{rsrm_port} + {len(sr_clients)} client(s){RS}\n')

        # ── 4. Ring settings ──
        step('STEP 4 ─── RING SETTINGS')
        vlan = ask('Main ring VLAN', '100')
        recovery = pick('Recovery delay', [
            ('200ms (standard)',   '200ms'),
            ('500ms (slow)',       '500ms'),
            ('30ms (fast)',        '30ms'),
            ('10ms (fastest)',     '10ms'),
        ])

        # ── 5. Edge protection ──
        step('STEP 5 ─── EDGE PROTECTION')
        edge = pick('Strategy', [
            ('rstp-full — BPDU Guard + admin edge + auto-disable (recommended)', 'rstp-full'),
            ('loop — keepalive-based, L2A+ only',                                'loop'),
            ('rstp — legacy per-port disable (minimal protection)',               'rstp'),
        ])

        storm = yesno('Enable storm control on edge ports?', default=True)
        storm_threshold = '100'
        storm_unit = 'pps'
        if storm:
            storm_threshold = ask('  Broadcast threshold', '100')
            storm_unit = pick('  Unit', [
                ('pps (packets per second)', 'pps'),
                ('percent',                  'percent'),
            ])

        timer_default = '30' if edge == 'rstp-full' else '0'
        timer = ask('Auto-disable recovery timer (seconds, 0=stay down)', timer_default)

        save_nvm = yesno('Save to NVM after ring verified?')

        # ── 6. Review ──
        step('STEP 6 ─── REVIEW')

        w = 60
        print(f'  {CY}┌{"─" * w}┐{RS}')
        print(f'  {CY}│{RS}  Protocol:        {YL}{protocol.upper():<{w - 21}}{RS}{CY}│{RS}')
        print(f'  {CY}│{RS}  Edge protection: {YL}{edge:<{w - 21}}{RS}{CY}│{RS}')
        storm_str = f'broadcast {storm_threshold} {storm_unit}' if storm else 'disabled'
        print(f'  {CY}│{RS}  Storm control:   {storm_str:<{w - 20}}{CY}│{RS}')
        print(f'  {CY}│{RS}  Save to NVM:     {"yes" if save_nvm else "no (RAM only)":<{w - 20}}{CY}│{RS}')
        print(f'  {CY}├{"─" * w}┤{RS}')
        print(f'  {CY}│{RS}  {BD}Main Ring (VLAN {vlan}){RS}{" " * (w - 20 - len(vlan))}{CY}│{RS}')
        for dev in main_devices:
            tag = ' [RM]' if dev['role'] == 'manager' else ''
            line = f'    {dev["ip"]:17s} {dev["port1"]} ↔ {dev["port2"]}{tag}'
            print(f'  {CY}│{RS}{line:<{w}}{CY}│{RS}')
        for sr in sub_rings:
            print(f'  {CY}│{RS}  {BD}Sub-Ring (VLAN {sr["vlan"]}){RS}{" " * (w - 19 - len(sr["vlan"]))}{CY}│{RS}')
            line = f'    {sr["srm"]["ip"]:17s} {sr["srm"]["port"]:<14s} [SRM]'
            print(f'  {CY}│{RS}{line:<{w}}{CY}│{RS}')
            line = f'    {sr["rsrm"]["ip"]:17s} {sr["rsrm"]["port"]:<14s} [RSRM]'
            print(f'  {CY}│{RS}{line:<{w}}{CY}│{RS}')
            for rc in sr['clients']:
                line = f'    {rc["ip"]:17s} {rc["port1"]} ↔ {rc["port2"]}'
                print(f'  {CY}│{RS}{line:<{w}}{CY}│{RS}')
        print(f'  {CY}└{"─" * w}┘{RS}')
        print()

        action = pick('Go', [
            ('Dry run — show plan only', 'dry'),
            ('Deploy ring',              'live'),
            ('Quit',                     'quit'),
        ])

        if action == 'quit':
            print(f'\n  {DM}Later.{RS}\n')
            return

        # Build script.cfg content
        cfg_lines = []
        if not is_offline:
            cfg_lines.append(f'username {username}')
            cfg_lines.append(f'password {password}')
        cfg_lines.append(f'protocol {protocol}')
        cfg_lines.append(f'port1 {default_p1}')
        cfg_lines.append(f'port2 {default_p2}')
        cfg_lines.append(f'vlan {vlan}')
        cfg_lines.append(f'recovery_delay {recovery}')
        cfg_lines.append(f'edge_protection {edge}')
        cfg_lines.append(f'auto_disable_timer {timer}')
        if storm:
            cfg_lines.append(f'storm_control true')
            cfg_lines.append(f'storm_control_threshold {storm_threshold}')
            cfg_lines.append(f'storm_control_unit {storm_unit}')
        else:
            cfg_lines.append(f'storm_control false')
        cfg_lines.append(f'save {"true" if save_nvm else "false"}')
        cfg_lines.append('')

        # Main ring devices
        for dev in main_devices:
            parts = [dev['ip']]
            if dev['port1'] != default_p1 or dev['port2'] != default_p2:
                parts += [dev['port1'], dev['port2']]
            if dev['role'] == 'manager':
                parts.append('RM')
            cfg_lines.append(' '.join(parts))

        # Sub-ring devices
        for sr in sub_rings:
            cfg_lines.append('')
            cfg_lines.append(f'{sr["srm"]["ip"]} SRM {sr["vlan"]} {sr["srm"]["port"]}')
            cfg_lines.append(f'{sr["rsrm"]["ip"]} RSRM {sr["vlan"]} {sr["rsrm"]["port"]}')
            for rc in sr['clients']:
                parts = [rc['ip'], 'RC', sr['vlan']]
                if rc['port1'] != default_p1 or rc['port2'] != default_p2:
                    parts += [rc['port1'], rc['port2']]
                cfg_lines.append(' '.join(parts))

        # Write temp config
        tmp_cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.interactive.cfg')
        with open(tmp_cfg, 'w') as f:
            f.write('\n'.join(cfg_lines) + '\n')

        # Run clamp.py with the generated config
        cmd = [sys.executable, os.path.abspath(__file__), '-c', tmp_cfg]
        if action == 'dry':
            cmd.append('--dry-run')

        print()
        subprocess.run(cmd)

        if action == 'dry':
            print()
            if not yesno('Deploy ring?'):
                try:
                    os.remove(tmp_cfg)
                except OSError:
                    pass
                print(f'\n  {DM}Done.{RS}\n')
                return
            # Run live
            live_cmd = [sys.executable, os.path.abspath(__file__), '-c', tmp_cfg]
            print()
            subprocess.run(live_cmd)

        # Clean up temp config
        try:
            os.remove(tmp_cfg)
        except OSError:
            pass

        # Offer to save as script.cfg
        print()
        if yesno('Save this configuration as script.cfg?'):
            save_path = get_resource_path('script.cfg')
            with open(save_path, 'w') as f:
                f.write('# CLAMPS — Generated by interactive mode\n')
                f.write('\n'.join(cfg_lines) + '\n')
            print(f'\n  {GR}Saved to {save_path}{RS}')

        print(f'\n  {DM}Done.{RS}\n')

    except KeyboardInterrupt:
        print(f'\n\n  {DM}Interrupted.{RS}\n')
    except EOFError:
        print(f'\n\n  {DM}Bye.{RS}\n')


def parse_arguments():
    parser = argparse.ArgumentParser(description='Deploy MRP ring across HiOS switches')
    parser.add_argument('-c', '--config', default='script.cfg',
                        help='Path to configuration file (default: script.cfg)')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help='Connection timeout in seconds (default: 30)')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Guided interactive wizard')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging (MOPS XML detail)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse config and show plan without executing')
    parser.add_argument('--edge', choices=EDGE_MODES,
                        help='Edge protection strategy (overrides config)')
    parser.add_argument('--migrate-edge', nargs='?', const='auto',
                        metavar='MODE', default=None,
                        help='Migrate edge strategy (auto-toggles, or specify: loop, rstp-full, rstp)')
    parser.add_argument('--no-storm-control', action='store_true',
                        help='Skip storm control deployment on edge ports')
    parser.add_argument('--verify', action='store_true',
                        help='Re-gather state after deploy to confirm changes (logged to file)')
    parser.add_argument('--export', metavar='FILE',
                        help='Export per-port protection config to CSV')
    parser.add_argument('--import', metavar='FILE', dest='import_file',
                        help='Import per-port protection config from CSV, diff + apply')
    parser.add_argument('--save', action='store_true',
                        help='Save config to NVM after import changes')
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
    """Parse script.cfg into global settings and device list.

    Supports main ring devices and sub-ring devices:
      <ip> [port1 port2] [RM]          — main ring (client or manager)
      <ip> SRM <vlan> <port>           — sub-ring branch point (manager)
      <ip> RSRM <vlan> <port>         — sub-ring branch point (redundant manager)
      <ip> RC <vlan> [port1 port2]     — sub-ring client
      <ip> [port1 port2]              — main ring client (no role = RC implied)
    """
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
        'storm_control': True,
        'storm_control_threshold': 100,
        'storm_control_unit': 'pps',
        'force': False,
        'sw_level': 'L2S',   # safe default for offline (no loop prot, no auto-disable)
        'devices': [],       # flat list (backward compat for connect/gather)
        'rings': {},         # keyed by VLAN — built after parsing
    }

    # Raw parsed entries before ring grouping
    raw_entries = []

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
            elif line.startswith('storm_control_threshold '):
                config['storm_control_threshold'] = int(line.split(None, 1)[1])
            elif line.startswith('storm_control_unit '):
                val = line.split(None, 1)[1].lower().strip()
                if val in ('pps', 'percent'):
                    config['storm_control_unit'] = val
                else:
                    logging.warning(f"Line {line_num}: unknown storm_control_unit '{val}', using 'pps'")
            elif line.startswith('storm_control '):
                config['storm_control'] = line.split(None, 1)[1].lower() in ('true', 'yes', '1')
            elif line.startswith('force '):
                config['force'] = line.split(None, 1)[1].lower() in ('true', 'yes', '1')
            elif line.startswith('debug '):
                config['debug'] = line.split(None, 1)[1].lower() in ('true', 'yes', '1')
            elif line.startswith('sw_level '):
                config['sw_level'] = line.split(None, 1)[1].upper().strip()
            else:
                tokens = line.split()
                if not tokens:
                    continue

                ip = tokens[0]
                if ip.endswith('.xml'):
                    # Offline config file — auto-set protocol
                    if not os.path.isabs(ip):
                        ip = os.path.join(os.path.dirname(os.path.abspath(config_file)), ip)
                    if not config.get('_offline_detected'):
                        config['protocol'] = 'offline'
                        config['_offline_detected'] = True
                elif not is_valid_ipv4(ip):
                    logging.warning(f"Line {line_num}: skipping invalid IP '{ip}'")
                    continue

                rest = tokens[1:]
                role = None
                entry_vlan = None
                ports = []
                dev_sw_level = None

                # Detect role keyword
                i = 0
                while i < len(rest):
                    tok = rest[i]
                    tok_upper = tok.upper()
                    if tok_upper in ('L2S', 'L2E', 'L2A', 'L3S', 'L3A'):
                        dev_sw_level = tok_upper
                        i += 1
                    elif tok_upper == 'RM':
                        role = 'manager'
                        i += 1
                    elif tok_upper in ('SRM', 'RSRM'):
                        role = tok_upper.lower()  # 'srm' or 'rsrm'
                        # Next token must be VLAN
                        if i + 1 < len(rest) and not is_port(rest[i + 1]):
                            entry_vlan = int(rest[i + 1])
                            i += 2
                        else:
                            raise ValueError(
                                f"Line {line_num}: {tok_upper} requires a VLAN number")
                    elif tok_upper == 'RC':
                        role = 'client'
                        # Next token might be VLAN
                        if i + 1 < len(rest) and not is_port(rest[i + 1]):
                            entry_vlan = int(rest[i + 1])
                            i += 2
                        else:
                            i += 1
                    elif is_port(tok):
                        ports.append(tok)
                        i += 1
                    else:
                        # Could be a bare VLAN number (for RC shorthand)
                        try:
                            entry_vlan = int(tok)
                            role = role or 'client'
                            i += 1
                        except ValueError:
                            logging.warning(f"Line {line_num}: ignoring unknown token '{tok}'")
                            i += 1

                if role is None:
                    role = 'client'

                raw_entries.append({
                    'ip': ip,
                    'role': role,
                    'vlan': entry_vlan,
                    'ports': ports,
                    'sw_level': dev_sw_level,
                    'line_num': line_num,
                })

    if config['protocol'] != 'offline':
        if not config['username'] or not config['password']:
            raise ValueError("Configuration must contain both username and password")
    if not raw_entries:
        raise ValueError("No valid device IPs found in configuration")

    # ---------------------------------------------------------------
    # Group entries into rings by VLAN
    # ---------------------------------------------------------------
    main_vlan = int(config['vlan'])
    rings = {}

    for entry in raw_entries:
        ip = entry['ip']
        role = entry['role']
        ports = entry['ports']
        ev = entry['vlan']

        if role in ('srm', 'rsrm'):
            # Sub-ring branch point — VLAN required, exactly 1 port
            if ev is None:
                raise ValueError(f"Device {ip}: {role.upper()} requires a VLAN number")
            if len(ports) != 1:
                raise ValueError(
                    f"Device {ip}: {role.upper()} requires exactly 1 port, got {len(ports)}")
            vlan = ev
            if vlan not in rings:
                rings[vlan] = {'vlan': vlan, 'is_main': False,
                               'srm': None, 'rsrm': None, 'devices': []}
            ring = rings[vlan]
            bp = {'ip': ip, 'port': ports[0]}
            if role == 'srm':
                if ring['srm'] is not None:
                    raise ValueError(f"Sub-ring VLAN {vlan}: duplicate SRM (already {ring['srm']['ip']})")
                ring['srm'] = bp
            else:
                if ring['rsrm'] is not None:
                    raise ValueError(f"Sub-ring VLAN {vlan}: duplicate RSRM (already {ring['rsrm']['ip']})")
                ring['rsrm'] = bp

        elif ev is not None and ev != main_vlan:
            # Sub-ring RC — client on a sub-ring VLAN
            vlan = ev
            if vlan not in rings:
                rings[vlan] = {'vlan': vlan, 'is_main': False,
                               'srm': None, 'rsrm': None, 'devices': []}
            p1 = ports[0] if len(ports) >= 1 else config['port1']
            p2 = ports[1] if len(ports) >= 2 else config['port2']
            if not p1 or not p2:
                raise ValueError(f"Device {ip} (sub-ring VLAN {vlan}): no ring ports specified")
            rings[vlan]['devices'].append({
                'ip': ip, 'port1': p1, 'port2': p2, 'role': 'client',
                'sw_level': entry.get('sw_level')})

        else:
            # Main ring device (RM or RC)
            p1 = ports[0] if len(ports) >= 1 else config['port1']
            p2 = ports[1] if len(ports) >= 2 else config['port2']
            if not p1 or not p2:
                raise ValueError(f"Device {ip}: no ring ports specified and no global defaults")
            if main_vlan not in rings:
                rings[main_vlan] = {'vlan': main_vlan, 'is_main': True, 'devices': []}
            rings[main_vlan]['devices'].append({
                'ip': ip, 'port1': p1, 'port2': p2, 'role': role,
                'sw_level': entry.get('sw_level')})

    # Validate main ring
    if main_vlan not in rings:
        raise ValueError("No main ring devices found in configuration")

    main_ring = rings[main_vlan]
    managers = [d for d in main_ring['devices'] if d['role'] == 'manager']
    if len(managers) == 0:
        main_ring['devices'][0]['role'] = 'manager'
        logging.warning(
            f"No RM specified — auto-assigning {main_ring['devices'][0]['ip']} as ring manager"
        )
    elif len(managers) > 1:
        ips = ', '.join(d['ip'] for d in managers)
        logging.warning(f"Multiple ring managers ({ips}) — MRP rings should have exactly one")

    # Validate sub-rings
    for vlan, ring in rings.items():
        if ring.get('is_main'):
            continue
        if ring['srm'] is None or ring['rsrm'] is None:
            missing = 'SRM' if ring['srm'] is None else 'RSRM'
            raise ValueError(f"Sub-ring VLAN {vlan}: missing {missing} branch point")
        if vlan == main_vlan:
            raise ValueError(f"Sub-ring VLAN {vlan} conflicts with main ring VLAN")

    config['rings'] = rings

    # Build flat device list (unique IPs) for connect/gather phases
    seen_ips = set()
    for ring in rings.values():
        for dev in ring.get('devices', []):
            if dev['ip'] not in seen_ips:
                config['devices'].append(dev)
                seen_ips.add(dev['ip'])
        # SRM/RSRM IPs (they're on the main ring too, but ensure present)
        for bp_key in ('srm', 'rsrm'):
            bp = ring.get(bp_key)
            if bp and bp['ip'] not in seen_ips:
                # Find their main ring entry for port1/port2
                main_dev = next((d for d in main_ring['devices'] if d['ip'] == bp['ip']), None)
                if main_dev:
                    config['devices'].append(main_dev)
                    seen_ips.add(bp['ip'])

    if not config['devices']:
        raise ValueError("No valid device IPs found in configuration")

    # Mode-aware auto-disable timer default (if not explicitly set in config)
    if config['auto_disable_timer'] is None:
        if config['edge_protection'] == 'loop':
            config['auto_disable_timer'] = 0   # kill and stay dead
        else:
            config['auto_disable_timer'] = 30  # recover + BPDU Guard catches instantly

    return config


def display_name(ip_or_path):
    """Short display name for device identifier."""
    if ip_or_path.endswith('.xml'):
        return os.path.basename(ip_or_path)
    return ip_or_path


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


def get_ring_ports_for_device(config, ip):
    """Build combined set of ring ports for a device across all rings.

    Used for edge protection — ring ports get different treatment from edge ports.
    """
    ring_ports = set()
    for ring in config.get('rings', {}).values():
        for dev in ring.get('devices', []):
            if dev['ip'] == ip:
                ring_ports.add(dev['port1'])
                ring_ports.add(dev['port2'])
        for bp_key in ('srm', 'rsrm'):
            bp = ring.get(bp_key)
            if bp and bp['ip'] == ip:
                ring_ports.add(bp['port'])
    return sorted(ring_ports)


def print_plan(config: dict):
    """Print the deployment plan."""
    rings = config.get('rings', {})
    main_vlan = int(config['vlan'])
    sub_ring_vlans = sorted(v for v in rings if v != main_vlan)

    print("\n" + "=" * 60)
    print("  MRP DEPLOYMENT PLAN — CLAMPS")
    print("=" * 60)
    print(f"  Protocol:        {config['protocol'].upper()}")
    print(f"  Edge protection: {edge_str(config)}")
    if config.get('storm_control'):
        unit = config['storm_control_unit']
        print(f"  Storm control:   broadcast {config['storm_control_threshold']} {unit} on edge ports")
    else:
        print(f"  Storm control:   disabled")
    print(f"  Save to NVM:     {'Yes (after ring verified)' if config['save'] else 'No (RAM only)'}")
    print("-" * 60)

    # Main ring
    main_ring = rings.get(main_vlan, {})
    print(f"  Main Ring (VLAN {main_vlan}):")
    for dev in main_ring.get('devices', []):
        role_tag = f"  [RM]" if dev['role'] == 'manager' else ""
        name = display_name(dev['ip'])
        print(f"    {name:20s} {dev['port1']} \u2194 {dev['port2']}{role_tag}")

    # Sub-rings
    for sv in sub_ring_vlans:
        ring = rings[sv]
        print(f"  Sub-Ring (VLAN {sv}):")
        if ring.get('srm'):
            name = display_name(ring['srm']['ip'])
            print(f"    {name:20s} {ring['srm']['port']:14s}  [SRM]")
        if ring.get('rsrm'):
            name = display_name(ring['rsrm']['ip'])
            print(f"    {name:20s} {ring['rsrm']['port']:14s}  [RSRM]")
        for dev in ring.get('devices', []):
            name = display_name(dev['ip'])
            print(f"    {name:20s} {dev['port1']} \u2194 {dev['port2']}")

    print("-" * 60)
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
    is_offline = config['protocol'] == 'offline'
    try:
        device = driver(
            hostname=ip,
            username=config['username'] if not is_offline else '',
            password=config['password'] if not is_offline else '',
            timeout=timeout,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()
        return ip, device, None
    except Exception as e:
        return ip, None, str(e)


def worker_gather_facts(device, dev, config=None, is_l2s_possible=True):
    """Thread worker: gather current state from one device.

    Returns: (ip, facts_dict, error_str)
    facts_dict has keys: sw_level, mrp, rstp, rstp_port, auto_disable, loop_protection,
                         all_ports, srm_ports
    """
    ip = dev['ip']
    result = {
        'sw_level': 'unknown',
        'mrp': None,
        'rstp': None,
        'rstp_port': {},
        'auto_disable': None,
        'loop_protection': None,
        'all_ports': [],
        'interfaces': {},
        'storm_control': None,
        'srm_ports': set(),
    }
    try:
        facts = device.get_facts()
        sw = get_sw_level(facts)
        if sw == 'unknown':
            sw = dev.get('sw_level') or (config or {}).get('sw_level', 'L2S')
        result['sw_level'] = sw
        is_l2s = result['sw_level'] == 'L2S'

        result['mrp'] = device.get_mrp()
        result['rstp'] = device.get_rstp()

        try:
            result['rstp_port'] = device.get_rstp_port()
        except Exception as e:
            logging.warning(f"[{ip}] get_rstp_port failed: {e}")

        # Discover sub-ring ports from live device state
        try:
            srm = device.get_mrp_sub_ring()
            for instance in srm.values():
                if isinstance(instance, dict):
                    port = instance.get('port')
                    if port:
                        result['srm_ports'].add(port)
        except Exception as e:
            logging.warning(f"[{ip}] get_mrp_sub_ring failed: {e}")

        if not is_l2s:
            try:
                result['auto_disable'] = device.get_auto_disable()
            except Exception as e:
                logging.warning(f"[{ip}] get_auto_disable failed: {e}")

            try:
                result['loop_protection'] = device.get_loop_protection()
            except Exception as e:
                logging.warning(f"[{ip}] get_loop_protection failed: {e}")

        try:
            result['storm_control'] = device.get_storm_control()
        except Exception as e:
            logging.warning(f"[{ip}] get_storm_control failed: {e}")

        # Get interface states (needed for ring port up/down check + all_ports list)
        try:
            result['interfaces'] = device.get_interfaces()
        except Exception as e:
            logging.warning(f"[{ip}] get_interfaces failed: {e}")

        # Build all_ports list from loop_protection interfaces or get_interfaces
        # Filter out non-switchports — MOPS/SNMP include cpu/1 (management)
        # and vlan/N (L3 routing interfaces) which have no RSTP CST entry,
        # loop protection, or auto-disable support.
        def _is_switchport(p):
            return not (p.startswith('cpu/') or p.startswith('vlan/'))

        if result['loop_protection'] and result['loop_protection'].get('interfaces'):
            result['all_ports'] = sorted(
                p for p in result['loop_protection']['interfaces']
                if _is_switchport(p))
        elif result['interfaces']:
            result['all_ports'] = sorted(
                p for p in result['interfaces']
                if _is_switchport(p))
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


# -- Staging helper --

def _start_staging(device):
    """Try to enter MOPS staging mode. Returns True if staging is active."""
    try:
        device.start_staging()
        return True
    except (NotImplementedError, AttributeError):
        return False


# -- RSTP workers --

def worker_disable_rstp(device, dev):
    """Thread worker: disable RSTP on ring ports for one device."""
    ip = dev['ip']
    try:
        device.set_rstp_port([dev['port1'], dev['port2']], enabled=False)
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
        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        staging = _start_staging(device)

        # Global enable + fastest detection
        device.set_loop_protection(enabled=True, transmit_interval=1)

        # Ring ports: passive + auto-disable on loop detection
        device.set_loop_protection(
            interface=ring_ports,
            enabled=True,
            mode='passive',
            action='auto-disable',
        )

        # Edge ports: active + auto-disable (detect and kill loops)
        device.set_loop_protection(
            interface=edge_ports,
            enabled=True,
            mode='active',
            action='auto-disable',
        )

        if staging:
            device.commit_staging()

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
        exclude = set(exclude_ports) if exclude_ports else set()
        ports = [p for p in all_ports if p not in exclude]

        staging = _start_staging(device)

        device.set_auto_disable_reason(reason, enabled=True)
        device.set_auto_disable(interface=ports, timer=timer)

        if staging:
            device.commit_staging()

        return ip, True, f"auto-disable ({reason}) timer={timer}s on {len(ports)} ports"
    except Exception as e:
        return ip, False, str(e)


def worker_setup_storm_control(device, dev, all_ports, ring_ports, threshold, unit='pps'):
    """Thread worker: enable broadcast storm control on edge ports.

    Broadcast only — CPU death path is ARP starvation through the
    VLAN-unaware rate limiter (~450 pps shared). Multicast/unknown-unicast
    not limited (MRP test frames, IGMP, PTP need multicast).

    Ring ports excluded — MRP traffic is multicast-heavy.
    """
    ip = dev['ip']
    try:
        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        staging = _start_staging(device)

        device.set_storm_control(
            interface=edge_ports,
            unit=unit,
            broadcast_enabled=True,
            broadcast_threshold=threshold,
        )

        if staging:
            device.commit_staging()

        return ip, True, f"storm control broadcast {threshold} {unit} on {len(edge_ports)} edge ports"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_storm_control(device, dev, all_ports):
    """Thread worker: disable broadcast storm control on all ports."""
    ip = dev['ip']
    try:
        staging = _start_staging(device)

        device.set_storm_control(
            interface=all_ports,
            broadcast_enabled=False,
        )

        if staging:
            device.commit_staging()

        return ip, True, "broadcast storm control disabled"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_loop_protection(device, dev, all_ports):
    """Thread worker: disable loop protection on all ports of one device.

    No staging on teardown — order matters more than speed.
    """
    ip = dev['ip']
    try:
        device.set_loop_protection(interface=all_ports, enabled=False)
        device.set_loop_protection(enabled=False)
        return ip, True, f"loop protection disabled on {len(all_ports)} ports"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_auto_disable(device, dev, all_ports, reason='loop-protection'):
    """Thread worker: reset auto-disable for a reason on all ports.

    Also clears any ports still held down by auto-disable (reset_auto_disable).
    No staging on teardown — order matters more than speed.
    """
    ip = dev['ip']
    try:
        device.set_auto_disable(interface=all_ports, timer=0)
        device.set_auto_disable_reason(reason, enabled=False)

        # Clear any ports still stuck in auto-disabled state
        ad = device.get_auto_disable()
        released = [
            port for port, state in ad.get('interfaces', {}).items()
            if state.get('active') and state.get('reason') == reason
        ]
        if released:
            device.reset_auto_disable(released)

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

    Uses MOPS staging when available — all mutations in one atomic POST.
    """
    ip = dev['ip']
    try:
        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        staging = _start_staging(device)

        # Disable RSTP on ring ports
        device.set_rstp_port(ring_ports, enabled=False)

        # Enable BPDU Guard globally
        device.set_rstp(bpdu_guard=True)

        # Force admin edge on all edge ports
        device.set_rstp_port(edge_ports, edge_port=True)

        # Auto-disable for bpdu-rate
        device.set_auto_disable_reason('bpdu-rate', enabled=True)
        device.set_auto_disable(interface=all_ports, timer=timer)

        if staging:
            device.commit_staging()

        return ip, True, f"RSTP Full on {len(edge_ports)} edge ports, BPDU Guard on, timer={timer}s"
    except Exception as e:
        return ip, False, str(e)


def worker_teardown_rstp_full(device, dev, all_ports, ring_ports):
    """Thread worker: tear down RSTP Full protection on one device.

    Reverses: admin edge, BPDU Guard, auto-disable for bpdu-rate,
    releases stuck ports, re-enables RSTP on ring ports.

    Safe to stage — runs while RSTP is still globally on (Phase 1a).
    get_auto_disable + reset happen AFTER commit (can't stage getters).
    """
    ip = dev['ip']
    try:
        ring_set = set(ring_ports)
        edge_ports = [p for p in all_ports if p not in ring_set]

        staging = _start_staging(device)

        # Reset auto-disable timers
        device.set_auto_disable(interface=all_ports, timer=0)
        device.set_auto_disable_reason('bpdu-rate', enabled=False)

        # Remove admin edge on edge ports
        device.set_rstp_port(edge_ports, edge_port=False)

        # Disable BPDU Guard globally
        device.set_rstp(bpdu_guard=False)

        # Re-enable RSTP on ring ports
        device.set_rstp_port(ring_ports, enabled=True)

        if staging:
            device.commit_staging()

        # After commit: clear any ports stuck in auto-disable
        ad = device.get_auto_disable()
        released = [
            port for port, state in ad.get('interfaces', {}).items()
            if state.get('active') and state.get('reason') == 'bpdu-rate'
        ]
        if released:
            device.reset_auto_disable(released)

        detail = f"RSTP Full torn down on {len(edge_ports)} edge ports"
        if released:
            detail += f", released {','.join(released)}"
        return ip, True, detail
    except Exception as e:
        return ip, False, str(e)


# -- Sub-ring workers --

def worker_configure_sub_ring_rc(device, dev, vlan, recovery_delay):
    """Thread worker: configure MRP client on a sub-ring RC device."""
    ip = dev['ip']
    try:
        t0 = time.time()
        logging.info(f"[{ip}] Sub-ring RC: {dev['port1']}+{dev['port2']}, vlan={vlan}")
        device.set_mrp(
            operation='enable',
            mode='client',
            port_primary=dev['port1'],
            port_secondary=dev['port2'],
            vlan=vlan,
            recovery_delay=recovery_delay,
        )
        dt = time.time() - t0
        return ip, True, f"sub-ring RC vlan={vlan} ({dt:.1f}s)"
    except Exception as e:
        return ip, False, str(e)


def worker_configure_srm(device, bp, vlan, mode, ring_id):
    """Thread worker: configure SRM/RSRM on a branch-point device."""
    ip = bp['ip']
    try:
        t0 = time.time()
        logging.info(f"[{ip}] SRM: ring_id={ring_id}, mode={mode}, port={bp['port']}, vlan={vlan}")
        device.set_mrp_sub_ring(
            ring_id=ring_id,
            mode=mode,
            port=bp['port'],
            vlan=vlan,
        )
        dt = time.time() - t0
        return ip, True, f"SRM {mode} vlan={vlan} ring_id={ring_id} ({dt:.1f}s)"
    except Exception as e:
        return ip, False, str(e)


def worker_delete_sub_ring(device, ip, ring_id):
    """Thread worker: delete a sub-ring instance on one device."""
    try:
        device.delete_mrp_sub_ring(ring_id=ring_id)
        return ip, True, f"SRM ring_id={ring_id} deleted"
    except Exception as e:
        return ip, False, str(e)


def worker_disable_srm_global(device, ip):
    """Thread worker: disable SRM globally on one device."""
    try:
        device.delete_mrp_sub_ring(ring_id=None)
        return ip, True, "SRM disabled globally"
    except Exception as e:
        return ip, False, str(e)


# -- Save worker --

def worker_save(device, dev):
    """Thread worker: save config on one device."""
    ip = dev['ip']
    try:
        status = device.save_config()
        # Live backends return {'saved': True, 'nvm': ...}
        # Offline backend returns {'status': 'saved', 'filename': ...}
        if status.get('saved') or status.get('status') == 'saved':
            detail = status.get('filename') or f"nvm={status.get('nvm')}"
            return ip, True, detail
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
        name = display_name(ip)
        log_print(f"  [{tag:4s}] {name:20s} {msg}")


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


def verify_sub_ring(srm_device, ring_id, vlan, max_attempts=3, delay=1):
    """Check sub-ring health on SRM device with retries.

    Returns: (healthy: bool, ring_state: str, redundancy: bool)
    """
    for attempt in range(1, max_attempts + 1):
        time.sleep(delay)
        srm = srm_device.get_mrp_sub_ring()
        for inst in srm.get('instances', []):
            if inst['ring_id'] == ring_id:
                ring_state = inst.get('ring_state', 'unknown')
                redundancy = inst.get('redundancy', False)
                if ring_state == 'closed' and redundancy:
                    return True, ring_state, redundancy
                if attempt < max_attempts:
                    log_print(f"  Attempt {attempt}/{max_attempts}: sub-ring VLAN {vlan} "
                              f"not ready (state={ring_state}), retrying...")
                return False if attempt == max_attempts else None, ring_state, redundancy

        if attempt < max_attempts:
            log_print(f"  Attempt {attempt}/{max_attempts}: sub-ring ring_id={ring_id} "
                      f"not found on SRM, retrying...")

    return False, 'not found', False


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


def gather_device_state(config, connections):
    """Parallel gather of facts from all devices. Returns (device_facts, l2s_devices)."""
    device_facts = {}
    l2s_devices = []

    with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
        futures = {}
        for dev in config['devices']:
            device = connections.get(dev['ip'])
            if device:
                futures[pool.submit(worker_gather_facts, device, dev, config)] = dev

        for future in as_completed(futures):
            ip, facts, err = future.result()
            device_facts[ip] = facts
            if err:
                logging.warning(f"[{ip}] gather_facts partial failure: {err}")

    for dev in config['devices']:
        ip = dev['ip']
        if ip in device_facts and device_facts[ip].get('sw_level') == 'L2S':
            l2s_devices.append(ip)

    return device_facts, l2s_devices


def display_device_state(label, config, device_facts):
    """Print summary table of device state with a custom label."""
    log_print(f"\n  {label}")
    log_print("  " + "-" * 55)
    for dev in config['devices']:
        ip = dev['ip']
        name = display_name(ip)
        if ip not in device_facts:
            log_print(f"  {name:22s} [no connection]")
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
        sc_state = '?'
        if facts['storm_control'] is not None:
            sc_ifaces = facts['storm_control'].get('interfaces', {})
            sc_on = sum(1 for p in sc_ifaces.values() if p.get('broadcast', {}).get('enabled'))
            sc_state = str(sc_on) if sc_on else 'off'
        role_tag = 'RM' if dev['role'] == 'manager' else 'RC'
        log_print(f"  {name:22s} [{sw}] MRP={mrp_state}, RSTP={rstp_state}, LP={lp_state}, BG={bg_state}, SC={sc_state}  ({role_tag})")


def run_phase0(config, connections):
    """Gather facts from all devices. Returns (device_facts, l2s_devices)."""
    log_print("\n  Phase 0: Gathering current state...")
    device_facts, l2s_devices = gather_device_state(config, connections)
    display_device_state("Phase 0: Current State", config, device_facts)
    log_device_state_json("BEFORE", device_facts)
    return device_facts, l2s_devices


# ---------------------------------------------------------------------------
# Phase 3: Deploy edge protection
# ---------------------------------------------------------------------------

def deploy_edge_protection(config, connections, device_facts, l2s_devices):
    """Deploy edge protection based on config['edge_protection'].

    Ring ports include both main ring and sub-ring ports for each device.
    """
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
                ring_ports = get_ring_ports_for_device(config, ip)
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
                    ring_ports = get_ring_ports_for_device(config, ip)
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
                ring_ports = get_ring_ports_for_device(config, ip)
                futures[pool.submit(
                    worker_setup_rstp_full, device, dev, all_ports, ring_ports, timer
                )] = dev
            for future in as_completed(futures):
                results.append(future.result())
        print_results("Phase 3 — RSTP Full", results)

    # Storm control — all modes (broadcast rate limit on edge ports)
    if config.get('storm_control'):
        threshold = config['storm_control_threshold']
        unit = config['storm_control_unit']
        log_print(f"\n  Phase 3 — Storm control: broadcast {threshold} {unit} on edge ports...")
        sc_results = []
        with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
            futures = {}
            for dev in config['devices']:
                ip = dev['ip']
                device = connections.get(ip)
                if not device:
                    continue
                all_ports = device_facts.get(ip, {}).get('all_ports', [])
                ring_ports = get_ring_ports_for_device(config, ip)
                futures[pool.submit(
                    worker_setup_storm_control, device, dev, all_ports, ring_ports, threshold, unit
                )] = dev
            for future in as_completed(futures):
                sc_results.append(future.result())
        print_results("Phase 3 — Storm Control", sc_results)


# ---------------------------------------------------------------------------
# Subcommand: --export / --import
# ---------------------------------------------------------------------------

def _bool_csv(val):
    """Format a bool for CSV export."""
    if val is None:
        return ''
    return 'true' if val else 'false'


def cmd_export(args, config, connections):
    """Export per-port protection config to CSV."""
    output_file = args.export

    # Gather state from all devices
    device_facts, _ = gather_device_state(config, connections)

    rows = []
    for dev in config['devices']:
        ip = dev['ip']
        if ip not in device_facts:
            continue
        facts = device_facts[ip]
        hostname = display_name(ip)

        rstp_port = facts.get('rstp_port', {})
        loop_prot = facts.get('loop_protection')
        loop_ifaces = loop_prot.get('interfaces', {}) if loop_prot else {}
        storm = facts.get('storm_control')
        storm_ifaces = storm.get('interfaces', {}) if storm else {}
        auto_dis = facts.get('auto_disable')
        auto_ifaces = auto_dis.get('interfaces', {}) if auto_dis else {}

        ports = facts.get('all_ports', [])
        if not ports:
            continue

        for port in sorted(ports, key=natural_sort_key):
            rp = rstp_port.get(port, {})
            lp = loop_ifaces.get(port, {})
            sp = storm_ifaces.get(port, {})
            ad = auto_ifaces.get(port, {})

            rows.append({
                'device_ip': ip,
                'hostname': hostname,
                'port': port,
                'rstp_enabled': _bool_csv(rp.get('enabled')),
                'rstp_edge': _bool_csv(rp.get('edge_port')),
                'rstp_auto_edge': _bool_csv(rp.get('auto_edge')),
                'rstp_priority': rp.get('priority', ''),
                'rstp_path_cost': rp.get('path_cost', ''),
                'rstp_root_guard': _bool_csv(rp.get('root_guard')),
                'rstp_loop_guard': _bool_csv(rp.get('loop_guard')),
                'rstp_tcn_guard': _bool_csv(rp.get('tcn_guard')),
                'rstp_bpdu_filter': _bool_csv(rp.get('bpdu_filter')),
                'rstp_bpdu_flood': _bool_csv(rp.get('bpdu_flood')),
                'loop_enabled': _bool_csv(lp.get('enabled')),
                'loop_mode': lp.get('mode', ''),
                'loop_action': lp.get('action', ''),
                'storm_unit': sp.get('unit', ''),
                'storm_bc_enabled': _bool_csv(sp.get('broadcast', {}).get('enabled')),
                'storm_bc_threshold': sp.get('broadcast', {}).get('threshold', ''),
                'storm_mc_enabled': _bool_csv(sp.get('multicast', {}).get('enabled')),
                'storm_mc_threshold': sp.get('multicast', {}).get('threshold', ''),
                'storm_uc_enabled': _bool_csv(sp.get('unicast', {}).get('enabled')),
                'storm_uc_threshold': sp.get('unicast', {}).get('threshold', ''),
                'auto_disable_timer': ad.get('timer', ''),
            })

    output_path = get_resource_path(output_file)
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=PROTECTION_CSV_HEADERS)
        writer.writeheader()
        writer.writerows(rows)

    log_print(f"\n  Exported {len(rows)} rows to {output_file}")


def _parse_csv_bool(val):
    """Parse a CSV bool value. Returns True/False/None (empty = no change)."""
    val = val.strip().lower()
    if not val:
        return None
    return val in ('true', '1', 'yes')


def _parse_csv_int(val):
    """Parse a CSV int value. Returns int or None (empty = no change)."""
    val = val.strip()
    if not val:
        return None
    return int(val)


def cmd_import(args, config, connections):
    """Import per-port protection config from CSV, diff against current, apply changes."""
    import_file = args.import_file
    import_path = get_resource_path(import_file)

    if not os.path.exists(import_path):
        log_print(f"\n  ERROR: File not found: {import_file}")
        sys.exit(1)

    with open(import_path, 'r') as f:
        reader = csv.DictReader(f)
        csv_rows = list(reader)

    if not csv_rows:
        log_print("\n  ERROR: CSV file is empty")
        sys.exit(1)

    # Build desired state: {ip: {port: {field: value}}}
    desired = {}
    for row in csv_rows:
        ip = row['device_ip']
        port = row['port']
        d = {}
        # RSTP
        d['rstp_enabled'] = _parse_csv_bool(row.get('rstp_enabled', ''))
        d['rstp_edge'] = _parse_csv_bool(row.get('rstp_edge', ''))
        d['rstp_auto_edge'] = _parse_csv_bool(row.get('rstp_auto_edge', ''))
        d['rstp_priority'] = _parse_csv_int(row.get('rstp_priority', ''))
        d['rstp_path_cost'] = _parse_csv_int(row.get('rstp_path_cost', ''))
        d['rstp_root_guard'] = _parse_csv_bool(row.get('rstp_root_guard', ''))
        d['rstp_loop_guard'] = _parse_csv_bool(row.get('rstp_loop_guard', ''))
        d['rstp_tcn_guard'] = _parse_csv_bool(row.get('rstp_tcn_guard', ''))
        d['rstp_bpdu_filter'] = _parse_csv_bool(row.get('rstp_bpdu_filter', ''))
        d['rstp_bpdu_flood'] = _parse_csv_bool(row.get('rstp_bpdu_flood', ''))
        # Loop protection
        d['loop_enabled'] = _parse_csv_bool(row.get('loop_enabled', ''))
        d['loop_mode'] = row.get('loop_mode', '').strip() or None
        d['loop_action'] = row.get('loop_action', '').strip() or None
        # Storm control
        d['storm_unit'] = row.get('storm_unit', '').strip() or None
        d['storm_bc_enabled'] = _parse_csv_bool(row.get('storm_bc_enabled', ''))
        d['storm_bc_threshold'] = _parse_csv_int(row.get('storm_bc_threshold', ''))
        d['storm_mc_enabled'] = _parse_csv_bool(row.get('storm_mc_enabled', ''))
        d['storm_mc_threshold'] = _parse_csv_int(row.get('storm_mc_threshold', ''))
        d['storm_uc_enabled'] = _parse_csv_bool(row.get('storm_uc_enabled', ''))
        d['storm_uc_threshold'] = _parse_csv_int(row.get('storm_uc_threshold', ''))
        # Auto-disable
        d['auto_disable_timer'] = _parse_csv_int(row.get('auto_disable_timer', ''))
        desired.setdefault(ip, {})[port] = d

    # Gather live state
    device_facts, _ = gather_device_state(config, connections)

    # Build current state in same format
    current = {}
    for ip, facts in device_facts.items():
        rstp_port = facts.get('rstp_port', {})
        loop_prot = facts.get('loop_protection')
        loop_ifaces = loop_prot.get('interfaces', {}) if loop_prot else {}
        storm = facts.get('storm_control')
        storm_ifaces = storm.get('interfaces', {}) if storm else {}
        auto_dis = facts.get('auto_disable')
        auto_ifaces = auto_dis.get('interfaces', {}) if auto_dis else {}

        for port in facts.get('all_ports', []):
            rp = rstp_port.get(port, {})
            lp = loop_ifaces.get(port, {})
            sp = storm_ifaces.get(port, {})
            ad = auto_ifaces.get(port, {})
            current.setdefault(ip, {})[port] = {
                'rstp_enabled': rp.get('enabled'),
                'rstp_edge': rp.get('edge_port'),
                'rstp_auto_edge': rp.get('auto_edge'),
                'rstp_priority': rp.get('priority'),
                'rstp_path_cost': rp.get('path_cost'),
                'rstp_root_guard': rp.get('root_guard'),
                'rstp_loop_guard': rp.get('loop_guard'),
                'rstp_tcn_guard': rp.get('tcn_guard'),
                'rstp_bpdu_filter': rp.get('bpdu_filter'),
                'rstp_bpdu_flood': rp.get('bpdu_flood'),
                'loop_enabled': lp.get('enabled'),
                'loop_mode': lp.get('mode'),
                'loop_action': lp.get('action'),
                'storm_unit': sp.get('unit'),
                'storm_bc_enabled': sp.get('broadcast', {}).get('enabled'),
                'storm_bc_threshold': sp.get('broadcast', {}).get('threshold'),
                'storm_mc_enabled': sp.get('multicast', {}).get('enabled'),
                'storm_mc_threshold': sp.get('multicast', {}).get('threshold'),
                'storm_uc_enabled': sp.get('unicast', {}).get('enabled'),
                'storm_uc_threshold': sp.get('unicast', {}).get('threshold'),
                'auto_disable_timer': ad.get('timer'),
            }

    # Diff — skip None (empty CSV cell = no change)
    changes = []  # (ip, port, field, current_val, desired_val)
    for ip, ports in desired.items():
        if ip not in current:
            log_print(f"  [SKIP] {ip} — not in fleet")
            continue
        for port, d_state in ports.items():
            c_state = current.get(ip, {}).get(port)
            if not c_state:
                log_print(f"  [SKIP] {ip} port {port} — not in current state")
                continue
            for field, d_val in d_state.items():
                if d_val is None:
                    continue
                c_val = c_state.get(field)
                if d_val != c_val:
                    changes.append((ip, port, field, c_val, d_val))

    if not changes:
        log_print("\n  No changes needed — fleet matches CSV.")
        return

    log_print(f"\n  Import diff: {len(changes)} change(s)")
    for ip, port, field, cur, des in changes:
        log_print(f"    {display_name(ip)} {port}: {field} {cur} -> {des}")

    if args.dry_run:
        log_print("\n  [DRY RUN] No changes applied.")
        return

    # Group changes by device
    by_device = {}
    for ip, port, field, cur, des in changes:
        by_device.setdefault(ip, []).append((port, field, cur, des))

    use_staging = config['protocol'] in ('mops', 'offline')
    ok_count = 0
    fail_count = 0

    for ip, device_changes in by_device.items():
        if ip not in connections:
            continue
        device = connections[ip]

        try:
            # Group by setter domain
            rstp_ports = {}  # {port: {kwarg: val}}
            loop_ports = {}  # {port: {kwarg: val}}
            storm_ports = {}  # {port: {kwarg: val}}
            ad_ports = {}  # {port: timer}

            for port, field, cur, des in device_changes:
                if field.startswith('rstp_'):
                    rstp_ports.setdefault(port, {})[field] = des
                elif field.startswith('loop_'):
                    loop_ports.setdefault(port, {})[field] = des
                elif field.startswith('storm_'):
                    storm_ports.setdefault(port, {})[field] = des
                elif field == 'auto_disable_timer':
                    ad_ports[port] = des

            # Apply RSTP per-port
            for port, kwargs in rstp_ports.items():
                device.set_rstp_port(
                    port,
                    enabled=kwargs.get('rstp_enabled'),
                    edge_port=kwargs.get('rstp_edge'),
                    auto_edge=kwargs.get('rstp_auto_edge'),
                    priority=kwargs.get('rstp_priority'),
                    path_cost=kwargs.get('rstp_path_cost'),
                    root_guard=kwargs.get('rstp_root_guard'),
                    loop_guard=kwargs.get('rstp_loop_guard'),
                    tcn_guard=kwargs.get('rstp_tcn_guard'),
                    bpdu_filter=kwargs.get('rstp_bpdu_filter'),
                    bpdu_flood=kwargs.get('rstp_bpdu_flood'),
                )

            # Apply loop protection per-port
            for port, kwargs in loop_ports.items():
                device.set_loop_protection(
                    interface=port,
                    enabled=kwargs.get('loop_enabled'),
                    mode=kwargs.get('loop_mode'),
                    action=kwargs.get('loop_action'),
                )

            # Apply storm control per-port
            for port, kwargs in storm_ports.items():
                device.set_storm_control(
                    port,
                    unit=kwargs.get('storm_unit'),
                    broadcast_enabled=kwargs.get('storm_bc_enabled'),
                    broadcast_threshold=kwargs.get('storm_bc_threshold'),
                    multicast_enabled=kwargs.get('storm_mc_enabled'),
                    multicast_threshold=kwargs.get('storm_mc_threshold'),
                    unicast_enabled=kwargs.get('storm_uc_enabled'),
                    unicast_threshold=kwargs.get('storm_uc_threshold'),
                )

            # Apply auto-disable per-port
            for port, timer in ad_ports.items():
                device.set_auto_disable(port, timer=timer)

            ok_count += 1
            n = len(device_changes)
            log_print(f"  [OK  ] {display_name(ip)} — {n} change(s)")

        except Exception as e:
            fail_count += 1
            log_print(f"  [FAIL] {display_name(ip)} — {e}")

    log_print(f"\n  Applied: {ok_count} devices OK, {fail_count} failed")

    # Save if requested
    if args.save:
        log_print("\n  Saving to NVM...")
        save_ok = 0
        for ip in by_device:
            if ip not in connections:
                continue
            try:
                connections[ip].save_config()
                save_ok += 1
            except Exception as e:
                log_print(f"  [FAIL] {display_name(ip)} save: {e}")
        log_print(f"  {save_ok}/{len(by_device)} saved")


# ---------------------------------------------------------------------------
# Main deploy flow
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    # Interactive mode: explicit -i, or no script.cfg and no args
    if args.interactive:
        return interactive_mode()
    cfg_path = get_resource_path(args.config)
    if (not os.path.exists(cfg_path) and not args.dry_run
            and args.migrate_edge is None
            and not args.export and not args.import_file):
        return interactive_mode()

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

        # CLI overrides
        if args.edge:
            config['edge_protection'] = args.edge
        if args.no_storm_control:
            config['storm_control'] = False
        config['verify'] = args.verify

        # Route to export/import mode if requested
        if args.export or args.import_file:
            from napalm import get_network_driver
            driver = get_network_driver('hios')

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
                        log_print(f"  FAIL: {display_name(ip)} — {err}")

            if not connections:
                log_print("\n  FATAL: No devices reachable.\n")
                sys.exit(1)

            try:
                if args.export:
                    cmd_export(args, config, connections)
                else:
                    cmd_import(args, config, connections)

                elapsed = time.time() - start_time
                log_print(f"\n  Done in {elapsed:.1f}s")
                log_print(f"  Log: {log_filename}\n")
            finally:
                for ip, device in connections.items():
                    try:
                        device.close()
                    except Exception:
                        pass
            return

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
                log_print(f"  FAIL: {display_name(ip)} — {err}")
        if not connections:
            log_print("\n  FATAL: No devices reachable.\n")
            sys.exit(1)

        try:
            managers = [d for d in config['devices'] if d['role'] == 'manager']
            rm_ip = managers[0]['ip']
            rm_device = connections.get(rm_ip)
            rm_dev = managers[0]

            if not rm_device:
                log_print(f"\n  FATAL: No connection to ring manager {display_name(rm_ip)}\n")
                sys.exit(1)

            # --- Phase 0: Gather facts ---
            device_facts, l2s_devices = run_phase0(config, connections)

            # L2S safety check
            check_l2s_safety(config, device_facts, l2s_devices)

            # --- Phase 1: Break rings (disable ports to prevent loops) ---
            broke_ring = rm_ring_needs_breaking(device_facts, rm_dev)
            main_vlan = int(config['vlan'])
            sub_ring_vlans = sorted(v for v in config.get('rings', {}) if v != main_vlan)

            # 1a: Break main ring (RM port2 DOWN)
            if broke_ring:
                log_print(f"\n  Phase 1a: Disabling RM port2 ({rm_dev['port2']}) on {rm_ip}...")
                try:
                    rm_device.set_interface(rm_dev['port2'], enabled=False)
                    log_print(f"  [{rm_ip}] port {rm_dev['port2']} admin DOWN")
                except Exception as e:
                    log_print(f"  FATAL: Cannot disable RM port2: {e}\n")
                    sys.exit(1)
            else:
                log_print(f"\n  Phase 1a: Skipped (ring ports not both up — no ring to break)")

            # 1b: Break sub-ring paths (RSRM ports DOWN)
            # When MRP takes over main ring ports, RSTP can no longer see the
            # parallel path through sub-ring devices. Admin-down RSRM ports to
            # prevent loops until sub-rings are configured in Phase 6.
            broke_sub_ports = []
            for sv in sub_ring_vlans:
                ring = config['rings'][sv]
                rsrm = ring.get('rsrm')
                if rsrm:
                    rsrm_device = connections.get(rsrm['ip'])
                    if rsrm_device:
                        try:
                            rsrm_device.set_interface(rsrm['port'], enabled=False)
                            log_print(f"  Phase 1b: [{rsrm['ip']}] port {rsrm['port']} admin DOWN (RSRM, VLAN {sv})")
                            broke_sub_ports.append((rsrm['ip'], rsrm['port'], sv))
                        except Exception as e:
                            log_print(f"  WARNING: Cannot disable RSRM port {rsrm['port']} on {rsrm['ip']}: {e}")
            if not broke_sub_ports and sub_ring_vlans:
                log_print(f"  Phase 1b: Skipped (no RSRM ports to break)")

            # --- Phase 2: Configure MRP on main ring devices ---
            main_ring_devs = config['rings'][main_vlan]['devices']
            log_print("\n  Phase 2: Configuring MRP...")
            recovery_delay = config['recovery_delay']
            mrp_results = []

            with ThreadPoolExecutor(max_workers=len(main_ring_devs)) as pool:
                futures = {}
                for dev in main_ring_devs:
                    device = connections.get(dev['ip'])
                    if device:
                        futures[pool.submit(
                            worker_configure_mrp, device, dev, main_vlan, recovery_delay
                        )] = dev
                    else:
                        mrp_results.append((dev['ip'], False, "no connection"))

                for future in as_completed(futures):
                    ip, ok, _mrp_data, detail = future.result()
                    role = [d for d in main_ring_devs if d['ip'] == ip][0]['role']
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
            is_offline = config['protocol'] == 'offline'
            if is_offline:
                log_print("\n  Phase 5: Skipped (offline — no live ring to verify)")
            else:
                log_print("\n  Phase 5: Verifying ring...")
                healthy, ring_state, redundancy = verify_ring(rm_device, max_attempts=3, delay=1)

                status_tag = "HEALTHY" if healthy else "UNHEALTHY"
                log_print(f"  Ring: [{status_tag}] state={ring_state}, redundancy={redundancy}")

                if not healthy:
                    log_print("\n  Ring NOT healthy. Configs NOT saved — power cycle to rollback.\n")
                    sys.exit(1)

            # --- Phase 6+7: Sub-ring configuration and verification ---
            if sub_ring_vlans:
                log_print("\n  Phase 6: Configuring sub-rings...")
                recovery_delay = config['recovery_delay']

                for ring_id, sv in enumerate(sub_ring_vlans, 1):
                    ring = config['rings'][sv]
                    srm = ring.get('srm')
                    rsrm = ring.get('rsrm')
                    sub_rcs = ring.get('devices', [])

                    log_print(f"\n  Phase 6 — Sub-Ring VLAN {sv} (ring_id={ring_id}):")

                    # 6a: Configure sub-ring RCs (standard MRP client)
                    if sub_rcs:
                        rc_results = []
                        with ThreadPoolExecutor(max_workers=max(1, len(sub_rcs))) as pool:
                            futures = {}
                            for dev in sub_rcs:
                                device = connections.get(dev['ip'])
                                if device:
                                    futures[pool.submit(
                                        worker_configure_sub_ring_rc, device, dev,
                                        sv, recovery_delay
                                    )] = dev
                            for future in as_completed(futures):
                                rc_results.append(future.result())
                        print_results(f"Phase 6a — Sub-Ring RCs (VLAN {sv})", rc_results)

                    # 6b: Configure SRM and RSRM
                    srm_results = []
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        futures = {}
                        if srm:
                            srm_device = connections.get(srm['ip'])
                            if srm_device:
                                futures[pool.submit(
                                    worker_configure_srm, srm_device, srm,
                                    sv, 'manager', ring_id
                                )] = 'srm'
                        if rsrm:
                            rsrm_device = connections.get(rsrm['ip'])
                            if rsrm_device:
                                futures[pool.submit(
                                    worker_configure_srm, rsrm_device, rsrm,
                                    sv, 'redundantManager', ring_id
                                )] = 'rsrm'
                        for future in as_completed(futures):
                            srm_results.append(future.result())
                    print_results(f"Phase 6b — SRM/RSRM (VLAN {sv})", srm_results)

                    failures = [r for r in srm_results if not r[1]]
                    if failures:
                        log_print(f"\n  Sub-ring VLAN {sv} SRM config failed. Continuing with other rings...")

                # 6c: Restore RSRM ports (close sub-rings)
                if broke_sub_ports:
                    log_print("")
                    for rsrm_ip, rsrm_port, sv in broke_sub_ports:
                        rsrm_device = connections.get(rsrm_ip)
                        if rsrm_device:
                            try:
                                rsrm_device.set_interface(rsrm_port, enabled=True)
                                log_print(f"  Phase 6c: [{rsrm_ip}] port {rsrm_port} admin UP (RSRM, VLAN {sv})")
                            except Exception as e:
                                log_print(f"  WARNING: Cannot re-enable RSRM port {rsrm_port} on {rsrm_ip}: {e}")

                # Phase 7: Verify sub-rings
                if is_offline:
                    log_print("\n  Phase 7: Skipped (offline — no live sub-rings to verify)")
                else:
                    log_print("\n  Phase 7: Verifying sub-rings...")
                    all_sub_healthy = True
                    for ring_id, sv in enumerate(sub_ring_vlans, 1):
                        ring = config['rings'][sv]
                        srm = ring.get('srm')
                        if not srm:
                            continue
                        srm_device = connections.get(srm['ip'])
                        if not srm_device:
                            log_print(f"  Sub-ring VLAN {sv}: no connection to SRM {srm['ip']}")
                            all_sub_healthy = False
                            continue

                        healthy, ring_state, redundancy = verify_sub_ring(
                            srm_device, ring_id, sv, max_attempts=3, delay=1)
                        status_tag = "HEALTHY" if healthy else "UNHEALTHY"
                        log_print(f"  Sub-ring VLAN {sv}: [{status_tag}] state={ring_state}, redundancy={redundancy}")
                        if not healthy:
                            all_sub_healthy = False

                    if not all_sub_healthy:
                        log_print("\n  WARNING: One or more sub-rings not healthy.")

            # --- Verify: Re-gather state after deploy ---
            if config['verify']:
                log_print("\n  Verify: Re-gathering state after deploy...")
                after_facts, _ = gather_device_state(config, connections)
                display_device_state("AFTER", config, after_facts)
                log_device_state_json("AFTER", after_facts)

            # --- Phase 8: Save ---
            if config['save']:
                phase_num = 8 if sub_ring_vlans else 6
                log_print(f"\n  Phase {phase_num}: Saving configs...")
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

                print_results(f"Phase {phase_num} — Config Save", save_results)

                save_failures = [r for r in save_results if not r[1]]
                if save_failures:
                    log_print(f"\n  WARNING: {len(save_failures)} device(s) failed to save.")
            else:
                phase_num = 8 if sub_ring_vlans else 6
                log_print(f"\n  Phase {phase_num}: Skipped (save=false)")
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
        name = display_name(dev['ip'])
        print(f"  {i}. {name:20s}  {dev['port1']} + {dev['port2']}  [{role_str}]")
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
                log_print(f"  FAIL: {display_name(ip)} — {err}")

    if not connections:
        log_print("\n  FATAL: No devices reachable.\n")
        sys.exit(1)

    try:
        managers = [d for d in config['devices'] if d['role'] == 'manager']
        rm_ip = managers[0]['ip']
        rm_device = connections.get(rm_ip)

        if not rm_device:
            log_print(f"\n  FATAL: No connection to ring manager {display_name(rm_ip)}\n")
            sys.exit(1)

        # Phase 0: Gather facts
        device_facts, l2s_devices = run_phase0(config, connections)

        # Build ring port map: config ring ports + live SRM ports per device
        ring_ports_map = {}
        for dev in config['devices']:
            ip = dev['ip']
            ports = set(get_ring_ports_for_device(config, ip))
            # Merge in sub-ring ports discovered from live device state
            srm_ports = device_facts.get(ip, {}).get('srm_ports', set())
            ports.update(srm_ports)
            ring_ports_map[ip] = sorted(ports)
            if srm_ports:
                logging.info(f"[{ip}] SRM ports discovered: {sorted(srm_ports)}")

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
            # Tear down old RSTP Full settings BEFORE disabling RSTP.
            # BPDU Guard + admin edge + auto-disable bpdu-rate must be off
            # while RSTP is still on — firmware puts edge ports in discarding
            # if these are active when RSTP global goes off.
            if has_bpdu_guard:
                log_print("\n  Clearing RSTP Full settings (RSTP stays on)...")
                results = []
                with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                    futures = {}
                    for dev in config['devices']:
                        ip = dev['ip']
                        device = connections.get(ip)
                        if not device:
                            continue
                        all_ports = device_facts.get(ip, {}).get('all_ports', [])
                        ring_ports = ring_ports_map.get(ip, [dev['port1'], dev['port2']])
                        futures[pool.submit(
                            worker_teardown_rstp_full, device, dev, all_ports, ring_ports
                        )] = dev
                    for future in as_completed(futures):
                        results.append(future.result())
                print_results("Phase 1a — RSTP Full Teardown", results)

            # Now safe to disable RSTP globally
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
            print_results("Phase 1b — RSTP Disable (global)", rstp_results)

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
                    ring_ports = ring_ports_map.get(ip, [dev['port1'], dev['port2']])
                    futures[pool.submit(
                        worker_setup_loop_protection, device, dev, all_ports, ring_ports
                    )] = dev
                for future in as_completed(futures):
                    lp_results.append(future.result())
            print_results("Phase 1c — Loop Protection", lp_results)

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
                        ring_ports = ring_ports_map.get(ip, [dev['port1'], dev['port2']])
                        futures[pool.submit(
                            worker_setup_auto_disable, device, dev, all_ports, timer,
                            'loop-protection'
                        )] = dev
                    for future in as_completed(futures):
                        ad_results.append(future.result())
                print_results("Phase 1d — Auto-Disable (loop-protection)", ad_results)

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
                    ring_ports = ring_ports_map.get(ip, [dev['port1'], dev['port2']])
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

        # Storm control — deploy with new edge protection (all modes)
        if config.get('storm_control'):
            threshold = config['storm_control_threshold']
            unit = config['storm_control_unit']
            log_print(f"\n  Storm control: broadcast {threshold} {unit} on edge ports...")
            sc_results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    ip = dev['ip']
                    device = connections.get(ip)
                    if not device:
                        continue
                    all_ports = device_facts.get(ip, {}).get('all_ports', [])
                    ring_ports = ring_ports_map.get(ip, [dev['port1'], dev['port2']])
                    futures[pool.submit(
                        worker_setup_storm_control, device, dev, all_ports, ring_ports, threshold, unit
                    )] = dev
                for future in as_completed(futures):
                    sc_results.append(future.result())
            print_results("Storm Control", sc_results)

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

        if has_bpdu_guard and target not in ('rstp-full', 'loop'):
            # loop migration tears down rstp-full in Phase 1 (before RSTP disable)
            results = []
            with ThreadPoolExecutor(max_workers=len(config['devices'])) as pool:
                futures = {}
                for dev in config['devices']:
                    ip = dev['ip']
                    device = connections.get(ip)
                    if not device or ip in l2s_devices:
                        continue
                    all_ports = device_facts.get(ip, {}).get('all_ports', [])
                    ring_ports = ring_ports_map.get(ip, [dev['port1'], dev['port2']])
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

        # Verify: Re-gather state after migration
        if config['verify']:
            log_print("\n  Verify: Re-gathering state after migration...")
            after_facts, _ = gather_device_state(config, connections)
            display_device_state("AFTER", config, after_facts)
            log_device_state_json("AFTER", after_facts)

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
