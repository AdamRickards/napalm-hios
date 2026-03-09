#!/usr/bin/env python3
"""JUSTIN — Justified Unified Security Testing for Industrial Networks.

IEC 62443-4-2 security audit and hardening tool for Hirschmann HiOS switches.
Connects via napalm-hios, audits against SL1 baseline, remediates findings.

Usage:
    justin --audit -d 192.168.1.4              # single device audit
    justin --audit -c site.cfg                 # fleet audit
    justin --audit -d 192.168.1.4 -o report.json  # save report
    justin --harden --from-report report.json  # harden from saved audit
    justin --harden -d 192.168.1.4 --dry-run   # show planned fixes
    justin --harden -d 192.168.1.4 --commit    # apply fixes
    justin -i -d 192.168.1.4                  # interactive mode
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------

class C:
    RED = '\033[91m'
    YEL = '\033[93m'
    GRN = '\033[92m'
    CYN = '\033[96m'
    WHT = '\033[97m'
    MG  = '\033[95m'
    DIM = '\033[2m'
    BOLD = '\033[1m'
    UL  = '\033[4m'
    RST = '\033[0m'

NO_COLOR = type('NC', (), {k: '' for k in vars(C) if not k.startswith('_')})()

# When True, progress/status goes to stderr so stdout stays clean for JSON
_JSON_MODE = False

def _progress(msg):
    """Print progress message — stderr in JSON mode, stdout otherwise."""
    if _JSON_MODE:
        print(msg, file=sys.stderr)
    else:
        print(msg)

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {'critical': 0, 'warning': 1, 'info': 2}
SEVERITY_LABELS = {
    'critical': ('CRIT', 'RED'),
    'warning':  ('WARN', 'YEL'),
    'info':     ('INFO', 'CYN'),
}

# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding:
    """A single audit finding."""

    def __init__(self, check_id, clause, clause_title, severity, desc,
                 detail=None, passed=False, fix_cmd=None):
        self.check_id = check_id
        self.clause = clause
        self.clause_title = clause_title
        self.severity = severity
        self.desc = desc
        self.detail = detail
        self.passed = passed
        self.fix_cmd = fix_cmd

    def to_dict(self):
        d = {
            'check_id': self.check_id,
            'clause': self.clause,
            'clause_title': self.clause_title,
            'severity': self.severity,
            'desc': self.desc,
            'passed': self.passed,
        }
        if self.detail:
            d['detail'] = self.detail
        if self.fix_cmd:
            d['fix'] = self.fix_cmd
        return d

    @classmethod
    def from_dict(cls, d):
        """Reconstruct a Finding from a dict (e.g. loaded from JSON report)."""
        return cls(
            check_id=d['check_id'],
            clause=d['clause'],
            clause_title=d.get('clause_title', ''),
            severity=d['severity'],
            desc=d['desc'],
            detail=d.get('detail'),
            passed=d['passed'],
            fix_cmd=d.get('fix'),
        )

# ---------------------------------------------------------------------------
# Check definitions loader
# ---------------------------------------------------------------------------

def load_checks(checks_file=None):
    """Load check definitions from checks.json."""
    if checks_file is None:
        checks_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'checks.json')
    with open(checks_file, 'r') as f:
        data = json.load(f)
    return {c['id']: c for c in data['checks']}

# ---------------------------------------------------------------------------
# Config parsing (same pattern as AARON/MOHAWC/CLAMPS)
# ---------------------------------------------------------------------------

def is_valid_ipv4(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def parse_config(config_file):
    """Parse script.cfg into settings and device list."""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file '{config_file}' not found")

    config = {
        'username': 'admin',
        'password': 'private',
        'protocol': 'mops',
        'devices': [],
        'syslog_server': None,
        'syslog_port': 514,
        'ntp_server': None,
        'banner': None,
        'level': 'SL1',
    }

    with open(config_file, 'r') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            if '=' in line and not is_valid_ipv4(line.split()[0]):
                key, _, val = line.partition('=')
                key = key.strip().lower()
                val = val.strip().strip('"\'')

                if key == 'username':
                    config['username'] = val
                elif key == 'password':
                    config['password'] = val
                elif key == 'protocol':
                    config['protocol'] = val.lower()
                elif key == 'syslog_server':
                    config['syslog_server'] = val
                elif key == 'syslog_port':
                    config['syslog_port'] = int(val)
                elif key == 'ntp_server':
                    config['ntp_server'] = val
                elif key == 'banner':
                    config['banner'] = val
                elif key == 'level':
                    config['level'] = val.upper()
                continue

            tokens = line.split()
            ip = tokens[0]
            if is_valid_ipv4(ip):
                config['devices'].append(ip)

    return config

# ---------------------------------------------------------------------------
# Gather phase — call all getters, build state dict
# ---------------------------------------------------------------------------

def gather(device, check_defs, color=C):
    """Call each unique getter referenced by the check set, return state dict."""
    getters = set()
    for spec in check_defs.values():
        if spec.get('getter'):
            getters.add(spec['getter'])

    state = {}
    for getter_name in sorted(getters):
        _progress(f"  {color.DIM}Gathering {getter_name}() ...{color.RST}")
        try:
            state[getter_name] = getattr(device, getter_name)()
        except Exception as e:
            logging.warning("Getter %s failed: %s", getter_name, e)
            state[getter_name] = None
    return state

# ---------------------------------------------------------------------------
# Check functions — one per check ID
# ---------------------------------------------------------------------------

CHECK_FNS = {}

def register_check(check_id):
    def decorator(fn):
        CHECK_FNS[check_id] = fn
        return fn
    return decorator


def _make_finding(spec, desc, passed=False, detail=None, fix_cmd=None):
    """Shorthand to build a Finding from a check spec."""
    return Finding(
        check_id=spec['id'],
        clause=spec['clause'],
        clause_title=spec['clause_title'],
        severity=spec['severity'],
        desc=desc,
        detail=detail,
        passed=passed,
        fix_cmd=fix_cmd,
    )


def _unable(spec):
    """Return an 'unable to assess' finding when data is missing."""
    return _make_finding(spec, 'Unable to assess (getter returned no data)',
                         detail='Check requires driver support not yet available')


# --- sec-hidiscovery -------------------------------------------------------

@register_check('sec-hidiscovery')
def check_hidiscovery(state, spec, config):
    hd = state.get('get_hidiscovery')
    if hd is None:
        return _unable(spec)
    if hd.get('enabled', False):
        mode = hd.get('mode', 'unknown')
        return _make_finding(
            spec, f"HiDiscovery enabled ({mode})",
            fix_cmd="set_hidiscovery('off')")
    return _make_finding(spec, 'HiDiscovery disabled', passed=True)


# --- sec-insecure-protocols ------------------------------------------------

@register_check('sec-insecure-protocols')
def check_insecure_protocols(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    issues = []
    if svc.get('http', {}).get('enabled'):
        issues.append('HTTP enabled')
    if svc.get('telnet', {}).get('enabled'):
        issues.append('Telnet enabled')
    if issues:
        return _make_finding(
            spec, ', '.join(issues),
            fix_cmd="set_services(http=False, telnet=False)")
    return _make_finding(spec, 'HTTP and Telnet disabled', passed=True)


# --- sec-unsigned-sw -------------------------------------------------------

@register_check('sec-unsigned-sw')
def check_unsigned_sw(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    if 'unsigned_sw' not in svc:
        return _make_finding(
            spec, 'Unable to assess (unsigned_sw not in get_services)',
            detail='Driver extension needed')
    if svc['unsigned_sw']:
        return _make_finding(spec, 'Unsigned firmware upload allowed',
                             fix_cmd="set_services(unsigned_sw=False)")
    return _make_finding(spec, 'Unsigned firmware rejected', passed=True)


# --- sec-login-policy ------------------------------------------------------

@register_check('sec-login-policy')
def check_login_policy(state, spec, config):
    lp = state.get('get_login_policy')
    if lp is None:
        return _unable(spec)
    issues = []
    attempts = lp.get('max_login_attempts', 0)
    lockout = lp.get('lockout_duration', 0)
    min_len = lp.get('min_password_length', 1)
    if attempts == 0:
        issues.append('no login lockout')
    if lockout == 0 and attempts > 0:
        issues.append('lockout duration is 0')
    if min_len < 8:
        issues.append(f'min password length {min_len} (should be >= 8)')
    if issues:
        return _make_finding(
            spec, '; '.join(issues).capitalize(),
            fix_cmd="set_login_policy(max_login_attempts=5, "
                    "lockout_duration=60, min_password_length=8)")
    return _make_finding(
        spec,
        f'Login policy configured (max {attempts}, lockout {lockout}s, '
        f'min pw len {min_len})',
        passed=True)


# --- sec-time-sync ---------------------------------------------------------

@register_check('sec-time-sync')
def check_time_sync(state, spec, config):
    ntp = state.get('get_ntp')
    if ntp is None:
        return _unable(spec)
    client = ntp.get('client', {})
    if not client.get('enabled'):
        return _make_finding(spec, 'SNTP client disabled',
                             fix_cmd="set_ntp(client_enabled=True)")
    servers = client.get('servers', [])
    active = [s for s in servers
              if s.get('address') and s['address'] != '0.0.0.0']
    if not active:
        return _make_finding(spec, 'SNTP client enabled but no server configured',
                             fix_cmd="set_ntp(client_enabled=True) + configure server")
    addrs = ', '.join(s['address'] for s in active)
    return _make_finding(spec, f'NTP configured ({addrs})', passed=True)


# --- sec-logging -----------------------------------------------------------

@register_check('sec-logging')
def check_logging(state, spec, config):
    sl = state.get('get_syslog')
    if sl is None:
        return _unable(spec)
    if not sl.get('enabled'):
        return _make_finding(spec, 'Syslog disabled',
                             fix_cmd="set_syslog(enabled=True, servers=[...])")
    servers = sl.get('servers', [])
    active = [s for s in servers
              if s.get('ip') and s['ip'] != '0.0.0.0']
    if not active:
        return _make_finding(spec, 'Syslog enabled but no destination configured',
                             fix_cmd="set_syslog(servers=[{ip, port, severity}])")
    dests = ', '.join(f"{s['ip']}:{s.get('port', 514)}" for s in active)
    return _make_finding(spec, f'Syslog configured ({dests})', passed=True)


# --- sec-mgmt-vlan ---------------------------------------------------------

@register_check('sec-mgmt-vlan')
def check_mgmt_vlan(state, spec, config):
    mgmt = state.get('get_management')
    if mgmt is None:
        return _unable(spec)
    vlan_id = mgmt.get('vlan_id', 1)
    if vlan_id == 1:
        return _make_finding(
            spec, 'Management on VLAN 1 (default)',
            detail='Advisory only — migrate via VIKTOR',
            fix_cmd=None)
    return _make_finding(spec, f'Management on VLAN {vlan_id}', passed=True)


# --- sec-aca-auto-update ---------------------------------------------------

@register_check('sec-aca-auto-update')
def check_aca_auto_update(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    if 'aca_auto_update' not in svc:
        return _make_finding(
            spec, 'Unable to assess (aca_auto_update not in get_services)',
            detail='Driver extension needed')
    if svc['aca_auto_update']:
        return _make_finding(spec, 'ACA auto-update enabled',
                             fix_cmd="set_services(aca_auto_update=False)")
    return _make_finding(spec, 'ACA auto-update disabled', passed=True)


# --- sec-aca-config-write --------------------------------------------------

@register_check('sec-aca-config-write')
def check_aca_config_write(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    if 'aca_config_write' not in svc:
        return _make_finding(
            spec, 'Unable to assess (aca_config_write not in get_services)',
            detail='Driver extension needed')
    if svc['aca_config_write']:
        return _make_finding(spec, 'ACA external config write enabled',
                             fix_cmd="set_services(aca_config_write=False)")
    return _make_finding(spec, 'ACA external config write disabled', passed=True)


# --- sec-aca-config-load ---------------------------------------------------

@register_check('sec-aca-config-load')
def check_aca_config_load(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    if 'aca_config_load' not in svc:
        return _make_finding(
            spec, 'Unable to assess (aca_config_load not in get_services)',
            detail='Driver extension needed')
    if svc['aca_config_load']:
        return _make_finding(spec, 'ACA external config load enabled',
                             fix_cmd="set_services(aca_config_load=False)")
    return _make_finding(spec, 'ACA external config load disabled', passed=True)


# --- sec-snmpv1-traps ------------------------------------------------------

@register_check('sec-snmpv1-traps')
def check_snmpv1_traps(state, spec, config):
    sc = state.get('get_snmp_config')
    if sc is None:
        return _unable(spec)
    v1 = sc.get('versions', {}).get('v1', False)
    if v1:
        return _make_finding(spec, 'SNMPv1 enabled',
                             fix_cmd="set_snmp_config(v1=False)")
    return _make_finding(spec, 'SNMPv1 disabled', passed=True)


# --- sec-snmpv1v2-write ----------------------------------------------------

@register_check('sec-snmpv1v2-write')
def check_snmpv1v2_write(state, spec, config):
    sc = state.get('get_snmp_config')
    if sc is None:
        return _unable(spec)
    communities = sc.get('communities', [])
    rw = [c for c in communities if c.get('access') == 'rw']
    v1 = sc.get('versions', {}).get('v1', False)
    v2 = sc.get('versions', {}).get('v2', False)
    if rw and (v1 or v2):
        names = ', '.join(c['name'] for c in rw)
        return _make_finding(
            spec, f'SNMPv1/v2 write communities present ({names})',
            fix_cmd="set_snmp_config(v1=False, v2=False)")
    if rw:
        return _make_finding(
            spec, 'Write communities exist but v1/v2 disabled', passed=True)
    return _make_finding(spec, 'No SNMPv1/v2 write communities', passed=True)


# --- sec-devsec-monitors ---------------------------------------------------

@register_check('sec-devsec-monitors')
def check_devsec_monitors(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    if 'devsec_monitors' not in svc:
        return _make_finding(
            spec, 'Unable to assess (devsec_monitors not in get_services)',
            detail='Driver extension needed')
    if not svc['devsec_monitors']:
        return _make_finding(spec, 'Device security monitors not all enabled',
                             fix_cmd="set_services(devsec_monitors=True)")
    return _make_finding(spec, 'All device security monitors enabled', passed=True)


# --- sys-default-passwords -------------------------------------------------

@register_check('sys-default-passwords')
def check_default_passwords(state, spec, config):
    username = config.get('username', 'admin')
    password = config.get('password', 'private')

    if username == 'admin' and password == 'private':
        return _make_finding(
            spec, 'Using default credentials (admin/private)',
            detail='Advisory only — change password manually',
            fix_cmd=None)
    if username == 'admin':
        return _make_finding(
            spec, 'Admin password changed from default', passed=True)
    return _make_finding(
        spec, 'Non-admin user in use — default password probe not implemented',
        detail='Future: probe admin/private on same protocol')


# --- ns-gvrp-mvrp ----------------------------------------------------------

@register_check('ns-gvrp-mvrp')
def check_gvrp_mvrp(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    issues = []
    if 'gvrp' in svc and svc['gvrp']:
        issues.append('GVRP enabled')
    elif 'gvrp' not in svc:
        return _make_finding(
            spec, 'Unable to assess (gvrp not in get_services)',
            detail='Driver extension needed')
    if 'mvrp' in svc and svc['mvrp']:
        issues.append('MVRP enabled')
    elif 'mvrp' not in svc:
        return _make_finding(
            spec, 'Unable to assess (mvrp not in get_services)',
            detail='Driver extension needed')
    if issues:
        return _make_finding(spec, ', '.join(issues),
                             fix_cmd="set_services(gvrp=False, mvrp=False)")
    return _make_finding(spec, 'GVRP/MVRP disabled', passed=True)


# --- ns-gmrp-mmrp ----------------------------------------------------------

@register_check('ns-gmrp-mmrp')
def check_gmrp_mmrp(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    issues = []
    if 'gmrp' in svc and svc['gmrp']:
        issues.append('GMRP enabled')
    elif 'gmrp' not in svc:
        return _make_finding(
            spec, 'Unable to assess (gmrp not in get_services)',
            detail='Driver extension needed')
    if 'mmrp' in svc and svc['mmrp']:
        issues.append('MMRP enabled')
    elif 'mmrp' not in svc:
        return _make_finding(
            spec, 'Unable to assess (mmrp not in get_services)',
            detail='Driver extension needed')
    if issues:
        return _make_finding(spec, ', '.join(issues),
                             fix_cmd="set_services(gmrp=False, mmrp=False)")
    return _make_finding(spec, 'GMRP/MMRP disabled', passed=True)


# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

def run_checks(state, check_defs, config, color=C, quiet=False):
    """Run all registered checks against gathered state, return findings."""
    findings = []
    for check_id, spec in check_defs.items():
        fn = CHECK_FNS.get(check_id)
        if fn is None:
            logging.warning("No check function for %s", check_id)
            continue
        if not quiet:
            sl_tag = f"SL{spec.get('sl', '?')}"
            clause = spec['clause']
            _progress(f"  {color.DIM}[{sl_tag}] {clause:<8s}"
                      f"Checking {spec['clause_title']} ({check_id}) ...{color.RST}")
        finding = fn(state, spec, config)
        findings.append(finding)
    # Sort: failures first (by severity), then passes
    findings.sort(key=lambda f: (
        f.passed,
        SEVERITY_ORDER.get(f.severity, 9),
        f.check_id,
    ))
    return findings

# ---------------------------------------------------------------------------
# Report output — "Justin makes everything pretty"
# ---------------------------------------------------------------------------

def _severity_badge(finding, color):
    """Return a coloured severity badge string."""
    if finding.passed:
        return f"{color.GRN}PASS{color.RST}"
    sev_label, sev_attr = SEVERITY_LABELS.get(
        finding.severity, ('????', 'WHT'))
    c = getattr(color, sev_attr, '')
    return f"{c}{sev_label}{color.RST}"


def _score_bar(passed, total, width=20, color=C):
    """Return a visual progress bar for the score."""
    if total == 0:
        return ''
    filled = int(passed / total * width)
    empty = width - filled
    pct = passed * 100 // total
    if pct == 100:
        bar_color = color.GRN
    elif pct >= 70:
        bar_color = color.YEL
    else:
        bar_color = color.RED
    bar = f"{bar_color}{'█' * filled}{color.DIM}{'░' * empty}{color.RST}"
    return f"  [{bar}] {bar_color}{pct}%{color.RST}"


def _box_header(title, width, color):
    """Print a box-drawn header line."""
    inner = f"  {title}  "
    pad = width - 2 - len(inner)
    if pad < 0:
        pad = 0
    print(f"  {color.MG}{color.BOLD}╔{'═' * (width - 2)}╗{color.RST}")
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"{inner}{' ' * pad}"
          f"{color.MG}{color.BOLD}║{color.RST}")
    print(f"  {color.MG}{color.BOLD}╚{'═' * (width - 2)}╝{color.RST}")


def print_report(findings, device_info=None, color=C):
    """Print a full, nicely-formatted audit report to console."""
    W = 80  # report width

    # Header
    print()
    _box_header("JUSTIN — IEC 62443-4-2 Security Audit", W, color)

    if device_info:
        ip = device_info.get('ip', '?')
        model = device_info.get('model', '?')
        fw = device_info.get('os_version', '?')
        hostname = device_info.get('hostname', '?')
        print(f"  {color.BOLD}Device:{color.RST}  {ip} ({model}, {fw})")
        if hostname and hostname != ip:
            print(f"  {color.BOLD}Name:{color.RST}    {hostname}")
    print(f"  {color.BOLD}Level:{color.RST}   SL1")
    print(f"  {color.BOLD}Date:{color.RST}    {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()

    # Results table
    print(f"  {color.BOLD}{'Clause':<10s}{'Check':<26s}"
          f"{'Result':>6s}  Description{color.RST}")
    print(f"  {'─' * W}")

    for f in findings:
        badge = _severity_badge(f, color)
        cid = f.check_id[:24]
        # Right-align the badge in a 6-char field (ANSI codes don't count)
        print(f"  {color.DIM}{f.clause:<10s}{color.RST}{cid:<26s}"
              f"{badge:>15s}  {f.desc}")

    # Score section
    total = len(findings)
    passed = sum(1 for f in findings if f.passed)
    failed = total - passed
    assessed = sum(1 for f in findings
                   if 'Unable to assess' not in f.desc)

    print(f"  {'─' * W}")
    print()
    if total > 0:
        has_crit = any(not f.passed and f.severity == 'critical'
                       for f in findings)
        sc = color.RED if has_crit else (color.YEL if failed else color.GRN)
        pct = passed * 100 // total
        print(f"  {color.BOLD}Score:{color.RST}  "
              f"{sc}{passed}/{total} passed{color.RST} (SL1)")
        print(_score_bar(passed, total, color=color))
        if total != assessed:
            print(f"  {color.DIM}{total - assessed} check(s) could not be "
                  f"assessed (driver extension needed){color.RST}")

    # Recommendations section
    failures = [f for f in findings if not f.passed]
    if failures:
        print()
        print(f"  {color.BOLD}┌─ Recommendations {'─' * (W - 21)}┐{color.RST}")

        auto_fixable = [f for f in failures if f.fix_cmd]
        advisory = [f for f in failures if not f.fix_cmd
                     and 'Unable to assess' not in f.desc]
        unable = [f for f in failures if 'Unable to assess' in f.desc]

        if auto_fixable:
            print(f"  {color.BOLD}│{color.RST}")
            print(f"  {color.BOLD}│  {color.GRN}Auto-remediable "
                  f"({len(auto_fixable)}):{color.RST}")
            print(f"  {color.BOLD}│{color.RST}  "
                  f"Run {color.CYN}justin --harden --commit{color.RST} to fix:")
            for f in auto_fixable:
                print(f"  {color.BOLD}│{color.RST}    "
                      f"{f.clause:<9s}{f.check_id}")
                print(f"  {color.BOLD}│{color.RST}    "
                      f"{color.DIM}→ {f.fix_cmd}{color.RST}")

        if advisory:
            print(f"  {color.BOLD}│{color.RST}")
            print(f"  {color.BOLD}│  {color.YEL}Manual action required "
                  f"({len(advisory)}):{color.RST}")
            for f in advisory:
                print(f"  {color.BOLD}│{color.RST}    "
                      f"{f.clause:<9s}{f.check_id}: {f.desc}")
                if f.detail:
                    print(f"  {color.BOLD}│{color.RST}    "
                          f"{color.DIM}→ {f.detail}{color.RST}")

        if unable:
            print(f"  {color.BOLD}│{color.RST}")
            print(f"  {color.BOLD}│  {color.DIM}Not assessed "
                  f"({len(unable)}) — driver extension needed:{color.RST}")
            ids = ', '.join(f.check_id for f in unable)
            print(f"  {color.BOLD}│{color.RST}    {color.DIM}{ids}{color.RST}")

        print(f"  {color.BOLD}│{color.RST}")
        print(f"  {color.BOLD}└{'─' * (W - 1)}┘{color.RST}")
    elif total > 0 and failed == 0:
        print()
        print(f"  {color.GRN}{color.BOLD}All checks passed.{color.RST}")

    print()


def print_fleet_report(all_results, failures, elapsed, color=C,
                       numbered=False):
    """Print fleet-wide summary report.

    If numbered=True, shows compact format with [N] device indices and
    [N] fixable finding indices for interactive selection. Returns
    ordered list of fixable check_ids (None when not numbered).
    """
    W = 84
    n_ok = len(all_results)
    n_fail = len(failures)

    print()
    if numbered:
        _box_header("JUSTIN — IEC 62443-4-2 Fleet Audit", W, color)
        print(f"  {color.DIM}{n_ok} devices  SL1  "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M')}{color.RST}")
    else:
        _box_header("JUSTIN — IEC 62443-4-2 Fleet Audit", W, color)
        print(f"  {color.BOLD}Devices:{color.RST} {n_ok} audited"
              + (f", {color.RED}{n_fail} unreachable{color.RST}"
                 if n_fail else ""))
        print(f"  {color.BOLD}Level:{color.RST}   SL1")
        print(f"  {color.BOLD}Date:{color.RST}    "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()

    # Per-device summary table
    if not numbered:
        print(f"  {color.BOLD}{'IP':<18s}{'Name':<20s}{'Model':<16s}"
              f"{'Score':>7s}  Status{color.RST}")
        print(f"  {'─' * W}")

    for idx, (ip, data) in enumerate(sorted(all_results.items()), 1):
        di = data['device']
        findings = data['findings']
        total = len(findings)
        passed = sum(1 for f in findings if f.passed)
        failed = total - passed
        has_crit = any(not f.passed and f.severity == 'critical'
                       for f in findings)
        sc = color.RED if has_crit else (
            color.YEL if failed else color.GRN)

        bar_w = 10
        bar_filled = int(passed / total * bar_w) if total else 0
        bar = (f"{sc}{'█' * bar_filled}"
               f"{'░' * (bar_w - bar_filled)}{color.RST}")

        name = di.get('hostname', ip)[:18]
        if numbered:
            print(f"  {color.CYN}[{idx}]{color.RST} {ip:<18s}"
                  f"{name:<20s}"
                  f"{sc}{passed:>2d}/{total:<2d}{color.RST}  {bar}")
        else:
            model = di.get('model', '?')[:14]
            status = (f"{color.GRN}CLEAN{color.RST}" if failed == 0
                      else f"{sc}{failed} finding"
                      f"{'s' if failed != 1 else ''}{color.RST}")
            print(f"  {ip:<18s}{name:<20s}{model:<16s}"
                  f"{sc}{passed:>2d}/{total:<2d}{color.RST}  "
                  f"{bar}  {status}")

    for fip, ferr in failures:
        if numbered:
            print(f"      {fip:<18s}"
                  f"{color.RED}UNREACHABLE{color.RST}")
        else:
            print(f"  {fip:<18s}{color.RED}{'—':<20s}{'—':<16s}"
                  f"{'—':>5s}  {'░' * 10}  UNREACHABLE{color.RST}")

    print(f"  {'─' * W}")

    # Fleet-wide totals
    all_findings = []
    for data in all_results.values():
        all_findings.extend(data['findings'])

    total_checks = len(all_findings)
    total_passed = sum(1 for f in all_findings if f.passed)

    if numbered:
        pct = (int(total_passed / total_checks * 100)
               if total_checks else 0)
        print(f"  {color.BOLD}Fleet:{color.RST} "
              f"{total_passed}/{total_checks} passed ({pct}%)"
              f"  {color.DIM}{elapsed:.0f}s{color.RST}")
    else:
        total_failed = total_checks - total_passed
        print()
        print(f"  {color.BOLD}Fleet score:{color.RST}  "
              f"{total_passed}/{total_checks} checks passed")
        print(_score_bar(total_passed, total_checks,
                         width=24, color=color))

    # Common findings across fleet
    finding_counts = {}
    for f in all_findings:
        if not f.passed:
            finding_counts[f.check_id] = (
                finding_counts.get(f.check_id, 0) + 1)

    ordered_fixable = []
    if finding_counts:
        max_count = max(finding_counts.values())
        sorted_findings = sorted(finding_counts.items(),
                                 key=lambda x: (-x[1], x[0]))

        if numbered:
            print()
            fix_num = 0
            for cid, count in sorted_findings:
                bar_w = (min(count * 20 // max_count, 20)
                         if max_count else 0)
                bar_str = '█' * bar_w
                sev = ('RED' if cid.startswith('sec-hidisc')
                       or cid == 'sys-default-passwords'
                       else 'YEL')
                sc = getattr(color, sev, '')
                if cid in HARDEN_DISPATCH:
                    fix_num += 1
                    ordered_fixable.append(cid)
                    prefix = (f"  {color.CYN}[{fix_num}]"
                              f"{color.RST} ")
                else:
                    prefix = "      "
                print(f"{prefix}{cid:<28s}"
                      f"{count:>2d}/{n_ok}  "
                      f"{sc}{bar_str}{color.RST}")
        else:
            print(f"\n  {color.BOLD}┌─ Common findings "
                  f"{'─' * (W - 21)}┐{color.RST}")
            for cid, count in sorted_findings:
                bar_w = (min(count * 20 // max_count, 20)
                         if max_count else 0)
                bar_str = '█' * bar_w
                sev = ('RED' if cid.startswith('sec-hidisc')
                       or cid == 'sys-default-passwords'
                       else 'YEL')
                sc = getattr(color, sev, '')
                print(f"  {color.BOLD}│{color.RST}  {cid:<28s}"
                      f"{count:>2d}/{n_ok}  "
                      f"{sc}{bar_str}{color.RST}")
            print(f"  {color.BOLD}└{'─' * (W - 1)}┘{color.RST}")

    if not numbered:
        print(f"\n  {color.DIM}Completed in "
              f"{elapsed:.1f}s{color.RST}\n")
    else:
        print()

    return ordered_fixable if numbered else None

# ---------------------------------------------------------------------------
# JSON / report file output
# ---------------------------------------------------------------------------

def to_json(findings, device_info=None):
    """Return findings as JSON-serialisable dict."""
    result = {
        'findings': [f.to_dict() for f in findings],
        'timestamp': datetime.now().isoformat(),
        'level': 'SL1',
    }
    if device_info:
        result['device'] = device_info
    total = len(findings)
    passed = sum(1 for f in findings if f.passed)
    result['score'] = {
        'total': total,
        'passed': passed,
        'failed': total - passed,
    }
    return result


def fleet_to_json(all_results, failures):
    """Return full fleet results as JSON-serialisable dict."""
    output = {
        'fleet': {},
        'failures': {ip: err for ip, err in failures},
        'timestamp': datetime.now().isoformat(),
        'level': 'SL1',
    }
    for ip, data in all_results.items():
        output['fleet'][ip] = to_json(data['findings'], data['device'])
    return output


def save_report(report_dict, output_path):
    """Write report JSON to file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report_dict, f, indent=2)


def auto_report_path(ip=None, suffix='audit'):
    """Generate a timestamped report path in output/ dir."""
    output_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'output')
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    tag = ip.replace('.', '-') if ip else 'fleet'
    return os.path.join(output_dir, f'justin_{tag}_{suffix}_{ts}.json')


def load_report(report_path):
    """Load a saved audit report for two-step hardening."""
    with open(report_path, 'r') as f:
        data = json.load(f)
    return data


# ---------------------------------------------------------------------------
# Session log — incremental JSON, the JUSTIN way: record everything
# ---------------------------------------------------------------------------

class SessionLog:
    """Incremental JSON session file — written on gather, updated on change.

    The JUSTIN way: always leave a paper trail. Every run produces a session
    file in output/ that captures device info, state, findings, every change
    made, and before/after diffs.
    """

    def __init__(self, ip, output_dir=None):
        self.data = {
            'tool': 'JUSTIN',
            'version': '0.1',
            'ip': ip,
            'started': datetime.now().isoformat(),
            'device': {},
            'config_status': {},
            'config_backup': None,
            'state_before': {},
            'findings': [],
            'score': {},
            'changes': [],
            'state_after': {},
            'state_diff': [],
            'watchdog': None,
            'completed': None,
        }
        if output_dir is None:
            output_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), 'output')
        os.makedirs(output_dir, exist_ok=True)
        tag = ip.replace('.', '-')
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.path = os.path.join(
            output_dir, f'justin_{tag}_session_{ts}.json')

    def update(self, **kwargs):
        """Update session data and flush to disk."""
        self.data.update(kwargs)
        self._write()

    def add_change(self, entry):
        """Append a change log entry and flush to disk."""
        self.data.setdefault('changes', []).append(entry)
        self._write()

    def finish(self):
        """Mark session complete and write final state."""
        self.data['completed'] = datetime.now().isoformat()
        self._write()

    def _write(self):
        self.data['updated'] = datetime.now().isoformat()
        with open(self.path, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Dirty-config guard — the JUSTIN way: never work on unsaved switches
# ---------------------------------------------------------------------------

def check_config_saved(device, color=C):
    """Check if the switch has unsaved config. Returns (saved: bool, status: dict)."""
    try:
        status = device.get_config_status()
        return status.get('saved', True), status
    except Exception:
        # If we can't check, warn but don't block
        return True, {'saved': True, 'nvm': 'unknown'}


def enforce_clean_config(device, ip, mode, color=C):
    """Refuse to harden a dirty switch. Audit gets a warning. Returns True if OK."""
    saved, status = check_config_saved(device, color)
    if saved:
        _progress(f"  {color.GRN}Config status: saved{color.RST}")
        return True

    nvm_state = status.get('nvm', 'unknown')
    if mode == 'harden':
        print(f"\n  {color.RED}{color.BOLD}REFUSED:{color.RST} "
              f"{ip} has unsaved config changes (NVM: {nvm_state})")
        print(f"  {color.RED}JUSTIN will not modify an unsaved switch.{color.RST}")
        print(f"  {color.DIM}Save the config first, then re-run.{color.RST}\n")
        return False
    else:
        print(f"  {color.YEL}WARNING:{color.RST} "
              f"{ip} has unsaved config changes (NVM: {nvm_state})")
        return True

# ---------------------------------------------------------------------------
# Hardening phase — with changes log and before/after
# ---------------------------------------------------------------------------

HARDEN_DISPATCH = {}

def register_harden(check_id):
    def decorator(fn):
        HARDEN_DISPATCH[check_id] = fn
        return fn
    return decorator


@register_harden('sec-hidiscovery')
def harden_hidiscovery(device, spec, config, color=C):
    device.set_hidiscovery('off')
    return "set_hidiscovery('off')"


@register_harden('sec-insecure-protocols')
def harden_insecure_protocols(device, spec, config, color=C):
    device.set_services(http=False, telnet=False)
    return "set_services(http=False, telnet=False)"


@register_harden('sec-login-policy')
def harden_login_policy(device, spec, config, color=C):
    defaults = spec.get('harden_defaults', {})
    device.set_login_policy(
        max_login_attempts=defaults.get('max_login_attempts', 5),
        lockout_duration=defaults.get('lockout_duration', 60),
        min_password_length=defaults.get('min_password_length', 8),
    )
    return ("set_login_policy(max_login_attempts=5, "
            "lockout_duration=60, min_password_length=8)")


@register_harden('sec-time-sync')
def harden_time_sync(device, spec, config, color=C):
    ntp_server = config.get('ntp_server')
    if not ntp_server:
        return None
    device.set_ntp(client_enabled=True)
    return f"set_ntp(client_enabled=True) [server={ntp_server}]"


@register_harden('sec-logging')
def harden_logging(device, spec, config, color=C):
    syslog_server = config.get('syslog_server')
    if not syslog_server:
        return None
    port = config.get('syslog_port', 514)
    device.set_syslog(
        enabled=True,
        servers=[{'index': 1, 'ip': syslog_server, 'port': port,
                  'severity': 'warning', 'transport': 'udp'}])
    return (f"set_syslog(enabled=True, "
            f"servers=[{{ip: '{syslog_server}', port: {port}}}])")


@register_harden('sec-snmpv1-traps')
def harden_snmpv1_traps(device, spec, config, color=C):
    device.set_snmp_config(v1=False)
    return "set_snmp_config(v1=False)"


@register_harden('sec-snmpv1v2-write')
def harden_snmpv1v2_write(device, spec, config, color=C):
    device.set_snmp_config(v1=False, v2=False)
    return "set_snmp_config(v1=False, v2=False)"


def _make_state_snapshot(state):
    """Deep-copy state dict for before/after comparison (JSON-safe)."""
    try:
        return json.loads(json.dumps(state, default=str))
    except (TypeError, ValueError):
        return {}


def _diff_states(before, after):
    """Compare two state dicts, return list of changes."""
    changes = []
    all_keys = set(list(before.keys()) + list(after.keys()))
    for key in sorted(all_keys):
        b = before.get(key)
        a = after.get(key)
        if b != a:
            changes.append({
                'getter': key,
                'before': b,
                'after': a,
            })
    return changes


# ---------------------------------------------------------------------------
# Snapshot helpers — stolen from MOHAWC, proven on hardware
# ---------------------------------------------------------------------------

def _is_valid_profile_name(name):
    """Profile names: alphanumeric, hyphens, underscores only."""
    return bool(name and re.match(r'^[A-Za-z0-9_-]+$', name))


def _do_snapshot(device, name):
    """Create a named NVM config snapshot. MOPS only.

    Downloads the active NVM profile, uploads it under a new name.
    Collision-avoidant (appends -1, -2, etc. if name exists).
    Returns the final snapshot name.
    """
    profiles = device.get_profiles()
    active = [p for p in profiles if p.get('active')]
    if not active:
        raise RuntimeError('no active profile found')
    active_name = active[0]['name']

    # Collision avoidance
    existing = {p['name'] for p in profiles}
    final = name
    if name in existing:
        n = 1
        while f'{name}-{n}' in existing:
            n += 1
        final = f'{name}-{n}'

    nvm_cfg = device.get_config(profile=active_name, source='nvm')
    device.load_config(nvm_cfg['running'], profile=final, destination='nvm')
    return final


def _worker_save_connect(driver, config, ip):
    """Connect to device, save config, close. For fleet phase 4."""
    try:
        device = driver(
            hostname=ip, username=config['username'],
            password=config['password'], timeout=30,
            optional_args={'protocol_preference': [config['protocol']]})
        device.open()
        device.save_config()
        device.close()
        return ip, 'OK', None
    except Exception as e:
        return ip, 'FAIL', str(e)


def _worker_snapshot_connect(driver, config, ip, name):
    """Connect to device, create snapshot, close. For fleet phase 4."""
    try:
        device = driver(
            hostname=ip, username=config['username'],
            password=config['password'], timeout=30,
            optional_args={'protocol_preference': [config['protocol']]})
        device.open()
        final = _do_snapshot(device, name)
        device.close()
        return ip, 'OK', final
    except Exception as e:
        return ip, 'FAIL', str(e)


def harden_device(device, findings, check_defs, config, dry_run=True,
                  save=False, color=C, state_before=None,
                  gather_fn=None, watchdog_seconds=None, session=None):
    """Apply remediation for failed findings. Returns (applied, changes_log, state_diff).

    The JUSTIN way: record everything. Before/after state. Every call logged.
    Watchdog safety net: start timer before changes, stop on success,
    auto-revert on failure/timeout.
    """
    fixable = [f for f in findings
               if not f.passed and f.check_id in HARDEN_DISPATCH]
    if not fixable:
        print(f"  {color.GRN}No fixable findings.{color.RST}\n")
        return [], [], []

    # Capture config backup before any changes
    if not dry_run:
        try:
            config_backup = device.get_config()
            _progress(f"  {color.DIM}Config backup captured{color.RST}")
            if session:
                session.update(config_backup='captured (get_config)')
        except Exception:
            _progress(f"  {color.DIM}Config backup not available "
                      f"(SSH-only feature){color.RST}")
            if session:
                session.update(config_backup='unavailable')

    # Watchdog safety net
    watchdog_active = False
    if watchdog_seconds and not dry_run:
        try:
            device.start_watchdog(watchdog_seconds)
            watchdog_active = True
            print(f"  {color.CYN}Watchdog started: {watchdog_seconds}s "
                  f"rollback timer{color.RST}")
            if session:
                session.update(watchdog={
                    'started': True, 'seconds': watchdog_seconds,
                    'stopped': False})
        except Exception as e:
            print(f"  {color.YEL}Watchdog unavailable: {e}{color.RST}")
            if session:
                session.update(watchdog={'started': False, 'error': str(e)})

    print(f"\n  {color.BOLD}Hardening ({len(fixable)} fixable):{color.RST}")
    applied = []
    changes_log = []

    for f in fixable:
        spec = check_defs.get(f.check_id, {})
        fn = HARDEN_DISPATCH[f.check_id]
        ts = datetime.now().isoformat()

        if dry_run:
            print(f"    {color.CYN}[DRY-RUN]{color.RST} "
                  f"{f.check_id}: {f.fix_cmd or '?'}")
            entry = {
                'check_id': f.check_id,
                'action': f.fix_cmd or '?',
                'result': 'dry-run',
                'timestamp': ts,
            }
            changes_log.append(entry)
            applied.append(f.check_id)
            if session:
                session.add_change(entry)
            continue

        print(f"    {f.check_id}: ", end='', flush=True)
        try:
            result = fn(device, spec, config, color)
            if result is None:
                print(f"{color.YEL}SKIP (missing config value){color.RST}")
                entry = {
                    'check_id': f.check_id,
                    'action': f.fix_cmd or '?',
                    'result': 'skipped',
                    'reason': 'missing config value',
                    'timestamp': ts,
                }
            else:
                print(f"{result} ... {color.GRN}OK{color.RST}")
                applied.append(f.check_id)
                entry = {
                    'check_id': f.check_id,
                    'action': result,
                    'result': 'applied',
                    'timestamp': ts,
                }
            changes_log.append(entry)
            if session:
                session.add_change(entry)
        except Exception as e:
            print(f"{color.RED}FAIL ({e}){color.RST}")
            logging.error("Harden %s failed: %s", f.check_id, e)
            entry = {
                'check_id': f.check_id,
                'action': f.fix_cmd or '?',
                'result': 'failed',
                'error': str(e),
                'timestamp': ts,
            }
            changes_log.append(entry)
            if session:
                session.add_change(entry)

    # Before/after state diff
    state_diff = []
    if not dry_run and applied and state_before is not None and gather_fn:
        _progress(f"\n  {color.DIM}Re-gathering state for before/after diff ...{color.RST}")
        state_after = gather_fn()
        snap_after = _make_state_snapshot(state_after)
        state_diff = _diff_states(state_before, snap_after)
        if state_diff:
            print(f"\n  {color.BOLD}State changes:{color.RST}")
            for d in state_diff:
                print(f"    {color.CYN}{d['getter']}{color.RST}: changed")
        if session:
            session.update(state_after=snap_after, state_diff=state_diff)

    # Stop watchdog on success (confirmed changes)
    if watchdog_active and applied:
        try:
            device.stop_watchdog()
            print(f"  {color.GRN}Watchdog stopped (changes confirmed){color.RST}")
            if session:
                session.update(watchdog={
                    'started': True, 'seconds': watchdog_seconds,
                    'stopped': True})
        except Exception as e:
            print(f"  {color.YEL}WARNING: Watchdog stop failed: {e} "
                  f"— timer still running!{color.RST}")

    if save and not dry_run and applied:
        print(f"\n  Saving config to NVM ... ", end='', flush=True)
        try:
            device.save_config()
            print(f"{color.GRN}OK{color.RST}")
            entry = {
                'check_id': '_save_config',
                'action': 'save_config()',
                'result': 'applied',
                'timestamp': datetime.now().isoformat(),
            }
            changes_log.append(entry)
            if session:
                session.add_change(entry)
        except Exception as e:
            print(f"{color.RED}FAIL ({e}){color.RST}")
            entry = {
                'check_id': '_save_config',
                'action': 'save_config()',
                'result': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }
            changes_log.append(entry)
            if session:
                session.add_change(entry)

    print()
    return applied, changes_log, state_diff

# ---------------------------------------------------------------------------
# Device-level audit
# ---------------------------------------------------------------------------

def audit_device(driver, config, ip, check_defs, color=C):
    """Connect to a single device, gather state, run checks.

    Returns (ip, device, device_info, findings, state, error).
    Device is left open so callers can harden after audit.
    """
    device = None
    try:
        device = driver(
            hostname=ip,
            username=config['username'],
            password=config['password'],
            timeout=30,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()

        facts = {}
        try:
            facts = device.get_facts()
        except Exception:
            pass
        device_info = {
            'ip': ip,
            'hostname': facts.get('hostname', ip),
            'model': facts.get('model', '?'),
            'os_version': facts.get('os_version', '?'),
        }

        state = gather(device, check_defs, color)
        findings = run_checks(state, check_defs, config, color)

        return ip, device, device_info, findings, state, None
    except Exception as e:
        if device:
            try:
                device.close()
            except Exception:
                pass
        return ip, None, None, None, None, str(e)


def worker_audit(driver, config, ip, check_defs):
    """Thread worker for fleet mode."""
    device = None
    try:
        device = driver(
            hostname=ip,
            username=config['username'],
            password=config['password'],
            timeout=30,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()

        facts = {}
        try:
            facts = device.get_facts()
        except Exception:
            pass
        device_info = {
            'ip': ip,
            'hostname': facts.get('hostname', ip),
            'model': facts.get('model', '?'),
            'os_version': facts.get('os_version', '?'),
        }

        # Gather silently (no per-getter output in fleet mode)
        getters = set()
        for spec in check_defs.values():
            if spec.get('getter'):
                getters.add(spec['getter'])
        state = {}
        for getter_name in sorted(getters):
            try:
                state[getter_name] = getattr(device, getter_name)()
            except Exception:
                state[getter_name] = None

        # Run checks silently
        findings = []
        for check_id, spec in check_defs.items():
            fn = CHECK_FNS.get(check_id)
            if fn:
                findings.append(fn(state, spec, config))
        findings.sort(key=lambda f: (
            f.passed, SEVERITY_ORDER.get(f.severity, 9), f.check_id))

        device.close()
        return ip, device_info, findings, None
    except Exception as e:
        return ip, None, None, str(e)
    finally:
        if device:
            try:
                device.close()
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Two-step: harden from saved report
# ---------------------------------------------------------------------------

def harden_from_report(driver, config, report_data, check_defs,
                       dry_run=True, save=False, color=C,
                       watchdog_seconds=None, snapshot_name=None):
    """Load findings from a saved audit report and apply hardening."""
    # Report can be single device or fleet
    if 'fleet' in report_data:
        devices = report_data['fleet']
    else:
        # Single device report
        ip = report_data.get('device', {}).get('ip')
        if not ip:
            print(f"  {color.RED}Report has no device IP.{color.RST}\n")
            return
        devices = {ip: report_data}

    for ip, device_data in devices.items():
        finding_dicts = device_data.get('findings', [])
        findings = [Finding.from_dict(fd) for fd in finding_dicts]
        failed = [f for f in findings
                  if not f.passed and f.check_id in HARDEN_DISPATCH]
        if not failed:
            print(f"  {ip}: no fixable findings in report")
            continue

        print(f"\n  {color.BOLD}Hardening {ip} from report ...{color.RST}")
        device = None
        try:
            device = driver(
                hostname=ip,
                username=config['username'],
                password=config['password'],
                timeout=30,
                optional_args={'protocol_preference': [config['protocol']]},
            )
            device.open()

            # Dirty-config guard
            if not dry_run:
                if not enforce_clean_config(device, ip, 'harden', color):
                    continue

            # Gather state for before/after
            state = gather(device, check_defs, color)
            snap_before = _make_state_snapshot(state)
            gather_fn = lambda d=device: gather(d, check_defs, color)

            session = SessionLog(ip)
            session.update(mode='harden-from-report')

            applied, changes_log, state_diff = harden_device(
                device, findings, check_defs, config,
                dry_run=dry_run, save=save, color=color,
                state_before=snap_before, gather_fn=gather_fn,
                watchdog_seconds=watchdog_seconds, session=session)

            # Snapshot per device
            if (snapshot_name and not dry_run and applied
                    and save and config['protocol'] == 'mops'
                    and _is_valid_profile_name(snapshot_name)):
                print(f"  Snapshot '{snapshot_name}' ... ",
                      end='', flush=True)
                try:
                    final = _do_snapshot(device, snapshot_name)
                    print(f"{color.GRN}OK{color.RST}")
                    session.add_change({
                        'check_id': '_snapshot',
                        'action': f"snapshot('{final}')",
                        'result': 'applied',
                        'timestamp': datetime.now().isoformat(),
                    })
                except Exception as e:
                    print(f"{color.RED}FAIL ({e}){color.RST}")

            session.finish()
            _progress(f"  {color.DIM}Session: {session.path}{color.RST}")
            device.close()
        except Exception as e:
            print(f"  {color.RED}FAIL: {e}{color.RST}")
        finally:
            if device:
                try:
                    device.close()
                except Exception:
                    pass

# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------

def _cls():
    """Clear terminal screen."""
    print('\033[2J\033[H', end='', flush=True)


def _ibar(current, total, label='', width=30):
    """Overwriting progress bar for interactive mode."""
    filled = int(current / total * width) if total else 0
    bar = f"{C.GRN}{'█' * filled}{C.DIM}{'░' * (width - filled)}{C.RST}"
    print(f'\r  [{bar}] {current}/{total}  {C.DIM}{label:<30s}{C.RST}',
          end='', flush=True)
    if current >= total:
        print()


_IBANNER = (
    f"\n  {C.MG}{C.BOLD} ╦╦ ╦╔═╗╔╦╗╦╔╗╔{C.RST}\n"
    f"  {C.MG}{C.BOLD} ║║ ║╚═╗ ║ ║║║║{C.RST}\n"
    f"  {C.MG}{C.BOLD}╚╝╚═╝╚═╝ ╩ ╩╝╚╝{C.RST}\n"
    f"  {C.DIM}Justified Unified Security Testing "
    f"for Industrial Networks{C.RST}\n"
    f"  {C.CYN}{'━' * 58}{C.RST}\n"
)


def _parse_selection(raw, max_val):
    """Parse multi-select: '1', '1,3,5', '1-3', '1-3,5', 'a' → set of 0-based indices."""
    raw = raw.strip().lower()
    if raw in ('a', 'all', ''):
        return set(range(max_val))
    indices = set()
    for part in raw.split(','):
        part = part.strip()
        if '-' in part:
            try:
                lo, hi = part.split('-', 1)
                for i in range(int(lo), int(hi) + 1):
                    if 1 <= i <= max_val:
                        indices.add(i - 1)
            except ValueError:
                pass
        else:
            try:
                i = int(part)
                if 1 <= i <= max_val:
                    indices.add(i - 1)
            except ValueError:
                pass
    return indices


def _igather(device, check_defs):
    """Gather state with interactive progress bar. Returns state dict."""
    getters = sorted(set(
        s['getter'] for s in check_defs.values() if s.get('getter')))
    state = {}
    for i, g in enumerate(getters, 1):
        _ibar(i, len(getters), g + '()')
        try:
            state[g] = getattr(device, g)()
        except Exception:
            state[g] = None
    return state


def _phase4_exit(device, session, config, color=C):
    """Phase 4: Save & exit gate for a single device.

    Prompts to save config to NVM and create a named snapshot.
    Snapshot requires MOPS protocol. Only runs if changes were applied.
    """
    changes = session.data.get('changes', [])
    applied = [c for c in changes
               if c.get('result') == 'applied'
               and c.get('check_id', '').startswith(('sec-', 'ns-'))]
    if not applied:
        return

    print(f'\n  {color.MG}{color.BOLD}── Save & Exit ──{color.RST}')
    print(f'  {color.DIM}{len(applied)} change(s) applied{color.RST}')

    # Save to NVM
    save_raw = input(
        f'  {color.GRN}▸{color.RST} Save to NVM? '
        f'{color.DIM}[Y/n]{color.RST}: ').strip().lower()
    if save_raw in ('n', 'no'):
        print(f'  {color.YEL}Changes NOT saved — '
              f'will revert on reboot{color.RST}')
        return

    print(f'  Saving to NVM ... ', end='', flush=True)
    try:
        device.save_config()
        print(f'{color.GRN}OK{color.RST}')
        session.add_change({
            'check_id': '_save_config',
            'action': 'save_config()',
            'result': 'applied',
            'timestamp': datetime.now().isoformat(),
        })
    except Exception as e:
        print(f'{color.RED}FAIL ({e}){color.RST}')
        return

    # Snapshot (MOPS only)
    if config.get('protocol') != 'mops':
        return

    snap_raw = input(
        f'  {color.GRN}▸{color.RST} Create snapshot? '
        f'{color.DIM}[Y/n]{color.RST}: ').strip().lower()
    if snap_raw in ('n', 'no'):
        return

    ts = datetime.now().strftime('%Y%m%d')
    default_name = f'SL1-{ts}'
    name = input(
        f'  {color.GRN}▸{color.RST} Snapshot name '
        f'{color.DIM}[{default_name}]{color.RST}: ').strip()
    if not name:
        name = default_name

    if not _is_valid_profile_name(name):
        print(f'  {color.RED}Invalid name (use letters, numbers, '
              f'hyphens, underscores){color.RST}')
        return

    print(f"  Snapshot '{name}' ... ", end='', flush=True)
    try:
        final = _do_snapshot(device, name)
        if final != name:
            print(f"{color.GRN}OK (as '{final}'){color.RST}")
        else:
            print(f'{color.GRN}OK{color.RST}')
        session.add_change({
            'check_id': '_snapshot',
            'action': f"snapshot('{final}')",
            'result': 'applied',
            'timestamp': datetime.now().isoformat(),
        })
    except Exception as e:
        print(f'{color.RED}FAIL ({e}){color.RST}')


def _print_fleet_live(all_ips, all_results, failures, completed,
                      total, color=C):
    """Print live fleet audit screen — devices fill in as they complete."""
    _cls()
    W = 60
    ts = datetime.now().strftime('%Y-%m-%d %H:%M')
    title = "JUSTIN — IEC 62443-4-2 Fleet Audit"
    sub = f"{total} devices  SL1  {ts}"
    print()
    print(f"  {color.MG}{color.BOLD}╔{'═' * W}╗{color.RST}")
    tpad = max(W - len(title) - 2, 0)
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"  {color.MG}{color.BOLD}JUSTIN{color.RST}"
          f"{color.BOLD} — IEC 62443-4-2 Fleet Audit{color.RST}"
          f"{' ' * tpad}"
          f"{color.MG}{color.BOLD}║{color.RST}")
    spad = max(W - len(sub) - 2, 0)
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"  {color.DIM}{sub}{color.RST}"
          f"{' ' * spad}"
          f"{color.MG}{color.BOLD}║{color.RST}")
    print(f"  {color.MG}{color.BOLD}╚{'═' * W}╝{color.RST}")
    print()

    failed_ips = {fip for fip, _ in failures}

    for idx, ip in enumerate(all_ips, 1):
        prefix = f"  {color.CYN}[{idx}]{color.RST} "
        if ip in all_results:
            data = all_results[ip]
            di = data['device']
            findings = data['findings']
            t = len(findings)
            p = sum(1 for f in findings if f.passed)
            failed = t - p
            has_crit = any(not f.passed and f.severity == 'critical'
                           for f in findings)
            sc = (color.RED if has_crit
                  else color.YEL if failed else color.GRN)
            bar_w = 10
            bar_filled = int(p / t * bar_w) if t else 0
            filled = '█' * bar_filled
            empty = '░' * (bar_w - bar_filled)
            bar = f"{sc}{filled}{empty}{color.RST}"
            name = di.get('hostname', ip)[:18]
            print(f"{prefix}{ip:<18s}{name:<20s}"
                  f"{sc}{p:>2d}/{t:<2d}{color.RST}  {bar}")
        elif ip in failed_ips:
            print(f"{prefix}{ip:<18s}"
                  f"{color.RED}UNREACHABLE{color.RST}")
        else:
            print(f"{prefix}{ip:<18s}"
                  f"{color.DIM}...{color.RST}")

    print()

    if completed < total:
        print(f"  {color.DIM}Auditing ... "
              f"{completed}/{total}{color.RST}")
    else:
        all_findings = []
        for data in all_results.values():
            all_findings.extend(data['findings'])
        tc = len(all_findings)
        tp = sum(1 for f in all_findings if f.passed)
        pct = int(tp / tc * 100) if tc else 0
        print(f"  {color.BOLD}Fleet:{color.RST} "
              f"{tp}/{tc} passed ({pct}%)")

    # Error section
    if failures:
        print()
        for fip, ferr in failures:
            err_short = str(ferr)[:50]
            print(f"  {color.RED}✗ {fip}: "
                  f"{err_short}{color.RST}")


def _print_device_compact(findings, device_info, color=C):
    """Compact single-device view for interactive mode.

    Shows device header, failing findings sorted by severity with
    [N] indices for fixable ones, and summary.
    Returns ordered list of fixable Finding objects.
    """
    ip = device_info.get('ip', '?')
    model = device_info.get('model', '?')
    fw = device_info.get('os_version', '?')
    hostname = device_info.get('hostname', '?')
    total = len(findings)
    passed = sum(1 for f in findings if f.passed)
    failed = total - passed

    # Header with box border
    W = 68
    print()
    print(f"  {color.MG}{color.BOLD}╔{'═' * W}╗{color.RST}")
    title = f"JUSTIN — {ip}"
    sub = f"({model}, {fw})"
    inner_pad = W - len(title) - len(sub) - 4
    if inner_pad < 1:
        inner_pad = 1
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"  {color.MG}{color.BOLD}JUSTIN{color.RST}"
          f"{color.BOLD} — {ip}{color.RST}"
          f"{' ' * inner_pad}"
          f"{color.DIM}{sub}{color.RST}"
          f"  {color.MG}{color.BOLD}║{color.RST}")

    # Score bar
    has_crit = any(not f.passed and f.severity == 'critical'
                   for f in findings)
    sc = (color.RED if has_crit
          else color.YEL if failed else color.GRN)
    bar_w = 16
    bar_filled = int(passed / total * bar_w) if total else 0
    bar = (f"{sc}{'█' * bar_filled}"
           f"{'░' * (bar_w - bar_filled)}{color.RST}")

    name = hostname if hostname and hostname != ip else ''
    score_txt = f"{passed}/{total} passed"
    # Visible chars inside ║...║: 2 + name(20) + score_txt + 3 + bar(16) + pad + 2
    score_vis = 2 + 20 + len(score_txt) + 3 + bar_w + 2
    score_pad = max(W - score_vis, 0)
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"  {name:<20s}"
          f"{sc}{score_txt}{color.RST}   {bar}"
          f"{' ' * score_pad}"
          f"  {color.MG}{color.BOLD}║{color.RST}")
    print(f"  {color.MG}{color.BOLD}╚{'═' * W}╝{color.RST}")

    # Failing findings sorted by severity (critical first)
    fail_list = sorted(
        [f for f in findings if not f.passed],
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9),
                       f.check_id))

    fixable = []
    fix_num = 0

    if fail_list:
        print()
        for f in fail_list:
            badge = _severity_badge(f, color)
            print(f"  {badge} {f.check_id:<26s}"
                  f"{color.DIM}{f.clause:<9s}{color.RST}"
                  f"{f.desc}")
            if f.check_id in HARDEN_DISPATCH and f.fix_cmd:
                fix_num += 1
                fixable.append(f)
                print(f"     {color.CYN}[{fix_num}]{color.RST} "
                      f"{color.DIM}→ {f.fix_cmd}{color.RST}")

    # Summary
    n_fixable = len(fixable)
    n_other = failed - n_fixable
    print()
    parts = [f"{passed} passed"]
    if n_fixable:
        parts.append(f"{n_fixable} fixable")
    if n_other:
        parts.append(f"{n_other} advisory/not assessed")
    print(f"  {color.DIM}{'  ·  '.join(parts)}{color.RST}")

    return fixable


# ---------------------------------------------------------------------------
# Single-device interactive REPL
# ---------------------------------------------------------------------------

def _interactive_single(driver, config, ip, check_defs, color=C):
    """Single-device REPL — audit, fix, verify, repeat.

    Returns final findings list (for fleet drill-down score updates).
    """
    device = None
    findings = []
    device_info = {'ip': ip}

    try:
        # Connect
        _cls()
        print(_IBANNER)
        print(f'  {C.BOLD}Connecting to {ip} ...{C.RST}\n')

        device = driver(
            hostname=ip,
            username=config['username'],
            password=config['password'],
            timeout=30,
            optional_args={'protocol_preference': [config['protocol']]},
        )
        device.open()

        facts = {}
        try:
            facts = device.get_facts()
        except Exception:
            pass
        device_info = {
            'ip': ip,
            'hostname': facts.get('hostname', ip),
            'model': facts.get('model', '?'),
            'os_version': facts.get('os_version', '?'),
        }

        session = SessionLog(ip)
        session.update(device=device_info)

        # Gather with progress bar
        state = _igather(device, check_defs)
        session.update(state_before=_make_state_snapshot(state))

        # Run checks quietly (progress bar was the visual)
        findings = run_checks(state, check_defs, config, color, quiet=True)

        total = len(findings)
        passed = sum(1 for f in findings if f.passed)
        session.update(
            findings=[f.to_dict() for f in findings],
            score={'total': total, 'passed': passed,
                   'failed': total - passed})

        # CLS → compact device view
        _cls()
        fixable = _print_device_compact(findings, device_info, color)

        # ── REPL ──
        while True:
            if fixable:
                print(f'\n  {C.CYN}[h]{C.RST}arden  '
                      f'{C.CYN}[r]{C.RST}eport  '
                      f'{C.CYN}[q]{C.RST}uit')
            else:
                print(f'\n  {C.CYN}[r]{C.RST}eport  '
                      f'{C.CYN}[q]{C.RST}uit')

            choice = input(f'  {C.GRN}▸{C.RST} ').strip().lower()

            if choice in ('q', 'quit', ''):
                break
            if choice in ('r', 'report'):
                default_path = auto_report_path(ip)
                name = input(
                    f'  {C.GRN}▸{C.RST} Filename '
                    f'{C.DIM}[{os.path.basename(default_path)}]'
                    f'{C.RST}: ').strip()
                path = name if name else default_path
                if not os.path.isabs(path):
                    path = os.path.join(
                        os.path.dirname(default_path), path)
                report = to_json(findings, device_info)
                save_report(report, path)
                print(f'  Saved to {path}')
                break
            if choice not in ('h', 'harden') or not fixable:
                continue

            # Findings multi-select (after explicit harden intent)
            fix_raw = input(
                f'  {C.GRN}▸{C.RST} Findings '
                f'{C.DIM}[a]{C.RST}: ').strip()
            sel = _parse_selection(fix_raw or 'a', len(fixable))
            if not sel:
                continue
            to_fix = [fixable[i] for i in sorted(sel)]

            # Prompt for missing config-dependent values
            for f in to_fix:
                if (f.check_id == 'sec-logging'
                        and not config.get('syslog_server')):
                    val = input(f'  {C.GRN}▸{C.RST} '
                                f'Syslog server IP: ').strip()
                    if val:
                        config['syslog_server'] = val
                if (f.check_id == 'sec-time-sync'
                        and not config.get('ntp_server')):
                    val = input(f'  {C.GRN}▸{C.RST} '
                                f'NTP server IP: ').strip()
                    if val:
                        config['ntp_server'] = val

            # Apply fixes
            print()
            for f in to_fix:
                fn = HARDEN_DISPATCH[f.check_id]
                spec = check_defs.get(f.check_id, {})
                print(f'    {f.check_id}: ', end='', flush=True)
                try:
                    result = fn(device, spec, config, color)
                    if result is None:
                        print(f'{C.YEL}SKIP (missing config value)'
                              f'{C.RST}')
                    else:
                        print(f'{result} ... {C.GRN}OK{C.RST}')
                        session.add_change({
                            'check_id': f.check_id,
                            'action': result,
                            'result': 'applied',
                            'timestamp': datetime.now().isoformat(),
                        })
                except Exception as e:
                    print(f'{C.RED}FAIL ({e}){C.RST}')
                    session.add_change({
                        'check_id': f.check_id,
                        'action': f.fix_cmd or '?',
                        'result': 'failed',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat(),
                    })

            # Re-gather + re-check (verify)
            print(f'\n  {C.DIM}Verifying ...{C.RST}')
            state = _igather(device, check_defs)
            findings = run_checks(
                state, check_defs, config, color, quiet=True)

            total = len(findings)
            passed = sum(1 for f in findings if f.passed)
            session.update(
                state_after=_make_state_snapshot(state),
                findings=[f.to_dict() for f in findings],
                score={'total': total, 'passed': passed,
                       'failed': total - passed})

            # CLS → updated compact view
            _cls()
            fixable = _print_device_compact(findings, device_info, color)

        # ── Phase 4: Save & Exit ──
        _phase4_exit(device, session, config, color)

        # ── Auto-save report on exit ──
        path = auto_report_path(ip)
        report = to_json(findings, device_info)
        save_report(report, path)
        session.finish()
        print(f'  {C.DIM}Report: {path}{C.RST}')
        print(f'  {C.DIM}Session: {session.path}{C.RST}\n')

    except (KeyboardInterrupt, EOFError):
        print(f'\n\n  {C.DIM}Interrupted.{C.RST}\n')
    finally:
        if device:
            try:
                device.close()
            except Exception:
                pass
    return findings


def _fleet_device_view(driver, config, ip, data, check_defs, color=C):
    """Single-device drill-down from fleet REPL.

    Shows compact device view, offers harden/report/return.
    Returns (data_dict, changed_bool).
    """
    changed = False
    _cls()
    fixable = _print_device_compact(
        data['findings'], data['device'], color)

    while True:
        # Menu
        if fixable:
            print(f'\n  {C.CYN}[h]{C.RST}arden  '
                  f'{C.CYN}[r]{C.RST}eport  '
                  f'{C.CYN}[q]{C.RST} Return')
        else:
            print(f'\n  {C.CYN}[r]{C.RST}eport  '
                  f'{C.CYN}[q]{C.RST} Return')

        choice = input(f'  {C.GRN}▸{C.RST} ').strip().lower()

        if choice in ('q', 'quit', ''):
            return data, changed
        if choice in ('r', 'report'):
            default_path = auto_report_path(ip)
            name = input(
                f'  {C.GRN}▸{C.RST} Filename '
                f'{C.DIM}[{os.path.basename(default_path)}]'
                f'{C.RST}: ').strip()
            path = name if name else default_path
            if not os.path.isabs(path):
                path = os.path.join(
                    os.path.dirname(default_path), path)
            report = to_json(data['findings'], data['device'])
            save_report(report, path)
            print(f'  Saved to {path}')
            return data, changed
        if choice not in ('h', 'harden') or not fixable:
            continue

        # Findings multi-select (numbers match [N] in display)
        fix_raw = input(
            f'  {C.GRN}▸{C.RST} Findings '
            f'{C.DIM}[a]{C.RST}: ').strip()
        sel = _parse_selection(fix_raw or 'a', len(fixable))
        if not sel:
            continue
        to_fix = [fixable[i] for i in sorted(sel)]

        # Prompt for config-dependent values
        for f in to_fix:
            if (f.check_id == 'sec-logging'
                    and not config.get('syslog_server')):
                val = input(
                    f'  {C.GRN}▸{C.RST} '
                    f'Syslog server IP: ').strip()
                if val:
                    config['syslog_server'] = val
            if (f.check_id == 'sec-time-sync'
                    and not config.get('ntp_server')):
                val = input(
                    f'  {C.GRN}▸{C.RST} '
                    f'NTP server IP: ').strip()
                if val:
                    config['ntp_server'] = val

        # Connect, apply, verify
        device = None
        try:
            device = driver(
                hostname=ip,
                username=config['username'],
                password=config['password'],
                timeout=30,
                optional_args={
                    'protocol_preference': [config['protocol']]},
            )
            device.open()

            print()
            for f in to_fix:
                fn = HARDEN_DISPATCH[f.check_id]
                spec = check_defs.get(f.check_id, {})
                print(f'    {f.check_id}: ', end='', flush=True)
                try:
                    result = fn(device, spec, config, color)
                    if result is None:
                        print(f'{C.YEL}SKIP{C.RST}')
                    else:
                        print(f'{result} ... {C.GRN}OK{C.RST}')
                        changed = True
                except Exception as e:
                    print(f'{C.RED}FAIL ({e}){C.RST}')

            device.close()
        except Exception as e:
            print(f'  {C.RED}Error: {e}{C.RST}')
        finally:
            if device:
                try:
                    device.close()
                except Exception:
                    pass

        # Re-audit to verify
        print(f'\n  {C.DIM}Verifying ...{C.RST}')
        rip, rdi, rfindings, rerr = worker_audit(
            driver, config, ip, check_defs)
        if not rerr:
            data = {'device': rdi, 'findings': rfindings}

        # CLS → updated compact view
        _cls()
        fixable = _print_device_compact(
            data['findings'], data['device'], color)

    return data, changed


# ---------------------------------------------------------------------------
# Interactive mode — audit → report → fix → verify → repeat
# ---------------------------------------------------------------------------

def interactive_mode():
    """Interactive mode entry point. Loads config, audits, offers fixes."""

    try:
        # ── Load config ──
        cfg_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'script.cfg')
        if os.path.exists(cfg_path):
            config = parse_config(cfg_path)
            _cls()
            print(_IBANNER)
            print(f'  {C.BOLD}CONFIG{C.RST}\n')
            print(f'  {C.DIM}Loaded from script.cfg:{C.RST}')
            print(f'    Devices:   {len(config["devices"])}')
            for dip in config['devices'][:6]:
                print(f'               {C.DIM}{dip}{C.RST}')
            if len(config['devices']) > 6:
                print(f'               {C.DIM}... '
                      f'+{len(config["devices"]) - 6} more{C.RST}')
            print(f'    Protocol:  {config["protocol"]}')
            print(f'    User:      {config["username"]}')
            if config.get('syslog_server'):
                print(f'    Syslog:    {config["syslog_server"]}:'
                      f'{config.get("syslog_port", 514)}')
            if config.get('ntp_server'):
                print(f'    NTP:       {config["ntp_server"]}')
            print()
            proceed = input(
                f'  {C.GRN}▸{C.RST} Press Enter to continue, '
                f'or {C.CYN}m{C.RST} for manual setup: ').strip()
            if proceed.lower() in ('m', 'manual'):
                config = None  # fall through to manual setup
        else:
            config = None

        if config is None:
            _cls()
            print(_IBANNER)
            print(f'  {C.BOLD}SETUP{C.RST}')
            print(f'  {C.DIM}No script.cfg found.{C.RST}\n')
            raw_ips = input(
                f'  {C.GRN}▸{C.RST} Device IP(s): ').strip()
            if not raw_ips:
                print(f'\n  {C.YEL}No devices. Exiting.{C.RST}\n')
                return
            devices = []
            for part in raw_ips.split(','):
                part = part.strip()
                if is_valid_ipv4(part):
                    devices.append(part)
                elif '-' in part.split('.')[-1]:
                    base = '.'.join(part.split('.')[:-1])
                    last_oct = part.split('.')[-1]
                    lo, hi = last_oct.split('-')
                    for i in range(int(lo), int(hi) + 1):
                        devices.append(f'{base}.{i}')
            username = input(
                f'  {C.GRN}▸{C.RST} Username '
                f'{C.DIM}[admin]{C.RST}: ').strip() or 'admin'
            password = input(
                f'  {C.GRN}▸{C.RST} Password '
                f'{C.DIM}[private]{C.RST}: ').strip() or 'private'
            config = {
                'username': username, 'password': password,
                'protocol': 'mops', 'devices': devices,
                'syslog_server': None, 'syslog_port': 514,
                'ntp_server': None, 'banner': None, 'level': 'SL1',
            }

        if not config['devices']:
            print(f'\n  {C.YEL}No devices in config.{C.RST}\n')
            return

        # Import driver
        from napalm import get_network_driver
        driver = get_network_driver('hios')
        check_defs = load_checks()

        # ── Single device ──
        if len(config['devices']) == 1:
            _interactive_single(
                driver, config, config['devices'][0], check_defs)
            return

        # ── Fleet audit with live display ──
        all_ips = sorted(config['devices'])
        all_results = {}
        failures = []
        total_devs = len(all_ips)
        start = time.time()
        completed = 0

        # Show initial screen (all devices pending)
        _print_fleet_live(all_ips, all_results, failures,
                          0, total_devs)

        with ThreadPoolExecutor(max_workers=min(total_devs, 8)) as pool:
            futures = {
                pool.submit(worker_audit, driver, config, ip,
                            check_defs): ip
                for ip in all_ips
            }
            for future in as_completed(futures):
                completed += 1
                ip_r, di, ffindings, err = future.result()
                if err:
                    failures.append((ip_r, err))
                else:
                    all_results[ip_r] = {
                        'device': di, 'findings': ffindings}
                # Redraw with updated results
                _print_fleet_live(all_ips, all_results, failures,
                                  completed, total_devs)

        elapsed = time.time() - start

        # ── Fleet REPL ──
        sorted_ips = sorted(all_results.keys())
        changed_ips = set()

        while True:
            # CLS → fleet report with indices
            _cls()
            ordered_fixable = print_fleet_report(
                all_results, failures, elapsed, numbered=True)

            # Action prompt
            if ordered_fixable:
                print(f'  {C.CYN}[v]{C.RST}iew  '
                      f'{C.CYN}[h]{C.RST}arden  '
                      f'{C.CYN}[r]{C.RST}eport  '
                      f'{C.CYN}[q]{C.RST}uit')
            else:
                print(f'  {C.CYN}[v]{C.RST}iew  '
                      f'{C.CYN}[r]{C.RST}eport  '
                      f'{C.CYN}[q]{C.RST}uit')

            choice = input(
                f'  {C.GRN}▸{C.RST} ').strip().lower()

            if choice in ('q', 'quit', ''):
                break

            if choice in ('v', 'view'):
                dev_raw = input(
                    f'  {C.GRN}▸{C.RST} Device: ').strip()
                try:
                    dev_idx = int(dev_raw) - 1
                    if 0 <= dev_idx < len(sorted_ips):
                        dip = sorted_ips[dev_idx]
                        updated, dev_changed = (
                            _fleet_device_view(
                                driver, config, dip,
                                all_results[dip], check_defs))
                        all_results[dip] = updated
                        if dev_changed:
                            changed_ips.add(dip)
                except (ValueError, IndexError):
                    pass
                continue

            if choice in ('r', 'report'):
                default_path = auto_report_path(suffix='fleet')
                name = input(
                    f'  {C.GRN}▸{C.RST} Filename '
                    f'{C.DIM}[{os.path.basename(default_path)}]'
                    f'{C.RST}: ').strip()
                path = name if name else default_path
                if not os.path.isabs(path):
                    path = os.path.join(
                        os.path.dirname(default_path), path)
                report = fleet_to_json(all_results, failures)
                save_report(report, path)
                print(f'  Saved to {path}')
                break

            if (choice not in ('h', 'harden')
                    or not ordered_fixable):
                continue

            # Two-prompt multi-select (after explicit harden)
            dev_raw = input(
                f'  {C.GRN}▸{C.RST} Devices '
                f'{C.DIM}[a]{C.RST}: ').strip()
            dev_sel = _parse_selection(
                dev_raw or 'a', len(sorted_ips))
            if not dev_sel:
                continue

            fix_raw = input(
                f'  {C.GRN}▸{C.RST} Findings '
                f'{C.DIM}[a]{C.RST}: ').strip()
            fix_sel = _parse_selection(
                fix_raw or 'a', len(ordered_fixable))
            if not fix_sel:
                continue

            selected_ips_list = [sorted_ips[i]
                                for i in sorted(dev_sel)]
            selected_checks = [ordered_fixable[i]
                               for i in sorted(fix_sel)]

            # Prompt for missing config-dependent values
            if ('sec-logging' in selected_checks
                    and not config.get('syslog_server')):
                val = input(
                    f'  {C.GRN}▸{C.RST} '
                    f'Syslog server IP: ').strip()
                if val:
                    config['syslog_server'] = val
            if ('sec-time-sync' in selected_checks
                    and not config.get('ntp_server')):
                val = input(
                    f'  {C.GRN}▸{C.RST} '
                    f'NTP server IP: ').strip()
                if val:
                    config['ntp_server'] = val

            print(f'\n  {C.BOLD}Fixing '
                  f'{len(selected_checks)} finding(s) on '
                  f'{len(selected_ips_list)} device(s) '
                  f'...{C.RST}\n')

            # Apply fixes per device
            fixed_ips = []
            for sip in selected_ips_list:
                data = all_results[sip]
                device_fixable = [
                    f for f in data['findings']
                    if not f.passed
                    and f.check_id in selected_checks
                    and f.check_id in HARDEN_DISPATCH]
                if not device_fixable:
                    print(f'    {sip}: '
                          f'{C.DIM}already passing{C.RST}')
                    continue

                device = None
                try:
                    device = driver(
                        hostname=sip,
                        username=config['username'],
                        password=config['password'],
                        timeout=30,
                        optional_args={
                            'protocol_preference':
                                [config['protocol']]},
                    )
                    device.open()

                    print(f'    {sip}: ', end='', flush=True)
                    for f in device_fixable:
                        fn = HARDEN_DISPATCH[f.check_id]
                        spec = check_defs.get(f.check_id, {})
                        try:
                            result = fn(device, spec, config)
                            if result:
                                print(f'{C.GRN}{f.check_id}'
                                      f'{C.RST} ',
                                      end='', flush=True)
                            else:
                                print(f'{C.YEL}{f.check_id}'
                                      f'(skip){C.RST} ',
                                      end='', flush=True)
                        except Exception as e:
                            print(f'{C.RED}{f.check_id}'
                                  f'(fail){C.RST} ',
                                  end='', flush=True)
                    print()
                    fixed_ips.append(sip)
                    device.close()
                except Exception as e:
                    print(f'{C.RED}FAIL ({e}){C.RST}')
                finally:
                    if device:
                        try:
                            device.close()
                        except Exception:
                            pass

            # Track changed devices
            changed_ips.update(fixed_ips)

            # Re-audit affected devices in parallel
            if fixed_ips:
                print(f'\n  {C.DIM}Verifying '
                      f'{len(fixed_ips)} device(s) ...{C.RST}')
                re_done = 0
                with ThreadPoolExecutor(
                        max_workers=min(len(fixed_ips), 8)
                        ) as pool:
                    futs = {
                        pool.submit(
                            worker_audit, driver, config,
                            fip, check_defs): fip
                        for fip in fixed_ips
                    }
                    for fut in as_completed(futs):
                        re_done += 1
                        rfip = futs[fut]
                        _ibar(re_done, len(fixed_ips), rfip)
                        rip, rdi, rfindings, rerr = (
                            fut.result())
                        if not rerr:
                            all_results[rip] = {
                                'device': rdi,
                                'findings': rfindings}

                elapsed = time.time() - start

        # ── Phase 4: Fleet save & exit ──
        if changed_ips:
            print(f'\n  {C.MG}{C.BOLD}── Save & Exit ──{C.RST}')
            print(f'  {C.DIM}{len(changed_ips)} device(s) '
                  f'with changes:{C.RST}')
            for cip in sorted(changed_ips):
                print(f'    {C.DIM}{cip}{C.RST}')

            save_raw = input(
                f'\n  {C.GRN}▸{C.RST} Save to NVM? '
                f'{C.CYN}[a]{C.RST}ll / '
                f'{C.CYN}[n]{C.RST}o: ').strip().lower()
            if save_raw not in ('n', 'no'):
                save_ok = 0
                with ThreadPoolExecutor(
                        max_workers=min(len(changed_ips), 8)
                        ) as pool:
                    futs = {
                        pool.submit(
                            _worker_save_connect, driver,
                            config, cip): cip
                        for cip in changed_ips
                    }
                    for fut in as_completed(futs):
                        sip, status, err = fut.result()
                        if status == 'OK':
                            print(f'    {sip}: '
                                  f'{C.GRN}saved{C.RST}')
                            save_ok += 1
                        else:
                            print(f'    {sip}: '
                                  f'{C.RED}{err}{C.RST}')

                # Snapshot (MOPS only)
                if (save_ok
                        and config.get('protocol') == 'mops'):
                    snap_raw = input(
                        f'  {C.GRN}▸{C.RST} Create '
                        f'snapshot? '
                        f'{C.CYN}[a]{C.RST}ll / '
                        f'{C.CYN}[n]{C.RST}o: '
                        ).strip().lower()
                    if snap_raw not in ('n', 'no'):
                        ts = datetime.now().strftime('%Y%m%d')
                        default_name = f'SL1-{ts}'
                        name = input(
                            f'  {C.GRN}▸{C.RST} Snapshot '
                            f'name {C.DIM}[{default_name}]'
                            f'{C.RST}: ').strip()
                        if not name:
                            name = default_name
                        if _is_valid_profile_name(name):
                            with ThreadPoolExecutor(
                                    max_workers=min(
                                        len(changed_ips), 8)
                                    ) as pool:
                                futs = {
                                    pool.submit(
                                        _worker_snapshot_connect,
                                        driver, config,
                                        cip, name): cip
                                    for cip in changed_ips
                                }
                                for fut in as_completed(futs):
                                    sip, status, result = (
                                        fut.result())
                                    if status == 'OK':
                                        print(
                                            f'    {sip}: '
                                            f'{C.GRN}'
                                            f'{result}'
                                            f'{C.RST}')
                                    else:
                                        print(
                                            f'    {sip}: '
                                            f'{C.RED}'
                                            f'{result}'
                                            f'{C.RST}')
                        else:
                            print(f'  {C.RED}Invalid name'
                                  f'{C.RST}')
            else:
                print(f'  {C.YEL}Changes NOT saved — '
                      f'will revert on reboot{C.RST}')

        # Auto-save fleet report on exit
        path = auto_report_path(suffix='fleet')
        report = fleet_to_json(all_results, failures)
        save_report(report, path)
        print(f'  {C.DIM}Report: {path}{C.RST}\n')

    except (KeyboardInterrupt, EOFError):
        print(f'\n\n  {C.DIM}Interrupted.{C.RST}\n')

# ---------------------------------------------------------------------------
# Fleet mode
# ---------------------------------------------------------------------------

def fleet_audit(driver, config, check_defs, color=C):
    """Parallel audit across all devices in config."""
    devices = config['devices']
    start = time.time()

    all_results = {}
    failures = []

    with ThreadPoolExecutor(max_workers=min(len(devices), 8)) as pool:
        futures = {
            pool.submit(worker_audit, driver, config, ip, check_defs): ip
            for ip in devices
        }
        for future in as_completed(futures):
            ip, device_info, findings, err = future.result()
            if err:
                failures.append((ip, err))
            else:
                all_results[ip] = {
                    'device': device_info,
                    'findings': findings,
                }

    elapsed = time.time() - start
    return all_results, failures, elapsed

# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='JUSTIN — IEC 62443-4-2 Security Audit & Hardening')

    # Mode
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--audit', action='store_true',
                      help='read-only security audit')
    mode.add_argument('--harden', action='store_true',
                      help='audit + apply remediations')
    mode.add_argument('-i', '--interactive', action='store_true',
                      help='interactive guided mode')

    # Target
    parser.add_argument('-d', metavar='IP',
                        help='single device IP')
    parser.add_argument('-c', metavar='FILE', default='script.cfg',
                        help='config file (default: script.cfg)')
    parser.add_argument('--from-report', metavar='FILE',
                        help='harden from a saved audit report (JSON)')

    # Credentials
    parser.add_argument('-u', metavar='USER', default=None,
                        help='username override')
    parser.add_argument('-p', metavar='PASS', default=None,
                        help='password override')
    parser.add_argument('--protocol', default=None,
                        choices=['mops', 'snmp', 'ssh'],
                        help='protocol (default: mops)')

    # Behaviour
    parser.add_argument('--dry-run', action='store_true',
                        help='show planned fixes without applying')
    parser.add_argument('--commit', action='store_true',
                        help='apply hardening changes')
    parser.add_argument('--save', action='store_true',
                        help='save config to NVM after hardening')
    parser.add_argument('--watchdog', type=int, default=None, metavar='SEC',
                        help='config watchdog rollback timer in seconds '
                             '(30-600, auto-reverts on failure)')
    parser.add_argument('--snapshot', metavar='NAME', default=None,
                        help='create named NVM snapshot after harden+save '
                             '(MOPS only, requires --save)')
    parser.add_argument('--level', default='SL1', choices=['SL1', 'SL2'],
                        help='security level (default: SL1)')

    # Output
    parser.add_argument('-j', '--json', action='store_true',
                        help='JSON output')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='save report to file (JSON)')
    parser.add_argument('-s', '--severity', default=None,
                        choices=['critical', 'warning', 'info'],
                        help='filter by minimum severity')
    parser.add_argument('--no-color', action='store_true',
                        help='disable ANSI colours')
    parser.add_argument('--debug', action='store_true',
                        help='verbose logging')

    return parser.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_arguments()

    color = NO_COLOR if args.no_color else C

    # Detect pipe — disable colour
    if not sys.stdout.isatty():
        color = NO_COLOR

    # Logging
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(
        log_dir, f'justin_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        filename=log_file, level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s')
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if args.debug else logging.WARNING)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger().addHandler(console)
    for lib in ('paramiko', 'napalm', 'netmiko', 'urllib3', 'requests'):
        logging.getLogger(lib).setLevel(log_level)

    # Load checks
    check_defs = load_checks()

    # Filter by SL
    sl_num = int(args.level.replace('SL', ''))
    check_defs = {k: v for k, v in check_defs.items()
                  if v.get('sl', 1) <= sl_num}

    # Filter by severity
    if args.severity:
        max_sev = SEVERITY_ORDER.get(args.severity, 9)
        check_defs = {k: v for k, v in check_defs.items()
                      if SEVERITY_ORDER.get(v['severity'], 9) <= max_sev}

    # Config
    try:
        if args.d:
            config = {
                'username': args.u or 'admin',
                'password': args.p or 'private',
                'protocol': args.protocol or 'mops',
                'devices': [args.d],
                'syslog_server': None,
                'syslog_port': 514,
                'ntp_server': None,
                'banner': None,
                'level': args.level,
            }
        elif args.from_report:
            # Two-step: harden from report — still need credentials
            config = {
                'username': args.u or 'admin',
                'password': args.p or 'private',
                'protocol': args.protocol or 'mops',
                'devices': [],
                'syslog_server': None,
                'syslog_port': 514,
                'ntp_server': None,
                'banner': None,
                'level': args.level,
            }
            # Try loading supplementary config for hardening targets
            cfg_path = args.c
            if os.path.exists(cfg_path):
                supplementary = parse_config(cfg_path)
                for key in ('syslog_server', 'syslog_port',
                            'ntp_server', 'banner'):
                    if supplementary.get(key) is not None:
                        config[key] = supplementary[key]
                if not args.u:
                    config['username'] = supplementary['username']
                if not args.p:
                    config['password'] = supplementary['password']
                if not args.protocol:
                    config['protocol'] = supplementary['protocol']
        else:
            config = parse_config(args.c)
            if args.u:
                config['username'] = args.u
            if args.p:
                config['password'] = args.p
            if args.protocol:
                config['protocol'] = args.protocol
    except (FileNotFoundError, ValueError) as e:
        print(f"\n  {color.RED}ERROR: {e}{color.RST}\n")
        sys.exit(1)

    # ---- Interactive: wizard handles everything, shells out ----
    if args.interactive:
        interactive_mode()
        return

    # Validate: need devices unless using --from-report
    if not args.from_report and not config['devices']:
        print(f"\n  {color.RED}ERROR: No devices specified. "
              f"Use -d IP or -c config.cfg{color.RST}\n")
        sys.exit(1)

    # Import driver
    try:
        from napalm import get_network_driver
        driver = get_network_driver('hios')
    except ImportError:
        print(f"\n  {color.RED}ERROR: napalm-hios not installed. "
              f"pip install napalm-hios{color.RST}\n")
        sys.exit(1)

    # Route progress to stderr in JSON mode
    global _JSON_MODE
    if args.json:
        _JSON_MODE = True

    start_time = time.time()

    # ---- Two-step: harden from saved report ----
    if args.from_report:
        if not args.harden:
            print(f"\n  {color.RED}ERROR: --from-report requires "
                  f"--harden{color.RST}\n")
            sys.exit(1)
        report_data = load_report(args.from_report)
        dry_run = not args.commit
        if dry_run:
            print(f"\n  {color.BOLD}Dry-run mode "
                  f"(use --commit to apply){color.RST}")
        harden_from_report(driver, config, report_data, check_defs,
                           dry_run=dry_run, save=args.save, color=color,
                           watchdog_seconds=args.watchdog,
                           snapshot_name=args.snapshot)
        elapsed = time.time() - start_time
        print(f"  {color.DIM}Completed in {elapsed:.1f}s{color.RST}\n")
        return

    # ---- Fleet mode (multiple devices) ----
    if len(config['devices']) > 1:
        all_results, failures, elapsed = fleet_audit(
            driver, config, check_defs, color)

        if args.json:
            report = fleet_to_json(all_results, failures)
            print(json.dumps(report, indent=2))
        else:
            print_fleet_report(all_results, failures, elapsed, color)

        # Save report if requested
        if args.output:
            report = fleet_to_json(all_results, failures)
            save_report(report, args.output)
            print(f"  Report saved to {args.output}\n")

        # Fleet harden
        if args.harden and not args.json:
            dry_run = not args.commit
            if dry_run:
                print(f"  {color.BOLD}Dry-run mode "
                      f"(use --commit to apply){color.RST}")
            for ip, data in sorted(all_results.items()):
                fixable = [f for f in data['findings']
                           if not f.passed and f.check_id in HARDEN_DISPATCH]
                if not fixable:
                    continue
                print(f"\n  {color.BOLD}Hardening {ip} ...{color.RST}")
                device = None
                try:
                    device = driver(
                        hostname=ip,
                        username=config['username'],
                        password=config['password'],
                        timeout=30,
                        optional_args={
                            'protocol_preference': [config['protocol']]},
                    )
                    device.open()

                    # Dirty-config guard
                    if not dry_run:
                        if not enforce_clean_config(
                                device, ip, 'harden', color):
                            continue

                    state = gather(device, check_defs, color)
                    snap_before = _make_state_snapshot(state)
                    gather_fn = lambda d=device: gather(d, check_defs, color)
                    session = SessionLog(ip)
                    session.update(device=data['device'],
                                   state_before=snap_before)

                    applied, changes_log, state_diff = harden_device(
                        device, data['findings'], check_defs, config,
                        dry_run=dry_run, save=args.save, color=color,
                        state_before=snap_before, gather_fn=gather_fn,
                        watchdog_seconds=args.watchdog, session=session)

                    # Snapshot per device
                    if (args.snapshot and not dry_run and applied
                            and args.save
                            and config['protocol'] == 'mops'
                            and _is_valid_profile_name(
                                args.snapshot)):
                        print(f"  Snapshot '{args.snapshot}'"
                              f" ... ", end='', flush=True)
                        try:
                            final = _do_snapshot(
                                device, args.snapshot)
                            print(f"{color.GRN}OK"
                                  f"{color.RST}")
                            session.add_change({
                                'check_id': '_snapshot',
                                'action':
                                    f"snapshot('{final}')",
                                'result': 'applied',
                                'timestamp':
                                    datetime.now().isoformat(),
                            })
                        except Exception as e:
                            print(f"{color.RED}FAIL "
                                  f"({e}){color.RST}")

                    session.finish()
                    _progress(f"  {color.DIM}Session: "
                              f"{session.path}{color.RST}")
                    device.close()
                except Exception as e:
                    print(f"  {color.RED}FAIL: {e}{color.RST}")
                finally:
                    if device:
                        try:
                            device.close()
                        except Exception:
                            pass
        return

    # ---- Single device ----
    ip = config['devices'][0]
    _progress(f"\n  Connecting to {ip} ...")

    ip, device, device_info, findings, state, err = audit_device(
        driver, config, ip, check_defs, color)

    if err:
        print(f"  {color.RED}FAIL: {err}{color.RST}\n")
        sys.exit(1)

    # Session log — written incrementally (the JUSTIN way)
    session = SessionLog(ip)
    snap_before = _make_state_snapshot(state)
    session.update(device=device_info, state_before=snap_before)

    # Config status check
    saved, cfg_status = check_config_saved(device, color)
    session.update(config_status=cfg_status)

    # JSON output
    if args.json:
        report = to_json(findings, device_info)
        print(json.dumps(report, indent=2))
        if args.output:
            save_report(report, args.output)
        total = len(findings)
        passed = sum(1 for f in findings if f.passed)
        session.update(
            findings=[f.to_dict() for f in findings],
            score={'total': total, 'passed': passed,
                   'failed': total - passed})
        session.finish()
        _progress(f"  {color.DIM}Session: {session.path}{color.RST}")
        if device:
            device.close()
        return

    # Console report
    print_report(findings, device_info, color)

    total = len(findings)
    passed = sum(1 for f in findings if f.passed)
    session.update(
        findings=[f.to_dict() for f in findings],
        score={'total': total, 'passed': passed,
               'failed': total - passed})

    # Save report if requested
    if args.output:
        report = to_json(findings, device_info)
        save_report(report, args.output)
        print(f"  Report saved to {args.output}")

    # Harden
    if args.harden:
        # Dirty-config guard — refuse to harden unsaved switch
        if not enforce_clean_config(device, ip, 'harden', color):
            session.update(refused='unsaved config')
            session.finish()
            _progress(f"  {color.DIM}Session: {session.path}{color.RST}")
            if device:
                device.close()
            return

        dry_run = not args.commit
        if dry_run:
            print(f"  {color.BOLD}Dry-run mode "
                  f"(use --commit to apply){color.RST}")

        gather_fn = lambda: gather(device, check_defs, color)
        applied, changes_log, state_diff = harden_device(
            device, findings, check_defs, config,
            dry_run=dry_run, save=args.save, color=color,
            state_before=snap_before, gather_fn=gather_fn,
            watchdog_seconds=args.watchdog, session=session)

        # Snapshot after harden+save
        if (args.snapshot and not dry_run and applied
                and args.save):
            if config['protocol'] != 'mops':
                print(f"  {color.YEL}Snapshot requires MOPS "
                      f"protocol{color.RST}")
            elif not _is_valid_profile_name(args.snapshot):
                print(f"  {color.RED}Invalid snapshot name"
                      f"{color.RST}")
            else:
                print(f"  Snapshot '{args.snapshot}' ... ",
                      end='', flush=True)
                try:
                    final = _do_snapshot(device, args.snapshot)
                    if final != args.snapshot:
                        print(f"{color.GRN}OK "
                              f"(as '{final}'){color.RST}")
                    else:
                        print(f"{color.GRN}OK{color.RST}")
                    session.add_change({
                        'check_id': '_snapshot',
                        'action': f"snapshot('{final}')",
                        'result': 'applied',
                        'timestamp': datetime.now().isoformat(),
                    })
                except Exception as e:
                    print(f"{color.RED}FAIL ({e}){color.RST}")

    elapsed = time.time() - start_time
    session.finish()
    _progress(f"  {color.DIM}Session: {session.path}{color.RST}")
    print(f"  {color.DIM}Completed in {elapsed:.1f}s{color.RST}\n")

    if device:
        device.close()


if __name__ == '__main__':
    main()
