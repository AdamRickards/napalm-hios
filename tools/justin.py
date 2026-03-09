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

def run_checks(state, check_defs, config, color=C):
    """Run all registered checks against gathered state, return findings."""
    findings = []
    for check_id, spec in check_defs.items():
        fn = CHECK_FNS.get(check_id)
        if fn is None:
            logging.warning("No check function for %s", check_id)
            continue
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


def print_report(findings, device_info=None, color=C):
    """Print a full, nicely-formatted audit report to console."""
    W = 80  # report width

    # Header
    print()
    print(f"  {color.MG}{color.BOLD}╔{'═' * (W - 2)}╗{color.RST}")
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"  JUSTIN — IEC 62443-4-2 Security Audit"
          f"{' ' * (W - 42)}"
          f"{color.MG}{color.BOLD}║{color.RST}")
    print(f"  {color.MG}{color.BOLD}╚{'═' * (W - 2)}╝{color.RST}")

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


def print_fleet_report(all_results, failures, elapsed, color=C):
    """Print fleet-wide summary report."""
    W = 84

    print()
    print(f"  {color.MG}{color.BOLD}╔{'═' * (W - 2)}╗{color.RST}")
    print(f"  {color.MG}{color.BOLD}║{color.RST}"
          f"  JUSTIN — IEC 62443-4-2 Fleet Audit"
          f"{' ' * (W - 39)}"
          f"{color.MG}{color.BOLD}║{color.RST}")
    print(f"  {color.MG}{color.BOLD}╚{'═' * (W - 2)}╝{color.RST}")

    n_ok = len(all_results)
    n_fail = len(failures)
    print(f"  {color.BOLD}Devices:{color.RST} {n_ok} audited"
          + (f", {color.RED}{n_fail} unreachable{color.RST}" if n_fail else ""))
    print(f"  {color.BOLD}Level:{color.RST}   SL1")
    print(f"  {color.BOLD}Date:{color.RST}    {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()

    # Per-device summary table
    print(f"  {color.BOLD}{'IP':<18s}{'Name':<20s}{'Model':<16s}"
          f"{'Score':>7s}  Status{color.RST}")
    print(f"  {'─' * W}")

    for ip, data in sorted(all_results.items()):
        di = data['device']
        findings = data['findings']
        total = len(findings)
        passed = sum(1 for f in findings if f.passed)
        failed = total - passed
        has_crit = any(not f.passed and f.severity == 'critical'
                       for f in findings)
        sc = color.RED if has_crit else (color.YEL if failed else color.GRN)

        # Mini bar
        bar_w = 10
        bar_filled = int(passed / total * bar_w) if total else 0
        bar = f"{sc}{'█' * bar_filled}{'░' * (bar_w - bar_filled)}{color.RST}"

        status = f"{color.GRN}CLEAN{color.RST}" if failed == 0 else (
            f"{sc}{failed} finding{'s' if failed != 1 else ''}{color.RST}")

        name = di.get('hostname', ip)[:18]
        model = di.get('model', '?')[:14]
        print(f"  {ip:<18s}{name:<20s}{model:<16s}"
              f"{sc}{passed:>2d}/{total:<2d}{color.RST}  "
              f"{bar}  {status}")

    for ip, err in failures:
        print(f"  {ip:<18s}{color.RED}{'—':<20s}{'—':<16s}"
              f"{'—':>5s}  {'░' * 10}  UNREACHABLE{color.RST}")

    print(f"  {'─' * W}")

    # Fleet-wide totals
    all_findings = []
    for data in all_results.values():
        all_findings.extend(data['findings'])

    total_checks = len(all_findings)
    total_passed = sum(1 for f in all_findings if f.passed)
    total_failed = total_checks - total_passed

    print()
    print(f"  {color.BOLD}Fleet score:{color.RST}  "
          f"{total_passed}/{total_checks} checks passed")
    print(_score_bar(total_passed, total_checks, width=24, color=color))

    # Common findings across fleet — horizontal bar chart
    finding_counts = {}
    for f in all_findings:
        if not f.passed:
            finding_counts[f.check_id] = finding_counts.get(f.check_id, 0) + 1

    if finding_counts:
        max_count = max(finding_counts.values())
        print(f"\n  {color.BOLD}┌─ Common findings {'─' * (W - 21)}┐{color.RST}")
        for cid, count in sorted(finding_counts.items(),
                                  key=lambda x: (-x[1], x[0])):
            bar_w = min(count * 20 // max_count, 20) if max_count else 0
            bar = '█' * bar_w
            sev = 'RED' if cid.startswith('sec-hidisc') or \
                cid == 'sys-default-passwords' else 'YEL'
            sc = getattr(color, sev, '')
            print(f"  {color.BOLD}│{color.RST}  {cid:<28s}"
                  f"{count:>2d}/{n_ok}  {sc}{bar}{color.RST}")
        print(f"  {color.BOLD}└{'─' * (W - 1)}┘{color.RST}")

    print(f"\n  {color.DIM}Completed in {elapsed:.1f}s{color.RST}\n")


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
    with open(output_path, 'w') as f:
        json.dump(report_dict, f, indent=2)


def load_report(report_path):
    """Load a saved audit report for two-step hardening."""
    with open(report_path, 'r') as f:
        data = json.load(f)
    return data

# ---------------------------------------------------------------------------
# Hardening phase
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


def harden_device(device, findings, check_defs, config, dry_run=True,
                  save=False, color=C):
    """Apply remediation for failed findings that have hardening functions."""
    fixable = [f for f in findings
               if not f.passed and f.check_id in HARDEN_DISPATCH]
    if not fixable:
        print(f"  {color.GRN}No fixable findings.{color.RST}\n")
        return []

    print(f"\n  {color.BOLD}Hardening ({len(fixable)} fixable):{color.RST}")
    applied = []
    for f in fixable:
        spec = check_defs.get(f.check_id, {})
        fn = HARDEN_DISPATCH[f.check_id]

        if dry_run:
            print(f"    {color.CYN}[DRY-RUN]{color.RST} "
                  f"{f.check_id}: {f.fix_cmd or '?'}")
            applied.append(f.check_id)
            continue

        print(f"    {f.check_id}: ", end='', flush=True)
        try:
            result = fn(device, spec, config, color)
            if result is None:
                print(f"{color.YEL}SKIP (missing config value){color.RST}")
            else:
                print(f"{result} ... {color.GRN}OK{color.RST}")
                applied.append(f.check_id)
        except Exception as e:
            print(f"{color.RED}FAIL ({e}){color.RST}")
            logging.error("Harden %s failed: %s", f.check_id, e)

    if save and not dry_run and applied:
        print(f"\n  Saving config to NVM ... ", end='', flush=True)
        try:
            device.save_config()
            print(f"{color.GRN}OK{color.RST}")
        except Exception as e:
            print(f"{color.RED}FAIL ({e}){color.RST}")

    print()
    return applied

# ---------------------------------------------------------------------------
# Device-level audit
# ---------------------------------------------------------------------------

def audit_device(driver, config, ip, check_defs, color=C):
    """Connect to a single device, gather state, run checks."""
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

        return ip, device, device_info, findings, None
    except Exception as e:
        if device:
            try:
                device.close()
            except Exception:
                pass
        return ip, None, None, None, str(e)


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
                       dry_run=True, save=False, color=C):
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
            harden_device(device, findings, check_defs, config,
                          dry_run=dry_run, save=save, color=color)
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
# Interactive mode
# ---------------------------------------------------------------------------

def interactive_mode(driver, config, check_defs, color=C):
    """Guided interactive audit + optional hardening for a single device."""
    ip = config['devices'][0] if config['devices'] else None
    if not ip:
        ip = input(f"  {color.GRN}>{color.RST} Device IP: ").strip()
        if not is_valid_ipv4(ip):
            print(f"  {color.RED}Invalid IP.{color.RST}\n")
            return

    print(f"\n  Connecting to {ip} ...")
    ip, device, device_info, findings, err = audit_device(
        driver, config, ip, check_defs, color)

    if err:
        print(f"  {color.RED}FAIL: {err}{color.RST}\n")
        return

    print_report(findings, device_info, color)

    # Offer hardening
    fixable = [f for f in findings
               if not f.passed and f.check_id in HARDEN_DISPATCH]
    if not fixable:
        if device:
            device.close()
        return

    try:
        answer = input(f"  Fix {len(fixable)} finding(s)? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = 'n'

    if answer != 'y':
        if device:
            device.close()
        return

    # Prompt for missing config values
    if config.get('syslog_server') is None:
        if any(f.check_id == 'sec-logging' for f in fixable):
            val = input("  Syslog server IP [skip]: ").strip()
            if val and is_valid_ipv4(val):
                config['syslog_server'] = val

    if config.get('ntp_server') is None:
        if any(f.check_id == 'sec-time-sync' for f in fixable):
            val = input("  NTP server IP [skip]: ").strip()
            if val and is_valid_ipv4(val):
                config['ntp_server'] = val

    print(f"\n  {color.BOLD}Applying fixes ...{color.RST}")
    harden_device(device, findings, check_defs, config,
                  dry_run=False, color=color)

    try:
        save_answer = input("  Save config to NVM? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        save_answer = 'n'

    if save_answer == 'y':
        print("  Saving ... ", end='', flush=True)
        try:
            device.save_config()
            print(f"{color.GRN}OK{color.RST}")
        except Exception as e:
            print(f"{color.RED}FAIL ({e}){color.RST}")

    device.close()
    print()

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
                           dry_run=dry_run, save=args.save, color=color)
        elapsed = time.time() - start_time
        print(f"  {color.DIM}Completed in {elapsed:.1f}s{color.RST}\n")
        return

    # ---- Interactive ----
    if args.interactive:
        interactive_mode(driver, config, check_defs, color)
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
                    harden_device(device, data['findings'], check_defs,
                                  config, dry_run=dry_run, save=args.save,
                                  color=color)
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

    ip, device, device_info, findings, err = audit_device(
        driver, config, ip, check_defs, color)

    if err:
        print(f"  {color.RED}FAIL: {err}{color.RST}\n")
        sys.exit(1)

    # JSON output
    if args.json:
        report = to_json(findings, device_info)
        print(json.dumps(report, indent=2))
        if args.output:
            save_report(report, args.output)
        if device:
            device.close()
        return

    # Console report
    print_report(findings, device_info, color)

    # Save report if requested
    if args.output:
        report = to_json(findings, device_info)
        save_report(report, args.output)
        print(f"  Report saved to {args.output}")

    # Harden
    if args.harden:
        dry_run = not args.commit
        if dry_run:
            print(f"  {color.BOLD}Dry-run mode "
                  f"(use --commit to apply){color.RST}")
        harden_device(device, findings, check_defs, config,
                      dry_run=dry_run, save=args.save, color=color)

    elapsed = time.time() - start_time
    print(f"  {color.DIM}Completed in {elapsed:.1f}s{color.RST}\n")

    if device:
        device.close()


if __name__ == '__main__':
    main()
