#!/usr/bin/env python3
"""JUSTIN — Justified Unified Security Testing for Industrial Networks.

IEC 62443-4-2 security audit and hardening tool for Hirschmann HiOS switches.
Connects via napalm-hios, audits against composable security levels, remediates findings.

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
import getpass
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

def _log(tag, msg='', end='\n', flush=False, color=C):
    """Tagged progress line: HH:MM:SS [TAG] msg.

    Use for all operational output (gather, check, harden, save, snapshot).
    Report card display (the boxed table) stays untagged.
    """
    ts = datetime.now().strftime('%H:%M:%S')
    line = f"  {color.DIM}{ts}{color.RST} [{tag}] {msg}"
    if _JSON_MODE:
        print(line, end=end, flush=flush, file=sys.stderr)
    else:
        print(line, end=end, flush=flush)

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
        if self.detail is not None:
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
# Composable --level filter
# ---------------------------------------------------------------------------

VALID_LEVELS = {'sl1', 'sl2', 'vendor', 'highest'}
# sl3 excluded until Phase 2/3 adds deducible SL3 checks (get_users,
# get_password_policy). Currently sl3 == sl2 (zero additional checks).
# Add 'sl3' to VALID_LEVELS when meaningful coverage exists.


def _check_sl_set(spec):
    """Return the set of SL values for a check (handles int or list)."""
    sl = spec.get('sl', 1)
    return set(sl) if isinstance(sl, list) else {sl}


def filter_checks_by_level(check_defs, level_str):
    """Filter checks by composable security level string.

    Supports comma-separated levels. Hierarchical SL levels collapse
    (sl1,sl2 -> sl2). 'vendor' = vendor checks only. 'sl1,vendor' =
    IEC SL1 + vendor. 'highest' = everything.

    sl field can be int (1) or list ([1, 2]) for checks that serve
    multiple levels. source can be 'iec', 'vendor', or 'cert'.

    Examples:
        'sl1'        -> IEC/cert SL1 checks
        'sl2'        -> IEC/cert SL1+SL2 + vendor checks tagged SL2
        'vendor'     -> vendor checks only
        'sl1,vendor' -> IEC SL1 + all vendor
        'highest'    -> everything
    """
    parts = [p.strip().lower() for p in level_str.split(',')]
    for p in parts:
        if p not in VALID_LEVELS:
            raise ValueError(
                f"Unknown level: {p}. Valid: {', '.join(sorted(VALID_LEVELS))}")

    if 'highest' in parts:
        return check_defs

    # Determine highest SL requested (hierarchical collapse)
    sl_max = 0
    for p in parts:
        if p.startswith('sl'):
            sl_max = max(sl_max, int(p[2:]))
    include_vendor = 'vendor' in parts

    filtered = {}
    for k, v in check_defs.items():
        source = v.get('source', 'iec')
        sls = _check_sl_set(v)
        # IEC + cert: include if any sl value <= sl_max
        if source in ('iec', 'cert') and sl_max > 0 and min(sls) <= sl_max:
            filtered[k] = v
        # Vendor: always include if vendor flag set
        elif source == 'vendor' and include_vendor:
            filtered[k] = v
        # Vendor with SL2 tag: include at SL2 even without vendor flag
        elif source == 'vendor' and sl_max >= 2 and max(sls) >= 2:
            filtered[k] = v
    return filtered


# ---------------------------------------------------------------------------
# Certs loader — IEC 62443-4-2 certification context
# ---------------------------------------------------------------------------

def load_certs(certs_file=None):
    """Load family->cert->SL-C lookup from certs.json."""
    if certs_file is None:
        certs_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'certs.json')
    if not os.path.exists(certs_file):
        return {}
    with open(certs_file, 'r') as f:
        return json.load(f)


def resolve_cert(certs, model):
    """Resolve a device model to its IEC 62443 cert info.

    Matches model prefix to family (longest-match-first so GRS1042
    matches before GRS10x0 before GRS10x). Lowercase 'x' in a family
    key acts as a single-character wildcard (e.g. GRS10x matches
    GRS1020, GRS1030).
    """
    if not certs or not model:
        return None
    families = certs.get('families', {})
    model_up = model.upper()
    # Sort by key length descending for longest-match-first
    for fam in sorted(families.keys(), key=len, reverse=True):
        # Build a regex from the family key: 'x' -> '.' (single char wildcard)
        pattern = ''.join('.' if c == 'x' else re.escape(c.upper())
                          for c in fam)
        if re.match(pattern, model_up):
            return families[fam]
    return None

# ---------------------------------------------------------------------------
# Config parsing (same pattern as AARON/MOHAWC/CLAMPS)
# ---------------------------------------------------------------------------

def is_valid_ipv4(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def parse_ips(spec):
    """Parse --ips spec into list of IPs.

    Formats:
      Comma: 192.168.1.1,192.168.1.5
      Last-octet range: 192.168.1.80-85
      CIDR: 192.168.1.0/24
    """
    ips = []
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '/' in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                ips.extend(str(h) for h in net.hosts())
            except ValueError:
                raise ValueError(f"Invalid CIDR: {part}")
            continue
        m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', part)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            if start > end:
                raise ValueError(f"Invalid range: {part} (start > end)")
            if not (0 <= start <= 255 and 0 <= end <= 255):
                raise ValueError(f"Invalid IP range: {part} (octet must be 0-255)")
            for i in range(start, end + 1):
                ip = f"{prefix}{i}"
                if is_valid_ipv4(ip):
                    ips.append(ip)
            continue
        if is_valid_ipv4(part):
            ips.append(part)
        else:
            raise ValueError(f"Invalid IP: {part}")
    return ips


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
        'level': 'sl1',
        'dirty_guard': True,
        'auto_save': False,
        'snapshot': 'off',
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
                    config['level'] = val.lower()
                elif key == 'dirty_guard':
                    config['dirty_guard'] = val.lower() not in (
                        'false', 'off', 'no', '0')
                elif key == 'auto_save':
                    config['auto_save'] = val.lower() in (
                        'true', 'on', 'yes', '1')
                elif key == 'snapshot':
                    config['snapshot'] = val.lower()
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
    """Call each unique getter referenced by the check set.

    Returns (state, evidence) where state is the raw getter results dict
    (used by check functions) and evidence is a timestamped copy for the
    audit trail: {getter: {gathered_at: iso, data: result}}.
    """
    getters = set()
    for spec in check_defs.values():
        if spec.get('getter'):
            getters.add(spec['getter'])

    state = {}
    evidence = {}
    for getter_name in sorted(getters):
        _log('GATHER', f"{color.DIM}{getter_name}() ...{color.RST}",
             color=color)
        ts = datetime.now().isoformat()
        try:
            result = getattr(device, getter_name)()
            state[getter_name] = result
            evidence[getter_name] = {
                'gathered_at': ts,
                'data': json.loads(json.dumps(result, default=str)),
            }
        except Exception as e:
            _log('GATHER', f"{color.YEL}WARNING: {getter_name}() "
                 f"failed: {type(e).__name__}: {e}{color.RST}",
                 color=color)
            state[getter_name] = None
            evidence[getter_name] = {
                'gathered_at': ts, 'error': str(e),
            }
    return state, evidence

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
                             fix_cmd="set_ntp(enabled=True)")
    servers = client.get('servers', [])
    active = [s for s in servers
              if s.get('address') and s['address'] != '0.0.0.0']
    if not active:
        return _make_finding(spec, 'SNTP client enabled but no server configured',
                             fix_cmd="set_ntp(enabled=True) + configure server")
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
    users = state.get('get_users')
    if users is not None:
        # New path: use get_users() default_password field (MOPS only)
        defaults = [u['name'] for u in users
                    if u.get('default_password')]
        if defaults:
            return _make_finding(
                spec,
                f"Default password active: {', '.join(defaults)}",
                detail='Factory-default credentials are a critical risk. '
                       'Change passwords for all flagged accounts',
                fix_cmd="set_user(name, password=<new>)")
        # No defaults flagged — but only MOPS detects this
        return _make_finding(
            spec, 'No default passwords detected', passed=True)
    # Fallback: credential-based detection (SNMP/SSH)
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
        spec, 'Non-admin user in use — default password status unknown',
        detail='Use MOPS protocol for definitive detection via '
               'hm2PwdMgmtDefaultPwdStatusTable')


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


# --- sec-industrial-protocols -----------------------------------------------

@register_check('sec-industrial-protocols')
def check_industrial_protocols(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    ind = svc.get('industrial')
    if ind is None:
        return _unable(spec)
    enabled = []
    for proto, label in [('profinet', 'PROFINET'), ('modbus', 'Modbus TCP'),
                         ('ethernet_ip', 'EtherNet/IP'),
                         ('iec61850', 'IEC 61850 MMS')]:
        if ind.get(proto):
            enabled.append(label)
    if enabled:
        return _make_finding(
            spec, f"Industrial protocols enabled: {', '.join(enabled)}",
            detail='Disable unless required by operational technology',
            fix_cmd="set_services(profinet=False, modbus=False, "
                    "ethernet_ip=False, iec61850=False)")
    return _make_finding(spec, 'No industrial protocols enabled', passed=True)


# --- ns-dos-protection ------------------------------------------------------

@register_check('ns-dos-protection')
def check_dos_protection(state, spec, config):
    sc = state.get('get_storm_control')
    if sc is None:
        return _unable(spec)
    interfaces = sc.get('interfaces', {})
    if not interfaces:
        return _unable(spec)
    protected = sum(
        1 for cfg in interfaces.values()
        if any(cfg.get(t, {}).get('enabled', False)
               for t in ('broadcast', 'multicast', 'unicast')))
    total = len(interfaces)
    if protected == 0:
        return _make_finding(
            spec, 'No storm control configured on any port',
            detail='Enable broadcast/multicast storm control on access ports')
    return _make_finding(
        spec, f"Storm control active on {protected}/{total} ports",
        passed=True)


# --- ns-lldp ----------------------------------------------------------------

@register_check('ns-lldp')
def check_lldp(state, spec, config):
    neighbors = state.get('get_lldp_neighbors')
    if neighbors is None:
        return _unable(spec)
    n_neighbors = sum(len(v) for v in neighbors.values())
    n_ports = len(neighbors)
    return _make_finding(
        spec,
        f"LLDP active: {n_neighbors} neighbor(s) on {n_ports} port(s)"
        if n_neighbors else 'No LLDP neighbors detected',
        detail='Advisory: review LLDP exposure — topology visible to neighbors',
        passed=True)


# --- ns-port-security -----------------------------------------------------

@register_check('ns-port-security')
def check_port_security(state, spec, config):
    ps = state.get('get_port_security')
    if ps is None:
        return _unable(spec)
    ports = ps.get('ports', {})
    if not ports:
        return _unable(spec)

    # Build skip set: uplinks (LLDP neighbors) + MRP ring ports
    skip = set()
    neighbors = state.get('get_lldp_neighbors')
    if neighbors:
        skip.update(neighbors.keys())
    mrp = state.get('get_mrp')
    if mrp:
        for domain in mrp.values() if isinstance(mrp, dict) else [mrp]:
            for key in ('ring_port_1', 'ring_port_2'):
                rp = domain.get(key, {}) if isinstance(domain, dict) else {}
                iface = rp.get('interface', '') if isinstance(rp, dict) else ''
                if iface:
                    skip.add(iface)

    unprotected = []
    access_total = 0
    for port, cfg in sorted(ports.items()):
        if port in skip:
            continue
        access_total += 1
        if not cfg.get('enabled', False):
            unprotected.append(port)

    if access_total == 0:
        return _make_finding(
            spec, 'No access ports found (all ports are uplinks/ring)',
            passed=True)
    if unprotected:
        sample = ', '.join(unprotected[:5])
        suffix = (f' (+{len(unprotected) - 5} more)'
                  if len(unprotected) > 5 else '')
        return _make_finding(
            spec,
            f"Port security disabled on {len(unprotected)}/{access_total}"
            f" access port(s): {sample}{suffix}",
            detail='Enable port security on access ports to limit MAC addresses'
                   ' — harden deferred (requires per-site MAC limit policy)')
    return _make_finding(
        spec,
        f"Port security enabled on all {access_total} access port(s)",
        passed=True)


# --- ns-dhcp-snooping -----------------------------------------------------

@register_check('ns-dhcp-snooping')
def check_dhcp_snooping(state, spec, config):
    ds = state.get('get_dhcp_snooping')
    if ds is None:
        return _unable(spec)
    ports = ds.get('ports', {})
    if not ports:
        return _unable(spec)

    if not ds.get('enabled', False):
        return _make_finding(
            spec, 'DHCP snooping globally disabled',
            detail='Enable DHCP snooping to prevent rogue DHCP servers'
                   ' — harden deferred (requires trust model planning)')

    # Build uplink set: LLDP neighbors + MRP ring ports
    uplinks = set()
    neighbors = state.get('get_lldp_neighbors')
    if neighbors:
        uplinks.update(neighbors.keys())
    mrp = state.get('get_mrp')
    if mrp:
        for domain in mrp.values() if isinstance(mrp, dict) else [mrp]:
            for key in ('ring_port_1', 'ring_port_2'):
                rp = domain.get(key, {}) if isinstance(domain, dict) else {}
                iface = rp.get('interface', '') if isinstance(rp, dict) else ''
                if iface:
                    uplinks.add(iface)

    issues = []
    # Uplinks should be trusted
    for port in sorted(uplinks):
        pcfg = ports.get(port, {})
        if not pcfg.get('trusted', False):
            issues.append(f"uplink {port} not trusted")

    # Access ports should NOT be trusted
    trusted_access = []
    for port, pcfg in sorted(ports.items()):
        if port in uplinks:
            continue
        if pcfg.get('trusted', False):
            trusted_access.append(port)

    if trusted_access:
        sample = ', '.join(trusted_access[:5])
        suffix = (f' (+{len(trusted_access) - 5} more)'
                  if len(trusted_access) > 5 else '')
        issues.append(
            f"access port(s) trusted (should be untrusted): "
            f"{sample}{suffix}")

    if issues:
        return _make_finding(
            spec,
            f"DHCP snooping enabled but trust model issues: "
            f"{'; '.join(issues)}",
            detail='Trust uplinks, untrust access ports'
                   ' — harden deferred (requires trust model planning)')

    return _make_finding(
        spec,
        f"DHCP snooping enabled with correct trust model",
        passed=True)


# --- ns-dai ---------------------------------------------------------------

@register_check('ns-dai')
def check_dai(state, spec, config):
    dai = state.get('get_arp_inspection')
    if dai is None:
        return _unable(spec)
    ports = dai.get('ports', {})
    if not ports:
        return _unable(spec)

    # DAI is per-VLAN enabled — check if ANY VLAN has it on
    vlans = dai.get('vlans', {})
    any_vlan_enabled = any(v.get('enabled', False)
                           for v in vlans.values())

    if not any_vlan_enabled:
        return _make_finding(
            spec, 'DAI not enabled on any VLAN',
            detail='Enable DAI on VLANs to validate ARP packets'
                   ' — harden deferred (requires DHCP snooping first)')

    # Build uplink set: LLDP neighbors + MRP ring ports
    uplinks = set()
    neighbors = state.get('get_lldp_neighbors')
    if neighbors:
        uplinks.update(neighbors.keys())
    mrp = state.get('get_mrp')
    if mrp:
        for domain in mrp.values() if isinstance(mrp, dict) else [mrp]:
            for key in ('ring_port_1', 'ring_port_2'):
                rp = domain.get(key, {}) if isinstance(domain, dict) else {}
                iface = rp.get('interface', '') if isinstance(rp, dict) else ''
                if iface:
                    uplinks.add(iface)

    issues = []
    # Uplinks should be trusted
    for port in sorted(uplinks):
        pcfg = ports.get(port, {})
        if not pcfg.get('trusted', False):
            issues.append(f"uplink {port} not trusted")

    # Access ports should NOT be trusted
    trusted_access = []
    for port, pcfg in sorted(ports.items()):
        if port in uplinks:
            continue
        if pcfg.get('trusted', False):
            trusted_access.append(port)

    if trusted_access:
        sample = ', '.join(trusted_access[:5])
        suffix = (f' (+{len(trusted_access) - 5} more)'
                  if len(trusted_access) > 5 else '')
        issues.append(
            f"access port(s) trusted (should be untrusted): "
            f"{sample}{suffix}")

    if issues:
        return _make_finding(
            spec,
            f"DAI enabled but trust model issues: "
            f"{'; '.join(issues)}",
            detail='Trust uplinks, untrust access ports'
                   ' — harden deferred (requires trust model planning)')

    return _make_finding(
        spec,
        f"DAI enabled with correct trust model",
        passed=True)


# --- ns-ipsg --------------------------------------------------------------

@register_check('ns-ipsg')
def check_ipsg(state, spec, config):
    ipsg = state.get('get_ip_source_guard')
    if ipsg is None:
        return _unable(spec)
    ports = ipsg.get('ports', {})
    if not ports:
        return _unable(spec)

    # Build uplink set: LLDP neighbors + MRP ring ports
    uplinks = set()
    neighbors = state.get('get_lldp_neighbors')
    if neighbors:
        uplinks.update(neighbors.keys())
    mrp = state.get('get_mrp')
    if mrp:
        for domain in mrp.values() if isinstance(mrp, dict) else [mrp]:
            for key in ('ring_port_1', 'ring_port_2'):
                rp = domain.get(key, {}) if isinstance(domain, dict) else {}
                iface = rp.get('interface', '') if isinstance(rp, dict) else ''
                if iface:
                    uplinks.add(iface)

    # Check access ports (non-uplinks) have verify_source enabled
    unprotected = []
    for port, pcfg in sorted(ports.items()):
        if port in uplinks:
            continue  # uplinks don't need IPSG
        if not pcfg.get('verify_source', False):
            unprotected.append(port)

    if unprotected:
        sample = ', '.join(unprotected[:5])
        suffix = (f' (+{len(unprotected) - 5} more)'
                  if len(unprotected) > 5 else '')
        return _make_finding(
            spec,
            f"IPSG disabled on access port(s): {sample}{suffix}",
            detail='Enable IP Source Guard on access ports to prevent'
                   ' IP spoofing — harden deferred'
                   ' (requires DHCP snooping first)')

    return _make_finding(
        spec,
        'IPSG enabled on all access ports',
        passed=True)


# --- sec-password-policy (SL2 — complexity requirements) ------------------

@register_check('sec-password-policy')
def check_password_policy(state, spec, config):
    lp = state.get('get_login_policy')
    if lp is None:
        return _unable(spec)
    fields = {
        'min_uppercase': ('uppercase', lp.get('min_uppercase', 0)),
        'min_lowercase': ('lowercase', lp.get('min_lowercase', 0)),
        'min_numeric': ('numeric', lp.get('min_numeric', 0)),
        'min_special': ('special', lp.get('min_special', 0)),
    }
    weak = [label for _, (label, val) in fields.items() if val < 1]
    if weak:
        return _make_finding(
            spec,
            f"Password complexity missing: {', '.join(weak)}",
            detail='IEC 62443-4-2 SL2 requires minimum 1 of each character class',
            fix_cmd="set_login_policy(min_uppercase=1, min_lowercase=1, "
                    "min_numeric=1, min_special=1)")
    return _make_finding(
        spec,
        f"Password complexity enforced (upper>={lp.get('min_uppercase', 0)}, "
        f"lower>={lp.get('min_lowercase', 0)}, "
        f"digit>={lp.get('min_numeric', 0)}, "
        f"special>={lp.get('min_special', 0)})",
        passed=True)


# --- sec-login-banner (pre-login authorised-use notice) -------------------

@register_check('sec-login-banner')
def check_login_banner(state, spec, config):
    banner = state.get('get_banner')
    if banner is None:
        return _unable(spec)
    pre = banner.get('pre_login', {})
    if pre.get('enabled') and pre.get('text', '').strip():
        return _make_finding(
            spec,
            f"Pre-login banner configured ({len(pre['text'])} chars)",
            passed=True)
    issues = []
    if not pre.get('enabled'):
        issues.append('pre-login banner disabled')
    if not pre.get('text', '').strip():
        issues.append('no banner text configured')
    return _make_finding(
        spec, '; '.join(issues).capitalize(),
        detail='Authorised-use warning banner deters unauthorised access',
        fix_cmd="set_banner(pre_login_enabled=True, "
                "pre_login_text='Authorized use only')")


# --- sec-signal-contact (relay monitors device/security status) -----------

@register_check('sec-signal-contact')
def check_signal_contact(state, spec, config):
    sc = state.get('get_signal_contact')
    if sc is None:
        return _unable(spec)
    # Check contact 1 (primary)
    c1 = sc.get(1, {})
    mode = c1.get('mode', 'manual')
    good_modes = ('deviceState', 'deviceSecurity', 'deviceStateAndSecurity')
    if mode in good_modes:
        return _make_finding(
            spec,
            f"Signal contact 1 mode: {mode}",
            passed=True)
    return _make_finding(
        spec,
        f"Signal contact 1 mode: {mode} (should monitor device/security status)",
        detail='Recommended: deviceStateAndSecurity for comprehensive fault relay',
        fix_cmd="set_signal_contact(contact_id=1, "
                "mode='deviceStateAndSecurity')")


# --- sec-session-timeouts (idle timeouts on all mgmt interfaces) -----------

@register_check('sec-session-timeouts')
def check_session_timeouts(state, spec, config):
    sc = state.get('get_session_config')
    if sc is None:
        return _unable(spec)
    zero_timeouts = []
    for proto in ('ssh', 'telnet', 'web', 'serial'):
        t = sc.get(proto, {}).get('timeout', 0)
        if t == 0:
            zero_timeouts.append(proto)
    if not zero_timeouts:
        return _make_finding(
            spec, "All management session timeouts configured",
            passed=True)
    return _make_finding(
        spec,
        f"Session timeout disabled for: {', '.join(zero_timeouts)}",
        detail='Idle sessions without timeout risk unauthorised access',
        fix_cmd="set_session_config(ssh_timeout=5, telnet_timeout=5, "
                "web_timeout=5, serial_timeout=5)")


# --- sec-ip-restrict (management access restricted by IP) ------------------

@register_check('sec-ip-restrict')
def check_ip_restrict(state, spec, config):
    rma = state.get('get_ip_restrict')
    if rma is None:
        return _unable(spec)
    if rma.get('enabled') and len(rma.get('rules', [])) > 0:
        n = len(rma['rules'])
        return _make_finding(
            spec,
            f"IP restriction enabled with {n} rule(s)",
            passed=True)
    issues = []
    if not rma.get('enabled'):
        issues.append('IP restriction disabled')
    if not rma.get('rules'):
        issues.append('no rules configured')
    return _make_finding(
        spec, '; '.join(issues).capitalize(),
        detail='Restrict management access to trusted subnets',
        fix_cmd="add_ip_restrict_rule(1, ip=<net>, prefix_length=<len>) "
                "+ set_ip_restrict(enabled=True)")


# --- sec-dns-client (DNS enabled with no servers = pointless) ---------------

@register_check('sec-dns-client')
def check_dns_client(state, spec, config):
    dns = state.get('get_dns')
    if dns is None:
        return _unable(spec)
    if not dns.get('enabled'):
        return _make_finding(
            spec, "DNS client disabled", passed=True)
    if dns.get('servers'):
        return _make_finding(
            spec, "DNS active (servers configured)", passed=True)
    return _make_finding(
        spec,
        "DNS enabled with no servers configured",
        detail='Pointless attack surface — DNS queries go nowhere, '
               'port open for no reason',
        fix_cmd="set_dns(enabled=False)")


# --- sec-poe (PoE on linkless ports) ----------------------------------------

@register_check('sec-poe')
def check_poe(state, spec, config):
    poe = state.get('get_poe')
    if poe is None:
        return _unable(spec)
    if not poe.get('enabled'):
        return _make_finding(
            spec, "PoE globally disabled", passed=True)
    ports = poe.get('ports', {})
    if not ports:
        return _make_finding(
            spec, "PoE enabled but no PoE ports on device",
            passed=True)
    # Cross-reference with interface link state
    ifaces = state.get('get_interfaces', {})
    linkless = []
    for port, cfg in ports.items():
        if not cfg.get('enabled'):
            continue
        iface = ifaces.get(port, {})
        if not iface.get('is_up', True):
            linkless.append(port)
    if linkless:
        return _make_finding(
            spec,
            f"PoE enabled on {len(linkless)} linkless port(s): "
            + ', '.join(sorted(linkless)),
            detail='Wasted power + physical attack surface — '
                   'plug in a rogue device and it gets powered',
            fix_cmd="set_poe(interface=<port>, enabled=False)")
    return _make_finding(
        spec, "PoE active on linked ports only", passed=True)


# --- sec-unused-ports (admin-enabled ports with no link/neighbor) ----------

@register_check('sec-unused-ports')
def check_unused_ports(state, spec, config):
    ifaces = state.get('get_interfaces')
    if ifaces is None:
        return _unable(spec)
    # Build exclusion set: LLDP neighbors + MRP ring ports
    exclude = set()
    neighbors = state.get('get_lldp_neighbors')
    if neighbors:
        exclude.update(neighbors.keys())
    mrp = state.get('get_mrp')
    if mrp:
        for domain in mrp.values() if isinstance(mrp, dict) else [mrp]:
            for key in ('ring_port_1', 'ring_port_2'):
                rp = domain.get(key, {}) if isinstance(domain, dict) else {}
                iface = rp.get('interface', '') if isinstance(rp, dict) else ''
                if iface:
                    exclude.add(iface)
    # Unused = admin-enabled, no link, no LLDP neighbor, not ring port
    unused = []
    for port, pcfg in sorted(ifaces.items()):
        if port in exclude:
            continue
        if not pcfg.get('is_enabled', True):
            continue  # already admin-disabled — good
        if pcfg.get('is_up', False):
            continue  # has link — in use
        unused.append(port)
    if unused:
        sample = ', '.join(unused[:8])
        suffix = (f' (+{len(unused) - 8} more)'
                  if len(unused) > 8 else '')
        return _make_finding(
            spec,
            f"{len(unused)} unused port(s) admin-enabled: {sample}{suffix}",
            detail='Admin-disable unused ports to reduce attack surface '
                   '— harden deferred (requires site-specific port plan)')
    return _make_finding(
        spec, 'No unused admin-enabled ports detected', passed=True)


# --- sec-console-port (physical diagnostic port control) -------------------

# Hardware profile: model prefix → physical port capabilities
# Derived from Hirschy family_props.json (oob, console, aca fields)
_HW_PROFILES = {
    'BRS':     {'console': 'usb_c',     'aca': 'usb_c',    'oob': 'usb_c'},
    'GRS10x':  {'console': 'usb_c',     'aca': 'usb_c',    'oob': 'usb_c'},
    'DRAGON':  {'console': 'v24_rj45',  'aca': 'usb_a_sd', 'oob': 'ethernet_rj45'},
    'GRS1042': {'console': 'v24_rj45',  'aca': 'usb_a_sd', 'oob': 'ethernet_rj45'},
    'GRS10x0': {'console': 'v24_rj45',  'aca': 'usb',      'oob': None},
    'GRS2000': {'console': 'v24_rj45',  'aca': 'microsd',  'oob': None},
    'RSPE':    {'console': 'v24_rj11',  'aca': 'usb_a_sd', 'oob': None},
    'RSP':     {'console': 'v24_rj11',  'aca': 'sd',       'oob': None},
    'MSP':     {'console': 'v24_rj45',  'aca': 'usb_a_sd', 'oob': None},
    'EAGLE40': {'console': 'v24_rj45',  'aca': 'usb',      'oob': None},
    'OS':      {'console': 'v24_m12',   'aca': 'm12_usb',  'oob': None},
    'OS3':     {'console': 'v24_m12',   'aca': 'm12_usb',  'oob': None},
}


def _resolve_hw_profile(model):
    """Resolve model string to hardware profile via longest-prefix match."""
    if not model:
        return None
    best = None
    best_len = 0
    for prefix, profile in _HW_PROFILES.items():
        if model.upper().startswith(prefix.upper()) and len(prefix) > best_len:
            best = profile
            best_len = len(prefix)
    return best


@register_check('sec-console-port')
def check_console_port(state, spec, config):
    sc = state.get('get_session_config')
    if sc is None:
        return _unable(spec)

    # Resolve hardware profile from model
    device_info = config.get('_device_info', {})
    model = device_info.get('model', '')
    hw = _resolve_hw_profile(model)

    issues = []

    # Serial console: timeout should be > 0 (auto-logout)
    serial_timeout = sc.get('serial', {}).get('timeout', 0)
    if serial_timeout == 0:
        issues.append('serial timeout disabled (infinite session)')

    # ENVM (external non-volatile memory): should be disabled
    envm = sc.get('envm', {})
    if envm.get('enabled', False):
        aca_type = hw.get('aca', 'unknown') if hw else 'unknown'
        issues.append(f'external storage enabled ({aca_type})')

    if not issues:
        parts = [f'serial timeout={serial_timeout}m']
        if not envm.get('enabled', True):
            parts.append('ENVM disabled')
        hw_note = f' [{model}]' if model else ''
        return _make_finding(
            spec,
            f"Physical ports secured ({', '.join(parts)}){hw_note}",
            passed=True)

    return _make_finding(
        spec,
        '; '.join(issues).capitalize(),
        detail='EDR 2.13: physical diagnostic ports must be secured — '
               'configure serial timeout and disable external storage',
        fix_cmd="set_session_config(serial_timeout=5, envm_enabled=False)")


# --- sec-remote-auth (any remote auth configured?) -------------------------

@register_check('sec-remote-auth')
def check_remote_auth(state, spec, config):
    auth = state.get('get_remote_auth')
    if auth is None:
        return _unable(spec)
    active = [name for name in ('radius', 'tacacs', 'ldap')
              if auth.get(name, {}).get('enabled')]
    if active:
        return _make_finding(
            spec,
            f"Remote authentication active: {', '.join(active).upper()}",
            passed=True)
    return _make_finding(
        spec,
        "No remote authentication configured",
        detail='Local-only authentication — no RADIUS, TACACS+, or LDAP. '
               'IEC 62443 CR 1.1 SL2 requires centralized authentication '
               'for accountability and lifecycle management',
        fix_cmd=None)


# --- sec-user-review (local account lifecycle advisory) ---------------------

@register_check('sec-user-review')
def check_user_review(state, spec, config):
    users = state.get('get_users')
    if users is None:
        return _unable(spec)
    names = [u['name'] for u in users]
    inactive = [u['name'] for u in users if not u.get('active')]
    locked = [u['name'] for u in users if u.get('locked')]
    parts = [f"{len(names)} local account(s): {', '.join(names)}"]
    if inactive:
        parts.append(f"inactive: {', '.join(inactive)}")
    if locked:
        parts.append(f"locked: {', '.join(locked)}")
    return _make_finding(
        spec, '; '.join(parts), passed=True,
        detail='Advisory — review for dormant/unnecessary accounts. '
               'IEC 62443 CR 1.3/1.4 requires account lifecycle management')


# --- sec-user-roles (RBAC check) -------------------------------------------

@register_check('sec-user-roles')
def check_user_roles(state, spec, config):
    users = state.get('get_users')
    if users is None:
        return _unable(spec)
    # If remote auth is active, local admin-only is fine (break-glass)
    auth = state.get('get_remote_auth')
    if auth:
        remote_active = any(
            auth.get(p, {}).get('enabled')
            for p in ('radius', 'tacacs', 'ldap'))
        if remote_active:
            return _make_finding(
                spec,
                'Remote authentication active — local accounts are '
                'break-glass only',
                passed=True)
    # No remote auth: check that not ALL local users are admin
    active_users = [u for u in users if u.get('active')]
    if not active_users:
        return _make_finding(
            spec, 'No active local users found',
            detail='Cannot assess role diversity without active users')
    roles = {u['role'] for u in active_users}
    all_admin = roles == {'administrator'}
    if all_admin and len(active_users) > 1:
        return _make_finding(
            spec,
            f"All {len(active_users)} active users are administrators",
            detail='Principle of least privilege: create operator/guest '
                   'accounts for non-admin functions',
            fix_cmd=None)
    if all_admin:
        return _make_finding(
            spec,
            'Single admin account — consider adding operator account',
            detail='RBAC requires role separation; add non-admin accounts '
                   'for day-to-day operations',
            fix_cmd=None)
    return _make_finding(
        spec,
        f"Role diversity OK: {', '.join(sorted(roles))}",
        passed=True)


# --- sec-snmpv3-auth (all v3 users should use SHA) -------------------------

@register_check('sec-snmpv3-auth')
def check_snmpv3_auth(state, spec, config):
    snmp = state.get('get_snmp_config')
    if snmp is None:
        return _unable(spec)
    users = snmp.get('v3_users', [])
    if not users:
        return _make_finding(
            spec, 'No SNMPv3 users found',
            detail='Cannot assess authentication without user data')
    weak = [u['name'] for u in users
            if u.get('auth_type', '') in ('', 'md5')]
    if not weak:
        return _make_finding(
            spec, "All SNMPv3 users use SHA authentication",
            passed=True)
    return _make_finding(
        spec,
        f"Weak/no auth: {', '.join(weak)}",
        detail='MD5 is deprecated; use SHA for SNMPv3 authentication',
        fix_cmd="snmp user <name> auth sha <pass>")


# --- sec-snmpv3-encrypt (all v3 users should use AES) ----------------------

@register_check('sec-snmpv3-encrypt')
def check_snmpv3_encrypt(state, spec, config):
    snmp = state.get('get_snmp_config')
    if snmp is None:
        return _unable(spec)
    users = snmp.get('v3_users', [])
    if not users:
        return _make_finding(
            spec, 'No SNMPv3 users found',
            detail='Cannot assess encryption without user data')
    weak = [u['name'] for u in users
            if u.get('enc_type', 'none') in ('none', 'des')]
    if not weak:
        return _make_finding(
            spec, "All SNMPv3 users use AES encryption",
            passed=True)
    return _make_finding(
        spec,
        f"Weak/no encryption: {', '.join(weak)}",
        detail='DES is deprecated; use AES for SNMPv3 privacy',
        fix_cmd="snmp user <name> auth sha <pass> priv aes <pass>")


# --- sec-snmpv3-traps (trap service + v3 authpriv destination) --------------

@register_check('sec-snmpv3-traps')
def check_snmpv3_traps(state, spec, config):
    snmp = state.get('get_snmp_config')
    if snmp is None:
        return _unable(spec)
    issues = []
    if not snmp.get('trap_service'):
        issues.append('trap service disabled')
    dests = snmp.get('trap_destinations', [])
    v3_authpriv = [d for d in dests
                   if d.get('security_model') == 'v3'
                   and d.get('security_level') == 'authpriv']
    if not v3_authpriv:
        issues.append('no SNMPv3 authPriv trap destination')
    if not issues:
        return _make_finding(
            spec,
            f"Trap service enabled with {len(v3_authpriv)} "
            f"v3 authPriv destination(s)",
            passed=True)
    return _make_finding(
        spec, '; '.join(issues).capitalize(),
        detail='SNMPv3 traps provide encrypted event notification',
        fix_cmd="snmp trap add <name> <ip> auth sha <pass> priv aes <pass>")


# --- sec-concurrent-sessions (SL2 — session limit per interface) -----------

@register_check('sec-concurrent-sessions')
def check_concurrent_sessions(state, spec, config):
    sc = state.get('get_session_config')
    if sc is None:
        return _unable(spec)
    unlimited = []
    for proto in ('ssh', 'ssh_outbound', 'telnet', 'netconf'):
        ms = sc.get(proto, {}).get('max_sessions')
        if ms is not None and ms > 5:
            unlimited.append(f"{proto}={ms}")
    if not unlimited:
        return _make_finding(
            spec, "Concurrent session limits configured",
            passed=True)
    return _make_finding(
        spec,
        f"High session limits: {', '.join(unlimited)}",
        detail='SL2 CR 2.7 requires ability to limit concurrent sessions',
        fix_cmd="set_session_config(ssh_max_sessions=5, telnet_max_sessions=5)")


# --- sec-crypto-ciphers (CR 4.3 — cipher depth) ----------------------------

# Weak algorithm sets — anything here should be disabled for SL2 compliance
_WEAK_TLS_VERSIONS = {'tlsv1.0', 'tlsv1.1'}
_WEAK_TLS_CIPHERS = {
    'tls-rsa-with-rc4-128-sha',       # RC4 — broken
    'tls-rsa-with-aes-128-cbc-sha',   # no PFS + CBC
}
_WEAK_SSH_KEX = {
    'diffie-hellman-group1-sha1',      # 768-bit DH + SHA1
}
_WEAK_SSH_HOST_KEY = {
    'ssh-dss',                         # DSA deprecated
    'ssh-rsa',                         # SHA1-based RSA
    'ssh-rsa-cert-v01@openssh.com',    # SHA1-based RSA cert
}


@register_check('sec-crypto-ciphers')
def check_crypto_ciphers(state, spec, config):
    svc = state.get('get_services')
    if svc is None:
        return _unable(spec)
    https = svc.get('https', {})
    ssh_cfg = svc.get('ssh', {})
    # Empty lists = SSH backend or older firmware — can't assess
    tls_vers = https.get('tls_versions', [])
    tls_cs = https.get('tls_cipher_suites', [])
    ssh_kex = ssh_cfg.get('kex_algorithms', [])
    ssh_hk = ssh_cfg.get('host_key_algorithms', [])
    if not tls_vers and not tls_cs and not ssh_kex and not ssh_hk:
        return _make_finding(
            spec, 'Cipher data unavailable (SSH backend returns empty)',
            detail='Use MOPS or SNMP protocol to assess cipher configuration')
    issues = []
    weak_tv = _WEAK_TLS_VERSIONS & set(tls_vers)
    if weak_tv:
        issues.append(f"TLS {', '.join(sorted(weak_tv))} enabled")
    weak_tc = _WEAK_TLS_CIPHERS & set(tls_cs)
    if weak_tc:
        issues.append(f"weak TLS ciphers: {', '.join(sorted(weak_tc))}")
    weak_kex = _WEAK_SSH_KEX & set(ssh_kex)
    if weak_kex:
        issues.append(f"weak SSH KEX: {', '.join(sorted(weak_kex))}")
    weak_hk = _WEAK_SSH_HOST_KEY & set(ssh_hk)
    if weak_hk:
        issues.append(f"weak SSH host key: {', '.join(sorted(weak_hk))}")
    if issues:
        return _make_finding(
            spec, '; '.join(issues),
            detail='CR 4.3 requires strong cryptographic configuration',
            fix_cmd="set_services(tls_versions=['tlsv1.2'], ...)")
    return _make_finding(
        spec, 'Strong cryptographic configuration', passed=True)


# --- sec-https-cert (DevSec trap cause #23) --------------------------------

@register_check('sec-https-cert')
def check_https_cert(state, spec, config):
    ds = state.get('get_devsec_status')
    if ds is None:
        return _unable(spec)
    events = ds.get('status', {}).get('events', [])
    cert_warn = any(
        e.get('cause') == 'https-certificate-warning' for e in events)
    if not cert_warn:
        monitoring = ds.get('monitoring', {})
        if not monitoring.get('https_certificate_warning', False):
            return _make_finding(
                spec,
                'HTTPS cert monitor disabled — enable to assess',
                detail='Enable hm2DevSecSenseHttpsCertWarning to detect '
                       'factory-default certificates')
        return _make_finding(
            spec, "HTTPS certificate OK (no DevSec warning)",
            passed=True)
    return _make_finding(
        spec,
        'Factory-default or self-signed HTTPS certificate detected',
        detail='Generate a device-specific certificate or install a '
               'CA-signed certificate',
        fix_cmd="https certificate generate")


# --- sec-dev-mode (DevSec trap cause #32) ----------------------------------

@register_check('sec-dev-mode')
def check_dev_mode(state, spec, config):
    ds = state.get('get_devsec_status')
    if ds is None:
        return _unable(spec)
    events = ds.get('status', {}).get('events', [])
    dev_active = any(
        e.get('cause') == 'dev-mode-enabled' for e in events)
    if not dev_active:
        monitoring = ds.get('monitoring', {})
        if not monitoring.get('dev_mode_enabled', False):
            return _make_finding(
                spec,
                'Dev-mode monitor disabled — enable to assess',
                detail='Enable hm2DevSecSenseDevModeEnabled to detect')
        return _make_finding(
            spec, "Development mode disabled", passed=True)
    return _make_finding(
        spec,
        'Development/debug mode is enabled',
        detail='Disable dev-mode for production deployment')


# --- sec-secure-boot (DevSec trap cause #31) -------------------------------

@register_check('sec-secure-boot')
def check_secure_boot(state, spec, config):
    ds = state.get('get_devsec_status')
    if ds is None:
        return _unable(spec)
    events = ds.get('status', {}).get('events', [])
    boot_warn = any(
        e.get('cause') == 'secure-boot-disabled' for e in events)
    if not boot_warn:
        monitoring = ds.get('monitoring', {})
        if not monitoring.get('secure_boot_disabled', False):
            return _make_finding(
                spec,
                'Secure-boot monitor disabled — enable to assess',
                detail='Enable hm2DevSecSenseSecureBootDisabled to detect')
        return _make_finding(
            spec, "Secure boot enabled", passed=True)
    return _make_finding(
        spec,
        'Secure boot is disabled',
        detail='Hardware-dependent — may require firmware reinstall')


# --- cert-inherent helpers -------------------------------------------------

def _cert_pass(state, spec, config, capability):
    """Auto-pass for hardware capabilities proven by TÜV SL-C 2 cert.

    References the device's cert from certs.json (not a copy — just
    the cert ID and SL-C level as evidence).
    """
    device_info = config.get('_device_info', {})
    model = device_info.get('model', '?')
    certs = load_certs()
    cert_info = resolve_cert(certs, model) if certs else None
    if cert_info and cert_info.get('cert'):
        cert_ref = f"{cert_info['cert']} SL-C {cert_info['sl_c']}"
        return _make_finding(
            spec,
            f"{capability} — certified ({cert_ref})",
            passed=True,
            detail=f"Evidence: {cert_ref} covers {spec['clause']}")
    return _make_finding(
        spec,
        f"{capability} — no cert found for {model}",
        detail='Device family not in certs.json — cannot verify')


# --- cert-hw-authenticator (CR 1.5 SL2 — certified capability) ------------

@register_check('cert-hw-authenticator')
def check_cert_hw_authenticator(state, spec, config):
    return _cert_pass(state, spec, config,
                      'Hardware-protected authenticator storage')


# --- cert-hw-pubkey (CR 1.9 SL2 — certified capability) -------------------

@register_check('cert-hw-pubkey')
def check_cert_hw_pubkey(state, spec, config):
    return _cert_pass(state, spec, config,
                      'Hardware-protected private key storage')


# --- cert-hw-symkey (CR 1.14 SL2 — certified capability) ------------------

@register_check('cert-hw-symkey')
def check_cert_hw_symkey(state, spec, config):
    return _cert_pass(state, spec, config,
                      'Hardware-protected shared key storage')


# --- cert-memory-purge (CR 4.2 SL2 — certified capability) ----------------

@register_check('cert-memory-purge')
def check_cert_memory_purge(state, spec, config):
    return _cert_pass(state, spec, config,
                      'Non-persistent memory purge capability')


# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

def run_checks(state, check_defs, config, color=C, quiet=False):
    """Run all registered checks against gathered state, return findings."""
    findings = []
    for check_id, spec in check_defs.items():
        fn = CHECK_FNS.get(check_id)
        if fn is None:
            # Stub check — not yet implemented
            finding = _make_finding(
                spec, 'Not yet implemented',
                detail=f"Requires driver method: {spec.get('getter', '?')}()")
            findings.append(finding)
            continue
        if not quiet:
            clause = spec['clause']
            _log(f"CHECK {check_id}",
                 f"{color.DIM}{clause} {spec['clause_title']}{color.RST}",
                 color=color)
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


def print_report(findings, device_info=None, color=C, level='sl1',
                 certs=None):
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
        # Cert context
        if certs:
            cert_info = resolve_cert(certs, model)
            if cert_info and cert_info.get('cert'):
                valid = cert_info.get('valid_until', '')
                valid_str = f", valid to {valid}" if valid else ''
                print(f"  {color.BOLD}Cert:{color.RST}    "
                      f"{color.CYN}{cert_info['cert']} "
                      f"(SL-C {cert_info['sl_c']}{valid_str}){color.RST}")
            elif cert_info and cert_info.get('note'):
                print(f"  {color.BOLD}Cert:{color.RST}    "
                      f"{color.DIM}{cert_info['note']}{color.RST}")
    print(f"  {color.BOLD}Level:{color.RST}   {level}")
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
    not_impl = sum(1 for f in findings
                   if 'Not yet implemented' in f.desc)
    assessed = total - not_impl
    unable = sum(1 for f in findings
                 if 'Unable to assess' in f.desc)

    print(f"  {'─' * W}")
    print()
    if total > 0:
        has_crit = any(not f.passed and f.severity == 'critical'
                       for f in findings)
        sc = color.RED if has_crit else (color.YEL if failed else color.GRN)
        pct = passed * 100 // total
        not_impl_str = (f" ({not_impl} not yet implemented)"
                        if not_impl else '')
        print(f"  {color.BOLD}Score:{color.RST}  "
              f"{sc}{passed}/{total} passed{color.RST} ({level})"
              f"{color.DIM}{not_impl_str}{color.RST}")
        print(_score_bar(passed, total, color=color))
        if unable:
            print(f"  {color.DIM}{unable} check(s) could not be "
                  f"assessed (driver extension needed){color.RST}")

    # Recommendations section
    failures = [f for f in findings if not f.passed]
    if failures:
        print()
        print(f"  {color.BOLD}┌─ Recommendations {'─' * (W - 21)}┐{color.RST}")

        auto_fixable = [f for f in failures if f.fix_cmd]
        advisory = [f for f in failures if not f.fix_cmd
                     and 'Unable to assess' not in f.desc
                     and 'Not yet implemented' not in f.desc]
        unable = [f for f in failures if 'Unable to assess' in f.desc]
        not_impl = [f for f in failures
                     if 'Not yet implemented' in f.desc]

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

        if not_impl:
            print(f"  {color.BOLD}│{color.RST}")
            print(f"  {color.BOLD}│  {color.DIM}Not yet implemented "
                  f"({len(not_impl)}) — requires new driver methods:{color.RST}")
            ids = ', '.join(f.check_id for f in not_impl)
            print(f"  {color.BOLD}│{color.RST}    {color.DIM}{ids}{color.RST}")

        print(f"  {color.BOLD}│{color.RST}")
        print(f"  {color.BOLD}└{'─' * (W - 1)}┘{color.RST}")
    elif total > 0 and failed == 0:
        print()
        print(f"  {color.GRN}{color.BOLD}All checks passed.{color.RST}")

    print()


def print_fleet_report(all_results, failures, elapsed, color=C,
                       numbered=False, level='sl1'):
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
        print(f"  {color.DIM}{n_ok} devices  {level}  "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M')}{color.RST}")
    else:
        _box_header("JUSTIN — IEC 62443-4-2 Fleet Audit", W, color)
        print(f"  {color.BOLD}Devices:{color.RST} {n_ok} audited"
              + (f", {color.RED}{n_fail} unreachable{color.RST}"
                 if n_fail else ""))
        print(f"  {color.BOLD}Level:{color.RST}   {level}")
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

def to_json(findings, device_info=None, level='sl1', check_defs=None,
            evidence=None):
    """Return findings as JSON-serialisable dict.

    When check_defs is provided, enriches each finding with source,
    vendor_ref, fix_cli, fix_webui, fix_tool, and evidence_key from
    the spec. When evidence is provided, includes the full timestamped
    getter results for the audit trail.
    """
    enriched = []
    for f in findings:
        d = f.to_dict()
        if check_defs:
            spec = check_defs.get(f.check_id, {})
            d['source'] = spec.get('source', 'iec')
            if spec.get('vendor_ref'):
                d['vendor_ref'] = spec['vendor_ref']
            if spec.get('fix_cli'):
                d['fix_cli'] = spec['fix_cli']
            if spec.get('fix_tool'):
                d['fix_tool'] = spec['fix_tool']
            if spec.get('getter'):
                d['evidence_key'] = spec['getter']
        enriched.append(d)
    result = {
        'findings': enriched,
        'timestamp': datetime.now().isoformat(),
        'level': level,
    }
    if device_info:
        result['device'] = device_info
    if evidence:
        result['evidence'] = evidence
    total = len(findings)
    passed = sum(1 for f in findings if f.passed)
    not_impl = sum(1 for f in findings
                   if 'Not yet implemented' in f.desc)
    result['score'] = {
        'total': total,
        'passed': passed,
        'failed': total - passed,
        'not_implemented': not_impl,
    }
    return result


def fleet_to_json(all_results, failures, level='sl1', check_defs=None):
    """Return full fleet results as JSON-serialisable dict."""
    output = {
        'fleet': {},
        'failures': {ip: err for ip, err in failures},
        'timestamp': datetime.now().isoformat(),
        'level': level,
    }
    for ip, data in all_results.items():
        output['fleet'][ip] = to_json(
            data['findings'], data['device'], level, check_defs,
            evidence=data.get('evidence'))
    return output


def save_report(report_dict, output_path):
    """Write report JSON to file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report_dict, f, indent=2)


def save_html_report(report_data, output_path, certs=None):
    """Write a self-contained HTML report file.

    Embeds report JSON and certs data into the HTML template.
    The template uses inline CSS and JS — no external dependencies.
    """
    from _html_template import HTML_TEMPLATE
    json_data = json.dumps(report_data, indent=2, default=str)
    certs_data = json.dumps(certs or {})
    html = HTML_TEMPLATE.format(
        json_data=json_data,
        certs_data=certs_data,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M'))
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html)


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
            'version': '0.2',
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


def enforce_clean_config(device, ip, mode, color=C, config=None):
    """Refuse to harden a dirty switch. Audit gets a warning. Returns True if OK.

    When config['dirty_guard'] is False, dirty switches get a warning
    instead of a hard refusal.
    """
    saved, status = check_config_saved(device, color)
    if saved:
        _log('CONFIG', f"{color.GRN}Config status: saved{color.RST}",
             color=color)
        return True

    nvm_state = status.get('nvm', 'unknown')
    dirty_guard = True if config is None else config.get('dirty_guard', True)
    if mode == 'harden' and dirty_guard:
        _log('CONFIG', f"{color.RED}{color.BOLD}REFUSED: "
             f"{ip} has unsaved config changes "
             f"(NVM: {nvm_state}){color.RST}", color=color)
        _log('CONFIG', f"{color.RED}JUSTIN will not modify an "
             f"unsaved switch.{color.RST}", color=color)
        _log('CONFIG', f"{color.DIM}Save the config first, "
             f"then re-run.{color.RST}", color=color)
        return False
    elif mode == 'harden':
        _log('CONFIG', f"{color.YEL}WARNING: {ip} has unsaved changes "
             f"(NVM: {nvm_state}) — dirty-config guard OFF, "
             f"proceeding{color.RST}", color=color)
        return True
    else:
        _log('CONFIG', f"{color.YEL}WARNING: {ip} has unsaved config "
             f"changes (NVM: {nvm_state}){color.RST}", color=color)
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
    addrs = [s.strip() for s in ntp_server.split(',') if s.strip()]
    servers = [{'address': a} for a in addrs]
    device.set_ntp(enabled=True, servers=servers)
    return f"set_ntp(enabled=True, servers=[{', '.join(addrs)}])"


@register_harden('sec-logging')
def harden_logging(device, spec, config, color=C):
    syslog_server = config.get('syslog_server')
    if not syslog_server:
        return None
    port = int(config.get('syslog_port', 514))
    addrs = [s.strip() for s in syslog_server.split(',') if s.strip()]
    servers = [{'index': i + 1, 'ip': a, 'port': port,
                'severity': 'warning', 'transport': 'udp'}
               for i, a in enumerate(addrs)]
    device.set_syslog(enabled=True, servers=servers)
    joined = ', '.join(addrs)
    return f"set_syslog(enabled=True, servers=[{joined}:{port}])"


@register_harden('sec-snmpv1-traps')
def harden_snmpv1_traps(device, spec, config, color=C):
    device.set_snmp_config(v1=False)
    return "set_snmp_config(v1=False)"


@register_harden('sec-snmpv1v2-write')
def harden_snmpv1v2_write(device, spec, config, color=C):
    device.set_snmp_config(v1=False, v2=False)
    return "set_snmp_config(v1=False, v2=False)"


@register_harden('sec-unsigned-sw')
def harden_unsigned_sw(device, spec, config, color=C):
    device.set_services(unsigned_sw=False)
    return "set_services(unsigned_sw=False)"


@register_harden('sec-aca-auto-update')
def harden_aca_auto_update(device, spec, config, color=C):
    device.set_services(aca_auto_update=False)
    return "set_services(aca_auto_update=False)"


@register_harden('sec-aca-config-write')
def harden_aca_config_write(device, spec, config, color=C):
    device.set_services(aca_config_write=False)
    return "set_services(aca_config_write=False)"


@register_harden('sec-aca-config-load')
def harden_aca_config_load(device, spec, config, color=C):
    device.set_services(aca_config_load=False)
    return "set_services(aca_config_load=False)"


@register_harden('sec-devsec-monitors')
def harden_devsec_monitors(device, spec, config, color=C):
    device.set_services(devsec_monitors=True)
    return "set_services(devsec_monitors=True)"


@register_harden('ns-gvrp-mvrp')
def harden_gvrp_mvrp(device, spec, config, color=C):
    device.set_services(mvrp=False)
    return "set_services(mvrp=False)"


@register_harden('ns-gmrp-mmrp')
def harden_gmrp_mmrp(device, spec, config, color=C):
    device.set_services(mmrp=False)
    return "set_services(mmrp=False)"


@register_harden('sec-industrial-protocols')
def harden_industrial_protocols(device, spec, config, color=C):
    svc = device.get_services('industrial')
    ind = svc.get('industrial', {})
    kwargs = {}
    for proto in ('profinet', 'modbus', 'ethernet_ip', 'iec61850'):
        if ind.get(proto):
            kwargs[proto] = False
    if not kwargs:
        return None
    device.set_services(**kwargs)
    return f"set_services({', '.join(f'{k}=False' for k in kwargs)})"


@register_harden('sec-password-policy')
def harden_password_policy(device, spec, config, color=C):
    defaults = spec.get('harden_defaults', {})
    device.set_login_policy(
        min_uppercase=defaults.get('min_uppercase', 1),
        min_lowercase=defaults.get('min_lowercase', 1),
        min_numeric=defaults.get('min_numeric', 1),
        min_special=defaults.get('min_special', 1),
    )
    return ("set_login_policy(min_uppercase=1, min_lowercase=1, "
            "min_numeric=1, min_special=1)")


@register_harden('sec-login-banner')
def harden_login_banner(device, spec, config, color=C):
    banner_text = config.get('login_banner',
                             'This system is for authorized use only.')
    device.set_banner(pre_login_enabled=True, pre_login_text=banner_text)
    return f"set_banner(pre_login_enabled=True, pre_login_text='{banner_text}')"


@register_harden('sec-signal-contact')
def harden_signal_contact(device, spec, config, color=C):
    device.set_signal_contact(contact_id=1, mode='deviceStateAndSecurity')
    return "set_signal_contact(contact_id=1, mode='deviceStateAndSecurity')"


@register_harden('sec-session-timeouts')
def harden_session_timeouts(device, spec, config, color=C):
    t = spec.get('harden_defaults', {}).get('timeout', 5)
    device.set_session_config(
        ssh_timeout=t, ssh_outbound_timeout=t,
        telnet_timeout=t, web_timeout=t, serial_timeout=t)
    return (f"set_session_config(ssh_timeout={t}, ssh_outbound_timeout={t}, "
            f"telnet_timeout={t}, web_timeout={t}, serial_timeout={t})")


@register_harden('sec-ip-restrict')
def harden_ip_restrict(device, spec, config, color=C):
    subnet = config.get('mgmt_subnet')
    if not subnet:
        logger.warning(
            "Set mgmt_subnet in config to enable "
            "IP restriction hardening")
        return None
    if '/' in subnet:
        net, prefix = subnet.rsplit('/', 1)
        prefix_len = int(prefix)
    else:
        net = subnet
        prefix_len = 24
    device.add_ip_restrict_rule(
        index=1, ip=net, prefix_length=prefix_len)
    device.set_ip_restrict(enabled=True)
    return (f"add_ip_restrict_rule(1, ip='{net}', "
            f"prefix_length={prefix_len}) + "
            f"set_ip_restrict(enabled=True)")


@register_harden('sec-dns-client')
def harden_dns_client(device, spec, config, color=C):
    device.set_dns(enabled=False)
    return "set_dns(enabled=False)"


@register_harden('sec-poe')
def harden_poe(device, spec, config, color=C):
    poe = device.get_poe()
    ifaces = device.get_interfaces()
    disabled = []
    for port, cfg in poe.get('ports', {}).items():
        if cfg.get('enabled') and not ifaces.get(port, {}).get('is_up', True):
            device.set_poe(interface=port, enabled=False)
            disabled.append(port)
    if disabled:
        return f"set_poe(enabled=False) on {', '.join(sorted(disabled))}"
    return "no linkless PoE ports found"


@register_harden('sec-concurrent-sessions')
def harden_concurrent_sessions(device, spec, config, color=C):
    ms = spec.get('harden_defaults', {}).get('max_sessions', 5)
    device.set_session_config(
        ssh_max_sessions=ms, telnet_max_sessions=ms)
    return (f"set_session_config(ssh_max_sessions={ms}, "
            f"telnet_max_sessions={ms})")


@register_harden('sec-crypto-ciphers')
def harden_crypto_ciphers(device, spec, config, color=C):
    svc = device.get_services()
    https = svc.get('https', {})
    ssh_cfg = svc.get('ssh', {})
    kwargs = {}
    # TLS versions — keep only 1.2+
    tls_vers = https.get('tls_versions', [])
    if tls_vers:
        strong_tv = [v for v in tls_vers if v not in _WEAK_TLS_VERSIONS]
        if len(strong_tv) < len(tls_vers):
            kwargs['tls_versions'] = strong_tv if strong_tv else ['tlsv1.2']
    # TLS cipher suites — remove weak
    tls_cs = https.get('tls_cipher_suites', [])
    if tls_cs:
        strong_tc = [c for c in tls_cs if c not in _WEAK_TLS_CIPHERS]
        if len(strong_tc) < len(tls_cs):
            kwargs['tls_cipher_suites'] = strong_tc
    # SSH KEX — remove weak
    ssh_kex = ssh_cfg.get('kex_algorithms', [])
    if ssh_kex:
        strong_kex = [k for k in ssh_kex if k not in _WEAK_SSH_KEX]
        if len(strong_kex) < len(ssh_kex):
            kwargs['ssh_kex'] = strong_kex
    # SSH host key — remove weak
    ssh_hk = ssh_cfg.get('host_key_algorithms', [])
    if ssh_hk:
        strong_hk = [k for k in ssh_hk if k not in _WEAK_SSH_HOST_KEY]
        if len(strong_hk) < len(ssh_hk):
            kwargs['ssh_host_key'] = strong_hk
    if not kwargs:
        return None
    device.set_services(**kwargs)
    parts = []
    for k, v in kwargs.items():
        parts.append(f"{k}={v}")
    return f"set_services({', '.join(parts)})"


@register_harden('sys-default-passwords')
def harden_default_passwords(device, spec, config, color=C):
    new_pw = config.get('harden_password')
    if not new_pw:
        return None  # requires harden_password config key
    users = device.get_users()
    defaults = [u['name'] for u in users if u.get('default_password')]
    if not defaults:
        return "no default-password users found"
    changed = []
    for name in defaults:
        device.set_user(name, password=new_pw)
        changed.append(name)
    return f"set_user(password=<new>) on {', '.join(changed)}"


@register_harden('sec-snmpv3-auth')
def harden_snmpv3_auth(device, spec, config, color=C):
    snmp_pw = config.get('snmp_password')
    if not snmp_pw:
        return None  # requires snmp_password config key
    users = device.get_users()
    weak = [u['name'] for u in users
            if u.get('snmp_auth') in ('', 'md5') and u.get('active')]
    if not weak:
        return "all active users already use SHA authentication"
    upgraded = []
    for name in weak:
        device.set_user(name, snmp_auth_type='sha',
                        snmp_auth_password=snmp_pw)
        upgraded.append(name)
    return (f"set_user(snmp_auth_type='sha') on "
            f"{', '.join(upgraded)}")


@register_harden('sec-snmpv3-encrypt')
def harden_snmpv3_encrypt(device, spec, config, color=C):
    snmp_pw = config.get('snmp_password')
    if not snmp_pw:
        return None  # requires snmp_password config key
    users = device.get_users()
    weak = [u['name'] for u in users
            if u.get('snmp_enc') in ('none', 'des') and u.get('active')]
    if not weak:
        return "all active users already use AES encryption"
    upgraded = []
    for name in weak:
        device.set_user(name, snmp_enc_type='aes128',
                        snmp_enc_password=snmp_pw)
        upgraded.append(name)
    return (f"set_user(snmp_enc_type='aes128') on "
            f"{', '.join(upgraded)}")


@register_harden('sec-snmpv3-traps')
def harden_snmpv3_traps(device, spec, config, color=C):
    trap_ip = config.get('trap_dest_ip')
    if not trap_ip:
        return None  # requires trap_dest_ip config key
    snmp = device.get_snmp_config()
    # Check if trap service is enabled
    if not snmp.get('trap_service'):
        device.set_snmp_config(trap_service=True)
    # Check for existing v3 authpriv destination to this IP
    dests = snmp.get('trap_destinations', [])
    existing = [d for d in dests
                if d.get('security_model') == 'v3'
                and d.get('security_level') == 'authpriv'
                and trap_ip in d.get('address', '')]
    if existing:
        svc_msg = " (trap service was disabled)" if not snmp.get('trap_service') else ""
        return (f"v3 authPriv destination to {trap_ip} already "
                f"exists{svc_msg}")
    # Add v3 authpriv trap destination
    name = f"justin_{trap_ip.replace('.', '_')}"
    device.add_snmp_trap_dest(
        name, trap_ip, security_model='v3',
        security_name='admin', security_level='authpriv')
    svc_msg = " + enabled trap service" if not snmp.get('trap_service') else ""
    return (f"add_snmp_trap_dest('{name}', '{trap_ip}', "
            f"v3/admin/authpriv){svc_msg}")


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
    Retry with escalating delays if NVM hasn't settled after save.
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

    # NVM may still be settling after save_config(). Retry with
    # escalating delays: 0s → 5s → 7.5s → ask user.
    delays = [0, 5, 7.5]
    last_err = None
    for i, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        try:
            device.load_config(nvm_cfg['running'], profile=final,
                               destination='nvm')
            return final
        except Exception as e:
            last_err = e
            if i < len(delays) - 1:
                logging.debug("Snapshot upload attempt %d failed, "
                              "retrying in %.0fs", i + 1, delays[i + 1])

    # All retries failed — ask user
    print(f"\n  NVM still busy after {sum(delays):.0f}s.")
    ans = input("  Wait 15s and retry? [Y/n]: ").strip().lower()
    if ans in ('', 'y', 'yes'):
        time.sleep(15)
        nvm_cfg = device.get_config(profile=active_name, source='nvm')
        device.load_config(nvm_cfg['running'], profile=final,
                           destination='nvm')
        return final
    raise last_err


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
                  gather_fn=None, watchdog_seconds=None, session=None,
                  snapshot_name=None):
    """Apply remediation for failed findings. Returns (applied, changes_log, state_diff).

    The JUSTIN way: record everything. Before/after state. Every call logged.
    Watchdog safety net: start timer before changes, stop on success,
    auto-revert on failure/timeout.

    When snapshot_name is provided and protocol is MOPS, creates a
    pre-harden snapshot ({name}-pre) before applying any changes so the
    exact state before JUSTIN touched the switch is preserved.
    The caller creates the post-harden snapshot ({name}-post) after save.
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
            _log('CONFIG', f"{color.DIM}Config backup captured{color.RST}",
                 color=color)
            if session:
                session.update(config_backup='captured (get_config)')
        except Exception:
            _log('CONFIG', f"{color.DIM}Config backup not available "
                 f"(SSH-only feature){color.RST}", color=color)
            if session:
                session.update(config_backup='unavailable')

    # Pre-harden snapshot (the "before" in before/after)
    if (snapshot_name and not dry_run
            and config.get('protocol') == 'mops'
            and _is_valid_profile_name(snapshot_name)):
        pre_name = f'{snapshot_name}-pre'
        _log('SNAPSHOT', f"'{pre_name}' (pre-harden) ... ",
             end='', flush=True, color=color)
        try:
            pre_final = _do_snapshot(device, pre_name)
            if pre_final != pre_name:
                print(f"{color.GRN}OK (as '{pre_final}'){color.RST}")
            else:
                print(f"{color.GRN}OK{color.RST}")
            if session:
                session.add_change({
                    'check_id': '_snapshot_pre',
                    'action': f"snapshot('{pre_final}')",
                    'result': 'applied',
                    'timestamp': datetime.now().isoformat(),
                })
        except Exception as e:
            print(f"{color.RED}FAIL ({e}){color.RST}")

    # Watchdog safety net
    watchdog_active = False
    if watchdog_seconds and not dry_run:
        try:
            device.start_watchdog(watchdog_seconds)
            watchdog_active = True
            _log('WATCHDOG', f"{color.CYN}Started: {watchdog_seconds}s "
                 f"rollback timer{color.RST}", color=color)
            if session:
                session.update(watchdog={
                    'started': True, 'seconds': watchdog_seconds,
                    'stopped': False})
        except Exception as e:
            _log('WATCHDOG', f"{color.YEL}Unavailable: {e}{color.RST}",
                 color=color)
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
            _log(f"HARDEN {f.check_id}",
                 f"{color.CYN}[DRY-RUN]{color.RST} {f.fix_cmd or '?'}",
                 color=color)
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

        _log(f"HARDEN {f.check_id}", '', end='', flush=True,
             color=color)
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
        _log('REGATHER', f"{color.DIM}Re-gathering state for "
             f"before/after diff ...{color.RST}", color=color)
        state_after = gather_fn()
        snap_after = _make_state_snapshot(state_after)
        state_diff = _diff_states(state_before, snap_after)
        if state_diff:
            for d in state_diff:
                _log('DIFF', f"{color.CYN}{d['getter']}{color.RST}: "
                     f"changed", color=color)
        elif applied:
            _log('DIFF', f"{color.YEL}WARNING: {len(applied)} fix(es) "
                 f"reported OK but no state change detected{color.RST}",
                 color=color)
        if session:
            session.update(state_after=snap_after, state_diff=state_diff)

    # Stop watchdog — only if no failures occurred (partial config = rollback)
    has_failures = any(e.get('result') == 'failed' for e in changes_log)
    if watchdog_active and applied and not has_failures:
        try:
            device.stop_watchdog()
            _log('WATCHDOG', f"{color.GRN}Stopped (changes "
                 f"confirmed){color.RST}", color=color)
            if session:
                session.update(watchdog={
                    'started': True, 'seconds': watchdog_seconds,
                    'stopped': True})
        except Exception as e:
            _log('WATCHDOG', f"{color.YEL}WARNING: Stop failed: {e} "
                 f"— timer still running!{color.RST}", color=color)
    elif watchdog_active and has_failures:
        n_failed = sum(1 for e in changes_log
                       if e.get('result') == 'failed')
        _log('WATCHDOG', f"{color.YEL}NOT stopped — {n_failed} fix(es) "
             f"failed, allowing rollback{color.RST}", color=color)
        if session:
            session.update(watchdog={
                'started': True, 'seconds': watchdog_seconds,
                'stopped': False, 'reason': 'partial_failure'})

    if save and not dry_run and applied:
        _log('SAVE', 'Saving config to NVM ... ', end='', flush=True,
             color=color)
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

    Returns (ip, device, device_info, findings, state, evidence, error).
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

        state, evidence = gather(device, check_defs, color)
        # Inject device/cert context for cert-inherent check functions
        config['_device_info'] = device_info
        findings = run_checks(state, check_defs, config, color)

        return ip, device, device_info, findings, state, evidence, None
    except Exception as e:
        if device:
            try:
                device.close()
            except Exception:
                pass
        return ip, None, None, None, None, None, str(e)


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
        evidence = {}
        for getter_name in sorted(getters):
            ts = datetime.now().isoformat()
            try:
                result = getattr(device, getter_name)()
                state[getter_name] = result
                evidence[getter_name] = {
                    'gathered_at': ts,
                    'data': json.loads(json.dumps(result, default=str)),
                }
            except Exception:
                state[getter_name] = None
                evidence[getter_name] = {
                    'gathered_at': ts, 'error': 'getter failed',
                }

        # Run checks silently
        findings = []
        for check_id, spec in check_defs.items():
            fn = CHECK_FNS.get(check_id)
            if fn:
                findings.append(fn(state, spec, config))
            else:
                findings.append(_make_finding(
                    spec, 'Not yet implemented',
                    detail=f"Requires driver method: "
                           f"{spec.get('getter', '?')}()"))
        findings.sort(key=lambda f: (
            f.passed, SEVERITY_ORDER.get(f.severity, 9), f.check_id))

        device.close()
        return ip, device_info, findings, evidence, None
    except Exception as e:
        return ip, None, None, None, str(e)
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
                if not enforce_clean_config(device, ip, 'harden', color, config=config):
                    continue

            # Gather state for before/after
            state, _ev = gather(device, check_defs, color)
            snap_before = _make_state_snapshot(state)
            gather_fn = lambda d=device: gather(d, check_defs, color)[0]

            session = SessionLog(ip)
            session.update(mode='harden-from-report', evidence=_ev)

            applied, changes_log, state_diff = harden_device(
                device, findings, check_defs, config,
                dry_run=dry_run, save=save, color=color,
                state_before=snap_before, gather_fn=gather_fn,
                watchdog_seconds=watchdog_seconds, session=session,
                snapshot_name=snapshot_name)

            # Post-harden snapshot per device
            if (snapshot_name and not dry_run and applied
                    and save and config['protocol'] == 'mops'
                    and _is_valid_profile_name(snapshot_name)):
                post_name = f'{snapshot_name}-post'
                _log('SNAPSHOT', f"'{post_name}' (post-harden) ... ",
                     end='', flush=True, color=color)
                try:
                    final = _do_snapshot(device, post_name)
                    print(f"{color.GRN}OK{color.RST}")
                    session.add_change({
                        'check_id': '_snapshot_post',
                        'action': f"snapshot('{final}')",
                        'result': 'applied',
                        'timestamp': datetime.now().isoformat(),
                    })
                except Exception as e:
                    print(f"{color.RED}FAIL ({e}){color.RST}")

            session.finish()
            _log('SESSION', f"{color.DIM}{session.path}{color.RST}",
                 color=color)
            device.close()
        except Exception as e:
            _log('CONNECT', f"{color.RED}FAIL: {e}{color.RST}",
                 color=color)
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


# ---------------------------------------------------------------------------
# Interactive harden input collection
# ---------------------------------------------------------------------------

# Maps check_id → list of required inputs.  Each input dict:
#   config_key: key in config dict to store the value
#   label:      prompt text shown to operator
#   secret:     True → getpass (no echo) + double-confirm
#   shared:     True → same config_key used by multiple checks (prompt once)
HARDEN_PROMPTS = {
    'sys-default-passwords': [{
        'config_key': 'harden_password',
        'label': 'New password for default-password users',
        'secret': True,
    }],
    'sec-snmpv3-auth': [{
        'config_key': 'snmp_password',
        'label': 'SNMPv3 rekey password (auth + encrypt)',
        'secret': True,
        'shared': True,
    }],
    'sec-snmpv3-encrypt': [{
        'config_key': 'snmp_password',
        'label': 'SNMPv3 rekey password (auth + encrypt)',
        'secret': True,
        'shared': True,
    }],
    'sec-logging': [{
        'config_key': 'syslog_server',
        'label': 'Syslog server IP(s)',
        'secret': False,
    }],
    'sec-time-sync': [{
        'config_key': 'ntp_server',
        'label': 'NTP server IP(s)',
        'secret': False,
    }],
    'sec-snmpv3-traps': [{
        'config_key': 'trap_dest_ip',
        'label': 'SNMPv3 trap destination IP',
        'secret': False,
    }],
}


def _prompt_value(label, secret=False, color=C):
    """Prompt for a single value.  Returns value or None on empty/quit.

    For secrets: getpass (no echo) + double-confirm.  Mismatch re-prompts
    once, then skips.  Empty input = skip.
    For plain text: input() with empty = skip.
    """
    if secret:
        val = getpass.getpass(
            f'  {color.GRN}\u25b8{color.RST} {label} '
            f'{color.DIM}(empty=skip){color.RST}: ')
        if not val:
            return None
        confirm = getpass.getpass(
            f'  {color.GRN}\u25b8{color.RST} Confirm: ')
        if val != confirm:
            print(f'  {color.YEL}Mismatch — try again.{color.RST}')
            val = getpass.getpass(
                f'  {color.GRN}\u25b8{color.RST} {label}: ')
            if not val:
                return None
            confirm = getpass.getpass(
                f'  {color.GRN}\u25b8{color.RST} Confirm: ')
            if val != confirm:
                print(f'  {color.RED}Mismatch — skipping.{color.RST}')
                return None
        return val
    else:
        val = input(
            f'  {color.GRN}\u25b8{color.RST} {label} '
            f'{color.DIM}(empty=skip){color.RST}: ').strip()
        return val or None


def _collect_harden_inputs(to_fix, config, device_ips=None, color=C):
    """Collect config values needed by fixable findings.

    Interactive S/P/Q flow for checks that need operator input.
    Populates config dict (site-wide) or returns per_device dict.

    Args:
        to_fix: list of Finding objects (or check_id strings) to harden.
        config: config dict — site-wide values are stored here directly.
        device_ips: list of IP strings for per-device mode (None = single).
        color: ANSI color object.

    Returns:
        (skip_checks, per_device) where:
        - skip_checks: set of check_ids the operator chose to skip entirely.
        - per_device: dict of {ip: {config_key: value}} for per-device values.
          Empty if site-wide or single-device mode.
    """
    check_ids = set()
    for f in to_fix:
        cid = f if isinstance(f, str) else f.check_id
        check_ids.add(cid)

    # Figure out which config keys we need to prompt for
    needed = []  # list of (check_id, prompt_dict)
    prompted_keys = set()  # avoid duplicate prompts for shared keys
    for cid in sorted(check_ids):
        prompts = HARDEN_PROMPTS.get(cid, [])
        for p in prompts:
            key = p['config_key']
            if config.get(key):
                continue  # already have it (from CLI or previous prompt)
            if key in prompted_keys:
                continue  # shared key already collected this round
            needed.append((cid, p))
            prompted_keys.add(key)

    if not needed:
        return set(), {}

    skip_checks = set()
    per_device = {}

    # Group by config_key for display
    print(f'\n  {color.MG}{color.BOLD}\u2500\u2500 Input Required '
          f'\u2500\u2500{color.RST}')

    for cid, p in needed:
        key = p['config_key']
        label = p['label']
        secret = p.get('secret', False)

        # Find all check_ids that share this key (including deduplicated)
        related = [c for c in check_ids
                   if any(pp['config_key'] == key
                          for pp in HARDEN_PROMPTS.get(c, []))]
        if len(related) > 1:
            check_label = ' + '.join(related)
        else:
            check_label = cid

        print(f'\n  {color.CYN}{check_label}{color.RST}'
              f' \u2014 {label}')

        if device_ips and len(device_ips) > 1:
            # Fleet mode: offer S/P/Q
            scope = input(
                f'  {color.GRN}\u25b8{color.RST} '
                f'{color.CYN}[S]{color.RST}ite-wide  '
                f'{color.CYN}[P]{color.RST}er-device  '
                f'{color.CYN}[Q]{color.RST}uit?  '
            ).strip().lower()

            if scope in ('q', 'quit'):
                # Skip all checks that depend on this key
                for rc in related:
                    skip_checks.add(rc)
                print(f'  {color.DIM}Skipped.{color.RST}')
                continue

            if scope in ('p', 'per-device'):
                # Prompt per device with Q to skip individual
                for ip in device_ips:
                    print(f'    {color.DIM}{ip}{color.RST}')
                    val = _prompt_value(label, secret, color)
                    if val is None:
                        # Empty input = skip this device
                        print(f'    {color.DIM}Skipped {ip}.{color.RST}')
                        continue
                    per_device.setdefault(ip, {})[key] = val
                continue

            # Default: site-wide (S or anything else)
            val = _prompt_value(label, secret, color)
            if val:
                config[key] = val
            else:
                for rc in related:
                    skip_checks.add(rc)
                print(f'  {color.DIM}Skipped.{color.RST}')
        else:
            # Single device: prompt with Q = empty/skip
            val = _prompt_value(label, secret, color)
            if val:
                config[key] = val
            else:
                for rc in related:
                    skip_checks.add(rc)
                print(f'  {color.DIM}Skipped.{color.RST}')

    return skip_checks, per_device


def _igather(device, check_defs):
    """Gather state with interactive progress bar.

    Returns (state, evidence) — same contract as gather().
    """
    getters = sorted(set(
        s['getter'] for s in check_defs.values() if s.get('getter')))
    state = {}
    evidence = {}
    for i, g in enumerate(getters, 1):
        _ibar(i, len(getters), g + '()')
        ts = datetime.now().isoformat()
        try:
            result = getattr(device, g)()
            state[g] = result
            evidence[g] = {
                'gathered_at': ts,
                'data': json.loads(json.dumps(result, default=str)),
            }
        except Exception:
            state[g] = None
            evidence[g] = {'gathered_at': ts, 'error': 'getter failed'}
    return state, evidence


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
    if config.get('auto_save'):
        print(f'  {color.CYN}Auto-save enabled{color.RST}')
        save_raw = 'y'
    else:
        save_raw = input(
            f'  {color.GRN}▸{color.RST} Save to NVM? '
            f'{color.DIM}[Y/n]{color.RST}: ').strip().lower()
    if save_raw in ('n', 'no'):
        print(f'  {color.YEL}Changes NOT saved — '
              f'will revert on reboot{color.RST}')
        return

    _log('SAVE', 'Saving config to NVM ... ', end='', flush=True, color=color)
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

    snapshot_mode = config.get('snapshot', 'off')

    # If snapshot mode was set in setup, skip the prompt
    if snapshot_mode == 'off':
        snap_raw = input(
            f'  {color.GRN}▸{color.RST} Create snapshot? '
            f'{color.DIM}[n]{color.RST} '
            f'{color.CYN}y{color.RST}/{color.CYN}n{color.RST}: '
            ).strip().lower()
        if snap_raw not in ('y', 'yes'):
            return
        # Ask mode since they opted in manually
        print(f'  {color.DIM}post = after changes, '
              f'pre+post = before AND after{color.RST}')
        mode_raw = input(
            f'  {color.GRN}▸{color.RST} Snapshot mode '
            f'{color.DIM}[post]{color.RST} '
            f'post/pre+post: ').strip().lower()
        snapshot_mode = mode_raw if mode_raw in ('post', 'pre+post') else 'post'
    else:
        print(f'  {color.CYN}Snapshot: {snapshot_mode}{color.RST}')

    # Use the pre-snapshot base name if one was created, so
    # pre+post pairs always share the same base name.
    default_name = config.get('_snapshot_base')
    if not default_name:
        ts = datetime.now().strftime('%Y%m%d')
        level = config.get('level', 'sl1').upper().replace(',', '-')
        default_name = f'{level}-{ts}'
    name = input(
        f'  {color.GRN}▸{color.RST} Snapshot name '
        f'{color.DIM}[{default_name}]{color.RST}: ').strip()
    if not name:
        name = default_name

    if not _is_valid_profile_name(name):
        print(f'  {color.RED}Invalid name (use letters, numbers, '
              f'hyphens, underscores){color.RST}')
        return

    # Post-harden snapshot (after changes — the saved state)
    post_name = f'{name}-post'
    _log('SNAPSHOT', f"'{post_name}' (post-harden) ... ",
         end='', flush=True, color=color)
    try:
        final = _do_snapshot(device, post_name)
        if final != post_name:
            print(f"{color.GRN}OK (as '{final}'){color.RST}")
        else:
            print(f'{color.GRN}OK{color.RST}')
        session.add_change({
            'check_id': '_snapshot_post',
            'action': f"snapshot('{final}')",
            'result': 'applied',
            'timestamp': datetime.now().isoformat(),
        })
    except Exception as e:
        print(f'{color.RED}FAIL ({e}){color.RST}')


def _print_fleet_live(all_ips, all_results, failures, completed,
                      total, color=C, level='sl1'):
    """Print live fleet audit screen — devices fill in as they complete."""
    _cls()
    W = 60
    ts = datetime.now().strftime('%Y-%m-%d %H:%M')
    title = "JUSTIN — IEC 62443-4-2 Fleet Audit"
    sub = f"{total} devices  {level}  {ts}"
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
        _log('CONNECT', ip, color=C)

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
        state, i_evidence = _igather(device, check_defs)
        session.update(state_before=_make_state_snapshot(state),
                       evidence=i_evidence)

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
                report = to_json(findings, device_info,
                                 evidence=i_evidence)
                save_report(report, path)
                print(f'  Saved to {path}')
                continue
            if choice not in ('h', 'harden') or not fixable:
                continue

            # Findings multi-select (after explicit harden intent)
            fix_raw = input(
                f'  {C.GRN}▸{C.RST} Findings '
                f'{C.CYN}[a]{C.RST}ll / 1-{len(fixable)}: '
                ).strip()
            sel = _parse_selection(fix_raw or 'a', len(fixable))
            if not sel:
                continue
            to_fix = [fixable[i] for i in sorted(sel)]

            # Collect config values interactively (S/P/Q)
            skip_checks, _per_dev = _collect_harden_inputs(
                to_fix, config, color=color)
            to_fix = [f for f in to_fix
                      if f.check_id not in skip_checks]
            if not to_fix:
                continue

            # Pre-harden snapshot (interactive, before first fix)
            snap_mode = config.get('snapshot', 'off')
            if (snap_mode == 'pre+post'
                    and config.get('protocol') == 'mops'):
                ts = datetime.now().strftime('%Y%m%d')
                lvl = config.get('level', 'sl1').upper().replace(',', '-')
                snap_base = f'{lvl}-{ts}'
                config['_snapshot_base'] = snap_base
                pre_name = f'{snap_base}-pre'
                # Only create once per session
                pre_done = any(
                    c.get('check_id') == '_snapshot_pre'
                    for c in session.data.get('changes', []))
                if not pre_done:
                    _log('SNAPSHOT', f"'{pre_name}' (pre-harden) ... ",
                         end='', flush=True)
                    try:
                        pre_final = _do_snapshot(device, pre_name)
                        if pre_final != pre_name:
                            print(f"{C.GRN}OK (as '{pre_final}'){C.RST}")
                        else:
                            print(f'{C.GRN}OK{C.RST}')
                        session.add_change({
                            'check_id': '_snapshot_pre',
                            'action': f"snapshot('{pre_final}')",
                            'result': 'applied',
                            'timestamp': datetime.now().isoformat(),
                        })
                    except Exception as e:
                        print(f'{C.RED}FAIL ({e}){C.RST}')

            # Apply fixes
            print()
            for f in to_fix:
                fn = HARDEN_DISPATCH[f.check_id]
                spec = check_defs.get(f.check_id, {})
                _log(f'HARDEN {f.check_id}', '', end='', flush=True)
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
            _log('REGATHER', f'{C.DIM}Verifying ...{C.RST}')
            state, i_evidence = _igather(device, check_defs)
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
        report = to_json(findings, device_info, evidence=i_evidence)
        save_report(report, path)
        session.finish()
        _log('SESSION', f'{C.DIM}Report: {path}{C.RST}')
        _log('SESSION', f'{C.DIM}{session.path}{C.RST}')

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
            continue
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
                _log(f'HARDEN {f.check_id}', '', end='', flush=True)
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
        _log('REGATHER', f'{C.DIM}Verifying ...{C.RST}')
        rip, rdi, rfindings, _rev, rerr = worker_audit(
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
            print(f'    Level:     {config.get("level", "sl1")}')
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
            level_input = input(
                f'  {C.GRN}▸{C.RST} Level '
                f'{C.DIM}[sl1] (sl1,sl2,vendor,highest){C.RST}: '
                ).strip().lower() or 'sl1'
            config = {
                'username': username, 'password': password,
                'protocol': 'mops', 'devices': devices,
                'syslog_server': None, 'syslog_port': 514,
                'ntp_server': None, 'banner': None, 'level': level_input,
            }

        if not config['devices']:
            print(f'\n  {C.YEL}No devices in config.{C.RST}\n')
            return

        # ── Safety & Save Settings ──
        # Defaults: dirty-config guard ON, auto-save OFF, snapshot OFF
        dirty_guard = config.get('dirty_guard', True)
        auto_save = config.get('auto_save', False)
        snapshot_mode = config.get('snapshot', 'off')  # off/post/pre+post

        print(f'\n  {C.BOLD}SAFETY{C.RST}')
        print(f'    Dirty-config guard:  '
              f'{C.GRN}ON{C.RST}  '
              f'{C.DIM}(refuse to touch unsaved switches){C.RST}')
        print(f'    Auto-save after:     '
              f'{C.YEL}OFF{C.RST} '
              f'{C.DIM}(prompt before saving to NVM){C.RST}')
        print(f'    Snapshot:            '
              f'{C.DIM}OFF{C.RST} '
              f'{C.DIM}(no NVM profiles created){C.RST}')
        print()
        tweak = input(
            f'  {C.GRN}▸{C.RST} Change defaults? '
            f'{C.DIM}[n]{C.RST} '
            f'{C.CYN}y{C.RST}/{C.CYN}n{C.RST}: ').strip().lower()
        if tweak in ('y', 'yes'):
            # Dirty-config guard
            dg = input(
                f'  {C.GRN}▸{C.RST} Dirty-config guard '
                f'{C.DIM}[ON]{C.RST} '
                f'on/off: ').strip().lower()
            if dg in ('off', 'false', 'no', '0'):
                dirty_guard = False
                print(f'    {C.YEL}Dirty-config guard OFF — '
                      f'will harden unsaved switches{C.RST}')

            # Auto-save
            asv = input(
                f'  {C.GRN}▸{C.RST} Auto-save after changes '
                f'{C.DIM}[OFF]{C.RST} '
                f'on/off: ').strip().lower()
            if asv in ('on', 'true', 'yes', '1'):
                auto_save = True
                print(f'    {C.CYN}Auto-save ON — '
                      f'NVM save after each device{C.RST}')

            # Snapshot
            print(f'  {C.DIM}Snapshot modes:{C.RST}')
            print(f'    {C.DIM}off      — no snapshots (default){C.RST}')
            print(f'    {C.DIM}post     — save profile after changes{C.RST}')
            print(f'    {C.DIM}pre+post — save before AND after '
                  f'(full audit trail){C.RST}')
            snap = input(
                f'  {C.GRN}▸{C.RST} Snapshot '
                f'{C.DIM}[off]{C.RST} '
                f'off/post/pre+post: ').strip().lower()
            if snap in ('post', 'pre+post'):
                snapshot_mode = snap
                if snap == 'pre+post':
                    print(f'    {C.CYN}Snapshot pre+post — '
                          f'full before/after profiles{C.RST}')
                else:
                    print(f'    {C.CYN}Snapshot post — '
                          f'profile saved after changes{C.RST}')

        config['dirty_guard'] = dirty_guard
        config['auto_save'] = auto_save
        config['snapshot'] = snapshot_mode

        # Import driver
        from napalm import get_network_driver
        driver = get_network_driver('hios')
        check_defs = load_checks()

        # Apply level filter
        i_level = config.get('level', 'sl1').lower()
        try:
            check_defs = filter_checks_by_level(check_defs, i_level)
        except ValueError:
            print(f'  {C.YEL}Invalid level "{i_level}", '
                  f'using sl1{C.RST}')
            i_level = 'sl1'
            check_defs = filter_checks_by_level(
                load_checks(), i_level)

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
                          0, total_devs, level=i_level)

        with ThreadPoolExecutor(max_workers=min(total_devs, 8)) as pool:
            futures = {
                pool.submit(worker_audit, driver, config, ip,
                            check_defs): ip
                for ip in all_ips
            }
            for future in as_completed(futures):
                completed += 1
                ip_r, di, ffindings, fev, err = future.result()
                if err:
                    failures.append((ip_r, err))
                else:
                    all_results[ip_r] = {
                        'device': di, 'findings': ffindings,
                        'evidence': fev}
                # Redraw with updated results
                _print_fleet_live(all_ips, all_results, failures,
                                  completed, total_devs, level=i_level)

        elapsed = time.time() - start

        # ── Fleet REPL ──
        sorted_ips = sorted(all_results.keys())
        changed_ips = set()

        while True:
            # CLS → fleet report with indices
            _cls()
            ordered_fixable = print_fleet_report(
                all_results, failures, elapsed, numbered=True,
                level=i_level)

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
                continue

            if (choice not in ('h', 'harden')
                    or not ordered_fixable):
                continue

            # Two-prompt multi-select (after explicit harden)
            dev_raw = input(
                f'  {C.GRN}▸{C.RST} Devices '
                f'{C.CYN}[a]{C.RST}ll / 1-{len(sorted_ips)}: '
                ).strip()
            dev_sel = _parse_selection(
                dev_raw or 'a', len(sorted_ips))
            if not dev_sel:
                continue

            fix_raw = input(
                f'  {C.GRN}▸{C.RST} Findings '
                f'{C.CYN}[a]{C.RST}ll / 1-{len(ordered_fixable)}: '
                ).strip()
            fix_sel = _parse_selection(
                fix_raw or 'a', len(ordered_fixable))
            if not fix_sel:
                continue

            selected_ips_list = [sorted_ips[i]
                                for i in sorted(dev_sel)]
            selected_checks = [ordered_fixable[i]
                               for i in sorted(fix_sel)]

            # Collect config values interactively (S/P/Q)
            skip_checks, per_device = _collect_harden_inputs(
                selected_checks, config,
                device_ips=selected_ips_list, color=color)
            selected_checks = [c for c in selected_checks
                               if c not in skip_checks]
            if not selected_checks:
                continue

            _log('HARDEN', f'{C.BOLD}Fixing '
                 f'{len(selected_checks)} finding(s) on '
                 f'{len(selected_ips_list)} device(s){C.RST}')

            # Apply fixes per device
            fixed_ips = []
            for sip in selected_ips_list:
                # Merge per-device overrides into a device-local config
                dev_config = dict(config)
                if sip in per_device:
                    dev_config.update(per_device[sip])
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

                    _log(f'HARDEN {sip}', '', end='', flush=True)
                    for f in device_fixable:
                        fn = HARDEN_DISPATCH[f.check_id]
                        spec = check_defs.get(f.check_id, {})
                        try:
                            result = fn(device, spec, dev_config)
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
                _log('REGATHER', f'{C.DIM}Verifying '
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
                        rip, rdi, rfindings, _rev, rerr = (
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
                            _log('SAVE', f'{sip}: '
                                 f'{C.GRN}saved{C.RST}')
                            save_ok += 1
                        else:
                            _log('SAVE', f'{sip}: '
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
                        lvl = config.get(
                            'level', 'sl1'
                            ).upper().replace(',', '-')
                        default_name = f'{lvl}-{ts}'
                        name = input(
                            f'  {C.GRN}▸{C.RST} Snapshot '
                            f'name {C.DIM}[{default_name}]'
                            f'{C.RST}: ').strip()
                        if not name:
                            name = default_name
                        if _is_valid_profile_name(name):
                            # Post-harden snapshot
                            post_name = f'{name}-post'
                            with ThreadPoolExecutor(
                                    max_workers=min(
                                        len(changed_ips), 8)
                                    ) as pool:
                                futs = {
                                    pool.submit(
                                        _worker_snapshot_connect,
                                        driver, config,
                                        cip, post_name): cip
                                    for cip in changed_ips
                                }
                                for fut in as_completed(futs):
                                    sip, status, result = (
                                        fut.result())
                                    if status == 'OK':
                                        _log('SNAPSHOT',
                                             f'{sip}: '
                                             f'{C.GRN}'
                                             f'{result}'
                                             f'{C.RST}')
                                    else:
                                        _log('SNAPSHOT',
                                             f'{sip}: '
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
        _log('SESSION', f'{C.DIM}Report: {path}{C.RST}')

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
            ip, device_info, findings, ev, err = future.result()
            if err:
                failures.append((ip, err))
            else:
                all_results[ip] = {
                    'device': device_info,
                    'findings': findings,
                    'evidence': ev,
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
    parser.add_argument('--ips', metavar='TARGETS',
                        help='comma list, last-octet range, or CIDR')
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
                        help='create named NVM snapshots: NAME-pre before '
                             'changes, NAME-post after (MOPS only, '
                             'requires --save)')
    parser.add_argument('--level', default='sl1',
                        help='sl1,sl2,vendor,highest — comma-separated '
                             '(default: sl1)')

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

    # Load checks and certs
    check_defs = load_checks()
    certs = load_certs()

    # Resolve effective level: CLI arg > script.cfg > default
    level_str = args.level.lower()

    # Filter by composable level
    try:
        check_defs = filter_checks_by_level(check_defs, level_str)
    except ValueError as e:
        print(f"\n  {color.RED}ERROR: {e}{color.RST}\n")
        sys.exit(1)

    # Filter by severity
    if args.severity:
        max_sev = SEVERITY_ORDER.get(args.severity, 9)
        check_defs = {k: v for k, v in check_defs.items()
                      if SEVERITY_ORDER.get(v['severity'], 9) <= max_sev}

    # Config
    try:
        if args.d or args.ips:
            devices = [args.d] if args.d else parse_ips(args.ips)
            config = {
                'username': args.u or 'admin',
                'password': args.p or 'private',
                'protocol': args.protocol or 'mops',
                'devices': devices,
                'syslog_server': None,
                'syslog_port': 514,
                'ntp_server': None,
                'banner': None,
                'level': level_str,
            }
            # Read hardening targets from script.cfg if it exists
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
                'level': level_str,
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

    # Resolve level: CLI --level overrides script.cfg level.
    # If user didn't change --level from default but script.cfg has one, use it.
    cfg_level = config.get('level', 'sl1').lower()
    if args.level == 'sl1' and cfg_level != 'sl1':
        # script.cfg had a non-default level and user didn't override
        level_str = cfg_level
        config['level'] = level_str
        try:
            check_defs_all = load_checks()
            check_defs = filter_checks_by_level(check_defs_all, level_str)
            if args.severity:
                max_sev = SEVERITY_ORDER.get(args.severity, 9)
                check_defs = {k: v for k, v in check_defs.items()
                              if SEVERITY_ORDER.get(v['severity'], 9) <= max_sev}
        except ValueError as e:
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
            _log('HARDEN', f"{color.BOLD}Dry-run mode "
                 f"(use --commit to apply){color.RST}", color=color)
        harden_from_report(driver, config, report_data, check_defs,
                           dry_run=dry_run, save=args.save, color=color,
                           watchdog_seconds=args.watchdog,
                           snapshot_name=args.snapshot)
        elapsed = time.time() - start_time
        _log('SESSION', f"{color.DIM}Completed in "
             f"{elapsed:.1f}s{color.RST}", color=color)
        return

    # ---- Fleet mode (multiple devices) ----
    if len(config['devices']) > 1:
        all_results, failures, elapsed = fleet_audit(
            driver, config, check_defs, color)

        if args.json:
            report = fleet_to_json(all_results, failures, level_str,
                                   check_defs)
            print(json.dumps(report, indent=2))
        else:
            print_fleet_report(all_results, failures, elapsed, color,
                               level=level_str)

        # Save report if requested
        if args.output:
            report = fleet_to_json(all_results, failures, level_str,
                                   check_defs)
            if args.output.endswith('.html'):
                save_html_report(report, args.output, certs)
            else:
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

                    state, _ev = gather(device, check_defs, color)
                    snap_before = _make_state_snapshot(state)
                    gather_fn = lambda d=device: gather(d, check_defs, color)[0]
                    session = SessionLog(ip)
                    session.update(device=data['device'],
                                   state_before=snap_before,
                                   evidence=_ev)

                    applied, changes_log, state_diff = harden_device(
                        device, data['findings'], check_defs, config,
                        dry_run=dry_run, save=args.save, color=color,
                        state_before=snap_before, gather_fn=gather_fn,
                        watchdog_seconds=args.watchdog, session=session,
                        snapshot_name=args.snapshot)

                    # Post-harden snapshot per device
                    if (args.snapshot and not dry_run and applied
                            and args.save
                            and config['protocol'] == 'mops'
                            and _is_valid_profile_name(
                                args.snapshot)):
                        post_name = f'{args.snapshot}-post'
                        _log('SNAPSHOT',
                             f"'{post_name}' (post-harden)"
                             f" ... ", end='', flush=True,
                             color=color)
                        try:
                            final = _do_snapshot(
                                device, post_name)
                            print(f"{color.GRN}OK"
                                  f"{color.RST}")
                            session.add_change({
                                'check_id': '_snapshot_post',
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
                    _log('SESSION',
                         f"{color.DIM}{session.path}{color.RST}",
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
    _log('CONNECT', ip, color=color)

    ip, device, device_info, findings, state, evidence, err = audit_device(
        driver, config, ip, check_defs, color)

    if err:
        _log('CONNECT', f"{color.RED}FAIL: {err}{color.RST}",
             color=color)
        sys.exit(1)

    # Session log — written incrementally (the JUSTIN way)
    session = SessionLog(ip)
    snap_before = _make_state_snapshot(state)
    session.update(device=device_info, state_before=snap_before,
                   evidence=evidence)

    # Config status check
    saved, cfg_status = check_config_saved(device, color)
    session.update(config_status=cfg_status)

    # JSON output
    if args.json:
        report = to_json(findings, device_info, level_str, check_defs,
                         evidence=evidence)
        print(json.dumps(report, indent=2))
        if args.output:
            if args.output.endswith('.html'):
                save_html_report(report, args.output, certs)
            else:
                save_report(report, args.output)
        total = len(findings)
        passed = sum(1 for f in findings if f.passed)
        session.update(
            findings=[f.to_dict() for f in findings],
            score={'total': total, 'passed': passed,
                   'failed': total - passed})
        session.finish()
        _log('SESSION', f"{color.DIM}{session.path}{color.RST}",
             color=color)
        if device:
            device.close()
        return

    # Console report
    print_report(findings, device_info, color, level=level_str,
                 certs=certs)

    total = len(findings)
    passed = sum(1 for f in findings if f.passed)
    session.update(
        findings=[f.to_dict() for f in findings],
        score={'total': total, 'passed': passed,
               'failed': total - passed})

    # Save report if requested
    if args.output:
        report = to_json(findings, device_info, level_str, check_defs,
                         evidence=evidence)
        if args.output.endswith('.html'):
            save_html_report(report, args.output, certs)
        else:
            save_report(report, args.output)
        print(f"  Report saved to {args.output}")

    # Harden
    if args.harden:
        # Dirty-config guard — refuse to harden unsaved switch
        if not enforce_clean_config(device, ip, 'harden', color, config=config):
            session.update(refused='unsaved config')
            session.finish()
            _log('SESSION', f"{color.DIM}{session.path}{color.RST}",
                 color=color)
            if device:
                device.close()
            return

        dry_run = not args.commit
        if dry_run:
            _log('HARDEN', f"{color.BOLD}Dry-run mode "
                 f"(use --commit to apply){color.RST}", color=color)

        gather_fn = lambda: gather(device, check_defs, color)[0]
        applied, changes_log, state_diff = harden_device(
            device, findings, check_defs, config,
            dry_run=dry_run, save=args.save, color=color,
            state_before=snap_before, gather_fn=gather_fn,
            watchdog_seconds=args.watchdog, session=session,
            snapshot_name=args.snapshot)

        # Post-harden snapshot (pre-harden is inside harden_device)
        if (args.snapshot and not dry_run and applied
                and args.save):
            post_name = f'{args.snapshot}-post'
            if config['protocol'] != 'mops':
                _log('SNAPSHOT', f"{color.YEL}Requires MOPS "
                     f"protocol{color.RST}", color=color)
            elif not _is_valid_profile_name(args.snapshot):
                _log('SNAPSHOT', f"{color.RED}Invalid snapshot "
                     f"name{color.RST}", color=color)
            else:
                _log('SNAPSHOT', f"'{post_name}' (post-harden)"
                     f" ... ", end='', flush=True, color=color)
                try:
                    final = _do_snapshot(device, post_name)
                    if final != post_name:
                        print(f"{color.GRN}OK "
                              f"(as '{final}'){color.RST}")
                    else:
                        print(f"{color.GRN}OK{color.RST}")
                    session.add_change({
                        'check_id': '_snapshot_post',
                        'action': f"snapshot('{final}')",
                        'result': 'applied',
                        'timestamp': datetime.now().isoformat(),
                    })
                except Exception as e:
                    print(f"{color.RED}FAIL ({e}){color.RST}")

    elapsed = time.time() - start_time
    session.finish()
    _log('SESSION', f"{color.DIM}{session.path}{color.RST}",
         color=color)
    _log('SESSION', f"{color.DIM}Completed in "
         f"{elapsed:.1f}s{color.RST}", color=color)

    if device:
        device.close()


if __name__ == '__main__':
    main()
