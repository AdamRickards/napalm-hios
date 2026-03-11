# CHECK_LOGIC.md — Decision Logic for All 47 JUSTIN Checks

This document defines the decision logic for every JUSTIN check. Not "is X
enabled = bad" but smart reasoning — e.g., DNS enabled with no servers =
pointless attack surface.

Three purposes:
1. **Reference** for anyone reading the code
2. **Design spec** — defines WHAT each check does before reading code
3. **Harden documentation** — what the auto-fix does and WHY

For architecture, phases, safety mechanisms, and session logging, see `LOGIC.md`.

---

## Quick Reference

| # | Check ID | CR | Source | SL | Sev | Harden | Evidence Key |
|---|----------|-----|--------|-----|------|--------|--------------|
| 1 | sec-hidiscovery | 7.7 | iec | 1 | crit | auto | get_hidiscovery |
| 2 | sec-insecure-protocols | 4.1 | iec | 1 | warn | auto | get_services |
| 3 | sec-industrial-protocols | 7.7 | vendor | 1 | warn | auto | get_services |
| 4 | ns-gvrp-mvrp | 7.7 | iec | 1 | warn | auto | get_services |
| 5 | ns-gmrp-mmrp | 7.7 | iec | 1 | warn | auto | get_services |
| 6 | sec-dns-client | 7.7 | vendor | 1 | info | deferred | get_dns |
| 7 | sec-poe | 7.7 | vendor | 1 | info | auto | get_poe |
| 8 | sec-unused-ports | 7.7 | vendor | 1 | warn | deferred | get_interfaces |
| 9 | sec-login-policy | 1.11 | iec | 1 | warn | auto | get_login_policy |
| 10 | sec-password-policy | 1.7 | iec | 2 | warn | auto | get_login_policy |
| 11 | sys-default-passwords | 1.5 | iec | 1 | crit | auto | — |
| 12 | sec-login-banner | 1.12 | vendor | 1 | warn | auto | get_banner |
| 13 | sec-remote-auth | 1.1 | iec | 2 | warn | none | get_remote_auth |
| 14 | sec-ip-restrict | 2.1 | vendor | 1,2 | warn | auto | get_ip_restrict |
| 15 | sec-session-timeouts | 2.6 | vendor | 1 | warn | auto | get_session_config |
| 16 | sec-concurrent-sessions | 2.7 | iec | 2 | warn | auto | get_session_config |
| 17 | sec-snmpv1-traps | 4.1 | iec | 1 | warn | auto | get_snmp_config |
| 18 | sec-snmpv1v2-write | 2.1 | iec | 1 | warn | auto | get_snmp_config |
| 19 | sec-snmpv3-auth | 4.3 | vendor | 1 | warn | auto | get_snmp_config |
| 20 | sec-snmpv3-encrypt | 4.3 | vendor | 1 | warn | auto | get_snmp_config |
| 21 | sec-snmpv3-traps | 6.2 | vendor | 1 | warn | auto | get_snmp_config |
| 22 | sec-time-sync | 2.11 | iec | 1 | warn | auto | get_ntp |
| 23 | sec-logging | 2.8 | iec | 1,2 | warn | auto | get_syslog |
| 24 | sec-devsec-monitors | 6.2 | iec | 1,2 | warn | auto | get_services |
| 25 | sec-signal-contact | 6.2 | vendor | 1 | warn | auto | get_signal_contact |
| 26 | sec-https-cert | 1.2 | vendor | 1,2 | info | none | get_devsec_status |
| 27 | sec-dev-mode | 7.7 | vendor | 1 | warn | none | get_devsec_status |
| 28 | sec-secure-boot | 3.14 | vendor | 1 | info | none | get_devsec_status |
| 29 | sec-mgmt-vlan | 5.1 | iec | 1 | warn | advisory | get_management |
| 30 | ns-dos-protection | 7.1 | vendor | 1 | warn | advisory | get_storm_control |
| 31 | ns-lldp | 7.7 | vendor | 1 | info | advisory | get_lldp_neighbors |
| 32 | ns-port-security | 7.1 | vendor | 1 | warn | deferred | get_port_security |
| 33 | ns-dhcp-snooping | 3.1 | vendor | 1 | warn | deferred | get_dhcp_snooping |
| 34 | ns-dai | 3.1 | vendor | 1 | warn | deferred | get_dai |
| 35 | ns-ipsg | 3.1 | vendor | 1 | warn | deferred | get_ip_source_guard |
| 36 | sec-unsigned-sw | 3.4 | iec | 1 | warn | auto | get_services |
| 37 | sec-aca-auto-update | 3.4 | iec | 1 | warn | auto | get_services |
| 38 | sec-aca-config-write | 3.4 | iec | 1 | warn | auto | get_services |
| 39 | sec-aca-config-load | 3.4 | iec | 1 | warn | auto | get_services |
| 40 | cert-hw-authenticator | 1.5 | cert | 2 | info | cert | — |
| 41 | cert-hw-pubkey | 1.9 | cert | 2 | info | cert | — |
| 42 | cert-hw-symkey | 1.14 | cert | 2 | info | cert | — |
| 43 | cert-memory-purge | 4.2 | cert | 2 | info | cert | — |
| 44 | sec-user-review | 1.3/1.4 | iec | 2 | info | none | get_users |
| 45 | sec-user-roles | 2.1 RE2 | iec | 2 | warn | none | get_users |
| 46 | sec-crypto-ciphers | 4.3 | iec | 2 | warn | auto | get_services |
| 47 | sec-console-port | EDR 2.13 | iec | 2 | warn | auto | get_session_config |

**Harden types**: auto (28) = HARDEN_DISPATCH registered, advisory (3) = detection only,
deferred (3) = needs driver/infrastructure work, none (6) = detection only, cert (4) = TÜV proof.

**Stubs**: none (all 47 checks wired).

## Evidence Trail

Every check links to its evidence via the `evidence_key` field in the finding.
Evidence is captured during `gather()` as timestamped snapshots of raw getter data:

```json
{
  "get_services": {
    "gathered_at": "2026-03-11T10:30:00",
    "data": { ... raw getter result ... }
  }
}
```

Multiple checks sharing the same getter (e.g., 11 checks use `get_services()`)
link to one evidence block. HTML reports render these as collapsible blocks with
click-to-expand links from every check row. Checks with no getter (cert-inherent,
sys-default-passwords) have no evidence_key — their evidence is the cert reference
or the connection credentials used.

Evidence provides:
- **Audit proof** — exactly what data each check was evaluated against
- **Timestamp** — when the data was collected (ISO 8601)
- **Reproducibility** — re-run the check function against the evidence to verify
- **Error capture** — if a getter fails, `{gathered_at, error}` is recorded instead

## Assessment Boundaries

JUSTIN is a stateless audit tool — it connects, gathers current state, evaluates,
and disconnects. This means some IEC 62443-4-2 requirements can be **fully proven**,
some can only be **partially assessed**, and some require **manual follow-up**.

Every check falls into one of three assessment categories:

### Fully Assessed (evidence = proof)
The getter data alone proves pass or fail. No human judgement needed.
Example: `sec-hidiscovery` — HiDiscovery is either enabled or disabled.
The evidence is the proof.

### Partially Assessed (evidence = data, verdict = advisory)
JUSTIN can gather the relevant data but cannot fully determine compliance
without context that a stateless tool cannot have. The finding presents the
data and explicitly states what the operator must verify.

Examples:
- **Account lifecycle** (CR 1.3/1.4): JUSTIN can list all local accounts
  via `get_users()`, but cannot know which are dormant — it has no login
  history. Finding: "3 local accounts found — review for dormant accounts."
- **PKI revocation** (CR 1.8): JUSTIN can detect a non-default HTTPS cert
  but cannot verify CRL/OCSP reachability. Finding: "Certificate present —
  verify revocation checking is configured at site level."
- **Storm control thresholds** (ns-dos-protection): JUSTIN detects whether
  storm control is configured, but thresholds are site-specific.

### Cannot Assess (noted as out of scope)
The requirement exists in the standard but the device/protocol/tool cannot
evaluate it. JUSTIN documents WHY it can't assess and what compensating
control the operator should verify.

Examples:
- **Password history/expiry** (CR 1.7 SL2): HiOS MIB doesn't expose
  password history or expiry settings. Noted as firmware limitation,
  TÜV accepted for SL-C 2.
- **CoPP** (CR 7.1): HiOS implements control plane policing in firmware —
  it's not configurable and not exposed via any management interface.
  Covered by TÜV certification inherently.

This three-tier model ensures the audit report is honest: "here's what we
proved, here's what we found but you need to verify, here's what we can't
check and why."

---

## 1. Service & Protocol Control

### sec-hidiscovery
CR 7.7 "Least functionality" | iec | `get_hidiscovery()` → `set_hidiscovery()` | severity: critical

```
    hd = get_hidiscovery()
    if hd is None                   → UNABLE
    if hd.enabled                   → FAIL "HiDiscovery enabled ({mode})"
    else                            → PASS "HiDiscovery disabled"
```

    Harden: set_hidiscovery('off')
    Config: none

    Why critical: HiDiscovery allows unauthenticated IP reconfiguration
    from any device on the L2 network. Must be disabled in production.


### sec-insecure-protocols
CR 4.1 "Communication confidentiality" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    issues = []
    if svc.http.enabled             → issue "HTTP enabled"
    if svc.telnet.enabled           → issue "Telnet enabled"
    if issues                       → FAIL "{issues}"
    else                            → PASS "HTTP and Telnet disabled"
```

    Harden: set_services(http=False, telnet=False)
    Config: none

    HTTPS and SSH remain enabled — only cleartext protocols are disabled.


### sec-industrial-protocols
CR 7.7 "Least functionality" | vendor §2.11.16 | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    ind = svc.industrial
    if ind is None                  → UNABLE
    enabled = []
    for proto in (profinet, modbus, ethernet_ip, iec61850):
        if ind.{proto}              → enabled.append(label)
    if enabled                      → FAIL "Industrial protocols enabled: {list}"
    else                            → PASS "No industrial protocols enabled"
```

    Harden: set_services(**{proto: False for proto in enabled_ones})
    Config: none

    Smart: only disables protocols that are currently enabled. If a site
    uses PROFINET, operator skips this finding — other protocols still fixed.


### ns-gvrp-mvrp
CR 7.7 "Least functionality" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    issues = []
    if 'gvrp' in svc and svc.gvrp  → issue "GVRP enabled"
    elif 'gvrp' not in svc         → UNABLE
    if 'mvrp' in svc and svc.mvrp  → issue "MVRP enabled"
    elif 'mvrp' not in svc         → UNABLE
    if issues                       → FAIL "{issues}"
    else                            → PASS "GVRP/MVRP disabled"
```

    Harden: set_services(mvrp=False)
    Config: none

    Note: harden targets MVRP only (supersedes GVRP on modern HiOS).
    Dynamic VLAN registration allows rogue devices to create VLANs.


### ns-gmrp-mmrp
CR 7.7 "Least functionality" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    issues = []
    if 'gmrp' in svc and svc.gmrp  → issue "GMRP enabled"
    elif 'gmrp' not in svc         → UNABLE
    if 'mmrp' in svc and svc.mmrp  → issue "MMRP enabled"
    elif 'mmrp' not in svc         → UNABLE
    if issues                       → FAIL "{issues}"
    else                            → PASS "GMRP/MMRP disabled"
```

    Harden: set_services(mmrp=False)
    Config: none

    Note: harden targets MMRP only (supersedes GMRP on modern HiOS).
    Dynamic multicast registration is unnecessary in static industrial networks.


### sec-dns-client
CR 7.7 "Least functionality" | vendor §2.11.18 | `get_dns()` → `set_dns()` | severity: info

```
    dns = get_dns()
    if not dns.enabled              → PASS "DNS client disabled"
    if dns.enabled and dns.servers  → PASS "DNS active (servers configured)"
    if dns.enabled and no servers   → FAIL "DNS enabled with no servers"
```

    Harden: set_dns(enabled=False) — only when no servers configured
    Config: none

    Smart: doesn't blindly flag "DNS enabled." Enabled WITH servers means
    the operator is using DNS intentionally — leave it. Enabled with NO
    servers = pointless attack surface (DNS queries go nowhere, port open
    for no reason).


### sec-poe
CR 7.7 "Least functionality" | vendor §2.11.17 | `get_poe()` + `get_interfaces()` → `set_poe()` | severity: info

```
    poe = get_poe()
    ifaces = get_interfaces()
    if not poe['enabled']           → PASS "PoE globally disabled"
    if not poe['ports']             → PASS "PoE enabled but no PoE ports"
    for port, cfg in poe['ports']:
        if cfg['enabled'] and not ifaces[port]['is_up']
                                    → FAIL "PoE on linkless port {port}"
    if no failures                  → PASS "PoE active on linked ports only"
```

    Harden: set_poe(interface=port, enabled=False) — only on linkless ports
    Config: none

    Smart: flags ports with PoE enabled but NO link — wasted power +
    physical attack surface (plug in a rogue device, it gets powered).
    Advisory: PoE-powered devices may be temporarily off during audit.


### sec-unused-ports
CR 7.7 "Least functionality" | vendor §3.2 | `get_interfaces()` + `get_lldp_neighbors()` + `get_mrp()` | severity: warning

```
    ifaces = get_interfaces()
    lldp = get_lldp_neighbors()
    mrp = get_mrp()
    ring_ports = set of all MRP ring ports (primary + secondary per instance)
    for port, cfg in ifaces:
        if cfg.admin_state == 'disable' → skip (already disabled)
        if cfg.is_up                → skip (link active)
        if port in lldp             → skip (has LLDP neighbor)
        if port in ring_ports       → skip (ring infrastructure)
        → FAIL "unused port {port} (admin-enabled, no link, no LLDP, not ring)"
    if no failures                  → PASS "No unused ports detected"
```

    Harden: deferred (site-specific port plan required)
    Config: none

    Smart: combines three signals (link state, LLDP neighbors, MRP ring
    membership) to avoid false positives. Never flags ring ports, uplinks
    (LLDP-detected), or ports with active links. Only targets genuinely
    unused ports — admin-enabled with no link, no LLDP neighbor, and not
    a ring port. Harden is deferred because disabling ports requires a
    site-specific port plan (operator must decide which ports to keep).


### sec-console-port — SL2
EDR 2.13 "Use of physical diagnostic and test interfaces" | iec | `get_session_config()` + `get_facts()` → `set_session_config()` | severity: warning

```
    model = get_facts().model
    hw_profile = _resolve_hw_profile(model)  # model prefix → physical port type dict
    sc = get_session_config()
    if sc is None                   → UNABLE
    issues = []
    # Serial port timeout
    if sc.serial.timeout == 0       → issue "serial console has no idle timeout"
    # ENVM (external non-volatile memory / USB storage)
    if sc.envm_enabled              → issue "ENVM (USB storage) enabled"
    if issues                       → FAIL "{issues}"
    else                            → PASS "Physical diagnostic interfaces restricted"
```

    Harden: set_session_config(serial_timeout=5, envm_enabled=False)
    Config: none

    Uses get_session_config() (serial timeout + ENVM state) combined with
    get_facts().model → _resolve_hw_profile() for hardware context. The
    hardware profile dict maps model prefixes to physical port types
    (e.g., BRS50 has USB-C serial, GRS1042 has RJ45 serial + USB-A).

    Two checks: (1) serial timeout must be > 0 (idle sessions auto-close),
    (2) ENVM must be disabled (prevents USB storage access). SL2 mandates
    strict control over physical diagnostic interfaces.

---

## 2. Authentication & Access Control

### sec-login-policy
CR 1.11 "Unsuccessful login attempts" | iec | `get_login_policy()` → `set_login_policy()` | severity: warning

```
    lp = get_login_policy()
    if lp is None                   → UNABLE
    issues = []
    attempts = lp.max_login_attempts (default 0)
    lockout = lp.lockout_duration (default 0)
    min_len = lp.min_password_length (default 1)
    if attempts == 0                → issue "no login lockout"
    if lockout == 0 and attempts > 0 → issue "lockout duration is 0"
    if min_len < 8                  → issue "min password length {min_len}"
    if issues                       → FAIL "{issues}"
    else                            → PASS "Login policy configured
                                            (max {attempts}, lockout {lockout}s,
                                             min pw len {min_len})"
```

    Harden: set_login_policy(max_login_attempts=5, lockout_duration=60,
                             min_password_length=8)
    Config: none

    Note: lockout_duration=0 with max_login_attempts>0 = lockout fires but
    releases immediately (pointless). Both must be nonzero together.


### sec-password-policy — SL2
CR 1.7 "Password-based auth strength" | iec | `get_login_policy()` → `set_login_policy()` | severity: warning

```
    lp = get_login_policy()
    if lp is None                   → UNABLE
    fields = {min_uppercase, min_lowercase, min_numeric, min_special}
    weak = [field for field in fields if lp.{field} < 1]
    if weak                         → FAIL "Password complexity missing: {weak}"
    else                            → PASS "Password complexity enforced
                                            (upper>={n}, lower>={n},
                                             digit>={n}, special>={n})"
```

    Harden: set_login_policy(min_uppercase=1, min_lowercase=1,
                             min_numeric=1, min_special=1)
    Config: none

    SL2 gap: password history/reuse prevention and expiry not in
    HM2-USERMGMT-MIB — HiOS firmware limitation, TÜV accepted for SL-C 2.
    This check covers what HiOS CAN enforce.


### sys-default-passwords
CR 1.5 "Authenticator management" | iec | — | severity: critical

```
    username = config.username (from script.cfg or CLI)
    password = config.password
    if username == 'admin' and password == 'private'
                                    → FAIL "Using default credentials (admin/private)"
    if username == 'admin' (non-default password)
                                    → PASS "Admin password changed from default"
    else                            → UNABLE "Non-admin user — default password
                                              probe not implemented"
```

    Harden: auto — set_user(password=<new>) on all default-password users
    Config: harden_password (prompted via getpass)
    Evidence: none (detection is config-based, not a live probe)

    Note: this is a credential-inference check, not a getter-based check.
    If JUSTIN connects with admin/private, the defaults haven't been changed.
    Future: probe admin/private independently of the session credentials.


### sec-login-banner
CR 1.12 "System use notification" | vendor §2.11.3 | `get_banner()` → `set_banner()` | severity: warning

```
    banner = get_banner()
    if banner is None               → UNABLE
    pre = banner.pre_login
    if pre.enabled and pre.text.strip()
                                    → PASS "Pre-login banner configured ({len} chars)"
    issues = []
    if not pre.enabled              → issue "pre-login banner disabled"
    if not pre.text.strip()         → issue "no banner text configured"
                                    → FAIL "{issues}"
```

    Harden: set_banner(pre_login_enabled=True,
                       pre_login_text=<login_banner or default>)
    Config: login_banner (default: "This system is for authorized use only.")

    Why: authorised-use warning banner deters unauthorised access and
    provides legal standing for prosecution in many jurisdictions.


### sec-remote-auth — SL2
CR 1.1 "Human user identification and authentication" | iec | `get_remote_auth()` → check only | severity: warning

```
    auth = get_remote_auth()
    active = [name for name in (radius, tacacs, ldap)
              if auth[name].enabled]
    if active                       → PASS "Remote authentication active: {active}"
    else                            → FAIL "No remote authentication configured"
```

    Harden: none (detection only — requires server infrastructure)
    Config: none

    Lightweight detection: checks if any of RADIUS, TACACS+, or LDAP
    has active servers (RADIUS/TACACS+) or global enable (LDAP).
    On hardware that doesn't support a protocol (e.g. TACACS+ < 10.3,
    LDAP on L2S), that protocol gracefully returns false.

    SL2 requires centralized authentication for accountability and
    lifecycle management. Full server detail (reachability, auth chain
    wiring) deferred to future get_radius()/get_ldap() getters.


### sec-user-review — SL2 — Partial Assessment
CR 1.3 "Account management" / CR 1.4 "Identifier management" | iec | `get_users()` → — | severity: info

```
    users = get_users()
    if users is None                → UNABLE
    account_list = [u.name for u in users]
    n = len(account_list)
    → PASS (always) "Manual review required: {n} local accounts found.
                      Ensure dormant accounts are disabled."
      detail: account names listed for operator review
```

    Harden: none (detection only — operator must audit account lifecycle)
    Config: none
    Assessment: PARTIAL — stateless tool, no login history

    Why partial: IEC 62443-4-2 CR 1.3/1.4 requires management of the
    account lifecycle, including disabling dormant accounts. JUSTIN has
    no persistence — it can't track "last login was 6 months ago." What
    it CAN do: list every local account so the operator can review.

    Always passes (advisory). The evidence IS the value — the account
    list in the audit report is the operator's input for manual review.


### sec-user-roles — SL2
CR 2.1 RE 2 "Role-based access control" | iec | `get_users()` + `get_remote_auth()` → — | severity: warning

```
    remote = get_remote_auth()
    if remote is not None:
        if remote has active servers wired to login
                                    → PASS "RBAC via external AAA (RADIUS/TACACS+)"
                                      detail: "Break-glass local admin accounts acceptable"
    users = get_users()
    if users is None                → UNABLE
    roles = set(u.role for u in users)
    if roles has non-admin roles (operator, auditor, etc.)
                                    → PASS "Local RBAC utilised ({roles})"
    if all users are admin          → FAIL "All local accounts are admin — no RBAC"
```

    Harden: none (detection only — requires organisational policy)
    Config: none

    Smart: if sec-remote-auth passes (RADIUS/LDAP active), RBAC is
    handled by the external AAA server — auto-PASS. Break-glass local
    admin accounts are expected and acceptable alongside external auth.

    Only fails if: no external auth AND all local accounts are admin.
    This matches real deployments: RADIUS for daily ops, 2 local admins
    for emergency break-glass access.


### sec-ip-restrict
CR 2.1 "Authorization enforcement" | vendor §2.11.7 | `get_ip_restrict()` → `set_ip_restrict()` | severity: warning
Also covers: CR 1.13 SL2 (access control for non-local access)

```
    rma = get_ip_restrict()
    if rma is None                  → UNABLE
    if rma.enabled and len(rma.rules) > 0
                                    → PASS "IP restriction enabled with {n} rule(s)"
    issues = []
    if not rma.enabled              → issue "IP restriction disabled"
    if not rma.rules                → issue "no rules configured"
                                    → FAIL "{issues}"
```

    Harden: add_ip_restrict_rule(1, ip=<net>, prefix_length=<len>)
            + set_ip_restrict(enabled=True)
    Config: mgmt_subnet (e.g. "192.168.60.0/24")

    Config-dependent: if mgmt_subnet not set, harden returns SKIP.
    Interactive mode prompts for the management subnet.

---

## 3. Session Management

### sec-session-timeouts
CR 2.6 "Remote session termination" | vendor §2.11.5 | `get_session_config()` → `set_session_config()` | severity: warning

```
    sc = get_session_config()
    if sc is None                   → UNABLE
    zero_timeouts = []
    for proto in (ssh, telnet, web, serial):
        if sc.{proto}.timeout == 0  → zero_timeouts.append(proto)
    if not zero_timeouts            → PASS "All management session timeouts configured"
    else                            → FAIL "Session timeout disabled for: {protos}"
```

    Harden: set_session_config(ssh_timeout=5, ssh_outbound_timeout=5,
                               telnet_timeout=5, web_timeout=5, serial_timeout=5)
    Config: none (default 5 minutes)

    Note: timeout=0 means infinite session — abandoned sessions stay open
    indefinitely, allowing walk-up access to an authenticated terminal.


### sec-concurrent-sessions — SL2
CR 2.7 "Concurrent session control" | iec | `get_session_config()` → `set_session_config()` | severity: warning

```
    sc = get_session_config()
    if sc is None                   → UNABLE
    unlimited = []
    for proto in (ssh, ssh_outbound, telnet, netconf):
        ms = sc.{proto}.max_sessions
        if ms is not None and ms > 5
                                    → unlimited.append("{proto}={ms}")
    if not unlimited                → PASS "Concurrent session limits configured"
    else                            → FAIL "High session limits: {unlimited}"
```

    Harden: set_session_config(ssh_max_sessions=5, telnet_max_sessions=5)
    Config: none (default max 5)

    Threshold is >5, not >0 — allows reasonable concurrent admin access.
    SL2 CR 2.7 requires the ABILITY to limit sessions, not a specific number.

---

## 4. SNMP Hardening

### sec-snmpv1-traps
CR 4.1 "Communication confidentiality" | iec | `get_snmp_config()` → `set_snmp_config()` | severity: warning

```
    sc = get_snmp_config()
    if sc is None                   → UNABLE
    if sc.versions.v1               → FAIL "SNMPv1 enabled"
    else                            → PASS "SNMPv1 disabled"
```

    Harden: set_snmp_config(v1=False)
    Config: none

    SNMPv1 sends community strings in cleartext — trivially sniffable.


### sec-snmpv1v2-write
CR 2.1 "Authorization enforcement" | iec | `get_snmp_config()` → `set_snmp_config()` | severity: warning

```
    sc = get_snmp_config()
    if sc is None                   → UNABLE
    rw = [c for c in communities if c.access == 'rw']
    v1 = sc.versions.v1
    v2 = sc.versions.v2
    if rw and (v1 or v2)            → FAIL "SNMPv1/v2 write communities present ({names})"
    if rw but v1+v2 disabled        → PASS "Write communities exist but v1/v2 disabled"
    else                            → PASS "No SNMPv1/v2 write communities"
```

    Harden: set_snmp_config(v1=False, v2=False)
    Config: none

    Smart: doesn't just check for rw communities — checks whether v1/v2
    are enabled to actually USE them. Communities without v1/v2 = harmless.
    Fix disables v1+v2 entirely (stronger than removing communities).


### sec-snmpv3-auth
CR 4.3 "Use of cryptography" | vendor §2.11.12 | `get_snmp_config()` → — | severity: warning

```
    snmp = get_snmp_config()
    if snmp is None                 → UNABLE
    users = snmp.v3_users
    if not users                    → "No SNMPv3 users found" (unable to assess)
    weak = [u.name for u in users if u.auth_type in ('', 'md5')]
    if not weak                     → PASS "All SNMPv3 users use SHA authentication"
    else                            → FAIL "Weak/no auth: {weak}"
```

    Harden: auto — set_user(snmp_auth_type='sha') on weak/no-auth users
    Config: snmp_password (shared with sec-snmpv3-encrypt, prompted via getpass)

    MD5 is deprecated; SHA minimum for SNMPv3 authentication.


### sec-snmpv3-encrypt
CR 4.3 "Use of cryptography" | vendor §2.11.12 | `get_snmp_config()` → — | severity: warning

```
    snmp = get_snmp_config()
    if snmp is None                 → UNABLE
    users = snmp.v3_users
    if not users                    → "No SNMPv3 users found" (unable to assess)
    weak = [u.name for u in users if u.enc_type in ('none', 'des')]
    if not weak                     → PASS "All SNMPv3 users use AES encryption"
    else                            → FAIL "Weak/no encryption: {weak}"
```

    Harden: auto — set_user(snmp_enc_type='aes128') on weak/no-enc users
    Config: snmp_password (shared with sec-snmpv3-auth, prompted via getpass)

    DES is deprecated; AES minimum for SNMPv3 privacy.


### sec-snmpv3-traps
CR 6.2 "Continuous monitoring" | vendor §2.11.14 | `get_snmp_config()` → — | severity: warning

```
    snmp = get_snmp_config()
    if snmp is None                 → UNABLE
    issues = []
    if not snmp.trap_service        → issue "trap service disabled"
    v3_authpriv = [d for d in trap_destinations
                   if d.security_model == 'v3'
                   and d.security_level == 'authpriv']
    if not v3_authpriv              → issue "no SNMPv3 authPriv trap destination"
    if not issues                   → PASS "Trap service enabled with {n}
                                            v3 authPriv destination(s)"
    else                            → FAIL "{issues}"
```

    Harden: auto — add_snmp_trap_dest(name, ip, v3/admin/authpriv)
                    + set_snmp_config(trap_service=True) if disabled
    Config: trap_dest_ip (prompted interactively)

    Checks two things: (1) trap service is running, (2) at least one
    trap destination uses v3 with authPriv (encrypted + authenticated).
    v1/v2c traps leak data in cleartext. Empty security_model (from
    legacy firmware entries) also treated as non-v3 = finding.


### sec-crypto-ciphers — SL2
CR 4.3 "Use of cryptography" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    # Empty cipher lists = SSH backend or older firmware
    if all lists empty              → "Cipher data unavailable (SSH backend)"
    issues = []
    # HTTPS / TLS — BITS list fields in svc.https
    weak_tv = {tlsv1.0, tlsv1.1} ∩ tls_versions
    if weak_tv                      → issue "TLS {versions} enabled"
    weak_tc = {rc4, rsa-aes-cbc} ∩ tls_cipher_suites
    if weak_tc                      → issue "weak TLS ciphers: {names}"
    # SSH — BITS list fields in svc.ssh
    weak_kex = {dh-group1-sha1} ∩ kex_algorithms
    if weak_kex                     → issue "weak SSH KEX: {names}"
    weak_hk = {ssh-dss, ssh-rsa} ∩ host_key_algorithms
    if weak_hk                      → issue "weak SSH host key: {names}"
    if issues                       → FAIL "{issues}"
    else                            → PASS "Strong cryptographic configuration"
```

    Harden: auto — set_services(tls_versions=[strong], tls_cipher_suites=[strong],
            ssh_kex=[strong], ssh_host_key=[strong])
    Config: none

    Same getter as sec-insecure-protocols — progressive depth on the
    same evidence. SL1 checks the top-level enabled flags (HTTP off,
    Telnet off). SL2 checks the cipher detail underneath (TLS 1.2+,
    no RC4, no DSA/SHA1-RSA). One getter, one evidence block.

    Cipher fields use BITS encoding (MSB-first bitmask). Six BITS fields:
    hm2WebHttpsServerTlsVersions (.17), hm2WebHttpsServerTlsCipherSuites (.18),
    hm2SshHmacAlgorithms (.19), hm2SshKexAlgorithms (.20),
    hm2SshEncryptionAlgorithms (.21), hm2SshHostKeyAlgorithms (.22).
    MOPS/SNMP only — SSH backend returns empty lists (no CLI equivalent).
    hm2SshHostKeyAlgorithms may be missing on older firmware (silently empty).

---

## 5. Monitoring & Events

### sec-time-sync
CR 2.11 "Timestamps" | iec | `get_ntp()` → `set_ntp()` | severity: warning

```
    ntp = get_ntp()
    if ntp is None                  → UNABLE
    if not ntp.client.enabled       → FAIL "SNTP client disabled"
    active = [s for s in servers if s.address != '0.0.0.0']
    if not active                   → FAIL "SNTP client enabled but no server configured"
    else                            → PASS "NTP configured ({addrs})"
```

    Harden: set_ntp(enabled=True, servers=[{address: <ntp_server>}])
    Config: ntp_server (comma-separated for multiple servers)

    Config-dependent: if ntp_server not set, harden returns SKIP.
    Smart: '0.0.0.0' treated as unconfigured — not a real NTP server.


### sec-logging
CR 2.8 "Auditable events" | iec | `get_syslog()` → `set_syslog()` | severity: warning
Also covers: CR 6.1 SL2 (audit log accessibility), CR 2.9 SL2 (audit storage)

```
    sl = get_syslog()
    if sl is None                   → UNABLE
    if not sl.enabled               → FAIL "Syslog disabled"
    active = [s for s in servers if s.ip != '0.0.0.0']
    if not active                   → FAIL "Syslog enabled but no destination configured"
    else                            → PASS "Syslog configured ({dests})"
```

    Harden: set_syslog(enabled=True,
                       servers=[{index, ip, port, severity, transport}])
    Config: syslog_server, syslog_port (default 514)

    Config-dependent: if syslog_server not set, harden returns SKIP.
    Smart: '0.0.0.0' treated as unconfigured.


### sec-devsec-monitors
CR 6.2 "Continuous monitoring" | iec | `get_services()` → `set_services()` | severity: warning
Also covers: CR 3.4 SL2 (software integrity monitoring)

```
    svc = get_services()
    if svc is None                  → UNABLE
    if 'devsec_monitors' not in svc → UNABLE "Driver extension needed"
    if not svc.devsec_monitors      → FAIL "Device security monitors not all enabled"
    else                            → PASS "All device security monitors enabled"
```

    Harden: set_services(devsec_monitors=True)
    Config: none

    HiOS device security status monitors: password change, min password
    length, HTTP enabled, Telnet enabled, SNMP unsecure. When all are
    enabled, the device security LED/trap reflects actual security state.


### sec-signal-contact
CR 6.2 "Continuous monitoring" | vendor §2.3 | `get_signal_contact()` → `set_signal_contact()` | severity: warning

```
    sc = get_signal_contact()
    if sc is None                   → UNABLE
    c1 = sc[1] (contact 1, primary relay)
    mode = c1.mode (default 'manual')
    good_modes = (deviceState, deviceSecurity, deviceStateAndSecurity)
    if mode in good_modes           → PASS "Signal contact 1 mode: {mode}"
    else                            → FAIL "Signal contact 1 mode: {mode}
                                            (should monitor device/security status)"
```

    Harden: set_signal_contact(contact_id=1, mode='deviceStateAndSecurity')
    Config: none

    Signal contact 1 = primary dry-contact relay. In 'manual' mode it does
    nothing useful. In deviceStateAndSecurity mode, the relay opens on ANY
    device or security fault — wired to PLC/SCADA alarm input.


### sec-https-cert
CR 1.2 "Software/device authentication" | vendor §2.11.9 | `get_devsec_status()` → — | severity: info
Also covers: CR 1.2 SL2 (uniquely identify device to other components)

```
    ds = get_devsec_status()
    if ds is None                   → UNABLE
    cert_warn = any(e.cause == 'https-certificate-warning' in ds.status.events)
    if not cert_warn:
        if not ds.monitoring.https_certificate_warning
                                    → "HTTPS cert monitor disabled — enable to assess"
        else                        → PASS "HTTPS certificate OK (no DevSec warning)"
    else                            → FAIL "Factory-default or self-signed
                                            HTTPS certificate detected"
```

    Harden: none (detection only)
    Config: none
    Fix: CLI `https certificate generate` or install CA-signed cert

    Uses DevSec trap cause #23. If the https_certificate_warning monitor
    is disabled, the check cannot assess — reports this as a note rather
    than pass/fail.


### sec-dev-mode
CR 7.7 "Least functionality" | vendor | `get_devsec_status()` → — | severity: warning

```
    ds = get_devsec_status()
    if ds is None                   → UNABLE
    dev_active = any(e.cause == 'dev-mode-enabled' in ds.status.events)
    if not dev_active:
        if not ds.monitoring.dev_mode_enabled
                                    → "Dev-mode monitor disabled — enable to assess"
        else                        → PASS "Development mode disabled"
    else                            → FAIL "Development/debug mode is enabled"
```

    Harden: none (firmware-level setting)
    Config: none

    DevSec trap cause #32. Development mode should never be active in
    production — indicates a debug/test firmware build.


### sec-secure-boot
CR 3.14 "Integrity of boot process" | vendor | `get_devsec_status()` → — | severity: info

```
    ds = get_devsec_status()
    if ds is None                   → UNABLE
    boot_warn = any(e.cause == 'secure-boot-disabled' in ds.status.events)
    if not boot_warn:
        if not ds.monitoring.secure_boot_disabled
                                    → "Secure-boot monitor disabled — enable to assess"
        else                        → PASS "Secure boot enabled"
    else                            → FAIL "Secure boot is disabled"
```

    Harden: none (hardware-dependent — may require firmware reinstall)
    Config: none

    DevSec trap cause #31. Secure boot verifies firmware signature at
    boot — prevents tampered firmware from executing. Info severity because
    it's hardware-dependent and not configurable.

---

## 6. Network Segmentation & Security

### sec-mgmt-vlan
CR 5.1 "Network segmentation" | iec | `get_management()` → — | severity: warning

```
    mgmt = get_management()
    if mgmt is None                 → UNABLE
    if mgmt.vlan_id == 1            → FAIL "Management on VLAN 1 (default)"
    else                            → PASS "Management on VLAN {vlan_id}"
```

    Harden: advisory only — requires VLAN migration (VIKTOR domain)
    Config: none

    VLAN 1 is the default untagged VLAN. Management traffic on VLAN 1
    is reachable from every port unless explicitly restricted.


### ns-dos-protection
CR 7.1 "Denial of service protection" | vendor §3.6.1 | `get_storm_control()` → — | severity: warning

```
    sc = get_storm_control()
    if sc is None                   → UNABLE
    interfaces = sc.interfaces
    if not interfaces               → UNABLE
    protected = count of ports with any storm control
                (broadcast/multicast/unicast) enabled
    total = count of all ports
    if protected == 0               → FAIL "No storm control configured on any port"
    else                            → PASS "Storm control active on {protected}/{total} ports"
```

    Harden: advisory only — site-specific thresholds
    Config: none

    Storm control thresholds are site-dependent (network speed, expected
    traffic patterns). JUSTIN detects absence but can't guess thresholds.


### ns-lldp
CR 7.7 "Least functionality" | vendor §3.10 | `get_lldp_neighbors()` → — | severity: info

```
    neighbors = get_lldp_neighbors()
    if neighbors is None            → UNABLE
    n_neighbors = sum of all neighbor entries
    n_ports = count of ports with neighbors
    → PASS (always) "LLDP active: {n} neighbor(s) on {p} port(s)"
       or "No LLDP neighbors detected"
```

    Harden: advisory only — review LLDP exposure
    Config: none

    Always passes. Advisory: LLDP exposes topology information (hostnames,
    models, port descriptions) to neighbors. Useful for tools (AARON,
    CLAMPS) but consider disabling on untrusted edge ports.


### ns-port-security
CR 7.1 "Denial of service protection" | vendor §3.4 | `get_port_security()` → `set_port_security()` | severity: warning

```
    ps = get_port_security()
    skip = set(get_lldp_neighbors().keys())    # uplinks
    for domain in get_mrp().values():           # ring ports
        skip.add(domain.ring_port_1.interface)
        skip.add(domain.ring_port_2.interface)
    access_total = 0; unprotected = []
    for port, cfg in sorted(ps.ports.items()):
        if port in skip             → skip (uplink or ring infrastructure)
        access_total += 1
        if not cfg.enabled          → unprotected.append(port)
    if access_total == 0            → PASS "No access ports found"
    if unprotected                  → FAIL "{N}/{total} access port(s): 1/2, 1/3 (+N more)"
    else                            → PASS "Port security enabled on all {N} access port(s)"
```

    Harden: DEFERRED — requires per-site MAC limit policy + port classification
            (what's the right max_mac? 1? 10? depends on downstream topology)
            Future: integrate AARON port classification to auto-determine limits
    Config: none

    Smart: only checks ACCESS ports — skip ring ports (MRP) and uplinks
    (LLDP-connected). Port security on an uplink blocks legitimate
    multi-MAC traffic from downstream switches. Gracefully degrades when
    LLDP/MRP data unavailable (checks all ports as access).


### ns-dhcp-snooping
CR 3.1 "Communication integrity" | vendor §3.7 | `get_dhcp_snooping()` → `set_dhcp_snooping()` | severity: warning

```
    ds = get_dhcp_snooping()
    if not ds.enabled               → FAIL "DHCP snooping globally disabled"
    uplinks = identify from LLDP + MRP ring ports
    for port in access_ports:
        if port.trusted             → FAIL "access port {port} trusted
                                            (should only trust uplinks)"
    for port in uplinks:
        if not port.trusted         → FAIL "uplink {port} not trusted"
    if no failures                  → PASS "DHCP snooping enabled with correct trust model"
```

    Harden: set_dhcp_snooping(enabled=True) + trust uplinks + untrust access
    Config: none

    Smart: global enable + trust model verification. Uplinks and ring
    ports are trusted (DHCP server is upstream). Access ports are
    untrusted (rogue DHCP server prevention). Uses same uplink detection
    as ns-port-security (LLDP neighbors + MRP ring ports).


### ns-dai
CR 3.1 "Communication integrity" | vendor §3.8 | `get_dai()` → `set_dai()` | severity: warning

```
    dai = get_dai()
    if not dai.enabled              → FAIL "DAI disabled"
    same trust logic as ns-dhcp-snooping:
        trust uplinks + ring ports, inspect access ports
    if no failures                  → PASS "DAI enabled with correct trust model"
```

    Harden: set_dai(enabled=True) + same trust model as dhcp-snooping
    Config: none

    Mirrors ns-dhcp-snooping trust model — DAI validates ARP packets
    against the DHCP snooping binding table. DAI without DHCP snooping =
    broken (no binding table to validate against). Prerequisite: ns-dhcp-snooping.


### ns-ipsg
CR 3.1 "Communication integrity" | vendor §3.9 | `get_ip_source_guard()` → `set_ip_source_guard()` | severity: warning

```
    ipsg = get_ip_source_guard()
    uplinks = LLDP neighbors + MRP ring ports
    for port in access_ports (not uplinks):
        if not ipsg[port].verify_source → FAIL "IPSG disabled on access port(s): {list}"
    if no failures                      → PASS "IPSG enabled on all access ports"
```

    Harden: DEFERRED — requires per-port enablement policy + DHCP snooping prerequisite
    Config: none

    Per-port, only on access ports (excludes LLDP uplinks and MRP ring
    ports). IPSG validates source IP against the DHCP snooping binding
    table — prevents IP spoofing. Prerequisite: ns-dhcp-snooping must
    pass first.

---

## 7. Firmware & Config Integrity

### sec-unsigned-sw
CR 3.4 "Software integrity" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    if 'unsigned_sw' not in svc     → UNABLE "Driver extension needed"
    if svc.unsigned_sw              → FAIL "Unsigned firmware upload allowed"
    else                            → PASS "Unsigned firmware rejected"
```

    Harden: set_services(unsigned_sw=False)
    Config: none

    Prevents uploading firmware images without valid cryptographic
    signatures. Without this, an attacker with management access could
    install modified firmware.


### sec-aca-auto-update
CR 3.4 "Software integrity" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    if 'aca_auto_update' not in svc → UNABLE "Driver extension needed"
    if svc.aca_auto_update          → FAIL "ACA auto-update enabled"
    else                            → PASS "ACA auto-update disabled"
```

    Harden: set_services(aca_auto_update=False)
    Config: none

    ACA = Automatic Configuration Adapter. Auto-update pulls config
    from external media (USB, ACA) on boot — supply chain risk.


### sec-aca-config-write
CR 3.4 "Software integrity" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    if 'aca_config_write' not in svc → UNABLE "Driver extension needed"
    if svc.aca_config_write         → FAIL "ACA external config write enabled"
    else                            → PASS "ACA external config write disabled"
```

    Harden: set_services(aca_config_write=False)
    Config: none

    Prevents external media from writing config to the device.


### sec-aca-config-load
CR 3.4 "Software integrity" | iec | `get_services()` → `set_services()` | severity: warning

```
    svc = get_services()
    if svc is None                  → UNABLE
    if 'aca_config_load' not in svc → UNABLE "Driver extension needed"
    if svc.aca_config_load          → FAIL "ACA external config load enabled"
    else                            → PASS "ACA external config load disabled"
```

    Harden: set_services(aca_config_load=False)
    Config: none

    Prevents device from loading config from external media on boot.

---

## 8. Certified Hardware Capabilities

All four cert checks use the same `_cert_pass()` helper. These are not
configuration checks — they verify that the device family has a valid
IEC 62443-4-2 TÜV certification covering the required capability.

Evidence: cert reference from `certs.json` (matched by device model prefix).

### cert-hw-authenticator — SL2
CR 1.5 "Authenticator management" | cert | — | severity: info

```
    model = device model from get_facts()
    cert = resolve_cert(certs.json, model)
    if cert exists and cert.cert    → PASS "Hardware-protected authenticator storage
                                            — certified ({cert_ref})"
    else                            → FAIL "no cert found for {model}"
```

    Harden: cert-inherent (TÜV certification proof, not configurable)

    SL2 requires hardware-protected authenticator storage (password-protected
    memory, OTP, HW integrity checks, secure boot).


### cert-hw-pubkey — SL2
CR 1.9 "Strength of public key authentication" | cert | — | severity: info

```
    (same _cert_pass logic as above)
```

    Harden: cert-inherent

    SL2 requires hardware-protected private key storage (TPM/secure element).


### cert-hw-symkey — SL2
CR 1.14 "Strength of symmetric key-based authentication" | cert | — | severity: info

```
    (same _cert_pass logic as above)
```

    Harden: cert-inherent

    SL2 requires hardware-protected shared key storage.


### cert-memory-purge — SL2
CR 4.2 "Information persistence" | cert | — | severity: info

```
    (same _cert_pass logic as above)
```

    Harden: cert-inherent

    SL2 requires capability to purge shared non-persistent memory.

---

## Harden Summary

### Auto-fix (21 checks — HARDEN_DISPATCH registered)

| Check | Setter Call | Notes |
|-------|-------------|-------|
| sec-hidiscovery | `set_hidiscovery('off')` | |
| sec-insecure-protocols | `set_services(http=False, telnet=False)` | HTTPS+SSH remain |
| sec-industrial-protocols | `set_services(**{proto: False})` | Only disables enabled ones |
| ns-gvrp-mvrp | `set_services(mvrp=False)` | MVRP supersedes GVRP |
| ns-gmrp-mmrp | `set_services(mmrp=False)` | MMRP supersedes GMRP |
| sec-login-policy | `set_login_policy(max=5, lockout=60, min_len=8)` | |
| sec-password-policy | `set_login_policy(min_upper=1, min_lower=1, min_num=1, min_spec=1)` | SL2 |
| sec-login-banner | `set_banner(pre_login_enabled=True, text=...)` | Config: login_banner |
| sec-ip-restrict | `add_ip_restrict_rule() + set_ip_restrict(enabled=True)` | Config: mgmt_subnet |
| sec-session-timeouts | `set_session_config(ssh=5, telnet=5, web=5, serial=5)` | Minutes |
| sec-concurrent-sessions | `set_session_config(ssh_max=5, telnet_max=5)` | SL2 |
| sec-snmpv1-traps | `set_snmp_config(v1=False)` | |
| sec-snmpv1v2-write | `set_snmp_config(v1=False, v2=False)` | Disables v1+v2 entirely |
| sec-unsigned-sw | `set_services(unsigned_sw=False)` | |
| sec-aca-auto-update | `set_services(aca_auto_update=False)` | |
| sec-aca-config-write | `set_services(aca_config_write=False)` | |
| sec-aca-config-load | `set_services(aca_config_load=False)` | |
| sec-time-sync | `set_ntp(enabled=True, servers=[...])` | Config: ntp_server |
| sec-logging | `set_syslog(enabled=True, servers=[...])` | Config: syslog_server/port |
| sec-devsec-monitors | `set_services(devsec_monitors=True)` | |
| sec-signal-contact | `set_signal_contact(1, mode='deviceStateAndSecurity')` | |

### Config-dependent hardening

| Check | Config Key | Purpose |
|-------|-----------|---------|
| sec-time-sync | `ntp_server` | NTP server address(es) |
| sec-logging | `syslog_server`, `syslog_port` | Syslog destination |
| sec-login-banner | `login_banner` | Banner text (has default) |
| sec-ip-restrict | `mgmt_subnet` | Management subnet CIDR |

If the config key is not set, the harden function returns SKIP (None).
Interactive mode prompts for these values when they're missing.

### Advisory only (3 checks — detection, no auto-fix)

- `sec-mgmt-vlan` — requires VLAN migration (VIKTOR domain)
- `ns-dos-protection` — site-specific storm control thresholds
- `ns-lldp` — topology exposure awareness (always passes)

### Detection only (6 checks — no setter exists / operator action required)

- `sec-https-cert` — fix via CLI `https certificate generate`
- `sec-dev-mode` — firmware-level setting
- `sec-secure-boot` — hardware-dependent
- `sec-user-review` — account list for manual lifecycle audit (partial assessment, always passes)
- `sec-user-roles` — RBAC verification (auto-PASS if external AAA active)

### Deferred (6 checks — harden needs driver/infrastructure/site-specific work)

- `sec-snmpv3-traps` — requires server infrastructure + credentials
- `ns-port-security` — check implemented (detect only), harden deferred (per-site MAC limit policy + AARON port classification)
- `ns-dhcp-snooping` — implemented (check only, harden deferred)
- `ns-dai` — implemented (check only, harden deferred)
- `ns-ipsg` — implemented (check only, harden deferred)
- `sec-unused-ports` — check only (harden deferred, site-specific port plan)

### Cert-inherent (4 checks — TÜV certification proof)

- `cert-hw-authenticator`, `cert-hw-pubkey`, `cert-hw-symkey`, `cert-memory-purge`
- Auto-pass when device model matches a certified family in `certs.json`
