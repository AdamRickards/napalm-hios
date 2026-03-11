# JUSTIN — Architecture & Logic

## Phase Lifecycle

JUSTIN runs as a phased pipeline. Every session follows the same
lifecycle, whether interactive, CLI, or fleet:

```
Phase 0 ─── Setup (config, creds, devices, level, safety settings)
  │
  ▼
Phase 1 ─── Gather (connect, call getters, build state + evidence)  ◄──┐
  │                                                                      │
  ▼                                                                      │
Phase 2 ─── Review (report, findings, select)                            │
  │                                                                      │
  ▼                                                                      │
Phase 3 ─── Execute (apply fixes, re-gather, verify) ───────────────────┘
  │
  ▼         (loop 1→2→3 until satisfied)
Phase 4 ─── Save & Exit (NVM save, pre/post snapshot, session close)
```

Phase 0 runs once. Phases 1→2→3 loop until the operator is done.
Phase 4 is the exit gate — you can't leave without being asked.

### Phase Details

| Phase | What Happens | JSON Session Log |
|-------|-------------|------------------|
| **0** | Load config, parse IPs, resolve level, configure safety settings | Created per device |
| **1** | Connect → `get_facts()` → gather all getters → `run_checks()` + evidence | `state_before`, `evidence`, `findings`, `score` |
| **2** | Display report, select findings to fix | — |
| **3** | Pre-snapshot (if enabled) → apply `HARDEN_DISPATCH` setters → re-gather → verify | `_snapshot_pre`, `changes[]` (each timestamped), `state_after`, `state_diff` |
| **4** | Save to NVM? → Post-snapshot? → session `finish()` | `_save_config`, `_snapshot_post` entries |

### Phase 0: Safety Settings

Interactive mode shows a SAFETY section during setup:

```
  SAFETY
    Dirty-config guard:  ON   (refuse to modify unsaved switches)
    Auto-save after:     OFF  (prompt before saving to NVM)
    Snapshot:            OFF  (no NVM profiles created)
  Change defaults? [n] y/n:
```

If `y`: prompts for each setting. Defaults come from `script.cfg`:

| Setting | `script.cfg` | Default | Values |
|---------|-------------|---------|--------|
| `dirty_guard` | `dirty_guard = true` | `true` | `true`/`false` |
| `auto_save` | `auto_save = false` | `false` | `true`/`false` |
| `snapshot` | `snapshot = off` | `off` | `off`/`post`/`pre+post` |

CLI `--save` is equivalent to `auto_save = true`. CLI `--snapshot NAME`
always creates pre+post pair.

### Phase 4: Save & Exit Gate

Phase 4 prevents walking away from unsaved switches:

```
  ── Save & Exit ──
  3 change(s) applied
  ▸ Save to NVM? [Y/n]: y
  Saving to NVM ... OK
  ▸ Create snapshot? [Y/n]: y
  ▸ Snapshot name [SL1-20260309]:
  Snapshot 'SL1-20260309-pre' ... OK (captured before changes)
  Snapshot 'SL1-20260309-post' ... OK (captured after changes)
```

Pre/post snapshot creates a named pair of NVM config profiles:
- `NAME-pre` — captured before any changes are applied (inside `harden_device()`)
- `NAME-post` — captured after save (in Phase 4 or caller)

Collision-avoidant — appends `-1`, `-2` if name exists. Requires MOPS
(`get_profiles()`, `get_config(profile=, source='nvm')`, `load_config()`).

Snapshot mode controls what's created:
- `off` — no snapshots (default)
- `post` — only `NAME-post` after save
- `pre+post` — both `NAME-pre` before changes and `NAME-post` after save

CLI equivalent: `--harden --commit --save --snapshot SL1-baseline`

## Architecture

```
checks.json  →  load_checks()  →  check_defs dict
certs.json   →  load_certs()   →  certs dict
                                        │
                     filter_checks_by_level(level_str)
                                        │
device  →  gather()  →  (state, evidence)  →  run_checks()  →  findings[]
                              │                                      │
                              ├─ state → check functions             │
                              └─ evidence → report/HTML              │
                                                                     │
                                        harden_device()  ←───────────┘
                                         │  (pre-snapshot)
                                         ▼
                                        _phase4_exit()
                                         │  (save + post-snapshot)
```

1. **Load**: `load_checks()` reads all check definitions (43 in checks.json,
   47 total including 4 future checks documented in CHECK_LOGIC.md).
   `filter_checks_by_level()` selects the active subset — only needed
   getters fire (no wasted I/O).
2. **Gather**: One connection per device. Each unique getter called once.
   Returns `(state, evidence)` — `state` has raw results for check
   functions, `evidence` has timestamped copies for the audit trail:
   `{getter: {gathered_at: iso, data: result}}`.
3. **Check**: Each registered check function receives `(state, spec, config)`,
   returns one `Finding`. Unimplemented checks emit "Not yet implemented"
   findings. Checks are pure functions — no device I/O.
4. **Report**: Findings sorted (failures first by severity), displayed as
   compact view (interactive) or full report (CLI). HTML via `-o report.html`.
   Each finding links to its evidence via `evidence_key`.
5. **Harden**: For each failed finding with a registered `HARDEN_DISPATCH`
   function, call the corresponding setter. Pre-snapshot fires before changes.
6. **Save/Snapshot**: Phase 4 gate. NVM save + optional post-snapshot.

## Three Access Patterns

All three use the same `gather()` → `run_checks()` → `harden_device()`
pipeline. Same checks, same findings, same setters.

### CLI (`--audit` / `--harden`)

```bash
justin --audit -d 192.168.1.4                    # SL1 (default)
justin --audit -d 192.168.1.4 --level sl1,vendor # SL1 + vendor
justin --audit -c site.cfg -o report.html         # fleet + HTML report
justin --harden -d 192.168.1.4 --commit --save --watchdog 120
justin --harden --from-report report.json --commit --save --snapshot SL1
```

### Config File (`script.cfg`)

```ini
username = admin
password = private
protocol = mops
level = sl1,vendor

# Hardening targets (used by setters)
syslog_server = 10.0.0.100
syslog_port = 514
ntp_server = 10.0.0.1

# Safety settings (all optional — shown with defaults)
dirty_guard = true
auto_save = false
snapshot = off

192.168.60.80
192.168.60.81
192.168.60.82
192.168.60.85
```

### Interactive (`-i`)

Phase 0 loads `script.cfg` or prompts for manual setup (including level).
Shows SAFETY section with configurable defaults (dirty-config guard,
auto-save, snapshot mode) — tweak before proceeding.
Phase 1 shows live progress (fleet: devices fill in as audits complete).
Phase 2 is a REPL with `[v]iew` / `[h]arden` / `[r]eport` / `[q]uit`.
Phase 3 applies fixes and loops back to Phase 1. Phase 4 respects
auto-save and snapshot settings from Phase 0.

Single device: connection stays open throughout all phases.
Fleet: devices connect per-operation, phase 4 reconnects in parallel.

## Feature Parity

| Feature | CLI `--arg` | `script.cfg` | Interactive `-i` |
|---------|:-----------:|:------------:|:----------------:|
| Audit | `--audit` | devices list | auto |
| Harden | `--harden --commit` | devices list | `[h]arden` |
| Level | `--level sl1,vendor` | `level = sl1,vendor` | prompted |
| Dry-run | `--dry-run` | — | — (always commit) |
| Dirty-config guard | on (default) | `dirty_guard = true` | Phase 0 SAFETY |
| Auto-save | `--save` | `auto_save = false` | Phase 0 SAFETY |
| Snapshot | `--snapshot NAME` (pre+post) | `snapshot = off` | Phase 0 SAFETY |
| Watchdog | `--watchdog SEC` | — | Phase 0 prompt |
| Report save | `-o FILE` | — | `[r]eport` prompt |
| HTML report | `-o report.html` | — | — |
| JSON output | `-j` | — | — |
| Two-step | `--from-report` | creds + targets | — |
| Fleet parallel | auto (>1 device) | devices list | auto |
| Evidence trail | auto (always) | auto (always) | auto (always) |
| Syslog target | — | `syslog_server` | prompted if missing |
| NTP target | — | `ntp_server` | prompted if missing |
| Severity filter | `-s critical` | — | — |
| No colour | `--no-color` | — | — |

## Security Levels

Composable, comma-separated. IEC SL levels are hierarchical.
`vendor` adds Hirschmann Security Guide checks. `highest` = everything.

| Level | Source | Scope |
|-------|--------|-------|
| `sl1` | IEC 62443-4-2 | 16 checks — core security baseline |
| `sl2` | IEC 62443-4-2 + cert + vendor(SL2) | 26 checks — adds complexity, sessions, certs, IP restrict, console |
| `vendor` | Hirschmann Security Guide | 20 checks — vendor hardening beyond IEC |
| `highest` | all | 44 checks — IEC SL2 + vendor + cert |

SL3 excluded until deducible checks land (requires `get_users`,
`get_password_policy` driver methods). Currently sl3 == sl2.

Level resolution priority: CLI `--level` > `script.cfg level=` > default `sl1`.

## IEC 62443-4-2 Clause Mapping

### CR 1 — Identification & Authentication

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-login-policy | CR 1.11 | Unsuccessful login attempts | iec | `get_login_policy()`: fail if `max_login_attempts == 0` or `min_password_length < 8` |
| sec-password-policy | CR 1.7 | Password-based auth strength | iec | `get_login_policy()`: fail if complexity rules not set. **SL2** |
| sys-default-passwords | CR 1.5 | Authenticator management | iec | Probe: if connecting with admin/private succeeds, FAIL |
| sec-login-banner | CR 1.12 | System use notification | vendor | `get_banner()`: fail if pre-login banner disabled or no text |
| sec-https-cert | CR 1.2 | Device authentication | vendor | `get_devsec_status()`: fail if DevSec cause #23 (https-certificate-warning) |
| sec-remote-auth | CR 1.1 | Human user ID & auth | iec | `get_remote_auth()`: fail if no RADIUS/TACACS+ servers. **SL2** |
| cert-hw-authenticator | CR 1.5 | Authenticator management | cert | `certs.json`: pass if model has TÜV cert. **SL2** |
| cert-hw-pubkey | CR 1.9 | Public key auth strength | cert | `certs.json`: pass if model has TÜV cert. **SL2** |
| cert-hw-symkey | CR 1.14 | Symmetric key auth strength | cert | `certs.json`: pass if model has TÜV cert. **SL2** |

### CR 2 — Use Control

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-snmpv1v2-write | CR 2.1 | Authorization enforcement | iec | `get_snmp_config()`: fail if v1/v2 enabled AND rw communities exist |
| sec-ip-restrict | CR 2.1 | Authorization enforcement | vendor | `get_ip_restrict()`: fail if no IP restriction enabled or no rules |
| sec-time-sync | CR 2.11 | Timestamps | iec | `get_ntp()`: fail if client disabled or no servers configured |
| sec-logging | CR 2.8 | Auditable events | iec | `get_syslog()`: fail if disabled or no active destinations |
| sec-session-timeouts | CR 2.6 | Remote session termination | vendor | `get_session_config()`: fail if any protocol timeout is 0 |
| sec-concurrent-sessions | CR 2.7 | Concurrent session control | iec | `get_session_config()`: fail if any max_sessions > 5. **SL2** |
| sec-console-port | EDR 2.13 | Physical diagnostic interfaces | iec | `get_session_config()` + `get_facts()` → `_resolve_hw_profile()`: fail if serial timeout == 0 or ENVM enabled. Check + harden. **SL2** |

### CR 3 — System Integrity

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-unsigned-sw | CR 3.4 | Software integrity | iec | `get_services()`: fail if `unsigned_sw == True` |
| sec-aca-auto-update | CR 3.4 | Software integrity | iec | `get_services()`: fail if `aca_auto_update == True` |
| sec-aca-config-write | CR 3.4 | Software integrity | iec | `get_services()`: fail if `aca_config_write == True` |
| sec-aca-config-load | CR 3.4 | Software integrity | iec | `get_services()`: fail if `aca_config_load == True` |
| ns-dhcp-snooping | CR 3.1 | Communication integrity | vendor | `get_dhcp_snooping()`: fail if disabled or trust model wrong. Check only (harden deferred) |
| ns-dai | CR 3.1 | Communication integrity | vendor | `get_arp_inspection()`: fail if no VLAN enabled or trust model wrong. Check only (harden deferred) |
| ns-ipsg | CR 3.1 | Communication integrity | vendor | `get_ip_source_guard()`: fail if disabled on access ports. Check only (harden deferred) |
| sec-secure-boot | CR 3.14 | Integrity of boot process | vendor | `get_devsec_status()`: fail if DevSec cause #31 (secure-boot-disabled) |

### CR 4 — Data Confidentiality

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-insecure-protocols | CR 4.1 | Communication confidentiality | iec | `get_services()`: fail if `http.enabled` or `telnet.enabled` |
| sec-snmpv1-traps | CR 4.1 | Communication confidentiality | iec | `get_snmp_config()`: fail if `versions.v1 == True` |
| sec-snmpv3-auth | CR 4.3 | Use of cryptography | vendor | `get_snmp_config()`: fail if any v3 user has auth '' or 'md5' |
| sec-snmpv3-encrypt | CR 4.3 | Use of cryptography | vendor | `get_snmp_config()`: fail if any v3 user has enc 'none' or 'des' |
| cert-memory-purge | CR 4.2 | Information persistence | cert | `certs.json`: pass if model has TÜV cert. **SL2** |

### CR 5 — Restricted Data Flow

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-mgmt-vlan | CR 5.1 | Network segmentation | iec | `get_management()`: fail if `vlan_id == 1` (advisory only) |

### CR 6 — Timely Response to Events

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-devsec-monitors | CR 6.2 | Continuous monitoring | iec | `get_services()`: fail if `devsec_monitors != True` |
| sec-snmpv3-traps | CR 6.2 | Continuous monitoring | vendor | `get_snmp_config()`: fail if trap service off or no v3 authPriv dest |
| sec-signal-contact | CR 6.2 | Continuous monitoring | vendor | `get_signal_contact()`: fail if contact 1 not in device/security mode |

### CR 7 — Resource Availability

| Check | CR | Requirement | Source | Logic |
|-------|----|-------------|--------|-------|
| sec-hidiscovery | CR 7.7 | Least functionality | iec | `get_hidiscovery()`: fail if `enabled == True` |
| ns-gvrp-mvrp | CR 7.7 | Least functionality | iec | `get_services()`: fail if `gvrp` or `mvrp` enabled |
| ns-gmrp-mmrp | CR 7.7 | Least functionality | iec | `get_services()`: fail if `gmrp` or `mmrp` enabled |
| sec-industrial-protocols | CR 7.7 | Least functionality | vendor | `get_services()`: fail if PROFINET/Modbus/EtherNet-IP/IEC61850 enabled |
| ns-lldp | CR 7.7 | Least functionality | vendor | `get_lldp_neighbors()`: advisory, reports neighbor count |
| ns-dos-protection | CR 7.1 | Denial of service protection | vendor | `get_storm_control()`: fail if no ports have storm control |
| ns-port-security | CR 7.1 | Denial of service protection | vendor | `get_port_security()`: fail if disabled on access ports. Check only (harden deferred) |
| sec-poe | CR 7.7 | Least functionality | vendor | `get_poe()` + `get_interfaces()`: PoE on linkless ports. Check + harden |
| sec-dns-client | CR 7.7 | Least functionality | vendor | `get_dns()`: enabled with no servers = pointless. Check + harden |
| sec-unused-ports | CR 7.7 | Least functionality | vendor | `get_interfaces()` + `get_lldp_neighbors()` + `get_mrp()`: unused = admin-enabled + no link + no LLDP + not ring. Check only (harden deferred) |
| sec-dev-mode | CR 7.7 | Least functionality | vendor | `get_devsec_status()`: fail if DevSec cause #32 (dev-mode-enabled) |

## Hardening Defaults

Values applied by `HARDEN_DISPATCH` functions (22 auto-fix checks):

| Check | Setter Call | Notes |
|-------|-------------|-------|
| sec-hidiscovery | `set_hidiscovery('off')` | |
| sec-insecure-protocols | `set_services(http=False, telnet=False)` | HTTPS+SSH remain |
| sec-industrial-protocols | `set_services(**{proto: False})` | Only disables enabled ones |
| ns-gvrp-mvrp | `set_services(mvrp=False)` | MVRP supersedes GVRP |
| ns-gmrp-mmrp | `set_services(mmrp=False)` | MMRP supersedes GMRP |
| sec-login-policy | `set_login_policy(max=5, lockout=60, min_len=8)` | |
| sec-password-policy | `set_login_policy(min_upper=1, lower=1, num=1, spec=1)` | SL2 |
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
| sec-console-port | `set_session_config(serial_timeout=5, envm_enabled=False)` | SL2 |

Advisory-only checks (no auto-fix):
- `sec-mgmt-vlan` — requires VLAN migration (VIKTOR domain)
- `ns-dos-protection` — site-specific thresholds
- `ns-lldp` — advisory only (topology exposure awareness)

Deferred checks (needs driver/infrastructure):
- `sys-default-passwords` — requires `set_user()` (driver v1.18.0)
- `sec-snmpv3-auth/encrypt/traps` — user-specific passwords / server infrastructure
For full decision logic on all checks, see `CHECK_LOGIC.md`.

## Config-Dependent Hardening

These checks require values from `script.cfg` or interactive prompts:

| Check | Config Key | Purpose |
|-------|-----------|---------|
| sec-logging | `syslog_server`, `syslog_port` | Syslog destination |
| sec-time-sync | `ntp_server` | NTP server address |

If the config key is not set, the harden function returns SKIP.
Interactive mode prompts for these values when they're missing.

## Safety Mechanisms

### Dirty-Config Guard

JUSTIN refuses to harden a switch with unsaved config changes. This
prevents overwriting in-progress work. The `get_config_status()` call
checks NVM sync state. Audit mode shows a warning; harden mode refuses.

Configurable: `dirty_guard = false` in `script.cfg` or interactive SAFETY
section. When disabled, harden shows a warning but proceeds.

### Watchdog Rollback

`--watchdog SEC` starts the HiOS config watchdog before applying changes.
If the watchdog timer expires before `stop_watchdog()` is called, the
device reverts to the last saved config automatically. On success,
`stop_watchdog()` is called to confirm changes. Range: 30–600 seconds.

In interactive mode, the watchdog wraps Phase 3 only — no timer ticking
while you're reviewing findings in Phase 2.

```
justin --harden -d 192.168.1.4 --commit --watchdog 120
```

### Config Backup

Before any changes, `get_config()` captures the running config XML
(SSH/MOPS). Logged in the session as `config_backup: 'captured'`.

### Pre/Post NVM Snapshots

`--snapshot NAME` creates a pair of named config profiles in NVM:
- `NAME-pre` — captured before any changes are applied (inside `harden_device()`)
- `NAME-post` — captured after save completes

Collision-avoidant — appends `-1`, `-2` if name exists. Requires MOPS.
Enables rollback to any named point: `SL1-baseline-pre`, `SL1-baseline-post`.

Snapshot modes (interactive SAFETY / `script.cfg`):
- `off` — no snapshots (default)
- `post` — only post-snapshot after save
- `pre+post` — full pair, before and after changes

CLI `--snapshot NAME` always creates pre+post pair. Interactive mode
respects the configured snapshot mode from Phase 0 SAFETY section.

Pre-snapshot fires once per session (dedup check in changes log).

**Name pairing**: In interactive pre+post mode, the pre-snapshot base
name is stored in `config['_snapshot_base']` and used as the default
in Phase 4's snapshot prompt. This ensures `SL1-20260310-pre` and
`SL1-20260310-post` always share the same base.

**NVM settle retry**: Post-snapshot uses `_do_snapshot()` with
escalating retry: attempt at 0s → 5s → 7.5s → user prompt (15s).
HiOS needs 5–10s after `save_config()` for NVM write to fully
commit to flash. Without retry, immediate download+upload fails
with "Invalid configuration file for device".

### Evidence Trail

Every audit embeds timestamped evidence — the raw getter data each check
was evaluated against. `gather()` returns `(state, evidence)` where
evidence is `{getter_name: {gathered_at: iso, data: result}}`.

Reports include an `evidence` section. Each finding has an `evidence_key`
linking it to the getter that produced it. Multiple checks sharing the
same getter (e.g., 11 checks use `get_services()`) link to one evidence
block. HTML reports render this as collapsible blocks with click-to-expand
links from every check row.

## Session Log

Every run produces an incremental JSON session file in `output/`.
Written at Phase 1 (gather), updated at Phase 3 (each change), closed
at Phase 4 (finish). Contains:

```json
{
  "tool": "JUSTIN", "version": "0.2", "ip": "...",
  "started": "...", "completed": "...",
  "device": {"ip": "", "hostname": "", "model": "", "os_version": ""},
  "config_status": {"saved": true, "nvm": "..."},
  "config_backup": "captured | unavailable | null",
  "state_before": {"getter_name": "result", "...": "..."},
  "evidence": {"getter_name": {"gathered_at": "iso", "data": "..."}},
  "findings": [{"check_id": "", "clause": "", "severity": "", "desc": "", "passed": false, "fix": "", "evidence_key": "getter_name"}],
  "score": {"total": 37, "passed": 28, "failed": 9, "not_implemented": 17, "assessed": 20},
  "changes": [
    {"check_id": "_snapshot_pre", "action": "SL1-pre", "result": "ok", "timestamp": "..."},
    {"check_id": "", "action": "", "result": "applied", "timestamp": "..."},
    {"check_id": "_save_config", "action": "save_config()", "result": "ok", "timestamp": "..."},
    {"check_id": "_snapshot_post", "action": "SL1-post", "result": "ok", "timestamp": "..."}
  ],
  "state_after": {"getter_name": "result", "...": "..."},
  "state_diff": [{"getter": "", "before": "", "after": ""}],
  "watchdog": {"started": true, "seconds": 120, "stopped": true}
}
```

## Tagged Output

All operational progress lines use `_log(tag, msg)` which prints:
```
  HH:MM:SS [TAG] message
```

Tags: `CONNECT`, `GATHER`, `CHECK <id>`, `CONFIG`, `HARDEN <id>`,
`REGATHER`, `DIFF`, `SAVE`, `SNAPSHOT`, `WATCHDOG`, `SESSION`.

Report card display (boxed table, score bar, recommendations) stays
untagged. `_log()` respects `--no-color` (passes `color=` through)
and `_JSON_MODE` (stderr redirect).

## Getter Return Shapes

```
get_hidiscovery()    → {enabled, mode, blinking, protocols}
get_services()       → {http: {enabled, port}, https, ssh, telnet, snmp: {v1,v2,v3,port},
                         industrial: {profinet, modbus, ethernet_ip, iec61850, opcua},
                         unsigned_sw, aca_auto_update, aca_config_write, aca_config_load,
                         gvrp, mvrp, gmrp, mmrp, devsec_monitors}
get_syslog()         → {enabled, servers: [{index, ip, port, severity, transport}]}
get_ntp()            → {client: {enabled, mode, servers: [{address, port, status}]}, server: {enabled, stratum}}
get_login_policy()   → {min_password_length, max_login_attempts, lockout_duration,
                         min_uppercase, min_lowercase, min_numeric, min_special}
get_snmp_config()    → {versions: {v1,v2,v3}, port, communities: [{name, access}],
                         v3_users: [{name, auth_type, enc_type}],
                         trap_service, trap_destinations: [{security_model, security_level}]}
get_management()     → {protocol, vlan_id, ip_address, netmask, gateway, ...}
get_storm_control()  → {interfaces: {port: {broadcast: {enabled, rate}, multicast: {enabled, rate}, unicast: {enabled, rate}}}}
get_lldp_neighbors() → {port: [{hostname, port, port_description, system_name, system_description, ...}]}
get_banner()         → {pre_login: {enabled, text}}
get_signal_contact() → {1: {mode}, 2: {mode}}
get_devsec_status()  → {status: {events: [{cause}]}, monitoring: {https_certificate_warning,
                         dev_mode_enabled, secure_boot_disabled}}
get_session_config() → {ssh: {timeout, max_sessions}, ssh_outbound: {timeout, max_sessions},
                         telnet: {timeout, max_sessions}, web: {timeout}, serial: {timeout},
                         netconf: {max_sessions}}
get_ip_restrict()    → {enabled, rules: [{index, ip, prefix_length}]}
```

## Driver Methods Used

| Method | Phase | Purpose |
|--------|-------|---------|
| `get_facts()` | 1 | Device identity (hostname, model, firmware) |
| `get_hidiscovery()` | 1 | HiDiscovery state |
| `get_services()` | 1 | Protocol/service state + industrial + devsec monitors |
| `get_syslog()` | 1 | Syslog configuration |
| `get_ntp()` | 1 | NTP configuration |
| `get_login_policy()` | 1 | Password/lockout/complexity policy |
| `get_snmp_config()` | 1 | SNMP versions + communities + v3 users + traps |
| `get_management()` | 1 | Management VLAN/IP |
| `get_storm_control()` | 1 | Storm control state (vendor checks) |
| `get_lldp_neighbors()` | 1 | LLDP topology (vendor checks) |
| `get_banner()` | 1 | Pre-login banner state |
| `get_signal_contact()` | 1 | Signal contact relay mode |
| `get_devsec_status()` | 1 | DevSec events + monitoring flags |
| `get_session_config()` | 1 | Session timeouts + max sessions |
| `get_ip_restrict()` | 1 | IP restriction rules + enabled state |
| `get_interfaces()` | 1 | Port state (sec-unused-ports) |
| `get_mrp()` | 1 | Ring port membership (sec-unused-ports) |
| `get_config_status()` | 1 | Dirty-config guard |
| `get_config()` | 3 | Config backup before changes |
| `set_hidiscovery()` | 3 | Disable HiDiscovery |
| `set_services()` | 3 | Disable HTTP/Telnet/industrial/ACA + enable devsec monitors |
| `set_login_policy()` | 3 | Set lockout + min password + complexity |
| `set_ntp()` | 3 | Enable NTP client |
| `set_syslog()` | 3 | Configure syslog destination |
| `set_snmp_config()` | 3 | Disable SNMPv1/v2 |
| `set_banner()` | 3 | Set pre-login banner |
| `set_signal_contact()` | 3 | Set signal contact mode |
| `set_session_config()` | 3 | Set timeouts + max sessions |
| `set_ip_restrict()` | 3 | Enable IP restriction |
| `add_ip_restrict_rule()` | 3 | Add IP restriction rule |
| `start_watchdog()` | 3 | Start rollback timer |
| `stop_watchdog()` | 3 | Confirm changes |
| `save_config()` | 4 | Save to NVM |
| `get_profiles()` | 4 | List NVM config profiles |
| `load_config()` | 4 | Upload snapshot profile |
