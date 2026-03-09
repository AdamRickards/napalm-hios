# JUSTIN — Architecture & Logic

## Phase Lifecycle

JUSTIN runs as a phased pipeline. Every session follows the same
lifecycle, whether interactive, CLI, or fleet:

```
Phase 0 ─── Setup (config, creds, devices, targets)
  │
  ▼
Phase 1 ─── Gather (connect, call getters, build state)  ◄──┐
  │                                                          │
  ▼                                                          │
Phase 2 ─── Review (report, findings, select)                │
  │                                                          │
  ▼                                                          │
Phase 3 ─── Execute (apply fixes, re-gather, verify) ───────┘
  │
  ▼         (loop 1→2→3 until satisfied)
Phase 4 ─── Save & Exit (NVM save, snapshot, session close)
```

Phase 0 runs once. Phases 1→2→3 loop until the operator is done.
Phase 4 is the exit gate — you can't leave without being asked.

### Phase Details

| Phase | What Happens | JSON Session Log |
|-------|-------------|------------------|
| **0** | Load config, parse IPs, import driver | Created per device |
| **1** | Connect → `get_facts()` → gather all getters → `run_checks()` | `state_before`, `findings`, `score` |
| **2** | Display report, select findings to fix | — |
| **3** | Apply `HARDEN_DISPATCH` setters, re-gather, verify | `changes[]` (each timestamped), `state_after`, `state_diff` |
| **4** | Save to NVM? → Create snapshot? → session `finish()` | `_save_config`, `_snapshot` entries |

### Phase 4: Save & Exit Gate

Phase 4 prevents walking away from unsaved switches:

```
  ── Save & Exit ──
  3 change(s) applied
  ▸ Save to NVM? [Y/n]: y
  Saving to NVM ... OK
  ▸ Create snapshot? [Y/n]: y
  ▸ Snapshot name [SL1-20260309]:
  Snapshot 'SL1-20260309' ... OK
```

Snapshot creates a named NVM config profile (collision-avoidant). If
SL2 hardening breaks something next month, revert to the SL1 snapshot.
Requires MOPS protocol (`get_profiles()`, `get_config(profile=, source='nvm')`,
`load_config()`). Logic stolen from MOHAWC's `worker_snapshot()`.

CLI equivalent: `--harden --commit --save --snapshot SL1-baseline`

## Architecture

```
checks.json  →  load_checks()  →  check_defs dict
                                        │
device  →  gather()  →  state dict  →  run_checks()  →  findings[]
                                                              │
                                        harden_device()  ←────┘
                                              │
                                        _phase4_exit()  ←─────┘
```

1. **Gather**: One connection per device. Each unique getter called once,
   results cached in `state[getter_name]`.
2. **Check**: Each check function receives `(state, spec, config)`, returns
   one `Finding`. Checks are pure functions — no device I/O.
3. **Report**: Findings sorted (failures first by severity), displayed as
   compact view (interactive) or full report (CLI).
4. **Harden**: For each failed finding with a registered `HARDEN_DISPATCH`
   function, call the corresponding setter.
5. **Save/Snapshot**: Phase 4 gate. NVM save + optional named snapshot.

## Three Access Patterns

All three use the same `gather()` → `run_checks()` → `harden_device()`
pipeline. Same checks, same findings, same setters.

### CLI (`--audit` / `--harden`)

```bash
justin --audit -d 192.168.1.4              # single audit
justin --audit -c site.cfg                 # fleet audit
justin --audit -c site.cfg -o report.json  # save report
justin --harden -d 192.168.1.4 --commit --save --watchdog 120
justin --harden -d 192.168.1.4 --commit --save --snapshot SL1-baseline
justin --harden --from-report report.json --commit --save --snapshot SL1
```

### Config File (`script.cfg`)

```ini
username = admin
password = private
protocol = mops

# Hardening targets (used by setters)
syslog_server = 10.0.0.100
syslog_port = 514
ntp_server = 10.0.0.1

192.168.60.80
192.168.60.81
192.168.60.82
192.168.60.85
```

### Interactive (`-i`)

Phase 0 loads `script.cfg` or prompts for manual setup. Phase 1 shows
live progress (fleet: devices fill in as audits complete). Phase 2 is a
REPL with `[v]iew` / `[h]arden` / `[r]eport` / `[q]uit`. Phase 3 applies
fixes and loops back to Phase 1. Phase 4 prompts save + snapshot on exit.

Single device: connection stays open throughout all phases.
Fleet: devices connect per-operation, phase 4 reconnects in parallel.

## Feature Parity

| Feature | CLI `--arg` | `script.cfg` | Interactive `-i` |
|---------|:-----------:|:------------:|:----------------:|
| Audit | `--audit` | devices list | auto |
| Harden | `--harden --commit` | devices list | `[h]arden` |
| Dry-run | `--dry-run` | — | — (always commit) |
| Save to NVM | `--save` | — | Phase 4 prompt |
| Snapshot | `--snapshot NAME` | — | Phase 4 prompt |
| Watchdog | `--watchdog SEC` | — | Phase 0 prompt |
| Report save | `-o FILE` | — | `[r]eport` prompt |
| JSON output | `-j` | — | — |
| Two-step | `--from-report` | creds + targets | — |
| Fleet parallel | auto (>1 device) | devices list | auto |
| Syslog target | — | `syslog_server` | prompted if missing |
| NTP target | — | `ntp_server` | prompted if missing |
| Severity filter | `-s critical` | — | — |
| No colour | `--no-color` | — | — |

## Security Levels

Checks are tagged with a security level (SL). `--level SL1` runs only
SL1 checks. `--level SL2` runs SL1 + SL2 checks.

| Level | Source | Scope |
|-------|--------|-------|
| SL1 | IEC 62443-4-2 | v0.1 — 16 checks |
| SL2 | IEC 62443-4-2 | v0.2 — password policy, session timeouts, port security |
| BSG | Belden Security Guide | Vendor-specific hardening beyond IEC |
| BPR | Industry Best Practice | Additional hardening advice |

## IEC 62443-4-2 Clause Mapping

### CR 1 — Identification & Authentication

| Check | CR | Requirement | Logic |
|-------|----|-------------|-------|
| sec-login-policy | CR 1.11 | Unsuccessful login attempts | `get_login_policy()`: fail if `max_login_attempts == 0` or `min_password_length < 8` |
| sys-default-passwords | CR 1.5 | Authenticator management | Probe: if connecting with admin/private succeeds, FAIL |

### CR 2 — Use Control

| Check | CR | Requirement | Logic |
|-------|----|-------------|-------|
| sec-snmpv1v2-write | CR 2.1 | Authorization enforcement | `get_snmp_config()`: fail if v1 or v2 enabled AND rw communities exist |

### CR 3 — System Integrity

| Check | CR | Requirement | Logic |
|-------|----|-------------|-------|
| sec-unsigned-sw | CR 3.4 | Software integrity | `get_services()`: fail if `unsigned_sw == True` |
| sec-aca-auto-update | CR 3.4 | Software integrity | `get_services()`: fail if `aca_auto_update == True` |
| sec-aca-config-write | CR 3.4 | Software integrity | `get_services()`: fail if `aca_config_write == True` |
| sec-aca-config-load | CR 3.4 | Software integrity | `get_services()`: fail if `aca_config_load == True` |

### CR 4 — Data Confidentiality

| Check | CR | Requirement | Logic |
|-------|----|-------------|-------|
| sec-insecure-protocols | CR 4.1 | Communication confidentiality | `get_services()`: fail if `http.enabled` or `telnet.enabled` |
| sec-snmpv1-traps | CR 4.1 | Communication confidentiality | `get_snmp_config()`: fail if `versions.v1 == True` |

### CR 6 — Timely Response to Events

| Check | CR | Requirement | Logic |
|-------|----|-------------|-------|
| sec-time-sync | CR 6.1 | Audit log | `get_ntp()`: fail if client disabled or no servers configured |
| sec-logging | CR 6.1 | Audit log | `get_syslog()`: fail if disabled or no active destinations |
| sec-devsec-monitors | CR 6.2 | Continuous monitoring | `get_services()`: fail if `devsec_monitors != True` |

### CR 7 — Resource Availability

| Check | CR | Requirement | Logic |
|-------|----|-------------|-------|
| sec-hidiscovery | CR 7.7 | Least functionality | `get_hidiscovery()`: fail if `enabled == True` |
| sec-mgmt-vlan | CR 7.6 | Network segmentation | `get_management()`: fail if `vlan_id == 1` (advisory only) |
| ns-gvrp-mvrp | CR 7.7 | Least functionality | `get_services()`: fail if `gvrp` or `mvrp` enabled |
| ns-gmrp-mmrp | CR 7.7 | Least functionality | `get_services()`: fail if `gmrp` or `mmrp` enabled |

## Hardening Defaults

Values applied by `HARDEN_DISPATCH` functions:

| Check | Setter Call | Notes |
|-------|-------------|-------|
| sec-hidiscovery | `set_hidiscovery('off')` | |
| sec-insecure-protocols | `set_services(http=False, telnet=False)` | HTTPS+SSH remain |
| sec-login-policy | `set_login_policy(max=5, lockout=60, min_len=8)` | |
| sec-time-sync | `set_ntp(client_enabled=True)` | Server IP from config |
| sec-logging | `set_syslog(enabled=True, servers=[...])` | Server IP from config |
| sec-snmpv1-traps | `set_snmp_config(v1=False)` | |
| sec-snmpv1v2-write | `set_snmp_config(v1=False, v2=False)` | Disables v1+v2 entirely |

Advisory-only checks (no auto-fix):
- `sec-mgmt-vlan` — requires VLAN migration (VIKTOR domain)
- `sys-default-passwords` — requires `set_user()` (driver v1.18.0)

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

### NVM Snapshot

`--snapshot NAME` creates a named config profile in NVM after save.
Collision-avoidant — appends `-1`, `-2` if name exists. Requires MOPS.
Enables rollback to any named point: `SL1-20260309`, `pre-SL2`, etc.

## Session Log

Every run produces an incremental JSON session file in `output/`.
Written at Phase 1 (gather), updated at Phase 3 (each change), closed
at Phase 4 (finish). Contains:

```json
{
  "tool": "JUSTIN", "version": "0.1", "ip": "...",
  "started": "...", "completed": "...",
  "device": {"ip": "", "hostname": "", "model": "", "os_version": ""},
  "config_status": {"saved": true, "nvm": "..."},
  "config_backup": "captured | unavailable | null",
  "state_before": {"getter_name": "result", "...": "..."},
  "findings": [{"check_id": "", "clause": "", "severity": "", "desc": "", "passed": false, "fix": ""}],
  "score": {"total": 16, "passed": 11, "failed": 5},
  "changes": [{"check_id": "", "action": "", "result": "applied", "timestamp": ""}],
  "state_after": {"getter_name": "result", "...": "..."},
  "state_diff": [{"getter": "", "before": "", "after": ""}],
  "watchdog": {"started": true, "seconds": 120, "stopped": true}
}
```

## Two-Step Workflow

Separates audit (read-only, any time) from remediation (change window):

```
Step 1:  justin --audit -c site.cfg -o audit_2026-03-09.json
         → Review report, get approval, schedule maintenance window

Step 2:  justin --harden --from-report audit_2026-03-09.json -c site.cfg --commit --save --snapshot SL1
         → Apply fixes, save, snapshot — using saved findings + config credentials
```

## Getter Return Shapes

```
get_hidiscovery()  → {enabled, mode, blinking, protocols}
get_services()     → {http: {enabled, port}, https, ssh, telnet, snmp: {v1,v2,v3,port}, industrial: {...}}
get_syslog()       → {enabled, servers: [{index, ip, port, severity, transport}]}
get_ntp()          → {client: {enabled, mode, servers: [{address, port, status}]}, server: {enabled, stratum}}
get_login_policy() → {min_password_length, max_login_attempts, lockout_duration, min_uppercase/lowercase/numeric/special}
get_snmp_config()  → {versions: {v1,v2,v3}, port, communities: [{name, access}]}
get_management()   → {protocol, vlan_id, ip_address, netmask, gateway, ...}
```

## Driver Methods Used

| Method | Phase | Purpose |
|--------|-------|---------|
| `get_facts()` | 1 | Device identity (hostname, model, firmware) |
| `get_hidiscovery()` | 1 | HiDiscovery state |
| `get_services()` | 1 | Protocol/service state |
| `get_syslog()` | 1 | Syslog configuration |
| `get_ntp()` | 1 | NTP configuration |
| `get_login_policy()` | 1 | Password/lockout policy |
| `get_snmp_config()` | 1 | SNMP versions + communities |
| `get_management()` | 1 | Management VLAN/IP |
| `get_config_status()` | 1 | Dirty-config guard |
| `get_config()` | 3 | Config backup before changes |
| `set_hidiscovery()` | 3 | Disable HiDiscovery |
| `set_services()` | 3 | Disable HTTP/Telnet |
| `set_login_policy()` | 3 | Set lockout + min password |
| `set_ntp()` | 3 | Enable NTP client |
| `set_syslog()` | 3 | Configure syslog destination |
| `set_snmp_config()` | 3 | Disable SNMPv1/v2 |
| `start_watchdog()` | 3 | Start rollback timer |
| `stop_watchdog()` | 3 | Confirm changes |
| `save_config()` | 4 | Save to NVM |
| `get_profiles()` | 4 | List NVM config profiles |
| `load_config()` | 4 | Upload snapshot profile |
