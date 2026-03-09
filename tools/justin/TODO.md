# JUSTIN — TODO

**J**ustified **U**nified **S**ecurity **T**esting for **I**ndustrial **N**etworks

Security audit and hardening tool for Hirschmann HiOS switches. Scans
devices against IEC 62443 baselines, reports pass/fail with clause
references, and remediates findings with corresponding setters.

## Relationship to ADAM

ADAM is the offline audit engine — XML config files, zero dependencies,
Belden Security Manual checks. ADAM stays standalone.

JUSTIN is the online engine — live connectivity via napalm-hios, IEC 62443
targeting, automatic remediation, fleet scale. Independent codebase, own
checks, own standard.

## Security Levels — 4-Tier Output

Each check is tagged with a level. Reports can show any combination:

| Level | Source | Description |
|-------|--------|-------------|
| **SL1** | IEC 62443-4-2 | Baseline security — must-have for any deployment |
| **SL2** | IEC 62443-4-2 | Enhanced security — segmented networks, stronger auth |
| **BSG** | Belden Security Guide | Vendor-specific hardening beyond IEC |
| **BPR** | Industry Best Practice | Additional hardening advice, defence-in-depth |

CLI: `--level SL1` (default), `--level SL2`, `--level BSG`, `--level BPR`,
`--level all`. Reports group findings by level.

## Phasing

### v0.1 — SL1 Audit + Harden (current)

- [x] `checks.json` — 16 SL1 check definitions with IEC clause mapping
- [x] `justin.py` — Finding class, colour, config parsing, argparse
- [x] Gather phase — call getters, build state dict
- [x] 16 check functions (one per check ID)
- [x] `audit_device()` — connect → gather → check → report
- [x] `harden_device()` — apply setters for failed checks
- [x] Fleet mode — `ThreadPoolExecutor` parallel audit
- [x] Interactive mode — guided audit + prompted hardening
- [x] Two-step — `--audit -o report.json` then `--harden --from-report`
- [x] Pretty report — results table + recommendations section
- [x] JSON output (`-j`) and report save (`-o`)
- [x] README.md + LOGIC.md
- [x] Incremental session log — JSON written on gather, updated on change
- [x] Dirty-config guard — refuse to harden unsaved switches
- [x] Before/after state capture + diff on harden
- [x] Watchdog rollback safety (`--watchdog SEC`)
- [x] Config backup capture before harden (`get_config()`)
- [x] Structured changes log — every setter call timestamped
- [x] Interactive wizard — CLAMPS-style setup, iterative REPL, watchdog option
- [x] Live test on .85 (factory defaults)
- [x] Fleet audit across .80/.81/.82/.85 + .4/.254/.239/.10 (8 devices, 11s)
- [ ] HTML report output (`-o report.html` or `--html`)
- [ ] Live harden on .85 + re-audit verification

### v0.2 — SL2 Checks

New driver methods needed: `get_password_policy()`, `set_password_policy()`,
`get_session_config()`, `set_session_config()`, `get_port_security()`,
`set_port_security()`, `get_dhcp_snooping()`, `set_dhcp_snooping()`,
`get_arp_inspection()`, `set_arp_inspection()`

- [ ] Password policy enforcement (complexity requirements)
- [ ] Session timeout configuration (CLI/web/SNMP)
- [ ] Industrial protocol hardening (EtherNet/IP, PROFINET, Modbus)
- [ ] IP access restriction review
- [ ] Port security (MAC limits)
- [ ] DHCP snooping (global + per-VLAN + trust)
- [ ] Dynamic ARP Inspection
- [ ] Login banner deployment

### v0.3 — Belden Security Guide (BSG)

Vendor-specific checks from the Belden/Hirschmann security manual
that go beyond IEC 62443. Map to ADAM's existing check set where
applicable.

- [ ] Import relevant ADAM checks (translate XML logic to getter logic)
- [ ] RSTP/MRP conflict detection (existing driver methods)
- [ ] VLAN PVID/egress mismatch
- [ ] Default community string detection
- [ ] Default hostname detection
- [ ] Edge loop protection advisory

### v0.4 — Best Practice + Advanced

Industry best practice, defence-in-depth, operational hygiene.

- [ ] SNMPv3 auth/encrypt quality (MD5→SHA, DES→AES)
- [ ] 802.1X / MAC authentication review
- [ ] IP Source Guard
- [ ] DoS protection status
- [ ] ACL builder (`--acl`) — interactive or intent-file-driven
- [ ] SNOOP validation loop (post-harden traffic verification)

### Future

- [ ] HTML report output (styled, printable, email-friendly)
- [ ] Compliance evidence export (PDF?)
- [ ] Hirschy integration tab (`tool-justin`)
- [ ] Drift detection (schedule → re-audit → alert on regression)
- [ ] POLO integration (harden as part of zero-touch commissioning)

## Driver Extension Needed for Full SL1

`get_services()` currently returns: http, https, ssh, telnet, snmp,
industrial. These additional fields are needed for full SL1 coverage:

| Field | Check |
|-------|-------|
| `unsigned_sw` | sec-unsigned-sw |
| `aca_auto_update` | sec-aca-auto-update |
| `aca_config_write` | sec-aca-config-write |
| `aca_config_load` | sec-aca-config-load |
| `devsec_monitors` | sec-devsec-monitors |
| `gvrp` / `mvrp` | ns-gvrp-mvrp |
| `gmrp` / `mmrp` | ns-gmrp-mmrp |

Until extended, these checks report "unable to assess" gracefully.

## Validation Loop

```
JUSTIN --harden → apply security config
  │
  ▼
SNOOP listens → observe actual traffic
  │
  ▼
JUSTIN --audit → verify compliance holds
  │
  ▼
Drift detected? → JUSTIN --harden again
```

## Config File

Same `script.cfg` format as all tools:

```ini
username = admin
password = private
protocol = mops

# Hardening targets
syslog_server = 10.0.0.100
syslog_port = 514
ntp_server = 10.0.0.1
banner = "Authorized access only."

192.168.60.80
192.168.60.81
192.168.60.82
192.168.60.85
```
