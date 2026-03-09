# JUSTIN — Justified Unified Security Testing for Industrial Networks

IEC 62443-4-2 security audit and hardening tool for Hirschmann HiOS switches.
Connects via napalm-hios, audits live device state against security baselines,
reports pass/fail with IEC clause references, and remediates findings.

ADAM audits offline configs. JUSTIN audits live devices and fixes them.

**Requires:** `napalm-hios >= 1.16.2`

## Quick Start

```bash
# Single device audit
justin --audit -d 192.168.1.4

# Fleet audit from config
justin --audit -c site.cfg

# Interactive (guided) mode
justin -i -d 192.168.1.4

# Save audit report
justin --audit -d 192.168.1.4 -o report.json

# Harden (dry-run first)
justin --harden -d 192.168.1.4 --dry-run
justin --harden -d 192.168.1.4 --commit
justin --harden -d 192.168.1.4 --commit --save

# Harden with watchdog rollback safety
justin --harden -d 192.168.1.4 --commit --watchdog 120

# Harden + save + named snapshot (MOPS only)
justin --harden -d 192.168.1.4 --commit --save --snapshot SL1-baseline

# Two-step: audit now, harden later
justin --audit -c site.cfg -o audit.json
justin --harden --from-report audit.json --commit --save --snapshot SL1

# JSON output
justin --audit -d 192.168.1.4 -j
```

## Modes

### Audit (`--audit`)

Read-only scan. Connects to device(s), gathers state via getters, runs
16 SL1 checks, prints a report card with IEC 62443-4-2 clause references.
No changes made to the device.

### Harden (`--harden`)

Audit + fix. Runs the same checks, then applies remediation for each
failed finding that has a corresponding setter. Dry-run by default —
must `--commit` to apply changes. Refuses to modify a switch with
unsaved config (dirty-config guard).

Add `--watchdog SEC` (30–600) to start a config watchdog timer before
applying changes. If anything goes wrong, the switch auto-reverts to
the last saved config when the timer expires. Stop is automatic on
success.

Add `--save` to save config to NVM after hardening. Add `--snapshot NAME`
(requires `--save`, MOPS only) to create a named NVM config profile as a
rollback point. Collision-avoidant — appends `-1`, `-2` if name exists.

### Interactive (`-i`)

Phased workflow: Phase 0 (setup) → Phase 1 (gather with live display) →
Phase 2 (review/select) → Phase 3 (execute fixes) → loop back to Phase 1.
Phase 4 is the exit gate: prompts to save to NVM and create a named
snapshot before allowing exit. See LOGIC.md for phase details.

### Two-Step (`--from-report`)

Separate the audit from the remediation:
1. Run `--audit -o report.json` to generate and review the report
2. Run `--harden --from-report report.json --commit` to apply fixes

## SL1 Checks (v0.1)

16 checks mapped to IEC 62443-4-2 Component Requirements:

| Check | Clause | What It Tests | Auto-Fix |
|-------|--------|--------------|----------|
| sec-hidiscovery | CR 7.7 | HiDiscovery disabled | Yes |
| sec-insecure-protocols | CR 4.1 | HTTP/Telnet disabled | Yes |
| sec-unsigned-sw | CR 3.4 | Reject unsigned firmware | * |
| sec-login-policy | CR 1.11 | Login lockout + min pw length | Yes |
| sec-time-sync | CR 6.1 | NTP configured | Yes |
| sec-logging | CR 6.1 | Syslog destination configured | Yes |
| sec-mgmt-vlan | CR 7.6 | Not on VLAN 1 | Advisory |
| sec-aca-auto-update | CR 3.4 | ACA auto-update disabled | * |
| sec-aca-config-write | CR 3.4 | ACA config write disabled | * |
| sec-aca-config-load | CR 3.4 | ACA config load disabled | * |
| sec-snmpv1-traps | CR 4.1 | SNMPv1 disabled | Yes |
| sec-snmpv1v2-write | CR 2.1 | No v1/v2 write communities | Yes |
| sec-devsec-monitors | CR 6.2 | All monitors enabled | * |
| sys-default-passwords | CR 1.5 | Not using admin/private | Advisory |
| ns-gvrp-mvrp | CR 7.7 | GVRP/MVRP disabled | * |
| ns-gmrp-mmrp | CR 7.7 | GMRP/MMRP disabled | * |

\* = Requires napalm-hios v1.16.2+ (`get_services()` extension)

## Protocol Support

| Protocol | Audit | Harden |
|----------|-------|--------|
| MOPS | Yes (recommended) | Yes |
| SNMP | Yes | Yes |
| SSH | Yes | Yes |

## Config File

Same `script.cfg` format as all tools, with JUSTIN-specific hardening targets:

```ini
username = admin
password = private
protocol = mops

# Hardening targets (used when applying fixes)
syslog_server = 10.0.0.100
syslog_port = 514
ntp_server = 10.0.0.1

192.168.60.80
192.168.60.81
192.168.60.82
192.168.60.85
```

## Session Log

Every run produces an incremental JSON session file in `output/`:
`justin_192-168-1-4_session_20260309_074240.json`. Written as data is
gathered and updated as changes are applied. Contains: device info,
full state before/after, all findings, every change made (with
timestamps), config status, watchdog state. Always leaves a paper trail.

## Report Output

Console output shows a per-clause results table followed by a
recommendations section. Reports can be saved as JSON (`-o`) for
archival, compliance evidence, or two-step hardening.

## See Also

- **LOGIC.md** — Phase lifecycle, architecture, IEC clause mapping, feature parity table
- **ADAM** (`tools/adam/`) — Offline config XML audit (predecessor)
- **tools/LOGIC.md** — Cross-tool driver method reference
