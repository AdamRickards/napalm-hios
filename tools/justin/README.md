# JUSTIN — Justified Unified Security Testing for Industrial Networks

IEC 62443-4-2 security audit and hardening tool for Hirschmann HiOS switches.
Connects via napalm-hios, audits live device state against composable security
levels, reports pass/fail with IEC clause references, and remediates findings.

ADAM audits offline configs. JUSTIN audits live devices and fixes them.

**Requires:** `napalm-hios >= 1.17.0`

## Quick Start

```bash
# Single device audit (IEC SL1 — default)
justin --audit -d 192.168.1.4

# Vendor hardening checks only
justin --audit -d 192.168.1.4 --level vendor

# IEC SL1 + vendor checks
justin --audit -d 192.168.1.4 --level sl1,vendor

# Everything (SL2 + vendor)
justin --audit -d 192.168.1.4 --level highest

# Fleet audit from config
justin --audit -c site.cfg

# Interactive (guided) mode
justin -i -d 192.168.1.4

# Save audit report (JSON or HTML)
justin --audit -d 192.168.1.4 -o report.json
justin --audit -d 192.168.1.4 -o report.html

# Harden (dry-run first)
justin --harden -d 192.168.1.4 --dry-run
justin --harden -d 192.168.1.4 --commit
justin --harden -d 192.168.1.4 --commit --save

# Harden with watchdog rollback safety
justin --harden -d 192.168.1.4 --commit --watchdog 120

# Harden + save + pre/post snapshots (MOPS only)
justin --harden -d 192.168.1.4 --commit --save --snapshot SL1-baseline

# Two-step: audit now, harden later
justin --audit -c site.cfg -o audit.json
justin --harden --from-report audit.json --commit --save --snapshot SL1

# JSON output
justin --audit -d 192.168.1.4 -j
```

## Security Levels (`--level`)

Composable, comma-separated levels. IEC SL levels are hierarchical (SL2
includes SL1). `vendor` adds Hirschmann Security Guide checks.

| Level | What | Checks |
|-------|------|--------|
| `sl1` | IEC 62443-4-2 SL1 (default) | 16 |
| `sl2` | IEC SL1 + SL2 | 18 |
| `vendor` | Vendor hardening guide only | 20 |
| `sl1,vendor` | IEC SL1 + vendor | 36 |
| `sl2,vendor` | IEC SL2 + vendor | 38 |
| `highest` | Everything | 38 |

Set in `script.cfg` with `level = sl1,vendor` — CLI `--level` overrides.
Interactive mode prompts for level during setup, showing `script.cfg` default.

## Modes

### Audit (`--audit`)

Read-only scan. Connects to device(s), gathers state via getters, runs
checks, prints a report card with IEC 62443-4-2 clause references.
No changes made to the device. Every getter result is timestamped and
included in the report as evidence.

### Harden (`--harden`)

Audit + fix. Runs the same checks, then applies remediation for each
failed finding that has a corresponding setter. Dry-run by default —
must `--commit` to apply changes. Refuses to modify a switch with
unsaved config (dirty-config guard — configurable).

Add `--watchdog SEC` (30–600) to start a config watchdog timer before
applying changes. If anything goes wrong, the switch auto-reverts to
the last saved config when the timer expires. Stop is automatic on
success.

Add `--save` to save config to NVM after hardening. Add `--snapshot NAME`
(requires `--save`, MOPS only) to create pre/post NVM config profiles:
`NAME-pre` before any changes, `NAME-post` after hardening. Collision-
avoidant — appends `-1`, `-2` if name exists.

### Interactive (`-i`)

Phased workflow: Phase 0 (setup + safety settings) → Phase 1 (gather
with live display) → Phase 2 (review/select) → Phase 3 (execute fixes)
→ loop back to Phase 1. Phase 4 is the exit gate: prompts to save to
NVM and create snapshots before allowing exit.

Phase 0 shows a SAFETY section with configurable defaults:
- **Dirty-config guard**: ON (default) — refuse to modify unsaved switches
- **Auto-save**: OFF (default) — prompt before saving to NVM
- **Snapshot**: off/post/pre+post — NVM profile creation mode

### Two-Step (`--from-report`)

Separate the audit from the remediation:
1. Run `--audit -o report.json` to generate and review the report
2. Run `--harden --from-report report.json --commit` to apply fixes

## Checks (v0.2)

### IEC 62443-4-2 — 20 checks (16 SL1 + 4 SL2) + cert-inherent checks

| Check | Clause | SL | What It Tests | Auto-Fix |
|-------|--------|----|--------------|----------|
| sec-hidiscovery | CR 7.7 | 1 | HiDiscovery disabled | Yes |
| sec-insecure-protocols | CR 4.1 | 1 | HTTP/Telnet disabled | Yes |
| sec-unsigned-sw | CR 3.4 | 1 | Reject unsigned firmware | Yes |
| sec-login-policy | CR 1.11 | 1 | Login lockout + min pw length | Yes |
| sec-time-sync | CR 2.11 | 1 | NTP configured | Yes |
| sec-logging | CR 2.8 | 1 | Syslog destination configured | Yes |
| sec-mgmt-vlan | CR 5.1 | 1 | Not on VLAN 1 | Advisory |
| sec-aca-auto-update | CR 3.4 | 1 | ACA auto-update disabled | Yes |
| sec-aca-config-write | CR 3.4 | 1 | ACA config write disabled | Yes |
| sec-aca-config-load | CR 3.4 | 1 | ACA config load disabled | Yes |
| sec-snmpv1-traps | CR 4.1 | 1 | SNMPv1 disabled | Yes |
| sec-snmpv1v2-write | CR 2.1 | 1 | No v1/v2 write communities | Yes |
| sec-devsec-monitors | CR 6.2 | 1 | All monitors enabled | Yes |
| sys-default-passwords | CR 1.5 | 1 | Not using admin/private | Yes |
| ns-gvrp-mvrp | CR 7.7 | 1 | GVRP/MVRP disabled | Yes |
| ns-gmrp-mmrp | CR 7.7 | 1 | GMRP/MMRP disabled | Yes |
| sec-password-policy | CR 1.7 | 2 | Password complexity rules | Yes |
| sec-user-review | CR 1.3 | 2 | Account lifecycle review | Advisory |
| sec-user-roles | CR 2.1 | 2 | RBAC role diversity | Check only |
| sec-console-port | EDR 2.13 | 2 | Console timeout + ENVM disabled | Yes |

### Vendor hardening — 20 checks

| Check | Clause | What It Tests | Status |
|-------|--------|--------------|--------|
| sec-industrial-protocols | CR 7.7 | Industrial protocols disabled | **Functional** (auto-fix) |
| ns-dos-protection | CR 7.1 | Storm control configured | **Functional** (advisory) |
| ns-lldp | CR 7.7 | LLDP topology exposure | **Functional** (advisory) |
| sec-login-banner | CR 1.12 | Login banner configured | **Functional** (auto-fix) |
| sec-session-timeouts | CR 2.6 | Idle session timeouts | **Functional** (auto-fix) |
| sec-ip-restrict | CR 2.1 | IP access restriction | **Functional** (auto-fix) |
| sec-snmpv3-auth | CR 4.3 | SNMPv3 authentication | **Functional** (auto-fix) |
| sec-snmpv3-encrypt | CR 4.3 | SNMPv3 encryption | **Functional** (auto-fix) |
| sec-snmpv3-traps | CR 6.2 | SNMPv3 trap receiver | **Functional** (auto-fix) |
| sec-poe | CR 7.7 | PoE disabled on unused ports | **Functional** (auto-fix) |
| sec-dns-client | CR 7.7 | DNS client disabled | **Functional** (auto-fix) |
| sec-signal-contact | CR 6.2 | Signal contact monitoring | **Functional** (auto-fix) |
| sec-https-cert | CR 1.2 | Device-specific HTTPS cert | **Functional** (check only) |
| sec-dev-mode | CR 7.7 | Debug mode disabled | **Functional** (check only) |
| sec-secure-boot | CR 3.14 | Secure boot enabled | **Functional** (check only) |
| sec-concurrent-sessions | CR 2.7 | Max concurrent sessions | **Functional** (auto-fix) |
| sec-crypto-ciphers | CR 4.3 | TLS 1.2+, no RC4/DSA/SHA1-RSA | **Functional** (auto-fix) |
| sec-remote-auth | CR 1.1 | Remote auth configured | **Functional** (check only) |
| ns-port-security | CR 7.1 | MAC limiting on access ports | **Functional** (check only) |
| ns-dhcp-snooping | CR 3.1 | DHCP snooping enabled | **Functional** (check only) |
| ns-dai | CR 3.1 | Dynamic ARP Inspection | **Functional** (check only) |
| ns-ipsg | CR 3.1 | IP Source Guard | **Functional** (check only) |
| sec-unused-ports | CR 7.7 | Unused ports admin-disabled | **Functional** (check only) |

## Evidence Trail

Every audit embeds timestamped evidence — the raw getter data each check
was evaluated against. Reports include an `evidence` section mapping each
getter to its gathered timestamp and full return value.

HTML reports render this as a collapsible Evidence Trail section. Each
check row links to its evidence block — click `[evidence]` to jump to
and auto-expand the getter data. Multiple checks sharing the same getter
(e.g., 11 checks use `get_services()`) link to one evidence block.

This means every PASS and every FAIL can be traced back to the exact
device state that produced it. No conclusions without receipts.

## IEC 62443 Certification Context

`certs.json` maps device families to their IEC 62443-4-2 certification:

| Family | Certificate | SL-C | Valid Until |
|--------|------------|------|------------|
| BRS, BXS | 968/CSP 1040.00/25 | 2 | 2030-07-17 |
| GRS10x, GRS1042 | 968/CSP 1042.00/25 | 2 | 2030-09-10 |
| RSP, RSPE, OS | 968/CSP 1056.00/25 | 1 | 2030-10-29 |
| MSP, OS3, BXP | 968/CSP 1057.00/25 | 2 | 2030-10-29 |
| EAGLE40 | 968/CSA 1002.00/22 | 1 | — (HiSecOS) |
| DRAGON | — | — | Uncertified |

Cert info is shown in console reports and embedded in HTML reports.
Model matching uses wildcard resolution (`GRS10x` matches GRS1020–GRS1030).

## Safety

JUSTIN measures twice, cuts once. Three layers of protection:

1. **Dirty-config guard** — refuses to harden a switch with unsaved
   changes (won't destroy in-progress work). Configurable: `dirty_guard = false`
2. **Watchdog rollback** — config timer auto-reverts if anything goes
   wrong mid-harden (`--watchdog 120`)
3. **Pre/post snapshots** — named NVM profiles before AND after hardening
   (`--snapshot SL1-baseline` creates `SL1-baseline-pre` + `SL1-baseline-post`).
   Post-snapshot uses escalating retry (0s → 5s → 7.5s → user prompt) to
   handle NVM settle time after save

## Report Output

Console output shows a per-clause results table followed by a
recommendations section. Reports can be saved as:

- **JSON** (`-o report.json`) — archival, compliance evidence, two-step hardening.
  Includes full evidence trail with timestamped getter data.
- **HTML** (`-o report.html`) — self-contained, dark theme, `@media print` for
  light printing. Evidence Trail section with collapsible getter data, linked
  from every check result.

HTML reports embed all data inline — no external dependencies. Open in
any browser. Print to PDF for compliance documentation.

## Protocol Support

| Protocol | Audit | Harden | Snapshot |
|----------|-------|--------|----------|
| MOPS | Yes (recommended) | Yes | Yes |
| SNMP | Yes | Yes | No |
| SSH | Yes | Yes | No |

## Config File

Same `script.cfg` format as all tools, with JUSTIN-specific keys:

```ini
username = admin
password = private
protocol = mops
level = sl1,vendor

# Hardening targets (used when applying fixes)
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

`level` in script.cfg is used by all modes (CLI, fleet, interactive).
CLI `--level` overrides the config value. Safety settings (`dirty_guard`,
`auto_save`, `snapshot`) are read from script.cfg and shown as defaults
in interactive mode's SAFETY section.

## Tagged Output

All operational progress lines use timestamped phase tags:

```
  04:27:40 [CONNECT] 192.168.60.85
  04:27:43 [GATHER] get_hidiscovery() ...
  04:27:43 [GATHER] get_login_policy() ...
  04:27:51 [CHECK sec-hidiscovery] CR 7.7 Least functionality
  04:27:51 [CHECK sec-insecure-protocols] CR 4.1 Communication confidentiality
```

| Tag | When |
|-----|------|
| `[CONNECT]` | Device connection |
| `[GATHER]` | Getter calls + warnings |
| `[CHECK <id>]` | Each check evaluation |
| `[CONFIG]` | Config status / dirty-guard |
| `[HARDEN <id>]` | Fix application per check |
| `[REGATHER]` | Post-harden re-gather |
| `[DIFF]` | Before/after state diff |
| `[SAVE]` | NVM save |
| `[SNAPSHOT]` | NVM profile creation |
| `[WATCHDOG]` | Watchdog start/stop |
| `[SESSION]` | Session log path + timing |

Report card display (the boxed table, score bar, recommendations) stays
untagged — clean for compliance screenshots.

## Session Log

Every run produces an incremental JSON session file in `output/`:
`justin_192-168-1-4_session_20260309_074240.json`. Written as data is
gathered and updated as changes are applied. Contains: device info,
full state before/after, all findings, every change made (with
timestamps), config status, watchdog state, snapshot records.
Always leaves a paper trail.

## See Also

- **LOGIC.md** — Phase lifecycle, architecture, IEC clause mapping, feature parity table
- **ADAM** (`tools/adam/`) — Offline config XML audit (predecessor)
- **tools/LOGIC.md** — Cross-tool driver method reference
