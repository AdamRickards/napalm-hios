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

## Security Levels — `--level` Selector

Each check tagged with `source` (iec/vendor) and `sl` (1/2). CLI selects scope:

| Level | What Runs | Count | Use Case |
|-------|-----------|-------|----------|
| `sl1` | IEC 62443-4-2 SL1 checks | 16 | Minimum compliance baseline |
| `sl2` | SL1 + SL2 IEC checks | 17 | Certified SL-C 2 devices (BRS, GRS, MSP, OS3) |
| `vendor` | Vendor hardening guide checks | 20 | Belden best-practice audit |
| `sl1,vendor` | IEC SL1 + vendor | 36 | IEC baseline + vendor hardening |
| `sl2,vendor` | IEC SL2 + vendor | 37 | Full coverage for SL-C 2 devices |
| `highest` | Union of all | 37 | Everything — IEC SL2 + vendor |

SL3 excluded until deducible checks land (requires `get_users`,
`get_password_policy`). Currently sl3 == sl2 (zero additional checks).

CLI: `--level sl1` (default), `--level sl1,vendor`, `--level highest`.
Composable, comma-separated. Reports show level badge. `certs.json` maps family→cert→SL-C.

Source of truth: `local/reference/62443/iec_62443_4_2_justin.yaml` → derives `checks.json` + `certs.json`.

## v0.1 — SL1 Audit + Harden (shipped v1.16.2)

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
- [x] Live harden on .85 + re-audit verification (5/16 → 8/16, all 3 setters confirmed)
- [x] All SL1 `get_services()` fields (v1.16.2): `unsigned_sw`, `aca_auto_update`, `aca_config_write`, `aca_config_load`, `gvrp`, `mvrp`, `gmrp`, `mmrp`, `devsec_monitors`. 16/16 checks, 0 "unable to assess"
- [x] Hirschy integration tab (`tool-justin`) — shipped, deployed to Cloudflare

## v0.2 — SL2 + Vendor + DevSec (v1.17.0)

All three phases below are v1.17.0. Staged for context management, not artificial version boundaries.

---

### Phase 1 — JUSTIN tool changes (no driver work) ✓

Expand JUSTIN with existing driver methods. Pure tool-side work. **Complete.**

**`--level` selector + checks.json expansion:**

- [x] Add `--level` flag to argparse: composable comma-separated (`sl1`, `sl2`, `vendor`, `highest`)
- [x] Add new fields to every check in `checks.json`: `source` (iec/vendor), `sl` (1/2), `vendor_ref`, `evidence_key`, `fix_justin`/`fix_cli`/`fix_webui`/`fix_tool`
- [x] `filter_checks_by_level()` — composable filter, hierarchical SL collapse, only needed getters fire
- [x] Apply clause fixes: sec-time-sync→CR 2.11, sec-logging→CR 2.8, sec-mgmt-vlan→CR 5.1, sec-login-banner→CR 1.12
- [x] 18 vendor stub entries — "Not yet implemented" with required driver method listed

**3 new checks (existing getters, just needed check + harden functions):**

- [x] `sec-industrial-protocols` — `get_services()` profinet/modbus/ethernetip/iec61850. CR 7.7. Auto-fix
- [x] `ns-dos-protection` — `get_storm_control()`. CR 7.1. Advisory (site-specific thresholds)
- [x] `ns-lldp` — `get_lldp_neighbors()`. CR 7.7. Advisory (topology exposure)

**`certs.json` — runtime cert index:**

- [x] Derive from `local/reference/62443/certs.yaml` — family→cert→SL-C lookup
- [x] `load_certs()` + `resolve_cert()` — longest-prefix-match model→family
- [x] Console + HTML reports show cert line per device

**Remediation reference:**

- [x] `fix_justin` populated for all functional checks
- [x] `fix_cli` populated for functional checks (from `cli_ref_hios_merged.json`)
- [ ] `fix_webui`: navigation paths (user-supplied per check, not yet populated)
- [x] `fix_tool`: cross-tool refs where applicable (MOHAWC, VIKTOR)

**HTML report:**

- [x] Self-contained `.html` — JSON + certs embedded inline, zero deps
- [x] Detect format by `-o` extension (`.json` / `.html`)
- [x] Sections: header, cert context, score bar, checks table, evidence trail (collapsible), recommendations
- [x] `@media print` CSS for light-theme printing
- [x] Evidence Trail — click `[evidence]` to jump + expand getter data

**Evidence trail:**

- [x] `gather()` returns `(state, evidence)` — timestamped raw getter data
- [x] Each finding has `evidence_key` linking to its getter
- [x] Evidence embedded in JSON reports, HTML reports, and session logs

**Safety & hardening improvements:**

- [x] Configurable safety defaults in `parse_config()`: `dirty_guard`, `auto_save`, `snapshot`
- [x] Interactive Phase 0 SAFETY section — dirty guard / auto-save / snapshot mode
- [x] Pre/post NVM snapshots with collision avoidance
- [x] Post-snapshot escalating retry (0s → 5s → 7.5s → user prompt) for NVM settle
- [x] Snapshot name pairing — pre base name threaded to Phase 4 default

**Tagged output:**

- [x] `_log(tag, msg)` — `HH:MM:SS [TAG] message` on all operational lines
- [x] Tags: CONNECT, GATHER, CHECK, CONFIG, HARDEN, REGATHER, DIFF, SAVE, SNAPSHOT, WATCHDOG, SESSION
- [x] Report card display stays untagged

**Live testing (v0.2 Phase 1):**

- [x] Audit: sl1, sl2, vendor, sl1+vendor, highest — all correct check counts
- [x] Audit: case insensitive levels, invalid level error, unreachable device graceful failure
- [x] Fleet audit: 4 devices parallel, HTML + JSON reports with evidence
- [x] Harden: break/fix on .82 (HTTP, HiDiscovery, ACA) — dirty guard → save → harden → verify
- [x] Harden: sec-industrial-protocols on .82 (Modbus) — only disabled enabled protocols
- [x] Harden: --save, two-step (audit.json → harden from report)
- [x] Snapshot: pre+post with retry on .82 — both profiles created successfully

---

### Phase 2 — Driver getters/setters (napalm-hios v1.17.0)

New driver methods in `mops_hios.py`. Each one: find OIDs in MIBs → live query on .85 → write getter → write setter → live round-trip test → unit test.

**Simple scalars (quick wins):**

- [ ] `get_banner()` / `set_banner()` — pre-login banner text. CR 1.12
- [ ] `get_password_policy()` / `set_password_policy()` — complexity (upper/lower/digit/special/length). CR 1.7
- [ ] `get_session_config()` / `set_session_config()` — CLI/web/SNMP timeouts, max sessions. CR 2.6
- [ ] `get_signal_contact()` / `set_signal_contact()` — relay mode (manual/deviceState/deviceSecurity/both). CR 6.2
- [ ] `get_devsec_status()` — OperState (noerror/error) + StatusTable (violations with timestamps). CR 6.2

**Table-based:**

- [ ] `get_ip_restrict()` / `set_ip_restrict()` — management IP ACL (allowed source IPs/nets). CR 2.1
- [x] `get_port_security()` / `set_port_security()` / `add_port_security()` / `delete_port_security()` — MAC limit per-port, violation action, static MAC/IP CRUD. CR 7.1
- [ ] `get_poe()` / `set_poe()` — PoE global + per-port enable/disable. CR 7.7
- [ ] `get_dns()` — DNS client config (servers, domain). CR 7.7

**L2 security suite:**

- [x] `get_dhcp_snooping()` / `set_dhcp_snooping()` — global enable, per-VLAN, trust per-port. CR 3.1
- [x] `get_arp_inspection()` / `set_arp_inspection()` — DAI global + per-VLAN + trust per-port. CR 3.1
- [x] `get_ip_source_guard()` / `set_ip_source_guard()` — IPSG per-port. CR 3.1

**SNMP extensions:**

- [ ] `get_snmp_config()` extensions — v3 auth (MD5→SHA), v3 encrypt (DES→AES-128), v3 trap destinations. CR 4.3/6.2

**Remote auth:**

- [ ] `get_remote_auth()` — RADIUS/TACACS+/LDAP server config + live status. CR 1.1 SL2
  - LDAP: `hm2LdapClientServerStatus` = ok/unreachable/other per server
  - RADIUS: `hm2AgentRadiusServerCurrentMode` = yes/no, `rowStatus` = notReady on DNS fail
  - TACACS+: cmd authorization + accounting mode

**User CRUD:**

- [ ] `get_users()` / `set_user()` / `delete_user()` — local user account CRUD (admin/operator/guest). CR 1.5
  - Unlocks: sys-default-passwords auto-fix (change password, verify no factory creds)
  - Unlocks: CR 2.1 SL3 dual-control prerequisite (≥2 admin accounts)

---

### Phase 3 — JUSTIN integration + report (wire it all together)

Connect Phase 2 driver methods to JUSTIN check/harden functions. Build the report.

**New check functions (one per driver method):**

- [ ] `sec-login-banner` → `get_banner()`. CR 1.12. Harden: set banner text from config
- [ ] `sec-password-policy` → `get_password_policy()`. CR 1.7 SL2. Harden: set complexity requirements
- [ ] `sec-session-timeouts` → `get_session_config()`. CR 2.6. Harden: set idle timeouts
- [ ] `sec-ip-restrict` → `get_ip_restrict()`. CR 2.1. Advisory (site-specific ACL)
- [ ] `sec-snmpv3-auth` → `get_snmp_config()`. CR 4.3. Harden: SHA over MD5
- [ ] `sec-snmpv3-encrypt` → `get_snmp_config()`. CR 4.3. Harden: AES over DES
- [ ] `sec-snmpv3-traps` → `get_snmp_config()`. CR 6.2. Check v3 trap destinations exist
- [x] `ns-port-security` → `get_port_security()`. CR 7.1. Check implemented (detect only). Harden deferred: per-site MAC limit policy + AARON port classification needed
- [x] `ns-dhcp-snooping` → `get_dhcp_snooping()`. CR 3.1. Check implemented (detect only). Harden deferred: trust model planning needed
- [x] `ns-dai` → `get_arp_inspection()`. CR 3.1. Check implemented (detect only). Harden deferred: requires DHCP snooping + trust model planning
- [x] `ns-ipsg` → `get_ip_source_guard()`. CR 3.1. Check implemented (detect only). Harden deferred: requires DHCP snooping first
- [ ] `sec-poe` → `get_poe()`. CR 7.7. Advisory (review PoE on non-PoE-intended ports)
- [ ] `sec-dns-client` → `get_dns()`. CR 7.7. Advisory (review DNS config)
- [ ] `sys-default-passwords` upgrade → `get_users()`. CR 1.5. Harden: change password, delete factory accounts

**DevSec integration checks:**

- [ ] `sec-signal-contact` → `get_signal_contact()`. CR 6.2. Harden: set deviceSecurity(4). Report recommends physical + logical monitoring
- [ ] `sec-https-cert` → `get_devsec_status()` trap #23. CR 1.2. Advisory (self-signed warning)
- [ ] `sec-dev-mode` → `get_devsec_status()` trap #32. CR 7.7. Harden: disable dev mode
- [ ] `sec-secure-boot` → `get_devsec_status()` trap #31. CR 3.14. Advisory (HW dependent)
- [ ] DevSec meta-check: `hm2DevSecOperState == noerror` = device passes its own audit. Summary finding alongside JUSTIN's own checks
- [ ] Note: DevSec status only reports violations for ENABLED monitors. JUSTIN's own checks use dedicated getters (always complete). DevSec is post-harden cross-validation. Harden order: enable all monitors → fix violations → read status to confirm

**Deducible at SL3+ (partial coverage via inference):**

- [ ] CR 2.1 SL3 "dual control" → `get_users()`: ≥2 admin accounts = `partial`
- [ ] CR 1.7 SL3 "password lifetime" → `get_password_policy()`: expiry configured = `partial`
- [ ] CR 1.1 SL2 "multifactor auth" → `get_remote_auth()`: RADIUS/TACACS+ configured = `partial`
- [ ] CR 3.14 "boot integrity" → `get_devsec_status()`: secure boot enabled = `partial`

**Populate remediation reference:**

- [ ] WebUI paths for all checks (user-supplied walkthrough per check)
- [ ] CLI commands from `cli_ref_hios_merged.json` per check
- [ ] Cross-tool references (VIKTOR for VLAN, MOHAWC for commissioning, etc.)

**Testing:**

- [ ] Unit tests for all new driver methods (based on live data from .85)
- [ ] Live JUSTIN audit on .85 — 0 "unable to assess"
- [ ] Live JUSTIN harden on .85 — all auto-fixable checks remediated
- [ ] Re-audit after harden — score improvement + DevSec OperState noerror
- [ ] Full fleet audit across .80/.81/.82/.85
- [ ] `pytest tests/unit/ -v` — all pass

**Release:**

- [ ] Version bump + CHANGELOG + root TODO.md cleanup
- [ ] Generate patch, `git apply --check` on baseline
- [ ] Update README.md, LOGIC.md, vendor_specific docs
- [ ] Update Hirschy integration tab

---

## Future

- [ ] Compliance evidence export (PDF?)
- [ ] Drift detection (schedule → re-audit → alert on regression)
- [ ] POLO integration (harden as part of zero-touch commissioning)
- [ ] SNOOP validation loop (post-harden traffic verification)
- [ ] 802.1X / MAC authentication review
- [ ] ACL builder (`--acl`) — interactive or intent-file-driven
- [ ] OPC-UA integration — test if `hm2DevSecOperState` exposed natively, else `asyncua` bridge

## Vendor Hardening Guide Extras (v0.3+)

ADAM checks not mapped to IEC CRs, imported as `source: vendor`:

- [ ] RSTP/MRP conflict detection (existing driver methods)
- [ ] VLAN PVID/egress mismatch
- [ ] Default community string detection
- [ ] Default hostname detection
- [ ] Edge loop protection advisory

## Validation Loop

```
JUSTIN --harden → apply security config + enable DevSec monitors + signal contact
  │
  ├── Physical: fault LED / relay opens on violation (signal contact)
  ├── SNMP trap: hm2DevSecStateChangeTrap → SNOOP listener (port 162)
  ├── MOPS poll: get_devsec_status() on next --audit
  └── OPC-UA: subscription (if exposed natively, else asyncua bridge)
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
level = sl1,vendor

# Hardening targets
syslog_server = 10.0.0.100
syslog_port = 514
ntp_server = 10.0.0.1
banner = "Authorized access only."

# Safety settings (all optional — shown with defaults)
dirty_guard = true
auto_save = false
snapshot = off

192.168.60.80
192.168.60.81
192.168.60.82
192.168.60.85
```
