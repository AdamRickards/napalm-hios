# TODO

## Release Process Checklist

1. Pull clean from GitHub
2. TODO task tracking before touching code
3. Code changes
4. Test (`pytest tests/unit/ -v`)
5. Iterate until passing
6. Move completed TODO items into CHANGELOG
7. Version increment (semver: patch for bugfix, minor for features)
8. Documentation update (README, vendor_specific, usage, protocols — ALL of them)
9. Generate patch file
10. User deploys patch on live repo
11. Commit notes + release notes
12. User confirms live, does git commit/tag/push
13. Pull clean from GitHub
14. Pull from PyPI into test venv
15. Test PyPI-deployed version against local test environment
16. Done

## JUSTIN driver methods — IEC 62443-4-2 SL2+

Each getter/setter pair unlocks audit (gather) + remediation (harden) for the corresponding JUSTIN checks. Grouped by security level so they can ship incrementally. See [JUSTIN TODO](tools/justin/TODO.md) for check→fix mapping.

SL1 shipped in v1.16.0–v1.16.2: `get/set_services` (extended v1.16.2), `get/set_syslog`, `get/set_ntp`, `get/set_login_policy`, `get/set_snmp_config`, `set_access_port`, multi-protocol watchdog. Full SL1 JUSTIN coverage (16/16 checks, 14 auto-remediate).

### SL2 — advanced hardening (v1.17.0)

Builds on SL1. Deeper controls, per-port security features.

- [ ] `get_banner()` / `set_banner()` — pre-login banner text. **Unlocks**: sec-login-banner
- [ ] `get_password_policy()` / `set_password_policy()` — complexity requirements (upper, lower, digit, special, length). **Unlocks**: sec-password-policy
- [ ] `get_session_config()` / `set_session_config()` — CLI/web/SNMP session timeouts, max sessions. **Unlocks**: sec-session-timeouts
- [ ] `get_snmp_config()` extensions — v3 auth (MD5→SHA), v3 encrypt (DES→AES-128), v3 trap destinations. **Unlocks**: sec-snmpv3-auth, sec-snmpv3-encrypt, sec-snmpv3-traps
- [ ] `get_port_security()` / `set_port_security()` — MAC limit per-port, violation action. **Unlocks**: ns-port-security
- [ ] `get_dhcp_snooping()` / `set_dhcp_snooping()` — global enable, per-VLAN, trust per-port. **Unlocks**: ns-dhcp-snooping
- [ ] `get_arp_inspection()` / `set_arp_inspection()` — DAI global + per-VLAN + trust per-port. **Unlocks**: ns-dai
- [ ] `get_ip_source_guard()` / `set_ip_source_guard()` — IPSG per-port. **Unlocks**: ns-ipsg

### Fleet credential management (v1.18.0)

- [ ] `get_users()` / `set_user()` / `delete_user()` — local user account CRUD. Create/modify/delete user accounts with role (admin/operator/guest). **Unlocks**: JUSTIN fleet-wide credential management, sys-default-passwords remediation

## `get_services()` / `set_services()` extension

Extend to cover all SL1+SL2 service state. Selective query: pass field names to get/set only those, omit to get/set all. All fields are global (not per-port) booleans unless noted.

**API:**
```python
# Get everything (slow on SSH, atomic on SNMP/MOPS)
device.get_services()

# Get specific fields only
device.get_services('unsigned_sw', 'aca_auto_update')

# Set — unchanged, kwargs only
device.set_services(unsigned_sw=False, aca_auto_update=False)
```

**New fields needed** (verify each one live before implementing):

- [x] `unsigned_sw` — allow unsigned firmware upload. **Unlocks**: sec-unsigned-sw *(v1.16.2)*
- [x] `aca_auto_update` — ACA auto software load from ext NVM. **Unlocks**: sec-aca-auto-update *(v1.16.2)*
- [x] `aca_config_write` — ACA config save to ext NVM. **Unlocks**: sec-aca-config-write *(v1.16.2)*
- [x] `aca_config_load` — ACA config load from ext NVM (priority: first/second/third/disabled). **Unlocks**: sec-aca-config-load *(v1.16.2)*
- [x] `gvrp` — hardcoded False (legacy, no global toggle in HiOS MIBs). **Unlocks**: ns-gvrp-mvrp *(v1.16.2)*
- [x] `mvrp` — MVRP global enable. **Unlocks**: ns-gvrp-mvrp *(v1.16.2)*
- [x] `gmrp` — hardcoded False (legacy, no global toggle in HiOS MIBs). **Unlocks**: ns-gmrp-mmrp *(v1.16.2)*
- [x] `mmrp` — MMRP global enable. **Unlocks**: ns-gmrp-mmrp *(v1.16.2)*
- [x] `devsec_monitors` — bool, True when all 19 DevSec sense monitors enabled. **Unlocks**: sec-devsec-monitors *(v1.16.2)*
- [ ] `dos_protection` — dict of DoS mitigation filters (TCP/ICMP/L2/IP checks). **Unlocks**: ns-dos-protection (SL2)

## Vendor-specific methods (driver) — future

- [ ] Multi-get composition — `get_multi()` API that lets callers request multiple getters in one HTTP POST. Phase 0 gather (CLAMPS, VIKTOR, AARON) gets all facts in a single round-trip. Each additional safety check (SRM ports, VLAN egress, etc.) costs zero extra HTTP requests

## CLAMPS

See also: [`tools/clamps/TODO.md`](tools/clamps/TODO.md)

- [ ] Phase 0 staged getters — depends on driver multi-get composition. One HTTP POST for entire gather phase instead of 7. Every additional safety check (SRM ports, VLAN state, etc.) becomes free
- [ ] Zero-config discovery mode — LLDP-driven topology discovery
- [ ] `--gather` mode — Phase 0 only, read-only audit
- [ ] `-fi` support — read device list from [site index](tools/SITE_INDEX.md)
- [ ] Site index enrichment — write ring/protection state back to site.json

## AARON

- [ ] Auto-entry detection — `get_local_identity()` testing (direct, through unmanaged switch, multi-NIC, VPN adapters, cross-subnet)
- [ ] `--seed IP` — LLDP BFS crawl, creates [site index](tools/SITE_INDEX.md) in one pass

## VIKTOR

- [ ] `-fi` support — read device list from [site index](tools/SITE_INDEX.md)
- [ ] `--entry` topology-safe ordering — cross-tool build
- [ ] Management VLAN migration — furthest-first ordering, atomic entry switch config. See [VIKTOR TODO](tools/viktor/TODO.md) for full design
- [ ] QoS via naming convention — VLAN name prefix (`AC-`/`AM-`/`NM-`/`NC-`) = automatic QoS. `--names` + rename = instant fleet-wide QoS intent. See [VIKTOR TODO](tools/viktor/TODO.md) for full design
- [ ] L3 boundary DSCP mapping — auto-detect L3 hops that drop PCP, configure DSCP trust/remap. Strategy varies by SW level (L2A: edge ACL, L2S: upstream, L3: trust DSCP)

## MOHAWC

- [ ] `set-ip` subcommand — wraps `set_management(ip_address=, netmask=, gateway=)`. Driver method already exists
- [ ] `reboot` subcommand — cold/warm start, needs driver `cold_start()` / `warm_start()`
- [ ] `--tftp-pull <switch> <tftp-server> <config-file>` — force config pull, wraps `set_tftp()`. Used by [POLO](tools/polo/TODO.md) escalation

## Tool design docs

- [JUSTIN](tools/justin/TODO.md) — security audit + hardening, IEC 62443 SL1/SL2, ACL builder. ADAM but online
- [SNOOP](tools/snoop/TODO.md) — sFlow/syslog/traps passive listener, enrichment dicts, anomaly detection
- [VIKTOR](tools/viktor/TODO.md) — fleet VLAN provisioning, `-m` ring selector, audit, management VLAN migration
- [POLO](tools/polo/TODO.md) — dnsmasq registry, MARCO/POLO self-healing loop
- [BLIP](tools/blip/TODO.md) — zero-config multicast disruption probe, MARCO-discoverable Pi
- [Site Index](tools/SITE_INDEX.md) — shared `-fi` cross-tool JSON, master CLI, PyPI extras
- [Architecture](tools/ARCHITECTURE.md) — 8 key design insights

## QoS / TSN (future)

- [ ] TSN getters/setters — gate control lists, stream filters, PTP config, traffic scheduling. MOPS will have the OIDs (everything in HiOS backend is SNMP). Hard part is designing a sane abstraction over the MIB tables. **Unlocks**: NILS TSN enricher, deterministic scheduling config

## Offline Backend — Build Mode (`NEW`)

- [ ] `hostname='NEW'` (or similar) starts from factory-default template instead of empty data. Enables config generation from scratch via driver API: `create_vlan()`, `set_mrp()`, `set_qos()` → complete config XML ready to load onto a switch
- [ ] Copy minimal config template + XML-CONFIG-LOGIC.md research into `local/reference/`:
  - Template: `local/reference/XML/minimal-192_168_1_85.xml` (88 lines — 8 mandatory VACM entries, header, footer)
  - Research: `local/reference/XML/XML-CONFIG-LOGIC.md` (missing MIBs = factory defaults, VACM gate, checksum rules)
- [ ] Embed template in `offline_client.py` or load from package data — no external file dependency at runtime
- [ ] **Unlocks**: CLAMPS `--build configs/` (generate ring configs from script.cfg or interactive mode, no hardware needed), POLO zero-touch (generate configs from site templates), CLI→XML pipeline (Provize CLI output → driver API → config XML)

## Future — firmware update

- [ ] Firmware update: upload firmware image, trigger install + reboot

## SSH CLI State Machine

- [ ] CLI context navigator — track current mode (User → Privileged Exec → Global Config → Interface Range / VLAN Database) from prompt detection. Single `_ensure_context(mode, target=None)` replaces all `_config_mode()` / `self.cli('exit')` / `self.cli(f'interface {iface}')` patterns. Each setter declares what it needs, navigator handles transitions
- [ ] Wire up `local/reference/CLI/cli_ref_hios_merged.json` — 1,849 commands already have `mode` and `privilege` fields. Setter functions can look up required context from the JSON instead of hardcoding. New CLI features become: define command name → state machine handles navigation automatically
- [ ] Port loop optimisation — setters that loop over ports currently bounce in/out of interface mode per port. State machine stays in Interface Range and just switches ports. Fewer CLI round-trips on SSH

## Backburner

### MRP setter staging
`set_mrp()`, `delete_mrp()`, `set_mrp_sub_ring()`, `delete_mrp_sub_ring()` use multi-step RowStatus sequences (createAndWait → notInService → set values → active) with try/except. Each transition depends on the previous one completing, so they can't be batched into one `set_multi()`. Would need a different staging approach (e.g. ordered sub-batches). Low value — MRP config is infrequent and CLAMPS already parallelizes across devices.

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The running-config as a single retrievable object does not exist in any standard or private MIB. For now, `get_config()` remains SSH-only. See HTTPS config transfer below — that's the path forward.

