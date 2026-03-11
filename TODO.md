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

## JUSTIN — shipped

SL1 shipped in v1.16.0–v1.16.2. SL2 + vendor shipped in v1.17.0. 47/47 checks wired, 34/47 hardens wired (6 detect-only, 3 advisory, 4 cert = cannot harden by design). See CHANGELOG.md for full details and [JUSTIN TODO](tools/justin/TODO.md) for future work.

**Deducible at higher SLs (partial coverage via inference):**

- CR 2.1 SL3 "dual control for critical functions" → `get_users()`: ≥2 admin accounts = partial pass
- CR 1.7 SL3 "password min/max lifetime" → `get_login_policy()`: check expiry config exists = partial pass
- CR 1.1 SL2 "multifactor auth" → `get_remote_auth()`: RADIUS/TACACS+ configured = partial
- CR 3.14 "boot integrity" → `get_devsec_status()`: secure boot status

## `get_services()` / `set_services()` extension

- [ ] `dos_protection` — dict of DoS mitigation filters (TCP/ICMP/L2/IP checks). **Unlocks**: ns-dos-protection

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

### RowStatus table CRUD verb homogenization
Three different verbs for the same operation: `create_vlan()`, `add_dns_server()`, `set_user()` — all RowStatus table row CRUD. Pick one pattern (`add`/`delete`) and alias the old names for backwards compat. Breaking change — needs a major version or deprecation cycle. Affects: `create_vlan`→`add_vlan`, `update_vlan`→`set_vlan`, `set_user`→`add_user` (or keep `set_user` since it also updates). Audit all table CRUD methods and unify.

### ACL / Firewall rules (2.0.0)
`get_acl()` / `set_acl()` — L2/L3/L4 traffic ACLs (QoS ACL MIB: `HM2-PLATFORM-QOS-ACL-MIB`) + packet filter firewall rules (`HM2-FW-MIB`). Rule tables with match criteria, actions (permit/deny/redirect/mirror), per-port binding, ordering. More powerful than port-security for network integrity but complex driver surface. Maps to IEC 62443 CR 5.1/5.2 (network segmentation / zone boundary protection) at SL2+. In 2.0.0 YAML engine refactor, support both HiOS and HiSecOS (EAGLE40 firewall) with auto command selection where they differ.

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The running-config as a single retrievable object does not exist in any standard or private MIB. For now, `get_config()` remains SSH-only. See HTTPS config transfer below — that's the path forward.

