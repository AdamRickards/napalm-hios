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

## Vendor-specific methods (driver)

- [ ] `get_vlan_egress()` should include VLANs with zero port membership — currently all three backends (MOPS line 1315, SSH line 2530, SNMP line 1339) skip VLANs where `port_modes` is empty. The data is there from the MIB/CLI, the driver just drops it. Fix: always include the VLAN with an empty ports dict. Discovered via VIKTOR `vlan list` not showing freshly-created VLANs until a port is assigned
- [ ] `set_mrp()` advanced_mode parameter — `get_mrp()` returns `advanced_mode` (OID `hm2MrpMRMReactOnLinkChange`) but `set_mrp()` doesn't accept it. Despite the "MRM" in the OID name, this applies to ALL ring participants. More critical on clients than the manager — enables link-down detection on RCs so they immediately signal the MRM to start recovery, dramatically faster failover in Hirschmann-only rings. Currently defaults to True on 10.3.04 but should be explicitly settable
- [ ] `set_access_port(port(s), vlan_id)` — atomic access mode change via MOPS `set_multi`. Reads VLAN table + ifIndex, then in a single POST: add untagged on new VLAN, remove from old VLAN(s), set PVID. Currently VIKTOR does this as staged egress + separate PVID call (two round-trips, measurable blip). Same function design should accommodate management VLAN migration: egress + PVID + management VLAN ID all in one atomic set. MOPS-only (SSH/SNMP fall back to current multi-call approach). Benchmark improvement with [BLIP](tools/blip/TODO.md). **Mirror**: VIKTOR TODO in `tools/viktor/TODO.md` — update both when complete
- [ ] Multi-get composition — `get_multi()` API that lets callers request multiple getters in one HTTP POST. Phase 0 gather (CLAMPS, VIKTOR, AARON) gets all facts in a single round-trip. Each additional safety check (SRM ports, VLAN egress, etc.) costs zero extra HTTP requests
- [ ] `get_tftp()` / `set_tftp()` — TFTP config management. Two functions: manual config pull from TFTP server, and enable/disable auto-backup on save. **Unlocks**: [POLO](tools/polo/TODO.md), MOHAWC `--tftp-pull`
- [ ] `get_syslog()` / `set_syslog()` — syslog server config (destination IP/port, severity filter, facility). MOPS + SNMP, SSH stub. **Unlocks**: [SNOOP](tools/snoop/TODO.md) syslog listener, fleet-wide log aggregation
- [ ] `get_users()` / `set_user()` / `delete_user()` — local user account CRUD. Create/modify/delete user accounts with role (admin/operator/guest). **Unlocks**: fleet-wide credential management, audit-ready accounts (e.g. per-tool service accounts)

## CLAMPS

See also: [`tools/clamps/TODO.md`](tools/clamps/TODO.md)

- [x] MOPS staging on setup workers — `worker_setup_rstp_full`, `worker_setup_loop_protection`, `worker_setup_auto_disable` batch all mutations into one atomic POST per device. Teardown workers intentionally not staged (order > speed)
- [x] Multi-interface setters — all workers pass lists instead of per-port loops. Combined with staging: 31.3s → 11.1s (65% faster, 4 BRS50 devices)
- [x] SRM-aware ring port map — phase 0 discovers sub-ring ports via `get_mrp_sub_ring()`, merges into ring_ports_map. Prevents edge protection (BPDU Guard, loop detection) from targeting sub-ring ports
- [x] `cpu/1` and `vlan/N` filtered from `all_ports` — fixes `noCreation` error on non-switchports via MOPS/SNMP
- [ ] Phase 0 staged getters — depends on driver multi-get composition. One HTTP POST for entire gather phase instead of 7. Every additional safety check (SRM ports, VLAN state, etc.) becomes free
- [ ] Zero-config discovery mode — LLDP-driven topology discovery
- [ ] `--gather` mode — Phase 0 only, read-only audit
- [ ] `-fi` support — read device list from [site index](tools/SITE_INDEX.md)
- [ ] Site index enrichment — write ring/protection state back to site.json

## AARON

- [ ] Auto-entry detection — `get_local_identity()` testing (direct, through unmanaged switch, multi-NIC, VPN adapters, cross-subnet)
- [ ] `--seed IP` — LLDP BFS crawl, creates [site index](tools/SITE_INDEX.md) in one pass

## VIKTOR

- [x] v1.0 — `vlan list/create/delete/rename`, `access`, `trunk`, `auto-trunk`, `--audit`, `--names`, `--export`, `--import`, `-m` ring selector
- [ ] `-fi` support — read device list from [site index](tools/SITE_INDEX.md)
- [ ] `--entry` topology-safe ordering — cross-tool build
- [ ] Management VLAN migration — furthest-first ordering, atomic entry switch config. See [VIKTOR TODO](tools/viktor/TODO.md) for full design
- [ ] QoS via naming convention — VLAN name prefix (`AC-`/`AM-`/`NM-`/`NC-`) = automatic QoS. `--names` + rename = instant fleet-wide QoS intent. See [VIKTOR TODO](tools/viktor/TODO.md) for full design
- [ ] L3 boundary DSCP mapping — auto-detect L3 hops that drop PCP, configure DSCP trust/remap. Strategy varies by SW level (L2A: edge ACL, L2S: upstream, L3: trust DSCP)

## MOHAWC

- [ ] `set-ip` subcommand — wraps `set_management(ip_address=, netmask=, gateway=)`
- [ ] `reboot` subcommand — cold/warm start, needs driver `cold_start()` / `warm_start()`
- [ ] `--tftp-pull <switch> <tftp-server> <config-file>` — force config pull, wraps `set_tftp()`. Used by [POLO](tools/polo/TODO.md) escalation

## Tool design docs

- [SNOOP](tools/snoop/TODO.md) — sFlow/syslog/traps passive listener, enrichment dicts, anomaly detection
- [VIKTOR](tools/viktor/TODO.md) — fleet VLAN provisioning, `-m` ring selector, audit, management VLAN migration
- [POLO](tools/polo/TODO.md) — dnsmasq registry, MARCO/POLO self-healing loop
- [Site Index](tools/SITE_INDEX.md) — shared `-fi` cross-tool JSON, master CLI, PyPI extras
- [Architecture](tools/ARCHITECTURE.md) — 8 key design insights

## QoS / TSN (future)

- [x] `get_qos()` / `set_qos()` — per-port trust mode, queue scheduling, shaping rate. All 3 protocols
- [x] `get_qos_mapping()` / `set_qos_mapping()` — global dot1p→TC and DSCP→TC mappings. All 3 protocols
- [x] `get_management_priority()` / `set_management_priority()` — management frame priority (dot1p + ip-dscp). All 3 protocols
- [x] `get_storm_control()` / `set_storm_control()` — per-port broadcast/multicast/unicast ingress rate limiting. All 3 protocols
- [ ] TSN getters/setters — gate control lists, stream filters, PTP config, traffic scheduling. MOPS will have the OIDs (everything in HiOS backend is SNMP). Hard part is designing a sane abstraction over the MIB tables. **Unlocks**: NILS TSN enricher, deterministic scheduling config

## CLI Reference Data

Already parsed in `HiOS-Config-Utility/` — 1,849 commands across 4 HiOS versions (9.0, 9.2, 10.0, 10.3). Parser: `parse_cli_ref.py`, merged: `cli_ref_hios_merged.json`. Per-command: section, chapter, command, mode, privilege, format, no-form, params, `_since` version.

- [x] `local/cli_ref_hios_merged.json` — 1,849 commands, 4 versions (9.0–10.3), version-aware `_since` field. Source: `HiOS-Config-Utility/cli_ref_hios_merged.json`. `local/` is gitignored

## Future — Config import/export + firmware update

- [ ] Config export: download running config as XML/profile via MOPS HTTPS endpoints
- [ ] Config import: upload profile/XML to device, activate as running config
- [ ] Firmware update: upload firmware image, trigger install + reboot

## Backburner

### MRP setter staging
`set_mrp()`, `delete_mrp()`, `set_mrp_sub_ring()`, `delete_mrp_sub_ring()` use multi-step RowStatus sequences (createAndWait → notInService → set values → active) with try/except. Each transition depends on the previous one completing, so they can't be batched into one `set_multi()`. Would need a different staging approach (e.g. ordered sub-batches). Low value — MRP config is infrequent and CLAMPS already parallelizes across devices.

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The running-config as a single retrievable object does not exist in any standard or private MIB. Future approach: replicate the HTTPS mechanism (authenticate to web interface, download config XML). For now, `get_config()` remains SSH-only.
