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

## MOPS staging — wire into vendor setters

The primitive exists: `mops_client.set_multi()` batches N mutations into one atomic HTTP POST. The staging infrastructure exists on `MOPSHIOS` (`start_staging` / `commit_staging` / `discard_staging` / `get_staged_mutations`). But no setter checks the `_staging` flag — every `set_*()` fires immediately.

- [ ] **Multi-interface setters**: extend per-port setters to accept a list of interfaces, build mutations internally, fire one `set_multi()` POST. Immediate efficiency win without staging complexity. Candidates: `set_rstp_port`, `set_auto_disable`, `reset_auto_disable`, `set_vlan_ingress`, `set_vlan_egress`, `set_loop_protection`, `set_interface`
- [ ] Make every MOPS setter staging-aware: check `self._staging`, append mutation tuple to `self._mutations` instead of calling `client.set()`/`set_indexed()` directly
- [ ] Expose staging on `HIOSDriver` dispatcher: `device.start_staging()` → routes to `mops.start_staging()`, SNMP raises `NotImplementedError`, SSH N/A (already has `load_merge_candidate`)
- [ ] Handle setters that do read-after-write (e.g. `set_mrp()` reads back state after SET) — in staging mode, skip the read-back and return `None` or similar
- [ ] Handle setters that do multi-step writes (e.g. `set_mrp()` does multiple `set_indexed()` calls) — all steps go into `_mutations`, committed together
- [ ] Handle `save_config()` interaction — `commit_staging()` already calls `save_config()`, so individual setters shouldn't save during staging
- [ ] Update CLAMPS to use `device.start_staging()` / `device.commit_staging()` per phase (~430 → ~82 HTTP requests)
- [ ] Unit tests for staging: setter in staging mode queues, commit fires one `set_multi()`, discard clears
- [ ] Live test: `start_staging()` → multiple `set_*()` calls → `commit_staging()` → verify device state matches
- [ ] Benchmark before/after: time CLAMPS per-device operation chain with per-POST timing. CLAMPS already parallelizes across devices (ThreadPoolExecutor), so wall-clock is bounded by the slowest device's sequential POSTs. Staging cuts per-device chains from ~N POSTs/phase to ~1 POST/phase. Measure per-device time reduction on live hardware

## MOPS getter consolidation — reduce HTTP POSTs per getter

`mops_client.get_multi()` already batches multiple MIB queries into one POST. Several getters call `get()` multiple times when they could use a single `get_multi()`. Pure internal refactor, no API change.

- [ ] `get_facts()`: 3 POSTs → 1. Merge HM2-DEVMGMT-MIB product desc + serial + firmware version table into the existing `get_multi` with SNMPv2-MIB + IF-MIB
- [ ] `get_environment()`: 3 POSTs → 1. Merge PSU (HM2-PWRMGMT-MIB) + fans (HM2-FAN-MIB) into the existing `get_multi` with temp + CPU + memory
- [ ] `get_lldp_neighbors_detail()`: 2 POSTs → 1. Merge lldpRemEntry + lldpRemManAddrEntry + ifindex into one `get_multi` (like `get_lldp_neighbors_detail_extended` already does)
- [ ] `get_mrp_sub_ring()`: 2 POSTs → 1. Merge hm2SrmMibGroup + hm2SrmEntry into one `get_multi`
- [ ] Consider merging `_build_ifindex_map()` fetch into each getter's own `get_multi` to eliminate cold-cache penalty (11 getters affected). Trade-off: slightly larger POSTs vs always-warm cache
- [ ] Benchmark before/after: time each consolidated getter on live device. ~500ms RTT, so `get_facts` 3→1 POST = ~1s saved, `get_environment` 3→1 = ~1s saved. Measure real improvement

## Vendor-specific methods (driver)

- [ ] `get_sflow()` / `set_sflow()` — global sFlow config + per-port sampling. MIBs: SFLOW-MIB (RFC 3176) + HM2-PLATFORM-SFLOW-MIB. MOPS + SNMP, SSH stub. **Unlocks**: [SNOOP](tools/snoop/TODO.md)
- [ ] `get_tftp()` / `set_tftp()` — TFTP config management. Two functions: manual config pull from TFTP server, and enable/disable auto-backup on save. **Unlocks**: [POLO](tools/polo/TODO.md), MOHAWC `--tftp-pull`

## CLAMPS

See also: [`tools/clamps/TODO.md`](tools/clamps/TODO.md)

- [ ] MOPS staging/commit for performance — depends on driver staging TODO above (one commit per phase, not per-port → ~80% reduction in HTTP requests)
- [ ] Zero-config discovery mode — LLDP-driven topology discovery
- [ ] `--gather` mode — Phase 0 only, read-only audit
- [ ] `-fi` support — read device list from [site index](tools/SITE_INDEX.md)
- [ ] Site index enrichment — write ring/protection state back to site.json

## AARON

- [ ] Auto-entry detection — `get_local_identity()` testing (direct, through unmanaged switch, multi-NIC, VPN adapters, cross-subnet)
- [ ] `--seed IP` — LLDP BFS crawl, creates [site index](tools/SITE_INDEX.md) in one pass

## MOHAWC

- [ ] `set-ip` subcommand — needs driver `set_management_ip()` or similar
- [ ] `reboot` subcommand — cold/warm start, needs driver `cold_start()` / `warm_start()`
- [ ] `--tftp-pull <switch> <tftp-server> <config-file>` — force config pull, wraps `set_tftp()`. Used by [POLO](tools/polo/TODO.md) escalation

## Tool design docs

- [SNOOP](tools/snoop/TODO.md) — sFlow/syslog/traps passive listener, enrichment dicts, anomaly detection
- [VIKTOR](tools/viktor/TODO.md) — fleet VLAN provisioning, `-m` ring selector, audit, management VLAN migration
- [POLO](tools/polo/TODO.md) — dnsmasq registry, MARCO/POLO self-healing loop
- [Site Index](tools/SITE_INDEX.md) — shared `-fi` cross-tool JSON, master CLI, PyPI extras
- [Architecture](tools/ARCHITECTURE.md) — 8 key design insights

## CLI Reference Parser

- [ ] Parse `local/RM_CLI_HiOS-10300_Overview_en.pdf` (500+ pages) into structured JSON
- [ ] Per-command metadata: section, title, page, command string, mode, privilege level, negate form, params
- [ ] Output: `local/cli_reference.json` — speeds up all future SSH backend work

## Future — Config import/export + firmware update

- [ ] Config export: download running config as XML/profile via MOPS HTTPS endpoints
- [ ] Config import: upload profile/XML to device, activate as running config
- [ ] Firmware update: upload firmware image, trigger install + reboot

## Backburner

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The running-config as a single retrievable object does not exist in any standard or private MIB. Future approach: replicate the HTTPS mechanism (authenticate to web interface, download config XML). For now, `get_config()` remains SSH-only.
