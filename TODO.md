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

- [ ] `get_sflow()` / `set_sflow()` — global sFlow config + per-port sampling. MIBs: SFLOW-MIB (RFC 3176) + HM2-PLATFORM-SFLOW-MIB. MOPS + SNMP, SSH stub. **Unlocks**: [SNOOP](tools/snoop/TODO.md)
- [ ] `get_tftp()` / `set_tftp()` — TFTP config management. Two functions: manual config pull from TFTP server, and enable/disable auto-backup on save. **Unlocks**: [POLO](tools/polo/TODO.md), MOHAWC `--tftp-pull`

## CLAMPS

See also: [`tools/clamps/TODO.md`](tools/clamps/TODO.md)

- [ ] MOPS staging/commit for performance — staging infrastructure ready in driver (v1.9.0). One commit per phase, not per-port → ~80% reduction in HTTP requests
- [ ] Benchmark before/after: time CLAMPS per-device operation chain. Staging cuts per-device chains from ~N POSTs/phase to ~1 POST/phase
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

### MRP setter staging
`set_mrp()`, `delete_mrp()`, `set_mrp_sub_ring()`, `delete_mrp_sub_ring()` use multi-step RowStatus sequences (createAndWait → notInService → set values → active) with try/except. Each transition depends on the previous one completing, so they can't be batched into one `set_multi()`. Would need a different staging approach (e.g. ordered sub-batches). Low value — MRP config is infrequent and CLAMPS already parallelizes across devices.

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The running-config as a single retrievable object does not exist in any standard or private MIB. Future approach: replicate the HTTPS mechanism (authenticate to web interface, download config XML). For now, `get_config()` remains SSH-only.
