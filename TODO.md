# TODO

## 1.4.2 — MOPS driver integration + performance

- [x] Wire MOPS into HIOSDriver (`hios.py`): import, _try_connect, _get_active_connection, close()
- [x] Default protocol_preference: `['mops', 'snmp', 'ssh', 'netconf']`
- [x] All 31 dispatch checks updated: `('ssh', 'snmp')` → `('ssh', 'snmp', 'mops')`
- [x] Add RSTP dispatch methods: get_rstp, get_rstp_port, set_rstp, set_rstp_port
- [x] Strip MOPS set_mrp read-backs: removed initial get_mrp() check + final get_mrp() read-back
- [x] Strip MOPS delete_mrp read-back: removed final get_mrp() read-back
- [x] Strip MOPS set_rstp_port read-back: removed final get_rstp_port() read-back
- [x] Fix set_mrp tests to match new createAndWait-first flow
- [x] Remove premature test files (test_factory_reset.py, test_onboarding.py) — methods don't exist yet on SSH/SNMP
- [x] Add deploy_mrp tool: threaded MRP ring deployment + undeploy, MOPS/SNMP/SSH selectable
- [x] Unit tests: 306 passed, 0 failed (1 pre-existing ssh fixture error)

## 1.5.0 — Port admin control + RSTP on SNMP/SSH

- [ ] set_interface(interface, enabled, description) — port admin up/down
- [ ] Safe MRP deploy/undeploy: disable RM port2 → configure MRP → disable RSTP on ring ports → enable RM port2
- [ ] set_rstp_port / set_rstp / get_rstp / get_rstp_port on SNMP backend
- [ ] set_rstp_port / set_rstp / get_rstp / get_rstp_port on SSH backend
- [ ] Factory reset methods: clear_config(), clear_factory() on all protocols
- [ ] Factory onboarding: is_factory_default(), onboard() on SSH/SNMP backends

## Documentation update

- [x] vendor_specific.md — full rewrite: added Profiles, RSTP, Factory Onboarding, Factory Reset, MOPS Staging, Config Watchdog sections. Fixed intro (was SSH-only, now all 3 protocols). Updated all examples from `device.ssh.method()` to `device.method()`. Added redundancy warning to set_mrp/set_rstp, loop note to delete_mrp. Added blinking param to set_hidiscovery.
- [x] usage.md — full rewrite: added MOPS as default protocol, updated protocol_preference default order, added all vendor-specific read/write methods to Available Methods, updated Protocol Information section, fixed Best Practices (was SSH/SNMP-only), added config workflow methods.
- [ ] protocols.md — already up to date (has MOPS, full matrix, cross-protocol diffs)
- [ ] README.md — already up to date (has MOPS, full method lists, protocol table)

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

## Backburner

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The HiOS web UI (Industrial HiVision, MOPS) retrieves configuration via HTTPS/TLS, not SNMP — it uses a combination of HTTPS for config transfer and SNMP for individual value reads/writes. The running-config as a single retrievable object does not exist in any standard or private MIB.

A future approach could replicate the HTTPS mechanism: authenticate to the device's web interface and download the config XML directly, then present it through `get_config()`. This would require understanding the exact HTTPS endpoints and authentication flow. For now, `get_config()` remains SSH-only.
