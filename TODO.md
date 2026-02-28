# TODO

## Documentation update

- [x] README.md — updated: added auto-disable + loop protection to features + method lists, updated test count

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

## AARON — auto-entry detection

Local machine identity detection added (`get_local_identity()`): detects own IP via socket + own MACs via `/sys/class/net/*/address` (Linux) or `getmac` (Windows). Injects into ARP map so the scanning machine resolves on its edge port.

Testing needed for auto-entry reliability:
- [ ] Basic test: laptop plugged directly into managed switch — does it find itself on an edge port?
- [ ] Through unmanaged switch: laptop behind dumb switch — does it find itself on an indirect port?
- [ ] Multiple NICs: laptop with WiFi + Ethernet — does it match the right MAC (the one on the switch network)?
- [ ] VPN/virtual adapters: do extra MACs from VPN/Docker/WSL cause false matches?
- [ ] Cross-subnet: laptop on different VLAN/subnet from switch management — does socket trick still find the right IP?
- [ ] Auto-entry: once we can reliably find our own switch+port, use it as `--entry` for MOHAWC/VINNY topology ordering

## deploy_mrp improvements

- [ ] Find a name (backronym tradition: AARON, MOHAWC, MARCO, STONE)
- [ ] Sub-Ring support
- [ ] Gather-facts stage: parallel connect, read current state (MRP, RSTP, loop prot, auto-disable), diff against target, apply playbook, verify loop (1s retry), save
- [ ] L2S safety: check getter before setter (SNMP raises noCreation on L2S devices that lack loop prot / auto-disable)
- [ ] Loop protection as alternative to RSTP disable (driver getters/setters done — MOPS + SNMP)
- [ ] Auto-disable integration (driver getters/setters done — MOPS + SNMP)
- [ ] Phase 5 ring verification: retry 3 times with short delay before declaring unhealthy (ring needs a beat to converge after port enable)
- [ ] Logging: all screen output should also go to log file (phase steps, per-device results, ring status). Log folder should be PWD, not fixed path

## Vendor-specific getters

- [ ] `get_vlan_ports()` — per-interface VLAN config: PVID, access/trunk mode, ingress filtering, acceptable frame types. Source: Q-BRIDGE-MIB (`dot1qPvid`, `dot1qVlanStaticEgressPorts`, `dot1qVlanStaticUntaggedPorts`). Needed for NILS edge port health checks and device type detection.
- [ ] `set_vlan()` / `set_vlan_ports()` — create/delete VLANs, set per-port T/U/PVID membership. No port roles on Hirschmann (respects the ASIC) — tool must explicitly set Tagged/Untagged/PVID per port per VLAN.
- [x] `get_loop_protection()` / `set_loop_protection()` — MOPS + SNMP (SSH pending)
- [x] `get_auto_disable()` / `set_auto_disable()` / `reset_auto_disable()` / `set_auto_disable_reason()` — MOPS + SNMP (SSH pending)

## VLAN deployment tool

Fleet-wide VLAN provisioning. Depends on `get_vlan_ports()` + `set_vlan()` / `set_vlan_ports()`.

- [ ] Find a name (backronym tradition)
- [ ] Add VLAN: `tool.py --add-vlan 5 --name "Pizzagate"` — create VLAN table entry across fleet
- [ ] Auto-trunk: `-T` flag — auto-tag on any port with LLDP neighbor to another switch in the device list. Hirschmann has no port roles — we explicitly set T per port, LLDP tells us which ports are inter-switch
- [ ] Access port: `--access-port 5 1/1-1/8` — set PVID, set U, remove other VLAN membership for those ports. Port range syntax: `1/1-1/8`, `1/1,1/3,1/5`, `1/1-1/8,2/1-2/4`
- [ ] CSV export: `tool.py --export vlans.csv` — dump all interfaces with current VLAN membership (PVID, T, U) from fleet to CSV
- [ ] CSV import: `tool.py --import vlans.csv` — read edited CSV back in, diff against live state, apply changes. Same file format both ways — dump, edit, apply
- [ ] Compact config format: `tool.py -f VLANset.cfg` — one line per interface: `ip interface pvid [vlan_id,T/U/-]` with multiple VLANs per interface on egress in one line
- [ ] `--entry ip interface` — specify network entry point for topology-safe ordering:
  - LLDP BFS from entry to map topology (same pattern as MOHAWC `--entry` reset ordering)
  - Detect if changes affect connectivity from entry point (current PVID, management VLAN)
  - Apply uplink changes in reverse order (furthest-first) if they affect our path
- [ ] **Management VLAN migration** — the ultimate feature:
  1. Add new VLAN structure across entire network first (safe — additive only)
  2. Change management VLAN + PVID on furthest switches first, work backwards toward entry
  3. At entry switch: set both current and new management VLAN as U on local port, then change management VLAN + port PVID in one MOPS exchange (atomic)
  4. Never lose access from entry point at any step
- [ ] Dry-run, protocol selection, banner/footer (standard tool patterns)
- Working name idea: VINNY — VLAN Interactive Network N...Y?

## CLI Reference Parser

- [ ] Parse `local/RM_CLI_HiOS-10300_Overview_en.pdf` (500+ pages) into structured JSON
- [ ] Per-command metadata: section, title, page, command string, mode (global_config/interface_range/privileged_exec), privilege level, negate form, params with allowed values, description
- [ ] Separate `commands` vs `show_commands` per section
- [ ] Output: `local/cli_reference.json` — grepping/filtering replaces reading PDF pages
- [ ] Speeds up all future SSH backend work (auto-disable, loop prot, RSTP, VLANs, etc.)

## Future — Config import/export + firmware update

- [ ] Config export: download running config as XML/profile via MOPS HTTPS endpoints
- [ ] Config import: upload profile/XML to device, activate as running config
- [ ] Firmware update: upload firmware image, trigger install + reboot
- Profile import is the high-value target — deploy a known-good config to fleet via napalm-hios

## Backburner

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The HiOS web UI (Industrial HiVision, MOPS) retrieves configuration via HTTPS/TLS, not SNMP — it uses a combination of HTTPS for config transfer and SNMP for individual value reads/writes. The running-config as a single retrievable object does not exist in any standard or private MIB.

A future approach could replicate the HTTPS mechanism: authenticate to the device's web interface and download the config XML directly, then present it through `get_config()`. This would require understanding the exact HTTPS endpoints and authentication flow. For now, `get_config()` remains SSH-only.
