# ADAM TODO

## Backlog
- [ ] Template comparison (Phase 6) + site context resolution of drift
- [ ] L3 checks (VLAN IPs, routing)
- [ ] Web version (static JS/HTML — upload XML, process client-side, no server)
- [ ] ConfigEngine: CLI↔XML translation using XML-CONFIG-LOGIC.md findings

## Done
- [x] **Security §2.11**: 24 XML checks mapped to vendor manual (SNMPv3 traps, VACM write added)
- [x] **Security §3 (network)**: 8 XML checks — GVRP/MVRP, GMRP/MMRP, port security, DHCP snooping, IPSG, DAI, DoS, LLDP
- [x] **Manual checks**: 11 CLI commands for live-only items (signal contact, digital input, certs, SSH, service shell, MAC conflict, persistent logging, etc.)
- [x] **Security extras**: device security sense monitors (17 conditions)
- [x] **Redundancy**: RSTP, MRP, SRM checks — global state, per-port, role validation
- [x] **Redundancy posture**: meta-check of all globals, false confidence detection
- [x] **SRM**: role enum fix (was misread as boolean), global state, topology validation
- [x] **Site MRP**: UUID+VLAN ring identity, RM count, SRM-managed rings resolved as healthy
- [x] **Site SRM**: role pair validation, effective state, VLAN name as intent indicator
- [x] **Edge protection**: per-port strategy detection, conflict/none warnings
- [x] **VLANs**: PVID mismatch, orphan, dirty access, name consistency (skip ring VLANs)
- [x] **System**: hostname, communities, users, auto-disable reasons/timers
- [x] **Output**: `-o report.txt/.html/.json`, `-s` severity filter, `-v` verbose, `--no-color`
- [x] **SW gating**: visible skip messages, per-check requiresSW in JSON
- [x] **XML Config Generation**: minimum viable XML research — 8 VACM entries as gate, factory-default behavior for missing MIBs, ~150-line production config proven on live switch. Documented in `reference/XML-CONFIG-LOGIC.md`
