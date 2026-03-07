# VIKTOR — TODO

## v1.0 (done)

- [x] `vlan list/create/delete/rename`
- [x] `access` — strict access mode with add-before-remove
- [x] `trunk` — additive tagged membership
- [x] `auto-trunk` — LLDP-discovered inter-switch link tagging
- [x] `-m` ring selector — filter fleet by MRP VLAN egress table
- [x] `--audit` — 5 fleet-wide health checks
- [x] `--names` — VLAN name consistency (majority vote)
- [x] `--export` / `--import` — CSV round-trip with diff display
- [x] `--ips` — comma, last-octet range, CIDR
- [x] `--dry-run`, `--save`, `--debug`
- [x] MOPS staging for port operations
- [x] HiOS LLDP port description normalization (`Module: 1 Port: 6` → `1/6`)

## Remaining

### Ring / Sub-Ring Operations

Current `-m` is inline in `main()` — useful logic buried in the flow. Needs
refactoring and proper terminology.

- [ ] Extract `filter_ring_members()` into a reusable "VLAN follower" function — given a VLAN ID, return devices + ports tagged for it. Useful beyond ring selection (any VLAN-based port targeting). Name TBD: `get_vlan_ports()`? `follow_vlan()`? Find the right term
- [ ] Ring/sub-ring "find" — discover ring VLANs by scanning VLAN names (HiOS auto-names MRP VLANs) and/or cross-referencing `get_mrp()` to confirm VLAN is actually an MRP domain. Enables: `--rings` discovery, auto-detect without `-m`, safety check on `vlan delete` of ring VLANs
- [ ] "Find" and "follow" should share common internals — both need egress data, both produce device+port sets. Factor out the shared VLAN→ports lookup so both paths use the same code
- [ ] Update LOGIC.md and README.md when terminology and API are settled

### Other

- [ ] `-fi` support — read device list from site index (`../site.json`)
- [ ] `-iN` / `-iN-M` / `-i*` — device selection by site index
- [ ] `--entry` topology-safe ordering — LLDP BFS, furthest-first for changes affecting connectivity
- [ ] Management VLAN migration — furthest-first ordering (like MOHAWC reset). Accept loss of access mid-flight, verify at end. Entry switch atomic MOPS POST: MGMT VLAN + MGMT PCP + entry port PVID + entry port "U" on new VLAN + entry port "-" on old VLAN. Needs driver `set_access_port()` or equivalent atomic set. **Open question**: does MOPS `start_staging()`/`commit_staging()` apply sequentially or as true atomic swap? Test with ping flood during commit
- [x] `qos` subcommand — set default PCP on ports carrying a VLAN. Edge-only by default, `--include-trunk` for trunk ports too. Uses `set_qos(default_priority=)`. LLDP edge/trunk classification, VLAN egress for port lookup. `viktor qos 5 --pcp 3`, multi-VLAN `5,6,10`
- [ ] QoS via naming convention — VLAN name prefix (`AC-`, `AM-`, `NM-`, `NC-`) drives automatic QoS class assignment. `--names` already enforces consistency; this gives names meaning. `viktor rename` pointed at a fleet = instant QoS intent. Builds on `qos` subcommand — naming convention is the autopilot, `qos` subcommand is the manual control. See `memory/qos-architecture.md` for full design
- [ ] QoS deployment — from naming convention, auto-configure PCP/TC mapping on all ports carrying each VLAN. Per SW level strategy: L2A writes DSCP via ACL at edge, L2S relies on upstream, L3 trusts DSCP on routed interfaces
- [ ] L3 boundary DSCP mapping — detect L3 hops where PCP dies, auto-configure DSCP trust/remap on routed egress. Topology-aware: NILS provides the graph, VIKTOR applies the config
- [ ] Engineering port exception — documentation-declared `"role": "engineering"` gets split ACL (dstip = switch mgmt IPs → NM priority, else default). First documentation-only feature
- [ ] Management VLAN priority — `network management priority dot1p` + `network management priority ip-dscp` fleet-wide. Needs driver getters/setters for QoS tables (FUTURE, also needed for TSN)
- [ ] `-v` / `-n` shorthand flags for VLAN ID and name

## Depends on driver

- [x] `get_vlan_egress()` should include VLANs with zero port membership — **fixed in driver v1.12.1** (all 3 backends)
- [ ] `set_access_port(port(s), vlan_id)` — atomic access mode via MOPS `set_multi`: read VLAN table + ifIndex, set egress (add new untagged, remove old) + PVID in a single call. Eliminates the blip between staged egress commit and separate PVID call. Same function reusable for management VLAN migration (egress + PVID + management VLAN ID in one atomic set). Benchmark with BLIP to measure improvement. **Mirror**: driver TODO in `../../TODO.md` — update both when complete

## Driver getters now available

QoS deployment depends on driver getters/setters that are now shipped:

| Method | Since | Notes |
|--------|-------|-------|
| `get_qos()` / `set_qos()` | v1.10.0 | Per-port trust mode, default priority |
| `get_qos_mapping()` / `set_qos_mapping()` | v1.10.0 | PCP↔TC mapping tables |
| `get_storm_control()` / `set_storm_control()` | v1.9.0 | Per-port rate limiting (broadcast/multicast/unknown-unicast) |
| `get_management()` / `set_management()` | v1.12.0 | Management VLAN, management priority (PCP + DSCP) |

QoS naming convention and QoS deployment items above can now proceed without waiting for driver work.
