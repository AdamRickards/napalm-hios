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
- [ ] Management VLAN migration — needs driver `set_management_vlan()` / `set_management_ip()`
- [ ] `-v` / `-n` shorthand flags for VLAN ID and name

## Depends on driver

- [ ] `get_vlan_egress()` should include VLANs with zero port membership (driver filters them out — data is there from the MIB, just dropped by the `if port_modes:` guard)
- [ ] `set_access_port(port(s), vlan_id)` — atomic access mode via MOPS `set_multi`: read VLAN table + ifIndex, set egress (add new untagged, remove old) + PVID in a single call. Eliminates the blip between staged egress commit and separate PVID call. Same function reusable for management VLAN migration (egress + PVID + management VLAN ID in one atomic set). Benchmark with BLIP to measure improvement. **Mirror**: driver TODO in `../../TODO.md` — update both when complete
