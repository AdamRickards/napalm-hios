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

- [ ] `-fi` support — read device list from site index (`../site.json`)
- [ ] `-iN` / `-iN-M` / `-i*` — device selection by site index
- [ ] `--entry` topology-safe ordering — LLDP BFS, furthest-first for changes affecting connectivity
- [ ] Management VLAN migration — needs driver `set_management_vlan()` / `set_management_ip()`
- [ ] `-v` / `-n` shorthand flags for VLAN ID and name

## Depends on driver

- [ ] `get_vlan_egress()` should include VLANs with zero port membership (driver filters them out — data is there from the MIB, just dropped by the `if port_modes:` guard)
