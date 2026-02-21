# Changelog

## 1.1.1 — 2026-02-21

NAPALM compliance audit — tested all getters against 4 live devices
(GRS1042, 2× BRS50, GRS106-ALPHA with 10G SFP+).

### Bug fixes
- **Speed parser**: `10G full` format now handled correctly (was returning speed=0 on 10G SFP+ ports). `parse_show_port` now uses `_parse_speed()` which handles `10G`, `2500`, `100G`, etc.
- **LLDP management address**: `get_lldp_neighbors_detail()` now parses and returns `remote_management_address` from `IPv4 Management address` LLDP TLV
- **SNMP community format**: now returns NAPALM-standard `{name: {acl: "", mode: "ro"}}` instead of non-standard `{name: "ro"}`
- **Interface MAC address**: `get_interfaces()` now populates `mac_address` with the device base MAC from `show system info`

### Test additions
- Added `test_speed_10g` — validates 10G/2500/1000 speed parsing in simulated show port output
- Added `test_mac_address_populated` — verifies base MAC propagation to all interfaces

## 1.1.0 — 2026-02-21

Refactored all CLI parsers to use shared infrastructure. Tested against
GRS1042 (L3, HiOS-3A-09.4.04) and BRS50 (L2, HiOS-2A-10.3.04).

### Shared parser library (`utils.py`)
- `parse_dot_keys()` — parses `Key....value` format (system info, temperature, resources, SNTP status)
- `parse_table()` — detects `-----` separator dynamically, returns field lists (replaces all hard-coded line skips)
- `parse_multiline_table()` — handles multi-line-per-record tables

### Parser fixes
- **get_facts**: rewritten with `parse_dot_keys`; interface list no longer contains dash continuation lines
- **get_interfaces / parse_show_port**: parse link status from `fields[-2]` instead of fixed index `fields[6]` which broke on multi-word speed values like "2500 full"
- **get_environment**: complete rewrite — fanless devices no longer crash; temperature/power/CPU/memory now match NAPALM standard format; `available_ram` is total (not free)
- **get_optics**: find TX/RX power by `float/float` regex instead of positional offset from `'SFP'` keyword; temperature column no longer confused with power
- **get_arp_table**: uses `show ip arp table` (L3) with `show arp` fallback (L2); finds MAC by regex pattern; L2 parser now filters IPv6 entries
- **get_interfaces_ip**: uses `parse_table`; gracefully returns `{}` on L2 switches
- **get_interfaces_counters**: uses `parse_table` instead of `lines[4:]` hard-coded skip
- **get_mac_address_table**: uses `parse_table` instead of `split('\n')[2:]`
- **get_users**: uses `parse_table` instead of 4 separate `startswith` header checks
- **get_vlans**: uses `parse_table` for both `show vlan brief` and `show vlan port`
- **get_ntp_servers / get_ntp_stats**: uses `parse_table` + `parse_dot_keys` instead of `server_lines[3:]`
- **get_snmp_information**: rewritten to use `show system info` + `show snmp community`

### Test suite
- Fixed all unit tests (was 5/19 passing, now 76/76)
- Fixed pysnmp v7 API change (`getCmd` → `get_cmd`) in `snmp_hios.py` and tests
- Added fixture-based parser tests (`test_parsers.py`) with real CLI output from GRS1042
- Added SFP optics parser tests with temperature-vs-power discrimination
- Updated mock device and integration tests to match NAPALM standard format

### Other
- Added `.venv/` to `.gitignore`
- Fixed `setup.py` author/URL metadata
- Pagination disabled on connect (`cli numlines 0`) — unchanged, confirmed working

## 1.0.2

Initial public release.
