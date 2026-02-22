# Changelog

## 1.3.0 — 2026-02-22

### Candidate config workflow

HiOS has no native candidate config — commands apply immediately. This release adds
an in-memory staging workflow (`load_merge_candidate` → `compare_config` → `commit_config`)
that executes staged CLI commands via SSH with safety checks.

- **`load_merge_candidate(filename=None, config=None)`** — stage CLI commands for later commit
- **`compare_config()`** — return staged commands (no real diff possible on HiOS)
- **`commit_config(message='', revert_in=None)`** — execute staged commands via SSH, save to NVM
  - Checks NVM sync before commit (rejects if someone else has unsaved changes)
  - Optional `revert_in` parameter starts HiOS config watchdog for auto-revert (30-600s)
  - Watchdog auto-stops on successful save
- **`discard_config()`** — clear staged commands
- **`rollback()`** — raises `NotImplementedError` with guidance to use `activate_profile()` instead
- **`load_replace_candidate()`** — stays as `NotImplementedError` (HiOS limitation)

### Profile management (SNMP)

New vendor-specific methods for HiOS config profile management via HM2-FILEMGMT-MIB:

- **`get_profiles(storage='nvm')`** — list config profiles with name, active state, datetime, firmware version, SHA1 fingerprint, encryption status
- **`get_config_fingerprint()`** — return SHA1 fingerprint of the active NVM profile
- **`activate_profile(storage='nvm', index=1)`** — activate a profile (causes warm restart)
- **`delete_profile(storage='nvm', index=1)`** — delete an inactive profile

All 4 profile methods implemented on both SSH and SNMP:
- SSH parser uses live device output fixture from GRS1042
- SSH `activate_profile()`: `config profile select nvm <index>` (configure mode, causes warm restart)
- SSH `delete_profile()`: `config profile delete {nvm|envm} num <index>` (configure mode)

### Config watchdog (SNMP)

HiOS has a built-in config watchdog that auto-reverts to saved config if a timer expires.
Used internally by `commit_config(revert_in=N)`, also available directly:

- **`start_watchdog(seconds)`** — start watchdog timer (30-600s)
- **`stop_watchdog()`** — stop (disable) watchdog timer
- **`get_watchdog_status()`** — read watchdog state (enabled, interval, remaining)

### Protocol preference — SNMP default + lazy SSH

- **Default protocol changed** from `['ssh', 'snmp', 'netconf']` to `['snmp', 'ssh', 'netconf']`
- SNMP connects first (lower overhead, stateless); SSH lazy-connects on demand
- **`_ensure_ssh()`** — auto-connects SSH when SSH-only methods are called
- SSH-only methods (`get_config`, `ping`, `cli`, `commit_config`) now work even when active protocol is SNMP
- Explicit `protocol_preference: ['ssh']` disables SNMP entirely (no change)

### Test additions
- `test_get_profiles_nvm` — walk profile table, filter by storage, format timestamps/firmware
- `test_get_profiles_envm` — filters by storage type 2
- `test_get_profiles_invalid_storage` — rejects invalid storage names
- `test_get_config_fingerprint` — finds active profile SHA1
- `test_get_config_fingerprint_no_active` — empty fingerprint when no active profile
- `test_activate_profile` — SET active column
- `test_delete_profile` — SET action=delete for inactive profile
- `test_delete_active_profile_raises` — refuses to delete active profile
- `test_start_watchdog` — SET interval then enable
- `test_start_watchdog_invalid_interval` — rejects out-of-range values
- `test_stop_watchdog` — SET disable
- `test_get_watchdog_status` / `test_get_watchdog_status_disabled` — read all 4 scalars
- `test_load_merge_candidate_string` / `test_load_merge_candidate_no_args`
- `test_compare_config_returns_staged` / `test_compare_config_empty`
- `test_discard_config` / `test_rollback_raises` / `test_load_replace_candidate_raises`
- `test_commit_config_not_loaded` / `test_commit_config_success` / `test_commit_config_unsaved_nvm_rejects`
- `test_default_protocol_snmp_first` — verifies SNMP-first default
- `test_get_config_lazy_ssh` / `test_cli_lazy_ssh` — verify lazy SSH connect
- `test_get_profiles_dispatch` / `test_get_config_fingerprint_dispatch` / `test_activate_profile_dispatch` / `test_delete_profile_dispatch`
- `test_single_profile` / `test_multi_profile` — SSH profile parser with live GRS1042 fixture
- `test_fingerprint` / `test_fingerprint_no_active` / `test_invalid_storage_raises` — SSH profile edge cases
- `test_delete_inactive_profile` / `test_delete_active_profile_raises` / `test_delete_nonexistent_raises` / `test_delete_invalid_storage_raises` — SSH profile delete
- `test_activate_inactive_profile` / `test_activate_already_active_raises` / `test_activate_envm_raises` — SSH profile activate

### Bug fixes
- **`commit_config` uses config mode**: commands now execute in `configure` mode (`_config_mode()` / `_exit_config_mode()`) instead of enable mode. HiOS configuration commands like `system location` require the `configure` sub-shell.
- **`commit_config` error checking**: CLI output is now checked for `Error:` responses during commit. Failed commands are collected and raised as `CommitError` with details.
- **NVM busy polling**: `commit_config` now polls through transient "busy" NVM state (up to 5s) instead of immediately rejecting. Prevents false failures when committing shortly after a previous save.

### Live validation (GRS1042, HiOS-3A-09.4.04)
- Full candidate config cycle: `load_merge_candidate` → `compare_config` → `commit_config` → verified on device
- Profile fingerprint divergence confirmed: SHA1 changes on each NVM save, useful for NMS change detection
- Watchdog: manual start/stop cycle verified, `commit_config(revert_in=60)` auto-starts and auto-stops
- SSH profile parser: matches SNMP profile output on same device
- Lazy SSH connect: SNMP-first → SSH auto-connects for `commit_config` and `get_config`

## 1.2.3 — 2026-02-22

### Bugfix: remove link-up safety check from set_mrp()

Removed the link-up port rejection from `set_mrp()` on both SSH and SNMP.
This was a lab testing guardrail that prevented configuring MRP on ports
with active links — not appropriate for production use where MRP is always
configured on connected uplink ports.

## 1.2.2 — 2026-02-21

### SNMP write operations — set_mrp, delete_mrp, set_hidiscovery

All three vendor-specific write operations now work on both SSH and SNMP.
The driver is now fully protocol-agnostic for all 23 methods except
`get_config`, `ping`, and `cli` (which are inherently CLI-based).

### New SNMP write methods
- **`set_mrp()`** via SNMP: RowStatus pattern on HM2-L2REDUNDANCY-MIB — createAndWait → SET columns → activate. Default domain UUID (all-FF).
- **`delete_mrp()`** via SNMP: SET RowStatus to notInService then destroy.
- **`set_hidiscovery()`** via SNMP: SET hm2NetHiDiscoveryOperation + hm2NetHiDiscoveryMode scalars.

### New features
- **`set_hidiscovery()` blinking**: new optional `blinking` parameter (True/False/'toggle') on both SSH and SNMP. `'toggle'` reads current state and flips it.
- **`_set_oids()`**: multi-value SNMP SET method for batch operations in a single PDU.
- **Recovery delay validation**: `set_mrp()` reads `hm2MrpRecoveryDelaySupported` from the device and rejects 30ms/10ms on hardware that only supports 200ms/500ms.
- **`get_mrp()` accuracy**: `recovery_delay_supported` now returns actual device capability instead of hardcoding all 4 values.

### Dispatch changes
- `set_mrp()`, `delete_mrp()`, `set_hidiscovery()` now dispatch to both SSH and SNMP (previously SSH-only).

### Test additions
- `test_set_hidiscovery_off/on/ro/invalid` — mode cycling and validation
- `test_set_mrp_create_enable` — domain creation via RowStatus pattern
- `test_set_mrp_unsupported_recovery_delay` — hardware capability check
- `test_delete_mrp` — notInService + destroy sequence
- Live validated: full MRP cycle (create/reconfigure/disable/delete) on GRS1042
- Live validated: HiDiscovery toggle cycle (on/off/ro + blinking) on GRS1042

## 1.2.1 — 2026-02-21

### SNMP Phase 2 complete — full SSH/SNMP getter parity

All 20 read getters now work on both SSH and SNMP. The driver provides
identical return formats regardless of protocol, with 11 documented
inherent differences (see README).

### New SNMP methods
- **`get_config_status()`** via SNMP: reads HM2-FILEMGMT-MIB scalars (hm2FMNvmState, hm2FMEnvmState, hm2FMBootParamState). Maps SNMP integer values to SSH-matching strings (`'out of sync'`, not `'outOfSync'`).
- **`save_config()`** via SNMP: uses HM2-FILEMGMT-MIB action table — GETs advisory lock key, SETs hm2FMActionActivate to trigger copy(running-config → NVM), polls NVM state until not busy.
- SNMP SET support added (`_set_scalar()` method) — same auth stack as read operations (SNMPv3 authPriv MD5/DES).

### Dispatch fixes
- **`get_config_status()`** and **`save_config()`** now dispatched through `HIOSDriver` for both SSH and SNMP.
- **`set_mrp()`**, **`delete_mrp()`**, **`set_hidiscovery()`** now dispatched through `HIOSDriver` (SSH-only). Previously only accessible via `device.ssh.set_mrp()`.

### Documentation
- README: updated supported methods list, getter availability table, known issues
- vendor_specific.md: updated access patterns to use `device.get_xxx()` dispatch
- usage.md: updated method list, protocol information
- Comprehensive SSH vs SNMP method audit documented

### Test additions
- `test_get_config_status_saved` — all 3 MIB scalars return ok → saved=True
- `test_get_config_status_unsaved` — NVM out of sync, ExtNVM absent → saved=False
- `test_save_config` — mock GET key + SET action + poll → verify correct OID and key value


## 1.2.0 — 2026-02-21

### Bug fixes
- **CLI output truncation**: `expect_string` changed from `r'[>#]'` to `r'[>#]\s*$'`. The bare `[>#]` matched `#` mid-line in LLDP output (`Remote data, X/Y - #N`), causing netmiko to stop reading prematurely on random chunk boundaries. The `$` anchor ensures only actual prompt characters at end-of-line are matched, supporting both user mode (`>`) and enable mode (`#`).
- **`get_interfaces_ip()` L2 fallback**: L2-only switches (no `show ip interface`) now fall back to `show network parms` and return the management IP keyed by `vlan/{mgmt_vlan_id}`.

### New methods
- **`get_config_status()`**: check if running config is saved to NVM. Returns `saved` boolean plus individual sync states for NVM, ACA (external memory), and boot parameters. Polls through transient "busy" state.
- **`save_config()`**: save running config to non-volatile memory (`copy config running-config nvm`). Waits for NVM write to complete before returning.
- **`get_mrp()`**: returns MRP (Media Redundancy Protocol) ring status — domain, mode (manager/client), ports, port states, VLAN, recovery delay, ring state, redundancy, open count. Returns `{'configured': False}` when no MRP domain exists.
- **`set_mrp(operation, mode, port_primary, port_secondary, vlan, recovery_delay)`**: configure MRP ring on the default domain. **Safety check**: refuses to assign ports that are currently link-up to avoid production impact. Creates default domain automatically if needed.
- **`delete_mrp()`**: disable and delete the MRP domain.
- **`get_hidiscovery()`**: returns HiDiscovery protocol status — enabled, mode (read-only/read-write), blinking, supported protocols, and relay status (L3 only)
- **`set_hidiscovery(status)`**: set HiDiscovery to `'on'` (read-write), `'off'` (disabled), or `'ro'` (read-only, recommended for production). Enters/exits enable mode automatically.
- **`_enable()` / `_disable()`**: enter/exit privileged (enable) mode for config commands
- **`_config_mode()` / `_exit_config_mode()`**: enter/exit global config mode (enable → configure) for MRP and other protocol configuration

### Test additions
- `TestConfigStatus` — synced/unsaved/busy states, `saved` boolean logic
- `TestMRPParser` — unconfigured returns `configured: False`, client mode parses all fields, manager mode shows ring state/redundancy/open count, safety check rejects link-up ports
- `TestInterfacesIpL2Fallback` — L2 management IP returned, 0.0.0.0 yields empty dict, L3 still uses `show ip interface`
- `TestHiDiscoveryParser` — L3 with relay, L2 without relay, disabled state
- Fixtures: `show_config_status_synced.txt`, `show_config_status_unsaved.txt`, `show_mrp_configured.txt`, `show_mrp_unconfigured.txt`, `show_mrp_manager.txt`, `show_network_parms.txt`, `show_network_hidiscovery.txt`
- Live validated: config save cycle (dirty → out of sync → save → ok) on BRS50
- Live validated: MRP configure/reconfigure/disable/delete cycle on BRS50 and GRS1042 using disconnected ports
- Live validated: HiDiscovery toggle cycle (on/off/ro) on BRS50 and GRS1042, blinking round-trip confirmed

## 1.1.2 — 2026-02-21

LLDP parser refactor — replaced three independent parsers with a single
shared `_parse_lldp_remote_data()` method. Fixes 4 bugs found during
live testing against GRS1042, BRS50, and GRS106.

### Bug fixes
- **Multiple management addresses lost**: GRS1042 advertises 5 IPv4 management IPs (one per VRI). Both detail methods used `=` assignment, storing only the last one. Now collects all into a list; `remote_management_address`/`remote_management_ipv4` returns the first.
- **`get_lldp_neighbors()` drops valid entries**: previously required both `system_name` AND `port_description`, silently dropping FDB-only neighbors. Now falls back to `chassis_id` for hostname and `port_id` for port.
- **Detail and extended duplicate parsing logic**: ~100 lines of near-identical code consolidated into shared `_parse_lldp_remote_data()`.
- **Capabilities never parsed**: `Autoneg. cap. bits` continuation line `(10baseT, ...)` was never processed because it lacks `....`. Continuation lines are now appended to the previous key's value.

### New fields
- `management_addresses` list on extended detail — contains all IPv4 + IPv6 management addresses

### Test additions
- `test_basic_neighbors_fallback` — verifies chassis_id used as hostname when system_name missing
- `test_detail_management_address_first` — verifies first IPv4 stored, not last
- `test_capabilities_parsed` — verifies `remote_system_capab` populated from continuation line
- Updated `test_basic_neighbors_count` and `test_extended_management_addresses` for new behavior

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
