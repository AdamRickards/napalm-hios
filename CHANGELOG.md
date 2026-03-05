# Changelog

## 1.10.0 — 2026-03-05

### sFlow support (MOPS-only) — RFC 3176

4 new vendor-specific methods for programmatic sFlow configuration via SFLOW-MIB:

- **`get_sflow()`** — agent version/address + 8-slot receiver table (owner, address, port, timeout, datagram version)
- **`set_sflow(receiver, ...)`** — configure/release sFlow receivers. Owner must be set first to claim a receiver (separate MOPS SET required by device). Setting owner to `''` releases the receiver and auto-clears all bound samplers/pollers
- **`get_sflow_port(interfaces=None, type=None)`** — per-port sampler (rate, header size) and poller (interval) config. Filters by interface list and table type (`'sampler'`/`'poller'`)
- **`set_sflow_port(interfaces, receiver, ...)`** — bind/unbind sampler and/or poller on ports. `sample_rate`/`interval` params select which table to configure. When unbinding (`receiver=0`), only the receiver field is sent — device auto-clears rate/interval

Helper: `_encode_hex_ip()` — IPv4 string to MOPS hex format, inverse of `_decode_hex_ip()`.

Dispatcher in `hios.py` gates on MOPS-only (`active_protocol == 'mops'`).

Live tested on BRS50 (.4) and GRS1042 (.254). 23 new unit tests.

## 1.9.0 — 2026-03-02

### Multi-interface setters — all 3 protocols

All 7 per-port setters now accept a single interface string or a list of interfaces. MOPS batches all mutations into one `set_multi()` POST. SNMP batches all varbinds into one SET PDU. SSH loops within one config mode session. Backward compatible — single string still works exactly as before.

- **`set_interface(interface, ...)`** — `str | list`. MOPS: separate mutations for `ifEntry` (admin status) and `ifXEntry` (alias) per port, all in one `set_multi()`.
- **`set_rstp_port(interface, ...)`** — `str | list`. Builds `hm2AgentStpPortEntry` (enabled) + `hm2AgentStpCstPortEntry` (CST params) mutations per port, one `set_multi()`.
- **`set_auto_disable(interface, timer)`** — `str | list`.
- **`reset_auto_disable(interface)`** — `str | list`.
- **`set_loop_protection(interface, ...)`** — `str | list` for per-port path. Global path unchanged.
- **`set_vlan_ingress(port, ...)`** — `str | list`.
- **`set_vlan_egress(vlan_id, port, mode)`** — `str | list` for port. Reads bitmaps once, modifies all target port bits in memory, writes back once.

### SNMP setter batching fix

`set_loop_protection` and `set_rstp_port` in SNMP were sending one SET PDU per parameter in a loop. Now batch all varbinds into one `_set_oids()` call. Reduces SNMP round-trips from N to 1 per setter call even for single-interface use.

### MOPS getter consolidation — 4 getters reduced from multiple POSTs to 1

Pure internal refactor — no API change, same return formats. Each getter now fetches all its MIB tables in a single `get_multi()` HTTP POST instead of sequential `get()` calls.

- **`get_facts()`**: 3 POSTs → 1. Merged HM2-DEVMGMT-MIB (product, serial, firmware) into existing `get_multi` with SNMPv2-MIB + IF-MIB.
- **`get_environment()`**: 3 POSTs → 1. Merged PSU (HM2-PWRMGMT-MIB) + fans (HM2-FAN-MIB) into existing `get_multi` with temp + CPU + memory.
- **`get_lldp_neighbors_detail()`**: 2 POSTs → 1. Merged `lldpRemEntry` + `lldpRemManAddrEntry` into one `get_multi`.
- **`get_mrp_sub_ring()`**: 2 POSTs → 1. Merged `hm2SrmMibGroup` + `hm2SrmEntry` into one `get_multi`.

### MOPS getter consolidation — ifindex map bundling (11 getters)

Added `_get_with_ifindex()` helper that conditionally bundles `IF-MIB/ifXEntry` into a getter's own `get_multi()` POST when the ifindex cache is cold. Eliminates a separate HTTP round-trip for interface name resolution. On warm cache (e.g. after `get_facts()`), the helper skips the extra table — zero overhead.

11 getters converted, 6 of which were also migrated from single `get()` to `get_multi()`:

- **Already `get_multi()`**: `get_lldp_neighbors_detail`, `get_lldp_neighbors_detail_extended`, `get_mrp_sub_ring`, `get_auto_disable`, `get_loop_protection`
- **Converted `get()` → `get_multi()`**: `get_interfaces_ip`, `get_lldp_neighbors`, `get_arp_table`, `get_optics`, `get_mrp`, `get_mac_address_table`
- **`get_mrp()`**: also gained `decode_strings=False` (was missing — now consistent with all other getters). `hm2MrpDomainName` now manually decoded via `_decode_hex_string()`.

### Bug fix: `get_mrp_sub_ring()` binary field mangling

MOPS `get_mrp_sub_ring()` was missing `decode_strings=False`, causing binary fields to be mangled by XML string decode:
- **`hm2SrmPartnerMAC`**: 6-byte MAC became U+FFFD replacement characters. Now decoded from raw hex to `xx:xx:xx:xx:xx:xx`.
- **`hm2SrmMRPDomainID`**: 16-byte UUID had `\xFF` bytes replaced with U+FFFD. Now decoded from raw hex to colon-separated format.
- **`hm2SrmSubRingPortIfIndex`**: integer port index was mangled (e.g. `16` → `\u0010`). Now parsed as integer correctly.
- **`hm2SrmSubRingProtocol`**: is an INTEGER enum (`4` = `iec-62439-mrp`), not a text string. Both MOPS and SNMP now map `4` → `'mrp'` instead of passing through the raw value.
- **`hm2SrmSubRingName`**: text field now manually decoded via `_decode_hex_string()`.

### MOPS staging — wired into vendor setters

Staging batches mutations into one atomic POST. The driver does not validate dependencies between staged operations. Operations that depend on prior state (e.g. `set_vlan_egress` requires the VLAN to exist) must have their prerequisites committed first. Tool layer is responsible for operation ordering.

- **`device.start_staging()`** / **`device.commit_staging()`** / **`device.discard_staging()`** / **`device.get_staged_mutations()`** — exposed on `HIOSDriver` dispatch layer. SNMP/SSH raise `NotImplementedError`.
- **14 setters wired** via three staging-aware helpers (`_apply_mutations`, `_apply_set_indexed`, `_apply_set`):
  - `set_vlan_ingress`, `set_vlan_egress`, `set_rstp`, `set_rstp_port`, `set_interface`, `set_hidiscovery`, `set_auto_disable`, `reset_auto_disable`, `set_auto_disable_reason`, `set_loop_protection` (global + per-port)
- **VLAN CRUD always fires immediately** — `create_vlan()`, `update_vlan()`, `delete_vlan()` bypass staging. These are database operations; other setters validate against live state (e.g. `set_vlan_egress` reads the VLAN table to verify the VLAN exists and get current bitmaps).
- **Read-back skips in staging** — `set_rstp()` and `set_hidiscovery()` return `None` when staging (read-back would return stale pre-commit state).
- **`commit_staging()` does NOT auto-save** — fires `set_multi()` only. Call `save_config()` separately. Avoids NVM race conditions when committing multiple batches.
- **MRP setters not wired** — `set_mrp()`, `delete_mrp()`, `set_mrp_sub_ring()`, `delete_mrp_sub_ring()` still fire immediately (complex multi-step RowStatus sequences with try/except).

### Live verification

All changes tested on 4 BRS50 devices (.80, .81, .82, .85) across MOPS and SNMP protocols. 152 live setter/getter tests passed (44 getter tests across 3 protocols + 108 setter tests across 2 protocols, single + multi-interface). `.85` (L2S) correctly skipped for loop protection (not supported on L2S).

40 staging live tests passed across all 4 devices:
- `start_staging` → empty queue verified
- VLAN ingress + egress staged → 2 mutations queued, device state unchanged pre-commit
- `commit_staging` → one atomic POST (0.38–0.77s), device state verified post-commit
- `discard_staging` → mutations cleared, device unchanged
- Mixed setter batch (interface description + RSTP port) → committed successfully
- `save_config()` independently after commit → NVM sync confirmed (2.6–7.2s)

### Unit tests

- 14 setter tests updated from `set_indexed` assertions to `set_multi` assertions.
- 7 getter tests updated for consolidated `get_multi` mock fixtures.
- 6 getter tests migrated from `client.get` mocks to `client.get_multi` mocks (ifindex consolidation).
- SRM test fixtures updated for `decode_strings=False` format (hex-encoded text fields, raw hex binary fields, integer protocol enum).
- 417 total passing.

## 1.8.1 — 2026-03-02

### Bug fix: MOPS SET error detection

`_is_ok_response()` in `mops_client.py` treated all `mibResponse` replies as success. When a MOPS SET fails (e.g. invalid port index, read-only attribute, non-existent table row), the switch returns `mibResponse` with `error` attributes on the affected MIB/Node/Attribute elements instead of `<ok/>`. The old code saw `mibResponse` and returned `True`, silently swallowing the error. Every `set()`, `set_indexed()`, and `set_multi()` call was affected — invalid writes appeared to succeed while nothing was applied to the switch.

- **`_is_ok_response()`**: now parses `mibResponse` XML for `error` attributes at MIB, Node, and Attribute levels. Raises `MOPSError` with details (e.g. `"SET failed: HM2-PLATFORM-SWITCHING-MIB/hm2AgentStpCstPortEntry/hm2AgentStpCstPortEdge: noCreation"`). Empty `mibResponse` (echo-back with no errors) still returns `True`.
- **`_parse_response()`**: now detects attribute-level `error` attributes in GET responses and adds them to the `errors` list with `attribute` field. Previously only caught MIB-level and Node-level errors.

### MOPS `set_multi()` atomicity confirmed

Live-tested on BRS50 (.80): `set_multi()` with one invalid mutation in a batch of valid ones results in atomic rejection — nothing is applied. Cross-MIB batching (different MIBs in one POST) works. No-ops (setting a value already in target state) are harmless.

### Unit tests

- 4 new tests: `test_is_ok_mibresponse_with_attribute_error`, `test_is_ok_mibresponse_with_node_error`, `test_is_ok_mibresponse_with_mib_error`, `test_parse_response_attribute_error`.
- Existing `test_is_ok_mibresponse` (empty mibResponse = success) unchanged and passing.

### Version bump

- `version.py` and `setup.py`: 1.8.0 → 1.8.1

## 1.8.0 — 2026-03-01

### VLAN Ingress/Egress API — all 3 protocols

Full VLAN configuration and membership management, implemented on MOPS, SNMP, and SSH:

- **`get_vlan_ingress(*ports)`** — per-port ingress settings: PVID, acceptable frame types (`admit_all`/`admit_only_tagged`), ingress filtering. Optional port filter. Source: Q-BRIDGE-MIB `dot1qPortVlanEntry`.
- **`get_vlan_egress(*ports)`** — per-VLAN-per-port membership with Tagged/Untagged/Forbidden classification. Decodes three PortList bitmaps (`EgressPorts`, `UntaggedPorts`, `ForbiddenEgressPorts`). Optional port filter omits VLANs with no matching ports.
- **`set_vlan_ingress(port, pvid, frame_types, ingress_filtering)`** — set any/all ingress parameters on a single port. `None` = don't change.
- **`set_vlan_egress(vlan_id, port, mode)`** — set one port's membership for one VLAN. Modes: `tagged`, `untagged`, `forbidden`, `none` (remove from egress).
- **`create_vlan(vlan_id, name)`** — create VLAN in database with optional name.
- **`update_vlan(vlan_id, name)`** — rename an existing VLAN.
- **`delete_vlan(vlan_id)`** — delete VLAN from database.

### Protocol-specific details

- **MOPS**: IEEE8021-Q-BRIDGE-MIB for GET, Q-BRIDGE-MIB for all SET operations (IEEE8021 SET returns HTTP 400). ForbiddenEgressPorts must be SET separately from EgressPorts+UntaggedPorts (combined request causes silent failure). Raw hex bitmap manipulation for egress modifications.
- **SNMP**: Four new OIDs (`dot1qPvid`, `dot1qPortAcceptableFrameTypes`, `dot1qPortIngressFiltering`, `dot1qVlanStaticForbiddenEgressPorts`). RowStatus 4=createAndGo, 6=destroy for VLAN CRUD. pysnmp `OctetString.asOctets()` for PortList byte conversion.
- **SSH**: `show vlan port` for ingress, `show vlan id N` for per-VLAN egress membership. `vlan database` context (from enable mode) for create/name/delete. Interface context for `vlan participation include|exclude|auto`, `vlan tagging`, `vlan pvid`, `vlan acceptframe all|vlanonly`, `vlan ingressfilter enable|disable`.

### Helpers

- **`_encode_portlist_hex()`** (MOPS) — reverse of `_decode_portlist_hex()`. Interface names → hex PortList bitmap string.
- **`_encode_portlist()`** (SNMP) — reverse of `_decode_portlist()`. Interface names → bytes for SNMP SET.
- **`_to_bytearray()`** (SNMP) — handles pysnmp `OctetString` objects that lack `.encode()`.

### Unit tests

- 57 new tests: 18 MOPS (getters, setters, CRUD, encode helper) + 18 SNMP (same coverage) + 16 dispatch (SSH/MOPS/SNMP routing, port filter passthrough) + 5 encode helper edge cases.
- 413 total passing.

### Documentation

- **vendor_specific.md**: new VLAN Ingress/Egress section with full getter/setter parameter tables.
- **protocols.md**: added 7 methods to availability matrix.
- **usage.md**: added 7 new methods to vendor-specific read/write lists.
- **README.md**: added VLAN methods to supported methods lists, updated test count.

### Version bump

- `version.py` and `setup.py`: 1.7.0 → 1.8.0

## 1.7.0 — 2026-03-01

### MRP Sub-Ring (SRM) — all 3 protocols

Sub-ring management for MRP, implemented on MOPS, SNMP, and SSH:

- **`get_mrp_sub_ring()`** — global SRM state (enabled, max_instances) and per-instance details (mode, vlan, port, ring_state, redundancy, partner_mac, domain_id, info). L2S devices return empty result gracefully on all protocols.
- **`set_mrp_sub_ring(ring_id, enabled, mode, port, vlan, name)`** — enable SRM globally and/or create/modify sub-ring instances. Auto-enables global SRM when creating an instance. Modes: `manager`, `redundantManager`, `singleManager`.
- **`delete_mrp_sub_ring(ring_id)`** — delete a specific instance or disable SRM globally. Idempotent — deleting a non-existent instance returns current state without error.

### Protocol-specific fixes

- **MOPS domain_id encoding**: `\xFF` bytes in `hm2SrmMRPDomainID` are mangled to U+FFFD by XML decoder (`decode_strings=False` pattern). Fixed with explicit `'\ufffd'` → `'ff'` mapping.
- **MOPS partner_mac encoding**: same binary mangling — fixed via `_try_mac()` helper.
- **SNMP L2S handling**: `createAndWait` on `hm2SrmRowStatus` returns `noSuchName` on L2S (OID doesn't exist). Wrapped in `try/except ConnectionException` for graceful early return.
- **SSH domain_id format**: CLI shows decimal-dotted (`255.255.255...`), converted to hex-colon (`ff:ff:ff:...`) to match MOPS/SNMP output.

### CLAMPS — sub-ring support

The S in CLAMPS is no longer aspirational:

- **Config format**: `SRM <vlan> <port>`, `RSRM <vlan> <port>`, `RC <vlan> [p1 p2]` lines in script.cfg. Devices grouped by VLAN into `config['rings']` dict.
- **Deploy Phase 6**: Configure sub-ring RCs (standard `set_mrp` with sub-ring VLAN) + SRM/RSRM branch points (`set_mrp_sub_ring`), parallelised per sub-ring.
- **Deploy Phase 7**: Verify sub-ring health on SRM device (ring_state=closed, redundancy=True) with 3x retry.
- **Undeploy Step 1**: Sub-ring teardown before main ring — delete SRM instances, disable SRM globally, delete MRP on sub-ring RCs.
- **Edge protection**: `get_ring_ports_for_device()` builds combined ring port set across all rings (main + sub-rings) for correct port classification.
- **Banner**: Shows main ring and sub-rings with port layout and role labels.

### Unit tests

- 12 new tests (6 MOPS + 6 SNMP): empty/populated get, global enable, create instance, unknown port, delete.
- 356 total passing.

### Documentation

- **vendor_specific.md**: new MRP Sub-Ring section, updated protocol line to include SSH.
- **protocols.md**: added `get_mrp_sub_ring` and `set/delete_mrp_sub_ring` to availability matrix.
- **usage.md**: added 3 SRM methods to vendor-specific read/write lists.
- **README.md**: added SRM methods to supported methods lists.
- **script.cfg**: updated with sub-ring config syntax and examples.

## 1.6.0 — 2026-02-28

### Auto-Disable — all 3 protocols

Port auto-disable monitoring and control, implemented on MOPS, SNMP, and SSH:

- **`get_auto_disable()`** — per-port timer/status/component and global reason enable/disable state. L2S devices return 7 reasons (vs 10 on L2A+). Live-tested on .117 (L2A), .127 (L2S), .254 (GRS1042).
- **`set_auto_disable(interface, timer=0)`** — set auto-disable timer per port. SSH always sends `auto-disable timer {value}` explicitly — `no auto-disable timer` is a no-op on HiOS CLI.
- **`reset_auto_disable(interface)`** — reset auto-disabled port back to active.
- **`set_auto_disable_reason(reason, enabled=True)`** — enable/disable individual auto-disable trigger reasons globally.

### Loop Protection — all 3 protocols

Loop detection heartbeat protocol, implemented on MOPS, SNMP, and SSH:

- **`get_loop_protection()`** — global settings (enabled, transmit_interval, receive_threshold, mode, action) plus per-port state (enabled, mode, action, vlan_id, tpid_type, last_loop_time). `tpid_type` is read-only — auto-derived by the device from `vlan_id` (0→none, >0→dot1q). L2S devices return empty result (SSH: `Error: Invalid command`, SNMP/MOPS: empty tables).
- **`set_loop_protection(interface=None, ...)`** — global settings when `interface=None`, per-port settings when interface specified. `tpid_type` removed from setter — auto-populated by device.

### RSTP — SNMP + SSH backends complete

RSTP was MOPS-only since 1.4.2. Now all 3 protocols produce identical output:

- **`get_rstp()`** — global STP/RSTP config and state (mode, bridge/root IDs, priority, timers, topology changes, BPDU guard/filter).
- **`get_rstp_port(interface=None)`** — per-port state (enabled, forwarding state, edge port, guards, BPDU stats, path cost, priority).
- **`set_rstp(...)`** — set global STP config (enabled, mode, priority, timers, BPDU guard/filter).
- **`set_rstp_port(interface, ...)`** — set per-port config (enabled, edge port, auto edge, path cost, priority, guards, BPDU filter/flood).
- SNMP: `Unsigned32` type required for priority, path_cost, and timer OIDs (wrongType fix).
- SSH: parses `show spanning-tree global` (dot-keys) + `show spanning-tree mst port 0` (table) + `show spanning-tree port <port>` (dot-keys per port).

### SNMP fixes

- **`Unsigned32` for `hm2AutoDisableIntfTimer`**: SNMP SET with `Integer32` caused wrongType — fixed to `Unsigned32`.
- **`Unsigned32` for STP OIDs**: bridge priority, port priority, path cost, hello time, max age, forward delay, hold count, max hops all require `Unsigned32`.
- **`_decode_date_time()` / `_decode_snmp_date_time()`**: DateAndTime helpers for auto-disable timestamps. Epoch (all zeros) returns empty string.

### SSH CLI quirks documented

- **`auto-disable timer 0`** works but **`no auto-disable timer`** does NOT reset (CLI no-op). Always send explicit value.
- **Loop protection on L2S**: `show loop-protection global` returns `Error: Invalid command` — gracefully handled as empty result.

### Unit tests

- 22 new tests (12 auto-disable + 10 loop protection), 344 total passing.

### Documentation

- **vendor_specific.md**: added Auto-Disable and Loop Protection sections with full getter/setter parameter tables.
- **protocols.md**: added 6 methods to availability matrix, 4 new cross-protocol diffs (#12 tpid_type, #13 L2S loop prot, #14 L2S auto-disable reasons, #15 timer reset quirk).
- **usage.md**: added 6 new methods to Available Methods.
- **CLI_REFERENCE.md**: added §6 Auto Disable and §64 Loop Protection command mappings.

### CLAMPS tool release

- New tool: `tools/clamps/` — MRP ring deployment + edge protection (clamp.py, unclamp.py). See `tools/clamps/README.md`.

### Version bump

- `version.py` and `setup.py`: 1.5.0 → 1.6.0

## 1.5.0 — 2026-02-26

### Port admin control

- **`set_interface(interface, enabled, description)`** — enable/disable ports and set descriptions on all 3 protocols. MOPS: atomic SET on IF-MIB + ifAlias. SNMP: multi-OID SET. SSH: `interface` config mode commands.

### Factory reset — all protocols

Two levels of device reset, matching HiOS CLI semantics:

- **`clear_config(keep_ip=False)`** — clears running config to factory defaults (RAM only). Warm restart ~12s. NVM shows "out of sync" after (saved config untouched). `keep_ip=True` preserves management IP and addressing mode (LOCAL/DHCP).
- **`clear_factory(erase_all=False)`** — full factory reset. Wipes RAM + NVM + ACA, cold reboot (uptime resets). `erase_all=True` also regenerates factory.cfg from firmware (for corrupted factory defaults).
- All 3 protocols: MOPS (hm2FMActionEntry indexed SET), SNMP (OID SET), SSH (CLI with Y/N prompt handling).
- Live-tested on BRS50: canary-based proofs (set port description → save → dirty → clear → verify revert to factory default).

### Factory onboarding

- **`is_factory_default()`** — detect factory-fresh HiOS 10.3+ devices. SSH: detects "Enter new password" prompt during `open()`. MOPS: reads `hm2UserForcePasswordStatus` MIB. SNMP: returns `False` (SNMP is gated on factory-default devices — if connected, gate is already cleared).
- **`onboard(new_password)`** — respond to factory password gate. SSH: sends password to interactive prompts via Netmiko channel. MOPS: POST to `/mops_changePassword`. SNMP: raises `NotImplementedError` (gated).
- Live-tested on factory-fresh BRS50 (both SSH and MOPS).

### Protocol cleanup

- **NETCONF removed from default `protocol_preference`**: was `['mops', 'snmp', 'ssh', 'netconf']`, now `['mops', 'snmp', 'ssh']`. NETCONF is stub-only and caused noisy connection failures. Opt in explicitly if needed.

### Safe MRP deploy/undeploy

Updated `tools/deploy_mrp/` with loop-prevention sequence:

- **deploy_mrp.py**: 6-phase — disable RM port2 → configure MRP (parallel) → disable RSTP on ring ports → enable RM port2 → verify ring → save. Error recovery re-enables RM port2 on failure.
- **undeploy_mrp.py**: 5-step — disable RM port2 → re-enable RSTP → delete MRP → enable RM port2 → save.
- Live-tested: 11s deploy, 7s undeploy on 2-device ring.

### MIBs reference folder

- 66 vendor MIB files restored to `MIBs/` (gitignored, reference only — from HiOS firmware).

### Unit tests

- `set_interface`: 5 MOPS tests, 3 SNMP tests
- `clear_config` / `clear_factory`: 4 MOPS tests, 4 SNMP tests
- `is_factory_default` / `onboard`: SSH + SNMP dispatch tests

### Documentation

- **vendor_specific.md**: full rewrite — added Profiles, RSTP, Factory Onboarding, Factory Reset, MOPS Staging, Config Watchdog, Port Admin Control sections. Updated all examples from `device.ssh.method()` to `device.method()`.
- **usage.md**: full rewrite — added MOPS as default protocol, updated protocol_preference default, added all vendor-specific methods to Available Methods.
- **protocols.md**: updated default order (removed NETCONF), added set_interface/is_factory_default/onboard to availability matrix, updated lazy-fail section for SNMP gating.

### Version bump

- `version.py` and `setup.py`: 1.4.2 → 1.5.0

## 1.4.2 — 2026-02-26

### MOPS driver integration

MOPS (MIB Operations over HTTPS) was implemented in 1.4.0 as a backend (`mops_hios.py`) but never wired into the main `HIOSDriver` dispatch layer. This release completes the integration:

- **MOPS in HIOSDriver**: `_try_connect()`, `_get_active_connection()`, `close()` all handle MOPS
- **Default protocol**: `protocol_preference` now defaults to `['mops', 'snmp', 'ssh']` — MOPS first
- **All 31 dispatch checks** updated from `('ssh', 'snmp')` to `('ssh', 'snmp', 'mops')`
- **RSTP dispatch**: `get_rstp()`, `get_rstp_port()`, `set_rstp()`, `set_rstp_port()` added to HIOSDriver

### Performance — MOPS setter read-back removal

MOPS setters were doing unnecessary GET read-backs after every successful SET (MOPS returns `<ok/>` on success — the read-back adds ~1.2s per call for zero value):

- **`set_mrp()`**: removed initial `get_mrp()` existence check (now try createAndWait, catch if exists) and final `get_mrp()` read-back. Returns `{'configured': True, 'operation': 'enabled'/'disabled'}` directly.
- **`delete_mrp()`**: removed final `get_mrp()` read-back. Returns `{'configured': False}` directly.
- **`set_rstp_port()`**: removed final `get_rstp_port()` read-back.

Combined effect: MRP deploy dropped from ~26s to ~7.5s for 2 devices (70% reduction).

### New tool: deploy_mrp

Threaded MRP ring deployment tool in `tools/deploy_mrp/`:

- **`deploy_mrp.py`**: parallel connect → parallel MRP configure → verify ring on manager → parallel RSTP disable → parallel save (optional). Supports MOPS, SNMP, and SSH via `script.cfg`.
- **`undeploy_mrp.py`**: reverse — parallel RSTP re-enable → parallel MRP delete → parallel save (optional).
- Config-driven: `script.cfg` defines credentials, ring ports, VLAN, recovery delay, protocol, device list.
- All operations threaded via `ThreadPoolExecutor`.

### Test fixes

- Fixed `test_set_mrp_enable_client` and `test_set_mrp_disable` to match new createAndWait-first flow
- Removed premature test files (`test_factory_reset.py`, `test_onboarding.py`) for unimplemented methods

### Version bump

- `version.py` and `setup.py`: 1.4.1 → 1.4.2

## 1.4.1 — 2026-02-26

### Bug fixes

- **SSH `get_profiles()` / `get_config_fingerprint()`**: called non-existent `_send_command()` method — raised `AttributeError` immediately on every invocation. Changed to `self.cli()` matching all other SSH getters.
- **SNMP `get_hidiscovery()` relay on L2 devices**: always included `relay: false` on L2 devices where the OID (`hm2NetHiDiscoveryRelay`) returns `NoSuchInstance`. The NoSuchInstance payload was interpreted as a garbage integer by `_snmp_int`, which happened to not equal `1`, producing `False`. Now checks for NoSuchInstance and omits `relay` on L2 devices, matching MOPS and SSH behaviour.

### Test additions

- `test_get_hidiscovery_l2_no_relay` — mocks NoSuchInstance for relay OID, verifies field omitted
- Profile parser/write tests updated to mock `cli()` instead of removed `_send_command()`

### Live validation

- Cross-protocol comparison against 4 devices (3x BRS50, 1x GRS1042) confirmed:
  - GRS1042 (L3): all 3 protocols return `relay: true` — match
  - BRS50 (L2): MOPS and SSH omit `relay`, SNMP now also omits — match
  - SSH `get_profiles` and `get_config_fingerprint` now execute successfully on all devices

### Version bump

- `version.py` and `setup.py`: 1.4.0 → 1.4.1

## 1.3.1 — 2026-02-22

### Documentation refresh

- **README.md rewritten**: cleaned up stale Quick Start example (removed old `ssh_port` optional arg, shows SNMP-default pattern), fixed typos (`docuemntation`, `ssh_examply.py`), replaced outdated `unittest discover` with `pytest`, removed stale mock device section, added Roadmap section, updated profile management to show SSH + SNMP (was SNMP-only), added `commit_config` error checking and NVM busy polling to known issues
- **`.gitignore`**: added `local/` (dev-only docs) and `*.patch` (release artifacts)

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
