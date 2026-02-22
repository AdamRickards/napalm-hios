# TODO

## Done (1.3.0)

- [x] Candidate config workflow — `load_merge_candidate`, `compare_config`, `commit_config`, `discard_config`
- [x] Config watchdog — `start_watchdog`, `stop_watchdog`, `get_watchdog_status` (SNMP)
- [x] Profile management — `get_profiles`, `get_config_fingerprint`, `activate_profile`, `delete_profile` (SNMP + SSH read)
- [x] SSH profile parser — `get_profiles()`, `get_config_fingerprint()` with live GRS1042 fixture
- [x] SNMP-first default protocol preference + lazy SSH connect for SSH-only methods
- [x] `rollback()` → guidance message pointing to `activate_profile()`
- [x] `commit_config` bugfix — config mode, error checking, NVM busy polling

## Done (1.2.x)

- [x] Config status / save — `get_config_status()`, `save_config()` (SSH + SNMP)
- [x] HiDiscovery — `get_hidiscovery()`, `set_hidiscovery()` (SSH + SNMP, including blinking toggle)
- [x] MRP — `get_mrp()`, `set_mrp()`, `delete_mrp()` (SSH + SNMP, with recovery delay validation)
- [x] Full SSH/SNMP getter parity — 20 getters on both protocols
- [x] All vendor write operations on both protocols (1.2.2)
- [x] Extended LLDP with 802.1/802.3 extensions on SNMP

## 1.3.0 (late additions)

- [x] SSH `activate_profile()` — `config profile select nvm <index>` (in configure mode, causes warm restart)
- [x] SSH `delete_profile()` — `config profile delete {nvm|envm} num <index>` (in configure mode)
- [x] Full SSH/SNMP profile parity (read + write) — all 4 profile methods on both protocols

## 1.4.0

### Factory-fresh device onboarding
HiOS 10.3+ forces a password change on first login (SSH prompt before CLI access). SNMP is non-functional until the default password has been accepted/changed. Ref: RM CLI Overview HiOS Release 10.3, page 46.

Needs factory-default hardware for testing. Implementation:
- Detect password change prompt during SSH connect (netmiko `expect_string` or connection handler)
- `initial_setup(new_password=None)` — handle first-login password change flow
- Raise `InitialSetupRequired` (custom exception) if the prompt is hit unexpectedly during normal `open()`
- SNMP only becomes usable after SSH password change completes
- Consider: accept default password and re-set to same value (`private`) for zero-touch scenarios

## Backburner

### get_config via SNMP
Investigated extensively — walked the entire Hirschmann enterprise OID tree (17,132 OIDs) and found no config XML or text blob available via SNMP. The HiOS web UI (Industrial HiVision, MOPS) retrieves configuration via HTTPS/TLS, not SNMP — it uses a combination of HTTPS for config transfer and SNMP for individual value reads/writes. The running-config as a single retrievable object does not exist in any standard or private MIB.

A future approach could replicate the HTTPS mechanism: authenticate to the device's web interface and download the config XML directly, then present it through `get_config()`. This would require understanding the exact HTTPS endpoints and authentication flow. For now, `get_config()` remains SSH-only.
