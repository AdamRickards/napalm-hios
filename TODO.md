# TODO

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
