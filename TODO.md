# TODO

## Done (1.2.x)

- [x] Config status / save — `get_config_status()`, `save_config()` (SSH + SNMP)
- [x] HiDiscovery — `get_hidiscovery()`, `set_hidiscovery()` (get: SSH + SNMP, set: SSH)
- [x] MRP — `get_mrp()`, `set_mrp()`, `delete_mrp()` (get: SSH + SNMP, set/delete: SSH)
- [x] Full SSH/SNMP getter parity — 20 getters on both protocols

## Ideas to implement

### Safe configuration change workflow
A safe config update method to handle the fact HiOS doesn't have candidate merging. We run the risk when messing with config to save other peoples unsaved changes, or save a config change someone else made while we are working on the device.

This method should:
1. Check running-config is in sync with NVM (`get_config_status()`)
2. Grab the running config
3. Execute the requested changes
4. Check the updated running-config doesn't contain lines we didn't set
5. Write running-config to NVM (`save_config()`)

This simulates what other vendors do with candidate configurations or config locking to handle race conditions and multi-user environments.

### get_config via SNMP
The entire running-config is available in a single SNMP OID (HM2-FILEMGMT-MIB). This would allow `get_config()` to work on SNMP too, removing one of the three SSH-only methods.

### Protocol preference changes (1.3.0)
- Consider making SNMP the default protocol (lower overhead, no session state)
- Explicit `protocol_preference` should disable auto-failback
- Single-protocol selection: `optional_args={'protocol_preference': ['snmp']}`
