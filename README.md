# NAPALM HiOS Driver

NAPALM driver for Hirschmann HiOS industrial switches by Belden. Four protocols — MOPS, SNMP, SSH, and Offline — with full getter parity and vendor-specific methods for MRP, RSTP, factory lifecycle, and config profiles.

## Features

- **MOPS (MIB Operations over HTTPS)** — default protocol, same mechanism as the HiOS web UI. Atomic multi-table writes in a single POST, HTTP Basic auth, zero pysnmp/net-snmp dependency
- **SNMPv3 authPriv** (MD5/DES) — works with HiOS factory defaults including short passwords (< 8 chars)
- **SSH** — CLI parsing via Netmiko, lazy auto-connect when MOPS/SNMP is primary
- **19 standard getters** on all 3 protocols, plus 3 SSH-only methods (`get_config`, `ping`, `cli`)
- **Atomic config staging** — `load_merge_candidate` → `compare_config` → `commit_config` (MOPS: single POST; SSH: CLI commands)
- **RSTP/STP** — full global and per-port get/set: mode, priority, timers, guards, edge ports, path cost
- **MRP ring redundancy** — configure manager/client roles, ring ports, recovery delay, domain management
- **Factory lifecycle** — detect and onboard factory-fresh HiOS 10.3+ devices, clear to defaults or full factory reset
- **Config profiles** — list, activate, delete NVM/ENVM config profiles with fingerprint tracking
- **HiDiscovery** — read/set discovery protocol mode (on/off/read-only) with blinking control
- **VLAN Ingress/Egress** — per-port ingress settings (PVID, frame types, filtering), per-VLAN egress membership (T/U/F), VLAN CRUD
- **Auto-Disable** — per-port timer/status monitoring, reason control, port reset
- **Loop Protection** — heartbeat-based loop detection with per-port and global config
- **sFlow** — receiver configuration + per-port flow sampling and counter polling (RFC 3176)
- **Storm Control** — per-port broadcast/multicast/unicast ingress rate limiting with pps/percent thresholds
- **QoS** — per-port trust mode, queue scheduling (strict/weighted), shaping, global dot1p/DSCP→TC mapping, management priority
- **Offline protocol** — read/write HiOS config export XML files through the same driver API. A config XML file IS a device: `driver(hostname='config.xml', optional_args={'protocol_preference': ['offline']})`. All config getters/setters work, `save_config()` writes back to disk
- **Multi-interface setters** — pass a list of ports to `set_interface`, `set_rstp_port`, `set_auto_disable`, `reset_auto_disable`, `set_loop_protection`, `set_vlan_ingress`, `set_vlan_egress` for batched operations
- **MOPS atomic staging** — `start_staging()` → multiple setter calls → `commit_staging()` batches all mutations into one atomic POST (e.g. change PVID + egress together so a port never loses comms)
- **Extended LLDP** — 802.1/802.3 org-specific TLVs, multiple management addresses, autoneg, VLAN membership
- 510 unit tests and live device validation on BRS50 and GRS1042

## Installation

```
pip install napalm-hios
```

## Quick Start

```python
from napalm import get_network_driver

driver = get_network_driver('hios')

# Default: MOPS (HTTPS, atomic writes, no SNMP dependency)
device = driver('192.168.1.4', 'admin', 'private')

# Or force a specific protocol:
# device = driver('192.168.1.4', 'admin', 'private',
#                 optional_args={'protocol_preference': ['snmp']})

device.open()
print(device.get_facts())
print(device.get_interfaces())
device.close()
```

## Documentation

| Document | Contents |
|----------|----------|
| [docs/usage.md](docs/usage.md) | Standard NAPALM methods — arguments, return values, examples |
| [docs/vendor_specific.md](docs/vendor_specific.md) | Vendor methods — MRP, RSTP, HiDiscovery, factory reset, onboarding, profiles, extended LLDP |
| [docs/protocols.md](docs/protocols.md) | Protocol details — MOPS/SNMP/SSH config, known cross-protocol differences, method availability matrix |

## Supported Methods

### Standard NAPALM getters (MOPS + SNMP + SSH)

`get_facts` | `get_interfaces` | `get_interfaces_ip` | `get_interfaces_counters` | `get_lldp_neighbors` | `get_lldp_neighbors_detail` | `get_mac_address_table` | `get_arp_table` | `get_ntp_servers` | `get_ntp_stats` | `get_users` | `get_optics` | `get_environment` | `get_snmp_information` | `get_vlans`

### SSH-only (auto-connects SSH when primary is MOPS/SNMP)

`get_config` | `ping` | `cli`

### Configuration workflow

`load_merge_candidate` → `compare_config` → `commit_config` | `discard_config`

### Vendor-specific

**Read:**
`get_mrp` | `get_mrp_sub_ring` | `get_hidiscovery` | `get_rstp` | `get_rstp_port` | `get_auto_disable` | `get_loop_protection` | `get_sflow` | `get_sflow_port` | `get_storm_control` | `get_qos` | `get_qos_mapping` | `get_management_priority` | `get_management` | `get_vlan_ingress` | `get_vlan_egress` | `get_lldp_neighbors_detail_extended` | `get_config_status` | `get_profiles` | `get_config_fingerprint` | `is_factory_default`

**Write:**
`set_interface` | `set_mrp` | `delete_mrp` | `set_mrp_sub_ring` | `delete_mrp_sub_ring` | `set_hidiscovery` | `set_rstp` | `set_rstp_port` | `set_auto_disable` | `reset_auto_disable` | `set_auto_disable_reason` | `set_loop_protection` | `set_sflow` | `set_sflow_port` | `set_storm_control` | `set_qos` | `set_qos_mapping` | `set_management_priority` | `set_management` | `set_vlan_ingress` | `set_vlan_egress` | `create_vlan` | `update_vlan` | `delete_vlan` | `save_config` | `clear_config` | `clear_factory` | `activate_profile` | `delete_profile` | `onboard` | `start_staging` | `commit_staging` | `discard_staging` | `get_staged_mutations`

See [docs/vendor_specific.md](docs/vendor_specific.md) for arguments, return values, and protocol behaviour.

## Protocol Support

Default order: MOPS → SNMP → SSH. Override with `protocol_preference` in `optional_args`.

| Protocol | Transport | Auth | Atomic Write | Dependencies |
|----------|-----------|------|--------------|-------------|
| **MOPS** | HTTPS 443 | HTTP Basic | Yes (single POST) | `requests` |
| **SNMP** | UDP 161 | SNMPv3 authPriv (MD5/DES) | No | `pysnmp` |
| **SSH** | TCP 22 | Password | No | `netmiko` |
| **Offline** | XML file | None | N/A (file) | None |

MOPS is the default and preferred protocol. SSH lazy-connects on demand for SSH-only methods. Offline reads/writes HiOS config export XML files — all config getters/setters work, online-only methods return empty. See [docs/protocols.md](docs/protocols.md) for configuration, known cross-protocol differences, and the full method availability matrix.

## Testing

```bash
# Unit tests (493+)
pytest tests/unit/ -v

# Live device test
python examples/test_all_commands.py <hostname> <user> <password>
```

## Contributing

Issues and PRs welcome at [GitHub](https://github.com/AdamRickards/napalm-hios). Driver tested against BRS50 and GRS1042 hardware. If you have a HiOS device and find a bug, include firmware version and the getter output.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
