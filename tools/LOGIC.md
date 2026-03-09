# Tools — Driver Method Cross-Reference

Which napalm-hios driver methods each tool uses. Excludes `open()`, `close()`, and `save_config()` (shared by all).

## Getters

| Method | AARON | STONE | MOHAWC | CLAMPS | VIKTOR | Domain |
|--------|-------|-------|--------|--------|--------|--------|
| `get_facts()` | x | x | x | x | x | System |
| `get_interfaces()` | | | x | x | | Ports |
| `get_environment()` | | | x | | | Hardware |
| `get_config_status()` | | | x | | | Config |
| `get_config_fingerprint()` | | | x | | | Config |
| `get_config()` | | | x | | | Config |
| `get_profiles()` | | | x | | | Config |
| `get_config_remote()` | | | x | | | Config |
| `is_factory_default()` | | | x | | | Config |
| `get_hidiscovery()` | | | x | | | HiDiscovery |
| `get_management()` | | | x | | | Management |
| `get_snmp_information()` | | | x | | | System |
| `get_optics()` | | x | | | | SFP |
| `get_mac_address_table()` | x | | | | | L2 |
| `get_arp_table()` | x | | | | | L3 |
| `get_lldp_neighbors_detail()` | | | x | | x | Topology |
| `get_lldp_neighbors_detail_extended()` | x | | | | | Topology |
| `get_vlan_ingress()` | | | | | x | VLAN |
| `get_vlan_egress()` | | | | | x | VLAN |
| `get_qos()` | | | | | x | QoS |
| `get_mrp()` | | | | x | | Redundancy |
| `get_mrp_sub_ring()` | | | | x | | Redundancy |
| `get_rstp()` | | | | x | | Redundancy |
| `get_rstp_port()` | | | | x | | Redundancy |
| `get_loop_protection()` | | | | x | | Protection |
| `get_auto_disable()` | | | | x | | Protection |
| `get_storm_control()` | | | | x | | Protection |

## Setters

| Method | MOHAWC | CLAMPS | VIKTOR | Domain |
|--------|--------|--------|--------|--------|
| `onboard()` | x | | | Commissioning |
| `clear_config()` | x | | | Commissioning |
| `clear_factory()` | x | | | Commissioning |
| `set_hidiscovery()` | x | | | HiDiscovery |
| `set_management()` | x | | | Management |
| `set_snmp_information()` | x | | | System |
| `set_config_remote()` | x | | | Config |
| `load_config()` | x | | | Config |
| `activate_profile()` | x | | | Config |
| `delete_profile()` | x | | | Config |
| `ping()` | x | | | Diagnostics |
| `cli()` | x | | | Diagnostics |
| `create_vlan()` | | | x | VLAN |
| `delete_vlan()` | | | x | VLAN |
| `update_vlan()` | | | x | VLAN |
| `set_vlan_egress()` | | | x | VLAN |
| `set_vlan_ingress()` | | | x | VLAN |
| `set_qos()` | | | x | QoS |
| `set_interface()` | | x | | Ports |
| `set_mrp()` | | x | | Redundancy |
| `delete_mrp()` | | x | | Redundancy |
| `set_mrp_sub_ring()` | | x | | Redundancy |
| `delete_mrp_sub_ring()` | | x | | Redundancy |
| `set_rstp()` | | x | | Redundancy |
| `set_rstp_port()` | | x | | Redundancy |
| `set_loop_protection()` | | x | | Protection |
| `set_auto_disable()` | | x | | Protection |
| `set_auto_disable_reason()` | | x | | Protection |
| `reset_auto_disable()` | | x | | Protection |
| `set_storm_control()` | | x | | Protection |

## Staging

| Method | CLAMPS | VIKTOR | Notes |
|--------|--------|--------|-------|
| `start_staging()` | x | x | MOPS/Offline only — batches mutations into one atomic POST |
| `commit_staging()` | x | x | Applies all staged changes |
| `discard_staging()` | | x | Rollback staged changes |

SNMP and SSH ignore staging calls — changes are sent individually.

## Standalone Tools

**MARCO** and **SNOOP** do not use napalm-hios.

| Tool | Protocol | Purpose |
|------|----------|---------|
| MARCO | HiDiscovery v2 (SNMPv2c multicast) | Device discovery + IP/name/blink configuration |
| SNOOP | sFlow v5 (UDP) | Passive traffic observation + FDB/ARP/VLAN reconstruction |

## Domain Ownership

Each domain has one tool that owns the writes. No two tools write to the same domain.

```
Commissioning     → MOHAWC   (onboard, reset, profiles, system, management)
VLAN + QoS        → VIKTOR   (create, delete, rename, access, trunk, QoS)
Redundancy        → CLAMPS   (MRP, RSTP, sub-rings)
Protection        → CLAMPS   (loop protection, auto-disable, storm control)
Discovery (L2)    → MARCO    (HiDiscovery multicast)
Discovery (L3)    → AARON    (LLDP + MAC + ARP, read-only)
Optics            → STONE    (SFP power levels, read-only)
Traffic           → SNOOP    (sFlow, passive listener)
Disruption        → BLIP     (multicast probe, planned)
```

Read-only tools (AARON, STONE, SNOOP) can run anytime without conflict.
Write tools (MOHAWC, VIKTOR, CLAMPS) operate on separate MIB domains — no overlap.
