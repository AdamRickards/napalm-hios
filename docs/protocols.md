# Protocol Support

The driver supports three protocols, selected via `protocol_preference` in `optional_args`. Default order: MOPS → SNMP → SSH.

| Protocol | Transport | Auth | Bulk Read | Atomic Write | Dependencies |
|----------|-----------|------|-----------|--------------|-------------|
| **MOPS** | HTTPS POST | HTTP Basic | One request = entire table | Yes (one POST) | `requests` |
| **SNMP** | UDP 161 | SNMPv3 authPriv (MD5/DES) | GETBULK walk | No (one SET per OID) | `pysnmp` |
| **SSH** | TCP 22 | Password | CLI parsing | No (one command at a time) | `netmiko` |

MOPS is the default and preferred protocol — it uses the same internal mechanism as the HiOS web UI, supports atomic multi-table writes in a single POST, and requires only HTTP Basic auth (no USM key derivation). SSH is lazy-connected on demand when SSH-only methods are called (`get_config`, `ping`, `cli`, `commit_config` in SSH mode).

## MOPS Configuration

MOPS connects to the switch's HTTPS interface (port 443) using the same username/password as SSH/SNMP. No additional configuration needed — it just works with factory defaults.

```python
# MOPS is the default — no special config needed
device = driver(hostname='192.168.1.4', username='admin', password='private')

# Explicit MOPS with custom port
device = driver(hostname='192.168.1.4', username='admin', password='private',
                optional_args={'protocol_preference': ['mops'], 'mops_port': 443})
```

## SNMP Configuration

SNMPv3 authPriv (MD5/DES) is used when a password is provided — this matches HiOS factory defaults where SNMPv1/v2c are disabled. HiOS CLI users are the SNMPv3 users (same username/password). Falls back to SNMPv2c when password is empty (community-only mode).

Short passwords (< 8 chars, including the HiOS default `private`) are handled by pre-computing the MD5 master key, bypassing pysnmp's RFC 3414 minimum length enforcement.

```python
# SNMP-only
device = driver(hostname='192.168.1.4', username='admin', password='private',
                optional_args={'protocol_preference': ['snmp']})

# SNMP with custom port
device = driver(hostname='192.168.1.4', username='admin', password='private',
                optional_args={'protocol_preference': ['snmp'], 'snmp_port': 161})
```

## SSH Configuration

```python
# SSH-only
device = driver(hostname='192.168.1.4', username='admin', password='private',
                optional_args={'protocol_preference': ['ssh']})
```

---

## Lazy-fail Design

The driver respects the user's protocol choice. If you select SNMP and `get_facts()` times out, you get that error — the driver does not silently reroute to another protocol.

SNMP raises `NotImplementedError` for `is_factory_default()` and `onboard()` —
the SNMP agent is gated on factory-default devices and cannot be used for
onboarding. Use MOPS or SSH to onboard, then SNMP becomes available.

SSH handles both natively: `is_factory_default()` detects the password-change
prompt during `open()`, `onboard()` responds to the interactive prompts.

---

## Known Cross-Protocol Differences

MOPS and SNMP return identical data (same underlying MIB). SSH parses CLI output, which introduces these inherent differences:

| # | Area | SSH | SNMP / MOPS | Impact |
|---|------|-----|-------------|--------|
| 1 | **cpu/1 interface** | Not exposed | Exposed via IF-MIB | SNMP/MOPS returns +1 interface in `get_facts`, `get_interfaces`, `get_interfaces_counters`, `get_interfaces_ip` |
| 2 | **MAC addresses** | Base MAC (same for all ports, uppercase) | Per-port incrementing MAC (lowercase) | `get_interfaces` mac_address field differs |
| 3 | **Speed on down ports** | Shows configured speed | ifHighSpeed=0 when link is down | `get_interfaces` speed field differs for down ports |
| 4 | **Counters** | 32-bit counters | 64-bit HC counters (more accurate) | SNMP/MOPS counters wrap at 2^64 instead of 2^32 |
| 5 | **VLANs** | Configured membership only | Egress bitmap (superset) | SNMP/MOPS `get_vlans` may show extra ports |
| 6 | **ARP on L2 devices** | Fails gracefully (empty list) | Returns empty (no error) | Both return `[]`, but SSH may log a warning |
| 7 | **SNMP communities** | Readable via CLI | Cannot query via SNMP/MOPS (security) | SNMP/MOPS `get_snmp_information` always has empty `community` dict |
| 8 | **ARP age** | Calculated from CLI output (seconds) | Always 0.0 (not in standard MIB) | `get_arp_table` age field differs on L3 devices |
| 9 | **LLDP system capabilities** | Not exposed by HiOS CLI | Decoded from LLDP-MIB bitmap | SSH `remote_system_capab` is always `[]`, SNMP/MOPS returns actual capabilities |
| 10 | **Management interface name** | `vlan/N` (from CLI) | `cpu/1` (from IF-MIB) | `get_interfaces_ip` key name differs |
| 11 | **HiDiscovery relay** | Omitted on L2 devices (CLI doesn't output it) | Always present (MIB returns a value) | SNMP/MOPS `get_hidiscovery` may include `relay` field when SSH doesn't |

---

## Getter Availability by Protocol

| Method | MOPS | SSH | SNMP | Notes |
|--------|------|-----|------|-------|
| `get_facts` | Yes | Yes | Yes | |
| `get_interfaces` | Yes | Yes | Yes | |
| `get_interfaces_ip` | Yes | Yes | Yes | |
| `get_interfaces_counters` | Yes | Yes | Yes | |
| `get_lldp_neighbors` | Yes | Yes | Yes | |
| `get_lldp_neighbors_detail` | Yes | Yes | Yes | |
| `get_lldp_neighbors_detail_extended` | Yes | Yes | Yes | Vendor; SNMP adds 802.1/802.3 |
| `get_mac_address_table` | Yes | Yes | Yes | |
| `get_arp_table` | Yes | Yes | Yes | |
| `get_vlans` | Yes | Yes | Yes | |
| `get_snmp_information` | Yes | Yes | Yes | |
| `get_environment` | Yes | Yes | Yes | |
| `get_optics` | Yes | Yes | Yes | |
| `get_users` | Yes | Yes | Yes | |
| `get_ntp_servers` | Yes | Yes | Yes | |
| `get_ntp_stats` | Yes | Yes | Yes | |
| `get_mrp` | Yes | Yes | Yes | Vendor |
| `get_hidiscovery` | Yes | Yes | Yes | Vendor |
| `get_config_status` | Yes | Yes | Yes | Vendor |
| `save_config` | Yes | Yes | Yes | Vendor |
| `clear_config` | Yes | Yes | Yes | Vendor write (warm restart) |
| `clear_factory` | Yes | Yes | Yes | Vendor write (full reboot) |
| `get_config` | No | Yes | No | SSH-only (lazy-connects) |
| `ping` | No | Yes | No | SSH-only (lazy-connects) |
| `cli` | No | Yes | No | SSH-only (lazy-connects) |
| `load_merge_candidate` | Yes | Yes | Yes | MOPS: staging; SSH: in-memory |
| `compare_config` | Yes | Yes | Yes | |
| `commit_config` | Yes | Yes | Yes | MOPS: atomic POST; SSH: CLI |
| `discard_config` | Yes | Yes | Yes | |
| `get_profiles` | Yes | Yes | Yes | Vendor |
| `get_config_fingerprint` | Yes | Yes | Yes | Vendor |
| `activate_profile` | Yes | Yes | Yes | Vendor write (warm restart) |
| `delete_profile` | Yes | Yes | Yes | Vendor write |
| `set_interface` | Yes | Yes | Yes | Vendor write |
| `set_mrp` / `delete_mrp` | Yes | Yes | Yes | Vendor write |
| `set_hidiscovery` | Yes | Yes | Yes | Vendor write |
| `get_rstp` | Yes | Yes | Yes | Vendor |
| `get_rstp_port` | Yes | Yes | Yes | Vendor |
| `set_rstp` | Yes | Yes | Yes | Vendor write |
| `set_rstp_port` | Yes | Yes | Yes | Vendor write |
| `is_factory_default` | Yes | Yes | No (gated) | Vendor |
| `onboard` | Yes | Yes | No (gated) | Vendor |

---

## Known Issues

- SSH-only methods (`get_config`, `ping`, `cli`, `commit_config` in SSH mode) auto-connect SSH when the active protocol is MOPS or SNMP. If SSH credentials are incorrect or the SSH port is blocked, these methods raise `NotImplementedError`.
- `activate_profile()` triggers a warm restart — the connection will drop. Reconnect after the device reboots.
- `commit_config()` in SSH mode executes commands in configure mode. CLI errors are detected and raised as `CommitError`. NVM busy state is polled through (up to 5s) to handle back-to-back commits.
- MOPS getter output matches SNMP output (same underlying MIB data), but some MOPS MIB/Node names are still being discovered.
- NETCONF support is stub-only — not in default protocol order. Opt in via `protocol_preference=['mops', 'snmp', 'ssh', 'netconf']`.
