# NAPALM HiOS Driver

NAPALM driver for Hirschmann HiOS industrial switches by Belden. Supports SSH and SNMPv3 protocols with full getter parity across both.

## Features

- **Dual protocol**: SNMPv3 (default) and SSH with lazy auto-connect
- **SNMPv3 authPriv** (MD5/DES) — works with HiOS factory defaults including short passwords
- **20 getters** on both SSH + SNMP, plus 3 SSH-only methods
- **Candidate config workflow**: `load_merge_candidate` → `compare_config` → `commit_config` with NVM sync safety checks and optional config watchdog auto-revert
- **Profile management**: list, fingerprint, activate, delete config profiles via SNMP
- Vendor-specific: MRP ring redundancy, HiDiscovery, extended LLDP, config save/status
- Comprehensive unit tests (193+) and live device validation

## Installation

To install the NAPALM HiOS driver, run:

```
pip install napalm-hios
```

## Quick Start

Here's a basic example of how to use the NAPALM HiOS driver:

```python
from napalm import get_network_driver

# Initialize the driver
driver = get_network_driver('hios')
device = driver(
    hostname='your_device_ip',
    username='your_username',
    password='your_password',
    optional_args={'ssh_port': 22}  # Optional: specify SSH port if different from default
)

# Open the connection
device.open()

# Use NAPALM methods
facts = device.get_facts()
interfaces = device.get_interfaces()

# Close the connection
device.close()
```
If you want to see it in action without a specific purpose or use case, simply create your virtual environment, install with the pip command above and then execute the test_hios.py file found in examples/test_all_commands.py
This command takes <hostname> <username> <password> [ip address for ping] [count] (with the later two being optional)
it will log the json returned dicts into the current folder in a file called test_live_device.md

## Documentation

For detailed information about the NAPALM HiOS driver, including supported methods, advanced usage, and error handling, please refer to the [comprehensive documentation](docs/usage.md).
This docuemntation was written by Claude from Anthropic so if anything is wrong I take no responsibility.

## Supported Methods

### Standard NAPALM getters (SSH + SNMP)

- `get_facts()`
- `get_interfaces()`
- `get_interfaces_ip()`
- `get_interfaces_counters()`
- `get_lldp_neighbors()`
- `get_lldp_neighbors_detail()`
- `get_mac_address_table()`
- `get_arp_table()`
- `get_ntp_servers()`
- `get_ntp_stats()`
- `get_users()`
- `get_optics()`
- `get_environment()`
- `get_snmp_information()`
- `get_vlans()`

### SSH-only standard methods

- `get_config()` — CLI scraping (auto-connects SSH if active protocol is SNMP)
- `ping()` — device-originated ping (auto-connects SSH)
- `cli()` — raw command execution (auto-connects SSH)

### Configuration workflow

- `load_merge_candidate()` — stage CLI commands for later commit
- `compare_config()` — return staged commands
- `commit_config()` — execute staged commands via SSH, save to NVM (with optional watchdog auto-revert)
- `discard_config()` — clear staged commands
- `rollback()` — not supported (use `activate_profile()` for atomic profile switching)

### Vendor-specific methods (SSH + SNMP)

- `get_mrp()` — MRP ring redundancy status
- `get_hidiscovery()` — HiDiscovery protocol status
- `get_lldp_neighbors_detail_extended()` — LLDP with 802.1/802.3 extensions
- `get_config_status()` — check if running config is saved to NVM
- `save_config()` — save running config to NVM
- `get_profiles()` — list config profiles (SSH + SNMP)
- `get_config_fingerprint()` — SHA1 fingerprint of active profile (SSH + SNMP)
- `activate_profile()` — activate a config profile (causes warm restart)
- `delete_profile()` — delete an inactive profile

### Vendor-specific write operations (SSH + SNMP)

- `set_mrp()` — configure MRP ring on default domain
- `delete_mrp()` — disable and delete MRP domain
- `set_hidiscovery()` — set HiDiscovery mode (on/off/read-only) + LED blinking

For vendor-specific method details, see [docs/vendor_specific.md](docs/vendor_specific.md). For standard method details, see [docs/usage.md](docs/usage.md).

## Example

```
python -m examples/ssh_examply.py
```
Note: the example runs with user permissions against an online application lab provided by Hirschmann in Germany, this limits which commands you can execute.

For more details about the application lab, see http://applicationlab.hirschmann.de/remoteaccess

## Testing

To run the unit tests:

```
python -m unittest discover tests/unit
```

To run the integration tests (requires a real HiOS device or a properly configured mock):

```
python -m unittest discover tests/integration
```

Note: I've been using example/test_all_commands.py against real devices by calling it with <hostname> <user> <password> <ping ip> <count>, the ping ip and count are optional and will default to 8.8.8.8 if not specified. This writes results to test_live_device.md and i've included an example output from a live device

## Mock Device

The driver includes a mock HiOS device for testing and development purposes. To use the mock device, set the hostname to 'localhost' when initializing the driver.

Note: The mock device functionality is still in development

## To-do

Some musings about what to do for next release, [Wishlist](TODO.md), feel free to make suggestions if you have a specific need.

## Protocol Support

The driver supports SSH and SNMPv3 protocols, selected via `protocol_preference` in `optional_args`. Default order: SNMP → SSH → NETCONF.

SNMP is the default protocol (lower overhead, stateless). SSH is lazy-connected on demand when SSH-only methods are called (`get_config`, `ping`, `cli`, `commit_config`). To use SSH as the primary protocol, set `protocol_preference: ['ssh']`.

### SNMP Configuration

SNMPv3 authPriv (MD5/DES) is used when a password is provided — this matches HiOS factory defaults where SNMPv1/v2c are disabled. HiOS CLI users are the SNMPv3 users (same username/password). Falls back to SNMPv2c when password is empty (community-only mode).

```python
device = driver(
    hostname='192.168.1.4',
    username='admin',
    password='private',
    optional_args={'protocol_preference': ['snmp']}
)
```

Short passwords (< 8 chars, including the HiOS default `private`) are handled by pre-computing the MD5 master key, bypassing pysnmp's RFC 3414 minimum length enforcement.

### SSH vs SNMP — Known Differences

Both protocols implement the same NAPALM getters, but there are inherent differences in the data returned:

| # | Area | SSH | SNMP | Impact |
|---|------|-----|------|--------|
| 1 | **cpu/1 interface** | Not exposed | Exposed via IF-MIB | SNMP returns +1 interface in `get_facts`, `get_interfaces`, `get_interfaces_counters`, `get_interfaces_ip` |
| 2 | **MAC addresses** | Base MAC (same for all ports, uppercase) | Per-port incrementing MAC (lowercase) | `get_interfaces` mac_address field differs |
| 3 | **Speed on down ports** | Shows configured speed | ifHighSpeed=0 when link is down | `get_interfaces` speed field differs for down ports |
| 4 | **Counters** | 32-bit counters | 64-bit HC counters (more accurate) | SNMP counters wrap at 2^64 instead of 2^32 |
| 5 | **VLANs** | Configured membership only | Egress bitmap (superset) | SNMP `get_vlans` may show extra ports |
| 6 | **ARP on L2 devices** | Fails gracefully (empty list) | Returns empty (no error) | Both return `[]`, but SSH may log a warning |
| 7 | **SNMP communities** | Readable via CLI | Cannot query via SNMP (security) | SNMP `get_snmp_information` always has empty `community` dict |
| 8 | **ARP age** | Calculated from CLI output (seconds) | Always 0.0 (not in standard MIB) | `get_arp_table` age field differs on L3 devices |
| 9 | **LLDP system capabilities** | Not exposed by HiOS CLI | Decoded from LLDP-MIB bitmap | SSH `remote_system_capab` is always `[]`, SNMP returns actual capabilities |
| 10 | **Management interface name** | `vlan/N` (from CLI) | `cpu/1` (from IF-MIB) | `get_interfaces_ip` key name differs |
| 11 | **HiDiscovery relay** | Omitted on L2 devices (CLI doesn't output it) | Always present (MIB returns a value) | SNMP `get_hidiscovery` may include `relay` field when SSH doesn't |

### Implementation Priority

When implementing getters, this priority order is followed:

1. **NAPALM spec compliance** — match the standard return format
2. **SSH/SNMP alignment** — same keys, same structure, minimal surprises
3. **Raw OID accuracy** — use the most precise MIB data available
4. **Error handling** — graceful degradation, never crash on missing data

### Getter Availability by Protocol

| Method | SSH | SNMP | Notes |
|--------|-----|------|-------|
| `get_facts` | Yes | Yes | |
| `get_interfaces` | Yes | Yes | |
| `get_interfaces_ip` | Yes | Yes | |
| `get_interfaces_counters` | Yes | Yes | |
| `get_lldp_neighbors` | Yes | Yes | |
| `get_lldp_neighbors_detail` | Yes | Yes | |
| `get_lldp_neighbors_detail_extended` | Yes | Yes | Vendor; SNMP adds 802.1/802.3 data |
| `get_mac_address_table` | Yes | Yes | |
| `get_arp_table` | Yes | Yes | |
| `get_vlans` | Yes | Yes | |
| `get_snmp_information` | Yes | Yes | |
| `get_environment` | Yes | Yes | |
| `get_optics` | Yes | Yes | |
| `get_users` | Yes | Yes | |
| `get_ntp_servers` | Yes | Yes | |
| `get_ntp_stats` | Yes | Yes | |
| `get_mrp` | Yes | Yes | Vendor (MRP ring redundancy) |
| `get_hidiscovery` | Yes | Yes | Vendor (HiDiscovery protocol) |
| `get_config_status` | Yes | Yes | Vendor (NVM/ACA/boot sync state) |
| `save_config` | Yes | Yes | Vendor (save running-config to NVM) |
| `get_config` | Yes | No | SSH-only (lazy-connects SSH) |
| `ping` | Yes | No | SSH-only (lazy-connects SSH) |
| `cli` | Yes | No | SSH-only (lazy-connects SSH) |
| `load_merge_candidate` | Yes | Yes | In-memory staging |
| `compare_config` | Yes | Yes | Returns staged commands |
| `commit_config` | Yes | Yes | SSH execution + NVM save |
| `discard_config` | Yes | Yes | Clears staged commands |
| `get_profiles` | Yes | Yes | Vendor (config profile list) |
| `get_config_fingerprint` | Yes | Yes | Vendor (active profile SHA1) |
| `activate_profile` | Yes | Yes | Vendor write (warm restart) |
| `delete_profile` | Yes | Yes | Vendor write |
| `set_mrp` / `delete_mrp` | Yes | Yes | Vendor write (MRP ring config) |
| `set_hidiscovery` | Yes | Yes | Vendor write (mode + blinking) |

## Known Issues

- SSH-only methods (`get_config`, `ping`, `cli`, `commit_config`) auto-connect SSH when the active protocol is SNMP. If SSH credentials are incorrect or the SSH port is blocked, these methods raise `NotImplementedError`.
- `activate_profile()` triggers a warm restart — the SSH connection will drop. Reconnect after the device reboots.
- NETCONF support is stub-only — not usable for production.

## Contributing

Contributions to the NAPALM HiOS driver are welcome! Please refer to the CONTRIBUTING.md file for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
