# Vendor-Specific Methods

These methods extend NAPALM with HiOS-specific functionality not covered
by the standard NAPALM API.  They are accessed through the SSH driver's
internal `ssh` object or via `device.cli()`.

## Configuration Save

HiOS has three config storage layers: **running-config** (RAM),
**NVM** (internal flash — survives reboot), and **ACA** (external
SD/USB — optional).  Changes live in running-config until explicitly
saved.

### get_config_status()

Check if the running config has been saved to NVM.  Read-only, safe.

```python
status = device.ssh.get_config_status()
```

```python
{
    'saved': True,     # running-config == NVM
    'nvm': 'ok',       # 'ok' | 'out of sync' | 'busy'
    'aca': 'absent',   # 'ok' | 'out of sync' | 'absent'
    'boot': 'ok',
}
```

| State | Meaning |
|-------|---------|
| `nvm: ok` | Running config matches NVM (saved) |
| `nvm: out of sync` | Unsaved changes exist |
| `nvm: busy` | NVM write in progress (transient) |
| `aca: ok` | External memory matches NVM |
| `aca: absent` | No SD card / USB present |
| `aca: out of sync` | External memory differs from NVM |

### save_config()

Save running config to NVM.  Waits for the NVM write to complete
(up to 10s) before returning.

```python
status = device.ssh.save_config()
# Returns: {'saved': True, 'nvm': 'ok', ...}
```

---

## MRP — Media Redundancy Protocol

MRP provides sub-second ring redundancy for industrial Ethernet.
A ring consists of one **manager** and one or more **clients**.
Each device contributes two **ring ports** (primary + secondary).

### get_mrp()

Returns the current MRP domain configuration and operating state.

```python
device.open()
mrp = device.ssh.get_mrp()
```

**Returns** when MRP is configured:

```python
{
    'configured': True,
    'operation': 'enabled',             # 'enabled' | 'disabled'
    'mode': 'client',                   # 'manager' | 'client'
    'mode_actual': 'client',            # real operating mode
    'port_primary': '1/3',
    'port_secondary': '1/4',
    'port_primary_state': 'forwarding', # 'forwarding' | 'blocked' | 'not connected'
    'port_secondary_state': 'blocked',
    'domain_id': '255.255...255 (Default)',
    'domain_name': '',
    'vlan': 1,                          # VLAN ID for MRP frames
    'recovery_delay': '200ms',          # '200ms' | '500ms'
    'recovery_delay_supported': ['200ms', '500ms'],
    'advanced_mode': True,              # react on link change
    'manager_priority': 32768,          # 0-65535
    'fixed_backup': False,
    'fast_mrp': False,                  # only present on some models
    'info': 'no error',                 # general status message
    'ring_state': 'closed',             # manager: 'closed' | 'open' | 'undefined'
    'redundancy': True,                 # manager: ring is redundant
    'ring_open_count': 2,               # manager: number of ring-open events
    'blocked_support': True,            # client field
}
```

**Returns** when no MRP domain exists:

```python
{'configured': False}
```

### set_mrp(operation, mode, port_primary, port_secondary, vlan, recovery_delay)

Configure MRP on the default domain.

**Safety**: Refuses to assign ring ports that are currently **link-up**.
This prevents accidentally disrupting a live production network.
Only disconnected ports can be assigned as ring ports.

```python
# Configure as MRP client on disconnected ports
result = device.ssh.set_mrp(
    operation='enable',
    mode='client',
    port_primary='1/3',
    port_secondary='1/4',
    vlan=1,
    recovery_delay='200ms'
)

# Reconfigure to manager mode (ports already assigned)
result = device.ssh.set_mrp(operation='enable', mode='manager')

# Disable MRP (keeps domain config)
result = device.ssh.set_mrp(operation='disable')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `operation` | `'enable'`, `'disable'` | `'enable'` | Enable or disable MRP |
| `mode` | `'manager'`, `'client'` | `'client'` | Ring role |
| `port_primary` | interface name | `None` | Primary ring port (e.g. `'1/3'`) |
| `port_secondary` | interface name | `None` | Secondary ring port (e.g. `'1/4'`) |
| `vlan` | `0`–`4042` | `None` | VLAN for MRP frames |
| `recovery_delay` | `'200ms'`, `'500ms'`, `'30ms'`, `'10ms'` | `None` | Max recovery time |

**Raises** `ValueError` if a specified port is currently link-up.

**Returns** the result of `get_mrp()` after configuration.

### delete_mrp()

Disable MRP globally and delete the MRP domain.

```python
result = device.ssh.delete_mrp()
# Returns {'configured': False}
```

---

## HiDiscovery Protocol

HiDiscovery is Belden's proprietary device discovery and configuration
protocol.  In **read-write** mode, devices can be remotely configured
(IP address, name) from the HiDiscovery PC tool.  **Read-only** mode
allows discovery without remote configuration.  Production devices should
use read-only or disabled.

### get_hidiscovery()

Returns HiDiscovery protocol status.

```python
result = device.ssh.get_hidiscovery()
```

```python
{
    'enabled': True,
    'mode': 'read-only',       # 'read-only' | 'read-write'
    'blinking': False,
    'protocols': ['v1', 'v2'],
    'relay': True              # only on L3/managed switches
}
```

### set_hidiscovery(status)

Set HiDiscovery operating mode.

```python
# Disable HiDiscovery (recommended for secured networks)
result = device.ssh.set_hidiscovery('off')

# Enable read-only (recommended for production)
result = device.ssh.set_hidiscovery('ro')

# Enable read-write (commissioning only)
result = device.ssh.set_hidiscovery('on')
```

| Status | Mode | Description |
|--------|------|-------------|
| `'off'` | disabled | HiDiscovery completely disabled |
| `'ro'` | read-only | Device visible in HiDiscovery tool but not remotely configurable |
| `'on'` | read-write | Full remote configuration via HiDiscovery tool |

**Returns** the result of `get_hidiscovery()` after the change.

---

## Extended LLDP

### get_lldp_neighbors_detail_extended(interface='')

Returns all LLDP TLV fields from `show lldp remote-data`, including
management addresses (IPv4 + IPv6), autonegotiation, VLAN membership,
link aggregation, and MAU type — fields not available in the standard
NAPALM `get_lldp_neighbors_detail()`.

```python
extended = device.ssh.get_lldp_neighbors_detail_extended()
for port, neighbors in extended.items():
    for n in neighbors:
        print(f"{port}: {n['remote_system_name']}")
        print(f"  Management IPs: {n['management_addresses']}")
        print(f"  Capabilities: {n['remote_system_capab']}")
```

Key fields beyond standard NAPALM:
- `management_addresses` — list of all IPv4 + IPv6 management addresses
- `remote_management_ipv4` / `remote_management_ipv6` — first of each type
- `autoneg_support` / `autoneg_enabled`
- `port_oper_mau_type`
- `port_vlan_id`
- `vlan_membership` — list of VLAN IDs
- `link_agg_status` / `link_agg_port_id`

---

## CLI Mode Helpers

These are used internally by the vendor-specific methods but can also
be called directly for custom configuration sequences.

| Method | Description |
|--------|-------------|
| `_enable()` | Enter privileged (enable) mode — prompt changes from `>` to `#` |
| `_disable()` | Exit enable mode back to user mode |
| `_config_mode()` | Enter global config mode (`enable` → `configure`) |
| `_exit_config_mode()` | Exit config mode back to user mode (`exit` → `disable`) |

```python
# Custom config sequence example
device.ssh._config_mode()
try:
    device.ssh.cli('some-config-command arg1 arg2')
finally:
    device.ssh._exit_config_mode()
```
