# Vendor-Specific Methods

These methods extend NAPALM with HiOS-specific functionality not covered
by the standard NAPALM API. They are available on all three protocols
(MOPS, SNMP, SSH) unless noted otherwise. Call them directly on the
driver object (e.g. `device.get_mrp()`).

For protocol availability of each method, see the matrix in
[protocols.md](protocols.md).

---

## Configuration Save

HiOS has three config storage layers: **running-config** (RAM),
**NVM** (internal flash — survives reboot), and **ACA** (external
SD/USB — optional).  Changes live in running-config until explicitly
saved.

### get_config_status()

Check if the running config has been saved to NVM.  Read-only, safe.

```python
status = device.get_config_status()
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
status = device.save_config()
# Returns: {'saved': True, 'nvm': 'ok', ...}
```

---

## Config Profiles

HiOS stores config snapshots as numbered profiles in NVM and ENVM.
One profile is active at any time.

### get_profiles(storage='nvm')

List all config profiles in the given storage.

```python
profiles = device.get_profiles('nvm')
```

```python
[
    {
        'index': 1,
        'name': 'config',
        'active': True,
        'datetime': '2026-02-13 13:25:16',
        'firmware': '09.4.4',
        'fingerprint': '9244C58FEA7549A1E2C80DB7608B8D75CF068A66',
        'fingerprint_verified': True,
        'encrypted': False,
        'encryption_verified': False,
    },
]
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `storage` | `'nvm'`, `'envm'` | `'nvm'` | Which storage to list profiles from |

### get_config_fingerprint()

Return SHA1 fingerprint of the active NVM profile.

```python
result = device.get_config_fingerprint()
# {'fingerprint': '9244C58F...', 'verified': True}
```

### activate_profile(storage='nvm', index=1)

Activate a config profile. **Warning**: triggers a warm restart — the
connection will drop. Reconnect after the device reboots.

Only NVM storage is supported by HiOS for profile selection.

```python
device.activate_profile('nvm', 2)
```

**Raises** `ValueError` if the profile doesn't exist, is already active,
or storage is not `'nvm'`.

### delete_profile(storage='nvm', index=1)

Delete a config profile from the given storage.

```python
device.delete_profile('nvm', 2)
```

**Raises** `ValueError` if the profile doesn't exist, is currently active,
or storage is invalid.

---

## MRP — Media Redundancy Protocol

MRP provides sub-second ring redundancy for industrial Ethernet.
A ring consists of one **manager** and one or more **clients**.
Each device contributes two **ring ports** (primary + secondary).

### get_mrp()

Returns the current MRP domain configuration and operating state.

```python
mrp = device.get_mrp()
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

**Warning**: Modifying redundancy configuration can have unpredictable
results on the network. To avoid a loop, ensure that there are no
existing loops being protected by redundancy before using MRP or RSTP
functions.

```python
# Configure as MRP client
result = device.set_mrp(
    operation='enable',
    mode='client',
    port_primary='1/3',
    port_secondary='1/4',
    vlan=1,
    recovery_delay='200ms'
)

# Reconfigure to manager mode (ports already assigned)
result = device.set_mrp(operation='enable', mode='manager')

# Disable MRP (keeps domain config)
result = device.set_mrp(operation='disable')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `operation` | `'enable'`, `'disable'` | `'enable'` | Enable or disable MRP |
| `mode` | `'manager'`, `'client'` | `'client'` | Ring role |
| `port_primary` | interface name | `None` | Primary ring port (e.g. `'1/3'`) |
| `port_secondary` | interface name | `None` | Secondary ring port (e.g. `'1/4'`) |
| `vlan` | `0`–`4042` | `None` | VLAN for MRP frames |
| `recovery_delay` | `'200ms'`, `'500ms'`, `'30ms'`, `'10ms'` | `None` | Max recovery time |

**Returns** the result of `get_mrp()` after configuration.

### delete_mrp()

Disable MRP globally and delete the MRP domain.

**Note**: If the ring manager detects that removing MRP would cause a
loop, the switch will administratively disable one of the ring ports
to prevent it.

```python
result = device.delete_mrp()
# Returns {'configured': False}
```

---

## RSTP — Rapid Spanning Tree Protocol

### get_rstp()

Returns global STP/RSTP configuration and state.

```python
rstp = device.get_rstp()
```

```python
{
    'enabled': True,
    'mode': 'rstp',                  # 'stp' | 'rstp' | 'mstp'
    'bridge_id': '80:00:...',
    'priority': 32768,
    'hello_time': 2,
    'max_age': 20,
    'forward_delay': 15,
    'hold_count': 6,
    'max_hops': 20,
    'root_id': '80:00:...',
    'root_port': 0,
    'root_path_cost': 0,
    'topology_changes': 5,
    'time_since_topology_change': 12345,
    'root_hello_time': 2,
    'root_max_age': 20,
    'root_forward_delay': 15,
    'bpdu_guard': False,
    'bpdu_filter': False,
}
```

### get_rstp_port(interface=None)

Returns per-port STP/RSTP state. If `interface` is `None`, returns all ports.

```python
ports = device.get_rstp_port()          # all ports
port = device.get_rstp_port('1/5')      # single port
```

```python
{
    '1/5': {
        'enabled': True,
        'state': 'forwarding',      # 'discarding' | 'learning' | 'forwarding' | 'disabled'
        'edge_port': False,
        'edge_port_oper': False,
        'auto_edge': True,
        'point_to_point': True,
        'path_cost': 200000,
        'priority': 128,
        'root_guard': False,
        'loop_guard': False,
        'tcn_guard': False,
        'bpdu_guard': False,
        'bpdu_filter': False,
        'bpdu_flood': False,
        'rstp_bpdu_rx': 100,
        'rstp_bpdu_tx': 200,
        'stp_bpdu_rx': 0,
        'stp_bpdu_tx': 0,
    }
}
```

### set_rstp(enabled, mode, priority, ...)

Set global STP/RSTP configuration. All parameters are optional — only
provided values are changed.

**Warning**: Modifying redundancy configuration can have unpredictable
results on the network. To avoid a loop, ensure that there are no
existing loops being protected by redundancy before using MRP or RSTP
functions.

```python
# Enable RSTP with custom priority
result = device.set_rstp(enabled=True, mode='rstp', priority=4096)

# Disable STP globally
result = device.set_rstp(enabled=False)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `enabled` | `True`, `False` | `None` | Enable/disable STP globally |
| `mode` | `'stp'`, `'rstp'`, `'mstp'` | `None` | STP variant |
| `priority` | `0`–`61440` (multiples of 4096) | `None` | Bridge priority |
| `hello_time` | `1`–`10` | `None` | Hello interval (seconds) |
| `max_age` | `6`–`40` | `None` | Max age (seconds) |
| `forward_delay` | `4`–`30` | `None` | Forward delay (seconds) |
| `hold_count` | `1`–`40` | `None` | BPDU hold count |
| `bpdu_guard` | `True`, `False` | `None` | Global BPDU guard |
| `bpdu_filter` | `True`, `False` | `None` | Global BPDU filter |

**Returns** the result of `get_rstp()` after configuration.

### set_rstp_port(interface, enabled, edge_port, ...)

Set per-port STP/RSTP configuration. All parameters except `interface`
are optional — only provided values are changed.

```python
# Configure port as edge port with root guard
result = device.set_rstp_port('1/5', edge_port=True, root_guard=True)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | interface name | required | Port to configure (e.g. `'1/5'`) |
| `enabled` | `True`, `False` | `None` | Enable/disable STP on this port |
| `edge_port` | `True`, `False` | `None` | Admin edge port |
| `auto_edge` | `True`, `False` | `None` | Auto-detect edge |
| `path_cost` | `0`–`200000000` | `None` | Port path cost |
| `priority` | `0`–`240` (multiples of 16) | `None` | Port priority |
| `root_guard` | `True`, `False` | `None` | Root guard |
| `loop_guard` | `True`, `False` | `None` | Loop guard |
| `tcn_guard` | `True`, `False` | `None` | TCN guard |
| `bpdu_filter` | `True`, `False` | `None` | Per-port BPDU filter |
| `bpdu_flood` | `True`, `False` | `None` | BPDU flood |

**Returns** the result of `get_rstp_port(interface)` after configuration.

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
result = device.get_hidiscovery()
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

### set_hidiscovery(status, blinking=None)

Set HiDiscovery operating mode.

```python
# Disable HiDiscovery (recommended for secured networks)
result = device.set_hidiscovery('off')

# Enable read-only (recommended for production)
result = device.set_hidiscovery('ro')

# Enable read-write (commissioning only)
result = device.set_hidiscovery('on')

# Toggle blinking
result = device.set_hidiscovery('ro', blinking='toggle')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `status` | `'on'`, `'off'`, `'ro'` | required | Operating mode |
| `blinking` | `True`, `False`, `'toggle'`, `None` | `None` | LED blinking control |

| Status | Mode | Description |
|--------|------|-------------|
| `'off'` | disabled | HiDiscovery completely disabled |
| `'ro'` | read-only | Device visible in HiDiscovery tool but not remotely configurable |
| `'on'` | read-write | Full remote configuration via HiDiscovery tool |

**Returns** the result of `get_hidiscovery()` after the change.

---

## Factory Onboarding (MOPS + SSH)

HiOS 10.3+ forces a password change on first login before any CLI or
SNMP access is available. These methods detect and handle that state.

### is_factory_default()

Check if the device is in factory-default password state.

```python
if device.is_factory_default():
    device.onboard('NewPassword1')
```

**Returns** `bool` — `True` if the device still requires initial password setup.

### onboard(new_password)

Change the default password on a factory-fresh device, unlocking CLI
and SNMP access. The new password can be the same as the current one —
the act of calling the endpoint clears the factory gate.

```python
device.onboard('NewPassword1')
```

**Raises** `ConnectionException` if the device is already onboarded
(calling this on an onboarded device causes a cold reset).

**Returns** `True` on success.

---

## Factory Reset (MOPS)

### clear_config(keep_ip=False)

Clear running config (back to default). Device warm-restarts —
connection will drop.

```python
result = device.clear_config()
result = device.clear_config(keep_ip=True)  # preserve management IP
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `keep_ip` | `True`, `False` | `False` | Preserve management IP address |

**Returns** `{'restarting': True}`

### clear_factory(erase_all=False)

Full factory reset. Wipes RAM, NVM, ENVM, SSH keys, HTTPS certs.
Device reboots — connection will drop.

```python
result = device.clear_factory()
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `erase_all` | `True`, `False` | `False` | Extended wipe |

**Returns** `{'rebooting': True}`

---

## MOPS Atomic Staging (MOPS-only)

MOPS supports batching multiple configuration changes into a single
atomic POST request. This is used internally by `commit_config()` but
can also be called directly.

### start_staging()

Enter staging mode — SET operations are queued instead of sent.

```python
device.start_staging()
```

### get_staged_mutations()

Return the list of queued mutations.

```python
mutations = device.get_staged_mutations()
```

### commit_staging()

Fire all queued mutations in one atomic POST, then save to NVM.

```python
device.commit_staging()
```

### discard_staging()

Clear queued mutations without sending.

```python
device.discard_staging()
```

---

## Config Watchdog (SNMP-only)

The config watchdog provides an automatic rollback safety net. If the
timer expires before `stop_watchdog()` is called, the device reverts
to the saved NVM config automatically.

### start_watchdog(seconds)

Start the config watchdog timer.

```python
device.start_watchdog(60)  # 60-second rollback timer
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `seconds` | `30`–`600` | required | Timer interval in seconds |

### stop_watchdog()

Stop the watchdog timer (confirms the config change is intentional).

```python
device.stop_watchdog()
```

### get_watchdog_status()

Read current watchdog state.

```python
status = device.get_watchdog_status()
```

```python
{
    'enabled': True,
    'oper_status': 1,
    'interval': 60,
    'remaining': 45,
}
```

---

## Extended LLDP

### get_lldp_neighbors_detail_extended(interface='')

Returns all LLDP TLV fields including management addresses (IPv4 + IPv6),
autonegotiation, VLAN membership, link aggregation, and MAU type — fields
not available in the standard NAPALM `get_lldp_neighbors_detail()`.

```python
extended = device.get_lldp_neighbors_detail_extended()
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

## CLI Mode Helpers (SSH-only)

These are used internally by the vendor-specific methods but can also
be called directly for custom configuration sequences.

| Method | Description |
|--------|-------------|
| `_enable()` | Enter privileged (enable) mode — prompt changes from `>` to `#` |
| `_disable()` | Exit enable mode back to user mode |
| `_config_mode()` | Enter global config mode (`enable` → `configure`) |
| `_exit_config_mode()` | Exit config mode back to user mode (`exit` → `disable`) |

```python
# Custom config sequence example (SSH backend)
device.ssh._config_mode()
try:
    device.ssh.cli('some-config-command arg1 arg2')
finally:
    device.ssh._exit_config_mode()
```
