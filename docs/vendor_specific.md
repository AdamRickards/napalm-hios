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

## MRP Sub-Ring (SRM)

Sub-ring support for MRP. A sub-ring branches off a main MRP ring at two
branch-point devices (SRM and RSRM). Sub-ring clients are configured as
regular MRP clients on a different VLAN.

**Protocols**: MOPS, SNMP, SSH.

### get_mrp_sub_ring()

Returns sub-ring (SRM) configuration and operating state.

```python
result = device.get_mrp_sub_ring()
```

```python
{
    'enabled': True,                  # global SRM admin state
    'max_instances': 8,               # max sub-ring instances (read-only)
    'instances': [
        {
            'ring_id': 1,
            'mode': 'manager',            # admin: manager / redundantManager / singleManager
            'mode_actual': 'manager',     # oper: manager / redundantManager / singleManager / disabled
            'vlan': 200,
            'domain_id': 'ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff',
            'partner_mac': '00:80:63:A1:B2:C3',
            'protocol': 'mrp',
            'name': '',
            'port': '1/3',
            'port_state': 'forwarding',   # disabled / blocked / forwarding / not-connected
            'ring_state': 'closed',       # undefined / open / closed
            'redundancy': True,           # True = guaranteed, False = not guaranteed
            'info': 'no error',
        },
    ]
}

# When nothing configured:
{'enabled': False, 'max_instances': 8, 'instances': []}
```

### set_mrp_sub_ring(ring_id, enabled, mode, port, vlan, name)

Configure SRM globally or create/modify a sub-ring instance.

```python
# Enable SRM globally
device.set_mrp_sub_ring(enabled=True)

# Create a sub-ring instance (auto-enables global SRM)
device.set_mrp_sub_ring(
    ring_id=1,
    mode='manager',          # 'manager', 'redundantManager', or 'singleManager'
    port='1/3',
    vlan=200,
    name='sub-ring-1',       # optional
)

# Configure redundant manager on the other branch-point device
device.set_mrp_sub_ring(
    ring_id=1,
    mode='redundantManager',
    port='1/3',
    vlan=200,
)
```

**Returns** the result of `get_mrp_sub_ring()` after configuration.

### delete_mrp_sub_ring(ring_id)

Delete a sub-ring instance or disable SRM globally.

```python
# Delete a specific instance
device.delete_mrp_sub_ring(ring_id=1)

# Disable SRM globally (no ring_id)
device.delete_mrp_sub_ring()
```

**Returns** the result of `get_mrp_sub_ring()` after deletion.

---

## VLAN Ingress/Egress

Per-port VLAN ingress settings (PVID, frame types, filtering) and per-VLAN
egress membership (Tagged/Untagged/Forbidden) with full CRUD.

### get_vlan_ingress(*ports)

Returns per-port ingress settings. No args = all ports.

```python
result = device.get_vlan_ingress()
result = device.get_vlan_ingress('1/1', '1/5')  # specific ports
```

```python
{
    '1/1': {'pvid': 1, 'frame_types': 'admit_all', 'ingress_filtering': False},
    '1/5': {'pvid': 3, 'frame_types': 'admit_only_tagged', 'ingress_filtering': True},
}
```

### get_vlan_egress(*ports)

Returns per-VLAN-per-port membership. No args = all ports. Ports not in a
VLAN's egress table are omitted (absence = not a member). VLANs with no
matching ports are omitted when filtering.

```python
result = device.get_vlan_egress()
result = device.get_vlan_egress('1/1')  # only port 1/1 data
```

```python
{
    1: {
        'name': 'default',
        'ports': {'1/1': 'untagged', '1/2': 'tagged', '1/3': 'forbidden'}
    },
    100: {
        'name': 'MRP-VLAN',
        'ports': {'1/5': 'tagged', '1/6': 'tagged'}
    },
}
```

| Mode | Meaning |
|------|---------|
| `tagged` | Port is in EgressPorts AND NOT in UntaggedPorts |
| `untagged` | Port is in EgressPorts AND in UntaggedPorts |
| `forbidden` | Port is in ForbiddenEgressPorts (prevents GVRP/MVRP override) |

### set_vlan_ingress(port, pvid, frame_types, ingress_filtering)

Set ingress parameters on one or more ports. `None` = don't change.
Pass a list of port names to configure multiple ports in one call.

```python
device.set_vlan_ingress('1/1', pvid=100)
device.set_vlan_ingress('1/1', frame_types='admit_only_tagged', ingress_filtering=True)
device.set_vlan_ingress('1/1', pvid=1, frame_types='admit_all', ingress_filtering=False)
device.set_vlan_ingress(['1/1', '1/2'], pvid=5, frame_types='admit_all')  # multiple ports
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `port` | `str` or `list` | required | Port(s) to configure (e.g. `'1/1'` or `['1/1', '1/2']`) |
| `pvid` | `1`–`4042` | `None` | Port VLAN ID |
| `frame_types` | `'admit_all'`, `'admit_only_tagged'` | `None` | Acceptable frame types |
| `ingress_filtering` | `True`, `False` | `None` | Enable/disable ingress filtering |

### set_vlan_egress(vlan_id, port, mode)

Set egress membership for one VLAN on one or more ports. The VLAN must
already exist in the VLAN database — use `create_vlan()` first if needed.
Pass a list of port names to configure multiple ports in one call.

```python
device.set_vlan_egress(100, '1/1', 'tagged')
device.set_vlan_egress(100, '1/1', 'untagged')
device.set_vlan_egress(100, '1/1', 'forbidden')
device.set_vlan_egress(100, '1/1', 'none')       # remove from VLAN
device.set_vlan_egress(100, ['1/1', '1/2'], 'tagged')  # multiple ports
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `vlan_id` | `1`–`4042` | required | VLAN ID |
| `port` | `str` or `list` | required | Port(s) to configure (e.g. `'1/1'` or `['1/1', '1/2']`) |
| `mode` | `'tagged'`, `'untagged'`, `'forbidden'`, `'none'` | required | Membership mode |

### create_vlan(vlan_id, name)

Create a VLAN in the VLAN database.

```python
device.create_vlan(100)
device.create_vlan(100, name='Production')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `vlan_id` | `2`–`4042` | required | VLAN ID to create |
| `name` | string | `''` | Optional VLAN name |

### update_vlan(vlan_id, name)

Rename an existing VLAN.

```python
device.update_vlan(100, 'Production-v2')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `vlan_id` | `1`–`4042` | required | VLAN ID to rename |
| `name` | string | required | New VLAN name |

### delete_vlan(vlan_id)

Delete a VLAN from the VLAN database.

```python
device.delete_vlan(100)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `vlan_id` | `2`–`4042` | required | VLAN ID to delete |

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
are optional — only provided values are changed. Pass a list of
interface names to configure multiple ports in one call.

```python
# Configure port as edge port with root guard
result = device.set_rstp_port('1/5', edge_port=True, root_guard=True)

# Configure multiple ports at once
device.set_rstp_port(['1/1', '1/2', '1/3'], edge_port=True, auto_edge=False)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | `str` or `list` | required | Port(s) to configure (e.g. `'1/5'` or `['1/1', '1/2']`) |
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

No-op if no parameters besides `interface` are provided.

---

## Auto-Disable

Auto-disable is a port enforcement mechanism. When a monitored condition
triggers (e.g. loop detected, CRC errors, link flapping), the port is
automatically shut down for a configurable recovery interval. After the
timer expires, the port re-enables automatically.

### get_auto_disable()

Returns per-interface auto-disable status and per-reason enable/disable
configuration.

```python
ad = device.get_auto_disable()
```

```python
{
    'interfaces': {
        '1/1': {
            'timer': 0,                     # recovery timer (seconds), 0 = disabled
            'reason': 'none',               # trigger reason or 'none'
            'active': False,                # True if port is currently auto-disabled
            'component': '',                # feature component that triggered
            'remaining_time': 0,            # seconds until recovery
            'error_time': '',               # ISO timestamp when error occurred
        },
        # ... one entry per port
    },
    'reasons': {
        'link-flap':           {'enabled': False, 'category': 'port-monitor'},
        'crc-error':           {'enabled': False, 'category': 'port-monitor'},
        'duplex-mismatch':     {'enabled': False, 'category': 'port-monitor'},
        'dhcp-snooping':       {'enabled': False, 'category': 'network-security'},
        'arp-rate':            {'enabled': False, 'category': 'network-security'},
        'bpdu-rate':           {'enabled': False, 'category': 'l2-redundancy'},
        'port-security':       {'enabled': False, 'category': 'network-security'},
        'overload-detection':  {'enabled': False, 'category': 'port-monitor'},
        'speed-duplex':        {'enabled': False, 'category': 'port-monitor'},
        'loop-protection':     {'enabled': False, 'category': 'l2-redundancy'},
    },
}
```

L2S firmware returns fewer reasons (no dhcp-snooping, arp-rate, loop-protection).
The getter returns whatever the device provides — no padding.

### set_auto_disable(interface, timer=0)

Set the auto-disable recovery timer on a port. Pass a list of
interface names to configure multiple ports in one call.

```python
device.set_auto_disable('1/1', timer=60)   # 60-second recovery
device.set_auto_disable('1/1', timer=0)    # disable timer
device.set_auto_disable(['1/1', '1/2'], timer=90)  # multiple ports
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | `str` or `list` | required | Port(s) to configure (e.g. `'1/1'` or `['1/1', '1/2']`) |
| `timer` | `0`, `30`–`4294967295` | `0` | Recovery interval in seconds (0 = disabled) |

### reset_auto_disable(interface)

Reset (re-enable) an auto-disabled port immediately, without waiting for
the recovery timer. Pass a list of interface names to reset multiple ports.

```python
device.reset_auto_disable('1/1')
device.reset_auto_disable(['1/1', '1/2'])  # multiple ports
```

### set_auto_disable_reason(reason, enabled=True)

Enable or disable auto-disable enforcement for a specific reason globally.
This controls whether the device will auto-disable ports when the given
condition is detected.

```python
device.set_auto_disable_reason('loop-protection', True)   # enable
device.set_auto_disable_reason('loop-protection', False)  # disable
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `reason` | see reasons table above | required | Reason name |
| `enabled` | `True`, `False` | `True` | Enable/disable enforcement |

---

## Loop Protection

Loop protection sends periodic detection PDUs on configured ports. When a
PDU is received back (indicating a loop), the port takes a configured
action: send a trap, auto-disable the port, or both.

### get_loop_protection()

Returns global loop protection state and per-interface settings.

```python
lp = device.get_loop_protection()
```

```python
{
    'enabled': False,                   # global enable state
    'transmit_interval': 5,            # PDU send interval (seconds)
    'receive_threshold': 1,            # PDUs before action
    'interfaces': {
        '1/1': {
            'enabled': False,           # per-port enable
            'mode': 'passive',          # 'active' | 'passive'
            'action': 'auto-disable',   # 'trap' | 'auto-disable' | 'all'
            'vlan_id': 0,               # detection VLAN (0 = untagged)
            'loop_detected': False,     # loop currently detected
            'last_loop_time': '',       # ISO timestamp or '' if never
            'tpid_type': 'none',        # read-only, auto-set by device based on vlan_id
        },
        # ... one entry per port
    },
}
```

**Mode**: `active` ports send AND process detection PDUs. `passive` ports
only process received PDUs. Use `active` on edge ports, `passive` on
ring/uplink ports.

**L2S devices**: Loop protection is not available. The getter returns
`{'enabled': False, 'transmit_interval': 0, 'receive_threshold': 0, 'interfaces': {}}`.
SSH returns `Error: Invalid command`, MOPS returns empty tables — both
are handled gracefully.

### set_loop_protection(interface=None, ...)

Configure loop protection. When `interface` is `None`, sets global
parameters. When `interface` is specified, sets per-port parameters.
Pass a list of interface names to configure multiple ports in one call.

```python
# Enable loop protection globally
device.set_loop_protection(enabled=True)

# Configure a port as active with trap+auto-disable
device.set_loop_protection(interface='1/1', enabled=True, mode='active', action='all')

# Configure multiple ports at once
device.set_loop_protection(interface=['1/1', '1/2'], enabled=True, mode='active')

# Set global transmit interval
device.set_loop_protection(transmit_interval=3)

# Disable loop protection globally
device.set_loop_protection(enabled=False)
```

**Global parameters** (when `interface=None`):

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `enabled` | `True`, `False` | `None` | Enable/disable globally |
| `transmit_interval` | `1`–`10` | `None` | PDU transmit interval (seconds) |
| `receive_threshold` | `1`–`50` | `None` | PDU count before action |

**Per-port parameters** (when `interface` is specified):

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | `str` or `list` | `None` | Port(s) to configure (e.g. `'1/1'` or `['1/1', '1/2']`) |
| `enabled` | `True`, `False` | `None` | Enable/disable on this port |
| `mode` | `'active'`, `'passive'` | `None` | Detection mode |
| `action` | `'trap'`, `'auto-disable'`, `'all'` | `None` | Action on loop detection |
| `vlan_id` | `0`–`4042` | `None` | Detection VLAN (0 = untagged) |

**Note**: The `tpid_type` field in the getter output is read-only and
auto-populated by the device based on `vlan_id`: setting `vlan_id=0`
→ `tpid_type='none'` (untagged), setting `vlan_id` > 0 → `tpid_type='dot1q'`
(802.1Q tagged). It cannot be overridden independently.

---

## sFlow (RFC 3176)

Programmatic sFlow configuration — receivers, per-port flow sampling and
counter polling. MOPS-only (SFLOW-MIB).

### get_sflow()

Returns agent info and the 8-slot receiver table.

```python
result = device.get_sflow()
```

```python
{
    'agent_version': '1.3;Hirschmann;10.3.04',
    'agent_address': '192.168.1.4',
    'receivers': {
        1: {'owner': 'snoop', 'timeout': -1, 'max_datagram_size': 1400,
            'address_type': 1, 'address': '192.168.1.100',
            'port': 6343, 'datagram_version': 5},
        2: {'owner': '', 'timeout': 0, 'max_datagram_size': 1400,
            'address_type': 1, 'address': '0.0.0.0',
            'port': 6343, 'datagram_version': 5},
        # ...8 receivers total
    }
}
```

### set_sflow(receiver, address=None, port=None, owner=None, timeout=None, max_datagram_size=None)

Configure an sFlow receiver. Owner must be set to claim a receiver before
binding samplers/pollers. Setting owner to `''` releases the receiver and
auto-clears all bound samplers/pollers.

```python
# Claim receiver 1 and configure
device.set_sflow(1, owner='snoop', address='192.168.1.100', timeout=-1)

# Release receiver (auto-clears bound samplers/pollers)
device.set_sflow(1, owner='')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `receiver` | `1`–`8` | required | Receiver index |
| `address` | IP string | `None` | Collector IP address |
| `port` | int | `None` | Collector UDP port |
| `owner` | string | `None` | Owner (set to claim, `''` to release) |
| `timeout` | int | `None` | Seconds (`-1`=permanent, `>0`=countdown) |
| `max_datagram_size` | int | `None` | Maximum datagram size in bytes |

### get_sflow_port(interfaces=None, type=None)

Returns per-port sFlow sampler and poller configuration.

```python
result = device.get_sflow_port()              # all ports, both tables
result = device.get_sflow_port(['1/1'])       # single port
result = device.get_sflow_port(type='sampler') # sampler table only
```

```python
{
    '1/1': {
        'sampler': {'receiver': 2, 'sample_rate': 256, 'max_header_size': 128},
        'poller': {'receiver': 2, 'interval': 20},
    },
    # ...
}
```

### set_sflow_port(interfaces, receiver, sample_rate=None, interval=None, max_header_size=None)

Configure sFlow sampling and/or polling on ports. At least one of
`sample_rate` or `interval` must be provided — they select which table
to configure.

```python
# Enable sampler + poller on two ports
device.set_sflow_port(['1/1', '1/2'], receiver=1, sample_rate=256, interval=20)

# Disable sampler only (poller untouched)
device.set_sflow_port('1/1', receiver=0, sample_rate=0)

# Disable both
device.set_sflow_port('1/1', receiver=0, sample_rate=0, interval=0)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interfaces` | `str` or `list` | required | Port(s) to configure |
| `receiver` | `0`–`8` | required | Receiver to bind (`0`=unbind) |
| `sample_rate` | int | `None` | Sampling rate (`256`–`65536`, `0`=off) |
| `interval` | int | `None` | Polling interval in seconds (`0`=off) |
| `max_header_size` | int | `None` | Max header capture size (sampler only) |

**Note**: When unbinding (`receiver=0`), the device auto-clears rate/interval.
The driver sends only the receiver field to avoid `commitFailed` errors.

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

## Port Admin Control

### set_interface(interface, enabled=None, description=None)

Set port admin state and/or description. Only provided parameters are
changed — omitted parameters are left untouched. Pass a list of
interface names to configure multiple ports in one call.

```python
# Disable a port
device.set_interface('1/5', enabled=False)

# Enable a port with a description
device.set_interface('1/5', enabled=True, description='Uplink')

# Clear the description
device.set_interface('1/5', description='')

# Configure multiple ports at once
device.set_interface(['1/1', '1/2', '1/3'], enabled=True, description='Edge')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | `str` or `list` | required | Port(s) to configure (e.g. `'1/5'` or `['1/1', '1/2']`) |
| `enabled` | `True`, `False`, `None` | `None` | Admin up/down |
| `description` | string, `None` | `None` | Port alias (ifAlias) |

**Raises** `ValueError` if the interface name is not found on the device.

No-op if both `enabled` and `description` are `None`.

---

## Factory Onboarding (MOPS + SSH)

HiOS 10.3+ forces a password change on first login before any CLI or
SNMP access is available. These methods detect and handle that state.

**Not available via SNMP** — the SNMP agent is gated on factory-default
devices. Use MOPS or SSH to onboard, then SNMP becomes available.

### is_factory_default()

Check if the device is in factory-default password state.

- **MOPS**: Reads `hm2UserForcePasswordStatus` (1=gate active)
- **SSH**: Detects `Enter new password` prompt during `open()`
- **SNMP**: Returns `False` (if SNMP connected, gate is already cleared)

```python
if device.is_factory_default():
    device.onboard('NewPassword1')
```

**Returns** `bool` — `True` if the device still requires initial password setup.

### onboard(new_password)

Change the default password on a factory-fresh device, unlocking CLI
and SNMP access. The new password can be the same as the current one —
the act of calling the endpoint clears the factory gate.

- **MOPS**: POST to `/mops_changePassword`
- **SSH**: Responds to interactive `Enter new password` / `Confirm` prompts

```python
device.onboard('NewPassword1')
```

**Raises** `ConnectionException` if the device is already onboarded
(calling this on an onboarded device causes a cold reset).

**Returns** `True` on success.

---

## Factory Reset

### clear_config(keep_ip=False)

Clear running config back to factory defaults. Wipes RAM only — NVM
is not touched. Device warm-restarts (~12s) — connection will drop.

After clear, `nvm` shows `out of sync` because NVM still has the
previously saved config while running config is now factory defaults.

```python
result = device.clear_config()
result = device.clear_config(keep_ip=True)  # preserve management IP + addressing mode
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `keep_ip` | `True`, `False` | `False` | Preserve management IP address and addressing mode (LOCAL/DHCP) |

**Returns** `{'restarting': True}`

### clear_factory(erase_all=False)

Full factory reset. Wipes RAM + NVM + ENVM. Device cold-reboots —
connection will drop. Uptime resets to 0.

```python
result = device.clear_factory()
result = device.clear_factory(erase_all=True)  # also regenerate factory.cfg
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `erase_all` | `True`, `False` | `False` | Also regenerate `factory.cfg` from firmware (use when factory defaults file may be corrupted) |

**Returns** `{'rebooting': True}`

---

## MOPS Atomic Staging (MOPS-only)

Batch multiple setter calls into one atomic `set_multi()` POST.
Useful for operations where intermediate states would break connectivity
(e.g. changing PVID + egress membership together so a port never
loses comms).

```python
device.start_staging()
device.set_vlan_ingress('1/1', pvid=5)
device.set_vlan_egress(5, '1/1', 'untagged')
device.commit_staging()   # one POST, both changes applied atomically
device.save_config()      # persist to NVM when ready
```

### Staging-aware setters

These setters queue mutations when staging is active:

| Setter | Notes |
|--------|-------|
| `set_vlan_ingress()` | |
| `set_vlan_egress()` | |
| `set_rstp()` | Returns `None` in staging (read-back skipped) |
| `set_rstp_port()` | |
| `set_interface()` | |
| `set_hidiscovery()` | Returns `None` in staging (read-back skipped) |
| `set_auto_disable()` | |
| `reset_auto_disable()` | |
| `set_auto_disable_reason()` | |
| `set_loop_protection()` | Global + per-port |

### Always fire immediately (bypass staging)

| Setter | Reason |
|--------|--------|
| `create_vlan()` | VLAN CRUD is a database operation — other setters validate against live state |
| `update_vlan()` | |
| `delete_vlan()` | |
| `set_mrp()` | Complex multi-step RowStatus sequences |
| `delete_mrp()` | |
| `set_mrp_sub_ring()` | |
| `delete_mrp_sub_ring()` | |
| `activate_profile()` | Causes device restart |
| `delete_profile()` | |

### Important

- The driver does **not** validate dependencies between staged operations.
  Operations that depend on prior state (e.g. `set_vlan_egress` requires
  the VLAN to exist) must have their prerequisites committed first.
  Tool layer is responsible for operation ordering.
- `commit_staging()` does **not** save to NVM. Call `save_config()`
  separately when ready.
- SNMP and SSH raise `NotImplementedError`. Use `load_merge_candidate()`
  for SSH CLI staging.

### start_staging()

Enter staging mode — setter calls queue mutations instead of sending.

```python
device.start_staging()
```

### get_staged_mutations()

Return the list of queued mutation tuples for inspection.

```python
mutations = device.get_staged_mutations()
# [('Q-BRIDGE-MIB', 'dot1qPortVlanEntry', {'dot1qPvid': '5'}, {'dot1dBasePort': '1'}), ...]
```

### commit_staging()

Fire all queued mutations in one atomic POST. Does not save to NVM.

```python
device.commit_staging()
device.save_config()  # save when ready
```

### discard_staging()

Clear queued mutations without sending. Device state unchanged.

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
