# Vendor-Specific Methods

These methods extend NAPALM with HiOS-specific functionality not covered
by the standard NAPALM API. They are available on all four protocols
(MOPS, SNMP, SSH, Offline) unless noted otherwise. Call them directly on
the driver object (e.g. `device.get_mrp()`).

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

## HTTPS Config Download/Upload (MOPS-only)

MOPS backend supports full config lifecycle via HTTPS — no SSH or TFTP
required. HiOS 10.x requires MOPS session key auth (`Authorization:
Mops <key>` via POST to `/mops_login`). HiOS 9.x accepts Basic auth.

### get_config(profile=None, source='nvm')

Download config XML via HTTPS. Returns NAPALM-standard dict.

```python
# Download active profile config
config = device.get_config()
print(config['running'][:200])  # XML string

# Download a specific profile from ENVM
config = device.get_config(profile='backup', source='envm')
```

```python
{
    'running': '<?xml version="1.0" ...>...',
    'startup': '',
    'candidate': '',
}
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `profile` | profile name | `None` (active) | Target profile (from `get_profiles()`) |
| `source` | `'nvm'`, `'envm'`, `'running-config'` | `'nvm'` | Which storage to download from |

Use `source='running-config', profile='running-config'` to download
the **live running config** (including unsaved changes). Compare it
against the saved NVM profile to see exactly what's unsaved:

```python
saved = device.get_config(profile='config', source='nvm')
running = device.get_config(profile='running-config', source='running-config')

import difflib
diff = difflib.unified_diff(
    saved['running'].splitlines(),
    running['running'].splitlines(),
    fromfile='nvm', tofile='running', lineterm='',
)
print('\n'.join(diff))
```

**Note**: The standard NAPALM `retrieve`, `full`, `sanitized`, and
`format` parameters are accepted but ignored — MOPS always returns
the full config XML. SSH `get_config()` behaviour is unchanged.

### load_config(xml_data, profile=None, destination='nvm')

Upload config XML to a profile via HTTPS. Use `activate_profile()`
after upload to apply.

```python
# Upload config to active profile
with open('config.xml') as f:
    device.load_config(f.read())

# Upload to a specific profile on ENVM
device.load_config(xml_data, profile='backup', destination='envm')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `xml_data` | string | required | Config XML content |
| `profile` | profile name | `None` (active) | Target profile |
| `destination` | `'nvm'`, `'envm'` | `'nvm'` | Which storage to upload to |

**Raises** `ConnectionException` on upload failure.

---

## Remote Config Management

Getter/setter pair for TFTP config transfer and automatic backup.
Available on MOPS, SNMP, and SSH.

### get_config_remote()

Returns remote config backup settings.

```python
remote = device.get_config_remote()
```

```python
{
    'server_username': 'admin',
    'auto_backup': {
        'enabled': True,
        'destination': 'tftp://192.168.4.3/%p/config-%d.xml',
        'username': 'backup_user',
    }
}
```

| Field | Description |
|-------|-------------|
| `server_username` | File transfer server login (SSH returns empty — not available via CLI) |
| `auto_backup.enabled` | Whether auto-backup is active |
| `auto_backup.destination` | Destination URL with `%p`/`%i`/`%m`/`%d`/`%t` wildcards |
| `auto_backup.username` | Auth username for backup server |

### set_config_remote(action, server, profile, source, destination, ...)

Configure remote config transfer and/or auto-backup.

**One-shot transfer** (push config to TFTP server or pull from it):

```python
# Push active profile to TFTP server
device.set_config_remote(
    action='push',
    server='tftp://192.168.4.3/switch-config.xml',
    profile='CLAMPS',      # source profile (default = active)
    source='nvm',
)

# Pull config from TFTP server into a profile
device.set_config_remote(
    action='pull',
    server='tftp://192.168.4.3/switch-config.xml',
    profile='CLAMPS',      # destination profile (default = active)
    destination='nvm',
)
```

**Auto-backup configuration**:

```python
# Enable auto-backup
device.set_config_remote(
    auto_backup=True,
    auto_backup_url='tftp://192.168.4.3/%p/config-%d.xml',
    auto_backup_username='backup',
    auto_backup_password='secret',
)

# Disable auto-backup
device.set_config_remote(auto_backup=False)
```

**Server credentials** (shared across all transfers):

```python
device.set_config_remote(username='admin', password='secret')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `action` | `'pull'`, `'push'` | `None` | Transfer direction |
| `server` | TFTP URL | `None` | e.g. `'tftp://192.168.4.3/config.xml'` |
| `profile` | profile name | `None` (active) | Source (push) or destination (pull) profile |
| `source` | `'nvm'`, `'envm'` | `'nvm'` | Source storage for push |
| `destination` | `'nvm'`, `'envm'` | `'nvm'` | Destination storage for pull |
| `auto_backup` | `True`, `False` | `None` | Enable/disable auto-backup |
| `auto_backup_url` | URL with wildcards | `None` | Destination URL for auto-backup |
| `auto_backup_username` | string | `None` | Auth username for backup server |
| `auto_backup_password` | string | `None` | Auth password for backup server |
| `username` | string | `None` | File transfer server login |
| `password` | string | `None` | File transfer server password |

**Note**: SSH cannot set server credentials (`username`/`password`) —
use MOPS or SNMP for those. SSH `server_username` is always returned
as empty string in `get_config_remote()`.

---

## SNMP System Information

### set_snmp_information(hostname=None, contact=None, location=None)

Set sysName, sysContact, and/or sysLocation. Pass `None` to skip a
field. Available on all four protocols (MOPS, SNMP, SSH, Offline).

```python
device.set_snmp_information(hostname='SW-OFFICE-01')
device.set_snmp_information(contact='NOC', location='Building A, Rack 3')
device.set_snmp_information(hostname='SW-01', contact='ops@example.com', location='DC-1')
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `hostname` | string | `None` | System name (sysName.0) |
| `contact` | string | `None` | System contact (sysContact.0) |
| `location` | string | `None` | System location (sysLocation.0) |

**Returns** the result of `get_snmp_information()` after setting. MOPS
respects staging — values are queued if `start_staging()` is active.

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

### set_mrp(operation, mode, port_primary, port_secondary, vlan, recovery_delay, advanced_mode)

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

# Enable advanced mode (react on link change — faster failover)
result = device.set_mrp(advanced_mode=True)

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
| `advanced_mode` | `True`, `False` | `None` | React on link change (faster failover) |

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
counter polling. All 3 protocols (SFLOW-MIB).

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

## Storm Control

Per-port ingress storm control for broadcast, multicast, and unicast traffic.
Limits the rate of incoming frames to protect the CPU and fabric from storms.

### get_storm_control()

Returns global bucket type and per-port storm control configuration.

```python
result = device.get_storm_control()
```

```python
{
    'bucket_type': 'single-bucket',    # 'single-bucket' or 'multi-bucket'
    'interfaces': {
        '1/1': {
            'unit': 'pps',             # 'pps' or 'percent'
            'broadcast':  {'enabled': True,  'threshold': 100},
            'multicast':  {'enabled': False, 'threshold': 0},
            'unicast':    {'enabled': False, 'threshold': 0},
        },
        # ... one entry per port
    },
}
```

### set_storm_control(interface, ...)

Set per-port storm control configuration. All parameters except `interface`
are optional — only provided values are changed. Pass a list of interface
names to configure multiple ports in one call.

```python
# Enable broadcast limiting at 100 pps
device.set_storm_control('1/1', unit='pps',
                         broadcast_enabled=True, broadcast_threshold=100)

# Enable all three traffic types on multiple ports
device.set_storm_control(['1/1', '1/2', '1/3'], unit='pps',
                         broadcast_enabled=True, broadcast_threshold=100,
                         multicast_enabled=True, multicast_threshold=500,
                         unicast_enabled=True, unicast_threshold=500)

# Disable broadcast limiting
device.set_storm_control('1/1', broadcast_enabled=False)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | `str` or `list` | required | Port(s) to configure |
| `unit` | `'pps'`, `'percent'` | `None` | Threshold unit |
| `broadcast_enabled` | `True`, `False` | `None` | Enable/disable broadcast limiting |
| `broadcast_threshold` | `0`–`14880000` | `None` | Broadcast rate limit |
| `multicast_enabled` | `True`, `False` | `None` | Enable/disable multicast limiting |
| `multicast_threshold` | `0`–`14880000` | `None` | Multicast rate limit |
| `unicast_enabled` | `True`, `False` | `None` | Enable/disable unknown unicast limiting |
| `unicast_threshold` | `0`–`14880000` | `None` | Unknown unicast rate limit |

---

## QoS — Quality of Service

Per-port trust mode, queue scheduling, traffic class mapping, and management
frame priority. Three function groups: port-level QoS, global TC mapping,
and management priority.

### get_qos()

Returns per-port QoS trust mode, default priority, shaping rate, and per-queue scheduling.

```python
result = device.get_qos()
```

```python
{
    'num_queues': 8,                    # device capability (read-only)
    'interfaces': {
        '1/1': {
            'trust_mode': 'dot1p',      # 'untrusted' | 'dot1p' | 'ip-precedence' | 'ip-dscp'
            'default_priority': 0,      # 0-7 — port default PCP for untagged frames
            'shaping_rate': 0,          # percent (0 = no limit)
            'queues': {
                0: {'scheduler': 'strict', 'min_bw': 0, 'max_bw': 0},
                1: {'scheduler': 'strict', 'min_bw': 0, 'max_bw': 0},
                # ... 8 queues total (0-7)
                7: {'scheduler': 'strict', 'min_bw': 0, 'max_bw': 0},
            },
        },
        # ... one entry per port
    },
}
```

**SSH note**: `shaping_rate` returns 0 (not available via CLI).

### set_qos(interface, ...)

Set per-port QoS trust mode, shaping rate, or queue scheduling. Pass a list
of interface names to configure multiple ports in one call. The `queue`
parameter is required when setting `scheduler`, `min_bw`, or `max_bw`.

```python
# Set trust mode on a port
device.set_qos('1/1', trust_mode='ip-dscp')

# Set trust mode on multiple ports
device.set_qos(['1/1', '1/2', '1/3'], trust_mode='dot1p')

# Set queue 7 to weighted scheduling with bandwidth limits
device.set_qos('1/1', queue=7, scheduler='weighted', min_bw=10, max_bw=50)

# Set shaping rate (MOPS/SNMP only)
device.set_qos('1/1', shaping_rate=80)

# Set default PCP for untagged frames
device.set_qos('1/1', default_priority=3)

# Set default PCP on multiple ports
device.set_qos(['1/1', '1/2', '1/3', '1/4'], default_priority=5)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `interface` | `str` or `list` | required | Port(s) to configure |
| `trust_mode` | `'untrusted'`, `'dot1p'`, `'ip-precedence'`, `'ip-dscp'` | `None` | Per-port trust mode |
| `default_priority` | `0`–`7` | `None` | Port default PCP for untagged ingress frames |
| `shaping_rate` | `0`–`100` | `None` | Egress shaping rate (percent, 0 = no limit) |
| `queue` | `0`–`7` | `None` | Queue index (required for scheduler/bandwidth) |
| `scheduler` | `'strict'`, `'weighted'` | `None` | Queue scheduling type |
| `min_bw` | `0`–`100` | `None` | Minimum bandwidth (percent, weighted only) |
| `max_bw` | `0`–`100` | `None` | Maximum bandwidth (percent, weighted only) |

**Raises** `ValueError` if trust_mode or scheduler is invalid, or if
scheduler/min_bw/max_bw is set without a queue index.

### get_qos_mapping()

Returns global dot1p and DSCP to traffic class mapping tables.

```python
result = device.get_qos_mapping()
```

```python
{
    'dot1p': {0: 1, 1: 0, 2: 0, 3: 1, 4: 2, 5: 2, 6: 3, 7: 3},
    'dscp':  {0: 0, 8: 1, 10: 1, 16: 2, ..., 56: 7},  # 64 entries (0-63)
}
```

### set_qos_mapping(dot1p=None, dscp=None)

Set individual dot1p and/or DSCP to traffic class mappings. Only the
mappings provided are changed; others are left untouched.

```python
# Set dot1p priority 5 → traffic class 3
device.set_qos_mapping(dot1p={5: 3})

# Set multiple dot1p mappings
device.set_qos_mapping(dot1p={0: 0, 1: 0, 2: 1, 3: 1, 4: 2, 5: 2, 6: 3, 7: 3})

# Set DSCP 46 (EF) → traffic class 7
device.set_qos_mapping(dscp={46: 7})

# Set both dot1p and DSCP in one call
device.set_qos_mapping(dot1p={7: 3}, dscp={46: 7, 34: 5})
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `dot1p` | dict `{priority(0-7): tc(0-7)}` | `None` | dot1p→TC mappings to set |
| `dscp` | dict `{dscp(0-63): tc(0-7)}` | `None` | DSCP→TC mappings to set |

### get_management_priority()

Returns management frame priority settings — the priority values the switch
uses for management reply frames (SSH, SNMP, HTTPS responses).

```python
result = device.get_management_priority()
```

```python
{
    'dot1p': 0,      # 0-7, VLAN PCP priority
    'ip_dscp': 0,    # 0-63, IP DSCP value
}
```

### set_management_priority(dot1p=None, ip_dscp=None)

Set management frame priority. Only provided values are changed.

```python
# Set management frames to PCP 7 (highest priority)
device.set_management_priority(dot1p=7)

# Set both dot1p and DSCP
device.set_management_priority(dot1p=7, ip_dscp=46)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `dot1p` | `0`–`7` | `None` | VLAN PCP priority for management replies |
| `ip_dscp` | `0`–`63` | `None` | IP DSCP value for management replies |

### get_management()

Returns management network configuration — IP assignment, management VLAN,
IPv6 status, and DHCP settings. Corresponds to the HiOS web UI under
Network → Global / IPv4 / IPv6.

```python
result = device.get_management()
```

```python
{
    'protocol': 'local',          # 'local' | 'bootp' | 'dhcp'
    'vlan_id': 1,                 # 1-4042, management VLAN ID
    'ip_address': '192.168.1.4',  # dotted quad
    'netmask': '255.255.255.0',   # dotted quad
    'gateway': '192.168.1.254',   # dotted quad
    'mgmt_port': 0,               # 0 = all ports
    'dhcp_client_id': '',         # read-only, DHCP client ID
    'dhcp_lease_time': 0,         # read-only, seconds
    'dhcp_option_66_67': True,    # DHCP config file download enabled
    'dot1p': 0,                   # 0-7, management VLAN priority
    'ip_dscp': 0,                 # 0-63, management IP DSCP
    'ipv6_enabled': True,         # IPv6 admin status
    'ipv6_protocol': 'auto',      # 'none' | 'auto' | 'dhcpv6' | 'all'
}
```

| Field | Type | Description |
|-------|------|-------------|
| `protocol` | str | IP assignment method |
| `vlan_id` | int | Management VLAN ID |
| `ip_address` | str | Management IP address |
| `netmask` | str | Subnet mask |
| `gateway` | str | Default gateway |
| `mgmt_port` | int | Restricted management port (0 = all) |
| `dhcp_client_id` | str | DHCP client identifier (read-only) |
| `dhcp_lease_time` | int | DHCP lease time in seconds (read-only) |
| `dhcp_option_66_67` | bool | DHCP options 66/67/4/42 enabled |
| `dot1p` | int | Management frame VLAN PCP priority |
| `ip_dscp` | int | Management frame IP DSCP value |
| `ipv6_enabled` | bool | IPv6 administrative status |
| `ipv6_protocol` | str | IPv6 address assignment method |

**Note:** On L3 devices (e.g. GRS1042) the management IP is on a routed
VLAN interface, not the management IP stack. `ip_address` will return
`0.0.0.0` — use `get_interfaces_ip()` to find routed interface IPs.

### set_management(protocol=None, vlan_id=None, ip_address=None, netmask=None, gateway=None, mgmt_port=None, dhcp_option_66_67=None, ipv6_enabled=None)

Set management network configuration. Only provided values are changed.
IP/gateway changes are activated atomically (MOPS: same POST; SNMP: same
SET batch; SSH: `network parms` command).

**VLAN safety check:** Changing `vlan_id` first validates the VLAN exists
in the device's VLAN table. If not, raises `ValueError` to prevent
management lockout.

```python
# Switch to DHCP
device.set_management(protocol='dhcp')

# Change management VLAN (must exist first)
device.create_vlan(100, 'Management')
device.set_management(vlan_id=100)

# Change IP address (atomic — includes activation trigger)
device.set_management(ip_address='10.0.0.1', netmask='255.255.255.0',
                      gateway='10.0.0.254')

# Disable IPv6 (reduces attack surface)
device.set_management(ipv6_enabled=False)

# Disable DHCP config file auto-download
device.set_management(dhcp_option_66_67=False)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `protocol` | `'local'`, `'bootp'`, `'dhcp'` | `None` | IP assignment method |
| `vlan_id` | `1`–`4042` | `None` | Management VLAN (validated against VLAN table) |
| `ip_address` | dotted quad str | `None` | Management IP address |
| `netmask` | dotted quad str | `None` | Subnet mask |
| `gateway` | dotted quad str | `None` | Default gateway |
| `mgmt_port` | int | `None` | Restrict management to specific port (0 = all) |
| `dhcp_option_66_67` | bool | `None` | Enable/disable DHCP option 66/67/4/42 |
| `ipv6_enabled` | bool | `None` | Enable/disable IPv6 |

**Warning:** Changing `ip_address`, `vlan_id`, or `gateway` may cause you
to lose connectivity to the device. Plan accordingly.

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

## Config Watchdog

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

## Access Port

### set_access_port(port, vlan_id)

Atomically configure port(s) as untagged access on a single VLAN. Removes the port
from all other VLANs (egress + untagged), adds it to the target VLAN as untagged, and
sets the PVID — all in one atomic request. The target VLAN must already exist.

```python
device.set_access_port('1/3', 5)         # single port
device.set_access_port(['1/1', '1/2'], 5) # multiple ports
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `port` | port name or list | required | Port(s) to configure |
| `vlan_id` | `1`–`4094` | required | Target VLAN (must exist) |

**Protocol support:** MOPS, SNMP, Offline. SSH raises `NotImplementedError` (not atomic).

---

## Login Policy

### get_login_policy()

Read password complexity and login lockout settings.

```python
policy = device.get_login_policy()
```

```python
{
    'min_password_length': 8,
    'max_login_attempts': 5,
    'lockout_duration': 300,
    'min_uppercase': 1,
    'min_lowercase': 1,
    'min_numeric': 1,
    'min_special': 1,
}
```

### set_login_policy(...)

Set password complexity and login lockout policy. Only provided kwargs are changed.

```python
device.set_login_policy(min_password_length=10, max_login_attempts=3)
```

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `min_password_length` | `1`–`64` | `None` | Minimum password length |
| `max_login_attempts` | `0`–`5` | `None` | Max failed logins (0 = disabled) |
| `lockout_duration` | `0`–`60` | `None` | Lockout period in seconds |
| `min_uppercase` | `0`–`16` | `None` | Minimum uppercase characters |
| `min_lowercase` | `0`–`16` | `None` | Minimum lowercase characters |
| `min_numeric` | `0`–`16` | `None` | Minimum numeric characters |
| `min_special` | `0`–`16` | `None` | Minimum special characters |

---

## Syslog

### get_syslog()

Read syslog configuration — global enable state and server list.

```python
syslog = device.get_syslog()
```

```python
{
    'enabled': True,
    'servers': [
        {
            'index': 1,
            'ip': '10.2.1.4',
            'port': 514,
            'severity': 'informational',
            'transport': 'udp',
        },
    ],
}
```

### set_syslog(enabled=None, servers=None)

Set syslog configuration. Only provided args are changed.

```python
device.set_syslog(enabled=True)
```

---

## NTP

### get_ntp()

Read SNTP client and NTP server configuration.

```python
ntp = device.get_ntp()
```

```python
{
    'client': {
        'enabled': True,
        'mode': 'sntp',
        'servers': [
            {'address': '10.2.1.1', 'port': 123, 'status': 'success'},
        ],
    },
    'server': {
        'enabled': False,
        'stratum': 1,
    },
}
```

### set_ntp(client_enabled=None, server_enabled=None)

Set SNTP client and NTP server enable/disable.

```python
device.set_ntp(client_enabled=True)
device.set_ntp(server_enabled=False)
```

---

## Services

### get_services()

Read service enable/disable state — management protocols, industrial protocols, firmware security, external NVM (ACA), registration protocols, and device security monitors.

```python
services = device.get_services()
```

Selective query — only fetch specific fields (reduces round-trips):

```python
services = device.get_services('unsigned_sw', 'mvrp')
```

```python
{
    'http': {'enabled': True, 'port': 80},
    'https': {
        'enabled': True, 'port': 443,
        'tls_versions': ['tlsv1.2'],
        'tls_cipher_suites': [
            'tls-ecdhe-rsa-with-aes-128-gcm-sha256',
            'tls-ecdhe-rsa-with-aes-256-gcm-sha384',
        ],
    },
    'ssh': {
        'enabled': True,
        'hmac_algorithms': ['hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com'],
        'kex_algorithms': ['diffie-hellman-group16-sha512', 'ecdh-sha2-nistp256'],
        'encryption_algorithms': ['aes128-ctr', 'aes128-gcm@openssh.com'],
        'host_key_algorithms': ['ecdsa-sha2-nistp256', 'ssh-ed25519'],
    },
    'telnet': {'enabled': False},
    'snmp': {'v1': False, 'v2': False, 'v3': True, 'port': 161},
    'industrial': {
        'iec61850': False,
        'profinet': False,
        'ethernet_ip': False,
        'opcua': False,
        'modbus': False,
    },
    'unsigned_sw': False,
    'aca_auto_update': True,
    'aca_config_write': True,
    'aca_config_load': True,
    'mvrp': False,
    'mmrp': False,
    'gvrp': False,
    'gmrp': False,
    'devsec_monitors': True,
}
```

### set_services(...)

Set service enable/disable state. Only provided kwargs are changed.

```python
device.set_services(telnet=False, snmp_v1=False)
device.set_services(unsigned_sw=False, devsec_monitors=True)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `http` | bool | HTTP web server |
| `https` | bool | HTTPS web server |
| `ssh` | bool | SSH server |
| `telnet` | bool | Telnet server |
| `snmp_v1` | bool | SNMPv1 access |
| `snmp_v2` | bool | SNMPv2c access |
| `snmp_v3` | bool | SNMPv3 access |
| `iec61850` | bool | IEC 61850 MMS |
| `profinet` | bool | PROFINET I/O |
| `ethernet_ip` | bool | EtherNet/IP |
| `opcua` | bool | OPC UA |
| `modbus` | bool | Modbus TCP |
| `unsigned_sw` | bool | Allow unsigned firmware upload |
| `aca_auto_update` | bool | ACA automatic software load from external NVM |
| `aca_config_write` | bool | ACA config save to external NVM |
| `aca_config_load` | bool | ACA config load from external NVM |
| `mvrp` | bool | MVRP global enable |
| `mmrp` | bool | MMRP global enable |
| `devsec_monitors` | bool | All 19 device security sense monitors |
| `tls_versions` | list[str] | HTTPS TLS versions (MOPS/SNMP only) |
| `tls_cipher_suites` | list[str] | HTTPS TLS cipher suites (MOPS/SNMP only) |
| `ssh_hmac` | list[str] | SSH HMAC algorithms (MOPS/SNMP only) |
| `ssh_kex` | list[str] | SSH key exchange algorithms (MOPS/SNMP only) |
| `ssh_encryption` | list[str] | SSH encryption algorithms (MOPS/SNMP only) |
| `ssh_host_key` | list[str] | SSH host key algorithms (MOPS/SNMP only) |

`gvrp` and `gmrp` are read-only (`False`) — legacy protocols with no global toggle in HiOS MIBs.

Cipher list parameters accept a list of algorithm names matching those returned by `get_services()`.
SSH backend returns empty lists for cipher fields (no CLI equivalent) and does not support cipher SET.

```python
# Harden TLS — restrict to TLS 1.2 with GCM-only ciphers
device.set_services(
    tls_versions=['tlsv1.2'],
    tls_cipher_suites=[
        'tls-ecdhe-rsa-with-aes-128-gcm-sha256',
        'tls-ecdhe-rsa-with-aes-256-gcm-sha384',
    ])

# Harden SSH — remove SHA1, keep SHA2 only
device.set_services(
    ssh_hmac=['hmac-sha2-256', 'hmac-sha2-256-etm@openssh.com'],
    ssh_kex=['diffie-hellman-group16-sha512', 'ecdh-sha2-nistp256'])
```

JUSTIN cross-reference: `sec-crypto-ciphers` uses these fields to detect weak algorithms.

---

## SNMP Config

### get_snmp_config()

Read SNMP version status, port, and community table.

```python
snmp = device.get_snmp_config()
```

```python
{
    'versions': {'v1': False, 'v2': False, 'v3': True},
    'port': 161,
    'communities': [
        {'name': 'public', 'access': 'ro'},
        {'name': 'private', 'access': 'rw'},
    ],
}
```

Community table is only available via MOPS. SNMP and SSH return an empty list.

### set_snmp_config(v1=None, v2=None, v3=None)

Set SNMP version enable/disable.

```python
device.set_snmp_config(v1=False, v2=False, v3=True)
```

---

## Signal Contact

The signal contact is a physical relay on HiOS switches used for fault signalling. It can be driven by the device's own monitoring engine (temperature, link failure, PSU state, etc.), the device security engine, or set manually.

### get_signal_contact()

Returns signal contact configuration and status for all contacts (typically 1, some platforms have 2).

```python
sc = device.get_signal_contact()
```

```python
{
    1: {
        'mode': 'monitor',           # manual/monitor/deviceState/deviceSecurity/deviceStateAndSecurity
        'manual_state': 'close',     # open/close (for manual mode)
        'trap_enabled': False,
        'monitoring': {
            'temperature': True,
            'link_failure': False,
            'envm_removal': False,
            'envm_not_in_sync': False,
            'ring_redundancy': False,
            # Platform-dependent: fan, module_removal, ethernet_loops, humidity, stp_port_block
        },
        'power_supply': {1: True, 2: True},      # per-PSU monitoring
        'link_alarm': {'1/1': False, '1/2': False, ...},  # per-port
        'status': {
            'oper_state': 'open',                 # open/close
            'last_change': '2026-03-10 08:23:09',
            'cause': 'power-supply',
            'cause_index': 2,
            'events': [
                {'cause': 'power-supply', 'info': 2, 'timestamp': '2026-03-10 08:23:09'},
            ],
        },
    }
}
```

### set_signal_contact(contact_id=1, mode=None, manual_state=None, trap_enabled=None, monitoring=None, power_supply=None, link_alarm=None)

Configure a signal contact. All parameters optional — only supplied values are changed.

```python
# Set to monitor device + security status
device.set_signal_contact(contact_id=1, mode='deviceStateAndSecurity')

# Unmonitor PSU 2 (intentionally unpowered)
device.set_signal_contact(contact_id=1, power_supply={2: False})

# Enable link alarm on specific port
device.set_signal_contact(contact_id=1, link_alarm={'1/1': True})
```

| Parameter | Type | Values |
|-----------|------|--------|
| `mode` | str | `manual`, `monitor`, `deviceState`, `deviceSecurity`, `deviceStateAndSecurity` |
| `manual_state` | str | `open`, `close` |
| `trap_enabled` | bool | Enable/disable SNMP trap on relay change |
| `monitoring` | dict | `{flag: bool}` — see monitoring keys above |
| `power_supply` | dict | `{psu_id: bool}` |
| `link_alarm` | dict | `{'port': bool}` |

---

## Device Monitor

The device monitor engine tracks device health (temperature, PSU, link, NVM). When signal contact mode is `deviceState` or `deviceStateAndSecurity`, the relay is driven by this engine's oper_state.

### get_device_monitor()

Returns device monitor configuration and status (singleton — no contact ID).

```python
dm = device.get_device_monitor()
```

```python
{
    'trap_enabled': True,
    'monitoring': {
        'temperature': True,
        'link_failure': False,
        'envm_removal': False,
        'envm_not_in_sync': False,
        'ring_redundancy': False,
    },
    'power_supply': {1: True, 2: True},
    'link_alarm': {'1/1': False, '1/2': False, ...},
    'status': {
        'oper_state': 'error',
        'last_change': '2026-03-10 08:53:30',
        'cause': 'power-supply',
        'cause_index': 2,
        'events': [...],
    },
}
```

### set_device_monitor(trap_enabled=None, monitoring=None, power_supply=None, link_alarm=None)

Configure device monitor. Same parameters as signal contact (minus `mode` and `manual_state`).

```python
device.set_device_monitor(trap_enabled=True)
device.set_device_monitor(monitoring={'temperature': True, 'link_failure': True})
device.set_device_monitor(power_supply={2: False})
```

---

## Device Security Status

HiOS's built-in IEC 62443 compliance engine — 19 security monitors that flag configuration weaknesses. When signal contact mode is `deviceSecurity` or `deviceStateAndSecurity`, the relay is driven by this engine's oper_state.

### get_devsec_status()

Returns security monitor flags, per-port no-link monitoring, and status events.

```python
ds = device.get_devsec_status()
```

```python
{
    'trap_enabled': False,
    'monitoring': {
        'password_change': True,
        'password_min_length': True,
        'password_policy_not_configured': True,
        'password_policy_bypass': True,
        'telnet_enabled': True,
        'http_enabled': True,
        'snmp_unsecure': True,
        'sysmon_enabled': True,
        'envm_update_enabled': True,
        'no_link_enabled': True,
        'hidiscovery_enabled': True,
        'envm_config_load_unsecure': True,
        'iec61850_mms_enabled': True,
        'https_cert_warning': True,
        'modbus_tcp_enabled': True,
        'ethernet_ip_enabled': True,
        'profinet_enabled': True,
        'secure_boot_disabled': True,
        'dev_mode_enabled': True,
        # Platform-dependent: pml_disabled
    },
    'no_link': {'1/1': False, '1/2': False, ...},  # per-port
    'status': {
        'oper_state': 'error',
        'last_change': '2026-03-10 09:19:44',
        'cause': 'sysmon-enabled',
        'cause_index': 0,
        'events': [
            {'cause': 'password-policy-inactive', 'info': 0, 'timestamp': '2026-03-09 11:41:07'},
            ...
        ],
    },
}
```

### set_devsec_status(trap_enabled=None, monitoring=None, no_link=None)

Configure device security monitors. Toggle individual monitors or per-port no-link detection.

```python
# Disable sysmon monitoring (intentionally accessible)
device.set_devsec_status(monitoring={'sysmon_enabled': False})

# Enable trap on security violation
device.set_devsec_status(trap_enabled=True)
```

---

## Banner

Pre-login and CLI login banners (HM2-MGMTACCESS-MIB).

### get_banner()

Returns banner configuration for both pre-login and CLI login.

```python
banner = device.get_banner()
```

```python
{
    'pre_login': {
        'enabled': True,
        'text': 'Authorized use only',
    },
    'cli_login': {
        'enabled': False,
        'text': '',
    },
}
```

### set_banner(pre_login_enabled=None, pre_login_text=None, cli_login_enabled=None, cli_login_text=None)

Configure pre-login and/or CLI login banners. All parameters optional.

```python
# Enable pre-login banner with text
device.set_banner(pre_login_enabled=True, pre_login_text='Authorized use only')

# Disable CLI banner
device.set_banner(cli_login_enabled=False)

# Set text (max 512 for pre-login, 1024 for CLI)
device.set_banner(pre_login_text='Warning: unauthorized access prohibited')
```

---

## Session Config

### get_session_config()

Read session timeout and max-sessions for all management protocols.

```python
sc = device.get_session_config()
# {
#     'ssh':          {'timeout': 5, 'max_sessions': 5, 'active_sessions': 1},
#     'ssh_outbound': {'timeout': 5, 'max_sessions': 5, 'active_sessions': 0},
#     'telnet':       {'timeout': 5, 'max_sessions': 5, 'active_sessions': 0},
#     'web':          {'timeout': 5},
#     'serial':       {'timeout': 5, 'enabled': True, 'oper_status': 'up'},
#     'netconf':      {'timeout': 60, 'max_sessions': 5, 'active_sessions': 0},
#     'envm':         {'enabled': False, 'oper_status': 'down'},
# }
```

All timeouts in minutes (0 = disabled). NETCONF timeout is stored as seconds on device but normalised to minutes. `active_sessions` is a read-only runtime counter (offline returns 0). `enabled` and `oper_status` are physical interface admin/oper state from `hm2MgmtAccessPhysicalIntfGroup`. `oper_status` is `'up'` or `'down'`. Not all platforms have serial or ENVM interfaces — fields reflect hardware capability.

### set_session_config(ssh_timeout=None, ssh_max_sessions=None, ssh_outbound_timeout=None, ssh_outbound_max_sessions=None, telnet_timeout=None, telnet_max_sessions=None, web_timeout=None, serial_timeout=None, serial_enabled=None, envm_enabled=None, netconf_timeout=None, netconf_max_sessions=None)

Set session timeouts and max-sessions. All parameters optional, all timeouts in minutes.

```python
# Set all timeouts to 5 minutes
device.set_session_config(ssh_timeout=5, telnet_timeout=5, web_timeout=5, serial_timeout=5)

# Increase SSH max sessions
device.set_session_config(ssh_max_sessions=3)

# Disable ENVM CLI interface
device.set_session_config(envm_enabled=False)

# Disable serial console
device.set_session_config(serial_enabled=False)
```

---

## IP Restrict (Restricted Management Access)

### get_ip_restrict()

Read restricted management access configuration — global enable/logging and per-rule table (max 16 rules).

```python
rma = device.get_ip_restrict()
# {
#     'enabled': False,
#     'logging': False,
#     'rules': [
#         {
#             'index': 1,
#             'ip': '192.168.1.0',
#             'prefix_length': 24,
#             'services': {
#                 'http': True, 'https': True, 'snmp': True,
#                 'telnet': True, 'ssh': True, 'iec61850': True,
#                 'modbus': True, 'ethernet_ip': True, 'profinet': True,
#             },
#             'interface': '',
#             'per_rule_logging': False,
#             'log_counter': 0,
#         },
#     ],
# }
```

### set_ip_restrict(enabled=None, logging=None)

Set global RMA enable and logging. Both parameters optional.

```python
device.set_ip_restrict(enabled=True)
device.set_ip_restrict(enabled=False, logging=True)
```

### add_ip_restrict_rule(index, ip='0.0.0.0', prefix_length=0, http=True, https=True, snmp=True, telnet=True, ssh=True, iec61850=True, modbus=True, ethernet_ip=True, profinet=True, interface='', per_rule_logging=False)

Create a restricted management access rule at index 1-16 (RowStatus createAndGo). Service flags default to True (allow all).

```python
# Allow management from 192.168.60.0/24 via HTTPS and SSH only
device.add_ip_restrict_rule(
    1, ip='192.168.60.0', prefix_length=24,
    http=False, snmp=False, telnet=False,
    iec61850=False, modbus=False, ethernet_ip=False, profinet=False)

# Then enable restriction
device.set_ip_restrict(enabled=True)
```

### delete_ip_restrict_rule(index)

Delete a restricted management access rule by index (RowStatus destroy).

```python
device.delete_ip_restrict_rule(1)
```

---

## DNS Client

### get_dns()

Read DNS client global configuration and server list.

```python
dns = device.get_dns()
# {
#     'enabled': False,
#     'config_source': 'mgmt-dhcp',
#     'domain_name': '',
#     'timeout': 3,
#     'retransmits': 2,
#     'cache_enabled': True,
#     'servers': ['10.0.0.1', '10.0.0.2'],
#     'active_servers': ['10.0.0.1'],
# }
```

`config_source` values: `'user'` (manually configured), `'mgmt-dhcp'` (DHCP on management interface), `'provider'` (ISP/WAN DHCP/PPPoE). `servers` contains user-configured entries (up to 4). `active_servers` is a read-only runtime list that may include DHCP-provided servers not in `servers`. All timeouts in seconds.

### set_dns(enabled=None, config_source=None, domain_name=None, timeout=None, retransmits=None, cache_enabled=None)

Set DNS client global configuration. All parameters optional.

```python
device.set_dns(enabled=True, config_source='user', timeout=5)
device.set_dns(domain_name='example.com')
device.set_dns(cache_enabled=False)
```

### add_dns_server(address)

Add a DNS server by IPv4 address. Auto-picks the next free slot (indices 1–4, max 4 servers).

```python
device.add_dns_server('8.8.8.8')
device.add_dns_server('1.1.1.1')
```

Raises `ValueError` if all 4 slots are full.

### delete_dns_server(address)

Delete a DNS server by exact IPv4 address.

```python
device.delete_dns_server('8.8.8.8')
```

Raises `ValueError` if address not found.

---

## PoE — Power over Ethernet

### get_poe()

Read global PoE status, per-module power budgets, and per-port PoE configuration.

```python
poe = device.get_poe()
# {
#     'enabled': True,
#     'power_w': 30,
#     'delivered_current_ma': 250,
#     'modules': {
#         '1/1': {
#             'budget_w': 370,
#             'max_w': 370,
#             'reserved_w': 30,
#             'delivered_w': 5,
#             'source': 'internal',
#             'threshold_pct': 90,
#             'notifications': True,
#         }
#     },
#     'ports': {
#         '1/1': {
#             'enabled': True,
#             'status': 'delivering',
#             'priority': 'high',
#             'classification': 'class4',
#             'consumption_mw': 5300,
#             'power_limit_mw': 15400,
#             'name': 'AP',
#             'fast_startup': True,
#         }
#     }
# }
```

`status` values: `'disabled'`, `'searching'`, `'delivering'`, `'fault'`, `'test'`, `'other-fault'`. `priority` values: `'critical'`, `'high'`, `'low'`. `classification` values: `'class0'`–`'class8'` (or `None` when port is not delivering or class is invalid). `source` values: `'internal'`, `'external'`. All power values in milliwatts except module-level fields which are in watts.

### set_poe(interface=None, enabled=None, priority=None, power_limit_mw=None, name=None, fast_startup=None)

Configure global PoE admin state or per-port settings. All parameters optional.

Without `interface`, sets global admin state only:

```python
device.set_poe(enabled=True)
device.set_poe(enabled=False)
```

With `interface`, sets per-port configuration (single port or list):

```python
device.set_poe(interface='1/1', enabled=False)
device.set_poe(interface='1/1', priority='critical', power_limit_mw=15400)
device.set_poe(interface=['1/1', '1/2'], priority='high', fast_startup=True)
device.set_poe(interface='1/1', name='AP-Office')
```

`priority` values: `'critical'`, `'high'`, `'low'`. `power_limit_mw`: 0–30000 (0 = unlimited). Raises `ValueError` for invalid priority or unknown interface.

---

## Remote Authentication

### get_remote_auth()

Check whether remote authentication services (RADIUS, TACACS+, LDAP) are configured. Detection only — no setter.

```python
auth = device.get_remote_auth()
# {
#     'radius': {'enabled': False},
#     'tacacs': {'enabled': False},
#     'ldap': {'enabled': False},
# }
```

RADIUS and TACACS+ are considered enabled if at least one server has active RowStatus. LDAP is considered enabled if the global admin state is on. On hardware/firmware that doesn't support a protocol (e.g. TACACS+ before 10.3, LDAP on L2S), that protocol returns `{'enabled': False}` gracefully.

Used by JUSTIN `sec-remote-auth` (IEC 62443 CR 1.1 SL2) to verify centralized authentication is configured.

---

## User Management

### get_users()

Get all local user accounts with role, status, SNMP security, and default password detection.

```python
users = device.get_users()
# [
#     {
#         'name': 'admin',
#         'role': 'administrator',
#         'locked': False,
#         'policy_check': False,
#         'snmp_auth': 'md5',
#         'snmp_enc': 'des',
#         'active': True,
#         'default_password': True,
#     },
# ]
```

**Return fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | str | Username |
| `role` | str | `'administrator'`, `'operator'`, `'guest'`, `'auditor'`, `'unauthorized'`, `'custom1'`, `'custom2'`, `'custom3'` |
| `locked` | bool | Account is locked out |
| `policy_check` | bool | Per-user password policy enforcement enabled |
| `snmp_auth` | str | SNMPv3 auth type: `'md5'` or `'sha'` |
| `snmp_enc` | str | SNMPv3 encryption: `'none'`, `'des'`, `'aes128'`, `'aes256'` |
| `active` | bool | Account is active (RowStatus = 1) |
| `default_password` | bool | Password unchanged from factory default (MOPS only — always `False` on SNMP/SSH) |

The `default_password` field queries `hm2PwdMgmtDefaultPwdStatusTable`, which is only available via MOPS. SNMP returns `NoSuchObject` for this table. SSH has no equivalent. Non-MOPS protocols always return `False`.

Used by JUSTIN `sys-default-passwords`, `sec-user-review`, and `sec-user-roles` (IEC 62443 CR 1.1/1.3).

### set_user()

Create or update a local user account.

```python
# Create a new user (password required for new users)
device.set_user('operator1', password='SecurePass123!', role='operator')

# Update password on existing user
device.set_user('admin', password='NewSecurePass!')

# Change role
device.set_user('operator1', role='auditor')

# Configure SNMPv3 security
device.set_user('operator1', snmp_auth_type='sha', snmp_enc_type='aes128',
                snmp_auth_password='AuthPass123!', snmp_enc_password='EncPass123!')

# Unlock a locked-out user
device.set_user('operator1', locked=False)

# Enable per-user password policy check
device.set_user('operator1', policy_check=True)
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | str | Yes | Username (1–32 chars) |
| `password` | str | New users | Login password (required when creating, optional when updating) |
| `role` | str | No | One of the role values from `get_users()` |
| `snmp_auth_type` | str | No | `'md5'` or `'sha'` |
| `snmp_enc_type` | str | No | `'none'`, `'des'`, `'aes128'`, `'aes256'` |
| `snmp_auth_password` | str | No | SNMPv3 authentication password |
| `snmp_enc_password` | str | No | SNMPv3 encryption password |
| `policy_check` | bool | No | Per-user password policy enforcement |
| `locked` | bool | No | Account lockout (set `False` to unlock) |

New users are created via a three-step RowStatus sequence: `createAndWait(5)` → set password (separate operation) → activate + set attributes. This is required because HiOS demands the password be set in a separate PDU from row creation before the row can transition to `active(1)`.

Raises `ValueError` for invalid role, auth type, or encryption type. Raises `ValueError` if password is omitted for a new user.

### delete_user()

Delete a local user account.

```python
device.delete_user('operator1')
```

Sets RowStatus to `destroy(6)`. The user is removed immediately.

---

## SNMP Config (extended)

`get_snmp_config()` and `set_snmp_config()` were extended in v1.17.0 with three new fields:

- **`trap_service`** — global SNMP trap service enable (read/write)
- **`v3_users`** — per-user SNMPv3 auth/encryption types (read-only, from HM2-USERMGMT-MIB)
- **`trap_destinations`** — SNMP trap receiver table (read-only, from SNMP-TARGET-MIB)

```python
snmp = device.get_snmp_config()
# Existing fields unchanged:
#   snmp['versions']     → {'v1': False, 'v2': False, 'v3': True}
#   snmp['port']         → 161
#   snmp['communities']  → [{'name': 'public', 'access': 'ro'}]
#
# New fields:
#   snmp['trap_service']       → True
#   snmp['v3_users']           → [{'name': 'admin', 'auth_type': 'md5', 'enc_type': 'des'}]
#   snmp['trap_destinations']  → [{'name': 'nms1', 'address': '192.168.1.100:162',
#                                   'security_model': 'v3', 'security_name': 'admin',
#                                   'security_level': 'authpriv'}]

# Toggle trap service
device.set_snmp_config(trap_service=True)
device.set_snmp_config(trap_service=False)
```

Auth type values: `''` (none), `'md5'`, `'sha'`. Encryption type values: `'none'`, `'des'`, `'aes128'`, `'aes256'`.

### add_snmp_trap_dest()

Add an SNMP trap destination. Creates entries in both `snmpTargetAddrTable` and
`snmpTargetParamsTable` (RFC 3413 SNMP-TARGET-MIB). Supports v1, v2c, and v3 traps.

```python
# v3 trap destination (encrypted + authenticated)
device.add_snmp_trap_dest('nms1', '192.168.1.100',
                          security_model='v3',
                          security_name='admin',
                          security_level='authpriv')

# v1 trap destination (community-based cleartext)
device.add_snmp_trap_dest('legacy', '10.0.0.1',
                          security_model='v1',
                          security_name='trap_user')
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | str | required | Destination name (1-32 chars) |
| `address` | str | required | Destination IP address |
| `port` | int | `162` | UDP port |
| `security_model` | str | `'v3'` | `'v1'`, `'v2c'`, or `'v3'` |
| `security_name` | str | `'admin'` | Community (v1/v2c) or username (v3) |
| `security_level` | str | `'authpriv'` | `'noauth'`, `'auth'`, or `'authpriv'` |

v1/v2c traps are community-based cleartext — `security_level` is forced to `noauth`
regardless of the value passed. Use v3 with `authpriv` for secure trap delivery.

JUSTIN cross-reference: `sec-snmpv3-traps` checks that at least one v3 authPriv
destination exists.

### delete_snmp_trap_dest()

Delete an SNMP trap destination by name. Removes both the address and params
entries from the SNMP-TARGET-MIB tables.

```python
device.delete_snmp_trap_dest('nms1')
```

---

## Port Security

### get_port_security(interface=None)

Return port security configuration — global state, operation mode, and per-port settings including MAC/IP limits, violation traps, and static entries.

```python
# All ports
ps = device.get_port_security()
print(ps['enabled'])  # True/False — global admin mode
print(ps['mode'])     # 'mac-based' or 'ip-based'
for port, cfg in ps['ports'].items():
    print(f"{port}: enabled={cfg['enabled']}, "
          f"dynamic_limit={cfg['dynamic_limit']}, "
          f"static_count={cfg['static_count']}")

# Single port (uses detailed CLI view on SSH)
ps = device.get_port_security(interface='1/1')

# Multiple ports (filters from full table)
ps = device.get_port_security(interface=['1/1', '1/2'])
```

**Return schema:**

```python
{
    'enabled': bool,          # global port security admin mode
    'mode': str,              # 'mac-based' or 'ip-based'
    'ports': {
        '1/1': {
            'enabled': bool,               # per-port admin mode
            'dynamic_limit': int,          # max dynamic MACs (0-600)
            'static_limit': int,           # max static MACs (0-64)
            'auto_disable': bool,          # auto-disable on violation
            'violation_trap_mode': bool,   # send trap on violation
            'violation_trap_frequency': int,  # trap rate limit (0-3600 sec)
            'dynamic_count': int,          # current dynamic MAC count
            'static_count': int,           # current static MAC count
            'static_ip_count': int,        # current static IP count
            'last_discarded_mac': str,     # last violation MAC
            'static_macs': [{'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'}],
            'static_ips': [{'vlan': 1, 'ip': '192.168.1.1'}],
        },
    },
}
```

MOPS uses `decode_strings=False` with manual hex decode on DisplayString fields (static MACs/IPs, last discarded MAC). SSH table view returns two lines per port; single-port detail view uses key-value format. SNMP walks `hm2AgentPortSecurityEntry` (HM2-PLATFORM-PORTSECURITY-MIB, base OID `1.3.6.1.4.1.248.12.20.1`).

### set_port_security(interface=None, ...)

Configure port security at global or per-port level.

```python
# Global: enable port security, set mode
device.set_port_security(enabled=True, mode='mac-based')

# Per-port: set dynamic limit
device.set_port_security('1/1', dynamic_limit=10)

# Per-port: full config
device.set_port_security('1/1',
    enabled=True,
    dynamic_limit=10,
    static_limit=5,
    auto_disable=True,
    violation_trap_mode=True,
    violation_trap_frequency=30)

# Multiple ports at once
device.set_port_security(['1/1', '1/2', '1/3'], enabled=True, dynamic_limit=10)
```

| Parameter | Type | Description |
|---|---|---|
| `interface` | str/list/None | Port name(s), or None for global |
| `enabled` | bool | Enable/disable (global or per-port) |
| `mode` | str | `'mac-based'` or `'ip-based'` (global only) |
| `dynamic_limit` | int | Max dynamic MACs (0-600, per-port) |
| `static_limit` | int | Max static MACs (0-64, per-port) |
| `auto_disable` | bool | Auto-disable port on violation |
| `violation_trap_mode` | bool | Send trap on violation |
| `violation_trap_frequency` | int | Trap rate limit in seconds (0-3600) |
| `move_macs` | bool | Trigger MAC address move (per-port) |

Raises `ValueError` for invalid `mode` values.

### add_port_security(interface, vlan, mac=None, ip=None, entries=None)

Add static MAC or IP entries to port security.

```python
# Single MAC
device.add_port_security('1/1', vlan=1, mac='aa:bb:cc:dd:ee:ff')

# Single IP
device.add_port_security('1/1', vlan=2, ip='192.168.1.100')

# Bulk (list of entries)
device.add_port_security('1/1', vlan=1, entries=[
    {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'},
    {'vlan': 2, 'mac': '11:22:33:44:55:66'},
])
```

MOPS encodes DisplayString values as hex (e.g., `"1 aa:bb:cc:dd:ee:ff"` → hex octets) for the action OIDs `hm2AgentPortSecurityMACAddressAdd` / `IPAddressAdd`. SNMP uses `OctetString`. SSH uses CLI commands `port-security mac-address add` / `ip-address add`.

### delete_port_security(interface, vlan, mac=None, ip=None, entries=None)

Remove static MAC or IP entries from port security. Same signature as `add_port_security`.

```python
device.delete_port_security('1/1', vlan=1, mac='aa:bb:cc:dd:ee:ff')
```

JUSTIN cross-reference: `ns-port-security` checks that port security is enabled on access ports (skips LLDP uplinks and MRP ring ports). Harden deferred — per-site MAC limit policy required.

---

## DHCP Snooping

### get_dhcp_snooping(interface=None)

Return DHCP snooping configuration — global state, MAC verification, per-VLAN enable, and per-port trust/rate-limit settings.

```python
# Global + all ports
ds = device.get_dhcp_snooping()
print(ds['enabled'])      # True/False — global admin mode
print(ds['verify_mac'])   # True/False — source MAC verification
for vid, cfg in ds['vlans'].items():
    print(f"VLAN {vid}: enabled={cfg['enabled']}")
for port, cfg in ds['ports'].items():
    print(f"{port}: trusted={cfg['trusted']}, "
          f"rate_limit={cfg['rate_limit']}, "
          f"auto_disable={cfg['auto_disable']}")

# Single port (filters from full table)
ds = device.get_dhcp_snooping(interface='1/1')

# Multiple ports (filters from full table)
ds = device.get_dhcp_snooping(interface=['1/1', '1/2'])
```

**Return schema:**

```python
{
    'enabled': bool,          # global DHCP snooping admin mode
    'verify_mac': bool,       # source MAC verification
    'vlans': {
        1: {
            'enabled': bool,  # DHCP snooping enabled on this VLAN
        },
    },
    'ports': {
        '1/1': {
            'trusted': bool,         # trusted port (server-facing)
            'log': bool,             # log invalid messages
            'rate_limit': int,       # max DHCP packets/sec (-1=unlimited)
            'burst_interval': int,   # rate limit burst window (seconds)
            'auto_disable': bool,    # auto-disable on violation
        },
    },
}
```

MOPS uses `decode_strings=False` with manual hex decode on DisplayString fields. SSH parses CLI output. SNMP walks DHCP snooping tables. All 4 backends supported (MOPS, SNMP, SSH, Offline).

### set_dhcp_snooping(interface=None, ...)

Configure DHCP snooping at global, per-VLAN, or per-port level.

```python
# Global: enable DHCP snooping + MAC verification
device.set_dhcp_snooping(enabled=True, verify_mac=True)

# Per-VLAN: enable snooping on VLAN 10
device.set_dhcp_snooping(vlan=10, vlan_enabled=True)

# Per-port: set as trusted (server-facing)
device.set_dhcp_snooping('1/1', trusted=True)

# Per-port: full config
device.set_dhcp_snooping('1/1',
    trusted=False,
    log=True,
    rate_limit=15,
    burst_interval=1,
    auto_disable=True)

# Multiple ports at once
device.set_dhcp_snooping(['1/1', '1/2', '1/3'], trusted=True)
```

| Parameter | Type | Description |
|---|---|---|
| `interface` | str/list/None | Port name(s), or None for global/VLAN |
| `enabled` | bool | Global DHCP snooping enable/disable |
| `verify_mac` | bool | Global source MAC verification |
| `vlan` | int | VLAN ID for per-VLAN config |
| `vlan_enabled` | bool | Enable/disable snooping on specified VLAN |
| `trusted` | bool | Mark port as trusted (per-port) |
| `log` | bool | Log invalid DHCP messages (per-port) |
| `rate_limit` | int | Max DHCP packets/sec, -1=unlimited (per-port) |
| `burst_interval` | int | Rate limit burst window in seconds (per-port) |
| `auto_disable` | bool | Auto-disable port on violation (per-port) |

JUSTIN cross-reference: `ns-dhcp-snooping` checks that DHCP snooping is enabled and configured on access VLANs.

---

## Dynamic ARP Inspection (DAI)

### get_arp_inspection(interface=None)

Return Dynamic ARP Inspection configuration — validation flags, per-VLAN enable/ACL, and per-port trust/rate-limit settings.

```python
# Global + all ports
dai = device.get_arp_inspection()
print(dai['validate_src_mac'])   # True/False — validate source MAC
print(dai['validate_dst_mac'])   # True/False — validate destination MAC
print(dai['validate_ip'])        # True/False — validate IP address
for vid, cfg in dai['vlans'].items():
    print(f"VLAN {vid}: enabled={cfg['enabled']}, "
          f"binding_check={cfg['binding_check']}")
for port, cfg in dai['ports'].items():
    print(f"{port}: trusted={cfg['trusted']}, "
          f"rate_limit={cfg['rate_limit']}, "
          f"auto_disable={cfg['auto_disable']}")

# Single port (filters from full table)
dai = device.get_arp_inspection(interface='1/1')

# Multiple ports (filters from full table)
dai = device.get_arp_inspection(interface=['1/1', '1/2'])
```

**Return schema:**

```python
{
    'validate_src_mac': bool,    # validate source MAC against sender MAC
    'validate_dst_mac': bool,    # validate destination MAC against target MAC
    'validate_ip': bool,         # validate IP addresses in ARP payload
    'vlans': {
        1: {
            'enabled': bool,       # DAI enabled on this VLAN
            'log': bool,           # log invalid ARP packets
            'acl_name': str,       # ARP access list name ('' if none)
            'acl_static': bool,    # use static ACL entries
            'binding_check': bool, # check against DHCP snooping binding table
        },
    },
    'ports': {
        '1/1': {
            'trusted': bool,         # trusted port (bypass inspection)
            'rate_limit': int,       # max ARP packets/sec (-1=unlimited)
            'burst_interval': int,   # rate limit burst window (seconds)
            'auto_disable': bool,    # auto-disable on violation
        },
    },
}
```

DAI has no single global enable — it is enabled per-VLAN. The `binding_check` flag links to the DHCP snooping binding table for source IP/MAC validation.

MOPS uses `decode_strings=False` with manual hex decode on DisplayString fields. SSH parses CLI output. SNMP walks DAI tables. All 4 backends supported (MOPS, SNMP, SSH, Offline).

### set_arp_inspection(interface=None, ...)

Configure Dynamic ARP Inspection at global, per-VLAN, or per-port level.

```python
# Global: enable validation flags
device.set_arp_inspection(validate_src_mac=True, validate_dst_mac=True, validate_ip=True)

# Per-VLAN: enable DAI on VLAN 10 with binding check
device.set_arp_inspection(vlan=10, vlan_enabled=True, vlan_binding_check=True)

# Per-VLAN: assign ARP ACL
device.set_arp_inspection(vlan=10, vlan_acl_name='arp-filter', vlan_acl_static=True)

# Per-port: set as trusted (server-facing, bypass inspection)
device.set_arp_inspection('1/1', trusted=True)

# Per-port: full config
device.set_arp_inspection('1/1',
    trusted=False,
    rate_limit=15,
    burst_interval=1,
    auto_disable=True)

# Multiple ports at once
device.set_arp_inspection(['1/1', '1/2', '1/3'], trusted=True)
```

| Parameter | Type | Description |
|---|---|---|
| `interface` | str/list/None | Port name(s), or None for global/VLAN |
| `validate_src_mac` | bool | Validate source MAC against ARP sender MAC |
| `validate_dst_mac` | bool | Validate destination MAC against ARP target MAC |
| `validate_ip` | bool | Validate IP addresses in ARP payload |
| `vlan` | int | VLAN ID for per-VLAN config |
| `vlan_enabled` | bool | Enable/disable DAI on specified VLAN |
| `vlan_log` | bool | Log invalid ARP packets on specified VLAN |
| `vlan_acl_name` | str | ARP access list name for specified VLAN |
| `vlan_acl_static` | bool | Use static ACL entries on specified VLAN |
| `vlan_binding_check` | bool | Check DHCP snooping binding table on specified VLAN |
| `trusted` | bool | Mark port as trusted (per-port) |
| `rate_limit` | int | Max ARP packets/sec, -1=unlimited (per-port) |
| `burst_interval` | int | Rate limit burst window in seconds (per-port) |
| `auto_disable` | bool | Auto-disable port on violation (per-port) |

JUSTIN cross-reference: `ns-dai` checks that Dynamic ARP Inspection is enabled on access VLANs with binding check linked to DHCP snooping.

---

## IP Source Guard (IPSG)

### get_ip_source_guard(interface=None)

Return IP Source Guard configuration — per-port verify-source and port-security flags, plus static and dynamic binding tables.

```python
# All ports + all bindings
ipsg = device.get_ip_source_guard()
for port, cfg in ipsg['ports'].items():
    print(f"{port}: verify_source={cfg['verify_source']}, "
          f"port_security={cfg['port_security']}")
for b in ipsg['static_bindings']:
    print(f"Static: {b['interface']} VLAN {b['vlan_id']} "
          f"{b['mac_address']} {b['ip_address']} active={b['active']}")
for b in ipsg['dynamic_bindings']:
    print(f"Dynamic: {b['interface']} VLAN {b['vlan_id']} "
          f"{b['mac_address']} {b['ip_address']} hw={b['hw_status']}")

# Single port (filters ports + bindings)
ipsg = device.get_ip_source_guard(interface='1/1')

# Multiple ports (filters from full table)
ipsg = device.get_ip_source_guard(interface=['1/1', '1/2'])
```

**Return schema:**

```python
{
    'ports': {
        '1/1': {
            'verify_source': bool,   # IP filtering enabled
            'port_security': bool,   # MAC filtering enabled (requires verify_source)
        },
    },
    'static_bindings': [
        {
            'interface': str,        # port name ('1/1')
            'vlan_id': int,          # VLAN ID
            'mac_address': str,      # MAC address ('AA:BB:CC:DD:EE:FF')
            'ip_address': str,       # IP address ('10.0.0.1')
            'active': bool,          # binding active
            'hw_status': bool,       # installed in hardware
        },
    ],
    'dynamic_bindings': [
        {
            'interface': str,        # port name ('1/1')
            'vlan_id': int,          # VLAN ID
            'mac_address': str,      # MAC address ('AA:BB:CC:DD:EE:FF')
            'ip_address': str,       # IP address ('10.0.0.1')
            'hw_status': bool,       # installed in hardware
        },
    ],
}
```

`port_security` requires `verify_source` to be enabled first — enabling MAC+IP filtering without IP filtering is not valid. Static bindings have an `active` flag (admin-controlled); dynamic bindings are learned from DHCP snooping.

MOPS uses `decode_strings=False` with manual hex decode on DisplayString fields. SSH parses CLI output. SNMP walks IPSG tables. All 4 backends supported (MOPS, SNMP, SSH, Offline).

### set_ip_source_guard(interface, verify_source=None, port_security=None)

Configure IP Source Guard per-port. No global settings.

```python
# Enable IP filtering on a port
device.set_ip_source_guard('1/1', verify_source=True)

# Enable both IP and MAC filtering
device.set_ip_source_guard('1/1', verify_source=True, port_security=True)

# Disable IP Source Guard on a port
device.set_ip_source_guard('1/1', verify_source=False, port_security=False)

# Multiple ports at once
device.set_ip_source_guard(['1/1', '1/2', '1/3'], verify_source=True)
```

| Parameter | Type | Description |
|---|---|---|
| `interface` | str/list | Port name(s) — required |
| `verify_source` | bool | Enable/disable IP filtering (per-port) |
| `port_security` | bool | Enable/disable MAC filtering (per-port, requires verify_source) |

JUSTIN cross-reference: `ns-ipsg` checks that IP Source Guard is enabled on access ports with verify_source active.

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
