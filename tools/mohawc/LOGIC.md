# MOHAWC — Decision Logic

How the tool decides what to do, and why it does it the way it does.

## Reset Ordering

Resetting multiple devices in a ring has a critical ordering constraint:
if you reset the switch you're connected through, you lose access to
everything downstream. MOHAWC uses LLDP to solve this.

```
Without --entry:
  All devices reset in parallel.
  Fast, but if you're inside the ring, you may lose
  access to devices before they're reset.

With --entry IP:
  1. Build LLDP adjacency graph
     get_facts() + get_lldp_neighbors_detail() on all devices
     Match neighbors by hostname (case-insensitive)
     Build {ip: set(neighbor_ips)} adjacency map

  2. BFS from entry point
     Compute hop distance from --entry to each device
     Unreachable devices (no LLDP path) get max distance + 1

  3. Sort furthest-first
     Highest distance resets first → entry device resets last
     You never cut yourself off from downstream devices
```

### Connection Drop Tolerance

Reset causes the device to reboot. The connection drops. MOHAWC treats
this as success:

```
device.clear_factory() or device.clear_config()
  │
  ├─ Returns normally → OK
  │
  └─ Exception raised:
       │
       ├─ Contains 'closed', 'reset', 'timeout', 'eof',
       │  'broken pipe', 'connection'
       │    → OK (expected drop)
       │
       └─ Other error → FAIL
```

### Reset Variants

```
reset (no flags):
  clear_config(keep_ip=False)
  Clears config, IP set to default (192.168.1.1)

reset --keep-ip:
  clear_config(keep_ip=True)
  Clears config, preserves management IP

reset --factory:
  clear_factory(erase_all=False)
  Full factory reset, deletes all profiles except boot

reset --factory --erase-all:
  clear_factory(erase_all=True)
  Nuclear — wipes all NVM profiles including boot
  Device comes up with absolutely nothing
```

## Profile Management

HiOS switches store multiple config profiles in NVM. MOHAWC provides
five profile operations with built-in safety.

### Collision Avoidance

`save-rollback` and `snapshot` both create new profiles. Name collisions
are avoided automatically:

```
Requested name: "pre-upgrade"
  │
  get_profiles() → list existing names
  │
  "pre-upgrade" exists?
    │
    ├─ NO → use "pre-upgrade"
    │
    └─ YES → try "pre-upgrade-1"
              "pre-upgrade-2"
              ... until unique
```

### Save-Rollback vs Snapshot

Two ways to create a backup profile, different semantics:

```
save-rollback:
  1. Copy active NVM profile → new name (backup)
  2. Save running config over active NVM profile
  Result: NVM = current running config
          Backup = what was in NVM before

snapshot:
  1. Check for unsaved changes
       │
       ├─ Unsaved + no --force → ABORT
       │  "snapshot captures NVM, not running config"
       │  Offer to save first (interactive mode)
       │
       └─ Clean or --force → proceed
  2. Copy active NVM profile → new name
  Result: NVM = unchanged (still the active profile)
          Snapshot = frozen copy of NVM

The difference: save-rollback writes running → NVM.
Snapshot copies NVM without modifying it.
```

### Active Profile Protection

`delete` refuses to delete the active profile:

```
delete --index N or --name X:
  │
  get_profiles() → find target
  │
  Is target the active profile?
    │
    ├─ YES → ABORT ("cannot delete active profile")
    │
    └─ NO → delete (with confirmation unless --yes)
```

### Activate and Connection Drop

`activate` triggers a warm restart — the device reboots with the new
profile. Like reset, the connection drops:

```
activate --index N or --name X:
  │
  activate_profile('nvm', index)
  │
  Device reboots → connection drops
  │
  Single-device session (-d)?
    │
    ├─ YES → wait + reconnect → refresh state
    │
    └─ NO → treat drop as success
```

## Config Diff

Compares running-config to the active NVM profile. MOPS-only — requires
HTTPS config download.

```
get_config(source='running')   → running XML
get_config(source='startup')   → NVM XML (active profile)
  │
  Parse both as XML trees
  │
  For each table (MIB entry) in both:
    For each row (index) in both:
      For each attribute:
        │
        ├─ Same value → skip
        └─ Different  → record change
  │
  Group by table, print human-readable diff
```

Table names are mapped to human-readable labels (e.g.,
`dot1qVlanStaticEntry` → `VLAN membership`). 60+ table labels
defined for VLAN, interface, STP, MRP, IGMP, DHCP, QoS, security,
and system configuration tables.

## HiDiscovery State Mapping

The getter returns a dict, the setter takes a string. MOHAWC converts:

```
get_hidiscovery() → {enabled: bool, mode: str, blinking: bool}
  │
  _hidiscovery_status_str():
    enabled=False           → 'off'
    enabled=True, mode='read-only' → 'ro'
    enabled=True, mode=*    → 'on'
  │
  set_hidiscovery(status_str, blinking=bool)
```

When only one dimension is specified (mode or blink), the other is
preserved from the current state. Omit `--on`/`--off`/`--ro` to change
only blink. Omit `--blink`/`--no-blink` to change only mode.

## Blink Toggle

The `-b` flag is a standalone shortcut — no subcommand needed:

```
-b (or -bd IP):
  │
  get_hidiscovery() → read current blink state
  │
  Invert: blinking=True → False, False → True
  │
  Preserve mode: _hidiscovery_status_str(before) → status
  │
  set_hidiscovery(status, blinking=new_blink)
```

Combines with `-d` for single device (`-bd 192.168.1.4`) or runs on
all devices in the config file (`-b` alone).

## Onboard Flow

Onboard changes the factory-default password. Only runs on devices that
are actually factory-default.

```
onboard --new-password X:
  │
  Protocol check:
    ├─ SNMP → ABORT ("SNMP is gated on factory-default devices")
    └─ Offline → ABORT ("onboard not available offline")
  │
  Per device (parallel):
    │
    is_factory_default()?
      │
      ├─ NO → SKIP (not FAIL — device is already configured)
      │
      └─ YES → device.onboard(new_password)
                │
                --save? → device.save_config()
```

SNMP is explicitly blocked because HiOS gates SNMPv3 credentials on
factory-default devices — the SNMP user doesn't exist until after
onboarding.

## Management Changes

Setting IP, netmask, gateway, or VLAN may sever the connection.
Requires `--yes` for set operations.

```
management --ip X --vlan Y --yes:
  │
  set_management(ip=X, vlan=Y, ...)
  │
  Connection lost?
    │
    ├─ YES → treat as success (expected if IP/VLAN changed)
    │        "management IP/VLAN change may sever connection"
    │
    └─ NO → save_config() if --save
```

DHCP/static protocol switching is also supported:

```
management --dhcp:  switch to DHCP (IP assigned by server)
management --static: switch to static (use current or specified IP)
```

## Per-Device Arguments

Config file device lines support `key=value` attributes for batching
per-device changes:

```
192.168.1.4   hostname=SW-OFFICE contact="Adam R" location="Room 5"
192.168.1.117 hostname=SW-LAB
```

Resolution priority:

```
For each key (hostname, contact, location, ip, netmask, etc.):
  │
  CLI flag set?
    │
    ├─ YES → CLI wins (overrides per-device)
    │
    └─ NO → per-device value from config (or None)
```

Used by `system` and `management` subcommands. One command, per-device
values — paste from a spreadsheet, run once.

## Auto-Backup

Two modes: persistent (enable/disable + URL template) and one-shot
(push/pull).

```
Persistent mode:
  auto-backup --enable --url "tftp://10.0.0.1/%p/config-%d.xml"
  │
  URL wildcards resolved by the switch:
    %p → profile name
    %d → date (YYYYMMDD)
    %i → management IP
    %m → MAC address
    %t → time (HHMMSS)
  │
  set_config_remote(enabled=True, url=url)

One-shot transfer:
  auto-backup --push --server "tftp://10.0.0.1/backup.xml"
  auto-backup --pull --server "tftp://10.0.0.1/backup.xml"
  │
  set_config_remote(push=True/False, server=url)
  │
  Push: switch → server (export current config)
  Pull: server → switch (import config to new profile)
```

## Ping and CLI

Both use SSH fallback — work with any protocol. The driver handles the
SSH lazy-connect internally.

```
ping (any protocol):
  device.ping(destination, count=N, size=N, timeout=N)
  │
  Driver internally opens SSH if not already connected
  Parses CLI "ping" output → structured result

cli (any protocol):
  device.cli(["show interface status", "show ip interface"])
  │
  Driver internally opens SSH
  Returns raw CLI output per command
  │
  Batch mode: output saved to cli_YYYYMMDD_HHMMSS/
    One file per device (192_168_1_4.txt)
    Each command prefixed with "> " then raw output
  │
  Interactive mode: output printed to console, loops until blank input
```

## Status Enrichment

Status gathers from multiple getters, each wrapped individually so a
failure in one doesn't break the entire status display:

```
Always gathered:
  get_facts()           → model, firmware, hostname, uptime
  is_factory_default()  → factory-default state
  get_config_status()   → NVM status, config saved state
  get_hidiscovery()     → HiDiscovery mode + blink

Enrichment (try/except wrapped, missing = omitted):
  get_environment()     → PSU, temp, fans, CPU, memory
  get_interfaces()      → port states (up/down count)
  get_config_fingerprint() → NVM profile fingerprint hash
  get_management()      → management IP, VLAN, gateway, protocol
```

Factory-default detection has a protocol caveat: SNMP always reports
`False` for `is_factory_default()` because the SNMPv3 credentials
required to connect don't exist on a true factory-default device.
Status notes this: `"SNMP: always reports No"`.

## Config Resolution

```
Device source priority:
  │
  ├─ -d IP           → single device, ignore config file devices
  │
  ├─ --ips SPEC      → parsed IP list (comma, range, CIDR)
  │   Still reads script.cfg for credentials if it exists
  │   Falls back to admin/private if no config file
  │
  └─ script.cfg      → devices from config file

Credential priority:
  CLI flags (-u, -p, --protocol) override ALL sources.
  Otherwise: config file values, or defaults (admin/private/mops).

Offline auto-detection:
  Any device path ends with .xml?
    → protocol forced to 'offline'
    → credentials cleared (not needed)
    → no save prompt on quit
```

## MOPS Feature Gate

Several features require MOPS because they depend on HTTPS config
file operations that only the MOPS protocol backend provides:

```
MOPS-only features:
  │
  ├─ diff          → get_config(source='running'|'startup')
  │                  Requires XML config download
  │
  ├─ save-rollback → load_config(xml, profile=name, destination='nvm')
  │                  Requires profile-level config upload
  │
  ├─ snapshot      → Same mechanism as save-rollback
  │                  (copy active profile to new name)
  │
  └─ upload        → load_config(xml, profile=name, destination='nvm')
                     Requires config file upload to NVM
```

SNMP and SSH backends don't expose the config file management API.
These features are hidden from the interactive menu and abort with
an error if attempted via CLI.
