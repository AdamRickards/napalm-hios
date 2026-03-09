# VIKTOR — VLAN Intent, Knowledgeable Topology-Optimized Rules

Fleet-wide VLAN provisioning for Hirschmann HiOS switches. Connects to multiple devices in parallel, manages VLANs and port membership, audits consistency, and auto-trunks inter-switch links using LLDP topology discovery.

## Requirements

- Python 3.7+
- `napalm-hios >= 1.13.0`

```bash
pip install napalm-hios
```

## Quick Start

Interactive session — connects once, then loops through operations:

```bash
python viktor.py -i
```

Walks you through device selection, credentials, and ring filter, then opens a multi-turn REPL: pick an operation, set parameters, dry-run or go live, repeat. Save to NVM once at quit. Also launches automatically if no `script.cfg` exists and no arguments are given.

If all devices are `.xml` paths, offline mode is auto-detected and the credentials step is skipped entirely (no NVM save prompt at quit either).

Single device:

```bash
python viktor.py -d 192.168.1.80 vlan list
```

Fleet via config file:

```bash
python viktor.py vlan list
python viktor.py vlan create 5 --name "Cameras"
python viktor.py access 1/1-1/8 5
```

## Subcommands

### `vlan list` (default)

List all VLANs on every device with per-port T/U membership.

```bash
python viktor.py vlan list
python viktor.py -m100 vlan list              # ring members only
```

### `vlan create`

Create a VLAN on all devices.

```bash
python viktor.py vlan create 5 --name "Cameras"
```

### `vlan delete`

Delete a VLAN from all devices. Refuses to delete VLAN 1.

```bash
python viktor.py vlan delete 5
```

### `vlan rename`

Rename a VLAN across the fleet.

```bash
python viktor.py vlan rename 5 "Cameras-v2"
```

### `access`

Set ports to strict access mode: PVID set, untagged on target VLAN, removed from all other VLANs. Add-before-remove avoids a moment with no VLAN membership.

```bash
python viktor.py access 1/1-1/8 5
python viktor.py access 1/1-1/4,2/1-2/4 5 --name "Cameras"   # auto-create if missing
```

### `trunk`

Tag ports for VLANs. Additive — doesn't touch PVID or other VLAN membership.

```bash
python viktor.py trunk 1/5,1/6 5,100,200
```

### `auto-trunk`

Discover inter-switch links via LLDP and tag them for a VLAN. Pairs with `-m` for ring-scoped operations.

```bash
python viktor.py auto-trunk 5 --name "Cameras"       # all devices
python viktor.py -m100 auto-trunk 5                   # ring 100 only
```

### `qos`

Set default PCP (802.1p priority) on ports carrying a VLAN. Uses LLDP to skip inter-switch trunk ports by default — only edge ports get changed.

```bash
python viktor.py qos 5 --pcp 3                    # edge ports carrying VLAN 5 → PCP 3
python viktor.py qos 5 --pcp 3 --include-trunk    # edge + trunk ports
python viktor.py qos 5,6,10 --pcp 3               # multiple VLANs
python viktor.py -m100 qos 5 --pcp 3              # ring 100 only
```

PCP is a per-port setting (not per-VLAN). VIKTOR uses the VLAN as a selector — "find all ports carrying VLAN X, set their default PCP to Y." Requires `napalm-hios >= 1.13.0`.

## Fleet-Wide Operations

### `--audit`

Read-only VLAN health check. Five checks:

- **PVID/egress mismatch** — PVID doesn't match untagged membership
- **Dirty access ports** — access port still untagged in VLANs beyond its PVID
- **LLDP cross-check** — VLAN mismatch across inter-switch links
- **Orphan VLANs** — VLAN trunked on one side of a link but not the neighbor
- **Name inconsistencies** — same VLAN ID with different names across devices

```bash
python viktor.py --audit
```

### `--names`

VLAN name consistency audit and fix. Majority name wins — devices with the minority name (or empty) get updated.

```bash
python viktor.py --names --dry-run           # preview fixes
python viktor.py --names --save              # apply and save to NVM
```

### `--export` / `--import`

Dump fleet VLAN and QoS state to CSV, edit in Excel, apply changes back. One row per port per device.

```bash
python viktor.py --export vlans.csv
# edit vlans.csv...
python viktor.py --import vlans.csv --dry-run    # preview diff
python viktor.py --import vlans.csv --save       # apply and save
```

CSV columns: `device_ip`, `hostname`, `port`, `pvid`, `tagged_vlans`, `untagged_vlans`, `qos_trust`, `qos_pcp`

- `qos_trust` — trust mode: `dot1p`, `ip-dscp`, `untrusted`, `ip-precedence`
- `qos_pcp` — default priority 0–7 (PCP assigned to untagged ingress frames)
- Empty QoS cells on import = no change (users who don't care about QoS leave them blank)

## Ring Selector (`-m`)

Filter the fleet to devices participating in an MRP ring by VLAN ID. Works because MRP creates a VLAN and tags ring ports — the egress table IS the topology map.

```bash
python viktor.py -m100 vlan list             # main ring (VLAN 100) members
python viktor.py -m200 vlan list             # sub-ring (VLAN 200) members
python viktor.py -m100 auto-trunk 5          # trunk VLAN 5 on ring 100 links
```

How it works:
1. Connect to ALL devices (from config/`--ips`/`-d`)
2. `get_vlan_egress()` on each
3. Filter: devices where the ring VLAN exists = ring members
4. Ports tagged for that VLAN = ring ports (inter-switch links)
5. Disconnect non-members, proceed with filtered set

## Global Arguments

| Flag | Description |
|------|-------------|
| `-i` | Interactive wizard — guided step-by-step mode |
| `-c <path>` | Config file (default: `script.cfg`) |
| `-d <ip>` | Single device — no config file needed |
| `--ips <spec>` | Comma list, last-octet range, or CIDR |
| `-m <vlan>` | Ring selector — filter by MRP VLAN egress |
| `-u <user>` | Username override (default: `admin`) |
| `-p <pass>` | Password override (default: `private`) |
| `--protocol` | `mops` / `snmp` / `ssh` (default: `mops`) |
| `--debug` | Verbose protocol logging |
| `--dry-run` | Show plan only, no changes |
| `--save` | Save to NVM after changes |

## Device Selection

Priority: `-d` > `--ips` > `script.cfg` devices.

`--ips` formats:

```bash
--ips 192.168.1.80,192.168.1.85          # comma list
--ips 192.168.1.80-85                     # last-octet range
--ips 192.168.1.0/24                      # CIDR
```

When `--ips` is used, `script.cfg` is still read for credentials (if it exists).

## Port Range Syntax

Ranges within the same slot, comma-separated for cross-slot:

```
1/1           single port
1/1-1/8       range (same slot only)
1/1-1/4,2/1   cross-slot via comma
```

## Config File

`script.cfg` — same `key = value` format as AARON/MOHAWC/STONE:

```ini
username = admin
password = private
protocol = mops

# Devices — one IP per line
192.168.1.80
192.168.1.81
192.168.1.82
192.168.1.85
```

CLI args (`-u`, `-p`, `--protocol`) override config file values. With `-d`, no config file is needed.

## Protocol Support

| Feature | MOPS | SNMP | SSH | Offline | Notes |
|---------|------|------|-----|---------|-------|
| `vlan list` | Yes | Yes | Yes | Yes | |
| `vlan create` | Yes | Yes | Yes | Yes | |
| `vlan delete` | Yes | Yes | Yes | Yes | |
| `vlan rename` | Yes | Yes | Yes | Yes | |
| `access` | Yes | Yes | Yes | Yes | Staged on MOPS/Offline |
| `trunk` | Yes | Yes | Yes | Yes | Staged on MOPS/Offline |
| `auto-trunk` | Yes | Yes | Yes | — | Requires live LLDP |
| `qos` | Yes | Yes | Yes | Yes | `napalm-hios >= 1.13.0` |
| `--audit` | Yes | Yes | Yes | — | Requires live LLDP |
| `--names` | Yes | Yes | Yes | Yes | |
| `--export` | Yes | Yes | Yes | Yes | QoS columns need `>= 1.13.0` |
| `--import` | Yes | Yes | Yes | Yes | Staged on MOPS/Offline |

Offline mode requires `napalm-hios >= 1.14.0`. Auto-detects when all device paths are `.xml` files.

## MOPS Staging

When using MOPS or Offline protocol, port operations (`access`, `trunk`, `auto-trunk`, `import`) use staging to batch egress mutations into a single atomic POST per device. VLAN CRUD (`create`/`delete`/`rename`) always fires immediately. PVID and QoS changes are separate calls after staging commits — different MIB tables.

## Example Output

```
============================================================
  VIKTOR — VLAN LIST
============================================================
  Protocol:  MOPS | Devices: 4
------------------------------------------------------------

  Connecting...
  4 device(s) connected
  Gathering VLAN data...
    192.168.1.80     Test unit 1          3 VLANs
    192.168.1.81     Test unit 3          2 VLANs
    192.168.1.82     Test unit 4          3 VLANs
    192.168.1.85     Test Unit 2 ACA      2 VLANs

  Test unit 1 (192.168.1.80)
  VLAN    Name                Ports
  ------  ------------------  ------------------------------
  1       default             U:1/1,1/2,1/3,1/4,1/5,1/6,1/7,1/8,1/9,1/10,1/11,1/12
  100     MRP-VLAN            T:1/5,1/6
  200     SRM-VLAN            T:1/10

============================================================
  4/4 devices reached | Done in 5.1s
============================================================
```

## Logs

Written to `logs/viktor_YYYYMMDD_HHMMSS.log` in the script directory.

## See Also

- [LOGIC.md](LOGIC.md) — Decision logic: access mode ordering, MOPS staging, ring selector, LLDP link discovery, audit checks
- [napalm-hios](https://github.com/adamr/napalm-hios) — NAPALM driver for HiOS
