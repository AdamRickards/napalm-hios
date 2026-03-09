# MOHAWC — Management, Onboarding, HiDiscovery, And Wipe Configuration

CLI tool for HiOS switch commissioning. Wraps napalm-hios vendor-specific methods for onboarding factory-fresh devices, controlling HiDiscovery, saving configs, managing profiles, and resetting to defaults.

Three access patterns:

1. **CLI args** — `mohawc -d IP <command> [--flags]` — power users, scripting, CI
2. **script.cfg** — `mohawc -c site.cfg save` — fleet-scale batch ops
3. **Interactive** — `mohawc -d IP -i` — guided mode, no need to memorise args

## Requirements

- Python 3.7+
- `napalm-hios >= 1.5.0`

```bash
pip install -r requirements.txt
```

## Quick Start

Single device with factory defaults (`admin`/`private`, MOPS):

```bash
python mohawc.py -d 192.168.1.4 status
python mohawc.py -d 192.168.1.4 -i       # interactive mode
```

Multiple devices via config file:

```bash
python mohawc.py status
python mohawc.py --dry-run reset --factory --yes
```

## Interactive Mode (`-i`)

Guided REPL — connect once, run multiple operations in a menu loop:

```bash
python mohawc.py -d 192.168.1.4 -i
python mohawc.py -d 192.168.1.4 interactive    # subcommand alias
python mohawc.py                                # auto-enters if no subcommand + no script.cfg
```

Menu adapts to protocol — MOPS-only items (diff, save-rollback) are hidden when connected via SSH/SNMP. Offline-incompatible items (reset, onboard) are hidden in offline mode.

Main menu follows the MOHAWC acronym — one letter per top-level item:

| # | Menu Item | Sub-menu |
|---|-----------|----------|
| 1 | **Status** (Monitor) | Overview, System info, Management, Diff\*, Ping†, CLI† |
| 2 | **Onboard**‡ | — |
| 3 | **HiDiscovery** | — |
| 4 | **Profiles** (Admin) | List, Activate, Delete, Download, Upload\* |
| 5 | **Reset**§ | — |
| 6 | **Save** (Config) | Save, Save with rollback\*, Snapshot\*, Auto-backup‖ |
| q | Quit | — |

\* MOPS-only, hidden otherwise · † Requires SSH, hidden when offline · ‡ Hidden when offline/SNMP · § Hidden when offline · ‖ Hidden when offline

Profile/config state is refreshed after every mutation. Activate handles the connection drop and reconnects on single-device sessions.

## Blink Toggle (`-b`)

Quick shortcut — reads the current HiDiscovery blink state and inverts it. No subcommand needed, combines with `-d`:

```bash
python mohawc.py -bd 192.168.1.4       # toggle blink on single device
python mohawc.py -b                     # toggle blink on all devices in config
```

## Subcommands

### `status` (default)

Read-only overview: model, firmware, uptime, factory-default state, config status, HiDiscovery, management network, environment (PSU/temp/fans/CPU/memory), and port states.

```bash
python mohawc.py status
python mohawc.py -d 192.168.1.4 status
```

### `profiles`

List config profiles on all devices (index, name, active flag, fingerprint).

```bash
python mohawc.py -d 192.168.1.4 profiles
```

### `diff`

Show unsaved config changes — compares running-config to the active NVM profile. MOPS-only (requires HTTPS config download).

```bash
python mohawc.py -d 192.168.1.4 diff
```

### `save`

Save running config to NVM on all devices.

```bash
python mohawc.py save
```

### `save-rollback`

Backup the current NVM profile under a new name, then save running config. MOPS-only. Avoids name collisions automatically (appends `-1`, `-2`, etc.).

```bash
python mohawc.py -d 192.168.1.4 save-rollback
python mohawc.py save-rollback --name pre-upgrade --yes
```

### `snapshot`

Named backup of the active NVM profile — copies it to a new profile without saving running config or restarting. MOPS-only. Avoids name collisions automatically.

Fails if any device has unsaved changes (snapshot captures NVM, not running config). Use `--force` to override, or save first with `mohawc save`. In interactive mode, MOHAWC offers to save before snapshotting.

```bash
python mohawc.py snapshot --name FAT
python mohawc.py snapshot --name pre-upgrade --yes
python mohawc.py snapshot --name FAT --force    # snapshot even if unsaved
```

### `activate`

Activate a config profile by index or name. Triggers a warm restart — the device reboots. Requires confirmation unless `--yes`.

```bash
python mohawc.py -d 192.168.1.4 activate --index 2
python mohawc.py -d 192.168.1.4 activate --name rollback --yes
```

### `delete`

Delete a config profile by index or name. Refuses to delete the active profile. Requires confirmation unless `--yes`.

```bash
python mohawc.py -d 192.168.1.4 delete --index 3
python mohawc.py -d 192.168.1.4 delete --name old-backup --yes
```

### `download`

Download config XML from a device. Defaults to the active profile. Outputs to stdout or a file.

```bash
python mohawc.py -d 192.168.1.4 download                          # stdout
python mohawc.py -d 192.168.1.4 download --profile CLAMPS -o config.xml
```

Multi-device downloads append `_IP` to the filename (e.g. `config_192_168_1_4.xml`).

### `upload`

Upload a config XML file to a device as a new NVM profile. MOPS-only. Defaults the profile name to the filename.

```bash
python mohawc.py -d 192.168.1.4 upload config.xml
python mohawc.py -d 192.168.1.4 upload config.xml --name pre-upgrade --yes
```

### `onboard`

Onboard factory-default devices (change default password). Skips devices that aren't factory-default (`[SKIP]`, not `[FAIL]`). Refuses SNMP protocol — SNMP is gated on factory-default devices.

```bash
python mohawc.py onboard --new-password NewPass1
python mohawc.py onboard --new-password NewPass1 --save
```

### `hidiscovery`

Control HiDiscovery protocol. Mode (`--on`/`--off`/`--ro`) and blink (`--blink`/`--no-blink`) can be set independently — omit either to preserve its current value. Shows before/after state.

```bash
python mohawc.py hidiscovery --off
python mohawc.py hidiscovery --ro --no-blink --save
python mohawc.py hidiscovery --blink
```

### `reset`

Reset device configuration. Requires confirmation (`Type 'yes'`) unless `--yes` is given. Connection drops after reset are expected and treated as success.

```bash
python mohawc.py reset                          # soft reset (clear_config)
python mohawc.py reset --keep-ip                # preserve management IP
python mohawc.py reset --factory                # full factory reset
python mohawc.py reset --factory --erase-all    # wipe NVM completely
```

#### Safe ordering with `--entry`

When resetting multiple devices, `--entry` specifies the switch you're connected to. MOHAWC uses LLDP to map the topology and resets devices **furthest-first**, so you never cut yourself off from downstream devices.

```bash
python mohawc.py reset --factory --entry 192.168.1.4 --yes
```

Without `--entry`, all devices reset in parallel.

### `system`

View or set sysName, sysContact, and sysLocation. No flags = read-only. All protocols supported.

```bash
python mohawc.py -d 192.168.1.4 system                                          # view
python mohawc.py -d 192.168.1.4 system --hostname SW-OFFICE --contact "Adam R"   # set fields
python mohawc.py -d 192.168.1.4 system --hostname SW-OFFICE --save               # set + save
```

In interactive mode: Status → System info (view/edit).

### `management`

View or set management network configuration (IP, netmask, gateway, VLAN, protocol). No flags = read-only. Changing IP/VLAN may sever your connection — requires `--yes` for set operations. All protocols supported.

```bash
python mohawc.py -d 192.168.1.4 management                                       # view
python mohawc.py -d 192.168.1.4 management --ip 10.0.0.5 --netmask 255.255.255.0 --gateway 10.0.0.1 --yes
python mohawc.py -d 192.168.1.4 management --vlan 5 --save --yes
python mohawc.py -d 192.168.1.4 management --dhcp --yes                           # switch to DHCP
python mohawc.py -d 192.168.1.4 management --static --yes                         # switch to static
```

In interactive mode: Status → Management (view/edit).

### `auto-backup`

View or configure remote config auto-backup. Also supports one-shot push/pull transfers. Not available offline.

```bash
python mohawc.py -d 192.168.1.4 auto-backup                                      # view current config
python mohawc.py -d 192.168.1.4 auto-backup --enable --url "tftp://10.0.0.1/%p/config-%d.xml"
python mohawc.py -d 192.168.1.4 auto-backup --disable --save
python mohawc.py -d 192.168.1.4 auto-backup --push --server "tftp://10.0.0.1/backup.xml"
python mohawc.py -d 192.168.1.4 auto-backup --pull --server "tftp://10.0.0.1/backup.xml"
```

URL wildcards: `%p` (profile name), `%d` (date), `%i` (IP), `%m` (MAC), `%t` (time).

In interactive mode: Save → Auto-backup (view/edit).

### `ping`

ICMP ping from the switch to a destination. Uses SSH fallback — works with any protocol (driver handles SSH lazy-connect). Not available offline.

```bash
python mohawc.py -d 192.168.1.4 ping 192.168.1.1
python mohawc.py -d 192.168.1.4 ping 192.168.1.1 --count 10 --size 1500
```

In interactive mode: Status → Ping.

### `cli`

Raw CLI escape hatch — execute one or more CLI commands on the switch. Uses SSH fallback. Not available offline. Intended for batching commands across a fleet that aren't covered by the tooling structure.

Output is always saved to a timestamped folder (`cli_YYYYMMDD_HHMMSS/`) with one file per device (`192_168_1_4.txt`). Each file contains the command prefixed with `> ` followed by raw output.

```bash
python mohawc.py -d 192.168.1.4 cli "show interface status"
python mohawc.py -c site.cfg cli "show system info" "show ip interface"
```

```
cli_20260309_143022/
  192_168_1_4.txt
  192_168_1_117.txt
  192_168_1_127.txt
```

In interactive mode: Status → CLI command (loops until blank input, no folder output).

## Protocol Support

| Subcommand | MOPS | SNMP | SSH | Offline | Notes |
|------------|------|------|-----|---------|-------|
| `status` | Yes | Yes | Yes | Yes | SNMP always reports factory-default=No |
| `profiles` | Yes | Yes | Yes | Yes | |
| `diff` | Yes | — | — | — | Requires HTTPS config download |
| `save` | Yes | Yes | Yes | Yes | Offline = write XML to disk |
| `save-rollback` | Yes | — | — | — | Requires profile upload |
| `snapshot` | Yes | — | — | — | Requires profile upload |
| `activate` | Yes | Yes | Yes | Yes | Triggers warm restart |
| `delete` | Yes | Yes | Yes | Yes | |
| `download` | Yes | Yes | Yes | Yes | |
| `upload` | Yes | — | — | — | Requires config upload |
| `onboard` | Yes | — | Yes | — | SNMP gated on factory-default |
| `hidiscovery` | Yes | Yes | Yes | Yes | |
| `reset` | Yes | Yes | Yes | — | |
| `system` | Yes | Yes | Yes | Yes | |
| `management` | Yes | Yes | Yes | Yes | |
| `auto-backup` | Yes | Yes | Yes | — | Push/pull need live network |
| `ping` | Yes | Yes | Yes | — | SSH fallback (any protocol) |
| `cli` | Yes | Yes | Yes | — | SSH fallback (any protocol) |

Interactive menu auto-hides unavailable items based on the active protocol.

## Global Arguments

| Flag | Description |
|------|-------------|
| `-b` | Toggle HiDiscovery blink (read current, invert) |
| `-c <path>` | Config file (default: `script.cfg`) |
| `-d <ip>` | Single device — no config file needed |
| `-i`, `--interactive` | Interactive guided mode |
| `-u <user>` | Username override (default: `admin`) |
| `-p <pass>` | Password override (default: `private`) |
| `--protocol` | `mops` / `snmp` / `ssh` / `offline` (default: `mops`) |
| `-s`, `--silent` | Suppress console output (errors still print to stderr) |
| `--debug` | Verbose protocol logging |
| `--dry-run` | Show plan without connecting |

## Config File

`script.cfg` — same `key = value` format as AARON:

```ini
# MOHAWC config
username = admin
password = private
# protocol = mops

# Devices — one IP per line
192.168.1.4
192.168.1.117
192.168.1.127
```

Offline mode — point at config XML files instead of IPs:

```ini
protocol = offline

# Config files
configs/switch1.xml
configs/switch2.xml
```

CLI args (`-u`, `-p`, `--protocol`) override config file values. With `-d`, no config file is needed at all.

### Per-device arguments

Device lines support `key=value` attributes after the IP. Useful for batching per-device changes from a spreadsheet — paste the data, run one command.

```ini
192.168.1.4   hostname=SW-OFFICE contact="Adam R" location="Room 5"
192.168.1.117 hostname=SW-LAB
192.168.1.127 hostname=SW-PLANT location="Floor 2"
```

```bash
python mohawc.py system             # each device gets its own hostname/contact/location
python mohawc.py system --save      # same, but save to NVM
```

Supported per-device keys: `hostname`, `contact`, `location` (for `system`), `ip`, `netmask`, `gateway`, `vlan` (for `management`). CLI args override per-device values when both are set.

Global settings `save = true` and `yes = true` can also be set in the config file to avoid typing `--save` and `--yes` every time.

## Example Output

```
============================================================
  MOHAWC — STATUS
============================================================
  Protocol:  MOPS | Devices: 2
------------------------------------------------------------

  192.168.1.4     BRS50-8TX/4SFP           09.4.04  (up 3d 12h)
    Factory default:  No
    Config:           nvm=ok  aca=absent  boot=ok  [SAVED]  fp=9244C58FEA75..
    HiDiscovery:      read-only  blink=off
    Management:       VLAN 1  192.168.1.4/24  gw 192.168.1.254  (local)
    Environment:      PSU1=ok PSU2=n/a  temp=42°C  fans=ok  CPU=12%  mem=58%
    Ports:            8/12 up  (1/1↑ 1/2↑ 1/3↓ 1/4↑ 1/5↑ 1/6↑ 1/7↓ 1/8↓ ...)

  192.168.1.117   BRS50-8TX/4SFP           09.4.04  (up 1d 5h)
    Factory default:  YES — needs onboarding
    Config:           nvm=ok  aca=absent  boot=ok  [SAVED]
    HiDiscovery:      on  blink=on

============================================================
  2/2 devices reached | Done in 2.4s
============================================================
```

## Logs

Written to `logs/mohawc_YYYYMMDD_HHMMSS.log` in the script directory. Always captured regardless of `--silent`.

## See Also

- [LOGIC.md](LOGIC.md) — Decision logic: reset ordering, profile management, config diff, HiDiscovery mapping
- [napalm-hios](https://github.com/adamr/napalm-hios) — NAPALM driver for HiOS
