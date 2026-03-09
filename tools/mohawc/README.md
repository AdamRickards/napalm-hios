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
| 1 | **Status** (Monitor) | Status overview, Diff |
| 2 | **Onboard** | — |
| 3 | **HiDiscovery** | — |
| 4 | **Profiles** (Admin) | List, Activate, Delete, Download, Upload |
| 5 | **Reset** (Wipe) | — |
| 6 | **Save** (Config) | Save, Save with rollback, Snapshot |
| q | Quit | — |

Profile/config state is refreshed after every mutation. Activate handles the connection drop and reconnects on single-device sessions.

## Blink Toggle (`-b`)

Quick shortcut — reads the current HiDiscovery blink state and inverts it. No subcommand needed, combines with `-d`:

```bash
python mohawc.py -bd 192.168.1.4       # toggle blink on single device
python mohawc.py -b                     # toggle blink on all devices in config
```

## Subcommands

### `status` (default)

Read-only overview: model, firmware, uptime, factory-default state, config status, HiDiscovery.

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

## Example Output

```
============================================================
  MOHAWC — STATUS
============================================================
  Protocol:  MOPS | Devices: 3
------------------------------------------------------------

  192.168.1.4     BRS50-8TX/4SFP           09.4.04  (up 3d 12h)
    Factory default:  No
    Config:           nvm=ok  aca=absent  boot=ok  [SAVED]
    HiDiscovery:      read-only  blink=off

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
