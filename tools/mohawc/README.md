# MOHAWC — Management, Onboarding, HiDiscovery, And Wipe Configuration

CLI tool for HiOS switch commissioning. Wraps napalm-hios vendor-specific methods for onboarding factory-fresh devices, controlling HiDiscovery, saving configs, and resetting to defaults.

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
```

Multiple devices via config file:

```bash
python mohawc.py status
python mohawc.py --dry-run reset --factory --yes
```

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

### `save`

Save running config to NVM on all devices.

```bash
python mohawc.py save
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
| `-u <user>` | Username override (default: `admin`) |
| `-p <pass>` | Password override (default: `private`) |
| `--protocol` | `mops` / `snmp` / `ssh` (default: `mops`) |
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
