# STONE — SFP Transceiver Optics Network Evaluator

Connects to HiOS switches via napalm-hios, reads SFP transceiver optical power levels from every device, and exports an Excel report with per-port TX/RX power, distance-normalised quality scores, and automatic outlier detection.

## Requirements

- Python 3.7+
- `napalm-hios >= 1.4.1`
- `openpyxl >= 3.0.0`

```bash
pip install -r requirements.txt
```

## Quick Start

Two access patterns (no interactive mode — STONE is a single-run report):

1. **Config file** — `python stone.py` — fleet-scale batch scan
2. **CLI overrides** — `python stone.py --protocol snmp -c site.cfg` — custom config

```bash
python stone.py                        # default config + Excel output
python stone.py -c my_site.cfg         # custom config file
python stone.py --protocol snmp        # protocol override
python stone.py --dry-run              # show plan, no connections
```

## Arguments

| Flag | Description |
|------|-------------|
| `-c <path>` | Config file (default: `script.cfg`) |
| `-o <path>` | Output Excel file (default: `network_data.xlsx`) |
| `-r <n>` | Connection retries per device (default: `3`) |
| `--delay <n>` | Delay between retries in seconds (default: `5`) |
| `-t <n>` | Connection timeout in seconds (default: `30`) |
| `--protocol` | `mops` / `snmp` / `ssh` (overrides config file) |
| `-s`, `--silent` | Suppress console output |
| `--debug` | Verbose protocol logging |
| `--dry-run` | Show plan without connecting |

## Config File

```ini
# STONE — SFP Transceiver Optics Network Evaluator
username = admin
password = private
protocol = mops

# Devices — one IP per line
192.168.1.4
192.168.1.117
192.168.1.254
```

## Config Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `username` | — | Device username (required) |
| `password` | — | Device password (required) |
| `protocol` | `mops` | `mops` / `snmp` / `ssh` |

## Excel Output

### Columns

| Column | Description |
|--------|-------------|
| Host | Device management IP |
| Interface | Port name (e.g. `1/5`) |
| Input Power | RX optical power (dBm) |
| Output Power | TX optical power (dBm) |
| Distance | User-fillable field (metres) — validated as positive decimal |
| Quality | Formula: Input Power / Distance |
| Problem | Flags outliers deviating >50% from fleet average quality |

### Features

- Problematic rows highlighted in red via conditional formatting
- Distance field has data validation (positive decimal only)
- Quality and Problem columns are live Excel formulas — update when Distance is entered
- If the output file is locked (e.g. open in Excel), saves to a timestamped alternative

## Example Output

```
============================================================
  STONE — SFP Transceiver Optics Network Evaluator
============================================================
  Protocol:  MOPS | Devices: 3 | Retries: 3
------------------------------------------------------------

  [  2.1s] 192.168.1.4     BRS50-8TX/4SFP           4 SFP ports
  [  1.8s] 192.168.1.117   BRS50-8TX/4SFP           2 SFP ports
  [FAIL ] 192.168.1.127   connection timeout

============================================================
  2/3 devices reached | 6 SFP ports | Done in 2.4s
  Output: network_data.xlsx
============================================================
```

## Protocol Support

Read-only tool — all features work with all live protocols. No offline mode (requires live SFP transceiver data).

| Feature | MOPS | SNMP | SSH | Offline |
|---------|------|------|-----|---------|
| SFP optical power | Yes | Yes | Yes | — |

## Logs

Written to `logs/stone_YYYYMMDD_HHMMSS.log` in the script directory.

## See Also

- [napalm-hios](https://github.com/adamr/napalm-hios) — NAPALM driver for HiOS
