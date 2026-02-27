# AARON — Automated Asset Recognition On Network

Connects to HiOS switches via napalm-hios, gathers MAC address tables and LLDP neighbour data, cross-references MACs across all devices, and classifies every port as **uplink**, **edge**, **indirect**, or **empty**. Outputs a flat CSV or JSON file — one row per port per switch.

## Requirements

- Python 3.7+
- `napalm-hios >= 1.5.0`

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
python aaron.py                    # CSV output (default)
python aaron.py -j                 # JSON output
python aaron.py -c my_site.cfg     # custom config file
python aaron.py --dry-run          # show plan, no connections
```

## Port Classification

| Type | Criteria |
|------|----------|
| **uplink** | Real LLDP neighbour detected (FDB-sourced entries filtered out) |
| **edge** | No LLDP, has MACs, MACs not seen on non-uplink ports of other devices |
| **indirect** | No LLDP, has MACs, but MACs also appear on non-uplink ports of another device (unmanaged switch/hub between) |
| **empty** | No LLDP, no MACs |

## ARP Scan

Optionally resolves edge device MACs to IP addresses via the local ARP cache. Runs in the background during device data gathering — no extra time cost.

```ini
# Passive — read existing OS ARP cache only, no traffic generated
arp_scan = passive

# Active — tickle subnet with UDP to populate cache, then read
arp_scan = 192.168.1.0/24

# Multiple subnets
arp_scan = 192.168.1.0/24, 10.0.0.0/24
```

## Arguments

| Flag | Description |
|------|-------------|
| `-c <path>` | Config file (default: `script.cfg`) |
| `-o <path>` | Output file (default: `aaron_output.csv` or `.json`) |
| `-j` | Output JSON instead of CSV |
| `--dry-run` | Show plan without connecting |
| `--debug` | Verbose protocol logging |

## Config File

```ini
# AARON — Automated Asset Recognition On Network
username = admin
password = private
protocol = mops
edge_threshold = 3
hide_empty = true
hide_uplinks = false
# arp_scan = passive

# Devices — one IP per line
192.168.1.4
192.168.1.117
192.168.1.127
```

## Config Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `username` | — | Device username (required) |
| `password` | — | Device password (required) |
| `protocol` | `mops` | `mops` / `snmp` / `ssh` |
| `edge_threshold` | `3` | Max MACs for edge classification (higher = more tolerant of multi-MAC devices like VM hosts) |
| `hide_empty` | `false` | Exclude empty ports from output |
| `hide_uplinks` | `false` | Exclude uplink ports from output |
| `arp_scan` | off | `passive`, or CIDR subnet(s) for active scan |

## CSV Output

| Column | Description |
|--------|-------------|
| `switch_ip` | Device management IP (repeated per row for Excel filtering) |
| `switch_name` | Device hostname |
| `interface` | Port name (e.g. `1/1`) |
| `type` | `uplink` / `edge` / `indirect` / `empty` |
| `vlan` | VLAN(s) seen on port |
| `mac_count` | Number of dynamic MACs learned |
| `macs` | Pipe-separated MAC addresses |
| `resolved_ip` | IP from ARP cache (if available) |
| `lldp_neighbor_ip` | LLDP neighbour management IP |
| `lldp_neighbor_name` | LLDP neighbour hostname |
| `lldp_neighbor_port` | LLDP neighbour port description |

## Logs

Written to `logs/aaron_YYYYMMDD_HHMMSS.log` in the script directory.
