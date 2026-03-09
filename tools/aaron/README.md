# AARON — Automated Asset Recognition On Network

Connects to HiOS switches via napalm-hios, gathers MAC address tables and LLDP neighbour data, cross-references MACs across all devices, and classifies every port as **uplink**, **edge**, **indirect**, or **empty**. Outputs a flat CSV or JSON file — one row per port per switch.

## Requirements

- Python 3.7+
- `napalm-hios >= 1.5.0`

```bash
pip install -r requirements.txt
```

## Quick Start

Two access patterns (no interactive mode — AARON is a single-run scan):

1. **Config file** — `python aaron.py` — fleet-scale batch scan
2. **CLI overrides** — `python aaron.py -c site.cfg --debug` — custom config

```bash
python aaron.py                    # CSV output (default)
python aaron.py -j                 # JSON output
python aaron.py -c my_site.cfg     # custom config file
python aaron.py --dry-run          # show plan, no connections
python aaron.py --debug            # verbose logging
```

## Port Classification

| Type | Criteria |
|------|----------|
| **uplink** | LLDP neighbour with system name, management IP, or port description (real switch/router) |
| **edge** | No LLDP (or bare LLDP with only a MAC — e.g. Windows LLDP stack), MACs not seen on non-uplink ports of other devices |
| **indirect** | No LLDP, has MACs, but MACs also appear on non-uplink ports of another device (unmanaged switch/hub between) |
| **empty** | No LLDP, no MACs |

## ARP Resolution

Three sources for resolving edge/indirect device MACs to IP addresses:

### Local ARP cache

Runs in the background during device data gathering — zero added latency.

```ini
# Passive — read existing OS ARP cache only, no traffic generated
arp_scan = passive

# Active — tickle subnet with UDP to populate cache, then read
arp_scan = 192.168.1.0/24

# Multiple subnets
arp_scan = 192.168.1.0/24, 10.0.0.0/24
```

### ARP gateway

Query L3 HiOS switches for their ARP tables. Resolves MACs on remote subnets that the scanning machine can't see in its own ARP cache.

```ini
# Single L3 gateway
arp_gateway = 10.0.0.1

# Multiple L3 gateways
arp_gateway = 10.0.0.1, 10.0.1.1
```

The gateway must be reachable with the same credentials and protocol as the target devices.

### Local identity

Automatically detects the scanning machine's own MAC and IP. If the machine is plugged into a managed switch port, that port's `resolved_ip` is populated automatically — no configuration needed. Cross-platform (Linux + Windows).

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
username = admin
password = private
protocol = mops
edge_threshold = 3
hide_empty = true
hide_uplinks = false
# arp_scan = passive
# arp_gateway = 10.0.0.1

# Devices — one IP per line
10.0.0.2
10.0.0.3
10.0.0.4
```

## Config Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `username` | — | Device username (required) |
| `password` | — | Device password (required) |
| `protocol` | `mops` | `mops` / `snmp` / `ssh` |
| `edge_threshold` | `3` | Max MACs for edge classification |
| `hide_empty` | `false` | Exclude empty ports from output |
| `hide_uplinks` | `false` | Exclude uplink ports from output |
| `arp_scan` | off | `passive`, or CIDR subnet(s) for active scan |
| `arp_gateway` | off | Comma-separated L3 HiOS switch IPs to query for ARP tables |

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
| `resolved_ip` | IP from ARP resolution (local cache, gateway, or self-detection) |
| `lldp_neighbor_ip` | LLDP neighbour management IP |
| `lldp_neighbor_name` | LLDP neighbour hostname |
| `lldp_neighbor_port` | LLDP neighbour port description |

## Protocol Support

Read-only tool — all features work with all live protocols. No offline mode (requires live LLDP, MAC table, and ARP data).

| Feature | MOPS | SNMP | SSH | Offline |
|---------|------|------|-----|---------|
| Port classification | Yes | Yes | Yes | — |
| ARP resolution (local cache) | Yes | Yes | Yes | — |
| ARP resolution (gateway) | Yes | Yes | Yes | — |

## Logs

Written to `logs/aaron_YYYYMMDD_HHMMSS.log` in the script directory.

## See Also

- [LOGIC.md](LOGIC.md) — Decision logic: port classification, ARP resolution, cross-device correlation
- [napalm-hios](https://github.com/adamr/napalm-hios) — NAPALM driver for HiOS
