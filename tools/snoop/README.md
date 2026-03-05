# SNOOP — sFlow Network Observation and Overview Platform

Passive network observation via sFlow v5. Receives sFlow datagrams from HiOS switches, decodes packet headers and interface counters, enriches with VLAN/subnet dictionaries, and writes structured JSON layer files. Zero external dependencies — hand-rolled XDR parser like MARCO's hand-rolled BER.

SNOOP never asks. SNOOP just listens.

## Requirements

- Python 3.8+
- No pip dependencies (stdlib only)
- sFlow v5 source (HiOS switch, or `test_snoop.py --send` for testing)

## Quick Start

```bash
python snoop.py                                          # listen on 0.0.0.0:6343
python snoop.py --sflow-port 6343 -o ./output            # explicit port + output dir
python snoop.py --vlan-dict vlan_dict.json               # VLAN enrichment
python snoop.py --subnet-dict subnet_dict.json           # subnet/zone enrichment
python snoop.py --vlan-dict vlan.json --subnet-dict sub.json --debug
```

## Configure sFlow on HiOS

```
sflow receiver 1 ip <snoop_ip> 6343
sflow sampler 1 1/1-1/6 sampling-rate 256
sflow poller 1 1/1-1/6 polling-interval 20
```

Or via MOPS/SNMP once `set_sflow()` exists in the driver.

## Arguments

| Flag | Description |
|------|-------------|
| `-l`, `--listen` | Bind address (default: `0.0.0.0`) |
| `--sflow-port` | sFlow UDP port (default: `6343`) |
| `-o`, `--output` | Output directory (default: `./output`) |
| `--write-interval` | Seconds between disk flushes (default: `5`) |
| `--vlan-dict` | VLAN enrichment dict (JSON file) |
| `--subnet-dict` | Subnet/zone enrichment dict (JSON file) |
| `--gateway-prefix` | Prefix length for gateway detection (default: `/24`) |
| `--debug` | Debug logging to console |
| `-s`, `--silent` | Suppress all console output |

## Enrichment Dicts

### Built-in (compiled from `sFlow/dictionaries/*.yaml`)

| Dict | Entries | Purpose |
|------|---------|---------|
| `ETHERTYPES` | 46 | Ethernet type → name (IPv4, ARP, PROFINET, EtherCAT, MRP, PTP, HSR, GOOSE, IEC 61850 SV, ...) |
| `IP_PROTOCOLS` | 139 | IP protocol number → name (TCP, UDP, ICMP, GRE, VRRP, OSPF, ...) |
| `SERVICES` | 361 | TCP/UDP port → name (Modbus, EtherNet/IP, OPC-UA, BACnet, DNP3, PROFINET-RT, HART-IP, IEC 104, MQTT, GE-SRTP, FINS, ...) |
| `TCP_FLAGS` | 64 | Flag byte → combination name (SYN, SYN-ACK, PSH-ACK, ...) |
| `TOS_VALUES` | 26 | IPv4 ToS byte → QoS class (Routine, Priority, Flash, Critical, ...) |
| `VLAN_PRIORITY` | 8 | 802.1p PCP → IEEE name (Best Effort, Voice, Network Ctrl, ...) |

### User-supplied (optional JSON)

**`vlan_dict.json`** — VLAN ID → name + Purdue level:
```json
{
  "10": {"name": "I/O Network", "purdue": 1},
  "20": {"name": "Engineering", "purdue": 2},
  "100": {"name": "MRP Ring", "purdue": 1},
  "200": {"name": "Management", "purdue": 3}
}
```

**`subnet_dict.json`** — CIDR → zone name + Purdue level (longest-prefix match):
```json
{
  "10.1.0.0/24": {"name": "PLC Network", "purdue": 1},
  "10.2.0.0/24": {"name": "SCADA", "purdue": 2},
  "10.10.0.0/24": {"name": "Management", "purdue": 3}
}
```

When both are loaded, every flow sample gets:
- `vlan_name`, `vlan_purdue` from VLAN dict
- `src_zone`, `src_purdue`, `dst_zone`, `dst_purdue` from subnet dict
- `purdue_crossing: true` if src and dst differ by more than 1 Purdue level

## Output

All files written atomically (`.tmp` + `os.replace()`), flushed every `--write-interval` seconds.

```
output/
  state.json                    ← session summary, stats, agent list, gateway count
  agents/{agent_ip}.json        ← per-switch agent info + interface counters
  layers/
    fdb.json                    ← per-agent per-port MAC table (reconstructed FDB, with OUI)
    arp_table.json              ← private IPs only + auto-detected gateways (with OUI)
    vlan_table.json             ← VLANs observed per agent per port, with end device MACs
    port_counters.json          ← per-agent per-port interface counters (+ ethernet if available)
    port_traffic.json           ← per-agent per-port: ethertypes, protocols, services, MACs
```

**Data hygiene**: Hirschmann switch MACs (6 OUIs) are filtered from the ARP table — VRI interfaces never appear as end devices. sFlow agent IPs are also excluded. Gateways are auto-detected when a MAC resolves to multiple IPs in different /24 networks (configurable) and moved to a separate `gateways` section. Dual-stack (IPv4 + IPv6 link-local) does not trigger gateway detection.

Other tools read these files directly — filesystem as IPC, same pattern as NILS `discovery/`.

## Console Output

```
============================================================
  SNOOP — sFlow Network Observation and Overview Platform
============================================================
  Listening: sFlow on 0.0.0.0:6343
  Dicts: vlan_dict.json (12 VLANs), subnet_dict.json (8 subnets)
  Output: ./output/
------------------------------------------------------------
  [  5s] dgrams:   127 | flows:   391 | cntrs:   24 | agents: 3 | MACs: 47 | IPs: 23 | GWs: 1
  [ 10s] dgrams:   254 | flows:   782 | cntrs:   48 | agents: 3 | MACs: 51 | IPs: 25 | GWs: 1
  ^C
============================================================
  Session: 10.2s | 254 datagrams | 3 agents | 51 MACs | 25 IPs | 1 GWs
  Output: ./output/ (8 files written)
============================================================
```

## Testing

```bash
# Run parser + enrichment + output tests (no network):
python test_snoop.py

# Send crafted sFlow datagrams to a running instance:
python test_snoop.py --send localhost 6343
```

16 tests covering: decode dicts, Ethernet/VLAN/ARP/PROFINET parsing, datagram parsing, enrichment, subnet lookup, state model, output files, full round-trip, gateway auto-detection, cross-network detection, infrastructure OUI filtering, and Ethernet counter parsing. All crafted binary sFlow v5 datagrams with `struct.pack()`, zero network required.

## See Also

- [LOGIC.md](LOGIC.md) — parser design, enrichment pipeline, data model decisions
- [TODO.md](TODO.md) — roadmap (syslog, traps, passive scan, anomaly detection)
- `sFlow/dictionaries/` — original YAML dicts from the Logstash pipeline
- `sFlow/*.conf` — legacy Logstash configs (reference only)
