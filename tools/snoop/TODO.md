# SNOOP — sFlow Network Observation and Overview Platform

Passive network topology and traffic mapping via sFlow. Alternative to AARON's active polling — SNOOP listens continuously and builds a live picture of what's talking to what. Feeds into NILS as the passive discovery layer.

## Driver — `get_sflow()` / `set_sflow()`

- [ ] `get_sflow()` — global sFlow config (collector IP/port, polling interval, agent address) + per-port sampling config (rate, enabled). MIBs: standard SFLOW-MIB (RFC 3176) + `HM2-PLATFORM-SFLOW-MIB` (source interface only, OID .59)
- [ ] `set_sflow(collector, port, interval, ...)` — configure collector destination, sampling rate, enable/disable per interface. MOPS + SNMP, SSH stub
- [ ] Dispatch in `hios.py`, unit tests

## Listener — Three UDP Sockets, One Daemon

SNOOP never asks. SNOOP just listens. Three event streams, all through WireGuard:

```python
sflow  = socket(AF_INET, SOCK_DGRAM)  # 6343 — traffic + heartbeat
syslog = socket(AF_INET, SOCK_DGRAM)  # 514  — human-readable events
traps  = socket(AF_INET, SOCK_DGRAM)  # 162  — structured, MIB-defined events
```

- [ ] **sFlow receiver** (UDP 6343) — sFlow v5 datagram parser. Counters + flow samples with header data. Evaluate existing Python libs (e.g. `python-sflow`) — if too heavy or unmaintained, hand-roll (sFlow v5 is a simple binary TLV format)
- [ ] **Syslog receiver** (UDP 514) — parse HiOS syslog messages. Human-readable events: link up/down, config changes, auth failures. You grep syslog
- [ ] **SNMP trap receiver** (UDP 162) — parse SNMP traps. Same events as syslog but machine-parseable: standard MIBs, standard OIDs. HiOS sends traps for: link up/down (ifOperStatus), MRP ring state changes, PSU failures, temperature warnings, auth failures, config changes. You parse traps. If SNOOP ever needs to hand off to a bigger NMS upstream, traps are the universal language
- [ ] Flow sample parsing — extract src/dst MAC, VLAN, ethertype, IP headers (if present), ingress/egress ifIndex
- [ ] Counter sample parsing — interface counters (octets, packets, errors, discards) per ifIndex
- [ ] Agent→device mapping — correlate sFlow agent IP to napalm-hios device identity (via `get_facts()` or config file)
- [ ] Port→name mapping — resolve ifIndex to interface name (via `get_interfaces()` or cached from initial connect)

## sFlow v5 Datagram Format Reference

```
UDP port 6343
├── sFlow Datagram Header
│   ├── sflow_version        (4B)  = 5
│   ├── address_type         (4B)  = 1 (IPv4)
│   ├── agent_address        (4B)  = switch IP
│   ├── sub_agent_id         (4B)  = 0
│   ├── sequence_number      (4B)
│   ├── uptime               (4B)  = ms since boot
│   └── num_samples          (4B)
│
├── Flow Sample (enterprise=0, format=1)
│   ├── source_id            = 0:N (ifIndex N)
│   ├── sampling_rate, sample_pool, drops
│   ├── input/output ifIndex
│   ├── Flow Record: Raw Packet Header (format=1)
│   │   └── header bytes: dst_mac, src_mac, 802.1Q tag, ethertype,
│   │       src_ip, dst_ip, protocol, ports, payload (truncated)
│   └── Flow Record: Extended Switch (format=1001)
│       └── src_vlan, src_priority, dst_vlan, dst_priority
│
└── Counter Sample (enterprise=0, format=2)
    └── Generic Interface (format=1): ifIndex, ifType, ifSpeed,
        ifDirection, ifStatus, octets/pkts/errors/discards in/out
```

## Passive Scan Logic (ceiling/floor/early-exit)

SNOOP's passive port census — fingerprint every edge device without sending a single frame:

- [ ] **Ceiling**: max N samplers active at once (default 4). Don't hammer the switch CPU. Tuneable: `--ceiling 2` for older RSP20, `--ceiling 8` for BRS50
- [ ] **Floor**: minimum 5s window per port. Give quiet devices a chance
- [ ] **Early exit**: got 1 unique src_mac:src_ip pair from that port? Done. Kill sampler immediately. Most PLCs are chatty — cyclic PROFINET, Modbus polling — first packet with src_mac+src_ip in header and you're done
- [ ] **Timeout**: 10s max per port. If nothing seen, mark port as "silent/no-traffic" (useful signal — either empty or listen-only device)
- [ ] **Queue**: ports waiting for a free sampler slot. Next port starts when one finishes

Example: 24-port switch, 20 edge ports:
```
t=0s    sample 1/1, 1/2, 1/3, 1/4 (ceiling=4)
t=0.3s  1/1 hits — PLC, Modbus, done. start 1/5
t=0.8s  1/3 hits — Siemens, PROFINET, done. start 1/6
t=1.1s  1/2 hits — camera, HTTP, done. start 1/7
t=3.2s  1/4 hits — HMI, done. start 1/8
...
t=14s   1/19 silent after 10s. mark unknown. start 1/20
t=16s   done. 19 devices identified, 1 silent port.
```

16 seconds for a full switch passive census. No packets sent. The silent port is useful too — AARON's LLDP/FDB already told you something's on that port, so "silent on sFlow" narrows what it could be.

## Enrichment Dictionaries (the actual value)

Raw sFlow is noise. Dicts turn numbers into meaning. User-supplied JSON config maps raw values to context:

- [ ] **VLAN dict** — map VLAN IDs to names, purposes, and Purdue levels. E.g. `{"10": {"name": "I/O Network", "purdue": 1}, "20": {"name": "Engineering", "purdue": 2}, "100": {"name": "MRP Ring", "purdue": 1}}`
- [ ] **Subnet dict** — map IP ranges to zones/purposes/Purdue levels. E.g. `{"10.1.0.0/24": {"name": "PLC Network", "purdue": 1}, "10.2.0.0/24": {"name": "SCADA", "purdue": 2}}`
- [ ] **Port classification dict** — AARON-style port types (uplink/edge/indirect) enriched onto every flow sample. Source port on an edge device = endpoint traffic, source port on an uplink = transit
- [ ] **Purdue level tagging** — every flow gets src_purdue and dst_purdue from VLAN/subnet dicts. Cross-level traffic is instantly visible. L1→L3 direct = policy violation. L0→internet = critical alert
- [ ] **Purdue flow matrix** — aggregate: how much traffic crosses each level boundary? Heatmap of L0↔L1, L1↔L2, L2↔L3, etc. Healthy network = mostly same-level + one-level-up. Anything skipping levels = investigate

## Anomaly Detection

Rules engine on enriched flow data. Not ML — deterministic pattern matching on dict-enriched fields:

- [ ] **Rogue remote access** — non-private src port (or known remote access ports: 3389, 5900, 4899, 8291) from an edge port = someone plugged in a remote access router/device. Alert immediately
- [ ] **Purdue violations** — traffic crossing more than 1 Purdue level (e.g. L0 device talking to L3 directly). Configurable policy: which level transitions are allowed
- [ ] **New MAC on edge port** — device appeared that wasn't there before. Could be laptop, could be rogue device. Log + alert
- [ ] **Unexpected VLAN traffic** — traffic on a VLAN that shouldn't exist on that port/device (misconfigured trunk, VLAN hopping)
- [ ] **Public source inside OT** — src in public range seen inside private OT network = someone already has access. Private→public is noise (devices seek default gateway even when blocked), but public→private means the path exists and is being used
- [ ] **Protocol anomalies** — industrial protocols (Modbus TCP/502, EtherNet/IP/44818, PROFINET/0x8892) seen on non-OT VLANs or non-OT subnets

## Topology Builder

- [ ] MAC learning — track src MAC + ingress port per agent, build MAC→location table (same as AARON but continuous)
- [ ] Uplink detection — MACs seen on multiple agents = transit/uplink port (same heuristic as AARON)
- [ ] Edge device tracking — MAC only seen on one agent+port = endpoint. Resolve to IP via ARP if available
- [ ] Topology diff — detect changes (new device, moved device, link down) vs last known state

## Frontend (HTML/JS)

- [ ] Live topology view — nodes (switches) + links (inter-switch) + edge devices. D3.js force-directed or similar
- [ ] Traffic overlay — flow rate per link from counter samples. Color/width = utilisation
- [ ] **Purdue view** — horizontal bands (L0 bottom to L5 top), devices placed in their level, links colored by allowed/violation. The money shot
- [ ] Device detail panel — click a node to see ports, MACs, traffic per port
- [ ] Alert feed — live anomaly alerts with context (which rule, what was seen, where)
- [ ] Timeline — history of topology changes (device joins/leaves, link flaps)
- [ ] Static site pattern (same as Hirschy) — no build step, vanilla JS, WebSocket or polling for live data from Python backend

## Integration

- [ ] NILS feed — SNOOP as passive discovery source alongside AARON (active). SNOOP sees traffic patterns, AARON sees LLDP/MAC snapshots
- [ ] CLAMPS awareness — sFlow samples reveal MRP topology (which ports carry ring traffic) without needing MRP-specific queries
- [ ] SNOOP as validator — cross-reference VIKTOR intent (what VLANs should be where), MOPS config (what's configured), and SNOOP reality (what traffic is actually flowing). Three layers of truth. The diff is where every problem lives
- [ ] SNOOP replaces AARON's L2 dependency — AARON's IP-to-MAC needed ARP (L2 only). SNOOP passive scan via sFlow eliminates that gap entirely over L3/VPN
- [ ] Hirschy integration card
