# SNOOP — TODO

## v0.1 — sFlow Listener + Layered Data Model (DONE)

- [x] sFlow v5 datagram parser — hand-rolled XDR, zero deps
- [x] Flow sample parsing — raw packet header (Ethernet/IPv4/IPv6/TCP/UDP) + extended switch
- [x] Counter sample parsing — generic interface counters (format=1) + Ethernet counters (format=2, parsed but HiOS doesn't send them)
- [x] Unknown counter record format logging (for discovering new record types)
- [x] Expanded flow/counter sample support (format 3/4)
- [x] Built-in decode dicts — ethertypes (46), IP protocols (139), services (361), TCP flags (64), ToS (26), 802.1p priority (8)
- [x] Industrial protocol coverage — Modbus, EtherNet/IP, OPC-UA, BACnet, DNP3, PROFINET-RT, IEC 104, HART-IP, GE-SRTP, FINS, MQTT, CIP, ADS/AMS, GOOSE, GSE, IEC 61850 SV
- [x] Optional VLAN dict (JSON) — VLAN → name + Purdue level
- [x] Optional subnet dict (JSON) — CIDR → zone + Purdue level, longest-prefix match
- [x] Purdue crossing detection (src/dst differ by >1 level)
- [x] Layered JSON output — FDB, arp_table (with gateways), vlan_table, port_counters, port_traffic
- [x] Per-agent FDB — reconstructed forwarding database per switch (agent → port → MACs)
- [x] Gateway auto-detection — multi-IP cross-network trigger (/24 default, configurable `--gateway-prefix`), dual-stack safe (IPv4+IPv6 not a trigger), multi-pop cleanup on reclassify
- [x] Infrastructure OUI filtering — 6 Hirschmann/Belden OUIs, VRI MACs never pollute ARP
- [x] Agent IP cross-reference — sFlow agent IPs excluded from ARP (they're switches)
- [x] OUI vendor in output — FDB and ARP entries tagged with manufacturer (SOC compliance)
- [x] Per-agent JSON files with interface counters
- [x] Atomic writes (.tmp + os.replace), periodic flush
- [x] CLI — argparse, banner/footer, stats line (incl. GW count), silent mode, debug
- [x] Test suite — 16 tests, crafted binary datagrams, round-trip validation
- [x] Test packet sender (`test_snoop.py --send`)
- [x] README.md, LOGIC.md
- [x] Live tested — GRS1042 + BRS50, 2 agents, zero parse errors

## Driver — `get_sflow()` / `set_sflow()`

- [ ] `get_sflow()` — global sFlow config (collector IP/port, polling interval, agent address) + per-port sampling config (rate, enabled). MIBs: SFLOW-MIB (RFC 3176) + `HM2-PLATFORM-SFLOW-MIB` (.59)
- [ ] `set_sflow(collector, port, interval, ...)` — configure collector destination, sampling rate, enable/disable per interface. MOPS + SNMP, SSH stub
- [ ] Dispatch in `hios.py`, unit tests

## Testing — PCAP Replay

- [ ] `replay_pcap.py` — read pcap files, wrap each frame in sFlow v5 flow sample, send to SNOOP. Hand-rolled pcap reader (24B global + 16B per-packet + data), zero deps. Uses existing `build_*` functions from test_snoop.py
- [ ] Validate decode dicts against real ICS traffic from public pcap collections:
  - `automayt/ICS-pcap` — comprehensive, sorted by protocol (Modbus, DNP3, EtherNet/IP, S7comm, BACnet, etc.)
  - `netresec.com/PCAP4SICS` — 360MB from 4SICS ICS village
  - `ITI/ICS-Security-Tools/pcaps` — community curated, PROFINET from the wild, OpenDNP3
  - `tjcruz-dei/ICS_PCAPS` — Univ. of Coimbra ICS cybersecurity collection
  - `wireshark.org/SampleCaptures` — GOOSE, MMS, etc.

## v0.2 — Passive Scan (requires `set_sflow()`)

- [ ] Ceiling/floor/early-exit sampler queue — max N ports active, min 5s window, exit on first unique src_mac:src_ip pair
- [ ] Timeout (10s) — mark port as silent/no-traffic
- [ ] Full switch passive census — ~16s for 24-port switch, zero packets sent
- [ ] Integration with site.json (`-fi` flag)

## v0.3 — Syslog + SNMP Traps

- [ ] Syslog receiver (UDP 514) — parse HiOS syslog messages: link up/down, config changes, auth failures
- [ ] SNMP trap receiver (UDP 162) — parse standard traps: ifOperStatus, MRP ring state, PSU failure, temperature, auth failures, config changes
- [ ] Per-socket threads feeding shared state
- [ ] Flush timer with thread lock

## v0.4 — Anomaly Detection

Rules engine on enriched flow data. Deterministic pattern matching, not ML:

- [ ] **Rogue remote access** — known remote access ports (3389, 5900, 4899, 8291) from an edge port
- [ ] **Purdue violations** — traffic crossing more than 1 Purdue level. Configurable policy per level pair
- [ ] **New MAC on edge port** — device appeared that wasn't there before
- [ ] **Unexpected VLAN traffic** — traffic on a VLAN that shouldn't exist on that port
- [ ] **Rogue gateway detection** — flow sample has `not is_private(src_ip)` → public IP arrived on ingress port N of agent X. That physical port has an internet gateway behind it (router, hotspot, cellular modem). Flag agent + port + src_ip
- [ ] **Protocol anomalies** — industrial protocols (Modbus, EtherNet/IP, PROFINET) on non-OT VLANs/subnets
- [ ] **MRP priority fault** — ethertype 0x88E3 (MRP) with 802.1p priority != 7 → MRP VLAN misconfiguration. MRP without VLAN tag at all → MRP running untagged (also bad)

## v0.5 — Topology Builder

- [ ] MAC learning — continuous MAC→location table (like AARON but live)
- [ ] Uplink detection — MACs seen on multiple agents = transit port
- [ ] Edge device tracking — MAC on one agent:port only = endpoint
- [ ] Topology diff — detect changes vs last known state (new device, moved, link down)

## Future — Frontend (HTML/JS)

- [ ] Live topology view — D3.js force-directed, switches + links + edge devices
- [ ] Traffic overlay — flow rate per link from counter samples
- [ ] **Purdue view** — horizontal bands (L0→L5), devices placed in level, violations colored
- [ ] Device detail panel — click node, see ports/MACs/traffic
- [ ] Alert feed — live anomaly alerts with context
- [ ] Timeline — history of topology changes
- [ ] Static site pattern (same as Hirschy) — no build step, vanilla JS

## Future — Integration

- [ ] Agent→device mapping — correlate sFlow agent IP to device identity via `get_facts()` or config
- [ ] Port→name mapping — resolve ifIndex to interface name via `get_interfaces()`
- [ ] Port classification dict — AARON-style uplink/edge/indirect enrichment per flow
- [ ] Purdue flow matrix — aggregate cross-level traffic heatmap
- [ ] NILS feed — SNOOP as passive discovery source alongside AARON
- [ ] CLAMPS awareness — sFlow reveals MRP ring topology without MRP queries
- [ ] SNOOP as validator — cross-reference VIKTOR intent, MOPS config, SNOOP reality (three layers of truth)
- [ ] Replace AARON's L2 dependency — sFlow for IP:MAC over L3/VPN instead of ARP
- [ ] Hirschy integration card
