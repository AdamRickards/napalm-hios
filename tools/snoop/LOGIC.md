# SNOOP — Decision Logic

How the sFlow v5 parser works, how enrichment flows, and why the data model is shaped the way it is.

## sFlow v5 Binary Format

XDR encoding (RFC 4506) — big-endian, 4-byte aligned. Every field is `struct.unpack('>I', ...)` or `'>Q'` for 64-bit counters. No TLV nesting surprises — it's flat within each sample.

### Datagram Structure

```
┌─────────────────────────────────────────────────┐
│ Datagram Header (28 bytes for IPv4)             │
│  version(u32)=5, addr_type, agent_ip,           │
│  sub_agent, seq, uptime_ms, num_samples         │
├─────────────────────────────────────────────────┤
│ Sample 0                                        │
│  enterprise_format(u32), length(u32), data...   │
├─────────────────────────────────────────────────┤
│ Sample 1                                        │
│  ...                                            │
└─────────────────────────────────────────────────┘
```

`enterprise_format` encodes two values in one u32:
- Top 20 bits = enterprise (0 = standard sFlow)
- Bottom 12 bits = format (1=flow, 2=counter, 3=expanded flow, 4=expanded counter)

We only care about enterprise=0. Anything else is vendor-specific and skipped.

### Sample Types

```
enterprise_format u32
  │
  ├─ enterprise=0, format=1 → Flow Sample (standard)
  │   source_id packs type:index into one u32 (top 8 : bottom 24)
  │
  ├─ enterprise=0, format=2 → Counter Sample (standard)
  │   same source_id packing
  │
  ├─ enterprise=0, format=3 → Expanded Flow Sample
  │   source_type and source_index as separate u32s
  │
  ├─ enterprise=0, format=4 → Expanded Counter Sample
  │   source_type and source_index as separate u32s
  │
  └─ anything else → skip (advance by length)
```

HiOS sends standard format (1/2). Expanded format (3/4) parsed for completeness — some agents use it.

### Flow Sample Records

Each flow sample contains N records, each with its own enterprise_format:

```
Flow sample records:
  │
  ├─ enterprise=0, format=1 → Raw Packet Header
  │   protocol(u32), frame_len(u32), stripped(u32), header_len(u32)
  │   followed by header_bytes (padded to 4-byte boundary)
  │   protocol=1 means Ethernet — that's all we parse
  │
  └─ enterprise=0, format=1001 → Extended Switch
      src_vlan(u32), src_priority(u32), dst_vlan(u32), dst_priority(u32)
      The switch tells us the VLAN — more reliable than the 802.1Q tag
      in the raw header (which may have been stripped)
```

### Ethernet Header Parsing

```
Raw header bytes:
  ├─ dst_mac (6 bytes)
  ├─ src_mac (6 bytes)
  ├─ ethertype (2 bytes)
  │   │
  │   ├─ 0x8100 → 802.1Q VLAN tag present
  │   │   ├─ TCI (2 bytes): priority(3 bits) + DEI(1) + VID(12)
  │   │   └─ real ethertype (2 bytes)
  │   │
  │   ├─ 0x0800 → IPv4 header follows
  │   │   ├─ ver/ihl, tos, len, ..., protocol, src_ip, dst_ip (20+ bytes)
  │   │   ├─ protocol=6 → TCP: src_port, dst_port, ..., flags (byte 13)
  │   │   └─ protocol=17 → UDP: src_port, dst_port
  │   │
  │   ├─ 0x86DD → IPv6 header follows
  │   │   └─ next_header, src_ip, dst_ip (40 bytes, no extension chasing)
  │   │
  │   └─ anything else → ethertype recorded, no further parsing
  │       (PROFINET 0x8892, MRP 0x88E3, PTP 0x88F7, etc. — L2 only)
  │
  └─ Result: {src_mac, dst_mac, ethertype, vlan, vlan_priority,
              src_ip, dst_ip, ip_protocol, src_port, dst_port, tcp_flags, tos}
```

### Counter Sample Records

```
Counter sample records:
  │
  ├─ enterprise=0, format=1 → Generic Interface Counters (84 bytes)
  │   ifIndex(4), ifType(4), ifSpeed(8), ifDirection(4), ifStatus(4)
  │   octets_in(8), pkts_in(4), mcast_in(4), bcast_in(4),
  │     discards_in(4), errors_in(4), unknown_protos(4)
  │   octets_out(8), pkts_out(4), mcast_out(4), bcast_out(4),
  │     discards_out(4), errors_out(4)
  │
  ├─ enterprise=0, format=2 → Ethernet Interface Counters (52 bytes)
  │   alignment_errors(4), fcs_errors(4), single_collision(4),
  │   multiple_collision(4), sqe_test_errors(4), deferred_tx(4),
  │   late_collisions(4), excessive_collisions(4),
  │   internal_mac_tx_errors(4), carrier_sense_errors(4),
  │   frame_too_longs(4), internal_mac_rx_errors(4), symbol_errors(4)
  │   → From EtherLike-MIB (RFC 2665). Gold for cable fault detection.
  │   → Parsed but HiOS 10.x does NOT send these. SNMP polling required.
  │
  └─ anything else → logged as unknown (enterprise, format, length)
```

84 bytes for generic, not 88. The sFlow spec description makes it look like 88 because it lists `ifPromiscuousMode` which isn't actually in the XDR encoding for format=1.

Ethernet counters (format=2) would give alignment errors, FCS errors, symbol errors — early indicators of cable/connector degradation in OT environments. Tested live: HiOS 10.3.04 on GRS1042 and BRS50 only sends format=1 (generic). The parser is ready if future firmware adds format=2.

## Enrichment Pipeline

Every parsed flow sample passes through `enrich_flow()` which layers decoded names on top of raw values.

### Decode Order

```
Raw parsed header
  │
  ├─ ethertype (int) → ETHERTYPES dict → ethertype_name ("IPv4", "PROFINET", ...)
  ├─ ip_protocol (int) → IP_PROTOCOLS dict → protocol_name ("TCP", "UDP", ...)
  ├─ src_port (int) → SERVICES dict → src_service ("SSH", "Modbus", ...)
  ├─ dst_port (int) → SERVICES dict → dst_service
  ├─ tcp_flags (int) → TCP_FLAGS dict → tcp_flags_name ("SYN-ACK", ...)
  ├─ tos (int) → TOS_VALUES dict → tos_name ("Routine", "Critical", ...)
  ├─ vlan_priority (int) → VLAN_PRIORITY dict → vlan_priority_name ("Voice", ...)
  │
  ├─ VLAN (from ext_switch.src_vlan, fallback to 802.1Q tag)
  │   └─ vlan_dict lookup → vlan_name, vlan_purdue
  │
  ├─ src_ip → subnet_dict longest-prefix match → src_zone, src_purdue
  ├─ dst_ip → subnet_dict longest-prefix match → dst_zone, dst_purdue
  │
  └─ purdue_crossing = abs(src_purdue - dst_purdue) > 1
```

### VLAN Source Priority

The VLAN ID comes from two places. Extended switch is preferred:

```
Which VLAN to use?
  │
  ├─ Extended switch record exists?
  │   └─ YES → use ext_switch.src_vlan (switch told us, most accurate)
  │
  └─ NO → use 802.1Q tag from raw header
      └─ may be None if untagged frame
```

Same logic for 802.1p priority: extended switch `src_priority` first, fallback to 802.1Q TCI.

### Subnet Lookup — Longest Prefix Match

Subnet table is pre-sorted by prefix length (longest first) at startup. Lookup walks the list, first match wins:

```
subnet_table (sorted: /28 before /24 before /8):
  10.1.0.0/28  → "PLC Rack A"
  10.1.0.0/24  → "PLC Network"
  10.0.0.0/8   → "Private"

lookup("10.1.0.5")  → hits /28 first → "PLC Rack A"
lookup("10.1.0.100") → misses /28, hits /24 → "PLC Network"
lookup("10.99.0.1")  → misses /28 and /24, hits /8 → "Private"
```

### Purdue Crossing

Simple: if both src and dst have a Purdue level from their respective subnet entries, and the absolute difference is greater than 1, flag it.

```
src_purdue=1 (PLC), dst_purdue=2 (SCADA)  → diff=1 → OK (adjacent levels)
src_purdue=1 (PLC), dst_purdue=3 (Mgmt)   → diff=2 → purdue_crossing=true
```

The threshold of 1 is hardcoded for v0.1. Future: configurable policy per level pair.

## Data Model

### Why Separate Layer Files

Each table answers a different question:
- **mac_table** — "Where is this device?" (agent + port + VLAN)
- **arp_table** — "What IP does this MAC have?" (and what zone is it in)
- **vlan_table** — "Which VLANs are active on which switches/ports?"
- **port_counters** — "How busy is each port?" (octets, packets, errors)
- **port_traffic** — "What kind of traffic is on each port?" (protocols, services, MACs)

Consumers pick what they need. NILS reads mac_table + arp_table. VIKTOR reads vlan_table. The anomaly detector reads port_traffic.

### State Accumulation

All state is in-memory (`SnoopState`), flushed to disk periodically. No database, no persistence between runs. Start fresh each time — sFlow will repopulate within seconds.

```
Datagram arrives
  │
  ├─ update_agent() — track agent IP, datagram count, sequence
  │
  ├─ For each flow sample:
  │   ├─ Extract raw_header + ext_switch from records
  │   ├─ enrich_flow() → decoded names + dict lookups
  │   ├─ update mac_table — src_mac → {agent, port, vlan, ip}
  │   ├─ update arp_table — src_ip → {mac, zone, purdue}
  │   ├─ update vlan_table — vlan → {agents, ports}
  │   └─ update port_traffic — agent:port → {ethertypes, protocols, services, macs}
  │
  └─ For each counter sample:
      └─ update port_counters — agent:ifIndex → raw counter values
```

### MAC Table Updates

Source MAC from the ingress port is the authoritative location:

```
src_mac seen on agent X, port Y, vlan Z
  │
  ├─ New MAC? → create entry with first_seen
  └─ Known MAC? → update agent, port, vlan, last_seen, bump samples
      └─ IP updated if present in this sample (may not always be)
```

Broadcast/multicast MACs (`ff:ff:ff:ff:ff:ff`) and zero MACs are skipped.

### ARP Table Updates + Gateway Auto-Detection

The ARP table only stores **private IPs from real end devices**. Two filters clean out noise before it can pollute the table:

1. **Infrastructure OUI filter** — Hirschmann/Belden switch MACs are never end devices. Their VRI interfaces appear as src_mac in routed traffic, but the IP belongs to the device behind the router, not the router itself. Filtering by OUI catches ALL VRI MACs regardless of IP address patterns.

2. **Gateway auto-detection** — non-infrastructure MACs that resolve to multiple IPs in different /24 networks (configurable via `--gateway-prefix`) are reclassified as gateways (e.g., the internet router). Only same-family comparisons — dual-stack (IPv4 + IPv6) is not a gateway trigger.

### Infrastructure OUI Filtering

```
INFRASTRUCTURE_OUIS = {
    'ec:74:ba'   — Hirschmann (GRS, RSP, MSP, DRAGON, etc.)
    '64:60:38'   — Hirschmann (BRS, OCTOPUS, etc.)
    '00:80:63'   — Hirschmann Automation (classic/legacy)
    '00:d0:26'   — Hirschmann Austria
    'a0:b0:86'   — Hirschmann (newer models, 2021+)
    '94:ae:e3'   — Belden Hirschmann (Suzhou)
}
```

If `mac[:8] in INFRASTRUCTURE_OUIS` → skip ARP entirely. The MAC still appears in the FDB (we want to see switch ports), but it never creates an ARP entry or triggers gateway detection.

**Why this matters**: when a GRS1042 routes a packet from VLAN 3 to VLAN 1, the src_mac is rewritten to the VRI's MAC (e.g., `ec:74:ba:35:75:9c`), but src_ip stays as the original sender (e.g., `192.168.4.3`). Without OUI filtering, the ARP table would record `192.168.4.3 → ec:74:ba:35:75:9c` (wrong — that's the router's VRI, not the end device). The real binding `192.168.4.3 → b4:2e:99:0e:39:fb` arrives when the pre-routing agent (GRS port 1) samples the same packet.

### Gateway Auto-Detection

Every IP→MAC binding passes through `_update_arp_or_gateway()` which routes it to either the ARP table or the gateways dict:

```
New IP→MAC binding arrives
  │
  ├─ Infrastructure OUI? → discard (switch MAC, not an end device)
  │
  ├─ Agent IP xref? → discard (IP belongs to a known sFlow agent = switch)
  │
  ├─ MAC already in gateways? → add IP to gateway's ip set, done
  │
  ├─ MAC already in ARP with a DIFFERENT IP?
  │   │
  │   └─ Same address family? (IPv4↔IPv6 = dual-stack, not gateway)
  │       │
  │       ├─ Mixed family → normal update (dual-stack device)
  │       │
  │       └─ Same family → cross-network? (different /24, configurable)
  │           │
  │           ├─ YES → reclassify as gateway
  │           │   ├─ Remove ALL ARP entries for this MAC
  │           │   ├─ Create gateway entry with all IPs
  │           │   └─ If any IP is private → record as own_ip
  │           │
  │           └─ NO → normal update (could be DHCP renew, same subnet)
  │
  └─ New MAC, not a gateway
      ├─ Public IP? → discard (don't pollute ARP)
      └─ Private IP? → create normal ARP entry
```

**Gateway detection trigger**: the second IP for the same MAC. Normal devices have one IP per MAC. A MAC resolving to multiple IPs in different networks is definitively a gateway — it's forwarding packets from many sources, and sFlow records the src_mac of the last L2 hop (the gateway's own MAC) with whatever L3 src_ip was in the packet.

**Cross-network check**: default `/24` prefix (configurable via `--gateway-prefix`). `192.168.1.x` and `192.168.2.x` → different /24 → flagged as gateway. `192.168.1.1` and `192.168.1.254` → same /24 → not flagged (could be secondary IP). Use `--gateway-prefix 8` for the loosest check (only different first octets trigger), `--gateway-prefix 16` for a middle ground.

**Dual-stack fix**: IPv4 + IPv6 link-local on the same MAC is normal dual-stack, not a gateway. Cross-network only compares within the same address family. Without this, every modern device with both `192.168.x.x` and `fe80::` would false-positive as a gateway.

**Gateway own_ip**: the gateway's actual management IP. Discovered when the gateway originates traffic (ICMP, ARP replies, routing protocol) — `src_mac=gateway_mac` with a private `src_ip`. Not guaranteed on first detection, fills in over time as more samples arrive.

**Output structure** (in `arp_table.json`):
```json
{
  "entries": {
    "192.168.1.100": {"mac": "00:11:22:33:44:55", ...}
  },
  "gateways": {
    "aa:bb:cc:dd:ee:ff": {
      "ips": ["18.155.216.101", "142.250.70.14", "192.168.1.1"],
      "own_ip": "192.168.1.1",
      "agent": "192.168.1.254",
      "port": "7",
      "first_seen": "...", "last_seen": "...", "samples": 1247
    }
  }
}
```

The `unique_ips` stat in `state.json` counts only ARP entries (local devices), not gateway IPs.

### Port Traffic Counters

Per-agent, per-port, decoded names as keys:

```json
{
  "ethertypes": {"IPv4": 145, "ARP": 3, "PROFINET": 87},
  "protocols": {"TCP": 98, "UDP": 47},
  "services": {"Modbus": 45, "HTTP": 12}
}
```

Dict keys are the decoded human-readable names, not raw numbers. Unknown values use fallback format: `"0x88b5"`, `"proto_47"`, `"9999"`.

### Agent IP Cross-Reference

Every sFlow agent identifies itself by IP. That IP may also appear in flow samples from OTHER agents (e.g., the BRS50 sees traffic from the GRS1042's management IP). If we let those through to ARP, the switch's management IP gets recorded as an end device.

Fix: `if ip in self.agents: return` — any IP that matches a known sFlow agent is infrastructure and gets skipped in ARP. This works alongside OUI filtering as a belt-and-suspenders approach:

- **OUI filter** catches Hirschmann MACs regardless of IP
- **Agent xref** catches any managed switch regardless of vendor (future: non-Hirschmann sFlow agents)

The two filters are complementary. OUI works from MAC→vendor, agent xref works from IP→role.

### OUI in Output (SOC/Compliance)

FDB entries and ARP entries include an `oui` field with the vendor name when the MAC matches a known OUI. This supports SOC compliance requirements where customers need to identify device manufacturers on their network.

```json
{
  "ec:74:ba:35:75:9c": {
    "vlan": 7, "ip": "192.168.1.254",
    "oui": "Hirschmann (GRS, RSP, MSP, DRAGON, etc.)",
    ...
  }
}
```

Only present when the OUI matches `INFRASTRUCTURE_OUIS`. Future: broader IEEE OUI database for all vendors.

## Atomic Writes

All JSON output uses write-to-temp + rename:

```python
write to path.tmp → os.replace(path.tmp, path)
```

No partial reads possible. Consumers always see complete JSON. Flush interval (default 5s) means disk writes are batched, not per-packet.

## Thread Model

v0.1 is single-threaded: one socket, one recv loop, parse and accumulate inline. This is fine — sFlow parsing is pure `struct.unpack()` with zero allocations on the hot path.

When syslog (514) and traps (162) are added, each gets its own thread feeding shared state. The flush timer will need a lock, but the per-socket recv loops stay independent.

## Decode Dict Sources

Six built-in dicts, all converted from the YAML files in `sFlow/dictionaries/` that powered the previous Logstash pipeline:

| Dict | Source YAML | Key type | Entries |
|------|------------|----------|---------|
| `ETHERTYPES` | `ieee_ethertype.yaml` + manual | `int(hex, 16)` | 46 |
| `IP_PROTOCOLS` | `iana_protocols.yaml` | `int(str)` | 139 |
| `SERVICES` | `iana_services.yaml` + industrial | `int(str)` | 361 |
| `TCP_FLAGS` | `tcp_flags.yaml` | `int(hex, 16)` | 64 |
| `TOS_VALUES` | `rfc_tos.yaml` | `int(hex, 16)` | 26 |
| `VLAN_PRIORITY` | IEEE 802.1Q-2022 Table 8-2 | `int` | 8 |

Industrial additions beyond IANA: Modbus (502), EtherNet/IP (44818), OPC-UA (4840), BACnet (47808), DNP3 (20000), ADS/AMS (48898), PROFINET-RT (34962-34964), IEC 60870-5-104 (2404), HART-IP (5094), GE-SRTP (4712/18245), FINS (9600), MQTT (1883/8883), CIP (2222/4000), GOOSE (0x88B8), GSE (0x88B9), IEC 61850 SV (0x88BA).
