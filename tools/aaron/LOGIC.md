# AARON — Decision Logic

How AARON classifies ports and resolves MAC addresses to IPs.

## Port Classification

Every port on every switch gets exactly one classification. The decision
tree runs in two passes: uplinks first (LLDP), then everything else
(MAC table + cross-device correlation).

```
Pass 1 — Identify uplinks (LLDP):

For each port with LLDP neighbors:
  │
  Filter out FDB-sourced entries (remote_port == 'FDB')
  │
  Take first real neighbor
  │
  Has detail? (system name OR mgmt IP OR port description)
    │
    ├─ YES → UPLINK (managed switch or infrastructure device)
    │
    └─ NO  → EDGE (bare LLDP)
             Typical of Windows LLDP stack — sends LLDP frames
             but with no useful identification fields


Pass 2 — Classify remaining ports (no LLDP):

  Has MACs on this port?
    │
    ├─ NO  → EMPTY (nothing connected, or device is off)
    │
    └─ YES → Check MAC index (cross-device lookup)
             │
             Any MAC also seen on a non-uplink port
             on a DIFFERENT device?
               │
               ├─ YES → INDIRECT (unmanaged switch suspected)
               │
               └─ NO  → EDGE (end device)
```

### Why "Indirect"?

An unmanaged switch bridges all MACs through it. If a MAC appears on
port 1/3 of switch A and also on port 1/7 of switch B (neither being
an uplink), there's likely an unmanaged switch between them creating
a shared L2 domain outside the managed ring.

The threshold is 1 — any single MAC match triggers indirect. This is
intentionally sensitive. A false positive (edge marked indirect) is
harmless. A false negative (unmanaged switch missed) hides a topology
problem.

### What Gets Filtered

Before classification:
- Static MACs are skipped (only dynamic/learned)
- `cpu` and `mgmt` interfaces are skipped (switch internals)

## ARP Scan

Resolves edge/indirect port MACs to IP addresses. Two modes:

```
Config: arp_scan = ?
  │
  ├─ passive     → read OS ARP cache only
  │               No packets sent. Only resolves IPs the scanner
  │               machine has already talked to. Fast but incomplete.
  │
  └─ subnet(s)   → active UDP tickle + read cache
     e.g. 192.168.1.0/24
```

### Active Mode: UDP Tickle

```
For each IP in subnet(s):
  │
  Skip known switch IPs (already connected)
  │
  socket.sendto(b'Hirschmann is the way.', (ip, 1))
  │
  ├─ IP exists → OS sends ARP request → ARP cache populated
  └─ IP absent → ARP times out → no cache entry
```

Why UDP port 1? Doesn't matter — the packet is throwaway. The goal is
to trigger the OS ARP resolution for that IP. The ARP cache is the
actual data source, not the UDP response (which is discarded).

256 threads in parallel — entire /24 tickled in under a second. Runs
in background while switch data is being gathered.

### Cache Reading

- **Linux:** parse `/proc/net/arp` directly (no subprocess)
- **Windows:** parse `arp -a` output

### Gateway ARP Table

ARP is L2 — the scanner can only resolve MACs in subnets it's directly
connected to. For devices in other subnets (across a router or L3
switch), the scanner's ARP cache will never have them.

The gateway solves this: query an L3 HiOS switch's ARP table via
`get_arp_table()` to get IP:MAC mappings for subnets the scanner
isn't part of.

```
Scanner subnet: 192.168.1.0/24
  └─ Local ARP cache covers this

Other subnets: 10.0.0.0/24, 172.16.0.0/24
  └─ Scanner can't ARP these — different L2 domain
  └─ L3 gateway (10.0.0.1) HAS these in its ARP table
  └─ arp_gateway = 10.0.0.1 → query + merge
```

Merges into the MAC→IP map. First match wins (`setdefault`) — local
cache takes priority over gateway data.

The gateway ARP table may be incomplete — a router only has entries
for hosts it has recently communicated with. For complete results,
couple with an active scan of those ranges (which populates the
gateway's ARP cache). Without active scan, accept partial results.

### Local Identity

AARON detects its own IP and MACs to exclude the scanner machine from
results. Uses a UDP connect trick (no data sent) to learn which local
IP the OS would route to the target subnet, then reads local interface
MACs.

## LLDP Neighbor Matching

Simpler than VIKTOR — AARON doesn't need to build links or deduplicate.
It just reads what LLDP provides per port:

```
Neighbor identification:
  Name:  remote_system_name → remote_chassis_id (fallback)
  Port:  remote_port_description → remote_port (fallback)
  IP:    remote_management_ipv4
```

No port normalization needed — AARON displays the raw values, it doesn't
need to correlate ports across devices like VIKTOR's auto-trunk does.

## ARP Enrichment

After classification, edge and indirect ports get IP resolution:

```
For each edge/indirect port:
  │
  Single MAC on port?
    │
    ├─ YES → exact lookup in MAC→IP map
    │
    └─ NO  → try each MAC, join resolved IPs with '|'
             (multiple devices behind unmanaged switch)
```

MAC normalization: switch MACs are lowercased before ARP cache lookup
(switch may report `AA:BB:CC`, cache has `aa:bb:cc`).

## Output Filtering

```
Config options:
  hide_empty   → suppress empty ports from output
  hide_uplinks → suppress uplink ports from output

Default: show everything. Hiding uplinks is useful when you only care
about what's connected at the edge.
```
