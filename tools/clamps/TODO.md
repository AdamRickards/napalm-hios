# CLAMPS — TODO

## Zero-Config Discovery Mode

The current CLAMPS requires a config file (`script.cfg`) where every device, port, role, and VLAN is declared explicitly. But the physical cabling already defines the topology — LLDP can tell us everything we need. The goal: **plug in a laptop and type `clamp`**.

### The Insight

MRP has one invariant: **there is exactly one main ring**. Everything else is a sub-ring, even if cascaded. The physical topology IS the logical configuration — we just need to read it.

### Bare Minimum Invocation

```
python clamp.py
```

No arguments. No config file. The script discovers everything.

### Discovery Flow

1. **Find ourselves** — `get_local_identity()` (from AARON) detects our own IP/MAC on the network. Identifies which switch and port we're connected to. This is our entry point.

2. **LLDP crawl** — starting from the entry switch, recursively call `get_lldp_neighbors_detail()` on every discovered switch. Build the full adjacency graph. Each edge knows: device A port X ↔ device B port Y.

3. **Find the ring** — cycle detection in the LLDP graph. There is exactly one main ring (the single cycle). The ports involved in the cycle are the ring ports.

4. **Find sub-rings** — any additional cycles branching off the main ring are sub-rings. A sub-ring branches at two devices on the main ring (or on a parent sub-ring for cascaded). The branch points are the SRM/RSRM devices, with one port each connecting to the sub-ring segment.

5. **Assign roles**:
   - **RM**: highest IP in the main ring (unless overridden)
   - **SRM**: first branch point of each sub-ring (by IP order)
   - **RSRM**: second branch point
   - **RC**: everything else (main ring clients + sub-ring segment devices)

6. **Assign VLANs**:
   - Main ring: VLAN 100 (unless overridden)
   - Sub-rings: VLAN 101, 102, ... incrementing (unless overridden)

7. **Assign ports** — LLDP already tells us exactly which port connects to which neighbor. Ring ports are the ports that form the cycle. Sub-ring ports are the ports on branch-point devices that connect to the sub-ring segment.

8. **Validate** — cross-check everything against LLDP reality. Detect mismatches, missing links, unexpected topologies. Flag anything suspicious.

9. **Show banner** — display the full deployment plan (same banner format as today). User confirms before anything is touched.

10. **Deploy** — same phased deployment as today. Safety sequence unchanged (RM port2 down, configure, close, verify).

### Override Model

The config file becomes purely optional — for overriding defaults when the auto-discovery isn't what you want:

```
# Override just the RM
python clamp.py --rm 192.168.1.80

# Override the main ring VLAN
python clamp.py --vlan 50

# Override entry point (skip auto-detection)
python clamp.py --entry 192.168.1.4

# Config file for complex overrides
python clamp.py -f overrides.cfg
```

Anything not specified is auto-discovered. Anything specified takes priority over discovery. Invalid overrides (port that doesn't match LLDP reality) are flagged with a warning.

### Existing Building Blocks

Everything needed already exists in napalm-hios:

| Component | Status | Location |
|-----------|--------|----------|
| `get_local_identity()` | Done | AARON (`tools/aaron/`) |
| `get_lldp_neighbors_detail()` | Done | All 3 protocols |
| LLDP crawl pattern | Done | AARON already crawls LLDP |
| Port classification (uplink/edge) | Done | AARON |
| MRP get/set/delete | Done | All 3 protocols |
| SRM get/set/delete | Done | All 3 protocols |
| Phased deployment | Done | CLAMPS clamp.py |
| Phased teardown | Done | CLAMPS unclamp.py |
| Edge protection | Done | CLAMPS (rstp-full/loop/rstp) |
| Banner + confirm | Done | CLAMPS |

### New Code Needed

1. **Graph builder** — LLDP adjacency list → NetworkX-style graph (or simple dict-of-dicts). Each edge = (deviceA, portA, deviceB, portB).

2. **Cycle finder** — find all simple cycles in the graph. Classify: longest cycle = main ring, shorter cycles branching off = sub-rings. For cascaded sub-rings: a sub-ring that branches off another sub-ring rather than the main ring.

3. **Role assigner** — given the cycle structure, assign RM/SRM/RSRM/RC roles with the default heuristics (highest IP = RM, branch-point ordering for SRM/RSRM).

4. **Config merger** — merge discovered topology with any user overrides (CLI args or config file). User overrides always win.

5. **Topology validator** — compare discovered topology against expected ring structure. Detect: open rings (missing link), unexpected cross-links, devices not reachable from entry.

### Edge Cases

- **No ring found** — all links are tree-shaped (no cycles). This means either the ring isn't cabled yet, or LLDP isn't enabled on all ports. Report error with guidance.

- **Multiple independent rings** — physically separate rings with no shared devices. Shouldn't happen if LLDP crawl is connected, but could occur with LLDP disabled on some inter-ring links. Each connected component is handled independently.

- **Partial LLDP** — some ports don't have LLDP enabled (e.g., edge ports with endpoints). That's fine — those ports are edge ports, not ring ports. Only ports with LLDP neighbors to other managed switches matter for ring detection.

- **Already-configured rings** — devices already have MRP configured. Discovery should detect existing MRP config (`get_mrp()`) and either skip, warn, or offer to reconfigure. Could support `--force` to overwrite.

- **Mixed SW levels** — L2S devices don't support SRM. Discovery should detect SW level during crawl (from `get_facts()`) and exclude L2S from sub-ring branch points. L2S devices can still be main ring or sub-ring clients.

- **Single-manager sub-ring** — both ends of a sub-ring connect to the same device. Detected when cycle analysis shows a sub-ring with both branch points on the same device. Use `singleManager` mode for both instances.

### Non-Goals (for now)

- **Multi-ring networks** — networks with multiple independent main rings. Out of scope for auto-discovery (which ring is "main"?). Use config file for these.
- **Inter-vendor rings** — custom MRP domain UUIDs needed. Requires explicit config.
- **LLDP-disabled networks** — if LLDP is off, we can't discover anything. Config file required.

## Zero-Config Discovery Mode

### Priority

This is a significant rework but not a rewrite — the deployment engine (phases, workers, verification) stays the same. The change is in how the deployment plan is built: from config file → from LLDP discovery. Both paths produce the same `config['rings']` dict that feeds into the existing deploy/undeploy logic.

Estimate: the graph builder + cycle finder + role assigner is the core work. Config merger and validator are polish. The existing CLAMPS deploy/undeploy code doesn't change at all.
