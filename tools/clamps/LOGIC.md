# CLAMPS — Decision Logic

How the tool decides what to do, and what each mode actually configures.

## Choosing an Edge Protection Strategy

```
Do you have downstream devices running RSTP
that you cannot disable?
  │
  ├─ YES → Use `loop` mode
  │        (loop prot replaces RSTP, no BPDU conflict)
  │
  └─ NO → Is there any risk of cross-switch loops?
          (two edge ports on different switches in the
           same MRP ring accidentally connected)
            │
            ├─ YES → Use `rstp-full` (recommended)
            │        (BPDU Guard catches cross-ring loops instantly)
            │
            └─ NO → `rstp-full` still recommended
                    (`rstp` legacy is available but offers no
                     additional protection beyond basic RSTP)
```

**Bottom line:** Use `rstp-full` unless you have a specific reason not to.

## Why rstp-full Wins

The fundamental difference is what happens when a looped port recovers
from auto-disable:

### BPDU Guard (rstp-full)

```
Port recovers from auto-disable
  │
  ▼
Port enters FORWARDING (admin edge)
  │
  ▼
First BPDU arrives (microseconds)
  │
  ▼
BPDU Guard fires → port auto-disabled
  │
  ▼
Port NEVER RE-OFFENDS
(cycle is too fast to cause any network impact)
```

### Loop Protection (loop)

```
Loop detected (1s transmit interval)
  │
  ▼
Port auto-disabled
  │
  ▼
timer=0 (default): PORT STAYS DOWN FOREVER
  │                 (one 1s storm, then done)
  │
timer=30+: Port recovers after timer
  │
  ▼
Port enters FORWARDING (no RSTP to hold it)
  │
  ▼
Broadcast storm begins IMMEDIATELY
  │
  ▼
1 second passes (transmit interval)
  │
  ▼
Keepalive detected → port auto-disabled AGAIN
  │
  ▼
1 SECOND OF STORM every recovery cycle
(MRP survives via prio 7, but network is disrupted)
```

The key: RSTP has a discarding state. Loop protection does not. When a port
comes up, RSTP can hold it from forwarding until it's safe. Loop protection
lets it forward immediately. Default timer=0 avoids this by never recovering.

## What Each Mode Configures

### rstp-full

```
Per Device:
  ┌───────────────────────────────────────────────────┐
  │ RSTP: Global ON, BPDU Guard ON                    │
  │                                                   │
  │ Ring Ports (1/5, 1/6 + sub-ring ports):           │
  │   RSTP: OFF (MRP owns these)                      │
  │   Admin Edge: OFF                                 │
  │   Auto-Disable: timer (bpdu-rate)                 │
  │                                                   │
  │ Edge Ports (all others):                          │
  │   RSTP: ON                                        │
  │   Admin Edge: ON                                  │
  │   Auto-Disable: timer (bpdu-rate)                 │
  └───────────────────────────────────────────────────┘
```

### loop

```
Per Device:
  ┌───────────────────────────────────────────────────┐
  │ RSTP: Global OFF                                  │
  │ Loop Protection: Global ON, tx_interval=1s        │
  │                                                   │
  │ Ring Ports (1/5, 1/6 + sub-ring ports):           │
  │   Loop Prot: ON, mode=passive,                    │
  │              action=auto-disable                  │
  │   Auto-Disable: timer=0 (loop-protection)         │
  │                                                   │
  │ Edge Ports (all others):                          │
  │   Loop Prot: ON, mode=active,                     │
  │              action=auto-disable                   │
  │   Auto-Disable: timer=0 (loop-protection)         │
  │                                                   │
  │ timer=0 = kill and stay dead (factory default).   │
  │ timer>0 = port recovers every Ns → 1s storm each │
  │ cycle. Not recommended.                           │
  └───────────────────────────────────────────────────┘
```

### rstp (legacy)

```
Per Device:
  ┌───────────────────────────────────────────────────┐
  │ RSTP: Global ON (untouched)                       │
  │                                                   │
  │ Ring Ports (1/5, 1/6 + sub-ring ports):           │
  │   RSTP: OFF                                       │
  │                                                   │
  │ Edge Ports (all others):                          │
  │   RSTP: ON (default, no changes)                  │
  │                                                   │
  │ NOT configured:                                   │
  │   No BPDU Guard                                   │
  │   No admin edge                                   │
  │   No auto-disable                                 │
  │   No loop protection                              │
  └───────────────────────────────────────────────────┘
```

## Deploy Phase Logic

```
                    ┌──────────────┐
                    │   Start      │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Connect     │  parallel to all devices
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Phase 0     │  gather facts (parallel)
                    │  SW level,   │  detect L2S devices
                    │  MRP, RSTP,  │  check edge protection mode
                    │  interfaces  │  L2S safety abort if needed
                    │  sub-ring    │  get_mrp_sub_ring() port discovery
                    │              │  BEFORE JSON → logfile (always)
                    └──────┬───────┘
                           │
                  ┌────────▼────────┐
                  │ Both ring ports │
                  │   up on RM?    │
                  └───┬────────┬───┘
                 YES  │        │  NO
                      │        │
               ┌──────▼──────┐ │
               │ Phase 1a    │ │
               │ Break main  │ │
               │ ring (RM    │ │
               │ port2 DOWN) │ │
               └──────┬──────┘ │
                      │        │
                      ├────────┘
                      │
               ┌──────▼──────────┐
               │ Sub-rings in    │
               │ config?         │
               └───┬─────────┬───┘
              YES  │         │  NO
                   │         │
            ┌──────▼──────┐  │
            │ Phase 1b    │  │
            │ Break sub-  │  │
            │ ring paths  │  │
            │ (RSRM ports │  │
            │  admin DOWN)│  │
            └──────┬──────┘  │
                   │         │
                   ├─────────┘
                   │
               ┌───▼──────────┐
               │  Phase 2     │  configure main ring MRP (parallel)
               └──────┬───────┘
                      │
               ┌──────▼───────┐
               │  Phase 3     │  deploy edge protection
               │  (mode       │  rstp-full / loop / rstp
               │   specific)  │  + storm control (broadcast 100 pps)
               │              │  sub-ring ports excluded
               └──────┬───────┘
                      │
                ┌─────▼──────┐
                │ Broke ring?│
                └──┬─────┬───┘
              YES  │     │  NO
                   │     │
            ┌──────▼──┐  │
            │ 2s wait │  │
            │ Phase 4 │  │
            │ Close   │  │
            │ main    │  │
            │ ring    │  │
            └──────┬──┘  │
                   │     │
                   ├─────┘
                   │
            ┌──────▼───────┐
            │  Phase 5     │  verify main ring (3x retry)
            │  ring_state  │  FATAL if unhealthy
            │  =closed     │
            └──────┬───────┘
                   │
            ┌──────▼───────────┐
            │ Sub-rings in     │
            │ config?          │
            └───┬──────────┬───┘
           YES  │          │  NO
                │          │
         ┌──────▼──────┐   │
         │  Phase 6    │   │
         │  (per VLAN) │   │
         │             │   │
         │ 6a: RCs     │   │  set_mrp (client, sub-ring VLAN)
         │ 6b: SRM +   │   │  set_mrp_sub_ring (manager/redundant)
         │     RSRM    │   │
         │ 6c: Restore │   │  RSRM ports admin UP
         │     paths   │   │
         └──────┬──────┘   │
                │          │
         ┌──────▼──────┐   │
         │  Phase 7    │   │  verify sub-rings (3x retry per VLAN)
         │  per SRM    │   │  WARNING if unhealthy (does not abort)
         └──────┬──────┘   │
                │          │
                ├──────────┘
                │
         ┌──────▼─────────────┐
         │  Verify (--verify) │  re-gather → AFTER JSON → logfile
         └──────┬─────────────┘
                │
         ┌──────▼───────┐
         │  Phase 8     │  save to NVM (if configured)
         └──────────────┘
```

## Undeploy Logic

The undeploy is **state-driven** — it reads the switch state and cleans
whatever it finds. The config file is only used for IPs, credentials,
ports, and save preference.

```
Phase 0: Gather facts
  │
  ├─ has_sub_rings?  → get_mrp_sub_ring() on each device
  ├─ has_loop_prot?    → tear down loop prot + auto-disable
  ├─ has_bpdu_guard?   → tear down rstp-full (admin edge, BPDU Guard, auto-disable)
  ├─ has_storm_ctrl?   → tear down broadcast storm control on edge ports
  ├─ has_mrp?          → delete MRP (main ring + sub-ring RCs)
  │
  └─ ALWAYS: restore RSTP global + per-port on ring ports
             (factory default redundancy state)

Step 1: Break all ring paths (prevent loops during teardown)
  │
  ├─ 1a: RSRM ports admin DOWN (sub-ring paths)
  │      One port per sub-ring VLAN. Skipped if no sub-rings.
  │
  └─ 1b: RM port2 admin DOWN (main ring)
         Skipped if ring ports not both up.

Step 2: Delete sub-rings (if detected)
  │
  ├─ 2a: delete_mrp_sub_ring(ring_id=N) on SRM/RSRM devices
  ├─ 2b: delete_mrp_sub_ring(ring_id=None) — disable SRM globally
  └─ 2c: delete_mrp() on sub-ring RC devices

Step 3: Tear down loop protection (if detected)
Step 4: Tear down RSTP Full (if BPDU Guard detected)
Step 4b: Tear down storm control (if detected)
Step 5: Delete MRP on main ring devices
Step 6: Restore RSTP (global + per-port on ring ports)
Step 7: Restore all broken ports (RM port2 + RSRM ports admin UP)
Step 8: Save to NVM (if save=true)
```

## Migrate-Edge Auto-Toggle

```
Detect current state:
  │
  ├─ Loop Protection ON  → target: rstp-full
  ├─ BPDU Guard ON       → target: loop
  └─ Neither (legacy)    → target: loop
```

Safety: new protection deploys FIRST, then old is torn down. The network
is never unprotected during migration. 2s RSTP hello delay when migrating
TO an RSTP-based strategy.

## Smart Ring Break

```
Phase 1a — Main Ring:
  Check RM ring ports (from Phase 0 interface data):
    │
    ├─ Both UP   → ring is formed → BREAK IT (disable port2)
    ├─ One UP    → ring already broken → skip
    └─ Neither UP → no ring → skip

Phase 1b — Sub-Rings:
  For each sub-ring VLAN in config:
    │
    └─ RSRM port → admin DOWN (always, if sub-ring exists)
       Prevents RSTP from routing through sub-ring path
       during main ring MRP configuration
```

Only break what needs breaking. Only restore what was broken.

## L2S Safety

```
Edge protection mode?
  │
  ├─ rstp-full → SAFE (BPDU Guard is an RSTP feature, works on L2S)
  ├─ rstp      → SAFE (per-port RSTP disable, works on L2S)
  └─ loop      → L2S devices present?
                    │
                    ├─ NO  → proceed
                    ├─ YES + force=true → proceed, skip L2S with warning
                    └─ YES + force=false → ABORT with error:
                         "Loop Protection requires L2A or higher"
                         Options: use rstp-full, upgrade firmware,
                         or set force=true in config
```

## RSTP Hello Timeout

Admin-down via MOPS doesn't trigger a physical link-down event at the
L1 layer. The neighbor switch still sees link — it needs the RSTP hello
timeout (~2 seconds) to notice the topology change via missing BPDUs.

The tool inserts a 2-second delay:
- **Deploy:** After Phase 3 (edge protection configured), before Phase 4
  (close ring). Only when the ring was broken in Phase 1.
- **Migrate:** After Phase 1 (new protection deployed), before Phase 2
  (old protection torn down). Only when migrating TO an RSTP-based strategy.

This ensures RSTP has processed BPDUs and established the correct forwarding
state before the ring closes or old protection is removed.

## Auto-Disable Timer Defaults

```
Mode not set in config?
  │
  ├─ loop      → timer=0  (kill and stay dead)
  └─ rstp-full → timer=30 (recover — BPDU Guard catches instantly)
```

Loop protection reoffends every recovery cycle (1s storm each time).
BPDU Guard catches it in microseconds — recovery is invisible. Different
default timers reflect this fundamental difference.

Explicit `auto_disable_timer` in config overrides the default for either mode.

## Storm Control — CPU Protection

Storm control limits broadcast ingress rate on edge ports. This protects the
CPU from ARP starvation during broadcast storms on any VLAN.

### Why broadcast storms kill management

The HiOS CPU port (`cpu/1`) receives broadcast from ALL VLANs — not just the
management VLAN. This is observed behaviour on BRS50 switches (TI AM3358 CPSW):

- The internal rate limiter between ASIC and CPU is ~450 pps, shared across
  all VLANs (VLAN-unaware)
- During a broadcast storm on any VLAN, storm traffic saturates the shared pipe
- Management ARP (VLAN 60) starves — ARP entries expire, switch becomes
  unreachable
- CPU is not overloaded (50% idle) — the failure is ARP starvation, not
  CPU exhaustion
- MRP/SRM ring failover is ASIC-level and unaffected — data plane stays up

### Why 100 pps

Observed formula: `CPU broadcast pps ≈ limiter_per_port × num_loop_ports × 0.8`

With 100 pps per edge port and a 2-port loop: 100 × 2 × 0.8 = 160 pps reaching
CPU. The ~450 pps watermark leaves ~300 pps for management ARP — 0% management
loss confirmed over 120s soak test.

No legitimate end device sends 100 broadcast packets/sec. Blackstart worst case
(unmanaged switch, 8 devices behind one port) peaks at ~30-50 pps.

### What CLAMPS configures

```
Per Device (all edge protection modes):
  ┌───────────────────────────────────────────────────┐
  │ Storm Control: broadcast 100 pps                  │
  │                                                   │
  │ Ring Ports (1/5, 1/6 + sub-ring ports):           │
  │   Storm Control: OFF (MRP uses multicast heavily) │
  │                                                   │
  │ Edge Ports (all others):                          │
  │   Storm Control: broadcast ON, 100 pps            │
  │   Multicast: OFF (legitimate protocols need it)   │
  │   Unknown Unicast: OFF (hard to distinguish)      │
  └───────────────────────────────────────────────────┘
```

Disabled with `storm_control false` in config or `--no-storm-control` CLI flag.
Threshold adjustable: `storm_control_threshold <value>` (default 100).
Unit adjustable: `storm_control_unit pps` or `storm_control_unit percent` (default pps).

## Structured Logging (Before/After)

Every run dumps full structured state to the logfile as JSON — the complete
`get_mrp()`, `get_rstp()`, `get_loop_protection()`, `get_auto_disable()`,
`get_storm_control()` dicts per device.

```
BEFORE: Always logged (no flag needed)
  │  Phase 0 gathers state → summary table on console
  │  Full JSON dumped to logfile only (not console)
  │
AFTER: Opt-in via --verify
  │  Re-gathers state after all deploy/undeploy phases
  │  Summary table on console + full JSON to logfile
  │  Costs one extra gather round (~5s for 4 devices)
```

The logfile is the audit record. Console stays clean with the one-line
summary per device. The JSON blocks are labelled `--- BEFORE ---` and
`--- AFTER ---` with per-device entries:

```
--- BEFORE ---
[192.168.1.80] BEFORE: {"mrp": {...}, "rstp": {...}, ...}
[192.168.1.82] BEFORE: {"mrp": {...}, "rstp": {...}, ...}
```

Sets (e.g. `srm_ports`) are serialized as sorted lists. All other
non-JSON-native types fall back to `str()`.

## Loop Protection: How It Works and Why It's Limited

Loop protection sends keepalive frames and detects when they return.
Ring ports in passive mode evaluate keepalives that traverse the ring and
return to the originating switch — this catches cross-switch loops.

### What works

- **Same-switch loops:** Edge port in active mode sends + receives its own
  keepalive. Detected in 1s (transmit interval). Port auto-disables.
- **Cross-switch loops:** Keepalive from switch A traverses the ring, returns
  to switch A via the looped cable. Ring port in passive mode detects it.
  Detected in 1s. Port auto-disables.
- **With timer=0:** One 1s storm on detection, port stays down forever.
  Never reoffends. Clean enough for production.

### What doesn't work

1. **No discarding state.** When a port comes up, it forwards immediately.
   BPDU Guard benefits from RSTP's discarding state — the port is held from
   forwarding until BPDUs are processed.

2. **Detection delay.** Keepalives are sent every 1s (minimum). A loop
   creates a broadcast storm instantly. The storm runs for the full
   transmit interval before detection.

3. **Recovery storms.** Each auto-disable recovery cycle (timer > 0) creates
   a new 1s storm. MRP priority 7 with strict QoS keeps the ring alive,
   but the network is disrupted each cycle. The port reoffends every
   timer expiry — indefinitely.

**Default timer is 0** for this reason. Kill and stay dead. If you set a
timer (30s+), accept that the port will storm for ~1s every timer interval
until the cable is removed.

**Future:** Hirschmann could fix this by sending keepalives from a
non-forwarding state during auto-disable recovery — probe before forwarding,
like RSTP's discarding state. Until then, rstp-full is superior for MRP rings.

## Sub-Ring Path Breaking

Sub-rings create parallel paths to the main ring through branch-point
devices (SRM/RSRM). When MRP takes over the main ring and blocks RM port2,
RSTP doesn't know about it — it sees the sub-ring path as an alternative
route and can create a loop.

```
Phase 1b breaks RSRM ports BEFORE any MRP configuration:

Main Ring:   .80 ─── 1/5 ═══ 1/6 ─── .82
              │                        │
              1/10 (SRM)        1/10 (RSRM) ← admin DOWN here
              │                        │
Sub-Ring:    .85 ─── 1/5 ═══ 1/6 ─── .81

Without Phase 1b:
  MRP blocks RM port2 (.80 1/6)
  RSTP sees: .80 → 1/10 → .85 → .81 → 1/10 → .82 → 1/6 → .80
  This is a valid alternate path → potential loop

With Phase 1b:
  RSRM port (.82 1/10) is admin DOWN
  Sub-ring path is physically severed
  MRP can safely take over main ring
```

The same logic applies in reverse during undeploy: Step 1a breaks RSRM
ports before Step 1b breaks the main ring.

## Sub-Ring Deploy Ordering

Sub-rings are configured AFTER the main ring is verified healthy (Phase 5).
This ensures the main ring is stable before adding complexity.

```
Per sub-ring VLAN:

Phase 6a: Configure RCs (parallel)
  │  set_mrp(mode='client', vlan=sub_vlan)
  │  Standard MRP client — same as main ring RCs
  │  Uses the sub-ring VLAN, NOT the main ring VLAN
  │
Phase 6b: Configure SRM + RSRM (parallel)
  │  set_mrp_sub_ring(ring_id=N, mode='manager'|'redundantManager')
  │  Branch-point devices — single port each
  │  ring_id assigned sequentially (1, 2, 3...)
  │
Phase 6c: Restore RSRM port (close sub-ring)
     set_interface(rsrm_port, enabled=True)
     Sub-ring can now form
```

**Why RCs first:** The sub-ring clients must have MRP configured before
the SRM/RSRM branch points activate. If SRM/RSRM come up first with no
clients, the sub-ring has no ring to manage.

## Sub-Ring Port Exclusion

Sub-ring ports (SRM/RSRM single port per branch) are treated identically
to main ring ports for edge protection:

```
get_ring_ports_for_device(config, ip):
  │
  ├─ Main ring ports: port1, port2
  ├─ SRM port (if this device is a branch point)
  └─ RSRM port (if this device is a branch point)

All collected → excluded from edge protection
  ├─ rstp-full: RSTP disabled on ring + sub-ring ports
  ├─ loop: passive mode on ring + sub-ring ports
  └─ rstp: RSTP disabled on ring + sub-ring ports
```

A device can be both a main ring member (ports 1/5, 1/6) and a sub-ring
branch point (port 1/10). All three ports are excluded from edge protection.

## Sub-Ring Verification

Sub-ring health is checked on the SRM device (not RSRM, not RCs):

```
Phase 7: Per sub-ring VLAN
  │
  get_mrp_sub_ring() on SRM device
  │
  Find instance matching ring_id
  │
  ├─ ring_state=closed AND redundancy=true → HEALTHY
  └─ Otherwise → WARNING (does NOT abort)
```

Unlike Phase 5 (main ring), sub-ring verification failure is a warning,
not a fatal error. The main ring is already healthy — a sub-ring issue
doesn't require rolling back the entire deployment.

## Sub-Ring Undeploy Ordering

Reverse of deploy. Delete sub-rings before main ring MRP:

```
Step 2a: Delete SRM instances
  │  delete_mrp_sub_ring(ring_id=N) per instance
  │  Removes branch-point sub-ring configuration
  │
Step 2b: Disable SRM globally
  │  delete_mrp_sub_ring(ring_id=None)
  │  Turns off sub-ring manager feature entirely
  │
Step 2c: Delete MRP on sub-ring RCs
     delete_mrp() on each RC device
     Removes standard MRP client config

Then Step 5 deletes MRP on main ring devices.
```

**Why sub-rings first:** Sub-rings depend on the main ring. Deleting main
ring MRP while sub-rings are still configured can leave orphaned sub-ring
instances that are harder to clean up.
