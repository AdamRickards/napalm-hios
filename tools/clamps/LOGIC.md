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
  ┌─────────────────────────────────────────────┐
  │ RSTP: Global ON, BPDU Guard ON              │
  │                                             │
  │ Ring Ports (1/5, 1/6):                      │
  │   RSTP: OFF (MRP owns these)                │
  │   Admin Edge: OFF                           │
  │   Auto-Disable: timer (bpdu-rate)           │
  │                                             │
  │ Edge Ports (all others):                    │
  │   RSTP: ON                                  │
  │   Admin Edge: ON                            │
  │   Auto-Disable: timer (bpdu-rate)           │
  └─────────────────────────────────────────────┘
```

### loop

```
Per Device:
  ┌─────────────────────────────────────────────┐
  │ RSTP: Global OFF                            │
  │ Loop Protection: Global ON, tx_interval=1s  │
  │                                             │
  │ Ring Ports (1/5, 1/6):                      │
  │   Loop Prot: ON, mode=passive,              │
  │              action=auto-disable            │
  │   Auto-Disable: timer (loop-protection)     │
  │                                             │
  │ Edge Ports (all others):                    │
  │   Loop Prot: ON, mode=active,               │
  │              action=auto-disable             │
  │   Auto-Disable: timer (loop-protection)     │
  └─────────────────────────────────────────────┘
```

### rstp (legacy)

```
Per Device:
  ┌─────────────────────────────────────────────┐
  │ RSTP: Global ON                             │
  │                                             │
  │ Ring Ports (1/5, 1/6):                      │
  │   RSTP: OFF                                 │
  │                                             │
  │ Edge Ports (all others):                    │
  │   RSTP: ON (default, no changes)            │
  └─────────────────────────────────────────────┘
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
                    └──────┬───────┘
                           │
                  ┌────────▼────────┐
                  │ Both ring ports │
                  │   up on RM?    │
                  └───┬────────┬───┘
                 YES  │        │  NO
                      │        │
               ┌──────▼──┐    │
               │ Phase 1  │   │
               │ Break    │   │
               │ ring     │   │
               └──────┬───┘   │
                      │       │
                      ├───────┘
                      │
               ┌──────▼───────┐
               │  Phase 2     │  configure MRP (parallel)
               └──────┬───────┘
                      │
               ┌──────▼───────┐
               │  Phase 3     │  deploy edge protection
               │  (mode       │  rstp-full / loop / rstp
               │   specific)  │
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
            │ ring    │  │
            └──────┬──┘  │
                   │     │
                   ├─────┘
                   │
            ┌──────▼───────┐
            │  Phase 5     │  verify ring (3x retry)
            │  ring_state  │  FATAL if unhealthy
            │  =closed     │
            └──────┬───────┘
                   │
            ┌──────▼───────┐
            │  Phase 6     │  save to NVM (if configured)
            └──────────────┘
```

## Undeploy Logic

The undeploy is **state-driven** — it reads the switch state and cleans
whatever it finds. The config file is only used for IPs, credentials,
ports, and save preference.

```
Phase 0: Gather facts
  │
  ├─ has_loop_prot?  → tear down loop prot + auto-disable
  ├─ has_bpdu_guard? → tear down rstp-full (admin edge, BPDU Guard, auto-disable)
  ├─ has_mrp?        → delete MRP
  │
  └─ ALWAYS: restore RSTP global + per-port on ring ports
             (factory default redundancy state)
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
Check RM ring ports (from Phase 0 interface data):
  │
  ├─ Both UP   → ring is formed → BREAK IT (disable port2)
  ├─ One UP    → ring already broken → skip
  └─ Neither UP → no ring → skip
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
