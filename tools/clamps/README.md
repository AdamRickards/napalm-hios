# CLAMPS

**C**onfiguration of **L**oops, **A**ccess, **M**RP, **P**rotection, and **S**ub-rings

*"What's the matter, you stupid or something? I'll give you the clamps!"*
*— Francis X. Clampazzo*

MRP ring deployment and edge protection tool for Hirschmann HiOS switches.

Deploys MRP rings with intelligent edge port protection, verifies ring health,
and supports live edge strategy migration — all from a single config file.

## Requirements

- Python 3.8+
- [napalm-hios](https://pypi.org/project/napalm-hios/) driver installed
- HTTPS (port 443) reachable to all switches (MOPS protocol, default)
- All switches running HiOS 10.x with matching credentials

## Quick Start

1. Edit `script.cfg` with your device IPs and credentials
2. Deploy: `python clamp.py`
3. Verify the ring is healthy (tool does this automatically)
4. Undeploy when done: `python unclamp.py`

## Config File (`script.cfg`)

```
# Credentials
username admin
password private

# Default ring ports (can be overridden per device)
port1 1/5
port2 1/6

# MRP settings
vlan 100                  # VLAN for MRP frames (0-4042, avoid 1 with loop mode)
recovery_delay 200ms      # 200ms, 500ms, 30ms, 10ms

# Edge protection strategy
edge_protection rstp-full  # rstp-full (recommended), loop, rstp
# auto_disable_timer 30   # omit for smart default: loop=0, rstp-full=30

# Protocol and save behavior
protocol mops              # mops (recommended), snmp, ssh
save false                 # true = save to NVM after ring verified healthy

# Force past L2S safety check (loop mode only)
force false

# Device list — one per line
# <ip> [port1 port2] [RM]
192.168.1.80 1/5 1/6 RM
192.168.1.81
192.168.1.82
```

If no device has `RM`, the first device is automatically assigned as ring manager.

## Edge Protection Strategies

### `rstp-full` — Recommended

BPDU Guard + admin edge + auto-disable for bpdu-rate. The most complete
protection available.

- RSTP stays on globally, off on ring ports only
- BPDU Guard enabled globally — any BPDU on an edge port triggers auto-disable
- Admin edge on all edge ports — ports start forwarding immediately
- Auto-disable timer on all ports for `bpdu-rate` reason
- Works on **all** SW levels including L2S

**What it catches:** Same-switch loops AND cross-switch loops (including
loops that traverse the MRP ring). BPDU Guard fires on the first BPDU frame —
effectively instant detection with zero storm window.

**Auto-disable recovery:** When the timer expires and the port comes back up,
BPDU Guard catches the loop again in microseconds. The port never visibly
re-offends. Continuous protection with no network impact.

**Caution:** BPDU Guard will auto-disable ports connected to any RSTP-speaking
device (PLCs, third-party switches). If you have downstream devices running
RSTP that you cannot disable, use `loop` mode instead.

### `loop` — Niche Use

Loop protection with keepalive frames. Use when RSTP is not an option (e.g.,
downstream PLCs with RSTP enabled that you cannot disable).

- RSTP disabled globally
- Edge ports: active mode (send + evaluate keepalives), action=auto-disable
- Ring ports: passive mode (evaluate only), action=auto-disable
- Transmit interval set to 1s (minimum, fastest detection)
- Auto-disable timer on all ports (default: 0 = no auto-recovery)
- Requires **L2A or higher** (abort on L2S unless `force true`)

**What it catches:** Same-switch and cross-switch loops. Keepalives traverse
the ring and return to the originating switch, triggering auto-disable on the
ring port. MRP priority 7 with strict QoS keeps ring control frames alive
during the 1s detection window.

**Default timer is 0** (kill and stay dead). Port detects the loop, disables,
and stays down until manual intervention. This is intentional — loop protection
has no "discarding" state, so any auto-recovery cycle (timer 30s+) causes a
brief broadcast storm before re-detection. Use `auto_disable_timer 0` unless
you accept periodic storms on recovery.

### `rstp` — Legacy

Minimal protection. Disables RSTP on ring ports only.

- RSTP stays on globally, off on ring ports
- No BPDU Guard, no admin edge, no auto-disable
- Works on all SW levels

**What it catches:** Nothing beyond standard RSTP. Blind to loops that
traverse the MRP ring (RSTP ignores ports where it's off — from RSTP's
perspective, there is no loop).

Not recommended for production. Use `rstp-full` instead.

## CLI Usage

### Deploy

```bash
python clamp.py                          # default: rstp-full
python clamp.py --edge loop              # loop protection
python clamp.py --edge rstp              # legacy RSTP
python clamp.py -c ring2.cfg             # custom config file
python clamp.py --dry-run                # show plan, no changes
python clamp.py --debug                  # verbose MOPS logging
```

### Undeploy

State-driven — reads switch state, cleans whatever is detected, restores
factory default redundancy config (RSTP global + all ports on).

```bash
python unclamp.py                        # clean everything
python unclamp.py --dry-run              # show what would be cleaned
```

### Migrate Edge Protection

Live migration between edge strategies without tearing down MRP. The ring
stays up the entire time — new protection goes up before old comes down.

```bash
python clamp.py --migrate-edge           # auto-toggle
python clamp.py --migrate-edge loop      # explicit target
python clamp.py --migrate-edge rstp-full # explicit target
```

Auto-toggle logic:
- Loop Protection detected → migrate to RSTP Full
- RSTP Full detected → migrate to Loop Protection
- No protection / legacy RSTP → deploy Loop Protection

## How It Works

### Deploy Flow

```
Connect (parallel)
  │
Phase 0: Gather facts (parallel)
  │  SW level, MRP, RSTP, loop prot, auto-disable, interfaces
  │  L2S safety check (abort if loop mode + L2S without force)
  │
Phase 1: Break ring (RM port2 admin DOWN)
  │  Skipped if ring ports not both up
  │
Phase 2: Configure MRP (parallel)
  │  Set role, ports, VLAN, recovery delay
  │
Phase 3: Edge protection
  │  Deploy selected strategy (see LOGIC.md for details)
  │  2s RSTP settle delay before closing ring
  │
Phase 4: Close ring (RM port2 admin UP)
  │  Skipped if ring was not broken
  │
Phase 5: Verify ring (3x retry @ 1s)
  │  Check ring_state=closed, redundancy=true on RM
  │
Phase 6: Save to NVM (parallel, if save=true)
```

### Undeploy Flow

```
Connect (parallel)
  │
Phase 0: Gather facts (parallel)
  │  Detect: loop protection? BPDU Guard? MRP?
  │
Step 1: Break ring (if ring ports both up)
  │
Step 2: Tear down loop protection (if detected)
  │  Reset auto-disable → disable loop prot per port → global off
  │
Step 3: Tear down RSTP Full (if BPDU Guard detected)
  │  Reset auto-disable → remove admin edge → disable BPDU Guard
  │
Step 4: Delete MRP (if configured)
  │
Step 5: Restore RSTP (always)
  │  Global enable + per-port enable on ring ports
  │
Step 6: Restore RM port2 (if broken in Step 1)
  │
Step 7: Save to NVM (if save=true)
```

## Important Notes

### MRP VLAN

When using `loop` mode, avoid VLAN 1 for MRP. In our testing, MRP on VLAN 1
caused issues with untagged loop protection keepalives on ring ports. Use a
dedicated VLAN (e.g., 100) to avoid any conflict. This is not an issue with
`rstp-full` or `rstp` modes however in general it's best practice to assign
a unique VLAN per MRP instance.

### L2S Devices

- `rstp-full` works on L2S (BPDU Guard and admin edge are RSTP features)
- `rstp` works on L2S (simple per-port RSTP disable)
- `loop` requires L2A+ (loop protection and auto-disable are not available on L2S)

Use `force true` in the config to proceed with `loop` mode when L2S devices
are present — they will be skipped with a warning (partial protection).

### RSTP Hello Timeout

Admin-down (MOPS) doesn't trigger a physical link-down event. Neighbors need
the RSTP hello timeout (~2s) to detect the change. The tool waits 2s after
edge protection is configured before closing the ring, ensuring RSTP has
settled before the first frame flows.

### Config Persistence

With `save false` (default), all changes are RAM-only. A power cycle on any
switch rolls back to the last saved config. This is intentional for testing —
deploy, test, power cycle to undo.

Set `save true` to persist configs after verifying the ring is healthy.

## Files

| File | Purpose |
|------|---------|
| `clamp.py` | Main deploy + migrate-edge tool |
| `unclamp.py` | State-driven reverse deployment |
| `script.cfg` | Configuration file (devices, credentials, settings) |
| `logs/` | Timestamped log files for each run |

## See Also

- [LOGIC.md](LOGIC.md) — Decision flowcharts and per-mode configuration details
- [napalm-hios](https://github.com/adamr/napalm-hios) — NAPALM driver for HiOS
