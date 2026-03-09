# BLIP — TODO

**B**roadcast **L**atency **I**nterruption **P**robe

Zero-config multicast disruption probe. A Pi that autoruns on boot, joins the HiDiscovery multicast group, measures traffic gaps, stores results locally, and advertises them over the same multicast channel. Discovered and managed by MARCO — no IP, no credentials, no SSH.

Replaces Belden mPING_LCD (aged, compiled exe, requires admin rights). BLIP is pure userspace UDP — no elevated privileges needed.

## Motivation

Every tool in the suite changes network state. BLIP quantifies the real-world cost of each operation — the disruption window in milliseconds.

Benchmarks across the toolset:
- **VIKTOR**: VLAN access mode changes (staged vs set_multi)
- **CLAMPS**: MRP ring deploy/undeploy, edge protection migration, sub-ring config
- **MOHAWC**: onboard, reset (how long is the switch offline?)
- **MRP itself**: ring failover time (spec says <200ms, prove it)
- **Sub-ring failover**: independent of main ring?
- **Protocol comparison**: MOPS vs SNMP vs SSH — same operation, different BLIP?

## Design

### Zero Config

Flash the SD card, plug the Pi into a port, done. No IP address, no DHCP, no DNS, no credentials. Link-local is enough — same as a factory-default Hirschmann switch. The Pi autoruns a script on boot that:

1. Joins the measurement multicast group (sender or receiver)
2. Joins the HiDiscovery multicast group (`239.255.16.12:51973`)
3. Responds to MARCO discovery — shows up in the device table
4. Starts measuring / sending immediately

### Two Roles

- **Sender (-s):** Blasts multicast UDP at configurable interval (default 1ms)
- **Receiver (-c):** Joins multicast group, logs transitions (start/stop) only

No raw sockets, no pcap — standard `IP_ADD_MEMBERSHIP` + `sendto`/`recvfrom`. Runs on Linux (Pi, laptop) and Windows without admin rights.

### MARCO Integration

BLIPs speak HiDiscovery v2 — a tiny SNMP responder that answers `@discover@` on `239.255.16.12:51973`. MARCO discovers them alongside switches. No new protocol, no new tool, no new workflow.

**Discovery** — BLIPs appear in `marco_results.json` with a BLIP device type:
```
  #   IP               Name                  Product     FW        Role
  1   192.168.1.80     SW-OFFICE             BRS50-...   10.3.04   switch
  2   169.254.12.34    BLIP-SENDER-1         BLIP        0.1.0     sender
  3   169.254.56.78    BLIP-RECEIVER-1       BLIP        0.1.0     receiver
```

**Configure** — MARCO Set operations configure BLIP parameters over multicast:
```bash
marco.py --blip-group 239.1.1.5 -i 2       # set multicast group
marco.py --blip-interval 1 -i 2            # set send interval (ms)
marco.py --blip-start -i 2                 # start measurement
marco.py --blip-stop -i 2                  # stop measurement
```

**Collect** — pull stored results from BLIPs:
```bash
marco.py --blip-dump -i 3                  # grab full history from BLIP #3
marco.py --blip-dump                       # grab from all discovered BLIPs
marco.py --blip-clear -i 3                 # clear after collection
```

### Two Operating Modes

**Live** — on the management VLAN, periodic multicast advertisements. MARCO sees them in real-time. Results accumulate in `marco_results.json`. Good for lab testing where you want instant feedback.

**RTU (field deploy)** — plug into whatever VLAN, leave for a week. The BLIP logs everything locally. Come back, move to management VLAN, MARCO discovers it, pull the full history. Same as an RTU in a substation — records locally, you poll when ready.

Periodic advertisement = last N results (heartbeat/summary). Full dataset stays on the Pi until explicitly collected or cleared.

### Measurement

Gap detection is local — the receiver measures silence duration on its own clock. No NTP sync needed for gap measurement (stop→start is a local duration, not a wall clock comparison). NTP only matters if you want to correlate gaps with external events (CLAMPS deploy timestamps, cable pull time).

```
Traffic flowing:  ████████████████████
Gap (BLIP):                          ░░░░░░░░░
Traffic resumes:                              ████████████████
                                     ^stop    ^start
                                     gap_ms = start - stop
```

### Local Storage

All results stored on the Pi's SD card as JSON:
```json
[
  {"stop": "14:22:01.047", "start": "14:22:01.212", "gap_ms": 165},
  {"stop": "14:25:33.891", "start": "14:25:33.944", "gap_ms": 53}
]
```

Survives power cycles. Cleared explicitly via MARCO or on-device.

## Hardware

- Raspberry Pi (any model with Ethernet — Pi Zero W + USB-Ethernet works)
- Autorun on boot (systemd service)
- No monitor, no keyboard, no SSH needed — headless from birth
- One sender per VLAN, one receiver per VLAN (or one Pi doing both)
- Doubles as SNOOP test source (sFlow validation) later

## Workflow

1. Flash Pi, plug into port
2. `marco.py` — BLIP shows up next to the switches
3. Pull a cable / run CLAMPS / deploy VIKTOR / whatever
4. `marco.py --blip-dump` — results on your screen
5. Move Pi to next site, repeat

## Test Plan

### VIKTOR (VLAN switchover)
1. Baseline: sender + receiver on same VLAN, no changes — confirm zero gaps
2. Access mode (current): staged egress + separate PVID — measure gap
3. Access mode (set_multi): batched egress + PVID in one POST — measure gap

### CLAMPS (redundancy)
4. MRP ring deploy: how long is traffic disrupted during ring formation?
5. MRP failover: pull a cable, measure recovery time (spec: <200ms)
6. Sub-ring failover: independent of main ring disruption?
7. Edge migration (rstp-full ↔ loop): any blip during live migration?

### MOHAWC (commissioning)
8. Onboard: how long is the switch unreachable during config push?
9. Reset: factory reset to operational — total downtime

### Protocol comparison
10. Same VIKTOR operation via MOPS vs SNMP vs SSH — which blips less?

## v1.0

- [ ] Sender mode: configurable multicast group, interval, payload
- [ ] Receiver mode: join group, log start/stop transitions with local timestamps
- [ ] Local JSON storage (survives power cycles)
- [ ] HiDiscovery v2 responder — discoverable by MARCO
- [ ] Periodic multicast advertisement (last N results as heartbeat)
- [ ] Timeout detection: configurable silence threshold to trigger "stop" event
- [ ] Autorun systemd service for headless Pi deployment

## v1.1 — MARCO Integration

- [ ] MARCO: `--blip-dump` — collect full history from discovered BLIPs
- [ ] MARCO: `--blip-clear` — clear stored results after collection
- [ ] MARCO: `--blip-start` / `--blip-stop` — remote start/stop measurement
- [ ] MARCO: `--blip-group` / `--blip-interval` — remote configuration
- [ ] `marco_results.json`: `blips` section alongside `devices`

## Future

- [ ] Comparison script: read collected results, compute stats (min/max/avg/p99 gap)
- [ ] Multiple groups: monitor several multicast addresses simultaneously
- [ ] Live display: terminal output showing current state + last gap duration
- [ ] Correlation mode: align BLIP gaps with CLAMPS/VIKTOR log timestamps
