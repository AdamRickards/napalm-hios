# BLIP — TODO

**B**roadcast **L**atency **I**nterruption **P**robe

Multicast traffic disruption measurement tool. Measures the "blip" —
how long traffic goes missing during network operations. Lower BLIP
values = higher production uptime.

## Motivation

Every tool in the suite changes network state. BLIP quantifies the
real-world cost of each operation — the disruption window in milliseconds.

Benchmarks across the toolset:
- **VIKTOR**: VLAN access mode changes (staged vs set_multi)
- **CLAMPS**: MRP ring deploy/undeploy, edge protection migration, sub-ring config
- **MOHAWC**: onboard, reset (how long is the switch offline?)
- **MRP itself**: ring failover time (spec says <200ms, prove it)
- **Sub-ring failover**: independent of main ring?
- **Protocol comparison**: MOPS vs SNMP vs SSH — same operation, different BLIP?

Replaces Belden mPING_LCD (aged, compiled exe, requires admin rights).
BLIP is pure userspace UDP — no elevated privileges needed.

## Design

### CLI

```bash
python blip.py -s                          # sender (default mcast 239.1.1.1)
python blip.py -s 239.1.1.5               # sender, custom group
python blip.py -c                          # client/receiver
python blip.py -c 239.1.1.1 --sync        # receiver, NTP sync before start
```

### Architecture

- **Sender (-s):** Blasts multicast UDP at configurable interval (default 1ms)
- **Receiver (-c):** Joins multicast group, logs transitions (start/stop) only
- No raw sockets, no pcap — standard `IP_ADD_MEMBERSHIP` + `sendto`/`recvfrom`
- Runs on Linux (Pi, laptop) and Windows without admin rights

### Output

JSON lines, one per transition event:
```json
{"event": "start", "mcast": "239.1.1.1", "ts": "2026-03-03T14:22:01.003412Z"}
{"event": "stop",  "mcast": "239.1.1.1", "ts": "2026-03-03T14:22:01.047891Z"}
{"event": "start", "mcast": "239.1.1.1", "ts": "2026-03-03T14:22:01.212003Z"}
```

The gap between a `stop` and next `start` IS the disruption measurement.

### Time Sync

Optional `--sync` flag: NTP offset check before starting (ntplib or
system timedatectl/chronyc). Both sides within a few ms of UTC is
sufficient — measuring gaps of 10-200ms, not microseconds.

### Data Collection

- Logs written locally on each Pi/device
- Syncthing collects logs to one location
- JSON output readable by eye or by comparison script

## Hardware

- 2x Raspberry Pi (or any two machines with Ethernet)
- One sender per VLAN, one receiver per VLAN
- Static IPs, SSH accessible, leave plugged in at lab permanently
- Doubles as SNOOP test sources (sFlow validation) later

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
- [ ] Receiver mode: join group, log start/stop transitions with UTC timestamps
- [ ] JSON line output
- [ ] Optional NTP sync (--sync)
- [ ] Timeout detection: configurable silence threshold to trigger "stop" event

## Future

- [ ] Comparison script: read two JSON logs, compute gap durations
- [ ] Multiple groups: monitor several multicast addresses simultaneously
- [ ] Live display: terminal output showing current state + last gap duration
