# VIKTOR — Decision Logic

How the tool decides what to do, and why it does it the way it does.

## Access Mode: Add-Before-Remove

Strict access mode (PVID + untagged on target, removed from everything
else) has a critical ordering constraint:

```
Setting port 1/1 to access VLAN 5:

  1. ADD:    set_vlan_egress(5, '1/1', 'untagged')     ← port joins VLAN 5
  2. REMOVE: set_vlan_egress(old, '1/1', 'none')       ← port leaves old VLANs
  3. PVID:   set_vlan_ingress('1/1', pvid=5)            ← ingress tag

  If reversed (remove first):
    Port has ZERO VLAN membership for a brief moment.
    Any frames in transit are dropped. On a busy port,
    this can cause a visible blip.
```

PVID is always last — it's a separate driver call (`set_vlan_ingress`
vs `set_vlan_egress`). Could be batched via MOPS `set_multi` in the
future, but currently runs after staging commits.

## MOPS Staging

MOPS protocol supports staging: batch multiple mutations into one
atomic POST per device. VIKTOR uses this selectively.

```
Staged (batched):
  ├─ access: add U on target + remove from others → one commit
  └─ trunk: tag multiple VLANs → one commit

Not staged (currently):
  ├─ PVID (set_vlan_ingress) → separate call after commit
  │  Separate driver method. Could be staged via set_multi
  │
  ├─ VLAN CRUD (create/delete/rename) → always immediate
  │  Driver bypasses staging internally
  │
  └─ --names fix (update_vlan) → always immediate
     Low volume, no batching benefit
```

Staging only matters for MOPS. SNMP and SSH ignore `start_staging()`.

## Ring Selector (-m)

The MRP VLAN egress table IS the topology map. No MRP queries needed.

```
-m100 (filter by VLAN 100):

  1. Connect to ALL devices (from any source)
  2. get_vlan_egress() on each
  3. Does VLAN 100 exist in egress?
       │
       ├─ YES → ring member
       │   Ports tagged/untagged for VLAN 100 = ring ports
       │
       └─ NO → not a ring member → disconnect
  4. Proceed with filtered fleet
```

Why this works: MRP creates a VLAN and tags its ring ports. A device
with that VLAN in its egress table is participating in that ring.
The tagged ports are the inter-switch links.

Works for both main rings (`-m100`) and sub-rings (`-m200`) — same
VLAN egress mechanism.

## LLDP Link Discovery

Auto-trunk and audit checks need to know which ports connect to which
neighbor. LLDP provides this, but matching requires care.

```
For each LLDP neighbor on each port:

  Match remote device to fleet:
    │
    ├─ 1. remote_management_address → direct IP lookup
    │     Most reliable. Exact match against fleet IPs.
    │
    └─ 2. remote_system_name → hostname lookup (case-insensitive)
          Fallback when management address is missing.
          Matches against get_facts() hostnames.

  Match remote port:
    │
    ├─ remote_port_description (preferred)
    │   HiOS returns: "Module: 1 Port: 6 - 1 Gbit"
    │   Normalized via regex → "1/6"
    │
    └─ remote_port (fallback)
       Often a MAC address on HiOS — less useful

  Deduplicate:
    Link A↔B appears in both A's and B's LLDP tables.
    frozenset of (ip, port) pairs → seen once only.
```

Port normalization handles the HiOS verbose format:
`"Module: 1 Port: 6 - 1 Gbit"` → `"1/6"`.
Already-normalized values pass through unchanged.

## Audit Checks

VLAN config on HiOS has two independent tables — ingress (PVID) and
egress (port membership per VLAN). They can get out of sync. Ports can
accumulate stale memberships. Inter-switch links can have mismatched
VLANs with no error or warning from the switch. VLAN names are
cosmetic and nobody enforces consistency.

None of these cause alarms. Traffic just silently breaks or leaks.
The audit catches what the switches won't tell you.

Five checks, ordered by severity. All read-only.

### PVID / Egress Mismatch (ERROR)

**Why:** A port's PVID controls where untagged ingress frames are
forwarded. But PVID is just a label — the port also needs to be an
untagged member of that VLAN on the egress side, or frames arrive at
the VLAN but can never leave through that port. The two tables are
independent and HiOS does not validate them against each other.

**What breaks:** Untagged devices (PLCs, cameras, anything without
802.1Q) connected to this port silently lose connectivity. No log, no
alarm, no indication on the switch.

```
For each port:
  PVID = 5
  Egress membership on VLAN 5 = ?
    │
    ├─ 'untagged' → OK
    ├─ 'tagged'   → MISMATCH (PVID expects untagged)
    ├─ 'none'     → MISMATCH (not even a member)
    └─ absent     → MISMATCH (VLAN doesn't exist on device)
```

Always a misconfiguration. Severity: ERROR.

### Dirty Access Ports (WARNING)

**Why:** When moving a port from VLAN 1 to VLAN 5, if you set the PVID
to 5 and add untagged membership on VLAN 5 but forget to remove
untagged membership from VLAN 1, the port is now untagged in both
VLANs. Ingress frames go to VLAN 5 (PVID wins) but the port still
receives broadcast/multicast from VLAN 1 (still a member).

**What breaks:** Unexpected traffic bleed between VLANs. The port
receives frames from VLANs it shouldn't be part of. On an industrial
network this can mean a PLC receiving broadcast storms from a VLAN
it was moved away from.

```
For each port:
  Has tagged VLANs?
    │
    ├─ YES → skip (intentional trunk port)
    │
    └─ NO → count untagged memberships beyond PVID
              │
              ├─ 0 → clean access port
              └─ 1+ → DIRTY (still in old VLANs)
```

The tagged-VLAN check avoids false positives on trunk ports, which are
legitimately in multiple VLANs. Only flags ports that look like access
ports but have stale untagged membership.

### LLDP Cross-Check (WARNING)

**Why:** Two sides of an inter-switch link must agree on which VLANs
are trunked. If switch A tags VLAN 5 on its uplink but switch B
doesn't, VLAN 5 traffic from A is silently dropped at B. Each switch
only knows its own config — neither switch reports an error.

**What breaks:** VLAN connectivity stops at this link. Devices on one
side of the ring can't reach devices on the other. Especially nasty in
MRP rings where traffic can take either path — works intermittently
depending on which ring path is active.

```
For each link (A:port ↔ B:port):
  VLANs on A's port = {1, 5, 100}
  VLANs on B's port = {1, 100}
    │
    only_local  = {5}     ← A has it, B doesn't
    only_remote = {}      ← B has it, A doesn't
    │
    Either set non-empty → MISMATCH
```

Common cause: forgot to trunk a VLAN on one side of a link. Also
catches cases where `auto-trunk` was run on one ring but not another.

### Orphan VLANs (INFO)

**Why:** A stricter version of cross-check. The VLAN is tagged on one
side of a link but doesn't even exist on the neighbor device. Cross-
check catches membership mismatches; this catches missing VLANs
entirely. Separate check because it often has a different cause (VLAN
not yet created on all devices vs. forgotten trunk).

**What breaks:** Same as cross-check — traffic doesn't traverse the
link. But the fix is different: create the VLAN first, then trunk it.

```
For each link, for each VLAN tagged on local port:
  │
  ├─ VLAN 1 → skip (default, always everywhere)
  │
  └─ Remote side has this VLAN on link port?
       │
       ├─ YES → OK
       └─ NO  → ORPHAN (trunked into the void)
```

Often intentional during staged rollouts (create VLAN on one side
first, roll out to others later). Severity: INFO.

### Name Mismatches (INFO)

**Why:** VLANs match by ID, not name. VLAN 5 called "Cameras" on one
switch and "cameras" on another works fine technically. But when an
operator opens the web UI and sees different names for the same VLAN
on different switches, they question whether it's the same VLAN or
a misconfiguration. Inconsistent names erode trust in the config.

**What breaks:** Nothing functionally. Confuses humans. On large fleets
with many VLANs, inconsistent names make it significantly harder to
audit by eye.

```
Collect all (VLAN ID, name) pairs across fleet:
  VLAN 100: {"MRP-VLAN": [.80, .82], "": [.81, .85]}
    │
    More than one name → MISMATCH
    └─ --names can fix this (majority name wins)
```

The `--names` subcommand uses majority vote to fix these: the name
used by the most devices wins. Ties broken alphabetically. Empty
names always lose to non-empty.

## QoS via Naming Convention (future)

VLAN name prefix determines QoS class. No explicit QoS configuration needed.

```
VLAN naming convention:
  AC-*  → Application Control  (PCP 5)  PLC ↔ I/O
  AM-*  → Application Monitoring (PCP 4)  PLC ↔ SCADA
  NM-*  → Network Monitoring   (PCP 6)  SNMP, SSH, sFlow
  NC-*  → Network Control      (PCP 7)  STP, MRP, LLDP
  (none) → Best effort          (PCP 0-3)

Priority hierarchy: NC > NM > AC > AM > *
```

The `--names` subcommand already enforces naming consistency across the fleet. Adding QoS meaning to the prefixes means `viktor rename` pointed at a fleet = instant QoS intent for the entire system.

### Deployment flow

```
VLAN name prefix
  → QoS class (from naming convention)
    → read egress table (which ports carry this VLAN)
      → configure PCP/TC mapping on those ports
        → NILS verifies
```

### L3 boundary handling

PCP dies at L3 hops (VLAN header rebuilt). DSCP (IP header) survives. Strategy depends on SW level of the edge device:

```
For each VLAN with a QoS prefix:
  For each port carrying that VLAN:
    Does the path to other members cross L3?
      │
      ├─ NO → PCP is sufficient
      │
      └─ YES → need DSCP to survive the hop
               │
               ├─ Edge is L2A → ACL stamps DSCP at edge (cheapest)
               ├─ Edge is L2S → can't remark, upstream must handle
               └─ Edge is L3  → trust DSCP on routed interface
```

NILS provides the topology graph and SW levels. VIKTOR applies the strategy.

### Management VLAN

Special case: `network management priority dot1p` + `network management priority ip-dscp` set fleet-wide. Management VLAN inherits NM class from naming (`NM-MGMT`) or is detected from device config (`get_management_vlan()`).

### Engineering port exception

`"role": "engineering"` declared in documentation (can't be discovered). Gets split ACL: dstip matching switch management IPs → NM priority, everything else → default. Management IPs known from NILS discovery data.

## Config Resolution

```
Device source priority:
  │
  ├─ -d IP           → single device, ignore config file devices
  │
  ├─ --ips SPEC      → parsed IP list
  │   Still reads script.cfg for credentials (if it exists)
  │   Falls back to admin/private if no config file
  │
  └─ script.cfg      → devices from config file
      Requires file to exist

Credential priority:
  CLI flags (-u, -p, --protocol) override ALL sources.
  Otherwise: config file values, or defaults (admin/private/mops).
```

`--ips` is special: device list from the command line, but credentials
from the config file. This lets you target arbitrary IPs without
repeating credentials every time.

## ensure_vlan_exists + Dry Run

The `--name` flag on `access` and `auto-trunk` triggers create-if-missing
behavior. The dry-run interaction matters:

```
access 1/1 5 --name "Cameras" --dry-run:
  │
  ├─ Print plan (which ports, which VLAN)
  ├─ Print "Would create VLAN 5 (Cameras) if missing"
  └─ EXIT (no changes)

access 1/1 5 --name "Cameras":
  │
  ├─ Dry-run check passes → continue
  ├─ ensure_vlan_exists() → create VLAN 5 on devices where missing
  └─ Apply port changes
```

`ensure_vlan_exists()` is called AFTER the dry-run guard. This was a
bug fix — originally it ran before the check, creating VLANs even
during dry-run.
