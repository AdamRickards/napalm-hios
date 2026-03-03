# MARCO — Decision Logic

How MARCO discovers and configures switches via HiDiscovery v2,
and the protocol quirks that took real debugging to solve.

## HiDiscovery v2 Protocol

SNMPv2c over multicast. Not standard SNMP infrastructure — it's a
custom discovery protocol that happens to use SNMP encoding.

```
Multicast group:  239.255.16.12
Port:             51973
Community:        @discover@
Direction:        GetRequest → multicast, GetResponse ← from device
```

The `@discover@` community has write access to the discovery MIB and
sysName (MIB-II). This is by design — HiDiscovery is an onboarding
protocol, not a management protocol.

## Why Multicast for SET Operations

SETs go to the multicast group, not to the device IP. This is not a
design choice — it's the only way that works.

```
Why unicast fails:

  New switch has no configured IP
    │
    It responds from 169.254.x.x (link-local)
    │
    You can't reliably route TO a link-local address
    │
    Even if you could, the switch only listens on the
    multicast group for HiDiscovery — not on unicast

How multicast SET works:

  1. Build SetRequest with target's UUID in the varbind list
  2. Send to 239.255.16.12:51973
  3. ALL switches on the segment receive the packet
  4. Each switch checks: does this UUID match mine?
       │
       ├─ NO  → ignore silently
       └─ YES → apply SET, respond from current IP
```

UUID is the targeting mechanism, multicast is the delivery mechanism.
The two are inseparable.

## Response Matching

Devices respond from whatever IP they currently have — could be
169.254.x.x (link-local), could be a configured management IP.

```
Discovery:
  Device responds → store _source_ip from socket addr

SET operation:
  send_and_wait() filters responses by _source_ip
    │
    ├─ Match + error_status=0 → [POLO] OK
    ├─ Match + error_status>0 → [POLO] error name
    └─ Timeout (3s)           → [POLO] No response
```

UUID is NOT used for response matching — it's only in the SET payload
to tell the device "this is for you." The source IP from discovery is
how MARCO knows which response is from the right device.

## The Gauge32 Bug

`InetAddressPrefixLength` (prefix length, e.g. 24 for /24) is defined
in the MIB as Gauge32, not INTEGER.

```
BER encoding difference:

  INTEGER:   tag 0x02, value bytes
  Gauge32:   tag 0x42, value bytes

  Same value encoding, different tag byte.
```

Using INTEGER (0x02) for prefix length caused `wrongType` (SNMP error 7).
The fix: `encode_unsigned()` with tag 0x42 instead of `encode_integer()`
with tag 0x02. One byte difference, hours of debugging.

## Blink Toggle

State-based toggle using cached discovery results:

```
Read current state from JSON cache:
  │
  ├─ blinking == 'enable'  → send value 2 (disable)
  └─ blinking != 'enable'  → send value 1 (enable)
  │
  Update cache with new state
  Write JSON
```

Blink updates the cache immediately (fire-and-forget to multicast).
This is less safe than IP/proto/name SETs which wait for confirmation,
but acceptable — worst case a blink toggle doesn't take and the cache
is wrong until next discovery.

## JSON Cache

`marco_results.json` — updated only on successful operations:

```
Discovery:
  Always overwrites entire cache (fresh scan)

SET operations (IP, proto, name):
  error_status == 0?
    │
    ├─ YES → update relevant fields, write JSON
    └─ NO  → don't touch cache (device state unchanged)

Blink:
  Updates cache immediately (no confirmation wait)
```

The cache serves two purposes:
1. Avoid re-discovery for every SET operation
2. Track blink state (device doesn't report this in discovery)

## SNMP Encoding

MARCO builds SNMP packets by hand. No pysnmp, no external library.
Zero dependencies beyond Python stdlib.

```
Hand-rolled:
  ├─ BER TLV encoder (tag, length, value)
  ├─ INTEGER encoder (tag 0x02, sign-safe)
  ├─ Gauge32 encoder (tag 0x42, unsigned)
  ├─ OCTET STRING encoder (tag 0x04)
  ├─ OID encoder (tag 0x06, base-128 sub-identifiers)
  └─ BER decoder (walks TLV structure, extracts varbinds)

Hardcoded:
  ├─ Discovery payload (320 bytes, captured from Wireshark)
  ├─ OID map (discovery MIB OIDs → human-readable keys)
  └─ Community string (@discover@)
```

The discovery payload is a byte-for-byte copy of what Hirschmann's
HiView tool sends. Building it dynamically would be possible but
pointless — the OID set never changes.

## [MARCO] / [POLO] Logging

The name IS the logging convention:

```
[MARCO]  = tool is SENDING (Marco shouts)
[POLO]   = device is RESPONDING (Polo answers)
```

Every network operation follows this pattern:
- `[MARCO] SET to 239.255.16.12:51973 (147 bytes)` — we sent
- `[POLO]  OK from 169.254.1.42` — device confirmed
- `[POLO]  wrongType from 169.254.1.42` — device rejected
- `[POLO]  No response from target (timeout)` — silence
