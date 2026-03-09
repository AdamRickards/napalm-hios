# MARCO — Multicast Address Resolution and Configuration Operator

Zero-dependency Python tool for HiDiscovery v2 protocol — multicast SNMP discovery and configuration of Hirschmann HiOS devices.

**WARNING: This tool is experimental. If symptoms persist, contact your Doctor. This manual does not constitute medical advice.**

## How It Works

HiDiscovery v2 is SNMPv2c over multicast group `239.255.16.12:51973` with community `@discover@`. Devices respond from their link-local (169.254.x.x) address. Set operations target devices by UUID.

## Quick Start

```bash
python marco.py              # interactive mode (default)
python marco.py -I           # interactive mode (explicit)
python marco.py -v           # CLI discovery (verbose)
python marco.py -b -i 2     # toggle blink on device 2
python marco.py -b           # toggle blink on all devices
```

## Interactive Mode

Run `python marco.py` with no arguments (or `-I`) to enter interactive mode — a two-stage REPL:

1. **Discover** — auto-detects interfaces, scans the multicast group, displays a live device table
2. **Operate** — pick a device by index, pick an action, enter values, see results inline

```
  ╔╦╗╔═╗╦═╗╔═╗╔═╗
  ║║║╠═╣╠╦╝║  ║ ║
  ╩ ╩╩ ╩╩╚═╚═╝╚═╝
  All your switch are belong to Belden.

  #   IP               Name                  Product              FW        Blink
  ───                   ────────────────────  ──────────────────   ────────  ─────
  1   192.168.1.80     BRS-A0B086F4EA1F      BRS50-001220Q2Q...  10.3.04   disable
  2   192.168.1.82     BRS-EC74BA123456      BRS50-001220Q2Q...  10.3.04   disable

  1) Blink         2) Set IP        3) Set name
  4) DHCP/Static   5) Re-discover   6) Quit

  ▸ What next? [6]:
```

The socket stays alive across the session. Device index defaults to the last-picked device. Type `list` at the menu to reprint the device table without re-scanning.

## Discovery

Sends a multicast GetRequest, collects responses, writes results to `marco_results.json`. All Set operations use the cached JSON — no re-discovery needed.

```bash
python marco.py
python marco.py -v           # full field breakdown per device
python marco.py --raw        # hex dump of each reply
python marco.py -s           # silent — JSON only
python marco.py --timeout 10 # wait longer for replies
```

## Set Operations

All Set operations read from the cached `marco_results.json` and target devices by index (`-i N`).

### Blink Toggle

```bash
python marco.py -b -i 2     # toggle blink on device 2
python marco.py -b           # toggle all devices
```

### Set IP Address

Automatically sets config protocol to static. Prefix is mandatory, gateway is optional.

```bash
python marco.py --set-ip 192.168.1.50 --prefix 24 -i 2
python marco.py --set-ip 192.168.1.50 --prefix 24 --gateway 192.168.1.254 -i 2
```

### Config Protocol (DHCP / Static)

```bash
python marco.py --dhcp -i 3
python marco.py --static -i 3
```

### Set sysName

```bash
python marco.py --name "MY-SWITCH" -i 2
```

## Arguments

| Flag | Description |
|------|-------------|
| `-I` | Interactive REPL mode (default when no args given) |
| `-v` | Verbose discovery output (full device details) |
| `--raw` | Hex dump of each reply |
| `-s` | Silent mode (JSON file only) |
| `--timeout N` | Seconds to wait for replies (default: 5) |
| `--interface IP` | Local IP of interface facing the switches |
| `-b` | Toggle blink (uses cached JSON) |
| `-i N` | Target device index (from discovery results) |
| `--set-ip IP` | Set management IP (requires `-i`, `--prefix`) |
| `--prefix N` | Prefix length for `--set-ip` |
| `--gateway IP` | Gateway for `--set-ip` (optional) |
| `--dhcp` | Set config protocol to DHCP (requires `-i`) |
| `--static` | Set config protocol to static (requires `-i`) |
| `--name NAME` | Set sysName (requires `-i`) |

## JSON Output

`marco_results.json` is written on every discovery and updated after successful Set operations:

```json
{
  "timestamp": "2026-02-27T18:45:49.213149",
  "devices": [
    {
      "_index": 1,
      "_source_ip": "169.254.234.31",
      "_response_time": 1.81,
      "product": "BRS50-00122Q2Q-STCY99HHSEA",
      "firmware": "HiOS-2A-10.3.04 2025-12-08 16:54",
      "mac": "a0:b0:86:f4:ea:1f",
      "ip": "192.168.1.117",
      "prefix_len": 24,
      "gateway": "192.168.1.254",
      "mode": "read-write",
      "blinking": "disable",
      "config_proto": "static",
      "uuid": "393432313730313131313738323031303036",
      "sysname": "BRS-A0B086F4EA1F"
    }
  ]
}
```

## Protocol Support

MARCO is standalone — it does NOT use napalm-hios. It speaks HiDiscovery v2 (SNMPv2c over multicast) directly via raw sockets. No dependencies.

| Feature | HiDiscovery v2 | Notes |
|---------|---------------|-------|
| Discover | Yes | Multicast GetRequest, all devices respond |
| Blink toggle | Yes | Requires `read-write` mode |
| Set IP | Yes | Auto-sets config protocol to static |
| Set sysName | Yes | MIB-II sysName via `@discover@` community |
| DHCP/Static | Yes | Config protocol toggle |

## Notes

- Requires HiDiscovery to be enabled (`read-write` mode) on target devices
- Devices in `read-only` mode will respond to discovery but reject Set operations
- Set operations are multicast — the UUID varbind identifies the target device
- The `_source_ip` (link-local) is the device's actual reply address, not the management IP
- Changes are not saved to NVM — use MOHAWC or the switch CLI to persist
- JSON cache is only updated on successful Set responses (SNMP error-status 0)
- This protocol is stateless — sometimes things might not appear to work but it's worth double checking because nr != dr

## See Also

- [LOGIC.md](LOGIC.md) — HiDiscovery v2 protocol, multicast targeting, Gauge32 bug, SNMP encoding
- [MOHAWC](../mohawc/) — Use MOHAWC to persist changes to NVM after MARCO configures a device
