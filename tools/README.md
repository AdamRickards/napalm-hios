# napalm-hios Tools

Fleet management tools for Hirschmann HiOS switches. Each tool handles one domain — discovery, commissioning, VLANs, ring protection, optics, monitoring — and they share a common config format, protocol selection, and parallel execution model.

All tools except MARCO and SNOOP use [napalm-hios](https://github.com/adamr/napalm-hios) as their driver.

## Tools

| Tool | Full Name | What It Does | Min Driver | Docs |
|------|-----------|-------------|------------|------|
| [AARON](aaron/) | Automated Asset Recognition On Network | Port classification (uplink/edge/indirect/empty) + ARP resolution | `>= 1.5.0` | [LOGIC](aaron/LOGIC.md) |
| [CLAMPS](clamps/) | Configuration of Loops, Access, MRP, Protection, and Sub-rings | MRP ring deployment, edge protection, sub-rings, storm control | `>= 1.14.0` | [LOGIC](clamps/LOGIC.md) |
| [MARCO](marco/) | Multicast Address Resolution and Configuration Operator | HiDiscovery v2 — L2 multicast discovery + IP/name/blink config | standalone | [LOGIC](marco/LOGIC.md) |
| [MOHAWC](mohawc/) | Management, Onboarding, HiDiscovery, And Wipe Configuration | Commissioning — onboard, save, reset, profiles, diff, system | `>= 1.5.0` | [LOGIC](mohawc/LOGIC.md) |
| [SNOOP](snoop/) | sFlow Network Observation and Overview Platform | Passive sFlow v5 listener — FDB, ARP, VLAN, counters, traffic | standalone | [LOGIC](snoop/LOGIC.md) |
| [STONE](stone/) | SFP Transceiver Optics Network Evaluator | SFP optical power levels → Excel report with outlier detection | `>= 1.4.1` | — |
| [VIKTOR](viktor/) | VLAN Intent, Knowledgeable Topology-Optimized Rules | Fleet VLAN provisioning, QoS, audit, auto-trunk via LLDP | `>= 1.13.0` | [LOGIC](viktor/LOGIC.md) |

**Planned:** [BLIP](blip/) (port blink identification), [POLO](polo/) (persistent onboarding via dnsmasq registry)

## Access Patterns

Most tools support three ways to run:

| Pattern | How | When |
|---------|-----|------|
| **CLI args** | `tool.py -d IP subcommand --flags` | Power users, scripting, CI |
| **Config file** | `tool.py -c site.cfg subcommand` | Fleet-scale batch operations |
| **Interactive** | `tool.py -i` | Guided mode, no args to memorise |

AARON and STONE are batch-only (no interactive mode). MARCO defaults to interactive. SNOOP is a passive listener.

## Shared Config Format

All tools that use `script.cfg` share the same `key = value` format:

```ini
username = admin
password = private
protocol = mops

# Devices — one IP per line
192.168.1.80
192.168.1.81
192.168.1.82
```

CLI flags (`-u`, `-p`, `--protocol`) override config file values. With `-d`, no config file is needed.

## Protocols

| Protocol | Speed | Staging | Offline | Notes |
|----------|-------|---------|---------|-------|
| **MOPS** (default) | Fast | Yes | — | HTTPS/XML, recommended |
| **SNMP** | Medium | — | — | SNMPv3 authPriv |
| **SSH** | Slow | — | — | CLI parsing |
| **Offline** | Instant | Yes | Yes | Config XML files, no network (`>= 1.14.0`) |

MOPS staging batches multiple mutations into a single atomic POST per device. SNMP and SSH send changes individually.

Offline mode auto-detects when device paths are `.xml` files — credentials and protocol line are not needed.

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — Cross-cutting design insights
- [SITE_INDEX.md](SITE_INDEX.md) — Shared site index (`-fi`) for cross-tool enrichment (planned)
- [napalm-hios](https://github.com/adamr/napalm-hios) — NAPALM driver for HiOS
