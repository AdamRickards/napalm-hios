# Shared Site Index (`-fi`)

Cross-tool enriched JSON — each tool reads from and writes back to a shared site index. One file describes the whole network: devices, ports, topology, health, traffic. Tools build on each other instead of starting from scratch.

Default path: `tools/site.json` (one level up from any `tools/name/` dir — shared by all tools). Every tool auto-discovers it via `../site.json` relative to its own location.

```
# MARCO discovers devices → creates site.json
python marco.py                          # writes tools/site.json

# AARON enriches with port classification (reads site.json, writes back)
python aaron.py -fi                      # -fi = --from-index, default ../site.json

# STONE checks optics on devices 3 and 7 by index number
python stone.py -fi -i 3,7

# CLAMPS deploys ring (reads topology from index)
python clamp.py -fi

# MOHAWC saves config on everything in the index
python mohawc.py save -fi

# Explicit path override
python aaron.py --from-index /path/to/other_site.json
```

## Index Format

```json
{
  "created": "2026-03-01T10:22:35Z",
  "updated": "2026-03-01T12:45:00Z",
  "devices": [
    {
      "index": 1,
      "ip": "192.168.1.80",
      "mac": "00:80:63:...",
      "product": "BRS50-0012...",
      "firmware": "10.3.04",
      "sysname": "Test unit 1",
      "sw_level": "L2A",
      "ports": { ... },
      "topology": { "uplinks": ["1/5", "1/6"], "edge": ["1/1", "1/2", ...] },
      "rings": { "100": {"role": "manager", "ports": ["1/5", "1/6"]}, "200": {"role": "srm", "port": "1/10"} },
      "optics": { ... },
      "sflow": { ... }
    }
  ],
  "links": [ ... ],
  "vlans": { ... },
  "enrichment": { "aaron": "2026-03-01T11:00:00Z", "stone": "2026-03-01T12:45:00Z" }
}
```

## Implementation

- [ ] Define site index JSON schema (devices, links, enrichment timestamps)
- [ ] `-fi` / `--from-index` flag on all tools (argparse, shared helper)
- [ ] Auto-discover `../site.json` when `-fi` used with no path
- [ ] Each tool: read index → use device list instead of script.cfg IPs → enrich → write back
- [ ] Tools that are already read-only (STONE, AARON) just enrich on every run with `-fi` — no separate `--gather` mode needed. Tools that write config (CLAMPS, MOHAWC) need explicit `--gather` for read-only enrichment pass
- [ ] Index numbers for device selection: `-i 3,7,12` picks devices by index
- [ ] Three ways to create the index:
  - **MARCO** — L2 multicast discovery, local segment only (`python marco.py` → `site.json`)
  - **AARON `--seed IP`** — give it one switch, LLDP BFS crawl discovers all connected switches. Connect to seed → `get_lldp_neighbors_detail()` → connect to discovered mgmt IPs → repeat until no new devices. Creates index with full topology in one pass. Needs credentials (from `-c` config or `--user`/`--pass`)
  - **Manual** — any tool with `-fi` and no existing index → falls back to `script.cfg` device list → creates index from it
- [ ] AARON as first enricher (port classification, topology links, edge MACs)
- [ ] Backwards compatible — all tools still work with `script.cfg` when `-fi` not used
- [ ] **Master CLI** — single entry point wrapping all tools: `map-site --seed IP`, `map-site --marco`, `map-site --stone`, `map-site --clamps --gather`, `map-site --view` (open NILS). One command, one file
- [ ] **PyPI extras** — `pip install napalm-hios[tools]` installs tool dependencies (openpyxl, etc.) + `map-site` CLI entry point via `console_scripts` in setup.py
