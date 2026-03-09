# ADAM — Automated Device Audit Model

Offline security audit tool for Hirschmann HiOS switches. Parses config XML exports and audits against Belden's Security Hardening Manual — 59 checks across security (§2.11), network security (§3), redundancy, switching, and system configuration. Zero external dependencies.

ADAM is the audit engine. [JUSTIN](../justin/) is ADAM but online — live audit + hardening.

## Requirements

- Python 3.7+
- No pip dependencies (stdlib only)
- HiOS config XML exports (from web UI, TFTP, or MOHAWC `download`)

## Quick Start

Single-run audit — no interactive mode, no network required:

```bash
python adam.py config.xml                     # audit one config
python adam.py configs/                       # audit all XMLs in directory (site mode)
python adam.py config.xml -v                  # verbose (show pass + fail)
python adam.py config.xml -s critical         # filter by severity
python adam.py config.xml -j                  # JSON output
python adam.py config.xml -o report.html      # HTML report
python adam.py config.xml --no-color          # plain text (pipe-friendly)
```

## Checks

59 checks across 7 categories, loaded from JSON specs in `checks/`:

| Category | Checks | Source |
|----------|--------|--------|
| Security (§2.11) | 23 | Belden Security Hardening Manual |
| Network Security (§3) | 8 | Belden Security Hardening Manual |
| System / Edge Protection | 8 | Operational best practice |
| RSTP | 5 | Redundancy posture |
| MRP / SRM | 5 | Ring integrity |
| VLAN | 4 | Switching hygiene |
| Security (L3A only) | 1 | Module slot hardening |

Checks are gated by SW level — L2S devices skip checks that require L2A+ features. Skip messages are visible in verbose mode.

### Severity Levels

- **CRITICAL** — active security risk or broken redundancy (4 checks)
- **WARNING** — misconfiguration or missing hardening (30 checks)
- **INFO** — awareness, best practice, no automatic fix (25 checks)

## Arguments

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show all checks (pass + fail), not just findings |
| `-s <level>` | Filter by minimum severity: `critical`, `warning`, `info` |
| `-j`, `--json` | JSON output |
| `-o <path>` | Output file (`.txt`, `.html`, `.json`) |
| `--no-color` | Disable ANSI colors |

## Site Mode

Point at a directory of config XMLs for fleet-wide audit:

```bash
python adam.py configs/
```

Site mode adds cross-device checks:
- MRP ring manager count (exactly one RM per ring?)
- VLAN name consistency across devices
- SRM role pair validation (one manager + one redundant-manager per sub-ring)

## Protocol Support

ADAM is standalone — it does NOT use napalm-hios. It parses HiOS config XML files directly using `xml.etree.ElementTree`. No network, no credentials, no protocol selection.

| Feature | Offline XML |
|---------|------------|
| Security audit (§2.11) | Yes |
| Network security audit (§3) | Yes |
| Redundancy checks | Yes |
| VLAN checks | Yes |
| System checks | Yes |
| Remediation | No (see JUSTIN) |

## Example Output

```
============================================================
  ADAM — Automated Device Audit Model
============================================================
  File: config-192_168_1_80.xml
  Device: BRS50-8TX/4SFP  (10.3.04, L2A)
------------------------------------------------------------

  CRITICAL  sec-hidiscovery        HiDiscovery enabled (read-write)
  WARNING   sec-insecure-protocols HTTP enabled
  WARNING   sec-logging            No syslog destination configured
  WARNING   sec-time-sync          No NTP server configured
  WARNING   rstp-bpdu-guard        BPDU Guard not enabled
  PASS      sec-unsigned-sw        Unsigned firmware rejected
  PASS      mrp-rstp-conflict      RSTP disabled on ring ports
  ...

============================================================
  14/22 passed | 1 critical | 3 warning | Score: 64%
============================================================
```

## See Also

- [LOGIC.md](LOGIC.md) — Check implementation details, XML parsing, severity rationale
- [JUSTIN](../justin/) — Online audit + hardening (ADAM + napalm-hios + remediation)
- Belden Security Hardening Manual (reference/SecurityManual_BRS_HiOS-2A-10000_en.pdf)
