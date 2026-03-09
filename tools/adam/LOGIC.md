# ADAM Check Logic

Rules for how checks are evaluated. JSON defines metadata (id, severity, scope). Python implements logic.

## Global Service Gating

If a service is globally off, skip ALL sub-checks for that service. No noise.

| Service | Global check | If off → skip |
|---------|-------------|---------------|
| RSTP | `rstp_global.admin_mode` | bpdu-guard, edge-on-edge, trunk-not-edge, per-port STP checks |
| Loop-prot | `loop_prot_global.enabled` | per-port loop-prot checks |
| MRP | `components['mrp']` empty | all MRP checks (natural — iterates empty list) |
| SRM | `components['srm']` empty | all SRM checks (natural) |
| SRM global | `srm_global.enabled` | instances configured but global off = warning |

## Redundancy Posture

Meta-check gathers all redundancy globals and reports effective state.

| Condition | Finding |
|-----------|---------|
| No RSTP, MRP, SRM, or loop-prot | WARN: no effective redundancy |
| RSTP global on, all ports STP off | WARN: false confidence (worse than off) |
| SRM global off, instances configured | WARN: inactive sub-rings |
| Any protocol actually running | PASS: summary of active protocols + roles |

## Edge Protection Strategy

Each edge port should have exactly ONE protection mechanism:

| Strategy | Conditions | Quality |
|----------|-----------|---------|
| `rstp-full` | RSTP global on + per-port STP on + BPDU guard on | Best |
| `rstp` | RSTP global on + per-port STP on + BPDU guard off | OK |
| `loop-prot` | Loop-prot global on + per-port enabled | OK |
| Both | RSTP + loop-prot on same port | Conflict (warning) |
| Neither | No protection | Warning |

## Port Role vs Protection Matrix

| Port role | RSTP allowed? | Loop-prot allowed? | Notes |
|-----------|--------------|-------------------|-------|
| edge | Yes | Yes | Exactly one strategy |
| trunk | Only if no MRP/SRM | No | MRP handles redundancy |
| ring | No | No | MRP handles it |
| sub-ring | No | No | SRM handles it |
| lag | TBD | TBD | |

Exception: if NO MRP/SRM configured at all, RSTP on trunks is expected (RSTP-only network).

## SRM Role Enum

`hm2SrmAdminState` is NOT a boolean. It is a role enum:

| Value | Role | Usage |
|-------|------|-------|
| 1 | manager | One end of sub-ring |
| 2 | redundant-manager | Other end of sub-ring |
| 3 | single-manager | Both endpoints on one switch |

**Do NOT use HIOS_BOOL** on this attribute — `2` would incorrectly map to `False`.

## Site Analysis

### MRP Ring Identity

MRP ring = UUID + VLAN. Same UUID with different VLANs = separate rings. This is normal practice — most sites leave the default UUID (all-FF) and rely on VLAN separation.

### MRP RM Count

Per ring instance (UUID+VLAN), validate exactly 1 ring manager:
- 0 MRP RMs → check if SRM provides the manager role on that VLAN
- SRM manager on same VLAN → ring is managed by SRM, PASS
- No SRM either → CRIT: no ring manager

### SRM Topology

Valid configurations per sub-ring (grouped by ring_id + VLAN):
- **2 members**: manager + redundant-manager = healthy
- **1 member**: single-manager = valid (both ports on one switch)
- **1 member**: manager or redundant-manager alone = partner missing (WARNING)

Effective state = row_status active (1) AND SRM global enabled. notInService (2) entries are configured but parked.

### VLAN Name as Intent

SRM/MRP VLAN names encode topology intent (e.g., "SRM-VLAN", "MRP-VLAN"). These are excluded from site VLAN name consistency checks — different names across devices are expected.

## Management IP

- Flat mgmt IP (`hm2NetLocalIPAddr`) and VLAN IPs (`hm2AgentSwitchIpInterfaceIpAddress` on `vlan/N`) are independent
- 0.0.0.0 flat mgmt IP is only a warning if there are also no VLAN IPs
- L3 devices typically use VLAN IPs; L2 devices use flat mgmt IP

## Segmentation Principle

Two layers of isolation in L2 networks:
- **Data segmentation**: VLANs — isolate broadcast domains
- **Topology segmentation**: RSTP boundaries — isolate reconvergence events

A non-RSTP device between RSTP segments creates two independent STP instances (fault domain isolation). This is a feature in MRP networks: MRP handles ring redundancy, each segment gets its own RSTP for edge protection, and a TCN on one side doesn't cascade to the other.

Mixed RSTP on/off in a site is an observation, not an error.

## Device Security (§2.11)

24 XML checks mapped to vendor security manual §2.11 hardening checklist. See `reference/SECURITY_CHECKLIST.md` for the full mapping.

### Severity Calibration

Vendor language determines severity:
- **critical**: vendor says "disable" and delivery default is insecure (e.g., HiDiscovery read-write)
- **warning**: vendor says "disable" or "enable" with clear recommendation
- **info**: vendor says "consider" or "configure to your situation"

### SNMPv3 Traps

Detection via SNMP-TARGET-MIB: `snmpTargetParamsMPModel` 0=SNMPv1, 3=SNMPv3. Cross-reference `snmpTargetAddrEntry` to see which params are bound to active target addresses.

### VACM Write Access (L2A+)

`vacmAccessSecurityModel` 1=SNMPv1, 2=SNMPv2c. If `vacmAccessWriteViewName` is non-empty and not "none", that security model has write access — reported per access group.

### Device Security Sense Monitors

17 conditions from `hm2DevSecConfigGroup` in `HM2-DIAGNOSTIC-MIB`. Each monitor can be enabled/disabled independently. Report shows which monitors are active and any that report non-secure status.

## Network Security (§3)

8 checks for network-layer security features. All require L2S minimum.

### Dynamic Registration Protocols

| Check | Feature | Severity | Vendor Guidance |
|-------|---------|----------|-----------------|
| ns-gvrp-mvrp | GVRP + MVRP | warning | "It is generally considered more secure to disable" (§3.3.2) |
| ns-gmrp-mmrp | GMRP + MMRP | warning | "It is generally considered more secure to disable" (§3.4.1) |

Both protocols checked independently — either being enabled triggers the finding. GVRP in Q-BRIDGE-MIB, MVRP in HM2-PLATFORM-MVRP-MIB, GMRP in BRIDGE-MIB, MMRP in HM2-PLATFORM-MMRP-MIB.

### Port-Level Security Features

| Check | Feature | Severity | Notes |
|-------|---------|----------|-------|
| ns-port-security | MAC limit per port | info | Report enabled count + global state |
| ns-dhcp-snooping | Rogue DHCP prevention | info | Global state + trusted port count |
| ns-ipsg | IP spoofing prevention | info | Port count with IPSG active |
| ns-dai | ARP spoofing prevention | info | Port count with DAI active |

These are INFO because vendor says "configure to your situation" — they're L2 hardening options, not universal requirements. Report counts of ports with each feature enabled for awareness.

### MIB Merging Note

IPSG, DAI, and DHCP Snooping tables sometimes appear under their own MIB names (`HM2-PLATFORM-IPSG-MIB`, `HM2-PLATFORM-DAI-MIB`, `HM2-PLATFORM-DHCP-SNOOPING-MIB`) and sometimes merged into `HM2-PLATFORM-SWITCHING-MIB`. Discovery searches all candidates.

### DoS and LLDP

| Check | Feature | Severity | Vendor Guidance |
|-------|---------|----------|-----------------|
| ns-dos-protection | TCP/ICMP DoS filters | info | "Consider setting up DoS filters" (§3.6.1) — 11 individual filter checks |
| ns-lldp | Topology exposure | info | Report LLDP state for awareness — not inherently wrong, but review scope |

## Manual Checks (Live-Only)

11 CLI commands for items not in XML config exports. Grouped in report under "Manual verification required":

| Ref | What | CLI Command |
|-----|------|-------------|
| 2.11.3 | Secure boot / device security status | `show security-status state` |
| 2.11.6 | Signal contact mode | `show signal-contact` |
| 2.11.7 | Digital input state | `show digital-input config` |
| 2.11.18 | HTTPS certificate (not self-signed?) | `show https` |
| 2.11.19 | SSH host key fingerprint | `show ssh server` |
| 2.11.20 | SSH known hosts | `show ssh` |
| 2.11.26 | Certificate validity/revocation | `show security-status monitor` |
| 2.11.32 | CLI service shell (irreversible disable) | `show serviceshell` |
| 3.6.3 | Management MAC conflict detection | `show address-conflict global` |
| 3.9.1 | Persistent logging to external memory | `show logging persistent` |
| ops | Running config saved to NVM | `show config status` |

Items confirmed NOT in XML: signal contact, digital input, CLI service shell, persistent logging state, MAC conflict detection mode.

## SW Level Gating

Checks specify `requiresSW` in JSON. Check is skipped if device SW level is below requirement. Skipped checks are visible in the report ("checks skipped — requires L2A").

Hierarchy: `L2S < L2E < L2A < L3S < L3A_UR < L3A_MR`
