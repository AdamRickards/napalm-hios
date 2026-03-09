# JUSTIN — TODO

**J**ustified **U**nified **S**ecurity **T**esting for **I**ndustrial **N**etworks

Security audit and hardening tool for Hirschmann HiOS switches. Scans
devices against IEC 62443 SL1/SL2 baselines, reports pass/fail, and
remediates findings with corresponding setters. ADAM but online — and
ADAM is much less security-conscious.

## Relationship to ADAM

ADAM is the offline audit engine — 59 checks, zero dependencies, works
on exported config XML files. ADAM stays standalone.

JUSTIN imports ADAM's check registry and adds:
- **Live connectivity** — connect to switches via napalm-hios, gather state via getters
- **Remediation** — every audit finding has a corresponding setter to fix it
- **IEC 62443 targeting** — `--level SL1` / `--level SL2` scopes which checks and fixes apply
- **ACL builder** — intent-based conduit enforcement on L3 switches
- **Fleet scale** — audit/harden across the entire fleet in parallel

ADAM = "here's what's wrong." JUSTIN = "here's what's wrong, and I fixed it."

## Modes

### Audit (`--audit`)

Read-only scan. Connects to device(s), runs ADAM checks against live
state, prints report card. No changes made.

```bash
justin --audit -d 192.168.1.4                # single device
justin --audit                               # fleet (script.cfg)
justin --audit --level SL2                   # filter to SL2 baseline
justin --audit -j                            # JSON output
justin --audit --offline configs/switch.xml  # ADAM mode (no network)
```

### Harden (`--harden`)

Audit + fix. Runs the same checks, then applies remediation setters
for every finding. Dry-run by default — must `--commit` to apply.

```bash
justin --harden -d 192.168.1.4 --dry-run     # show what would change
justin --harden -d 192.168.1.4 --commit      # apply fixes
justin --harden --level SL1 --commit         # harden to SL1 only
justin --harden --commit --save              # apply + save to NVM
```

### ACL Builder (`--acl`)

Interactive or intent-file-driven ACL generation for L3 switches.
Pulls interfaces and VLAN matrix, user declares permitted flows,
JUSTIN generates and deploys ACLs.

```bash
justin --acl -d 192.168.1.254 -i             # interactive flow builder
justin --acl -d 192.168.1.254 -f flows.yaml  # from intent file
justin --acl -d 192.168.1.254 --dry-run      # show generated ACLs
```

## Check → Fix Mapping

Every ADAM audit check gets a corresponding remediation action in JUSTIN.
Checks that are info-only (awareness) have no automatic fix — they
generate advisory output only.

### Security (IEC 62443 §2.11)

| Check | Finding | Fix | Driver Method | SL |
|-------|---------|-----|---------------|----|
| sec-hidiscovery | HiDiscovery enabled | Disable | `set_hidiscovery('off')` | SL1 |
| sec-insecure-protocols | HTTP/Telnet enabled | Disable HTTP, Telnet | `set_services()` | SL1 |
| sec-industrial-protocols | Unused protocols on | Disable EtherNet/IP, PROFINET, Modbus | `set_services()` | SL2 |
| sec-unsigned-sw | Unsigned FW accepted | Reject unsigned | `set_services()` | SL1 |
| sec-login-policy | No lockout configured | Set lockout + min length | `set_login_policy()` | SL1 |
| sec-password-policy | Weak passwords allowed | Enforce complexity | `set_password_policy()` | SL2 |
| sec-ip-restrict | No IP restrictions | Advisory only | — | SL2 |
| sec-time-sync | No NTP configured | Configure NTP server | `set_ntp()` | SL1 |
| sec-logging | No syslog configured | Configure syslog dest | `set_syslog()` | SL1 |
| sec-login-banner | No banner set | Set standard banner | `set_banner()` | SL2 |
| sec-mgmt-vlan | Management on VLAN 1 | Advisory only (manual) | — | SL1 |
| sec-aca-auto-update | ACA auto-update on | Disable | `set_services()` | SL1 |
| sec-aca-config-write | ACA config write on | Disable | `set_services()` | SL1 |
| sec-aca-config-load | ACA config load on | Disable | `set_services()` | SL1 |
| sec-session-timeouts | Excessive timeouts | Set reasonable defaults | `set_session_config()` | SL2 |
| sec-snmpv1-traps | SNMPv1 traps on | Disable v1 traps | `set_snmp_config()` | SL1 |
| sec-snmpv3-traps | No v3 traps configured | Configure v3 trap dest | `set_snmp_config()` | SL2 |
| sec-snmpv1v2-write | SNMPv1/v2 write enabled | Disable write access | `set_snmp_config()` | SL1 |
| sec-snmpv3-auth | MD5 auth in use | Switch to SHA | `set_snmp_config()` | SL2 |
| sec-snmpv3-encrypt | DES encryption in use | Switch to AES-128 | `set_snmp_config()` | SL2 |
| sec-dns-client | DNS config review | Advisory only | — | — |
| sec-devsec-monitors | Monitors not all enabled | Enable all | `set_services()` | SL1 |
| sys-default-passwords | Default accounts present | Advisory only (manual) | — | SL1 |

### Network Security (IEC 62443 §3)

| Check | Finding | Fix | Driver Method | SL |
|-------|---------|-----|---------------|----|
| ns-gvrp-mvrp | GVRP/MVRP enabled | Disable | `set_services()` | SL1 |
| ns-gmrp-mmrp | GMRP/MMRP enabled | Disable | `set_services()` | SL1 |
| ns-port-security | No MAC limit | Configure limit | `set_port_security()` | SL2 |
| ns-dhcp-snooping | Not configured | Enable + trust uplinks | `set_dhcp_snooping()` | SL2 |
| ns-ipsg | Not configured | Enable on edge ports | `set_ip_source_guard()` | SL2 |
| ns-dai | Not configured | Enable on edge ports | `set_arp_inspection()` | SL2 |
| ns-dos-protection | Not configured | Enable DoS filters | `set_services()` | SL2 |
| ns-lldp | LLDP state review | Advisory only | — | — |

### System / Edge / Redundancy

These checks already have existing driver methods — no new getters/setters needed.

| Check | Finding | Fix | Existing Method |
|-------|---------|-----|-----------------|
| sys-hostname-default | Default hostname | Set hostname | `set_snmp_information()` |
| sys-snmp-communities | Default communities | Advisory only | — |
| edge-loop-protection | No edge protection | Deploy via CLAMPS | — |
| mrp-rstp-conflict | RSTP on ring ports | Disable RSTP | `set_rstp_port()` |
| vlan-pvid-mismatch | PVID/egress mismatch | Fix via VIKTOR | — |

## New Driver Methods Required

### Getters (Phase 1 — audit)

| Method | What It Returns | MIB Source |
|--------|----------------|------------|
| `get_services()` | HTTP/HTTPS/SSH/Telnet/SNMP on/off, industrial protocols, ACA settings, DoS, GVRP/MVRP/GMRP/MMRP | Multiple MIBs |
| `get_ntp()` | NTP server(s), status, stratum, offset | HM2-PLATFORM-SNTP-MIB |
| `get_syslog()` | Syslog destinations, severity filter, facility | HM2-PLATFORM-LOGGING-MIB |
| `get_banner()` | Pre-login banner text | HM2-PLATFORM-MIB |
| `get_snmp_config()` | Communities, v3 users, trap destinations, auth/encrypt | SNMPv2-MIB, SNMP-FRAMEWORK-MIB |
| `get_login_policy()` | Lockout threshold, lockout duration, min password length | HM2-PLATFORM-MIB |
| `get_password_policy()` | Complexity requirements (upper, lower, digit, special, length) | HM2-PLATFORM-MIB |
| `get_session_config()` | CLI/web/SNMP session timeouts, max sessions | HM2-PLATFORM-MIB |
| `get_dot1x()` | 802.1X global + per-port config, MAC auth | IEEE8021-PAE-MIB |
| `get_dhcp_snooping()` | Global enable, per-VLAN, trust per-port | HM2-PLATFORM-MIB |
| `get_arp_inspection()` | DAI global + per-VLAN + trust per-port | HM2-PLATFORM-MIB |
| `get_ip_source_guard()` | IPSG per-port | HM2-PLATFORM-MIB |
| `get_port_security()` | MAC limit per-port, violation action | HM2-PLATFORM-MIB |
| `get_acl()` | ACL rules (L2/L3/L4), per-interface binding | HM2-PLATFORM-MIB |

### Setters (Phase 2 — harden)

Corresponding setter for each getter above. Same signature pattern as
existing driver setters.

### ACL Methods (Phase 3)

| Method | What It Does |
|--------|-------------|
| `get_acl()` | Read ACL rules + interface bindings |
| `set_acl()` | Create/modify ACL rules |
| `delete_acl()` | Remove ACL rules |
| `bind_acl()` | Apply ACL to interface (ingress/egress) |
| `unbind_acl()` | Remove ACL from interface |

## Phasing

### v0.1 — Audit Only

- [ ] Import ADAM check registry (`@register_check` + JSON specs)
- [ ] Live state gathering via napalm-hios (connect → getters → facts dict)
- [ ] Map ADAM's XML-parsed facts to getter-based facts (translation layer)
- [ ] `--audit` mode: connect, gather, run checks, print report
- [ ] `--offline` mode: pass-through to ADAM (XML files, no network)
- [ ] `--level SL1`/`SL2` filtering
- [ ] Report output: console (colored), JSON (`-j`), CSV
- [ ] Fleet mode: parallel audit across script.cfg devices

Driver work needed: **zero** — v0.1 uses only existing getters. Some
checks will report "unable to assess" when the getter doesn't exist yet.

### v0.2 — Basic Hardening

New driver methods: `get_services()`, `set_services()`, `get_syslog()`,
`set_syslog()`, `get_ntp()`, `set_ntp()`, `get_banner()`, `set_banner()`,
`get_login_policy()`, `set_login_policy()`

- [ ] `--harden --dry-run`: show planned remediations
- [ ] `--harden --commit`: apply fixes
- [ ] Fix mapping: each check ID → remediation function
- [ ] Services hardening (HTTP/Telnet/ACA/industrial protocols/GVRP/GMRP)
- [ ] Syslog configuration
- [ ] NTP configuration
- [ ] Banner deployment
- [ ] Login policy (lockout, min password length)
- [ ] HiDiscovery disable (already exists: `set_hidiscovery()`)

### v0.3 — Advanced Hardening

New driver methods: `get_snmp_config()`, `set_snmp_config()`,
`get_password_policy()`, `set_password_policy()`, `get_session_config()`,
`set_session_config()`, `get_dot1x()`, `set_dot1x()`,
`get_dhcp_snooping()`, `set_dhcp_snooping()`, `get_arp_inspection()`,
`set_arp_inspection()`, `get_port_security()`, `set_port_security()`

- [ ] SNMP hardening (disable v1/v2c write, configure v3, SHA/AES)
- [ ] Password policy enforcement
- [ ] Session timeout configuration
- [ ] 802.1X / MAC authentication
- [ ] DHCP snooping (global + per-VLAN + trust)
- [ ] Dynamic ARP Inspection
- [ ] IP Source Guard
- [ ] Port security (MAC limits)

### v0.4 — ACL Builder

New driver methods: `get_acl()`, `set_acl()`, `delete_acl()`,
`bind_acl()`, `unbind_acl()`

- [ ] Pull interface + VLAN matrix from L3 switch
- [ ] Interactive flow builder (`-i`): per-VLAN pair, yes/no + port numbers
- [ ] Intent file (`flows.yaml`): declarative conduit spec
- [ ] ACL rule generation from intent
- [ ] Deploy + bind ACLs
- [ ] SNOOP validation: post-deploy, verify only permitted traffic flows

## Validation Loop

```
JUSTIN --harden → apply security config
  │
  ▼
SNOOP listens → observe actual traffic
  │
  ▼
JUSTIN --audit → verify compliance holds
  │
  ▼
Drift detected? → JUSTIN --harden again
```

JUSTIN hardens. SNOOP validates. JUSTIN re-audits. Continuous loop.

## Config File

Same `script.cfg` format as all tools. Additional JUSTIN-specific settings:

```ini
username = admin
password = private
protocol = mops

# JUSTIN settings
level = SL1                        # default security level
syslog_server = 10.0.0.100        # remediation target for sec-logging
ntp_server = 10.0.0.1             # remediation target for sec-time-sync
banner = "Authorized access only." # remediation target for sec-login-banner

# Devices
192.168.1.4
192.168.1.80
192.168.1.254
```

## Interactive Mode (`-i`)

Guided hardening session:

```
  JUSTIN — Security Audit
  ════════════════════════
  Device: 192.168.1.4 (BRS50-8TX/4SFP, 10.3.04, L2A)
  Level:  SL1

  CRITICAL  sec-hidiscovery     HiDiscovery is enabled (read-write)
  WARNING   sec-insecure-protocols  HTTP enabled, Telnet enabled
  WARNING   sec-logging          No syslog destination configured
  WARNING   sec-time-sync        No NTP server configured
  PASS      sec-unsigned-sw      Unsigned firmware rejected
  PASS      sec-aca-auto-update  ACA auto-update disabled
  ...

  Score: 14/22 passed (SL1)

  Fix all findings? [y/N]:
```
