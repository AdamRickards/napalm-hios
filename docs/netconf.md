# NETCONF on napalm-hios

This document is the scope of what the 1.18 NETCONF transport can map
and expose against the HiOS **10.7.00 BETA83 BRS** image, and how to
extend it when Hirschmann / Belden ships vendor YANG.

The transport is read-only. It issues `<get>`, `<get-config>`,
`<get-data>` and (in the lab smoke) `<get-schema>` only. There is no
`<edit-config>`, `<commit>`, `<lock>`, or other write RPC.

## Server

The 10.7.00 BETA83 BRS image runs a stock **YumaWorks netconfd**
server (`master-2026-11-12.16.50`, 23.7.0-T) on TCP port 830. The
hello advertises IETF and Yuma models only — **no Hirschmann, Belden,
or HiOS vendor modules**.

A cursory audit of that beta recorded 47 hello capabilities, 46
schemas (0 `get-schema` errors), and yang-library content-id 5315.
`ietf-interfaces` and `ietf-ip` are import-only in the library but
interface state still answers a namespaced plain `<get>`.
`ietf-system` is present; its optional features (NTP, local-users,
authentication, DNS, and so on) are **not** advertised, and the
corresponding data is absent.

Port 830 remains an SSH server even when the NETCONF subsystem is
disabled: password authentication can succeed and the `netconf`
subsystem is then rejected. That is why NETCONF is last in the default
protocol order (see [Selector](#selector) below) and why callers who
want NETCONF should put it first.

RESTCONF is also live on this beta (`restconf-state`). gNMI is not.
This driver uses NETCONF only.

## Capabilities (ietf-netconf)

Advertised `:ietf-netconf` features:

| Feature            | Advertised |
|--------------------|------------|
| candidate          | yes        |
| confirmed-commit   | yes        |
| rollback-on-error  | yes        |
| validate           | yes        |
| url                | yes        |
| xpath              | yes        |
| writable-running   | no         |
| startup            | no         |

`with-defaults` basic-mode is `explicit`. Writes are out of scope for
this release even though candidate / confirmed-commit are advertised.

## Datastores

`netconf-state` names **candidate** and **running** only (no startup).
The yang-library also names NMDA `ds:intended` and `ds:operational`.

| Datastore        | How this driver reads it        | What it contains on this beta                          |
|------------------|---------------------------------|--------------------------------------------------------|
| running          | `<get-config>`                  | IETF interfaces (13 ports: name, description, type, enabled, link trap) + IETF system (contact, location, timezone-utc-offset). Not a HiOS running-config. |
| candidate        | `<get-config>`                  | Identical to running on the box that was audited.      |
| intended         | not used by getters             | Same local-name tree as running.                       |
| operational      | `<get-data>` for hostname only  | Library/monitoring + system (including hostname). **Empty `interfaces` / `interfaces-state`.** |
| startup          | not advertised                  | `get_config()` always returns `startup: ""`.           |

Interface state must come from a namespaced plain `<get>` of
`ietf-interfaces`, not from NMDA `ds:operational`.

Access control (NACM) reads returned empty `<data/>` — no groups or
rules, and NACM is absent from running/candidate.

## Getter matrix

Paths are IETF YANG instance identifiers. Leaves that are missing on
this beta are listed as absent, not defaulted in the table.

### Supported or partial

| Getter | Status | YANG paths | Notes |
|--------|--------|------------|-------|
| `get_facts` | partial | `/ietf-system:system/hostname` (often only in `ds:operational`); `/ietf-system:system/contact`; `/ietf-system:system/location`; `/ietf-system:system-state/clock/current-datetime`; `/ietf-system:system-state/clock/boot-datetime`; `/ietf-interfaces:interfaces/interface/name` and `/ietf-interfaces:interfaces-state/interface/name` | `vendor` is the constant `Belden` (same as SSH/SNMP). `model`, `serial_number`, and `os_version` are empty — there is no serial or order-code model, and `/ietf-system:system-state/platform` (`os-name`, `os-release`, `os-version`, `machine`) is the **Linux kernel**, not HiOS. Uptime is current − boot in seconds (see [clock Z](#clock-z-suffix)). `fqdn` is the hostname (no domain leaf). |
| `get_interfaces` | partial | `/ietf-interfaces:interfaces/interface/*` (name, description, type, enabled, link-up-down-trap-enable); `/ietf-interfaces:interfaces-state/interface/*` (admin-status, oper-status, if-index, phys-address, speed, statistics) | `is_enabled` = config `enabled` (else state `admin-status == up`). `is_up` = `oper-status == up`. **Do not swap these.** Speed is the IETF `speed` leaf in **bits/s** (same unit SSH/SNMP already return). Missing speed → `0`. No `mtu` leaf on this beta → `1500`, matching SSH. Empty `<description/>` → `""`, not `None`. `last_flapped` is unknown (`-1.0`). |
| `get_interfaces_counters` | supported | `/ietf-interfaces:interfaces-state/interface/statistics` (`in-octets`, `out-octets`, `in-unicast-pkts`, `out-unicast-pkts`, `in-broadcast-pkts`, `out-broadcast-pkts`, `in-multicast-pkts`, `out-multicast-pkts`, `in-discards`, `out-discards`, `in-errors`, `out-errors`) | No last-clear. Missing counters → `0`. |
| `get_config` | partial | `<get-config>` source `running` / `candidate` | Returns XML text of the IETF slice described above, not a HiOS CLI/XML export. `startup` is always `""`. `full` / `sanitized` have no effect. |
| `get_snmp_information` | partial | `/ietf-system:system/contact`; `/ietf-system:system/location` | Honest slice only. `chassis_id` is `""` and `community` is `{}` — there is no SNMP YANG. |

### Unsupported

These raise `NotImplementedError` on the NETCONF protocol so the
driver does not invent data. They stay available on MOPS, SNMP, and
SSH.

| Getter | Why this beta cannot serve it |
|--------|-------------------------------|
| `get_interfaces_ip` | `ietf-ip` is import-only; no IPv4/IPv6 interface data in `<get>`. The audited box is L2. |
| `get_lldp_neighbors` / `_detail` | No LLDP YANG. |
| `get_mac_address_table` | No forwarding-database / IEEE 802.1Q YANG. |
| `get_arp_table` | No ARP / IPv4 neighbor YANG. |
| `get_vlans` / `get_vlan_ingress` / `get_vlan_egress` | No VLAN / 802.1Q vendor model. |
| `get_users` | `ietf-system` local-users feature is not advertised; NACM is empty. |
| `get_ntp` / `get_ntp_servers` / `get_ntp_stats` | `ietf-system` ntp feature is not advertised. |
| `get_snmp_config` | No SNMP YANG (distinct from the partial `get_snmp_information`). |
| `get_optics` / environment / PoE / MRP / RSTP / and other vendor getters | No vendor modules. |

## Known beta quirks

- **Speed is uneven.** Oper-up copper 1G ports send `speed` (1e9
  bits/s). Oper-up fiber ports omit the leaf. Down ports and the
  `cpu/1` interface send `0`. The driver reports `0` when the leaf is
  missing or zero; it does not invent 1G.
- **Clock Z suffix.** `current-datetime` and `boot-datetime` use a `Z`
  suffix on a clock the CLI treats as local time
  (`timezone-utc-offset` is 660, UTC+11, on the audited box). The
  interval between the two stamps is still valid if both are parsed as
  naive datetimes with the suffix stripped. Do **not** convert via
  UTC. See `uptime_seconds()` in `napalm_hios/netconf_hios.py`.
- **`platform` is the kernel.** `system-state/platform/os-version`
  (and related leaves) name the Linux kernel (`os-name` Linux, a
  machine such as `armv7l`). They are not a HiOS version string and
  must not be copied into `os_version` or `model`.
- **Empty description.** Config `<description/>` is present and empty.
  The driver returns `""`.
- **`ds:operational` has empty interfaces.** An unfiltered (or
  interface-filtered) NMDA `<get-data>` on `ds:operational` returns
  empty `interfaces` / `interfaces-state`. Interface config and state
  come from a namespaced plain `<get>`.
- **Hostname is missing from a filtered operational `<system>`.** A
  subtree filter of `ietf-system` (even with an explicit `<hostname/>`
  leaf) omits hostname on this beta. An unfiltered `ds:operational`
  `<get-data>` includes `/ietf-system:system/hostname`. The facts
  getter uses that unfiltered fallback when a plain `<get>` has no
  hostname. Do not print the value in reports.
- **Config is not HiOS running-config.** running, candidate and
  intended are a 4 KiB IETF slice: interface config plus system
  contact/location/timezone. No users, VLANs, SNMP, or NTP.
- **Filters must be namespaced.** Bare (un-namespaced) subtree
  filters do not select IETF data on this server.

## Selector

Default `protocol_preference` is `['mops', 'snmp', 'ssh', 'netconf']`.
The driver stops at the first protocol that connects.

- On a healthy device, MOPS (or SNMP, or SSH) succeeds and **port 830
  is never opened**. Adding NETCONF last does not slow or break
  existing flows.
- NETCONF is only tried if MOPS, SNMP, and SSH all fail (or if the
  caller puts it earlier). That last-resort attempt can add a delay
  when port 830 accepts SSH and then rejects the `netconf` subsystem.
- To actually use NETCONF, put it first or only:

  ```python
  device = driver(
      hostname,
      username,
      password,
      optional_args={
          'protocol_preference': ['netconf'],
          'netconf_port': 830,  # default
      },
  )
  ```

`netconf_port` is unchanged (default 830). Unsupported getters still
raise `NotImplementedError` when `active_protocol == 'netconf'`; the
driver does not silently fall back to SSH for those methods.

## Adding vendor YANG mappings later

The client is built around a data-driven profile table in
`napalm_hios/netconf_hios.py`:

- `NETCONF_PROFILES` — one entry per server flavour. The only entry
  today is `ietf-only`.
- Each profile has `advertised_modules` (capability / module URN
  substrings), `supported_getters`, a `paths` mapping (getter → field
  → YANG XPath), and an optional `parser_hooks` dict.
- `select_netconf_profile(server_capabilities)` returns the first
  non-default profile whose `advertised_modules` appear in the hello;
  otherwise `ietf-only`.

When a vendor model is published:

1. Add a new profile, for example `hios-vendor`, with the real module
   URNs from the hello (do not invent URNs ahead of time).
2. Copy `PATHS_IETF_ONLY` and replace or extend field XPaths for
   facts, interfaces, counters, config, and SNMP with the vendor
   paths. Leave IETF paths in place for leaves the vendor model still
   does not provide.
3. If a getter needs a different structure (for example a VLAN list),
   add a parser hook and implement a dedicated parser; do not fold a
   half-mapping into `ietf-only`.
4. Promote a getter from `NotImplementedError` to the driver dispatch
   list only when the new paths have fixtures and tests.
5. Keep inventing nothing: empty string / empty list / `0` for
   unknown, never a guessed serial, model, or HiOS version.

Unit tests in `tests/unit/test_netconf_hios.py` cover profile
selection (including a temporary vendor profile) and parse sanitized
fixtures under `tests/fixtures/netconf/`. Those fixtures are
placeholder-valued and contain no lab identity.
