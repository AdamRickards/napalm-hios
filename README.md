# napalm-hios

**This is the `v2` branch.** Thin NAPALM shim over [crude-engine](https://github.com/AdamRickards/crude-engine). It is not a GitHub Release and is not on PyPI. `main` stays at 1.17 (`v1.17.0`).

## Installation

Do not `pip install napalm-hios` from PyPI while working from this branch. That is 1.17 and will shadow the shim.

```bash
pip install -e /path/to/crude-engine
pip install napalm
pip install -e . --no-deps
```

`--no-deps` is required because `setup.py` asks for `crude-engine>=2.9.0`, which is not on PyPI yet. Install the engine from source first.

## Usage

```python
from napalm import get_network_driver

driver = get_network_driver("hios")
device = driver("192.168.1.4", "admin", "private")
device.open()

# NAPALM standard — reshaped to NAPALM spec
facts = device.get_facts()
interfaces = device.get_interfaces()      # keys: is_up, is_enabled, etc.

# Vendor-specific — canonical engine output, no reshaping
dns = device.get_dns()
device.set_dns(enabled=True, domain_name="example.com")
mrp = device.get_mrp()

# Bypass NAPALM reshaping — get canonical output directly
interfaces = device.get_interfaces(napalm_compat=False)  # keys: oper_status, admin_status, etc.

device.close()
```

## How It Works

```
User calls device.get_interfaces()
  → hios.py routes to crude-engine
    → engine returns canonical output:
        {"1/1": {"oper_status": "up", "admin_status": "enabled", "alias": "", ...}}
  → hios.py reshapes for NAPALM (napalm_compat=True):
        {"1/1": {"is_up": True, "is_enabled": True, "description": "", "last_flapped": -1.0, ...}}
  → returns to caller
```

For the 60 vendor-specific methods, no reshaping occurs — canonical output IS the output. The `napalm_compat` flag only affects the 18 NAPALM standard getters, and only those that need reshaping (most are already canonical).

## Method Coverage

### NAPALM Standard (18 getters)

All 18 NAPALM standard getters are supported. Methods that need reshaping are marked:

| Method | Reshaping | Notes |
|--------|-----------|-------|
| `get_facts()` | None | Canonical keys match NAPALM |
| `get_interfaces()` | Key rename + type | `oper_status`→`is_up`, `admin_status`→`is_enabled`, etc. |
| `get_interfaces_ip()` | Structure | Flat → nested `{iface: {ipv4: {ip: {prefix_length}}}}` |
| `get_interfaces_counters()` | None | Canonical keys match NAPALM |
| `get_lldp_neighbors()` | Key rename | `sys_name`→`hostname`, `port_id`→`port` |
| `get_lldp_neighbors_detail()` | Key rename | `sys_name`→`remote_hostname`, etc. |
| `get_mac_address_table()` | Decompose | `status` → `active`/`static` bools + placeholders |
| `get_arp_table()` | None | Canonical keys match NAPALM |
| `get_ntp_servers()` | None | Canonical keys match NAPALM |
| `get_ntp_stats()` | None | Canonical keys match NAPALM |
| `get_users()` | None | Canonical keys match NAPALM |
| `get_snmp_information()` | None | Canonical keys match NAPALM |
| `get_optics()` | Structure | Flat → nested `physical_channels` structure |
| `get_config()` | None | Canonical keys match NAPALM |
| `get_environment()` | None | Canonical keys match NAPALM |
| `get_vlans()` | None | Canonical `ports` U/T/F dict matches NAPALM |
| `get_route_to()` | None | Canonical keys match NAPALM |
| `get_ipv6_neighbors_table()` | None | Canonical keys match NAPALM |

### Inapplicable NAPALM Methods (return `{}`)

These NAPALM methods are confirmed inapplicable to HiOS — industrial L2/L3 switches don't run BGP, firewalls, etc.:

`get_bgp_config`, `get_bgp_neighbors`, `get_bgp_neighbors_detail`, `get_firewall_policies`, `get_network_instances`, `get_ntp_peers`, `get_probes_config`, `get_probes_results`

### Vendor-Specific Methods (166)

60 read, 64 update, 16 create, 16 delete, 10 execute — all available via dynamic dispatch. No explicit Python definition needed.

```python
device.get_capabilities()    # discover all available methods
```

For the full method list see crude-engine's [METHOD_REFERENCE.md](https://github.com/AdamRickards/crude-engine/blob/main/docs/METHOD_REFERENCE.md). For per-attribute wire sources see [API_REFERENCE.md](https://github.com/AdamRickards/crude-engine/blob/main/docs/API_REFERENCE.md).

## Protocol Support

Inherited from crude-engine. Default order: MOPS > SNMP > SSH.

```python
# Force a specific protocol
device = driver("192.168.1.4", "admin", "private",
                optional_args={"protocol": "snmp"})

# Offline mode (config XML file as device)
device = driver("config.xml", "", "")
```

## License

Apache License 2.0
