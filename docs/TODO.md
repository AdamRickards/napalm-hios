# napalm-hios v2.0 TODO

> This package is a NAPALM adapter for crude-engine. It reshapes canonical
> engine output into NAPALM-compliant shapes. Vendor-specific methods pass
> through unchanged.

## Release Checklist

- [x] napalm_compat reshaping infrastructure
- [x] Per-method reshapers (6 methods reshaped)
- [x] Verify all 18 NAPALM standard getters produce NAPALM-compliant output
- [x] Verify `napalm_compat=False` returns canonical output
- [x] NAPALM type compliance check (all 18 getters: keys present, types correct)
- [x] Inapplicable methods fall through to base class `NotImplementedError`
- [x] LICENSE, .gitignore, CONTRIBUTING.md, AUTHORS
- [x] Tests: 28 offline reshaper tests + 18 live compliance tests
- [x] NAPALM entry point verification (non-editable `pip install`)
- [ ] PyPI publish (blocked on crude-engine GitHub/PyPI setup)

---

## Reshaping Infrastructure — DONE

Each NAPALM getter that needs reshaping has a `_shape_get_<method>` static method
defined directly above it. Pattern:

```python
@staticmethod
def _shape_get_interfaces(data):
    return {port: {
        'is_up': row.get('oper_status') == 'up',
        ...
    } for port, row in data.items()}

def get_interfaces(self, napalm_compat=True, **kw):
    result = self._call('get_interfaces', **kw)
    return self._shape_get_interfaces(result) if napalm_compat else result
```

`napalm_compat=True` (default): NAPALM-shaped output.
`napalm_compat=False`: canonical engine output, no reshaping.

---

## Per-Method Reshapers — ALL DONE

### 1. get_interfaces — DONE
`oper_status`→`is_up` (bool), `admin_status`→`is_enabled` (bool), `alias`→`description`, `phys_address`→`mac_address`, adds `last_flapped: -1.0`

### 2. get_lldp_neighbors — DONE
`sys_name`→`hostname`, `port_id`→`port`

### 3. get_lldp_neighbors_detail — DONE
`sys_name`→`remote_hostname`, `port_id`→`remote_port`, `chassis_id`→`remote_chassis_id`, etc.

### 4. get_mac_address_table — DONE
`status` decomposed to `active`/`static` bools, adds `moves: 0`, `last_move: -1.0`

### 5. get_optics — DONE
Flat `tx_power`/`rx_power` nested into `physical_channels.channel[].state`, zero-value ports filtered

### 6. get_interfaces_ip — DONE
Passthrough reshaper (structure already handled by engine)

---

## Methods That Need No Reshaping

Canonical keys match NAPALM — no reshaper needed:

`get_facts`, `get_interfaces_counters`, `get_arp_table`, `get_ntp_servers`, `get_ntp_stats`, `get_users`, `get_snmp_information`, `get_config`, `get_environment`, `get_vlans`, `get_route_to`, `get_ipv6_neighbors_table`

---

## Testing — DONE

- [x] All 18 NAPALM getters: keys present, types correct (bool/str/int/float/list/dict)
- [x] `napalm_compat=True`: NAPALM-shaped output verified
- [x] `napalm_compat=False`: canonical engine output verified
- [x] 78/78 getter audit on live device (MOPS protocol)
- [x] Inapplicable methods (BGP, firewall, etc.): `NotImplementedError` from base class

---

## Remaining

- [ ] PyPI publish (blocked on crude-engine GitHub/PyPI setup)
- [ ] Tools: verify all tools work with crude-engine imports (AARON, JUSTIN, MOHAWC, STONE, CLAMPS, MARCO, SNOOP)
- [ ] Verify `set_interface` fields scope works through reshaper (admin_status/alias/mtu only)
- [ ] Verify mrp_sub_ring global+instances shape works for CLAMPS tool
