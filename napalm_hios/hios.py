"""
hios.py — NAPALM adapter for Hirschmann HiOS.

Layer: Adapter. Thin shim between NAPALM interface and the engine.
Owns: method names, output shaping, connection management, execute dispatch.
Cannot: know about OIDs, MIB names, wire encoding, or protocol details.
Replace NAPALM? Replace this file. Everything else stays.
"""

import re
import logging
import asyncio
from typing import Dict, List, Any, Optional

from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ConnectionException

from crude_engine.engine.interpreter import FeatureEngine
from crude_engine.engine.crude import resolve as transform_resolve
from crude_engine.transport_registry import (
    get_transport_class as _get_transport_class,
    get_engine_protocol as _get_engine_protocol,
    get_connect_port as _get_connect_port,
    PROTOCOLS as _PROTOCOLS,
    DEFAULT_PREFERENCE as _DEFAULT_PREFERENCE,
)
import ipaddress

logger = logging.getLogger(__name__)


class HIOSDriver(NetworkDriver):
    """NAPALM driver for Hirschmann HiOS (v2.0 YAML-driven)."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.optional_args = optional_args or {}

        self.engine = FeatureEngine()

        # Transport instances — keyed by protocol name, populated by _try_connect
        self._transports = {}
        self._is_alive = False
        self.active_protocol = None
        self._merge_candidate = ''

        # Protocol selection: explicit > auto-detect > default
        protocol = self.optional_args.get('protocol')
        if protocol:
            if protocol not in _PROTOCOLS:
                raise ValueError(
                    f"Unknown protocol '{protocol}'. "
                    f"Valid: {list(_PROTOCOLS.keys())}")
            self.protocol_preference = [protocol]
        elif hostname.endswith('.xml'):
            self.protocol_preference = ['offline']
        else:
            self.protocol_preference = self.optional_args.get(
                'protocol_preference', list(_DEFAULT_PREFERENCE)
            )

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def open(self):
        if self.active_protocol:
            return
        for protocol in self.protocol_preference:
            if self._try_connect(protocol):
                self.active_protocol = protocol
                self._is_alive = True
                self.engine.build_context(
                    self._engine_protocol(), self._transport(),
                    fetch_device_info=self._fetch_device_info)
                logger.info("Connected to %s via %s", self.hostname, protocol)
                return
        raise ConnectionException(
            f"Failed to connect to {self.hostname} via {self.protocol_preference}"
        )

    def _try_connect(self, protocol):
        try:
            cls = _get_transport_class(protocol)
            port = _get_connect_port(protocol, self.optional_args)
            kwargs = {}
            if port is not None:
                kwargs['port'] = port
            transport = cls(self.hostname, self.username, self.password,
                           self.timeout, **kwargs)
            transport.open()
            self._transports[protocol] = transport
            return True
        except Exception as e:
            logger.debug("Connect via %s failed: %s", protocol, e)
        return False

    def close(self):
        for conn in self._transports.values():
            try:
                conn.close()
            except Exception:
                pass
        self._transports.clear()
        self._is_alive = False
        self.active_protocol = None

    def is_alive(self):
        return {"is_alive": self._is_alive}

    def _fetch_device_info(self):
        """Lazy device_info: called on first guard evaluation.

        Uses get_facts() through the engine (protocol-agnostic).
        Extracts guard-relevant fields:
          swlevel:   L2S, L2A, L3S, L3A (from os_version)
          swversion: 10.3.04 (from os_version)
          hwtype:    model name (from model)
          os:        hios, hisecos (from os_version prefix)
        Caches facts for reuse.
        """
        import re
        info = {}
        try:
            facts = self.get_facts()
            self._cached_facts = facts
            descr = facts.get('os_version', '')
            # Parse "HiOS-2A-10.3.04" or "HiSecOS-3S-07.2.00"
            m = re.search(r'(HiOS|HiSecOS)-(\d[A-Z])-(\S+)', descr)
            if m:
                info['os'] = m.group(1).lower()
                info['swlevel'] = f'L{m.group(2)}'
                info['swversion'] = m.group(3)
            info['hwtype'] = facts.get('model', '')
        except Exception:
            pass
        return info

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _transport(self):
        t = self._transports.get(self.active_protocol)
        if t is None:
            raise ConnectionException("No active connection")
        return t

    def _engine_protocol(self):
        """Map active protocol to engine protocol via registry."""
        return _get_engine_protocol(self.active_protocol)

    def _call(self, method, **kwargs):
        """Single entry point for all schema method calls."""
        debug = kwargs.pop('debug', False)
        if debug:
            kwargs['trace'] = True
            logging.getLogger('napalm_hios').setLevel(logging.DEBUG)
        is_setter = not method.startswith('get_')
        resolved = self.engine.resolve_intent(method, is_setter=is_setter, **kwargs)
        return self.engine.execute_resolved(
            resolved, self._engine_protocol(), self._transport())

    @property
    def last_trace(self):
        """Last pipeline trace from the engine (None if tracing was off)."""
        return self.engine.last_trace

    def __getattr__(self, method_name):
        """Dynamic method dispatch — schema methods are automatically available.

        Any get_*, set_*, create_*, delete_* method that has a schema or
        feature YAML becomes callable without explicit Python definition.
        """
        if method_name.startswith(('get_', 'set_', 'create_', 'delete_', 'activate_')):
            if self.engine.has_method(method_name):
                def dispatch(*args, **kwargs):
                    if args:
                        kwargs['index'] = args[0]
                    return self._call(method_name, **kwargs)
                return dispatch
        raise AttributeError(
            f"'{type(self).__name__}' has no method '{method_name}'"
        )

    # ==================================================================
    # NAPALM config management — CLI text staging
    # ==================================================================

    def load_merge_candidate(self, filename=None, config=None):
        """Stage CLI commands for commit. HiOS applies immediately —
        we buffer in Python and send via SSH on commit."""
        if filename:
            with open(filename) as f:
                config = f.read()
        if config:
            self._merge_candidate += config + '\n'

    def compare_config(self):
        """Return staged CLI commands."""
        return self._merge_candidate.strip()

    def commit_config(self, message='', revert_in=None):
        """Send staged CLI commands via SSH, then save to NVM."""
        if not self._merge_candidate.strip():
            return
        # Ensure a CLI-capable transport is available
        proto, transport = self._ensure_execute_transport('cli')
        for line in self._merge_candidate.strip().splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                transport.cli(line)
        self.save_config()
        self._merge_candidate = ''

    def discard_config(self):
        """Clear staged CLI commands."""
        self._merge_candidate = ''

    def rollback(self):
        raise NotImplementedError(
            "HiOS has no non-disruptive rollback. "
            "Use activate_profile() for atomic profile switching (causes warm restart).")

    # ==================================================================
    # EXECUTE — transport-direct operations
    # ==================================================================

    def _execute_transport(self, method, **kwargs):
        """Call a method on the active transport. YAML declares, Python implements.

        The protocol YAML execute_methods list is the contract — if the method
        isn't declared there, it's not supported regardless of what the Python
        transport class has. Both must agree.
        """
        allowed = self.engine.get_execute_methods(self._engine_protocol())
        if method not in allowed:
            raise NotImplementedError(
                f"{method} not declared in {self._engine_protocol().upper()}.yaml execute_methods")
        transport = self._transport()
        fn = getattr(transport, method, None)
        if fn is None:
            raise NotImplementedError(
                f"{method} declared but not implemented on {self.active_protocol}")
        return fn(**kwargs)

    def save_config(self, dest='nvm'):
        """Save running config to NVM/ENVM."""
        return self._execute_transport('save_config', dest=dest)

    def load_config(self, xml_data, profile=None, destination='nvm'):
        """Upload config XML to device."""
        return self._execute_transport('load_config', xml_data=xml_data,
                                        profile=profile, destination=destination)

    def onboard(self, new_password):
        """Change default password on factory-fresh device."""
        return self._execute_transport('onboard', new_password=new_password)

    def is_factory_default(self):
        """Check if device is in factory-default state."""
        return self._execute_transport('is_factory_default')

    def clear_config(self, keep_ip=False):
        """Clear running config."""
        return self._execute_transport('clear_config', keep_ip=keep_ip)

    def clear_factory(self, erase_all=False):
        """Factory reset."""
        return self._execute_transport('clear_factory', erase_all=erase_all)

    def start_staging(self):
        """Begin MOPS staging transaction."""
        return self._execute_transport('start_staging')

    def commit_staging(self):
        """Commit staged MOPS mutations atomically."""
        return self._execute_transport('commit_staging')

    def discard_staging(self):
        """Discard staged MOPS mutations."""
        return self._execute_transport('discard_staging')

    def get_staged_mutations(self):
        """Return list of staged MOPS mutations."""
        return self._execute_transport('get_staged_mutations')

    # ==================================================================
    # CAPABILITIES
    # ==================================================================

    def get_capabilities(self, facts=None):
        """Return available CRUDE operations and protocol support.

        Args:
            facts: optional dict from get_facts(). If connected and not
                   provided, calls get_facts() automatically. Pass cached
                   facts to avoid device query.
        """
        device_info = {}
        if facts:
            device_info = self._parse_device_info(facts)
        elif self._is_alive:
            try:
                device_info = self._fetch_device_info()
            except Exception:
                pass

        caps = self.engine.get_capabilities(device_info=device_info or None)

        # Add transport layer info — execute_methods from protocol YAML
        active_proto = self._engine_protocol() if self._is_alive else None
        active_execute = []
        if active_proto:
            active_execute = self.engine.get_execute_methods(active_proto)

        caps["transport"] = {
            "active": self.active_protocol,
            "preference": self.protocol_preference,
            "connected": {p: p in self._transports for p in _PROTOCOLS},
            "execute_methods": active_execute,
        }

        # Transport execute methods belong in crude["execute"] too
        caps["crude"]["execute"] = active_execute
        caps["totals"]["execute"] = len(active_execute)
        caps["totals"]["total"] = sum(caps["totals"].get(k, 0) for k in ("create", "read", "upsert", "delete", "execute"))

        return caps

    def _parse_device_info(self, facts):
        """Extract guard-relevant fields from a facts dict.

        Accepts any dict. Extracts what it can, ignores what it can't.
        Vendor-specific parsing (os_version format) is best-effort.
        """
        import re
        info = {}
        try:
            descr = str(facts.get('os_version', ''))
            m = re.search(r'(\w+)-(\d[A-Z])-(\S+)', descr)
            if m:
                info['os'] = m.group(1).lower()
                info['swlevel'] = f'L{m.group(2)}'
                info['swversion'] = m.group(3)
            model = facts.get('model', '')
            if model:
                info['hwtype'] = str(model)
        except Exception:
            pass
        return info

    # ==================================================================
    # NAPALM STANDARD GETTERS
    # ==================================================================

    # ------------------------------------------------------------------
    # NAPALM base class overrides — required because NetworkDriver
    # defines stubs that raise NotImplementedError. __getattr__ can't
    # override these since Python finds the base class method first.
    #
    # Methods that need reshaping have a _shape_<method> above them.
    # napalm_compat=True (default) reshapes for NAPALM.
    # napalm_compat=False returns canonical engine output.
    # ------------------------------------------------------------------

    def get_facts(self, napalm_compat=True, **kw):
        if not kw and hasattr(self, '_cached_facts') and self._cached_facts:
            return self._cached_facts
        return self._call('get_facts', **kw)

    # -- get_interfaces: key renames + type conversion ----------------

    @staticmethod
    def _shape_get_interfaces(data):
        return {port: {
            'is_up': row.get('oper_status') == 'up',
            'is_enabled': row.get('admin_status') == 'enabled',
            'description': row.get('alias', ''),
            'last_flapped': -1.0,
            'speed': row.get('speed', 0),
            'mtu': row.get('mtu', 1500),
            'mac_address': row.get('phys_address', ''),
        } for port, row in data.items()}

    def get_interfaces(self, napalm_compat=True, **kw):
        result = self._call('get_interfaces', **kw)
        return self._shape_get_interfaces(result) if napalm_compat else result

    # -- get_interfaces_ip: flat → nested per-interface ---------------

    @staticmethod
    def _shape_get_interfaces_ip(data):
        result = {}
        for iface, info in data.items():
            ipv4 = info.get('ipv4', {})
            ipv6 = info.get('ipv6', {})
            if ipv4 or ipv6:
                result[iface] = {'ipv4': ipv4, 'ipv6': ipv6}
        return result

    def get_interfaces_ip(self, napalm_compat=True, **kw):
        result = self._call('get_interfaces_ip', **kw)
        return self._shape_get_interfaces_ip(result) if napalm_compat else result

    # -- get_interfaces_counters: strip non-NAPALM fields ---------------

    _NAPALM_COUNTER_KEYS = {
        'tx_errors', 'rx_errors', 'tx_discards', 'rx_discards',
        'tx_octets', 'rx_octets', 'tx_unicast_packets', 'rx_unicast_packets',
        'tx_multicast_packets', 'rx_multicast_packets',
        'tx_broadcast_packets', 'rx_broadcast_packets',
    }

    @classmethod
    def _shape_get_interfaces_counters(cls, data):
        return {port: {k: v for k, v in row.items() if k in cls._NAPALM_COUNTER_KEYS}
                for port, row in data.items()}

    def get_interfaces_counters(self, napalm_compat=True, **kw):
        result = self._call('get_interface_statistics', **kw)
        return self._shape_get_interfaces_counters(result) if napalm_compat else result

    # -- get_lldp_neighbors: key renames ------------------------------

    @staticmethod
    def _shape_get_lldp_neighbors(data):
        return {port: [
            {'hostname': e.get('sys_name', ''), 'port': e.get('port_id', '')}
            for e in entries
        ] for port, entries in data.items()}

    def get_lldp_neighbors(self, napalm_compat=True, **kw):
        result = self._call('get_lldp_neighbors', **kw)
        return self._shape_get_lldp_neighbors(result) if napalm_compat else result

    # -- get_lldp_neighbors_detail: key renames -----------------------

    @staticmethod
    def _shape_get_lldp_neighbors_detail(data):
        return {port: [{
            'remote_hostname': e.get('sys_name', ''),
            'remote_port': e.get('port_id', ''),
            'remote_port_description': e.get('port_description', ''),
            'remote_chassis_id': e.get('chassis_id', ''),
            'remote_system_description': e.get('sys_description', ''),
            'remote_system_capabilities': e.get('sys_capabilities', []),
            'remote_system_enabled_capabilities': e.get('sys_enabled_capabilities', []),
            'autoneg_supported': e.get('autoneg_supported', False),
            'autoneg_enabled': e.get('autoneg_enabled', False),
            'mau_type': e.get('mau_type', 0),
            'pvid': e.get('pvid', 0),
            'aggregation_enabled': e.get('aggregation_enabled', []),
            'aggregation_port_id': e.get('aggregation_port_id', 0),
        } for e in entries] for port, entries in data.items()}

    def get_lldp_neighbors_detail(self, interface="", napalm_compat=True, **kw):
        result = self._call('get_lldp_neighbors_detail', **kw)
        return self._shape_get_lldp_neighbors_detail(result) if napalm_compat else result

    # -- get_mac_address_table: status decomposition ------------------

    @staticmethod
    def _shape_get_mac_address_table(data):
        return [{
            'mac': row.get('mac', ''),
            'interface': row.get('interface', ''),
            'vlan': row.get('vlan', 0),
            'active': row.get('status') in ('learned', 'self', 'mgmt'),
            'static': row.get('status') in ('self', 'mgmt'),
            'moves': 0,
            'last_move': -1.0,
        } for row in data]

    def get_mac_address_table(self, napalm_compat=True, **kw):
        result = self._call('get_mac_address_table', **kw)
        return self._shape_get_mac_address_table(result) if napalm_compat else result

    def get_arp_table(self, vrf='', napalm_compat=True, **kw):
        return self._call('get_arp_table', **kw)

    def get_ntp_servers(self, napalm_compat=True, **kw):
        return self._call('get_ntp_servers', **kw)

    def get_ntp_stats(self, napalm_compat=True, **kw):
        return self._call('get_ntp_stats', **kw)

    def get_users(self, napalm_compat=True, **kw):
        return self._call('get_users', **kw)

    def get_snmp_information(self, napalm_compat=True, **kw):
        return self._call('get_snmp_information', **kw)

    # -- get_optics: flat → nested physical_channels ------------------

    @staticmethod
    def _shape_get_optics(data):
        _zero = {'instant': 0.0, 'avg': 0.0, 'min': 0.0, 'max': 0.0}
        result = {}
        for port, row in data.items():
            tx = row.get('tx_power', 0.0)
            rx = row.get('rx_power', 0.0)
            if not tx and not rx:
                continue
            try:
                tx = float(tx)
            except (ValueError, TypeError):
                tx = 0.0
            try:
                rx = float(rx)
            except (ValueError, TypeError):
                rx = 0.0
            result[port] = {
                'physical_channels': {
                    'channel': [{
                        'index': 0,
                        'state': {
                            'input_power': {**_zero, 'instant': rx},
                            'output_power': {**_zero, 'instant': tx},
                            'laser_bias_current': dict(_zero),
                        },
                    }],
                },
            }
        return result

    def get_optics(self, napalm_compat=True, **kw):
        result = self._call('get_optics', **kw)
        return self._shape_get_optics(result) if napalm_compat else result

    def get_config(self, retrieve='all', full=False, sanitized=False, napalm_compat=True, **kw):
        return self._call('get_config', **kw)

    def get_environment(self, napalm_compat=True, **kw):
        return self._call('get_environment', **kw)

    def get_vlans(self, napalm_compat=True, **kw):
        return self._call('get_vlans', **kw)

    def get_route_to(self, destination='', protocol='', longer=False, napalm_compat=True, **kw):
        return self._call('get_route_to', **kw)

    def get_ipv6_neighbors_table(self, napalm_compat=True, **kw):
        return self._call('get_ipv6_neighbors_table', **kw)

    # ==================================================================
    # NAPALM UTILITY METHODS (SSH-only, engine dispatch)
    # ==================================================================

    def _ensure_execute_transport(self, method):
        """Ensure a transport supporting the execute method is available.

        Checks connected transports first, then tries connecting protocols
        that declare the method in their execute_methods.
        """
        # Already have a connected transport that supports this method?
        for proto, transport in self._transports.items():
            engine_proto = _get_engine_protocol(proto)
            if method in self.engine.get_execute_methods(engine_proto):
                return proto, transport

        # Try connecting protocols that might support it
        for proto in _PROTOCOLS:
            if proto in self._transports:
                continue
            if self._try_connect(proto):
                engine_proto = _get_engine_protocol(proto)
                if method in self.engine.get_execute_methods(engine_proto):
                    return proto, self._transports[proto]

        raise NotImplementedError(
            f"No protocol supports execute method '{method}' "
            f"(active protocol: {self.active_protocol})"
        )

    def cli(self, commands=None, encoding='text'):
        """Execute CLI commands on the device. Returns {command: output}."""
        proto, transport = self._ensure_execute_transport('cli')
        result = self.engine.execute(
            'cli', _get_engine_protocol(proto), transport,
            commands=commands or []
        )
        return result.get('outputs', result)

    def ping(self, destination, source='', ttl=0, timeout=0, size=0,
             count=5, vrf='', source_interface=''):
        """Execute ping from the device. Returns NAPALM-compliant dict."""
        proto, transport = self._ensure_execute_transport('ping')
        raw = self.engine.execute(
            'ping', _get_engine_protocol(proto), transport,
            destination=destination, count=count
        )
        return self._parse_ping(raw.get('raw_output', ''))

    def traceroute(self, destination, source='', ttl=0, timeout=0, vrf=''):
        """Execute traceroute from the device. Returns NAPALM-compliant dict."""
        proto, transport = self._ensure_execute_transport('traceroute')
        raw = self.engine.execute(
            'traceroute', _get_engine_protocol(proto), transport,
            destination=destination
        )
        return self._parse_traceroute(raw.get('raw_output', ''))

    # ------------------------------------------------------------------
    # Output parsers for execute methods
    # ------------------------------------------------------------------
    # These parse CLI text into NAPALM-compliant nested dicts.
    # They live in hios.py (not engine) because the output shapes are
    # NAPALM-specific and don't generalize to other engine consumers.
    # ENGINE MIGRATION PATH: if a future `parser:` tag on execute sources
    # can declare output shaping in YAML, move these there. The raw output
    # is already captured by the engine — only the shaping step would move.
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ping(raw: str) -> dict:
        """Parse HiOS ping output into NAPALM format.

        HiOS (BusyBox) format:
            64 bytes from 1.2.3.4: seq=0 ttl=64 time=3.672 ms
            ...
            round-trip min/avg/max = 3.372/5.218/8.474 ms
        """
        if not raw:
            return {'error': 'Ping returned no output'}

        results = []
        for m in re.finditer(
            r'(\d+) bytes from ([\d.]+): seq=\d+ ttl=(\d+) time=([\d.]+)', raw
        ):
            results.append({
                'ip_address': m.group(2),
                'rtt': float(m.group(4)),
            })

        # Summary line
        rtt_min = rtt_avg = rtt_max = 0.0
        m_rtt = re.search(r'min/avg/max = ([\d.]+)/([\d.]+)/([\d.]+)', raw)
        if m_rtt:
            rtt_min, rtt_avg, rtt_max = (
                float(m_rtt.group(1)), float(m_rtt.group(2)), float(m_rtt.group(3))
            )

        m_loss = re.search(r'(\d+) packets transmitted, (\d+) packets received', raw)
        probes_sent = int(m_loss.group(1)) if m_loss else len(results)
        probes_received = int(m_loss.group(2)) if m_loss else len(results)
        packet_loss = probes_sent - probes_received

        return {
            'success': {
                'probes_sent': probes_sent,
                'packet_loss': packet_loss,
                'rtt_min': rtt_min,
                'rtt_avg': rtt_avg,
                'rtt_max': rtt_max,
                'results': results,
            }
        }

    @staticmethod
    def _parse_traceroute(raw: str) -> dict:
        """Parse HiOS traceroute output into NAPALM format.

        HiOS (BusyBox) format:
            1  192.168.60.81  4.918 ms  2.394 ms  2.946 ms
            2  10.0.0.1  1.234 ms  *  2.345 ms
            3  * * *
        """
        if not raw:
            return {'error': 'Traceroute returned no output'}

        hops = {}
        for line in raw.splitlines():
            m = re.match(r'\s*(\d+)\s+(.+)', line)
            if not m:
                continue
            hop_num = int(m.group(1))
            rest = m.group(2).strip()

            # Parse probes: alternating IP/hostname and rtt values
            # Format: "IP  rtt ms  rtt ms  rtt ms" or "* * *"
            probes = {}
            probe_idx = 1
            current_ip = '*'
            tokens = rest.split()
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token == '*':
                    probes[probe_idx] = {
                        'host_name': '*', 'ip_address': '*', 'rtt': -1.0
                    }
                    probe_idx += 1
                    i += 1
                elif token == 'ms':
                    i += 1
                elif re.match(r'[\d.]+$', token) and i + 1 < len(tokens) and tokens[i + 1] == 'ms':
                    # This is an RTT value
                    probes[probe_idx] = {
                        'host_name': current_ip,
                        'ip_address': current_ip,
                        'rtt': float(token),
                    }
                    probe_idx += 1
                    i += 2  # skip value + 'ms'
                else:
                    # IP address or hostname
                    current_ip = token
                    i += 1

            if probes:
                hops[hop_num] = {'probes': probes}

        if not hops:
            return {'error': 'Could not parse traceroute output'}

        return {'success': hops}

    # ------------------------------------------------------------------
    # NAPALM standard methods not applicable to HiOS (BGP, firewalls, probes)
    # are NOT overridden — base class raises NotImplementedError per NAPALM spec.

    # All setters, CRUD operations, and vendor-specific methods are
    # handled by __getattr__ dynamic dispatch. No explicit definitions
    # needed — if a schema or feature YAML exists, it works.
