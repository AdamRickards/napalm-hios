"""NETCONF transport for HiOS.

The 10.7.00 BETA83 BRS image exposes a stock YumaWorks NETCONF server
with IETF and Yuma models only — no Hirschmann / Belden vendor YANG.
This client maps only what those IETF models actually return. NAPALM
getters with no honest mapping are left unimplemented so HIOSDriver
raises NotImplementedError and the protocol selector can fall through.

When vendor models ship, add a profile to ``NETCONF_PROFILES`` (see
docs/netconf.md) rather than hard-coding new paths in the getters.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Union

from lxml import etree
from ncclient import manager
from napalm.base.exceptions import ConnectionException

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------

NC_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
IF_NS = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
SYS_NS = "urn:ietf:params:xml:ns:yang:ietf-system"
NMDA_NS = "urn:ietf:params:xml:ns:yang:ietf-netconf-nmda"
DS_NS = "urn:ietf:params:xml:ns:yang:ietf-datastores"

NSMAP = {
    "nc": NC_NS,
    "if": IF_NS,
    "sys": SYS_NS,
    "nmda": NMDA_NS,
    "ds": DS_NS,
}

# Vendor string matches SSH / SNMP / the previous NETCONF stub in this repo.
VENDOR = "Belden"

# IETF speed leaf is already bits/s. Missing or unparsable -> 0, same as SSH.
# IETF does not expose MTU on this beta; SSH (and the previous stub) use 1500
# when the device does not report one.
DEFAULT_SPEED = 0
DEFAULT_MTU = 1500
DEFAULT_LAST_FLAPPED = -1.0

# ---------------------------------------------------------------------------
# Data-driven mapping table
#
# Each profile names the YANG modules that select it and the field paths
# used by the IETF parsers. A future vendor profile adds its advertised
# module URNs plus replacement/additional paths (or a dedicated parser
# hook). ``select_netconf_profile`` picks the first non-default profile
# whose advertised modules appear in the server hello; otherwise ietf-only.
# ---------------------------------------------------------------------------

PATHS_IETF_ONLY = {
    "get_facts": {
        "hostname": "sys:system/sys:hostname",
        "vendor": None,  # constant VENDOR; not from YANG
        "model": None,  # unknown on this beta — empty string, never invented
        "serial_number": None,
        "os_version": None,  # platform/os-version is the kernel, not HiOS
        "contact": "sys:system/sys:contact",
        "location": "sys:system/sys:location",
        "current_datetime": "sys:system-state/sys:clock/sys:current-datetime",
        "boot_datetime": "sys:system-state/sys:clock/sys:boot-datetime",
        "interface_list": "if:interfaces/if:interface/if:name",
        # Fallback when hostname is absent from a plain <get> of ietf-system
        "hostname_operational": "sys:system/sys:hostname",
    },
    "get_interfaces": {
        "list": "if:interfaces-state/if:interface",
        # Some servers also copy state under if:interfaces; parsers try both.
        "list_config": "if:interfaces/if:interface",
        "name": "if:name",
        "description": "if:description",
        "admin_enabled": "if:enabled",  # config leaf; is_enabled
        "admin_status": "if:admin-status",  # state leaf; up/down
        "oper_status": "if:oper-status",  # is_up when "up"
        "speed": "if:speed",  # bits/s
        "mtu": "if:mtu",
        "mac_address": "if:phys-address",
    },
    "get_interfaces_counters": {
        "list": "if:interfaces-state/if:interface",
        "list_config": "if:interfaces/if:interface",
        "name": "if:name",
        "statistics": "if:statistics",
        "tx_octets": "if:out-octets",
        "rx_octets": "if:in-octets",
        "tx_unicast_packets": "if:out-unicast-pkts",
        "rx_unicast_packets": "if:in-unicast-pkts",
        "tx_broadcast_packets": "if:out-broadcast-pkts",
        "rx_broadcast_packets": "if:in-broadcast-pkts",
        "tx_multicast_packets": "if:out-multicast-pkts",
        "rx_multicast_packets": "if:in-multicast-pkts",
        "tx_discards": "if:out-discards",
        "rx_discards": "if:in-discards",
        "tx_errors": "if:out-errors",
        "rx_errors": "if:in-errors",
    },
    "get_snmp_information": {
        # No SNMP YANG on this beta. Honest slice from ietf-system only.
        "contact": "sys:system/sys:contact",
        "location": "sys:system/sys:location",
        "chassis_id": None,
        "community": None,
    },
    "get_config": {
        "running": "running",
        "candidate": "candidate",
        "startup": None,  # not advertised; always empty
    },
}

NETCONF_PROFILES = {
    "ietf-only": {
        "advertised_modules": (
            "urn:ietf:params:xml:ns:yang:ietf-interfaces",
            "urn:ietf:params:xml:ns:yang:ietf-system",
        ),
        "supported_getters": (
            "get_facts",
            "get_interfaces",
            "get_interfaces_counters",
            "get_config",
            "get_snmp_information",
        ),
        "paths": PATHS_IETF_ONLY,
        # Reserved for a future vendor profile: a callable or module
        # path that replaces a getter parser. Unused on ietf-only.
        "parser_hooks": {},
    },
}


def select_netconf_profile(capabilities: Optional[Iterable[Any]] = None) -> str:
    """Choose a mapping profile from the server hello / capability URNs.

    Vendor profiles (any profile other than ``ietf-only``) win when one
    of their ``advertised_modules`` substrings appears in a capability.
    The 10.7 beta has no vendor modules, so this returns ``ietf-only``.
    """
    caps = [str(c) for c in (capabilities or [])]
    blob = " ".join(caps)
    for name, profile in NETCONF_PROFILES.items():
        if name == "ietf-only":
            continue
        for module in profile.get("advertised_modules") or ():
            if module and module in blob:
                return name
    return "ietf-only"


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _as_element(reply: Any) -> etree._Element:
    """Return the <data> element (or the root) from an ncclient reply."""
    if reply is None:
        return etree.Element("data")
    if hasattr(reply, "data_ele") and reply.data_ele is not None:
        return reply.data_ele
    xml = reply.xml if hasattr(reply, "xml") else reply
    if isinstance(xml, etree._Element):
        root = xml
    elif isinstance(xml, bytes):
        root = etree.fromstring(xml)
    elif isinstance(xml, str):
        root = etree.fromstring(xml.encode("utf-8"))
    else:
        raise TypeError("Unsupported NETCONF reply type: %s" % type(reply))
    data = root.find(".//{%s}data" % NC_NS)
    if data is None and root.tag != "{%s}data" % NC_NS:
        # Some replies use an un-namespaced <data>
        data = root.find(".//data")
    return data if data is not None else root


def _text(node: Optional[etree._Element], default: str = "") -> str:
    if node is None or node.text is None:
        return default
    return node.text.strip()


def _xpath_text(elem: etree._Element, xpath: Optional[str], default: str = "") -> str:
    if not xpath or elem is None:
        return default
    found = elem.xpath(xpath, namespaces=NSMAP)
    if not found:
        return default
    first = found[0]
    if isinstance(first, str):
        return first.strip() or default
    return _text(first, default)


def _xpath_nodes(elem: etree._Element, xpath: str) -> List[etree._Element]:
    if elem is None or not xpath:
        return []
    found = elem.xpath(xpath, namespaces=NSMAP)
    return [n for n in found if isinstance(n, etree._Element)]


def _child(elem: etree._Element, ns: str, local: str) -> Optional[etree._Element]:
    if elem is None:
        return None
    return elem.find("{%s}%s" % (ns, local))


def _child_text(elem: etree._Element, ns: str, local: str, default: str = "") -> str:
    return _text(_child(elem, ns, local), default)


def _format_mac(raw: str) -> str:
    if not raw:
        return ""
    s = raw.strip().lower().replace("-", ":")
    if ":" in s:
        parts = [p.zfill(2) for p in s.split(":") if p != ""]
        return ":".join(parts)
    hexonly = re.sub(r"[^0-9a-f]", "", s)
    if len(hexonly) == 12:
        return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))
    return s


def _parse_uint(raw: str, default: int = 0) -> int:
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _parse_enabled(raw: str) -> bool:
    return raw.strip().lower() in ("true", "1", "yes", "enabled")


def _parse_yang_datetime(value: str) -> Optional[datetime]:
    """Parse a YANG date-and-time value.

    The 10.7 beta appends ``Z`` to timestamps the CLI treats as local
    time (timezone-utc-offset is not UTC). The interval between two
    such stamps is still valid if both are parsed as naive datetimes
    with the suffix stripped — do not convert via UTC.
    """
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1]
    # Fractional seconds, optional
    # Strip a trailing numeric offset only (not the date hyphens).
    text = re.sub(r"[+-]\d{2}:\d{2}$", "", text)
    text = re.sub(r"[+-]\d{4}$", "", text)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def uptime_seconds(current_datetime: str, boot_datetime: str) -> int:
    """Return current − boot in seconds, ignoring a bogus Z suffix."""
    current = _parse_yang_datetime(current_datetime)
    boot = _parse_yang_datetime(boot_datetime)
    if current is None or boot is None:
        return 0
    delta = (current - boot).total_seconds()
    if delta < 0:
        return 0
    return int(delta)


def _elem(ns: str, local: str) -> etree._Element:
    return etree.Element("{%s}%s" % (ns, local), nsmap={None: ns})


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class NetconfHIOS:
    """Read-only NETCONF client for HiOS (IETF models on the 10.7 beta)."""

    def __init__(self, hostname, username, password, timeout=60, port=830, **kwargs):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.connection = None
        self.profile = "ietf-only"
        self.paths = NETCONF_PROFILES[self.profile]["paths"]
        self.server_capabilities = []

    # -- session -------------------------------------------------------------

    def open(self):
        try:
            self.connection = manager.connect(
                host=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                hostkey_verify=False,
                device_params={"name": "default"},
                allow_agent=False,
                look_for_keys=False,
                timeout=self.timeout,
            )
        except Exception as e:
            logger.error("Cannot connect to device using NETCONF: %s", type(e).__name__)
            raise ConnectionException(
                "Cannot connect to %s using NETCONF" % self.hostname
            )
        caps = []
        try:
            caps = list(self.connection.server_capabilities or [])
        except Exception:
            caps = []
        self.server_capabilities = caps
        self.profile = select_netconf_profile(caps)
        self.paths = NETCONF_PROFILES[self.profile]["paths"]
        logger.debug("NETCONF profile selected: %s", self.profile)

    def close(self):
        if self.connection is not None:
            try:
                self.connection.close_session()
            except Exception:
                logger.debug("NETCONF close_session failed", exc_info=True)
            finally:
                self.connection = None

    def _require_connection(self):
        if self.connection is None:
            raise ConnectionException("Not connected to device using NETCONF")

    def _rpc_get(self, *containers: etree._Element) -> etree._Element:
        """Namespaced subtree <get>. One RPC per call; multiple containers
        are requested sequentially and merged under a synthetic <data>."""
        self._require_connection()
        if not containers:
            reply = self.connection.get()
            return _as_element(reply)
        chunks: List[etree._Element] = []
        for container in containers:
            filt = ("subtree", etree.tostring(container, encoding="unicode"))
            reply = self.connection.get(filter=filt)
            chunks.append(_as_element(reply))
        if len(chunks) == 1:
            return chunks[0]
        merged = etree.Element("{%s}data" % NC_NS)
        for chunk in chunks:
            for child in list(chunk):
                # Copy, do not move: a cached/shared reply tree must stay intact.
                merged.append(etree.fromstring(etree.tostring(child)))
        return merged

    def _rpc_get_config(self, source: str) -> etree._Element:
        self._require_connection()
        reply = self.connection.get_config(source=source)
        return _as_element(reply)

    def _rpc_get_data(self, datastore: str, container: etree._Element) -> etree._Element:
        """NMDA <get-data> (read-only). ``datastore`` is e.g. 'operational'."""
        self._require_connection()
        rpc = etree.Element("{%s}get-data" % NMDA_NS, nsmap={None: NMDA_NS, "ds": DS_NS})
        ds = etree.SubElement(rpc, "{%s}datastore" % NMDA_NS)
        ds.text = "ds:%s" % datastore
        filt = etree.SubElement(rpc, "{%s}subtree-filter" % NMDA_NS)
        filt.append(container)
        reply = self.connection.dispatch(rpc)
        return _as_element(reply)

    # -- getters -------------------------------------------------------------

    def get_facts(self) -> Dict[str, Any]:
        """Partial facts from ietf-system + interface names.

        Hostname is taken from a plain <get> of ietf-system when present,
        otherwise from NMDA ds:operational (the 10.7 beta keeps hostname
        there). model, serial_number and os_version stay empty — the
        platform leaf is the Linux kernel, not a HiOS version, and no
        serial/order-code model exists on this server.
        """
        paths = self.paths["get_facts"]
        system = self._rpc_get(_elem(SYS_NS, "system"), _elem(SYS_NS, "system-state"))
        hostname = _xpath_text(system, paths["hostname"])
        if not hostname:
            try:
                operational = self._rpc_get_data("operational", _elem(SYS_NS, "system"))
                hostname = _xpath_text(operational, paths["hostname_operational"])
            except Exception:
                logger.debug(
                    "NETCONF operational hostname fallback failed", exc_info=True
                )
                hostname = ""

        try:
            if_data = self._rpc_get(_elem(IF_NS, "interfaces"), _elem(IF_NS, "interfaces-state"))
        except Exception:
            logger.debug("NETCONF interface list fetch failed", exc_info=True)
            if_data = etree.Element("data")

        interface_list = self._interface_names(if_data)
        uptime = uptime_seconds(
            _xpath_text(system, paths["current_datetime"]),
            _xpath_text(system, paths["boot_datetime"]),
        )
        return {
            "uptime": uptime,
            "vendor": VENDOR,
            "os_version": "",
            "serial_number": "",
            "model": "",
            "hostname": hostname,
            "fqdn": hostname,
            "interface_list": interface_list,
        }

    def get_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Interface table from ietf-interfaces.

        is_enabled comes from the admin ``enabled`` / ``admin-status``
        leaf (not oper-status). is_up comes from oper-status == 'up'.
        Missing speed -> 0; missing mtu -> 1500; empty description -> "";
        last_flapped is unknown (-1.0). Speed is bits/s (IETF leaf).
        """
        data = self._rpc_get(_elem(IF_NS, "interfaces"), _elem(IF_NS, "interfaces-state"))
        return self._parse_interfaces(data)

    def get_interfaces_counters(self) -> Dict[str, Dict[str, int]]:
        data = self._rpc_get(_elem(IF_NS, "interfaces"), _elem(IF_NS, "interfaces-state"))
        return self._parse_counters(data)

    def get_config(self, retrieve="all", full=False, sanitized=False, format=None, **kwargs):
        """Return IETF running/candidate XML. startup is always empty.

        The 10.7 beta has no startup datastore and no vendor config
        model — the payload is the IETF interface + system slice, not
        a HiOS running-config. ``full`` and ``sanitized`` have no
        effect (the IETF slice has no secrets to strip).
        """
        valid = ("all", "running", "candidate", "startup")
        if retrieve not in valid:
            raise ValueError("Invalid retrieve value. Must be one of: %s" % ", ".join(valid))
        config = {"running": "", "startup": "", "candidate": ""}
        if retrieve in ("all", "running"):
            config["running"] = self._serialize_config(self._rpc_get_config("running"))
        if retrieve in ("all", "candidate"):
            try:
                config["candidate"] = self._serialize_config(
                    self._rpc_get_config("candidate")
                )
            except Exception:
                logger.debug("NETCONF get-config candidate failed", exc_info=True)
                config["candidate"] = ""
        # startup: not advertised
        return config

    def get_snmp_information(self) -> Dict[str, Any]:
        """Partial SNMP info: contact and location from ietf-system.

        chassis_id is empty and community is {} — there is no SNMP YANG
        on this beta, so those fields are not invented.
        """
        paths = self.paths["get_snmp_information"]
        system = self._rpc_get(_elem(SYS_NS, "system"))
        return {
            "chassis_id": "",
            "community": {},
            "contact": _xpath_text(system, paths["contact"]),
            "location": _xpath_text(system, paths["location"]),
        }

    # -- parsers (also used by unit tests on fixtures) ----------------------

    def _interface_names(self, data: etree._Element) -> List[str]:
        names = []
        seen = set()
        for xpath in (
            "if:interfaces-state/if:interface/if:name",
            "if:interfaces/if:interface/if:name",
        ):
            for node in data.xpath(xpath, namespaces=NSMAP):
                name = node if isinstance(node, str) else _text(node)
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
        return names

    def _iter_interfaces(self, data: etree._Element):
        """Yield (name, state_el_or_None, config_el_or_None) per interface."""
        state_map: Dict[str, etree._Element] = {}
        config_map: Dict[str, etree._Element] = {}
        for el in _xpath_nodes(data, "if:interfaces-state/if:interface"):
            name = _child_text(el, IF_NS, "name")
            if name:
                state_map[name] = el
        for el in _xpath_nodes(data, "if:interfaces/if:interface"):
            name = _child_text(el, IF_NS, "name")
            if name:
                config_map[name] = el
        # If the server collapsed state into if:interfaces (no
        # interfaces-state), treat those as state as well.
        names = list(state_map.keys())
        for name in config_map:
            if name not in state_map:
                names.append(name)
        for name in names:
            yield name, state_map.get(name), config_map.get(name)

    def _parse_interfaces(self, data: etree._Element) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for name, state_el, config_el in self._iter_interfaces(data):
            src = state_el if state_el is not None else config_el
            config_src = config_el if config_el is not None else state_el
            description = _child_text(config_src, IF_NS, "description")
            if not description and state_el is not None:
                description = _child_text(state_el, IF_NS, "description")

            enabled_raw = _child_text(config_src, IF_NS, "enabled")
            admin_status = _child_text(src, IF_NS, "admin-status")
            if enabled_raw != "":
                is_enabled = _parse_enabled(enabled_raw)
            elif admin_status:
                is_enabled = admin_status.lower() == "up"
            else:
                is_enabled = False

            oper_status = _child_text(src, IF_NS, "oper-status")
            is_up = oper_status.lower() == "up"

            speed_raw = _child_text(src, IF_NS, "speed")
            if speed_raw == "" and config_src is not src:
                speed_raw = _child_text(config_src, IF_NS, "speed")
            speed = _parse_uint(speed_raw, DEFAULT_SPEED)

            mtu_raw = _child_text(src, IF_NS, "mtu")
            if mtu_raw == "" and config_src is not src:
                mtu_raw = _child_text(config_src, IF_NS, "mtu")
            mtu = _parse_uint(mtu_raw, DEFAULT_MTU) if mtu_raw != "" else DEFAULT_MTU

            mac = _format_mac(_child_text(src, IF_NS, "phys-address"))
            if not mac and config_src is not src:
                mac = _format_mac(_child_text(config_src, IF_NS, "phys-address"))

            result[name] = {
                "is_up": is_up,
                "is_enabled": is_enabled,
                "description": description,
                "last_flapped": DEFAULT_LAST_FLAPPED,
                "speed": speed,
                "mtu": mtu,
                "mac_address": mac,
            }
        return result

    def _parse_counters(self, data: etree._Element) -> Dict[str, Dict[str, int]]:
        result: Dict[str, Dict[str, int]] = {}
        for name, state_el, config_el in self._iter_interfaces(data):
            src = state_el if state_el is not None else config_el
            stats = _child(src, IF_NS, "statistics")
            def _stat(local: str) -> int:
                if stats is None:
                    return 0
                return _parse_uint(_child_text(stats, IF_NS, local))
            result[name] = {
                "tx_errors": _stat("out-errors"),
                "rx_errors": _stat("in-errors"),
                "tx_discards": _stat("out-discards"),
                "rx_discards": _stat("in-discards"),
                "tx_octets": _stat("out-octets"),
                "rx_octets": _stat("in-octets"),
                "tx_unicast_packets": _stat("out-unicast-pkts"),
                "rx_unicast_packets": _stat("in-unicast-pkts"),
                "tx_multicast_packets": _stat("out-multicast-pkts"),
                "rx_multicast_packets": _stat("in-multicast-pkts"),
                "tx_broadcast_packets": _stat("out-broadcast-pkts"),
                "rx_broadcast_packets": _stat("in-broadcast-pkts"),
            }
        return result

    def _serialize_config(self, data: etree._Element) -> str:
        if data is None:
            return ""
        # Pretty-print the <data> payload (or its children wrapped in <data>).
        payload = data
        if not payload.tag.endswith("data"):
            wrap = etree.Element("{%s}data" % NC_NS)
            if payload.tag not in ("rpc-reply", "{%s}rpc-reply" % NC_NS):
                wrap.append(payload)
            else:
                for child in list(payload):
                    wrap.append(child)
            payload = wrap
        return etree.tostring(payload, encoding="unicode", pretty_print=True).strip() + "\n"

    def parse_interfaces_xml(self, xml: Union[str, bytes, etree._Element]) -> Dict[str, Dict[str, Any]]:
        """Public helper for unit tests: parse a fixture <rpc-reply> or <data>."""
        return self._parse_interfaces(_as_element(xml))

    def parse_counters_xml(self, xml: Union[str, bytes, etree._Element]) -> Dict[str, Dict[str, int]]:
        return self._parse_counters(_as_element(xml))

    def parse_facts_xml(
        self,
        system_xml: Union[str, bytes, etree._Element],
        interfaces_xml: Optional[Union[str, bytes, etree._Element]] = None,
        operational_xml: Optional[Union[str, bytes, etree._Element]] = None,
    ) -> Dict[str, Any]:
        """Public helper for unit tests: facts from fixture XML."""
        paths = self.paths["get_facts"]
        system = _as_element(system_xml)
        hostname = _xpath_text(system, paths["hostname"])
        if not hostname and operational_xml is not None:
            hostname = _xpath_text(
                _as_element(operational_xml), paths["hostname_operational"]
            )
        interface_list: List[str] = []
        if interfaces_xml is not None:
            interface_list = self._interface_names(_as_element(interfaces_xml))
        return {
            "uptime": uptime_seconds(
                _xpath_text(system, paths["current_datetime"]),
                _xpath_text(system, paths["boot_datetime"]),
            ),
            "vendor": VENDOR,
            "os_version": "",
            "serial_number": "",
            "model": "",
            "hostname": hostname,
            "fqdn": hostname,
            "interface_list": interface_list,
        }

    def parse_snmp_xml(self, system_xml: Union[str, bytes, etree._Element]) -> Dict[str, Any]:
        paths = self.paths["get_snmp_information"]
        system = _as_element(system_xml)
        return {
            "chassis_id": "",
            "community": {},
            "contact": _xpath_text(system, paths["contact"]),
            "location": _xpath_text(system, paths["location"]),
        }
