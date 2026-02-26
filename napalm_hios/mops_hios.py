"""
MOPS protocol handler for NAPALM HiOS driver.

Uses MOPS (MIB Operations over HTTPS) — the same protocol the HiOS web UI
uses internally. Advantages over SNMP: atomic multi-table writes in one POST,
HTTP Basic auth (no USM key derivation), no pysnmp dependency, one request
returns entire tables (no walking).

Confirmed working MIBs/Nodes:
  SNMPv2-MIB/system, IF-MIB/ifEntry, IF-MIB/ifXEntry,
  LLDP-MIB/lldpRemEntry, HM2-FILEMGMT-MIB/hm2FileMgmtStatusGroup,
  HM2-DIAGNOSTIC-MIB/hm2DevMonCommonEntry,
  IEEE8021-Q-BRIDGE-MIB/ieee8021QBridgeVlanStaticEntry
"""

import logging

from napalm.base.exceptions import ConnectionException

from napalm_hios.mops_client import (
    MOPSClient, MOPSError,
    _decode_hex_string, _decode_hex_mac, encode_string, encode_int,
)

logger = logging.getLogger(__name__)

# LLDP capability bit positions (from MSB of first octet)
LLDP_CAPABILITIES = [
    'other',            # bit 0
    'repeater',         # bit 1
    'bridge',           # bit 2
    'wlan-access-point', # bit 3
    'router',           # bit 4
    'telephone',        # bit 5
    'docsis-cable-device', # bit 6
    'station',          # bit 7
]

# MRP enum mappings (match snmp_hios.py)
_MRP_PORT_OPER_STATE = {'1': 'disabled', '2': 'blocked', '3': 'forwarding', '4': 'notConnected'}
_MRP_ROLE = {'1': 'client', '2': 'manager', '3': 'undefined'}
_MRP_RECOVERY_DELAY = {'1': '500ms', '2': '200ms', '3': '30ms', '4': '10ms'}
_MRP_RING_OPER_STATE = {'1': 'open', '2': 'closed', '3': 'undefined'}
_MRP_CONFIG_INFO = {'1': 'no error', '2': 'ring port link error', '3': 'multiple MRM detected'}
_MRP_RECOVERY_DELAY_REV = {'500ms': '1', '200ms': '2', '30ms': '3', '10ms': '4'}
_MRP_ROLE_REV = {'client': '1', 'manager': '2'}

# IANA dot3MauType OID suffix → human-readable name (match snmp_hios.py)
_MAU_TYPES = {
    '10': '10BaseTHD', '11': '10BaseTFD',
    '15': '100BaseTXHD', '16': '100BaseTXFD',
    '17': '100BaseFXHD', '18': '100BaseFXFD',
    '29': '1000BaseTHD', '30': '1000BaseTFD',
    '32': '1000BaseSXHD', '33': '1000BaseSXFD',
    '34': '1000BaseLXHD', '35': '1000BaseLXFD',
    '110': '2p5GbaseX',
}


def _try_mac(value):
    """If value looks like a MAC (6 raw bytes or hex string), format as xx:xx:xx:xx:xx:xx.

    Handles three forms:
    1. Mangled 6-byte binary string (after _decode_hex_string)
    2. Raw hex string "64 60 38 8a 42 d6" (6 space-separated hex pairs)
    3. Already-formatted "xx:xx:xx:xx:xx:xx" — passed through unchanged
    """
    if not value:
        return value
    # Already formatted?
    if ":" in value and len(value) == 17:
        return value
    # Form 2: space-separated hex pairs
    parts = value.strip().split()
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            bytes.fromhex("".join(parts))
            return ":".join(p.lower() for p in parts)
        except ValueError:
            pass
    # Form 1: mangled 6-byte binary string
    if len(value) == 6 and " " not in value:
        return ":".join(f"{ord(c):02x}" for c in value)
    return value


def _re_hex(value):
    """Re-encode a mangled binary string back to space-separated hex.

    _decode_hex_string converts "00 24" to raw bytes "\\x00$". This reverses it
    so bitmap decoders (like _decode_lldp_capabilities) get the hex they expect.
    If the value already looks like hex tokens, return as-is.
    """
    if not value:
        return value
    # Already hex tokens? (e.g. "00 24")
    parts = value.strip().split()
    if parts and all(len(p) == 2 for p in parts):
        try:
            bytes.fromhex("".join(parts))
            return value  # already hex
        except ValueError:
            pass
    # Mangled binary — re-encode each char as hex
    return " ".join(f"{ord(c):02x}" for c in value)


def _safe_int(val, default=0):
    """Safely convert string to int."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _safe_int_or_ord(val, default=0):
    """Convert string to int, handling hex-mangled single bytes.

    _decode_hex_string converts "01" to chr(1)='\x01', "02" to chr(2)='\x02'.
    These aren't parseable by int() but ord() gives the right value.
    """
    if not val:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        if len(val) == 1:
            return ord(val)
        return default


def _parse_sysDescr(text):
    """Parse sysDescr to extract model and os_version.

    Expected format: 'Hirschmann GRS1042 HiOS-3A-09.4.04 ...'
    """
    parts = str(text).split()
    if len(parts) >= 3 and parts[0].lower() == 'hirschmann':
        return parts[1], parts[2]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return 'Unknown', 'Unknown'


def _decode_hex_ip(hex_str):
    """Decode hex-encoded IP address from MOPS.

    IPv4: "c0 a8 03 01" (4 bytes) → "192.168.3.1"
    IPv6: 16 bytes → compressed IPv6 notation
    Returns empty string if not a valid IP.
    """
    if not hex_str or not hex_str.strip():
        return ""
    parts = hex_str.strip().split()
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return hex_str
    if len(octets) == 4:
        return ".".join(str(o) for o in octets)
    if len(octets) == 16:
        import ipaddress
        return str(ipaddress.IPv6Address(bytes(octets)))
    return hex_str


def _mask_to_prefix(mask_str):
    """Convert dotted subnet mask to prefix length."""
    try:
        parts = [int(p) for p in mask_str.split('.')]
        bits = ''.join(f'{p:08b}' for p in parts)
        return bits.count('1')
    except (ValueError, AttributeError):
        return 32


def _decode_portlist_hex(hex_str, ifindex_map):
    """Decode PortList hex string to interface names.

    MOPS returns PortList as space-separated hex bytes (e.g. "c0 00 00 00").
    Each bit = a bridge port number (1-based, MSB first).
    """
    interfaces = []
    if not hex_str or not hex_str.strip():
        return interfaces
    try:
        octets = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        return interfaces
    for byte_idx, byte_val in enumerate(octets):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                port_num = byte_idx * 8 + bit_idx + 1
                name = ifindex_map.get(str(port_num), f'port{port_num}')
                interfaces.append(name)
    return interfaces


def _decode_lldp_capabilities(hex_str):
    """Decode LLDP capability bitmap from hex string."""
    caps = []
    if not hex_str or not hex_str.strip():
        return caps
    parts = hex_str.strip().split()
    if not parts:
        return caps
    try:
        byte0 = int(parts[0], 16)
    except ValueError:
        return caps
    for i, name in enumerate(LLDP_CAPABILITIES):
        if byte0 & (0x80 >> i):
            caps.append(name)
    return caps


class MOPSHIOS:
    """MOPS protocol handler for HiOS devices.

    Provides the same getter interface as SSHHIOS and SNMPHIOS, using
    MOPS (HTTPS/XML) as the transport instead of SSH CLI or SNMP walks.
    """

    def __init__(self, hostname, username, password, timeout, port=443):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.client = None
        self._connected = False
        self._ifindex_map = None  # cached ifIndex -> name

        # Staging support for atomic commits
        self._staging = False
        self._mutations = []

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def open(self):
        """Connect via MOPS and verify with sysDescr probe."""
        self.client = MOPSClient(
            self.hostname, self.username, self.password,
            port=self.port, timeout=self.timeout,
        )
        try:
            self.client.probe()
            self._connected = True
        except (ConnectionException, MOPSError) as e:
            self.client.close()
            self.client = None
            raise ConnectionException(f"MOPS probe failed on {self.hostname}: {e}")

    def is_factory_default(self):
        """Check if device is in factory-default password state."""
        if not self.client:
            raise ConnectionException("Not connected")
        return self.client.is_factory_default()

    def onboard(self, new_password):
        """Onboard a factory-fresh device by changing the default password.

        Calls POST /mops_changePassword which flips hm2UserForcePasswordStatus
        from enable(1) to disable(2), unlocking the SNMP agent.

        The new_password can be the same as the current password — the act of
        calling the endpoint is what clears the factory gate.

        Safety: Refuses to proceed if device is already onboarded —
        calling change_password on an onboarded device causes a cold reset.

        Args:
            new_password: Password to set (can be same as current).

        Returns: True on success.
        Raises: ConnectionException if not connected or already onboarded.
        """
        if not self.client:
            raise ConnectionException("Not connected")
        # The safety guard is also in MOPSClient.change_password(), but
        # we check here too for a clear error message at this layer.
        if not self.client.is_factory_default():
            raise ConnectionException(
                "Device is already onboarded — onboard() must only be "
                "called on factory-fresh devices (cold reset risk)")
        return self.client.change_password(new_password)

    def close(self):
        """Close the MOPS session."""
        if self.client:
            self.client.close()
            self.client = None
        self._connected = False
        self._ifindex_map = None
        self._staging = False
        self._mutations = []

    def is_alive(self):
        return self._connected

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_ifindex_map(self):
        """Build and cache ifIndex -> interface name mapping via IF-MIB/ifXEntry.

        decode_strings=False because ifIndex values like "10", "11", "12", "25"
        are valid 2-char hex tokens that _decode_hex_string corrupts into control
        chars or ASCII symbols (e.g. "10" → \\x10, "25" → '%').
        """
        if self._ifindex_map is not None:
            return self._ifindex_map
        entries = self.client.get("IF-MIB", "ifXEntry", ["ifIndex", "ifName"],
                                  decode_strings=False)
        self._ifindex_map = {}
        for entry in entries:
            idx = entry.get("ifIndex", "")
            name = _decode_hex_string(entry.get("ifName", ""))
            if idx and name:
                self._ifindex_map[idx] = name
        return self._ifindex_map

    def _get_bridge_port_map(self):
        """Map bridge port numbers to interface names.

        For VLAN PortList decoding. Bridge ports may not match ifIndex
        on all HiOS firmware versions, but in practice they align.
        """
        return self._build_ifindex_map()

    # ------------------------------------------------------------------
    # Staging support
    # ------------------------------------------------------------------

    def start_staging(self):
        """Enter staging mode — mutations are queued, not sent."""
        self._staging = True
        self._mutations = []

    def commit_staging(self):
        """Fire all queued mutations in one atomic POST, then save to NVM."""
        if not self._mutations:
            self._staging = False
            return
        self.client.set_multi(self._mutations)
        self.client.save_config()
        self._staging = False
        self._mutations = []

    def discard_staging(self):
        """Clear queued mutations without sending."""
        self._staging = False
        self._mutations = []

    def get_staged_mutations(self):
        """Return list of staged mutation tuples for compare_config."""
        return list(self._mutations)

    # ------------------------------------------------------------------
    # Standard NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self):
        """Return device facts from SNMPv2-MIB + IF-MIB + HM2 private MIBs."""
        # decode_strings=False: ifIndex values like "10","11","25" are valid hex
        # tokens that _decode_hex_string corrupts. Manually decode text fields.
        result = self.client.get_multi([
            ("SNMPv2-MIB", "system",
             ["sysDescr", "sysName", "sysUpTime", "sysContact", "sysLocation"]),
            ("IF-MIB", "ifXEntry", ["ifIndex", "ifName"]),
        ], decode_strings=False)

        mibs = result["mibs"]
        sys_entries = mibs.get("SNMPv2-MIB", {}).get("system", [{}])
        sys_data = sys_entries[0] if sys_entries else {}

        # Build interface list from ifXEntry
        if_entries = mibs.get("IF-MIB", {}).get("ifXEntry", [])
        interface_list = sorted(
            [_decode_hex_string(e["ifName"]) for e in if_entries if e.get("ifName")],
            key=lambda x: (x.split('/')[0] if '/' in x else x,
                           int(x.split('/')[1]) if '/' in x and x.split('/')[1].isdigit() else 0)
        )

        # Cache the ifindex map from this query (raw ifIndex, decoded ifName)
        self._ifindex_map = {}
        for entry in if_entries:
            idx = entry.get("ifIndex", "")
            name = _decode_hex_string(entry.get("ifName", ""))
            if idx and name:
                self._ifindex_map[idx] = name

        sys_descr = _decode_hex_string(sys_data.get("sysDescr", ""))
        model, os_version = _parse_sysDescr(sys_descr)

        hostname = _decode_hex_string(sys_data.get("sysName", ""))
        uptime_ticks = _safe_int(sys_data.get("sysUpTime", "0"))

        # Get product description and serial from private MIBs
        serial = ""
        try:
            hm2_entries = self.client.get("HM2-DEVMGMT-MIB", "hm2DeviceMgmtGroup",
                                          ["hm2DevMgmtProductDescr", "hm2DevMgmtSerialNumber"],
                                          decode_strings=False)
            if hm2_entries:
                product_descr = _decode_hex_string(hm2_entries[0].get("hm2DevMgmtProductDescr", ""))
                serial = _decode_hex_string(hm2_entries[0].get("hm2DevMgmtSerialNumber", ""))
                if product_descr:
                    model = product_descr
        except MOPSError:
            pass

        # Get firmware version from software version table
        # RAM entry (FileLocation=1) with FileIdx=1 = running version
        try:
            fw_entries = self.client.get("HM2-DEVMGMT-MIB", "hm2DevMgmtSwVersEntry",
                                         ["hm2DevMgmtSwVersion",
                                          "hm2DevMgmtSwFileLocation",
                                          "hm2DevMgmtSwFileIdx"],
                                         decode_strings=False)
            for entry in fw_entries:
                loc = entry.get("hm2DevMgmtSwFileLocation", "")
                idx = entry.get("hm2DevMgmtSwFileIdx", "")
                if loc == "1" and idx == "1":
                    raw_version = _decode_hex_string(entry.get("hm2DevMgmtSwVersion", ""))
                    if raw_version:
                        # "HiOS-2A-10.3.04 2025-12-08 16:54" → "HiOS-2A-10.3.04"
                        os_version = raw_version.split()[0] if ' ' in raw_version else raw_version
                    break
        except MOPSError:
            pass

        return {
            'uptime': uptime_ticks // 100,
            'vendor': 'Belden',
            'model': model,
            'hostname': hostname,
            'fqdn': hostname,
            'os_version': os_version,
            'serial_number': serial,
            'interface_list': interface_list,
        }

    def get_interfaces(self):
        """Return interface details from IF-MIB/ifEntry + ifXEntry."""
        # decode_strings=False because ifPhysAddress contains binary MAC bytes
        # that get corrupted by UTF-8 decode (bytes >127 become U+FFFD)
        result = self.client.get_multi([
            ("IF-MIB", "ifEntry", [
                "ifIndex", "ifDescr", "ifMtu", "ifSpeed",
                "ifPhysAddress", "ifAdminStatus", "ifOperStatus"]),
            ("IF-MIB", "ifXEntry", [
                "ifIndex", "ifName", "ifHighSpeed", "ifAlias"]),
        ], decode_strings=False)

        mibs = result["mibs"]
        if_entries = mibs.get("IF-MIB", {}).get("ifEntry", [])
        ifx_entries = mibs.get("IF-MIB", {}).get("ifXEntry", [])

        # Index ifXEntry by ifIndex for merging
        ifx_by_idx = {}
        for entry in ifx_entries:
            idx = entry.get("ifIndex", "")
            if idx:
                ifx_by_idx[idx] = entry

        interfaces = {}
        for entry in if_entries:
            idx = entry.get("ifIndex", "")
            ifx = ifx_by_idx.get(idx, {})

            name = _decode_hex_string(ifx.get("ifName", "")) or \
                   _decode_hex_string(entry.get("ifDescr", "")) or f"if{idx}"
            admin_status = _safe_int(entry.get("ifAdminStatus", "2"))
            oper_status = _safe_int(entry.get("ifOperStatus", "2"))

            # Speed: prefer ifHighSpeed (Mbps), fall back to ifSpeed (bps)
            high_speed = _safe_int(ifx.get("ifHighSpeed", "0"))
            if high_speed > 0:
                speed = high_speed * 1_000_000  # Convert Mbps to bps
            else:
                speed = _safe_int(entry.get("ifSpeed", "0"))

            # MAC: raw hex string, decode directly (no UTF-8 mangling)
            mac_raw = entry.get("ifPhysAddress", "")
            mac = _decode_hex_mac(mac_raw) if mac_raw and mac_raw.strip() else ""

            interfaces[name] = {
                'is_up': oper_status == 1,
                'is_enabled': admin_status == 1,
                'description': _decode_hex_string(ifx.get("ifAlias", "")),
                'last_flapped': -1.0,
                'speed': speed,
                'mtu': _safe_int(entry.get("ifMtu", "0")),
                'mac_address': mac,
            }

        return interfaces

    def get_interfaces_ip(self):
        """Return IP addresses from IP-MIB/ipAddrEntry."""
        ifindex_map = self._build_ifindex_map()
        # decode_strings=False: ipAdEntIfIndex values like "25" are valid hex
        entries = self.client.get("IP-MIB", "ipAddrEntry",
                                  ["ipAdEntAddr", "ipAdEntIfIndex", "ipAdEntNetMask"],
                                  decode_strings=False)
        result = {}
        for entry in entries:
            ip = entry.get("ipAdEntAddr", "")
            ifidx = entry.get("ipAdEntIfIndex", "")
            mask = entry.get("ipAdEntNetMask", "255.255.255.0")

            if not ip or not ifidx:
                continue

            iface = ifindex_map.get(ifidx, f"if{ifidx}")
            prefix = _mask_to_prefix(mask)

            if iface not in result:
                result[iface] = {"ipv4": {}, "ipv6": {}}
            result[iface]["ipv4"][ip] = {"prefix_length": prefix}

        return result

    def get_interfaces_counters(self):
        """Return interface counters from IF-MIB/ifEntry + ifXEntry."""
        # decode_strings=False: ifIndex values like "10","11","12" are valid
        # hex tokens that get corrupted by _decode_hex_string
        result = self.client.get_multi([
            ("IF-MIB", "ifEntry", [
                "ifIndex", "ifInErrors", "ifOutErrors",
                "ifInDiscards", "ifOutDiscards"]),
            ("IF-MIB", "ifXEntry", [
                "ifIndex", "ifName",
                "ifHCInOctets", "ifHCOutOctets",
                "ifHCInUcastPkts", "ifHCOutUcastPkts",
                "ifHCInMulticastPkts", "ifHCOutMulticastPkts",
                "ifHCInBroadcastPkts", "ifHCOutBroadcastPkts"]),
        ], decode_strings=False)

        mibs = result["mibs"]
        if_entries = mibs.get("IF-MIB", {}).get("ifEntry", [])
        ifx_entries = mibs.get("IF-MIB", {}).get("ifXEntry", [])

        # Index by ifIndex
        if_by_idx = {}
        for entry in if_entries:
            idx = entry.get("ifIndex", "")
            if idx:
                if_by_idx[idx] = entry

        counters = {}
        for entry in ifx_entries:
            idx = entry.get("ifIndex", "")
            name = _decode_hex_string(entry.get("ifName", "")) or f"if{idx}"
            if_data = if_by_idx.get(idx, {})

            counters[name] = {
                'tx_errors': _safe_int(if_data.get("ifOutErrors", "0")),
                'rx_errors': _safe_int(if_data.get("ifInErrors", "0")),
                'tx_discards': _safe_int(if_data.get("ifOutDiscards", "0")),
                'rx_discards': _safe_int(if_data.get("ifInDiscards", "0")),
                'tx_octets': _safe_int(entry.get("ifHCOutOctets", "0")),
                'rx_octets': _safe_int(entry.get("ifHCInOctets", "0")),
                'tx_unicast_packets': _safe_int(entry.get("ifHCOutUcastPkts", "0")),
                'rx_unicast_packets': _safe_int(entry.get("ifHCInUcastPkts", "0")),
                'tx_multicast_packets': _safe_int(entry.get("ifHCOutMulticastPkts", "0")),
                'rx_multicast_packets': _safe_int(entry.get("ifHCInMulticastPkts", "0")),
                'tx_broadcast_packets': _safe_int(entry.get("ifHCOutBroadcastPkts", "0")),
                'rx_broadcast_packets': _safe_int(entry.get("ifHCInBroadcastPkts", "0")),
            }

        return counters

    def get_lldp_neighbors(self):
        """Return LLDP neighbors from LLDP-MIB/lldpRemEntry."""
        ifindex_map = self._build_ifindex_map()
        # decode_strings=False: port ID and chassis ID contain binary MACs
        entries = self.client.get("LLDP-MIB", "lldpRemEntry",
                                  ["lldpRemLocalPortNum", "lldpRemSysName",
                                   "lldpRemPortId", "lldpRemChassisId"],
                                  decode_strings=False)
        neighbors = {}
        for entry in entries:
            local_port_num = entry.get("lldpRemLocalPortNum", "")
            remote_name = _decode_hex_string(entry.get("lldpRemSysName", ""))
            # Port ID and chassis ID: try MAC first, fall back to text decode
            remote_port_raw = entry.get("lldpRemPortId", "")
            chassis_raw = entry.get("lldpRemChassisId", "")
            remote_port = _try_mac(remote_port_raw)
            chassis_id = _try_mac(chassis_raw)
            # If _try_mac didn't convert (still looks like hex tokens), decode as text
            if remote_port == remote_port_raw and " " in remote_port:
                remote_port = _decode_hex_string(remote_port_raw)
            if chassis_id == chassis_raw and " " in chassis_id:
                chassis_id = _decode_hex_string(chassis_raw)

            local_port = ifindex_map.get(local_port_num, f"port{local_port_num}")

            hostname = remote_name if remote_name else chassis_id

            if local_port not in neighbors:
                neighbors[local_port] = []
            neighbors[local_port].append({
                'hostname': hostname,
                'port': remote_port,
            })

        return neighbors

    def _get_lldp_mgmt_addresses(self):
        """Fetch LLDP management addresses from lldpRemManAddrEntry.

        Returns dict keyed by (localPortNum, remIndex) → list of IPv4 strings.
        """
        try:
            mgmt_entries = self.client.get("LLDP-MIB", "lldpRemManAddrEntry", [
                "lldpRemManAddrSubtype", "lldpRemManAddr",
                "lldpRemIndex", "lldpRemLocalPortNum",
            ], decode_strings=False)
        except MOPSError:
            return {}

        mgmt_map = {}  # (localPortNum, remIndex) → [ip, ...]
        for entry in mgmt_entries:
            subtype = _safe_int(entry.get("lldpRemManAddrSubtype", "0"))
            addr_raw = entry.get("lldpRemManAddr", "")
            port_num = entry.get("lldpRemLocalPortNum", "")
            rem_idx = entry.get("lldpRemIndex", "")
            if not port_num or not rem_idx:
                continue
            key = (port_num, rem_idx)
            if subtype == 1:  # IPv4
                ip = _decode_hex_ip(addr_raw)
                if ip:
                    mgmt_map.setdefault(key, []).append(ip)
        return mgmt_map

    def get_lldp_neighbors_detail(self, interface=""):
        """Return detailed LLDP neighbor info from LLDP-MIB/lldpRemEntry."""
        ifindex_map = self._build_ifindex_map()
        # decode_strings=False: chassis/port IDs are binary MACs, capabilities are bitmaps
        entries = self.client.get("LLDP-MIB", "lldpRemEntry", [
            "lldpRemLocalPortNum", "lldpRemIndex",
            "lldpRemPortId", "lldpRemPortDesc",
            "lldpRemChassisId", "lldpRemSysName", "lldpRemSysDesc",
            "lldpRemSysCapSupported", "lldpRemSysCapEnabled",
        ], decode_strings=False)

        mgmt_map = self._get_lldp_mgmt_addresses()

        result = {}
        for entry in entries:
            local_port_num = entry.get("lldpRemLocalPortNum", "")
            rem_idx = entry.get("lldpRemIndex", "")
            local_port = ifindex_map.get(local_port_num, f"port{local_port_num}")

            if interface and local_port != interface:
                continue

            chassis_raw = entry.get("lldpRemChassisId", "")
            remote_port_raw = entry.get("lldpRemPortId", "")
            chassis_id = _try_mac(chassis_raw)
            remote_port = _try_mac(remote_port_raw)
            # If _try_mac didn't convert (still looks like hex tokens), decode as text
            if remote_port == remote_port_raw and " " in remote_port:
                remote_port = _decode_hex_string(remote_port_raw)
            if chassis_id == chassis_raw and " " in chassis_id:
                chassis_id = _decode_hex_string(chassis_raw)

            # Capabilities: raw hex (decode_strings=False), pass directly
            caps_sup = _decode_lldp_capabilities(entry.get("lldpRemSysCapSupported", ""))
            caps_en = _decode_lldp_capabilities(entry.get("lldpRemSysCapEnabled", ""))

            # Management address — first IPv4 for this neighbor
            mgmt_addrs = mgmt_map.get((local_port_num, rem_idx), [])
            mgmt_addr = mgmt_addrs[0] if mgmt_addrs else ''

            neighbor = {
                'parent_interface': local_port,
                'remote_port': remote_port,
                'remote_port_description': _decode_hex_string(entry.get("lldpRemPortDesc", "")),
                'remote_chassis_id': chassis_id,
                'remote_system_name': _decode_hex_string(entry.get("lldpRemSysName", "")),
                'remote_system_description': _decode_hex_string(entry.get("lldpRemSysDesc", "")),
                'remote_system_capab': caps_sup,
                'remote_system_enable_capab': caps_en,
                'remote_management_address': mgmt_addr,
            }

            if local_port not in result:
                result[local_port] = []
            result[local_port].append(neighbor)

        return result

    def get_lldp_neighbors_detail_extended(self, interface=""):
        """Return extended LLDP neighbor details including 802.1/802.3 TLVs.

        Confirmed MIB/Node names from web UI capture:
          LLDP-EXT-DOT3-MIB/lldpXdot3RemPortEntry: AutoNegSupported, AutoNegEnabled
          LLDP-EXT-DOT1-MIB/lldpXdot1RemPortVlanIdEntry: not in capture, try anyway
        """
        ifindex_map = self._build_ifindex_map()

        # Fetch standard LLDP + management addresses + DOT3 extensions in one get_multi
        try:
            result = self.client.get_multi([
                ("LLDP-MIB", "lldpRemEntry", [
                    "lldpRemLocalPortNum", "lldpRemIndex",
                    "lldpRemPortId", "lldpRemPortDesc",
                    "lldpRemChassisId", "lldpRemSysName", "lldpRemSysDesc",
                    "lldpRemSysCapSupported", "lldpRemSysCapEnabled",
                ]),
                ("LLDP-MIB", "lldpRemManAddrEntry", [
                    "lldpRemManAddrSubtype", "lldpRemManAddr",
                    "lldpRemIndex", "lldpRemLocalPortNum",
                ]),
                ("LLDP-EXT-DOT3-MIB", "lldpXdot3RemPortEntry", [
                    "lldpXdot3RemPortAutoNegSupported",
                    "lldpXdot3RemPortAutoNegEnabled",
                    "lldpXdot3RemPortOperMauType",
                    "lldpRemLocalPortNum", "lldpRemIndex",
                ]),
            ], decode_strings=False)
        except MOPSError:
            return {}

        mibs = result["mibs"]
        lldp_entries = mibs.get("LLDP-MIB", {}).get("lldpRemEntry", [])
        mgmt_entries = mibs.get("LLDP-MIB", {}).get("lldpRemManAddrEntry", [])
        dot3_entries = mibs.get("LLDP-EXT-DOT3-MIB", {}).get(
            "lldpXdot3RemPortEntry", [])

        # Build management address map: (localPortNum, remIndex) → [ipv4, ...]
        mgmt_map = {}
        mgmt_ipv4_map = {}  # first IPv4
        for entry in mgmt_entries:
            subtype = _safe_int(entry.get("lldpRemManAddrSubtype", "0"))
            addr_raw = entry.get("lldpRemManAddr", "")
            port_num = entry.get("lldpRemLocalPortNum", "")
            rem_idx = entry.get("lldpRemIndex", "")
            if not port_num or not rem_idx:
                continue
            key = (port_num, rem_idx)
            if subtype == 1:  # IPv4
                ip = _decode_hex_ip(addr_raw)
                if ip:
                    mgmt_map.setdefault(key, []).append(ip)
                    if key not in mgmt_ipv4_map:
                        mgmt_ipv4_map[key] = ip

        # Build DOT3 autoneg map: (localPortNum, remIndex) → {autoneg_sup, autoneg_en}
        dot3_map = {}
        for entry in dot3_entries:
            port_num = entry.get("lldpRemLocalPortNum", "")
            rem_idx = entry.get("lldpRemIndex", "")
            if not port_num or not rem_idx:
                continue
            key = (port_num, rem_idx)
            # TruthValue: 1=true, 2=false → yes/no
            sup = _safe_int(entry.get("lldpXdot3RemPortAutoNegSupported", "0"))
            en = _safe_int(entry.get("lldpXdot3RemPortAutoNegEnabled", "0"))
            # MAU type: OID like "1.3.6.1.2.1.26.4.110" → suffix "110" → "2p5GbaseX"
            mau_raw = entry.get("lldpXdot3RemPortOperMauType", "")
            mau_str = ''
            if mau_raw and mau_raw != '0' and mau_raw != '0.0':
                mau_suffix = mau_raw.rsplit('.', 1)[-1] if '.' in mau_raw else mau_raw
                mau_str = _MAU_TYPES.get(mau_suffix, mau_raw)
            dot3_map[key] = {
                'autoneg_sup': 'yes' if sup == 1 else 'no' if sup == 2 else '',
                'autoneg_en': 'yes' if en == 1 else 'no' if en == 2 else '',
                'mau_type': mau_str,
            }

        # Also try DOT3 link aggregation and DOT1 PVID (may not be in capture)
        # Query separately so failure doesn't break everything
        agg_map = {}
        try:
            agg_entries = self.client.get("LLDP-EXT-DOT3-MIB",
                                          "lldpXdot3RemLinkAggEntry", [
                "lldpXdot3RemLinkAggStatus",
                "lldpXdot3RemLinkAggPortId",
                "lldpRemLocalPortNum", "lldpRemIndex",
            ], decode_strings=False)
            for entry in agg_entries:
                port_num = entry.get("lldpRemLocalPortNum", "")
                rem_idx = entry.get("lldpRemIndex", "")
                if not port_num or not rem_idx:
                    continue
                key = (port_num, rem_idx)
                agg_bits = _safe_int(entry.get("lldpXdot3RemLinkAggStatus", "0"))
                agg_port = entry.get("lldpXdot3RemLinkAggPortId", "0")
                if agg_bits & 0xC0 == 0xC0:
                    agg_str = 'agg. active'
                elif agg_bits & 0x80:
                    agg_str = 'agg. capable'
                else:
                    agg_str = 'not capable'
                agg_map[key] = {'status': agg_str, 'port_id': agg_port}
        except MOPSError:
            pass

        # DOT1 PVID
        pvid_map = {}
        try:
            pvid_entries = self.client.get("LLDP-EXT-DOT1-MIB",
                                           "lldpXdot1RemPortVlanIdEntry", [
                "lldpXdot1RemPortVlanId",
                "lldpRemLocalPortNum", "lldpRemIndex",
            ], decode_strings=False)
            for entry in pvid_entries:
                port_num = entry.get("lldpRemLocalPortNum", "")
                rem_idx = entry.get("lldpRemIndex", "")
                if not port_num or not rem_idx:
                    continue
                key = (port_num, rem_idx)
                pvid_map[key] = entry.get("lldpXdot1RemPortVlanId", "0")
        except MOPSError:
            pass

        # Build result
        neighbors = {}
        for entry in lldp_entries:
            local_port_num = entry.get("lldpRemLocalPortNum", "")
            rem_idx = entry.get("lldpRemIndex", "")
            local_port = ifindex_map.get(local_port_num, f"port{local_port_num}")

            if interface and local_port != interface:
                continue

            chassis_raw = entry.get("lldpRemChassisId", "")
            remote_port_raw = entry.get("lldpRemPortId", "")
            chassis_id = _try_mac(chassis_raw)
            remote_port = _try_mac(remote_port_raw)
            if remote_port == remote_port_raw and " " in remote_port:
                remote_port = _decode_hex_string(remote_port_raw)
            if chassis_id == chassis_raw and " " in chassis_id:
                chassis_id = _decode_hex_string(chassis_raw)

            caps_sup = _decode_lldp_capabilities(entry.get("lldpRemSysCapSupported", ""))
            caps_en = _decode_lldp_capabilities(entry.get("lldpRemSysCapEnabled", ""))

            key = (local_port_num, rem_idx)
            mgmt_addrs = mgmt_map.get(key, [])
            mgmt_ipv4 = mgmt_ipv4_map.get(key, '')
            dot3 = dot3_map.get(key, {})
            agg = agg_map.get(key, {})
            pvid = pvid_map.get(key, '0')

            mau_type_str = dot3.get('mau_type', '')

            detail = {
                'parent_interface': local_port,
                'remote_chassis_id': chassis_id,
                'remote_system_name': _decode_hex_string(entry.get("lldpRemSysName", "")),
                'remote_system_description': _decode_hex_string(entry.get("lldpRemSysDesc", "")),
                'remote_port': remote_port,
                'remote_port_description': _decode_hex_string(entry.get("lldpRemPortDesc", "")),
                'remote_system_capab': caps_sup,
                'remote_system_enable_capab': caps_en,
                'remote_management_ipv4': mgmt_ipv4,
                'remote_management_ipv6': '',
                'management_addresses': mgmt_addrs,
                'autoneg_support': dot3.get('autoneg_sup', ''),
                'autoneg_enabled': dot3.get('autoneg_en', ''),
                'port_oper_mau_type': mau_type_str,
                'port_vlan_id': str(pvid) if pvid else '0',
                'vlan_membership': [],
                'link_agg_status': agg.get('status', ''),
                'link_agg_port_id': agg.get('port_id', '0'),
            }
            neighbors.setdefault(local_port, []).append(detail)

        return neighbors

    def get_mac_address_table(self):
        """Return MAC address table from IEEE8021-Q-BRIDGE-MIB FDB.

        Request ieee8021QBridgeFdbId (or dot1qFdbId) explicitly — on HiOS
        this equals the VLAN ID directly, matching the SNMP OID index suffix.
        """
        ifindex_map = self._build_ifindex_map()

        # decode_strings=False: FDB address is binary MAC
        try:
            entries = self.client.get("IEEE8021-Q-BRIDGE-MIB",
                                      "ieee8021QBridgeTpFdbEntry",
                                      ["ieee8021QBridgeTpFdbAddress",
                                       "ieee8021QBridgeTpFdbPort",
                                       "ieee8021QBridgeTpFdbStatus",
                                       "ieee8021QBridgeFdbId"],
                                      decode_strings=False)
        except MOPSError:
            try:
                entries = self.client.get("Q-BRIDGE-MIB",
                                          "dot1qTpFdbEntry",
                                          ["dot1qTpFdbAddress",
                                           "dot1qTpFdbPort",
                                           "dot1qTpFdbStatus",
                                           "dot1qFdbId"],
                                          decode_strings=False)
            except MOPSError:
                return []

        mac_table = []
        for entry in entries:
            # Get MAC address — try both MIB naming conventions
            mac_raw = (entry.get("ieee8021QBridgeTpFdbAddress", "") or
                       entry.get("dot1qTpFdbAddress", ""))
            port = (entry.get("ieee8021QBridgeTpFdbPort", "") or
                    entry.get("dot1qTpFdbPort", ""))
            status = (entry.get("ieee8021QBridgeTpFdbStatus", "") or
                      entry.get("dot1qTpFdbStatus", ""))
            # FDB ID = VLAN ID on HiOS (matches SNMP OID index suffix)
            fdb_id = (entry.get("ieee8021QBridgeFdbId", "") or
                      entry.get("dot1qFdbId", ""))

            mac = _decode_hex_mac(mac_raw) if mac_raw else ""
            iface = ifindex_map.get(port, f"port{port}") if port else ""

            # Status: 3=learned, 5=static (match SNMP: anything not learned = static)
            static = _safe_int(status) != 3

            mac_table.append({
                'mac': mac,
                'interface': iface,
                'vlan': _safe_int(fdb_id, 0),
                'static': static,
                'active': True,
                'moves': 0,
                'last_move': 0.0,
            })

        return mac_table

    def get_arp_table(self, vrf=""):
        """Return ARP table from IP-MIB/ipNetToMediaEntry."""
        ifindex_map = self._build_ifindex_map()
        # decode_strings=False: MAC address is binary
        entries = self.client.get("IP-MIB", "ipNetToMediaEntry",
                                  ["ipNetToMediaIfIndex", "ipNetToMediaPhysAddress",
                                   "ipNetToMediaNetAddress", "ipNetToMediaType"],
                                  decode_strings=False)
        arp_table = []
        for entry in entries:
            ifidx = entry.get("ipNetToMediaIfIndex", "")
            mac_raw = entry.get("ipNetToMediaPhysAddress", "")
            ip = entry.get("ipNetToMediaNetAddress", "")

            if not ip:
                continue

            iface = ifindex_map.get(ifidx, f"if{ifidx}")
            mac = _decode_hex_mac(mac_raw) if mac_raw else ""

            arp_table.append({
                'interface': iface,
                'mac': mac,
                'ip': ip,
                'age': 0.0,
            })

        return arp_table

    def get_vlans(self):
        """Return VLAN table from IEEE8021-Q-BRIDGE-MIB or Q-BRIDGE-MIB.

        MOPS doesn't return table index columns in <Index> elements for GET
        responses — they must be explicitly requested as regular attributes.
        """
        bridge_map = self._get_bridge_port_map()

        try:
            # Request VlanIndex explicitly — MOPS returns it as a regular Attribute
            # decode_strings=False: EgressPorts is a PortList bitmap (hex bytes),
            # _decode_hex_string would corrupt it; Name needs manual decode
            entries = self.client.get("IEEE8021-Q-BRIDGE-MIB",
                                      "ieee8021QBridgeVlanStaticEntry",
                                      ["ieee8021QBridgeVlanStaticVlanIndex",
                                       "ieee8021QBridgeVlanStaticName",
                                       "ieee8021QBridgeVlanStaticRowStatus",
                                       "ieee8021QBridgeVlanStaticEgressPorts"],
                                      decode_strings=False)
        except MOPSError:
            try:
                entries = self.client.get_multi([
                    ("Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
                     ["dot1qVlanIndex",
                      "dot1qVlanStaticName", "dot1qVlanStaticEgressPorts"]),
                ], decode_strings=False)
                entries = entries["mibs"].get("Q-BRIDGE-MIB", {}).get(
                    "dot1qVlanStaticEntry", [])
            except MOPSError:
                return {}

        vlans = {}
        for entry in entries:
            vlan_name_raw = (entry.get("ieee8021QBridgeVlanStaticName", "") or
                             entry.get("dot1qVlanStaticName", ""))
            vlan_name = _decode_hex_string(vlan_name_raw)

            # VLAN ID from explicitly-requested index attribute
            vlan_id_raw = (entry.get("ieee8021QBridgeVlanStaticVlanIndex", "") or
                           entry.get("dot1qVlanIndex", ""))

            # Egress ports as PortList
            egress_raw = entry.get("ieee8021QBridgeVlanStaticEgressPorts",
                                   entry.get("dot1qVlanStaticEgressPorts", ""))
            ifaces = _decode_portlist_hex(egress_raw, bridge_map) if egress_raw else []

            vlan_id = _safe_int(vlan_id_raw, 0)
            if vlan_id > 0:
                vlans[vlan_id] = {
                    'name': vlan_name,
                    'interfaces': ifaces,
                }

        return vlans

    def get_ntp_servers(self):
        """Return NTP/SNTP servers from HM2-TIMESYNC-MIB/hm2SntpClientServerAddrEntry.

        Confirmed Node name from web UI capture (not hm2SntpClientServerEntry).
        Address is hex-encoded raw IP bytes: "c0 a8 03 01" → 192.168.3.1
        """
        try:
            entries = self.client.get("HM2-TIMESYNC-MIB",
                                      "hm2SntpClientServerAddrEntry",
                                      ["hm2SntpClientServerAddr"],
                                      decode_strings=False)
        except MOPSError:
            return {}

        servers = {}
        for entry in entries:
            addr = _decode_hex_ip(entry.get("hm2SntpClientServerAddr", ""))
            if addr:
                servers[addr] = {}
        return servers

    def get_ntp_stats(self):
        """Return NTP sync stats from HM2-TIMESYNC-MIB.

        Uses hm2SntpClientServerAddrEntry for server list and
        hm2SntpClientGroup for overall client sync status.
        """
        try:
            result = self.client.get_multi([
                ("HM2-TIMESYNC-MIB", "hm2SntpClientServerAddrEntry",
                 ["hm2SntpClientServerAddr", "hm2SntpClientServerStatus"]),
                ("HM2-TIMESYNC-MIB", "hm2SntpClientGroup",
                 ["hm2SntpClientStatus", "hm2SntpClientRequestInterval"]),
            ], decode_strings=False)
        except MOPSError:
            return []

        mibs = result["mibs"]
        server_entries = mibs.get("HM2-TIMESYNC-MIB", {}).get(
            "hm2SntpClientServerAddrEntry", [])
        client_entries = mibs.get("HM2-TIMESYNC-MIB", {}).get(
            "hm2SntpClientGroup", [{}])

        ce = client_entries[0] if client_entries else {}
        client_status = _safe_int(ce.get("hm2SntpClientStatus", "0"))
        # 1=other, 2=disabled, 3=notSynchronized, 4=synchronizedToLocal,
        # 5=synchronizedToRefclock, 6=synchronizedToRemoteServer
        synced = client_status >= 5
        interval = _safe_int(ce.get("hm2SntpClientRequestInterval", "0"))

        stats = []
        for entry in server_entries:
            addr = _decode_hex_ip(entry.get("hm2SntpClientServerAddr", ""))
            if not addr:
                continue
            server_status = _safe_int(entry.get("hm2SntpClientServerStatus", "0"))
            # server_status: 1=other, 2=success, 3=badServer
            # Match SNMP: server_status == 2 means success
            addr_type = 'ipv6' if ':' in addr else 'ipv4'
            stats.append({
                'remote': addr,
                'referenceid': '',
                'synchronized': synced and server_status == 2,
                'stratum': 0,
                'type': addr_type,
                'when': '',
                'hostpoll': interval,
                'reachability': 0,
                'delay': 0.0,
                'offset': 0.0,
                'jitter': 0.0,
            })

        return stats

    def get_users(self):
        """Return user accounts from HM2-USERMGMT-MIB/hm2UserConfigEntry.

        Confirmed attribute names from web UI capture:
          hm2UserName (hex-encoded), hm2UserAccessRole (15=admin, 1=readOnly),
          hm2UserStatus (1=active)
        """
        try:
            # decode_strings=False: hm2UserName is hex-encoded, hm2UserAccessRole
            # value "15" would survive but be consistent with other getters
            entries = self.client.get("HM2-USERMGMT-MIB", "hm2UserConfigEntry",
                                      ["hm2UserName", "hm2UserAccessRole",
                                       "hm2UserStatus"],
                                      decode_strings=False)
        except MOPSError:
            return {}

        users = {}
        for entry in entries:
            name = _decode_hex_string(entry.get("hm2UserName", ""))
            role = _safe_int(entry.get("hm2UserAccessRole", "0"))
            status = _safe_int(entry.get("hm2UserStatus", "0"))

            if not name or status != 1:  # 1=active
                continue

            # HiOS AccessRole value IS the NAPALM level (15=admin, 1=readOnly)
            users[name] = {
                'level': role,
                'password': '',
                'sshkeys': [],
            }

        return users

    def get_optics(self):
        """Return SFP diagnostics from HM2-DEVMGMT-MIB/hm2SfpDiagEntry.

        Confirmed attribute names from web UI capture:
          hm2SfpCurrentTemperature, hm2SfpCurrentTxPower, hm2SfpCurrentRxPower,
          hm2SfpCurrentTxPowerdBm, hm2SfpCurrentRxPowerdBm, ifIndex
        Power values are in units of 0.1 µW. dBm values are hex-encoded strings.
        """
        ifindex_map = self._build_ifindex_map()
        try:
            # decode_strings=False: dBm values are hex-encoded strings
            entries = self.client.get("HM2-DEVMGMT-MIB", "hm2SfpDiagEntry",
                                      ["ifIndex",
                                       "hm2SfpCurrentTxPower",
                                       "hm2SfpCurrentRxPower",
                                       "hm2SfpCurrentTxPowerdBm",
                                       "hm2SfpCurrentRxPowerdBm"],
                                      decode_strings=False)
        except MOPSError:
            return {}

        optics = {}
        for entry in entries:
            ifidx = entry.get("ifIndex", "")
            tx_raw = entry.get("hm2SfpCurrentTxPower", "0")
            rx_raw = entry.get("hm2SfpCurrentRxPower", "0")

            if not ifidx:
                continue

            iface = ifindex_map.get(ifidx, f"if{ifidx}")

            # Use dBm values directly from MOPS (hex-encoded strings like "2d 34 2e 31" = "-4.1")
            tx_dbm_str = _decode_hex_string(entry.get("hm2SfpCurrentTxPowerdBm", ""))
            rx_dbm_str = _decode_hex_string(entry.get("hm2SfpCurrentRxPowerdBm", ""))
            try:
                tx_dbm = float(tx_dbm_str) if tx_dbm_str else -40.0
            except ValueError:
                # Fallback: compute from 0.1 µW
                import math
                tx_uw = _safe_int(tx_raw) / 10.0
                tx_dbm = 10 * math.log10(tx_uw / 1000.0) if tx_uw > 0 else -40.0
            try:
                rx_dbm = float(rx_dbm_str) if rx_dbm_str else -40.0
            except ValueError:
                import math
                rx_uw = _safe_int(rx_raw) / 10.0
                rx_dbm = 10 * math.log10(rx_uw / 1000.0) if rx_uw > 0 else -40.0

            optics[iface] = {
                'physical_channels': {
                    'channel': [{
                        'index': 0,
                        'state': {
                            'input_power': {
                                'instant': round(rx_dbm, 2),
                                'avg': 0.0, 'min': 0.0, 'max': 0.0,
                            },
                            'output_power': {
                                'instant': round(tx_dbm, 2),
                                'avg': 0.0, 'min': 0.0, 'max': 0.0,
                            },
                            'laser_bias_current': {
                                'instant': 0.0,
                                'avg': 0.0, 'min': 0.0, 'max': 0.0,
                            },
                        },
                    }],
                },
            }

        return optics

    def get_environment(self):
        """Return environment data: temperature, PSU, CPU, memory, fans."""
        env = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {},
        }

        # Temperature from HM2-DEVMGMT-MIB, CPU+memory from HM2-DIAGNOSTIC-MIB
        # Confirmed Node names:
        #   hm2DeviceMgmtTemperatureGroup (note: "Device" not "Dev")
        #   hm2DiagCpuResourcesGroup, hm2DiagMemoryResourcesGroup
        try:
            # decode_strings=False: temperature "42" and "70" are valid hex tokens
            # that _decode_hex_string corrupts to ASCII chars 'B' and 'p'
            result = self.client.get_multi([
                ("HM2-DEVMGMT-MIB", "hm2DeviceMgmtTemperatureGroup",
                 ["hm2DevMgmtTemperature",
                  "hm2DevMgmtTemperatureUpperLimit",
                  "hm2DevMgmtTemperatureLowerLimit"]),
                ("HM2-DIAGNOSTIC-MIB", "hm2DiagCpuResourcesGroup",
                 ["hm2DiagCpuUtilization"]),
                ("HM2-DIAGNOSTIC-MIB", "hm2DiagMemoryResourcesGroup",
                 ["hm2DiagMemoryRamAllocated", "hm2DiagMemoryRamFree"]),
            ], decode_strings=False)
            mibs = result["mibs"]

            # Temperature
            temp_entries = mibs.get("HM2-DEVMGMT-MIB", {}).get(
                "hm2DeviceMgmtTemperatureGroup", [])
            if temp_entries:
                t = temp_entries[0]
                temp_val = _safe_int(t.get("hm2DevMgmtTemperature", "0"))
                upper = _safe_int(t.get("hm2DevMgmtTemperatureUpperLimit", "70"))
                env['temperature']['chassis'] = {
                    'temperature': float(temp_val),
                    'is_alert': temp_val >= upper,
                    'is_critical': temp_val >= upper + 10,
                }

            # CPU
            cpu_entries = mibs.get("HM2-DIAGNOSTIC-MIB", {}).get(
                "hm2DiagCpuResourcesGroup", [])
            if cpu_entries:
                cpu_util = _safe_int(cpu_entries[0].get("hm2DiagCpuUtilization", "0"))
                env['cpu']['0'] = {'%usage': float(cpu_util)}

            # Memory — HiOS "allocated" = total pool, "free" = unused
            # Match SNMP driver: available_ram = allocated, used_ram = allocated - free
            mem_entries = mibs.get("HM2-DIAGNOSTIC-MIB", {}).get(
                "hm2DiagMemoryResourcesGroup", [])
            if mem_entries:
                m = mem_entries[0]
                mem_alloc = _safe_int(m.get("hm2DiagMemoryRamAllocated", "0"))
                mem_free = _safe_int(m.get("hm2DiagMemoryRamFree", "0"))
                env['memory'] = {
                    'available_ram': mem_alloc,
                    'used_ram': mem_alloc - mem_free,
                }
        except MOPSError:
            pass

        # Power supplies from HM2-PWRMGMT-MIB
        try:
            psu_entries = self.client.get("HM2-PWRMGMT-MIB", "hm2PSEntry",
                                          ["hm2PSState"])
            for i, entry in enumerate(psu_entries, 1):
                # PSU index may be in _idx_ or inferred from entry order
                idx = entry.get("_idx_hm2PSIndex", str(i))
                state = _safe_int_or_ord(entry.get("hm2PSState", "3"))
                # 1=present, 2=defective, 3=notInstalled, 4=unknown
                if state != 3:  # Skip not-installed
                    env['power'][f'Power Supply P{idx}'] = {
                        'status': state == 1,
                        'capacity': -1.0,
                        'output': -1.0,
                    }
        except MOPSError:
            pass

        # Fans from HM2-FAN-MIB
        try:
            fan_entries = self.client.get("HM2-FAN-MIB", "hm2FanEntry",
                                          ["hm2FanStatus"])
            for i, entry in enumerate(fan_entries, 1):
                idx = entry.get("_idx_hm2FanIndex", str(i))
                status = _safe_int_or_ord(entry.get("hm2FanStatus", "1"))
                # 1=not-available, 2=available-and-ok, 3=available-but-failure
                if status != 1:
                    env['fans'][f'Fan {idx}'] = {
                        'status': status == 2,
                    }
        except MOPSError:
            pass

        return env

    def get_snmp_information(self):
        """Return SNMP system info."""
        entries = self.client.get("SNMPv2-MIB", "system",
                                  ["sysContact", "sysLocation", "sysName"])
        sys_data = entries[0] if entries else {}
        return {
            'chassis_id': sys_data.get("sysName", "").strip(),
            'community': {},  # Cannot query communities via MOPS (security)
            'contact': sys_data.get("sysContact", "").strip(),
            'location': sys_data.get("sysLocation", "").strip(),
        }

    # ------------------------------------------------------------------
    # Vendor-specific getters
    # ------------------------------------------------------------------

    def get_config_status(self):
        """Check if running config is saved to NVM."""
        state = self.client.nvm_state()
        nvm = state.get("hm2FMNvmState", {}).get("label", "unknown")
        envm = state.get("hm2FMEnvmState", {}).get("label", "absent")
        boot = state.get("hm2FMBootParamState", {}).get("label", "ok")
        return {
            'saved': nvm == 'ok',
            'nvm': nvm,
            'aca': envm,
            'boot': boot,
        }

    def save_config(self):
        """Save running config to NVM via MOPS."""
        self.client.save_config()
        return self.get_config_status()

    def clear_config(self, keep_ip=False):
        """Clear running config (back to default) via MOPS.

        WARNING: Device warm-restarts. Connection will drop.
        """
        return self.client.clear_config(keep_ip=keep_ip)

    def clear_factory(self, erase_all=False):
        """Factory reset via MOPS. Device will reboot."""
        return self.client.clear_factory(erase_all=erase_all)

    def get_mrp(self):
        """Return MRP domain configuration and operating state."""
        try:
            entries = self.client.get("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry", [
                "hm2MrpDomainName",
                "hm2MrpRingport1IfIndex", "hm2MrpRingport1OperState",
                "hm2MrpRingport2IfIndex", "hm2MrpRingport2OperState",
                "hm2MrpRoleAdminState", "hm2MrpRoleOperState",
                "hm2MrpRecoveryDelay", "hm2MrpVlanID",
                "hm2MrpMRMPriority", "hm2MrpMRMReactOnLinkChange",
                "hm2MrpMRMRingOpenCount",
                "hm2MrpMRCBlockedSupported",
                "hm2MrpRingOperState", "hm2MrpRedundancyOperState",
                "hm2MrpConfigOperState",
                "hm2MrpRowStatus",
                "hm2MrpRingport2FixedBackup",
                "hm2MrpRecoveryDelaySupported",
            ])
        except MOPSError:
            return {'configured': False}

        if not entries:
            return {'configured': False}

        # Use first entry (default domain)
        e = entries[0]
        ifindex_map = self._build_ifindex_map()

        row_status = _safe_int(e.get("hm2MrpRowStatus", "0"))
        if row_status not in (1, 4):  # active(1) or createAndGo(4)
            return {'configured': False}

        role_admin = _MRP_ROLE.get(e.get("hm2MrpRoleAdminState", "3"), 'undefined')
        role_oper = _MRP_ROLE.get(e.get("hm2MrpRoleOperState", "3"), 'undefined')

        port1_idx = e.get("hm2MrpRingport1IfIndex", "")
        port2_idx = e.get("hm2MrpRingport2IfIndex", "")

        recovery = _MRP_RECOVERY_DELAY.get(e.get("hm2MrpRecoveryDelay", "1"), '500ms')
        recovery_supported_raw = e.get("hm2MrpRecoveryDelaySupported", "")
        recovery_supported = []
        for k, v in _MRP_RECOVERY_DELAY.items():
            recovery_supported.append(v)

        config_state = e.get("hm2MrpConfigOperState", "1")
        ring_state = _MRP_RING_OPER_STATE.get(e.get("hm2MrpRingOperState", "3"), 'undefined')
        redundancy = _safe_int(e.get("hm2MrpRedundancyOperState", "2"))

        mrp = {
            'configured': True,
            'operation': 'enabled' if row_status == 1 else 'disabled',
            'mode': role_admin,
            'mode_actual': role_oper,
            'port_primary': ifindex_map.get(port1_idx, port1_idx),
            'port_secondary': ifindex_map.get(port2_idx, port2_idx),
            'port_primary_state': _MRP_PORT_OPER_STATE.get(
                e.get("hm2MrpRingport1OperState", "4"), 'notConnected'),
            'port_secondary_state': _MRP_PORT_OPER_STATE.get(
                e.get("hm2MrpRingport2OperState", "4"), 'notConnected'),
            'domain_id': '',
            'domain_name': e.get("hm2MrpDomainName", ""),
            'vlan': _safe_int(e.get("hm2MrpVlanID", "0")),
            'recovery_delay': recovery,
            'recovery_delay_supported': recovery_supported,
            'advanced_mode': _safe_int(e.get("hm2MrpMRMReactOnLinkChange", "2")) == 1,
            'manager_priority': _safe_int(e.get("hm2MrpMRMPriority", "32768")),
            'fixed_backup': _safe_int(e.get("hm2MrpRingport2FixedBackup", "2")) == 1,
            'info': _MRP_CONFIG_INFO.get(config_state, 'unknown'),
            'ring_state': ring_state,
            'redundancy': redundancy == 1,
            'ring_open_count': _safe_int(e.get("hm2MrpMRMRingOpenCount", "0")),
            'blocked_support': _safe_int(e.get("hm2MrpMRCBlockedSupported", "2")) == 1,
        }

        return mrp

    def get_hidiscovery(self):
        """Return HiDiscovery protocol status from HM2-NETCONFIG-MIB/hm2NetHiDiscoveryGroup.

        Confirmed attribute names from web UI capture:
          hm2NetHiDiscoveryOperation (1=enabled), hm2NetHiDiscoveryMode (1=readWrite, 2=readOnly),
          hm2NetHiDiscoveryBlinking, hm2NetHiDiscoveryProtocol (BITS), hm2NetHiDiscoveryRelay
        Note: hm2NetHiDiscoveryRelay returns noSuchName on L2 devices (BRS50).
        """
        try:
            entries = self.client.get("HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup", [
                "hm2NetHiDiscoveryOperation", "hm2NetHiDiscoveryMode",
                "hm2NetHiDiscoveryBlinking", "hm2NetHiDiscoveryProtocol",
                "hm2NetHiDiscoveryRelay",
            ], decode_strings=False)
        except MOPSError:
            return {}

        if not entries:
            return {}

        e = entries[0]
        oper = _safe_int(e.get("hm2NetHiDiscoveryOperation", "2"))
        mode_val = _safe_int(e.get("hm2NetHiDiscoveryMode", "2"))
        blinking = _safe_int(e.get("hm2NetHiDiscoveryBlinking", "2")) == 1

        # Protocols: BITS field {none(0),v1(1),v2(2)} — MSB-first
        proto_raw = e.get("hm2NetHiDiscoveryProtocol", "")
        protocols = []
        if proto_raw:
            parts = proto_raw.strip().split()
            if parts:
                try:
                    proto_byte = int(parts[0], 16)
                    if proto_byte & 0x40:
                        protocols.append('v1')
                    if proto_byte & 0x20:
                        protocols.append('v2')
                except ValueError:
                    pass

        result = {
            'enabled': oper == 1,
            'mode': 'read-write' if mode_val == 1 else 'read-only',
            'blinking': blinking,
            'protocols': protocols,
        }

        # Relay — only on L3 devices (noSuchName on BRS50)
        relay_raw = e.get("hm2NetHiDiscoveryRelay", "")
        if relay_raw:
            result['relay'] = _safe_int(relay_raw) == 1

        return result

    def get_profiles(self, storage='nvm'):
        """Return config profile list from HM2-FILEMGMT-MIB."""
        try:
            entries = self.client.get("HM2-FILEMGMT-MIB", "hm2FMProfileEntry", [
                "hm2FMProfileStorageType", "hm2FMProfileIndex",
                "hm2FMProfileName", "hm2FMProfileDateTime",
                "hm2FMProfileActive",
                "hm2FMProfileEncryptionActive",
                "hm2FMProfileEncryptionVerified",
                "hm2FMProfileSwMajorRelNum",
                "hm2FMProfileSwMinorRelNum",
                "hm2FMProfileSwBugfixRelNum",
                "hm2FMProfileFingerprint",
                "hm2FMProfileFingerprintVerified",
            ], decode_strings=False)
        except MOPSError:
            return []

        storage_code = '1' if storage == 'nvm' else '2'
        profiles = []
        for entry in entries:
            st = entry.get("hm2FMProfileStorageType", "1")
            if st != storage_code:
                continue

            idx = _safe_int(entry.get("hm2FMProfileIndex", "0"))
            name = _decode_hex_string(entry.get("hm2FMProfileName", ""))
            active = _safe_int(entry.get("hm2FMProfileActive", "2")) == 1
            major = entry.get("hm2FMProfileSwMajorRelNum", "")
            minor = entry.get("hm2FMProfileSwMinorRelNum", "")
            bugfix = entry.get("hm2FMProfileSwBugfixRelNum", "")
            fw_version = f"{major}.{minor}.{bugfix}" if major else ""
            fingerprint = _decode_hex_string(
                entry.get("hm2FMProfileFingerprint", ""))

            profiles.append({
                'index': idx,
                'name': name,
                'datetime': entry.get("hm2FMProfileDateTime", ""),
                'active': active,
                'firmware_version': fw_version,
                'fingerprint': fingerprint,
                'fingerprint_verified': _safe_int(
                    entry.get("hm2FMProfileFingerprintVerified", "2")) == 1,
                'encrypted': _safe_int(
                    entry.get("hm2FMProfileEncryptionActive", "2")) == 1,
                'encryption_verified': _safe_int(
                    entry.get("hm2FMProfileEncryptionVerified", "2")) == 1,
            })

        return profiles

    def get_config_fingerprint(self):
        """Return the SHA1 fingerprint of the active config profile."""
        profiles = self.get_profiles()
        for p in profiles:
            if p.get('active'):
                return {
                    'fingerprint': p.get('fingerprint', ''),
                    'verified': p.get('fingerprint_verified', False),
                }
        return {'fingerprint': '', 'verified': False}

    # ------------------------------------------------------------------
    # RSTP / Spanning Tree
    # ------------------------------------------------------------------

    # ForwardingState enum from HM2-PLATFORM-SWITCHING-MIB
    _STP_FWD_STATE = {
        '1': 'discarding', '2': 'learning', '3': 'forwarding',
        '4': 'disabled', '5': 'manualFwd', '6': 'notParticipate',
    }
    # ForceVersion enum
    _STP_VERSION = {'1': 'stp', '2': 'rstp', '3': 'mstp'}
    _STP_VERSION_REV = {'stp': '1', 'rstp': '2', 'mstp': '3'}

    def get_rstp(self):
        """Return global STP/RSTP configuration and state."""
        result = self.client.get_multi([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpSwitchConfigGroup", [
                "hm2AgentStpForceVersion",
                "hm2AgentStpAdminMode",
                "hm2AgentStpBpduGuardMode",
                "hm2AgentStpBpduFilterDefault",
            ]),
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstConfigGroup", [
                "hm2AgentStpCstHelloTime",
                "hm2AgentStpCstMaxAge",
                "hm2AgentStpCstRootFwdDelay",
                "hm2AgentStpCstBridgeFwdDelay",
                "hm2AgentStpCstBridgeHelloTime",
                "hm2AgentStpCstBridgeMaxAge",
                "hm2AgentStpCstBridgeMaxHops",
                "hm2AgentStpCstBridgePriority",
                "hm2AgentStpCstBridgeHoldCount",
                "hm2AgentStpCstBridgeHoldTime",
            ]),
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpMstEntry", [
                "hm2AgentStpMstBridgeIdentifier",
                "hm2AgentStpMstDesignatedRootId",
                "hm2AgentStpMstRootPortId",
                "hm2AgentStpMstRootPathCost",
                "hm2AgentStpMstTopologyChangeCount",
                "hm2AgentStpMstTimeSinceTopologyChange",
            ]),
        ], decode_strings=False)

        mibs = result["mibs"]
        sw = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
              .get("hm2AgentStpSwitchConfigGroup", [{}])[0])
        cst = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
               .get("hm2AgentStpCstConfigGroup", [{}])[0])
        mst = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
               .get("hm2AgentStpMstEntry", [{}])[0])

        version_code = sw.get("hm2AgentStpForceVersion", "2")

        def _format_bridge_id(hex_str):
            """Format bridge ID from hex: '80 00 64 60 ...' -> '80:00:64:60:...'"""
            parts = hex_str.strip().split()
            return ":".join(parts) if len(parts) == 8 else hex_str

        bridge_id = _format_bridge_id(
            mst.get("hm2AgentStpMstBridgeIdentifier", ""))
        root_id = _format_bridge_id(
            mst.get("hm2AgentStpMstDesignatedRootId", ""))
        root_port_hex = mst.get("hm2AgentStpMstRootPortId", "00 00")
        root_port_parts = root_port_hex.strip().split()
        if len(root_port_parts) == 2:
            root_port_val = int(root_port_parts[0], 16) * 256 + int(
                root_port_parts[1], 16)
            root_port_num = root_port_val & 0x0FFF
        else:
            root_port_num = 0

        return {
            'enabled': sw.get("hm2AgentStpAdminMode", "2") == "1",
            'mode': self._STP_VERSION.get(version_code, 'rstp'),
            'bridge_id': bridge_id,
            'priority': _safe_int(cst.get("hm2AgentStpCstBridgePriority", "32768")),
            'hello_time': _safe_int(cst.get("hm2AgentStpCstBridgeHelloTime", "2")),
            'max_age': _safe_int(cst.get("hm2AgentStpCstBridgeMaxAge", "20")),
            'forward_delay': _safe_int(cst.get("hm2AgentStpCstBridgeFwdDelay", "15")),
            'hold_count': _safe_int(cst.get("hm2AgentStpCstBridgeHoldCount", "10")),
            'max_hops': _safe_int(cst.get("hm2AgentStpCstBridgeMaxHops", "0")),
            'root_id': root_id,
            'root_port': root_port_num,
            'root_path_cost': _safe_int(
                mst.get("hm2AgentStpMstRootPathCost", "0")),
            'topology_changes': _safe_int(
                mst.get("hm2AgentStpMstTopologyChangeCount", "0")),
            'time_since_topology_change': _safe_int(
                mst.get("hm2AgentStpMstTimeSinceTopologyChange", "0")) // 100,
            'root_hello_time': _safe_int(cst.get("hm2AgentStpCstHelloTime", "2")),
            'root_max_age': _safe_int(cst.get("hm2AgentStpCstMaxAge", "20")),
            'root_forward_delay': _safe_int(
                cst.get("hm2AgentStpCstRootFwdDelay", "15")),
            'bpdu_guard': sw.get("hm2AgentStpBpduGuardMode", "2") == "1",
            'bpdu_filter': sw.get("hm2AgentStpBpduFilterDefault", "2") == "1",
        }

    def get_rstp_port(self, interface=None):
        """Return per-port STP/RSTP state.

        Args:
            interface: optional interface name (e.g. '1/5'). If None, all ports.

        Returns:
            dict keyed by interface name, each value a dict of STP port state.
        """
        result = self.client.get_multi([
            ("IF-MIB", "ifXEntry", ["ifIndex", "ifName"]),
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpPortEntry", [
                "hm2AgentStpPortState",
                "hm2AgentStpPortStatsRstpBpduRx",
                "hm2AgentStpPortStatsRstpBpduTx",
                "hm2AgentStpPortStatsStpBpduRx",
                "hm2AgentStpPortStatsStpBpduTx",
            ]),
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstPortEntry", [
                "hm2AgentStpCstPortEdge",
                "hm2AgentStpCstPortOperEdge",
                "hm2AgentStpCstPortAutoEdge",
                "hm2AgentStpCstPortForwardingState",
                "hm2AgentStpCstPortPathCost",
                "hm2AgentStpCstPortPriority",
                "hm2AgentStpCstPortOperPointToPoint",
                "hm2AgentStpCstPortRootGuard",
                "hm2AgentStpCstPortLoopGuard",
                "hm2AgentStpCstPortTCNGuard",
                "hm2AgentStpCstPortBpduGuardEffect",
                "hm2AgentStpCstPortBpduFilter",
                "hm2AgentStpCstPortBpduFlood",
            ]),
        ], decode_strings=False)

        mibs = result["mibs"]
        ifx = mibs.get("IF-MIB", {}).get("ifXEntry", [])
        stp_ports = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
                     .get("hm2AgentStpPortEntry", []))
        cst_ports = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
                     .get("hm2AgentStpCstPortEntry", []))

        # Build ifIndex→name map from the ifXEntry response
        idx_names = []
        for entry in ifx:
            idx = entry.get("ifIndex", "")
            name = _decode_hex_string(entry.get("ifName", ""))
            if idx and name:
                idx_names.append((idx, name))

        # STP tables are indexed by ifIndex in same order
        ports = {}
        for i, (idx, name) in enumerate(idx_names):
            # Skip cpu/management interfaces
            if name.startswith("cpu"):
                continue
            stp = stp_ports[i] if i < len(stp_ports) else {}
            cst = cst_ports[i] if i < len(cst_ports) else {}

            if interface and name != interface:
                continue

            fwd_state = cst.get("hm2AgentStpCstPortForwardingState", "4")
            ports[name] = {
                'enabled': stp.get("hm2AgentStpPortState", "2") == "1",
                'state': self._STP_FWD_STATE.get(fwd_state, 'disabled'),
                'edge_port': cst.get("hm2AgentStpCstPortEdge", "2") == "1",
                'edge_port_oper': cst.get("hm2AgentStpCstPortOperEdge", "2") == "1",
                'auto_edge': cst.get("hm2AgentStpCstPortAutoEdge", "2") == "1",
                'point_to_point': cst.get(
                    "hm2AgentStpCstPortOperPointToPoint", "2") == "1",
                'path_cost': _safe_int(
                    cst.get("hm2AgentStpCstPortPathCost", "0")),
                'priority': _safe_int(
                    cst.get("hm2AgentStpCstPortPriority", "128")),
                'root_guard': cst.get("hm2AgentStpCstPortRootGuard", "2") == "1",
                'loop_guard': cst.get("hm2AgentStpCstPortLoopGuard", "2") == "1",
                'tcn_guard': cst.get("hm2AgentStpCstPortTCNGuard", "2") == "1",
                'bpdu_guard': cst.get(
                    "hm2AgentStpCstPortBpduGuardEffect", "2") == "1",
                'bpdu_filter': cst.get(
                    "hm2AgentStpCstPortBpduFilter", "2") == "1",
                'bpdu_flood': cst.get(
                    "hm2AgentStpCstPortBpduFlood", "2") == "1",
                'rstp_bpdu_rx': _safe_int(
                    stp.get("hm2AgentStpPortStatsRstpBpduRx", "0")),
                'rstp_bpdu_tx': _safe_int(
                    stp.get("hm2AgentStpPortStatsRstpBpduTx", "0")),
                'stp_bpdu_rx': _safe_int(
                    stp.get("hm2AgentStpPortStatsStpBpduRx", "0")),
                'stp_bpdu_tx': _safe_int(
                    stp.get("hm2AgentStpPortStatsStpBpduTx", "0")),
            }

        return ports

    def set_rstp(self, enabled=None, mode=None, priority=None,
                 hello_time=None, max_age=None, forward_delay=None,
                 hold_count=None, bpdu_guard=None, bpdu_filter=None):
        """Set global STP/RSTP configuration.

        All parameters are optional — only provided values are changed.
        """
        sw_values = {}
        cst_values = {}

        if enabled is not None:
            sw_values["hm2AgentStpAdminMode"] = "1" if enabled else "2"
        if mode is not None:
            if mode not in self._STP_VERSION_REV:
                raise ValueError(
                    f"Invalid mode '{mode}': use 'stp', 'rstp', or 'mstp'")
            sw_values["hm2AgentStpForceVersion"] = self._STP_VERSION_REV[mode]
        if bpdu_guard is not None:
            sw_values["hm2AgentStpBpduGuardMode"] = "1" if bpdu_guard else "2"
        if bpdu_filter is not None:
            sw_values["hm2AgentStpBpduFilterDefault"] = (
                "1" if bpdu_filter else "2")

        if priority is not None:
            cst_values["hm2AgentStpCstBridgePriority"] = str(int(priority))
        if hello_time is not None:
            cst_values["hm2AgentStpCstBridgeHelloTime"] = str(int(hello_time))
        if max_age is not None:
            cst_values["hm2AgentStpCstBridgeMaxAge"] = str(int(max_age))
        if forward_delay is not None:
            cst_values["hm2AgentStpCstBridgeFwdDelay"] = str(int(forward_delay))
        if hold_count is not None:
            cst_values["hm2AgentStpCstBridgeHoldCount"] = str(int(hold_count))

        mutations = []
        if sw_values:
            mutations.append(("HM2-PLATFORM-SWITCHING-MIB",
                              "hm2AgentStpSwitchConfigGroup", sw_values))
        if cst_values:
            mutations.append(("HM2-PLATFORM-SWITCHING-MIB",
                              "hm2AgentStpCstConfigGroup", cst_values))

        if mutations:
            self.client.set_multi(mutations)

        return self.get_rstp()

    def set_rstp_port(self, interface, enabled=None, edge_port=None,
                      auto_edge=None, path_cost=None, priority=None,
                      root_guard=None, loop_guard=None, tcn_guard=None,
                      bpdu_filter=None, bpdu_flood=None):
        """Set per-port STP/RSTP configuration.

        Args:
            interface: port name (e.g. '1/5')
            All other params optional — only provided values are changed.
        """
        # Resolve interface name to ifIndex
        ifindex_map = self._build_ifindex_map()
        ifindex = None
        for idx, name in ifindex_map.items():
            if name == interface:
                ifindex = idx
                break
        if ifindex is None:
            raise ValueError(f"Unknown interface '{interface}'")

        # Port enable/disable is in hm2AgentStpPortEntry (indexed by ifIndex)
        if enabled is not None:
            self.client.set_indexed(
                "HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpPortEntry",
                index={"ifIndex": ifindex},
                values={"hm2AgentStpPortState": "1" if enabled else "2"})

        # CST port settings (indexed by ifIndex)
        cst_values = {}
        if edge_port is not None:
            cst_values["hm2AgentStpCstPortEdge"] = "1" if edge_port else "2"
        if auto_edge is not None:
            cst_values["hm2AgentStpCstPortAutoEdge"] = "1" if auto_edge else "2"
        if path_cost is not None:
            cst_values["hm2AgentStpCstPortPathCost"] = str(int(path_cost))
        if priority is not None:
            cst_values["hm2AgentStpCstPortPriority"] = str(int(priority))
        if root_guard is not None:
            cst_values["hm2AgentStpCstPortRootGuard"] = (
                "1" if root_guard else "2")
        if loop_guard is not None:
            cst_values["hm2AgentStpCstPortLoopGuard"] = (
                "1" if loop_guard else "2")
        if tcn_guard is not None:
            cst_values["hm2AgentStpCstPortTCNGuard"] = (
                "1" if tcn_guard else "2")
        if bpdu_filter is not None:
            cst_values["hm2AgentStpCstPortBpduFilter"] = (
                "1" if bpdu_filter else "2")
        if bpdu_flood is not None:
            cst_values["hm2AgentStpCstPortBpduFlood"] = (
                "1" if bpdu_flood else "2")

        if cst_values:
            self.client.set_indexed(
                "HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstPortEntry",
                index={"ifIndex": ifindex},
                values=cst_values)

    # ------------------------------------------------------------------
    # Vendor setters
    # ------------------------------------------------------------------

    def set_hidiscovery(self, status, blinking=None):
        """Set HiDiscovery operating mode via MOPS.

        Args:
            status: 'on' (read-write), 'off' (disabled), or 'ro' (read-only)
            blinking: True to enable, False to disable, 'toggle' to flip,
                      or None to leave unchanged
        """
        status = status.lower().strip()
        if status not in ('on', 'off', 'ro'):
            raise ValueError(f"Invalid status '{status}': use 'on', 'off', or 'ro'")

        if blinking == 'toggle':
            current = self.get_hidiscovery()
            blinking = not current.get('blinking', False)

        values = {}
        if status == 'off':
            values["hm2NetHiDiscoveryOperation"] = "2"  # disable
        elif status == 'on':
            values["hm2NetHiDiscoveryOperation"] = "1"  # enable
            values["hm2NetHiDiscoveryMode"] = "1"        # readWrite
        elif status == 'ro':
            values["hm2NetHiDiscoveryOperation"] = "1"  # enable
            values["hm2NetHiDiscoveryMode"] = "2"        # readOnly

        if blinking is not None:
            values["hm2NetHiDiscoveryBlinking"] = "1" if blinking else "2"

        self.client.set("HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup", values)
        return self.get_hidiscovery()

    def set_mrp(self, operation='enable', mode='client', port_primary=None,
                port_secondary=None, vlan=None, recovery_delay=None):
        """Configure MRP ring on the default domain via MOPS.

        Args:
            operation: 'enable' or 'disable'
            mode: 'manager' or 'client'
            port_primary: primary ring port (e.g. '1/3')
            port_secondary: secondary ring port (e.g. '1/4')
            vlan: VLAN ID for MRP domain (0-4042)
            recovery_delay: '200ms', '500ms', '30ms', or '10ms'
        """
        if operation not in ('enable', 'disable'):
            raise ValueError(f"operation must be 'enable' or 'disable', got '{operation}'")
        if mode not in ('manager', 'client'):
            raise ValueError(f"mode must be 'manager' or 'client', got '{mode}'")

        # Default domain ID: 16 bytes of 0xFF
        domain_id = "ff " * 16
        domain_id = domain_id.strip()
        idx = {"hm2MrpDomainID": domain_id}

        # Try to create domain — if it already exists, just put it in notInService
        try:
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx,
                                    values={"hm2MrpRowStatus": "5"})  # createAndWait
        except (MOPSError, ConnectionException):
            pass  # domain already exists

        if operation == 'disable':
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx,
                                    values={"hm2MrpRowStatus": "2"})  # notInService
        else:
            # Ensure notInService for modification
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx,
                                    values={"hm2MrpRowStatus": "2"})

            # Build ifName → ifIndex reverse map for port resolution
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {name: idx_val for idx_val, name in ifindex_map.items()}

            # Set parameters
            values = {"hm2MrpRoleAdminState": _MRP_ROLE_REV[mode]}

            if port_primary:
                pidx = name_to_idx.get(port_primary)
                if pidx is None:
                    raise ValueError(f"Unknown port '{port_primary}'")
                values["hm2MrpRingport1IfIndex"] = pidx

            if port_secondary:
                pidx = name_to_idx.get(port_secondary)
                if pidx is None:
                    raise ValueError(f"Unknown port '{port_secondary}'")
                values["hm2MrpRingport2IfIndex"] = pidx

            if vlan is not None:
                values["hm2MrpVlanID"] = str(int(vlan))

            if recovery_delay:
                delay_val = _MRP_RECOVERY_DELAY_REV.get(recovery_delay)
                if delay_val is None:
                    raise ValueError(f"Invalid recovery_delay '{recovery_delay}'")
                values["hm2MrpRecoveryDelay"] = delay_val

            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx, values=values)

            # Activate
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx,
                                    values={"hm2MrpRowStatus": "1"})  # active

        return {'configured': True, 'operation': 'enabled' if operation == 'enable' else 'disabled'}

    def delete_mrp(self):
        """Delete the MRP default domain via MOPS."""
        domain_id = "ff " * 16
        domain_id = domain_id.strip()
        idx = {"hm2MrpDomainID": domain_id}

        try:
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx,
                                    values={"hm2MrpRowStatus": "2"})  # notInService
        except (MOPSError, ConnectionException):
            pass
        try:
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry",
                                    index=idx,
                                    values={"hm2MrpRowStatus": "6"})  # destroy
        except (MOPSError, ConnectionException):
            pass

        return {'configured': False}

    def activate_profile(self, storage='nvm', index=1):
        """Activate a config profile. Note: causes a warm restart.

        Args:
            storage: 'nvm' or 'envm'
            index: profile index (1-100)
        """
        storage_code = '1' if storage == 'nvm' else '2' if storage == 'envm' else None
        if storage_code is None:
            raise ValueError(f"Invalid storage '{storage}': use 'nvm' or 'envm'")

        self.client.set_indexed("HM2-FILEMGMT-MIB", "hm2FMProfileEntry",
                                index={
                                    "hm2FMProfileStorageType": storage_code,
                                    "hm2FMProfileIndex": str(index),
                                },
                                values={"hm2FMProfileActive": "1"})
        return self.get_profiles(storage)

    def delete_profile(self, storage='nvm', index=1):
        """Delete a config profile. Cannot delete the active profile.

        Args:
            storage: 'nvm' or 'envm'
            index: profile index (1-100)
        """
        storage_code = '1' if storage == 'nvm' else '2' if storage == 'envm' else None
        if storage_code is None:
            raise ValueError(f"Invalid storage '{storage}': use 'nvm' or 'envm'")

        # Check the profile is not active
        profiles = self.get_profiles(storage)
        for p in profiles:
            if p['index'] == index and p['active']:
                raise ValueError(f"Cannot delete active profile {index}")

        self.client.set_indexed("HM2-FILEMGMT-MIB", "hm2FMProfileEntry",
                                index={
                                    "hm2FMProfileStorageType": storage_code,
                                    "hm2FMProfileIndex": str(index),
                                },
                                values={"hm2FMProfileAction": "2"})  # delete
        return self.get_profiles(storage)
