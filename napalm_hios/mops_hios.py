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

# SRM (Sub-Ring Manager) enum mappings
_SRM_ADMIN_STATE = {'1': 'manager', '2': 'redundantManager', '3': 'singleManager'}
_SRM_OPER_STATE = {'1': 'manager', '2': 'redundantManager', '3': 'singleManager', '4': 'disabled'}
_SRM_PORT_OPER_STATE = {'1': 'disabled', '2': 'blocked', '3': 'forwarding', '4': 'not-connected'}
_SRM_RING_OPER_STATE = {'1': 'undefined', '2': 'open', '3': 'closed'}
_SRM_REDUNDANCY = {'1': True, '2': False}
_SRM_CONFIG_INFO = {
    '1': 'no error', '2': 'ring port link error', '3': 'multiple SRM',
    '4': 'no partner manager', '5': 'concurrent VLAN', '6': 'concurrent port',
    '7': 'concurrent redundancy', '8': 'trunk member', '9': 'shared VLAN',
}
_SRM_ADMIN_STATE_REV = {'manager': '1', 'redundantManager': '2', 'singleManager': '3'}

# Auto-disable error reason enum (hm2AutoDisableIntfErrorReason)
_AUTO_DISABLE_REASONS = {
    '0': 'none', '1': 'link-flap', '2': 'crc-error', '3': 'duplex-mismatch',
    '4': 'dhcp-snooping', '5': 'arp-rate', '6': 'bpdu-rate',
    '7': 'mac-based-port-security', '8': 'overload-detection',
    '9': 'speed-duplex', '10': 'loop-protection',
}
_AUTO_DISABLE_REASONS_REV = {v: k for k, v in _AUTO_DISABLE_REASONS.items() if v != 'none'}

# Auto-disable reason category (hm2AutoDisableReasonCategory)
_AUTO_DISABLE_CATEGORY = {
    '1': 'other', '2': 'port-monitor', '3': 'network-security', '4': 'l2-redundancy',
}

# Loop protection action enum (hm2AgentKeepalivePortRxAction)
_LOOP_PROT_ACTION = {'10': 'trap', '11': 'auto-disable', '12': 'all'}
_LOOP_PROT_ACTION_REV = {'trap': '10', 'auto-disable': '11', 'all': '12'}

# Loop protection mode enum (hm2AgentKeepalivePortMode)
_LOOP_PROT_MODE = {'1': 'active', '2': 'passive'}
_LOOP_PROT_MODE_REV = {'active': '1', 'passive': '2'}

# Loop protection tpid type (hm2AgentKeepalivePortTpidType)
_LOOP_PROT_TPID = {'0': 'none', '1': 'dot1q', '2': 'dot1ad'}
_LOOP_PROT_TPID_REV = {'none': '0', 'dot1q': '1', 'dot1ad': '2'}

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


def _decode_date_time(hex_str):
    """Decode SNMP DateAndTime (8 or 11 bytes) to ISO string.

    Format: year(2) month(1) day(1) hour(1) min(1) sec(1) decisec(1)
    Returns '' for zero/empty values.
    """
    if not hex_str or not hex_str.strip():
        return ''
    parts = hex_str.strip().split()
    # Mangled binary string — re-encode
    if not all(len(p) == 2 for p in parts):
        parts = [f"{ord(c):02x}" for c in hex_str]
    if len(parts) < 8:
        return ''
    try:
        raw = bytes.fromhex("".join(parts[:8]))
        year = (raw[0] << 8) | raw[1]
        month, day, hour, minute, sec = raw[2], raw[3], raw[4], raw[5], raw[6]
        if year <= 1970:
            return ''
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"
    except (ValueError, IndexError):
        return ''


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


def _encode_hex_ip(ip_str):
    """Encode IPv4 address to MOPS hex format. '192.168.1.4' -> 'c0 a8 01 04'"""
    parts = ip_str.split('.')
    return ' '.join(f'{int(p):02x}' for p in parts)


def _mask_to_prefix(mask_str):
    """Convert dotted subnet mask to prefix length."""
    try:
        parts = [int(p) for p in mask_str.split('.')]
        bits = ''.join(f'{p:08b}' for p in parts)
        return bits.count('1')
    except (ValueError, AttributeError):
        return 32


def _prefix_to_mask(prefix):
    """Convert prefix length to dotted subnet mask. 24 -> '255.255.255.0'"""
    prefix = int(prefix)
    if prefix < 0 or prefix > 32:
        return '0.0.0.0'
    bits = ('1' * prefix).ljust(32, '0')
    return '.'.join(str(int(bits[i:i+8], 2)) for i in range(0, 32, 8))


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


def _encode_portlist_hex(interfaces, ifindex_map):
    """Encode interface names to PortList hex string for MOPS.

    Reverse of _decode_portlist_hex(). Returns space-separated hex bytes
    (e.g. "c0 00 00 00"). ifindex_map maps ifIndex/bridge port → name,
    so we reverse it to name → bridge port.
    """
    name_to_bp = {name: int(bp) for bp, name in ifindex_map.items()}
    bp_nums = []
    for iface in interfaces:
        bp = name_to_bp.get(iface)
        if bp is None:
            raise ValueError(f"Unknown interface '{iface}'")
        bp_nums.append(bp)
    max_port = max(bp_nums) if bp_nums else 0
    num_bytes = (max_port + 7) // 8 if max_port else 0
    bitmap = bytearray(num_bytes)
    for bp in bp_nums:
        byte_idx = (bp - 1) // 8
        bit_idx = (bp - 1) % 8
        bitmap[byte_idx] |= (0x80 >> bit_idx)
    return " ".join(f"{b:02x}" for b in bitmap)


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

    def _get_with_ifindex(self, *tables, decode_strings=False):
        """Fetch tables via get_multi, bundling IF-MIB/ifXEntry when cache is cold.

        On cold cache: adds ifXEntry to the request so ifindex map is built
        from the same HTTP POST as the getter's own data (1 POST instead of 2).
        On warm cache: fetches only the requested tables (ifindex from cache).

        Returns (mibs_dict, ifindex_map) where mibs_dict is
        result["mibs"] from get_multi.
        """
        table_list = list(tables)
        need_cache = self._ifindex_map is None
        if need_cache:
            table_list.append(("IF-MIB", "ifXEntry", ["ifIndex", "ifName"]))

        result = self.client.get_multi(table_list, decode_strings=decode_strings)
        mibs = result["mibs"]

        if need_cache:
            if_entries = mibs.get("IF-MIB", {}).get("ifXEntry", [])
            self._ifindex_map = {}
            for entry in if_entries:
                idx = entry.get("ifIndex", "")
                name = _decode_hex_string(entry.get("ifName", ""))
                if idx and name:
                    self._ifindex_map[idx] = name

        return mibs, self._ifindex_map

    # ------------------------------------------------------------------
    # Staging support
    # ------------------------------------------------------------------

    def start_staging(self):
        """Enter staging mode — mutations are queued, not sent.

        Staging batches mutations into one atomic POST.
        The driver does not validate dependencies between staged operations.
        Operations that depend on prior state (e.g. set_vlan_egress requires
        the VLAN to exist) must have their prerequisites committed first.
        Tool layer is responsible for operation ordering.

        VLAN CRUD (create/update/delete_vlan) always fires immediately
        regardless of staging mode.
        """
        self._staging = True
        self._mutations = []

    def commit_staging(self):
        """Fire all queued mutations in one atomic POST.

        Applies staged mutations to running config via set_multi().
        Does NOT save to NVM — call save_config() separately when ready.
        """
        if not self._mutations:
            self._staging = False
            return
        self.client.set_multi(self._mutations)
        self._staging = False
        self._mutations = []

    def discard_staging(self):
        """Clear queued mutations without sending."""
        self._staging = False
        self._mutations = []

    def get_staged_mutations(self):
        """Return list of staged mutation tuples for compare_config."""
        return list(self._mutations)

    def _apply_mutations(self, mutations):
        """Send mutations immediately or queue them if staging.

        mutations: list of (mib, node, values[, index]) tuples.
        """
        if not mutations:
            return
        if self._staging:
            self._mutations.extend(mutations)
        else:
            self.client.set_multi(mutations)

    def _apply_set_indexed(self, mib, node, index, values):
        """set_indexed() that respects staging mode.

        Converts to a mutation tuple and queues if staging, otherwise
        calls client.set_indexed() directly.
        """
        if self._staging:
            self._mutations.append((mib, node, values, index))
        else:
            self.client.set_indexed(mib, node, index=index, values=values)

    def _apply_set(self, mib, node, values):
        """set() that respects staging mode.

        Converts to a mutation tuple and queues if staging, otherwise
        calls client.set() directly.
        """
        if self._staging:
            self._mutations.append((mib, node, values))
        else:
            self.client.set(mib, node, values)

    # ------------------------------------------------------------------
    # Standard NAPALM getters
    # ------------------------------------------------------------------

    def get_facts(self):
        """Return device facts from SNMPv2-MIB + IF-MIB + HM2 private MIBs.

        Single get_multi fetches all 4 MIB tables in one HTTP POST.
        """
        # decode_strings=False: ifIndex values like "10","11","25" are valid hex
        # tokens that _decode_hex_string corrupts. Manually decode text fields.
        result = self.client.get_multi([
            ("SNMPv2-MIB", "system",
             ["sysDescr", "sysName", "sysUpTime", "sysContact", "sysLocation"]),
            ("IF-MIB", "ifXEntry", ["ifIndex", "ifName"]),
            ("HM2-DEVMGMT-MIB", "hm2DeviceMgmtGroup",
             ["hm2DevMgmtProductDescr", "hm2DevMgmtSerialNumber"]),
            ("HM2-DEVMGMT-MIB", "hm2DevMgmtSwVersEntry",
             ["hm2DevMgmtSwVersion", "hm2DevMgmtSwFileLocation",
              "hm2DevMgmtSwFileIdx"]),
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

        # Product description and serial from private MIBs
        serial = ""
        hm2 = mibs.get("HM2-DEVMGMT-MIB", {})
        hm2_entries = hm2.get("hm2DeviceMgmtGroup", [])
        if hm2_entries:
            product_descr = _decode_hex_string(hm2_entries[0].get("hm2DevMgmtProductDescr", ""))
            serial = _decode_hex_string(hm2_entries[0].get("hm2DevMgmtSerialNumber", ""))
            if product_descr:
                model = product_descr

        # Firmware version from software version table
        # RAM entry (FileLocation=1) with FileIdx=1 = running version
        fw_entries = hm2.get("hm2DevMgmtSwVersEntry", [])
        for entry in fw_entries:
            loc = entry.get("hm2DevMgmtSwFileLocation", "")
            idx = entry.get("hm2DevMgmtSwFileIdx", "")
            if loc == "1" and idx == "1":
                raw_version = _decode_hex_string(entry.get("hm2DevMgmtSwVersion", ""))
                if raw_version:
                    os_version = raw_version.split()[0] if ' ' in raw_version else raw_version
                break

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
        # decode_strings=False: ipAdEntIfIndex values like "25" are valid hex
        mibs, ifindex_map = self._get_with_ifindex(
            ("IP-MIB", "ipAddrEntry",
             ["ipAdEntAddr", "ipAdEntIfIndex", "ipAdEntNetMask"]),
            decode_strings=False,
        )
        entries = mibs.get("IP-MIB", {}).get("ipAddrEntry", [])
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
        # decode_strings=False: port ID and chassis ID contain binary MACs
        mibs, ifindex_map = self._get_with_ifindex(
            ("LLDP-MIB", "lldpRemEntry",
             ["lldpRemLocalPortNum", "lldpRemSysName",
              "lldpRemPortId", "lldpRemChassisId"]),
            decode_strings=False,
        )
        entries = mibs.get("LLDP-MIB", {}).get("lldpRemEntry", [])
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
        """Return detailed LLDP neighbor info from LLDP-MIB.

        Single get_multi fetches lldpRemEntry + lldpRemManAddrEntry in one HTTP POST.
        """
        # decode_strings=False: chassis/port IDs are binary MACs, capabilities are bitmaps
        try:
            mibs, ifindex_map = self._get_with_ifindex(
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
                decode_strings=False,
            )
        except MOPSError:
            return {}

        entries = mibs.get("LLDP-MIB", {}).get("lldpRemEntry", [])
        mgmt_entries = mibs.get("LLDP-MIB", {}).get("lldpRemManAddrEntry", [])

        # Build management address map from inline results
        mgmt_map = {}
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
        # Fetch standard LLDP + management addresses + DOT3 extensions in one get_multi
        try:
            mibs, ifindex_map = self._get_with_ifindex(
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
                decode_strings=False,
            )
        except MOPSError:
            return {}

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
        # decode_strings=False: FDB address is binary MAC
        try:
            mibs, ifindex_map = self._get_with_ifindex(
                ("IEEE8021-Q-BRIDGE-MIB", "ieee8021QBridgeTpFdbEntry",
                 ["ieee8021QBridgeTpFdbAddress",
                  "ieee8021QBridgeTpFdbPort",
                  "ieee8021QBridgeTpFdbStatus",
                  "ieee8021QBridgeFdbId"]),
                decode_strings=False,
            )
            entries = mibs.get("IEEE8021-Q-BRIDGE-MIB", {}).get(
                "ieee8021QBridgeTpFdbEntry", [])
        except MOPSError:
            try:
                mibs, ifindex_map = self._get_with_ifindex(
                    ("Q-BRIDGE-MIB", "dot1qTpFdbEntry",
                     ["dot1qTpFdbAddress",
                      "dot1qTpFdbPort",
                      "dot1qTpFdbStatus",
                      "dot1qFdbId"]),
                    decode_strings=False,
                )
                entries = mibs.get("Q-BRIDGE-MIB", {}).get(
                    "dot1qTpFdbEntry", [])
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
        # decode_strings=False: MAC address is binary
        mibs, ifindex_map = self._get_with_ifindex(
            ("IP-MIB", "ipNetToMediaEntry",
             ["ipNetToMediaIfIndex", "ipNetToMediaPhysAddress",
              "ipNetToMediaNetAddress", "ipNetToMediaType"]),
            decode_strings=False,
        )
        entries = mibs.get("IP-MIB", {}).get("ipNetToMediaEntry", [])
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

    def get_vlan_ingress(self, *ports):
        """Return per-port ingress settings from Q-BRIDGE-MIB via MOPS."""
        bridge_map = self._get_bridge_port_map()

        try:
            entries = self.client.get("Q-BRIDGE-MIB", "dot1qPortVlanEntry",
                                      ["dot1dBasePort", "dot1qPvid",
                                       "dot1qPortAcceptableFrameTypes",
                                       "dot1qPortIngressFiltering"],
                                      decode_strings=False)
        except MOPSError:
            return {}

        port_set = set(ports) if ports else None
        result = {}
        for entry in entries:
            bp = entry.get("dot1dBasePort", "")
            name = bridge_map.get(str(bp), f'port{bp}')
            if port_set and name not in port_set:
                continue
            ft_val = _safe_int(entry.get("dot1qPortAcceptableFrameTypes", "1"))
            filt_val = _safe_int(entry.get("dot1qPortIngressFiltering", "2"))
            result[name] = {
                'pvid': _safe_int(entry.get("dot1qPvid", "1")),
                'frame_types': 'admit_only_tagged' if ft_val == 2 else 'admit_all',
                'ingress_filtering': filt_val == 1,
            }
        return result

    def get_vlan_egress(self, *ports):
        """Return per-VLAN-per-port membership (T/U/F) via MOPS."""
        bridge_map = self._get_bridge_port_map()

        try:
            entries = self.client.get("IEEE8021-Q-BRIDGE-MIB",
                                      "ieee8021QBridgeVlanStaticEntry",
                                      ["ieee8021QBridgeVlanStaticVlanIndex",
                                       "ieee8021QBridgeVlanStaticName",
                                       "ieee8021QBridgeVlanStaticEgressPorts",
                                       "ieee8021QBridgeVlanStaticUntaggedPorts",
                                       "ieee8021QBridgeVlanStaticForbiddenEgressPorts"],
                                      decode_strings=False)
        except MOPSError:
            try:
                entries = self.client.get_multi([
                    ("Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
                     ["dot1qVlanIndex",
                      "dot1qVlanStaticName",
                      "dot1qVlanStaticEgressPorts",
                      "dot1qVlanStaticUntaggedPorts",
                      "dot1qVlanStaticForbiddenEgressPorts"]),
                ], decode_strings=False)
                entries = entries["mibs"].get("Q-BRIDGE-MIB", {}).get(
                    "dot1qVlanStaticEntry", [])
            except MOPSError:
                return {}

        port_set = set(ports) if ports else None
        vlans = {}
        for entry in entries:
            vlan_id_raw = (entry.get("ieee8021QBridgeVlanStaticVlanIndex", "") or
                           entry.get("dot1qVlanIndex", ""))
            vlan_id = _safe_int(vlan_id_raw, 0)
            if vlan_id <= 0:
                continue

            vlan_name = _decode_hex_string(
                entry.get("ieee8021QBridgeVlanStaticName", "") or
                entry.get("dot1qVlanStaticName", ""))

            egress_raw = (entry.get("ieee8021QBridgeVlanStaticEgressPorts", "") or
                          entry.get("dot1qVlanStaticEgressPorts", ""))
            untagged_raw = (entry.get("ieee8021QBridgeVlanStaticUntaggedPorts", "") or
                            entry.get("dot1qVlanStaticUntaggedPorts", ""))
            forbidden_raw = (entry.get("ieee8021QBridgeVlanStaticForbiddenEgressPorts", "") or
                             entry.get("dot1qVlanStaticForbiddenEgressPorts", ""))

            egress_ifaces = set(_decode_portlist_hex(egress_raw, bridge_map))
            untagged_ifaces = set(_decode_portlist_hex(untagged_raw, bridge_map))
            forbidden_ifaces = set(_decode_portlist_hex(forbidden_raw, bridge_map))

            port_modes = {}
            for iface in egress_ifaces:
                if port_set and iface not in port_set:
                    continue
                if iface in untagged_ifaces:
                    port_modes[iface] = 'untagged'
                else:
                    port_modes[iface] = 'tagged'
            for iface in forbidden_ifaces:
                if iface not in egress_ifaces:
                    if port_set and iface not in port_set:
                        continue
                    port_modes[iface] = 'forbidden'

            if port_modes or not port_set:
                vlans[vlan_id] = {'name': vlan_name, 'ports': port_modes}

        return vlans

    def set_vlan_ingress(self, port, pvid=None, frame_types=None,
                         ingress_filtering=None):
        """Set ingress parameters on one or more ports via MOPS.

        Args:
            port: port name (str) or list of port names
            pvid, frame_types, ingress_filtering: applied to all ports
        """
        ports = [port] if isinstance(port, str) else list(port)
        bridge_map = self._get_bridge_port_map()
        name_to_bp = {name: bp for bp, name in bridge_map.items()}

        values = {}
        if pvid is not None:
            values["dot1qPvid"] = str(int(pvid))
        if frame_types is not None:
            if frame_types == 'admit_only_tagged':
                values["dot1qPortAcceptableFrameTypes"] = "2"
            elif frame_types == 'admit_all':
                values["dot1qPortAcceptableFrameTypes"] = "1"
            else:
                raise ValueError(
                    f"Invalid frame_types '{frame_types}': "
                    f"use 'admit_all' or 'admit_only_tagged'")
        if ingress_filtering is not None:
            values["dot1qPortIngressFiltering"] = "1" if ingress_filtering else "2"

        if not values:
            return

        mutations = []
        for p in ports:
            bp = name_to_bp.get(p)
            if bp is None:
                raise ValueError(f"Unknown interface '{p}'")
            mutations.append(("Q-BRIDGE-MIB", "dot1qPortVlanEntry",
                              dict(values), {"dot1dBasePort": bp}))

        self._apply_mutations(mutations)

    def set_vlan_egress(self, vlan_id, port, mode):
        """Set port(s) VLAN membership via MOPS.

        Reads the current raw hex bitmaps once, modifies all target ports'
        bits, and writes back in one SET. Uses Q-BRIDGE-MIB for SET
        (IEEE8021 SET fails on HiOS despite GET working).

        Args:
            vlan_id: VLAN ID (must already exist)
            port: port name (str) or list of port names
            mode: 'tagged', 'untagged', 'forbidden', or 'none'
        """
        if mode not in ('tagged', 'untagged', 'forbidden', 'none'):
            raise ValueError(
                f"Invalid mode '{mode}': use 'tagged', 'untagged', "
                f"'forbidden', or 'none'")

        ports = [port] if isinstance(port, str) else list(port)
        bridge_map = self._get_bridge_port_map()
        name_to_bp = {name: int(bp) for bp, name in bridge_map.items()}

        # Validate all ports up front
        bps = []
        for p in ports:
            bp = name_to_bp.get(p)
            if bp is None:
                raise ValueError(f"Unknown interface '{p}'")
            bps.append(bp)

        # Read current raw hex bitmaps for all VLANs (one GET)
        try:
            entries = self.client.get("IEEE8021-Q-BRIDGE-MIB",
                                      "ieee8021QBridgeVlanStaticEntry",
                                      ["ieee8021QBridgeVlanStaticVlanIndex",
                                       "ieee8021QBridgeVlanStaticEgressPorts",
                                       "ieee8021QBridgeVlanStaticUntaggedPorts",
                                       "ieee8021QBridgeVlanStaticForbiddenEgressPorts"],
                                      decode_strings=False)
            vid_key = "ieee8021QBridgeVlanStaticVlanIndex"
            egress_key = "ieee8021QBridgeVlanStaticEgressPorts"
            untagged_key = "ieee8021QBridgeVlanStaticUntaggedPorts"
            forbidden_key = "ieee8021QBridgeVlanStaticForbiddenEgressPorts"
        except MOPSError:
            entries = self.client.get_multi([
                ("Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
                 ["dot1qVlanIndex",
                  "dot1qVlanStaticEgressPorts",
                  "dot1qVlanStaticUntaggedPorts",
                  "dot1qVlanStaticForbiddenEgressPorts"]),
            ], decode_strings=False)
            entries = entries["mibs"].get("Q-BRIDGE-MIB", {}).get(
                "dot1qVlanStaticEntry", [])
            vid_key = "dot1qVlanIndex"
            egress_key = "dot1qVlanStaticEgressPorts"
            untagged_key = "dot1qVlanStaticUntaggedPorts"
            forbidden_key = "dot1qVlanStaticForbiddenEgressPorts"

        # Find our VLAN's raw hex bitmaps
        target = None
        for entry in entries:
            if _safe_int(entry.get(vid_key, ""), 0) == vlan_id:
                target = entry
                break
        if target is None:
            raise ValueError(f"VLAN {vlan_id} does not exist")

        egress_hex = target.get(egress_key, "") or ""
        untagged_hex = target.get(untagged_key, "") or ""
        forbidden_hex = target.get(forbidden_key, "") or ""

        # Parse hex to mutable bytearrays
        def _hex_to_bytearray(h):
            h = h.strip()
            if not h:
                return bytearray(4)  # default 4 bytes
            try:
                return bytearray(bytes.fromhex(h.replace(" ", "")))
            except ValueError:
                return bytearray(4)

        egress = _hex_to_bytearray(egress_hex)
        untagged = _hex_to_bytearray(untagged_hex)
        forbidden = _hex_to_bytearray(forbidden_hex)

        # Modify bits for ALL target ports
        for bp in bps:
            byte_idx = (bp - 1) // 8
            bit_mask = 0x80 >> ((bp - 1) % 8)
            for arr in (egress, untagged, forbidden):
                while len(arr) <= byte_idx:
                    arr.append(0)

            if mode == 'tagged':
                egress[byte_idx] |= bit_mask
                untagged[byte_idx] &= ~bit_mask
                forbidden[byte_idx] &= ~bit_mask
            elif mode == 'untagged':
                egress[byte_idx] |= bit_mask
                untagged[byte_idx] |= bit_mask
                forbidden[byte_idx] &= ~bit_mask
            elif mode == 'forbidden':
                egress[byte_idx] &= ~bit_mask
                untagged[byte_idx] &= ~bit_mask
                forbidden[byte_idx] |= bit_mask
            elif mode == 'none':
                egress[byte_idx] &= ~bit_mask
                untagged[byte_idx] &= ~bit_mask
                forbidden[byte_idx] &= ~bit_mask

        # Encode back to space-separated hex
        def _bytearray_to_hex(ba):
            return " ".join(f"{b:02x}" for b in ba)

        # SET via Q-BRIDGE (IEEE8021 SET fails on HiOS).
        # EgressPorts + UntaggedPorts must be set together.
        # ForbiddenEgressPorts must be set separately — combining all three
        # in one request causes the device to silently reject the change.
        idx = {"dot1qVlanIndex": str(vlan_id)}
        self._apply_set_indexed(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry", index=idx,
            values={
                "dot1qVlanStaticEgressPorts": _bytearray_to_hex(egress),
                "dot1qVlanStaticUntaggedPorts": _bytearray_to_hex(untagged),
            })
        if mode == 'forbidden' or forbidden_hex.replace(' ', '').replace('0', ''):
            self._apply_set_indexed(
                "Q-BRIDGE-MIB", "dot1qVlanStaticEntry", index=idx,
                values={
                    "dot1qVlanStaticForbiddenEgressPorts": _bytearray_to_hex(forbidden),
                })

    def set_access_port(self, port, vlan_id):
        """Atomically configure port(s) as untagged access on a single VLAN.

        For each target port:
        1. Removes port from ALL current VLANs (egress bitmap → none)
        2. Adds port to target VLAN as untagged
        3. Sets PVID to target VLAN

        All changes are sent in one atomic POST via set_multi.

        Args:
            port: port name (str) or list of port names
            vlan_id: target VLAN ID (must already exist)
        """
        ports = [port] if isinstance(port, str) else list(port)
        bridge_map = self._get_bridge_port_map()
        name_to_bp = {name: int(bp) for bp, name in bridge_map.items()}

        # Validate all ports
        bps = []
        for p in ports:
            bp = name_to_bp.get(p)
            if bp is None:
                raise ValueError(f"Unknown interface '{p}'")
            bps.append(bp)

        # Read current egress bitmaps for all VLANs
        try:
            entries = self.client.get("IEEE8021-Q-BRIDGE-MIB",
                                      "ieee8021QBridgeVlanStaticEntry",
                                      ["ieee8021QBridgeVlanStaticVlanIndex",
                                       "ieee8021QBridgeVlanStaticEgressPorts",
                                       "ieee8021QBridgeVlanStaticUntaggedPorts",
                                       "ieee8021QBridgeVlanStaticForbiddenEgressPorts"],
                                      decode_strings=False)
            vid_key = "ieee8021QBridgeVlanStaticVlanIndex"
            egress_key = "ieee8021QBridgeVlanStaticEgressPorts"
            untagged_key = "ieee8021QBridgeVlanStaticUntaggedPorts"
            forbidden_key = "ieee8021QBridgeVlanStaticForbiddenEgressPorts"
        except MOPSError:
            entries = self.client.get_multi([
                ("Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
                 ["dot1qVlanIndex",
                  "dot1qVlanStaticEgressPorts",
                  "dot1qVlanStaticUntaggedPorts",
                  "dot1qVlanStaticForbiddenEgressPorts"]),
            ], decode_strings=False)
            entries = entries["mibs"].get("Q-BRIDGE-MIB", {}).get(
                "dot1qVlanStaticEntry", [])
            vid_key = "dot1qVlanIndex"
            egress_key = "dot1qVlanStaticEgressPorts"
            untagged_key = "dot1qVlanStaticUntaggedPorts"
            forbidden_key = "dot1qVlanStaticForbiddenEgressPorts"

        def _hex_to_bytearray(h):
            h = (h or "").strip()
            if not h:
                return bytearray(4)
            try:
                return bytearray(bytes.fromhex(h.replace(" ", "")))
            except ValueError:
                return bytearray(4)

        def _bytearray_to_hex(ba):
            return " ".join(f"{b:02x}" for b in ba)

        # Build mutations: for each VLAN, remove port bits; for target, add
        mutations = []
        target_found = False
        for entry in entries:
            vid = _safe_int(entry.get(vid_key, ""), 0)
            if vid <= 0:
                continue

            egress = _hex_to_bytearray(entry.get(egress_key, ""))
            untagged = _hex_to_bytearray(entry.get(untagged_key, ""))
            forbidden = _hex_to_bytearray(entry.get(forbidden_key, ""))
            changed = False

            for bp in bps:
                byte_idx = (bp - 1) // 8
                bit_mask = 0x80 >> ((bp - 1) % 8)
                for arr in (egress, untagged, forbidden):
                    while len(arr) <= byte_idx:
                        arr.append(0)

                if vid == vlan_id:
                    # Target VLAN: set untagged
                    target_found = True
                    if not (egress[byte_idx] & bit_mask
                            and untagged[byte_idx] & bit_mask):
                        egress[byte_idx] |= bit_mask
                        untagged[byte_idx] |= bit_mask
                        forbidden[byte_idx] &= ~bit_mask
                        changed = True
                else:
                    # Other VLANs: remove port entirely
                    if (egress[byte_idx] & bit_mask
                            or untagged[byte_idx] & bit_mask
                            or forbidden[byte_idx] & bit_mask):
                        egress[byte_idx] &= ~bit_mask
                        untagged[byte_idx] &= ~bit_mask
                        forbidden[byte_idx] &= ~bit_mask
                        changed = True

            if changed:
                mutations.append((
                    "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
                    {"dot1qVlanStaticEgressPorts": _bytearray_to_hex(egress),
                     "dot1qVlanStaticUntaggedPorts": _bytearray_to_hex(untagged)},
                    {"dot1qVlanIndex": str(vid)}))

        if not target_found:
            raise ValueError(f"VLAN {vlan_id} does not exist")

        # Set PVID for all target ports
        for p in ports:
            bp = name_to_bp[p]
            mutations.append((
                "Q-BRIDGE-MIB", "dot1qPortVlanEntry",
                {"dot1qPvid": str(vlan_id)},
                {"dot1dBasePort": str(bp)}))

        self._apply_mutations(mutations)

    def create_vlan(self, vlan_id, name=''):
        """Create a VLAN in the VLAN database via MOPS.

        Uses Q-BRIDGE-MIB for SET (IEEE8021 SET fails on HiOS).
        Always fires immediately — VLAN CRUD is a database operation,
        not port config, and other setters validate against live state.
        """
        values = {"dot1qVlanStaticRowStatus": "4"}  # createAndGo
        if name:
            values["dot1qVlanStaticName"] = encode_string(name)
        self.client.set_indexed(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": str(vlan_id)},
            values=values)

    def update_vlan(self, vlan_id, name):
        """Rename an existing VLAN via MOPS.

        Always fires immediately — VLAN CRUD is a database operation.
        """
        self.client.set_indexed(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": str(vlan_id)},
            values={"dot1qVlanStaticName": encode_string(name)})

    def delete_vlan(self, vlan_id):
        """Delete a VLAN from the VLAN database via MOPS.

        Always fires immediately — VLAN CRUD is a database operation.
        """
        self.client.set_indexed(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": str(vlan_id)},
            values={"dot1qVlanStaticRowStatus": "6"})  # destroy

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
        try:
            # decode_strings=False: dBm values are hex-encoded strings
            mibs, ifindex_map = self._get_with_ifindex(
                ("HM2-DEVMGMT-MIB", "hm2SfpDiagEntry",
                 ["ifIndex",
                  "hm2SfpCurrentTxPower",
                  "hm2SfpCurrentRxPower",
                  "hm2SfpCurrentTxPowerdBm",
                  "hm2SfpCurrentRxPowerdBm"]),
                decode_strings=False,
            )
            entries = mibs.get("HM2-DEVMGMT-MIB", {}).get("hm2SfpDiagEntry", [])
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
        """Return environment data: temperature, PSU, CPU, memory, fans.

        Single get_multi fetches all 5 MIB tables in one HTTP POST.
        """
        env = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {},
        }

        # decode_strings=False: temperature "42" and "70" are valid hex tokens
        # that _decode_hex_string corrupts to ASCII chars 'B' and 'p'
        try:
            result = self.client.get_multi([
                ("HM2-DEVMGMT-MIB", "hm2DeviceMgmtTemperatureGroup",
                 ["hm2DevMgmtTemperature",
                  "hm2DevMgmtTemperatureUpperLimit",
                  "hm2DevMgmtTemperatureLowerLimit"]),
                ("HM2-DIAGNOSTIC-MIB", "hm2DiagCpuResourcesGroup",
                 ["hm2DiagCpuUtilization"]),
                ("HM2-DIAGNOSTIC-MIB", "hm2DiagMemoryResourcesGroup",
                 ["hm2DiagMemoryRamAllocated", "hm2DiagMemoryRamFree"]),
                ("HM2-PWRMGMT-MIB", "hm2PSEntry",
                 ["hm2PSState"]),
                ("HM2-FAN-MIB", "hm2FanEntry",
                 ["hm2FanStatus"]),
            ], decode_strings=False)
            mibs = result["mibs"]
        except MOPSError:
            return env

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

        # Power supplies from HM2-PWRMGMT-MIB
        psu_entries = mibs.get("HM2-PWRMGMT-MIB", {}).get("hm2PSEntry", [])
        for i, entry in enumerate(psu_entries, 1):
            idx = entry.get("_idx_hm2PSIndex", str(i))
            state = _safe_int_or_ord(entry.get("hm2PSState", "3"))
            # 1=present, 2=defective, 3=notInstalled, 4=unknown
            if state != 3:  # Skip not-installed
                env['power'][f'Power Supply P{idx}'] = {
                    'status': state == 1,
                    'capacity': -1.0,
                    'output': -1.0,
                }

        # Fans from HM2-FAN-MIB
        fan_entries = mibs.get("HM2-FAN-MIB", {}).get("hm2FanEntry", [])
        for i, entry in enumerate(fan_entries, 1):
            idx = entry.get("_idx_hm2FanIndex", str(i))
            status = _safe_int_or_ord(entry.get("hm2FanStatus", "1"))
            # 1=not-available, 2=available-and-ok, 3=available-but-failure
            if status != 1:
                env['fans'][f'Fan {idx}'] = {
                    'status': status == 2,
                }

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

    def set_snmp_information(self, hostname=None, contact=None, location=None):
        """Set sysName, sysContact, and/or sysLocation via MOPS.

        Args:
            hostname: system name (sysName.0), None to skip
            contact: system contact (sysContact.0), None to skip
            location: system location (sysLocation.0), None to skip
        """
        values = {}
        if hostname is not None:
            values["sysName"] = encode_string(hostname)
        if contact is not None:
            values["sysContact"] = encode_string(contact)
        if location is not None:
            values["sysLocation"] = encode_string(location)
        if not values:
            return None
        self._apply_set("SNMPv2-MIB", "system", values)
        if self._staging:
            return None
        return self.get_snmp_information()

    def get_config(self, retrieve='all', full=False, sanitized=False,
                   format='text', profile=None, source='nvm'):
        """Download config XML via HTTPS.

        Args:
            retrieve: ignored (MOPS always returns full running config)
            full: ignored
            sanitized: ignored
            format: ignored (always XML)
            profile: profile name (default = active profile)
            source: 'nvm' or 'envm'

        Returns:
            NAPALM-standard dict::

                {'running': '<xml>...', 'startup': '', 'candidate': ''}
        """
        if profile is None:
            profiles = self.get_profiles(storage=source)
            active = [p for p in profiles if p.get('active')]
            if not active:
                raise ValueError(f"No active profile found on {source}")
            profile = active[0]['name']
        xml = self.client.download_config(profile, source=source)
        return {
            'running': xml,
            'startup': '',
            'candidate': '',
        }

    def load_config(self, xml_data, profile=None, destination='nvm'):
        """Upload config XML to a profile via HTTPS.

        Args:
            xml_data: config XML string
            profile: target profile name (default = active profile)
            destination: 'nvm' or 'envm'

        Use activate_profile() after upload to apply.
        """
        if profile is None:
            profiles = self.get_profiles(storage=destination)
            active = [p for p in profiles if p.get('active')]
            if not active:
                raise ValueError(f"No active profile found on {destination}")
            profile = active[0]['name']
        return self.client.upload_config(xml_data, profile,
                                         destination=destination)

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

    def get_config_remote(self):
        """Return remote config backup settings.

        Returns::

            {
                'server_username': 'admin',
                'auto_backup': {
                    'enabled': True,
                    'destination': 'tftp://192.168.4.3/%p/config-%d.xml',
                    'username': 'backup_user',
                }
            }
        """
        server = self.client.get(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtServerAccessGroup",
            ["hm2FMServerUserName"], decode_strings=False)
        server_data = server[0] if server else {}

        backup = self.client.get(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtConfigRemoteSaveGroup",
            ["hm2FMConfigRemoteSaveAdminStatus",
             "hm2FMConfigRemoteSaveDestination",
             "hm2FMConfigRemoteSaveUsername"],
            decode_strings=False)
        backup_data = backup[0] if backup else {}

        return {
            'server_username': _decode_hex_string(
                server_data.get("hm2FMServerUserName", "")),
            'auto_backup': {
                'enabled': _safe_int(backup_data.get(
                    "hm2FMConfigRemoteSaveAdminStatus", "2")) == 1,
                'destination': _decode_hex_string(
                    backup_data.get("hm2FMConfigRemoteSaveDestination", "")),
                'username': _decode_hex_string(
                    backup_data.get("hm2FMConfigRemoteSaveUsername", "")),
            },
        }

    def set_config_remote(self, action=None, server=None, profile=None,
                          source='nvm', destination='nvm',
                          auto_backup=None, auto_backup_url=None,
                          auto_backup_username=None, auto_backup_password=None,
                          username=None, password=None):
        """Configure remote config transfer and/or auto-backup via MOPS.

        One-shot transfer (requires action + server):
            action: 'pull' (server→device) or 'push' (device→server)
            server: TFTP URL (e.g. 'tftp://192.168.4.3/config.xml')
            profile: target profile name (default = active profile)
            source: 'nvm' or 'envm' (for push)
            destination: 'nvm' or 'envm' (for pull)

        Auto-backup config:
            auto_backup: True/False — enable/disable
            auto_backup_url: destination URL with wildcards
            auto_backup_username: auth username for backup server
            auto_backup_password: auth password for backup server

        Server credentials (shared across all transfers):
            username: file transfer server login
            password: file transfer server password
        """
        result = {}

        # Server credentials (shared)
        if username is not None or password is not None:
            cred_values = {}
            if username is not None:
                cred_values["hm2FMServerUserName"] = encode_string(username)
            if password is not None:
                cred_values["hm2FMServerPassword"] = encode_string(password)
            self.client.set("HM2-FILEMGMT-MIB",
                            "hm2FileMgmtServerAccessGroup", cred_values)

        # Auto-backup config
        backup_values = {}
        if auto_backup is not None:
            backup_values["hm2FMConfigRemoteSaveAdminStatus"] = (
                "1" if auto_backup else "2")
        if auto_backup_url is not None:
            backup_values["hm2FMConfigRemoteSaveDestination"] = (
                encode_string(auto_backup_url))
        if auto_backup_username is not None:
            backup_values["hm2FMConfigRemoteSaveUsername"] = (
                encode_string(auto_backup_username))
        if auto_backup_password is not None:
            backup_values["hm2FMConfigRemoteSavePassword"] = (
                encode_string(auto_backup_password))
        if backup_values:
            self.client.set("HM2-FILEMGMT-MIB",
                            "hm2FileMgmtConfigRemoteSaveGroup", backup_values)

        # One-shot transfer
        if action and server:
            src_map = {'nvm': '2', 'envm': '3'}
            dst_map = {'nvm': '2', 'envm': '3'}

            if profile is None:
                storage = destination if action == 'pull' else source
                profiles = self.get_profiles(storage=storage)
                active = [p for p in profiles if p.get('active')]
                if active:
                    profile = active[0]['name']
                else:
                    profile = ''

            if action == 'pull':
                result = self.client.config_transfer(
                    action='pull', server_url=server,
                    source_type='20', dest_type=dst_map.get(destination, '2'),
                    source_data=server, dest_data=profile)
            elif action == 'push':
                result = self.client.config_transfer(
                    action='push', server_url=server,
                    source_type=src_map.get(source, '2'), dest_type='20',
                    source_data=profile, dest_data=server)
            else:
                raise ValueError(f"Invalid action '{action}': use 'pull' or 'push'")

        return result or self.get_config_remote()

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
            mibs, ifindex_map = self._get_with_ifindex(
                ("HM2-L2REDUNDANCY-MIB", "hm2MrpEntry", [
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
                ]),
                decode_strings=False,
            )
        except MOPSError:
            return {'configured': False}

        entries = mibs.get("HM2-L2REDUNDANCY-MIB", {}).get("hm2MrpEntry", [])
        if not entries:
            return {'configured': False}

        # Use first entry (default domain)
        e = entries[0]

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
            'domain_name': _decode_hex_string(e.get("hm2MrpDomainName", "")),
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

        # Relay — only on L3 devices (noSuchName on L2, attribute
        # simply absent from response thanks to partial-error tolerance)
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
            self._apply_mutations(mutations)

        if self._staging:
            return None
        return self.get_rstp()

    def set_rstp_port(self, interface, enabled=None, edge_port=None,
                      auto_edge=None, path_cost=None, priority=None,
                      root_guard=None, loop_guard=None, tcn_guard=None,
                      bpdu_filter=None, bpdu_flood=None):
        """Set per-port STP/RSTP configuration.

        Args:
            interface: port name (str) or list of port names
            All other params optional — only provided values are changed.
        """
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        # Build CST values dict once
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

        # Resolve all interfaces, build mutations
        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            if enabled is not None:
                mutations.append((
                    "HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpPortEntry",
                    {"hm2AgentStpPortState": "1" if enabled else "2"},
                    {"ifIndex": ifidx}))
            if cst_values:
                mutations.append((
                    "HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstPortEntry",
                    dict(cst_values), {"ifIndex": ifidx}))

        if not mutations:
            return
        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # Vendor setters
    # ------------------------------------------------------------------

    def set_interface(self, interface, enabled=None, description=None):
        """Set interface admin state and/or description via MOPS.

        Args:
            interface: port name (str) or list of port names
            enabled: True (admin up) or False (admin down), None to skip
            description: port description string, None to skip
        """
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            idx = {"ifIndex": ifidx}
            if enabled is not None:
                mutations.append(("IF-MIB", "ifEntry",
                                  {"ifAdminStatus": "1" if enabled else "2"},
                                  idx))
            if description is not None:
                mutations.append(("IF-MIB", "ifXEntry",
                                  {"ifAlias": encode_string(description)},
                                  idx))

        if not mutations:
            return
        self._apply_mutations(mutations)

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

        self._apply_set("HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup", values)
        if self._staging:
            return None
        return self.get_hidiscovery()

    def set_mrp(self, operation='enable', mode='client', port_primary=None,
                port_secondary=None, vlan=None, recovery_delay=None,
                advanced_mode=None):
        """Configure MRP ring on the default domain via MOPS.

        Args:
            operation: 'enable' or 'disable'
            mode: 'manager' or 'client'
            port_primary: primary ring port (e.g. '1/3')
            port_secondary: secondary ring port (e.g. '1/4')
            vlan: VLAN ID for MRP domain (0-4042)
            recovery_delay: '200ms', '500ms', '30ms', or '10ms'
            advanced_mode: True/False — react on link change (faster failover)
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

            if advanced_mode is not None:
                values["hm2MrpMRMReactOnLinkChange"] = "1" if advanced_mode else "2"

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

    def get_mrp_sub_ring(self):
        """Return MRP sub-ring (SRM) configuration and operating state.

        Single get_multi fetches global scalars + instance table in one HTTP POST.
        """
        try:
            mibs, ifindex_map = self._get_with_ifindex(
                ("HM2-L2REDUNDANCY-MIB", "hm2SrmMibGroup", [
                    "hm2SrmGlobalAdminState",
                    "hm2SrmMaxInstances",
                ]),
                ("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry", [
                    "hm2SrmRingID",
                    "hm2SrmAdminState", "hm2SrmOperState",
                    "hm2SrmVlanID", "hm2SrmMRPDomainID",
                    "hm2SrmPartnerMAC", "hm2SrmSubRingProtocol",
                    "hm2SrmSubRingName",
                    "hm2SrmSubRingPortIfIndex", "hm2SrmSubRingPortOperState",
                    "hm2SrmSubRingOperState", "hm2SrmRedundancyOperState",
                    "hm2SrmConfigOperState",
                    "hm2SrmRowStatus",
                ]),
                decode_strings=False,
            )
        except MOPSError:
            return {
                'enabled': False,
                'max_instances': 8,
                'instances': [],
            }

        global_data = mibs.get("HM2-L2REDUNDANCY-MIB", {}).get("hm2SrmMibGroup", [])
        entries = mibs.get("HM2-L2REDUNDANCY-MIB", {}).get("hm2SrmEntry", [])

        enabled = False
        max_instances = 8
        if global_data:
            g = global_data[0] if isinstance(global_data, list) else global_data
            enabled = _safe_int(g.get("hm2SrmGlobalAdminState", "2")) == 1
            max_instances = _safe_int(g.get("hm2SrmMaxInstances", "8"), 8)

        instances = []
        if entries:
            for e in entries:
                row_status = _safe_int(e.get("hm2SrmRowStatus", "0"))
                if row_status not in (1, 4):  # active(1) or createAndGo(4)
                    continue

                # With decode_strings=False, integer fields come as hex.
                # Port ifIndex: hex string like "10" (=16 decimal) — parse as int
                port_idx_raw = e.get("hm2SrmSubRingPortIfIndex", "")
                port_idx = str(_safe_int(port_idx_raw, 0))
                admin_state = e.get("hm2SrmAdminState", "1")
                oper_state = e.get("hm2SrmOperState", "4")

                # Domain ID: raw hex "ff ff ff ..." → colon-separated
                domain_raw = e.get("hm2SrmMRPDomainID", "")
                if domain_raw and domain_raw.strip():
                    domain_id = ':'.join(
                        domain_raw.strip().split())
                else:
                    domain_id = 'ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff'

                # Partner MAC: raw hex "64 60 38 8a 42 d6" → formatted MAC
                partner_raw = e.get("hm2SrmPartnerMAC", "")
                partner_mac = _try_mac(partner_raw) if partner_raw else ""

                instances.append({
                    'ring_id': _safe_int(e.get("hm2SrmRingID", "0")),
                    'mode': _SRM_ADMIN_STATE.get(admin_state, 'manager'),
                    'mode_actual': _SRM_OPER_STATE.get(oper_state, 'disabled'),
                    'vlan': _safe_int(e.get("hm2SrmVlanID", "0")),
                    'domain_id': domain_id,
                    'partner_mac': partner_mac,
                    'protocol': 'mrp' if e.get(
                        "hm2SrmSubRingProtocol", "4") == "4" else 'unknown',
                    'name': _decode_hex_string(
                        e.get("hm2SrmSubRingName", "")),
                    'port': ifindex_map.get(port_idx, port_idx),
                    'port_state': _SRM_PORT_OPER_STATE.get(
                        e.get("hm2SrmSubRingPortOperState", "4"), 'not-connected'),
                    'ring_state': _SRM_RING_OPER_STATE.get(
                        e.get("hm2SrmSubRingOperState", "1"), 'undefined'),
                    'redundancy': _SRM_REDUNDANCY.get(
                        e.get("hm2SrmRedundancyOperState", "2"), False),
                    'info': _SRM_CONFIG_INFO.get(
                        e.get("hm2SrmConfigOperState", "1"), 'no error'),
                })

        return {
            'enabled': enabled,
            'max_instances': max_instances,
            'instances': instances,
        }

    def set_mrp_sub_ring(self, ring_id=None, enabled=None, mode='manager',
                         port=None, vlan=None, name=None):
        """Configure MRP sub-ring (SRM) via MOPS.

        Global operation (ring_id=None):
            set_mrp_sub_ring(enabled=True)   — enable SRM globally
            set_mrp_sub_ring(enabled=False)  — disable SRM globally

        Instance operation (ring_id provided):
            Creates/modifies an SRM instance. Auto-enables global SRM.

        Args:
            ring_id:  int — sub-ring instance ID (None = global only)
            enabled:  bool — global SRM enable/disable
            mode:     'manager', 'redundantManager', or 'singleManager'
            port:     interface name (e.g. '1/3') — single sub-ring port
            vlan:     VLAN for sub-ring (0-4042)
            name:     sub-ring name string (optional)
        """
        if mode not in _SRM_ADMIN_STATE_REV:
            raise ValueError(f"mode must be one of {list(_SRM_ADMIN_STATE_REV)}, got '{mode}'")

        # Global enable/disable
        if enabled is not None:
            try:
                self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmMibGroup",
                                        index={},
                                        values={"hm2SrmGlobalAdminState": "1" if enabled else "2"})
            except (MOPSError, ConnectionException):
                pass

        if ring_id is None:
            return self.get_mrp_sub_ring()

        # Auto-enable global SRM when creating an instance
        if enabled is None:
            try:
                self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmMibGroup",
                                        index={},
                                        values={"hm2SrmGlobalAdminState": "1"})
            except (MOPSError, ConnectionException):
                pass

        idx = {"hm2SrmRingID": str(ring_id)}

        # Try to create — if it already exists, just modify
        try:
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry",
                                    index=idx,
                                    values={"hm2SrmRowStatus": "5"})  # createAndWait
        except (MOPSError, ConnectionException):
            pass  # instance already exists

        # notInService for modification
        self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry",
                                index=idx,
                                values={"hm2SrmRowStatus": "2"})

        values = {"hm2SrmAdminState": _SRM_ADMIN_STATE_REV[mode]}

        if port:
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: i for i, n in ifindex_map.items()}
            pidx = name_to_idx.get(port)
            if pidx is None:
                raise ValueError(f"Unknown port '{port}'")
            values["hm2SrmSubRingPortIfIndex"] = pidx

        if vlan is not None:
            values["hm2SrmVlanID"] = str(int(vlan))

        if name is not None:
            values["hm2SrmSubRingName"] = name

        self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry",
                                index=idx, values=values)

        # Activate
        self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry",
                                index=idx,
                                values={"hm2SrmRowStatus": "1"})  # active

        return self.get_mrp_sub_ring()

    def delete_mrp_sub_ring(self, ring_id=None):
        """Delete sub-ring instance or disable SRM globally.

        Args:
            ring_id: int — specific instance to delete (None = disable globally)
        """
        if ring_id is None:
            # Disable SRM globally
            try:
                self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmMibGroup",
                                        index={},
                                        values={"hm2SrmGlobalAdminState": "2"})
            except (MOPSError, ConnectionException):
                pass
            return self.get_mrp_sub_ring()

        idx = {"hm2SrmRingID": str(ring_id)}

        try:
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry",
                                    index=idx,
                                    values={"hm2SrmRowStatus": "2"})  # notInService
        except (MOPSError, ConnectionException):
            pass
        try:
            self.client.set_indexed("HM2-L2REDUNDANCY-MIB", "hm2SrmEntry",
                                    index=idx,
                                    values={"hm2SrmRowStatus": "6"})  # destroy
        except (MOPSError, ConnectionException):
            pass

        return self.get_mrp_sub_ring()

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

    # ------------------------------------------------------------------
    # Auto-Disable
    # ------------------------------------------------------------------

    def get_auto_disable(self):
        """Return auto-disable state: per-port table + per-reason table.

        Returns:
            dict with:
                'interfaces': {port_name: {timer, remaining_time, component,
                    reason, active, error_time}}
                'reasons': {reason_name: {enabled, category}}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-DEVMGMT-MIB", "hm2AutoDisableIntfEntry", [
                "ifIndex",
                "hm2AutoDisableIntfTimer",
                "hm2AutoDisableIntfRemainingTime",
                "hm2AutoDisableIntfComponentName",
                "hm2AutoDisableIntfErrorReason",
                "hm2AutoDisableIntfOperState",
                "hm2AutoDisableIntfErrorTime",
            ]),
            ("HM2-DEVMGMT-MIB", "hm2AutoDisableReasonEntry", [
                "hm2AutoDisableReasons",
                "hm2AutoDisableReasonOperation",
                "hm2AutoDisableReasonCategory",
            ]),
            decode_strings=False,
        )

        intf_entries = (mibs.get("HM2-DEVMGMT-MIB", {})
                        .get("hm2AutoDisableIntfEntry", []))
        reason_entries = (mibs.get("HM2-DEVMGMT-MIB", {})
                          .get("hm2AutoDisableReasonEntry", []))

        interfaces = {}
        for entry in intf_entries:
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue

            component_hex = entry.get("hm2AutoDisableIntfComponentName", "")
            component = _decode_hex_string(component_hex)
            if component == '-':
                component = ''

            reason_code = entry.get("hm2AutoDisableIntfErrorReason", "0")

            interfaces[name] = {
                'timer': _safe_int(entry.get("hm2AutoDisableIntfTimer", "0")),
                'remaining_time': _safe_int(
                    entry.get("hm2AutoDisableIntfRemainingTime", "0")),
                'component': component,
                'reason': _AUTO_DISABLE_REASONS.get(reason_code, 'none'),
                'active': entry.get("hm2AutoDisableIntfOperState", "2") == "1",
                'error_time': _safe_int(
                    entry.get("hm2AutoDisableIntfErrorTime", "0")),
            }

        reasons = {}
        for entry in reason_entries:
            reason_idx = entry.get("hm2AutoDisableReasons", "")
            reason_name = _AUTO_DISABLE_REASONS.get(reason_idx, "")
            if not reason_name or reason_name == 'none':
                continue

            cat_code = entry.get("hm2AutoDisableReasonCategory", "1")
            reasons[reason_name] = {
                'enabled': entry.get(
                    "hm2AutoDisableReasonOperation", "2") == "1",
                'category': _AUTO_DISABLE_CATEGORY.get(cat_code, 'other'),
            }

        return {'interfaces': interfaces, 'reasons': reasons}

    def set_auto_disable(self, interface, timer=0):
        """Set auto-disable recovery timer for one or more ports.

        Args:
            interface: port name (str) or list of port names
            timer: recovery interval in seconds (0=off, 30 minimum)
        """
        interfaces = [interface] if isinstance(interface, str) else list(interface)
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            mutations.append(("HM2-DEVMGMT-MIB", "hm2AutoDisableIntfEntry",
                              {"hm2AutoDisableIntfTimer": str(int(timer))},
                              {"ifIndex": ifidx}))

        self._apply_mutations(mutations)

    def reset_auto_disable(self, interface):
        """Manually re-enable one or more auto-disabled ports.

        Writes true(1) to hm2AutoDisableIntfReset — no need for admin down/up.

        Args:
            interface: port name (str) or list of port names
        """
        interfaces = [interface] if isinstance(interface, str) else list(interface)
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            mutations.append(("HM2-DEVMGMT-MIB", "hm2AutoDisableIntfEntry",
                              {"hm2AutoDisableIntfReset": "1"},
                              {"ifIndex": ifidx}))

        self._apply_mutations(mutations)

    def set_auto_disable_reason(self, reason, enabled=True):
        """Enable or disable auto-disable recovery for a specific reason type.

        Args:
            reason: reason name (e.g. 'loop-protection', 'link-flap')
            enabled: True to enable, False to disable
        """
        reason_idx = _AUTO_DISABLE_REASONS_REV.get(reason)
        if reason_idx is None:
            raise ValueError(
                f"Unknown reason '{reason}': use one of "
                f"{list(_AUTO_DISABLE_REASONS_REV.keys())}")

        self._apply_set_indexed("HM2-DEVMGMT-MIB", "hm2AutoDisableReasonEntry",
                                index={"hm2AutoDisableReasons": reason_idx},
                                values={"hm2AutoDisableReasonOperation":
                                        "1" if enabled else "2"})

    # ------------------------------------------------------------------
    # Loop Protection (Keepalive)
    # ------------------------------------------------------------------

    def get_loop_protection(self):
        """Return loop protection configuration and state.

        Returns:
            dict with:
                'enabled': bool (global)
                'transmit_interval': int (seconds, 1-10)
                'receive_threshold': int (0|1-50)
                'interfaces': {port_name: {enabled, mode, action, vlan_id,
                    tpid_type, loop_detected, loop_count, last_loop_time,
                    tx_frames, rx_frames, discard_frames}}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentSwitchKeepaliveGroup", [
                "hm2AgentSwitchKeepaliveState",
                "hm2AgentSwitchKeepaliveTransmitInterval",
                "hm2AgentSwitchKeepaliveRxThreshold",
            ]),
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentKeepalivePortEntry", [
                "ifIndex",
                "hm2AgentKeepalivePortState",
                "hm2AgentKeepalivePortMode",
                "hm2AgentKeepalivePortRxAction",
                "hm2AgentKeepalivePortVlanId",
                "hm2AgentKeepalivePortTpidType",
                "hm2AgentKeepalivePortLoopDetected",
                "hm2AgentKeepalivePortLoopCount",
                "hm2AgentKeepalivePortLastLoopDetectedTime",
                "hm2AgentKeepalivePortTxFrameCount",
                "hm2AgentKeepalivePortRxFrameCount",
                "hm2AgentKeepalivePortDiscardFrameCount",
            ]),
            decode_strings=False,
        )

        glb = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
               .get("hm2AgentSwitchKeepaliveGroup", [{}])[0])
        port_entries = (mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
                        .get("hm2AgentKeepalivePortEntry", []))

        interfaces = {}
        for entry in port_entries:
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue

            action_code = entry.get("hm2AgentKeepalivePortRxAction", "11")
            mode_code = entry.get("hm2AgentKeepalivePortMode", "2")
            tpid_code = entry.get("hm2AgentKeepalivePortTpidType", "0")

            interfaces[name] = {
                'enabled': entry.get(
                    "hm2AgentKeepalivePortState", "2") == "1",
                'mode': _LOOP_PROT_MODE.get(mode_code, 'passive'),
                'action': _LOOP_PROT_ACTION.get(action_code, 'auto-disable'),
                'vlan_id': _safe_int(
                    entry.get("hm2AgentKeepalivePortVlanId", "0")),
                'tpid_type': _LOOP_PROT_TPID.get(tpid_code, 'none'),
                'loop_detected': entry.get(
                    "hm2AgentKeepalivePortLoopDetected", "2") == "1",
                'loop_count': _safe_int(
                    entry.get("hm2AgentKeepalivePortLoopCount", "0")),
                'last_loop_time': _decode_date_time(
                    entry.get("hm2AgentKeepalivePortLastLoopDetectedTime", "")),
                'tx_frames': _safe_int(
                    entry.get("hm2AgentKeepalivePortTxFrameCount", "0")),
                'rx_frames': _safe_int(
                    entry.get("hm2AgentKeepalivePortRxFrameCount", "0")),
                'discard_frames': _safe_int(
                    entry.get("hm2AgentKeepalivePortDiscardFrameCount", "0")),
            }

        return {
            'enabled': glb.get("hm2AgentSwitchKeepaliveState", "2") == "1",
            'transmit_interval': _safe_int(
                glb.get("hm2AgentSwitchKeepaliveTransmitInterval", "5")),
            'receive_threshold': _safe_int(
                glb.get("hm2AgentSwitchKeepaliveRxThreshold", "1")),
            'interfaces': interfaces,
        }

    def set_loop_protection(self, interface=None, enabled=None, mode=None,
                            action=None, vlan_id=None,
                            transmit_interval=None, receive_threshold=None):
        """Set loop protection configuration.

        If interface is provided, sets per-port values.
        If interface is None, sets global values.

        Args:
            interface: port name (str), list of port names, or None for global
            enabled: True/False for on/off
            mode: 'active' or 'passive' (per-port only)
            action: 'trap', 'auto-disable', or 'all' (per-port only)
            vlan_id: VLAN ID (0=untagged, 1-4042=tagged dot1q) (per-port only)
            transmit_interval: 1-10 seconds (global only)
            receive_threshold: 0|1-50 probes (global only)

        Note: tpid_type is auto-derived from vlan_id by the device
        (0→none, >0→dot1q). It is read-only in the getter.
        """
        if interface is not None:
            # Per-port — accept single string or list
            interfaces = ([interface] if isinstance(interface, str)
                          else list(interface))
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {name: idx for idx, name in ifindex_map.items()}

            values = {}
            if enabled is not None:
                values["hm2AgentKeepalivePortState"] = "1" if enabled else "2"
            if mode is not None:
                val = _LOOP_PROT_MODE_REV.get(mode)
                if val is None:
                    raise ValueError(
                        f"Invalid mode '{mode}': use 'active' or 'passive'")
                values["hm2AgentKeepalivePortMode"] = val
            if action is not None:
                val = _LOOP_PROT_ACTION_REV.get(action)
                if val is None:
                    raise ValueError(
                        f"Invalid action '{action}': use 'trap', "
                        f"'auto-disable', or 'all'")
                values["hm2AgentKeepalivePortRxAction"] = val
            if vlan_id is not None:
                values["hm2AgentKeepalivePortVlanId"] = str(int(vlan_id))

            if not values:
                return

            mutations = []
            for iface in interfaces:
                ifidx = name_to_idx.get(iface)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{iface}'")
                mutations.append((
                    "HM2-PLATFORM-SWITCHING-MIB",
                    "hm2AgentKeepalivePortEntry",
                    dict(values), {"ifIndex": ifidx}))

            if mutations:
                self._apply_mutations(mutations)
        else:
            # Global
            values = {}
            if enabled is not None:
                values["hm2AgentSwitchKeepaliveState"] = (
                    "1" if enabled else "2")
            if transmit_interval is not None:
                values["hm2AgentSwitchKeepaliveTransmitInterval"] = str(
                    int(transmit_interval))
            if receive_threshold is not None:
                values["hm2AgentSwitchKeepaliveRxThreshold"] = str(
                    int(receive_threshold))

            if values:
                self._apply_set("HM2-PLATFORM-SWITCHING-MIB",
                                "hm2AgentSwitchKeepaliveGroup", values)

    # ------------------------------------------------------------------
    # Storm Control
    # ------------------------------------------------------------------

    _STORM_UNIT = {'1': 'percent', '2': 'pps'}
    _STORM_UNIT_REV = {'percent': '1', 'pps': '2'}
    _STORM_BUCKET = {'1': 'single-bucket', '2': 'multi-bucket'}

    def get_storm_control(self):
        """Return per-port storm control configuration.

        Returns:
            dict with:
                'bucket_type': str ('single-bucket' or 'multi-bucket')
                'interfaces': {port_name: {
                    'unit': str ('percent' or 'pps'),
                    'broadcast': {'enabled': bool, 'threshold': int},
                    'multicast': {'enabled': bool, 'threshold': int},
                    'unicast':   {'enabled': bool, 'threshold': int},
                }}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-TRAFFICMGMT-MIB", "hm2TrafficMgmtMibObjects", [
                "hm2TrafficMgmtIngressStormBucketType",
            ]),
            ("HM2-TRAFFICMGMT-MIB", "hm2TrafficMgmtIfEntry", [
                "ifIndex",
                "hm2TrafficMgmtIfIngressStormCtlThresholdUnit",
                "hm2TrafficMgmtIfIngressStormCtlBcastMode",
                "hm2TrafficMgmtIfIngressStormCtlBcastThreshold",
                "hm2TrafficMgmtIfIngressStormCtlMcastMode",
                "hm2TrafficMgmtIfIngressStormCtlMcastThreshold",
                "hm2TrafficMgmtIfIngressStormCtlUcastMode",
                "hm2TrafficMgmtIfIngressStormCtlUcastThreshold",
            ]),
            decode_strings=False,
        )

        glb = (mibs.get("HM2-TRAFFICMGMT-MIB", {})
               .get("hm2TrafficMgmtMibObjects", [{}])[0])
        bucket_code = glb.get("hm2TrafficMgmtIngressStormBucketType", "1")

        port_entries = (mibs.get("HM2-TRAFFICMGMT-MIB", {})
                        .get("hm2TrafficMgmtIfEntry", []))

        interfaces = {}
        for entry in port_entries:
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue

            unit_code = entry.get(
                "hm2TrafficMgmtIfIngressStormCtlThresholdUnit", "1")

            interfaces[name] = {
                'unit': self._STORM_UNIT.get(unit_code, 'percent'),
                'broadcast': {
                    'enabled': entry.get(
                        "hm2TrafficMgmtIfIngressStormCtlBcastMode",
                        "2") == "1",
                    'threshold': _safe_int(entry.get(
                        "hm2TrafficMgmtIfIngressStormCtlBcastThreshold",
                        "0")),
                },
                'multicast': {
                    'enabled': entry.get(
                        "hm2TrafficMgmtIfIngressStormCtlMcastMode",
                        "2") == "1",
                    'threshold': _safe_int(entry.get(
                        "hm2TrafficMgmtIfIngressStormCtlMcastThreshold",
                        "0")),
                },
                'unicast': {
                    'enabled': entry.get(
                        "hm2TrafficMgmtIfIngressStormCtlUcastMode",
                        "2") == "1",
                    'threshold': _safe_int(entry.get(
                        "hm2TrafficMgmtIfIngressStormCtlUcastThreshold",
                        "0")),
                },
            }

        return {
            'bucket_type': self._STORM_BUCKET.get(bucket_code,
                                                   'single-bucket'),
            'interfaces': interfaces,
        }

    def set_storm_control(self, interface, unit=None,
                          broadcast_enabled=None, broadcast_threshold=None,
                          multicast_enabled=None, multicast_threshold=None,
                          unicast_enabled=None, unicast_threshold=None):
        """Set per-port storm control configuration.

        Args:
            interface: port name (str) or list of port names
            unit: 'percent' or 'pps'
            broadcast_enabled: True/False
            broadcast_threshold: int (0..14880000)
            multicast_enabled: True/False
            multicast_threshold: int (0..14880000)
            unicast_enabled: True/False
            unicast_threshold: int (0..14880000)
        """
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        values = {}
        if unit is not None:
            val = self._STORM_UNIT_REV.get(unit)
            if val is None:
                raise ValueError(
                    f"Invalid unit '{unit}': use 'percent' or 'pps'")
            values["hm2TrafficMgmtIfIngressStormCtlThresholdUnit"] = val
        if broadcast_enabled is not None:
            values["hm2TrafficMgmtIfIngressStormCtlBcastMode"] = (
                "1" if broadcast_enabled else "2")
        if broadcast_threshold is not None:
            values["hm2TrafficMgmtIfIngressStormCtlBcastThreshold"] = str(
                int(broadcast_threshold))
        if multicast_enabled is not None:
            values["hm2TrafficMgmtIfIngressStormCtlMcastMode"] = (
                "1" if multicast_enabled else "2")
        if multicast_threshold is not None:
            values["hm2TrafficMgmtIfIngressStormCtlMcastThreshold"] = str(
                int(multicast_threshold))
        if unicast_enabled is not None:
            values["hm2TrafficMgmtIfIngressStormCtlUcastMode"] = (
                "1" if unicast_enabled else "2")
        if unicast_threshold is not None:
            values["hm2TrafficMgmtIfIngressStormCtlUcastThreshold"] = str(
                int(unicast_threshold))

        if not values:
            return

        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            mutations.append((
                "HM2-TRAFFICMGMT-MIB", "hm2TrafficMgmtIfEntry",
                dict(values), {"ifIndex": ifidx}))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # sFlow (RFC 3176)
    # ------------------------------------------------------------------

    def get_sflow(self):
        """Return sFlow agent info and receiver table.

        Returns:
            dict with:
                'agent_version': str (e.g. '1.3;Hirschmann;10.3.04')
                'agent_address': str (IP)
                'receivers': {1..8: {owner, timeout, max_datagram_size,
                    address_type, address, port, datagram_version}}
        """
        result = self.client.get_multi([
            ("SFLOW-MIB", "sFlowAgent", [
                "sFlowVersion", "sFlowAgentAddressType", "sFlowAgentAddress",
            ]),
            ("SFLOW-MIB", "sFlowRcvrEntry", [
                "sFlowRcvrIndex", "sFlowRcvrOwner", "sFlowRcvrTimeout",
                "sFlowRcvrMaximumDatagramSize", "sFlowRcvrAddressType",
                "sFlowRcvrAddress", "sFlowRcvrPort",
                "sFlowRcvrDatagramVersion",
            ]),
        ], decode_strings=False)

        mibs = result["mibs"]
        agent = mibs.get("SFLOW-MIB", {}).get("sFlowAgent", [{}])[0]
        rcvr_entries = mibs.get("SFLOW-MIB", {}).get("sFlowRcvrEntry", [])

        receivers = {}
        for entry in rcvr_entries:
            idx = _safe_int(entry.get("sFlowRcvrIndex", "0"))
            if idx < 1:
                continue
            receivers[idx] = {
                'owner': _decode_hex_string(
                    entry.get("sFlowRcvrOwner", "")),
                'timeout': _safe_int(
                    entry.get("sFlowRcvrTimeout", "0")),
                'max_datagram_size': _safe_int(
                    entry.get("sFlowRcvrMaximumDatagramSize", "1400")),
                'address_type': _safe_int(
                    entry.get("sFlowRcvrAddressType", "1")),
                'address': _decode_hex_ip(
                    entry.get("sFlowRcvrAddress", "")),
                'port': _safe_int(
                    entry.get("sFlowRcvrPort", "6343")),
                'datagram_version': _safe_int(
                    entry.get("sFlowRcvrDatagramVersion", "5")),
            }

        return {
            'agent_version': _decode_hex_string(
                agent.get("sFlowVersion", "")),
            'agent_address': _decode_hex_ip(
                agent.get("sFlowAgentAddress", "")),
            'receivers': receivers,
        }

    def set_sflow(self, receiver, address=None, port=None, owner=None,
                  timeout=None, max_datagram_size=None):
        """Configure an sFlow receiver.

        Args:
            receiver: int 1-8 (receiver index)
            address: IP string (e.g. '192.168.1.100', '0.0.0.0' to clear)
            port: UDP port (default 6343)
            owner: owner string (set to claim receiver, '' to release)
            timeout: seconds (-1=permanent, >0=countdown)
            max_datagram_size: max datagram size in bytes

        Owner must be set before other attributes on an unclaimed receiver.
        Setting owner to '' releases the receiver and auto-clears all
        bound samplers/pollers.
        """
        if not 1 <= receiver <= 8:
            raise ValueError(f"receiver must be 1-8, got {receiver}")

        index = {"sFlowRcvrIndex": str(receiver)}

        # Owner must be sent as a separate SET — the device requires it
        # before accepting other attributes on an unclaimed receiver.
        if owner is not None:
            self._apply_set_indexed(
                "SFLOW-MIB", "sFlowRcvrEntry", index=index,
                values={"sFlowRcvrOwner": encode_string(owner)})

        values = {}
        if address is not None:
            values["sFlowRcvrAddress"] = _encode_hex_ip(address)
            values["sFlowRcvrAddressType"] = "1"
        if port is not None:
            values["sFlowRcvrPort"] = str(int(port))
        if timeout is not None:
            values["sFlowRcvrTimeout"] = str(int(timeout))
        if max_datagram_size is not None:
            values["sFlowRcvrMaximumDatagramSize"] = str(
                int(max_datagram_size))

        if values:
            self._apply_set_indexed(
                "SFLOW-MIB", "sFlowRcvrEntry", index=index,
                values=values)

        if not self._staging:
            return self.get_sflow()

    def get_sflow_port(self, interfaces=None, type=None):
        """Return sFlow sampler and poller config per port.

        Args:
            interfaces: list of port names (None=all)
            type: 'sampler', 'poller', or None (both)

        Returns:
            {port_name: {sampler: {receiver, sample_rate, max_header_size},
                         poller: {receiver, interval}}}
        """
        tables = []
        if type is None or type == 'sampler':
            tables.append(("SFLOW-MIB", "sFlowFsEntry", [
                "sFlowFsDataSource", "sFlowFsInstance",
                "sFlowFsReceiver", "sFlowFsPacketSamplingRate",
                "sFlowFsMaximumHeaderSize",
            ]))
        if type is None or type == 'poller':
            tables.append(("SFLOW-MIB", "sFlowCpEntry", [
                "sFlowCpDataSource", "sFlowCpInstance",
                "sFlowCpReceiver", "sFlowCpInterval",
            ]))

        mibs, ifindex_map = self._get_with_ifindex(
            *tables, decode_strings=False)

        # Build reverse map for filtering
        iface_set = set(interfaces) if interfaces else None

        result = {}
        sflow = mibs.get("SFLOW-MIB", {})

        if type is None or type == 'sampler':
            for entry in sflow.get("sFlowFsEntry", []):
                ds = entry.get("sFlowFsDataSource", "")
                ifidx = ds.rsplit(".", 1)[-1] if "." in ds else ds
                name = ifindex_map.get(ifidx, "")
                if not name or name.startswith("cpu"):
                    continue
                if iface_set and name not in iface_set:
                    continue
                if name not in result:
                    result[name] = {}
                result[name]['sampler'] = {
                    'receiver': _safe_int(
                        entry.get("sFlowFsReceiver", "0")),
                    'sample_rate': _safe_int(
                        entry.get("sFlowFsPacketSamplingRate", "0")),
                    'max_header_size': _safe_int(
                        entry.get("sFlowFsMaximumHeaderSize", "128")),
                }

        if type is None or type == 'poller':
            for entry in sflow.get("sFlowCpEntry", []):
                ds = entry.get("sFlowCpDataSource", "")
                ifidx = ds.rsplit(".", 1)[-1] if "." in ds else ds
                name = ifindex_map.get(ifidx, "")
                if not name or name.startswith("cpu"):
                    continue
                if iface_set and name not in iface_set:
                    continue
                if name not in result:
                    result[name] = {}
                result[name]['poller'] = {
                    'receiver': _safe_int(
                        entry.get("sFlowCpReceiver", "0")),
                    'interval': _safe_int(
                        entry.get("sFlowCpInterval", "0")),
                }

        return result

    def set_sflow_port(self, interfaces, receiver, sample_rate=None,
                       interval=None, max_header_size=None):
        """Configure sFlow sampling/polling on ports.

        Args:
            interfaces: port name (str) or list of port names
            receiver: int 0-8 (0=disable, 1-8=bind to receiver)
            sample_rate: configure sampler (0=off, 256-65536)
            interval: configure poller (0=off, seconds)
            max_header_size: sampler max header size in bytes

        At least one of sample_rate or interval must be provided.
        When disabling (receiver=0), set receiver only — the device
        auto-clears rate/interval.
        """
        if sample_rate is None and interval is None:
            raise ValueError(
                "At least one of sample_rate or interval must be provided")

        interfaces = ([interfaces] if isinstance(interfaces, str)
                      else list(interfaces))
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")

            ds_oid = f"1.3.6.1.2.1.2.2.1.1.{ifidx}"

            if sample_rate is not None:
                # When unbinding (receiver=0), only send receiver —
                # the device auto-clears rate and rejects combined SETs.
                if receiver == 0:
                    values = {"sFlowFsReceiver": "0"}
                else:
                    values = {
                        "sFlowFsReceiver": str(int(receiver)),
                        "sFlowFsPacketSamplingRate": str(int(sample_rate)),
                    }
                    if max_header_size is not None:
                        values["sFlowFsMaximumHeaderSize"] = str(
                            int(max_header_size))
                mutations.append((
                    "SFLOW-MIB", "sFlowFsEntry", values,
                    {"sFlowFsDataSource": ds_oid,
                     "sFlowFsInstance": "1"}))

            if interval is not None:
                if receiver == 0:
                    values = {"sFlowCpReceiver": "0"}
                else:
                    values = {
                        "sFlowCpReceiver": str(int(receiver)),
                        "sFlowCpInterval": str(int(interval)),
                    }
                mutations.append((
                    "SFLOW-MIB", "sFlowCpEntry", values,
                    {"sFlowCpDataSource": ds_oid,
                     "sFlowCpInstance": "1"}))

        if mutations:
            self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # QoS (Class of Service)
    # ------------------------------------------------------------------
    _QOS_TRUST_MODE = {
        '1': 'untrusted', '2': 'dot1p',
        '3': 'ip-precedence', '4': 'ip-dscp',
    }
    _QOS_TRUST_MODE_REV = {
        'untrusted': '1', 'dot1p': '2',
        'ip-precedence': '3', 'ip-dscp': '4',
    }
    _QOS_SCHEDULER = {'1': 'strict', '2': 'weighted'}
    _QOS_SCHEDULER_REV = {'strict': '1', 'weighted': '2'}

    def get_qos(self):
        """Return per-port QoS trust mode and queue scheduling.

        Returns:
            dict with:
                'num_queues': int (device capability, typically 8)
                'interfaces': {port_name: {
                    'trust_mode': str,
                    'shaping_rate': int (0 = no limit),
                    'queues': {0..7: {
                        'scheduler': str ('strict' or 'weighted'),
                        'min_bw': int (percent),
                        'max_bw': int (percent),
                    }},
                }}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-PLATFORM-QOS-COS-MIB", "hm2AgentCosQueueCfgGroup", [
                "hm2AgentCosQueueNumQueuesPerPort",
            ]),
            ("HM2-PLATFORM-QOS-COS-MIB", "hm2AgentCosMapIntfTrustEntry", [
                "hm2AgentCosMapIntfTrustIntfIndex",
                "hm2AgentCosMapIntfTrustMode",
            ]),
            ("HM2-PLATFORM-QOS-COS-MIB", "hm2AgentCosQueueControlEntry", [
                "hm2AgentCosQueueIntfIndex",
                "hm2AgentCosQueueIntfShapingRate",
            ]),
            ("HM2-PLATFORM-QOS-COS-MIB", "hm2AgentCosQueueEntry", [
                "hm2AgentCosQueueIntfIndex",
                "hm2AgentCosQueueIndex",
                "hm2AgentCosQueueSchedulerType",
                "hm2AgentCosQueueMinBandwidth",
                "hm2AgentCosQueueMaxBandwidth",
            ]),
            ("P-BRIDGE-MIB", "dot1dPortPriorityEntry", [
                "dot1dBasePort",
                "dot1dPortDefaultUserPriority",
            ]),
            decode_strings=False,
        )

        qos_mib = mibs.get("HM2-PLATFORM-QOS-COS-MIB", {})

        # Scalar: number of queues
        cfg = qos_mib.get("hm2AgentCosQueueCfgGroup", [{}])[0]
        num_queues = _safe_int(
            cfg.get("hm2AgentCosQueueNumQueuesPerPort", "8"))

        # Trust mode per port
        trust_by_idx = {}
        for entry in qos_mib.get("hm2AgentCosMapIntfTrustEntry", []):
            idx = entry.get("hm2AgentCosMapIntfTrustIntfIndex", "")
            if idx == "0":
                continue  # global default, skip
            trust_by_idx[idx] = self._QOS_TRUST_MODE.get(
                entry.get("hm2AgentCosMapIntfTrustMode", "2"), 'dot1p')

        # Shaping rate per port
        shaping_by_idx = {}
        for entry in qos_mib.get("hm2AgentCosQueueControlEntry", []):
            idx = entry.get("hm2AgentCosQueueIntfIndex", "")
            if idx == "0":
                continue
            shaping_by_idx[idx] = _safe_int(
                entry.get("hm2AgentCosQueueIntfShapingRate", "0"))

        # Default priority per port (P-BRIDGE-MIB, indexed by dot1dBasePort)
        priority_by_idx = {}
        pbridge_mib = mibs.get("P-BRIDGE-MIB", {})
        for entry in pbridge_mib.get("dot1dPortPriorityEntry", []):
            idx = entry.get("dot1dBasePort", "")
            if not idx or idx == "0":
                continue
            priority_by_idx[idx] = _safe_int(
                entry.get("dot1dPortDefaultUserPriority", "0"))

        # Queue scheduling per port per queue
        queues_by_idx = {}
        for entry in qos_mib.get("hm2AgentCosQueueEntry", []):
            idx = entry.get("hm2AgentCosQueueIntfIndex", "")
            if idx == "0":
                continue
            qidx = _safe_int(entry.get("hm2AgentCosQueueIndex", "0"))
            if idx not in queues_by_idx:
                queues_by_idx[idx] = {}
            queues_by_idx[idx][qidx] = {
                'scheduler': self._QOS_SCHEDULER.get(
                    entry.get("hm2AgentCosQueueSchedulerType", "1"),
                    'strict'),
                'min_bw': _safe_int(
                    entry.get("hm2AgentCosQueueMinBandwidth", "0")),
                'max_bw': _safe_int(
                    entry.get("hm2AgentCosQueueMaxBandwidth", "0")),
            }

        # Build result keyed by port name
        interfaces = {}
        for idx, name in ifindex_map.items():
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue
            if idx not in trust_by_idx:
                continue
            interfaces[name] = {
                'trust_mode': trust_by_idx.get(idx, 'dot1p'),
                'default_priority': priority_by_idx.get(idx, 0),
                'shaping_rate': shaping_by_idx.get(idx, 0),
                'queues': queues_by_idx.get(idx, {}),
            }

        return {
            'num_queues': num_queues,
            'interfaces': interfaces,
        }

    def set_qos(self, interface, trust_mode=None, shaping_rate=None,
                queue=None, scheduler=None, min_bw=None, max_bw=None,
                default_priority=None):
        """Set per-port QoS trust mode, shaping rate, or queue scheduling.

        Args:
            interface: port name (str) or list of port names
            trust_mode: 'untrusted', 'dot1p', 'ip-precedence', 'ip-dscp'
            shaping_rate: int 0-100 (percent, 0 = no limit)
            queue: int 0-7 (required if setting scheduler/min_bw/max_bw)
            scheduler: 'strict' or 'weighted'
            min_bw: int 0-100 (percent, weighted queue minimum)
            max_bw: int 0-100 (percent, weighted queue maximum)
            default_priority: int 0-7 (port default PCP for untagged frames)
        """
        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {name: idx for idx, name in ifindex_map.items()}

        # Validate enums
        if trust_mode is not None:
            val = self._QOS_TRUST_MODE_REV.get(trust_mode)
            if val is None:
                raise ValueError(
                    f"Invalid trust_mode '{trust_mode}': use "
                    "'untrusted', 'dot1p', 'ip-precedence', 'ip-dscp'")

        if scheduler is not None:
            val = self._QOS_SCHEDULER_REV.get(scheduler)
            if val is None:
                raise ValueError(
                    f"Invalid scheduler '{scheduler}': "
                    "use 'strict' or 'weighted'")

        queue_needed = (scheduler is not None or min_bw is not None
                        or max_bw is not None)
        if queue_needed and queue is None:
            raise ValueError(
                "queue index (0-7) required when setting "
                "scheduler, min_bw, or max_bw")

        mutations = []
        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")

            if trust_mode is not None:
                mutations.append((
                    "HM2-PLATFORM-QOS-COS-MIB",
                    "hm2AgentCosMapIntfTrustEntry",
                    {"hm2AgentCosMapIntfTrustMode":
                     self._QOS_TRUST_MODE_REV[trust_mode]},
                    {"hm2AgentCosMapIntfTrustIntfIndex": ifidx}))

            if shaping_rate is not None:
                mutations.append((
                    "HM2-PLATFORM-QOS-COS-MIB",
                    "hm2AgentCosQueueControlEntry",
                    {"hm2AgentCosQueueIntfShapingRate":
                     str(int(shaping_rate))},
                    {"hm2AgentCosQueueIntfIndex": ifidx}))

            if default_priority is not None:
                mutations.append((
                    "P-BRIDGE-MIB",
                    "dot1dPortPriorityEntry",
                    {"dot1dPortDefaultUserPriority":
                     str(int(default_priority))},
                    {"dot1dBasePort": ifidx}))

            if queue_needed:
                q_values = {}
                if scheduler is not None:
                    q_values["hm2AgentCosQueueSchedulerType"] = (
                        self._QOS_SCHEDULER_REV[scheduler])
                if min_bw is not None:
                    q_values["hm2AgentCosQueueMinBandwidth"] = str(
                        int(min_bw))
                if max_bw is not None:
                    q_values["hm2AgentCosQueueMaxBandwidth"] = str(
                        int(max_bw))
                mutations.append((
                    "HM2-PLATFORM-QOS-COS-MIB",
                    "hm2AgentCosQueueEntry",
                    q_values,
                    {"hm2AgentCosQueueIntfIndex": ifidx,
                     "hm2AgentCosQueueIndex": str(int(queue))}))

        if mutations:
            self._apply_mutations(mutations)

        if self._staging:
            return None
        return self.get_qos()

    def get_qos_mapping(self):
        """Return global dot1p and DSCP to traffic class mapping tables.

        Returns:
            dict with:
                'dot1p': {0: tc, 1: tc, ..., 7: tc}
                'dscp':  {0: tc, 8: tc, 10: tc, ..., 56: tc}
        """
        result = self.client.get_multi([
            ("HM2-L2FORWARDING-MIB", "hm2TrafficClassEntry", [
                "hm2TrafficClassPriority",
                "hm2TrafficClass",
            ]),
            ("HM2-L2FORWARDING-MIB", "hm2CosMapIpDscpEntry", [
                "hm2CosMapIpDscpValue",
                "hm2CosMapIpDscpTrafficClass",
            ]),
        ], decode_strings=False)

        l2fwd = result["mibs"].get("HM2-L2FORWARDING-MIB", {})

        # dot1p → TC (8 entries, priority 0-7)
        dot1p = {}
        for entry in l2fwd.get("hm2TrafficClassEntry", []):
            prio = _safe_int(entry.get("hm2TrafficClassPriority", "0"))
            tc = _safe_int(entry.get("hm2TrafficClass", "0"))
            dot1p[prio] = tc

        # DSCP → TC (64 entries, dscp 0-63)
        dscp = {}
        for entry in l2fwd.get("hm2CosMapIpDscpEntry", []):
            dval = _safe_int(entry.get("hm2CosMapIpDscpValue", "0"))
            tc = _safe_int(entry.get("hm2CosMapIpDscpTrafficClass", "0"))
            dscp[dval] = tc

        return {'dot1p': dot1p, 'dscp': dscp}

    def set_qos_mapping(self, dot1p=None, dscp=None):
        """Set global dot1p and/or DSCP to traffic class mappings.

        Args:
            dot1p: dict {priority(0-7): traffic_class(0-7)}
            dscp:  dict {dscp_value(0-63): traffic_class(0-7)}

        Only the mappings provided are changed; others are left untouched.
        """
        mutations = []

        if dot1p is not None:
            for prio, tc in dot1p.items():
                mutations.append((
                    "HM2-L2FORWARDING-MIB",
                    "hm2TrafficClassEntry",
                    {"hm2TrafficClass": str(int(tc))},
                    {"hm2TrafficClassPriority": str(int(prio))}))

        if dscp is not None:
            for dval, tc in dscp.items():
                mutations.append((
                    "HM2-L2FORWARDING-MIB",
                    "hm2CosMapIpDscpEntry",
                    {"hm2CosMapIpDscpTrafficClass": str(int(tc))},
                    {"hm2CosMapIpDscpValue": str(int(dval))}))

        if mutations:
            self._apply_mutations(mutations)

        if self._staging:
            return None
        return self.get_qos_mapping()

    def get_management_priority(self):
        """Return management frame priority settings.

        Returns:
            dict with:
                'dot1p': int (0-7, VLAN priority for management replies)
                'ip_dscp': int (0-63, IP DSCP for management replies)
        """
        result = self.client.get_multi([
            ("HM2-NETCONFIG-MIB", "hm2NetStaticGroup", [
                "hm2NetVlanPriority",
                "hm2NetIpDscpPriority",
            ]),
        ], decode_strings=False)

        net = (result["mibs"].get("HM2-NETCONFIG-MIB", {})
               .get("hm2NetStaticGroup", [{}])[0])

        return {
            'dot1p': _safe_int(net.get("hm2NetVlanPriority", "0")),
            'ip_dscp': _safe_int(net.get("hm2NetIpDscpPriority", "0")),
        }

    def set_management_priority(self, dot1p=None, ip_dscp=None):
        """Set management frame priority.

        Args:
            dot1p: int 0-7 (VLAN priority for management replies)
            ip_dscp: int 0-63 (IP DSCP for management replies)
        """
        values = {}
        if dot1p is not None:
            values["hm2NetVlanPriority"] = str(int(dot1p))
        if ip_dscp is not None:
            values["hm2NetIpDscpPriority"] = str(int(ip_dscp))

        if not values:
            return

        self._apply_set("HM2-NETCONFIG-MIB", "hm2NetStaticGroup", values)

        if self._staging:
            return None
        return self.get_management_priority()

    def get_management(self):
        """Return management network configuration from HM2-NETCONFIG-MIB.

        Returns:
            dict with:
                'protocol': str ('local', 'bootp', 'dhcp')
                'vlan_id': int (1-4042)
                'ip_address': str (dotted quad)
                'netmask': str (dotted quad)
                'gateway': str (dotted quad)
                'mgmt_port': int (0 = all ports)
                'dhcp_client_id': str (read-only)
                'dhcp_lease_time': int seconds (read-only)
                'dhcp_option_66_67': bool
                'dot1p': int (0-7)
                'ip_dscp': int (0-63)
                'ipv6_enabled': bool
                'ipv6_protocol': str ('none', 'auto', 'dhcpv6', 'all')
        """
        _PROTOCOL_MAP = {'1': 'local', '2': 'bootp', '3': 'dhcp'}
        _IPV6_PROTOCOL_MAP = {'1': 'none', '2': 'auto', '3': 'dhcpv6', '4': 'all'}

        entries = self.client.get("HM2-NETCONFIG-MIB", "hm2NetStaticGroup", [
            "hm2NetConfigProtocol",
            "hm2NetVlanID",
            "hm2NetLocalIPAddr",
            "hm2NetPrefixLength",
            "hm2NetGatewayIPAddr",
            "hm2NetMgmtPort",
            "hm2NetDHCPClientId",
            "hm2NetDHCPClientLeaseTime",
            "hm2NetDHCPClientConfigLoad",
            "hm2NetVlanPriority",
            "hm2NetIpDscpPriority",
            "hm2NetIPv6AdminStatus",
            "hm2NetIPv6ConfigProtocol",
        ], decode_strings=False)

        if not entries:
            return {}

        e = entries[0]
        proto_val = e.get("hm2NetConfigProtocol", "1")
        prefix_len = _safe_int(e.get("hm2NetPrefixLength", "0"))

        return {
            'protocol': _PROTOCOL_MAP.get(proto_val, 'local'),
            'vlan_id': _safe_int(e.get("hm2NetVlanID", "1")),
            'ip_address': _decode_hex_ip(e.get("hm2NetLocalIPAddr", "")),
            'netmask': _prefix_to_mask(prefix_len),
            'gateway': _decode_hex_ip(e.get("hm2NetGatewayIPAddr", "")),
            'mgmt_port': _safe_int(e.get("hm2NetMgmtPort", "0")),
            'dhcp_client_id': _decode_hex_string(e.get("hm2NetDHCPClientId", "")),
            'dhcp_lease_time': _safe_int(e.get("hm2NetDHCPClientLeaseTime", "0")),
            'dhcp_option_66_67': _safe_int(
                e.get("hm2NetDHCPClientConfigLoad", "1")) == 1,
            'dot1p': _safe_int(e.get("hm2NetVlanPriority", "0")),
            'ip_dscp': _safe_int(e.get("hm2NetIpDscpPriority", "0")),
            'ipv6_enabled': _safe_int(
                e.get("hm2NetIPv6AdminStatus", "1")) == 1,
            'ipv6_protocol': _IPV6_PROTOCOL_MAP.get(
                e.get("hm2NetIPv6ConfigProtocol", "2"), 'auto'),
        }

    def set_management(self, protocol=None, vlan_id=None, ip_address=None,
                       netmask=None, gateway=None, mgmt_port=None,
                       dhcp_option_66_67=None, ipv6_enabled=None):
        """Set management network configuration via MOPS.

        All parameters are optional — only provided values are changed.
        IP changes are activated atomically via hm2NetAction in the same POST.

        Args:
            protocol: 'local', 'bootp', or 'dhcp'
            vlan_id: int 1-4042 (management VLAN — validated against VLAN table)
            ip_address: str dotted quad
            netmask: str dotted quad
            gateway: str dotted quad
            mgmt_port: int (0 = all ports, or specific port number)
            dhcp_option_66_67: bool (enable/disable DHCP option 66/67/4/42)
            ipv6_enabled: bool (enable/disable IPv6 — disabling reduces attack surface)

        Returns:
            dict: current management config (from get_management())
        """
        _PROTOCOL_REV = {'local': '1', 'bootp': '2', 'dhcp': '3'}

        # Validate VLAN exists before changing management VLAN
        if vlan_id is not None:
            vlan_id = int(vlan_id)
            if vlan_id < 1 or vlan_id > 4042:
                raise ValueError(f"vlan_id must be 1-4042, got {vlan_id}")
            vlans = self.get_vlans()
            if vlan_id not in vlans:
                raise ValueError(
                    f"VLAN {vlan_id} does not exist on device — "
                    f"create it first to avoid management lockout")

        values = {}

        if protocol is not None:
            protocol = protocol.lower().strip()
            if protocol not in _PROTOCOL_REV:
                raise ValueError(
                    f"protocol must be 'local', 'bootp', or 'dhcp', "
                    f"got '{protocol}'")
            values["hm2NetConfigProtocol"] = _PROTOCOL_REV[protocol]

        if vlan_id is not None:
            values["hm2NetVlanID"] = str(vlan_id)

        if ip_address is not None:
            values["hm2NetLocalIPAddr"] = _encode_hex_ip(ip_address)

        if netmask is not None:
            values["hm2NetPrefixLength"] = str(_mask_to_prefix(netmask))

        if gateway is not None:
            values["hm2NetGatewayIPAddr"] = _encode_hex_ip(gateway)

        if mgmt_port is not None:
            values["hm2NetMgmtPort"] = str(int(mgmt_port))

        if dhcp_option_66_67 is not None:
            values["hm2NetDHCPClientConfigLoad"] = \
                "1" if dhcp_option_66_67 else "2"

        if ipv6_enabled is not None:
            values["hm2NetIPv6AdminStatus"] = \
                "1" if ipv6_enabled else "2"

        if not values:
            return self.get_management()

        # Include activate trigger for IP/gateway changes
        if any(k in values for k in (
                "hm2NetLocalIPAddr", "hm2NetPrefixLength",
                "hm2NetGatewayIPAddr")):
            values["hm2NetAction"] = "2"  # activate

        self._apply_set("HM2-NETCONFIG-MIB", "hm2NetStaticGroup", values)

        if self._staging:
            return None
        return self.get_management()

    # ------------------------------------------------------------------
    # Config Watchdog (HM2-FILEMGMT-MIB)
    # ------------------------------------------------------------------

    def get_watchdog_status(self):
        """Read config watchdog state.

        Returns::

            {
                'enabled': True,
                'oper_status': 1,
                'interval': 60,
                'remaining': 45,
            }
        """
        entries = self.client.get(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtConfigWatchdogControl",
            ["hm2ConfigWatchdogAdminStatus",
             "hm2ConfigWatchdogOperStatus",
             "hm2ConfigWatchdogTimeInterval",
             "hm2ConfigWatchdogTimerValue"],
            decode_strings=False)
        data = entries[0] if entries else {}
        return {
            'enabled': _safe_int(data.get(
                "hm2ConfigWatchdogAdminStatus", "2")) == 1,
            'oper_status': _safe_int(data.get(
                "hm2ConfigWatchdogOperStatus", "2")),
            'interval': _safe_int(data.get(
                "hm2ConfigWatchdogTimeInterval", "0")),
            'remaining': _safe_int(data.get(
                "hm2ConfigWatchdogTimerValue", "0")),
        }

    def start_watchdog(self, seconds):
        """Start the config watchdog timer.

        If the timer expires before stop_watchdog() is called, the device
        reverts to the saved config (NVM) automatically.

        Args:
            seconds: timer interval (30-600)
        """
        if not (30 <= seconds <= 600):
            raise ValueError(
                f"Watchdog interval must be 30-600, got {seconds}")
        self._apply_set(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtConfigWatchdogControl",
            {"hm2ConfigWatchdogTimeInterval": str(seconds),
             "hm2ConfigWatchdogAdminStatus": "1"})

    def stop_watchdog(self):
        """Stop (disable) the config watchdog timer."""
        self._apply_set(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtConfigWatchdogControl",
            {"hm2ConfigWatchdogAdminStatus": "2"})

    # ------------------------------------------------------------------
    # Login Policy (HM2-USERMGMT-MIB / hm2PwdMgmtGroup)
    # ------------------------------------------------------------------

    def get_login_policy(self):
        """Read password and login lockout policy.

        Returns::

            {
                'min_password_length': 6,
                'max_login_attempts': 0,
                'lockout_duration': 0,
                'min_uppercase': 1,
                'min_lowercase': 1,
                'min_numeric': 1,
                'min_special': 1,
            }
        """
        entries = self.client.get(
            "HM2-USERMGMT-MIB", "hm2PwdMgmtGroup",
            ["hm2PwdMgmtMinLength", "hm2PwdMgmtLoginAttempts",
             "hm2PwdMgmtLoginAttemptsTimePeriod",
             "hm2PwdMgmtMinUpperCase", "hm2PwdMgmtMinLowerCase",
             "hm2PwdMgmtMinNumericNumbers",
             "hm2PwdMgmtMinSpecialCharacters"],
            decode_strings=False)
        data = entries[0] if entries else {}
        return {
            'min_password_length': _safe_int(data.get(
                "hm2PwdMgmtMinLength", "6")),
            'max_login_attempts': _safe_int(data.get(
                "hm2PwdMgmtLoginAttempts", "0")),
            'lockout_duration': _safe_int(data.get(
                "hm2PwdMgmtLoginAttemptsTimePeriod", "0")),
            'min_uppercase': _safe_int(data.get(
                "hm2PwdMgmtMinUpperCase", "1")),
            'min_lowercase': _safe_int(data.get(
                "hm2PwdMgmtMinLowerCase", "1")),
            'min_numeric': _safe_int(data.get(
                "hm2PwdMgmtMinNumericNumbers", "1")),
            'min_special': _safe_int(data.get(
                "hm2PwdMgmtMinSpecialCharacters", "1")),
        }

    def set_login_policy(self, min_password_length=None,
                         max_login_attempts=None, lockout_duration=None,
                         min_uppercase=None, min_lowercase=None,
                         min_numeric=None, min_special=None):
        """Set password and login lockout policy.

        Args:
            min_password_length: 1-64
            max_login_attempts: 0=disabled, 1-5
            lockout_duration: 0=disabled, 1-60 seconds
            min_uppercase: 0-16
            min_lowercase: 0-16
            min_numeric: 0-16
            min_special: 0-16
        """
        values = {}
        if min_password_length is not None:
            values["hm2PwdMgmtMinLength"] = str(int(min_password_length))
        if max_login_attempts is not None:
            values["hm2PwdMgmtLoginAttempts"] = str(int(max_login_attempts))
        if lockout_duration is not None:
            values["hm2PwdMgmtLoginAttemptsTimePeriod"] = str(
                int(lockout_duration))
        if min_uppercase is not None:
            values["hm2PwdMgmtMinUpperCase"] = str(int(min_uppercase))
        if min_lowercase is not None:
            values["hm2PwdMgmtMinLowerCase"] = str(int(min_lowercase))
        if min_numeric is not None:
            values["hm2PwdMgmtMinNumericNumbers"] = str(int(min_numeric))
        if min_special is not None:
            values["hm2PwdMgmtMinSpecialCharacters"] = str(int(min_special))
        if not values:
            return
        self._apply_set("HM2-USERMGMT-MIB", "hm2PwdMgmtGroup", values)

    # ------------------------------------------------------------------
    # Syslog (HM2-LOGGING-MIB)
    # ------------------------------------------------------------------

    def get_syslog(self):
        """Read syslog configuration.

        Returns::

            {
                'enabled': bool,
                'servers': [
                    {'index': int, 'ip': str, 'port': int,
                     'severity': str, 'transport': str},
                ]
            }
        """
        _SEVERITY = {
            '0': 'emergency', '1': 'alert', '2': 'critical',
            '3': 'error', '4': 'warning', '5': 'notice',
            '6': 'informational', '7': 'debug',
        }
        _TRANSPORT = {'1': 'udp', '2': 'tls'}

        global_data = self.client.get(
            "HM2-LOGGING-MIB", "hm2LogSyslogGroup",
            ["hm2LogSyslogAdminStatus"], decode_strings=False)
        g = global_data[0] if global_data else {}

        try:
            entries = self.client.get(
                "HM2-LOGGING-MIB", "hm2LogSyslogServerEntry",
                ["hm2LogSyslogServerIndex",
                 "hm2LogSyslogServerIPAddr",
                 "hm2LogSyslogServerUdpPort",
                 "hm2LogSyslogServerLevelUpto",
                 "hm2LogSyslogServerTransportType"],
                decode_strings=False)
        except MOPSError:
            entries = []

        servers = []
        for entry in entries:
            idx = _safe_int(entry.get("hm2LogSyslogServerIndex", "0"))
            if idx < 1:
                continue
            sev_code = entry.get("hm2LogSyslogServerLevelUpto", "7")
            trans_code = entry.get("hm2LogSyslogServerTransportType", "1")
            ip_raw = entry.get("hm2LogSyslogServerIPAddr", "")
            servers.append({
                'index': idx,
                'ip': _decode_hex_ip(ip_raw) if ip_raw else '',
                'port': _safe_int(entry.get(
                    "hm2LogSyslogServerUdpPort", "514")),
                'severity': _SEVERITY.get(str(sev_code), str(sev_code)),
                'transport': _TRANSPORT.get(str(trans_code), str(trans_code)),
            })
        return {
            'enabled': _safe_int(g.get(
                "hm2LogSyslogAdminStatus", "2")) == 1,
            'servers': servers,
        }

    def set_syslog(self, enabled=None, servers=None):
        """Set syslog configuration.

        Args:
            enabled: True/False — global syslog enable
            servers: list of dicts with optional keys:
                index (1-8), ip, port, severity, transport
        """
        _SEVERITY_REV = {
            'emergency': '0', 'alert': '1', 'critical': '2',
            'error': '3', 'warning': '4', 'notice': '5',
            'informational': '6', 'debug': '7',
        }
        _TRANSPORT_REV = {'udp': '1', 'tls': '2'}

        if enabled is not None:
            self._apply_set(
                "HM2-LOGGING-MIB", "hm2LogSyslogGroup",
                {"hm2LogSyslogAdminStatus": "1" if enabled else "2"})

        if servers:
            # Find existing row indices
            try:
                existing = self.client.get(
                    "HM2-LOGGING-MIB", "hm2LogSyslogServerEntry",
                    ["hm2LogSyslogServerIndex",
                     "hm2LogSyslogServerRowStatus"],
                    decode_strings=False)
            except MOPSError:
                existing = []
            existing_idx = set()
            for e in existing:
                rs = _safe_int(e.get("hm2LogSyslogServerRowStatus", "0"))
                if rs in (1, 2, 3):  # active, notInService, notReady
                    existing_idx.add(
                        _safe_int(e.get("hm2LogSyslogServerIndex", "0")))

            for srv in servers:
                idx_num = int(srv.get('index', 1))
                idx = {"hm2LogSyslogServerIndex": str(idx_num)}

                # Create row if it doesn't exist
                if idx_num not in existing_idx:
                    self._apply_set_indexed(
                        "HM2-LOGGING-MIB", "hm2LogSyslogServerEntry",
                        idx, {"hm2LogSyslogServerRowStatus": "5"})

                # Build values
                values = {}
                if 'ip' in srv:
                    values["hm2LogSyslogServerIPAddrType"] = "1"
                    values["hm2LogSyslogServerIPAddr"] = _encode_hex_ip(
                        srv['ip'])
                if 'port' in srv:
                    values["hm2LogSyslogServerUdpPort"] = str(
                        int(srv['port']))
                if 'severity' in srv:
                    sev = _SEVERITY_REV.get(srv['severity'])
                    if sev is not None:
                        values["hm2LogSyslogServerLevelUpto"] = sev
                if 'transport' in srv:
                    trans = _TRANSPORT_REV.get(srv['transport'])
                    if trans is not None:
                        values["hm2LogSyslogServerTransportType"] = trans
                if values:
                    self._apply_set_indexed(
                        "HM2-LOGGING-MIB", "hm2LogSyslogServerEntry",
                        idx, values)

                # Activate new rows
                if idx_num not in existing_idx:
                    self._apply_set_indexed(
                        "HM2-LOGGING-MIB", "hm2LogSyslogServerEntry",
                        idx, {"hm2LogSyslogServerRowStatus": "1"})

    # ------------------------------------------------------------------
    # NTP / SNTP (HM2-TIMESYNC-MIB)
    # ------------------------------------------------------------------

    def get_ntp(self):
        """Read NTP/SNTP client and server configuration.

        Returns::

            {
                'client': {
                    'enabled': bool,
                    'mode': str,
                    'servers': [{'address': str, 'port': int,
                                 'status': str}]
                },
                'server': {'enabled': bool, 'stratum': int},
            }
        """
        # SNTP client status
        client_data = self.client.get(
            "HM2-TIMESYNC-MIB", "hm2SntpClientGroup",
            ["hm2SntpClientAdminState", "hm2SntpClientOperStatus",
             "hm2SntpClientRequestInterval"],
            decode_strings=False)
        c = client_data[0] if client_data else {}

        # SNTP server table
        try:
            server_entries = self.client.get(
                "HM2-TIMESYNC-MIB", "hm2SntpClientServerAddrEntry",
                ["hm2SntpClientServerIndex",
                 "hm2SntpClientServerAddr",
                 "hm2SntpClientServerPort",
                 "hm2SntpClientServerOperStatus",
                 "hm2SntpClientServerDescription"],
                decode_strings=False)
        except MOPSError:
            server_entries = []

        _STATUS = {'1': 'other', '2': 'success', '3': 'requestTimedOut',
                   '4': 'badDateEncoded', '5': 'versionNotSupported'}

        servers = []
        for entry in server_entries:
            idx = _safe_int(entry.get("hm2SntpClientServerIndex", "0"))
            if idx < 1:
                continue
            addr_raw = entry.get("hm2SntpClientServerAddr", "")
            status_code = entry.get(
                "hm2SntpClientServerOperStatus", "1")
            servers.append({
                'address': _decode_hex_ip(addr_raw) if addr_raw else '',
                'port': _safe_int(entry.get(
                    "hm2SntpClientServerPort", "123")),
                'status': _STATUS.get(
                    str(status_code), str(status_code)),
            })

        # NTP server config (may not be available on L2S)
        try:
            srv_data = self.client.get(
                "HM2-TIMESYNC-MIB", "hm2NtpServerConfigGroup",
                ["hm2NtpServerAdminState", "hm2NtpServerStratum"],
                decode_strings=False)
            s = srv_data[0] if srv_data else {}
        except MOPSError:
            s = {}

        return {
            'client': {
                'enabled': _safe_int(c.get(
                    "hm2SntpClientAdminState", "2")) == 1,
                'mode': 'sntp',
                'servers': servers,
            },
            'server': {
                'enabled': _safe_int(s.get(
                    "hm2NtpServerAdminState", "2")) == 1,
                'stratum': _safe_int(s.get(
                    "hm2NtpServerStratum", "1")),
            },
        }

    def set_ntp(self, client_enabled=None, server_enabled=None,
                servers=None):
        """Set NTP/SNTP configuration.

        Args:
            client_enabled: True/False — SNTP client admin state
            server_enabled: True/False — NTP server admin state
            servers: list of dicts with keys: address, port (optional)
        """
        mutations = []
        if client_enabled is not None:
            mutations.append((
                "HM2-TIMESYNC-MIB", "hm2SntpClientGroup",
                {"hm2SntpClientAdminState":
                 "1" if client_enabled else "2"}))
        if server_enabled is not None:
            mutations.append((
                "HM2-TIMESYNC-MIB", "hm2NtpServerConfigGroup",
                {"hm2NtpServerAdminState":
                 "1" if server_enabled else "2"}))
        self._apply_mutations(mutations)

        if servers:
            # Find existing server row indices
            try:
                existing = self.client.get(
                    "HM2-TIMESYNC-MIB", "hm2SntpClientServerAddrEntry",
                    ["hm2SntpClientServerIndex",
                     "hm2SntpClientServerRowStatus"],
                    decode_strings=False)
            except MOPSError:
                existing = []
            existing_idx = set()
            for e in existing:
                rs = _safe_int(e.get(
                    "hm2SntpClientServerRowStatus", "0"))
                if rs in (1, 2, 3):
                    existing_idx.add(_safe_int(
                        e.get("hm2SntpClientServerIndex", "0")))

            for i, srv in enumerate(servers):
                idx_num = srv.get('index', i + 1)
                idx = {"hm2SntpClientServerIndex": str(idx_num)}

                # Create row if it doesn't exist
                if idx_num not in existing_idx:
                    self._apply_set_indexed(
                        "HM2-TIMESYNC-MIB",
                        "hm2SntpClientServerAddrEntry",
                        idx,
                        {"hm2SntpClientServerRowStatus": "5"})

                # Set address
                values = {"hm2SntpClientServerAddrType": "1"}
                values["hm2SntpClientServerAddr"] = _encode_hex_ip(
                    srv['address'])
                if 'port' in srv:
                    values["hm2SntpClientServerPort"] = str(
                        int(srv['port']))
                self._apply_set_indexed(
                    "HM2-TIMESYNC-MIB",
                    "hm2SntpClientServerAddrEntry",
                    idx, values)

                # Activate new rows
                if idx_num not in existing_idx:
                    self._apply_set_indexed(
                        "HM2-TIMESYNC-MIB",
                        "hm2SntpClientServerAddrEntry",
                        idx,
                        {"hm2SntpClientServerRowStatus": "1"})

    # ------------------------------------------------------------------
    # Services (multi-MIB)
    # ------------------------------------------------------------------

    def get_services(self):
        """Read service enable/disable state across management + industrial.

        Returns::

            {
                'http': {'enabled': bool, 'port': int},
                'https': {'enabled': bool, 'port': int},
                'ssh': {'enabled': bool},
                'telnet': {'enabled': bool},
                'snmp': {'v1': bool, 'v2': bool, 'v3': bool, 'port': int},
                'industrial': {
                    'iec61850': bool, 'profinet': bool,
                    'ethernet_ip': bool, 'opcua': bool, 'modbus': bool,
                },
            }
        """
        result = self.client.get_multi([
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup", [
                "hm2WebHttpAdminStatus", "hm2WebHttpsAdminStatus",
                "hm2WebHttpPortNumber", "hm2WebHttpsPortNumber"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup", [
                "hm2SshAdminStatus"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessTelnetGroup", [
                "hm2TelnetServerAdminStatus"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup", [
                "hm2SnmpV1AdminStatus", "hm2SnmpV2AdminStatus",
                "hm2SnmpV3AdminStatus", "hm2SnmpPortNumber"]),
        ], decode_strings=False)
        mibs = result["mibs"].get("HM2-MGMTACCESS-MIB", {})
        web = (mibs.get("hm2MgmtAccessWebGroup", [{}])[0])
        ssh = (mibs.get("hm2MgmtAccessSshGroup", [{}])[0])
        tel = (mibs.get("hm2MgmtAccessTelnetGroup", [{}])[0])
        snmp = (mibs.get("hm2MgmtAccessSnmpGroup", [{}])[0])

        # Industrial protocols (separate MIB)
        ind_result = self.client.get_multi([
            ("HM2-INDUSTRIAL-PROTOCOLS-MIB", "hm2Iec61850ConfigGroup",
             ["hm2Iec61850MmsServerAdminStatus"]),
            ("HM2-INDUSTRIAL-PROTOCOLS-MIB", "hm2ProfinetIOConfigGroup",
             ["hm2PNIOAdminStatus"]),
            ("HM2-INDUSTRIAL-PROTOCOLS-MIB", "hm2EthernetIPConfigGroup",
             ["hm2EtherNetIPAdminStatus"]),
            ("HM2-INDUSTRIAL-PROTOCOLS-MIB", "hm2Iec62541ConfigGroup",
             ["hm2Iec62541OpcUaServerAdminStatus"]),
            ("HM2-INDUSTRIAL-PROTOCOLS-MIB", "hm2ModbusConfigGroup",
             ["hm2ModbusTcpServerAdminStatus"]),
        ], decode_strings=False)
        ind_mibs = ind_result["mibs"].get(
            "HM2-INDUSTRIAL-PROTOCOLS-MIB", {})
        iec = (ind_mibs.get("hm2Iec61850ConfigGroup", [{}])[0])
        pn = (ind_mibs.get("hm2ProfinetIOConfigGroup", [{}])[0])
        eip = (ind_mibs.get("hm2EthernetIPConfigGroup", [{}])[0])
        opc = (ind_mibs.get("hm2Iec62541ConfigGroup", [{}])[0])
        mb = (ind_mibs.get("hm2ModbusConfigGroup", [{}])[0])

        return {
            'http': {
                'enabled': _safe_int(web.get(
                    "hm2WebHttpAdminStatus", "2")) == 1,
                'port': _safe_int(web.get(
                    "hm2WebHttpPortNumber", "80")),
            },
            'https': {
                'enabled': _safe_int(web.get(
                    "hm2WebHttpsAdminStatus", "2")) == 1,
                'port': _safe_int(web.get(
                    "hm2WebHttpsPortNumber", "443")),
            },
            'ssh': {
                'enabled': _safe_int(ssh.get(
                    "hm2SshAdminStatus", "2")) == 1,
            },
            'telnet': {
                'enabled': _safe_int(tel.get(
                    "hm2TelnetServerAdminStatus", "2")) == 1,
            },
            'snmp': {
                'v1': _safe_int(snmp.get(
                    "hm2SnmpV1AdminStatus", "2")) == 1,
                'v2': _safe_int(snmp.get(
                    "hm2SnmpV2AdminStatus", "2")) == 1,
                'v3': _safe_int(snmp.get(
                    "hm2SnmpV3AdminStatus", "2")) == 1,
                'port': _safe_int(snmp.get(
                    "hm2SnmpPortNumber", "161")),
            },
            'industrial': {
                'iec61850': _safe_int(iec.get(
                    "hm2Iec61850MmsServerAdminStatus", "2")) == 1,
                'profinet': _safe_int(pn.get(
                    "hm2PNIOAdminStatus", "2")) == 1,
                'ethernet_ip': _safe_int(eip.get(
                    "hm2EtherNetIPAdminStatus", "2")) == 1,
                'opcua': _safe_int(opc.get(
                    "hm2Iec62541OpcUaServerAdminStatus", "2")) == 1,
                'modbus': _safe_int(mb.get(
                    "hm2ModbusTcpServerAdminStatus", "2")) == 1,
            },
        }

    def set_services(self, http=None, https=None, ssh=None,
                     telnet=None, snmp_v1=None, snmp_v2=None,
                     snmp_v3=None, iec61850=None, profinet=None,
                     ethernet_ip=None, opcua=None, modbus=None):
        """Set service enable/disable state.

        Each arg is bool (True=enable, False=disable) or None (no change).
        """
        mutations = []

        def _en(v):
            return "1" if v else "2"

        if http is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup",
                {"hm2WebHttpAdminStatus": _en(http)}))
        if https is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup",
                {"hm2WebHttpsAdminStatus": _en(https)}))
        if ssh is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup",
                {"hm2SshAdminStatus": _en(ssh)}))
        if telnet is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessTelnetGroup",
                {"hm2TelnetServerAdminStatus": _en(telnet)}))
        if any(v is not None for v in (snmp_v1, snmp_v2, snmp_v3)):
            snmp_vals = {}
            if snmp_v1 is not None:
                snmp_vals["hm2SnmpV1AdminStatus"] = _en(snmp_v1)
            if snmp_v2 is not None:
                snmp_vals["hm2SnmpV2AdminStatus"] = _en(snmp_v2)
            if snmp_v3 is not None:
                snmp_vals["hm2SnmpV3AdminStatus"] = _en(snmp_v3)
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup",
                snmp_vals))
        if iec61850 is not None:
            mutations.append((
                "HM2-INDUSTRIAL-PROTOCOLS-MIB",
                "hm2Iec61850ConfigGroup",
                {"hm2Iec61850MmsServerAdminStatus": _en(iec61850)}))
        if profinet is not None:
            mutations.append((
                "HM2-INDUSTRIAL-PROTOCOLS-MIB",
                "hm2ProfinetIOConfigGroup",
                {"hm2PNIOAdminStatus": _en(profinet)}))
        if ethernet_ip is not None:
            mutations.append((
                "HM2-INDUSTRIAL-PROTOCOLS-MIB",
                "hm2EthernetIPConfigGroup",
                {"hm2EtherNetIPAdminStatus": _en(ethernet_ip)}))
        if opcua is not None:
            mutations.append((
                "HM2-INDUSTRIAL-PROTOCOLS-MIB",
                "hm2Iec62541ConfigGroup",
                {"hm2Iec62541OpcUaServerAdminStatus": _en(opcua)}))
        if modbus is not None:
            mutations.append((
                "HM2-INDUSTRIAL-PROTOCOLS-MIB",
                "hm2ModbusConfigGroup",
                {"hm2ModbusTcpServerAdminStatus": _en(modbus)}))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # SNMP Config (HM2-MGMTACCESS-MIB + SNMP-COMMUNITY-MIB)
    # ------------------------------------------------------------------

    def get_snmp_config(self):
        """Read SNMP configuration: versions, port, communities.

        Returns::

            {
                'versions': {'v1': bool, 'v2': bool, 'v3': bool},
                'port': int,
                'communities': [{'name': str, 'access': str}],
            }
        """
        snmp_data = self.client.get(
            "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup",
            ["hm2SnmpV1AdminStatus", "hm2SnmpV2AdminStatus",
             "hm2SnmpV3AdminStatus", "hm2SnmpPortNumber"],
            decode_strings=False)
        s = snmp_data[0] if snmp_data else {}

        # Community table
        try:
            comm_entries = self.client.get(
                "SNMP-COMMUNITY-MIB", "snmpCommunityEntry",
                ["snmpCommunityIndex", "snmpCommunityName",
                 "snmpCommunitySecurityName"],
                decode_strings=False)
        except MOPSError:
            comm_entries = []

        communities = []
        for entry in comm_entries:
            name = _decode_hex_string(
                entry.get("snmpCommunityName", ""))
            sec_name = _decode_hex_string(
                entry.get("snmpCommunitySecurityName", ""))
            if not name:
                continue
            access = 'rw' if 'rw' in sec_name.lower() else 'ro'
            communities.append({'name': name, 'access': access})

        return {
            'versions': {
                'v1': _safe_int(s.get(
                    "hm2SnmpV1AdminStatus", "2")) == 1,
                'v2': _safe_int(s.get(
                    "hm2SnmpV2AdminStatus", "2")) == 1,
                'v3': _safe_int(s.get(
                    "hm2SnmpV3AdminStatus", "2")) == 1,
            },
            'port': _safe_int(s.get("hm2SnmpPortNumber", "161")),
            'communities': communities,
        }

    def set_snmp_config(self, v1=None, v2=None, v3=None):
        """Set SNMP version enable/disable.

        Args:
            v1, v2, v3: bool or None
        """
        values = {}
        if v1 is not None:
            values["hm2SnmpV1AdminStatus"] = "1" if v1 else "2"
        if v2 is not None:
            values["hm2SnmpV2AdminStatus"] = "1" if v2 else "2"
        if v3 is not None:
            values["hm2SnmpV3AdminStatus"] = "1" if v3 else "2"
        if values:
            self._apply_set(
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup",
                values)
