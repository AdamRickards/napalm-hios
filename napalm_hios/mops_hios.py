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


def _decode_bits_hex(hex_str, bit_map):
    """Decode SNMP BITS hex string to list of enabled names.

    BITS encoding: MSB-first, bit 0 = 0x80 of first byte.
    ``bit_map`` is {bit_position: name}.  Returns sorted list of names
    for all set bits.
    """
    if not hex_str or not hex_str.strip():
        return []
    try:
        octets = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        return []
    enabled = []
    for byte_idx, byte_val in enumerate(octets):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                bit_num = byte_idx * 8 + bit_idx
                name = bit_map.get(bit_num)
                if name:
                    enabled.append(name)
    return enabled


def _encode_bits_hex(names, bit_map):
    """Encode list of algorithm names to BITS hex string.

    Reverse of ``_decode_bits_hex``.  ``bit_map`` is {bit_position: name}.
    Returns space-separated hex bytes.
    """
    rev = {v: k for k, v in bit_map.items()}
    max_bit = max(bit_map.keys()) if bit_map else 0
    num_bytes = (max_bit // 8) + 1
    octets = [0] * num_bytes
    for name in names:
        bit = rev.get(name)
        if bit is not None:
            octets[bit // 8] |= (0x80 >> (bit % 8))
    return ' '.join(f'{b:02x}' for b in octets)


# -- Cipher / TLS / SSH algorithm BITS mappings (HM2-MGMTACCESS-MIB) ------

_TLS_VERSIONS = {
    0: 'tlsv1.0',
    1: 'tlsv1.1',
    2: 'tlsv1.2',
}

_TLS_CIPHER_SUITES = {
    0: 'tls-rsa-with-rc4-128-sha',
    1: 'tls-rsa-with-aes-128-cbc-sha',
    2: 'tls-dhe-rsa-with-aes-128-cbc-sha',
    3: 'tls-dhe-rsa-with-aes-256-cbc-sha',
    4: 'tls-ecdhe-rsa-with-aes-128-cbc-sha',
    5: 'tls-ecdhe-rsa-with-aes-256-cbc-sha',
    6: 'tls-ecdhe-rsa-with-aes-128-gcm-sha256',
    7: 'tls-ecdhe-rsa-with-aes-256-gcm-sha384',
}

_SSH_HMAC = {
    0: 'hmac-sha1',
    1: 'hmac-sha2-256',
    2: 'hmac-sha2-512',
    3: 'hmac-sha1-etm@openssh.com',
    4: 'hmac-sha2-256-etm@openssh.com',
    5: 'hmac-sha2-512-etm@openssh.com',
}

_SSH_KEX = {
    0: 'diffie-hellman-group1-sha1',
    1: 'diffie-hellman-group14-sha1',
    2: 'diffie-hellman-group14-sha256',
    3: 'diffie-hellman-group16-sha512',
    4: 'diffie-hellman-group18-sha512',
    5: 'diffie-hellman-group-exchange-sha256',
    6: 'ecdh-sha2-nistp256',
    7: 'ecdh-sha2-nistp384',
}

_SSH_ENCRYPTION = {
    0: 'aes128-ctr',
    1: 'aes192-ctr',
    2: 'aes256-ctr',
    3: 'aes128-gcm@openssh.com',
    4: 'aes256-gcm@openssh.com',
    5: 'chacha20-poly1305@openssh.com',
}

_SSH_HOST_KEY = {
    0: 'ecdsa-sha2-nistp256',
    1: 'ecdsa-sha2-nistp384',
    2: 'ecdsa-sha2-nistp521',
    3: 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
    4: 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
    5: 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
    6: 'rsa-sha2-256',
    7: 'rsa-sha2-512',
    8: 'rsa-sha2-256-cert-v01@openssh.com',
    9: 'rsa-sha2-512-cert-v01@openssh.com',
    10: 'ssh-dss',
    11: 'ssh-ed25519',
    12: 'ssh-ed25519-cert-v01@openssh.com',
    13: 'ssh-rsa',
    14: 'ssh-rsa-cert-v01@openssh.com',
}


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
    # PoE (Power over Ethernet)
    # ------------------------------------------------------------------

    _POE_STATUS = {
        '1': 'disabled', '2': 'searching', '3': 'delivering',
        '4': 'fault', '5': 'test', '6': 'other-fault',
    }
    _POE_PRIORITY = {'1': 'critical', '2': 'high', '3': 'low'}
    _POE_PRIORITY_REV = {'critical': '1', 'high': '2', 'low': '3'}
    _POE_CLASS = {
        '1': 'class0', '2': 'class1', '3': 'class2', '4': 'class3',
        '5': 'class4', '6': 'class5', '7': 'class6', '8': 'class7',
        '9': 'class8',
    }
    _POE_SOURCE = {'0': 'internal', '1': 'external'}

    def get_poe(self):
        """Return PoE global state, per-module budgets, and per-port config.

        Returns:
            dict with:
                'enabled': bool (global admin state)
                'power_w': int (reserved system power, watts)
                'delivered_current_ma': int (system delivered current, mA)
                'modules': {unit/slot: {budget_w, max_w, reserved_w,
                    delivered_w, source, threshold_pct, notifications}}
                'ports': {port_name: {enabled, status, priority,
                    classification, consumption_mw, power_limit_mw,
                    name, fast_startup}}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-POE-MIB", "hm2PoeMgmtGlobalGroup", [
                "hm2PoeMgmtAdminStatus",
                "hm2PoeMgmtReservedPower",
                "hm2PoeMgmtDeliveredCurrent",
            ]),
            ("HM2-POE-MIB", "hm2PoeMgmtPortEntry", [
                "ifIndex",
                "hm2PoeMgmtPortAdminEnable",
                "hm2PoeMgmtPortDetectionStatus",
                "hm2PoeMgmtPortPowerPriority",
                "hm2PoeMgmtPortPowerClassification",
                "hm2PoeMgmtPortConsumptionPower",
                "hm2PoeMgmtPortPowerLimit",
                "hm2PoeMgmtPortName",
                "hm2PoeMgmtPortFastStartup",
                "hm2PoeMgmtPortClassValid",
            ]),
            ("HM2-POE-MIB", "hm2PoeMgmtModuleEntry", [
                "hm2PoeMgmtModuleUnitIndex",
                "hm2PoeMgmtModuleSlotIndex",
                "hm2PoeMgmtModulePower",
                "hm2PoeMgmtModuleMaximumPower",
                "hm2PoeMgmtModuleReservedPower",
                "hm2PoeMgmtModuleDeliveredPower",
                "hm2PoeMgmtModulePowerSource",
                "hm2PoeMgmtModuleUsageThreshold",
                "hm2PoeMgmtModuleNotificationControlEnable",
            ]),
            decode_strings=False,
        )

        poe = mibs.get("HM2-POE-MIB", {})
        glb = poe.get("hm2PoeMgmtGlobalGroup", [{}])[0]

        # --- modules ---
        modules = {}
        for entry in poe.get("hm2PoeMgmtModuleEntry", []):
            unit = entry.get("hm2PoeMgmtModuleUnitIndex", "1")
            slot = entry.get("hm2PoeMgmtModuleSlotIndex", "1")
            key = f"{unit}/{slot}"
            src_code = entry.get("hm2PoeMgmtModulePowerSource", "0")
            modules[key] = {
                'budget_w': _safe_int(
                    entry.get("hm2PoeMgmtModulePower", "0")),
                'max_w': _safe_int(
                    entry.get("hm2PoeMgmtModuleMaximumPower", "0")),
                'reserved_w': _safe_int(
                    entry.get("hm2PoeMgmtModuleReservedPower", "0")),
                'delivered_w': _safe_int(
                    entry.get("hm2PoeMgmtModuleDeliveredPower", "0")),
                'source': self._POE_SOURCE.get(src_code, 'internal'),
                'threshold_pct': _safe_int(
                    entry.get("hm2PoeMgmtModuleUsageThreshold", "90")),
                'notifications': entry.get(
                    "hm2PoeMgmtModuleNotificationControlEnable",
                    "1") == "1",
            }

        # --- ports ---
        ports = {}
        for entry in poe.get("hm2PoeMgmtPortEntry", []):
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue

            pri_code = entry.get("hm2PoeMgmtPortPowerPriority", "3")
            status_code = entry.get("hm2PoeMgmtPortDetectionStatus", "1")
            class_code = entry.get("hm2PoeMgmtPortPowerClassification", "1")
            class_valid = entry.get("hm2PoeMgmtPortClassValid", "0") == "1"
            name_hex = entry.get("hm2PoeMgmtPortName", "")

            ports[name] = {
                'enabled': entry.get(
                    "hm2PoeMgmtPortAdminEnable", "2") == "1",
                'status': self._POE_STATUS.get(status_code, 'disabled'),
                'priority': self._POE_PRIORITY.get(pri_code, 'low'),
                'classification': (
                    self._POE_CLASS.get(class_code)
                    if class_valid else None),
                'consumption_mw': _safe_int(
                    entry.get("hm2PoeMgmtPortConsumptionPower", "0")),
                'power_limit_mw': _safe_int(
                    entry.get("hm2PoeMgmtPortPowerLimit", "0")),
                'name': _decode_hex_string(name_hex),
                'fast_startup': entry.get(
                    "hm2PoeMgmtPortFastStartup", "2") == "1",
            }

        return {
            'enabled': glb.get("hm2PoeMgmtAdminStatus", "2") == "1",
            'power_w': _safe_int(
                glb.get("hm2PoeMgmtReservedPower", "0")),
            'delivered_current_ma': _safe_int(
                glb.get("hm2PoeMgmtDeliveredCurrent", "0")),
            'modules': modules,
            'ports': ports,
        }

    def set_poe(self, interface=None, enabled=None, priority=None,
                power_limit_mw=None, name=None, fast_startup=None):
        """Set PoE configuration.

        If interface is provided, sets per-port values.
        If interface is None, sets global admin state.

        Args:
            interface: port name (str), list of port names, or None for global
            enabled: True/False
            priority: 'critical', 'high', or 'low' (per-port only)
            power_limit_mw: int 0-30000, 0=unlimited (per-port only)
            name: str device label up to 32 chars (per-port only)
            fast_startup: True/False (per-port only)
        """
        if interface is not None:
            interfaces = ([interface] if isinstance(interface, str)
                          else list(interface))
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: idx for idx, n in ifindex_map.items()}

            values = {}
            if enabled is not None:
                values["hm2PoeMgmtPortAdminEnable"] = (
                    "1" if enabled else "2")
            if priority is not None:
                val = self._POE_PRIORITY_REV.get(priority)
                if val is None:
                    raise ValueError(
                        f"Invalid priority '{priority}': "
                        f"use 'critical', 'high', or 'low'")
                values["hm2PoeMgmtPortPowerPriority"] = val
            if power_limit_mw is not None:
                values["hm2PoeMgmtPortPowerLimit"] = str(
                    int(power_limit_mw))
            if name is not None:
                values["hm2PoeMgmtPortName"] = name
            if fast_startup is not None:
                values["hm2PoeMgmtPortFastStartup"] = (
                    "1" if fast_startup else "2")

            if not values:
                return

            mutations = []
            for iface in interfaces:
                ifidx = name_to_idx.get(iface)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{iface}'")
                mutations.append((
                    "HM2-POE-MIB", "hm2PoeMgmtPortEntry",
                    dict(values), {"ifIndex": ifidx}))

            self._apply_mutations(mutations)
        else:
            values = {}
            if enabled is not None:
                values["hm2PoeMgmtAdminStatus"] = (
                    "1" if enabled else "2")

            if values:
                self._apply_set("HM2-POE-MIB",
                                "hm2PoeMgmtGlobalGroup", values)

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

    # Field → batch mapping for selective get_services() queries.
    # Batches: 'mgmt', 'industrial', 'ext' (scalars), 'aca' (table)
    _SVC_FIELD_BATCH = {
        'http': 'mgmt', 'https': 'mgmt', 'ssh': 'mgmt',
        'telnet': 'mgmt', 'snmp': 'mgmt',
        'industrial': 'industrial',
        'unsigned_sw': 'ext', 'mvrp': 'ext', 'mmrp': 'ext',
        'devsec_monitors': 'ext',
        'aca_auto_update': 'aca', 'aca_config_write': 'aca',
        'aca_config_load': 'aca',
        'gvrp': None, 'gmrp': None,  # hardcoded, no query
    }

    _DEVSEC_ATTRS = [
        "hm2DevSecSensePasswordChange",
        "hm2DevSecSensePasswordMinLength",
        "hm2DevSecSensePasswordStrengthNotConfigured",
        "hm2DevSecSenseBypassPasswordStrength",
        "hm2DevSecSenseTelnetEnabled",
        "hm2DevSecSenseHttpEnabled",
        "hm2DevSecSenseSnmpUnsecure",
        "hm2DevSecSenseSysmonEnabled",
        "hm2DevSecSenseExtNvmUpdateEnabled",
        "hm2DevSecSenseNoLinkEnabled",
        "hm2DevSecSenseHiDiscoveryEnabled",
        "hm2DevSecSenseExtNvmConfigLoadUnsecure",
        "hm2DevSecSenseIec61850MmsEnabled",
        "hm2DevSecSenseHttpsCertificateWarning",
        "hm2DevSecSenseModbusTcpEnabled",
        "hm2DevSecSenseEtherNetIpEnabled",
        "hm2DevSecSenseProfinetIOEnabled",
        "hm2DevSecSenseSecureBootDisabled",
        "hm2DevSecSenseDevModeEnabled",
    ]

    def get_services(self, *fields):
        """Read service enable/disable state across management + industrial.

        Args:
            *fields: optional field names to query.  If omitted, returns
                all fields.  Pass specific names (e.g. ``'unsigned_sw'``,
                ``'mvrp'``) to query only the batches that contain those
                fields — fewer MOPS round-trips.

        Returns::

            {
                'http': {'enabled': bool, 'port': int},
                'https': {'enabled': bool, 'port': int,
                          'tls_versions': [str],
                          'tls_cipher_suites': [str]},
                'ssh': {'enabled': bool,
                        'hmac_algorithms': [str],
                        'kex_algorithms': [str],
                        'encryption_algorithms': [str],
                        'host_key_algorithms': [str]},
                'telnet': {'enabled': bool},
                'snmp': {'v1': bool, 'v2': bool, 'v3': bool, 'port': int},
                'industrial': {
                    'iec61850': bool, 'profinet': bool,
                    'ethernet_ip': bool, 'opcua': bool, 'modbus': bool,
                },
                'unsigned_sw': bool,
                'aca_auto_update': bool,
                'aca_config_write': bool,
                'aca_config_load': bool,
                'mvrp': bool,
                'mmrp': bool,
                'gvrp': bool,
                'gmrp': bool,
                'devsec_monitors': bool,
            }
        """
        if fields:
            need = {self._SVC_FIELD_BATCH.get(f) for f in fields} - {None}
        else:
            need = {'mgmt', 'industrial', 'ext', 'aca'}

        out = {}

        # Batch: management protocols
        if 'mgmt' in need:
            result = self.client.get_multi([
                ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup", [
                    "hm2WebHttpAdminStatus", "hm2WebHttpsAdminStatus",
                    "hm2WebHttpPortNumber", "hm2WebHttpsPortNumber",
                    "hm2WebHttpsServerTlsVersions",
                    "hm2WebHttpsServerTlsCipherSuites"]),
                ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup", [
                    "hm2SshAdminStatus",
                    "hm2SshHmacAlgorithms",
                    "hm2SshKexAlgorithms",
                    "hm2SshEncryptionAlgorithms",
                    "hm2SshHostKeyAlgorithms"]),
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
            out.update({
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
                    'tls_versions': _decode_bits_hex(
                        web.get("hm2WebHttpsServerTlsVersions", ""),
                        _TLS_VERSIONS),
                    'tls_cipher_suites': _decode_bits_hex(
                        web.get("hm2WebHttpsServerTlsCipherSuites",
                                ""), _TLS_CIPHER_SUITES),
                },
                'ssh': {
                    'enabled': _safe_int(ssh.get(
                        "hm2SshAdminStatus", "2")) == 1,
                    'hmac_algorithms': _decode_bits_hex(
                        ssh.get("hm2SshHmacAlgorithms", ""),
                        _SSH_HMAC),
                    'kex_algorithms': _decode_bits_hex(
                        ssh.get("hm2SshKexAlgorithms", ""),
                        _SSH_KEX),
                    'encryption_algorithms': _decode_bits_hex(
                        ssh.get("hm2SshEncryptionAlgorithms", ""),
                        _SSH_ENCRYPTION),
                    'host_key_algorithms': _decode_bits_hex(
                        ssh.get("hm2SshHostKeyAlgorithms", ""),
                        _SSH_HOST_KEY),
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
            })

        # Batch: industrial protocols
        if 'industrial' in need:
            ind_result = self.client.get_multi([
                ("HM2-INDUSTRIAL-PROTOCOLS-MIB",
                 "hm2Iec61850ConfigGroup",
                 ["hm2Iec61850MmsServerAdminStatus"]),
                ("HM2-INDUSTRIAL-PROTOCOLS-MIB",
                 "hm2ProfinetIOConfigGroup",
                 ["hm2PNIOAdminStatus"]),
                ("HM2-INDUSTRIAL-PROTOCOLS-MIB",
                 "hm2EthernetIPConfigGroup",
                 ["hm2EtherNetIPAdminStatus"]),
                ("HM2-INDUSTRIAL-PROTOCOLS-MIB",
                 "hm2Iec62541ConfigGroup",
                 ["hm2Iec62541OpcUaServerAdminStatus"]),
                ("HM2-INDUSTRIAL-PROTOCOLS-MIB",
                 "hm2ModbusConfigGroup",
                 ["hm2ModbusTcpServerAdminStatus"]),
            ], decode_strings=False)
            ind_mibs = ind_result["mibs"].get(
                "HM2-INDUSTRIAL-PROTOCOLS-MIB", {})
            iec = (ind_mibs.get("hm2Iec61850ConfigGroup", [{}])[0])
            pn = (ind_mibs.get("hm2ProfinetIOConfigGroup", [{}])[0])
            eip = (ind_mibs.get("hm2EthernetIPConfigGroup", [{}])[0])
            opc = (ind_mibs.get("hm2Iec62541ConfigGroup", [{}])[0])
            mb = (ind_mibs.get("hm2ModbusConfigGroup", [{}])[0])
            out['industrial'] = {
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
            }

        # Batch: extended scalars (unsigned_sw + MVRP + MMRP + DevSec)
        if 'ext' in need:
            ext_result = self.client.get_multi([
                ("HM2-DEVMGMT-MIB",
                 "hm2DeviceMgmtSoftwareVersionGroup",
                 ["hm2DevMgmtSwVersAllowUnsigned"]),
                ("HM2-PLATFORM-MVRP-MIB", "hm2AgentDot1qMvrp",
                 ["hm2AgentDot1qBridgeMvrpMode"]),
                ("HM2-PLATFORM-MMRP-MIB", "hm2AgentDot1qMmrp",
                 ["hm2AgentDot1qBridgeMmrpMode"]),
                ("HM2-DIAGNOSTIC-MIB", "hm2DevSecConfigGroup",
                 self._DEVSEC_ATTRS),
            ], decode_strings=False)
            unsw = (ext_result["mibs"]
                    .get("HM2-DEVMGMT-MIB", {})
                    .get("hm2DeviceMgmtSoftwareVersionGroup",
                         [{}])[0])
            mvrp_d = (ext_result["mibs"]
                      .get("HM2-PLATFORM-MVRP-MIB", {})
                      .get("hm2AgentDot1qMvrp", [{}])[0])
            mmrp_d = (ext_result["mibs"]
                      .get("HM2-PLATFORM-MMRP-MIB", {})
                      .get("hm2AgentDot1qMmrp", [{}])[0])
            devsec = (ext_result["mibs"]
                      .get("HM2-DIAGNOSTIC-MIB", {})
                      .get("hm2DevSecConfigGroup", [{}])[0])
            out['unsigned_sw'] = _safe_int(unsw.get(
                "hm2DevMgmtSwVersAllowUnsigned", "2")) == 1
            out['mvrp'] = _safe_int(mvrp_d.get(
                "hm2AgentDot1qBridgeMvrpMode", "2")) == 1
            out['mmrp'] = _safe_int(mmrp_d.get(
                "hm2AgentDot1qBridgeMmrpMode", "2")) == 1
            out['devsec_monitors'] = all(
                _safe_int(devsec.get(a, "2")) == 1
                for a in self._DEVSEC_ATTRS)

        # Batch: ACA / ExtNVM table
        if 'aca' in need:
            try:
                aca_rows = self.client.get(
                    "HM2-DEVMGMT-MIB", "hm2ExtNvmEntry",
                    ["hm2ExtNvmTableIndex",
                     "hm2ExtNvmAutomaticSoftwareLoad",
                     "hm2ExtNvmConfigLoadPriority",
                     "hm2ExtNvmConfigSave"],
                    decode_strings=False)
            except (MOPSError, ConnectionException):
                aca_rows = []
            aca_auto = False
            aca_write = False
            aca_load = False
            for row in aca_rows:
                if _safe_int(row.get(
                        "hm2ExtNvmAutomaticSoftwareLoad", "2")) == 1:
                    aca_auto = True
                if _safe_int(row.get(
                        "hm2ExtNvmConfigSave", "2")) == 1:
                    aca_write = True
                if _safe_int(row.get(
                        "hm2ExtNvmConfigLoadPriority", "0")) != 0:
                    aca_load = True
            out['aca_auto_update'] = aca_auto
            out['aca_config_write'] = aca_write
            out['aca_config_load'] = aca_load

        # Hardcoded (no OID in HiOS MIBs — legacy, not supported)
        if not fields or 'gvrp' in fields:
            out['gvrp'] = False
        if not fields or 'gmrp' in fields:
            out['gmrp'] = False

        return out

    def set_services(self, http=None, https=None, ssh=None,
                     telnet=None, snmp_v1=None, snmp_v2=None,
                     snmp_v3=None, iec61850=None, profinet=None,
                     ethernet_ip=None, opcua=None, modbus=None,
                     unsigned_sw=None, aca_auto_update=None,
                     aca_config_write=None, aca_config_load=None,
                     mvrp=None, mmrp=None, devsec_monitors=None,
                     tls_versions=None, tls_cipher_suites=None,
                     ssh_hmac=None, ssh_kex=None,
                     ssh_encryption=None, ssh_host_key=None):
        """Set service enable/disable state.

        Each bool arg is True=enable, False=disable, None=no change.
        Cipher list args accept a list of algorithm names (see
        ``get_services()`` for valid names).
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
        if unsigned_sw is not None:
            mutations.append((
                "HM2-DEVMGMT-MIB",
                "hm2DeviceMgmtSoftwareVersionGroup",
                {"hm2DevMgmtSwVersAllowUnsigned": _en(unsigned_sw)}))
        if mvrp is not None:
            mutations.append((
                "HM2-PLATFORM-MVRP-MIB", "hm2AgentDot1qMvrp",
                {"hm2AgentDot1qBridgeMvrpMode": _en(mvrp)}))
        if mmrp is not None:
            mutations.append((
                "HM2-PLATFORM-MMRP-MIB", "hm2AgentDot1qMmrp",
                {"hm2AgentDot1qBridgeMmrpMode": _en(mmrp)}))
        if devsec_monitors is not None:
            mutations.append((
                "HM2-DIAGNOSTIC-MIB", "hm2DevSecConfigGroup",
                {a: _en(devsec_monitors) for a in self._DEVSEC_ATTRS}))
        if tls_versions is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup",
                {"hm2WebHttpsServerTlsVersions":
                 _encode_bits_hex(tls_versions, _TLS_VERSIONS)}))
        if tls_cipher_suites is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup",
                {"hm2WebHttpsServerTlsCipherSuites":
                 _encode_bits_hex(tls_cipher_suites,
                                  _TLS_CIPHER_SUITES)}))
        if ssh_hmac is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup",
                {"hm2SshHmacAlgorithms":
                 _encode_bits_hex(ssh_hmac, _SSH_HMAC)}))
        if ssh_kex is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup",
                {"hm2SshKexAlgorithms":
                 _encode_bits_hex(ssh_kex, _SSH_KEX)}))
        if ssh_encryption is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup",
                {"hm2SshEncryptionAlgorithms":
                 _encode_bits_hex(ssh_encryption, _SSH_ENCRYPTION)}))
        if ssh_host_key is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup",
                {"hm2SshHostKeyAlgorithms":
                 _encode_bits_hex(ssh_host_key, _SSH_HOST_KEY)}))

        self._apply_mutations(mutations)

        # ACA fields require indexed SET on each NVM row
        if any(v is not None for v in (aca_auto_update,
                                       aca_config_write,
                                       aca_config_load)):
            try:
                aca_rows = self.client.get(
                    "HM2-DEVMGMT-MIB", "hm2ExtNvmEntry",
                    ["hm2ExtNvmTableIndex"],
                    decode_strings=False)
            except (MOPSError, ConnectionException):
                aca_rows = []
            for row in aca_rows:
                idx_val = row.get("hm2ExtNvmTableIndex", "")
                if not idx_val:
                    continue
                values = {}
                if aca_auto_update is not None:
                    values["hm2ExtNvmAutomaticSoftwareLoad"] = (
                        _en(aca_auto_update))
                if aca_config_write is not None:
                    values["hm2ExtNvmConfigSave"] = (
                        _en(aca_config_write))
                if aca_config_load is not None:
                    values["hm2ExtNvmConfigLoadPriority"] = (
                        "0" if not aca_config_load else "1")
                if values:
                    self._apply_set_indexed(
                        "HM2-DEVMGMT-MIB", "hm2ExtNvmEntry",
                        {"hm2ExtNvmTableIndex": idx_val},
                        values)

    # ------------------------------------------------------------------
    # SNMP Config (HM2-MGMTACCESS-MIB + SNMP-COMMUNITY-MIB)
    # ------------------------------------------------------------------

    # SNMP auth/enc type enums
    _SNMP_AUTH_TYPE = {0: '', 1: 'md5', 2: 'sha'}
    _SNMP_ENC_TYPE = {0: 'none', 1: 'des', 2: 'aes128', 3: 'aes256'}

    def get_snmp_config(self):
        """Read SNMP configuration: versions, port, communities,
        trap service, v3 user auth/enc, trap destinations.

        Returns::

            {
                'versions': {'v1': bool, 'v2': bool, 'v3': bool},
                'port': int,
                'communities': [{'name': str, 'access': str}],
                'trap_service': bool,
                'v3_users': [{'name': str, 'auth_type': str, 'enc_type': str}],
                'trap_destinations': [
                    {'name': str, 'address': str, 'security_model': str,
                     'security_name': str, 'security_level': str},
                ],
            }
        """
        snmp_data = self.client.get(
            "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup",
            ["hm2SnmpV1AdminStatus", "hm2SnmpV2AdminStatus",
             "hm2SnmpV3AdminStatus", "hm2SnmpPortNumber",
             "hm2SnmpTrapServiceAdminStatus"],
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

        # v3 user auth/enc from HM2-USERMGMT-MIB
        v3_users = self._get_snmp_v3_users()

        # Trap destinations from SNMP-TARGET-MIB
        trap_destinations = self._get_trap_destinations()

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
            'trap_service': _safe_int(s.get(
                "hm2SnmpTrapServiceAdminStatus", "2")) == 1,
            'v3_users': v3_users,
            'trap_destinations': trap_destinations,
        }

    def _get_snmp_v3_users(self):
        """Read SNMPv3 user auth/enc types from HM2-USERMGMT-MIB."""
        try:
            entries = self.client.get(
                "HM2-USERMGMT-MIB", "hm2UserConfigEntry",
                ["hm2UserName", "hm2UserSnmpAuthType",
                 "hm2UserSnmpEncType", "hm2UserStatus"],
                decode_strings=False)
        except MOPSError:
            return []

        users = []
        for entry in entries:
            status = _safe_int(entry.get("hm2UserStatus", "0"))
            if status != 1:  # only active users
                continue
            name = _decode_hex_string(
                entry.get("hm2UserName", ""))
            if not name:
                continue
            auth = _safe_int(entry.get("hm2UserSnmpAuthType", "0"))
            enc = _safe_int(entry.get("hm2UserSnmpEncType", "0"))
            users.append({
                'name': name,
                'auth_type': self._SNMP_AUTH_TYPE.get(auth, ''),
                'enc_type': self._SNMP_ENC_TYPE.get(enc, 'none'),
            })
        return users

    def _get_trap_destinations(self):
        """Read SNMP trap destinations from SNMP-TARGET-MIB."""
        _SEC_MODEL = {1: 'v1', 2: 'v2c', 3: 'v3'}
        _SEC_LEVEL = {1: 'noauth', 2: 'auth', 3: 'authpriv'}

        # Target address table
        try:
            addr_entries = self.client.get(
                "SNMP-TARGET-MIB", "snmpTargetAddrEntry",
                ["snmpTargetAddrName", "snmpTargetAddrTAddress",
                 "snmpTargetAddrParams"],
                decode_strings=False)
        except MOPSError:
            return []

        # Target params table
        try:
            params_entries = self.client.get(
                "SNMP-TARGET-MIB", "snmpTargetParamsEntry",
                ["snmpTargetParamsName",
                 "snmpTargetParamsSecurityModel",
                 "snmpTargetParamsSecurityName",
                 "snmpTargetParamsSecurityLevel"],
                decode_strings=False)
        except MOPSError:
            params_entries = []

        # Build params lookup
        params_map = {}
        for pe in params_entries:
            pname = _decode_hex_string(
                pe.get("snmpTargetParamsName", ""))
            if pname:
                params_map[pname] = {
                    'security_model': _SEC_MODEL.get(_safe_int(
                        pe.get("snmpTargetParamsSecurityModel",
                               "0")), ''),
                    'security_name': _decode_hex_string(
                        pe.get("snmpTargetParamsSecurityName", "")),
                    'security_level': _SEC_LEVEL.get(_safe_int(
                        pe.get("snmpTargetParamsSecurityLevel",
                               "0")), ''),
                }

        destinations = []
        for ae in addr_entries:
            name = _decode_hex_string(
                ae.get("snmpTargetAddrName", ""))
            taddr = ae.get("snmpTargetAddrTAddress", "")
            params_ref = _decode_hex_string(
                ae.get("snmpTargetAddrParams", ""))
            address = self._decode_taddress(taddr)
            params = params_map.get(params_ref, {})
            model = params.get('security_model', '')
            # v1/v2c don't use security levels — normalise
            level = ('noauth' if model in ('v1', 'v2c')
                     else params.get('security_level', ''))
            destinations.append({
                'name': name,
                'address': address,
                'security_model': model,
                'security_name': params.get(
                    'security_name', ''),
                'security_level': level,
            })
        return destinations

    @staticmethod
    def _decode_taddress(hex_str):
        """Decode SNMP TAddress (6 hex bytes: 4 IP + 2 port) to ip:port."""
        if not hex_str:
            return ''
        parts = hex_str.strip().split()
        if len(parts) == 6:
            try:
                ip = '.'.join(str(int(p, 16)) for p in parts[:4])
                port = int(parts[4], 16) * 256 + int(parts[5], 16)
                return f'{ip}:{port}'
            except ValueError:
                pass
        return hex_str

    def set_snmp_config(self, v1=None, v2=None, v3=None,
                        trap_service=None):
        """Set SNMP version enable/disable and trap service.

        Args:
            v1, v2, v3: bool or None
            trap_service: bool or None — enable/disable trap service
        """
        values = {}
        if v1 is not None:
            values["hm2SnmpV1AdminStatus"] = "1" if v1 else "2"
        if v2 is not None:
            values["hm2SnmpV2AdminStatus"] = "1" if v2 else "2"
        if v3 is not None:
            values["hm2SnmpV3AdminStatus"] = "1" if v3 else "2"
        if trap_service is not None:
            values["hm2SnmpTrapServiceAdminStatus"] = (
                "1" if trap_service else "2")
        if values:
            self._apply_set(
                "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup",
                values)

    # ------------------------------------------------------------------
    # SNMP Trap Destinations (SNMP-TARGET-MIB)
    # ------------------------------------------------------------------

    _SEC_MODEL_REV = {'v1': '1', 'v2c': '2', 'v3': '3'}
    _SEC_LEVEL_REV = {'noauth': '1', 'auth': '2', 'authpriv': '3'}

    @staticmethod
    def _encode_taddress(ip, port=162):
        """Encode IP:port to MOPS hex TAddress (6 bytes)."""
        parts = ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address: {ip}")
        octets = [int(p) for p in parts]
        octets.append(port >> 8)
        octets.append(port & 0xFF)
        return " ".join(f"{b:02x}" for b in octets)

    def add_snmp_trap_dest(self, name, address, port=162,
                           security_model='v3', security_name='admin',
                           security_level='authpriv'):
        """Add an SNMP trap destination.

        Creates entries in both snmpTargetAddrTable and
        snmpTargetParamsTable (RFC 3413 SNMP-TARGET-MIB).

        Args:
            name: Destination name (1-32 chars).
            address: Destination IP address.
            port: UDP port (default 162).
            security_model: 'v1', 'v2c', or 'v3'.
            security_name: Community (v1/v2c) or username (v3).
            security_level: 'noauth', 'auth', or 'authpriv'.
        """
        if security_model not in self._SEC_MODEL_REV:
            raise ValueError(
                f"Invalid security_model '{security_model}': "
                f"use 'v1', 'v2c', or 'v3'")
        # v1/v2c only supports noauth — override regardless
        if security_model in ('v1', 'v2c'):
            security_level = 'noauth'
        if security_level not in self._SEC_LEVEL_REV:
            raise ValueError(
                f"Invalid security_level '{security_level}': "
                f"use 'noauth', 'auth', or 'authpriv'")

        hex_name = encode_string(name)
        idx_addr = {"snmpTargetAddrName": hex_name}
        idx_params = {"snmpTargetParamsName": hex_name}

        # Create params entry first (addr references it)
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetParamsEntry",
            index=idx_params,
            values={
                "snmpTargetParamsRowStatus": "5",  # createAndWait
            })
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetParamsEntry",
            index=idx_params,
            values={
                "snmpTargetParamsSecurityModel":
                    self._SEC_MODEL_REV[security_model],
                "snmpTargetParamsSecurityName":
                    encode_string(security_name),
                "snmpTargetParamsSecurityLevel":
                    self._SEC_LEVEL_REV[security_level],
            })
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetParamsEntry",
            index=idx_params,
            values={"snmpTargetParamsRowStatus": "1"})  # active

        # Create addr entry
        taddr = self._encode_taddress(address, port)
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetAddrEntry",
            index=idx_addr,
            values={
                "snmpTargetAddrRowStatus": "5",  # createAndWait
            })
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetAddrEntry",
            index=idx_addr,
            values={
                "snmpTargetAddrTAddress": taddr,
                "snmpTargetAddrParams": hex_name,
            })
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetAddrEntry",
            index=idx_addr,
            values={"snmpTargetAddrRowStatus": "1"})  # active

    def delete_snmp_trap_dest(self, name):
        """Delete an SNMP trap destination.

        Removes entries from both snmpTargetAddrTable and
        snmpTargetParamsTable.

        Args:
            name: Destination name to delete.
        """
        hex_name = encode_string(name)
        # Destroy addr first, then params
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetAddrEntry",
            index={"snmpTargetAddrName": hex_name},
            values={"snmpTargetAddrRowStatus": "6"})  # destroy
        self._apply_set_indexed(
            "SNMP-TARGET-MIB", "snmpTargetParamsEntry",
            index={"snmpTargetParamsName": hex_name},
            values={"snmpTargetParamsRowStatus": "6"})  # destroy

    # ------------------------------------------------------------------
    # Signal Contact (HM2-DIAGNOSTIC-MIB / hm2SignalContactGroup)
    # ------------------------------------------------------------------

    _SIGCON_MODE = {
        '1': 'manual', '2': 'monitor', '3': 'deviceState',
        '4': 'deviceSecurity', '5': 'deviceStateAndSecurity',
    }
    _SIGCON_MODE_REV = {v: k for k, v in _SIGCON_MODE.items()}

    _SIGCON_OPER = {'1': 'open', '2': 'close'}
    _SIGCON_MANUAL = {'1': 'open', '2': 'close'}
    _SIGCON_MANUAL_REV = {'open': '1', 'close': '2'}

    _SIGCON_TRAP_CAUSE = {
        '1': 'none', '2': 'power-supply', '3': 'link-failure',
        '4': 'temperature', '5': 'fan-failure', '6': 'module-removal',
        '7': 'ext-nvm-removal', '8': 'ext-nvm-not-in-sync',
        '9': 'ring-redundancy', '10': 'power-fail-imminent',
        '11': 'invalid-cfg', '12': 'sw-watchdog', '13': 'hw-watchdog',
        '14': 'ext-nvm-update-enabled', '15': 'hw-failure',
        '16': 'dev-temp-sensor-failure', '17': 'temp-warning',
        '18': 'security-incident', '19': 'config-corrupted',
        '20': 'system-reboot', '21': 'system-poweron',
        '22': 'system-poweroff', '23': 'license-invalid',
        '24': 'license-missing', '25': 'pml-enabled',
        '26': 'profinet-io-enabled', '27': 'ethernet-loops',
        '28': 'humidity', '29': 'pml-disabled',
        '30': 'stp-port-blocked', '31': 'secure-boot-disabled',
        '32': 'dev-mode-enabled',
    }

    # Sense flag attrs → human-readable key.  Order matches MIB OID order.
    _SIGCON_SENSE = [
        ("hm2SigConSenseLinkFailure", "link_failure"),
        ("hm2SigConSenseTemperature", "temperature"),
        ("hm2SigConSenseFan", "fan"),
        ("hm2SigConSenseModuleRemoval", "module_removal"),
        ("hm2SigConSenseExtNvmRemoval", "envm_removal"),
        ("hm2SigConSenseExtNvmNotInSync", "envm_not_in_sync"),
        ("hm2SigConSenseRingRedundancy", "ring_redundancy"),
        ("hm2SigConSenseEthernetLoops", "ethernet_loops"),
        ("hm2SigConSenseHumidity", "humidity"),
        ("hm2SigConSenseStpPortBlock", "stp_port_block"),
    ]
    _SIGCON_SENSE_REV = {v: k for k, v in _SIGCON_SENSE}

    def get_signal_contact(self):
        """Read signal contact configuration and status.

        Returns dict keyed by contact ID (int)::

            {
                1: {
                    'mode': 'monitor',
                    'manual_state': 'close',
                    'trap_enabled': False,
                    'monitoring': {
                        'temperature': True,
                        'link_failure': False,
                        ...  # platform-dependent keys
                    },
                    'power_supply': {1: True, 2: True},
                    'link_alarm': {'1/1': False, ...},
                    'status': {
                        'oper_state': 'open',
                        'last_change': '2026-03-10 08:23:09',
                        'cause': 'power-supply',
                        'cause_index': 2,
                        'events': [
                            {'cause': 'power-supply', 'info': 2,
                             'timestamp': '...'},
                        ],
                    },
                }
            }
        """
        sense_attrs = [a for a, _ in self._SIGCON_SENSE]
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-DIAGNOSTIC-MIB", "hm2SigConCommonEntry",
             ["hm2SigConID", "hm2SigConMode", "hm2SigConOperState",
              "hm2SigConTrapEnable", "hm2SigConTrapCause",
              "hm2SigConTrapCauseIndex", "hm2SigConManualActivate",
              "hm2SigConOperTimeStamp"] + sense_attrs),
            ("HM2-DIAGNOSTIC-MIB", "hm2SigConPSEntry",
             ["hm2SigConID", "hm2SigConSensePSState"]),
            ("HM2-DIAGNOSTIC-MIB", "hm2SigConInterfaceEntry",
             ["hm2SigConID", "hm2SigConSenseIfLinkAlarm"]),
            ("HM2-DIAGNOSTIC-MIB", "hm2SigConStatusEntry",
             ["hm2SigConStatusIndex", "hm2SigConStatusTimeStamp",
              "hm2SigConStatusTrapCause", "hm2SigConStatusTrapCauseIndex"]),
            decode_strings=False,
        )

        diag = mibs.get("HM2-DIAGNOSTIC-MIB", {})
        common_rows = diag.get("hm2SigConCommonEntry", [])
        ps_rows = diag.get("hm2SigConPSEntry", [])
        intf_rows = diag.get("hm2SigConInterfaceEntry", [])
        status_rows = diag.get("hm2SigConStatusEntry", [])

        result = {}
        for row in common_rows:
            cid = _safe_int(row.get("hm2SigConID", "1"))
            ts = _safe_int(row.get("hm2SigConOperTimeStamp", "0"))

            monitoring = {}
            for attr, key in self._SIGCON_SENSE:
                val = row.get(attr)
                if val is not None:
                    monitoring[key] = _safe_int(val) == 1

            cause_val = row.get("hm2SigConTrapCause", "1")
            result[cid] = {
                'mode': self._SIGCON_MODE.get(
                    row.get("hm2SigConMode", "2"), "monitor"),
                'manual_state': self._SIGCON_MANUAL.get(
                    row.get("hm2SigConManualActivate", "2"), "close"),
                'trap_enabled': _safe_int(
                    row.get("hm2SigConTrapEnable", "2")) == 1,
                'monitoring': monitoring,
                'power_supply': {},
                'link_alarm': {},
                'status': {
                    'oper_state': self._SIGCON_OPER.get(
                        row.get("hm2SigConOperState", "2"), "close"),
                    'last_change': self._format_timestamp(ts),
                    'cause': self._SIGCON_TRAP_CAUSE.get(
                        cause_val, cause_val),
                    'cause_index': _safe_int(
                        row.get("hm2SigConTrapCauseIndex", "0")),
                    'events': [],
                },
            }

        # Power supply rows: indexed by (SigConID, PSID) — PSID is
        # implicit row order (1, 2, ...) since MOPS doesn't return it.
        ps_by_contact = {}
        for row in ps_rows:
            cid = _safe_int(row.get("hm2SigConID", "1"))
            ps_by_contact.setdefault(cid, []).append(row)
        for cid, rows in ps_by_contact.items():
            if cid in result:
                for i, row in enumerate(rows, 1):
                    result[cid]['power_supply'][i] = (
                        _safe_int(row.get("hm2SigConSensePSState", "2"))
                        == 1)

        # Interface rows: indexed by (SigConID, ifIndex)
        for row in intf_rows:
            cid = _safe_int(row.get("hm2SigConID", "1"))
            if cid not in result:
                continue
            # Resolve ifIndex — rows arrive in ifIndex order
            # but ifIndex not always returned as attribute.
            # We match by position against known ifindex_map.
        # Re-fetch interface table with ifIndex for proper resolution
        intf_by_contact = {}
        for row in intf_rows:
            cid = _safe_int(row.get("hm2SigConID", "1"))
            intf_by_contact.setdefault(cid, []).append(row)
        for cid, rows in intf_by_contact.items():
            if cid not in result:
                continue
            # MOPS returns rows in ifIndex order; match to ifindex_map
            sorted_idx = sorted(ifindex_map.keys(), key=int)
            for i, row in enumerate(rows):
                if i < len(sorted_idx):
                    port_name = ifindex_map.get(sorted_idx[i], "")
                    if port_name and not port_name.startswith("cpu"):
                        result[cid]['link_alarm'][port_name] = (
                            _safe_int(row.get(
                                "hm2SigConSenseIfLinkAlarm", "2")) == 1)

        # Status/events rows
        for row in status_rows:
            # Status table is under signal contact group but
            # indexed by (SigConID, StatusIndex).  MOPS returns
            # all rows — distribute to matching contact.
            # For single-contact devices, all go to contact 1.
            cause_val = row.get("hm2SigConStatusTrapCause", "1")
            ts = _safe_int(row.get("hm2SigConStatusTimeStamp", "0"))
            cause_idx = _safe_int(
                row.get("hm2SigConStatusTrapCauseIndex", "0"))
            event = {
                'cause': self._SIGCON_TRAP_CAUSE.get(
                    cause_val, cause_val),
                'info': cause_idx,
                'timestamp': self._format_timestamp(ts),
            }
            # Assign to first contact (most devices have 1)
            for cid in result:
                result[cid]['status']['events'].append(event)
                break

        return result

    @staticmethod
    def _format_timestamp(epoch_seconds):
        """Convert HmTimeSeconds1970 to ISO-ish string."""
        if not epoch_seconds:
            return ''
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, OSError, OverflowError):
            return str(epoch_seconds)

    def set_signal_contact(self, contact_id=1, mode=None,
                           manual_state=None, trap_enabled=None,
                           monitoring=None, power_supply=None,
                           link_alarm=None):
        """Configure signal contact relay.

        Args:
            contact_id: 1 or 2 (most devices only have 1)
            mode: 'manual'/'monitor'/'deviceState'/'deviceSecurity'/
                  'deviceStateAndSecurity'
            manual_state: 'open'/'close' (only effective in manual mode)
            trap_enabled: bool
            monitoring: dict of sense flags, e.g.
                {'temperature': True, 'ring_redundancy': True}
            power_supply: dict {psu_id: bool}, e.g. {1: True, 2: False}
            link_alarm: dict {port_name: bool}, e.g. {'1/1': True}
        """
        idx = {"hm2SigConID": str(contact_id)}
        values = {}

        if mode is not None:
            if mode not in self._SIGCON_MODE_REV:
                raise ValueError(
                    f"Invalid mode '{mode}'. Valid: "
                    f"{', '.join(sorted(self._SIGCON_MODE_REV))}")
            values["hm2SigConMode"] = self._SIGCON_MODE_REV[mode]

        if manual_state is not None:
            if manual_state not in self._SIGCON_MANUAL_REV:
                raise ValueError(
                    f"Invalid manual_state '{manual_state}'. "
                    f"Valid: open, close")
            values["hm2SigConManualActivate"] = (
                self._SIGCON_MANUAL_REV[manual_state])

        if trap_enabled is not None:
            values["hm2SigConTrapEnable"] = "1" if trap_enabled else "2"

        if monitoring:
            for key, enabled in monitoring.items():
                attr = self._SIGCON_SENSE_REV.get(key)
                if attr is None:
                    raise ValueError(
                        f"Unknown sense flag '{key}'. Valid: "
                        f"{', '.join(sorted(self._SIGCON_SENSE_REV))}")
                values[attr] = "1" if enabled else "2"

        mutations = []
        if values:
            mutations.append((
                "HM2-DIAGNOSTIC-MIB", "hm2SigConCommonEntry",
                values, idx))

        if power_supply:
            # PS table indexed by (SigConID, PSID) — use set_indexed
            for ps_id, enabled in power_supply.items():
                mutations.append((
                    "HM2-DIAGNOSTIC-MIB", "hm2SigConPSEntry",
                    {"hm2SigConSensePSState": "1" if enabled else "2"},
                    {"hm2SigConID": str(contact_id),
                     "hm2PSID": str(ps_id)}))

        if link_alarm:
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: i for i, n in ifindex_map.items()}
            for port, enabled in link_alarm.items():
                ifidx = name_to_idx.get(port)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{port}'")
                mutations.append((
                    "HM2-DIAGNOSTIC-MIB", "hm2SigConInterfaceEntry",
                    {"hm2SigConSenseIfLinkAlarm":
                     "1" if enabled else "2"},
                    {"hm2SigConID": str(contact_id),
                     "ifIndex": ifidx}))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # Device Monitor (HM2-DIAGNOSTIC-MIB / hm2DeviceMonitorGroup)
    # ------------------------------------------------------------------

    _DEVMON_SENSE = [
        ("hm2DevMonSenseLinkFailure", "link_failure"),
        ("hm2DevMonSenseTemperature", "temperature"),
        ("hm2DevMonSenseFan", "fan"),
        ("hm2DevMonSenseModuleRemoval", "module_removal"),
        ("hm2DevMonSenseExtNvmRemoval", "envm_removal"),
        ("hm2DevMonSenseExtNvmNotInSync", "envm_not_in_sync"),
        ("hm2DevMonSenseRingRedundancy", "ring_redundancy"),
        ("hm2DevMonSenseHumidity", "humidity"),
        ("hm2DevMonSenseStpPortBlock", "stp_port_block"),
    ]
    _DEVMON_SENSE_REV = {v: k for k, v in _DEVMON_SENSE}

    # Device monitor trap causes (subset of signal contact causes)
    _DEVMON_TRAP_CAUSE = {
        '1': 'none', '2': 'power-supply', '3': 'link-failure',
        '4': 'temperature', '5': 'fan-failure', '6': 'module-removal',
        '7': 'ext-nvm-removal', '8': 'ext-nvm-not-in-sync',
        '9': 'ring-redundancy', '28': 'humidity',
        '30': 'stp-port-blocked',
    }

    def get_device_monitor(self):
        """Read device status monitoring configuration and state.

        Returns::

            {
                'trap_enabled': True,
                'monitoring': {
                    'temperature': True,
                    'link_failure': False,
                    ...
                },
                'power_supply': {1: True, 2: True},
                'link_alarm': {'1/1': False, ...},
                'status': {
                    'oper_state': 'error',
                    'last_change': '...',
                    'cause': 'power-supply',
                    'cause_index': 2,
                    'events': [...],
                },
            }
        """
        sense_attrs = [a for a, _ in self._DEVMON_SENSE]
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-DIAGNOSTIC-MIB", "hm2DevMonCommonEntry",
             ["hm2DevMonID", "hm2DevMonTrapEnable",
              "hm2DevMonTrapCause", "hm2DevMonTrapCauseIndex",
              "hm2DevMonOperState", "hm2DevMonOperTimeStamp"]
             + sense_attrs),
            ("HM2-DIAGNOSTIC-MIB", "hm2DevMonPSEntry",
             ["hm2DevMonID", "hm2DevMonSensePSState"]),
            ("HM2-DIAGNOSTIC-MIB", "hm2DevMonInterfaceEntry",
             ["hm2DevMonID", "hm2DevMonSenseIfLinkAlarm"]),
            ("HM2-DIAGNOSTIC-MIB", "hm2DevMonStatusEntry",
             ["hm2DevMonStatusIndex", "hm2DevMonStatusTimeStamp",
              "hm2DevMonStatusTrapCause",
              "hm2DevMonStatusTrapCauseIndex"]),
            decode_strings=False,
        )

        diag = mibs.get("HM2-DIAGNOSTIC-MIB", {})
        common_rows = diag.get("hm2DevMonCommonEntry", [])
        ps_rows = diag.get("hm2DevMonPSEntry", [])
        intf_rows = diag.get("hm2DevMonInterfaceEntry", [])
        status_rows = diag.get("hm2DevMonStatusEntry", [])

        row = common_rows[0] if common_rows else {}
        ts = _safe_int(row.get("hm2DevMonOperTimeStamp", "0"))
        cause_val = row.get("hm2DevMonTrapCause", "1")

        monitoring = {}
        for attr, key in self._DEVMON_SENSE:
            val = row.get(attr)
            if val is not None:
                monitoring[key] = _safe_int(val) == 1

        result = {
            'trap_enabled': _safe_int(
                row.get("hm2DevMonTrapEnable", "2")) == 1,
            'monitoring': monitoring,
            'power_supply': {},
            'link_alarm': {},
            'status': {
                'oper_state': 'error' if _safe_int(
                    row.get("hm2DevMonOperState", "1")) == 2
                    else 'ok',
                'last_change': self._format_timestamp(ts),
                'cause': self._DEVMON_TRAP_CAUSE.get(
                    cause_val, cause_val),
                'cause_index': _safe_int(
                    row.get("hm2DevMonTrapCauseIndex", "0")),
                'events': [],
            },
        }

        # Power supply
        for i, ps_row in enumerate(ps_rows, 1):
            result['power_supply'][i] = (
                _safe_int(ps_row.get(
                    "hm2DevMonSensePSState", "2")) == 1)

        # Interface link alarm
        sorted_idx = sorted(ifindex_map.keys(), key=int)
        for i, irow in enumerate(intf_rows):
            if i < len(sorted_idx):
                port_name = ifindex_map.get(sorted_idx[i], "")
                if port_name and not port_name.startswith("cpu"):
                    result['link_alarm'][port_name] = (
                        _safe_int(irow.get(
                            "hm2DevMonSenseIfLinkAlarm", "2")) == 1)

        # Events
        for srow in status_rows:
            cause_val = srow.get("hm2DevMonStatusTrapCause", "1")
            ts = _safe_int(srow.get("hm2DevMonStatusTimeStamp", "0"))
            result['status']['events'].append({
                'cause': self._DEVMON_TRAP_CAUSE.get(
                    cause_val, cause_val),
                'info': _safe_int(
                    srow.get("hm2DevMonStatusTrapCauseIndex", "0")),
                'timestamp': self._format_timestamp(ts),
            })

        return result

    def set_device_monitor(self, trap_enabled=None, monitoring=None,
                           power_supply=None, link_alarm=None):
        """Configure device status monitoring.

        Args:
            trap_enabled: bool
            monitoring: dict of sense flags
            power_supply: dict {psu_id: bool}
            link_alarm: dict {port_name: bool}
        """
        idx = {"hm2DevMonID": "1"}
        values = {}

        if trap_enabled is not None:
            values["hm2DevMonTrapEnable"] = (
                "1" if trap_enabled else "2")

        if monitoring:
            for key, enabled in monitoring.items():
                attr = self._DEVMON_SENSE_REV.get(key)
                if attr is None:
                    raise ValueError(
                        f"Unknown sense flag '{key}'. Valid: "
                        f"{', '.join(sorted(self._DEVMON_SENSE_REV))}")
                values[attr] = "1" if enabled else "2"

        mutations = []
        if values:
            mutations.append((
                "HM2-DIAGNOSTIC-MIB", "hm2DevMonCommonEntry",
                values, idx))

        if power_supply:
            for ps_id, enabled in power_supply.items():
                mutations.append((
                    "HM2-DIAGNOSTIC-MIB", "hm2DevMonPSEntry",
                    {"hm2DevMonSensePSState":
                     "1" if enabled else "2"},
                    {"hm2DevMonID": "1",
                     "hm2PSID": str(ps_id)}))

        if link_alarm:
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: i for i, n in ifindex_map.items()}
            for port, enabled in link_alarm.items():
                ifidx = name_to_idx.get(port)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{port}'")
                mutations.append((
                    "HM2-DIAGNOSTIC-MIB", "hm2DevMonInterfaceEntry",
                    {"hm2DevMonSenseIfLinkAlarm":
                     "1" if enabled else "2"},
                    {"hm2DevMonID": "1", "ifIndex": ifidx}))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # Device Security Status (HM2-DIAGNOSTIC-MIB / hm2DeviceSecurityGroup)
    # ------------------------------------------------------------------

    _DEVSEC_SENSE = [
        ("hm2DevSecSensePasswordChange", "password_change"),
        ("hm2DevSecSensePasswordMinLength", "password_min_length"),
        ("hm2DevSecSensePasswordStrengthNotConfigured",
         "password_policy_not_configured"),
        ("hm2DevSecSenseBypassPasswordStrength",
         "password_policy_bypass"),
        ("hm2DevSecSenseTelnetEnabled", "telnet_enabled"),
        ("hm2DevSecSenseHttpEnabled", "http_enabled"),
        ("hm2DevSecSenseSnmpUnsecure", "snmp_unsecure"),
        ("hm2DevSecSenseSysmonEnabled", "sysmon_enabled"),
        ("hm2DevSecSenseExtNvmUpdateEnabled", "envm_update_enabled"),
        ("hm2DevSecSenseNoLinkEnabled", "no_link_enabled"),
        ("hm2DevSecSenseHiDiscoveryEnabled", "hidiscovery_enabled"),
        ("hm2DevSecSenseExtNvmConfigLoadUnsecure",
         "envm_config_load_unsecure"),
        ("hm2DevSecSenseIec61850MmsEnabled", "iec61850_mms_enabled"),
        ("hm2DevSecSenseHttpsCertificateWarning",
         "https_cert_warning"),
        ("hm2DevSecSenseModbusTcpEnabled", "modbus_tcp_enabled"),
        ("hm2DevSecSenseEtherNetIpEnabled", "ethernet_ip_enabled"),
        ("hm2DevSecSenseProfinetIOEnabled", "profinet_enabled"),
        ("hm2DevSecSensePMLDisabled", "pml_disabled"),
        ("hm2DevSecSenseSecureBootDisabled", "secure_boot_disabled"),
        ("hm2DevSecSenseDevModeEnabled", "dev_mode_enabled"),
    ]
    _DEVSEC_SENSE_REV = {v: k for k, v in _DEVSEC_SENSE}

    _DEVSEC_TRAP_CAUSE = {
        '1': 'none', '10': 'password-change',
        '11': 'password-min-length',
        '12': 'password-policy-not-configured',
        '13': 'password-policy-inactive',
        '14': 'telnet-enabled', '15': 'http-enabled',
        '16': 'snmp-unsecure', '17': 'sysmon-enabled',
        '18': 'ext-nvm-update-enabled', '19': 'no-link',
        '20': 'hidiscovery-enabled',
        '21': 'ext-nvm-config-load-unsecure',
        '22': 'iec61850-mms-enabled',
        '23': 'https-certificate-warning',
        '24': 'modbus-tcp-enabled',
        '25': 'ethernet-ip-enabled', '26': 'profinet-io-enabled',
        '29': 'pml-disabled', '31': 'secure-boot-disabled',
        '32': 'dev-mode-enabled',
    }

    def get_devsec_status(self):
        """Read device security monitoring configuration and status.

        Returns::

            {
                'trap_enabled': False,
                'monitoring': {
                    'password_change': True,
                    'telnet_enabled': True,
                    'http_enabled': True,
                    ...  # 20 security sense flags
                },
                'no_link': {'1/1': False, ...},
                'status': {
                    'oper_state': 'error',
                    'last_change': '...',
                    'cause': 'https-certificate-warning',
                    'cause_index': 0,
                    'events': [...],
                },
            }
        """
        sense_attrs = [a for a, _ in self._DEVSEC_SENSE]
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-DIAGNOSTIC-MIB", "hm2DevSecConfigGroup",
             ["hm2DevSecTrapEnable", "hm2DevSecTrapCause",
              "hm2DevSecTrapCauseIndex", "hm2DevSecOperState",
              "hm2DevSecOperTimeStamp"] + sense_attrs),
            ("HM2-DIAGNOSTIC-MIB", "hm2DevSecInterfaceEntry",
             ["hm2DevSecSenseIfNoLink"]),
            ("HM2-DIAGNOSTIC-MIB", "hm2DevSecStatusEntry",
             ["hm2DevSecStatusIndex", "hm2DevSecStatusTimeStamp",
              "hm2DevSecStatusTrapCause",
              "hm2DevSecStatusTrapCauseIndex"]),
            decode_strings=False,
        )

        diag = mibs.get("HM2-DIAGNOSTIC-MIB", {})
        config_rows = diag.get("hm2DevSecConfigGroup", [])
        intf_rows = diag.get("hm2DevSecInterfaceEntry", [])
        status_rows = diag.get("hm2DevSecStatusEntry", [])

        row = config_rows[0] if config_rows else {}
        ts = _safe_int(row.get("hm2DevSecOperTimeStamp", "0"))
        cause_val = row.get("hm2DevSecTrapCause", "1")

        monitoring = {}
        for attr, key in self._DEVSEC_SENSE:
            val = row.get(attr)
            if val is not None:
                monitoring[key] = _safe_int(val) == 1

        result = {
            'trap_enabled': _safe_int(
                row.get("hm2DevSecTrapEnable", "2")) == 1,
            'monitoring': monitoring,
            'no_link': {},
            'status': {
                'oper_state': 'error' if _safe_int(
                    row.get("hm2DevSecOperState", "1")) == 2
                    else 'ok',
                'last_change': self._format_timestamp(ts),
                'cause': self._DEVSEC_TRAP_CAUSE.get(
                    cause_val, cause_val),
                'cause_index': _safe_int(
                    row.get("hm2DevSecTrapCauseIndex", "0")),
                'events': [],
            },
        }

        # Per-port no-link monitoring
        sorted_idx = sorted(ifindex_map.keys(), key=int)
        for i, irow in enumerate(intf_rows):
            if i < len(sorted_idx):
                port_name = ifindex_map.get(sorted_idx[i], "")
                if port_name and not port_name.startswith("cpu"):
                    result['no_link'][port_name] = (
                        _safe_int(irow.get(
                            "hm2DevSecSenseIfNoLink", "2")) == 1)

        # Events
        for srow in status_rows:
            cause_val = srow.get("hm2DevSecStatusTrapCause", "1")
            ts = _safe_int(srow.get("hm2DevSecStatusTimeStamp", "0"))
            result['status']['events'].append({
                'cause': self._DEVSEC_TRAP_CAUSE.get(
                    cause_val, cause_val),
                'info': _safe_int(
                    srow.get("hm2DevSecStatusTrapCauseIndex", "0")),
                'timestamp': self._format_timestamp(ts),
            })

        return result

    def set_devsec_status(self, trap_enabled=None, monitoring=None,
                          no_link=None):
        """Configure device security monitoring.

        Args:
            trap_enabled: bool
            monitoring: dict of security sense flags, e.g.
                {'telnet_enabled': True, 'http_enabled': True}
            no_link: dict {port_name: bool}
        """
        values = {}

        if trap_enabled is not None:
            values["hm2DevSecTrapEnable"] = (
                "1" if trap_enabled else "2")

        if monitoring:
            for key, enabled in monitoring.items():
                attr = self._DEVSEC_SENSE_REV.get(key)
                if attr is None:
                    raise ValueError(
                        f"Unknown sense flag '{key}'. Valid: "
                        f"{', '.join(sorted(self._DEVSEC_SENSE_REV))}")
                values[attr] = "1" if enabled else "2"

        mutations = []
        if values:
            mutations.append((
                "HM2-DIAGNOSTIC-MIB", "hm2DevSecConfigGroup",
                values))

        if no_link:
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: i for i, n in ifindex_map.items()}
            for port, enabled in no_link.items():
                ifidx = name_to_idx.get(port)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{port}'")
                mutations.append((
                    "HM2-DIAGNOSTIC-MIB", "hm2DevSecInterfaceEntry",
                    {"hm2DevSecSenseIfNoLink":
                     "1" if enabled else "2"},
                    {"ifIndex": ifidx}))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # Banner (HM2-MGMTACCESS-MIB)
    # ------------------------------------------------------------------

    def get_banner(self):
        """Read pre-login and CLI login banner configuration.

        Returns::

            {
                'pre_login': {'enabled': False, 'text': ''},
                'cli_login': {'enabled': False, 'text': ''},
            }
        """
        result = self.client.get_multi([
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessPreLoginBannerGroup",
             ["hm2PreLoginBannerAdminStatus",
              "hm2PreLoginBannerText"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessCliGroup",
             ["hm2CliLoginBannerAdminStatus",
              "hm2CliLoginBannerText"]),
        ], decode_strings=False)

        mgmt = result["mibs"].get("HM2-MGMTACCESS-MIB", {})
        pre = (mgmt.get("hm2MgmtAccessPreLoginBannerGroup", [{}])
               [0] if mgmt.get("hm2MgmtAccessPreLoginBannerGroup")
               else {})
        cli = (mgmt.get("hm2MgmtAccessCliGroup", [{}])
               [0] if mgmt.get("hm2MgmtAccessCliGroup")
               else {})

        return {
            'pre_login': {
                'enabled': _safe_int(pre.get(
                    "hm2PreLoginBannerAdminStatus", "2")) == 1,
                'text': _decode_hex_string(
                    pre.get("hm2PreLoginBannerText", "")),
            },
            'cli_login': {
                'enabled': _safe_int(cli.get(
                    "hm2CliLoginBannerAdminStatus", "2")) == 1,
                'text': _decode_hex_string(
                    cli.get("hm2CliLoginBannerText", "")),
            },
        }

    def set_banner(self, pre_login_enabled=None, pre_login_text=None,
                   cli_login_enabled=None, cli_login_text=None):
        """Set pre-login and/or CLI login banner.

        Args:
            pre_login_enabled: bool (NERC CIP-005-1 R2.6 banner)
            pre_login_text: str (max 512 chars, supports \\n \\t)
            cli_login_enabled: bool (replaces system overview on CLI)
            cli_login_text: str (max 1024 chars, supports \\n \\t)
        """
        mutations = []

        pre_values = {}
        if pre_login_enabled is not None:
            pre_values["hm2PreLoginBannerAdminStatus"] = (
                "1" if pre_login_enabled else "2")
        if pre_login_text is not None:
            pre_values["hm2PreLoginBannerText"] = encode_string(
                pre_login_text)
        if pre_values:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessPreLoginBannerGroup", pre_values))

        cli_values = {}
        if cli_login_enabled is not None:
            cli_values["hm2CliLoginBannerAdminStatus"] = (
                "1" if cli_login_enabled else "2")
        if cli_login_text is not None:
            cli_values["hm2CliLoginBannerText"] = encode_string(
                cli_login_text)
        if cli_values:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessCliGroup", cli_values))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # Session Config (HM2-MGMTACCESS-MIB — session timeouts/limits)
    # ------------------------------------------------------------------

    def get_session_config(self):
        """Read session timeout and max-sessions for all management protocols.

        Returns::

            {
                'ssh':          {'timeout': 5, 'max_sessions': 5, 'active_sessions': 1},
                'ssh_outbound': {'timeout': 5, 'max_sessions': 5, 'active_sessions': 0},
                'telnet':       {'timeout': 5, 'max_sessions': 5, 'active_sessions': 0},
                'web':          {'timeout': 5},
                'serial':       {'timeout': 5},
                'netconf':      {'timeout': 60, 'max_sessions': 5, 'active_sessions': 0},
            }

        All timeouts in minutes (0 = disabled).
        NETCONF stored as seconds on device, normalised to minutes here.
        active_sessions is read-only runtime counter.
        """
        result = self.client.get_multi([
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessSshGroup",
             ["hm2SshMaxSessionsCount", "hm2SshSessionTimeout",
              "hm2SshSessionsCount",
              "hm2SshOutboundMaxSessionsCount",
              "hm2SshOutboundSessionTimeout",
              "hm2SshOutboundSessionsCount"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessTelnetGroup",
             ["hm2TelnetServerMaxSessions",
              "hm2TelnetServerSessionsTimeOut",
              "hm2TelnetServerSessionsCount"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessWebGroup",
             ["hm2WebIntfTimeOut"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessCliGroup",
             ["hm2CliLoginTimeoutSerial"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessNetconfGroup",
             ["hm2NetconfMaxSessions", "hm2NetconfSessionTimeout",
              "hm2NetconfSessionsCount"]),
            ("HM2-MGMTACCESS-MIB", "hm2MgmtAccessPhysicalIntfGroup",
             ["hm2MgmtAccessPhysicalIntfSerialAdminStatus",
              "hm2MgmtAccessPhysicalIntfSerialOperStatus",
              "hm2MgmtAccessPhysicalIntfEnvmAdminStatus",
              "hm2MgmtAccessPhysicalIntfEnvmOperStatus"]),
        ], decode_strings=False)

        mgmt = result["mibs"].get("HM2-MGMTACCESS-MIB", {})
        ssh = (mgmt.get("hm2MgmtAccessSshGroup", [{}])[0]
               if mgmt.get("hm2MgmtAccessSshGroup") else {})
        tel = (mgmt.get("hm2MgmtAccessTelnetGroup", [{}])[0]
               if mgmt.get("hm2MgmtAccessTelnetGroup") else {})
        web = (mgmt.get("hm2MgmtAccessWebGroup", [{}])[0]
               if mgmt.get("hm2MgmtAccessWebGroup") else {})
        cli_g = (mgmt.get("hm2MgmtAccessCliGroup", [{}])[0]
                 if mgmt.get("hm2MgmtAccessCliGroup") else {})
        nc = (mgmt.get("hm2MgmtAccessNetconfGroup", [{}])[0]
              if mgmt.get("hm2MgmtAccessNetconfGroup") else {})
        phys = (mgmt.get("hm2MgmtAccessPhysicalIntfGroup", [{}])[0]
                if mgmt.get("hm2MgmtAccessPhysicalIntfGroup") else {})

        # NETCONF timeout is in seconds on device — normalise to minutes
        nc_timeout_sec = _safe_int(
            nc.get("hm2NetconfSessionTimeout", "0"))
        nc_timeout_min = nc_timeout_sec // 60 if nc_timeout_sec else 0

        return {
            'ssh': {
                'timeout': _safe_int(
                    ssh.get("hm2SshSessionTimeout", "0")),
                'max_sessions': _safe_int(
                    ssh.get("hm2SshMaxSessionsCount", "0")),
                'active_sessions': _safe_int(
                    ssh.get("hm2SshSessionsCount", "0")),
            },
            'ssh_outbound': {
                'timeout': _safe_int(
                    ssh.get("hm2SshOutboundSessionTimeout", "0")),
                'max_sessions': _safe_int(
                    ssh.get("hm2SshOutboundMaxSessionsCount", "0")),
                'active_sessions': _safe_int(
                    ssh.get("hm2SshOutboundSessionsCount", "0")),
            },
            'telnet': {
                'timeout': _safe_int(
                    tel.get("hm2TelnetServerSessionsTimeOut", "0")),
                'max_sessions': _safe_int(
                    tel.get("hm2TelnetServerMaxSessions", "0")),
                'active_sessions': _safe_int(
                    tel.get("hm2TelnetServerSessionsCount", "0")),
            },
            'web': {
                'timeout': _safe_int(
                    web.get("hm2WebIntfTimeOut", "0")),
            },
            'serial': {
                'timeout': _safe_int(
                    cli_g.get("hm2CliLoginTimeoutSerial", "0")),
                'enabled': phys.get(
                    "hm2MgmtAccessPhysicalIntfSerialAdminStatus",
                    "1") == "1",
                'oper_status': phys.get(
                    "hm2MgmtAccessPhysicalIntfSerialOperStatus",
                    "1") == "1",
            },
            'envm': {
                'enabled': phys.get(
                    "hm2MgmtAccessPhysicalIntfEnvmAdminStatus",
                    "1") == "1",
                'oper_status': phys.get(
                    "hm2MgmtAccessPhysicalIntfEnvmOperStatus",
                    "1") == "1",
            },
            'netconf': {
                'timeout': nc_timeout_min,
                'max_sessions': _safe_int(
                    nc.get("hm2NetconfMaxSessions", "0")),
                'active_sessions': _safe_int(
                    nc.get("hm2NetconfSessionsCount", "0")),
            },
        }

    def set_session_config(self, ssh_timeout=None, ssh_max_sessions=None,
                           ssh_outbound_timeout=None,
                           ssh_outbound_max_sessions=None,
                           telnet_timeout=None, telnet_max_sessions=None,
                           web_timeout=None, serial_timeout=None,
                           netconf_timeout=None,
                           netconf_max_sessions=None,
                           serial_enabled=None, envm_enabled=None):
        """Set session timeouts and max-sessions.

        All timeouts in minutes (0 = disabled).
        NETCONF timeout converted to seconds before writing.
        """
        mutations = []

        ssh_values = {}
        if ssh_timeout is not None:
            ssh_values["hm2SshSessionTimeout"] = str(ssh_timeout)
        if ssh_max_sessions is not None:
            ssh_values["hm2SshMaxSessionsCount"] = str(ssh_max_sessions)
        if ssh_outbound_timeout is not None:
            ssh_values["hm2SshOutboundSessionTimeout"] = str(
                ssh_outbound_timeout)
        if ssh_outbound_max_sessions is not None:
            ssh_values["hm2SshOutboundMaxSessionsCount"] = str(
                ssh_outbound_max_sessions)
        if ssh_values:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessSshGroup", ssh_values))

        tel_values = {}
        if telnet_timeout is not None:
            tel_values["hm2TelnetServerSessionsTimeOut"] = str(
                telnet_timeout)
        if telnet_max_sessions is not None:
            tel_values["hm2TelnetServerMaxSessions"] = str(
                telnet_max_sessions)
        if tel_values:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessTelnetGroup", tel_values))

        if web_timeout is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessWebGroup",
                {"hm2WebIntfTimeOut": str(web_timeout)}))

        if serial_timeout is not None:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessCliGroup",
                {"hm2CliLoginTimeoutSerial": str(serial_timeout)}))

        nc_values = {}
        if netconf_timeout is not None:
            # Convert minutes to seconds for device
            nc_values["hm2NetconfSessionTimeout"] = str(
                netconf_timeout * 60)
        if netconf_max_sessions is not None:
            nc_values["hm2NetconfMaxSessions"] = str(netconf_max_sessions)
        if nc_values:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessNetconfGroup", nc_values))

        phys_values = {}
        if serial_enabled is not None:
            phys_values["hm2MgmtAccessPhysicalIntfSerialAdminStatus"] = (
                "1" if serial_enabled else "2")
        if envm_enabled is not None:
            phys_values["hm2MgmtAccessPhysicalIntfEnvmAdminStatus"] = (
                "1" if envm_enabled else "2")
        if phys_values:
            mutations.append((
                "HM2-MGMTACCESS-MIB",
                "hm2MgmtAccessPhysicalIntfGroup", phys_values))

        self._apply_mutations(mutations)

    # ------------------------------------------------------------------
    # IP Restrict (HM2-MGMTACCESS-MIB — restricted management access)
    # ------------------------------------------------------------------

    def get_ip_restrict(self):
        """Read restricted management access configuration.

        Returns::

            {
                'enabled': False,
                'logging': False,
                'rules': [
                    {
                        'index': 1,
                        'ip': '192.168.1.0',
                        'prefix_length': 24,
                        'services': {
                            'http': True, 'https': True, 'snmp': True,
                            'telnet': True, 'ssh': True, 'iec61850': True,
                            'modbus': True, 'ethernet_ip': True,
                            'profinet': True,
                        },
                        'interface': '',
                        'per_rule_logging': False,
                        'log_counter': 0,
                    },
                ],
            }
        """
        # Global scalars
        try:
            scalars = self.client.get(
                "HM2-MGMTACCESS-MIB",
                "hm2RestrictedMgmtAccessGroup",
                ["hm2RmaOperation", "hm2RmaLoggingGlobal"],
                decode_strings=False)
        except MOPSError:
            scalars = []
        s = scalars[0] if scalars else {}

        # Rule table
        try:
            entries = self.client.get(
                "HM2-MGMTACCESS-MIB", "hm2RmaEntry",
                ["hm2RmaRowStatus", "hm2RmaIpAddr",
                 "hm2RmaPrefixLength",
                 "hm2RmaSrvHttp", "hm2RmaSrvHttps",
                 "hm2RmaSrvSnmp", "hm2RmaSrvTelnet",
                 "hm2RmaSrvSsh", "hm2RmaSrvIEC61850",
                 "hm2RmaSrvModbusTcp", "hm2RmaSrvEthernetIP",
                 "hm2RmaSrvProfinetIO",
                 "hm2RmaInterface", "hm2RmaLogging"],
                decode_strings=False)
        except MOPSError:
            entries = []

        rules = []
        for i, entry in enumerate(entries):
            status = _safe_int(entry.get("hm2RmaRowStatus", "0"))
            if status not in (1, 3):  # active or notInService
                continue
            ip_hex = entry.get("hm2RmaIpAddr", "")
            ip = self._decode_inet_address(ip_hex)
            iface = _decode_hex_string(
                entry.get("hm2RmaInterface", ""))
            rules.append({
                'index': i + 1,
                'ip': ip,
                'prefix_length': _safe_int(
                    entry.get("hm2RmaPrefixLength", "0")),
                'services': {
                    'http': _safe_int(
                        entry.get("hm2RmaSrvHttp", "1")) == 1,
                    'https': _safe_int(
                        entry.get("hm2RmaSrvHttps", "1")) == 1,
                    'snmp': _safe_int(
                        entry.get("hm2RmaSrvSnmp", "1")) == 1,
                    'telnet': _safe_int(
                        entry.get("hm2RmaSrvTelnet", "1")) == 1,
                    'ssh': _safe_int(
                        entry.get("hm2RmaSrvSsh", "1")) == 1,
                    'iec61850': _safe_int(
                        entry.get("hm2RmaSrvIEC61850", "1")) == 1,
                    'modbus': _safe_int(
                        entry.get("hm2RmaSrvModbusTcp", "1")) == 1,
                    'ethernet_ip': _safe_int(
                        entry.get("hm2RmaSrvEthernetIP", "1")) == 1,
                    'profinet': _safe_int(
                        entry.get("hm2RmaSrvProfinetIO", "1")) == 1,
                },
                'interface': iface if iface else '',
                'per_rule_logging': _safe_int(
                    entry.get("hm2RmaLogging", "2")) == 1,
                'log_counter': 0,
            })

        return {
            'enabled': _safe_int(
                s.get("hm2RmaOperation", "2")) == 1,
            'logging': _safe_int(
                s.get("hm2RmaLoggingGlobal", "2")) == 1,
            'rules': rules,
        }

    @staticmethod
    def _decode_inet_address(hex_str):
        """Decode MOPS hex InetAddress to dotted-quad string."""
        if not hex_str:
            return '0.0.0.0'
        parts = hex_str.strip().split()
        if len(parts) == 4:
            try:
                return '.'.join(str(int(p, 16)) for p in parts)
            except ValueError:
                pass
        return hex_str

    @staticmethod
    def _encode_inet_address(ip_str):
        """Encode dotted-quad IP to MOPS hex InetAddress."""
        try:
            octets = ip_str.split('.')
            return ' '.join(f'{int(o):02x}' for o in octets)
        except (ValueError, AttributeError):
            return '00 00 00 00'

    def set_ip_restrict(self, enabled=None, logging=None):
        """Set global RMA enable/logging.

        Args:
            enabled: bool — global restricted management access
            logging: bool — global RMA logging
        """
        values = {}
        if enabled is not None:
            values["hm2RmaOperation"] = "1" if enabled else "2"
        if logging is not None:
            values["hm2RmaLoggingGlobal"] = "1" if logging else "2"
        if values:
            self._apply_set(
                "HM2-MGMTACCESS-MIB",
                "hm2RestrictedMgmtAccessGroup", values)

    def add_ip_restrict_rule(self, index, ip='0.0.0.0',
                             prefix_length=0,
                             http=True, https=True, snmp=True,
                             telnet=True, ssh=True, iec61850=True,
                             modbus=True, ethernet_ip=True,
                             profinet=True,
                             interface='',
                             per_rule_logging=False):
        """Create RMA rule at index 1-16. RowStatus createAndGo."""
        values = {
            "hm2RmaRowStatus": "4",  # createAndGo
            "hm2RmaIpAddrType": "1",  # ipv4
            "hm2RmaIpAddr": self._encode_inet_address(ip),
            "hm2RmaPrefixLength": str(prefix_length),
            "hm2RmaSrvHttp": "1" if http else "2",
            "hm2RmaSrvHttps": "1" if https else "2",
            "hm2RmaSrvSnmp": "1" if snmp else "2",
            "hm2RmaSrvTelnet": "1" if telnet else "2",
            "hm2RmaSrvSsh": "1" if ssh else "2",
            "hm2RmaSrvIEC61850": "1" if iec61850 else "2",
            "hm2RmaSrvModbusTcp": "1" if modbus else "2",
            "hm2RmaSrvEthernetIP": "1" if ethernet_ip else "2",
            "hm2RmaSrvProfinetIO": "1" if profinet else "2",
            "hm2RmaLogging": "1" if per_rule_logging else "2",
        }
        if interface:
            values["hm2RmaInterface"] = encode_string(interface)
        self.client.set_indexed(
            "HM2-MGMTACCESS-MIB", "hm2RmaEntry",
            index={"hm2RmaIndex": str(index)},
            values=values)

    def delete_ip_restrict_rule(self, index):
        """Delete RMA rule by index. RowStatus destroy."""
        self.client.set_indexed(
            "HM2-MGMTACCESS-MIB", "hm2RmaEntry",
            index={"hm2RmaIndex": str(index)},
            values={"hm2RmaRowStatus": "6"})  # destroy

    # ------------------------------------------------------------------
    # DNS client
    # ------------------------------------------------------------------

    _DNS_CONFIG_SOURCE = {'1': 'user', '2': 'mgmt-dhcp', '3': 'provider'}
    _DNS_CONFIG_SOURCE_REV = {v: k for k, v in _DNS_CONFIG_SOURCE.items()}

    def get_dns(self):
        """Read DNS client configuration.

        Returns::

            {
                'enabled': False,
                'config_source': 'mgmt-dhcp',
                'domain_name': '',
                'timeout': 3,
                'retransmits': 2,
                'cache_enabled': True,
                'servers': ['10.0.0.1', '10.0.0.2'],
                'active_servers': ['10.0.0.1'],
            }
        """
        # Scalars: admin state + config source + global settings
        result = self.client.get_multi([
            ("HM2-DNS-MIB", "hm2DnsClientGroup",
             ["hm2DnsClientAdminState",
              "hm2DnsClientConfigSource"]),
            ("HM2-DNS-MIB", "hm2DnsClientGlobalGroup",
             ["hm2DnsClientDefaultDomainName",
              "hm2DnsClientRequestTimeout",
              "hm2DnsClientRequestRetransmits",
              "hm2DnsClientCacheAdminState"]),
        ], decode_strings=False)

        dns = result["mibs"].get("HM2-DNS-MIB", {})
        client_grp = (dns.get("hm2DnsClientGroup", [{}])[0]
                      if dns.get("hm2DnsClientGroup") else {})
        global_grp = (dns.get("hm2DnsClientGlobalGroup", [{}])[0]
                      if dns.get("hm2DnsClientGlobalGroup") else {})

        # User-configured server table (up to 4)
        try:
            cfg_entries = self.client.get(
                "HM2-DNS-MIB", "hm2DnsClientServerCfgEntry",
                ["hm2DnsClientServerIndex",
                 "hm2DnsClientServerAddressType",
                 "hm2DnsClientServerAddress",
                 "hm2DnsClientServerRowStatus"],
                decode_strings=False)
        except (MOPSError, ConnectionException):
            cfg_entries = []

        # Active server table (RO — may include DHCP-provided)
        try:
            diag_entries = self.client.get(
                "HM2-DNS-MIB", "hm2DnsClientServerDiagEntry",
                ["hm2DnsClientServerDiagIndex",
                 "hm2DnsClientServerDiagAddressType",
                 "hm2DnsClientServerDiagAddress"],
                decode_strings=False)
        except (MOPSError, ConnectionException):
            diag_entries = []

        servers = []
        for entry in cfg_entries:
            addr = _decode_hex_ip(
                entry.get("hm2DnsClientServerAddress", ""))
            rs = entry.get("hm2DnsClientServerRowStatus", "")
            # Only include active rows with real addresses
            if addr and addr != '0.0.0.0' and rs != '6':
                servers.append(addr)

        active_servers = []
        for entry in diag_entries:
            addr = _decode_hex_ip(
                entry.get("hm2DnsClientServerDiagAddress", ""))
            if addr and addr != '0.0.0.0':
                active_servers.append(addr)

        return {
            'enabled': _safe_int(client_grp.get(
                "hm2DnsClientAdminState", "2")) == 1,
            'config_source': self._DNS_CONFIG_SOURCE.get(
                client_grp.get("hm2DnsClientConfigSource", "2"),
                "mgmt-dhcp"),
            'domain_name': _decode_hex_string(
                global_grp.get(
                    "hm2DnsClientDefaultDomainName", "")),
            'timeout': _safe_int(global_grp.get(
                "hm2DnsClientRequestTimeout", "3")),
            'retransmits': _safe_int(global_grp.get(
                "hm2DnsClientRequestRetransmits", "2")),
            'cache_enabled': _safe_int(global_grp.get(
                "hm2DnsClientCacheAdminState", "2")) == 1,
            'servers': servers,
            'active_servers': active_servers,
        }

    def set_dns(self, enabled=None, config_source=None, domain_name=None,
                timeout=None, retransmits=None, cache_enabled=None):
        """Set DNS client global configuration.

        Args:
            enabled: bool — DNS client admin state
            config_source: str — 'user' | 'mgmt-dhcp' | 'provider'
            domain_name: str — default domain for unqualified hostnames
            timeout: int — request timeout in seconds (0-3600)
            retransmits: int — retry count (0-100)
            cache_enabled: bool — DNS client cache
        """
        mutations = []

        client_values = {}
        if enabled is not None:
            client_values["hm2DnsClientAdminState"] = (
                "1" if enabled else "2")
        if config_source is not None:
            rev = self._DNS_CONFIG_SOURCE_REV.get(config_source)
            if rev is None:
                raise ValueError(
                    f"config_source must be one of "
                    f"{list(self._DNS_CONFIG_SOURCE.values())}, "
                    f"got '{config_source}'")
            client_values["hm2DnsClientConfigSource"] = rev
        if client_values:
            mutations.append((
                "HM2-DNS-MIB", "hm2DnsClientGroup", client_values))

        global_values = {}
        if domain_name is not None:
            global_values["hm2DnsClientDefaultDomainName"] = (
                encode_string(domain_name))
        if timeout is not None:
            global_values["hm2DnsClientRequestTimeout"] = str(
                int(timeout))
        if retransmits is not None:
            global_values["hm2DnsClientRequestRetransmits"] = str(
                int(retransmits))
        if cache_enabled is not None:
            global_values["hm2DnsClientCacheAdminState"] = (
                "1" if cache_enabled else "2")
        if global_values:
            mutations.append((
                "HM2-DNS-MIB", "hm2DnsClientGlobalGroup",
                global_values))

        self._apply_mutations(mutations)

    def add_dns_server(self, address):
        """Add a DNS server. Auto-picks next free index (1-4).

        Args:
            address: str — IPv4 address (e.g. '192.168.3.1')
        """
        # Read current servers to find a free index
        try:
            cfg_entries = self.client.get(
                "HM2-DNS-MIB", "hm2DnsClientServerCfgEntry",
                ["hm2DnsClientServerIndex",
                 "hm2DnsClientServerRowStatus"],
                decode_strings=False)
        except (MOPSError, ConnectionException):
            cfg_entries = []

        used = set()
        for entry in cfg_entries:
            rs = entry.get("hm2DnsClientServerRowStatus", "")
            if rs not in ('', '6'):  # 6 = destroy
                idx = _safe_int(
                    entry.get("hm2DnsClientServerIndex", "0"))
                if idx:
                    used.add(idx)

        free_idx = None
        for i in range(1, 5):
            if i not in used:
                free_idx = i
                break
        if free_idx is None:
            raise ValueError(
                "All 4 DNS server slots are in use")

        self.client.set_indexed(
            "HM2-DNS-MIB", "hm2DnsClientServerCfgEntry",
            index={"hm2DnsClientServerIndex": str(free_idx)},
            values={
                "hm2DnsClientServerAddressType": "1",  # ipv4
                "hm2DnsClientServerAddress": _encode_hex_ip(
                    address),
                "hm2DnsClientServerRowStatus": "4",  # createAndGo
            })

    def delete_dns_server(self, address):
        """Delete a DNS server by IP address.

        Args:
            address: str — IPv4 address to remove
        """
        try:
            cfg_entries = self.client.get(
                "HM2-DNS-MIB", "hm2DnsClientServerCfgEntry",
                ["hm2DnsClientServerIndex",
                 "hm2DnsClientServerAddress",
                 "hm2DnsClientServerRowStatus"],
                decode_strings=False)
        except (MOPSError, ConnectionException):
            cfg_entries = []

        target_idx = None
        for entry in cfg_entries:
            addr = _decode_hex_ip(
                entry.get("hm2DnsClientServerAddress", ""))
            rs = entry.get("hm2DnsClientServerRowStatus", "")
            if addr == address and rs not in ('', '6'):
                target_idx = _safe_int(
                    entry.get("hm2DnsClientServerIndex", "0"))
                break

        if target_idx is None:
            raise ValueError(
                f"DNS server '{address}' not found")

        self.client.set_indexed(
            "HM2-DNS-MIB", "hm2DnsClientServerCfgEntry",
            index={"hm2DnsClientServerIndex": str(target_idx)},
            values={"hm2DnsClientServerRowStatus": "6"})  # destroy

    # ------------------------------------------------------------------
    # Remote Authentication
    # ------------------------------------------------------------------

    def get_remote_auth(self):
        """Check whether remote authentication services are configured.

        Returns::

            {
                'radius': {'enabled': True},
                'tacacs': {'enabled': False},
                'ldap': {'enabled': False},
            }

        RADIUS/TACACS+: enabled if any server row has RowStatus active(1).
        LDAP: enabled if global admin state is enable(1).
        """
        # LDAP global admin state (scalar)
        result = self.client.get_multi([
            ("HM2-REMOTE-AUTHENTICATION-MIB", "hm2LdapConfigGroup",
             ["hm2LdapClientAdminState"]),
        ], decode_strings=False)
        ldap_grp = (result["mibs"]
                    .get("HM2-REMOTE-AUTHENTICATION-MIB", {})
                    .get("hm2LdapConfigGroup", [{}])[0])
        ldap_enabled = ldap_grp.get(
            "hm2LdapClientAdminState", "2") == "1"

        # RADIUS auth server table — any active row?
        try:
            radius_entries = self.client.get(
                "HM2-PLATFORM-RADIUS-MIB",
                "hm2AgentRadiusServerConfigEntry",
                ["hm2AgentRadiusServerRowStatus"],
                decode_strings=False)
        except (MOPSError, ConnectionException):
            radius_entries = []

        radius_enabled = any(
            e.get("hm2AgentRadiusServerRowStatus") == "1"
            for e in radius_entries)

        # TACACS+ server table — any active row?
        try:
            tacacs_entries = self.client.get(
                "HM2-PLATFORM-TACACSCLIENT-MIB",
                "hm2AgentTacacsServerEntry",
                ["hm2AgentTacacsServerStatus"],
                decode_strings=False)
        except (MOPSError, ConnectionException):
            tacacs_entries = []

        tacacs_enabled = any(
            e.get("hm2AgentTacacsServerStatus") == "1"
            for e in tacacs_entries)

        return {
            'radius': {'enabled': radius_enabled},
            'tacacs': {'enabled': tacacs_enabled},
            'ldap': {'enabled': ldap_enabled},
        }

    # ------------------------------------------------------------------
    # User Management
    # ------------------------------------------------------------------

    _ROLE_MAP = {
        '0': 'unauthorized', '1': 'guest', '2': 'auditor',
        '5': 'custom1', '6': 'custom2', '7': 'custom3',
        '13': 'operator', '15': 'administrator',
    }
    _ROLE_REV = {v: k for k, v in _ROLE_MAP.items()}

    _AUTH_MAP = {'1': 'md5', '2': 'sha'}
    _ENC_MAP = {'0': 'none', '1': 'des', '2': 'aes128', '3': 'aes256'}
    _AUTH_REV = {v: k for k, v in _AUTH_MAP.items()}
    _ENC_REV = {v: k for k, v in _ENC_MAP.items()}

    def get_users(self):
        """Get local user accounts.

        Returns::

            [
                {
                    'name': 'admin',
                    'role': 'administrator',
                    'locked': False,
                    'policy_check': False,
                    'snmp_auth': 'md5',
                    'snmp_enc': 'des',
                    'active': True,
                    'default_password': True,
                },
            ]
        """
        entries = self.client.get(
            "HM2-USERMGMT-MIB",
            "hm2UserConfigEntry",
            ["hm2UserName", "hm2UserAccessRole", "hm2UserLockoutStatus",
             "hm2UserPwdPolicyChk", "hm2UserSnmpAuthType",
             "hm2UserSnmpEncType", "hm2UserStatus"],
            decode_strings=False)

        # Default password status table
        default_pwd_users = set()
        try:
            pwd_entries = self.client.get(
                "HM2-USERMGMT-MIB",
                "hm2PwdMgmtDefaultPwdStatusEntry",
                ["hm2PwdMgmtDefaultPwdStatusUserName"],
                decode_strings=False)
            for pe in pwd_entries:
                raw = pe.get("hm2PwdMgmtDefaultPwdStatusUserName", "")
                default_pwd_users.add(
                    bytes.fromhex(raw.replace(" ", "")).decode(
                        "ascii", errors="replace"))
        except (MOPSError, ConnectionException):
            pass

        users = []
        for e in entries:
            raw_name = e.get("hm2UserName", "")
            name = bytes.fromhex(raw_name.replace(" ", "")).decode(
                "ascii", errors="replace")
            role_val = e.get("hm2UserAccessRole", "1")
            users.append({
                'name': name,
                'role': self._ROLE_MAP.get(role_val, f'unknown({role_val})'),
                'locked': e.get("hm2UserLockoutStatus", "2") == "1",
                'policy_check': e.get("hm2UserPwdPolicyChk", "2") == "1",
                'snmp_auth': self._AUTH_MAP.get(
                    e.get("hm2UserSnmpAuthType", "1"), 'md5'),
                'snmp_enc': self._ENC_MAP.get(
                    e.get("hm2UserSnmpEncType", "1"), 'des'),
                'active': e.get("hm2UserStatus", "1") == "1",
                'default_password': name in default_pwd_users,
            })
        return users

    def set_user(self, name, password=None, role=None,
                 snmp_auth_type=None, snmp_enc_type=None,
                 snmp_auth_password=None, snmp_enc_password=None,
                 policy_check=None, locked=None):
        """Create or update a local user account.

        Creates the user if it doesn't exist (createAndGo with password).
        Updates fields on an existing user.

        Args:
            name: Username (1-32 chars).
            password: Login password (required for new users).
            role: 'administrator', 'operator', 'guest', 'auditor',
                  'unauthorized', 'custom1', 'custom2', 'custom3'.
            snmp_auth_type: 'md5' or 'sha'.
            snmp_enc_type: 'none', 'des', 'aes128', or 'aes256'.
            snmp_auth_password: SNMPv3 authentication password.
            snmp_enc_password: SNMPv3 encryption password.
            policy_check: bool — per-user password policy enforcement.
            locked: bool — account lockout (set False to unlock).
        """
        # Check if user exists
        existing = self.client.get(
            "HM2-USERMGMT-MIB",
            "hm2UserConfigEntry",
            ["hm2UserName", "hm2UserStatus"],
            decode_strings=False)
        existing_names = set()
        for e in existing:
            raw = e.get("hm2UserName", "")
            existing_names.add(
                bytes.fromhex(raw.replace(" ", "")).decode(
                    "ascii", errors="replace"))

        # Validate enum args early
        if role is not None and role not in self._ROLE_REV:
            raise ValueError(
                f"Invalid role '{role}': use one of "
                f"{list(self._ROLE_REV.keys())}")
        if snmp_auth_type is not None and snmp_auth_type not in self._AUTH_REV:
            raise ValueError(
                f"Invalid snmp_auth_type '{snmp_auth_type}': "
                f"use 'md5' or 'sha'")
        if snmp_enc_type is not None and snmp_enc_type not in self._ENC_REV:
            raise ValueError(
                f"Invalid snmp_enc_type '{snmp_enc_type}': "
                f"use 'none', 'des', 'aes128', or 'aes256'")

        hex_name = encode_string(name)
        idx = {"hm2UserName": hex_name}

        if name not in existing_names:
            # Create new user: three-step RowStatus sequence.
            # createAndGo(4) bundles password with creation but
            # leaves the row in notInService — HiOS requires
            # password to be set as a SEPARATE operation after
            # row creation before it can transition to active(1).
            if password is None:
                raise ValueError(
                    "password is required when creating a new user")
            # Step 1: createAndWait — allocate the row
            self._apply_set_indexed(
                "HM2-USERMGMT-MIB", "hm2UserConfigEntry",
                index=idx,
                values={"hm2UserStatus": "5"})  # createAndWait
            # Step 2: set password (must be separate from creation)
            self._apply_set_indexed(
                "HM2-USERMGMT-MIB", "hm2UserConfigEntry",
                index=idx,
                values={"hm2UserPassword": encode_string(password)})
            # Step 3: set attributes + activate
            update = {"hm2UserStatus": "1"}  # active
            if role is not None:
                update["hm2UserAccessRole"] = self._ROLE_REV[role]
            if snmp_auth_type is not None:
                update["hm2UserSnmpAuthType"] = (
                    self._AUTH_REV[snmp_auth_type])
            if snmp_enc_type is not None:
                update["hm2UserSnmpEncType"] = (
                    self._ENC_REV[snmp_enc_type])
            if snmp_auth_password is not None:
                update["hm2UserSnmpAuthPassword"] = encode_string(
                    snmp_auth_password)
            if snmp_enc_password is not None:
                update["hm2UserSnmpEncPassword"] = encode_string(
                    snmp_enc_password)
            if policy_check is not None:
                update["hm2UserPwdPolicyChk"] = (
                    "1" if policy_check else "2")
            if locked is not None:
                update["hm2UserLockoutStatus"] = (
                    "1" if locked else "2")
            self._apply_set_indexed(
                "HM2-USERMGMT-MIB", "hm2UserConfigEntry",
                index=idx, values=update)
        else:
            # Update existing user
            values = {}
            if password is not None:
                values["hm2UserPassword"] = encode_string(password)
            if role is not None:
                values["hm2UserAccessRole"] = self._ROLE_REV[role]
            if snmp_auth_type is not None:
                values["hm2UserSnmpAuthType"] = (
                    self._AUTH_REV[snmp_auth_type])
            if snmp_enc_type is not None:
                values["hm2UserSnmpEncType"] = (
                    self._ENC_REV[snmp_enc_type])
            if snmp_auth_password is not None:
                values["hm2UserSnmpAuthPassword"] = encode_string(
                    snmp_auth_password)
            if snmp_enc_password is not None:
                values["hm2UserSnmpEncPassword"] = encode_string(
                    snmp_enc_password)
            if policy_check is not None:
                values["hm2UserPwdPolicyChk"] = (
                    "1" if policy_check else "2")
            if locked is not None:
                values["hm2UserLockoutStatus"] = (
                    "1" if locked else "2")
            if values:
                self._apply_set_indexed(
                    "HM2-USERMGMT-MIB", "hm2UserConfigEntry",
                    index=idx, values=values)

    def delete_user(self, name):
        """Delete a local user account.

        Args:
            name: Username to delete.
        """
        hex_name = encode_string(name)
        self._apply_set_indexed(
            "HM2-USERMGMT-MIB", "hm2UserConfigEntry",
            index={"hm2UserName": hex_name},
            values={"hm2UserStatus": "6"})  # destroy

    # ------------------------------------------------------------------
    # Port Security
    # ------------------------------------------------------------------

    _PORTSEC_MODE = {'1': 'mac-based', '2': 'ip-based'}
    _PORTSEC_MODE_REV = {'mac-based': '1', 'ip-based': '2'}

    def _parse_portsec_macs(self, raw):
        """Parse 'VLAN MAC,VLAN MAC,...' DisplayString into list of dicts."""
        if not raw or not raw.strip():
            return []
        result = []
        for pair in raw.split(','):
            pair = pair.strip()
            if not pair:
                continue
            parts = pair.split()
            if len(parts) >= 2:
                result.append({'vlan': int(parts[0]), 'mac': parts[1]})
        return result

    def _parse_portsec_ips(self, raw):
        """Parse 'VLAN IP,VLAN IP,...' DisplayString into list of dicts."""
        if not raw or not raw.strip():
            return []
        result = []
        for pair in raw.split(','):
            pair = pair.strip()
            if not pair:
                continue
            parts = pair.split()
            if len(parts) >= 2:
                result.append({'vlan': int(parts[0]), 'ip': parts[1]})
        return result

    def get_port_security(self, interface=None):
        """Return port security configuration and status.

        Args:
            interface: port name (str), list of port names, or None for all

        Returns:
            dict with:
                'enabled': bool (global admin state)
                'mode': str ('mac-based' or 'ip-based')
                'ports': {port_name: {
                    'enabled': bool,
                    'dynamic_limit': int (0-600),
                    'static_limit': int (0-64),
                    'auto_disable': bool,
                    'violation_trap_mode': bool,
                    'violation_trap_frequency': int (0-3600),
                    'dynamic_count': int,
                    'static_count': int,
                    'static_ip_count': int,
                    'last_discarded_mac': str,
                    'static_macs': [{'vlan': int, 'mac': str}],
                    'static_ips': [{'vlan': int, 'ip': str}],
                }}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-PLATFORM-PORTSECURITY-MIB",
             "hm2AgentPortSecurityGroup", [
                 "hm2AgentGlobalPortSecurityMode",
                 "hm2AgentPortSecurityOperationMode",
             ]),
            ("HM2-PLATFORM-PORTSECURITY-MIB",
             "hm2AgentPortSecurityEntry", [
                 "ifIndex",
                 "hm2AgentPortSecurityMode",
                 "hm2AgentPortSecurityDynamicLimit",
                 "hm2AgentPortSecurityStaticLimit",
                 "hm2AgentPortSecurityAutoDisable",
                 "hm2AgentPortSecurityViolationTrapMode",
                 "hm2AgentPortSecurityViolationTrapFrequency",
                 "hm2AgentPortSecurityDynamicCount",
                 "hm2AgentPortSecurityStaticCount",
                 "hm2AgentPortSecurityStaticIpCount",
                 "hm2AgentPortSecurityLastDiscardedMAC",
                 "hm2AgentPortSecurityStaticMACs",
                 "hm2AgentPortSecurityStaticIPs",
             ]),
            decode_strings=False,
        )

        psmib = mibs.get("HM2-PLATFORM-PORTSECURITY-MIB", {})
        glb = psmib.get("hm2AgentPortSecurityGroup", [{}])[0]

        # Filter interfaces if requested
        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for entry in psmib.get("hm2AgentPortSecurityEntry", []):
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue
            if want is not None and name not in want:
                continue

            ports[name] = {
                'enabled': entry.get(
                    "hm2AgentPortSecurityMode", "2") == "1",
                'dynamic_limit': _safe_int(entry.get(
                    "hm2AgentPortSecurityDynamicLimit", "600")),
                'static_limit': _safe_int(entry.get(
                    "hm2AgentPortSecurityStaticLimit", "64")),
                'auto_disable': entry.get(
                    "hm2AgentPortSecurityAutoDisable", "1") == "1",
                'violation_trap_mode': entry.get(
                    "hm2AgentPortSecurityViolationTrapMode", "2") == "1",
                'violation_trap_frequency': _safe_int(entry.get(
                    "hm2AgentPortSecurityViolationTrapFrequency", "0")),
                'dynamic_count': _safe_int(entry.get(
                    "hm2AgentPortSecurityDynamicCount", "0")),
                'static_count': _safe_int(entry.get(
                    "hm2AgentPortSecurityStaticCount", "0")),
                'static_ip_count': _safe_int(entry.get(
                    "hm2AgentPortSecurityStaticIpCount", "0")),
                'last_discarded_mac': _decode_hex_string(entry.get(
                    "hm2AgentPortSecurityLastDiscardedMAC", "")),
                'static_macs': self._parse_portsec_macs(
                    _decode_hex_string(entry.get(
                        "hm2AgentPortSecurityStaticMACs", ""))),
                'static_ips': self._parse_portsec_ips(
                    _decode_hex_string(entry.get(
                        "hm2AgentPortSecurityStaticIPs", ""))),
            }

        return {
            'enabled': glb.get(
                "hm2AgentGlobalPortSecurityMode", "2") == "1",
            'mode': self._PORTSEC_MODE.get(
                glb.get("hm2AgentPortSecurityOperationMode", "1"),
                'mac-based'),
            'ports': ports,
        }

    def set_port_security(self, interface=None, enabled=None, mode=None,
                          dynamic_limit=None, static_limit=None,
                          auto_disable=None, violation_trap_mode=None,
                          violation_trap_frequency=None, move_macs=None):
        """Set port security configuration.

        If interface is provided, sets per-port values.
        If interface is None, sets global values (enabled, mode).

        Args:
            interface: port name (str), list of port names, or None for global
            enabled: True/False
            mode: 'mac-based' or 'ip-based' (global only)
            dynamic_limit: int 0-600 (per-port only)
            static_limit: int 0-64 (per-port only)
            auto_disable: True/False (per-port only)
            violation_trap_mode: True/False (per-port only)
            violation_trap_frequency: int 0-3600 seconds (per-port only)
            move_macs: True to promote dynamic MACs to static (per-port only)
        """
        if interface is not None:
            interfaces = ([interface] if isinstance(interface, str)
                          else list(interface))
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: idx for idx, n in ifindex_map.items()}

            values = {}
            if enabled is not None:
                values["hm2AgentPortSecurityMode"] = (
                    "1" if enabled else "2")
            if dynamic_limit is not None:
                values["hm2AgentPortSecurityDynamicLimit"] = str(
                    int(dynamic_limit))
            if static_limit is not None:
                values["hm2AgentPortSecurityStaticLimit"] = str(
                    int(static_limit))
            if auto_disable is not None:
                values["hm2AgentPortSecurityAutoDisable"] = (
                    "1" if auto_disable else "2")
            if violation_trap_mode is not None:
                values["hm2AgentPortSecurityViolationTrapMode"] = (
                    "1" if violation_trap_mode else "2")
            if violation_trap_frequency is not None:
                values["hm2AgentPortSecurityViolationTrapFrequency"] = str(
                    int(violation_trap_frequency))
            if move_macs:
                values["hm2AgentPortSecurityMACAddressMove"] = "1"

            if not values:
                return

            mutations = []
            for iface in interfaces:
                ifidx = name_to_idx.get(iface)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{iface}'")
                mutations.append((
                    "HM2-PLATFORM-PORTSECURITY-MIB",
                    "hm2AgentPortSecurityEntry",
                    dict(values), {"ifIndex": ifidx}))

            self._apply_mutations(mutations)
        else:
            values = {}
            if enabled is not None:
                values["hm2AgentGlobalPortSecurityMode"] = (
                    "1" if enabled else "2")
            if mode is not None:
                val = self._PORTSEC_MODE_REV.get(mode)
                if val is None:
                    raise ValueError(
                        f"Invalid mode '{mode}': "
                        f"use 'mac-based' or 'ip-based'")
                values["hm2AgentPortSecurityOperationMode"] = val
            if values:
                self._apply_set("HM2-PLATFORM-PORTSECURITY-MIB",
                                "hm2AgentPortSecurityGroup", values)

    def add_port_security(self, interface, vlan, mac=None, ip=None,
                          entries=None):
        """Add static MAC or IP entries to port security.

        Single entry:
            add_port_security('1/1', vlan=1, mac='aa:bb:cc:dd:ee:ff')
            add_port_security('1/1', vlan=2, ip='192.168.1.100')

        Bulk (atomic on MOPS):
            add_port_security('1/1', entries=[
                {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'},
                {'vlan': 2, 'ip': '192.168.1.100'},
            ])

        Args:
            interface: port name (str)
            vlan: VLAN ID (int) — ignored if entries provided
            mac: MAC address string (mutually exclusive with ip)
            ip: IP address string (mutually exclusive with mac)
            entries: list of {'vlan': int, 'mac': str} or {'vlan': int, 'ip': str}
        """
        if entries is None:
            if mac is not None:
                entries = [{'vlan': vlan, 'mac': mac}]
            elif ip is not None:
                entries = [{'vlan': vlan, 'ip': ip}]
            else:
                raise ValueError("Provide mac=, ip=, or entries=")

        ifindex_map = self._build_ifindex_map()
        name_to_idx = {n: idx for idx, n in ifindex_map.items()}
        ifidx = name_to_idx.get(interface)
        if ifidx is None:
            raise ValueError(f"Unknown interface '{interface}'")

        # Action OIDs take "VLAN ADDR" DisplayString — each write is
        # an action, so same-OID writes in one POST may only keep last.
        # Send one mutation per entry to be safe.
        for entry in entries:
            v = entry.get('vlan', vlan)
            if 'mac' in entry:
                self._apply_set_indexed(
                    "HM2-PLATFORM-PORTSECURITY-MIB",
                    "hm2AgentPortSecurityEntry",
                    index={"ifIndex": ifidx},
                    values={"hm2AgentPortSecurityMACAddressAdd":
                            encode_string(f"{v} {entry['mac']}")})
            elif 'ip' in entry:
                self._apply_set_indexed(
                    "HM2-PLATFORM-PORTSECURITY-MIB",
                    "hm2AgentPortSecurityEntry",
                    index={"ifIndex": ifidx},
                    values={"hm2AgentPortSecurityIPAddressAdd":
                            encode_string(f"{v} {entry['ip']}")})

    def delete_port_security(self, interface, vlan=None, mac=None, ip=None,
                             entries=None):
        """Remove static MAC or IP entries from port security.

        Single entry:
            delete_port_security('1/1', vlan=1, mac='aa:bb:cc:dd:ee:ff')
            delete_port_security('1/1', vlan=2, ip='192.168.1.100')

        Bulk:
            delete_port_security('1/1', entries=[
                {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'},
                {'vlan': 2, 'ip': '192.168.1.100'},
            ])

        Args:
            interface: port name (str)
            vlan: VLAN ID (int) — ignored if entries provided
            mac: MAC address string (mutually exclusive with ip)
            ip: IP address string (mutually exclusive with mac)
            entries: list of {'vlan': int, 'mac': str} or {'vlan': int, 'ip': str}
        """
        if entries is None:
            if mac is not None:
                entries = [{'vlan': vlan, 'mac': mac}]
            elif ip is not None:
                entries = [{'vlan': vlan, 'ip': ip}]
            else:
                raise ValueError("Provide mac=, ip=, or entries=")

        ifindex_map = self._build_ifindex_map()
        name_to_idx = {n: idx for idx, n in ifindex_map.items()}
        ifidx = name_to_idx.get(interface)
        if ifidx is None:
            raise ValueError(f"Unknown interface '{interface}'")

        for entry in entries:
            v = entry.get('vlan', vlan)
            if 'mac' in entry:
                self._apply_set_indexed(
                    "HM2-PLATFORM-PORTSECURITY-MIB",
                    "hm2AgentPortSecurityEntry",
                    index={"ifIndex": ifidx},
                    values={"hm2AgentPortSecurityMACAddressRemove":
                            encode_string(f"{v} {entry['mac']}")})
            elif 'ip' in entry:
                self._apply_set_indexed(
                    "HM2-PLATFORM-PORTSECURITY-MIB",
                    "hm2AgentPortSecurityEntry",
                    index={"ifIndex": ifidx},
                    values={"hm2AgentPortSecurityIPAddressRemove":
                            encode_string(f"{v} {entry['ip']}")})

    # ------------------------------------------------------------------
    # DHCP Snooping
    # ------------------------------------------------------------------

    def get_dhcp_snooping(self, interface=None):
        """Return DHCP snooping configuration and status.

        Args:
            interface: port name (str), list of port names, or None for all

        Returns:
            dict with:
                'enabled': bool (global admin state)
                'verify_mac': bool (source MAC verification)
                'vlans': {vlan_id: {'enabled': bool}}
                'ports': {port_name: {
                    'trusted': bool,
                    'log': bool,
                    'rate_limit': int (-1 = unlimited),
                    'burst_interval': int (seconds),
                    'auto_disable': bool,
                }}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-PLATFORM-SWITCHING-MIB",
             "hm2AgentDhcpSnoopingConfigGroup", [
                 "hm2AgentDhcpSnoopingAdminMode",
                 "hm2AgentDhcpSnoopingVerifyMac",
             ]),
            ("HM2-PLATFORM-SWITCHING-MIB",
             "hm2AgentDhcpSnoopingIfConfigEntry", [
                 "ifIndex",
                 "hm2AgentDhcpSnoopingIfTrustEnable",
                 "hm2AgentDhcpSnoopingIfLogEnable",
                 "hm2AgentDhcpSnoopingIfRateLimit",
                 "hm2AgentDhcpSnoopingIfBurstInterval",
                 "hm2AgentDhcpSnoopingIfAutoDisable",
             ]),
            decode_strings=False,
        )

        # VLAN table (separate — not ifIndex-indexed)
        vlan_data = self.client.get(
            "HM2-PLATFORM-SWITCHING-MIB",
            "hm2AgentDhcpSnoopingVlanConfigEntry",
            ["hm2AgentDhcpSnoopingVlanIndex",
             "hm2AgentDhcpSnoopingVlanEnable"],
            decode_strings=False)

        swmib = mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
        glb = swmib.get("hm2AgentDhcpSnoopingConfigGroup", [{}])[0]

        # Build VLANs dict
        vlans = {}
        for entry in (vlan_data or []):
            vid = _safe_int(entry.get("hm2AgentDhcpSnoopingVlanIndex", "0"))
            if vid > 0:
                vlans[vid] = {
                    'enabled': entry.get(
                        "hm2AgentDhcpSnoopingVlanEnable", "2") == "1",
                }

        # Filter interfaces
        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for entry in swmib.get("hm2AgentDhcpSnoopingIfConfigEntry", []):
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue
            if want is not None and name not in want:
                continue

            ports[name] = {
                'trusted': entry.get(
                    "hm2AgentDhcpSnoopingIfTrustEnable", "2") == "1",
                'log': entry.get(
                    "hm2AgentDhcpSnoopingIfLogEnable", "2") == "1",
                'rate_limit': _safe_int(entry.get(
                    "hm2AgentDhcpSnoopingIfRateLimit", "-1")),
                'burst_interval': _safe_int(entry.get(
                    "hm2AgentDhcpSnoopingIfBurstInterval", "1")),
                'auto_disable': entry.get(
                    "hm2AgentDhcpSnoopingIfAutoDisable", "1") == "1",
            }

        return {
            'enabled': glb.get(
                "hm2AgentDhcpSnoopingAdminMode", "2") == "1",
            'verify_mac': glb.get(
                "hm2AgentDhcpSnoopingVerifyMac", "2") == "1",
            'vlans': vlans,
            'ports': ports,
        }

    def set_dhcp_snooping(self, interface=None, enabled=None,
                          verify_mac=None, vlan=None, vlan_enabled=None,
                          trusted=None, log=None, rate_limit=None,
                          burst_interval=None, auto_disable=None,
                          **kwargs):
        """Set DHCP snooping configuration.

        Global:
            set_dhcp_snooping(enabled=True)
            set_dhcp_snooping(verify_mac=True)

        Per-VLAN:
            set_dhcp_snooping(vlan=1, vlan_enabled=True)

        Per-port:
            set_dhcp_snooping('1/1', trusted=True)
            set_dhcp_snooping(['1/1', '1/2'], trusted=True, rate_limit=15)
        """
        # Global settings
        if enabled is not None or verify_mac is not None:
            attrs = {}
            if enabled is not None:
                attrs["hm2AgentDhcpSnoopingAdminMode"] = (
                    "1" if enabled else "2")
            if verify_mac is not None:
                attrs["hm2AgentDhcpSnoopingVerifyMac"] = (
                    "1" if verify_mac else "2")
            self._apply_set(
                "HM2-PLATFORM-SWITCHING-MIB",
                "hm2AgentDhcpSnoopingConfigGroup",
                attrs)

        # Per-VLAN
        if vlan is not None and vlan_enabled is not None:
            vlans = [vlan] if isinstance(vlan, int) else list(vlan)
            for vid in vlans:
                self._apply_set_indexed(
                    "HM2-PLATFORM-SWITCHING-MIB",
                    "hm2AgentDhcpSnoopingVlanConfigEntry",
                    index={"hm2AgentDhcpSnoopingVlanIndex": str(vid)},
                    values={"hm2AgentDhcpSnoopingVlanEnable":
                            "1" if vlan_enabled else "2"})

        # Per-port
        if interface is not None:
            interfaces = ([interface] if isinstance(interface, str)
                          else list(interface))
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: idx for idx, n in ifindex_map.items()}

            for iface in interfaces:
                ifidx = name_to_idx.get(iface)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{iface}'")
                vals = {}
                if trusted is not None:
                    vals["hm2AgentDhcpSnoopingIfTrustEnable"] = (
                        "1" if trusted else "2")
                if log is not None:
                    vals["hm2AgentDhcpSnoopingIfLogEnable"] = (
                        "1" if log else "2")
                if rate_limit is not None:
                    vals["hm2AgentDhcpSnoopingIfRateLimit"] = (
                        str(int(rate_limit)))
                if burst_interval is not None:
                    vals["hm2AgentDhcpSnoopingIfBurstInterval"] = (
                        str(int(burst_interval)))
                if auto_disable is not None:
                    vals["hm2AgentDhcpSnoopingIfAutoDisable"] = (
                        "1" if auto_disable else "2")
                if vals:
                    self._apply_set_indexed(
                        "HM2-PLATFORM-SWITCHING-MIB",
                        "hm2AgentDhcpSnoopingIfConfigEntry",
                        index={"ifIndex": ifidx},
                        values=vals)

    # ------------------------------------------------------------------
    # ARP Inspection (DAI)
    # ------------------------------------------------------------------

    def get_arp_inspection(self, interface=None):
        """Return Dynamic ARP Inspection configuration.

        Args:
            interface: port name (str), list of port names, or None for all

        Returns:
            dict with:
                'validate_src_mac': bool
                'validate_dst_mac': bool
                'validate_ip': bool
                'vlans': {vlan_id: {
                    'enabled': bool,
                    'log': bool,
                    'acl_name': str,
                    'acl_static': bool,
                    'binding_check': bool,
                }}
                'ports': {port_name: {
                    'trusted': bool,
                    'rate_limit': int (-1 = unlimited),
                    'burst_interval': int (seconds),
                    'auto_disable': bool,
                }}
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-PLATFORM-SWITCHING-MIB",
             "hm2AgentDaiConfigGroup", [
                 "hm2AgentDaiSrcMacValidate",
                 "hm2AgentDaiDstMacValidate",
                 "hm2AgentDaiIPValidate",
             ]),
            ("HM2-PLATFORM-SWITCHING-MIB",
             "hm2AgentDaiIfConfigEntry", [
                 "ifIndex",
                 "hm2AgentDaiIfTrustEnable",
                 "hm2AgentDaiIfRateLimit",
                 "hm2AgentDaiIfBurstInterval",
                 "hm2AgentDaiIfAutoDisable",
             ]),
            decode_strings=False,
        )

        # VLAN table (separate — not ifIndex-indexed)
        vlan_data = self.client.get(
            "HM2-PLATFORM-SWITCHING-MIB",
            "hm2AgentDaiVlanConfigEntry",
            ["hm2AgentDaiVlanIndex",
             "hm2AgentDaiVlanDynArpInspEnable",
             "hm2AgentDaiVlanLoggingEnable",
             "hm2AgentDaiVlanArpAclName",
             "hm2AgentDaiVlanArpAclStaticFlag",
             "hm2AgentDaiVlanBindingCheckEnable"],
            decode_strings=False)

        swmib = mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})
        glb = swmib.get("hm2AgentDaiConfigGroup", [{}])[0]

        # Build VLANs dict
        vlans = {}
        for entry in (vlan_data or []):
            vid = _safe_int(entry.get("hm2AgentDaiVlanIndex", "0"))
            if vid > 0:
                acl_name = entry.get("hm2AgentDaiVlanArpAclName", "")
                if isinstance(acl_name, str):
                    acl_name = bytes.fromhex(
                        acl_name.replace(' ', '')).decode(
                        'ascii', errors='replace').strip(
                        '\x00') if acl_name.strip() else ''
                vlans[vid] = {
                    'enabled': entry.get(
                        "hm2AgentDaiVlanDynArpInspEnable", "2") == "1",
                    'log': entry.get(
                        "hm2AgentDaiVlanLoggingEnable", "2") == "1",
                    'acl_name': acl_name,
                    'acl_static': entry.get(
                        "hm2AgentDaiVlanArpAclStaticFlag", "2") == "1",
                    'binding_check': entry.get(
                        "hm2AgentDaiVlanBindingCheckEnable", "2") == "1",
                }

        # Filter interfaces
        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for entry in swmib.get("hm2AgentDaiIfConfigEntry", []):
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue
            if want is not None and name not in want:
                continue

            ports[name] = {
                'trusted': entry.get(
                    "hm2AgentDaiIfTrustEnable", "2") == "1",
                'rate_limit': _safe_int(entry.get(
                    "hm2AgentDaiIfRateLimit", "-1")),
                'burst_interval': _safe_int(entry.get(
                    "hm2AgentDaiIfBurstInterval", "1")),
                'auto_disable': entry.get(
                    "hm2AgentDaiIfAutoDisable", "1") == "1",
            }

        return {
            'validate_src_mac': glb.get(
                "hm2AgentDaiSrcMacValidate", "2") == "1",
            'validate_dst_mac': glb.get(
                "hm2AgentDaiDstMacValidate", "2") == "1",
            'validate_ip': glb.get(
                "hm2AgentDaiIPValidate", "2") == "1",
            'vlans': vlans,
            'ports': ports,
        }

    def set_arp_inspection(self, interface=None,
                           validate_src_mac=None, validate_dst_mac=None,
                           validate_ip=None,
                           vlan=None, vlan_enabled=None, vlan_log=None,
                           vlan_acl_name=None, vlan_acl_static=None,
                           vlan_binding_check=None,
                           trusted=None, rate_limit=None,
                           burst_interval=None, auto_disable=None,
                           **kwargs):
        """Set Dynamic ARP Inspection configuration.

        Global:
            set_arp_inspection(validate_src_mac=True)
            set_arp_inspection(validate_ip=True)

        Per-VLAN:
            set_arp_inspection(vlan=1, vlan_enabled=True)
            set_arp_inspection(vlan=1, vlan_log=True, vlan_binding_check=True)

        Per-port:
            set_arp_inspection('1/1', trusted=True)
            set_arp_inspection(['1/1', '1/2'], trusted=True, rate_limit=15)
        """
        # Global settings
        if any(v is not None for v in (validate_src_mac, validate_dst_mac,
                                        validate_ip)):
            attrs = {}
            if validate_src_mac is not None:
                attrs["hm2AgentDaiSrcMacValidate"] = (
                    "1" if validate_src_mac else "2")
            if validate_dst_mac is not None:
                attrs["hm2AgentDaiDstMacValidate"] = (
                    "1" if validate_dst_mac else "2")
            if validate_ip is not None:
                attrs["hm2AgentDaiIPValidate"] = (
                    "1" if validate_ip else "2")
            self._apply_set(
                "HM2-PLATFORM-SWITCHING-MIB",
                "hm2AgentDaiConfigGroup",
                attrs)

        # Per-VLAN
        if vlan is not None:
            vlans = [vlan] if isinstance(vlan, int) else list(vlan)
            for vid in vlans:
                vals = {}
                if vlan_enabled is not None:
                    vals["hm2AgentDaiVlanDynArpInspEnable"] = (
                        "1" if vlan_enabled else "2")
                if vlan_log is not None:
                    vals["hm2AgentDaiVlanLoggingEnable"] = (
                        "1" if vlan_log else "2")
                if vlan_acl_name is not None:
                    vals["hm2AgentDaiVlanArpAclName"] = vlan_acl_name
                if vlan_acl_static is not None:
                    vals["hm2AgentDaiVlanArpAclStaticFlag"] = (
                        "1" if vlan_acl_static else "2")
                if vlan_binding_check is not None:
                    vals["hm2AgentDaiVlanBindingCheckEnable"] = (
                        "1" if vlan_binding_check else "2")
                if vals:
                    self._apply_set_indexed(
                        "HM2-PLATFORM-SWITCHING-MIB",
                        "hm2AgentDaiVlanConfigEntry",
                        index={"hm2AgentDaiVlanIndex": str(vid)},
                        values=vals)

        # Per-port
        if interface is not None:
            interfaces = ([interface] if isinstance(interface, str)
                          else list(interface))
            ifindex_map = self._build_ifindex_map()
            name_to_idx = {n: idx for idx, n in ifindex_map.items()}

            for iface in interfaces:
                ifidx = name_to_idx.get(iface)
                if ifidx is None:
                    raise ValueError(f"Unknown interface '{iface}'")
                vals = {}
                if trusted is not None:
                    vals["hm2AgentDaiIfTrustEnable"] = (
                        "1" if trusted else "2")
                if rate_limit is not None:
                    vals["hm2AgentDaiIfRateLimit"] = (
                        str(int(rate_limit)))
                if burst_interval is not None:
                    vals["hm2AgentDaiIfBurstInterval"] = (
                        str(int(burst_interval)))
                if auto_disable is not None:
                    vals["hm2AgentDaiIfAutoDisable"] = (
                        "1" if auto_disable else "2")
                if vals:
                    self._apply_set_indexed(
                        "HM2-PLATFORM-SWITCHING-MIB",
                        "hm2AgentDaiIfConfigEntry",
                        index={"ifIndex": ifidx},
                        values=vals)

    def get_ip_source_guard(self, interface=None):
        """Return IP Source Guard configuration and bindings.

        Args:
            interface: port name (str), list of port names, or None for all

        Returns:
            dict with:
                'ports': {port_name: {
                    'verify_source': bool (IP filtering),
                    'port_security': bool (MAC filtering),
                }}
                'static_bindings': [{
                    'interface': str,
                    'vlan_id': int,
                    'mac_address': str,
                    'ip_address': str,
                    'active': bool,
                    'hw_status': bool,
                }]
                'dynamic_bindings': [{
                    'interface': str,
                    'vlan_id': int,
                    'mac_address': str,
                    'ip_address': str,
                    'hw_status': bool,
                }]
        """
        mibs, ifindex_map = self._get_with_ifindex(
            ("HM2-PLATFORM-SWITCHING-MIB",
             "hm2AgentIpsgIfConfigEntry", [
                 "ifIndex",
                 "hm2AgentIpsgIfVerifySource",
                 "hm2AgentIpsgIfPortSecurity",
             ]),
            decode_strings=False,
        )

        # Binding tables (composite index, not ifIndex-indexed)
        static_data = self.client.get(
            "HM2-PLATFORM-SWITCHING-MIB",
            "hm2AgentStaticIpsgBindingEntry",
            ["hm2AgentStaticIpsgBindingIfIndex",
             "hm2AgentStaticIpsgBindingVlanId",
             "hm2AgentStaticIpsgBindingMacAddr",
             "hm2AgentStaticIpsgBindingIpAddr",
             "hm2AgentStaticIpsgBindingRowStatus",
             "hm2AgentStaticIpsgBindingHwStatus"],
            decode_strings=False)

        dynamic_data = self.client.get(
            "HM2-PLATFORM-SWITCHING-MIB",
            "hm2AgentDynamicIpsgBindingEntry",
            ["hm2AgentDynamicIpsgBindingIfIndex",
             "hm2AgentDynamicIpsgBindingVlanId",
             "hm2AgentDynamicIpsgBindingMacAddr",
             "hm2AgentDynamicIpsgBindingIpAddr",
             "hm2AgentDynamicIpsgBindingHwStatus"],
            decode_strings=False)

        swmib = mibs.get("HM2-PLATFORM-SWITCHING-MIB", {})

        # Filter interfaces
        want = None
        if interface is not None:
            want = ({interface} if isinstance(interface, str)
                    else set(interface))

        ports = {}
        for entry in swmib.get("hm2AgentIpsgIfConfigEntry", []):
            idx = entry.get("ifIndex", "")
            name = ifindex_map.get(idx, "")
            if not name or name.startswith("cpu") or name.startswith("vlan"):
                continue
            if want is not None and name not in want:
                continue

            ports[name] = {
                'verify_source': entry.get(
                    "hm2AgentIpsgIfVerifySource", "2") == "1",
                'port_security': entry.get(
                    "hm2AgentIpsgIfPortSecurity", "2") == "1",
            }

        # Build reverse ifindex map for binding tables
        idx_to_name = ifindex_map

        # Static bindings
        static_bindings = []
        for entry in (static_data or []):
            ifidx = entry.get("hm2AgentStaticIpsgBindingIfIndex", "")
            iface = idx_to_name.get(str(ifidx), str(ifidx))
            if want is not None and iface not in want:
                continue
            mac_raw = entry.get("hm2AgentStaticIpsgBindingMacAddr", "")
            if isinstance(mac_raw, str) and ' ' in mac_raw:
                mac_raw = mac_raw.replace(' ', '')
            mac = _decode_hex_mac(mac_raw) if mac_raw else ''
            row_status = _safe_int(entry.get(
                "hm2AgentStaticIpsgBindingRowStatus", "0"))
            static_bindings.append({
                'interface': iface,
                'vlan_id': _safe_int(entry.get(
                    "hm2AgentStaticIpsgBindingVlanId", "0")),
                'mac_address': mac,
                'ip_address': entry.get(
                    "hm2AgentStaticIpsgBindingIpAddr", ""),
                'active': row_status == 1,
                'hw_status': entry.get(
                    "hm2AgentStaticIpsgBindingHwStatus", "2") == "1",
            })

        # Dynamic bindings
        dynamic_bindings = []
        for entry in (dynamic_data or []):
            ifidx = entry.get("hm2AgentDynamicIpsgBindingIfIndex", "")
            iface = idx_to_name.get(str(ifidx), str(ifidx))
            if want is not None and iface not in want:
                continue
            mac_raw = entry.get("hm2AgentDynamicIpsgBindingMacAddr", "")
            if isinstance(mac_raw, str) and ' ' in mac_raw:
                mac_raw = mac_raw.replace(' ', '')
            mac = _decode_hex_mac(mac_raw) if mac_raw else ''
            dynamic_bindings.append({
                'interface': iface,
                'vlan_id': _safe_int(entry.get(
                    "hm2AgentDynamicIpsgBindingVlanId", "0")),
                'mac_address': mac,
                'ip_address': entry.get(
                    "hm2AgentDynamicIpsgBindingIpAddr", ""),
                'hw_status': entry.get(
                    "hm2AgentDynamicIpsgBindingHwStatus", "2") == "1",
            })

        return {
            'ports': ports,
            'static_bindings': static_bindings,
            'dynamic_bindings': dynamic_bindings,
        }

    def set_ip_source_guard(self, interface=None,
                            verify_source=None, port_security=None,
                            **kwargs):
        """Set IP Source Guard configuration per port.

        Per-port:
            set_ip_source_guard('1/1', verify_source=True)
            set_ip_source_guard(['1/1', '1/2'], verify_source=True,
                                port_security=True)
        """
        if interface is None:
            return

        interfaces = ([interface] if isinstance(interface, str)
                      else list(interface))
        ifindex_map = self._build_ifindex_map()
        name_to_idx = {n: idx for idx, n in ifindex_map.items()}

        for iface in interfaces:
            ifidx = name_to_idx.get(iface)
            if ifidx is None:
                raise ValueError(f"Unknown interface '{iface}'")
            vals = {}
            if verify_source is not None:
                vals["hm2AgentIpsgIfVerifySource"] = (
                    "1" if verify_source else "2")
            if port_security is not None:
                vals["hm2AgentIpsgIfPortSecurity"] = (
                    "1" if port_security else "2")
            if vals:
                self._apply_set_indexed(
                    "HM2-PLATFORM-SWITCHING-MIB",
                    "hm2AgentIpsgIfConfigEntry",
                    index={"ifIndex": ifidx},
                    values=vals)
