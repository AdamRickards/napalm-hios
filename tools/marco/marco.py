"""
MARCO — Multicast Address Resolution and Configuration Operator

Zero-dependency HiDiscovery v2 client for Hirschmann HiOS devices.
Discover, blink, set IP, change protocol, rename — all via multicast SNMP.

Usage:
    python marco.py                    # discover all devices
    python marco.py -v                 # verbose discovery output
    python marco.py -b -i 2           # toggle blink on device 2
    python marco.py -b                 # toggle blink on ALL devices
    python marco.py --set-ip 192.168.1.50 --prefix 24 -i 2
    python marco.py --set-ip 192.168.1.50 --prefix 24 --gateway 192.168.1.254 -i 2
    python marco.py --dhcp -i 3
    python marco.py --name "MY-SWITCH" -i 2
"""

import socket
import struct
import sys
import os
import json
import argparse
import time
from datetime import datetime

MCAST_GROUP = '239.255.16.12'
MCAST_PORT = 51973
JSON_FILE = 'marco_results.json'

# Exact SNMPv2c GetRequest payload captured from HiView — community '@discover@'
# Requests all HiDiscovery MIB OIDs (.1.x status, .2.x config) + sysName
# Byte-for-byte copy from Wireshark capture (320 bytes UDP payload)
DISCOVERY_PAYLOAD = bytes.fromhex(
    '3082013c020101040a40646973636f76657240a0820129020100020100020100'
    '3082011c3010060c2b060104018178106401010005003010060c2b0601040181'
    '78106401020005003010060c2b060104018178106401030005003010060c2b06'
    '0104018178106401040005003010060c2b060104018178106401050005003010'
    '060c2b060104018178106401070005003010060c2b0601040181781064010a00'
    '05003010060c2b060104018178106402010005003010060c2b06010401817810'
    '6402020005003010060c2b060104018178106402030005003010060c2b060104'
    '018178106402040005003010060c2b060104018178106402050005003010060c'
    '2b060104018178106402060005003010060c2b06010401817810640207000500'
    '3010060c2b06010401817810640209000500300c06082b060102010105000500'
)

# OID to key name mapping (from HIRSCHMANN-DISCOVERY-MGMT-MIB)
OID_MAP = {
    '1.3.6.1.4.1.248.16.100.1.1.0':  'mode',
    '1.3.6.1.4.1.248.16.100.1.2.0':  'mac',
    '1.3.6.1.4.1.248.16.100.1.3.0':  'ip_intf_type',
    '1.3.6.1.4.1.248.16.100.1.4.0':  'firmware',
    '1.3.6.1.4.1.248.16.100.1.5.0':  'product',
    '1.3.6.1.4.1.248.16.100.1.6.0':  'ipv6_type',
    '1.3.6.1.4.1.248.16.100.1.7.0':  'ipv6_link_local',
    '1.3.6.1.4.1.248.16.100.1.10.0': 'factory_default',
    '1.3.6.1.4.1.248.16.100.2.1.0':  'uuid',
    '1.3.6.1.4.1.248.16.100.2.2.0':  'config_proto',
    '1.3.6.1.4.1.248.16.100.2.3.0':  'ip_type',
    '1.3.6.1.4.1.248.16.100.2.4.0':  'ip',
    '1.3.6.1.4.1.248.16.100.2.5.0':  'prefix_len',
    '1.3.6.1.4.1.248.16.100.2.6.0':  'gw_type',
    '1.3.6.1.4.1.248.16.100.2.7.0':  'gateway',
    '1.3.6.1.4.1.248.16.100.2.8.0':  'config_action',
    '1.3.6.1.4.1.248.16.100.2.9.0':  'blinking',
    '1.3.6.1.2.1.1.5.0':             'sysname',
}

# Display labels for console output
DISPLAY_NAMES = {
    'mode': 'Mode', 'mac': 'MAC Address', 'ip_intf_type': 'IP Intf Type',
    'firmware': 'Firmware', 'product': 'Product', 'ipv6_link_local': 'IPv6 Link-Local',
    'factory_default': 'Factory Default', 'uuid': 'UUID', 'config_proto': 'Config Proto',
    'ip': 'IP Address', 'prefix_len': 'Prefix Length', 'gateway': 'Gateway',
    'blinking': 'Blinking', 'sysname': 'sysName',
}

DISC_MODE = {1: 'read-write', 2: 'read-only'}
IP_INTF_TYPE = {1: 'loopback', 2: 'router', 3: 'mgmt'}
CFG_PROTO = {1: 'static', 2: 'bootp', 3: 'dhcp'}
BLINK_STATE = {1: 'enable', 2: 'disable'}
PDU_GET_REQUEST = 0xa0
PDU_SET_REQUEST = 0xa3
PDU_GET_RESPONSE = 0xa2

# OIDs for Set operations
OID_UUID       = '1.3.6.1.4.1.248.16.100.2.1.0'
OID_CFG_PROTO  = '1.3.6.1.4.1.248.16.100.2.2.0'
OID_IP_TYPE    = '1.3.6.1.4.1.248.16.100.2.3.0'
OID_IP         = '1.3.6.1.4.1.248.16.100.2.4.0'
OID_PREFIX     = '1.3.6.1.4.1.248.16.100.2.5.0'
OID_GW_TYPE    = '1.3.6.1.4.1.248.16.100.2.6.0'
OID_GATEWAY    = '1.3.6.1.4.1.248.16.100.2.7.0'
OID_ACTION     = '1.3.6.1.4.1.248.16.100.2.8.0'
OID_BLINK      = '1.3.6.1.4.1.248.16.100.2.9.0'
OID_SYSNAME    = '1.3.6.1.2.1.1.5.0'

SNMP_ERRORS = {
    1: 'tooBig', 2: 'noSuchName', 3: 'badValue', 4: 'readOnly',
    5: 'genErr', 6: 'noAccess', 7: 'wrongType', 8: 'wrongLength',
    9: 'wrongEncoding', 10: 'wrongValue', 11: 'noCreation',
    12: 'inconsistentValue', 13: 'resourceUnavailable',
    14: 'commitFailed', 15: 'undoFailed', 17: 'notWritable',
}


# ---------------------------------------------------------------------------
# Minimal BER/ASN.1 decoder (just enough for SNMP responses)
# ---------------------------------------------------------------------------

def decode_length(data, offset):
    """Decode BER length. Returns (length, new_offset)."""
    b = data[offset]
    if b < 0x80:
        return b, offset + 1
    num_bytes = b & 0x7f
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, offset + 1 + num_bytes


def decode_oid(data):
    """Decode BER-encoded OID bytes to dotted string."""
    if not data:
        return ''
    components = [str(data[0] // 40), str(data[0] % 40)]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7f)
        if not (b & 0x80):
            components.append(str(val))
            val = 0
    return '.'.join(components)


def decode_tlv(data, offset):
    """Decode one TLV. Returns (tag, value_bytes, new_offset)."""
    tag = data[offset]
    length, val_start = decode_length(data, offset + 1)
    value = data[val_start:val_start + length]
    return tag, value, val_start + length


def decode_integer(data):
    """Decode BER INTEGER to Python int."""
    val = 0
    for b in data:
        val = (val << 8) | b
    return val


def decode_ip(data):
    """Decode 4-byte IP address or InetAddress."""
    if len(data) == 4:
        return '.'.join(str(b) for b in data)
    if len(data) == 16:
        parts = []
        for i in range(0, 16, 2):
            parts.append(f'{data[i]:02x}{data[i+1]:02x}')
        return ':'.join(parts)
    return data.hex()


def format_mac(data):
    """Format 6-byte MAC address."""
    if len(data) == 6:
        return ':'.join(f'{b:02x}' for b in data)
    return data.hex()


def decode_varbinds(data):
    """Decode SNMP varbind list. Returns [(oid_str, tag, value), ...]."""
    varbinds = []
    offset = 0

    # Outer SEQUENCE (varbind list)
    tag, seq_data, _ = decode_tlv(data, offset)
    if tag != 0x30:
        return varbinds

    inner_offset = 0
    while inner_offset < len(seq_data):
        vb_tag, vb_data, inner_offset = decode_tlv(seq_data, inner_offset)
        if vb_tag != 0x30:
            continue

        vb_offset = 0
        oid_tag, oid_bytes, vb_offset = decode_tlv(vb_data, vb_offset)
        oid_str = decode_oid(oid_bytes) if oid_tag == 0x06 else '?'

        val_tag, val_bytes, vb_offset = decode_tlv(vb_data, vb_offset)
        varbinds.append((oid_str, val_tag, val_bytes))

    return varbinds


def decode_snmp_message(data):
    """Decode full SNMP message. Returns (version, community, pdu_tag, error_status, varbinds)."""
    offset = 0

    tag, msg_data, _ = decode_tlv(data, offset)
    if tag != 0x30:
        return None

    offset = 0
    _, ver_bytes, offset = decode_tlv(msg_data, offset)
    version = decode_integer(ver_bytes)

    _, comm_bytes, offset = decode_tlv(msg_data, offset)
    community = comm_bytes.decode('ascii', errors='replace')

    pdu_tag, pdu_data, _ = decode_tlv(msg_data, offset)

    pdu_offset = 0
    _, _, pdu_offset = decode_tlv(pdu_data, pdu_offset)  # request-id
    _, err_bytes, pdu_offset = decode_tlv(pdu_data, pdu_offset)
    error_status = decode_integer(err_bytes)
    _, _, pdu_offset = decode_tlv(pdu_data, pdu_offset)  # error-index
    varbinds = decode_varbinds(pdu_data[pdu_offset:])

    return version, community, pdu_tag, error_status, varbinds


def parse_value(key, val_tag, val_bytes):
    """Parse a varbind value into a Python-native value for JSON."""
    if val_tag == 0x05:
        return None

    if val_tag == 0x02:
        val = decode_integer(val_bytes)
        if key == 'mode':
            return DISC_MODE.get(val, str(val))
        if key == 'ip_intf_type':
            return IP_INTF_TYPE.get(val, str(val))
        if key == 'config_proto':
            return CFG_PROTO.get(val, str(val))
        if key == 'blinking':
            return BLINK_STATE.get(val, str(val))
        if key == 'factory_default':
            return val == 1
        return val

    # OCTET STRING (0x04) or context-specific (0x81 etc for InetAddress)
    if val_tag in (0x04, 0x81):
        if key == 'mac':
            return format_mac(val_bytes)
        if key in ('ip', 'gateway', 'ipv6_link_local'):
            return decode_ip(val_bytes)
        if key == 'uuid':
            return val_bytes.hex()
        try:
            text = val_bytes.decode('ascii')
            if all(32 <= ord(c) < 127 for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        return val_bytes.hex()

    # IpAddress (0x40)
    if val_tag == 0x40:
        return decode_ip(val_bytes)

    if val_tag in (0x41, 0x42, 0x43):
        return decode_integer(val_bytes)

    return f'[tag=0x{val_tag:02x}] {val_bytes.hex()}'


# ---------------------------------------------------------------------------
# Minimal BER/ASN.1 encoder (just enough for SNMP SetRequests)
# ---------------------------------------------------------------------------

def encode_length(length):
    """Encode BER length bytes."""
    if length < 0x80:
        return bytes([length])
    encoded = []
    tmp = length
    while tmp > 0:
        encoded.append(tmp & 0xff)
        tmp >>= 8
    encoded.reverse()
    return bytes([0x80 | len(encoded)] + encoded)


def encode_tlv(tag, value):
    """Encode a TLV triplet."""
    return bytes([tag]) + encode_length(len(value)) + value


def encode_integer(val):
    """Encode a Python int as BER INTEGER."""
    if val == 0:
        return encode_tlv(0x02, b'\x00')
    octets = []
    tmp = val
    while tmp > 0:
        octets.append(tmp & 0xff)
        tmp >>= 8
    octets.reverse()
    if octets[0] & 0x80:
        octets.insert(0, 0)
    return encode_tlv(0x02, bytes(octets))


def encode_oid(dotted):
    """Encode dotted OID string to BER OID TLV."""
    parts = [int(x) for x in dotted.split('.')]
    encoded = [parts[0] * 40 + parts[1]]
    for p in parts[2:]:
        if p < 128:
            encoded.append(p)
        else:
            chunks = []
            tmp = p
            while tmp > 0:
                chunks.append(tmp & 0x7f)
                tmp >>= 7
            chunks.reverse()
            for j, c in enumerate(chunks):
                encoded.append(c | (0x80 if j < len(chunks) - 1 else 0))
    return encode_tlv(0x06, bytes(encoded))


def encode_unsigned(val):
    """Encode a Python int as BER Gauge32/Unsigned32 (tag 0x42)."""
    if val == 0:
        return encode_tlv(0x42, b'\x00')
    octets = []
    tmp = val
    while tmp > 0:
        octets.append(tmp & 0xff)
        tmp >>= 8
    octets.reverse()
    if octets[0] & 0x80:
        octets.insert(0, 0)
    return encode_tlv(0x42, bytes(octets))


def encode_octet_string(data):
    """Encode bytes as BER OCTET STRING."""
    return encode_tlv(0x04, data)


def build_set_request(request_id, varbind_pairs):
    """Build an SNMPv2c SetRequest message."""
    community = b'@discover@'

    varbinds_data = b''
    for oid_str, val_tlv in varbind_pairs:
        oid_tlv = encode_oid(oid_str)
        varbind = encode_tlv(0x30, oid_tlv + val_tlv)
        varbinds_data += varbind

    varbind_list = encode_tlv(0x30, varbinds_data)

    pdu_data = encode_integer(request_id) + encode_integer(0) + encode_integer(0) + varbind_list
    pdu = encode_tlv(PDU_SET_REQUEST, pdu_data)

    msg_data = encode_integer(1) + encode_tlv(0x04, community) + pdu
    return encode_tlv(0x30, msg_data)


def build_blink_set(uuid_hex, blink_value):
    """Build SetRequest to toggle blinking on a specific device by UUID."""
    uuid_bytes = bytes.fromhex(uuid_hex)
    varbinds = [
        (OID_UUID, encode_octet_string(uuid_bytes)),
        (OID_BLINK, encode_integer(blink_value)),
    ]
    return build_set_request(42, varbinds)


def build_ip_set(uuid_hex, ip_addr, prefix_len, gateway=None):
    """Build SetRequest to configure IP address on a device by UUID."""
    uuid_bytes = bytes.fromhex(uuid_hex)
    ip_bytes = socket.inet_aton(ip_addr)

    varbinds = [
        (OID_UUID, encode_octet_string(uuid_bytes)),
        (OID_CFG_PROTO, encode_integer(1)),         # static
        (OID_IP_TYPE, encode_integer(1)),            # ipv4
        (OID_IP, encode_octet_string(ip_bytes)),
        (OID_PREFIX, encode_unsigned(prefix_len)),   # Gauge32
    ]

    if gateway:
        gw_bytes = socket.inet_aton(gateway)
        varbinds.append((OID_GW_TYPE, encode_integer(1)))
        varbinds.append((OID_GATEWAY, encode_octet_string(gw_bytes)))

    varbinds.append((OID_ACTION, encode_integer(2)))  # activate
    return build_set_request(43, varbinds)


def build_proto_set(uuid_hex, proto_value):
    """Build SetRequest to change config protocol on a device by UUID."""
    uuid_bytes = bytes.fromhex(uuid_hex)
    varbinds = [
        (OID_UUID, encode_octet_string(uuid_bytes)),
        (OID_CFG_PROTO, encode_integer(proto_value)),
    ]
    return build_set_request(44, varbinds)


def build_name_set(uuid_hex, name):
    """Build SetRequest to set sysName on a device by UUID."""
    uuid_bytes = bytes.fromhex(uuid_hex)
    varbinds = [
        (OID_UUID, encode_octet_string(uuid_bytes)),
        (OID_SYSNAME, encode_octet_string(name.encode('ascii'))),
    ]
    return build_set_request(45, varbinds)


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def make_multicast_socket(interface=None):
    """Create a UDP socket bound to the multicast group."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MCAST_PORT))
    if interface:
        mreq = struct.pack('4s4s', socket.inet_aton(MCAST_GROUP),
                           socket.inet_aton(interface))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(interface))
    else:
        mreq = struct.pack('4sL', socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock, mreq


def send_and_wait(sock, payload, source_ip):
    """Send a SetRequest to multicast and wait for the target device's response."""
    print(f"  [MARCO] SET to {MCAST_GROUP}:{MCAST_PORT} ({len(payload)} bytes)")

    sock.sendto(payload, (MCAST_GROUP, MCAST_PORT))
    sock.settimeout(3)

    while True:
        try:
            resp_data, resp_addr = sock.recvfrom(4096)
            result = decode_snmp_message(resp_data)
            if not result:
                continue
            _, _, pdu_tag, error_status, _ = result
            if pdu_tag == PDU_SET_REQUEST:
                continue
            if resp_addr[0] == source_ip:
                if error_status == 0:
                    print(f"  [POLO]  OK from {resp_addr[0]}")
                else:
                    err_name = SNMP_ERRORS.get(error_status, f'error({error_status})')
                    print(f"  [POLO]  {err_name} from {resp_addr[0]}")
                return error_status
        except socket.timeout:
            print(f"  [POLO]  No response from target (timeout)")
            return -1


def load_json(json_path):
    """Load cached discovery results."""
    if not os.path.exists(json_path):
        print(f"  ERROR: no results file — run discovery first", file=sys.stderr)
        sys.exit(1)
    with open(json_path) as f:
        return json.load(f)


def get_device(data, index):
    """Get a device by 1-based index from cached results."""
    devices = data.get('devices', [])
    if not devices:
        print(f"  ERROR: no devices in results", file=sys.stderr)
        sys.exit(1)
    if index < 1 or index > len(devices):
        print(f"  ERROR: index {index} out of range (1-{len(devices)})", file=sys.stderr)
        sys.exit(1)
    dev = devices[index - 1]
    if not dev.get('uuid'):
        print(f"  ERROR: device has no UUID", file=sys.stderr)
        sys.exit(1)
    return dev


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='MARCO — Multicast Address Resolution and Configuration Operator')
    parser.add_argument('--timeout', type=float, default=5,
                        help='seconds to wait for replies (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show full device details per reply')
    parser.add_argument('--raw', action='store_true',
                        help='also print raw hex of each reply')
    parser.add_argument('--interface', metavar='IP',
                        help='local IP of interface facing the switches')
    parser.add_argument('-s', '--silent', action='store_true',
                        help='suppress console output (JSON file only)')
    parser.add_argument('-b', '--blink', action='store_true',
                        help='toggle blink (uses cached JSON)')
    parser.add_argument('-i', '--index', type=int, metavar='N',
                        help='device index to target (from discovery results)')
    parser.add_argument('--set-ip', metavar='IP',
                        help='set management IP on device (requires -i and --prefix)')
    parser.add_argument('--prefix', type=int, metavar='N',
                        help='prefix length for --set-ip (e.g. 24)')
    parser.add_argument('--gateway', metavar='IP',
                        help='gateway for --set-ip (optional)')
    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument('--dhcp', action='store_true',
                             help='set config protocol to DHCP (requires -i)')
    proto_group.add_argument('--static', action='store_true',
                             help='set config protocol to static (requires -i)')
    parser.add_argument('--name', metavar='NAME',
                        help='set sysName on device (requires -i)')
    args = parser.parse_args()

    has_action = args.blink or args.set_ip or args.dhcp or args.static or args.name
    if args.index is not None and not has_action:
        parser.error('-i/--index requires an action (-b, --set-ip, --dhcp, --static, --name)')
    if args.set_ip:
        if args.index is None:
            parser.error('--set-ip requires -i/--index')
        if args.prefix is None:
            parser.error('--set-ip requires --prefix')
    if (args.dhcp or args.static) and args.index is None:
        parser.error('--dhcp/--static requires -i/--index')
    if args.name and args.index is None:
        parser.error('--name requires -i/--index')

    if args.silent:
        sys.stdout = open(os.devnull, 'w')

    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), JSON_FILE)

    if args.blink:
        do_blink(args, json_path)
    elif args.set_ip:
        do_set_ip(args, json_path)
    elif args.dhcp or args.static:
        do_set_proto(args, json_path)
    elif args.name:
        do_set_name(args, json_path)
    else:
        discover(args, json_path)


def discover(args, json_path):
    """Send multicast GetRequest, collect and display replies, write JSON."""
    sock, mreq = make_multicast_socket(args.interface)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.settimeout(args.timeout)

    iface_label = args.interface or 'default'
    print(f"\n  MARCO — HiDiscovery v2")
    print(f"  Group: {MCAST_GROUP}:{MCAST_PORT}  Community: @discover@")
    print(f"  Interface: {iface_label}  Timeout: {args.timeout}s\n")

    try:
        sock.sendto(DISCOVERY_PAYLOAD, (MCAST_GROUP, MCAST_PORT))
        print(f"  [MARCO] Discovery request sent ({len(DISCOVERY_PAYLOAD)} bytes)\n")
    except Exception as e:
        print(f"  [MARCO] FAILED to send: {e}", file=sys.stderr)
        sys.exit(1)

    devices = []
    start = time.time()

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            break

        ip, port = addr
        elapsed = time.time() - start

        try:
            result = decode_snmp_message(data)
            if not result:
                continue
            version, community, pdu_tag, error_status, varbinds = result
            if pdu_tag == PDU_GET_REQUEST:
                continue
        except Exception as e:
            print(f"  (decode error from {ip}: {e})")
            continue

        idx = len(devices) + 1
        device = {'_index': idx, '_source_ip': ip, '_response_time': round(elapsed, 2)}
        for oid_str, val_tag, val_bytes in varbinds:
            key = OID_MAP.get(oid_str)
            if key:
                device[key] = parse_value(key, val_tag, val_bytes)

        devices.append(device)

        sysname = device.get('sysname', '?')
        mgmt_ip = device.get('ip', ip)
        product = device.get('product', '')
        fw = device.get('firmware', '').split(' ')[0] if device.get('firmware') else ''
        mac = device.get('mac', '')

        if args.verbose or args.raw:
            print(f"  [POLO] [{idx}] {mgmt_ip}  {sysname}  ({len(data)} bytes, {elapsed:.2f}s)")
            print(f"  {'=' * 56}")

            if args.raw:
                for i in range(0, len(data), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
                    print(f"  {i:04x}  {hex_part:<48s}  {ascii_part}")
                print()

            for key in ('product', 'firmware', 'mac', 'ip', 'prefix_len', 'gateway',
                         'mode', 'blinking', 'factory_default', 'config_proto',
                         'ipv6_link_local', 'uuid', 'sysname'):
                if key in device and device[key] is not None:
                    label = DISPLAY_NAMES.get(key, key)
                    print(f"    {label:<20s} {device[key]}")
            print()
        else:
            print(f"  [POLO] [{idx}] {mgmt_ip:<16s} {sysname:<24s} {product}  {fw}  {mac}")

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
    sock.close()

    total = time.time() - start

    output = {
        'timestamp': datetime.now().isoformat(),
        'devices': devices,
    }
    with open(json_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n  {len(devices)} device(s) found in {total:.1f}s")
    print(f"  Results: {json_path}\n")


def do_blink(args, json_path):
    """Toggle blink using cached JSON results."""
    data = load_json(json_path)
    devices = data.get('devices', [])
    if not devices:
        print(f"  ERROR: no devices in results", file=sys.stderr)
        sys.exit(1)

    ts = data.get('timestamp', '?')
    print(f"\n  MARCO — Blink Toggle")
    print(f"  Cached results from {ts}\n")

    if args.index is not None:
        targets = [get_device(data, args.index)]
    else:
        targets = devices

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if args.interface:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(args.interface))

    for dev in targets:
        uuid_hex = dev.get('uuid')
        if not uuid_hex:
            continue

        current = dev.get('blinking', 'disable')
        new_val = 2 if current == 'enable' else 1
        new_label = 'enable' if new_val == 1 else 'disable'

        payload = build_blink_set(uuid_hex, new_val)
        sock.sendto(payload, (MCAST_GROUP, MCAST_PORT))

        idx = dev.get('_index', '?')
        mgmt_ip = dev.get('ip', '?')
        sysname = dev.get('sysname', '?')
        print(f"  [MARCO] [{idx}] {mgmt_ip}  {sysname}  blink: {current} -> {new_label}")

        dev['blinking'] = new_label

    sock.close()

    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    print()


def do_set_ip(args, json_path):
    """Set management IP on a device."""
    data = load_json(json_path)
    dev = get_device(data, args.index)

    idx = dev.get('_index', '?')
    sysname = dev.get('sysname', '?')
    old_ip = dev.get('ip', '?')
    old_prefix = dev.get('prefix_len', '?')
    old_gw = dev.get('gateway', '?')

    ts = data.get('timestamp', '?')
    print(f"\n  MARCO — Set IP")
    print(f"  Cached results from {ts}\n")
    print(f"  [{idx}] {sysname}  ({dev.get('product', '?')})")
    print(f"    Current:  {old_ip}/{old_prefix}  gw {old_gw}")
    print(f"    New:      {args.set_ip}/{args.prefix}  gw {args.gateway or old_gw}")
    print()

    payload = build_ip_set(dev['uuid'], args.set_ip, args.prefix, args.gateway)
    sock, mreq = make_multicast_socket(args.interface)
    result = send_and_wait(sock, payload, dev.get('_source_ip'))
    sock.close()

    if result == 0:
        dev['ip'] = args.set_ip
        dev['prefix_len'] = args.prefix
        dev['config_proto'] = 'static'
        if args.gateway:
            dev['gateway'] = args.gateway
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
    print()


def do_set_proto(args, json_path):
    """Set config protocol (DHCP/static) on a device."""
    data = load_json(json_path)
    dev = get_device(data, args.index)

    proto_val = 3 if args.dhcp else 1
    proto_label = 'dhcp' if args.dhcp else 'static'
    old_proto = dev.get('config_proto', '?')

    idx = dev.get('_index', '?')
    sysname = dev.get('sysname', '?')
    mgmt_ip = dev.get('ip', '?')

    ts = data.get('timestamp', '?')
    print(f"\n  MARCO — Set Protocol")
    print(f"  Cached results from {ts}\n")
    print(f"  [{idx}] {mgmt_ip}  {sysname}")
    print(f"    Config proto: {old_proto} -> {proto_label}")
    print()

    payload = build_proto_set(dev['uuid'], proto_val)
    sock, mreq = make_multicast_socket(args.interface)
    result = send_and_wait(sock, payload, dev.get('_source_ip'))
    sock.close()

    if result == 0:
        dev['config_proto'] = proto_label
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
    print()


def do_set_name(args, json_path):
    """Set sysName on a device."""
    data = load_json(json_path)
    dev = get_device(data, args.index)

    idx = dev.get('_index', '?')
    old_name = dev.get('sysname', '?')
    mgmt_ip = dev.get('ip', '?')

    ts = data.get('timestamp', '?')
    print(f"\n  MARCO — Set sysName")
    print(f"  Cached results from {ts}\n")
    print(f"  [{idx}] {mgmt_ip}  {old_name}")
    print(f"    sysName: {old_name} -> {args.name}")
    print()

    payload = build_name_set(dev['uuid'], args.name)
    sock, mreq = make_multicast_socket(args.interface)
    result = send_and_wait(sock, payload, dev.get('_source_ip'))
    sock.close()

    if result == 0:
        dev['sysname'] = args.name
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
    print()


if __name__ == '__main__':
    main()
