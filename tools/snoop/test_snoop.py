"""
Test script for SNOOP sFlow v5 parser.

Crafts minimal sFlow v5 datagrams and either sends them to a running
SNOOP instance or validates the parser directly.

Usage:
    # Direct parser test (no network, no running SNOOP needed):
    python test_snoop.py

    # Send test packets to running SNOOP:
    python test_snoop.py --send localhost 6343
"""

import json
import os
import socket
import struct
import sys
import time

# Import parser functions from snoop.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from snoop import (
    parse_datagram, parse_ethernet_header, enrich_flow,
    build_subnet_table, subnet_lookup, SnoopState, flush_all,
    decode_ethertype, decode_protocol, decode_service, decode_tcp_flags,
    format_mac, ETHERTYPES, IP_PROTOCOLS, SERVICES, TCP_FLAGS, TOS_VALUES,
)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def build_ethernet_header(src_mac, dst_mac, ethertype, vlan=None):
    """Build raw Ethernet header bytes."""
    hdr = dst_mac + src_mac
    if vlan is not None:
        hdr += struct.pack('>HH', 0x8100, (vlan & 0x0FFF))
        hdr += struct.pack('>H', ethertype)
    else:
        hdr += struct.pack('>H', ethertype)
    return hdr


def build_ipv4_header(src_ip, dst_ip, protocol=6, ttl=64, tos=0):
    """Build minimal 20-byte IPv4 header (no options)."""
    ver_ihl = 0x45
    total_len = 40  # 20 IP + 20 TCP/UDP placeholder
    ident = 0
    flags_frag = 0x4000  # DF
    checksum = 0
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    return struct.pack('>BBHHHBBH4s4s',
                       ver_ihl, tos, total_len, ident, flags_frag,
                       ttl, protocol, checksum, src, dst)


def build_tcp_header(src_port, dst_port, flags=0x12):
    """Build minimal TCP header (20 bytes)."""
    seq = 1000
    ack = 0
    data_offset = 5 << 4  # 20 bytes, no options
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port, seq, ack,
                       data_offset, flags, window, checksum, urgent)


def build_udp_header(src_port, dst_port, length=8):
    """Build UDP header (8 bytes)."""
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, length, checksum)


def pad_to_4(data):
    """Pad bytes to 4-byte XDR boundary."""
    rem = len(data) % 4
    if rem:
        data += b'\x00' * (4 - rem)
    return data


def build_raw_header_record(header_bytes, frame_len=None):
    """Build a raw packet header flow record (enterprise=0, format=1)."""
    if frame_len is None:
        frame_len = len(header_bytes)
    padded = pad_to_4(header_bytes)
    record_data = struct.pack('>IIII',
                              1,               # protocol (Ethernet)
                              frame_len,
                              0,               # stripped
                              len(header_bytes))
    record_data += padded
    # enterprise_format: enterprise=0, format=1 → (0 << 12) | 1
    ef = (0 << 12) | 1
    return struct.pack('>II', ef, len(record_data)) + record_data


def build_extended_switch_record(src_vlan, dst_vlan,
                                 src_pri=0, dst_pri=0):
    """Build extended switch flow record (enterprise=0, format=1001)."""
    record_data = struct.pack('>IIII',
                              src_vlan, src_pri, dst_vlan, dst_pri)
    ef = (0 << 12) | 1001
    return struct.pack('>II', ef, len(record_data)) + record_data


def build_flow_sample(source_index, input_port, output_port,
                      records_data, rate=256):
    """Build a flow sample (enterprise=0, format=1)."""
    seq = 1
    source_id = (0 << 24) | (source_index & 0x00FFFFFF)
    pool = 1000
    drops = 0
    # Count records
    num_records = 0
    tmp = records_data
    while tmp:
        if len(tmp) < 8:
            break
        _, rec_len = struct.unpack_from('>II', tmp, 0)
        num_records += 1
        tmp = tmp[8 + rec_len:]

    sample_data = struct.pack('>IIIIIIII',
                              seq, source_id, rate, pool, drops,
                              input_port, output_port, num_records)
    sample_data += records_data

    ef = (0 << 12) | 1  # enterprise=0, format=1 (flow sample)
    return struct.pack('>II', ef, len(sample_data)) + sample_data


def build_generic_counter_record(ifIndex, ifSpeed=1000000000,
                                 octets_in=1000000, pkts_in=5000,
                                 octets_out=500000, pkts_out=3000):
    """Build generic interface counter record (enterprise=0, format=1)."""
    record_data = struct.pack('>II', ifIndex, 6)  # ifType=6 (ethernet)
    record_data += struct.pack('>Q', ifSpeed)
    record_data += struct.pack('>II', 1, 3)  # ifDirection=fullDuplex, ifStatus=up
    record_data += struct.pack('>Q', octets_in)
    record_data += struct.pack('>IIIII', pkts_in, 0, 0, 0, 0)  # mcast/bcast/discards/errors=0
    record_data += struct.pack('>I', 0)  # unknown_protos
    record_data += struct.pack('>Q', octets_out)
    record_data += struct.pack('>IIIII', pkts_out, 0, 0, 0, 0)

    ef = (0 << 12) | 1  # generic interface counters
    return struct.pack('>II', ef, len(record_data)) + record_data


def build_ethernet_counter_record(alignment_errors=0, fcs_errors=0,
                                   single_collision=0, symbol_errors=0):
    """Build Ethernet interface counter record (enterprise=0, format=2)."""
    record_data = struct.pack('>IIIIIIIIIIIII',
                              alignment_errors, fcs_errors,
                              single_collision, 0,  # multiple_collision
                              0, 0,  # sqe_test, deferred_tx
                              0, 0,  # late_collision, excessive_collision
                              0, 0,  # internal_mac_tx, carrier_sense
                              0, 0,  # frame_too_long, internal_mac_rx
                              symbol_errors)
    ef = (0 << 12) | 2  # enterprise=0, format=2 (ethernet counters)
    return struct.pack('>II', ef, len(record_data)) + record_data


def build_counter_sample(source_index, records_data):
    """Build a counter sample (enterprise=0, format=2)."""
    seq = 1
    source_id = (0 << 24) | (source_index & 0x00FFFFFF)
    num_records = 0
    tmp = records_data
    while tmp:
        if len(tmp) < 8:
            break
        _, rec_len = struct.unpack_from('>II', tmp, 0)
        num_records += 1
        tmp = tmp[8 + rec_len:]

    sample_data = struct.pack('>III', seq, source_id, num_records)
    sample_data += records_data

    ef = (0 << 12) | 2  # enterprise=0, format=2 (counter sample)
    return struct.pack('>II', ef, len(sample_data)) + sample_data


def build_datagram(agent_ip, samples_data, num_samples,
                   sub_agent=0, seq=1, uptime=60000):
    """Build complete sFlow v5 datagram."""
    header = struct.pack('>II', 5, 1)  # version=5, addr_type=1 (IPv4)
    header += socket.inet_aton(agent_ip)
    header += struct.pack('>IIII', sub_agent, seq, uptime, num_samples)
    return header + samples_data


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_decode_dicts():
    """Verify decode dicts have expected entries."""
    print('  [TEST] Decode dicts...')

    assert decode_ethertype(0x0800) == 'IPv4'
    assert decode_ethertype(0x0806) == 'ARP'
    assert decode_ethertype(0x8892) == 'PROFINET'
    assert decode_ethertype(0x88E3) == 'MRP'
    assert decode_ethertype(0x88F7) == 'PTP'
    assert decode_ethertype(0x892F) == 'HSR'
    assert decode_ethertype(0x88CC) == 'LLDP'
    assert decode_ethertype(0x9999) == '0x9999'  # unknown

    assert decode_protocol(6) == 'TCP'
    assert decode_protocol(17) == 'UDP'
    assert decode_protocol(1) == 'ICMP'
    assert decode_protocol(89) == 'OSPFIGP'
    assert decode_protocol(250) == 'proto_250'  # undefined

    assert decode_service(80) == 'HTTP'
    assert decode_service(443) == 'HTTPS'
    assert decode_service(502) == 'Modbus'
    assert decode_service(44818) == 'EtherNet/IP'
    assert decode_service(4840) == 'OPC-UA'
    assert decode_service(47808) == 'BACnet'
    assert decode_service(48898) == 'ADS/AMS'
    assert decode_service(20000) == 'DNP3'
    assert decode_service(99999) == '99999'  # unknown

    assert decode_tcp_flags(0x02) == 'SYN'
    assert decode_tcp_flags(0x12) == 'SYN-ACK'
    assert decode_tcp_flags(0x18) == 'PSH-ACK'
    assert decode_tcp_flags(0xFF) == '0xff'  # unknown

    assert len(ETHERTYPES) == 46  # 42 yaml - 1 dupe + 5 additions (GOOSE, GSE, SV, WSMP, QinQ)
    assert len(TCP_FLAGS) == 64
    assert len(TOS_VALUES) == 26
    # IP_PROTOCOLS: only non-"Undefined" entries from YAML = ~139
    assert len(IP_PROTOCOLS) > 130

    print('         PASS')


def test_format_mac():
    print('  [TEST] MAC formatting...')
    assert format_mac(b'\xaa\xbb\xcc\xdd\xee\xff') == 'aa:bb:cc:dd:ee:ff'
    assert format_mac(b'\x00\x00\x00\x00\x00\x00') == '00:00:00:00:00:00'
    print('         PASS')


def test_ethernet_parser():
    """Test parsing of crafted Ethernet headers."""
    print('  [TEST] Ethernet header parsing...')

    # Plain IPv4 TCP
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    eth = build_ethernet_header(src_mac, dst_mac, 0x0800)
    ip = build_ipv4_header('10.1.0.100', '10.2.0.50', protocol=6)
    tcp = build_tcp_header(12345, 502, flags=0x18)  # PSH-ACK to Modbus
    header = eth + ip + tcp

    parsed = parse_ethernet_header(header)
    assert parsed['src_mac'] == '00:11:22:33:44:55'
    assert parsed['dst_mac'] == 'aa:bb:cc:dd:ee:ff'
    assert parsed['ethertype'] == 0x0800
    assert parsed['vlan'] is None
    assert parsed['src_ip'] == '10.1.0.100'
    assert parsed['dst_ip'] == '10.2.0.50'
    assert parsed['ip_protocol'] == 6
    assert parsed['src_port'] == 12345
    assert parsed['dst_port'] == 502
    assert parsed['tcp_flags'] == 0x18

    print('         PASS')


def test_ethernet_vlan():
    """Test 802.1Q tagged frame parsing."""
    print('  [TEST] 802.1Q VLAN parsing...')

    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    eth = build_ethernet_header(src_mac, dst_mac, 0x0800, vlan=10)
    ip = build_ipv4_header('10.1.0.100', '10.2.0.50', protocol=17)
    udp = build_udp_header(5000, 4840)  # OPC-UA
    header = eth + ip + udp

    parsed = parse_ethernet_header(header)
    assert parsed['vlan'] == 10
    assert parsed['ethertype'] == 0x0800
    assert parsed['src_port'] == 5000
    assert parsed['dst_port'] == 4840

    print('         PASS')


def test_arp_frame():
    """Test ARP ethertype detection."""
    print('  [TEST] ARP frame...')

    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    eth = build_ethernet_header(src_mac, dst_mac, 0x0806)
    # ARP payload doesn't need to be parsed — just ethertype
    header = eth + b'\x00' * 28  # ARP payload placeholder

    parsed = parse_ethernet_header(header)
    assert parsed['ethertype'] == 0x0806
    assert parsed.get('ip_protocol') is None  # ARP, not IP

    print('         PASS')


def test_profinet_frame():
    """Test PROFINET (industrial L2) frame detection."""
    print('  [TEST] PROFINET frame...')

    src_mac = b'\x00\x0e\xcf\x11\x22\x33'  # Siemens OUI
    dst_mac = b'\x01\x0e\xcf\x00\x00\x00'  # PROFINET multicast
    eth = build_ethernet_header(src_mac, dst_mac, 0x8892)
    header = eth + b'\x00' * 20  # PROFINET payload

    parsed = parse_ethernet_header(header)
    assert parsed['ethertype'] == 0x8892
    assert parsed['src_mac'] == '00:0e:cf:11:22:33'

    print('         PASS')


def test_datagram_parser():
    """Test full sFlow v5 datagram parsing."""
    print('  [TEST] sFlow v5 datagram...')

    # Build a flow sample with raw header + extended switch
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    eth = build_ethernet_header(src_mac, dst_mac, 0x0800)
    ip = build_ipv4_header('10.1.0.100', '10.2.0.50', protocol=6)
    tcp = build_tcp_header(49152, 502, flags=0x18)
    packet_header = eth + ip + tcp

    records = build_raw_header_record(packet_header)
    records += build_extended_switch_record(10, 10)
    flow_sample = build_flow_sample(3, 3, 5, records, rate=256)

    # Build a counter sample
    counter_rec = build_generic_counter_record(
        ifIndex=3, octets_in=5000000, pkts_in=10000)
    counter_sample = build_counter_sample(3, counter_rec)

    datagram = build_datagram(
        '192.168.1.4', flow_sample + counter_sample, 2)

    # Parse
    result = parse_datagram(datagram)
    assert result is not None
    assert result['agent'] == '192.168.1.4'
    assert len(result['flow_samples']) == 1
    assert len(result['counter_samples']) == 1

    fs = result['flow_samples'][0]
    assert fs['source_index'] == 3
    assert fs['input'] == 3
    assert fs['output'] == 5
    assert fs['rate'] == 256
    assert len(fs['records']) == 2

    rtype, raw_hdr = fs['records'][0]
    assert rtype == 'raw_header'
    assert raw_hdr['src_ip'] == '10.1.0.100'
    assert raw_hdr['dst_ip'] == '10.2.0.50'
    assert raw_hdr['dst_port'] == 502

    rtype, ext_sw = fs['records'][1]
    assert rtype == 'ext_switch'
    assert ext_sw['src_vlan'] == 10

    cs = result['counter_samples'][0]
    assert cs['source_index'] == 3
    rtype, ctrs = cs['records'][0]
    assert rtype == 'generic'
    assert ctrs['ifIndex'] == 3
    assert ctrs['octets_in'] == 5000000

    print('         PASS')


def test_enrichment():
    """Test flow enrichment with VLAN and subnet dicts."""
    print('  [TEST] Flow enrichment...')

    vlan_dict = {
        '10': {'name': 'I/O Network', 'purdue': 1},
        '20': {'name': 'Engineering', 'purdue': 2},
    }
    subnet_dict = {
        '10.1.0.0/24': {'name': 'PLC Network', 'purdue': 1},
        '10.2.0.0/24': {'name': 'SCADA', 'purdue': 2},
        '10.10.0.0/24': {'name': 'Management', 'purdue': 3},
    }
    subnet_table = build_subnet_table(subnet_dict)

    header = {
        'ethertype': 0x0800,
        'ip_protocol': 6,
        'src_port': 49152,
        'dst_port': 502,
        'tcp_flags': 0x18,
        'tos': 0x00,
        'src_ip': '10.1.0.100',
        'dst_ip': '10.2.0.50',
        'vlan': 10,
    }
    ext_switch = {'src_vlan': 10, 'dst_vlan': 10}

    enriched = enrich_flow(header, ext_switch, vlan_dict, subnet_table)
    assert enriched['ethertype_name'] == 'IPv4'
    assert enriched['protocol_name'] == 'TCP'
    assert enriched['dst_service'] == 'Modbus'
    assert enriched['tcp_flags_name'] == 'PSH-ACK'
    assert enriched['tos_name'] == 'Routine'
    assert enriched['vlan'] == 10
    assert enriched['vlan_name'] == 'I/O Network'
    assert enriched['vlan_purdue'] == 1
    assert enriched['src_zone'] == 'PLC Network'
    assert enriched['src_purdue'] == 1
    assert enriched['dst_zone'] == 'SCADA'
    assert enriched['dst_purdue'] == 2
    assert enriched['purdue_crossing'] is False  # diff=1, not >1

    # Test purdue crossing: L1 → L3
    header2 = {
        'ethertype': 0x0800, 'ip_protocol': 6,
        'src_ip': '10.1.0.100', 'dst_ip': '10.10.0.1',
    }
    enriched2 = enrich_flow(header2, None, vlan_dict, subnet_table)
    assert enriched2['purdue_crossing'] is True  # L1→L3, diff=2

    print('         PASS')


def test_subnet_lookup():
    """Test longest-prefix match."""
    print('  [TEST] Subnet lookup...')

    subnet_dict = {
        '10.0.0.0/8': {'name': 'Private', 'purdue': 0},
        '10.1.0.0/24': {'name': 'PLC', 'purdue': 1},
        '10.1.0.0/28': {'name': 'PLC Rack A', 'purdue': 1},
    }
    table = build_subnet_table(subnet_dict)

    # Most specific wins
    result = subnet_lookup('10.1.0.5', table)
    assert result['name'] == 'PLC Rack A'

    # Falls back to /24
    result = subnet_lookup('10.1.0.100', table)
    assert result['name'] == 'PLC'

    # Falls back to /8
    result = subnet_lookup('10.99.0.1', table)
    assert result['name'] == 'Private'

    # No match
    result = subnet_lookup('192.168.1.1', table)
    assert result is None

    print('         PASS')


def test_state_model():
    """Test in-memory state accumulation."""
    print('  [TEST] State model...')

    state = SnoopState()

    vlan_dict = {
        '10': {'name': 'I/O Network', 'purdue': 1},
    }
    subnet_dict = {
        '10.1.0.0/24': {'name': 'PLC Network', 'purdue': 1},
    }
    subnet_table = build_subnet_table(subnet_dict)

    # Simulate a parsed flow sample
    sample = {
        'seq': 1, 'source_type': 0, 'source_index': 3,
        'rate': 256, 'pool': 1000, 'drops': 0,
        'input': 3, 'output': 5,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': '00:11:22:33:44:55',
                'dst_mac': 'aa:bb:cc:dd:ee:ff',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '10.1.0.100',
                'dst_ip': '10.2.0.50',
                'src_port': 49152, 'dst_port': 502,
                'tcp_flags': 0x18, 'tos': 0,
            }),
            ('ext_switch', {
                'src_vlan': 10, 'src_priority': 0,
                'dst_vlan': 10, 'dst_priority': 0,
            }),
        ],
    }

    state.update_agent('192.168.1.4', 1)
    state.update_from_flow('192.168.1.4', sample, vlan_dict, subnet_table)

    # Check FDB (per-agent per-port)
    assert '192.168.1.4' in state.fdb
    assert '3' in state.fdb['192.168.1.4']
    assert '00:11:22:33:44:55' in state.fdb['192.168.1.4']['3']
    entry = state.fdb['192.168.1.4']['3']['00:11:22:33:44:55']
    assert entry['vlan'] == 10
    assert entry['ip'] == '10.1.0.100'

    # Check ARP table (site-wide)
    assert '10.1.0.100' in state.arp_table
    arp = state.arp_table['10.1.0.100']
    assert arp['mac'] == '00:11:22:33:44:55'
    assert arp['zone'] == 'PLC Network'

    # Check VLAN table (per-vlan per-agent per-port with MACs)
    assert '10' in state.vlan_table
    vt = state.vlan_table['10']
    assert vt['name'] == 'I/O Network'
    assert '192.168.1.4' in vt['agents']
    assert '3' in vt['agents']['192.168.1.4']['ports']
    assert '00:11:22:33:44:55' in vt['agents']['192.168.1.4']['ports']['3']['macs']

    # Check port traffic
    assert '192.168.1.4' in state.port_traffic
    assert '3' in state.port_traffic['192.168.1.4']
    pt = state.port_traffic['192.168.1.4']['3']
    assert pt['ethertypes']['IPv4'] == 1
    assert pt['protocols']['TCP'] == 1
    assert pt['services']['Modbus'] == 1
    assert '00:11:22:33:44:55' in pt['macs']

    # Counters
    counter_sample = {
        'seq': 1, 'source_type': 0, 'source_index': 3,
        'records': [('generic', {
            'ifIndex': 3, 'ifType': 6, 'ifSpeed': 1000000000,
            'ifDirection': 1, 'ifStatus': 3,
            'octets_in': 5000000, 'pkts_in': 10000,
            'mcast_in': 0, 'bcast_in': 0,
            'discards_in': 0, 'errors_in': 0,
            'unknown_protos': 0,
            'octets_out': 2500000, 'pkts_out': 5000,
            'mcast_out': 0, 'bcast_out': 0,
            'discards_out': 0, 'errors_out': 0,
        })],
    }
    state.update_from_counters('192.168.1.4', counter_sample)
    assert '3' in state.port_counters.get('192.168.1.4', {})

    print('         PASS')


def test_output_files():
    """Test JSON output file generation."""
    print('  [TEST] Output files...')

    import tempfile
    output_dir = tempfile.mkdtemp(prefix='snoop_test_')

    state = SnoopState()
    vlan_dict = {'10': {'name': 'I/O Network', 'purdue': 1}}
    subnet_table = build_subnet_table(
        {'10.1.0.0/24': {'name': 'PLC', 'purdue': 1}})

    # Feed some data
    sample = {
        'input': 3, 'output': 5, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': '00:11:22:33:44:55',
                'dst_mac': 'aa:bb:cc:dd:ee:ff',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '10.1.0.100',
                'dst_ip': '10.2.0.50',
                'src_port': 49152, 'dst_port': 502,
                'tcp_flags': 0x18, 'tos': 0,
            }),
            ('ext_switch', {'src_vlan': 10, 'dst_vlan': 10}),
        ],
    }
    state.update_agent('192.168.1.4', 1)
    state.sflow_datagrams = 1
    state.flow_samples = 1
    state.update_from_flow('192.168.1.4', sample, vlan_dict, subnet_table)

    os.makedirs(os.path.join(output_dir, 'agents'), exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'layers'), exist_ok=True)

    flush_all(state, output_dir, '0.0.0.0', 6343, None, None)

    # Verify files exist and are valid JSON
    expected_files = [
        'state.json',
        'agents/192.168.1.4.json',
        'layers/fdb.json',
        'layers/arp_table.json',
        'layers/vlan_table.json',
        'layers/port_counters.json',
        'layers/port_traffic.json',
    ]
    for rel in expected_files:
        path = os.path.join(output_dir, rel)
        assert os.path.exists(path), f'Missing: {rel}'
        with open(path, 'r') as f:
            data = json.load(f)
        assert isinstance(data, dict), f'Not a dict: {rel}'

    # Spot-check state.json
    with open(os.path.join(output_dir, 'state.json')) as f:
        st = json.load(f)
    assert st['stats']['sflow_datagrams'] == 1
    assert st['stats']['unique_macs'] == 1
    assert '192.168.1.4' in st['agents']

    # Spot-check FDB (per-agent per-port)
    with open(os.path.join(output_dir, 'layers', 'fdb.json')) as f:
        fdb = json.load(f)
    assert '192.168.1.4' in fdb['agents']
    assert '3' in fdb['agents']['192.168.1.4']
    assert '00:11:22:33:44:55' in fdb['agents']['192.168.1.4']['3']
    assert fdb['agents']['192.168.1.4']['3']['00:11:22:33:44:55']['vlan'] == 10

    # Spot-check vlan_table (per-vlan per-agent per-port with MACs)
    with open(os.path.join(output_dir, 'layers', 'vlan_table.json')) as f:
        vt = json.load(f)
    assert '10' in vt['vlans']
    assert '00:11:22:33:44:55' in vt['vlans']['10']['agents']['192.168.1.4']['ports']['3']['macs']

    # Spot-check port_traffic
    with open(os.path.join(output_dir, 'layers', 'port_traffic.json')) as f:
        pf = json.load(f)
    assert pf['agents']['192.168.1.4']['3']['services']['Modbus'] == 1

    # Cleanup
    import shutil
    shutil.rmtree(output_dir)

    print('         PASS')


def test_full_round_trip():
    """Build a datagram, parse it, feed to state, verify output."""
    print('  [TEST] Full round trip (build → parse → state)...')

    # Build packet
    src_mac = b'\x00\x0e\xcf\x11\x22\x33'
    dst_mac = b'\x00\x80\x63\xaa\xbb\xcc'
    eth = build_ethernet_header(src_mac, dst_mac, 0x0800, vlan=20)
    ip = build_ipv4_header('10.2.0.10', '10.1.0.100', protocol=17)
    udp = build_udp_header(44818, 44818)  # EtherNet/IP
    packet = eth + ip + udp

    records = build_raw_header_record(packet)
    records += build_extended_switch_record(20, 20)
    flow = build_flow_sample(1, 1, 3, records, rate=128)
    dgram = build_datagram('192.168.1.81', flow, 1, seq=42)

    # Parse
    result = parse_datagram(dgram)
    assert result is not None
    assert result['agent'] == '192.168.1.81'
    assert result['seq'] == 42

    fs = result['flow_samples'][0]
    _, hdr = fs['records'][0]
    assert hdr['src_mac'] == '00:0e:cf:11:22:33'
    assert hdr['dst_port'] == 44818
    assert hdr['vlan'] == 20

    # Feed to state
    vlan_dict = {'20': {'name': 'Engineering', 'purdue': 2}}
    subnet_table = build_subnet_table({
        '10.1.0.0/24': {'name': 'PLC', 'purdue': 1},
        '10.2.0.0/24': {'name': 'SCADA', 'purdue': 2},
    })

    state = SnoopState()
    state.update_agent('192.168.1.81', 42)
    state.update_from_flow('192.168.1.81', fs, vlan_dict, subnet_table)

    fdb_entry = state.fdb['192.168.1.81']['1']['00:0e:cf:11:22:33']
    assert fdb_entry['vlan'] == 20
    assert fdb_entry['ip'] == '10.2.0.10'

    pt = state.port_traffic['192.168.1.81']['1']
    assert 'EtherNet/IP' in pt['services']

    print('         PASS')


def test_gateway_detection():
    """Test auto-detection of gateways via multi-IP MAC classification."""
    print('  [TEST] Gateway detection...')

    state = SnoopState()
    vlan_dict = {}
    subnet_table = []

    # Flow 1: private src_ip from a normal device
    sample1 = {
        'input': 3, 'output': 7, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': '00:11:22:33:44:55',
                'dst_mac': 'aa:bb:cc:dd:ee:ff',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '192.168.1.100',
                'dst_ip': '18.155.216.101',
                'src_port': 49152, 'dst_port': 443,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state.update_agent('192.168.1.254', 1)
    state.update_from_flow('192.168.1.254', sample1, vlan_dict, subnet_table)

    # Normal device should be in ARP table
    assert '192.168.1.100' in state.arp_table
    assert state.arp_table['192.168.1.100']['mac'] == '00:11:22:33:44:55'
    # Public dst_ip should NOT be in ARP table
    assert '18.155.216.101' not in state.arp_table
    # No gateways yet (dst_mac only seen with one IP so far — the public
    # one was filtered before it could trigger multi-IP detection)
    assert len(state.gateways) == 0

    # Flow 2: same dst_mac (gateway) with a DIFFERENT public IP
    # First we need the gateway MAC to appear with a private IP in ARP
    # to set up the multi-IP trigger.
    # Simulate: the gateway itself sends a packet (src_mac=gateway, src_ip=private)
    sample_gw_private = {
        'input': 7, 'output': 3, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'aa:bb:cc:dd:ee:ff',
                'dst_mac': '00:11:22:33:44:55',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 1, 'src_ip': '192.168.1.1',
                'dst_ip': '192.168.1.100',
                'src_port': None, 'dst_port': None,
                'tcp_flags': None, 'tos': 0,
            }),
        ],
    }
    state.update_from_flow('192.168.1.254', sample_gw_private, vlan_dict, subnet_table)

    # Gateway MAC now has one private IP in ARP
    assert '192.168.1.1' in state.arp_table
    assert state.arp_table['192.168.1.1']['mac'] == 'aa:bb:cc:dd:ee:ff'

    # Flow 3: gateway sends another packet from a public IP (routed traffic)
    sample_gw_public = {
        'input': 7, 'output': 3, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'aa:bb:cc:dd:ee:ff',
                'dst_mac': '00:11:22:33:44:55',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '18.155.216.101',
                'dst_ip': '192.168.1.100',
                'src_port': 443, 'dst_port': 49152,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state.update_from_flow('192.168.1.254', sample_gw_public, vlan_dict, subnet_table)

    # Gateway auto-detected: MAC had 192.168.1.1, now has 18.155.216.101
    # These are cross-network (192.x vs 18.x) → reclassified
    assert 'aa:bb:cc:dd:ee:ff' in state.gateways
    gw = state.gateways['aa:bb:cc:dd:ee:ff']
    assert '192.168.1.1' in gw['ips']
    assert '18.155.216.101' in gw['ips']
    assert gw['own_ip'] == '192.168.1.1'  # private IP = own_ip

    # Gateway's private IP should have been removed from ARP table
    assert '192.168.1.1' not in state.arp_table

    # Normal device still in ARP
    assert '192.168.1.100' in state.arp_table

    # Flow 4: more public IPs through gateway — should go straight to gateways
    sample_gw_more = {
        'input': 7, 'output': 3, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'aa:bb:cc:dd:ee:ff',
                'dst_mac': '00:11:22:33:44:55',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '142.250.70.14',
                'dst_ip': '192.168.1.100',
                'src_port': 443, 'dst_port': 49153,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state.update_from_flow('192.168.1.254', sample_gw_more, vlan_dict, subnet_table)

    # New IP added to gateway, NOT to ARP
    assert '142.250.70.14' in state.gateways['aa:bb:cc:dd:ee:ff']['ips']
    assert '142.250.70.14' not in state.arp_table

    # unique_ips should only count ARP entries (local devices)
    assert state.unique_ips() == 1  # just 192.168.1.100

    # Flow 5: dual-stack device — IPv4 + IPv6 link-local should NOT trigger gateway
    state2 = SnoopState()
    state2.update_agent('192.168.1.254', 1)
    sample_v4 = {
        'input': 1, 'output': 7, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'e4:b9:7a:fa:39:f6',
                'dst_mac': '00:11:22:33:44:55',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '192.168.1.132',
                'dst_ip': '192.168.1.100',
                'src_port': 49152, 'dst_port': 80,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state2.update_from_flow('192.168.1.254', sample_v4, vlan_dict, subnet_table)
    sample_v6 = {
        'input': 1, 'output': 7, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'e4:b9:7a:fa:39:f6',
                'dst_mac': '00:11:22:33:44:55',
                'ethertype': 0x86DD, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': 'fe80::ac75:6612:9e24:4e22',
                'dst_ip': 'fe80::1',
                'src_port': 49152, 'dst_port': 80,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state2.update_from_flow('192.168.1.254', sample_v6, vlan_dict, subnet_table)

    # Dual-stack device must NOT be classified as gateway
    assert 'e4:b9:7a:fa:39:f6' not in state2.gateways
    assert '192.168.1.132' in state2.arp_table

    print('         PASS')


def test_cross_network():
    """Test _is_cross_network helper with configurable prefix."""
    print('  [TEST] Cross-network detection...')

    # Default /24 — tighter than old /8
    s24 = SnoopState()  # gateway_prefix=24 by default
    assert s24._is_cross_network('192.168.1.1', '10.0.0.1') == True
    assert s24._is_cross_network('192.168.1.1', '18.155.216.101') == True
    assert s24._is_cross_network('172.16.0.1', '8.8.8.8') == True
    assert s24._is_cross_network('192.168.1.1', '192.168.2.1') == True   # different /24
    assert s24._is_cross_network('10.1.0.1', '10.2.0.1') == True         # different /24
    assert s24._is_cross_network('192.168.1.1', '192.168.1.254') == False # same /24

    # Dual-stack (IPv4 + IPv6) is NOT cross-network
    assert s24._is_cross_network('192.168.1.1', 'fe80::1') == False
    assert s24._is_cross_network('10.0.0.1', '2001:db8::1') == False

    # Configurable: /16 prefix
    s16 = SnoopState(gateway_prefix=16)
    assert s16._is_cross_network('192.168.1.1', '192.168.2.1') == False   # same /16 (192.168.x.x)
    assert s16._is_cross_network('10.1.0.1', '10.1.1.1') == False         # same /16 (10.1.x.x)
    assert s16._is_cross_network('10.1.0.1', '10.2.0.1') == True          # different /16
    assert s16._is_cross_network('192.168.1.1', '192.169.1.1') == True    # different /16

    # Configurable: /8 prefix (old behaviour)
    s8 = SnoopState(gateway_prefix=8)
    assert s8._is_cross_network('192.168.1.1', '192.168.2.1') == False    # same /8
    assert s8._is_cross_network('10.1.0.1', '10.2.0.1') == False          # same /8
    assert s8._is_cross_network('192.168.1.1', '10.0.0.1') == True        # different /8

    print('         PASS')


def test_infrastructure_oui():
    """Test that Hirschmann OUI MACs are excluded from ARP table."""
    print('  [TEST] Infrastructure OUI filtering...')

    state = SnoopState()
    vlan_dict = {}
    subnet_table = []

    # Flow from a Hirschmann VRI (ec:74:ba OUI)
    sample = {
        'input': 7, 'output': 3, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'ec:74:ba:35:75:9c',
                'dst_mac': '00:11:22:33:44:55',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '192.168.4.3',
                'dst_ip': '192.168.1.100',
                'src_port': 443, 'dst_port': 49152,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state.update_agent('192.168.1.4', 1)
    state.update_from_flow('192.168.1.4', sample, vlan_dict, subnet_table)

    # Hirschmann MAC should NOT create an ARP entry
    assert '192.168.4.3' not in state.arp_table
    assert 'ec:74:ba:35:75:9c' not in state.gateways

    # But it SHOULD still be in the FDB (we want to see switch ports)
    assert 'ec:74:ba:35:75:9c' in state.fdb['192.168.1.4']['7']

    # Now send from a real end device — should appear in ARP
    sample2 = {
        'input': 3, 'output': 7, 'rate': 256,
        'records': [
            ('raw_header', {
                'protocol': 1, 'frame_len': 100, 'header_len': 54,
                'src_mac': 'b4:2e:99:0e:39:fb',
                'dst_mac': 'ec:74:ba:35:75:9c',
                'ethertype': 0x0800, 'vlan': None,
                'vlan_priority': None,
                'ip_protocol': 6, 'src_ip': '192.168.4.3',
                'dst_ip': '192.168.1.100',
                'src_port': 49152, 'dst_port': 443,
                'tcp_flags': 0x18, 'tos': 0,
            }),
        ],
    }
    state.update_from_flow('192.168.1.4', sample2, vlan_dict, subnet_table)

    # Real device MAC should be in ARP
    assert '192.168.4.3' in state.arp_table
    assert state.arp_table['192.168.4.3']['mac'] == 'b4:2e:99:0e:39:fb'

    # Also test all OUIs
    assert SnoopState._is_infrastructure('ec:74:ba:11:22:33') == True
    assert SnoopState._is_infrastructure('64:60:38:11:22:33') == True
    assert SnoopState._is_infrastructure('00:80:63:11:22:33') == True
    assert SnoopState._is_infrastructure('00:d0:26:11:22:33') == True
    assert SnoopState._is_infrastructure('a0:b0:86:11:22:33') == True
    assert SnoopState._is_infrastructure('94:ae:e3:11:22:33') == True
    assert SnoopState._is_infrastructure('b4:2e:99:0e:39:fb') == False
    assert SnoopState._is_infrastructure('90:ec:77:1b:6c:26') == False

    print('         PASS')


def test_ethernet_counters():
    """Test Ethernet counter record parsing (format=2)."""
    print('  [TEST] Ethernet counters...')

    # Build a counter sample with both generic + ethernet records
    generic_rec = build_generic_counter_record(3, octets_in=5000000)
    ethernet_rec = build_ethernet_counter_record(
        alignment_errors=5, fcs_errors=12, symbol_errors=3)
    combined = generic_rec + ethernet_rec
    counter = build_counter_sample(3, combined)
    dgram = build_datagram('192.168.1.4', counter, 1, seq=1)

    result = parse_datagram(dgram)
    assert result is not None

    cs = result['counter_samples'][0]
    assert len(cs['records']) == 2

    # First record should be generic
    rec_type0, rec_data0 = cs['records'][0]
    assert rec_type0 == 'generic'
    assert rec_data0['ifIndex'] == 3

    # Second record should be ethernet
    rec_type1, rec_data1 = cs['records'][1]
    assert rec_type1 == 'ethernet'
    assert rec_data1['alignment_errors'] == 5
    assert rec_data1['fcs_errors'] == 12
    assert rec_data1['symbol_errors'] == 3
    assert rec_data1['single_collision'] == 0

    # Test state model integration
    state = SnoopState()
    state.update_agent('192.168.1.4', 1)
    state.update_from_counters('192.168.1.4', cs)

    port_data = state.port_counters['192.168.1.4']['3']
    assert port_data['ifIndex'] == 3
    assert 'ethernet' in port_data
    assert port_data['ethernet']['fcs_errors'] == 12
    assert port_data['ethernet']['symbol_errors'] == 3

    print('         PASS')


def send_test_packets(host, port):
    """Send test sFlow datagrams to a running SNOOP instance."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f'\n  Sending test packets to {host}:{port}...\n')

    # Packet 1: Modbus TCP from PLC to SCADA
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    dst_mac = b'\xaa\xbb\xcc\xdd\xee\xff'
    eth = build_ethernet_header(src_mac, dst_mac, 0x0800)
    ip = build_ipv4_header('10.1.0.100', '10.2.0.50', protocol=6)
    tcp = build_tcp_header(49152, 502, flags=0x18)
    records = build_raw_header_record(eth + ip + tcp)
    records += build_extended_switch_record(10, 10)
    flow = build_flow_sample(3, 3, 5, records, rate=256)
    counter_rec = build_generic_counter_record(3, octets_in=5000000)
    counter = build_counter_sample(3, counter_rec)
    dgram = build_datagram('192.168.1.4', flow + counter, 2, seq=1)
    sock.sendto(dgram, (host, port))
    print('  [SENT] Modbus TCP 10.1.0.100→10.2.0.50 (VLAN 10, port 3)')

    time.sleep(0.1)

    # Packet 2: EtherNet/IP on VLAN 20
    src2 = b'\x00\x0e\xcf\x11\x22\x33'
    dst2 = b'\x00\x80\x63\xaa\xbb\xcc'
    eth2 = build_ethernet_header(src2, dst2, 0x0800, vlan=20)
    ip2 = build_ipv4_header('10.2.0.10', '10.1.0.100', protocol=17)
    udp2 = build_udp_header(44818, 44818)
    records2 = build_raw_header_record(eth2 + ip2 + udp2)
    records2 += build_extended_switch_record(20, 20)
    flow2 = build_flow_sample(1, 1, 3, records2, rate=128)
    dgram2 = build_datagram('192.168.1.4', flow2, 1, seq=2)
    sock.sendto(dgram2, (host, port))
    print('  [SENT] EtherNet/IP 10.2.0.10→10.1.0.100 (VLAN 20, port 1)')

    time.sleep(0.1)

    # Packet 3: PROFINET L2 frame (no IP)
    src3 = b'\x00\x0e\xcf\x99\x88\x77'
    dst3 = b'\x01\x0e\xcf\x00\x00\x00'
    eth3 = build_ethernet_header(src3, dst3, 0x8892)
    pn_payload = b'\x00' * 40
    records3 = build_raw_header_record(eth3 + pn_payload)
    records3 += build_extended_switch_record(10, 10)
    flow3 = build_flow_sample(5, 5, 6, records3, rate=256)
    dgram3 = build_datagram('192.168.1.81', flow3, 1, seq=1)
    sock.sendto(dgram3, (host, port))
    print('  [SENT] PROFINET L2 frame (VLAN 10, port 5, agent .81)')

    time.sleep(0.1)

    # Packet 4: ARP broadcast
    src4 = b'\x00\x11\x22\x33\x44\x55'
    dst4 = b'\xff\xff\xff\xff\xff\xff'
    eth4 = build_ethernet_header(src4, dst4, 0x0806)
    arp_payload = b'\x00' * 28
    records4 = build_raw_header_record(eth4 + arp_payload)
    records4 += build_extended_switch_record(10, 10)
    flow4 = build_flow_sample(3, 3, 0, records4, rate=256)
    dgram4 = build_datagram('192.168.1.4', flow4, 1, seq=3)
    sock.sendto(dgram4, (host, port))
    print('  [SENT] ARP broadcast (VLAN 10, port 3, agent .4)')

    time.sleep(0.1)

    # Packet 5: Counter-only datagram from second agent
    counter_recs = b''
    for ifidx in [1, 2, 3, 4, 5, 6]:
        counter_recs += build_generic_counter_record(
            ifidx, octets_in=ifidx * 1000000,
            pkts_in=ifidx * 1000, octets_out=ifidx * 500000)
    # One counter sample per ifIndex (sFlow sends one source_id per sample)
    samples = b''
    num = 0
    for ifidx in [1, 2, 3, 4, 5, 6]:
        rec = build_generic_counter_record(
            ifidx, octets_in=ifidx * 1000000,
            pkts_in=ifidx * 1000, octets_out=ifidx * 500000)
        samples += build_counter_sample(ifidx, rec)
        num += 1
    dgram5 = build_datagram('192.168.1.82', samples, num, seq=1)
    sock.sendto(dgram5, (host, port))
    print('  [SENT] Counter samples for 6 ports (agent .82)')

    sock.close()
    print(f'\n  Done. 5 datagrams sent to {host}:{port}')
    print('  Check SNOOP console output and ./output/ files.\n')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == '--send':
        host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 6343
        send_test_packets(host, port)
        return

    print('\n' + '=' * 60)
    print('  SNOOP Test Suite')
    print('=' * 60)

    test_decode_dicts()
    test_format_mac()
    test_ethernet_parser()
    test_ethernet_vlan()
    test_arp_frame()
    test_profinet_frame()
    test_datagram_parser()
    test_enrichment()
    test_subnet_lookup()
    test_state_model()
    test_output_files()
    test_full_round_trip()
    test_gateway_detection()
    test_cross_network()
    test_infrastructure_oui()
    test_ethernet_counters()

    print('\n' + '-' * 60)
    print('  All tests passed.')
    print('=' * 60 + '\n')


if __name__ == '__main__':
    main()
