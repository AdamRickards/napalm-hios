"""
SNOOP — sFlow Network Observation and Overview Platform

Passive network observation via sFlow v5. Receives sFlow datagrams,
decodes headers, enriches with VLAN/subnet dictionaries, and writes
structured JSON layer files for downstream consumers.

Usage:
    python snoop.py
    python snoop.py --sflow-port 6343 -o ./output
    python snoop.py --vlan-dict vlan_dict.json --subnet-dict subnet_dict.json
    python snoop.py --debug
    python snoop.py -s
"""

import argparse
import ipaddress
import json
import logging
import os
import socket
import struct
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Decode Dicts — converted from sFlow/dictionaries/*.yaml
# ---------------------------------------------------------------------------

# Hirschmann/Belden OUI prefixes (first 3 bytes of MAC).
# MACs matching these are switch infrastructure (ports, VRIs, management)
# and should not appear as end devices in the ARP table.
INFRASTRUCTURE_OUIS = {
    'ec:74:ba': 'Hirschmann (GRS, RSP, MSP, DRAGON, etc.)',
    '64:60:38': 'Hirschmann (BRS, OCTOPUS, etc.)',
    '00:80:63': 'Hirschmann Automation (classic/legacy)',
    '00:d0:26': 'Hirschmann Austria',
    'a0:b0:86': 'Hirschmann (newer models, 2021+)',
    '94:ae:e3': 'Belden Hirschmann (Suzhou)',
}


# Converted from sFlow/dictionaries/ieee_ethertype.yaml (42 entries)
# Keys: int(hex_str, 16) → short name
ETHERTYPES = {
    0x0800: 'IPv4',
    0x0806: 'ARP',
    0x0842: 'WoL',
    0x22F3: 'TRILL',
    0x6003: 'DECnet',
    0x8035: 'RARP',
    0x809B: 'AppleTalk',
    0x80F3: 'AARP',
    0x8100: '802.1Q',
    0x8137: 'IPX',
    0x8204: 'QNX',
    0x86DD: 'IPv6',
    0x8808: 'Flow Control',
    0x8819: 'CobraNet',
    0x8847: 'MPLS',
    0x8848: 'MPLS Multicast',
    0x8863: 'PPPoE Discovery',
    0x8864: 'PPPoE Session',
    0x8870: 'Jumbo',
    0x887B: 'HomePlug',
    0x888E: '802.1X',
    0x8892: 'PROFINET',
    0x889A: 'HyperSCSI',
    0x88A2: 'AoE',
    0x88A4: 'EtherCAT',
    0x88A8: '802.1ad',
    0x88AB: 'Powerlink',
    0x88CC: 'LLDP',
    0x88CD: 'SERCOS III',
    0x88E1: 'HomePlug AV',
    0x88E3: 'MRP',
    0x88E5: 'MACsec',
    0x88E7: 'PBB',
    0x88F7: 'PTP',
    0x8902: 'CFM',
    0x8906: 'FCoE',
    0x8914: 'FCoE Init',
    0x8915: 'RoCE',
    0x891D: 'TTE',
    0x892F: 'HSR',
    0x88B8: 'GOOSE',
    0x88B9: 'GSE',
    0x88BA: 'IEC 61850 SV',
    0x88DC: 'WSMP',
    0x9000: 'Config Test',
    0x9100: 'VLAN Double Tag',
}

# Converted from sFlow/dictionaries/iana_protocols.yaml
# Only non-"Undefined" entries (skip "Undefined" placeholders)
IP_PROTOCOLS = {
    0: 'HOPOPT',        1: 'ICMP',          2: 'IGMP',
    3: 'GGP',           4: 'IPv4',          5: 'ST',
    6: 'TCP',           7: 'CBT',           8: 'EGP',
    9: 'IGP',           10: 'BBN-RCC-MON',  11: 'NVP-II',
    12: 'PUP',          13: 'ARGUS',        14: 'EMCON',
    15: 'XNET',         16: 'CHAOS',        17: 'UDP',
    18: 'MUX',          19: 'DCN-MEAS',     20: 'HMP',
    21: 'PRM',          22: 'XNS-IDP',      23: 'TRUNK-1',
    24: 'TRUNK-2',      25: 'LEAF-1',       26: 'LEAF-2',
    27: 'RDP',          28: 'IRTP',         29: 'ISO-TP4',
    30: 'NETBLT',       31: 'MFE-NSP',      32: 'MERIT-INP',
    33: 'DCCP',         34: '3PC',          35: 'IDPR',
    36: 'XTP',          37: 'DDP',          38: 'IDPR-CMTP',
    39: 'TP++',         40: 'IL',           41: 'IPv6',
    42: 'SDRP',         43: 'IPv6-Route',   44: 'IPv6-Frag',
    45: 'IDRP',         46: 'RSVP',         47: 'GRE',
    48: 'DSR',          49: 'BNA',          50: 'ESP',
    51: 'AH',           52: 'I-NLSP',       53: 'SWIPE',
    54: 'NARP',         55: 'MOBILE',       56: 'TLSP',
    57: 'SKIP',         58: 'IPv6-ICMP',    59: 'IPv6-NoNxt',
    60: 'IPv6-Opts',    62: 'CFTP',         64: 'SAT-EXPAK',
    65: 'KRYPTOLAN',    66: 'RVD',          67: 'IPPC',
    69: 'SAT-MON',      70: 'VISA',         71: 'IPCV',
    72: 'CPNX',         73: 'CPHB',         74: 'WSN',
    75: 'PVP',          76: 'BR-SAT-MON',   77: 'SUN-ND',
    78: 'WB-MON',       79: 'WB-EXPAK',     80: 'ISO-IP',
    81: 'VMTP',         82: 'SECURE-VMTP',  83: 'VINES',
    84: 'TTP/IPTM',     85: 'NSFNET-IGP',   86: 'DGP',
    87: 'TCF',          88: 'EIGRP',        89: 'OSPFIGP',
    90: 'Sprite-RPC',   91: 'LARP',         92: 'MTP',
    93: 'AX.25',        94: 'IPIP',         95: 'MICP',
    96: 'SCC-SP',       97: 'ETHERIP',      98: 'ENCAP',
    100: 'GMTP',        101: 'IFMP',        102: 'PNNI',
    103: 'PIM',         104: 'ARIS',        105: 'SCPS',
    106: 'QNX',         107: 'A/N',         108: 'IPComp',
    109: 'SNP',         110: 'Compaq-Peer', 111: 'IPX-in-IP',
    112: 'VRRP',        113: 'PGM',         115: 'L2TP',
    116: 'DDX',         117: 'IATP',        118: 'STP',
    119: 'SRP',         120: 'UTI',         121: 'SMP',
    122: 'SM',          123: 'PTP',         124: 'ISIS',
    125: 'FIRE',        126: 'CRTP',        127: 'CRUDP',
    128: 'SSCOPMCE',    129: 'IPLT',        130: 'SPS',
    131: 'PIPE',        132: 'SCTP',        133: 'FC',
    134: 'RSVP-E2E-IGNORE',                 135: 'Mobility',
    136: 'UDPLite',     137: 'MPLS-in-IP',  138: 'manet',
    139: 'HIP',         140: 'Shim6',       141: 'WESP',
    142: 'ROHC',        255: 'Reserved',
}

# Converted from sFlow/dictionaries/iana_services.yaml (345 entries)
# + industrial additions not in IANA
SERVICES = {
    1: 'tcpmux', 2: 'nbp', 4: 'echo', 6: 'zip', 7: 'echo',
    9: 'discard', 11: 'systat', 13: 'daytime', 15: 'netstat',
    17: 'qotd', 18: 'msp', 19: 'chargen', 20: 'FTP-Data',
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 37: 'time',
    39: 'rlp', 42: 'nameserver', 43: 'whois', 49: 'TACACS',
    50: 're-mail-ck', 53: 'DNS', 57: 'mtp', 65: 'tacacs-ds',
    67: 'DHCP-S', 68: 'DHCP-C', 69: 'TFTP', 70: 'gopher',
    77: 'rje', 79: 'finger', 80: 'HTTP', 87: 'link',
    88: 'Kerberos', 95: 'supdup', 98: 'linuxconf',
    101: 'hostnames', 102: 'MMS/ISO-TSAP', 104: 'acr-nema',
    105: 'csnet-ns', 106: 'poppassd', 107: 'rtelnet',
    109: 'POP2', 110: 'POP3', 111: 'sunrpc', 113: 'auth',
    115: 'sftp', 117: 'uucp-path', 119: 'NNTP', 123: 'NTP',
    129: 'pwdgen', 135: 'loc-srv', 137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP',
    161: 'SNMP', 162: 'SNMP-Trap', 163: 'cmip-man',
    164: 'cmip-agent', 174: 'mailq', 177: 'xdmcp',
    178: 'nextstep', 179: 'BGP', 191: 'prospero', 194: 'IRC',
    199: 'smux', 201: 'at-rtmp', 202: 'at-nbp', 204: 'at-echo',
    206: 'at-zis', 209: 'qmtp', 210: 'z3950', 213: 'ipx',
    220: 'imap3', 345: 'pawserv', 346: 'zserv', 347: 'fatserv',
    369: 'rpc2portmap', 370: 'codaauth2', 371: 'clearcase',
    372: 'ulistserv', 389: 'LDAP', 406: 'imsp', 427: 'svrloc',
    443: 'HTTPS', 444: 'snpp', 445: 'SMB', 464: 'kpasswd',
    465: 'SMTPS', 487: 'saft', 500: 'IKE',
    # Industrial protocols
    502: 'Modbus',
    512: 'exec', 513: 'login', 514: 'Syslog', 515: 'printer',
    517: 'talk', 518: 'ntalk', 520: 'route', 525: 'timed',
    526: 'tempo', 530: 'courier', 531: 'conference',
    532: 'netnews', 533: 'netwall', 538: 'gdomap', 540: 'uucp',
    543: 'klogin', 544: 'kshell', 546: 'DHCPv6-C',
    547: 'DHCPv6-S', 548: 'afpovertcp', 549: 'idfp',
    554: 'RTSP', 556: 'remotefs', 563: 'NNTPS', 587: 'submission',
    607: 'nqs', 610: 'npmp-local', 611: 'npmp-gui',
    612: 'hmmp-ind', 623: 'IPMI', 628: 'qmqp', 631: 'IPP',
    636: 'LDAPS', 655: 'tinc', 706: 'silc', 749: 'kerberos-adm',
    750: 'kerberos4', 751: 'kerberos-master', 752: 'passwd-server',
    754: 'krb-prop', 760: 'krbupdate', 765: 'webster',
    775: 'moira-db', 777: 'moira-update', 779: 'moira-ureg',
    783: 'spamd', 808: 'omirr', 871: 'supfilesrv', 873: 'rsync',
    901: 'swat', 989: 'FTPS-Data', 990: 'FTPS', 992: 'TelnetS',
    993: 'IMAPS', 994: 'IRCS', 995: 'POP3S', 1001: 'customs',
    1080: 'SOCKS', 1093: 'proofd', 1094: 'rootd',
    1099: 'rmiregistry', 1109: 'kpop', 1127: 'supfiledbg',
    1178: 'skkserv', 1194: 'OpenVPN', 1210: 'predict',
    1214: 'kazaa', 1236: 'rmtcfg', 1241: 'nessus', 1300: 'wipld',
    1313: 'xtel', 1314: 'xtelw', 1352: 'lotusnote',
    1433: 'MSSQL', 1434: 'MSSQL-M', 1524: 'ingreslock',
    1525: 'prospero-np', 1529: 'support', 1645: 'datametrics',
    1646: 'sa-msg-port', 1649: 'kermit', 1677: 'groupwise',
    1701: 'L2F', 1812: 'RADIUS', 1813: 'RADIUS-Acct',
    1863: 'msnp', 1883: 'MQTT',
    1957: 'unix-status', 1958: 'log-server',
    1959: 'remoteping', 2000: 'cisco-sccp', 2003: 'cfinger',
    2010: 'search', 2049: 'NFS', 2053: 'knetd', 2086: 'gnunet',
    2101: 'rtcm-sc104', 2102: 'zephyr-srv', 2103: 'zephyr-clt',
    2104: 'zephyr-hm', 2105: 'eklogin', 2111: 'kx',
    2119: 'gsigatekeeper', 2121: 'iprop', 2135: 'gris',
    2150: 'ninstall', 2222: 'CIP',
    2401: 'CVS', 2404: 'IEC 60870-5-104', 2430: 'venus',
    2431: 'venus-se', 2432: 'codasrv', 2433: 'codasrv-se',
    2583: 'mon', 2600: 'zebrasrv', 2601: 'zebra', 2602: 'ripd',
    2603: 'ripngd', 2604: 'ospfd', 2605: 'bgpd', 2606: 'ospf6d',
    2607: 'ospfapi', 2608: 'isisd', 2628: 'dict',
    2792: 'f5-globalsite', 2811: 'gsiftp', 2947: 'gpsd',
    2988: 'afbackup', 2989: 'afmbackup', 3050: 'gds-db',
    3130: 'icpv2', 3260: 'iSCSI', 3306: 'MySQL', 3389: 'RDP',
    3493: 'nut', 3632: 'distcc', 3689: 'DAAP', 3690: 'SVN',
    4000: 'ENIP-CIP',
    4031: 'suucp', 4094: 'sysrqd', 4190: 'sieve', 4224: 'xtell',
    4353: 'f5-iquery', 4369: 'epmd', 4373: 'remctl',
    4500: 'IPsec-NAT-T', 4557: 'fax', 4559: 'hylafax',
    4569: 'iax', 4600: 'distmp3', 4691: 'mtn',
    4712: 'GE-SRTP',
    # Industrial protocols
    4840: 'OPC-UA',
    4899: 'radmin', 4949: 'munin', 5002: 'rfe', 5050: 'mmcc',
    5051: 'enbd-cstatd', 5052: 'enbd-sstatd', 5060: 'SIP',
    5061: 'SIP-TLS', 5094: 'HART-IP', 5151: 'pcrd', 5190: 'aol',
    5222: 'XMPP-C', 5269: 'XMPP-S', 5308: 'cfengine',
    5353: 'mDNS', 5354: 'noclog', 5355: 'hostmon',
    5432: 'PostgreSQL', 5555: 'rplay', 5556: 'freeciv',
    5666: 'nrpe', 5667: 'nsca', 5672: 'AMQP', 5674: 'mrtd',
    5675: 'bgpsim', 5680: 'canna', 5688: 'ggz',
    5900: 'VNC',
    6000: 'X11', 6001: 'X11-1', 6002: 'X11-2', 6003: 'X11-3',
    6004: 'X11-4', 6005: 'X11-5', 6006: 'X11-6', 6007: 'X11-7',
    6346: 'gnutella-svc', 6347: 'gnutella-rtr',
    6444: 'sge-qmaster', 6445: 'sge-execd', 6446: 'mysql-proxy',
    6514: 'Syslog-TLS', 6566: 'sane-port', 6667: 'IRC',
    7000: 'afs3-fileserver', 7001: 'afs3-callback',
    7002: 'afs3-prserver', 7003: 'afs3-vlserver',
    7004: 'afs3-kaserver', 7005: 'afs3-volser',
    7006: 'afs3-errors', 7007: 'afs3-bos', 7008: 'afs3-update',
    7009: 'afs3-rmtsys', 7100: 'font-service',
    8021: 'zope-ftp', 8080: 'HTTP-Alt', 8081: 'tproxy',
    8088: 'omniorb', 8291: 'WinBox', 8883: 'MQTT-TLS',
    8990: 'clc-build-daemon', 9098: 'xinetd',
    9101: 'bacula-dir', 9102: 'bacula-fd', 9103: 'bacula-sd',
    9359: 'mandelspawn', 9418: 'Git', 9600: 'FINS',
    9667: 'xmms2', 9673: 'zope',
    10000: 'webmin', 10050: 'Zabbix-Agent', 10051: 'Zabbix-Trap',
    10080: 'amanda', 10081: 'kamanda', 10082: 'amandaidx',
    10083: 'amidxtape', 10809: 'nbd', 11112: 'DICOM',
    11201: 'smsqp', 11371: 'hkp', 13720: 'bprd', 13721: 'bpdbm',
    13722: 'bpjava-msvc', 13724: 'vnetd', 13782: 'bpcd',
    13783: 'vopied', 15345: 'xpilot', 17001: 'sgi-cmsd',
    17002: 'sgi-crsd', 17003: 'sgi-gcd', 17004: 'sgi-cad',
    17500: 'db-lsp', 18245: 'GE-SRTP',
    # Industrial additions (not in IANA YAML)
    20000: 'DNP3',
    20011: 'isdnlog', 20012: 'vboxd', 22125: 'dcap',
    22128: 'gsidcap', 22273: 'wnn6', 24554: 'binkp', 27374: 'asp',
    30865: 'csync2',
    34962: 'PROFINET-RT', 34963: 'PROFINET-RTCYC',
    34964: 'PROFINET-CM',
    44818: 'EtherNet/IP',
    47808: 'BACnet',
    48898: 'ADS/AMS',
    57000: 'dircproxy', 60177: 'tfido', 60179: 'fido',
}

# Converted from sFlow/dictionaries/tcp_flags.yaml (64 entries)
TCP_FLAGS = {
    0x00: 'NULL', 0x01: 'FIN', 0x02: 'SYN', 0x03: 'FIN-SYN',
    0x08: 'PSH', 0x09: 'FIN-PSH', 0x0A: 'SYN-PSH',
    0x0B: 'FIN-SYN-PSH', 0x10: 'ACK', 0x11: 'FIN-ACK',
    0x12: 'SYN-ACK', 0x13: 'FIN-SYN-ACK', 0x18: 'PSH-ACK',
    0x19: 'FIN-PSH-ACK', 0x1A: 'SYN-PSH-ACK',
    0x1B: 'FIN-SYN-PSH-ACK', 0x40: 'ECE', 0x41: 'FIN-ECE',
    0x42: 'SYN-ECE', 0x43: 'FIN-SYN-ECE', 0x48: 'PSH-ECE',
    0x49: 'FIN-PSH-ECE', 0x4A: 'SYN-PSH-ECE',
    0x4B: 'FIN-SYN-PSH-ECE', 0x50: 'ACK-ECE',
    0x51: 'FIN-ACK-ECE', 0x52: 'SYN-ACK-ECE',
    0x53: 'FIN-SYN-ACK-ECE', 0x58: 'PSH-ACK-ECE',
    0x59: 'FIN-PSH-ACK-ECE', 0x5A: 'SYN-PSH-ACK-ECE',
    0x5B: 'FIN-SYN-PSH-ACK-ECE', 0x80: 'CWR',
    0x81: 'FIN-CWR', 0x82: 'SYN-CWR', 0x83: 'FIN-SYN-CWR',
    0x88: 'PSH-CWR', 0x89: 'FIN-PSH-CWR', 0x8A: 'SYN-PSH-CWR',
    0x8B: 'FIN-SYN-PSH-CWR', 0x90: 'ACK-CWR',
    0x91: 'FIN-ACK-CWR', 0x92: 'SYN-ACK-CWR',
    0x93: 'FIN-SYN-ACK-CWR', 0x98: 'PSH-ACK-CWR',
    0x99: 'FIN-PSH-ACK-CWR', 0x9A: 'SYN-PSH-ACK-CWR',
    0x9B: 'FIN-SYN-PSH-ACK-CWR', 0xC0: 'ECE-CWR',
    0xC1: 'FIN-ECE-CWR', 0xC2: 'SYN-ECE-CWR',
    0xC3: 'FIN-SYN-ECE-CWR', 0xC8: 'PSH-ECE-CWR',
    0xC9: 'FIN-PSH-ECE-CWR', 0xCA: 'SYN-PSH-ECE-CWR',
    0xCB: 'FIN-SYN-PSH-ECE-CWR', 0xD0: 'ACK-ECE-CWR',
    0xD1: 'FIN-ACK-ECE-CWR', 0xD2: 'SYN-ACK-ECE-CWR',
    0xD3: 'FIN-SYN-ACK-ECE-CWR', 0xD8: 'PSH-ACK-ECE-CWR',
    0xD9: 'FIN-PSH-ACK-ECE-CWR', 0xDA: 'SYN-PSH-ACK-ECE-CWR',
    0xDB: 'FIN-SYN-PSH-ACK-ECE-CWR',
}

# Converted from sFlow/dictionaries/rfc_tos.yaml (26 entries)
TOS_VALUES = {
    0x00: 'Routine', 0x04: 'Routine', 0x08: 'Routine',
    0x0C: 'Routine', 0x10: 'Routine',
    0x20: 'Priority', 0x28: 'Priority', 0x30: 'Priority',
    0x38: 'Priority',
    0x40: 'Immediate', 0x48: 'Immediate', 0x50: 'Immediate',
    0x58: 'Immediate',
    0x60: 'Flash', 0x68: 'Flash', 0x70: 'Flash', 0x78: 'Flash',
    0x80: 'FlashOverride', 0x88: 'FlashOverride',
    0x90: 'FlashOverride', 0x98: 'FlashOverride',
    0xA0: 'Critical', 0xB0: 'Critical', 0xB8: 'Critical',
    0xC0: 'InterNetwork-Control',
    0xE0: 'Network-Control',
}

# IEEE 802.1p Priority Code Point (PCP) — 3 bits from 802.1Q TCI
# The naming is a mess (renumbered in 802.1Q-2005, again in 2014) but
# these are the current IEEE designations per 802.1Q-2022 Table 8-2.
VLAN_PRIORITY = {
    0: 'Best Effort',       1: 'Background',
    2: 'Excellent Effort',  3: 'Critical Apps',
    4: 'Video',             5: 'Voice',
    6: 'Internetwork Ctrl', 7: 'Network Ctrl',
}


# ---------------------------------------------------------------------------
# Decode helpers
# ---------------------------------------------------------------------------

def decode_ethertype(val):
    return ETHERTYPES.get(val, f'0x{val:04x}')


def decode_protocol(val):
    return IP_PROTOCOLS.get(val, f'proto_{val}')


def decode_service(port):
    return SERVICES.get(port, str(port))


def decode_tcp_flags(val):
    return TCP_FLAGS.get(val, f'0x{val:02x}')


def decode_vlan_priority(val):
    return VLAN_PRIORITY.get(val, str(val))


def format_mac(raw):
    """Format 6 raw bytes as colon-separated MAC."""
    return ':'.join(f'{b:02x}' for b in raw)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# sFlow v5 XDR Parser
# ---------------------------------------------------------------------------

def parse_datagram(data):
    """Parse an sFlow v5 datagram. Returns dict or None on error."""
    if len(data) < 28:
        return None

    version = struct.unpack_from('>I', data, 0)[0]
    if version != 5:
        logging.debug('sFlow version %d, expected 5', version)
        return None

    addr_type = struct.unpack_from('>I', data, 4)[0]
    if addr_type == 1:  # IPv4
        agent_ip = socket.inet_ntoa(data[8:12])
        offset = 12
    elif addr_type == 2:  # IPv6
        if len(data) < 40:
            return None
        agent_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        offset = 24
    else:
        return None

    sub_agent, seq, uptime, num_samples = struct.unpack_from(
        '>IIII', data, offset)
    offset += 16

    result = {
        'agent': agent_ip,
        'sub_agent': sub_agent,
        'seq': seq,
        'uptime': uptime,
        'flow_samples': [],
        'counter_samples': [],
    }

    for _ in range(num_samples):
        if offset + 8 > len(data):
            break
        enterprise_format, sample_len = struct.unpack_from(
            '>II', data, offset)
        offset += 8
        enterprise = enterprise_format >> 12
        fmt = enterprise_format & 0xFFF
        sample_end = offset + sample_len

        if enterprise == 0 and fmt == 1:
            # Flow sample
            sample = parse_flow_sample(data, offset, sample_end)
            if sample:
                result['flow_samples'].append(sample)
        elif enterprise == 0 and fmt == 2:
            # Counter sample
            sample = parse_counter_sample(data, offset, sample_end)
            if sample:
                result['counter_samples'].append(sample)
        elif enterprise == 0 and fmt == 3:
            # Expanded flow sample
            sample = parse_expanded_flow_sample(data, offset, sample_end)
            if sample:
                result['flow_samples'].append(sample)
        elif enterprise == 0 and fmt == 4:
            # Expanded counter sample
            sample = parse_expanded_counter_sample(data, offset, sample_end)
            if sample:
                result['counter_samples'].append(sample)

        offset = sample_end

    return result


def parse_flow_sample(data, offset, end):
    """Parse a standard flow sample (enterprise=0, format=1)."""
    if offset + 32 > end:
        return None

    seq, source_id, rate, pool, drops, inp, out, num_records = \
        struct.unpack_from('>IIIIIIII', data, offset)
    offset += 32

    source_type = (source_id >> 24) & 0xFF
    source_index = source_id & 0x00FFFFFF
    input_port = inp & 0x3FFFFFFF
    output_port = out & 0x3FFFFFFF

    return _parse_flow_records(data, offset, end, num_records, {
        'seq': seq,
        'source_type': source_type,
        'source_index': source_index,
        'rate': rate,
        'pool': pool,
        'drops': drops,
        'input': input_port,
        'output': output_port,
    })


def parse_expanded_flow_sample(data, offset, end):
    """Parse an expanded flow sample (enterprise=0, format=3)."""
    if offset + 44 > end:
        return None

    seq, src_type, src_index, rate, pool, drops, \
        inp_fmt, inp_val, out_fmt, out_val, num_records = \
        struct.unpack_from('>IIIIIIIIIII', data, offset)
    offset += 44

    return _parse_flow_records(data, offset, end, num_records, {
        'seq': seq,
        'source_type': src_type,
        'source_index': src_index,
        'rate': rate,
        'pool': pool,
        'drops': drops,
        'input': inp_val,
        'output': out_val,
    })


def _parse_flow_records(data, offset, end, num_records, sample):
    """Parse flow records within a flow sample."""
    sample['records'] = []

    for _ in range(num_records):
        if offset + 8 > end:
            break
        rec_ef, rec_len = struct.unpack_from('>II', data, offset)
        offset += 8
        rec_enterprise = rec_ef >> 12
        rec_format = rec_ef & 0xFFF
        rec_end = offset + rec_len

        if rec_enterprise == 0 and rec_format == 1:
            # Raw packet header
            header = parse_raw_header_record(data, offset, rec_end)
            if header:
                sample['records'].append(('raw_header', header))
        elif rec_enterprise == 0 and rec_format == 1001:
            # Extended switch data
            switch = parse_extended_switch(data, offset)
            if switch:
                sample['records'].append(('ext_switch', switch))

        offset = rec_end

    return sample


def parse_raw_header_record(data, offset, end):
    """Parse a raw packet header flow record (format=1)."""
    if offset + 16 > end:
        return None

    protocol, frame_len, stripped, header_len = struct.unpack_from(
        '>IIII', data, offset)
    offset += 16

    if offset + header_len > end:
        header_len = end - offset
    header_bytes = data[offset:offset + header_len]

    result = {
        'protocol': protocol,
        'frame_len': frame_len,
        'header_len': header_len,
    }

    if protocol == 1 and header_len >= 14:
        # Ethernet
        parsed = parse_ethernet_header(header_bytes)
        if parsed:
            result.update(parsed)

    return result


def parse_ethernet_header(header):
    """Parse Ethernet header bytes → MAC, VLAN, ethertype, IP, ports."""
    if len(header) < 14:
        return None

    dst_mac = header[0:6]
    src_mac = header[6:12]
    offset = 12
    ethertype = struct.unpack_from('>H', header, offset)[0]
    offset += 2

    vlan = None
    vlan_priority = None

    # 802.1Q tag
    if ethertype == 0x8100:
        if offset + 4 > len(header):
            return {'dst_mac': format_mac(dst_mac),
                    'src_mac': format_mac(src_mac),
                    'ethertype': 0x8100, 'vlan': None}
        tci = struct.unpack_from('>H', header, offset)[0]
        vlan = tci & 0x0FFF
        vlan_priority = (tci >> 13) & 0x07
        offset += 2
        ethertype = struct.unpack_from('>H', header, offset)[0]
        offset += 2

    result = {
        'dst_mac': format_mac(dst_mac),
        'src_mac': format_mac(src_mac),
        'ethertype': ethertype,
        'vlan': vlan,
        'vlan_priority': vlan_priority,
    }

    # IPv4
    if ethertype == 0x0800 and offset + 20 <= len(header):
        ver_ihl = header[offset]
        ihl = (ver_ihl & 0x0F) * 4
        if ihl >= 20 and offset + ihl <= len(header):
            tos = header[offset + 1]
            ip_len = struct.unpack_from('>H', header, offset + 2)[0]
            ttl = header[offset + 8]
            ip_proto = header[offset + 9]
            src_ip = socket.inet_ntoa(header[offset + 12:offset + 16])
            dst_ip = socket.inet_ntoa(header[offset + 16:offset + 20])

            result['tos'] = tos
            result['ip_len'] = ip_len
            result['ttl'] = ttl
            result['ip_protocol'] = ip_proto
            result['src_ip'] = src_ip
            result['dst_ip'] = dst_ip

            transport_offset = offset + ihl
            # TCP
            if ip_proto == 6 and transport_offset + 14 <= len(header):
                src_port, dst_port = struct.unpack_from(
                    '>HH', header, transport_offset)
                # TCP flags at offset 13 of TCP header
                tcp_flags = header[transport_offset + 13]
                result['src_port'] = src_port
                result['dst_port'] = dst_port
                result['tcp_flags'] = tcp_flags
            # UDP
            elif ip_proto == 17 and transport_offset + 4 <= len(header):
                src_port, dst_port = struct.unpack_from(
                    '>HH', header, transport_offset)
                result['src_port'] = src_port
                result['dst_port'] = dst_port

    # IPv6 — extract src/dst only
    elif ethertype == 0x86DD and offset + 40 <= len(header):
        ip_proto = header[offset + 6]  # next header
        src_ip = socket.inet_ntop(
            socket.AF_INET6, header[offset + 8:offset + 24])
        dst_ip = socket.inet_ntop(
            socket.AF_INET6, header[offset + 24:offset + 40])
        result['ip_protocol'] = ip_proto
        result['src_ip'] = src_ip
        result['dst_ip'] = dst_ip
        # Skip extension header chasing for v0.1

    return result


def parse_extended_switch(data, offset):
    """Parse extended switch flow record (format=1001)."""
    if offset + 16 > len(data):
        return None
    src_vlan, src_pri, dst_vlan, dst_pri = struct.unpack_from(
        '>IIII', data, offset)
    return {
        'src_vlan': src_vlan,
        'src_priority': src_pri,
        'dst_vlan': dst_vlan,
        'dst_priority': dst_pri,
    }


def parse_counter_sample(data, offset, end):
    """Parse a standard counter sample (enterprise=0, format=2)."""
    if offset + 12 > end:
        return None

    seq, source_id, num_records = struct.unpack_from('>III', data, offset)
    offset += 12

    source_type = (source_id >> 24) & 0xFF
    source_index = source_id & 0x00FFFFFF

    return _parse_counter_records(data, offset, end, num_records, {
        'seq': seq,
        'source_type': source_type,
        'source_index': source_index,
    })


def parse_expanded_counter_sample(data, offset, end):
    """Parse an expanded counter sample (enterprise=0, format=4)."""
    if offset + 16 > end:
        return None

    seq, src_type, src_index, num_records = struct.unpack_from(
        '>IIII', data, offset)
    offset += 16

    return _parse_counter_records(data, offset, end, num_records, {
        'seq': seq,
        'source_type': src_type,
        'source_index': src_index,
    })


def _parse_counter_records(data, offset, end, num_records, sample):
    """Parse counter records within a counter sample."""
    sample['records'] = []

    for _ in range(num_records):
        if offset + 8 > end:
            break
        rec_ef, rec_len = struct.unpack_from('>II', data, offset)
        offset += 8
        rec_enterprise = rec_ef >> 12
        rec_format = rec_ef & 0xFFF
        rec_end = offset + rec_len

        if rec_enterprise == 0 and rec_format == 1:
            counters = parse_generic_counters(data, offset, rec_end)
            if counters:
                sample['records'].append(('generic', counters))
        elif rec_enterprise == 0 and rec_format == 2:
            eth_counters = parse_ethernet_counters(data, offset, rec_end)
            if eth_counters:
                sample['records'].append(('ethernet', eth_counters))
        else:
            logging.debug('Unknown counter record: enterprise=%d format=%d len=%d',
                          rec_enterprise, rec_format, rec_len)

        offset = rec_end

    return sample


def parse_generic_counters(data, offset, end):
    """Parse generic interface counters (format=1)."""
    # 84 bytes: ifIndex(4) ifType(4) ifSpeed(8) ifDir(4) ifStatus(4) = 24
    # octetsIn(8) pktsIn(4) mcastIn(4) bcastIn(4) discardsIn(4) errorsIn(4)
    # unknownProtos(4) = 32
    # octetsOut(8) pktsOut(4) mcastOut(4) bcastOut(4) discardsOut(4) errorsOut(4) = 28
    if offset + 84 > end:
        return None

    ifIndex, ifType = struct.unpack_from('>II', data, offset)
    ifSpeed = struct.unpack_from('>Q', data, offset + 8)[0]
    ifDirection, ifStatus = struct.unpack_from('>II', data, offset + 16)

    octets_in = struct.unpack_from('>Q', data, offset + 24)[0]
    pkts_in, mcast_in, bcast_in, discards_in, errors_in, unknown_protos = \
        struct.unpack_from('>IIIIII', data, offset + 32)

    octets_out = struct.unpack_from('>Q', data, offset + 56)[0]
    pkts_out, mcast_out, bcast_out, discards_out, errors_out = \
        struct.unpack_from('>IIIII', data, offset + 64)

    return {
        'ifIndex': ifIndex,
        'ifType': ifType,
        'ifSpeed': ifSpeed,
        'ifDirection': ifDirection,
        'ifStatus': ifStatus,
        'octets_in': octets_in,
        'pkts_in': pkts_in,
        'mcast_in': mcast_in,
        'bcast_in': bcast_in,
        'discards_in': discards_in,
        'errors_in': errors_in,
        'unknown_protos': unknown_protos,
        'octets_out': octets_out,
        'pkts_out': pkts_out,
        'mcast_out': mcast_out,
        'bcast_out': bcast_out,
        'discards_out': discards_out,
        'errors_out': errors_out,
    }


def parse_ethernet_counters(data, offset, end):
    """Parse Ethernet interface counters (enterprise=0, format=2).

    From EtherLike-MIB (RFC 2665). 52 bytes:
      alignment_errors(4), fcs_errors(4), single_collision(4),
      multiple_collision(4), sqe_test_errors(4), deferred_tx(4),
      late_collisions(4), excessive_collisions(4),
      internal_mac_tx_errors(4), carrier_sense_errors(4),
      frame_too_longs(4), internal_mac_rx_errors(4), symbol_errors(4)

    Gold for cable fault detection in OT environments.
    """
    if offset + 52 > end:
        return None

    fields = struct.unpack_from('>IIIIIIIIIIIII', data, offset)
    return {
        'alignment_errors': fields[0],
        'fcs_errors': fields[1],
        'single_collision': fields[2],
        'multiple_collision': fields[3],
        'sqe_test_errors': fields[4],
        'deferred_tx': fields[5],
        'late_collisions': fields[6],
        'excessive_collisions': fields[7],
        'internal_mac_tx_errors': fields[8],
        'carrier_sense_errors': fields[9],
        'frame_too_longs': fields[10],
        'internal_mac_rx_errors': fields[11],
        'symbol_errors': fields[12],
    }


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def load_json_dict(path):
    """Load a user-supplied JSON dictionary file."""
    if not path:
        return None
    with open(path, 'r') as f:
        return json.load(f)


def build_subnet_table(subnet_dict):
    """Pre-parse subnet_dict into (network, data) tuples sorted by prefix
    length descending for longest-prefix match."""
    if not subnet_dict:
        return []
    table = []
    for cidr, info in subnet_dict.items():
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            table.append((net, info))
        except ValueError:
            logging.warning('Invalid CIDR in subnet dict: %s', cidr)
    table.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return table


def subnet_lookup(ip_str, subnet_table):
    """Longest-prefix match for an IP against the subnet table."""
    if not subnet_table or not ip_str:
        return None
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net, info in subnet_table:
        if addr in net:
            return info
    return None


def enrich_flow(parsed_header, ext_switch, vlan_dict, subnet_table):
    """Add decoded names, VLAN/subnet enrichment to a parsed flow."""
    enriched = {}

    # Ethertype
    et = parsed_header.get('ethertype')
    if et is not None:
        enriched['ethertype_name'] = decode_ethertype(et)

    # IP protocol
    proto = parsed_header.get('ip_protocol')
    if proto is not None:
        enriched['protocol_name'] = decode_protocol(proto)

    # Service ports
    src_port = parsed_header.get('src_port')
    dst_port = parsed_header.get('dst_port')
    if src_port is not None:
        enriched['src_service'] = decode_service(src_port)
    if dst_port is not None:
        enriched['dst_service'] = decode_service(dst_port)

    # TCP flags
    flags = parsed_header.get('tcp_flags')
    if flags is not None:
        enriched['tcp_flags_name'] = decode_tcp_flags(flags)

    # ToS
    tos = parsed_header.get('tos')
    if tos is not None:
        enriched['tos_name'] = TOS_VALUES.get(tos, f'0x{tos:02x}')

    # 802.1p VLAN priority — from extended switch or raw 802.1Q TCI
    vlan_pri = None
    if ext_switch:
        vlan_pri = ext_switch.get('src_priority')
    if vlan_pri is None:
        vlan_pri = parsed_header.get('vlan_priority')
    if vlan_pri is not None:
        enriched['vlan_priority'] = vlan_pri
        enriched['vlan_priority_name'] = decode_vlan_priority(vlan_pri)

    # VLAN enrichment — prefer extended switch if available
    vlan = None
    if ext_switch:
        vlan = ext_switch.get('src_vlan')
    if vlan is None:
        vlan = parsed_header.get('vlan')
    enriched['vlan'] = vlan

    if vlan is not None and vlan_dict:
        vlan_info = vlan_dict.get(str(vlan))
        if vlan_info:
            enriched['vlan_name'] = vlan_info.get('name')
            enriched['vlan_purdue'] = vlan_info.get('purdue')

    # Subnet enrichment
    src_ip = parsed_header.get('src_ip')
    dst_ip = parsed_header.get('dst_ip')
    if src_ip:
        src_info = subnet_lookup(src_ip, subnet_table)
        if src_info:
            enriched['src_zone'] = src_info.get('name')
            enriched['src_purdue'] = src_info.get('purdue')
    if dst_ip:
        dst_info = subnet_lookup(dst_ip, subnet_table)
        if dst_info:
            enriched['dst_zone'] = dst_info.get('name')
            enriched['dst_purdue'] = dst_info.get('purdue')

    # Purdue crossing detection
    sp = enriched.get('src_purdue')
    dp = enriched.get('dst_purdue')
    if sp is not None and dp is not None:
        enriched['purdue_crossing'] = abs(sp - dp) > 1

    return enriched


# ---------------------------------------------------------------------------
# Data Model — in-memory state, flushed to JSON periodically
# ---------------------------------------------------------------------------

class SnoopState:
    """Holds all accumulated state from sFlow datagrams."""

    def __init__(self, gateway_prefix=24):
        self.started = now_iso()
        self.updated = None
        self.gateway_prefix = gateway_prefix  # cross-network mask for gateway detection

        # Stats
        self.sflow_datagrams = 0
        self.flow_samples = 0
        self.counter_samples = 0
        self.parse_errors = 0

        # Agent tracking
        self.agents = {}  # ip → {first_seen, last_seen, datagrams, seq}

        # Layer tables
        # FDB: per-agent per-port MAC table (reconstructed from sFlow ingress)
        self.fdb = {}         # agent_ip → {port(str) → {mac → {vlan, ip, first_seen, last_seen, samples}}}
        self.arp_table = {}   # ip → {mac, zone, purdue, first_seen, last_seen, samples}  (site-wide, private only)
        self.gateways = {}    # mac → {ips: set, own_ip: str|None, agent, port, first_seen, last_seen, samples}
        # VLAN: per-vlan per-agent per-port with end devices
        self.vlan_table = {}  # vlan_id(str) → {name, purdue, agents: {ip: {ports: {port: {macs: set, samples}}}}, first_seen}
        self.port_counters = {}  # agent_ip → {ifIndex(str) → counters dict}
        self.port_traffic = {}   # agent_ip → {port(str) → {ethertypes, protocols, services, macs: set, samples}}

    def update_agent(self, agent_ip, seq):
        now = now_iso()
        if agent_ip not in self.agents:
            self.agents[agent_ip] = {
                'first_seen': now, 'last_seen': now,
                'datagrams': 1, 'seq': seq,
            }
        else:
            a = self.agents[agent_ip]
            a['last_seen'] = now
            a['datagrams'] += 1
            a['seq'] = seq

    def update_from_flow(self, agent_ip, sample, vlan_dict, subnet_table):
        """Process a parsed flow sample and update all layer tables."""
        input_port = sample.get('input', 0)
        rate = sample.get('rate', 1)

        # Extract header and extended switch from records
        header = None
        ext_switch = None
        for rec_type, rec_data in sample.get('records', []):
            if rec_type == 'raw_header':
                header = rec_data
            elif rec_type == 'ext_switch':
                ext_switch = rec_data

        if not header:
            return

        enriched = enrich_flow(header, ext_switch, vlan_dict, subnet_table)
        now = now_iso()

        src_mac = header.get('src_mac')
        src_ip = header.get('src_ip')
        dst_ip = header.get('dst_ip')
        vlan = enriched.get('vlan')
        et_name = enriched.get('ethertype_name')
        proto_name = enriched.get('protocol_name')
        dst_service = enriched.get('dst_service')

        # FDB — per-agent per-port MAC table (like show mac-address-table)
        if src_mac and src_mac != '00:00:00:00:00:00':
            if agent_ip not in self.fdb:
                self.fdb[agent_ip] = {}
            port_key = str(input_port)
            if port_key not in self.fdb[agent_ip]:
                self.fdb[agent_ip][port_key] = {}
            fdb_port = self.fdb[agent_ip][port_key]
            if src_mac not in fdb_port:
                fdb_port[src_mac] = {
                    'vlan': vlan, 'ip': src_ip,
                    'first_seen': now, 'last_seen': now,
                    'samples': 1,
                }
            else:
                entry = fdb_port[src_mac]
                entry['last_seen'] = now
                entry['samples'] += 1
                if vlan is not None:
                    entry['vlan'] = vlan
                if src_ip:
                    entry['ip'] = src_ip

        # ARP table — IP→MAC from source (private IPs only, gateways auto-detected)
        if src_ip and src_mac and src_mac != '00:00:00:00:00:00':
            self._update_arp_or_gateway(
                src_ip, src_mac, agent_ip, port_key,
                enriched.get('src_zone'), enriched.get('src_purdue'), now)

        # Also track dst IP→MAC if we see ARP (ethertype 0x0806)
        if header.get('ethertype') == 0x0806 and dst_ip:
            dst_mac = header.get('dst_mac')
            if dst_mac and dst_mac != 'ff:ff:ff:ff:ff:ff':
                self._update_arp_or_gateway(
                    dst_ip, dst_mac, agent_ip, port_key,
                    enriched.get('dst_zone'), enriched.get('dst_purdue'), now)

        # VLAN table — per-vlan per-agent per-port with end device MACs
        if vlan is not None:
            vlan_key = str(vlan)
            if vlan_key not in self.vlan_table:
                self.vlan_table[vlan_key] = {
                    'name': enriched.get('vlan_name'),
                    'purdue': enriched.get('vlan_purdue'),
                    'agents': {},
                    'first_seen': now,
                }
            vt = self.vlan_table[vlan_key]
            if agent_ip not in vt['agents']:
                vt['agents'][agent_ip] = {'ports': {}}
            va = vt['agents'][agent_ip]
            port_key = str(input_port)
            if port_key not in va['ports']:
                va['ports'][port_key] = {'macs': set(), 'samples': 0}
            vp = va['ports'][port_key]
            vp['samples'] += 1
            if src_mac and src_mac != '00:00:00:00:00:00':
                vp['macs'].add(src_mac)

        # Port traffic
        if agent_ip not in self.port_traffic:
            self.port_traffic[agent_ip] = {}
        port_key = str(input_port)
        if port_key not in self.port_traffic[agent_ip]:
            self.port_traffic[agent_ip][port_key] = {
                'ethertypes': {}, 'protocols': {}, 'services': {},
                'macs': set(), 'samples': 0,
            }
        pt = self.port_traffic[agent_ip][port_key]
        pt['samples'] += 1
        if et_name:
            pt['ethertypes'][et_name] = pt['ethertypes'].get(et_name, 0) + 1
        if proto_name:
            pt['protocols'][proto_name] = pt['protocols'].get(proto_name, 0) + 1
        if dst_service:
            pt['services'][dst_service] = pt['services'].get(dst_service, 0) + 1
        if src_mac and src_mac != '00:00:00:00:00:00':
            pt['macs'].add(src_mac)

    def update_from_counters(self, agent_ip, sample):
        """Process a parsed counter sample."""
        if_key = None
        for rec_type, rec_data in sample.get('records', []):
            if rec_type == 'generic':
                if agent_ip not in self.port_counters:
                    self.port_counters[agent_ip] = {}
                if_key = str(rec_data['ifIndex'])
                self.port_counters[agent_ip][if_key] = rec_data
            elif rec_type == 'ethernet':
                # Ethernet counters follow generic in the same sample
                # (same source_id = same ifIndex). Merge into existing entry.
                if agent_ip in self.port_counters and if_key and \
                        if_key in self.port_counters[agent_ip]:
                    self.port_counters[agent_ip][if_key]['ethernet'] = rec_data

    def unique_macs(self):
        macs = set()
        for agent_ports in self.fdb.values():
            for port_macs in agent_ports.values():
                macs.update(port_macs.keys())
        return len(macs)

    def _update_arp_or_gateway(self, ip, mac, agent_ip, port_key,
                               zone, purdue, now):
        """Route an IP→MAC binding to either the ARP table or gateways.

        Four filters (checked in order):
        1. Infrastructure OUI — Hirschmann switch MACs are never end devices
        2. Agent IP xref — sFlow agent IPs are switches, not end devices
        3. Known gateway — already reclassified, accumulate IPs
        4. Multi-IP cross-network — triggers gateway reclassification

        Only private IPs from non-infrastructure, non-agent MACs reach the ARP table.
        """
        # Infrastructure MAC (Hirschmann switch) — skip ARP entirely.
        # These are VRI interfaces, management ports, etc.
        if self._is_infrastructure(mac):
            return

        # Agent IP xref — if this IP belongs to a known sFlow agent,
        # it's a switch management interface, not an end device.
        if ip in self.agents:
            return

        # Already known gateway — just record the IP
        if mac in self.gateways:
            gw = self.gateways[mac]
            gw['ips'].add(ip)
            gw['last_seen'] = now
            gw['samples'] += 1
            gw['agent'] = agent_ip
            gw['port'] = port_key
            # If this is a private IP from the gateway itself, record as own_ip
            if self._is_private(ip) and gw['own_ip'] is None:
                gw['own_ip'] = ip
            return

        # Check if this MAC already exists in ARP with a different IP
        existing_ip = None
        for aip, entry in self.arp_table.items():
            if entry['mac'] == mac and aip != ip:
                existing_ip = aip
                break

        if existing_ip and self._is_cross_network(existing_ip, ip):
            # Reclassify as gateway — move ALL ARP entries for this MAC out
            all_ips = {ip}
            earliest = now
            total_samples = 1
            own_ip = None
            for aip in list(self.arp_table):
                if self.arp_table[aip]['mac'] == mac:
                    entry = self.arp_table.pop(aip)
                    all_ips.add(aip)
                    total_samples += entry['samples']
                    if entry['first_seen'] < earliest:
                        earliest = entry['first_seen']
                    if self._is_private(aip) and own_ip is None:
                        own_ip = aip
            if own_ip is None and self._is_private(ip):
                own_ip = ip
            self.gateways[mac] = {
                'ips': all_ips,
                'own_ip': own_ip,
                'agent': agent_ip,
                'port': port_key,
                'first_seen': earliest,
                'last_seen': now,
                'samples': total_samples,
            }
            return

        # Normal ARP entry — private IPs only
        if not self._is_private(ip):
            return

        if ip not in self.arp_table:
            self.arp_table[ip] = {
                'mac': mac,
                'zone': zone,
                'purdue': purdue,
                'first_seen': now, 'last_seen': now,
                'samples': 1,
            }
        else:
            a = self.arp_table[ip]
            a['mac'] = mac
            a['last_seen'] = now
            a['samples'] += 1
            if zone:
                a['zone'] = zone
            if purdue is not None:
                a['purdue'] = purdue

    @staticmethod
    def _is_infrastructure(mac):
        """Check if a MAC belongs to a known switch OUI (Hirschmann/Belden)."""
        return mac[:8] in INFRASTRUCTURE_OUIS

    @staticmethod
    def _lookup_oui(mac):
        """Return OUI vendor string if known, else None."""
        return INFRASTRUCTURE_OUIS.get(mac[:8])

    @staticmethod
    def _is_private(ip_str):
        """Check if an IP is private/link-local (not public internet)."""
        try:
            addr = ipaddress.ip_address(ip_str)
            return addr.is_private or addr.is_link_local
        except ValueError:
            return False

    def _is_cross_network(self, ip1, ip2):
        """Check if two IPv4 IPs are in different networks.

        Uses self.gateway_prefix (default /24) as the comparison mask.
        Only compares IPv4 to IPv4 — mixed address families (IPv4 + IPv6
        link-local) are dual-stack devices, not gateways.
        """
        try:
            a = ipaddress.ip_address(ip1)
            b = ipaddress.ip_address(ip2)
        except ValueError:
            return False
        # Only compare same address family — dual-stack is not cross-network
        if type(a) != type(b):
            return False
        if isinstance(a, ipaddress.IPv4Address):
            net = ipaddress.ip_network(
                f'{ip1}/{self.gateway_prefix}', strict=False)
            return b not in net
        else:
            # IPv6: compare /48 (site prefix)
            net = ipaddress.ip_network(f'{ip1}/48', strict=False)
            return b not in net

    def unique_ips(self):
        return len(self.arp_table)


# ---------------------------------------------------------------------------
# Output — atomic JSON writes
# ---------------------------------------------------------------------------

def atomic_write(path, data):
    """Write JSON atomically via tmp + rename."""
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2, default=_json_default)
    os.replace(tmp, path)


def _json_default(obj):
    """Handle sets in JSON serialization."""
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f'Not serializable: {type(obj)}')


def write_state(state, output_dir, listen_addr, sflow_port,
                vlan_dict_path, subnet_dict_path):
    path = os.path.join(output_dir, 'state.json')
    elapsed = (datetime.now(timezone.utc) -
               datetime.fromisoformat(state.started)).total_seconds()
    data = {
        'status': 'running',
        'started': state.started,
        'updated': now_iso(),
        'elapsed': round(elapsed, 1),
        'listen': {'sflow': sflow_port},
        'dicts': {
            'vlan': vlan_dict_path,
            'subnet': subnet_dict_path,
        },
        'stats': {
            'sflow_datagrams': state.sflow_datagrams,
            'flow_samples': state.flow_samples,
            'counter_samples': state.counter_samples,
            'parse_errors': state.parse_errors,
            'unique_agents': len(state.agents),
            'unique_macs': state.unique_macs(),
            'unique_ips': state.unique_ips(),
            'gateways': len(state.gateways),
        },
        'agents': state.agents,
    }
    atomic_write(path, data)


def write_agents(state, output_dir):
    agents_dir = os.path.join(output_dir, 'agents')
    os.makedirs(agents_dir, exist_ok=True)
    for ip, info in state.agents.items():
        path = os.path.join(agents_dir, f'{ip}.json')
        data = {
            'agent': ip,
            'updated': now_iso(),
            'info': info,
            'counters': state.port_counters.get(ip, {}),
        }
        atomic_write(path, data)


def write_fdb(state, output_dir):
    """Write per-agent FDB (reconstructed forwarding database) with OUI."""
    path = os.path.join(output_dir, 'layers', 'fdb.json')
    agents = {}
    for agent_ip, ports in state.fdb.items():
        agents[agent_ip] = {}
        for port_key, macs in ports.items():
            agents[agent_ip][port_key] = {}
            for mac, entry in macs.items():
                enriched = dict(entry)
                oui = SnoopState._lookup_oui(mac)
                if oui:
                    enriched['oui'] = oui
                agents[agent_ip][port_key][mac] = enriched
    atomic_write(path, {'updated': now_iso(), 'agents': agents})


def write_arp_table(state, output_dir):
    path = os.path.join(output_dir, 'layers', 'arp_table.json')
    # Enrich entries with OUI
    entries = {}
    for ip, entry in state.arp_table.items():
        enriched = dict(entry)
        oui = SnoopState._lookup_oui(entry['mac'])
        if oui:
            enriched['oui'] = oui
        entries[ip] = enriched
    # Serialize gateways: convert ip sets to sorted lists, add OUI
    gateways = {}
    for mac, gw in state.gateways.items():
        gw_out = {
            'ips': sorted(gw['ips']),
            'own_ip': gw['own_ip'],
            'agent': gw['agent'],
            'port': gw['port'],
            'first_seen': gw['first_seen'],
            'last_seen': gw['last_seen'],
            'samples': gw['samples'],
        }
        oui = SnoopState._lookup_oui(mac)
        if oui:
            gw_out['oui'] = oui
        gateways[mac] = gw_out
    atomic_write(path, {
        'updated': now_iso(),
        'entries': entries,
        'gateways': gateways,
    })


def write_vlan_table(state, output_dir):
    path = os.path.join(output_dir, 'layers', 'vlan_table.json')
    vlans = {}
    for vid, vinfo in state.vlan_table.items():
        agents = {}
        total_macs = set()
        total_samples = 0
        for aip, adata in vinfo['agents'].items():
            ports = {}
            for port_key, pdata in adata['ports'].items():
                mac_list = sorted(pdata['macs'])
                total_macs.update(mac_list)
                total_samples += pdata['samples']
                ports[port_key] = {
                    'macs': mac_list,
                    'samples': pdata['samples'],
                }
            agents[aip] = {'ports': ports}
        vlans[vid] = {
            'name': vinfo['name'],
            'purdue': vinfo['purdue'],
            'agents': agents,
            'mac_count': len(total_macs),
            'samples': total_samples,
            'first_seen': vinfo['first_seen'],
        }
    atomic_write(path, {'updated': now_iso(), 'vlans': vlans})


def write_port_counters(state, output_dir):
    path = os.path.join(output_dir, 'layers', 'port_counters.json')
    atomic_write(path, {
        'updated': now_iso(), 'agents': state.port_counters,
    })


def write_port_traffic(state, output_dir):
    path = os.path.join(output_dir, 'layers', 'port_traffic.json')
    # Convert sets to lists
    agents = {}
    for aip, ports in state.port_traffic.items():
        agents[aip] = {}
        for port_key, pdata in ports.items():
            agents[aip][port_key] = {
                'ethertypes': pdata['ethertypes'],
                'protocols': pdata['protocols'],
                'services': pdata['services'],
                'macs': sorted(pdata['macs']),
                'samples': pdata['samples'],
            }
    atomic_write(path, {'updated': now_iso(), 'agents': agents})


def flush_all(state, output_dir, listen_addr, sflow_port,
              vlan_dict_path, subnet_dict_path):
    """Write all output files."""
    write_state(state, output_dir, listen_addr, sflow_port,
                vlan_dict_path, subnet_dict_path)
    write_agents(state, output_dir)
    write_fdb(state, output_dir)
    write_arp_table(state, output_dir)
    write_vlan_table(state, output_dir)
    write_port_counters(state, output_dir)
    write_port_traffic(state, output_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SNOOP — sFlow Network Observation and Overview Platform'
    )
    parser.add_argument('-l', '--listen', default='0.0.0.0',
                        help='bind address (default: 0.0.0.0)')
    parser.add_argument('--sflow-port', type=int, default=6343,
                        help='sFlow UDP port (default: 6343)')
    parser.add_argument('-o', '--output', default='./output',
                        help='output directory (default: ./output)')
    parser.add_argument('--write-interval', type=int, default=5,
                        help='seconds between disk flushes (default: 5)')
    parser.add_argument('--vlan-dict',
                        help='VLAN enrichment dict JSON')
    parser.add_argument('--subnet-dict',
                        help='subnet/zone enrichment dict JSON')
    parser.add_argument('--gateway-prefix', type=int, default=24,
                        help='prefix length for gateway detection (default: /24)')
    parser.add_argument('--debug', action='store_true',
                        help='debug logging to console')
    parser.add_argument('-s', '--silent', action='store_true',
                        help='suppress console output')
    return parser.parse_args()


def setup_output_dir(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'agents'), exist_ok=True)
    os.makedirs(os.path.join(output_dir, 'layers'), exist_ok=True)


def print_banner(args, vlan_dict, subnet_dict):
    print('\n' + '=' * 60)
    print('  SNOOP \u2014 sFlow Network Observation and Overview Platform')
    print('=' * 60)
    print(f'  Listening: sFlow on {args.listen}:{args.sflow_port}')
    dicts_parts = []
    if vlan_dict:
        dicts_parts.append(
            f'{args.vlan_dict} ({len(vlan_dict)} VLANs)')
    if subnet_dict:
        dicts_parts.append(
            f'{args.subnet_dict} ({len(subnet_dict)} subnets)')
    if dicts_parts:
        print(f'  Dicts: {", ".join(dicts_parts)}')
    else:
        print('  Dicts: none')
    print(f'  Output: {args.output}/')
    print('-' * 60)


def print_stats_line(state, elapsed):
    print(f'  [{elapsed:4.0f}s] dgrams: {state.sflow_datagrams:5d}'
          f' | flows: {state.flow_samples:5d}'
          f' | cntrs: {state.counter_samples:4d}'
          f' | agents: {len(state.agents)}'
          f' | MACs: {state.unique_macs()}'
          f' | IPs: {state.unique_ips()}'
          f' | GWs: {len(state.gateways)}')


def print_footer(state, elapsed, output_dir):
    # Count output files
    file_count = 0
    for root, dirs, files in os.walk(output_dir):
        file_count += len([f for f in files if f.endswith('.json')])
    print('\n' + '=' * 60)
    print(f'  Session: {elapsed:.1f}s'
          f' | {state.sflow_datagrams} datagrams'
          f' | {len(state.agents)} agents'
          f' | {state.unique_macs()} MACs'
          f' | {state.unique_ips()} IPs'
          f' | {len(state.gateways)} GWs')
    print(f'  Output: {output_dir}/ ({file_count} files written)')
    print('=' * 60 + '\n')


def main():
    args = parse_arguments()

    # Logging
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(levelname)s %(message)s',
    )

    # Silent mode
    if args.silent:
        sys.stdout = open(os.devnull, 'w')

    # Load optional dicts
    vlan_dict = None
    subnet_dict = None
    subnet_table = []

    if args.vlan_dict:
        vlan_dict = load_json_dict(args.vlan_dict)
        logging.info('Loaded VLAN dict: %d entries', len(vlan_dict))
    if args.subnet_dict:
        subnet_dict = load_json_dict(args.subnet_dict)
        subnet_table = build_subnet_table(subnet_dict)
        logging.info('Loaded subnet dict: %d entries', len(subnet_dict))

    # Output dirs
    setup_output_dir(args.output)

    # State
    state = SnoopState(gateway_prefix=args.gateway_prefix)

    # Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.listen, args.sflow_port))
    sock.settimeout(1.0)

    print_banner(args, vlan_dict, subnet_dict)

    start_time = time.monotonic()
    last_flush = start_time
    last_print = start_time

    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                # Check if we need to flush
                now = time.monotonic()
                if now - last_flush >= args.write_interval:
                    flush_all(state, args.output, args.listen,
                              args.sflow_port, args.vlan_dict,
                              args.subnet_dict)
                    last_flush = now
                if now - last_print >= args.write_interval:
                    elapsed = now - start_time
                    print_stats_line(state, elapsed)
                    last_print = now
                continue

            # Parse datagram
            result = parse_datagram(data)
            if result is None:
                state.parse_errors += 1
                logging.debug('Parse error from %s', addr)
                continue

            state.sflow_datagrams += 1
            agent_ip = result['agent']
            state.update_agent(agent_ip, result['seq'])

            # Process flow samples
            for sample in result['flow_samples']:
                state.flow_samples += 1
                state.update_from_flow(
                    agent_ip, sample, vlan_dict, subnet_table)

            # Process counter samples
            for sample in result['counter_samples']:
                state.counter_samples += 1
                state.update_from_counters(agent_ip, sample)

            # Periodic flush + console
            now = time.monotonic()
            if now - last_flush >= args.write_interval:
                flush_all(state, args.output, args.listen,
                          args.sflow_port, args.vlan_dict,
                          args.subnet_dict)
                last_flush = now
            if now - last_print >= args.write_interval:
                elapsed = now - start_time
                print_stats_line(state, elapsed)
                last_print = now

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        # Final flush
        flush_all(state, args.output, args.listen,
                  args.sflow_port, args.vlan_dict, args.subnet_dict)
        # Mark state as complete
        state_path = os.path.join(args.output, 'state.json')
        with open(state_path, 'r') as f:
            state_data = json.load(f)
        state_data['status'] = 'complete'
        atomic_write(state_path, state_data)

        elapsed = time.monotonic() - start_time
        print_footer(state, elapsed, args.output)


if __name__ == '__main__':
    main()
