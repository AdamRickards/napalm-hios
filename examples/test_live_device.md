# HIOS Driver Live Device Test Results
Test run on: 2024-10-09 23:32:44
Device: 192.168.1.254
Ping Destination: 192.168.3.1
Ping Count: 5
## Protocol Test Results
### SSH
Connection Status: ✓ Connected

Method Results:

#### ✓ get_facts (Duration: 0.08s)
```json
{
  "vendor": "Belden",
  "uptime": "12 days, 07:31:03",
  "os_version": "HiOS-3A-09.4.04",
  "model": "GRS1042-6T6ZTHH00V9HHSE3AMR",
  "serial_number": "942135999000101022"
}
```

#### ✓ get_interfaces (Duration: 0.18s)
```json
{
  "1/1": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 2500000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/2": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 2500000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/3": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/4": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/5": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 2500000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/6": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 2500000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/7": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/8": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 10000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/9": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/10": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/11": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "1/12": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/1": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/2": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/3": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/4": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/5": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/6": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/7": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 100000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "2/8": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/1": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/2": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/3": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 1000000000,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/4": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/5": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/6": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/7": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "3/8": {
    "is_up": false,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1518,
    "mac_address": ""
  },
  "vlan/1": {
    "is_up": true,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1500,
    "mac_address": ""
  },
  "vlan/2": {
    "is_up": true,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1500,
    "mac_address": ""
  },
  "vlan/3": {
    "is_up": true,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1500,
    "mac_address": ""
  },
  "vlan/6": {
    "is_up": true,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1500,
    "mac_address": ""
  },
  "vlan/9": {
    "is_up": true,
    "is_enabled": true,
    "description": "",
    "last_flapped": -1.0,
    "speed": 0,
    "mtu": 1500,
    "mac_address": ""
  }
}
```

#### ✓ get_snmp_information (Duration: 0.08s)
```json
{
  "chassis_id": "SSH-CHASSIS-ID",
  "contact": "admin@example.com",
  "location": "SSH Lab",
  "community": {
    "public": "read-only",
    "private": "read-write"
  }
}
```

#### ✓ get_environment (Duration: 0.3s)
```json
{
  "fans": {
    "Error": {
      "status": false
    }
  },
  "temperature": {
    "temperature": 47.0,
    "is_alert": false,
    "is_critical": false
  },
  "power": {
    "status": true
  },
  "cpu": {
    "usage": 23.0
  },
  "memory": {
    "available_ram": 150592,
    "used_ram": 206328
  }
}
```

#### ✓ get_arp_table (Duration: 0.15s)
```json
[
  {
    "interface": "cpu/1",
    "ip": "0.0.0.0",
    "mac": "ec:74:ba:35:75:70",
    "age": 0.0
  }
]
```

#### ✓ get_config (Duration: 3.23s)
```json
{
  "running": "! GRS1042-6T6Z Configuration\n\n! Version: HiOS-3A-09.4.04\n\n! Build Date: 2024-06-19 12:08\n\nnetwork hidiscovery mode read-only \nnetwork management access web timeout 0 \nnetwork out-of-band parms 192.168.199.2 255.255.255.0 192.168.199.1 \nnetwork out-of-band protocol none \nno network out-of-band operation \nnetwork management access add 2 \nnetwork management access modify 2 ip 192.168.4.3 \nnetwork management access modify 2 mask 24 \n\nvlan database\nvlan add 2\nvlan add 3\nvlan add 4\nvlan add 5\nvlan add 6\nvlan add 7\nvlan add 9\nvlan add 10\nname 1 HOME \nname 2 WLAN \nname 3 ADAM \nname 4 CABLE \nname 5 DSL \nname 6 ROUTER \nname 7 FTTH \nname 9 WORK \nname 10 DEMO \nrouting add 1 \nrouting add 2 \nrouting add 3 \nrouting add 6 \nrouting add 9 \nigmp-snooping vlan-id 1 fast-leave \nigmp-snooping vlan-id 3 fast-leave \nigmp-snooping vlan-id 1 mode \nigmp-snooping vlan-id 3 mode \nigmp-snooping vlan-id 1 querier address 192.168.1.254 \nigmp-snooping vlan-id 1 querier mode \nvlan protocol group add 1 name \"\" vlan-id 0\nexit\nnetwork parms 0.0.0.0 0.0.0.0 0.0.0.0 \nnetwork protocol none \nno network ipv6 operation \nnetwork ipv6 protocol none \n! dot1x mac-authentication-bypass password  \"\"\nconfigure\ndevice-status monitor power-supply 2 disable \ndhcp-server operation \ndhcp-server pool add 1 dynamic 192.168.1.105 192.168.1.200 \ndhcp-server pool add 2 dynamic 192.168.10.100 192.168.10.200 \ndhcp-server pool add 3 dynamic 192.168.4.3 192.168.4.10 \ndhcp-server pool add 4 dynamic 192.168.9.100 192.168.9.200 \ndhcp-server pool modify 1 option dns 192.168.3.1 \ndhcp-server pool modify 2 option dns 192.168.3.1 \ndhcp-server pool modify 3 option dns 192.168.3.1 \ndhcp-server pool modify 4 option dns 192.168.3.1 \ndhcp-server pool modify 1 option gateway 192.168.1.254 \ndhcp-server pool modify 2 option gateway 192.168.10.254 \ndhcp-server pool modify 3 option gateway 192.168.4.254 \ndhcp-server pool modify 4 option gateway 192.168.9.254 \ndhcp-server pool modify 1 mode vlan 1 \ndhcp-server pool modify 2 mode vlan 2 \ndhcp-server pool modify 3 mode vlan 3 \ndhcp-server pool modify 4 mode vlan 9 \ndhcp-server pool mode 1 enable\ndhcp-server pool mode 2 enable\ndhcp-server pool mode 3 enable\ndhcp-server pool mode 4 enable\ndns cache adminstate \ndns client adminstate \ndns client servers add 1 ip 192.168.3.1 \ndns client source user \nclock summer-time mode recurring \nclock summer-time recurring start first wed jul 12:00 \nclock summer-time recurring end first thu aug 12:00 \nclock timezone offset 600 \nconfig remote-backup destination tftp://192.168.4.3/%p/config-%d.xml \n! config remote-backup username ****** \n! config remote-backup password ****** \nno http server \nigmp-snooping mode \nigmp-snooping querier mode \nsignal-contact 1 mode device-status \nlogging host add 1 addr 192.168.4.3 transport udp port 514 severity informational type systemlog \nlogging syslog operation \nip routing \nip default-route add 192.168.3.1\npasswords min-length 5 \npasswords min-numeric-chars 0 \npasswords min-special-chars 0 \npasswords min-uppercase-chars 0 \nptp v2-boundary-clock utc-offset 36 \nptp v2-transparent-clock vlan-priority 4 \nno security-status monitor hidisc-enabled \nno security-status monitor extnvm-load-unsecure \nno security-status monitor iec61850-mms-enabled \nno security-status monitor modbus-tcp-enabled \nno security-status monitor ethernet-ip-enabled \nno security-status monitor profinet-io-enabled \nno security-status monitor https-certificate \nno security-status monitor pwd-change \nno security-status monitor pwd-min-length \nno security-status monitor pwd-policy-config \nsntp client server add 1 192.168.3.1 port 123 description \"Pool NTP\" \nsntp client server mode 1 enable \nsntp client operation \nsntp server operation \nno spanning-tree operation \nsystem contact \"Adam Rickards 0472827169\" \nsystem location Kitchen \nsystem name GRS1042-CORE \n\nip ospf router-id 192.168.1.254 \nip ospf default-info originate enable always enable \nip ospf re-distribute connected enable \nip ospf re-distribute static enable \nsnmp trap add \"hivision\" 192.168.4.3:162\nip access-list extended name test index 1 permit every \n\ninterface 1/1\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan tagging 1\nvlan participation include 2\nvlan tagging 2\nvlan participation include 3\nvlan tagging 3\nvlan participation include 4\nvlan tagging 4\nvlan participation include 5\nvlan tagging 5\nvlan participation include 6\nvlan tagging 6\nvlan participation include 7\nvlan tagging 7\nvlan participation include 9\nvlan tagging 9\nvlan participation include 10\nvlan tagging 10\nexit\n\ninterface 1/2\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation include 10\nvlan tagging 10\nexit\n\ninterface 1/3\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 7\nvlan pvid 7 \nexit\n\ninterface 1/4\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 6\nvlan pvid 6 \nexit\n\ninterface 1/5\nno dhcp-server operation \nport-monitor condition speed-duplex speed fdx-1000 fdx-2500  \nptp v2-boundary-clock vlan-priority 4 \nvlan participation include 6\nvlan pvid 6 \nexit\n\ninterface 1/6\nno dhcp-server operation \nport-monitor condition speed-duplex speed fdx-1000 fdx-2500  \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 1/7\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan tagging 1\nvlan participation include 2\nvlan tagging 2\nvlan participation include 3\nvlan tagging 3\nvlan participation include 4\nvlan tagging 4\nvlan participation include 5\nvlan tagging 5\nvlan participation include 6\nvlan tagging 6\nvlan participation include 7\nvlan tagging 7\nvlan participation include 9\nvlan tagging 9\nvlan participation include 10\nvlan tagging 10\nexit\n\ninterface 1/8\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 1/9\nno auto-negotiate\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 1/10\nno auto-negotiate\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 1/11\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 4\nvlan pvid 4 \nexit\n\ninterface 1/12\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 5\nvlan pvid 5 \nexit\n\ninterface 2/1\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 2/2\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 2/3\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 2/4\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 2/5\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 2/6\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 2/7\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nno spanning-tree mode \nvlan participation auto 1\nvlan participation include 2\nvlan participation include 3\nvlan pvid 2 \nexit\n\ninterface 2/8\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation auto 1\nvlan participation include 2\nvlan pvid 2 \nexit\n\ninterface 3/1\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation include 3\nvlan pvid 3 \nexit\n\ninterface 3/2\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 3/3\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 3/4\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 3/5\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nexit\n\ninterface 3/6\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation include 3\nexit\n\ninterface 3/7\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation include 3\nexit\n\ninterface 3/8\ncable-crossing auto-mdix\nno dhcp-server operation \nptp v2-boundary-clock vlan-priority 4 \nvlan participation include 3\nexit\n\ninterface vlan/1\nip routing \nip address primary 192.168.1.254 255.255.255.0 \nno ip proxy-arp operation \nno ip irdp operation \nip irdp address 224.0.0.1 \nip irdp holdtime 1800 \nip irdp maxadvertinterval 600 \nip irdp minadvertinterval 450 \nip irdp preference 0 \nip ospf area-id 0.0.0.0 \nip ospf operation \nip ospf link-type broadcast \nip ospf priority 1 \nip ospf transmit-delay 1 \nip ospf retransmit-interval 5 \nip ospf hello-interval 10 \nip ospf dead-interval 40 \nip ospf cost auto \nno ip ospf mtu-ignore \nip ospf authentication type none \nip ospf authentication key-id 0 \nno ip ospf fast-hello \nip rip authentication type none \nip rip authentication key-id 0 \nip rip send-version ripv2 \nip rip receive-version both \nno ip igmp operation \nip igmp querier query-interval 125 \nip igmp version 3 \nip igmp robustness 2 \nip igmp querier last-member-interval 10 \nip igmp querier max-response-time 100 \nip mcast ttl-threshold 1 \nip icmp unreachables \nip icmp redirects \nip mtu 1500 \nno ip netdirbcast \nno signal-contact 1 link-alarm \nno device-status link-alarm \nno shutdown \nname \"\" \nno security-status no-link \nexit\n\ninterface vlan/2\nip routing \nip address primary 192.168.10.254 255.255.255.0 \nno ip proxy-arp operation \nno ip irdp operation \nip irdp address 224.0.0.1 \nip irdp holdtime 1800 \nip irdp maxadvertinterval 600 \nip irdp minadvertinterval 450 \nip irdp preference 0 \nip ospf area-id 0.0.0.0 \nno ip ospf operation \nip ospf link-type broadcast \nip ospf priority 1 \nip ospf transmit-delay 1 \nip ospf retransmit-interval 5 \nip ospf hello-interval 10 \nip ospf dead-interval 40 \nip ospf cost auto \nno ip ospf mtu-ignore \nip ospf authentication type none \nip ospf authentication key-id 0 \nno ip ospf fast-hello \nip rip authentication type none \nip rip authentication key-id 0 \nip rip send-version ripv2 \nip rip receive-version both \nno ip igmp operation \nip igmp querier query-interval 125 \nip igmp version 3 \nip igmp robustness 2 \nip igmp querier last-member-interval 10 \nip igmp querier max-response-time 100 \nip mcast ttl-threshold 1 \nip icmp unreachables \nip icmp redirects \nip mtu 1500 \nno ip netdirbcast \nno signal-contact 1 link-alarm \nno device-status link-alarm \nno shutdown \nname \"\" \nno security-status no-link \nexit\n\ninterface vlan/3\nip routing \nip address primary 192.168.4.254 255.255.255.0 \nno ip proxy-arp operation \nno ip irdp operation \nip irdp address 224.0.0.1 \nip irdp holdtime 1800 \nip irdp maxadvertinterval 600 \nip irdp minadvertinterval 450 \nip irdp preference 0 \nip ospf area-id 0.0.0.0 \nno ip ospf operation \nip ospf link-type broadcast \nip ospf priority 1 \nip ospf transmit-delay 1 \nip ospf retransmit-interval 5 \nip ospf hello-interval 10 \nip ospf dead-interval 40 \nip ospf cost auto \nno ip ospf mtu-ignore \nip ospf authentication type none \nip ospf authentication key-id 0 \nno ip ospf fast-hello \nip rip authentication type none \nip rip authentication key-id 0 \nip rip send-version ripv2 \nip rip receive-version both \nno ip igmp operation \nip igmp querier query-interval 125 \nip igmp version 3 \nip igmp robustness 2 \nip igmp querier last-member-interval 10 \nip igmp querier max-response-time 100 \nip mcast ttl-threshold 1 \nip icmp unreachables \nip icmp redirects \nip mtu 1500 \nno ip netdirbcast \nno signal-contact 1 link-alarm \nno device-status link-alarm \nno shutdown \nname \"\" \nno security-status no-link \nexit\n\ninterface vlan/6\nip routing \nip address primary 192.168.3.254 255.255.255.0 \nno ip proxy-arp operation \nno ip irdp operation \nip irdp address 224.0.0.1 \nip irdp holdtime 1800 \nip irdp maxadvertinterval 600 \nip irdp minadvertinterval 450 \nip irdp preference 0 \nip ospf area-id 0.0.0.0 \nip ospf operation \nip ospf link-type broadcast \nip ospf priority 1 \nip ospf transmit-delay 1 \nip ospf retransmit-interval 5 \nip ospf hello-interval 10 \nip ospf dead-interval 40 \nip ospf cost auto \nno ip ospf mtu-ignore \nip ospf authentication type none \nip ospf authentication key-id 0 \nno ip ospf fast-hello \nip rip authentication type none \nip rip authentication key-id 0 \nip rip send-version ripv2 \nip rip receive-version both \nno ip igmp operation \nip igmp querier query-interval 125 \nip igmp version 3 \nip igmp robustness 2 \nip igmp querier last-member-interval 10 \nip igmp querier max-response-time 100 \nip mcast ttl-threshold 1 \nip icmp unreachables \nip icmp redirects \nip mtu 1500 \nno ip netdirbcast \nno signal-contact 1 link-alarm \nno device-status link-alarm \nno shutdown \nname \"\" \nno security-status no-link \nexit\n\ninterface vlan/9\nip routing \nip address primary 192.168.9.254 255.255.255.0 \nno ip proxy-arp operation \nno ip irdp operation \nip irdp address 224.0.0.1 \nip irdp holdtime 1800 \nip irdp maxadvertinterval 600 \nip irdp minadvertinterval 450 \nip irdp preference 0 \nip ospf area-id 0.0.0.0 \nno ip ospf operation \nip ospf link-type broadcast \nip ospf priority 1 \nip ospf transmit-delay 1 \nip ospf retransmit-interval 5 \nip ospf hello-interval 10 \nip ospf dead-interval 40 \nip ospf cost auto \nno ip ospf mtu-ignore \nip ospf authentication type none \nip ospf authentication key-id 0 \nno ip ospf fast-hello \nip rip authentication type none \nip rip authentication key-id 0 \nip rip send-version ripv2 \nip rip receive-version both \nno ip igmp operation \nip igmp querier query-interval 125 \nip igmp version 3 \nip igmp robustness 2 \nip igmp querier last-member-interval 10 \nip igmp querier max-response-time 100 \nip mcast ttl-threshold 1 \nip icmp unreachables \nip icmp redirects \nip mtu 1500 \nno ip netdirbcast \nno signal-contact 1 link-alarm \nno device-status link-alarm \nno shutdown \nname \"\" \nno security-status no-link \nexit\n\nusers add \"snmpuser\"\nusers add \"user\"\n! users password snmpuser \"********\"\n! users password user \"********\"\nusers enable snmpuser \nusers enable user \nauthlists add LoginWeb \nauthlists set-policy LoginWeb local reject reject reject reject \nappllists set-authlist WebInterface LoginWeb \nopc-ua operation enable \nopc-ua security-policy basic256 \nopc-ua users add opctest \nopc-ua users enable opctest \n! opc-ua users modify opctest password ******** \nmodbus-tcp operation \nno modbus-tcp write-access \nexit",
  "candidate": "",
  "startup": ""
}
```

#### ✓ get_interfaces_counters (Duration: 0.09s)
```json
{
  "1/1": {
    "rx_unicast_packets": 1358611135,
    "rx_multicast_packets": 629480,
    "rx_broadcast_packets": 26574,
    "rx_octets": 242339760,
    "rx_discards": 2501,
    "rx_errors": 0,
    "tx_unicast_packets": 1008406913,
    "tx_multicast_packets": 541987,
    "tx_broadcast_packets": 498466,
    "tx_octets": 1579498827,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "1/2": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "1/3": {
    "rx_unicast_packets": 415282397,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 892,
    "rx_octets": 2592475719,
    "rx_discards": 132,
    "rx_errors": 0,
    "tx_unicast_packets": 1094182201,
    "tx_multicast_packets": 35449,
    "tx_broadcast_packets": 1,
    "tx_octets": 2808691797,
    "tx_discards": 393289,
    "tx_errors": 0
  },
  "1/4": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 35443,
    "tx_broadcast_packets": 92,
    "tx_octets": 13260640,
    "tx_discards": 393289,
    "tx_errors": 0
  },
  "1/5": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "1/6": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "1/7": {
    "rx_unicast_packets": 1219718930,
    "rx_multicast_packets": 380681,
    "rx_broadcast_packets": 369613,
    "rx_octets": 940138946,
    "rx_discards": 896,
    "rx_errors": 0,
    "tx_unicast_packets": 745241578,
    "tx_multicast_packets": 934531,
    "tx_broadcast_packets": 155719,
    "tx_octets": 2256023705,
    "tx_discards": 1206,
    "tx_errors": 0
  },
  "1/8": {
    "rx_unicast_packets": 11403637,
    "rx_multicast_packets": 21172,
    "rx_broadcast_packets": 1714,
    "rx_octets": 1910596250,
    "rx_discards": 477,
    "rx_errors": 0,
    "tx_unicast_packets": 40759637,
    "tx_multicast_packets": 1147865,
    "tx_broadcast_packets": 498551,
    "tx_octets": 4140739506,
    "tx_discards": 92563,
    "tx_errors": 0
  },
  "1/9": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "1/10": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "1/11": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 35439,
    "tx_broadcast_packets": 0,
    "tx_octets": 12793182,
    "tx_discards": 393289,
    "tx_errors": 0
  },
  "1/12": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 35439,
    "tx_broadcast_packets": 0,
    "tx_octets": 12793182,
    "tx_discards": 393289,
    "tx_errors": 0
  },
  "2/1": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "2/2": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "2/3": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "2/4": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "2/5": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "2/6": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "2/7": {
    "rx_unicast_packets": 55865,
    "rx_multicast_packets": 17729,
    "rx_broadcast_packets": 17730,
    "rx_octets": 7958473,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 22641,
    "tx_multicast_packets": 39562,
    "tx_broadcast_packets": 207,
    "tx_octets": 16272820,
    "tx_discards": 393289,
    "tx_errors": 0
  },
  "2/8": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/1": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/2": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/3": {
    "rx_unicast_packets": 44487881,
    "rx_multicast_packets": 344577,
    "rx_broadcast_packets": 105787,
    "rx_octets": 2165486705,
    "rx_discards": 10013,
    "rx_errors": 0,
    "tx_unicast_packets": 162166068,
    "tx_multicast_packets": 929235,
    "tx_broadcast_packets": 394567,
    "tx_octets": 4097488769,
    "tx_discards": 1120,
    "tx_errors": 0
  },
  "3/4": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/5": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/6": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/7": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  },
  "3/8": {
    "rx_unicast_packets": 0,
    "rx_multicast_packets": 0,
    "rx_broadcast_packets": 0,
    "rx_octets": 0,
    "rx_discards": 0,
    "rx_errors": 0,
    "tx_unicast_packets": 0,
    "tx_multicast_packets": 0,
    "tx_broadcast_packets": 0,
    "tx_octets": 0,
    "tx_discards": 0,
    "tx_errors": 0
  }
}
```

#### ✓ get_interfaces_ip (Duration: 0.08s)
```json
{
  "vlan/1": {
    "ipv4": {
      "192.168.1.254": {
        "prefix_length": 24
      }
    }
  },
  "vlan/2": {
    "ipv4": {
      "192.168.10.254": {
        "prefix_length": 24
      }
    }
  },
  "vlan/3": {
    "ipv4": {
      "192.168.4.254": {
        "prefix_length": 24
      }
    }
  },
  "vlan/6": {
    "ipv4": {
      "192.168.3.254": {
        "prefix_length": 24
      }
    }
  },
  "vlan/9": {
    "ipv4": {
      "192.168.9.254": {
        "prefix_length": 24
      }
    }
  }
}
```

#### ✓ get_lldp_neighbors (Duration: 0.08s)
```json
{
  "1/7": [
    {
      "hostname": "BRS50-LOUNGE",
      "port": "Module: 1 Port: 5 - 1 Gbit"
    }
  ],
  "3/3": [
    {
      "hostname": "eero",
      "port": "eth1"
    }
  ],
  "1/1": [
    {
      "hostname": "BRS50-Office",
      "port": "Module: 1 Port: 1 - 2.5 Gbit"
    }
  ]
}
```

#### ✓ get_lldp_neighbors_detail (Duration: 0.09s)
```json
{
  "2/7": [
    {
      "parent_interface": "",
      "remote_port": "FDB",
      "remote_port_description": "",
      "remote_chassis_id": "00:0C:42:04:7C:74",
      "remote_system_name": "",
      "remote_system_description": "",
      "remote_system_capab": [],
      "remote_system_enable_capab": []
    }
  ],
  "1/7": [
    {
      "parent_interface": "",
      "remote_port": "64:60:38:3F:4A:EA",
      "remote_port_description": "Module: 1 Port: 5 - 1 Gbit",
      "remote_chassis_id": "64:60:38:3F:4A:E1",
      "remote_system_name": "BRS50-LOUNGE",
      "remote_system_description": "Hirschmann BOBCAT - SW: HiOS-2A-09.4.00",
      "remote_system_capab": [],
      "remote_system_enable_capab": []
    }
  ],
  "3/3": [
    {
      "parent_interface": "",
      "remote_port": "1",
      "remote_port_description": "eth1",
      "remote_chassis_id": "50:27:A9:04:EE:60",
      "remote_system_name": "eero",
      "remote_system_description": "eero 6+ GGC1UCD124550L9A",
      "remote_system_capab": [],
      "remote_system_enable_capab": []
    }
  ],
  "1/1": [
    {
      "parent_interface": "",
      "remote_port": "64:60:38:3F:4A:A6",
      "remote_port_description": "Module: 1 Port: 1 - 2.5 Gbit",
      "remote_chassis_id": "64:60:38:3F:4A:A1",
      "remote_system_name": "BRS50-Office",
      "remote_system_description": "Hirschmann BOBCAT - SW: HiOS-2A-10.0.00",
      "remote_system_capab": [],
      "remote_system_enable_capab": []
    }
  ],
  "1/3": [
    {
      "parent_interface": "",
      "remote_port": "FDB",
      "remote_port_description": "",
      "remote_chassis_id": "90:EC:77:1B:6C:2B",
      "remote_system_name": "",
      "remote_system_description": "",
      "remote_system_capab": [],
      "remote_system_enable_capab": []
    }
  ]
}
```

#### ✓ get_mac_address_table (Duration: 0.08s)
```json
[
  {
    "mac": "12:dd:6e:60:34:4b",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "3a:2b:cf:6a:18:78",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "3c:a6:f6:22:59:05",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "50:27:a9:04:ee:61",
    "interface": "3/3",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "50:27:a9:04:ee:6d",
    "interface": "3/3",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "50:27:a9:05:fd:cd",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "50:27:a9:06:0c:cd",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "64:60:38:3f:4a:a1",
    "interface": "1/1",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "64:60:38:3f:4a:a6",
    "interface": "1/1",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "64:60:38:3f:4a:e1",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "64:60:38:3f:4a:ea",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "64:60:38:8a:42:d0",
    "interface": "1/1",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "74:d4:23:d7:fa:41",
    "interface": "3/3",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "84:e3:42:41:d7:dc",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "96:aa:c2:ff:de:7c",
    "interface": "3/3",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "a0:b0:86:f4:e9:bf",
    "interface": "1/1",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "b4:f7:a1:e8:49:82",
    "interface": "3/3",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "c2:09:c3:1e:28:45",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "c8:7f:54:0a:a1:39",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "d0:73:d5:03:4b:7d",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "da:33:e8:48:d2:69",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "dc:68:eb:bd:73:7f",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "ec:74:ba:35:75:70",
    "interface": "cpu/1",
    "vlan": 1,
    "static": true,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "ec:74:ba:35:75:99",
    "interface": "vlan/1",
    "vlan": 1,
    "static": true,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "fa:1c:17:71:99:99",
    "interface": "1/7",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "fa:d5:f5:9e:72:5b",
    "interface": "3/3",
    "vlan": 1,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "00:0c:42:04:7c:74",
    "interface": "2/7",
    "vlan": 2,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "ec:74:ba:35:75:9a",
    "interface": "vlan/2",
    "vlan": 2,
    "static": true,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "b4:2e:99:0e:39:fb",
    "interface": "1/1",
    "vlan": 3,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "ec:74:ba:35:75:9b",
    "interface": "vlan/3",
    "vlan": 3,
    "static": true,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "90:ec:77:1b:6c:26",
    "interface": "1/1",
    "vlan": 6,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "ec:74:ba:35:75:9c",
    "interface": "vlan/6",
    "vlan": 6,
    "static": true,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "00:a2:00:b2:00:c2",
    "interface": "1/7",
    "vlan": 7,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "90:ec:77:1b:6c:2b",
    "interface": "1/3",
    "vlan": 7,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "e4:b9:7a:fa:39:f6",
    "interface": "1/1",
    "vlan": 9,
    "static": false,
    "active": true,
    "moves": null,
    "last_move": null
  },
  {
    "mac": "ec:74:ba:35:75:9d",
    "interface": "vlan/9",
    "vlan": 9,
    "static": true,
    "active": true,
    "moves": null,
    "last_move": null
  }
]
```

#### ✓ get_ntp_servers (Duration: 0.15s)
```json
{
  "192.168.3.1": {}
}
```

#### ✓ get_ntp_stats (Duration: 0.15s)
```json
[
  {
    "remote": "192.168.3.1",
    "referenceid": "",
    "synchronized": true,
    "stratum": 0,
    "type": "ipv4",
    "when": "",
    "hostpoll": 30,
    "reachability": 0,
    "delay": 0.0,
    "offset": 0.0,
    "jitter": 0.0
  }
]
```

#### ✓ get_optics (Duration: 0.08s)
```json
{
  "1/1": {
    "physical_channels": {
      "channel": [
        {
          "index": 0,
          "state": {
            "input_power": {
              "instant": -4.4,
              "avg": 0.0,
              "min": 0.0,
              "max": 0.0
            },
            "output_power": {
              "instant": -4.2,
              "avg": 0.0,
              "min": 0.0,
              "max": 0.0
            },
            "laser_bias_current": {
              "instant": 0.0,
              "avg": 0.0,
              "min": 0.0,
              "max": 0.0
            }
          }
        }
      ]
    }
  }
}
```

#### ✓ get_users (Duration: 0.08s)
```json
{
  "admin": {
    "level": 15,
    "password": "",
    "sshkeys": []
  },
  "snmpuser": {
    "level": 1,
    "password": "",
    "sshkeys": []
  },
  "user": {
    "level": 1,
    "password": "",
    "sshkeys": []
  }
}
```

#### ✓ get_vlans (Duration: 0.15s)
```json
{
  "1": {
    "name": "HOME",
    "interfaces": [
      "1/1",
      "1/2",
      "1/6",
      "1/7",
      "1/8",
      "1/9",
      "1/10",
      "3/2",
      "3/3",
      "3/4",
      "3/5",
      "3/6",
      "3/7",
      "3/8"
    ]
  },
  "2": {
    "name": "WLAN",
    "interfaces": [
      "2/1",
      "2/2",
      "2/3",
      "2/4",
      "2/5",
      "2/6",
      "2/7",
      "2/8"
    ]
  },
  "3": {
    "name": "ADAM",
    "interfaces": [
      "3/1"
    ]
  },
  "4": {
    "name": "CABLE",
    "interfaces": [
      "1/11"
    ]
  },
  "5": {
    "name": "DSL",
    "interfaces": [
      "1/12"
    ]
  },
  "6": {
    "name": "ROUTER",
    "interfaces": [
      "1/4",
      "1/5"
    ]
  },
  "7": {
    "name": "FTTH",
    "interfaces": [
      "1/3"
    ]
  },
  "9": {
    "name": "WORK",
    "interfaces": []
  },
  "10": {
    "name": "DEMO",
    "interfaces": []
  }
}
```

#### ✓ ping (Duration: 3.16s)
```json
{
  "success": {
    "probes_sent": 3,
    "packet_loss": 0.0,
    "rtt_min": 0.741,
    "rtt_max": 0.923,
    "rtt_avg": 0.804,
    "rtt_stddev": 0.0,
    "results": [
      {
        "ip_address": "192.168.3.1",
        "rtt": 0.75
      }
    ]
  }
}
```
#### ✓ get_lldp_neighbors_detail_extended (Duration: 0.09s)
```json
{
  "2/7": [
    {
      "parent_interface": "2/7",
      "remote_port": "FDB",
      "remote_port_description": "",
      "remote_chassis_id": "00:0C:42:04:7C:74",
      "remote_system_name": "",
      "remote_system_description": "",
      "remote_system_capab": [],
      "remote_system_enable_capab": [],
      "remote_management_ipv4": "",
      "remote_management_ipv6": "",
      "autoneg_support": "",
      "autoneg_enabled": "",
      "port_oper_mau_type": "",
      "port_vlan_id": "",
      "vlan_membership": [],
      "link_agg_status": "",
      "link_agg_port_id": ""
    }
  ],
  "1/7": [
    {
      "parent_interface": "1/7",
      "remote_port": "64:60:38:3F:4A:EA",
      "remote_port_description": "Module: 1 Port: 5 - 1 Gbit",
      "remote_chassis_id": "64:60:38:3F:4A:E1",
      "remote_system_name": "BRS50-LOUNGE",
      "remote_system_description": "Hirschmann BOBCAT - SW: HiOS-2A-09.4.00",
      "remote_system_capab": [],
      "remote_system_enable_capab": [],
      "remote_management_ipv4": "192.168.1.239",
      "remote_management_ipv6": "",
      "autoneg_support": "yes",
      "autoneg_enabled": "yes",
      "port_oper_mau_type": "1000BaseTFD",
      "port_vlan_id": "1",
      "vlan_membership": [
        1,
        2,
        3,
        4,
        5,
        6,
        7
      ],
      "link_agg_status": "agg. capable",
      "link_agg_port_id": "0"
    }
  ],
  "3/3": [
    {
      "parent_interface": "3/3",
      "remote_port": "1",
      "remote_port_description": "eth1",
      "remote_chassis_id": "50:27:A9:04:EE:60",
      "remote_system_name": "eero",
      "remote_system_description": "eero 6+ GGC1UCD124550L9A",
      "remote_system_capab": [],
      "remote_system_enable_capab": [],
      "remote_management_ipv4": "192.168.1.115",
      "remote_management_ipv6": "fe80::5227:a9ff:fe04:ee6d",
      "autoneg_support": "yes",
      "autoneg_enabled": "yes",
      "port_oper_mau_type": "1000BaseTFD",
      "port_vlan_id": "1",
      "vlan_membership": [],
      "link_agg_status": "agg. capable",
      "link_agg_port_id": "0"
    }
  ],
  "1/1": [
    {
      "parent_interface": "1/1",
      "remote_port": "64:60:38:3F:4A:A6",
      "remote_port_description": "Module: 1 Port: 1 - 2.5 Gbit",
      "remote_chassis_id": "64:60:38:3F:4A:A1",
      "remote_system_name": "BRS50-Office",
      "remote_system_description": "Hirschmann BOBCAT - SW: HiOS-2A-10.0.00",
      "remote_system_capab": [],
      "remote_system_enable_capab": [],
      "remote_management_ipv4": "192.168.1.4",
      "remote_management_ipv6": "fe80::6660:38ff:fe3f:4aa1",
      "autoneg_support": "no",
      "autoneg_enabled": "no",
      "port_oper_mau_type": "2p5GbaseX",
      "port_vlan_id": "1",
      "vlan_membership": [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        9
      ],
      "link_agg_status": "agg. capable",
      "link_agg_port_id": "0"
    }
  ],
  "1/3": [
    {
      "parent_interface": "1/3",
      "remote_port": "FDB",
      "remote_port_description": "",
      "remote_chassis_id": "90:EC:77:1B:6C:2B",
      "remote_system_name": "",
      "remote_system_description": "",
      "remote_system_capab": [],
      "remote_system_enable_capab": [],
      "remote_management_ipv4": "",
      "remote_management_ipv6": "",
      "autoneg_support": "",
      "autoneg_enabled": "",
      "port_oper_mau_type": "",
      "port_vlan_id": "",
      "vlan_membership": [],
      "link_agg_status": "",
      "link_agg_port_id": ""
    }
  ],
  "1/8": [
    {
      "parent_interface": "1/8",
      "remote_port": "D8:CB:8A:C0:37:C8",
      "remote_port_description": "",
      "remote_chassis_id": "D8:CB:8A:C0:37:C8",
      "remote_system_name": "",
      "remote_system_description": "",
      "remote_system_capab": [],
      "remote_system_enable_capab": [],
      "remote_management_ipv4": "",
      "remote_management_ipv6": "",
      "autoneg_support": "yes",
      "autoneg_enabled": "yes",
      "port_oper_mau_type": "0",
      "port_vlan_id": "1",
      "vlan_membership": [],
      "link_agg_status": "",
      "link_agg_port_id": ""
    }
  ]
}
```

#### ✓ show vlan brief (Duration: 0.08s)
```json
{
  "show vlan brief": "Max. VLAN ID................................4042\nMax. supported VLANs........................512\nNumber of currently configured VLANs........9\n\nVLAN unaware mode...........................disabled\n\nVLAN ID VLAN Name                        VLAN Type         VLAN Creation Time\n------- -------------------------------- ----------------- ------------------\n      1 HOME                             default             0 days, 00:00:13\n      2 WLAN                             static              0 days, 00:00:15\n      3 ADAM                             static              0 days, 00:00:15\n      4 CABLE                            static              0 days, 00:00:15\n      5 DSL                              static              0 days, 00:00:16\n      6 ROUTER                           static              0 days, 00:00:16\n      7 FTTH                             static              0 days, 00:00:16\n      9 WORK                             static              0 days, 00:00:16\n     10 DEMO                             static              0 days, 00:00:16"
}
```

#### ✓ show telnet (Duration: 0.08s)
```json
{
  "show telnet": "Telnet server information\n-------------------------\nTelnet server status........................disabled\nTelnet idle timeout (minutes)...............5\nTelnet listening port.......................23\nTelnet active sessions......................0\nTelnet maximum number of sessions...........5"
}
```

Total duration: 8.63s

---
