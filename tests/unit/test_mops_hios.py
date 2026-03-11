"""Unit tests for MOPS backend — getters with mocked MOPSClient."""

import unittest
from unittest.mock import Mock, patch, MagicMock

from napalm_hios.mops_hios import (
    MOPSHIOS, _safe_int, _parse_sysDescr, _mask_to_prefix,
    _decode_portlist_hex, _decode_lldp_capabilities, _encode_hex_ip,
    _decode_bits_hex, _encode_bits_hex,
    _TLS_VERSIONS, _TLS_CIPHER_SUITES, _SSH_HMAC, _SSH_KEX,
    _SSH_ENCRYPTION, _SSH_HOST_KEY,
)
from napalm.base.exceptions import ConnectionException


class TestHelpers(unittest.TestCase):
    """Test MOPS backend helper functions."""

    def test_safe_int(self):
        self.assertEqual(_safe_int("42"), 42)
        self.assertEqual(_safe_int("0"), 0)
        self.assertEqual(_safe_int(""), 0)
        self.assertEqual(_safe_int(None), 0)
        self.assertEqual(_safe_int("abc", -1), -1)

    def test_parse_sysDescr(self):
        model, ver = _parse_sysDescr("Hirschmann GRS1042 HiOS-3A-09.4.04 blah")
        self.assertEqual(model, "GRS1042")
        self.assertEqual(ver, "HiOS-3A-09.4.04")

    def test_parse_sysDescr_short(self):
        model, ver = _parse_sysDescr("BRS50 HiOS-2A-10.3.04")
        self.assertEqual(model, "BRS50")
        self.assertEqual(ver, "HiOS-2A-10.3.04")

    def test_mask_to_prefix(self):
        self.assertEqual(_mask_to_prefix("255.255.255.0"), 24)
        self.assertEqual(_mask_to_prefix("255.255.0.0"), 16)
        self.assertEqual(_mask_to_prefix("255.255.255.255"), 32)

    def test_decode_portlist_hex(self):
        ifmap = {"1": "1/1", "2": "1/2", "3": "1/3"}
        # 0xC0 = 11000000 → ports 1 and 2
        result = _decode_portlist_hex("c0 00", ifmap)
        self.assertEqual(result, ["1/1", "1/2"])

    def test_decode_portlist_hex_empty(self):
        self.assertEqual(_decode_portlist_hex("", {}), [])
        self.assertEqual(_decode_portlist_hex(None, {}), [])

    def test_decode_lldp_capabilities(self):
        # 0x24 = 00100100 → bit 2 (bridge) + bit 5 (telephone)
        caps = _decode_lldp_capabilities("24")
        self.assertIn("bridge", caps)
        self.assertIn("telephone", caps)

    def test_decode_lldp_capabilities_empty(self):
        self.assertEqual(_decode_lldp_capabilities(""), [])
        self.assertEqual(_decode_lldp_capabilities(None), [])


class TestMOPSHIOSGetters(unittest.TestCase):
    """Test MOPS backend getters with mocked client."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    # --- get_facts ---

    def test_get_facts(self):
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SNMPv2-MIB": {
                    "system": [{
                        "sysDescr": "Hirschmann BRS50 HiOS-2A-10.3.04",
                        "sysName": "BRS50-Lab",
                        "sysUpTime": "1039868",
                        "sysContact": "admin",
                        "sysLocation": "Lab",
                    }]
                },
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "1/1"},
                        {"ifIndex": "2", "ifName": "1/2"},
                    ]
                },
            },
            "errors": [],
        }
        # Private MIB queries may raise MOPSError
        from napalm_hios.mops_client import MOPSError
        self.backend.client.get.side_effect = MOPSError("not found")

        facts = self.backend.get_facts()
        self.assertEqual(facts["vendor"], "Belden")
        self.assertEqual(facts["hostname"], "BRS50-Lab")
        self.assertIn("1/1", facts["interface_list"])
        self.assertIn("1/2", facts["interface_list"])
        self.assertEqual(facts["uptime"], 10398)

    def test_get_facts_firmware_from_private_mib(self):
        """Test firmware version from hm2DevMgmtSwVersEntry (confirmed Node name)."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SNMPv2-MIB": {
                    "system": [{
                        "sysDescr": "Hirschmann BRS50 HiOS-2A-10.3.04",
                        "sysName": "BRS50-Lab",
                        "sysUpTime": "1039868",
                        "sysContact": "",
                        "sysLocation": "",
                    }]
                },
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "1/1"},
                    ]
                },
                "HM2-DEVMGMT-MIB": {
                    "hm2DeviceMgmtGroup": [
                        {"hm2DevMgmtProductDescr": "42 52 53 35 30 2d 38 54 58",
                         "hm2DevMgmtSerialNumber": "53 4e 31 32 33"}],
                    "hm2DevMgmtSwVersEntry": [
                        {"hm2DevMgmtSwVersion": "48 69 4f 53 2d 32 41 2d 31 30 2e 33 2e 30 34 20 32 30 32 35 2d 31 32 2d 30 38 20 31 36 3a 35 34",
                         "hm2DevMgmtSwFileLocation": "1", "hm2DevMgmtSwFileIdx": "1"},
                        {"hm2DevMgmtSwVersion": "48 69 4f 53 2d 31 30 2e 33 2e 30 34",
                         "hm2DevMgmtSwFileLocation": "2", "hm2DevMgmtSwFileIdx": "1"},
                    ],
                },
            },
            "errors": [],
        }
        facts = self.backend.get_facts()
        self.assertEqual(facts["os_version"], "HiOS-2A-10.3.04")
        self.assertEqual(facts["serial_number"], "SN123")
        self.assertEqual(facts["model"], "BRS50-8TX")

    # --- get_interfaces ---

    def test_get_interfaces(self):
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IF-MIB": {
                    "ifEntry": [{
                        "ifIndex": "1",
                        "ifDescr": "Module: 1 Port: 1",
                        "ifMtu": "1518",
                        "ifSpeed": "1000000000",
                        "ifPhysAddress": "64 60 38 8a 42 d6",
                        "ifAdminStatus": "1",
                        "ifOperStatus": "1",
                    }],
                    "ifXEntry": [{
                        "ifIndex": "1",
                        "ifName": "1/1",
                        "ifHighSpeed": "1000",
                        "ifAlias": "Uplink",
                    }],
                },
            },
            "errors": [],
        }

        interfaces = self.backend.get_interfaces()
        self.assertIn("1/1", interfaces)
        iface = interfaces["1/1"]
        self.assertTrue(iface["is_up"])
        self.assertTrue(iface["is_enabled"])
        self.assertEqual(iface["speed"], 1000000000)
        self.assertEqual(iface["mtu"], 1518)
        self.assertEqual(iface["mac_address"], "64:60:38:8a:42:d6")
        self.assertEqual(iface["description"], "Uplink")

    # --- get_interfaces_ip ---

    def test_get_interfaces_ip(self):
        self.backend._ifindex_map = {"100": "cpu/1"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IP-MIB": {
                    "ipAddrEntry": [
                        {"ipAdEntAddr": "192.168.1.254", "ipAdEntIfIndex": "100",
                         "ipAdEntNetMask": "255.255.255.0"},
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_interfaces_ip()
        self.assertIn("cpu/1", result)
        self.assertIn("192.168.1.254", result["cpu/1"]["ipv4"])
        self.assertEqual(result["cpu/1"]["ipv4"]["192.168.1.254"]["prefix_length"], 24)

    # --- get_interfaces_counters ---

    def test_get_interfaces_counters(self):
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IF-MIB": {
                    "ifEntry": [{
                        "ifIndex": "1",
                        "ifInErrors": "5",
                        "ifOutErrors": "3",
                        "ifInDiscards": "10",
                        "ifOutDiscards": "2",
                    }],
                    "ifXEntry": [{
                        "ifIndex": "1",
                        "ifName": "1/1",
                        "ifHCInOctets": "1000000",
                        "ifHCOutOctets": "500000",
                        "ifHCInUcastPkts": "100",
                        "ifHCOutUcastPkts": "50",
                        "ifHCInMulticastPkts": "10",
                        "ifHCOutMulticastPkts": "5",
                        "ifHCInBroadcastPkts": "20",
                        "ifHCOutBroadcastPkts": "8",
                    }],
                },
            },
            "errors": [],
        }

        counters = self.backend.get_interfaces_counters()
        self.assertIn("1/1", counters)
        c = counters["1/1"]
        self.assertEqual(c["rx_errors"], 5)
        self.assertEqual(c["tx_errors"], 3)
        self.assertEqual(c["rx_octets"], 1000000)
        self.assertEqual(c["tx_octets"], 500000)

    # --- get_lldp_neighbors ---

    def test_get_lldp_neighbors(self):
        self.backend._ifindex_map = {"7": "1/7"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "LLDP-MIB": {
                    "lldpRemEntry": [
                        {"lldpRemLocalPortNum": "7", "lldpRemSysName": "BRS50-LOUNGE",
                         "lldpRemPortId": "Module: 1 Port: 5"},
                    ],
                },
            },
            "errors": [],
        }

        neighbors = self.backend.get_lldp_neighbors()
        self.assertIn("1/7", neighbors)
        self.assertEqual(neighbors["1/7"][0]["hostname"], "BRS50-LOUNGE")

    # --- get_lldp_neighbors_detail ---

    def test_get_lldp_neighbors_detail(self):
        self.backend._ifindex_map = {"7": "1/7"}
        # Single get_multi: lldpRemEntry + lldpRemManAddrEntry
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "LLDP-MIB": {
                    "lldpRemEntry": [
                        {"lldpRemLocalPortNum": "7", "lldpRemIndex": "1",
                         "lldpRemPortId": "Module: 1 Port: 5",
                         "lldpRemPortDesc": "1/5",
                         "lldpRemChassisId": "64 60 38 8a 42 d6",
                         "lldpRemSysName": "BRS50-LOUNGE",
                         "lldpRemSysDesc": "Hirschmann BRS50",
                         "lldpRemSysCapSupported": "24",
                         "lldpRemSysCapEnabled": "24"}],
                    "lldpRemManAddrEntry": [
                        {"lldpRemLocalPortNum": "7", "lldpRemIndex": "1",
                         "lldpRemManAddrSubtype": "1",
                         "lldpRemManAddr": "c0 a8 01 fe"}],
                },
            },
            "errors": [],
        }

        detail = self.backend.get_lldp_neighbors_detail()
        self.assertIn("1/7", detail)
        n = detail["1/7"][0]
        self.assertEqual(n["remote_system_name"], "BRS50-LOUNGE")
        self.assertEqual(n["remote_chassis_id"], "64:60:38:8a:42:d6")
        self.assertIn("bridge", n["remote_system_capab"])
        self.assertEqual(n["remote_management_address"], "192.168.1.254")

    # --- get_mac_address_table ---

    def test_get_mac_address_table(self):
        self.backend._ifindex_map = {"7": "1/7", "25": "cpu/1"}
        # FDB ID = VLAN ID on HiOS (requested explicitly as attribute)
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IEEE8021-Q-BRIDGE-MIB": {
                    "ieee8021QBridgeTpFdbEntry": [
                        {"ieee8021QBridgeTpFdbAddress": "12 dd 6e 60 34 4b",
                         "ieee8021QBridgeTpFdbPort": "7",
                         "ieee8021QBridgeTpFdbStatus": "3",
                         "ieee8021QBridgeFdbId": "1"},
                        {"ieee8021QBridgeTpFdbAddress": "64 60 38 3f 4a a1",
                         "ieee8021QBridgeTpFdbPort": "25",
                         "ieee8021QBridgeTpFdbStatus": "5",
                         "ieee8021QBridgeFdbId": "3"},
                    ],
                },
            },
            "errors": [],
        }

        mac_table = self.backend.get_mac_address_table()
        self.assertEqual(len(mac_table), 2)
        self.assertEqual(mac_table[0]["mac"], "12:dd:6e:60:34:4b")
        self.assertEqual(mac_table[0]["interface"], "1/7")
        self.assertEqual(mac_table[0]["vlan"], 1)
        self.assertFalse(mac_table[0]["static"])
        self.assertEqual(mac_table[1]["mac"], "64:60:38:3f:4a:a1")
        self.assertEqual(mac_table[1]["interface"], "cpu/1")
        self.assertEqual(mac_table[1]["vlan"], 3)
        self.assertTrue(mac_table[1]["static"])

    # --- get_vlans ---

    def test_get_vlans(self):
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "3": "1/3"}
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "1",
             "ieee8021QBridgeVlanStaticName": "default",
             "ieee8021QBridgeVlanStaticRowStatus": "1",
             "ieee8021QBridgeVlanStaticEgressPorts": "e0 00 00 00"},
            {"ieee8021QBridgeVlanStaticVlanIndex": "100",
             "ieee8021QBridgeVlanStaticName": "mgmt",
             "ieee8021QBridgeVlanStaticRowStatus": "1",
             "ieee8021QBridgeVlanStaticEgressPorts": "80 00 00 00"},
        ]

        vlans = self.backend.get_vlans()
        self.assertEqual(len(vlans), 2)
        self.assertIn(1, vlans)
        self.assertIn(100, vlans)
        self.assertEqual(vlans[1]["name"], "default")
        self.assertEqual(vlans[100]["name"], "mgmt")
        # VLAN 1 egress e0 = ports 1,2,3
        self.assertIn("1/1", vlans[1]["interfaces"])
        self.assertIn("1/2", vlans[1]["interfaces"])
        self.assertIn("1/3", vlans[1]["interfaces"])
        # VLAN 100 egress 80 = port 1 only
        self.assertIn("1/1", vlans[100]["interfaces"])
        self.assertNotIn("1/2", vlans[100]["interfaces"])

    # --- get_arp_table ---

    def test_get_arp_table(self):
        self.backend._ifindex_map = {"100": "cpu/1"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IP-MIB": {
                    "ipNetToMediaEntry": [
                        {"ipNetToMediaIfIndex": "100",
                         "ipNetToMediaPhysAddress": "aa bb cc dd ee ff",
                         "ipNetToMediaNetAddress": "192.168.1.1",
                         "ipNetToMediaType": "3"},
                    ],
                },
            },
            "errors": [],
        }

        arp = self.backend.get_arp_table()
        self.assertEqual(len(arp), 1)
        self.assertEqual(arp[0]["ip"], "192.168.1.1")
        self.assertEqual(arp[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(arp[0]["interface"], "cpu/1")

    # --- get_snmp_information ---

    def test_get_snmp_information(self):
        self.backend.client.get.return_value = [
            {"sysContact": "admin@example.com",
             "sysLocation": "Lab",
             "sysName": "GRS1042-CORE"},
        ]

        snmp = self.backend.get_snmp_information()
        self.assertEqual(snmp["chassis_id"], "GRS1042-CORE")
        self.assertEqual(snmp["contact"], "admin@example.com")
        self.assertEqual(snmp["community"], {})

    # --- get_config_status ---

    def test_get_config_status(self):
        self.backend.client.nvm_state.return_value = {
            "hm2FMNvmState": {"value": "1", "label": "ok"},
            "hm2FMEnvmState": {"value": "3", "label": "absent"},
            "hm2FMBootParamState": {"value": "1", "label": "ok"},
        }

        status = self.backend.get_config_status()
        self.assertTrue(status["saved"])
        self.assertEqual(status["nvm"], "ok")
        self.assertEqual(status["aca"], "absent")

    # --- get_users ---

    def test_get_users(self):
        # hm2UserAccessRole: 15=administrator, 1=guest
        self.backend.client.get.side_effect = [
            [
                {"hm2UserName": "61 64 6d 69 6e", "hm2UserAccessRole": "15",
                 "hm2UserLockoutStatus": "2", "hm2UserPwdPolicyChk": "2",
                 "hm2UserSnmpAuthType": "1", "hm2UserSnmpEncType": "1",
                 "hm2UserStatus": "1"},
                {"hm2UserName": "75 73 65 72", "hm2UserAccessRole": "1",
                 "hm2UserLockoutStatus": "2", "hm2UserPwdPolicyChk": "2",
                 "hm2UserSnmpAuthType": "1", "hm2UserSnmpEncType": "1",
                 "hm2UserStatus": "1"},
            ],
            [],  # default password table
        ]

        users = self.backend.get_users()
        names = {u['name'] for u in users}
        self.assertIn("admin", names)
        self.assertIn("user", names)
        admin = next(u for u in users if u['name'] == 'admin')
        self.assertEqual(admin['role'], 'administrator')
        user = next(u for u in users if u['name'] == 'user')
        self.assertEqual(user['role'], 'guest')

    # --- get_environment ---

    def test_get_environment(self):
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DEVMGMT-MIB": {
                    "hm2DeviceMgmtTemperatureGroup": [{
                        "hm2DevMgmtTemperature": "42",
                        "hm2DevMgmtTemperatureUpperLimit": "70",
                        "hm2DevMgmtTemperatureLowerLimit": "0",
                    }]
                },
                "HM2-DIAGNOSTIC-MIB": {
                    "hm2DiagCpuResourcesGroup": [{
                        "hm2DiagCpuUtilization": "35",
                    }],
                    "hm2DiagMemoryResourcesGroup": [{
                        "hm2DiagMemoryRamAllocated": "128484",
                        "hm2DiagMemoryRamFree": "124592",
                    }],
                },
            },
            "errors": [],
        }
        # PSU and fan queries
        from napalm_hios.mops_client import MOPSError
        self.backend.client.get.side_effect = MOPSError("not found")

        env = self.backend.get_environment()
        self.assertEqual(env["temperature"]["chassis"]["temperature"], 42.0)
        self.assertFalse(env["temperature"]["chassis"]["is_alert"])
        self.assertEqual(env["cpu"]["0"]["%usage"], 35.0)
        self.assertGreater(env["memory"]["available_ram"], env["memory"]["used_ram"])

    # --- get_optics ---

    def test_get_optics(self):
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DEVMGMT-MIB": {
                    "hm2SfpDiagEntry": [
                        {"ifIndex": "1",
                         "hm2SfpCurrentTxPower": "3835",
                         "hm2SfpCurrentRxPower": "3613",
                         "hm2SfpCurrentTxPowerdBm": "2d 34 2e 31",
                         "hm2SfpCurrentRxPowerdBm": "2d 34 2e 34"},
                        {"ifIndex": "2",
                         "hm2SfpCurrentTxPower": "3816",
                         "hm2SfpCurrentRxPower": "3502",
                         "hm2SfpCurrentTxPowerdBm": "2d 34 2e 31",
                         "hm2SfpCurrentRxPowerdBm": "2d 34 2e 35"},
                    ],
                },
            },
            "errors": [],
        }

        optics = self.backend.get_optics()
        self.assertIn("1/1", optics)
        self.assertIn("1/2", optics)
        ch = optics["1/1"]["physical_channels"]["channel"][0]["state"]
        self.assertAlmostEqual(ch["output_power"]["instant"], -4.1, places=1)
        self.assertAlmostEqual(ch["input_power"]["instant"], -4.4, places=1)

    # --- get_ntp_servers ---

    def test_get_ntp_servers(self):
        # Address is hex-encoded raw IP: "c0 a8 03 01" → 192.168.3.1
        self.backend.client.get.return_value = [
            {"hm2SntpClientServerAddr": "c0 a8 03 01"},
        ]

        servers = self.backend.get_ntp_servers()
        self.assertIn("192.168.3.1", servers)

    # --- get_ntp_stats ---

    def test_get_ntp_stats(self):
        # Node name: hm2SntpClientServerAddrEntry (not hm2SntpClientServerEntry)
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-TIMESYNC-MIB": {
                    "hm2SntpClientServerAddrEntry": [
                        {"hm2SntpClientServerAddr": "c0 a8 03 01",
                         "hm2SntpClientServerStatus": "2"},  # 2=success
                    ],
                    "hm2SntpClientGroup": [
                        {"hm2SntpClientStatus": "6",
                         "hm2SntpClientRequestInterval": "30"},
                    ],
                },
            },
            "errors": [],
        }

        stats = self.backend.get_ntp_stats()
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0]["remote"], "192.168.3.1")
        self.assertTrue(stats[0]["synchronized"])

    # --- get_hidiscovery ---

    def test_get_hidiscovery(self):
        # Correct attribute names from HM2-NETCONFIG-MIB/hm2NetHiDiscoveryGroup
        self.backend.client.get.return_value = [{
            "hm2NetHiDiscoveryOperation": "1",
            "hm2NetHiDiscoveryMode": "2",
            "hm2NetHiDiscoveryBlinking": "2",
            "hm2NetHiDiscoveryProtocol": "60",  # hex: 0x60 = v1+v2 bits
            "hm2NetHiDiscoveryRelay": "1",
        }]

        result = self.backend.get_hidiscovery()
        self.assertTrue(result["enabled"])
        self.assertEqual(result["mode"], "read-only")
        self.assertFalse(result["blinking"])
        self.assertIn("v1", result["protocols"])
        self.assertIn("v2", result["protocols"])
        self.assertTrue(result["relay"])


class TestStaging(unittest.TestCase):
    """Test MOPS staging lifecycle."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_staging_lifecycle(self):
        """start → accumulate → commit → clear."""
        self.backend.start_staging()
        self.assertTrue(self.backend._staging)
        self.assertEqual(self.backend._mutations, [])

        # Simulate adding mutations
        self.backend._mutations.append(
            ("SNMPv2-MIB", "system", {"sysLocation": "4c 61 62"}))
        self.assertEqual(len(self.backend.get_staged_mutations()), 1)

        # Commit — fires set_multi, does NOT auto-save
        self.backend.client.set_multi.return_value = True
        self.backend.commit_staging()

        self.assertFalse(self.backend._staging)
        self.assertEqual(self.backend._mutations, [])
        self.backend.client.set_multi.assert_called_once()
        self.backend.client.save_config.assert_not_called()

    def test_discard_staging(self):
        self.backend.start_staging()
        self.backend._mutations.append(("X", "Y", {"Z": "1"}))
        self.backend.discard_staging()
        self.assertFalse(self.backend._staging)
        self.assertEqual(self.backend._mutations, [])

    def test_commit_empty_staging(self):
        """Committing with no mutations should just clear staging."""
        self.backend.start_staging()
        self.backend.commit_staging()
        self.assertFalse(self.backend._staging)
        self.backend.client.set_multi.assert_not_called()


class TestConnectionLifecycle(unittest.TestCase):
    """Test MOPS backend open/close."""

    @patch('napalm_hios.mops_hios.MOPSClient')
    def test_open_success(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.probe.return_value = "Hirschmann BRS50 HiOS-2A-10.3.04"

        backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        backend.open()
        self.assertTrue(backend._connected)
        mock_client.probe.assert_called_once()

    @patch('napalm_hios.mops_hios.MOPSClient')
    def test_open_failure(self, mock_client_cls):
        mock_client = mock_client_cls.return_value
        mock_client.probe.side_effect = ConnectionException("refused")

        backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        with self.assertRaises(ConnectionException):
            backend.open()
        self.assertFalse(backend._connected)

    def test_close(self):
        backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        backend.client = Mock()
        backend._connected = True
        backend._ifindex_map = {"1": "1/1"}
        backend.close()
        self.assertFalse(backend._connected)
        self.assertIsNone(backend._ifindex_map)
        self.assertIsNone(backend.client)


class TestOnboarding(unittest.TestCase):
    """Test MOPS backend onboarding and factory default detection."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_is_factory_default_true(self):
        self.backend.client.is_factory_default.return_value = True
        self.assertTrue(self.backend.is_factory_default())

    def test_is_factory_default_false(self):
        self.backend.client.is_factory_default.return_value = False
        self.assertFalse(self.backend.is_factory_default())

    def test_is_factory_default_not_connected(self):
        self.backend.client = None
        with self.assertRaises(ConnectionException):
            self.backend.is_factory_default()

    def test_onboard_success(self):
        self.backend.client.change_password.return_value = True
        result = self.backend.onboard("Private1")
        self.assertTrue(result)
        self.backend.client.change_password.assert_called_once_with("Private1")

    def test_onboard_not_connected(self):
        self.backend.client = None
        with self.assertRaises(ConnectionException):
            self.backend.onboard("Private1")


class TestMOPSHIOSSetters(unittest.TestCase):
    """Test MOPS backend setter methods with mocked client."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    # --- set_hidiscovery ---

    def test_set_hidiscovery_on(self):
        self.backend.client.get.return_value = [
            {"hm2NetHiDiscoveryOperation": "1", "hm2NetHiDiscoveryMode": "1",
             "hm2NetHiDiscoveryBlinking": "2", "hm2NetHiDiscoveryProtocol": "60"}
        ]
        result = self.backend.set_hidiscovery('on')
        self.backend.client.set.assert_called_once_with(
            "HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup",
            {"hm2NetHiDiscoveryOperation": "1", "hm2NetHiDiscoveryMode": "1"})
        self.assertTrue(result['enabled'])

    def test_set_hidiscovery_off(self):
        self.backend.client.get.return_value = [
            {"hm2NetHiDiscoveryOperation": "2", "hm2NetHiDiscoveryMode": "1",
             "hm2NetHiDiscoveryBlinking": "2", "hm2NetHiDiscoveryProtocol": "60"}
        ]
        self.backend.set_hidiscovery('off')
        self.backend.client.set.assert_called_once_with(
            "HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup",
            {"hm2NetHiDiscoveryOperation": "2"})

    def test_set_hidiscovery_ro(self):
        self.backend.client.get.return_value = [
            {"hm2NetHiDiscoveryOperation": "1", "hm2NetHiDiscoveryMode": "2",
             "hm2NetHiDiscoveryBlinking": "2", "hm2NetHiDiscoveryProtocol": "60"}
        ]
        self.backend.set_hidiscovery('ro')
        self.backend.client.set.assert_called_once_with(
            "HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup",
            {"hm2NetHiDiscoveryOperation": "1", "hm2NetHiDiscoveryMode": "2"})

    def test_set_hidiscovery_with_blinking(self):
        self.backend.client.get.return_value = [
            {"hm2NetHiDiscoveryOperation": "1", "hm2NetHiDiscoveryMode": "1",
             "hm2NetHiDiscoveryBlinking": "1", "hm2NetHiDiscoveryProtocol": "60"}
        ]
        self.backend.set_hidiscovery('on', blinking=True)
        self.backend.client.set.assert_called_once_with(
            "HM2-NETCONFIG-MIB", "hm2NetHiDiscoveryGroup",
            {"hm2NetHiDiscoveryOperation": "1", "hm2NetHiDiscoveryMode": "1",
             "hm2NetHiDiscoveryBlinking": "1"})

    def test_set_hidiscovery_invalid_status(self):
        with self.assertRaises(ValueError):
            self.backend.set_hidiscovery('invalid')

    # --- set_mrp ---

    def test_set_mrp_enable_client(self):
        """Enable MRP as client — creates domain if needed."""
        # ifindex map for port resolution
        self.backend._build_ifindex_map = Mock(return_value={
            "1": "1/1", "2": "1/2", "3": "1/3", "4": "1/4"})
        self.backend.client.set_indexed.return_value = True

        self.backend.set_mrp(operation='enable', mode='client',
                             port_primary='1/3', port_secondary='1/4')

        calls = self.backend.client.set_indexed.call_args_list
        # Call 1: createAndWait (may fail if exists)
        self.assertEqual(calls[0].kwargs['values'], {"hm2MrpRowStatus": "5"})
        # Call 2: notInService for modification
        self.assertEqual(calls[1].kwargs['values'], {"hm2MrpRowStatus": "2"})
        # Call 3: set parameters
        params = calls[2].kwargs['values']
        self.assertEqual(params["hm2MrpRoleAdminState"], "1")  # client
        self.assertEqual(params["hm2MrpRingport1IfIndex"], "3")
        self.assertEqual(params["hm2MrpRingport2IfIndex"], "4")
        # Call 4: activate
        self.assertEqual(calls[3].kwargs['values'], {"hm2MrpRowStatus": "1"})

    def test_set_mrp_disable(self):
        self.backend.client.set_indexed.return_value = True

        self.backend.set_mrp(operation='disable')

        calls = self.backend.client.set_indexed.call_args_list
        # Call 1: createAndWait (may fail if exists)
        self.assertEqual(calls[0].kwargs['values'], {"hm2MrpRowStatus": "5"})
        # Call 2: notInService (disable)
        self.assertEqual(calls[1].kwargs['values'], {"hm2MrpRowStatus": "2"})

    def test_set_mrp_invalid_operation(self):
        with self.assertRaises(ValueError):
            self.backend.set_mrp(operation='restart')

    def test_set_mrp_invalid_mode(self):
        with self.assertRaises(ValueError):
            self.backend.set_mrp(mode='observer')

    def test_set_mrp_unknown_port(self):
        self.backend.get_mrp = Mock(return_value={'configured': True})
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend.client.set_indexed.return_value = True

        with self.assertRaises(ValueError) as ctx:
            self.backend.set_mrp(port_primary='9/9')
        self.assertIn("Unknown port", str(ctx.exception))

    # --- delete_mrp ---

    def test_delete_mrp(self):
        self.backend.get_mrp = Mock(return_value={'configured': False})
        self.backend.client.set_indexed.return_value = True

        result = self.backend.delete_mrp()

        calls = self.backend.client.set_indexed.call_args_list
        # notInService then destroy
        self.assertEqual(calls[0].kwargs['values'], {"hm2MrpRowStatus": "2"})
        self.assertEqual(calls[1].kwargs['values'], {"hm2MrpRowStatus": "6"})
        self.assertFalse(result['configured'])

    # --- MRP sub-ring (SRM) ---

    def test_get_mrp_sub_ring_empty(self):
        """No SRM instances configured."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-L2REDUNDANCY-MIB": {
                    "hm2SrmMibGroup": [{"hm2SrmGlobalAdminState": "2", "hm2SrmMaxInstances": "8"}],
                    "hm2SrmEntry": [],
                },
            },
            "errors": [],
        }
        result = self.backend.get_mrp_sub_ring()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['max_instances'], 8)
        self.assertEqual(result['instances'], [])

    def test_get_mrp_sub_ring_one_instance(self):
        """One SRM instance configured and active (decode_strings=False)."""
        self.backend._ifindex_map = {
            "1": "1/1", "2": "1/2", "3": "1/3", "4": "1/4"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-L2REDUNDANCY-MIB": {
                    "hm2SrmMibGroup": [{"hm2SrmGlobalAdminState": "1", "hm2SrmMaxInstances": "8"}],
                    "hm2SrmEntry": [{
                        "hm2SrmRingID": "1",
                        "hm2SrmAdminState": "1",  # manager
                        "hm2SrmOperState": "1",   # manager
                        "hm2SrmVlanID": "200",
                        "hm2SrmMRPDomainID": "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
                        "hm2SrmPartnerMAC": "00 80 63 a1 b2 c3",
                        "hm2SrmSubRingProtocol": "4",              # iec-62439-mrp(4)
                        "hm2SrmSubRingName": "73 75 62 31",        # "sub1"
                        "hm2SrmSubRingPortIfIndex": "3",
                        "hm2SrmSubRingPortOperState": "3",  # forwarding
                        "hm2SrmSubRingOperState": "3",       # closed
                        "hm2SrmRedundancyOperState": "1",    # True
                        "hm2SrmConfigOperState": "1",        # no error
                        "hm2SrmRowStatus": "1",              # active
                    }],
                },
            },
            "errors": [],
        }

        result = self.backend.get_mrp_sub_ring()
        self.assertTrue(result['enabled'])
        self.assertEqual(len(result['instances']), 1)
        inst = result['instances'][0]
        self.assertEqual(inst['ring_id'], 1)
        self.assertEqual(inst['mode'], 'manager')
        self.assertEqual(inst['vlan'], 200)
        self.assertEqual(inst['port'], '1/3')
        self.assertEqual(inst['port_state'], 'forwarding')
        self.assertEqual(inst['ring_state'], 'closed')
        self.assertTrue(inst['redundancy'])
        self.assertEqual(inst['name'], 'sub1')
        self.assertEqual(inst['partner_mac'], '00:80:63:a1:b2:c3')
        self.assertEqual(inst['protocol'], 'mrp')
        self.assertEqual(inst['domain_id'],
                         'ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff')

    def test_set_mrp_sub_ring_global_enable(self):
        """Global SRM enable only (no instance)."""
        self.backend.client.set_indexed.return_value = True
        # Read-back via get_mrp_sub_ring() now uses get_multi
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-L2REDUNDANCY-MIB": {
                    "hm2SrmMibGroup": [{"hm2SrmGlobalAdminState": "1", "hm2SrmMaxInstances": "8"}],
                    "hm2SrmEntry": [],
                },
            },
            "errors": [],
        }

        result = self.backend.set_mrp_sub_ring(enabled=True)

        calls = self.backend.client.set_indexed.call_args_list
        self.assertEqual(calls[0].kwargs['values'], {"hm2SrmGlobalAdminState": "1"})
        self.assertTrue(result['enabled'])

    def test_set_mrp_sub_ring_create_instance(self):
        """Create SRM instance — 4-step RowStatus lifecycle."""
        self.backend._build_ifindex_map = Mock(return_value={
            "1": "1/1", "2": "1/2", "3": "1/3", "4": "1/4"})
        self.backend.client.set_indexed.return_value = True
        # Read-back via get_mrp_sub_ring() now uses get_multi
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-L2REDUNDANCY-MIB": {
                    "hm2SrmMibGroup": [{"hm2SrmGlobalAdminState": "1", "hm2SrmMaxInstances": "8"}],
                    "hm2SrmEntry": [],
                },
            },
            "errors": [],
        }

        self.backend.set_mrp_sub_ring(ring_id=1, mode='manager',
                                       port='1/3', vlan=200)

        calls = self.backend.client.set_indexed.call_args_list
        # Call 1: auto-enable global SRM
        self.assertEqual(calls[0].kwargs['values'], {"hm2SrmGlobalAdminState": "1"})
        # Call 2: createAndWait(5)
        self.assertEqual(calls[1].kwargs['values'], {"hm2SrmRowStatus": "5"})
        # Call 3: notInService(2)
        self.assertEqual(calls[2].kwargs['values'], {"hm2SrmRowStatus": "2"})
        # Call 4: set parameters
        params = calls[3].kwargs['values']
        self.assertEqual(params["hm2SrmAdminState"], "1")  # manager
        self.assertEqual(params["hm2SrmSubRingPortIfIndex"], "3")
        self.assertEqual(params["hm2SrmVlanID"], "200")
        # Call 5: activate(1)
        self.assertEqual(calls[4].kwargs['values'], {"hm2SrmRowStatus": "1"})

    def test_set_mrp_sub_ring_unknown_port(self):
        """Unknown port raises ValueError."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend.client.set_indexed.return_value = True

        with self.assertRaises(ValueError) as ctx:
            self.backend.set_mrp_sub_ring(ring_id=1, port='9/9')
        self.assertIn("Unknown port", str(ctx.exception))

    def test_delete_mrp_sub_ring(self):
        """Delete SRM instance: notInService → destroy."""
        self.backend.client.set_indexed.return_value = True
        # Read-back via get_mrp_sub_ring() now uses get_multi
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-L2REDUNDANCY-MIB": {
                    "hm2SrmMibGroup": [{"hm2SrmGlobalAdminState": "1", "hm2SrmMaxInstances": "8"}],
                    "hm2SrmEntry": [],
                },
            },
            "errors": [],
        }

        result = self.backend.delete_mrp_sub_ring(ring_id=1)

        calls = self.backend.client.set_indexed.call_args_list
        self.assertEqual(calls[0].kwargs['values'], {"hm2SrmRowStatus": "2"})
        self.assertEqual(calls[1].kwargs['values'], {"hm2SrmRowStatus": "6"})

    # --- activate_profile ---

    def test_activate_profile_nvm(self):
        self.backend.client.set_indexed.return_value = True
        self.backend.client.get.return_value = [
            {"hm2FMProfileStorageType": "1", "hm2FMProfileIndex": "1",
             "hm2FMProfileName": "config1", "hm2FMProfileActive": "1",
             "hm2FMProfileDateTime": "", "hm2FMProfileFingerprint": "",
             "hm2FMProfileFingerprintVerified": "2",
             "hm2FMProfileEncryptionActive": "2",
             "hm2FMProfileEncryptionVerified": "2",
             "hm2FMProfileSwMajorRelNum": "10",
             "hm2FMProfileSwMinorRelNum": "3",
             "hm2FMProfileSwBugfixRelNum": "04"}
        ]

        self.backend.activate_profile('nvm', 1)

        self.backend.client.set_indexed.assert_called_once_with(
            "HM2-FILEMGMT-MIB", "hm2FMProfileEntry",
            index={"hm2FMProfileStorageType": "1", "hm2FMProfileIndex": "1"},
            values={"hm2FMProfileActive": "1"})

    def test_activate_profile_invalid_storage(self):
        with self.assertRaises(ValueError):
            self.backend.activate_profile('usb', 1)

    # --- delete_profile ---

    def test_delete_profile(self):
        self.backend.client.set_indexed.return_value = True
        # get_profiles needs mock data — profile 2 is not active
        self.backend.get_profiles = Mock(return_value=[
            {'index': 1, 'name': 'config1', 'active': True},
            {'index': 2, 'name': 'backup', 'active': False},
        ])

        self.backend.delete_profile('nvm', 2)

        self.backend.client.set_indexed.assert_called_once_with(
            "HM2-FILEMGMT-MIB", "hm2FMProfileEntry",
            index={"hm2FMProfileStorageType": "1", "hm2FMProfileIndex": "2"},
            values={"hm2FMProfileAction": "2"})

    def test_delete_profile_active_refused(self):
        self.backend.get_profiles = Mock(return_value=[
            {'index': 1, 'name': 'config1', 'active': True},
        ])
        with self.assertRaises(ValueError) as ctx:
            self.backend.delete_profile('nvm', 1)
        self.assertIn("Cannot delete active", str(ctx.exception))

    def test_delete_profile_invalid_storage(self):
        with self.assertRaises(ValueError):
            self.backend.delete_profile('usb', 1)

    # --- set_interface ---

    def test_set_interface_disable(self):
        self.backend._build_ifindex_map = Mock(return_value={"5": "1/5"})

        self.backend.set_interface('1/5', enabled=False)

        self.backend.client.set_multi.assert_called_once_with([
            ("IF-MIB", "ifEntry", {"ifAdminStatus": "2"}, {"ifIndex": "5"}),
        ])

    def test_set_interface_enable(self):
        self.backend._build_ifindex_map = Mock(return_value={"5": "1/5"})

        self.backend.set_interface('1/5', enabled=True)

        self.backend.client.set_multi.assert_called_once_with([
            ("IF-MIB", "ifEntry", {"ifAdminStatus": "1"}, {"ifIndex": "5"}),
        ])

    def test_set_interface_description(self):
        self.backend._build_ifindex_map = Mock(return_value={"5": "1/5"})

        self.backend.set_interface('1/5', description='Uplink')

        self.backend.client.set_multi.assert_called_once_with([
            ("IF-MIB", "ifXEntry",
             {"ifAlias": "55 70 6c 69 6e 6b"}, {"ifIndex": "5"}),
        ])

    def test_set_interface_both(self):
        self.backend._build_ifindex_map = Mock(return_value={"5": "1/5"})

        self.backend.set_interface('1/5', enabled=False, description='Down')

        self.backend.client.set_multi.assert_called_once_with([
            ("IF-MIB", "ifEntry", {"ifAdminStatus": "2"}, {"ifIndex": "5"}),
            ("IF-MIB", "ifXEntry",
             {"ifAlias": "44 6f 77 6e"}, {"ifIndex": "5"}),
        ])

    def test_set_interface_unknown_port(self):
        self.backend._build_ifindex_map = Mock(return_value={"5": "1/5"})
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_interface('99/99', enabled=True)
        self.assertIn("Unknown interface", str(ctx.exception))

    # --- clear_config / clear_factory ---

    def test_clear_config(self):
        self.backend.client.clear_config = Mock(return_value={"restarting": True})
        result = self.backend.clear_config()
        self.backend.client.clear_config.assert_called_once_with(keep_ip=False)
        self.assertTrue(result['restarting'])

    def test_clear_config_keep_ip(self):
        self.backend.client.clear_config = Mock(return_value={"restarting": True})
        result = self.backend.clear_config(keep_ip=True)
        self.backend.client.clear_config.assert_called_once_with(keep_ip=True)
        self.assertTrue(result['restarting'])

    def test_clear_factory(self):
        self.backend.client.clear_factory = Mock(return_value={"rebooting": True})
        result = self.backend.clear_factory()
        self.backend.client.clear_factory.assert_called_once_with(erase_all=False)
        self.assertTrue(result['rebooting'])

    def test_clear_factory_erase_all(self):
        self.backend.client.clear_factory = Mock(return_value={"rebooting": True})
        result = self.backend.clear_factory(erase_all=True)
        self.backend.client.clear_factory.assert_called_once_with(erase_all=True)
        self.assertTrue(result['rebooting'])


class TestMOPSHIOSRSTP(unittest.TestCase):
    """Test MOPS backend RSTP getter and setter methods."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    # ----------------------------------------------------------------
    # get_rstp
    # ----------------------------------------------------------------

    def test_get_rstp(self):
        """Verify all global RSTP fields are parsed correctly."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentStpSwitchConfigGroup": [{
                        "hm2AgentStpForceVersion": "2",
                        "hm2AgentStpAdminMode": "1",
                        "hm2AgentStpBpduGuardMode": "2",
                        "hm2AgentStpBpduFilterDefault": "2",
                    }],
                    "hm2AgentStpCstConfigGroup": [{
                        "hm2AgentStpCstHelloTime": "2",
                        "hm2AgentStpCstMaxAge": "20",
                        "hm2AgentStpCstRootFwdDelay": "15",
                        "hm2AgentStpCstBridgeFwdDelay": "15",
                        "hm2AgentStpCstBridgeHelloTime": "2",
                        "hm2AgentStpCstBridgeMaxAge": "20",
                        "hm2AgentStpCstBridgeMaxHops": "40",
                        "hm2AgentStpCstBridgePriority": "32768",
                        "hm2AgentStpCstBridgeHoldCount": "10",
                        "hm2AgentStpCstBridgeHoldTime": "1",
                    }],
                    "hm2AgentStpMstEntry": [{
                        "hm2AgentStpMstBridgeIdentifier":
                            "80 00 a0 b0 86 f4 ea 1f",
                        "hm2AgentStpMstDesignatedRootId":
                            "80 00 64 60 38 6a 7e ac",
                        "hm2AgentStpMstRootPortId": "80 05",
                        "hm2AgentStpMstRootPathCost": "20000",
                        "hm2AgentStpMstTopologyChangeCount": "7",
                        "hm2AgentStpMstTimeSinceTopologyChange": "60000",
                    }],
                },
            },
            "errors": [],
        }

        rstp = self.backend.get_rstp()
        self.assertTrue(rstp["enabled"])
        self.assertEqual(rstp["mode"], "rstp")
        self.assertEqual(rstp["bridge_id"], "80:00:a0:b0:86:f4:ea:1f")
        self.assertEqual(rstp["priority"], 32768)
        self.assertEqual(rstp["hello_time"], 2)
        self.assertEqual(rstp["max_age"], 20)
        self.assertEqual(rstp["forward_delay"], 15)
        self.assertEqual(rstp["hold_count"], 10)
        self.assertEqual(rstp["max_hops"], 40)
        self.assertEqual(rstp["root_id"], "80:00:64:60:38:6a:7e:ac")
        self.assertEqual(rstp["root_port"], 5)
        self.assertEqual(rstp["root_path_cost"], 20000)
        self.assertEqual(rstp["topology_changes"], 7)
        self.assertEqual(rstp["time_since_topology_change"], 600)
        self.assertEqual(rstp["root_hello_time"], 2)
        self.assertEqual(rstp["root_max_age"], 20)
        self.assertEqual(rstp["root_forward_delay"], 15)
        self.assertFalse(rstp["bpdu_guard"])
        self.assertFalse(rstp["bpdu_filter"])

    def test_get_rstp_disabled(self):
        """Verify STP disabled state is parsed correctly."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentStpSwitchConfigGroup": [{
                        "hm2AgentStpForceVersion": "1",
                        "hm2AgentStpAdminMode": "2",
                        "hm2AgentStpBpduGuardMode": "1",
                        "hm2AgentStpBpduFilterDefault": "1",
                    }],
                    "hm2AgentStpCstConfigGroup": [{
                        "hm2AgentStpCstBridgePriority": "4096",
                        "hm2AgentStpCstBridgeHelloTime": "1",
                        "hm2AgentStpCstBridgeMaxAge": "10",
                        "hm2AgentStpCstBridgeFwdDelay": "5",
                        "hm2AgentStpCstBridgeHoldCount": "6",
                        "hm2AgentStpCstBridgeMaxHops": "20",
                        "hm2AgentStpCstHelloTime": "1",
                        "hm2AgentStpCstMaxAge": "10",
                        "hm2AgentStpCstRootFwdDelay": "5",
                    }],
                    "hm2AgentStpMstEntry": [{
                        "hm2AgentStpMstBridgeIdentifier":
                            "10 00 a0 b0 86 f4 ea 1f",
                        "hm2AgentStpMstDesignatedRootId": "",
                        "hm2AgentStpMstRootPortId": "00 00",
                        "hm2AgentStpMstRootPathCost": "200000",
                        "hm2AgentStpMstTopologyChangeCount": "0",
                        "hm2AgentStpMstTimeSinceTopologyChange": "0",
                    }],
                },
            },
            "errors": [],
        }

        rstp = self.backend.get_rstp()
        self.assertFalse(rstp["enabled"])
        self.assertEqual(rstp["mode"], "stp")
        self.assertEqual(rstp["priority"], 4096)
        self.assertTrue(rstp["bpdu_guard"])
        self.assertTrue(rstp["bpdu_filter"])
        self.assertEqual(rstp["root_path_cost"], 200000)
        self.assertEqual(rstp["bridge_id"], "10:00:a0:b0:86:f4:ea:1f")
        # Empty root ID when no root elected
        self.assertEqual(rstp["root_id"], "")
        self.assertEqual(rstp["root_port"], 0)
        self.assertEqual(rstp["topology_changes"], 0)

    # ----------------------------------------------------------------
    # get_rstp_port
    # ----------------------------------------------------------------

    def test_get_rstp_port(self):
        """Verify per-port STP fields from IF-MIB + STP tables."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "31 2f 31"},    # "1/1"
                        {"ifIndex": "2", "ifName": "31 2f 32"},    # "1/2"
                        {"ifIndex": "25", "ifName": "63 70 75 2f 31"},  # "cpu/1"
                    ],
                },
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentStpPortEntry": [
                        {"hm2AgentStpPortState": "1",
                         "hm2AgentStpPortStatsRstpBpduRx": "142",
                         "hm2AgentStpPortStatsRstpBpduTx": "305",
                         "hm2AgentStpPortStatsStpBpduRx": "0",
                         "hm2AgentStpPortStatsStpBpduTx": "0"},
                        {"hm2AgentStpPortState": "2",
                         "hm2AgentStpPortStatsRstpBpduRx": "0",
                         "hm2AgentStpPortStatsRstpBpduTx": "0",
                         "hm2AgentStpPortStatsStpBpduRx": "5",
                         "hm2AgentStpPortStatsStpBpduTx": "3"},
                        {"hm2AgentStpPortState": "1",
                         "hm2AgentStpPortStatsRstpBpduRx": "0",
                         "hm2AgentStpPortStatsRstpBpduTx": "0",
                         "hm2AgentStpPortStatsStpBpduRx": "0",
                         "hm2AgentStpPortStatsStpBpduTx": "0"},
                    ],
                    "hm2AgentStpCstPortEntry": [
                        {"hm2AgentStpCstPortEdge": "2",
                         "hm2AgentStpCstPortOperEdge": "2",
                         "hm2AgentStpCstPortAutoEdge": "1",
                         "hm2AgentStpCstPortForwardingState": "3",
                         "hm2AgentStpCstPortPathCost": "20000",
                         "hm2AgentStpCstPortPriority": "128",
                         "hm2AgentStpCstPortOperPointToPoint": "1",
                         "hm2AgentStpCstPortRootGuard": "2",
                         "hm2AgentStpCstPortLoopGuard": "2",
                         "hm2AgentStpCstPortTCNGuard": "2",
                         "hm2AgentStpCstPortBpduGuardEffect": "2",
                         "hm2AgentStpCstPortBpduFilter": "2",
                         "hm2AgentStpCstPortBpduFlood": "1"},
                        {"hm2AgentStpCstPortEdge": "1",
                         "hm2AgentStpCstPortOperEdge": "1",
                         "hm2AgentStpCstPortAutoEdge": "1",
                         "hm2AgentStpCstPortForwardingState": "4",
                         "hm2AgentStpCstPortPathCost": "200000",
                         "hm2AgentStpCstPortPriority": "64",
                         "hm2AgentStpCstPortOperPointToPoint": "2",
                         "hm2AgentStpCstPortRootGuard": "1",
                         "hm2AgentStpCstPortLoopGuard": "1",
                         "hm2AgentStpCstPortTCNGuard": "1",
                         "hm2AgentStpCstPortBpduGuardEffect": "1",
                         "hm2AgentStpCstPortBpduFilter": "1",
                         "hm2AgentStpCstPortBpduFlood": "2"},
                        {"hm2AgentStpCstPortEdge": "2",
                         "hm2AgentStpCstPortOperEdge": "2",
                         "hm2AgentStpCstPortAutoEdge": "2",
                         "hm2AgentStpCstPortForwardingState": "1",
                         "hm2AgentStpCstPortPathCost": "0",
                         "hm2AgentStpCstPortPriority": "128",
                         "hm2AgentStpCstPortOperPointToPoint": "1",
                         "hm2AgentStpCstPortRootGuard": "2",
                         "hm2AgentStpCstPortLoopGuard": "2",
                         "hm2AgentStpCstPortTCNGuard": "2",
                         "hm2AgentStpCstPortBpduGuardEffect": "2",
                         "hm2AgentStpCstPortBpduFilter": "2",
                         "hm2AgentStpCstPortBpduFlood": "2"},
                    ],
                },
            },
            "errors": [],
        }

        ports = self.backend.get_rstp_port()

        # cpu/1 should be excluded
        self.assertNotIn("cpu/1", ports)
        self.assertEqual(len(ports), 2)

        # Port 1/1 — enabled, forwarding, non-edge, auto-edge, p2p
        p1 = ports["1/1"]
        self.assertTrue(p1["enabled"])
        self.assertEqual(p1["state"], "forwarding")
        self.assertFalse(p1["edge_port"])
        self.assertFalse(p1["edge_port_oper"])
        self.assertTrue(p1["auto_edge"])
        self.assertTrue(p1["point_to_point"])
        self.assertEqual(p1["path_cost"], 20000)
        self.assertEqual(p1["priority"], 128)
        self.assertFalse(p1["root_guard"])
        self.assertFalse(p1["loop_guard"])
        self.assertFalse(p1["tcn_guard"])
        self.assertFalse(p1["bpdu_guard"])
        self.assertFalse(p1["bpdu_filter"])
        self.assertTrue(p1["bpdu_flood"])
        self.assertEqual(p1["rstp_bpdu_rx"], 142)
        self.assertEqual(p1["rstp_bpdu_tx"], 305)
        self.assertEqual(p1["stp_bpdu_rx"], 0)
        self.assertEqual(p1["stp_bpdu_tx"], 0)

        # Port 1/2 — disabled, disabled state, edge, guards active
        p2 = ports["1/2"]
        self.assertFalse(p2["enabled"])
        self.assertEqual(p2["state"], "disabled")
        self.assertTrue(p2["edge_port"])
        self.assertTrue(p2["edge_port_oper"])
        self.assertFalse(p2["point_to_point"])
        self.assertEqual(p2["path_cost"], 200000)
        self.assertEqual(p2["priority"], 64)
        self.assertTrue(p2["root_guard"])
        self.assertTrue(p2["loop_guard"])
        self.assertTrue(p2["tcn_guard"])
        self.assertTrue(p2["bpdu_guard"])
        self.assertTrue(p2["bpdu_filter"])
        self.assertFalse(p2["bpdu_flood"])
        self.assertEqual(p2["stp_bpdu_rx"], 5)
        self.assertEqual(p2["stp_bpdu_tx"], 3)

    def test_get_rstp_port_single(self):
        """Filter for a single interface returns only that port."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "31 2f 31"},
                        {"ifIndex": "2", "ifName": "31 2f 32"},
                    ],
                },
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentStpPortEntry": [
                        {"hm2AgentStpPortState": "1",
                         "hm2AgentStpPortStatsRstpBpduRx": "10",
                         "hm2AgentStpPortStatsRstpBpduTx": "20",
                         "hm2AgentStpPortStatsStpBpduRx": "0",
                         "hm2AgentStpPortStatsStpBpduTx": "0"},
                        {"hm2AgentStpPortState": "1",
                         "hm2AgentStpPortStatsRstpBpduRx": "30",
                         "hm2AgentStpPortStatsRstpBpduTx": "40",
                         "hm2AgentStpPortStatsStpBpduRx": "0",
                         "hm2AgentStpPortStatsStpBpduTx": "0"},
                    ],
                    "hm2AgentStpCstPortEntry": [
                        {"hm2AgentStpCstPortEdge": "2",
                         "hm2AgentStpCstPortOperEdge": "2",
                         "hm2AgentStpCstPortAutoEdge": "1",
                         "hm2AgentStpCstPortForwardingState": "3",
                         "hm2AgentStpCstPortPathCost": "20000",
                         "hm2AgentStpCstPortPriority": "128",
                         "hm2AgentStpCstPortOperPointToPoint": "1",
                         "hm2AgentStpCstPortRootGuard": "2",
                         "hm2AgentStpCstPortLoopGuard": "2",
                         "hm2AgentStpCstPortTCNGuard": "2",
                         "hm2AgentStpCstPortBpduGuardEffect": "2",
                         "hm2AgentStpCstPortBpduFilter": "2",
                         "hm2AgentStpCstPortBpduFlood": "2"},
                        {"hm2AgentStpCstPortEdge": "1",
                         "hm2AgentStpCstPortOperEdge": "1",
                         "hm2AgentStpCstPortAutoEdge": "1",
                         "hm2AgentStpCstPortForwardingState": "3",
                         "hm2AgentStpCstPortPathCost": "200000",
                         "hm2AgentStpCstPortPriority": "64",
                         "hm2AgentStpCstPortOperPointToPoint": "2",
                         "hm2AgentStpCstPortRootGuard": "2",
                         "hm2AgentStpCstPortLoopGuard": "2",
                         "hm2AgentStpCstPortTCNGuard": "2",
                         "hm2AgentStpCstPortBpduGuardEffect": "2",
                         "hm2AgentStpCstPortBpduFilter": "2",
                         "hm2AgentStpCstPortBpduFlood": "2"},
                    ],
                },
            },
            "errors": [],
        }

        ports = self.backend.get_rstp_port(interface="1/2")
        self.assertEqual(len(ports), 1)
        self.assertIn("1/2", ports)
        self.assertNotIn("1/1", ports)
        self.assertTrue(ports["1/2"]["edge_port"])
        self.assertEqual(ports["1/2"]["priority"], 64)

    # ----------------------------------------------------------------
    # set_rstp
    # ----------------------------------------------------------------

    def test_set_rstp_priority(self):
        """Verify set_multi is called with correct args for priority change."""
        # Mock get_rstp return for the verification read-back
        self.backend.get_rstp = Mock(return_value={
            'enabled': True, 'mode': 'rstp', 'priority': 4096,
        })

        result = self.backend.set_rstp(priority=4096)

        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstConfigGroup",
             {"hm2AgentStpCstBridgePriority": "4096"}),
        ])
        self.assertEqual(result["priority"], 4096)

    def test_set_rstp_enable_with_mode(self):
        """Enable STP and set mode in one call — two mutation groups."""
        self.backend.get_rstp = Mock(return_value={
            'enabled': True, 'mode': 'mstp',
        })

        self.backend.set_rstp(enabled=True, mode='mstp')

        self.backend.client.set_multi.assert_called_once()
        mutations = self.backend.client.set_multi.call_args[0][0]
        # Should have two groups: switch config + cst config (none for cst here)
        self.assertEqual(len(mutations), 1)
        mib, node, values = mutations[0]
        self.assertEqual(mib, "HM2-PLATFORM-SWITCHING-MIB")
        self.assertEqual(node, "hm2AgentStpSwitchConfigGroup")
        self.assertEqual(values["hm2AgentStpAdminMode"], "1")
        self.assertEqual(values["hm2AgentStpForceVersion"], "3")

    def test_set_rstp_all_params(self):
        """Verify all parameter types map to correct MIB attributes."""
        self.backend.get_rstp = Mock(return_value={'enabled': True})

        self.backend.set_rstp(
            enabled=False, mode='stp', priority=8192,
            hello_time=1, max_age=10, forward_delay=5,
            hold_count=6, bpdu_guard=True, bpdu_filter=True)

        mutations = self.backend.client.set_multi.call_args[0][0]
        # Two mutation groups: switch config + cst config
        self.assertEqual(len(mutations), 2)

        sw_mib, sw_node, sw_vals = mutations[0]
        self.assertEqual(sw_vals["hm2AgentStpAdminMode"], "2")
        self.assertEqual(sw_vals["hm2AgentStpForceVersion"], "1")
        self.assertEqual(sw_vals["hm2AgentStpBpduGuardMode"], "1")
        self.assertEqual(sw_vals["hm2AgentStpBpduFilterDefault"], "1")

        cst_mib, cst_node, cst_vals = mutations[1]
        self.assertEqual(cst_vals["hm2AgentStpCstBridgePriority"], "8192")
        self.assertEqual(cst_vals["hm2AgentStpCstBridgeHelloTime"], "1")
        self.assertEqual(cst_vals["hm2AgentStpCstBridgeMaxAge"], "10")
        self.assertEqual(cst_vals["hm2AgentStpCstBridgeFwdDelay"], "5")
        self.assertEqual(cst_vals["hm2AgentStpCstBridgeHoldCount"], "6")

    def test_set_rstp_no_params(self):
        """Calling set_rstp with no params should skip set_multi."""
        self.backend.get_rstp = Mock(return_value={'enabled': True})

        self.backend.set_rstp()

        self.backend.client.set_multi.assert_not_called()

    def test_set_rstp_mode_invalid(self):
        """Invalid mode should raise ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_rstp(mode='pvst')
        self.assertIn("Invalid mode", str(ctx.exception))

    # ----------------------------------------------------------------
    # set_rstp_port
    # ----------------------------------------------------------------

    def test_set_rstp_port_enable_disable(self):
        """Enable then disable a port — verify set_multi calls."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2", "5": "1/5"})
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "5": "1/5"}

        # Enable port 1/5
        self.backend.set_rstp_port("1/5", enabled=True)

        self.backend.client.set_multi.assert_called_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpPortEntry",
             {"hm2AgentStpPortState": "1"}, {"ifIndex": "5"}),
        ])

        self.backend.client.set_multi.reset_mock()

        # Disable port 1/5
        self.backend.set_rstp_port("1/5", enabled=False)

        self.backend.client.set_multi.assert_called_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpPortEntry",
             {"hm2AgentStpPortState": "2"}, {"ifIndex": "5"}),
        ])

    def test_set_rstp_port_cst_params(self):
        """Verify CST port parameters are sent via set_multi."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2"})
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}

        self.backend.set_rstp_port(
            "1/1", edge_port=True, auto_edge=False,
            path_cost=200000, priority=64,
            root_guard=True, loop_guard=True, tcn_guard=True,
            bpdu_filter=True, bpdu_flood=False)

        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstPortEntry",
             {
                 "hm2AgentStpCstPortEdge": "1",
                 "hm2AgentStpCstPortAutoEdge": "2",
                 "hm2AgentStpCstPortPathCost": "200000",
                 "hm2AgentStpCstPortPriority": "64",
                 "hm2AgentStpCstPortRootGuard": "1",
                 "hm2AgentStpCstPortLoopGuard": "1",
                 "hm2AgentStpCstPortTCNGuard": "1",
                 "hm2AgentStpCstPortBpduFilter": "1",
                 "hm2AgentStpCstPortBpduFlood": "2",
             }, {"ifIndex": "1"}),
        ])

    def test_set_rstp_port_enable_plus_cst(self):
        """Enable + CST params should produce two mutations in one set_multi."""
        self.backend._build_ifindex_map = Mock(
            return_value={"3": "1/3"})
        self.backend._ifindex_map = {"3": "1/3"}

        self.backend.set_rstp_port("1/3", enabled=True, edge_port=True)

        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpPortEntry",
             {"hm2AgentStpPortState": "1"}, {"ifIndex": "3"}),
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentStpCstPortEntry",
             {"hm2AgentStpCstPortEdge": "1"}, {"ifIndex": "3"}),
        ])

    def test_set_rstp_port_unknown_interface(self):
        """Unknown interface name should raise ValueError."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2"})
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}

        with self.assertRaises(ValueError) as ctx:
            self.backend.set_rstp_port("9/9", enabled=True)
        self.assertIn("Unknown interface", str(ctx.exception))

    def test_set_rstp_port_no_params(self):
        """No params beyond interface should skip set_multi entirely."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend._ifindex_map = {"1": "1/1"}

        self.backend.set_rstp_port("1/1")

        self.backend.client.set_multi.assert_not_called()


class TestAutoDisable(unittest.TestCase):
    """Test auto-disable getter/setters with mocked client."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True
        self.backend._ifindex_map = {
            "1": "1/1", "2": "1/2", "3": "1/3",
            "29": "cpu/1", "38": "vlan/1",
        }

    def _make_intf_entry(self, idx, timer=0, reason="0", oper="2",
                         remaining=0, error_time=0):
        return {
            "ifIndex": str(idx),
            "hm2AutoDisableIntfTimer": str(timer),
            "hm2AutoDisableIntfRemainingTime": str(remaining),
            "hm2AutoDisableIntfComponentName": "2d",
            "hm2AutoDisableIntfErrorReason": str(reason),
            "hm2AutoDisableIntfOperState": str(oper),
            "hm2AutoDisableIntfErrorTime": str(error_time),
        }

    def _make_reason_entry(self, idx, operation="2", category="1"):
        return {
            "hm2AutoDisableReasons": str(idx),
            "hm2AutoDisableReasonOperation": str(operation),
            "hm2AutoDisableReasonCategory": str(category),
        }

    def test_get_auto_disable_default(self):
        """All ports default: timer=0, no error, inactive."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DEVMGMT-MIB": {
                    "hm2AutoDisableIntfEntry": [
                        self._make_intf_entry(1),
                        self._make_intf_entry(2),
                        self._make_intf_entry(3),
                        self._make_intf_entry(29),  # cpu — should be skipped
                        self._make_intf_entry(38),  # vlan — should be skipped
                    ],
                    "hm2AutoDisableReasonEntry": [
                        self._make_reason_entry(1, "2", "2"),   # link-flap, disabled
                        self._make_reason_entry(6, "2", "4"),   # bpdu-rate, disabled
                        self._make_reason_entry(10, "2", "4"),  # loop-protection, disabled
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_auto_disable()
        # Only physical ports, no cpu/vlan
        self.assertEqual(sorted(result['interfaces'].keys()),
                         ['1/1', '1/2', '1/3'])
        # Default values
        port = result['interfaces']['1/1']
        self.assertEqual(port['timer'], 0)
        self.assertEqual(port['reason'], 'none')
        self.assertFalse(port['active'])
        self.assertEqual(port['component'], '')
        # Reasons
        self.assertIn('loop-protection', result['reasons'])
        self.assertFalse(result['reasons']['loop-protection']['enabled'])
        self.assertEqual(result['reasons']['loop-protection']['category'],
                         'l2-redundancy')
        self.assertFalse(result['reasons']['link-flap']['enabled'])
        self.assertEqual(result['reasons']['link-flap']['category'],
                         'port-monitor')

    def test_get_auto_disable_active_port(self):
        """Port with active auto-disable (loop protection triggered)."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DEVMGMT-MIB": {
                    "hm2AutoDisableIntfEntry": [
                        self._make_intf_entry(1, timer=30, reason="10",
                                              oper="1", remaining=25,
                                              error_time=1709078400),
                    ],
                    "hm2AutoDisableReasonEntry": [],
                },
            },
            "errors": [],
        }
        result = self.backend.get_auto_disable()
        port = result['interfaces']['1/1']
        self.assertEqual(port['timer'], 30)
        self.assertEqual(port['reason'], 'loop-protection')
        self.assertTrue(port['active'])
        self.assertEqual(port['remaining_time'], 25)
        self.assertEqual(port['error_time'], 1709078400)

    def test_get_auto_disable_component_dash(self):
        """Component '2d' (hex for '-') should decode to empty string."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DEVMGMT-MIB": {
                    "hm2AutoDisableIntfEntry": [
                        self._make_intf_entry(1),
                    ],
                    "hm2AutoDisableReasonEntry": [],
                },
            },
            "errors": [],
        }
        result = self.backend.get_auto_disable()
        self.assertEqual(result['interfaces']['1/1']['component'], '')

    def test_get_auto_disable_l2s_reduced_reasons(self):
        """L2S device: only 7 reasons (no dhcp-snooping, arp-rate, loop-protection)."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DEVMGMT-MIB": {
                    "hm2AutoDisableIntfEntry": [
                        self._make_intf_entry(1),
                    ],
                    "hm2AutoDisableReasonEntry": [
                        self._make_reason_entry(1, "2", "2"),
                        self._make_reason_entry(2, "2", "2"),
                        self._make_reason_entry(3, "2", "2"),
                        self._make_reason_entry(7, "2", "3"),
                        self._make_reason_entry(8, "2", "2"),
                        self._make_reason_entry(9, "2", "2"),
                        self._make_reason_entry(6, "2", "4"),
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_auto_disable()
        self.assertEqual(len(result['reasons']), 7)
        self.assertNotIn('loop-protection', result['reasons'])
        self.assertNotIn('dhcp-snooping', result['reasons'])
        self.assertNotIn('arp-rate', result['reasons'])

    def test_set_auto_disable_timer(self):
        """Set recovery timer on a port."""
        self.backend.set_auto_disable('1/1', timer=30)
        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-DEVMGMT-MIB", "hm2AutoDisableIntfEntry",
             {"hm2AutoDisableIntfTimer": "30"}, {"ifIndex": "1"}),
        ])

    def test_set_auto_disable_timer_zero(self):
        """Set timer to 0 (off)."""
        self.backend.set_auto_disable('1/2', timer=0)
        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-DEVMGMT-MIB", "hm2AutoDisableIntfEntry",
             {"hm2AutoDisableIntfTimer": "0"}, {"ifIndex": "2"}),
        ])

    def test_set_auto_disable_unknown_interface(self):
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_auto_disable('9/9', timer=30)
        self.assertIn("Unknown interface", str(ctx.exception))

    def test_reset_auto_disable(self):
        """Manual port re-enable writes true(1) to reset."""
        self.backend.reset_auto_disable('1/1')
        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-DEVMGMT-MIB", "hm2AutoDisableIntfEntry",
             {"hm2AutoDisableIntfReset": "1"}, {"ifIndex": "1"}),
        ])

    def test_reset_auto_disable_unknown_interface(self):
        with self.assertRaises(ValueError) as ctx:
            self.backend.reset_auto_disable('9/9')
        self.assertIn("Unknown interface", str(ctx.exception))

    def test_set_auto_disable_reason_enable(self):
        """Enable auto-disable for loop-protection reason."""
        self.backend.set_auto_disable_reason('loop-protection', enabled=True)
        self.backend.client.set_indexed.assert_called_once_with(
            "HM2-DEVMGMT-MIB", "hm2AutoDisableReasonEntry",
            index={"hm2AutoDisableReasons": "10"},
            values={"hm2AutoDisableReasonOperation": "1"})

    def test_set_auto_disable_reason_disable(self):
        self.backend.set_auto_disable_reason('link-flap', enabled=False)
        self.backend.client.set_indexed.assert_called_once_with(
            "HM2-DEVMGMT-MIB", "hm2AutoDisableReasonEntry",
            index={"hm2AutoDisableReasons": "1"},
            values={"hm2AutoDisableReasonOperation": "2"})

    def test_set_auto_disable_reason_unknown(self):
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_auto_disable_reason('bogus', enabled=True)
        self.assertIn("Unknown reason", str(ctx.exception))


class TestLoopProtection(unittest.TestCase):
    """Test loop protection getter/setters with mocked client."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True
        self.backend._ifindex_map = {
            "1": "1/1", "2": "1/2", "3": "1/3",
            "29": "cpu/1", "38": "vlan/1",
        }

    def _make_port_entry(self, idx, state="2", mode="2", action="11",
                         vlan="0", tpid="0", detected="2", count="0",
                         last_time="07 b2 01 01 00 00 00 00",
                         tx="0", rx="0", discard="0"):
        return {
            "ifIndex": str(idx),
            "hm2AgentKeepalivePortState": state,
            "hm2AgentKeepalivePortMode": mode,
            "hm2AgentKeepalivePortRxAction": action,
            "hm2AgentKeepalivePortVlanId": vlan,
            "hm2AgentKeepalivePortTpidType": tpid,
            "hm2AgentKeepalivePortLoopDetected": detected,
            "hm2AgentKeepalivePortLoopCount": count,
            "hm2AgentKeepalivePortLastLoopDetectedTime": last_time,
            "hm2AgentKeepalivePortTxFrameCount": tx,
            "hm2AgentKeepalivePortRxFrameCount": rx,
            "hm2AgentKeepalivePortDiscardFrameCount": discard,
        }

    def _make_global(self, state="2", interval="5", threshold="1"):
        return {
            "hm2AgentSwitchKeepaliveState": state,
            "hm2AgentSwitchKeepaliveTransmitInterval": interval,
            "hm2AgentSwitchKeepaliveRxThreshold": threshold,
        }

    def test_get_loop_protection_default(self):
        """Default state: disabled globally, all ports passive."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentSwitchKeepaliveGroup": [self._make_global()],
                    "hm2AgentKeepalivePortEntry": [
                        self._make_port_entry(1),
                        self._make_port_entry(2),
                        self._make_port_entry(29),  # cpu — skipped
                        self._make_port_entry(38),  # vlan — skipped
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_loop_protection()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['transmit_interval'], 5)
        self.assertEqual(result['receive_threshold'], 1)
        self.assertEqual(sorted(result['interfaces'].keys()), ['1/1', '1/2'])
        port = result['interfaces']['1/1']
        self.assertFalse(port['enabled'])
        self.assertEqual(port['mode'], 'passive')
        self.assertEqual(port['action'], 'auto-disable')
        self.assertEqual(port['vlan_id'], 0)
        self.assertEqual(port['tpid_type'], 'none')
        self.assertFalse(port['loop_detected'])
        self.assertEqual(port['last_loop_time'], '')

    def test_get_loop_protection_active_with_detection(self):
        """Port with active mode and a detected loop."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentSwitchKeepaliveGroup": [
                        self._make_global("1", "3", "2")],
                    "hm2AgentKeepalivePortEntry": [
                        self._make_port_entry(1, state="1", mode="1",
                                              action="12", detected="1",
                                              count="5", tx="100", rx="3",
                                              last_time="07 ea 02 1c 0e 1e 00 00"),
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_loop_protection()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['transmit_interval'], 3)
        self.assertEqual(result['receive_threshold'], 2)
        port = result['interfaces']['1/1']
        self.assertTrue(port['enabled'])
        self.assertEqual(port['mode'], 'active')
        self.assertEqual(port['action'], 'all')
        self.assertTrue(port['loop_detected'])
        self.assertEqual(port['loop_count'], 5)
        self.assertEqual(port['tx_frames'], 100)
        self.assertEqual(port['rx_frames'], 3)
        self.assertEqual(port['last_loop_time'], '2026-02-28 14:30:00')

    def test_get_loop_protection_l2s_empty(self):
        """L2S device: global MIB exists but port table is empty."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-PLATFORM-SWITCHING-MIB": {
                    "hm2AgentSwitchKeepaliveGroup": [
                        self._make_global("2", "0", "0")],
                    "hm2AgentKeepalivePortEntry": [],
                },
            },
            "errors": [],
        }
        result = self.backend.get_loop_protection()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['transmit_interval'], 0)
        self.assertEqual(result['receive_threshold'], 0)
        self.assertEqual(result['interfaces'], {})

    def test_set_loop_protection_per_port(self):
        """Set per-port: enabled, active, auto-disable."""
        self.backend.set_loop_protection('1/1', enabled=True, mode='active',
                                         action='auto-disable')
        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentKeepalivePortEntry",
             {
                 "hm2AgentKeepalivePortState": "1",
                 "hm2AgentKeepalivePortMode": "1",
                 "hm2AgentKeepalivePortRxAction": "11",
             }, {"ifIndex": "1"}),
        ])

    def test_set_loop_protection_per_port_passive(self):
        """Set ring port: enabled, passive (no action change)."""
        self.backend.set_loop_protection('1/2', enabled=True, mode='passive')
        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-PLATFORM-SWITCHING-MIB", "hm2AgentKeepalivePortEntry",
             {
                 "hm2AgentKeepalivePortState": "1",
                 "hm2AgentKeepalivePortMode": "2",
             }, {"ifIndex": "2"}),
        ])

    def test_set_loop_protection_per_port_unknown(self):
        with self.assertRaises(ValueError):
            self.backend.set_loop_protection('9/9', enabled=True)

    def test_set_loop_protection_per_port_bad_mode(self):
        with self.assertRaises(ValueError):
            self.backend.set_loop_protection('1/1', mode='bogus')

    def test_set_loop_protection_per_port_bad_action(self):
        with self.assertRaises(ValueError):
            self.backend.set_loop_protection('1/1', action='bogus')

    def test_set_loop_protection_global(self):
        """Set global: enable + interval + threshold."""
        self.backend.set_loop_protection(enabled=True, transmit_interval=3,
                                         receive_threshold=2)
        self.backend.client.set.assert_called_once_with(
            "HM2-PLATFORM-SWITCHING-MIB", "hm2AgentSwitchKeepaliveGroup",
            {
                "hm2AgentSwitchKeepaliveState": "1",
                "hm2AgentSwitchKeepaliveTransmitInterval": "3",
                "hm2AgentSwitchKeepaliveRxThreshold": "2",
            })

    def test_set_loop_protection_global_disable(self):
        """Disable global loop protection."""
        self.backend.set_loop_protection(enabled=False)
        self.backend.client.set.assert_called_once_with(
            "HM2-PLATFORM-SWITCHING-MIB", "hm2AgentSwitchKeepaliveGroup",
            {"hm2AgentSwitchKeepaliveState": "2"})


    # ------------------------------------------------------------------
    # VLAN ingress/egress getters
    # ------------------------------------------------------------------

    def test_get_vlan_ingress(self):
        """get_vlan_ingress returns per-port PVID, frame_types, ingress_filtering."""
        self.backend._ifindex_map = {
            "1": "1/1", "2": "1/2", "3": "1/3", "4": "1/4", "5": "1/5",
        }
        self.backend.client.get.return_value = [
            {"dot1dBasePort": "1", "dot1qPvid": "1",
             "dot1qPortAcceptableFrameTypes": "1", "dot1qPortIngressFiltering": "2"},
            {"dot1dBasePort": "2", "dot1qPvid": "5",
             "dot1qPortAcceptableFrameTypes": "2", "dot1qPortIngressFiltering": "1"},
            {"dot1dBasePort": "5", "dot1qPvid": "3",
             "dot1qPortAcceptableFrameTypes": "1", "dot1qPortIngressFiltering": "2"},
        ]

        result = self.backend.get_vlan_ingress()
        self.assertEqual(result["1/1"]["pvid"], 1)
        self.assertEqual(result["1/1"]["frame_types"], "admit_all")
        self.assertFalse(result["1/1"]["ingress_filtering"])
        self.assertEqual(result["1/2"]["pvid"], 5)
        self.assertEqual(result["1/2"]["frame_types"], "admit_only_tagged")
        self.assertTrue(result["1/2"]["ingress_filtering"])
        self.assertEqual(result["1/5"]["pvid"], 3)

    def test_get_vlan_ingress_port_filter(self):
        """get_vlan_ingress with port filtering returns only requested ports."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "3": "1/3"}
        self.backend.client.get.return_value = [
            {"dot1dBasePort": "1", "dot1qPvid": "1",
             "dot1qPortAcceptableFrameTypes": "1", "dot1qPortIngressFiltering": "2"},
            {"dot1dBasePort": "2", "dot1qPvid": "5",
             "dot1qPortAcceptableFrameTypes": "2", "dot1qPortIngressFiltering": "1"},
            {"dot1dBasePort": "3", "dot1qPvid": "10",
             "dot1qPortAcceptableFrameTypes": "1", "dot1qPortIngressFiltering": "2"},
        ]

        result = self.backend.get_vlan_ingress("1/2")
        self.assertEqual(len(result), 1)
        self.assertIn("1/2", result)
        self.assertEqual(result["1/2"]["pvid"], 5)

    def test_get_vlan_egress(self):
        """get_vlan_egress returns T/U/F per port per VLAN."""
        self.backend._ifindex_map = {
            "1": "1/1", "2": "1/2", "3": "1/3", "5": "1/5", "6": "1/6",
        }
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "1",
             "ieee8021QBridgeVlanStaticName": "default",
             "ieee8021QBridgeVlanStaticEgressPorts": "e0 00 00 00",  # ports 1,2,3
             "ieee8021QBridgeVlanStaticUntaggedPorts": "60 00 00 00",  # ports 2,3
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
            {"ieee8021QBridgeVlanStaticVlanIndex": "100",
             "ieee8021QBridgeVlanStaticName": "MRP",
             "ieee8021QBridgeVlanStaticEgressPorts": "c0 00 00 00",  # ports 1,2
             "ieee8021QBridgeVlanStaticUntaggedPorts": "00 00 00 00",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
        ]

        result = self.backend.get_vlan_egress()
        # VLAN 1: 1/1=tagged (in egress, not in untagged), 1/2=untagged, 1/3=untagged
        self.assertEqual(result[1]["name"], "default")
        self.assertEqual(result[1]["ports"]["1/1"], "tagged")
        self.assertEqual(result[1]["ports"]["1/2"], "untagged")
        self.assertEqual(result[1]["ports"]["1/3"], "untagged")
        # VLAN 100: 1/1=tagged, 1/2=tagged
        self.assertEqual(result[100]["name"], "MRP")
        self.assertEqual(result[100]["ports"]["1/1"], "tagged")
        self.assertEqual(result[100]["ports"]["1/2"], "tagged")

    def test_get_vlan_egress_port_filter(self):
        """get_vlan_egress with port filtering only includes requested ports."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "3": "1/3"}
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "1",
             "ieee8021QBridgeVlanStaticName": "default",
             "ieee8021QBridgeVlanStaticEgressPorts": "e0 00",
             "ieee8021QBridgeVlanStaticUntaggedPorts": "60 00",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
        ]

        result = self.backend.get_vlan_egress("1/1")
        self.assertEqual(result[1]["ports"], {"1/1": "tagged"})
        self.assertNotIn("1/2", result[1]["ports"])

    def test_get_vlan_egress_forbidden(self):
        """Ports in ForbiddenEgressPorts (not in Egress) show as 'forbidden'."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "10",
             "ieee8021QBridgeVlanStaticName": "TEST",
             "ieee8021QBridgeVlanStaticEgressPorts": "80 00",  # 1/1 only
             "ieee8021QBridgeVlanStaticUntaggedPorts": "80 00",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": "40 00"},  # 1/2 forbidden
        ]

        result = self.backend.get_vlan_egress()
        self.assertEqual(result[10]["ports"]["1/1"], "untagged")
        self.assertEqual(result[10]["ports"]["1/2"], "forbidden")

    def test_get_vlan_egress_empty_vlan_omitted(self):
        """VLANs with no matching ports after filtering are omitted."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "50",
             "ieee8021QBridgeVlanStaticName": "EMPTY",
             "ieee8021QBridgeVlanStaticEgressPorts": "80 00",  # 1/1
             "ieee8021QBridgeVlanStaticUntaggedPorts": "80 00",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
        ]

        result = self.backend.get_vlan_egress("1/2")
        self.assertNotIn(50, result)

    def test_get_vlan_egress_empty_vlan_included(self):
        """VLANs with zero port membership are included when unfiltered."""
        self.backend._ifindex_map = {"1": "1/1"}
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "999",
             "ieee8021QBridgeVlanStaticName": "45 6d 70 74 79",
             "ieee8021QBridgeVlanStaticEgressPorts": "00 00",
             "ieee8021QBridgeVlanStaticUntaggedPorts": "00 00",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
        ]

        result = self.backend.get_vlan_egress()
        self.assertIn(999, result)
        self.assertEqual(result[999]['ports'], {})

    # ------------------------------------------------------------------
    # VLAN ingress/egress setters
    # ------------------------------------------------------------------

    def test_set_vlan_ingress_pvid(self):
        """Set PVID on a port."""
        self.backend._ifindex_map = {"3": "1/3"}

        self.backend.set_vlan_ingress("1/3", pvid=100)

        self.backend.client.set_multi.assert_called_once_with([
            ("Q-BRIDGE-MIB", "dot1qPortVlanEntry",
             {"dot1qPvid": "100"}, {"dot1dBasePort": "3"}),
        ])

    def test_set_vlan_ingress_all_params(self):
        """Set PVID, frame_types, and ingress_filtering together."""
        self.backend._ifindex_map = {"3": "1/3"}

        self.backend.set_vlan_ingress("1/3", pvid=5,
                                      frame_types="admit_only_tagged",
                                      ingress_filtering=True)

        self.backend.client.set_multi.assert_called_once_with([
            ("Q-BRIDGE-MIB", "dot1qPortVlanEntry",
             {
                 "dot1qPvid": "5",
                 "dot1qPortAcceptableFrameTypes": "2",
                 "dot1qPortIngressFiltering": "1",
             }, {"dot1dBasePort": "3"}),
        ])

    def test_set_vlan_ingress_invalid_frame_types(self):
        self.backend._ifindex_map = {"3": "1/3"}
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_vlan_ingress("1/3", frame_types="invalid")
        self.assertIn("Invalid frame_types", str(ctx.exception))

    def test_set_vlan_ingress_unknown_port(self):
        self.backend._ifindex_map = {"3": "1/3"}
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_vlan_ingress("99/99", pvid=1)
        self.assertIn("Unknown interface", str(ctx.exception))

    def test_set_vlan_egress_tagged(self):
        """set_vlan_egress modifies bitmap and writes back via Q-BRIDGE."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "3": "1/3"}
        # Mock get_vlan_egress read path
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "10",
             "ieee8021QBridgeVlanStaticName": "TEST",
             "ieee8021QBridgeVlanStaticEgressPorts": "00 00 00 00",
             "ieee8021QBridgeVlanStaticUntaggedPorts": "ff ff ff ff",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
        ]
        self.backend.client.set_indexed.return_value = True

        self.backend.set_vlan_egress(10, "1/3", "tagged")

        calls = self.backend.client.set_indexed.call_args_list
        # Egress + Untagged in first call
        vals = calls[0].kwargs["values"]
        self.assertIn("dot1qVlanStaticEgressPorts", vals)
        self.assertIn("dot1qVlanStaticUntaggedPorts", vals)
        # Port 3 bit set in egress (0x20), cleared in untagged
        egress_hex = vals["dot1qVlanStaticEgressPorts"]
        self.assertTrue(egress_hex.startswith("20"))

    def test_set_vlan_egress_invalid_mode(self):
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_vlan_egress(10, "1/1", "invalid")
        self.assertIn("Invalid mode", str(ctx.exception))

    def test_set_vlan_egress_unknown_port(self):
        self.backend._ifindex_map = {"1": "1/1"}
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_vlan_egress(10, "99/99", "tagged")
        self.assertIn("Unknown interface", str(ctx.exception))

    def test_set_vlan_egress_nonexistent_vlan(self):
        """set_vlan_egress raises ValueError for non-existent VLAN."""
        self.backend._ifindex_map = {"1": "1/1"}
        self.backend.client.get.return_value = [
            {"ieee8021QBridgeVlanStaticVlanIndex": "1",
             "ieee8021QBridgeVlanStaticName": "default",
             "ieee8021QBridgeVlanStaticEgressPorts": "ff f0 00 00",
             "ieee8021QBridgeVlanStaticUntaggedPorts": "ff f0 00 00",
             "ieee8021QBridgeVlanStaticForbiddenEgressPorts": ""},
        ]
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_vlan_egress(999, "1/1", "tagged")
        self.assertIn("does not exist", str(ctx.exception))

    # ------------------------------------------------------------------
    # VLAN CRUD
    # ------------------------------------------------------------------

    def test_create_vlan(self):
        self.backend.client.set_indexed.return_value = True
        self.backend.create_vlan(100, "MGMT")
        self.backend.client.set_indexed.assert_called_once_with(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": "100"},
            values={
                "dot1qVlanStaticRowStatus": "4",
                "dot1qVlanStaticName": "4d 47 4d 54",  # hex "MGMT"
            })

    def test_create_vlan_no_name(self):
        self.backend.client.set_indexed.return_value = True
        self.backend.create_vlan(200)
        self.backend.client.set_indexed.assert_called_once_with(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": "200"},
            values={"dot1qVlanStaticRowStatus": "4"})

    def test_update_vlan(self):
        self.backend.client.set_indexed.return_value = True
        self.backend.update_vlan(100, "NEW-NAME")
        self.backend.client.set_indexed.assert_called_once_with(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": "100"},
            values={"dot1qVlanStaticName": "4e 45 57 2d 4e 41 4d 45"})

    def test_delete_vlan(self):
        self.backend.client.set_indexed.return_value = True
        self.backend.delete_vlan(100)
        self.backend.client.set_indexed.assert_called_once_with(
            "Q-BRIDGE-MIB", "dot1qVlanStaticEntry",
            index={"dot1qVlanIndex": "100"},
            values={"dot1qVlanStaticRowStatus": "6"})


class TestEncodePortlistHex(unittest.TestCase):
    """Test _encode_portlist_hex helper."""

    def test_encode_single_port(self):
        from napalm_hios.mops_hios import _encode_portlist_hex
        ifmap = {"1": "1/1", "2": "1/2", "3": "1/3"}
        result = _encode_portlist_hex(["1/1"], ifmap)
        self.assertEqual(result, "80")

    def test_encode_multiple_ports(self):
        from napalm_hios.mops_hios import _encode_portlist_hex
        ifmap = {"1": "1/1", "2": "1/2", "3": "1/3"}
        result = _encode_portlist_hex(["1/1", "1/2"], ifmap)
        self.assertEqual(result, "c0")

    def test_encode_empty(self):
        from napalm_hios.mops_hios import _encode_portlist_hex
        result = _encode_portlist_hex([], {"1": "1/1"})
        self.assertEqual(result, "")

    def test_encode_unknown_port_raises(self):
        from napalm_hios.mops_hios import _encode_portlist_hex
        with self.assertRaises(ValueError):
            _encode_portlist_hex(["99/99"], {"1": "1/1"})

    def test_roundtrip(self):
        """encode → decode should return the same ports."""
        from napalm_hios.mops_hios import _encode_portlist_hex
        ifmap = {"1": "1/1", "2": "1/2", "3": "1/3", "5": "1/5", "6": "1/6"}
        original = ["1/1", "1/3", "1/5"]
        encoded = _encode_portlist_hex(original, ifmap)
        decoded = _decode_portlist_hex(encoded, ifmap)
        self.assertEqual(sorted(decoded), sorted(original))


# ------------------------------------------------------------------
# sFlow helpers
# ------------------------------------------------------------------


class TestEncodeHexIp(unittest.TestCase):
    """Test _encode_hex_ip helper."""

    def test_encode_standard(self):
        self.assertEqual(_encode_hex_ip("192.168.1.4"), "c0 a8 01 04")

    def test_encode_zeros(self):
        self.assertEqual(_encode_hex_ip("0.0.0.0"), "00 00 00 00")

    def test_encode_broadcast(self):
        self.assertEqual(_encode_hex_ip("255.255.255.255"), "ff ff ff ff")

    def test_roundtrip(self):
        from napalm_hios.mops_hios import _decode_hex_ip
        ip = "10.2.1.4"
        self.assertEqual(_decode_hex_ip(_encode_hex_ip(ip)), ip)


# ------------------------------------------------------------------
# sFlow getters
# ------------------------------------------------------------------


class TestSFlowGetters(unittest.TestCase):
    """Test sFlow getter methods with mocked client."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_sflow(self):
        """get_sflow returns agent info + 8 receivers."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SFLOW-MIB": {
                    "sFlowAgent": [{
                        "sFlowVersion": "31 2e 33 3b 48 69 72 73 63 68 6d 61 6e 6e 3b 31 30 2e 33 2e 30 34",
                        "sFlowAgentAddressType": "1",
                        "sFlowAgentAddress": "c0 a8 01 04",
                    }],
                    "sFlowRcvrEntry": [
                        {"sFlowRcvrIndex": "1", "sFlowRcvrOwner": "31",
                         "sFlowRcvrTimeout": "151306",
                         "sFlowRcvrMaximumDatagramSize": "1400",
                         "sFlowRcvrAddressType": "1",
                         "sFlowRcvrAddress": "0a 02 01 04",
                         "sFlowRcvrPort": "6343",
                         "sFlowRcvrDatagramVersion": "5"},
                        {"sFlowRcvrIndex": "2", "sFlowRcvrOwner": "",
                         "sFlowRcvrTimeout": "0",
                         "sFlowRcvrMaximumDatagramSize": "1400",
                         "sFlowRcvrAddressType": "1",
                         "sFlowRcvrAddress": "00 00 00 00",
                         "sFlowRcvrPort": "6343",
                         "sFlowRcvrDatagramVersion": "5"},
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_sflow()
        self.assertEqual(result['agent_version'], '1.3;Hirschmann;10.3.04')
        self.assertEqual(result['agent_address'], '192.168.1.4')
        self.assertIn(1, result['receivers'])
        self.assertIn(2, result['receivers'])

        r1 = result['receivers'][1]
        self.assertEqual(r1['owner'], '1')
        self.assertEqual(r1['address'], '10.2.1.4')
        self.assertEqual(r1['timeout'], 151306)
        self.assertEqual(r1['port'], 6343)
        self.assertEqual(r1['datagram_version'], 5)

        r2 = result['receivers'][2]
        self.assertEqual(r2['owner'], '')
        self.assertEqual(r2['address'], '0.0.0.0')
        self.assertEqual(r2['timeout'], 0)

    def test_get_sflow_port(self):
        """get_sflow_port returns sampler + poller per port."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "25": "cpu/1"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SFLOW-MIB": {
                    "sFlowFsEntry": [
                        {"sFlowFsDataSource": "1.3.6.1.2.1.2.2.1.1.1",
                         "sFlowFsInstance": "1", "sFlowFsReceiver": "2",
                         "sFlowFsPacketSamplingRate": "256",
                         "sFlowFsMaximumHeaderSize": "128"},
                        {"sFlowFsDataSource": "1.3.6.1.2.1.2.2.1.1.2",
                         "sFlowFsInstance": "1", "sFlowFsReceiver": "0",
                         "sFlowFsPacketSamplingRate": "0",
                         "sFlowFsMaximumHeaderSize": "128"},
                        {"sFlowFsDataSource": "1.3.6.1.2.1.2.2.1.1.25",
                         "sFlowFsInstance": "1", "sFlowFsReceiver": "0",
                         "sFlowFsPacketSamplingRate": "0",
                         "sFlowFsMaximumHeaderSize": "128"},
                    ],
                    "sFlowCpEntry": [
                        {"sFlowCpDataSource": "1.3.6.1.2.1.2.2.1.1.1",
                         "sFlowCpInstance": "1", "sFlowCpReceiver": "2",
                         "sFlowCpInterval": "20"},
                        {"sFlowCpDataSource": "1.3.6.1.2.1.2.2.1.1.2",
                         "sFlowCpInstance": "1", "sFlowCpReceiver": "0",
                         "sFlowCpInterval": "0"},
                        {"sFlowCpDataSource": "1.3.6.1.2.1.2.2.1.1.25",
                         "sFlowCpInstance": "1", "sFlowCpReceiver": "0",
                         "sFlowCpInterval": "0"},
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_sflow_port()
        self.assertIn("1/1", result)
        self.assertIn("1/2", result)
        self.assertNotIn("cpu/1", result)

        s1 = result["1/1"]["sampler"]
        self.assertEqual(s1["receiver"], 2)
        self.assertEqual(s1["sample_rate"], 256)
        self.assertEqual(s1["max_header_size"], 128)

        p1 = result["1/1"]["poller"]
        self.assertEqual(p1["receiver"], 2)
        self.assertEqual(p1["interval"], 20)

        s2 = result["1/2"]["sampler"]
        self.assertEqual(s2["receiver"], 0)
        self.assertEqual(s2["sample_rate"], 0)

    def test_get_sflow_port_filter_interfaces(self):
        """get_sflow_port with interface filter returns only requested ports."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SFLOW-MIB": {
                    "sFlowFsEntry": [
                        {"sFlowFsDataSource": "1.3.6.1.2.1.2.2.1.1.1",
                         "sFlowFsInstance": "1", "sFlowFsReceiver": "0",
                         "sFlowFsPacketSamplingRate": "0",
                         "sFlowFsMaximumHeaderSize": "128"},
                        {"sFlowFsDataSource": "1.3.6.1.2.1.2.2.1.1.2",
                         "sFlowFsInstance": "1", "sFlowFsReceiver": "0",
                         "sFlowFsPacketSamplingRate": "0",
                         "sFlowFsMaximumHeaderSize": "128"},
                    ],
                    "sFlowCpEntry": [
                        {"sFlowCpDataSource": "1.3.6.1.2.1.2.2.1.1.1",
                         "sFlowCpInstance": "1", "sFlowCpReceiver": "0",
                         "sFlowCpInterval": "0"},
                        {"sFlowCpDataSource": "1.3.6.1.2.1.2.2.1.1.2",
                         "sFlowCpInstance": "1", "sFlowCpReceiver": "0",
                         "sFlowCpInterval": "0"},
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_sflow_port(['1/1'])
        self.assertIn("1/1", result)
        self.assertNotIn("1/2", result)

    def test_get_sflow_port_type_sampler(self):
        """get_sflow_port with type='sampler' returns only sampler keys."""
        self.backend._ifindex_map = {"1": "1/1"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SFLOW-MIB": {
                    "sFlowFsEntry": [
                        {"sFlowFsDataSource": "1.3.6.1.2.1.2.2.1.1.1",
                         "sFlowFsInstance": "1", "sFlowFsReceiver": "0",
                         "sFlowFsPacketSamplingRate": "0",
                         "sFlowFsMaximumHeaderSize": "128"},
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_sflow_port(type='sampler')
        self.assertIn("sampler", result["1/1"])
        self.assertNotIn("poller", result["1/1"])

    def test_get_sflow_port_type_poller(self):
        """get_sflow_port with type='poller' returns only poller keys."""
        self.backend._ifindex_map = {"1": "1/1"}
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "SFLOW-MIB": {
                    "sFlowCpEntry": [
                        {"sFlowCpDataSource": "1.3.6.1.2.1.2.2.1.1.1",
                         "sFlowCpInstance": "1", "sFlowCpReceiver": "0",
                         "sFlowCpInterval": "0"},
                    ],
                },
            },
            "errors": [],
        }

        result = self.backend.get_sflow_port(type='poller')
        self.assertIn("poller", result["1/1"])
        self.assertNotIn("sampler", result["1/1"])


# ------------------------------------------------------------------
# sFlow setters
# ------------------------------------------------------------------


class TestSFlowSetters(unittest.TestCase):
    """Test sFlow setter methods with mocked client."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True
        self.backend._ifindex_map = {
            "1": "1/1", "2": "1/2", "3": "1/3",
        }
        # Mock get_sflow for read-back after set
        self.backend.get_sflow = Mock(return_value={
            'agent_version': '1.3;Hirschmann;10.3.04',
            'agent_address': '192.168.1.4',
            'receivers': {},
        })

    def test_set_sflow_owner_then_address(self):
        """set_sflow sends owner as separate SET, then address."""
        self.backend.set_sflow(2, owner='snoop', address='192.168.1.100',
                               timeout=-1)
        calls = self.backend.client.set_indexed.call_args_list
        # Call 1: owner
        self.assertEqual(calls[0].kwargs['values'],
                         {"sFlowRcvrOwner": "73 6e 6f 6f 70"})
        self.assertEqual(calls[0].kwargs['index'],
                         {"sFlowRcvrIndex": "2"})
        # Call 2: address + timeout
        vals = calls[1].kwargs['values']
        self.assertEqual(vals["sFlowRcvrAddress"], "c0 a8 01 64")
        self.assertEqual(vals["sFlowRcvrAddressType"], "1")
        self.assertEqual(vals["sFlowRcvrTimeout"], "-1")

    def test_set_sflow_address_only(self):
        """set_sflow with address only sends one SET (no owner)."""
        self.backend.set_sflow(1, address='192.168.1.100')
        self.backend.client.set_indexed.assert_called_once_with(
            "SFLOW-MIB", "sFlowRcvrEntry",
            index={"sFlowRcvrIndex": "1"},
            values={"sFlowRcvrAddress": "c0 a8 01 64",
                    "sFlowRcvrAddressType": "1"})

    def test_set_sflow_release(self):
        """set_sflow with owner='' sends empty owner to release."""
        self.backend.set_sflow(2, owner='')
        self.backend.client.set_indexed.assert_called_once_with(
            "SFLOW-MIB", "sFlowRcvrEntry",
            index={"sFlowRcvrIndex": "2"},
            values={"sFlowRcvrOwner": ""})

    def test_set_sflow_invalid_receiver(self):
        with self.assertRaises(ValueError):
            self.backend.set_sflow(0)
        with self.assertRaises(ValueError):
            self.backend.set_sflow(9)

    def test_set_sflow_port_bind(self):
        """set_sflow_port binds sampler + poller to receiver."""
        self.backend.set_sflow_port(['1/1', '1/2'], receiver=2,
                                    sample_rate=256, interval=20)
        mutations = self.backend.client.set_multi.call_args[0][0]
        # 4 mutations: sampler+poller for each of 2 ports
        self.assertEqual(len(mutations), 4)

        # Port 1/1 sampler
        mib, node, vals, idx = mutations[0]
        self.assertEqual(mib, "SFLOW-MIB")
        self.assertEqual(node, "sFlowFsEntry")
        self.assertEqual(vals["sFlowFsReceiver"], "2")
        self.assertEqual(vals["sFlowFsPacketSamplingRate"], "256")
        self.assertEqual(idx["sFlowFsDataSource"],
                         "1.3.6.1.2.1.2.2.1.1.1")
        self.assertEqual(idx["sFlowFsInstance"], "1")

        # Port 1/1 poller
        mib, node, vals, idx = mutations[1]
        self.assertEqual(node, "sFlowCpEntry")
        self.assertEqual(vals["sFlowCpReceiver"], "2")
        self.assertEqual(vals["sFlowCpInterval"], "20")

        # Port 1/2 sampler
        mib, node, vals, idx = mutations[2]
        self.assertEqual(idx["sFlowFsDataSource"],
                         "1.3.6.1.2.1.2.2.1.1.2")

    def test_set_sflow_port_unbind(self):
        """set_sflow_port with receiver=0 sends only receiver field."""
        self.backend.set_sflow_port('1/1', receiver=0,
                                    sample_rate=0, interval=0)
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(len(mutations), 2)

        # Sampler: only receiver, no rate
        mib, node, vals, idx = mutations[0]
        self.assertEqual(vals, {"sFlowFsReceiver": "0"})
        self.assertNotIn("sFlowFsPacketSamplingRate", vals)

        # Poller: only receiver, no interval
        mib, node, vals, idx = mutations[1]
        self.assertEqual(vals, {"sFlowCpReceiver": "0"})
        self.assertNotIn("sFlowCpInterval", vals)

    def test_set_sflow_port_sampler_only(self):
        """set_sflow_port with sample_rate only touches sampler table."""
        self.backend.set_sflow_port('1/1', receiver=1, sample_rate=512)
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][1], "sFlowFsEntry")

    def test_set_sflow_port_poller_only(self):
        """set_sflow_port with interval only touches poller table."""
        self.backend.set_sflow_port('1/1', receiver=1, interval=30)
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][1], "sFlowCpEntry")

    def test_set_sflow_port_max_header_size(self):
        """set_sflow_port passes max_header_size to sampler."""
        self.backend.set_sflow_port('1/1', receiver=1, sample_rate=256,
                                    max_header_size=256)
        mutations = self.backend.client.set_multi.call_args[0][0]
        vals = mutations[0][2]
        self.assertEqual(vals["sFlowFsMaximumHeaderSize"], "256")

    def test_set_sflow_port_no_rate_or_interval_raises(self):
        with self.assertRaises(ValueError):
            self.backend.set_sflow_port('1/1', receiver=1)

    def test_set_sflow_port_unknown_interface(self):
        with self.assertRaises(ValueError):
            self.backend.set_sflow_port('9/9', receiver=1, sample_rate=256)

    def test_set_sflow_port_single_string(self):
        """set_sflow_port accepts a single string interface."""
        self.backend.set_sflow_port('1/1', receiver=1, sample_rate=256)
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(len(mutations), 1)

    def test_set_sflow_staging(self):
        """set_sflow in staging mode queues mutations."""
        self.backend._staging = True
        self.backend._mutations = []
        self.backend.set_sflow(1, owner='test')
        # Should queue, not call client
        self.backend.client.set_indexed.assert_not_called()
        self.assertEqual(len(self.backend._mutations), 1)

    def test_set_sflow_port_staging(self):
        """set_sflow_port in staging mode queues mutations."""
        self.backend._staging = True
        self.backend._mutations = []
        self.backend.set_sflow_port('1/1', receiver=1, sample_rate=256)
        self.backend.client.set_multi.assert_not_called()
        self.assertEqual(len(self.backend._mutations), 1)


    # ------------------------------------------------------------------
    # Storm Control
    # ------------------------------------------------------------------

    def _make_storm_global(self, bucket_type="2"):
        return {"hm2TrafficMgmtIngressStormBucketType": bucket_type}

    def _make_storm_port(self, ifidx, unit="1", bcast_mode="2",
                         bcast_thresh="0", mcast_mode="2", mcast_thresh="0",
                         ucast_mode="2", ucast_thresh="0"):
        return {
            "ifIndex": str(ifidx),
            "hm2TrafficMgmtIfIngressStormCtlThresholdUnit": unit,
            "hm2TrafficMgmtIfIngressStormCtlBcastMode": bcast_mode,
            "hm2TrafficMgmtIfIngressStormCtlBcastThreshold": bcast_thresh,
            "hm2TrafficMgmtIfIngressStormCtlMcastMode": mcast_mode,
            "hm2TrafficMgmtIfIngressStormCtlMcastThreshold": mcast_thresh,
            "hm2TrafficMgmtIfIngressStormCtlUcastMode": ucast_mode,
            "hm2TrafficMgmtIfIngressStormCtlUcastThreshold": ucast_thresh,
        }

    def _storm_response(self, global_entry, port_entries):
        return {
            "mibs": {
                "HM2-TRAFFICMGMT-MIB": {
                    "hm2TrafficMgmtMibObjects": [global_entry],
                    "hm2TrafficMgmtIfEntry": port_entries,
                },
            },
            "errors": [],
        }

    def test_get_storm_control_default(self):
        """All ports disabled, percent unit, multi-bucket."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2", "25": "cpu/1"}
        self.backend.client.get_multi.return_value = self._storm_response(
            self._make_storm_global("2"),
            [self._make_storm_port(1), self._make_storm_port(2),
             self._make_storm_port(25)],
        )
        result = self.backend.get_storm_control()
        self.assertEqual(result['bucket_type'], 'multi-bucket')
        self.assertEqual(sorted(result['interfaces'].keys()), ['1/1', '1/2'])
        port = result['interfaces']['1/1']
        self.assertEqual(port['unit'], 'percent')
        self.assertFalse(port['broadcast']['enabled'])
        self.assertEqual(port['broadcast']['threshold'], 0)
        self.assertFalse(port['multicast']['enabled'])
        self.assertFalse(port['unicast']['enabled'])

    def test_get_storm_control_active_port(self):
        """Port with broadcast enabled at 100 pps."""
        self.backend._ifindex_map = {"11": "1/11"}
        self.backend.client.get_multi.return_value = self._storm_response(
            self._make_storm_global("2"),
            [self._make_storm_port(11, unit="2", bcast_mode="1",
                                   bcast_thresh="100")],
        )
        result = self.backend.get_storm_control()
        port = result['interfaces']['1/11']
        self.assertEqual(port['unit'], 'pps')
        self.assertTrue(port['broadcast']['enabled'])
        self.assertEqual(port['broadcast']['threshold'], 100)
        self.assertFalse(port['multicast']['enabled'])

    def test_get_storm_control_single_bucket(self):
        """Device reports single-bucket capability."""
        self.backend._ifindex_map = {"1": "1/1"}
        self.backend.client.get_multi.return_value = self._storm_response(
            self._make_storm_global("1"),
            [self._make_storm_port(1)],
        )
        result = self.backend.get_storm_control()
        self.assertEqual(result['bucket_type'], 'single-bucket')

    def test_get_storm_control_skips_cpu_vlan(self):
        """cpu/ and vlan/ pseudo-interfaces are excluded."""
        self.backend._ifindex_map = {
            "1": "1/1", "25": "cpu/1", "100": "vlan/1"}
        self.backend.client.get_multi.return_value = self._storm_response(
            self._make_storm_global(),
            [self._make_storm_port(1), self._make_storm_port(25),
             self._make_storm_port(100)],
        )
        result = self.backend.get_storm_control()
        self.assertEqual(list(result['interfaces'].keys()), ['1/1'])

    def test_set_storm_control_single_port(self):
        """Set broadcast 100 pps on one port."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2"})
        self.backend.set_storm_control(
            '1/1', unit='pps', broadcast_enabled=True,
            broadcast_threshold=100)
        self.backend.client.set_multi.assert_called_once_with([
            ("HM2-TRAFFICMGMT-MIB", "hm2TrafficMgmtIfEntry",
             {
                 "hm2TrafficMgmtIfIngressStormCtlThresholdUnit": "2",
                 "hm2TrafficMgmtIfIngressStormCtlBcastMode": "1",
                 "hm2TrafficMgmtIfIngressStormCtlBcastThreshold": "100",
             }, {"ifIndex": "1"}),
        ])

    def test_set_storm_control_multi_port(self):
        """Set on multiple ports — one set_multi call."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2", "3": "1/3"})
        self.backend.set_storm_control(
            ['1/1', '1/2'], unit='pps', broadcast_enabled=True,
            broadcast_threshold=100)
        call_args = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(len(call_args), 2)
        self.assertEqual(call_args[0][3], {"ifIndex": "1"})
        self.assertEqual(call_args[1][3], {"ifIndex": "2"})

    def test_set_storm_control_disable(self):
        """Disable broadcast storm control."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend.set_storm_control('1/1', broadcast_enabled=False)
        call_args = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(call_args[0][2],
                         {"hm2TrafficMgmtIfIngressStormCtlBcastMode": "2"})

    def test_set_storm_control_all_types(self):
        """Set all three storm types at once."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend.set_storm_control(
            '1/1', broadcast_enabled=True, broadcast_threshold=100,
            multicast_enabled=True, multicast_threshold=200,
            unicast_enabled=True, unicast_threshold=300)
        values = self.backend.client.set_multi.call_args[0][0][0][2]
        self.assertEqual(values["hm2TrafficMgmtIfIngressStormCtlBcastMode"], "1")
        self.assertEqual(values["hm2TrafficMgmtIfIngressStormCtlBcastThreshold"], "100")
        self.assertEqual(values["hm2TrafficMgmtIfIngressStormCtlMcastMode"], "1")
        self.assertEqual(values["hm2TrafficMgmtIfIngressStormCtlMcastThreshold"], "200")
        self.assertEqual(values["hm2TrafficMgmtIfIngressStormCtlUcastMode"], "1")
        self.assertEqual(values["hm2TrafficMgmtIfIngressStormCtlUcastThreshold"], "300")

    def test_set_storm_control_bad_unit(self):
        with self.assertRaises(ValueError):
            self.backend.set_storm_control('1/1', unit='bps')

    def test_set_storm_control_bad_port(self):
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        with self.assertRaises(ValueError):
            self.backend.set_storm_control('9/9', broadcast_enabled=True)

    def test_set_storm_control_noop(self):
        """No args = no mutation, no set_multi call."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend.set_storm_control('1/1')
        self.backend.client.set_multi.assert_not_called()

    def test_set_storm_control_staging(self):
        """Staging mode queues mutations."""
        self.backend._staging = True
        self.backend._mutations = []
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend.set_storm_control('1/1', unit='pps')
        self.backend.client.set_multi.assert_not_called()
        self.assertEqual(len(self.backend._mutations), 1)


class TestManagementMOPS(unittest.TestCase):
    """Test MOPS get_management / set_management."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_management(self):
        """Parse management network config from MOPS."""
        self.backend.client.get.return_value = [{
            "hm2NetConfigProtocol": "1",   # none/local
            "hm2NetVlanID": "1",
            "hm2NetLocalIPAddr": "c0 a8 01 04",  # 192.168.1.4
            "hm2NetPrefixLength": "24",
            "hm2NetGatewayIPAddr": "c0 a8 01 fe",  # 192.168.1.254
            "hm2NetMgmtPort": "0",
            "hm2NetDHCPClientId": "",
            "hm2NetDHCPClientLeaseTime": "0",
            "hm2NetDHCPClientConfigLoad": "1",  # enabled
            "hm2NetVlanPriority": "0",
            "hm2NetIpDscpPriority": "0",
            "hm2NetIPv6AdminStatus": "1",  # enabled
            "hm2NetIPv6ConfigProtocol": "2",  # auto
        }]

        result = self.backend.get_management()
        self.assertEqual(result['protocol'], 'local')
        self.assertEqual(result['vlan_id'], 1)
        self.assertEqual(result['ip_address'], '192.168.1.4')
        self.assertEqual(result['netmask'], '255.255.255.0')
        self.assertEqual(result['gateway'], '192.168.1.254')
        self.assertEqual(result['mgmt_port'], 0)
        self.assertTrue(result['dhcp_option_66_67'])
        self.assertEqual(result['dot1p'], 0)
        self.assertEqual(result['ip_dscp'], 0)
        self.assertTrue(result['ipv6_enabled'])
        self.assertEqual(result['ipv6_protocol'], 'auto')

    def test_get_management_dhcp(self):
        """Parse management config with DHCP."""
        self.backend.client.get.return_value = [{
            "hm2NetConfigProtocol": "3",  # dhcp
            "hm2NetVlanID": "100",
            "hm2NetLocalIPAddr": "0a 00 00 32",  # 10.0.0.50
            "hm2NetPrefixLength": "16",
            "hm2NetGatewayIPAddr": "0a 00 00 01",
            "hm2NetMgmtPort": "0",
            "hm2NetDHCPClientId": "42 52 53 35 30",  # BRS50
            "hm2NetDHCPClientLeaseTime": "86400",
            "hm2NetDHCPClientConfigLoad": "2",  # disabled
            "hm2NetVlanPriority": "5",
            "hm2NetIpDscpPriority": "46",
            "hm2NetIPv6AdminStatus": "2",  # disabled
            "hm2NetIPv6ConfigProtocol": "1",  # none
        }]

        result = self.backend.get_management()
        self.assertEqual(result['protocol'], 'dhcp')
        self.assertEqual(result['vlan_id'], 100)
        self.assertEqual(result['ip_address'], '10.0.0.50')
        self.assertEqual(result['netmask'], '255.255.0.0')
        self.assertFalse(result['dhcp_option_66_67'])
        self.assertEqual(result['dot1p'], 5)
        self.assertEqual(result['ip_dscp'], 46)
        self.assertFalse(result['ipv6_enabled'])

    def test_get_management_empty(self):
        """Empty response returns empty dict."""
        self.backend.client.get.return_value = []
        result = self.backend.get_management()
        self.assertEqual(result, {})

    def test_set_management_vlan_validation(self):
        """Rejects VLAN that doesn't exist."""
        self.backend.get_vlans = Mock(
            return_value={1: {'name': 'default', 'interfaces': []}})
        with self.assertRaises(ValueError) as ctx:
            self.backend.set_management(vlan_id=999)
        self.assertIn('999', str(ctx.exception))
        self.assertIn('does not exist', str(ctx.exception))

    def test_set_management_vlan_range(self):
        """Rejects out-of-range VLAN."""
        with self.assertRaises(ValueError):
            self.backend.set_management(vlan_id=0)
        with self.assertRaises(ValueError):
            self.backend.set_management(vlan_id=5000)

    def test_set_management_bad_protocol(self):
        """Rejects invalid protocol."""
        with self.assertRaises(ValueError):
            self.backend.set_management(protocol='ospf')

    def test_set_management_ip_triggers_activate(self):
        """IP address change includes hm2NetAction=activate."""
        self.backend.client.get.return_value = [{
            "hm2NetConfigProtocol": "1", "hm2NetVlanID": "1",
            "hm2NetLocalIPAddr": "c0 a8 01 05",
            "hm2NetPrefixLength": "24",
            "hm2NetGatewayIPAddr": "c0 a8 01 fe",
            "hm2NetMgmtPort": "0",
            "hm2NetDHCPClientId": "",
            "hm2NetDHCPClientLeaseTime": "0",
            "hm2NetDHCPClientConfigLoad": "1",
            "hm2NetVlanPriority": "0", "hm2NetIpDscpPriority": "0",
            "hm2NetIPv6AdminStatus": "1", "hm2NetIPv6ConfigProtocol": "2",
        }]
        self.backend.set_management(ip_address='192.168.1.5')
        call_args = self.backend.client.set.call_args
        values = call_args[0][2]
        self.assertEqual(values['hm2NetLocalIPAddr'], 'c0 a8 01 05')
        self.assertEqual(values['hm2NetAction'], '2')

    def test_set_management_no_change(self):
        """No args returns current config without SET."""
        self.backend.client.get.return_value = [{
            "hm2NetConfigProtocol": "1", "hm2NetVlanID": "1",
            "hm2NetLocalIPAddr": "c0 a8 01 04",
            "hm2NetPrefixLength": "24",
            "hm2NetGatewayIPAddr": "c0 a8 01 fe",
            "hm2NetMgmtPort": "0",
            "hm2NetDHCPClientId": "",
            "hm2NetDHCPClientLeaseTime": "0",
            "hm2NetDHCPClientConfigLoad": "1",
            "hm2NetVlanPriority": "0", "hm2NetIpDscpPriority": "0",
            "hm2NetIPv6AdminStatus": "1", "hm2NetIPv6ConfigProtocol": "2",
        }]
        result = self.backend.set_management()
        self.backend.client.set.assert_not_called()
        self.assertEqual(result['ip_address'], '192.168.1.4')


class TestConfigMOPS(unittest.TestCase):
    """Test MOPS get_config, load_config, get_config_remote, set_config_remote."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    # --- set_snmp_information ---

    def test_set_snmp_information_hostname(self):
        """Set only hostname."""
        self.backend.client.get.return_value = [
            {"sysContact": "admin", "sysLocation": "Lab",
             "sysName": "TEST-HOST"}]
        self.backend.set_snmp_information(hostname='TEST-HOST')
        call_args = self.backend.client.set.call_args
        self.assertEqual(call_args[0][0], "SNMPv2-MIB")
        self.assertEqual(call_args[0][1], "system")
        values = call_args[0][2]
        self.assertIn("sysName", values)
        self.assertNotIn("sysContact", values)
        self.assertNotIn("sysLocation", values)

    def test_set_snmp_information_all(self):
        """Set hostname, contact, and location."""
        self.backend.client.get.return_value = [
            {"sysContact": "test", "sysLocation": "loc",
             "sysName": "host"}]
        self.backend.set_snmp_information(
            hostname='H', contact='C', location='L')
        values = self.backend.client.set.call_args[0][2]
        self.assertIn("sysName", values)
        self.assertIn("sysContact", values)
        self.assertIn("sysLocation", values)

    def test_set_snmp_information_no_args(self):
        """No args returns None without calling set."""
        result = self.backend.set_snmp_information()
        self.assertIsNone(result)
        self.backend.client.set.assert_not_called()

    def test_set_snmp_information_hex_encodes(self):
        """Values should be hex-encoded for MOPS."""
        self.backend.client.get.return_value = [
            {"sysContact": "", "sysLocation": "", "sysName": ""}]
        self.backend.set_snmp_information(hostname='Lab')
        values = self.backend.client.set.call_args[0][2]
        self.assertEqual(values["sysName"], "4c 61 62")

    # --- get_config (HTTPS download) ---

    def test_get_config_default(self):
        """Downloads active profile config via HTTPS."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'CLAMPS', 'active': True, 'index': 1}])
        self.backend.client.download_config.return_value = '<?xml version="1.0"?><Config/>'
        result = self.backend.get_config()
        self.assertEqual(result['running'], '<?xml version="1.0"?><Config/>')
        self.assertEqual(result['startup'], '')
        self.assertEqual(result['candidate'], '')
        self.backend.client.download_config.assert_called_once_with(
            'CLAMPS', source='nvm')

    def test_get_config_explicit_profile(self):
        """Explicit profile bypasses active profile lookup."""
        self.backend.client.download_config.return_value = '<Config/>'
        result = self.backend.get_config(profile='Test123')
        self.backend.client.download_config.assert_called_once_with(
            'Test123', source='nvm')
        self.backend.get_profiles = Mock()
        self.backend.get_profiles.assert_not_called()

    def test_get_config_no_active_profile(self):
        """Raises ValueError if no active profile found."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'old', 'active': False}])
        with self.assertRaises(ValueError) as ctx:
            self.backend.get_config()
        self.assertIn("No active profile", str(ctx.exception))

    def test_get_config_envm(self):
        """Source=envm passed through to download."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'ACA', 'active': True}])
        self.backend.client.download_config.return_value = '<Config/>'
        self.backend.get_config(source='envm')
        self.backend.client.download_config.assert_called_once_with(
            'ACA', source='envm')

    # --- load_config (HTTPS upload) ---

    def test_load_config_default(self):
        """Uploads to active profile by default."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'CLAMPS', 'active': True}])
        self.backend.client.upload_config.return_value = True
        result = self.backend.load_config('<Config/>')
        self.assertTrue(result)
        self.backend.client.upload_config.assert_called_once_with(
            '<Config/>', 'CLAMPS', destination='nvm')

    def test_load_config_explicit_profile(self):
        """Explicit profile bypasses lookup."""
        self.backend.client.upload_config.return_value = True
        self.backend.load_config('<Config/>', profile='Test123')
        self.backend.client.upload_config.assert_called_once_with(
            '<Config/>', 'Test123', destination='nvm')

    def test_load_config_no_active_profile(self):
        """Raises ValueError if no active profile."""
        self.backend.get_profiles = Mock(return_value=[])
        with self.assertRaises(ValueError):
            self.backend.load_config('<Config/>')

    # --- get_config_remote ---

    def test_get_config_remote(self):
        """Parse remote backup settings from MOPS."""
        self.backend.client.get.side_effect = [
            # First call: server access group
            [{"hm2FMServerUserName": "61 64 6d 69 6e"}],  # "admin"
            # Second call: remote save group
            [{"hm2FMConfigRemoteSaveAdminStatus": "1",
              "hm2FMConfigRemoteSaveDestination":
                  "74 66 74 70 3a 2f 2f 31 30 2e 32 2e 31 2e 34 2f"
                  " 74 65 73 74 2e 78 6d 6c",  # "tftp://10.2.1.4/test.xml"
              "hm2FMConfigRemoteSaveUsername": "62 61 63 6b 75 70"}],  # "backup"
        ]
        result = self.backend.get_config_remote()
        self.assertEqual(result['server_username'], 'admin')
        self.assertTrue(result['auto_backup']['enabled'])
        self.assertEqual(result['auto_backup']['destination'],
                         'tftp://10.2.1.4/test.xml')
        self.assertEqual(result['auto_backup']['username'], 'backup')

    def test_get_config_remote_disabled(self):
        """Auto-backup disabled, empty fields."""
        self.backend.client.get.side_effect = [
            [{"hm2FMServerUserName": ""}],
            [{"hm2FMConfigRemoteSaveAdminStatus": "2",
              "hm2FMConfigRemoteSaveDestination": "",
              "hm2FMConfigRemoteSaveUsername": ""}],
        ]
        result = self.backend.get_config_remote()
        self.assertEqual(result['server_username'], '')
        self.assertFalse(result['auto_backup']['enabled'])
        self.assertEqual(result['auto_backup']['destination'], '')

    # --- set_config_remote ---

    def test_set_config_remote_auto_backup_url(self):
        """Set auto-backup destination URL."""
        # After set, returns get_config_remote
        self.backend.client.get.side_effect = [
            [{"hm2FMServerUserName": ""}],
            [{"hm2FMConfigRemoteSaveAdminStatus": "2",
              "hm2FMConfigRemoteSaveDestination": "",
              "hm2FMConfigRemoteSaveUsername": ""}],
        ]
        self.backend.set_config_remote(
            auto_backup_url='tftp://10.2.1.4/test/%p-%d.xml')
        # Verify the SET call
        call_args = self.backend.client.set.call_args
        self.assertEqual(call_args[0][0], "HM2-FILEMGMT-MIB")
        self.assertEqual(call_args[0][1], "hm2FileMgmtConfigRemoteSaveGroup")
        values = call_args[0][2]
        self.assertIn("hm2FMConfigRemoteSaveDestination", values)

    def test_set_config_remote_enable_backup(self):
        """Enable auto-backup."""
        self.backend.client.get.side_effect = [
            [{"hm2FMServerUserName": ""}],
            [{"hm2FMConfigRemoteSaveAdminStatus": "1",
              "hm2FMConfigRemoteSaveDestination": "",
              "hm2FMConfigRemoteSaveUsername": ""}],
        ]
        self.backend.set_config_remote(auto_backup=True)
        call_args = self.backend.client.set.call_args
        values = call_args[0][2]
        self.assertEqual(values["hm2FMConfigRemoteSaveAdminStatus"], "1")

    def test_set_config_remote_server_creds(self):
        """Set server username/password."""
        self.backend.client.get.side_effect = [
            [{"hm2FMServerUserName": ""}],
            [{"hm2FMConfigRemoteSaveAdminStatus": "2",
              "hm2FMConfigRemoteSaveDestination": "",
              "hm2FMConfigRemoteSaveUsername": ""}],
        ]
        self.backend.set_config_remote(username='admin', password='secret')
        # First set call is for server credentials
        first_call = self.backend.client.set.call_args_list[0]
        self.assertEqual(first_call[0][0], "HM2-FILEMGMT-MIB")
        self.assertEqual(first_call[0][1], "hm2FileMgmtServerAccessGroup")
        values = first_call[0][2]
        self.assertIn("hm2FMServerUserName", values)
        self.assertIn("hm2FMServerPassword", values)

    def test_set_config_remote_push(self):
        """One-shot push triggers config_transfer."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'CLAMPS', 'active': True}])
        self.backend.client.config_transfer.return_value = {
            'hm2FMActionStatus': '1', 'hm2FMActionResult': '1'}
        result = self.backend.set_config_remote(
            action='push', server='tftp://10.2.1.4/test.xml')
        self.backend.client.config_transfer.assert_called_once_with(
            action='push', server_url='tftp://10.2.1.4/test.xml',
            source_type='2', dest_type='20',
            source_data='CLAMPS', dest_data='tftp://10.2.1.4/test.xml')

    def test_set_config_remote_pull(self):
        """One-shot pull triggers config_transfer."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'CLAMPS', 'active': True}])
        self.backend.client.config_transfer.return_value = {
            'hm2FMActionStatus': '1', 'hm2FMActionResult': '1'}
        result = self.backend.set_config_remote(
            action='pull', server='tftp://10.2.1.4/test.xml')
        self.backend.client.config_transfer.assert_called_once_with(
            action='pull', server_url='tftp://10.2.1.4/test.xml',
            source_type='20', dest_type='2',
            source_data='tftp://10.2.1.4/test.xml', dest_data='CLAMPS')

    def test_set_config_remote_invalid_action(self):
        """Invalid action raises ValueError."""
        self.backend.get_profiles = Mock(return_value=[
            {'name': 'X', 'active': True}])
        with self.assertRaises(ValueError):
            self.backend.set_config_remote(action='delete', server='x')

    # --- set_mrp advanced_mode ---

    def test_set_mrp_advanced_mode_enable(self):
        """Set advanced_mode=True on existing domain."""
        self.backend._build_ifindex_map = Mock(return_value={
            "5": "1/5", "6": "1/6"})
        self.backend.client.set_indexed.return_value = True

        self.backend.set_mrp(advanced_mode=True)

        calls = self.backend.client.set_indexed.call_args_list
        # createAndWait, notInService, set params, activate
        params = calls[2].kwargs['values']
        self.assertEqual(params["hm2MrpMRMReactOnLinkChange"], "1")

    def test_set_mrp_advanced_mode_disable(self):
        """Set advanced_mode=False on existing domain."""
        self.backend._build_ifindex_map = Mock(return_value={
            "5": "1/5", "6": "1/6"})
        self.backend.client.set_indexed.return_value = True

        self.backend.set_mrp(advanced_mode=False)

        calls = self.backend.client.set_indexed.call_args_list
        params = calls[2].kwargs['values']
        self.assertEqual(params["hm2MrpMRMReactOnLinkChange"], "2")


class TestMOPSWatchdog(unittest.TestCase):
    """Test MOPS watchdog methods."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_watchdog_status_disabled(self):
        """Watchdog disabled returns correct shape."""
        self.backend.client.get.return_value = [{
            "hm2ConfigWatchdogAdminStatus": "2",
            "hm2ConfigWatchdogOperStatus": "2",
            "hm2ConfigWatchdogTimeInterval": "0",
            "hm2ConfigWatchdogTimerValue": "0",
        }]
        result = self.backend.get_watchdog_status()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['oper_status'], 2)
        self.assertEqual(result['interval'], 0)
        self.assertEqual(result['remaining'], 0)

    def test_get_watchdog_status_enabled(self):
        """Watchdog enabled with timer running."""
        self.backend.client.get.return_value = [{
            "hm2ConfigWatchdogAdminStatus": "1",
            "hm2ConfigWatchdogOperStatus": "1",
            "hm2ConfigWatchdogTimeInterval": "30",
            "hm2ConfigWatchdogTimerValue": "25",
        }]
        result = self.backend.get_watchdog_status()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['oper_status'], 1)
        self.assertEqual(result['interval'], 30)
        self.assertEqual(result['remaining'], 25)

    def test_start_watchdog(self):
        """start_watchdog calls _apply_set with correct args."""
        self.backend.client.set.return_value = True
        self.backend.start_watchdog(30)
        self.backend.client.set.assert_called_once_with(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtConfigWatchdogControl",
            {"hm2ConfigWatchdogTimeInterval": "30",
             "hm2ConfigWatchdogAdminStatus": "1"})

    def test_start_watchdog_invalid_range(self):
        """start_watchdog rejects values outside 30-600."""
        with self.assertRaises(ValueError):
            self.backend.start_watchdog(10)
        with self.assertRaises(ValueError):
            self.backend.start_watchdog(700)

    def test_stop_watchdog(self):
        """stop_watchdog disables admin status."""
        self.backend.client.set.return_value = True
        self.backend.stop_watchdog()
        self.backend.client.set.assert_called_once_with(
            "HM2-FILEMGMT-MIB", "hm2FileMgmtConfigWatchdogControl",
            {"hm2ConfigWatchdogAdminStatus": "2"})


class TestMOPSLoginPolicy(unittest.TestCase):
    """Test MOPS login policy getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_login_policy(self):
        """get_login_policy returns correct shape."""
        self.backend.client.get.return_value = [{
            "hm2PwdMgmtMinLength": "8",
            "hm2PwdMgmtLoginAttempts": "5",
            "hm2PwdMgmtLoginAttemptsTimePeriod": "300",
            "hm2PwdMgmtMinUpperCase": "2",
            "hm2PwdMgmtMinLowerCase": "2",
            "hm2PwdMgmtMinNumericNumbers": "1",
            "hm2PwdMgmtMinSpecialCharacters": "1",
        }]
        result = self.backend.get_login_policy()
        self.assertEqual(result['min_password_length'], 8)
        self.assertEqual(result['max_login_attempts'], 5)
        self.assertEqual(result['lockout_duration'], 300)
        self.assertEqual(result['min_uppercase'], 2)
        self.assertEqual(result['min_lowercase'], 2)
        self.assertEqual(result['min_numeric'], 1)
        self.assertEqual(result['min_special'], 1)

    def test_get_login_policy_defaults(self):
        """Missing attributes use factory defaults."""
        self.backend.client.get.return_value = [{}]
        result = self.backend.get_login_policy()
        self.assertEqual(result['min_password_length'], 6)
        self.assertEqual(result['max_login_attempts'], 0)
        self.assertEqual(result['lockout_duration'], 0)

    def test_set_login_policy_partial(self):
        """set_login_policy only sets provided kwargs."""
        self.backend.client.set.return_value = True
        self.backend.set_login_policy(min_password_length=10)
        call_args = self.backend.client.set.call_args
        values = call_args[0][2]
        self.assertEqual(values["hm2PwdMgmtMinLength"], "10")
        self.assertEqual(len(values), 1)

    def test_set_login_policy_noop(self):
        """set_login_policy with no args is a no-op."""
        self.backend.set_login_policy()
        self.backend.client.set.assert_not_called()


class TestMOPSSyslog(unittest.TestCase):
    """Test MOPS syslog getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_syslog_disabled_no_servers(self):
        """Syslog disabled, no server entries."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{"hm2LogSyslogAdminStatus": "2"}],
            MOPSError("no entries"),
        ]
        result = self.backend.get_syslog()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['servers'], [])

    def test_get_syslog_with_servers(self):
        """Syslog enabled with server entries."""
        self.backend.client.get.side_effect = [
            [{"hm2LogSyslogAdminStatus": "1"}],
            [
                {
                    "hm2LogSyslogServerIndex": "1",
                    "hm2LogSyslogServerIPAddr": "0a 02 01 04",
                    "hm2LogSyslogServerUdpPort": "514",
                    "hm2LogSyslogServerLevelUpto": "6",
                    "hm2LogSyslogServerTransportType": "1",
                },
            ],
        ]
        result = self.backend.get_syslog()
        self.assertTrue(result['enabled'])
        self.assertEqual(len(result['servers']), 1)
        srv = result['servers'][0]
        self.assertEqual(srv['index'], 1)
        self.assertEqual(srv['ip'], '10.2.1.4')
        self.assertEqual(srv['port'], 514)
        self.assertEqual(srv['severity'], 'informational')
        self.assertEqual(srv['transport'], 'udp')

    def test_set_syslog_enable(self):
        """set_syslog enables global syslog."""
        self.backend.client.set.return_value = True
        self.backend.client.set_multi = Mock()
        self.backend.set_syslog(enabled=True)


class TestMOPSNtp(unittest.TestCase):
    """Test MOPS NTP getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_ntp_disabled_no_servers(self):
        """NTP client disabled, no servers."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{"hm2SntpClientAdminState": "2"}],
            MOPSError("no entries"),
            MOPSError("no NTP server"),
        ]
        result = self.backend.get_ntp()
        self.assertFalse(result['client']['enabled'])
        self.assertEqual(result['client']['mode'], 'sntp')
        self.assertEqual(result['client']['servers'], [])
        self.assertFalse(result['server']['enabled'])

    def test_get_ntp_enabled_with_server(self):
        """NTP client enabled with servers."""
        self.backend.client.get.side_effect = [
            [{"hm2SntpClientAdminState": "1"}],
            [{
                "hm2SntpClientServerIndex": "1",
                "hm2SntpClientServerAddr": "0a 02 01 01",
                "hm2SntpClientServerPort": "123",
                "hm2SntpClientServerOperStatus": "2",
                "hm2SntpClientServerDescription": "",
            }],
            [{"hm2NtpServerAdminState": "2", "hm2NtpServerStratum": "1"}],
        ]
        result = self.backend.get_ntp()
        self.assertTrue(result['client']['enabled'])
        self.assertEqual(len(result['client']['servers']), 1)
        self.assertEqual(result['client']['servers'][0]['address'], '10.2.1.1')

    def test_set_ntp_client_enable(self):
        """set_ntp enables client."""
        self.backend.client.set.return_value = True
        self.backend.client.set_multi = Mock()
        self.backend.set_ntp(client_enabled=True)


class TestMOPSServices(unittest.TestCase):
    """Test MOPS services getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def _mock_mgmt_response(self):
        return {"mibs": {
            "HM2-MGMTACCESS-MIB": {
                "hm2MgmtAccessWebGroup": [{
                    "hm2WebHttpAdminStatus": "1",
                    "hm2WebHttpsAdminStatus": "1",
                    "hm2WebHttpPortNumber": "80",
                    "hm2WebHttpsPortNumber": "443",
                }],
                "hm2MgmtAccessSshGroup": [{
                    "hm2SshAdminStatus": "1",
                }],
                "hm2MgmtAccessTelnetGroup": [{
                    "hm2TelnetServerAdminStatus": "2",
                }],
                "hm2MgmtAccessSnmpGroup": [{
                    "hm2SnmpV1AdminStatus": "2",
                    "hm2SnmpV2AdminStatus": "2",
                    "hm2SnmpV3AdminStatus": "1",
                    "hm2SnmpPortNumber": "161",
                }],
            },
        }, "errors": []}

    def _mock_industrial_response(self):
        return {"mibs": {
            "HM2-INDUSTRIAL-PROTOCOLS-MIB": {
                "hm2Iec61850ConfigGroup": [{
                    "hm2Iec61850MmsServerAdminStatus": "2",
                }],
                "hm2ProfinetIOConfigGroup": [{
                    "hm2PNIOAdminStatus": "2",
                }],
                "hm2EthernetIPConfigGroup": [{
                    "hm2EtherNetIPAdminStatus": "2",
                }],
                "hm2Iec62541ConfigGroup": [{
                    "hm2Iec62541OpcUaServerAdminStatus": "2",
                }],
                "hm2ModbusConfigGroup": [{
                    "hm2ModbusTcpServerAdminStatus": "2",
                }],
            },
        }, "errors": []}

    def _mock_ext_response(self, unsigned="2", mvrp="2", mmrp="2",
                           devsec_val="1"):
        """Extended scalars: unsigned_sw, MVRP, MMRP, DevSec monitors.

        Based on live BRS50 10.3.04 responses — 19 DevSec monitors.
        """
        devsec_attrs = {a: devsec_val for a in [
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
        ]}
        return {"mibs": {
            "HM2-DEVMGMT-MIB": {
                "hm2DeviceMgmtSoftwareVersionGroup": [{
                    "hm2DevMgmtSwVersAllowUnsigned": unsigned,
                }],
            },
            "HM2-PLATFORM-MVRP-MIB": {
                "hm2AgentDot1qMvrp": [{
                    "hm2AgentDot1qBridgeMvrpMode": mvrp,
                }],
            },
            "HM2-PLATFORM-MMRP-MIB": {
                "hm2AgentDot1qMmrp": [{
                    "hm2AgentDot1qBridgeMmrpMode": mmrp,
                }],
            },
            "HM2-DIAGNOSTIC-MIB": {
                "hm2DevSecConfigGroup": [devsec_attrs],
            },
        }, "errors": []}

    def _mock_aca_rows(self, auto="2", save="2", load="0"):
        """ACA / ExtNVM table rows (sd + usb)."""
        return [
            {"hm2ExtNvmTableIndex": "1",
             "hm2ExtNvmAutomaticSoftwareLoad": auto,
             "hm2ExtNvmConfigSave": save,
             "hm2ExtNvmConfigLoadPriority": load},
            {"hm2ExtNvmTableIndex": "2",
             "hm2ExtNvmAutomaticSoftwareLoad": auto,
             "hm2ExtNvmConfigSave": save,
             "hm2ExtNvmConfigLoadPriority": load},
        ]

    def test_get_services(self):
        """get_services returns correct shape with all fields."""
        self.backend.client.get_multi.side_effect = [
            self._mock_mgmt_response(),
            self._mock_industrial_response(),
            self._mock_ext_response(),
        ]
        self.backend.client.get.return_value = self._mock_aca_rows()
        result = self.backend.get_services()
        self.assertTrue(result['http']['enabled'])
        self.assertEqual(result['http']['port'], 80)
        self.assertTrue(result['https']['enabled'])
        self.assertTrue(result['ssh']['enabled'])
        self.assertFalse(result['telnet']['enabled'])
        self.assertFalse(result['snmp']['v1'])
        self.assertFalse(result['snmp']['v2'])
        self.assertTrue(result['snmp']['v3'])
        self.assertEqual(result['snmp']['port'], 161)
        self.assertFalse(result['industrial']['iec61850'])
        self.assertFalse(result['industrial']['profinet'])
        self.assertFalse(result['industrial']['ethernet_ip'])
        self.assertFalse(result['industrial']['opcua'])
        self.assertFalse(result['industrial']['modbus'])
        # New fields
        self.assertFalse(result['unsigned_sw'])
        self.assertFalse(result['mvrp'])
        self.assertFalse(result['mmrp'])
        self.assertTrue(result['devsec_monitors'])
        self.assertFalse(result['aca_auto_update'])
        self.assertFalse(result['aca_config_write'])
        self.assertFalse(result['aca_config_load'])
        self.assertFalse(result['gvrp'])
        self.assertFalse(result['gmrp'])

    def test_get_services_unsigned_sw_enabled(self):
        """get_services detects unsigned_sw=True."""
        self.backend.client.get_multi.side_effect = [
            self._mock_mgmt_response(),
            self._mock_industrial_response(),
            self._mock_ext_response(unsigned="1"),
        ]
        self.backend.client.get.return_value = self._mock_aca_rows()
        result = self.backend.get_services()
        self.assertTrue(result['unsigned_sw'])

    def test_get_services_aca_enabled(self):
        """get_services detects ACA fields when any NVM row enabled."""
        self.backend.client.get_multi.side_effect = [
            self._mock_mgmt_response(),
            self._mock_industrial_response(),
            self._mock_ext_response(),
        ]
        self.backend.client.get.return_value = self._mock_aca_rows(
            auto="1", save="1", load="1")
        result = self.backend.get_services()
        self.assertTrue(result['aca_auto_update'])
        self.assertTrue(result['aca_config_write'])
        self.assertTrue(result['aca_config_load'])

    def test_get_services_mvrp_mmrp_enabled(self):
        """get_services detects MVRP/MMRP enabled."""
        self.backend.client.get_multi.side_effect = [
            self._mock_mgmt_response(),
            self._mock_industrial_response(),
            self._mock_ext_response(mvrp="1", mmrp="1"),
        ]
        self.backend.client.get.return_value = self._mock_aca_rows()
        result = self.backend.get_services()
        self.assertTrue(result['mvrp'])
        self.assertTrue(result['mmrp'])

    def test_get_services_devsec_some_disabled(self):
        """devsec_monitors is False when any monitor disabled."""
        ext = self._mock_ext_response(devsec_val="1")
        # Disable one monitor
        ext["mibs"]["HM2-DIAGNOSTIC-MIB"]["hm2DevSecConfigGroup"][0][
            "hm2DevSecSenseSysmonEnabled"] = "2"
        self.backend.client.get_multi.side_effect = [
            self._mock_mgmt_response(),
            self._mock_industrial_response(),
            ext,
        ]
        self.backend.client.get.return_value = self._mock_aca_rows()
        result = self.backend.get_services()
        self.assertFalse(result['devsec_monitors'])

    def test_get_services_selective(self):
        """get_services('unsigned_sw') only queries ext batch."""
        self.backend.client.get_multi.side_effect = [
            self._mock_ext_response(unsigned="1"),
        ]
        result = self.backend.get_services('unsigned_sw')
        self.assertTrue(result['unsigned_sw'])
        # Only 1 get_multi call (ext), no client.get (aca)
        self.assertEqual(self.backend.client.get_multi.call_count, 1)
        self.backend.client.get.assert_not_called()

    def test_get_services_selective_aca(self):
        """get_services('aca_auto_update') only queries aca batch."""
        self.backend.client.get.return_value = self._mock_aca_rows(
            auto="1")
        result = self.backend.get_services('aca_auto_update')
        self.assertTrue(result['aca_auto_update'])
        self.backend.client.get_multi.assert_not_called()

    def test_set_services_single(self):
        """set_services with one kwarg."""
        self.backend.client.set.return_value = True
        self.backend.client.set_multi = Mock()
        self.backend.set_services(telnet=True)

    def test_set_services_noop(self):
        """set_services with no args is a no-op."""
        self.backend.set_services()
        self.backend.client.set.assert_not_called()
        self.backend.client.set_multi.assert_not_called()

    def test_set_services_unsigned_sw(self):
        """set_services(unsigned_sw=False) sends correct mutation."""
        self.backend.client.set_multi = Mock()
        self.backend.set_services(unsigned_sw=False)
        self.backend.client.set_multi.assert_called_once()
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(mutations[0][0], "HM2-DEVMGMT-MIB")
        self.assertEqual(mutations[0][2][
            "hm2DevMgmtSwVersAllowUnsigned"], "2")

    def test_set_services_mvrp_mmrp(self):
        """set_services(mvrp=False, mmrp=False) sends two mutations."""
        self.backend.client.set_multi = Mock()
        self.backend.set_services(mvrp=False, mmrp=False)
        self.backend.client.set_multi.assert_called_once()
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(len(mutations), 2)

    def test_set_services_devsec_monitors(self):
        """set_services(devsec_monitors=True) sets all 19 DevSec attrs."""
        self.backend.client.set_multi = Mock()
        self.backend.set_services(devsec_monitors=True)
        self.backend.client.set_multi.assert_called_once()
        mutations = self.backend.client.set_multi.call_args[0][0]
        self.assertEqual(mutations[0][0], "HM2-DIAGNOSTIC-MIB")
        # All 19 DevSec attrs set to "1"
        self.assertEqual(len(mutations[0][2]), 19)
        for v in mutations[0][2].values():
            self.assertEqual(v, "1")

    def test_set_services_aca_auto_update(self):
        """set_services(aca_auto_update=False) sets on all NVM rows."""
        self.backend.client.set_multi = Mock()
        self.backend.client.get.return_value = [
            {"hm2ExtNvmTableIndex": "1"},
            {"hm2ExtNvmTableIndex": "2"},
        ]
        self.backend.client.set_indexed = Mock()
        self.backend.set_services(aca_auto_update=False)
        # set_multi not called (no scalar mutations)
        self.backend.client.set_multi.assert_not_called()
        # set_indexed called once per NVM row
        self.assertEqual(
            self.backend.client.set_indexed.call_count, 2)
        for call in self.backend.client.set_indexed.call_args_list:
            self.assertEqual(call[0][0], "HM2-DEVMGMT-MIB")
            self.assertEqual(
                call[1]["values"]["hm2ExtNvmAutomaticSoftwareLoad"],
                "2")


class TestMOPSSnmpConfig(unittest.TestCase):
    """Test MOPS SNMP config getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_snmp_config(self):
        """get_snmp_config returns versions + communities."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{
                "hm2SnmpV1AdminStatus": "2",
                "hm2SnmpV2AdminStatus": "2",
                "hm2SnmpV3AdminStatus": "1",
                "hm2SnmpPortNumber": "161",
                "hm2SnmpTrapServiceAdminStatus": "2",
            }],
            [{
                "snmpCommunityIndex": "70 75 62 6c 69 63",
                "snmpCommunityName": "70 75 62 6c 69 63",
                "snmpCommunitySecurityName": "72 65 61 64 4f 6e 6c 79",
            }],
            MOPSError("no user table"),   # v3 users
            MOPSError("no target addr"),  # trap addr
            MOPSError("no target params"),  # trap params
        ]
        result = self.backend.get_snmp_config()
        self.assertFalse(result['versions']['v1'])
        self.assertFalse(result['versions']['v2'])
        self.assertTrue(result['versions']['v3'])
        self.assertEqual(result['port'], 161)
        self.assertEqual(len(result['communities']), 1)
        self.assertEqual(result['communities'][0]['name'], 'public')
        self.assertEqual(result['communities'][0]['access'], 'ro')

    def test_get_snmp_config_no_communities(self):
        """get_snmp_config with empty community table."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{
                "hm2SnmpV1AdminStatus": "1",
                "hm2SnmpV2AdminStatus": "1",
                "hm2SnmpV3AdminStatus": "2",
                "hm2SnmpPortNumber": "161",
                "hm2SnmpTrapServiceAdminStatus": "2",
            }],
            MOPSError("no community entries"),
            MOPSError("no user table"),
            MOPSError("no target addr"),
            MOPSError("no target params"),
        ]
        result = self.backend.get_snmp_config()
        self.assertTrue(result['versions']['v1'])
        self.assertTrue(result['versions']['v2'])
        self.assertFalse(result['versions']['v3'])
        self.assertEqual(result['communities'], [])

    def test_set_snmp_config_v1(self):
        """set_snmp_config enables v1."""
        self.backend.client.set.return_value = True
        self.backend.set_snmp_config(v1=True)
        self.backend.client.set.assert_called_once_with(
            "HM2-MGMTACCESS-MIB", "hm2MgmtAccessSnmpGroup",
            {"hm2SnmpV1AdminStatus": "1"})

    def test_set_snmp_config_noop(self):
        """set_snmp_config with no args is a no-op."""
        self.backend.set_snmp_config()
        self.backend.client.set.assert_not_called()


class TestMOPSSignalContact(unittest.TestCase):
    """Test MOPS signal contact getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def _make_ifindex(self):
        return {str(i): f"1/{i}" for i in range(1, 13)}

    def test_get_signal_contact(self):
        """get_signal_contact returns correct shape from BRS50 data."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DIAGNOSTIC-MIB": {
                    "hm2SigConCommonEntry": [{
                        "hm2SigConID": "1",
                        "hm2SigConMode": "2",
                        "hm2SigConOperState": "1",
                        "hm2SigConTrapEnable": "2",
                        "hm2SigConTrapCause": "10",
                        "hm2SigConTrapCauseIndex": "0",
                        "hm2SigConManualActivate": "2",
                        "hm2SigConOperTimeStamp": "1773134373",
                        "hm2SigConSenseLinkFailure": "2",
                        "hm2SigConSenseTemperature": "1",
                        "hm2SigConSenseExtNvmRemoval": "2",
                        "hm2SigConSenseExtNvmNotInSync": "2",
                        "hm2SigConSenseRingRedundancy": "2",
                    }],
                    "hm2SigConPSEntry": [
                        {"hm2SigConID": "1", "hm2SigConSensePSState": "1"},
                        {"hm2SigConID": "1", "hm2SigConSensePSState": "1"},
                    ],
                    "hm2SigConInterfaceEntry": [
                        {"hm2SigConID": "1", "hm2SigConSenseIfLinkAlarm": "2"}
                    ] * 12,
                    "hm2SigConStatusEntry": [{
                        "hm2SigConStatusIndex": "6",
                        "hm2SigConStatusTimeStamp": "1773135114",
                        "hm2SigConStatusTrapCause": "2",
                        "hm2SigConStatusTrapCauseIndex": "2",
                    }],
                },
                "IF-MIB": {
                    "ifXEntry": [{"ifIndex": str(i), "ifName":
                        ' '.join(f'{b:02x}' for b in f"1/{i}".encode())}
                        for i in range(1, 13)]
                    + [{"ifIndex": "25", "ifName": "63 70 75 2f 31"}],
                },
            }
        }
        result = self.backend.get_signal_contact()
        self.assertIn(1, result)
        sc1 = result[1]
        self.assertEqual(sc1['mode'], 'monitor')
        self.assertFalse(sc1['trap_enabled'])
        self.assertEqual(sc1['manual_state'], 'close')
        self.assertTrue(sc1['monitoring']['temperature'])
        self.assertFalse(sc1['monitoring']['link_failure'])
        self.assertTrue(sc1['power_supply'][1])
        self.assertEqual(sc1['status']['oper_state'], 'open')
        self.assertEqual(sc1['status']['cause'], 'power-fail-imminent')
        self.assertEqual(len(sc1['status']['events']), 1)
        self.assertEqual(sc1['status']['events'][0]['cause'], 'power-supply')

    def test_set_signal_contact_mode(self):
        """set_signal_contact mode change calls set_multi."""
        self.backend.client.set_multi = Mock()
        self.backend.set_signal_contact(contact_id=1, mode='deviceSecurity')
        self.backend.client.set_multi.assert_called()

    def test_set_signal_contact_noop(self):
        """set_signal_contact with no args is a no-op."""
        self.backend.client.set_multi = Mock()
        self.backend.set_signal_contact()
        self.backend.client.set_multi.assert_not_called()


class TestMOPSDeviceMonitor(unittest.TestCase):
    """Test MOPS device monitor getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_device_monitor(self):
        """get_device_monitor returns correct shape from BRS50 data."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DIAGNOSTIC-MIB": {
                    "hm2DevMonCommonEntry": [{
                        "hm2DevMonID": "1",
                        "hm2DevMonTrapEnable": "1",
                        "hm2DevMonTrapCause": "2",
                        "hm2DevMonTrapCauseIndex": "2",
                        "hm2DevMonOperState": "2",
                        "hm2DevMonOperTimeStamp": "1773132810",
                        "hm2DevMonSenseLinkFailure": "2",
                        "hm2DevMonSenseTemperature": "1",
                        "hm2DevMonSenseExtNvmRemoval": "2",
                        "hm2DevMonSenseExtNvmNotInSync": "2",
                        "hm2DevMonSenseRingRedundancy": "2",
                    }],
                    "hm2DevMonPSEntry": [
                        {"hm2DevMonID": "1", "hm2DevMonSensePSState": "1"},
                        {"hm2DevMonID": "1", "hm2DevMonSensePSState": "1"},
                    ],
                    "hm2DevMonInterfaceEntry": [
                        {"hm2DevMonID": "1", "hm2DevMonSenseIfLinkAlarm": "2"}
                    ] * 12,
                    "hm2DevMonStatusEntry": [{
                        "hm2DevMonStatusIndex": "1",
                        "hm2DevMonStatusTimeStamp": "1773132810",
                        "hm2DevMonStatusTrapCause": "2",
                        "hm2DevMonStatusTrapCauseIndex": "2",
                    }],
                },
                "IF-MIB": {
                    "ifXEntry": [{"ifIndex": str(i), "ifName":
                        ' '.join(f'{b:02x}' for b in f"1/{i}".encode())}
                        for i in range(1, 13)]
                    + [{"ifIndex": "25", "ifName": "63 70 75 2f 31"}],
                },
            }
        }
        result = self.backend.get_device_monitor()
        self.assertTrue(result['trap_enabled'])
        self.assertTrue(result['monitoring']['temperature'])
        self.assertFalse(result['monitoring']['link_failure'])
        self.assertTrue(result['power_supply'][1])
        self.assertEqual(result['status']['oper_state'], 'error')
        self.assertEqual(result['status']['cause'], 'power-supply')
        self.assertEqual(result['status']['cause_index'], 2)
        self.assertEqual(len(result['status']['events']), 1)

    def test_set_device_monitor_trap(self):
        """set_device_monitor trap toggle calls set_multi."""
        self.backend.client.set_multi = Mock()
        self.backend.set_device_monitor(trap_enabled=False)
        self.backend.client.set_multi.assert_called()


class TestMOPSDevSecStatus(unittest.TestCase):
    """Test MOPS device security status getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_devsec_status(self):
        """get_devsec_status returns 19 monitors + events from BRS50 data."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DIAGNOSTIC-MIB": {
                    "hm2DevSecConfigGroup": [{
                        "hm2DevSecTrapEnable": "2",
                        "hm2DevSecTrapCause": "17",
                        "hm2DevSecTrapCauseIndex": "0",
                        "hm2DevSecOperState": "2",
                        "hm2DevSecOperTimeStamp": "1773135123",
                        "hm2DevSecSensePasswordChange": "1",
                        "hm2DevSecSensePasswordMinLength": "1",
                        "hm2DevSecSensePasswordStrengthNotConfigured": "1",
                        "hm2DevSecSenseBypassPasswordStrength": "1",
                        "hm2DevSecSenseTelnetEnabled": "1",
                        "hm2DevSecSenseHttpEnabled": "1",
                        "hm2DevSecSenseSnmpUnsecure": "1",
                        "hm2DevSecSenseSysmonEnabled": "1",
                        "hm2DevSecSenseExtNvmUpdateEnabled": "1",
                        "hm2DevSecSenseNoLinkEnabled": "1",
                        "hm2DevSecSenseHiDiscoveryEnabled": "1",
                        "hm2DevSecSenseExtNvmConfigLoadUnsecure": "1",
                        "hm2DevSecSenseIec61850MmsEnabled": "1",
                        "hm2DevSecSenseHttpsCertificateWarning": "1",
                        "hm2DevSecSenseModbusTcpEnabled": "1",
                        "hm2DevSecSenseEtherNetIpEnabled": "1",
                        "hm2DevSecSenseProfinetIOEnabled": "1",
                        "hm2DevSecSenseSecureBootDisabled": "1",
                        "hm2DevSecSenseDevModeEnabled": "1",
                    }],
                    "hm2DevSecInterfaceEntry": [
                        {"hm2DevSecSenseIfNoLink": "2"}
                    ] * 12,
                    "hm2DevSecStatusEntry": [
                        {"hm2DevSecStatusIndex": "1",
                         "hm2DevSecStatusTimeStamp": "1773056467",
                         "hm2DevSecStatusTrapCause": "13",
                         "hm2DevSecStatusTrapCauseIndex": "0"},
                        {"hm2DevSecStatusIndex": "4",
                         "hm2DevSecStatusTimeStamp": "1773056470",
                         "hm2DevSecStatusTrapCause": "10",
                         "hm2DevSecStatusTrapCauseIndex": "0"},
                    ],
                },
                "IF-MIB": {
                    "ifXEntry": [{"ifIndex": str(i), "ifName":
                        ' '.join(f'{b:02x}' for b in f"1/{i}".encode())}
                        for i in range(1, 13)]
                    + [{"ifIndex": "25", "ifName": "63 70 75 2f 31"}],
                },
            }
        }
        result = self.backend.get_devsec_status()
        self.assertFalse(result['trap_enabled'])
        self.assertEqual(len(result['monitoring']), 19)
        self.assertTrue(result['monitoring']['password_change'])
        self.assertTrue(result['monitoring']['sysmon_enabled'])
        self.assertTrue(result['monitoring']['secure_boot_disabled'])
        self.assertEqual(result['status']['oper_state'], 'error')
        self.assertEqual(result['status']['cause'], 'sysmon-enabled')
        self.assertEqual(len(result['status']['events']), 2)
        self.assertFalse(result['no_link']['1/1'])

    def test_set_devsec_status_monitoring(self):
        """set_devsec_status toggles a monitor flag."""
        self.backend.client.set_multi = Mock()
        self.backend.set_devsec_status(monitoring={'sysmon_enabled': False})
        self.backend.client.set_multi.assert_called()


class TestMOPSBanner(unittest.TestCase):
    """Test MOPS banner getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_banner_defaults(self):
        """get_banner factory defaults — both disabled, empty text."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-MGMTACCESS-MIB": {
                    "hm2MgmtAccessPreLoginBannerGroup": [{
                        "hm2PreLoginBannerAdminStatus": "2",
                        "hm2PreLoginBannerText": "",
                    }],
                    "hm2MgmtAccessCliGroup": [{
                        "hm2CliLoginBannerAdminStatus": "2",
                        "hm2CliLoginBannerText": "",
                    }],
                },
            }
        }
        result = self.backend.get_banner()
        self.assertFalse(result['pre_login']['enabled'])
        self.assertEqual(result['pre_login']['text'], '')
        self.assertFalse(result['cli_login']['enabled'])
        self.assertEqual(result['cli_login']['text'], '')

    def test_get_banner_enabled_with_text(self):
        """get_banner with pre-login enabled and hex-encoded text."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-MGMTACCESS-MIB": {
                    "hm2MgmtAccessPreLoginBannerGroup": [{
                        "hm2PreLoginBannerAdminStatus": "1",
                        "hm2PreLoginBannerText":
                            "41 75 74 68 6f 72 69 7a 65 64",
                    }],
                    "hm2MgmtAccessCliGroup": [{
                        "hm2CliLoginBannerAdminStatus": "2",
                        "hm2CliLoginBannerText": "",
                    }],
                },
            }
        }
        result = self.backend.get_banner()
        self.assertTrue(result['pre_login']['enabled'])
        self.assertEqual(result['pre_login']['text'], 'Authorized')

    def test_set_banner_pre_login(self):
        """set_banner enables pre-login with text."""
        self.backend.client.set_multi = Mock()
        self.backend.set_banner(pre_login_enabled=True,
                                pre_login_text='Test')
        self.backend.client.set_multi.assert_called()

    def test_set_banner_noop(self):
        """set_banner with no args is a no-op."""
        self.backend.client.set_multi = Mock()
        self.backend.set_banner()
        self.backend.client.set_multi.assert_not_called()


class TestMOPSSessionConfig(unittest.TestCase):
    """Test MOPS session config getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_session_config_factory(self):
        """get_session_config with factory default values from .85."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-MGMTACCESS-MIB": {
                    "hm2MgmtAccessSshGroup": [{
                        "hm2SshMaxSessionsCount": "5",
                        "hm2SshSessionTimeout": "5",
                        "hm2SshSessionsCount": "0",
                        "hm2SshOutboundMaxSessionsCount": "0",
                        "hm2SshOutboundSessionTimeout": "0",
                        "hm2SshOutboundSessionsCount": "0",
                    }],
                    "hm2MgmtAccessTelnetGroup": [{
                        "hm2TelnetServerMaxSessions": "5",
                        "hm2TelnetServerSessionsTimeOut": "5",
                        "hm2TelnetServerSessionsCount": "0",
                    }],
                    "hm2MgmtAccessWebGroup": [{
                        "hm2WebIntfTimeOut": "5",
                    }],
                    "hm2MgmtAccessCliGroup": [{
                        "hm2CliLoginTimeoutSerial": "5",
                    }],
                    "hm2MgmtAccessNetconfGroup": [{
                        "hm2NetconfMaxSessions": "0",
                        "hm2NetconfSessionTimeout": "0",
                        "hm2NetconfSessionsCount": "0",
                    }],
                },
            }
        }
        result = self.backend.get_session_config()
        self.assertEqual(result['ssh']['timeout'], 5)
        self.assertEqual(result['ssh']['max_sessions'], 5)
        self.assertEqual(result['ssh']['active_sessions'], 0)
        self.assertEqual(result['ssh_outbound']['timeout'], 0)
        self.assertEqual(result['telnet']['timeout'], 5)
        self.assertEqual(result['web']['timeout'], 5)
        self.assertEqual(result['serial']['timeout'], 5)
        self.assertEqual(result['netconf']['timeout'], 0)

    def test_get_session_config_netconf_seconds_to_minutes(self):
        """NETCONF timeout normalised from seconds to minutes."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-MGMTACCESS-MIB": {
                    "hm2MgmtAccessSshGroup": [{}],
                    "hm2MgmtAccessTelnetGroup": [{}],
                    "hm2MgmtAccessWebGroup": [{}],
                    "hm2MgmtAccessCliGroup": [{}],
                    "hm2MgmtAccessNetconfGroup": [{
                        "hm2NetconfMaxSessions": "5",
                        "hm2NetconfSessionTimeout": "3600",
                        "hm2NetconfSessionsCount": "0",
                    }],
                },
            }
        }
        result = self.backend.get_session_config()
        self.assertEqual(result['netconf']['timeout'], 60)
        self.assertEqual(result['netconf']['max_sessions'], 5)

    def test_set_session_config_ssh_timeout(self):
        """set_session_config sets SSH timeout."""
        self.backend.client.set_multi = Mock()
        self.backend.set_session_config(ssh_timeout=10)
        self.backend.client.set_multi.assert_called()

    def test_set_session_config_netconf_minutes_to_seconds(self):
        """set_session_config converts NETCONF minutes to seconds."""
        self.backend.client.set_multi = Mock()
        self.backend.set_session_config(netconf_timeout=1)
        call_args = self.backend.client.set_multi.call_args[0][0]
        # Find the NetconfGroup mutation
        nc_mut = [m for m in call_args
                  if m[1] == "hm2MgmtAccessNetconfGroup"]
        self.assertEqual(len(nc_mut), 1)
        self.assertEqual(
            nc_mut[0][2]["hm2NetconfSessionTimeout"], "60")

    def test_set_session_config_noop(self):
        """set_session_config with no args is a no-op."""
        self.backend.client.set_multi = Mock()
        self.backend.set_session_config()
        self.backend.client.set_multi.assert_not_called()


class TestMOPSIpRestrict(unittest.TestCase):
    """Test MOPS IP restrict getter/setter/CRUD."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_ip_restrict_factory(self):
        """get_ip_restrict factory defaults — 1 rule, disabled."""
        self.backend.client.get.side_effect = [
            # Scalars
            [{"hm2RmaOperation": "2", "hm2RmaLoggingGlobal": "2"}],
            # Rule table — 1 default entry
            [{
                "hm2RmaRowStatus": "1",
                "hm2RmaIpAddr": "00 00 00 00",
                "hm2RmaPrefixLength": "0",
                "hm2RmaSrvHttp": "1", "hm2RmaSrvHttps": "1",
                "hm2RmaSrvSnmp": "1", "hm2RmaSrvTelnet": "1",
                "hm2RmaSrvSsh": "1", "hm2RmaSrvIEC61850": "1",
                "hm2RmaSrvModbusTcp": "1", "hm2RmaSrvEthernetIP": "1",
                "hm2RmaSrvProfinetIO": "1",
                "hm2RmaInterface": "", "hm2RmaLogging": "2",
            }],
        ]
        result = self.backend.get_ip_restrict()
        self.assertFalse(result['enabled'])
        self.assertFalse(result['logging'])
        self.assertEqual(len(result['rules']), 1)
        self.assertEqual(result['rules'][0]['ip'], '0.0.0.0')
        self.assertEqual(result['rules'][0]['prefix_length'], 0)
        self.assertTrue(result['rules'][0]['services']['ssh'])

    def test_get_ip_restrict_with_subnet(self):
        """get_ip_restrict with a configured subnet rule."""
        self.backend.client.get.side_effect = [
            [{"hm2RmaOperation": "1", "hm2RmaLoggingGlobal": "1"}],
            [{
                "hm2RmaRowStatus": "1",
                "hm2RmaIpAddr": "c0 a8 3c 00",  # 192.168.60.0
                "hm2RmaPrefixLength": "24",
                "hm2RmaSrvHttp": "2", "hm2RmaSrvHttps": "1",
                "hm2RmaSrvSnmp": "2", "hm2RmaSrvTelnet": "2",
                "hm2RmaSrvSsh": "1", "hm2RmaSrvIEC61850": "2",
                "hm2RmaSrvModbusTcp": "2", "hm2RmaSrvEthernetIP": "2",
                "hm2RmaSrvProfinetIO": "2",
                "hm2RmaInterface": "", "hm2RmaLogging": "2",
            }],
        ]
        result = self.backend.get_ip_restrict()
        self.assertTrue(result['enabled'])
        self.assertTrue(result['logging'])
        r = result['rules'][0]
        self.assertEqual(r['ip'], '192.168.60.0')
        self.assertEqual(r['prefix_length'], 24)
        self.assertFalse(r['services']['http'])
        self.assertTrue(r['services']['https'])
        self.assertTrue(r['services']['ssh'])
        self.assertFalse(r['services']['snmp'])

    def test_set_ip_restrict_enable(self):
        """set_ip_restrict enables RMA."""
        self.backend.client.set = Mock()
        self.backend.set_ip_restrict(enabled=True)
        self.backend.client.set.assert_called_once_with(
            "HM2-MGMTACCESS-MIB", "hm2RestrictedMgmtAccessGroup",
            {"hm2RmaOperation": "1"})

    def test_add_ip_restrict_rule(self):
        """add_ip_restrict_rule creates rule via set_indexed."""
        self.backend.client.set_indexed = Mock()
        self.backend.add_ip_restrict_rule(
            2, ip='192.168.1.0', prefix_length=24,
            http=False, ssh=True, https=True)
        self.backend.client.set_indexed.assert_called_once()
        call_kwargs = self.backend.client.set_indexed.call_args
        values = call_kwargs[1]['values'] if 'values' in call_kwargs[1] else call_kwargs[0][3]
        self.assertEqual(values["hm2RmaRowStatus"], "4")
        self.assertEqual(values["hm2RmaSrvHttp"], "2")
        self.assertEqual(values["hm2RmaSrvSsh"], "1")

    def test_delete_ip_restrict_rule(self):
        """delete_ip_restrict_rule destroys row."""
        self.backend.client.set_indexed = Mock()
        self.backend.delete_ip_restrict_rule(2)
        self.backend.client.set_indexed.assert_called_once()
        call_args = self.backend.client.set_indexed.call_args
        values = call_args[1]['values'] if 'values' in call_args[1] else call_args[0][3]
        self.assertEqual(values["hm2RmaRowStatus"], "6")

    def test_decode_inet_address(self):
        """_decode_inet_address hex to dotted quad."""
        self.assertEqual(
            MOPSHIOS._decode_inet_address("c0 a8 01 01"),
            "192.168.1.1")
        self.assertEqual(
            MOPSHIOS._decode_inet_address("00 00 00 00"),
            "0.0.0.0")
        self.assertEqual(
            MOPSHIOS._decode_inet_address(""),
            "0.0.0.0")

    def test_encode_inet_address(self):
        """_encode_inet_address dotted quad to hex."""
        self.assertEqual(
            MOPSHIOS._encode_inet_address("192.168.1.1"),
            "c0 a8 01 01")
        self.assertEqual(
            MOPSHIOS._encode_inet_address("0.0.0.0"),
            "00 00 00 00")


class TestMOPSSnmpConfigExtended(unittest.TestCase):
    """Test MOPS extended SNMP config (trap_service, v3_users, trap_dests)."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    def test_get_snmp_config_trap_service(self):
        """get_snmp_config returns trap_service field."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{"hm2SnmpV1AdminStatus": "2", "hm2SnmpV2AdminStatus": "2",
              "hm2SnmpV3AdminStatus": "1", "hm2SnmpPortNumber": "161",
              "hm2SnmpTrapServiceAdminStatus": "1"}],
            MOPSError("no communities"),
            # v3 users
            [{"hm2UserName": "61 64 6d 69 6e",  # admin
              "hm2UserSnmpAuthType": "1",  # md5
              "hm2UserSnmpEncType": "1",   # des
              "hm2UserStatus": "1"}],
            MOPSError("no target addr"),
            MOPSError("no target params"),
        ]
        result = self.backend.get_snmp_config()
        self.assertTrue(result['trap_service'])
        self.assertEqual(len(result['v3_users']), 1)
        self.assertEqual(result['v3_users'][0]['name'], 'admin')
        self.assertEqual(result['v3_users'][0]['auth_type'], 'md5')
        self.assertEqual(result['v3_users'][0]['enc_type'], 'des')
        self.assertEqual(result['trap_destinations'], [])

    def test_get_snmp_config_with_trap_dest(self):
        """get_snmp_config with trap destination."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{"hm2SnmpV1AdminStatus": "2", "hm2SnmpV2AdminStatus": "2",
              "hm2SnmpV3AdminStatus": "1", "hm2SnmpPortNumber": "161",
              "hm2SnmpTrapServiceAdminStatus": "1"}],
            MOPSError("no communities"),
            MOPSError("no users"),
            # Target addr table
            [{"snmpTargetAddrName": "6e 6d 73 31",  # nms1
              "snmpTargetAddrTAddress": "c0 a8 01 64 00 a2",  # 192.168.1.100:162
              "snmpTargetAddrParams": "70 31"}],  # p1
            # Target params table
            [{"snmpTargetParamsName": "70 31",  # p1
              "snmpTargetParamsSecurityModel": "3",
              "snmpTargetParamsSecurityName": "61 64 6d 69 6e",
              "snmpTargetParamsSecurityLevel": "3"}],
        ]
        result = self.backend.get_snmp_config()
        self.assertEqual(len(result['trap_destinations']), 1)
        d = result['trap_destinations'][0]
        self.assertEqual(d['name'], 'nms1')
        self.assertEqual(d['address'], '192.168.1.100:162')
        self.assertEqual(d['security_model'], 'v3')
        self.assertEqual(d['security_name'], 'admin')
        self.assertEqual(d['security_level'], 'authpriv')

    def test_set_snmp_config_trap_service(self):
        """set_snmp_config with trap_service kwarg."""
        self.backend.client.set = Mock()
        self.backend.set_snmp_config(trap_service=True)
        self.backend.client.set.assert_called_once()
        call_args = self.backend.client.set.call_args[0]
        self.assertIn("hm2SnmpTrapServiceAdminStatus", call_args[2])
        self.assertEqual(
            call_args[2]["hm2SnmpTrapServiceAdminStatus"], "1")

    def test_decode_taddress(self):
        """_decode_taddress hex bytes to ip:port."""
        self.assertEqual(
            MOPSHIOS._decode_taddress("c0 a8 01 64 00 a2"),
            "192.168.1.100:162")
        self.assertEqual(MOPSHIOS._decode_taddress(""), "")


class TestMOPSDns(unittest.TestCase):
    """Test MOPS DNS client getter/setter/CRUD."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    # --- get_dns ---

    def test_get_dns_factory_defaults(self):
        """get_dns factory defaults — disabled, no servers."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DNS-MIB": {
                    "hm2DnsClientGroup": [{
                        "hm2DnsClientAdminState": "2",
                        "hm2DnsClientConfigSource": "2",
                    }],
                    "hm2DnsClientGlobalGroup": [{
                        "hm2DnsClientDefaultDomainName": "",
                        "hm2DnsClientRequestTimeout": "3",
                        "hm2DnsClientRequestRetransmits": "2",
                        "hm2DnsClientCacheAdminState": "1",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [],  # cfg table — empty
            [],  # diag table — empty
        ]
        result = self.backend.get_dns()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['config_source'], 'mgmt-dhcp')
        self.assertEqual(result['domain_name'], '')
        self.assertEqual(result['timeout'], 3)
        self.assertEqual(result['retransmits'], 2)
        self.assertTrue(result['cache_enabled'])
        self.assertEqual(result['servers'], [])
        self.assertEqual(result['active_servers'], [])

    def test_get_dns_with_server(self):
        """get_dns with DNS enabled and a configured server."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DNS-MIB": {
                    "hm2DnsClientGroup": [{
                        "hm2DnsClientAdminState": "1",
                        "hm2DnsClientConfigSource": "1",
                    }],
                    "hm2DnsClientGlobalGroup": [{
                        "hm2DnsClientDefaultDomainName":
                            "74 65 73 74 2e 6c 6f 63 61 6c",
                        "hm2DnsClientRequestTimeout": "5",
                        "hm2DnsClientRequestRetransmits": "3",
                        "hm2DnsClientCacheAdminState": "2",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            # cfg table — 1 server
            [{
                "hm2DnsClientServerIndex": "1",
                "hm2DnsClientServerAddressType": "1",
                "hm2DnsClientServerAddress": "c0 a8 03 01",
                "hm2DnsClientServerRowStatus": "1",
            }],
            # diag table — 1 active
            [{
                "hm2DnsClientServerDiagIndex": "1",
                "hm2DnsClientServerDiagAddressType": "1",
                "hm2DnsClientServerDiagAddress": "c0 a8 03 01",
            }],
        ]
        result = self.backend.get_dns()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['config_source'], 'user')
        self.assertEqual(result['domain_name'], 'test.local')
        self.assertEqual(result['timeout'], 5)
        self.assertEqual(result['retransmits'], 3)
        self.assertFalse(result['cache_enabled'])
        self.assertEqual(result['servers'], ['192.168.3.1'])
        self.assertEqual(result['active_servers'], ['192.168.3.1'])

    def test_get_dns_skips_destroyed_rows(self):
        """get_dns ignores servers with RowStatus=6 (destroyed)."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DNS-MIB": {
                    "hm2DnsClientGroup": [{
                        "hm2DnsClientAdminState": "1",
                        "hm2DnsClientConfigSource": "1",
                    }],
                    "hm2DnsClientGlobalGroup": [{
                        "hm2DnsClientDefaultDomainName": "",
                        "hm2DnsClientRequestTimeout": "3",
                        "hm2DnsClientRequestRetransmits": "2",
                        "hm2DnsClientCacheAdminState": "1",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [{
                "hm2DnsClientServerIndex": "1",
                "hm2DnsClientServerAddressType": "1",
                "hm2DnsClientServerAddress": "c0 a8 03 01",
                "hm2DnsClientServerRowStatus": "6",
            }],
            [],
        ]
        result = self.backend.get_dns()
        self.assertEqual(result['servers'], [])

    def test_get_dns_multiple_servers(self):
        """get_dns returns multiple configured servers."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-DNS-MIB": {
                    "hm2DnsClientGroup": [{
                        "hm2DnsClientAdminState": "1",
                        "hm2DnsClientConfigSource": "1",
                    }],
                    "hm2DnsClientGlobalGroup": [{
                        "hm2DnsClientDefaultDomainName": "",
                        "hm2DnsClientRequestTimeout": "3",
                        "hm2DnsClientRequestRetransmits": "2",
                        "hm2DnsClientCacheAdminState": "1",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [
                {
                    "hm2DnsClientServerIndex": "1",
                    "hm2DnsClientServerAddressType": "1",
                    "hm2DnsClientServerAddress": "c0 a8 03 01",
                    "hm2DnsClientServerRowStatus": "1",
                },
                {
                    "hm2DnsClientServerIndex": "2",
                    "hm2DnsClientServerAddressType": "1",
                    "hm2DnsClientServerAddress": "0a 00 00 01",
                    "hm2DnsClientServerRowStatus": "1",
                },
            ],
            [],
        ]
        result = self.backend.get_dns()
        self.assertEqual(result['servers'], ['192.168.3.1', '10.0.0.1'])

    # --- set_dns ---

    def test_set_dns_enable(self):
        """set_dns enables DNS client."""
        self.backend.client.set_multi = Mock()
        self.backend.set_dns(enabled=True)
        calls = self.backend.client.set_multi.call_args_list
        self.assertEqual(len(calls), 1)
        mutations = calls[0][0][0]  # first positional arg = list of tuples
        vals = mutations[0][2]
        self.assertEqual(vals["hm2DnsClientAdminState"], "1")

    def test_set_dns_disable(self):
        """set_dns disables DNS client."""
        self.backend.client.set_multi = Mock()
        self.backend.set_dns(enabled=False)
        calls = self.backend.client.set_multi.call_args_list
        mutations = calls[0][0][0]
        vals = mutations[0][2]
        self.assertEqual(vals["hm2DnsClientAdminState"], "2")

    def test_set_dns_multiple_fields(self):
        """set_dns sets multiple global fields."""
        self.backend.client.set_multi = Mock()
        self.backend.set_dns(
            cache_enabled=False, timeout=10, retransmits=5)
        calls = self.backend.client.set_multi.call_args_list
        self.assertEqual(len(calls), 1)
        mutations = calls[0][0][0]
        # All global fields go in one mutation tuple
        vals = mutations[0][2]
        self.assertEqual(vals["hm2DnsClientCacheAdminState"], "2")
        self.assertEqual(vals["hm2DnsClientRequestTimeout"], "10")
        self.assertEqual(vals["hm2DnsClientRequestRetransmits"], "5")

    def test_set_dns_invalid_config_source(self):
        """set_dns raises ValueError for invalid config_source."""
        with self.assertRaises(ValueError):
            self.backend.set_dns(config_source='invalid')

    # --- add_dns_server ---

    def test_add_dns_server_empty_table(self):
        """add_dns_server picks index 1 when table is empty."""
        self.backend.client.get.side_effect = [
            [],  # no existing servers
        ]
        self.backend.client.set_indexed = Mock()
        self.backend.add_dns_server('192.168.3.1')
        call = self.backend.client.set_indexed.call_args
        self.assertEqual(
            call[1]['index']['hm2DnsClientServerIndex'], '1')
        self.assertEqual(
            call[1]['values']['hm2DnsClientServerRowStatus'], '4')

    def test_add_dns_server_picks_next_free(self):
        """add_dns_server skips used indices."""
        self.backend.client.get.side_effect = [
            [{
                "hm2DnsClientServerIndex": "1",
                "hm2DnsClientServerRowStatus": "1",
            }],
        ]
        self.backend.client.set_indexed = Mock()
        self.backend.add_dns_server('10.0.0.1')
        call = self.backend.client.set_indexed.call_args
        self.assertEqual(
            call[1]['index']['hm2DnsClientServerIndex'], '2')

    def test_add_dns_server_full_table(self):
        """add_dns_server raises ValueError when all 4 slots used."""
        self.backend.client.get.side_effect = [
            [
                {"hm2DnsClientServerIndex": "1",
                 "hm2DnsClientServerRowStatus": "1"},
                {"hm2DnsClientServerIndex": "2",
                 "hm2DnsClientServerRowStatus": "1"},
                {"hm2DnsClientServerIndex": "3",
                 "hm2DnsClientServerRowStatus": "1"},
                {"hm2DnsClientServerIndex": "4",
                 "hm2DnsClientServerRowStatus": "1"},
            ],
        ]
        with self.assertRaises(ValueError) as ctx:
            self.backend.add_dns_server('10.0.0.5')
        self.assertIn('4 DNS server slots', str(ctx.exception))

    # --- delete_dns_server ---

    def test_delete_dns_server(self):
        """delete_dns_server destroys row by IP match."""
        self.backend.client.get.side_effect = [
            [{
                "hm2DnsClientServerIndex": "2",
                "hm2DnsClientServerAddress": "c0 a8 03 01",
                "hm2DnsClientServerRowStatus": "1",
            }],
        ]
        self.backend.client.set_indexed = Mock()
        self.backend.delete_dns_server('192.168.3.1')
        call = self.backend.client.set_indexed.call_args
        self.assertEqual(
            call[1]['values']['hm2DnsClientServerRowStatus'], '6')

    def test_delete_dns_server_not_found(self):
        """delete_dns_server raises ValueError when IP not in table."""
        self.backend.client.get.side_effect = [
            [{
                "hm2DnsClientServerIndex": "1",
                "hm2DnsClientServerAddress": "c0 a8 03 01",
                "hm2DnsClientServerRowStatus": "1",
            }],
        ]
        with self.assertRaises(ValueError) as ctx:
            self.backend.delete_dns_server('10.10.10.10')
        self.assertIn('not found', str(ctx.exception))


class TestMOPSPoe(unittest.TestCase):
    """Test MOPS PoE getter/setter."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True

    # --- get_poe ---

    def test_get_poe_factory_defaults(self):
        """get_poe factory defaults — disabled, empty ports/modules."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-POE-MIB": {
                    "hm2PoeMgmtGlobalGroup": [{
                        "hm2PoeMgmtAdminStatus": "2",
                        "hm2PoeMgmtReservedPower": "0",
                        "hm2PoeMgmtDeliveredCurrent": "0",
                    }],
                    "hm2PoeMgmtPortEntry": [],
                    "hm2PoeMgmtModuleEntry": [],
                },
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "31 2f 31"},
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_poe()
        self.assertFalse(result['enabled'])
        self.assertEqual(result['power_w'], 0)
        self.assertEqual(result['delivered_current_ma'], 0)
        self.assertEqual(result['modules'], {})
        self.assertEqual(result['ports'], {})

    def test_get_poe_enabled_with_port(self):
        """get_poe with global enabled and a PoE port delivering power."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-POE-MIB": {
                    "hm2PoeMgmtGlobalGroup": [{
                        "hm2PoeMgmtAdminStatus": "1",
                        "hm2PoeMgmtReservedPower": "30",
                        "hm2PoeMgmtDeliveredCurrent": "250",
                    }],
                    "hm2PoeMgmtPortEntry": [{
                        "ifIndex": "1",
                        "hm2PoeMgmtPortAdminEnable": "1",
                        "hm2PoeMgmtPortDetectionStatus": "3",
                        "hm2PoeMgmtPortPowerPriority": "2",
                        "hm2PoeMgmtPortPowerClassification": "5",
                        "hm2PoeMgmtPortConsumptionPower": "5300",
                        "hm2PoeMgmtPortPowerLimit": "15400",
                        "hm2PoeMgmtPortName": "41 50",
                        "hm2PoeMgmtPortFastStartup": "1",
                        "hm2PoeMgmtPortClassValid": "1",
                    }],
                    "hm2PoeMgmtModuleEntry": [{
                        "hm2PoeMgmtModuleUnitIndex": "1",
                        "hm2PoeMgmtModuleSlotIndex": "1",
                        "hm2PoeMgmtModulePower": "370",
                        "hm2PoeMgmtModuleMaximumPower": "370",
                        "hm2PoeMgmtModuleReservedPower": "30",
                        "hm2PoeMgmtModuleDeliveredPower": "5",
                        "hm2PoeMgmtModulePowerSource": "0",
                        "hm2PoeMgmtModuleUsageThreshold": "90",
                        "hm2PoeMgmtModuleNotificationControlEnable": "1",
                    }],
                },
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "31 2f 31"},
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_poe()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['power_w'], 30)
        self.assertEqual(result['delivered_current_ma'], 250)
        # Module
        self.assertIn('1/1', result['modules'])
        mod = result['modules']['1/1']
        self.assertEqual(mod['budget_w'], 370)
        self.assertEqual(mod['max_w'], 370)
        self.assertEqual(mod['source'], 'internal')
        self.assertEqual(mod['threshold_pct'], 90)
        self.assertTrue(mod['notifications'])
        # Port
        self.assertIn('1/1', result['ports'])
        port = result['ports']['1/1']
        self.assertTrue(port['enabled'])
        self.assertEqual(port['status'], 'delivering')
        self.assertEqual(port['priority'], 'high')
        self.assertEqual(port['classification'], 'class4')
        self.assertEqual(port['consumption_mw'], 5300)
        self.assertEqual(port['power_limit_mw'], 15400)
        self.assertEqual(port['name'], 'AP')
        self.assertTrue(port['fast_startup'])

    def test_get_poe_class_invalid_when_not_delivering(self):
        """get_poe classification is None when class_valid=0."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-POE-MIB": {
                    "hm2PoeMgmtGlobalGroup": [{
                        "hm2PoeMgmtAdminStatus": "1",
                        "hm2PoeMgmtReservedPower": "0",
                        "hm2PoeMgmtDeliveredCurrent": "0",
                    }],
                    "hm2PoeMgmtPortEntry": [{
                        "ifIndex": "1",
                        "hm2PoeMgmtPortAdminEnable": "1",
                        "hm2PoeMgmtPortDetectionStatus": "2",
                        "hm2PoeMgmtPortPowerPriority": "3",
                        "hm2PoeMgmtPortPowerClassification": "1",
                        "hm2PoeMgmtPortConsumptionPower": "0",
                        "hm2PoeMgmtPortPowerLimit": "0",
                        "hm2PoeMgmtPortName": "",
                        "hm2PoeMgmtPortFastStartup": "2",
                        "hm2PoeMgmtPortClassValid": "0",
                    }],
                    "hm2PoeMgmtModuleEntry": [],
                },
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "31 2f 31"},
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_poe()
        port = result['ports']['1/1']
        self.assertIsNone(port['classification'])
        self.assertEqual(port['status'], 'searching')

    def test_get_poe_multiple_ports(self):
        """get_poe returns multiple ports."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-POE-MIB": {
                    "hm2PoeMgmtGlobalGroup": [{
                        "hm2PoeMgmtAdminStatus": "1",
                        "hm2PoeMgmtReservedPower": "15",
                        "hm2PoeMgmtDeliveredCurrent": "120",
                    }],
                    "hm2PoeMgmtPortEntry": [
                        {
                            "ifIndex": "1",
                            "hm2PoeMgmtPortAdminEnable": "1",
                            "hm2PoeMgmtPortDetectionStatus": "3",
                            "hm2PoeMgmtPortPowerPriority": "3",
                            "hm2PoeMgmtPortPowerClassification": "4",
                            "hm2PoeMgmtPortConsumptionPower": "3200",
                            "hm2PoeMgmtPortPowerLimit": "0",
                            "hm2PoeMgmtPortName": "",
                            "hm2PoeMgmtPortFastStartup": "2",
                            "hm2PoeMgmtPortClassValid": "1",
                        },
                        {
                            "ifIndex": "2",
                            "hm2PoeMgmtPortAdminEnable": "2",
                            "hm2PoeMgmtPortDetectionStatus": "1",
                            "hm2PoeMgmtPortPowerPriority": "3",
                            "hm2PoeMgmtPortPowerClassification": "1",
                            "hm2PoeMgmtPortConsumptionPower": "0",
                            "hm2PoeMgmtPortPowerLimit": "0",
                            "hm2PoeMgmtPortName": "",
                            "hm2PoeMgmtPortFastStartup": "2",
                            "hm2PoeMgmtPortClassValid": "0",
                        },
                    ],
                    "hm2PoeMgmtModuleEntry": [],
                },
                "IF-MIB": {
                    "ifXEntry": [
                        {"ifIndex": "1", "ifName": "31 2f 31"},
                        {"ifIndex": "2", "ifName": "31 2f 32"},
                    ],
                },
            },
            "errors": [],
        }
        result = self.backend.get_poe()
        self.assertEqual(len(result['ports']), 2)
        self.assertIn('1/1', result['ports'])
        self.assertIn('1/2', result['ports'])
        self.assertTrue(result['ports']['1/1']['enabled'])
        self.assertFalse(result['ports']['1/2']['enabled'])

    # --- set_poe ---

    def test_set_poe_global_enable(self):
        """set_poe(enabled=True) sets global admin state."""
        self.backend.client.set = Mock()
        self.backend.set_poe(enabled=True)
        call = self.backend.client.set.call_args
        self.assertEqual(call[0][0], "HM2-POE-MIB")
        self.assertEqual(call[0][1], "hm2PoeMgmtGlobalGroup")
        self.assertEqual(call[0][2]["hm2PoeMgmtAdminStatus"], "1")

    def test_set_poe_global_disable(self):
        """set_poe(enabled=False) disables global admin state."""
        self.backend.client.set = Mock()
        self.backend.set_poe(enabled=False)
        call = self.backend.client.set.call_args
        self.assertEqual(call[0][2]["hm2PoeMgmtAdminStatus"], "2")

    def test_set_poe_per_port_disable(self):
        """set_poe(interface='1/1', enabled=False) disables PoE on port."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}
        self.backend.client.set_multi = Mock()
        self.backend.set_poe(interface='1/1', enabled=False)
        calls = self.backend.client.set_multi.call_args_list
        mutations = calls[0][0][0]
        self.assertEqual(mutations[0][0], "HM2-POE-MIB")
        self.assertEqual(mutations[0][1], "hm2PoeMgmtPortEntry")
        self.assertEqual(
            mutations[0][2]["hm2PoeMgmtPortAdminEnable"], "2")
        self.assertEqual(mutations[0][3]["ifIndex"], "1")

    def test_set_poe_per_port_multi(self):
        """set_poe with list of interfaces sets all."""
        self.backend._ifindex_map = {"1": "1/1", "2": "1/2"}
        self.backend.client.set_multi = Mock()
        self.backend.set_poe(
            interface=['1/1', '1/2'], enabled=False)
        calls = self.backend.client.set_multi.call_args_list
        mutations = calls[0][0][0]
        self.assertEqual(len(mutations), 2)

    def test_set_poe_per_port_priority(self):
        """set_poe priority sets correct MOPS value."""
        self.backend._ifindex_map = {"1": "1/1"}
        self.backend.client.set_multi = Mock()
        self.backend.set_poe(
            interface='1/1', priority='critical')
        mutations = (self.backend.client.set_multi
                     .call_args_list[0][0][0])
        self.assertEqual(
            mutations[0][2]["hm2PoeMgmtPortPowerPriority"], "1")

    def test_set_poe_invalid_priority(self):
        """set_poe raises ValueError for invalid priority."""
        self.backend._ifindex_map = {"1": "1/1"}
        with self.assertRaises(ValueError):
            self.backend.set_poe(
                interface='1/1', priority='invalid')

    def test_set_poe_unknown_interface(self):
        """set_poe raises ValueError for unknown interface."""
        self.backend._ifindex_map = {"1": "1/1"}
        with self.assertRaises(ValueError):
            self.backend.set_poe(
                interface='9/9', enabled=False)


    # --- get_remote_auth ---

    def test_get_remote_auth_all_disabled(self):
        """get_remote_auth factory defaults — nothing configured."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-REMOTE-AUTHENTICATION-MIB": {
                    "hm2LdapConfigGroup": [{
                        "hm2LdapClientAdminState": "2",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [],  # RADIUS — no servers
            [],  # TACACS+ — no servers
        ]
        result = self.backend.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_radius_active(self):
        """get_remote_auth with one active RADIUS server."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-REMOTE-AUTHENTICATION-MIB": {
                    "hm2LdapConfigGroup": [{
                        "hm2LdapClientAdminState": "2",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [{"hm2AgentRadiusServerRowStatus": "1"}],  # RADIUS active
            [],  # TACACS+ — no servers
        ]
        result = self.backend.get_remote_auth()
        self.assertTrue(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_ldap_enabled(self):
        """get_remote_auth with LDAP globally enabled."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-REMOTE-AUTHENTICATION-MIB": {
                    "hm2LdapConfigGroup": [{
                        "hm2LdapClientAdminState": "1",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [],  # RADIUS — no servers
            [],  # TACACS+ — no servers
        ]
        result = self.backend.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertTrue(result['ldap']['enabled'])

    def test_get_remote_auth_tacacs_active(self):
        """get_remote_auth with one active TACACS+ server."""
        self.backend.client.get_multi.return_value = {
            "mibs": {
                "HM2-REMOTE-AUTHENTICATION-MIB": {
                    "hm2LdapConfigGroup": [{
                        "hm2LdapClientAdminState": "2",
                    }],
                },
            },
            "errors": [],
        }
        self.backend.client.get.side_effect = [
            [],  # RADIUS — no servers
            [{"hm2AgentTacacsServerStatus": "1"}],  # TACACS+ active
        ]
        result = self.backend.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertTrue(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])

    def test_get_remote_auth_unsupported_graceful(self):
        """get_remote_auth handles MOPSError gracefully on unsupported HW."""
        from napalm_hios.mops_client import MOPSError
        self.backend.client.get_multi.return_value = {
            "mibs": {},
            "errors": [],
        }
        self.backend.client.get.side_effect = MOPSError("noSuchName")
        result = self.backend.get_remote_auth()
        self.assertFalse(result['radius']['enabled'])
        self.assertFalse(result['tacacs']['enabled'])
        self.assertFalse(result['ldap']['enabled'])


    # --- get_users ---

    def test_get_users_single_admin(self):
        """get_users with single admin user (factory default)."""
        self.backend.client.get.side_effect = [
            # User table
            [{
                "hm2UserName": "61 64 6d 69 6e",
                "hm2UserAccessRole": "15",
                "hm2UserLockoutStatus": "2",
                "hm2UserPwdPolicyChk": "2",
                "hm2UserSnmpAuthType": "1",
                "hm2UserSnmpEncType": "1",
                "hm2UserStatus": "1",
            }],
            # Default password table
            [{"hm2PwdMgmtDefaultPwdStatusUserName": "61 64 6d 69 6e"}],
        ]
        result = self.backend.get_users()
        self.assertEqual(len(result), 1)
        u = result[0]
        self.assertEqual(u['name'], 'admin')
        self.assertEqual(u['role'], 'administrator')
        self.assertFalse(u['locked'])
        self.assertFalse(u['policy_check'])
        self.assertEqual(u['snmp_auth'], 'md5')
        self.assertEqual(u['snmp_enc'], 'des')
        self.assertTrue(u['active'])
        self.assertTrue(u['default_password'])

    def test_get_users_multiple(self):
        """get_users with multiple users including inactive."""
        self.backend.client.get.side_effect = [
            [
                {
                    "hm2UserName": "61 64 6d 69 6e",
                    "hm2UserAccessRole": "15",
                    "hm2UserLockoutStatus": "2",
                    "hm2UserPwdPolicyChk": "2",
                    "hm2UserSnmpAuthType": "2",
                    "hm2UserSnmpEncType": "2",
                    "hm2UserStatus": "1",
                },
                {
                    "hm2UserName": "6f 70 65 72 61 74 6f 72",
                    "hm2UserAccessRole": "13",
                    "hm2UserLockoutStatus": "2",
                    "hm2UserPwdPolicyChk": "1",
                    "hm2UserSnmpAuthType": "1",
                    "hm2UserSnmpEncType": "0",
                    "hm2UserStatus": "2",
                },
            ],
            [],  # No default password users
        ]
        result = self.backend.get_users()
        self.assertEqual(len(result), 2)
        admin = result[0]
        self.assertEqual(admin['name'], 'admin')
        self.assertEqual(admin['snmp_auth'], 'sha')
        self.assertEqual(admin['snmp_enc'], 'aes128')
        self.assertTrue(admin['active'])
        oper = result[1]
        self.assertEqual(oper['name'], 'operator')
        self.assertEqual(oper['role'], 'operator')
        self.assertTrue(oper['policy_check'])
        self.assertEqual(oper['snmp_enc'], 'none')
        self.assertFalse(oper['active'])

    def test_get_users_default_pwd_table_error(self):
        """get_users handles MOPSError on default password table."""
        from napalm_hios.mops_client import MOPSError
        self.backend.client.get.side_effect = [
            [{
                "hm2UserName": "61 64 6d 69 6e",
                "hm2UserAccessRole": "15",
                "hm2UserLockoutStatus": "2",
                "hm2UserPwdPolicyChk": "2",
                "hm2UserSnmpAuthType": "1",
                "hm2UserSnmpEncType": "1",
                "hm2UserStatus": "1",
            }],
            MOPSError("noSuchName"),
        ]
        # Should not raise — graceful fallback
        result = self.backend.get_users()
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['default_password'])

    # --- set_user ---

    def test_set_user_create_new(self):
        """set_user creates new user with createAndWait sequence."""
        self.backend.client.get.return_value = [
            {"hm2UserName": "61 64 6d 69 6e", "hm2UserStatus": "1"},
        ]
        self.backend.client.set_indexed = Mock()
        self.backend.set_user('newuser', password='Test1234!',
                              role='operator')
        calls = self.backend.client.set_indexed.call_args_list
        # Step 1: createAndWait
        self.assertEqual(calls[0][1]['values']['hm2UserStatus'], '5')
        # Step 2: password
        self.assertIn('hm2UserPassword', calls[1][1]['values'])
        # Step 3: activate + role
        self.assertEqual(calls[2][1]['values']['hm2UserStatus'], '1')
        self.assertEqual(calls[2][1]['values']['hm2UserAccessRole'], '13')

    def test_set_user_update_existing(self):
        """set_user updates existing user attributes."""
        self.backend.client.get.return_value = [
            {"hm2UserName": "61 64 6d 69 6e", "hm2UserStatus": "1"},
        ]
        self.backend.client.set_indexed = Mock()
        self.backend.set_user('admin', snmp_auth_type='sha',
                              snmp_enc_type='aes128')
        calls = self.backend.client.set_indexed.call_args_list
        self.assertEqual(len(calls), 1)
        vals = calls[0][1]['values']
        self.assertEqual(vals['hm2UserSnmpAuthType'], '2')
        self.assertEqual(vals['hm2UserSnmpEncType'], '2')

    def test_set_user_requires_password_for_new(self):
        """set_user raises ValueError when creating without password."""
        self.backend.client.get.return_value = []
        with self.assertRaises(ValueError):
            self.backend.set_user('newuser', role='guest')

    def test_set_user_invalid_role(self):
        """set_user raises ValueError for invalid role."""
        self.backend.client.get.return_value = [
            {"hm2UserName": "61 64 6d 69 6e", "hm2UserStatus": "1"},
        ]
        with self.assertRaises(ValueError):
            self.backend.set_user('admin', role='superadmin')

    # --- delete_user ---

    def test_delete_user(self):
        """delete_user sends destroy(6) RowStatus."""
        self.backend.client.set_indexed = Mock()
        self.backend.delete_user('testuser')
        call = self.backend.client.set_indexed.call_args
        self.assertEqual(call[1]['values']['hm2UserStatus'], '6')


class TestBitsCodec(unittest.TestCase):
    """Test BITS hex encode/decode for cipher algorithm fields."""

    def test_decode_bits_hex_single(self):
        """Decode single bit set."""
        # Bit 2 = 0x20 (MSB-first: 0b00100000)
        result = _decode_bits_hex("20", _TLS_VERSIONS)
        self.assertEqual(result, ['tlsv1.2'])

    def test_decode_bits_hex_multiple(self):
        """Decode multiple bits set."""
        # Bits 6,7 = 0x03 (0b00000011)
        result = _decode_bits_hex("03", _TLS_CIPHER_SUITES)
        self.assertEqual(result, [
            'tls-ecdhe-rsa-with-aes-128-gcm-sha256',
            'tls-ecdhe-rsa-with-aes-256-gcm-sha384',
        ])

    def test_decode_bits_hex_empty(self):
        self.assertEqual(_decode_bits_hex("", _TLS_VERSIONS), [])
        self.assertEqual(_decode_bits_hex(None, _TLS_VERSIONS), [])

    def test_decode_bits_hex_ssh_hmac(self):
        """Bits 0,1,3,4 = 0xD8 (11011000)."""
        result = _decode_bits_hex("d8", _SSH_HMAC)
        self.assertEqual(result, [
            'hmac-sha1', 'hmac-sha2-256',
            'hmac-sha1-etm@openssh.com',
            'hmac-sha2-256-etm@openssh.com',
        ])

    def test_encode_bits_hex_roundtrip(self):
        """Encode then decode gives original list."""
        names = ['tlsv1.0', 'tlsv1.2']
        encoded = _encode_bits_hex(names, _TLS_VERSIONS)
        decoded = _decode_bits_hex(encoded, _TLS_VERSIONS)
        self.assertEqual(decoded, names)

    def test_encode_bits_hex_single(self):
        """Encode single algorithm."""
        result = _encode_bits_hex(['tlsv1.2'], _TLS_VERSIONS)
        self.assertEqual(result, '20')

    def test_encode_bits_hex_multi_byte(self):
        """SSH host key algorithms span multiple bytes."""
        names = ['ssh-ed25519']  # bit 11
        result = _encode_bits_hex(names, _SSH_HOST_KEY)
        decoded = _decode_bits_hex(result, _SSH_HOST_KEY)
        self.assertEqual(decoded, ['ssh-ed25519'])

    def test_encode_bits_hex_ignores_unknown(self):
        """Unknown algorithm names are silently skipped."""
        result = _encode_bits_hex(
            ['tlsv1.2', 'tlsv99.9'], _TLS_VERSIONS)
        decoded = _decode_bits_hex(result, _TLS_VERSIONS)
        self.assertEqual(decoded, ['tlsv1.2'])


class TestMOPSTrapDestCRUD(unittest.TestCase):
    """Test MOPS add/delete SNMP trap destination."""

    def setUp(self):
        self.backend = MOPSHIOS("198.51.100.1", "admin", "private", timeout=10)
        self.backend.client = Mock()
        self.backend._connected = True
        self.backend._staging = False

    def test_add_snmp_trap_dest_v3(self):
        """add_snmp_trap_dest creates params then addr entries."""
        self.backend.client.set_indexed = Mock()
        self.backend.add_snmp_trap_dest(
            'nms1', '192.168.1.100', port=162,
            security_model='v3', security_name='admin',
            security_level='authpriv')
        calls = self.backend.client.set_indexed.call_args_list
        # 6 calls: params create/set/activate + addr create/set/activate
        self.assertEqual(len(calls), 6)
        # Params createAndWait
        self.assertEqual(
            calls[0][1]['values']['snmpTargetParamsRowStatus'], '5')
        # Params attributes
        self.assertEqual(
            calls[1][1]['values']['snmpTargetParamsSecurityModel'], '3')
        self.assertEqual(
            calls[1][1]['values']['snmpTargetParamsSecurityLevel'], '3')
        # Params activate
        self.assertEqual(
            calls[2][1]['values']['snmpTargetParamsRowStatus'], '1')
        # Addr createAndWait
        self.assertEqual(
            calls[3][1]['values']['snmpTargetAddrRowStatus'], '5')
        # Addr activate
        self.assertEqual(
            calls[5][1]['values']['snmpTargetAddrRowStatus'], '1')

    def test_add_snmp_trap_dest_v1_forces_noauth(self):
        """add_snmp_trap_dest with v1 forces security_level to noauth."""
        self.backend.client.set_indexed = Mock()
        self.backend.add_snmp_trap_dest(
            'trap1', '10.0.0.1', security_model='v1',
            security_name='public', security_level='authpriv')
        calls = self.backend.client.set_indexed.call_args_list
        # Params step 2 should have noauth (1), not authpriv (3)
        self.assertEqual(
            calls[1][1]['values']['snmpTargetParamsSecurityLevel'], '1')

    def test_add_snmp_trap_dest_invalid_model(self):
        """add_snmp_trap_dest raises ValueError for invalid model."""
        with self.assertRaises(ValueError):
            self.backend.add_snmp_trap_dest(
                'bad', '10.0.0.1', security_model='v4')

    def test_add_snmp_trap_dest_invalid_level(self):
        """add_snmp_trap_dest raises ValueError for invalid level."""
        with self.assertRaises(ValueError):
            self.backend.add_snmp_trap_dest(
                'bad', '10.0.0.1', security_model='v3',
                security_level='invalid')

    def test_delete_snmp_trap_dest(self):
        """delete_snmp_trap_dest destroys addr then params entries."""
        self.backend.client.set_indexed = Mock()
        self.backend.delete_snmp_trap_dest('nms1')
        calls = self.backend.client.set_indexed.call_args_list
        self.assertEqual(len(calls), 2)
        # Both should set RowStatus to destroy(6)
        self.assertEqual(
            calls[0][1]['values']['snmpTargetAddrRowStatus'], '6')
        self.assertEqual(
            calls[1][1]['values']['snmpTargetParamsRowStatus'], '6')

    def test_encode_taddress(self):
        """_encode_taddress produces correct hex string."""
        result = MOPSHIOS._encode_taddress('192.168.1.100', 162)
        self.assertEqual(result, 'c0 a8 01 64 00 a2')

    def test_get_trap_dest_v1_normalises_level(self):
        """get_snmp_config normalises security_level to noauth for v1."""
        from napalm_hios.mops_hios import MOPSError
        self.backend.client.get.side_effect = [
            [{"hm2SnmpV1AdminStatus": "1", "hm2SnmpV2AdminStatus": "2",
              "hm2SnmpV3AdminStatus": "2", "hm2SnmpPortNumber": "161",
              "hm2SnmpTrapServiceAdminStatus": "1"}],
            MOPSError("no comm"),
            MOPSError("no users"),
            # Addr table
            [{"snmpTargetAddrName": "74 31",  # t1
              "snmpTargetAddrTAddress": "0a 00 00 01 00 a2",
              "snmpTargetAddrParams": "74 31"}],  # t1
            # Params table — v1 with authpriv stored
            [{"snmpTargetParamsName": "74 31",
              "snmpTargetParamsSecurityModel": "1",
              "snmpTargetParamsSecurityName": "70 75 62",  # pub
              "snmpTargetParamsSecurityLevel": "3"}],  # authpriv
        ]
        result = self.backend.get_snmp_config()
        td = result['trap_destinations'][0]
        self.assertEqual(td['security_model'], 'v1')
        self.assertEqual(td['security_level'], 'noauth')


class TestMOPSPortSecurity(unittest.TestCase):
    """Tests for get_port_security / set_port_security / add/delete."""

    def setUp(self):
        self.backend = MOPSHIOS.__new__(MOPSHIOS)
        self.backend.client = Mock()
        self.backend._staging = False
        self.backend._mutations = []

    def test_parse_portsec_macs(self):
        result = self.backend._parse_portsec_macs(
            '1 aa:bb:cc:dd:ee:ff,2 11:22:33:44:55:66')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'})
        self.assertEqual(result[1], {'vlan': 2, 'mac': '11:22:33:44:55:66'})

    def test_parse_portsec_macs_empty(self):
        self.assertEqual(self.backend._parse_portsec_macs(''), [])
        self.assertEqual(self.backend._parse_portsec_macs(None), [])

    def test_parse_portsec_ips(self):
        result = self.backend._parse_portsec_ips(
            '1 192.168.1.1,2 10.0.0.1')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], {'vlan': 1, 'ip': '192.168.1.1'})

    def test_get_port_security_all(self):
        """get_port_security() returns global + per-port data."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-PORTSECURITY-MIB": {
                "hm2AgentPortSecurityGroup": [{
                    "hm2AgentGlobalPortSecurityMode": "1",
                    "hm2AgentPortSecurityOperationMode": "1",
                }],
                "hm2AgentPortSecurityEntry": [{
                    "ifIndex": "1",
                    "hm2AgentPortSecurityMode": "1",
                    "hm2AgentPortSecurityDynamicLimit": "10",
                    "hm2AgentPortSecurityStaticLimit": "5",
                    "hm2AgentPortSecurityAutoDisable": "1",
                    "hm2AgentPortSecurityViolationTrapMode": "2",
                    "hm2AgentPortSecurityViolationTrapFrequency": "30",
                    "hm2AgentPortSecurityDynamicCount": "3",
                    "hm2AgentPortSecurityStaticCount": "1",
                    "hm2AgentPortSecurityStaticIpCount": "0",
                    "hm2AgentPortSecurityLastDiscardedMAC":
                        "31 20 30 30 3a 31 31 3a 32 32 3a 33 33 3a 34 34"
                        " 3a 35 35",
                    "hm2AgentPortSecurityStaticMACs":
                        "31 20 61 61 3a 62 62 3a 63 63 3a 64 64 3a 65 65"
                        " 3a 66 66",
                    "hm2AgentPortSecurityStaticIPs": "",
                }],
            }},
            {"1": "1/1"},
        ))
        result = self.backend.get_port_security()
        self.assertTrue(result['enabled'])
        self.assertEqual(result['mode'], 'mac-based')
        self.assertIn('1/1', result['ports'])
        port = result['ports']['1/1']
        self.assertTrue(port['enabled'])
        self.assertEqual(port['dynamic_limit'], 10)
        self.assertEqual(port['static_limit'], 5)
        self.assertEqual(port['dynamic_count'], 3)
        self.assertEqual(port['static_count'], 1)
        self.assertTrue(port['auto_disable'])
        self.assertEqual(port['violation_trap_frequency'], 30)

    def test_get_port_security_filter(self):
        """get_port_security(interface='1/2') filters to that port."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-PORTSECURITY-MIB": {
                "hm2AgentPortSecurityGroup": [{
                    "hm2AgentGlobalPortSecurityMode": "2",
                    "hm2AgentPortSecurityOperationMode": "1",
                }],
                "hm2AgentPortSecurityEntry": [
                    {"ifIndex": "1",
                     "hm2AgentPortSecurityMode": "2",
                     "hm2AgentPortSecurityDynamicLimit": "600",
                     "hm2AgentPortSecurityStaticLimit": "64",
                     "hm2AgentPortSecurityAutoDisable": "1",
                     "hm2AgentPortSecurityViolationTrapMode": "2",
                     "hm2AgentPortSecurityViolationTrapFrequency": "0",
                     "hm2AgentPortSecurityDynamicCount": "0",
                     "hm2AgentPortSecurityStaticCount": "0",
                     "hm2AgentPortSecurityStaticIpCount": "0",
                     "hm2AgentPortSecurityLastDiscardedMAC": "",
                     "hm2AgentPortSecurityStaticMACs": "",
                     "hm2AgentPortSecurityStaticIPs": ""},
                    {"ifIndex": "2",
                     "hm2AgentPortSecurityMode": "2",
                     "hm2AgentPortSecurityDynamicLimit": "600",
                     "hm2AgentPortSecurityStaticLimit": "64",
                     "hm2AgentPortSecurityAutoDisable": "1",
                     "hm2AgentPortSecurityViolationTrapMode": "2",
                     "hm2AgentPortSecurityViolationTrapFrequency": "0",
                     "hm2AgentPortSecurityDynamicCount": "0",
                     "hm2AgentPortSecurityStaticCount": "0",
                     "hm2AgentPortSecurityStaticIpCount": "0",
                     "hm2AgentPortSecurityLastDiscardedMAC": "",
                     "hm2AgentPortSecurityStaticMACs": "",
                     "hm2AgentPortSecurityStaticIPs": ""},
                ],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        result = self.backend.get_port_security(interface='1/2')
        self.assertEqual(list(result['ports'].keys()), ['1/2'])

    def test_set_port_security_global(self):
        """set_port_security(enabled=True) sets global mode."""
        self.backend.client.set = Mock()
        self.backend.set_port_security(enabled=True, mode='ip-based')
        self.backend.client.set.assert_called_once()
        args = self.backend.client.set.call_args
        self.assertIn("hm2AgentGlobalPortSecurityMode",
                       args[0][2])
        self.assertEqual(args[0][2]["hm2AgentGlobalPortSecurityMode"], "1")

    def test_set_port_security_per_port(self):
        """set_port_security('1/1', dynamic_limit=10) sets per-port."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend.client.set_multi = Mock()
        self.backend.set_port_security('1/1', dynamic_limit=10)
        self.backend.client.set_multi.assert_called_once()

    def test_set_port_security_invalid_mode(self):
        with self.assertRaises(ValueError):
            self.backend.set_port_security(mode='invalid')

    def test_add_port_security_mac(self):
        """add_port_security encodes DisplayString for MOPS."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend.client.set_indexed = Mock()
        self.backend.add_port_security('1/1', vlan=1,
                                        mac='aa:bb:cc:dd:ee:ff')
        self.backend.client.set_indexed.assert_called_once()
        vals = self.backend.client.set_indexed.call_args[1]['values']
        self.assertIn("hm2AgentPortSecurityMACAddressAdd", vals)
        # Should be hex-encoded "1 aa:bb:cc:dd:ee:ff"
        hex_val = vals["hm2AgentPortSecurityMACAddressAdd"]
        self.assertIn('31', hex_val)  # '1' = 0x31

    def test_delete_port_security_mac(self):
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend.client.set_indexed = Mock()
        self.backend.delete_port_security('1/1', vlan=1,
                                           mac='aa:bb:cc:dd:ee:ff')
        vals = self.backend.client.set_indexed.call_args[1]['values']
        self.assertIn("hm2AgentPortSecurityMACAddressRemove", vals)

    def test_add_port_security_no_mac_or_ip(self):
        """add_port_security with no mac/ip/entries raises ValueError."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        with self.assertRaises(ValueError):
            self.backend.add_port_security('1/1', vlan=1)

    def test_add_port_security_bulk(self):
        """Bulk add sends one call per entry."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend.client.set_indexed = Mock()
        self.backend.add_port_security('1/1', 1, entries=[
            {'vlan': 1, 'mac': 'aa:bb:cc:dd:ee:ff'},
            {'vlan': 2, 'mac': '11:22:33:44:55:66'},
        ])
        self.assertEqual(self.backend.client.set_indexed.call_count, 2)


class TestMOPSDhcpSnooping(unittest.TestCase):
    """Tests for get_dhcp_snooping / set_dhcp_snooping."""

    def setUp(self):
        self.backend = MOPSHIOS.__new__(MOPSHIOS)
        self.backend.client = Mock()
        self.backend._staging = False
        self.backend._mutations = []

    def test_get_dhcp_snooping_all(self):
        """get_dhcp_snooping() returns global + vlans + ports."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDhcpSnoopingConfigGroup": [{
                    "hm2AgentDhcpSnoopingAdminMode": "1",
                    "hm2AgentDhcpSnoopingVerifyMac": "2",
                }],
                "hm2AgentDhcpSnoopingIfConfigEntry": [{
                    "ifIndex": "1",
                    "hm2AgentDhcpSnoopingIfTrustEnable": "1",
                    "hm2AgentDhcpSnoopingIfLogEnable": "2",
                    "hm2AgentDhcpSnoopingIfRateLimit": "15",
                    "hm2AgentDhcpSnoopingIfBurstInterval": "1",
                    "hm2AgentDhcpSnoopingIfAutoDisable": "1",
                }, {
                    "ifIndex": "2",
                    "hm2AgentDhcpSnoopingIfTrustEnable": "2",
                    "hm2AgentDhcpSnoopingIfLogEnable": "1",
                    "hm2AgentDhcpSnoopingIfRateLimit": "-1",
                    "hm2AgentDhcpSnoopingIfBurstInterval": "5",
                    "hm2AgentDhcpSnoopingIfAutoDisable": "2",
                }],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        self.backend.client.get = Mock(return_value=[
            {"hm2AgentDhcpSnoopingVlanIndex": "1",
             "hm2AgentDhcpSnoopingVlanEnable": "1"},
            {"hm2AgentDhcpSnoopingVlanIndex": "100",
             "hm2AgentDhcpSnoopingVlanEnable": "2"},
        ])

        result = self.backend.get_dhcp_snooping()
        self.assertTrue(result['enabled'])
        self.assertFalse(result['verify_mac'])
        self.assertEqual(len(result['vlans']), 2)
        self.assertTrue(result['vlans'][1]['enabled'])
        self.assertFalse(result['vlans'][100]['enabled'])
        self.assertEqual(len(result['ports']), 2)
        p1 = result['ports']['1/1']
        self.assertTrue(p1['trusted'])
        self.assertFalse(p1['log'])
        self.assertEqual(p1['rate_limit'], 15)
        self.assertEqual(p1['burst_interval'], 1)
        self.assertTrue(p1['auto_disable'])
        p2 = result['ports']['1/2']
        self.assertFalse(p2['trusted'])
        self.assertTrue(p2['log'])
        self.assertEqual(p2['rate_limit'], -1)
        self.assertFalse(p2['auto_disable'])

    def test_get_dhcp_snooping_single_interface(self):
        """get_dhcp_snooping('1/1') filters to one port."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDhcpSnoopingConfigGroup": [{
                    "hm2AgentDhcpSnoopingAdminMode": "2",
                    "hm2AgentDhcpSnoopingVerifyMac": "2",
                }],
                "hm2AgentDhcpSnoopingIfConfigEntry": [{
                    "ifIndex": "1",
                    "hm2AgentDhcpSnoopingIfTrustEnable": "1",
                    "hm2AgentDhcpSnoopingIfLogEnable": "2",
                    "hm2AgentDhcpSnoopingIfRateLimit": "-1",
                    "hm2AgentDhcpSnoopingIfBurstInterval": "1",
                    "hm2AgentDhcpSnoopingIfAutoDisable": "1",
                }, {
                    "ifIndex": "2",
                    "hm2AgentDhcpSnoopingIfTrustEnable": "2",
                }],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        self.backend.client.get = Mock(return_value=[])

        result = self.backend.get_dhcp_snooping('1/1')
        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_get_dhcp_snooping_skips_cpu_vlan(self):
        """CPU and VLAN interfaces are excluded."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDhcpSnoopingConfigGroup": [{
                    "hm2AgentDhcpSnoopingAdminMode": "2",
                }],
                "hm2AgentDhcpSnoopingIfConfigEntry": [{
                    "ifIndex": "100",
                    "hm2AgentDhcpSnoopingIfTrustEnable": "2",
                }, {
                    "ifIndex": "200",
                    "hm2AgentDhcpSnoopingIfTrustEnable": "2",
                }],
            }},
            {"100": "cpu0", "200": "vlan1"},
        ))
        self.backend.client.get = Mock(return_value=[])

        result = self.backend.get_dhcp_snooping()
        self.assertEqual(len(result['ports']), 0)

    def test_get_dhcp_snooping_empty_vlans(self):
        """No VLAN entries returns empty dict."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDhcpSnoopingConfigGroup": [{}],
                "hm2AgentDhcpSnoopingIfConfigEntry": [],
            }},
            {},
        ))
        self.backend.client.get = Mock(return_value=None)

        result = self.backend.get_dhcp_snooping()
        self.assertFalse(result['enabled'])
        self.assertFalse(result['verify_mac'])
        self.assertEqual(result['vlans'], {})
        self.assertEqual(result['ports'], {})

    def test_set_dhcp_snooping_global(self):
        """set_dhcp_snooping(enabled=True) sets global admin mode."""
        self.backend._apply_set = Mock()
        self.backend.set_dhcp_snooping(enabled=True)
        self.backend._apply_set.assert_called_once()
        args = self.backend._apply_set.call_args
        self.assertEqual(args[0][0], "HM2-PLATFORM-SWITCHING-MIB")
        attrs = args[0][2]
        self.assertEqual(attrs["hm2AgentDhcpSnoopingAdminMode"], "1")

    def test_set_dhcp_snooping_verify_mac(self):
        """set_dhcp_snooping(verify_mac=False) disables MAC verify."""
        self.backend._apply_set = Mock()
        self.backend.set_dhcp_snooping(verify_mac=False)
        attrs = self.backend._apply_set.call_args[0][2]
        self.assertEqual(attrs["hm2AgentDhcpSnoopingVerifyMac"], "2")

    def test_set_dhcp_snooping_vlan(self):
        """set_dhcp_snooping(vlan=1, vlan_enabled=True) enables on VLAN."""
        self.backend._apply_set_indexed = Mock()
        self.backend.set_dhcp_snooping(vlan=1, vlan_enabled=True)
        self.backend._apply_set_indexed.assert_called_once()
        args = self.backend._apply_set_indexed.call_args
        self.assertEqual(
            args[1]['index']['hm2AgentDhcpSnoopingVlanIndex'], '1')
        self.assertEqual(
            args[1]['values']['hm2AgentDhcpSnoopingVlanEnable'], '1')

    def test_set_dhcp_snooping_port(self):
        """set_dhcp_snooping('1/1', trusted=True) sets trust on port."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_dhcp_snooping('1/1', trusted=True, log=False,
                                       rate_limit=15, burst_interval=1,
                                       auto_disable=True)
        self.backend._apply_set_indexed.assert_called_once()
        args = self.backend._apply_set_indexed.call_args
        vals = args[1]['values']
        self.assertEqual(vals["hm2AgentDhcpSnoopingIfTrustEnable"], "1")
        self.assertEqual(vals["hm2AgentDhcpSnoopingIfLogEnable"], "2")
        self.assertEqual(vals["hm2AgentDhcpSnoopingIfRateLimit"], "15")
        self.assertEqual(vals["hm2AgentDhcpSnoopingIfBurstInterval"], "1")
        self.assertEqual(vals["hm2AgentDhcpSnoopingIfAutoDisable"], "1")

    def test_set_dhcp_snooping_multi_port(self):
        """set_dhcp_snooping(['1/1', '1/2'], trusted=True) sets both."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_dhcp_snooping(['1/1', '1/2'], trusted=True)
        self.assertEqual(self.backend._apply_set_indexed.call_count, 2)

    def test_set_dhcp_snooping_multi_vlan(self):
        """set_dhcp_snooping(vlan=[1, 100], vlan_enabled=True)."""
        self.backend._apply_set_indexed = Mock()
        self.backend.set_dhcp_snooping(vlan=[1, 100], vlan_enabled=True)
        self.assertEqual(self.backend._apply_set_indexed.call_count, 2)

    def test_set_dhcp_snooping_unknown_interface(self):
        """set_dhcp_snooping('9/9', ...) raises ValueError."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        with self.assertRaises(ValueError):
            self.backend.set_dhcp_snooping('9/9', trusted=True)


class TestMOPSArpInspection(unittest.TestCase):
    """Tests for get_arp_inspection / set_arp_inspection."""

    def setUp(self):
        self.backend = MOPSHIOS.__new__(MOPSHIOS)
        self.backend.client = Mock()
        self.backend._staging = False
        self.backend._mutations = []

    def test_get_arp_inspection_all(self):
        """get_arp_inspection() returns globals + vlans + ports."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDaiConfigGroup": [{
                    "hm2AgentDaiSrcMacValidate": "1",
                    "hm2AgentDaiDstMacValidate": "2",
                    "hm2AgentDaiIPValidate": "1",
                }],
                "hm2AgentDaiIfConfigEntry": [{
                    "ifIndex": "1",
                    "hm2AgentDaiIfTrustEnable": "1",
                    "hm2AgentDaiIfRateLimit": "15",
                    "hm2AgentDaiIfBurstInterval": "1",
                    "hm2AgentDaiIfAutoDisable": "1",
                }, {
                    "ifIndex": "2",
                    "hm2AgentDaiIfTrustEnable": "2",
                    "hm2AgentDaiIfRateLimit": "-1",
                    "hm2AgentDaiIfBurstInterval": "5",
                    "hm2AgentDaiIfAutoDisable": "2",
                }],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        self.backend.client.get = Mock(return_value=[
            {"hm2AgentDaiVlanIndex": "1",
             "hm2AgentDaiVlanDynArpInspEnable": "1",
             "hm2AgentDaiVlanLoggingEnable": "2",
             "hm2AgentDaiVlanArpAclName": "",
             "hm2AgentDaiVlanArpAclStaticFlag": "2",
             "hm2AgentDaiVlanBindingCheckEnable": "1"},
            {"hm2AgentDaiVlanIndex": "100",
             "hm2AgentDaiVlanDynArpInspEnable": "2",
             "hm2AgentDaiVlanLoggingEnable": "1",
             "hm2AgentDaiVlanArpAclName": "",
             "hm2AgentDaiVlanArpAclStaticFlag": "2",
             "hm2AgentDaiVlanBindingCheckEnable": "2"},
        ])

        result = self.backend.get_arp_inspection()
        self.assertTrue(result['validate_src_mac'])
        self.assertFalse(result['validate_dst_mac'])
        self.assertTrue(result['validate_ip'])
        self.assertEqual(len(result['vlans']), 2)
        self.assertTrue(result['vlans'][1]['enabled'])
        self.assertTrue(result['vlans'][1]['binding_check'])
        self.assertFalse(result['vlans'][100]['enabled'])
        self.assertTrue(result['vlans'][100]['log'])
        self.assertEqual(len(result['ports']), 2)
        p1 = result['ports']['1/1']
        self.assertTrue(p1['trusted'])
        self.assertEqual(p1['rate_limit'], 15)
        self.assertTrue(p1['auto_disable'])
        p2 = result['ports']['1/2']
        self.assertFalse(p2['trusted'])
        self.assertEqual(p2['rate_limit'], -1)
        self.assertFalse(p2['auto_disable'])

    def test_get_arp_inspection_single_interface(self):
        """get_arp_inspection('1/1') filters to one port."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDaiConfigGroup": [{}],
                "hm2AgentDaiIfConfigEntry": [{
                    "ifIndex": "1",
                    "hm2AgentDaiIfTrustEnable": "1",
                }, {
                    "ifIndex": "2",
                    "hm2AgentDaiIfTrustEnable": "2",
                }],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        self.backend.client.get = Mock(return_value=[])

        result = self.backend.get_arp_inspection('1/1')
        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_get_arp_inspection_skips_cpu(self):
        """CPU/VLAN interfaces excluded."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentDaiConfigGroup": [{}],
                "hm2AgentDaiIfConfigEntry": [{
                    "ifIndex": "100",
                    "hm2AgentDaiIfTrustEnable": "2",
                }],
            }},
            {"100": "cpu0"},
        ))
        self.backend.client.get = Mock(return_value=[])

        result = self.backend.get_arp_inspection()
        self.assertEqual(len(result['ports']), 0)

    def test_set_arp_inspection_global(self):
        """set_arp_inspection(validate_src_mac=True) sets global flag."""
        self.backend._apply_set = Mock()
        self.backend.set_arp_inspection(validate_src_mac=True,
                                        validate_ip=False)
        self.backend._apply_set.assert_called_once()
        attrs = self.backend._apply_set.call_args[0][2]
        self.assertEqual(attrs["hm2AgentDaiSrcMacValidate"], "1")
        self.assertEqual(attrs["hm2AgentDaiIPValidate"], "2")

    def test_set_arp_inspection_vlan(self):
        """set_arp_inspection(vlan=1, vlan_enabled=True)."""
        self.backend._apply_set_indexed = Mock()
        self.backend.set_arp_inspection(vlan=1, vlan_enabled=True,
                                        vlan_log=True)
        self.backend._apply_set_indexed.assert_called_once()
        args = self.backend._apply_set_indexed.call_args
        vals = args[1]['values']
        self.assertEqual(vals["hm2AgentDaiVlanDynArpInspEnable"], "1")
        self.assertEqual(vals["hm2AgentDaiVlanLoggingEnable"], "1")

    def test_set_arp_inspection_port(self):
        """set_arp_inspection('1/1', trusted=True)."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_arp_inspection('1/1', trusted=True,
                                        rate_limit=15,
                                        auto_disable=True)
        self.backend._apply_set_indexed.assert_called_once()
        vals = self.backend._apply_set_indexed.call_args[1]['values']
        self.assertEqual(vals["hm2AgentDaiIfTrustEnable"], "1")
        self.assertEqual(vals["hm2AgentDaiIfRateLimit"], "15")
        self.assertEqual(vals["hm2AgentDaiIfAutoDisable"], "1")

    def test_set_arp_inspection_multi_port(self):
        """set_arp_inspection(['1/1', '1/2'], trusted=True)."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_arp_inspection(['1/1', '1/2'], trusted=True)
        self.assertEqual(self.backend._apply_set_indexed.call_count, 2)

    def test_set_arp_inspection_unknown_interface(self):
        """set_arp_inspection('9/9', ...) raises ValueError."""
        self.backend._build_ifindex_map = Mock(return_value={"1": "1/1"})
        with self.assertRaises(ValueError):
            self.backend.set_arp_inspection('9/9', trusted=True)


class TestMOPSIpSourceGuard(unittest.TestCase):
    """Tests for get_ip_source_guard / set_ip_source_guard."""

    def setUp(self):
        self.backend = MOPSHIOS.__new__(MOPSHIOS)
        self.backend.client = Mock()
        self.backend._staging = False
        self.backend._mutations = []

    def test_get_ip_source_guard_all(self):
        """get_ip_source_guard() returns ports + bindings."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentIpsgIfConfigEntry": [{
                    "ifIndex": "1",
                    "hm2AgentIpsgIfVerifySource": "1",
                    "hm2AgentIpsgIfPortSecurity": "1",
                }, {
                    "ifIndex": "2",
                    "hm2AgentIpsgIfVerifySource": "2",
                    "hm2AgentIpsgIfPortSecurity": "2",
                }],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        self.backend.client.get = Mock(side_effect=[[], []])

        result = self.backend.get_ip_source_guard()
        self.assertEqual(len(result['ports']), 2)
        self.assertTrue(result['ports']['1/1']['verify_source'])
        self.assertTrue(result['ports']['1/1']['port_security'])
        self.assertFalse(result['ports']['1/2']['verify_source'])
        self.assertFalse(result['ports']['1/2']['port_security'])
        self.assertEqual(result['static_bindings'], [])
        self.assertEqual(result['dynamic_bindings'], [])

    def test_get_ip_source_guard_single_interface(self):
        """get_ip_source_guard('1/1') filters to one port."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentIpsgIfConfigEntry": [{
                    "ifIndex": "1",
                    "hm2AgentIpsgIfVerifySource": "1",
                    "hm2AgentIpsgIfPortSecurity": "2",
                }, {
                    "ifIndex": "2",
                    "hm2AgentIpsgIfVerifySource": "2",
                    "hm2AgentIpsgIfPortSecurity": "2",
                }],
            }},
            {"1": "1/1", "2": "1/2"},
        ))
        self.backend.client.get = Mock(side_effect=[[], []])

        result = self.backend.get_ip_source_guard('1/1')
        self.assertEqual(len(result['ports']), 1)
        self.assertIn('1/1', result['ports'])

    def test_get_ip_source_guard_defaults(self):
        """Missing attributes default to False."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentIpsgIfConfigEntry": [{
                    "ifIndex": "1",
                }],
            }},
            {"1": "1/1"},
        ))
        self.backend.client.get = Mock(side_effect=[[], []])

        result = self.backend.get_ip_source_guard()
        self.assertFalse(result['ports']['1/1']['verify_source'])
        self.assertFalse(result['ports']['1/1']['port_security'])

    def test_get_ip_source_guard_skips_cpu(self):
        """CPU interfaces are excluded."""
        self.backend._get_with_ifindex = Mock(return_value=(
            {"HM2-PLATFORM-SWITCHING-MIB": {
                "hm2AgentIpsgIfConfigEntry": [{
                    "ifIndex": "100",
                    "hm2AgentIpsgIfVerifySource": "2",
                }],
            }},
            {"100": "cpu0"},
        ))
        self.backend.client.get = Mock(side_effect=[[], []])

        result = self.backend.get_ip_source_guard()
        self.assertEqual(len(result['ports']), 0)

    def test_set_ip_source_guard_enable(self):
        """set_ip_source_guard('1/1', verify_source=True)."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_ip_source_guard('1/1', verify_source=True)
        self.backend._apply_set_indexed.assert_called_once()
        call_vals = self.backend._apply_set_indexed.call_args[1]['values']
        self.assertEqual(call_vals['hm2AgentIpsgIfVerifySource'], '1')

    def test_set_ip_source_guard_both(self):
        """set_ip_source_guard('1/1', verify_source=True, port_security=True)."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_ip_source_guard('1/1', verify_source=True,
                                         port_security=True)
        call_vals = self.backend._apply_set_indexed.call_args[1]['values']
        self.assertEqual(call_vals['hm2AgentIpsgIfVerifySource'], '1')
        self.assertEqual(call_vals['hm2AgentIpsgIfPortSecurity'], '1')

    def test_set_ip_source_guard_multi(self):
        """set_ip_source_guard(['1/1', '1/2'], verify_source=True)."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1", "2": "1/2"})
        self.backend._apply_set_indexed = Mock()
        self.backend.set_ip_source_guard(['1/1', '1/2'],
                                         verify_source=True)
        self.assertEqual(self.backend._apply_set_indexed.call_count, 2)

    def test_set_ip_source_guard_unknown_interface(self):
        """set_ip_source_guard('9/9', ...) raises ValueError."""
        self.backend._build_ifindex_map = Mock(
            return_value={"1": "1/1"})
        with self.assertRaises(ValueError):
            self.backend.set_ip_source_guard('9/9', verify_source=True)

    def test_set_ip_source_guard_no_interface(self):
        """set_ip_source_guard(interface=None) is a no-op."""
        self.backend._build_ifindex_map = Mock()
        self.backend.set_ip_source_guard()
        self.backend._build_ifindex_map.assert_not_called()


if __name__ == '__main__':
    unittest.main()
