"""Unit tests for MOPS backend — getters with mocked MOPSClient."""

import unittest
from unittest.mock import Mock, patch, MagicMock

from napalm_hios.mops_hios import (
    MOPSHIOS, _safe_int, _parse_sysDescr, _mask_to_prefix,
    _decode_portlist_hex, _decode_lldp_capabilities,
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
        # hm2UserAccessRole value IS the privilege level (15=admin, 1=readOnly)
        self.backend.client.get.return_value = [
            {"hm2UserName": "61 64 6d 69 6e", "hm2UserAccessRole": "15", "hm2UserStatus": "1"},
            {"hm2UserName": "75 73 65 72", "hm2UserAccessRole": "1", "hm2UserStatus": "1"},
        ]

        users = self.backend.get_users()
        self.assertIn("admin", users)
        self.assertEqual(users["admin"]["level"], 15)
        self.assertIn("user", users)
        self.assertEqual(users["user"]["level"], 1)

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


if __name__ == '__main__':
    unittest.main()
