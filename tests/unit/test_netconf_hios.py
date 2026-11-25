"""Unit tests for the IETF-only NETCONF client.

Fixtures under tests/fixtures/netconf/ are sanitized placeholders
shaped like the 10.7.00 BETA83 BRS replies. They contain no lab
identity.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from lxml import etree
from napalm.base.exceptions import ConnectionException

from napalm_hios.hios import DEFAULT_PROTOCOL_PREFERENCE, HIOSDriver
from napalm_hios.netconf_hios import (
    NETCONF_PROFILES,
    NetconfHIOS,
    select_netconf_profile,
    uptime_seconds,
)


FIXTURES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "fixtures", "netconf")
)

HOST = "192.0.2.1"
USER = "testuser"
PASS = "testpass"


def _load(name):
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return fh.read()


class FakeReply:
    """Minimal ncclient-style reply with data_ele / xml."""

    def __init__(self, xml_text):
        self.xml = xml_text
        root = etree.fromstring(xml_text.encode("utf-8"))
        data = root.find("{urn:ietf:params:xml:ns:netconf:base:1.0}data")
        self.data_ele = data if data is not None else root
        self.data_xml = (
            etree.tostring(self.data_ele, encoding="unicode") if self.data_ele is not None else ""
        )


class TestUptimeAndProfile(unittest.TestCase):
    def test_uptime_treats_z_as_naive(self):
        # Same-suffix "Z" stamps 9 minutes 54 seconds apart.
        self.assertEqual(
            uptime_seconds("2026-11-25T15:15:46Z", "2026-11-25T15:05:52Z"),
            594,
        )

    def test_uptime_missing_returns_zero(self):
        self.assertEqual(uptime_seconds("", "2026-11-25T15:05:52Z"), 0)
        self.assertEqual(uptime_seconds("2026-11-25T15:15:46Z", ""), 0)

    def test_uptime_negative_clamped(self):
        self.assertEqual(
            uptime_seconds("2026-11-25T15:05:52Z", "2026-11-25T15:15:46Z"),
            0,
        )

    def test_default_profile_is_ietf_only(self):
        caps = [
            "urn:ietf:params:netconf:base:1.1",
            "urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces",
            "urn:ietf:params:xml:ns:yang:ietf-system?module=ietf-system",
        ]
        self.assertEqual(select_netconf_profile(caps), "ietf-only")

    def test_vendor_profile_wins_when_registered(self):
        # Inject a temporary vendor profile, then restore.
        original = dict(NETCONF_PROFILES)
        try:
            NETCONF_PROFILES["hios-vendor"] = {
                "advertised_modules": ("urn:example:params:xml:ns:yang:hios",),
                "supported_getters": (),
                "paths": {},
                "parser_hooks": {},
            }
            caps = [
                "urn:ietf:params:xml:ns:yang:ietf-system?module=ietf-system",
                "urn:example:params:xml:ns:yang:hios?module=hios",
            ]
            self.assertEqual(select_netconf_profile(caps), "hios-vendor")
        finally:
            NETCONF_PROFILES.clear()
            NETCONF_PROFILES.update(original)


class TestParseFixtures(unittest.TestCase):
    def setUp(self):
        self.client = NetconfHIOS(HOST, USER, PASS)
        self.if_xml = _load("ietf-interfaces-get.xml")
        self.sys_xml = _load("ietf-system-get.xml")
        self.oper_xml = _load("ietf-system-operational.xml")

    def test_facts_from_fixtures(self):
        facts = self.client.parse_facts_xml(
            self.sys_xml, interfaces_xml=self.if_xml, operational_xml=self.oper_xml
        )
        self.assertEqual(facts["uptime"], 594)
        self.assertEqual(facts["vendor"], "Belden")
        self.assertEqual(facts["os_version"], "")
        self.assertEqual(facts["serial_number"], "")
        self.assertEqual(facts["model"], "")
        self.assertEqual(facts["hostname"], "sw1")
        self.assertEqual(facts["fqdn"], "sw1")
        self.assertEqual(facts["interface_list"], ["1/1", "1/2", "1/3", "1/4", "cpu/1"])

    def test_facts_without_operational_has_empty_hostname(self):
        facts = self.client.parse_facts_xml(self.sys_xml, interfaces_xml=self.if_xml)
        self.assertEqual(facts["hostname"], "")
        self.assertEqual(facts["uptime"], 594)

    def test_facts_do_not_use_kernel_as_os_version(self):
        facts = self.client.parse_facts_xml(self.sys_xml)
        self.assertEqual(facts["os_version"], "")
        self.assertEqual(facts["model"], "")

    def test_interfaces_admin_oper_not_swapped(self):
        ifaces = self.client.parse_interfaces_xml(self.if_xml)
        # 1/1: admin enabled, oper up, no speed leaf (fiber quirk)
        self.assertTrue(ifaces["1/1"]["is_enabled"])
        self.assertTrue(ifaces["1/1"]["is_up"])
        self.assertEqual(ifaces["1/1"]["speed"], 0)
        self.assertEqual(ifaces["1/1"]["mtu"], 1500)
        self.assertEqual(ifaces["1/1"]["description"], "")
        self.assertEqual(ifaces["1/1"]["mac_address"], "00:11:22:33:44:01")
        self.assertEqual(ifaces["1/1"]["last_flapped"], -1.0)
        # 1/2: up copper with 1G in bits/s
        self.assertTrue(ifaces["1/2"]["is_up"])
        self.assertTrue(ifaces["1/2"]["is_enabled"])
        self.assertEqual(ifaces["1/2"]["speed"], 1_000_000_000)
        # 1/3: admin enabled, oper down, speed 0
        self.assertTrue(ifaces["1/3"]["is_enabled"])
        self.assertFalse(ifaces["1/3"]["is_up"])
        self.assertEqual(ifaces["1/3"]["speed"], 0)
        # 1/4: admin disabled, oper down, has a description
        self.assertFalse(ifaces["1/4"]["is_enabled"])
        self.assertFalse(ifaces["1/4"]["is_up"])
        self.assertEqual(ifaces["1/4"]["description"], "uplink to core")
        # cpu/1: up, speed 0
        self.assertTrue(ifaces["cpu/1"]["is_up"])
        self.assertTrue(ifaces["cpu/1"]["is_enabled"])
        self.assertEqual(ifaces["cpu/1"]["speed"], 0)
        self.assertEqual(ifaces["cpu/1"]["description"], "")

    def test_counters(self):
        counters = self.client.parse_counters_xml(self.if_xml)
        self.assertEqual(counters["1/1"]["rx_octets"], 1000)
        self.assertEqual(counters["1/1"]["tx_octets"], 2000)
        self.assertEqual(counters["1/1"]["rx_unicast_packets"], 10)
        self.assertEqual(counters["1/1"]["tx_unicast_packets"], 20)
        self.assertEqual(counters["1/1"]["rx_broadcast_packets"], 1)
        self.assertEqual(counters["1/1"]["tx_broadcast_packets"], 3)
        self.assertEqual(counters["1/1"]["rx_multicast_packets"], 2)
        self.assertEqual(counters["1/1"]["tx_multicast_packets"], 4)
        self.assertEqual(counters["1/2"]["rx_discards"], 1)
        self.assertEqual(counters["1/2"]["tx_discards"], 3)
        self.assertEqual(counters["1/2"]["rx_errors"], 2)
        self.assertEqual(counters["1/2"]["tx_errors"], 4)
        self.assertEqual(counters["1/3"]["rx_octets"], 0)
        self.assertIn("cpu/1", counters)

    def test_snmp_information_is_honest(self):
        snmp = self.client.parse_snmp_xml(self.sys_xml)
        self.assertEqual(snmp["contact"], "Example Contact")
        self.assertEqual(snmp["location"], "Example Location")
        self.assertEqual(snmp["chassis_id"], "")
        self.assertEqual(snmp["community"], {})


class TestNetconfGettersWithMockSession(unittest.TestCase):
    def setUp(self):
        self.client = NetconfHIOS(HOST, USER, PASS, timeout=30, port=830)
        self.client.connection = MagicMock()

        if_reply = FakeReply(_load("ietf-interfaces-get.xml"))
        sys_reply = FakeReply(_load("ietf-system-get.xml"))
        oper_reply = FakeReply(_load("ietf-system-operational.xml"))
        running_reply = FakeReply(_load("get-config-running.xml"))
        candidate_reply = FakeReply(_load("get-config-candidate.xml"))

        def _get(filter=None):
            filt = ""
            if filter is not None:
                filt = filter[1] if isinstance(filter, tuple) else str(filter)
            if "ietf-system" in filt:
                return sys_reply
            return if_reply

        def _dispatch(rpc):
            return oper_reply

        def _get_config(source="running"):
            if source == "candidate":
                return candidate_reply
            return running_reply

        self.client.connection.get.side_effect = _get
        self.client.connection.dispatch.side_effect = _dispatch
        self.client.connection.get_config.side_effect = _get_config

    def test_get_facts_uses_operational_hostname(self):
        facts = self.client.get_facts()
        self.assertEqual(facts["hostname"], "sw1")
        self.assertEqual(facts["vendor"], "Belden")
        self.assertEqual(facts["model"], "")
        self.assertEqual(facts["serial_number"], "")
        self.assertEqual(facts["os_version"], "")
        self.assertEqual(facts["uptime"], 594)
        self.assertEqual(facts["interface_list"], ["1/1", "1/2", "1/3", "1/4", "cpu/1"])
        # Namespaced subtree filters, not bare element names.
        called_filters = [
            call.kwargs.get("filter") or (call.args[0] if call.args else None)
            for call in self.client.connection.get.call_args_list
        ]
        blob = " ".join(
            c[1] if isinstance(c, tuple) and len(c) > 1 else str(c) for c in called_filters
        )
        self.assertIn("urn:ietf:params:xml:ns:yang:ietf-system", blob)
        self.assertIn("urn:ietf:params:xml:ns:yang:ietf-interfaces", blob)

    def test_get_interfaces_and_counters(self):
        ifaces = self.client.get_interfaces()
        self.assertTrue(ifaces["1/1"]["is_up"])
        self.assertTrue(ifaces["1/1"]["is_enabled"])
        self.assertEqual(ifaces["1/2"]["speed"], 1_000_000_000)
        counters = self.client.get_interfaces_counters()
        self.assertEqual(counters["1/1"]["rx_octets"], 1000)

    def test_get_config_running_and_candidate(self):
        config = self.client.get_config(retrieve="all")
        self.assertIn("<interfaces", config["running"])
        self.assertIn("urn:ietf:params:xml:ns:yang:ietf-interfaces", config["running"])
        self.assertIn("<system", config["candidate"])
        self.assertEqual(config["startup"], "")
        only_running = self.client.get_config(retrieve="running")
        self.assertTrue(only_running["running"])
        self.assertEqual(only_running["candidate"], "")
        only_startup = self.client.get_config(retrieve="startup")
        self.assertEqual(only_startup["running"], "")
        self.assertEqual(only_startup["startup"], "")

    def test_get_config_rejects_bad_retrieve(self):
        with self.assertRaises(ValueError):
            self.client.get_config(retrieve="intended")

    def test_get_snmp_information(self):
        snmp = self.client.get_snmp_information()
        self.assertEqual(snmp["contact"], "Example Contact")
        self.assertEqual(snmp["location"], "Example Location")
        self.assertEqual(snmp["chassis_id"], "")
        self.assertEqual(snmp["community"], {})

    def test_getters_require_connection(self):
        bare = NetconfHIOS(HOST, USER, PASS)
        with self.assertRaises(ConnectionException):
            bare.get_facts()


class TestOpenClose(unittest.TestCase):
    @patch("napalm_hios.netconf_hios.manager.connect")
    def test_open_selects_ietf_profile(self, mock_connect):
        session = MagicMock()
        session.server_capabilities = [
            "urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces",
            "urn:ietf:params:xml:ns:yang:ietf-system?module=ietf-system",
        ]
        mock_connect.return_value = session
        client = NetconfHIOS(HOST, USER, PASS, timeout=15, port=830)
        client.open()
        kwargs = mock_connect.call_args.kwargs
        self.assertEqual(kwargs["host"], HOST)
        self.assertEqual(kwargs["port"], 830)
        self.assertEqual(kwargs["username"], USER)
        self.assertEqual(kwargs["password"], PASS)
        self.assertFalse(kwargs["hostkey_verify"])
        self.assertFalse(kwargs["allow_agent"])
        self.assertFalse(kwargs["look_for_keys"])
        self.assertEqual(kwargs["timeout"], 15)
        self.assertEqual(kwargs["device_params"], {"name": "default"})
        self.assertEqual(client.profile, "ietf-only")
        client.close()
        session.close_session.assert_called_once()

    @patch("napalm_hios.netconf_hios.manager.connect")
    def test_open_wraps_failures(self, mock_connect):
        mock_connect.side_effect = OSError("refused")
        client = NetconfHIOS(HOST, USER, PASS)
        with self.assertRaises(ConnectionException) as ctx:
            client.open()
        # Hostname is mentioned; the raw OS error / secrets are not.
        self.assertIn(HOST, str(ctx.exception))
        self.assertNotIn("refused", str(ctx.exception))


class TestDriverSelector(unittest.TestCase):
    def test_default_preference_puts_netconf_last(self):
        self.assertEqual(
            DEFAULT_PROTOCOL_PREFERENCE, ["mops", "snmp", "ssh", "netconf"]
        )
        self.assertEqual(DEFAULT_PROTOCOL_PREFERENCE[-1], "netconf")
        self.assertEqual(DEFAULT_PROTOCOL_PREFERENCE[0], "mops")

    def test_supported_getters_dispatch_to_netconf(self):
        driver = HIOSDriver(HOST, USER, PASS, timeout=60, optional_args={})
        driver.active_protocol = "netconf"
        driver.netconf = MagicMock()
        driver.netconf.get_facts.return_value = {
            "uptime": 1,
            "vendor": "Belden",
            "os_version": "",
            "serial_number": "",
            "model": "",
            "hostname": "sw1",
            "fqdn": "sw1",
            "interface_list": ["1/1"],
        }
        driver.netconf.get_interfaces.return_value = {}
        driver.netconf.get_interfaces_counters.return_value = {}
        driver.netconf.get_config.return_value = {
            "running": "<data/>",
            "startup": "",
            "candidate": "<data/>",
        }
        driver.netconf.get_snmp_information.return_value = {
            "chassis_id": "",
            "community": {},
            "contact": "Example Contact",
            "location": "Example Location",
        }
        self.assertEqual(driver.get_facts()["hostname"], "sw1")
        self.assertEqual(driver.get_interfaces(), {})
        self.assertEqual(driver.get_interfaces_counters(), {})
        self.assertEqual(driver.get_config()["startup"], "")
        self.assertEqual(driver.get_snmp_information()["contact"], "Example Contact")
        driver.netconf.get_facts.assert_called_once()
        driver.netconf.get_config.assert_called()

    def test_unsupported_getters_raise(self):
        driver = HIOSDriver(HOST, USER, PASS, timeout=60, optional_args={})
        driver.active_protocol = "netconf"
        driver.netconf = MagicMock()
        with self.assertRaises(NotImplementedError):
            driver.get_vlans()
        with self.assertRaises(NotImplementedError):
            driver.get_lldp_neighbors()
        with self.assertRaises(NotImplementedError):
            driver.get_mac_address_table()
        with self.assertRaises(NotImplementedError):
            driver.get_arp_table()
        with self.assertRaises(NotImplementedError):
            driver.get_interfaces_ip()
        with self.assertRaises(NotImplementedError):
            driver.get_users()
        # get_config must not lazy-connect SSH when netconf is active
        driver.ssh = MagicMock()
        driver.netconf.get_config.return_value = {
            "running": "x",
            "startup": "",
            "candidate": "y",
        }
        driver.get_config()
        driver.ssh.get_config.assert_not_called()


if __name__ == "__main__":
    unittest.main()
