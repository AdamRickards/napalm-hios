"""Unit tests for MOPS client — XML building, response parsing, hex decode."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import xml.etree.ElementTree as ET

from napalm_hios.mops_client import (
    MOPSClient, MOPSError,
    _decode_hex_string, _decode_hex_mac, encode_string, encode_int,
    NS_NETCONF, NS_MOPS,
)
from napalm.base.exceptions import ConnectionException


class TestHexDecoding(unittest.TestCase):
    """Test MOPS hex string and MAC decoding."""

    def test_decode_hex_string_basic(self):
        self.assertEqual(_decode_hex_string("48 65 6c 6c 6f"), "Hello")

    def test_decode_hex_string_empty(self):
        self.assertEqual(_decode_hex_string(""), "")
        self.assertEqual(_decode_hex_string(None), "")
        self.assertEqual(_decode_hex_string("   "), "")

    def test_decode_hex_string_plain_text(self):
        """Non-hex strings should be returned as-is."""
        self.assertEqual(_decode_hex_string("Hello World"), "Hello World")
        self.assertEqual(_decode_hex_string("123"), "123")

    def test_decode_hex_string_single_byte(self):
        self.assertEqual(_decode_hex_string("41"), "A")

    def test_decode_hex_string_utf8(self):
        """UTF-8 multi-byte characters should decode correctly."""
        # "ä" = 0xc3 0xa4
        self.assertEqual(_decode_hex_string("c3 a4"), "ä")

    def test_decode_hex_mac(self):
        self.assertEqual(_decode_hex_mac("64 60 38 8a 42 d6"), "64:60:38:8a:42:d6")

    def test_decode_hex_mac_not_six_bytes(self):
        """Non-6-byte values should be returned as-is."""
        self.assertEqual(_decode_hex_mac("64 60 38"), "64 60 38")

    def test_encode_string(self):
        self.assertEqual(encode_string("Lab"), "4c 61 62")
        self.assertEqual(encode_string("Hello"), "48 65 6c 6c 6f")

    def test_encode_int(self):
        self.assertEqual(encode_int(42), "42")
        self.assertEqual(encode_int(0), "0")


class TestXMLBuilding(unittest.TestCase):
    """Test MOPS XML request construction."""

    def setUp(self):
        self.client = MOPSClient("198.51.100.1", "admin", "private")

    def _strip_ns(self, tag):
        """Strip namespace prefix from XML tag for assertion."""
        if tag.startswith('{'):
            return tag.split('}', 1)[1]
        return tag

    def test_build_get_request_single(self):
        xml = self.client._build_get_request([
            ("SNMPv2-MIB", "system", ["sysDescr", "sysName"]),
        ])
        root = ET.fromstring(xml)
        self.assertEqual(self._strip_ns(root.tag), "rpc")
        self.assertEqual(root.get("message-id"), "1")

        # Find Get elements (may have namespace prefix)
        get_elems = [e for e in root.iter() if self._strip_ns(e.tag) == "Get"]
        self.assertEqual(len(get_elems), 2)
        names = [e.get("name") for e in get_elems]
        self.assertIn("sysDescr", names)
        self.assertIn("sysName", names)

    def test_build_get_request_multi_mib(self):
        """Multiple MIBs should be grouped correctly."""
        xml = self.client._build_get_request([
            ("SNMPv2-MIB", "system", ["sysDescr"]),
            ("IF-MIB", "ifEntry", ["ifIndex"]),
        ])
        root = ET.fromstring(xml)
        mib_elems = [e for e in root.iter() if self._strip_ns(e.tag) == "MIB"]
        self.assertEqual(len(mib_elems), 2)
        mib_names = [e.get("name") for e in mib_elems]
        self.assertIn("SNMPv2-MIB", mib_names)
        self.assertIn("IF-MIB", mib_names)

    def test_build_set_request_scalar(self):
        xml = self.client._build_set_request([
            ("SNMPv2-MIB", "system", {"sysLocation": "4c 61 62"}),
        ])
        root = ET.fromstring(xml)
        set_elems = [e for e in root.iter() if self._strip_ns(e.tag) == "Set"]
        self.assertEqual(len(set_elems), 1)
        self.assertEqual(set_elems[0].get("name"), "sysLocation")
        self.assertEqual(set_elems[0].text, "4c 61 62")

    def test_build_set_request_indexed(self):
        """Indexed SET should include <Index> element."""
        xml = self.client._build_set_request([
            ("HM2-FILEMGMT-MIB", "hm2FMActionEntry",
             {"hm2FMActionActivate": "9"},
             {"hm2FMActionType": "2", "hm2FMActionItemType": "10"}),
        ])
        root = ET.fromstring(xml)
        index_elems = [e for e in root.iter() if self._strip_ns(e.tag) == "Index"]
        self.assertEqual(len(index_elems), 1)
        # Index should have Attribute children
        idx_attrs = [e for e in index_elems[0]
                     if self._strip_ns(e.tag) == "Attribute"]
        self.assertEqual(len(idx_attrs), 2)

    def test_message_id_increments(self):
        xml1 = self.client._build_get_request([("X", "Y", ["Z"])])
        xml2 = self.client._build_get_request([("X", "Y", ["Z"])])
        root1 = ET.fromstring(xml1)
        root2 = ET.fromstring(xml2)
        self.assertEqual(root1.get("message-id"), "1")
        self.assertEqual(root2.get("message-id"), "2")

    def test_set_no_target_wrapper(self):
        """edit-config should NOT have a <target> wrapper."""
        xml = self.client._build_set_request([
            ("SNMPv2-MIB", "system", {"sysName": "74 65 73 74"}),
        ])
        self.assertNotIn("<target>", xml)
        self.assertIn("edit-config", xml)

    def tearDown(self):
        self.client.close()


class TestResponseParsing(unittest.TestCase):
    """Test MOPS response XML parsing."""

    def setUp(self):
        self.client = MOPSClient("198.51.100.1", "admin", "private")

    def test_parse_simple_response(self):
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="SNMPv2-MIB">
                <Node name="system">
                  <Entry>
                    <Attribute name="sysDescr">48 69 72 73 63 68 6d 61 6e 6e</Attribute>
                    <Attribute name="sysName">42 52 53 35 30</Attribute>
                  </Entry>
                </Node>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''

        result = self.client._parse_response(xml)
        self.assertEqual(result["message_id"], "1")
        self.assertIn("SNMPv2-MIB", result["mibs"])
        entries = result["mibs"]["SNMPv2-MIB"]["system"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["sysDescr"], "Hirschmann")
        self.assertEqual(entries[0]["sysName"], "BRS50")

    def test_parse_multiple_entries(self):
        """Table responses should have multiple entries."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="2">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="IF-MIB">
                <Node name="ifXEntry">
                  <Entry>
                    <Attribute name="ifIndex">1</Attribute>
                    <Attribute name="ifName">31 2f 31</Attribute>
                  </Entry>
                  <Entry>
                    <Attribute name="ifIndex">2</Attribute>
                    <Attribute name="ifName">31 2f 32</Attribute>
                  </Entry>
                </Node>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''

        result = self.client._parse_response(xml)
        entries = result["mibs"]["IF-MIB"]["ifXEntry"]
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["ifName"], "1/1")
        self.assertEqual(entries[1]["ifName"], "1/2")

    def test_parse_no_string_decode(self):
        """With decode_strings=False, hex values should be kept raw."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="TEST">
                <Node name="node">
                  <Entry>
                    <Attribute name="val">48 65 6c 6c 6f</Attribute>
                  </Entry>
                </Node>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''

        result = self.client._parse_response(xml, decode_strings=False)
        self.assertEqual(result["mibs"]["TEST"]["node"][0]["val"], "48 65 6c 6c 6f")

    def test_parse_error_response(self):
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="FAKE-MIB" error="noSuchName"/>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''

        result = self.client._parse_response(xml)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["mib"], "FAKE-MIB")
        self.assertEqual(result["errors"][0]["error"], "noSuchName")

    def test_parse_node_error(self):
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="IF-MIB">
                <Node name="badNode" error="noSuchName"/>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''

        result = self.client._parse_response(xml)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["node"], "badNode")

    def test_is_ok_response(self):
        ok_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <ok/>
        </rpc-reply>'''
        self.assertTrue(self.client._is_ok_response(ok_xml))

    def test_is_ok_mibresponse(self):
        """mibResponse is also a success indicator for some SETs."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData/>
          </mibResponse>
        </rpc-reply>'''
        self.assertTrue(self.client._is_ok_response(xml))

    def test_is_ok_mibresponse_with_attribute_error(self):
        """mibResponse with attribute-level error should raise MOPSError."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="HM2-PLATFORM-SWITCHING-MIB">
                <Node name="hm2AgentStpCstPortEntry">
                  <Entry>
                    <Attribute name="hm2AgentStpCstPortEdge" error="noCreation"/>
                  </Entry>
                </Node>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''
        with self.assertRaises(MOPSError) as ctx:
            self.client._is_ok_response(xml)
        self.assertIn("noCreation", str(ctx.exception))
        self.assertIn("hm2AgentStpCstPortEdge", str(ctx.exception))

    def test_is_ok_mibresponse_with_node_error(self):
        """mibResponse with node-level error should raise MOPSError."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="TEST-MIB">
                <Node name="badNode" error="noSuchName"/>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''
        with self.assertRaises(MOPSError) as ctx:
            self.client._is_ok_response(xml)
        self.assertIn("noSuchName", str(ctx.exception))
        self.assertIn("TEST-MIB/badNode", str(ctx.exception))

    def test_is_ok_mibresponse_with_mib_error(self):
        """mibResponse with MIB-level error should raise MOPSError."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="NONEXISTENT-MIB" error="noSuchName"/>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''
        with self.assertRaises(MOPSError) as ctx:
            self.client._is_ok_response(xml)
        self.assertIn("noSuchName", str(ctx.exception))
        self.assertIn("NONEXISTENT-MIB", str(ctx.exception))

    def test_parse_response_attribute_error(self):
        """_parse_response should capture attribute-level errors."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="TEST-MIB">
                <Node name="testEntry">
                  <Entry>
                    <Attribute name="goodAttr">42</Attribute>
                    <Attribute name="badAttr" error="noCreation"/>
                  </Entry>
                </Node>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''
        result = self.client._parse_response(xml, decode_strings=False)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(result["errors"][0]["attribute"], "badAttr")
        self.assertEqual(result["errors"][0]["error"], "noCreation")
        # Good attribute should still be parsed
        entry = result["mibs"]["TEST-MIB"]["testEntry"][0]
        self.assertEqual(entry["goodAttr"], "42")
        self.assertNotIn("badAttr", entry)

    def test_parse_empty_attribute(self):
        """Self-closing attributes (no text) should return empty string."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply xmlns="{NS_NETCONF}" message-id="1">
          <mibResponse xmlns="{NS_MOPS}">
            <MIBData>
              <MIB name="TEST">
                <Node name="node">
                  <Entry>
                    <Attribute name="empty"/>
                    <Attribute name="full">31</Attribute>
                  </Entry>
                </Node>
              </MIB>
            </MIBData>
          </mibResponse>
        </rpc-reply>'''

        result = self.client._parse_response(xml)
        entry = result["mibs"]["TEST"]["node"][0]
        self.assertEqual(entry["empty"], "")
        self.assertEqual(entry["full"], "1")

    def tearDown(self):
        self.client.close()


class TestConnectionHandling(unittest.TestCase):
    """Test MOPS client connection error handling."""

    @patch('napalm_hios.mops_client.requests.Session')
    def test_connection_error_raises(self, mock_session_cls):
        """HTTP connection errors should raise ConnectionException."""
        import requests
        mock_session = mock_session_cls.return_value
        mock_session.post.side_effect = requests.exceptions.ConnectionError("refused")
        mock_session.auth = ("admin", "private")
        mock_session.verify = False
        mock_session.headers = {}

        client = MOPSClient("198.51.100.1", "admin", "private")
        client.session = mock_session
        with self.assertRaises(ConnectionException):
            client._send("<rpc/>")

    @patch('napalm_hios.mops_client.requests.Session')
    def test_auth_failure_raises(self, mock_session_cls):
        """HTTP 401 should raise ConnectionException with auth message."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_session = mock_session_cls.return_value
        mock_session.post.return_value = mock_response

        client = MOPSClient("198.51.100.1", "admin", "wrong")
        client.session = mock_session
        with self.assertRaises(ConnectionException) as ctx:
            client._send("<rpc/>")
        self.assertIn("authentication", str(ctx.exception).lower())

    @patch('napalm_hios.mops_client.requests.Session')
    def test_http_error_raises_mops_error(self, mock_session_cls):
        """Non-200/401 HTTP errors should raise MOPSError."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_session = mock_session_cls.return_value
        mock_session.post.return_value = mock_response

        client = MOPSClient("198.51.100.1", "admin", "private")
        client.session = mock_session
        with self.assertRaises(MOPSError):
            client._send("<rpc/>")


class TestContextManager(unittest.TestCase):
    """Test MOPSClient context manager."""

    def test_context_manager(self):
        with MOPSClient("198.51.100.1") as client:
            self.assertIsNotNone(client.session)


class TestChangePassword(unittest.TestCase):
    """Test MOPSClient.change_password() — two-step factory onboarding.

    The change_password flow mirrors the web UI:
    1. POST /mops_login → 401 + <pwchange-request/> (on gated devices)
    2. POST /mops_changePassword → 200 + <pwchange-ok/>

    Both use a SEPARATE session without HTTP Basic auth but WITH
    Content-Type: application/xml (required — without it the device
    cold-starts instead of handling the request gracefully).
    """

    def setUp(self):
        self.client = MOPSClient("198.51.100.1", "admin", "private")
        # Mock the safety guard — tests assume device is gated (needs onboarding)
        self.client.is_factory_default = Mock(return_value=True)

    def _make_mock_session(self, login_response=None, pw_response=None,
                           pw_side_effect=None):
        """Build a mock Session whose post() handles the two-step flow.

        First call → mops_login response (default: 401 pwchange-request).
        Second call → mops_changePassword response (default: 200 pwchange-ok).
        """
        mock_session = MagicMock()
        mock_session.verify = True  # will be overwritten to False
        mock_session.headers = {}

        if login_response is None:
            login_response = Mock()
            login_response.status_code = 401
            login_response.text = (
                '<mops-auth>\n<pwchange-request/>\n</mops-auth>')

        if pw_side_effect:
            mock_session.post.side_effect = [login_response, pw_side_effect]
        elif pw_response is None:
            pw_resp = Mock()
            pw_resp.status_code = 200
            pw_resp.text = "<mops-auth><pwchange-ok/></mops-auth>"
            mock_session.post.side_effect = [login_response, pw_resp]
        else:
            mock_session.post.side_effect = [login_response, pw_response]

        return mock_session

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_success(self, mock_session_cls):
        """Two-step flow: login→401, changePassword→200 returns True."""
        mock_session = self._make_mock_session()
        mock_session_cls.return_value = mock_session

        result = self.client.change_password("NewPass1")
        self.assertTrue(result)
        self.assertEqual(self.client.session.auth, ("admin", "NewPass1"))
        # Two POSTs: mops_login then mops_changePassword
        self.assertEqual(mock_session.post.call_count, 2)
        self.assertIn("/mops_login", mock_session.post.call_args_list[0][0][0])
        self.assertIn("/mops_changePassword",
                      mock_session.post.call_args_list[1][0][0])

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_same_password(self, mock_session_cls):
        """Setting password to same value works (clears factory gate)."""
        mock_session = self._make_mock_session()
        mock_session_cls.return_value = mock_session

        result = self.client.change_password("private")
        self.assertTrue(result)
        self.assertEqual(self.client.session.auth, ("admin", "private"))

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_different_user(self, mock_session_cls):
        """Changing another user's password doesn't update our session auth."""
        mock_session = self._make_mock_session()
        mock_session_cls.return_value = mock_session

        result = self.client.change_password("NewPass1", username="user",
                                             current_password="public")
        self.assertTrue(result)
        # Our session auth should NOT change
        self.assertEqual(self.client.session.auth, ("admin", "private"))

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_auth_failure(self, mock_session_cls):
        """HTTP 401 on mops_changePassword raises ConnectionException."""
        pw_response = Mock()
        pw_response.status_code = 401
        pw_response.text = "Unauthorized"
        mock_session = self._make_mock_session(pw_response=pw_response)
        mock_session_cls.return_value = mock_session

        with self.assertRaises(ConnectionException) as ctx:
            self.client.change_password("NewPass1")
        self.assertIn("auth failed", str(ctx.exception))

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_http_error(self, mock_session_cls):
        """Non-200/401 HTTP errors on mops_changePassword raise MOPSError."""
        pw_response = Mock()
        pw_response.status_code = 500
        pw_response.text = "Internal Server Error"
        mock_session = self._make_mock_session(pw_response=pw_response)
        mock_session_cls.return_value = mock_session

        with self.assertRaises(MOPSError):
            self.client.change_password("NewPass1")

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_unexpected_response(self, mock_session_cls):
        """Response 200 without <pwchange-ok/> raises MOPSError."""
        pw_response = Mock()
        pw_response.status_code = 200
        pw_response.text = "<mops-auth><error/></mops-auth>"
        mock_session = self._make_mock_session(pw_response=pw_response)
        mock_session_cls.return_value = mock_session

        with self.assertRaises(MOPSError):
            self.client.change_password("NewPass1")

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_timeout_is_success(self, mock_session_cls):
        """Timeout on mops_changePassword = success (some firmware)."""
        import requests
        mock_session = self._make_mock_session(
            pw_side_effect=requests.exceptions.Timeout("timed out"))
        mock_session_cls.return_value = mock_session

        result = self.client.change_password("NewPass1")
        self.assertTrue(result)
        self.assertEqual(self.client.session.auth, ("admin", "NewPass1"))

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_connection_error(self, mock_session_cls):
        """Network error on mops_changePassword raises ConnectionException."""
        import requests
        mock_session = self._make_mock_session(
            pw_side_effect=requests.exceptions.ConnectionError("refused"))
        mock_session_cls.return_value = mock_session

        with self.assertRaises(ConnectionException) as ctx:
            self.client.change_password("NewPass1")
        self.assertIn("failed", str(ctx.exception))

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_uses_no_auth_session(self, mock_session_cls):
        """Verify a SEPARATE session is used — no HTTP Basic auth."""
        mock_session = self._make_mock_session()
        mock_session_cls.return_value = mock_session

        # Replace client's own session with a mock to verify it's NOT used
        original_session = self.client.session
        self.client.session = Mock()
        self.client.session.auth = original_session.auth

        self.client.change_password("Private1")
        # A new Session was created (not the client's session)
        mock_session_cls.assert_called_once()
        # verify=False was set on the no-auth session
        self.assertFalse(mock_session.verify)
        # Content-Type: application/xml was set on the session
        self.assertEqual(mock_session.headers.get("Content-Type"),
                         "application/xml")
        # The client's own session should NOT have been used for the POST
        self.client.session.post.assert_not_called()

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_xml_payload(self, mock_session_cls):
        """Verify the mops_changePassword XML envelope format."""
        mock_session = self._make_mock_session()
        mock_session_cls.return_value = mock_session

        self.client.change_password("Private1")
        # Second POST is the changePassword call
        call_args = mock_session.post.call_args_list[1]
        payload = call_args.kwargs.get('data', '')
        if not payload and len(call_args.args) > 1:
            payload = call_args.args[1]
        self.assertIn("<mops-auth>", payload)
        self.assertIn("<pwchange>", payload)
        self.assertIn("<user>admin</user>", payload)
        self.assertIn("<password>private</password>", payload)
        self.assertIn("<new-password>Private1</new-password>", payload)

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_login_payload(self, mock_session_cls):
        """Verify the mops_login XML envelope format."""
        mock_session = self._make_mock_session()
        mock_session_cls.return_value = mock_session

        self.client.change_password("Private1")
        # First POST is the login call
        call_args = mock_session.post.call_args_list[0]
        payload = call_args.kwargs.get('data', '')
        if not payload and len(call_args.args) > 1:
            payload = call_args.args[1]
        self.assertIn("<mops-auth>", payload)
        self.assertIn("<login>", payload)
        self.assertIn("<app-name>webif</app-name>", payload)
        self.assertIn("<user>admin</user>", payload)
        self.assertIn("<password>private</password>", payload)

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_blocked_by_login_ok(self, mock_session_cls):
        """If mops_login returns 200+ok, device is onboarded — refuse."""
        login_response = Mock()
        login_response.status_code = 200
        login_response.text = (
            '<mops-auth><ok><session-key>abc</session-key>'
            '<auth-type>local</auth-type></ok></mops-auth>')
        mock_session = self._make_mock_session(login_response=login_response)
        mock_session_cls.return_value = mock_session

        with self.assertRaises(ConnectionException) as ctx:
            self.client.change_password("NewPass1")
        self.assertIn("already onboarded", str(ctx.exception))
        # Only one POST (login) — changePassword never called
        self.assertEqual(mock_session.post.call_count, 1)

    @patch('napalm_hios.mops_client.requests.Session')
    def test_change_password_login_network_error(self, mock_session_cls):
        """Network error on mops_login raises ConnectionException."""
        import requests
        mock_session = MagicMock()
        mock_session.headers = {}
        mock_session.post.side_effect = requests.exceptions.ConnectionError(
            "refused")
        mock_session_cls.return_value = mock_session

        with self.assertRaises(ConnectionException) as ctx:
            self.client.change_password("NewPass1")
        self.assertIn("login failed", str(ctx.exception))

    def test_change_password_blocked_on_onboarded_device(self):
        """change_password refuses if is_factory_default() says onboarded."""
        self.client.is_factory_default = Mock(return_value=False)

        with self.assertRaises(ConnectionException) as ctx:
            self.client.change_password("NewPass1")
        self.assertIn("already onboarded", str(ctx.exception))

    def tearDown(self):
        self.client.close()


class TestIsFactoryDefault(unittest.TestCase):
    """Test MOPSClient.is_factory_default() — gate flag detection."""

    def setUp(self):
        self.client = MOPSClient("198.51.100.1", "admin", "private")

    def test_factory_default_true(self):
        """ForcePasswordStatus=1 means factory gate active."""
        self.client.get = Mock(return_value=[
            {"hm2UserForcePasswordStatus": "1"}
        ])
        self.assertTrue(self.client.is_factory_default())

    def test_factory_default_false(self):
        """ForcePasswordStatus=2 means already onboarded."""
        self.client.get = Mock(return_value=[
            {"hm2UserForcePasswordStatus": "2"}
        ])
        self.assertFalse(self.client.is_factory_default())

    def test_factory_default_empty_response(self):
        """Empty response returns False (safe default)."""
        self.client.get = Mock(return_value=[])
        self.assertFalse(self.client.is_factory_default())

    def test_factory_default_missing_attribute(self):
        """Response without the expected attribute returns False."""
        self.client.get = Mock(return_value=[{"someOtherAttr": "1"}])
        self.assertFalse(self.client.is_factory_default())

    def tearDown(self):
        self.client.close()


class TestSessionKey(unittest.TestCase):
    """Test MOPS session key authentication for download/upload."""

    def setUp(self):
        self.client = MOPSClient("198.51.100.1", "admin", "private")

    def test_get_session_key_success(self):
        """Extract session key from mops_login response."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '<mops-auth><session-key>abc123</session-key></mops-auth>'
        with patch('napalm_hios.mops_client.requests.Session') as MockSession:
            MockSession.return_value.__enter__ = Mock(return_value=MockSession.return_value)
            MockSession.return_value.__exit__ = Mock(return_value=False)
            MockSession.return_value.post.return_value = mock_resp
            MockSession.return_value.verify = False
            MockSession.return_value.headers = {}
            MockSession.return_value.close = Mock()
            key = self.client._get_session_key()
            self.assertEqual(key, 'abc123')

    def test_get_session_key_cached(self):
        """Cached key returned without new request."""
        self.client._session_key = 'cached-key'
        key = self.client._get_session_key()
        self.assertEqual(key, 'cached-key')

    def test_get_session_key_failure_returns_none(self):
        """Failed login returns None (falls back to Basic auth)."""
        import requests as req
        with patch('napalm_hios.mops_client.requests.Session') as MockSession:
            MockSession.return_value.post.side_effect = (
                req.exceptions.ConnectionError("connection refused"))
            MockSession.return_value.verify = False
            MockSession.return_value.headers = {}
            MockSession.return_value.close = Mock()
            key = self.client._get_session_key()
            self.assertIsNone(key)

    def test_config_auth_headers_with_key(self):
        """Returns Mops auth header when session key available."""
        self.client._session_key = 'test-key'
        headers = self.client._config_auth_headers()
        self.assertEqual(headers['Authorization'], 'Mops test-key')

    def test_config_auth_headers_without_key(self):
        """Returns empty dict when no session key (falls back to Basic)."""
        self.client._session_key = None
        with patch('napalm_hios.mops_client.requests.Session'):
            headers = self.client._config_auth_headers()
            self.assertEqual(headers, {})

    def tearDown(self):
        self.client.close()


class TestConfigTransfer(unittest.TestCase):
    """Test download_config, upload_config, config_transfer."""

    def setUp(self):
        self.client = MOPSClient("198.51.100.1", "admin", "private")

    def test_download_config(self):
        """Download config via HTTPS GET."""
        self.client._config_auth_headers = Mock(return_value={
            'Authorization': 'Mops testkey'})
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = '<?xml version="1.0"?><Config/>'
        self.client.session.get = Mock(return_value=mock_resp)

        xml = self.client.download_config('CLAMPS', source='nvm')
        self.assertEqual(xml, '<?xml version="1.0"?><Config/>')
        call_args = self.client.session.get.call_args
        self.assertIn('download.html', call_args[0][0])
        self.assertIn('profile=CLAMPS', call_args[0][0])
        self.assertIn('source=nvm', call_args[0][0])

    def test_download_config_http_error(self):
        """HTTP error raises ConnectionException."""
        self.client._config_auth_headers = Mock(return_value={})
        mock_resp = Mock()
        mock_resp.status_code = 400
        mock_resp.text = 'Bad Request'
        self.client.session.get = Mock(return_value=mock_resp)
        with self.assertRaises(ConnectionException):
            self.client.download_config('CLAMPS')

    def test_upload_config(self):
        """Upload config via HTTPS POST multipart."""
        self.client._config_auth_headers = Mock(return_value={
            'Authorization': 'Mops testkey'})
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = ("<html><body><upload-result>"
                          "<errortoken value='config.OK'/>"
                          "<errortext value='Configuration successfully "
                          "uploaded on {0}' /><param><para value='brs'/>"
                          "</param></upload-result></body></html>")
        self.client.session.post = Mock(return_value=mock_resp)

        result = self.client.upload_config('<Config/>', 'CLAMPS')
        self.assertTrue(result)
        call_args = self.client.session.post.call_args
        self.assertIn('upload.html', call_args[0][0])
        self.assertIn('profile=CLAMPS', call_args[0][0])

    def test_upload_config_error_raises(self):
        """Upload that returns error token raises ConnectionException."""
        self.client._config_auth_headers = Mock(return_value={
            'Authorization': 'Mops testkey'})
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.text = ("<html><body><upload-result>"
                          "<errortoken value='config.invalidProfile'/>"
                          "<errortext value='Invalid profile name on "
                          "device {0}' /><param><para value='brs'/>"
                          "</param></upload-result></body></html>")
        self.client.session.post = Mock(return_value=mock_resp)

        with self.assertRaises(ConnectionException) as ctx:
            self.client.upload_config('<Config/>', 'bad name')
        self.assertIn('Invalid profile name', str(ctx.exception))

    def test_config_transfer_push(self):
        """Push triggers action table with correct params."""
        # Mock _wait_action_idle (returns idle)
        self.client._wait_action_idle = Mock(return_value={
            'hm2FMActionStatus': '1'})
        # Mock get for reading activate key
        self.client._send = Mock(return_value='<rpc/>')
        self.client._parse_response = Mock(return_value={
            'mibs': {'HM2-FILEMGMT-MIB': {'hm2FileMgmtActionGroup': [
                {'hm2FMActionActivateKey': '44'}
            ]}}, 'errors': []})
        self.client.set = Mock(return_value=True)
        self.client.set_indexed = Mock(return_value=True)

        result = self.client.config_transfer(
            action='push', server_url='tftp://10.2.1.4/test.xml',
            source_type='2', dest_type='20',
            source_data='CLAMPS', dest_data='tftp://10.2.1.4/test.xml')

        # Verify source/dest data SET with hex encoding
        set_call = self.client.set.call_args
        values = set_call[0][2]
        self.assertIn('hm2FMActionSourceData', values)
        self.assertIn('hm2FMActionDestinationData', values)
        # Values should be hex-encoded
        self.assertEqual(values['hm2FMActionSourceData'],
                         encode_string('CLAMPS'))

        # Verify trigger SET
        idx_call = self.client.set_indexed.call_args
        self.assertEqual(idx_call.kwargs['values'],
                         {'hm2FMActionActivate': '44'})

    def tearDown(self):
        self.client.close()


if __name__ == '__main__':
    unittest.main()
