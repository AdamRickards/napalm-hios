"""
MOPS Client — talk to HiOS switches via MOPS (MIB Operations over HTTPS).

MOPS is the internal protocol that the HiOS web UI uses to read/write switch
configuration. It wraps SNMP MIB operations in XML over HTTPS, providing:
  - Atomic multi-table writes in one POST
  - HTTP Basic auth (same credentials as SSH/SNMP)
  - No net-snmp/pysnmp dependency — just requests + xml.etree

Adapted from Hirschy-MOPS/lib/mops.py for use as a napalm-hios transport.

Usage:
    from napalm_hios.mops_client import MOPSClient

    with MOPSClient("192.168.1.4", "admin", "private") as m:
        result = m.get("SNMPv2-MIB", "system", ["sysDescr", "sysName"])
        m.set("SNMPv2-MIB", "system", {"sysLocation": encode_string("Lab")})
"""

import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement
import logging

import requests
import urllib3

from napalm.base.exceptions import ConnectionException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Namespaces
NS_NETCONF = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
NS_MOPS = "urn:x-mops:1.0"

# For parsing responses
NSMAP = {
    "nc": NS_NETCONF,
    "mops": NS_MOPS,
}


def _decode_hex_string(value):
    """Decode MOPS hex-encoded string to text. Returns original if not hex."""
    if not value or not value.strip():
        return ""
    parts = value.strip().split()
    if all(len(p) == 2 for p in parts):
        try:
            raw = bytes.fromhex(value.replace(" ", ""))
            return raw.decode("utf-8", errors="replace")
        except ValueError:
            pass
    return value


def _decode_hex_mac(value):
    """Decode hex bytes to MAC address format.

    Handles two input forms:
    1. Raw hex string from MOPS: "64 60 38 3f 4a a6" (before _decode_hex_string)
    2. Already-decoded bytes: 6-char binary string (after _decode_hex_string mangled it)
    """
    if not value:
        return ""
    # Form 1: space-separated hex pairs (raw from MOPS, decode_strings=False)
    parts = value.strip().split()
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            # Validate they're actual hex
            bytes.fromhex("".join(parts))
            return ":".join(p.lower() for p in parts)
        except ValueError:
            pass
    # Form 2: already decoded by _decode_hex_string into a 6-byte raw string
    if len(value) == 6 and not value.isascii() or (len(value) == 6 and any(ord(c) > 127 or ord(c) < 32 for c in value)):
        return ":".join(f"{ord(c):02x}" for c in value)
    # Form 2b: 6-byte string that happens to be all printable (still binary MAC)
    # Detect by checking if it does NOT look like text (no spaces, length exactly 6)
    if len(value) == 6 and " " not in value and ":" not in value:
        return ":".join(f"{ord(c):02x}" for c in value)
    return value


def encode_string(text):
    """Encode a Python string to MOPS hex format (space-separated bytes)."""
    return " ".join(f"{b:02x}" for b in text.encode("utf-8"))


def encode_int(value):
    """Encode an integer for MOPS (plain string)."""
    return str(int(value))


class MOPSError(Exception):
    """MOPS protocol error."""
    pass


class MOPSClient:
    """Client for MOPS (MIB Operations over HTTPS) on HiOS switches."""

    def __init__(self, host, username="admin", password="private",
                 port=443, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.url = f"https://{host}:{port}/mops_data"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False
        self.session.headers.update({
            "Content-Type": "application/xml",
            "Accept-Encoding": "gzip",
        })
        self._message_id = 0
        self._session_key = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.session.close()

    def _get_session_key(self):
        """Get MOPS session key via /mops_login.

        Required for download/upload on HiOS 10.x (uses Authorization: Mops).
        Falls back silently if login endpoint is unavailable (HiOS 9.x uses Basic).

        Uses a separate session without HTTP Basic auth — the /mops_login
        endpoint rejects Basic and expects credentials in the XML body.
        """
        if self._session_key:
            return self._session_key
        user, pwd = self.session.auth
        payload = (
            "<mops-auth><login>"
            "<app-name>webif</app-name>"
            "<credentials>"
            f"<user>{user}</user>"
            f"<password>{pwd}</password>"
            "</credentials>"
            "</login></mops-auth>"
        )
        try:
            login_session = requests.Session()
            login_session.verify = False
            login_session.headers.update({"Content-Type": "application/xml"})
            r = login_session.post(
                f"https://{self.host}:{self.port}/mops_login",
                data=payload, timeout=self.timeout)
            login_session.close()
            if r.status_code == 200 and "<session-key>" in r.text:
                import re
                m = re.search(r'<session-key>([^<]+)</session-key>', r.text)
                if m:
                    self._session_key = m.group(1)
        except requests.exceptions.RequestException:
            pass
        return self._session_key

    def _next_id(self):
        self._message_id += 1
        return self._message_id

    def _rpc_envelope(self):
        """Create the common RPC envelope."""
        rpc = Element("rpc")
        rpc.set("xmlns", NS_NETCONF)
        rpc.set("xmlns:xsi", NS_XSI)
        rpc.set("xsi:schemaLocation", "urn:x-mops:1.0 ../mops.xsd")
        rpc.set("message-id", str(self._next_id()))
        mib_op = SubElement(rpc, "mibOperation")
        mib_op.set("xmlns", NS_MOPS)
        return rpc, mib_op

    def _build_get_request(self, queries, source="running-config"):
        """Build MOPS get-config XML request.

        queries: list of (mib_name, node_name, [attr_names])
        """
        rpc, mib_op = self._rpc_envelope()

        get_config = SubElement(mib_op, "get-config")
        src = SubElement(get_config, "source")
        SubElement(src, source)

        mib_data = SubElement(get_config, "MIBData")

        # Group queries by MIB name
        mib_nodes = {}
        for mib_name, node_name, attrs in queries:
            if mib_name not in mib_nodes:
                mib_nodes[mib_name] = []
            mib_nodes[mib_name].append((node_name, attrs))

        for mib_name, nodes in mib_nodes.items():
            mib_elem = SubElement(mib_data, "MIB")
            mib_elem.set("name", mib_name)
            for node_name, attrs in nodes:
                node_elem = SubElement(mib_elem, "Node")
                node_elem.set("name", node_name)
                for attr in attrs:
                    get_elem = SubElement(node_elem, "Get")
                    get_elem.set("name", attr)

        return ET.tostring(rpc, encoding="unicode", xml_declaration=True)

    def _build_set_request(self, mutations):
        """Build MOPS edit-config XML request.

        mutations: list of tuples, either:
          (mib_name, node_name, {attr: value})                    — scalar SET
          (mib_name, node_name, {attr: value}, {idx_col: idx_val}) — indexed SET

        Note: edit-config has NO <target> wrapper — goes straight to <MIBData>.
        Values must be pre-encoded (hex for strings, plain for integers).
        """
        rpc, mib_op = self._rpc_envelope()

        edit_config = SubElement(mib_op, "edit-config")
        mib_data = SubElement(edit_config, "MIBData")

        # Group by MIB name
        mib_nodes = {}
        for item in mutations:
            mib_name = item[0]
            node_name = item[1]
            attrs = item[2]
            index = item[3] if len(item) > 3 else None
            if mib_name not in mib_nodes:
                mib_nodes[mib_name] = []
            mib_nodes[mib_name].append((node_name, attrs, index))

        for mib_name, nodes in mib_nodes.items():
            mib_elem = SubElement(mib_data, "MIB")
            mib_elem.set("name", mib_name)
            for node_name, attrs, index in nodes:
                node_elem = SubElement(mib_elem, "Node")
                node_elem.set("name", node_name)

                # Add <Index> for table row addressing
                if index:
                    idx_elem = SubElement(node_elem, "Index")
                    for idx_name, idx_value in index.items():
                        attr_elem = SubElement(idx_elem, "Attribute")
                        attr_elem.set("name", idx_name)
                        attr_elem.text = str(idx_value)

                for attr_name, attr_value in attrs.items():
                    set_elem = SubElement(node_elem, "Set")
                    set_elem.set("name", attr_name)
                    set_elem.text = str(attr_value)

        return ET.tostring(rpc, encoding="unicode", xml_declaration=True)

    def _send(self, xml_body):
        """Send XML request and return parsed response."""
        try:
            r = self.session.post(self.url, data=xml_body, timeout=self.timeout)
        except requests.exceptions.ConnectionError as e:
            raise ConnectionException(f"MOPS connection failed to {self.host}: {e}")
        except requests.exceptions.Timeout as e:
            raise ConnectionException(f"MOPS timeout connecting to {self.host}: {e}")
        except requests.exceptions.RequestException as e:
            raise ConnectionException(f"MOPS request failed to {self.host}: {e}")
        if r.status_code == 401:
            raise ConnectionException(
                f"MOPS authentication failed on {self.host} (HTTP 401)")
        if r.status_code != 200:
            raise MOPSError(f"HTTP {r.status_code}: {r.text[:200]}")
        return r.text

    def _is_ok_response(self, xml_text):
        """Check if response indicates SET success.

        Returns True for <ok/> responses.
        For mibResponse, parses for errors at MIB, Node, and Attribute levels.
        Raises MOPSError with details if any errors are found.
        Returns True if mibResponse contains no errors (echo-back success).
        Returns False if response contains neither <ok/> nor mibResponse.
        """
        root = ET.fromstring(xml_text)
        for elem in root:
            tag = elem.tag.replace("{%s}" % NS_NETCONF, "")
            if tag == "ok":
                return True
            tag_mops = elem.tag.replace("{%s}" % NS_MOPS, "")
            if tag_mops == "mibResponse":
                # Parse mibResponse for errors at any level
                errors = []
                for mib_data in elem.iter("{%s}MIBData" % NS_MOPS):
                    for mib_elem in mib_data:
                        mib_tag = mib_elem.tag.replace("{%s}" % NS_MOPS, "")
                        if mib_tag != "MIB":
                            continue
                        mib_name = mib_elem.get("name", "?")
                        if mib_elem.get("error"):
                            errors.append(f"{mib_name}: {mib_elem.get('error')}")
                            continue
                        for node_elem in mib_elem:
                            node_tag = node_elem.tag.replace("{%s}" % NS_MOPS, "")
                            if node_tag != "Node":
                                continue
                            node_name = node_elem.get("name", "?")
                            if node_elem.get("error"):
                                errors.append(
                                    f"{mib_name}/{node_name}: "
                                    f"{node_elem.get('error')}")
                                continue
                            for entry_elem in node_elem:
                                for attr_elem in entry_elem:
                                    if attr_elem.get("error"):
                                        attr_name = attr_elem.get("name", "?")
                                        errors.append(
                                            f"{mib_name}/{node_name}/"
                                            f"{attr_name}: "
                                            f"{attr_elem.get('error')}")
                if errors:
                    raise MOPSError(
                        f"SET failed: {'; '.join(errors)}")
                return True
        return False

    def _parse_response(self, xml_text, decode_strings=True):
        """Parse MOPS response into structured dict.

        Returns: {
            "message_id": "1",
            "mibs": {
                "SNMPv2-MIB": {
                    "system": [
                        {"sysDescr": "Hirschmann BOBCAT", "sysName": "BRS50-Office", ...}
                    ]
                }
            },
            "errors": [{"mib": "...", "node": "...", "error": "noSuchName"}, ...]
        }
        """
        root = ET.fromstring(xml_text)

        result = {
            "message_id": root.get("message-id"),
            "mibs": {},
            "errors": [],
        }

        # Find MIBData in response
        for mib_data in root.iter("{%s}MIBData" % NS_MOPS):
            for mib_elem in mib_data:
                mib_name = mib_elem.get("name")
                tag = mib_elem.tag.replace("{%s}" % NS_MOPS, "")

                if tag != "MIB":
                    continue

                # Check for MIB-level error
                if mib_elem.get("error"):
                    result["errors"].append({
                        "mib": mib_name,
                        "node": None,
                        "error": mib_elem.get("error"),
                    })
                    continue

                if mib_name not in result["mibs"]:
                    result["mibs"][mib_name] = {}

                for node_elem in mib_elem:
                    node_tag = node_elem.tag.replace("{%s}" % NS_MOPS, "")
                    if node_tag != "Node":
                        continue

                    node_name = node_elem.get("name")

                    # Check for node-level error
                    if node_elem.get("error"):
                        result["errors"].append({
                            "mib": mib_name,
                            "node": node_name,
                            "error": node_elem.get("error"),
                        })
                        continue

                    entries = []
                    for entry_elem in node_elem:
                        entry_tag = entry_elem.tag.replace("{%s}" % NS_MOPS, "")
                        if entry_tag != "Entry":
                            continue

                        entry = {}
                        for child_elem in entry_elem:
                            child_tag = child_elem.tag.replace("{%s}" % NS_MOPS, "")

                            if child_tag == "Attribute":
                                name = child_elem.get("name")
                                if child_elem.get("error"):
                                    result["errors"].append({
                                        "mib": mib_name,
                                        "node": node_name,
                                        "attribute": name,
                                        "error": child_elem.get("error"),
                                    })
                                    continue
                                value = child_elem.text or ""
                                if decode_strings:
                                    value = _decode_hex_string(value)
                                entry[name] = value

                            elif child_tag == "Index":
                                # Table row index — contains Attribute children
                                # with index column values (e.g. VLAN ID, row key)
                                for idx_attr in child_elem:
                                    idx_tag = idx_attr.tag.replace("{%s}" % NS_MOPS, "")
                                    if idx_tag == "Attribute":
                                        name = idx_attr.get("name")
                                        value = idx_attr.text or ""
                                        # Index values are typically integers,
                                        # don't hex-decode them
                                        entry["_idx_" + name] = value

                        entries.append(entry)

                    result["mibs"][mib_name][node_name] = entries

        return result

    def get(self, mib_name, node_name, attributes, decode_strings=True):
        """Query a single MIB node.

        Returns: list of entry dicts

        Attribute-level errors (e.g. noSuchName on one column) are
        silently ignored — the attribute is simply absent from the
        returned dicts.  Callers already use .get() with defaults.
        MIB-level and node-level errors still raise MOPSError.
        """
        xml = self._build_get_request([(mib_name, node_name, attributes)])
        response = self._send(xml)
        parsed = self._parse_response(response, decode_strings=decode_strings)

        for err in parsed["errors"]:
            if "attribute" not in err:
                raise MOPSError(
                    f"{err['mib']}/{err.get('node', '?')}: {err['error']}")

        return parsed["mibs"].get(mib_name, {}).get(node_name, [])

    def get_multi(self, queries, decode_strings=True):
        """Query multiple MIB nodes in one request.

        queries: list of (mib_name, node_name, [attr_names])
        Returns: full parsed response dict
        """
        xml = self._build_get_request(queries)
        response = self._send(xml)
        return self._parse_response(response, decode_strings=decode_strings)

    def set(self, mib_name, node_name, values):
        """Set attributes on a single MIB node.

        values: dict of {attr_name: encoded_value}
                Use encode_string() for text, plain str for integers.
        Returns: True on success, raises MOPSError on failure.
        """
        xml = self._build_set_request([(mib_name, node_name, values)])
        response = self._send(xml)
        if self._is_ok_response(response):
            return True
        raise MOPSError(f"SET failed: {response[:300]}")

    def set_multi(self, mutations):
        """Set attributes on multiple MIB nodes in one request.

        mutations: list of (mib_name, node_name, {attr: encoded_value})
        Returns: True on success, raises MOPSError on failure.
        """
        xml = self._build_set_request(mutations)
        response = self._send(xml)
        if self._is_ok_response(response):
            return True
        raise MOPSError(f"SET failed: {response[:300]}")

    def set_indexed(self, mib_name, node_name, index, values):
        """Set attributes on a specific table row.

        index: dict of {index_col: index_value} identifying the row
        values: dict of {attr_name: encoded_value} to set
        """
        xml = self._build_set_request([(mib_name, node_name, values, index)])
        response = self._send(xml)
        if self._is_ok_response(response):
            return True
        raise MOPSError(f"SET failed: {response[:300]}")

    def save_config(self, dest="nvm"):
        """Save running config to NVM (or ENVM).

        Replicates the web UI save sequence:
        1. Read activate key (raw, no string decode)
        2. Clear source/dest data
        3. Trigger copy(2) config(10) running(10) → nvm(2)/envm(3)
        4. Poll for completion

        Returns: dict with action result fields
        """
        dst_code = "2" if dest == "nvm" else "3"

        # Step 1: Read the activation key (raw — it's an integer, not a string)
        xml = self._build_get_request([
            ("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
             ["hm2FMActionActivateKey", "hm2FMActionStatus"])
        ])
        response = self._send(xml)
        parsed = self._parse_response(response, decode_strings=False)
        entries = parsed["mibs"]["HM2-FILEMGMT-MIB"]["hm2FileMgmtActionGroup"]
        key = entries[0]["hm2FMActionActivateKey"]

        # Step 2: Clear source/dest data
        self.set("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup", {
            "hm2FMActionSourceData": "",
            "hm2FMActionDestinationData": "",
        })

        # Step 3: Trigger the save — SET on indexed table row
        self.set_indexed("HM2-FILEMGMT-MIB", "hm2FMActionEntry",
            index={
                "hm2FMActionType": "2",           # copy
                "hm2FMActionItemType": "10",       # config
                "hm2FMActionSourceType": "10",     # runningConfig
                "hm2FMActionDestinationType": dst_code,  # nvm(2) or envm(3)
            },
            values={"hm2FMActionActivate": key})

        # Step 4: Read result
        entries = self.get("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
                           ["hm2FMActionActivateResult", "hm2FMActionStatus",
                            "hm2FMActionResult", "hm2FMActionResultText"])
        return entries[0] if entries else {}

    def _wait_action_idle(self, timeout=120):
        """Wait for the action table to be idle. Returns status dict."""
        import time
        entries = None
        elapsed = 0
        interval = 10
        while elapsed < timeout:
            time.sleep(interval)
            elapsed += interval
            entries = self.get(
                "HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
                ["hm2FMActionStatus", "hm2FMActionResult",
                 "hm2FMActionResultText"],
                decode_strings=False)
            if not entries:
                return {}
            if entries[0].get("hm2FMActionStatus") != "2":  # not running
                return entries[0]
        return entries[0] if entries else {}

    def config_transfer(self, action, server_url, source_type, dest_type,
                        source_data='', dest_data=''):
        """Transfer config via TFTP using the action table copy engine.

        Args:
            action: 'pull' (server→device) or 'push' (device→server)
            server_url: TFTP URL (e.g. 'tftp://192.168.4.3/config.xml')
            source_type: '2'=nvm, '3'=envm, '20'=server
            dest_type: '2'=nvm, '3'=envm, '20'=server
            source_data: profile name or URL for source
            dest_data: profile name or URL for destination

        Returns: dict with action result fields
        """
        # Step 0: Wait for any previous action to finish
        self._wait_action_idle()

        # Step 1: Read the activation key
        xml = self._build_get_request([
            ("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
             ["hm2FMActionActivateKey"])
        ])
        response = self._send(xml)
        parsed = self._parse_response(response, decode_strings=False)
        entries = parsed["mibs"]["HM2-FILEMGMT-MIB"]["hm2FileMgmtActionGroup"]
        key = entries[0]["hm2FMActionActivateKey"]

        # Step 2: Set source/dest data (DisplayString — needs hex encoding)
        self.set("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup", {
            "hm2FMActionSourceData": encode_string(source_data),
            "hm2FMActionDestinationData": encode_string(dest_data),
        })

        # Step 3: Trigger the copy
        self.set_indexed("HM2-FILEMGMT-MIB", "hm2FMActionEntry",
            index={
                "hm2FMActionType": "2",            # copy
                "hm2FMActionItemType": "10",        # config
                "hm2FMActionSourceType": source_type,
                "hm2FMActionDestinationType": dest_type,
            },
            values={"hm2FMActionActivate": key})

        # Step 4: Poll until idle (up to 60s for TFTP over slow links)
        return self._wait_action_idle(timeout=60)

    def nvm_state(self):
        """Check if running config is saved.

        Returns: dict with nvm/envm/bootparam states.
        Values: 1=ok, 2=outOfSync (UNSAVED), 3=absent/busy
        """
        entries = self.get("HM2-FILEMGMT-MIB", "hm2FileMgmtStatusGroup",
                           ["hm2FMNvmState", "hm2FMEnvmState", "hm2FMBootParamState"])
        if entries:
            STATE_NAMES = {"1": "ok", "2": "out of sync", "3": "absent"}
            return {k: {"value": v, "label": STATE_NAMES.get(v, v)}
                    for k, v in entries[0].items()}
        return {}

    def clear_config(self, keep_ip=False):
        """Clear running config (back to default).

        Replicates the web UI "Back to Default" action:
        1. Read activate key
        2. SET hm2FMActionParameter = keep-ip(11) or none(1)
        3. Trigger clear(3) config(10) runningConfig(10) → runningConfig(10)

        WARNING: Device will warm-restart. The HTTP connection will drop.

        Args:
            keep_ip: If True, preserve management IP address.

        Returns: dict with 'restarting': True
        """
        param_value = "11" if keep_ip else "1"

        # Step 1: Read the activation key
        xml = self._build_get_request([
            ("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
             ["hm2FMActionActivateKey", "hm2FMActionStatus"])
        ])
        response = self._send(xml)
        parsed = self._parse_response(response, decode_strings=False)
        entries = parsed["mibs"]["HM2-FILEMGMT-MIB"]["hm2FileMgmtActionGroup"]
        key = entries[0]["hm2FMActionActivateKey"]

        # Step 2: SET the parameter (keep-ip or none)
        self.set("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup", {
            "hm2FMActionParameter": param_value,
        })

        # Step 3: Trigger the clear — device will warm-restart
        try:
            self.set_indexed("HM2-FILEMGMT-MIB", "hm2FMActionEntry",
                index={
                    "hm2FMActionType": "3",            # clear
                    "hm2FMActionItemType": "10",        # config
                    "hm2FMActionSourceType": "10",      # runningConfig
                    "hm2FMActionDestinationType": "10", # runningConfig
                },
                values={"hm2FMActionActivate": key})
        except Exception:
            # Device warm-restarts before sending HTTP response
            return {"restarting": True}

        return {"restarting": True}

    def clear_factory(self, erase_all=False):
        """Factory reset (back to factory defaults).

        Replicates the web UI "Back to Factory" action:
        1. Read activate key
        2. Clear source/destination data fields
        3. SET hm2FMActionParameter = all(2) if erase_all else none(1)
        4. Trigger clear(3) config(10) nvm(2) → nvm(2)

        WARNING: Device will reboot. The HTTP response may not arrive.

        Args:
            erase_all: If True, also regenerate factory.cfg from firmware.
                Use when factory defaults file may be corrupted.

        Returns: dict with 'rebooting': True (or action result if response arrives)
        """
        param_value = "2" if erase_all else "1"

        # Step 1: Read the activation key
        xml = self._build_get_request([
            ("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
             ["hm2FMActionActivateKey", "hm2FMActionStatus"])
        ])
        response = self._send(xml)
        parsed = self._parse_response(response, decode_strings=False)
        entries = parsed["mibs"]["HM2-FILEMGMT-MIB"]["hm2FileMgmtActionGroup"]
        key = entries[0]["hm2FMActionActivateKey"]

        # Step 2: Clear source/destination data (matches web UI sequence)
        self.set("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup", {
            "hm2FMActionSourceData": "",
            "hm2FMActionDestinationData": "",
        })

        # Step 3: SET the parameter
        self.set("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup", {
            "hm2FMActionParameter": param_value,
        })

        # Step 4: Trigger the factory reset — device will reboot
        try:
            self.set_indexed("HM2-FILEMGMT-MIB", "hm2FMActionEntry",
                index={
                    "hm2FMActionType": "3",            # clear
                    "hm2FMActionItemType": "10",        # config
                    "hm2FMActionSourceType": "2",       # nvm
                    "hm2FMActionDestinationType": "2",  # nvm
                },
                values={"hm2FMActionActivate": key})
        except Exception:
            # Device may reboot before sending HTTP response
            return {"rebooting": True}

        # If we get here, read result
        try:
            entries = self.get("HM2-FILEMGMT-MIB", "hm2FileMgmtActionGroup",
                               ["hm2FMActionActivateResult", "hm2FMActionStatus",
                                "hm2FMActionResult", "hm2FMActionResultText"])
            return entries[0] if entries else {"rebooting": True}
        except Exception:
            return {"rebooting": True}

    def change_password(self, new_password, username=None, current_password=None):
        """Change a user's password via the mops_changePassword endpoint.

        Follows the same two-step flow the web UI uses:
        1. POST /mops_login → gets 401 + <pwchange-request/> on gated devices
        2. POST /mops_changePassword → flips the factory gate, HTTP 200

        Both steps MUST use Content-Type: application/xml. Without it the
        device's web server cold-starts instead of handling the request
        gracefully.

        On factory-fresh HiOS 10.3+ devices, this flips
        hm2UserForcePasswordStatus from enable(1) to disable(2), which
        unlocks the SNMP agent. The password can be set to the same value
        as the current password (e.g. 'private' → 'private') — the act of
        calling this endpoint is what clears the factory gate.

        WARNING: Calling this on an already-onboarded device causes a cold
        reset (full firmware reload). Always check is_factory_default()
        first. This method enforces that check as a safety guard.

        Args:
            new_password: The new password to set.
            username: Username to change (default: session username).
            current_password: Current password (default: session password).

        Returns: True on success.
        Raises:
            ConnectionException: On auth failure or if device is already onboarded.
            MOPSError: On protocol error.
        """
        # Safety guard: calling change_password on an onboarded device causes
        # a cold reset (full firmware reload). Check the gate first.
        if not self.is_factory_default():
            raise ConnectionException(
                f"Device {self.host} is already onboarded — change_password "
                f"MUST NOT be called on onboarded devices (causes cold reset)")

        user = username or self.session.auth[0]
        pwd = current_password or self.session.auth[1]

        base_url = f"https://{self.host}:{self.port}"

        # Pre-auth session — no HTTP Basic auth, but MUST have
        # Content-Type: application/xml or the device cold-starts.
        no_auth_session = requests.Session()
        no_auth_session.verify = False
        no_auth_session.headers.update({
            "Content-Type": "application/xml",
        })

        # Step 1: POST /mops_login — primes the web server's auth state.
        # On gated devices this returns 401 + <pwchange-request/>.
        # On onboarded devices this returns 200 + <ok><session-key>...</ok>.
        login_payload = (
            "<mops-auth><login>"
            "<app-name>webif</app-name>"
            "<credentials>"
            f"<user>{user}</user>"
            f"<password>{pwd}</password>"
            "</credentials>"
            "</login></mops-auth>"
        )

        try:
            r = no_auth_session.post(
                f"{base_url}/mops_login", data=login_payload, timeout=10)
        except requests.exceptions.RequestException as e:
            raise ConnectionException(
                f"MOPS login failed on {self.host}: {e}")

        # If login succeeds (200), the device is already onboarded — bail out.
        if r.status_code == 200 and "<ok>" in r.text:
            raise ConnectionException(
                f"Device {self.host} is already onboarded (mops_login "
                f"returned session-key) — change_password refused")

        # Step 2: POST /mops_changePassword
        pw_payload = (
            "<mops-auth><pwchange>"
            "<credentials>"
            f"<user>{user}</user>"
            f"<password>{pwd}</password>"
            "</credentials>"
            f"<new-password>{new_password}</new-password>"
            "</pwchange></mops-auth>"
        )

        try:
            r = no_auth_session.post(
                f"{base_url}/mops_changePassword", data=pw_payload, timeout=10)
        except requests.exceptions.Timeout:
            # Some firmware versions may not respond — treat as success.
            if user == self.session.auth[0]:
                self.session.auth = (user, new_password)
            return True
        except requests.exceptions.RequestException as e:
            raise ConnectionException(
                f"MOPS change_password failed on {self.host}: {e}")

        if r.status_code == 200 and "<pwchange-ok/>" in r.text:
            if user == self.session.auth[0]:
                self.session.auth = (user, new_password)
            return True

        if r.status_code == 401:
            raise ConnectionException(
                f"MOPS change_password auth failed on {self.host} (HTTP 401)")

        raise MOPSError(
            f"MOPS change_password HTTP {r.status_code}: {r.text[:200]}")

    def is_factory_default(self):
        """Check if the device is in factory-default password state.

        Reads hm2UserForcePasswordStatus: 1=enable (factory gate active),
        2=disable (password has been changed, SNMP unlocked).

        Returns: True if factory gate is active, False if already onboarded.
        """
        entries = self.get("HM2-USERMGMT-MIB", "hm2UserStatusGroup",
                           ["hm2UserForcePasswordStatus"],
                           decode_strings=False)
        if entries and "hm2UserForcePasswordStatus" in entries[0]:
            return entries[0]["hm2UserForcePasswordStatus"] == "1"
        return False

    def get_raw(self, queries):
        """Query and return raw XML response text."""
        xml = self._build_get_request(queries)
        return self._send(xml)

    def raw_request(self, xml_body):
        """Send arbitrary XML and return raw response."""
        return self._send(xml_body)

    def device_info(self):
        """Get basic device info (no auth required)."""
        url = f"https://{self.host}:{self.port}/deviceInfo.xml"
        try:
            r = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise ConnectionException(
                f"MOPS device_info failed on {self.host}: {e}")
        if r.status_code != 200:
            raise ConnectionException(
                f"MOPS device_info HTTP {r.status_code} from {self.host}")

        root = ET.fromstring(r.text)
        info = {}

        product = root.find("product")
        if product is not None:
            info["company"] = product.findtext("company", "")
            family = product.find("family")
            if family is not None:
                info["family"] = family.text
                info["family_id"] = family.get("id")
            info["description"] = product.findtext("description", "")

        sw = root.find("software")
        if sw is not None:
            ver = sw.find("version")
            if ver is not None:
                info["software_version"] = ver.findtext("description", "")

        sys_elem = root.find("system")
        if sys_elem is not None:
            name_hex = sys_elem.findtext("name", "")
            info["name_raw"] = name_hex
            info["name"] = _decode_hex_string(name_hex)
            info["host"] = sys_elem.findtext("host", "")

        return info

    def probe(self):
        """Probe the device for MOPS availability.

        Checks both unauthenticated deviceInfo.xml and authenticated sysDescr GET.
        Returns the sysDescr string on success.
        Raises ConnectionException on failure.
        """
        # Step 1: Check device is reachable via deviceInfo.xml (no auth)
        self.device_info()

        # Step 2: Authenticated MOPS GET — verifies credentials
        entries = self.get("SNMPv2-MIB", "system", ["sysDescr"])
        if not entries or "sysDescr" not in entries[0]:
            raise ConnectionException(
                f"MOPS probe on {self.host}: sysDescr not returned")
        return entries[0]["sysDescr"]

    def _config_auth_headers(self):
        """Build auth headers for download/upload endpoints.

        HiOS 10.x requires Authorization: Mops <session-key>.
        HiOS 9.x accepts Basic auth (no extra headers needed).
        """
        key = self._get_session_key()
        if key:
            return {'Authorization': f'Mops {key}'}
        return {}

    def download_config(self, profile, source='nvm'):
        """Download config XML from the device.

        Args:
            profile: profile name (from get_profiles)
            source: 'nvm' or 'envm'

        Returns:
            Config XML as string.
        """
        url = (f"https://{self.host}:{self.port}/download.html"
               f"?filetype=config&source={source}&profile={profile}")
        headers = self._config_auth_headers()
        try:
            # Use auth=() to suppress session.auth (Basic) when using Mops key
            auth = () if 'Authorization' in headers else None
            r = self.session.get(url, timeout=self.timeout, headers=headers,
                                auth=auth)
        except requests.exceptions.RequestException as e:
            raise ConnectionException(
                f"Config download failed on {self.host}: {e}")
        if r.status_code != 200:
            raise ConnectionException(
                f"Config download HTTP {r.status_code} from {self.host}")
        return r.text

    def upload_config(self, xml_data, profile, destination='nvm'):
        """Upload config XML to the device.

        Args:
            xml_data: config XML string
            profile: target profile name
            destination: 'nvm' or 'envm'

        Returns:
            True on success.

        Raises:
            ConnectionException: on HTTP error or device-reported error.
        """
        url = (f"https://{self.host}:{self.port}/upload.html"
               f"?filetype=config&destination={destination}&profile={profile}")
        headers = self._config_auth_headers()
        # The session has Content-Type: application/xml for MOPS XML-RPC.
        # Multipart file uploads need requests to auto-generate the
        # multipart/form-data Content-Type with boundary.  Temporarily
        # remove the session default so it doesn't override.
        saved_ct = self.session.headers.pop('Content-Type', None)
        try:
            auth = () if 'Authorization' in headers else None
            r = self.session.post(
                url,
                files={'file': ('config.xml', xml_data, 'text/xml')},
                headers=headers,
                auth=auth,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            raise ConnectionException(
                f"Config upload failed on {self.host}: {e}")
        finally:
            if saved_ct is not None:
                self.session.headers['Content-Type'] = saved_ct
        if r.status_code != 200:
            raise ConnectionException(
                f"Config upload HTTP {r.status_code} from {self.host}")
        # The switch returns HTTP 200 for both success and application-level
        # errors.  Parse the response body to detect failures.
        if 'config.OK' not in r.text:
            import re
            m = re.search(r"<errortext value='([^']+)'", r.text)
            msg = m.group(1) if m else r.text.strip()
            raise ConnectionException(
                f"Config upload rejected on {self.host}: {msg}")
        return True
