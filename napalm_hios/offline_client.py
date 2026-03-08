"""
Offline Client — parse HiOS config export XML into MOPS-format data.

Same interface as MOPSClient: get(), get_multi(), set(), set_multi(),
set_indexed(), save_config(). Instead of HTTP POSTs, reads/writes XML files.

Config XML uses human-readable encoding (plaintext strings, comma port lists,
port names). MOPS uses SNMP-native encoding (hex strings, hex bitmaps,
integer ifIndex). This client translates at the boundary so all MOPSHIOS
getters/setters work unchanged.

Translation rules (config XML → MOPS format):
  convert="ascii"    → encode_string() (plaintext → hex bytes)
  convert="portlist" → _encode_portlist_hex() (port names → hex bitmap)
  convert="ifname"   → name_to_idx map (port name → integer string)
  convert="scrambled" → pass through (base64 passwords)
  (no convert)       → pass through (already in SNMP-native format)
"""

import copy
import hashlib
import logging
import os
import xml.etree.ElementTree as ET

from napalm_hios.mops_client import encode_string, _decode_hex_string, MOPSError

logger = logging.getLogger(__name__)

# Config XML namespace
_CFG_NS = "urn:xml:ns:mibconf:base:1.0"
_CFG_NS_PREFIX = "{%s}" % _CFG_NS


def _strip_ns(tag):
    """Remove namespace prefix from XML tag."""
    if tag.startswith(_CFG_NS_PREFIX):
        return tag[len(_CFG_NS_PREFIX):]
    return tag


def _encode_portlist_hex(port_names, name_to_idx):
    """Encode comma-separated port names to MOPS hex bitmap.

    Each bit = a bridge port number (1-based, MSB first).
    Bridge port number = ifIndex on HiOS.
    """
    if not port_names or not port_names.strip():
        return ""
    names = [n.strip() for n in port_names.split(",") if n.strip()]
    bp_nums = []
    for name in names:
        bp = name_to_idx.get(name)
        if bp is not None:
            bp_nums.append(int(bp))
    if not bp_nums:
        return ""
    max_port = max(bp_nums)
    num_bytes = (max_port + 7) // 8
    bitmap = bytearray(num_bytes)
    for bp in bp_nums:
        byte_idx = (bp - 1) // 8
        bit_idx = (bp - 1) % 8
        bitmap[byte_idx] |= (0x80 >> bit_idx)
    return " ".join(f"{b:02x}" for b in bitmap)


def _decode_portlist_to_names(hex_str, ifindex_map):
    """Decode MOPS hex bitmap back to comma-separated port names."""
    if not hex_str or not hex_str.strip():
        return ""
    try:
        octets = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        return ""
    names = []
    for byte_idx, byte_val in enumerate(octets):
        for bit_idx in range(8):
            if byte_val & (0x80 >> bit_idx):
                port_num = byte_idx * 8 + bit_idx + 1
                name = ifindex_map.get(str(port_num), f'port{port_num}')
                names.append(name)
    return ",".join(names)


class OfflineClient:
    """Config XML file client — same interface as MOPSClient.

    Parses HiOS config export XML into the same dict structure that
    MOPSClient._parse_response() returns. Getters work identically.
    Setters modify in-memory state. save_config() writes back to disk.
    """

    def __init__(self, filename):
        self.filename = filename
        self.host = filename  # for error messages (matches MOPSClient.host)
        self._data = {}       # {mib_name: {node_name: [entry_dicts]}}
        self._header = {}     # productId, sw versions
        self._ifindex_map = {}   # {"1": "1/1", "2": "1/2", ...}
        self._name_to_idx = {}   # {"1/1": "1", "1/2": "2", ...}
        self._convert_info = {}  # {(mib, node, attr): convert_type}
        self._node_types = {}    # {(mib, node): "Scalar"|"Table"}
        self._loaded = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        """No-op — nothing to close for a file."""
        pass

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def open(self):
        """Parse config XML into MOPS-format in-memory data."""
        if not os.path.exists(self.filename):
            # Build mode: start with empty data
            self._data = {}
            self._header = {
                "productId": "unknown",
                "swMajorRelNum": "10",
                "swMinorRelNum": "3",
                "swBugfixRelNum": "0",
            }
            self._loaded = True
            return

        tree = ET.parse(self.filename)
        root = tree.getroot()

        # Extract header
        header_elem = root.find(f"{_CFG_NS_PREFIX}Header")
        if header_elem is not None:
            for var in header_elem.findall(f"{_CFG_NS_PREFIX}Variable"):
                name = var.get("name", "")
                self._header[name] = var.text or ""

        # Find MibData
        mib_data = root.find(f"{_CFG_NS_PREFIX}MibData")
        if mib_data is None:
            self._loaded = True
            return

        # First pass: build ifIndex map from IF-MIB ifEntry ordering
        self._build_ifindex_map_from_xml(mib_data)

        # Second pass: parse all MIBs with convert translations
        self._parse_all_mibs(mib_data)

        self._loaded = True

    def _build_ifindex_map_from_xml(self, mib_data):
        """Build ifIndex ↔ port name mapping from IF-MIB ifEntry order.

        Config XML stores ifEntry entries in ascending ifIndex order.
        Entry 1 = ifIndex 1, entry 2 = ifIndex 2, etc.
        The ifIndex attribute value is the port name (convert="ifname").
        """
        for mib_elem in mib_data:
            tag = _strip_ns(mib_elem.tag)
            if tag != "MIB":
                continue
            if mib_elem.get("name") != "IF-MIB":
                continue

            for node_elem in mib_elem:
                node_tag = _strip_ns(node_elem.tag)
                node_name = node_elem.get("name", "")
                if node_tag != "Table" or node_name != "ifEntry":
                    continue

                idx = 0
                for entry_elem in node_elem:
                    if _strip_ns(entry_elem.tag) != "Entry":
                        continue
                    idx += 1
                    # ifIndex attr has convert="ifname", value is port name
                    for attr_elem in entry_elem:
                        if (_strip_ns(attr_elem.tag) == "Attribute"
                                and attr_elem.get("name") == "ifIndex"):
                            port_name = (attr_elem.text or "").strip()
                            if port_name:
                                self._ifindex_map[str(idx)] = port_name
                                self._name_to_idx[port_name] = str(idx)
                            break
                return  # found IF-MIB ifEntry, done

    def _parse_all_mibs(self, mib_data):
        """Parse all MIB elements, applying convert translations."""
        for mib_elem in mib_data:
            if _strip_ns(mib_elem.tag) != "MIB":
                continue
            mib_name = mib_elem.get("name", "")

            for node_elem in mib_elem:
                node_tag = _strip_ns(node_elem.tag)
                if node_tag not in ("Table", "Scalar"):
                    continue
                node_name = node_elem.get("name", "")
                self._node_types[(mib_name, node_name)] = node_tag

                entries = []
                if node_tag == "Scalar":
                    # Scalar: single implicit entry with all attributes
                    entry = {}
                    for attr_elem in node_elem:
                        if _strip_ns(attr_elem.tag) != "Attribute":
                            continue
                        attr_name = attr_elem.get("name", "")
                        convert = attr_elem.get("convert", "")
                        raw_value = (attr_elem.text or "").strip()

                        if convert:
                            self._convert_info[(mib_name, node_name, attr_name)] = convert

                        entry[attr_name] = self._translate_value(
                            raw_value, convert)
                    entries.append(entry)

                else:  # Table
                    for entry_elem in node_elem:
                        if _strip_ns(entry_elem.tag) != "Entry":
                            continue
                        entry = {}
                        for attr_elem in entry_elem:
                            if _strip_ns(attr_elem.tag) != "Attribute":
                                continue
                            attr_name = attr_elem.get("name", "")
                            convert = attr_elem.get("convert", "")
                            raw_value = (attr_elem.text or "").strip()

                            if convert:
                                self._convert_info[(mib_name, node_name, attr_name)] = convert

                            entry[attr_name] = self._translate_value(
                                raw_value, convert)
                        entries.append(entry)

                # Skip empty table nodes — config XML declares MIBs
                # with empty tables as placeholders. Treat as "not present"
                # so getters with try/except MOPSError can fall through.
                if not entries:
                    continue

                # Merge with existing data (handles duplicate MIB names)
                if mib_name not in self._data:
                    self._data[mib_name] = {}
                if node_name in self._data[mib_name]:
                    # Duplicate node: extend entries
                    self._data[mib_name][node_name].extend(entries)
                else:
                    self._data[mib_name][node_name] = entries

    def _translate_value(self, raw_value, convert):
        """Translate config XML value to MOPS format.

        convert="ascii"    → hex-encode plaintext
        convert="portlist" → comma port names → hex bitmap
        convert="ifname"   → port name → integer ifIndex string
        convert="scrambled" → pass through
        (none)             → pass through
        """
        if not convert:
            return raw_value

        if convert == "ascii":
            if not raw_value:
                return ""
            return encode_string(raw_value)

        if convert == "portlist":
            if not raw_value:
                return ""
            return _encode_portlist_hex(raw_value, self._name_to_idx)

        if convert == "ifname":
            if not raw_value:
                return ""
            idx = self._name_to_idx.get(raw_value)
            if idx is not None:
                return idx
            # Unknown interface name — return as-is
            return raw_value

        # scrambled, ipv6, or unknown — pass through
        return raw_value

    # ------------------------------------------------------------------
    # MOPSClient interface — read
    # ------------------------------------------------------------------

    def get(self, mib_name, node_name, attributes, decode_strings=True):
        """Look up a single MIB node from in-memory data.

        Returns: list of entry dicts (same as MOPSClient.get)
        Raises MOPSError if MIB or node doesn't exist (matches MOPSClient).
        """
        mib_data = self._data.get(mib_name)
        if mib_data is None:
            raise MOPSError(f"{mib_name}: noSuchName")
        entries = mib_data.get(node_name)
        if entries is None:
            raise MOPSError(f"{mib_name}/{node_name}: noSuchName")
        if not entries:
            return []

        # Filter to requested attributes
        result = []
        attr_set = set(attributes)
        for entry in entries:
            filtered = {}
            for attr in attr_set:
                if attr in entry:
                    value = entry[attr]
                    if decode_strings:
                        value = _decode_hex_string(value)
                    filtered[attr] = value
            result.append(filtered)
        return result

    def get_multi(self, queries, decode_strings=True):
        """Multi-node lookup from in-memory data.

        Returns: full parsed response dict (same as MOPSClient.get_multi)
        """
        result = {
            "message_id": "0",
            "mibs": {},
            "errors": [],
        }

        for mib_name, node_name, attrs in queries:
            mib_data = self._data.get(mib_name)
            if mib_data is None:
                continue
            entries = mib_data.get(node_name)
            if entries is None:
                continue

            attr_set = set(attrs)
            filtered_entries = []
            for entry in entries:
                filtered = {}
                for attr in attr_set:
                    if attr in entry:
                        value = entry[attr]
                        if decode_strings:
                            value = _decode_hex_string(value)
                        filtered[attr] = value
                filtered_entries.append(filtered)

            if mib_name not in result["mibs"]:
                result["mibs"][mib_name] = {}
            result["mibs"][mib_name][node_name] = filtered_entries

        return result

    # ------------------------------------------------------------------
    # MOPSClient interface — write
    # ------------------------------------------------------------------

    def set(self, mib_name, node_name, values):
        """Set attributes on a scalar node (or first entry of a table)."""
        entries = self._data.get(mib_name, {}).get(node_name, [])
        if entries:
            entries[0].update(values)
        else:
            # Create node if it doesn't exist
            if mib_name not in self._data:
                self._data[mib_name] = {}
            self._data[mib_name][node_name] = [dict(values)]
        return True

    def set_multi(self, mutations):
        """Set attributes on multiple nodes."""
        for item in mutations:
            mib_name = item[0]
            node_name = item[1]
            attrs = item[2]
            index = item[3] if len(item) > 3 else None

            if index:
                self.set_indexed(mib_name, node_name, index, attrs)
            else:
                self.set(mib_name, node_name, attrs)
        return True

    def set_indexed(self, mib_name, node_name, index, values):
        """Set attributes on a specific table row identified by index.

        index: dict of {col_name: col_value} identifying the row
        """
        entries = self._data.get(mib_name, {}).get(node_name, [])

        # Find matching entry
        for entry in entries:
            match = all(
                str(entry.get(k, "")) == str(v)
                for k, v in index.items()
            )
            if match:
                entry.update(values)
                return True

        # No match found — create new entry with index + values
        new_entry = {}
        new_entry.update({k: str(v) for k, v in index.items()})
        new_entry.update(values)
        if mib_name not in self._data:
            self._data[mib_name] = {}
        if node_name not in self._data[mib_name]:
            self._data[mib_name][node_name] = []
        self._data[mib_name][node_name].append(new_entry)
        return True

    # ------------------------------------------------------------------
    # MOPSClient interface — lifecycle / management
    # ------------------------------------------------------------------

    def save_config(self, dest="nvm"):
        """Write in-memory state back to config XML file.

        Reverse-translates MOPS format → config XML encoding:
          hex strings → plaintext + convert="ascii"
          hex bitmaps → comma port names + convert="portlist"
          integer ifIndex → port name + convert="ifname"
          scrambled → pass through + convert="scrambled"
        """
        root = ET.Element("Config")
        root.set("version", "1.0")
        root.set("xmlns", _CFG_NS)

        # Header
        header = ET.SubElement(root, "Header")
        for name in ("productId", "swMajorRelNum", "swMinorRelNum",
                      "swBugfixRelNum"):
            var = ET.SubElement(header, "Variable")
            var.set("name", name)
            var.text = self._header.get(name, "")

        # MibData
        mib_data = ET.SubElement(root, "MibData")

        # Track which MIB names we've written (for ordering)
        for mib_name, nodes in self._data.items():
            mib_elem = ET.SubElement(mib_data, "MIB")
            mib_elem.set("name", mib_name)

            for node_name, entries in nodes.items():
                node_type = self._node_types.get(
                    (mib_name, node_name), "Table")

                if node_type == "Scalar":
                    node_elem = ET.SubElement(mib_elem, "Scalar")
                    node_elem.set("name", node_name)
                    if entries:
                        for attr_name, value in entries[0].items():
                            attr_elem = ET.SubElement(node_elem, "Attribute")
                            attr_elem.set("name", attr_name)
                            convert = self._convert_info.get(
                                (mib_name, node_name, attr_name), "")
                            attr_elem.text = self._reverse_translate(
                                value, convert)
                            if convert:
                                attr_elem.set("convert", convert)
                else:  # Table
                    node_elem = ET.SubElement(mib_elem, "Table")
                    node_elem.set("name", node_name)
                    for entry_data in entries:
                        entry_elem = ET.SubElement(node_elem, "Entry")
                        for attr_name, value in entry_data.items():
                            attr_elem = ET.SubElement(
                                entry_elem, "Attribute")
                            attr_elem.set("name", attr_name)
                            convert = self._convert_info.get(
                                (mib_name, node_name, attr_name), "")
                            attr_elem.text = self._reverse_translate(
                                value, convert)
                            if convert:
                                attr_elem.set("convert", convert)

        # Footer with checksum
        footer = ET.SubElement(root, "Footer")
        checksum = ET.SubElement(footer, "Checksum")
        checksum.set("type", "SHA1")
        # Generate a valid-looking SHA1 hash from the data
        mib_xml = ET.tostring(mib_data, encoding="unicode")
        sha1 = hashlib.sha1(mib_xml.encode("utf-8")).hexdigest().upper()
        checksum.set("value", sha1)

        # Write
        tree = ET.ElementTree(root)
        ET.indent(tree, space=" ")
        tree.write(self.filename, encoding="utf-8", xml_declaration=True)

        return {"hm2FMActionResult": "1", "hm2FMActionStatus": "1"}

    def _reverse_translate(self, value, convert):
        """Reverse-translate MOPS format → config XML encoding."""
        if not convert:
            return value

        if convert == "ascii":
            if not value or not value.strip():
                return ""
            return _decode_hex_string(value)

        if convert == "portlist":
            if not value or not value.strip():
                return ""
            return _decode_portlist_to_names(value, self._ifindex_map)

        if convert == "ifname":
            if not value:
                return ""
            return self._ifindex_map.get(str(value), value)

        # scrambled, ipv6, or unknown — pass through
        return value

    # ------------------------------------------------------------------
    # MOPSClient interface — stubs for online-only operations
    # ------------------------------------------------------------------

    def probe(self):
        """Return sysDescr from parsed data (or a placeholder)."""
        entries = self._data.get("SNMPv2-MIB", {}).get("system", [])
        if entries and "sysDescr" in entries[0]:
            return _decode_hex_string(entries[0]["sysDescr"])
        product = self._header.get("productId", "offline")
        return f"Hirschmann {product} (offline)"

    def nvm_state(self):
        """Offline configs are always 'saved' (file on disk)."""
        return {
            "hm2FMNvmState": {"value": "1", "label": "ok"},
            "hm2FMEnvmState": {"value": "1", "label": "ok"},
            "hm2FMBootParamState": {"value": "1", "label": "ok"},
        }

    def is_factory_default(self):
        """Offline configs are never factory-default."""
        return False

    def change_password(self, new_password, username=None,
                        current_password=None):
        """Not supported offline."""
        raise NotImplementedError("change_password not available offline")

    def clear_config(self, keep_ip=False):
        """Not supported offline."""
        raise NotImplementedError("clear_config not available offline")

    def clear_factory(self, erase_all=False):
        """Not supported offline."""
        raise NotImplementedError("clear_factory not available offline")

    def device_info(self):
        """Return device info from header."""
        return {
            "company": "Hirschmann",
            "family": self._header.get("productId", "").split("_")[0],
            "description": self._header.get("productId", ""),
            "software_version": (
                f"{self._header.get('swMajorRelNum', '?')}."
                f"{self._header.get('swMinorRelNum', '?')}."
                f"{self._header.get('swBugfixRelNum', '?')}"
            ),
        }

    def get_raw(self, queries):
        """Not meaningful offline — return empty."""
        return ""

    def raw_request(self, xml_body):
        """Not meaningful offline."""
        return ""
