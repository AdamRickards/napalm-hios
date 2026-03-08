"""
Offline protocol handler for NAPALM HiOS driver.

Subclasses MOPSHIOS — all 86+ getters/setters work by inheriting from the
MOPS backend. The only difference is the client: OfflineClient reads/writes
config XML files instead of HTTP POSTing to a switch.

Online-only getters (LLDP, MAC table, ARP, optics, counters, NTP) return
empty results since config XML doesn't contain runtime state.
"""

import logging

from napalm_hios.offline_client import OfflineClient
from napalm_hios.mops_hios import MOPSHIOS

logger = logging.getLogger(__name__)


class OfflineHIOS(MOPSHIOS):
    """Offline protocol handler — config XML file as a device.

    Inherits all getters/setters from MOPSHIOS. Overrides connection
    lifecycle and online-only methods.
    """

    def __init__(self, hostname, username="", password="", timeout=10,
                 port=None):
        # hostname is a file path for offline mode
        super().__init__(hostname, username, password, timeout, port=443)
        self._filename = hostname

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def open(self):
        """Parse config XML into memory."""
        self.client = OfflineClient(self._filename)
        self.client.open()
        self._connected = True

    def close(self):
        """No-op — nothing to close for a file."""
        if self.client:
            self.client.close()
            self.client = None
        self._connected = False
        self._ifindex_map = None

    def is_alive(self):
        """File exists and was parsed."""
        return {"is_alive": self._connected}

    # ------------------------------------------------------------------
    # Online-only methods — return empty
    # ------------------------------------------------------------------

    def is_factory_default(self):
        """Offline configs are never factory-default."""
        return False

    def onboard(self, new_password):
        """Not available offline."""
        raise NotImplementedError("onboard not available offline")

    def get_lldp_neighbors(self):
        """LLDP is runtime state — not in config XML."""
        return {}

    def get_lldp_neighbors_detail(self, interface=""):
        """LLDP is runtime state — not in config XML."""
        return {}

    def get_lldp_neighbors_detail_extended(self, interface=""):
        """LLDP is runtime state — not in config XML."""
        return {}

    def get_mac_address_table(self):
        """MAC table is runtime state — not in config XML."""
        return []

    def get_arp_table(self, vrf=""):
        """ARP table is runtime state — not in config XML."""
        return []

    def get_optics(self):
        """Optics are runtime state — not in config XML."""
        return {}

    def get_interfaces_counters(self):
        """Counters are runtime state — not in config XML."""
        return {}

    def get_ntp_stats(self):
        """NTP stats are runtime state — not in config XML."""
        return []

    def clear_config(self, keep_ip=False):
        """Not available offline."""
        raise NotImplementedError("clear_config not available offline")

    def clear_factory(self, erase_all=False):
        """Not available offline."""
        raise NotImplementedError("clear_factory not available offline")

    # ------------------------------------------------------------------
    # save_config — write XML to disk
    # ------------------------------------------------------------------

    def save_config(self):
        """Write in-memory state to config XML file."""
        self.client.save_config()
        return {"status": "saved", "filename": self._filename}
