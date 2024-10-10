from napalm.base.base import NetworkDriver
from napalm_hios.hios import HIOSDriver
from napalm_hios.version import __version__

__all__ = ['HIOSDriver', '__version__']

def get_network_driver(name):
    if name == "hios":
        return HIOSDriver
    raise NotImplementedError(f'Driver not found: {name}')
