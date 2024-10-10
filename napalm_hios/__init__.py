from napalm.base.base import NetworkDriver
from napalm_hios.hios import HIOSDriver

__all__ = ['HIOSDriver']

def get_network_driver(name):
    if name == "hios":
        return HIOSDriver
    raise NotImplementedError(f'Driver not found: {name}')
