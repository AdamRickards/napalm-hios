# NAPALM HiOS Driver

This is a NAPALM driver for HiOS network switches by Belden. It currently supports SSH protocol for interacting with HiOS devices.

## Features

- Supports SSH protocol
- Implements standard NAPALM methods
- Includes comprehensive unit and integration tests
- Offers a mock device for testing and development

## Installation

To install the NAPALM HiOS driver, run:

```
pip install napalm-hios
```

## Quick Start

Here's a basic example of how to use the NAPALM HiOS driver:

```python
from napalm import get_network_driver

# Initialize the driver
driver = get_network_driver('hios')
device = driver(
    hostname='your_device_ip',
    username='your_username',
    password='your_password',
    optional_args={'ssh_port': 22}  # Optional: specify SSH port if different from default
)

# Open the connection
device.open()

# Use NAPALM methods
facts = device.get_facts()
interfaces = device.get_interfaces()

# Close the connection
device.close()
```

## Documentation

For detailed information about the NAPALM HiOS driver, including supported methods, advanced usage, and error handling, please refer to the [comprehensive documentation](docs/napalm_hios_documentation.md).

## Supported Methods

The NAPALM HiOS driver supports the following standard NAPALM methods:

- `get_facts()`
- `get_interfaces()`
- `get_interfaces_ip()`
- `get_interfaces_counters()`
- `get_lldp_neighbors()`
- `get_lldp_neighbors_detail()`
- `get_mac_address_table()`
- `get_arp_table()`
- `get_ntp_servers()`
- `get_ntp_stats()`
- `get_users()`
- `get_optics()`
- `get_config()`
- `get_environment()`
- `get_snmp_information()`
- `ping()`
- `get_vlans()`

Note: Configuration-related methods like `load_merge_candidate()`, `load_replace_candidate()`, `compare_config()`, `commit_config()`, `discard_config()`, and `rollback()` are not currently implemented.

For a complete list and detailed explanations, see the [documentation](docs/napalm_hios_documentation.md).

## Example

```
python -m examples/ssh_examply.py

```
Note: the example runs with user permissions against an online application lab provided by Hirschmann in Germany, this limits which commands you can execute.

For more details about the application lab, see http://applicationlab.hirschmann.de/remoteaccess

## Testing

To run the unit tests:

```
python -m unittest discover tests/unit
```
Note: tests are still a work in progress...

To run the integration tests (requires a real HiOS device or a properly configured mock):

```
python -m unittest discover tests/integration
```

Note: I've been using tests/integration/test_hioy.py against real devices by calling it with <hostname> <user> <password> <ping ip> <count>, the ping ip and count are optional and will default to 8.8.8.8 if not specified. This writes results to test_live_device.md and i've included an example output from a live device

## Mock Device

The driver includes a mock HiOS device for testing and development purposes. To use the mock device, set the hostname to 'localhost' when initializing the driver.

## Contributing

Contributions to the NAPALM HiOS driver are welcome! Please refer to the CONTRIBUTING.md file for guidelines.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
