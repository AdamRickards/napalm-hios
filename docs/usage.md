# NAPALM HiOS Driver Usage Guide

## Introduction

NAPALM (Network Automation and Programmability Abstraction Layer with Multivendor support) is a Python library that implements a set of functions to interact with different network device Operating Systems using a unified API. This document provides detailed information on how to use the NAPALM HiOS driver, which is specifically designed for HiOS network switches by Belden.

The NAPALM HiOS driver allows network engineers and administrators to manage and automate HiOS devices using a standardized interface, making it easier to integrate these devices into larger network automation frameworks and scripts.

## Table of Contents

1. [Installation](#installation)
2. [Initializing the Driver](#initializing-the-driver)
3. [Available Methods](#available-methods)
4. [Method Details](#method-details)
5. [Protocol Information](#protocol-information)
6. [Error Handling](#error-handling)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)

## Installation

To install the NAPALM HiOS driver, run:

```bash
pip install napalm-hios
```

## Initializing the Driver

To use the NAPALM HiOS driver, you first need to initialize it. Here's how:

```python
from napalm import get_network_driver

driver = get_network_driver('hios')
device = driver(
    hostname='your_device_ip',
    username='your_username',
    password='your_password',
    timeout=60,
    optional_args={'protocol_preference': ['mops', 'snmp', 'ssh']}
)

# Open the connection
device.open()

# Use methods...

# Close the connection
device.close()
```

### Arguments

- `hostname` (str): The IP address or hostname of the HiOS device.
- `username` (str): The username for authentication.
- `password` (str): The password for authentication.
- `timeout` (int, optional): Connection timeout in seconds. Default is 60.
- `optional_args` (dict, optional): A dictionary of optional arguments. Supported keys:
  - `protocol_preference` (list): Order of protocols to try. Default: `['mops', 'snmp', 'ssh', 'netconf']`.
  - `mops_port` (int): The MOPS (HTTPS) port. Default is 443.
  - `ssh_port` (int): The SSH port. Default is 22.
  - `snmp_port` (int): The SNMP port. Default is 161.
  - `netconf_port` (int): The NETCONF port. Default is 830.

## Available Methods

### Standard NAPALM getters (MOPS + SNMP + SSH)

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
- `get_environment()`
- `get_snmp_information()`
- `get_vlans()`

### SSH-only standard methods

- `get_config()` — CLI scraping
- `ping()` — device-originated ping
- `cli()` — raw command execution

### Configuration workflow

- `load_merge_candidate()` — stage CLI commands (MOPS: atomic staging; SSH: in-memory)
- `compare_config()` — return staged commands
- `commit_config()` — execute staged commands, save to NVM
- `discard_config()` — clear staged commands

### Vendor-specific read methods (MOPS + SNMP + SSH)

- `get_mrp()` — MRP ring redundancy status
- `get_mrp_sub_ring()` — MRP sub-ring (SRM) configuration and state
- `get_hidiscovery()` — HiDiscovery protocol status
- `get_rstp()` — global STP/RSTP configuration and state
- `get_rstp_port()` — per-port STP/RSTP state
- `get_auto_disable()` — per-port auto-disable status and reason configuration
- `get_loop_protection()` — global and per-port loop detection state
- `get_vlan_ingress()` — per-port VLAN ingress settings (PVID, frame types, filtering)
- `get_vlan_egress()` — per-VLAN-per-port membership (Tagged/Untagged/Forbidden)
- `get_lldp_neighbors_detail_extended()` — LLDP with 802.1/802.3 extensions
- `get_config_status()` — check if running config is saved to NVM
- `get_profiles()` — list NVM/ENVM config profiles
- `get_config_fingerprint()` — SHA1 fingerprint of active config
- `is_factory_default()` — detect factory-fresh HiOS 10.3+ devices

### Vendor-specific write methods

- `set_mrp()` — configure MRP ring on default domain
- `delete_mrp()` — disable and delete MRP domain
- `set_mrp_sub_ring()` — configure MRP sub-ring (SRM) instance
- `delete_mrp_sub_ring()` — delete sub-ring instance or disable SRM globally
- `set_hidiscovery()` — set HiDiscovery mode (on/off/read-only)
- `set_rstp()` — set global STP/RSTP configuration
- `set_rstp_port()` — set per-port STP/RSTP configuration
- `set_auto_disable()` — set auto-disable recovery timer per port
- `reset_auto_disable()` — re-enable an auto-disabled port
- `set_auto_disable_reason()` — enable/disable auto-disable per reason
- `set_loop_protection()` — configure loop protection (global or per-port)
- `set_vlan_ingress()` — set per-port VLAN ingress parameters
- `set_vlan_egress()` — set per-port VLAN egress membership
- `create_vlan()` — create VLAN in database
- `update_vlan()` — rename a VLAN
- `delete_vlan()` — delete VLAN from database
- `save_config()` — save running config to NVM
- `clear_config()` — clear running config (warm restart)
- `clear_factory()` — full factory reset (reboot)
- `activate_profile()` — activate a config profile (warm restart)
- `delete_profile()` — delete a config profile
- `onboard()` — change default password on factory-fresh device

For vendor-specific method details, see [vendor_specific.md](vendor_specific.md).

## Method Details

### get_facts()

Retrieves general facts about the device.

**Arguments:** None

**Returns:** A dictionary with the following keys:
- `uptime` (int): The uptime of the device in seconds.
- `vendor` (str): The vendor of the device (e.g., "Hirschmann").
- `model` (str): The device model.
- `hostname` (str): The hostname of the device.
- `fqdn` (str): The fully qualified domain name of the device.
- `os_version` (str): The operating system version.
- `serial_number` (str): The serial number of the device.
- `interface_list` (list): A list of all interfaces on the device.

**Example:**
```python
facts = device.get_facts()
print(f"Hostname: {facts['hostname']}")
print(f"OS Version: {facts['os_version']}")
print(f"Interfaces: {', '.join(facts['interface_list'])}")
```

### get_interfaces()

Retrieves information about all interfaces on the device.

**Arguments:** None

**Returns:** A dictionary where the keys are interface names and the values are dictionaries with the following keys:
- `is_up` (bool): Whether the interface is up.
- `is_enabled` (bool): Whether the interface is enabled.
- `description` (str): The description of the interface.
- `last_flapped` (float): The number of seconds since the interface last changed status.
- `speed` (int): The speed of the interface in Mbps.
- `mtu` (int): The MTU of the interface.
- `mac_address` (str): The MAC address of the interface.

**Example:**
```python
interfaces = device.get_interfaces()
for interface, details in interfaces.items():
    print(f"Interface: {interface}")
    print(f"  Status: {'Up' if details['is_up'] else 'Down'}")
    print(f"  Speed: {details['speed']} Mbps")
    print(f"  MAC Address: {details['mac_address']}")
```

### ping(destination, source='', ttl=255, timeout=2, size=100, count=5, vrf='', source_interface='')

Executes a ping from the device to a given destination.

**Arguments:**
- `destination` (str): The IP address or hostname to ping.
- `source` (str, optional): The source IP address to use for the ping.
- `ttl` (int, optional): The Time To Live for the ping packets. Default is 255.
- `timeout` (int, optional): The timeout for the ping in seconds. Default is 2.
- `size` (int, optional): The size of the ping packets in bytes. Default is 100.
- `count` (int, optional): The number of ping packets to send. Default is 5.
- `vrf` (str, optional): The VRF to use for the ping.
- `source_interface` (str, optional): The source interface to use for the ping.

**Returns:** A dictionary with the ping results.

**Example:**
```python
result = device.ping('8.8.8.8', count=3)
if 'success' in result:
    print(f"Ping successful. Packet loss: {result['success']['packet_loss']}%")
    print(f"Round trip times - Min: {result['success']['rtt_min']}ms, Avg: {result['success']['rtt_avg']}ms, Max: {result['success']['rtt_max']}ms")
else:
    print(f"Ping failed: {result.get('error', 'Unknown error')}")
```

### cli(commands, encoding='text')

Executes a list of commands and returns the output.

**Arguments:**
- `commands` (list): A list of commands to execute.
- `encoding` (str, optional): The encoding of the output. Default is 'text'.

**Returns:** A dictionary where the keys are the commands and the values are the command outputs.

**Example:**
```python
commands = ['show version', 'show interfaces status']
outputs = device.cli(commands)
for command, output in outputs.items():
    print(f"Command: {command}")
    print(output)
    print("-" * 40)
```

Note: This method is only available when using the SSH protocol. When the primary protocol is MOPS or SNMP, SSH is lazy-connected on demand.

## Protocol Information

The NAPALM HiOS driver supports three protocols for device communication:

1. **MOPS (MIB Operations over HTTPS)**: Default and preferred protocol. Uses the same internal mechanism as the HiOS web UI. Supports atomic multi-table writes in a single POST, HTTP Basic auth, and returns entire tables in one request. Port 443.

2. **SNMPv3**: authPriv (MD5/DES) matching HiOS factory defaults. Lower overhead than SSH, no session state, doesn't consume SSH session slots. Short passwords (< 8 chars, including the default `private`) are supported via pre-computed master keys. Port 161.

3. **SSH**: CLI parsing via Netmiko. Required for `get_config`, `ping`, and `cli` methods. Lazy-connects on demand when the primary protocol is MOPS or SNMP. Port 22.

You can specify the protocol preference in the `optional_args` when initializing the driver. The driver tries each protocol in order and uses the first one that connects successfully.

```python
# Default: MOPS first (recommended)
device = driver(hostname, user, pw)

# SNMP-only (good for monitoring)
device = driver(hostname, user, pw, optional_args={'protocol_preference': ['snmp']})

# SSH-only (needed for get_config, ping, cli)
device = driver(hostname, user, pw, optional_args={'protocol_preference': ['ssh']})
```

For detailed protocol configuration, known cross-protocol differences, and the full method availability matrix, see [protocols.md](protocols.md).

## Error Handling

When using the NAPALM HiOS driver, you may encounter various exceptions. Here are some common ones and how to handle them:

1. **ConnectionException**: Raised when the driver fails to connect to the device.
   ```python
   from napalm.base.exceptions import ConnectionException

   try:
       device.open()
   except ConnectionException as e:
       print(f"Failed to connect to the device: {e}")
   ```

2. **CommandErrorException**: Raised when a command execution fails.
   ```python
   from napalm.base.exceptions import CommandErrorException

   try:
       device.cli(['invalid command'])
   except CommandErrorException as e:
       print(f"Command execution failed: {e}")
   ```

3. **NotImplementedError**: Raised when trying to use a method that is not implemented for the HiOS driver.
   ```python
   try:
       device.load_replace_candidate(config='some config')
   except NotImplementedError:
       print("Replace candidate is not supported — use load_merge_candidate instead")
   ```

Always ensure to properly close the connection after use, preferably using a context manager:

```python
with driver(hostname, username, password) as device:
    # Perform operations
    pass  # The connection will be automatically closed after this block
```

## Best Practices

1. **Use MOPS for most operations**: MOPS is the default and supports all getters plus atomic writes. Use SSH only when you need `get_config`, `ping`, or `cli`.

2. **Handle exceptions**: Always wrap your code in try-except blocks to handle potential exceptions gracefully.

3. **Use context managers**: Utilize Python's context manager (`with` statement) to ensure connections are properly closed, even if an exception occurs.

4. **Limit concurrent connections**: Avoid opening multiple concurrent connections to the same device, as this may lead to performance issues or connection failures.

5. **Verify protocol support**: Before using a method, check if it's supported by the current protocol. See [protocols.md](protocols.md) for the full availability matrix.

6. **Use get_facts() for initial device information**: The `get_facts()` method provides a good overview of the device and can be used to verify successful connection and basic device information.

7. **Regularly update the driver**: Keep your NAPALM HiOS driver up to date to benefit from the latest features, bug fixes, and security updates.

## Troubleshooting

Here are some common issues you might encounter when using the NAPALM HiOS driver and how to resolve them:

1. **Connection Timeout**
   - Ensure the device is reachable (try pinging it).
   - Verify that the correct hostname/IP and port are being used.
   - Check if there are any firewall rules blocking the connection.

2. **Authentication Failure**
   - Double-check the username and password.
   - Ensure the user has the necessary privileges on the device.

3. **Method Not Implemented**
   - Verify that the method you're trying to use is supported by the HiOS driver.
   - Check if the method is supported by the protocol you're using. See [protocols.md](protocols.md).

4. **Unexpected Output Format**
   - Ensure you're using the latest version of the driver.
   - Check the method's documentation for the expected output format.
   - If the issue persists, it might be due to a change in the device's output format. Please report this as an issue (see Contributing section).

5. **SNMP Issues**
   - Verify that SNMP is enabled on the device.
   - Ensure that the SNMP user/password is correct (HiOS CLI users = SNMPv3 users).
   - Check if the correct SNMP version is being used (SNMPv3 authPriv by default).

If you encounter persistent issues that you can't resolve, please check the project's issue tracker or consider contributing by reporting the issue (see Contributing section).

## Contributing

Contributions to the NAPALM HiOS driver are welcome! Here's how you can contribute:

1. **Reporting Issues**: If you encounter a bug or have a feature request, please open an issue on the project's GitHub repository. Provide as much detail as possible, including the driver version, device model, and a minimal code example that reproduces the issue.

2. **Submitting Pull Requests**: If you've fixed a bug or implemented a new feature, you can submit a pull request. Please ensure your code follows the project's coding standards and includes appropriate tests and documentation.

3. **Improving Documentation**: If you find any areas of the documentation that could be improved or expanded, please submit a pull request with your changes.

4. **Sharing Use Cases**: If you have interesting use cases or examples of how you're using the NAPALM HiOS driver, consider sharing them with the community. This can be done through blog posts, presentations, or by adding examples to the project's documentation.

Before contributing, please read the project's CONTRIBUTING.md file (if available) for any specific guidelines or requirements.

Thank you for using and contributing to the NAPALM HiOS driver!
