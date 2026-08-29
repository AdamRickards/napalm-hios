"""
Offline unit tests for NAPALM reshapers.

Tests the _shape_* static methods with known canonical input.
No device needed — verifies reshaping logic only.

Usage:
    pytest tests/test_reshapers.py -v
"""
from napalm_hios.hios import HIOSDriver


class TestShapeGetInterfaces:

    CANONICAL = {
        '1/1': {'oper_status': 'up', 'admin_status': 'enabled', 'alias': 'uplink', 'speed': 1000, 'mtu': 1518, 'phys_address': 'aa:bb:cc:dd:ee:ff'},
        '1/2': {'oper_status': 'down', 'admin_status': 'disabled', 'alias': '', 'speed': 100, 'mtu': 1500, 'phys_address': '11:22:33:44:55:66'},
    }

    def test_keys(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        expected_keys = {'is_up', 'is_enabled', 'description', 'last_flapped', 'speed', 'mtu', 'mac_address'}
        assert set(result['1/1'].keys()) == expected_keys

    def test_oper_status_up(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/1']['is_up'] is True

    def test_oper_status_down(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/2']['is_up'] is False

    def test_admin_status_enabled(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/1']['is_enabled'] is True

    def test_admin_status_disabled(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/2']['is_enabled'] is False

    def test_alias_to_description(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/1']['description'] == 'uplink'

    def test_phys_address_to_mac_address(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/1']['mac_address'] == 'aa:bb:cc:dd:ee:ff'

    def test_last_flapped_placeholder(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        assert result['1/1']['last_flapped'] == -1.0

    def test_types(self):
        result = HIOSDriver._shape_get_interfaces(self.CANONICAL)
        row = result['1/1']
        assert isinstance(row['is_up'], bool)
        assert isinstance(row['is_enabled'], bool)
        assert isinstance(row['description'], str)
        assert isinstance(row['last_flapped'], float)
        assert isinstance(row['speed'], int)
        assert isinstance(row['mtu'], int)
        assert isinstance(row['mac_address'], str)


class TestShapeGetLldpNeighbors:

    CANONICAL = {
        '1/1': [{'sys_name': 'CORE', 'port_id': 'ec:74:ba:35:75:75'}],
        '1/2': [{'sys_name': '', 'port_id': '46:44:42'}],
    }

    def test_keys(self):
        result = HIOSDriver._shape_get_lldp_neighbors(self.CANONICAL)
        assert set(result['1/1'][0].keys()) == {'hostname', 'port'}

    def test_values(self):
        result = HIOSDriver._shape_get_lldp_neighbors(self.CANONICAL)
        assert result['1/1'][0]['hostname'] == 'CORE'
        assert result['1/1'][0]['port'] == 'ec:74:ba:35:75:75'

    def test_empty_hostname(self):
        result = HIOSDriver._shape_get_lldp_neighbors(self.CANONICAL)
        assert result['1/2'][0]['hostname'] == ''


class TestShapeGetLldpNeighborsDetail:

    CANONICAL = {
        '1/1': [{
            'sys_name': 'CORE', 'port_id': 'eth0', 'port_description': 'port 1',
            'chassis_id': 'aa:bb:cc:dd:ee:ff', 'sys_description': 'HiOS Switch',
            'sys_capabilities': ['bridge', 'router'],
            'sys_enabled_capabilities': ['bridge'],
            'autoneg_supported': True, 'autoneg_enabled': True,
            'mau_type': 16, 'pvid': 1,
            'aggregation_enabled': [], 'aggregation_port_id': 0,
        }],
    }

    def test_keys(self):
        result = HIOSDriver._shape_get_lldp_neighbors_detail(self.CANONICAL)
        row = result['1/1'][0]
        assert 'remote_hostname' in row
        assert 'remote_port' in row
        assert 'remote_chassis_id' in row
        assert 'remote_system_description' in row
        assert 'remote_system_capabilities' in row
        assert 'remote_system_enabled_capabilities' in row

    def test_values(self):
        result = HIOSDriver._shape_get_lldp_neighbors_detail(self.CANONICAL)
        row = result['1/1'][0]
        assert row['remote_hostname'] == 'CORE'
        assert row['remote_port'] == 'eth0'
        assert row['remote_chassis_id'] == 'aa:bb:cc:dd:ee:ff'
        assert row['remote_system_capabilities'] == ['bridge', 'router']

    def test_passthrough_keys(self):
        result = HIOSDriver._shape_get_lldp_neighbors_detail(self.CANONICAL)
        row = result['1/1'][0]
        assert row['autoneg_supported'] is True
        assert row['mau_type'] == 16
        assert row['pvid'] == 1


class TestShapeGetMacAddressTable:

    CANONICAL = [
        {'mac': 'aa:bb:cc:dd:ee:ff', 'interface': '1/1', 'vlan': 1, 'status': 'learned'},
        {'mac': '11:22:33:44:55:66', 'interface': '1/2', 'vlan': 1, 'status': 'self'},
        {'mac': 'ff:ff:ff:ff:ff:ff', 'interface': '1/3', 'vlan': 0, 'status': 'invalid'},
    ]

    def test_keys(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        expected_keys = {'mac', 'interface', 'vlan', 'active', 'static', 'moves', 'last_move'}
        assert set(result[0].keys()) == expected_keys

    def test_learned_is_active_not_static(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        assert result[0]['active'] is True
        assert result[0]['static'] is False

    def test_self_is_active_and_static(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        assert result[1]['active'] is True
        assert result[1]['static'] is True

    def test_invalid_is_not_active(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        assert result[2]['active'] is False
        assert result[2]['static'] is False

    def test_placeholders(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        assert result[0]['moves'] == 0
        assert result[0]['last_move'] == -1.0

    def test_no_status_key(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        assert 'status' not in result[0]

    def test_types(self):
        result = HIOSDriver._shape_get_mac_address_table(self.CANONICAL)
        row = result[0]
        assert isinstance(row['active'], bool)
        assert isinstance(row['static'], bool)
        assert isinstance(row['moves'], int)
        assert isinstance(row['last_move'], float)


class TestShapeGetOptics:

    CANONICAL = {
        '1/1': {'tx_power': 3825, 'rx_power': 3597, 'temperature': 39},
        '1/2': {'tx_power': 0.0, 'rx_power': 0.0, 'temperature': 0.0},
    }

    def test_filters_zero_ports(self):
        result = HIOSDriver._shape_get_optics(self.CANONICAL)
        assert '1/1' in result
        assert '1/2' not in result

    def test_napalm_structure(self):
        result = HIOSDriver._shape_get_optics(self.CANONICAL)
        port = result['1/1']
        assert 'physical_channels' in port
        channel = port['physical_channels']['channel']
        assert isinstance(channel, list)
        assert channel[0]['index'] == 0
        state = channel[0]['state']
        assert 'input_power' in state
        assert 'output_power' in state
        assert 'laser_bias_current' in state

    def test_power_values(self):
        result = HIOSDriver._shape_get_optics(self.CANONICAL)
        state = result['1/1']['physical_channels']['channel'][0]['state']
        assert state['input_power']['instant'] == 3597.0
        assert state['output_power']['instant'] == 3825.0
        assert state['laser_bias_current']['instant'] == 0.0

    def test_power_stat_keys(self):
        result = HIOSDriver._shape_get_optics(self.CANONICAL)
        state = result['1/1']['physical_channels']['channel'][0]['state']
        for metric in ('input_power', 'output_power', 'laser_bias_current'):
            assert set(state[metric].keys()) == {'instant', 'avg', 'min', 'max'}


class TestShapeGetInterfacesIp:

    CANONICAL = {
        '1/1': {'ipv4': {'192.168.1.4': {'prefix_length': 24}}, 'ipv6': {}},
    }

    def test_passthrough(self):
        result = HIOSDriver._shape_get_interfaces_ip(self.CANONICAL)
        assert '1/1' in result
        assert '192.168.1.4' in result['1/1']['ipv4']
        assert result['1/1']['ipv4']['192.168.1.4']['prefix_length'] == 24

    def test_filters_empty(self):
        data = {'1/1': {'ipv4': {}, 'ipv6': {}}}
        result = HIOSDriver._shape_get_interfaces_ip(data)
        assert '1/1' not in result
