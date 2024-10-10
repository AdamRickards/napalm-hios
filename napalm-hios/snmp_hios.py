import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from napalm.base.exceptions import ConnectionException
from napalm_hios.utils import log_error

import logging

logger = logging.getLogger(__name__)

class SNMPHIOS:
    def __init__(self, hostname, username, password, timeout, port=161):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.port = port
        self.engine = None
        self.context = None

    def open(self):
        try:
            self.engine = SnmpEngine()
            self.context = ContextData()
            # Test connection with a simple get
            asyncio.run(self._get_snmp_data_with_timeout('SNMPv2-MIB', ['sysDescr']))
        except Exception as e:
            log_error(logger, f"Error setting up SNMP connection: {str(e)}")
            raise ConnectionException(f"Cannot set up SNMP for {self.hostname}")

    def close(self):
        self.engine = None
        self.context = None

    async def _get_snmp_data(self, mib, *oids):  # Changed to accept variable number of oids
        data = {}
        for oid in oids:
            try:
                iterator = getCmd(
                    self.engine,
                    CommunityData(self.username, mpModel=0),
                    await UdpTransportTarget.create((self.hostname, self.port)),
                    self.context,
                    ObjectType(ObjectIdentity(mib, oid, 0))
                )
                errorIndication, errorStatus, errorIndex, varBinds = await iterator
                if errorIndication or errorStatus:
                    log_error(logger, f"SNMP error for {oid}: {errorIndication or errorStatus}")
                else:
                    for varBind in varBinds:
                        data[oid] = varBind[1].prettyPrint()
            except Exception as e:
                log_error(logger, f"Error querying {oid}: {str(e)}")
        return data

    async def _get_snmp_data_with_timeout(self, mib, oids):
        """Wrapper for SNMP gets with timeout handling"""
        try:
            return await asyncio.wait_for(
                self._get_snmp_data(mib, *oids),  # Unpack oids list here
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            raise ConnectionException(f"SNMP timeout while querying {self.hostname}")

    def get_facts(self):
        if not self.engine:
            raise ConnectionException("SNMP connection is not set up")

        facts = {}
        try:
            system_info = asyncio.run(self._get_snmp_data_with_timeout(
                'SNMPv2-MIB', 
                ['sysDescr', 'sysName', 'sysObjectID']  # Pass as list
            ))
            facts['vendor'] = 'Belden'
            facts['model'] = 'HiOS'
            facts['hostname'] = system_info.get('sysName', 'Unknown')
            facts['os_version'] = system_info.get('sysDescr', 'Unknown').split()[2]
        except Exception as e:
            log_error(logger, f"Error retrieving facts via SNMP: {str(e)}")
            raise

        return facts

    def get_interfaces(self):
        if not self.engine:
            raise ConnectionException("SNMP connection is not set up")

        interfaces = {}
        try:
            if_info = asyncio.run(self._get_snmp_data_with_timeout(
                'IF-MIB',
                ['ifIndex', 'ifDescr', 'ifType', 'ifMtu', 'ifSpeed', 
                 'ifPhysAddress', 'ifAdminStatus', 'ifOperStatus']  # Pass as list
            ))
            for index, data in if_info.items():
                interface_name = data['ifDescr']
                interfaces[interface_name] = {
                    'is_up': data['ifOperStatus'] == 1,
                    'is_enabled': data['ifAdminStatus'] == 1,
                    'description': '',
                    'speed': data['ifSpeed'],
                    'mtu': data['ifMtu']
                }
        except Exception as e:
            log_error(logger, f"Error retrieving interfaces via SNMP: {str(e)}")
            raise

        return interfaces
    
    def get_environment(self):
        env_data = {
            'fans': {},
            'temperature': {},
            'power': {},
            'cpu': {},
            'memory': {}
        }
        return env_data

    def get_snmp_information(self):
        if not self.engine:
            raise ConnectionException("SNMP connection is not set up")

        snmp_info = {}
        try:
            snmp_data = asyncio.run(self._get_snmp_data_with_timeout(
                'SNMPv2-MIB',
                ['sysDescr', 'sysName', 'sysLocation', 'sysContact']  # Pass as list
            ))
            snmp_info['chassis_id'] = snmp_data.get('sysName', 'Unknown')
            snmp_info['contact'] = snmp_data.get('sysContact', 'Unknown')
            snmp_info['location'] = snmp_data.get('sysLocation', 'Unknown')
            snmp_info['system_description'] = snmp_data.get('sysDescr', 'Unknown')
            snmp_info['community'] = {'public': 'read-only'}
        except Exception as e:
            log_error(logger, f"Error retrieving SNMP information: {str(e)}")
            raise

        return snmp_info