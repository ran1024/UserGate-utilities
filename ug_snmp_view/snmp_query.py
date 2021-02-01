#!/usr/bin/python3
from fastsnmp import snmp_poller
from dataclasses import dataclass


MAX_COUNTER = 18446744073709551615

@dataclass
class Port:
    name: str
    port_type: int = 4
    status: str = 'up'
    b_color: str = '#0A37A3'
    octets_in: int = 0
    octets_out: int = 0
    octets_in_old: int = 0
    octets_out_old: int = 0

def switch(x):
    return {
        4: '#00345B',
        5: '#00345B',      # 5079D3
        6: '#004EA1',
        7: '#4A6984',
        8: '#5079D3',
    }.get(x, '#6F00FF')    # 6F00FF

def get_ifnumber(ip, community):
    hosts = (ip,)
    if_number = ["1.3.6.1.2.1.2.1.0",]
    snmp_data = snmp_poller.poller(hosts, (if_number,), community, msg_type="Get")
    try:
        for d in snmp_data:
            return d[3]
    except ConnectionError:
        return -1
    except OSError:
        return -2

def get_ports(ip, community, ports):
    hosts = (ip,)
    oid_group = ["1.3.6.1.2.1.31.1.1.1.1",]
    snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="GetBulk")
    try:
        for d in snmp_data:
            port_type = int(d[2][0])
            ports[d[2]] = Port(d[3].decode(), port_type, 'up', switch(port_type))
    except ConnectionError:
        return -1
    except OSError:
        return -2
    return 0

def get_utm_status(ip, community):
    hosts = (ip,)
    data = {}
    oid_group = ['1.3.6.1.4.1.45741.2.2',]
    array = {
        '2.0': 'CpuLoad',
        '3.0': 'MemoryUsed',
        '4.0': 'LogSpace',
        '5.0': 'PowerStatus1',
        '6.0': 'PowerStatus2',
        '7.0': 'RaidStatus',
        '8.0': 'VcpuUsage',
        '9.0': 'VcpuCount',
        '10.0': 'UsersCounter',
        }
    snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="GetBulk")
    try:
        for d in snmp_data:
            if d[2] in array:
                data[array[d[2]]] = d[3].decode() if d[2] in ('5.0', '6.0', '7.0') else d[3]
        return len(data), data
    except ConnectionError:
        return -1, data
    except OSError:
        return -2, data

def count_octets(old, new):
    return (new - old) if new >= old else (MAX_COUNTER - old + new)

def get_port_counter(ip, community, ports):
    hosts = (ip,)
    oid_group = ['1.3.6.1.2.1.31.1.1.1.6', '1.3.6.1.2.1.31.1.1.1.10']
    snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="GetBulk")
    try:
        for d in snmp_data:
            if d[1][-1] == '6':
                ports[d[2]].octets_in = count_octets(ports[d[2]].octets_in_old, d[3])
                ports[d[2]].octets_in_old = d[3]
            else:
                ports[d[2]].octets_out = count_octets(ports[d[2]].octets_out_old, d[3])
                ports[d[2]].octets_out_old = d[3]
    except KeyError:
        pass
    except ConnectionError:
        return -1
    except OSError:
        return -2
    return 0
