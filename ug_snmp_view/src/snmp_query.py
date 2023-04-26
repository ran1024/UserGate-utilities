#!/usr/bin/python3
import os, rrdtool
from fastsnmp import snmp_poller


class Port:
    def __init__(self, port, start_time):
        self.name = port
        self.rrd_file = f'data/{self.name}.rrd'
        self.rrd_file_png = f'data/{self.name}.png'
        self.octets_in: int = 0
        self.octets_out: int = 0
        
        if not os.path.isdir('data'):
            os.makedirs('data')
        if not os.path.isfile(self.rrd_file):
            rrdtool.create(self.rrd_file,
                            '--step', '1',
                            'DS:input:COUNTER:4:U:U',
                            'DS:output:COUNTER:4:U:U',
                            'RRA:AVERAGE:0.5:1:1200',  # 20 min
                            'RRA:AVERAGE:0.5:5:720',   # 1 hous
                            'RRA:AVERAGE:0.5:60:1440', # 1 day
                            )
        if not os.path.isfile(self.rrd_file_png):
            self.create_rrd_graph(start_time)

    def rrd_update(self):
        rrdtool.update(self.rrd_file, f'N:{self.octets_in}:{self.octets_out}')

    def create_rrd_graph(self, start_time):
        if start_time not in ('-20m', '-1h', '-24h'):
            start_time = '-1h'
        rrdtool.graph(self.rrd_file_png,
            '--lazy',
            '--imgformat', 'PNG',
            '--height', '80',
            '--width', '300',
            '--start', start_time,
            '--end', 'now',
            '--title', f'Trafic - {self.name} (bps)',
            f'DEF:inoctets={self.rrd_file}:input:AVERAGE',
            f'DEF:outoctets={self.rrd_file}:output:AVERAGE',
            'CDEF:inbits=inoctets,8,*',
            'CDEF:outbits=outoctets,8,*',
            'AREA:inbits#00FF00:in',
            'LINE1:outbits#0000FF:out',
        )

    def remove_rrd_graph(self):
        if os.path.isfile(self.rrd_file_png):
            os.remove(self.rrd_file_png)


def create_host_rrd():
    rrd_file = 'data/main.rrd'
    if not os.path.isdir('data'):
        os.makedirs('data')
    if not os.path.isfile(rrd_file):
        rrdtool.create(rrd_file,
                       '--step', '1',
                       'DS:cpu:GAUGE:4:U:U',
                       'DS:vcpu:GAUGE:4:U:U',
                       'DS:memory:GAUGE:4:U:U',
                       'RRA:AVERAGE:0.5:1:1200',  # 20 min
                       'RRA:AVERAGE:0.5:5:720',   # 1 hous
                       'RRA:AVERAGE:0.5:60:1440', # 1 day
                      )

def update_host_rrd(cpu, vcpu, memory):
    rrdtool.update('data/main.rrd', f'N:{cpu}:{vcpu}:{memory}')

def create_host_graph(start_time):
    if start_time not in ('-20m', '-1h', '-24h'):
        start_time = '-1h'
    rrdtool.graph('data/main.png',
        '--lazy',
        '--imgformat', 'PNG',
        '--height', '80',
        '--width', '264',
        '--start', start_time,
        '--end', 'now',
        '--title', 'График производительности(%)',
        'DEF:cpuload=data/main.rrd:cpu:AVERAGE',
        'DEF:vcpuload=data/main.rrd:vcpu:AVERAGE',
        'DEF:memload=data/main.rrd:memory:AVERAGE',
        'LINE1:memload#008000:Память',
        'LINE1:vcpuload#000FF0:vCPU',
        'LINE1:cpuload#E32B24:Процессор',
        )

def remove_host_graph():
    if os.path.isfile('data/main.png'):
        os.remove('data/main.png')

def check_snmp(ip, community):
    result = 'timeout'
#    status = 0
    hosts = (ip,)
    oid_group = ("1.3.6.1.2.1.1.1.0",)
    snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="Get", timeout=0, retry=0)
    try:
        result = next(snmp_data).value.decode()
    except StopIteration:
        pass
    return result

def get_all_ports(ip, community):
    hosts = (ip,)
    oid = ("1.3.6.1.2.1.31.1.1.1.1",)
    bad_ports = ("pimreg",)
    snmp_data = snmp_poller.poller(hosts, (oid,), community, msg_type="GetBulk")
    all_ports = sorted([d.value.decode() for d in snmp_data if d.value.decode() not in bad_ports])
    return all_ports

def get_ports(ip, community, used_ports, trafic_time):
    status = 0
    ports = {}
    if used_ports:
        hosts = (ip,)
        oid_group = ("1.3.6.1.2.1.31.1.1.1.1",)
        snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="GetBulk")
        try:
            for d in snmp_data:
                if d.value.decode() in used_ports:
                    ports[d.index_part] = Port(d.value.decode(), trafic_time)
        except ConnectionError:
            status = 1
        except OSError:
            status = 2
    if not ports:
        status = 3
    return status, ports

def get_utm_status(ip, community):
    hosts = (ip,)
    oid_group = ['1.3.6.1.4.1.45741.2.2.1',]
    data = {}
    array = {
        '1.1.0': 'vcpuCount',
        '1.2.0': 'vcpuUsage',
        '1.3.0': 'usersCounter',
        '4.1.0': 'CpuLoad',
        '4.2.0': 'MemoryUsed',
        '4.3.0': 'LogSpace',
        '4.4.0': 'PowerStatus1',
        '4.5.0': 'PowerStatus2',
        '4.6.0': 'RaidType',
        '4.7.0': 'RaidStatus',
    }
    snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="GetBulk")
    try:
        for d in snmp_data:
            if d.index_part in array:
                data[array[d.index_part]] = d.value.decode() if d.index_part in ('4.4.0', '4.5.0', '4.6.0', '4.7.0') else d.value
        return 0, data
    except ConnectionError as err:
        return 1, err
    except OSError as err:
        return 2, err
    except KeyError as err:
        return 3, err.errmsg       # В настройках SNMP не указаны необходимые события.

def get_port_counter(ip, community, ports):
    hosts = (ip,)
    oid_group = ['1.3.6.1.2.1.31.1.1.1.6', '1.3.6.1.2.1.31.1.1.1.10']
    snmp_data = snmp_poller.poller(hosts, (oid_group,), community, msg_type="GetBulk")
    try:
        for d in snmp_data:
            if d.index_part in ports:
                if d.main_oid[-1] == '6':
                    ports[d.index_part].octets_in = d.value
                else:
                    ports[d.index_part].octets_out = d.value
        for index_part in ports:
            ports[index_part].rrd_update()
    except ConnectionError:
        return 1
    except OSError:
        return 2
    return 0
