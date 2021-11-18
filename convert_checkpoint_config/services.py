#!/usr/bin/python3
from dataclasses import dataclass

@dataclass(frozen = True)
class ServicePorts:
    tcp = {
        '20': 'FTP',
        '21': 'FTP',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '53': 'DNS',
        '67': 'DHCP',
        '80': 'HTTP',
        '110': 'POP3',
        '139': 'NetBIOS',
        '143': 'IMAP',
        '161': 'SNMP',
        '162': 'SNMPTRAP',
        '443': 'HTTPS',
        '445': 'SMB',
        '465': 'SMTPS',
        '873': 'Rsync',
        '993': 'IMAPS',
        '995': 'POP3S',
        '1194': 'OpenVPN',
        '1433-1434': 'MS SQL',
        '1494': 'Citrix',
        '1503': 'NetMeeting',
        '1645-1646': 'Radius',
        '1723': 'VPN PPTP',
        '2041-2042': 'Mail Agent',
        '2404': 'SCADA',
        '2598': 'Citrix',
        '3050': 'Firebird',
        '3306': 'MySQL',
        '3389': 'RDP',
        '3690': 'SVN',
        '4899': 'Radmin',
        '5000': 'UPnP',
        '5004-5005': 'RTP',
        '5060': 'SIP',
        '5061': 'SIP',
        '5060-5061': 'SIP',
        '5190': 'ICQ',
        '5222': 'XMPP-CLIENT',
        '5269': 'XMPP-SERVER',
        '5432': 'Postgres SQL',
        '6665-6669': 'IRC',
        '6881-6999': 'Torrents',
        '8080': 'CheckPoint Proxy',
        '8090': 'HTTP Proxy',
        '8091': 'HTTPS Proxy',
        '1000-65535': 'TCP/UDP 1000-65535',
        '10053': 'DNS Proxy',
        }
    udp = {
        '53': 'DNS',
        '67': 'DHCP',
        '68': 'DHCP',
        '69': 'TFTP',
        '80': 'Quick UDP Internet Connections',
        '87': 'Client-Bank Sberbank',
        '123': 'NTP',
        '137': 'NetBIOS',
        '138': 'NetBIOS',
        '161': 'SNMP',
        '162': 'SNMPTRAP',
        '443': 'Quick UDP Internet Connections',
        '1194': 'OpenVPN',
        '1645-1646': 'Radius',
        '3690': 'SVN',
        '4500': 'IPSec',
        '5004-5005': 'RTP',
        '5060': 'SIP',
        '5777': 'VipNet Client',
        '6881-6999': 'Torrents',
        '1000-65535': 'TCP/UDP 1000-65535',
        '10053': 'DNS Proxy',
        '55777': 'VipNet Client',
        }

    @classmethod
    def get_dict_by_port(cls, proto, service_port, service_name):
        try:
            if proto == 'tcp':
                return {'services': cls.tcp[service_port]}
            else:
                return {'services': cls.udp[service_port]}
        except KeyError:
            return {'services': service_name}

    @classmethod
    def get_name_by_port(cls, proto, service_port, service_name):
        try:
            if proto == 'tcp':
                return cls.tcp[service_port]
            else:
                return cls.udp[service_port]
        except KeyError:
            return service_name

dict_risk = {
    'Very_Low': 1,
    'Low': 2,
    'Medium': 3,
    'High': 4,
    'Critical': 5,
}

character_map = {
    ord('\n'): None,
    ord('\t'): None,
    ord('\r'): None,
    ' ': '_',
    '/': '_',
    '\\': '_',
    '.': '_',
}