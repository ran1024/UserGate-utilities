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
url_category = {
    '': {'type': 'url_category', 'name': 'Unknown'},
    'Facebook Social Plugins': {'type': 'url_category', 'name': 'Advertisements & Pop-Ups'},
    '': {'type': 'url_category', 'name': 'Alcohol & Tobacco'},
    'Anonymizer': {'type': 'url_category', 'name': 'Anonymizers'},
    'Proxy based anonymizers': {'type': 'url_category', 'name': 'Anonymizers'},
    'Anonymizers/proxy avoidance sites': {'type': 'url_category', 'name': 'Anonymizers'},
    'NetConceal Anonymizer': {'type': 'url_category', 'name': 'Anonymizers'},
    '': {'type': 'url_category', 'name': 'Arts'},
    'Business / Economy': {'type': 'url_category', 'name': 'Business'},
    '': {'type': 'url_category', 'name': 'Transportation'},
    '': {'type': 'url_category', 'name': 'Chat'},
    '': {'type': 'url_category', 'name': 'Kids sites'},
    '': {'type': 'url_category', 'name': 'Forums & Newsgroups'},
    '': {'type': 'url_category', 'name': 'Compromised'},
    '': {'type': 'url_category', 'name': 'Computers & Technogy'},
    '': {'type': 'url_category', 'name': 'Criminal Activity'},
    '': {'type': 'url_category', 'name': 'Dating & Personals'},
    '': {'type': 'url_category', 'name': 'Download Sites'},
    '': {'type': 'url_category', 'name': 'Education'},
    '': {'type': 'url_category', 'name': 'Entertainment'},
    '': {'type': 'url_category', 'name': 'Finance'},
    '': {'type': 'url_category', 'name': 'Gambling'},
    'Games': {'type': 'url_category', 'name': 'Games'},
    '': {'type': 'url_category', 'name': 'Government'},
    '': {'type': 'url_category', 'name': 'Hate & Intolerance'},
    '': {'type': 'url_category', 'name': 'Health & Medicine'},
    '': {'type': 'url_category', 'name': 'Illegal Drug'},
    '': {'type': 'url_category', 'name': 'Job Search'},
    '': {'type': 'url_category', 'name': 'Military'},
    '': {'type': 'url_category', 'name': 'Streaming Media & Downloads'},
    'News / Media': {'type': 'url_category', 'name': 'News'},
    '': {'type': 'url_category', 'name': 'Non-profits & NGOs'},
    '': {'type': 'url_category', 'name': 'Nudity'},
    '': {'type': 'url_category', 'name': 'Personal Sites'},
    '': {'type': 'url_category', 'name': 'Phishing & Fraud'},
    '': {'type': 'url_category', 'name': 'Politics'},
    'Pornography': {'type': 'url_category', 'name': 'Pornography/Sexually Explicit'},
    'Sex': {'type': 'url_category', 'name': 'Pornography/Sexually Explicit'},
    '': {'type': 'url_category', 'name': 'Real Estate'},
    '': {'type': 'url_category', 'name': 'Religion'},
    '': {'type': 'url_category', 'name': 'Restaurants & Dining'},
    '': {'type': 'url_category', 'name': 'Search Engines & Portals'},
    '': {'type': 'url_category', 'name': 'Shopping'},
    'Social Networking': {'type': 'url_category', 'name': 'Social Networking'},
    'Social Plugins': {'type': 'url_category', 'name': 'Social Networking'},
    '': {'type': 'url_category', 'name': 'Spam Sites'},
    '': {'type': 'url_category', 'name': 'Sports'},
    '': {'type': 'url_category', 'name': 'Malware'},
    '': {'type': 'url_category', 'name': 'Stock trading'},
    '': {'type': 'url_category', 'name': 'Translators'},
    '': {'type': 'url_category', 'name': 'Travel'},
    '': {'type': 'url_category', 'name': 'Violence'},
    '': {'type': 'url_category', 'name': 'Weapons'},
    '': {'type': 'url_category', 'name': 'Web-based Email'},
    '': {'type': 'url_category', 'name': 'General'},
    '': {'type': 'url_category', 'name': 'Leisure & Recreation'},
    '': {'type': 'url_category', 'name': 'Online training and tools'},
    '': {'type': 'url_category', 'name': 'Legal'},
    '': {'type': 'url_category', 'name': 'Local Information'},
    '': {'type': 'url_category', 'name': 'Reference and Research'},
    '': {'type': 'url_category', 'name': 'Technical or business forums and news groups'},
    '': {'type': 'url_category', 'name': 'Technical information and documentation'},
    '': {'type': 'url_category', 'name': 'Personal Storage'},
    '': {'type': 'url_category', 'name': 'CDNs'},
    '': {'type': 'url_category', 'name': 'Profanity'},
    '': {'type': 'url_category', 'name': 'Professional social networks'},
    'Botnets': {'type': 'url_category', 'name': 'Botnets'},
    '': {'type': 'url_category', 'name': 'Cults'},
    '': {'type': 'url_category', 'name': 'Fashion & Beauty'},
    '': {'type': 'url_category', 'name': 'Greeting cards'},
    '': {'type': 'url_category', 'name': 'Hacking'},
    '': {'type': 'url_category', 'name': 'Cryptocurrency Mining'},
    '': {'type': 'url_category', 'name': 'Illegal Software'},
    '': {'type': 'url_category', 'name': 'Image Sharing'},
    '': {'type': 'url_category', 'name': 'Information Security'},
    'Instant Messaging': {'type': 'url_category', 'name': 'Instant Messaging'},
    '': {'type': 'url_category', 'name': 'Network Errors'},
    '': {'type': 'url_category', 'name': 'Parked Domains'},
    'P2P File Sharing': {'type': 'url_category', 'name': 'Peer-to-Peer'},
    '': {'type': 'url_category', 'name': 'Private IP Addresses'},
    '': {'type': 'url_category', 'name': 'School Cheating'},
    'Sex Education': {'type': 'url_category', 'name': 'Sex Education'},
    '': {'type': 'url_category', 'name': 'Tasteless'},
    'Child Abuse': {'type': 'url_category', 'name': 'Child Abuse Images'},
    '': {'type': 'url_category', 'name': 'Gay, Lesbian or Bisexual'},
    '': {'type': 'url_category', 'name': 'Literature & Books'},
    '': {'type': 'url_category', 'name': 'Nutrition & Diet'},
    '': {'type': 'url_category', 'name': 'Pets & Animals'},
    'Windows Update': {'type': 'url_category', 'name': 'Updates'},
    'Windows Server Update Service (WSUS)': {'type': 'url_category', 'name': 'Updates'},
    'Windows Product Activation': {'type': 'url_category', 'name': 'Updates'},
    'Low risk': {'type': 'url_category', 'name': 'Reputation: Low risk'},
    'Medium risk': {'type': 'url_category', 'name': 'Reputation: Medium risk'},
    'Critical Risk': {'type': 'url_category', 'name': 'Reputation: High risk'},
}

l7categories = {
    '': {'type': 'l7_category', 'name': 'Standard networks'},
    'P2P File Sharing': {'type': 'l7_category', 'name': 'File sharing P2P'},
    'VoIP': {'type': 'l7_category', 'name': 'VOIP'},
    'Video Conferencing': {'type': 'l7_category', 'name': 'Conferencing'},
    'Instant messaging': {'type': 'l7_category', 'name': 'Instant messaging'},
    'Media Streams': {'type': 'l7_category', 'name': 'Media streaming'},
    'Anonymizer Universal': {'type': 'l7_category', 'name': 'Proxies and anonymizers'},
    'Proxy based anonymizer': {'type': 'l7_category', 'name': 'Proxies and anonymizers'},
    'Encrypts communications': {'type': 'l7_category', 'name': 'Tunneling'},
    'File storage and Sharing': {'type': 'l7_category', 'name': 'File storage and backup'},
    'Games Radar': {'type': 'l7_category', 'name': 'File storage and backup'},
    'Games': {'type': 'l7_category', 'name': 'Games'},
    'Mobile Software': {'type': 'l7_category', 'name': 'Mobile'},
    'Business / Economy': {'type': 'l7_category', 'name': 'Business'},
    '': {'type': 'l7_category', 'name': 'Email'},
    'Web Services Provider': {'type': 'l7_category', 'name': 'Web browsing'},
    'Remote Administration': {'type': 'l7_category', 'name': 'Remote access'},
    'Social Networking': {'type': 'l7_category', 'name': 'Social networking'},
    '': {'type': 'l7_category', 'name': 'Web posting'},
    'Software update': {'type': 'l7_category', 'name': 'Software update'},
    '': {'type': 'l7_category', 'name': 'Trojan Horses'},
    '': {'type': 'l7_category', 'name': 'Coin Miners'},
}

l7apps = {
    'Facebook Games': {'type': 'l7apps', 'name': ['Facebook Apps',]},
    'Facebook-video-upload': {'type': 'l7apps', 'name': ['Facebook Video',]},
    'Facebook-video': {'type': 'l7apps', 'name': ['Facebook Video',]},
    'Ammyy Admin': {'type': 'l7apps', 'name': ['Ammyy Admin',]},
    'TeamViewer': {'type': 'l7apps', 'name': ['TeamViewer',]},
    'TeamViewer-web-Join Meeting': {'type': 'l7apps', 'name': ['TeamViewer',]},
    'TeamViewer-web-Management Console': {'type': 'l7apps', 'name': ['TeamViewer',]},
    'Windows Update': {'type': 'l7apps', 'name': ['WinUpdate', 'Microsoft Update']},
    'Windows Server Update Service (WSUS)': {'type': 'l7apps', 'name': ['WinUpdate', 'Microsoft Update']},
    'WhatsApp Messenger': {'type': 'l7apps', 'name': ['WhatsApp', 'WhatsApp Chat', 'WhatsApp Media']},
    'WhatsApp Messenger-file transfer': {'type': 'l7apps', 'name': ['WhatsApp Media',]},
    'WhatsApp Messenger-voice call': {'type': 'l7apps', 'name': ['WhatsApp',]},
    'WhatsApp Messenger-web/PC': {'type': 'l7apps', 'name': ['WhatsApp', 'WhatsApp Chat', 'WhatsApp Media']},
    'Hangouts': {'type': 'l7apps', 'name': ['Google Hangouts',]},
    'Hangouts-audio-video': {'type': 'l7apps', 'name': ['Google Hangouts',]},
    'Hangouts-chat': {'type': 'l7apps', 'name': ['Google Hangouts',]},
    'Hangouts-download': {'type': 'l7apps', 'name': ['Google Hangouts',]},
    'Hangouts-upload': {'type': 'l7apps', 'name': ['Google Hangouts',]},
    'Odnoklassniki': {'type': 'l7apps', 'name': ['Odnoklassniki',]},
    'Odnoklassniki-apps': {'type': 'l7apps', 'name': ['Odnoklassniki',]},
    'Odnoklassniki-messaging': {'type': 'l7apps', 'name': ['Odnoklassniki',]},
    'Odnoklassniki-voice-video chat': {'type': 'l7apps', 'name': ['Odnoklassniki',]},
    'Twitter Social Plugins': {'type': 'l7apps', 'name': ['Twitter', 'Twitter Posting']},
    'Mail.Ru Agent': {'type': 'l7apps', 'name': ['Mail.Ru Agent',]},
    'Mail.Ru Agent-file transfer': {'type': 'l7apps', 'name': ['Mail.ru Cloud',]},
    'Mail.Ru WebAgent': {'type': 'l7apps', 'name': ['Mail.ru',]},
    'GameSpy': {'type': 'l7apps', 'name': ['GameSpy',]},
    'Windows Live Messenger-games': {'type': 'l7apps', 'name': ['MSN Game',]},
    'P2Ptv Remote Control': {'type': 'l7apps', 'name': ['PPLive',]},
    'Anatomic P2P': {'type': 'l7apps', 'name': ['BitTorrent announce',]},
    'Ants P2P': {'type': 'l7apps', 'name': ['ANts P2P',]},
    'BitTorrent Protocol': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'BitTorrent Sync': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'BitTorrent Now': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'BitTorrent Bleep': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'Gnome Bittorrent': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'BitTyrant': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'BitTornado': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'BitTorrent Live': {'type': 'l7apps', 'name': ['BitTorrent announce',]},
    'Turbo Torrent': {'type': 'l7apps', 'name': ['BitTorrent',]},
    'Torrent Swapper': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'Torrent Monster': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'Arctic Torrent': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'G3 Torrent': {'type': 'l7apps', 'name': ['BitTorrent', 'BitTorrent announce', 'BitTorrent Scrape']},
    'FilePipe P2P': {'type': 'l7apps', 'name': ['Ares', 'FastTrack', 'Gnutella']},
    'Gimme P2P': {'type': 'l7apps', 'name': ['Gnutella',]},
    'WeChat-audio video chat': {'type': 'l7apps', 'name': ['WeChat',]},
    'Twitch.tv-video play': {'type': 'l7apps', 'name': ['Twitch',]},
    'Skype for Business (Lync)-video and voip': {'type': 'l7apps', 'name': ['Skype for Business',]},
    'Sohu video-upload': {'type': 'l7apps', 'name': ['Sohu',]},
    'Sohu-video': {'type': 'l7apps', 'name': ['Sohu',]},
    'Twitch.tv-video access': {'type': 'l7apps', 'name': ['Twitch',]},
    'Nate-video': {'type': 'l7apps', 'name': ['NateOn', 'NateOn desktop', 'NateOn VOIP']},
    'NateOn-audio video': {'type': 'l7apps', 'name': ['NateOn', 'NateOn desktop', 'NateOn VOIP']},
    'NBA.com-video': {'type': 'l7apps', 'name': ['NBA', 'NBA Turner']},
    'NBC-video': {'type': 'l7apps', 'name': ['NBC News',]},
    'Qik-video upload': {'type': 'l7apps', 'name': ['Qik Video',]},
    'Qik-video viewing': {'type': 'l7apps', 'name': ['Qik Video',]},
    'Instagram-video': {'type': 'l7apps', 'name': ['Instagram',]},
    'MySpace Video': {'type': 'l7apps', 'name': ['myspace',]},
    'FC2-video': {'type': 'l7apps', 'name': ['FC2',]},
    'FC2-video-upload': {'type': 'l7apps', 'name': ['FC2',]},
    'Fetion-audio-video': {'type': 'l7apps', 'name': ['Fetion',]},
    'CBS-video': {'type': 'l7apps', 'name': ['Viacom CBS',]},
    'CNN-video': {'type': 'l7apps', 'name': ['CNN',]},
    'Epicurious-video': {'type': 'l7apps', 'name': ['Epicurious',]},
    'AIM-video chat': {'type': 'l7apps', 'name': ['AIM',]},
    'Apple Daily-video': {'type': 'l7apps', 'name': ['Apple Daily',]},
    'Baidu Hi-video chat': {'type': 'l7apps', 'name': ['Baidu Hi',]},
    'Baidu Video Search': {'type': 'l7apps', 'name': ['Baidu Player',]},
    'Caihong-audio-video': {'type': 'l7apps', 'name': ['Caihong QQ',]},
    'Camfrog Video Chat': {'type': 'l7apps', 'name': ['Camfrog',]},
}
none_apps = {
    'Baidu Hi-games': {'type': '', 'name': 'Baidu Hi-games', 'url_category': 'Games'},
    'Roblox-games': {'type': '', 'name': 'Roblox-games', 'url_category': 'Games'},
    'Supercell games (Clash of Clans)': {'type': '', 'name': 'Supercell games (Clash of Clans)', 'url_category': 'Games'},
    'Yahoo! Games': {'type': '', 'name': 'Yahoo! Games', 'url_category': 'Games'},
    'YY Voice-games': {'type': '', 'name': 'YY Voice-games', 'url_category': 'Games'},
    'Torch Games': {'type': '', 'name': 'Torch Games', 'url_category': 'Games'},
    'Zynga Games': {'type': '', 'name': 'Zynga Games', 'url_category': 'Games'},
    'Flash Games Den': {'type': '', 'name': 'Flash Games Den', 'url_category': 'Games'},
    'Games for Her By You': {'type': '', 'name': 'Games for Her By You', 'url_category': 'Games'},
    'Games Only': {'type': '', 'name': 'Games Only', 'url_category': 'Games'},
    'games2go': {'type': '', 'name': 'games2go', 'url_category': 'Games'},
    'QQ Games': {'type': '', 'name': 'GameSkoot', 'url_category': 'Games'},
    'Mail.ru-games': {'type': '', 'name': 'Mail.Ru-games', 'url_category': 'Games'},
    'GameSkoot': {'type': '', 'name': 'GameSkoot', 'category': 'Games'},
    'Garage Games': {'type': '', 'name': 'Garage Games', 'category': 'Games'},
    'Google Plus-games': {'type': '', 'name': 'Google Plus-games', 'category': 'Games'},
    'Hyves-games': {'type': '', 'name': 'Hyves-games', 'category': 'Games'},
    '51.com-games': {'type': '', 'name': '51.com-games', 'category': 'Games'},
    'I <3 Games': {'type': '', 'name': 'I <3 Games', 'category': 'Games'},
    'P2P Cache': {'type': '', 'name': 'P2P Cache', 'category': 'File sharing P2P'},
    'P2P Messenger': {'type': '', 'name': 'P2P Messenger', 'category': 'File sharing P2P'},
    'P2P-Radio': {'type': '', 'name': 'P2P-Radio', 'category': 'File sharing P2P'},
    'Speedy P2P Movie Finder': {'type': '', 'name': 'Speedy P2P Movie Finder', 'category': 'File sharing P2P'},
    'Transporter P2P': {'type': '', 'name': 'Transporter P2P', 'category': 'File sharing P2P'},
    'Anubis P2P': {'type': '', 'name': 'Anubis P2P', 'category': 'File sharing P2P'},
    'Korea P2P-Downloader': {'type': '', 'name': 'Korea P2P-Downloader', 'category': 'File storage and backup'},
    'Bittorent.biz': {'type': '', 'name': 'Bittorent.biz', 'category': 'File sharing P2P'},
    'Bittorent Bleep': {'type': '', 'name': 'Bittorent Bleep', 'category': 'Instant messaging'},
    'Bittorent Now': {'type': '', 'name': 'Bittorent Now', 'category': 'File sharing P2P'},
    'Torrents2hell.com': {'type': '', 'name': 'Torrents2hell.com', 'category': 'File sharing P2P'},
    'TorrentVolve': {'type': '', 'name': 'TorrentVolve', 'category': 'File sharing P2P'},
    'Torrentz': {'type': '', 'name': 'Torrentz', 'category': 'File sharing P2P'},
    'Uk-torrents': {'type': '', 'name': 'Uk-torrents', 'category': 'File sharing P2P'},
    'Torrent.e2k.ru': {'type': '', 'name': 'Torrent.e2k.ru', 'category': 'File sharing P2P'},
    'Torrent69.net': {'type': '', 'name': 'Torrent69.net', 'category': 'File sharing P2P'},
    'TorrentBytes.net': {'type': '', 'name': 'TorrentBytes.net', 'category': 'File sharing P2P'},
    'Torrentesx.com': {'type': '', 'name': 'Torrentesx.com', 'category': 'File sharing P2P'},
    'Torrentleech.org': {'type': '', 'name': 'Torrentleech.org', 'category': 'File sharing P2P'},
    'Torrentmatrix.com': {'type': '', 'name': 'Torrentmatrix.com', 'category': 'File sharing P2P'},
    'Torrentplaza.be': {'type': '', 'name': 'Torrentplaza.be', 'category': 'File sharing P2P'},
    'Torrentradar.org': {'type': '', 'name': 'Torrentradar.org', 'category': 'File sharing P2P'},
    'Torrents.bgsalsa.info': {'type': '', 'name': 'Torrents.bgsalsa.info', 'category': 'File sharing P2P'},
    'Central-torrent.eu': {'type': '', 'name': 'Central-torrent.eu', 'category': 'File sharing P2P'},
    'Energy-torrent.com': {'type': '', 'name': 'Energy-torrent.com', 'category': 'File sharing P2P'},
    'G-torrent.waw.pl': {'type': '', 'name': 'G-torrent.waw.pl', 'category': 'File sharing P2P'},
    'Midnight-torrents.com': {'type': '', 'name': 'Midnight-torrents.com', 'category': 'File sharing P2P'},
    'Movie-torrentz.com': {'type': '', 'name': 'Movie-torrentz.com', 'category': 'File sharing P2P'},
    'MP3 Torrent Downloader': {'type': '', 'name': 'MP3 Torrent Downloader', 'category': 'File sharing P2P'},
    'Quad-core-torrents.co.uk': {'type': '', 'name': 'Quad-core-torrents.co.uk', 'category': 'File sharing P2P'},
    'Torrent Episode Downloader': {'type': '', 'name': 'Torrent Episode Downloader', 'category': 'File sharing P2P'},
    'Assasin-torrents.co.uk': {'type': '', 'name': 'Assasin-torrents.co.uk', 'category': 'File sharing P2P'},
    'Basket-torrent.webpark.pl': {'type': '', 'name': 'Basket-torrent.webpark.pl', 'category': 'File sharing P2P'},
    'Bit-torrents.6x.to': {'type': '', 'name': 'Bit-torrents.6x.to', 'category': 'File sharing P2P'},
    'Blog Torrent': {'type': '', 'name': 'Blog Torrent', 'category': 'File sharing P2P'},
    'Pornorip.net': {'type': '', 'name': 'Pornorip.net', 'category': 'File sharing P2P'},
    'Sexy Insurance!': {'type': '', 'name': 'Sexy Insurance!', 'category': 'Social Networking'},
    'VidiPedia-video access': {'type': '', 'name': 'VidiPedia-video access', 'category': 'Media streaming'},
    'Vidmax-video access': {'type': '', 'name': 'Vidmax-video access', 'url_category': 'Entertainment'},
    'Vidmax-video play': {'type': '', 'name': 'Vidmax-video play', 'url_category': 'Streaming Media & Downloads'},
    'Vidmax-video upload': {'type': '', 'name': 'Vidmax-video play', 'url_category': 'Peer-to-Peer'},
    'Viewster-video access': {'type': '', 'name': 'Viewster-video access', 'url_category': 'Streaming Media & Downloads'},
    'Viewster-video play': {'type': '', 'name': 'Viewster-video play', 'url_category': 'Streaming Media & Downloads'},
    'Viewster-video chat': {'type': '', 'name': 'Viewster-video chat', 'category': 'Conferencing'},
    'UltraGet Video Downloader': {'type': '', 'name': 'UltraGet Video Downloader', 'url_category': 'Streaming Media & Downloads'},
    'Ustream-video': {'type': '', 'name': 'Ustream-video', 'url_category': 'Streaming Media & Downloads'},
    'Veoh-video upload': {'type': '', 'name': 'Veoh-video upload', 'url_category': 'Streaming Media & Downloads'},
    'Video Download Toolbar': {'type': '', 'name': 'Video Dowload Toolbar', 'url_category': 'Streaming Media & Downloads'},
    'Video4pc Downloader': {'type': '', 'name': 'Video4pc Dowloader', 'url_category': 'Streaming Media & Downloads'},
    'VideoFrame': {'type': '', 'name': 'VideoFrame', 'url_category': 'Streaming Media & Downloads'},
    'VideoSlurp': {'type': '', 'name': 'VideoSlurp', 'url_category': 'Streaming Media & Downloads'},
    'videosurf': {'type': '', 'name': 'videosurf', 'url_category': 'Streaming Media & Downloads'},
    'RTP Protocol-video': {'type': '', 'name': 'RTP Protocol-video', 'category': 'Standard networks'},
    'SpeedBit Video Accelerator': {'type': '', 'name': 'SpeedBit Video Accelerator', 'url_category': 'Streaming Media & Downloads'},
    'ThatsHow-video': {'type': '', 'name': 'ThatsHow-video', 'url_category': 'Streaming Media & Downloads'},
    'Tubi TV-video': {'type': '', 'name': 'Tubi TV-video', 'category': 'Media streaming'},
    'TV-Video': {'type': '', 'name': 'TV-Video', 'url_category': 'Streaming Media & Downloads'},
    'tv.com-video': {'type': '', 'name': 'tv.com-video', 'url_category': 'Streaming Media & Downloads'},
    'NEXTmedia-video': {'type': '', 'name': 'NEXTmedia-video', 'url_category': 'Streaming Media & Downloads'},
    'omNovia-video chat': {'type': '', 'name': 'omNovia-video chat', 'category': 'Conferencing'},
    'Pullbbang-video': {'type': '', 'name': 'Pullbbang-video', 'url_category': 'Streaming Media & Downloads'},
    'QQ IM-audio and video call': {'type': '', 'name': 'QQ IM-audio and video call', 'category': 'Instant messaging'},
    'HKTV-video': {'type': '', 'name': 'HKTV-video', 'url_category': 'Streaming Media & Downloads'},
    'HTTP Video': {'type': '', 'name': 'HTTP Video', 'category': 'Media streaming'},
    'iMBC-video': {'type': '', 'name': 'iMBC-video', 'category': 'Media streaming'},
    'Integrated Network Enhanced Telemetry (iNetX) - Video': {'type': '', 'name': 'Integrated Network Enhanced Telemetry (iNetX) - Video', 'category': 'SCADA'},
    'InterCall Unified Meeting - video chat': {'type': '', 'name': 'InterCall Unified Meeting', 'category': 'Conferencing'},
    'iSpQ VideoChat': {'type': '', 'name': 'iSpQ VideoChat', 'category': 'Instant messaging'},
    'Libero Video': {'type': '', 'name': 'Libero Video', 'category': 'Media streaming'},
    'LiveLeak-video': {'type': '', 'name': 'LiveLeak-video', 'category': 'Media streaming'},
    'Flash Video Downloader': {'type': '', 'name': 'Flash Video Downloader', 'url_category': 'Streaming Media & Downloads'},
    'Flixya-video access': {'type': '', 'name': 'Flixya-video access', 'url_category': 'Streaming Media & Downloads'},
    'Glide - Video Texting': {'type': '', 'name': 'Glide - Video Texting', 'category': 'Instant messaging'},
    'Google Video': {'type': '', 'name': 'Google Video', 'url_category': 'Search Engines & Portals'},
    'Google Video-enterprise': {'type': '', 'name': 'Google Video', 'url_category': 'Streaming Media & Downloads'},
    'Graboid Video': {'type': '', 'name': 'Graboid Video', 'category': 'Media streaming'},
    'Cellcom TV-video streaming': {'type': '', 'name': 'Cellcom TV-video streaming', 'url_category': 'Streaming Media & Downloads'},
    'Cisco Webex Teams-video': {'type': '', 'name': 'Cisco Webex Teams-video', 'category': 'Conferencing'},
    'cyph-video': {'type': '', 'name': 'Cisco Webex Teams-video', 'category': 'VOIP'},
    'Dwyco Video Conferencing': {'type': '', 'name': 'Dwyco Video Conferencing', 'category': 'Conferencing'},
    'Ebaumsworld-video': {'type': '', 'name': 'Ebaumsworld-video', 'url_category': 'Streaming Media & Downloads'},
    'El Universal-video': {'type': '', 'name': 'El Universal-video', 'url_category': 'Streaming Media & Downloads'},
    'Air Video': {'type': '', 'name': 'Air Video', 'category': 'Media streaming'},
    'AliWangWang-audio-video': {'type': '', 'name': 'AliWangWang-audio-video', 'category': 'VOIP'},
    'Amazon Prime Video': {'type': '', 'name': 'Amazon Prime Video', 'category': 'Media streaming'},
    'Blip.tv-video': {'type': '', 'name': 'Blip.tv-video', 'url_category': 'Streaming Media & Downloads'},
    '115-video': {'type': '', 'name': '115-video', 'category': 'Media streaming'},
    '121 Video Calling': {'type': '', 'name': '121 Video Calling', 'category': 'VOIP'},
    'Voxwire-video chat': {'type': '', 'name': 'Voxwire-video chat', 'category': 'Conferencing'},
}
