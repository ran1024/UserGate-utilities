#!/usr/bin/python3
# Версия 0.4
# программа предназначена для переноса конфигурации с CheckPoint на NGFW версии 6.
#

import os, sys, json
import stdiomask
import ipaddress
from services import ServicePorts, character_map, dict_risk, url_category, l7categories, l7apps, none_apps
from utm import UTM


def convert_file():
    """Преобразуем все файлы конфигурации CheckPoint в читабельный вид."""
    data = ""
    if os.path.isdir('data_cp'):
        for file_name in os.listdir('data_cp'):
            if file_name.endswith('.json'):
                print(file_name)
                with open(f"data_cp/{file_name}", "r") as fh:
                    data = json.load(fh)
                pp_file = file_name.replace('.json', '_pp.json', 1)
                with open(f"data_cp/{pp_file}", "w") as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
    else:
        print(f'Не найден каталог с конфигурацией Check Point.')
        return

def convert_services(objects):
    """
    Выгружаем список сервисов в файл data_ug/library/config_services.json для последующей загрузки в NGFW.
    В файле объектов objects.json UID с сервисами переписываются в вид: uid: {'services': 'ИМЯ_СЕРВИСА'}
    для загрузки сервисов в правила.
    """
    services = {}
    print('Экспорт списка сервисов:')

    for key, value in objects.items():
        if value['type'] == 'service-icmp':
            objects[key] = {'services': 'Any ICMP'}
            services[key] = {
                'name': 'Any ICMP',
                'description': 'Any ICMP packet',
                'protocols': [
                    {
                        'proto': 'icmp',
                        'port': '',
                        'source_port': ''
                    }
                ]
            }
        elif value['type'] == 'service-icmp6':
            objects[key] = {'services': 'Any IPV6-ICMP'}
            services[key] = {
                'name': 'Any IPV6-ICMP',
                'description': 'Any IPV6-ICMP packet',
                'protocols': [
                    {
                        'proto': 'ipv6-icmp',
                        'port': '',
                        'source_port': ''
                    }
                ]
            }
        elif value['type'] in ('service-tcp', 'service-udp'):
            _, proto = value['type'].split('-')
            objects[key] = ServicePorts.get_dict_by_port(proto, value['port'], value['name'])
            service_name = ServicePorts.get_name_by_port(proto, value['port'], value['name'])

            services[key] = {
                'name': service_name,
                'description': value['comments'],
                'protocols': [
                    {
                        'proto': proto,
                        'port': value.get('port', ""),
                        'source_port': ""
                    }
                ]
            }

    for key, value in objects.items():
        try:
            if value['type'] == 'service-group':
                members = [services[uid]['protocols'][0] for uid in value['members']]
                services[key] = {
                    'name': 'Any ICMP' if value['name'] == 'icmp-requests' else value['name'],
                    'description': value['comments'],
                    'protocols': list(map(dict, set(tuple(d.items()) for d in members)))
                }
                objects[key] = {'services': services[key]['name']}
        except KeyError:
            pass

    if not os.path.isdir('data_ug/library'):
        os.makedirs('data_ug/library')

    array = list(services.values())
    with open("data_ug/library/config_services.json", "w") as fh:
        json.dump(array, fh, indent=4, ensure_ascii=False)
    print(f'\tСписок сервисов выгружен в файл "data_ug/library/config_services.json".')

def convert_ip_lists(objects):
    """
    Выгружаем список IP-адресов в файл data_ug/library/ip_list.json для последующей загрузки в NGFW.
    В файле objects.json типы host, address-range, network, group переписываются в вид:
    uid: {'ip-list': 'ИМЯ_IP_ЛИСТА'}.
    """
    ip_list = {}
    print('Экспорт списка IP-адресов:')

    for key, value in objects.items():
        try:
            if value['type'] == 'host':
                if 'ipv6-address' in value.keys():
                    print(f"\t\033[36mОбъект host: '{value['name']}' содержит IPV6 адрес. Данный тип адреса не поддерживается.\033[0m")
                objects[key] = {'ip-list': value['name']}
                ip_list[key] = {
                    'name': value['name'],
                    'description': value['comments'],
                    'type': "network",
                    'url': '',
                    'attributes': {
                        "threat_level": 3
                    },
                    'content': [
                        {
                            'value': value['ipv4-address']
                        },
                    ]
                }
            elif value['type'] == 'address-range':
                objects[key] = {'ip-list': value['name']}
                ip_list[key] = {
                    'name': value['name'],
                    'description': value['comments'],
                    'type': "network",
                    'url': '',
                    'attributes': {
                        "threat_level": 3
                    },
                    'content': [
                        {
                            'value': f"{value['ipv4-address-first']}-{value['ipv4-address-last']}"
                        },
                    ]
                }
            elif value['type'] == 'network':
                objects[key] = {'ip-list': value['name']}
                ip_list[key] = {
                    'name': value['name'],
                    'description': value['comments'],
                    'type': "network",
                    'url': '',
                    'attributes': {
                        "threat_level": 3
                    },
                    'content': [
                        {
                            'value': f"{value['subnet4']}/{value['mask-length4']}"
                        },
                    ]
                }
        except KeyError:
            pass

    for key, value in objects.items():
        try:
            if value['type'] == 'group':
                objects[key] = {'ip-list': value['name']}
                members = []
                for uid in value['members']:
                    members.extend(ip_list[uid]['content'])
                ip_list[key] = {
                    'name': value['name'],
                    'description': value['comments'],
                    'type': "network",
                    'url': '',
                    'attributes': {
                        "threat_level": 3
                    },
                    'content': members
                }
        except KeyError:
            pass

    array = list(ip_list.values())
    with open("data_ug/library/ip_list.json", "w") as fh:
        json.dump(array, fh, indent=4, ensure_ascii=False)
    print(f'\tСписок IP-адресов выгружен в файл "data_ug/library/ip_list.json".')

def convert_url_lists(objects):
    """
    Выгружаем списки URL в каталог data_ug/library/url для последующей загрузки в NGFW.
    В файле objects.json в типе application-site url-list переписывается в вид:
    uid: {'url-list': 'ИМЯ_URL_ЛИСТА'}.
    """
    url_list = {}
    trans_table = str.maketrans(character_map)
    print('Экспорт списков URL:')

    if os.path.isdir('data_ug/library/url'):
        for file_name in os.listdir('data_ug/library/url'):
            os.remove(f'data_ug/library/url/{file_name}')
    else:
        os.makedirs('data_ug/library/url')

    for key, value in objects.items():
        try:
            if value['type'] == 'application-site':
                if 'url-list' in value:
                    url_risk = value['risk'].translate(trans_table)
                    url_list_name = value['name'].translate(trans_table)
                    objects[key] = {'type': 'url-list', 'name': url_list_name}
                    url_list[key] = {
                        'name': url_list_name,
                        'description': value['comments'],
                        'type': "url",
                        'url': '',
                        'attributes': {
                            "threat_level": dict_risk[url_risk]
                        },
                        'content': [{'value': url} for url in value['url-list']]
                    }
                    with open(f"data_ug/library/url/{url_list_name}.json", "w") as fh:
                        json.dump(url_list[key], fh, indent=4, ensure_ascii=False)
                    print(f'\tСписок URL "{value["name"]}" выгружен в файл "data_ug/library/url/{url_list_name}.json"')
        except KeyError:
            pass

def convert_application_site(objects):
    """
    В файле objects.json в типе application-site переписывается в вид:
    uid: {'type': 'l7apps', 'name': ['app_name']}.
    """
    print('Конвертация application-site в Приложения и Категории URL:')

    for key, value in objects.items():
        try:
            if value['type'] == 'application-site-category':
                if value['name'] in l7categories:
                    objects[key] = l7categories[value['name']]
                elif value['name'] in l7apps:
                    objects[key] = l7apps[value['name']]
                elif value['name'] in url_category:
                    objects[key] = url_category[value['name']]
                elif value['name'] in none_apps:
                    print(f'\tКатегория "{value["name"]}" не будет перенесена так как не существует в UG NGFW.')
                    objects[key] = none_apps[value['name']]
                else:
                    print(f'\tНе найдена application-site-category: "{value["name"]}", uid: {key}')
            elif value['type'] == 'application-site':
                if value['name'] in l7categories:
                    objects[key] = l7categories[value['name']]
                elif value['name'] in l7apps:
                    objects[key] = l7apps[value['name']]
                elif value['name'] in url_category:
                    objects[key] = url_category[value['name']]
                elif value['name'] in none_apps:
                    print(f'\tПриложение "{value["name"]}" не будет перенесено так как не существует в UG NGFW.')
                    objects[key] = none_apps[value['name']]
                else:
                    print(f'\tНе найден application-site: "{value["name"]}", uid: {key}')
        except KeyError:
            pass

def convert_application_group(objects):
    """
    В файле objects.json в типе application-site-group переписывается в вид:
    uid: {'url-list': 'ИМЯ_URL_ЛИСТА'}.
    """
    print('Конвертация application-site-group:')

    if not os.path.isdir('data_ug/library'):
        os.makedirs('data_ug/library')

    app_groups = []
    url_groups = []
    for key, value in objects.items():
        try:
            if value['type'] == 'application-site-group':
                app = set()
                ro_group = set()
                url_category = set()
                url_list = set()
                value.pop('uid', None)
                value.pop('comments', None)
                value['type'] = 'apps_group'
                for item in value['members']:
                    if objects[item]['type'] == 'l7apps':
                        app.update(set(objects[item]['name']))
                    elif objects[item]['type'] == 'l7_category':
                        ro_group.add(objects[item]['name'])
                    elif objects[item]['type'] == 'url_category':
                        url_category.add(objects[item]['name'])
                    elif objects[item]['type'] == 'url-list':
                        url_list.add(objects[item]['name'])
                value.pop('members', None)

                value['apps'] = [['ro_group', x] for x in ro_group]
                if app:
                    app_groups.append(
                        {
                            'name': value['name'],
                            'description': '',
                            'type': 'applicationgroup',
                            'attributes': [],
                            'content': [{'value': x} for x in app]
                        }
                    )
                    value['apps'].append(['group', value['name']])
                value['url_categories'] = []
                if url_category:
                    url_groups.append(
                        {
                            'name': value['name'],
                            'description': '',
                            'type': 'urlcategorygroup',
                            'url': '',
                            'attributes': [],
                            'content': [{'name': x} for x in url_category]
                        }
                    )
                    value['url_categories'].append(['category_id', value['name']])
                value['urls'] = [x for x in url_list]
        except KeyError:
            pass

    if app_groups:
        with open("data_ug/library/application_groups.json", "w") as fh:
            json.dump(app_groups, fh, indent=4, ensure_ascii=False)
        print(f'\tГруппы приложений выгружены в файл "data_ug/library/application_groups.json".')
    if url_groups:
        with open("data_ug/library/url_category_groups.json", "w") as fh:
            json.dump(url_groups, fh, indent=4, ensure_ascii=False)
        print(f'\tГруппы URL категорий выгружены в файл "data_ug/library/url_category_groups.json".')

def convert_access_role(objects):
    """
    В файле объектов objects.json UID с access-role переписываются в вид:
    uid = {
        'networks': [{'ip-list': 'ИМЯ_IP_ЛИСТА'}],
        'users': [
            [ 'user', 'доменое_имя_юзера' ]
        ]
    }
    """
    print('Конвертация access role...', end = ' - ')

    for key, value in objects.items():
        try:
            if value['type'] == 'access-role':
                tmp_role = {
                    'type': value['type'],
                    'name': value['name'],
                }
                if value['networks'] != 'any':
                    tmp_role['networks'] = [{'ip-list': x['name']} for x in value['networks']]
                users = []
                if isinstance(value['users'], list):
                    for item in value['users']:
                        tmp = [y.split(' = ') for y in item['tooltiptext'].split('\n')]
                        name = f'{tmp[0][1][:-4].lower()}\\{tmp[1][1]}'
                        if item['type'] == 'CpmiAdGroup':
                            users.append(['group', name])
                        else:
                            users.append(['user', name])
                elif value['users'] == "all identified":
                    users.append(['special', 'known_user'])
                tmp_role['users'] = users
                objects[key] = tmp_role
        except KeyError:
            pass
    print('\033[32mOk!\033[0m')

def convert_other(objects):
    """
    В файле объектов objects.json конвертятся UID с type 'RulebaseAction', 'CpmiAnyObject'
    """
    print('Конвертация сопутствующих объектов...', end = ' - ')

    for key, value in objects.items():
        try:
            if value['type'] == 'RulebaseAction':
                objects[key] = value['name'].lower()
            elif value['type'] == 'CpmiAnyObject':
                objects[key] = 'Any'
            elif value['type'] == 'service-other':
                objects[key] = 'Any'
        except KeyError:
            pass
    print('\033[32mOk!\033[0m')

def convert_access_rule(cp, objects):
    """
    """
    print('Конвертация access rule...', end = ' - ')
    file_name = "data_cp/Firewall-Management server_pp.json"
    if cp == 'Main_4600':
        file_name = f"data_cp/{cp} Firewall-Management server_pp.json"

    with open(f"{file_name}", "r") as fh:
        data = json.load(fh)

    for item in data:
        if item['type'] == 'access-rule':
            item['source'] = [objects[uid] for uid in item['source'] if objects[uid] != 'Any']
            item['destination'] = [objects[uid] for uid in item['destination'] if objects[uid] != 'Any']
            item['content'] = [objects[uid] for uid in item['content'] if objects[uid] != 'Any']
            item['vpn'] = [objects[uid] for uid in item['vpn']]# if objects[uid] != 'Any']
#            for uid in item['service']:
#                if objects[uid]['services'] == 'UserCheck':
#                    print(objects[uid])
            item['position'] = item['rule-number']
            item['services'] = list({objects[uid]['services'] for uid in item['service'] if objects[uid] != 'Any'})
            item['services_negate'] = item['service-negate']
            item['log'] = True if True in item['track'].values() else False
            item['log_session_start'] = item['log']
            item['action'] = objects[item['action']]
            item['description'] = item['comments']
            item.pop('meta-info', None)
            item.pop('domain', None)
            item.pop('uid', None)
            item.pop('custom-fields', None)
            item.pop('install-on', None)
            item.pop('service', None)
            item.pop('service-negate', None)
            item.pop('track', None)
            item.pop('action-settings', None)
            item.pop('comments', None)
            item.pop('rule-number', None)

    with open("4600_firewall_rab.json", "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)
    print('\033[32mOk!\033[0m')

def convert_interfaces():
    """
    Выгружаем конфигурацию интерфейсов в файл data_ug/network/config_interfaces.json для последующей загрузки в NGFW.
    """
    print('Экспорт интерфейсов')
    if not os.path.isdir('data_ug/network'):
        os.makedirs('data_ug/network')

    config = []
    try:
        with open("data_cp/config_cp.txt", "r") as fh:
            for line in fh:
                x = line.strip('\n').split(' ')
                if x[0] in ('set', 'add'):
                    config.append(x)
    except FileNotFoundError:
        print(f'\t\033[31m\tНе найден файл "data_cp/config_cp.txt" с конфигурацией Check Point!\033[0;0m')
        sys.exit(1)

    cp_conf = {}
    vlans = []
    mgmt_iface = ''
    net_untr = ''
    for item in config:
        key = item.pop(0)
        l = len(item)
        if item[0] == 'management':
            mgmt_iface = item[2]
        elif item[0] == 'interface':
            if key == 'set':
                try:
                    cp_conf[item[1]].update({item[i]: item[i+1] if i+1 < l else '' for i in range(2,l,2)})
                except KeyError:
                    cp_conf[item[1]] = {item[i]: item[i+1] if i+1 < l else '' for i in range(2,l,2)}
            elif key  == 'add':
                if item[2] == 'vlan':
                    vlans.append(item[3])
        elif item[0] == 'static-route':
            if item[1] == 'default':
                net_untr = item[5].rpartition('.')[0]

    array = []
    for key, value in cp_conf.items():
        ifname = key.partition('.')
        name = ifname[0].replace('eth', 'port')
        if 'ipv4-address' in value:
            zone = 'Untrusted' if value['ipv4-address'].startswith(net_untr) else 'Trusted'
        else:
            zone = 0
        if ifname[2] and ifname[2] in vlans:
            tmp = {
                'id': f'{name}.{ifname[2]}',
                'zone_id': zone,
                'master': False,
                'description': value['comments'] if 'comments' in value else '',
                'netflow_profile': 'undefined',
                'tap': False,
                'name': f'{name}.{ifname[2]}',
                'enabled': False,
                'kind': 'vlan',
                'mtu': int(value['mtu']) if 'mtu' in value else 1500,
                'ipv4': [f"{value['ipv4-address']}/{value['mask-length']}"] if 'ipv4-address' in value else [],
                'vlan_id': int(ifname[2]),
                'link': name,
                'mode': 'static' if 'ipv4-address' in value else 'manual'
            }
            array.append(tmp)
        else:
            if key == 'lo':
                continue
            if key == mgmt_iface:
                name = 'port0'
                zone = 'Management'
            tmp = {
                'id': name,
                'zone_id': zone,
                'master': False,
                'description': value['comments'] if 'comments' in value else '',
                'netflow_profile': 'undefined',
                'tap': False,
                'name': name,
                'enabled': True,
                'kind': 'adapter',
                'mtu': int(value['mtu']) if 'mtu' in value else 1500,
                'ipv4': [f"{value['ipv4-address']}/{value['mask-length']}"] if 'ipv4-address' in value else [],
                'mode': 'static' if 'ipv4-address' in value else 'manual'
            }
            array.append(tmp)

    with open("data_ug/network/config_interfaces.json", "w") as fh:
        json.dump(array, fh, indent=4, ensure_ascii=False)
    print(f'\tКонфигурация интерфейсов выгружена в файл "data_ug/network/config_interfaces.json".')
            
def convert_routes():
    """
    Выгружаем список маршрутов в файл data_ug/network/config_routers.json для последующей загрузки в NGFW.
    """
    print('Экспорт списка маршрутов: ')
    if not os.path.isdir('data_ug/network'):
        os.makedirs('data_ug/network')
    try:
        with open("data_ug/network/config_interfaces.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31m\tНе найден файл "data_ug/network/config_interfaces.json"!\033[0;0m')
        sys.exit(1)

    net_list = {ipaddress.ip_interface(x['ipv4'][0]).network: x['name'] for x in data if x['ipv4']}

    config = []
    try:
        with open("data_cp/config_cp.txt", "r") as fh:
            for line in fh:
                x = line.strip('\n').split(' ')
                if x[0] in ('set', 'add'):
                    config.append(x)
    except FileNotFoundError:
        print(f'\t\033[31m\tНе найден файл "data_cp/config_cp.txt" с конфигурацией Check Point!\033[0;0m')
        sys.exit(1)

    vrfs = [{
        'name': 'default',
        'routes': [],
        'ospf': {},
        'bgp': {},
        'rip': {},
        'pimsm': {}
    }]
    for item in config:
        item.pop(0)
        l = len(item)
        if item[0] == 'static-route':
            if item[1] == 'default':
                continue
            ifname = 'undefined'
            for net in net_list:
                if ipaddress.ip_address(item[5]) in net:
                    ifname = net_list[net]
            route = {
                'name': item[1],
                'description': '',
                'dest': item[1],
                'metric': 0,
                'enabled': True if item[6] == 'on' else False,
                'gateway': item[5],
                'ifname': ifname
            }
            vrfs[0]['routes'].append(route)

    with open("data_ug/network/config_routers.json", "w") as fh:
        json.dump(vrfs, fh, indent=4, ensure_ascii=False)
    print(f'\tСписок маршрутов выгружен в файл "data_ug/network/config_routers.json".')

#    with open("data_cp/config_cp.json", "w") as fh:
#        json.dump(cp_conf, fh, indent=4, ensure_ascii=False)

##### Импорт ######
def import_services(utm):
    """Импортировать список сервисов раздела библиотеки"""
    print('Импорт списка сервисов раздела "Библиотеки":')
    services_list = utm.get_services_list()
    try:
        with open("data_ug/library/config_services.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Сервисы" не импортирован!\n\tНе найден файл "data_ug/library/config_services.json" с сохранённой конфигурацией!\033[0;0m')
        return

    for item in data:
        if item['name'] not in services_list:
            err, result = utm.add_service(item)
            if err != 0:
                print(result)
            else:
                services_list[item['name']] = result
                print(f'\tСервис "{item["name"]}" добавлен.')
        else:
            print(f'\tСервис "{item["name"]}" уже существует.')

def import_ip_lists(utm):
    """Импортировать списки IP адресов"""
    print('Импорт списков IP-адресов раздела "Библиотеки":')
    list_ip = utm.get_nlists_list('network')
    try:
        with open("data_ug/library/ip_list.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "IP-адреса" не импортирован!\n\tНе найден файл "data_ug/library/ip_list.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет списков IP-адресов для импорта.")
        return

    for item in data:
        content = item.pop('content')
        err, result = utm.add_nlist(item)
        if err == 1:
            print(result, end= ' - ')
            list_id = list_ip[item['name']]
            err1, result1 = utm.update_nlist(list_id, item)
            if err1 != 0:
                print("\n", f"\033[31m{result1}\033[0m")
            else:
                print("\033[32mUpdated!\033[0;0m")
        elif err == 2:
             print(f"\033[31m{result}\033[0m")
             continue
        else:
            list_ip[item['name']] = result
            print(f'\tДобавлен список IP-адресов: "{item["name"]}".')
        if content:
            err2, result2 = utm.add_nlist_items(list_ip[item['name']], content)
            if err2 != 0:
                print(f"\033[31m{result2}\033[0m")
            else:
                print(f'\tСодержимое списка "{item["name"]}" обновлено. Added {result2} record.')
        else:
            print(f'\tСписок "{item["name"]}" пуст.')

def import_url_lists(utm):
    """Импортировать списки URL на UTM"""
    print('Импорт списков URL раздела "Библиотеки":')
    url_list = utm.get_nlists_list('url')
    
    if os.path.isdir('data_ug/library/url'):
        files_list = os.listdir('data_ug/library/url')
        if files_list:
            for file_name in files_list:
                try:
                    with open(f"data_ug/library/url/{file_name}", "r") as fh:
                        data = json.load(fh)
                except FileNotFoundError as err:
                    print(f'\t\033[31mСписок "Списки URL" не импортирован!\n\tНе найден файл "data_ug/library/url/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                    return

                content = data.pop('content')
                err, result = utm.add_nlist(data)
                if err == 1:
                    print(result, end= ' - ')
                    list_id = url_list[data['name']]
                    err1, result1 = utm.update_nlist(list_id, data)
                    if err1 == 1:
                        print("\n", f'\033[31m{result1}\033[0m')
                    elif err1 == 2:
                        print("\n", f'\033[31m{result1}\033[0m')
                        print(f'\033[33mСписок URL "{data["name"]}" - Not updated!\033[0m')
                        continue
                    else:
                        print("\033[32mUpdated!\033[0;0m")
                elif err == 2:
                    print(f'\033[31m{result}\033[0m')
                    continue
                else:
                    url_list[data['name']] = result
                    print(f'\tДобавлен список URL: "{data["name"]}".')
                if content:
                    err2, result2 = utm.add_nlist_items(url_list[data['name']], content)
                    if err2 != 0:
                        print(f"\033[31m{result2}\033[0m")
                    else:
                        print(f'\tСодержимое списка "{data["name"]}" обновлено. Added {result2} record.')
                else:
                    print(f'\tСписок "{data["name"]}" пуст.')
        else:
            print("\033[33m\tНет списков URL для импорта.\033[0m")
    else:
        print("\033[33m\tНет списков URL для импорта.\033[0m")

def import_application_groups(utm):
    """Импортировать список "Приложения" на UTM"""
    print('Импорт списка "Приложения" раздела "Библиотеки":')
    try:
        with open("data_ug/library/application_groups.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print('\t\033[31mСписок "Приложения" не импортирован!\n\tНе найден файл "data_ug/library/application_groups.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет групп приложений для импорта.")
        return

    l7apps = utm.get_l7_apps()

    for item in data:
        content = item.pop('content')
        err, result = utm.add_nlist(item)
        if err == 1:
            print(result, "\033[32mOk!\033[0;0m")
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\tГруппа приложений "{item["name"]}" добавлена.')
            if content:
                content = [{'value': l7apps[x['value']]} for x in content]
                try:
                    err2, result2 = utm.add_nlist_items(result, content)
                    if err2 != 0:
                        print(f'\033[31m{result2}\033[0m')
                    else:
                        print(f'\t\tСодержимое группы приложений: "{item["name"]}" добавлено.')
                except Exception as err:
                    print(f'\t\t\033[31mСодержимое группы приложений "{item["name"]}" не добавлено.\n\t\t{err}\033[0m')

def import_categories_groups(utm):
    """Импортировать список "Категории URL" на UTM"""
    print('Импорт списка "Категории URL" раздела "Библиотеки":')
    try:
        with open("data_ug/library/url_category_groups.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print('\t\033[31mСписок "Категории URL" не импортирован!\n\tНе найден файл "data_ug/library/url_category_groups.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет групп URL категорий для импорта.")
        return

    url_category = utm.get_url_category()

    for item in data:
        content = item.pop('content')
        err, result = utm.add_nlist(item)
        if err == 1:
            print(result, "\033[32mOk!\033[0;0m")
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\tГруппа URL категорий "{item["name"]}" добавлена.')
            if content:
                content = [{'category_id': url_category[x['name']]} for x in content]
                try:
                    err2, result2 = utm.add_nlist_items(result, content)
                    if err2 != 0:
                        print(f'\033[31m{result2}\033[0m')
                    else:
                        print(f'\t\tСодержимое группы URL категорий "{item["name"]}" добавлено.')
                except Exception as err:
                    print(f'\t\t\033[31mСодержимое группы URL категорий "{item["name"]}" не будет добавлено.\n\t\t{err}\033[0m')

def import_interfaces(utm):
    """Импортировать интерфесы"""
    print('Импорт списка "Интерфейсы" раздела "Сеть":')
    try:
        with open("data_ug/network/config_interfaces.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Интерфейсы" не импортированы!\n\tНе найден файл "data/network/config_interfaces.json" с сохранённой конфигурацией!\033[0;0m')
        return

    management_port = ''
    slave_interfaces = set()
    interfaces_list = {}
    vpn_ips = set()

    zones = utm.get_zones_list()

    result = utm.get_interfaces_list()
    for item in result:
        interfaces_list[item['name']] = item['kind']
        if item['master']:
            slave_interfaces.add(item['name'])
        for ip in item['ipv4']:
            if ip.startswith(utm.server_ip):
                management_port = item["name"]
                print(f'\tИнтерфейс "{item["name"]}" [{utm.server_ip}] используется для текущей сессии - \033[32mNot updated!\033[0;0m')
        if item['kind'] == 'vpn':
            vpn_ips.update({x[:x.rfind('.')] for x in item['ipv4']})

    # Update сетевых адаптеров
    for item in data:
        if item['zone_id']:
            try:
                item['zone_id'] = zones[item['zone_id']]
            except KeyError as err:
                print(f'\t\033[33mЗона {err} для интерфейса "{item["name"]}" не найдена.\n\t\Создайте зону {err}.\033[0m')
                item['zone_id'] = 0

        if item['kind'] == 'adapter' and item['name'] != management_port:
            if item['name'] in interfaces_list:
                if item['name'] in slave_interfaces:
                    print(f'\tСетевой адаптер "{item["name"]}" не обновлён так как является slave интерфейсом!')
                else:
                    print(f'\tПрименение настроек для сетевого адаптера "{item["name"]}"', end= ' - ')
                    utm.update_interface(item['name'], item)
            else:
                print(f'\t\033[33mСетевой адаптер "{item["name"]}" не существует!\033[0m')

    # Импорт интерфейсов VLAN
    for item in data:
        if 'kind' in item and item['kind'] == 'vlan':
            if item['link'] not in slave_interfaces:
                try:
                    if interfaces_list[item['link']] in ('bridge', 'bond', 'adapter'):
                        if item['name'] in interfaces_list:
                            print(f'\tИнтерфейс "{item["name"]}" уже существует', end= ' - ')
                            utm.update_interface(item['name'], item)
                        else:
                            item.pop('kind')
                            err, result = utm.add_interface_vlan(item)
                            if err == 2:
                                print(f'\033[33m\tИнтерфейс "{item["name"]}" не добавлен!\033[0m')
                                print(f"\033[31m{result}\033[0m")
                            else:
                                interfaces_list[item['name']] = 'vlan'
                                print(f'\tИнтерфейс "{item["name"]}" добавлен.')
                    else:
                        print(f'\033[33m\tИнтерфейс "{item["name"]}" пропущен, так как ссылается на интерфейс "{item["link"]}" с недопустимым типом!\033[0m')
                except KeyError:
                    print(f'\033[33m\tИнтерфейс "{item["name"]}" пропущен, так как ссылается на несуществующий интерфейс "{item["link"]}"!\033[0m')
            else:
                print(f'\033[33m\tИнтерфейс "{item["name"]}" пропущен, так как ссылается на slave-порт принадлежащий другому интерфейсу!\033[0m')

def import_virt_routes(utm):
    """Импортировать список виртуальных маршрутизаторов"""
    print(f'Импорт списка "Виртуальные маршрутизаторы" раздела "Сеть":')
    try:
        with open("data_ug/network/config_routers.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mВиртуальные маршрутизаторы не импортированы!\n\tНе найден файл "data_ug/network/config_routers.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print('\tНет данных для импорта. Файл "data_ug/network/config_routers.json" пуст.')
        return

    virt_routers = {x['name']: x['id'] for x in utm.get_routers_list()}

    for item in data:
        if item['name'] in virt_routers:
            err, result = utm.update_routers_rule(virt_routers[item['name']], item)
            if err == 2:
                print(f'\033[31m{result}\033[0m')
            else:
                print(f'\tВиртуальный маршрутизатор "{item["name"]}" - \033[32mUpdated!\033[0m')
        else:
            err, result = utm.add_routers_rule(item)
            if err == 2:
                print(f'\033[31m{result}\033[0m')
            else:
                print(f'\tСоздан виртуальный маршрутизатор "{item["name"]}".')

def menu1():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m                  Конвертация конфигурации с CheckPoint на NGFW                 \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма конвертирует конфигурацию CheckPoin в файлы json в каталог 'data_ug' в текущей директории.")
    print("Вы можете изменить содержимое файлов и импортировать данные конфигурационные файлы в NGFW UserGate.\033[0m\n")
    print("1  - Экспорт конфигурации")
    print("2  - Импорт конфигурации")
    print("\033[33m0  - Выход.\033[0m")
    while True:
        try:
            mode = int(input("\nВведите номер нужной операции: "))
            if mode not in [0, 1, 2]:
                print("Вы ввели несуществующую команду.")
            elif mode == 0:
                sys.exit()
            else:
                return mode
        except ValueError:
            print("Ошибка! Введите число.")

def menu2():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m             Импорт конвертированной конфигурации CheckPoint на NGFW            \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ug' в текущей директории на NGFW UserGate.\033[0m\n")

def main():
    print("\033c")
    print("\033[1;36;43mUserGate\033[1;37;43m                   Конвертация конфигурации с CheckPoint на NGFW                 \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма конвертирует конфигурацию CheckPoin в файлы json в каталог 'data_ug' в текущей директории.")
    print("Вы можете изменить содержимое файлов и импортировать данные конфигурационные файлы в NGFW UserGate.\033[0m\n")
    try:
        while True:
            mode = menu1()
            cp = 'Main_4600'
            if mode == 1:
                try:
                    convert_file()

                    with open(f"data_cp/{cp}_objects_pp.json", "r") as fh:
                        data = json.load(fh)
                    objects = {x['uid']: x for x in data}

                    convert_services(objects)
                    convert_ip_lists(objects)
                    convert_url_lists(objects)
                    convert_application_site(objects)
                    convert_application_group(objects)
                    convert_access_role(objects)
                    convert_other(objects)
                    with open("objects.json", "w") as fh:
                        json.dump(objects, fh, indent=4, ensure_ascii=False)
                    convert_interfaces()
                    convert_routes()
#                    convert_access_rule(cp, objects)
                except json.JSONDecodeError as err:
                    print(f'\n\033[31mОшибка парсинга конфигурации: {err}\033[0m')
                    sys.exit(1)
                finally:
                    print("\n\033[32mКонвертация конфигурации CheckPoin в файлы json завершён.\033[0m")
                    while True:
                        input_value = input("\nНажмите пробел для возврата в меню: ")
                        if input_value == " ":
                            break
            else:
                try:
                    menu2()
                    server_ip = input("\033[36mВведите IP-адрес UTM:\033[0m ")
                    login = input("\033[36mВведите логин администратора UTM:\033[0m ")
                    password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
                    print("\n")
                    utm = UTM(server_ip, login, password)
                    utm.connect()
                    import_url_lists(utm)        
                    import_services(utm)
                    import_ip_lists(utm)
                    import_application_groups(utm)
                    import_categories_groups(utm)
                    import_interfaces(utm)
                    import_virt_routes(utm)
                except json.JSONDecodeError as err:
                    print(f'\n\033[31mОшибка парсинга конфигурации: {err}\033[0m')
                    utm.logout()
                    sys.exit(1)
                else:
                    utm.logout()
                    print("\n\033[32mИмпорт конфигурации CheckPoin на UTM завершён.\033[0m")
                    while True:
                        input_value = input("\nНажмите пробел для возврата в меню: ")
                        if input_value == " ":
                            break

    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        sys.exit()
    print('\033[32mИмпорт конфигурации завершён.\033[0m')

if __name__ == '__main__':
    main()
