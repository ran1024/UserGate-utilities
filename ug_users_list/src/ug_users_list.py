#!/usr/bin/python3
#
# Copyright @ 2021-2023 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <ran1024@yandex.ru>
# License: GPLv3
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, contact the site <https://www.gnu.org/licenses/>.
#
#------------------------------------------------------------------------------------------------
# Программа формирует файл со списками локальных групп с пользователями в каждой
# группе и списком локальных пользователей. Для каждого пользователя выводися его
# статус, логин, группы, статические IP/MAC/Vlan, дата создания и дата окончания действия.
# Программа работает в версии 5 и версии 6.
# Файл отчёта создаётся в директории программы.
#
# Версия 2.0
#------------------------------------------------------------------------------------------------

import stdiomask
import xmlrpc.client as rpc
from datetime import datetime as dt
from prettytable import PrettyTable


character_map = {
    ord('\n'): None,
    ord('\t'): '_',
    ord('\r'): None,
    ord('@'): '_',
    ord(' '): '_',
    ord('.'): '_'
}

def get_node_status(server):
    """Получить статус устройства"""
    result = server.v2.core.node.status()
    return result.get('status')

def logout(server, auth_token):
    try:
        if server is not None and auth_token is not None:
            server.v2.core.logout(auth_token)
    except rpc.Fault as err:
        if err.faultCode == 104:
            print('Сессия завершилась по таймауту.')

def get_groups_list(server, auth_token, groups, version):
    """Получить список групп и список пользователей в каждой группе"""
    array = []
    result = server.v3.accounts.groups.list(auth_token, 0, 1000, {})
    if result['total']:
        for group in result['items']:
            groups[group['guid']] = group['name']
            descr = group['description'] if group['description'] else '---'
            array.append(f"{group['name']}\n\tОписание: {descr}\n\tГруппа для гостевых пользователей: {group['is_transient']}\n")
            users = get_user_in_group(server, auth_token, group['guid'], version)
            if users:
                array.append(users)
    else:
        array.append('Локальные группы отсутствуют.')
    return result['total'], array

def get_local_users(server, auth_token, groups):
    """Получить список локальных пользователей с их параметрами"""
    array = []
    empty_row = ['', '', '', '', '', '', '']
    x = PrettyTable()
    x.field_names = ['Имя', 'Логин', 'Статус', 'Группы', 'Статика', 'Дата создания', 'Дата окончания действия']

    result = server.v3.accounts.users.list(auth_token, 0, 1000, {})

    if result['count']:
        for item in result['items']:
            user_groups = []
            if item['creation_date']:
                item['creation_date'] = dt.strptime(item['creation_date'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d")
            if item['expiration_date']:
                item['expiration_date'] = dt.strptime(item['expiration_date'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d")
            else:
                item['expiration_date'] = ''
            static = ', '.join(str(x) for x in item['static_ip_addresses']) if item['static_ip_addresses'] else ''
            for guid in item['groups']:
                user_groups.append(groups[guid])
            enabled = 'enabled' if item['enabled'] else 'disabled'

            x.add_row(empty_row)
            row = [item['name'], item['auth_login'], enabled,
                '\n'.join(y for y in user_groups),
                '\n'.join(f"{y}" for y in item['static_ip_addresses']) if item['static_ip_addresses'] else '',
                item['creation_date'], item['expiration_date'],
            ]
            x.add_row(row)
            x.align = "l"

        array.append(x.get_string())
    else:
        array.append('Локальные пользователи отсутствуют.')

    return result['count'], array

def get_user_in_group(server, auth_token, group_id, version):
    """Получить список пользователей в конкретной группе"""
    users = '\tПользователи:\n'
    result = server.v3.accounts.group.users.list(auth_token, group_id, 0, 1000, {})
    if result['count']:
        if version.startswith('6'):
            for item in result['items']:
                users += f"\t\t{item[1]}\n"
        else:
            for item in result['items']:
                users += f"\t\t{item['name']}\n"
    return users

def main():
    server_ip = input("Введите IP-адрес узла: ")
    login = input("Введите логин: ")
    password = stdiomask.getpass("Введите пароль: ")
    url = f'http://{server_ip}:4040/rpc'
    auth_token = None
    file_name = f'config_{server_ip.translate(character_map)}.txt'
    groups = {}
    list_config = open(file_name, 'w')
    with rpc.ServerProxy(url, verbose=False) as server:
        try:
            if get_node_status(server) == 'work':
                result = server.v2.core.login(login, password, {'origin': 'dev-script'})
                auth_token = result.get('auth_token')
                node_name =  result.get('node')
                version = result.get('version')
            title = f'\nКонфигурация узла {node_name}, IP: {server_ip}, Версия: {version}\n'
            list_config.write("-"*(len(title)-1))
            list_config.write(title)
            list_config.write("-"*(len(title)-1))
            total, list_groups = get_groups_list(server, auth_token, groups, version)
            list_config.write('\n')
            list_config.write(f'\nЛокальные группы ({total}):\n')
            for string in list_groups:
                list_config.write(string)
            total, users = get_local_users(server, auth_token, groups)
            list_config.write('\n')
            list_config.write(f'\nЛокальные пользователи ({total}):\n')
            for string in users:
                list_config.write(string)
        except OSError as err:
            print(f'Ошибка: {err} (Node: {server_ip}).')
        except rpc.ProtocolError as err:
            print(f'Ошибка: [{err.errcode}] {err.errmsg} (Node: {server_ip}).')
        except rpc.Fault as err:
            print(f'Ошибка: {err.faultString} (Node: {server_ip}).')
        else:
            print("Отчёт сформирован в файле", f'config_{server_ip.translate(character_map)}.txt')
        finally:
            logout(server, auth_token)
            list_config.close()

if __name__ == '__main__':
    main()
