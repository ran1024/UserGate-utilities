#!/usr/bin/python3
#
# Программа предназначена для переноса конфигурации с UTM версии 5 на версию 6
# или между устройствами 6-ой версии.
#
import os, sys
import stdiomask
import json
from utm import UtmXmlRpc, UtmError


class UTM(UtmXmlRpc):
    def __init__(self, server_ip, login, password):
        super().__init__(server_ip, login, password)
        self._categories = {}           # Список Категорий URL {id: name} для экспорта и {name: id} для импорта
        self.zones = {}                 # Список зон {id: name} для экспорта и {name: id} для импорта
        self.services = {}              # Список сервисов раздела библиотеки {id: name} для экспорта и {name: id} для импорта
        self.shaper = {}                # Список полос пропускания раздела библиотеки {name: id}
        self.list_morph = {}            # Списки морфлолгии раздела библиотеки {name: id}
        self.list_IP = {}               # Списки IP-адресов раздела библиотеки {id: name} для экспорта и {name: id} для импорта
        self.list_useragent = {}        # Списки UserAgent раздела библиотеки  {name: id}
        self.list_mime = {}             # Списки mime групп типов контента раздела библиотеки  {name: id}
        self.list_url = {}              # Списки URL раздела библиотеки {id: name} для экспорта и {name: id} для импорта
        self.list_calendar = {}         # Списки календарей раздела библиотеки {id: name} для экспорта и {name: id} для импорта
        self.list_scada = {}            # Списки профилей АСУ ТП раздела библиотеки  {name: id}
        self.list_templates = {}        # Списки шаблонов страниц раздела библиотеки  {name: id}
        self.list_urlcategorygroup = {} # Список групп категорий URL раздела библиотеки {id: name} для экспорта и {name: id} для импорта
        self.list_applicationgroup = {} # Список групп приложений раздела библиотеки {id: name} для экспорта и {name: id} для импорта
        self.l7_categories = {}         # Список L7 категорий
        self.l7_apps = {}               # Список L7 приложений
        self.list_notifications = {}    # Список профилей оповещения {id: name} для экспорта и {name: id} для импорта
        self.list_netflow = {}          # Список профилей netflow {name: id}
        self.list_ssl_profiles = {}     # Список профилей ssl {name: id}
        self.list_groups = {}           # Список локальных групп {guid: name} для экспорта и {name: guid} для импорта
        self.list_users = {}            # Список локальных пользователей {guid: name} для экспорта и {name: guid} для импорта
        self.profiles_2fa = {}          # Список профилей MFA {name: guid}
        self.auth_servers = {}          # Список серверов авторизации {id: name} для экспорта и {name: id} для импорта
        self.auth_profiles = {}         # Список профилей авторизации {id: name} для экспорта и {name: id} для импорта
        self.captive_profiles = {}      # Список captive-профилей {id: name} для экспорта и {name: id} для импорта
        self.captive_portal_rules = {}  # Список captive-профилей {name: id}
        self.byod_rules = {}            # Список политик BYOD {name: id} для импорта
        self.scenarios_rules = {}       # Список сценариев {id: name} для экспорта и {name: id} для импорта
        self.firewall_rules = {}        # Список правил МЭ {name: id} для импорта
        self.nat_rules = {}             # Список правил NAT {name: id} для импорта
        self.icap_servers = {}          # Список серверов icap {id: name} для экспорта и {name: id} для импорта
        self.reverse_servers = {}       # Список серверов reverse-proxy {id: name} для экспорта и {name: id} для импорта
        self.tcpudp_rules = {}
        self.icap_loadbalancing = {}
        self.reverse_rules = {}
        self.default_url_category = {
            'Parental Control': 'URL_CATEGORY_GROUP_PARENTAL_CONTROL',
            'Productivity': 'URL_CATEGORY_GROUP_PRODUCTIVITY',
            'Safe categories': 'URL_CATEGORY_GROUP_SAFE',
            'Threats': 'URL_CATEGORY_GROUP_THREATS',
            'Recommended for morphology checking': 'URL_CATEGORY_MORPHO_RECOMMENDED',
            'Recommended for virus check': 'URL_CATEGORY_VIRUSCHECK_RECOMMENDED'
        }
        self._connect()

    def init_struct_for_export(self):
        """Заполнить служебные структуры данных"""
        try:
            result = self._server.v2.core.get.categories()
            self._categories = {x['id']: x['name'] for x in result}
            
            result = self._server.v2.core.get.l7categories(self._auth_token, 0, 10000, '')
            self.l7_categories = {x['id']: x['name'] for x in result['items'] if result['count']}
            
            if self.version.startswith('6'):
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, {}, [])
            else:
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, '')
            self.l7_apps = {x['id'] if 'id' in x.keys() else x['app_id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'network', 0, 1000, {})
            self.list_IP = {x['id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'mime', 0, 1000, {})
            self.list_mime = {x['id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'url', 0, 1000, {})
            self.list_url = {x['id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'timerestrictiongroup', 0, 1000, {})
            self.list_calendar = {x['id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'urlcategorygroup', 0, 1000, {})
            self.list_urlcategorygroup = {x['id']: self.default_url_category.get(x['name'], x['name']) for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'applicationgroup', 0, 1000, {})
            self.list_applicationgroup = {x['id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
            self.list_groups = {x['guid']: x['name'] for x in result['items'] if result['total']}

            result = self._server.v1.auth.user.auth.profiles.list(self._auth_token)
            self.auth_profiles = {x['id']: x['name'] for x in result}
            
            result = self._server.v1.notification.profiles.list(self._auth_token)
            self.list_notifications = {x['id']: x['name'] for x in result}

            result = self._server.v1.captiveportal.profiles.list(self._auth_token, 0, 100, '')
            self.captive_profiles = {x['id']: x['name'] for x in result['items']}

        except rpc.Fault as err:
            print(f"\033[31mОшибка ug_convert_config/init_struct_for_export(): [{err.faultCode}] {err.faultString}\033[0m")

        total, data = self.get_users_list()
        self.list_users = {x['guid']: x['name'] for x in data if total}

        total, data = self.get_zones_list()
        self.zones = {x['id']: x['name'] for x in data if total}

        total, data = self.get_services_list()
        self.services = {x['id']: x['name'] for x in data['items'] if total}

        total, data = self.get_templates_list()
        self.list_templates = {x['type'] if x['default'] else x['id']: x['name'] for x in data if total}

        total, data = self.get_2fa_profiles()
        self.profiles_2fa = {x['id']: x['name'] for x in data if total}

        ldap, radius, tacacs, ntlm, saml = self.get_auth_servers()
        self.auth_servers = {x['id']: x['name'] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

        _, data = self.get_scenarios_rules()
        self.scenarios_rules = {x['id']: x['name'] for x in data}

    def init_struct_for_import(self):
        """Заполнить служебные структуры данных"""
        try:
            result = self._server.v2.core.get.categories()
            self._categories = {x['name']: x['id'] for x in result}

            result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, {}, [])
            self.services = {x['name']: x['id'] for x in result['items'] if result['total']}

            result = self._server.v2.nlists.list(self._auth_token, 'morphology', 0, 1000, {})
            self.list_morph = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'network', 0, 1000, {})
            self.list_IP = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'useragent', 0, 1000, {})
            self.list_useragent = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'mime', 0, 1000, {})
            self.list_mime = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'url', 0, 1000, {})
            self.list_url = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'timerestrictiongroup', 0, 1000, {})
            self.list_calendar = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'urlcategorygroup', 0, 1000, {})
            self.list_urlcategorygroup = {self.default_url_category.get(x['name'], x['name']): x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.nlists.list(self._auth_token, 'applicationgroup', 0, 1000, {})
            self.list_applicationgroup = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v2.core.get.l7categories(self._auth_token, 0, 10000, '')
            self.l7_categories = {x['name']: x['id'] for x in result['items'] if result['count']}
            
            if self.version.startswith('6'):
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, {}, [])
            else:
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, '')
            self.l7_apps = {x['name']: x['id'] if 'id' in x.keys() else x['app_id'] for x in result['items'] if result['count']}

            result = self._server.v1.notification.profiles.list(self._auth_token)
            self.list_notifications = {x['name']: x['id'] for x in result}

            result = self._server.v1.netmanager.netflow.profiles.list(self._auth_token, 0, 1000, {})
            self.list_netflow = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v1.content.ssl.profiles.list(self._auth_token, 0, 100, {})
            self.list_ssl_profiles = {x['name']: x['id'] for x in result['items'] if result['count']}

            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
            self.list_groups = {x['name']: x['guid'] for x in result['items'] if result['total']}

            result = self._server.v1.auth.user.auth.profiles.list(self._auth_token)
            self.auth_profiles = {x['name']: x['id'] for x in result}

            result = self._server.v1.captiveportal.profiles.list(self._auth_token, 0, 100, '')
            self.captive_profiles = {x['name']: x['id'] for x in result['items']}

            result = self._server.v1.captiveportal.rules.list(self._auth_token, 0, 100, {})
            self.captive_portal_rules = {x['name']: x['id'] for x in result['items']}

        except rpc.Fault as err:
            print(f"\033[31mОшибка ug_convert_config/init_struct_for_import(): [{err.faultCode}] {err.faultString}\033[0m")

        total, data = self.get_zones_list()
        self.zones = {x['name']: x['id'] for x in data if total}

        total, data = self.get_shaper_list()
        self.shaper = {x['name']: x['id'] for x in data if total}

        total, data = self.get_scada_list()
        self.list_scada = {x['name']: x['id'] for x in data if total}

        total, data = self.get_templates_list()
        self.list_templates = {x['name']: x['id'] for x in data if total}

        total, data = self.get_users_list()
        self.list_users = {x['name']: x['guid'] for x in data if total}

        total, data = self.get_2fa_profiles()
        self.profiles_2fa = {x['name']: x['id'] for x in data if total}

        ldap, radius, tacacs, ntlm, saml = self.get_auth_servers()
        self.auth_servers = {x['name']: x['id'] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

        total, data = self.get_scenarios_rules()
        self.scenarios_rules = {x['name']: x['id'] for x in data if total}

    def init_struct(self):
        """Заполнить служебные структуры данных. Применяется при экспорте и импорте."""
        pass
        
################### Библиотеки ################################
    def export_morphology_lists(self):
        """Выгружает списки морфологии и преобразует формат атрибутов списков к версии 6"""
        print('Выгружаются списки морфологии раздела "Библиотеки":')
        if os.path.isdir('data/library/morphology'):
            for file_name in os.listdir('data/library/morphology'):
                os.remove(f"data/library/morphology/{file_name}")
        else:
            os.makedirs('data/library/morphology')

        total, data = self.get_nlist_list('morphology')

        for item in data:
            if self.version.startswith('5'):
                attributes = {}
                for attr in item['attributes']:
                    if attr['name'] == 'threat_level':
                        attributes['threat_level'] = attr['value']
                    else:
                        attributes['threshold'] = attr['value']
                item['attributes'] = attributes
            item.pop('id')
            item.pop('guid')
            item.pop('editable')
            item.pop('enabled')
            item.pop('global', None)
            item.pop('version')
            item.pop('last_update')
            for content in item['content']:
                content.pop('id')
            with open(f"data/library/morphology/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f'\tСписок морфологии "{item["name"]}" выгружен в файл "data/library/morphology/{item["name"]}.json"')

    def import_morphology(self):
        """Импортировать списки морфологии на UTM"""
        print('Импорт списков морфологии раздела "Библиотеки":')
        if os.path.isdir('data/library/morphology'):
            files_list = os.listdir('data/library/morphology')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/library/morphology/{file_name}", "r") as fh:
                            morph_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Морфология" не импортирован!\n\tНе найден файл "data/library/morphology/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = morph_list.pop('content')
                    err, result = self.add_nlist(morph_list)
                    if err == 1:
                        print(result, end= ' - ')
                        result = self.list_morph[morph_list['name']]
                        err1, result1 = self.update_nlist(result, morph_list)
                        if err1 != 0:
                            print("\n", f"\033[31m{result1}\033[0m")
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(f"\033[31m{result}\033[0m")
                        continue
                    else:
                        self.list_morph[morph_list['name']] = result
                        print(f'\tДобавлен список морфологии: "{morph_list["name"]}".')
                    for item in content:
                        err2, result2 = self.add_nlist_item(result, item)
                        if err2 == 2:
                            print(f"\033[31m{result2}\033[0m")
#                        elif err2 == 1:
#                            print(result2)
                    print(f'\t\tСодержимое списка "{morph_list["name"]}" обновлено.')
            else:
                print("\t\033[33mНет списков морфологии для импорта.\033[0m")
        else:
            print("\t\033[33mНет списков морфологии для импорта.\033[0m")

    def export_services_list(self):
        """Выгрузить список сервисов раздела библиотеки"""
        print('Выгружается список сервисов раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        data = {}
        _, data = self.get_services_list()
        for item in data['items']:
            item.pop('id')
            item.pop('guid')
            item.pop('cc', None)
            item.pop('readonly', None)
        with open("data/library/config_services.json", "w") as fh:
            json.dump(data['items'], fh, indent=4, ensure_ascii=False)
        print(f'\tСписок сервисов выгружен в файл "data/library/config_services.json".')

    def import_services(self):
        """Импортировать список сервисов раздела библиотеки"""
        print('Импорт списка сервисов раздела "Библиотеки":')
        try:
            with open("data/library/config_services.json", "r") as fh:
                services = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Сервисы" не импортирован!\n\tНе найден файл "data/library/config_services.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in services:
            err, result = self.add_service(item)
            if err == 1:
                print(result, end= ' - ')
                try:
                    err1, result1 = self.update_service(self.services[item['name']], item)
                except KeyError as keyerr:
                    print(f"\n\t\t\033[31mService {keyerr} not updated.\n\t\tУстановите последнее обновление на UTM и повторите попытку.\033[0m")
                else:
                    if err1 != 0:
                        print(result1)
                    else:
                        print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                self.services[item['name']] = result
                print(f'\tСервис "{item["name"]}" добавлен.')

    def export_IP_lists(self):
        """Выгружает списки IP-адресов и преобразует формат атрибутов списков к версии 6"""
        print('Выгружаются списки IP-адресов раздела "Библиотеки":')
        if os.path.isdir('data/library/ip_lists'):
            for file_name in os.listdir('data/library/ip_lists'):
                os.remove(f"data/library/ip_lists/{file_name}")
        else:
            os.makedirs('data/library/ip_lists')

        total, data = self.get_nlist_list('network')

        for item in data:
            if self.version.startswith('5'):
                item['attributes'] = {'threat_level': x['value'] for x in item['attributes']}
            item.pop('id')
            item.pop('guid')
            item.pop('editable')
            item.pop('enabled')
            item.pop('global', None)
            item.pop('version')
            item.pop('last_update')
            for content in item['content']:
                content.pop('id')
            with open(f"data/library/ip_lists/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f'\tСписок IP-адресов "{item["name"]}" выгружен в файл "data/library/ip_lists/{item["name"]}.json".')

    def import_IP_lists(self):
        """Импортировать списки IP адресов"""
        print('Импорт списков IP-адресов раздела "Библиотеки":')
        if os.path.isdir('data/library/ip_lists'):
            files_list = os.listdir('data/library/ip_lists')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/library/ip_lists/{file_name}", "r") as fh:
                            ip_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "IP-адреса" не импортирован!\n\tНе найден файл "data/library/ip_lists/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = ip_list.pop('content')
                    err, result = self.add_nlist(ip_list)
                    if err == 1:
                        print(result, end= ' - ')
                        result = self.list_IP[ip_list['name']]
                        err1, result1 = self.update_nlist(result, ip_list)
                        if err1 != 0:
                            print("\n", f"\033[31m{result1}\033[0m")
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(f"\033[31m{result}\033[0m")
                        continue
                    else:
                        self.list_IP[ip_list['name']] = result
                        print(f'\tДобавлен список IP-адресов: "{ip_list["name"]}".')
                    for item in content:
                        err2, result2 = self.add_nlist_item(result, item)
                        if err2 == 2:
                            print(f"\033[31m{result2}\033[0m")
                    print(f'\t\tСодержимое списка "{ip_list["name"]}" обновлено.')
            else:
                print("\033[33m\tНет списков IP-адресов для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков IP-адресов для импорта.\033[0m")

    def export_useragent_lists(self):
        """Выгружает списки useragent и преобразует формат атрибутов списков к версии 6"""
        print('Выгружаются список "Useragent браузеров" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list('useragent')

        for item in data:
            if self.version.startswith('5'):
                item['attributes'] = {}
            item.pop('id')
            item.pop('guid')
            item.pop('editable')
            item.pop('enabled')
            item.pop('global', None)
            item.pop('version')
            item.pop('last_update', None)
            for content in item['content']:
                content.pop('id')
        with open("data/library/config_useragents.json", "w") as fd:
                json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Useragent браузеров" выгружен в файл "data/library/config_useragents.json".')

    def import_useragent_lists(self):
        """Импортировать списки Useragent браузеров"""
        print('Импорт списков "Useragent браузеров" раздела "Библиотеки":')
        try:
            with open("data/library/config_useragents.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Useragent браузеров" не импортирован!\n\tНе найден файл "data/library/config_useragents.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет списков Useragent для импорта.")
            return
        for item in data:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, end= ' - ')
                result = self.list_useragent[item['name']]
                err1, result1 = self.update_nlist(result, item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
                continue
            else:
                self.list_useragent[item['name']] = result
                print(f'\tДобавлен список Useragent: "{item["name"]}".')

            for agent in content:
                err2, result2 = self.add_nlist_item(result, agent)
                if err2 == 2:
                    print(f"\033[31m{result2}\033[0m")
#                elif err2 == 1:
#                    print(result2)
            print(f'\t\tСодержимое списка "{item["name"]}" обновлено.')

    def export_mime_lists(self):
        """Выгружает списки Типов контента и преобразует формат атрибутов списков к версии 6"""
        print('Выгружается список "Типы контента" (mime типы) раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list('mime')

        for item in data:
            if self.version.startswith('5'):
                item['attributes'] = {}
            item.pop('id')
            item.pop('guid')
            item.pop('editable')
            item.pop('enabled')
            item.pop('global', None)
            item.pop('version')
            item.pop('last_update', None)
            for content in item['content']:
                content.pop('id')
        with open("data/library/config_mime_types.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Типы контента" выгружен в файл "data/library/config_mime_types.json".')

    def import_mime_lists(self):
        """Импортировать списки Типов контента"""
        print('Импорт списка "Типы контента" раздела "Библиотеки":')
        try:
            with open("data/library/config_mime_types.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Типы контента" не импортирован!\n\tНе найден файл "data/library/config_mime_types.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print('\033[33m\tНет списка "Типы контента" для импорта.\033[0m')
            return
        for item in data:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, end= ' - ')
                result = self.list_mime[item['name']]
                err1, result1 = self.update_nlist(result, item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
                continue
            else:
                self.list_mime[item['name']] = result
                print(f"\tДобавлен список типов контента '{item['name']}'.")

            for x in content:
                err2, result2 = self.add_nlist_item(result, x)
                if err2 == 2:
                   print(f"\033[31m{result2}\033[0m")
            print(f'\t\tСодержимое списка "{item["name"]}" обновлено.')

    def export_url_lists(self):
        """Выгружает списки URL и преобразует формат атрибутов списков к версии 6"""
        print('Выгружаются "Списки URL" раздела "Библиотеки":')
        if os.path.isdir('data/library/url'):
            for file_name in os.listdir('data/library/url'):
                os.remove(f"data/library/url/{file_name}")
        else:
            os.makedirs('data/library/url')

        total, data = self.get_nlist_list('url')

        for item in data:
            if self.version.startswith('5'):
                item['attributes'] = {'threat_level': x['value'] for x in item['attributes']}
            item.pop('id')
            item.pop('guid')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            item.pop('last_update', None)
            for content in item['content']:
                content.pop('id')
            with open(f"data/library/url/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tСписок URL {item['name']} выгружен в файл data/library/url/{item['name']}.json")

    def import_url_lists(self):
        """Импортировать списки URL на UTM"""
        print('Импорт списков URL раздела "Библиотеки":')
        if os.path.isdir('data/library/url'):
            files_list = os.listdir('data/library/url')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/library/url/{file_name}", "r") as fh:
                            url_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Списки URL" не импортирован!\n\tНе найден файл "data/library/url/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = url_list.pop('content')
                    err, result = self.add_nlist(url_list)
                    if err == 1:
                        print(result, end= ' - ')
                        result = self.list_url[url_list['name']]
                        err1, result1 = self.update_nlist(result, url_list)
                        if err1 != 0:
                            print("\n", f'\033[31m{result1}\033[0m')
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(f"\033[31m{result}\033[0m")
                        continue
                    else:
                        self.list_url[url_list['name']] = result
                        print(f'\tДобавлен список URL: "{url_list["name"]}".')
                    for item in content:
                        err2, result2 = self.add_nlist_item(result, item)
                        if err2 == 2:
                            print(f"\033[31m{result2}\033[0m")
                    print(f'\t\tСодержимое списка "{url_list["name"]}" обновлено.')
            else:
                print("\033[33m\tНет списков URL для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков URL для импорта.\033[0m")

    def export_time_restricted_lists(self):
        """Выгружает содержимое календарей и преобразует формат атрибутов списков к версии 6"""
        print('Выгружается список "Календари" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list('timerestrictiongroup')

        for item in data:
            if self.version.startswith('5'):
                item['attributes'] = {}
            item.pop('id')
            item.pop('guid')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            item.pop('last_update', None)
            for content in item['content']:
                content.pop('id', None)
                content.pop('fixed_date_from', None)
                content.pop('fixed_date_to', None)
                content.pop('fixed_date', None)
        with open("data/library/config_calendars.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Календари" выгружен в файл "data/library/config_calendars.json".')

    def import_time_restricted_lists(self):
        """Импортировать содержимое календарей"""
        print('Импорт списка "Календари" раздела "Библиотеки":')
        try:
            with open("data/library/config_calendars.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Календари" не импортирован!\n\tНе найден файл "data/library/config_calendars.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\033[33m\tНет списков Календарей для импорта.\033[0m")
            return
        for item in data:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, end= ' - ')
                result = self.list_calendar[item['name']]
                err1, result1 = self.update_nlist(result, item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
                continue
            else:
                self.list_calendar[item['name']] = result
                print(f'\tДобавлен элемент календаря: "{item["name"]}".')
            for x in content:
                err2, result2 = self.add_nlist_item(result, x)
                if err2 == 2:
                    print(f"\033[31m{result2}\033[0m")
            print(f'\t\tСодержимое списка "{item["name"]}" обновлено.')
            
    def export_shaper_list(self):
        """Выгрузить список Полос пропускания раздела библиотеки"""
        print('Выгружается список "Полосы пропускания" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        _, data = self.get_shaper_list()

        for item in data:
            item.pop('id')
            item.pop('guid')
            item.pop('cc', None)
        with open("data/library/config_shaper.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Полосы пропускания" выгружен в файл "data/library/config_shaper.json".')

    def import_shaper(self):
        """Импортировать список Полос пропускания раздела библиотеки"""
        print('Импорт списка "Полосы пропускания" раздела "Библиотеки":')
        try:
            with open("data/library/config_shaper.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Полосы пропускания" не импортирован!\n\tНе найден файл "data/library/config_shaper.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет полос пропускания для импорта.")
            return
        for item in data:
            err, result = self.add_shaper(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_shaper(self.shaper[item['name']], item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.shaper[item['name']] = result
                print(f'\tПолоса пропускания "{item["name"]}" добавлена.')

    def export_scada_list(self):
        """Выгрузить список профилей АСУ ТП раздела библиотеки"""
        print('Выгружается список "Профили АСУ ТП" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        _, data = self.get_scada_list()

        for item in data:
            item.pop('id')
            item.pop('cc', None)
        with open("data/library/config_scada.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили АСУ ТП" выгружен в файл "data/library/config_scada.json".')

    def import_scada_list(self):
        """Импортировать список профилей АСУ ТП раздела библиотеки"""
        print('Импорт списка "Профили АСУ ТП" раздела "Библиотеки":')
        try:
            with open("data/library/config_scada.json", "r") as fh:
                scada = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили АСУ ТП" не импортирован!\n\tНе найден файл "data/library/config_scada.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in scada:
            err, result = self.add_scada(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_scada(self.list_scada[item['name']], item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_scada[item['name']] = result
                print(f'\tПрофиль АСУ ТП "{item["name"]}" добавлен.')

    def export_templates_list(self):
        """
        Выгрузить список шаблонов страниц раздела библиотеки.
        Выгружает файл HTML только для изменённых страниц шаблонов.
        """
        print('Выгружается список "Шаблоны страниц" раздела "Библиотеки":')
        if os.path.isdir('data/library/templates'):
            for file_name in os.listdir('data/library/templates'):
                os.remove(f"data/library/templates/{file_name}")
        else:
            os.makedirs('data/library/templates')

        _, data = self.get_templates_list()
        for item in data:
            _, html_data = self.get_template_data(item['type'], item['id'])
            if html_data:
                with open(f"data/library/templates/{item['name']}.html", "w") as fh:
                    fh.write(html_data)
                print(f'\tСтраница HTML для шаблона "{item["name"]}" выгружена в файл "data/library/templates/{item["name"]}.html".')
            item.pop('id')
            item.pop('last_update', None)
            item.pop('cc', None)
        with open("data/library/templates/config_templates.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print('\tСписок "Шаблоны страниц" выгружен в файл "data/library/templates/config_templates.json".')

    def import_templates_list(self):
        """
        Импортировать список шаблонов страниц раздела библиотеки.
        После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
        """
        print('Импорт списка "Шаблоны страниц" раздела "Библиотеки":')
        try:
            with open("data/library/templates/config_templates.json", "r") as fh:
                templates = json.load(fh)
        except FileNotFoundError as err:
            print('\t\033[31mСписок "Шаблоны страниц" не импортирован!\n\tНе найден файл "data/library/templates/config_templates.json" с сохранённой конфигурацией!\033[0;0m')
            return

        html_files = os.listdir('data/library/templates')

        for item in templates:
            err, result = self.add_template(item)
            if err == 1:
                print(result, end= ' - ')
                result = self.list_templates[item['name']]
                err1, result1 = self.update_template(result, item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
                continue
            else:
                self.list_templates[item['name']] = result
                print(f'\tШаблон страницы "{item["name"]}" добавлен.')

            if f"{item['name']}.html" in html_files:
                with open(f"data/library/templates/{item['name']}.html", "br") as fh:
                    file_data = fh.read()
                _, result2 = self.set_template_data(result, file_data)
                if result2:
                    print(f'\t\tСтраница "{item["name"]}.html" добавлена.')

    def export_categories_groups(self):
        """Выгружает список "Категории URL" и преобразует формат атрибутов списков к версии 6"""
        print('Выгружается список "Категории URL" раздела "Библиотеки":')
        group_name_revert = {v: k for k, v in self.default_url_category.items()}

        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list('urlcategorygroup')

        for item in data:
            item.pop('id')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            item.pop('last_update', None)
            item['name'] = group_name_revert.get(item['name'], item['name'])
            if self.version.startswith('5'):
                item['guid'] = self.default_url_category.get(item['name'], item['guid'])
            for content in item['content']:
                content.pop('id')
                if self.version.startswith('5'):
                    content['category_id'] = content.pop('value')
                    content['name'] = self._categories[int(content['category_id'])]

        with open("data/library/config_categories_url.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Категории URL" выгружен в файл "data/library/config_categories_url.json".')

    def import_categories_groups(self):
        """Импортировать список "Категории URL" на UTM"""
        print('Импорт списка "Категории URL":')
        try:
            with open("data/library/config_categories_url.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print('\t\033[31mСписок "Категории URL" не импортирован!\n\tНе найден файл "data/library/config_categories_url.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет групп URL категорий для импорта.")
            return
        for item in data:
            content = item.pop('content')
            if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                    'Recommended for morphology checking', 'Recommended for virus check']:
                err, result = self.add_nlist(item)
                if err == 1:
                    print(result, "\033[32mOk!\033[0;0m")
                elif err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    self.list_urlcategorygroup[item['name']] = result
                    print(f'\tГруппа URL категорий "{item["name"]}" добавлена.')
                    for category in content:
                        try:
                            err2, result2 = self.add_nlist_item(result, category)
                            if err2 != 0:
                                print(f'\033[31m{result2}\033[0m')
                            else:
                                print(f'\t\tДобавлена категория: "{category["name"]}".')
                        except:
                            print(f'\t\tКатегория "{category["name"]}" не будет добавлена, так как не существует на целевой системе.')

    def export_application_groups(self):
        """Выгружает список "Приложения" и преобразует формат атрибутов списков к версии 6"""
        print('Выгружается список "Приложения" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list('applicationgroup')

        for item in data:
            item.pop('id')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('url', None)
            item.pop('version', None)
            item.pop('last_update', None)
            for content in item['content']:
                content.pop('id')
                content['value'] = self.l7_apps.get(content['value'], content['value'])

        with open("data/library/config_applications.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Приложения" выгружен в файл "data/library/config_applications.json".')

    def import_application_groups(self):
        """Импортировать список "Приложения" на UTM"""
        print('Импорт списка "Приложения" раздела "Библиотеки":')
        try:
            with open("data/library/config_applications.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print('\t\033[31mСписок "Приложения" не импортирован!\n\tНе найден файл "data/library/config_applications.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет групп приложений для импорта.")
            return
        for item in data:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, "\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_applicationgroup[item['name']] = result
                print(f'\tГруппа приложений "{item["name"]}" добавлена.')
                for app in content:
                    try:
                        err2, result2 = self.add_nlist_item(result, self.l7_apps[app['value']])
                        if err2 != 0:
                            print(f'\033[31m{result2}\033[0m')
                        else:
                            print(f'\t\tДобавлено приложение: "{app["value"]}".')
                    except:
                        print(f'\t\t\033[33mПриложение "{app["value"]}" не будет добавлено, так как не существует на целевой системе.\033[0m')

    def export_nlist_groups(self, list_type):
        """Выгружает списки: "Почтовые адреса", "Номера телефонов" и преобразует формат списков к версии 6"""
        list_name = {
            'emailgroup': "Почтовые адреса",
            'phonegroup': "Номера телефонов"
            }
        print(f'Выгружается список "{list_name[list_type]}" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list(list_type)

        for item in data:
            item.pop('id')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            item.pop('last_update', None)
            item.pop('attributes')
            for content in item['content']:
                content.pop('id')

        with open(f"data/library/config_{list_type}.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "{list_name[list_type]}" выгружен в файл "data/library/config_{list_type}.json".')

    def import_nlist_groups(self, list_type):
        """Импортировать списки: "Почтовые адреса" и "Номера телефонов" на UTM"""
        list_name = {
            'emailgroup': ["Почтовые адреса", "адресов", "адрес"],
            'phonegroup': ["Номера телефонов", "номеров", "номер"],
            }
        print(f'Импорт списка "{list_name[list_type][0]}":')
        try:
            with open(f"data/library/config_{list_type}.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "{list_name[list_type][0]}" не импортирован!\n\tНе найден файл "data/library/config_{list_type}.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print(f"\tНет {list_name[list_type][1]} для импорта.")
            return
        for item in data:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, "\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tГруппа {list_name[list_type][1]} "{item["name"]}" добавлена.')
                for email in content:
                    try:
                        err2, result2 = self.add_nlist_item(result, email)
                        if err2 != 0:
                            print(f'\033[31m{result2}\033[0m')
                        else:
                            print(f'\t\tДобавлен {list_name[list_type][2]}: "{email["value"]}".')
                    except:
                        print(f'\t\t\033[31m{list_name[list_type][2]} "{email["value"]}" не будет добавлен, так как произошла ошибка при добавлении.\033[0m')

    def export_ips_profiles(self):
        """Выгружает списки: "Профили СОВ" и преобразует формат списков к версии 6"""
        print(f'Выгружается список "Профили СОВ" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        total, data = self.get_nlist_list('ipspolicy')

        for item in data:
            item.pop('id')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            item.pop('url', None)
            item.pop('last_update', None)
            item.pop('attributes')
            for content in item['content']:
                content.pop('id', None)
                content.pop('l10n', None)
                content.pop('action', None)
                content.pop('bugtraq', None)
                content.pop('cve', None)
                content.pop('nessus', None)
                if 'threat_level' in content.keys():
                    content['threat'] = content.pop('threat_level')

        with open(f"data/library/config_ips_profiles.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили СОВ" выгружен в файл "data/library/config_ips_profiles.json".')

    def import_ips_profiles(self):
        """Импортировать списки: "Профили СОВ" на UTM"""
        print(f'Импорт списка "Профили СОВ":')
        try:
            with open(f"data/library/config_ips_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили СОВ" не импортирован!\n\tНе найден файл "data/library/config_ips_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print(f"\tНет профилей СОВ для импорта.")
            return

        _, idps_profiles = self.get_nlist_list('ipspolicy')
        idps = {x['name']: x['id'] for x in idps_profiles}

        for item in data:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, "\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
                continue
            else:
                idps[item['name']] = result
                print(f'\tПрофиль СОВ "{item["name"]}" добавлен.')

            if int(self.version[6:11]) >= 10709:
                for signature in content:
                    if 'value' not in signature.keys():
                        print(f'\t\t\033[33mСигнатуры для данного профиля не будут добавлены так как формат не соответствует целевой системе.\033[0m')
                        break
                    try:
                        err2, result2 = self.add_nlist_item(idps[item['name']], {'value': signature['value']})
                        if err2 != 0:
                            print(f'{result2}')
                        else:
                            print(f'\t\tДобавлена сигнатура: "{signature["msg"]}".')
                    except:
                        print(f'\t\t\033[33mСигнатура "{signature["msg"]}":\n\t\t\tне будет добавлена, так как отсутствует на целевой системе!\033[0m')
            else:
                print(f'\t\t\033[33mСигнатуры для данного профиля не будут добавлены.\n\t\tИспользуйте версию UTM 6.1.3.10709 или выше.\033[0m')

    def export_notification_profiles_list(self):
        """Выгрузить список профилей оповещения раздела библиотеки"""
        print('Выгружается список "Профили оповещений" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        _, data = self.get_notification_profiles_list()

        for item in data:
            item.pop('cc', None)
        with open("data/library/config_notification_profiles.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили оповещений" выгружен в файл "data/library/config_notification_profiles.json".')

    def import_notification_profiles(self):
        """Импортировать список профилей оповещения раздела библиотеки"""
        print('Импорт списка "Профили оповещений" раздела "Библиотеки":')
        try:
            with open("data/library/config_notification_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили оповещений" не импортирован!\n\tНе найден файл "data/library/config_notification_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print(f"\tНет профилей оповещения для импорта.")
            return
        for item in data:
            err, result = self.add_notification_profile(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_notification_profile(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_notifications[item['name']] = result
                print(f'\tПрофиль оповещения "{item["name"]}" добавлен.')

    def export_netflow_profiles_list(self):
        """Выгрузить список профилей netflow раздела библиотеки"""
        print('Выгружается список "Профили netflow" раздела "Библиотеки":')
        if not os.path.isdir('data/library'):
            os.makedirs('data/library')

        _, data = self.get_netflow_profiles_list()

        for item in data:
            item.pop('cc', None)
        with open("data/library/config_netflow_profiles.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили netflow" выгружен в файл "data/library/config_netflow_profiles.json".')

    def import_netflow_profiles(self):
        """Импортировать список профилей netflow раздела библиотеки"""
        print('Импорт списка "Профили netflow" раздела "Библиотеки":')
        try:
            with open("data/library/config_netflow_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили netflow" не импортирован!\n\tНе найден файл "data/library/config_netflow_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print(f"\tНет профилей netflow для импорта.")
            return
        for item in data:
            err, result = self.add_netflow_profile(item)
            if err == 1:
                print(result, end= ' - ')
                item['id'] = self.list_netflow[item['name']]
                err1, result1 = self.update_netflow_profile(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_netflow[item['name']] = result
                print(f'\tПрофиль netflow "{item["name"]}" добавлен.')

    def export_ssl_profiles_list(self):
        """Выгрузить список профилей SSL раздела библиотеки"""
        if self.version.startswith('6'):
            print('Выгружается список "Профили SSL" раздела "Библиотеки":')
            if not os.path.isdir('data/library'):
                os.makedirs('data/library')

            _, data = self.get_ssl_profiles_list()
            for item in data:
                item.pop('cc', None)
            with open("data/library/config_ssl_profiles.json", "w") as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            print(f'\tСписок "Профили SSL" выгружен в файл "data/library/config_ssl_profiles.json".')

    def import_ssl_profiles(self):
        """Импортировать список профилей SSL раздела библиотеки"""
        print('Импорт списка "Профили SSL" раздела "Библиотеки":')
        try:
            with open("data/library/config_ssl_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили SSL" не импортирован!\n\tНе найден файл "data/library/config_ssl_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print(f"\tНет профилей netflow для импорта.")
            return
        for item in data:
            err, result = self.add_ssl_profile(item)
            if err == 1:
                print(result, end= ' - ')
                item['id'] = self.list_ssl_profiles[item['name']]
                err1, result1 = self.update_ssl_profile(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_ssl_profiles[item['name']] = result
                print(f'\tПрофиль SSL "{item["name"]}" добавлен.')

################### Настройки ################################################
    def export_ntp(self):
        """Выгрузить настройки NTP"""
        print('Выгружаются "Настройки NTP" раздела "Настройки":')
        if not os.path.isdir('data/settings'):
            os.makedirs('data/settings')

        _, data = self.get_ntp_config()
        if data:
            data.pop('local_time', None)
            data.pop('timezone', None)
            data.pop('utc_time', None)
        with open("data/settings/config_ntp.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tНастройки NTP выгружены в файл "data/settings/config_ntp.json".')

    def import_ntp(self):
        """Импортировать настройки NTP"""
        print('Импорт настроек NTP раздела "Настройки":')
        try:
            with open("data/settings/config_ntp.json", "r") as fh:
                ntp = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mНастройки NTP не импортированы!\n\tНе найден файл "data/settings/config_ntp.json" с сохранённой конфигурацией!\033[0;0m')
            return

        err, result = self.add_ntp_config(ntp)
        if err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\tНастройки NTP обновлены.')

    def export_settings(self):
        """Выгрузить настройки"""
        print('Выгружаются настройки кэширования HTTP и модулей раздела "Настройки":')
        if not os.path.isdir('data/settings'):
            os.makedirs('data/settings')

        params = ["auth_captive", "logout_captive", "block_page_domain", "ftpclient_captive",
                  "ftp_proxy_enabled", "http_cache_mode", "http_cache_docsize_max", "http_cache_precache_size"]
        _, data = self.get_settings_params(params)
        with open("data/settings/config_settings.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tНастройки кэширования HTTP и модулей выгружены в файл "data/settings/config_settings.json".')

        _, data = self.get_proxy_port()
        if data:
            with open("data/settings/config_proxy_port.json", "w") as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

        _, data = self.get_nlist_list('httpcwl')
        for content in data['content']:
            content.pop('id')
        with open("data/settings/config_proxy_exceptions.json", "w") as fd:
            json.dump(data['content'], fd, indent=4, ensure_ascii=False)
        print(f'\tИсключения кеширования http выгружены в файл data/settings/config_proxy_exceptions.json')

    def import_settings(self):
        """Импортировать настройки"""
        print('Импорт настроек кэширования HTTP и модулей раздела "Настройки":')
        try:
            with open("data/settings/config_proxy_port.json", "r") as fh:
                port = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mПорт прокси не импортирован!\n\tНе найден файл "data/settings/config_proxy_port.json" с сохранённой конфигурацией!\033[0;0m')
            return

        err, result = self.set_proxy_port(port)
        if err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\tHTTP(S)-прокси порт обновлён.')

        try:
            with open("data/settings/config_settings.json", "r") as fh:
                settings = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mНастройки кэширования HTTP и модулей не импортированы!\n\tНе найден файл "data/settings/config_settings.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for key, value in settings.items():
            err, result = self.set_settings_param(key, value)
            if err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПараметр {key} обновлён.')

        try:
            with open("data/settings/config_proxy_exceptions.json", "r") as fh:
                settings = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mИсключения кеширования http не импортированы!\n\tНе найден файл "data/settings/config_proxy_exceptions.json" с сохранённой конфигурацией!\033[0;0m')
            return

        _, data = self.get_nlist_list('httpcwl')
        for item in settings:
            err, result = self.add_nlist_item(data['id'], item)
            if err != 0:
                print(f'\t{result}')
            else:
                print(f'\tВ исключения кеширования добавлен URL: "{item["value"]}".')

    def export_proxy_portal(self):
        """Выгрузить настройки веб-портала"""
        print('Выгружаются настройки Веб-портала раздела "Настройки":')
        if not os.path.isdir('data/settings'):
            os.makedirs('data/settings')

#        print(self.list_templates)
        _, data = self.get_proxyportal_config()
        if data:
            data['user_auth_profile_id'] = self.auth_profiles.get(data['user_auth_profile_id'], None)
#            data['proxy_portal_template_id'] = self.list_templates.get(data['proxy_portal_template_id'], self.list_templates['proxy_portal'])
        with open("data/settings/config_proxy_portal.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tНастройки Веб-портала выгружены в файл "data/settings/config_proxy_portal.json".')

################### Пользователи и устройства ################################
    def export_groups_lists(self):
        """Выгружает список групп"""
        print('Выгружается список локальных групп раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        _, data = self.get_groups_list()

        for item in data:
            _, users = self.get_group_users(item['guid'])
            item.pop('cc', None)
            if self.version.startswith('6'):
                item['users'] = [x[1] for x in users]
            else:
                item['users'] = [x['name'] for x in users]

        with open(f"data/users_and_devices/config_groups.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок локальных групп выгружен в файл data/users_and_devices/config_groups.json")

    def import_groups_list(self):
        """Импортировать локальные группы"""
        print('Импорт списка локальных групп раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_groups.json", "r") as fh:
                groups = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок локальных групп не импортирован!\n\tНе найден файл "data/users_and_devices/config_groups.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in groups:
            users = item.pop('users')
            err, result = self.add_group(item)
            if err == 1:
                print(result, end= ' - ')
                item['guid'] = self.list_groups[item['name']]
                err1, result1 = self.update_group(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_groups[item['name']] = result
                print(f'\tЛокальная группа "{item["name"]}" добавлена.')

            for user_name in users:
                i = user_name.partition("\\")
                if i[2]:
                    err, result = self.get_ldap_user_guid(i[0], i[2])
                    if err != 0:
                        print(f"\033[31m{result}\033[0m")
                        break
                    elif not result:
                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                        break
                    err2, result2 = self.add_user_in_group(self.list_groups[item['name']], result)
                    if err2 != 0:
                        print(f"\033[31m{result2}\033[0m")
                    else:
                        print(f'\t\tПользователь "{user_name}" добавлен в группу.')

    def export_users_lists(self):
        """Выгружает список локальных пользователей"""
        print('Выгружается список локальных пользователей раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        _, data = self.get_users_list()

        for item in data:
            item.pop('guid')
            item.pop('creation_date')
            item.pop('expiration_date')
            item.pop('cc', None)
            if not item['first_name']:
                item['first_name'] = ""
            if not item['last_name']:
                item['last_name'] = ""
            item['groups'] = [self.list_groups[guid] for guid in item['groups']]
        with open(f"data/users_and_devices/config_users.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок локальных пользователей выгружен в файл data/users_and_devices/config_users.json")

    def import_users_list(self):
        """Импортировать список локальных пользователей"""
        print('Импорт списка локальных пользователей раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_users.json", "r") as fh:
                users = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок локальных пользователей не импортирован!\n\tНе найден файл "data/users_and_devices/config_users.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in users:
            item['groups'] = [self.list_groups[name] for name in item['groups']]
            err, result = self.add_user(item)
            if err == 1:
                print(result, end= ' - ')
                item['guid'] = self.list_users[item['name']]
                err1, result1 = self.update_user(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                self.list_users[item['name']] = result
                item['guid'] = result
                print(f'\tЛокальный пользователь "{item["name"]}" добавлен.')
            for group_guid in item['groups']:
                err2, result2 = self.add_user_in_group(group_guid, item['guid'])
                if err2 != 0:
                    print("\n", f"\033[31m{result2}\033[0m")

    def export_auth_servers(self):
        """Выгрузить списки серверов авторизации"""
        print('Выгружается список "Cерверы авторизации" раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        ldap, radius, tacacs, ntlm, saml = self.get_auth_servers()

        with open("data/users_and_devices/config_ldap_servers.json", "w") as fd:
            json.dump(ldap, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок серверов LDAP выгружен в файл 'data/users_and_devices/config_ldap_servers.json'.")

        with open("data/users_and_devices/config_radius_servers.json", "w") as fd:
            json.dump(radius, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок серверов RADIUS выгружен в файл 'data/users_and_devices/config_radius_servers.json'.")

        with open("data/users_and_devices/config_tacacs_servers.json", "w") as fd:
            json.dump(tacacs, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок серверов TACACS выгружен в файл 'data/users_and_devices/config_tacacs_static.json'.")

        with open("data/users_and_devices/config_ntlm_servers.json", "w") as fd:
            json.dump(ntlm, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок серверов NTLM выгружен в файл 'data/users_and_devices/config_ntlm_servers.json'.")

        with open("data/users_and_devices/config_saml_servers.json", "w") as fd:
            json.dump(saml, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок серверов SAML выгружен в файл 'data/users_and_devices/config_saml_servers.json'.")

    def import_ldap_server(self):
        """Импортировать список серверов LDAP"""
        print('Импорт списка серверов LDAP раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_ldap_servers.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок серверов LDAP не импортирован!\n\tНе найден файл "data/users_and_devices/config_ldap_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет серверов авторизации LDAP для импорта.")
            return
        for item in data:
            item['enabled'] = False
            item['keytab_exists'] = False
            item.pop("cc", None)
            err, result = self.add_auth_server('ldap', item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСервер авторизации LDAP "{item["name"]}" добавлен.')
                print(f'\t\033[36mНеобходимо включить "{item["name"]}", ввести пароль и импортировать keytab файл.\033[0m')

    def import_ntlm_server(self):
        """Импортировать список серверов NTLM"""
        print('Импорт списка серверов NTLM раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_ntlm_servers.json", "r") as fh:
                ntlm = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок серверов LDAP не импортирован!\n\tНе найден файл "data/users_and_devices/config_ntlm_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not ntlm:
            print("\tНет серверов авторизации NTLM для импорта.")
            return
        for item in ntlm:
            item.pop("cc", None)
            err, result = self.add_auth_server('ntlm', item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСервер авторизации NTLM "{item["name"]}" добавлен.')

    def import_radius_server(self):
        """Импортировать список серверов RADIUS"""
        print('Импорт списка серверов RADIUS раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_radius_servers.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок серверов RADIUS не импортирован!\n\tНе найден файл "data/users_and_devices/config_radius_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет серверов авторизации RADIUS для импорта.")
            return
        for item in data:
            item.pop("cc", None)
            err, result = self.add_auth_server('radius', item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСервер авторизации RADIUS "{item["name"]}" добавлен.')
                print(f'\t\033[36mНа сервере авторизации "{item["name"]}" необходимо ввести пароль.\033[0m')

    def import_tacacs_server(self):
        """Импортировать список серверов TACACS"""
        print('Импорт списка серверов TACACS раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_tacacs_servers.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок серверов TACACS не импортирован!\n\tНе найден файл "data/users_and_devices/config_tacacs_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет серверов авторизации TACACS для импорта.")
            return
        for item in data:
            item.pop("cc", None)
            err, result = self.add_auth_server('tacacs', item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСервер авторизации TACACS "{item["name"]}" добавлен.')
                print(f'\t\033[36mНа сервере авторизации "{item["name"]}" необходимо ввести секретный ключ.\033[0m')

    def import_saml_server(self):
        """Импортировать список серверов SAML"""
        print('Импорт списка серверов SAML раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_saml_servers.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок серверов SAML не импортирован!\n\tНе найден файл "data/users_and_devices/config_saml_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет серверов авторизации SAML для импорта.")
            return
        for item in data:
            item.pop("cc", None)
            err, result = self.add_auth_server('saml', item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСервер авторизации SAML "{item["name"]}" добавлен.')
                print(f'\t\033[36mНа сервере авторизации "{item["name"]}" загрузите SAML metadata.\033[0m')

    def export_2fa_profiles(self):
        """Выгрузить список 2FA профилей"""
        print('Выгружается список "Профили MFA" раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.mkdir('data/users_and_devices')

        _, data = self.get_2fa_profiles()
        for item in data:
            if item['type'] == 'totp':
                item['init_notification_profile_id'] = self.list_notifications.get(item['init_notification_profile_id'], item['init_notification_profile_id'])
            else:
                item['auth_notification_profile_id'] = self.list_notifications.get(item['auth_notification_profile_id'], item['auth_notification_profile_id'])
        with open("data/users_and_devices/config_2fa_profiles.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили MFA" выгружен в файл "data/users_and_devices/config_2fa_profiles.json".')

    def import_2fa_profiles(self):
        """Импортировать список 2FA профилей"""
        print('Импорт списка "Профили MFA" раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_2fa_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили MFA" не импортирован!\n\tНе найден файл "data/users_and_devices/config_2fa_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет профилей MFA для импорта.")
            return
        for item in data:
            if item['type'] == 'totp':
                if item['init_notification_profile_id'] != -5 and item['init_notification_profile_id'] not in self.list_notifications.keys():
                    print(f'\t\033[31mПрофиль MFA "{item["name"]}" не добавлен так как "Инициализация TOTP" для него не существует.\n\tЗагрузите профили оповещения и повторите попытку.\033[0m')
                    continue
                item['init_notification_profile_id'] = self.list_notifications.get(item['init_notification_profile_id'], -5)
            else:
                if item['auth_notification_profile_id'] not in self.list_notifications.keys():
                    print(f'\t\033[31mПрофиль MFA "{item["name"]}" не добавлен так как профиль отправки MFA для него не существует.\n\tЗагрузите профили оповещения и повторите попытку.\033[0m')
                    continue
                item['auth_notification_profile_id'] = self.list_notifications[item['auth_notification_profile_id']]
            err, result = self.add_2fa_profile(item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПрофиль MFA "{item["name"]}" добавлен.')

    def get_auth_profile_methods(self, method):
        auth_type = {
            'ldap': 'ldap_server_id',
            'radius': 'radius_server_id',
            'tacacs_plus': 'tacacs_plus_server_id',
            'ntlm': 'ntlm_server_id',
            'saml_idp': 'saml_idp_server_id' if self.version.startswith('6') else 'saml_idp_server'
        }
        name = auth_type[method['type']]
        try:
            if name == 'saml_idp_server':
                method['saml_idp_server_id'] = self.auth_servers[method[name]]
                method.pop('saml_idp_server')
            else:
                method[name] = self.auth_servers[method[name]]
        except KeyError:
            print(f'\t\033[33mСервер авторизации "{method[name]}" не найден.\n\tЗагрузите серверы авторизации и повторите попытку.\033[0m')
            method.clear()

    def export_auth_profiles(self):
        """Выгрузить список профилей авторизации"""
        print('Выгружается список "Профили авторизации" раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        _, data = self.get_auth_profiles()

        for item in data:
            item['2fa_profile_id'] = self.profiles_2fa.get(item['2fa_profile_id'], False)
            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    self.get_auth_profile_methods(auth_method)

        with open("data/users_and_devices/config_auth_profiles.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили авторизации" выгружен в файл "data/users_and_devices/config_auth_profiles.json".')

    def import_auth_profiles(self):
        """Импортировать список профилей авторизации"""
        print('Импорт списка "Профили авторизации" раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_auth_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили авторизации" не импортирован!\n\tНе найден файл "data/users_and_devices/config_auth_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет профилей авторизации для импорта.")
            return
        for item in data:
            if item['2fa_profile_id']:
                try:
                    item['2fa_profile_id'] = self.profiles_2fa[item['2fa_profile_id']]
                except KeyError:
                    print(f'\t\033[33mПрофиль MFA "{item["2fa_profile_id"]}" не найден.\n\tЗагрузите профили MFA и повторите попытку.\033[0m')
                    item['2fa_profile_id'] = False

            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    self.get_auth_profile_methods(auth_method)

            err, result = self.add_auth_profile(item)
            if err == 1:
                print(result, end= ' - ')
                item['id'] = self.auth_profiles[item['name']]
                err1, result1 = self.update_auth_profile(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПрофиль авторизации "{item["name"]}" добавлен.')

    def export_captive_profiles(self):
        """Выгрузить список Captive-профилей"""
        print('Выгружается список "Captive-профили" раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        _, data = self.get_captive_profiles()

        for item in data:
            item['captive_template_id'] = self.list_templates.get(item['captive_template_id'], -1)
            item['notification_profile_id'] = self.list_notifications.get(item['notification_profile_id'], -1)
            item['user_auth_profile_id'] = self.auth_profiles[item['user_auth_profile_id']]
            if self.version.startswith('5'):
                item['ta_groups'] = [self.list_groups[guid] for guid in item['ta_groups']]
            else:
                result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
                groups = {x['id']: x['name'] for x in result['items'] if result['total']}
                item['ta_groups'] = [groups[id] for id in item['ta_groups']]
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('ta_expiration_date', None),
            item.pop('cc', None)

        with open("data/users_and_devices/config_captive_profiles.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Captive-профили" выгружен в файл "data/users_and_devices/config_captive_profiles.json".')

    def import_captive_profiles(self):
        """Импортировать список Captive-профилей"""
        print('Импорт списка "Captive-профили" раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_captive_profiles.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Captive-профили" не импортирован!\n\tНе найден файл "data/users_and_devices/config_captive_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет Captive-профилей для импорта.")
            return
        result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
        groups = {x['name']: x['id'] for x in result['items'] if result['total']}
        for item in data:
            item['captive_template_id'] = self.list_templates.get(item['captive_template_id'], -1)

            try:
                item['user_auth_profile_id'] = self.auth_profiles[item['user_auth_profile_id']]
            except KeyError:
                print(f'\t\033[33mПрофиль авторизации "{item["user_auth_profile_id"]}" не найден.\n\tЗагрузите профили авторизации и повторите попытку.\033[0m')
                item['user_auth_profile_id'] = 1

            if item['notification_profile_id'] != -1:
                try:
                    item['notification_profile_id'] = self.list_notifications[item['notification_profile_id']]
                except KeyError:
                    print(f'\t\033[33mПрофиль оповещения "{item["notification_profile_id"]}" не найден.\n\tЗагрузите профили оповещения и повторите попытку.\033[0m')
                    item['notification_profile_id'] = -1

            if item['ta_groups']:
                try:
                    item['ta_groups'] = [groups[name] for name in item['ta_groups']]
                except KeyError:
                    print(f'\t\033[33mГруппы "{item["ta_groups"]}" не найдены.\n\tЗагрузите локальные группы и повторите попытку.\033[0m')
                    item['ta_groups'] = []

            err, result = self.add_captive_profile(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_captive_profile(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tCaptive-профиль "{item["name"]}" добавлен.')

    def export_captive_portal_rules(self):
        """Выгрузить список правил Captive-портала"""
        print('Выгружается список "Captive-портал" раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        _, data = self.get_captive_portal_rules()

        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('rownumber', None)
            item.pop('position_layer', None),
            item['profile_id'] = self.captive_profiles.get(item['profile_id'], 0)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_urls_and_categories(item)
            self.set_time_restrictions(item)

        with open("data/users_and_devices/config_captive_portal_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Captive-портал" выгружен в файл "data/users_and_devices/config_captive_portal_rules.json".')


    def import_captive_portal_rules(self):
        """Импортировать список правил Captive-портала"""
        print('Импорт списка правил "Captive-портала" раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_captive_portal_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Captive-портал" не импортирован!\n\tНе найден файл "data/users_and_devices/config_captive_portal_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил Captive-портала для импорта.")
            return
        for item in data:
            if item['profile_id'] != 0:
                try:
                    item['profile_id'] = self.captive_profiles[item['profile_id']]
                except KeyError:
                    print(f'\t\033[33mCaptive-профиль "{item["profile_id"]}"  в правиле "{item["name"]}" не найден.\n\tЗагрузите Captive-профили и повторите попытку.\033[0m')
                    item['profile_id'] = 0
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_urls_and_categories(item)
            self.set_time_restrictions(item)

            err, result = self.add_captive_portal_rules(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_captive_portal_rule(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПравило Captive-портала "{item["name"]}" добавлено.')

    def export_byod_policy(self):
        """Выгрузить список Политики BYOD"""
        print('Выгружается список "Политики BYOD" раздела "Пользователи и устройства":')
        if not os.path.isdir('data/users_and_devices'):
            os.makedirs('data/users_and_devices')

        _, data = self.get_byod_policy()

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('position_layer', None),
            item.pop('deleted_users', None)
            self.get_names_users_and_groups(item)

        with open("data/users_and_devices/config_byod_policy.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Политики BYOD" выгружен в файл "data/users_and_devices/config_byod_policy.json".')

    def import_byod_policy(self):
        """Импортировать список Политики BYOD"""
        print('Импорт списка "Политики BYOD" раздела "Пользователи и устройства":')
        try:
            with open("data/users_and_devices/config_byod_policy.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Политики BYOD" не импортирован!\n\tНе найден файл "data/users_and_devices/config_byod_policy.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет политик BYOD для импорта.")
            return

        total, byods = self.get_byod_policy()
        self.byod_rules = {x['name']: x['id'] for x in byods if total}

        for item in data:
            self.get_guids_users_and_groups(item)
            err, result = self.add_byod_policy(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_byod_policy(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПравило BYOD "{item["name"]}" добавлено.')

    def export_firewall_rules(self):
        """Выгрузить список правил межсетевого экрана"""
        print('Выгружается список "Межсетевой экран" раздела "Политики сети":')
        if not os.path.isdir('data/network_policies'):
            os.makedirs('data/network_policies')

        _, data = self.get_firewall_rules()

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('position_layer', None),
            item.pop('deleted_users', None)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
            self.get_names_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_time_restrictions(item)
            item['services'] = [self.services[x] for x in item['services']]
            self.get_apps(item['apps'])

        with open("data/network_policies/config_firewall_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Межсетевой экран" выгружен в файл "data/network_policies/config_firewall_rules.json".')

    def import_firewall_rules(self):
        """Импортировать список правил межсетевого экрана"""
        print('Импорт списка "Межсетевой экран" раздела "Политики сети":')
        try:
            with open("data/network_policies/config_firewall_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Межсетевой экран" не импортирован!\n\tНе найден файл "data/network_policies/config_firewall_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил межсетевого экрана для импорта.")
            return

        total, firewall = self.get_firewall_rules()
        self.firewall_rules = {x['name']: x['id'] for x in firewall if total}

        for item in data:
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
                except KeyError as err:
                    print(f'\t\033[33mНе найден сценарий {err} для правила "{item["name"]}".\n\tЗагрузите сценарии и повторите попытку.\033[0m')
                    item['scenario_rule_id'] = False
            self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_time_restrictions(item)
            try:
                item['services'] = [self.services[x] for x in item['services']]
            except KeyError as err:
                print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
                item['services'] = []
            try:
                self.get_apps(item['apps'])
            except KeyError as err:
                print(f'\t\033[33mНе найдено приложение {err} для сценария "{item["name"]}".\n\tЗагрузите приложения и повторите попытку.\033[0m')
                item['apps'] = []

            err, result = self.add_firewall_rule(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_firewall_rule(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПравило МЭ "{item["name"]}" добавлено.')

    def export_nat_rules(self):
        """Выгрузить список правил NAT"""
        print('Выгружается список "NAT и маршрутизация" раздела "Политики сети":')
        if not os.path.isdir('data/network_policies'):
            os.makedirs('data/network_policies')

        _, data = self.get_traffic_rules()

        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item.pop('guid', None)
            item.pop('position_layer', None),
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
            if self.version.startswith('6'):
                self.get_names_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            item['service'] = [self.services[x] for x in item['service']]

        with open("data/network_policies/config_nat_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "NAT и маршрутизация" выгружен в файл "data/network_policies/config_nat_rules.json".')

    def import_nat_rules(self):
        """Импортировать список правил NAT"""
        print('Импорт списка "NAT и маршрутизация" раздела "Политики сети":')
        try:
            with open("data/network_policies/config_nat_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "NAT и маршрутизация" не импортирован!\n\tНе найден файл "data/network_policies/config_nat_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print('\tНет правил в списке "NAT и маршрутизация" для импорта.')
            return

        total, list_nat = self.get_traffic_rules()
        self.nat_rules = {x['name']: x['id'] for x in list_nat if total}

        for item in data:
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
                except KeyError as err:
                    print(f'\t\033[33mНе найден сценарий {err} для правила "{item["name"]}".\n\tЗагрузите сценарии и повторите попытку.\033[0m')
                    item['scenario_rule_id'] = False
            if self.version.startswith('6'):
                self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            try:
                item['service'] = [self.services[x] for x in item['service']]
            except KeyError as err:
                print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
                item['service'] = []
            if item['action'] == 'route':
                print(f'\t\033[33mПроверьте шлюз для правила ПБР "{item["name"]}".\n\tВ случае отсутствия, установите вручную.\033[0m')

            err, result = self.add_traffic_rule(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_traffic_rule(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПравило "{item["name"]}" добавлено.')

    def export_icap_servers(self):
        """Выгрузить список серверов ICAP"""
        print('Выгружается список "ICAP-серверы" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        _, data = self.get_icap_servers()

        for item in data:
            item.pop('id', None)
            item.pop('cc', None)

        with open("data/security_policies/config_icap_servers.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "ICAP-серверы" выгружен в файл "data/security_policies/config_icap_servers.json".')


    def import_icap_servers(self):
        """Импортировать список серверов ICAP"""
        print('Импорт списка "ICAP-серверы" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_icap_servers.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "ICAP-серверы" не импортирован!\n\tНе найден файл "data/security_policies/config_icap_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if data:
            total, icap = self.get_icap_servers()
            self.icap_servers = {x['name']: x['id'] for x in icap if total}

            for item in data:
                err, result = self.add_icap_server(item)
                if err == 1:
                    print(result, end= ' - ')
                    err1, result1 = self.update_icap_server(item)
                    if err1 != 0:
                        print("\n", f"\033[31m{result1}\033[0m")
                    else:
                        print("\033[32mUpdated!\033[0;0m")
                elif err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    print(f'\tICAP-сервер "{item["name"]}" добавлен.')
        else:
            print('\tНет записей в списке "ICAP-серверы" для импорта.')

    def export_loadbalancing_rules(self):
        """Выгрузить список правил балансировки нагрузки"""
        print('Выгружается список "Балансировка нагрузки" раздела "Политики сети":')
        if not os.path.isdir('data/network_policies'):
            os.makedirs('data/network_policies')

        total, data = self.get_icap_servers()
        self.icap_servers = {x['id']: x['name'] for x in data if total}
        total, data = self.get_reverseproxy_servers()
        self.reverse_servers = {x['id']: x['name'] for x in data if total}

        tcpudp, icap, reverse = self.get_loadbalancing_rules()

        for item in tcpudp:
            item.pop('id', None)
            item.pop('guid', None)
        for item in icap:
            item.pop('id', None)
            item['profiles'] = [self.icap_servers[x] for x in item['profiles']]
        for item in reverse:
            item.pop('id', None)
            item['profiles'] = [self.reverse_servers[x] for x in item['profiles']]

        with open("data/network_policies/config_loadbalancing_tcpudp.json", "w") as fd:
            json.dump(tcpudp, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок балансировщиков TCP/UDP выгружен в файл "data/network_policies/config_loadbalancing_tcpudp.json".')

        with open("data/network_policies/config_loadbalancing_icap.json", "w") as fd:
            json.dump(icap, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок балансировщиков ICAP выгружен в файл "data/network_policies/config_loadbalancing_icap.json".')

        with open("data/network_policies/config_loadbalancing_reverse.json", "w") as fd:
            json.dump(reverse, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок балансировщиков reverse-прокси выгружен в файл "data/network_policies/config_loadbalancing_reverse.json".')

    def import_loadbalancing_rules(self):
        """Импортировать список правил балансировки нагрузки"""
        print('Импорт списка "Балансировка нагрузки" раздела "Политики сети":')
        tcpudp, icap, reverse = self.get_loadbalancing_rules()
        self.tcpudp_rules = {x['name']: x['id'] for x in tcpudp}
        self.icap_loadbalancing = {x['name']: x['id'] for x in icap}
        self.reverse_rules = {x['name']: x['id'] for x in reverse}

        try:
            with open("data/network_policies/config_loadbalancing_tcpudp.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок балансировщиков TCP/UDP не импортирован!\n\tНе найден файл "data/network_policies/config_loadbalancing_tcpudp.json" с сохранённой конфигурацией!\033[0;0m')
        else:
            if data:
                for item in data:
                    err, result = self.add_virtualserver_rule(item)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_virtualserver_rule(item)
                        if err1 != 0:
                            print("\n", f"\033[31m{result1}\033[0m")
                        else:
                            print("\033[32mUpdated!\033[0;0m")
                    elif err == 2:
                        print(f"\033[31m{result}\033[0m")
                    else:
                        print(f'\tБалансировщик TCP/UDP "{item["name"]}" добавлен.')
            else:
                print('\tНет правил в списке балансировщиков TCP/UDP для импорта.')

        try:
            with open("data/network_policies/config_loadbalancing_icap.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок балансировщиков ICAP не импортирован!\n\tНе найден файл "data/network_policies/config_loadbalancing_icap.json" с сохранённой конфигурацией!\033[0;0m')
        else:
            total, icap = self.get_icap_servers()
            self.icap_servers = {x['name']: x['id'] for x in icap if total}

            if data:
                for item in data:
                    try:
                        item['profiles'] = [self.icap_servers[x] for x in item['profiles']]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден сервер ICAP {err} для правила "{item["name"]}".\n\tИмпортируйте серверы ICAP и повторите попытку.\033[0m')
                        item['profiles'] = []
                    err, result = self.add_icap_loadbalancing_rule(item)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_icap_loadbalancing_rule(item)
                        if err1 != 0:
                            print("\n", f"\033[31m{result1}\033[0m")
                        else:
                            print("\033[32mUpdated!\033[0;0m")
                    elif err == 2:
                        print(f"\033[31m{result}\033[0m")
                    else:
                        print(f'\tБалансировщик ICAP "{item["name"]}" добавлен.')
            else:
                print('\tНет правил в списке балансировщиков ICAP для импорта.')

        try:
            with open("data/network_policies/config_loadbalancing_reverse.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок балансировщиков reverse-proxy не импортирован!\n\tНе найден файл "data/network_policies/config_loadbalancing_reverse.json" с сохранённой конфигурацией!\033[0;0m')
        else:
            total, reverse = self.get_reverseproxy_servers()
            self.reverse_servers = {x['name']: x['id'] for x in reverse if total}

            if data:
                for item in data:
                    try:
                        item['profiles'] = [self.reverse_servers[x] for x in item['profiles']]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден сервер reverse-proxy {err} для правила "{item["name"]}".\n\tЗагрузите серверы reverse-proxy и повторите попытку.\033[0m')
                        item['profiles'] = []
                    err, result = self.add_reverse_loadbalancing_rule(item)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_reverse_loadbalancing_rule(item)
                        if err1 != 0:
                            print("\n", f"\033[31m{result1}\033[0m")
                        else:
                            print("\033[32mUpdated!\033[0;0m")
                    elif err == 2:
                        print(f"\033[31m{result}\033[0m")
                    else:
                        print(f'\tБалансировщик reverse-proxy "{item["name"]}" добавлен.')
            else:
                print('\tНет правил в списке балансировщиков reverse-proxy для импорта.')

    def export_shaper_rules(self):
        """Выгрузить список правил пропускной способности"""
        print('Выгружается список "Пропускная способность" раздела "Политики сети":')
        if not os.path.isdir('data/network_policies'):
            os.makedirs('data/network_policies')

        total, data = self.get_shaper_list()
        self.shaper = {x['id']: x['name'] for x in data if total}

        _, data = self.get_shaper_rules()

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('position_layer', None)
            item.pop('deleted_users', None)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
            self.get_names_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            item['services'] = [self.services[x] for x in item['services']]
            self.get_apps(item['apps'])
            self.set_time_restrictions(item)
            item['pool'] = self.shaper[item['pool']]

        with open("data/network_policies/config_shaper_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Пропускная способность" выгружен в файл "data/network_policies/config_shaper_rules.json".')

    def import_shaper_rules(self):
        """Импортировать список правил пропускной способности"""
        print('Импорт списка "Пропускная способность" раздела "Политики сети":')
        try:
            with open("data/network_policies/config_shaper_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Пропускная способность" не импортирован!\n\tНе найден файл "data/network_policies/config_shaper_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print('\tНет правил в списке "Пропускная способность" для импорта.')
            return

        _, shaperrules = self.get_shaper_rules()
        shaper_rules = {x['name']: x['id'] for x in shaperrules}

        for item in data:
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
                except KeyError as err:
                    print(f'\t\033[33mНе найден сценарий {err} для правила "{item["name"]}".\n\tЗагрузите сценарии и повторите попытку.\033[0m')
                    item['scenario_rule_id'] = False
            self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            try:
                item['services'] = [self.services[x] for x in item['services']]
            except KeyError as err:
                print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
                item['service'] = []
            try:
                self.get_apps(item['apps'])
            except KeyError as err:
                print(f'\t\033[33mНе найдено приложение {err} для правила "{item["name"]}".\n\tЗагрузите приложения и повторите попытку.\033[0m')
                item['apps'] = []
            self.set_time_restrictions(item)
            try:
                item['pool'] = self.shaper[item['pool']]
            except KeyError as err:
                print(f'\t\033[33mНе найден полоса пропускания {err} для правила "{item["name"]}".\n\tЗагрузите полосы пропускания и повторите попытку.\033[0m')
                item['pool'] = 1

            err, result = self.add_shaper_rule(shaper_rules, item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_shaper_rule(shaper_rules[item['name']], item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tПравило пропускной способности "{item["name"]}" добавлено.')

    def export_content_rules(self):
        """Выгрузить список правил фильтрации контента"""
        print('Выгружается список "Фильтрация контента" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        result = self._server.v2.nlists.list(self._auth_token, 'morphology', 0, 1000, {})
        self.list_morph = {x['id']: x['name'] for x in result['items'] if result['count']}
        result = self._server.v2.nlists.list(self._auth_token, 'useragent', 0, 1000, {})
        self.list_useragent = {x['id']: x['name'] for x in result['items'] if result['count']}

        _, data = self.get_content_rules()
        data.pop()    # удаляем последнее правило (защищённое).

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('position_layer', None)
            item.pop('deleted_users', None)
            item['blockpage_template_id'] = self.list_templates.get(item['blockpage_template_id'], -1)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
            self.get_names_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_time_restrictions(item)
            self.set_urls_and_categories(item)
            item['morph_categories'] = [self.list_morph[x] for x in item['morph_categories']]
            item['referers'] = [self.list_url[x] for x in item['referers']]
            for x in item['user_agents']:
                x[1] = self.list_useragent[x[1]] if x[0] == 'list_id' else x[1]
            item['content_types'] = [self.list_mime[x] for x in item['content_types']]
            if 'referer_categories' in item.keys():
                try:
                    for x in item['referer_categories']:
                        if x[0] == 'list_id':
                            x[1] = self.list_urlcategorygroup[x[1]]
                        elif x[0] == 'category_id':
                            x[1] = self._categories[x[1]]
                except KeyError as err:
                    print(f'\t\033[33mНе найдена группа URL-категорий {err} для правила "{item["name"]}".\n\tЗагрузите ктегории URL и повторите попытку.\033[0m')
                    item['referer_categories'] = []

        with open("data/security_policies/config_content_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Пропускная способность" выгружен в файл "data/security_policies/config_content_rules.json".')

    def import_content_rules(self):
        """Импортировать список правил фильтрации контента"""
        print('Импорт списка "Фильтрация контента" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_content_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Фильтрация контента" не импортирован!\n\tНе найден файл "data/security_policies/config_content_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил фильтрации контента для импорта.")
            return

        _, rules = self.get_content_rules()
        content_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            item['blockpage_template_id'] = self.list_templates.get(item['blockpage_template_id'], -1)
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.scenarios_rules[item['scenario_rule_id']]
                except KeyError as err:
                    print(f'\t\033[33mНе найден сценарий {err} для правила "{item["name"]}".\n\tЗагрузите сценарии и повторите попытку.\033[0m')
                    item['scenario_rule_id'] = False
            self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_time_restrictions(item)
            self.set_urls_and_categories(item)
            try:
                item['morph_categories'] = [self.list_morph[x] for x in item['morph_categories']]
            except KeyError as err:
                print(f'\t\033[33mНе найден список морфрлогии {err} для правила "{item["name"]}".\n\tЗагрузите списки морфологии и повторите попытку.\033[0m')
                item['morph_categories'] = []
            try:
                item['referers'] = [self.list_url[x] for x in item['referers']]
            except KeyError as err:
                print(f'\t\033[33mНе найден список URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
                item['referers'] = []
            try:
                for x in item['user_agents']:
                    x[1] = self.list_useragent[x[1]] if x[0] == 'list_id' else x[1]
            except KeyError as err:
                print(f'\t\033[33mНе найден useragent {err} для правила "{item["name"]}".\n\tЗагрузите список Useragent браузеров и повторите попытку.\033[0m')
                item['user_agents'] = []
            try:
                item['content_types'] = [self.list_mime[x] for x in item['content_types']]
            except KeyError as err:
                print(f'\t\033[33mНе найден тип контента {err} для правила "{item["name"]}".\n\tЗагрузите список типов контента и повторите попытку.\033[0m')
                item['content_types'] = []
            if 'referer_categories' in item.keys():
                try:
                    for x in item['referer_categories']:
                        if x[0] == 'list_id':
                            x[1] = self.list_urlcategorygroup[x[1]]
                        elif x[0] == 'category_id':
                            x[1] = self._categories[x[1]]
                except KeyError as err:
                    print(f'\t\033[33mНе найдена группа URL-категорий {err} для правила "{item["name"]}".\n\tЗагрузите ктегории URL и повторите попытку.\033[0m')
                    item['referer_categories'] = []

            if item['name'] in content_rules:
                print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
                err1, result1 = self.update_content_rule(content_rules[item['name']], item)
                if err1 == 2:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = self.add_content_rule(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    content_rules[item['name']] = result
                    print(f'\tПравило "{item["name"]}" добавлено.')

    def export_safebrowsing_rules(self):
        """Выгрузить список правил веб-безопасности"""
        print('Выгружается список "Веб-безопасность" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        _, data = self.get_safebrowsing_rules()

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('position_layer', None)
            item.pop('deleted_users', None)
            self.get_names_users_and_groups(item)
            self.set_time_restrictions(item)
            self.set_src_zone_and_ips(item)
            item['url_list_exclusions'] = [self.list_url[x] for x in item['url_list_exclusions']]

        with open("data/security_policies/config_safebrowsing_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Веб-безопасность" выгружен в файл "data/security_policies/config_safebrowsing_rules.json".')

    def import_safebrowsing_rules(self):
        """Импортировать список правил веб-безопасности"""
        print('Импорт списка "Веб-безопасность" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_safebrowsing_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Веб-безопасность" не импортирован!\n\tНе найден файл "data/security_policies/config_safebrowsing_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил веб-безопасности для импорта.")
            return

        _, rules = self.get_safebrowsing_rules()
        safebrowsing_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            self.get_guids_users_and_groups(item)
            self.set_time_restrictions(item)
            self.set_src_zone_and_ips(item)
            try:
                item['url_list_exclusions'] = [self.list_url[x] for x in item['url_list_exclusions']]
            except KeyError as err:
                print(f'\t\033[33mНе найден URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
                item['url_list_exclusions'] = []

            if item['name'] in safebrowsing_rules:
                print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
                err1, result1 = self.update_safebrowsing_rule(safebrowsing_rules[item['name']], item)
                if err1 == 2:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = self.add_safebrowsing_rule(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    safebrowsing_rules[item['name']] = result
                    print(f'\tПравило "{item["name"]}" добавлено.')

    def export_ssldecrypt_rules(self):
        """Выгрузить список правил инспектирования SSL"""
        print('Выгружается список "Инспектирование SSL" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        if self.version.startswith('6'):
            _, data = self.get_ssl_profiles_list()
            self.list_ssl_profiles = {x['id']: x['name'] for x in data}

        _, data = self.get_ssldecrypt_rules()

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('position_layer', None)
            item.pop('deleted_users', None)
            self.get_names_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_urls_and_categories(item)
            self.set_time_restrictions(item)
            item['ssl_profile_id'] = self.list_ssl_profiles[item['ssl_profile_id']] if 'ssl_profile_id' in item else 'Default SSL profile'

        with open("data/security_policies/config_ssldecrypt_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Инспектирование SSL" выгружен в файл "data/security_policies/config_ssldecrypt_rules.json".')

    def import_ssldecrypt_rules(self):
        """Импортировать список правил инспектирования SSL"""
        print('Импорт списка "Инспектирование SSL" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_ssldecrypt_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Инспектирование SSL" не импортирован!\n\tНе найден файл "data/security_policies/config_ssldecrypt_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил инспектирования SSL для импорта.")
            return

        _, rules = self.get_ssldecrypt_rules()
        ssldecrypt_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_urls_and_categories(item)
            self.set_time_restrictions(item)
            try:
                item['ssl_profile_id'] = self.list_ssl_profiles[item['ssl_profile_id']]
            except KeyError as err:
                print(f'\t\033[33mНе найден профиль SSL {err} для правила "{item["name"]}".\n\tЗагрузите профили SSL и повторите попытку.\033[0m')
                item['ssl_profile_id'] = self.list_ssl_profiles['Default SSL profile']

            if item['name'] in ssldecrypt_rules:
                print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
                err1, result1 = self.update_ssldecrypt_rule(ssldecrypt_rules[item['name']], item)
                if err1 == 2:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = self.add_ssldecrypt_rule(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    ssldecrypt_rules[item['name']] = result
                    print(f'\tПравило "{item["name"]}" добавлено.')

    def export_sshdecrypt_rules(self):
        """Выгрузить список правил инспектирования SSH"""
        if self.version.startswith('6'):
            print('Выгружается список "Инспектирование SSH" раздела "Политики безопасности":')
            if not os.path.isdir('data/security_policies'):
                os.makedirs('data/security_policies')

            _, data = self.get_sshdecrypt_rules()

            for item in data:
                item.pop('id', None)
                item.pop('rownumber', None)
                item.pop('guid', None)
                item.pop('position_layer', None)
                self.get_names_users_and_groups(item)
                self.set_src_zone_and_ips(item)
                self.set_dst_zone_and_ips(item)
                self.set_time_restrictions(item)
                item['protocols'] = [self.services[x] for x in item['protocols']]

            with open("data/security_policies/config_sshdecrypt_rules.json", "w") as fd:
                json.dump(data, fd, indent=4, ensure_ascii=False)
            print(f'\tСписок "Инспектирование SSH" выгружен в файл "data/security_policies/config_sshdecrypt_rules.json".')

    def import_sshdecrypt_rules(self):
        """Импортировать список правил инспектирования SSH"""
        print('Импорт списка "Инспектирование SSH" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_sshdecrypt_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Инспектирование SSH" не импортирован!\n\tНе найден файл "data/security_policies/config_sshdecrypt_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил инспектирования SSH для импорта.")
            return

        _, rules = self.get_sshdecrypt_rules()
        sshdecrypt_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_time_restrictions(item)
            try:
                item['protocols'] = [self.services[x] for x in item['protocols']]
            except KeyError as err:
                print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите список сервисов и повторите попытку.\033[0m')
                item['protocols'] = []

            if item['name'] in sshdecrypt_rules:
                print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
                err1, result1 = self.update_sshdecrypt_rule(sshdecrypt_rules[item['name']], item)
                if err1 == 2:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = self.add_sshdecrypt_rule(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    sshdecrypt_rules[item['name']] = result
                    print(f'\tПравило "{item["name"]}" добавлено.')

    def export_idps_rules(self):
        """Выгрузить список правил СОВ"""
        print('Выгружается список "СОВ" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        result = self._server.v2.nlists.list(self._auth_token, 'ipspolicy', 0, 1000, {})
        idps_profiles = {x['id']: x['name'] for x in result['items']}

        _, data = self.get_idps_rules()

        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('position_layer', None)
            item.pop('apps', None)
            item.pop('cc', None)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            item['services'] = [self.services[x] for x in item['services']]
            item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
            if self.version.startswith('6'):
                item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
            else:
                item['idps_profiles_exclusions'] = []

        with open("data/security_policies/config_idps_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "СОВ" выгружен в файл "data/security_policies/config_idps_rules.json".')

    def import_idps_rules(self):
        """Импортировать список правил СОВ"""
        print('Импорт списка "СОВ" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_idps_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "СОВ" не импортирован!\n\tНе найден файл "data/security_policies/config_idps_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил СОВ для импорта.")
            return

        result = self._server.v2.nlists.list(self._auth_token, 'ipspolicy', 0, 1000, {})
        idps_profiles = {x['name']: x['id'] for x in result['items']}

        _, rules = self.get_idps_rules()
        idps_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            try:
                item['services'] = [self.services[x] for x in item['services']]
            except KeyError as err:
                print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите список сервисов и повторите попытку.\033[0m')
                item['services'] = []
            try:
                item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
            except KeyError as err:
                print(f'\t\033[33mНе найден профиль СОВ {err} для правила "{item["name"]}".\n\tЗагрузите профили СОВ и повторите попытку.\033[0m')
                item['idps_profiles'] = []
            try:
                item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
            except KeyError as err:
                print(f'\t\033[33mНе найден профиль СОВ {err} для правила "{item["name"]}".\n\tЗагрузите профили СОВ и повторите попытку.\033[0m')
                item['idps_profiles_exclusions'] = []

            if item['name'] in idps_rules:
                print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
                err1, result1 = self.update_idps_rule(idps_rules[item['name']], item)
                if err1 == 2:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = self.add_idps_rule(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    idps_rules[item['name']] = result
                    print(f'\tПравило "{item["name"]}" добавлено.')

    def export_scada_rules(self):
        """Выгрузить список правил АСУ ТП"""
        print('Выгружается список "Правила АСУ ТП" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        _, result = self.get_scada_list()
        scada_profiles = {x['id']: x['name'] for x in result}

        _, data = self.get_scada_rules()

        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('position_layer', None)
            item.pop('cc', None)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            item['services'] = [self.services[x] for x in item['services']]
            item['scada_profiles'] = [scada_profiles[x] for x in item['scada_profiles']]

        with open("data/security_policies/config_scada_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Правила АСУ ТП" выгружен в файл "data/security_policies/config_scada_rules.json".')

    def import_scada_rules(self):
        """Импортировать список правил АСУ ТП"""
        print('Импорт списка "Правила АСУ ТП" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_scada_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Правила АСУ ТП" не импортирован!\n\tНе найден файл "data/security_policies/config_scada_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет правил АСУ ТП для импорта.")
            return

        _, rules = self.get_scada_rules()
        scada_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            try:
                item['services'] = [self.services[x] for x in item['services']]
            except KeyError as err:
                print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите список сервисов и повторите попытку.\033[0m')
                item['services'] = []
            try:
                item['scada_profiles'] = [self.list_scada[x] for x in item['scada_profiles']]
            except KeyError as err:
                print(f'\t\033[33mНе найден профиль СОВ {err} для правила "{item["name"]}".\n\tЗагрузите профили СОВ и повторите попытку.\033[0m')
                item['scada_profiles'] = []

            if item['name'] in scada_rules:
                print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
                err1, result1 = self.update_scada_rule(scada_rules[item['name']], item)
                if err1 == 2:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = self.add_scada_rule(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    scada_rules[item['name']] = result
                    print(f'\tПравило "{item["name"]}" добавлено.')

    def export_scenarios(self):
        """Выгрузить список сценариев"""
        print('Выгружается список "Сценарии" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        _, data = self.get_scenarios_rules()

        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('position_layer', None),
            item.pop('deleted_users', None)
            item.pop('cc', None)
            for condition in item['conditions']:
                if condition['kind'] == 'application':
                    self.get_apps(condition['apps'])
                elif condition['kind'] == 'mime_types':
                    condition['content_types'] = [self.list_mime[x] for x in condition['content_types']]
                elif condition['kind'] == 'url_category':
                    condition['url_categories'] = [[x[0], self.list_urlcategorygroup[x[1]] if x[0] == 'list_id' else self._categories[x[1]]] for x in condition['url_categories']]

        with open("data/security_policies/config_scenarios.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Сценарии" выгружен в файл "data/security_policies/config_scenarios.json".')

    def import_scenarios(self):
        """Импортировать список сценариев"""
        print('Импорт списка "Сценарии" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_scenarios.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Сценарии" не импортирован!\n\tНе найден файл "data/security_policies/config_scenarios.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет сценариев для импорта.")
            return

        for item in data:
            for condition in item['conditions']:
                if condition['kind'] == 'application':
                    try:
                        self.get_apps(condition['apps'])
                    except KeyError as err:
                        print(f'\t\033[33mНе найдено приложение {err} для сценария "{item["name"]}".\n\tЗагрузите приложения и повторите попытку.\033[0m')
                        condition['apps'] = []
                elif condition['kind'] == 'mime_types':
                    try:
                        condition['content_types'] = [self.list_mime[x] for x in condition['content_types']]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден тип контента {err} для сценария "{item["name"]}".\n\tЗагрузите типы контента и повторите попытку.\033[0m')
                        condition['content_types'] = []
                elif condition['kind'] == 'url_category':
                    try:
                        condition['url_categories'] = [[x[0], self.list_urlcategorygroup[x[1]] if x[0] == 'list_id' else self._categories[x[1]]] for x in condition['url_categories']]
                    except KeyError as err:
                        print(f'\t\033[33mНе найдена категория URL {err} для сценария "{item["name"]}".\n\tЗагрузите категории URL и повторите попытку.\033[0m')
                        condition['url_categories'] = []

            err, result = self.add_scenarios_rule(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_scenarios_rule(item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСценарий "{item["name"]}" добавлен.')

    def export_icap_rules(self):
        """Выгрузить список правил ICAP"""
        print('Выгружается список "ICAP-правила" раздела "Политики безопасности":')
        if not os.path.isdir('data/security_policies'):
            os.makedirs('data/security_policies')

        total, icapservers = self.get_icap_servers()
        self.icap_servers = {x['id']: x['name'] for x in icapservers if total}
        _, icaprules, _ = self.get_loadbalancing_rules()
        self.icap_loadbalancing = {x['id']: x['name'] for x in icaprules}

        _, data = self.get_icap_rules()

        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            for server in item['servers']:
                if server[0] == 'lbrule':
                    try:
                        server[1] = self.icap_loadbalancing[server[1]]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден балансировщик серверов ICAP {err} для правила "{item["name"]}".\n\tИмпортируйте балансировщики ICAP и повторите попытку.\033[0m')
                        item['servers'] = []
                elif server[0] == 'profile':
                    try:
                        server[1] = self.icap_servers[server[1]]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден сервер ICAP {err} для правила "{item["name"]}".\n\tИмпортируйте сервера ICAP и повторите попытку.\033[0m')
                        item['servers'] = []
            self.get_names_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_urls_and_categories(item)
            item['content_types'] = [self.list_mime[x] for x in item['content_types']]

        with open("data/security_policies/config_icap_rules.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "ICAP-правила" выгружен в файл "data/security_policies/config_icap_rules.json".')

    def import_icap_rules(self):
        """Импортировать список правил ICAP"""
        print('Импорт списка "ICAP-правила" раздела "Политики безопасности":')
        try:
            with open("data/security_policies/config_icap_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "ICAP-правила" не импортирован!\n\tНе найден файл "data/security_policies/config_icap_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        if not data:
            print("\tНет ICAP-правил для импорта.")
            return

        total, icapservers = self.get_icap_servers()
        self.icap_servers = {x['name']: x['id'] for x in icapservers if total}
        _, icap, _ = self.get_loadbalancing_rules()
        self.icap_loadbalancing = {x['name']: x['id'] for x in icap}
        total, icaprules = self.get_icap_rules()
        icap_rules = {x['name']: x['id'] for x in icaprules if total}

        for item in data:
            for server in item['servers']:
                if server[0] == 'lbrule':
                    try:
                        server[1] = self.icap_loadbalancing[server[1]]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден балансировщик серверов ICAP {err} для правила "{item["name"]}".\n\tИмпортируйте балансировщики ICAP и повторите попытку.\033[0m')
                        item['servers'] = []
                elif server[0] == 'profile':
                    try:
                        server[1] = self.icap_servers[server[1]]
                    except KeyError as err:
                        print(f'\t\033[33mНе найден сервер ICAP {err} для правила "{item["name"]}".\n\tИмпортируйте сервера ICAP и повторите попытку.\033[0m')
                        item['servers'] = []
            self.get_guids_users_and_groups(item)
            self.set_src_zone_and_ips(item)
            self.set_dst_zone_and_ips(item)
            self.set_urls_and_categories(item)
            item['content_types'] = [self.list_mime[x] for x in item['content_types']]

            err, result = self.add_icap_rule(icap_rules, item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_icap_rule(icap_rules, item)
                if err1 != 0:
                    print("\n", f"\033[31m{result1}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tICAP-правило "{item["name"]}" добавлено.')

################### ZONES #####################################
    def export_zones_list(self):
        """Выгрузить список зон"""
        print('Выгружается список "Зоны" раздела "Сеть":')
        if not os.path.isdir('data/network'):
            os.makedirs('data/network')

        _, data = self.get_zones_list()
        with open("data/network/config_zones.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок зон выгружен в файл 'data/network/config_zones.json'.")

    def import_zones(self):
        """Импортировать зоны на UTM"""
        print("Импорт зон:")
        try:
            with open("data/network/config_zones.json", "r") as fd:
                zones = json.load(fd)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Зоны" не импортирован!\n\tНе найден файл "data/network/config_zones.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in zones:
            if "cc" in item.keys():
                item.pop("cc")
            err, result = self.add_zone(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_zone(self.zones[item['name']], item)
                if err1 != 0:
                    print(result1)
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f"\tЗона '{item['name']}' добавлена.")

################### INTERFACES #################################
    def export_interfaces_list(self):
        """Выгрузить список интерфейсов"""
        _, zones = self.get_zones_list()
        for item in zones:
            self.zones[item['id']] = item['name']

        _, data = self.get_interfaces_list()
        for item in data:
            item['id'], _ = item['id'].split(':')
            item.pop('link_info', None)
            item.pop('speed', None)
            item.pop('errors', None)
            item.pop('node_name', None)
            item.pop('mac', None)
            item['enabled'] = False
            item['running'] = False
            if item['zone_id']:
                item['zone_id'] = self.zones[item['zone_id']]
            if self.version.startswith('5'):
                item.pop('iface_id', None)
                item.pop('qlen', None)
                item.pop('nameservers', None)
                item.pop('ifindex', None)
                if item['kind'] not in ('vpn', 'ppp', 'tunnel'):
                    if not item['dhcp_relay']:
                        item['dhcp_relay'] = {
                            'enabled': False,
                            'host_ipv4': '',
                            'servers': []
                        }
                    else:
                        item['dhcp_relay'].pop('id', None)
                        item['dhcp_relay'].pop('iface_id', None)
        data.sort(key=lambda x: x['name'])

        with open("config_interfaces.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\nСписок интерфейсов: {self.node_name}, ip: {self.server_ip} выгружен в файл 'config_interfaces.json'.")

    def import_interfaces(self):
        """Добавить/обновить интерфейс на UTM"""
        new_ports = {}
        dst_ports = {'': True,}
        _, data = self.get_interfaces_list()
        for item in data:
            dst_ports[item['name']] = item['enabled']
        available_ports = [x for x in sorted(dst_ports.keys()) if x != ''
                                                                 and not x.startswith('tunnel')
                                                                 and not x.startswith('bridge')
                                                                 and x.find('.') == -1]

        _, data = self.get_zones_list()
        zones = {x['name']: x['id'] for x in data}

        print(dst_ports)
        print(zones, '\n')

        try:
            with open("config_interfaces.json", "r") as fd:
                data = json.load(fd)
        except FileNotFoundError as err:
            raise UtmError(f"\nОшибка: [FileNotFoundError] Не найден файл 'config_interfaces.json' с сохранённой конфигурацией!")

        for item in data:
            if item['kind'] == 'adapter' and item['name'] not in dst_ports.keys():
                print(f"\nВы добавляете несуществующий порт: {item['name']}")
                print(f"Существуют следующие порты: {available_ports}")
                while True:
                    port = input("\nВведите имя порта или Enter, если данный порт не импортируется: ")
                    if port not in available_ports and port != '':
                        print("Вы ввели некорректный порт.")
                    else:
                        break
                new_ports[item['name']] = port
                item['id'] = port
                item['name'] = port
                if port != '':
                    available_ports.remove(port)

        for item in data:
            if item['kind'] == 'adapter':
                if dst_ports[item['name']]:
                    if item['name'] != '':
                        print(f"Пропускаем {item['name']} так как он включён.")
                    continue
                else:
                    print(f"Импортируем {item['name']}")
        for item in data:
            if item['kind'] == 'vlan':
                
                if item['name'] in dst_ports.keys():
                    if dst_ports[item['name'], ]:
                        print(f"Пропускаем {item['name']} так как он включён.")
                        continue
                    else:
                        print(f"Делаем update настроек порта {item['name']}")
                else:
                    print(f"Создаём новый порт {item['name']}")
                    

################### DHCP #################################
    def export_dhcp_subnets(self):
        """Выгрузить список DHCP"""
        print('Выгружается список "DHCP" раздела "Сеть":')
        if not os.path.isdir('data/network'):
            os.makedirs('data/network')

        _, data = self.get_dhcp_list()
        with open("data/network/config_dhcp_subnets.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок подсетей DHCP выгружен в файл 'data/network/config_dhcp_subnets.json'.")

    def import_dhcp_subnets(self):
        """Добавить DHCP subnets на UTM"""
        print("Импорт DHCP subnets:")
        try:
            with open("data/network/config_dhcp_subnets.json", "r") as fd:
                subnets = json.load(fd)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "DHCP" не импортирован!\n\tНе найден файл "data/network/config_dhcp_subnets.json.json" с сохранённой конфигурацией!\033[0;0m')
            return

        _, data = self.get_interfaces_list()
        dst_ports = [x['name'] for x in data if not x['name'].startswith('tunnel')]

        total, data = self.get_dhcp_list()
        old_dhcp_subtets = [x['name'] for x in data]

        for item in subnets:
            if item['name'] in old_dhcp_subtets:
                print(f'\tDHCP subnet "{item["name"]}" уже существует!')
                continue
            if item['iface_id'] not in dst_ports:
                print(f'\n\033[36mВы добавляете DHCP subnet\033[0m "{item["name"]}" \033[36mна несуществующий порт: \033[33m{item["iface_id"]}\033[0m')
                print(f"\033[36mСуществуют следующие порты:\033[0m {sorted(dst_ports)}")
                while True:
                    port = input("\n\033[36mВведите имя порта:\033[0m ")
                    if port not in dst_ports:
                        print("\033[31mВы ввели несуществующий порт.\033[0m")
                    else:
                        break
                item['iface_id'] = port

            if item['name'] == "":
                item['name'] = "No Name subnet" 
            if "cc" in item.keys():
                item.pop("cc")
                item.pop("node_name")
            err, result = self.add_dhcp_subnet(item)
            print(f"\033[31m{result}\033[0m") if err else print(f'\tSubnet "{item["name"]}" добавлен.')

################### DNS #################################
    def export_dns_config(self):
        """Выгрузить настройки DNS"""
        print('Выгружаются настройки DNS раздела "Сеть":')
        if not os.path.isdir('data/network'):
            os.makedirs('data/network')
        params = (
            'use_cache_enabled',
            'enable_dns_filtering',
            'recursive_enabled',
            'dns_max_ttl',
            'dns_max_queries_per_user',
            'only_a_for_unknown',
            'dns_receive_timeout',
            'dns_max_attempts'
        )

        dns_servers, dns_rules, static_records = self.get_dns_config()

        with open("data/network/config_dns_servers.json", "w") as fd:
            json.dump(dns_servers, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок системных DNS серверов выгружен в файл 'data/network/config_dns_servers.json'.")

        with open("data/network/config_dns_rules.json", "w") as fd:
            json.dump(dns_rules, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок правил DNS прокси выгружен в файл 'data/network/config_dns_rules.json'.")

        with open("data/network/config_dns_static.json", "w") as fd:
            json.dump(static_records, fd, indent=4, ensure_ascii=False)
        print(f"\tСтатические записи DNS прокси выгружены в файл 'data/network/config_dns_static.json'.")

        _, data = self.get_settings_params(params)
        with open("data/network/config_dns_proxy.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tНастройки DNS-прокси выгружены в файл 'data/network/config_dns_proxy.json'.")

    def import_dns_proxy(self):
        """Импортировать настройки DNS прокси"""
        try:
            with open("data/network/config_dns_proxy.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mНастройки DNS-прокси не импортированы!\n\tНе найден файл "data/network/config_dns_proxy.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for key, value in data.items():
            err, result = self.set_settings_param(key, value)
            if err == 2:
                print(f"\033[31m{result}\033[0m")
        print(f'\tНастройки DNS-прокси импортированы.')
            
    def import_dns_servers(self):
        """Импортировать список системных DNS серверов"""
        try:
            with open("data/network/config_dns_servers.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок системных DNS серверов не импортирован!\n\tНе найден файл "data/network/config_dns_servers.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in data:
            err, result = self.add_dns_server(item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tDNS сервер "{item["dns"]}" добавлен.')

    def import_dns_rules(self):
        """Импортировать список правил DNS прокси"""
        try:
            with open("data/network/config_dns_rules.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок правил DNS прокси не импортирован!\n\tНе найден файл "data/network/config_dns_rules.json" с сохранённой конфигурацией!\033[0;0m')
            return

        dns_rules = [x['name'] for x in self._server.v1.dns.rules.list(self._auth_token, 0, 1000, {})['items']]
        for item in data:
            if item['name'] in dns_rules:
                print(f'\tПравило DNS прокси "{item["name"]}" уже существует.')
            else:
                err, result = self.add_dns_rule(item)
                if err == 1:
                    print(result)
                elif err == 2:
                    print(f"\033[31m{result}\033[0m")
                else:
                    print(f'\tПравило DNS прокси "{item["name"]}" добавлено.')

    def import_dns_static(self):
        """Импортировать статические записи DNS прокси"""
        try:
            with open("data/network/config_dns_static.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСтатические записи DNS прокси не импортированы!\n\tНе найден файл "data/network/config_dns_static.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in data:
            err, result = self.add_dns_record(item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\tСтатическая запись DNS "{item["name"]}" добавлена.')
        
    def import_dns_config(self):
        """Импортировать настройки DNS"""
        print('Импорт настроек DNS раздела "Сеть":')
        self.import_dns_proxy()
        self.import_dns_servers()
        self.import_dns_rules()
        self.import_dns_static()

################################## Служебные функции ###################################
    def set_src_zone_and_ips(self, item):
        if 'src_zones' in item.keys():
            zone_name = 'src_zones'
            ip_name = 'src_ips'
        else:
            zone_name = 'zone_in'
            ip_name = 'source_ip'
        if item[zone_name]:
            try:
                item[zone_name] = [self.zones[x] for x in item[zone_name]]
            except KeyError as err:
                print(f'\t\033[33mИсходная зона {err} для правила "{item["name"]}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
                item[zone_name] = []
        if item[ip_name]:
            try:
                for x in item[ip_name]:
                    if x[0] == 'list_id':
                        x[1] = self.list_IP[x[1]]
                    elif x[0] == 'urllist_id':
                        x[1] = self.list_url[x[1]]
            except KeyError as err:
                print(f'\t\033[33mНе найден адрес источника {err} для правила "{item["name"]}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
                item[ip_name] = []

    def set_dst_zone_and_ips(self, item):
        if 'dst_ips' in item.keys():
            zone_name = 'dst_zones'
            ip_name = 'dst_ips'
        else:
            zone_name = 'zone_out'
            ip_name = 'dest_ip'
        if zone_name in item.keys() and item[zone_name]:
            try:
                item[zone_name] = [self.zones[x] for x in item[zone_name]]
            except KeyError as err:
                print(f'\t\033[33mЗона назначения {err} для правила "{item["name"]}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
                item[zone_name] = []
        if item[ip_name]:
            try:
                for x in item[ip_name]:
                    if x[0] == 'list_id':
                        x[1] = self.list_IP[x[1]]
                    elif x[0] == 'urllist_id':
                        x[1] = self.list_url[x[1]]
            except KeyError as err:
                print(f'\t\033[33mНе найден адрес назначения {err} для правила "{item["name"]}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
                item[ip_name] = []

    def set_urls_and_categories(self, item):
        if item['urls']:
            try:
                item['urls'] = [self.list_url[x] for x in item['urls']]
            except KeyError as err:
                print(f'\t\033[33mНе найден URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
                item['urls'] = []
        if item['url_categories']:
            try:
                for x in item['url_categories']:
                    if x[0] == 'list_id':
                        x[1] = self.list_urlcategorygroup[x[1]]
                    elif x[0] == 'category_id':
                        x[1] = self._categories[x[1]]
            except KeyError as err:
                print(f'\t\033[33mНе найдена группа URL-категорий {err} для правила "{item["name"]}".\n\tЗагрузите ктегории URL и повторите попытку.\033[0m')
                item['url_categories'] = []

    def set_time_restrictions(self, item):
        if item['time_restrictions']:
            try:
                item['time_restrictions'] = [self.list_calendar[x] for x in item['time_restrictions']]
            except KeyError as err:
                print(f'\t\033[33mНе найден календарь {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
                item['time_restrictions'] = []

    def get_apps(self, array_apps):
        """Определяем имя приложения по ID при экспорте и ID приложения по имени при импорте"""
        for app in array_apps:
            if app[0] == 'ro_group':
                if app[1] == 0:
                    app[1] = "All"
                elif app[1] == "All":
                    app[1] = 0
                else:
                    app[1] = self.l7_categories[app[1]]
            elif app[0] == 'group':
                app[1] = self.list_applicationgroup[app[1]]
            elif app[0] == 'app':
                app[1] = self.l7_apps[app[1]]

    def get_names_users_and_groups(self, item):
        """
        Получить имена групп и пользователей по их GUID.
        Заменяет GUID-ы на имена локальных и доменных пользователей и групп.
        """
        if item['users']:
            for x in item['users']:
                if x[0] == 'user':
                    try:
                        x[1] = self.list_users[x[1]]
                    except KeyError:
                        err, result = self.get_ldap_user_name(x[1])
                        if err != 0:
                            print(f"\033[31m{result}\033[0m")
                            x[1] = False
                        else:
                            x[1] = result
                elif x[0] == 'group':
                    try:
                        x[1] = self.list_groups[x[1]]
                    except KeyError:
                        err, result = self.get_ldap_group_name(x[1])
                        if err != 0:
                            print(f"\033[31m{result}\033[0m")
                            x[1] = False
                        else:
                            x[1] = result

    def get_guids_users_and_groups(self, item):
        """
        Получить GUID-ы групп и пользователей по их именам.
        Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
        """
        if 'users' in item.keys() and item['users']:
            users = []
            for x in item['users']:
                if x[0] == 'user' and x[1]:
                    i = x[1].partition("\\")
                    if i[2]:
                        err, result = self.get_ldap_user_guid(i[0], i[2])
                        if err != 0:
                            print(f"\033[31m{result}\033[0m")
                        elif not result:
                            print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                        else:
                            x[1] = result
                            users.append(x)
                    else:
                        x[1] = self.list_users[x[1]]
                        users.append(x)

                elif x[0] == 'group' and x[1]:
                    i = x[1].partition("\\")
                    if i[2]:
                        err, result = self.get_ldap_group_guid(i[0], i[2])
                        if err != 0:
                            print(f"\033[31m{result}\033[0m")
                        elif not result:
                            print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                        else:
                            x[1] = result
                            users.append(x)
                    else:
                        x[1] = self.list_groups[x[1]]
                        users.append(x)
                elif x[0] == 'special' and x[1]:
                    users.append(x)
            item['users'] = users
        else:
            item['users'] = []

def menu1():
    print("\033c")
    print("\033[1;36;43mUserGate\033[1;37;43m                      Экспорт / Импорт конфигурации                     \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма экспортирует настройки UTM в файлы json в каталог 'data' в текущей директории.")
    print("Вы можете изменить содержимое файлов и импортировать данные конфигурационные файлы в UTM.\033[0m\n")
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

def menu2(mode):
    print("\033c")
    print("\033[1;36;43mUserGate\033[1;37;43m                      Экспорт / Импорт конфигурации                     \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма экспортирует настройки UTM в файлы json в каталог 'data' в текущей директории.")
    print("Вы можете изменить содержимое файлов и импортировать данные конфигурационные файлы в UTM.\033[0m\n")
    print(f"Выберите раздел для {'экспорта' if mode == 1 else 'импорта'}.\n")
    print("1   - Библиотека")
    print("2   - Сеть")
    print("3   - Настройки")
    print("4   - Пользователи и устройства")
    print("5   - Политики сети")
    print("6   - Политики безопасности")
    print("\033[36m99  - Выбрать всё.\033[0m")
    print("\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m")
    print("\033[33m0   - Выход.\033[0m")
    while True:
        try:
            section = int(input(f"\nВведите номер раздела для {'экспорта' if mode == 1 else 'импорта'}: "))
            print("")
            if section not in [0, 1, 2, 3, 4, 5, 6, 99, 999]:
                print("Вы ввели номер несуществующего раздела.")
            elif section == 0:
                sys.exit()
            else:
                return section
        except ValueError:
            print("Ошибка! Введите число.")

def menu3(utm, mode, section):
    print("\033c")
    print("\033[1;36;43mUserGate\033[1;37;43m                      Экспорт / Импорт конфигурации                     \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма экспортирует настройки UTM в файлы json в каталог 'data' в текущей директории.")
    print("Вы можете изменить содержимое файлов и импортировать данные конфигурационные файлы в UTM.\033[0m\n")
    print(f"Выберите список для {'экспорта' if mode == 1 else 'импорта'}.\n")
    if mode == 1:
        if section == 1:
            print('1   - Экспортировать список "Морфология" раздела "Библиотеки".')
            print('2   - Экспортировать список "Сервисы" раздела "Библиотеки".')
            print('3   - Экспортировать список "IP-адреса" раздела "Библиотеки".')
            print('4   - Экспортировать список "UserAgent браузеров" раздела "Библиотеки".')
            print('5   - Экспортировать список "Типы контента" раздела "Библиотеки".')
            print('6   - Экспортировать список "Списки URL" раздела "Библиотеки".')
            print('7   - Экспортировать список "Календари" раздела "Библиотеки".')
            print('8   - Экспортировать список "Полосы пропускания" раздела "Библиотеки".')
            print('9   - Экспортировать список "Профили АСУ ТП" раздела "Библиотеки".')
            print('10  - Экспортировать список "Шаблоны страниц" раздела "Библиотеки".')
            print('11  - Экспортировать список "Категории URL" раздела "Библиотеки".')
            print('12  - Экспортировать список "Приложения" раздела "Библиотеки".')
            print('13  - Экспортировать список "Почтовые адреса" раздела "Библиотеки".')
            print('14  - Экспортировать список "Номера телефонов" раздела "Библиотеки".')
            print('15  - Экспортировать список "Профили СОВ" раздела "Библиотеки".')
            print('16  - Экспортировать список "Профили оповещений" раздела "Библиотеки".')
            print('17  - Экспортировать список "Профили netflow" раздела "Библиотеки".')
            if utm.version.startswith('6'):
                print('18  - Экспортировать список "Профили SSL" раздела "Библиотеки".')
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 2:
            print("1   - Экспортировать список Зон.")
#            print("2  - Экспортировать список интерфейсов.")
            print("3   - Экспортировать список подсетей DHCP.")
            print("4   - Экспортировать настройки DNS.")
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 3:
            print('1   - Экспортировать настройки NTP раздела "Настройки".')
            print('2   - Экспортировать настройки Модулей и кэширования HTTP раздела "Настройки".')
            print('3   - Экспортировать настройки Веб-портала раздела "Настройки".')
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 4:
            print("1   - Экспортировать список локальных групп.")
            print("2   - Экспортировать список локальных пользователей.")
            print('3   - Экспортировать список "Профили MFA".')
            print('4   - Экспортировать список "Серверы авторизации".')
            print('5   - Экспортировать список "Профили авторизации".')
            print('6   - Экспортировать список "Captive-профили".')
            print('7   - Экспортировать список "Captive-портал".')
            print('8   - Экспортировать список "Политики BYOD".')
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 5:
            print("1   - Экспортировать правила межсетевого экрана.")
            print("2   - Экспортировать правила NAT.")
            print("3   - Экспортировать правила балансировки нагрузки.")
            print("4   - Экспортировать правила пропускной способности.")
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 6:
            print("1   - Экспортировать правила фильтрации контента.")
            print("2   - Экспортировать правила веб-безопасности.")
            print("3   - Экспортировать правила инспектирования SSL.")
            if utm.version.startswith('6'):
                print("4   - Экспортировать правила инспектирования SSH.")
            print("5   - Экспортировать правила СОВ.")
            print("6   - Экспортировать правила АСУ ТП.")
            print("7   - Экспортировать сценарии.")
            print('9   - Экспортировать список "ICAP-серверы".')
            print('10   - Экспортировать список "ICAP-правила".')
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
    else:
        if section == 1:
            print("1   - Импортировать списки морфологии.")
            print('2   - Импортировать список "Сервисы" раздела "Библиотеки".')
            print('3   - Импортировать список "IP-адреса" раздела "Библиотеки".')
            print('4   - Импортировать список "UserAgent браузеров" раздела "Библиотеки".')
            print('5   - Импортировать список "Типы контента" раздела "Библиотеки".')
            print('6   - Импортировать "Список URL" раздела "Библиотеки".')
            print('7   - Импортировать список "Календари" раздела "Библиотеки".')
            print('8   - Импортировать список "Полосы пропускания" раздела "Библиотеки".')
            print('9   - Импортировать список "Профили АСУ ТП" раздела "Библиотеки".')
            print('10  - Импортировать список "Шаблоны страниц" раздела "Библиотеки".')
            print('11  - Импортировать список "Категории URL" раздела "Библиотеки".')
            print('12  - Импортировать список "Приложения" раздела "Библиотеки".')
            print('13  - Импортировать список "Почтовые адреса" раздела "Библиотеки".')
            print('14  - Импортировать список "Номера телефонов" раздела "Библиотеки".')
            print('15  - Импортировать список "Профили СОВ" раздела "Библиотеки".')
            print('16  - Импортировать список "Профили оповещений" раздела "Библиотеки".')
            print('17  - Импортировать список "Профили netflow" раздела "Библиотеки".')
            if utm.version.startswith('6'):
                print('18  - Импортировать список "Профили SSL" раздела "Библиотеки".')
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 2:
            print("1   - Импортировать список Зон.")
#            print("2  - Импортировать список интерфейсов.")
            print("3   - Импортировать список подсетей DHCP.")
            print("4   - Импортировать настройки DNS.")
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 3:
            print("1   - Импортировать настройки NTP.")
            print('2   - Импортировать настройки Модулей и кэширования HTTP раздела "Настройки".')
#            print('3   - Импортировать настройки Веб-портала раздела "Настройки".')
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 4:
            print("1   - Импортировать список локальных групп.")
            print("2   - Импортировать список локальных пользователей.")
            print('3   - Импортировать список "Профили MFA".')
            print("4   - Импортировать список серверов авторизации LDAP.")
            print("5   - Импортировать список серверов авторизации NTLM.")
            print("6   - Импортировать список серверов авторизации RADIUS.")
            print("7   - Импортировать список серверов авторизации TACACS.")
            print("8   - Импортировать список серверов авторизации SAML.")
            print('9   - Импортировать список "Профили авторизации".')
            print('10  - Импортировать список "Captive-профили".')
            print('11  - Импортировать список "Captive-портал".')
            print('12  - Импортировать список "Политики BYOD".')
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 5:
            print("1   - Импортировать Сценарии.")
            print("2   - Импортировать правила межсетевого экрана.")
            print("3   - Импортировать правила NAT.")
            print('4   - Импортировать список "ICAP-серверы".')
            print("6   - Импортировать правила балансировки нагрузки.")
            print("7   - Импортировать правила пропускной способности.")
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 6:
            print('1   - Импортировать список "Фильтрация контента".')
            print('2   - Импортировать список "Веб-безопасность".')
            print('3   - Импортировать список "Инспектирование SSL".')
            print('4   - Импортировать список "Инспектирование SSH".')
            print('5   - Импортировать правила "СОВ".')
            print('6   - Импортировать список "Правила АСУ ТП".')
            print('8   - Импортировать список "ICAP-правила".')
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")

    while True:
        try:
            command = int(input("\nВведите номер нужной операции: "))
            print("")
            if command not in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 99, 999]:
                print("Вы ввели несуществующую команду.")
            elif command == 0:
                sys.exit()
            else:
                return command
        except ValueError:
            print("Ошибка! Введите число.")

def main():
    print("\033c")
    print("\033[1;36;43mUserGate\033[1;37;43m                      Экспорт / Импорт конфигурации                     \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма экспортирует настройки UTM в файлы json в каталог 'data' в текущей директории.")
    print("Вы можете изменить содержимое файлов и импортировать данные конфигурационные файлы в UTM.\033[0m\n")
    try:
        server_ip = input("\033[36mВведите IP-адрес UTM:\033[0m ")
        login = input("\033[36mВведите логин администратора UTM:\033[0m ")
        password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        exit()

    try:
        utm = UTM(server_ip, login, password)
        while True:
            mode = menu1()
            while True:
                section = menu2(mode)
                if section == 999:
                    break
                elif section == 99:
                    command = 99
                    break
                command = menu3(utm, mode, section)
                if command != 999:
                    break
            if section != 999:
                break

        command = section * 100 + command
        utm.init_struct()
        if mode ==1:
            if not os.path.isdir('data'):
                os.mkdir('data')
                print("Создана директория 'data' в текущем каталоге.")
            utm.init_struct_for_export()
            try:
                if command == 101:
                    utm.export_morphology_lists()
                elif command == 102:
                    utm.export_services_list()
                elif command == 103:
                    utm.export_IP_lists()
                elif command == 104:
                    utm.export_useragent_lists()
                elif command == 105:
                    utm.export_mime_lists()
                elif command == 106:
                    utm.export_url_lists()
                elif command == 107:
                    utm.export_time_restricted_lists()
                elif command == 108:
                    utm.export_shaper_list()
                elif command == 109:
                    utm.export_scada_list()
                elif command == 110:
                    utm.export_templates_list()
                elif command == 111:
                    utm.export_categories_groups()
                elif command == 112:
                    utm.export_application_groups()
                elif command == 113:
                    utm.export_nlist_groups('emailgroup')
                elif command == 114:
                    utm.export_nlist_groups('phonegroup')
                elif command == 115:
                    utm.export_ips_profiles()
                elif command == 116:
                    utm.export_notification_profiles_list()
                elif command == 117:
                    utm.export_netflow_profiles_list()
                elif command == 118:
                    utm.export_ssl_profiles_list()
                elif command == 199:
                    utm.export_morphology_lists()
                    utm.export_services_list()
                    utm.export_IP_lists()
                    utm.export_useragent_lists()
                    utm.export_mime_lists()
                    utm.export_url_lists()
                    utm.export_time_restricted_lists()
                    utm.export_shaper_list()
                    utm.export_scada_list()
                    utm.export_templates_list()
                    utm.export_categories_groups()
                    utm.export_application_groups()
                    utm.export_nlist_groups('emailgroup')
                    utm.export_nlist_groups('phonegroup')
                    utm.export_ips_profiles()
                    utm.export_notification_profiles_list()
                    utm.export_netflow_profiles_list()
                    utm.export_ssl_profiles_list()

                elif command == 201:
                    utm.export_zones_list()
#                elif command == 202:
#                    utm.export_interfaces_list()
                elif command == 203:
                    utm.export_dhcp_subnets()
                elif command == 204:
                    utm.export_dns_config()
                elif command == 299:
                    utm.export_zones_list()
                    utm.export_dhcp_subnets()
                    utm.export_dns_config()

                elif command == 301:
                    utm.export_ntp()
                elif command == 302:
                    utm.export_settings()
                elif command == 303:
                    utm.export_proxy_portal()
                elif command == 399:
                    utm.export_ntp()
                    utm.export_settings()
                    utm.export_proxy_portal()

                elif command == 401:
                    utm.export_groups_lists()
                elif command == 402:
                    utm.export_users_lists()
                elif command == 403:
                    utm.export_2fa_profiles()
                elif command == 404:
                    utm.export_auth_servers()
                elif command == 405:
                    utm.export_auth_profiles()
                elif command == 406:
                    utm.export_captive_profiles()
                elif command == 407:
                    utm.export_captive_portal_rules()
                elif command == 408:
                    utm.export_byod_policy()
                elif command == 499:
                    utm.export_groups_lists()
                    utm.export_users_lists()
                    utm.export_2fa_profiles()
                    utm.export_auth_servers()
                    utm.export_auth_profiles()
                    utm.export_captive_profiles()
                    utm.export_captive_portal_rules()
                    utm.export_byod_policy()

                elif command == 501:
                    utm.export_firewall_rules()
                elif command == 502:
                    utm.export_nat_rules()
                elif command == 503:
                    utm.export_loadbalancing_rules()
                elif command == 504:
                    utm.export_shaper_rules()
                elif command == 599:
                    utm.export_firewall_rules()
                    utm.export_nat_rules()
                    utm.export_loadbalancing_rules()
                    utm.export_shaper_rules()

                elif command == 601:
                    utm.export_content_rules()
                elif command == 602:
                    utm.export_safebrowsing_rules()
                elif command == 603:
                    utm.export_ssldecrypt_rules()
                elif command == 604:
                    utm.export_sshdecrypt_rules()
                elif command == 605:
                    utm.export_idps_rules()
                elif command == 606:
                    utm.export_scada_rules()
                elif command == 607:
                    utm.export_scenarios()
                elif command == 609:
                    utm.export_icap_servers()
                elif command == 610:
                    utm.export_icap_rules()
                elif command == 699:
                    utm.export_content_rules()
                    utm.export_safebrowsing_rules()
                    utm.export_ssldecrypt_rules()
                    utm.export_sshdecrypt_rules()
                    utm.export_idps_rules()
                    utm.export_scada_rules()
                    utm.export_scenarios()
                    utm.export_icap_servers()
                    utm.export_icap_rules()

                elif command == 9999:
                    utm.export_morphology_lists()
                    utm.export_services_list()
                    utm.export_IP_lists()
                    utm.export_useragent_lists()
                    utm.export_mime_lists()
                    utm.export_url_lists()
                    utm.export_time_restricted_lists()
                    utm.export_shaper_list()
                    utm.export_scada_list()
                    utm.export_templates_list()
                    utm.export_categories_groups()
                    utm.export_application_groups()
                    utm.export_nlist_groups('emailgroup')
                    utm.export_nlist_groups('phonegroup')
                    utm.export_ips_profiles()
                    utm.export_notification_profiles_list()
                    utm.export_netflow_profiles_list()
                    utm.export_ssl_profiles_list()
                    utm.export_zones_list()
                    utm.export_dhcp_subnets()
                    utm.export_dns_config()
                    utm.export_ntp()
                    utm.export_settings()
                    utm.export_proxy_portal()
                    utm.export_groups_lists()
                    utm.export_users_lists()
                    utm.export_2fa_profiles()
                    utm.export_auth_servers()
                    utm.export_auth_profiles()
                    utm.export_captive_profiles()
                    utm.export_captive_portal_rules()
                    utm.export_byod_policy()
                    utm.export_firewall_rules()
                    utm.export_nat_rules()
                    utm.export_loadbalancing_rules()
                    utm.export_shaper_rules()
                    utm.export_content_rules()
                    utm.export_safebrowsing_rules()
                    utm.export_ssldecrypt_rules()
                    utm.export_sshdecrypt_rules()
                    utm.export_idps_rules()
                    utm.export_scada_rules()
                    utm.export_scenarios()
                    utm.export_icap_servers()
                    utm.export_icap_rules()
            except UtmError as err:
                print(err)
            except Exception as err:
                print(f'\n\033[31mОшибка ug_convert_config/main(): {err} (Node: {server_ip}).\033[0m')
            finally:
                utm.logout()
                print("\033[32mЭкспорт конфигурации завершён.\033[0m\n")
        else:
            if utm.version.startswith('6'):
                utm.init_struct_for_import()
                try:
                    if command == 101:
                        utm.import_morphology()
                    elif command == 102:
                        utm.import_services()
                    elif command == 103:
                        utm.import_IP_lists()
                    elif command == 104:
                        utm.import_useragent_lists()
                    elif command == 105:
                        utm.import_mime_lists()
                    elif command == 106:
                        utm.import_url_lists()
                    elif command == 107:
                        utm.import_time_restricted_lists()
                    elif command == 108:
                        utm.import_shaper()
                    elif command == 109:
                        utm.import_scada_list()
                    elif command == 110:
                        utm.import_templates_list()
                    elif command == 111:
                        utm.import_categories_groups()
                    elif command == 112:
                        utm.import_application_groups()
                    elif command == 113:
                        utm.import_nlist_groups('emailgroup')
                    elif command == 114:
                        utm.import_nlist_groups('phonegroup')
                    elif command == 115:
                        utm.import_ips_profiles()
                    elif command == 116:
                        utm.import_notification_profiles()
                    elif command == 117:
                        utm.import_netflow_profiles()
                    elif command == 118:
                        utm.import_ssl_profiles()
                    elif command == 199:
                        utm.import_morphology()
                        utm.import_services()
                        utm.import_IP_lists()
                        utm.import_useragent_lists()
                        utm.import_mime_lists()
                        utm.import_url_lists()
                        utm.import_time_restricted_lists()
                        utm.import_shaper()
                        utm.import_scada_list()
                        utm.import_templates_list()
                        utm.import_categories_groups()
                        utm.import_application_groups()
                        utm.import_nlist_groups('emailgroup')
                        utm.import_nlist_groups('phonegroup')
                        utm.import_ips_profiles()
                        utm.import_notification_profiles()
                        utm.import_netflow_profiles()
                        utm.import_ssl_profiles()
                    elif command == 201:
                        utm.import_zones()
#                    elif command == 202:
#                        utm.import_interfaces()
                    elif command == 203:
                        utm.import_dhcp_subnets()
                    elif command == 204:
                        utm.import_dns_config()
                    elif command == 299:
                        utm.import_zones()
                        utm.import_dhcp_subnets()
                        utm.import_dns_config()

                    elif command == 301:
                        utm.import_ntp()
                    elif command == 302:
                        utm.import_settings()
                    elif command == 399:
                        utm.import_ntp()
                        utm.import_settings()

                    elif command == 401:
                        utm.import_groups_list()
                    elif command == 402:
                        utm.import_users_list()
                    elif command == 403:
                        utm.import_2fa_profiles()
                    elif command == 404:
                        utm.import_ldap_server()
                    elif command == 405:
                        utm.import_ntlm_server()
                    elif command == 406:
                        utm.import_radius_server()
                    elif command == 407:
                        utm.import_tacacs_server()
                    elif command == 408:
                        utm.import_saml_server()
                    elif command == 409:
                        utm.import_auth_profiles()
                    elif command == 410:
                        utm.import_captive_profiles()
                    elif command == 411:
                        utm.import_captive_portal_rules()
                    elif command == 412:
                        utm.import_byod_policy()
                    elif command == 499:
                        utm.import_groups_list()
                        utm.import_users_list()
                        utm.import_2fa_profiles()
                        utm.import_ldap_server()
                        utm.import_ntlm_server()
                        utm.import_radius_server()
                        utm.import_tacacs_server()
                        utm.import_saml_server()
                        utm.import_auth_profiles()
                        utm.import_captive_profiles()
                        utm.import_captive_portal_rules()
                        utm.import_byod_policy()
                        
                    elif command == 501:
                        utm.import_scenarios()
                    elif command == 502:
                        utm.import_firewall_rules()
                    elif command == 503:
                        utm.import_nat_rules()
                    elif command == 504:
                        utm.import_icap_servers()
                    elif command == 506:
                        utm.import_loadbalancing_rules()
                    elif command == 507:
                        utm.import_shaper_rules()
                    elif command == 599:
                        utm.import_scenarios()
                        utm.import_firewall_rules()
                        utm.import_nat_rules()
                        utm.import_icap_servers()
                        utm.import_loadbalancing_rules()
                        utm.import_shaper_rules()

                    elif command == 601:
                        utm.import_content_rules()
                    elif command == 602:
                        utm.import_safebrowsing_rules()
                    elif command == 603:
                        utm.import_ssldecrypt_rules()
                    elif command == 604:
                        utm.import_sshdecrypt_rules()
                    elif command == 605:
                        utm.import_idps_rules()
                    elif command == 606:
                        utm.import_scada_rules()
                    elif command == 608:
                        utm.import_icap_rules()
                    elif command == 699:
                        utm.import_content_rules()
                        utm.import_safebrowsing_rules()
                        utm.import_ssldecrypt_rules()
                        utm.import_sshdecrypt_rules()
                        utm.import_idps_rules()
                        utm.import_scada_rules()
                        utm.import_icap_rules()

                    elif command == 9999:
                        utm.import_morphology()
                        utm.import_services()
                        utm.import_IP_lists()
                        utm.import_useragent_lists()
                        utm.import_mime_lists()
                        utm.import_url_lists()
                        utm.import_time_restricted_lists()
                        utm.import_shaper()
                        utm.import_scada_list()
                        utm.import_templates_list()
                        utm.import_categories_groups()
                        utm.import_application_groups()
                        utm.import_nlist_groups('emailgroup')
                        utm.import_nlist_groups('phonegroup')
                        utm.import_ips_profiles()
                        utm.import_notification_profiles()
                        utm.import_netflow_profiles()
                        utm.import_ssl_profiles()
                        utm.import_zones()
                        utm.import_dhcp_subnets()
                        utm.import_dns_config()
                        utm.import_ntp()
                        utm.import_settings()
                        utm.import_groups_list()
                        utm.import_users_list()
                        utm.import_2fa_profiles()
                        utm.import_ldap_server()
                        utm.import_ntlm_server()
                        utm.import_radius_server()
                        utm.import_tacacs_server()
                        utm.import_saml_server()
                        utm.import_auth_profiles()
                        utm.import_captive_profiles()
                        utm.import_captive_portal_rules()
                        utm.import_byod_policy()
                        utm.import_scenarios()
                        utm.import_firewall_rules()
                        utm.import_nat_rules()
                        utm.import_icap_servers()
                        utm.import_loadbalancing_rules()
                        utm.import_shaper_rules()
                        utm.import_content_rules()
                        utm.import_safebrowsing_rules()
                        utm.import_ssldecrypt_rules()
                        utm.import_sshdecrypt_rules()
                        utm.import_idps_rules()
                        utm.import_scada_rules()
                        utm.import_icap_rules()
                except UtmError as err:
                    print(err)
                except Exception as err:
                    print(f'\n\033[31mОшибка ug_convert_config/main(): {err} (Node: {server_ip}).\033[0m')
                finally:
                    utm.logout()
                    print("\033[32mИмпорт конфигурации завершён.\033[0m\n")
            else:
                print("\033[31mВы подключились к UTM 5-ой версии. Импорт конфигурации доступен только на версию 6.\033[0m")
                
    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.\n")
        utm.logout()
    except:
        print("\nПрограмма завершена.\n")

if __name__ == '__main__':
    main()
