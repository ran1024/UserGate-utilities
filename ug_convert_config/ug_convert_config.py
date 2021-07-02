#!/usr/bin/python3
#
# Программа предназначена для переноса конфигурации с UTM версии 5 на версию 6
# или между устройствами 6-ой версии.
#
import os, sys, ipaddress
import stdiomask
import json
from utm import UtmXmlRpc, UtmError


class UTM(UtmXmlRpc):
    def __init__(self, server_ip, login, password):
        super().__init__(server_ip, login, password)
        self._categories = {}         # Список Категорий URL
        self.zones = {}               # Список зон {name: id}
        self.services = {}            # Список сервисов раздела библиотеки {name: id}
        self.shaper = {}              # Список полос пропускания раздела библиотеки {name: id}
        self.list_morph = {}          # Списки морфлолгии раздела библиотеки {name: id}
        self.list_IP = {}             # Списки IP-адресов раздела библиотеки  {name: id}
        self.list_useragent = {}      # Списки UserAgent раздела библиотеки  {name: id}
        self.list_mime = {}           # Списки mime групп типов контента раздела библиотеки  {name: id}
        self.list_url = {}            # Списки URL раздела библиотеки  {name: id}
        self.list_calendar = {}       # Списки календарей раздела библиотеки  {name: id}
        self.list_scada = {}          # Списки профилей АСУ ТП раздела библиотеки  {name: id}
        self.list_templates = {}      # Списки шаблонов страниц раздела библиотеки  {name: id}
        self.l7_categories = {}       # Список L7 категорий
        self.l7_apps = {}             # Список L7 приложений
        self.list_notifications = {}  # Список профилей оповещения {name: id}
        self.list_netflow = {}        # Список профилей netflow {name: id}
        self.list_ssl_profiles = {}   # Список профилей ssl {name: id}
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
            
        except rpc.Fault as err:
            print(f"\033[31mОшибка ug_convert_config/init_struct_for_export(): [{err.faultCode}] {err.faultString}\033[0m")

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
        
################### Библиотеки ################################
    def export_morphology_lists(self):
        """Выгружает списки морфологии и преобразует формат атрибутов списков к версии 6"""
        print("Выгружаются списки морфологии раздела Библиотеки:")
        if os.path.isdir('data/morphology'):
            for file_name in os.listdir('data/morphology'):
                os.remove(f"data/morphology/{file_name}")
        else:
            os.mkdir('data/morphology')

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
            with open(f"data/morphology/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tСписок морфологии: {item['name']} выгружен в файл data/morphology/{item['name']}.json")

    def import_morphology(self):
        """Импортировать списки морфологии на UTM"""
        print("Импорт списков морфологии раздела Библиотеки:")
        if os.path.isdir('data/morphology'):
            files_list = os.listdir('data/morphology')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/morphology/{file_name}", "r") as fh:
                            morph_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Морфология" не импортирован!\n\tНе найден файл "data/morphology/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = morph_list.pop('content')
                    err, result = self.add_nlist(morph_list)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_nlist(self.list_morph[morph_list['name']], morph_list)
                        if err1 != 0:
                            print(result1)
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(result)
                    else:
                        for item in content:
                            err2, result2 = self.add_nlist_item(result, item)
                            if err2 != 0:
                                print(result2)
                        print(f"\tДобавлен список морфологии: '{morph_list['name']}'.")
            else:
                print("\t\033[33mНет списков морфологии для импорта.\033[0m")
        else:
            print("\t\033[33mНет списков морфологии для импорта.\033[0m")

    def export_services_list(self):
        """Выгрузить список сервисов раздела библиотеки"""
        print("Выгружается список сервисов раздела Библиотеки:")
        data = {}
        _, data = self.get_services_list()
        for item in data['items']:
            item.pop('id')
            item.pop('guid')
            item.pop('cc', None)
            item.pop('readonly', None)
        with open("data/config_services.json", "w") as fh:
            json.dump(data['items'], fh, indent=4, ensure_ascii=False)
        print(f"\tСписок сервисов: выгружен в файл 'data/config_services.json'.")

    def import_services(self):
        """Импортировать список сервисов раздела библиотеки"""
        print("Импорт списка сервисов раздела Библиотеки:")
        try:
            with open("data/config_services.json", "r") as fh:
                services = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Сервисы" не импортирован!\n\tНе найден файл "data/config_services.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in services:
            err, result = self.add_service(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_service(self.services[item['name']], item)
                if err1 != 0:
                    print(result1)
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f"\tСервис '{item['name']}' добавлен.")

    def export_IP_lists(self):
        """Выгружает списки IP-адресов и преобразует формат атрибутов списков к версии 6"""
        print("Выгружаются списки IP-адресов раздела Библиотеки:")
        if os.path.isdir('data/ip_lists'):
            for file_name in os.listdir('data/ip_lists'):
                os.remove(f"data/ip_lists/{file_name}")
        else:
            os.mkdir('data/ip_lists')

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
            with open(f"data/ip_lists/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tСписок IP-адресов: {item['name']} выгружен в файл data/ip_lists/{item['name']}.json")

    def import_IP_lists(self):
        """Импортировать списки IP адресов"""
        print("Импорт списков IP-адресов:")
        if os.path.isdir('data/ip_lists'):
            files_list = os.listdir('data/ip_lists')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/ip_lists/{file_name}", "r") as fh:
                            ip_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "IP-адреса" не импортирован!\n\tНе найден файл "data/ip_lists/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = ip_list.pop('content')
                    err, result = self.add_nlist(ip_list)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_nlist(self.list_IP[ip_list['name']], ip_list)
                        if err1 != 0:
                            print(result1)
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(result)
                    else:
                        for item in content:
                            err2, result2 = self.add_nlist_item(result, item)
                            if err2 != 0:
                                print(result2)
                        print(f"\tДобавлен список IP-адресов: '{ip_list['name']}'.")
            else:
                print("\033[33m\tНет списков IP-адресов для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков IP-адресов для импорта.\033[0m")

    def export_useragent_lists(self):
        """Выгружает списки useragent и преобразует формат атрибутов списков к версии 6"""
        print("Выгружаются списки Useragent браузеров раздела Библиотеки:")
        if os.path.isdir('data/useragent_lists'):
            for file_name in os.listdir('data/useragent_lists'):
                os.remove(f"data/useragent_lists/{file_name}")
        else:
            os.mkdir('data/useragent_lists')

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
            with open(f"data/useragent_lists/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tСписок Useragent браузеров: '{item['name']}' выгружен в файл data/useragent_lists/{item['name']}.json")

    def import_useragent_lists(self):
        """Импортировать списки Useragent браузеров"""
        print('Импорт списков "Useragent браузеров" раздела Библиотеки:')
        if os.path.isdir('data/useragent_lists'):
            files_list = os.listdir('data/useragent_lists')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/useragent_lists/{file_name}", "r") as fh:
                            useragent_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Useragent браузеров" не импортирован!\n\tНе найден файл "data/useragent_lists/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = useragent_list.pop('content')
                    err, result = self.add_nlist(useragent_list)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_nlist(self.list_useragent[useragent_list['name']], useragent_list)
                        if err1 != 0:
                            print(result1)
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(result)
                    else:
                        for item in content:
                            err2, result2 = self.add_nlist_item(result, item)
                            if err2 != 0:
                                print(result2)
                        print(f"\tДобавлен список Useragent: '{useragent_list['name']}'.")
            else:
                print("\033[33m\tНет списков Useragent для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков Useragent для импорта.\033[0m")

    def export_mime_lists(self):
        """Выгружает списки Типов контента и преобразует формат атрибутов списков к версии 6"""
        print("Выгружаются списки Типов контента (mime типы) раздела Библиотеки:")
        if os.path.isdir('data/mime_lists'):
            for file_name in os.listdir('data/mime_lists'):
                os.remove(f"data/mime_lists/{file_name}")
        else:
            os.mkdir('data/mime_lists')

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
            with open(f"data/mime_lists/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tСписок Типов контента: '{item['name']}' выгружен в файл data/mime_lists/{item['name']}.json")

    def import_mime_lists(self):
        """Импортировать списки Типов контента"""
        print("Импорт списков Типа контента:")
        if os.path.isdir('data/mime_lists'):
            files_list = os.listdir('data/mime_lists')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/mime_lists/{file_name}", "r") as fh:
                            mime_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Типы контента" не импортирован!\n\tНе найден файл "data/mime_lists/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = mime_list.pop('content')
                    err, result = self.add_nlist(mime_list)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_nlist(self.list_mime[mime_list['name']], mime_list)
                        if err1 != 0:
                            print(result1)
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(result)
                    else:
                        for item in content:
                            err2, result2 = self.add_nlist_item(result, item)
                            if err2 != 0:
                                print(result2)
                        print(f"\tДобавлен список Типов контента: '{mime_list['name']}'.")
            else:
                print("\033[33m\tНет списков Типа контента для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков Типов контента для импорта.\033[0m")

    def export_url_lists(self):
        """Выгружает списки URL и преобразует формат атрибутов списков к версии 6"""
        print("Выгружаются списки URL раздела Библиотеки:")
        if os.path.isdir('data/url'):
            for file_name in os.listdir('data/url'):
                os.remove(f"data/url/{file_name}")
        else:
            os.mkdir('data/url')

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
            with open(f"data/url/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tСписок URL: {item['name']} выгружен в файл data/url/{item['name']}.json")

    def import_url_lists(self):
        """Импортировать списки URL на UTM"""
        print("Импорт списков URL:")
        if os.path.isdir('data/url'):
            files_list = os.listdir('data/url')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/url/{file_name}", "r") as fh:
                            url_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Списки URL" не импортирован!\n\tНе найден файл "data/url/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = url_list.pop('content')
                    err, result = self.add_nlist(url_list)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_nlist(self.list_url[url_list['name']], url_list)
                        if err1 != 0:
                            print(result1)
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(result)
                    else:
                        for item in content:
                            err2, result2 = self.add_nlist_item(result, item)
                            if err2 != 0:
                                print(result2)
                        print(f"\tДобавлен список URL: '{url_list['name']}'.")
            else:
                print("\033[33m\tНет списков URL для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков URL для импорта.\033[0m")

    def export_time_restricted_lists(self):
        """Выгружает содержимое календарей и преобразует формат атрибутов списков к версии 6"""
        print("Выгружаются списки Календарей раздела Библиотеки:")
        if os.path.isdir('data/calendars'):
            for file_name in os.listdir('data/calendars'):
                os.remove(f"data/calendars/{file_name}")
        else:
            os.mkdir('data/calendars')

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
            with open(f"data/calendars/{item['name']}.json", "w") as fd:
                json.dump(item, fd, indent=4, ensure_ascii=False)
            print(f"\tЭлемент календаря: '{item['name']}' выгружен в файл data/calendars/{item['name']}.json")

    def import_time_restricted_lists(self):
        """Импортировать содержимое календарей"""
        print("Импорт списков Календарей:")
        if os.path.isdir('data/calendars'):
            files_list = os.listdir('data/calendars')
            if files_list:
                for file_name in files_list:
                    try:
                        with open(f"data/calendars/{file_name}", "r") as fh:
                            cal_list = json.load(fh)
                    except FileNotFoundError as err:
                        print(f'\t\033[31mСписок "Календари" не импортирован!\n\tНе найден файл "data/calendars/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                        return

                    content = cal_list.pop('content')
                    err, result = self.add_nlist(cal_list)
                    if err == 1:
                        print(result, end= ' - ')
                        err1, result1 = self.update_nlist(self.list_calendar[cal_list['name']], cal_list)
                        if err1 != 0:
                            print("\n", result1)
                        else:
                            print("\033[32mOk!\033[0;0m")
                    elif err == 2:
                        print(result)
                    else:
                        for item in content:
                            err2, result2 = self.add_nlist_item(result, item)
                            if err2 != 0:
                                print(result2)
                        print(f"\tДобавлен элемент календаря: '{cal_list['name']}'.")
            else:
                print("\033[33m\tНет списков Календарей для импорта.\033[0m")
        else:
            print("\033[33m\tНет списков Календарей для импорта.\033[0m")

    def export_shaper_list(self):
        """Выгрузить список Полос пропускания раздела библиотеки"""
        print('Выгружается список "Полосы пропускания" раздела "Библиотеки":')
        data = {}
        _, data = self.get_shaper_list()
        for item in data:
            item.pop('id')
            item.pop('guid')
            item.pop('cc', None)
        with open("data/config_shaper.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Полосы пропускания" выгружен в файл "data/config_shaper.json".')

    def import_shaper(self):
        """Импортировать список Полос пропускания раздела библиотеки"""
        print('Импорт списка "Полосы пропускания" раздела "Библиотеки":')
        try:
            with open("data/config_shaper.json", "r") as fh:
                shaper = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Полосы пропускания" не импортирован!\n\tНе найден файл "data/config_shaper.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in shaper:
            err, result = self.add_shaper(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_shaper(self.shaper[item['name']], item)
                if err1 != 0:
                    print("\n", result1)
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tПолоса пропускания "{item["name"]}" добавлена.')

    def export_scada_list(self):
        """Выгрузить список профилей АСУ ТП раздела библиотеки"""
        print('Выгружается список "Профили АСУ ТП" раздела "Библиотеки":')
        data = {}
        _, data = self.get_scada_list()
        for item in data:
            item.pop('id')
            item.pop('cc', None)
        with open("data/config_scada.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили АСУ ТП" выгружен в файл "data/config_scada.json".')

    def import_scada_list(self):
        """Импортировать список профилей АСУ ТП раздела библиотеки"""
        print('Импорт списка "Профили АСУ ТП" раздела "Библиотеки":')
        try:
            with open("data/config_scada.json", "r") as fh:
                scada = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили АСУ ТП" не импортирован!\n\tНе найден файл "data/config_scada.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in scada:
            err, result = self.add_scada(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_scada(self.list_scada[item['name']], item)
                if err1 != 0:
                    print("\n", result1)
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tПрофиль АСУ ТП "{item["name"]}" добавлен.')

    def export_templates_list(self):
        """
        Выгрузить список шаблонов страниц раздела библиотеки.
        Выгружает файл HTML только для изменённых страниц шаблонов.
        """
        print('Выгружается список "Шаблоны страниц" раздела "Библиотеки":')
        if os.path.isdir('data/templates'):
            for file_name in os.listdir('data/templates'):
                os.remove(f"data/templates/{file_name}")
        else:
            os.mkdir('data/templates')

        data = {}
        _, data = self.get_templates_list()
        for item in data:
            _, html_data = self.get_template_data(item['type'], item['id'])
            if html_data:
                with open(f"data/templates/{item['name']}.html", "w") as fh:
                    fh.write(html_data)
                print(f'\tСтраница HTML для шаблона "{item["name"]}" выгружена в файл "data/templates/{item["name"]}.html".')
            item.pop('id')
            item.pop('last_update', None)
            item.pop('cc', None)
        with open("data/templates/config_templates.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Шаблоны страниц" выгружен в файл "data/templates/config_templates.json".')

    def import_templates_list(self):
        """
        Импортировать список шаблонов страниц раздела библиотеки.
        После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
        """
        print('Импорт списка "Шаблоны страниц" раздела "Библиотеки":')
        try:
            with open("data/templates/config_templates.json", "r") as fh:
                templates = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Шаблоны страниц" не импортирован!\n\tНе найден файл "data/templates/config_templates.json" с сохранённой конфигурацией!\033[0;0m')
            return

        html_files = os.listdir('data/templates')

        for item in templates:
            err, result = self.add_template(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_template(self.list_templates[item['name']], item)
                if err1 != 0:
                    print("\n", result1)
                else:
                    print("\033[32mOk!\033[0;0m")
                if f"{item['name']}.html" in html_files:
                    with open(f"data/templates/{item['name']}.html", "br") as fh:
                        file_data = fh.read()
                    _, result2 = self.set_template_data(self.list_templates[item['name']], file_data)
                    if result2:
                        print(f'\t\tСтраница "{item["name"]}.html" добавлена.')
            elif err == 2:
                print(result)
            else:
                print(f'\tШаблон страницы "{item["name"]}" добавлен.')
                if f"{item['name']}.html" in html_files:
                    with open(f"data/templates/{item['name']}.html", "br") as fh:
                        file_data = fh.read()
                    _, result2 = self.set_template_data(result, file_data)
                    if result2:
                        print(f'\t\tСтраница "{item["name"]}.html" добавлена.')

    def export_categories_groups(self):
        """Выгружает список "Категории URL" и преобразует формат атрибутов списков к версии 6"""
        print('Выгружается список "Категории URL" раздела "Библиотеки":')
        group_name = {
            'URL_CATEGORY_GROUP_PARENTAL_CONTROL': 'Parental Control',
            'URL_CATEGORY_GROUP_PRODUCTIVITY': 'Productivity',
            'URL_CATEGORY_GROUP_SAFE': 'Safe categories',
            'URL_CATEGORY_GROUP_THREATS': 'Threats',
            'URL_CATEGORY_MORPHO_RECOMMENDED': 'Recommended for morphology checking',
            'URL_CATEGORY_VIRUSCHECK_RECOMMENDED': 'Recommended for virus check'
        }
        group_name_revert = {v: k for k, v in group_name.items()}
        total, data = self.get_nlist_list('urlcategorygroup')

        for item in data:
            item.pop('id')
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            item.pop('last_update', None)
            item['name'] = group_name.get(item['name'], item['name'])
            if self.version.startswith('5'):
                item['guid'] = group_name_revert.get(item['name'], item['guid'])
            for content in item['content']:
                content.pop('id')
                if self.version.startswith('5'):
                    content['category_id'] = content.pop('value')
                    content['name'] = self._categories[int(content['category_id'])]

        with open("data/config_categories_url.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Категории URL" выгружен в файл data/config_categories_url.json')

    def import_categories_groups(self):
        """Импортировать список "Категории URL" на UTM"""
        print('Импорт списка "Категории URL":')
        try:
            with open("data/config_categories_url.json", "r") as fh:
                category_list = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Категории URL" не импортирован!\n\tНе найден файл "data/config_categories_url.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in category_list:
            content = item.pop('content')
            if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                    'Recommended for morphology checking', 'Recommended for virus check']:
                err, result = self.add_nlist(item)
                if err == 1:
                    print(result, "\033[32mOk!\033[0;0m")
                elif err == 2:
                    print(result)
                else:
                    print(f'\tГруппа URL категорий "{item["name"]}" добавлена.')
                    for category in content:
                        try:
                            err2, result2 = self.add_nlist_item(result, category)
                            if err2 != 0:
                                print(f'\t{result2}')
                            else:
                                print(f'\t\tДобавлена категория: "{category["name"]}".')
                        except:
                            print(f'\t\tКатегория "{category["name"]}" не будет добавлена, так как не существует на целевой системе.')

    def export_application_groups(self):
        """Выгружает список "Приложения" и преобразует формат атрибутов списков к версии 6"""
        print('Выгружается список "Приложения" раздела "Библиотеки":')
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

        with open("data/config_applications.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Приложения" выгружен в файл data/config_applications.json')

    def import_application_groups(self):
        """Импортировать список "Приложения" на UTM"""
        print('Импорт списка "Приложения":')
        try:
            with open("data/config_applications.json", "r") as fh:
                app_list = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Приложения" не импортирован!\n\tНе найден файл "data/config_applications.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in app_list:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, "\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tГруппа приложений "{item["name"]}" добавлена.')
                for app in content:
                    try:
                        err2, result2 = self.add_nlist_item(result, self.l7_apps[app['value']])
                        if err2 != 0:
                            print(f'\t{result2}')
                        else:
                            print(f'\t\tДобавлено приложение: "{app["value"]}".')
                    except:
                        print(f'\t\tПриложение "{app["value"]}" не будет добавлена, так как не существует на целевой системе.')

    def export_nlist_groups(self, list_type):
        """Выгружает списки: "Почтовые адреса", "Номера телефонов" и преобразует формат списков к версии 6"""
        list_name = {
            'emailgroup': "Почтовые адреса",
            'phonegroup': "Номера телефонов"
            }
        print(f'Выгружается список "{list_name[list_type]}" раздела "Библиотеки":')
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

        with open(f"data/config_{list_type}.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "{list_name[list_type]}" выгружен в файл data/config_{list_type}.json')

    def import_nlist_groups(self, list_type):
        """Импортировать списки: "Почтовые адреса" и "Номера телефонов" на UTM"""
        list_name = {
            'emailgroup': ["Почтовые адреса", "адресов", "адрес"],
            'phonegroup': ["Номера телефонов", "номеров", "номер"],
            }
        print(f'Импорт списка "{list_name[list_type][0]}":')
        try:
            with open(f"data/config_{list_type}.json", "r") as fh:
                email_list = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "{list_name[list_type][0]}" не импортирован!\n\tНе найден файл "data/config_{list_type}.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in email_list:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, "\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tГруппа {list_name[list_type][1]} "{item["name"]}" добавлена.')
                for email in content:
                    try:
                        err2, result2 = self.add_nlist_item(result, email)
                        if err2 != 0:
                            print(f'\t{result2}')
                        else:
                            print(f'\t\tДобавлен {list_name[list_type][2]}: "{email["value"]}".')
                    except:
                        print(f'\t\tПочтовый адрес "{email["value"]}" не будет добавлен, так как произошла ошибка при добавлении.')

    def export_ips_profiles(self):
        """Выгружает списки: "Профили СОВ" и преобразует формат списков к версии 6"""
        print(f'Выгружается список "Профили СОВ" раздела "Библиотеки":')
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
                content.pop('l10n', None)
                content.pop('action', None)
                content.pop('bugtraq', None)
                content.pop('cve', None)
                content.pop('nessus', None)
                if 'threat_level' in content.keys():
                    content['threat'] = content.pop('threat_level')

        with open(f"data/config_ips_profiles.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили СОВ" выгружен в файл data/config_ips_profiles.json')

    def import_ips_profiles(self):
        """Импортировать списки: "Профили СОВ" на UTM"""
        print(f'Импорт списка "Профили СОВ":')
        try:
            with open(f"data/config_ips_profiles.json", "r") as fh:
                email_list = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили СОВ" не импортирован!\n\tНе найден файл "data/config_ips_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        _, idps = self.get_idps_signatures_list()

        for item in email_list:
            content = item.pop('content')
            err, result = self.add_nlist(item)
            if err == 1:
                print(result, "\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tПрофиль СОВ "{item["name"]}" добавлен.')
                for signature in content:
                    try:
                        signature['id'] = idps[signature['msg']]
                        err2, result2 = self.add_nlist_item(result, {'id': signature['id']})
                        if err2 == 1:
                            print(f'\t{result2}')
                        else:
                            print(f'\t\tДобавлена сигнатура: "{signature["msg"]}".')
                    except:
                        print(f'\t\tСигнатура "{signature["msg"]}":\n\t\t\tне будет добавлена, так как отсутствует на целевой системе!')

    def export_notification_profiles_list(self):
        """Выгрузить список профилей оповещения раздела библиотеки"""
        print('Выгружается список "Профили оповещений" раздела "Библиотеки":')
        data = {}
        _, data = self.get_notification_profiles_list()
        for item in data:
            item.pop('cc', None)
        with open("data/config_notification_profiles.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили оповещений" выгружен в файл "data/config_notification_profiles.json".')

    def import_notification_profiles(self):
        """Импортировать список профилей оповещения раздела библиотеки"""
        print('Импорт списка "Профили оповещений" раздела "Библиотеки":')
        try:
            with open("data/config_notification_profiles.json", "r") as fh:
                profiles = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили оповещений" не импортирован!\n\tНе найден файл "data/config_notification_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in profiles:
            err, result = self.add_notification_profile(item)
            if err == 1:
                print(result, end= ' - ')
                err1, result1 = self.update_notification_profile(item)
                if err1 != 0:
                    print("\n", result1)
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tПрофиль оповещения "{item["name"]}" добавлен.')

    def export_netflow_profiles_list(self):
        """Выгрузить список профилей netflow раздела библиотеки"""
        print('Выгружается список "Профили netflow" раздела "Библиотеки":')
        data = {}
        _, data = self.get_netflow_profiles_list()
        for item in data:
            item.pop('cc', None)
        with open("data/config_netflow_profiles.json", "w") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        print(f'\tСписок "Профили netflow" выгружен в файл "data/config_netflow_profiles.json".')

    def import_netflow_profiles(self):
        """Импортировать список профилей netflow раздела библиотеки"""
        print('Импорт списка "Профили netflow" раздела "Библиотеки":')
        try:
            with open("data/config_netflow_profiles.json", "r") as fh:
                profiles = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Профили netflow" не импортирован!\n\tНе найден файл "data/config_netflow_profiles.json" с сохранённой конфигурацией!\033[0;0m')
            return

        for item in profiles:
            err, result = self.add_netflow_profile(item)
            if err == 1:
                print(result, end= ' - ')
                item['id'] = self.list_netflow[item['name']]
                err1, result1 = self.update_netflow_profile(item)
                if err1 != 0:
                    print("\n", result1)
                else:
                    print("\033[32mOk!\033[0;0m")
            elif err == 2:
                print(result)
            else:
                print(f'\tПрофиль netflow "{item["name"]}" добавлен.')

    def export_ssl_profiles_list(self):
        """Выгрузить список профилей SSL раздела библиотеки"""
        if self.version.startswith('6'):
            print('Выгружается список "Профили SSL" раздела "Библиотеки":')
            data = {}
            _, data = self.get_ssl_profiles_list()
            for item in data:
                item.pop('cc', None)
            with open("data/config_ssl_profiles.json", "w") as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            print(f'\tСписок "Профили SSL" выгружен в файл "data/config_ssl_profiles.json".')

    def import_ssl_profiles(self):
        """Импортировать список профилей SSL раздела библиотеки"""
        if self.version.startswith('6'):
            print('Импорт списка "Профили SSL" раздела "Библиотеки":')
            try:
                with open("data/config_ssl_profiles.json", "r") as fh:
                    profiles = json.load(fh)
            except FileNotFoundError as err:
                print(f'\t\033[31mСписок "Профили SSL" не импортирован!\n\tНе найден файл "data/config_ssl_profiles.json" с сохранённой конфигурацией!\033[0;0m')
                return

            for item in profiles:
                err, result = self.add_ssl_profile(item)
                if err == 1:
                    print(result, end= ' - ')
                    item['id'] = self.list_ssl_profiles[item['name']]
                    err1, result1 = self.update_ssl_profile(item)
                    if err1 != 0:
                        print("\n", result1)
                    else:
                        print("\033[32mOk!\033[0;0m")
                elif err == 2:
                    print(result)
                else:
                    print(f'\tПрофиль SSL "{item["name"]}" добавлен.')

################### ZONES #####################################
    def export_zones_list(self):
        """Выгрузить список зон"""
        print('Выгружается список "Зоны" раздела "Сеть":')
        data = {}
        _, data = self.get_zones_list()
        with open("data/config_zones.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок зон: выгружен в файл 'data/config_zones.json'.")

    def import_zones(self):
        """Импортировать зоны на UTM"""
        print("Импорт зон:")
        try:
            with open("data/config_zones.json", "r") as fd:
                zones = json.load(fd)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "Зоны" не импортирован!\n\tНе найден файл "data/config_zones.json" с сохранённой конфигурацией!\033[0;0m')
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
                print(f"\tЗона '{item['name']}' добавлена на узел: {self.node_name}, ip: {self.server_ip}.")

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
        data = {}
        _, data = self.get_dhcp_list()
        with open("data/config_dhcp_subnets.json", "w") as fd:
            json.dump(data, fd, indent=4, ensure_ascii=False)
        print(f"\tСписок подсетей DHCP: выгружен в файл 'data/config_dhcp_subnets.json'.")

    def import_dhcp_subnets(self):
        """Добавить DHCP subnets на UTM"""
        print("Импорт DHCP subnets:")
        _, data = self.get_interfaces_list()
        dst_ports = [x['name'] for x in data if not x['name'].startswith('tunnel')]

        try:
            with open("data/config_dhcp_subnets.json", "r") as fd:
                subnets = json.load(fd)
        except FileNotFoundError as err:
            print(f'\t\033[31mСписок "DHCP" не импортирован!\n\tНе найден файл "data/config_dhcp_subnets.json.json" с сохранённой конфигурацией!\033[0;0m')
            return

        src_ports = {x['iface_id']: '' for x in subnets}
        for port in src_ports.keys():
            if port in dst_ports:
                src_ports[port] = port
            else:
                print(f"\nВы добавляете DHCP subnet на несуществующий порт: {port}")
                print(f"Существуют следующие порты: {sorted(dst_ports)}")
                while True:
                    command = input("\nВведите имя порта: ")
                    if command not in dst_ports:
                        print("Вы ввели несуществующий порт.")
                    else:
                        break
                src_ports[port] = command

        for item in subnets:
            if item['name'] == "":
                item['name'] = "No Name subnet" 
            if "cc" in item.keys():
                item.pop("cc")
                item.pop("node_name")
            item['iface_id'] = src_ports[item['iface_id']]
            err, result = self.add_dhcp_subnet(item)
            print(result) if err else print(f"\tSubnet '{item['name']}' добавлен на node: {self.node_name}, ip: {self.server_ip}.")

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
    print("3   - Пользователи и устройства")
    print("\033[36m99  - Выбрать всё.\033[0m")
    print("\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m")
    print("\033[33m0   - Выход.\033[0m")
    while True:
        try:
            section = int(input(f"\nВведите номер раздела для {'экспорта' if mode == 1 else 'импорта'}: "))
            print("")
            if section not in [0, 1, 2, 3, 99, 999]:
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
            print("1  - Экспортировать список Зон.")
#            print("2  - Экспортировать список интерфейсов.")
            print("3  - Экспортировать список подсетей DHCP.")
            print('\033[36m99  - Экспортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 3:
            pass
    else:
        if section == 1:
            print("1  - Импортировать списки морфологии.")
            print('2  - Импортировать список "Сервисы" раздела "Библиотеки".')
            print('3  - Импортировать список "IP-адреса" раздела "Библиотеки".')
            print('4  - Импортировать список "UserAgent браузеров" раздела "Библиотеки".')
            print('5  - Импортировать список "Типы контента" раздела "Библиотеки".')
            print('6  - Импортировать "Список URL" раздела "Библиотеки".')
            print('7  - Импортировать список "Календари" раздела "Библиотеки".')
            print('8  - Импортировать список "Полосы пропускания" раздела "Библиотеки".')
            print('9  - Импортировать список "Профили АСУ ТП" раздела "Библиотеки".')
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
            print("\n1  - Импортировать список Зон.")
#            print("2  - Импортировать список интерфейсов.")
            print("3  - Импортировать список подсетей DHCP.")
            print('\033[36m99  - Импортировать всё.\033[0m')
            print('\033[35m999 - Вверх (вернуться в предыдущее меню).\033[0m')
            print("\033[33m0   - Выход.\033[0m")
        elif section == 3:
            pass

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

#        print(command)
        command = section * 100 + command
#        print(command)
#        exit()
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
                elif command == 299:
                    utm.export_zones_list()
                    utm.export_dhcp_subnets()
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
            except UtmError as err:
                print(err)
            except Exception as err:
                print(f'\n\033[31mОшибка ug_convert_config: {err} (Node: {server_ip}).\033[0m')
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
                    elif command == 299:
                        utm.import_zones()
                        utm.import_dhcp_subnets()
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
                except UtmError as err:
                    print(err)
                except Exception as err:
                    print(f'\n\033[31mОшибка ug_convert_config: {err} (Node: {server_ip}).\033[0m')
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
