#!/usr/bin/python3
# Общий класс для работы с xml-rpc
import sys
import xmlrpc.client as rpc


class UtmXmlRpc:
    def __init__(self, server_ip, login, password):
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4040/rpc'
        self._auth_token = None
        self._server = None
        self.version = None
        self.server_ip = server_ip
        self.node_name = None
        self.auth_servers = {}  # Список серверов авторизации {name: id}

    def _connect(self):
        """Подключиться к UTM"""
        try:
            self._server = rpc.ServerProxy(self._url, verbose=False)
            if self.get_node_status() == 'work':
                result = self._server.v2.core.login(self._login, self._password, {'origin': 'dev-script'})
                self._auth_token = result.get('auth_token')
                self.node_name =  result.get('node')
                self.version = result.get('version')
            else:
                print('Ошибка: UTM не позволяет установить соединение!')
                sys.exit(1)
        except OSError as err:
            print(f'Ошибка: {err} (Node: {self.server_ip}).')
            sys.exit(1)
        except rpc.ProtocolError as err:
            print(f'Ошибка: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).')
            sys.exit(1)
        except rpc.Fault as err:
            print(f'Ошибка: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).')
            sys.exit(1)
        return 0

    def get_node_status(self):
        """Получить статус узла"""
        result = self._server.v2.core.node.status()
        return result.get('status')

    def logout(self):
        try:
            if self._server is not None and self._auth_token is not None:
                self._server.v2.core.logout(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 104:
                print('Сессия завершилась по таймауту.')

################################### Settings ####################################
    def get_ntp_config(self):
        """Получить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_ntp_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_ntp_config(self, ntp):
        """Обновить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.set(self._auth_token, ntp)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_ntp_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_settings_params(self, params):
        """
        Получить несколько параметров за 1 запрос.
        params - list of params
        Возвращает dict
        """
        try:
            result = self._server.v2.settings.get.params(self._auth_token, params)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_settings_params: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def set_settings_param(self, param_name, param_value):
        """Изменить параметр"""
        try:
            result = self._server.v2.settings.set.param(self._auth_token, param_name, param_value)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_settings_param: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает True

    def get_proxy_port(self):
        """Получить порт прокси"""
        try:
            result = self._server.v2.settings.proxy.port.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_proxy_port: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result  # Возвращает номер порта

    def set_proxy_port(self, port):
        """Изменить порт прокси"""
        try:
            result = self._server.v2.settings.proxy.port.set(self._auth_token, port)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_proxy_port: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает True

    def get_proxyportal_config(self):
        """Получить настройки веб-портала"""
        try:
            result = self._server.v1.proxyportal.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_proxyportal_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

##################################### ZONES #####################################
    def get_zones_list(self):
        """Получить список зон"""
        try:
            result = self._server.v1.netmanager.zones.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_{command}: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_zone(self, zone):
        """Добавить зону"""
        try:
            result = self._server.v1.netmanager.zone.add(self._auth_token, zone)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tЗона: {zone['name']} уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_zone: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def update_zone(self, zone_id, zone):
        """Обновить параметры зоны"""
        try:
            result = self._server.v1.netmanager.zone.update(self._auth_token, zone_id, zone)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tЗона: {zone['name']} - нет отличающихся параметров для изменения."
            else:
                return 2, f"Ошибка update_zone: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

################################## Interfaces ###################################
    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_interfaces_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def update_interface(self, iface_id, iface_data):
        """Update interface"""
        try:
            result = self._server.v1.netmanager.interface.update(self._auth_token, self.node_name, iface_id, iface_data)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            return 1, f"Ошибка update_interface: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result    # Возвращается True

##################################### DHCP ######################################
    def get_dhcp_list(self):
        """Получить список подсетей для dhcp"""
        try:
            result = self._server.v1.netmanager.dhcp.subnets.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_dhcp_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_dhcp_subnet(self, subnet):
        """Добавить DHCP subnet"""
        try:
            result = self._server.v1.netmanager.dhcp.subnet.add(self._auth_token, self.node_name, subnet)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 1017:
                return 1, f"\tDHCP subnet: {subnet['name']} уже существует."
            else:
                return 2, f"Ошибка add_dhcp_subnet: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

##################################### DNS ######################################
    def get_dns_config(self):
        """Получить настройки DNS"""
        try:
            dns_servers = self._server.v2.settings.custom.dnses.list(self._auth_token)  # список системных DNS-серверов
            dns_rules = self._server.v1.dns.rules.list(self._auth_token, 0, 1000, {})   # список правил DNS
            static_records = self._server.v1.dns.static.records.list(self._auth_token, 0, 1000, {})   # список статических записей
        except rpc.Fault as err:
            print(f"Ошибка utm.get_dns_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return dns_servers, dns_rules['items'], static_records['items']

    def add_dns_server(self, dns_server):
        """Добавить DNS server"""
        try:
            result = self._server.v2.settings.custom.dns.add(self._auth_token, dns_server)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tDNS server {dns_server['dns']} уже существует."
            else:
                return 2, f"\tОшибка utm.add_dns_server: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_dns_rule(self, dns_rule):
        """Добавить правило DNS"""
        try:
            result = self._server.v1.dns.rule.add(self._auth_token, dns_rule)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПравило DNS {dns_rule['name']} уже существует."
            else:
                return 2, f"\tОшибка utm.add_dns_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_dns_record(self, dns_record):
        """Добавить статическую запись DNS"""
        try:
            result = self._server.v1.dns.static.record.add(self._auth_token, dns_record)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'\tСтатическая запись DNS "{dns_record["name"]}" уже существует.'
            else:
                return 2, f"\tОшибка utm.add_dns_record: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

##################################### Библиотека  ######################################
    def get_nlist_list(self, list_type):
        """Получить содержимое пользовательских именованных списков раздела Библиотеки"""
        array = []
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 1000, {})
            for item in result['items']:
                if item['editable']:
                    if list_type == 'ipspolicy' and self.version.startswith('5'):
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 1000, {}, [])
                    else:
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 1000, '', [])
                    if list_type == 'timerestrictiongroup' and self.version.startswith('5'):
                        item['content'] = [x['value'] for x in content['items']]
                    elif list_type == 'httpcwl':
                        array = {'id': item['id'], 'content': [x for x in content['items']]}
                        break
                    else:
                        item['content'] = [x for x in content['items']]
                    array.append(item)
        except rpc.Fault as err:
            print(f"Ошибка get_namedlist_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(array), array

    def add_nlist(self, named_list):
        """Добавить именованный список"""
        try:
            result = self._server.v2.nlists.add(self._auth_token, named_list)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tСписок: '{named_list['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_namedlist: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def update_nlist(self, named_list_id, named_list):
        """Обновить параметры именованного списка"""
        try:
            result = self._server.v2.nlists.update(self._auth_token, named_list_id, named_list)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tСписок: {named_list['name']} - нет отличающихся параметров для изменения."
            else:
                return 2, f"Ошибка update_namedlist: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_nlist_item(self, named_list_id, item):
        """Добавить слова в именованный список"""
        try:
            result = self._server.v2.nlists.list.add(self._auth_token, named_list_id, item)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 2001:
                return 1, f"\tСодержимое: {item} не будет добавлено, так как уже существует."
            else:
                return 2, f"Ошибка utm.add_nlist_item: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def get_services_list(self):
        """Получить список сервисов раздела Библиотеки"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, '', [])
        except rpc.Fault as err:
            print(f"Ошибка get_dervices_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['total'], result

    def add_service(self, service):
        """Добавить список сервисов раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.add(self._auth_token, service)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tСервис: '{service['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_service: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID сервиса

    def update_service(self, service_id, service):
        """Обновить отдельный сервис раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.update(self._auth_token, service_id, service)
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить сервис '{service['name']}' c id: {service_id}. Данный сервис не найден."
            else:
                return 2, f"Ошибка update_service: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_shaper_list(self):
        """Получить список полос пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_shaper_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_shaper(self, shaper):
        """Добавить полосу пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.add(self._auth_token, shaper)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tСервис: '{shaper['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_shaper: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID шейпера

    def update_shaper(self, shaper_id, shaper):
        """Обновить полосу пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.update(self._auth_token, shaper_id, shaper)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить полосу пропускания '{shaper['name']}' c id: {shaper_id}. Данный сервис не найден."
            else:
                return 2, f"Ошибка update_shaper: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_scada_list(self):
        """Получить список профилей АСУ ТП раздела Библиотеки"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, '', [])
        except rpc.Fault as err:
            print(f"Ошибка get_scada_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['total'], result['items']

    def add_scada(self, scada):
        """Добавить профиль АСУ ТП раздела Библиотеки"""
        try:
            result = self._server.v1.scada.profile.add(self._auth_token, scada)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПрофиль АСУ ТП: '{scada['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_scada: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID шейпера

    def update_scada(self, scada_id, scada):
        """Обновить профиль АСУ ТП раздела Библиотеки"""
        try:
            result = self._server.v1.scada.profile.update(self._auth_token, scada_id, scada)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить Профиль АСУ ТП '{scada['name']}' c id: {scada_id}. Данный сервис не найден."
            else:
                return 2, f"Ошибка update_scada: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_templates_list(self):
        """Получить список шаблонов страниц раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.templates.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_templates_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_template(self, template):
        """Добавить новый шаблон в раздел "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.add(self._auth_token, template)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tШаблон страницы: '{template['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_template: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID шаблона

    def update_template(self, template_id, template):
        """Обновить шаблон в разделе "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.update(self._auth_token, template_id, template)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить шаблон страницы '{template['name']}' c id: {template_id}. Данная страница не найдена."
            else:
                return 2, f"Ошибка update_template: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_template_data(self, template_type, template_id):
        """Получить HTML страницы шаблона раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.public.data.fetch(template_type, template_id)
        except rpc.Fault as err:
            print(f"Ошибка get_template_data: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

    def set_template_data(self, template_id, data):
        """Импортировать страницу HTML шаблона раздела Библиотеки"""
        try:
            data64 = rpc.Binary(data)
            result = self._server.v1.libraries.response.page.template.data.update(self._auth_token, template_id, data64)
        except rpc.Fault as err:
            print(f"Ошибка set_template_data: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result    # Возвращает True

    def get_notification_profiles_list(self):
        """Получить список профилей оповещения раздела Библиотеки"""
        try:
            result = self._server.v1.notification.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_notification_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_notification_profile(self, profile):
        """Добавить профиль оповещения раздела Библиотеки"""
        if profile['name'] in self.list_notifications.keys():
            return 1, f'\tПрофиль оповещения "{profile["name"]}" уже существует. Проверка параметров...'
        else:
            try:
                result = self._server.v1.notification.profile.add(self._auth_token, profile)
            except rpc.Fault as err:
                return 2, f"Ошибка add_notification_profiles: [{err.faultCode}] — {err.faultString}"
            return 0, result     # Возвращает ID добавленного профиля
        
    def update_notification_profile(self, profile):
        """Обновить профиль оповещения раздела Библиотеки"""
        try:
            np_id = self.list_notifications[profile['name']]
            result = self._server.v1.notification.profile.update(self._auth_token, np_id, profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"Ошибка update_notification_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_idps_signatures_list(self):
        """Получить список сигнатур IDPS"""
        idps = {}
        try:
            result = self._server.v1.idps.signatures.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            print(f"Ошибка get_idps_signatures_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        for item in result['items']:
            idps[item['msg']] = item['id']
        return 0, idps

    def get_netflow_profiles_list(self):
        """Получить список профилей netflow раздела Библиотеки"""
        try:
            result = self._server.v1.netmanager.netflow.profiles.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"Ошибка get_notification_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_netflow_profile(self, profile):
        """Добавить профиль netflow в Библиотеку"""
        try:
            result = self._server.v1.netmanager.netflow.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПрофиль netflow: '{profile['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_netflow_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_netflow_profile(self, profile):
        """Обновить профиль netflow раздела Библиотеки"""
        try:
            result = self._server.v1.netmanager.netflow.profile.update(self._auth_token, profile['id'], profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"Ошибка update_netflow_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_ssl_profiles_list(self):
        """Получить список профилей SSL раздела Библиотеки"""
        try:
            result = self._server.v1.content.ssl.profiles.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"Ошибка get_ssl_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_ssl_profile(self, profile):
        """Добавить профиль SSL в Библиотеку"""
        try:
            result = self._server.v1.content.ssl.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПрофиль SSL: '{profile['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_ssl_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_ssl_profile(self, profile):
        """Обновить профиль SSL раздела Библиотеки"""
        try:
            result = self._server.v1.content.ssl.profile.update(self._auth_token, profile['id'], profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"Ошибка update_ssl_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

################################### Пользователи и устройства #####################################
    def get_groups_list(self):
        """Получить список локальных групп"""
        try:
            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка get_groups_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_group(self, group):
        """Добавить локальную группу"""
        try:
            result = self._server.v3.accounts.group.add(self._auth_token, group)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tГруппа '{group['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"\tОшибка add_group: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает GUID добавленной группы

    def update_group(self, group):
        """Обновить локальную группу"""
        try:
            result = self._server.v3.accounts.group.update(self._auth_token, group['guid'], group)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"\tОшибка update_group: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_users_list(self):
        """Получить список локальных пользователей"""
        try:
            result = self._server.v3.accounts.users.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка get_users_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_user(self, user):
        """Добавить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.add(self._auth_token, user)
        except rpc.Fault as err:
            if err.faultCode == 5002:
                return 1, f"\tПользователь '{user['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"\tОшибка add_user: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает GUID добавленного пользователя

    def update_user(self, user):
        """Обновить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.update(self._auth_token, user['guid'], user)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_user: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def add_user_in_group(self, group_guid, user_guid):
        """Добавить локального пользователя в локальную группу"""
        try:
            result = self._server.v3.accounts.group.user.add(self._auth_token, group_guid, user_guid)
        except rpc.Fault as err:
            return 2, f"\t\tОшибка add_user: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает true

    def get_auth_servers(self):
        """Получить список серверов авторизации"""
        try:
            ldap = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
            radius = self._server.v1.auth.radius.servers.list(self._auth_token, {})
            tacacs = self._server.v1.auth.tacacs.plus.server.list(self._auth_token, {})
            ntlm = self._server.v1.auth.ntlm.server.list(self._auth_token, {})
            saml = self._server.v1.auth.saml.idp.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_auth_servers: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return ldap, radius, tacacs, ntlm, saml

    def add_auth_server(self, type, server):
        """Добавить auth сервер"""
        if server['name'] in self.auth_servers.keys():
            return 1, f"\tСервер авторизации '{server['name']}' уже существует."
        try:
            if type == 'ldap':
                result = self._server.v1.auth.ldap.server.add(self._auth_token, server)
            elif type == 'ntlm':
                result = self._server.v1.auth.ntlm.server.add(self._auth_token, server)
            elif type == 'radius':
                result = self._server.v1.auth.radius.server.add(self._auth_token, server)
            elif type == 'tacacs':
                result = self._server.v1.auth.tacacs.plus.server.add(self._auth_token, server)
            elif type == 'saml':
                result = self._server.v1.auth.saml.idp.server.add(self._auth_token, server)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_auth_server: [{err.faultCode}] — {err.faultString}"
        else:
            self.auth_servers[server['name']] = result
            return 0, result     # Возвращает ID добавленного сервера авторизации

class UtmError(Exception): pass
