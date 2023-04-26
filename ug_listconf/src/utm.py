#!/usr/bin/python3
# Общий класс для работы с xml-rpc
#
# Версия 0.8
#################################################################################################
import sys
import xmlrpc.client as rpc


class UtmXmlRpc:
    def __init__(self, server_ip, login, password):
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4040/rpc'
        self._auth_token = None
        self._server = None
        self._groups = {}           # Список групп {name: guid}
        self._users = {}            # Список пользователей {guid: name}
        self._categories = {}       # Список категорий URL {id: name}
        self._scenarios = {}        # Список сценариев {id: name}
        self._l7apps = {}           # Список L7 приложений {id: name}
        self._l7categories = {}     # Список L7 категорий {id: name}
        self._geoip_code = {}       # Список кодов стран GEOIP {geoip_code: name}
        self.version = None
        self.server_ip = server_ip
        self.node_name = None

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

    def _init_struct(self):
        """
        Заполнить структуры:
             self._groups - {name: guid}
             self._scenarios - {id: name}
             self._l7apps - {id: name}
             self._l7categories - {id: name}
        """
        self._groups.clear()
        try:
            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
            self._groups = {x['name']: x['guid'] for x in result['items'] if result['total']}

            result = self._server.v1.scenarios.rules.list(self._auth_token, 0, 1000, {})
            self._scenarios = {x['id']: x['name'] for x in result['items'] if result['count']}

            result = self._server.v2.core.get.l7categories(self._auth_token, 0, 10000, '')
            self._l7categories = {x['id']: x['name'] for x in result['items'] if result['count']}

            if self.version.startswith('6'):
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, {}, [])
            else:
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, '')
            self._l7apps = {x['id'] if 'id' in x.keys() else x['app_id']: x['name'] for x in result['items'] if result['count']}
            
            result = self._server.v1.libraries.geoip.countries.list(self._auth_token)
            self._geoip_code = {x['code']: x['name'] for x in result}

        except rpc.Fault as err:
            print(f'Ошибка: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).')
            sys.exit(1)

    def _init_categories(self):
        """Заполнить структуру категорий UserGate URL Filtering - {id: name}"""
        self._categories.clear()
        try:
            result = self._server.v2.core.get.categories()
        except rpc.Fault as err:
            print(f"Ошибка _init_categories: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        if result:
            for item in result:
                self._categories[item['id']] = item['name']

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

    def get_license_info(self):
        """Получить данные по лицензии"""
        result = self._server.v2.core.license_info(self._auth_token)
        print(result)

    def get_groups_list(self):
        """Получить список локальных групп"""
        try:
            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f'Ошибка: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).')
            sys.exit(1)
        return result

    def add_group(self, group):
        """Добавить локальную группу"""
        if self._groups.get(group['name'], None):
            return 1, f"Группа '{group['name']}' уже существует."
        else:
            try:
                result = self._server.v3.accounts.group.add(self._auth_token, group)
                self._groups[group['name']] = result
            except rpc.Fault as err:
                if err.faultCode == 409:
                    return 1, f"Группа '{group['name']}' уже существует."
                else:
                    return 2, f"Ошибка: [{err.faultCode}] — {err.faultString}"
            else:
                return 0, result

    def get_users_in_group(self, guid):
        """Получить список пользователей в конкретной группе"""
        users = []
        try:
            result = self._server.v3.accounts.group.users.list(self._auth_token, guid, 0, 1000, {})
        except rpc.Fault as err:
            return err.faultCode, err.faultString
        if result['count']:
            if self.version.startswith('6'):
                for item in result['items']:
                    users.append(item[1])
            else:
                for item in result['items']:
                    users.append(item['name'])
            return users

    def add_user_in_group(self, guid, uid):
        """Добавить локального пользователя в локальную группу"""
        try:
            result = self._server.v3.accounts.group.user.add(self._auth_token, guid, uid)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            return err.faultCode, err.faultString
        else:
            return 0, result    # Возвращается: true

    def get_local_users(self):
        """Получить список локальных пользователей"""
        array = []
        user = {}
        try:
            result = self._server.v3.accounts.users.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        if result['count']:
            groups = {v: k for k, v in self._groups.items()}
            for item in result['items']:
                self._users[item['guid']] = item['name']
                user['name'] = item['name']
                user['auth_login'] = item['auth_login']
                user['enabled'] = item['enabled']
                user['groups'] = []
                for guid in item['groups']:
                    user['groups'].append(groups[guid])
                for key in ['groups', 'id', 'guid', 'creation_date', 'expiration_date']:
                    item.pop(key, None)
                if item['first_name'] is None:
                    item['first_name'] = ""
                if item['last_name'] is None:
                    item['last_name'] = ""
                user.update(item)
                array.append(dict(user))
                user.clear()
        return array

    def add_local_user(self, user):
        """Добавить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.add(self._auth_token, user)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            return err.faultCode, err.faultString
        else:
            return 0, result

    def get_admin_options(self):
        """Получить глобальные опции аутентификации"""
        try:
            result = self._server.v2.core.administrator.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_admin_profiles(self):
        """Получить профили администраторов"""
        try:
            result = self._server.v2.core.administrator.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_admins_list(self):
        """Получить список администраторов"""
        try:
            result = self._server.v2.core.administrator.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"Ошибка: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_zones_list(self):
        """Получить список зон"""
        try:
            result = self._server.v1.netmanager.zones.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result),result

    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_interfaces_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_ntp_config(self):
        """Получить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.get(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_ntp_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_gateways_list(self):
        """Получить список шлюзов"""
        try:
            result = self._server.v1.netmanager.gateways.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_gateways_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_gateway_fetch(self, route_id):
        """Получить шлюз по его id"""
        try:
            result = self._server.v1.netmanager.gateway.fetch(self._auth_token, self.node_name, route_id)
        except rpc.Fault as err:
            print(f"Ошибка get_gateway_fetch: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_gateway_failover(self):
        """Получить настройки проверки сети шлюзов"""
        try:
            result = self._server.v1.netmanager.failover.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_gateway_fetch: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_dhcp_list(self):
        """Получить список подсетей для dhcp"""
        try:
            result = self._server.v1.netmanager.dhcp.subnets.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_dhcp_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_dns_list(self):
        """Получить список системных DNS-серверов"""
        try:
            result = self._server.v2.settings.custom.dnses.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_dns_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_dns_rules_list(self):
        """Получить список правил DNS в DNS-прокси"""
        try:
            result = self._server.v1.dns.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_dns_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['count'], result['items']

    def get_dns_static_list(self):
        """Получить список статических записей DNS в DNS-прокси"""
        try:
            result = self._server.v1.dns.static.records.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_dns_static_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['count'], result['items']

    def get_wccp_list(self):
        """Получить список правил WCCP"""
        try:
            result = self._server.v1.wccp.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_wccp_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_params_list(self, param):
        """Получить список произвольных параметров"""
        try:
            result = self._server.v2.settings.get.params(self._auth_token, param)
        except rpc.Fault as err:
            print(f"Ошибка get_params_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_routers_list(self):
        """Получить список роутеров"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.netmanager.virtualrouters.list(self._auth_token)
            else:
                result = self._server.v1.netmanager.route.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_routers_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_ospf_params_v5(self):
        """Получить конфигурацию OSPF (только для UTM v5)"""
        try:
            data = self._server.v1.netmanager.ospf.router.fetch(self._auth_token, self.node_name)
            ifaces = self._server.v1.netmanager.ospf.interfaces.list(self._auth_token, self.node_name)
            areas = self._server.v1.netmanager.ospf.areas.list(self._auth_token, self.node_name)
        except rpc.Fault as err:
            print(f"Ошибка get_ospf_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return data, ifaces, areas

    def get_bgp_params_v5(self):
        """Получить конфигурацию OSPF (только для UTM v5)"""
        try:
            data = self._server.v1.netmanager.bgp.router.fetch(self._auth_token, self.node_name)
            neigh = self._server.v1.netmanager.bgp.neighbors.list(self._auth_token, self.node_name)
            rmaps = self._server.v1.netmanager.bgp.routemaps.list(self._auth_token, self.node_name)
            filters = self._server.v1.netmanager.bgp.filters.list(self._auth_token, self.node_name)
        except rpc.Fault as err:
            print(f"Ошибка get_ospf_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return data, neigh, rmaps, filters

#################### Пользователи и устройства ################
    def get_auth_servers_list(self):
        """Получить список серверов авторизации"""
        try:
            ldap = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
            radius = self._server.v1.auth.radius.servers.list(self._auth_token, {})
            tacacs = self._server.v1.auth.tacacs.plus.server.list(self._auth_token, {})
            ntlm = self._server.v1.auth.ntlm.server.list(self._auth_token, {})
            saml = self._server.v1.auth.saml.idp.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"Ошибка get_auth_servers_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return ldap, radius, tacacs, ntlm, saml

    def get_auth_profiles_list(self):
        """Получить список профилей авторизации"""
        try:
            result = self._server.v1.auth.user.auth.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_auth_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_2fa_profiles_list(self):
        """Получить список профилей авторизации"""
        try:
            f = getattr(self._server, 'v1.2fa.profiles.list')
            result = f(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            print(f"Ошибка get_2fa_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_captive_profiles_list(self):
        """Получить список Captive-профилей"""
        try:
            result = self._server.v1.captiveportal.profiles.list(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            print(f"Ошибка get_captive_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_captive_portal_list(self):
        """Получить список правил Captive-портала"""
        try:
            result = self._server.v1.captiveportal.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_captive_portal_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_byod_policy_list(self):
        """Получить список политик BYOD"""
        try:
            result = self._server.v1.byod.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_byod_policy_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_firewall_rules_list(self):
        """Получить список правил межсетевого экрана"""
        try:
            result = self._server.v1.firewall.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_firewall_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_traffic_rules_list(self):
        """Получить список правил раздела NAT и маршрутизация"""
        try:
            result = self._server.v1.traffic.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_traffic_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_icap_servers_list(self):
        """Получить список серверов ICAP"""
        try:
            result = self._server.v1.icap.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_icap_servers_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_icap_rules_list(self):
        """Получить список правил ICAP"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.icap.rules.list(self._auth_token, 0, 1000, {})['items']
            else:
                result = self._server.v1.icap.rules.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"Ошибка get_icap_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def get_icap_loadbalancing_rules(self):
        """Получить список правил балансировки серверов ICAP"""
        try:
            result = self._server.v1.icap.loadbalancing.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_icap_loadbalancing_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_tcpudp_loadbalancing_rules(self):
        """Получить список правил балансировки серверов TCP/UDP"""
        try:
            result = self._server.v1.virtualserver.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_tcpudp_loadbalancing_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_reverseproxy_servers_list(self):
        """Получить список серверов Reverse-proxy"""
        try:
            result = self._server.v1.reverseproxy.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_reverseproxy_servers_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_reverseproxy_loadbalancing_rules(self):
        """Получить список правил балансировки серверов reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.loadbalancing.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_reverseproxy_loadbalancing_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_shaper_rules_list(self):
        """Получить список правил ограничения пропускной пособности"""
        try:
            result = self._server.v1.shaper.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_shaper_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

#################### Политики безопасности ################
    def get_content_rules_list(self):
        """Получить список правил Фильтрации контента"""
        try:
            result = self._server.v1.content.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_content_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_safebrowsing_rules_list(self):
        """Получить список правил веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_safebrowsing_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_ssldecrypt_rules_list(self):
        """Получить список правил Инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_ssldecrypt_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_sshdecrypt_rules_list(self):
        """Получить список правил Инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_sshdecrypt_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_idps_rules_list(self):
        """Получить список правил СОВ"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.idps.rules.list(self._auth_token, 0, 1000, {})['items']
            else:
                result = self._server.v1.idps.rules.list(self._auth_token, {})
            ipspolicy = {x['id']: x['name'] for x in self._server.v2.nlists.list(self._auth_token, 'ipspolicy', 0, 1000, {})['items']}
        except rpc.Fault as err:
            print(f"Ошибка get_idps_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result, ipspolicy

    def get_scada_rules_list(self):
        """Получить список правил АСУ ТП"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.scada.rules.list(self._auth_token, 0, 1000, {})['items']
            else:
                result = self._server.v1.scada.rules.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"Ошибка get_scada_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_scenarios_rules_list(self):
        """Получить список Сценариев"""
        try:
            result = self._server.v1.scenarios.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_scenarios_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_mailsecurity_rules_list(self):
        """Получить список Сценариев"""
        try:
            result = self._server.v1.mailsecurity.rules.list(self._auth_token, 0, 1000, {})
            result['dnsbl'] = self._server.v1.mailsecurity.dnsbl.config.get(self._auth_token)
            result['batv'] = self._server.v1.mailsecurity.batv.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_mailsecurity_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_dos_profiles_list(self):
        """Получить список Профилей DoS"""
        try:
            result = self._server.v1.dos.profiles.list(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            print(f"Ошибка get_dos_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['count'], result['items']

    def get_dos_rules_list(self):
        """Получить список Правил защиты DoS"""
        try:
            result = self._server.v1.dos.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_dos_rules_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['count'], result['items']

###################### Библиотеки ######################3
    def get_services_list(self):
        """Получить список сервисов"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, '', [])
        except rpc.Fault as err:
            print(f"Ошибка get_services_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_namedlist_list(self, list_type):
        """Получить содержимое именованных списков раздела Библиотеки"""
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 5000, {})
        except rpc.Fault as err:
            print(f"Ошибка-1 get_namedlist_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)

        for item in result['items']:
            if item['editable']:
                try:
                    if (list_type == 'ipspolicy' and self.version.startswith('5')):
                        contents = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, {}, [])
                    elif int(self.version[4:5]) >= 9:
                        contents = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, {}, [])
                    else:
                        contents = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, '', [])
                except rpc.Fault as err:
                    print(f"Ошибка: get_namedlist_list: [{err.faultCode}] — {err.faultString}")
                    print(f'\033[33m\tСодержимое списка "{item["name"]}" не экспортировано. Ошибка загрузки списка!\033[0m')
                    sys.exit(1)
                except ExpatError:
                    print(f'\033[33m\tСодержимое списка "{item["name"]}" не экспортировано. Список corrupted!\033[0m')
                    sys.exit(1)
                except UnboundLocalError:
                    print(f'\033[33m\tСодержимое списка "{item["name"]}" не экспортировано. Ошибка программы!\033[0m')
                    sys.exit(1)
                if list_type in ['urlcategorygroup', 'morphology']:
                    item['content'] = [x for x in contents['items']]
                else:
                    item['contents'] = [x['value'] for x in contents['items']]
        return result

    def get_time_restrict_list(self):
        """Получить содержимое календарей раздела Библиотеки"""
        try:
            result = self._server.v2.nlists.list(self._auth_token, 'timerestrictiongroup', 0, 5000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_time_restrict_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)

        for item in result['items']:
            try:
                if self.version.startswith('5'):
                    contents = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, '', [])
                elif int(self.version[4:5]) >= 9:
                    contents = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, {}, [])
            except rpc.Fault as err:
                print(f"Ошибка get_time_restrict_list: [{err.faultCode}] — {err.faultString}")
                print(f'\033[33m\tСодержимое списка "{item["name"]}" не экспортировано. Ошибка загрузки списка!\033[0m')
                sys.exit(1)

            if self.version.startswith('6'):
                item['contents'] = contents['items']
            else:
                item['contents'] = [x['value'] for x in contents['items']]
        return result

    def get_shaper_list(self):
        """Получить список полосы пропускания"""
        try:
            result = self._server.v1.shaper.pool.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_shaper_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_scada_profiles_list(self):
        """Получить список профилей АСУ ТП"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, '', [])
        except rpc.Fault as err:
            print(f"Ошибка get_scada_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_templates_list(self):
        """Получить список шаблонов страниц"""
        try:
            result = self._server.v1.libraries.response.page.templates.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_templates_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_notification_profiles_list(self):
        """Получить список профилей оповещения"""
        try:
            result = self._server.v1.notification.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_notification_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_ssl_profiles_list(self):
        """Получить список профилей SSL"""
        try:
            result = self._server.v1.content.ssl.profiles.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_ssl_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result


class UtmError(Exception): pass
