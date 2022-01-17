#!/usr/bin/python3
#########################################################################################
# Версия 0.1                                                                            #
# Общий класс для работы с xml-rpc                                                      #
#########################################################################################
import sys
import xmlrpc.client as rpc
from datetime import datetime as dt
from PySimpleGUI import PopupError


class UTM:
    def __init__(self, server_ip, login, password):
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4040/rpc'
        self._auth_token = None
        self._server = None
        self.version = None
        self.server_ip = server_ip
        self.node_name = None

    def connect(self):
        """Подключиться к UTM"""
        try:
            self._server = rpc.ServerProxy(self._url, verbose=False)
            if self.get_node_status() == 'work':
                result = self._server.v2.core.login(self._login, self._password, {'origin': 'dev-script'})
                self._auth_token = result.get('auth_token')
                self.node_name =  result.get('node')
                self.version = result.get('version')
            else:
                PopupError('Ошибка: UTM не позволяет установить соединение!', keep_on_top=True)
                sys.exit(1)
        except OSError as err:
            PopupError(f'Ошибка: {err} (Node: {self.server_ip}).', keep_on_top=True)
            sys.exit(1)
        except rpc.ProtocolError as err:
            PopupError(f'Ошибка: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).', keep_on_top=True)
            sys.exit(1)
        except rpc.Fault as err:
            PopupError(f'Ошибка: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).', keep_on_top=True)
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

    def get_license_info(self):
        """Получить информацию по лицензии"""
        try:
            result = self._server.v2.core.license.info(self._auth_token)
        except rpc.Fault as err:
            PopupError(f'Ошибка get_license_info: [{err.faultCode}] — {err.faultString}', keep_on_top=True)
            sys.exit(1)
        if result['expiry_date'] != 'infinity':
                expire_date = dt.strptime(result['expiry_date'].value, "%Y-%m-%dT%H:%M:%SZ")
                result['expiry_date'] = expire_date.strftime("%d-%b-%Y")
        else:
            result['expiry_date'] = 'Бессрочная'
        for license in result['modules']:
            try:
                if license['expiry'] != 'infinity':
                    expire_date = dt.strptime(license['expiry'].value, "%Y-%m-%dT%H:%M:%S")
                    license['expiry'] = expire_date.strftime("%d-%b-%Y")
                else:
                    license['expiry'] = 'Бессрочная'
            except AttributeError:
                pass
        return result

    def get_active_ips_number(self):
        """Получить число активных ips"""
        try:
            result = self._server.v1.sysstat.active.ips(self._auth_token)
        except rpc.Fault as err:
            PopupError(f'Ошибка get_active_ips_number: [{err.faultCode}] — {err.faultString}', keep_on_top=True)
            sys.exit(1)
        return result

    def get_active_ips_list(self):
        """Получить список активных ips"""
        try:
            result = self._server.v1.sysstat.active.ips.list(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 1:
                string = "API, необходимое для работы отсутствует на вашем UTM.\n"
                string += "Обратитесь в техподдержку компании UserGate для исправления ситуации."
                PopupError(string, keep_on_top=True)
            else:
                PopupError(f'Ошибка get_active_ips_list: [{err.faultCode}] — {err.faultString}', keep_on_top=True)
            sys.exit(1)
        return result

    def ping_session(self):
        """Ping сессии"""
        try:
            result = self._server.v2.core.session.ping(self._auth_token)
        except rpc.Fault:
            return 1
        else:
            return 0
