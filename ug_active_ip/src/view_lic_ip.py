#!/usr/bin/python3
#########################################################################################
# Версия 0.2                                                                            #
# Программа выводит число активных коннектов и список IP-адресов, занимающих лицензию.  #
#########################################################################################

import os, sys, socket
import stdiomask
import ipaddress
import xmlrpc.client as rpc
from datetime import datetime as dt


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

    def get_active_ips_number(self):
        """Получить число активных ips"""
        try:
            result = self._server.v1.sysstat.active.ips(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_active_ips_number: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_active_ips_list(self):
        """Получить список активных ips"""
        try:
            result = self._server.v1.sysstat.active.ips.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_active_ips_list: [{err.faultCode}] — {err.faultString}")
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

def get_fqdn(ip):
    try:
        return socket.getfqdn(ip)
    except OSError:
        return ' '

def view_active_ips(mode, utm):
    """
    Выгружаем список активных IP-адресов в каталог data.
    """
    number_ips = utm.get_active_ips_number()
    if number_ips:
        string = f"Число активных коннектов: {number_ips}"
        string += "\n      IP                          FQDN"
        string += "\n-----------------       -------------------------------"
        private_ips = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))
        list_ips = utm.get_active_ips_list()
        if mode == 2:
            time_stamp = dt.today().strftime("%Y-%m-%d_%H-%M-%S")
            for ip in list_ips:
                string += f"\n{ip:16}    -     {get_fqdn(ip)}"
            if not os.path.isdir('data'):
                os.makedirs('data')
            with open(f"data/active_ips ({time_stamp}).txt", "w") as fh:
                fh.write(string)
                print(f'\033[36mСписок активных IP-адресов выгружен в файл "data/active_ips ({time_stamp}).txt"\033[0m')
        else:
            print(string)
            for ip in list_ips:
                if any(ipaddress.ip_address(ip) in subnet for subnet in private_ips):
                    print(f"\033[36m {ip:16}   -    {get_fqdn(ip)}\033[0m")
                else:
                    print(f"\033[33m {ip:20}   -    {get_fqdn(ip)}\033[0m")
    else:
        print("Нет активных IP-адресов!")

def menu1():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m                  Получение списка активных IP                 \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма выводит список IP-адресов занимающих лицензию в данный момент.\033[0m\n")

def menu2(utm):
    menu1()
    print("1  - Вывод на экран")
    print("2  - Вывод в файл")
    print("\033[33m0  - Выход.\033[0m")
    while True:
        try:
            mode = int(input("\nВведите номер нужной операции: "))
            if mode not in [0, 1, 2]:
                print("Вы ввели несуществующую команду.")
            elif mode == 0:
                utm.logout()
                print("Программа завершена.")
                sys.exit()
            else:
                return mode
        except ValueError:
            print("Ошибка! Введите число.")

def main():
    menu1()
    try:
        server_ip = input("\033[36mВведите IP-адрес UTM:\033[0m ")
        login = input("\033[36mВведите логин администратора UTM:\033[0m ")
        password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        sys.exit(0)

    try:
        utm = UTM(server_ip, login, password)
        utm.connect()
        while True:
            mode = menu2(utm)
            if utm.ping_session():
                utm = UTM(server_ip, login, password)
                utm.connect()
            menu1()
            view_active_ips(mode, utm)
            while True:
                input_value = input("\nНажмите пробел для возврата в меню: ")
                if input_value == " ":
                    break
    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        utm.logout()
        sys.exit(0)

if __name__ == '__main__':
    main()
