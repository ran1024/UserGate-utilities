#!/usr/bin/python3
#
# ug_view_license (Gets the list of IP addresses that hold the NGFW license).
#
# Copyright @ 2021-2022 UserGate Corporation. All rights reserved.
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
#--------------------------------------------------------------------------------------------------- 
# Версия 1.2
# Программа выводит число активных коннектов и список IP-адресов, занимающих лицензию.
# Так же показывает все данные по текущей лицензии.
#
import sys, os, socket
import ipaddress
import xmlrpc.client as rpc
import PySimpleGUI as sg
from datetime import datetime as dt
from itertools import zip_longest
from user_settings import make_settings, progress_bar
from utmlib import UTM
from GUIlib import TextKey, TextValue


SETTINGS_PATH = '.'
sg.user_settings_filename(path=SETTINGS_PATH)

def get_fqdn(ip):
    try:
        return socket.getfqdn(ip)
    except OSError:
        return ''

def test_network(ind):
    if ind == -2:
        sg.PopupError('Ошибка!', 'Network is unreachable.', 'Проверьте сетевое соединение.')
        exit()
    elif ind == -1:
        sg.PopupError('Ошибка!', 'Time out.', 'Устройство не отвечает.')

def get_location():
    """
    Определение координат окна.
    """
    if 'Location' in sg.user_settings():
        arr = sg.user_settings_get_entry('Location')
        return (arr[0], arr[1]-20)
    else:
        return (150, 130)

def set_location(window):
    """
    Отслеживаем положение окна на экране и запомнаем, если изменилось.
    """
    current_location = window.CurrentLocation()
    if current_location != sg.user_settings_get_entry('Location'):
        sg.user_settings_set_entry('Location', window.CurrentLocation())

def view_active_ips(utm):
    """
    Получаем список активных IP-адресов.
    """
    private_ips = (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'))
    list_ips = utm.get_active_ips_list()
#    list_ips = ['192.168.30.11', '192.168.30.12', '192.168.30.13', '192.168.30.14', '192.168.70.1', '192.168.30.15', '4.4.4.4',
#        '8.8.8.8', '4.4.8.8', '192.168.30.16', '10.10.10.1', '10.20.1.2', '192.180.56.7', '122.156.15.10', '192.168.70.11',
#        '8.8.8.7', '4.4.4.1','10.10.10.18', '10.20.1.26', '192.180.66.75', '122.156.16.1', '77.88.55.50',
#        '10.10.11.10', '10.20.21.25', '192.181.56.75', '122.159.15.1', '192.168.79.1', '8.88.8.8', '4.84.4.4',
#    ]
    row_ips = []
    row_colors = []
    new_location = [sum(i) for i in zip_longest(sg.user_settings_get_entry('Location'), [36, 100], fillvalue=0)]
    bar_layout = [
        [sg.ProgressBar(len(list_ips), orientation='h', size=(20, 20), key='-PROGRESS_BAR-', bar_color=('#000099', 'grey'), border_width=1)],
        [sg.Text(size=(28, 1), justification='center', text_color='#CCCCCC', key='-BAR_TEXT-')]
    ]
    bar_window = sg.Window('Операция выполняется...',
                            bar_layout, keep_on_top=True,
                            no_titlebar=True,
                            background_color='#282923',
                            modal=True,
                            location=new_location)
    progress_bar = bar_window['-PROGRESS_BAR-']
    i = 0

    for ip in list_ips:
        event, values = bar_window.read(timeout=10)
        bar_window['-BAR_TEXT-'].update(ip)
        if any(ipaddress.ip_address(ip) in subnet for subnet in private_ips):
            row_ips.append([ip, get_fqdn(ip)])
            row_colors.append((list_ips.index(ip), '#CCFFFF', ''))
        else:
            row_ips.append([ip, get_fqdn(ip)])
            row_colors.append((list_ips.index(ip), '#E9E9EA', ''))
        progress_bar.UpdateBar(i+1)
        i += 1

    bar_window.close()
    return row_ips, row_colors

def save_to_file(window):
    list_ips = window['-TABLE_IPS-'].get()
    number_ips = window['-USE_LIC-'].get()
    time_stamp = dt.today().strftime("%Y-%m-%d_%H-%M-%S")
    string = f"Число активных коннектов: {number_ips}"
    string += "\n       IP                           FQDN"
    string += "\n-----------------       -------------------------------"

    for ip in list_ips:
        string += f"\n{ip[0]:16}    -     {ip[1]}"

    if not os.path.isdir('data'):
        os.makedirs('data')
    with open(f"data/active_ips ({time_stamp}).txt", "w") as fh:
        fh.write(string)
    new_location = [sum(i) for i in zip_longest(sg.user_settings_get_entry('Location'), [30, 200], fillvalue=0)]
    sg.popup('Список активных IP-адресов выгружен в файл:', f'data/active_ips ({time_stamp}).txt', text_color='#E9E9EA', keep_on_top=True, location=new_location)

def init_window(window, utm):
    """
    Начальная инициализация окна.
    """
    license = utm.get_license_info()
    window['-SERVER_IP-'](utm.server_ip)
    window['-SERVER_NAME-'](utm.node_name)
    window['-PIN_CODE-'](license['pin_code'])
    window['-REG_NAME-'](license['reg_name'])
    window['-USER_NAME-'](license['user_name'])
    window['-LAST_NAME-'](license['last_name'])
    window['-EMAIL-'](license['email'])
    window['-COUNTRY-'](license['country'])
    window['-REGION-'](license['region'])
    window['-COMPANY-'](license['company'])
    window['-ADDRESS-'](license['address'])
    window['-PHONE-'](license['phone'])
    window['-FAX-'](license['fax'])
    window['-EXPIRY_DATE-'](license['expiry_date'])
    window['-LIC_TYPE-'](license['license_type'])
    window['-VERSION-'](license['version'])
    window['-DEVICE-'](license['product_device'])
    window['-USER_LIMIT-'](license['user_limit'])
    modules = {}
    for item in license['modules']:
        modules[item['name']] = item['expiry']
    window['-SECURITY_UPDATE-'](modules['securityupdate'] if 'securityupdate' in modules.keys() else 'Нет лицензии')
    window['-ATP-'](modules['atp'] if 'atp' in modules.keys() else 'Нет лицензии')
    window['-MAIL_SEC-'](modules['mailsec'] if 'mailsec' in modules.keys() else 'Нет лицензии')
    window['-KAS-'](modules['kas'] if 'kas' in modules.keys() else 'Нет лицензии')
    window['-CLUSTER-'](modules['cluster'] if 'cluster' in modules.keys() else 'Нет лицензии')
    if license['version'].startswith('7'):
        window['-SCADA-'](modules['scada'] if 'scada' in modules.keys() else 'Нет лицензии')
        window['-PRSUPPORT-'](modules['premiumsupport'] if 'premiumsupport' in modules.keys() else 'Нет лицензии')
    else:
        window['-SCADA-'](modules['scada'] if 'scada' in modules.keys() else 'Бессрочная')
        window['-PRSUPPORT-'](modules['premiumsupport'] if 'premiumsupport' in modules.keys() else 'Не определено')

    user_limit = license['user_limit']
    number_ips = utm.get_active_ips_number()
    window['-ALL_LIC-'](user_limit)
    window['-USE_LIC-'](number_ips)
    row_ips, row_colors = view_active_ips(utm)
    window['-TABLE_IPS-'](row_ips, row_colors=row_colors)

def make_window():
    sg.theme('Topanga')
    list_head = ['IP', 'FQDN']
    list_val = [['---------------', '-------------------']]

    col_width = [17, 100]
    tab1_layout = [
        [TextKey('Кол-во лицензий:'), TextValue(key='-ALL_LIC-'), TextKey('Используется:'), TextValue(key='-USE_LIC-')],
        [sg.Table(list_val, headings=list_head, justification='left', expand_x=True, expand_y=True, key='-TABLE_IPS-',
            row_height=16, auto_size_columns=False, col_widths=[16, 30], font=('Verdana', 8), select_mode='browse')
        ]
    ]
    col1 = [
        [TextKey('Security Update:')],
        [TextKey('ATP:')],
        [TextKey('Mail security:')],
        [TextKey('Потоковый антивирус UserGate:')],
        [TextKey('Scada:')],
        [TextKey('Cluster:')],
        [TextKey('Premium Support:')],
    ]
    col2 = [
        [TextValue(key='-SECURITY_UPDATE-')],
        [TextValue(key='-ATP-')],
        [TextValue(key='-MAIL_SEC-')],
        [TextValue(key='-KAS-')],
        [TextValue(key='-SCADA-')],
        [TextValue(key='-CLUSTER-')],
        [TextValue(key='-PRSUPPORT-')],
    ]
    frame_layout = [
        [sg.Column(col1), sg.Column(col2)]
    ]
    tab2_layout = [
        [TextKey('IP-адрес узла:'), TextValue(key='-SERVER_IP-')],
        [TextKey('Имя узла:'), TextValue(key='-SERVER_NAME-')],
        [TextKey('Пин код:'), TextValue(key='-PIN_CODE-')],
        [TextKey('Регистрационное имя:'), TextValue(key='-REG_NAME-')],
        [TextKey('Имя:'), TextValue(key='-USER_NAME-')],
        [TextKey('Фамилия:'), TextValue(key='-LAST_NAME-')],
        [TextKey('E-mail:'), TextValue(key='-EMAIL-')],
        [TextKey('Страна:'), TextValue(key='-COUNTRY-')],
        [TextKey('Регион:'), TextValue(key='-REGION-')],
        [TextKey('Компания:'), TextValue(key='-COMPANY-')],
        [TextKey('Почтовый адрес:'), TextValue(key='-ADDRESS-')],
        [TextKey('Номер телефона:'), TextValue(key='-PHONE-')],
        [TextKey('Факс:'), TextValue(key='-FAX-')],
        [TextKey('Дата окончания лицензии:'), TextValue(key='-EXPIRY_DATE-')],
        [TextKey('Тип лицензии:'), TextValue(key='-LIC_TYPE-')],
        [TextKey('Версия UTM:'), TextValue(key='-VERSION-')],
        [TextKey('Модель ПАК:'), TextValue(key='-DEVICE-')],
        [TextKey('Количество лицензий:'), TextValue(key='-USER_LIMIT-')],
        [sg.Frame('Зарегистрированные модули', frame_layout, expand_x=True)]
    ]
    layout = [
        [sg.TabGroup([[sg.Tab('Пользователи', tab1_layout), sg.Tab('Лицензия', tab2_layout)]], expand_y=True, expand_x=True)],
        [sg.Button(visible=False), sg.Button('Обновить'), sg.Button('Сохранить в файл', key='-SAVE-'), sg.Exit()]

    ]
    return sg.Window('Монитор лицензий v1.2',
                    layout,
                    keep_on_top=True,
                    location=get_location(),
                    resizable=True,
                    element_padding=(2, 5),
                    margins=(2, 3),
                    finalize=True)

def main():
    window = make_window()
    set_location(window)
    password = make_settings()
    if password:
        utm = UTM(sg.user_settings_get_entry('IP'), sg.user_settings_get_entry('Login'), password)
        utm.connect()
        init_window(window, utm)
    else:
        window.close()
        sys.exit()

    while True:
        event, values = window.read(timeout=50)
        if event in (sg.WINDOW_CLOSED, 'Exit'):
            utm.logout()
            break
        elif event == 'Обновить':
            if utm.ping_session():
                utm = UTM(sg.user_settings_get_entry('IP'), sg.user_settings_get_entry('Login'), password)
                utm.connect()
            init_window(window, utm)
        elif event == '-SAVE-':
            save_to_file(window)
        set_location(window)

    window.close()

if __name__ == '__main__':
    main()
