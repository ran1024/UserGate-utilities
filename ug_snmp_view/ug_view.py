#!/usr/bin/python3
#
# ug_view (simple SNMP viewer for NGFW UserGate), version 2.0.
#
# Copyright @ 2020-2022 UserGate Corporation. All rights reserved.
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
#
#import threading
import PySimpleGUI as sg
from user_settings import make_settings, make_ports, make_graphs
from snmp_query import get_ports, get_utm_status, get_port_counter, check_snmp, get_all_ports, create_host_rrd, update_host_rrd, create_host_graph, remove_host_graph


SETTINGS_PATH = '.'
FIRST_INIT = 1
SETTINGS_UPDATED = 2
sg.user_settings_filename(path=SETTINGS_PATH)

def get_location():
    """
    Определение координат окна.
    """
    if 'Location' in sg.user_settings():
        arr = sg.user_settings_get_entry('Location')
        return (arr[0]-5, arr[1]-51)
    else:
        return (150, 130)

def set_location(window):
    """
    Отслеживаем положение окна на экране и запомнаем, если изменилось.
    """
    current_location = window.CurrentLocation()
    if current_location != sg.user_settings_get_entry('Location'):
        sg.user_settings_set_entry('Location', window.CurrentLocation())

def make_window():
    sg.theme('Dark')
    sg.SetOptions(
                  progress_meter_color = ('white', '#404040')
                 )
    menu_def = [
        ['Main', ['Параметры', '!Интерфейсы', '!Графики', '---', 'Exit']],
    ]
    left_col1 = [
        [sg.Text('Имя:', font=(22), pad=(0, (0, 8))), sg.Text(size=(14, 1), pad=(0, (0, 8)), key='-NAME-', text_color='lightgreen', font=(22))],
        [sg.Text('Загрузка процессора (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-CpuLoad-')],
        [sg.Text('Занятая память (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-MemoryUsed-')],
        [sg.Text('Журналами занято (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-LogSpace-')],
        [sg.Text('Загрузка vCPU (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-VcpuUsage-')],
        [sg.Text('Количество vCPU:', pad=(0, 2), size=(19, 1)), sg.Text(size=(7, 1), justification='right', pad=(0, 2), key='-VcpuCount-')],
    ]
    left_col2 = [
        [sg.Text('IP:', font=(22), pad=(0, (0, 7))), sg.Text(size=(14, 1), pad=(0, (0, 7)), key='-IP-', text_color='lightgreen', font=(22))],
        [sg.Text('Блок питания-1: ', pad=(0, 2), size=(14, 1)), sg.Text(size=(16, 1), justification='right', pad=(0, 2), key='-PowerStatus1-')],
        [sg.Text('Блок питания-2: ', pad=(0, 2), size=(14, 1)), sg.Text(size=(16, 1), justification='right', pad=(0, 2), key='-PowerStatus2-')],
        [sg.Text('Raid Status: ', pad=(0, 2), size=(14, 1)), sg.Text(size=(16, 1), justification='right', pad=(0, 2), key='-RaidStatus-')],
        [sg.Text('Активные пользователи: ', pad=(0, 2), size=(21, 1)), sg.Text(size=(9, 1), justification='right', pad=(0, 2), key='-UsersCounter-')],
        [sg.Text(pad=(0, 2))],
    ]
    image_col = [[sg.Image(key='-MAIN_IMAGE-', pad=((2, 0), (0, 2)))]]
    left_col_summ = [
        [sg.Column(left_col1, pad=(0, 0)), sg.Column(left_col2, pad=((10, 0), 0))],
        [sg.HSep()],
    ]
    layout = [
        [sg.Menu(menu_def, key='-Menu-')],
        [sg.Column(left_col_summ, pad=(0, 0)), sg.Column(image_col, pad=(0, 0))],
        
    ]
    return sg.Window(
        'Состояние UTM',
        layout, button_color=('Green', 'White'),
        keep_on_top=True,
        location=get_location(),
        finalize=True
    )

def init_window(window):
    """
    Начальная инициализация окна.
    """
    ports = {}
    window.bind('<Button-3>', '+RIGHT CLICK+')
    status = SETTINGS_UPDATED
    ip = sg.user_settings_get_entry('IP')
    community = sg.user_settings_get_entry('Community')
    if not ip or not community:
        return FIRST_INIT, '', '', {}
    else:
        utm_name = sg.user_settings_get_entry('Name')
        window['-NAME-'](utm_name)
        window['-IP-'](ip)
        status = check_host(ip, community)
        if status != FIRST_INIT:
            status, ports = check_ports(ip, community)
            update_menu(window)
            update_window(window, ports)
        return status, ip, community, ports

def update_window(window, ports):
    graphs_list = [sg.Image(filename=f'data/{port.name}.png', pad=(0, 0), key=f'{port.name}') for port in ports.values()]
    if len(graphs_list)%2 != 0:
        graphs_list.append(sg.Text("", visible=False))
    layout = [[graphs_list[i], graphs_list[i+1]] for i in range(0, len(graphs_list)-1, 2)]
    window.extend_layout(window, layout)

def update_menu(window):
    menu_def = [
        ['Main', ['Параметры', 'Интерфейсы', 'Графики', '---', 'Exit']],
    ]
    window['-Menu-'].update(menu_def)

def update_utm_data(window, perf_time):
    status = SETTINGS_UPDATED
    ip=sg.user_settings_get_entry('IP')
    community = sg.user_settings_get_entry('Community')
    err, data = get_utm_status(ip, community)
    if not err:
        update_host_rrd(data.get('CpuLoad', 'U'), data.get('vcpuUsage', 'U'), data.get('MemoryUsed', 'U'))
        create_host_graph(perf_time)
        window['-CpuLoad-'](data.get('CpuLoad', '--'))
        window['-MemoryUsed-'](data.get('MemoryUsed', '--'))
        window['-LogSpace-'](data.get('LogSpace', '--'))
        window['-VcpuUsage-'](data.get('vcpuUsage', '--'))
        window['-VcpuCount-'](data['vcpuCount']*100 if data.get('vcpuCount', False) else '--')
        window['-PowerStatus1-'](data.get('PowerStatus1', '--'))
        window['-PowerStatus2-'](data.get('PowerStatus2', '--'))
        window['-RaidStatus-'](data.get('RaidStatus', '--'))
        window['-UsersCounter-'](data.get('usersCounter', '--'))
        window['-MAIN_IMAGE-']('data/main.png')
    elif err == 3:
        sg.PopupError(f'Ошибка!', 'В snmp_query.get_utm_status не указаны необходимые события.', keep_on_top=True)
        status = FIRST_INIT
    else:
        sg.PopupError(f'Ошибка ({err})!', f'Устройство не ответило на SNMP запрос.\n{data}', keep_on_top=True)
        status = FIRST_INIT
    return status

def check_host(ip, community):
    status = SETTINGS_UPDATED
    if check_snmp(ip, community) == 'timeout':
        sg.PopupError('Ошибка!', 'Данный узел не отвечает на SNMP запросы.', keep_on_top=True,)
        status = FIRST_INIT
    else:
        create_host_rrd()
    return status

def check_ports(ip, community):
    status = SETTINGS_UPDATED
    used_ports = sg.user_settings_get_entry('Ports')
    trafic_time = sg.user_settings_get_entry('TraficTime')
    err, ports = get_ports(ip, community, used_ports, trafic_time)
    if err == 3:
        sg.PopupError(f'Ошибка!', 'На UTM в настройках SNMP не указано событие:\n"Таблица статистики сетевых интерфейсов"', keep_on_top=True)
        status = FIRST_INIT
    elif err != 0:
        sg.PopupError(f'Ошибка ({err})!', 'Устройство не ответило на SNMP запрос.', keep_on_top=True)
        status = FIRST_INIT
    return status, ports

def main():
    window = make_window()
    window_status, ip, community, ports = init_window(window)
    perf_time = sg.user_settings_get_entry('PerformanceTime')
    trafic_time = sg.user_settings_get_entry('TraficTime')
    while True:
        event, values = window.read(timeout=1000)
        if event in (sg.WINDOW_CLOSED, 'Exit'):
            break
        elif event == 'Параметры':
            window_status = make_settings()
            if window_status == SETTINGS_UPDATED:
                utm_name = sg.user_settings_get_entry('Name')
                ip = sg.user_settings_get_entry('IP')
                community = sg.user_settings_get_entry('Community')
                window['-NAME-'](utm_name)
                window['-IP-'](ip)
                update_menu(window)
                window_status = check_host(ip, community)

        elif event == 'Интерфейсы':
            all_ports = get_all_ports(ip, community)
            window_status = make_ports(all_ports)
            if window_status == SETTINGS_UPDATED:
                window_status, ports = check_ports(ip, community)
                window.close()
                del window
                window = make_window()
                window_status, ip, community, ports = init_window(window)

        elif event == 'Графики':
            window_status = make_graphs()
            if window_status == SETTINGS_UPDATED:
                perf_time = sg.user_settings_get_entry('PerformanceTime')
                trafic_time = sg.user_settings_get_entry('TraficTime')
                remove_host_graph()
                for port in ports.values():
                    port.remove_rrd_graph()

        set_location(window)
        if window_status != FIRST_INIT:
            window_status = update_utm_data(window, perf_time)

            if ports:
                state = get_port_counter(ip, community, ports)

        for port in ports.values():
            port.create_rrd_graph(trafic_time)
            window[port.name](f'data/{port.name}.png')

    window.close()

if __name__ == '__main__':
    main()
