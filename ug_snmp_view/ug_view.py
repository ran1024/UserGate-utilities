#!/usr/bin/python3
import threading
import PySimpleGUI as sg
from math import log10, sin
from time import sleep
from user_settings import make_settings
from snmp_query import get_ifnumber, get_ports, get_utm_status, get_port_counter


SETTINGS_PATH = '.'
state_1 = 0
state_2 = 0
utm_data = {
        'CpuLoad': 0,
        'MemoryUsed': 0,
        'LogSpace': 0,
        'PowerStatus1': '--',
        'PowerStatus2': '--',
        'RaidStatus': '--',
        'VcpuUsage': 0,
        'VcpuCount': 0,
        'UsersCounter': 0,
    }
ports = {}
sg.user_settings_filename(path=SETTINGS_PATH)

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

def test_network(ind):
    if ind == -2:
        sg.PopupError('Ошибка!', 'Network is unreachable.', 'Проверьте сетевое соединение.')
        exit()
    elif ind == -1:
        sg.PopupError('Ошибка!', 'Time out.', 'Устройство не отвечает.')

def init_window(window, utm_data):
    """
    Начальная инициализация окна.
    """
    window.bind('<Button-3>', '+RIGHT CLICK+')
    ip = sg.user_settings_get_entry('IP')
    community = sg.user_settings_get_entry('Community')
    utm_name = sg.user_settings_get_entry('Name')
    window['-NAME-'](utm_name)
    window['-IP-'](ip)
    update_status(window, utm_data)
    ports.clear()

    result = get_ports(ip, community, ports)
    test_network(result)
    if result == -1:
        return 1000
    layout = []
    for port in ports.values():
        layout.append(
            [sg.Text(port.name, size=(10, 1), pad=(6, 0), font=('', 8), background_color=(port.b_color)),
            sg.ProgressBar(11, orientation='h', size=(19, 12), pad=(0, 0), key=f'-{port.name}-', bar_color=('gray', port.b_color)),
            sg.Text(size=(11, 1), pad=(4, 0), font=('', 8), key=f'-COUNT{port.name}-', background_color=(port.b_color)),
            sg.Text('Байт/с', size=(5, 1), pad=(0, 0), font=('', 7), background_color=(port.b_color))]
        )
    window.extend_layout(window, layout)
    result = get_ifnumber(ip, community)
    if not result or result < 0:
        sg.PopupError('Ошибка!', 'Устройство не отвечает на SNMP запросы.')
        return 1000
    return result

def update_window(if_number, window, utm_data):
    """
    Периодически проверяем кол-во интерфейсов и при не совпадении переинициализируем окно.
    """
    ip=sg.user_settings_get_entry('IP')
    community = sg.user_settings_get_entry('Community')
    new_number = get_ifnumber(ip, community)
#    test_network(new_number)
    if new_number == -2:
        exit()
    elif new_number != -1:
        if if_number != new_number:
            window.close()
            del window
            window = make_window()
            if_number = init_window(window, utm_data)
    return if_number, window

def make_window():
    sg.theme('Dark')
    sg.SetOptions(
                  progress_meter_color = ('white', '#404040')
                 )
    layout = [[sg.Text('Имя:', size=(4, 1), font=(22)), sg.Text(size=(14, 1), pad=(0, 0), key='-NAME-', text_color='lightgreen', font=(22)),
               sg.Text('IP:', font=(22), pad=(7, 0)), sg.Text(size=(15, 1), key='-IP-', text_color='lightgreen', font=(22))],
              [sg.Text('Загрузка процессора (%):', size=(22, 1)), sg.Text(size=(4, 1), pad=(0, 0), key='-CpuLoad-'),
               sg.Text('Блок питания-1: ', size=(14, 1)), sg.Text(size=(16, 1), pad=(0, 0), key='-PowerStatus1-')],
              [sg.Text('Занятая память (%):', size=(22, 1)), sg.Text(size=(4, 1), pad=(0, 0), key='-MemoryUsed-'),
               sg.Text('Блок питания-2: ', size=(14, 1)), sg.Text(size=(16, 1), pad=(0, 0), key='-PowerStatus2-')],
              [sg.Text('Журналами занято (%):', size=(22, 1)), sg.Text(size=(4, 1), pad=(0, 0), key='-LogSpace-'),
               sg.Text('Raid Status: ', ), sg.Text(size=(10, 1), key='-RaidStatus-')],
              [sg.Text('System vCPU used:', size=(22, 1)), sg.Text(size=(4, 1), pad=(0, 0), key='-VcpuUsage-'),
               sg.Text('Активные пользователи: ', size=(22, 1)), sg.Text(size=(4, 1), pad=(0, 0), key='-UsersCounter-')],
              [sg.Text('System vCPU count:', size=(22, 1)), sg.Text(size=(10, 1), pad=(0, 0), key='-VcpuCount-')],
               [sg.Text('-'*103)]]

    return sg.Window('Состояние UTM',
                    layout, button_color=('Green', 'White'),
                    keep_on_top=True,
                    location=get_location(),
                    finalize=True)

def update_status(window, utm_data):
    window['-CpuLoad-'](utm_data['CpuLoad'])
    window['-MemoryUsed-'](utm_data['MemoryUsed'])
    window['-LogSpace-'](utm_data['LogSpace'])
    window['-VcpuUsage-'](utm_data['VcpuUsage'])
    window['-VcpuCount-'](utm_data['VcpuCount'])
    window['-PowerStatus1-'](utm_data['PowerStatus1'])
    window['-PowerStatus2-'](utm_data['PowerStatus2'])
    window['-RaidStatus-'](utm_data['RaidStatus'])
    window['-UsersCounter-'](utm_data['UsersCounter'])

def update_utm_data(utm_data):
    global state_1
    while True:
        ip=sg.user_settings_get_entry('IP')
        community = sg.user_settings_get_entry('Community')
        state_1, data = get_utm_status(ip, community)
        for key in data:
            utm_data[key] = data[key]
        sleep(3)

def snmp_requests(ports):
    global state_2
    while True:
        ip=sg.user_settings_get_entry('IP')
        community = sg.user_settings_get_entry('Community')
        state_2 = get_port_counter(ip, community, ports)
        sleep(3)

def update_ports_count(window):
    global state_1
    for port in ports.values():
        value = 1
        octets_sum = (port.octets_in + port.octets_out) // 3
        if octets_sum <= 100:
            bar_value = sin(octets_sum) / 3
        else:
            bar_value = log10(octets_sum + 1)
        window[f'-{port.name}-'].UpdateBar(bar_value)
        window[f'-COUNT{port.name}-'](octets_sum)
    if state_1 <= 0:
        window['-IP-'].update(text_color='red')
        window['-NAME-'].update(text_color='red')
    else:
         window['-IP-'].update(text_color='lightgreen')
         window['-NAME-'].update(text_color='lightgreen')

def main():
    update_counter1 = 0
    update_counter2 = 0
    window = make_window()

    if not sg.user_settings_get_entry('IP') or not sg.user_settings_get_entry('Community'):
        set_location(window)
        status = make_settings()
        if status == 1:
            window.close()
            exit()
    if_number = init_window(window, utm_data)
    x = threading.Thread(target=snmp_requests, args=(ports,), daemon=True)
    y = threading.Thread(target=update_utm_data, args=(utm_data,), daemon=True)
    x.start()
    y.start()

    while True:
        event, values = window.read(timeout=50)
        if event in (sg.WINDOW_CLOSED, 'Exit'):
            break
        elif event == '+RIGHT CLICK+':
            status = make_settings()
            if status == 1:
                break
            elif status == 2:
                window.close()
                del window
                window = make_window()
                if_number = init_window(window, utm_data)
        set_location(window)
        # Периодически проверяем кол-во интерфейсов и при не совпадении переинициализируем окно.
        if update_counter1 >= 200:
            if update_counter2 >= 250:
                if_number, window = update_window(if_number, window, utm_data)
                update_counter1 = 0
                update_counter2 = 0
            else:
                update_counter2 += 1
        update_counter1 += 1

        update_status(window, utm_data)
        update_ports_count(window)
    window.close()

if __name__ == '__main__':
    main()
