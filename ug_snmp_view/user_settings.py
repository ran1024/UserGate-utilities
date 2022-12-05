#!/usr/bin/python3
import PySimpleGUI as sg
from itertools import zip_longest
from fastsnmp import snmp_poller


def make_settings():
    """
    Окно для ввода имени UTM, IP адреса и community.
    """
    new_loc = [sum(i) for i in zip_longest(sg.user_settings_get_entry('Location'), [100,100], fillvalue=0)]
    layout = [[sg.Text('Имя:', size=(10, 1), pad=((1, 5),(10, 5))),
                 sg.Input(sg.user_settings_get_entry('Name'), size=(20, 1), pad=((1, 0),(10, 5)), border_width=0, key='-NAME-')],
              [sg.Text('IP: ', size=(10, 1), pad=((1, 5),(5, 10))),
                 sg.Input(sg.user_settings_get_entry('IP'), size=(20, 1), pad=((1, 0),(5, 10)), border_width=0, key='-IPADDR-')],
              [sg.Text('Community: ', size=(10, 1), pad=((1, 5),(5, 10))),
                 sg.Input(sg.user_settings_get_entry('Community'), size=(20, 1), pad=((1, 0),(5, 10)), border_width=0, key='-COMMUNITY-')],
              [sg.Cancel(pad=((1, 1), (5, 5))), sg.B('Save', pad=((83, 0), (5, 5)), size=(6, 1))]]


    window = sg.Window('Настройка опроса',
                    layout, button_color=('Green', 'White'),
                    keep_on_top=True,
                    location = new_loc,
                    finalize = True,)
    window.make_modal()
    status = 0
    data = ('None', 0, '', ' ', 'null')
    while True:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, 'Cancel'):
            if (values['-NAME-'] in data) or (values['-IPADDR-'] in data) or (values['-COMMUNITY-'] in data):
                status = 1
            break
        elif event == 'Save':
            if (values['-NAME-'] in data) or (values['-IPADDR-'] in data) or (values['-COMMUNITY-'] in data):
                sg.PopupError('Ошибка!', 'Заполните все поля!')
                continue
            if values['-IPADDR-'].count('.') == 3 and all(0<=int(num)<256 for num in values['-IPADDR-'].rstrip().split('.')):
                sg.user_settings_set_entry('Name', values['-NAME-'])
                sg.user_settings_set_entry('IP', values['-IPADDR-'])
                sg.user_settings_set_entry('Community', values['-COMMUNITY-'])
                status = 2
                break
            else:
                sg.PopupError('Ошибка!', 'Некорректный IP-адрес!')
                continue

    window.close()
    del window
    return status

def make_ports(all_ports):
    """
    Окно для выбора портов для мониторинга.
    """
    used_ports = sg.user_settings_get_entry('Ports')
    if used_ports:
        ports = [sg.Checkbox(d, size=(10, 1),  key=f'{d}', default=(True if d in used_ports else False)) for d in all_ports]
    else:
        ports = [sg.Checkbox(d, size=(10, 1),  key=f'{d}') for d in all_ports]
    while len(ports)%3 != 0:
        ports.append(sg.Text('Text', visible=False))

    new_location = [sum(i) for i in zip_longest(sg.user_settings_get_entry('Location'), [100,100], fillvalue=0)]
    layout = [[sg.Text('Выберите порты для мониторинга.')],]

    len_ports = len(ports)

    if len_ports <= 7:
        for element in ports:
            layout.append([element])
    else:
        num_rows = len_ports//3
#        num = (num_rows)*3
        layout_ports = [[ports[i], ports[i+num_rows], ports[i+num_rows*2]] for i in range(0, num_rows)]
        layout.extend(layout_ports)

    layout.append([sg.Cancel(pad=((10, 10), (5, 5))), sg.B('Save', size=(6, 1))])

    window = sg.Window('Выбор портов для опроса',
                    layout, button_color=('Green', 'White'),
                    keep_on_top=True,
                    location = new_location,
                    finalize = True,)
    window.make_modal()

    status = 0
    while True:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, 'Cancel'):
            break
        elif event == 'Save':
            result = [k for k, v in values.items() if v]
            if not result:
                sg.popup_ok('Не выбраны порты для мониторинга.', keep_on_top=True)
                result = []
            sg.user_settings_set_entry('Ports', result)
            status = 2
            break

    window.close()
    del window
    return status

def make_graphs():
    """
    Окно для выбора периода времени для графиков.
    """
    perfomance_time = sg.user_settings_get_entry('PerformanceTime')
    trafic_time = sg.user_settings_get_entry('TraficTime')
    times = {1: '-20m', 2: '-1h', 3: '-24h', 4: '-20m', 5: '-1h', 6: '-24h'}
    if not perfomance_time:
        perfomance_time = times[2]
    if not trafic_time:
        trafic_time = times[5]

    new_location = [sum(i) for i in zip_longest(sg.user_settings_get_entry('Location'), [100,100], fillvalue=0)]
    layout = [
        [sg.Text('Выберите точку отсчёта начала графика')],
        [sg.HSep()],
        [sg.Text('Для графика производительности')],
        [sg.Radio('20 минут', 'PERF', size=(10, 1), default=True if perfomance_time == '-20m' else ''),
         sg.Radio('1 час', 'PERF', default=True if perfomance_time == '-1h' else ''),
         sg.Radio('1 день', 'PERF', default=True if perfomance_time == '-24h' else '')],
        [sg.Text('Для графиков трафика')],
        [sg.Radio('20 минут', 'TRAFIC', size=(10, 1), default=True if trafic_time == '-20m' else ''),
         sg.Radio('1 час', 'TRAFIC', default=True if trafic_time == '-1h' else ''),
         sg.Radio('1 день', 'TRAFIC', default=True if trafic_time == '-24h' else '')],
        [sg.Cancel(pad=((10, 10), (5, 5))), sg.B('Save', size=(6, 1))]
    ]

    window = sg.Window('Выбор временного периода графиков',
                    layout, button_color=('Green', 'White'),
                    keep_on_top=True,
                    location = new_location,
                    finalize = True,)
    window.make_modal()

    status = 0
    while True:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, 'Cancel'):
            break
        elif event == 'Save':
            result = [times[k] for k, v in values.items() if v]
            sg.user_settings_set_entry('PerformanceTime', result[0])
            sg.user_settings_set_entry('TraficTime', result[1])
            status = 2
            break

    window.close()
    del window
    return status
