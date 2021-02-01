#!/usr/bin/python3
import PySimpleGUI as sg
from itertools import zip_longest


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
                    location = new_loc)

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
            sg.user_settings_set_entry('Name', values['-NAME-'])
            sg.user_settings_set_entry('IP', values['-IPADDR-'])
            sg.user_settings_set_entry('Community', values['-COMMUNITY-'])
            status = 2
            break

    window.close()
    del window
    return status
