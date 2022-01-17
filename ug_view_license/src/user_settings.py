#!/usr/bin/python3
import PySimpleGUI as sg
from itertools import zip_longest


def make_settings():
    """
    Окно для ввода имени IP адреса, имени и пароля администратора.
    """
    new_loc = [sum(i) for i in zip_longest(sg.user_settings_get_entry('Location'), [100,100], fillvalue=0)]
    layout = [
                [sg.Text('UTM IP: ', size=(10, 1), pad=((1, 5),(5, 5))),
                 sg.Input(sg.user_settings_get_entry('IP'), size=(20, 1), pad=((1, 0),(5, 5)), border_width=0, key='-IPADDR-', text_color='#E9E9EA')],
                [sg.Text('Имя:', size=(10, 1), pad=((1, 5),(5, 5))),
                 sg.Input(sg.user_settings_get_entry('Login'), size=(20, 1), pad=((1, 0),(5, 5)), border_width=0, key='-NAME-', text_color='#E9E9EA')],
                [sg.Text('Пароль: ', size=(10, 1), pad=((1, 5),(5, 10))),
                 sg.Input(password_char='*', size=(20, 1), pad=((1, 0),(5, 10)), border_width=0, key='-PASSWORD-', text_color='#E9E9EA')],
                [sg.Exit(pad=((1, 1), (5, 5)), key='-EXIT-'), sg.B('Save', key='-SAVE-')]
              ]


    window = sg.Window('Настройка', layout, keep_on_top=True, location = new_loc, modal=True, return_keyboard_events=True)

    status = 0
    data = ('None', 0, '', ' ', 'null')
    while True:
        event, values = window.read()
        if event in (sg.WINDOW_CLOSED, '-EXIT-'):
            break
        elif event == '-SAVE-':
            if (values['-NAME-'] in data) or (values['-IPADDR-'] in data) or (values['-PASSWORD-'] in data):
                sg.PopupError('Ошибка!', 'Заполните все поля!', keep_on_top=True)
                continue
            sg.user_settings_set_entry('Login', values['-NAME-'])
            sg.user_settings_set_entry('IP', values['-IPADDR-'])
            status = values['-PASSWORD-']
            break
        elif event == 'Return:36':
            element = window.find_element_with_focus()
            if element in (window['-EXIT-'], window['-SAVE-']):
                element.click()

    window.close()
    del window
    return status

def progress_bar():
    """
    Окно progress bar
    """
    layout = [
        [sg.Text('Операция выполняется...')],
        [sg.ProgressBar(2000, orientation='h', size=(20, 20), key='-PROGRESS_BAR-')],
        [sg.Cancel()]
    ]
    
    window = sg.Window('Выполнение', layout, keep_on_top=True)
    progress_bar = window['-PROGRESS_BAR-']
    for i in range(2000):
        event, values = window.read(timeout=10)
        if event == 'Cancel' or event is None:
            break
        progress_bar.UpdateBar(i+1)
    
    window.close()
