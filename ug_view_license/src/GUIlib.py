#!/usr/bin/python3
#########################################################################################
# Версия 0.1                                                                            #
# Общий класс для работы с графическими виджетами                                       #
#########################################################################################
import PySimpleGUI as sg
from dataclasses import dataclass

@dataclass(frozen=True)
class Color:
    key: str = "#CCCCCC"
    value: str = "#CCFFFF"

class TextKey(sg.Text):
    def __init__(self, text):
        super().__init__(text, pad=((2, 2), (4, 0)), text_color=Color.key)

class TextValue(sg.Text):
    def __init__(self, key):
        super().__init__(key=key, pad=((2, 2), (4, 0)), text_color=Color.value)
