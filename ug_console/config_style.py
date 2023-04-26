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
from enum import Enum
from datetime import datetime as dt
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QSpinBox, QMessageBox


appointment = {
    "proxy_ca": "SSL инспектирование",
    "saml": "SAML server",
    "reverseproxy_rules": "Правила reverse-прокси",
    "webui": "SSL веб-консоли"
}

class Color(str, Enum):
    ALARM = "darkred"
    BLACK = "darkblack"
    GRAY = "gray"
    GREEN = "darkgreen"
    NORM = "steelblue"
    ORANGE = "darkorange"


class Style(str, Enum):
    Test = ("""
        QWidget {
            background: yllow;
        }
    """)
    GroupBox = ("""
        QGroupBox {
            color: grey;
            font-weight: bold;
        }
        Qwidget {
            background-color: #ffffff;
        }
    """)
    MainTree = ("""
        QTreeWidget::item:hover {
            background: lightblue;
        }
        QTreeWidget::item:hover:selected {
            background: #349AD9;
        }
    """)
    ListTree = ("""
        QTreeWidget::item {
            padding-top: 3px;
            padding-bottom: 3px;
        }
        QTreeWidget::item:hover {
            background: lightblue;
            color: black;
        }
        QTreeWidget::item:hover:selected {
            background: #349AD9;
        }
    """)
    ListTreeEnabledItems = ("""
        QTreeWidget::item {
            color: #1f5e82;
            padding-top: 3px;
            padding-bottom: 3px;
        }
        QTreeWidget::item:hover {
            background: lightblue;
            color: black;
        }
        QTreeWidget::item:hover:selected {
            background: #349AD9;
        }
    """)
    LineEdit = ("""
        QLineEdit {
            background-color: white;
            color: black;
            min-width: 170px;
        }
        QLineEdit:hover {
            background-color: lightblue;
            color: black;
        }
    """)
#    app = ("""
#        QScrollBar {
#            background: blue;
#        }
#    """)

class SelectLabel(QLabel):
    def __init__(self, value, color=Color.BLACK, wrap=False):
        super().__init__(value)
        self.color = color
        self.setWordWrap(wrap)
        self.setStyleSheet(f"color: {self.color}")
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)


class SpinBox(QSpinBox):
    def __init__(self, value, min_length=0, max_length=100, frame=True, enabled=True):
        super().__init__()
        self.setMinimum(min_length)
        self.setMaximum(max_length)
        self.setValue(value)
        self.setWrapping(True)
        self.setEnabled(enabled)
        self.setFrame(frame)

    
class EventTracker():
    def __init__(self, param):
        self.base_path = param
    
    def __call__(self):
        print("Метод EventTracker", self.base_path)
#        self.exec()


def message_alert(self, err, messsage):
    """
    Алерт при любых ошибках.
    """
    QMessageBox.critical(self.parent(), "Ошибка!", f"{messsage}\n{err}", defaultButton=QMessageBox.StandardButton.Ok)

def message_inform(self, title, text):
    """
    Общее информационное окно. Принимает родителя, заголовок и текст сообщения.
    """
    QMessageBox.information(self.parent(), title, text, defaultButton=QMessageBox.StandardButton.Ok)


def convert_date(datetime):
    date = dt.strptime(datetime, "%Y-%m-%dT%H:%M:%S%fZ").strftime("%d %B %Y г.")
    return date

def convert_datetime(datetime):
    date_time = dt.strptime(datetime, "%Y-%m-%dT%H:%M:%S%fZ").strftime("%Y-%m-%d %H:%M:%S")
    return date_time

