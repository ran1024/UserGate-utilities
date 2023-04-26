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
import os, sys
import console_classes as cc
import config_style as cs
from PyQt6.QtGui import QFont, QPalette
from PyQt6.QtCore import QSize, Qt, QObject
from PyQt6.QtWidgets import QApplication, QMainWindow, QHBoxLayout, QVBoxLayout, QWidget, QTabWidget, QSplitter, QMenu, QFileDialog, QScrollArea, QFrame


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._create_menu_bar()
        self._connect_actions()
        self.setWindowTitle("Консоль")
        self.base_path = ""

        self.settings = QWidget()
        self.settings.setContentsMargins(0, 0, 0, 0)
        self.settings_vbox = QVBoxLayout()
#        self.settings_vbox.addStretch(10)
        self.settings.setLayout(self.settings_vbox)

        routes = QWidget()
        snmp = QWidget()

        self.tab_main = QTabWidget()
        self.tab_main.addTab(self.settings, "Настройки")
        self.tab_main.addTab(routes, "Маршруты")
        self.tab_main.addTab(snmp, "SNMP")
        
        self.tree = cc.MainTree()

        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.tab_main)
        hbox = QHBoxLayout()
        hbox.addWidget(splitter)

        container = QWidget()
        container.setLayout(hbox)
        self.setCentralWidget(container)

        self.tree.itemSelected.connect(self.tree_selected)
        
    def _create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("Файл")
        self.open_config_action = file_menu.addAction("Загрузить конфигурацию")
        self.save_config_action = file_menu.addAction("Сохранить конфигурацию")
        file_menu.addSeparator()
        self.exit_action = file_menu.addAction("Выход", self.close)
        edit_menu = menu_bar.addMenu("Правка")
        help_menu = menu_bar.addMenu("Справка")

    def _connect_actions(self):
        # Menu actions
        self.open_config_action.triggered.connect(self.load_config_data)
        self.save_config_action.triggered.connect(self.save_config_data)

    def load_config_data(self):
        """
        Выбираем каталог с конфигурацией и читаем его. Фомируем set() с именами подкаталогов разделов.
        И вызываем функцию разблокировки соответствующего пункта дерева разделов MainTree::change_items_status()
        """
        print("Загружаем конфигурацию...")
        self.base_path = QFileDialog.getExistingDirectory(self, directory="~")
        print(self.base_path)
        data = set()
        if not os.path.isdir(self.base_path):
            print("Нет каталога с конфигурацией.")
        else:
            try:
                for entry in os.scandir(self.base_path):
                    if entry.is_dir():
                        for sub_entry in os.scandir(entry.path):
                            if sub_entry.is_dir():
                                data.add(sub_entry.name)
                self.tree.change_items_status(data)
            except FileNotFoundError as err:
                print("Ошибка:", err)

    def tree_selected(self, selected_path):
        """
        Получаем относительный путь к конфигурации выделенного раздела. Строим полный путь и загружаем файлы конфигурации раздела.
        """
        path = f"{self.base_path}/{selected_path}"
        print("Получили ...", selected_path)
        print("path:       ", path)

        if not os.path.isdir(self.base_path):
            label = cc.AlertLabel(f"Не найден каталог с конфигурацией\n{self.base_path}")
            self._update_tab_settings(label)
        elif not os.path.isdir(path):
            label = cc.AlertLabel(f"Не найден каталог\n {path}\n с конфигурацией этого раздела.")
            self._update_tab_settings(label)
        elif selected_path == "UserGate/GeneralSettings":
            widget = cc.GeneralSettings(self.base_path, selected_path)
            new_widget = cc.MyScrollArea()
            new_widget.setWidget(widget)
            self._update_tab_settings(new_widget)
            self.tab_main.setTabText(0, "Настройки")
        elif selected_path == "UserGate/Administrators":
            new_widget = cc.Administrators(self.base_path, selected_path)
            self._update_tab_settings(new_widget)
            self.tab_main.setTabText(0, "Администраторы")
        elif selected_path == "UserGate/Certificates":
            new_widget = cc.Certificates(self.base_path, selected_path)
            self._update_tab_settings(new_widget)
            self.tab_main.setTabText(0, "Сертификаты")
            
    def _update_tab_settings(self, new_widget):
        """
        Добавляем виджет раздела в таб если там пусто. Если нет, то удаляем существующий виджет и затем добавляем новый.
        """
        print("count: ", self.settings_vbox.count())
        if self.settings_vbox.count() == 0:
            self.settings_vbox.insertWidget(0, new_widget)
        else:
#            print(self.settings.children())
#            old_widget = self.settings.children()[1]
            old_widget = self.settings.findChild(QObject, "section_mainwidget")
            print(old_widget.parentWidget(), " --> ", old_widget)
            old_widget.deleteLater()
            self.settings_vbox.insertWidget(0, new_widget)

    def save_config_data(self):
        print("Сохраняем конфигурацию...")


def main():
    app = QApplication([])
#    app.setStyle("Fusion")
#    app.setStyleSheet(cs.Style.app)
    window = MainWindow()
    window.resize(1000, 800)
    window.show()
    app.exec()

if __name__ == '__main__':
    main()
