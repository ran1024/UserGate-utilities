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
import os, json
from PyQt6.QtGui import *
from PyQt6.QtCore import Qt, QObject
from PyQt6.QtWidgets import (QDialog, QPushButton, QVBoxLayout, QFormLayout, QTreeWidget, QTreeWidgetItem,
                             QTabWidget, QWidget, QLineEdit, QTextEdit, QGroupBox, QListWidget, QCheckBox, QFrame,
                             QGridLayout)
import config_style as cs

class TestEventTracker():
    def __init__(self, param):
        self.base_path = param
    
    def __call__(self):
        print("Метод TestEventTracker", self.base_path)
#        self.exec()


class LineEdit(QLineEdit):
    def __init__(self, value, frame=True):
        super().__init__()
        self.setStyleSheet(cs.Style.LineEdit)
        self.setText(value)
        self.setFrame(frame)
#        self.setReadOnly(True)

    def mousePressEvent(self, e):
        print("Clicked!", e)


class CertSettings(QDialog):
    """
    Диалоговое окно "UserGate" --> "Сертификаты" --> "Редактировать".
    """
    def __init__(self, parent, base_path, cert_name):
        super().__init__()
        self.setParent(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Свойства SSL-сертификата")
        self.resize(490, 400)
        self.path = f"{base_path}/certificates_list.json"
        self.cert_name = cert_name
        text1 = "Опциональное поле, требуется в случае, если необходимо возвращать клиентам полную цепочку сертификатов."
        text2 = "Нельзя изменить тип сертификата, потому что он используется в качестве сертификата SSL веб-консоли или сертификата для SSL инспектирования."
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QGridLayout()
        btn_select = QPushButton("Выбрать")
        btn_select.setEnabled(False)
        try:
            with open(self.path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")
        else:
            for item in data:
                if item['name'] == self.cert_name:
                    self.cert_data = item
                    break
            layout.addWidget(cs.SelectLabel("Название:"), 0, 0)
            layout.addWidget(QLineEdit(self.cert_data['name']), 0, 1, 1, 2)
            layout.addWidget(cs.SelectLabel("Описание:"), 1, 0)
            layout.addWidget(QTextEdit(self.cert_data['description']), 1, 1, 1, 2)
            layout.addWidget(cs.SelectLabel("Используется:", color=cs.Color.GRAY), 2, 0)
            self.used_linedit = QLineEdit(cs.appointment.get(self.cert_data['role'], self.cert_data['role']))
            self.used_linedit.setEnabled(False)
            layout.addWidget(self.used_linedit, 2, 1, 1, 2)
            layout.addWidget(cs.SelectLabel("Пользователь:", color=cs.Color.GRAY), 3, 0)
            self.user_linedit = QLineEdit(self.cert_data['user_guid'])
            self.user_linedit.setEnabled(False)
            layout.addWidget(self.user_linedit, 3, 1)
            layout.addWidget(btn_select, 3, 2)
            layout.addWidget(cs.SelectLabel("Файл сертификата:"), 4, 0)
            layout.addWidget(QLineEdit(""), 4, 1)
            layout.addWidget(QPushButton("Обзор..."), 4, 2)
            layout.addWidget(cs.SelectLabel("Цепочка сертификатов:"), 5, 0)
            layout.addWidget(QLineEdit(""), 5, 1)
            layout.addWidget(QPushButton("Обзор..."), 5, 2)
            layout.addWidget(cs.SelectLabel(text1, color=cs.Color.GRAY, wrap=True), 6, 1, 1, 2)
            if self.cert_data['role'] in ("proxy_ca", "webui"):
                layout.addWidget(cs.SelectLabel(text2, wrap=True), 7, 0, 1, 3)

        frame.setLayout(layout)

        buttonOK = QPushButton("Закрыть")
        buttonOK.setDefault(True)
        buttonOK.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(frame)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def __call__(self):
        self.exec()


class CertView(QDialog):
    """
    Диалоговое окно "UserGate" --> "Сертификаты" --> "Показать".
    """
    def __init__(self, parent, base_path, cert_name):
        super().__init__()
        self.setParent(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Детали сертификата")
#        self.resize(530, 600)
        self.path = f"{base_path}/{cert_name}.json"
        self.cert_name = cert_name
        tab = QTabWidget()
        try:
            with open(self.path, "r") as fh:
                self.data = json.load(fh)
        except FileNotFoundError as err:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")
        else:
            self._create_tab_cert_settings()
            self._create_tab_cert_chains()
            tab.addTab(self.tab_cert_settings, "Свойства сертификата")
            tab.addTab(self.tab_cert_chains, "Информация цепочки")

        buttonOK = QPushButton("Закрыть")
        buttonOK.clicked.connect(self.accept)
            
        layout = QVBoxLayout()
        layout.addWidget(tab)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def _create_tab_cert_settings(self):
        """
        Создаём форму для вкладки "Свойства сертификата".
        """
        start_time = cs.convert_datetime(self.data['notBefore'])
        end_time = cs.convert_datetime(self.data['notAfter'])
        self.tab_cert_settings = QWidget()
        form = QFormLayout()
        form.addRow("Серийный номер:", cs.SelectLabel(self.data['serialNumber']))
        form.addRow("Алгоритм подписи:", cs.SelectLabel(self.data['signatureAlgorithm']))
        form.addRow("Алгоритм публичного ключа:", cs.SelectLabel(self.data['publicKeyAlgorithm']))
        form.addRow("Действует с:", cs.SelectLabel(start_time))
        form.addRow("Истекает:", cs.SelectLabel(end_time))
        form.setHorizontalSpacing(20)

        box1 = QGroupBox("Эмитент")
        box1.setStyleSheet(cs.Style.GroupBox)
        form_box1 = QFormLayout()
        form_box1.addRow("Страна:", cs.SelectLabel(self.data['issuer']['countryName']))
        if 'stateOrProvinceName' in self.data['issuer']:
            form_box1.addRow("stateOrProvinceName:", cs.SelectLabel(self.data['issuer']['stateOrProvinceName']))
        form_box1.addRow("Город:", cs.SelectLabel(self.data['issuer']['localityName']))
        form_box1.addRow("Название организации:", cs.SelectLabel(self.data['issuer']['organizationName']))
        form_box1.addRow("Common name:", cs.SelectLabel(self.data['issuer']['commonName']))
        if 'emailAddress' in self.data['issuer']:
            form_box1.addRow("E-mail:", cs.SelectLabel(self.data['issuer']['emailAddress']))
        form_box1.setHorizontalSpacing(40)
        box1.setLayout(form_box1)

        box2 = QGroupBox("Subject")
        box2.setStyleSheet(cs.Style.GroupBox)
        form_box2 = QFormLayout()
        form_box2.addRow("Страна:", cs.SelectLabel(self.data['subject']['countryName']))
        if 'stateOrProvinceName' in self.data['subject']:
            form_box2.addRow("stateOrProvinceName:", cs.SelectLabel(self.data['subject']['stateOrProvinceName']))
        form_box2.addRow("Город:", cs.SelectLabel(self.data['subject']['localityName']))
        form_box2.addRow("Название организации:", cs.SelectLabel(self.data['subject']['organizationName']))
        form_box2.addRow("Common name:", cs.SelectLabel(self.data['subject']['commonName']))
        if 'emailAddress' in self.data['subject']:
            form_box2.addRow("E-mail:", cs.SelectLabel(self.data['subject']['emailAddress']))
        form_box2.setHorizontalSpacing(40)
        box2.setLayout(form_box2)

        form2 = QFormLayout()
        form2.addRow("Альтернативные имена (subjectAltName):", cs.SelectLabel(", ".join(x for x in self.data['altNames'])))
        form2.addRow("Key usage:", cs.SelectLabel(", ".join(x for x in self.data['keyUsage'])))
        form2.setHorizontalSpacing(20)
        
        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(box1)
        layout.addWidget(box2)
        layout.addLayout(form2)
        self.tab_cert_settings.setLayout(layout)

    def _create_tab_cert_chains(self):
        """
        Создаём форму для вкладки "Информация цепочки".
        """
        self.tab_cert_chains = QWidget()
        form = QFormLayout()
#        form.addRow("Название:", QLineEdit(self.profile["name"]))
#        form.addRow("Описание:", QTextEdit(self.profile["description"]))
#        form.setHorizontalSpacing(20)
        
        self.tab_cert_chains.setLayout(form)

    def __call__(self):
        self.exec()


class SettingsAdminsAuth(QDialog):
    """
    Диалоговое окно "UserGate" --> "Администраторы" --> "Настроить".
    """
    def __init__(self, parent, base_path):
        super().__init__()
        self.setParent(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Настройки")
        self.path = f"{base_path}/admin_config.json"
        param = False
        try:
            with open(self.path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")

        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        form = QFormLayout()
        strong_pwd = QCheckBox(self)
        if data['strong_pwd']:
            strong_pwd.setCheckState(Qt.CheckState.Checked)
            param = True
        form.addRow("Сложный пароль:", strong_pwd)
        form.addRow("Число неверных попыток аутентификации:", cs.SpinBox(data['n_of_invalid_auth']))
        form.addRow("Время блокировки (сек):", cs.SpinBox(data['block_time'], min_length=1, max_length=3600))
        form.addRow("Минимальная длина:", cs.SpinBox(data['min_length'], min_length=1, enabled=param))
        form.addRow("Минимальное число символов в верхнем регистре:", cs.SpinBox(data['min_uppercase'], enabled=param))
        form.addRow("Минимальное число символов в нижнем регистре:", cs.SpinBox(data['min_lowercase'], enabled=param))
        form.addRow("Минимальное число цифр:", cs.SpinBox(data['min_digit'], enabled=param))
        form.addRow("Минимальное число специальных символов:", cs.SpinBox(data['min_special'], enabled=param))
        form.addRow("Минимальная длина блока из одного символа:", cs.SpinBox(data['max_char_repetition'], min_length=1, enabled=param))
        form.setHorizontalSpacing(20)
        frame.setLayout(form)

        buttonOK = QPushButton("Закрыть")
        buttonOK.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(frame)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def __call__(self):
        self.exec()


class AdminSettings(QDialog):
    """
    Диалоговое окно "Настройки" --> "Администраторы" --> "Администраторы" --> "Свойства администратра".
    """
    def __init__(self, parent, base_path, admin_name):
        super().__init__()
        self.setParent(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Свойства администратра")
        self.path = f"{base_path}/admins_list.json"
        self.admin_name = admin_name

        try:
            with open(self.path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")
        else:
            for item in data:
                if item["login"] == self.admin_name:
                    self.settings = item

        profile = self.settings['profile_id'] if self.settings['profile_id'] != -1 else "Корневой профиль"

        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        form = QFormLayout()
        account_enebled = QCheckBox(self)
        if self.settings['enabled']:
            account_enebled.setCheckState(Qt.CheckState.Checked)
        form.addRow("Включено:", account_enebled)
        form.addRow("Логин:", QLineEdit(self.settings['login']))
        form.addRow("Описание:", QTextEdit(self.settings['description']))
        form.addRow("Профиль администратора:", QLineEdit(profile))
        form.addRow("Пароль:", QLineEdit(""))
        form.addRow("Подтверждение пароля:", QLineEdit(""))
        form.setHorizontalSpacing(20)
        frame.setLayout(form)

        buttonOK = QPushButton("Закрыть")
        buttonOK.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(frame)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def __call__(self):
        self.exec()


class AdminProfile(QDialog):
    """
    Диалоговое окно "Настройки" --> "Администраторы" --> "Профили администраторов" --> "Настройка профиля".
    """
    def __init__(self, parent, base_path, profile_name):
        super().__init__()
        self.setParent(parent, Qt.WindowType.Dialog)
        self.setWindowTitle("Настройка профиля")
        self.resize(530, 620)
        self.path = f"{base_path}/admin_profiles_list.json"
        self.profile_name = profile_name
        tab = QTabWidget()
        try:
            with open(self.path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")
        else:
            for item in data:
                if item["name"] == self.profile_name:
                    self.profile = item

            self._create_tab_general()
            self._create_tab_api()
            self._create_tab_web()
            self._create_tab_cli()
            tab.addTab(self.tab_general, "Общие")
            tab.addTab(self.tab_api, "Разрешения для API")
            tab.addTab(self.tab_web, "Разрешения доступа")
            tab.addTab(self.tab_cli, "Разрешения для CLI")

        buttonOK = QPushButton("Закрыть")
        buttonOK.clicked.connect(self.accept)
            
        layout = QVBoxLayout()
        layout.addWidget(tab)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def _create_tab_web(self):
        """
        Создаём дерево для вкладки "Разрешения доступа".
        """
        self.tab_web = QTreeWidget()
        self.tab_web.setHeaderLabels(["Объекты", "Разрешения"])
        self.tab_web.setColumnWidth(0, 320)
        permissions = {
            "none": ("Нет доступа", QBrush(Qt.GlobalColor.red)),
            "read": ("Чтение", QBrush(Qt.GlobalColor.blue)),
            "readwrite": ("Чтение/запись", QBrush(Qt.GlobalColor.darkGreen))
        }
        top_level_items = {
            "screen_dashboard": "Дашборд",
            "screen_diagnostics": "Диагностика и мониторинг",
            "screen_stat": "Журналы и отчёты",
            "screen_taconsole": "Гостевой портал"
        }
        dict_webui = {
            "UserGate": {
                "page_general_settings": "Настройки",
                "page_device_management": "Управление устройством",
                "page_administrators": "Администраторы",
                "page_certificates": "Сертификаты"
            },
            "Сеть": {
                "page_zones": "Зоны",
                "page_interfaces": "Интерфейсы",
                "page_gateways": "Шлюзы",
                "page_dhcp": "DHCP",
                "page_dns": "DNS",
                "page_virtual_routers": "Виртуальные маршрутизаторы",
                "page_wccp_rules": "WCCP"
            },
            "Пользователи и устройства": {
                "page_groups": "Группы",
                "page_users": "Пользователи",
                "page_auth_servers": "Серверы аутентификации",
                "page_auth_profiles": "Профили аутентификации",
                "page_captive_portal": "Captive-портал",
                "page_captive_profiles": "Captive-профили",
                "page_terminal_servers": "Терминальные серверы",
                "page_2fa_profiles": "Профили MFA",
                "page_byod_policies": "Политики BYOD",
                "page_byod_devices": "Устройства BYOD"
            },
            "Политики сети": {
                "page_firewall": "Межсетевой экран",
                "page_nat_routing": "NAT и маршрутизация",
                "page_load_balancing": "Балансировка нагрузки",
                "page_traffic_shaping": "Пропускная способность"
            },
            "Политики безопасности": {
                "page_content_filtering": "Фильтрация контента",
                "page_safe_browsing": "Веб-безопасность",
                "page_decryption": "Инспектирование SSL",
                "page_ssh_decryption": "Инспектирование SSH",
                "page_intrusion_prevention": "СОВ",
                "page_scada_rules": "Правила АСУ ТП",
                "page_scenarios": "Сценарии",
                "page_mailsecurity": "Защита почтового трафика",
                "page_icap_rules": "ICAP-правила",
                "page_icap_profiles": "ICAP-серверы",
                "page_dos_rules": "Правила защиты DoS",
                "page_dos_profiles": "Профили DoS"
            },
            "Глобальный портал": {
                "page_proxyportal_bookmarks": "Веб-портал",
                "page_reverseproxy_rules": "Правила reverse-прокси",
                "page_reverseproxy_profiles": "Серверы reverse-прокси"
            },
            "VPN": {
                "page_vpn_server_rules": "Серверные правила",
                "page_vpn_client_rules": "Клиентские правила",
                "page_vpn_tunnels": "Сети VPN",
                "page_vpn_server_profiles": "Профили безопасности VPN"
            },
            "Библиотеки": {
                "page_morphology": "Морфология",
                "page_services": "Сервисы",
                "page_ip_addresses": "IP-адреса",
                "page_useragents": "Useragent браузеров",
                "page_content_types": "Типы контента",
                "page_url_lists": "Списки URL",
                "page_time_sets": "Календари",
                "page_bandwidth_pools": "Полосы пропускания",
                "page_scada_profiles": "Профили АСУ ТП",
                "page_response_pages": "Шаблоны страниц",
                "page_url_categories": "Категории URL",
                "page_override_domains": "Изменённые категории URL",
                "page_applications": "Приложения",
                "page_emails": "Почтовые адреса",
                "page_phones": "Номера телефонов",
                "page_ips_profiles": "Профили СОВ",
                "page_notification_profiles": "Профили оповещений",
                "page_netflow_profiles": "Профили netflow",
                "page_ssl_profiles": "Профили SSL"
            }
        }

        perm_webui = {val[0]: val[1] for val in self.profile["webui_permissions"]}
        items = []
        adminconsole = QTreeWidgetItem(["Консоль администратора", permissions[perm_webui["screen_adminconsole"]][0]])
        adminconsole.setForeground(0, permissions[perm_webui["screen_adminconsole"]][1])
        adminconsole.setForeground(1, permissions[perm_webui["screen_adminconsole"]][1])
        for key, val_dict in dict_webui.items():
            item = QTreeWidgetItem([key])
            for page, name in val_dict.items():
                child = QTreeWidgetItem([name, permissions[perm_webui[page]][0]])
                child.setForeground(0, permissions[perm_webui[page]][1])
                child.setForeground(1, permissions[perm_webui[page]][1])
                item.addChild(child)
            items.append(item)
        adminconsole.addChildren(items)
        self.tab_web.insertTopLevelItem(0, adminconsole)
        for page, name in top_level_items.items():
            item = QTreeWidgetItem([name, permissions[perm_webui[page]][0]])
            item.setForeground(0, permissions[perm_webui[page]][1])
            item.setForeground(1, permissions[perm_webui[page]][1])
            self.tab_web.addTopLevelItem(item)
        self.tab_web.expandAll()

    def _create_tab_cli(self):
        """
        Создаём дерево для вкладки "Разрешения для CLI".
        """
        self.tab_cli = QTreeWidget()
        self.tab_cli.setHeaderLabels(["Объекты", "Разрешения"])
        self.tab_cli.setSortingEnabled(True)
        self.tab_cli.sortItems(0, Qt.SortOrder.AscendingOrder)
        self.tab_cli.setColumnWidth(0, 320)
        items = []
        permissions = {
            "none": ("Нет доступа", QBrush(Qt.GlobalColor.red)),
            "read": ("Чтение", QBrush(Qt.GlobalColor.blue)),
            "readwrite": ("Чтение/запись", QBrush(Qt.GlobalColor.darkGreen))
        }
        name = {
            "login": "Доступ к CLI",
        }
        for val in self.profile["cli_permissions"]:
            item = QTreeWidgetItem([name[val[0]], permissions[val[1]][0]])
            item.setForeground(0, permissions[val[1]][1])
            item.setForeground(1, permissions[val[1]][1])
            items.append(item)
        self.tab_cli.insertTopLevelItems(0, items)

    def _create_tab_api(self):
        """
        Создаём дерево для вкладки "Разрешения для API".
        """
        self.tab_api = QTreeWidget()
        self.tab_api.setHeaderLabels(["Объекты", "Разрешения"])
        self.tab_api.setSortingEnabled(True)
        self.tab_api.sortItems(0, Qt.SortOrder.AscendingOrder)
        self.tab_api.setColumnWidth(0, 320)
        items = []
        permissions = {
            "none": ("Нет доступа", QBrush(Qt.GlobalColor.red)),
            "read": ("Чтение", QBrush(Qt.GlobalColor.blue)),
            "readwrite": ("Чтение/запись", QBrush(Qt.GlobalColor.darkGreen))
        }
        for val in self.profile["xmlrpc_permissions"]:
            item = QTreeWidgetItem([val[0], permissions[val[1]][0]])
            item.setForeground(0, permissions[val[1]][1])
            item.setForeground(1, permissions[val[1]][1])
            items.append(item)
        self.tab_api.insertTopLevelItems(0, items)

    def _create_tab_general(self):
        """
        Создаём форму для вкладки Общие.
        """
        self.tab_general = QWidget()
        form = QFormLayout()
        form.addRow("Название:", QLineEdit(self.profile["name"]))
        form.addRow("Описание:", QTextEdit(self.profile["description"]))
        form.setHorizontalSpacing(20)
        
        self.tab_general.setLayout(form)
        
    def __call__(self):
        self.exec()


class ProxyExceptions(QDialog):
    """
    Диалоговое окно "Настройки"-->"Настройки кэширования HTTP"-->"Исключения кэширования".
    """
    def __init__(self, parent):
        super().__init__()
        parent = parent.parent()
        base_path = parent.base_path
        self.setParent(parent, Qt.WindowType.Dialog)
        self.path = f"{base_path}/UserGate/GeneralSettings/config_proxy_exceptions.json"
        self.setWindowTitle("Исключения из HTTP кеширования")

        box = QGroupBox("Исключения кеширования")
        box_layout = QVBoxLayout()
        try:
            with open(self.path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")
        else:
            list_exceptions = QListWidget()
            for item in data:
                list_exceptions.addItem(item["value"])
            box_layout.addWidget(list_exceptions)
        box.setLayout(box_layout)

        buttonOK = QPushButton("Закрыть")
        buttonOK.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(box)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def __call__(self):
        self.exec()


class ProxyPortal(QDialog):
    """
    Диалоговое окно настроек веб-портала: "Настройки"-->"Веб-портал".
    """
    def __init__(self, parent):
        super().__init__()
        parent = parent.parent()
        base_path = parent.base_path
        self.setParent(parent, Qt.WindowType.Dialog)
        self.path = f"{base_path}/UserGate/GeneralSettings/config_proxy_portal.json"
        self.setWindowTitle("Веб-портал")

        box1 = QGroupBox("Настройки")
        box1_layout = QFormLayout()
        box1_layout.setHorizontalSpacing(20)
        box2 = QGroupBox("Настройка HTTPS")
        box2_layout = QFormLayout()
        box2_layout.setHorizontalSpacing(20)
        try:
            with open(self.path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            cs.message_alert(self, err, f"Не найден файл:\n{self.path}")
        else:
            portal_enabled = QCheckBox(self)
            if data['enabled']:
                portal_enabled.setCheckState(Qt.CheckState.Checked)
            box1_layout.addRow("Включено:", portal_enabled)
            box1_layout.addRow("Имя хоста:", LineEdit(data['host']))
            box1_layout.addRow("Порт:", LineEdit(str(data['port'])))
            box1_layout.addRow("Профиль аутентификации:", LineEdit(data['user_auth_profile_id']))
            box1_layout.addRow("Шаблон станицы\nаутентификации:", LineEdit(data['proxy_portal_login_template_id']))
            box1_layout.addRow("Шаблон портала:", LineEdit(data['proxy_portal_template_id']))
            domain_selector = QCheckBox(self)
            if data['enable_ldap_domain_selector']:
                domain_selector.setCheckState(Qt.CheckState.Checked)
            box1_layout.addRow("Предлагать выбор домена AD/LDAP\nна странице аутентификации:", domain_selector)
            use_captcha = QCheckBox(self)
            if data['use_captcha']:
                use_captcha.setCheckState(Qt.CheckState.Checked)
            box1_layout.addRow("Показывать CAPTCHA:", use_captcha)

            box2_layout.addRow("Профиль SSL:", LineEdit(data['ssl_profile_id']))
            box2_layout.addRow("Сертификат:", LineEdit(str(data['certificate_id'])))
            cert_auth = QCheckBox(self)
            if data['cert_auth_enabled']:
                cert_auth.setCheckState(Qt.CheckState.Checked)
            box2_layout.addRow("Аутентификация пользователя\nпо сертификату:", cert_auth)

        box1.setLayout(box1_layout)
        box2.setLayout(box2_layout)

        buttonOK = QPushButton("Закрыть")
        buttonOK.clicked.connect(self.accept)

        layout = QVBoxLayout()
        layout.addWidget(box1)
        layout.addWidget(box2)
        layout.addWidget(buttonOK)
        self.setLayout(layout)

    def __call__(self):
        self.exec()


class EventTracker(QDialog):
    """
    Диалоговое окно настроек учёта изменений: "Настройки"-->"Учёт изменений".
    """
    def __call__(self):
#        self.exec()
        pass

#            row_count = len(data)
#            table = QTableWidget(row_count, 3)
#            table.setHorizontalHeaderLabels(["Имя", "Описание", "Профиль администратора"])
#            for i, item in enumerate(data):
#                profile = item['profile_id'] if item['profile_id'] != -1 else "Корневой профиль"
#                table.setItem(i, 0, QTableWidgetItem(item['login']))
#                table.setItem(i, 1, QTableWidgetItem(item['description']))
#                table.setItem(i, 2, QTableWidgetItem(profile))
#            table.horizontalHeader().setDefaultSectionSize(180)
#            table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
#            table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
#            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
#            table.horizontalHeader().setStretchLastSection(True)
#            table.resizeColumnsToContents()
