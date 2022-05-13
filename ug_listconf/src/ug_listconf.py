#!/usr/bin/python3
#
# Программа формирует текстовый файл с конфигурацией UTM.
# Работаетв версии 5 и 6.
# Файл отчёта создаётся в директории программы.
# 
# Версия 0.7

import stdiomask
from prettytable import PrettyTable
from utm import UtmXmlRpc, UtmError


class UTM(UtmXmlRpc):
    def __init__(self, server_ip, login, password):
        self.zones = {}
        self.notification = {-5: 'Показать ключ на странице captive-портала'}
        self.auth_srv = {}              # Серверы авторизации {id: name}
        self.profile2fa = {}            # 2fa профили         {id: name}
        self.auth_profiles = {}         # Профили авторизации {id: name}
        self.captive_profiles = {}      # Captive-Профили     {id: name}
        self.templates = {}             # Шаблоны страниц {ident: name} ident - id или type если default == True
        self.services = {}              # Список сервисов {id: name}
        self.routes = {}                # Список шлюзов {id: name}
        self.list_morph_groups = {}     # Список списков морфологии {id: name}
        self.list_ip_addresses = {}     # Списки IP адресов {id: name}
        self.list_useragent = {}        # Списки Useragent браузеров {id: name}
        self.list_mime_groups = {}      # Списки mime групп типов контента {id: name}
        self.list_url = {}              # Списки URL {id: name}
        self.list_calendar = {}         # Список календарей {id: name}
        self.list_shapers = {}          # Список полос пропускания {id: name}
        self.list_scada_profiles = {}   # Список профилей АСУ ТП {id: name}
        self.list_urlcategorygroup = {} # Список групп URL сатегорий {id: name}
        self.list_app_categories = {}   # Список категорий приложений {id: name}
        self.list_emailgroup = {}       # Список Групп почтовых адресов {id: name}
        self.list_ssl_profiles = {}     # Список профилей SSL {id: name}
        self.list_icap_servers = {}     # Список серверов ICAP {id: name}
        self.list_icap_balancers = {}   # Список балансировщиков ICAP {id: name}
        self.list_dos_profiles = {}     # Список профилей DoS {id: name}
        self.list_reverseproxy_servers = {} # Список серверов reverse-proxy {id: name}
        self.zone_services = {
            1: 'Ping',
            2: 'SNMP',
            3: '3',
            4: 'Captive-портал и страница блокировки',
            5: 'XML-RPC для управления',
            6: 'Кластер',
            7: 'VRRP',
            8: 'Консоль администрирования',
            9: 'DNS',
            10: 'HTTP(S)-прокси',
            11: 'Агент авторизации',
            12: 'SMTP(S)-прокси',
            13: 'POP(S)-прокси',
            14: 'CLI по SSH',
            15: 'VPN',
            16: '16',
            17: 'SCADA',
            18: 'Reverse-прокси',
            19: 'Веб-портал',
            20: '20',
            21: '21',
            22: 'SAML сервер',
            23: 'Log Analyzer',
            24: 'OSPF',
            25: 'BGP',
            26: 'SNMP-прокси',
            27: 'SSH-прокси',
            28: 'Multicast',
            29: 'NTP сервис',
            30: 'RIP'
        }
        self.threat_level = {       # Уровень угрозы
            1: "Очень низкий",
            2: "Низкий",
            3: "Средний",
            4: "Высокий",
            5: "Очень высокий",
            -1: "",
        }
        self.ug_list_url = {
            'BAD_SEARCH_BLACK_LIST': 'Список поисковых систем без безопасного поиска',
            'ENTENSYS_BLACK_LIST': 'Список запрещённых URL Министерства Юстиции РФ',
            'ENTENSYS_KAZ_BLACK_LIST': 'Список запрещённых URL Республики Казахстан',
            'ENTENSYS_WHITE_LIST': 'Список образовательных учреждений',
            'FISHING_BLACK_LIST': 'Список фишинговых сайтов',
            'ZAPRET_INFO_BLACK_LIST': 'Реестр запрещённых сайтов Роскомнадзора (URL)',
            'ZAPRET_INFO_BLACK_LIST_DOMAIN': 'Реестр запрещённых сайтов Роскомнадзора (домены)',
        }
        super().__init__(server_ip, login, password)
        self._connect()
        self._init_struct()
        self._init_categories()

    def export_ntp(self):
        """Выгрузить список серверов NTP"""
        data = self.get_ntp_config()
        if data:
            return f"\tИспользовать NTP: {data['ntp_enabled']}\n\tСерверы NTP:      {data['ntp_servers']}\n"
        else:
            return "\tНастройки NTP недоступны.\n"

    def export_groups(self):
        """Выгрузить список локальных групп и список пользователей в каждой группе"""
        array = []
        empty_row = ['', '', '', '']
        data = self.get_groups_list()

        x = PrettyTable()
        x.field_names = ['Группа', 'Пользователи', 'Описание', 'Гостевые пользователи']
        if data['total']:
            for group in data['items']:
                x.add_row(empty_row)
                users = ''
                users_in_group = self.get_users_in_group(group['guid'])
                users = "\n".join(y for y in users_in_group) if users_in_group else "---"
                descr = group['description'] if group['description'] else '---'
                row = [group['name'], users, descr, group['is_transient']]
                x.add_row(row)
                x.align = "l"
            array.append(x.get_string())
            array.append("\n")
        else:
            array.append("Локальные группы отсутствуют.\n")
        return data['total'], array

    def export_users(self):
        """Выгрузить список локальных пользвателей"""
        array = []
        empty_row = ['', '', '', '', '', '', '']
        data = self.get_local_users()

        x = PrettyTable()
        x.field_names = ['Имя', 'Логин', 'Статус', 'Группы', 'Статика', 'Эл.почта', 'Телефон']
        if data:
            for item in data:
                x.add_row(empty_row)
                row = [item['name'], item['auth_login'], item['enabled'],
                    "\n".join(y for y in item['groups']) if item['groups'] else " ",
                    "\n".join(f"{y}" for y in item['static_ip_addresses']) if item['static_ip_addresses'] else " ",
                    "\n".join(y for y in item['emails']) if item['emails'] else " ",
                    "\n".join(y for y in item['phones']) if item['phones'] else " ",
                ]
                x.add_row(row)
                x.align = "l"
            array.append(x.get_string())
            array.append("\n")
        else:
            array.append("Локальные пользователи отсутствуют.\n")
        return len(data), array

    def export_auth_options(self):
        """Выгрузить глобальные опции аутентификации"""
        array = []
        data = self.get_admin_options()
        array.append(f"\tСложный пароль: {data['strong_pwd']}\n")
        array.append(f"\tЧисло неверных попыток аутентификации: {data['n_of_invalid_auth']}\n")
        array.append(f"\tВремя блокировки: {data['block_time']}\n")
        if data['strong_pwd']:
            array.append(f"\tМинимальная длина пароля: {data['min_length']}\n")
            array.append(f"\tМинимальное число символов в верхнем регистре: {data['min_uppercase']}\n")
            array.append(f"\tМинимальное число символов в нижнем регистре: {data['min_lowercase']}\n")
            array.append(f"\tМинимальное число цифр: {data['min_digit']}\n")
            array.append(f"\tМинимальное число специальных символов: {data['min_special']}\n")
            array.append(f"\tМаксимальная длина блока из одного и того же символа: {data['max_char_repetition']}\n")
        return 0, array
        
    def export_admins(self):
        """Выгрузить список администраторов"""
        array = []
        profile = {}
        data = self.get_admin_profiles()
        for item in data:
            profile[item['id']] = item['name']
        data = self.get_admins_list()
        x = PrettyTable()
        header = ['Логин', 'Профиль', 'Описание', 'Статус', 'Тип']
        if self.version.startswith('6'):
            header.append('Админ МС')
        x.field_names = header
        for item in data:
            if item['profile_id'] == -1:
                prof = "Корневой профиль"
            else:
                prof = profile[item['profile_id']]
            row = [item['login'], prof, item['description'], item['enabled'], item['type']]
            if self.version.startswith('6'):
                row.append(item['cc'])
            x.add_row(row)
            x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array

######## Библиотеки #################################
    def export_morphology_list(self):
        """Выгрузить списки морфологии"""
        array = []
        empty_row = ['', '', '', '', '', '']
        group_name = {
            'MORPH_CAT_BADWORDS': 'Нецензурная лекика',
            'MORPH_CAT_DRUGSWORDS': 'Наркотики',
            'MORPH_CAT_PORNOWORDS': 'Порнография',
            'MORPH_CAT_SUICIDEWORDS': 'Суицид',
            'MORPH_CAT_TERRORWORDS': 'Терроризм',
            'MORPH_CAT_MINJUSTWORDS': 'Соответствие списку запрещённых материалов минюста РФ',
            'MORPH_CAT_GAMBLING': 'Азартные игры',
            'MORPH_CAT_FZ_436': 'Соответствие ФЗ-436 (защита детей)',
            'MORPH_CAT_DLP_LEGAL': 'Юридический (DLP)',
            'MORPH_CAT_DLP_ACCOUNTING': 'Бухгалтерия (DLP)',
            'MORPH_CAT_DLP_FINANCE': 'Финансы (DLP)',
            'MORPH_CAT_DLP_PERSONAL': 'Персональные данные (DLP)',
            'MORPH_CAT_DLP_MARKETING': 'Маркетинг (DLP)',
            'MORPH_CAT_KAZAKHSTAN': 'Соответствие списку запрещённых материалов Республики Казахстан',
        }
        data = self.get_namedlist_list('morphology')
        x = PrettyTable()
        x.field_names = ['Название списка', 'Описание', 'Уровень угрозы', 'Порог', 'URL обновления', 'Слова']

        for item in data['items']:
            self.list_morph_groups[item['id']] = group_name.get(item['name'], item['name'])
            x.add_row(empty_row)

            weight = ''
            threat_level = ''
            if self.version.startswith('6'):
                threat_level = item['attributes']['threat_level']
                weight = item['attributes'].get('threshold', '')
            else:
                for attr in item['attributes']:
                    if attr['name'] == 'weight':
                        weight = str(attr['value'])
                    elif attr['name'] == 'threat_level':
                        threat_level = attr['value']

            x.add_row([
                self.list_morph_groups[item['id']],
                split_descr(item['description']),
                threat_level,
                weight,
                '' if item['url'] == '<hidden>' else item['url'],
                "\n".join(f"'{x['value']}', вес: {x['weight']}" for x in item.get('content', ''))
            ])

        x.align = "l"
        x.align['Уровень угрозы'] = "c"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет списков морфологии."

    def export_services_list(self):
        """Выгрузить список сервисов"""
        array = []
        empty_row = ['', '', '', '', '']
        data = self.get_services_list()

        x = PrettyTable()
        x.field_names = ['Название', 'Описание', 'Протокол', 'Порты назначения', 'Порты источника']
        for item in reversed(data['items']):
            self.services[item['id']] = item['name']
            x.add_row(empty_row)
            proto = []
            dst_ports = []
            src_ports = []
            for i in item['protocols']:
                proto.append(i['proto'])
                dst_ports.append(i['port'])
                src_ports.append(i['source_port'])

            row = [
                item['name'],
                item['description'],
                "\n".join(proto),
                "\n".join(dst_ports),
                "\n".join(src_ports),
            ]
            x.add_row(row)
            x.align = "l"

        array.append(x.get_string())
        array.append("\n")
        return data['total'], array if array else "\tСписок сервисов пуст."

    def export_named_list(self, list_type, list_name):
        """Выгрузить именованные списки"""
        array = []
        empty_row = ['', '', '', '', '', '']
        if list_type == 'url':
            data_dict = self.list_url
        elif list_type == 'network':
            data_dict = self.list_ip_addresses
        elif list_type == 'applicationgroup':
            data_dict = self.list_app_categories

        data = self.get_namedlist_list(list_type)
        x = PrettyTable()
        x.field_names = ['Название списка', list_name, 'Уровень угрозы', 'URL обновления', 'Тип списка', 'Описание']

        for item in data['items']:
            x.add_row(empty_row)
            data_dict[item['id']] = self.ug_list_url.get(item['name'], item['name']) if list_type == 'url' else item['name']
            threat_level = ''
            url = ''
            list_content = ''
            if self.version.startswith('6'):
                threat_level = self.threat_level[item['attributes'].get('threat_level', -1)]
            else:
                for attr in item['attributes']:
                    if attr['name'] == 'threat_level':
                        threat_level = self.threat_level[attr['value']] 
            if item['editable']:
                list_content = "\n".join(self._l7apps[x] if list_type == 'applicationgroup' else x for x in item['contents'])
                url = item['url']
            row = [
                self.ug_list_url.get(item['name'], item['name']) if list_type == 'url' else item['name'],
                list_content,
                threat_level,
                url,
                "Пользовательский" if item['editable'] else "Закрытый список UserGate",
                split_descr(item['description']),
            ]
            x.add_row(row)
            x.align = "l"

        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if array else f"\tНет списков {list_name}."

    def export_useragent_list(self):
        """Выгрузить списки Useragent браузеров"""
        array = []
        empty_row = ['', '', '', '']
        group_name = {
            'USERAGENT_ANDROID': 'Android',
            'USERAGENT_APPLE': 'Apple',
            'USERAGENT_BLACKBERRY': 'BlackBerry',
            'USERAGENT_CHROMEGENERIC': 'Chrome',
            'USERAGENT_CHROMEOS': 'Chrome OS',
            'USERAGENT_CHROMIUM': 'Chromium',
            'USERAGENT_EDGE': 'Edge',
            'USERAGENT_FFGENERIC': 'Firefox',
            'USERAGENT_IE': 'Internet explorer',
            'USERAGENT_IOS': 'IOS',
            'USERAGENT_LINUX': 'Linux',
            'USERAGENT_MACOS': 'MacOS',
            'USERAGENT_MOBILESAFARI': 'Safari mobile',
            'USERAGENT_OPERA': 'Opera',
            'USERAGENT_SAFARIGENERIC': 'Safari',
            'USERAGENT_SPIDER': 'Краулеры',
            'USERAGENT_UCBROWSER': 'UCBrowser',
            'USERAGENT_WIN': 'Windows',
            'USERAGENT_WINPHONE': 'Windows phone',
            'USERAGENT_YABROWSER': 'Яндекс браузер',
        }
        data = self.get_namedlist_list('useragent')
        x = PrettyTable()
        x.field_names = ['Название списка', 'Описание', 'URL обновления', 'Шаблоны useragent']

        for item in data['items']:
            self.list_useragent[item['id']] = group_name.get(item['name'], item['name'])
            x.add_row(empty_row)

            x.add_row([
                self.list_useragent[item['id']],
                split_descr(item['description']),
                item['url'],
                "\n".join(x for x in item.get('contents', ''))
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет списков Useragent браузеров."

    def export_mime_list(self):
        """Выгрузить список Типов контента"""
        array = []
        empty_row = ['', '', '']
        group_name = {
            'MIME_CAT_VIDEO': 'Видео',
            'MIME_CAT_SOUNDS': 'Звуки и музыка',
            'MIME_CAT_IMAGES': 'Картинки',
            'MIME_CAT_DOCUMENTS': 'Документы',
            'MIME_CAT_APPLICATIONS': 'Приложения',
            'MIME_CAT_JAVASCRIPT': 'Java-script',
        }
        data = self.get_namedlist_list('mime')
        x = PrettyTable()
        x.field_names = ['Название типа контента', 'Описание', 'Тип контента']

        for item in data['items']:
            self.list_mime_groups[item['id']] = group_name.get(item['name'], item['name'])
            x.add_row(empty_row)

            x.add_row([
                self.list_mime_groups[item['id']],
                split_descr(item['description']),
                "\n".join(x for x in item.get('contents', ''))
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет категорий типов контента."


    def export_time_restricted_list(self):
        """Выгрузить содержимое календарей раздела Библиотеки"""
        array = []
        empty_row1 = ['', '', '', '']
        empty_row2 = ['', '', '', '', '']
        data = self.get_time_restrict_list()

        x = PrettyTable()
        x.field_names = ['Название списка', 'URL обновления', 'Описание', 'Элементы']

        y = PrettyTable()
        y.field_names = ['Название списка', 'Тип', 'Time from', 'Time to', 'Days']

        for item in data['items']:
            x.add_row(empty_row1)
            self.list_calendar[item['id']] = item['name']

            calendars = ''
            for element in item['contents']:
                y.add_row(empty_row2)
                y.add_row([
                    element['name'],
                    element['type'],
                    element.get('time_from', ''),
                    element.get('time_to', ''),
                    element.get('days', ''),
                ])
                calendars += f"{element['name']}\n"

            row = [
                item['name'],
                item['url'],
                split_descr(item['description']),
                calendars,
            ]
            x.add_row(row)

        y.align = "l"
        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        array.append(y.get_string())
        array.append("\n")
        return data['count'], array if array else "\tНет календарей."

    def export_shaper_list(self):
        """Выгрузить список полосы пропускания"""
        array = []
        empty_row = ['', '', '', '']
        data = self.get_shaper_list()
        x = PrettyTable()
        x.field_names = ['Название', 'Описание', 'Скорость (Кбит/сек)', 'DSCP']
        for item in data:
            self.list_shapers[item['id']] = item['name']
            x.add_row(empty_row)
            x.add_row([
                item['name'],
                split_descr(item['description']),
                item['rate'],
                item['dscp'],
            ])
        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if array else "\tНет полос пропускания."

    def export_scada_profiles_list(self):
        """Выгрузить список профилей АСУ ТП"""
        array = []
        empty_row = ['', '', '']
        data = self.get_scada_profiles_list()

        x = PrettyTable()
        x.field_names = ['Название', 'Описание', 'Команда:Адрес АСУ ТП']

        for item in data['items']:
            self.list_scada_profiles[item['id']] = item['name']
            x.add_row(empty_row)
            command = [f"{x['protocol']} : {x['command']} : {x.get('address', '')}" for x in item['units']]

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(x for x in command),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['total'], array if array else "\tНет профилей АСУ ТП."

    def export_templates_list(self):
        """Выгрузить список шаблонов страниц"""
        array = []
        data = self.get_templates_list()
        x = PrettyTable()
        x.field_names = ['Название', 'По умолчанию', 'Тип', 'Базовый шаблон', 'Описание']
        for item in data:
            self.templates[item['id']] = item['name']
            if item['default']:
                self.templates[item['type']] = item['name']
            x.add_row([
                item['name'],
                item['default'],
                item['type'],
                item['default_template_name'],
                split_descr(item['description']),
            ])
        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if array else "\tНет шаблонов страниц."

    def export_urlcategory_group_list(self):
        """Выгрузить список групп Категорий URL"""
        array = []
        empty_row = ['', '', '']
        group_name = {
            'URL_CATEGORY_GROUP_PARENTAL_CONTROL': 'Parental Control',
            'URL_CATEGORY_GROUP_PRODUCTIVITY': 'Productivity',
            'URL_CATEGORY_GROUP_SAFE': 'Safe catecories',
            'URL_CATEGORY_GROUP_THREATS': 'Threats',
            'URL_CATEGORY_MORPHO_RECOMMENDED': 'Recommended for morphology checking',
            'URL_CATEGORY_VIRUSCHECK_RECOMMENDED': 'Recommended for virus check',
        }
        data = self.get_namedlist_list('urlcategorygroup')
        x = PrettyTable()
        x.field_names = ['Группы URL категорий', 'Описание', 'Категории']

        for item in data['items']:
            if self.version.startswith('6'):
                self.list_urlcategorygroup[item['id']] = group_name.get(item['name'], item['name'])
            else:
                self.list_urlcategorygroup[item['id']] = item['name']
            x.add_row(empty_row)

            urlcategorygroup = []
            for category in item['content']:
                if self.version.startswith('6'):
                    urlcategorygroup.append(category['name'])
                else:
                    urlcategorygroup.append(self._categories[int(category['value'])])

            x.add_row([
                self.list_urlcategorygroup[item['id']],
                split_descr(item['description']),
                ''.join([f"'{word}',\n" if (i+1)%8 == 0 else f"'{word}', " for i, word in enumerate(urlcategorygroup)]),
            ])
        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет групп URL категорий."

    def export_emailgroup_list(self):
        """Выгрузить списки Почтовых адресов"""
        array = []
        empty_row = ['', '', '', '']
        data = self.get_namedlist_list('emailgroup')

        x = PrettyTable()
        x.field_names = ['Название списка', 'Описание', 'URL обновления', 'Почтовые адреса']

        for item in data['items']:
            self.list_emailgroup[item['id']] = item['name']
            x.add_row(empty_row)
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['url'],
                "\n".join(x for x in item.get('contents', ''))
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет списков Почтовых адресов."

    def export_notification_profiles(self):
        """Выгрузить список профилей оповещений"""
        array = []
        data = self.get_notification_profiles_list()
        for item in data:
            self.notification[item['id']] = item['name']
            array.append(f"\nНазвание: '{item['name']}'\nОписание: '{item['description']}'\n")
            x = PrettyTable()
            if item['type'] == 'smtp':
                x.field_names = [
                    'Тип', 'Хост', 'Безопасность', 'Авторизация', 'Логин',
                ]
                x.add_row([
                    item['type'],
                    f"{item['host']}:{item['port']}",
                    item['security'],
                    item['authentication'],
                    item['login'],
                ])
            elif item['type'] == 'smpp':
                x.field_names = [
                    'Тип', 'Хост', 'SSL', 'Логин', 'Трансляция номеров',
                    'TON источника', 'TON назначения', 'NPI источника', 'NPI назначения'
                ]
                x.add_row([
                    item['type'],
                    f"{item['host']}:{item['port']}",
                    item['ssl'],
                    item['login'],
                    item['translation_rules'] if item['type'] == 'smpp' else '',
                    item['source_addr_ton'] if item['type'] == 'smpp' else '',
                    item['dest_addr_ton'] if item['type'] == 'smpp' else '',
                    item['source_addr_npi'] if item['type'] == 'smpp' else '',
                    item['dest_addr_npi'] if item['type'] == 'smpp' else '',
                ])
            array.append(x.get_string())
            array.append("\n")
        return len(data), array if array else "\tНет профилей оповещения."

    def export_ssl_profiles(self):
        """Выгрузить список профилей SSL"""
        if self.version.startswith('6'):
            array = []
            empty_row = ['', '', '', '']
            data = self.get_ssl_profiles_list()

            x = PrettyTable()
            x.field_names = ['Название', 'Описание', 'Протоколы SSL', 'Наборы алгоритмов шифрования']

            for item in data['items']:
                self.list_ssl_profiles[item['id']] = item['name']
                
                x.add_row(empty_row)
                x.add_row([
                        split_name(item['name']),
                        split_descr(item['description']),
                        f"Минимальная версия TLS:  {item['ssl_min_proto']}\nМаксимальная версия TLS: {item['ssl_max_proto']}",
                        "\n".join(x for x in item['ssl_ciphers']),
                    ])

            x.align = "l"
            array.append(x.get_string())
            array.append("\n")

            return data['count'], array if array else "\tНет профилей SSL."
        else:
            return 0, "\tВ версии 5 в библиотеке нет профилей SSL."

######## Сеть #################################
    def export_zones(self):
        """Выгрузить список зон"""
        array = []
        total, data = self.get_zones_list()

        empty_row = ['', '', '', '', '', '', '', '']
        y = PrettyTable()
        y.field_names = [
            'Зона', 'Описание', 'Защита от DoS: SYN', 'Защита от DoS: UDP', 'Защита от DoS: ICMP', 'Исключения DoS',
            'Контроль доступа', 'Защита от IP-спуфинга',
        ]
        for item in data:
            self.zones[item['id']] = item['name']
            y.add_row(empty_row)
            dos_syn = []
            dos_udp = []
            dos_icmp = []
            excluded_ips = {}
            services = {}
            antispoof = []
            for dos in item['dos_profiles']:
                if dos['kind'] == 'syn':
                    dos_syn = [
                        "Включено:                   ДА" if dos['enabled'] else "Включено:                   НЕТ",
                        "Агрегировать:               Да" if dos['aggregate'] else "Агрегировать:               Нет",
                        f"Порог уведомления:          {dos['alert_threshold']}",
                        f"Порог отбрасывания пакетов: {dos['drop_threshold']}",
                    ]
                    if dos['excluded_ips']:
                        for ei in dos['excluded_ips']:
                            excluded_ips[ei] = excluded_ips.get(ei, '') + 'SYN '
                elif dos['kind'] == 'udp':
                    dos_udp = [
                        "Включено:                   ДА" if dos['enabled'] else "Включено:                   НЕТ",
                        "Агрегировать:               Да" if dos['aggregate'] else "Агрегировать:               Нет",
                        f"Порог уведомления:          {dos['alert_threshold']}",
                        f"Порог отбрасывания пакетов: {dos['drop_threshold']}",
                    ]
                    if dos['excluded_ips']:
                        for ei in dos['excluded_ips']:
                            excluded_ips[ei] = excluded_ips.get(ei, '') + 'UDP '
                elif dos['kind'] == 'icmp':
                    dos_icmp = [
                        "Включено:                   ДА" if dos['enabled'] else "Включено:                   НЕТ",
                        "Агрегировать:               Да" if dos['aggregate'] else "Агрегировать:               Нет",
                        f"Порог уведомления:          {dos['alert_threshold']}",
                        f"Порог отбрасывания пакетов: {dos['drop_threshold']}",
                    ]
                    if dos['excluded_ips']:
                        for ei in dos['excluded_ips']:
                            excluded_ips[ei] = excluded_ips.get(ei, '') + 'ICMP '

            for service in item['services_access']:
                if service['enabled']:
                    services[self.zone_services[service['service_id']]] = "\n".join(f"        {a}" for a in service['allowed_ips'])

            if item['enable_antispoof']:
                antispoof = [
                    "Включено: ДА" if item['enable_antispoof'] else "Включено: НЕТ",
                    "Диапазоны IP-адресов:",
                    "\n".join(x for x in item['networks']),
                ]

            y.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(x for x in dos_syn),
                "\n".join(x for x in dos_udp),
                "\n".join(x for x in dos_icmp),
                "\n".join(f"{k} - {v}" for k, v in excluded_ips.items()),
                "\n".join(f"{k}\n{v}" if v else k for k, v in services.items()),
                "\n".join(x for x in antispoof),
            ])

        y.align = "l"
        array.append(y.get_string())
        array.append("\n")

        return total, array

    def export_interfaces(self):
        """Выгрузить сисок интерфейсов"""
        xmit = {0: 'Layer 2', 1: 'Layer 3+4', 2: 'Layer 2+3'}
        failover_mac = {0: 'Отключено', 1: 'Active', 2: 'Follow'}
        bond_mode = {
            0: 'Round robin',
            1: 'Active backup',
            2: 'XOR',
            3: 'Broadcast',
            4: 'IEE 802.3ad',
            5: 'Adaptive transmit load balancing',
            6: 'Adaptive load balancing',
        }
        array = []
        data = self.get_interfaces_list()
        for item in data:
            separator = "- "*(37 - len(item['name']))
            array.append(f"\nИнтерфейс: '{item['name']}'      {separator}\nОписание: '{item['description']}'\n")
            x = PrettyTable()
            header = ['Тип', 'Включён', 'Режим', 'IP интерфейса', 'Зона', 'MTU', 'Скорость']
            row = [item['kind'],
                   item['enabled'],
                   item['mode'],
                   item['ipv4'],
                   self.zones[item['zone_id']] if item['zone_id'] else '',
                   item['mtu'],
                   item['speed'],
            ]
            if item['netflow_profile']:
                header.insert(7, 'Профиль netflow')
                row.insert(7, item['netflow_profile'])
            if item['kind'] == 'tunnel':
                header.insert(7, 'Тоннель')
                header.insert(8, 'VXLAN ID')
                header.insert(9, 'Локальный IP')
                header.insert(10, 'Удалённый IP')
                row.insert(7, item['tunnel']['mode'])
                row.insert(8, item['tunnel']['vni'])
                row.insert(9, item['tunnel']['local_ipv4'])
                row.insert(10, item['tunnel']['remote_ipv4'])

            if item['kind'] not in ('vpn', 'ppp', 'tunnel'):
                header.insert(4, 'MAC-адрес')
                header.insert(8, 'Тип интерф.')
                row.insert(4, item['mac'])
                row.insert(8, 'mirror' if item['tap'] else 'layer 3')
                if item['master']:
                    header.insert(5, 'Используется в')
                    row.insert(5, item['master'])

                if item['kind'] == 'bond':
                    header.insert(6, 'Интерфейсы')
                    row.insert(6, item['bonding']['slaves'])
                elif item['kind'] == 'bridge':
                    header.insert(6, 'Интерфейсы')
                    row.insert(6, item['bridging']['ports'])
                elif item['kind'] == 'vlan':
                    header.insert(1, 'vlan id')
                    header.insert(2, 'link')
                    row.insert(1, item['vlan_id'])
                    row.insert(2, item['link'])

                if item['dhcp_relay'] and item['dhcp_relay']['servers']:
                    header.insert(8, 'DHCP-релей')
                    header.insert(9, 'DHCP enabled')
                    row.insert(8, item['dhcp_relay']['servers'])
                    row.insert(9, item['dhcp_relay']['enabled'])

            x.field_names = header
            x.add_row(row)
            array.append(x.get_string())
            array.append("\n")
            
            if item['kind'] == 'bond':
                x = PrettyTable()
                array.append(f"Дополнительно:\n")
                x.field_names = ['Режим', 'MII (мсек)', 'Down delay (мсек)', 'Up delay (мсек)', 'LACP rate', 'Failover MAC', 'Xmit hash policy']
                x.add_row([
                    bond_mode[item['bonding']['mode']],
                    item['bonding']['miimon'],
                    item['bonding']['downdelay'],
                    item['bonding']['updelay'],
                    'Fast' if item['bonding']['lacp_rate'] else 'Slow',
                    failover_mac[item['bonding']['fail_over_mac']],
                    xmit[item['bonding']['xmit_hash_policy']]
                ])
                array.append(x.get_string())
                array.append("\n")

            if item['kind'] == 'bridge':
                x = PrettyTable()
                array.append(f"Дополнительно:\n")
                x.field_names = ['Тип', 'STP', 'Forward delay', 'Maximum age', 'Байпас']
                x.add_row([
                    'Layer 2' if item['bridging']['bridge_type'] == 'l2' else 'Layer 3',
                    'Включено' if item['bridging']['stp_state'] else 'Отключено',
                    item['bridging']['forward_delay'],
                    item['bridging']['max_age'],
                    item['bridging']['bypass_slot'] if item['bridging']['bypass_slot'] else 'Нет',
                ])
                array.append(x.get_string())
                array.append("\n")
        return len(data), array

    def export_gateways(self):
        """Выгрузить список шлюзов"""
        array = []
        total = 0
        data = self.get_gateways_list()
        empty_row = ['', '', '', '', '', '', '', '', '', '']
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Интерфейс', 'Включён', 'IP шлюза', 'MAC', 'Вес',
            'Балансировка', 'По умолчанию', 'Вирт.маршрутизатор'
        ]

        if data:
            total = len(data)
            for item in data:
                x.add_row(empty_row)
                route_name = item['name'] if 'name' in item.keys() else f"{item['ipv4']}(read only)"
                self.routes[str(item['id'])] = route_name

                if 'description' in item.keys():
                    aaa = item['description'].split()
                    descr = ''.join([f'{word}\n' if (i+1)%3 == 0 else f'{word} ' for i, word in enumerate(aaa)])
                else:
                    descr = "Read only"

                row = [
                    route_name,
                    descr,
                    item['iface'],
                    item['enabled'],
                    item['ipv4'],
                    item['mac'],
                    item['weight'],
                    item['multigate'],
                    item['default'],
                    item['vrf'] if self.version.startswith('6') else ''
                ]
                x.add_row(row)

            array.append(x.get_string())
        else:
            array.append("\tНастройки шлюзов недоступны.")

        array.append("\n")
        empty_row = ['', '', '', '', '']
        data = self.get_gateway_failover()
        x = PrettyTable()
        x.field_names = ['Название', 'Включено', 'Частота проверки', 'Процент неудачных запросов', 'IP-адреса']
        x.add_row([
            'Свойства проверки сети',
            data['enabled'],
            data['period'],
            data['percent'],
            "\n".join(y for y in data['hosts']), # if data['hosts'] else " ",
        ])
        array.append(x.get_string())
        array.append("\n")

        return total, array

    def export_dhcp_subnets(self):
        """Выгрузить список шлюзов"""
        array = []
        data = self.get_dhcp_list()
        if data:
            for item in data:
                x = PrettyTable()
                array.append(f"\nНазвание: '{item['name']}'\nОписание: '{item['description']}'\nИнтерфейс: {item['iface_id']}\n")
                x.field_names = ['Включёно', 'Диапазон IP', 'Маска', 'Время аренды', 'Домен', 'Шлюз', 'Серверы DNS']
                x.add_row([
                    item['enabled'],
                    f"{item['start_ip']}-{item['end_ip']}",
                    item['netmask'],
                    item['lease_time'],
                    item['domain'],
                    item['gateway'],
                    item['nameservers']
                ])
                array.append(x.get_string())
                array.append("\n")
                
                if item['hosts']:
                    x = PrettyTable()
                    array.append(f"Зарезервированные адреса:\n")
                    x.field_names = ['MAC', 'IP-адрес', 'Hostname']
                    for host in item['hosts']:
                        x.add_row([
                            host['mac'],
                            host['ipv4'],
                            host['hostname']
                        ])
                    array.append(x.get_string())
                    array.append("\n")
                
                if item['ignored_macs']:
                    array.append(f"Игнорируемые MAC: {item['ignored_macs']}\n")
                
                if item['boot_server_ip']:
                    array.append(f"Адрес сервера PXE: {item['boot_server_ip']}\n")
                    array.append(f"Название файла для загрузки с PXE-сервера: {item['boot_filename']}\n")
                
                if item['options']:
                    array.append(f"DHCP опции: {item['options']}\n")
            return len(data), array
        else:
            return 0, "\tDHCP не настроено."

    def export_dns(self):
        """Выгрузить настройки DNS"""
        array = []
        params = {
            'use_cache_enabled': 'Кэширование DNS:',
            'enable_dns_filtering': 'DNS-фильтрация:',
            'recursive_enabled': 'Рекурсивные DNS-запросы:',
            'dns_max_ttl': 'Максимальное время жизни для DNS-записей (сек):',
            'dns_max_queries_per_user': 'Лимит DNS-запросов в секунду на пользователя:',
            'only_a_for_unknown': 'Только А и АААА DNS-записи для неизвестных пользователей:'
        }

        data = self.get_dns_list()
        if data:
            array.append(f"\nСистемные DNS-серверы:\n")
            for item in data:
                array.append(f"\t{item['dns']}\n")

        array.append(f"\nНастройки DNS-прокси:\n")
        data = self.get_params_list(list(params.keys()))
        for key, value in params.items():
            array.append(f"\t{value}: {data[key]}\n")

        total, data = self.get_dns_rules_list()
        if total:
            for item in data:
                array.append(f"\nПравила DNS в DNS-прокси ({total}):\n")
                x = PrettyTable()
                x.field_names = ['Название', 'Описание', 'Включёно', 'Домены', 'Серверы DNS']
                x.add_row([
                    item['name'],
                    item['description'],
                    item['enabled'],
                    item['domains'],
                    item['dns_servers']
                ])
                array.append(x.get_string())
                array.append("\n")

        total, data = self.get_dns_static_list()
        if total:
            for item in data:
                array.append(f"\nСтатические записи DNS в DNS-прокси ({total}):\n")
                x = PrettyTable()
                x.field_names = ['Название', 'Описание', 'Включёно', 'Домен', 'IP-адреса']
                x.add_row([
                    item['name'],
                    item['description'],
                    item['enabled'],
                    item['domain_name'],
                    item['ip_addresses']
                ])
                array.append(x.get_string())
                array.append("\n")
        return 0, array

    def export_wccp(self):
        """Выгрузить настройки WCCP"""
        array = []
        data = self.get_wccp_list()
        if data:
            for item in data:
                x = PrettyTable()
                array.append(f"\nНазвание: '{item['name']}'\nОписание: '{item['description']}'\n")
                x.field_names = [
                    'Включёно', 'Способ перенаправления трафика', 'Способ возврата трафика',
                    'Сервисная группа', 'Приоритет', 'Порты для перенаправления', 'Порт источника', 'Протокол'
                ]
                x.add_row([
                    item['enabled'],
                    item['forwarding_type'],
                    item['returning_type'],
                    item['service_group'],
                    item['priority'],
                    item['ports'],
                    item['ports_source'],
                    item['protocol'],
                ])
                array.append(x.get_string())
                array.append("\n")

                array.append(f"\nРоутеры WCCP:\n")
                for router_list in item['routers']:
                    array.append(f"Название списка: {router_list}")
                array.append(f"\nИнвертировать: {item['routers_negate']}\n")
                    
                array.append(f"\nСпособ назначения: {item['assigment_type']}\n")
                x = PrettyTable()
                if item['assigment_type'] == 'hash':
                    x.field_names = ['Тип', 'IP источника', 'Порт источника', 'IP назначения', 'Порт назначения']
                    x.add_row([
                        'Хэш',
                        item['primary_source_ip'],
                        item['primary_source_port'],
                        item['primary_dest_ip'],
                        item['primary_dest_port'],
                    ])
                    x.add_row([
                        'Альтернативный хэш',
                        item['alternate_source_ip'],
                        item['alternate_source_port'],
                        item['alternate_dest_ip'],
                        item['alternate_dest_port'],
                    ])
                else:
                    x.field_names = ['Схема маскирования', 'Значение маски']
                    scheme = ''
                    if item['mask_source_ip']:
                        scheme = 'IP источника'
                    elif item['mask_source_port']:
                        scheme = 'Порт источника'
                    elif item['mask_dest_ip']:
                        scheme = 'IP назначения'
                    elif item['mask_dest_port']:
                        scheme = 'Порт назначения'
                    x.add_row([scheme, hex(item['mask_value'])[2:].upper()])

                array.append(x.get_string())
                array.append("\n")
            return 0, array
        else:
            return 0, "\tWCCP не настроено.\n"

    def export_routers(self):
        """Выгрузить настройки маршрутов"""
        array = []
        data = self.get_routers_list()
        if data:
            if self.version.startswith('6'):
                for item in data:
                    separator = "- "*(37 - len(item['name']))
                    array.append(f"\nНазвание виртуального маршрутизатора: '{item['name']}'     {separator}\nОписание: '{item['description']}'\nИнтерфейсы: {item['interfaces']}\n")
                    if item['routes']:
                        array.append("\nСтатические маршруты\n")
                        x = PrettyTable()
                        x.field_names = [
                            'Название', 'Описание', 'Включёно', 'Тип',
                            'Адрес назначения', 'Шлюз', 'Интерфейс', 'Метрика',
                        ]
                        for rout in item['routes']:
                            x.add_row([
                                rout['name'],
                                rout['description'],
                                rout['enabled'],
                                rout['kind'],
                                rout['dest'],
                                rout['gateway'],
                                rout['ifname'] if rout['ifname'] != 'undefined' else "Автоматически",
                                rout['metric'],
                            ])
                            array.append(x.get_string())
                            array.append("\n")

                    #######################################################
                    if item['ospf']['interfaces'] and item['ospf']['areas']:
                        array.append("\nOSPF\n")
                        x = PrettyTable()
                        x.field_names = [
                            'Включено', 'Идентификатор роутера', 'Redistribute', 'Метрика', 'Default Originate',
                        ]
                        x.add_row([
                            item['ospf']['enabled'],
                            item['ospf']['router_id'],
                            item['ospf']['redistribute'],
                            item['ospf']['metric'],
                            item['ospf']['default_originate'],
                        ])
                        array.append(x.get_string())
                        array.append("\n")
                    
                        array.append("Интерфейсы:\n")
                        for iface in item['ospf']['interfaces']:
                            x = PrettyTable()
                            x.field_names = [
                                'Интерфейс', 'Включено', 'Описание', 'Стоимость', 'Приоритет', 'Интервал hello',
                                'Интервал dead', 'Интервал повторения', 'Задержка передачи' 
                            ]
                            x.add_row([
                                iface['iface_id'],
                                iface['enabled'],
                                iface['description'],
                                iface['cost'],
                                iface['priority'],
                                iface['hello_interval'],
                                iface['dead_interval'],
                                iface['retransmit_interval'],
                                iface['transmit_delay'],
                            ])
                            array.append(x.get_string())
                            array.append("\n")
                            x = PrettyTable()
                            x.field_names = ['', 'Включено', 'Тип авторизации', 'MD5 key ID', 'Ключ']
                            x.add_row([
                                'Аутентификация',
                                iface['auth_params']['enabled'],
                                iface['auth_params']['auth_type'],
                                iface['auth_params']['md5_id'],
                                iface['auth_params']['auth_key'],
                            ])
                            array.append(x.get_string())
                            array.append("\n")
                        
                        array.append("Области:\n")
                        for area in item['ospf']['areas']:
                            x = PrettyTable()
                            x.field_names = [
                                'Имя области', 'Включено', 'Описание', 'Стоимость', 'Идентификатор области',
                                'Тип авторизации', 'Тип области', 'Не суммировать' 
                            ]
                            x.add_row([
                                area['name'],
                                area['enabled'],
                                area['description'],
                                area['cost'],
                                area['area_id'],
                                area['auth_type'],
                                area['area_type'],
                                area['no_summary'],
                            ])
                            array.append(x.get_string())
                            array.append(f"\nИнтерфейсы области: {area['interfaces']}\nВиртуальные линки: {area['virtual_links']}\n")

                    ############## BGP #############
                    filters = {}
                    routemaps = {}
                    if item['bgp']['router_id']:
                        array.append("\nBGP\n")
                        x = PrettyTable()
                        x.field_names = [
                            'Включено', 'Идентификатор роутера', 'Номер автономной системы (AS)', 'Multiple path', 'Redistribute'
                        ]
                        x.add_row([
                            item['bgp']['enabled'],
                            item['bgp']['router_id'],
                            item['bgp']['as_number'],
                            item['bgp']['multiple_path'],
                            item['bgp']['redistribute'],
                        ])
                        array.append(x.get_string())
                        array.append(f"\nСети: {item['bgp']['networks']}\n")
                        
                        array.append("\nRoutemaps:\n")
                        for rmap in item['bgp']['routemaps']:
                            routemaps[rmap['id']] = {
                                'name': rmap['name'],
                                'action': rmap['action'],
                                'in': False,
                                'out': False,
                            }
                            x = PrettyTable()
                            x.field_names = [
                                'Название', 'Описание', 'Действие', 'Сравнивать по', 'Next hop', 'Вес',
                                'Метрика', 'Предпочтение', 'AS prepend', 'Community', 'Добавлять community'
                            ]
                            x.add_row([
                                rmap['name'],
                                rmap['description'],
                                rmap['action'],
                                rmap['match_by'],
                                rmap['next_hop'],
                                rmap['weight'],
                                rmap['metric'],
                                rmap['preference'],
                                rmap['as_prepend'],
                                rmap['community'],
                                rmap['additive']
                            ])
                            array.append(x.get_string())
                            if rmap['match_by'] == 'ip':
                                array.append(f"\nIP-адреса: {rmap['match_items']}\n")
                            elif rmap['match_by'] == 'aspath':
                                array.append(f"\nAS путь: {rmap['match_items']}\n")
                            else:
                                array.append(f"\nCommunity: {rmap['match_items']}\n")
                            
                        array.append("\nФильтры:\n")
                        for rmap in item['bgp']['filters']:
                            filters[rmap['id']] = {
                                'name': rmap['name'],
                                'action': rmap['action'],
                                'in': False,
                                'out': False,
                            }
                            x = PrettyTable()
                            x.field_names = ['Название', 'Описание', 'Действие', 'Фильтровать по']
                            x.add_row([
                                rmap['name'],
                                rmap['description'],
                                rmap['action'],
                                rmap['filter_by'],
                            ])
                            array.append(x.get_string())
                            if rmap['filter_by'] == 'ip':
                                array.append(f"\nФильтры по IP: {rmap['filter_items']}\n")
                            else:
                                array.append(f"\nФильтры по AS пути: {rmap['filter_items']}\n")
                            
                        array.append("\nBGP-соседи:\n")
                        for rmap in item['bgp']['neighbors']:
                            x = PrettyTable()
                            x.field_names = ['Включено', 'Описание', 'Host', 'удалённая ASN', 'Вес', 'TTL']
                            x.add_row([
                                rmap['enabled'],
                                rmap['description'],
                                rmap['host'],
                                rmap['remote_asn'],
                                rmap['weight'],
                                rmap['multihop_ttl'],
                            ])
                            array.append(x.get_string())
                            array.append(f"\nАнонсировать себя в качестве next hop: {rmap['next_hop_self']}")
                            array.append(f"\nMultihop для eBGP: {rmap['ebgp_multihop']}")
                            array.append(f"\nRoute reflector client: {rmap['route_reflector_client']}")
                            array.append(f"\nSoft reconfiguration: {rmap['soft_reconfiguration']}")
                            array.append(f"\nDefault originate: {rmap['default_originate']}")
                            array.append(f"\nSend community: {rmap['send_community']}")
                            array.append(f"\nПароль: {rmap['password']}")
                            array.append(f"\nФильтры BGP-соседей:\n")
                            x = PrettyTable()
                            x.field_names = ['in', 'out', 'Название', 'Действие']
                            for key, val in filters.items():
                                val['in'] = 'x' if key in rmap['filter_in'] else '-'
                                val['out'] = 'x' if key in rmap['filter_out'] else '-'
                                row = [val['in'], val['out'], val['name'], val['action']]
                                x.add_row(row)
                            array.append(x.get_string())
                            array.append(f"\nRoutemaps:\n")
                            x = PrettyTable()
                            x.field_names = ['in', 'out', 'Название', 'Действие']
                            for key, val in routemaps.items():
                                val['in'] = 'x' if key in rmap['routemap_in'] else '-'
                                val['out'] = 'x' if key in rmap['routemap_out'] else '-'
                                row = [val['in'], val['out'], val['name'], val['action']]
                                x.add_row(row)
                            array.append(x.get_string())
                            array.append("\n")

                    ############# RIP ##############
                    if item['rip']['networks']:
                        array.append("\nRIP\n")
                        array.append(f"Включено: {item['rip']['enabled']}\n")
                        array.append(f"Версия RIP: {item['rip']['version']}\n")
                        array.append(f"Метрика по умолчанию: {item['rip']['default_metric']}\n")
                        array.append(f"Административное расстояние: {item['rip']['administrative_distance']}\n")
                        array.append(f"Отправлять себя в качестве маршрута по умолчанию: {item['rip']['default_originate']}\n")
                        array.append("Сети RIP: ")
                        array.append(", ".join(list(x.values())[0] for x in item['rip']['networks']))
                        array.append("\nRedistribute: \n")
                        x = PrettyTable()
                        x.field_names = ['Redistribute routes', 'Метрика']
                        for d in item['rip']['redistribute']:
                            x.add_row([d['kind'], d['metric']])
                        array.append(x.get_string())
                        array.append("\nИнтерфейсы: \n")
                        x = PrettyTable()
                        x.field_names = [
                            'Интерфейс', 'Посылать версию', 'Принимать версию',
                            'Split horizon', 'Poison reverse', 'Пассивный режим'
                        ]
                        for iface in item['rip']['interfaces']:
                            x.add_row([
                                iface['name'],
                                iface['send_version'],
                                iface['receive_version'],
                                iface['split_horizone'],
                                iface['poisoned_reverse'],
                                iface['passive_mode'],
                            ])
                        array.append(x.get_string())
                        array.append("\n")

                    ############# Мультикаст роутер ################
                    if item['pimsm']['interfaces']:
                        array.append("\nМультикаст роутер\n")
                        array.append(f"Включено: {item['pimsm']['enabled']}\n")
                        array.append(f"Использовать ECMP: {item['pimsm']['use_ecmp']}\n")
                        array.append(f"Использовать ECMP rebalance: {item['pimsm']['ecmp_rebalance']}\n")
                        array.append(f"JOIN/PRUNE интервал (сек): {item['pimsm']['join_prune_interval']}\n")
                        array.append(f"Интервал register suppress (сек): {item['pimsm']['register_suppress_time']}\n")
                        array.append(f"Keep-alive таймер (сек): {item['pimsm']['keep_alive_timer']}\n")
                        array.append("\nИнтерфейсы:\n")
                        x = PrettyTable()
                        x.field_names = [
                            'Интерфейс', 'Включено', 'Интервал отправки HELLO (сек)',
                            'Приоритет выбора DR', 'Разрешить IGMP', 'Использовать IGMPv2'
                        ]
                        for iface in item['pimsm']['interfaces']:
                            x.add_row([
                                iface['name'],
                                iface['enabled'],
                                iface['pim_hello_interval'],
                                iface['pim_dr_priority'],
                                iface['use_igmp'],
                                iface['use_igmp_v2'],
                            ])
                        array.append(x.get_string())
                        array.append("\nСвойства Rendevouz Point:\n")
                        x = PrettyTable()
                        x.field_names = ['Название', 'Включено', 'IP-адрес', 'Разрешённые группы ASM']
                        for gr in item['pimsm']['rpmappings']:
                            x.add_row([
                                gr['name'],
                                gr['enabled'],
                                gr['ipv4'],
                                gr['groups'],
                            ])
                        array.append(x.get_string())
                        array.append("\n")
                        array.append(f"Разрешённые группы SSM: {item['pimsm']['ssm_address_range']}\n")
                        array.append(f"Исключения из SPT: {item['pimsm']['spt_exclusions']}\n")
                        array.append("\n")
            else:
                for item in data:
                    x = PrettyTable()
                    x.field_names = [
                        'Название', 'Описание', 'Включёно', 'Адрес назначения', 'Шлюз', 'Интерфейс', 'Метрика',
                    ]
                    x.add_row([
                        item['name'],
                        item['description'],
                        item['enabled'],
                        item['dest'],
                        item['gateway'],
                        item['iface_id'] if item['iface_id'] else "Автоматически",
                        item['metric'],
                    ])
                    array.append(x.get_string())
                    array.append("\n")

                    ######################## OSPF v5 #########################
                    data, interfaces, areas = self.get_ospf_params_v5()
                    if data['router_id'] and interfaces:
                        array.append("\nOSPF\n")
                        x = PrettyTable()
                        x.field_names = [
                            'Включено', 'Идентификатор роутера', 'Redistribute', 'Метрика', 'Default originate',
                        ]
                        x.add_row([
                            data['enabled'],
                            data['router_id'],
                            data['redistribute'],
                            data['metric'],
                            data['default_originate'],
                        ])
                        array.append(x.get_string())
                        array.append("\n")
                    
                        array.append("Интерфейсы:\n")
                        hash_id = {}
                        for iface in interfaces:
                            hash_id[iface['id']] = iface['iface_id'].split(':')[0]
                            x = PrettyTable()
                            x.field_names = [
                                'Интерфейс', 'Включено', 'Описание', 'Стоимость', 'Приоритет', 'Интервал hello',
                                'Интервал dead', 'Интервал повторения', 'Задержка передачи' 
                            ]
                            x.add_row([
                                iface['iface_id'].split(':')[0],
                                iface['enabled'],
                                iface['description'],
                                iface['cost'],
                                iface['priority'],
                                iface['hello_interval'],
                                iface['dead_interval'],
                                iface['retransmit_interval'],
                                iface['transmit_delay'],
                            ])
                            array.append(x.get_string())
                            array.append("\n")
                            x = PrettyTable()
                            x.field_names = ['', 'Включено', 'Тип авторизации', 'MD5 key ID', 'Ключ']
                            x.add_row([
                                'Аутентификация',
                                iface['auth_params']['enabled'],
                                iface['auth_params']['auth_type'],
                                iface['auth_params']['md5_id'],
                                iface['auth_params']['auth_key'],
                            ])
                            array.append(x.get_string())
                            array.append("\n")
                        
                        array.append("Области:\n")
                        for area in areas:
                            x = PrettyTable()
                            x.field_names = [
                                'Имя области', 'Включено', 'Описание', 'Стоимость', 'Идентификатор области',
                                'Тип авторизации', 'Тип области', 'Не суммировать' 
                            ]
                            x.add_row([
                                area['name'],
                                area['enabled'],
                                area['description'],
                                area['cost'],
                                area['area_id'],
                                area['auth_type'],
                                area['area_type'],
                                area['no_summary'],
                            ])
                            array.append(x.get_string())
                            array.append(f"\nИнтерфейсы области: {', '.join(hash_id[x] for x in area['interfaces'])}")
                            array.append(f"\nВиртуальные линки: {area['virtual_links']}\n")

                    ############## BGP v5 #############
                    filtr = {}
                    routemaps = {}
                    data, neighbors, rmaps, filters = self.get_bgp_params_v5()
                    if data['router_id'] and neighbors:
                        array.append("\nBGP\n")
                        x = PrettyTable()
                        x.field_names = [
                            'Включено', 'Идентификатор роутера', 'Номер автономной системы (AS)',
                            'Multiple path', 'Redistribute'
                        ]
                        x.add_row([
                            data['enabled'],
                            data['router_id'],
                            data['as_number'],
                            data['multiple_path'],
                            data['redistribute'],
                        ])
                        array.append(x.get_string())
                        array.append(f"\nСети: {data['networks']}\n")
                        
                        array.append("\nRoutemaps:\n")
                        for rmap in rmaps:
                            routemaps[rmap['id']] = {
                                'name': rmap['name'],
                                'action': rmap['action'],
                                'in': False,
                                'out': False,
                            }
                            x = PrettyTable()
                            x.field_names = [
                                'Название', 'Описание', 'Действие', 'Сравнивать по', 'Next hop', 'Вес',
                                'Метрика', 'Предпочтение', 'AS prepend', 'Community', 'Добавлять community'
                            ]
                            x.add_row([
                                rmap['name'],
                                rmap['description'],
                                rmap['action'],
                                rmap['match_by'],
                                rmap['next_hop'],
                                rmap['weight'],
                                rmap['metric'],
                                rmap['preference'],
                                rmap['as_prepend'],
                                rmap['community'],
                                rmap['additive']
                            ])
                            array.append(x.get_string())
                            if rmap['match_by'] == 'ip':
                                array.append(f"\nIP-адреса: {rmap['match_items']}\n")
                            elif rmap['match_by'] == 'aspath':
                                array.append(f"\nAS путь: {rmap['match_items']}\n")
                            else:
                                array.append(f"\nCommunity: {rmap['match_items']}\n")
                            
                        array.append("\nФильтры:\n")
                        for rmap in filters:
                            filtr[rmap['id']] = {
                                'name': rmap['name'],
                                'action': rmap['action'],
                                'in': False,
                                'out': False,
                            }
                            x = PrettyTable()
                            x.field_names = ['Название', 'Описание', 'Действие', 'Фильтровать по']
                            x.add_row([
                                rmap['name'],
                                rmap['description'],
                                rmap['action'],
                                rmap['filter_by'],
                            ])
                            array.append(x.get_string())
                            if rmap['filter_by'] == 'ip':
                                array.append(f"\nФильтры по IP: {rmap['filter_items']}\n")
                            else:
                                array.append(f"\nФильтры по AS пути: {rmap['filter_items']}\n")
                            
                        array.append("\nBGP-соседи:\n")
                        for rmap in neighbors:
                            x = PrettyTable()
                            x.field_names = [
                                'Включено', 'Описание', 'Интерфейс', 'Host', 'удалённая ASN', 'Вес', 'TTL'
                            ]
                            x.add_row([
                                rmap['enabled'],
                                rmap['description'],
                                rmap['iface_id'].split(':')[0],
                                rmap['host'],
                                rmap['remote_asn'],
                                rmap['weight'],
                                rmap['multihop_ttl'],
                            ])
                            array.append(x.get_string())
                            array.append(f"\nАнонсировать себя в качестве next hop: {rmap['next_hop_self']}")
                            array.append(f"\nMultihop для eBGP: {rmap['ebgp_multihop']}")
                            array.append(f"\nRoute reflector client: {rmap['route_reflector_client']}")
                            array.append(f"\nSoft reconfiguration: {rmap['soft_reconfiguration']}")
                            array.append(f"\nDefault originate: {rmap['default_originate']}")
                            array.append(f"\nSend community: {rmap['send_community']}")
                            array.append(f"\nПароль: {rmap['password']}")
                            array.append(f"\nФильтры BGP-соседей:\n")
                            x = PrettyTable()
                            x.field_names = ['in', 'out', 'Название', 'Действие']
                            for key, val in filtr.items():
                                val['in'] = 'x' if key in rmap['filter_in'] else '-'
                                val['out'] = 'x' if key in rmap['filter_out'] else '-'
                                row = [val['in'], val['out'], val['name'], val['action']]
                                x.add_row(row)
                            array.append(x.get_string())
                            array.append(f"\nRoutemaps:\n")
                            x = PrettyTable()
                            x.field_names = ['in', 'out', 'Название', 'Действие']
                            for key, val in routemaps.items():
                                val['in'] = 'x' if key in rmap['routemap_in'] else '-'
                                val['out'] = 'x' if key in rmap['routemap_out'] else '-'
                                row = [val['in'], val['out'], val['name'], val['action']]
                                x.add_row(row)
                            array.append(x.get_string())
                            array.append("\n")


            return 0, array
        else:
            return 0, "\tМаршруты не настроены.\n"

    def export_auth_servers(self):
        """Выгрузить список серверов авторизации"""
        array = []
        ldap, radius, tacacs, ntlm, saml = self.get_auth_servers_list()
        for item in ldap:
            self.auth_srv[item['id']] = item['name']
            x = PrettyTable()
            x.field_names = [
                'Тип', 'Название', 'Включён', 'Описание', 'Имя LDAP или IP-адрес', 'SSL',
                'Bind DN (логин)', 'Домены LDAP', 'Kerberos keytab', 'Пути поиска'
            ]
            x.add_row([
                'ad',
                item['name'],
                item['enabled'],
                item['description'],
                item['address'],
                item['ssl'],
                item['bind_dn'],
                item['domains'],
                item['keytab_exists'],
                item['roots'],
            ])
            array.append(x.get_string())
            array.append("\n\n")

        for item in radius:
            self.auth_srv[item['id']] = item['name']
            x = PrettyTable()
            x.field_names = ['Тип', 'Название', 'Включён', 'Описание', 'Адрес сервера']
            x.add_row([
                'radius',
                item['name'],
                item['enabled'],
                item['description'],
                ", ".join(f"{x['host']}:{x['port']}" for x in item['addresses']),
            ])
            array.append(x.get_string())
            array.append("\n\n")

        for item in tacacs:
            self.auth_srv[item['id']] = item['name']
            x = PrettyTable()
            x.field_names = [
                'Тип', 'Название', 'Включён', 'Описание', 'Адрес сервера',
                'Порт', 'Использовать одно TCP соединение', 'Таймаут (сек)'
            ]
            x.add_row([
                'tacacs+',
                item['name'],
                item['enabled'],
                item['description'],
                item['address'],
                item['port'],
                item['use_single_connection'],
                item['timeout'],
            ])
            array.append(x.get_string())
            array.append("\n\n")

        for item in ntlm:
            self.auth_srv[item['id']] = item['name']
            x = PrettyTable()
            x.field_names = ['Тип', 'Название', 'Включён', 'Описание', 'IP-адрес', 'Домен Windows']
            x.add_row([
                'ntlm',
                item['name'],
                item['enabled'],
                item['description'],
                item['ip'],
                item['domain'],
            ])
            array.append(x.get_string())
            array.append("\n\n")

        for item in saml:
            self.auth_srv[item['id']] = item['name']
            x = PrettyTable()
            x.field_names = [
                'Тип', 'Название', 'Включён', 'Описание', 'SAML metadata URL',
                'Сертификат SAML IDP', 'Single sign-on URL', 'Single sign-on binding',
                'Single logout URL', 'Single logout binding'
            ]
            x.add_row([
                'saml idp',
                item['name'],
                item['enabled'],
                item['description'],
                item['metadata_url'],
                item['certificate_id'],
                item['sso_url'],
                item['sso_http_binding'].upper(),
                item['slo_url'],
                item['slo_http_binding'].upper(),
            ])
            array.append(x.get_string())
            array.append("\n")

        return 0, array if array else "\tНет серверов авторизации."

    def export_2fa_profiles(self):
        """Выгрузить список 2FA профилей"""
        array = []
        data = self.get_2fa_profiles_list()
        for item in data['items']:
            self.profile2fa[item['id']] = item['name']
            array.append(f"\nНазвание: '{item['name']}'\nОписание: '{item['description']}'\n")
            x = PrettyTable()
            if item['type'] == 'totp':
                aaa = item['init_notification_body'].split()
                body = ''.join([f'{word}\n' if (i+1)%3 == 0 else f'{word} ' for i, word in enumerate(aaa)])
                aaa = item['init_notification_subject'].split()
                subject = ''.join([f'{word}\n' if (i+1)%3 == 0 else f'{word} ' for i, word in enumerate(aaa)])
                empty_row = ['', '', '', '', '', '', '']
                x.field_names = [
                    'MFA через', 'Инициализация TOTP', 'Показывать QR-код',
                    'От', 'Тема', 'Содержимое', 'Время жизни MFA-кода'
                ]
                x.add_row(empty_row)
                x.add_row([
                    item['type'].upper(),
                    self.notification.get(item['init_notification_profile_id'], 'Нет'),
                    item['totp_show_qr_code'],
                    item['init_notification_sender'],
                    subject,
                    body,
                    item['auth_code_lifetime']
                ])
            else:
                aaa = item['auth_notification_body'].split()
                body = ''.join([f'{word}\n' if (i+1)%3 == 0 else f'{word} ' for i, word in enumerate(aaa)])
                aaa = item['auth_notification_subject'].split()
                subject = ''.join([f'{word}\n' if (i+1)%3 == 0 else f'{word} ' for i, word in enumerate(aaa)])
                empty_row = ['', '', '', '', '', '']
                x.field_names = [
                    'MFA через', 'Профиль отправки MFA', 'От', 'Тема', 'Содержимое', 'Время жизни MFA-кода'
                ]
                x.add_row(empty_row)
                x.add_row([
                    item['type'].upper(),
                    self.notification.get(item['auth_notification_profile_id'], 'Нет'),
                    item['auth_notification_sender'],
                    subject,
                    body,
                    item['auth_code_lifetime']
                ])
            x.align['Тема'] = "l"
            x.align['Содержимое'] = "l"
            array.append(x.get_string())
            array.append("\n")
        return data['count'], array if array else "\tНет профилей MFA."


    def export_auth_profiles(self):
        """Выгрузить список профилей авторизации"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '']
        data = self.get_auth_profiles_list()
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Профиль MFA', 'Время бездействия до отключения',
            'Время жизни авториз. пользователя', 'Число неудачных попыток авториз.',
            'Время блокировки лок.пользователя', 'Методы аутентификации'
        ]
        for item in data:
            x.add_row(empty_row)
            self.auth_profiles[item['id']] = item['name']
            methods = []
            for method in item['allowed_auth_methods']:
                if method['type'] in ['ldap', 'radius', 'tacacs_plus', 'ntlm']:
                    sid = f"{method['type']}_server_id"
                    methods.append(f"{method['type']}: {self.auth_srv[method[sid]]}")
                else:
                    methods.append(method['type'])
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                self.profile2fa.get(item['2fa_profile_id'], 'Нет'),
                item['idle_time'],
                item['expiration_time'],
                item['max_auth_attempts'],
                item['auth_lockout_time'],
                "\n".join(x for x in  methods),
            ])
        x.align = "r"
        x.align['Название'] = "l"
        x.align['Профиль MFA'] = "l"
        x.align['Методы аутентификации'] = "l"
        array.append(x.get_string())
        array.append("\n")

        return 0, array if array else "\tНет профилей авторизации."

    def export_captive_profiles(self):
        """Выгрузить список captive-профилей"""
        array = []
        tpl = {
            'num': 'Цифры',
            'alpha_num': 'Буквы+цифры',
            'alpha_num_special': 'Буквы+цифры+спецсимволы'
        }
        data = self.get_captive_profiles_list()
        for item in data['items']:
            self.captive_profiles[item['id']] = item['name']
            array.append(f"\nНазвание: '{item['name']}'\nОписание: '{item['description']}'\n")
            x = PrettyTable()
            x.field_names = [
                'Шаблон страницы авторизации', 'Метод идентификации', 'Профиль авторизации',
                'URL для редиректа', 'Разрешить браузерам помнить авторизацию',
                'Предлагать выбор домена', 'Показывать CAPTCHA', 'HTTPS для авторизации'
            ]
            x.add_row([
                self.templates.get(item['captive_template_id'], self.templates['captiveportal_user_auth']),
                item['auth_mode'],
                self.auth_profiles.get(item['user_auth_profile_id'], 'Нет'),
                item['custom_redirect'],
                f"{item['use_cookie_auth']} - {item['cookie_expiration_time']}",
                item['enable_ldap_domain_selector'],
                item['use_captcha'],
                item['use_https_auth']
            ])
            array.append(x.get_string())
            if item['notification_profile_id'] != -1:
                array.append("\nРегистрация гостевых пользователей:'\n")
                array.append(f"\tПрофиль оповещения: {self.notification.get(item['notification_profile_id'])}\n")
                array.append(f"\tОт: '{item['notification_sender']}'\n")
                array.append(f"\tТема оповещения: '{item['notification_subject']}'\n")
                array.append(f"\tПисьмо оповещения: '{item['notification_body']}'\n")
                array.append(f"\tДлина пароля: {item['ta_password_len']}\n")
                array.append(f"\tСложность пароля: {tpl[item['ta_password_tpl']]}\n")
                groups = {v: k for k, v in self._groups.items()}
                array.append(f"\tГруппы: {[groups[x] for x in item['ta_groups']]}")
            array.append("\n")
        return data['count'], array if array else "\tНет captive-профилей."

    def export_captive_portal(self):
        """Выгрузить список правил captive-портала"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '', '']
        data = self.get_captive_portal_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Включено', 'Captive-профиль', 'Журналировать', 'Исходная зона', 'Зона назначения',
            'Адрес источника', 'Адрес назначения', 'Категории', 'URL', 'Время', 'Описание'
        ]
        for item in data['items']:
            x.add_row(empty_row)
            row = [
                split_name(item['name']),
                item['enabled'],
                self.captive_profiles.get(item['profile_id'], 'Не использовать аутентификацию'),
                item['rule_log'],
                "\n".join(self.zones[x] for x in item['src_zones']) if item['src_zones'] else '',
                "\n".join(self.zones[x] for x in item['dst_zones']) if item['dst_zones'] else '',
                "\n".join(self.list_ip_addresses[x[1]] for x in item['src_ips']),
                "\n".join(self.list_ip_addresses[x[1]] for x in item['dst_ips']),
                "\n".join(self._categories[y[1]] for y in item['url_categories']),
                "\n".join(self.list_url[y] for y in item['urls']),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
                split_descr(item['description']),
            ]
            x.add_row(row)

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if array else "\tНет правил captive-портала."

    def export_byod_policy(self):
        """Выгрузить список политик BYOD"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '']
        data = self.get_byod_policy_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Действие', 'Подтверждение администратора', 'Разрешено устройств',
            'Устройств одновременно', 'Пользователи/Группы', 'Тип устройств'
        ]
        for item in data['items']:
            x.add_row(empty_row)
            users_and_groups = []
            groups = {v: k for k, v in self._groups.items()}
            for ug in item['users']:
                if ug[0] == 'user':
                    if ug[1] in self._users:
                        users_and_groups.append(f"User: {self._users[ug[1]]}")
                else:
                    if ug[1] in groups:
                        users_and_groups.append(f"Group: {groups[ug[1]]}")
            row = [
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                item['action'],
                item['approving_required'],
                item['max_device_number'],
                item['max_active_device_number'],
                "\n".join(x for x in users_and_groups),
                "\n".join(x for x in item['user_agent_list']),
            ]
            x.add_row(row)

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if array else "\tНет политик BYOD."


    def export_firewall_rules(self):
        """Выгрузить список правил межсетевого экрана"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '']
        fragm = {
            'ignore': 'Все пакеты',
            'yes': 'Фрагм. пакеты',
            'no': 'Нефрагм. пакеты',
        }
        data = self.get_firewall_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Общие',
            'SRC Zone /invert', 'Адрес источника /invert',
            'DST Zone /invert', 'Адрес назначения /invert', 'Пользователи', 'Сервис', 'Приложения', 'Время'
        ]
        for item in data['items']:
            x.add_row(empty_row)

            general = [
                "Включено:       Да" if item['enabled'] else "Включено:       Нет",
                "Действие:       Разрешить" if item['action'] == 'accept' else "Действие:       Запретить",
                f"Send host ICMP: {item['send_host_icmp']}" if item['send_host_icmp'] else "Send host ICMP: ---",
                f"Сценарий: '{self._scenarios.get(item['scenario_rule_id'], -1)}'" if item['scenario_rule_id'] else 'Сценарий: ---',
                "Журналирование: Включено" if item['log'] else "Журналирование: Выключено",
                f"Применить к..:  {fragm.get(item['fragmented'], -1)}",
            ]

            apps = []
            for app in item['apps']:
                if app[0] == 'app':
                    apps.append(self._l7apps.get(app[1], 'Error'))
                elif app[0] == 'group':
                    apps.append(self.list_app_categories.get(app[1], 'Error'))
                elif app[0] == 'ro_group':
                    apps.append(self._l7categories.get(app[1], 'Error'))

            row = [
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(general),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{self.zones[x]} /инверт' if item['dst_zones_negate'] else self.zones[x] for x in item['dst_zones']),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                self.get_users_list(item['users']),
                "\n".join(self.services[x] for x in item['services']),
                "\n".join(apps),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
            ]
            x.add_row(row)

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if array else "\tНет правил межсетевого экрана."

    def export_traffic_rules(self):
        """Выгрузить список правил раздела NAT и маршрутизация"""
        array = []
        data = self.get_traffic_rules_list()
        
        nat_present = 0
        nat_empty_row = ['', '', '', '', '', '', '', '', '', '', '']
        nat = PrettyTable()
        nat.field_names = [
            'Тип', 'Название', 'Описание', 'Включено', 'SNAT IP', 'Журналирование', 'SRC Zone /invert',
            'Адрес источника /invert', 'DST Zone /invert', 'Адрес назначения /invert', 'Сервис'
        ]
        dnat_present = 0
        dnat_empty_row = ['', '', '', '', '', '', '', '', '', '', '', '']
        dnat = PrettyTable()
        dnat.field_names = [
            'Тип', 'Название', 'Описание', 'Включено', 'SNAT IP', 'Журналирование', 'SRC Zone /invert',
            'Адрес источника /invert', 'Адрес назначения /invert', 'Сервис',
            'DNAT IP', 'Включить SNAT'
        ]
        pm_present = 0
        pm_empty_row = ['', '', '', '', '', '', '', '', '', '', '', '']
        pm = PrettyTable()
        pm.field_names = [
            'Тип', 'Название', 'Описание', 'Включено', 'SNAT IP', 'Журналирование', 'SRC Zone /invert',
            'Адрес источника /invert',  'Адрес назначения /invert', 'Порт-форвардинг',
            'DNAT IP', 'Включить SNAT'
        ]
        route_present = 0
        route_empty_row = ['', '', '', '', '', '', '', '', '', '', '', '']
        route = PrettyTable()
        route.field_names = [
            'Тип', 'Название', 'Описание', 'Включено', 'Шлюз', 'Сценарий', 'Журналирование', 'SRC Zone /invert',
            'Адрес источника /invert', 'Пользователи',  'Адрес назначения /invert', 'Сервис'
        ]
        netmap_present = 0
        netmap_empty_row = ['', '', '', '', '', '', '', '', '', '', '']
        netmap = PrettyTable()
        netmap.field_names = [
            'Тип', 'Название', 'Описание', 'Включено', 'Журналирование', 'SRC Zone /invert',
            'Адрес источника /invert',  'Адрес назначения /invert', 'Сервис', 'Новая IP-сеть', 'Напрвление'
        ]

        for item in data['items']:
            if item['action'] == 'nat':
                nat_present += 1
                nat.add_row(nat_empty_row)
                row = [
                    item['action'].upper(),
                    split_name(item['name']),
                    split_descr(item['description']),
                    item['enabled'],
                    item['snat_target_ip'],
                    item['log'],
                    "\n".join(f'{self.zones[x]} /инверт' if item['zone_in_negate'] else self.zones[x] for x in item['zone_in']),
                    "\n".join(f'{x} /инверт' if item['source_ip_negate'] else x for x in self.get_ips_list(item['source_ip'])),
                    "\n".join(f'{self.zones[x]} /инверт' if item['zone_out_negate'] else self.zones[x] for x in item['zone_out']),
                    "\n".join(f'{x} /инверт' if item['dest_ip_negate'] else x for x in self.get_ips_list(item['dest_ip'])),
                    "\n".join(self.services[x] for x in item['service']),
                ]
                nat.add_row(row)
            elif item['action'] == 'dnat':
                dnat_present += 1
                dnat.add_row(dnat_empty_row)
                row = [
                    item['action'].upper(),
                    split_name(item['name']),
                    split_descr(item['description']),
                    item['enabled'],
                    item['snat_target_ip'],
                    item['log'],
                    "\n".join(f'{self.zones[x]} /инверт' if item['zone_in_negate'] else self.zones[x] for x in item['zone_in']),
                    "\n".join(f'{x} /инверт' if item['source_ip_negate'] else x for x in self.get_ips_list(item['source_ip'])),
                    "\n".join(f'{x} /инверт' if item['dest_ip_negate'] else x for x in self.get_ips_list(item['dest_ip'])),
                    "\n".join(self.services[x] for x in item['service']),
                    item['target_ip'],
                    item['target_snat'],
                ]
                dnat.add_row(row)
            elif item['action'] == 'port_mapping':
                pm_present += 1
                pm.add_row(pm_empty_row)
                row = [
                    'Порт-форвардинг',
                    split_name(item['name']),
                    split_descr(item['description']),
                    item['enabled'],
                    item['snat_target_ip'],
                    item['log'],
                    "\n".join(f'{self.zones[x]} /инверт' if item['zone_in_negate'] else self.zones[x] for x in item['zone_in']),
                    "\n".join(f'{x} /инверт' if item['source_ip_negate'] else x for x in self.get_ips_list(item['source_ip'])),
                    "\n".join(f'{x} /инверт' if item['dest_ip_negate'] else x for x in self.get_ips_list(item['dest_ip'])),
                    "\n".join(f"{x['proto']}: {x['src_port']} -> {x['dst_port']}" for x in item['port_mappings']),
                    item['target_ip'],
                    item['target_snat'],
                ]
                pm.add_row(row)
            elif item['action'] == 'route':
                route_present += 1
                route.add_row(route_empty_row)
                route_id, _ = item['gateway'].split(":")
                route_name = self.routes[route_id]
                row = [
                    'Policy-based routing',
                    split_name(item['name']),
                    split_descr(item['description']),
                    item['enabled'],
                    route_name,
                    self._scenarios.get(item['scenario_rule_id'], ''),
                    item['log'],
                    "\n".join(f'{self.zones[x]} /инверт' if item['zone_in_negate'] else self.zones[x] for x in item['zone_in']),
                    "\n".join(f'{x} /инверт' if item['source_ip_negate'] else x for x in self.get_ips_list(item['source_ip'])),
                    self.get_users_list(item['users']) if 'users' in item.keys() else '',
                    "\n".join(f'{x} /инверт' if item['dest_ip_negate'] else x for x in self.get_ips_list(item['dest_ip'])),
                    "\n".join(self.services[x] for x in item['service']),
                ]
                route.add_row(row)
            elif item['action'] == 'netmap':
                netmap_present += 1
                netmap.add_row(netmap_empty_row)
                row = [
                    'Network mapping',
                    split_name(item['name']),
                    split_descr(item['description']),
                    item['enabled'],
                    item['log'],
                    "\n".join(f'{self.zones[x]} /инверт' if item['zone_in_negate'] else self.zones[x] for x in item['zone_in']),
                    "\n".join(f'{x} /инверт' if item['source_ip_negate'] else x for x in self.get_ips_list(item['source_ip'])),
                    "\n".join(f'{x} /инверт' if item['dest_ip_negate'] else x for x in self.get_ips_list(item['dest_ip'])),
                    "\n".join(self.services[x] for x in item['service']),
                    item['target_ip'],
                    'Входящий, подменяется IP-сеть назначения' if item['direction'] == 'input' else 'Исходящий, подменяется IP-сеть источника',
                ]
                netmap.add_row(row)

        if nat_present:
            nat.align = "l"
            array.append(nat.get_string())
            array.append("\n")
        if dnat_present:
            dnat.align = "l"
            array.append(dnat.get_string())
            array.append("\n")
        if pm_present:
            pm.align = "l"
            array.append(pm.get_string())
            array.append("\n")
        if route_present:
            route.align = "l"
            array.append(route.get_string())
            array.append("\n")
        if netmap_present:
            netmap.align = "l"
            array.append(netmap.get_string())
            array.append("\n")

        return data['count'], array if array else "\tНет правил межсетевого экрана."

    def export_icap_servers_list(self):
        """Выгрузить список серверов ICAP"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '']
        data = self.get_icap_servers_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Адрес сервера', 'Порт', 'Общие', 'Reqmod путь', 'Respmod путь',
            'Посылать имя пользователя', 'Base64', 'Посылать IP-адрес', 'Посылать MAC-адрес'
        ]
        for item in data:
            self.list_icap_servers[item['id']] = item['name']
            x.add_row(empty_row)
            general = [
                f"Max размер сообщения:        {item['max_request_size']}",
                f"Период проверки доступности: {item['keep_alive_interval']}",
                f"Пропускать при ошибках:      {item['error_bypass']}",
            ]
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['address'],
                item['port'],
                "\n".join(general),
                f"Включено: {item['reqmod_enabled']}\nПуть: {item['reqmod_service']}",
                f"Включено: {item['respmod_enabled']}\nПуть: {item['respmod_service']}",
                f"Включено: {item['header_user_enabled']}\nHeader: {item['header_user']}",
                item['xauth_base64_encode'],
                f"Включено: {item['header_ip_enabled']}\nHeader: {item['header_ip']}",
                f"Включено: {item['header_mac_enabled']}\nHeader: {item['header_mac']}",
            ])

        x.align = "l"
        x.align['Max размер сообщения'] = "c"
        x.align['Период проверки доступности'] = "c"
        x.align['Пропускать при ошибках'] = "c"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет серверов ICAP."

    def export_icap_loadbalancing_rules(self):
        """Выгрузить список правил балансировки серверов ICAP"""
        array = []
        empty_row = ['', '', '', '', '']
        data = self.get_icap_loadbalancing_rules()
        
        x = PrettyTable()
        x.field_names = ['Тип', 'Название', 'Описание', 'Включено', 'ICAP-серверы']
        for item in data:
            self.list_icap_balancers[item['id']] = item['name']
            x.add_row(empty_row)
            x.add_row([
                'ICAP',
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                "\n".join(self.list_icap_servers[x] for x in item['profiles']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет правил балансировки серверов ICAP."

    def export_tcpudp_loadbalancing_rules(self):
        """Выгрузить список правил балансировки серверов TCP/UDP"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '']
        scheduler = {
            'wrr': 'Weighted round robin',
            'rr': 'Round robin',
            'lc': 'Least connections',
            'wlc': 'Weighted least connections',
        }
        mode = {
            'gateFalse': 'Шлюз',
            'masqFalse': 'Маскарадинг',
            'masqTrue': 'Маскарадинг с подменой IP-источника (SNAT)',
        }

        data = self.get_tcpudp_loadbalancing_rules()
        
        x = PrettyTable()
        x.field_names = [
            'Тип', 'Название', 'Описание', 'Включено', 'IP вирт.сервера',
            'Метод балансировки', 'Серверы: IP/Порт/Вес/Режим', 'Аварийный режим', 'Мониторинг'
        ]
        for item in data:
            x.add_row(empty_row)
            general = [
                f"IP: {item['ip_address']}",
                f"Порт:     {item['port']}",
                f"Протокол: {item['protocol'].upper()}",
            ]
            real_srv = []
            for srv in item['hosts']:
                srv_mode = mode[srv['mode'] + str(srv['snat'])]
                real_srv.append(f"{srv['ip_address']}:{srv['port']} - Вес: {srv['weight']} {srv_mode}")
            if item['fallback']:
                alarm_mode = mode[item['fallback']['mode'] + str(item['fallback']['snat'])]
                fallback = f"{item['fallback']['ip_address']}:{item['fallback']['port']} - {alarm_mode}"
            else:
                fallback = 'Отключено'
            monit = [
                f"Режим: {item['monitoring']['kind']}",
                f"Сервис: {item['monitoring']['service']}",
                f"Запрос: {item['monitoring']['request']}",
                f"Ожидаемый ответ: {item['monitoring']['response']}",
                f"Интервал проверки: {item['monitoring']['interval']}",
                f"Время ожидания: {item['monitoring']['timeout']}",
                f"Число неудачных попыток: {item['monitoring']['failurecount']}",
            ]
            row = [
                'TCP/IP',
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                "\n".join(general),
                scheduler.get(item['scheduler'], 'Error'),
                "\n".join(real_srv),
                fallback,
                "\n".join(monit),
            ]
            x.add_row(row)

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет правил балансировки серверов TCP/IP."

    def export_reverseproxy_servers_list(self):
        """Выгрузить список серверов reverse-прокси"""
        array = []
        empty_row = ['', '', '', '', '', '', '']
        data = self.get_reverseproxy_servers_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Адрес сервера', 'Порт', 'HTTPS до сервера',
            'Проверять SSL сертификат', 'Не изменять IP источника'
        ]
        for item in data:
            self.list_reverseproxy_servers[item['id']] = item['name']
            x.add_row(empty_row)
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['address'],
                item['port'],
                item['is_https'],
                item['check_certificate'],
                item['is_tproxy'],
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет серверов Reverse-proxy."


    def export_reverseproxy_loadbalancing_rules(self):
        """Выгрузить список правил балансировки серверов reverse-прокси"""
        array = []
        empty_row = ['', '', '', '', '']
        data = self.get_reverseproxy_loadbalancing_rules()
        
        x = PrettyTable()
        x.field_names = ['Тип', 'Название', 'Описание', 'Включено', 'Серверы reverse-proxy']
        for item in data:
            x.add_row(empty_row)
            x.add_row([
                'Reverse proxy',
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                "\n".join(self.list_reverseproxy_servers[x] for x in item['profiles']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет правил балансировки серверов Reverse-proxy."

    def export_loadbalancing_rules(self):
        """Выгрузить список правил балансировки нагрузки"""
        array = []
        total = 0
        i, tcpudp = self.export_tcpudp_loadbalancing_rules()
        total += i
        array += tcpudp
        i, icap = self.export_icap_loadbalancing_rules()
        total += i
        array += icap
        i, reverse = self.export_reverseproxy_loadbalancing_rules()
        total += i
        array += reverse
        return total, array if total else "\tНет правил балансировки нагрузки."

    def export_shaper_rules_list(self):
        """Выгрузить список правил ограничения пропускной способности"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '', '', '']
        data = self.get_shaper_rules_list()
        counter = data['count'] if self.version.startswith('6') else data['total']
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Полоса пропускания', 'Сценарий', 'SRC zone/invert', 'Адрес источника/invert',
            'DST Zone/invert', 'Адрес назначения/invert', 'Пользователи', 'Сервис', 'Приложения', 'Время',
        ]
        for item in data['items']:
            x.add_row(empty_row)

            apps = []
            for app in item['apps']:
                if app[0] == 'app':
                    apps.append(f"Приложение: {self._l7apps.get(app[1], 'Error')}")
                elif app[0] == 'group':
                    apps.append(self.list_app_categories.get(app[1], 'Error'))
                elif app[0] == 'ro_group':
                    apps.append(f"Категория: {self._l7categories.get(app[1], 'Error')}")

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                self.list_shapers.get(item['pool'], 'Error'),
                self._scenarios.get(item['scenario_rule_id'], -1) if item['scenario_rule_id'] else '',
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{self.zones[x]} /инверт' if item['dst_zones_negate'] else self.zones[x] for x in item['dst_zones']),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                self.get_users_list(item['users']),
                "\n".join(f'{self.services[x]} /инверт' if item['services_negate'] else self.services[x] for x in item['services']),
                "\n".join(f'{x} /инверт' if item['apps_negate'] else x for x in apps),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return counter, array if counter else "\tНет правил ограничения пропускной способности."

    def export_content_rules_list(self):
        """Выгрузить список правил Фильтрации контента"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '']
        data = self.get_content_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Общие', 'SRC zone/invert', 'Адрес источника/invert', 'Пользователи',
            'DST Zone/invert', 'Адрес назначения/invert', 'Категории', 'URL', 'Типы контента', 'Морфология',
            'Useragent', 'HTTP метод', 'Реферы', 'Время',
        ]
        for item in data['items']:
            x.add_row(empty_row)

            page = self.templates[item['blockpage_template_id']] if item['blockpage_template_id'] != -1 else self.templates['blockpage']
            general = [
                "Включено:       ДА" if item['enabled'] else "Включено:       НЕТ",
                "Действие:       Разрешить" if item['action'] == 'accept' else "Действие:       Запретить",
                "Журналирование: Включено" if item['rule_log'] else "Журналирование: Выключено",
                f"Сценарий:      '{self._scenarios.get(item['scenario_rule_id'], -1)}'" if item['scenario_rule_id'] else 'Сценарий:       ---',
                f"Название стр.блокировки: '{item['public_name']}'" if item['public_name'] else "Название стр.блокировки: ---",
                f"Проверять антивир.UserGate: {item['enable_md5_check']}",
                f"Эвристическая проверка:     {item['enable_kav_check']}",
                "  --- Страница блокировки ---  ",
                f"Использовать внутр.стр.блокировки: {not item['enable_custom_redirect']}",
                f"Страница: {page}",
                f"Использовать внешний URL:          {item['enable_custom_redirect']}",
                f"URL: {item['custom_redirect']}",
            ]

            category = []
            for cat in item['url_categories']:
                if cat[0] == 'list_id':
                    category.append(self.list_urlcategorygroup[cat[1]])
                else:
                    category.append(self._categories[cat[1]])

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(general),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                self.get_users_list(item['users']),
                "\n".join(f'{self.zones[x]} /инверт' if item['dst_zones_negate'] else self.zones[x] for x in item['dst_zones']),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                "\n".join(f'{x} /инверт' if item['url_categories_negate'] else x for x in category),
                "\n".join(f'{self.list_url[x]} /инверт' if item['urls_negate'] else self.list_url[x] for x in item['urls']),
                "\n".join(f'{self.list_mime_groups[x]} /инверт' if item['content_types_negate'] else self.list_mime_groups[x]
                                 for x in item['content_types']),
                "\n".join(self.list_morph_groups[x] for x in item['morph_categories']),
                "\n".join(self.list_useragent[x[1]] for x in item['user_agents']),
                "\n".join(x for x in item['http_methods']),
                "\n".join(self.list_url[x] for x in item['referers']),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет правил Фильтрации контента."

    def export_safebrowing_rules_list(self):
        """Выгрузить список правил веб-безопасности"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '', '']
        data = self.get_safebrowsing_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Общие', 'Блокировать рекламу', 'Исключения блокировки',
            'Инжектор', 'Код инжектора', 'SRC zone/invert', 'Адрес источника/invert', 'Пользователи',
            'Время',
        ]
        for item in data['items']:
            x.add_row(empty_row)

            general = [
                "Записывать в журнал правил: Да" if item['rule_log'] else "Записывать в журнал правил: Нет",
                f"Безопасный поиск:           {item['enable_safe_search']}",
                f"История поиска:             {item['enable_search_history_logging']}",
                f"Блокировать прил.соц.сетей: {item['enable_social_sites_block']}",
            ]

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "Включено" if item['enabled'] else "Выключено",
                "\n".join(general),
                item['enable_adblock'],
                "\n".join(self.list_url[x] for x in item['url_list_exclusions']),
                item['enable_injector'],
                item['custom_injector'],
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                self.get_users_list(item['users']),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет правил Веб-безопасности."

    def export_sslderypt_rules_list(self):
        """Выгрузить список правил Инспектирования SSL"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '']
        data = self.get_ssldecrypt_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Общие', 'Пользователи', 'SRC zone/invert', 'Адрес источника/invert',
            'Адрес назначения/invert', 'Сервисы', 'Категории/invert', 'Домены/invert', 'Время',
        ]
        for item in data['items']:
            x.add_row(empty_row)

            general = [
                "Включено:                   " + ("ДА" if item['enabled'] else "НЕТ"),
                "Действие:                   " + ("Расшифровывать" if item['action'] == 'decrypt' else "Не расшифровывать"),
                f"Профиль SSL: {self.list_ssl_profiles[item['ssl_profile_id']]}" if 'ssl_profile_id' in item.keys() else ''
                "Записывать в журнал правил: Да" if item['rule_log'] else "Записывать в журнал правил: Нет",
                f"Блокировать сайты с некорректным серт.:  {item['block_invalid_certs']}",
                f"Проверять по списку отозванных сертиф.:  {item['block_revoked_certs']}",
                f"Блокировать сертиф. с истёкшим сроком:   {item['block_expired_certs']}",
                f"Блокировать самоподписанные сертификаты: {item['block_selfsigned_certs']}",
            ]

            category = []
            for cat in item['url_categories']:
                if cat[0] == 'list_id':
                    category.append(self.list_urlcategorygroup[cat[1]])
                else:
                    category.append(self._categories[cat[1]])

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(general),
                self.get_users_list(item['users']),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                "\n".join(item['protocols']),
                "\n".join(f'{x} /инверт' if item['url_categories_negate'] else x for x in category),
                "\n".join(f'{self.list_url[x]} /инверт' if item['urls_negate'] else self.list_url[x] for x in item['urls']),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет правил Инспектирования SSL."

    def export_sshderypt_rules_list(self):
        """Выгрузить список правил Инспектирования SSH"""
        if self.version.startswith('6'):
            array = []
            empty_row = ['', '', '', '', '', '', '', '', '', '']
            data = self.get_sshdecrypt_rules_list()
        
            x = PrettyTable()
            x.field_names = [
                'Название', 'Описание', 'Общие', 'Редактировать команду SSH', 'Пользователи', 'SRC zone/invert',
                'Адрес источника/invert', 'Адрес назначения/invert', 'Сервисы', 'Время',
            ]
            for item in data['items']:
                x.add_row(empty_row)

                general = [
                    "Включено:                   " + ("ДА" if item['enabled'] else "НЕТ"),
                    "Действие:                   " + ("Расшифровывать" if item['action'] == 'decrypt' else "Не расшифровывать"),
                    "Записывать в журнал правил: Да" if item['rule_log'] else "Записывать в журнал правил: Нет",
                    f"Блокировать SFTP:           {item['block_ssh_port']}",
                    f"Блокировать удалённый запуск shell:      {item['block_ssh_shell']}",
                    f"Блокировать удалённое выполнение по SSH: {item['block_ssh_exec']}",
                ]

                category = []
                for cat in item['url_categories']:
                    if cat[0] == 'list_id':
                        category.append(self.list_urlcategorygroup[cat[1]])
                    else:
                        category.append(self._categories[cat[1]])

                x.add_row([
                    split_name(item['name']),
                    split_descr(item['description']),
                    "\n".join(general),
                    "\n".join(x for x in item['ssh_commands']),
                    self.get_users_list(item['users']),
                    "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                    "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                    "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                    "\n".join(self.services[x] for x in item['protocols']),
                    "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
                ])

            x.align = "l"
            array.append(x.get_string())
            array.append("\n")
            return data['count'], array if data['count'] else "\tНет правил Инспектирования SSH."
        else:
            return 0, "\tВ версии 5 нет Инспектирования SSH."

    def export_idps_rules_list(self):
        """Выгрузить список правил СОВ"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '']
        action = {
            'log': 'Журналировать',
            'pass': 'Разрешить',
            'drop': 'Запретить',
        }
        data, idps_profiles_list = self.get_idps_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Действие', 'SRC zone/invert', 'Адрес источника/invert',
            'DST zone/invert', 'Адрес назначения/invert', 'Сервис', 'Профили СОВ',
        ]
        for item in data:
            x.add_row(empty_row)
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                action.get(item['action'], 'Error'),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{self.zones[x]} /инверт' if item['dst_zones_negate'] else self.zones[x] for x in item['dst_zones']),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                "\n".join(self.services[x] for x in item['services']),
                "\n".join(idps_profiles_list[x] for x in item['idps_profiles']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет правил СОВ."

    def export_scada_rules_list(self):
        """Выгрузить список правил АСУ ТП"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '']
        action = {
            'pass': 'Пропускать',
            'drop': 'Блокировать',
        }
        data = self.get_scada_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Действие', 'Логировать', 'SRC zone', 'Адрес источника',
            'Адрес назначения', 'Сервис', 'Профили АСУ ТП',
        ]
        for item in data:
            x.add_row(empty_row)
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                action.get(item['action'], 'Error'),
                item['log'],
                "\n".join(self.zones[x] for x in item['src_zones']),
                "\n".join(x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(x for x in self.get_ips_list(item['dst_ips'])),
                "\n".join(self.services[x] for x in item['services']),
                "\n".join(self.list_scada_profiles[x] for x in item['scada_profiles']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return len(data), array if len(data) else "\tНет правил АСУ ТП."

    def export_scenarios_rules_list(self):
        """Выгрузить список Сценариев"""
        array = []
        empty_row = ['', '', '', '', '', '', '']
        data = self.get_scenarios_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Применить для', 'Продолжительность', 'Если выполнится',
            'Условия',
        ]
        for item in data['items']:
            x.add_row(empty_row)

            condition = []
            for cs in item['conditions']:
                if cs['kind'] == 'mime_types':
                    string = "Один из следующих типов контента: " + ", ".join([self.list_mime_groups[x] for x in cs['content_types']])
                    string += f"; max_event_count: {cs['max_event_count']}; count_interval: {cs['count_interval']}"
                    condition.append(string)
                elif cs['kind'] == 'url_category':
                    string = "Категория сайта: " + ", ".join(x for x in self.get_lists_url(cs['url_categories']))
                    string += f"; max_event_count: {cs['max_event_count']}; count_interval: {cs['count_interval']}"
                    condition.append(string)
                elif cs['kind'] == 'sessions_per_ip':
                    condition.append(f"Достигнуто ограничение количества сессий: {cs['sessions_limit']}")
                elif cs['kind'] == 'traffic_limit':
                    condition.append(f"Объём трафика достиг: {cs['traffic_limit']} Байт / {cs['period']}")
                elif cs['kind'] == 'net_packet_size':
                    condition.append(f"Размер пакета превысил: {cs['packet_size']} Байт")
                elif cs['kind'] == 'ips':
                    condition.append(f"Уровни угрозы СОВ: {self.threat_level[cs['ips_tl']]}")
                elif cs['kind'] == 'application':
                    string = "Одно из следующих приложений: " + ", ".join(x for x in self.get_list_apps(cs['apps']))
                    string += f"; max_event_count: {cs['max_event_count']}; count_interval: {cs['count_interval']}"
                    condition.append(string)
                elif cs['kind'] == 'virus_detection':
                    condition.append("Обнаружен вирус")
                if cs['kind'] == 'health_check':
                    gateway = ''
                    if cs['gateway']:
                        gateway = self.routes[cs['gateway'].split(':')[0]] if ":" in cs['gateway'] else self.routes[cs['gateway']]
                    else:
                        gateway = 'По умолчанию'
                    if cs['health_check_method'] == 'ping':
                        string = f"Проверка ping - адрес: {cs['health_check_address']}; шлюз: {gateway}; "
                        string += f"результат: {cs['health_result']}; таймаут подключения: {cs['health_request_timeout']}"
                        string += f"; max_event_count: {cs['max_event_count']}; count_interval: {cs['count_interval']}"
                        condition.append(string)
                    if cs['health_check_method'] == 'dns':
                        string = f"Проверка DNS - адрес: {cs['health_check_address']}; шлюз: {gateway}; "
                        string += f"FQDN запроса: {cs['health_request_address']}; результат: {cs['health_result']}; "
                        string += f"таймаут подключения: {cs['health_request_timeout']}; тип DNS запроса: {cs['health_type_request']}"
                        string += f"; max_event_count: {cs['max_event_count']}; count_interval: {cs['count_interval']}"
                        condition.append(string)
                    if cs['health_check_method'] == 'get':
                        string = f"Проверка HTTP GET - адрес: {cs['health_check_address']}; шлюз: {gateway}; "
                        string += f"результат: {cs['health_result']}; таймаут подключения: {cs['health_request_timeout']}; "
                        string += f"таймаут ответа: {cs['health_answer_timeout']}"
                        string += f"; max_event_count: {cs['max_event_count']}; count_interval: {cs['count_interval']}"
                        condition.append(string)

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['enabled'],
                item['trigger'],
                f"{item['duration']} минут",
                "Любое из условий" if item['op_mode'] == 'or' else "Все условия",
                "\n".join(x for x in condition),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return data['count'], array if data['count'] else "\tНет Сценариев."

    def export_mailsecurity_rules_list(self):
        """Выгрузить список правил Защиты почтового трафика"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '']
        action = {
            'pass': 'Пропустить',
            'mark': 'Маркировать',
            'drop_without_error': 'Блокировать без ошибки',
            'drop_with_error': 'Блокировать с ошибкой',
        }
        data = self.get_mailsecurity_rules_list()

        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'Действие', 'SRC zone', 'Адрес источника',
            'Адрес назначения', 'Пользователи', 'Сервис', 'Envelope from', 'Envelope to',
        ]
        for item in data['items']:
            x.add_row(empty_row)

            general = [
                f"Действие:                     {action.get(item['action'], 'Error')}",
                "Проверка антиспамом UserGate: Да" if item['ct'] else "Проверка антиспамом UserGate: Нет",
                "DNSBL проверка (только SMTP): Да" if item['dnsbl'] else "DNSBL проверка (только SMTP): Нет",
            ]
            services = []
            if not self.version.startswith('6'):
                general.append("Эвристическая проверка:       Да" if item['kav'] else "Эвристическая проверка:       Нет",)
                services.extend(item['protocol']),
            else:
                services.extend(self.services[x] for x in item['services']),

            if item['action'] == 'mark':
                general.extend([
                    f"Заголовок:   {item['mark_hdr']}",
                    f"Маркировка:  {item['mark']}",
                ])

            x.add_row([
                split_name(item['name']),
                split_descr(item['comment']),
                item['enabled'],
                "\n".join(x for x in general),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                self.get_users_list(item['users']),
                "\n".join(x for x in services),
                "\n".join(self.list_emailgroup[x[1]] for x in item['envelope_from']),
                "\n".join(self.list_emailgroup[x[1]] for x in item['envelope_to']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")

        array.append("Настройки антиспама\n")
        y = PrettyTable()
        y.field_names = ['Настройки BATV', 'Серверы DNSBL', 'Белый список DNSBL', 'Чёрный список DNSBL']
        y.add_row(['', '', '', ''])
        y.add_row([
            data['batv']['enabled'],
            "\n".join(x for x in data['dnsbl']['lists']),
            "\n".join(x for x in self.get_ips_list(data['dnsbl']['white_list'])),
            "\n".join(x for x in self.get_ips_list(data['dnsbl']['black_list'])),
        ])
        y.align = "l"
        array.append(y.get_string())
        array.append("\n")

        return data['count'], array if data['count'] else "\tНет правил Защиты почтового трафика."

    def export_icap_rules_list(self):
        """Выгрузить список правил ICAP"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '', '', '', '']
        action = {
            'bypass': 'Пропустить',
            'redirect': 'Переслать',
            'redirect_ignore': 'Переслать и игнорировать',
        }
        total, data = self.get_icap_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Включено', 'ICAP-серверы', 'SRC zone', 'Адрес источника',
            'Адрес назначения', 'Пользователи', 'Типы контента', 'Категории', 'URL', 'HTTP метод', 'Сервисы',
        ]

        for item in data:
            x.add_row(empty_row)
            general = [
                "Включено: ДА" if item['enabled'] else "Включено: НЕТ",
                f"Действие: {action.get(item['action'], 'Error')}",
            ]
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(x for x in general),
                "\n".join(x for x in self.get_library_list(item['servers'])),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                self.get_users_list(item['users']),
                "\n".join(f'{self.list_mime_groups[x]} /инверт' if item['content_types_negate'] else self.list_mime_groups[x]
                                                                                                 for x in item['content_types']),
                "\n".join(f'{x} /инверт' if item['url_categories_negate'] else x for x in self.get_lists_url(item['url_categories'])),
                "\n".join(f'{self.list_url[x]} /инверт' if item['urls_negate'] else self.list_url[x] for x in item['urls']),
                "\n".join(x for x in item['http_methods']),
                "\n".join(x for x in item['protocols']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return total, array if total else "\tНет правил ICAP."

    def export_dos_profiles(self):
        """Выгрузить список Профилей DoS"""
        array = []
        total, data = self.get_dos_profiles_list()

        empty_row = ['', '', '', '', '', '', '']
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Агрегировать', 'Защита от DoS: SYN', 'Защита от DoS: UDP',
            'Защита от DoS: ICMP', 'Защита ресурсов',
        ]
        for item in data:
            self.list_dos_profiles[item['id']] = item['name']
            x.add_row(empty_row)
            dos_syn = []
            dos_udp = []
            dos_icmp = []
            for dos in item['floods']:
                if dos['type'] == 'syn':
                    dos_syn = [
                        "Включено:                   ДА" if dos['enabled'] else "Включено:                   НЕТ",
                        f"Порог уведомления:          {dos['alert']}",
                        f"Порог отбрасывания пакетов: {dos['drop']}",
                    ]
                elif dos['type'] == 'udp':
                    dos_udp = [
                        "Включено:                   ДА" if dos['enabled'] else "Включено:                   НЕТ",
                        f"Порог уведомления:          {dos['alert']}",
                        f"Порог отбрасывания пакетов: {dos['drop']}",
                    ]
                elif dos['type'] == 'icmp':
                    dos_icmp = [
                        "Включено:                   ДА" if dos['enabled'] else "Включено:                   НЕТ",
                        f"Порог уведомления:          {dos['alert']}",
                        f"Порог отбрасывания пакетов: {dos['drop']}",
                    ]


            antispoof = [
                "Включено:                ДА" if item['sessions']['enabled'] else "Включено:                НЕТ",
                f"Ограничить число сессий: {item['sessions']['max_sessions']}",
            ]

            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                item['aggregate'],
                "\n".join(x for x in dos_syn),
                "\n".join(x for x in dos_udp),
                "\n".join(x for x in dos_icmp),
                "\n".join(x for x in antispoof),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return total, array if total else "\tНет Профилей DoS."

    def export_dos_rules_list(self):
        """Выгрузить список правил защиты DoS"""
        array = []
        empty_row = ['', '', '', '', '', '', '', '', '', '']
        action = {
            'protect': 'Защитить',
            'accept': 'Разрешить',
            'drop': 'Запретить',
        }
        total, data = self.get_dos_rules_list()
        
        x = PrettyTable()
        x.field_names = [
            'Название', 'Описание', 'Общие', 'SRC zone', 'Адрес источника',
            'DST zone', 'Адрес назначения', 'Пользователи', 'Сервис', 'Время',
        ]

        for item in data:
            x.add_row(empty_row)
            general = [
                "Включено:       ДА" if item['enabled'] else "Включено:       НЕТ",
                f"Действие:       {action.get(item['action'], 'Error')}",
                f"Профиль DoS:    {self.list_dos_profiles[item['dos_profile']]}",
                f"Сценарий:       {self._scenarios[item['scenario_rule_id']]}",
                "Журналирование: Включено" if item['log'] else "Журналирование: Выключено",
            ]
            x.add_row([
                split_name(item['name']),
                split_descr(item['description']),
                "\n".join(x for x in general),
                "\n".join(f'{self.zones[x]} /инверт' if item['src_zones_negate'] else self.zones[x] for x in item['src_zones']),
                "\n".join(f'{x} /инверт' if item['src_ips_negate'] else x for x in self.get_ips_list(item['src_ips'])),
                "\n".join(f'{self.zones[x]} /инверт' if item['dst_zones_negate'] else self.zones[x] for x in item['dst_zones']),
                "\n".join(f'{x} /инверт' if item['dst_ips_negate'] else x for x in self.get_ips_list(item['dst_ips'])),
                self.get_users_list(item['users']),
                "\n".join(self.services[x] for x in item['services']),
                "\n".join(self.list_calendar[x] for x in item['time_restrictions']),
            ])

        x.align = "l"
        array.append(x.get_string())
        array.append("\n")
        return total, array if total else "\tНет Правил защиты DoS."

    def get_library_list(self, items_list):
        """Получить список из библиотеки"""
        result = []
        for item in items_list:
            if item[0] == 'lbrule':
                result.append(self.list_icap_balancers.get(item[1], 'Error'))
            elif item[0] == 'profile':
                result.append(self.list_icap_servers.get(item[1]))
        return result

    def get_lists_url(self, url_categories):
        """Получить список категорий URL и групп категорий URL"""
        category = []
        for cat in url_categories:
            if cat[0] == 'list_id':
                category.append(self.list_urlcategorygroup.get(cat[1], 'Error'))
            elif cat[0] == 'category_id':
                category.append(self._categories.get(cat[1]))
        return category

    def get_list_apps(self, apps_list):
        """Получить список приложений и категорий приложений"""
        apps = []
        for app in apps_list:
            if app[0] == 'app':
                apps.append(self._l7apps.get(app[1], 'Error'))
            elif app[0] == 'group':
                apps.append(self.list_app_categories.get(app[1], 'Error'))
            elif app[0] == 'ro_group':
                apps.append(self._l7categories.get(app[1], 'Error'))
        return apps

    def get_ips_list(self, ips):
        """ """
        result = []
        for x in ips:
            if x[0] == 'list_id':
                result.append(f'ip_list: {self.list_ip_addresses[x[1]]}')
            elif x[0] == 'ip':
                result.append(f'ip: {x[1]}')
            elif x[0] == 'mac':
                result.append(f'mac: {x[1]}')
            elif x[0] == 'geoip_code':
                result.append(f'geoip: {self._geoip_code[x[1]]}')
            elif x[0] == 'urllist_id':
                result.append(f'url_list: {self.list_url[x[1]]}')
        return result

    def get_users_list(self, users):
        """ """
        result = []
        groups = {v: k for k, v in self._groups.items()}
        for ug_list in users:
            if ug_list[0] == 'user':
                if ug_list[1] in self._users:
                    result.append(f"User: {self._users[ug_list[1]]}")
            elif ug_list[0] == 'special':
                result.append(f"Special: {ug_list[1]}")
            else:
                if ug_list[1] in groups:
                    result.append(f"Group: {groups[ug_list[1]]}")
        return "\n".join(x for x in result)

def split_name(item_name):
    name = item_name.split()
    return ''.join([f'{word}\n' if (i+1)%2 == 0 else f'{word} ' for i, word in enumerate(name)])

def split_descr(item_descr):
    descr = item_descr.split()
    return ''.join([f'{word}\n' if (i+1)%3 == 0 else f'{word} ' for i, word in enumerate(descr)])

def main():
    character_map = {
        ord('\n'): None,
        ord('\r'): None,
        ord('\t'): '_',
        ord('@'): '_',
        ord(' '): '_',
        ord('.'): '_'
    }
    print("\nЭкспорт конфигурации UTM в файл.\n")
    try:
        server_ip = input("Введите IP-адрес UTM: ")
        login = input("Введите логин: ")
        password = stdiomask.getpass("Введите пароль: ")

        utm = UTM(server_ip, login, password)
        file_name = f"config_{server_ip.translate(character_map)}.txt"
        title = f"Конфигурация  узла {utm.node_name}, IP: {server_ip}, Версия: {utm.version}\n"
        separator = "\n" + "="*133 + "\n"
        route_text = 'Сеть: Виртуальные маршрутизаторы' if utm.version.startswith('6') else 'Сеть: Маршруты'
        dict_func = {
            'UserGate: Администраторы UTM': utm.export_admins(),
            'Глобальные опции аутентификации для Администраторов UTM': utm.export_auth_options(),
            'Библиотеки: Морфология': utm.export_morphology_list(),
            'Библиотеки: Список сервисов': utm.export_services_list(),
            'Библиотеки: Списки IP адресов': utm.export_named_list('network', 'IP адреса'),
            'Библиотеки: Useragent браузеров': utm.export_useragent_list(),
            'Библиотеки: Типы контента': utm.export_mime_list(),
            'Библиотеки: Списки URL': utm.export_named_list('url', 'URL'),
            'Библиотеки: Календари': utm.export_time_restricted_list(),
            'Библиотеки: Полосы пропускания': utm.export_shaper_list(),
            'Библиотеки: Профили АСУ ТП': utm.export_scada_profiles_list(),
            'Библиотеки: Шаблоны страниц': utm.export_templates_list(),
            'Библиотеки: Категории URL': utm.export_urlcategory_group_list(),
            'Библиотеки: Список Приложений (пользовательские категории)': utm.export_named_list('applicationgroup', 'Приложение'),
            'Библиотеки: Почтовые адреса': utm.export_emailgroup_list(),
            'Библиотеки: Профили оповещения': utm.export_notification_profiles(),
            'Библиотеки: Профили SSL': utm.export_ssl_profiles(),
            'Сеть: Зоны': utm.export_zones(),
            'Сеть: Интерфейсы': utm.export_interfaces(),
            'Сеть: Шлюзы': utm.export_gateways(),
            'Сеть: Подсети DHCP': utm.export_dhcp_subnets(),
            'Сеть: Настройки DNS': utm.export_dns(),
            'Сеть: Настройки WCCP': utm.export_wccp(),
            route_text: utm.export_routers(),
            'Пользователи и устройства: Локальные группы': utm.export_groups(),
            'Пользователи и устройства: Локальные пользователи': utm.export_users(),
            'Пользователи и устройства: Серверы авторизации': utm.export_auth_servers(),
            'Пользователи и устройства: Профили MFA': utm.export_2fa_profiles(),
            'Пользователи и устройства: Профили авторизации': utm.export_auth_profiles(),
            'Пользователи и устройства: Captive-профили': utm.export_captive_profiles(),
            'Пользователи и устройства: Captive-портал': utm.export_captive_portal(),
            'Пользователи и устройства: Политики BYOD': utm.export_byod_policy(),
            'Политики сети: Межсетевой экран': utm.export_firewall_rules(),
            'Политики сети: NAT и маршрутизация': utm.export_traffic_rules(),
            'Политики безопасности: ICAP-серверы': utm.export_icap_servers_list(),
            'Глобальный портал: Серверы reverse-прокси': utm.export_reverseproxy_servers_list(),
            'Политики сети: Балансировка нагрузки': utm.export_loadbalancing_rules(),
            'Политики сети: Пропускная способность': utm.export_shaper_rules_list(),
            'Политики безопасности: Фильтрация контента': utm.export_content_rules_list(),
            'Политики безопасности: Веб-безопасность': utm.export_safebrowing_rules_list(),
            'Политики безопасности: Инспектирование SSL': utm.export_sslderypt_rules_list(),
            'Политики безопасности: Инспектирование SSH': utm.export_sshderypt_rules_list(),
            'Политики безопасности: СОВ': utm.export_idps_rules_list(),
            'Политики безопасности: Правила АСУ ТП': utm.export_scada_rules_list(),
            'Политики безопасности: Сценарии': utm.export_scenarios_rules_list(),
            'Политики безопасности: Защита почтового трафика': utm.export_mailsecurity_rules_list(),
            'Политики безопасности: ICAP-правила': utm.export_icap_rules_list(),
            'Политики безопасности: Профили DoS': utm.export_dos_profiles(),
            'Политики безопасности: Правила защиты DoS': utm.export_dos_rules_list(),
        }
        list_config = open(file_name, 'w')
        try:
            list_config.write(title)
            list_config.write(separator)
 
            list_config.write(f"\nНастройка времени сервера\n")
            list_config.write(utm.export_ntp())
            list_config.write(separator)

            for text, func in dict_func.items():
                total, data = func
                if total:
                    list_config.write(f"\n{text} ({total}):\n")
                else:
                    list_config.write(f"\n{text}:\n")
                for string in data:
                    list_config.write(string)
                list_config.write(separator)

        except UtmError as err:
            print(err)
        except Exception as err:
            print(f'\nОшибка: {err} (Node: {server_ip}).')
        else:
            print("\nОтчёт сформирован в файле", f"config_{server_ip.translate(character_map)}.txt\n")
        finally:
            utm.logout()
            list_config.close()
    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")

if __name__ == '__main__':
    main()
