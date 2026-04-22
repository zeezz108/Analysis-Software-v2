"""
Модуль конфигурации типов узлов

Содержит словарь NODE_CONFIG с настройками для каждого типа узла:
- Какие вкладки показывать (hardware, software, peripheral)
- Какие методы БД использовать для заполнения
- Какие порты создавать по умолчанию
- Возможности Wi-Fi
"""

# ============================================================================
# Общие блоки вкладок (переиспользуются между типами узлов)
# ============================================================================

# --- Процессоры (десктопный порядок: Core i9 -> Atom) ---
_PROCESSORS_DESKTOP = {
    "title": "Процессоры", "method": "get_processors", "var_name": "processor",
    "cpe_filter": {"part": "h", "vendors": ["intel", "amd"],
                   "families": {
                       "intel": [
                           ("Core i9", "core_i9"),
                           ("Core i7", "core_i7"),
                           ("Core i5", "core_i5"),
                           ("Core i3", "core_i3"),
                           ("Core 2 Duo", "core_2_duo"),
                           ("Core 2 Quad", "core_2_quad"),
                           ("Xeon", "xeon"),
                           ("Pentium", "pentium"),
                           ("Celeron", "celeron"),
                           ("Atom", "atom"),
                       ],
                       "amd": [
                           ("Ryzen 9", "ryzen_9"),
                           ("Ryzen 7", "ryzen_7"),
                           ("Ryzen 5", "ryzen_5"),
                           ("Ryzen 3", "ryzen_3"),
                           ("Threadripper", "threadripper"),
                           ("EPYC", "epyc"),
                           ("Athlon", "athlon"),
                           ("FX", "fx-"),
                           ("Phenom", "phenom"),
                           ("Sempron", "sempron"),
                       ],
                   }},
    "prefix": "Процессор"}

# --- Процессоры (серверный порядок: Xeon/EPYC первыми) ---
_PROCESSORS_SERVER = {
    "title": "Процессоры", "method": "get_processors", "var_name": "server_cpu",
    "cpe_filter": {"part": "h", "vendors": ["intel", "amd"],
                   "families": {
                       "intel": [
                           ("Xeon", "xeon"),
                           ("Core i9", "core_i9"),
                           ("Core i7", "core_i7"),
                           ("Core i5", "core_i5"),
                           ("Core i3", "core_i3"),
                           ("Core 2 Duo", "core_2_duo"),
                           ("Core 2 Quad", "core_2_quad"),
                           ("Pentium", "pentium"),
                           ("Celeron", "celeron"),
                           ("Atom", "atom"),
                       ],
                       "amd": [
                           ("EPYC", "epyc"),
                           ("Ryzen 9", "ryzen_9"),
                           ("Ryzen 7", "ryzen_7"),
                           ("Ryzen 5", "ryzen_5"),
                           ("Ryzen 3", "ryzen_3"),
                           ("Threadripper", "threadripper"),
                           ("Athlon", "athlon"),
                           ("FX", "fx-"),
                           ("Phenom", "phenom"),
                           ("Sempron", "sempron"),
                       ],
                   }},
    "prefix": "Процессор"}

# --- Видеоконтроллеры ---
_GPU_TAB = {
    "title": "Видеоконтроллеры", "method": "get_graphics_cards", "var_name": "gpu",
    "cpe_filter": {"part": "h", "vendors": ["nvidia", "amd", "intel"],
                   "families": {
                       "nvidia": [
                           ("GeForce", "geforce"),
                           ("Quadro", "quadro"),
                           ("Tesla", "tesla"),
                           ("DGX", "dgx"),
                           ("Jetson", "jetson"),
                       ],
                       "amd": [
                           ("Radeon", "radeon"),
                           ("Instinct", "instinct"),
                       ],
                       "intel": [
                           ("Arc", "arc_a"),
                           ("Iris", "iris"),
                           ("UHD Graphics", "uhd_graphics"),
                           ("HD Graphics", "hd_graphics"),
                       ],
                   }},
    "prefix": "Видеоконтроллер"}

# --- Материнские платы ---
_MOTHERBOARD_TAB = {
    "title": "Материнские платы", "method": "get_motherboards", "var_name": "motherboard",
    "cpe_filter": {"part": "h", "vendors": ["asus", "supermicro", "gigabyte"],
                   "families": {
                       "asus": [
                           ("ROG", "rog"),
                           ("TUF", "tuf"),
                           ("Prime", "prime"),
                           ("B150-B760", "b"),
                           ("X370-X670", "x"),
                           ("Z170-Z790", "z"),
                       ],
                       "supermicro": [
                           ("A-серия", "a"),
                           ("H-серия", "h"),
                           ("X10", "x10"),
                           ("X11", "x11"),
                           ("X12", "x12"),
                           ("X13", "x13"),
                       ],
                   }},
    "prefix": "Материнская плата"}

# --- Накопители данных (HDD/SSD) ---
_STORAGE_CPE_FILTER = {
    "part": "h",
    "vendors": ["samsung", "intel", "crucial", "micron",
                "western_digital", "seagate", "toshiba"],
    "families": {
        "intel": [
            ("Optane SSD", "optane_ssd"),
            ("SSD Pro", "ssd_pro"),
            ("SSD DC", "ssd_dc"),
            ("SSD D-серия", "ssd_d"),
            ("SSD Consumer", "ssd_"),
        ],
        "western_digital": [
            ("My Cloud NAS", "my_cloud"),
        ],
        "seagate": [
            ("BlackArmor NAS", "blackarmor"),
            ("HDD (ST-серия)", "st"),
        ],
    },
    "product_like": ["ssd", "optane_ssd", "840_evo", "850_evo", "850_pro",
                     "crucial_mx", "my_cloud", "blackarmor", "st500",
                     "hd-ma", "hd-mb", "hd-sa", "hd-sb", "stcg"],
    "product_not_like": ["usb", "flash", "datatraveler", "cruzer",
                         "galaxy", "chromebook", "watch", "phone",
                         "tablet", "laptop", "notebook", "ethernet",
                         "driver", "wireless", "wifi", "bluetooth",
                         "exynos", "printer", "clp-", "clx-", "dvr",
                         "data_management", "d6000", "charm", "ddr",
                         "apq", "goflex", "personal_cloud", "business_nas",
                         "face_recognition", "atom", "celeron", "core",
                         "nuc", "server_board", "server_system",
                         "compute_module", "tiger_lake", "x722",
                         "field_programmable", "eth_converged",
                         "ethernet_converged", "ethernet_controller",
                         "ethernet_network", "lapkc", "m10jnp"]}

_STORAGE_TAB = {
    "title": "Накопители данных", "method": "get_storage_devices", "var_name": "hdd",
    "cpe_filter": _STORAGE_CPE_FILTER,
    "prefix": "HDD/SSD"}

# --- Сетевые адаптеры ---
_NETWORK_ADAPTER_TAB = {
    "title": "Сетевые адаптеры", "method": "get_network_cards", "var_name": "network_adapter",
    "cpe_filter": {"part": "h", "vendors": ["intel", "broadcom", "realtek", "qualcomm"],
                   "families": {
                       "intel": [
                           ("Ethernet", "ethernet"),
                           ("Wi-Fi 6/6E", "wi-fi_6"),
                           ("Wi-Fi 5/AC", "wireless-ac"),
                           ("Centrino", "centrino"),
                           ("Killer", "killer"),
                       ],
                   },
                   "product_not_like": ["ssd", "optane", "core", "xeon", "atom",
                                        "celeron", "pentium", "nuc", "server",
                                        "fpga", "arc_a", "iris", "uhd",
                                        "hd_graphics", "compute_module"]},
    "prefix": "Сетевой адаптер"}

# --- Набор микросхем (чипсет) ---
_CHIPSET_TAB = {
    "title": "Набор микросхем", "method": "get_processors", "var_name": "chipset",
    "cpe_filter": {"part": "h", "vendors": ["intel"],
                   "product_like": ["chipset", "pch", "100_series", "200_series",
                                    "300_series", "400_series", "500_series",
                                    "600_series", "700_series"]},
    "prefix": "Чипсет"}

# --- Клиентские ОС ---
_CLIENT_OS_TAB = {
    "title": "Операционные системы", "method": "get_client_operating_systems", "var_name": "os",
    "cpe_filter": {"part": "o", "vendors": ["microsoft", "canonical", "redhat", "fedoraproject",
                                             "debian", "apple", "opensuse", "suse", "linux"],
                   "families": {
                       "microsoft": [
                           ("Windows 11", "windows_11"),
                           ("Windows 10", "windows_10"),
                           ("Windows 8.1", "windows_8"),
                           ("Windows 7", "windows_7"),
                           ("Windows Vista", "windows_vista"),
                           ("Windows XP", "windows_xp"),
                       ],
                       "canonical": [
                           ("Ubuntu", "ubuntu"),
                       ],
                       "redhat": [
                           ("Enterprise Linux", "enterprise_linux"),
                       ],
                       "apple": [
                           ("macOS", "macos"),
                           ("Mac OS X", "mac_os"),
                       ],
                       "opensuse": [
                           ("Leap", "leap"),
                           ("Tumbleweed", "tumbleweed"),
                       ],
                       "debian": [
                           ("Debian Linux", "debian_linux"),
                       ],
                       "fedoraproject": [
                           ("Fedora", "fedora"),
                       ],
                   },
                   "product_not_like": ["server", "azure", "surface", "xbox", "phone",
                                        "mobile", "rt", "storsimple", "embedded", "iot",
                                        "wireless_display", "office", "sql", "devops",
                                        "hci", "copilot", "365"]},
    "prefix": "ОС"}

# --- Средства защиты информации ---
_SECURITY_SOFTWARE_TAB = {
    "title": "Средства защиты информации", "method": "get_application_software",
    "var_name": "security_software",
    "cpe_filter": {"part": "a",
                   "vendors": ["kaspersky", "drweb", "symantec", "mcafee", "trendmicro",
                               "eset", "avast", "avg", "bitdefender", "f-secure",
                               "comodo", "avira", "panda"],
                   "product_like": ["anti-virus", "antivirus", "anti-malware", "antimalware",
                                    "endpoint_security", "internet_security", "total_security",
                                    "security_space", "client_security", "cyber_security",
                                    "endpoint_antivirus", "endpoint_protection"]},
    "prefix": "СЗИ"}

# --- Прикладное ПО (включая офисное) ---
_APP_SOFTWARE_TAB = {
    "title": "Прикладное ПО", "method": "get_application_software", "var_name": "app_software",
    "cpe_filter": {"part": "a",
                   "vendors": [
                       # Офисное/продуктивность
                       "microsoft", "libreoffice", "adobe",
                       # Утилиты
                       "videolan", "7-zip", "wireshark", "putty", "filezilla",
                       "notepad-plus-plus", "gimp", "mozilla",
                       # Серверное/инфраструктурное
                       "oracle", "ibm", "apache", "sap", "vmware", "redhat",
                       "dell", "hp", "netapp", "broadcom", "hitachi",
                       # Языки/рантаймы
                       "python", "nodejs", "php", "perl", "ruby-lang", "rust-lang", "gnu",
                       # БД/поиск
                       "postgresql", "mariadb", "mongodb", "redis", "elastic",
                       # Контейнеры/облако
                       "docker", "kubernetes", "nginx", "lighttpd",
                   ],
                   "families": {
                       "microsoft": [
                           ("Microsoft Office", "office"),
                           ("Word", "word"),
                           ("Excel", "excel"),
                           ("PowerPoint", "powerpoint"),
                           ("Outlook", "outlook"),
                           ("365 Apps", "365"),
                           (".NET Framework", ".net"),
                           ("Visual Studio", "visual_studio"),
                           ("SQL Server", "sql_server"),
                           ("Exchange", "exchange"),
                           ("SharePoint", "sharepoint"),
                       ],
                       "adobe": [
                           ("Acrobat/Reader", "acrobat"),
                           ("Photoshop", "photoshop"),
                           ("Illustrator", "illustrator"),
                           ("After Effects", "after_effects"),
                           ("Premiere", "premiere"),
                           ("InDesign", "indesign"),
                           ("Flash/Animate", "flash"),
                           ("Creative Cloud", "creative_cloud"),
                       ],
                       "oracle": [
                           ("Oracle Database", "database"),
                           ("MySQL", "mysql"),
                           ("Java", "jdk"),
                           ("WebLogic", "weblogic"),
                       ],
                       "apache": [
                           ("HTTP Server", "http_server"),
                           ("Tomcat", "tomcat"),
                           ("ActiveMQ", "activemq"),
                           ("Kafka", "kafka"),
                           ("Hadoop", "hadoop"),
                           ("Spark", "spark"),
                       ],
                   },
                   "product_not_like": [
                       # Мобильное — не нужно для АРМ/серверов
                       "android", "mobile", "phone", "ios_", "ipad", "iphone",
                       "galaxy", "tizen", "watch", "wearable", "airwatch",
                       "bixby", "samsung_", "ar_emoji", "smart_switch",
                       # Драйверы/прошивки
                       "firmware", "bios",
                       # Облачное специфичное
                       "azure_vm", "surface_",
                   ]},
    "prefix": "Приложение", "multiple": True}

# --- Веб-браузеры ---
_BROWSER_TAB = {
    "title": "Веб-браузеры", "method": "get_application_software", "var_name": "browser",
    "cpe_filter": {"part": "a",
                   "vendors": ["google", "mozilla", "apple", "microsoft", "opera"],
                   "product_like": ["chrome", "firefox", "safari", "edge", "opera"],
                   "product_not_like": ["driver", "extension", "launcher", "plugin",
                                        "frame", "readiness", "update", "connector",
                                        "ios", "mobile", "focus", "esr", "mail",
                                        "touch", "mini"]},
    "prefix": "Браузер"}

# --- СУБД ---
_DATABASE_TAB = {
    "title": "СУБД", "method": "get_application_software", "var_name": "database_software",
    "cpe_filter": {"part": "a",
                   "vendors": ["oracle", "microsoft", "postgresql", "mariadb", "mongodb",
                               "redis", "apache", "elastic", "mysql"],
                   "product_like": ["mysql", "postgresql", "sql_server", "mariadb",
                                    "mongodb", "redis", "oracle_database", "database",
                                    "couchdb", "elasticsearch", "sqlite"],
                   "product_not_like": ["jdbc", "odbc", "ole_db", "enterprise_manager",
                                        "cluster", "router", "workbench", "shell",
                                        "connector", "utilities"]},
    "prefix": "СУБД"}

# --- Серверные ОС ---
_SERVER_OS_TAB = {
    "title": "Серверные операционные системы", "method": "get_server_operating_systems",
    "var_name": "server_os",
    "cpe_filter": {"part": "o",
                   "vendors": ["microsoft", "canonical", "redhat", "suse", "debian",
                               "centos", "oracle"],
                   "families": {
                       "microsoft": [
                           ("Windows Server 2025", "windows_server_2025"),
                           ("Windows Server 2022", "windows_server_2022"),
                           ("Windows Server 2019", "windows_server_2019"),
                           ("Windows Server 2016", "windows_server_2016"),
                           ("Windows Server 2012", "windows_server_2012"),
                           ("Windows Server 2008", "windows_server_2008"),
                       ],
                       "canonical": [
                           ("Ubuntu", "ubuntu"),
                       ],
                       "redhat": [
                           ("Enterprise Linux", "enterprise_linux"),
                       ],
                       "suse": [
                           ("SLES", "linux_enterprise_server"),
                           ("openSUSE", "opensuse"),
                       ],
                       "centos": [
                           ("CentOS", "centos"),
                       ],
                   }},
    "prefix": "ОС сервера"}

# --- Периферийные устройства (мыши, клавиатуры, принтеры, мониторы) ---
_PERIPHERAL_TABS = [
    {"title": "Мыши", "method": "get_mice", "var_name": "mouse"},
    {"title": "Клавиатуры", "method": "get_keyboards", "var_name": "keyboard"},
    {"title": "Принтеры", "method": "get_printers", "var_name": "printer"},
    {"title": "Мониторы", "method": "get_monitors", "var_name": "monitor"},
]

# --- Периферийные устройства для сервера (другие var_name) ---
_SERVER_PERIPHERAL_TABS = [
    {"title": "Мыши", "method": "get_mice", "var_name": "server_mouse"},
    {"title": "Клавиатуры", "method": "get_keyboards", "var_name": "server_keyboard"},
    {"title": "Принтеры", "method": "get_printers", "var_name": "server_printer"},
    {"title": "Мониторы", "method": "get_monitors", "var_name": "server_monitor"},
]

# --- Драйверы ---
_DRIVER_TABS = [
    {"title": "Драйверы видеоконтроллеров", "method": "get_gpu_drivers_by_vendor",
     "var_name": "gpu_driver"},
]

# ============================================================================
# Основная конфигурация NODE_CONFIG
# ============================================================================

NODE_CONFIG = {
    # ==================================================================
    # АРМ (Автоматизированное рабочее место)
    # ==================================================================
    "ARM": {
        "name": "АРМ",
        "hardware_tabs": [
            _PROCESSORS_DESKTOP,
            _GPU_TAB,
            _MOTHERBOARD_TAB,
            _STORAGE_TAB,
            _NETWORK_ADAPTER_TAB,

        ],
        "driver_tabs": _DRIVER_TABS,
        "software_tabs": [
            _CLIENT_OS_TAB,
            {"title": "Программное обеспечение", "method": "get_application_software",
             "var_name": "app_software",
             "cpe_filter": _APP_SOFTWARE_TAB.get("cpe_filter", {}),
             "prefix": "Приложение", "multiple": True,
             "software_categories": [
                 {"name": "Прикладное ПО", "filter": _APP_SOFTWARE_TAB.get("cpe_filter", {})},
                 {"name": "Средства защиты информации", "filter": _SECURITY_SOFTWARE_TAB.get("cpe_filter", {})},
                 {"name": "Веб-браузеры", "filter": _BROWSER_TAB.get("cpe_filter", {})},
                 {"name": "СУБД", "filter": _DATABASE_TAB.get("cpe_filter", {})},
             ]},
        ],
        "peripheral_tabs": _PERIPHERAL_TABS,
        "zone_type": "tim",
        "default_ports": {
            "ethernet": 1,
            "pon": 0,
            "wifi": 1,
            "usb": 4
        },
        "wifi_capabilities": {
            "can_be_ap": True,
            "can_be_client": True
        }
    },

    # ==================================================================
    # Ноутбук
    # ==================================================================
    "Laptop": {
        "name": "Ноутбук",
        "hardware_tabs": [
            _PROCESSORS_DESKTOP,
            _GPU_TAB,
            _MOTHERBOARD_TAB,
            _STORAGE_TAB,
            _NETWORK_ADAPTER_TAB,

        ],
        "driver_tabs": _DRIVER_TABS,
        "software_tabs": [
            _CLIENT_OS_TAB,
            {"title": "Программное обеспечение", "method": "get_application_software",
             "var_name": "app_software",
             "cpe_filter": _APP_SOFTWARE_TAB.get("cpe_filter", {}),
             "prefix": "Приложение", "multiple": True,
             "software_categories": [
                 {"name": "Прикладное ПО", "filter": _APP_SOFTWARE_TAB.get("cpe_filter", {})},
                 {"name": "Средства защиты информации", "filter": _SECURITY_SOFTWARE_TAB.get("cpe_filter", {})},
                 {"name": "Веб-браузеры", "filter": _BROWSER_TAB.get("cpe_filter", {})},
                 {"name": "СУБД", "filter": _DATABASE_TAB.get("cpe_filter", {})},
             ]},
        ],
        "peripheral_tabs": _PERIPHERAL_TABS,
        "zone_type": "tim",
        "default_ports": {
            "ethernet": 1,
            "pon": 0,
            "wifi": 1,
            "usb": 3
        },
        "wifi_capabilities": {
            "can_be_ap": True,
            "can_be_client": True
        }
    },

    # ==================================================================
    # Маршрутизатор
    # ==================================================================
    "Router": {
        "name": "Маршрутизатор",
        "hardware_tabs": [
            {"title": "Аппаратные платформы", "method": "get_router_hardware",
             "var_name": "router_platform",
             "cpe_filter": {"part": "h",
                            "vendors": ["cisco", "juniper", "huawei", "mikrotik",
                                        "tp-link", "dlink", "zyxel", "netgear"],
                            "families": {
                                "cisco": [
                                    ("ISR", "integrated_services_router"),
                                    ("ASR", "asr"),
                                    ("Catalyst", "catalyst"),
                                    ("Meraki", "meraki"),
                                ],
                                "juniper": [
                                    ("SRX", "srx"),
                                    ("MX", "mx"),
                                    ("ACX", "acx"),
                                ],
                                "huawei": [
                                    ("AR-серия", "ar"),
                                    ("NE-серия", "ne"),
                                ],
                                "mikrotik": [
                                    ("CCR", "ccr"),
                                    ("RB", "rb"),
                                    ("CRS", "crs"),
                                    ("hAP", "hap"),
                                ],
                                "tp-link": [
                                    ("Archer", "archer"),
                                ],
                            }},
             "prefix": "Платформа"},
        ],
        "software_tabs": [
            {"title": "Cisco IOS/IOS-XE", "method": "get_cisco_ios", "var_name": "cisco_ios",
             "cpe_filter": {"part": "o", "vendors": ["cisco"],
                            "product_like": ["ios"]},
             "prefix": "Cisco IOS"},
            {"title": "Juniper JunOS", "method": "get_junos", "var_name": "junos",
             "cpe_filter": {"part": "o", "vendors": ["juniper"],
                            "product_like": ["junos"]},
             "prefix": "JunOS"},
            {"title": "Huawei VRP", "method": "get_huawei_versions", "var_name": "huawei",
             "cpe_filter": {"part": "o", "vendors": ["huawei"]},
             "prefix": "Huawei VRP"},
            {"title": "Другие ОС маршрутизаторов", "method": "get_other_router_os",
             "var_name": "other_router_os",
             "cpe_filter": {"part": "o",
                            "vendors": ["mikrotik", "dlink", "tp-link", "zyxel", "netgear"]},
             "prefix": "ОС маршрутизатора"},
        ],
        "zone_type": "tim",
        "default_ports": {
            "ethernet": 4,
            "pon": 1,
            "wifi": 1,
            "usb": 2
        },
        "wifi_capabilities": {
            "can_be_ap": True,
            "can_be_client": True
        }
    },

    # ==================================================================
    # Коммутатор
    # ==================================================================
    "Switch": {
        "name": "Коммутатор",
        "hardware_tabs": [
            {"title": "Аппаратные платформы", "method": "get_switch_hardware",
             "var_name": "switch_platform",
             "cpe_filter": {"part": "h",
                            "vendors": ["cisco", "juniper", "huawei", "hp", "aruba",
                                        "dlink", "netgear"],
                            "families": {
                                "cisco": [
                                    ("Catalyst", "catalyst"),
                                    ("Nexus", "nexus"),
                                    ("Meraki", "meraki"),
                                    ("Smart Switch", "smart_switch"),
                                    ("Managed Switch", "managed_switch"),
                                ],
                                "juniper": [
                                    ("EX", "ex"),
                                    ("QFX", "qfx"),
                                ],
                            }},
             "prefix": "Платформа"},
        ],
        "software_tabs": [
            {"title": "Cisco Switch IOS", "method": "get_cisco_switch_os",
             "var_name": "cisco_switch_os",
             "cpe_filter": {"part": "o", "vendors": ["cisco"]},
             "prefix": "Cisco IOS"},
            {"title": "Управляемые коммутаторы", "method": "get_managed_switch_os",
             "var_name": "managed_switch_os",
             "cpe_filter": {"part": "o", "vendors": ["juniper", "huawei", "hp", "aruba"]},
             "prefix": "ОС коммутатора"},
            {"title": "Неуправляемые коммутаторы", "method": "get_unmanaged_switch_os",
             "var_name": "unmanaged_switch_os",
             "cpe_filter": {"part": "o",
                            "vendors": ["dlink", "netgear", "tp-link", "tenda", "mercusys"],
                            "families": {
                                "dlink": [
                                    ("DGS коммутаторы", "dgs"),
                                    ("DES коммутаторы", "des"),
                                ],
                                "netgear": [
                                    ("GS коммутаторы", "gs"),
                                    ("FS коммутаторы", "fs"),
                                ],
                            }},
             "prefix": "Коммутатор"},
        ],
        "zone_type": "tim",
        "default_ports": {
            "ethernet": 8,
            "pon": 0,
            "wifi": 0,
            "usb": 1
        },
        "wifi_capabilities": {
            "can_be_ap": False,
            "can_be_client": False
        }
    },

    # ==================================================================
    # Сервер
    # ==================================================================
    "Server": {
        "name": "Сервер",
        "hardware_tabs": [
            _PROCESSORS_SERVER,
            {"title": "Накопители данных", "method": "get_storage_devices",
             "var_name": "server_storage",
             "cpe_filter": _STORAGE_CPE_FILTER,
             "prefix": "HDD/SSD"},
            {"title": "Сетевые адаптеры", "method": "get_network_cards",
             "var_name": "server_nic",
             "cpe_filter": {"part": "h", "vendors": ["intel", "broadcom", "realtek", "qualcomm"],
                            "families": {
                                "intel": [
                                    ("Ethernet", "ethernet"),
                                    ("Wi-Fi 6/6E", "wi-fi_6"),
                                    ("Wi-Fi 5/AC", "wireless-ac"),
                                    ("Centrino", "centrino"),
                                    ("Killer", "killer"),
                                ],
                            },
                            "product_not_like": ["ssd", "optane", "core", "xeon", "atom",
                                                 "celeron", "pentium", "nuc", "server",
                                                 "fpga", "arc_a", "iris", "uhd",
                                                 "hd_graphics", "compute_module"]},
             "prefix": "Сетевой адаптер"},
            {"title": "Серверные платформы", "method": "get_processors",
             "var_name": "server_platform",
             "cpe_filter": {"part": "h",
                            "vendors": ["intel", "supermicro", "dell", "hp", "hpe", "lenovo"],
                            "families": {
                                "intel": [
                                    ("Server Board", "server_board"),
                                    ("Server System", "server_system"),
                                    ("Compute Module", "compute_module"),
                                ],
                                "supermicro": [
                                    ("A-серия", "a"),
                                    ("H-серия", "h"),
                                    ("X10", "x10"),
                                    ("X11", "x11"),
                                    ("X12", "x12"),
                                    ("X13", "x13"),
                                ],
                            },
                            "product_like": ["server", "compute_module", "poweredge",
                                             "proliant", "thinksystem"]},
             "prefix": "Серверная платформа"},
        ],
        "software_tabs": [
            _SERVER_OS_TAB,
            {"title": "Серверное ПО", "method": "get_application_software",
             "var_name": "server_app",
             "cpe_filter": {"part": "a"},
             "prefix": "Приложение", "multiple": True},
            _DATABASE_TAB,
            {"title": "Веб-серверы", "method": "get_application_software",
             "var_name": "web_server",
             "cpe_filter": {"part": "a",
                            "vendors": ["apache", "nginx", "lighttpd", "microsoft"],
                            "product_like": ["http_server", "nginx", "lighttpd", "iis"]},
             "prefix": "Веб-сервер"},
            _SECURITY_SOFTWARE_TAB,
        ],
        "peripheral_tabs": _SERVER_PERIPHERAL_TABS,
        "zone_type": "tim",
        "default_ports": {
            "ethernet": 4,
            "pon": 0,
            "wifi": 0,
            "usb": 4
        },
        "wifi_capabilities": {
            "can_be_ap": False,
            "can_be_client": True
        }
    },

    # ==================================================================
    # Сервер виртуализации
    # ==================================================================
    "VirtualizationServer": {
        "name": "Сервер виртуализации",
        "hardware_tabs": [
            {"title": "Процессоры", "method": "get_processors", "var_name": "server_cpus",
             "multiple": True,
             "cpe_filter": {"part": "h", "vendors": ["intel", "amd"],
                            "families": {
                                "intel": [
                                    ("Xeon", "xeon"),
                                    ("Core i9", "core_i9"),
                                    ("Core i7", "core_i7"),
                                    ("Core i5", "core_i5"),
                                    ("Core i3", "core_i3"),
                                    ("Core 2 Duo", "core_2_duo"),
                                    ("Core 2 Quad", "core_2_quad"),
                                    ("Pentium", "pentium"),
                                    ("Celeron", "celeron"),
                                    ("Atom", "atom"),
                                ],
                                "amd": [
                                    ("EPYC", "epyc"),
                                    ("Ryzen 9", "ryzen_9"),
                                    ("Ryzen 7", "ryzen_7"),
                                    ("Ryzen 5", "ryzen_5"),
                                    ("Ryzen 3", "ryzen_3"),
                                    ("Threadripper", "threadripper"),
                                    ("Athlon", "athlon"),
                                    ("FX", "fx-"),
                                    ("Phenom", "phenom"),
                                    ("Sempron", "sempron"),
                                ],
                            }},
             "prefix": "Процессор"},
            {"title": "Оперативная память", "method": "get_ram_options",
             "var_name": "server_ram",
             "cpe_filter": {"part": "h",
                            "vendors": ["samsung", "micron", "kingston", "corsair",
                                        "g.skill", "sk_hynix"],
                            "product_like": ["ddr4", "ddr5", "ddr3", "sdram", "dimm",
                                             "memory", "lpddr"]},
             "prefix": "ОЗУ"},
            {"title": "Диски/Хранилище", "method": "get_server_storage",
             "var_name": "server_storage", "multiple": True,
             "cpe_filter": _STORAGE_CPE_FILTER,
             "prefix": "HDD/SSD"},
            {"title": "Сетевые карты", "method": "get_network_cards",
             "var_name": "server_nics", "multiple": True,
             "cpe_filter": {"part": "h",
                            "vendors": ["intel", "broadcom", "realtek", "qualcomm"],
                            "families": {
                                "intel": [
                                    ("Ethernet", "ethernet"),
                                    ("Wi-Fi 6/6E", "wi-fi_6"),
                                    ("Wi-Fi 5/AC", "wireless-ac"),
                                    ("Centrino", "centrino"),
                                    ("Killer", "killer"),
                                ],
                            },
                            "product_not_like": ["ssd", "optane", "core", "xeon", "atom",
                                                 "celeron", "pentium", "nuc", "server",
                                                 "fpga", "arc_a", "iris", "uhd",
                                                 "hd_graphics", "compute_module"]},
             "prefix": "Сетевая карта"},
        ],
        "hypervisor_tabs": [
            {"title": "VMware vSphere/ESXi", "method": "get_vmware_versions",
             "var_name": "vmware",
             "cpe_filter": {"part": "a", "vendors": ["vmware"],
                            "product_like": ["esxi", "vsphere", "vcenter", "vcloud", "nsx"]},
             "prefix": "VMware"},
            {"title": "Microsoft Hyper-V", "method": "get_hyperv_versions",
             "var_name": "hyperv",
             "cpe_filter": {"part": "a", "vendors": ["microsoft"],
                            "product_like": ["hyper-v", "hypervisor"]},
             "prefix": "Hyper-V"},
            {"title": "Proxmox VE", "method": "get_proxmox_versions", "var_name": "proxmox",
             "cpe_filter": {"part": "a", "vendors": ["proxmox"]},
             "prefix": "Proxmox"},
            {"title": "KVM/QEMU", "method": "get_kvm_versions", "var_name": "kvm",
             "cpe_filter": {"part": "a",
                            "vendors": ["qemu", "redhat", "kvm_qumranet", "libvirt", "kvm_group"],
                            "families": {
                                "qemu": [("QEMU", "qemu")],
                                "redhat": [("KVM", "kvm"), ("libvirt", "libvirt")],
                                "libvirt": [("libvirt", "libvirt")],
                            }},
             "prefix": "KVM"},
            {"title": "Citrix Hypervisor", "method": "get_citrix_versions",
             "var_name": "citrix",
             "cpe_filter": {"part": "a", "vendors": ["citrix"],
                            "product_like": ["hypervisor", "xenserver", "xen"]},
             "prefix": "Citrix"},
        ],
        "host_os_tabs": [
            {"title": "Операционная система хоста", "method": "get_server_operating_systems",
             "var_name": "host_os",
             "cpe_filter": {"part": "o",
                            "vendors": ["microsoft", "canonical", "redhat", "suse",
                                        "debian", "centos", "oracle"],
                            "families": {
                                "microsoft": [
                                    ("Windows Server 2025", "windows_server_2025"),
                                    ("Windows Server 2022", "windows_server_2022"),
                                    ("Windows Server 2019", "windows_server_2019"),
                                    ("Windows Server 2016", "windows_server_2016"),
                                    ("Windows Server 2012", "windows_server_2012"),
                                    ("Windows Server 2008", "windows_server_2008"),
                                ],
                                "canonical": [
                                    ("Ubuntu", "ubuntu"),
                                ],
                                "redhat": [
                                    ("Enterprise Linux", "enterprise_linux"),
                                ],
                                "suse": [
                                    ("SLES", "linux_enterprise_server"),
                                    ("openSUSE", "opensuse"),
                                ],
                                "centos": [
                                    ("CentOS", "centos"),
                                ],
                            }},
             "prefix": "ОС хоста"},
        ],
        "containerizer_tabs": [
            {"title": "Средства контейнеризации", "method": "get_containerizers",
             "var_name": "containerizer",
             "cpe_filter": {"part": "a",
                            "vendors": ["docker", "kubernetes", "linuxfoundation", "redhat"],
                            "product_like": ["docker", "kubernetes", "podman",
                                             "containerd", "cri-o"]},
             "prefix": "Контейнеризатор"},
        ],
        "guest_os_tabs": [
            {"title": "Гостевые ОС", "method": "get_guest_os_list", "var_name": "guest_os",
             "multiple": True,
             "cpe_filter": {"part": "o",
                            "vendors": ["microsoft", "canonical", "redhat", "fedoraproject",
                                        "debian", "apple", "opensuse", "centos", "linux",
                                        "suse", "oracle"],
                            "families": {
                                "microsoft": [
                                    ("Windows Server 2025", "windows_server_2025"),
                                    ("Windows Server 2022", "windows_server_2022"),
                                    ("Windows Server 2019", "windows_server_2019"),
                                    ("Windows Server 2016", "windows_server_2016"),
                                    ("Windows Server 2012", "windows_server_2012"),
                                    ("Windows Server 2008", "windows_server_2008"),
                                    ("Windows 11", "windows_11"),
                                    ("Windows 10", "windows_10"),
                                    ("Windows 8.1", "windows_8"),
                                    ("Windows 7", "windows_7"),
                                ],
                                "canonical": [
                                    ("Ubuntu", "ubuntu"),
                                ],
                                "redhat": [
                                    ("Enterprise Linux", "enterprise_linux"),
                                ],
                                "fedoraproject": [
                                    ("Fedora", "fedora"),
                                ],
                                "debian": [
                                    ("Debian Linux", "debian_linux"),
                                ],
                                "suse": [
                                    ("SLES", "linux_enterprise_server"),
                                    ("openSUSE", "opensuse"),
                                ],
                                "centos": [
                                    ("CentOS", "centos"),
                                ],
                            }},
             "prefix": "Гостевая ОС"},
        ],
        "zone_type": "tim",
        "default_ports": {
            "ethernet": 4,
            "pon": 0,
            "wifi": 0,
            "usb": 0
        },
        "default_physical_ports": 4,
        "wifi_capabilities": {
            "can_be_ap": False,
            "can_be_client": False
        }
    },

    # ==================================================================
    # Интернет
    # ==================================================================
    "Internet": {
        "name": "Интернет",
        "hardware_tabs": [],
        "software_tabs": [],
        "zone_type": "free",
        "default_ports": {
            "ethernet": 1,
            "pon": 1,
            "wifi": 0,
            "usb": 0
        },
        "wifi_capabilities": {
            "can_be_ap": False,
            "can_be_client": False
        }
    }
}

# Дополнительные конфигурации для UI
NODE_TYPE_DISPLAY = {
    "ARM": "💻 АРМ",
    "Laptop": "📓 Ноутбук",
    "Router": "📡 Маршрутизатор",
    "Switch": "🔌 Коммутатор",
    "Server": "🖥️ Сервер",
    "VirtualizationServer": "☁️ Сервер виртуализации",
    "Internet": "🌐 Интернет"
}

# Цвета для отрисовки узлов (используются в CanvasView)
NODE_COLORS = {
    "Internet": "#1f77b4",  # синий
    "Router": "#ff7f0e",  # оранжевый
    "Switch": "#2ca02c",  # зелёный
    "Server": "#d62728",  # красный
    "VirtualizationServer": "#9C27B0",  # фиолетовый
    "ARM": "#9467bd",  # сиреневый
    "Laptop": "#8B4513",  # коричневый
    "Container": "#8c564b"  # тёмно-коричневый
}

# Маппинг русских названий типов узлов (для UI)
NODE_TYPE_RUSSIAN = {
    "Internet": "Интернет",
    "Router": "Маршрутизатор",
    "Switch": "Коммутатор",
    "Server": "Сервер",
    "VirtualizationServer": "Сервер виртуализации",
    "ARM": "АРМ",
    "Laptop": "Ноутбук"
}

# Маппинг английских названий (для обратной конвертации)
NODE_TYPE_ENGLISH = {
    "АРМ": "ARM",
    "Ноутбук": "Laptop",
    "Маршрутизатор": "Router",
    "Коммутатор": "Switch",
    "Сервер": "Server",
    "Сервер виртуализации": "VirtualizationServer",
    "Интернет": "Internet"
}

# Обязательные сетевые поля для разных типов узлов
REQUIRED_NETWORK_FIELDS = {
    "ARM": {"ip": True, "mac": True, "mask": True},
    "Laptop": {"ip": True, "mac": True, "mask": True},
    "Router": {"ip": True, "mac": True, "mask": True},
    "Switch": {"ip": False, "mac": True, "mask": False},
    "Server": {"ip": True, "mac": True, "mask": True},
    "VirtualizationServer": {"ip": True, "mac": True, "mask": True},
    "Internet": {"ip": False, "mac": False, "mask": False}
}

# Размеры узлов по умолчанию (ширина, высота)
DEFAULT_NODE_SIZE = (200.0, 200.0)

# Минимальные размеры узлов
MIN_NODE_SIZE = (40.0, 40.0)

# Размеры зон по умолчанию
DEFAULT_ZONE_SIZE = (200, 150)
MIN_ZONE_SIZE = (100, 100)

# Настройки сетки (для автоматического размещения)
GRID_SETTINGS = {
    "enabled": True,
    "cell_size": 50,  # размер ячейки в пикселях
    "snap_enabled": False  # привязка к сетке
}

# Настройки соединений (линий)
LINK_SETTINGS = {
    "default_width": 2,
    "selected_width": 3,
    "ethernet_color": "#4CAF50",  # зелёный
    "pon_color": "#FF9800",  # оранжевый
    "wifi_color": "#9C27B0",  # фиолетовый
    "vpn_color": "#FF8C00",  # тёмно-оранжевый
    "dash_pattern": (8, 4)  # пунктир для Wi-Fi и VPN
}

# Имена файлов иконок
ICON_FILES = {
    "Internet": "Интернет.png",
    "Router": "Маршрутизатор.png",
    "Switch": "Коммутатор.png",
    "Server": "Сервер.png",
    "VirtualizationServer": "Сервер виртуализации.png",
    "ARM": "АРМ.png",
    "Laptop": "Ноутбук.png"
}

# Расширения для файлов иконок (если нужно искать в разных форматах)
ICON_EXTENSIONS = [".png", ".jpg", ".jpeg", ".gif", ".ico"]

# Путь к папке с ресурсами (относительно корня проекта)
RESOURCES_DIR = "resources"


def get_node_config(node_type: str) -> dict:
    """
    Возвращает конфигурацию для указанного типа узла.

    Args:
        node_type: Тип узла (английское название, например "ARM")

    Returns:
        Словарь с конфигурацией
    """
    return NODE_CONFIG.get(node_type, NODE_CONFIG["ARM"])


def get_node_display_name(node_type: str) -> str:
    """
    Возвращает отображаемое имя типа узла.

    Args:
        node_type: Тип узла (английское название)

    Returns:
        Русское название с эмодзи
    """
    return NODE_TYPE_DISPLAY.get(node_type, node_type)


def get_node_color(node_type: str) -> str:
    """
    Возвращает цвет для отрисовки узла.

    Args:
        node_type: Тип узла

    Returns:
        Цвет в формате HEX
    """
    return NODE_COLORS.get(node_type, "#999999")


def get_node_type_russian(node_type_en: str) -> str:
    """
    Преобразует английское название типа узла в русское.

    Args:
        node_type_en: Английское название (например, "ARM")

    Returns:
        Русское название (например, "АРМ")
    """
    return NODE_TYPE_RUSSIAN.get(node_type_en, node_type_en)


def get_node_type_english(node_type_ru: str) -> str:
    """
    Преобразует русское название типа узла в английское.

    Args:
        node_type_ru: Русское название (например, "АРМ")

    Returns:
        Английское название (например, "ARM")
    """
    return NODE_TYPE_ENGLISH.get(node_type_ru, "ARM")


def get_required_fields(node_type: str) -> dict:
    """
    Возвращает словарь обязательных полей для типа узла.

    Args:
        node_type: Тип узла

    Returns:
        Словарь с ключами ip, mac, mask
    """
    return REQUIRED_NETWORK_FIELDS.get(node_type, {"ip": False, "mac": False, "mask": False})


def get_icon_path(icon_name: str) -> str:
    """
    Возвращает полный путь к файлу иконки.

    Args:
        icon_name: Имя файла иконки

    Returns:
        Полный путь к файлу
    """
    import os
    return os.path.join(RESOURCES_DIR, icon_name)


def validate_node_config() -> bool:
    """
    Проверяет целостность конфигурации.

    Returns:
        True если конфигурация валидна
    """
    required_keys = ["name", "zone_type", "default_ports", "wifi_capabilities"]

    for node_type, config in NODE_CONFIG.items():
        for key in required_keys:
            if key not in config:
                print(f"[ОШИБКА] Ошибка в конфигурации {node_type}: отсутствует ключ '{key}'")
                return False

        # Проверяем, что для всех типов, кроме Internet, zone_type = "tim"
        if node_type != "Internet" and config["zone_type"] != "tim":
            print(f"[ВНИМАНИЕ] {node_type} имеет zone_type={config['zone_type']}, ожидалось 'tim'")

    print("[OK] Конфигурация узлов валидна")
    return True


# Автоматическая проверка при импорте
if __name__ != "__main__":
    validate_node_config()
