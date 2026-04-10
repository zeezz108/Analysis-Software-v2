"""
Модуль конфигурации типов узлов

Содержит словарь NODE_CONFIG с настройками для каждого типа узла:
- Какие вкладки показывать (hardware, software, peripheral)
- Какие методы БД использовать для заполнения
- Какие порты создавать по умолчанию
- Возможности Wi-Fi
"""

NODE_CONFIG = {
    "ARM": {
        "name": "АРМ",
        "hardware_tabs": [
            {"title": "Процессоры", "method": "get_processors", "var_name": "processor"},
            {"title": "Видеоконтроллеры", "method": "get_graphics_cards", "var_name": "gpu"},
            {"title": "Материнские платы", "method": "get_motherboards", "var_name": "motherboard"},
            {"title": "HDD/SSD", "method": "get_storage_devices", "var_name": "hdd"},
        ],
        "driver_tabs": [
            {"title": "Драйверы видеоконтроллеров", "method": "get_gpu_drivers_by_vendor", "var_name": "gpu_driver"},
        ],
        "software_tabs": [
            {"title": "Операционные системы", "method": "get_client_operating_systems", "var_name": "os"},
            {"title": "Прикладное ПО", "method": "get_application_software", "var_name": "app_software", "multiple": True},
        ],
        "peripheral_tabs": [
            {"title": "Мыши", "method": "get_mice", "var_name": "mouse"},
            {"title": "Клавиатуры", "method": "get_keyboards", "var_name": "keyboard"},
            {"title": "Принтеры", "method": "get_printers", "var_name": "printer"},
            {"title": "Мониторы", "method": "get_monitors", "var_name": "monitor"},
        ],
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

    "Laptop": {
        "name": "Ноутбук",
        "hardware_tabs": [
            {"title": "Процессоры", "method": "get_processors", "var_name": "processor"},
            {"title": "Видеоконтроллеры", "method": "get_graphics_cards", "var_name": "gpu"},
            {"title": "Материнские платы", "method": "get_motherboards", "var_name": "motherboard"},
            {"title": "HDD/SSD", "method": "get_storage_devices", "var_name": "hdd"},
        ],
        "driver_tabs": [
            {"title": "Драйверы видеоконтроллеров", "method": "get_gpu_drivers_by_vendor", "var_name": "gpu_driver"},
        ],
        "software_tabs": [
            {"title": "Операционные системы", "method": "get_client_operating_systems", "var_name": "os"},
            {"title": "Прикладное ПО", "method": "get_application_software", "var_name": "app_software", "multiple": True},
        ],
        "peripheral_tabs": [
            {"title": "Мыши", "method": "get_mice", "var_name": "mouse"},
            {"title": "Клавиатуры", "method": "get_keyboards", "var_name": "keyboard"},
            {"title": "Принтеры", "method": "get_printers", "var_name": "printer"},
            {"title": "Мониторы", "method": "get_monitors", "var_name": "monitor"},
        ],
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

    "Router": {
        "name": "Маршрутизатор",
        "hardware_tabs": [
            {"title": "Аппаратные платформы", "method": "get_router_hardware", "var_name": "router_platform"},
        ],
        "software_tabs": [
            {"title": "Cisco IOS/IOS-XE", "method": "get_cisco_ios", "var_name": "cisco_ios"},
            {"title": "Juniper JunOS", "method": "get_junos", "var_name": "junos"},
            {"title": "Huawei VRP", "method": "get_huawei_versions", "var_name": "huawei"},
            {"title": "Другие ОС", "method": "get_other_router_os", "var_name": "other_router_os"},
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

    "Switch": {
        "name": "Коммутатор",
        "hardware_tabs": [
            {"title": "Аппаратные платформы", "method": "get_switch_hardware", "var_name": "switch_platform"},
        ],
        "software_tabs": [
            {"title": "Cisco Switch IOS", "method": "get_cisco_switch_os", "var_name": "cisco_switch_os"},
            {"title": "Управляемые коммутаторы", "method": "get_managed_switch_os", "var_name": "managed_switch_os"},
            {"title": "Неуправляемые коммутаторы", "method": "get_unmanaged_switch_os",
             "var_name": "unmanaged_switch_os"},
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

    "Server": {
        "name": "Сервер",
        "hardware_tabs": [
            {"title": "Процессоры", "method": "get_processors", "var_name": "server_cpu"},
            {"title": "HDD/SSD", "method": "get_storage_devices", "var_name": "server_storage"},
        ],
        "software_tabs": [
            {"title": "Серверные ОС", "method": "get_server_operating_systems", "var_name": "server_os"},
            {"title": "Прикладное ПО", "method": "get_application_software", "var_name": "server_app"},
        ],
        "peripheral_tabs": [
            {"title": "Мыши", "method": "get_mice", "var_name": "server_mouse"},
            {"title": "Клавиатуры", "method": "get_keyboards", "var_name": "server_keyboard"},
            {"title": "Принтеры", "method": "get_printers", "var_name": "server_printer"},
            {"title": "Мониторы", "method": "get_monitors", "var_name": "server_monitor"},
        ],
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

    "VirtualizationServer": {
        "name": "Сервер виртуализации",
        "hardware_tabs": [
            {"title": "Процессоры", "method": "get_processors", "var_name": "server_cpus", "multiple": True},
            {"title": "Оперативная память", "method": "get_ram_options", "var_name": "server_ram"},
            {"title": "Диски/Хранилище", "method": "get_server_storage", "var_name": "server_storage",
             "multiple": True},
            {"title": "Сетевые карты", "method": "get_network_cards", "var_name": "server_nics", "multiple": True},
        ],
        "hypervisor_tabs": [
            {"title": "VMware vSphere/ESXi", "method": "get_vmware_versions", "var_name": "vmware"},
            {"title": "Microsoft Hyper-V", "method": "get_hyperv_versions", "var_name": "hyperv"},
            {"title": "Proxmox VE", "method": "get_proxmox_versions", "var_name": "proxmox"},
            {"title": "KVM", "method": "get_kvm_versions", "var_name": "kvm"},
            {"title": "Citrix Hypervisor", "method": "get_citrix_versions", "var_name": "citrix"},
        ],
        "host_os_tabs": [
            {"title": "Операционная система хоста", "method": "get_server_operating_systems", "var_name": "host_os"},
        ],
        "containerizer_tabs": [
            {"title": "Контейнеризатор", "method": "get_containerizers", "var_name": "containerizer"},
        ],
        "guest_os_tabs": [
            {"title": "Гостевые ОС", "method": "get_guest_os_list", "var_name": "guest_os", "multiple": True},
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
DEFAULT_NODE_SIZE = (60.0, 60.0)

# Минимальные размеры узлов
MIN_NODE_SIZE = (20.0, 20.0)

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