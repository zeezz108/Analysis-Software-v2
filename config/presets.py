"""
Пресеты конфигураций узлов для быстрого тестирования.

Каждый пресет — это словарь, содержащий полную конфигурацию узла:
- name: имя узла
- type: тип (ARM, Router, Server, etc.)
- hardware: список аппаратных компонентов
- software: список ПО (ОС, приложения, периферия)
- ports: список портов с реальными IP/MAC/масками
- vpn_client/vpn_server: настройки VPN (если есть)
- firewall: настройки файервола (если есть)

Все данные — адекватные, реальные, взаимосовместимые по IP-адресации.

Топология по умолчанию (preset_topology):
  Интернет ↔ Маршрутизатор ↔ [АРМ1, АРМ2, Сервер1]
  Маршрутизатор: 192.168.1.1/24 (внутренняя сеть), VPN-сервер
  АРМ1: 192.168.1.10/24, VPN-клиент
  АРМ2: 192.168.1.11/24
  Сервер1: 192.168.1.100/24
"""

from typing import List, Dict, Any


# ===================================================================
# Отдельные пресеты узлов
# ===================================================================

PRESET_ARM_OFFICE = {
    "name": "АРМ-Офис",
    "type": "ARM",
    "hardware": [
        "Процессор: Intel Core I7-12700K -",
        "Видеоконтроллер: Nvidia Geforce Rtx 3060 -",
        "Материнская плата: Asus Prime B660M-A -",
        "HDD/SSD: Crucial Ct1000Mx500Ssd1 -",
    ],
    "software": [
        "ОС: Microsoft Windows 10 21h2",
        "Приложение: Microsoft Office 365",
        "Приложение: Google Chrome",
        "Мышь: A4Tech Bloody V8",
        "Клавиатура: A4Tech Bloody B120",
        "Монитор: Dell E2420H",
    ],
    "ports": [
        {
            "port_id": "eth_1_preset",
            "port_type": "ethernet",
            "port_number": 1,
            "name": "ETH1",
            "ip_address": "192.168.1.10",
            "mac_address": "00:1A:2B:3C:4D:10",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
    ],
}

PRESET_ARM_DEVELOPER = {
    "name": "АРМ-Разработчик",
    "type": "ARM",
    "hardware": [
        "Процессор: Amd Ryzen 9 5950X -",
        "Видеоконтроллер: Nvidia Geforce Rtx 4070 -",
        "Материнская плата: Msi Meg X570 Ace -",
        "HDD/SSD: Samsung 970 Evo Plus -",
    ],
    "software": [
        "ОС: Canonical Ubuntu Linux 22.04",
        "Приложение: JetBrains IntelliJ IDEA",
        "Приложение: Docker Desktop",
        "Приложение: Mozilla Firefox",
        "Мышь: Logitech G502 Hero",
        "Клавиатура: Corsair K95 RGB",
        "Монитор: LG 27UK850",
    ],
    "ports": [
        {
            "port_id": "eth_1_preset",
            "port_type": "ethernet",
            "port_number": 1,
            "name": "ETH1",
            "ip_address": "192.168.1.11",
            "mac_address": "00:1A:2B:3C:4D:11",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
        {
            "port_id": "wifi_1_preset",
            "port_type": "wifi",
            "port_number": 1,
            "name": "WiFi1",
            "ip_address": "",
            "mac_address": "00:1A:2B:3C:4D:12",
            "subnet_mask": "",
            "wifi_role": "client",
            "connected_clients": [],
            "connected_to_ap": None,
            "connected_to": None,
            "connected_port": None,
        },
    ],
}

PRESET_ROUTER = {
    "name": "Маршрутизатор",
    "type": "Router",
    "hardware": [
        "Процессор: Intel Atom C3558 -",
    ],
    "software": [
        "ОС: Cisco Ios 15.9",
    ],
    "ports": [
        # WAN — к Интернету
        {
            "port_id": "eth_wan_preset",
            "port_type": "ethernet",
            "port_number": 1,
            "name": "ETH1-WAN",
            "ip_address": "10.0.0.2",
            "mac_address": "00:AA:BB:CC:DD:01",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
        # LAN1 — к АРМ1
        {
            "port_id": "eth_lan1_preset",
            "port_type": "ethernet",
            "port_number": 2,
            "name": "ETH2-LAN",
            "ip_address": "192.168.1.1",
            "mac_address": "00:AA:BB:CC:DD:02",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
        # LAN2 — к АРМ2
        {
            "port_id": "eth_lan2_preset",
            "port_type": "ethernet",
            "port_number": 3,
            "name": "ETH3-LAN",
            "ip_address": "192.168.1.1",
            "mac_address": "00:AA:BB:CC:DD:03",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
        # LAN3 — к Серверу
        {
            "port_id": "eth_lan3_preset",
            "port_type": "ethernet",
            "port_number": 4,
            "name": "ETH4-LAN",
            "ip_address": "192.168.1.1",
            "mac_address": "00:AA:BB:CC:DD:04",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
    ],
    # VPN-сервер на маршрутизаторе
    "vpn_server": {
        "enabled": True,
        "tunnel_ip": "10.8.0.1/24",
        "port": 51820,
        "protocol": "WireGuard",
        "remote_network": "192.168.1.0",
        "remote_mask": "24",
    },
    # Фаервол
    "firewall": {
        "enabled": True,
        "rules": [
            {
                "name": "Блокировать входящие извне",
                "direction": "in",
                "action": "block",
                "protocol": "any",
                "local_ports": "",
                "remote_ports": "",
                "local_addresses": "10.0.0.2",
                "remote_addresses": "any",
                "enabled": True,
                "description": "Блокировка входящего трафика на WAN-порт",
            },
            {
                "name": "Разрешить LAN → WAN",
                "direction": "out",
                "action": "allow",
                "protocol": "any",
                "local_ports": "",
                "remote_ports": "",
                "local_addresses": "any",
                "remote_addresses": "any",
                "enabled": True,
                "description": "Разрешить исходящий трафик из LAN",
            },
        ],
    },
}

PRESET_SERVER = {
    "name": "Сервер",
    "type": "Server",
    "hardware": [
        "Процессор: Intel Xeon E-2388G -",
        "HDD/SSD: Samsung 870 Evo -",
    ],
    "software": [
        "ОС: Canonical Ubuntu Linux 22.04",
        "Приложение: Apache HTTP Server",
        "Приложение: PostgreSQL",
        "Приложение: OpenSSH",
    ],
    "ports": [
        {
            "port_id": "eth_1_preset",
            "port_type": "ethernet",
            "port_number": 1,
            "name": "ETH1",
            "ip_address": "192.168.1.100",
            "mac_address": "00:1A:2B:3C:4D:A0",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
    ],
}

PRESET_INTERNET = {
    "name": "Интернет",
    "type": "Internet",
    "hardware": [],
    "software": [],
    "ports": [
        {
            "port_id": "eth_1_preset",
            "port_type": "ethernet",
            "port_number": 1,
            "name": "ETH1",
            "ip_address": "10.0.0.1",
            "mac_address": "FF:FF:FF:00:00:01",
            "subnet_mask": "24",
            "connected_to": None,
            "connected_port": None,
        },
    ],
}

# VPN-клиент для АРМ1 (подключается к маршрутизатору)
PRESET_VPN_CLIENT = {
    "enabled": True,
    "server_ip": "10.8.0.1",
    "port": 51820,
    "tunnel_ip": "10.8.0.2/24",
    "protocol": "WireGuard",
}


# ===================================================================
# Каталог пресетов для UI
# ===================================================================

PRESETS_CATALOG = {
    "ARM": [
        {"id": "arm_office", "name": "АРМ — Офисный", "preset": PRESET_ARM_OFFICE},
        {"id": "arm_dev", "name": "АРМ — Разработчик", "preset": PRESET_ARM_DEVELOPER},
    ],
    "Router": [
        {"id": "router_main", "name": "Маршрутизатор Cisco", "preset": PRESET_ROUTER},
    ],
    "Server": [
        {"id": "server_web", "name": "Веб-сервер Ubuntu", "preset": PRESET_SERVER},
    ],
    "Internet": [
        {"id": "internet", "name": "Интернет (провайдер)", "preset": PRESET_INTERNET},
    ],
}


def get_presets_for_type(node_type_ru: str) -> list:
    """Возвращает список пресетов для данного типа узла (русское имя)."""
    type_mapping = {
        "АРМ": "ARM",
        "Ноутбук": "ARM",  # те же пресеты
        "Маршрутизатор": "Router",
        "Коммутатор": "Router",
        "Сервер": "Server",
        "Сервер виртуализации": "Server",
        "Интернет": "Internet",
    }
    en_type = type_mapping.get(node_type_ru, "")
    return PRESETS_CATALOG.get(en_type, [])


def apply_preset(node, preset: dict):
    """Применяет пресет к существующему объекту Node.

    Заполняет hardware, software, ports, VPN и firewall.
    """
    node.properties["hardware"] = list(preset.get("hardware", []))
    node.properties["software"] = list(preset.get("software", []))

    if "ports" in preset:
        node.ports = [p.copy() for p in preset["ports"]]

    # VPN-сервер
    vpn_srv = preset.get("vpn_server")
    if vpn_srv:
        node.vpn_server_enabled = vpn_srv.get("enabled", False)
        ips = vpn_srv.get("tunnel_ip", "")
        node.vpn_server_tunnel_ips = [ips] if ips else []
        node.vpn_server_port = vpn_srv.get("port")
        node.vpn_server_protocol = vpn_srv.get("protocol", "WireGuard")
        node.vpn_server_remote_network = vpn_srv.get("remote_network", "")
        node.vpn_server_remote_mask = vpn_srv.get("remote_mask", "")

    # VPN-клиент
    vpn_cli = preset.get("vpn_client")
    if vpn_cli:
        node.vpn_client_enabled = vpn_cli.get("enabled", False)
        node.vpn_client_server_ip = vpn_cli.get("server_ip", "")
        node.vpn_client_port = vpn_cli.get("port")
        node.vpn_client_tunnel_ip = vpn_cli.get("tunnel_ip", "")
        node.vpn_client_protocol = vpn_cli.get("protocol", "WireGuard")

    # Фаервол
    fw = preset.get("firewall")
    if fw:
        node.firewall_enabled = fw.get("enabled", False)
        from models.firewall import FirewallRule
        from utils.generators import uid
        rules = []
        for r in fw.get("rules", []):
            rule = FirewallRule(
                name=r.get("name", ""),
                direction=r.get("direction", "in"),
                action=r.get("action", "allow"),
                protocol=r.get("protocol", "any"),
                local_ports=r.get("local_ports", ""),
                remote_ports=r.get("remote_ports", ""),
                local_addresses=r.get("local_addresses", "any"),
                remote_addresses=r.get("remote_addresses", "any"),
                enabled=r.get("enabled", True),
                description=r.get("description", ""),
            )
            rules.append(rule.__dict__)
        node.properties["firewall"] = {
            "node_id": node.id,
            "rules": rules,
            "profiles": {},
            "firewall_enabled": node.firewall_enabled,
            "notification_enabled": True,
        }
