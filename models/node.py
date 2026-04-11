"""
Модуль модели узла (Node)

Содержит классы:
- NetworkPort: Сетевой порт узла
- VirtualMachine: Виртуальная машина на сервере виртуализации
- Node: Основной класс узла сети
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
import uuid

from utils.validators import validate_ip, validate_mac, validate_mask
from utils.generators import uid
from utils.network_utils import calculate_network


@dataclass
class NetworkPort:
    """
    Расширенный класс для представления сетевого порта.

    Поддерживает:
    - ethernet (RJ45): точка-точка
    - pon (PON): точка-точка (оптика)
    - usb: не участвует в сетевых соединениях
    - wifi: может быть точкой доступа (AP) или клиентом

    Attributes:
        port_id: Уникальный идентификатор порта
        port_type: Тип порта ("ethernet", "pon", "wifi", "usb")
        port_number: Номер порта
        name: Имя порта
        ip_address: IP-адрес
        mac_address: MAC-адрес
        subnet_mask: Маска подсети
        vlan_id: VLAN ID (1-65000)
        vlan_mode: Режим VLAN ("tagged" или "untagged")
        connected_to: ID узла, к которому подключен порт
        connected_port: ID порта, к которому подключен
        wifi_role: Роль для Wi-Fi ("ap" или "client")
        connected_clients: Список подключенных клиентов (для AP)
        connected_to_ap: Информация о точке доступа (для клиента)
    """
    port_id: str
    port_type: str
    port_number: int
    name: str = ""
    ip_address: str = ""
    mac_address: str = ""
    subnet_mask: str = ""

    # VLAN настройки
    vlan_id: Optional[str] = None
    vlan_mode: str = "untagged"

    # Для точка-точка соединений
    connected_to: Optional[str] = None
    connected_port: Optional[str] = None

    # Для Wi-Fi
    wifi_role: Optional[str] = None
    connected_clients: List[Dict[str, str]] = field(default_factory=list)
    connected_to_ap: Optional[Dict[str, str]] = None

    def __post_init__(self):
        """Автоматически генерирует имя порта, если не задано."""
        if not self.name:
            if self.port_type == "ethernet":
                self.name = f"ETH{self.port_number}"
            elif self.port_type == "pon":
                self.name = f"PON{self.port_number}"
            elif self.port_type == "wifi":
                self.name = f"WiFi{self.port_number}"
            else:
                self.name = f"USB{self.port_number}"

    def can_connect(self, other_port: 'NetworkPort') -> Tuple[bool, str]:
        """
        Проверяет, можно ли соединить этот порт с другим портом.

        Args:
            other_port: Другой порт для соединения

        Returns:
            Кортеж (можно_ли_соединить, причина_отказа)
        """
        # Проверка типов портов
        if self.port_type == "usb" or other_port.port_type == "usb":
            return False, "USB порты не участвуют в сетевых соединениях"

        # Проверка, не заняты ли порты
        if self.connected_to is not None:
            return False, f"Порт {self.name} уже занят"
        if other_port.connected_to is not None and other_port.port_type != "wifi":
            return False, f"Порт {other_port.name} уже занят"

        # Для Wi-Fi особая проверка
        if self.port_type == "wifi" or other_port.port_type == "wifi":
            if self.port_type == "wifi" and other_port.port_type == "wifi":
                if self.wifi_role == "ap" and other_port.wifi_role == "client":
                    if len(self.connected_clients) > 0:
                        return False, f"Точка доступа {self.name} уже имеет клиентов"
                    return True, "OK"
                elif self.wifi_role == "client" and other_port.wifi_role == "ap":
                    if len(other_port.connected_clients) > 0:
                        return False, f"Точка доступа {other_port.name} уже имеет клиентов"
                    return True, "OK"
                else:
                    return False, "Для Wi-Fi соединения нужны порты с ролями AP и Client"
            else:
                return False, "Нельзя соединить Wi-Fi порт с проводным портом"

        # Для Ethernet и PON - проверяем совместимость
        if self.port_type != other_port.port_type:
            return False, f"Нельзя соединить {self.port_type} с {other_port.port_type}"

        return True, "OK"

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        result = {
            "port_id": self.port_id,
            "port_type": self.port_type,
            "port_number": self.port_number,
            "name": self.name,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "subnet_mask": self.subnet_mask,
            "vlan_id": self.vlan_id,
            "vlan_mode": self.vlan_mode,
            "connected_to": self.connected_to,
            "connected_port": self.connected_port,
        }

        if self.port_type == "wifi":
            result["wifi_role"] = self.wifi_role
            result["connected_clients"] = self.connected_clients.copy()
            result["connected_to_ap"] = self.connected_to_ap.copy() if self.connected_to_ap else None

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkPort':
        """Десериализация из словаря."""
        port = cls(
            port_id=data.get("port_id", ""),
            port_type=data.get("port_type", "ethernet"),
            port_number=data.get("port_number", 1),
            name=data.get("name", ""),
            ip_address=data.get("ip_address", ""),
            mac_address=data.get("mac_address", ""),
            subnet_mask=data.get("subnet_mask", ""),
            vlan_id=data.get("vlan_id"),
            vlan_mode=data.get("vlan_mode", "untagged"),
            connected_to=data.get("connected_to"),
            connected_port=data.get("connected_port")
        )

        if port.port_type == "wifi":
            port.wifi_role = data.get("wifi_role")
            port.connected_clients = data.get("connected_clients", [])
            port.connected_to_ap = data.get("connected_to_ap")

        return port


@dataclass
class VirtualMachine:
    """Класс для представления виртуальной машины на сервере виртуализации."""

    vm_id: str
    name: str
    os: str = ""
    host_os: str = ""
    software: List[str] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vm_id": self.vm_id,
            "name": self.name,
            "os": self.os,
            "host_os": self.host_os,
            "software": self.software.copy(),
            "ports": self.ports.copy()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VirtualMachine':
        return cls(
            vm_id=data.get("vm_id", uid()),
            name=data.get("name", "Новая ВМ"),
            os=data.get("os", ""),
            host_os=data.get("host_os", ""),
            software=data.get("software", []),
            ports=data.get("ports", [])
        )


@dataclass
class Node:
    """
    Класс для представления узла сети.

    Attributes:
        id: Уникальный идентификатор
        type: Тип узла ("Internet", "Router", "Switch", "Server", "ARM", "Laptop", "VirtualizationServer")
        name: Имя узла
        zone: Зона, в которой находится узел
        position: Позиция на холсте (x, y)
        size: Размер узла (ширина, высота)
        firewall_enabled: Включён ли файервол
        vpn_client_enabled: Включён ли VPN-клиент
        vpn_client_tunnel_ip: Виртуальный IP клиента
        vpn_client_peer_id: ID узла-сервера
        vpn_client_peer_ip: Реальный IP сервера
        vpn_client_remote_network: Удалённая сеть клиента
        vpn_client_remote_mask: Маска удалённой сети клиента
        vpn_server_enabled: Включён ли VPN-сервер
        vpn_server_tunnel_ips: Список виртуальных IP сервера
        vpn_server_clients: Список ID подключенных клиентов
        vpn_server_real_ip: Реальный IP сервера
        vpn_server_remote_network: Удалённая сеть сервера
        vpn_server_remote_mask: Маска удалённой сети сервера
        properties: Дополнительные свойства (hardware, software, network)
        ports: Список портов узла
        physical_port_count: Количество физических портов (для сервера виртуализации)
        virtual_machines: Список виртуальных машин (для сервера виртуализации)
        routing_table: Таблица маршрутизации
    """
    id: str
    type: str
    name: str
    zone: 'Zone'
    position: Tuple[float, float]
    size: Tuple[float, float] = (60.0, 60.0)

    firewall_enabled: bool = False

    # VPN поля для клиента
    vpn_client_enabled: bool = False
    vpn_client_tunnel_ip: str = ""
    vpn_client_peer_id: Optional[str] = None
    vpn_client_peer_ip: str = ""
    vpn_client_remote_network: str = ""
    vpn_client_remote_mask: str = ""
    vpn_client_server_ip: str = ""  # VPN IP сервера
    vpn_client_port: Optional[int] = None  # Порт сервера
    vpn_client_protocol: str = "WireGuard"  # VPN-протокол клиента

    # VPN поля для сервера
    vpn_server_enabled: bool = False
    vpn_server_tunnel_ips: List[str] = field(default_factory=list)
    vpn_server_clients: List[str] = field(default_factory=list)
    vpn_server_real_ip: str = ""
    vpn_server_remote_network: str = ""
    vpn_server_remote_mask: str = ""
    vpn_server_port: Optional[int] = None  # Порт сервера
    vpn_server_protocol: str = "WireGuard"  # VPN-протокол сервера

    properties: Dict[str, Any] = field(default_factory=lambda: {
        "hardware": [],
        "software": [],
        "network": []
    })
    ports: List[Dict[str, Any]] = field(default_factory=list)

    physical_port_count: int = 0
    virtual_machines: List[Dict[str, Any]] = field(default_factory=list)
    routing_table: List[Dict[str, Any]] = field(default_factory=list)

    def move(self, nx: float, ny: float, zone: Optional['Zone'] = None) -> bool:
        """
        Перемещает узел в новую позицию.

        Args:
            nx: Новая координата X
            ny: Новая координата Y
            zone: Новая зона (опционально)

        Returns:
            True если перемещение успешно
        """
        if self.type == "Internet" and zone and zone.zone_type == "tim":
            return False

        target_zone = zone or self.zone

        if (target_zone.contains_point(nx, ny) and
                target_zone.contains_point(nx + self.size[0], ny + self.size[1])):
            self.position = (nx, ny)
            if zone:
                self.zone = zone
            return True
        return False

    def resize(self, nw: float, nh: float) -> bool:
        """
        Изменяет размер узла.

        Args:
            nw: Новая ширина
            nh: Новая высота

        Returns:
            True если изменение успешно
        """
        if nw <= 0 or nh <= 0:
            return False
        cx, cy = self.center()
        w, h = nw, nh
        nx = cx - w / 2.0
        ny = cy - h / 2.0
        if not self.zone.contains_point(nx, ny) or not self.zone.contains_point(nx + w, ny + h):
            return False
        self.size = (nw, nh)
        self.position = (nx, ny)
        return True

    def center(self) -> Tuple[float, float]:
        """Возвращает координаты центра узла."""
        x, y = self.position
        w, h = self.size
        return (x + w / 2.0, y + h / 2.0)

    def contains_point(self, px: float, py: float) -> bool:
        """Проверяет, находится ли точка внутри узла."""
        x, y = self.position
        w, h = self.size
        return x <= px <= x + w and y <= py <= y + h

    def get_corner_at(self, x: float, y: float) -> Optional[str]:
        """
        Определяет, на каком углу узла находится точка (для изменения размера).

        Returns:
            'nw', 'ne', 'sw', 'se' или None
        """
        corner_size = 10
        x_pos, y_pos = self.position
        w, h = self.size

        if abs(x - x_pos) < corner_size and abs(y - y_pos) < corner_size:
            return 'nw'
        elif abs(x - (x_pos + w)) < corner_size and abs(y - y_pos) < corner_size:
            return 'ne'
        elif abs(x - x_pos) < corner_size and abs(y - (y_pos + h)) < corner_size:
            return 'sw'
        elif abs(x - (x_pos + w)) < corner_size and abs(y - (y_pos + h)) < corner_size:
            return 'se'

        return None

    def get_hardware_components(self) -> Dict[str, str]:
        """Возвращает словарь аппаратных компонентов узла."""
        components = {
            "Процессор": "",
            "Видеоконтроллер": "",
            "Материнская плата": "",
            "HDD/SSD": "",
            "ОС": "",
            "Прикладное ПО": "",
            "Другое оборудование": "",
            "Другое ПО": ""
        }

        hardware_items = self.properties.get("hardware", [])
        software_items = self.properties.get("software", [])

        for item in hardware_items:
            if item.startswith("Процессор:"):
                components["Процессор"] = item.replace("Процессор:", "").strip()
            elif item.startswith("Видеокарта:") or item.startswith("Видеоконтроллер:"):
                components["Видеоконтроллер"] = item.split(":", 1)[1].strip()
            elif item.startswith("Материнская плата:"):
                components["Материнская плата"] = item.replace("Материнская плата:", "").strip()
            elif item.startswith("HDD/SSD:"):
                components["HDD/SSD"] = item.replace("HDD/SSD:", "").strip()
            else:
                if components["Другое оборудование"]:
                    components["Другое оборудование"] += "\n" + item
                else:
                    components["Другое оборудование"] = item

        for item in software_items:
            if item.startswith("ОС:"):
                components["ОС"] = item.replace("ОС:", "").strip()
            elif item.startswith("Приложение:"):
                components["Прикладное ПО"] = item.replace("Приложение:", "").strip()
            else:
                if components["Другое ПО"]:
                    components["Другое ПО"] += "\n" + item
                else:
                    components["Другое ПО"] = item

        return components

    # ===== МЕТОДЫ ДЛЯ РАБОТЫ С ПОРТАМИ =====

    def add_port(self, port_type: str = "ethernet", wifi_role: Optional[str] = None) -> bool:
        """Добавляет новый порт к узлу."""
        existing_ports = [p for p in self.ports if p.get("port_type") == port_type]
        next_number = len(existing_ports) + 1

        port_id = f"{port_type}_{next_number}_{uuid.uuid4().hex[:8]}"

        if port_type == "ethernet":
            name = f"ETH{next_number}"
        elif port_type == "pon":
            name = f"PON{next_number}"
        elif port_type == "wifi":
            name = f"WiFi{next_number}"
        else:
            name = f"USB{next_number}"

        new_port = {
            "port_id": port_id,
            "port_type": port_type,
            "port_number": next_number,
            "name": name,
            "ip_address": "",
            "mac_address": "",
            "subnet_mask": "",
            "connected_to": None,
            "connected_port": None,
        }

        if port_type == "wifi":
            new_port["wifi_role"] = wifi_role
            new_port["connected_clients"] = []
            new_port["connected_to_ap"] = None

        self.ports.append(new_port)
        return True

    def remove_port(self, port_id: str) -> bool:
        """Удаляет порт по ID."""
        self.ports = [p for p in self.ports if p.get("port_id") != port_id]
        return True

    def update_port(self, port_id: str, **kwargs) -> bool:
        """Обновляет параметры порта."""
        for port in self.ports:
            if port.get("port_id") == port_id:
                for key, value in kwargs.items():
                    if key in port:
                        port[key] = value
                return True
        return False

    def get_ports_by_type(self, port_type: str) -> List[Dict]:
        """Возвращает все порты указанного типа."""
        return [p for p in self.ports if p.get("port_type") == port_type]

    def get_connected_ports(self) -> List[Dict]:
        """Возвращает список занятых портов."""
        result = []
        for p in self.ports:
            if p["port_type"] == "wifi":
                if (p.get("wifi_role") == "ap" and len(p.get("connected_clients", [])) > 0) or \
                        (p.get("wifi_role") == "client" and p.get("connected_to_ap") is not None):
                    result.append(p)
            else:
                if p.get("connected_to") is not None:
                    result.append(p)
        return result

    def get_free_ports(self, port_type: Optional[str] = None) -> List[Dict]:
        """Возвращает список свободных портов."""
        result = []
        for p in self.ports:
            if port_type and p["port_type"] != port_type:
                continue

            if p["port_type"] == "wifi":
                if (p.get("wifi_role") == "ap" and len(p.get("connected_clients", [])) == 0) or \
                        (p.get("wifi_role") == "client" and p.get("connected_to_ap") is None):
                    result.append(p)
            else:
                if p.get("connected_to") is None:
                    result.append(p)

        return result

    def get_required_network_fields(self) -> Dict[str, bool]:
        """Возвращает словарь обязательных полей для типа узла."""
        required = {"ip": False, "mac": False, "mask": False}

        if self.type in ["ARM", "Laptop", "Router", "Server"]:
            required["ip"] = True
            required["mac"] = True
            required["mask"] = True
        elif self.type == "Switch":
            required["mac"] = True

        return required

    def can_be_wifi_ap(self) -> bool:
        """Проверяет, может ли узел быть точкой доступа Wi-Fi."""
        return self.type in ["Router", "ARM", "Laptop"]

    def can_be_wifi_client(self) -> bool:
        """Проверяет, может ли узел быть Wi-Fi клиентом."""
        return self.type in ["ARM", "Server", "Laptop", "Router"]

    def validate_ports(self) -> Tuple[bool, str]:
        """Проверяет корректность заполнения портов."""
        required = self.get_required_network_fields()

        for port in self.get_ports_by_type("ethernet"):
            if required["mac"] and not port.get("mac_address"):
                return False, f"Для порта {port['name']} необходимо указать MAC-адрес"
            if required["ip"] and not port.get("ip_address"):
                return False, f"Для порта {port['name']} необходимо указать IP-адрес"
            if required["mask"] and not port.get("subnet_mask"):
                return False, f"Для порта {port['name']} необходимо указать маску подсети"

            if port.get("mac_address") and not validate_mac(port["mac_address"]):
                return False, f"Неверный формат MAC-адреса для порта {port['name']}"
            if port.get("ip_address") and not validate_ip(port["ip_address"]):
                return False, f"Неверный формат IP-адреса для порта {port['name']}"
            if port.get("subnet_mask") and not validate_mask(port["subnet_mask"]):
                return False, f"Неверный формат маски для порта {port['name']} (должно быть число от 0 до 32)"

        for port in self.get_ports_by_type("pon"):
            if required["mac"] and not port.get("mac_address"):
                return False, f"Для PON порта {port['name']} необходимо указать MAC-адрес"
            if port.get("mac_address") and not validate_mac(port["mac_address"]):
                return False, f"Неверный формат MAC-адреса для PON порта {port['name']}"

        return True, "OK"

    def to_canvas(self):
        """Возвращает координаты для отрисовки."""
        return (self.position[0], self.position[1], self.size[0], self.size[1])

    def to_dict(self) -> Dict[str, Any]:
        """Сериализует узел в словарь."""
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "zone_id": self.zone.id,
            "position": self.position,
            "size": self.size,

            "firewall_enabled": self.firewall_enabled,
            "vpn_client_enabled": self.vpn_client_enabled,
            "vpn_client_tunnel_ip": self.vpn_client_tunnel_ip,
            "vpn_client_peer_id": self.vpn_client_peer_id,
            "vpn_client_peer_ip": self.vpn_client_peer_ip,
            "vpn_client_remote_network": self.vpn_client_remote_network,
            "vpn_client_remote_mask": self.vpn_client_remote_mask,
            "vpn_client_server_ip": self.vpn_client_server_ip,
            "vpn_client_port": self.vpn_client_port,
            "vpn_client_protocol": self.vpn_client_protocol,

            "vpn_server_enabled": self.vpn_server_enabled,
            "vpn_server_tunnel_ips": self.vpn_server_tunnel_ips.copy(),
            "vpn_server_clients": self.vpn_server_clients.copy(),
            "vpn_server_real_ip": self.vpn_server_real_ip,
            "vpn_server_remote_network": self.vpn_server_remote_network,
            "vpn_server_remote_mask": self.vpn_server_remote_mask,
            "vpn_server_port": self.vpn_server_port,
            "vpn_server_protocol": self.vpn_server_protocol,

            "properties": self.properties.copy(),
            "ports": [p.copy() for p in self.ports],
            "physical_port_count": self.physical_port_count,
            "virtual_machines": self.virtual_machines.copy(),
            "routing_table": self.routing_table.copy()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], zones_dict: Dict[str, 'Zone']) -> Optional['Node']:
        """Восстанавливает узел из словаря."""
        zone = zones_dict.get(data.get("zone_id"))
        if not zone:
            return None

        node = cls(
            id=data.get("id", uid()),
            type=data.get("type", "ARM"),
            name=data.get("name", ""),
            zone=zone,
            position=tuple(data.get("position", (0, 0))),
            size=tuple(data.get("size", (60.0, 60.0))),
            firewall_enabled=data.get("firewall_enabled", False),
            vpn_client_enabled=data.get("vpn_client_enabled", False),
            vpn_client_tunnel_ip=data.get("vpn_client_tunnel_ip", ""),
            vpn_client_peer_id=data.get("vpn_client_peer_id"),
            vpn_client_peer_ip=data.get("vpn_client_peer_ip", ""),
            vpn_client_remote_network=data.get("vpn_client_remote_network", ""),
            vpn_client_remote_mask=data.get("vpn_client_remote_mask", ""),
            vpn_client_protocol=data.get("vpn_client_protocol", "WireGuard"),
            vpn_server_enabled=data.get("vpn_server_enabled", False),
            vpn_server_tunnel_ips=data.get("vpn_server_tunnel_ips", []),
            vpn_server_clients=data.get("vpn_server_clients", []),
            vpn_server_real_ip=data.get("vpn_server_real_ip", ""),
            vpn_server_remote_network=data.get("vpn_server_remote_network", ""),
            vpn_server_remote_mask=data.get("vpn_server_remote_mask", ""),
            vpn_server_protocol=data.get("vpn_server_protocol", "WireGuard"),
            properties=data.get("properties", {"hardware": [], "software": [], "network": []}),
            ports=data.get("ports", []),
            physical_port_count=data.get("physical_port_count", 0),
            virtual_machines=data.get("virtual_machines", []),
            routing_table=data.get("routing_table", [])
        )

        return node


# Импорт Zone для избежания циклических импортов
from models.zone import Zone