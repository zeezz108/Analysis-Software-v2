"""
Модуль модели VPN (Virtual Private Network)

Содержит классы для работы с VPN:
- VPNClient: Конфигурация VPN-клиента
- VPNServer: Конфигурация VPN-сервера
- VPNConnection: Активное VPN-соединение
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime

from utils.generators import uid
from utils.validators import validate_ip, validate_mask


@dataclass
class VPNClient:
    """
    Конфигурация VPN-клиента.

    Attributes:
        enabled: Включён ли VPN-клиент
        tunnel_ip: Виртуальный IP-адрес клиента в туннеле (например, "10.0.0.2/24")
        peer_id: ID узла-сервера, к которому подключен клиент
        peer_ip: Реальный IP-адрес сервера
        remote_network: Удалённая сеть, доступная через VPN (опционально)
        remote_mask: Маска удалённой сети
        protocol: Протокол VPN ("ipsec", "openvpn", "wireguard")
        port: Порт для VPN-соединения
    """
    enabled: bool = False
    tunnel_ip: str = ""
    peer_id: Optional[str] = None
    peer_ip: str = ""
    remote_network: str = ""
    remote_mask: str = ""
    protocol: str = "ipsec"
    port: int = 1194

    def get_tunnel_ip_address(self) -> str:
        """
        Возвращает только IP-адрес туннеля (без маски).

        Returns:
            IP-адрес или пустую строку
        """
        if '/' in self.tunnel_ip:
            return self.tunnel_ip.split('/')[0]
        return self.tunnel_ip

    def get_tunnel_mask(self) -> str:
        """
        Возвращает маску туннеля.

        Returns:
            Маска в CIDR формате или пустую строку
        """
        if '/' in self.tunnel_ip:
            return self.tunnel_ip.split('/')[1]
        return ""

    def is_valid(self) -> bool:
        """
        Проверяет валидность конфигурации клиента.

        Returns:
            True если конфигурация валидна
        """
        if not self.enabled:
            return True

        if not self.tunnel_ip:
            return False

        ip_part = self.get_tunnel_ip_address()
        mask_part = self.get_tunnel_mask()

        if not validate_ip(ip_part):
            return False

        if mask_part and not validate_mask(mask_part):
            return False

        if not self.peer_id and not self.peer_ip:
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "enabled": self.enabled,
            "tunnel_ip": self.tunnel_ip,
            "peer_id": self.peer_id,
            "peer_ip": self.peer_ip,
            "remote_network": self.remote_network,
            "remote_mask": self.remote_mask,
            "protocol": self.protocol,
            "port": self.port
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VPNClient':
        """Десериализация из словаря."""
        return cls(
            enabled=data.get("enabled", False),
            tunnel_ip=data.get("tunnel_ip", ""),
            peer_id=data.get("peer_id"),
            peer_ip=data.get("peer_ip", ""),
            remote_network=data.get("remote_network", ""),
            remote_mask=data.get("remote_mask", ""),
            protocol=data.get("protocol", "ipsec"),
            port=data.get("port", 1194)
        )


@dataclass
class VPNServer:
    """
    Конфигурация VPN-сервера.

    Attributes:
        enabled: Включён ли VPN-сервер
        tunnel_ips: Список виртуальных IP-адресов сервера (можно несколько для разных подсетей)
        clients: Список ID подключенных клиентов
        real_ip: Реальный IP-адрес сервера
        remote_network: Удалённая сеть, доступная через VPN (опционально)
        remote_mask: Маска удалённой сети
        protocol: Протокол VPN ("ipsec", "openvpn", "wireguard")
        port: Порт для VPN-соединения
        max_clients: Максимальное количество клиентов
    """
    enabled: bool = False
    tunnel_ips: List[str] = field(default_factory=list)
    clients: List[str] = field(default_factory=list)
    real_ip: str = ""
    remote_network: str = ""
    remote_mask: str = ""
    protocol: str = "ipsec"
    port: int = 1194
    max_clients: int = 10

    def add_tunnel_ip(self, ip_with_mask: str) -> bool:
        """
        Добавляет виртуальный IP для сервера.

        Args:
            ip_with_mask: IP с маской (например, "10.0.0.1/24")

        Returns:
            True если добавление успешно
        """
        if '/' not in ip_with_mask:
            return False

        ip_part, mask_part = ip_with_mask.split('/')
        if not validate_ip(ip_part) or not validate_mask(mask_part):
            return False

        if ip_with_mask not in self.tunnel_ips:
            self.tunnel_ips.append(ip_with_mask)
            return True
        return False

    def remove_tunnel_ip(self, ip_with_mask: str) -> bool:
        """
        Удаляет виртуальный IP сервера.

        Args:
            ip_with_mask: IP с маской для удаления

        Returns:
            True если удаление успешно
        """
        if ip_with_mask in self.tunnel_ips:
            self.tunnel_ips.remove(ip_with_mask)
            return True
        return False

    def add_client(self, client_id: str) -> bool:
        """
        Добавляет клиента к серверу.

        Args:
            client_id: ID узла-клиента

        Returns:
            True если добавление успешно
        """
        if client_id not in self.clients and len(self.clients) < self.max_clients:
            self.clients.append(client_id)
            return True
        return False

    def remove_client(self, client_id: str) -> bool:
        """
        Удаляет клиента с сервера.

        Args:
            client_id: ID узла-клиента

        Returns:
            True если удаление успешно
        """
        if client_id in self.clients:
            self.clients.remove(client_id)
            return True
        return False

    def get_client_count(self) -> int:
        """Возвращает количество подключенных клиентов."""
        return len(self.clients)

    def is_full(self) -> bool:
        """Проверяет, достигнуто ли максимальное количество клиентов."""
        return len(self.clients) >= self.max_clients

    def get_tunnel_networks(self) -> List[str]:
        """
        Возвращает список туннельных сетей в формате CIDR.

        Returns:
            Список сетей (например, ["10.0.0.0/24"])
        """
        import ipaddress
        networks = []
        for ip_with_mask in self.tunnel_ips:
            if '/' in ip_with_mask:
                try:
                    net = ipaddress.IPv4Network(ip_with_mask, strict=False)
                    networks.append(str(net))
                except (ValueError, ipaddress.AddressValueError):
                    continue
        return networks

    def is_valid(self) -> bool:
        """
        Проверяет валидность конфигурации сервера.

        Returns:
            True если конфигурация валидна
        """
        if not self.enabled:
            return True

        if not self.tunnel_ips:
            return False

        for ip_with_mask in self.tunnel_ips:
            if '/' not in ip_with_mask:
                return False
            ip_part, mask_part = ip_with_mask.split('/')
            if not validate_ip(ip_part) or not validate_mask(mask_part):
                return False

        if not self.real_ip or not validate_ip(self.real_ip):
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "enabled": self.enabled,
            "tunnel_ips": self.tunnel_ips.copy(),
            "clients": self.clients.copy(),
            "real_ip": self.real_ip,
            "remote_network": self.remote_network,
            "remote_mask": self.remote_mask,
            "protocol": self.protocol,
            "port": self.port,
            "max_clients": self.max_clients
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VPNServer':
        """Десериализация из словаря."""
        return cls(
            enabled=data.get("enabled", False),
            tunnel_ips=data.get("tunnel_ips", []),
            clients=data.get("clients", []),
            real_ip=data.get("real_ip", ""),
            remote_network=data.get("remote_network", ""),
            remote_mask=data.get("remote_mask", ""),
            protocol=data.get("protocol", "ipsec"),
            port=data.get("port", 1194),
            max_clients=data.get("max_clients", 10)
        )


@dataclass
class VPNConnection:
    """
    Активное VPN-соединение между клиентом и сервером.

    Attributes:
        id: Уникальный идентификатор соединения
        client_id: ID узла-клиента
        server_id: ID узла-сервера
        client_tunnel_ip: Виртуальный IP клиента
        server_tunnel_ip: Виртуальный IP сервера
        established: Время установки соединения
        bytes_sent: Количество отправленных байт
        bytes_received: Количество полученных байт
        status: Статус соединения ("active", "connecting", "disconnected")
    """
    id: str
    client_id: str
    server_id: str
    client_tunnel_ip: str = ""
    server_tunnel_ip: str = ""
    established: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    status: str = "disconnected"

    def __post_init__(self):
        """Устанавливает время создания, если не указано."""
        if not self.established:
            self.established = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def is_active(self) -> bool:
        """Проверяет, активно ли соединение."""
        return self.status == "active"

    def connect(self):
        """Устанавливает соединение."""
        self.status = "active"
        self.established = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def disconnect(self):
        """Разрывает соединение."""
        self.status = "disconnected"

    def update_traffic(self, sent: int = 0, received: int = 0):
        """Обновляет статистику трафика."""
        self.bytes_sent += sent
        self.bytes_received += received

    def get_traffic_display(self) -> str:
        """
        Возвращает отформатированную статистику трафика.

        Returns:
            Строка вида "⬆ 1.5 MB / ⬇ 2.3 MB"
        """

        def format_bytes(bytes_val: int) -> str:
            for unit in ['B', 'KB', 'MB', 'GB']:
                if bytes_val < 1024:
                    return f"{bytes_val:.1f} {unit}"
                bytes_val /= 1024
            return f"{bytes_val:.1f} TB"

        return f"⬆ {format_bytes(self.bytes_sent)} / ⬇ {format_bytes(self.bytes_received)}"

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "id": self.id,
            "client_id": self.client_id,
            "server_id": self.server_id,
            "client_tunnel_ip": self.client_tunnel_ip,
            "server_tunnel_ip": self.server_tunnel_ip,
            "established": self.established,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "status": self.status
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VPNConnection':
        """Десериализация из словаря."""
        return cls(
            id=data.get("id", uid()),
            client_id=data.get("client_id", ""),
            server_id=data.get("server_id", ""),
            client_tunnel_ip=data.get("client_tunnel_ip", ""),
            server_tunnel_ip=data.get("server_tunnel_ip", ""),
            established=data.get("established", ""),
            bytes_sent=data.get("bytes_sent", 0),
            bytes_received=data.get("bytes_received", 0),
            status=data.get("status", "disconnected")
        )

    def __str__(self) -> str:
        """Строковое представление соединения."""
        return f"VPN: {self.client_id} → {self.server_id} [{self.status}]"


# Константы для протоколов VPN
VPN_PROTOCOL_IPSEC = "ipsec"
VPN_PROTOCOL_OPENVPN = "openvpn"
VPN_PROTOCOL_WIREGUARD = "wireguard"
VPN_PROTOCOL_L2TP = "l2tp"
VPN_PROTOCOL_PPTP = "pptp"

VPN_PROTOCOLS = [
    VPN_PROTOCOL_IPSEC,
    VPN_PROTOCOL_OPENVPN,
    VPN_PROTOCOL_WIREGUARD,
    VPN_PROTOCOL_L2TP,
    VPN_PROTOCOL_PPTP
]

VPN_PROTOCOL_DISPLAY = {
    VPN_PROTOCOL_IPSEC: "IPsec",
    VPN_PROTOCOL_OPENVPN: "OpenVPN",
    VPN_PROTOCOL_WIREGUARD: "WireGuard",
    VPN_PROTOCOL_L2TP: "L2TP",
    VPN_PROTOCOL_PPTP: "PPTP (не рекомендуется)"
}

# Константы для статусов соединения
VPN_STATUS_ACTIVE = "active"
VPN_STATUS_CONNECTING = "connecting"
VPN_STATUS_DISCONNECTED = "disconnected"

VPN_STATUS_DISPLAY = {
    VPN_STATUS_ACTIVE: "🟢 Активно",
    VPN_STATUS_CONNECTING: "🟡 Подключение...",
    VPN_STATUS_DISCONNECTED: "🔴 Отключено"
}

# Порты по умолчанию для разных протоколов
DEFAULT_VPN_PORTS = {
    VPN_PROTOCOL_IPSEC: 500,
    VPN_PROTOCOL_OPENVPN: 1194,
    VPN_PROTOCOL_WIREGUARD: 51820,
    VPN_PROTOCOL_L2TP: 1701,
    VPN_PROTOCOL_PPTP: 1723
}