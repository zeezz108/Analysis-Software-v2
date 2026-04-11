"""
Модуль модели маршрута (Route)

Содержит класс для представления записи в таблице маршрутизации.
"""

from dataclasses import dataclass
from typing import Dict, Any

from utils.generators import uid


@dataclass
class Route:
    """
    Класс для представления одной записи в таблице маршрутизации.

    Attributes:
        route_id: Уникальный идентификатор маршрута
        destination: Сеть назначения (например, "192.168.1.0")
        netmask: Маска сети (например, "255.255.255.0" или "24")
        gateway: IP-адрес шлюза (например, "192.168.1.1")
        interface: Имя интерфейса (например, "eth0")
        metric: Метрика (приоритет маршрута, чем меньше тем выше приоритет)
    """
    route_id: str
    destination: str = "0.0.0.0"
    netmask: str = "0.0.0.0"
    gateway: str = "0.0.0.0"
    interface: str = ""
    metric: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализует маршрут в словарь для сохранения.

        Returns:
            Словарь с данными маршрута

        Example:
            >>> route = Route(route_id="123", destination="192.168.1.0", netmask="24", gateway="192.168.1.1")
            >>> route.to_dict()
            {'route_id': '123', 'destination': '192.168.1.0', 'netmask': '24', 'gateway': '192.168.1.1', 'interface': '', 'metric': 0}
        """
        return {
            "route_id": self.route_id,
            "destination": self.destination,
            "netmask": self.netmask,
            "gateway": self.gateway,
            "interface": self.interface,
            "metric": self.metric,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Route':
        """
        Восстанавливает маршрут из словаря.

        Args:
            data: Словарь с данными маршрута

        Returns:
            Экземпляр Route

        Example:
            >>> data = {'route_id': '123', 'destination': '192.168.1.0', 'netmask': '24', 'gateway': '192.168.1.1'}
            >>> route = Route.from_dict(data)
            >>> route.destination
            '192.168.1.0'
        """
        return cls(
            route_id=data.get("route_id", uid()),
            destination=data.get("destination", "0.0.0.0"),
            netmask=data.get("netmask", "0.0.0.0"),
            gateway=data.get("gateway", "0.0.0.0"),
            interface=data.get("interface", ""),
            metric=data.get("metric", 0)
        )

    def is_default_route(self) -> bool:
        """
        Проверяет, является ли маршрут маршрутом по умолчанию.

        Returns:
            True если это маршрут по умолчанию (0.0.0.0/0)

        Example:
            >>> route = Route(route_id="1", destination="0.0.0.0", netmask="0.0.0.0")
            >>> route.is_default_route()
            True
        """
        return self.destination == "0.0.0.0" and self.netmask == "0.0.0.0"

    def is_connected_route(self) -> bool:
        """
        Проверяет, является ли маршрут прямым (connected route).

        Returns:
            True если это прямой маршрут (gateway = 0.0.0.0)
        """
        return self.gateway == "0.0.0.0"

    def get_cidr_notation(self) -> str:
        """
        Возвращает сеть в формате CIDR.

        Returns:
            Строка вида "192.168.1.0/24"

        Example:
            >>> route = Route(route_id="1", destination="192.168.1.0", netmask="24")
            >>> route.get_cidr_notation()
            '192.168.1.0/24'
        """
        if self.netmask.isdigit():
            return f"{self.destination}/{self.netmask}"

        # Если маска в десятичном формате, пробуем преобразовать
        try:
            from utils.network_utils import decimal_mask_to_cidr
            cidr = decimal_mask_to_cidr(self.netmask)
            return f"{self.destination}/{cidr}"
        except Exception:
            return f"{self.destination}/{self.netmask}"

    def prefix_length(self) -> int:
        """Возвращает длину префикса маски в битах (CIDR).

        Используется для Longest Prefix Match при выборе маршрута.
        """
        try:
            if self.netmask.isdigit():
                return max(0, min(32, int(self.netmask)))
            from utils.network_utils import decimal_mask_to_cidr
            return decimal_mask_to_cidr(self.netmask)
        except Exception:
            return 0

    def normalized_destination(self) -> str:
        """Возвращает адрес сети, нормализованный по маске (host bits = 0).

        Например, destination=192.168.1.55, netmask=24 → 192.168.1.0
        """
        try:
            from utils.network_utils import calculate_network
            return calculate_network(self.destination, self.netmask)
        except Exception:
            return self.destination

    def matches_ip(self, ip: str) -> bool:
        """Проверяет, подходит ли этот маршрут для данного IP."""
        try:
            from utils.network_utils import is_ip_in_network
            if self.destination == "0.0.0.0" and self.prefix_length() == 0:
                # Default-route совпадает с любым IP
                return True
            return is_ip_in_network(ip, self.destination, self.netmask)
        except Exception:
            return False

    def get_display_string(self) -> str:
        """
        Возвращает строку для отображения в UI.

        Returns:
            Отформатированная строка маршрута

        Example:
            >>> route = Route(route_id="1", destination="192.168.1.0", netmask="24", gateway="192.168.1.1", interface="eth0", metric=10)
            >>> route.get_display_string()
            '192.168.1.0/24 via 192.168.1.1 dev eth0 metric 10'
        """
        parts = []

        # Сеть назначения
        parts.append(self.get_cidr_notation())

        # Шлюз
        if self.gateway and self.gateway != "0.0.0.0":
            parts.append(f"via {self.gateway}")
        elif self.is_connected_route():
            parts.append("(connected)")

        # Интерфейс
        if self.interface:
            parts.append(f"dev {self.interface}")

        # Метрика
        if self.metric > 0:
            parts.append(f"metric {self.metric}")

        return " ".join(parts)

    def __str__(self) -> str:
        """Строковое представление маршрута."""
        return self.get_display_string()

    def __repr__(self) -> str:
        """Представление для отладки."""
        return f"Route(destination={self.destination}, netmask={self.netmask}, gateway={self.gateway}, interface={self.interface}, metric={self.metric})"

    def is_equal(self, other: 'Route') -> bool:
        """
        Сравнивает два маршрута (без учёта route_id).

        Args:
            other: Другой маршрут для сравнения

        Returns:
            True если маршруты одинаковы (destination, netmask, gateway, interface, metric)
        """
        return (self.destination == other.destination and
                self.netmask == other.netmask and
                self.gateway == other.gateway and
                self.interface == other.interface and
                self.metric == other.metric)

    def clone(self) -> 'Route':
        """
        Создаёт копию маршрута с новым ID.

        Returns:
            Новый экземпляр Route
        """
        return Route(
            route_id=uid(),
            destination=self.destination,
            netmask=self.netmask,
            gateway=self.gateway,
            interface=self.interface,
            metric=self.metric
        )

    @classmethod
    def create_default_route(cls, gateway: str, interface: str = "", metric: int = 10) -> 'Route':
        """
        Создаёт маршрут по умолчанию.

        Args:
            gateway: IP-адрес шлюза
            interface: Интерфейс (опционально)
            metric: Метрика (по умолчанию 10)

        Returns:
            Новый маршрут по умолчанию
        """
        return cls(
            route_id=uid(),
            destination="0.0.0.0",
            netmask="0.0.0.0",
            gateway=gateway,
            interface=interface,
            metric=metric
        )

    @classmethod
    def create_connected_route(cls, network: str, netmask: str, interface: str, metric: int = 1) -> 'Route':
        """
        Создаёт прямой маршрут (connected route).

        Args:
            network: Адрес сети
            netmask: Маска сети
            interface: Интерфейс
            metric: Метрика (по умолчанию 1)

        Returns:
            Новый прямой маршрут
        """
        return cls(
            route_id=uid(),
            destination=network,
            netmask=netmask,
            gateway="0.0.0.0",
            interface=interface,
            metric=metric
        )


# Специальные константы для маршрутов
DEFAULT_ROUTE_DESTINATION = "0.0.0.0"
DEFAULT_ROUTE_NETMASK = "0.0.0.0"
CONNECTED_ROUTE_GATEWAY = "0.0.0.0"

# Диапазоны метрик
METRIC_MIN = 1
METRIC_MAX = 999
METRIC_DEFAULT = 10
METRIC_CONNECTED = 1