"""
Модуль модели зоны (Zone)

Содержит классы:
- Zone: зона TIM или свободная зона для размещения узлов
- Board: доска (контейнер для всех зон, узлов и связей)
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
from tkinter import messagebox

from utils.generators import uid


@dataclass
class Zone:
    """
    Класс для представления зоны на схеме.

    Зоны бывают двух типов:
    - tim: зоны TIM (ТИМ1-ЛВС, ТИМ2-ЦОД, ТИМ3-Удаленный пользователь)
    - free: свободная зона для размещения Интернет-узлов

    Attributes:
        id: Уникальный идентификатор зоны
        name: Название зоны
        description: Описание зоны
        x: Координата X левого верхнего угла
        y: Координата Y левого верхнего угла
        width: Ширина зоны
        height: Высота зоны
        zone_type: Тип зоны ("tim" или "free")
        zone_subtype: Подтип зоны ("ТИМ1 - ЛВС", "ТИМ2 - ЦОД", "ТИМ3 - Удаленный пользователь")
        zone_number: Номер зоны (автоматически увеличивается для каждого подтипа)
    """
    id: str
    name: str
    description: str = ""
    x: float = 0
    y: float = 0
    width: float = 0
    height: float = 0
    zone_type: str = "tim"  # "tim" для зон TIM, "free" для свободной зоны
    zone_subtype: str = "ТИМ1 - ЛВС"
    zone_number: int = 1

    def contains_point(self, px: float, py: float) -> bool:
        """
        Проверяет, находится ли точка внутри зоны.

        Args:
            px: Координата X точки
            py: Координата Y точки

        Returns:
            True если точка внутри зоны, иначе False
        """
        return self.x <= px <= self.x + self.width and self.y <= py <= self.y + self.height

    def contains_node(self, node: 'Node') -> bool:
        """
        Проверяет, полностью ли узел помещается внутри зоны.

        Args:
            node: Узел для проверки

        Returns:
            True если узел полностью внутри зоны, иначе False
        """
        nx, ny = node.position
        nw, nh = node.size
        return (self.contains_point(nx, ny) and
                self.contains_point(nx + nw, ny + nh))

    def to_canvas(self) -> Tuple[float, float, float, float]:
        """
        Возвращает координаты для отрисовки на Canvas.

        Returns:
            Кортеж (x1, y1, x2, y2) - левый верхний и правый нижний углы
        """
        return (self.x, self.y, self.x + self.width, self.y + self.height)

    def resize(self, new_x: float, new_y: float, new_width: float, new_height: float) -> bool:
        """
        Изменяет размер и положение зоны.

        Args:
            new_x: Новая координата X
            new_y: Новая координата Y
            new_width: Новая ширина
            new_height: Новая высота

        Returns:
            True если изменение успешно, False если размеры некорректны
        """
        if new_width <= 0 or new_height <= 0:
            return False
        self.x = new_x
        self.y = new_y
        self.width = new_width
        self.height = new_height
        return True

    def center(self) -> Tuple[float, float]:
        """
        Возвращает координаты центра зоны.

        Returns:
            Кортеж (center_x, center_y)
        """
        return (self.x + self.width / 2.0, self.y + self.height / 2.0)

    def get_display_text(self) -> str:
        """
        Возвращает форматированный текст для отображения на схеме.

        Returns:
            Строка вида "ТИМ1-ЛВС1" или "ТИМ2-ЦОД1"
        """
        if self.zone_type == "free":
            return "Свободная зона"

        if " - " in self.zone_subtype:
            tim_part, subtype_part = self.zone_subtype.split(" - ", 1)
            return f"{tim_part} - {subtype_part}{self.zone_number}"
        else:
            # Для обратной совместимости со старыми зонами
            if self.zone_subtype == "ЛВС":
                tim_prefix = "ТИМ1"
            elif self.zone_subtype == "ЦОД":
                tim_prefix = "ТИМ2"
            else:
                tim_prefix = "ТИМ3"
            return f"{tim_prefix} - {self.zone_subtype}{self.zone_number}"

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализует зону в словарь для сохранения.

        Returns:
            Словарь с данными зоны
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "zone_type": self.zone_type,
            "zone_subtype": self.zone_subtype,
            "zone_number": self.zone_number
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Zone':
        """
        Восстанавливает зону из словаря.

        Args:
            data: Словарь с данными зоны

        Returns:
            Экземпляр Zone
        """
        return cls(
            id=data.get("id", uid()),
            name=data.get("name", ""),
            description=data.get("description", ""),
            x=data.get("x", 0),
            y=data.get("y", 0),
            width=data.get("width", 0),
            height=data.get("height", 0),
            zone_type=data.get("zone_type", "tim"),
            zone_subtype=data.get("zone_subtype", "ТИМ1 - ЛВС"),
            zone_number=data.get("zone_number", 1)
        )


# Импортируем Node с отложенной загрузкой для избежания циклических импортов
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.node import Node
    from models.link import Link


@dataclass
class Board:
    """
    Класс-контейнер для всех элементов схемы.

    Содержит списки зон, узлов и связей между ними.
    Обеспечивает основные операции: добавление, удаление, перемещение.

    Attributes:
        zones: Список зон
        nodes: Список узлов
        links: Список связей
    """
    zones: List['Zone'] = field(default_factory=list)
    nodes: List['Node'] = field(default_factory=list)
    links: List['Link'] = field(default_factory=list)

    def __post_init__(self):
        """Создаёт свободную зону при инициализации, если её нет."""
        self.create_free_zone()

    def get_next_zone_number(self, zone_subtype: str) -> int:
        """
        Возвращает следующий номер для зоны данного подтипа.

        Args:
            zone_subtype: Подтип зоны ("ТИМ1 - ЛВС", "ТИМ2 - ЦОД", "ТИМ3 - Удаленный пользователь")

        Returns:
            Следующий номер для этого подтипа
        """
        count = 0
        for zone in self.zones:
            if zone.zone_type == "tim" and hasattr(zone, 'zone_subtype') and zone.zone_subtype == zone_subtype:
                count += 1
        return count + 1

    def create_free_zone(self):
        """Создаёт свободную зону для размещения Интернет-узлов."""
        free_zone = Zone(
            id="free_zone",
            name="Свободная зона",
            description="Для размещения Интернет-узлов",
            x=0,
            y=0,
            width=4000,
            height=3000,
            zone_type="free"
        )
        if not any(z.id == "free_zone" for z in self.zones):
            self.zones.append(free_zone)

    def add_zone(self, zone: 'Zone') -> None:
        """
        Добавляет зону на доску.

        Args:
            zone: Зона для добавления
        """
        self.zones.append(zone)

    def remove_zone(self, zone_id: str) -> None:
        """
        Удаляет зону и все узлы внутри неё.

        Args:
            zone_id: ID удаляемой зоны
        """
        if zone_id == "free_zone":
            return

        # Удаляем все узлы, находящиеся в этой зоне
        nodes_to_remove = [n.id for n in self.nodes if n.zone.id == zone_id]
        for node_id in nodes_to_remove:
            self.remove_node(node_id)

        # Удаляем саму зону
        self.zones = [z for z in self.zones if z.id != zone_id]

    def add_node(self, node: 'Node') -> bool:
        """
        Добавляет узел на доску.

        Args:
            node: Узел для добавления

        Returns:
            True если добавление успешно, False если ошибка
        """
        # Интернет-узлы нельзя размещать в зонах TIM
        if node.type == "Internet" and node.zone.zone_type == "tim":
            messagebox.showerror("Ошибка", "Интернет-узлы нельзя размещать в зонах TIM!")
            return False

        # Корректируем позицию, если узел выходит за границы зоны
        if not node.zone.contains_node(node):
            zone = node.zone
            x, y = node.position
            w, h = node.size
            x = max(zone.x, min(x, zone.x + zone.width - w))
            y = max(zone.y, min(y, zone.y + zone.height - h))
            node.position = (x, y)

        self.nodes.append(node)
        return True

    def remove_node(self, node_id: str) -> None:
        """
        Удаляет узел и все связанные с ним связи.

        Args:
            node_id: ID удаляемого узла
        """
        # Удаляем все связи, связанные с узлом
        self.links = [l for l in self.links if l.a.id != node_id and l.b.id != node_id]

        self.nodes = [n for n in self.nodes if n.id != node_id]

    def to_dict(self) -> Dict[str, Any]:
        """Сериализует всю доску в словарь."""
        return {
            "zones": [z.to_dict() for z in self.zones],
            "nodes": [n.to_dict() for n in self.nodes],
            "links": [l.to_dict() for l in self.links],
        }

    def load_from_dict(self, data: Dict[str, Any]) -> None:
        """Восстанавливает доску из словаря."""
        from models.node import Node as _Node
        from models.link import Link as _Link

        self.zones.clear()
        self.nodes.clear()
        self.links.clear()

        # Зоны
        zones_dict = {}
        for zd in data.get("zones", []):
            zone = Zone.from_dict(zd)
            self.zones.append(zone)
            zones_dict[zone.id] = zone
        self.create_free_zone()
        # Добавляем free_zone в словарь
        for z in self.zones:
            if z.id not in zones_dict:
                zones_dict[z.id] = z

        # Узлы
        nodes_dict = {}
        for nd in data.get("nodes", []):
            node = _Node.from_dict(nd, zones_dict)
            if node:
                self.nodes.append(node)
                nodes_dict[node.id] = node

        # Связи
        for ld in data.get("links", []):
            link = _Link.from_dict(ld, nodes_dict)
            if link:
                self.links.append(link)

    def find_node(self, node_id: str) -> Optional['Node']:
        """
        Находит узел по ID.

        Args:
            node_id: ID узла

        Returns:
            Узел или None, если не найден
        """
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def get_free_zone(self) -> Optional['Zone']:
        """
        Возвращает свободную зону.

        Returns:
            Свободная зона или None
        """
        for z in self.zones:
            if z.id == "free_zone":
                return z
        return None

    def get_tim_zones(self) -> List['Zone']:
        """
        Возвращает список всех зон TIM (не включая свободную зону).

        Returns:
            Список зон TIM
        """
        return [z for z in self.zones if z.zone_type == "tim"]

    @staticmethod
    def _rects_overlap(r1: Tuple[float, float, float, float],
                        r2: Tuple[float, float, float, float]) -> bool:
        """Проверяет пересечение двух прямоугольников (x, y, w, h).

        Касание границами не считается пересечением.
        """
        x1, y1, w1, h1 = r1
        x2, y2, w2, h2 = r2
        return not (x1 + w1 <= x2 or x2 + w2 <= x1 or
                    y1 + h1 <= y2 or y2 + h2 <= y1)

    def zone_rect_overlaps_any(self, x: float, y: float, w: float, h: float,
                                 exclude_id: Optional[str] = None) -> bool:
        """Проверяет, пересекается ли прямоугольник (x, y, w, h) с какой-либо
        TIM-зоной (кроме exclude_id). Используется при создании и перемещении
        зон, чтобы они не накладывались друг на друга (промт 9 №3).
        """
        for z in self.get_tim_zones():
            if exclude_id and z.id == exclude_id:
                continue
            if self._rects_overlap((x, y, w, h), (z.x, z.y, z.width, z.height)):
                return True
        return False

    def get_next_free_position(self, zone: 'Zone', node_size: Tuple[float, float] = (60.0, 60.0)) -> Tuple[
        float, float]:
        """
        Возвращает следующую свободную позицию для нового узла в зоне.

        Args:
            zone: Зона, в которой размещается узел
            node_size: Размер узла (ширина, высота)

        Returns:
            Координаты (x, y) для нового узла
        """
        if zone.id == "free_zone":
            existing_nodes = [n for n in self.nodes if n.zone.id == "free_zone"]
            if not existing_nodes:
                return (300, 300)
            else:
                last_node = existing_nodes[-1]
                new_x = last_node.position[0] + last_node.size[0] + 30
                new_y = last_node.position[1]
                if new_x + node_size[0] > 1800:
                    new_x = 300
                    new_y = last_node.position[1] + last_node.size[1] + 30
                return (new_x, new_y)
        else:
            center_x, center_y = zone.center()
            return (center_x - node_size[0] / 2, center_y - node_size[1] / 2)

    def is_zone_name_exists(self, name: str) -> bool:
        """
        Проверяет, существует ли уже зона с таким именем.

        Args:
            name: Имя зоны для проверки

        Returns:
            True если имя занято, иначе False
        """
        for z in self.zones:
            if z.name == name:
                return True
        return False

    def move_zone(self, zone_id: str, nx: float, ny: float) -> bool:
        """
        Перемещает зону и все узлы внутри неё.

        Args:
            zone_id: ID перемещаемой зоны
            nx: Новая координата X
            ny: Новая координата Y

        Returns:
            True если перемещение успешно
        """
        if zone_id == "free_zone":
            return False

        zone = next((z for z in self.zones if z.id == zone_id), None)
        if zone is None:
            return False

        delta_x = nx - zone.x
        delta_y = ny - zone.y
        zone.x = nx
        zone.y = ny

        # Перемещаем все узлы внутри зоны
        nodes_in_zone = [n for n in self.nodes if n.zone.id == zone_id]
        for node in nodes_in_zone:
            node.position = (node.position[0] + delta_x, node.position[1] + delta_y)

        return True

    def resize_zone(self, zone_id: str, nx: float, ny: float, nw: float, nh: float) -> bool:
        """
        Изменяет размер зоны.

        Args:
            zone_id: ID изменяемой зоны
            nx: Новая координата X
            ny: Новая координата Y
            nw: Новая ширина
            nh: Новая высота

        Returns:
            True если изменение успешно
        """
        if zone_id == "free_zone":
            return False

        zone = next((z for z in self.zones if z.id == zone_id), None)
        if zone is None:
            return False

        # Сохраняем старые значения для отката при ошибке
        old_zone = Zone(
            id=zone.id, name=zone.name, description=zone.description,
            x=zone.x, y=zone.y, width=zone.width, height=zone.height,
            zone_type=zone.zone_type,
            zone_subtype=zone.zone_subtype, zone_number=zone.zone_number
        )

        if zone.resize(nx, ny, nw, nh):
            # Проверяем, что все узлы остались внутри зоны
            nodes_in_zone = [n for n in self.nodes if n.zone.id == zone_id]
            for node in nodes_in_zone:
                if not zone.contains_node(node):
                    # Откатываем изменения
                    zone.x = old_zone.x
                    zone.y = old_zone.y
                    zone.width = old_zone.width
                    zone.height = old_zone.height
                    return False
            return True

        return False

    def add_link(self, a_id: str, b_id: str, connection_info: Dict[str, Any]) -> Optional['Link']:
        """
        Добавляет соединение между узлами.

        Args:
            a_id: ID первого узла
            b_id: ID второго узла
            connection_info: Словарь с параметрами соединения

        Returns:
            Созданный Link или None
        """
        from models.link import Link
        from models.node import NetworkPort
        from utils.network_utils import calculate_network

        a = self.find_node(a_id)
        b = self.find_node(b_id)
        if a is None or b is None:
            return None

        # Проверяем существующее соединение
        for link in self.links:
            if (link.a.id == a_id and link.b.id == b_id) or (link.a.id == b_id and link.b.id == a_id):
                if not link.is_wifi:
                    return None

        if connection_info["type"] == "p2p":
            port_a_id = connection_info["port_a"]
            port_b_id = connection_info["port_b"]

            port_a = None
            port_b = None
            for port in a.ports:
                if port["port_id"] == port_a_id:
                    port_a = port
                    break
            for port in b.ports:
                if port["port_id"] == port_b_id:
                    port_b = port
                    break

            if not port_a or not port_b:
                return None

            network_port_a = NetworkPort.from_dict(port_a)
            network_port_b = NetworkPort.from_dict(port_b)
            can_connect, reason = network_port_a.can_connect(network_port_b)
            if not can_connect:
                messagebox.showerror("Ошибка", reason)
                return None

            link = Link(
                id=uid(),
                a=a,
                b=b,
                ports_connected={"a": port_a_id, "b": port_b_id},
                is_wifi=False
            )

        elif connection_info["type"] == "wifi":
            ap_node_id = connection_info["ap_node_id"]
            ap_port_id = connection_info["ap_port_id"]
            client_node_id = connection_info["client_node_id"]
            client_port_id = connection_info["client_port_id"]

            ap_node = self.find_node(ap_node_id)
            client_node = self.find_node(client_node_id)

            if not ap_node or not client_node:
                return None

            ap_port = None
            client_port = None
            for port in ap_node.ports:
                if port["port_id"] == ap_port_id:
                    ap_port = port
                    break
            for port in client_node.ports:
                if port["port_id"] == client_port_id:
                    client_port = port
                    break

            if not ap_port or not client_port:
                return None

            if ap_port.get("wifi_role") != "ap":
                messagebox.showerror("Ошибка", "Выбранный порт не является точкой доступа")
                return None
            if client_port.get("wifi_role") != "client":
                messagebox.showerror("Ошибка", "Выбранный порт не является клиентом")
                return None

            network_ap_port = NetworkPort.from_dict(ap_port)
            network_client_port = NetworkPort.from_dict(client_port)
            can_connect, reason = network_ap_port.can_connect(network_client_port)
            if not can_connect:
                messagebox.showerror("Ошибка", reason)
                return None

            link = Link(
                id=uid(),
                a=ap_node,
                b=client_node,
                is_wifi=True,
                wifi_ap_node_id=ap_node_id,
                wifi_ap_port_id=ap_port_id,
                wifi_client_node_id=client_node_id,
                wifi_client_port_id=client_port_id
            )
        else:
            return None

        if not link.is_valid():
            return None

        self.links.append(link)
        link.update_ports_connection() if not link.is_wifi else link.update_wifi_connection()

        return link

    def remove_link_between_nodes(self, node1_id: str, node2_id: str) -> bool:
        """Удаляет соединение между двумя узлами."""
        for link in self.links[:]:
            if (link.a.id == node1_id and link.b.id == node2_id) or \
                    (link.a.id == node2_id and link.b.id == node1_id):

                # Очищаем порты
                if link.is_wifi:
                    # Очищаем Wi-Fi порты
                    if link.wifi_ap_node_id:
                        ap_node = self.find_node(link.wifi_ap_node_id)
                        if ap_node:
                            for port in ap_node.ports:
                                if port.get("port_id") == link.wifi_ap_port_id:
                                    port["connected_clients"] = []
                                    break

                    if link.wifi_client_node_id:
                        client_node = self.find_node(link.wifi_client_node_id)
                        if client_node:
                            for port in client_node.ports:
                                if port.get("port_id") == link.wifi_client_port_id:
                                    port["connected_to_ap"] = None
                                    break
                else:
                    # Очищаем точка-точка порты
                    port_a_id = link.ports_connected.get("a")
                    port_b_id = link.ports_connected.get("b")

                    if port_a_id:
                        for port in link.a.ports:
                            if port.get("port_id") == port_a_id:
                                port["connected_to"] = None
                                port["connected_port"] = None
                                break

                    if port_b_id:
                        for port in link.b.ports:
                            if port.get("port_id") == port_b_id:
                                port["connected_to"] = None
                                port["connected_port"] = None
                                break

                self.links.remove(link)
                return True

        return False

    def get_connectivity_matrix(self):
        """Возвращает матрицу связности сети."""
        from models.connectivity_matrix import ConnectivityMatrix
        return ConnectivityMatrix(self)


# Добавляем импорт Link после определения класса для избежания циклических импортов
from models.link import Link