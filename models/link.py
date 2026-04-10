"""
Модуль модели связи (Link)

Содержит класс для представления соединения между двумя узлами.
Поддерживает:
- Точка-точка соединения (Ethernet, PON)
- Wi-Fi соединения (точка-многоточка)
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple, TYPE_CHECKING

from utils.generators import uid

if TYPE_CHECKING:
    from models.node import Node


@dataclass
class Link:
    """
    Класс для представления соединения между двумя узлами.

    Поддерживает два типа соединений:
    - p2p (точка-точка): Ethernet, PON
    - wifi (точка-многоточка): Wi-Fi (AP -> Client)

    Attributes:
        id: Уникальный идентификатор связи
        a: Первый узел
        b: Второй узел
        properties: Дополнительные свойства (hardware, software, network)
        ports_connected: Словарь с ID подключенных портов {"a": "port_id", "b": "port_id"}
        is_wifi: Является ли соединение Wi-Fi
        wifi_ap_node_id: ID узла, который является точкой доступа (для Wi-Fi)
        wifi_ap_port_id: ID порта точки доступа (для Wi-Fi)
        wifi_client_node_id: ID узла-клиента (для Wi-Fi)
        wifi_client_port_id: ID порта клиента (для Wi-Fi)
    """
    id: str
    a: 'Node'
    b: 'Node'
    properties: Dict[str, Any] = field(default_factory=lambda: {
        "hardware": [],
        "software": [],
        "network": []
    })

    # Для точка-точка соединений
    ports_connected: Dict[str, str] = field(default_factory=dict)  # {"a": "port_id", "b": "port_id"}

    # Для Wi-Fi (точка-многоточка)
    is_wifi: bool = False
    wifi_ap_node_id: Optional[str] = None
    wifi_ap_port_id: Optional[str] = None
    wifi_client_node_id: Optional[str] = None
    wifi_client_port_id: Optional[str] = None

    def __post_init__(self):
        """После создания связи обновляем порты узлов."""
        if self.is_wifi:
            self.update_wifi_connection()
        else:
            self.update_ports_connection()

    def update_ports_connection(self):
        """Обновляет информацию о подключении в портах (для точка-точка)."""
        if not self.ports_connected:
            return

        port_a_id = self.ports_connected.get("a")
        port_b_id = self.ports_connected.get("b")

        if not port_a_id or not port_b_id:
            return

        # Обновляем порт узла A
        for port in self.a.ports:
            if port.get("port_id") == port_a_id:
                port["connected_to"] = self.b.id
                port["connected_port"] = port_b_id
                break

        # Обновляем порт узла B
        for port in self.b.ports:
            if port.get("port_id") == port_b_id:
                port["connected_to"] = self.a.id
                port["connected_port"] = port_a_id
                break

    def update_wifi_connection(self):
        """Обновляет информацию о Wi-Fi подключении."""
        if not all([self.wifi_ap_node_id, self.wifi_ap_port_id,
                    self.wifi_client_node_id, self.wifi_client_port_id]):
            return

        # Находим порт AP (точки доступа)
        ap_node = None
        client_node = None

        if self.a.id == self.wifi_ap_node_id:
            ap_node = self.a
            client_node = self.b
        elif self.b.id == self.wifi_ap_node_id:
            ap_node = self.b
            client_node = self.a

        if not ap_node or not client_node:
            return

        # Добавляем клиента в список connected_clients порта AP
        for port in ap_node.ports:
            if port.get("port_id") == self.wifi_ap_port_id:
                if "connected_clients" not in port:
                    port["connected_clients"] = []

                # Проверяем, нет ли уже такого клиента
                client_exists = False
                for client in port["connected_clients"]:
                    if client.get("node_id") == self.wifi_client_node_id:
                        client_exists = True
                        break

                if not client_exists:
                    port["connected_clients"].append({
                        "node_id": self.wifi_client_node_id,
                        "port_id": self.wifi_client_port_id
                    })
                break

        # Обновляем порт клиента - указываем, к какой AP он подключен
        for port in client_node.ports:
            if port.get("port_id") == self.wifi_client_port_id:
                port["connected_to_ap"] = {
                    "node_id": self.wifi_ap_node_id,
                    "port_id": self.wifi_ap_port_id
                }
                break

    def is_valid(self) -> bool:
        """
        Проверяет валидность связи.

        Returns:
            True если связь валидна (узлы существуют и разные)
        """
        if self.a is None or self.b is None:
            return False
        if self.a.id == self.b.id:
            return False
        return True

    def get_connection_info(self) -> str:
        """
        Возвращает информацию о соединении для отображения.

        Returns:
            Строка с описанием соединения
        """
        if self.is_wifi:
            # Определяем, какой узел AP, какой клиент
            if self.wifi_ap_node_id == self.a.id:
                ap_node = self.a
                client_node = self.b
            else:
                ap_node = self.b
                client_node = self.a

            # Находим имена портов
            ap_port_name = "?"
            for port in ap_node.ports:
                if port.get("port_id") == self.wifi_ap_port_id:
                    ap_port_name = port.get("name", "?")
                    break

            client_port_name = "?"
            for port in client_node.ports:
                if port.get("port_id") == self.wifi_client_port_id:
                    client_port_name = port.get("name", "?")
                    break

            return f"WiFi: {ap_node.name}:{ap_port_name} [AP] → {client_node.name}:{client_port_name} [Client]"
        else:
            # Точка-точка соединение
            port_a_id = self.ports_connected.get("a")
            port_b_id = self.ports_connected.get("b")

            port_a_name = "?"
            port_b_name = "?"

            if port_a_id:
                for port in self.a.ports:
                    if port.get("port_id") == port_a_id:
                        port_a_name = port.get("name", "?")
                        break

            if port_b_id:
                for port in self.b.ports:
                    if port.get("port_id") == port_b_id:
                        port_b_name = port.get("name", "?")
                        break

            return f"{self.a.name}:{port_a_name} → {self.b.name}:{port_b_name}"

    def get_bezier_coords(self, canvas_view, link_index: int = 0, total_links_on_side: int = 1) -> List[float]:
        """
        Рассчитывает координаты для отрисовки ортогональной линии с обходом препятствий.

        Args:
            canvas_view: Экземпляр CanvasView (нужен для получения границ иконок)
            link_index: Индекс этой линии среди линий на той же стороне узла (для разведения)
            total_links_on_side: Общее количество линий, выходящих с той же стороны

        Returns:
            Список координат: [x1,y1, x2,y2, ..., dummy*6]
            (последние 6 значений — заглушка для обратной совместимости)
        """
        # Получаем границы иконок узлов
        a_bounds = canvas_view.get_icon_bounds(self.a)
        b_bounds = canvas_view.get_icon_bounds(self.b)

        # Центры узлов
        cx_a = a_bounds[0] + a_bounds[2] / 2
        cy_a = a_bounds[1] + a_bounds[3] / 2
        cx_b = b_bounds[0] + b_bounds[2] / 2
        cy_b = b_bounds[1] + b_bounds[3] / 2

        dx = cx_b - cx_a
        dy = cy_b - cy_a

        # Определяем стороны выхода/входа
        if abs(dx) > abs(dy):
            if dx > 0:
                a_side, b_side = "right", "left"
            else:
                a_side, b_side = "left", "right"
        else:
            if dy > 0:
                a_side, b_side = "bottom", "top"
            else:
                a_side, b_side = "top", "bottom"

        def get_edge_point(bounds, side, offset_ratio=0.5):
            """Точка на краю иконки. offset_ratio=0.5 — середина стороны."""
            bx, by, bw, bh = bounds
            if side == "right":
                return (bx + bw, by + bh * offset_ratio)
            elif side == "left":
                return (bx, by + bh * offset_ratio)
            elif side == "bottom":
                return (bx + bw * offset_ratio, by + bh)
            else:  # top
                return (bx + bw * offset_ratio, by)

        def get_direction(side):
            dirs = {"right": (1, 0), "left": (-1, 0), "bottom": (0, 1), "top": (0, -1)}
            return dirs[side]

        # Смещение точки подключения для разведения нескольких линий на одной стороне
        if total_links_on_side > 1:
            spacing = 0.6 / total_links_on_side
            ratio_a = 0.2 + spacing * (link_index + 0.5)
            ratio_b = 0.2 + spacing * (link_index + 0.5)
        else:
            ratio_a = 0.5
            ratio_b = 0.5

        a_point = get_edge_point(a_bounds, a_side, ratio_a)
        b_point = get_edge_point(b_bounds, b_side, ratio_b)
        a_dir = get_direction(a_side)
        b_dir = get_direction(b_side)

        # Небольшой отступ от края иконки для первого «колена»
        stub = 10
        a_start = (a_point[0] + a_dir[0] * stub, a_point[1] + a_dir[1] * stub)
        b_end = (b_point[0] + b_dir[0] * stub, b_point[1] + b_dir[1] * stub)

        # Строим ортогональный путь: A_edge -> a_start -> промежуточные -> b_end -> B_edge
        points = [a_point, a_start]

        is_horizontal = a_dir[0] != 0  # линия выходит горизонтально

        if is_horizontal:
            if a_start[1] != b_end[1]:
                mid_x = (a_start[0] + b_end[0]) / 2
                # Разведение параллельных линий: смещаем среднюю точку
                spread = (link_index - (total_links_on_side - 1) / 2) * 12
                mid_x += spread if total_links_on_side > 1 else 0
                points.append((mid_x, a_start[1]))
                points.append((mid_x, b_end[1]))
        else:
            if a_start[0] != b_end[0]:
                mid_y = (a_start[1] + b_end[1]) / 2
                spread = (link_index - (total_links_on_side - 1) / 2) * 12
                mid_y += spread if total_links_on_side > 1 else 0
                points.append((a_start[0], mid_y))
                points.append((b_end[0], mid_y))

        points.append(b_end)
        points.append(b_point)

        # Обход препятствий: проверяем, пересекает ли путь иконки других узлов
        # Только для серединных сегментов (не от/к иконкам A и B)
        obstacle_bounds = []
        margin = 3  # минимальный отступ от иконки
        if hasattr(canvas_view, 'board') and len(points) > 4:
            for node in canvas_view.board.nodes:
                if node.id == self.a.id or node.id == self.b.id:
                    continue
                nb = canvas_view.get_icon_bounds(node)
                obstacle_bounds.append((
                    nb[0] - margin, nb[1] - margin,
                    nb[0] + nb[2] + margin, nb[1] + nb[3] + margin
                ))

        if obstacle_bounds:
            # Проверяем только серединные сегменты (2..len-3), не трогаем выход/вход
            mid_start = 2
            mid_end = len(points) - 2
            needs_avoidance = False
            for i in range(mid_start, mid_end):
                if i < len(points) - 1:
                    for obs in obstacle_bounds:
                        if self._segment_intersects_rect(points[i], points[i + 1], obs):
                            needs_avoidance = True
                            break
                if needs_avoidance:
                    break
            if needs_avoidance:
                points = self._avoid_obstacles(points, obstacle_bounds)

        # Плоский список координат
        flat_points = []
        for point in points:
            flat_points.extend([point[0], point[1]])

        # Заглушка для обратной совместимости (6 значений)
        last = points[-1] if points else (0, 0)
        flat_points += [last[0], last[1], last[0], last[1], last[0], last[1]]

        return flat_points

    @staticmethod
    def _segment_intersects_rect(p1: Tuple[float, float], p2: Tuple[float, float],
                                  rect: Tuple[float, float, float, float]) -> bool:
        """Проверяет, пересекает ли отрезок (p1->p2) прямоугольник (x1,y1,x2,y2)."""
        rx1, ry1, rx2, ry2 = rect
        x1, y1 = p1
        x2, y2 = p2

        # Проверяем горизонтальный отрезок
        if y1 == y2:
            if ry1 <= y1 <= ry2:
                seg_min_x = min(x1, x2)
                seg_max_x = max(x1, x2)
                if seg_min_x < rx2 and seg_max_x > rx1:
                    return True
            return False

        # Проверяем вертикальный отрезок
        if x1 == x2:
            if rx1 <= x1 <= rx2:
                seg_min_y = min(y1, y2)
                seg_max_y = max(y1, y2)
                if seg_min_y < ry2 and seg_max_y > ry1:
                    return True
            return False

        return False

    def _avoid_obstacles(self, points: List[Tuple[float, float]],
                          obstacles: List[Tuple[float, float, float, float]]) -> List[Tuple[float, float]]:
        """Корректирует серединные сегменты пути, чтобы обойти иконки узлов.

        Сдвигает среднюю линию выше/ниже/левее/правее если она проходит через иконку.
        Не добавляет лишних точек — только сдвигает существующие.
        """
        result = list(points)

        # Проверяем каждый сегмент (кроме первых двух и последних двух — выход/вход)
        for i in range(2, len(result) - 2):
            if i >= len(result) - 1:
                break
            p1 = result[i]
            p2 = result[i + 1]

            for obs in obstacles:
                if not self._segment_intersects_rect(p1, p2, obs):
                    continue

                rx1, ry1, rx2, ry2 = obs

                if p1[1] == p2[1]:
                    # Горизонтальный сегмент — сдвигаем по Y
                    dist_top = abs(p1[1] - ry1)
                    dist_bottom = abs(p1[1] - ry2)
                    if dist_top <= dist_bottom:
                        new_y = ry1 - 5
                    else:
                        new_y = ry2 + 5
                    result[i] = (p1[0], new_y)
                    result[i + 1] = (p2[0], new_y)
                    # Обновляем соседние вертикальные сегменты
                    if i > 0:
                        result[i - 1] = (result[i - 1][0], result[i - 1][1])  # не меняем
                    break

                elif p1[0] == p2[0]:
                    # Вертикальный сегмент — сдвигаем по X
                    dist_left = abs(p1[0] - rx1)
                    dist_right = abs(p1[0] - rx2)
                    if dist_left <= dist_right:
                        new_x = rx1 - 5
                    else:
                        new_x = rx2 + 5
                    result[i] = (new_x, p1[1])
                    result[i + 1] = (new_x, p2[1])
                    break

        return result

    def get_port_names(self) -> Tuple[str, str]:
        """
        Возвращает имена портов, участвующих в соединении.

        Returns:
            Кортеж (имя_порта_на_узле_A, имя_порта_на_узле_B)
        """
        port_a_name = "?"
        port_b_name = "?"

        if self.is_wifi:
            # Для Wi-Fi
            if self.wifi_ap_node_id == self.a.id:
                for port in self.a.ports:
                    if port.get("port_id") == self.wifi_ap_port_id:
                        port_a_name = port.get("name", "?")
                        break
                for port in self.b.ports:
                    if port.get("port_id") == self.wifi_client_port_id:
                        port_b_name = port.get("name", "?")
                        break
            else:
                for port in self.b.ports:
                    if port.get("port_id") == self.wifi_ap_port_id:
                        port_a_name = port.get("name", "?")
                        break
                for port in self.a.ports:
                    if port.get("port_id") == self.wifi_client_port_id:
                        port_b_name = port.get("name", "?")
                        break
        else:
            # Для точка-точка
            port_a_id = self.ports_connected.get("a")
            port_b_id = self.ports_connected.get("b")

            if port_a_id:
                for port in self.a.ports:
                    if port.get("port_id") == port_a_id:
                        port_a_name = port.get("name", "?")
                        break

            if port_b_id:
                for port in self.b.ports:
                    if port.get("port_id") == port_b_id:
                        port_b_name = port.get("name", "?")
                        break

        return (port_a_name, port_b_name)

    def get_link_type(self) -> str:
        """
        Возвращает тип соединения.

        Returns:
            "wifi", "ethernet" или "pon"
        """
        if self.is_wifi:
            return "wifi"

        if not self.ports_connected:
            return "unknown"

        port_a_id = self.ports_connected.get("a")
        if port_a_id:
            for port in self.a.ports:
                if port.get("port_id") == port_a_id:
                    port_type = port.get("port_type", "ethernet")
                    return port_type

        return "ethernet"

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализует связь в словарь.

        Returns:
            Словарь с данными связи
        """
        result = {
            "id": self.id,
            "a_id": self.a.id,
            "b_id": self.b.id,
            "properties": self.properties.copy(),
            "ports_connected": self.ports_connected.copy(),
            "is_wifi": self.is_wifi
        }

        if self.is_wifi:
            result.update({
                "wifi_ap_node_id": self.wifi_ap_node_id,
                "wifi_ap_port_id": self.wifi_ap_port_id,
                "wifi_client_node_id": self.wifi_client_node_id,
                "wifi_client_port_id": self.wifi_client_port_id
            })

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any], nodes_dict: Dict[str, 'Node']) -> Optional['Link']:
        """
        Восстанавливает связь из словаря.

        Args:
            data: Словарь с данными связи
            nodes_dict: Словарь узлов {node_id: Node}

        Returns:
            Экземпляр Link или None, если узлы не найдены
        """
        a = nodes_dict.get(data.get("a_id"))
        b = nodes_dict.get(data.get("b_id"))

        if not a or not b:
            return None

        link = cls(
            id=data.get("id", uid()),
            a=a,
            b=b,
            properties=data.get("properties", {"hardware": [], "software": [], "network": []}),
            ports_connected=data.get("ports_connected", {}),
            is_wifi=data.get("is_wifi", False)
        )

        if link.is_wifi:
            link.wifi_ap_node_id = data.get("wifi_ap_node_id")
            link.wifi_ap_port_id = data.get("wifi_ap_port_id")
            link.wifi_client_node_id = data.get("wifi_client_node_id")
            link.wifi_client_port_id = data.get("wifi_client_port_id")

        return link

    def __str__(self) -> str:
        """Строковое представление связи."""
        return self.get_connection_info()

    def __repr__(self) -> str:
        """Представление для отладки."""
        return f"Link({self.get_connection_info()})"


# Константы для типов соединений
LINK_TYPE_P2P = "p2p"
LINK_TYPE_WIFI = "wifi"
LINK_TYPES = [LINK_TYPE_P2P, LINK_TYPE_WIFI]

# Типы портов для соединений
PORT_TYPE_ETHERNET = "ethernet"
PORT_TYPE_PON = "pon"
PORT_TYPE_WIFI = "wifi"
PORT_TYPE_USB = "usb"