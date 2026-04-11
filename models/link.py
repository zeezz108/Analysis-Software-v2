"""
Модуль модели связи (Link)

Содержит класс для представления соединения между двумя узлами.
Поддерживает:
- Точка-точка соединения (Ethernet, PON)
- Wi-Fi соединения (точка-многоточка)
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple, TYPE_CHECKING  # noqa: F401

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
        Рассчитывает координаты для отрисовки ортогональной линии.

        Путь строится только из сегментов под углом 90°.
        При наличии препятствий маршрут обходит их дополнительными поворотами
        под 90°, никогда не переходя в диагональ. Стремится к минимальному
        количеству углов и симметричному рисунку для симметричных расстановок.

        Args:
            canvas_view: Экземпляр CanvasView (нужен для получения границ иконок)
            link_index: Индекс этой линии среди линий на той же стороне узла
            total_links_on_side: Общее количество линий, выходящих с той же стороны

        Returns:
            Плоский список координат: [x1,y1, x2,y2, ...] + 6 дублей последней
            точки для обратной совместимости со старым кодом отрисовки.
        """
        a_bounds = canvas_view.get_icon_bounds(self.a)
        b_bounds = canvas_view.get_icon_bounds(self.b)

        ax, ay, aw, ah = a_bounds
        bx, by, bw, bh = b_bounds
        cx_a, cy_a = ax + aw / 2.0, ay + ah / 2.0
        cx_b, cy_b = bx + bw / 2.0, by + bh / 2.0

        dx = cx_b - cx_a
        dy = cy_b - cy_a

        # Стороны выхода/входа по доминирующей оси (детерминированно — для симметрии)
        if abs(dx) >= abs(dy):
            a_side = "right" if dx >= 0 else "left"
            b_side = "left" if dx >= 0 else "right"
        else:
            a_side = "bottom" if dy >= 0 else "top"
            b_side = "top" if dy >= 0 else "bottom"

        # Разведение параллельных линий на одной стороне узла
        if total_links_on_side > 1:
            spacing = 0.6 / total_links_on_side
            ratio = 0.2 + spacing * (link_index + 0.5)
        else:
            ratio = 0.5

        def edge_point(bounds, side, r):
            bx_, by_, bw_, bh_ = bounds
            if side == "right":
                return (bx_ + bw_, by_ + bh_ * r)
            if side == "left":
                return (bx_, by_ + bh_ * r)
            if side == "bottom":
                return (bx_ + bw_ * r, by_ + bh_)
            return (bx_ + bw_ * r, by_)

        def dir_of(side):
            return {"right": (1, 0), "left": (-1, 0),
                    "bottom": (0, 1), "top": (0, -1)}[side]

        a_pt = edge_point(a_bounds, a_side, ratio)
        b_pt = edge_point(b_bounds, b_side, ratio)
        a_dir = dir_of(a_side)
        b_dir = dir_of(b_side)

        stub = 10
        a1 = (a_pt[0] + a_dir[0] * stub, a_pt[1] + a_dir[1] * stub)
        b1 = (b_pt[0] + b_dir[0] * stub, b_pt[1] + b_dir[1] * stub)

        horizontal_exit = a_dir[0] != 0  # линия выходит по горизонтали

        # Равномерное смещение для параллельных линий — сохраняет симметрию
        spread = 0.0
        if total_links_on_side > 1:
            spread = (link_index - (total_links_on_side - 1) / 2.0) * 12.0

        # Базовый путь: Z-образный (2 поворота) либо прямая (0 поворотов)
        middle: List[Tuple[float, float]] = []
        if horizontal_exit:
            if abs(a1[1] - b1[1]) < 0.5:
                # a1 и b1 на одной горизонтали — прямой путь
                pass
            else:
                mid_x = (a1[0] + b1[0]) / 2.0 + spread
                middle.append((mid_x, a1[1]))
                middle.append((mid_x, b1[1]))
        else:
            if abs(a1[0] - b1[0]) < 0.5:
                pass
            else:
                mid_y = (a1[1] + b1[1]) / 2.0 + spread
                middle.append((a1[0], mid_y))
                middle.append((b1[0], mid_y))

        points: List[Tuple[float, float]] = [a_pt, a1] + middle + [b1, b_pt]

        # Собираем препятствия (иконки других узлов)
        obstacles: List[Tuple[float, float, float, float]] = []
        margin = 4
        if hasattr(canvas_view, "board"):
            for node in canvas_view.board.nodes:
                if node.id == self.a.id or node.id == self.b.id:
                    continue
                nb = canvas_view.get_icon_bounds(node)
                obstacles.append((
                    nb[0] - margin, nb[1] - margin,
                    nb[0] + nb[2] + margin, nb[1] + nb[3] + margin
                ))

        if obstacles:
            points = self._route_around_obstacles(points, obstacles, horizontal_exit)

        # Плоский список координат + 6 дублей последней точки (совместимость)
        flat: List[float] = []
        for p in points:
            flat.extend([p[0], p[1]])
        last = points[-1] if points else (0.0, 0.0)
        flat += [last[0], last[1], last[0], last[1], last[0], last[1]]
        return flat

    @staticmethod
    def _segment_intersects_rect(p1: Tuple[float, float], p2: Tuple[float, float],
                                  rect: Tuple[float, float, float, float]) -> bool:
        """Проверяет пересечение ортогонального отрезка p1->p2 с прямоугольником rect."""
        rx1, ry1, rx2, ry2 = rect
        x1, y1 = p1
        x2, y2 = p2

        # Горизонтальный отрезок
        if abs(y1 - y2) < 0.5:
            if ry1 < y1 < ry2:
                seg_min_x = min(x1, x2)
                seg_max_x = max(x1, x2)
                return seg_min_x < rx2 and seg_max_x > rx1
            return False

        # Вертикальный отрезок
        if abs(x1 - x2) < 0.5:
            if rx1 < x1 < rx2:
                seg_min_y = min(y1, y2)
                seg_max_y = max(y1, y2)
                return seg_min_y < ry2 and seg_max_y > ry1
            return False

        return False

    def _any_intersects(self, p1: Tuple[float, float], p2: Tuple[float, float],
                        obstacles: List[Tuple[float, float, float, float]]) -> bool:
        return any(self._segment_intersects_rect(p1, p2, o) for o in obstacles)

    def _route_around_obstacles(self,
                                 points: List[Tuple[float, float]],
                                 obstacles: List[Tuple[float, float, float, float]],
                                 horizontal_exit: bool) -> List[Tuple[float, float]]:
        """Корректирует серединные сегменты пути, обходя препятствия.

        Сохраняет точки-заглушки (первый/последний индекс и их стубы),
        а также строго ортогональность: при сдвиге серединного сегмента
        двигает одинаковую координату обоих его концов, не затрагивая
        соседние сегменты (они продолжают быть горизонтальными/вертикальными).
        """
        result = list(points)

        # --- Случай 1: Z-образный путь (6 точек, 2 поворота) ---
        if len(result) == 6:
            # Серединный сегмент: result[2] <-> result[3]
            a1 = result[1]
            b1 = result[4]
            mid1 = result[2]
            mid2 = result[3]

            # Проверяем все три средних сегмента
            seg1 = (a1, mid1)       # горизонт. при horizontal_exit, верт. иначе
            seg_mid = (mid1, mid2)  # вертикаль при horizontal_exit, горизонт. иначе
            seg2 = (mid2, b1)       # горизонт. при horizontal_exit, верт. иначе

            blocked_mid = self._any_intersects(*seg_mid, obstacles)
            blocked_seg1 = self._any_intersects(*seg1, obstacles)
            blocked_seg2 = self._any_intersects(*seg2, obstacles)

            if blocked_mid and not blocked_seg1 and not blocked_seg2:
                # Сдвигаем середину Z, сохраняя ортогональность соседних сегментов
                if horizontal_exit:
                    # Серединный сегмент вертикальный: ищем свободный X
                    new_x = self._find_clear_mid(
                        axis="x",
                        seg_start=mid1, seg_end=mid2,
                        neighbors=[(a1, None), (b1, None)],
                        obstacles=obstacles,
                        original=mid1[0]
                    )
                    if new_x is not None:
                        result[2] = (new_x, mid1[1])
                        result[3] = (new_x, mid2[1])
                else:
                    # Серединный сегмент горизонтальный: ищем свободный Y
                    new_y = self._find_clear_mid(
                        axis="y",
                        seg_start=mid1, seg_end=mid2,
                        neighbors=[(a1, None), (b1, None)],
                        obstacles=obstacles,
                        original=mid1[1]
                    )
                    if new_y is not None:
                        result[2] = (mid1[0], new_y)
                        result[3] = (mid2[0], new_y)
                return result

            if blocked_seg1 or blocked_seg2 or blocked_mid:
                # Сложный случай — пробуем U-образный обход через дополнительные повороты
                detoured = self._build_detour(result[0], result[1], result[4], result[5],
                                                obstacles, horizontal_exit)
                if detoured is not None:
                    return detoured
                # Не удалось — возвращаем как есть (всё равно 90°)
                return result

        # --- Случай 2: прямой путь (4 точки, 0 поворотов) ---
        if len(result) == 4:
            a1 = result[1]
            b1 = result[2]
            if self._any_intersects(a1, b1, obstacles):
                detoured = self._build_detour(result[0], a1, b1, result[3], obstacles, horizontal_exit)
                if detoured is not None:
                    return detoured

        return result

    def _find_clear_mid(self, axis: str,
                        seg_start: Tuple[float, float],
                        seg_end: Tuple[float, float],
                        neighbors: List[Tuple[Tuple[float, float], Any]],
                        obstacles: List[Tuple[float, float, float, float]],
                        original: float) -> Optional[float]:
        """Подбирает координату для сдвига серединного сегмента,
        минимизируя смещение и сохраняя ортогональность.
        """
        # Кандидаты: обойти каждое препятствие слева/справа (или сверху/снизу)
        candidates = [original]
        pad = 8
        for rx1, ry1, rx2, ry2 in obstacles:
            if axis == "x":
                candidates.append(rx1 - pad)
                candidates.append(rx2 + pad)
            else:
                candidates.append(ry1 - pad)
                candidates.append(ry2 + pad)

        # Сортируем по расстоянию от исходной координаты — ближайший подходящий
        candidates.sort(key=lambda v: abs(v - original))

        for v in candidates:
            if axis == "x":
                new_mid1 = (v, seg_start[1])
                new_mid2 = (v, seg_end[1])
            else:
                new_mid1 = (seg_start[0], v)
                new_mid2 = (seg_end[0], v)

            # Проверяем серединный сегмент
            if self._any_intersects(new_mid1, new_mid2, obstacles):
                continue
            # Соседние сегменты: от a1 до new_mid1 и от new_mid2 до b1
            a1 = neighbors[0][0]
            b1 = neighbors[1][0]
            if self._any_intersects(a1, new_mid1, obstacles):
                continue
            if self._any_intersects(new_mid2, b1, obstacles):
                continue
            return v
        return None

    def _build_detour(self,
                       a_pt: Tuple[float, float],
                       a1: Tuple[float, float],
                       b1: Tuple[float, float],
                       b_pt: Tuple[float, float],
                       obstacles: List[Tuple[float, float, float, float]],
                       horizontal_exit: bool) -> Optional[List[Tuple[float, float]]]:
        """Строит U-образный обход через препятствия (4 поворота)
        с сохранением строгой ортогональности.
        """
        pad = 8

        if horizontal_exit:
            # Маршрут: a_pt -> a1 -> (a1.x+dx_extend, a1.y) -> (..., detour_y)
            #          -> (b1.x-dx_retract, detour_y) -> (b1.x-..., b1.y) -> b1 -> b_pt
            # Проще: выход по горизонтали, детур по Y через крайнюю позицию
            detour_y_candidates = [a1[1], b1[1]]
            min_y = min((o[1] for o in obstacles), default=a1[1])
            max_y = max((o[3] for o in obstacles), default=a1[1])
            detour_y_candidates.append(min_y - pad * 3)
            detour_y_candidates.append(max_y + pad * 3)

            for dy_val in sorted(detour_y_candidates, key=lambda v: abs(v - (a1[1] + b1[1]) / 2.0)):
                # Путь: a_pt, a1, (a1.x, dy_val), (b1.x, dy_val), b1, b_pt
                p1 = a1
                p2 = (a1[0], dy_val)
                p3 = (b1[0], dy_val)
                p4 = b1
                if (not self._any_intersects(p1, p2, obstacles) and
                    not self._any_intersects(p2, p3, obstacles) and
                    not self._any_intersects(p3, p4, obstacles)):
                    return [a_pt, a1, p2, p3, b1, b_pt]
        else:
            detour_x_candidates = [a1[0], b1[0]]
            min_x = min((o[0] for o in obstacles), default=a1[0])
            max_x = max((o[2] for o in obstacles), default=a1[0])
            detour_x_candidates.append(min_x - pad * 3)
            detour_x_candidates.append(max_x + pad * 3)

            for dx_val in sorted(detour_x_candidates, key=lambda v: abs(v - (a1[0] + b1[0]) / 2.0)):
                p1 = a1
                p2 = (dx_val, a1[1])
                p3 = (dx_val, b1[1])
                p4 = b1
                if (not self._any_intersects(p1, p2, obstacles) and
                    not self._any_intersects(p2, p3, obstacles) and
                    not self._any_intersects(p3, p4, obstacles)):
                    return [a_pt, a1, p2, p3, b1, b_pt]
        return None

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