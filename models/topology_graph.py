"""
Единый граф декомпозиции всей топологии — основа для волнового алгоритма.

Зачем нужен модуль
------------------
`models/threat_graph.py` строит граф одного узла и только ради отрисовки:
рёбра там прописаны частными правилами вида `if has_ethernet: add_edge(...)`.
Волновому алгоритму нужно другое — граф **всей** сети сразу, где вершины
компонентов разных узлов связаны через физические линии связи. Именно по
такому графу на эталонной схеме проложен маршрут χ3: он спускается по стеку
маршрутизатора, пересекает кабель и поднимается по стеку сервера.

Правило построения рёбер
------------------------
Взято с плаката «Модели определения объектов деструктивного воздействия»,
где каждое ребро таксономии подписано словом «Используется:»:

    магистраль между соседними уровнями   → «для прохождения»
    ответвление к конкретному протоколу   → «для подмены, для блокировки,
                                             для получения доступа»

То есть переходы идут между соседними уровнями стека в обе стороны, плюс
связи с подсистемами ядра ОС, аппаратным и пользовательским уровнями.

ЦО и ТрО
--------
Легенда плаката «Комплексные компьютерные атаки»: сплошной кружок — целевой
объект, пунктирный — транзитный. На графе одного АРМ (Grafy_1_ARM.jpg) точки
входа `ω1…ω7` помечены только ТрО, тупиковые компоненты — только ЦО,
всё остальное — «ЦО, ТрО». Отсюда правило:

    ТрО — если у вершины есть исходящие рёбра (угроза может пройти дальше)
    ЦО  — если вершина не является точкой входа (по ней можно ударить)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, TYPE_CHECKING

from models.osi_decomposition import (NodeDecomposition, OSILevel,
                                      level_code_for)

if TYPE_CHECKING:
    from models.node import Node
    from models.zone import Board

__all__ = [
    "TopologyVertex",
    "TopologyGraph",
    "build_topology_graph",
    "STACK_ORDER",
]


# Порядок уровней стека ЭМВОС снизу вверх. Волна поднимается по нему
# от точки входа и спускается обратно при переходе на соседний узел.
STACK_ORDER: List[str] = ["f", "z", "l", "t", "d", "r", "q"]

# Уровни, с которых угроза уходит в подсистемы ядра ОС
_NETWORK_LEVELS = ("z", "l", "t")

# Какие компоненты уровня передают данные дальше по стеку («несущие»),
# а какие являются только объектом воздействия.
#
# Различие взято с эталонного графа Grafy_1_ARM.jpg: там IEEE 802 (z1)
# и IPv4 (l2) помечены «ЦО, ТрО» и имеют исходящие стрелки, а MAC-адрес (z3),
# IP-адрес (l1) и ARP-таблица помечены только «ЦО» — угроза может по ним
# ударить, но пройти через них дальше нельзя: это атрибуты и структуры
# данных, а не протоколы переноса.
#
# None означает «все компоненты уровня являются несущими».
CARRIER_NAMES: Dict[str, Optional[Set[str]]] = {
    "f": None,                              # Все протоколы IEEE 802.x
    "z": {"ieee 802"},
    "l": {"ipv4", "ipv6", "ipsec"},
    "t": {"tcp", "udp", "sctp"},
    "d": None,                              # Сеансовые протоколы несут сессию
    "r": None,                              # Кодирование выполняется по пути
    "q": None,                              # Прикладное ПО — конечная точка стека
}


def _is_carrier(level_code: str, name: str) -> bool:
    """Передаёт ли компонент данные на следующий уровень стека."""
    allowed = CARRIER_NAMES.get(level_code, None)
    if allowed is None:
        return True
    low = name.strip().lower()
    return any(low.startswith(prefix) for prefix in allowed)


# Соответствие типа порта стандарту физического уровня. Порт Ethernet
# работает через IEEE 802.3 и не имеет отношения к Wi-Fi или WiMAX —
# без этого соответствия волна проходила через чужие стандарты, и в
# маршрутах появлялись бессмысленные шаги вида «IEEE 802.16» на узле,
# где есть только витая пара.
_PORT_MARKERS = (
    ("rj-45",     "ieee 802.3"),
    ("ethernet",  "ieee 802.3"),
    ("pon",       "ieee 802.3"),
    ("оптич",     "ieee 802.3"),
    ("wi-fi",     "ieee 802.11"),
    ("wifi",      "ieee 802.11"),
    ("bluetooth", "ieee 802.15"),
    ("wimax",     "ieee 802.16"),
    ("usb",       "usb"),
)


def _port_standard(port_name: str) -> str:
    """Стандарт физического уровня, соответствующий порту."""
    low = port_name.lower()
    for marker, standard in _PORT_MARKERS:
        if marker in low:
            return standard
    return ""


# ===================================================================
# Вершина графа
# ===================================================================

@dataclass
class TopologyVertex:
    """Компонент конкретного узла как вершина графа всей топологии.

    Attributes:
        id: Уникальный в пределах топологии идентификатор «<узел>::<компонент>»
        node_id: Идентификатор узла
        node_name: Имя узла для отображения
        node_type: Тип узла (ARM, Server, Router…)
        identifier: Идентификатор компонента в паспорте (t1.1, z4, а12.m)
        name: Наименование компонента
        level_code: Буквенный код уровня модели УБИ
        component_type: protocol, interface, subsystem, hardware, software…
        is_entry_point: True для физических портов — точек входа УБИ (ω)
        is_target: ЦО — по компоненту можно нанести удар
        is_transit: ТрО — угроза может пройти через компонент дальше
    """

    id: str
    node_id: str
    node_name: str
    node_type: str
    identifier: str
    name: str
    level_code: str
    component_type: str
    is_entry_point: bool = False
    is_target: bool = False
    is_transit: bool = False

    @property
    def role(self) -> str:
        """Подпись роли, как на эталонном графе: «ЦО», «ТрО» или «ЦО, ТрО»."""
        if self.is_target and self.is_transit:
            return "ЦО, ТрО"
        if self.is_target:
            return "ЦО"
        if self.is_transit:
            return "ТрО"
        return ""

    @property
    def title(self) -> str:
        """Читаемое имя вида «АРМ 1.1 · TCP»."""
        return f"{self.node_name} · {self.name}"


# ===================================================================
# Граф
# ===================================================================

@dataclass
class TopologyGraph:
    """Граф компонентов всей топологии со связями между узлами."""

    vertices: Dict[str, TopologyVertex] = field(default_factory=dict)
    adjacency: Dict[str, List[str]] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    # Компоненты каждого узла — для быстрой выборки
    by_node: Dict[str, List[str]] = field(default_factory=dict)

    # ----- Построение -----

    def add_vertex(self, vertex: TopologyVertex) -> None:
        """Добавляет вершину, если её ещё нет."""
        if vertex.id in self.vertices:
            return
        self.vertices[vertex.id] = vertex
        self.adjacency.setdefault(vertex.id, [])
        self.by_node.setdefault(vertex.node_id, []).append(vertex.id)
        if vertex.is_entry_point:
            self.entry_points.append(vertex.id)

    def connect(self, source: str, target: str, both: bool = True) -> None:
        """Соединяет вершины. По умолчанию в обе стороны.

        Угроза поднимается по стеку при приёме данных и спускается при
        передаче, поэтому переходы между уровнями двусторонние.
        """
        if source == target:
            return
        if source not in self.vertices or target not in self.vertices:
            return
        neighbours = self.adjacency.setdefault(source, [])
        if target not in neighbours:
            neighbours.append(target)
        if both:
            self.connect(target, source, both=False)

    # ----- Запросы -----

    @property
    def edge_count(self) -> int:
        """Число направленных рёбер."""
        return sum(len(v) for v in self.adjacency.values())

    def vertices_of_level(self, node_id: str, level_code: str) -> List[str]:
        """Вершины заданного уровня внутри одного узла."""
        return [vid for vid in self.by_node.get(node_id, [])
                if self.vertices[vid].level_code == level_code
                and not self.vertices[vid].is_entry_point]

    def targets(self) -> List[str]:
        """Все вершины, которые могут быть целевым объектом."""
        return [vid for vid, v in self.vertices.items() if v.is_target]

    def describe(self) -> str:
        """Краткая сводка — для журнала и отладки."""
        return (f"узлов {len(self.by_node)}, вершин {len(self.vertices)}, "
                f"рёбер {self.edge_count}, точек входа {len(self.entry_points)}")


# ===================================================================
# Сборка
# ===================================================================

def _make_vertex(node: "Node", comp, decomposition_cache: Dict) -> TopologyVertex:
    """Создаёт вершину из компонента разложения узла."""
    level_code = level_code_for(comp)
    is_entry = (comp.component_type == "interface"
                and comp.level is OSILevel.PHYSICAL)
    return TopologyVertex(
        id=f"{node.id}::{comp.identifier or comp.name}",
        node_id=node.id,
        node_name=node.name,
        node_type=node.type,
        identifier=comp.identifier or "",
        name=comp.name,
        level_code=level_code,
        component_type=comp.component_type,
        is_entry_point=is_entry,
    )


def _link_levels(graph: TopologyGraph, node_id: str,
                 lower: str, upper: str) -> None:
    """Соединяет соседние уровни стека по правилу несущих компонентов.

    Данные поднимаются только через несущие компоненты нижнего уровня.
    Дойдя до верхнего уровня, они попадают во все его компоненты, но
    дальше пойдут снова лишь через несущие:

        несущий(N) ↔ несущий(N+1)   — магистраль, в обе стороны
        несущий(N) → лист(N+1)      — только внутрь: пройти сквозь нельзя

    Односторонность рёбер к листьям и делает их «ЦО» без «ТрО», как
    на эталонном графе узла.
    """
    sources = [vid for vid in graph.vertices_of_level(node_id, lower)
               if _is_carrier(lower, graph.vertices[vid].name)]
    for target in graph.vertices_of_level(node_id, upper):
        target_is_carrier = _is_carrier(upper, graph.vertices[target].name)
        for source in sources:
            graph.connect(source, target, both=target_is_carrier)


def _build_node(graph: TopologyGraph, node: "Node") -> None:
    """Раскладывает узел на компоненты и связывает их внутри узла."""
    decomposition = NodeDecomposition(node)

    for level in OSILevel:
        for comp in decomposition.get_components_by_level(level):
            graph.add_vertex(_make_vertex(node, comp, {}))

    node_id = node.id

    # --- Точки входа: порт → свой стандарт физического уровня ---
    entry_ids = [vid for vid in graph.by_node.get(node_id, [])
                 if graph.vertices[vid].is_entry_point]
    physical = graph.vertices_of_level(node_id, "f")

    for entry in entry_ids:
        standard = _port_standard(graph.vertices[entry].name)
        matched = [vid for vid in physical
                   if standard
                   and graph.vertices[vid].name.lower().startswith(standard)]
        # Если стандарт не распознан или его нет среди компонентов —
        # соединяем со всем физическим уровнем, чтобы не разорвать граф
        for target in (matched or physical):
            graph.connect(entry, target)

    # Если физических протоколов нет вовсе, порт ведёт сразу на канальный
    if not physical:
        for entry in entry_ids:
            for target in graph.vertices_of_level(node_id, "z"):
                graph.connect(entry, target)

    # --- Магистраль стека ЭМВОС: f ↔ z ↔ l ↔ t ↔ d ↔ r ↔ q ---
    # Уровень может отсутствовать целиком (у коммутатора нет прикладного),
    # поэтому соединяются ближайшие непустые уровни — стек остаётся связным
    present = [code for code in STACK_ORDER
               if graph.vertices_of_level(node_id, code)]
    for lower, upper in zip(present, present[1:]):
        _link_levels(graph, node_id, lower, upper)

    # --- Подсистемы ядра ОС ---
    drivers = graph.vertices_of_level(node_id, "i")
    access = graph.vertices_of_level(node_id, "w")
    files = graph.vertices_of_level(node_id, "p")
    processes = graph.vertices_of_level(node_id, "v")

    # Сетевые уровни обращаются к драйверам, драйверы передают дальше —
    # в обе стороны, они транзитные
    for level_code in _NETWORK_LEVELS:
        for source in graph.vertices_of_level(node_id, level_code):
            if not _is_carrier(level_code, graph.vertices[source].name):
                continue
            for driver in drivers:
                graph.connect(source, driver)

    for driver in drivers:
        for target in access:
            graph.connect(driver, target)

    # Подсистемы управления файлами и процессами — тупиковые: на эталонном
    # графе p1 и v1 помечены только «ЦО». Ребро ведёт внутрь, но не наружу
    for controller in access:
        for target in files + processes:
            graph.connect(controller, target, both=False)

    # --- Аппаратный уровень: драйверы управляют железом ---
    hardware = graph.vertices_of_level(node_id, "a")
    for driver in drivers:
        for target in hardware:
            graph.connect(driver, target)

    # --- Пользовательский уровень ---
    # Периферия — тоже тупик: h1…h10 на эталонном графе помечены «ЦО».
    # Исключение — съёмные носители, они переносят угрозу дальше,
    # поэтому для них ребро двустороннее
    user = graph.vertices_of_level(node_id, "h")
    for target in user:
        removable = "носител" in graph.vertices[target].name.lower()
        for source in graph.vertices_of_level(node_id, "q"):
            graph.connect(source, target, both=removable)
        for driver in drivers:
            graph.connect(driver, target, both=removable)


def _port_vertex(graph: TopologyGraph, node: "Node",
                 port_id: str) -> Optional[str]:
    """Находит вершину точки входа, соответствующую порту узла."""
    entries = [vid for vid in graph.by_node.get(node.id, [])
               if graph.vertices[vid].is_entry_point]
    if not entries:
        return None

    port_name = ""
    for port in node.ports:
        if port.get("port_id") == port_id:
            port_name = port.get("name", "")
            break

    # Ищем по имени порта; если не нашли — берём первую точку входа узла
    return next((vid for vid in entries
                 if port_name and port_name in graph.vertices[vid].name),
                entries[0])


def _connect_nodes(graph: TopologyGraph, board: "Board",
                   skipped: Set[str]) -> None:
    """Связывает узлы через физические линии связи.

    Это единственные рёбра, выводящие волну за пределы узла — на эталонной
    схеме им соответствует шаг χ3.5, переход с порта маршрутизатора
    на порт сервера.

    Отдельно обрабатывается транзит через неразложенные узлы. «Интернет» —
    абстрактный провайдер без собственной архитектуры, он не раскладывается
    на компоненты, но именно через него на плакате соединены зоны ТИМ-1,
    ТИМ-2 и ТИМ-3. Если просто пропустить такой узел, граф распадётся
    на несвязные куски и волна застрянет в первой зоне. Поэтому всё, что
    подключено к цепочке пропущенных узлов, соединяется напрямую.
    """
    # --- Прямые связи между разложенными узлами ---
    for link in board.links:
        if link.a is None or link.b is None:
            continue
        if link.a.id in skipped or link.b.id in skipped:
            continue

        end_a = _port_vertex(graph, link.a, link.ports_connected.get("a", ""))
        end_b = _port_vertex(graph, link.b, link.ports_connected.get("b", ""))
        if end_a and end_b:
            graph.connect(end_a, end_b)

    if not skipped:
        return

    # --- Транзит через пропущенные узлы ---
    # Пропущенные узлы могут соединяться друг с другом, поэтому сначала
    # находим их связные группы, а потом сшиваем всё, что к группе подключено.
    transit_links: Dict[str, Set[str]] = {n: set() for n in skipped}
    attached: Dict[str, List[str]] = {n: [] for n in skipped}

    for link in board.links:
        if link.a is None or link.b is None:
            continue
        a_skipped, b_skipped = link.a.id in skipped, link.b.id in skipped
        if a_skipped and b_skipped:
            transit_links[link.a.id].add(link.b.id)
            transit_links[link.b.id].add(link.a.id)
        elif a_skipped or b_skipped:
            transit, real, port_key = ((link.a, link.b, "b") if a_skipped
                                       else (link.b, link.a, "a"))
            vertex = _port_vertex(graph, real,
                                  link.ports_connected.get(port_key, ""))
            if vertex:
                attached[transit.id].append(vertex)

    # Обход групп: все концы одной группы видят друг друга
    unvisited = set(skipped)
    while unvisited:
        stack = [unvisited.pop()]
        group_ends: List[str] = []
        while stack:
            current = stack.pop()
            group_ends.extend(attached.get(current, []))
            for neighbour in transit_links.get(current, ()):
                if neighbour in unvisited:
                    unvisited.discard(neighbour)
                    stack.append(neighbour)

        unique_ends = list(dict.fromkeys(group_ends))
        for i, source in enumerate(unique_ends):
            for target in unique_ends[i + 1:]:
                graph.connect(source, target)


def _mark_roles(graph: TopologyGraph) -> None:
    """Расставляет метки ЦО и ТрО по правилу эталонного графа."""
    for vertex_id, vertex in graph.vertices.items():
        vertex.is_transit = bool(graph.adjacency.get(vertex_id))
        vertex.is_target = not vertex.is_entry_point


def build_topology_graph(board: "Board",
                         skip_types: Sequence[str] = ("Internet",)
                         ) -> TopologyGraph:
    """Строит граф компонентов всей топологии.

    Args:
        board: Схема сети с узлами и связями
        skip_types: Типы узлов, которые не раскладываются на компоненты.
            «Интернет» — абстрактный узел-провайдер без собственной
            архитектуры, он служит источником угрозы, а не её объектом

    Returns:
        Граф, готовый для запуска волнового алгоритма
    """
    graph = TopologyGraph()

    skipped = {node.id for node in board.nodes if node.type in skip_types}
    for node in board.nodes:
        if node.id in skipped:
            continue
        _build_node(graph, node)

    _connect_nodes(graph, board, skipped)
    _mark_roles(graph)
    return graph
