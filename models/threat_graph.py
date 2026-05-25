"""
Модуль построения графа угроз безопасности для узла сети.

Строит ориентированный граф, где:
- Вершины — компоненты узла, распределённые по уровням ЭМВОС + доп. уровни
- Рёбра — пути распространения угроз с маркировкой типа (ЦО, ТрО, ПО)

Все уровни развёрнуты горизонтально (слева направо).
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import IntEnum

from models.node import Node


# ============================================================================
# Типы угроз на рёбрах
# ============================================================================

class ThreatType:
    """Типы угроз (маркировка рёбер)."""
    CO = "ЦО"       # Целостность Обработки
    TRO = "ТрО"     # Транспортная Обработка
    PO = "ПО"       # Порядок Обработки
    CO_TRO = "ЦО,ТрО"  # Комбинация


# ============================================================================
# Уровни графа (порядок слева направо)
# ============================================================================

class GraphLevel(IntEnum):
    """Уровни графа угроз (горизонтальный порядок)."""
    ENTRY_POINT = 0       # Точки входа (ω) — физ. порты
    PHYSICAL = 1          # Физический уровень (f)
    DATA_LINK = 2         # Канальный уровень (z)
    NETWORK = 3           # Сетевой уровень (l)
    DRIVERS = 4           # Драйверы (i) — подсистема ОС
    ACCESS_CONTROL = 5    # Модели разграничения доступа (w)
    FILE_SYSTEM = 6       # Подсистема управления файлами (p)
    PROCESS_MGMT = 7      # Подсистема управления процессами (v)
    TRANSPORT = 8         # Транспортный уровень (t)
    SESSION = 9           # Сеансовый уровень (d)
    PRESENTATION = 10     # Уровень представления (r)
    APPLICATION = 11      # Прикладной уровень (q)
    NET_APPS = 12         # Сетевые приложения (a.m)
    HARDWARE = 13         # Аппаратный уровень (h)
    USER = 14             # Пользовательский уровень


LEVEL_LABELS = {
    GraphLevel.ENTRY_POINT: "Точки входа",
    GraphLevel.PHYSICAL: "Физический\nуровень",
    GraphLevel.DATA_LINK: "Канальный\nуровень",
    GraphLevel.NETWORK: "Сетевой\nуровень",
    GraphLevel.DRIVERS: "Драйверы",
    GraphLevel.ACCESS_CONTROL: "Разграничение\nдоступа",
    GraphLevel.FILE_SYSTEM: "Управление\nфайлами",
    GraphLevel.PROCESS_MGMT: "Управление\nпроцессами",
    GraphLevel.TRANSPORT: "Транспортный\nуровень",
    GraphLevel.SESSION: "Сеансовый\nуровень",
    GraphLevel.PRESENTATION: "Уровень\nпредставления",
    GraphLevel.APPLICATION: "Прикладной\nуровень",
    GraphLevel.NET_APPS: "Сетевые\nприложения",
    GraphLevel.HARDWARE: "Аппаратный\nуровень",
    GraphLevel.USER: "Пользовательский\nуровень",
}

# Краткие префиксы для идентификаторов вершин
LEVEL_PREFIXES = {
    GraphLevel.ENTRY_POINT: "ω",
    GraphLevel.PHYSICAL: "f",
    GraphLevel.DATA_LINK: "z",
    GraphLevel.NETWORK: "l",
    GraphLevel.DRIVERS: "i",
    GraphLevel.ACCESS_CONTROL: "w",
    GraphLevel.FILE_SYSTEM: "p",
    GraphLevel.PROCESS_MGMT: "v",
    GraphLevel.TRANSPORT: "t",
    GraphLevel.SESSION: "d",
    GraphLevel.PRESENTATION: "r",
    GraphLevel.APPLICATION: "q",
    GraphLevel.NET_APPS: "a",
    GraphLevel.HARDWARE: "h",
    GraphLevel.USER: "u",
}


# ============================================================================
# Вершина и ребро графа
# ============================================================================

@dataclass
class GraphVertex:
    """Вершина графа угроз."""
    id: str                     # Уникальный ID (например "ω1", "f2.1")
    label: str                  # Подпись (например "ETH1", "TCP")
    level: GraphLevel           # Уровень
    description: str = ""       # Подробное описание
    component_name: str = ""    # Имя компонента из Node (для связки с CVE)


@dataclass
class GraphEdge:
    """Ребро графа угроз (направленное)."""
    source_id: str              # ID вершины-источника
    target_id: str              # ID вершины-цели
    threat_types: List[str] = field(default_factory=list)  # ["ЦО", "ТрО", ...]


@dataclass
class ThreatGraph:
    """Полный граф угроз для одного узла."""
    node_name: str
    node_type: str
    vertices: List[GraphVertex] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def get_vertices_by_level(self, level: GraphLevel) -> List[GraphVertex]:
        """Возвращает все вершины данного уровня."""
        return [v for v in self.vertices if v.level == level]

    def get_used_levels(self) -> List[GraphLevel]:
        """Возвращает список уровней, где есть хотя бы одна вершина."""
        levels = sorted(set(v.level for v in self.vertices))
        return levels


# ============================================================================
# Построитель графа
# ============================================================================

class ThreatGraphBuilder:
    """Строит граф угроз из данных узла (Node)."""

    def __init__(self, node: Node):
        self.node = node
        self.vertices: List[GraphVertex] = []
        self.edges: List[GraphEdge] = []
        self._counters: Dict[GraphLevel, int] = {}

    def build(self) -> ThreatGraph:
        """Основной метод — строит полный граф."""
        self._build_entry_points()
        self._build_physical()
        self._build_data_link()
        self._build_network()
        self._build_os_subsystems()
        self._build_transport()
        self._build_session()
        self._build_presentation()
        self._build_application()
        self._build_net_apps()
        self._build_hardware()
        self._build_user()
        self._build_edges()

        return ThreatGraph(
            node_name=self.node.name,
            node_type=self.node.type,
            vertices=self.vertices,
            edges=self.edges,
        )

    # ------------------------------------------------------------------
    # Генерация ID
    # ------------------------------------------------------------------

    def _next_id(self, level: GraphLevel) -> str:
        """Генерирует следующий ID для уровня (ω1, ω2, f1, f2, ...)."""
        count = self._counters.get(level, 0) + 1
        self._counters[level] = count
        prefix = LEVEL_PREFIXES[level]
        return f"{prefix}{count}"

    def _add_vertex(self, level: GraphLevel, label: str,
                    description: str = "", component_name: str = "") -> GraphVertex:
        """Добавляет вершину и возвращает её."""
        v = GraphVertex(
            id=self._next_id(level),
            label=label,
            level=level,
            description=description,
            component_name=component_name,
        )
        self.vertices.append(v)
        return v

    def _add_edge(self, source_id: str, target_id: str, threats: List[str]):
        """Добавляет ребро."""
        self.edges.append(GraphEdge(source_id, target_id, threats))

    # ------------------------------------------------------------------
    # Уровень: Точки входа (ω)
    # ------------------------------------------------------------------

    def _build_entry_points(self):
        """Точки входа — физические порты узла."""
        for port in self.node.ports:
            port_name = port.get("name", "Port")
            port_type = port.get("port_type", "ethernet")
            self._add_vertex(
                GraphLevel.ENTRY_POINT,
                label=port_name,
                description=f"Порт {port_name} ({port_type})",
            )

    # ------------------------------------------------------------------
    # Уровень: Физический (f)
    # ------------------------------------------------------------------

    def _build_physical(self):
        """Физический уровень — сетевые адаптеры, физические интерфейсы."""
        # Сетевые адаптеры из hardware
        for item in self.node.properties.get("hardware", []):
            if item.startswith("Сетевой адаптер:"):
                name = item.split(":", 1)[1].strip()
                display = name.split("||")[0].strip().rstrip("- ")
                self._add_vertex(
                    GraphLevel.PHYSICAL,
                    label=display[:30],
                    description=f"Сетевой адаптер: {display}",
                    component_name=name,
                )

        # Если нет явных адаптеров — генерируем по портам
        phys_vertices = [v for v in self.vertices if v.level == GraphLevel.PHYSICAL]
        if not phys_vertices:
            port_types_seen = set()
            for port in self.node.ports:
                pt = port.get("port_type", "ethernet")
                if pt not in port_types_seen and pt != "usb":
                    port_types_seen.add(pt)
                    label = {"ethernet": "Ethernet PHY",
                             "pon": "PON PHY",
                             "wifi": "Wi-Fi PHY"}.get(pt, f"{pt} PHY")
                    self._add_vertex(
                        GraphLevel.PHYSICAL,
                        label=label,
                        description=f"Физический интерфейс {pt}",
                    )

    # ------------------------------------------------------------------
    # Уровень: Канальный (z)
    # ------------------------------------------------------------------

    def _build_data_link(self):
        """Канальный уровень — протоколы L2."""
        has_ethernet = any(p.get("port_type") == "ethernet" for p in self.node.ports)
        has_wifi = any(p.get("port_type") == "wifi" for p in self.node.ports)
        has_pon = any(p.get("port_type") == "pon" for p in self.node.ports)
        has_vlan = any(p.get("vlan_id") for p in self.node.ports)

        if has_ethernet:
            self._add_vertex(GraphLevel.DATA_LINK, "IEEE 802.3",
                             "Протокол Ethernet")
        if has_wifi:
            self._add_vertex(GraphLevel.DATA_LINK, "IEEE 802.11",
                             "Протокол Wi-Fi")
        if has_pon:
            self._add_vertex(GraphLevel.DATA_LINK, "IEEE 802.3ah",
                             "Протокол PON")
        if has_vlan:
            self._add_vertex(GraphLevel.DATA_LINK, "IEEE 802.1Q",
                             "Протокол VLAN")

        # ARP всегда есть если есть MAC-адреса
        has_mac = any(p.get("mac_address") for p in self.node.ports)
        if has_mac:
            self._add_vertex(GraphLevel.DATA_LINK, "ARP",
                             "Address Resolution Protocol")

    # ------------------------------------------------------------------
    # Уровень: Сетевой (l)
    # ------------------------------------------------------------------

    def _build_network(self):
        """Сетевой уровень — IP, ICMP, маршрутизация."""
        has_ip = any(p.get("ip_address") for p in self.node.ports)

        if has_ip:
            self._add_vertex(GraphLevel.NETWORK, "IPv4",
                             "Internet Protocol v4")
            self._add_vertex(GraphLevel.NETWORK, "ICMP",
                             "Internet Control Message Protocol")

        # Маршрутизация
        if self.node.routing_table:
            self._add_vertex(GraphLevel.NETWORK, "Маршрутизация",
                             "Таблица маршрутизации")

        # NAT (для маршрутизаторов)
        if self.node.type == "Router":
            self._add_vertex(GraphLevel.NETWORK, "NAT",
                             "Network Address Translation")

    # ------------------------------------------------------------------
    # Подсистемы ОС (драйверы, разграничение доступа, файлы, процессы)
    # ------------------------------------------------------------------

    def _build_os_subsystems(self):
        """Подсистемы ядра ОС."""
        os_name = self._get_os_name()
        if not os_name and self.node.type in ("Internet", "Switch"):
            return

        # Драйверы — по одному на каждый тип порта + GPU
        port_types = set(p.get("port_type", "") for p in self.node.ports)
        driver_map = {
            "ethernet": "Драйвер Ethernet",
            "wifi": "Драйвер Wi-Fi",
            "pon": "Драйвер PON",
            "usb": "Драйвер USB",
        }
        for pt in sorted(port_types):
            if pt in driver_map:
                self._add_vertex(GraphLevel.DRIVERS, driver_map[pt],
                                 f"Драйвер для интерфейса {pt}")

        # Драйвер GPU
        has_gpu = any(item.startswith("Видеоконтроллер:")
                      for item in self.node.properties.get("hardware", []))
        if has_gpu:
            self._add_vertex(GraphLevel.DRIVERS, "Драйвер GPU",
                             "Драйвер видеоконтроллера")

        # Драйвер накопителя
        has_storage = any(item.startswith("HDD/SSD:")
                          for item in self.node.properties.get("hardware", []))
        if has_storage:
            self._add_vertex(GraphLevel.DRIVERS, "Драйвер HDD/SSD",
                             "Драйвер накопителя данных")

        # Контроль доступа, Файловая система, Управление процессами —
        # убраны: это предполагаемые подсистемы ОС, не реальные компоненты узла.

    # ------------------------------------------------------------------
    # Уровень: Транспортный (t)
    # ------------------------------------------------------------------

    def _build_transport(self):
        """Транспортный уровень — TCP, UDP."""
        has_ip = any(p.get("ip_address") for p in self.node.ports)
        if has_ip:
            self._add_vertex(GraphLevel.TRANSPORT, "TCP",
                             "Transmission Control Protocol")
            self._add_vertex(GraphLevel.TRANSPORT, "UDP",
                             "User Datagram Protocol")

    # ------------------------------------------------------------------
    # Уровень: Сеансовый (d)
    # ------------------------------------------------------------------

    def _build_session(self):
        """Сеансовый уровень — только реально настроенные компоненты."""
        # VPN — только если явно включён на узле
        if self.node.vpn_client_enabled or self.node.vpn_server_enabled:
            protocol = (self.node.vpn_client_protocol
                        if self.node.vpn_client_enabled
                        else self.node.vpn_server_protocol)
            self._add_vertex(GraphLevel.SESSION, f"VPN ({protocol})",
                             f"VPN-туннель: {protocol}")

    # ------------------------------------------------------------------
    # Уровень: Представления (r)
    # ------------------------------------------------------------------

    def _build_presentation(self):
        """Уровень представления — только реально установленное ПО."""
        # СЗИ (антивирус и т.п.) — только если явно в software
        for item in self.node.properties.get("software", []):
            if item.startswith("СЗИ:"):
                name = item.split(":", 1)[1].strip()
                display = name.split("||")[0].strip().rstrip("- ")
                self._add_vertex(
                    GraphLevel.PRESENTATION, display[:25],
                    description=f"СЗИ: {display}",
                    component_name=name,
                )

    # ------------------------------------------------------------------
    # Уровень: Прикладной (q)
    # ------------------------------------------------------------------

    def _build_application(self):
        """Прикладной уровень — пользовательское ПО."""
        software = self.node.properties.get("software", [])

        for item in software:
            # Пропускаем ОС, периферию, драйверы, СЗИ — они на других уровнях
            if (item.startswith("ОС:") or
                    item.startswith(("Мышь:", "Клавиатура:", "Принтер:", "Монитор:")) or
                    "драйвер" in item.lower() or "driver" in item.lower() or
                    item.startswith("СЗИ:")):
                continue

            if item.startswith("Приложение:"):
                name = item.split(":", 1)[1].strip()
                display = name.split("||")[0].strip().rstrip("- ")
                self._add_vertex(
                    GraphLevel.APPLICATION, display[:25],
                    description=f"Приложение: {display}",
                    component_name=name,
                )
            elif item.startswith("Браузер:"):
                name = item.split(":", 1)[1].strip()
                display = name.split("||")[0].strip().rstrip("- ")
                self._add_vertex(
                    GraphLevel.APPLICATION, display[:25],
                    description=f"Браузер: {display}",
                    component_name=name,
                )
            elif item.startswith("СУБД:"):
                name = item.split(":", 1)[1].strip()
                display = name.split("||")[0].strip().rstrip("- ")
                self._add_vertex(
                    GraphLevel.APPLICATION, display[:25],
                    description=f"СУБД: {display}",
                    component_name=name,
                )

    # ------------------------------------------------------------------
    # Уровень: Сетевые приложения (a.m)
    # ------------------------------------------------------------------

    def _build_net_apps(self):
        """Сетевые приложения — убраны: это предполагаемые службы,
        не реальные компоненты узла."""
        pass

    # ------------------------------------------------------------------
    # Уровень: Аппаратный (h)
    # ------------------------------------------------------------------

    def _build_hardware(self):
        """Аппаратный уровень — железо."""
        hw_prefixes = {
            "Процессор:": "CPU",
            "Видеоконтроллер:": "GPU",
            "Материнская плата:": "MB",
            "HDD/SSD:": "HDD/SSD",
            "Чипсет:": "Чипсет",
            "Платформа:": "Платформа",
            "Серверная платформа:": "Платформа",
        }

        for item in self.node.properties.get("hardware", []):
            # Сетевые адаптеры уже на физическом уровне
            if item.startswith("Сетевой адаптер:"):
                continue

            for prefix, short in hw_prefixes.items():
                if item.startswith(prefix):
                    name = item.split(":", 1)[1].strip()
                    display = name.split("||")[0].strip().rstrip("- ")
                    self._add_vertex(
                        GraphLevel.HARDWARE, f"{short}: {display[:20]}",
                        description=f"{prefix} {display}",
                        component_name=name,
                    )
                    break

    # ------------------------------------------------------------------
    # Уровень: Пользовательский (u)
    # ------------------------------------------------------------------

    def _build_user(self):
        """Пользовательский уровень — периферия."""
        periph_prefixes = {
            "Мышь:": "Мышь",
            "Клавиатура:": "Клавиатура",
            "Принтер:": "Принтер",
            "Монитор:": "Монитор",
        }

        for item in self.node.properties.get("software", []):
            for prefix, short in periph_prefixes.items():
                if item.startswith(prefix):
                    name = item.split(":", 1)[1].strip()
                    display = name.split("||")[0].strip().rstrip("- ")
                    self._add_vertex(
                        GraphLevel.USER, f"{short}: {display[:20]}",
                        description=f"{prefix} {display}",
                        component_name=name,
                    )
                    break

    # ------------------------------------------------------------------
    # Построение рёбер — ЛОГИЧЕСКИЕ связи (не все-ко-всем)
    # ------------------------------------------------------------------

    def _build_edges(self):
        """Строит рёбра графа на основе ЛОГИЧЕСКИХ связей между компонентами.

        Каждое ребро имеет реальный смысл:
        - IPv4 → Драйвер Ethernet (а не → Драйвер GPU)
        - GPU → Драйвер GPU (а не → Драйвер Ethernet)
        и т.д.
        """

        # --- Вспомогательные: получить вершины по уровню и подстроке ---

        def by_level(level: GraphLevel) -> List[GraphVertex]:
            return [v for v in self.vertices if v.level == level]

        def find(level: GraphLevel, *keywords) -> Optional[GraphVertex]:
            """Находит первую вершину на уровне, label которой содержит keyword."""
            for v in self.vertices:
                if v.level == level:
                    lbl = v.label.lower()
                    for kw in keywords:
                        if kw.lower() in lbl:
                            return v
            return None

        def find_all(level: GraphLevel, *keywords) -> List[GraphVertex]:
            """Находит все вершины на уровне, чей label содержит любой keyword."""
            result = []
            for v in self.vertices:
                if v.level == level:
                    lbl = v.label.lower()
                    for kw in keywords:
                        if kw.lower() in lbl:
                            result.append(v)
                            break
            return result

        # === 1. Точки входа (ω) → Физический (f) ===
        # Каждый порт → соответствующий физический адаптер
        entry_verts = by_level(GraphLevel.ENTRY_POINT)
        phys_verts = by_level(GraphLevel.PHYSICAL)
        for ev in entry_verts:
            port_type = ev.label.lower()
            matched = False
            for pv in phys_verts:
                pl = pv.label.lower()
                # ETH → Ethernet PHY / Intel Ethernet...
                if ("eth" in port_type and
                        ("ethernet" in pl or "phy" in pl)):
                    self._add_edge(ev.id, pv.id, [ThreatType.TRO])
                    matched = True
                    break
                elif ("wifi" in port_type and
                      ("wi-fi" in pl or "wifi" in pl or "wireless" in pl)):
                    self._add_edge(ev.id, pv.id, [ThreatType.TRO])
                    matched = True
                    break
                elif ("pon" in port_type and "pon" in pl):
                    self._add_edge(ev.id, pv.id, [ThreatType.TRO])
                    matched = True
                    break
            # Fallback: если не нашли точного — к первому
            if not matched and phys_verts:
                self._add_edge(ev.id, phys_verts[0].id, [ThreatType.TRO])

        # === 2. Физический (f) → Канальный (z) ===
        # Ethernet PHY / сетевой адаптер → 802.3, ARP
        # Wi-Fi PHY → 802.11
        for pv in phys_verts:
            pl = pv.label.lower()
            desc = pv.description.lower()
            is_ethernet = ("ethernet" in pl or "phy" in pl
                           or "сетевой адаптер" in desc)
            is_wifi = "wi-fi" in pl or "wifi" in pl or "wireless" in pl
            is_pon = "pon" in pl
            if is_ethernet and not is_wifi and not is_pon:
                for target in ["802.3", "arp"]:
                    dv = find(GraphLevel.DATA_LINK, target)
                    if dv:
                        self._add_edge(pv.id, dv.id, [ThreatType.CO, ThreatType.TRO])
            if is_wifi:
                dv = find(GraphLevel.DATA_LINK, "802.11")
                if dv:
                    self._add_edge(pv.id, dv.id, [ThreatType.CO, ThreatType.TRO])
            if is_pon:
                dv = find(GraphLevel.DATA_LINK, "802.3ah")
                if dv:
                    self._add_edge(pv.id, dv.id, [ThreatType.CO, ThreatType.TRO])

        # === 3. Канальный (z) → Сетевой (l) ===
        # 802.3/802.11 → IPv4; ARP → IPv4
        dl_verts = by_level(GraphLevel.DATA_LINK)
        ipv4 = find(GraphLevel.NETWORK, "ipv4")
        icmp = find(GraphLevel.NETWORK, "icmp")
        for dv in dl_verts:
            if ipv4:
                self._add_edge(dv.id, ipv4.id, [ThreatType.CO, ThreatType.TRO])
            # ICMP только от основных протоколов (не ARP)
            if icmp and "arp" not in dv.label.lower():
                self._add_edge(dv.id, icmp.id, [ThreatType.CO, ThreatType.TRO])

        # === 4. Сетевой (l) → сетевые Драйверы (i) ===
        # IPv4/ICMP → Драйвер Ethernet, Драйвер Wi-Fi, Драйвер PON
        net_drivers = find_all(GraphLevel.DRIVERS,
                               "ethernet", "wi-fi", "pon")
        net_verts = by_level(GraphLevel.NETWORK)
        for nv in net_verts:
            for nd in net_drivers:
                self._add_edge(nv.id, nd.id, [ThreatType.CO, ThreatType.TRO])

        # === 5. Сетевой (l) → Транспортный (t) ===
        # IPv4 → TCP, UDP
        if ipv4:
            tcp = find(GraphLevel.TRANSPORT, "tcp")
            udp = find(GraphLevel.TRANSPORT, "udp")
            if tcp:
                self._add_edge(ipv4.id, tcp.id, [ThreatType.CO, ThreatType.TRO])
            if udp:
                self._add_edge(ipv4.id, udp.id, [ThreatType.CO, ThreatType.TRO])

        # === 6. Сетевые драйверы → Контроль доступа (w) ===
        access = find(GraphLevel.ACCESS_CONTROL, "контроль", "доступ")
        if access:
            for nd in net_drivers:
                self._add_edge(nd.id, access.id, [ThreatType.CO, ThreatType.TRO])

        # === 7. Контроль доступа → Файловая система, Процессы ===
        fs = find(GraphLevel.FILE_SYSTEM, "файл")
        pm = find(GraphLevel.PROCESS_MGMT, "процесс")
        if access:
            if fs:
                self._add_edge(access.id, fs.id, [ThreatType.PO])
            if pm:
                self._add_edge(access.id, pm.id, [ThreatType.PO])

        # === 8. Транспортный → Сеансовый ===
        # TCP → NetBIOS, RPC; UDP → NetBIOS
        tcp = find(GraphLevel.TRANSPORT, "tcp")
        udp = find(GraphLevel.TRANSPORT, "udp")
        netbios = find(GraphLevel.SESSION, "netbios")
        rpc = find(GraphLevel.SESSION, "rpc")
        auth = find(GraphLevel.SESSION, "аутентификац")
        vpn_sess = find(GraphLevel.SESSION, "vpn")

        if tcp and netbios:
            self._add_edge(tcp.id, netbios.id, [ThreatType.CO, ThreatType.TRO])
        if tcp and rpc:
            self._add_edge(tcp.id, rpc.id, [ThreatType.CO, ThreatType.TRO])
        if udp and netbios:
            self._add_edge(udp.id, netbios.id, [ThreatType.CO, ThreatType.TRO])
        if tcp and vpn_sess:
            self._add_edge(tcp.id, vpn_sess.id, [ThreatType.CO, ThreatType.TRO])

        # Контроль доступа → Аутентификация
        if access and auth:
            self._add_edge(access.id, auth.id, [ThreatType.CO, ThreatType.TRO])

        # === 9. Сеансовый → Представление ===
        # NetBIOS/RPC → SSL/TLS; Auth → SSL/TLS
        ssl = find(GraphLevel.PRESENTATION, "ssl", "tls")
        encoding = find(GraphLevel.PRESENTATION, "кодировк")
        session_verts = by_level(GraphLevel.SESSION)
        for sv in session_verts:
            if ssl:
                self._add_edge(sv.id, ssl.id, [ThreatType.CO, ThreatType.TRO])

        # Auth → Кодировки
        if auth and encoding:
            self._add_edge(auth.id, encoding.id, [ThreatType.CO])

        # === 10. Представление → Прикладной ===
        # SSL/TLS → каждое приложение; Кодировки → каждое приложение
        app_verts = by_level(GraphLevel.APPLICATION)
        if ssl:
            for av in app_verts:
                self._add_edge(ssl.id, av.id, [ThreatType.CO, ThreatType.TRO])
        if encoding and not ssl:
            # Если нет SSL — кодировки напрямую к приложениям
            for av in app_verts:
                self._add_edge(encoding.id, av.id, [ThreatType.CO, ThreatType.TRO])

        # === 11. Сетевые приложения → Транспортный ===
        # DNS/DHCP/HTTP → TCP; DNS/DHCP → UDP
        na_verts = by_level(GraphLevel.NET_APPS)
        for nav in na_verts:
            nl = nav.label.lower()
            if tcp:
                self._add_edge(nav.id, tcp.id, [ThreatType.CO, ThreatType.TRO])
            if udp and ("dns" in nl or "dhcp" in nl or "snmp" in nl):
                self._add_edge(nav.id, udp.id, [ThreatType.CO, ThreatType.TRO])

        # === 12. Аппаратный → логические связи ===
        hw_verts = by_level(GraphLevel.HARDWARE)
        gpu_drv = find(GraphLevel.DRIVERS, "gpu", "видео")
        hdd_drv = find(GraphLevel.DRIVERS, "hdd", "ssd", "накопитель")

        for hv in hw_verts:
            hl = hv.label.lower()
            # GPU → Драйвер GPU
            if ("gpu" in hl or "видео" in hl) and gpu_drv:
                self._add_edge(hv.id, gpu_drv.id, [ThreatType.CO])
            # HDD/SSD → Драйвер HDD
            elif ("hdd" in hl or "ssd" in hl) and hdd_drv:
                self._add_edge(hv.id, hdd_drv.id, [ThreatType.CO])
            # MB/CPU → первый физический (через чипсет)
            elif ("cpu" in hl or "mb" in hl or "материнск" in hl
                  or "платформа" in hl or "чипсет" in hl):
                if phys_verts:
                    self._add_edge(hv.id, phys_verts[0].id, [ThreatType.CO])

        # === 13. Пользовательский → Аппаратный/Прикладной ===
        user_verts = by_level(GraphLevel.USER)
        for uv in user_verts:
            ul = uv.label.lower()
            # Монитор → GPU hardware
            if "монитор" in ul:
                gpu_hw = find(GraphLevel.HARDWARE, "gpu", "видео")
                if gpu_hw:
                    self._add_edge(uv.id, gpu_hw.id, [ThreatType.CO])
            # Мышь/Клавиатура → первое приложение (ввод данных)
            elif "мышь" in ul or "клавиатур" in ul:
                if app_verts:
                    self._add_edge(uv.id, app_verts[0].id,
                                   [ThreatType.CO, ThreatType.TRO])
            # Принтер → файловая система
            elif "принтер" in ul:
                if fs:
                    self._add_edge(uv.id, fs.id, [ThreatType.CO])

    # ------------------------------------------------------------------
    # Вспомогательные
    # ------------------------------------------------------------------

    def _get_os_name(self) -> str:
        """Извлекает имя ОС из software."""
        for item in self.node.properties.get("software", []):
            if item.startswith("ОС:"):
                name = item.split(":", 1)[1].strip()
                return name.split("||")[0].strip().rstrip("- ")
        # Для маршрутизаторов — firmware
        for item in self.node.properties.get("software", []):
            for prefix in ("Cisco IOS:", "JunOS:", "Huawei VRP:",
                           "ОС маршрутизатора:", "ОС коммутатора:",
                           "ОС сервера:", "ОС хоста:"):
                if item.startswith(prefix):
                    name = item.split(":", 1)[1].strip()
                    return name.split("||")[0].strip().rstrip("- ")
        return ""
