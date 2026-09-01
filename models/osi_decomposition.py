"""
Модуль разложения узла по 7 уровням ЭМВОС (OSI) + уровни модели ФСТЭК РФ.

Содержит:
- OSILevel: перечисление всех уровней
- OSIComponent: один компонент на схеме (протокол, оборудование, подсистема)
- NodeDecomposition: автоматическое разложение узла на компоненты по уровням
- VulnerabilityPath: маршрут распространения уязвимости (χ) между узлами

Используется для построения схемы разложения топологии на компоненты
с визуализацией маршрутов уязвимостей.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from models.node import Node
    from models.zone import Board


# ===================================================================
# Уровни модели
# ===================================================================

class OSILevel(Enum):
    """Уровни ЭМВОС (OSI) + дополнительные уровни модели ФСТЭК РФ."""
    # 7 уровней ЭМВОС
    PHYSICAL = 1        # Физический: IEEE 802.x, разъёмы, кабели
    DATA_LINK = 2       # Канальный: PPP, MAC, ARP, передача фреймов
    NETWORK = 3         # Сетевой: IP, IPv4, IPv6, IPSec, ICMP
    TRANSPORT = 4       # Транспортный: TCP, UDP, SCTP
    SESSION = 5         # Сеансовый: L2TP, RPC, gRPC, MS-CHAPv2
    PRESENTATION = 6    # Представления: SSL/TLS, ASCII, EBCDIC
    APPLICATION = 7     # Прикладной: HTTP, SSH, FTP, SMTP, RDP

    # Уровни модели ФСТЭК РФ (вне ЭМВОС)
    HARDWARE = 10       # Аппаратный: процессор, мат.плата, БП, ОЗУ
    KERNEL = 11         # Ядро ОС: драйверы, доступ, ФС, процессы
    USER = 12           # Пользовательский: периферия, UI


# Русские названия уровней
LEVEL_NAMES = {
    OSILevel.PHYSICAL:     "Физический уровень ЭМВОС",
    OSILevel.DATA_LINK:    "Канальный уровень ЭМВОС",
    OSILevel.NETWORK:      "Сетевой уровень ЭМВОС",
    OSILevel.TRANSPORT:    "Транспортный уровень ЭМВОС",
    OSILevel.SESSION:      "Сеансовый уровень ЭМВОС",
    OSILevel.PRESENTATION: "Уровень представления ЭМВОС",
    OSILevel.APPLICATION:  "Прикладной уровень ЭМВОС",
    OSILevel.HARDWARE:     "Аппаратный уровень",
    OSILevel.KERNEL:       "Ядро ОС",
    OSILevel.USER:         "Пользовательский уровень",
}

LEVEL_DESCRIPTIONS = {
    OSILevel.PHYSICAL:     "Передача битов через физическую среду",
    OSILevel.DATA_LINK:    "Передача фреймов, MAC-адресация",
    OSILevel.NETWORK:      "Передача пакетов, маршрутизация",
    OSILevel.TRANSPORT:    "Образование единой транспортной системы",
    OSILevel.SESSION:      "Управление сессиями",
    OSILevel.PRESENTATION: "Кодирование, декодирование, шифрование",
    OSILevel.APPLICATION:  "Передача прикладных данных",
    OSILevel.HARDWARE:     "Аппаратная архитектура узла",
    OSILevel.KERNEL:       "Подсистемы ядра операционной системы",
    OSILevel.USER:         "Устройства ввода/вывода, пользовательский интерфейс",
}


# ===================================================================
# Компонент на схеме
# ===================================================================

@dataclass
class OSIComponent:
    """Один компонент на схеме разложения.

    Это может быть протокол, аппаратный элемент, подсистема ОС
    или пользовательское устройство.
    """
    name: str                           # Человекочитаемое название
    level: OSILevel                     # На каком уровне расположен
    component_type: str                 # 'protocol', 'hardware', 'software',
                                        # 'interface', 'subsystem', 'peripheral'
    identifier: str = ""                # Идентификатор для схемы (f1.1, z1, l1, a1, h1)
    description: str = ""               # Краткое описание функции
    cve_vendor: str = ""                # Vendor для поиска CVE
    cve_product: str = ""               # Product для поиска CVE
    cve_list: List[Dict] = field(default_factory=list)  # Найденные CVE
    has_vulnerability: bool = False     # Есть ли уязвимости


# ===================================================================
# Разложение одного узла
# ===================================================================

class NodeDecomposition:
    """Автоматическое разложение узла на компоненты по уровням ЭМВОС.

    Анализирует:
    - node.ports → физический уровень (интерфейсы, IEEE стандарты)
    - node.properties['hardware'] → аппаратный уровень
    - node.properties['software'] → ОС → какие протоколы/подсистемы доступны
    - node.type → какие серверные/клиентские протоколы прикладного уровня
    - VPN/firewall настройки → дополнительные протоколы
    """

    def __init__(self, node: 'Node'):
        self.node = node
        self.components: Dict[OSILevel, List[OSIComponent]] = {
            level: [] for level in OSILevel
        }
        self._decompose()

    def _decompose(self):
        """Выполняет полное разложение узла.

        Поиск CVE НЕ выполняется автоматически — он тяжёлый (~50 SQL-запросов
        на узел). Вызывайте find_vulnerabilities() отдельно, когда нужно.
        """
        self._decompose_physical()
        self._decompose_data_link()
        self._decompose_network()
        self._decompose_transport()
        self._decompose_session()
        self._decompose_presentation()
        self._decompose_application()
        self._decompose_hardware()
        self._decompose_kernel()
        self._decompose_user()
        self._renumber_identifiers()

    def _renumber_identifiers(self):
        """Иерархическая нумерация компонентов по образцу паспорта ФСТЭК.

        Физический уровень:
          f1.ТИП.ЭКЗЕМПЛЯР — интерфейсы, сгруппированные по типу порта
            ethernet → f1.1.1, f1.1.2...  (кросс-ссылка /а14.N на разъём)
            pon      → f1.2.1, f1.2.2...  (кросс-ссылка /а15.N)
            wifi     → f1.3.1, f1.3.2...  (кросс-ссылка /а16.N)
            usb      → f1.4.1, f1.4.2...  (кросс-ссылка /а19.N)
          f2.N — IEEE-протоколы (IEEE 802.3, 802.11...)

        Аппаратный уровень:
          аN.m  — основные компоненты (а1–а13), один экземпляр
          аN.K  — разъёмы/модули (а14–а19), по числу портов

        Остальные уровни — последовательно: z1, l1, t1, d1, r1, q1, i1, u1.
        """
        from collections import defaultdict

        # ── Физический уровень ──────────────────────────────────────
        # Порядок групп портов: ethernet=1, pon=2, wifi=3, usb=4
        PORT_TYPE_GROUP = {"ethernet": 1, "pon": 2, "wifi": 3, "usb": 4}
        # Базовый аппаратный идентификатор разъёма для каждого типа порта
        PT_HW_BASE = {"ethernet": "а14", "pon": "а15", "wifi": "а16", "usb": "а19"}

        def _detect_pt(name: str) -> str:
            nl = name.lower()
            if "rj-45" in nl or "ethernet" in nl:
                return "ethernet"
            if "wi-fi" in nl or "wifi" in nl:
                return "wifi"
            if "pon" in nl or "оптич" in nl:
                return "pon"
            if "usb" in nl:
                return "usb"
            return "other"

        interfaces = [c for c in self.components.get(OSILevel.PHYSICAL, [])
                      if c.component_type == "interface"]
        protocols  = [c for c in self.components.get(OSILevel.PHYSICAL, [])
                      if c.component_type == "protocol"]

        inst_counters: dict = defaultdict(int)
        for comp in interfaces:
            pt = _detect_pt(comp.name)
            inst_counters[pt] += 1
            inst = inst_counters[pt]
            group = PORT_TYPE_GROUP.get(pt, 9)
            hw_base = PT_HW_BASE.get(pt, "")
            if hw_base:
                comp.identifier = f"f1.{group}.{inst}/{hw_base}.{inst}"
            else:
                comp.identifier = f"f1.{group}.{inst}"

        for idx, comp in enumerate(protocols, start=1):
            comp.identifier = f"f2.{idx}"

        # ── Аппаратный уровень ──────────────────────────────────────
        # Базовые идентификаторы используют латинскую 'a'; разъёмы (≥14)
        # получают суффикс .K (по числу экземпляров), основные — .m
        conn_counters: dict = defaultdict(int)
        for comp in self.components.get(OSILevel.HARDWARE, []):
            raw = comp.identifier  # "a1", "a14", ...
            try:
                num = int(raw.lstrip("aа"))
                # Переводим латинскую 'a' в кириллическую 'а'
                cyr = "а" + str(num)
                if num >= 14:   # разъём/модуль — счётчик экземпляров
                    conn_counters[raw] += 1
                    comp.identifier = f"{cyr}.{conn_counters[raw]}"
                else:           # основной компонент — один экземпляр
                    comp.identifier = f"{cyr}.m"
            except (ValueError, IndexError):
                pass  # нестандартный идент — оставляем как есть

        # ── Остальные уровни — последовательно ──────────────────────
        for level, prefix in [
            (OSILevel.DATA_LINK,    "z"),
            (OSILevel.NETWORK,      "l"),
            (OSILevel.TRANSPORT,    "t"),
            (OSILevel.SESSION,      "d"),
            (OSILevel.PRESENTATION, "r"),
            (OSILevel.APPLICATION,  "q"),
            (OSILevel.KERNEL,       "i"),
            (OSILevel.USER,         "u"),
        ]:
            for idx, comp in enumerate(self.components.get(level, []), start=1):
                comp.identifier = f"{prefix}{idx}"

    # ----- Физический уровень -----

    def _decompose_physical(self):
        """Физический уровень: порты, разъёмы, IEEE стандарты."""
        level = OSILevel.PHYSICAL

        # Порты узла → интерфейсы
        port_types_seen = set()
        for port in self.node.ports:
            pt = port.get("port_type", "")
            name = port.get("name", "")

            if pt == "ethernet":
                self.components[level].append(OSIComponent(
                    name=f"Порт {name} (RJ-45)", level=level,
                    component_type="interface", identifier=f"f1.{name}",
                    description="Интерфейс Ethernet"
                ))
                port_types_seen.add("ethernet")
            elif pt == "wifi":
                self.components[level].append(OSIComponent(
                    name=f"Порт {name} (Wi-Fi)", level=level,
                    component_type="interface", identifier=f"f1.{name}",
                    description="Беспроводной интерфейс"
                ))
                port_types_seen.add("wifi")
            elif pt == "pon":
                self.components[level].append(OSIComponent(
                    name=f"Порт {name} (PON)", level=level,
                    component_type="interface", identifier=f"f1.{name}",
                    description="Оптический интерфейс"
                ))
                port_types_seen.add("pon")
            elif pt == "usb":
                self.components[level].append(OSIComponent(
                    name=f"Порт {name} (USB)", level=level,
                    component_type="interface", identifier=f"f1.{name}",
                    description="USB интерфейс"
                ))

        # IEEE стандарты протоколов
        if "ethernet" in port_types_seen:
            self.components[level].append(OSIComponent(
                name="IEEE 802.3", level=level,
                component_type="protocol", identifier="f2.1",
                description="Стандарт Ethernet"
            ))
        if "wifi" in port_types_seen:
            self.components[level].append(OSIComponent(
                name="IEEE 802.11", level=level,
                component_type="protocol", identifier="f2.2",
                description="Стандарт Wi-Fi"
            ))

        # Bluetooth и WiMAX — всегда присутствуют при наличии сетевых портов
        if port_types_seen:
            self.components[level].append(OSIComponent(
                name="IEEE 802.15", level=level,
                component_type="protocol", identifier="f2.3",
                description="Стандарт Bluetooth"
            ))
            self.components[level].append(OSIComponent(
                name="IEEE 802.16", level=level,
                component_type="protocol", identifier="f2.4",
                description="Стандарт WiMAX"
            ))

    # ----- Канальный уровень -----

    def _decompose_data_link(self):
        """Канальный уровень: IEEE 802, PPP, MAC, ARP."""
        level = OSILevel.DATA_LINK
        has_net = any(p.get("port_type") in ("ethernet", "pon", "wifi")
                      for p in self.node.ports)
        if not has_net:
            return

        for proto_name, ident, desc in [
            ("IEEE 802", "z1", "Стандарт канального уровня"),
            ("PPP", "z2", "Point-to-Point Protocol"),
            ("MAC-адрес", "z3", "Физическая адресация"),
            ("ARP", "z4", "Address Resolution Protocol"),
        ]:
            self.components[level].append(OSIComponent(
                name=proto_name, level=level,
                component_type="protocol", identifier=ident,
                description=desc
            ))

    # ----- Сетевой уровень -----

    def _decompose_network(self):
        """Сетевой уровень: IP, IPv4, IPv6, IPSec, ICMP."""
        level = OSILevel.NETWORK
        has_ip = any(p.get("ip_address") for p in self.node.ports)
        has_net = any(p.get("port_type") in ("ethernet", "pon", "wifi")
                      for p in self.node.ports)
        if not has_net:
            return

        for proto_name, ident, desc in [
            ("IP-адрес", "l1", "Логическая адресация"),
            ("IPv4", "l2", "Internet Protocol v4"),
            ("IPSec", "l4", "IP Security"),
            ("ICMP", "l5", "Internet Control Message Protocol"),
            ("ARP-таблица", "l6", "Таблица соответствия IP↔MAC"),
        ]:
            self.components[level].append(OSIComponent(
                name=proto_name, level=level,
                component_type="protocol", identifier=ident,
                description=desc
            ))

    # ----- Транспортный уровень -----

    def _decompose_transport(self):
        """Транспортный уровень: TCP, UDP, SCTP."""
        level = OSILevel.TRANSPORT
        has_net = any(p.get("port_type") in ("ethernet", "pon", "wifi")
                      for p in self.node.ports)
        if not has_net:
            return

        for proto_name, ident, desc in [
            ("TCP", "t1.1", "Transmission Control Protocol"),
            ("UDP", "t2.1", "User Datagram Protocol"),
            ("SCTP", "t3", "Stream Control Transmission Protocol"),
        ]:
            self.components[level].append(OSIComponent(
                name=proto_name, level=level,
                component_type="protocol", identifier=ident,
                description=desc
            ))

    # ----- Сеансовый уровень -----

    def _decompose_session(self):
        """Сеансовый уровень: L2TP, RPC, gRPC, MS-CHAPv2, HTTPУС."""
        level = OSILevel.SESSION
        has_net = any(p.get("port_type") in ("ethernet", "pon", "wifi")
                      for p in self.node.ports)
        if not has_net:
            return

        protos = [("HTTPУС", "d5", "HTTP управление сессиями")]

        # VPN → L2TP
        if self.node.vpn_client_enabled or self.node.vpn_server_enabled:
            protos.insert(0, ("L2TP", "d1", "Layer 2 Tunneling Protocol"))

        # Сервер/Маршрутизатор → RPC, gRPC
        if self.node.type in ("Server", "Router", "VirtualizationServer"):
            protos.append(("RPC", "d4", "Remote Procedure Call"))
            protos.append(("gRPC", "d2", "gRPC фреймворк"))

        protos.append(("MS-CHAPv2", "d3", "Challenge-Handshake Authentication"))

        for name, ident, desc in protos:
            self.components[level].append(OSIComponent(
                name=name, level=level,
                component_type="protocol", identifier=ident,
                description=desc
            ))

    # ----- Уровень представления -----

    def _decompose_presentation(self):
        """Уровень представления: SSL/TLS, ASCII, EBCDIC, HTTPКД."""
        level = OSILevel.PRESENTATION
        has_net = any(p.get("port_type") in ("ethernet", "pon", "wifi")
                      for p in self.node.ports)
        if not has_net:
            return

        for name, ident, desc in [
            ("SSL/TLS", "r7", "Шифрование транспорта"),
            ("ASCII", "r2", "Кодировка текста"),
            ("ICA", "r3", "Independent Computing Architecture"),
            ("HTTPКД", "r8", "HTTP кодирование данных"),
        ]:
            self.components[level].append(OSIComponent(
                name=name, level=level,
                component_type="protocol", identifier=ident,
                description=desc
            ))

        # Для серверов — дополнительные форматы
        if self.node.type in ("Server", "VirtualizationServer"):
            for name, ident, desc in [
                ("EBCDIC", "r1", "Кодировка IBM"),
                ("XDR", "r6", "External Data Representation"),
                ("LPP", "r4", "Lightweight Presentation Protocol"),
                ("NCP", "r5", "NetWare Core Protocol"),
            ]:
                self.components[level].append(OSIComponent(
                    name=name, level=level,
                    component_type="protocol", identifier=ident,
                    description=desc
                ))

    # ----- Прикладной уровень -----

    def _decompose_application(self):
        """Прикладной уровень: HTTP, SSH, FTP, SMTP, RDP и т.д."""
        level = OSILevel.APPLICATION

        # Клиентские протоколы (для АРМ, Ноутбук)
        if self.node.type in ("ARM", "Laptop"):
            clients = [
                ("FTP-клиент", "q1", "File Transfer Protocol"),
                ("SSH-клиент", "q2", "Secure Shell"),
                ("RDP-клиент", "q3", "Remote Desktop Protocol"),
                ("SMTP-клиент", "q4", "Simple Mail Transfer Protocol"),
                ("IMAP-клиент", "q5", "Internet Message Access Protocol"),
                ("POP3-клиент", "q6", "Post Office Protocol v3"),
                ("SIP-клиент", "q7", "Session Initiation Protocol"),
                ("SNMP-клиент", "q8", "Simple Network Management Protocol"),
                ("HTTPппо-клиент", "q9", "HTTP прикладное ПО"),
            ]
            for name, ident, desc in clients:
                self.components[level].append(OSIComponent(
                    name=name, level=level,
                    component_type="protocol", identifier=ident,
                    description=desc
                ))

        # Серверные протоколы
        if self.node.type in ("Server", "VirtualizationServer"):
            servers = [
                ("FTP-сервер", "q1s", "FTP сервер"),
                ("SSH-сервер", "q2s", "SSH сервер"),
                ("RDP-сервер", "q3s", "RDP сервер"),
                ("SMTP-сервер", "q4s", "Почтовый сервер (отправка)"),
                ("IMAP-сервер", "q5s", "Почтовый сервер (чтение)"),
                ("POP3-сервер", "q6s", "Почтовый сервер (загрузка)"),
                ("SNMP-сервер", "q8s", "Мониторинг сети"),
                ("HTTPппо-сервер", "q9s", "Веб-сервер"),
            ]
            for name, ident, desc in servers:
                self.components[level].append(OSIComponent(
                    name=name, level=level,
                    component_type="protocol", identifier=ident,
                    description=desc
                ))

        # Маршрутизатор — сетевые протоколы управления
        if self.node.type == "Router":
            for name, ident, desc in [
                ("SNMP", "q8", "Simple Network Management Protocol"),
                ("SSH", "q2", "Secure Shell (управление)"),
                ("HTTPппо", "q9", "Веб-интерфейс управления"),
            ]:
                self.components[level].append(OSIComponent(
                    name=name, level=level,
                    component_type="protocol", identifier=ident,
                    description=desc
                ))

        # Прикладное ПО из properties
        for sw in self.node.properties.get("software", []):
            if sw and isinstance(sw, str) and sw.strip():
                if sw.startswith("ОС:") or sw.startswith("Приложение:"):
                    self.components[level].append(OSIComponent(
                        name=sw, level=level,
                        component_type="software", identifier="",
                        description="Установленное ПО"
                    ))

    # ----- Аппаратный уровень -----

    def _decompose_hardware(self):
        """Аппаратный уровень: процессор, мат.плата, ОЗУ, БП, СХД."""
        level = OSILevel.HARDWARE

        # Из properties['hardware']
        hw_items = self.node.properties.get("hardware", [])
        for item in hw_items:
            if not item or not isinstance(item, str):
                continue
            # Определяем тип и идентификатор
            ident = "a"
            if "Процессор" in item:
                ident = "a1"
            elif "Видеоконтроллер" in item or "Видеокарта" in item:
                ident = "a4"
            elif "Материнская плата" in item:
                ident = "a2"
            elif "HDD" in item or "SSD" in item:
                ident = "a8"
            elif "Память" in item or "RAM" in item:
                ident = "a7"

            self.components[level].append(OSIComponent(
                name=item, level=level,
                component_type="hardware", identifier=ident,
                description="Компонент аппаратной архитектуры"
            ))

        # Стандартные компоненты (всегда присутствуют, если есть hardware)
        if hw_items or self.node.type != "Internet":
            for name, ident, desc in [
                ("Блок питания", "a13", "Электропитание компонентов"),
                ("BIOS/UEFI", "a6", "Базовая система ввода/вывода"),
                ("PCI Express контроллеры", "a3", "Шина расширения"),
                ("Аудиоконтроллер", "a5", "Звуковая подсистема"),
                ("SATA контроллеры", "a9", "Интерфейс накопителей"),
                ("USB контроллеры", "a11", "Контроллеры USB"),
                ("RTC", "a10", "Часы реального времени"),
                ("Сетевая карта", "a12", "Ethernet контроллер"),
            ]:

                self.components[level].append(OSIComponent(
                    name=name, level=level,
                    component_type="hardware", identifier=ident,
                    description=desc
                ))

            # Разъёмы и модули — по одному на каждый порт (для кросс-ссылок)
            for port in self.node.ports:
                pt = port.get("port_type", "")
                if pt == "ethernet":
                    self.components[level].append(OSIComponent(
                        name="Разъём RJ-45", level=level,
                        component_type="hardware", identifier="a14",
                        description="Ethernet разъём"
                    ))
                elif pt == "wifi":
                    self.components[level].append(OSIComponent(
                        name="Модуль Wi-Fi", level=level,
                        component_type="hardware", identifier="a16",
                        description="Беспроводной модуль IEEE 802.11"
                    ))
                elif pt == "usb":
                    self.components[level].append(OSIComponent(
                        name="Разъём USB", level=level,
                        component_type="hardware", identifier="a19",
                        description="Разъём USB"
                    ))
                elif pt == "pon":
                    self.components[level].append(OSIComponent(
                        name="Оптический разъём SC/PC", level=level,
                        component_type="hardware", identifier="a15",
                        description="PON оптический разъём"
                    ))

    # ----- Ядро ОС -----

    def _decompose_kernel(self):
        """Ядро ОС: подсистемы драйверов, доступа, ФС, процессов."""
        level = OSILevel.KERNEL

        if self.node.type == "Internet":
            return  # У узла «Интернет» нет ОС

        subsystems = [
            ("Драйвер сетевой карты", "i1.1", "Ethernet / Wi-Fi драйвер"),
            ("Драйвер видеоконтроллера", "i2", "GPU драйвер"),
            ("Драйвер аудиоконтроллера", "i3", "Аудио драйвер"),
            ("Драйвер USB", "i4", "USB драйвер"),
            ("Драйвер клавиатуры", "i5", "HID клавиатуры"),
            ("Драйвер мыши", "i6", "HID мыши"),
            ("Драйвер СВВ", "i7", "Средства ввода/вывода"),
            ("Подсистема управления доступом", "w1", "DAC/MAC модели"),
            ("Подсистема управления файлами", "p1", "Файловые системы"),
            ("Подсистема управления процессами", "v1", "Планировщик и управление ОЗУ"),
        ]

        for name, ident, desc in subsystems:
            self.components[level].append(OSIComponent(
                name=name, level=level,
                component_type="subsystem", identifier=ident,
                description=desc
            ))

        # Файловые системы — определяются ОС
        os_name = self._detect_os()
        if "windows" in os_name:
            fs_list = ["NTFS", "FAT32"]
        elif "linux" in os_name or "ubuntu" in os_name:
            fs_list = ["EXT4", "XFS", "Btrfs"]
        else:
            fs_list = ["NTFS", "FAT32", "XFS", "EXT4"]

        for fs in fs_list:
            self.components[level].append(OSIComponent(
                name=fs, level=level,
                component_type="software", identifier="p1.fs",
                description="Файловая система"
            ))

    # ----- Пользовательский уровень -----

    def _decompose_user(self):
        """Пользовательский уровень: периферия, UI."""
        level = OSILevel.USER

        if self.node.type == "Internet":
            return

        # Из properties['software'] — периферия с конкретными h-индексами
        _PERIPH_MAP = {
            "Клавиатура:": ("h1", "Клавиатура"),
            "Мышь:":       ("h2", "Манипуляторная мышь"),
            "Принтер:":    ("h3", "МФУ / Принтер"),
            "Монитор:":    ("h7", "Монитор"),
        }
        for sw in self.node.properties.get("software", []):
            if sw and isinstance(sw, str):
                for prefix, (ident, desc) in _PERIPH_MAP.items():
                    if sw.startswith(prefix):
                        self.components[level].append(OSIComponent(
                            name=sw, level=level,
                            component_type="peripheral",
                            identifier=ident,
                            description=desc
                        ))
                        break

        # Пользовательский интерфейс
        self.components[level].append(OSIComponent(
            name="Пользовательский интерфейс", level=level,
            component_type="software", identifier="h5",
            description="Графический пульт управления"
        ))

    # ----- Поиск уязвимостей (вызывается отдельно, не из конструктора) -----

    def find_vulnerabilities(self):
        """Ищет CVE для всех компонентов.

        Сначала проверяет кеш паспорта безопасности узла
        (node.properties["security_passport_cache"]).
        Если кеша нет — делает SQL-запросы через cve_db.
        """
        # --- Кеш паспорта: component_name → [cve_list] ---
        passport_cache = (
            self.node.properties
            .get("security_passport_cache", {})
            .get("components", {})
        )

        # Префиксы для перебора вариантов имени в кеше
        _RU_PREFIXES = (
            "Процессор: ", "Видеоконтроллер: ", "Материнская плата: ",
            "HDD/SSD: ", "Память: ", "ОС: ", "Приложение: ",
            "Мышь: ", "Клавиатура: ", "Принтер: ", "Монитор: ",
        )

        def _lookup_cache(name):
            """Ищет CVE в кеше паспорта по имени компонента."""
            # Полное имя
            if name in passport_cache:
                return passport_cache[name]
            # Имя без русского префикса (кеш хранит часть после «:»)
            for pfx in _RU_PREFIXES:
                if name.startswith(pfx):
                    short = name[len(pfx):]
                    if short in passport_cache:
                        return passport_cache[short]
                    break
            return None

        # --- Если кеш есть, используем его ---
        if passport_cache:
            for level, comps in self.components.items():
                for comp in comps:
                    cached = _lookup_cache(comp.name)
                    if cached:
                        comp.cve_list = cached
                        comp.has_vulnerability = bool(cached)
            return

        # --- Кеша нет: делаем SQL-запросы ---
        try:
            from database.cve_db import CVEDatabase
            db = CVEDatabase()
        except Exception:
            return

        from utils.cpe_utils import extract_cpe_components

        for level, comps in self.components.items():
            for comp in comps:
                if comp.component_type in ("hardware", "software", "peripheral"):
                    cpe = extract_cpe_components(comp.name)
                    vendor = cpe.get("vendor", "")
                    product = cpe.get("product", "")
                    version = cpe.get("version", "")
                    cves = None
                    if vendor:
                        cves = db.get_cves_for_component(vendor, product, version)
                        if not cves and version:
                            cves = db.get_cves_for_component(vendor, product)
                        if not cves and product:
                            cves = db.get_cves_for_component(vendor)
                    if cves:
                        comp.cve_list = cves
                        comp.has_vulnerability = True
                        comp.cve_vendor = vendor
                        comp.cve_product = product
                elif comp.component_type == "protocol":
                    proto_name = comp.name.lower().replace("-", "_").replace("/", "_")
                    if proto_name and len(proto_name) > 2:
                        cves = db.get_cves_by_cpe_mask(proto_name)
                        if cves:
                            comp.cve_list = cves
                            comp.has_vulnerability = True

    # ----- Вспомогательные -----

    def _detect_os(self) -> str:
        """Определяет ОС узла из properties['software']."""
        for sw in self.node.properties.get("software", []):
            if isinstance(sw, str) and sw.startswith("ОС:"):
                return sw.lower()
        return ""

    def get_components_by_level(self, level: OSILevel) -> List[OSIComponent]:
        """Возвращает компоненты для указанного уровня."""
        return self.components.get(level, [])

    def get_all_components(self) -> List[OSIComponent]:
        """Возвращает все компоненты всех уровней."""
        result = []
        for level in OSILevel:
            result.extend(self.components.get(level, []))
        return result

    def get_nonempty_levels(self) -> List[OSILevel]:
        """Возвращает только непустые уровни."""
        return [level for level in OSILevel if self.components.get(level)]

    def to_dict(self) -> Dict:
        """Сериализация в словарь."""
        return {
            "node_id": self.node.id,
            "node_name": self.node.name,
            "node_type": self.node.type,
            "levels": {
                level.name: [
                    {
                        "name": c.name,
                        "type": c.component_type,
                        "identifier": c.identifier,
                        "description": c.description,
                        "has_vulnerability": c.has_vulnerability,
                        "cve_count": len(c.cve_list),
                    }
                    for c in comps
                ]
                for level, comps in self.components.items()
                if comps
            },
        }


# ===================================================================
# Маршрут распространения уязвимости
# ===================================================================

@dataclass
class VulnerabilityPath:
    """Маршрут распространения уязвимости (χ) между узлами.

    Описывает путь, по которому злоумышленник может проникнуть
    от точки входа одного узла через компоненты к точке выхода
    другого узла.
    """
    path_id: str                            # χ1.1, χ2.3 и т.д.
    source_node_id: str                     # ID узла-источника
    target_node_id: str                     # ID узла-назначения
    entry_port: str                         # Имя порта входа (ω1)
    exit_port: str                          # Имя порта выхода (ω2)
    components: List[OSIComponent] = field(default_factory=list)
    description: str = ""


# ===================================================================
# Разложение всей топологии
# ===================================================================

class TopologyDecomposition:
    """Разложение всей топологии (всех узлов) на компоненты."""

    def __init__(self, board: 'Board'):
        self.board = board
        self.decompositions: Dict[str, NodeDecomposition] = {}
        self.vulnerability_paths: List[VulnerabilityPath] = []

        self._decompose_all()

    def _decompose_all(self):
        """Раскладывает каждый узел и строит маршруты уязвимостей."""
        for node in self.board.nodes:
            self.decompositions[node.id] = NodeDecomposition(node)

        self._build_vulnerability_paths()

    def _build_vulnerability_paths(self):
        """Строит маршруты χ на основе физических связей между узлами."""
        path_counter = 1

        for link in self.board.links:
            if link.a is None or link.b is None:
                continue

            # Определяем порты
            port_a_id = link.ports_connected.get("a", "")
            port_b_id = link.ports_connected.get("b", "")

            port_a_name = ""
            for p in link.a.ports:
                if p.get("port_id") == port_a_id:
                    port_a_name = p.get("name", port_a_id)
                    break

            port_b_name = ""
            for p in link.b.ports:
                if p.get("port_id") == port_b_id:
                    port_b_name = p.get("name", port_b_id)
                    break

            # Маршрут A → B
            self.vulnerability_paths.append(VulnerabilityPath(
                path_id=f"χ{path_counter}.1",
                source_node_id=link.a.id,
                target_node_id=link.b.id,
                entry_port=port_a_name,
                exit_port=port_b_name,
                description=f"{link.a.name} → {link.b.name}"
            ))

            # Маршрут B → A
            self.vulnerability_paths.append(VulnerabilityPath(
                path_id=f"χ{path_counter}.2",
                source_node_id=link.b.id,
                target_node_id=link.a.id,
                entry_port=port_b_name,
                exit_port=port_a_name,
                description=f"{link.b.name} → {link.a.name}"
            ))

            path_counter += 1

    def get_node_decomposition(self, node_id: str) -> Optional[NodeDecomposition]:
        return self.decompositions.get(node_id)

    def get_ordered_nodes(self) -> List['Node']:
        """Возвращает узлы в порядке: от ближайшего к Интернету до самого дальнего.

        Если узла Интернет нет — просто маршрутизаторы первыми,
        потом серверы, потом АРМ/ноутбуки.
        """
        # Приоритет типов (чем меньше — тем ближе к «внешнему миру»)
        type_priority = {
            "Internet": 0,
            "Router": 1,
            "Switch": 2,
            "Server": 3,
            "VirtualizationServer": 4,
            "ARM": 5,
            "Laptop": 6,
        }

        nodes = [n for n in self.board.nodes if n.type != "Internet"]
        nodes.sort(key=lambda n: type_priority.get(n.type, 99))
        return nodes
