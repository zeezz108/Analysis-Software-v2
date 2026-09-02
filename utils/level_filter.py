"""
Фильтрация CVE по уровню модели УБИ / ЭМВОС.

Зачем нужен модуль
------------------
CPE (vendor + product) указывает на *продукт*, а не на компонент внутри него.
TCP-стек — часть Windows, поэтому запрос по ``product = windows`` возвращает
17 639 уязвимостей обо всём подряд: принтеры, GDI, Word, ядро. Первые десять
из них попадают в строку «TCP» паспорта, и девять оказываются не на своём
уровне.

Модуль добавляет второй фильтр — по смыслу самой уязвимости. Для каждого
уровня задан профиль: слова, характерные для обработчика этого уровня,
стоп-слова чужих уровней и типичные CWE. CVE получает оценку релевантности
и попадает в паспорт, только если набрал порог.

Главное правило, по которому построены профили
----------------------------------------------
Уровень уязвимости — это уровень того обработчика, в коде которого лежит
дефект. Не уровень данных, которые до него дошли, и не уровень устройства.
Heartbleed приходит по TCP:443, но разбирает его библиотека TLS — значит
уровень представления, а не транспортный.

Использование
-------------
    from utils.level_filter import filter_cves_by_level

    cves = filter_cves_by_level(all_cves, level_code="t",
                                component_name="TCP", limit=10)

Пустой результат — это нормально и соответствует эталонному паспорту,
где у многих компонентов в колонке CVE стоит прочерк.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

__all__ = [
    "LevelProfile",
    "LEVEL_PROFILES",
    "score_cve",
    "filter_cves_by_level",
    "explain_score",
]


# ===================================================================
# Профиль уровня
# ===================================================================

@dataclass
class LevelProfile:
    """Признаки, по которым CVE относится к уровню.

    Attributes:
        code: Буквенный код уровня (f, z, l, t, d, r, q, a, i, w, p, v, h)
        title: Человекочитаемое название уровня
        keywords: Слова, характерные для обработчика этого уровня
        stop_words: Слова, однозначно указывающие на чужой уровень
        cwe_typical: CWE, часто встречающиеся на этом уровне (бонус)
        cwe_impossible: CWE, которые на этом уровне быть не могут (штраф)
    """

    code: str
    title: str
    keywords: Sequence[str] = ()
    stop_words: Sequence[str] = ()
    cwe_typical: Set[int] = field(default_factory=set)
    cwe_impossible: Set[int] = field(default_factory=set)

    # Скомпилированные шаблоны — заполняются лениво в _compiled()
    _kw_re: Optional[re.Pattern] = field(default=None, repr=False, compare=False)
    _sw_re: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compiled(self) -> tuple:
        """Возвращает (regex ключевых слов, regex стоп-слов), компилируя при первом вызове."""
        if self._kw_re is None:
            self._kw_re = _build_regex(self.keywords)
            self._sw_re = _build_regex(self.stop_words)
        return self._kw_re, self._sw_re


def _build_regex(words: Sequence[str]) -> Optional[re.Pattern]:
    """Собирает один regex из списка слов с границами слова.

    Слова с точками и дефисами (802.11, ms-chap) экранируются, но границы
    ставятся только там, где они осмысленны — иначе «802.11» не найдётся.

    Граничные условия выносятся за скобки, общие на всю группу, а не
    повторяются у каждого слова: на выборке в 17 600 описаний это 120 мс
    против 3 200 мс при том же результате. Внутри группы слова отсортированы
    по убыванию длины, чтобы «http server» находилось раньше «http».
    """
    if not words:
        return None

    lowered = [w.lower() for w in words]
    # Слова, кончающиеся буквой или цифрой, требуют границы и справа
    bounded = sorted({w for w in lowered if w[-1].isalnum()}, key=len, reverse=True)
    open_end = sorted({w for w in lowered if not w[-1].isalnum()}, key=len, reverse=True)

    parts = []
    if bounded:
        alt = "|".join(re.escape(w) for w in bounded)
        parts.append(rf"(?<![a-z0-9_])(?:{alt})(?![a-z0-9_])")
    if open_end:
        alt = "|".join(re.escape(w) for w in open_end)
        parts.append(rf"(?<![a-z0-9_])(?:{alt})")

    return re.compile("|".join(parts), re.IGNORECASE)


# ===================================================================
# Стоп-слова, общие для всех сетевых уровней
# ===================================================================

# Признаки прикладных/пользовательских уязвимостей: если они есть в описании,
# дефект почти наверняка не в сетевом стеке.
_WEB_NOISE = (
    "cross-site scripting", "xss", "sql injection", "csrf",
    "web interface", "web application", "web page", "browser",
    "wordpress", "plugin", "php", "javascript", "cookie consent",
)

_CREDENTIAL_NOISE = (
    "default password", "blank password", "null password",
    "guessable password", "hardcoded password", "weak password",
    "password is not", "share password",
)

_APP_NOISE = ("samba", "smb share", "print spooler", "office", "pdf reader")


# ===================================================================
# Профили уровней
# ===================================================================

LEVEL_PROFILES: Dict[str, LevelProfile] = {

    # ── Физический уровень ЭМВОС + точки входа ──────────────────────
    "f": LevelProfile(
        code="f",
        title="Физический уровень ЭМВОС",
        keywords=(
            "physical layer", "phy", "cable", "connector", "rj-45", "rj45",
            "antenna", "radio", "rf signal", "electromagnetic", "side channel",
            "wireless", "wi-fi", "wifi", "802.11", "802.15", "802.16", "wimax",
            "bluetooth", "zigbee", "nfc", "transceiver", "sfp", "optical",
            "usb port", "usb connector", "signal", "modulation",
        ),
        stop_words=_WEB_NOISE + _CREDENTIAL_NOISE + _APP_NOISE + (
            "file system", "database", "sql",
        ),
        cwe_typical={1188, 1191, 1300, 1256},
        cwe_impossible={79, 89, 352, 434, 22},
    ),

    # ── Канальный уровень ЭМВОС ─────────────────────────────────────
    "z": LevelProfile(
        code="z",
        title="Канальный уровень ЭМВОС",
        keywords=(
            "arp", "mac address", "ethernet frame", "frame", "layer 2", "l2",
            "vlan", "802.1q", "802.1x", "spanning tree", "stp", "lldp",
            "ppp", "pppoe", "pppd", "chap negotiation", "bridge", "switching",
            "data link", "802.3", "802.11", "ieee 802", "eapol", "wpa",
        ),
        stop_words=_WEB_NOISE + _CREDENTIAL_NOISE + _APP_NOISE + (
            "file system", "sql", "http request",
        ),
        cwe_typical={290, 350, 940, 20, 125, 787},
        cwe_impossible={79, 89, 352, 434},
    ),

    # ── Сетевой уровень ЭМВОС ───────────────────────────────────────
    "l": LevelProfile(
        code="l",
        title="Сетевой уровень ЭМВОС",
        keywords=(
            "ip packet", "ip header", "ipv4", "ipv6", "icmp", "igmp",
            "fragment", "fragmentation", "reassembly", "routing", "route",
            "router advertisement", "neighbor discovery", "ndp",
            "ipsec", "ike", "esp packet", "ah packet", "tunnel",
            "netfilter", "iptables", "nftables", "nat", "ttl", "hop limit",
            "network layer", "layer 3", "ping", "traceroute", "ip forwarding",
            "ip address", "subnet", "multicast", "gre",
        ),
        stop_words=_WEB_NOISE + _CREDENTIAL_NOISE + _APP_NOISE + (
            "file system", "sql",
        ),
        cwe_typical={20, 125, 787, 400, 401, 476, 732},
        cwe_impossible={79, 89, 352, 434, 22},
    ),

    # ── Транспортный уровень ЭМВОС ──────────────────────────────────
    "t": LevelProfile(
        code="t",
        title="Транспортный уровень ЭМВОС",
        keywords=(
            "tcp", "udp", "sctp", "dccp", "quic",
            "segment", "sequence number", "acknowledgment number",
            "three-way handshake", "syn flood", "syn cookie", "rst packet",
            "congestion", "window size", "transport layer", "layer 4",
            "port exhaustion", "socket", "listening port", "datagram",
            "tcp stack", "tcp/ip stack", "connection reset", "keepalive",
        ),
        stop_words=_WEB_NOISE + _CREDENTIAL_NOISE + _APP_NOISE + (
            "file system", "sql", "kernel driver",
        ),
        cwe_typical={20, 125, 787, 400, 476, 362},
        cwe_impossible={79, 89, 352, 434, 22, 306},
    ),

    # ── Сеансовый уровень ЭМВОС ─────────────────────────────────────
    "d": LevelProfile(
        code="d",
        title="Сеансовый уровень ЭМВОС",
        keywords=(
            "session", "session id", "session token", "session fixation",
            "session hijack", "rpc", "grpc", "xml-rpc", "dcerpc",
            "l2tp", "pptp", "chap", "ms-chap", "mschapv2", "eap",
            "ntlm", "kerberos", "sasl", "negotiate", "handshake",
            "authentication protocol", "reauthentication", "renegotiation",
        ),
        stop_words=_WEB_NOISE[:6] + _APP_NOISE + ("file system",),
        cwe_typical={287, 290, 384, 613, 294, 131},
        cwe_impossible={89, 434},
    ),

    # ── Уровень представления ЭМВОС ─────────────────────────────────
    "r": LevelProfile(
        code="r",
        title="Уровень представления ЭМВОС",
        keywords=(
            "tls", "ssl", "dtls", "certificate", "x.509", "cipher",
            "cipher suite", "encryption", "decryption", "cryptographic",
            "openssl", "gnutls", "nss", "heartbeat extension",
            "encode", "decode", "encoding", "decoding", "charset",
            "unicode", "utf-8", "ascii", "ebcdic", "base64",
            "serialization", "deserialization", "asn.1", "der", "xdr",
            "compression", "decompression", "parser", "codec",
        ),
        stop_words=_CREDENTIAL_NOISE + ("sql injection", "print spooler"),
        cwe_typical={295, 327, 326, 502, 20, 125, 787, 400},
        cwe_impossible={89, 306},
    ),

    # ── Прикладной уровень ЭМВОС ────────────────────────────────────
    "q": LevelProfile(
        code="q",
        title="Прикладной уровень ЭМВОС",
        keywords=(
            "http", "https", "ssh", "sftp", "ftp", "telnet",
            "smtp", "imap", "pop3", "snmp", "sip", "rdp", "vnc",
            "smb", "nfs", "ldap", "dns", "dhcp", "ntp", "mqtt",
            "web server", "http server", "http request", "http response",
            "url", "uri", "daemon", "application protocol",
            # «server», «client», «service», «api» намеренно не включены:
            # они встречаются почти в каждом описании и признаком уровня
            # не являются — их место занимают имена самих протоколов
        ),
        stop_words=("kernel", "device driver", "firmware", "bios", "uefi",
                    "microcode", "phy", "antenna"),
        cwe_typical={22, 78, 79, 89, 94, 287, 306, 352, 434, 611, 918, 252, 415, 476},
        cwe_impossible={1300, 1256},
    ),

    # ── Аппаратный уровень модели УБИ ───────────────────────────────
    "a": LevelProfile(
        code="a",
        title="Аппаратный уровень",
        keywords=(
            "firmware", "bios", "uefi", "smm", "microcode", "processor",
            "cpu", "speculative execution", "branch predictor",
            "side channel", "cache timing", "rowhammer",
            "dma", "pcie", "pci express", "sata", "nvme", "usb controller",
            "memory controller", "chipset", "baseboard", "bmc", "ipmi",
            "power supply", "thermal", "tpm", "secure boot", "boot loader",
            "gpu", "graphics driver", "audio controller", "rtc",
        ),
        stop_words=_WEB_NOISE + _CREDENTIAL_NOISE + ("http request", "sql"),
        cwe_typical={1189, 1191, 1256, 1300, 119, 787, 125},
        cwe_impossible={79, 89, 352, 434, 918},
    ),

    # ── Подсистема драйверов (ядро ОС) ──────────────────────────────
    "i": LevelProfile(
        code="i",
        title="Подсистема драйверов устройств",
        keywords=(
            "driver", "device driver", "kernel module", "ioctl",
            "kernel", "kernel space", "dma", "interrupt", "irq",
            "firmware interface", "hal", "wdm", "miniport",
            "network adapter driver", "nic driver", "gpu driver",
            "usb driver", "audio driver", "storage driver",
        ),
        stop_words=_WEB_NOISE + _CREDENTIAL_NOISE + ("http request", "sql"),
        cwe_typical={119, 125, 787, 416, 415, 476, 362, 269},
        cwe_impossible={79, 89, 352, 434, 918},
    ),

    # ── Подсистема разграничения доступа (ядро ОС) ──────────────────
    "w": LevelProfile(
        code="w",
        title="Подсистема управления доступом",
        keywords=(
            "privilege", "privilege escalation", "permission", "access control",
            "selinux", "apparmor", "capability", "setuid", "setgid",
            "sudo", "acl", "discretionary access", "mandatory access",
            "security descriptor", "token", "impersonation",
            "authorization", "sandbox escape", "namespace",
        ),
        stop_words=_WEB_NOISE[:6] + ("phy", "antenna", "cable"),
        cwe_typical={269, 250, 264, 276, 285, 862, 863, 732, 284},
        cwe_impossible={1300, 1256},
    ),

    # ── Подсистема управления файлами (ядро ОС) ─────────────────────
    "p": LevelProfile(
        code="p",
        title="Подсистема управления файлами",
        keywords=(
            "file system", "filesystem", "ext4", "ext3", "xfs", "btrfs",
            "zfs", "ntfs", "fat32", "f2fs", "overlayfs", "tmpfs",
            "inode", "mount", "unmount", "symlink", "hard link",
            "path traversal", "directory traversal", "file descriptor",
            "journaling", "quota", "vfs",
        ),
        stop_words=_WEB_NOISE[:6] + ("phy", "antenna", "cable", "http request"),
        cwe_typical={22, 59, 787, 415, 416, 639, 732, 276},
        cwe_impossible={79, 89, 1300},
    ),

    # ── Подсистема управления процессами (ядро ОС) ──────────────────
    "v": LevelProfile(
        code="v",
        title="Подсистема управления процессами",
        keywords=(
            "process", "scheduler", "scheduling", "task_struct",
            "memory management", "page table", "mmap", "munmap",
            "fork", "exec", "signal handling", "ipc", "shared memory",
            "semaphore", "cgroup", "thread", "context switch",
            "out-of-memory", "oom", "race condition",
        ),
        stop_words=_WEB_NOISE[:6] + ("phy", "antenna", "cable", "http request"),
        cwe_typical={362, 416, 415, 400, 476, 190},
        cwe_impossible={79, 89, 1300},
    ),

    # ── Пользовательский уровень модели УБИ (периферия) ─────────────
    "h": LevelProfile(
        code="h",
        title="Пользовательский уровень",
        keywords=(
            "keyboard", "mouse", "touchpad", "touch screen", "hid",
            "printer", "scanner", "multifunction", "mfp",
            "monitor", "display", "webcam", "camera", "microphone",
            "speaker", "audio device", "headset",
            "removable media", "flash drive", "usb storage", "sd card",
            "peripheral", "input device", "output device",
        ),
        stop_words=("sql injection", "web application", "kernel", "phy"),
        cwe_typical={200, 306, 862, 1188},
        cwe_impossible={89, 918},
    ),
}


# ===================================================================
# Русские названия компонентов → английские токены поиска
# ===================================================================

# Названия протоколов уже латиницей (TCP, IPv4, SSL/TLS), их достаточно
# разбить на токены. Русским названиям нужен явный перевод.
COMPONENT_TOKENS: Dict[str, Sequence[str]] = {
    "драйвер сетевой карты":        ("network adapter", "nic", "ethernet driver"),
    "драйвер видео":                ("gpu", "graphics", "display driver"),
    "драйвер аудио":                ("audio", "sound", "codec"),
    "драйвер usb":                  ("usb",),
    "драйвер клавиатуры":           ("keyboard", "hid"),
    "драйвер компьютерной мыши":    ("mouse", "hid"),
    "драйвер съемных устройств":    ("removable", "usb storage"),
    "драйвер":                      ("driver",),
    "модель разграничения доступа": ("access control", "privilege", "permission"),
    "подсистема управления доступом": ("access control", "privilege", "permission",
                                       "authorization"),
    "подсистема управления файлами": ("file system", "filesystem", "ntfs", "ext4"),
    "подсистема управления процессами": ("process", "scheduler", "memory management"),
    "процессор":                    ("processor", "cpu"),
    "видеоконтроллер":              ("gpu", "graphics"),
    "аудиоконтроллер":              ("audio", "sound"),
    "материнская плата":            ("motherboard", "baseboard", "chipset"),
    "оперативное запоминающее":     ("memory", "dram", "dimm"),
    "система хранения данных":      ("storage", "ssd", "hard drive"),
    "сетевая карта":                ("network adapter", "nic", "ethernet"),
    "сетевой адаптер":              ("network adapter", "nic", "ethernet"),
    "блок питания":                 ("power supply",),
    "клавиатура":                   ("keyboard", "hid"),
    "компьютерная мышь":            ("mouse", "hid"),
    "мфу":                          ("printer", "scanner", "multifunction"),
    "принтер":                      ("printer",),
    "монитор":                      ("monitor", "display"),
    "сенсорн":                      ("touch", "touchscreen"),
    "съемные носители":             ("removable", "usb storage", "flash drive"),
    # Без ipv4/ipv6: для них есть отдельные строки паспорта, иначе
    # одни и те же уязвимости продублируются в трёх местах
    "ip-адрес":                     ("ip address", "ip packet", "ip header",
                                     "ip spoofing"),
    "mac адрес":                    ("mac address",),
    "mac-адрес":                    ("mac address",),
    "arp-таблица":                  ("arp",),
    "разъем":                       ("connector", "port"),
    "разъём":                       ("connector", "port"),
    "модуль wi-fi":                 ("wi-fi", "wifi", "wireless", "802.11"),
    "порт":                         ("port",),
}

# Токены короче трёх символов ловят слишком много ложных совпадений
_MIN_TOKEN_LEN = 3

# Служебные слова, которые не несут смысла при поиске в описании CVE
_STOP_TOKENS = {
    "для", "and", "the", "уровень", "уровня", "протокол", "сервер", "клиент",
    "server", "client", "подсистема", "модель", "устройств", "устройства",
}


def component_search_tokens(component_name: str) -> List[str]:
    """Извлекает из названия компонента токены для поиска в описании CVE.

    Название компонента — самый сильный сигнал релевантности: если в описании
    уязвимости встречается «TCP», она с большой вероятностью относится
    к компоненту TCP.

    Args:
        component_name: Название компонента, например «SSH-клиент»,
            «Драйвер сетевой карты», «IPv4»

    Returns:
        Список токенов в нижнем регистре
    """
    name = component_name.lower().strip()
    tokens: List[str] = []

    # 1) Явный перевод русских названий
    for ru_key, en_tokens in COMPONENT_TOKENS.items():
        if ru_key in name:
            tokens.extend(en_tokens)
            break

    # 2) Латинские фрагменты самого названия (TCP, IPv4, SSL, HTTP)
    for raw in re.findall(r"[a-z0-9][a-z0-9.\-/]*", name):
        for part in raw.split("/"):
            part = part.strip(".-")
            if len(part) >= _MIN_TOKEN_LEN and part not in _STOP_TOKENS:
                tokens.append(part)

    # Убираем дубликаты, сохраняя порядок
    seen: Set[str] = set()
    unique = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# ===================================================================
# Оценка релевантности
# ===================================================================

# Веса сигналов подобраны так, чтобы совпадение имени компонента само по себе
# проходило порог, а два ключевых слова уровня — тоже.
W_COMPONENT_HIT = 5     # Название компонента встретилось в описании
W_KEYWORD_HIT = 2       # Ключевое слово уровня
W_STOP_HIT = -3         # Стоп-слово чужого уровня
W_CWE_TYPICAL = 2       # CWE характерен для уровня
W_CWE_IMPOSSIBLE = -6   # CWE на этом уровне невозможен

SCORE_THRESHOLD = 5     # Ниже — считаем, что CVE не относится к уровню

_MAX_KEYWORD_CREDIT = 3  # Больше трёх ключевых слов роли уже не играют


def _parse_cwe_numbers(raw: object) -> Set[int]:
    """Достаёт номера CWE из поля cwe_id (может быть «CWE-119, CWE-787»)."""
    if not raw:
        return set()
    return {int(n) for n in re.findall(r"\b(\d{1,4})\b", str(raw))}


# Кеш скомпилированных шаблонов имени компонента: filter_cves_by_level
# вызывается для десятков компонентов подряд, а строит шаблон один раз.
_TOKEN_RE_CACHE: Dict[tuple, Optional[re.Pattern]] = {}


def _token_regex(tokens: Sequence[str]) -> Optional[re.Pattern]:
    """Возвращает скомпилированный шаблон для токенов имени компонента."""
    key = tuple(tokens)
    if key not in _TOKEN_RE_CACHE:
        _TOKEN_RE_CACHE[key] = _build_regex(tokens)
    return _TOKEN_RE_CACHE[key]


# Кеш слов предварительного отсева, ключ — (уровень, токены компонента)
_PRESCREEN_CACHE: Dict[tuple, tuple] = {}


def _prescreen_words(level_code: str, tokens: tuple,
                     profile: LevelProfile) -> tuple:
    """Слова быстрого отсева: имя компонента ИЛИ любое слово уровня.

    Описание, не содержащее ничего из этого, набрать порог не может —
    его можно пропустить, не запуская подсчёт совпадений.

    Проверка идёт обычным поиском подстроки, без регулярных выражений:
    на выборке в 17 600 описаний это 70 мс против 2 100 мс у шаблона
    с граничными условиями. Отсев намеренно грубый — он пропускает лишнее
    (например, «tcp» внутри «tcpdump»), а точный подсчёт с границами слов
    выполняется дальше, уже на паре сотен выживших записей.
    """
    key = (level_code, tokens)
    if key not in _PRESCREEN_CACHE:
        words = [w.lower() for w in list(tokens) + list(profile.keywords)]
        _PRESCREEN_CACHE[key] = tuple(dict.fromkeys(words))
    return _PRESCREEN_CACHE[key]


def _score_prepared(description: str, cwe_numbers: Set[int],
                    profile: LevelProfile,
                    tok_re: Optional[re.Pattern],
                    kw_re: Optional[re.Pattern],
                    sw_re: Optional[re.Pattern]) -> int:
    """Считает оценку по уже скомпилированным шаблонам.

    Вынесено отдельно, потому что filter_cves_by_level прогоняет через эту
    функцию тысячи описаний: компиляция шаблонов внутри цикла делала отбор
    на порядки медленнее самого запроса к базе.
    """
    score = 0

    if description:
        if tok_re is not None and tok_re.search(description):
            score += W_COMPONENT_HIT
        if kw_re is not None:
            hits = len({m.group(0) for m in kw_re.finditer(description)})
            score += W_KEYWORD_HIT * min(hits, _MAX_KEYWORD_CREDIT)
        if sw_re is not None:
            stops = len({m.group(0) for m in sw_re.finditer(description)})
            score += W_STOP_HIT * stops

    if cwe_numbers & profile.cwe_impossible:
        score += W_CWE_IMPOSSIBLE
    elif cwe_numbers & profile.cwe_typical:
        score += W_CWE_TYPICAL

    return score


def score_cve(cve: Dict, level_code: str,
              component_tokens: Sequence[str] = ()) -> int:
    """Считает релевантность CVE уровню модели.

    Args:
        cve: Словарь CVE. Значимы ключи ``description`` и ``cwe_id``
        level_code: Буквенный код уровня из LEVEL_PROFILES
        component_tokens: Токены названия компонента (см. component_search_tokens)

    Returns:
        Целочисленная оценка. Чем выше, тем вероятнее, что уязвимость
        относится к этому уровню. Порог отсечения — SCORE_THRESHOLD.
    """
    profile = LEVEL_PROFILES.get(level_code)
    if profile is None:
        return SCORE_THRESHOLD  # Неизвестный уровень — не фильтруем

    kw_re, sw_re = profile.compiled()
    return _score_prepared(
        (cve.get("description") or "").lower(),
        _parse_cwe_numbers(cve.get("cwe_id")),
        profile, _token_regex(tuple(component_tokens)), kw_re, sw_re,
    )


def explain_score(cve: Dict, level_code: str,
                  component_tokens: Sequence[str] = ()) -> str:
    """Человекочитаемое объяснение оценки — для отладки и подсказок в UI."""
    profile = LEVEL_PROFILES.get(level_code)
    if profile is None:
        return "уровень неизвестен, фильтр не применялся"

    description = (cve.get("description") or "").lower()
    kw_re, sw_re = profile.compiled()
    parts = []

    matched_tokens = [t for t in component_tokens
                      if re.search(rf"(?<![a-z0-9_]){re.escape(t)}(?![a-z0-9_])",
                                   description)]
    if matched_tokens:
        parts.append(f"имя компонента: {', '.join(matched_tokens[:3])}")
    if kw_re is not None:
        hits = sorted(set(m.group(0).lower() for m in kw_re.finditer(description)))
        if hits:
            parts.append(f"слова уровня: {', '.join(hits[:5])}")
    if sw_re is not None:
        stops = sorted(set(m.group(0).lower() for m in sw_re.finditer(description)))
        if stops:
            parts.append(f"стоп-слова: {', '.join(stops[:5])}")

    cwe_numbers = _parse_cwe_numbers(cve.get("cwe_id"))
    if cwe_numbers & profile.cwe_impossible:
        bad = sorted(cwe_numbers & profile.cwe_impossible)
        parts.append(f"CWE невозможен на уровне: {', '.join(f'CWE-{n}' for n in bad)}")
    elif cwe_numbers & profile.cwe_typical:
        good = sorted(cwe_numbers & profile.cwe_typical)
        parts.append(f"CWE характерен: {', '.join(f'CWE-{n}' for n in good)}")

    return "; ".join(parts) if parts else "признаков уровня не найдено"


# ===================================================================
# Основная функция фильтрации
# ===================================================================

def _cvss_value(cve: Dict) -> float:
    """Лучшая доступная оценка CVSS для сортировки (приоритет 3.1)."""
    for key in ("cvss_v3", "cvss_v4", "cvss_v2"):
        raw = cve.get(key)
        if raw not in (None, "", "--"):
            try:
                return float(raw)
            except (TypeError, ValueError):
                continue
    return 0.0


def filter_cves_by_level(cves: Iterable[Dict],
                         level_code: str,
                         component_name: str = "",
                         limit: int = 10,
                         threshold: Optional[int] = None) -> List[Dict]:
    """Отбирает CVE, относящиеся к уровню, и ранжирует по релевантности.

    Порядок сортировки: сначала релевантность уровню, при равной
    релевантности — CVSS по убыванию, затем дата публикации по убыванию.
    Это заменяет прежнее «первые десять из выборки», из-за которого
    в паспорт попадали уязвимости 1999 года.

    Args:
        cves: Исходный список CVE (результат запроса по CPE)
        level_code: Буквенный код уровня из LEVEL_PROFILES
        component_name: Название компонента для сопоставления с описанием
        limit: Сколько CVE вернуть максимум
        threshold: Порог отсечения; по умолчанию SCORE_THRESHOLD

    Returns:
        Отфильтрованный и отсортированный список. Каждому CVE добавляется
        ключ ``level_score`` — оценка релевантности.

        Пустой список — допустимый результат: он означает, что среди
        уязвимостей продукта нет относящихся к этому уровню. В эталонном
        паспорте у многих компонентов в колонке CVE стоит прочерк.
    """
    if threshold is None:
        threshold = SCORE_THRESHOLD

    profile = LEVEL_PROFILES.get(level_code)
    if profile is None:
        # Уровень неизвестен — отдаём как есть, отсортировав по CVSS
        return sorted(cves, key=_cvss_value, reverse=True)[:limit]

    tokens = component_search_tokens(component_name) if component_name else []
    tok_re = _token_regex(tuple(tokens))
    kw_re, sw_re = profile.compiled()

    # Если у компонента есть узнаваемое имя (TCP, IPSec, ARP, Wi-Fi),
    # требуем, чтобы оно встречалось в описании. Иначе строка «IPSec»
    # заполняется уязвимостями IPv6: уровень верный, но компонент чужой,
    # и одни и те же CVE дублируются по всем строкам уровня.
    # Слова уровня в этом случае влияют только на порядок, а не на допуск.
    #
    # Когда токенов нет (название целиком русское и перевода для него
    # не задано), допуск идёт по словам уровня — иначе строка осталась бы
    # пустой при наличии подходящих уязвимостей.
    if tokens:
        prescreen = tuple(tokens)
        gate = tok_re
    else:
        prescreen = _prescreen_words(level_code, (), profile)
        gate = None

    scored: List[Dict] = []
    for cve in cves:
        description = (cve.get("description") or "").lower()
        # Грубый отсев подстрокой — отбрасывает почти всю выборку без regex
        if prescreen and not any(w in description for w in prescreen):
            continue
        # Точная проверка с границами слов: «tcp» не должен ловиться в «tcpdump»
        if gate is not None and not gate.search(description):
            continue
        score = _score_prepared(
            description, _parse_cwe_numbers(cve.get("cwe_id")),
            profile, tok_re, kw_re, sw_re,
        )
        if score >= threshold:
            enriched = dict(cve)
            enriched["level_score"] = score
            scored.append(enriched)

    scored.sort(
        key=lambda c: (c["level_score"], _cvss_value(c), c.get("published") or ""),
        reverse=True,
    )
    return scored[:limit]
