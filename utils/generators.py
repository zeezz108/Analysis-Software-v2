"""
Модуль генерации тестовых данных

Содержит функции для генерации:
- Тестовых IP-адресов
- Тестовых MAC-адресов
- Тестовых масок подсети
- Уникальных идентификаторов (UID)
"""

import uuid
import random
from typing import List, Optional


def uid() -> str:
    """
    Генерирует уникальный идентификатор (UUID4).

    Returns:
        Строка с уникальным идентификатором

    Examples:
        >>> uid()
        '123e4567-e89b-12d3-a456-426614174000'
    """
    return str(uuid.uuid4())


def generate_test_ip() -> str:
    """
    Генерирует тестовый IP-адрес в диапазоне 192.168.x.x.

    Returns:
        Строка с IP-адресом вида "192.168.1.100"

    Examples:
        >>> ip = generate_test_ip()
        >>> ip.startswith('192.168.')
        True
    """
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"


def generate_test_mac() -> str:
    """
    Генерирует тестовый MAC-адрес в формате с двоеточиями.

    Returns:
        Строка с MAC-адресом вида "aa:bb:cc:dd:ee:ff"

    Examples:
        >>> mac = generate_test_mac()
        >>> len(mac) == 17  # 6 групп по 2 символа + 5 двоеточий
        True
    """
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


def generate_test_mac_dash() -> str:
    """
    Генерирует тестовый MAC-адрес в формате с дефисами.

    Returns:
        Строка с MAC-адресом вида "aa-bb-cc-dd-ee-ff"
    """
    return "-".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


def generate_test_mac_dot() -> str:
    """
    Генерирует тестовый MAC-адрес в формате с точками.

    Returns:
        Строка с MAC-адресом вида "aabb.ccdd.eeff"
    """
    parts = []
    for i in range(0, 6, 2):
        part = f"{random.randint(0, 255):02x}{random.randint(0, 255):02x}"
        parts.append(part)
    return ".".join(parts)


def generate_test_mask() -> str:
    """
    Генерирует тестовую маску подсети (CIDR).

    Returns:
        Строка с маской (чаще всего /24, /16, /8, /29, /30)

    Examples:
        >>> mask = generate_test_mask()
        >>> mask in ['24', '16', '8', '29', '30']
        True
    """
    masks = ["24", "16", "8", "29", "30"]
    return random.choice(masks)


def generate_test_vlan_id(mode: str = "untagged") -> Optional[str]:
    """
    Генерирует тестовый VLAN ID с учётом режима.

    Args:
        mode: Режим порта - "untagged" или "tagged"

    Returns:
        Строка с VLAN ID или None если генерация невозможна

    Examples:
        >>> vlan = generate_test_vlan_id("untagged")
        >>> 1 <= int(vlan) <= 4094
        True
        >>> vlan = generate_test_vlan_id("tagged")
        >>> ',' in vlan or '-' in vlan  # Может быть несколько VLAN
        True
    """
    if mode == "untagged":
        # Один VLAN
        return str(random.randint(1, 4094))
    elif mode == "tagged":
        # Выбираем случайный формат
        fmt = random.choice(['single', 'multiple', 'range', 'mixed'])

        if fmt == 'single':
            return str(random.randint(1, 4094))
        elif fmt == 'multiple':
            # 2-4 VLAN через запятую
            count = random.randint(2, 4)
            vlans = [str(random.randint(1, 4094)) for _ in range(count)]
            return ",".join(vlans)
        elif fmt == 'range':
            # Диапазон VLAN
            start = random.randint(1, 4000)
            end = start + random.randint(10, 100)
            return f"{start}-{end}"
        else:  # mixed
            # Комбинация одиночных и диапазона
            single1 = str(random.randint(1, 4094))
            single2 = str(random.randint(1, 4094))
            start = random.randint(1, 4000)
            end = start + random.randint(10, 100)
            return f"{single1},{single2},{start}-{end}"

    return None


def generate_test_port_number() -> str:
    """
    Генерирует тестовый номер порта (1-65535).

    Returns:
        Строка с номером порта
    """
    # Чаще генерируем популярные порты
    popular_ports = ["80", "443", "22", "3389", "53", "25", "21", "8080", "3306", "5432"]
    if random.choice([True, False]):
        return random.choice(popular_ports)
    else:
        return str(random.randint(1024, 65535))


def generate_test_port_range() -> str:
    """
    Генерирует тестовый диапазон портов.

    Returns:
        Строка с диапазоном вида "1000-2000"
    """
    start = random.randint(1024, 50000)
    end = start + random.randint(10, 1000)
    return f"{start}-{end}"


def generate_test_ports_list() -> str:
    """
    Генерирует тестовый список портов (смесь одиночных и диапазонов).

    Returns:
        Строка со списком портов вида "80,443,1000-2000,8080"
    """
    formats = []

    # Добавляем 1-3 популярных порта
    popular = ["80", "443", "22", "3389"]
    popular_count = random.randint(1, 3)
    formats.extend(random.sample(popular, popular_count))

    # Иногда добавляем диапазон
    if random.choice([True, False]):
        formats.append(generate_test_port_range())

    # Иногда добавляем случайный порт
    if random.choice([True, False]):
        formats.append(str(random.randint(1024, 65535)))

    return ",".join(formats)


def generate_test_network_cidr() -> str:
    """
    Генерирует тестовую сеть в формате CIDR.

    Returns:
        Строка с сетью вида "192.168.1.0/24"
    """
    # Генерируем случайную сеть
    first_octet = random.choice([10, 172, 192])

    if first_octet == 10:
        # 10.0.0.0/8
        second = random.randint(0, 255)
        third = random.randint(0, 255)
        network = f"10.{second}.{third}.0"
    elif first_octet == 172:
        # 172.16.0.0/12
        second = random.randint(16, 31)
        third = random.randint(0, 255)
        network = f"172.{second}.{third}.0"
    else:
        # 192.168.0.0/16
        second = random.randint(0, 255)
        third = random.randint(0, 255)
        network = f"192.168.{second}.{third}.0"

    mask = random.choice(["24", "16", "8", "29", "30"])
    return f"{network}/{mask}"


def generate_test_hostname(prefix: str = "host") -> str:
    """
    Генерирует тестовое имя хоста.

    Args:
        prefix: Префикс для имени хоста

    Returns:
        Строка с именем хоста вида "host-01"
    """
    number = random.randint(1, 99)
    return f"{prefix}-{number:02d}"


def generate_test_description() -> str:
    """
    Генерирует тестовое описание.

    Returns:
        Строка с тестовым описанием
    """
    descriptions = [
        "Тестовый узел для отладки",
        "Временная конфигурация",
        "Образец для демонстрации",
        "Узел разрабо��чика",
        "Лабораторный стенд",
        "Тестовая среда",
        "Для отработки сценариев"
    ]
    return random.choice(descriptions)


def generate_batch_test_data(count: int = 10) -> List[dict]:
    """
    Генерирует пакет тестовых данных для узлов.

    Args:
        count: Количество наборов данных для генерации

    Returns:
        Список словарей с тестовыми данными
    """
    node_types = ["ARM", "Router", "Switch", "Server"]
    result = []

    for i in range(count):
        data = {
            "name": f"Test_{node_types[i % len(node_types)]}_{i + 1:02d}",
            "type": node_types[i % len(node_types)],
            "ip": generate_test_ip(),
            "mac": generate_test_mac(),
            "mask": generate_test_mask(),
            "vlan_id": generate_test_vlan_id(random.choice(["untagged", "tagged"])),
            "description": generate_test_description()
        }
        result.append(data)

    return result


# Константы для популярных значений
POPULAR_IPS = [
    "192.168.1.1",
    "192.168.1.254",
    "10.0.0.1",
    "172.16.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1"
]

POPULAR_MACS = [
    "00:11:22:33:44:55",
    "AA:BB:CC:DD:EE:FF",
    "DE:AD:BE:EF:CA:FE",
    "00:1A:2B:3C:4D:5E"
]

POPULAR_MASKS = ["24", "16", "8", "29", "30", "32", "0"]

POPULAR_VLANS = {
    "untagged": ["100", "200", "300", "400", "500"],
    "tagged": ["10,20,30", "100-200", "100,200,300", "1000-2000", "10,20,100-200"]
}