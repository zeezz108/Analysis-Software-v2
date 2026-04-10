"""
Модуль сетевых утилит

Содержит функции для:
- Расчёта адреса сети по IP и маске
- Проверки принадлежности IP к сети
- Преобразования масок (CIDR <-> десятичная)
- Работы с подсетями
"""

import ipaddress
from typing import Tuple, Optional


def cidr_to_decimal_mask(cidr: int) -> str:
    """
    Преобразует CIDR маску в десятичный формат.

    Args:
        cidr: CIDR маска (0-32)

    Returns:
        Десятичная маска в виде "255.255.255.0"

    Examples:
        >>> cidr_to_decimal_mask(24)
        '255.255.255.0'
        >>> cidr_to_decimal_mask(16)
        '255.255.0.0'
    """
    if not 0 <= cidr <= 32:
        return "0.0.0.0"

    mask_int = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
    return f"{(mask_int >> 24) & 0xFF}.{(mask_int >> 16) & 0xFF}.{(mask_int >> 8) & 0xFF}.{mask_int & 0xFF}"


def decimal_mask_to_cidr(mask: str) -> int:
    """
    Преобразует десятичную маску в CIDR формат.

    Args:
        mask: Десятичная маска (например, "255.255.255.0")

    Returns:
        CIDR маска (0-32)

    Examples:
        >>> decimal_mask_to_cidr("255.255.255.0")
        24
        >>> decimal_mask_to_cidr("255.255.0.0")
        16
    """
    try:
        parts = mask.split('.')
        if len(parts) != 4:
            return 0

        mask_int = 0
        for part in parts:
            mask_int = (mask_int << 8) | int(part)

        # Подсчитываем количество единичных битов
        cidr = bin(mask_int).count('1')
        return cidr
    except (ValueError, AttributeError):
        return 0


def calculate_network(ip: str, mask: str) -> str:
    """
    Рассчитывает адрес сети по IP и маске.

    Поддерживает маску как в CIDR формате (число), так и в десятичном формате.

    Args:
        ip: IP-адрес (например, "192.168.1.100")
        mask: Маска ("24" или "255.255.255.0")

    Returns:
        Адрес сети (например, "192.168.1.0")

    Examples:
        >>> calculate_network("192.168.1.100", "24")
        '192.168.1.0'
        >>> calculate_network("10.0.0.50", "255.255.0.0")
        '10.0.0.0'
    """
    if not ip or not mask:
        return "0.0.0.0"

    try:
        # Если маска в формате CIDR (число)
        if mask.isdigit():
            cidr = int(mask)
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
            return str(network.network_address)

        # Если маска в десятичном формате
        else:
            cidr = decimal_mask_to_cidr(mask)
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
            return str(network.network_address)

    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        # Упрощённый расчёт для распространённых случаев (на случай ошибок)
        try:
            if mask.isdigit():
                mask_int = int(mask)
                if mask_int == 24:
                    return ".".join(ip.split('.')[:3]) + ".0"
                elif mask_int == 16:
                    return ".".join(ip.split('.')[:2]) + ".0.0"
                elif mask_int == 8:
                    return ip.split('.')[0] + ".0.0.0"
        except (ValueError, TypeError, AttributeError):
            pass
        return "0.0.0.0"


def calculate_broadcast(ip: str, mask: str) -> str:
    """
    Рассчитывает широковещательный адрес для сети.

    Args:
        ip: IP-адрес
        mask: Маска ("24" или "255.255.255.0")

    Returns:
        Широковещательный адрес

    Examples:
        >>> calculate_broadcast("192.168.1.100", "24")
        '192.168.1.255'
    """
    if not ip or not mask:
        return "255.255.255.255"

    try:
        if mask.isdigit():
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        else:
            cidr = decimal_mask_to_cidr(mask)
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return str(network.broadcast_address)
    except (ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return "255.255.255.255"


def calculate_host_range(ip: str, mask: str) -> Tuple[str, str]:
    """
    Рассчитывает диапазон доступных хостов в сети.

    Args:
        ip: IP-адрес
        mask: Маска

    Returns:
        Кортеж (первый_доступный_IP, последний_доступный_IP)

    Examples:
        >>> calculate_host_range("192.168.1.100", "24")
        ('192.168.1.1', '192.168.1.254')
    """
    if not ip or not mask:
        return ("0.0.0.0", "0.0.0.0")

    try:
        if mask.isdigit():
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        else:
            cidr = decimal_mask_to_cidr(mask)
            network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)

        hosts = list(network.hosts())
        if hosts:
            return (str(hosts[0]), str(hosts[-1]))
        return (str(network.network_address), str(network.broadcast_address))
    except (ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return ("0.0.0.0", "0.0.0.0")


def is_ip_in_network(ip: str, network_ip: str, mask: str) -> bool:
    """
    Проверяет, принадлежит ли IP-адрес указанной сети.

    Args:
        ip: Проверяемый IP-адрес
        network_ip: Адрес сети
        mask: Маска сети

    Returns:
        True если IP принадлежит сети, иначе False

    Examples:
        >>> is_ip_in_network("192.168.1.100", "192.168.1.0", "24")
        True
        >>> is_ip_in_network("192.168.2.100", "192.168.1.0", "24")
        False
    """
    if not all([ip, network_ip, mask]):
        return False

    try:
        if mask.isdigit():
            network = ipaddress.IPv4Network(f"{network_ip}/{mask}", strict=False)
        else:
            cidr = decimal_mask_to_cidr(mask)
            network = ipaddress.IPv4Network(f"{network_ip}/{cidr}", strict=False)

        return ipaddress.IPv4Address(ip) in network
    except (ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def get_network_size(mask: str) -> int:
    """
    Возвращает количество доступных хостов в сети.

    Args:
        mask: Маска ("24" или "255.255.255.0")

    Returns:
        Количество хостов

    Examples:
        >>> get_network_size("24")
        254
        >>> get_network_size("30")
        2
    """
    try:
        if mask.isdigit():
            cidr = int(mask)
        else:
            cidr = decimal_mask_to_cidr(mask)

        return 2 ** (32 - cidr) - 2
    except (ValueError, TypeError):
        return 0


def is_valid_network_pair(ip1: str, mask1: str, ip2: str, mask2: str) -> bool:
    """
    Проверяет, находятся ли два IP в одной сети.

    Args:
        ip1: Первый IP
        mask1: Маска первого IP
        ip2: Второй IP
        mask2: Маска второго IP

    Returns:
        True если оба IP в одной сети, иначе False
    """
    if not all([ip1, mask1, ip2, mask2]):
        return False

    network1 = calculate_network(ip1, mask1)
    network2 = calculate_network(ip2, mask2)

    return network1 == network2


def get_next_ip(ip: str, increment: int = 1) -> Optional[str]:
    """
    Возвращает следующий IP-адрес.

    Args:
        ip: Исходный IP-адрес
        increment: Шаг увеличения

    Returns:
        Следующий IP или None при ошибке

    Examples:
        >>> get_next_ip("192.168.1.1")
        '192.168.1.2'
        >>> get_next_ip("192.168.1.254")
        '192.168.1.255'
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        next_ip = ip_obj + increment
        return str(next_ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def get_previous_ip(ip: str, decrement: int = 1) -> Optional[str]:
    """
    Возвращает предыдущий IP-адрес.

    Args:
        ip: Исходный IP-адрес
        decrement: Шаг уменьшения

    Returns:
        Предыдущий IP или None при ошибке
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        prev_ip = ip_obj - decrement
        return str(prev_ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def ip_to_int(ip: str) -> Optional[int]:
    """
    Преобразует IP-адрес в целое число.

    Args:
        ip: IP-адрес в виде строки

    Returns:
        Целое число или None при ошибке

    Examples:
        >>> ip_to_int("192.168.1.1")
        3232235521
    """
    try:
        return int(ipaddress.IPv4Address(ip))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def int_to_ip(ip_int: int) -> Optional[str]:
    """
    Преобразует целое число в IP-адрес.

    Args:
        ip_int: Целое число (0 - 4294967295)

    Returns:
        IP-адрес или None при ошибке

    Examples:
        >>> int_to_ip(3232235521)
        '192.168.1.1'
    """
    try:
        return str(ipaddress.IPv4Address(ip_int))
    except (ValueError, ipaddress.AddressValueError):
        return None


def sort_ips(ips: list) -> list:
    """
    Сортирует список IP-адресов.

    Args:
        ips: Список IP-адресов в виде строк

    Returns:
        Отсортированный список IP-адресов
    """
    valid_ips = []
    for ip in ips:
        ip_int = ip_to_int(ip)
        if ip_int is not None:
            valid_ips.append((ip_int, ip))

    valid_ips.sort(key=lambda x: x[0])
    return [ip for _, ip in valid_ips]


# Константы для распространённых сетей
COMMON_NETWORKS = {
    "192.168.0.0/16": "Частная сеть (C класс)",
    "10.0.0.0/8": "Частная сеть (A класс)",
    "172.16.0.0/12": "Частная сеть (B класс)",
    "169.254.0.0/16": "Link-local (APIPA)",
    "127.0.0.0/8": "Локальный хост (loopback)",
    "0.0.0.0/0": "Маршрут по умолчанию",
    "224.0.0.0/4": "Мультикаст",
    "240.0.0.0/4": "Резервирование"
}


def get_network_description(network_cidr: str) -> str:
    """
    Возвращает описание для распространённых сетей.

    Args:
        network_cidr: Сеть в формате CIDR (например, "192.168.0.0/16")

    Returns:
        Описание сети или "Неизвестная сеть"
    """
    return COMMON_NETWORKS.get(network_cidr, "Неизвестная сеть")