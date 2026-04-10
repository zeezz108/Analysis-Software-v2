"""
Модуль валидации сетевых параметров

Содержит функции для проверки корректности:
- IP-адресов
- MAC-адресов
- Масок подсети
- VLAN ID с учётом режима порта
"""

import re
from typing import Tuple


def validate_ip(ip: str) -> bool:
    """
    Проверяет корректность IP-адреса (IPv4).

    Args:
        ip: IP-адрес в виде строки (например, "192.168.1.1")

    Returns:
        True если IP-адрес корректен, иначе False

    Examples:
        >>> validate_ip("192.168.1.1")
        True
        >>> validate_ip("256.1.1.1")
        False
        >>> validate_ip("")
        False
    """
    if not ip:
        return False

    # Проверяем формат: три точки, четыре числа
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False

    # Проверяем диапазон каждого октета
    for octet in ip.split('.'):
        if int(octet) > 255:
            return False

    return True


def validate_mac(mac: str) -> bool:
    """
    Проверяет корректность MAC-адреса.

    Поддерживаемые форматы:
    - 00:11:22:33:44:55 (шесть групп, разделённых двоеточием)
    - 00-11-22-33-44-55 (шесть групп, разделённых дефисом)
    - 0011.2233.4455 (три группы, разделённых точкой)

    Args:
        mac: MAC-адрес в виде строки

    Returns:
        True если MAC-адрес корректен, иначе False

    Examples:
        >>> validate_mac("00:11:22:33:44:55")
        True
        >>> validate_mac("00-11-22-33-44-55")
        True
        >>> validate_mac("0011.2233.4455")
        True
        >>> validate_mac("invalid")
        False
    """
    if not mac:
        return False

    # Формат: 00:11:22:33:44:55 или 00-11-22-33-44-55
    pattern1 = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    # Формат: 0011.2233.4455
    pattern2 = r'^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$'

    return bool(re.match(pattern1, mac) or re.match(pattern2, mac))


def validate_mask(mask: str) -> bool:
    """
    Проверяет корректность маски подсети (формат CIDR).

    Args:
        mask: Маска в формате CIDR (число от 0 до 32)

    Returns:
        True если маска корректна, иначе False

    Examples:
        >>> validate_mask("24")
        True
        >>> validate_mask("0")
        True
        >>> validate_mask("32")
        True
        >>> validate_mask("33")
        False
        >>> validate_mask("abc")
        False
    """
    if not mask:
        return False

    try:
        cidr = int(mask)
        return 0 <= cidr <= 32
    except ValueError:
        return False


def validate_vlan_id(vlan_id: str, vlan_mode: str = "untagged") -> bool:
    """
    Проверяет корректность VLAN ID с учётом режима порта.

    Args:
        vlan_id: Строка с VLAN ID (например "100" или "10,20,30" или "100-200")
        vlan_mode: Режим порта - "untagged" (access) или "tagged" (trunk)

    Returns:
        True если VLAN ID корректен, False если ошибка

    Examples:
        >>> validate_vlan_id("100", "untagged")
        True
        >>> validate_vlan_id("100,200", "untagged")  # Несколько VLAN в untagged - запрещено
        False
        >>> validate_vlan_id("100,200", "tagged")
        True
        >>> validate_vlan_id("100-200", "tagged")
        True
        >>> validate_vlan_id("", "tagged")  # Пустое значение допустимо
        True
    """
    # Пустое значение допустимо (VLAN не настроен)
    if not vlan_id or vlan_id.strip() == "":
        return True

    vlan_id = vlan_id.strip()

    # Режим untagged (access) - разрешён ТОЛЬКО один VLAN ID
    if vlan_mode == "untagged":
        if ',' in vlan_id or '-' in vlan_id:
            return False  # Несколько VLAN или диапазон недопустимы
        try:
            vid = int(vlan_id)
            return 1 <= vid <= 65000
        except ValueError:
            return False

    # Режим tagged (trunk) - разрешены несколько VLAN, диапазоны и комбинации
    elif vlan_mode == "tagged":
        vlan_parts = [v.strip() for v in vlan_id.split(',')]

        for part in vlan_parts:
            if not part:
                continue

            # Проверяем, является ли это диапазоном (например, "100-200")
            if '-' in part:
                try:
                    range_parts = part.split('-')
                    if len(range_parts) != 2:
                        return False
                    start_vid = int(range_parts[0].strip())
                    end_vid = int(range_parts[1].strip())
                    if not (1 <= start_vid <= 65000 and 1 <= end_vid <= 65000):
                        return False
                    if start_vid > end_vid:
                        return False
                except ValueError:
                    return False
            else:
                # Одиночный VLAN ID
                try:
                    vid = int(part)
                    if not (1 <= vid <= 65000):
                        return False
                except ValueError:
                    return False

        return True

    # Неизвестный режим
    return False


def validate_port_number(port: str) -> bool:
    """
    Проверяет корректность номера порта (1-65535).

    Args:
        port: Номер порта в виде строки

    Returns:
        True если порт корректен, иначе False
    """
    if not port:
        return False

    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False


def validate_port_range(port_range: str) -> bool:
    """
    Проверяет корректность диапазона портов (например, "1000-2000").

    Args:
        port_range: Диапазон портов в формате "start-end"

    Returns:
        True если диапазон корректен, иначе False
    """
    if not port_range or '-' not in port_range:
        return False

    try:
        start, end = port_range.split('-')
        start_num = int(start.strip())
        end_num = int(end.strip())
        return 1 <= start_num <= 65535 and 1 <= end_num <= 65535 and start_num <= end_num
    except ValueError:
        return False


def validate_ports_list(ports_str: str) -> bool:
    """
    Проверяет корректность списка портов (например, "80,443,8080").

    Args:
        ports_str: Список портов через запятую

    Returns:
        True если все порты корректны, иначе False
    """
    if not ports_str:
        return True  # Пустой список допустим

    parts = [p.strip() for p in ports_str.split(',')]

    for part in parts:
        # Проверяем, может быть это диапазон
        if '-' in part:
            if not validate_port_range(part):
                return False
        else:
            if not validate_port_number(part):
                return False

    return True


def validate_cidr_network(network: str) -> bool:
    """
    Проверяет корректность сети в формате CIDR (например, "192.168.1.0/24").

    Args:
        network: Сеть в формате IP/маска

    Returns:
        True если сеть корректна, иначе False
    """
    if not network or '/' not in network:
        return False

    try:
        ip_part, mask_part = network.split('/')
        return validate_ip(ip_part) and validate_mask(mask_part)
    except ValueError:
        return False


# Словарь с сообщениями об ошибках для удобства использования в UI
ERROR_MESSAGES = {
    'ip_invalid': 'Неверный формат IP-адреса!\nФормат: 192.168.1.1',
    'mac_invalid': 'Неверный формат MAC-адреса!\nФормат: 00:11:22:33:44:55',
    'mask_invalid': 'Неверный формат маски подсети!\nФормат: число от 0 до 32',
    'vlan_untagged_invalid': 'Для режима "untagged" разрешён ТОЛЬКО ОДИН VLAN ID!\nПример: 100',
    'vlan_tagged_invalid': 'Для режима "tagged" доступны форматы:\n• Один VLAN: 100\n• Несколько VLAN: 10,20,30\n• Диапазон: 100-200\n• Комбинация: 10,20,100-200',
    'port_invalid': 'Неверный номер порта!\nДиапазон: 1-65535',
    'port_range_invalid': 'Неверный диапазон портов!\nФормат: 1000-2000',
    'cidr_invalid': 'Неверный формат сети!\nФормат: 192.168.1.0/24'
}


def get_error_message(error_key: str) -> str:
    """
    Возвращает сообщение об ошибке по ключу.

    Args:
        error_key: Ключ ошибки из ERROR_MESSAGES

    Returns:
        Текст сообщения об ошибке
    """
    return ERROR_MESSAGES.get(error_key, 'Неизвестная ошибка валидации')