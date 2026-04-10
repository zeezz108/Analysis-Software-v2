"""
Модуль для работы с CPE (Common Platform Enumeration)

Содержит функции для:
- Парсинга CPE строк
- Извлечения вендора, продукта и версии из компонентов
- Нормализации строк компонентов для поиска в CVE базе
"""

import re
from typing import Dict, List, Optional, Tuple


def extract_cpe_components(component_string: str) -> Dict[str, str]:
    """
    Извлекает вендора, продукт и версию из строки компонента.

    Поддерживает различные форматы:
    - "Microsoft Windows 10"
    - "Intel Core i7-8700K"
    - "NVIDIA GeForce RTX 3080"
    - "OpenSSL 1.1.1"

    Args:
        component_string: Строка с описанием компонента

    Returns:
        Словарь с ключами 'vendor', 'product', 'version'

    Examples:
        >>> extract_cpe_components("Microsoft Windows 10")
        {'vendor': 'microsoft', 'product': 'windows', 'version': '10'}

        >>> extract_cpe_components("Intel Core i7-8700K")
        {'vendor': 'intel', 'product': 'core i7-8700k', 'version': ''}

        >>> extract_cpe_components("NVIDIA GeForce RTX 3080 Driver 551.86")
        {'vendor': 'nvidia', 'product': 'geforce rtx 3080 driver', 'version': '551.86'}
    """
    result = {
        'vendor': '',
        'product': '',
        'version': ''
    }

    if not component_string:
        return result

    parts = component_string.strip().split(' ')

    if len(parts) >= 2:
        result['vendor'] = parts[0].lower()

        product_parts = []
        version_parts = []

        for part in parts[1:]:
            # Проверяем, похоже ли на версию (содержит цифры или точки)
            if any(c.isdigit() for c in part) or '.' in part:
                version_parts.append(part)
            else:
                product_parts.append(part)

        result['product'] = ' '.join(product_parts).lower()
        result['version'] = ' '.join(version_parts).lower()

    # Специальная обработка для известных вендоров
    component_lower = component_string.lower()

    # Microsoft Windows
    if 'windows' in component_lower:
        result['vendor'] = 'microsoft'
        result['product'] = 'windows'
        for part in parts:
            if part.isdigit() or part in ['10', '11', '8.1', '7', 'xp', 'vista']:
                result['version'] = part
                break

    # Linux дистрибутивы
    elif 'ubuntu' in component_lower:
        result['vendor'] = 'canonical'
        result['product'] = 'ubuntu'
        # Извлекаем версию (например, "20.04")
        version_match = re.search(r'(\d+\.\d+)', component_string)
        if version_match:
            result['version'] = version_match.group(1)

    elif 'debian' in component_lower:
        result['vendor'] = 'debian'
        result['product'] = 'debian'
        version_match = re.search(r'(\d+)', component_string)
        if version_match:
            result['version'] = version_match.group(1)

    elif 'centos' in component_lower or 'rhel' in component_lower or 'red hat' in component_lower:
        result['vendor'] = 'redhat'
        result['product'] = 'enterprise_linux' if 'rhel' in component_lower else 'centos'
        version_match = re.search(r'(\d+)', component_string)
        if version_match:
            result['version'] = version_match.group(1)

    # Intel
    elif 'intel' in component_lower:
        result['vendor'] = 'intel'
        # Определяем тип продукта
        if 'core' in component_lower:
            result['product'] = 'core'
            version_match = re.search(r'core\s+(\S+)', component_lower)
            if version_match:
                result['version'] = version_match.group(1)
        elif 'xeon' in component_lower:
            result['product'] = 'xeon'
        elif 'pentium' in component_lower:
            result['product'] = 'pentium'
        elif 'celeron' in component_lower:
            result['product'] = 'celeron'
        elif 'atom' in component_lower:
            result['product'] = 'atom'

    # AMD
    elif 'amd' in component_lower:
        result['vendor'] = 'amd'
        if 'ryzen' in component_lower:
            result['product'] = 'ryzen'
        elif 'athlon' in component_lower:
            result['product'] = 'athlon'
        elif 'radeon' in component_lower:
            result['product'] = 'radeon'
        elif 'epyc' in component_lower:
            result['product'] = 'epyc'

    # NVIDIA
    elif 'nvidia' in component_lower:
        result['vendor'] = 'nvidia'
        if 'geforce' in component_lower:
            result['product'] = 'geforce'
        elif 'quadro' in component_lower:
            result['product'] = 'quadro'
        elif 'tesla' in component_lower:
            result['product'] = 'tesla'
        elif 'rtx' in component_lower:
            result['product'] = 'rtx'
        elif 'driver' in component_lower:
            result['product'] = 'driver'

    # Cisco
    elif 'cisco' in component_lower:
        result['vendor'] = 'cisco'
        if 'ios' in component_lower:
            result['product'] = 'ios'
        elif 'nx-os' in component_lower:
            result['product'] = 'nx_os'
        elif 'asa' in component_lower:
            result['product'] = 'asa'

    # VMware
    elif 'vmware' in component_lower:
        result['vendor'] = 'vmware'
        if 'esxi' in component_lower:
            result['product'] = 'esxi'
        elif 'vsphere' in component_lower:
            result['product'] = 'vsphere'
        elif 'workstation' in component_lower:
            result['product'] = 'workstation'

    return result


def normalize_component_name(component: str) -> str:
    """
    Нормализует имя компонента для поиска.

    Удаляет лишние пробелы, приводит к нижнему регистру,
    заменяет специальные символы.

    Args:
        component: Исходное имя компонента

    Returns:
        Нормализованная строка
    """
    if not component:
        return ""

    # Приводим к нижнему регистру
    normalized = component.lower()

    # Заменяем пробелы на подчёркивания (для CPE формата)
    normalized = normalized.replace(' ', '_')

    # Удаляем специальные символы
    normalized = re.sub(r'[^\w\-\.]', '', normalized)

    # Убираем множественные подчёркивания
    normalized = re.sub(r'_+', '_', normalized)

    return normalized.strip('_')


def parse_cpe_string(cpe_string: str) -> Optional[Dict[str, str]]:
    """
    Парсит CPE строку формата:
    cpe:2.3:part:vendor:product:version:update:edition:language

    Args:
        cpe_string: CPE строка

    Returns:
        Словарь с полями CPE или None при ошибке

    Examples:
        >>> parse_cpe_string("cpe:2.3:o:microsoft:windows_10:10.0:*:*:*:*:*:*:*")
        {'part': 'o', 'vendor': 'microsoft', 'product': 'windows_10', 'version': '10.0'}
    """
    if not cpe_string:
        return None

    parts = cpe_string.split(':')

    # Минимальная длина CPE строки
    if len(parts) < 6:
        return None

    # Проверяем, что это CPE
    if parts[0] != 'cpe' or (parts[1] != '2.3' and parts[1] != '2.2'):
        return None

    result = {
        'part': parts[2],  # h (hardware), o (os), a (application)
        'vendor': parts[3],
        'product': parts[4],
        'version': parts[5],
        'update': parts[6] if len(parts) > 6 else '',
        'edition': parts[7] if len(parts) > 7 else '',
        'language': parts[8] if len(parts) > 8 else ''
    }

    return result


def format_cpe_for_display(vendor: str, product: str, version: str = "") -> str:
    """
    Форматирует компонент CPE для отображения.

    Args:
        vendor: Вендор
        product: Продукт
        version: Версия (опционально)

    Returns:
        Отформатированная строка вида "Vendor Product Version"

    Examples:
        >>> format_cpe_for_display("microsoft", "windows", "10")
        'Microsoft Windows 10'
    """
    vendor = vendor.capitalize() if vendor else ""
    product = product.replace('_', ' ').title() if product else ""
    version = version.replace('_', ' ').strip('*') if version else ""

    if version:
        return f"{vendor} {product} {version}"
    return f"{vendor} {product}".strip()


def extract_keywords_from_component(component: str) -> List[str]:
    """
    Извлекает ключевые слова из компонента для поиска.

    Args:
        component: Строка компонента

    Returns:
        Список ключевых слов
    """
    if not component:
        return []

    # Приводим к нижнему регистру и разбиваем
    words = component.lower().split()

    # Фильтруем слишком короткие слова
    keywords = [w for w in words if len(w) > 2]

    # Добавляем биграммы для лучшего поиска
    bigrams = []
    for i in range(len(keywords) - 1):
        bigrams.append(f"{keywords[i]} {keywords[i + 1]}")

    return keywords + bigrams


def match_component_with_cpe(component: str, cpe_list: List[str]) -> List[Tuple[str, float]]:
    """
    Сопоставляет компонент со списком CPE и возвращает релевантные совпадения.

    Args:
        component: Строка компонента
        cpe_list: Список CPE строк

    Returns:
        Список кортежей (cpe_строка, коэффициент_совпадения)
    """
    if not component or not cpe_list:
        return []

    component_lower = component.lower()
    cpe_info = extract_cpe_components(component)
    results = []

    for cpe in cpe_list:
        parsed = parse_cpe_string(cpe)
        if not parsed:
            continue

        score = 0.0

        # Совпадение по вендору (основной вес)
        if parsed['vendor'] == cpe_info['vendor']:
            score += 0.5

        # Совпадение по продукту
        if parsed['product'] == normalize_component_name(cpe_info['product']):
            score += 0.3

        # Частичное совпадение по продукту
        elif cpe_info['product'] and parsed['product'] in cpe_info['product']:
            score += 0.15

        # Совпадение по версии
        if cpe_info['version'] and parsed['version'] == cpe_info['version']:
            score += 0.2
        elif cpe_info['version'] and parsed['version'] and parsed['version'] in cpe_info['version']:
            score += 0.1

        if score > 0:
            results.append((cpe, score))

    # Сортируем по убыванию коэффициента
    results.sort(key=lambda x: x[1], reverse=True)

    return results


# Предопределённые маппинги для распространённых компонентов
COMMON_COMPONENT_MAPPING = {
    # Операционные системы
    "windows": {"vendor": "microsoft", "product": "windows"},
    "windows 10": {"vendor": "microsoft", "product": "windows", "version": "10"},
    "windows 11": {"vendor": "microsoft", "product": "windows", "version": "11"},
    "windows server": {"vendor": "microsoft", "product": "windows_server"},
    "ubuntu": {"vendor": "canonical", "product": "ubuntu"},
    "debian": {"vendor": "debian", "product": "debian"},
    "centos": {"vendor": "centos", "product": "centos"},
    "rhel": {"vendor": "redhat", "product": "enterprise_linux"},

    # Процессоры
    "intel core": {"vendor": "intel", "product": "core"},
    "intel xeon": {"vendor": "intel", "product": "xeon"},
    "amd ryzen": {"vendor": "amd", "product": "ryzen"},
    "amd epyc": {"vendor": "amd", "product": "epyc"},

    # Видеокарты
    "nvidia geforce": {"vendor": "nvidia", "product": "geforce"},
    "nvidia rtx": {"vendor": "nvidia", "product": "rtx"},
    "amd radeon": {"vendor": "amd", "product": "radeon"},

    # Сетевое оборудование
    "cisco ios": {"vendor": "cisco", "product": "ios"},
    "juniper junos": {"vendor": "juniper", "product": "junos"},
    "huawei vrp": {"vendor": "huawei", "product": "vrp"},
}


def get_common_component_mapping(component: str) -> Optional[Dict[str, str]]:
    """
    Возвращает предопределённый маппинг для распространённых компонентов.

    Args:
        component: Строка компонента

    Returns:
        Словарь с полями vendor, product, version или None
    """
    component_lower = component.lower()

    for key, mapping in COMMON_COMPONENT_MAPPING.items():
        if key in component_lower:
            return mapping.copy()

    return None