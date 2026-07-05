"""
Модуль оценки критичности уязвимостей по методике ФСТЭК России.

Реализует методику оценки критичности уязвимостей (утв. 30.06.2025),
формула: V = I_cvss × I_infr × (I_at + I_imp)

Где:
- I_cvss — базовая оценка CVSS (0–10)
- I_infr = k×K + l×L + p×P — инфраструктурный показатель
- I_at  = e×E — показатель эксплуатируемости
- I_imp = h×H — показатель последствий

Уровни критичности (Таблица 2 методики):
- V > 8.0  → Критический (красный)
- 5.0 ≤ V ≤ 8.0 → Высокий (оранжевый)
- 2.0 ≤ V < 5.0 → Средний (жёлтый)
- V < 2.0  → Низкий (зелёный)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


# ============================================================================
# Справочники коэффициентов (Таблица 1 методики ФСТЭК)
# ============================================================================

# K — тип компонента инфраструктуры, вес k = 0.5
COMPONENT_TYPE_K: Dict[str, float] = {
    "critical_process": 1.1,   # Критичные бизнес-процессы
    "firewall":         0.9,   # Межсетевые экраны
    "network_device":   0.9,   # Сетевые устройства / шлюзы
    "telecom":          0.8,   # Телекоммуникационное оборудование
    "server":           0.7,   # Серверы
    "workstation":      0.5,   # АРМ (рабочие станции)
    "storage":          0.4,   # Системы хранения данных
    "other":            0.1,   # Прочее
}

# Маппинг типов узлов Analysis-Software на категории K
NODE_TYPE_TO_K_CATEGORY: Dict[str, str] = {
    "Router":               "network_device",
    "Switch":               "network_device",
    "Firewall":             "firewall",
    "Server":               "server",
    "VirtualizationServer": "server",
    "ARM":                  "workstation",
    "Laptop":               "workstation",
    "Internet":             "network_device",
}

# L — доля уязвимых компонентов, вес l = 0.2
QUANTITY_RANGES_L: List[Tuple[float, float, float]] = [
    # (min_percent, max_percent, L)
    (70.0, 100.0, 1.0),   # >70%
    (50.0,  70.0, 0.8),   # 50–70%
    (10.0,  50.0, 0.6),   # 10–50%
    ( 0.0,  10.0, 0.5),   # <10%
]

# P — доступность с периметра, вес p = 0.3
PERIMETER_P: Dict[bool, float] = {
    True:  1.1,   # Доступен из Интернета
    False: 0.6,   # Недоступен
}

# E — эксплуатируемость, вес e = 1.0
EXPLOITATION_E: Dict[str, float] = {
    "active_attack":  0.6,   # Эксплуатируется в реальных атаках
    "exploit_exists":  0.3,   # Эксплойт существует
    "no_exploit":      0.1,   # Эксплойт не известен
}

# H — последствия эксплуатации, вес h = 1.0
CONSEQUENCES_H: Dict[str, float] = {
    "code_execution":       0.5,    # Выполнение произвольного кода
    "privilege_escalation": 0.5,    # Повышение привилегий
    "security_bypass":      0.4,    # Обход средств защиты
    "code_injection":       0.34,   # Внедрение кода
}

# CWE-категории, определяющие тип последствий
# (упрощённый маппинг наиболее распространённых CWE)
CWE_TO_CONSEQUENCE: Dict[str, str] = {
    # Выполнение произвольного кода
    "CWE-119": "code_execution",     # Переполнение буфера
    "CWE-120": "code_execution",     # Классическое переполнение буфера
    "CWE-122": "code_execution",     # Переполнение кучи
    "CWE-787": "code_execution",     # Запись за пределы буфера
    "CWE-416": "code_execution",     # Use After Free
    "CWE-415": "code_execution",     # Double Free
    "CWE-190": "code_execution",     # Целочисленное переполнение
    "CWE-125": "code_execution",     # Чтение за пределы буфера
    "CWE-476": "code_execution",     # NULL Pointer Dereference
    "CWE-134": "code_execution",     # Форматная строка
    "CWE-362": "code_execution",     # Race Condition
    # Повышение привилегий
    "CWE-269": "privilege_escalation",  # Неправильное управление привилегиями
    "CWE-250": "privilege_escalation",  # Выполнение с избыточными привилегиями
    "CWE-264": "privilege_escalation",  # Permissions, Privileges, Access Controls
    "CWE-285": "privilege_escalation",  # Неправильная авторизация
    "CWE-862": "privilege_escalation",  # Отсутствие авторизации
    "CWE-863": "privilege_escalation",  # Некорректная авторизация
    # Обход средств защиты
    "CWE-287": "security_bypass",    # Неправильная аутентификация
    "CWE-290": "security_bypass",    # Обход аутентификации через спуфинг
    "CWE-306": "security_bypass",    # Отсутствие аутентификации
    "CWE-307": "security_bypass",    # Ограничение попыток аутентификации
    "CWE-327": "security_bypass",    # Использование слабого крипто-алгоритма
    "CWE-295": "security_bypass",    # Неправильная проверка сертификата
    "CWE-798": "security_bypass",    # Вшитые учётные данные
    "CWE-522": "security_bypass",    # Недостаточная защита credentials
    # Внедрение кода
    "CWE-78":  "code_injection",     # Инъекция команд ОС
    "CWE-79":  "code_injection",     # XSS
    "CWE-89":  "code_injection",     # SQL-инъекция
    "CWE-94":  "code_injection",     # Инъекция кода
    "CWE-77":  "code_injection",     # Инъекция команд
    "CWE-502": "code_injection",     # Десериализация
    "CWE-917": "code_injection",     # Expression Language Injection
    "CWE-611": "code_injection",     # XXE
}


# ============================================================================
# Весовые коэффициенты
# ============================================================================

WEIGHT_K = 0.5   # Вес типа компонента
WEIGHT_L = 0.2   # Вес доли уязвимых компонентов
WEIGHT_P = 0.3   # Вес доступности с периметра
WEIGHT_E = 1.0   # Вес эксплуатируемости
WEIGHT_H = 1.0   # Вес последствий


# ============================================================================
# Dataclass оценки
# ============================================================================

@dataclass
class FSTECAssessment:
    """Результат оценки критичности уязвимости по методике ФСТЭК.

    Содержит все промежуточные параметры для отображения в UI
    и итоговое значение V с уровнем критичности.
    """

    # Исходные данные
    node_type: str = ""                # Тип узла (Router, Server, ARM и т.д.)
    cve_id: str = ""                   # CVE с наивысшим CVSS
    cvss_score: float = 0.0            # Базовая оценка CVSS (I_cvss)
    is_internet_facing: bool = False   # Доступность из Интернета
    cve_count: int = 0                 # Общее количество CVE

    # Компоненты I_infr
    k_category: str = "other"          # Категория компонента (ключ COMPONENT_TYPE_K)
    K: float = 0.1                     # Значение K (тип компонента)
    L: float = 0.5                     # Значение L (доля уязвимых компонентов)
    P: float = 0.6                     # Значение P (доступность с периметра)
    I_infr: float = 0.0               # k×K + l×L + p×P

    # Компоненты I_at
    e_category: str = "no_exploit"     # Категория эксплуатируемости
    E: float = 0.1                     # Значение E
    I_at: float = 0.0                  # e×E

    # Компоненты I_imp
    h_category: str = ""               # Категория последствий (или пустая)
    H: float = 0.0                     # Значение H
    I_imp: float = 0.0                 # h×H

    # Итог
    V: float = 0.0                     # Итоговая оценка критичности
    level: str = "Низкий"              # Уровень: Критический/Высокий/Средний/Низкий
    color: str = "#38A169"             # Цвет уровня (hex)

    def calculate(self) -> "FSTECAssessment":
        """Вычисляет V по формуле ФСТЭК и определяет уровень критичности.

        Формула: V = I_cvss × I_infr × (I_at + I_imp)

        Returns:
            self — для цепочечного вызова
        """
        # I_infr = k×K + l×L + p×P
        self.I_infr = (
            WEIGHT_K * self.K +
            WEIGHT_L * self.L +
            WEIGHT_P * self.P
        )

        # I_at = e×E
        self.I_at = WEIGHT_E * self.E

        # I_imp = h×H
        self.I_imp = WEIGHT_H * self.H

        # V = I_cvss × I_infr × (I_at + I_imp)
        self.V = self.cvss_score * self.I_infr * (self.I_at + self.I_imp)

        # Округляем до 2 знаков
        self.V = round(self.V, 2)
        self.I_infr = round(self.I_infr, 4)
        self.I_at = round(self.I_at, 4)
        self.I_imp = round(self.I_imp, 4)

        # Определяем уровень и цвет
        self.level = get_criticality_level(self.V)
        self.color = get_criticality_color(self.V)

        return self

    def to_dict(self) -> Dict:
        """Сериализация для сохранения в properties узла."""
        return {
            "node_type": self.node_type,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "is_internet_facing": self.is_internet_facing,
            "cve_count": self.cve_count,
            "k_category": self.k_category,
            "K": self.K,
            "L": self.L,
            "P": self.P,
            "I_infr": self.I_infr,
            "e_category": self.e_category,
            "E": self.E,
            "I_at": self.I_at,
            "h_category": self.h_category,
            "H": self.H,
            "I_imp": self.I_imp,
            "V": self.V,
            "level": self.level,
            "color": self.color,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "FSTECAssessment":
        """Десериализация из сохранённого словаря."""
        return cls(
            node_type=data.get("node_type", ""),
            cve_id=data.get("cve_id", ""),
            cvss_score=data.get("cvss_score", 0.0),
            is_internet_facing=data.get("is_internet_facing", False),
            cve_count=data.get("cve_count", 0),
            k_category=data.get("k_category", "other"),
            K=data.get("K", 0.1),
            L=data.get("L", 0.5),
            P=data.get("P", 0.6),
            I_infr=data.get("I_infr", 0.0),
            e_category=data.get("e_category", "no_exploit"),
            E=data.get("E", 0.1),
            I_at=data.get("I_at", 0.0),
            h_category=data.get("h_category", ""),
            H=data.get("H", 0.0),
            I_imp=data.get("I_imp", 0.0),
            V=data.get("V", 0.0),
            level=data.get("level", "Низкий"),
            color=data.get("color", "#38A169"),
        )


# ============================================================================
# Вспомогательные функции
# ============================================================================

def get_criticality_level(v: float) -> str:
    """Определяет уровень критичности по значению V (Таблица 2 методики).

    Args:
        v: Итоговая оценка критичности

    Returns:
        Строка: "Критический", "Высокий", "Средний" или "Низкий"
    """
    if v > 8.0:
        return "Критический"
    elif v >= 5.0:
        return "Высокий"
    elif v >= 2.0:
        return "Средний"
    else:
        return "Низкий"


def get_criticality_color(v: float) -> str:
    """Возвращает hex-цвет для уровня критичности.

    Args:
        v: Итоговая оценка критичности

    Returns:
        Hex-цвет: красный, оранжевый, жёлтый или зелёный
    """
    if v > 8.0:
        return "#E53E3E"   # Критический — красный
    elif v >= 5.0:
        return "#DD6B20"   # Высокий — оранжевый
    elif v >= 2.0:
        return "#D69E2E"   # Средний — жёлтый
    else:
        return "#38A169"   # Низкий — зелёный


def _get_best_cvss(cve: Dict) -> float:
    """Извлекает наилучшую (наивысшую) оценку CVSS из записи CVE.

    Приоритет: cvss_v3 → cvss_v4 → cvss_v2 → base_score.

    Args:
        cve: Словарь CVE из БД NVD

    Returns:
        Числовая оценка CVSS (0.0 если данных нет)
    """
    # Пробуем все известные ключи из cve_db.py
    for key in ("cvss_v3", "cvss_v4", "cvss_v2", "base_score", "cvss_v3_score"):
        val = cve.get(key)
        if val is not None:
            try:
                score = float(val)
                if score > 0:
                    return score
            except (ValueError, TypeError):
                continue
    return 0.0


def _determine_K(node_type: str) -> Tuple[str, float]:
    """Определяет категорию и значение K по типу узла.

    Args:
        node_type: Тип узла из Analysis-Software (Router, Server, ARM и т.д.)

    Returns:
        Кортеж (категория, значение K)
    """
    category = NODE_TYPE_TO_K_CATEGORY.get(node_type, "other")
    K = COMPONENT_TYPE_K.get(category, 0.1)
    return category, K


def _determine_E(cve_list: List[Dict]) -> Tuple[str, float]:
    """Определяет показатель эксплуатируемости E по списку CVE.

    Эвристика:
    - Если CVSS ≥ 9.0, считаем что эксплойт вероятно существует
      (критические уязвимости часто имеют публичные эксплойты)
    - Если CVSS ≥ 7.0, эксплойт может существовать
    - Иначе — эксплойт не известен

    Примечание: для точного определения нужны данные из CISA KEV или
    Exploit-DB, которые пока не интегрированы. Используется
    приблизительная оценка на основе CVSS.

    Args:
        cve_list: Список словарей CVE

    Returns:
        Кортеж (категория, значение E)
    """
    if not cve_list:
        return "no_exploit", EXPLOITATION_E["no_exploit"]

    max_cvss = max(_get_best_cvss(cve) for cve in cve_list)

    # Эвристика на основе CVSS-оценки
    if max_cvss >= 9.0:
        return "exploit_exists", EXPLOITATION_E["exploit_exists"]
    elif max_cvss >= 7.0:
        return "exploit_exists", EXPLOITATION_E["exploit_exists"]
    else:
        return "no_exploit", EXPLOITATION_E["no_exploit"]


def _determine_H(cve_list: List[Dict]) -> Tuple[str, float]:
    """Определяет показатель последствий H по CWE-классам из CVE.

    Анализирует CWE-идентификаторы всех CVE и выбирает наиболее
    опасный тип последствий. Приоритет:
    1. Выполнение произвольного кода (H=0.5)
    2. Повышение привилегий (H=0.5)
    3. Обход средств защиты (H=0.4)
    4. Внедрение кода (H=0.34)

    Args:
        cve_list: Список словарей CVE (с полем cwe_id)

    Returns:
        Кортеж (категория, значение H). Если CWE не определён —
        возвращает ("code_injection", 0.34) как безопасное значение по умолчанию.
    """
    if not cve_list:
        return "", 0.0

    # Приоритет последствий (от наиболее к наименее критичным)
    consequence_priority = [
        "code_execution",
        "privilege_escalation",
        "security_bypass",
        "code_injection",
    ]

    found_consequences = set()

    for cve in cve_list:
        cwe_raw = cve.get("cwe_id", "")
        if not cwe_raw:
            continue

        # cwe_id может содержать несколько через запятую: "CWE-79, CWE-89"
        for cwe_part in cwe_raw.replace(" ", "").split(","):
            cwe_part = cwe_part.strip()
            if not cwe_part:
                continue
            # Нормализуем формат: "119" → "CWE-119"
            if not cwe_part.startswith("CWE-"):
                cwe_part = f"CWE-{cwe_part}"
            consequence = CWE_TO_CONSEQUENCE.get(cwe_part)
            if consequence:
                found_consequences.add(consequence)

    # Выбираем наиболее критичное последствие
    for cons in consequence_priority:
        if cons in found_consequences:
            return cons, CONSEQUENCES_H[cons]

    # Если CWE не маппится — базовое значение (инъекция кода)
    # Наличие CVE подразумевает наличие какого-то воздействия
    if cve_list:
        return "code_injection", CONSEQUENCES_H["code_injection"]

    return "", 0.0


# ============================================================================
# Основная функция оценки
# ============================================================================

def assess_component(
    node_type: str,
    cve_list: List[Dict],
    is_internet_facing: bool,
    vulnerable_percent: Optional[float] = None,
) -> FSTECAssessment:
    """Выполняет оценку критичности уязвимостей узла по методике ФСТЭК.

    Алгоритм:
    1. Находит CVE с наивысшим CVSS (I_cvss)
    2. Определяет K по типу узла
    3. Устанавливает L (по умолчанию <10% → L=0.5)
    4. Устанавливает P по доступности из Интернета
    5. Определяет E (эксплуатируемость) по данным CVE
    6. Определяет H (последствия) по CWE-классам из CVE
    7. Вычисляет V = I_cvss × I_infr × (I_at + I_imp)

    Args:
        node_type: Тип узла ("Router", "Server", "ARM", "Switch" и т.д.)
        cve_list: Список словарей CVE из БД NVD. Каждый содержит:
            - cve_id (str)
            - cvss_v2, cvss_v3, cvss_v4 (float или None)
            - cwe_id (str, может содержать несколько через запятую)
        is_internet_facing: True если узел доступен из Интернета
        vulnerable_percent: Доля уязвимых компонентов (0–100).
            Если None — используется значение по умолчанию (<10%).

    Returns:
        FSTECAssessment с заполненными параметрами и вычисленным V
    """
    assessment = FSTECAssessment()
    assessment.node_type = node_type
    assessment.is_internet_facing = is_internet_facing
    assessment.cve_count = len(cve_list)

    # --- I_cvss: находим CVE с максимальным CVSS ---
    if cve_list:
        best_cve = max(cve_list, key=lambda c: _get_best_cvss(c))
        assessment.cvss_score = _get_best_cvss(best_cve)
        assessment.cve_id = best_cve.get("cve_id", "")
    else:
        assessment.cvss_score = 0.0
        assessment.cve_id = ""

    # --- K: тип компонента ---
    assessment.k_category, assessment.K = _determine_K(node_type)

    # --- L: доля уязвимых компонентов ---
    if vulnerable_percent is not None:
        # Определяем L по диапазону
        assessment.L = 0.5  # Значение по умолчанию
        for min_pct, max_pct, l_value in QUANTITY_RANGES_L:
            if min_pct <= vulnerable_percent <= max_pct:
                assessment.L = l_value
                break
    else:
        # По умолчанию — <10%
        assessment.L = 0.5

    # --- P: доступность с периметра ---
    assessment.P = PERIMETER_P[is_internet_facing]

    # --- E: эксплуатируемость ---
    assessment.e_category, assessment.E = _determine_E(cve_list)

    # --- H: последствия ---
    assessment.h_category, assessment.H = _determine_H(cve_list)

    # --- Вычисление V ---
    assessment.calculate()

    return assessment
