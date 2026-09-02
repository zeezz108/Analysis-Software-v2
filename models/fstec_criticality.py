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

import re
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
#
# Все двенадцать значений таблицы 1 Методики. Раньше здесь были только
# первые четыре, а остальные последствия давали H = 0 и обнуляли критичность.
# Тяжелее всего это било по отказу в обслуживании — самому частому
# последствию в БДУ (24 659 записей) — и по раскрытию информации (CWE-200),
# по которому на эталонной схеме выбирается цель первого этапа ККА.
CONSEQUENCES_H: Dict[str, float] = {
    "code_execution":       0.50,   # Выполнение произвольного кода
    "privilege_escalation": 0.50,   # Повышение привилегий
    "security_bypass":      0.40,   # Обход механизмов безопасности
    "code_injection":       0.34,   # Внедрение кода
    "obtain_info":          0.30,   # Получение конфиденциальной информации
    "loss_of_integrity":    0.30,   # Нарушение целостности данных
    "dos":                  0.26,   # Отказ в обслуживании
    "overwrite_files":      0.22,   # Перезапись произвольных файлов
    "write_local_files":    0.20,   # Запись локальных файлов
    "read_local_files":     0.18,   # Чтение локальных файлов
    "spoof_ui":             0.12,   # Поддельный пользовательский интерфейс
    "xss":                  0.10,   # Межсайтовый скриптинг
}

# Русские названия последствий — для отображения в паспорте и подсказках
CONSEQUENCE_NAMES: Dict[str, str] = {
    "code_execution":       "Выполнение произвольного кода",
    "privilege_escalation": "Повышение привилегий",
    "security_bypass":      "Обход механизмов безопасности",
    "code_injection":       "Внедрение кода",
    "obtain_info":          "Получение конфиденциальной информации",
    "loss_of_integrity":    "Нарушение целостности данных",
    "dos":                  "Отказ в обслуживании",
    "overwrite_files":      "Перезапись произвольных файлов",
    "write_local_files":    "Запись локальных файлов",
    "read_local_files":     "Чтение локальных файлов",
    "spoof_ui":             "Поддельный пользовательский интерфейс",
    "xss":                  "Межсайтовый скриптинг",
    "undetermined":         "Последствие не определено",
}

# Значение H, когда последствие определить не удалось — ни по описанию БДУ,
# ни по классу слабости. В таблице 1 такой строки нет: это медиана
# двенадцати значений, применяемая, чтобы неизвестное последствие
# не обнуляло критичность и не завышало её.
H_UNDETERMINED = 0.30

# Порядок убывания веса — для правила «берётся наибольшее из значений»
# (пункты 15, 16 и 17 Методики)
CONSEQUENCE_PRIORITY: List[str] = sorted(
    CONSEQUENCES_H, key=lambda k: CONSEQUENCES_H[k], reverse=True)

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
    "CWE-89":  "code_injection",     # SQL-инъекция
    "CWE-94":  "code_injection",     # Инъекция кода
    "CWE-77":  "code_injection",     # Инъекция команд
    "CWE-502": "code_injection",     # Десериализация
    "CWE-917": "code_injection",     # Expression Language Injection
    "CWE-611": "code_injection",     # XXE
    # Межсайтовый скриптинг — отдельная строка таблицы 1 (0,10).
    # Раньше CWE-79 относился к внедрению кода (0,34) — завышение в 3,4 раза
    "CWE-79":  "xss",
    "CWE-80":  "xss",
    "CWE-83":  "xss",
    # Получение конфиденциальной информации
    "CWE-200": "obtain_info",        # Раскрытие информации
    "CWE-209": "obtain_info",        # Информация в сообщении об ошибке
    "CWE-359": "obtain_info",        # Раскрытие персональных данных
    "CWE-532": "obtain_info",        # Информация в журналах
    "CWE-538": "obtain_info",        # Информация в файлах и каталогах
    # Нарушение целостности данных
    "CWE-345": "loss_of_integrity",  # Недостаточная проверка подлинности данных
    "CWE-347": "loss_of_integrity",  # Неверная проверка подписи
    "CWE-494": "loss_of_integrity",  # Загрузка кода без проверки целостности
    "CWE-565": "loss_of_integrity",  # Доверие непроверенным cookie
    # Отказ в обслуживании — самое частое последствие в БДУ
    "CWE-400": "dos",                # Неконтролируемое потребление ресурсов
    "CWE-404": "dos",                # Некорректное освобождение ресурса
    "CWE-770": "dos",                # Выделение ресурсов без ограничений
    "CWE-835": "dos",                # Бесконечный цикл
    "CWE-834": "dos",                # Избыточные итерации
    "CWE-401": "dos",                # Утечка памяти
    # Перезапись произвольных файлов
    "CWE-59":  "overwrite_files",    # Переход по символьной ссылке
    "CWE-73":  "overwrite_files",    # Внешнее управление именем файла
    # Запись и чтение локальных файлов
    "CWE-22":  "read_local_files",   # Выход за пределы каталога
    "CWE-23":  "read_local_files",   # Относительный обход каталога
    "CWE-98":  "write_local_files",  # Подключение внешнего файла
    "CWE-434": "write_local_files",  # Загрузка файла опасного типа
    # Поддельный пользовательский интерфейс
    "CWE-451": "spoof_ui",           # Искажение критичной информации в UI
    "CWE-601": "spoof_ui",           # Открытое перенаправление
    "CWE-1021": "spoof_ui",          # Некорректное ограничение отрисовки
}


# ============================================================================
# Распознавание последствий по описанию из БДУ ФСТЭК
# ============================================================================

# БДУ формулирует последствие прямо в описании: «Эксплуатация уязвимости
# может позволить нарушителю выполнить произвольный код», «повысить свои
# привилегии», «вызвать отказ в обслуживании». Это надёжнее вывода по CWE:
# один и тот же класс слабости приводит к разным последствиям в зависимости
# от того, где он находится.
#
# Порядок важен: проверка идёт сверху вниз, от тяжёлых последствий к лёгким,
# как того требует правило «наибольшего из значений» (п. 17 Методики).
CONSEQUENCE_PATTERNS: List[Tuple[str, str]] = [
    # Выполнение произвольного кода (0,50)
    ("code_execution",       r"выполн\w*\s+(?:\w+\s+){0,3}?произвольн\w*\s+"
                             r"(?:код|команд|программ|скрипт|запрос)"),
    ("code_execution",       r"выполнение\s+произвольного\s+кода"),
    ("code_execution",       r"удал[её]нн\w*\s+выполнени\w*\s+кода"),
    ("code_execution",       r"получить\s+(?:\w+\s+){0,2}?контроль\s+над"),
    # Повышение привилегий (0,50)
    ("privilege_escalation", r"повы\w*\s+(?:свои\s+)?привилегии|повышение\s+привилегий"),
    ("privilege_escalation", r"эскалаци\w*\s+привилегий"),
    ("privilege_escalation", r"получить\s+(?:\w+\s+){0,3}?прав\w*\s+"
                             r"(?:администратор|суперпользовател|root|доступа)"),
    ("privilege_escalation", r"получить\s+(?:\w+\s+){0,2}?полн\w*\s+доступ"),
    # Обход механизмов безопасности (0,40)
    ("security_bypass",      r"обойти\s+(?:\w+\s+){0,3}?(?:ограничени|защит|аутентификаци|"
                             r"авторизаци|механизм|политик|песочниц|проверк)"),
    ("security_bypass",      r"обход\s+(?:\w+\s+){0,3}?(?:ограничени|защит|аутентификаци|"
                             r"авторизаци|механизм)"),
    ("security_bypass",      r"получить\s+несанкционированн\w*\s+доступ"),
    ("security_bypass",      r"получить\s+(?:авторизованн\w*|привилегированн\w*)\s+доступ"),
    # Внедрение кода (0,34)
    ("code_injection",       r"внедри\w*\s+(?:\w+\s+){0,2}?код|внедрение\s+(?:\w+\s+){0,2}?кода"),
    ("code_injection",       r"инъекци\w*\s+(?:sql|команд|кода)"),
    # Получение конфиденциальной информации (0,30)
    ("obtain_info",          r"раскры\w*\s+(?:\w+\s+){0,3}?(?:информаци|данн|сведени)"),
    ("obtain_info",          r"получить\s+(?:\w+\s+){0,3}?(?:конфиденциальн|защищаем|"
                             r"чувствительн|персональн)"),
    ("obtain_info",          r"нарушить\s+конфиденциальност|нарушение\s+конфиденциальност"),
    ("obtain_info",          r"утечк\w*\s+(?:\w+\s+){0,2}?(?:информаци|данн)"),
    # Нарушение целостности данных (0,30)
    ("loss_of_integrity",    r"нарушить\s+целостност|нарушение\s+целостност"),
    ("loss_of_integrity",    r"модифицировать\s+(?:\w+\s+){0,3}?(?:данные|информаци|содержимое)"),
    # Отказ в обслуживании (0,26)
    ("dos",                  r"отказ\w*\s+в\s+обслуживании"),
    ("dos",                  r"нарушить\s+доступност|нарушение\s+доступности"),
    ("dos",                  r"аварийн\w*\s+завершени|вызвать\s+сбой"),
    # Перезапись произвольных файлов (0,22)
    ("overwrite_files",      r"перезапис\w*\s+(?:\w+\s+){0,3}?файл"),
    # Запись локальных файлов (0,20)
    ("write_local_files",    r"запис\w*\s+(?:\w+\s+){0,3}?(?:локальн\w*\s+)?файл"),
    ("write_local_files",    r"загрузить\s+(?:\w+\s+){0,3}?файл"),
    # Чтение локальных файлов (0,18)
    ("read_local_files",     r"(?:прочитать|читать)\s+(?:\w+\s+){0,3}?файл"),
    ("read_local_files",     r"чтени\w*\s+(?:\w+\s+){0,2}?(?:локальн\w*\s+)?файл"),
    # Поддельный пользовательский интерфейс (0,12)
    ("spoof_ui",             r"подделать\s+(?:\w+\s+){0,3}?интерфейс|подмен\w*\s+"
                             r"(?:\w+\s+){0,2}?интерфейс"),
    ("spoof_ui",             r"перенаправ\w*\s+(?:\w+\s+){0,3}?пользовател"),
    # Межсайтовый скриптинг (0,10) — «межсайтовые атаки», «межсайтовый скриптинг»
    ("xss",                  r"межсайтов\w*"),
]

# Скомпилированные шаблоны — собираются при первом обращении
_CONSEQUENCE_RE: List[Tuple[str, "re.Pattern"]] = []


def consequence_from_description(description: str) -> Optional[str]:
    """Определяет тип последствий по русскому описанию уязвимости из БДУ.

    Args:
        description: Поле description записи БДУ

    Returns:
        Ключ из CONSEQUENCES_H или None, если последствие не распознано.
        Если описание содержит несколько последствий, возвращается
        наиболее тяжёлое — как требует пункт 17 Методики.
    """
    if not description:
        return None

    if not _CONSEQUENCE_RE:
        for key, pattern in CONSEQUENCE_PATTERNS:
            _CONSEQUENCE_RE.append((key, re.compile(pattern, re.IGNORECASE)))

    text = description.lower()
    found = {key for key, rx in _CONSEQUENCE_RE if rx.search(text)}
    if not found:
        return None

    for key in CONSEQUENCE_PRIORITY:
        if key in found:
            return key
    return None


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

    # Данные БДУ ФСТЭК
    bdu_id: str = ""                   # Идентификатор вида «BDU:2021-05516»
    exploit_status: str = ""           # Наличие эксплойта по данным БДУ

    # Итог
    V: float = 0.0                     # Итоговая оценка критичности
    level: str = "Низкий"              # Уровень: Критический/Высокий/Средний/Низкий
    color: str = "#38A169"             # Цвет уровня (hex)
    deadline: str = ""                 # Рекомендуемый срок устранения (п. 21)

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

        # Определяем уровень, цвет и срок устранения
        self.level = get_criticality_level(self.V)
        self.color = get_criticality_color(self.V)
        self.deadline = get_remediation_deadline(self.V)

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
            "bdu_id": self.bdu_id,
            "exploit_status": self.exploit_status,
            "V": self.V,
            "level": self.level,
            "color": self.color,
            "deadline": self.deadline,
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
            bdu_id=data.get("bdu_id", ""),
            exploit_status=data.get("exploit_status", ""),
            V=data.get("V", 0.0),
            level=data.get("level", "Низкий"),
            color=data.get("color", "#38A169"),
            deadline=data.get("deadline", ""),
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


# Рекомендуемые сроки устранения (пункт 21 Методики)
REMEDIATION_DEADLINES: Dict[str, str] = {
    "Критический": "до 24 часов",
    "Высокий":     "до 7 дней",
    "Средний":     "до 4 недель",
    "Низкий":      "до 4 месяцев",
}


def get_remediation_deadline(v: float) -> str:
    """Возвращает рекомендуемый срок устранения уязвимости.

    Пункт 21 Методики связывает срок с уровнем критичности: критический —
    несколько часов, высокий — несколько дней, средний — несколько недель,
    низкий — несколько месяцев.

    Args:
        v: Итоговая оценка критичности

    Returns:
        Строка вида «до 7 дней»
    """
    return REMEDIATION_DEADLINES.get(get_criticality_level(v), "")


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


def _determine_E(cve_list: List[Dict],
                 bdu_records: Optional[Dict[str, Dict]] = None) -> Tuple[str, float]:
    """Определяет показатель эксплуатируемости E (таблица 1 Методики).

    Источник — поле наличия эксплойта из БДУ ФСТЭК, которое использует те же
    формулировки, что и примеры Методики:

        «Существует в открытом доступе» → E = 0,3
        «Существует»                    → E = 0,3
        «Данные уточняются»             → E = 0,1

    Пункт 16 Методики: если показатель может принимать несколько значений,
    итоговой оценке присваивается наибольшее из них — поэтому по всем CVE
    компонента берётся максимум.

    Раньше E угадывался по CVSS («если ≥ 7,0, эксплойт наверное есть»).
    Сверка с БДУ на 55 752 сопоставленных CVE показала, что такая догадка
    ошибается в 47,6 % случаев, причём в обе стороны.

    Значение E = 0,6 («эксплуатируется в реальных атаках») из текущего
    среза БДУ получить нельзя: соответствующее поле не попало в импорт.
    До его появления оценка консервативна — это занижение, а не завышение.

    Args:
        cve_list: Список словарей CVE
        bdu_records: Записи БДУ по идентификатору CVE (BDUDatabase.get_many_by_cve).
            Если не переданы, используется запасная оценка по CVSS.

    Returns:
        Кортеж (категория, значение E)
    """
    if not cve_list:
        return "no_exploit", EXPLOITATION_E["no_exploit"]

    if bdu_records:
        for cve in cve_list:
            record = bdu_records.get(cve.get("cve_id", ""))
            if not record:
                continue
            status = (record.get("exploit_status") or "").lower()
            if "существует" in status:
                # Максимум из доступных значений достигнут — дальше не ищем
                return "exploit_exists", EXPLOITATION_E["exploit_exists"]
        # Записи БДУ есть, но ни в одной эксплойт не заявлен
        if any(cve.get("cve_id", "") in bdu_records for cve in cve_list):
            return "no_exploit", EXPLOITATION_E["no_exploit"]

    # Запасной путь: для уязвимости нет записи в БДУ. Высокая базовая оценка
    # косвенно указывает на вероятное наличие средств эксплуатации.
    max_cvss = max(_get_best_cvss(cve) for cve in cve_list)
    if max_cvss >= 7.0:
        return "exploit_exists", EXPLOITATION_E["exploit_exists"]
    return "no_exploit", EXPLOITATION_E["no_exploit"]


def _determine_H(cve_list: List[Dict],
                 bdu_records: Optional[Dict[str, Dict]] = None) -> Tuple[str, float]:
    """Определяет показатель последствий H (таблица 1 Методики).

    Два источника, в порядке убывания надёжности:

    1. Русское описание из БДУ ФСТЭК. Оно прямо называет последствие:
       «позволить нарушителю выполнить произвольный код», «повысить свои
       привилегии», «вызвать отказ в обслуживании». Распознаётся в 86,7 %
       описаний БДУ.
    2. Класс слабости CWE. Менее точен: один и тот же CWE приводит
       к разным последствиям в зависимости от того, где он находится.

    Пункт 17 Методики: если показатель принимает несколько значений,
    итоговой оценке присваивается наибольшее — поэтому среди всех
    найденных последствий выбирается самое тяжёлое.

    Args:
        cve_list: Список словарей CVE (с полем cwe_id)
        bdu_records: Записи БДУ по идентификатору CVE

    Returns:
        Кортеж (категория, значение H). Категория «undetermined» означает,
        что последствие определить не удалось.
    """
    if not cve_list:
        return "", 0.0

    found: set = set()

    for cve in cve_list:
        cve_id = cve.get("cve_id", "")

        # --- Источник 1: описание из БДУ ---
        if bdu_records:
            record = bdu_records.get(cve_id)
            if record:
                consequence = consequence_from_description(record.get("description", ""))
                if consequence:
                    found.add(consequence)
                    continue  # Описание надёжнее CWE — к нему не обращаемся

        # --- Источник 2: класс слабости CWE ---
        cwe_raw = cve.get("cwe_id", "")
        if not cwe_raw:
            continue
        # cwe_id может содержать несколько через запятую: «CWE-79, CWE-89»
        for cwe_part in cwe_raw.replace(" ", "").split(","):
            cwe_part = cwe_part.strip()
            if not cwe_part:
                continue
            if not cwe_part.startswith("CWE-"):
                cwe_part = f"CWE-{cwe_part}"  # Нормализуем «119» → «CWE-119»
            consequence = CWE_TO_CONSEQUENCE.get(cwe_part)
            if consequence:
                found.add(consequence)

    # Правило наибольшего значения (п. 17 Методики)
    for consequence in CONSEQUENCE_PRIORITY:
        if consequence in found:
            return consequence, CONSEQUENCES_H[consequence]

    return "undetermined", H_UNDETERMINED


# ============================================================================
# Основная функция оценки
# ============================================================================

def assess_component(
    node_type: str,
    cve_list: List[Dict],
    is_internet_facing: bool,
    vulnerable_percent: Optional[float] = None,
    bdu_records: Optional[Dict[str, Dict]] = None,
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

    # --- E: эксплуатируемость (по данным БДУ ФСТЭК) ---
    assessment.e_category, assessment.E = _determine_E(cve_list, bdu_records)

    # --- H: последствия (по описанию БДУ, при неудаче — по CWE) ---
    assessment.h_category, assessment.H = _determine_H(cve_list, bdu_records)

    # --- Идентификатор БДУ для отображения рядом с CVE ---
    if bdu_records:
        record = bdu_records.get(assessment.cve_id)
        if record:
            assessment.bdu_id = record.get("bdu_id", "")
            assessment.exploit_status = record.get("exploit_status", "")

    # --- Вычисление V ---
    assessment.calculate()

    return assessment
