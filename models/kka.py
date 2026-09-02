"""
Комплексная компьютерная атака (ККА) — сборка вектора атаки по этапам.

Что строится
------------
На плакате «Комплексные компьютерные атаки» вектор выписан вручную:

    1 этап  внедрение и легализация. Атака типа «Брутфорс».
            Вектор: Точка входа УБИ (Маршрутизатор 3.1) → ЦО №1
    4 этап  НСД к защищаемой информации. Атака вредоносным кодом.
            Вектор: АРМ 1.1 → ТрО №4.1 → ТрО №4.2 → ТрО №4.3 → ТрО №4.4 → ЦО №4

Модуль считает то же самое автоматически: волновым алгоритмом по графу
компонентов всей топологии.

Правило выбора целей
--------------------
Атака идёт узел за узлом, всё дальше от точки входа, а целевой объект
предыдущего этапа становится плацдармом для следующего:

    позиция = точка входа УБИ
    для каждого этапа N = 1…4:
        пустить волну из позиции
        кандидаты = компоненты с уязвимостями класса αN на узлах,
                    которые ещё не были целью и лежат не ближе предыдущего
        ЦО[N] = этапы 1–3: ближайший узел, внутри него самый критичный
                этап 4:    самый удалённый узел — там защищаемые данные
        маршрут[N] = обратный ход волны от ЦО[N] к позиции
        позиция = ЦО[N]

Подробное обоснование двух разных критериев — в docstring build_kka_vector().

Профили CWE взяты из колонки «Категории уязвимостей» схемы Shablon_atak.jpg
напротив каждого этапа.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set

from models.wave import count_routes, propagate, restore_route

__all__ = [
    "StageProfile",
    "STAGE_PROFILES",
    "KKAStage",
    "build_kka_vector",
]


# ===================================================================
# Профили этапов
# ===================================================================

@dataclass(frozen=True)
class StageProfile:
    """Описание одного этапа комплексной компьютерной атаки.

    Attributes:
        number: Номер этапа, 1–4
        name: Название этапа с плаката
        attack_type: Тип простой компьютерной атаки (ПКА)
        capec_chain: Цепочка CAPEC от категории к частному — со схемы
        cwe_profile: Классы слабостей, по которым выбирается цель этапа
        expected_result: Формулировка результата с плаката
        color: Цвет этапа на схеме (оранжевый, синий, красный, малиновый)
    """

    number: int
    name: str
    attack_type: str
    capec_chain: str
    cwe_profile: Set[int]
    expected_result: str
    color: str


# Порядок соответствует α1…α4 на эталонной схеме
STAGE_PROFILES: List[StageProfile] = [
    StageProfile(
        number=1,
        name="Внедрение и легализация",
        attack_type="Брутфорс",
        capec_chain="CAPEC-118 → 169 → 292 → 285",
        # Раскрытие информации: разведка, обнаружение хоста, сбор сведений
        cwe_profile={200, 209, 359, 532, 538, 306, 307, 522},
        expected_result="Получен IP-адрес объекта ДВ, доступ в сеть",
        color="#D97706",   # оранжевый — α1 на схеме
    ),
    StageProfile(
        number=2,
        name="Распространение",
        attack_type="Произвольный код",
        capec_chain="CAPEC-255 → 123 → 100",
        # Манипулирование памятью: переполнение буфера и родственное
        cwe_profile={119, 120, 121, 122, 125, 787, 805, 190, 415, 416, 131},
        expected_result="Доступ во внутреннюю сеть, вход в ЛВС",
        color="#2563EB",   # синий — α2
    ),
    StageProfile(
        number=3,
        name="Повышение привилегий",
        attack_type="Произвольный код",
        capec_chain="CAPEC-152 → 242",
        # Внедрение непредусмотренных элементов и кода
        cwe_profile={77, 78, 88, 94, 502, 611, 917, 74, 20},
        expected_result="Права администратора на целевом узле",
        color="#7C3AED",   # фиолетовый — α3
    ),
    StageProfile(
        number=4,
        name="НСД к защищаемой информации",
        attack_type="Вредоносный код",
        capec_chain="CAPEC-225 → 122",
        # Нарушение контроля доступа, злоупотребление привилегиями
        cwe_profile={269, 250, 264, 276, 284, 285, 732, 862, 863, 1317},
        expected_result="Деструктивное воздействие на защищаемые данные",
        color="#DC2626",   # красный — α4
    ),
]


# ===================================================================
# Результат: этап вектора ККА
# ===================================================================

@dataclass
class KKAStage:
    """Один рассчитанный этап вектора атаки.

    Attributes:
        profile: Профиль этапа
        source_id: Откуда начинается этап (точка входа или ЦО прошлого этапа)
        target_id: Целевой объект этапа — ЦО №N
        route: Маршрут по вершинам, от источника к цели
        route_count: Сколько всего кратчайших маршрутов ведёт к цели
        criticality: Критичность V целевого объекта по методике ФСТЭК
        cve_id: Уязвимость, по которой цель отобрана
        reachable: Дошла ли волна до подходящей цели
        note: Пояснение, если этап нереализуем
    """

    profile: StageProfile
    source_id: str = ""
    target_id: str = ""
    route: List[str] = field(default_factory=list)
    route_count: int = 0
    criticality: float = 0.0
    cve_id: str = ""
    reachable: bool = False
    note: str = ""

    @property
    def steps(self) -> int:
        """Число шагов маршрута — длина без учёта самой точки старта."""
        return max(len(self.route) - 1, 0)


# ===================================================================
# Сборка вектора
# ===================================================================

_CWE_RE = re.compile(r"\b(\d{1,4})\b")


def _cwe_numbers(raw: object) -> Set[int]:
    """Достаёт номера CWE из строки вида «CWE-119, CWE-787»."""
    if not raw:
        return set()
    return {int(n) for n in _CWE_RE.findall(str(raw))}


def build_kka_vector(adjacency: Dict[str, Sequence[str]],
                     entry_point: str,
                     assessments: Dict[str, object],
                     cwe_of: Callable[[str], Set[int]],
                     criticality_of: Callable[[str], float],
                     node_of: Callable[[str], str],
                     stages: Optional[Sequence[StageProfile]] = None
                     ) -> List[KKAStage]:
    """Строит вектор ККА: четыре этапа с маршрутами по компонентам.

    Правило продвижения взято с плаката. Там атака идёт узел за узлом,
    всё дальше от точки входа:

        этап 1  ЦО №1 — Маршрутизатор 3.1  (сам узел входа)
        этап 2  ЦО №2 — АРМ 3.1            (соседний узел той же зоны)
        этап 3  ЦО №3 — АРМ 1.1            (узел следующей зоны, ЛВС)
        этап 4  ЦО №4 — Сервер БД          (самое ценное, в ЦОД)

    Отсюда два разных критерия отбора:

    - **Этапы 1–3** берут ближайший подходящий узел, до которого волна
      доходит дальше, чем до цели предыдущего этапа. Внутри узла —
      самый критичный компонент. Так атака расширяется постепенно,
      а не прыгает сразу к самому ценному активу.
    - **Этап 4** — «НСД к защищаемой информации» — берёт самый критичный
      компонент из оставшихся: это цель всей атаки.

    На каждом этапе целевой объект должен быть на новом узле: повторно
    бить по уже захваченному узлу смысла нет, а ЦО предыдущего этапа
    становится плацдармом для следующего.

    Args:
        adjacency: Граф смежности всей топологии
        entry_point: Точка входа УБИ, откуда начинается атака
        assessments: Оценки компонентов (нужны, чтобы отобрать уязвимые)
        cwe_of: Классы слабостей компонента
        criticality_of: Критичность V компонента по методике ФСТЭК
        node_of: Узел, которому принадлежит компонент
        stages: Профили этапов; по умолчанию STAGE_PROFILES

    Returns:
        Список этапов. Этап без подходящей цели помечается reachable=False —
        это тоже результат анализа: атака по такому сценарию не проходит.
    """
    profiles = list(stages) if stages else list(STAGE_PROFILES)
    result: List[KKAStage] = []

    # Глубина каждого узла от исходной точки входа — по ней меряется,
    # насколько этап продвинул атаку вглубь сети
    base_wave = propagate(adjacency, [entry_point])
    node_depth: Dict[str, int] = {}
    for vid, depth in base_wave.distance.items():
        node = node_of(vid)
        if node not in node_depth or depth < node_depth[node]:
            node_depth[node] = depth

    position = entry_point
    used_nodes: Set[str] = set()
    reached_depth = -1
    last = profiles[-1] if profiles else None

    for profile in profiles:
        stage = KKAStage(profile=profile, source_id=position)

        wave = propagate(adjacency, [position])
        counts = count_routes(wave)

        def _suitable(min_depth: int) -> List[str]:
            return [
                vid for vid in wave.distance
                if vid != position
                and vid in assessments
                and cwe_of(vid) & profile.cwe_profile
                and node_of(vid) not in used_nodes
                and node_depth.get(node_of(vid), 0) >= min_depth
            ]

        # Сначала требуем продвижения вглубь; если некуда — допускаем
        # ту же глубину, лишь бы узел был новым
        candidates = _suitable(reached_depth + 1) or _suitable(0)

        if not candidates:
            stage.note = ("Нет достижимых компонентов с уязвимостями "
                          "этого класса на новых узлах — этап не реализуется")
            result.append(stage)
            continue

        if profile is last:
            # Завершающий этап — НСД к защищаемой информации. Целью должен
            # стать самый защищённый актив, а он в сети лежит глубже всего:
            # берём наиболее удалённый достижимый узел, внутри него — самый
            # критичный компонент.
            #
            # Одной критичностью V здесь руководствоваться нельзя: по таблице 1
            # Методики сетевые устройства и шлюзы весят 0,9, а серверы — 0,7,
            # поэтому уязвимость коммутатора обгоняет уязвимость сервера БД.
            # Это верно для методики, но не отражает, где лежат данные.
            # (Если у узла проставить тип «критичные бизнес-процессы», K станет
            # 1,1 и критичность сама выведет его вперёд — такого признака
            # у узлов пока нет.)
            target = max(candidates,
                         key=lambda v: (node_depth.get(node_of(v), 0),
                                        criticality_of(v)))
        else:
            # Промежуточные — ближайший новый узел, внутри него самый критичный
            target = min(candidates,
                         key=lambda v: (node_depth.get(node_of(v), 0),
                                        -criticality_of(v)))

        stage.target_id = target
        stage.route = restore_route(wave, target)
        stage.route_count = counts.get(target, 0)
        stage.criticality = criticality_of(target)
        stage.reachable = True

        assessment = assessments.get(target)
        stage.cve_id = getattr(assessment, "cve_id", "") if assessment else ""

        used_nodes.add(node_of(target))
        reached_depth = max(reached_depth, node_depth.get(node_of(target), 0))
        position = target        # ЦО этапа становится плацдармом следующего
        result.append(stage)

    return result
