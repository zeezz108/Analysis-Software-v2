"""
Волновой алгоритм (алгоритм Ли) для поиска маршрутов распространения УБИ.

Зачем нужен модуль
------------------
На эталонной схеме маршруты распространения угрозы подписаны как
`χ3.1 → χ3.2 → … → χ3.9`, а на плакате «Комплексные компьютерные атаки»
вектор атаки записан как `ТрО №4.1 → ТрО №4.2 → … → ЦО №4`. И то и другое —
пронумерованный по шагам кратчайший путь от точки входа УБИ до целевого
объекта. Номер шага и есть номер волнового фронта.

Почему маршруты не перечисляются
--------------------------------
Если волна проходит через любые вершины, число различных путей растёт как
произведение: три варианта на каждом из десяти шагов дают 59 049 маршрутов,
на реальной сети — числа с двадцатью нулями. Перечислить их нельзя ни на
какой машине, и дело не в оптимизации: их столько физически.

Волновой алгоритм их и не перечисляет. Он присваивает каждой вершине два
значения — номер фронта `d(v)` и список всех предшественников, из которых
в неё можно прийти за `d(v)−1` шагов. Эти два значения и есть «все
маршруты» в сжатом виде: число маршрутов считается сложением за один
проход, критический находится тем же проходом, а конкретный разворачивается
по требованию. Память — O(вершин + рёбер), а не O(числа маршрутов).

Модуль намеренно не знает ни про узлы, ни про компоненты: он работает
с абстрактным графом смежности, поэтому одна и та же реализация применяется
и к топологии сети (вектор ККА), и к внутренностям узлов (маршруты χ).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import (Callable, Dict, Iterable, Iterator, List, Mapping,
                    Optional, Sequence, Set, Tuple)

__all__ = [
    "WaveField",
    "propagate",
    "count_routes",
    "rank_routes",
    "restore_route",
    "iter_routes",
    "ROUTE_COUNT_CAP",
]

# Adjacency — граф смежности: вершина → список достижимых из неё вершин
Adjacency = Mapping[str, Sequence[str]]

# Число маршрутов растёт экспоненциально; выше этого порога точное значение
# теряет смысл, а вычисления начинают стоить дорого — счётчик насыщается.
ROUTE_COUNT_CAP = 10 ** 15


# ===================================================================
# Результат распространения волны
# ===================================================================

@dataclass
class WaveField:
    """Поле волны — сжатая запись всех кратчайших маршрутов сразу.

    Attributes:
        sources: Вершины, из которых пущена волна (точки входа УБИ)
        distance: Номер волнового фронта для каждой достигнутой вершины.
            Это и есть номер шага в обозначениях χN.M и ТрО №N.M
        predecessors: Все вершины, из которых можно прийти в данную
            за минимальное число шагов. Именно множественность
            предшественников кодирует множество маршрутов
        order: Достигнутые вершины в порядке неубывания номера фронта.
            Нужен для обхода динамическим программированием
    """

    sources: List[str] = field(default_factory=list)
    distance: Dict[str, int] = field(default_factory=dict)
    predecessors: Dict[str, List[str]] = field(default_factory=dict)
    order: List[str] = field(default_factory=list)

    def reached(self, vertex: str) -> bool:
        """Достигла ли волна вершины."""
        return vertex in self.distance

    def depth(self, vertex: str) -> Optional[int]:
        """Номер волнового фронта или None, если вершина не достигнута."""
        return self.distance.get(vertex)

    @property
    def max_depth(self) -> int:
        """Наибольший достигнутый номер фронта."""
        return max(self.distance.values()) if self.distance else 0

    def frontier(self, depth: int) -> List[str]:
        """Все вершины на заданном фронте."""
        return [v for v in self.order if self.distance[v] == depth]


# ===================================================================
# Распространение волны
# ===================================================================

def propagate(adjacency: Adjacency,
              sources: Iterable[str],
              passable: Optional[Callable[[str], bool]] = None,
              max_depth: Optional[int] = None) -> WaveField:
    """Пускает волну из точек входа и размечает граф номерами фронтов.

    Обход в ширину: на каждом шаге волна переходит из текущего фронта во все
    смежные ещё не размеченные вершины. В отличие от обычного поиска в ширину
    сохраняются **все** предшественники вершины, а не один — иначе потерялись
    бы альтернативные маршруты той же длины.

    Args:
        adjacency: Граф смежности: вершина → достижимые из неё вершины
        sources: Точки входа УБИ (одна или несколько)
        passable: Условие проходимости вершины. По умолчанию проходимы все:
            волна идёт через любой объект, а уязвимости лишь помечают опасные
            шаги. Функция получает идентификатор вершины и возвращает
            True, если волна может через неё пройти
        max_depth: Ограничение глубины. None — без ограничения

    Returns:
        WaveField с номерами фронтов и списками предшественников
    """
    field_ = WaveField(sources=[s for s in sources])

    queue: deque = deque()
    for source in field_.sources:
        if source in field_.distance:
            continue
        if passable is not None and not passable(source):
            continue
        field_.distance[source] = 0
        field_.predecessors[source] = []
        field_.order.append(source)
        queue.append(source)

    while queue:
        current = queue.popleft()
        depth = field_.distance[current]
        if max_depth is not None and depth >= max_depth:
            continue

        for neighbour in adjacency.get(current, ()):  # type: ignore[arg-type]
            if passable is not None and not passable(neighbour):
                continue

            known = field_.distance.get(neighbour)
            if known is None:
                field_.distance[neighbour] = depth + 1
                field_.predecessors[neighbour] = [current]
                field_.order.append(neighbour)
                queue.append(neighbour)
            elif known == depth + 1:
                # Ещё один маршрут той же длины — сохраняем и его
                predecessors = field_.predecessors[neighbour]
                if current not in predecessors:
                    predecessors.append(current)

    return field_


# ===================================================================
# Сколько маршрутов ведёт в каждую вершину
# ===================================================================

def count_routes(field_: WaveField,
                 cap: int = ROUTE_COUNT_CAP) -> Dict[str, int]:
    """Считает число кратчайших маршрутов, ведущих в каждую вершину.

    Перебора нет: в вершину ведёт столько маршрутов, сколько суммарно ведёт
    в её предшественников. Один проход по вершинам в порядке возрастания
    номера фронта даёт точные значения для всего графа.

    Args:
        field_: Поле волны
        cap: Порог насыщения счётчика

    Returns:
        Словарь «вершина → число маршрутов». Значение, равное cap,
        означает «не меньше чем cap»
    """
    counts: Dict[str, int] = {}
    for vertex in field_.order:
        predecessors = field_.predecessors.get(vertex, [])
        if not predecessors:
            counts[vertex] = 1          # Сама точка входа
            continue
        total = sum(counts.get(p, 0) for p in predecessors)
        counts[vertex] = min(total, cap)
    return counts


# ===================================================================
# Критический маршрут
# ===================================================================

def rank_routes(field_: WaveField,
                weight: Callable[[str], float]
                ) -> Tuple[Dict[str, float], Dict[str, str]]:
    """Находит для каждой вершины самый «тяжёлый» из ведущих в неё маршрутов.

    Тем же одним проходом, что и подсчёт числа маршрутов, только вместо
    суммы берётся максимум. Вес вершины задаётся вызывающей стороной —
    обычно это критичность V по методике ФСТЭК.

    Args:
        field_: Поле волны
        weight: Вес вершины (например, её критичность)

    Returns:
        Кортеж из двух словарей:
        - суммарный вес лучшего маршрута до вершины
        - выбранный предшественник для восстановления этого маршрута
    """
    best: Dict[str, float] = {}
    chosen: Dict[str, str] = {}

    for vertex in field_.order:
        predecessors = field_.predecessors.get(vertex, [])
        own = weight(vertex)
        if not predecessors:
            best[vertex] = own
            continue
        top = max(predecessors, key=lambda p: best.get(p, 0.0))
        best[vertex] = best.get(top, 0.0) + own
        chosen[vertex] = top

    return best, chosen


def restore_route(field_: WaveField,
                  target: str,
                  chosen: Optional[Mapping[str, str]] = None) -> List[str]:
    """Восстанавливает маршрут обратным ходом от целевого объекта.

    Args:
        field_: Поле волны
        target: Целевой объект
        chosen: Предшественники из rank_routes. Если не заданы, берётся
            первый предшественник — любой кратчайший маршрут

    Returns:
        Маршрут от точки входа к цели, по шагам. Пустой список,
        если волна до цели не дошла
    """
    if target not in field_.distance:
        return []

    route = [target]
    current = target
    while True:
        predecessors = field_.predecessors.get(current, [])
        if not predecessors:
            break
        if chosen is not None and current in chosen:
            current = chosen[current]
        else:
            current = predecessors[0]
        route.append(current)

    route.reverse()
    return route


# ===================================================================
# Перебор конкретных маршрутов по требованию
# ===================================================================

def iter_routes(field_: WaveField, target: str,
                limit: int = 10) -> Iterator[List[str]]:
    """Разворачивает конкретные кратчайшие маршруты до цели.

    Считается лениво и только для запрошенной цели: остальные маршруты
    не строятся. Используется, когда пользователь нажал «Другой маршрут» —
    развернуть все миллионы вариантов не нужно и невозможно.

    Args:
        field_: Поле волны
        target: Целевой объект
        limit: Сколько маршрутов вернуть максимум

    Yields:
        Маршруты от точки входа к цели, по шагам
    """
    if target not in field_.distance or limit <= 0:
        return

    produced = 0
    # Стек частичных маршрутов, строящихся от цели к точке входа
    stack: List[List[str]] = [[target]]

    while stack and produced < limit:
        partial = stack.pop()
        head = partial[-1]
        predecessors = field_.predecessors.get(head, [])

        if not predecessors:
            yield list(reversed(partial))
            produced += 1
            continue

        # В обратном порядке, чтобы первым разворачивался первый предшественник
        for predecessor in reversed(predecessors):
            stack.append(partial + [predecessor])


# ===================================================================
# Вспомогательное
# ===================================================================

def reachable_targets(field_: WaveField,
                      candidates: Iterable[str]) -> List[str]:
    """Отбирает из кандидатов те, до которых волна дошла, ближайшие первыми."""
    reached = [c for c in candidates if c in field_.distance]
    reached.sort(key=lambda v: field_.distance[v])
    return reached
