"""
Единый источник компонентов для выбора при создании узла.

Зачем
-----
CPE-браузер в диалоге узла берёт вендоров и продукты из таблицы `cpe_entries`
базы NVD. Отечественных изделий там нет вообще: проверка показала ноль
записей CPE у `mcst`, `baikal_electronics`, `astralinux`, `basealt`
и `red_soft`. Поэтому собрать топологию из российских компонентов
было невозможно — их просто не было в списках.

При этом в `component_catalog.db` лежат 36 062 записи реестров: 31 966 из
реестра ПО Минцифры, 4 087 из ГИСП и 9 добавленных вручную процессоров
«Эльбрус» и «Байкал». Этот модуль подмешивает их в те же списки.

Как ищутся уязвимости отечественных компонентов
----------------------------------------------
В NVD их нет, значит и CVE у них не будет. Единственный источник —
БДУ ФСТЭК: там 20 277 записей содержат номер реестра прямо в наименовании
продукта. Паспорт безопасности уже умеет искать по наименованию изделия,
если выборка по CPE пуста (см. security_passport_dialog).

Устройство
----------
Класс притворяется CVEDatabase: всё, чего он не переопределяет, уходит
в неё через __getattr__ — включая три десятка методов вида get_processors,
get_motherboards и прочих, которые диалог вызывает по имени из конфигурации.
Переопределены только четыре метода выбора, и только они подмешивают
российские записи.

Какие категории реестра подмешивать, задаётся в конфигурации вкладки
ключом `ru_categories` внутри `cpe_filter`: у вкладки процессоров это
«Процессоры», у операционных систем — «ОС Linux» и так далее.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from database.catalog_db import ComponentCatalog
from database.cve_db import CVEDatabase

__all__ = ["ComponentSource", "RU_MARK", "is_russian_choice", "strip_mark"]

# Пометка в списке выбора. Ставится перед названием, чтобы отечественные
# изделия было видно сразу, и снимается перед записью в свойства узла.
RU_MARK = "★ "


def is_russian_choice(value: str) -> bool:
    """Помечен ли элемент списка как отечественный."""
    return bool(value) and value.startswith(RU_MARK)


def strip_mark(value: str) -> str:
    """Убирает пометку — в свойствах узла хранится чистое имя."""
    return value[len(RU_MARK):] if is_russian_choice(value) else value


class ComponentSource:
    """NVD CPE плюс реестры отечественного ПО и оборудования."""

    def __init__(self) -> None:
        self._nvd = CVEDatabase()
        try:
            self._catalog: Optional[ComponentCatalog] = ComponentCatalog()
            if not self._catalog.available:
                self._catalog = None
        except Exception:      # noqa: BLE001 — без каталога работаем как раньше
            self._catalog = None

    # Всё, что не переопределено, обслуживает база NVD: у диалога есть
    # три десятка методов, вызываемых по имени из конфигурации вкладок
    def __getattr__(self, name):
        return getattr(self._nvd, name)

    @property
    def available(self) -> bool:
        return self._catalog is not None

    # ------------------------------------------------------------------
    # Российские записи
    # ------------------------------------------------------------------

    def _ru_rows(self, categories: Optional[Sequence[str]],
                 vendor: str = "", limit: int = 600,
                 title_like: Optional[Sequence[str]] = None) -> List[Dict]:
        """Записи реестров по категориям вкладки, при желании — одного вендора.

        Категории в реестре засорены: например, в «ОС Linux» из 515 записей
        операционными системами выглядят 87, остальное — прикладные программы,
        попавшие туда при импорте. Поэтому вкладка может дополнительно задать
        `ru_title_like` — куски наименования, по которым отбирать.

        У 168 записей имя вендора начинается с пробела, поэтому оно всюду
        обрезается: иначе один и тот же производитель попадает в список дважды.
        """
        if not self._catalog or not categories:
            return []

        cursor = self._catalog._connection.cursor()
        placeholders = ",".join("?" * len(categories))
        conditions = [f"category IN ({placeholders})"]
        params: List = list(categories)

        if vendor:
            conditions.append("TRIM(vendor) = ?")
            params.append(vendor)

        if title_like:
            conditions.append("(" + " OR ".join(["title LIKE ?"] * len(title_like)) + ")")
            params.extend(f"%{piece}%" for piece in title_like)

        # У 3 920 записей поле вендора пустое или стоит прочерк — в схеме
        # «вендор → продукт» они непригодны, поэтому отсеиваются
        conditions.append("TRIM(vendor) NOT IN ('', '-', '—', '–')")

        cursor.execute(
            "SELECT TRIM(title) AS title, TRIM(vendor) AS vendor, product, version, "
            "category, registry, registry_id "
            "FROM russian_components WHERE " + " AND ".join(conditions) +
            " ORDER BY vendor, title LIMIT ?", params + [limit])
        rows = []
        for row in cursor.fetchall():
            record = dict(row)
            # В реестре встречаются вендоры из одних прочерков и с переносами
            # строк внутри. Оставляем только те, где есть буква или цифра,
            # а лишние пробелы и переносы схлопываем
            vendor_name = " ".join((record.get("vendor") or "").split())
            if not any(ch.isalnum() for ch in vendor_name):
                continue
            record["vendor"] = vendor_name
            record["title"] = " ".join((record.get("title") or "").split())
            rows.append(record)
        return rows

    # ------------------------------------------------------------------
    # Переопределённые методы выбора
    # ------------------------------------------------------------------

    def get_vendors(self, part: str = None, vendors_filter: list = None,
                    search: str = "",
                    ru_categories: Optional[Sequence[str]] = None,
                    ru_title_like: Optional[Sequence[str]] = None) -> List[str]:
        """Вендоры NVD плюс отечественные производители нужных категорий."""
        vendors = list(self._nvd.get_vendors(part=part,
                                             vendors_filter=vendors_filter,
                                             search=search))
        known = set(vendors)
        russian = []
        for row in self._ru_rows(ru_categories, title_like=ru_title_like):
            marked = RU_MARK + row["vendor"]
            if row["vendor"] in known or marked in known:
                continue
            known.add(marked)
            russian.append(marked)

        if search:
            needle = search.lower()
            russian = [v for v in russian if needle in v.lower()]

        # Отечественные идут первыми: их немного, и искать их проще сверху
        return sorted(russian) + vendors

    def get_products(self, vendor: str, part: str = None,
                     product_like: list = None, product_not_like: list = None,
                     search: str = "",
                     ru_categories: Optional[Sequence[str]] = None,
                     ru_title_like: Optional[Sequence[str]] = None) -> List[str]:
        """Продукты вендора. Для отечественного вендора — записи реестра."""
        if is_russian_choice(vendor):
            rows = self._ru_rows(ru_categories, vendor=strip_mark(vendor),
                                 title_like=ru_title_like)
            titles = [row["title"] for row in rows if row["title"]]
            if search:
                needle = search.lower()
                titles = [t for t in titles if needle in t.lower()]
            return sorted(dict.fromkeys(titles))

        return self._nvd.get_products(vendor, part=part,
                                      product_like=product_like,
                                      product_not_like=product_not_like,
                                      search=search)

    def get_product_families(self, vendor: str, part: str = None,
                             family_prefixes: List[tuple] = None) -> List[tuple]:
        """У отечественных вендоров семейств нет — сразу список изделий."""
        if is_russian_choice(vendor):
            return []
        return self._nvd.get_product_families(vendor, part=part,
                                              family_prefixes=family_prefixes)

    def get_versions(self, vendor: str, product: str,
                     search: str = "",
                     ru_categories: Optional[Sequence[str]] = None,
                     ru_title_like: Optional[Sequence[str]] = None) -> List[str]:
        """Версии. У реестровых записей версия часто не указана."""
        if is_russian_choice(vendor):
            rows = self._ru_rows(ru_categories, vendor=strip_mark(vendor),
                                 title_like=ru_title_like)
            versions = [row["version"] for row in rows
                        if row["title"] == product and row["version"]]
            return sorted(dict.fromkeys(versions))
        return self._nvd.get_versions(vendor, product, search=search)

    # ------------------------------------------------------------------

    def registry_note(self, title: str) -> str:
        """Короткая подпись о реестре для выбранного изделия."""
        if not self._catalog:
            return ""
        try:
            return self._catalog.registry_label(title=strip_mark(title))
        except Exception:      # noqa: BLE001
            return ""
