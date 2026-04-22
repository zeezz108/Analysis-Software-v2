"""
Модуль запросов к каталогу компонентов (component_catalog.db).

Предоставляет иерархический поиск: категория → вендор → продукт → версия.
Объединяет NVD CPE и российские компоненты в едином интерфейсе.
"""

import os
import sqlite3
from typing import List, Dict, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ComponentCatalog:
    """Синглтон для работы с каталогом компонентов."""

    _instance = None
    _connection = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._connection is not None:
            return

        if db_path is None:
            db_path = os.path.join(BASE_DIR, "component_catalog.db")

        if not os.path.exists(db_path):
            print(f"[CATALOG] БД не найдена: {db_path}")
            self._connection = None
            return

        print(f"[CATALOG] Подключение к: {db_path}")
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

    @property
    def available(self) -> bool:
        return self._connection is not None

    # ─── Категории ───

    def get_categories(self, part: str = None) -> List[str]:
        """Возвращает список категорий."""
        if not self._connection:
            return []

        conditions = ["category != ''"]
        params = []
        if part:
            conditions.append("part = ?")
            params.append(part)

        # NVD
        query = f"""
            SELECT category, COUNT(*) as cnt FROM components
            WHERE {' AND '.join(conditions)}
            GROUP BY category
        """
        cursor = self._connection.cursor()
        cursor.execute(query, params)
        cats = {r[0]: r[1] for r in cursor.fetchall()}

        # Российские
        query_ru = f"""
            SELECT category, COUNT(*) as cnt FROM russian_components
            WHERE {' AND '.join(conditions)}
            GROUP BY category
        """
        cursor.execute(query_ru, params)
        for r in cursor.fetchall():
            cats[r[0]] = cats.get(r[0], 0) + r[1]

        return sorted(cats.keys())

    # ─── Вендоры ───

    def get_vendors(self, category: str = None, part: str = None,
                    search: str = "", limit: int = 200) -> List[str]:
        """Возвращает список вендоров для категории."""
        if not self._connection:
            return []

        cursor = self._connection.cursor()
        vendors = set()

        # NVD
        conds = []
        params = []
        if category:
            conds.append("category = ?")
            params.append(category)
        if part:
            conds.append("part = ?")
            params.append(part)
        where = " AND ".join(conds) if conds else "1=1"

        cursor.execute(f"""
            SELECT DISTINCT vendor FROM components
            WHERE {where} AND deprecated = 0
            ORDER BY vendor LIMIT ?
        """, params + [limit])
        for r in cursor.fetchall():
            vendors.add(r[0])

        # Российские
        cursor.execute(f"""
            SELECT DISTINCT vendor FROM russian_components
            WHERE {where}
            ORDER BY vendor LIMIT ?
        """, params + [limit])
        for r in cursor.fetchall():
            vendors.add(r[0])

        result = sorted(vendors)
        if search:
            sl = search.lower()
            result = [v for v in result if sl in v.lower()]
        return result

    # ─── Продукты ───

    def get_products(self, vendor: str, category: str = None,
                     search: str = "", limit: int = 500) -> List[Dict]:
        """Возвращает продукты вендора. Каждый элемент: {title, product, source}."""
        if not self._connection:
            return []

        cursor = self._connection.cursor()
        results = []
        seen = set()

        # NVD
        conds = ["vendor = ?", "deprecated = 0"]
        params = [vendor]
        if category:
            conds.append("category = ?")
            params.append(category)
        where = " AND ".join(conds)

        cursor.execute(f"""
            SELECT title, product, version, cpe_uri FROM components
            WHERE {where}
            ORDER BY title LIMIT ?
        """, params + [limit])
        for r in cursor.fetchall():
            key = r["product"]
            if key not in seen:
                seen.add(key)
                results.append({
                    "title": r["title"],
                    "product": r["product"],
                    "version": r["version"] or "",
                    "cpe_uri": r["cpe_uri"],
                    "source": "NVD",
                })

        # Российские
        conds_ru = ["vendor = ?"]
        params_ru = [vendor]
        if category:
            conds_ru.append("category = ?")
            params_ru.append(category)
        where_ru = " AND ".join(conds_ru)

        cursor.execute(f"""
            SELECT title, product, version FROM russian_components
            WHERE {where_ru}
            ORDER BY title LIMIT ?
        """, params_ru + [limit])
        for r in cursor.fetchall():
            key = r["product"]
            if key not in seen:
                seen.add(key)
                results.append({
                    "title": r["title"],
                    "product": r["product"],
                    "version": r["version"] or "",
                    "cpe_uri": "",
                    "source": "RU",
                })

        if search:
            sl = search.lower()
            results = [r for r in results if sl in r["title"].lower()]

        return results

    # ─── Поиск по title ───

    def search_by_title(self, query: str, category: str = None,
                        limit: int = 50) -> List[Dict]:
        """Поиск компонентов по названию."""
        if not self._connection or len(query) < 2:
            return []

        cursor = self._connection.cursor()
        results = []
        pattern = f"%{query}%"

        # NVD
        conds = ["title LIKE ?", "deprecated = 0"]
        params = [pattern]
        if category:
            conds.append("category = ?")
            params.append(category)

        cursor.execute(f"""
            SELECT title, vendor, product, version, cpe_uri, category FROM components
            WHERE {' AND '.join(conds)}
            ORDER BY title LIMIT ?
        """, params + [limit])
        for r in cursor.fetchall():
            results.append({
                "title": r["title"], "vendor": r["vendor"],
                "product": r["product"], "version": r["version"] or "",
                "cpe_uri": r["cpe_uri"], "category": r["category"],
                "source": "NVD",
            })

        # Российские
        conds_ru = ["title LIKE ?"]
        params_ru = [pattern]
        if category:
            conds_ru.append("category = ?")
            params_ru.append(category)

        cursor.execute(f"""
            SELECT title, vendor, product, version, category, registry FROM russian_components
            WHERE {' AND '.join(conds_ru)}
            ORDER BY title LIMIT ?
        """, params_ru + [limit])
        for r in cursor.fetchall():
            results.append({
                "title": r["title"], "vendor": r["vendor"],
                "product": r["product"], "version": r["version"] or "",
                "cpe_uri": "", "category": r["category"],
                "source": f"RU ({r['registry']})",
            })

        return results

    # ─── Получить CPE для компонента ───

    def get_cpe_for_component(self, title: str) -> Optional[Dict]:
        """Находит CPE данные по display-title компонента."""
        if not self._connection:
            return None

        cursor = self._connection.cursor()

        # Сначала NVD (trim для совместимости)
        clean = title.strip()
        cursor.execute(
            "SELECT vendor, product, version, cpe_uri FROM components WHERE TRIM(title) = ? LIMIT 1",
            (clean,))
        r = cursor.fetchone()
        if r:
            return {"vendor": r["vendor"], "product": r["product"],
                    "version": r["version"] or "", "cpe_uri": r["cpe_uri"]}

        # Российские
        cursor.execute(
            "SELECT vendor, product, version FROM russian_components WHERE TRIM(title) = ? LIMIT 1",
            (clean,))
        r = cursor.fetchone()
        if r:
            return {"vendor": r["vendor"], "product": r["product"],
                    "version": r["version"] or "", "cpe_uri": ""}

        return None
