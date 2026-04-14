"""
Модуль базы данных CAPEC — запросы к capec_database.db.

Предоставляет поиск паттернов атак по CWE-идентификаторам,
которые извлекаются из CVE-записей в паспорте безопасности.

Цепочка: Компонент → CVE → CWE → CAPEC
"""

import os
import sqlite3
from typing import List, Dict, Optional, Set

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class CAPECDatabase:
    """Синглтон для работы с базой данных CAPEC."""

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
            db_path = os.path.join(BASE_DIR, "capec_database.db")

        if not os.path.exists(db_path):
            print(f"[CAPEC] БД не найдена: {db_path}")
            self._connection = None
            return

        print(f"[CAPEC] Подключение к: {db_path}")
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

    @property
    def available(self) -> bool:
        return self._connection is not None

    def get_capecs_by_cwe_ids(self, cwe_ids: Set[int]) -> List[Dict]:
        """Находит CAPEC-паттерны по набору CWE-идентификаторов.

        Args:
            cwe_ids: множество числовых CWE ID (например {89, 79, 120})

        Returns:
            Список словарей с информацией о CAPEC-паттернах,
            отсортированный по severity (High → Low).
        """
        if not self._connection or not cwe_ids:
            return []

        placeholders = ",".join("?" * len(cwe_ids))
        query = f"""
            SELECT DISTINCT
                e.capec_id,
                e.name,
                e.abstraction,
                e.severity,
                e.likelihood,
                e.description,
                w.cwe_id
            FROM capec_entries e
            JOIN capec_weaknesses w ON e.capec_id = w.capec_id
            WHERE w.cwe_id IN ({placeholders})
              AND e.status != 'Deprecated'
            ORDER BY
                CASE e.severity
                    WHEN 'Very High' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    WHEN 'Very Low' THEN 5
                    ELSE 6
                END,
                e.capec_id
        """

        cursor = self._connection.cursor()
        cursor.execute(query, list(cwe_ids))

        # Группируем CWE по CAPEC (один CAPEC может быть связан с несколькими CWE)
        capec_map = {}
        for row in cursor.fetchall():
            cid = row["capec_id"]
            if cid not in capec_map:
                capec_map[cid] = {
                    "capec_id": cid,
                    "name": row["name"],
                    "abstraction": row["abstraction"],
                    "severity": row["severity"] or "",
                    "likelihood": row["likelihood"] or "",
                    "description": row["description"] or "",
                    "cwe_ids": [],
                }
            capec_map[cid]["cwe_ids"].append(row["cwe_id"])

        # Сортировка по severity
        severity_order = {"Very High": 1, "High": 2, "Medium": 3, "Low": 4, "Very Low": 5}
        result = sorted(capec_map.values(),
                        key=lambda x: (severity_order.get(x["severity"], 6), x["capec_id"]))
        return result

    def get_mitigations(self, capec_id: int) -> List[str]:
        """Возвращает меры защиты для конкретного CAPEC."""
        if not self._connection:
            return []
        cursor = self._connection.cursor()
        cursor.execute("SELECT text FROM capec_mitigations WHERE capec_id = ?", (capec_id,))
        return [row["text"] for row in cursor.fetchall()]

    def get_execution_steps(self, capec_id: int) -> List[Dict]:
        """Возвращает шаги выполнения атаки."""
        if not self._connection:
            return []
        cursor = self._connection.cursor()
        cursor.execute(
            "SELECT step_num, phase, description, techniques "
            "FROM capec_execution_steps WHERE capec_id = ? ORDER BY step_num",
            (capec_id,))
        return [dict(row) for row in cursor.fetchall()]
