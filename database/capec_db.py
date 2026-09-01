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
                w.cwe_id,
                e.name_ru
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
                    "name_ru": row["name_ru"] or "",
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

    # ── Маппинг ATT&CK technique ID → Этап ККА (4 этапа) ───────────────────
    # Модель Комплексной Компьютерной Атаки: 4 последовательных этапа.
    # Ключ: числовой ID техники ATT&CK (без "T" и без суффикса .xxx)
    _ATTACK_STAGE: Dict[int, str] = {
        # Этап 1 — Внедрение и легализация
        # Recon (TA0043) + Initial Access (TA0001) + Execution (TA0002)
        **{t: "Этап 1: Внедрение и легализация" for t in [
            # Reconnaissance
            1595, 1592, 1589, 1590, 1591, 1598, 1597, 1596, 1593, 1594,
            # Discovery
            1087, 1010, 1217, 1580, 1613, 1622, 1083, 1046, 1135, 1040,
            1201, 1120, 1069, 1057, 1012, 1018, 1518, 1082, 1016, 1049,
            1033, 1007, 1124, 1497,
            # Initial Access
            1189, 1190, 1133, 1200, 1566, 1091, 1195, 1199, 1078,
            # Execution
            1059, 1203, 1559, 1106, 1053, 1129, 1072, 1569, 1204, 1047,
        ]},
        # Этап 2 — Распространение
        # Persistence (TA0003) + C2 (TA0011) + Defense Evasion (TA0005)
        # + Lateral Movement (TA0008)
        **{t: "Этап 2: Распространение" for t in [
            # Persistence
            1098, 1197, 1547, 1037, 1176, 1554, 1136, 1543, 1546,
            1574, 1525, 1556, 1137, 1542, 1505, 1205,
            # Command and Control
            1071, 1092, 1132, 1001, 1568, 1573, 1008, 1104, 1095,
            1090, 1219, 1572, 1105,
            # Defense Evasion
            1140, 1006, 1480, 1550, 1562, 1036, 1027, 1070, 1202,
            1564, 1553, 1127, 1207, 1014, 1218, 1216, 1620, 1600,
            # Lateral Movement
            1210, 1534, 1570, 1563, 1021, 1080,
        ]},
        # Этап 3 — Повышение привилегий
        # Privilege Escalation (TA0004) + Credential Access (TA0006)
        **{t: "Этап 3: Повышение привилегий" for t in [
            1548, 1134, 1484, 1611, 1068, 1055,
            1110, 1555, 1212, 1187, 1606, 1056, 1557, 1111, 1003,
            1528, 1539, 1558, 1552,
        ]},
        # Этап 4 — НСД к защищаемой информации
        # Collection (TA0009) + Exfiltration (TA0010) + Impact (TA0040)
        **{t: "Этап 4: НСД к информации" for t in [
            # Collection + Exfiltration
            1560, 1123, 1119, 1185, 1213, 1005, 1039, 1025, 1074,
            1114, 1115, 1530, 1602,
            1020, 1030, 1048, 1041, 1011, 1567, 1029,
            # Impact
            1531, 1485, 1486, 1565, 1491, 1498, 1499, 1495, 1490,
            1496, 1489, 1529,
        ]},
    }

    def get_bdu_stage(self, capec_id: int) -> str:
        """Определяет этап ККА для данного CAPEC.

        Цепочка: CAPEC → ATT&CK technique ID → Этап ККА (1–4).
        Если ATT&CK привязки нет — keyword-fallback по name/description CAPEC.
        """
        if not self._connection:
            return "--"

        cursor = self._connection.cursor()

        # Шаг 1: ATT&CK technique IDs из taxonomy
        cursor.execute(
            "SELECT entry_id FROM capec_taxonomy WHERE capec_id=? AND taxonomy_name='ATTACK'",
            (capec_id,))
        for row in cursor.fetchall():
            raw = row["entry_id"].split(".")[0]  # убираем суффикс .xxx
            try:
                tid = int(raw)
                stage = self._ATTACK_STAGE.get(tid)
                if stage:
                    return stage
            except ValueError:
                pass

        # Шаг 2: keyword-fallback по имени/описанию CAPEC
        cursor.execute(
            "SELECT name, description FROM capec_entries WHERE capec_id=?", (capec_id,))
        row = cursor.fetchone()
        if not row:
            return "--"
        text = (row["name"] + " " + (row["description"] or "")).lower()

        # Этап 1: разведка, первоначальный доступ, выполнение кода
        if any(k in text for k in ("footprint", "fingerprint", "scan", "enumerat",
                                   "gather", "reconnaissance", "probe", "survey",
                                   "phishing", "initial access", "spoof",
                                   "social engineer", "brute force",
                                   "inject", "execute", "payload", "shellcode",
                                   "malware", "trojan", "backdoor", "exploit")):
            return "Этап 1: Внедрение и легализация"
        # Этап 2: закрепление, управление, распространение, сокрытие
        if any(k in text for k in ("persist", "autorun", "startup", "scheduled task",
                                   "registry", "hook", "command and control", "c2",
                                   "beacon", "remote control", "lateral", "pivot",
                                   "spread", "propagat", "evad", "obfuscat",
                                   "hide", "conceal", "rootkit", "move")):
            return "Этап 2: Распространение"
        # Этап 3: повышение привилегий, кража учётных данных
        if any(k in text for k in ("privilege", "escalat", "elevat", "admin",
                                   "root", "permission", "credential", "bypass",
                                   "token", "impersonat")):
            return "Этап 3: Повышение привилегий"
        # Этап 4: НСД, вывод данных, деструктивное воздействие
        if any(k in text for k in ("exfiltrat", "collect", "harvest", "steal",
                                   "intercept", "sniff", "dump", "denial",
                                   "destruct", "ransomware", "wipe", "overflow",
                                   "flood", "corrupt", "tamper", "defac",
                                   "dos", "ddos", "unauthorized access")):
            return "Этап 4: НСД к информации"

        return "--"

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
