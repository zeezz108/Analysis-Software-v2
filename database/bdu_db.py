"""
Модуль банка данных угроз безопасности информации ФСТЭК России (БДУ).

Зачем нужен модуль
------------------
Методика оценки уровня критичности уязвимостей (утв. ФСТЭК 30.06.2025)
в пункте 8а прямо называет исходными данными БДУ ФСТЭК (bdu.fstec.ru)
«а также иные источники, содержащие сведения об известных уязвимостях».
NVD NIST — как раз такой иной источник, поэтому базы не конкурируют,
а дополняют друг друга:

    NVD NIST   → CVSS, CWE, CPE, связь с CAPEC (техническая механика)
    БДУ ФСТЭК  → русское описание, наличие эксплойта, меры защиты

Мост между ними уже есть в данных: 84 612 записей БДУ из 86 495 содержат
ссылку на CVE.

Что даёт БДУ для расчёта критичности
------------------------------------
Показатель эксплуатируемости E из таблицы 1 Методики раньше угадывался
по CVSS («если ≥ 7,0, эксплойт наверное есть»). Сверка с БДУ показала,
что такая догадка ошибается в 47,6 % случаев. БДУ содержит эту сведение
явно — в поле наличия эксплойта, теми же словами, что и в примерах Методики.

Особенность импорта: колонки в bdu_fstec.db названы неверно
-----------------------------------------------------------
Скрипт импорта перепутал имена, данные при этом загружены правильно:

    колонка в базе   что в ней на самом деле        как называется здесь
    exploit          «Подтверждена производителем»  vuln_status
    impact           «Установка обновлений…»        remediation
    fix_status       «Существует в открытом доступе» exploit_status  ← это E
    fix_info         «Уязвимость устранена»         fix_status

Модуль отдаёт записи уже с правильными именами, поэтому переименовывать
колонки в базе не требуется.
"""

import os
import re
import sqlite3
from typing import Dict, Iterable, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

__all__ = ["BDUDatabase", "EXPLOIT_PUBLIC", "EXPLOIT_EXISTS", "EXPLOIT_UNKNOWN"]


# ===================================================================
# Значения поля «Наличие эксплойта» в БДУ
# ===================================================================

EXPLOIT_PUBLIC = "Существует в открытом доступе"
EXPLOIT_EXISTS = "Существует"
EXPLOIT_UNKNOWN = "Данные уточняются"


# Разбор строки уровня опасности:
# «Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 7,8)»
_SEVERITY_RE = re.compile(r"CVSS\s*([\d.]+)\s*составляет\s*([\d,.]+)", re.IGNORECASE)

# Поле cve_id в БДУ может содержать список ссылок вперемешку:
# «CVE-2015-5212, USN-2793-1, DSA-3394, Security Tracker ID:1034085»
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Номер реестра российских программ указан прямо в наименовании продукта:
# «РЕД ОС (запись в едином реестре российских программ №3751)».
# Таких записей в БДУ 20 277 — это более надёжный признак отечественного
# происхождения, чем сопоставление названия с каталогом компонентов.
_REGISTRY_RE = re.compile(
    r"запис\w*\s+в\s+едином\s+реестре\s+российских\s+программ\s*№\s*(\d+)",
    re.IGNORECASE)


def _parse_cvss_scores(severity: str) -> Dict[str, float]:
    """Извлекает оценки CVSS из текстового поля уровня опасности.

    Args:
        severity: Строка вида «… CVSS 2.0 составляет 7\n… CVSS 3.0 составляет 7,8»

    Returns:
        Словарь {версия: оценка}, например {"2.0": 7.0, "3.0": 7.8}
    """
    scores: Dict[str, float] = {}
    for version, raw in _SEVERITY_RE.findall(severity or ""):
        try:
            scores[version] = float(raw.replace(",", "."))
        except ValueError:
            continue
    return scores


class BDUDatabase:
    """Синглтон для работы с банком данных угроз ФСТЭК России."""

    _instance = None
    _connection = None
    _cve_index = None   # Ленивое соответствие CVE → BDU, см. _ensure_cve_index()

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._connection is not None:
            return

        if db_path is None:
            db_path = os.path.join(BASE_DIR, "bdu_fstec.db")

        if not os.path.exists(db_path):
            print(f"[БДУ] БД не найдена: {db_path}")
            self._connection = None
            return

        print(f"[БДУ] Подключение к: {db_path}")
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

    @property
    def available(self) -> bool:
        """True, если база подключена и с ней можно работать."""
        return self._connection is not None

    # ------------------------------------------------------------------
    # Нормализация записи
    # ------------------------------------------------------------------

    @staticmethod
    def registry_number_for(product_string: str, component_name: str) -> str:
        """Номер реестра, относящийся именно к указанному компоненту.

        Запись БДУ перечисляет через запятую все затронутые продукты, и номер
        реестра стоит в скобках сразу после конкретного наименования:

            «Google Chrome, Astra Linux Special Edition (запись в едином
             реестре российских программ №369)»

        Брать из записи первый попавшийся номер нельзя: в записи про
        уязвимость процессора AMD может соседствовать отечественная ОС,
        и процессор ошибочно получит её регистрационный номер. Поэтому
        номер ищется только в том фрагменте перечисления, где упомянут
        сам компонент.

        Args:
            product_string: Поле product записи БДУ
            component_name: Наименование компонента из паспорта

        Returns:
            Номер реестра или пустая строка, если компоненту он не принадлежит
        """
        name = (component_name or "").strip().lower()
        if not product_string or len(name) < 4:
            return ""
        for segment in product_string.split(","):
            if name in segment.lower():
                match = _REGISTRY_RE.search(segment)
                if match:
                    return match.group(1)
        return ""

    @staticmethod
    def _normalize(row: sqlite3.Row) -> Dict:
        """Приводит запись БДУ к словарю с правильными именами полей.

        Исправляет перепутанные при импорте колонки (см. описание модуля)
        и достаёт числовые оценки CVSS из текстового поля уровня опасности.
        """
        scores = _parse_cvss_scores(row["severity"])
        # Методика (п. 13) требует базовую оценку по CVSS 3.1; в БДУ версия
        # указывается как 3.0 или 3.1 — годятся обе, берём любую тройку
        cvss_v3 = next((v for k, v in scores.items() if k.startswith("3")), None)

        # В поле cve_id перемешаны идентификаторы разных систем — оставляем
        # только собственно CVE, остальное уходит в cve_all
        cve_matches = _CVE_RE.findall(row["cve_id"] or "")
        product = row["product"] or ""
        registry_match = _REGISTRY_RE.search(product)

        return {
            "bdu_id": row["bdu_id"],
            "cve_id": (cve_matches[0].upper() if cve_matches else ""),
            "cve_all": [c.upper() for c in cve_matches],
            "registry_number": registry_match.group(1) if registry_match else "",
            "description": row["description"] or "",
            "vendor": row["vendor"] or "",
            "product": row["product"] or "",
            "version": row["version"] or "",
            "software_type": row["software_type"] or "",
            "vuln_type": row["vuln_type"] or "",
            "publish_date": row["publish_date"] or "",
            "cwe_id": row["cwe_id"] or "",
            "cwe_name": row["cwe_name"] or "",
            "severity_text": row["severity"] or "",
            "cvss_scores": scores,
            "cvss_v3_score": cvss_v3,
            "cvss_v3_vector": row["cvss_v3"] or "",
            # Ниже — колонки, переименованные из перепутанных
            "exploit_status": row["fix_status"] or "",   # наличие эксплойта → E
            "vuln_status": row["exploit"] or "",         # статус уязвимости
            "fix_status": row["fix_info"] or "",         # статус исправления
            "remediation": row["impact"] or "",          # способ устранения
            "refs": row["refs"] or "",
        }

    # ------------------------------------------------------------------
    # Поиск
    # ------------------------------------------------------------------

    def _ensure_cve_index(self) -> Dict[str, str]:
        """Строит соответствие «идентификатор CVE → идентификатор БДУ».

        Прямой поиск `WHERE cve_id = ?` находит только записи с одним CVE,
        а в БДУ поле часто содержит список вперемешку с другими системами:
        «CVE-2015-5212, USN-2793-1, DSA-3394». Поиск через LIKE не может
        использовать индекс и на пакетном запросе становится неприемлемо
        медленным, поэтому соответствие один раз собирается в память.

        Строится лениво, при первом обращении.
        """
        if getattr(self, "_cve_index", None) is not None:
            return self._cve_index

        index: Dict[str, str] = {}
        cursor = self._connection.cursor()
        cursor.execute(
            "SELECT bdu_id, cve_id FROM bdu_entries "
            "WHERE cve_id IS NOT NULL AND cve_id != ''")
        for bdu_id, raw in cursor.fetchall():
            for cve in _CVE_RE.findall(raw):
                index.setdefault(cve.upper(), bdu_id)

        self._cve_index = index
        return index

    def _fetch_by_bdu_id(self, bdu_id: str) -> Optional[Dict]:
        """Возвращает нормализованную запись по идентификатору БДУ."""
        cursor = self._connection.cursor()
        cursor.execute("SELECT * FROM bdu_entries WHERE bdu_id = ?", (bdu_id,))
        row = cursor.fetchone()
        return self._normalize(row) if row else None

    def get_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Возвращает запись БДУ, соответствующую идентификатору CVE.

        Args:
            cve_id: Идентификатор вида «CVE-2021-41379»

        Returns:
            Нормализованная запись или None, если соответствия нет
        """
        if not self._connection or not cve_id:
            return None

        bdu_id = self._ensure_cve_index().get(cve_id.strip().upper())
        return self._fetch_by_bdu_id(bdu_id) if bdu_id else None

    def get_many_by_cve(self, cve_ids: Iterable[str]) -> Dict[str, Dict]:
        """Пакетный поиск записей БДУ по списку CVE.

        Args:
            cve_ids: Идентификаторы CVE

        Returns:
            Словарь {cve_id: запись БДУ} только для найденных
        """
        ids = [c.strip().upper() for c in cve_ids if c and c.strip()]
        if not self._connection or not ids:
            return {}

        index = self._ensure_cve_index()
        wanted = {cve: index[cve] for cve in ids if cve in index}
        if not wanted:
            return {}

        # Одна запись БДУ может покрывать несколько запрошенных CVE
        records: Dict[str, Dict] = {}
        cursor = self._connection.cursor()
        unique_bdu = list(dict.fromkeys(wanted.values()))

        CHUNK = 400  # SQLite ограничивает число параметров в запросе
        for start in range(0, len(unique_bdu), CHUNK):
            chunk = unique_bdu[start:start + CHUNK]
            placeholders = ",".join("?" * len(chunk))
            cursor.execute(
                f"SELECT * FROM bdu_entries WHERE bdu_id IN ({placeholders})",
                chunk)
            for row in cursor.fetchall():
                records[row["bdu_id"]] = self._normalize(row)

        return {cve: records[bdu_id] for cve, bdu_id in wanted.items()
                if bdu_id in records}

    def search_by_product(self, vendor: str = "", product: str = "",
                          limit: int = 50) -> List[Dict]:
        """Ищет записи БДУ по производителю и наименованию продукта.

        Нужен для отечественных компонентов, которых нет в NVD: у них
        не будет CVE, но запись в БДУ может быть.
        """
        if not self._connection:
            return []

        conditions, params = [], []
        if vendor:
            conditions.append("vendor LIKE ?")
            params.append(f"%{vendor}%")
        if product:
            conditions.append("product LIKE ?")
            params.append(f"%{product}%")
        if not conditions:
            return []

        cursor = self._connection.cursor()
        cursor.execute(
            "SELECT * FROM bdu_entries WHERE " + " AND ".join(conditions)
            + " LIMIT ?", params + [limit])
        return [self._normalize(r) for r in cursor.fetchall()]

    def close(self):
        """Закрывает соединение с базой."""
        if self._connection:
            self._connection.close()
            self._connection = None
            BDUDatabase._connection = None
