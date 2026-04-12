"""
Скрипт импорта CVE из NVD NIST API 2.0 в нормализованную SQLite БД.

Создаёт файл `database/cve_database_v2.db` с тремя таблицами:
  - cve_entries:  CVE-записи (id, описание, CVSS, CWE, дата публикации)
  - cpe_entries:  уникальные CPE-компоненты (part, vendor, product, version)
  - cve_cpe_map:  связь M:N между CVE и CPE

Использование:
    python scripts/import_nvd.py --api-key YOUR_KEY
    python scripts/import_nvd.py --api-key YOUR_KEY --limit 5000   # тест на 5000 записей

С API key (~50 запросов/30 сек): полная загрузка ~250K CVE за 5-10 минут.
Без API key (~5 запросов/30 сек): ~30-40 минут.
"""

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime


# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000          # максимум NVD API
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "cve_database_v2.db")
RATE_LIMIT_WITH_KEY = 0.7        # секунд между запросами (с ключом)
RATE_LIMIT_WITHOUT_KEY = 6.5     # секунд между запросами (без ключа)


# ---------------------------------------------------------------------------
# Создание БД
# ---------------------------------------------------------------------------

def create_database(db_path: str) -> sqlite3.Connection:
    """Создаёт новую SQLite БД с нормализованной схемой."""
    # Удаляем старую, если есть
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"[INFO] Старая БД удалена: {db_path}")

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")  # 64MB cache

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id       TEXT PRIMARY KEY,
            description  TEXT,
            cvss_v2      REAL,
            cvss_v3      REAL,
            cvss_v4      REAL,
            cwe_id       TEXT,
            published    TEXT
        );

        CREATE TABLE IF NOT EXISTS cpe_entries (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            part     TEXT NOT NULL,       -- 'a' (application), 'o' (OS), 'h' (hardware)
            vendor   TEXT NOT NULL,
            product  TEXT NOT NULL,
            version  TEXT DEFAULT '*',
            UNIQUE(part, vendor, product, version)
        );

        CREATE TABLE IF NOT EXISTS cve_cpe_map (
            cve_id   TEXT NOT NULL,
            cpe_id   INTEGER NOT NULL,
            FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id),
            FOREIGN KEY (cpe_id) REFERENCES cpe_entries(id)
        );

        -- Индексы для быстрого поиска
        CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_entries(vendor, product);
        CREATE INDEX IF NOT EXISTS idx_cpe_part ON cpe_entries(part);
        CREATE INDEX IF NOT EXISTS idx_cve_cpe_cve ON cve_cpe_map(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cpe_cpe ON cve_cpe_map(cpe_id);
    """)

    conn.commit()
    print(f"[INFO] БД создана: {db_path}")
    return conn


# ---------------------------------------------------------------------------
# Парсинг CPE 2.3
# ---------------------------------------------------------------------------

def parse_cpe23(cpe_str: str) -> dict:
    """Парсит строку CPE 2.3 в словарь {part, vendor, product, version}.

    Формат: cpe:2.3:part:vendor:product:version:update:edition:language:...
    """
    parts = cpe_str.split(":")
    if len(parts) < 6:
        return None

    return {
        "part":    parts[2],      # 'a', 'o', 'h'
        "vendor":  parts[3],
        "product": parts[4],
        "version": parts[5] if parts[5] != "*" else "*",
    }


# ---------------------------------------------------------------------------
# Парсинг одной CVE-записи из ответа NVD API
# ---------------------------------------------------------------------------

def parse_cve_entry(vuln: dict) -> tuple:
    """Парсит одну CVE из ответа NVD API.

    Returns:
        (cve_row, cpe_list) где
        cve_row = (cve_id, description, cvss_v2, cvss_v3, cvss_v4, cwe_id, published)
        cpe_list = list of dict {part, vendor, product, version}
    """
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # Описание (английское)
    descriptions = cve.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS
    metrics = cve.get("metrics", {})

    cvss_v2 = None
    for m in metrics.get("cvssMetricV2", []):
        score = m.get("cvssData", {}).get("baseScore")
        if score is not None:
            cvss_v2 = float(score)
            break

    cvss_v3 = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []):
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                cvss_v3 = float(score)
                break
        if cvss_v3 is not None:
            break

    cvss_v4 = None
    for m in metrics.get("cvssMetricV40", []):
        score = m.get("cvssData", {}).get("baseScore")
        if score is not None:
            cvss_v4 = float(score)
            break

    # CWE
    cwe_id = None
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_id = val
                break
        if cwe_id:
            break

    # Дата публикации
    published = cve.get("published", "")[:10]  # YYYY-MM-DD

    # CPE из configurations
    cpe_list = []
    seen_cpes = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria and criteria.startswith("cpe:2.3:"):
                    parsed = parse_cpe23(criteria)
                    if parsed:
                        key = (parsed["part"], parsed["vendor"], parsed["product"], parsed["version"])
                        if key not in seen_cpes:
                            seen_cpes.add(key)
                            cpe_list.append(parsed)

    cve_row = (cve_id, description, cvss_v2, cvss_v3, cvss_v4, cwe_id, published)
    return cve_row, cpe_list


# ---------------------------------------------------------------------------
# Вставка в БД
# ---------------------------------------------------------------------------

def insert_batch(conn: sqlite3.Connection, cve_rows: list, cpe_data: dict):
    """Вставляет пачку CVE и CPE в БД.

    cpe_data = {cve_id: [list of cpe dicts]}
    """
    cursor = conn.cursor()

    # Вставка CVE
    cursor.executemany(
        "INSERT OR IGNORE INTO cve_entries (cve_id, description, cvss_v2, cvss_v3, cvss_v4, cwe_id, published) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        cve_rows
    )

    # Вставка CPE и маппинга
    for cve_id, cpes in cpe_data.items():
        for cpe in cpes:
            # INSERT OR IGNORE для уникальности CPE
            cursor.execute(
                "INSERT OR IGNORE INTO cpe_entries (part, vendor, product, version) VALUES (?, ?, ?, ?)",
                (cpe["part"], cpe["vendor"], cpe["product"], cpe["version"])
            )
            # Получаем id CPE
            cursor.execute(
                "SELECT id FROM cpe_entries WHERE part=? AND vendor=? AND product=? AND version=?",
                (cpe["part"], cpe["vendor"], cpe["product"], cpe["version"])
            )
            row = cursor.fetchone()
            if row:
                cpe_id = row[0]
                cursor.execute(
                    "INSERT OR IGNORE INTO cve_cpe_map (cve_id, cpe_id) VALUES (?, ?)",
                    (cve_id, cpe_id)
                )

    conn.commit()


# ---------------------------------------------------------------------------
# Скачивание из NVD API
# ---------------------------------------------------------------------------

def fetch_page(start_index: int, api_key: str = None) -> dict:
    """Скачивает одну страницу CVE из NVD API 2.0."""
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    url = NVD_API_URL + "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url)
    req.add_header("User-Agent", "AnalysisSoftwareV2/1.0")
    if api_key:
        req.add_header("apiKey", api_key)

    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data
    except urllib.error.HTTPError as e:
        print(f"\n[ERROR] HTTP {e.code}: {e.reason}")
        if e.code == 403:
            print("[ERROR] Rate limit exceeded. Waiting 30 seconds...")
            time.sleep(30)
            return fetch_page(start_index, api_key)  # retry
        elif e.code == 503:
            print("[ERROR] Service unavailable. Waiting 60 seconds...")
            time.sleep(60)
            return fetch_page(start_index, api_key)  # retry
        raise
    except urllib.error.URLError as e:
        print(f"\n[ERROR] URL error: {e.reason}")
        print("[ERROR] Retrying in 10 seconds...")
        time.sleep(10)
        return fetch_page(start_index, api_key)  # retry


def run_import(api_key: str, limit: int = 0):
    """Основная функция импорта."""
    db_path = os.path.abspath(DB_PATH)
    print(f"[START] Импорт CVE из NVD NIST API 2.0")
    print(f"[INFO]  API key: {'***' + api_key[-4:] if api_key else 'НЕТ (медленный режим)'}")
    print(f"[INFO]  БД: {db_path}")
    print(f"[INFO]  Лимит: {'без лимита' if not limit else f'{limit} записей'}")
    print()

    conn = create_database(db_path)

    rate_limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_WITHOUT_KEY

    # Первый запрос — узнаём общее количество
    print("[FETCH] Запрос #1 (определение общего количества CVE)...")
    data = fetch_page(0, api_key)
    total_results = data.get("totalResults", 0)
    print(f"[INFO]  Всего CVE в NVD: {total_results:,}")

    if limit:
        total_results = min(total_results, limit)
        print(f"[INFO]  Ограничено лимитом: {total_results:,}")

    total_pages = (total_results + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE
    print(f"[INFO]  Страниц для скачивания: {total_pages}")
    print(f"[INFO]  Rate limit: {rate_limit} сек между запросами")
    estimated_time = total_pages * rate_limit
    print(f"[INFO]  Ожидаемое время: ~{int(estimated_time // 60)} мин {int(estimated_time % 60)} сек")
    print()

    # Обрабатываем первую страницу
    vulns = data.get("vulnerabilities", [])
    cve_rows = []
    cpe_data = {}
    total_cves = 0
    total_cpes = 0

    for vuln in vulns:
        cve_row, cpe_list = parse_cve_entry(vuln)
        if cve_row[0]:  # cve_id не пустой
            cve_rows.append(cve_row)
            cpe_data[cve_row[0]] = cpe_list
            total_cpes += len(cpe_list)

    insert_batch(conn, cve_rows, cpe_data)
    total_cves += len(cve_rows)

    start_time = time.time()
    print(f"[PAGE 1/{total_pages}] CVE: {total_cves:,} | CPE: {total_cpes:,}")

    # Остальные страницы
    for page in range(1, total_pages):
        start_index = page * RESULTS_PER_PAGE
        if limit and start_index >= limit:
            break

        time.sleep(rate_limit)

        try:
            data = fetch_page(start_index, api_key)
        except Exception as e:
            print(f"\n[ERROR] Ошибка на странице {page + 1}: {e}")
            print("[ERROR] Продолжаю со следующей страницы...")
            continue

        vulns = data.get("vulnerabilities", [])
        cve_rows = []
        cpe_data = {}

        for vuln in vulns:
            cve_row, cpe_list = parse_cve_entry(vuln)
            if cve_row[0]:
                cve_rows.append(cve_row)
                cpe_data[cve_row[0]] = cpe_list
                total_cpes += len(cpe_list)

        insert_batch(conn, cve_rows, cpe_data)
        total_cves += len(cve_rows)

        elapsed = time.time() - start_time
        speed = total_cves / max(elapsed, 1)
        remaining = (total_results - total_cves) / max(speed, 1)

        print(f"\r[PAGE {page + 1}/{total_pages}] "
              f"CVE: {total_cves:,}/{total_results:,} "
              f"({total_cves * 100 // max(total_results, 1)}%) | "
              f"CPE: {total_cpes:,} | "
              f"~{int(remaining // 60)}м {int(remaining % 60)}с осталось",
              end="", flush=True)

    print()
    print()

    # Финальная статистика
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM cve_entries")
    db_cves = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cpe_entries")
    db_cpes = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM cve_cpe_map")
    db_maps = cursor.fetchone()[0]

    # Топ-10 вендоров
    cursor.execute("""
        SELECT vendor, COUNT(DISTINCT cve_id) as cnt
        FROM cpe_entries
        JOIN cve_cpe_map ON cpe_entries.id = cve_cpe_map.cpe_id
        GROUP BY vendor
        ORDER BY cnt DESC
        LIMIT 10
    """)
    top_vendors = cursor.fetchall()

    # Топ-5 по типам (part)
    cursor.execute("""
        SELECT part,
               CASE part WHEN 'a' THEN 'Application'
                         WHEN 'o' THEN 'OS'
                         WHEN 'h' THEN 'Hardware'
                         ELSE part END as type_name,
               COUNT(*) as cnt
        FROM cpe_entries
        GROUP BY part
        ORDER BY cnt DESC
    """)
    part_stats = cursor.fetchall()

    elapsed_total = time.time() - start_time
    db_size = os.path.getsize(db_path) / (1024 * 1024)

    conn.close()

    print("=" * 60)
    print("ИМПОРТ ЗАВЕРШЁН")
    print("=" * 60)
    print(f"  Время:         {int(elapsed_total // 60)} мин {int(elapsed_total % 60)} сек")
    print(f"  Размер БД:     {db_size:.1f} МБ")
    print(f"  CVE записей:   {db_cves:,}")
    print(f"  CPE компонентов: {db_cpes:,}")
    print(f"  Связей CVE-CPE: {db_maps:,}")
    print()
    print("  Типы компонентов:")
    for part, type_name, cnt in part_stats:
        print(f"    {type_name}: {cnt:,}")
    print()
    print("  Топ-10 вендоров по количеству CVE:")
    for vendor, cnt in top_vendors:
        print(f"    {vendor}: {cnt:,} CVE")
    print()
    print(f"  Файл: {db_path}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Импорт CVE из NVD NIST API 2.0 в SQLite БД"
    )
    parser.add_argument(
        "--api-key", required=True,
        help="API key для NVD (получить: https://nvd.nist.gov/developers/request-an-api-key)"
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Ограничить количество CVE для тестирования (0 = без лимита)"
    )
    args = parser.parse_args()

    run_import(api_key=args.api_key, limit=args.limit)
