"""
Импорт БДУ ФСТЭК (Банк данных угроз безопасности информации) из XLSX.

Скачивает vullist.xlsx с bdu.fstec.ru и создаёт SQLite БД
`database/bdu_fstec.db` с уязвимостями.

Использование:
    python scripts/import_bdu.py
    python scripts/import_bdu.py --file scripts/vullist.xlsx  (если уже скачан)
"""

import argparse
import os
import re
import sqlite3
import ssl
import sys
import urllib.request

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "bdu_fstec.db")
BDU_URL = "https://bdu.fstec.ru/files/documents/vullist.xlsx"


def download_bdu(dest):
    """Скачивает vullist.xlsx с bdu.fstec.ru."""
    print(f"[INFO] Скачивание БДУ ФСТЭК...")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(BDU_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
        data = resp.read()
    with open(dest, "wb") as f:
        f.write(data)
    print(f"[OK] Скачано: {dest} ({len(data)/1024/1024:.1f} МБ)")
    return dest


def create_database(db_path):
    """Создаёт SQLite БД для BDU."""
    if os.path.exists(db_path):
        os.remove(db_path)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript("""
        CREATE TABLE bdu_entries (
            bdu_id      TEXT PRIMARY KEY,
            description TEXT,
            vendor      TEXT,
            product     TEXT,
            version     TEXT,
            software_type TEXT,
            cpe_string  TEXT,
            vuln_type   TEXT,
            publish_date TEXT,
            cvss_v2     TEXT,
            cvss_v3     TEXT,
            cvss_v4     TEXT,
            severity    TEXT,
            impact      TEXT,
            exploit     TEXT,
            fix_status  TEXT,
            fix_info    TEXT,
            refs        TEXT,
            cve_id      TEXT,
            remediation TEXT,
            cwe_name    TEXT,
            cwe_id      TEXT,
            confirmed   TEXT
        );

        CREATE INDEX idx_bdu_vendor ON bdu_entries(vendor);
        CREATE INDEX idx_bdu_product ON bdu_entries(product);
        CREATE INDEX idx_bdu_cve ON bdu_entries(cve_id);
        CREATE INDEX idx_bdu_cwe ON bdu_entries(cwe_id);
        CREATE INDEX idx_bdu_severity ON bdu_entries(severity);
    """)
    conn.commit()
    print(f"[OK] БД создана: {db_path}")
    return conn


def parse_xlsx(filepath, conn):
    """Парсит vullist.xlsx и вставляет в БД."""
    import openpyxl

    print(f"[INFO] Парсинг {filepath}...")
    wb = openpyxl.load_workbook(filepath, read_only=True)
    ws = wb.active

    cursor = conn.cursor()
    count = 0
    batch = []

    for row_idx, row in enumerate(ws.iter_rows(min_row=4, values_only=True)):
        bdu_id = str(row[0] or "").strip()
        if not bdu_id.startswith("BDU:"):
            continue

        description = str(row[1] or "")
        vendor = str(row[3] or "")
        product = str(row[4] or "")
        version = str(row[5] or "")
        software_type = str(row[6] or "")
        cpe_string = str(row[7] or "")
        vuln_type = str(row[8] or "")
        publish_date = str(row[9] or "")
        cvss_v2 = str(row[10] or "")
        cvss_v3 = str(row[11] or "")
        cvss_v4 = str(row[12] or "")
        severity = str(row[13] or "")
        impact = str(row[14] or "")
        exploit = str(row[15] or "")
        fix_status = str(row[16] or "")
        fix_info = str(row[17] or "")
        references = str(row[18] or "")
        cve_id = str(row[19] or "")
        remediation = str(row[20] or "")
        cwe_name = str(row[28] or "")
        cwe_id = str(row[29] or "")
        confirmed = str(row[27] or "")

        batch.append((
            bdu_id, description, vendor, product, version,
            software_type, cpe_string, vuln_type, publish_date,
            cvss_v2, cvss_v3, cvss_v4, severity, impact,
            exploit, fix_status, fix_info, references,
            cve_id, remediation, cwe_name, cwe_id, confirmed
        ))

        if len(batch) >= 5000:
            cursor.executemany("""
                INSERT OR IGNORE INTO bdu_entries VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, batch)
            conn.commit()
            count += len(batch)
            batch.clear()
            print(f"  {count:,} записей...")

    if batch:
        cursor.executemany("""
            INSERT OR IGNORE INTO bdu_entries VALUES
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, batch)
        conn.commit()
        count += len(batch)

    wb.close()
    print(f"[OK] Импортировано: {count:,} уязвимостей BDU")
    return count


def print_stats(conn):
    """Выводит статистику."""
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM bdu_entries")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM bdu_entries WHERE cve_id != '' AND cve_id != 'None'")
    with_cve = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT vendor) FROM bdu_entries WHERE vendor != '' AND vendor != 'None'")
    vendors = c.fetchone()[0]
    c.execute("SELECT COUNT(DISTINCT product) FROM bdu_entries WHERE product != '' AND product != 'None'")
    products = c.fetchone()[0]

    db_size = os.path.getsize(DB_PATH) / (1024 * 1024)

    print(f"\n{'='*50}")
    print(f"  ИМПОРТ БДУ ФСТЭК ЗАВЕРШЁН")
    print(f"{'='*50}")
    print(f"  Уязвимостей: {total:,}")
    print(f"  С привязкой к CVE: {with_cve:,}")
    print(f"  Вендоров: {vendors:,}")
    print(f"  Продуктов: {products:,}")
    print(f"  Размер БД: {db_size:.1f} МБ")
    print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description="Импорт БДУ ФСТЭК")
    parser.add_argument("--file", type=str, default=None)
    parser.add_argument("--db", type=str, default=DB_PATH)
    args = parser.parse_args()

    xlsx_path = args.file
    if not xlsx_path:
        xlsx_path = os.path.join(os.path.dirname(__file__), "vullist.xlsx")
        if not os.path.exists(xlsx_path):
            download_bdu(xlsx_path)

    conn = create_database(args.db)
    parse_xlsx(xlsx_path, conn)
    print_stats(conn)
    conn.close()


if __name__ == "__main__":
    main()
