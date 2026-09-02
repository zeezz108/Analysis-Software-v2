"""
Дозагрузка категорий CAPEC в существующую базу.

Зачем
-----
`import_capec.py` разбирает только `<Attack_Pattern>` и пропускает
`<Category>`. Из-за этого в базе 615 записей — 341 Detailed, 197 Standard,
77 Meta — и ни одной категории.

А категория — это вершина цепочки. На эталонной схеме Shablon_atak.jpg
каждый этап ККА начинается именно с неё:

    α1  CAPEC-118  Collect and Analyze Information
    α2  CAPEC-255  Manipulate Data Structures
    α3  CAPEC-152  Inject Unexpected Items
    α4  CAPEC-225  Subvert Access Control

Причём колонка «Типы шаблонов ПКА» на схеме — это буквально список
`Has_Member` категории: у CAPEC-118 членами идут 116, 117, 169, 224,
188, 192, 410 — ровно то, что нарисовано.

Без категорий этап ККА приходится угадывать по ключевым словам описания.
С ними он выводится точно: паттерн → его категория → этап.

Скрипт дописывает данные, ничего не удаляя: существующие записи и русские
переводы `name_ru` остаются нетронутыми.

Запуск:
    python scripts/import_capec_categories.py
    python scripts/import_capec_categories.py --file scripts/capec_latest.xml
"""

import argparse
import os
import sqlite3
import sys
import urllib.request
import xml.etree.ElementTree as ET

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "capec_database.db")
XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
NS = {"capec": "http://capec.mitre.org/capec-3"}


def _text(element) -> str:
    """Собирает весь текст элемента, включая вложенные теги."""
    if element is None:
        return ""
    return " ".join(t.strip() for t in element.itertext() if t.strip())


def download_xml(dest: str) -> str:
    """Скачивает CAPEC XML, если его ещё нет рядом со скриптом."""
    if os.path.exists(dest):
        print(f"[INFO] Использую готовый файл: {dest}")
        return dest
    print(f"[INFO] Скачиваю {XML_URL}")
    urllib.request.urlretrieve(XML_URL, dest)
    print(f"[INFO] Загружено: {os.path.getsize(dest) // 1024} КБ")
    return dest


def import_categories(conn: sqlite3.Connection, xml_path: str) -> None:
    """Добавляет категории и их состав, не трогая существующие записи."""
    root = ET.parse(xml_path).getroot()
    categories = root.findall(".//capec:Category", NS)
    print(f"[INFO] Категорий в XML: {len(categories)}")

    cursor = conn.cursor()
    cursor.execute("SELECT capec_id FROM capec_entries")
    existing = {str(row[0]) for row in cursor.fetchall()}

    added_entries = 0
    added_relations = 0

    for category in categories:
        capec_id = category.get("ID")
        if not capec_id:
            continue

        if capec_id not in existing:
            cursor.execute(
                "INSERT INTO capec_entries "
                "(capec_id, name, abstraction, status, description) "
                "VALUES (?, ?, 'Category', ?, ?)",
                (capec_id, category.get("Name", ""),
                 category.get("Status", ""),
                 _text(category.find("capec:Summary", NS))))
            added_entries += 1

        # Состав категории. Направление «член → категория» совпадает
        # с уже принятым в базе ChildOf: от частного к общему
        relationships = category.find("capec:Relationships", NS)
        if relationships is None:
            continue
        for member in relationships.findall("capec:Has_Member", NS):
            member_id = member.get("CAPEC_ID")
            if not member_id:
                continue
            cursor.execute(
                "SELECT 1 FROM capec_relations "
                "WHERE capec_id = ? AND nature = 'MemberOf' AND related_id = ?",
                (member_id, capec_id))
            if cursor.fetchone():
                continue
            cursor.execute(
                "INSERT INTO capec_relations (capec_id, nature, related_id) "
                "VALUES (?, 'MemberOf', ?)", (member_id, capec_id))
            added_relations += 1

    conn.commit()
    print(f"[INFO] Добавлено категорий: {added_entries}")
    print(f"[INFO] Добавлено связей «член → категория»: {added_relations}")


def report(conn: sqlite3.Connection) -> None:
    """Печатает итог и проверяет вершины цепочек α1…α4."""
    cursor = conn.cursor()
    cursor.execute("SELECT abstraction, COUNT(*) FROM capec_entries "
                   "GROUP BY abstraction ORDER BY COUNT(*) DESC")
    print("\nУровни абстракции в базе:")
    for abstraction, count in cursor.fetchall():
        print(f"   {abstraction or '(пусто)':<12} {count}")

    print("\nВершины цепочек этапов ККА:")
    for capec_id, stage in (("118", "α1"), ("255", "α2"),
                            ("152", "α3"), ("225", "α4")):
        cursor.execute("SELECT name FROM capec_entries WHERE capec_id = ?",
                       (capec_id,))
        row = cursor.fetchone()
        cursor.execute("SELECT COUNT(*) FROM capec_relations "
                       "WHERE nature = 'MemberOf' AND related_id = ?",
                       (capec_id,))
        members = cursor.fetchone()[0]
        status = f"{row[0]} · членов {members}" if row else "НЕ НАЙДЕНА"
        print(f"   {stage}  CAPEC-{capec_id:<5} {status}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Дозагрузка категорий CAPEC в существующую базу")
    parser.add_argument("--file", default=None, help="Локальный capec_latest.xml")
    parser.add_argument("--db", default=DB_PATH, help="Путь к базе CAPEC")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"[ОШИБКА] База не найдена: {args.db}")
        sys.exit(1)

    xml_path = args.file or download_xml(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "capec_latest.xml"))
    if not os.path.exists(xml_path):
        print(f"[ОШИБКА] XML не найден: {xml_path}")
        sys.exit(1)

    conn = sqlite3.connect(args.db)
    try:
        import_categories(conn, xml_path)
        report(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
