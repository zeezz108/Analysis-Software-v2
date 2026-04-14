"""
Скрипт импорта CAPEC (Common Attack Pattern Enumeration and Classification)
из XML-файла с capec.mitre.org в SQLite БД.

Создаёт файл `database/capec_database.db` с таблицами:
  - capec_entries      — основная информация об атаке
  - capec_prerequisites — предусловия для атаки
  - capec_consequences  — последствия (scope + impact)
  - capec_mitigations   — меры защиты
  - capec_weaknesses    — связь CAPEC → CWE (M:N)
  - capec_relations     — связи между CAPEC (ChildOf, ParentOf, CanPrecede и т.д.)
  - capec_skills        — требуемые навыки (уровень + описание)
  - capec_taxonomy      — привязка к OWASP, ATT&CK и другим классификациям
  - capec_execution_steps — шаги выполнения атаки (Explore → Experiment → Exploit)

Использование:
    python scripts/import_capec.py
    python scripts/import_capec.py --file path/to/capec_latest.xml
    python scripts/import_capec.py --download

По умолчанию скачивает XML с https://capec.mitre.org/data/xml/capec_latest.xml
"""

import argparse
import os
import re
import sqlite3
import sys
import urllib.request
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

CAPEC_XML_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "capec_database.db")

# Namespace в CAPEC XML
NS = {
    "capec": "http://capec.mitre.org/capec-3",
    "xhtml": "http://www.w3.org/1999/xhtml",
}


# ---------------------------------------------------------------------------
# Создание БД
# ---------------------------------------------------------------------------

def create_database(db_path: str) -> sqlite3.Connection:
    """Создаёт SQLite БД с нужной схемой."""
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"[INFO] Старая БД удалена: {db_path}")

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript("""
        CREATE TABLE capec_entries (
            capec_id        INTEGER PRIMARY KEY,
            name            TEXT NOT NULL,
            abstraction     TEXT,          -- Meta / Standard / Detailed
            status          TEXT,          -- Draft / Stable / Deprecated
            description     TEXT,
            extended_desc   TEXT,
            likelihood      TEXT,          -- High / Medium / Low
            severity        TEXT,          -- High / Medium / Low
            resources_req   TEXT
        );

        CREATE TABLE capec_prerequisites (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id    INTEGER NOT NULL,
            text        TEXT NOT NULL,
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_consequences (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id    INTEGER NOT NULL,
            scope       TEXT,
            impact      TEXT,
            likelihood  TEXT,
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_mitigations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id    INTEGER NOT NULL,
            text        TEXT NOT NULL,
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_weaknesses (
            capec_id    INTEGER NOT NULL,
            cwe_id      INTEGER NOT NULL,
            PRIMARY KEY (capec_id, cwe_id),
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_relations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id    INTEGER NOT NULL,
            nature      TEXT NOT NULL,     -- ChildOf / ParentOf / CanPrecede / CanAlsoBeUsedWith
            related_id  INTEGER NOT NULL,
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_skills (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id    INTEGER NOT NULL,
            level       TEXT,             -- Low / Medium / High
            description TEXT,
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_taxonomy (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id        INTEGER NOT NULL,
            taxonomy_name   TEXT,          -- ATTACK, OWASP, WASC и т.д.
            entry_id        TEXT,
            entry_name      TEXT,
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        CREATE TABLE capec_execution_steps (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            capec_id    INTEGER NOT NULL,
            step_num    INTEGER,
            phase       TEXT,             -- Explore / Experiment / Exploit
            description TEXT,
            techniques  TEXT,             -- JSON-массив или разделённые \\n
            FOREIGN KEY (capec_id) REFERENCES capec_entries(capec_id)
        );

        -- Индексы
        CREATE INDEX idx_capec_prereq ON capec_prerequisites(capec_id);
        CREATE INDEX idx_capec_conseq ON capec_consequences(capec_id);
        CREATE INDEX idx_capec_mitig ON capec_mitigations(capec_id);
        CREATE INDEX idx_capec_weak ON capec_weaknesses(cwe_id);
        CREATE INDEX idx_capec_rel ON capec_relations(capec_id);
        CREATE INDEX idx_capec_skill ON capec_skills(capec_id);
        CREATE INDEX idx_capec_tax ON capec_taxonomy(capec_id);
        CREATE INDEX idx_capec_exec ON capec_execution_steps(capec_id);
    """)

    conn.commit()
    print(f"[OK] БД создана: {db_path}")
    return conn


# ---------------------------------------------------------------------------
# Хелперы для парсинга XML
# ---------------------------------------------------------------------------

def get_text(el, tag: str) -> str:
    """Извлекает текст из дочернего элемента (с учётом namespace)."""
    child = el.find(f"capec:{tag}", NS)
    if child is None:
        return ""
    return _collect_text(child).strip()


def _collect_text(el) -> str:
    """Рекурсивно собирает весь текст из элемента и его потомков
    (включая xhtml:p и другие вложенные теги)."""
    parts = []
    if el.text:
        parts.append(el.text)
    for child in el:
        parts.append(_collect_text(child))
        if child.tail:
            parts.append(child.tail)
    return " ".join(parts)


def clean_text(text: str) -> str:
    """Убирает лишние пробелы и переносы строк."""
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


# ---------------------------------------------------------------------------
# Парсинг одной Attack_Pattern
# ---------------------------------------------------------------------------

def parse_attack_pattern(ap, conn: sqlite3.Connection):
    """Парсит один Attack_Pattern и записывает в БД."""
    capec_id = int(ap.get("ID"))
    name = ap.get("Name", "")
    abstraction = ap.get("Abstraction", "")
    status = ap.get("Status", "")

    description = clean_text(get_text(ap, "Description"))
    extended_desc = clean_text(get_text(ap, "Extended_Description"))
    likelihood = get_text(ap, "Likelihood_Of_Attack")
    severity = get_text(ap, "Typical_Severity")

    # Resources Required
    resources_el = ap.find("capec:Resources_Required", NS)
    resources_req = ""
    if resources_el is not None:
        parts = []
        for res in resources_el.findall("capec:Resource", NS):
            parts.append(clean_text(_collect_text(res)))
        resources_req = "; ".join(parts)

    # Основная запись
    conn.execute("""
        INSERT OR IGNORE INTO capec_entries
        (capec_id, name, abstraction, status, description, extended_desc,
         likelihood, severity, resources_req)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (capec_id, name, abstraction, status, description, extended_desc,
          likelihood, severity, resources_req))

    # Prerequisites
    prereqs_el = ap.find("capec:Prerequisites", NS)
    if prereqs_el is not None:
        for p in prereqs_el.findall("capec:Prerequisite", NS):
            text = clean_text(_collect_text(p))
            if text:
                conn.execute("INSERT INTO capec_prerequisites (capec_id, text) VALUES (?, ?)",
                             (capec_id, text))

    # Consequences
    conseqs_el = ap.find("capec:Consequences", NS)
    if conseqs_el is not None:
        for c in conseqs_el.findall("capec:Consequence", NS):
            scopes = [s.text for s in c.findall("capec:Scope", NS) if s.text]
            impacts = [i.text for i in c.findall("capec:Impact", NS) if i.text]
            like = ""
            like_el = c.find("capec:Likelihood", NS)
            if like_el is not None and like_el.text:
                like = like_el.text
            conn.execute(
                "INSERT INTO capec_consequences (capec_id, scope, impact, likelihood) VALUES (?, ?, ?, ?)",
                (capec_id, "; ".join(scopes), "; ".join(impacts), like))

    # Mitigations
    mitig_el = ap.find("capec:Mitigations", NS)
    if mitig_el is not None:
        for m in mitig_el.findall("capec:Mitigation", NS):
            text = clean_text(_collect_text(m))
            if text:
                conn.execute("INSERT INTO capec_mitigations (capec_id, text) VALUES (?, ?)",
                             (capec_id, text))

    # Related Weaknesses (CWE)
    weak_el = ap.find("capec:Related_Weaknesses", NS)
    if weak_el is not None:
        for w in weak_el.findall("capec:Related_Weakness", NS):
            cwe_id = w.get("CWE_ID")
            if cwe_id:
                conn.execute(
                    "INSERT OR IGNORE INTO capec_weaknesses (capec_id, cwe_id) VALUES (?, ?)",
                    (capec_id, int(cwe_id)))

    # Related Attack Patterns
    rel_el = ap.find("capec:Related_Attack_Patterns", NS)
    if rel_el is not None:
        for r in rel_el.findall("capec:Related_Attack_Pattern", NS):
            nature = r.get("Nature", "")
            related_id = r.get("CAPEC_ID")
            if related_id:
                conn.execute(
                    "INSERT INTO capec_relations (capec_id, nature, related_id) VALUES (?, ?, ?)",
                    (capec_id, nature, int(related_id)))

    # Skills Required
    skills_el = ap.find("capec:Skills_Required", NS)
    if skills_el is not None:
        for s in skills_el.findall("capec:Skill", NS):
            level = s.get("Level", "")
            desc = clean_text(_collect_text(s))
            conn.execute(
                "INSERT INTO capec_skills (capec_id, level, description) VALUES (?, ?, ?)",
                (capec_id, level, desc))

    # Taxonomy Mappings
    tax_el = ap.find("capec:Taxonomy_Mappings", NS)
    if tax_el is not None:
        for t in tax_el.findall("capec:Taxonomy_Mapping", NS):
            tax_name = t.get("Taxonomy_Name", "")
            entry_id_el = t.find("capec:Entry_ID", NS)
            entry_name_el = t.find("capec:Entry_Name", NS)
            entry_id = entry_id_el.text if entry_id_el is not None and entry_id_el.text else ""
            entry_name = entry_name_el.text if entry_name_el is not None and entry_name_el.text else ""
            conn.execute(
                "INSERT INTO capec_taxonomy (capec_id, taxonomy_name, entry_id, entry_name) VALUES (?, ?, ?, ?)",
                (capec_id, tax_name, entry_id, entry_name))

    # Execution Flow
    exec_el = ap.find("capec:Execution_Flow", NS)
    if exec_el is not None:
        for step in exec_el.findall("capec:Attack_Step", NS):
            step_num_el = step.find("capec:Step", NS)
            phase_el = step.find("capec:Phase", NS)
            desc_el = step.find("capec:Description", NS)
            step_num = int(step_num_el.text) if step_num_el is not None and step_num_el.text else 0
            phase = phase_el.text if phase_el is not None and phase_el.text else ""
            desc = clean_text(_collect_text(desc_el)) if desc_el is not None else ""
            techniques = []
            for tech in step.findall("capec:Technique", NS):
                t_text = clean_text(_collect_text(tech))
                if t_text:
                    techniques.append(t_text)
            conn.execute(
                "INSERT INTO capec_execution_steps (capec_id, step_num, phase, description, techniques) VALUES (?, ?, ?, ?, ?)",
                (capec_id, step_num, phase, desc, "\n".join(techniques)))


# ---------------------------------------------------------------------------
# Скачивание XML
# ---------------------------------------------------------------------------

def download_xml(url: str, dest: str) -> str:
    """Скачивает XML-файл."""
    print(f"[INFO] Скачивание: {url}")
    print(f"[INFO] Файл CAPEC XML ~3-5 МБ, это займёт несколько секунд...")

    req = urllib.request.Request(url, headers={"User-Agent": "CAPEC-Importer/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()

    with open(dest, "wb") as f:
        f.write(data)

    size_mb = len(data) / (1024 * 1024)
    print(f"[OK] Скачано: {dest} ({size_mb:.1f} МБ)")
    return dest


# ---------------------------------------------------------------------------
# Главная функция
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Импорт CAPEC XML в SQLite")
    parser.add_argument("--file", type=str, default=None,
                        help="Путь к локальному capec_latest.xml")
    parser.add_argument("--download", action="store_true", default=True,
                        help="Скачать XML с capec.mitre.org (по умолчанию)")
    parser.add_argument("--db", type=str, default=DB_PATH,
                        help="Путь к выходному файлу БД")
    args = parser.parse_args()

    # Определяем путь к XML
    if args.file:
        xml_path = args.file
        if not os.path.exists(xml_path):
            print(f"[ОШИБКА] Файл не найден: {xml_path}")
            sys.exit(1)
    else:
        xml_path = os.path.join(os.path.dirname(__file__), "capec_latest.xml")
        download_xml(CAPEC_XML_URL, xml_path)

    # Создаём БД
    conn = create_database(args.db)

    # Парсим XML
    print(f"[INFO] Парсинг XML: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Ищем все Attack_Pattern
    attack_patterns = root.findall(".//capec:Attack_Pattern", NS)
    total = len(attack_patterns)
    print(f"[INFO] Найдено Attack Patterns: {total}")

    for i, ap in enumerate(attack_patterns, 1):
        parse_attack_pattern(ap, conn)
        if i % 50 == 0 or i == total:
            conn.commit()
            print(f"  [{i}/{total}] обработано...")

    conn.commit()

    # Статистика
    cur = conn.cursor()
    stats = []
    for table in ["capec_entries", "capec_prerequisites", "capec_consequences",
                   "capec_mitigations", "capec_weaknesses", "capec_relations",
                   "capec_skills", "capec_taxonomy", "capec_execution_steps"]:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        stats.append((table, count))

    print("\n" + "=" * 50)
    print("  ИМПОРТ CAPEC ЗАВЕРШЁН")
    print("=" * 50)
    for table, count in stats:
        print(f"  {table}: {count:,} записей")
    print(f"\n  БД: {args.db}")
    db_size = os.path.getsize(args.db) / (1024 * 1024)
    print(f"  Размер: {db_size:.1f} МБ")
    print("=" * 50)

    conn.close()

    # Удаляем скачанный XML (если скачивали)
    if not args.file and os.path.exists(xml_path):
        os.remove(xml_path)
        print(f"[INFO] Временный XML удалён: {xml_path}")


if __name__ == "__main__":
    main()
