"""
Скрипт создания каталога компонентов из NVD CPE Dictionary.

Скачивает CPE записи через NVD API 2.0 (с человекочитаемыми titles)
и создаёт SQLite БД `database/component_catalog.db`.

Структура каталога:
  - components — основная таблица с читаемыми названиями
  - categories — категории (Процессоры, GPU, ОС, СЗИ и т.д.)

Использование:
    python scripts/import_component_catalog.py
    python scripts/import_component_catalog.py --api-key YOUR_NVD_KEY
    python scripts/import_component_catalog.py --russian-only  (только добавить российские)

С API key: ~15-20 минут (50 req/30s)
Без API key: ~2-3 часа (5 req/30s)
"""

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "component_catalog.db")
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 10000
RATE_LIMIT_WITH_KEY = 0.7
RATE_LIMIT_WITHOUT_KEY = 6.5


def create_database(db_path):
    """Создаёт SQLite БД с таблицами каталога."""
    if os.path.exists(db_path):
        os.remove(db_path)

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")

    conn.executescript("""
        CREATE TABLE components (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cpe_uri     TEXT UNIQUE NOT NULL,
            title       TEXT NOT NULL,
            part        TEXT NOT NULL,      -- h=hardware, o=OS, a=application
            vendor      TEXT NOT NULL,
            product     TEXT NOT NULL,
            version     TEXT DEFAULT '',
            category    TEXT DEFAULT '',    -- Процессоры, GPU, ОС, СЗИ и т.д.
            country     TEXT DEFAULT '',    -- RU для российских
            deprecated  INTEGER DEFAULT 0,
            source      TEXT DEFAULT 'NVD' -- NVD, FSTEC, MINTSIFRY, GISP, MANUAL
        );

        CREATE TABLE russian_components (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            vendor      TEXT NOT NULL,
            product     TEXT NOT NULL,
            version     TEXT DEFAULT '',
            part        TEXT NOT NULL,
            category    TEXT NOT NULL,
            subcategory TEXT DEFAULT '',
            registry    TEXT DEFAULT '',    -- mintsifry, gisp, fstec, manual
            registry_id TEXT DEFAULT '',    -- номер в реестре
            cpe_uri     TEXT DEFAULT '',    -- CPE если есть в NVD
            has_cve     INTEGER DEFAULT 0   -- есть ли CVE в NVD
        );

        CREATE INDEX idx_comp_vendor ON components(vendor);
        CREATE INDEX idx_comp_product ON components(product);
        CREATE INDEX idx_comp_part ON components(part);
        CREATE INDEX idx_comp_category ON components(category);
        CREATE INDEX idx_comp_title ON components(title);
        CREATE INDEX idx_comp_country ON components(country);
        CREATE INDEX idx_ru_vendor ON russian_components(vendor);
        CREATE INDEX idx_ru_category ON russian_components(category);
    """)

    conn.commit()
    print(f"[OK] БД создана: {db_path}")
    return conn


def parse_cpe_uri(cpe_uri):
    """Разбирает CPE URI на составные части."""
    # cpe:2.3:h:intel:core_i7:12700k:*:*:*:*:*:*:*
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return None
    return {
        "part": parts[2],      # h, o, a
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if len(parts) > 5 and parts[5] not in ('*', '-') else "",
    }


def categorize_component(part, vendor, product):
    """Определяет категорию компонента по vendor/product."""
    v = vendor.lower()
    p = product.lower()

    if part == "h":
        # Процессоры
        if v in ("intel", "amd") and any(x in p for x in ("core", "xeon", "atom", "celeron",
                "pentium", "ryzen", "epyc", "athlon", "threadripper", "phenom", "sempron")):
            return "Процессоры"
        # GPU
        if any(x in p for x in ("geforce", "quadro", "tesla", "radeon", "instinct",
                "firepro", "arc_a", "iris", "uhd_graphics", "hd_graphics")):
            return "Видеоконтроллеры"
        # Сетевое
        if any(x in p for x in ("switch", "catalyst", "nexus", "router", "meraki",
                "aironet", "wireless_lan")):
            return "Сетевое оборудование"
        # Накопители
        if any(x in p for x in ("ssd", "optane", "evo", "barracuda", "ironwolf")):
            return "Накопители"
        # Серверы
        if any(x in p for x in ("server", "proliant", "poweredge", "thinksystem")):
            return "Серверы"
        # Принтеры
        if any(x in p for x in ("printer", "laserjet", "officejet", "deskjet", "mfc-")):
            return "Принтеры"
        return "Оборудование"

    elif part == "o":
        if "windows" in p:
            return "ОС Windows"
        if any(x in v for x in ("canonical", "redhat", "debian", "fedora", "suse", "opensuse")):
            return "ОС Linux"
        if v == "apple" and any(x in p for x in ("mac_os", "macos")):
            return "ОС macOS"
        if any(x in p for x in ("firmware", "bios")):
            return "Прошивки"
        return "Операционные системы"

    elif part == "a":
        if any(x in p for x in ("anti-virus", "antivirus", "endpoint_security",
                "internet_security", "total_security")):
            return "СЗИ / Антивирусы"
        if any(x in p for x in ("office", "word", "excel", "powerpoint", "libreoffice")):
            return "Офисное ПО"
        if any(x in p for x in ("chrome", "firefox", "safari", "edge", "opera")):
            return "Браузеры"
        if any(x in p for x in ("mysql", "postgresql", "sql_server", "oracle_database",
                "mariadb", "mongodb", "redis")):
            return "СУБД"
        if any(x in p for x in ("http_server", "nginx", "apache", "iis", "tomcat")):
            return "Веб-серверы"
        if any(x in p for x in ("esxi", "vsphere", "hyper-v", "proxmox", "xenserver", "qemu")):
            return "Гипервизоры"
        if any(x in p for x in ("docker", "kubernetes", "containerd", "podman")):
            return "Контейнеризация"
        return "Прикладное ПО"

    return "Другое"


def download_cpe_page(start_index, api_key=None):
    """Скачивает одну страницу CPE записей через NVD API."""
    url = f"{NVD_CPE_API}?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"
    headers = {"User-Agent": "CPE-Catalog-Importer/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP {e.code} at index {start_index}")
        return None
    except Exception as e:
        print(f"[ERROR] {e} at index {start_index}")
        return None


def import_nvd_cpe(conn, api_key=None):
    """Импортирует CPE Dictionary из NVD API."""
    # Получаем общее количество
    data = download_cpe_page(0, api_key)
    if not data:
        print("[ERROR] Не удалось получить данные NVD API")
        return

    total = data.get("totalResults", 0)
    print(f"[INFO] Всего CPE записей: {total:,}")

    cursor = conn.cursor()
    rate_limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_WITHOUT_KEY
    imported = 0
    start_index = 0

    while start_index < total:
        if start_index > 0:
            time.sleep(rate_limit)
            data = download_cpe_page(start_index, api_key)
            if not data:
                start_index += RESULTS_PER_PAGE
                continue

        products = data.get("products", [])
        batch = []

        for item in products:
            cpe = item.get("cpe", {})
            cpe_uri = cpe.get("cpeName", "")
            deprecated = cpe.get("deprecated", False)

            # Title
            titles = cpe.get("titles", [])
            title = ""
            for t in titles:
                if t.get("lang") == "en":
                    title = t.get("title", "")
                    break
            if not title and titles:
                title = titles[0].get("title", "")

            # Parse CPE
            parsed = parse_cpe_uri(cpe_uri)
            if not parsed or not title:
                continue

            category = categorize_component(parsed["part"], parsed["vendor"], parsed["product"])

            batch.append((
                cpe_uri, title, parsed["part"], parsed["vendor"],
                parsed["product"], parsed["version"], category,
                "", 1 if deprecated else 0, "NVD"
            ))

        if batch:
            cursor.executemany("""
                INSERT OR IGNORE INTO components
                (cpe_uri, title, part, vendor, product, version, category, country, deprecated, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, batch)
            conn.commit()
            imported += len(batch)

        start_index += RESULTS_PER_PAGE
        pct = min(100, int(start_index / total * 100))
        print(f"  [{pct}%] {imported:,} / {total:,} импортировано...")

    print(f"[OK] NVD CPE: {imported:,} записей импортировано")


def add_russian_components(conn):
    """Добавляет российские компоненты в каталог."""
    cursor = conn.cursor()

    russian = [
        # Процессоры
        ("Эльбрус-8СВ", "mcst", "elbrus_8sv", "", "h", "Процессоры", "VLIW", "manual", ""),
        ("Эльбрус-16С", "mcst", "elbrus_16s", "", "h", "Процессоры", "VLIW", "manual", ""),
        ("Эльбрус-2С3", "mcst", "elbrus_2s3", "", "h", "Процессоры", "VLIW", "manual", ""),
        ("Эльбрус-8С", "mcst", "elbrus_8s", "", "h", "Процессоры", "VLIW", "manual", ""),
        ("Эльбрус-4С", "mcst", "elbrus_4s", "", "h", "Процессоры", "VLIW", "manual", ""),
        ("Эльбрус-2С+", "mcst", "elbrus_2s_plus", "", "h", "Процессоры", "VLIW", "manual", ""),
        ("Байкал-М", "baikal_electronics", "baikal_m", "", "h", "Процессоры", "ARM", "manual", ""),
        ("Байкал-S", "baikal_electronics", "baikal_s", "", "h", "Процессоры", "ARM", "manual", ""),
        ("Байкал-L", "baikal_electronics", "baikal_l", "", "h", "Процессоры", "ARM", "manual", ""),

        # ОС
        ("Astra Linux Special Edition", "astralinux", "astra_linux_se", "", "o", "ОС Linux", "Сертифицированные", "mintsifry", ""),
        ("Astra Linux Common Edition", "astralinux", "astra_linux_ce", "", "o", "ОС Linux", "Общего назначения", "mintsifry", ""),
        ("Альт Рабочая станция 10", "basealt", "alt_workstation", "10", "o", "ОС Linux", "Сертифицированные", "mintsifry", ""),
        ("Альт Сервер 10", "basealt", "alt_server", "10", "o", "ОС Linux", "Серверные", "mintsifry", ""),
        ("Альт СП", "basealt", "alt_sp", "", "o", "ОС Linux", "Сертифицированные", "mintsifry", ""),
        ("РЕД ОС", "red-soft", "red_os", "", "o", "ОС Linux", "Сертифицированные", "mintsifry", ""),
        ("РОСА ОС", "rosalinux", "rosa_os", "", "o", "ОС Linux", "Общего назначения", "mintsifry", ""),
        ("ОСнова", "osnova", "osnova", "", "o", "ОС Linux", "Сертифицированные", "mintsifry", ""),
        ("Стрелец", "streletz", "streletz_os", "", "o", "ОС Linux", "Сертифицированные", "mintsifry", ""),
        ("Calculate Linux", "calculate", "calculate_linux", "", "o", "ОС Linux", "Общего назначения", "mintsifry", ""),

        # Сетевое оборудование — Eltex
        ("Eltex MES-2124", "eltex", "mes_2124", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("Eltex MES-3124F", "eltex", "mes_3124f", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("Eltex MES-2324", "eltex", "mes_2324", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("Eltex MES-5248", "eltex", "mes_5248", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("Eltex ESR-12VF", "eltex", "esr_12vf", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("Eltex ESR-20", "eltex", "esr_20", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("Eltex ESR-21", "eltex", "esr_21", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("Eltex ESR-100", "eltex", "esr_100", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("Eltex ESR-1000", "eltex", "esr_1000", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("Eltex ESR-1200", "eltex", "esr_1200", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("Eltex ME5100", "eltex", "me5100", "", "h", "Сетевое оборудование", "МСЭ", "gisp", ""),
        ("Eltex WEP-2ac", "eltex", "wep_2ac", "", "h", "Сетевое оборудование", "Wi-Fi точки", "gisp", ""),
        ("Eltex WOP-2ac", "eltex", "wop_2ac", "", "h", "Сетевое оборудование", "Wi-Fi точки", "gisp", ""),

        # Сетевое оборудование — QTECH
        ("QTECH QSW-4610", "qtech", "qsw_4610", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("QTECH QSW-3470", "qtech", "qsw_3470", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("QTECH QSW-8200", "qtech", "qsw_8200", "", "h", "Сетевое оборудование", "Коммутаторы", "gisp", ""),
        ("QTECH QSR-1920", "qtech", "qsr_1920", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),
        ("QTECH QSR-2920", "qtech", "qsr_2920", "", "h", "Сетевое оборудование", "Маршрутизаторы", "gisp", ""),

        # СЗИ
        ("Kaspersky Endpoint Security", "kaspersky", "endpoint_security", "", "a", "СЗИ / Антивирусы", "Антивирусы", "mintsifry", ""),
        ("Kaspersky Security Center", "kaspersky", "security_center", "", "a", "СЗИ / Антивирусы", "Управление", "mintsifry", ""),
        ("Dr.Web Enterprise Security Suite", "drweb", "enterprise_security_suite", "", "a", "СЗИ / Антивирусы", "Антивирусы", "mintsifry", ""),
        ("Dr.Web Desktop Security Suite", "drweb", "desktop_security_suite", "", "a", "СЗИ / Антивирусы", "Антивирусы", "mintsifry", ""),
        ("VipNet Client", "infotecs", "vipnet_client", "", "a", "СЗИ / Антивирусы", "VPN/Шифрование", "mintsifry", ""),
        ("VipNet Coordinator", "infotecs", "vipnet_coordinator", "", "a", "СЗИ / Антивирусы", "VPN/Шифрование", "mintsifry", ""),
        ("Secret Net Studio", "securitycode", "secret_net_studio", "", "a", "СЗИ / Антивирусы", "СЗИ от НСД", "mintsifry", ""),
        ("Dallas Lock", "confidential", "dallas_lock", "", "a", "СЗИ / Антивирусы", "СЗИ от НСД", "mintsifry", ""),
        ("MaxPatrol SIEM", "ptsecurity", "maxpatrol_siem", "", "a", "СЗИ / Антивирусы", "SIEM", "mintsifry", ""),
        ("MaxPatrol VM", "ptsecurity", "maxpatrol_vm", "", "a", "СЗИ / Антивирусы", "Сканеры", "mintsifry", ""),
        ("PT ISIM", "ptsecurity", "pt_isim", "", "a", "СЗИ / Антивирусы", "IDS/IPS", "mintsifry", ""),
        ("InfoWatch Traffic Monitor", "infowatch", "traffic_monitor", "", "a", "СЗИ / Антивирусы", "DLP", "mintsifry", ""),
        ("UserGate", "usergate", "usergate", "", "a", "СЗИ / Антивирусы", "NGFW", "mintsifry", ""),

        # Серверы
        ("Аквариус Server T50 D212CF", "aquarius", "server_t50", "", "h", "Серверы", "Башенные", "gisp", ""),
        ("Аквариус Server S50 D224CF", "aquarius", "server_s50", "", "h", "Серверы", "Стоечные", "gisp", ""),
        ("DEPO Storm 3400N5", "depo", "storm_3400n5", "", "h", "Серверы", "Стоечные", "gisp", ""),
        ("DEPO Neos T34", "depo", "neos_t34", "", "h", "Серверы", "Башенные", "gisp", ""),
        ("Kraftway Express G6", "kraftway", "express_g6", "", "h", "Серверы", "Стоечные", "gisp", ""),
        ("Yadro VEGMAN R120", "yadro", "vegman_r120", "", "h", "Серверы", "Стоечные", "gisp", ""),
        ("Yadro VEGMAN N110", "yadro", "vegman_n110", "", "h", "Серверы", "Стоечные", "gisp", ""),
        ("Bulat BS-327", "bulat", "bs_327", "", "h", "Серверы", "Стоечные", "gisp", ""),

        # АРМ
        ("Аквариус Cmp NS765", "aquarius", "cmp_ns765", "", "h", "АРМ", "Ноутбуки", "gisp", ""),
        ("DEPO Neos N400", "depo", "neos_n400", "", "h", "АРМ", "Настольные", "gisp", ""),
        ("Kraftway Idea", "kraftway", "idea", "", "h", "АРМ", "Моноблоки", "gisp", ""),
        ("ТОНК TN1200", "tonk", "tn1200", "", "h", "АРМ", "Тонкие клиенты", "gisp", ""),

        # Офисное ПО
        ("МойОфис Стандартный", "myoffice", "standard", "", "a", "Офисное ПО", "Офисные пакеты", "mintsifry", ""),
        ("МойОфис Профессиональный", "myoffice", "professional", "", "a", "Офисное ПО", "Офисные пакеты", "mintsifry", ""),
        ("Р7-Офис", "r7_office", "r7_office", "", "a", "Офисное ПО", "Офисные пакеты", "mintsifry", ""),
        ("OnlyOffice", "onlyoffice", "onlyoffice", "", "a", "Офисное ПО", "Офисные пакеты", "mintsifry", ""),

        # СУБД
        ("PostgreSQL (Postgres Pro)", "postgrespro", "postgres_pro", "", "a", "СУБД", "Реляционные", "mintsifry", ""),
        ("Ред База Данных", "red-soft", "red_database", "", "a", "СУБД", "Реляционные", "mintsifry", ""),
        ("Tarantool", "vk", "tarantool", "", "a", "СУБД", "NoSQL", "mintsifry", ""),
        ("ClickHouse", "yandex", "clickhouse", "", "a", "СУБД", "Аналитические", "mintsifry", ""),

        # Браузеры
        ("Яндекс Браузер", "yandex", "yandex_browser", "", "a", "Браузеры", "", "mintsifry", ""),
        ("Атом", "mailoo", "atom_browser", "", "a", "Браузеры", "", "mintsifry", ""),
        ("Спутник", "sputnik", "sputnik_browser", "", "a", "Браузеры", "", "mintsifry", ""),

        # Виртуализация
        ("Р-Виртуализация", "rostelecom", "r_virtualization", "", "a", "Гипервизоры", "", "mintsifry", ""),
        ("zVirt", "orion_soft", "zvirt", "", "a", "Гипервизоры", "", "mintsifry", ""),
        ("HOSTVM", "hostvm", "hostvm", "", "a", "Гипервизоры", "", "mintsifry", ""),
    ]

    for row in russian:
        cursor.execute("""
            INSERT OR IGNORE INTO russian_components
            (title, vendor, product, version, part, category, subcategory, registry, registry_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, row)

    conn.commit()
    count = cursor.execute("SELECT COUNT(*) FROM russian_components").fetchone()[0]
    print(f"[OK] Российские компоненты: {count} записей")


def main():
    parser = argparse.ArgumentParser(description="Импорт каталога компонентов")
    parser.add_argument("--api-key", type=str, default=None,
                        help="API key от NVD (ускоряет загрузку в 10 раз)")
    parser.add_argument("--db", type=str, default=DB_PATH)
    parser.add_argument("--russian-only", action="store_true",
                        help="Только добавить российские компоненты (без NVD)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Ограничить количество CPE записей (для тестирования)")
    args = parser.parse_args()

    conn = create_database(args.db)

    if not args.russian_only:
        print(f"\n{'='*50}")
        print("  ИМПОРТ NVD CPE DICTIONARY")
        print(f"{'='*50}")
        if args.api_key:
            print("[INFO] API key предоставлен, ~15-20 минут")
        else:
            print("[INFO] Без API key, ~2-3 часа (рекомендуется --api-key)")
        import_nvd_cpe(conn, args.api_key)

    print(f"\n{'='*50}")
    print("  ДОБАВЛЕНИЕ РОССИЙСКИХ КОМПОНЕНТОВ")
    print(f"{'='*50}")
    add_russian_components(conn)

    # Статистика
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM components")
    total_comp = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM russian_components")
    total_ru = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT category) FROM components")
    cats = cursor.fetchone()[0]

    db_size = os.path.getsize(args.db) / (1024 * 1024)

    print(f"\n{'='*50}")
    print("  ИМПОРТ ЗАВЕРШЁН")
    print(f"{'='*50}")
    print(f"  Компоненты NVD: {total_comp:,}")
    print(f"  Российские: {total_ru}")
    print(f"  Категорий: {cats}")
    print(f"  БД: {args.db}")
    print(f"  Размер: {db_size:.1f} МБ")
    print(f"{'='*50}")

    conn.close()


if __name__ == "__main__":
    main()
