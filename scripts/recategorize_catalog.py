"""Перекатегоризация всего каталога компонентов — правильное распределение."""
import sqlite3
import sys
import time
import os

sys.stdout.reconfigure(encoding='utf-8')

DB = os.path.join(os.path.dirname(__file__), "..", "database", "component_catalog.db")
conn = sqlite3.connect(DB)
c = conn.cursor()
t0 = time.time()

# ============================================================
# HARDWARE (part=h) — по vendor+product
# ============================================================
print("=== HARDWARE ===")

hw_rules = {
    # (category, vendor, product_prefixes_or_None)
    # Процессоры
    "Процессоры": [
        ("intel", ["core_i", "core_2", "core_3", "core_5", "core_7", "core_ultra",
                   "xeon", "atom", "pentium", "celeron"]),
        ("amd", ["ryzen", "epyc", "athlon", "threadripper", "phenom", "sempron",
                 "fx-", "turion", "opteron", "a4-", "a6-", "a8-", "a10-", "a12-"]),
        ("qualcomm", ["snapdragon", "qcs", "qcm"]),
        ("mediatek", ["helio", "dimensity", "mt6", "mt8"]),
    ],
    # Видеоконтроллеры
    "Видеоконтроллеры": [
        ("nvidia", ["geforce", "quadro", "tesla", "rtx_a", "dgx", "jetson"]),
        ("amd", ["radeon", "instinct", "firepro"]),
        ("intel", ["arc_a", "iris", "uhd_graphics", "hd_graphics"]),
    ],
    # Накопители
    "Накопители": [
        ("intel", ["ssd", "optane"]),
        ("samsung", ["840", "850", "860", "870", "970", "980", "990"]),
        ("crucial", ["mx", "bx", "p1", "p2", "p3", "p5", "ct"]),
        ("micron", ["crucial", "5300", "7300", "9300"]),
        ("western_digital", ["my_cloud", "my_book", "my_passport", "wd_"]),
        ("seagate", ["barracuda", "ironwolf", "firecuda", "exos", "blackarmor", "st5"]),
        ("toshiba", ["canvio", "hd-", "dt01", "n300", "x300"]),
    ],
    # Сетевое оборудование (целые вендоры)
    "Сетевое оборудование": [
        ("cisco", None), ("juniper", None), ("huawei", None),
        ("dlink", None), ("netgear", None), ("tp-link", None),
        ("zyxel", None), ("mikrotik", None), ("aruba", None),
        ("fortinet", None), ("moxa", None), ("ubiquiti", None),
        ("paloaltonetworks", None), ("sonicwall", None),
        ("intel", ["ethernet", "wi-fi", "wireless", "centrino", "killer",
                   "x710", "x722", "xl710", "e810", "i210", "i350", "82599"]),
        ("broadcom", ["bcm"]),
        ("realtek", None),
    ],
    # Серверы
    "Серверы": [
        ("supermicro", None),
        ("intel", ["server_board", "server_system", "compute_module", "nuc"]),
        ("dell", ["poweredge", "idrac"]),
        ("hp", ["proliant", "ilo", "moonshot"]),
        ("hpe", None),
        ("lenovo", ["thinksystem", "thinkserver"]),
        ("ibm", ["system_x", "bladecenter", "flex_system"]),
    ],
    # Принтеры
    "Принтеры": [
        ("hp", ["laserjet", "officejet", "deskjet", "pagewide", "designjet", "scanjet", "color_laserjet"]),
        ("lexmark", None), ("brother", None), ("sharp", None),
        ("xerox", None), ("ricoh", None), ("kyocera", None), ("epson", None),
        ("canon", ["imagerunner", "imageclass", "pixma", "selphy", "lbp"]),
        ("samsung", ["proxpress", "xpress", "clp-", "clx-", "ml-", "scx-"]),
    ],
    # IP-камеры
    "IP-камеры": [
        ("hikvision", None), ("dahuasecurity", None),
        ("axis", None), ("hanwhavision", None),
        ("vivotek", None), ("mobotix", None),
    ],
    # Промышленное оборудование
    "Промышленное оборудование": [
        ("siemens", None), ("schneider-electric", None),
        ("mitsubishielectric", None), ("omron", None),
        ("abb", None), ("honeywell", None), ("rockwellautomation", None),
        ("bosch", None), ("ge", ["cimplicity", "proficy"]),
    ],
    # Материнские платы
    "Материнские платы": [
        ("asus", ["rog", "tuf", "prime", "pro_", "strix",
                  "b150", "b250", "b350", "b450", "b550", "b650", "b660",
                  "x370", "x470", "x570", "x670",
                  "z170", "z270", "z370", "z390", "z490", "z590", "z690", "z790"]),
    ],
    # АРМ
    "АРМ": [
        ("lenovo", ["thinkpad", "thinkcentre", "ideapad", "ideacentre", "legion", "yoga"]),
        ("dell", ["latitude", "optiplex", "inspiron", "xps", "vostro", "precision"]),
        ("hp", ["elitebook", "probook", "pavilion", "envy", "spectre", "zbook",
                "prodesk", "elitedesk", "victus", "omen"]),
        ("apple", ["macbook", "imac", "mac_pro", "mac_mini", "mac_studio"]),
        ("asus", ["zenbook", "vivobook", "rog_zephyrus", "tuf_gaming"]),
    ],
    # Мобильные устройства
    "Мобильные устройства": [
        ("samsung", ["galaxy", "sm-"]),
        ("apple", ["iphone", "ipad", "ipod", "apple_watch", "airpods"]),
        ("google", ["pixel", "nexus"]),
        ("xiaomi", None), ("huawei", ["mate", "p30", "p40", "p50", "nova"]),
    ],
}

total_hw = 0
for category, vendor_rules in hw_rules.items():
    for vendor, patterns in vendor_rules:
        if patterns is None:
            c.execute("UPDATE components SET category = ? WHERE part = 'h' AND vendor = ?",
                      (category, vendor))
        else:
            for p in patterns:
                c.execute("UPDATE components SET category = ? WHERE part = 'h' AND vendor = ? AND product LIKE ?",
                          (category, vendor, f"{p}%"))
        total_hw += c.rowcount

# Остальные hw → Оборудование
c.execute("UPDATE components SET category = 'Оборудование' WHERE part = 'h' AND category NOT IN (%s)" %
          ",".join(f"'{cat}'" for cat in list(hw_rules.keys()) + ["Оборудование"]))
conn.commit()
print(f"  Updated: {total_hw:,}")

# ============================================================
# OS/FIRMWARE (part=o)
# ============================================================
print("\n=== OS/FIRMWARE ===")

# Прошивки — всё с firmware в product
c.execute("UPDATE components SET category = 'Прошивки' WHERE part = 'o' AND product LIKE '%firmware%'")
print(f"  Прошивки: {c.rowcount:,}")

# Windows
c.execute("UPDATE components SET category = 'ОС Windows' WHERE part = 'o' AND vendor = 'microsoft' AND product LIKE 'windows%'")
# Linux
linux_vendors = ['canonical', 'redhat', 'debian', 'fedoraproject', 'opensuse', 'suse',
                 'centos', 'oracle', 'rocky', 'almalinux']
for v in linux_vendors:
    c.execute("UPDATE components SET category = 'ОС Linux' WHERE part = 'o' AND vendor = ? AND product NOT LIKE '%firmware%'", (v,))
c.execute("UPDATE components SET category = 'ОС Linux' WHERE part = 'o' AND vendor = 'linux' AND product LIKE '%kernel%'")
# macOS
c.execute("UPDATE components SET category = 'ОС macOS' WHERE part = 'o' AND vendor = 'apple' AND (product LIKE 'mac%' OR product LIKE 'os_x%')")
# Мобильные ОС
c.execute("UPDATE components SET category = 'Мобильные ОС' WHERE part = 'o' AND vendor = 'apple' AND (product LIKE 'iphone%' OR product LIKE 'ipad%' OR product LIKE 'watch%' OR product LIKE 'tvos%' OR product LIKE 'visionos%')")
c.execute("UPDATE components SET category = 'Мобильные ОС' WHERE part = 'o' AND vendor = 'google' AND product LIKE 'android%'")
# Сетевые ОС (не firmware)
net_os_vendors = ['cisco', 'juniper', 'huawei', 'mikrotik', 'dlink', 'netgear',
                  'tp-link', 'zyxel', 'fortinet', 'aruba', 'paloaltonetworks']
for v in net_os_vendors:
    c.execute("UPDATE components SET category = 'Сетевые ОС' WHERE part = 'o' AND vendor = ? AND product NOT LIKE '%firmware%'", (v,))

# Остальные part=o → Операционные системы
c.execute("""UPDATE components SET category = 'Операционные системы' WHERE part = 'o'
    AND category NOT IN ('Прошивки', 'ОС Windows', 'ОС Linux', 'ОС macOS', 'Мобильные ОС', 'Сетевые ОС')""")
conn.commit()

# ============================================================
# APPLICATIONS (part=a)
# ============================================================
print("\n=== APPLICATIONS ===")

# Сначала всё part=a → Прикладное ПО (default)
c.execute("UPDATE components SET category = 'Прикладное ПО' WHERE part = 'a'")

# Теперь точечные правила (перезаписывают default)
app_vendor_rules = {
    "СЗИ / Антивирусы": [
        "kaspersky", "drweb", "symantec", "mcafee", "trendmicro",
        "eset", "avast", "avg", "bitdefender", "f-secure", "comodo",
        "avira", "panda", "norton", "sophos", "malwarebytes", "clamav",
    ],
}
for cat, vendors in app_vendor_rules.items():
    for v in vendors:
        c.execute("UPDATE components SET category = ? WHERE part = 'a' AND vendor = ?", (cat, v))

# По vendor+product
app_product_rules = [
    ("Браузеры", "google", "chrome"),
    ("Браузеры", "mozilla", "firefox"),
    ("Браузеры", "apple", "safari"),
    ("Браузеры", "microsoft", "edge"),
    ("Браузеры", "opera", "opera"),
    ("Браузеры", "brave", "brave"),
    ("СУБД", "oracle", "mysql"), ("СУБД", "oracle", "database"),
    ("СУБД", "postgresql", "postgresql"),
    ("СУБД", "mariadb", "mariadb"),
    ("СУБД", "mongodb", "mongodb"),
    ("СУБД", "redis", "redis"),
    ("СУБД", "microsoft", "sql_server"),
    ("СУБД", "elastic", "elasticsearch"),
    ("СУБД", "apache", "couchdb"),
    ("Офисное ПО", "microsoft", "office"),
    ("Офисное ПО", "microsoft", "word"),
    ("Офисное ПО", "microsoft", "excel"),
    ("Офисное ПО", "microsoft", "powerpoint"),
    ("Офисное ПО", "microsoft", "outlook"),
    ("Офисное ПО", "microsoft", "access"),
    ("Офисное ПО", "microsoft", "onenote"),
    ("Офисное ПО", "microsoft", "publisher"),
    ("Офисное ПО", "microsoft", "365"),
    ("Офисное ПО", "libreoffice", "libreoffice"),
    ("Офисное ПО", "apache", "openoffice"),
    ("Веб-серверы", "apache", "http_server"),
    ("Веб-серверы", "apache", "tomcat"),
    ("Веб-серверы", "nginx", "nginx"),
    ("Веб-серверы", "lighttpd", "lighttpd"),
    ("Веб-серверы", "microsoft", "iis"),
    ("Гипервизоры", "vmware", "esxi"),
    ("Гипервизоры", "vmware", "vsphere"),
    ("Гипервизоры", "vmware", "vcenter"),
    ("Гипервизоры", "vmware", "workstation"),
    ("Гипервизоры", "citrix", "hypervisor"),
    ("Гипервизоры", "citrix", "xenserver"),
    ("Гипервизоры", "proxmox", "proxmox"),
    ("Гипервизоры", "qemu", "qemu"),
    ("Гипервизоры", "oracle", "virtualbox"),
    ("Контейнеризация", "docker", "docker"),
    ("Контейнеризация", "kubernetes", "kubernetes"),
    ("Контейнеризация", "redhat", "podman"),
    ("Контейнеризация", "linuxfoundation", "containerd"),
]

for cat, vendor, product_prefix in app_product_rules:
    c.execute("UPDATE components SET category = ? WHERE part = 'a' AND vendor = ? AND product LIKE ?",
              (cat, vendor, f"{product_prefix}%"))

conn.commit()

# ============================================================
# Статистика
# ============================================================
print(f"\n{'='*50}")
print("  ИТОГОВЫЕ КАТЕГОРИИ")
print(f"{'='*50}")
c.execute("SELECT category, COUNT(*) FROM components GROUP BY category ORDER BY COUNT(*) DESC")
for r in c.fetchall():
    print(f"  {r[0]}: {r[1]:,}")

elapsed = time.time() - t0
print(f"\nВремя: {elapsed:.1f} сек")
conn.close()
