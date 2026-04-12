"""
Модуль базы данных CVE — версия для нормализованной БД v2.

Все данные берутся из `cve_database_v2.db` через SQL-запросы с JOIN.
Никаких статических списков — всё из реальных данных NVD NIST.

Таблицы БД:
  cve_entries  — CVE-записи (id, описание, CVSS v2/v3/v4, CWE, дата)
  cpe_entries  — уникальные CPE (part, vendor, product, version)
  cve_cpe_map  — связь M:N между CVE и CPE
"""

import os
import sqlite3
from typing import List, Dict, Optional

from utils.cpe_utils import format_cpe_for_display

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class CVEDatabase:
    """Синглтон для работы с нормализованной CVE базой данных."""

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
            db_path = os.path.join(BASE_DIR, "cve_database_v2.db")
            if not os.path.exists(db_path):
                # Fallback на старую БД
                db_path = os.path.join(BASE_DIR, "cve_database.db")

        if not os.path.exists(db_path):
            raise FileNotFoundError(f"БД CVE не найдена: {db_path}")

        print(f"[CVE] Подключение к: {db_path}")
        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

    # =================================================================
    # УНИВЕРСАЛЬНЫЙ HELPER ДЛЯ ЗАПРОСОВ К CPE
    # =================================================================

    def _query_components(self, part: str = None,
                          vendors: list = None,
                          product_like: list = None,
                          product_not_like: list = None,
                          search: str = "",
                          limit: int = 5000) -> List[str]:
        """SQL-запрос к cpe_entries с гибкой фильтрацией.

        Args:
            part: 'h' (hardware), 'o' (OS), 'a' (application)
            vendors: список вендоров (точное совпадение, lowercase)
            product_like: список подстрок для LIKE по product
            product_not_like: список подстрок для NOT LIKE
            search: пользовательский поиск (финальная фильтрация)
            limit: максимум строк

        Returns:
            List[str] — отформатированные строки "Vendor Product Version"
        """
        conditions = []
        params = []

        if part:
            conditions.append("part = ?")
            params.append(part)

        if vendors:
            placeholders = ",".join("?" * len(vendors))
            conditions.append(f"vendor IN ({placeholders})")
            params.extend(vendors)

        if product_like:
            like_clauses = " OR ".join(["product LIKE ?" for _ in product_like])
            conditions.append(f"({like_clauses})")
            params.extend([f"%{p}%" for p in product_like])

        if product_not_like:
            for ex in product_not_like:
                conditions.append("product NOT LIKE ?")
                params.append(f"%{ex}%")

        where = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT DISTINCT vendor, product, version
            FROM cpe_entries
            WHERE {where}
            ORDER BY vendor, product, version
            LIMIT ?
        """
        params.append(limit)

        cursor = self._connection.cursor()
        cursor.execute(query, params)

        result = [format_cpe_for_display(r[0], r[1], r[2]) for r in cursor.fetchall()]
        return self._apply_search(result, search)

    def _apply_search(self, data: List[str], search: str = "") -> List[str]:
        if not search:
            return sorted(set(data))
        search_lower = search.lower()
        return sorted(set(d for d in data if search_lower in d.lower()))

    # =================================================================
    # HARDWARE — ПРОЦЕССОРЫ
    # =================================================================

    def get_processors(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["intel", "amd"],
            product_like=["core", "xeon", "ryzen", "athlon", "epyc",
                          "pentium", "celeron", "atom", "threadripper",
                          "opteron", "phenom", "sempron", "turion"],
            search=search
        )

    def get_server_processors(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["intel", "amd"],
            product_like=["xeon", "epyc", "opteron"],
            search=search
        )

    # =================================================================
    # HARDWARE — ВИДЕОКАРТЫ
    # =================================================================

    def get_graphics_cards(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["nvidia", "amd", "intel"],
            product_like=["geforce", "rtx_", "gtx_", "quadro", "tesla_",
                          "radeon", "instinct", "firepro",
                          "iris_", "uhd_graphics", "hd_graphics", "arc_a"],
            product_not_like=["microarchitectural", "processor", "ethernet",
                              "xeon", "core_", "atom", "celeron", "pentium"],
            search=search
        )

    # =================================================================
    # HARDWARE — ХРАНЕНИЕ ДАННЫХ
    # =================================================================

    def get_storage_devices(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["samsung", "western_digital", "seagate", "crucial",
                     "kingston", "intel", "sandisk", "toshiba", "hgst",
                     "micron", "sk_hynix", "corsair", "adata"],
            product_like=["ssd", "hdd", "nvme", "solid_state", "hard_disk",
                          "storage_device", "860_evo", "870_evo", "980_pro",
                          "970_evo", "850_evo", "840_evo", "850_pro",
                          "t5_portable", "t7_portable", "mx500", "bx500",
                          "barracuda", "ironwolf", "wd_blue", "wd_black",
                          "wd_red", "my_passport", "my_book"],
            product_not_like=["processor", "galaxy", "chromebook", "watch",
                              "gear", "nuc", "ethernet", "driver",
                              "commander", "lighting_node", "phone",
                              "tablet", "laptop", "notebook"],
            search=search
        )

    def get_server_storage(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["dell", "hp", "hpe", "ibm", "netapp", "emc",
                     "hitachi", "pure_storage", "samsung", "seagate",
                     "western_digital", "intel", "micron"],
            product_like=["storage", "san", "nas", "raid", "array",
                          "disk", "ssd", "nvme", "powervault",
                          "proliant", "storageworks"],
            search=search
        )

    # =================================================================
    # HARDWARE — МАТЕРИНСКИЕ ПЛАТЫ
    # =================================================================

    def get_motherboards(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["asus", "asustek", "gigabyte", "msi",
                     "asrock", "supermicro", "intel", "biostar",
                     "evga", "foxconn"],
            product_like=["motherboard", "mainboard", "rog_strix",
                          "rog_maximus", "rog_crosshair",
                          "prime_", "tuf_gaming", "aorus_",
                          "meg_", "mpg_", "mag_",
                          "x570", "b550", "z690", "z790", "b660",
                          "x670", "b650", "h670", "h610"],
            product_not_like=["programmable", "fpga", "acceleration",
                              "processor", "ethernet", "nuc", "driver"],
            search=search
        )

    # =================================================================
    # HARDWARE — МОНИТОРЫ И ПРИНТЕРЫ
    # =================================================================

    def get_monitors(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["samsung", "lg", "dell", "hp", "acer", "asus",
                     "benq", "viewsonic", "philips", "aoc", "lenovo"],
            product_like=["monitor", "display", "lcd", "led", "oled"],
            search=search
        )

    def get_printers(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["hp", "canon", "epson", "brother", "xerox",
                     "lexmark", "samsung", "ricoh", "kyocera",
                     "sharp", "konica_minolta", "oki"],
            product_like=["printer", "laserjet", "officejet", "deskjet",
                          "pixma", "workforce", "mfc", "ecosys",
                          "imagerunner", "pagewide", "envy"],
            search=search
        )

    # =================================================================
    # HARDWARE — СЕТЕВОЕ ОБОРУДОВАНИЕ
    # =================================================================

    def get_router_hardware(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["cisco", "juniper", "huawei", "mikrotik",
                     "ubiquiti", "netgear", "tp-link", "asus",
                     "dlink", "zyxel", "fortinet", "arista"],
            product_like=["router", "gateway", "asr", "isr", "rv",
                          "srx", "mx", "ex", "ar", "ne"],
            product_not_like=["switch", "modem"],
            search=search
        )

    def get_switch_hardware(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["cisco", "juniper", "huawei", "hp", "hpe",
                     "arista", "netgear", "dlink", "zyxel",
                     "tp-link", "ubiquiti", "extreme_networks"],
            product_like=["switch", "catalyst", "nexus", "sg",
                          "procurve", "aruba", "comware",
                          "quidway", "s5700", "s5720"],
            search=search
        )

    def get_network_cards(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["intel", "broadcom", "realtek", "mellanox",
                     "nvidia", "qualcomm", "marvell", "chelsio"],
            product_like=["ethernet", "network", "nic", "adapter",
                          "wifi", "wireless", "i210", "i225", "i350",
                          "x520", "x540", "x550", "x710", "xxv710",
                          "bcm", "connectx", "infiniband"],
            search=search
        )

    # =================================================================
    # HARDWARE — ОПЕРАТИВНАЯ ПАМЯТЬ
    # =================================================================

    def get_ram_options(self, search: str = "") -> List[str]:
        return self._query_components(
            part="h",
            vendors=["samsung", "sk_hynix", "micron", "kingston",
                     "corsair", "gskill", "crucial", "patriot",
                     "team_group", "adata"],
            product_like=["ddr", "memory", "ram", "dimm", "sodimm",
                          "rdimm", "lrdimm", "ecc"],
            search=search
        )

    # =================================================================
    # ОПЕРАЦИОННЫЕ СИСТЕМЫ — КЛИЕНТСКИЕ
    # =================================================================

    def get_client_operating_systems(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["microsoft", "apple", "canonical", "debian",
                     "fedoraproject", "linuxmint", "opensuse",
                     "manjaro", "google"],
            product_like=["windows_10", "windows_11", "windows_7",
                          "windows_8", "windows_xp", "windows_vista",
                          "mac_os", "macos", "os_x",
                          "ubuntu", "debian", "fedora", "linux_mint",
                          "opensuse", "manjaro",
                          "chrome_os", "android"],
            product_not_like=["server"],
            search=search
        )

    # =================================================================
    # ОПЕРАЦИОННЫЕ СИСТЕМЫ — СЕРВЕРНЫЕ
    # =================================================================

    def get_server_operating_systems(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["microsoft", "canonical", "redhat", "centos",
                     "debian", "suse", "oracle", "rocky",
                     "almalinux", "amazon", "vmware"],
            product_like=["windows_server", "ubuntu", "enterprise_linux",
                          "centos", "debian", "suse", "oracle_linux",
                          "rocky", "alma", "linux", "photon"],
            search=search
        )

    # =================================================================
    # ОПЕРАЦИОННЫЕ СИСТЕМЫ — СЕТЕВОЕ ОБОРУДОВАНИЕ
    # =================================================================

    def get_cisco_ios(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["cisco"],
            product_like=["ios", "ios_xe", "ios_xr"],
            product_not_like=["nx-os", "asa"],
            search=search
        )

    def get_junos(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["juniper"],
            product_like=["junos"],
            search=search
        )

    def get_huawei_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["huawei"],
            product_like=["vrp", "harmonyos", "emui", "magic_ui"],
            search=search
        )

    def get_other_router_os(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["mikrotik", "ubiquiti", "openwrt", "vyos",
                     "netgate", "pfsense", "opnsense"],
            search=search
        )

    def get_cisco_switch_os(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["cisco"],
            product_like=["nx-os", "ios", "cat", "asa"],
            search=search
        )

    def get_managed_switch_os(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["hp", "hpe", "arista", "aruba",
                     "extreme_networks", "juniper", "huawei"],
            product_like=["procurve", "aruba", "comware", "eos",
                          "nos", "exos", "junos", "vrp"],
            search=search
        )

    def get_unmanaged_switch_os(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["netgear", "dlink", "tp-link", "zyxel", "tenda"],
            search=search
        )

    # =================================================================
    # ПРИКЛАДНОЕ ПО
    # =================================================================

    def get_application_software(self, search: str = "") -> List[str]:
        return self._query_components(
            part="a",
            vendors=["microsoft", "google", "mozilla", "apache",
                     "oracle", "adobe", "ibm", "sap", "vmware",
                     "redhat", "postgresql", "mysql", "mariadb",
                     "elastic", "docker", "nginx", "openssl",
                     "python", "nodejs", "php", "wordpress",
                     "libreoffice", "7-zip", "videolan",
                     "wireshark", "putty", "filezilla"],
            search=search
        )

    # =================================================================
    # ВИРТУАЛИЗАЦИЯ И КОНТЕЙНЕРИЗАЦИЯ
    # =================================================================

    def get_vmware_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            vendors=["vmware"],
            product_like=["esxi", "vsphere", "vcenter", "workstation",
                          "fusion", "player", "nsx", "vrealize",
                          "horizon", "cloud_foundation"],
            search=search
        )

    def get_hyperv_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["microsoft"],
            product_like=["hyper-v", "windows_server"],
            search=search
        )

    def get_proxmox_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            vendors=["proxmox"],
            search=search
        )

    def get_kvm_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            vendors=["redhat", "linux", "qemu"],
            product_like=["kvm", "qemu", "libvirt", "ovirt",
                          "rhev", "virtualization"],
            search=search
        )

    def get_citrix_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            vendors=["citrix"],
            product_like=["hypervisor", "xenserver", "xen",
                          "virtual_apps", "workspace"],
            search=search
        )

    def get_containerizers(self, search: str = "") -> List[str]:
        return self._query_components(
            vendors=["docker", "linuxcontainers", "podman_project",
                     "kubernetes", "linuxfoundation", "sylabs",
                     "redhat", "canonical"],
            product_like=["docker", "containerd", "podman", "cri-o",
                          "lxc", "lxd", "singularity", "runc",
                          "buildah", "skopeo"],
            search=search
        )

    def get_windows_server_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["microsoft"],
            product_like=["windows_server"],
            search=search
        )

    def get_linux_server_versions(self, search: str = "") -> List[str]:
        return self._query_components(
            part="o",
            vendors=["canonical", "redhat", "centos", "debian",
                     "suse", "oracle", "rocky", "almalinux",
                     "amazon", "fedoraproject"],
            product_like=["ubuntu", "enterprise_linux", "centos",
                          "debian", "suse", "oracle_linux", "rocky",
                          "alma", "linux", "fedora"],
            search=search
        )

    # =================================================================
    # ДРАЙВЕРЫ GPU
    # =================================================================

    def get_nvidia_drivers_from_db(self, search: str = "") -> List[str]:
        return self._query_components(
            part="a",
            vendors=["nvidia"],
            product_like=["driver", "gpu_display", "cuda", "geforce",
                          "virtual_gpu"],
            search=search
        )

    def get_amd_drivers_from_db(self, search: str = "") -> List[str]:
        return self._query_components(
            part="a",
            vendors=["amd"],
            product_like=["driver", "adrenalin", "radeon_software",
                          "rocm", "catalyst"],
            search=search
        )

    def get_intel_drivers_from_db(self, search: str = "") -> List[str]:
        return self._query_components(
            part="a",
            vendors=["intel"],
            product_like=["driver", "graphics", "arc", "uhd",
                          "iris", "dch"],
            search=search
        )

    def get_gpu_drivers_by_vendor(self, vendor: str = "all",
                                  search: str = "") -> List[str]:
        if vendor == "nvidia":
            return self.get_nvidia_drivers_from_db(search)
        elif vendor == "amd":
            return self.get_amd_drivers_from_db(search)
        elif vendor == "intel":
            return self.get_intel_drivers_from_db(search)
        else:
            result = []
            result.extend(self.get_nvidia_drivers_from_db(search))
            result.extend(self.get_amd_drivers_from_db(search))
            result.extend(self.get_intel_drivers_from_db(search))
            return sorted(set(result))

    def get_gpu_drivers_by_cpe_keyword(self, gpu_name: str = "",
                                       search: str = "") -> List[str]:
        gpu_lower = gpu_name.lower() if gpu_name else ""
        if "nvidia" in gpu_lower or "geforce" in gpu_lower or "rtx" in gpu_lower:
            return self.get_nvidia_drivers_from_db(search)
        elif "amd" in gpu_lower or "radeon" in gpu_lower:
            return self.get_amd_drivers_from_db(search)
        elif "intel" in gpu_lower or "iris" in gpu_lower or "uhd" in gpu_lower:
            return self.get_intel_drivers_from_db(search)
        return self.get_gpu_drivers_by_vendor("all", search)

    # =================================================================
    # ПЕРИФЕРИЯ (МЫШИ / КЛАВИАТУРЫ — из отдельных БД)
    # =================================================================

    def get_mice(self, search: str = "") -> List[str]:
        try:
            from database.mice_db import MiceDatabase
            db = MiceDatabase()
            return db.get_all_mice(search)
        except Exception:
            return []

    def get_keyboards(self, search: str = "") -> List[str]:
        try:
            from database.keyboards_db import KeyboardsDatabase
            db = KeyboardsDatabase()
            return db.get_all_keyboards(search)
        except Exception:
            return []

    # =================================================================
    # ПОИСК CVE — через JOIN с нормализованными таблицами
    # =================================================================

    def get_cves_for_component(self, vendor: str,
                                product: str = None) -> List[Dict]:
        """Ищет CVE для vendor+product через JOIN."""
        cursor = self._connection.cursor()

        query = """
            SELECT DISTINCT c.cve_id, c.cvss_v2, c.cvss_v3, c.cvss_v4, c.cwe_id
            FROM cve_entries c
            JOIN cve_cpe_map m ON c.cve_id = m.cve_id
            JOIN cpe_entries p ON m.cpe_id = p.id
            WHERE p.vendor LIKE ?
        """
        params = [f"%{vendor.lower()}%"]
        if product:
            query += " AND p.product LIKE ?"
            params.append(f"%{product.lower()}%")
        query += " LIMIT 200"

        cursor.execute(query, params)
        return [
            {
                "cve_id": r["cve_id"],
                "cvss_v2": r["cvss_v2"],
                "cvss_v3": r["cvss_v3"],
                "cvss_v4": r["cvss_v4"],
                "cwe_id": r["cwe_id"] or "",
            }
            for r in cursor.fetchall()
        ]

    def get_cves_by_cpe_mask(self, keyword: str) -> List[Dict]:
        """Ищет CVE по ключевому слову в vendor или product."""
        cursor = self._connection.cursor()
        kw = f"%{keyword.lower()}%"

        cursor.execute("""
            SELECT DISTINCT c.cve_id, c.cvss_v2, c.cvss_v3, c.cvss_v4, c.cwe_id
            FROM cve_entries c
            JOIN cve_cpe_map m ON c.cve_id = m.cve_id
            JOIN cpe_entries p ON m.cpe_id = p.id
            WHERE p.vendor LIKE ? OR p.product LIKE ?
            LIMIT 100
        """, [kw, kw])

        return [
            {
                "cve_id": r["cve_id"],
                "cvss_v2": r["cvss_v2"],
                "cvss_v3": r["cvss_v3"],
                "cvss_v4": r["cvss_v4"],
                "cwe_id": r["cwe_id"] or "",
            }
            for r in cursor.fetchall()
        ]
