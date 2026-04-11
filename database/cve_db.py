"""
Модуль базы данных CVE (Common Vulnerabilities and Exposures)

Содержит класс CVEDatabase для работы с базой уязвимостей.
"""

import os
import sqlite3
from typing import List, Dict, Optional

# Импорт из utils (правильный путь)
from utils.cpe_utils import extract_cpe_components, parse_cpe_string, format_cpe_for_display

# Базовая папка (где лежит этот файл)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class CVEDatabase:
    """
    Синглтон для работы с базой данных CVE.
    """

    _instance = None
    _connection = None
    _parsed_cpes = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._connection is not None:
            return

        if db_path is None:
            db_path = os.path.join(BASE_DIR, "cve_database.db")

        if not os.path.exists(db_path):
            raise FileNotFoundError(f"❌ cve_database.db не найден: {db_path}")

        print(f"[CVE] Подключение к: {db_path}")

        self._connection = sqlite3.connect(db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

    # =========================================================
    # 🔹 CPE ПАРСИНГ
    # =========================================================

    def _parse_cpe(self, cpe: str) -> Optional[Dict]:
        parts = cpe.split(":")
        if len(parts) < 6:
            return None
        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5],
        }

    def _load_all_cpes(self) -> List[Dict]:
        if self._parsed_cpes is not None:
            return self._parsed_cpes

        print("[CVE] Парсинг CPE...")

        cursor = self._connection.cursor()
        cursor.execute("SELECT cpe_list FROM cve_data WHERE cpe_list IS NOT NULL")

        parsed = []
        for row in cursor.fetchall():
            cpe_list = row["cpe_list"]
            if not cpe_list:
                continue
            for cpe in cpe_list.split(","):
                cpe = cpe.strip()
                p = self._parse_cpe(cpe)
                if p:
                    parsed.append(p)

        print(f"[CVE] Загружено CPE: {len(parsed)}")
        self._parsed_cpes = parsed
        return parsed

    # =========================================================
    # 🔹 ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # =========================================================

    def _format_cpe(self, cpe: Dict) -> str:
        return format_cpe_for_display(cpe["vendor"], cpe["product"], cpe["version"])

    def _apply_search(self, data: List[str], search: str = "") -> List[str]:
        if not search:
            return sorted(set(data))
        search = search.lower()
        return sorted(set([d for d in data if search in d.lower()]))

    # =========================================================
    # 🔹 HARDWARE
    # =========================================================

    def get_processors(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "intel" in v and any(x in p for x in ["core", "pentium", "celeron", "atom"]):
                result.append(self._format_cpe(cpe))
            elif "amd" in v and any(x in p for x in ["ryzen", "athlon", "fx", "a-series"]):
                result.append(self._format_cpe(cpe))
            elif "qualcomm" in v and "snapdragon" in p:
                result.append(self._format_cpe(cpe))
            elif "mediatek" in v and any(x in p for x in ["dimensity", "helio"]):
                result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    def get_graphics_cards(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "nvidia" in v and any(x in p for x in ["geforce", "rtx", "quadro", "tesla", "titan"]):
                result.append(self._format_cpe(cpe))
            elif "amd" in v and any(x in p for x in ["radeon", "rx", "firepro"]):
                result.append(self._format_cpe(cpe))
            elif "intel" in v and any(x in p for x in ["iris", "uhd", "hd graphics"]):
                result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    def get_storage_devices(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            p = cpe["product"].lower()
            v = cpe["vendor"].lower()
            if any(x in p for x in ["software", "driver", "firmware", "firewall"]):
                continue
            if any(x in p for x in ["ssd", "hdd", "nvme", "storage", "hard drive"]):
                result.append(self._format_cpe(cpe))
            elif any(x in v for x in ["western digital", "seagate", "kingston", "crucial", "sandisk"]):
                result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    def get_motherboards(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            p = cpe["product"].lower()
            v = cpe["vendor"].lower()
            if any(x in p for x in ["software", "driver", "firmware", "firewall"]):
                continue
            if any(x in p for x in ["motherboard", "mainboard", "board"]):
                result.append(self._format_cpe(cpe))
            elif any(x in v for x in ["asus", "gigabyte", "msi", "asrock", "biostar", "evga"]):
                if not any(x in p for x in ["gpu", "graphics", "video"]):
                    result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    def get_monitors(self, search: str = "") -> List[str]:
        keywords = ["monitor", "display", "lcd", "led", "screen"]
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            if any(k in cpe["product"] for k in keywords):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_printers(self, search: str = "") -> List[str]:
        keywords = ["printer", "laserjet", "deskjet", "epson", "canon", "xerox"]
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            if any(k in cpe["product"] for k in keywords):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    # =========================================================
    # 🔹 OPERATING SYSTEMS
    # =========================================================

    def get_client_operating_systems(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            v = cpe["vendor"]
            p = cpe["product"]
            if any(x in v for x in ["microsoft", "apple", "canonical", "debian", "linux"]):
                if not any(x in p for x in ["server", "enterprise"]):
                    result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_server_operating_systems(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            p = cpe["product"]
            if any(x in p for x in ["server", "enterprise", "rhel", "ubuntu"]):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    # =========================================================
    # 🔹 NETWORK HARDWARE
    # =========================================================

    def get_router_hardware(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            p = cpe["product"].lower()
            v = cpe["vendor"].lower()
            if any(x in p for x in ["software", "os", "ios", "junos", "vrp"]):
                continue
            if any(x in p for x in ["router", "routing"]):
                result.append(self._format_cpe(cpe))
            elif any(x in v for x in ["cisco", "juniper", "huawei", "mikrotik", "ubiquiti"]):
                if not any(x in p for x in ["switch", "modem"]):
                    result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    def get_switch_hardware(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            p = cpe["product"].lower()
            v = cpe["vendor"].lower()
            if any(x in p for x in ["software", "os", "ios", "nx-os", "catos"]):
                continue
            if any(x in p for x in ["switch", "switching"]):
                result.append(self._format_cpe(cpe))
            elif any(x in v for x in ["cisco", "juniper", "huawei", "hp", "arista", "brocade"]):
                if not any(x in p for x in ["router", "firewall"]):
                    result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    def get_server_processors(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "intel" in v and any(x in p for x in ["xeon", "itanium"]):
                result.append(self._format_cpe(cpe))
            elif "amd" in v and any(x in p for x in ["epyc", "opteron"]):
                result.append(self._format_cpe(cpe))
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    # =========================================================
    # 🔹 NETWORK OS
    # =========================================================

    def get_cisco_ios(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "cisco" in v and ("ios" in p or "ios-xe" in p):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_junos(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "juniper" in v and "junos" in p:
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_huawei_versions(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "huawei" in v and ("vrp" in p or "vrp_" in p):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_other_router_os(self, search: str = "") -> List[str]:
        result = []
        router_os = ["mikrotik routeros", "ubiquiti edgeos", "vyos", "pfsense", "opnsense"]
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            p = cpe["product"].lower()
            v = cpe["vendor"].lower()
            combined = f"{v} {p}"
            if any(os_name in combined for os_name in router_os):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_cisco_switch_os(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if "cisco" in v and ("ios" in p or "nx-os" in p or "catos" in p):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_managed_switch_os(self, search: str = "") -> List[str]:
        result = []
        managed_os = ["procurve", "aruba", "arista", "extreme", "dlink"]
        for cpe in self._load_all_cpes():
            if cpe["part"] != "o":
                continue
            v = cpe["vendor"].lower()
            p = cpe["product"].lower()
            if any(os_name in v or os_name in p for os_name in managed_os):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    def get_unmanaged_switch_os(self, search: str = "") -> List[str]:
        return self._apply_search(["Неуправляемый коммутатор (без ОС)", "Неконфигурируемый коммутатор"], search)

    # =========================================================
    # 🔹 RAM AND STORAGE
    # =========================================================

    def get_ram_options(self, search: str = "") -> List[str]:
        ram_options = [
            "4 GB DDR4", "8 GB DDR4", "16 GB DDR4", "32 GB DDR4", "64 GB DDR4",
            "128 GB DDR4", "256 GB DDR4", "512 GB DDR4", "1 TB DDR4", "2 TB DDR4",
            "4 GB DDR5", "8 GB DDR5", "16 GB DDR5", "32 GB DDR5", "64 GB DDR5",
            "128 GB DDR5", "256 GB DDR5", "512 GB DDR5", "1 TB DDR5"
        ]
        return self._apply_search(ram_options, search)

    def get_server_storage(self, search: str = "") -> List[str]:
        storage_options = [
            "240 GB SSD", "480 GB SSD", "960 GB SSD", "1.92 TB SSD", "3.84 TB SSD",
            "7.68 TB SSD", "15.36 TB SSD", "1 TB HDD", "2 TB HDD", "4 TB HDD",
            "8 TB HDD", "12 TB HDD", "16 TB HDD", "NVMe 1 TB", "NVMe 2 TB",
            "NVMe 4 TB", "NVMe 8 TB", "RAID 1 (2 диска)", "RAID 5 (3+ дисков)",
            "RAID 6 (4+ дисков)", "RAID 10 (зеркалирование + чередование)"
        ]
        return self._apply_search(storage_options, search)

    def get_network_cards(self, search: str = "") -> List[str]:
        result = []
        nics = [
            "1 GbE (1 порт)", "1 GbE (2 порта)", "1 GbE (4 порта)",
            "10 GbE SFP+ (1 порт)", "10 GbE SFP+ (2 порта)", "10 GbE SFP+ (4 порта)",
            "25 GbE SFP28 (1 порт)", "25 GbE SFP28 (2 порта)",
            "40 GbE QSFP+ (1 порт)", "40 GbE QSFP+ (2 порта)",
            "100 GbE QSFP28 (1 порт)", "100 GbE QSFP28 (2 порта)",
            "FC 16 Gb (HBA)", "FC 32 Gb (HBA)",
            "Intel I350-T4", "Intel X710-DA2", "Mellanox ConnectX-4", "Broadcom NetXtreme"
        ]
        for cpe in self._load_all_cpes():
            if cpe["part"] != "h":
                continue
            p = cpe["product"].lower()
            v = cpe["vendor"].lower()
            if any(x in p for x in ["network card", "nic", "ethernet adapter", "network adapter"]):
                result.append(self._format_cpe(cpe))
            elif any(x in v for x in ["intel", "broadcom", "mellanox", "realtek", "qualcomm"]):
                if any(x in p for x in ["ethernet", "network", "nic", "adapter"]):
                    result.append(self._format_cpe(cpe))
        result.extend(nics)
        result = list(dict.fromkeys(result))
        return self._apply_search(result, search)

    # =========================================================
    # 🔹 VIRTUALIZATION
    # =========================================================

    def get_vmware_versions(self, search: str = "") -> List[str]:
        versions = [
            "VMware ESXi 6.5", "VMware ESXi 6.7", "VMware ESXi 7.0", "VMware ESXi 8.0",
            "VMware vSphere 6.5", "VMware vSphere 6.7", "VMware vSphere 7.0", "VMware vSphere 8.0"
        ]
        return self._apply_search(versions, search)

    def get_hyperv_versions(self, search: str = "") -> List[str]:
        versions = [
            "Hyper-V Server 2012 R2", "Hyper-V Server 2016", "Hyper-V Server 2019", "Hyper-V Server 2022",
            "Windows Server 2012 R2 (с Hyper-V)", "Windows Server 2016 (с Hyper-V)",
            "Windows Server 2019 (с Hyper-V)", "Windows Server 2022 (с Hyper-V)"
        ]
        return self._apply_search(versions, search)

    def get_proxmox_versions(self, search: str = "") -> List[str]:
        versions = [
            "Proxmox VE 6.4", "Proxmox VE 7.0", "Proxmox VE 7.1", "Proxmox VE 7.2",
            "Proxmox VE 7.3", "Proxmox VE 7.4", "Proxmox VE 8.0", "Proxmox VE 8.1", "Proxmox VE 8.2"
        ]
        return self._apply_search(versions, search)

    def get_kvm_versions(self, search: str = "") -> List[str]:
        versions = [
            "KVM (ядро Linux 4.x)", "KVM (ядро Linux 5.x)", "KVM (ядро Linux 6.x)",
            "Red Hat Virtualization 4.4", "Red Hat Virtualization 4.5", "oVirt 4.5"
        ]
        return self._apply_search(versions, search)

    def get_citrix_versions(self, search: str = "") -> List[str]:
        versions = [
            "Citrix Hypervisor 8.2", "Citrix Hypervisor 8.3", "Citrix Hypervisor 9.0",
            "XenServer 7.5", "XenServer 7.6", "XenServer 8.0"
        ]
        return self._apply_search(versions, search)

    def get_containerizers(self, search: str = "") -> List[str]:
        containerizers = ["Docker", "Podman", "containerd", "CRI-O", "LXC", "LXD", "rkt", "Singularity/Apptainer"]
        return self._apply_search(containerizers, search)

    def get_windows_server_versions(self, search: str = "") -> List[str]:
        versions = [
            "Windows Server 2012 R2", "Windows Server 2016", "Windows Server 2019",
            "Windows Server 2022", "Windows Server 2025"
        ]
        return self._apply_search(versions, search)

    def get_linux_server_versions(self, search: str = "") -> List[str]:
        versions = [
            "Ubuntu Server 20.04 LTS", "Ubuntu Server 22.04 LTS", "Ubuntu Server 24.04 LTS",
            "Debian 11 (Bullseye)", "Debian 12 (Bookworm)", "Red Hat Enterprise Linux 8",
            "Red Hat Enterprise Linux 9", "CentOS 7", "CentOS Stream 8", "CentOS Stream 9",
            "Rocky Linux 8", "Rocky Linux 9", "AlmaLinux 8", "AlmaLinux 9",
            "SUSE Linux Enterprise Server 15", "Oracle Linux 8", "Oracle Linux 9"
        ]
        return self._apply_search(versions, search)

    # =========================================================
    # 🔹 APPLICATION SOFTWARE
    # =========================================================

    def get_application_software(self, search: str = "") -> List[str]:
        keywords = [
            "office", "chrome", "firefox", "edge", "mysql", "postgres",
            "oracle", "nginx", "apache", "git", "docker", "kubernetes"
        ]
        result = []
        for cpe in self._load_all_cpes():
            if cpe["part"] != "a":
                continue
            p = cpe["product"].lower()
            if any(k in p for k in keywords):
                result.append(self._format_cpe(cpe))
        return self._apply_search(result, search)

    # =========================================================
    # 🔹 GPU DRIVERS
    # =========================================================

    def get_nvidia_drivers_from_db(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            v = cpe["vendor"]
            p = cpe["product"]
            if "nvidia" in v and ("driver" in p or "gpu driver" in p or "display driver" in p):
                formatted = self._format_cpe(cpe)
                if formatted not in result:
                    result.append(formatted)
            ver = cpe["version"]
            if "nvidia" in v and ver and ("driver" in ver.lower() or "display" in ver.lower()):
                formatted = f"NVIDIA {ver}"
                if formatted not in result:
                    result.append(formatted)
        if not result:
            result = [
                "NVIDIA GeForce 551.xx Driver", "NVIDIA GeForce 550.xx Driver",
                "NVIDIA GeForce 545.xx Driver", "NVIDIA GeForce 535.xx Driver",
                "NVIDIA GeForce 525.xx Driver", "NVIDIA RTX 5000 Driver",
                "NVIDIA RTX 4000 Driver", "NVIDIA Tesla Driver", "NVIDIA GRID Driver"
            ]
        return self._apply_search(result, search)

    def get_amd_drivers_from_db(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            v = cpe["vendor"]
            p = cpe["product"]
            if ("amd" in v or "ati" in v) and ("driver" in p or "radeon driver" in p or "adrenalin" in p):
                formatted = self._format_cpe(cpe)
                if formatted not in result:
                    result.append(formatted)
            ver = cpe["version"]
            if ("amd" in v or "ati" in v) and ver and ("driver" in ver.lower() or "adrenalin" in ver.lower()):
                formatted = f"AMD {ver}"
                if formatted not in result:
                    result.append(formatted)
        if not result:
            result = [
                "AMD Adrenalin 24.x.x", "AMD Adrenalin 23.x.x", "AMD Adrenalin 22.x.x",
                "AMD Pro Edition 23.Q4", "AMD Pro Edition 23.Q3", "AMD ROCm 5.x", "AMD ROCm 6.x"
            ]
        return self._apply_search(result, search)

    def get_intel_drivers_from_db(self, search: str = "") -> List[str]:
        result = []
        for cpe in self._load_all_cpes():
            v = cpe["vendor"]
            p = cpe["product"]
            if "intel" in v and ("graphics driver" in p or "display driver" in p or "gpu driver" in p):
                formatted = self._format_cpe(cpe)
                if formatted not in result:
                    result.append(formatted)
            ver = cpe["version"]
            if "intel" in v and ver and ("graphics" in ver.lower() or "driver" in ver.lower()):
                formatted = f"Intel {ver}"
                if formatted not in result:
                    result.append(formatted)
        if not result:
            result = [
                "Intel Graphics Driver 31.0.101.xxxx", "Intel Graphics Driver 30.0.101.xxxx",
                "Intel Graphics Driver 27.20.100.xxxx", "Intel Arc Graphics Driver 31.0.101.xxxx"
            ]
        return self._apply_search(result, search)

    def get_gpu_drivers_by_vendor(self, vendor: str = "all", search: str = "") -> List[str]:
        all_drivers = []
        if vendor in ["nvidia", "all"]:
            all_drivers.extend(self.get_nvidia_drivers_from_db(search))
        if vendor in ["amd", "all"]:
            all_drivers.extend(self.get_amd_drivers_from_db(search))
        if vendor in ["intel", "all"]:
            all_drivers.extend(self.get_intel_drivers_from_db(search))
        seen = set()
        unique_drivers = []
        for driver in all_drivers:
            if driver not in seen:
                seen.add(driver)
                unique_drivers.append(driver)
        return self._apply_search(unique_drivers, search)

    def get_gpu_drivers_by_cpe_keyword(self, gpu_name: str = "", search: str = "") -> List[str]:
        if not gpu_name:
            return self.get_gpu_drivers_by_vendor("all", search)
        gpu_lower = gpu_name.lower()
        vendor = "all"
        if "nvidia" in gpu_lower or "geforce" in gpu_lower or "rtx" in gpu_lower:
            vendor = "nvidia"
        elif "amd" in gpu_lower or "radeon" in gpu_lower or "rx" in gpu_lower:
            vendor = "amd"
        elif "intel" in gpu_lower or "arc" in gpu_lower or "iris" in gpu_lower:
            vendor = "intel"
        drivers = self.get_gpu_drivers_by_vendor(vendor, search)
        result = []
        for driver in drivers:
            driver_lower = driver.lower()
            if ("rtx" in gpu_lower and "rtx" in driver_lower) or \
               ("gtx" in gpu_lower and "gtx" in driver_lower) or \
               ("radeon" in gpu_lower and "radeon" in driver_lower) or \
               ("rx" in gpu_lower and "rx" in driver_lower) or \
               ("arc" in gpu_lower and "arc" in driver_lower):
                result.append(driver)
        if not result:
            result = drivers
        return self._apply_search(result, search)

    # =========================================================
    # 🔹 PERIPHERALS (внешние БД)
    # =========================================================

    def get_mice(self, search: str = "") -> List[str]:
        try:
            from database.mice_db import MiceDatabase
            return MiceDatabase().get_all_mice(search)
        except Exception as e:
            print(f"❌ Ошибка мышей: {e}")
            return []

    def get_keyboards(self, search: str = "") -> List[str]:
        try:
            from database.keyboards_db import KeyboardsDatabase
            return KeyboardsDatabase().get_all_keyboards(search)
        except Exception as e:
            print(f"❌ Ошибка клавиатур: {e}")
            return []

    # =========================================================
    # 🔹 CVE SEARCH
    # =========================================================

    def get_cves_for_component(self, vendor: str, product: str = None) -> List[Dict]:
        cursor = self._connection.cursor()
        query = """
            SELECT cve_id, cvss_v2, cvss_v3, cvss_v4, cwe_id, cpe_list
            FROM cve_data
            WHERE LOWER(vendor) LIKE ?
        """
        params = [f"%{vendor.lower()}%"]
        if product:
            query += " AND LOWER(product) LIKE ?"
            params.append(f"%{product.lower()}%")
        query += " LIMIT 100"
        cursor.execute(query, params)
        results = []
        for row in cursor.fetchall():
            results.append({
                "cve_id": row["cve_id"],
                "cvss_v2": row["cvss_v2"],
                "cvss_v3": row["cvss_v3"],
                "cvss_v4": row["cvss_v4"],
                "cwe_id": row["cwe_id"] if row["cwe_id"] else "—",
                "cpe_list": row["cpe_list"]
            })
        return results

    def get_cves_by_cpe_mask(self, keyword: str) -> List[Dict]:
        cursor = self._connection.cursor()
        query = """
            SELECT cve_id, cvss_v2, cvss_v3, cvss_v4, cpe_list
            FROM cve_data
            WHERE cpe_list LIKE ?
            LIMIT 50
        """
        cursor.execute(query, [f"%{keyword}%"])
        results = []
        for row in cursor.fetchall():
            results.append({
                "cve_id": row["cve_id"],
                "cvss_v2": row["cvss_v2"],
                "cvss_v3": row["cvss_v3"],
                "cvss_v4": row["cvss_v4"],
                "cpe_list": row["cpe_list"]
            })
        return results