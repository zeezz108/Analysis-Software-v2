"""
Модуль диалога паспорта безопасности

Содержит класс SecurityPassportDialog для отображения уязвимостей узла
на основе базы данных CVE.
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from utils.theme import center_window, sp

from models.node import Node
from database.cve_db import CVEDatabase
from database.capec_db import CAPECDatabase
from utils.cache import DataCache
from utils.cpe_utils import extract_cpe_components


class SecurityPassportDialog:
    """Диалог паспорта безопасности узла."""

    def __init__(self, parent, node: Node):
        self.parent = parent
        self.node = node
        self.loading_active = False
        self.cache = DataCache()

        try:
            self.db = CVEDatabase()
        except FileNotFoundError as e:
            messagebox.showerror("Ошибка", str(e))
            raise

        try:
            self.capec_db = CAPECDatabase()
        except Exception:
            self.capec_db = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Паспорт безопасности: {node.name}")
        self.dialog.geometry("1600x1020")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        # grab_set убран — можно открывать несколько окон одновременно

        self.show_loading_screen()
        self.dialog.after(100, self.load_security_data_async)

    def center_window(self):
        self.dialog.update_idletasks()
        # Get the geometry size that was set
        geo = self.dialog.geometry()
        # Parse "WxH+X+Y" or "WxH"
        size_part = geo.split('+')[0]
        if 'x' in size_part:
            width = int(size_part.split('x')[0])
            height = int(size_part.split('x')[1])
        else:
            width = self.dialog.winfo_reqwidth()
            height = self.dialog.winfo_reqheight()
        center_window(self.dialog, width, height)

    def show_loading_screen(self):
        """Показывает экран загрузки."""
        temp_frame = ctk.CTkFrame(self.dialog)
        frame_color = temp_frame.cget("fg_color")
        temp_frame.destroy()
        self.dialog.configure(fg_color=frame_color)

        self.loading_frame = ctk.CTkFrame(self.dialog, fg_color=frame_color)
        self.loading_frame.pack(fill=tk.BOTH, expand=True)

        content_frame = ctk.CTkFrame(self.loading_frame, fg_color="transparent")
        content_frame.pack(expand=True)

        ctk.CTkLabel(
            content_frame,
            text="Загрузка паспорта безопасности...",
            font=("Segoe UI", 22, "bold")
        ).pack(pady=(0, 30))

        self.animation_label = ctk.CTkLabel(
            content_frame, text="🔍",
            font=("Segoe UI", 72, "bold"), text_color="#1E88E5"
        )
        self.animation_label.pack(pady=20)

        self.status_label = ctk.CTkLabel(
            content_frame, text="Анализ компонентов узла...",
            font=("Segoe UI", 14), text_color="gray"
        )
        self.status_label.pack(pady=(0, 20))

        self.progress = ctk.CTkProgressBar(content_frame, width=500)
        self.progress.pack(pady=15)
        self.progress.set(0)

        self.loading_active = True
        self.animate_loading(0)

    def animate_loading(self, idx):
        """Анимация загрузки."""
        if self.loading_active:
            chars = ["🔍", "🔎", "🔍", "🔎"]
            colors = ["#1E88E5", "#FF9800", "#4CAF50", "#F44336"]

            try:
                if hasattr(self, 'animation_label') and self.animation_label.winfo_exists():
                    self.animation_label.configure(
                        text=chars[idx % len(chars)],
                        text_color=colors[idx % len(colors)]
                    )
                    self.dialog.after(150, lambda: self.animate_loading(idx + 1))
            except (tk.TclError, AttributeError):
                pass

    def get_node_components(self) -> Dict[str, Any]:
        """Собирает все компоненты узла."""
        components = {
            "hardware": [],
            "software": [],
            "drivers": [],
            "peripherals": [],
            "ports": [],
            "os": "",
            "has_ip": False,
            "has_mac": False,
            "has_wifi": False,
            "has_usb": False,
            "has_pon": False
        }

        # Префиксы для классификации
        peripheral_prefixes = ("Мышь:", "Клавиатура:", "Принтер:", "Монитор:")

        # Аппаратные компоненты
        for item in self.node.properties.get("hardware", []):
            if item and item.strip():
                components["hardware"].append(item)

        # Программные компоненты — классификация по префиксам
        for item in self.node.properties.get("software", []):
            if item and item.strip():
                item_lower = item.lower()
                if item.startswith(peripheral_prefixes):
                    components["peripherals"].append(item)
                elif "драйвер" in item_lower or "driver" in item_lower:
                    components["drivers"].append(item)
                else:
                    components["software"].append(item)
                if item.startswith("ОС:"):
                    components["os"] = item.replace("ОС:", "").strip()

        # Порты
        for port in self.node.ports:
            port_type = port.get("port_type", "")
            port_info = {
                "name": port.get("name", ""),
                "type": port_type,
                "mac": port.get("mac_address", ""),
                "ip": port.get("ip_address", ""),
                "mask": port.get("subnet_mask", "")
            }

            if port_type == "wifi":
                components["has_wifi"] = True
            elif port_type == "usb":
                components["has_usb"] = True
            elif port_type == "pon":
                components["has_pon"] = True

            if port_info["ip"]:
                components["has_ip"] = True
            if port_info["mac"]:
                components["has_mac"] = True

            if port_info["mac"] or port_info["ip"]:
                components["ports"].append(port_info)

        return components

    def get_all_cves_for_component(self, component_name: str) -> List[Dict]:
        """Возвращает все CVE для компонента (с кешированием в properties узла).

        При первом обращении результат сохраняется в
        `node.properties["security_passport_cache"]["components"][component_name]`.
        Последующие открытия паспорта читают готовые данные из кеша.
        Если компонент отсутствует в узле — его запись вычищается из кеша.
        """
        if not component_name or component_name == "—":
            return []

        # Готовим двухуровневый кеш: {"components": {name: [cves]}}
        cache_root = self.node.properties.setdefault(
            "security_passport_cache", {"components": {}, "version": 1}
        )
        comp_cache = cache_root.setdefault("components", {})
        # Фиксируем все ключи, которые мы реально использовали в этой сессии —
        # по завершении сборки паспорта вычистим устаревшие.
        if not hasattr(self, "_cache_used_keys"):
            self._cache_used_keys = set()
        self._cache_used_keys.add(component_name)

        if component_name in comp_cache:
            cached = comp_cache.get(component_name)
            if isinstance(cached, list):
                return cached

        try:
            # v2.1.3+: точный поиск по CPE через cpe_map (сохранён при создании узла).
            # cpe_map хранит точные vendor/product/version из CPE-браузера,
            # без необходимости парсить display-строку обратно.
            all_cves: List[Dict] = []

            # Убираем CPE-суффикс, лишние пробелы, trailing дефисы
            clean_name = component_name.split("||")[0].strip().rstrip("- ").strip()

            # 1. Ищем в таблице обратного поиска cpe_display_map (самый точный способ)
            vendor, product, version = "", "", ""
            try:
                cursor = self.db._connection.cursor()
                cursor.execute(
                    "SELECT vendor, product, version FROM cpe_display_map WHERE display_name = ?",
                    (clean_name,))
                row = cursor.fetchone()
                if row:
                    vendor, product, version = row[0], row[1], row[2]
            except Exception:
                pass

            # 2. Если в display_map не нашли — пробуем CPE-суффикс
            if not vendor and "||" in component_name:
                _, cpe_part = component_name.split("||", 1)
                parts = cpe_part.split("|")
                vendor = parts[0] if len(parts) > 0 else ""
                product = parts[1] if len(parts) > 1 else ""
                version = parts[2] if len(parts) > 2 else ""

            # 3. Последний fallback — старый парсер
            if not vendor:
                cpe_info = extract_cpe_components(clean_name)
                vendor = cpe_info.get('vendor', '')
                product = cpe_info.get('product', '')
                version = cpe_info.get('version', '')

            if vendor and product:
                cve_list = self.db.get_cves_exact(vendor, product, version)
                if not cve_list and version:
                    cve_list = self.db.get_cves_exact(vendor, product)
                all_cves.extend(cve_list)

            # Убираем дубликаты по cve_id
            seen_cves = set()
            unique_cves = []
            for cve in all_cves:
                cve_id = cve.get('cve_id', '')
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    unique_cves.append(cve)

            comp_cache[component_name] = unique_cves
            return unique_cves
        except Exception as e:
            print(f"Ошибка поиска CVE для {component_name}: {e}")
            return []

    def _prune_cache(self) -> None:
        """Удаляет из кеша записи, компоненты которых исчезли из конфигурации."""
        cache_root = self.node.properties.get("security_passport_cache")
        if not isinstance(cache_root, dict):
            return
        comp_cache = cache_root.get("components")
        if not isinstance(comp_cache, dict):
            return
        used = getattr(self, "_cache_used_keys", set())
        stale = [k for k in comp_cache.keys() if k not in used]
        for k in stale:
            comp_cache.pop(k, None)

    def build_dynamic_passport(self, components: Dict) -> List[Dict]:
        """Строит паспорт безопасности по модели ЭМВОС.

        Использует NodeDecomposition для генерации всех разделов
        с правильными индексами и порядком по эталону.
        """
        from models.osi_decomposition import NodeDecomposition, OSILevel

        decomp = NodeDecomposition(self.node)
        os_label = components.get("os", "") or ""

        # Порядок разделов по эталону паспорта
        SECTIONS = [
            (OSILevel.PHYSICAL,     "Физический уровень ЭМВОС"),
            (OSILevel.DATA_LINK,    "Канальный уровень ЭМВОС"),
            (OSILevel.NETWORK,      "Сетевой уровень ЭМВОС"),
            (OSILevel.TRANSPORT,    "Транспортный уровень ЭМВОС"),
            (OSILevel.KERNEL,       "Подсистемы ядра ОС"),
            (OSILevel.SESSION,      "Сеансовый уровень ЭМВОС"),
            (OSILevel.PRESENTATION, "Уровень представления ЭМВОС"),
            (OSILevel.APPLICATION,  "Прикладной уровень ЭМВОС"),
            (OSILevel.HARDWARE,     "Аппаратный уровень"),
            (OSILevel.USER,         "Пользовательский уровень"),
        ]

        # MAC/IP для обогащения портов физического уровня
        port_info_map = {}
        for port in self.node.ports:
            name = port.get("name", "")
            parts = []
            if port.get("mac_address"):
                parts.append(f"MAC: {port['mac_address']}")
            if port.get("ip_address"):
                mask = port.get("subnet_mask", "")
                parts.append(f"IP: {port['ip_address']}/{mask}")
            if parts:
                port_info_map[name] = "; ".join(parts)

        passport_data = []

        for level, title in SECTIONS:
            comps = decomp.get_components_by_level(level)
            if not comps:
                continue

            section_items = []
            for comp in comps:
                # --- Колонка «Наименование объекта» ---
                obj_name = comp.name

                # --- Колонка «Спецификация» ---
                # --- Ключ для поиска CVE ---
                if comp.component_type == "interface":
                    # Порт: спецификация = MAC/IP
                    port_name = comp.name.split("(")[0].replace("Порт ", "").strip()
                    spec = port_info_map.get(port_name, comp.description)
                    search_key = comp.name
                elif comp.component_type == "protocol":
                    spec = f"{comp.name} для {os_label}" if os_label else comp.name
                    search_key = comp.name
                elif comp.component_type == "subsystem":
                    spec = f"{comp.description} для {os_label}" if os_label else comp.description
                    search_key = comp.name
                elif comp.component_type in ("hardware", "software", "peripheral"):
                    # Разделяем «Процессор: Intel i7||vendor|product|ver»
                    if ":" in comp.name:
                        prefix, model = comp.name.split(":", 1)
                        obj_name = prefix.strip()
                        search_key = model.strip()
                        # Для отображения убираем CPE-суффикс и trailing дефисы
                        spec = search_key.split("||")[0].strip().rstrip("- ").strip()
                    else:
                        search_key = comp.name
                        spec = comp.name.split("||")[0].strip().rstrip("- ").strip()
                else:
                    spec = comp.description or comp.name
                    search_key = comp.name

                # CVE ищем только для реальных продуктов (hardware/software/peripheral)
                if comp.component_type in ("hardware", "software", "peripheral"):
                    all_cves = self.get_all_cves_for_component(search_key)
                else:
                    all_cves = []

                section_items.append({
                    "is_header": True,
                    "identifier": comp.identifier,
                    "component_type": obj_name,
                    "component_name": spec,
                    "spec": "",
                    "cves_count": len(all_cves)
                })

                if all_cves:
                    for cve_data in all_cves:
                        section_items.append({
                            "is_header": False,
                            "cwe": cve_data.get('cwe_id', '--'),
                            "cve": cve_data.get('cve_id', '--'),
                            "cvss_v2": cve_data.get('cvss_v2', '--'),
                            "cvss_v3": cve_data.get('cvss_v3', '--'),
                            "cvss_v4": cve_data.get('cvss_v4', '--')
                        })
                else:
                    section_items.append({
                        "is_header": False, "cwe": "--", "cve": "--",
                        "cvss_v2": "--", "cvss_v3": "--", "cvss_v4": "--"
                    })

            if section_items:
                passport_data.append({
                    "title": title,
                    "items": section_items
                })

        return passport_data

    def load_security_data_async(self):
        """Асинхронная загрузка данных об уязвимостях."""

        def load_thread():
            try:
                self.dialog.after(0, lambda: self.status_label.configure(text="Сбор компонентов узла..."))
                self.dialog.after(0, lambda: self.progress.set(0.1))

                components = self.get_node_components()

                self.dialog.after(0, lambda: self.progress.set(0.3))
                self.dialog.after(0, lambda: self.status_label.configure(text="Поиск уязвимостей в базе CVE..."))

                # Сбрасываем список «использованных» ключей для этого запуска
                self._cache_used_keys = set()
                passport_data = self.build_dynamic_passport(components)
                # Вычищаем из кеша устаревшие компоненты (которых больше нет)
                self._prune_cache()

                total_vulnerabilities = 0
                for section in passport_data:
                    for item in section["items"]:
                        if not item.get("is_header") and item.get('cve', '--') != '--':
                            total_vulnerabilities += 1

                def _safe_after(func):
                    try:
                        if self.dialog.winfo_exists():
                            self.dialog.after(0, func)
                    except Exception:
                        pass

                _safe_after(lambda: self.progress.set(0.9))
                _safe_after(lambda: self.status_label.configure(text="Формирование отчета..."))
                _safe_after(lambda: self.finish_loading(total_vulnerabilities, passport_data))

            except Exception as e:
                try:
                    if self.dialog.winfo_exists():
                        self.dialog.after(0, lambda: self.show_load_error(str(e)))
                except Exception:
                    pass

        thread = threading.Thread(target=load_thread, daemon=True)
        thread.start()

    def finish_loading(self, total_vulnerabilities: int, passport_data: List[Dict]):
        """Завершает загрузку и показывает результат."""
        self.loading_active = False

        try:
            if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
                self.loading_frame.destroy()
        except:
            pass

        self.create_widgets()
        self.populate_table(passport_data, total_vulnerabilities)

    def show_load_error(self, error_msg: str):
        self.loading_active = False
        messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить данные:\n{error_msg}")
        try:
            if self.dialog.winfo_exists():
                self.dialog.destroy()
        except:
            pass

    def get_node_type_russian(self, node_type_en: str) -> str:
        mapping = {
            "Internet": "Интернет", "Router": "Маршрутизатор",
            "Switch": "Коммутатор", "Server": "Сервер",
            "VirtualizationServer": "Сервер виртуализации",
            "ARM": "АРМ", "Laptop": "Ноутбук"
        }
        return mapping.get(node_type_en, node_type_en)

    def create_widgets(self):
        """Создаёт основной интерфейс."""
        main_frame = ctk.CTkFrame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # --- Кнопки внизу (пакуем первыми — всегда видны) ---
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

        left_buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        left_buttons.pack(side=tk.LEFT)

        ctk.CTkButton(left_buttons, text="📄 Экспорт в PDF", command=self.export_to_pdf, width=130, height=38,
                      fg_color="#8E44AD", hover_color="#7B3E96").pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(left_buttons, text="🔄 Обновить", command=self.refresh_data, width=110, height=38).pack(
            side=tk.LEFT, padx=5)

        right_buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        right_buttons.pack(side=tk.RIGHT)

        ctk.CTkButton(right_buttons, text="✕ Закрыть", command=self.dialog.destroy, width=110, height=38,
                      fg_color="#F44336").pack(side=tk.RIGHT, padx=5)

        # --- Заголовок ---
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 15))

        ctk.CTkLabel(title_frame, text="📋", font=("Segoe UI", 36), text_color="#1E88E5").pack(side=tk.LEFT, padx=(0, 10))

        header_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        header_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ctk.CTkLabel(header_frame, text="Паспорт безопасности", font=("Segoe UI", 22, "bold")).pack(anchor=tk.W)
        ctk.CTkLabel(
            header_frame, text=f"{self.node.name} • {self.get_node_type_russian(self.node.type)}",
            font=("Segoe UI", 13), text_color="gray"
        ).pack(anchor=tk.W)

        # --- Таблица CVE (верхняя, занимает ~60% высоты) ---
        table_card = ctk.CTkFrame(main_frame)
        table_card.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        table_header = ctk.CTkFrame(table_card, fg_color="transparent")
        table_header.pack(fill=tk.X, padx=15, pady=(10, 5))

        ctk.CTkLabel(table_header, text="🔍 Найденные уязвимости (CVE)", font=("Segoe UI", 15, "bold")).pack(side=tk.LEFT)

        self.count_label = ctk.CTkLabel(table_header, text="", font=("Segoe UI", 13), text_color="gray")
        self.count_label.pack(side=tk.LEFT, padx=(10, 0))

        self.status_label = ctk.CTkLabel(table_header, text="", font=("Segoe UI", 12), text_color="gray")
        self.status_label.pack(side=tk.RIGHT)

        table_container = ctk.CTkFrame(table_card)
        table_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.create_vulnerabilities_table(table_container)

        self.center_window()

    def create_vulnerabilities_table(self, parent):
        """Создаёт таблицу с уязвимостями."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Treeview", background="white", foreground="black",
                        fieldbackground="white", font=('Segoe UI', 10), rowheight=sp(28))
        style.configure("Treeview.Heading", background="#d9d9d9", foreground="black",
                        font=('Segoe UI', 10, 'bold'), height=30)

        columns = ("Идентификатор", "Наименование объекта", "Спецификация",
                   "CWE", "CVE", "CVSS V2", "CVSS V3", "CVSS V4")

        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=25, selectmode="browse")

        for col in columns:
            self.tree.heading(col, text=col)

        self.tree.column("Идентификатор", width=140, anchor='center')
        self.tree.column("Наименование объекта", width=220, anchor='w')
        self.tree.column("Спецификация", width=280, anchor='w')
        self.tree.column("CWE", width=90, anchor='center')
        self.tree.column("CVE", width=150, anchor='center')
        self.tree.column("CVSS V2", width=80, anchor='center')
        self.tree.column("CVSS V3", width=80, anchor='center')
        self.tree.column("CVSS V4", width=80, anchor='center')

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure('section_header', background='#e0e0e0', font=('Segoe UI', 10, 'bold'))
        self.tree.tag_configure('component_header', background='#f5f5f5', font=('Segoe UI', 10, 'bold'))

    def populate_table(self, passport_data: List[Dict], total_vulnerabilities: int):
        """Заполняет таблицу данными."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not passport_data:
            self.tree.insert("", tk.END, values=("—", "Нет данных", "Компоненты не найдены", "—", "—", "—", "—", "—"))
            self.status_label.configure(text="ℹ️ Нет данных для анализа", text_color="gray")
            self.count_label.configure(text="(0)")
            return

        for section in passport_data:
            self.tree.insert("", tk.END, values=("", section["title"], "", "", "", "", "", ""),
                             tags=('section_header',))

            for item in section["items"]:
                if item.get("is_header"):
                    self.tree.insert("", tk.END, values=(
                        item.get('identifier', ''),
                        item.get('component_type', ''),
                        item.get('component_name', ''),
                        f"🔍 Уязвимостей: {item.get('cves_count', 0)}",
                        "", "", "", ""
                    ), tags=('component_header',))
                else:
                    self.tree.insert("", tk.END, values=(
                        "", "", "",
                        item.get('cwe', '--'),
                        item.get('cve', '--'),
                        item.get('cvss_v2', '--'),
                        item.get('cvss_v3', '--'),
                        item.get('cvss_v4', '--')
                    ))

        if total_vulnerabilities > 0:
            self.status_label.configure(text=f"⚠️ Найдено уязвимостей: {total_vulnerabilities}", text_color="red")
        else:
            self.status_label.configure(text="✅ Уязвимостей не найдено", text_color="green")

        self.count_label.configure(text=f"({total_vulnerabilities})")

    def create_capec_table(self, parent):
        """Создаёт таблицу паттернов атак CAPEC."""
        style = ttk.Style()

        style.configure("Capec.Treeview", background="white", foreground="black",
                        fieldbackground="white", font=('Segoe UI', 10), rowheight=sp(28))
        style.configure("Capec.Treeview.Heading", background="#d9d9d9", foreground="black",
                        font=('Segoe UI', 10, 'bold'), height=30)

        columns = ("CAPEC ID", "Название атаки", "Уровень", "Серьёзность",
                   "Вероятность", "Связанные CWE", "Описание")

        self.capec_tree = ttk.Treeview(parent, columns=columns, show="headings",
                                        height=10, selectmode="browse", style="Capec.Treeview")

        for col in columns:
            self.capec_tree.heading(col, text=col)

        self.capec_tree.column("CAPEC ID", width=90, anchor='center')
        self.capec_tree.column("Название атаки", width=280, anchor='w')
        self.capec_tree.column("Уровень", width=90, anchor='center')
        self.capec_tree.column("Серьёзность", width=100, anchor='center')
        self.capec_tree.column("Вероятность", width=100, anchor='center')
        self.capec_tree.column("Связанные CWE", width=130, anchor='center')
        self.capec_tree.column("Описание", width=400, anchor='w')

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.capec_tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.capec_tree.xview)
        self.capec_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.capec_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)

        # Цвета по severity
        self.capec_tree.tag_configure('severity_vh', background='#FFCDD2')  # Very High — красный
        self.capec_tree.tag_configure('severity_h', background='#FFE0B2')   # High — оранжевый
        self.capec_tree.tag_configure('severity_m', background='#FFF9C4')   # Medium — жёлтый
        self.capec_tree.tag_configure('severity_l', background='#C8E6C9')   # Low — зелёный
        self.capec_tree.tag_configure('severity_vl', background='#E0E0E0')  # Very Low — серый

    def populate_capec_table(self, capec_data: List[Dict]):
        """Заполняет таблицу CAPEC."""
        for item in self.capec_tree.get_children():
            self.capec_tree.delete(item)

        if not capec_data:
            self.capec_tree.insert("", tk.END, values=(
                "—", "Паттерны атак не найдены", "—", "—", "—", "—", "—"))
            self.capec_status_label.configure(text="ℹ️ CAPEC не найдены", text_color="gray")
            self.capec_count_label.configure(text="(0)")
            return

        severity_tags = {
            "Very High": "severity_vh", "High": "severity_h",
            "Medium": "severity_m", "Low": "severity_l", "Very Low": "severity_vl"
        }

        for entry in capec_data:
            cwe_str = ", ".join(f"CWE-{c}" for c in entry["cwe_ids"])
            tag = severity_tags.get(entry["severity"], "")
            # Обрезаем описание для таблицы
            desc = entry["description"]
            if len(desc) > 150:
                desc = desc[:147] + "..."

            self.capec_tree.insert("", tk.END, values=(
                f"CAPEC-{entry['capec_id']}",
                entry["name"],
                entry["abstraction"],
                entry["severity"] or "—",
                entry["likelihood"] or "—",
                cwe_str,
                desc
            ), tags=(tag,) if tag else ())

        total = len(capec_data)
        self.capec_count_label.configure(text=f"({total})")
        self.capec_status_label.configure(
            text=f"⚠️ Найдено паттернов атак: {total}", text_color="#E65100")

    def export_to_pdf(self):
        """Экспортирует паспорт безопасности в PDF (через reportlab).

        Структура документа:
        - Заголовок с названием узла и датой
        - Сводка (тип узла, число уязвимостей)
        - Таблица: повторяет табличное представление на экране,
          включая строки-заголовки секций и компонентов.
        - Поддержка кириллицы через шрифт DejaVuSans / Segoe UI, который
          регистрируется в pdfmetrics. Если системный шрифт не найден,
          используется встроенный Helvetica (кириллица может не отрисоваться).
        """
        try:
            from tkinter import filedialog
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            )
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont
        except ImportError:
            messagebox.showerror(
                "Нет библиотеки reportlab",
                "Для экспорта в PDF требуется reportlab.\n"
                "Установите: pip install reportlab"
            )
            return

        # Собираем данные с отображаемой Treeview
        rows = []
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            tags = self.tree.item(item).get('tags') or ()
            rows.append((tags, [("" if v is None else str(v)) for v in values]))

        # Убираем пустую заглушку "Нет данных"
        rows = [r for r in rows if not (r[1][1] == "Нет данных")]

        if not rows:
            messagebox.showwarning("Нет данных", "Нет данных для экспорта в PDF.")
            return

        # Диалог выбора файла
        default_name = f"Паспорт_безопасности_{self.node.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filename = filedialog.asksaveasfilename(
            parent=self.dialog,
            title="Сохранить паспорт безопасности в PDF",
            defaultextension=".pdf",
            initialfile=default_name,
            filetypes=[("PDF файлы", "*.pdf")]
        )
        if not filename:
            return

        # Регистрация шрифта с поддержкой кириллицы
        font_name = "Helvetica"
        font_bold = "Helvetica-Bold"
        candidates = [
            ("DejaVuSans", "DejaVuSans.ttf"),
            ("DejaVuSans", "DejaVuSans-Bold.ttf"),
            ("Segoe UITT", r"C:\Windows\Fonts\arial.ttf"),
            ("Segoe UITT-Bold", r"C:\Windows\Fonts\arialbd.ttf"),
        ]
        registered = {}
        for name, path in candidates:
            if os.path.exists(path) and name not in registered:
                try:
                    pdfmetrics.registerFont(TTFont(name, path))
                    registered[name] = True
                except Exception:
                    pass

        if "Segoe UITT" in registered:
            font_name = "Segoe UITT"
            font_bold = "Segoe UITT-Bold" if "Segoe UITT-Bold" in registered else "Segoe UITT"
        elif "DejaVuSans" in registered:
            font_name = "DejaVuSans"
            font_bold = "DejaVuSans"

        # Настраиваем документ (альбомный A4 — под широкую таблицу)
        doc = SimpleDocTemplate(
            filename,
            pagesize=landscape(A4),
            leftMargin=10 * mm,
            rightMargin=10 * mm,
            topMargin=12 * mm,
            bottomMargin=12 * mm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleRu", parent=styles["Heading1"],
            fontName=font_bold, fontSize=18, leading=22,
            textColor=colors.HexColor("#1565C0"),
        )
        subtitle_style = ParagraphStyle(
            "SubRu", parent=styles["Normal"],
            fontName=font_name, fontSize=11, leading=14,
            textColor=colors.HexColor("#555555"),
        )
        body_style = ParagraphStyle(
            "BodyRu", parent=styles["Normal"],
            fontName=font_name, fontSize=9, leading=11,
        )

        story = []

        # Заголовок
        story.append(Paragraph("Паспорт безопасности", title_style))
        story.append(Paragraph(
            f"Узел: <b>{self.node.name}</b> ({self.get_node_type_russian(self.node.type)})",
            subtitle_style
        ))
        story.append(Paragraph(
            f"Дата формирования: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            subtitle_style
        ))

        # Подсчёт общего числа CVE
        total_cves = sum(
            1 for tags, v in rows
            if not ("section_header" in tags or "component_header" in tags)
            and v[4] and v[4] != "--"
        )
        story.append(Paragraph(
            f"Всего найдено уязвимостей: <b>{total_cves}</b>",
            subtitle_style
        ))
        story.append(Spacer(1, 8 * mm))

        # Таблица
        headers = [
            "Идентификатор", "Наименование объекта", "Спецификация",
            "CWE", "CVE", "CVSS V2", "CVSS V3", "CVSS V4"
        ]
        table_data = [[Paragraph(h, ParagraphStyle(
            "HeadRu", fontName=font_bold, fontSize=9, textColor=colors.white, alignment=1
        )) for h in headers]]

        # Маркируем строки, чтобы назначить стили
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#455A64")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), font_name),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CCCCCC")),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]

        for idx, (tags, values) in enumerate(rows, start=1):
            # Оборачиваем длинный текст в Paragraph, чтобы reportlab переносил
            wrapped = [Paragraph(v or "", body_style) for v in values]
            table_data.append(wrapped)

            if "section_header" in tags:
                style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), colors.HexColor("#CFD8DC")))
                style_cmds.append(("FONTNAME", (0, idx), (-1, idx), font_bold))
            elif "component_header" in tags:
                style_cmds.append(("BACKGROUND", (0, idx), (-1, idx), colors.HexColor("#ECEFF1")))
                style_cmds.append(("FONTNAME", (0, idx), (-1, idx), font_bold))

        # Ширина колонок — подбираем под альбомный A4 (≈ 277 мм полезной ширины)
        col_widths = [
            28 * mm,  # Идентификатор
            50 * mm,  # Наименование
            65 * mm,  # Спецификация
            22 * mm,  # CWE
            38 * mm,  # CVE
            18 * mm,  # V2
            18 * mm,  # V3
            18 * mm,  # V4
        ]

        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle(style_cmds))
        story.append(table)

        try:
            doc.build(story)
            messagebox.showinfo(
                "Экспорт завершён",
                f"Паспорт безопасности сохранён в файл:\n{filename}"
            )
        except Exception as e:
            messagebox.showerror("Ошибка экспорта", f"Не удалось создать PDF:\n{e}")

    def refresh_data(self):
        """Обновляет данные. Полностью сбрасывает кеш CVE для этого узла."""
        # Полная инвалидация кеша — запрос к базе CVE пойдёт заново
        self.node.properties.pop("security_passport_cache", None)
        for widget in self.dialog.winfo_children():
            widget.destroy()
        self.show_loading_screen()
        self.dialog.after(100, self.load_security_data_async)