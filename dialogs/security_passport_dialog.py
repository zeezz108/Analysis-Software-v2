"""
Модуль диалога паспорта безопасности

Содержит класс SecurityPassportDialog для отображения уязвимостей узла
на основе базы данных CVE.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import time
from datetime import datetime
import pandas as pd
from typing import List, Dict, Any, Optional

from models.node import Node
from database.cve_db import CVEDatabase
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

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Паспорт безопасности: {node.name}")
        self.dialog.geometry("1600x900")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

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
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'{width}x{height}+{x}+{y}')

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
            font=("Arial", 22, "bold")
        ).pack(pady=(0, 30))

        self.animation_label = ctk.CTkLabel(
            content_frame, text="🔍",
            font=("Arial", 72, "bold"), text_color="#1E88E5"
        )
        self.animation_label.pack(pady=20)

        self.status_label = ctk.CTkLabel(
            content_frame, text="Анализ компонентов узла...",
            font=("Arial", 14), text_color="gray"
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
        """Возвращает все CVE для компонента."""
        try:
            if not component_name or component_name == "—":
                return []

            all_cves = []
            cpe_info = extract_cpe_components(component_name)

            if cpe_info.get('vendor'):
                cve_list = self.db.get_cves_for_component(
                    vendor=cpe_info['vendor'],
                    product=cpe_info['product']
                )
                all_cves.extend(cve_list)

            if not all_cves:
                keywords = component_name.lower().split()[:3]
                for keyword in keywords:
                    if len(keyword) > 3:
                        cve_list = self.db.get_cves_by_cpe_mask(keyword)
                        all_cves.extend(cve_list)
                        if len(all_cves) >= 20:
                            break

            # Убираем дубликаты
            seen_cves = set()
            unique_cves = []
            for cve in all_cves:
                cve_id = cve.get('cve_id', '')
                if cve_id and cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    unique_cves.append(cve)

            return unique_cves
        except Exception as e:
            print(f"Ошибка поиска CVE для {component_name}: {e}")
            return []

    def build_dynamic_passport(self, components: Dict) -> List[Dict]:
        """Строит динамический паспорт безопасности."""
        passport_data = []

        # ===== 1. Аппаратный уровень (порты) =====
        if components["ports"]:
            ports_items = []
            for i, port in enumerate(components["ports"], 1):
                port_type = port["type"]

                if port_type == "ethernet":
                    identifier = f"*f*~1.1.{i}~/а~14.{i}~"
                    comp_type = "Порт 802.3/разъем RJ-45"
                    comp_name = "cat.5e TWT TWT--PL45--8P8C--5E"
                elif port_type == "pon":
                    identifier = f"*f*~1.2.{i}~/а~15.{i}~"
                    comp_type = "Порт/разъем RJ-11"
                    comp_name = "6P2C"
                elif port_type == "wifi":
                    identifier = f"*f*~1.3.{i}~/а~16.{i}~"
                    comp_type = "Порт 802.11/разъем 'антенна' Wi-Fi"
                    comp_name = "Wi-Fi 6E"
                else:
                    continue

                spec_parts = []
                if port["mac"]:
                    spec_parts.append(f"MAC: {port['mac']}")
                if port["ip"]:
                    spec_parts.append(f"IP: {port['ip']}/{port['mask']}")
                spec = "; ".join(spec_parts)

                all_cves = self.get_all_cves_for_component(port_type)

                ports_items.append({
                    "is_header": True,
                    "identifier": identifier,
                    "component_type": comp_type,
                    "component_name": comp_name,
                    "spec": spec,
                    "cves_count": len(all_cves)
                })

                if all_cves:
                    for cve_data in all_cves[:5]:
                        ports_items.append({
                            "is_header": False,
                            "cwe": cve_data.get('cwe_id', '--'),
                            "cve": cve_data.get('cve_id', '--'),
                            "cvss_v2": cve_data.get('cvss_v2', '--'),
                            "cvss_v3": cve_data.get('cvss_v3', '--'),
                            "cvss_v4": cve_data.get('cvss_v4', '--')
                        })
                else:
                    ports_items.append({
                        "is_header": False, "cwe": "--", "cve": "--",
                        "cvss_v2": "--", "cvss_v3": "--", "cvss_v4": "--"
                    })

            if components["has_usb"]:
                usb_ports = [p for p in components["ports"] if p["type"] == "usb"]
                for i, port in enumerate(usb_ports, 1):
                    identifier = f"*f*~12.{i}~/а~19.{i}~"
                    all_cves = self.get_all_cves_for_component("USB")

                    ports_items.append({
                        "is_header": True, "identifier": identifier,
                        "component_type": "Порт/разъем USB",
                        "component_name": "USB 2.0 High-speed",
                        "spec": "", "cves_count": len(all_cves)
                    })

                    if all_cves:
                        for cve_data in all_cves[:5]:
                            ports_items.append({
                                "is_header": False,
                                "cwe": cve_data.get('cwe_id', 'CWE--787'),
                                "cve": cve_data.get('cve_id', 'CVE--2022--2964'),
                                "cvss_v2": cve_data.get('cvss_v2', '--'),
                                "cvss_v3": cve_data.get('cvss_v3', '7.8'),
                                "cvss_v4": cve_data.get('cvss_v4', '--')
                            })
                    else:
                        ports_items.append({
                            "is_header": False, "cwe": "CWE--787", "cve": "CVE--2022--2964",
                            "cvss_v2": "--", "cvss_v3": "7.8", "cvss_v4": "--"
                        })

            if ports_items:
                passport_data.append({
                    "title": "Аппаратный уровень (точки входа)",
                    "items": ports_items
                })

        # ===== 2. Аппаратные компоненты =====
        if components["hardware"]:
            hardware_items = []
            for item in components["hardware"]:
                if ":" in item:
                    comp_type, comp_name = item.split(":", 1)
                    comp_type = comp_type.strip()
                    comp_name = comp_name.strip()
                else:
                    comp_type = "Компонент"
                    comp_name = item

                if "Процессор" in comp_type:
                    identifier = "*а~1.m~"
                elif "Видеоконтроллер" in comp_type or "Видеокарта" in comp_type:
                    identifier = "*а~4.m~"
                elif "Материнская плата" in comp_type:
                    identifier = "*а~2.m~"
                elif "HDD" in comp_type or "SSD" in comp_type:
                    identifier = "*а~8.m~"
                elif "Память" in comp_type or "RAM" in comp_type:
                    identifier = "*а~7.m~"
                else:
                    identifier = "*а~?.m~"

                all_cves = self.get_all_cves_for_component(comp_name)

                hardware_items.append({
                    "is_header": True, "identifier": identifier,
                    "component_type": comp_type, "component_name": comp_name,
                    "spec": "", "cves_count": len(all_cves)
                })

                if all_cves:
                    for cve_data in all_cves[:5]:
                        hardware_items.append({
                            "is_header": False,
                            "cwe": cve_data.get('cwe_id', '--'),
                            "cve": cve_data.get('cve_id', '--'),
                            "cvss_v2": cve_data.get('cvss_v2', '--'),
                            "cvss_v3": cve_data.get('cvss_v3', '--'),
                            "cvss_v4": cve_data.get('cvss_v4', '--')
                        })
                else:
                    hardware_items.append({
                        "is_header": False, "cwe": "--", "cve": "--",
                        "cvss_v2": "--", "cvss_v3": "--", "cvss_v4": "--"
                    })

            if hardware_items:
                passport_data.append({
                    "title": "Аппаратный уровень (компоненты)",
                    "items": hardware_items
                })

        # ===== 3. Прикладной уровень =====
        if components["software"]:
            app_items = []
            for item in components["software"]:
                if ":" in item:
                    comp_type, comp_name = item.split(":", 1)
                    comp_type = comp_type.strip()
                    comp_name = comp_name.strip()
                else:
                    comp_type = "Прикладное ПО"
                    comp_name = item

                all_cves = self.get_all_cves_for_component(comp_name)

                app_items.append({
                    "is_header": True, "identifier": f"*q*~{comp_type}~",
                    "component_type": comp_type, "component_name": comp_name,
                    "spec": "", "cves_count": len(all_cves)
                })

                if all_cves:
                    for cve_data in all_cves[:5]:
                        app_items.append({
                            "is_header": False,
                            "cwe": cve_data.get('cwe_id', '--'),
                            "cve": cve_data.get('cve_id', '--'),
                            "cvss_v2": cve_data.get('cvss_v2', '--'),
                            "cvss_v3": cve_data.get('cvss_v3', '--'),
                            "cvss_v4": cve_data.get('cvss_v4', '--')
                        })
                else:
                    app_items.append({
                        "is_header": False, "cwe": "--", "cve": "--",
                        "cvss_v2": "--", "cvss_v3": "--", "cvss_v4": "--"
                    })

            if app_items:
                passport_data.append({
                    "title": "Прикладной уровень",
                    "items": app_items
                })

        # ===== 4. Периферия =====
        if components["peripherals"]:
            peripheral_items = []

            # Определяем тип периферии по ключевым словам
            def detect_peripheral_type(text: str) -> str:
                text_lower = text.lower()
                if any(k in text_lower for k in ["мышь", "mouse", "bloody", "zowie"]):
                    return "Мышь"
                elif any(k in text_lower for k in ["клавиатур", "keyboard", "key pad"]):
                    return "Клавиатура"
                elif any(k in text_lower for k in ["принтер", "printer", "мфу"]):
                    return "Принтер"
                elif any(k in text_lower for k in ["монитор", "monitor", "display", "экран", "дисплей", "lcd", "led"]):
                    return "Монитор"
                return "Периферийное устройство"

            # Идентификаторы для периферии
            peripheral_id_map = {
                "Мышь": "*p*~мш~",
                "Клавиатура": "*p*~кл~",
                "Принтер": "*p*~пр~",
                "Монитор": "*p*~мн~",
                "Периферийное устройство": "*p*~пу~"
            }

            for item in components["peripherals"]:
                if ":" in item:
                    comp_type, comp_name = item.split(":", 1)
                    comp_type = comp_type.strip()
                    comp_name = comp_name.strip()
                else:
                    comp_type = detect_peripheral_type(item)
                    comp_name = item

                # Если тип общий, уточняем по содержимому
                if comp_type in ("Периферия", "Компонент"):
                    comp_type = detect_peripheral_type(comp_name)

                identifier = peripheral_id_map.get(comp_type, "*p*~пу~")
                all_cves = self.get_all_cves_for_component(comp_name)

                peripheral_items.append({
                    "is_header": True, "identifier": identifier,
                    "component_type": comp_type, "component_name": comp_name,
                    "spec": "", "cves_count": len(all_cves)
                })

                if all_cves:
                    for cve_data in all_cves[:5]:
                        peripheral_items.append({
                            "is_header": False,
                            "cwe": cve_data.get('cwe_id', '--'),
                            "cve": cve_data.get('cve_id', '--'),
                            "cvss_v2": cve_data.get('cvss_v2', '--'),
                            "cvss_v3": cve_data.get('cvss_v3', '--'),
                            "cvss_v4": cve_data.get('cvss_v4', '--')
                        })
                else:
                    peripheral_items.append({
                        "is_header": False, "cwe": "--", "cve": "--",
                        "cvss_v2": "--", "cvss_v3": "--", "cvss_v4": "--"
                    })

            if peripheral_items:
                passport_data.append({
                    "title": "Пользовательский уровень",
                    "items": peripheral_items
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

                passport_data = self.build_dynamic_passport(components)

                total_vulnerabilities = 0
                for section in passport_data:
                    for item in section["items"]:
                        if not item.get("is_header") and item.get('cve', '--') != '--':
                            total_vulnerabilities += 1

                self.dialog.after(0, lambda: self.progress.set(0.9))
                self.dialog.after(0, lambda: self.status_label.configure(text="Формирование отчета..."))

                self.dialog.after(0, lambda: self.finish_loading(total_vulnerabilities, passport_data))

            except Exception as e:
                self.dialog.after(0, lambda: self.show_load_error(str(e)))

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

        # Заголовок
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 20))

        ctk.CTkLabel(title_frame, text="📋", font=("Arial", 36), text_color="#1E88E5").pack(side=tk.LEFT, padx=(0, 10))

        header_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        header_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ctk.CTkLabel(header_frame, text="Паспорт безопасности", font=("Arial", 22, "bold")).pack(anchor=tk.W)
        ctk.CTkLabel(
            header_frame, text=f"{self.node.name} • {self.get_node_type_russian(self.node.type)}",
            font=("Arial", 13), text_color="gray"
        ).pack(anchor=tk.W)

        # Таблица
        table_card = ctk.CTkFrame(main_frame)
        table_card.pack(fill=tk.BOTH, expand=True)

        table_header = ctk.CTkFrame(table_card, fg_color="transparent")
        table_header.pack(fill=tk.X, padx=15, pady=(10, 5))

        ctk.CTkLabel(table_header, text="🔍 Найденные уязвимости", font=("Arial", 15, "bold")).pack(side=tk.LEFT)

        self.count_label = ctk.CTkLabel(table_header, text="", font=("Arial", 13), text_color="gray")
        self.count_label.pack(side=tk.LEFT, padx=(10, 0))

        self.status_label = ctk.CTkLabel(table_header, text="", font=("Arial", 12), text_color="gray")
        self.status_label.pack(side=tk.RIGHT)

        table_container = ctk.CTkFrame(table_card)
        table_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.create_vulnerabilities_table(table_container)

        # Кнопки
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill=tk.X, pady=(20, 0))

        left_buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        left_buttons.pack(side=tk.LEFT)

        ctk.CTkButton(left_buttons, text="📥 Экспорт в CSV", command=self.export_to_csv, width=130, height=38).pack(
            side=tk.LEFT, padx=5)
        ctk.CTkButton(left_buttons, text="🔄 Обновить", command=self.refresh_data, width=110, height=38).pack(
            side=tk.LEFT, padx=5)

        right_buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        right_buttons.pack(side=tk.RIGHT)

        ctk.CTkButton(right_buttons, text="✕ Закрыть", command=self.dialog.destroy, width=110, height=38,
                      fg_color="#F44336").pack(side=tk.RIGHT, padx=5)

        self.center_window()

    def create_vulnerabilities_table(self, parent):
        """Создаёт таблицу с уязвимостями."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Treeview", background="white", foreground="black",
                        fieldbackground="white", font=('Arial', 10), rowheight=28)
        style.configure("Treeview.Heading", background="#d9d9d9", foreground="black",
                        font=('Arial', 10, 'bold'), height=30)

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

        self.tree.tag_configure('section_header', background='#e0e0e0', font=('Arial', 10, 'bold'))
        self.tree.tag_configure('component_header', background='#f5f5f5', font=('Arial', 10, 'bold'))

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

    def export_to_csv(self):
        """Экспортирует данные в CSV."""
        data = []
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            if values[0] != "" or values[1] != "Нет данных":
                data.append(values)

        if data:
            df = pd.DataFrame(data, columns=["Идентификатор", "Наименование объекта", "Спецификация",
                                             "CWE", "CVE", "CVSS V2.0", "CVSS V3.1", "CVSS V4.0"])
            filename = f"Паспорт_безопасности_{self.node.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(filename, index=False, encoding='utf-8-sig')
            messagebox.showinfo("Экспорт завершен", f"Данные экспортированы в файл:\n{filename}")
        else:
            messagebox.showwarning("Нет данных", "Нет данных для экспорта")

    def refresh_data(self):
        """Обновляет данные."""
        for widget in self.dialog.winfo_children():
            widget.destroy()
        self.show_loading_screen()
        self.dialog.after(100, self.load_security_data_async)