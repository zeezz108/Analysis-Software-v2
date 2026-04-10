"""
Модуль диалога создания/редактирования узла

Содержит классы:
- NodeTypeSelectionDialog: Диалог выбора типа узла
- NodeCreationDialog: Основной диалог создания/редактирования узла
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import time
import uuid
from typing import Dict, List, Optional, Any, Tuple

from models.zone import Zone
from models.node import Node, VirtualMachine
from database.cve_db import CVEDatabase
from utils.cache import DataCache
from utils.validators import validate_ip, validate_mac, validate_mask, validate_vlan_id
from utils.generators import uid, generate_test_ip, generate_test_mac, generate_test_mask
from config.node_config import NODE_CONFIG, get_node_type_english


# ============================================================================
# ДИАЛОГ ВЫБОРА ТИПА УЗЛА
# ============================================================================

class NodeTypeSelectionDialog:
    """Диалог выбора типа узла перед созданием."""

    def __init__(self, parent, board=None):
        self.parent = parent
        self.board = board  # может быть None
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Выбор типа узла")
        self.dialog.geometry("450x500")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.create_widgets()
        self.center_window()

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

    def create_widgets(self):
        temp_frame = ctk.CTkFrame(self.dialog)
        frame_color = temp_frame.cget("fg_color")
        temp_frame.destroy()
        self.dialog.configure(fg_color=frame_color)

        # Заголовок
        ctk.CTkLabel(
            self.dialog,
            text="Выберите тип создаваемого узла",
            font=("Arial", 18, "bold")
        ).pack(pady=(25, 20))

        # Переменная для хранения выбранного типа
        self.node_type_var = tk.StringVar(value="АРМ")

        # Список типов узлов
        node_types = [
            ("АРМ (автоматизированное рабочее место)", "АРМ"),
            ("Ноутбук", "Ноутбук"),
            ("Маршрутизатор", "Маршрутизатор"),
            ("Коммутатор", "Коммутатор"),
            ("Сервер", "Сервер"),
            ("Сервер виртуализации", "Сервер виртуализации"),
            ("Интернет", "Интернет")
        ]

        for display_text, value in node_types:
            rb = ctk.CTkRadioButton(
                self.dialog,
                text=display_text,
                variable=self.node_type_var,
                value=value,
                font=("Arial", 13),
                height=35
            )
            rb.pack(anchor=tk.W, pady=5, padx=30)

        # Фрейм для кнопок
        button_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        button_frame.pack(fill=tk.X, pady=(25, 20), padx=20)

        ctk.CTkButton(
            button_frame,
            text="Далее →",
            command=self.select_type,
            fg_color="#1E88E5",
            width=120,
            height=38,
            font=("Arial", 13, "bold")
        ).pack(side=tk.RIGHT, padx=5)

        ctk.CTkButton(
            button_frame,
            text="Отмена",
            command=self.dialog.destroy,
            fg_color="#CD3333",
            width=100,
            height=38,
            font=("Arial", 13)
        ).pack(side=tk.RIGHT, padx=5)

        self.dialog.bind("<Return>", lambda e: self.select_type())
        self.dialog.bind("<Escape>", lambda e: self.dialog.destroy())

    def select_type(self):
        self.result = self.node_type_var.get()
        self.dialog.destroy()

# ============================================================================
# ОСНОВНОЙ ДИАЛОГ СОЗДАНИЯ/РЕДАКТИРОВАНИЯ УЗЛА
# ============================================================================

class NodeCreationDialog:
    """Основной диалог создания/редактирования узла."""

    def __init__(self, parent, board, node_type=None, existing_node=None):
        self.parent = parent
        self.board = board
        self.preselected_type = node_type
        self.existing_node = existing_node
        self.is_edit_mode = existing_node is not None

        self.result = None
        self.current_ports = []
        self.port_vars = {}
        self.wifi_role_vars = {}
        self.cached_data = {}
        self.ports_cache = {}
        self.cache = DataCache()
        self.loading_active = False

        # Для существующих данных
        self.existing_hardware = {}
        self.existing_software = {}
        self.existing_zone_id = None
        self.virtualization_subtype = "hypervisor"

        # Подключаемся к БД
        try:
            self.db = CVEDatabase()
        except FileNotFoundError as e:
            messagebox.showerror("Ошибка", str(e))
            raise

        # Создаём окно
        self.dialog = ctk.CTkToplevel(parent)
        title = "Редактирование узла" if self.is_edit_mode else "Создание нового узла"
        self.dialog.title(title)
        self.dialog.geometry("1100x850")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Загружаем данные существующего узла
        if self.is_edit_mode:
            self.load_existing_node_data()

        # Если кеш уже загружен — сразу создаём виджеты, без экрана загрузки
        if self.cache.is_loaded():
            self._fill_cached_data_for_current_type()
            self.finish_loading()
        else:
            self.show_loading_screen()
            self.dialog.after(100, self.load_data_async)

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

    # ========================================================================
    # ЗАГРУЗКА ДАННЫХ
    # ========================================================================

    def load_existing_node_data(self):
        """Загружает данные из существующего узла для редактирования."""
        if not self.existing_node:
            return

        node_type_mapping = {
            "ARM": "АРМ", "Laptop": "Ноутбук", "Router": "Маршрутизатор",
            "Switch": "Коммутатор", "Server": "Сервер",
            "VirtualizationServer": "Сервер виртуализации", "Internet": "Интернет",
        }

        self.preselected_type = node_type_mapping.get(self.existing_node.type, "АРМ")
        self.existing_zone_id = self.existing_node.zone.id
        self.current_ports = [port.copy() for port in self.existing_node.ports]

        # Сохраняем выбранные значения аппаратных компонентов
        for item in self.existing_node.properties.get("hardware", []):
            if item.startswith("Процессор:"):
                self.existing_hardware["processor"] = item.replace("Процессор:", "").strip()
            elif "Видеоконтроллер" in item or "Видеокарта" in item:
                self.existing_hardware["gpu"] = item.split(":", 1)[1].strip()
            elif item.startswith("Материнская плата:"):
                self.existing_hardware["motherboard"] = item.replace("Материнская плата:", "").strip()
            elif item.startswith("HDD/SSD:"):
                self.existing_hardware["hdd"] = item.replace("HDD/SSD:", "").strip()
            elif item.startswith("Аппаратная платформа:"):
                self.existing_hardware["router_platform"] = item.replace("Аппаратная платформа:", "").strip()
            elif item.startswith("Оперативная память:"):
                self.existing_hardware["server_ram"] = item.replace("Оперативная память:", "").strip()
            elif item.startswith("Сетевая карта:"):
                if "server_nics" not in self.existing_hardware:
                    self.existing_hardware["server_nics"] = []
                self.existing_hardware["server_nics"].append(item.replace("Сетевая карта:", "").strip())

        for item in self.existing_node.properties.get("software", []):
            if item.startswith("ОС:"):
                self.existing_software["os"] = item.replace("ОС:", "").strip()
            elif item.startswith("Гипервизор:"):
                hypervisor = item.replace("Гипервизор:", "").strip().lower()
                if "vmware" in hypervisor:
                    self.existing_software["vmware"] = hypervisor
                elif "hyper-v" in hypervisor:
                    self.existing_software["hyperv"] = hypervisor
                elif "proxmox" in hypervisor:
                    self.existing_software["proxmox"] = hypervisor
            elif item.startswith("Приложение:"):
                if "app_software" not in self.existing_software:
                    self.existing_software["app_software"] = []
                self.existing_software["app_software"].append(item.replace("Приложение:", "").strip())

    def get_current_selection_for_tab(self, tab_config):
        """Возвращает текущее выбранное значение для вкладки."""
        var_name = tab_config["var_name"]

        if tab_config.get("multiple", False):
            if var_name == "server_cpus":
                return [self.existing_hardware.get("server_cpu", "")] if self.existing_hardware.get(
                    "server_cpu") else []
            elif var_name == "server_storage":
                return [self.existing_hardware.get("server_storage", "")] if self.existing_hardware.get(
                    "server_storage") else []
            elif var_name == "server_nics":
                return self.existing_hardware.get("server_nics", [])
            elif var_name == "app_software":
                return self.existing_software.get("app_software", [])
            return []

        value_map = {
            "processor": self.existing_hardware.get("processor", ""),
            "gpu": self.existing_hardware.get("gpu", ""),
            "motherboard": self.existing_hardware.get("motherboard", ""),
            "hdd": self.existing_hardware.get("hdd", ""),
            "server_ram": self.existing_hardware.get("server_ram", ""),
            "router_platform": self.existing_hardware.get("router_platform", ""),
            "os": self.existing_software.get("os", ""),
            "server_os": self.existing_software.get("os", ""),
            "vmware": self.existing_software.get("vmware", ""),
            "hyperv": self.existing_software.get("hyperv", ""),
        }
        return value_map.get(var_name, "")

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
            content_frame, text="Загрузка конфигураций...",
            font=("Arial", 22, "bold")
        ).pack(pady=(0, 30))

        self.animation_label = ctk.CTkLabel(
            content_frame, text="⏳", font=("Arial", 72, "bold"), text_color="#2196F3"
        )
        self.animation_label.pack(pady=20)

        self.status_label_loading = ctk.CTkLabel(
            content_frame, text="Подготовка данных для выбранного типа узла...",
            font=("Arial", 14), text_color="gray"
        )
        self.status_label_loading.pack(pady=(0, 20))

        self.progress = ctk.CTkProgressBar(content_frame, width=450)
        self.progress.pack(pady=15)
        self.progress.set(0)

        if self.preselected_type:
            ctk.CTkLabel(
                content_frame, text=f"Тип узла: {self.preselected_type}",
                font=("Arial", 16, "bold")
            ).pack(pady=(30, 0))

        self.loading_active = True
        self.animate_loading(0)

    def animate_loading(self, idx):
        """Анимация загрузки."""
        if self.loading_active:
            chars = ["⏳", "⌛", "⏳", "⌛"]
            colors = ["#2196F3", "#FF9800", "#4CAF50", "#F44336"]
            try:
                if hasattr(self, 'animation_label') and self.animation_label.winfo_exists():
                    self.animation_label.configure(
                        text=chars[idx % len(chars)],
                        text_color=colors[idx % len(colors)]
                    )
                    self.dialog.after(150, lambda: self.animate_loading(idx + 1))
            except:
                pass

    def load_data_async(self):
        """Асинхронная загрузка данных из БД."""

        def load_thread():
            try:
                if self.cache.is_loaded():
                    # Даже если кэш загружен, нужно заполнить cached_data для текущего типа
                    self._fill_cached_data_for_current_type()
                    self.dialog.after(0, self.finish_loading)
                    return

                # Загружаем данные для ВСЕХ типов узлов (как при создании)
                for node_type, config in NODE_CONFIG.items():
                    self.cached_data[node_type] = {}

                    for tab_config in config.get("hardware_tabs", []):
                        cache_key = f"{node_type}_{tab_config['var_name']}"
                        method = getattr(self.db, tab_config["method"], None)
                        if method:
                            items = self.cache.get(cache_key, method)
                            self.cached_data[node_type][tab_config["var_name"]] = items

                    for tab_config in config.get("software_tabs", []):
                        cache_key = f"{node_type}_{tab_config['var_name']}"
                        method = getattr(self.db, tab_config["method"], None)
                        if method:
                            items = self.cache.get(cache_key, method)
                            self.cached_data[node_type][tab_config["var_name"]] = items

                    for tab_config in config.get("hypervisor_tabs", []):
                        cache_key = f"{node_type}_{tab_config['var_name']}"
                        method = getattr(self.db, tab_config["method"], None)
                        if method:
                            items = self.cache.get(cache_key, method)
                            self.cached_data[node_type][tab_config["var_name"]] = items

                    for tab_config in config.get("peripheral_tabs", []):
                        cache_key = f"{node_type}_{tab_config['var_name']}"
                        method = getattr(self.db, tab_config["method"], None)
                        if method:
                            items = self.cache.get(cache_key, method)
                            self.cached_data[node_type][tab_config["var_name"]] = items

                self.cache.set_loaded()
                self.dialog.after(0, self.finish_loading)

            except Exception as e:
                self.dialog.after(0, lambda: self.show_load_error(str(e)))

        thread = threading.Thread(target=load_thread, daemon=True)
        thread.start()

    def _fill_cached_data_for_current_type(self):
        """Заполняет cached_data для текущего типа узла из уже загруженного кэша."""
        current_display_name = self.preselected_type if self.preselected_type else "АРМ"

        # Находим ключ типа узла
        current_node_type = None
        for node_type, config in NODE_CONFIG.items():
            if config["name"] == current_display_name:
                current_node_type = node_type
                break

        if not current_node_type:
            current_node_type = "ARM"

        # Если cached_data для этого типа ещё не заполнена, заполняем из кэша
        if current_node_type not in self.cached_data:
            self.cached_data[current_node_type] = {}

            config = NODE_CONFIG.get(current_node_type, NODE_CONFIG["ARM"])

            for tab_config in config.get("hardware_tabs", []):
                cache_key = f"{current_node_type}_{tab_config['var_name']}"
                if self.cache.has_key(cache_key):
                    self.cached_data[current_node_type][tab_config["var_name"]] = self.cache[cache_key]

            for tab_config in config.get("software_tabs", []):
                cache_key = f"{current_node_type}_{tab_config['var_name']}"
                if self.cache.has_key(cache_key):
                    self.cached_data[current_node_type][tab_config["var_name"]] = self.cache[cache_key]

            for tab_config in config.get("hypervisor_tabs", []):
                cache_key = f"{current_node_type}_{tab_config['var_name']}"
                if self.cache.has_key(cache_key):
                    self.cached_data[current_node_type][tab_config["var_name"]] = self.cache[cache_key]

            for tab_config in config.get("peripheral_tabs", []):
                cache_key = f"{current_node_type}_{tab_config['var_name']}"
                if self.cache.has_key(cache_key):
                    self.cached_data[current_node_type][tab_config["var_name"]] = self.cache[cache_key]

    def finish_loading(self):
        """Завершает загрузку и создаёт интерфейс."""
        self.loading_active = False

        # Убеждаемся, что cached_data для текущего типа заполнена
        self._fill_cached_data_for_current_type()

        try:
            if hasattr(self, 'progress') and self.progress.winfo_exists():
                self.progress.set(1.0)
        except:
            pass
        self.dialog.after(300, self.destroy_loading_and_create_widgets)

    def destroy_loading_and_create_widgets(self):
        try:
            if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
                self.loading_frame.destroy()
        except:
            pass
        try:
            if self.dialog.winfo_exists():
                self.create_widgets()
        except:
            pass

    def show_load_error(self, error_msg):
        self.loading_active = False
        messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить данные:\n{error_msg}")
        try:
            if self.dialog.winfo_exists():
                self.dialog.destroy()
        except:
            pass

    # ========================================================================
    # СОЗДАНИЕ ИНТЕРФЕЙСА
    # ========================================================================

    def create_widgets(self):
        """Создаёт основной интерфейс диалога."""
        temp_frame = ctk.CTkFrame(self.dialog)
        frame_color = temp_frame.cget("fg_color")
        temp_frame.destroy()
        self.dialog.configure(fg_color=frame_color)

        # Заголовок
        title_text = "Создание нового узла" if not self.is_edit_mode else f"Редактирование узла: {self.existing_node.name}"
        ctk.CTkLabel(
            self.dialog, text=title_text,
            font=("Arial", 18, "bold")
        ).pack(pady=(15, 10))

        # Имя узла
        name_frame = ctk.CTkFrame(self.dialog)
        name_frame.pack(fill=tk.X, padx=15, pady=(0, 10))

        ctk.CTkLabel(name_frame, text="Имя узла", font=("Arial", 14, "bold")).pack(anchor=tk.W, padx=10, pady=(5, 0))

        if not hasattr(self, 'node_name_var') or not self.node_name_var:
            self.node_name_var = tk.StringVar()
            if self.is_edit_mode and self.existing_node:
                self.node_name_var.set(self.existing_node.name)

        ctk.CTkEntry(name_frame, textvariable=self.node_name_var, height=35).pack(fill=tk.X, padx=10, pady=(5, 10))

        # Выбор зоны
        self.zone_frame = ctk.CTkFrame(self.dialog)
        self.zone_frame.pack(fill=tk.X, padx=15, pady=(0, 10))
        self.update_zone_frame()

        # Вкладки
        self.notebook = ctk.CTkTabview(self.dialog)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        self.update_tabs()

        # Кнопки
        button_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        button_frame.pack(fill=tk.X, padx=15, pady=(10, 15))

        ctk.CTkButton(
            button_frame, text="Сохранить" if self.is_edit_mode else "Создать",
            command=self.create_node, font=("Arial", 13, "bold"),
            fg_color="#4CAF50", width=120, height=38
        ).pack(side=tk.RIGHT, padx=5)

        ctk.CTkButton(
            button_frame, text="Отмена", command=self.dialog.destroy,
            fg_color="#CD3333", font=("Arial", 13), width=100, height=38
        ).pack(side=tk.RIGHT, padx=5)

        self.center_window()

    def update_zone_frame(self):
        """Обновляет фрейм выбора зоны."""
        for widget in self.zone_frame.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self.zone_frame, text="Выбор зоны для размещения:",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 10))

        current_type = self.preselected_type if self.preselected_type else "АРМ"
        target_zone_type = "free"

        for node_type, config in NODE_CONFIG.items():
            if config["name"] == current_type:
                target_zone_type = config["zone_type"]
                break

        if target_zone_type == "free":
            ctk.CTkLabel(
                self.zone_frame,
                text="🌐 Интернет-узел будет размещен в свободной зоне (вне зон TIM)",
                font=("Arial", 12)
            ).pack(anchor=tk.W, padx=10, pady=2)
        else:
            tim_zones = self.board.get_tim_zones()
            if tim_zones:
                default_zone_id = self.existing_zone_id if self.is_edit_mode else tim_zones[0].id
                self.zone_var = tk.StringVar(value=default_zone_id)

                for zone in tim_zones:
                    display_text = zone.get_display_text()
                    if zone.name:
                        display_text += f" - {zone.name}"

                    ctk.CTkRadioButton(
                        self.zone_frame, text=display_text,
                        variable=self.zone_var, value=zone.id, font=("Arial", 13)
                    ).pack(anchor=tk.W, padx=20, pady=3)
            else:
                ctk.CTkLabel(
                    self.zone_frame, text="❌ Сначала создайте зону TIM!",
                    font=("Arial", 12), text_color="red"
                ).pack(anchor=tk.W, padx=10, pady=5)

    def update_tabs(self):
        """Обновляет вкладки в зависимости от типа узла."""
        for tab in self.notebook._tab_dict.copy():
            self.notebook.delete(tab)

        current_display_name = self.preselected_type if self.preselected_type else "АРМ"

        # Находим конфигурацию
        current_node_type = None
        current_config = None

        for node_type, config in NODE_CONFIG.items():
            if config["name"] == current_display_name:
                current_config = config
                current_node_type = node_type
                break

        if not current_config:
            return

        self.current_node_type_key = current_node_type
        self.current_node_config = current_config

        # Создаём порты по умолчанию
        if not self.is_edit_mode and not self.current_ports:
            self.create_default_ports()

        # Добавляем вкладки
        if current_config.get("hardware_tabs"):
            self.notebook.add("Аппаратная архитектура")
            hw_frame = self.notebook.tab("Аппаратная архитектура")
            self.create_hardware_tabs(hw_frame, current_config["hardware_tabs"])

        if current_config.get("software_tabs"):
            self.notebook.add("Программное обеспечение")
            sw_frame = self.notebook.tab("Программное обеспечение")
            self.create_software_tabs(sw_frame, current_config["software_tabs"])

        if current_config.get("peripheral_tabs"):
            self.notebook.add("Периферия")
            per_frame = self.notebook.tab("Периферия")
            self.create_peripheral_tabs(per_frame, current_config["peripheral_tabs"])

        # Вкладка "Сеть" — не показываем для узла Интернет
        if current_node_type != "Internet":
            self.notebook.add("Сеть")
            net_frame = self.notebook.tab("Сеть")
            self.create_network_tab(net_frame, current_config)

    def create_default_ports(self):
        """Создаёт порты по умолчанию для текущего типа узла."""
        node_type_en = self.current_node_type_key

        if node_type_en in self.ports_cache:
            self.current_ports = [port.copy() for port in self.ports_cache[node_type_en]]
            return

        default_ports = self.current_node_config["default_ports"]
        wifi_caps = self.current_node_config.get("wifi_capabilities", {})

        self.current_ports = []

        # Ethernet порты
        for i in range(1, default_ports.get("ethernet", 0) + 1):
            self.current_ports.append({
                "port_id": f"eth_{i}_{uuid.uuid4().hex[:8]}",
                "port_type": "ethernet", "port_number": i, "name": f"ETH{i}",
                "ip_address": "", "mac_address": "", "subnet_mask": "",
                "vlan_id": None, "vlan_mode": "untagged",
                "connected_to": None, "connected_port": None
            })

        # PON порты
        for i in range(1, default_ports.get("pon", 0) + 1):
            self.current_ports.append({
                "port_id": f"pon_{i}_{uuid.uuid4().hex[:8]}",
                "port_type": "pon", "port_number": i, "name": f"PON{i}",
                "ip_address": "", "mac_address": "", "subnet_mask": "",
                "vlan_id": None, "vlan_mode": "untagged",
                "connected_to": None, "connected_port": None
            })

        # Wi-Fi порты
        for i in range(1, default_ports.get("wifi", 0) + 1):
            wifi_role = "ap" if wifi_caps.get("can_be_ap") else "client"
            self.current_ports.append({
                "port_id": f"wifi_{i}_{uuid.uuid4().hex[:8]}",
                "port_type": "wifi", "port_number": i, "name": f"WiFi{i}",
                "ip_address": "", "mac_address": "", "subnet_mask": "",
                "vlan_id": None, "vlan_mode": "untagged",
                "wifi_role": wifi_role, "connected_clients": [], "connected_to_ap": None
            })

        # USB порты
        for i in range(1, default_ports.get("usb", 0) + 1):
            self.current_ports.append({
                "port_id": f"usb_{i}_{uuid.uuid4().hex[:8]}",
                "port_type": "usb", "port_number": i, "name": f"USB{i}",
                "ip_address": "", "mac_address": "", "subnet_mask": "",
                "vlan_id": None, "vlan_mode": "untagged",
                "connected_to": None, "connected_port": None
            })

        self.ports_cache[node_type_en] = [port.copy() for port in self.current_ports]

    # ========================================================================
    # ВКЛАДКИ КОМПОНЕНТОВ
    # ========================================================================

    def create_hardware_tabs(self, parent, hardware_configs):
        """Создаёт вкладки аппаратного обеспечения."""
        if len(hardware_configs) > 1:
            tabview = ctk.CTkTabview(parent)
            tabview.pack(fill=tk.BOTH, expand=True)
            for config in hardware_configs:
                tabview.add(config["title"])
                frame = tabview.tab(config["title"])
                items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
                if config.get("multiple", False):
                    self.create_multi_select_combo(frame, config["title"], items, config["var_name"])
                else:
                    self.create_paginated_combo(frame, config["title"], items, config["var_name"])
        else:
            config = hardware_configs[0]
            items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
            if config.get("multiple", False):
                self.create_multi_select_combo(parent, config["title"], items, config["var_name"])
            else:
                self.create_paginated_combo(parent, config["title"], items, config["var_name"])

    def create_software_tabs(self, parent, software_configs):
        """Создаёт вкладки программного обеспечения."""
        if len(software_configs) > 1:
            tabview = ctk.CTkTabview(parent)
            tabview.pack(fill=tk.BOTH, expand=True)
            for config in software_configs:
                tabview.add(config["title"])
                frame = tabview.tab(config["title"])
                items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
                if config.get("multiple", False):
                    self.create_multi_select_combo(frame, config["title"], items, config["var_name"])
                else:
                    self.create_paginated_combo(frame, config["title"], items, config["var_name"])
        else:
            config = software_configs[0]
            items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
            if config.get("multiple", False):
                self.create_multi_select_combo(parent, config["title"], items, config["var_name"])
            else:
                self.create_paginated_combo(parent, config["title"], items, config["var_name"])

    def create_peripheral_tabs(self, parent, peripheral_configs):
        """Создаёт вкладки периферийных устройств."""
        if len(peripheral_configs) > 1:
            tabview = ctk.CTkTabview(parent)
            tabview.pack(fill=tk.BOTH, expand=True)
            for config in peripheral_configs:
                tabview.add(config["title"])
                frame = tabview.tab(config["title"])
                items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
                self.create_paginated_combo(frame, config["title"], items, config["var_name"])
        else:
            config = peripheral_configs[0]
            items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
            self.create_paginated_combo(parent, config["title"], items, config["var_name"])

    def create_paginated_combo(self, parent, title, items, var_name, current_value=None):
        """Создаёт комбобокс с поиском и пагинацией."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text=title, font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))

        if current_value is None and self.is_edit_mode:
            current_value = self.get_current_selection_for_tab({"var_name": var_name})

        var = tk.StringVar(value=current_value if current_value else "")
        setattr(self, f"{var_name}_var", var)

        # Поиск
        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(search_frame, text="🔍 Поиск:", font=("Arial", 12)).pack(side=tk.LEFT, padx=(0, 5))
        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="Введите текст для поиска...").pack(
            side=tk.LEFT, fill=tk.X, expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)} шт.)", font=("Arial", 10), text_color="gray")
        count_label.pack(side=tk.RIGHT, padx=(5, 0))

        # Список
        list_frame = ctk.CTkFrame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        text_list = ctk.CTkTextbox(list_frame, wrap="none")
        text_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        text_list.configure(cursor="hand2")

        scrollbar = ctk.CTkScrollbar(list_frame, command=text_list.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_list.configure(yscrollcommand=scrollbar.set)

        for item in items:
            text_list.insert("end", item + "\n")

        text_list.configure(state="disabled")

        # Фильтрация
        def filter_list(*args):
            search_text = search_var.get().lower()
            text_list.configure(state="normal")
            text_list.delete("1.0", "end")
            if search_text:
                filtered = [item for item in items if search_text in item.lower()]
                for item in filtered:
                    text_list.insert("end", item + "\n")
                count_label.configure(text=f"({len(filtered)}/{len(items)})", text_color="blue")
            else:
                filtered = items
                for item in items:
                    text_list.insert("end", item + "\n")
                count_label.configure(text=f"({len(items)} шт.)", text_color="gray")
            # Восстанавливаем подсветку текущего выбора
            current = var.get()
            if current:
                displayed = filtered if search_text else items
                for i, item in enumerate(displayed, 1):
                    if item == current:
                        text_list.tag_add("selected", f"{i}.0", f"{i}.0 lineend")
                        text_list.tag_config("selected", background="#d0e8ff", foreground="#1a5276")
                        break
            text_list.configure(state="disabled")

        search_var.trace('w', filter_list)

        # Выбор
        def on_list_click(event):
            try:
                index = text_list.index(f"@{event.x},{event.y}")
                line_num = int(index.split('.')[0])
                line = text_list.get(f"{index} linestart", f"{index} lineend").strip()
                if line:
                    var.set(line)
                    selected_label.configure(text=f"{line}", text_color="green")
                    # Подсветка выбранной строки
                    text_list.configure(state="normal")
                    text_list.tag_remove("selected", "1.0", "end")
                    text_list.tag_add("selected", f"{line_num}.0", f"{line_num}.0 lineend")
                    text_list.tag_config("selected", background="#d0e8ff", foreground="#1a5276")
                    text_list.configure(state="disabled")
            except (tk.TclError, ValueError):
                pass

        text_list.bind("<Button-1>", on_list_click)

        # Подсветить текущее значение при загрузке
        if current_value:
            text_list.configure(state="normal")
            for i, item in enumerate(items, 1):
                if item == current_value:
                    text_list.tag_add("selected", f"{i}.0", f"{i}.0 lineend")
                    text_list.tag_config("selected", background="#d0e8ff", foreground="#1a5276")
                    text_list.see(f"{i}.0")
                    break
            text_list.configure(state="disabled")

        # Выбранное значение
        selected_frame = ctk.CTkFrame(frame, fg_color="transparent")
        selected_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkLabel(selected_frame, text="✅ Выбрано:", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        selected_label = ctk.CTkLabel(selected_frame, text=current_value if current_value else "не выбрано",
                                      text_color="green" if current_value else "gray")
        selected_label.pack(side=tk.LEFT)

        if current_value:
            ctk.CTkButton(selected_frame, text="✕ Очистить",
                          command=lambda: [var.set(""), selected_label.configure(text="не выбрано", text_color="gray")],
                          width=80, height=25).pack(side=tk.RIGHT)

        def update_selected(*args):
            if var.get():
                selected_label.configure(text=var.get(), text_color="green")
            else:
                selected_label.configure(text="не выбрано", text_color="gray")

        var.trace('w', update_selected)

    def create_multi_select_combo(self, parent, title, items, var_name):
        """Создаёт двухпанельный виджет множественного выбора (как в ВМ)."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text=title, font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))

        # Загружаем текущие выбранные значения
        current_values = []
        if self.is_edit_mode:
            current_values = self.get_current_selection_for_tab({"var_name": var_name, "multiple": True})
            if isinstance(current_values, str):
                current_values = [current_values] if current_values else []

        selected_items = list(current_values)
        setattr(self, f"{var_name}_selected", selected_items)

        # Две колонки
        columns_frame = ctk.CTkFrame(frame, fg_color="transparent")
        columns_frame.pack(fill=tk.BOTH, expand=True)

        is_dark = ctk.get_appearance_mode() == "Dark"
        lb_bg = "#2b2b2b" if is_dark else "white"
        lb_fg = "white" if is_dark else "black"

        # === Левая колонка: доступные ===
        left_frame = ctk.CTkFrame(columns_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        ctk.CTkLabel(left_frame, text="Доступные:", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))

        search_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, pady=(0, 5))

        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="Поиск...", height=30).pack(
            side=tk.LEFT, fill=tk.X, expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)})", font=("Arial", 10), text_color="gray")
        count_label.pack(side=tk.RIGHT, padx=(5, 0))

        left_list_frame = ctk.CTkFrame(left_frame)
        left_list_frame.pack(fill=tk.BOTH, expand=True)

        available_listbox = tk.Listbox(
            left_list_frame, bg=lb_bg, fg=lb_fg, font=("Arial", 10),
            height=12, selectmode=tk.MULTIPLE, selectbackground="#3a7ebf",
            selectforeground="white", activestyle="none"
        )
        left_scroll = ctk.CTkScrollbar(left_list_frame, command=available_listbox.yview)
        left_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        available_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        available_listbox.configure(yscrollcommand=left_scroll.set)

        for item in items:
            available_listbox.insert(tk.END, item)

        # === Правая колонка: выбранные ===
        right_frame = ctk.CTkFrame(columns_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ctk.CTkLabel(right_frame, text="Выбранные:", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))

        right_list_frame = ctk.CTkFrame(right_frame)
        right_list_frame.pack(fill=tk.BOTH, expand=True, pady=(35, 0))

        selected_listbox = tk.Listbox(
            right_list_frame, bg=lb_bg, fg=lb_fg, font=("Arial", 10),
            height=12, selectbackground="#c0392b", selectforeground="white",
            activestyle="none"
        )
        right_scroll = ctk.CTkScrollbar(right_list_frame, command=selected_listbox.yview)
        right_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        selected_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        selected_listbox.configure(yscrollcommand=right_scroll.set)

        for item in selected_items:
            selected_listbox.insert(tk.END, item)

        # Фильтрация
        def filter_list(*args):
            search_text = search_var.get().lower()
            available_listbox.delete(0, tk.END)
            if search_text:
                filtered = [item for item in items if search_text in item.lower()]
                for item in filtered:
                    available_listbox.insert(tk.END, item)
                count_label.configure(text=f"({len(filtered)}/{len(items)})", text_color="blue")
            else:
                for item in items:
                    available_listbox.insert(tk.END, item)
                count_label.configure(text=f"({len(items)})", text_color="gray")

        search_var.trace('w', filter_list)

        # Статус
        status_label = ctk.CTkLabel(
            frame,
            text=f"Выбрано: {len(selected_items)}" if selected_items else "Выбрано: 0",
            font=("Arial", 11, "bold"),
            text_color="green" if selected_items else "gray"
        )

        def update_status():
            if selected_items:
                status_label.configure(text=f"Выбрано: {len(selected_items)}", text_color="green")
            else:
                status_label.configure(text="Выбрано: 0", text_color="gray")

        # Кнопки
        def add_selected():
            selection = available_listbox.curselection()
            for idx in selection:
                item = available_listbox.get(idx)
                if item not in selected_items:
                    selected_items.append(item)
                    selected_listbox.insert(tk.END, item)
            update_status()

        def remove_selected():
            selection = selected_listbox.curselection()
            for idx in sorted(selection, reverse=True):
                item = selected_listbox.get(idx)
                if item in selected_items:
                    selected_items.remove(item)
                selected_listbox.delete(idx)
            update_status()

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkButton(btn_frame, text="Добавить >>", command=add_selected,
                      width=120, height=30).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="<< Удалить", command=remove_selected,
                      width=120, height=30, fg_color="#c0392b", hover_color="#e74c3c").pack(side=tk.LEFT, padx=5)

        status_label.pack(side=tk.RIGHT, padx=10)
        btn_frame.tkraise()  # Ensure buttons are above status

        status_label.pack_forget()
        status_label.pack(in_=btn_frame, side=tk.RIGHT, padx=10)

    # ========================================================================
    # ВКЛАДКА СЕТИ
    # ========================================================================

    def create_network_tab(self, parent, config):
        """Создаёт вкладку с настройками сети."""
        # Основной фрейм с прокруткой
        main_frame = ctk.CTkFrame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_frame, bg=self._get_canvas_bg_color(), highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ctk.CTkFrame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Прокрутка колесиком
        def on_mousewheel(event):
            try:
                if canvas.winfo_exists():
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except:
                pass

        canvas.bind_all("<MouseWheel>", on_mousewheel)

        # Контейнер для портов
        ports_frame = ctk.CTkFrame(scrollable_frame)
        ports_frame.pack(fill=tk.X, padx=10, pady=10)

        ctk.CTkLabel(ports_frame, text="🔌 Сетевые порты", font=("Arial", 14, "bold")).pack(anchor=tk.W, padx=10,
                                                                                           pady=(10, 5))

        self.ports_container = ctk.CTkFrame(ports_frame)
        self.ports_container.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Кнопка добавления порта
        add_frame = ctk.CTkFrame(ports_frame)
        add_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        ctk.CTkLabel(add_frame, text="Добавить порт:", font=("Arial", 12)).pack(side=tk.LEFT, padx=(0, 5))

        self.new_port_type = tk.StringVar(value="ethernet")

        ctk.CTkRadioButton(add_frame, text="🔌 RJ45", variable=self.new_port_type, value="ethernet").pack(side=tk.LEFT,
                                                                                                         padx=2)
        ctk.CTkRadioButton(add_frame, text="🔆 PON", variable=self.new_port_type, value="pon").pack(side=tk.LEFT, padx=2)
        ctk.CTkRadioButton(add_frame, text="📶 Wi-Fi", variable=self.new_port_type, value="wifi").pack(side=tk.LEFT,
                                                                                                      padx=2)
        ctk.CTkRadioButton(add_frame, text="🔌 USB", variable=self.new_port_type, value="usb").pack(side=tk.LEFT, padx=2)

        ctk.CTkButton(add_frame, text="➕ Добавить", command=self.add_new_port, width=100).pack(side=tk.RIGHT)

        # Кнопка тестовых данных
        test_frame = ctk.CTkFrame(ports_frame)
        test_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        ctk.CTkButton(test_frame, text="🧪 Тестовые данные", command=self.fill_test_data).pack(side=tk.RIGHT)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.display_ports()

    def _get_canvas_bg_color(self):
        return "#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff"

    def display_ports(self):
        """Отображает список портов."""
        if not hasattr(self, 'ports_container') or self.ports_container is None:
            return

        for widget in self.ports_container.winfo_children():
            widget.destroy()

        self.port_vars = {}
        self.wifi_role_vars = {}

        eth_ports = [p for p in self.current_ports if p["port_type"] == "ethernet"]
        pon_ports = [p for p in self.current_ports if p["port_type"] == "pon"]
        wifi_ports = [p for p in self.current_ports if p["port_type"] == "wifi"]
        usb_ports = [p for p in self.current_ports if p["port_type"] == "usb"]

        if eth_ports:
            ctk.CTkLabel(self.ports_container, text="🔌 RJ45 порты:", font=("Arial", 11, "bold")).pack(anchor=tk.W,
                                                                                                      pady=(5, 2))
            for port in eth_ports:
                self.create_port_widget(port)

        if pon_ports:
            ctk.CTkLabel(self.ports_container, text="🔆 PON порты:", font=("Arial", 11, "bold")).pack(anchor=tk.W,
                                                                                                     pady=(10, 2))
            for port in pon_ports:
                self.create_port_widget(port)

        if wifi_ports:
            ctk.CTkLabel(self.ports_container, text="📶 Wi-Fi порты:", font=("Arial", 11, "bold")).pack(anchor=tk.W,
                                                                                                       pady=(10, 2))
            for port in wifi_ports:
                self.create_wifi_port_widget(port)

        if usb_ports:
            ctk.CTkLabel(self.ports_container, text="🔌 USB порты:", font=("Arial", 11, "bold")).pack(anchor=tk.W,
                                                                                                     pady=(10, 2))
            for port in usb_ports:
                self.create_port_widget(port, show_network=False)

    def create_port_widget(self, port: Dict, show_network: bool = True):
        """Создаёт виджет для порта."""
        frame = ctk.CTkFrame(self.ports_container)
        frame.pack(fill=tk.X, pady=2)

        icon = "🔌" if port["port_type"] == "ethernet" else "🔆"
        is_busy = port.get("connected_to") is not None
        status_icon = "🔴" if is_busy else "🟢"

        ctk.CTkLabel(frame, text=f"{icon} {port['name']} {status_icon}", width=90, anchor=tk.W).pack(side=tk.LEFT,
                                                                                                     padx=(5, 5))

        if show_network:
            mac_var = tk.StringVar(value=port.get("mac_address", ""))
            ip_var = tk.StringVar(value=port.get("ip_address", ""))
            mask_var = tk.StringVar(value=port.get("subnet_mask", ""))
            vlan_id_var = tk.StringVar(value=str(port.get("vlan_id", "")) if port.get("vlan_id") else "")
            vlan_mode_var = tk.StringVar(value=port.get("vlan_mode", "untagged"))

            self.port_vars[port["port_id"]] = {"mac": mac_var, "ip": ip_var, "mask": mask_var, "vlan_id": vlan_id_var,
                                               "vlan_mode": vlan_mode_var, "port": port}

            ctk.CTkEntry(frame, textvariable=mac_var, width=120, placeholder_text="MAC").pack(side=tk.LEFT, padx=2)
            ctk.CTkEntry(frame, textvariable=ip_var, width=110, placeholder_text="IP").pack(side=tk.LEFT, padx=2)
            ctk.CTkLabel(frame, text="/", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
            ctk.CTkEntry(frame, textvariable=mask_var, width=50, placeholder_text="маска").pack(side=tk.LEFT,
                                                                                                padx=(2, 5))
            ctk.CTkLabel(frame, text="|", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=2)
            ctk.CTkEntry(frame, textvariable=vlan_id_var, width=60, placeholder_text="VLAN").pack(side=tk.LEFT, padx=2)
            ctk.CTkComboBox(frame, values=["untagged", "tagged"], variable=vlan_mode_var, width=90).pack(side=tk.LEFT,
                                                                                                         padx=2)
        else:
            ctk.CTkLabel(frame, text="(USB порт)").pack(side=tk.LEFT, padx=2)

        if not is_busy:
            ctk.CTkButton(frame, text="✕", width=30, command=lambda p=port: self.remove_port(p["port_id"])).pack(
                side=tk.RIGHT, padx=5)

    def create_wifi_port_widget(self, port: Dict):
        """Создаёт виджет для Wi-Fi порта."""
        frame = ctk.CTkFrame(self.ports_container)
        frame.pack(fill=tk.X, pady=2, padx=2)

        wifi_caps = self.current_node_config.get("wifi_capabilities", {})

        if port.get("wifi_role") == "ap":
            is_busy = len(port.get("connected_clients", [])) > 0
        else:
            is_busy = port.get("connected_to_ap") is not None

        status_icon = "🔴" if is_busy else "🟢"
        role_text = "AP" if port.get("wifi_role") == "ap" else "Client"

        name_frame = ctk.CTkFrame(frame, fg_color="transparent")
        name_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ctk.CTkLabel(name_frame, text=f"📶 {port['name']} [{role_text}] {status_icon}", width=100, anchor=tk.W).pack(
            side=tk.LEFT, padx=(5, 5))

        if wifi_caps.get("can_be_ap") and wifi_caps.get("can_be_client") and not is_busy:
            role_var = tk.StringVar(value=port.get("wifi_role", "client"))
            self.wifi_role_vars[port["port_id"]] = role_var
            role_frame = ctk.CTkFrame(name_frame, fg_color="transparent")
            role_frame.pack(side=tk.LEFT, padx=5)
            ctk.CTkRadioButton(role_frame, text="AP", value="ap", variable=role_var,
                               command=lambda: self.update_port_role(port["port_id"], role_var.get())).pack(
                side=tk.LEFT, padx=2)
            ctk.CTkRadioButton(role_frame, text="Client", value="client", variable=role_var,
                               command=lambda: self.update_port_role(port["port_id"], role_var.get())).pack(
                side=tk.LEFT, padx=2)

        fields_frame = ctk.CTkFrame(frame, fg_color="transparent")
        fields_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        mac_var = tk.StringVar(value=port.get("mac_address", ""))
        ip_var = tk.StringVar(value=port.get("ip_address", ""))
        mask_var = tk.StringVar(value=port.get("subnet_mask", ""))
        vlan_id_var = tk.StringVar(value=str(port.get("vlan_id", "")) if port.get("vlan_id") else "")
        vlan_mode_var = tk.StringVar(value=port.get("vlan_mode", "untagged"))

        self.port_vars[port["port_id"]] = {"mac": mac_var, "ip": ip_var, "mask": mask_var, "vlan_id": vlan_id_var,
                                           "vlan_mode": vlan_mode_var, "port": port}

        ctk.CTkEntry(fields_frame, textvariable=mac_var, width=120, placeholder_text="MAC").pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(fields_frame, textvariable=ip_var, width=110, placeholder_text="IP").pack(side=tk.LEFT, padx=2)
        ctk.CTkLabel(fields_frame, text="/", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        ctk.CTkEntry(fields_frame, textvariable=mask_var, width=50, placeholder_text="маска").pack(side=tk.LEFT,
                                                                                                   padx=(2, 5))
        ctk.CTkLabel(fields_frame, text="|", font=("Arial", 12, "bold")).pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(fields_frame, textvariable=vlan_id_var, width=60, placeholder_text="VLAN").pack(side=tk.LEFT,
                                                                                                     padx=2)
        ctk.CTkComboBox(fields_frame, values=["untagged", "tagged"], variable=vlan_mode_var, width=90).pack(
            side=tk.LEFT, padx=2)

        if not is_busy:
            ctk.CTkButton(frame, text="✕", width=30, command=lambda p=port: self.remove_port(p["port_id"])).pack(
                side=tk.RIGHT, padx=5)

    def update_port_role(self, port_id: str, new_role: str):
        for port in self.current_ports:
            if port["port_id"] == port_id:
                port["wifi_role"] = new_role
                break

    def add_new_port(self):
        """Добавляет новый порт."""
        port_type = self.new_port_type.get()
        existing_ports = [p for p in self.current_ports if p["port_type"] == port_type]
        next_number = len(existing_ports) + 1

        new_port = {
            "port_id": f"{port_type}_{next_number}_{uuid.uuid4().hex[:8]}",
            "port_type": port_type, "port_number": next_number
        }

        if port_type == "ethernet":
            new_port.update(
                {"name": f"ETH{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "connected_to": None, "connected_port": None})
        elif port_type == "pon":
            new_port.update(
                {"name": f"PON{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "connected_to": None, "connected_port": None})
        elif port_type == "wifi":
            wifi_caps = self.current_node_config.get("wifi_capabilities", {})
            wifi_role = "ap" if wifi_caps.get("can_be_ap") else "client"
            new_port.update(
                {"name": f"WiFi{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "wifi_role": wifi_role, "connected_clients": [], "connected_to_ap": None})
        else:
            new_port.update(
                {"name": f"USB{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "connected_to": None, "connected_port": None})

        self.current_ports.append(new_port)
        self.display_ports()

    def remove_port(self, port_id: str):
        self.current_ports = [p for p in self.current_ports if p["port_id"] != port_id]
        if port_id in self.port_vars:
            del self.port_vars[port_id]
        self.display_ports()

    def fill_test_data(self):
        for port_id, vars_dict in self.port_vars.items():
            vars_dict["mac"].set(generate_test_mac())
            vars_dict["ip"].set(generate_test_ip())
            vars_dict["mask"].set(generate_test_mask())

    # ========================================================================
    # СОЗДАНИЕ/СОХРАНЕНИЕ УЗЛА
    # ========================================================================

    def validate_network_fields(self) -> bool:
        """Проверяет заполнение сетевых полей."""
        from config.node_config import REQUIRED_NETWORK_FIELDS

        required = REQUIRED_NETWORK_FIELDS.get(self.current_node_type_key, {"ip": False, "mac": False, "mask": False})

        for port in self.current_ports:
            if port["port_type"] not in ["ethernet", "pon", "wifi"]:
                continue

            port_id = port["port_id"]

            if port_id in self.port_vars:
                mac = self.port_vars[port_id]["mac"].get().strip()
                ip = self.port_vars[port_id]["ip"].get().strip()
                mask = self.port_vars[port_id]["mask"].get().strip()
                vlan_id = self.port_vars[port_id]["vlan_id"].get().strip()
                vlan_mode = self.port_vars[port_id]["vlan_mode"].get().strip()
            else:
                mac = port.get("mac_address", "")
                ip = port.get("ip_address", "")
                mask = port.get("subnet_mask", "")
                vlan_id = str(port.get("vlan_id", "")) if port.get("vlan_id") else ""
                vlan_mode = port.get("vlan_mode", "untagged")

            if required["mac"] and not mac:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать MAC-адрес!")
                return False
            if mac and not validate_mac(mac):
                messagebox.showerror("Ошибка",
                                     f"Неверный формат MAC-адреса для порта {port['name']}!\nФормат: 00:11:22:33:44:55")
                return False

            if required["ip"] and not ip:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать IP-адрес!")
                return False
            if ip and not validate_ip(ip):
                messagebox.showerror("Ошибка",
                                     f"Неверный формат IP-адреса для порта {port['name']}!\nФормат: 192.168.1.1")
                return False

            if required["mask"] and not mask:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать маску подсети!")
                return False
            if mask and not validate_mask(mask):
                messagebox.showerror("Ошибка",
                                     f"Неверный формат маски для порта {port['name']}!\nФормат: число от 0 до 32")
                return False

            if vlan_id and not validate_vlan_id(vlan_id, vlan_mode):
                if vlan_mode == "untagged":
                    error_msg = f"Неверный VLAN ID для порта {port['name']}!\n\n⚠️ Для режима 'untagged' разрешён ТОЛЬКО ОДИН VLAN ID!\nПример: 100"
                else:
                    error_msg = f"Неверный VLAN ID для порта {port['name']}!\n\n✅ Для режима 'tagged' доступны форматы:\n• Один VLAN: 100\n• Несколько VLAN: 10,20,30\n• Диапазон: 100-200"
                messagebox.showerror("Ошибка", error_msg)
                return False

        return True

    def create_node(self):
        """Создаёт или обновляет узел."""
        node_type_mapping = {
            "АРМ": "ARM", "Ноутбук": "Laptop", "Маршрутизатор": "Router",
            "Коммутатор": "Switch", "Сервер": "Server",
            "Сервер виртуализации": "VirtualizationServer", "Интернет": "Internet"
        }

        node_type_ru = self.preselected_type if self.preselected_type else "АРМ"
        node_type_en = node_type_mapping.get(node_type_ru, "ARM")

        # Выбор зоны
        selected_zone = None

        if node_type_ru == "Интернет":
            selected_zone = self.board.get_free_zone()
            if not selected_zone:
                messagebox.showerror("Ошибка", "Свободная зона не найдена!")
                return
        else:
            tim_zones = self.board.get_tim_zones()
            if not tim_zones:
                messagebox.showerror("Ошибка", "Нет доступных зон TIM для размещения узла!")
                return
            if not hasattr(self, 'zone_var'):
                messagebox.showerror("Ошибка", "Не выбрана зона TIM!")
                return
            zone_id = self.zone_var.get()
            for zone in tim_zones:
                if zone.id == zone_id:
                    selected_zone = zone
                    break
            if not selected_zone:
                messagebox.showerror("Ошибка", "Не выбрана зона для размещения узла!")
                return

        # Сохраняем данные портов
        for port_id, vars_dict in self.port_vars.items():
            for port in self.current_ports:
                if port["port_id"] == port_id:
                    port["mac_address"] = vars_dict["mac"].get().strip()
                    port["ip_address"] = vars_dict["ip"].get().strip()
                    port["subnet_mask"] = vars_dict["mask"].get().strip()
                    vlan_id = vars_dict["vlan_id"].get().strip()
                    port["vlan_id"] = vlan_id if vlan_id else None
                    port["vlan_mode"] = vars_dict["vlan_mode"].get().strip()
                    break

        for port_id, role_var in self.wifi_role_vars.items():
            for port in self.current_ports:
                if port["port_id"] == port_id:
                    port["wifi_role"] = role_var.get()
                    break

        if not self.validate_network_fields():
            return

        # Позиция узла
        if self.is_edit_mode:
            node_position = self.existing_node.position
        else:
            node_position = self.board.get_next_free_position(selected_zone)

        # Собираем компоненты
        properties = {"hardware": [], "software": [], "network": []}
        hardware_items = []
        software_items = []

        for attr_name in dir(self):
            if attr_name.endswith('_var') and not attr_name.startswith('node_') and not attr_name.startswith('zone_'):
                var = getattr(self, attr_name)
                if hasattr(var, 'get'):
                    value = var.get()
                    if value:
                        if "processor" in attr_name or "cpu" in attr_name:
                            hardware_items.append(f"Процессор: {value}")
                        elif "gpu" in attr_name and "driver" not in attr_name:
                            hardware_items.append(f"Видеоконтроллер: {value}")
                        elif "motherboard" in attr_name:
                            hardware_items.append(f"Материнская плата: {value}")
                        elif "hdd" in attr_name or "storage" in attr_name:
                            hardware_items.append(f"HDD/SSD: {value}")
                        elif "mouse" in attr_name:
                            software_items.append(f"Мышь: {value}")
                        elif "keyboard" in attr_name:
                            software_items.append(f"Клавиатура: {value}")
                        elif "printer" in attr_name:
                            software_items.append(f"Принтер: {value}")
                        elif "monitor" in attr_name:
                            software_items.append(f"Монитор: {value}")
                        elif "os" in attr_name:
                            software_items.append(f"ОС: {value}")
                        elif "app" in attr_name:
                            software_items.append(f"Приложение: {value}")
                        else:
                            software_items.append(value)

            # Обработка множественного выбора (_selected списки)
            if attr_name.endswith('_selected') and not attr_name.startswith('_'):
                selected_list = getattr(self, attr_name)
                if isinstance(selected_list, list):
                    for value in selected_list:
                        if value:
                            if "app" in attr_name:
                                software_items.append(f"Приложение: {value}")
                            else:
                                software_items.append(value)

        properties["hardware"] = hardware_items
        properties["software"] = software_items

        # Имя узла
        node_name = self.node_name_var.get().strip()
        if not node_name:
            existing_names = [n.name for n in self.board.nodes if n.type == node_type_en]
            count = 1
            node_name = f"{node_type_ru}{count}"
            while node_name in existing_names:
                count += 1
                node_name = f"{node_type_ru}{count}"

        # Создаём или обновляем узел
        if self.is_edit_mode:
            node = self.existing_node
            node.name = node_name
            node.zone = selected_zone
            node.properties = properties
            node.ports = self.current_ports
        else:
            node = Node(
                id=uid(), type=node_type_en, name=node_name, zone=selected_zone,
                position=node_position, properties=properties, ports=self.current_ports
            )

        # Инициализируем файервол
        if "firewall" not in node.properties:
            node.properties["firewall"] = {
                "node_id": node.id, "rules": [],
                "profiles": {"domain": True, "private": True, "public": True},
                "firewall_enabled": node.firewall_enabled, "notification_enabled": True
            }

        self.result = node
        self.dialog.destroy()