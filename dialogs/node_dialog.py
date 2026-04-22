"""
Модуль диалога создания/редактирования узла

Содержит классы:
- NodeTypeSelectionDialog: Диалог выбора типа узла
- NodeCreationDialog: Основной диалог создания/редактирования узла
"""

import os
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import time
import uuid
from utils.theme import center_window
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
    """Диалог выбора типа узла — карточки-плитки с иконками (промт-стиль2)."""

    # Описания типов узлов для карточек (порядок = порядок отображения)
    _NODE_TYPES = [
        {"value": "АРМ",      "title": "АРМ",        "subtitle": "автоматизированное\nрабочее место", "icon_key": "ARM"},
        {"value": "Ноутбук",  "title": "Ноутбук",    "subtitle": "портативное\nустройство",          "icon_key": "Laptop"},
        {"value": "Маршрутизатор", "title": "Маршрутизатор", "subtitle": "Маршрутизатор",             "icon_key": "Router"},
        {"value": "Коммутатор", "title": "Коммутатор", "subtitle": "Коммутатор",                      "icon_key": "Switch"},
        {"value": "Сервер",   "title": "Сервер",      "subtitle": "Сервер",                           "icon_key": "Server"},
        {"value": "Сервер виртуализации", "title": "Сервер\nвиртуализации", "subtitle": "VM-хост",    "icon_key": "VirtualizationServer"},
        {"value": "Интернет", "title": "Интернет",    "subtitle": "Интернет",                         "icon_key": "Internet"},
    ]

    def __init__(self, parent, board=None):
        from utils.theme import style_dialog
        self.parent = parent
        self.board = board
        self.result = None
        self._card_frames = []
        self._icon_refs = []  # prevent garbage collection

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Выбор типа узла")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.node_type_var = tk.StringVar(value="АРМ")
        self.create_widgets()
        style_dialog(self.dialog, width=580, height=520)

    def create_widgets(self):
        from utils.theme import color
        from config.node_config import ICON_FILES, RESOURCES_DIR

        dialog_bg = color("dialog_bg")
        card_bg = color("card_bg")
        card_border = color("card_border")
        card_sel_brd = color("card_sel_brd")
        card_selected = color("card_selected")
        text_primary = color("text_primary")
        text_muted = color("text_muted")
        primary = color("primary")
        primary_hover = color("primary_hover")
        danger = color("danger")
        danger_hover = color("danger_hover")

        self.dialog.configure(fg_color=dialog_bg)

        main = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)

        ctk.CTkLabel(main, text="Выберите тип создаваемого узла",
                      font=("Segoe UI", 18, "bold"), text_color=text_primary).pack(pady=(0, 20))

        # --- Сетка карточек 4 + 3 ---
        grid = ctk.CTkFrame(main, fg_color="transparent")
        grid.pack(fill=tk.BOTH, expand=True)

        # 4 колонки
        for i in range(4):
            grid.grid_columnconfigure(i, weight=1, uniform="node_card")

        self._card_frames = []
        for idx, nt in enumerate(self._NODE_TYPES):
            row = 0 if idx < 4 else 1
            col = idx if idx < 4 else idx - 4

            card = ctk.CTkFrame(
                grid, fg_color=card_bg,
                border_width=2, border_color=card_border,
                corner_radius=10, cursor="hand2"
            )
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(expand=True, padx=8, pady=10)

            # Иконка из resources/ (переиспользуем существующие)
            icon_filename = ICON_FILES.get(nt["icon_key"])
            icon_loaded = False
            if icon_filename:
                icon_path = os.path.join(RESOURCES_DIR, icon_filename)
                if os.path.exists(icon_path):
                    try:
                        from PIL import Image
                        img = Image.open(icon_path).resize((48, 48), Image.Resampling.LANCZOS)
                        ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(48, 48))
                        self._icon_refs.append(ctk_img)
                        ctk.CTkLabel(inner, image=ctk_img, text="").pack(pady=(0, 6))
                        icon_loaded = True
                    except Exception:
                        pass

            if not icon_loaded:
                ctk.CTkLabel(inner, text="[icon]", font=("Segoe UI", 10),
                              text_color=text_muted).pack(pady=(0, 6))

            ctk.CTkLabel(inner, text=nt["title"], font=("Segoe UI", 11, "bold"),
                          text_color=text_primary, justify="center").pack()
            ctk.CTkLabel(inner, text=nt["subtitle"], font=("Segoe UI", 9),
                          text_color=text_muted, justify="center").pack(pady=(2, 0))

            value = nt["value"]
            for w in [card, inner] + inner.winfo_children():
                w.bind("<Button-1>", lambda e, v=value: self._select(v))

            self._card_frames.append((card, value))

        self._update_selection()

        # --- Кнопки ---
        btn_frame = ctk.CTkFrame(main, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(16, 0))

        ctk.CTkButton(
            btn_frame, text="Далее →", command=self.select_type,
            fg_color=primary, hover_color=primary_hover,
            text_color="#FFFFFF", width=140, height=40,
            corner_radius=10, font=("Segoe UI", 13, "bold")
        ).pack(side=tk.RIGHT, padx=(8, 0))

        ctk.CTkButton(
            btn_frame, text="Отмена", command=self.dialog.destroy,
            fg_color=danger, hover_color=danger_hover,
            text_color="#FFFFFF", width=110, height=40,
            corner_radius=10, font=("Segoe UI", 13)
        ).pack(side=tk.RIGHT)

        self.dialog.bind("<Return>", lambda e: self.select_type())
        self.dialog.bind("<Escape>", lambda e: self.dialog.destroy())

    def _select(self, value: str):
        self.node_type_var.set(value)
        self._update_selection()

    def _update_selection(self):
        from utils.theme import color
        selected = self.node_type_var.get()
        for card, val in self._card_frames:
            if val == selected:
                card.configure(border_color=color("card_sel_brd"),
                               fg_color=color("card_selected"))
            else:
                card.configure(border_color=color("card_border"),
                               fg_color=color("card_bg"))

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
        self.dialog.geometry("1400x800")
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
        center_window(self.dialog, width, height)

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
        """Показывает экран загрузки (тёмная палитра)."""
        from utils.theme import color

        self.dialog.configure(fg_color=color("dialog_bg"))

        self.loading_frame = ctk.CTkFrame(self.dialog, fg_color=color("dialog_bg"))
        self.loading_frame.pack(fill=tk.BOTH, expand=True)

        content_frame = ctk.CTkFrame(self.loading_frame, fg_color="transparent")
        content_frame.pack(expand=True)

        ctk.CTkLabel(
            content_frame, text="Загрузка конфигураций...",
            font=("Segoe UI", 22, "bold"), text_color=color("text_primary")
        ).pack(pady=(0, 30))

        self.animation_label = ctk.CTkLabel(
            content_frame, text="⏳", font=("Segoe UI", 72, "bold"),
            text_color=color("primary")
        )
        self.animation_label.pack(pady=20)

        self.status_label_loading = ctk.CTkLabel(
            content_frame, text="Подготовка данных для выбранного типа узла...",
            font=("Segoe UI", 14), text_color=color("text_muted")
        )
        self.status_label_loading.pack(pady=(0, 20))

        self.progress = ctk.CTkProgressBar(content_frame, width=450)
        self.progress.pack(pady=15)
        self.progress.set(0)

        if self.preselected_type:
            ctk.CTkLabel(
                content_frame, text=f"Тип узла: {self.preselected_type}",
                font=("Segoe UI", 16, "bold"), text_color=color("text_primary")
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
        """Создаёт основной интерфейс диалога — 3-панельный layout:
        LEFT sidebar (220px) | CENTER content | RIGHT config summary (250px)."""
        from utils.theme import color, style_dialog
        from config.node_config import ICON_FILES, RESOURCES_DIR

        self.dialog.configure(fg_color=color("dialog_bg"))

        # --- Инициализация переменных ---
        if not hasattr(self, 'node_name_var') or not self.node_name_var:
            self.node_name_var = tk.StringVar()
            if self.is_edit_mode and self.existing_node:
                self.node_name_var.set(self.existing_node.name)

        self._sidebar_buttons = {}
        self._current_tab = None
        self._config_scroll_active = False

        # ============================================================
        # MAIN 3-COLUMN LAYOUT
        # ============================================================
        main_container = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_container.pack(fill=tk.BOTH, expand=True)
        main_container.grid_columnconfigure(0, minsize=220)   # sidebar
        main_container.grid_columnconfigure(1, weight=1)       # content
        main_container.grid_columnconfigure(2, minsize=250)    # config summary
        main_container.grid_rowconfigure(0, weight=1)

        # ============================================================
        # LEFT SIDEBAR (220px)
        # ============================================================
        sidebar = ctk.CTkFrame(main_container, fg_color=color("sidebar_bg"), corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        self._sidebar_frame = sidebar

        # --- Node header: icon + type + subtitle ---
        header_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        header_frame.pack(fill=tk.X, padx=16, pady=(16, 8))

        node_type_ru = self.preselected_type if self.preselected_type else "АРМ"
        node_type_en = get_node_type_english(node_type_ru)

        # Load node icon
        icon_filename = ICON_FILES.get(node_type_en)
        self._sidebar_icon_refs = []
        if icon_filename:
            icon_path = os.path.join(RESOURCES_DIR, icon_filename)
            if os.path.exists(icon_path):
                try:
                    from PIL import Image
                    img = Image.open(icon_path).resize((48, 48), Image.Resampling.LANCZOS)
                    ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(48, 48))
                    self._sidebar_icon_refs.append(ctk_img)
                    ctk.CTkLabel(header_frame, image=ctk_img, text="").pack(pady=(0, 6))
                except Exception:
                    pass

        ctk.CTkLabel(header_frame, text=node_type_ru,
                     font=("Segoe UI", 15, "bold"),
                     text_color=color("text_primary")).pack()
        subtitle = "Редактирование" if self.is_edit_mode else "Создание узла"
        ctk.CTkLabel(header_frame, text=subtitle,
                     font=("Segoe UI", 11),
                     text_color=color("text_muted")).pack(pady=(2, 0))

        # --- Name field ---
        name_section = ctk.CTkFrame(sidebar, fg_color="transparent")
        name_section.pack(fill=tk.X, padx=16, pady=(4, 12))
        ctk.CTkLabel(name_section, text="Имя узла",
                     font=("Segoe UI", 11),
                     text_color=color("text_secondary"), anchor="w").pack(fill=tk.X)
        ctk.CTkEntry(name_section, textvariable=self.node_name_var, height=32,
                     corner_radius=6, fg_color=color("input_bg"),
                     border_color=color("input_border"), border_width=1).pack(fill=tk.X, pady=(4, 0))

        # --- Navigation buttons container ---
        self._nav_container = ctk.CTkFrame(sidebar, fg_color="transparent")
        self._nav_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=(0, 8))

        # --- Zone selector at the bottom ---
        zone_section = ctk.CTkFrame(sidebar, fg_color="transparent")
        zone_section.pack(fill=tk.X, padx=16, pady=(0, 16), side=tk.BOTTOM)
        self.zone_frame = zone_section
        self.update_zone_frame()

        # ============================================================
        # CENTER CONTENT AREA
        # ============================================================
        self._content_outer = ctk.CTkFrame(main_container, fg_color=color("dialog_bg"),
                                           corner_radius=12)
        self._content_outer.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)

        # Section title
        self._section_title_label = ctk.CTkLabel(
            self._content_outer, text="",
            font=("Segoe UI", 16, "bold"),
            text_color=color("text_primary"), anchor="w"
        )
        self._section_title_label.pack(fill=tk.X, padx=16, pady=(12, 4))

        # Content frame (will be cleared/rebuilt per tab)
        self._content_frame = ctk.CTkFrame(self._content_outer, fg_color="transparent")
        self._content_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # ============================================================
        # RIGHT CONFIG SUMMARY (250px)
        # ============================================================
        config_panel = ctk.CTkFrame(main_container, fg_color=color("sidebar_bg"), corner_radius=0)
        config_panel.grid(row=0, column=2, sticky="nsew")

        ctk.CTkLabel(config_panel, text="Конфигурация",
                     font=("Segoe UI", 14, "bold"),
                     text_color=color("text_primary")).pack(padx=12, pady=(12, 8), anchor="w")

        self._config_scroll = ctk.CTkScrollableFrame(
            config_panel, fg_color="transparent"
        )
        self._config_scroll.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # Mouse hover scroll control (without unbind_all)
        def _on_config_enter(e):
            self._config_scroll_active = True

        def _on_config_leave(e):
            self._config_scroll_active = False

        self._config_scroll.bind("<Enter>", _on_config_enter)
        self._config_scroll.bind("<Leave>", _on_config_leave)

        # ============================================================
        # BOTTOM BUTTONS (inside dialog, below 3-panel layout)
        # ============================================================
        button_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        button_frame.pack(fill=tk.X, padx=15, pady=(4, 12))

        # Кнопка загрузки пресета (слева)
        if not self.is_edit_mode:
            self._add_preset_button(button_frame)

        ctk.CTkButton(
            button_frame,
            text="Сохранить" if self.is_edit_mode else "Создать",
            command=self.create_node, font=("Segoe UI", 13, "bold"),
            fg_color=color("primary"), hover_color=color("primary_hover"),
            text_color="#FFFFFF", width=120, height=36, corner_radius=8
        ).pack(side=tk.RIGHT, padx=(8, 0))

        ctk.CTkButton(
            button_frame, text="Отмена", command=self.dialog.destroy,
            fg_color=color("ghost_bg"), hover_color=color("ghost_hover"),
            text_color=color("text_primary"), font=("Segoe UI", 13),
            width=100, height=36, corner_radius=8
        ).pack(side=tk.RIGHT)

        # ============================================================
        # Populate sidebar tabs and show first tab
        # ============================================================
        self.update_tabs()
        self._rebuild_config_summary()
        self.center_window()

    # ------------------------------------------------------------------
    # SIDEBAR NAVIGATION helpers
    # ------------------------------------------------------------------

    def _add_sidebar_tab(self, key, label, group=None):
        """Adds a navigation button to the sidebar. `group` is used for separators."""
        from utils.theme import color

        btn = ctk.CTkButton(
            self._nav_container, text=label,
            font=("Segoe UI", 12), anchor="w",
            fg_color="transparent", hover_color=color("ghost_hover"),
            text_color=color("text_primary"),
            height=32, corner_radius=6,
            command=lambda k=key: self._show_tab(k)
        )
        btn.pack(fill=tk.X, padx=8, pady=1)
        self._sidebar_buttons[key] = btn

    def _add_sidebar_separator(self):
        """Adds a thin divider line in the sidebar."""
        from utils.theme import color
        ctk.CTkFrame(self._nav_container, fg_color=color("divider"),
                     height=1).pack(fill=tk.X, padx=16, pady=6)

    def _show_tab(self, key):
        """Switches content panel to the tab identified by `key`."""
        from utils.theme import color

        self._current_tab = key

        # Update pill indicators on sidebar buttons
        for k, btn in self._sidebar_buttons.items():
            if k == key:
                btn.configure(
                    fg_color=color("ghost_hover"),
                    border_width=0
                )
                # Pill indicator via left border trick — use a colored bg strip
            else:
                btn.configure(
                    fg_color="transparent",
                    border_width=0
                )

        # Clear content
        for w in self._content_frame.winfo_children():
            w.destroy()

        # Set section title
        self._section_title_label.configure(text=self._tab_titles.get(key, key))

        # Build content for the tab
        builder = self._tab_builders.get(key)
        if builder:
            builder(self._content_frame)

    def _show_subtab_panel(self, parent, subtabs):
        """Creates a sub-tab panel inside the content area.
        subtabs: list of (label, builder_func) tuples."""
        from utils.theme import color

        if len(subtabs) <= 1:
            if subtabs:
                subtabs[0][1](parent)
            return

        container = ctk.CTkFrame(parent, fg_color="transparent")
        container.pack(fill=tk.BOTH, expand=True)

        # Sub-tab buttons row
        btn_row = ctk.CTkFrame(container, fg_color="transparent")
        btn_row.pack(fill=tk.X, padx=8, pady=(4, 8))

        content_area = ctk.CTkFrame(container, fg_color="transparent")
        content_area.pack(fill=tk.BOTH, expand=True)

        subtab_btns = {}

        def show_sub(label):
            for w in content_area.winfo_children():
                w.destroy()
            for lbl, builder in subtabs:
                if lbl == label:
                    builder(content_area)
                    break
            for lbl, b in subtab_btns.items():
                if lbl == label:
                    b.configure(fg_color=color("primary"), text_color="#FFFFFF")
                else:
                    b.configure(fg_color=color("ghost_bg"), text_color=color("text_primary"))

        for lbl, builder in subtabs:
            b = ctk.CTkButton(
                btn_row, text=lbl, font=("Segoe UI", 11),
                fg_color=color("ghost_bg"), hover_color=color("ghost_hover"),
                text_color=color("text_primary"),
                height=28, corner_radius=6,
                command=lambda l=lbl: show_sub(l)
            )
            b.pack(side=tk.LEFT, padx=2)
            subtab_btns[lbl] = b

        # Show first sub-tab
        if subtabs:
            show_sub(subtabs[0][0])

    def _show_subtab_content(self, parent, config):
        """Builds content for a single hardware/software/peripheral sub-tab."""
        self._create_tab_widget(parent, config)

    # ------------------------------------------------------------------
    # CONFIG SUMMARY panel
    # ------------------------------------------------------------------

    def _rebuild_config_summary(self):
        """Rebuilds the config summary cards in the right panel."""
        from utils.theme import color

        if not hasattr(self, '_config_scroll'):
            return

        for w in self._config_scroll.winfo_children():
            w.destroy()

        node_config = getattr(self, 'current_node_config', None)
        if not node_config:
            return

        self._config_labels = {}

        # Collect all tab configs to show
        all_tabs = []
        for grp in ['hardware_tabs', 'software_tabs', 'peripheral_tabs',
                     'driver_tabs', 'hypervisor_tabs', 'host_os_tabs',
                     'containerizer_tabs', 'guest_os_tabs']:
            for tc in node_config.get(grp, []):
                all_tabs.append(tc)

        for tc in all_tabs:
            card = ctk.CTkFrame(self._config_scroll, fg_color=color("card_bg"),
                                corner_radius=8)
            card.pack(fill=tk.X, pady=3, padx=2)

            title_text = tc.get("title", tc.get("var_name", ""))
            ctk.CTkLabel(card, text=title_text,
                         font=("Segoe UI", 11, "bold"),
                         text_color=color("text_secondary"),
                         anchor="w").pack(fill=tk.X, padx=8, pady=(6, 0))

            val_label = ctk.CTkLabel(card, text="не выбрано",
                                     font=("Segoe UI", 12),
                                     text_color=color("text_muted"),
                                     anchor="w", wraplength=210)
            val_label.pack(fill=tk.X, padx=8, pady=(0, 6))

            self._config_labels[tc["var_name"]] = val_label

        # Fill with current values
        self._update_config_summary()

    def _try_fill_config_label(self, var_name):
        """Tries to fill a single config label from current var state."""
        from utils.theme import color

        if var_name not in self._config_labels:
            return

        label = self._config_labels[var_name]
        value = None

        # Check _var
        var = getattr(self, f"{var_name}_var", None)
        if var and hasattr(var, 'get'):
            raw = var.get().strip()
            if raw:
                # Strip CPE suffix for display
                if "||" in raw:
                    value = raw.split("||")[0].strip()
                else:
                    value = raw

        # Check _selected_items (multi-select CPE)
        if not value:
            items = getattr(self, f"{var_name}_selected_items", None)
            if isinstance(items, list) and items:
                displays = []
                for it in items:
                    if "||" in it:
                        displays.append(it.split("||")[0].strip())
                    else:
                        displays.append(it)
                value = ", ".join(displays)

        # Check _selected (old multi-select)
        if not value:
            items = getattr(self, f"{var_name}_selected", None)
            if isinstance(items, list) and items:
                value = ", ".join(items)

        if value:
            label.configure(text=value, text_color=color("primary"))
        else:
            label.configure(text="не выбрано", text_color=color("text_muted"))

    def _update_config_summary(self):
        """Updates all config summary labels."""
        if not hasattr(self, '_config_labels'):
            return
        for var_name in self._config_labels:
            self._try_fill_config_label(var_name)

    def _add_preset_button(self, parent):
        """Добавляет кнопку с меню пресетов для быстрого заполнения."""
        from config.presets import get_presets_for_type
        from utils.theme import color

        current_type = self.preselected_type if self.preselected_type else "АРМ"
        presets = get_presets_for_type(current_type)
        if not presets:
            return

        self._presets_data = {p["name"]: p["preset"] for p in presets}

        def show_preset_menu():
            menu = tk.Menu(parent, tearoff=0)
            for p in presets:
                name = p["name"]
                menu.add_command(label=name,
                                 command=lambda n=name: self._on_preset_selected(n))
            try:
                btn = self._preset_btn
                menu.tk_popup(btn.winfo_rootx(), btn.winfo_rooty() - len(presets) * 25)
            except Exception:
                pass

        self._preset_btn = ctk.CTkButton(
            parent, text="Загрузить пресет",
            command=show_preset_menu, width=200, height=40,
            fg_color=color("accent"), hover_color=color("accent_hover"),
            text_color="#FFFFFF", corner_radius=10, font=("Segoe UI", 14, "bold")
        )
        self._preset_btn.pack(side=tk.LEFT)

    def _on_preset_selected(self, choice: str):
        """Применяет выбранный пресет: заполняет имя, порты, hardware/software.

        Сохраняет данные пресета в _preset_applied — они будут использованы
        в create_node напрямую, минуя вкладки (потому что вкладки не умеют
        принимать готовые значения извне).
        """
        preset = self._presets_data.get(choice)
        if not preset:
            return

        # Имя узла
        self.node_name_var.set(preset.get("name", ""))

        # Порты
        self.current_ports = [p.copy() for p in preset.get("ports", [])]

        # Запоминаем данные пресета для create_node
        self._preset_applied = {
            "hardware": list(preset.get("hardware", [])),
            "software": list(preset.get("software", [])),
        }

        # Обновляем вкладку «Сеть» чтобы показать новые порты
        try:
            self.update_tabs()
        except Exception:
            pass

        from tkinter import messagebox
        messagebox.showinfo("Пресет загружен",
                            f"Пресет «{choice}» применён.\n"
                            f"Порты: {len(self.current_ports)}\n"
                            f"Hardware: {len(preset.get('hardware', []))}\n"
                            f"Software: {len(preset.get('software', []))}")

    def update_zone_frame(self):
        """Обновляет фрейм выбора зоны (промт-стиль2: dropdown вместо радиокнопок)."""
        from utils.theme import color

        for widget in self.zone_frame.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self.zone_frame, text="Выбор зоны TIM для размещения",
            font=("Segoe UI", 16, "bold"), text_color=color("text_primary"),
            anchor="w"
        ).pack(fill=tk.X)

        current_type = self.preselected_type if self.preselected_type else "АРМ"
        target_zone_type = "free"

        for node_type, config in NODE_CONFIG.items():
            if config["name"] == current_type:
                target_zone_type = config["zone_type"]
                break

        if target_zone_type == "free":
            ctk.CTkLabel(
                self.zone_frame,
                text="Интернет-узел — свободная зона (вне TIM)",
                font=("Segoe UI", 11), text_color=color("text_muted"), anchor="w"
            ).pack(fill=tk.X, pady=(4, 0))
        else:
            tim_zones = self.board.get_tim_zones()
            if tim_zones:
                default_zone_id = self.existing_zone_id if self.is_edit_mode else tim_zones[0].id
                self.zone_var = tk.StringVar(value=default_zone_id)

                # Маппинг display_text → zone_id
                self._zone_map = {}
                values = []
                default_display = ""
                for zone in tim_zones:
                    display_text = zone.get_display_text()
                    if zone.name:
                        display_text += f" - {zone.name}"
                    self._zone_map[display_text] = zone.id
                    values.append(display_text)
                    if zone.id == default_zone_id:
                        default_display = display_text

                self._zone_display_var = tk.StringVar(value=default_display)

                combo = ctk.CTkComboBox(
                    self.zone_frame, values=values,
                    variable=self._zone_display_var,
                    height=36, corner_radius=8,
                    fg_color=color("input_bg"),
                    border_color=color("input_border"),
                    button_color=color("primary"),
                    command=self._on_zone_combo_changed,
                    state="readonly"
                )
                combo.pack(fill=tk.X, pady=(4, 0))
            else:
                ctk.CTkLabel(
                    self.zone_frame, text="Сначала создайте зону TIM!",
                    font=("Segoe UI", 11), text_color=color("danger"), anchor="w"
                ).pack(fill=tk.X, pady=(4, 0))

    def _on_zone_combo_changed(self, choice: str):
        """Обновляет zone_var при выборе зоны из комбобокса."""
        zone_id = getattr(self, '_zone_map', {}).get(choice)
        if zone_id and hasattr(self, 'zone_var'):
            self.zone_var.set(zone_id)

    def update_tabs(self):
        """Обновляет sidebar-навигацию в зависимости от типа узла."""
        # Clear existing sidebar buttons
        for w in self._nav_container.winfo_children():
            w.destroy()
        self._sidebar_buttons = {}
        self._tab_builders = {}
        self._tab_titles = {}

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

        first_key = None

        # --- Hardware tabs ---
        hw_tabs = current_config.get("hardware_tabs", [])
        if hw_tabs:
            for tc in hw_tabs:
                key = f"hw_{tc['var_name']}"
                if first_key is None:
                    first_key = key
                self._tab_titles[key] = tc["title"]
                self._tab_builders[key] = lambda parent, c=tc: self._show_subtab_content(parent, c)
                self._add_sidebar_tab(key, tc["title"], group="hardware")

        if hw_tabs:
            self._add_sidebar_separator()

        # --- Software tabs ---
        sw_tabs = current_config.get("software_tabs", [])
        if sw_tabs:
            for tc in sw_tabs:
                key = f"sw_{tc['var_name']}"
                if first_key is None:
                    first_key = key
                self._tab_titles[key] = tc["title"]
                self._tab_builders[key] = lambda parent, c=tc: self._show_subtab_content(parent, c)
                self._add_sidebar_tab(key, tc["title"], group="software")

        # --- Hypervisor/Host OS/Containerizer/Guest OS tabs ---
        for grp in ['hypervisor_tabs', 'host_os_tabs', 'containerizer_tabs', 'guest_os_tabs']:
            grp_tabs = current_config.get(grp, [])
            if grp_tabs:
                for tc in grp_tabs:
                    key = f"{grp}_{tc['var_name']}"
                    if first_key is None:
                        first_key = key
                    self._tab_titles[key] = tc["title"]
                    self._tab_builders[key] = lambda parent, c=tc: self._show_subtab_content(parent, c)
                    self._add_sidebar_tab(key, tc["title"], group=grp)

        if sw_tabs or any(current_config.get(g) for g in ['hypervisor_tabs', 'host_os_tabs', 'containerizer_tabs', 'guest_os_tabs']):
            self._add_sidebar_separator()

        # --- Peripheral tabs ---
        per_tabs = current_config.get("peripheral_tabs", [])
        if per_tabs:
            for tc in per_tabs:
                key = f"per_{tc['var_name']}"
                if first_key is None:
                    first_key = key
                self._tab_titles[key] = tc["title"]
                # Peripheral tabs use paginated_combo (no cpe_filter)
                self._tab_builders[key] = lambda parent, c=tc: self._build_peripheral_tab(parent, c)
                self._add_sidebar_tab(key, tc["title"], group="peripheral")

        if per_tabs:
            self._add_sidebar_separator()

        # --- Network tab ---
        if current_node_type != "Internet":
            key = "network"
            if first_key is None:
                first_key = key
            self._tab_titles[key] = "Сеть"
            self._tab_builders[key] = lambda parent, c=current_config: self.create_network_tab(parent, c)
            self._add_sidebar_tab(key, "Сеть", group="network")

        # Show first tab
        if first_key:
            self._show_tab(first_key)

    def _build_peripheral_tab(self, parent, config):
        """Builds a peripheral tab content (uses paginated_combo)."""
        items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
        self.create_paginated_combo(parent, config["title"], items, config["var_name"])

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

    def _styled_subtabview(self, parent):
        """Создаёт подвкладки с фоном под палитру."""
        from utils.theme import color as _tc
        tv = ctk.CTkTabview(parent, fg_color=_tc("dialog_bg"),
                             segmented_button_fg_color=_tc("card_bg"),
                             segmented_button_selected_color=_tc("primary"),
                             segmented_button_unselected_color=_tc("card_bg"))
        tv.pack(fill=tk.BOTH, expand=True)
        # Текст вкладок — чёрный на светлой теме, белый на тёмной
        try:
            tv._segmented_button.configure(
                font=("Segoe UI", 12, "bold"),
                text_color=("#111827", "#E2E8F0")
            )
        except Exception:
            pass
        return tv

    def _create_tab_widget(self, frame, config):
        """Выбирает виджет: CPE-браузер если есть cpe_filter, иначе старый список."""
        if "cpe_filter" in config:
            current_value = None
            if self.is_edit_mode:
                current_value = self.get_current_selection_for_tab({"var_name": config["var_name"]})
            self.create_cpe_browser(frame, config, current_value)
        else:
            items = self.cached_data.get(self.current_node_type_key, {}).get(config["var_name"], [])
            if config.get("multiple", False):
                self.create_multi_select_combo(frame, config["title"], items, config["var_name"])
            else:
                self.create_paginated_combo(frame, config["title"], items, config["var_name"])

    def create_hardware_tabs(self, parent, hardware_configs):
        """Stub — logic moved to sidebar navigation."""
        pass

    def create_software_tabs(self, parent, software_configs):
        """Stub — logic moved to sidebar navigation."""
        pass

    def create_peripheral_tabs(self, parent, peripheral_configs):
        """Stub — logic moved to sidebar navigation."""
        pass

    def create_cpe_browser(self, parent, config, current_value=None):
        """Создаёт иерархический CPE-браузер.

        Поддерживает:
        - Семейства (families) → 4 уровня: Vendor → Family → Model → Version
        - Без семейств → 3 уровня: Vendor → Product → Version
        - multiple=True → мультивыбор с кнопкой "Добавить" и списком выбранных
        - Ленивая загрузка для табов без vendors_filter (не грузить 34K вендоров)
        """
        from utils.theme import color as _tc
        from utils.styled_dropdown import StyledDropdown

        var_name = config["var_name"]
        title = config["title"]
        cpe_filter = config["cpe_filter"]
        part = cpe_filter.get("part")
        vendors_filter = cpe_filter.get("vendors")
        families_map = cpe_filter.get("families")
        p_like = cpe_filter.get("product_like")
        p_not_like = cpe_filter.get("product_not_like")
        has_families = bool(families_map)
        is_multiple = config.get("multiple", False)

        frame = ctk.CTkFrame(parent, fg_color=_tc("surface"),
                              border_width=1, border_color=_tc("card_border"),
                              corner_radius=8)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text=title, font=("Segoe UI", 14, "bold"),
                      text_color=_tc("text_primary")).pack(anchor=tk.W, padx=12, pady=(10, 12))

        # Software categories support
        software_categories = config.get("software_categories")
        if software_categories:
            cat_frame = ctk.CTkFrame(frame, fg_color="transparent")
            cat_frame.pack(fill=tk.X, padx=12, pady=(0, 8))
            ctk.CTkLabel(cat_frame, text="Категория:", font=("Segoe UI", 12, "bold"),
                         text_color=_tc("text_primary")).pack(anchor=tk.W, pady=(0, 4))
            cat_names = [c["name"] for c in software_categories]
            cat_var = tk.StringVar(value=cat_names[0] if cat_names else "")

            def _on_category_change(choice):
                for cat in software_categories:
                    if cat["name"] == choice:
                        new_filter = cat["filter"]
                        nonlocal vendors_filter, families_map, p_like, p_not_like, has_families
                        vendors_filter = new_filter.get("vendors")
                        families_map = new_filter.get("families")
                        p_like = new_filter.get("product_like")
                        p_not_like = new_filter.get("product_not_like")
                        has_families = bool(families_map)
                        # Reload vendors
                        new_vendors = self.db.get_vendors(part=part, vendors_filter=vendors_filter)
                        vendor_cb.configure(values=new_vendors)
                        _clear_selection()
                        break

            ctk.CTkComboBox(cat_frame, values=cat_names, variable=cat_var,
                           height=32, corner_radius=6,
                           fg_color=_tc("input_bg"), border_color=_tc("input_border"),
                           button_color=_tc("primary"),
                           command=_on_category_change,
                           state="readonly").pack(fill=tk.X)

        # Для single-select: одна переменная
        # Для multi-select: список выбранных + переменная текущего выбора
        if is_multiple:
            selected_items = []
            # Загрузить ранее выбранные при редактировании
            if self.is_edit_mode:
                existing = self.get_current_selection_for_tab(
                    {"var_name": var_name, "multiple": True})
                if isinstance(existing, list):
                    selected_items.extend(existing)
                elif existing:
                    selected_items.append(existing)
            var = tk.StringVar()
            setattr(self, f"{var_name}_var", var)
            setattr(self, f"{var_name}_selected_items", selected_items)
        else:
            var = tk.StringVar(value=current_value if current_value else "")
            setattr(self, f"{var_name}_var", var)

        cpe_state = {"vendor": "", "family_prefix": "", "product": "", "version": ""}

        def _make_step(parent_frame, label_text):
            sf = ctk.CTkFrame(parent_frame, fg_color="transparent")
            ctk.CTkLabel(sf, text=label_text, font=("Segoe UI", 12, "bold"),
                          text_color=_tc("text_primary")).pack(anchor=tk.W, pady=(0, 4))
            v = tk.StringVar()
            cb = StyledDropdown(sf, variable=v)
            cb.pack(fill=tk.X)
            cl = ctk.CTkLabel(sf, text="", font=("Segoe UI", 10), text_color=_tc("text_muted"))
            cl.pack(anchor=tk.W, pady=(2, 0))
            return sf, v, cb, cl

        # --- Контейнер шагов ---
        steps_container = ctk.CTkFrame(frame, fg_color="transparent")
        steps_container.pack(fill=tk.X, padx=12, pady=(0, 4))

        # === 1. Производитель ===
        vendor_f, vendor_var, vendor_cb, vendor_hint = _make_step(steps_container, "1. Производитель")
        vendor_f.pack(fill=tk.X, pady=(0, 6))

        # === 2-4. Семейство / Продукт / Версия (all visible at once) ===
        if has_families:
            family_f, family_var, family_cb, family_cnt = _make_step(steps_container, "2. Семейство")
            family_f.pack(fill=tk.X, pady=(0, 6))
            product_f, product_var, product_cb, product_cnt = _make_step(steps_container, "3. Модель")
            product_f.pack(fill=tk.X, pady=(0, 6))
            version_f, version_var, version_cb, version_cnt = _make_step(steps_container, "4. Версия")
            version_f.pack(fill=tk.X, pady=(0, 6))
        else:
            family_f = family_var = family_cb = family_cnt = None
            product_f, product_var, product_cb, product_cnt = _make_step(steps_container, "2. Продукт")
            product_f.pack(fill=tk.X, pady=(0, 6))
            version_f, version_var, version_cb, version_cnt = _make_step(steps_container, "3. Версия")
            version_f.pack(fill=tk.X, pady=(0, 6))

        # === Нижняя панель ===
        bottom = ctk.CTkFrame(frame, fg_color="transparent")
        bottom.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 10))

        if is_multiple:
            # --- Кнопка "Добавить" + строка текущего выбора ---
            add_row = ctk.CTkFrame(bottom, fg_color="transparent")
            add_row.pack(fill=tk.X, pady=(0, 6))

            selected_label = ctk.CTkLabel(add_row, text="не выбрано",
                                           font=("Segoe UI", 11),
                                           text_color=_tc("text_muted"))
            selected_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

            add_btn = ctk.CTkButton(add_row, text="＋ Добавить", width=100, height=28,
                                     fg_color=_tc("primary"), hover_color=_tc("primary_hover"),
                                     text_color="#FFFFFF")
            add_btn.pack(side=tk.RIGHT, padx=(8, 0))

            # --- Список выбранных ---
            ctk.CTkLabel(bottom, text="Выбранные компоненты:",
                          font=("Segoe UI", 11, "bold"),
                          text_color=_tc("text_primary")).pack(anchor=tk.W, pady=(4, 2))

            items_scroll = ctk.CTkScrollableFrame(bottom, fg_color=_tc("input_bg"),
                                                    height=120)
            items_scroll.pack(fill=tk.BOTH, expand=True)

            def _refresh_items_list():
                for w in items_scroll.winfo_children():
                    w.destroy()
                for idx, item in enumerate(selected_items):
                    row = ctk.CTkFrame(items_scroll, fg_color="transparent")
                    row.pack(fill=tk.X, pady=1)
                    ctk.CTkLabel(row, text=f"• {item}", font=("Segoe UI", 11),
                                  text_color=_tc("text_primary"),
                                  anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
                    ctk.CTkButton(row, text="✕", width=24, height=24,
                                   fg_color=_tc("ghost_bg"),
                                   hover_color=_tc("danger"),
                                   text_color=_tc("text_primary"),
                                   command=lambda i=idx: _remove_item(i)).pack(side=tk.RIGHT)

            def _remove_item(idx):
                if 0 <= idx < len(selected_items):
                    selected_items.pop(idx)
                    _refresh_items_list()

            def _add_current():
                display = var.get().strip()
                if display and display not in selected_items:
                    selected_items.append(display)
                    _refresh_items_list()
                    # Сбросить выбор для следующего добавления
                    _clear_selection()

            add_btn.configure(command=_add_current)
            _refresh_items_list()
        else:
            # --- Single select: просто "Выбрано: ..." ---
            sel_row = ctk.CTkFrame(bottom, fg_color="transparent")
            sel_row.pack(fill=tk.X)

            ctk.CTkLabel(sel_row, text="Выбрано:", font=("Segoe UI", 12, "bold"),
                          text_color=_tc("text_primary")).pack(side=tk.LEFT, padx=(0, 8))
            selected_label = ctk.CTkLabel(sel_row,
                                           text=current_value if current_value else "не выбрано",
                                           font=("Segoe UI", 12),
                                           text_color="#22C55E" if current_value else _tc("text_muted"))
            selected_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

            ctk.CTkButton(sel_row, text="✕ Сбросить", width=80, height=28,
                           fg_color=_tc("ghost_bg"), hover_color=_tc("ghost_hover"),
                           text_color=_tc("text_primary"),
                           command=lambda: _clear_selection()).pack(side=tk.RIGHT)

        def _show_step(step_frame):
            if not step_frame.winfo_manager():
                step_frame.pack(fill=tk.X, pady=(0, 6))

        def _hide_from(level):
            """Clears values from level onwards (keeps frames visible)."""
            if level <= 2 and family_var:
                family_var.set("")
                if family_cb:
                    family_cb.configure(values=[])
            if level <= 3:
                product_var.set("")
                product_cb.configure(values=[])
            if level <= 4:
                version_var.set("")
                version_cb.configure(values=[])

        def _clear_selection():
            var.set("")
            vendor_var.set("")
            if family_var:
                family_var.set("")
            product_var.set("")
            version_var.set("")
            cpe_state.update({"vendor": "", "family_prefix": "", "product": "", "version": ""})
            _hide_from(2)
            selected_label.configure(text="не выбрано", text_color=_tc("text_muted"))

        def _update_display():
            v, p, ver = cpe_state["vendor"], cpe_state["product"], cpe_state["version"]
            if v and p:
                display = f"{v.replace('_', ' ').title()} {p.replace('_', ' ').title()}"
                if ver:
                    display += f" {ver}"
                # CPE-суффикс встраивается прямо в строку: ||vendor|product|version
                # Паспорт безопасности парсит этот суффикс для точного поиска CVE
                cpe_suffix = f"||{v}|{p}|{ver}"
                var.set(display + cpe_suffix)
                selected_label.configure(text=display, text_color="#22C55E")
            self._update_config_summary()

        # --- Загрузка вендоров ---
        vendors = self.db.get_vendors(part=part, vendors_filter=vendors_filter)
        vendor_cb.configure(values=vendors)

        def _on_vendor(*_):
            vendor = vendor_var.get().strip()
            if not vendor:
                return
            cpe_state.update({"vendor": vendor, "family_prefix": "", "product": "", "version": ""})
            if family_var:
                family_var.set("")
            product_var.set("")
            version_var.set("")
            _hide_from(2)

            if has_families and vendor in families_map:
                fam_list = families_map[vendor]
                fam_data = self.db.get_product_families(vendor, part=part, family_prefixes=fam_list)
                display_values = [f"{name} ({cnt})" for name, prefix, cnt in fam_data]
                self._family_map = {f"{name} ({cnt})": prefix for name, prefix, cnt in fam_data}
                family_cb.configure(values=display_values)
                family_cnt.configure(text=f"{len(fam_data)} семейств")
                _show_step(family_f)
            else:
                products = self.db.get_products(vendor, part=part,
                                                 product_like=p_like, product_not_like=p_not_like)
                product_cb.configure(values=products)
                product_cnt.configure(text=f"{len(products)} продуктов")
                _show_step(product_f)

        def _on_family(*_):
            if not family_var:
                return
            selected = family_var.get().strip()
            if not selected:
                return
            prefix = getattr(self, '_family_map', {}).get(selected, "")
            if not prefix:
                return
            cpe_state.update({"family_prefix": prefix, "product": "", "version": ""})
            product_var.set("")
            version_var.set("")
            version_cb.configure(values=[])

            products = self.db.get_products_by_prefix(cpe_state["vendor"], prefix, part=part,
                                                       product_like=p_like, product_not_like=p_not_like)
            product_cb.configure(values=products)
            product_cnt.configure(text=f"{len(products)} моделей")
            _show_step(product_f)

        def _on_product(*_):
            product = product_var.get().strip()
            vendor = cpe_state["vendor"]
            if not product or not vendor:
                return
            cpe_state.update({"product": product, "version": ""})
            version_var.set("")

            versions = self.db.get_versions(vendor, product)
            version_cb.configure(values=versions)
            version_cnt.configure(text=f"{len(versions)} версий")
            _update_display()

        def _on_version(*_):
            version = version_var.get().strip()
            if version:
                cpe_state["version"] = version
                _update_display()

        vendor_var.trace("w", _on_vendor)
        if family_var:
            family_var.trace("w", _on_family)
        product_var.trace("w", _on_product)
        version_var.trace("w", _on_version)

    def create_paginated_combo(self, parent, title, items, var_name, current_value=None):
        """Создаёт комбобокс с поиском и пагинацией."""
        from utils.theme import color as _tc
        frame = ctk.CTkFrame(parent, fg_color=_tc("surface"),
                              border_width=1, border_color=_tc("card_border"),
                              corner_radius=8)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text=title, font=("Segoe UI", 14, "bold"),
                      text_color=_tc("text_primary")).pack(anchor=tk.W, padx=10, pady=(10, 10))

        if current_value is None and self.is_edit_mode:
            current_value = self.get_current_selection_for_tab({"var_name": var_name})

        var = tk.StringVar(value=current_value if current_value else "")
        setattr(self, f"{var_name}_var", var)

        # Поиск
        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, padx=8, pady=(0, 10))

        ctk.CTkLabel(search_frame, text="🔍 Поиск:", font=("Segoe UI", 12),
                      text_color=_tc("text_secondary")).pack(side=tk.LEFT, padx=(0, 5))
        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var,
                      placeholder_text="Введите текст для поиска...",
                      fg_color=_tc("input_bg"), border_color=_tc("input_border"),
                      border_width=1).pack(side=tk.LEFT, fill=tk.X, expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)} шт.)", font=("Segoe UI", 10), text_color="gray")
        count_label.pack(side=tk.RIGHT, padx=(5, 0))

        # Список (высота ограничена чтобы обводка фрейма не обрезалась)
        list_frame = ctk.CTkFrame(frame, fg_color="transparent")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 8))

        text_list = ctk.CTkTextbox(list_frame, wrap="none", height=280,
                                    fg_color=_tc("input_bg"),
                                    text_color=_tc("text_primary"))
        text_list.pack(fill=tk.BOTH, expand=True)
        text_list.configure(cursor="hand2")

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
        selected_frame.pack(fill=tk.X, padx=8, pady=(10, 8))

        ctk.CTkLabel(selected_frame, text="✅ Выбрано:", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=(0, 5))
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
        from utils.theme import color as _tc
        frame = ctk.CTkFrame(parent, fg_color=_tc("surface"),
                              border_width=1, border_color=_tc("card_border"),
                              corner_radius=8)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text=title, font=("Segoe UI", 14, "bold"),
                      text_color=_tc("text_primary")).pack(anchor=tk.W, padx=10, pady=(10, 10))

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
        columns_frame.pack(fill=tk.BOTH, expand=True, padx=8)

        # === Левая колонка: доступные ===
        left_frame = ctk.CTkFrame(columns_frame, fg_color=_tc("card_bg"),
                                   border_width=1, border_color=_tc("card_border"),
                                   corner_radius=8)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        ctk.CTkLabel(left_frame, text="Доступные:", font=("Segoe UI", 12, "bold"),
                      text_color=_tc("text_primary")).pack(anchor=tk.W, padx=8, pady=(8, 5))

        search_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, padx=8, pady=(0, 5))

        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="Поиск...", height=30).pack(
            side=tk.LEFT, fill=tk.X, expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)})", font=("Segoe UI", 10), text_color="gray")
        count_label.pack(side=tk.RIGHT, padx=(5, 0))

        available_text = ctk.CTkTextbox(left_frame, wrap="none", height=250,
                                         fg_color=_tc("input_bg"),
                                         text_color=_tc("text_primary"))
        available_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        available_text.configure(cursor="hand2")

        # Множество выбранных строк в левом списке (для подсветки)
        _left_selected = set()

        def _populate_available(data):
            available_text.configure(state="normal")
            available_text.delete("1.0", "end")
            for item in data:
                available_text.insert("end", item + "\n")
            # Подсветка уже выбранных
            _left_selected.clear()
            for i, item in enumerate(data, 1):
                if item in selected_items:
                    available_text.tag_add("chosen", f"{i}.0", f"{i}.0 lineend")
            available_text.tag_config("chosen", background="#d0e8ff", foreground="#1a5276")
            available_text.configure(state="disabled")

        _populate_available(items)

        # === Правая колонка: выбранные ===
        right_frame = ctk.CTkFrame(columns_frame, fg_color=_tc("card_bg"),
                                    border_width=1, border_color=_tc("card_border"),
                                    corner_radius=8)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ctk.CTkLabel(right_frame, text="Выбранные:", font=("Segoe UI", 12, "bold"),
                      text_color=_tc("text_primary")).pack(anchor=tk.W, padx=8, pady=(8, 5))

        selected_text = ctk.CTkTextbox(right_frame, wrap="none", height=250,
                                        fg_color=_tc("input_bg"),
                                        text_color=_tc("text_primary"))
        selected_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        selected_text.configure(cursor="hand2")

        # Индекс выбранной строки в правом списке
        _right_sel_line = [0]

        def _populate_selected():
            selected_text.configure(state="normal")
            selected_text.delete("1.0", "end")
            for item in selected_items:
                selected_text.insert("end", item + "\n")
            selected_text.configure(state="disabled")

        _populate_selected()

        # Клик по левому списку — подсветка
        def _on_left_click(event):
            try:
                index = available_text.index(f"@{event.x},{event.y}")
                line = available_text.get(f"{index} linestart", f"{index} lineend").strip()
                line_num = int(index.split('.')[0])
                if line:
                    available_text.configure(state="normal")
                    available_text.tag_remove("selected", "1.0", "end")
                    available_text.tag_add("selected", f"{line_num}.0", f"{line_num}.0 lineend")
                    available_text.tag_config("selected", background="#d0e8ff", foreground="#1a5276")
                    available_text.configure(state="disabled")
                    _left_selected.clear()
                    _left_selected.add(line)
            except (tk.TclError, ValueError):
                pass

        available_text.bind("<Button-1>", _on_left_click)

        # Клик по правому списку — подсветка
        def _on_right_click(event):
            try:
                index = selected_text.index(f"@{event.x},{event.y}")
                line = selected_text.get(f"{index} linestart", f"{index} lineend").strip()
                line_num = int(index.split('.')[0])
                if line:
                    selected_text.configure(state="normal")
                    selected_text.tag_remove("selected", "1.0", "end")
                    selected_text.tag_add("selected", f"{line_num}.0", f"{line_num}.0 lineend")
                    selected_text.tag_config("selected", background="#d0e8ff", foreground="#1a5276")
                    selected_text.configure(state="disabled")
                    _right_sel_line[0] = line_num
            except (tk.TclError, ValueError):
                pass

        selected_text.bind("<Button-1>", _on_right_click)

        # Фильтрация
        def filter_list(*args):
            search_text = search_var.get().lower()
            if search_text:
                filtered = [item for item in items if search_text in item.lower()]
                count_label.configure(text=f"({len(filtered)}/{len(items)})", text_color="blue")
            else:
                filtered = items
                count_label.configure(text=f"({len(items)})", text_color="gray")
            _populate_available(filtered)

        search_var.trace('w', filter_list)

        # Статус
        status_label = ctk.CTkLabel(
            frame,
            text=f"Выбрано: {len(selected_items)}" if selected_items else "Выбрано: 0",
            font=("Segoe UI", 11, "bold"),
            text_color="green" if selected_items else "gray"
        )

        def update_status():
            if selected_items:
                status_label.configure(text=f"Выбрано: {len(selected_items)}", text_color="green")
            else:
                status_label.configure(text="Выбрано: 0", text_color="gray")

        # Кнопки
        def add_selected():
            for item in list(_left_selected):
                if item and item not in selected_items:
                    selected_items.append(item)
            _left_selected.clear()
            _populate_selected()
            filter_list()  # обновить подсветку в левом
            update_status()

        def remove_selected():
            line_num = _right_sel_line[0]
            if 1 <= line_num <= len(selected_items):
                selected_items.pop(line_num - 1)
                _right_sel_line[0] = 0
                _populate_selected()
                filter_list()
                update_status()

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, padx=8, pady=(10, 8))

        ctk.CTkButton(btn_frame, text="Добавить >>", command=add_selected,
                      width=120, height=30).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(btn_frame, text="<< Удалить", command=remove_selected,
                      width=120, height=30, fg_color="#c0392b", hover_color="#e74c3c").pack(side=tk.LEFT, padx=5)

        status_label.pack(in_=btn_frame, side=tk.RIGHT, padx=10)

    # ========================================================================
    # ВКЛАДКА СЕТИ
    # ========================================================================

    def create_network_tab(self, parent, config):
        """Создаёт вкладку с настройками сети.

        Промт 9 №6: современный стиль — акцентная полоска сверху секции,
        theme-aware цвета, цветные hover-кнопки. Основано на палитре
        `utils.theme`.
        """
        from utils import theme

        surface_bg = theme.color("dialog_bg")
        card_bg = theme.color("card_bg")
        border_clr = theme.color("card_border")
        primary = theme.color("primary")
        primary_hover = theme.color("primary_hover")
        accent = theme.color("accent")
        accent_hover = theme.color("accent_hover")
        text_primary = theme.color("text_primary")
        text_muted = theme.color("text_muted")

        # Основной фрейм с прокруткой
        main_frame = ctk.CTkFrame(parent, fg_color=surface_bg)
        main_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_frame, bg=self._get_canvas_bg_color(), highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ctk.CTkFrame(canvas, fg_color=surface_bg)

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

        # Секция с сетевыми портами — card с выделяющейся обводкой, без синей полосы
        ports_frame = ctk.CTkFrame(scrollable_frame, fg_color=card_bg,
                                    border_width=2, border_color=primary, corner_radius=10)
        ports_frame.pack(fill=tk.X, padx=14, pady=14)

        # Заголовок секции
        header = ctk.CTkFrame(ports_frame, fg_color="transparent")
        header.pack(fill=tk.X, padx=16, pady=(12, 4))
        ctk.CTkLabel(
            header, text="🔌 Сетевые порты",
            font=("Segoe UI", 15, "bold"), text_color=text_primary, anchor="w"
        ).pack(side=tk.LEFT)
        ctk.CTkLabel(
            header,
            text="IP, MAC, VLAN и роли Wi-Fi",
            font=("Segoe UI", 10), text_color=text_muted, anchor="w"
        ).pack(side=tk.LEFT, padx=(12, 0))

        # Сабконтейнеры прозрачные — чтобы не было разнотонности
        self.ports_container = ctk.CTkFrame(ports_frame, fg_color="transparent")
        self.ports_container.pack(fill=tk.X, padx=16, pady=(4, 10))

        # Разделитель перед «Добавить»
        ctk.CTkFrame(ports_frame, fg_color=border_clr, height=1).pack(fill=tk.X, padx=16, pady=4)

        # Кнопка добавления порта
        add_frame = ctk.CTkFrame(ports_frame, fg_color="transparent")
        add_frame.pack(fill=tk.X, padx=16, pady=(8, 10))

        ctk.CTkLabel(add_frame, text="Добавить порт:",
                      font=("Segoe UI", 12, "bold"), text_color=text_primary).pack(side=tk.LEFT, padx=(0, 10))

        self.new_port_type = tk.StringVar(value="ethernet")

        ctk.CTkRadioButton(add_frame, text="🔌 RJ45", variable=self.new_port_type, value="ethernet").pack(side=tk.LEFT,
                                                                                                         padx=4)
        ctk.CTkRadioButton(add_frame, text="🔆 PON", variable=self.new_port_type, value="pon").pack(side=tk.LEFT, padx=4)
        ctk.CTkRadioButton(add_frame, text="📶 Wi-Fi", variable=self.new_port_type, value="wifi").pack(side=tk.LEFT,
                                                                                                      padx=4)
        ctk.CTkRadioButton(add_frame, text="🔌 USB", variable=self.new_port_type, value="usb").pack(side=tk.LEFT, padx=4)

        ctk.CTkButton(
            add_frame, text="➕ Добавить",
            command=self.add_new_port, width=110, height=32,
            fg_color=primary, hover_color=primary_hover,
            corner_radius=8, font=("Segoe UI", 12, "bold")
        ).pack(side=tk.RIGHT)

        # Кнопка тестовых данных
        test_frame = ctk.CTkFrame(ports_frame, fg_color="transparent")
        test_frame.pack(fill=tk.X, padx=16, pady=(0, 12))
        ctk.CTkButton(
            test_frame, text="🧪 Тестовые данные",
            command=self.fill_test_data, width=160, height=32,
            fg_color=accent, hover_color=accent_hover,
            corner_radius=8, font=("Segoe UI", 12)
        ).pack(side=tk.RIGHT)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.display_ports()

    def _get_canvas_bg_color(self):
        from utils import theme
        return theme.c("dialog_bg")

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
            ctk.CTkLabel(self.ports_container, text="🔌 RJ45 порты:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W,
                                                                                                      pady=(5, 2))
            for port in eth_ports:
                self.create_port_widget(port)

        if pon_ports:
            ctk.CTkLabel(self.ports_container, text="🔆 PON порты:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W,
                                                                                                     pady=(10, 2))
            for port in pon_ports:
                self.create_port_widget(port)

        if wifi_ports:
            ctk.CTkLabel(self.ports_container, text="📶 Wi-Fi порты:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W,
                                                                                                       pady=(10, 2))
            for port in wifi_ports:
                self.create_wifi_port_widget(port)

        if usb_ports:
            ctk.CTkLabel(self.ports_container, text="🔌 USB порты:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W,
                                                                                                     pady=(10, 2))
            for port in usb_ports:
                self.create_port_widget(port, show_network=False)

    def create_port_widget(self, port: Dict, show_network: bool = True):
        """Создаёт виджет для порта."""
        from utils.theme import color as _tc
        _inp = {"fg_color": _tc("input_bg"), "border_color": _tc("input_border"), "border_width": 1}

        frame = ctk.CTkFrame(self.ports_container, fg_color="transparent")
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

            ctk.CTkEntry(frame, textvariable=mac_var, width=120, placeholder_text="MAC", **_inp).pack(side=tk.LEFT, padx=2)
            ctk.CTkEntry(frame, textvariable=ip_var, width=110, placeholder_text="IP", **_inp).pack(side=tk.LEFT, padx=2)
            ctk.CTkLabel(frame, text="/", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
            ctk.CTkEntry(frame, textvariable=mask_var, width=50, placeholder_text="маска", **_inp).pack(side=tk.LEFT,
                                                                                                padx=(2, 5))
            ctk.CTkLabel(frame, text="|", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=2)
            ctk.CTkEntry(frame, textvariable=vlan_id_var, width=60, placeholder_text="VLAN", **_inp).pack(side=tk.LEFT, padx=2)
            ctk.CTkComboBox(frame, values=["untagged", "tagged"], variable=vlan_mode_var, width=90,
                            fg_color=_tc("input_bg"), border_color=_tc("input_border"),
                            button_color=_tc("primary")).pack(side=tk.LEFT, padx=2)
        else:
            ctk.CTkLabel(frame, text="(USB порт)").pack(side=tk.LEFT, padx=2)

        if not is_busy:
            ctk.CTkButton(frame, text="✕", width=30, command=lambda p=port: self.remove_port(p["port_id"])).pack(
                side=tk.RIGHT, padx=5)

    def create_wifi_port_widget(self, port: Dict):
        """Создаёт виджет для Wi-Fi порта."""
        from utils.theme import color as _tc
        _inp = {"fg_color": _tc("input_bg"), "border_color": _tc("input_border"), "border_width": 1}

        frame = ctk.CTkFrame(self.ports_container, fg_color="transparent")
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

        ctk.CTkEntry(fields_frame, textvariable=mac_var, width=120, placeholder_text="MAC", **_inp).pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(fields_frame, textvariable=ip_var, width=110, placeholder_text="IP", **_inp).pack(side=tk.LEFT, padx=2)
        ctk.CTkLabel(fields_frame, text="/", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
        ctk.CTkEntry(fields_frame, textvariable=mask_var, width=50, placeholder_text="маска", **_inp).pack(side=tk.LEFT,
                                                                                                   padx=(2, 5))
        ctk.CTkLabel(fields_frame, text="|", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(fields_frame, textvariable=vlan_id_var, width=60, placeholder_text="VLAN", **_inp).pack(side=tk.LEFT,
                                                                                                     padx=2)
        ctk.CTkComboBox(fields_frame, values=["untagged", "tagged"], variable=vlan_mode_var, width=90,
                        fg_color=_tc("input_bg"), border_color=_tc("input_border"),
                        button_color=_tc("primary")).pack(
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

            # WiFi-клиенты и USB не обязаны иметь IP/маску
            is_wifi_client = (port["port_type"] == "wifi" and
                              port.get("wifi_role", "client") == "client")

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

            if required["ip"] and not ip and not is_wifi_client:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать IP-адрес!")
                return False
            if ip and not validate_ip(ip):
                messagebox.showerror("Ошибка",
                                     f"Неверный формат IP-адреса для порта {port['name']}!\nФормат: 192.168.1.1")
                return False

            if required["mask"] and not mask and not is_wifi_client:
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

        # Позиция узла.
        # Промт 9 №4: если в режиме редактирования пользователь сменил зону,
        # пересчитываем позицию на центр новой зоны — иначе узел визуально
        # остаётся «висеть» по старым координатам до первого клика.
        if self.is_edit_mode:
            old_zone_id = self.existing_node.zone.id if self.existing_node.zone else None
            if selected_zone and old_zone_id != selected_zone.id:
                node_position = self.board.get_next_free_position(selected_zone)
            else:
                node_position = self.existing_node.position
        else:
            node_position = self.board.get_next_free_position(selected_zone)

        # Собираем компоненты
        properties = {"hardware": [], "software": [], "network": []}

        # Если применён пресет — берём данные из него напрямую
        if hasattr(self, '_preset_applied') and self._preset_applied:
            properties["hardware"] = list(self._preset_applied.get("hardware", []))
            properties["software"] = list(self._preset_applied.get("software", []))
        else:
            # Иначе — собираем из вкладок через _var переменные
            node_config = NODE_CONFIG.get(node_type_en, {})
            hardware_items = []
            software_items = []

            # Белый список префиксов для сбора (чтобы zone_var и прочее не попадало)
            _skip_prefixes = ("node_", "zone_", "_zone", "connection_",
                              "new_port", "wifi_config", "preset", "interface_",
                              "action_", "direction_", "protocol_", "metric_",
                              "client_", "server_", "notify_", "status_",
                              "search_", "count_")

            for attr_name in dir(self):
                if attr_name.endswith('_var'):
                    if any(attr_name.startswith(p) for p in _skip_prefixes):
                        continue
                    var = getattr(self, attr_name, None)
                    if var is None or not hasattr(var, 'get'):
                        continue
                    value = var.get()
                    if not value or not isinstance(value, str) or not value.strip():
                        continue

                    # Определяем prefix из конфига если доступен
                    base = attr_name.replace('_var', '')
                    saved = False

                    # Ищем prefix в конфиге
                    for grp in ['hardware_tabs', 'software_tabs', 'peripheral_tabs',
                                'driver_tabs', 'hypervisor_tabs', 'host_os_tabs',
                                'containerizer_tabs', 'guest_os_tabs']:
                        for tc in node_config.get(grp, []):
                            if tc.get("var_name") == base and tc.get("prefix"):
                                pfx = tc["prefix"]
                                if grp in ('hardware_tabs',):
                                    hardware_items.append(f"{pfx}: {value}")
                                else:
                                    software_items.append(f"{pfx}: {value}")
                                saved = True
                                break
                        if saved:
                            break

                    if not saved:
                        # Fallback на старую логику
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

                # Множественный выбор (старый формат _selected)
                if attr_name.endswith('_selected') and not attr_name.startswith('_'):
                    selected_list = getattr(self, attr_name, None)
                    if isinstance(selected_list, list):
                        for value in selected_list:
                            if value:
                                if "app" in attr_name:
                                    software_items.append(f"Приложение: {value}")
                                else:
                                    software_items.append(value)

                # Множественный выбор (CPE-браузер _selected_items)
                if attr_name.endswith('_selected_items') and not attr_name.startswith('_'):
                    selected_list = getattr(self, attr_name, None)
                    if isinstance(selected_list, list):
                        for value in selected_list:
                            if not value:
                                continue
                            # Определяем prefix по var_name
                            base = attr_name.replace('_selected_items', '')
                            if "app" in base or "software" in base:
                                software_items.append(f"Приложение: {value}")
                            elif "storage" in base or "hdd" in base:
                                hardware_items.append(f"HDD/SSD: {value}")
                            elif "nic" in base or "network" in base:
                                hardware_items.append(f"Сетевой адаптер: {value}")
                            elif "cpu" in base or "processor" in base:
                                hardware_items.append(f"Процессор: {value}")
                            else:
                                software_items.append(value)

            properties["hardware"] = hardware_items
            properties["software"] = software_items

        # Сохраняем CPE-маппинг для точного поиска CVE в паспорте
        if hasattr(self, '_cpe_map') and self._cpe_map:
            properties["cpe_map"] = dict(self._cpe_map)

        # Сбрасываем кеш паспорта при изменении компонентов
        properties.pop("security_passport_cache", None)

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
            node.position = node_position  # обновляем координаты под (возможно новую) зону
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