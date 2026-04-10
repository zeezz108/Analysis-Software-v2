"""
Модуль диалога редактирования свойств

Содержит класс PropertiesDialog для редактирования:
- Зон TIM
- Узлов (аппаратура, ПО, сеть, безопасность)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import time
from typing import Dict, List, Optional, Any
import tkinter as tk
from typing import List
from models.zone import Zone
from models.node import Node
from models.route import Route
from models.firewall import FirewallManager
from database.cve_db import CVEDatabase
from utils.cache import DataCache
from utils.validators import validate_ip, validate_mac, validate_mask, validate_vlan_id
from utils.generators import generate_test_ip, generate_test_mac, generate_test_mask
from config.node_config import NODE_CONFIG, get_node_type_russian
from dialogs.routing_dialog import RoutingTableDialog
from dialogs.security_passport_dialog import SecurityPassportDialog
from dialogs.node_dialog import NodeCreationDialog
from typing import Dict


class PropertiesDialog:
    """Диалог редактирования свойств зоны или узла."""

    def __init__(self, parent, title: str, element, element_type: str):
        self.parent = parent
        self.element = element
        self.element_type = element_type
        self.port_edit_vars = {}
        self.wifi_role_vars = {}
        self.hardware_combos = {}
        self.software_combos = {}
        self.current_ports = []
        self.cached_data = {}
        self.loading_active = False
        self.db = None
        self.cache = DataCache()

        # Для сервера виртуализации
        self.virtualization_type = "hypervisor"
        if isinstance(element, Node) and hasattr(element, 'editing_context'):
            if 'virtualization_type' in element.editing_context:
                self.virtualization_type = element.editing_context['virtualization_type']
                del element.editing_context['virtualization_type']

        # Создаём окно
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Редактирование: {title}")

        if isinstance(element, Zone):
            self.dialog.geometry("600x400")
        else:
            self.dialog.geometry("1100x900")

        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        if isinstance(element, Node):
            self.current_ports = [port.copy() for port in self.element.ports]

            try:
                self.db = CVEDatabase()
                if self.cache.is_loaded():
                    self.load_from_cache()
                    self.create_widgets()
                else:
                    self.show_loading_screen()
                    self.dialog.after(100, self.load_data_async)
            except FileNotFoundError:
                messagebox.showwarning("Предупреждение",
                                       "❌ База данных CVE не найдена!\nРедактирование компонентов будет недоступно.")
                self.create_widgets()
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к БД: {str(e)}")
                self.create_widgets()
        else:
            self.create_widgets()

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

    def load_from_cache(self):
        """Загружает данные из кэша."""
        node_type = self.element.type
        config = self.get_node_config()

        for tab_config in config.get("hardware_tabs", []):
            cache_key = f"{node_type}_{tab_config['var_name']}"
            self.cached_data[tab_config["var_name"]] = self.cache.get(cache_key, lambda: [])

        for tab_config in config.get("software_tabs", []):
            cache_key = f"{node_type}_{tab_config['var_name']}"
            self.cached_data[tab_config["var_name"]] = self.cache.get(cache_key, lambda: [])

    def show_loading_screen(self):
        """Показывает экран загрузки."""
        self.loading_frame = ctk.CTkFrame(self.dialog)
        self.loading_frame.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)

        ctk.CTkLabel(
            self.loading_frame, text=f"Загрузка данных для {self.element.name}...",
            font=("Arial", 18, "bold")
        ).pack(pady=(0, 20))

        self.animation_label = ctk.CTkLabel(
            self.loading_frame, text="⏳", font=("Arial", 48, "bold"), text_color="#2196F3"
        )
        self.animation_label.pack(pady=20)

        self.status_label = ctk.CTkLabel(
            self.loading_frame, text="Подключение к базе данных CVE...",
            font=("Arial", 13), text_color="gray"
        )
        self.status_label.pack(pady=(0, 20))

        self.progress = ctk.CTkProgressBar(self.loading_frame, width=350)
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.loading_active = True
        self.animate_loading(0)

    def animate_loading(self, idx):
        if self.loading_active:
            chars = ["⏳", "⌛", "⏳", "⌛"]
            colors = ["#2196F3", "#FF9800", "#4CAF50", "#F44336"]
            try:
                if hasattr(self, 'animation_label') and self.animation_label.winfo_exists():
                    self.animation_label.configure(text=chars[idx % len(chars)], text_color=colors[idx % len(colors)])
                    self.dialog.after(100, lambda: self.animate_loading(idx + 1))
            except:
                pass

    def load_data_async(self):
        """Асинхронная загрузка данных."""

        def load_thread():
            try:
                if self.cache.is_loaded():
                    self.dialog.after(0, self.finish_loading)
                    return

                node_type = self.element.type
                config = self.get_node_config()

                for tab_config in config.get("hardware_tabs", []):
                    cache_key = f"{node_type}_{tab_config['var_name']}"
                    method = getattr(self.db, tab_config["method"], None)
                    if method:
                        items = self.cache.get(cache_key, method)
                        self.cached_data[tab_config["var_name"]] = items

                for tab_config in config.get("software_tabs", []):
                    cache_key = f"{node_type}_{tab_config['var_name']}"
                    method = getattr(self.db, tab_config["method"], None)
                    if method:
                        items = self.cache.get(cache_key, method)
                        self.cached_data[tab_config["var_name"]] = items

                self.cache.set_loaded()
                self.dialog.after(0, self.finish_loading)

            except Exception as e:
                self.dialog.after(0, lambda: self.show_load_error(str(e)))

        thread = threading.Thread(target=load_thread, daemon=True)
        thread.start()

    def finish_loading(self):
        self.loading_active = False
        try:
            if hasattr(self, 'progress') and self.progress.winfo_exists():
                self.progress.stop()
        except:
            pass
        try:
            if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
                self.loading_frame.destroy()
        except:
            pass
        try:
            if self.dialog.winfo_exists():
                self.create_widgets()
        except Exception as e:
            print(f"Ошибка при создании интерфейса: {e}")

    def show_load_error(self, error_msg):
        self.loading_active = False
        messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить данные:\n{error_msg}")
        try:
            if self.dialog.winfo_exists():
                self.create_widgets()
        except:
            pass

    def get_node_config(self) -> Dict:
        """Возвращает конфигурацию для текущего типа узла."""
        return NODE_CONFIG.get(self.element.type, NODE_CONFIG["ARM"])

    def get_current_selection(self, tab_config: Dict) -> str:
        """Получает текущее выбранное значение для вкладки."""
        properties = self.element.properties
        var_name = tab_config["var_name"]

        component_mapping = {
            "processor": "Процессор", "gpu": "Видеоконтроллер",
            "motherboard": "Материнская плата", "hdd": "HDD/SSD",
            "server_ram": "Оперативная память", "os": "ОС", "server_os": "ОС",
            "vmware": "Гипервизор", "hyperv": "Гипервизор",
            "mouse": "Мышь", "keyboard": "Клавиатура",
            "printer": "Принтер", "monitor": "Монитор"
        }

        prefix = component_mapping.get(var_name, "")
        if not prefix:
            return ""

        for item in properties.get("hardware", []):
            if item.startswith(f"{prefix}:"):
                return item.replace(f"{prefix}:", "").strip()

        for item in properties.get("software", []):
            if item.startswith(f"{prefix}:"):
                return item.replace(f"{prefix}:", "").strip()

        return ""

    def create_widgets(self):
        """Создаёт основной интерфейс."""
        temp_frame = ctk.CTkFrame(self.dialog)
        frame_color = temp_frame.cget("fg_color")
        temp_frame.destroy()
        self.dialog.configure(fg_color=frame_color)

        if isinstance(self.element, Zone):
            self.create_zone_widgets()
        else:
            self.create_node_widgets()

        self.center_window()

    def create_zone_widgets(self):
        """Создаёт интерфейс для редактирования зоны."""
        # Заголовок
        ctk.CTkLabel(
            self.dialog, text=f"Редактирование зоны: {self.element.name}",
            font=("Arial", 18, "bold")
        ).pack(pady=(15, 15))

        # Название
        name_frame = ctk.CTkFrame(self.dialog)
        name_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

        ctk.CTkLabel(name_frame, text="Название зоны:", font=("Arial", 14, "bold")).pack(anchor=tk.W, padx=10,
                                                                                         pady=(10, 5))
        self.name_var = tk.StringVar(value=self.element.name)
        ctk.CTkEntry(name_frame, textvariable=self.name_var, height=35).pack(fill=tk.X, padx=10, pady=(0, 10))

        # Описание
        desc_frame = ctk.CTkFrame(self.dialog)
        desc_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        ctk.CTkLabel(desc_frame, text="Описание зоны:", font=("Arial", 14, "bold")).pack(anchor=tk.W, padx=10,
                                                                                         pady=(10, 5))
        self.desc_var = tk.StringVar(value=self.element.description or "")
        ctk.CTkEntry(desc_frame, textvariable=self.desc_var, height=35).pack(fill=tk.X, padx=10, pady=(0, 10))

        # Кнопки
        button_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

        ctk.CTkButton(button_frame, text="Сохранить", command=self.save_zone, fg_color="#4CAF50", width=100,
                      height=35).pack(side=tk.RIGHT, padx=5)
        ctk.CTkButton(button_frame, text="Отмена", command=self.dialog.destroy, fg_color="#CD3333", width=100,
                      height=35).pack(side=tk.RIGHT, padx=5)

    def create_node_widgets(self):
        """Создаёт интерфейс для редактирования узла."""
        # Заголовок
        ctk.CTkLabel(
            self.dialog, text=f"Редактирование: {get_node_type_russian(self.element.type)} - {self.element.name}",
            font=("Arial", 18, "bold")
        ).pack(pady=(15, 10))

        # Имя узла
        name_frame = ctk.CTkFrame(self.dialog)
        name_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

        ctk.CTkLabel(name_frame, text="Имя узла:", font=("Arial", 14, "bold")).pack(anchor=tk.W, padx=10, pady=(5, 2))
        self.node_name_var = tk.StringVar(value=self.element.name)
        ctk.CTkEntry(name_frame, textvariable=self.node_name_var, height=35).pack(fill=tk.X, padx=10, pady=(0, 10))

        # Вкладки
        self.notebook = ctk.CTkTabview(self.dialog)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        config = self.get_node_config()

        # Аппаратная архитектура
        if config.get("hardware_tabs"):
            self.notebook.add("Аппаратная архитектура")
            hw_frame = self.notebook.tab("Аппаратная архитектура")
            self.create_hardware_editor(hw_frame, config["hardware_tabs"])

        # Программное обеспечение
        if config.get("software_tabs"):
            self.notebook.add("Программное обеспечение")
            sw_frame = self.notebook.tab("Программное обеспечение")
            self.create_software_editor(sw_frame, config["software_tabs"])

        # Сеть — не показываем для узла Интернет
        if self.element.type != "Internet":
            self.notebook.add("Сеть")
            net_frame = self.notebook.tab("Сеть")
            self.create_network_editor(net_frame, config)

        # Маршрутизация
        self.notebook.add("Маршрутизация")
        route_frame = self.notebook.tab("Маршрутизация")
        self.create_routing_tab(route_frame)

        # Безопасность
        self.notebook.add("Безопасность")
        sec_frame = self.notebook.tab("Безопасность")
        self.create_security_editor(sec_frame)

        # Кнопки
        button_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        button_frame.pack(fill=tk.X, padx=20, pady=(10, 20))

        if self.element.type in ["ARM", "Laptop", "Router", "Switch", "Server"]:
            ctk.CTkButton(button_frame, text="Паспорт безопасности", command=self.open_security_passport,
                          width=150).pack(side=tk.LEFT, padx=5)

        ctk.CTkButton(button_frame, text="Сохранить", command=self.save_node, fg_color="#4CAF50", width=100,
                      height=35).pack(side=tk.RIGHT, padx=5)
        ctk.CTkButton(button_frame, text="Отмена", command=self.dialog.destroy, fg_color="#CD3333", width=100,
                      height=35).pack(side=tk.RIGHT, padx=5)

    def create_hardware_editor(self, parent, hardware_configs: List[Dict]):
        """Создаёт редактор аппаратной части."""
        if len(hardware_configs) > 1:
            tabview = ctk.CTkTabview(parent)
            tabview.pack(fill=tk.BOTH, expand=True)
            for config in hardware_configs:
                tabview.add(config["title"])
                frame = tabview.tab(config["title"])
                items = self.cached_data.get(config["var_name"], [])
                current_value = self.get_current_selection(config)
                self.create_combo_selector(frame, config["title"], items, config["var_name"], current_value,
                                           is_hardware=True)
        else:
            config = hardware_configs[0]
            items = self.cached_data.get(config["var_name"], [])
            current_value = self.get_current_selection(config)
            self.create_combo_selector(parent, config["title"], items, config["var_name"], current_value,
                                       is_hardware=True)

    def create_software_editor(self, parent, software_configs: List[Dict]):
        """Создаёт редактор программного обеспечения."""
        if len(software_configs) > 1:
            tabview = ctk.CTkTabview(parent)
            tabview.pack(fill=tk.BOTH, expand=True)
            for config in software_configs:
                tabview.add(config["title"])
                frame = tabview.tab(config["title"])
                items = self.cached_data.get(config["var_name"], [])
                current_value = self.get_current_selection(config)
                self.create_combo_selector(frame, config["title"], items, config["var_name"], current_value,
                                           is_hardware=False)
        else:
            config = software_configs[0]
            items = self.cached_data.get(config["var_name"], [])
            current_value = self.get_current_selection(config)
            self.create_combo_selector(parent, config["title"], items, config["var_name"], current_value,
                                       is_hardware=False)

    def create_combo_selector(self, parent, title: str, items: List[str], var_name: str, current_value: str = "",
                              is_hardware: bool = True):
        """Создаёт комбобокс с поиском."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text=title, font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))

        var = tk.StringVar(value=current_value)
        if is_hardware:
            self.hardware_combos[var_name] = var
        else:
            self.software_combos[var_name] = var

        # Поиск
        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill=tk.X, pady=(0, 10))

        search_var = tk.StringVar()
        ctk.CTkEntry(search_frame, textvariable=search_var, placeholder_text="🔍 Поиск...").pack(side=tk.LEFT, fill=tk.X,
                                                                                                expand=True)

        count_label = ctk.CTkLabel(search_frame, text=f"({len(items)})", font=("Arial", 10), text_color="gray")
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
                for item in items:
                    text_list.insert("end", item + "\n")
                count_label.configure(text=f"({len(items)})", text_color="gray")
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

        # Выбранное значение
        selected_frame = ctk.CTkFrame(frame, fg_color="transparent")
        selected_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkLabel(selected_frame, text="Выбрано:", font=("Arial", 11, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        selected_label = ctk.CTkLabel(selected_frame, text=current_value if current_value else "не выбрано",
                                      text_color="green" if current_value else "gray")
        selected_label.pack(side=tk.LEFT)

        if current_value:
            ctk.CTkButton(selected_frame, text="✕ Очистить",
                          command=lambda: [var.set(""), selected_label.configure(text="не выбрано", text_color="gray")],
                          width=80, height=25).pack(side=tk.RIGHT)

        var.trace('w', lambda *args: selected_label.configure(text=var.get() if var.get() else "не выбрано",
                                                              text_color="green" if var.get() else "gray"))

    def create_network_editor(self, parent, config: Dict):
        """Создаёт редактор сети."""
        # Основной фрейм с прокруткой
        main_frame = ctk.CTkFrame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_frame, bg=self._get_canvas_bg_color(), highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ctk.CTkFrame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Прокрутка
        def on_mousewheel(event):
            try:
                if canvas.winfo_exists():
                    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            except:
                pass

        canvas.bind_all("<MouseWheel>", on_mousewheel)

        # Порты
        ports_frame = ctk.CTkFrame(scrollable_frame)
        ports_frame.pack(fill=tk.X, padx=10, pady=10)

        ctk.CTkLabel(ports_frame, text="🔌 Сетевые порты", font=("Arial", 14, "bold")).pack(anchor=tk.W, padx=10,
                                                                                           pady=(10, 5))

        ports_container = ctk.CTkFrame(ports_frame)
        ports_container.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Отображаем порты
        eth_ports = [p for p in self.current_ports if p["port_type"] == "ethernet"]
        pon_ports = [p for p in self.current_ports if p["port_type"] == "pon"]
        wifi_ports = [p for p in self.current_ports if p["port_type"] == "wifi"]
        usb_ports = [p for p in self.current_ports if p["port_type"] == "usb"]

        if eth_ports:
            ctk.CTkLabel(ports_container, text="🔌 RJ45 порты:", font=("Arial", 12, "bold")).pack(anchor=tk.W,
                                                                                                 pady=(5, 2))
            for port in eth_ports:
                self.create_port_editor_widget(ports_container, port)

        if pon_ports:
            ctk.CTkLabel(ports_container, text="🔆 PON порты:", font=("Arial", 12, "bold")).pack(anchor=tk.W,
                                                                                                pady=(10, 2))
            for port in pon_ports:
                self.create_port_editor_widget(ports_container, port)

        if wifi_ports:
            ctk.CTkLabel(ports_container, text="📶 Wi-Fi порты:", font=("Arial", 12, "bold")).pack(anchor=tk.W,
                                                                                                  pady=(10, 2))
            for port in wifi_ports:
                self.create_wifi_port_editor_widget(ports_container, port, config)

        if usb_ports:
            ctk.CTkLabel(ports_container, text="🔌 USB порты:", font=("Arial", 12, "bold")).pack(anchor=tk.W,
                                                                                                pady=(10, 2))
            for port in usb_ports:
                self.create_port_editor_widget(ports_container, port, show_network=False)

        # Кнопка добавления порта
        add_frame = ctk.CTkFrame(ports_frame)
        add_frame.pack(fill=tk.X, padx=10, pady=(10, 10))

        ctk.CTkLabel(add_frame, text="Добавить порт:", font=("Arial", 12)).pack(side=tk.LEFT, padx=(0, 5))

        self.new_port_type = tk.StringVar(value="ethernet")
        ctk.CTkRadioButton(add_frame, text="RJ45", variable=self.new_port_type, value="ethernet").pack(side=tk.LEFT,
                                                                                                       padx=2)
        ctk.CTkRadioButton(add_frame, text="PON", variable=self.new_port_type, value="pon").pack(side=tk.LEFT, padx=2)
        ctk.CTkRadioButton(add_frame, text="Wi-Fi", variable=self.new_port_type, value="wifi").pack(side=tk.LEFT,
                                                                                                    padx=2)
        ctk.CTkRadioButton(add_frame, text="USB", variable=self.new_port_type, value="usb").pack(side=tk.LEFT, padx=2)

        ctk.CTkButton(add_frame, text="➕ Добавить", command=self.add_port_to_node, width=100).pack(side=tk.RIGHT)

        # Тестовые данные
        test_frame = ctk.CTkFrame(ports_frame)
        test_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        ctk.CTkButton(test_frame, text="🧪 Тестовые данные", command=self.fill_test_data).pack(side=tk.RIGHT)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _get_canvas_bg_color(self) -> str:
        return "#2b2b2b" if ctk.get_appearance_mode() == "Dark" else "#ffffff"

    def create_port_editor_widget(self, parent, port: Dict, show_network: bool = True):
        """Создаёт виджет для редактирования порта."""
        frame = ctk.CTkFrame(parent)
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

            self.port_edit_vars[port["port_id"]] = {"mac": mac_var, "ip": ip_var, "mask": mask_var,
                                                    "vlan_id": vlan_id_var, "vlan_mode": vlan_mode_var, "port": port}

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
            ctk.CTkButton(frame, text="✕", width=30, command=lambda p=port: self.remove_port_from_node(p)).pack(
                side=tk.RIGHT, padx=5)

    def create_wifi_port_editor_widget(self, parent, port: Dict, config: Dict):
        """Создаёт виджет для редактирования Wi-Fi порта."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.X, pady=2)

        wifi_caps = config.get("wifi_capabilities", {})

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
                               command=lambda: self.update_wifi_port_role(port["port_id"], role_var.get())).pack(
                side=tk.LEFT, padx=2)
            ctk.CTkRadioButton(role_frame, text="Client", value="client", variable=role_var,
                               command=lambda: self.update_wifi_port_role(port["port_id"], role_var.get())).pack(
                side=tk.LEFT, padx=2)

        fields_frame = ctk.CTkFrame(frame, fg_color="transparent")
        fields_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        mac_var = tk.StringVar(value=port.get("mac_address", ""))
        ip_var = tk.StringVar(value=port.get("ip_address", ""))
        mask_var = tk.StringVar(value=port.get("subnet_mask", ""))
        vlan_id_var = tk.StringVar(value=str(port.get("vlan_id", "")) if port.get("vlan_id") else "")
        vlan_mode_var = tk.StringVar(value=port.get("vlan_mode", "untagged"))

        self.port_edit_vars[port["port_id"]] = {"mac": mac_var, "ip": ip_var, "mask": mask_var, "vlan_id": vlan_id_var,
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
            ctk.CTkButton(frame, text="✕", width=30, command=lambda p=port: self.remove_port_from_node(p)).pack(
                side=tk.RIGHT, padx=5)

    def update_wifi_port_role(self, port_id: str, new_role: str):
        for port in self.current_ports:
            if port["port_id"] == port_id:
                port["wifi_role"] = new_role
                break

    def add_port_to_node(self):
        """Добавляет новый порт."""
        port_type = self.new_port_type.get()
        existing_ports = [p for p in self.current_ports if p["port_type"] == port_type]
        next_number = len(existing_ports) + 1

        new_port = {"port_id": f"{port_type}_{next_number}", "port_type": port_type, "port_number": next_number}

        if port_type == "ethernet":
            new_port.update(
                {"name": f"ETH{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "connected_to": None, "connected_port": None})
        elif port_type == "pon":
            new_port.update(
                {"name": f"PON{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "connected_to": None, "connected_port": None})
        elif port_type == "wifi":
            new_port.update(
                {"name": f"WiFi{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "wifi_role": "client", "connected_clients": [], "connected_to_ap": None})
        else:
            new_port.update(
                {"name": f"USB{next_number}", "ip_address": "", "mac_address": "", "subnet_mask": "", "vlan_id": None,
                 "vlan_mode": "untagged", "connected_to": None, "connected_port": None})

        self.current_ports.append(new_port)
        self.dialog.destroy()
        self.create_widgets()

    def remove_port_from_node(self, port: Dict):
        if messagebox.askyesno("Удаление порта", f"Удалить порт {port['name']}?"):
            self.current_ports = [p for p in self.current_ports if p["port_id"] != port["port_id"]]
            self.dialog.destroy()
            self.create_widgets()

    def fill_test_data(self):
        for port_id, vars_dict in self.port_edit_vars.items():
            vars_dict["mac"].set(generate_test_mac())
            vars_dict["ip"].set(generate_test_ip())
            vars_dict["mask"].set(generate_test_mask())

    def create_routing_tab(self, parent):
        """Создаёт вкладку маршрутизации."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="📋 Таблица маршрутизации", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))

        routes_count = len(self.element.routing_table) if hasattr(self.element, 'routing_table') else 0
        ctk.CTkLabel(frame, text=f"Маршрутов в таблице: {routes_count}", font=("Arial", 12)).pack(anchor=tk.W,
                                                                                                  pady=(0, 10))

        ctk.CTkButton(frame, text="📋 Открыть редактор маршрутизации", command=self.open_routing_editor, height=40,
                      font=("Arial", 12, "bold")).pack(fill=tk.X, pady=10)

        # Предпросмотр
        if routes_count > 0:
            preview_frame = ctk.CTkFrame(frame)
            preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)

            ctk.CTkLabel(preview_frame, text="Предпросмотр (первые 5 записей):", font=("Arial", 12, "bold")).pack(
                anchor=tk.W)

            preview_text = ctk.CTkTextbox(preview_frame, height=150)
            preview_text.pack(fill=tk.BOTH, expand=True, pady=5)

            header = f"{'Сеть':<20} {'Маска':<15} {'Шлюз':<15} {'Интерфейс':<10} Метрика\n"
            preview_text.insert("1.0", header)
            preview_text.insert("end", "-" * 70 + "\n")

            for route_data in self.element.routing_table[:5]:
                route = Route.from_dict(route_data)
                line = f"{route.destination:<20} {route.netmask:<15} {route.gateway:<15} {route.interface:<10} {route.metric}\n"
                preview_text.insert("end", line)

            preview_text.configure(state="disabled")

    def open_routing_editor(self):
        if not hasattr(self.element, 'routing_table'):
            self.element.routing_table = []
        dialog = RoutingTableDialog(self.dialog, self.element)
        self.dialog.wait_window(dialog.dialog)
        self.dialog.destroy()
        self.create_widgets()

    def create_security_editor(self, parent):
        """Создаёт вкладку безопасности."""
        frame = ctk.CTkFrame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="🛡️ Настройки файервола", font=("Arial", 14, "bold")).pack(anchor=tk.W, pady=(0, 10))

        self.firewall_var = tk.BooleanVar(value=self.element.firewall_enabled)
        ctk.CTkCheckBox(frame, text="Включить файервол", variable=self.firewall_var, font=("Arial", 13)).pack(
            anchor=tk.W, pady=5)

        ctk.CTkLabel(frame, text="При включении файервола над узлом будет отображаться иконка щита", font=("Arial", 11),
                     text_color="gray").pack(anchor=tk.W, pady=(10, 0))

    def validate_network_fields(self) -> bool:
        """Проверяет заполнение сетевых полей."""
        required = self.element.get_required_network_fields()

        for port in self.current_ports:
            if port["port_type"] not in ["ethernet", "pon", "wifi"]:
                continue

            port_id = port["port_id"]

            if port_id in self.port_edit_vars:
                mac = self.port_edit_vars[port_id]["mac"].get().strip()
                ip = self.port_edit_vars[port_id]["ip"].get().strip()
                mask = self.port_edit_vars[port_id]["mask"].get().strip()
                vlan_id = self.port_edit_vars[port_id]["vlan_id"].get().strip()
                vlan_mode = self.port_edit_vars[port_id]["vlan_mode"].get().strip()
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
                messagebox.showerror("Ошибка", f"Неверный MAC для порта {port['name']}!\nФормат: 00:11:22:33:44:55")
                return False

            if required["ip"] and not ip:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать IP-адрес!")
                return False
            if ip and not validate_ip(ip):
                messagebox.showerror("Ошибка", f"Неверный IP для порта {port['name']}!\nФормат: 192.168.1.1")
                return False

            if required["mask"] and not mask:
                messagebox.showerror("Ошибка", f"Для порта {port['name']} необходимо указать маску подсети!")
                return False
            if mask and not validate_mask(mask):
                messagebox.showerror("Ошибка", f"Неверная маска для порта {port['name']}!\nФормат: число от 0 до 32")
                return False

            if vlan_id and not validate_vlan_id(vlan_id, vlan_mode):
                if vlan_mode == "untagged":
                    error_msg = f"Неверный VLAN для порта {port['name']}!\nДля 'untagged' разрешён ОДИН VLAN ID!\nПример: 100"
                else:
                    error_msg = f"Неверный VLAN для порта {port['name']}!\nДля 'tagged' доступны:\n• Один VLAN: 100\n• Несколько: 10,20,30\n• Диапазон: 100-200"
                messagebox.showerror("Ошибка", error_msg)
                return False

        return True

    def save_zone(self):
        """Сохраняет изменения зоны."""
        self.element.name = self.name_var.get().strip()
        self.element.description = self.desc_var.get().strip()
        self.dialog.destroy()

    def save_node(self):
        """Сохраняет изменения узла."""
        # Имя узла
        new_name = self.node_name_var.get().strip()
        if new_name:
            self.element.name = new_name

        # Файервол
        old_state = self.element.firewall_enabled
        self.element.firewall_enabled = self.firewall_var.get()
        if old_state != self.element.firewall_enabled and "firewall" in self.element.properties:
            self.element.properties["firewall"]["firewall_enabled"] = self.element.firewall_enabled

        # Порты
        for port_id, vars_dict in self.port_edit_vars.items():
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

        self.element.ports = self.current_ports

        # Аппаратные и программные компоненты
        hardware_items = []
        software_items = []
        config = self.get_node_config()

        for tab_config in config.get("hardware_tabs", []):
            var_name = tab_config["var_name"]
            if var_name in self.hardware_combos:
                value = self.hardware_combos[var_name].get().strip()
                if value:
                    if "Процессор" in tab_config["title"]:
                        hardware_items.append(f"Процессор: {value}")
                    elif "Видеоконтроллер" in tab_config["title"]:
                        hardware_items.append(f"Видеоконтроллер: {value}")
                    elif "Память" in tab_config["title"]:
                        hardware_items.append(f"Оперативная память: {value}")
                    elif "Диски" in tab_config["title"] or "Хранилище" in tab_config["title"]:
                        hardware_items.append(f"HDD/SSD: {value}")
                    else:
                        hardware_items.append(value)

        for tab_config in config.get("software_tabs", []):
            var_name = tab_config["var_name"]
            if var_name in self.software_combos:
                value = self.software_combos[var_name].get().strip()
                if value:
                    if "Операционн" in tab_config["title"] or "ОС" in tab_config["title"]:
                        software_items.append(f"ОС: {value}")
                    elif "Прикладное ПО" in tab_config["title"]:
                        software_items.append(f"Приложение: {value}")
                    else:
                        software_items.append(value)

        if hardware_items:
            self.element.properties["hardware"] = hardware_items
        if software_items:
            self.element.properties["software"] = software_items

        messagebox.showinfo("Успех", f"✅ Свойства узла {self.element.name} сохранены!")
        self.dialog.destroy()

    def open_security_passport(self):
        try:
            SecurityPassportDialog(self.parent, self.element)
        except FileNotFoundError:
            messagebox.showerror("Ошибка", "❌ База данных CVE не найдена!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть паспорт: {str(e)}")


class ViewOnlyPropertiesDialog:
    """Диалог просмотра свойств узла (только для чтения) с кнопкой редактирования."""

    def __init__(self, parent, node: Node, board, canvas_view):
        self.parent = parent
        self.node = node
        self.board = board
        self.canvas_view = canvas_view

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Свойства узла: {node.name}")
        self.dialog.geometry("850x750")
        self.dialog.resizable(True, True)
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

    def get_node_type_russian(self, node_type_en: str) -> str:
        from config.node_config import NODE_TYPE_RUSSIAN
        return NODE_TYPE_RUSSIAN.get(node_type_en, node_type_en)

    def _get_neighbor_info(self, port: Dict) -> tuple:
        """Возвращает информацию о соседе для порта (имя, ip, маска, имя_порта)."""
        connected_to = port.get("connected_to")
        if not connected_to:
            return (None, None, None)

        neighbor = self.board.find_node(connected_to)
        if not neighbor:
            return (None, None, None)

        connected_port_id = port.get("connected_port")
        neighbor_ip = ""
        neighbor_mask = ""
        neighbor_port_name = ""

        if connected_port_id:
            for n_port in neighbor.ports:
                if n_port.get("port_id") == connected_port_id:
                    neighbor_ip = n_port.get("ip_address", "")
                    neighbor_mask = n_port.get("subnet_mask", "")
                    neighbor_port_name = n_port.get("name", "")
                    break

        return (neighbor.name, neighbor_ip, neighbor_mask, neighbor_port_name)

    def _get_all_components(self) -> Dict[str, List[Dict]]:
        """Собирает все компоненты узла в структурированном виде с метаданными."""

        result = {
            "🖥️ Аппаратная архитектура": [],
            "💿 Прикладное ПО": [],
            "🖱️ Периферия": [],
            "🌐 Сетевые порты": []
        }

        # Префиксы для классификации
        hardware_prefixes = (
            "Процессор:", "Видеоконтроллер:", "Материнская плата:",
            "HDD/SSD:", "Аппаратная платформа:", "Оперативная память:",
            "Диск:", "Сетевая карта:", "Платформа:"
        )
        peripheral_prefixes = ("Мышь:", "Клавиатура:", "Принтер:", "Монитор:")
        software_prefixes = ("ОС:", "Приложение:")

        peripheral_categories = {
            "Мышь": [],
            "Клавиатура": [],
            "Принтер/МФУ": [],
            "Монитор": []
        }

        def categorize_by_prefix(item: str):
            """Классифицирует элемент по его префиксу."""
            if item.startswith("Мышь:"):
                peripheral_categories["Мышь"].append(item)
                return True
            elif item.startswith("Клавиатура:"):
                peripheral_categories["Клавиатура"].append(item)
                return True
            elif item.startswith("Принтер:"):
                peripheral_categories["Принтер/МФУ"].append(item)
                return True
            elif item.startswith("Монитор:"):
                peripheral_categories["Монитор"].append(item)
                return True
            return False

        # 1. Аппаратная архитектура
        hardware_items = self.node.properties.get("hardware", [])
        for item in hardware_items:
            if item and isinstance(item, str) and item.strip():
                result["🖥️ Аппаратная архитектура"].append({"text": item, "type": "hardware"})

        # 2. Программное обеспечение и периферия
        software_items = self.node.properties.get("software", [])
        for item in software_items:
            if item and isinstance(item, str) and item.strip():
                item_lower = item.lower()
                # Периферия по префиксу
                if categorize_by_prefix(item):
                    continue
                # Пропускаем драйверы
                if "драйвер" in item_lower or "driver" in item_lower:
                    continue
                # Прикладное ПО
                display_text = item
                if item.startswith("Приложение:"):
                    display_text = item.replace("Приложение:", "Прикладное ПО:", 1)
                result["💿 Прикладное ПО"].append({"text": display_text, "type": "software"})

        # 3. Периферия
        for category, items in peripheral_categories.items():
            if items:
                for item in items:
                    result["🖱️ Периферия"].append({"text": item, "category": category})

        # 4. Сетевые порты
        print(f"[DEBUG] Node ports: {self.node.ports}")
        for port in self.node.ports:
            port_type = port.get("port_type", "unknown")
            port_name = port.get("name", "?")
            mac = port.get("mac_address", "")
            ip = port.get("ip_address", "")
            mask = port.get("subnet_mask", "")
            vlan_id = port.get("vlan_id", "")
            vlan_mode = port.get("vlan_mode", "untagged")

            port_data = {
                "name": port_name,
                "type": port_type,
                "mac": mac,
                "ip": ip,
                "mask": mask,
                "vlan_id": vlan_id,
                "vlan_mode": vlan_mode,
                "connected": port.get("connected_to") is not None
            }

            neighbor_info = self._get_neighbor_info(port)
            if neighbor_info[0]:
                port_data["neighbor_name"] = neighbor_info[0]
                port_data["neighbor_ip"] = neighbor_info[1]
                port_data["neighbor_mask"] = neighbor_info[2]
                port_data["neighbor_port"] = neighbor_info[3]

            result["🌐 Сетевые порты"].append(port_data)

        print(f"[DEBUG] Final result ports count: {len(result['🌐 Сетевые порты'])}")
        print(f"[DEBUG] _get_all_components END")
        return result

    def create_widgets(self):
        print("[DEBUG] create_widgets START")

        # Заголовок
        title_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        title_frame.pack(fill=tk.X, padx=25, pady=(15, 5))

        type_icons = {
            "Router": "📡",
            "Switch": "🔌",
            "Server": "🖥️",
            "ARM": "💻",
            "Laptop": "📓",
            "Internet": "🌐",
            "VirtualizationServer": "☁️"
        }
        icon = type_icons.get(self.node.type, "📦")

        header_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        header_frame.pack(fill=tk.X)

        ctk.CTkLabel(
            header_frame,
            text=f"{icon} {self.node.name}",
            font=("Segoe UI", 24, "bold"),
            text_color="#1E88E5"
        ).pack(anchor=tk.W)

        ctk.CTkLabel(
            header_frame,
            text=f"Тип: {self.get_node_type_russian(self.node.type)}",
            font=("Segoe UI", 13),
            text_color="gray"
        ).pack(anchor=tk.W, pady=(2, 0))

        has_status = self.node.firewall_enabled or self.node.vpn_client_enabled or self.node.vpn_server_enabled
        if has_status:
            status_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
            status_frame.pack(anchor=tk.W, pady=(5, 0))

            if self.node.firewall_enabled:
                ctk.CTkLabel(
                    status_frame,
                    text="🛡️ Файервол включён",
                    font=("Segoe UI", 11),
                    text_color="#4CAF50"
                ).pack(side=tk.LEFT, padx=(0, 10))

            if self.node.vpn_client_enabled or self.node.vpn_server_enabled:
                vpn_text = "🔒 VPN клиент" if self.node.vpn_client_enabled else "🔒 VPN сервер" if self.node.vpn_server_enabled else ""
                if vpn_text:
                    ctk.CTkLabel(
                        status_frame,
                        text=vpn_text,
                        font=("Segoe UI", 11),
                        text_color="#FF9800"
                    ).pack(side=tk.LEFT)

        separator = ctk.CTkFrame(self.dialog, height=2, fg_color="#1E88E5")
        separator.pack(fill=tk.X, padx=25, pady=(5, 10))

        main_scroll_frame = ctk.CTkScrollableFrame(self.dialog, fg_color="transparent")
        main_scroll_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=(0, 10))

        components = self._get_all_components()

        for category, items in components.items():
            if not items:
                continue

            if ctk.get_appearance_mode() == "Dark":
                card_bg = "#2D2D2D"
            else:
                card_bg = "#F8F9FA"

            category_card = ctk.CTkFrame(main_scroll_frame, fg_color=card_bg, corner_radius=12)
            category_card.pack(fill=tk.X, pady=(0, 12))

            header_frame_cat = ctk.CTkFrame(category_card, fg_color="transparent")
            header_frame_cat.pack(fill=tk.X, padx=20, pady=(15, 10))

            ctk.CTkLabel(
                header_frame_cat,
                text=category,
                font=("Segoe UI", 16, "bold"),
                text_color="#1E88E5"
            ).pack(anchor=tk.W)

            ctk.CTkFrame(category_card, height=1, fg_color="#CCCCCC").pack(fill=tk.X, padx=20, pady=(0, 10))

            content_frame = ctk.CTkFrame(category_card, fg_color="transparent")
            content_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

            for idx, item in enumerate(items):
                print(f"[DEBUG] Item {idx} in {category}: {item}")
                if category == "🌐 Сетевые порты":
                    self._create_port_widget(content_frame, item)
                else:
                    self._create_component_widget(content_frame, item)

            ctk.CTkFrame(main_scroll_frame, height=5, fg_color="transparent").pack()

        has_any_data = any(components.values())
        if not has_any_data:
            empty_frame = ctk.CTkFrame(main_scroll_frame, fg_color="#F8F9FA", corner_radius=12)
            empty_frame.pack(fill=tk.BOTH, expand=True, pady=50, padx=50)

            ctk.CTkLabel(
                empty_frame,
                text="📭 Нет данных о конфигурации узла",
                font=("Segoe UI", 16),
                text_color="gray"
            ).pack(expand=True)

        btn_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        btn_frame.pack(fill=tk.X, padx=25, pady=(0, 20))

        ctk.CTkButton(
            btn_frame,
            text="✏️ Редактировать",
            command=self.open_edit_dialog,
            fg_color="#1E88E5",
            hover_color="#1565C0",
            width=140,
            height=42,
            font=("Segoe UI", 14, "bold"),
            corner_radius=8
        ).pack(side=tk.RIGHT, padx=5)

        ctk.CTkButton(
            btn_frame,
            text="✕ Закрыть",
            command=self.dialog.destroy,
            fg_color="#757575",
            hover_color="#616161",
            width=110,
            height=42,
            font=("Segoe UI", 13),
            corner_radius=8
        ).pack(side=tk.RIGHT, padx=5)

        print("[DEBUG] create_widgets END")

    def _create_component_widget(self, parent, item):
        """Создаёт виджет для обычного компонента."""
        print(f"[DEBUG] _create_component_widget: {item}")

        item_frame = ctk.CTkFrame(parent, fg_color="transparent")
        item_frame.pack(fill=tk.X, pady=(0, 8))

        ctk.CTkLabel(
            item_frame,
            text="●",
            font=("Segoe UI", 10),
            text_color="#1E88E5",
            width=15
        ).pack(side=tk.LEFT, anchor=tk.N)

        if isinstance(item, dict):
            item_text = item.get("text", str(item))
        else:
            item_text = str(item)

        if isinstance(item, dict) and "category" in item:
            ctk.CTkLabel(
                item_frame,
                text=f"[{item['category']}]",
                font=("Segoe UI", 11, "bold"),
                text_color="#FF9800",
                width=80
            ).pack(side=tk.LEFT, anchor=tk.N, padx=(0, 5))

            ctk.CTkLabel(
                item_frame,
                text=item_text,
                font=("Segoe UI", 12),
                anchor=tk.W,
                justify=tk.LEFT,
                wraplength=550
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        else:
            ctk.CTkLabel(
                item_frame,
                text=item_text,
                font=("Segoe UI", 12),
                anchor=tk.W,
                justify=tk.LEFT,
                wraplength=650
            ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _create_port_widget(self, parent, port: Dict):
        """Создаёт виджет для сетевого порта с красивым оформлением."""
        print(f"[DEBUG] _create_port_widget: {port}")

        port_frame = ctk.CTkFrame(parent, fg_color="transparent")
        port_frame.pack(fill=tk.X, pady=(0, 4))

        icon = "🔌"
        if port.get("type") == "pon":
            icon = "🔆"
        elif port.get("type") == "wifi":
            icon = "📶"
        elif port.get("type") == "usb":
            icon = "🔌"

        status_icon = "🟢" if port.get("connected") else "⚫"

        header_frame = ctk.CTkFrame(port_frame, fg_color="transparent")
        header_frame.pack(fill=tk.X)

        ctk.CTkLabel(
            header_frame,
            text=f"{icon} {port.get('name', '?')} [{port.get('type', 'unknown').upper()}] {status_icon}",
            font=("Segoe UI", 13, "bold"),
            text_color="#1E88E5" if port.get("connected") else "#757575"
        ).pack(anchor=tk.W)

        # Собираем детали
        details = []

        mac = port.get("mac", "")
        if mac and mac.strip():
            details.append(f"MAC: {mac}")

        ip = port.get("ip", "")
        mask = port.get("mask", "")
        if ip and ip.strip():
            if mask and mask.strip():
                details.append(f"IP: {ip}/{mask}")
            else:
                details.append(f"IP: {ip}")

        vlan_id = port.get("vlan_id")
        vlan_mode = port.get("vlan_mode", "untagged")
        if vlan_id and str(vlan_id).strip():
            details.append(f"VLAN: {vlan_id} ({vlan_mode})")

        # СОЗДАЁМ ФРЕЙМ ДЛЯ ДЕТАЛЕЙ ТОЛЬКО ЕСЛИ ОНИ ЕСТЬ ИЛИ ЕСТЬ ПОДКЛЮЧЕНИЕ
        has_details = len(details) > 0
        has_connection = port.get("connected") and port.get("neighbor_name")

        if has_details or has_connection:
            details_frame = ctk.CTkFrame(port_frame, fg_color="transparent")
            details_frame.pack(fill=tk.X, padx=(25, 0))

            # Показываем детали если есть
            for detail in details:
                ctk.CTkLabel(
                    details_frame,
                    text=f"📍 {detail}",
                    font=("Segoe UI", 11),
                    text_color="gray"
                ).pack(anchor=tk.W, pady=(2, 0))

            # Показываем информацию о подключении если есть
            if has_connection:
                neighbor_frame = ctk.CTkFrame(details_frame,
                                              fg_color="#E3F2FD" if ctk.get_appearance_mode() == "Light" else "#1a2a3a",
                                              corner_radius=6)
                neighbor_frame.pack(fill=tk.X, pady=(8, 0), padx=(0, 10))

                ctk.CTkLabel(
                    neighbor_frame,
                    text="🔗 ПОДКЛЮЧЕНО К:",
                    font=("Segoe UI", 10, "bold"),
                    text_color="#1E88E5"
                ).pack(anchor=tk.W, padx=10, pady=(5, 2))

                ctk.CTkLabel(
                    neighbor_frame,
                    text=f"Узел: {port.get('neighbor_name', '?')}",
                    font=("Segoe UI", 11),
                    anchor=tk.W
                ).pack(anchor=tk.W, padx=10, pady=(0, 2))

                if port.get("neighbor_port"):
                    ctk.CTkLabel(
                        neighbor_frame,
                        text=f"Порт: {port['neighbor_port']}",
                        font=("Segoe UI", 11),
                        anchor=tk.W
                    ).pack(anchor=tk.W, padx=10, pady=(0, 2))

                if port.get("neighbor_ip"):
                    ip_text = f"IP: {port['neighbor_ip']}"
                    if port.get("neighbor_mask"):
                        ip_text += f"/{port['neighbor_mask']}"
                    ctk.CTkLabel(
                        neighbor_frame,
                        text=ip_text,
                        font=("Segoe UI", 11),
                        anchor=tk.W
                    ).pack(anchor=tk.W, padx=10, pady=(0, 5))
        else:
            # Если нет ни деталей, ни подключения - показываем "Не подключен" для не-USB портов
            if port.get("type") != "usb":
                details_frame = ctk.CTkFrame(port_frame, fg_color="transparent")
                details_frame.pack(fill=tk.X, padx=(25, 0))
                ctk.CTkLabel(
                    details_frame,
                    text="❌ Не подключен",
                    font=("Segoe UI", 11),
                    text_color="red"
                ).pack(anchor=tk.W, pady=(4, 0))

    def open_edit_dialog(self):
        """Открывает полноценный диалог редактирования."""
        self.dialog.destroy()

        node_type_mapping = {
            "ARM": "АРМ",
            "Laptop": "Ноутбук",
            "Router": "Маршрутизатор",
            "Switch": "Коммутатор",
            "Server": "Сервер",
            "VirtualizationServer": "Сервер виртуализации",
            "Internet": "Интернет"
        }
        node_type_ru = node_type_mapping.get(self.node.type, "АРМ")

        from dialogs.node_dialog import NodeCreationDialog
        dialog = NodeCreationDialog(self.parent, self.board, node_type_ru, existing_node=self.node)
        self.parent.wait_window(dialog.dialog)

        if dialog.result:
            updated_node = dialog.result
            updated_node.id = self.node.id
            updated_node.position = self.node.position

            for i, n in enumerate(self.board.nodes):
                if n.id == self.node.id:
                    self.board.nodes[i] = updated_node
                    break

            self.canvas_view.redraw()