"""
Модуль диалога выбора портов для соединения между узлами

Содержит класс LinkPortSelectionDialog для создания соединений:
- Точка-точка (Ethernet, PON)
- Wi-Fi (точка доступа → клиент)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from typing import Dict, Optional, List

from models.node import Node


class LinkPortSelectionDialog:
    """Диалог выбора портов для соединения между узлами."""

    def __init__(self, parent, node_a: Node, node_b: Node):
        self.parent = parent
        self.node_a = node_a
        self.node_b = node_b
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Выбор портов для соединения")
        self.dialog.geometry("1200x850")
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
        mapping = {
            "Internet": "Интернет",
            "Router": "Маршрутизатор",
            "Switch": "Коммутатор",
            "Server": "Сервер",
            "ARM": "АРМ",
            "Laptop": "Ноутбук",
            "VirtualizationServer": "Сервер виртуализации"
        }
        return mapping.get(node_type_en, node_type_en)

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Заголовок
        title_label = ctk.CTkLabel(
            main_frame,
            text=f"Соединение: {self.node_a.name}  ↔  {self.node_b.name}",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=(0, 10))

        # Информация о типах узлов
        info_text = f"Тип A: {self.get_node_type_russian(self.node_a.type)} | "
        info_text += f"Тип B: {self.get_node_type_russian(self.node_b.type)}"
        ctk.CTkLabel(main_frame, text=info_text, font=("Arial", 12)).pack(pady=(0, 15))

        # Фрейм для выбора типа соединения
        type_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        type_frame.pack(fill=tk.X, pady=(0, 15))

        ctk.CTkLabel(
            type_frame, text="Тип соединения:",
            font=("Arial", 13, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.connection_type = tk.StringVar(value="ethernet")

        types_row = ctk.CTkFrame(type_frame, fg_color="transparent")
        types_row.pack(fill=tk.X, padx=10, pady=(0, 10))

        # RJ45 (Ethernet)
        ctk.CTkRadioButton(
            types_row, text="RJ45 (Ethernet)",
            variable=self.connection_type, value="ethernet",
            command=self.on_connection_type_changed
        ).pack(side=tk.LEFT, padx=10)

        # PON (Оптика)
        ctk.CTkRadioButton(
            types_row, text="PON (Оптика)",
            variable=self.connection_type, value="pon",
            command=self.on_connection_type_changed
        ).pack(side=tk.LEFT, padx=10)

        # Wi-Fi
        wifi_can_be_used = self.can_create_wifi_connection()

        wifi_radio = ctk.CTkRadioButton(
            types_row, text="Wi-Fi",
            variable=self.connection_type, value="wifi",
            command=self.on_connection_type_changed
        )
        wifi_radio.pack(side=tk.LEFT, padx=10)

        if not wifi_can_be_used:
            wifi_radio.configure(state="disabled")
            ctk.CTkLabel(
                types_row, text="(недоступно - нет подходящих портов)",
                font=("Arial", 10), text_color="gray"
            ).pack(side=tk.LEFT)

        # Фрейм для выбора портов
        self.ports_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        self.ports_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Изначально показываем Ethernet
        self.show_ethernet_ports()

        # Информация о соединении
        info_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        info_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkLabel(
            info_frame, text="ℹ️ Информация о соединении",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(5, 2))

        self.connection_info = ctk.CTkLabel(
            info_frame, text="Выберите порты для соединения",
            font=("Arial", 11), text_color="gray"
        )
        self.connection_info.pack(anchor=tk.W, padx=10, pady=(0, 5))

        # Кнопки
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill=tk.X, pady=(15, 0))

        ctk.CTkButton(
            button_frame, text="✓ Создать соединение",
            command=self.create_link, fg_color="#4CAF50",
            height=38, font=("Arial", 13, "bold")
        ).pack(side=tk.RIGHT, padx=5)

        ctk.CTkButton(
            button_frame, text="✕ Отмена",
            command=self.dialog.destroy, fg_color="#CD3333",
            height=38, font=("Arial", 13)
        ).pack(side=tk.RIGHT, padx=5)

    def can_create_wifi_connection(self) -> bool:
        """Проверяет, можно ли создать Wi-Fi соединение."""
        # Ищем AP порт в первом узле и client порт во втором
        for port_a in self.node_a.ports:
            if port_a.get("port_type") == "wifi" and port_a.get("wifi_role") == "ap":
                if not port_a.get("connected_clients"):
                    for port_b in self.node_b.ports:
                        if port_b.get("port_type") == "wifi" and port_b.get("wifi_role") == "client":
                            if not port_b.get("connected_to_ap"):
                                return True

        # Ищем AP порт во втором узле и client порт в первом
        for port_b in self.node_b.ports:
            if port_b.get("port_type") == "wifi" and port_b.get("wifi_role") == "ap":
                if not port_b.get("connected_clients"):
                    for port_a in self.node_a.ports:
                        if port_a.get("port_type") == "wifi" and port_a.get("wifi_role") == "client":
                            if not port_a.get("connected_to_ap"):
                                return True

        return False

    def on_connection_type_changed(self):
        """Обработчик изменения типа соединения."""
        for widget in self.ports_frame.winfo_children():
            widget.destroy()

        conn_type = self.connection_type.get()

        if conn_type == "ethernet":
            self.show_ethernet_ports()
        elif conn_type == "pon":
            self.show_pon_ports()
        elif conn_type == "wifi":
            self.show_wifi_ports()

    def show_ethernet_ports(self):
        """Показывает выбор Ethernet портов."""
        ports_row = ctk.CTkFrame(self.ports_frame, fg_color="transparent")
        ports_row.pack(fill=tk.BOTH, expand=True)

        # Левый узел (A)
        left_frame = ctk.CTkFrame(ports_row)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        ctk.CTkLabel(
            left_frame, text=f"Порты узла A: {self.node_a.name}",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        # Правый узел (B)
        right_frame = ctk.CTkFrame(ports_row)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ctk.CTkLabel(
            right_frame, text=f"Порты узла B: {self.node_b.name}",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        # Переменные для выбранных портов
        self.port_a_var = tk.StringVar()
        self.port_b_var = tk.StringVar()

        # Заполняем Ethernet порты
        self.create_port_list(left_frame, self.node_a, self.port_a_var, "ethernet")
        self.create_port_list(right_frame, self.node_b, self.port_b_var, "ethernet")

        # Отслеживаем выбор
        self.port_a_var.trace('w', self.update_connection_info)
        self.port_b_var.trace('w', self.update_connection_info)

    def show_pon_ports(self):
        """Показывает выбор PON портов."""
        ports_row = ctk.CTkFrame(self.ports_frame, fg_color="transparent")
        ports_row.pack(fill=tk.BOTH, expand=True)

        left_frame = ctk.CTkFrame(ports_row)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        ctk.CTkLabel(
            left_frame, text=f"📌 PON порты узла A: {self.node_a.name}",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        right_frame = ctk.CTkFrame(ports_row)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        ctk.CTkLabel(
            right_frame, text=f"📌 PON порты узла B: {self.node_b.name}",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.port_a_var = tk.StringVar()
        self.port_b_var = tk.StringVar()

        self.create_port_list(left_frame, self.node_a, self.port_a_var, "pon")
        self.create_port_list(right_frame, self.node_b, self.port_b_var, "pon")

        self.port_a_var.trace('w', self.update_connection_info)
        self.port_b_var.trace('w', self.update_connection_info)

    def show_wifi_ports(self):
        """Показывает выбор Wi-Fi портов."""
        configs = []

        # Вариант 1: A - AP, B - Client
        for port_a in self.node_a.ports:
            if port_a.get("port_type") == "wifi" and port_a.get("wifi_role") == "ap":
                if not port_a.get("connected_clients"):
                    for port_b in self.node_b.ports:
                        if port_b.get("port_type") == "wifi" and port_b.get("wifi_role") == "client":
                            if not port_b.get("connected_to_ap"):
                                configs.append(("A_AP_B_Client", port_a, port_b))

        # Вариант 2: B - AP, A - Client
        for port_b in self.node_b.ports:
            if port_b.get("port_type") == "wifi" and port_b.get("wifi_role") == "ap":
                if not port_b.get("connected_clients"):
                    for port_a in self.node_a.ports:
                        if port_a.get("port_type") == "wifi" and port_a.get("wifi_role") == "client":
                            if not port_a.get("connected_to_ap"):
                                configs.append(("B_AP_A_Client", port_b, port_a))

        if not configs:
            no_wifi_frame = ctk.CTkFrame(self.ports_frame)
            no_wifi_frame.pack(fill=tk.BOTH, expand=True)

            ctk.CTkLabel(
                no_wifi_frame, text="❌ Нет доступных Wi-Fi портов с подходящими ролями",
                font=("Arial", 16, "bold"), text_color="red"
            ).pack(expand=True)

            ctk.CTkLabel(
                no_wifi_frame,
                text="Требуется: один узел с портом AP, другой с портом Client",
                font=("Arial", 12), text_color="gray"
            ).pack(expand=True, pady=(5, 0))
            return

        config_frame = ctk.CTkFrame(self.ports_frame)
        config_frame.pack(fill=tk.BOTH, expand=True)

        ctk.CTkLabel(
            config_frame, text="📶 Доступные Wi-Fi соединения",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 10))

        self.wifi_config_var = tk.StringVar()

        for config_type, ap_port, client_port in configs:
            if config_type.startswith("A_AP"):
                text = f"📶 {self.node_a.name}:{ap_port['name']} [AP] → {self.node_b.name}:{client_port['name']} [Client]"
                value = f"ap_{ap_port['port_id']}_client_{client_port['port_id']}"
            else:
                text = f"📶 {self.node_b.name}:{ap_port['name']} [AP] → {self.node_a.name}:{client_port['name']} [Client]"
                value = f"ap_{ap_port['port_id']}_client_{client_port['port_id']}"

            rb = ctk.CTkRadioButton(
                config_frame, text=text, variable=self.wifi_config_var,
                value=value, command=self.update_connection_info,
                font=("Arial", 12)
            )
            rb.pack(anchor=tk.W, padx=20, pady=5)

        if configs:
            self.wifi_config_var.set(value)

    def create_port_list(self, parent, node: Node, var: tk.StringVar, port_type: str):
        """Создаёт список портов для выбора."""
        # Узел «Интернет» имеет «бесконечный порт»: не показываем список
        # существующих портов, а предлагаем автоматическое подключение.
        if node.type == "Internet" and port_type in ("ethernet", "pon"):
            scroll_frame = ctk.CTkFrame(parent, fg_color="transparent")
            scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            info_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
            info_frame.pack(fill=tk.X, pady=2)

            rb = ctk.CTkRadioButton(
                info_frame,
                text="🌐 Автоматическое подключение (порт будет создан)",
                variable=var,
                value="__auto__",
                font=("Arial", 11)
            )
            rb.pack(anchor=tk.W, padx=5, pady=2)
            # Выбираем автоматически, чтобы пользователь ничего не искал
            var.set("__auto__")
            return

        ports = [p for p in node.ports if p.get("port_type") == port_type]

        if not ports:
            ctk.CTkLabel(parent, text=f"Нет портов типа {port_type}!", text_color="red").pack(pady=10)
            return

        # Фрейм с прокруткой
        scroll_frame = ctk.CTkScrollableFrame(parent)
        scroll_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        for port in ports:
            port_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
            port_frame.pack(fill=tk.X, pady=2)

            is_busy = port.get("connected_to") is not None
            status = "🔴 Занят" if is_busy else "🟢 Свободен"

            port_info = f"{port['name']} - {status}"
            if port.get("mac_address"):
                port_info += f"  MAC: {port['mac_address']}"
            if port.get("ip_address"):
                port_info += f"  IP: {port['ip_address']}/{port.get('subnet_mask', '')}"

            rb = ctk.CTkRadioButton(
                port_frame, text=port_info, variable=var,
                value=port["port_id"], state="normal" if not is_busy else "disabled",
                font=("Arial", 11)
            )
            rb.pack(anchor=tk.W, padx=5, pady=2)

    def update_connection_info(self, *args):
        """Обновляет информацию о выбранных портах."""
        conn_type = self.connection_type.get()

        if conn_type == "wifi":
            self.update_wifi_connection_info()
        else:
            self.update_p2p_connection_info()

    def update_p2p_connection_info(self):
        """Обновляет информацию для точка-точка соединения."""
        port_a_id = self.port_a_var.get() if hasattr(self, 'port_a_var') else None
        port_b_id = self.port_b_var.get() if hasattr(self, 'port_b_var') else None

        if port_a_id and port_b_id:
            port_a = next((p for p in self.node_a.ports if p["port_id"] == port_a_id), None)
            port_b = next((p for p in self.node_b.ports if p["port_id"] == port_b_id), None)

            if port_a and port_b:
                info = f"✅ Соединение: {port_a['name']} → {port_b['name']}"
                self.connection_info.configure(text=info, text_color="green")
        else:
            self.connection_info.configure(text="⚠️ Выберите оба порта", text_color="orange")

    def update_wifi_connection_info(self):
        """Обновляет информацию для Wi-Fi соединения."""
        if hasattr(self, 'wifi_config_var') and self.wifi_config_var.get():
            self.connection_info.configure(text="✅ Wi-Fi соединение выбрано", text_color="green")
        else:
            self.connection_info.configure(text="⚠️ Выберите Wi-Fi соединение", text_color="orange")

    def create_link(self):
        """Создаёт соединение с выбранными параметрами."""
        conn_type = self.connection_type.get()

        if conn_type == "wifi":
            self.create_wifi_link()
        else:
            self.create_p2p_link()

    def create_p2p_link(self):
        """Создаёт точка-точка соединение."""
        port_a_id = self.port_a_var.get() if hasattr(self, 'port_a_var') else None
        port_b_id = self.port_b_var.get() if hasattr(self, 'port_b_var') else None

        if not port_a_id or not port_b_id:
            messagebox.showerror("Ошибка", "Выберите порты на обоих узлах!")
            return

        conn_type = self.connection_type.get()
        port_type = "pon" if conn_type == "pon" else "ethernet"

        # Для узла «Интернет» порт создаётся автоматически (бесконечный порт).
        if port_a_id == "__auto__" and self.node_a.type == "Internet":
            port_a_id = self._spawn_internet_port(self.node_a, port_type)
        if port_b_id == "__auto__" and self.node_b.type == "Internet":
            port_b_id = self._spawn_internet_port(self.node_b, port_type)

        if not port_a_id or not port_b_id:
            messagebox.showerror("Ошибка", "Не удалось создать автоматический порт.")
            return

        self.result = {
            "type": "p2p",
            "port_a": port_a_id,
            "port_b": port_b_id
        }
        self.dialog.destroy()

    @staticmethod
    def _spawn_internet_port(node: Node, port_type: str) -> Optional[str]:
        """Создаёт новый порт на узле Интернет и возвращает его port_id."""
        before = {p.get("port_id") for p in node.ports}
        if not node.add_port(port_type=port_type):
            return None
        after = [p for p in node.ports if p.get("port_id") not in before]
        if not after:
            return None
        return after[-1].get("port_id")

    def create_wifi_link(self):
        """Создаёт Wi-Fi соединение."""
        if not hasattr(self, 'wifi_config_var') or not self.wifi_config_var.get():
            messagebox.showerror("Ошибка", "Выберите Wi-Fi соединение!")
            return

        config = self.wifi_config_var.get()
        parts = config.split('_')

        if len(parts) == 4 and parts[0] == 'ap' and parts[2] == 'client':
            ap_port_id = parts[1]
            client_port_id = parts[3]

            # Проверяем, в каком узле находится AP
            for port in self.node_a.ports:
                if port["port_id"] == ap_port_id:
                    self.result = {
                        "type": "wifi",
                        "ap_node_id": self.node_a.id,
                        "ap_port_id": ap_port_id,
                        "client_node_id": self.node_b.id,
                        "client_port_id": client_port_id
                    }
                    self.dialog.destroy()
                    return

            for port in self.node_b.ports:
                if port["port_id"] == ap_port_id:
                    self.result = {
                        "type": "wifi",
                        "ap_node_id": self.node_b.id,
                        "ap_port_id": ap_port_id,
                        "client_node_id": self.node_a.id,
                        "client_port_id": client_port_id
                    }
                    self.dialog.destroy()
                    return

        messagebox.showerror("Ошибка", "Не удалось определить параметры соединения")


# Удобная функция-обёртка
def create_link_dialog(parent, node_a: Node, node_b: Node) -> Optional[Dict]:
    """
    Создаёт диалог выбора портов и возвращает параметры соединения.

    Returns:
        Словарь с параметрами соединения или None
    """
    dialog = LinkPortSelectionDialog(parent, node_a, node_b)
    parent.wait_window(dialog.dialog)
    return dialog.result