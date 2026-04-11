"""
Модуль диалога настройки VPN

Содержит класс VPNConfigDialog для настройки VPN-клиента и VPN-сервера на узле.
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from typing import Optional, List, Dict, Any

from models.node import Node
from models.zone import Board
from utils.validators import validate_ip, validate_mask


# Список поддерживаемых VPN-протоколов.
# Порядок задаёт приоритет в выпадающем списке: современные сверху,
# устаревшие с пометкой помечены ниже (их по-прежнему встречают в дикой
# природе, но использовать не рекомендуется).
VPN_PROTOCOLS = [
    "WireGuard",               # современный, самый быстрый, рекомендован по умолчанию
    "OpenVPN (UDP)",           # проверенный стандарт, AES-256
    "OpenVPN (TCP)",           # то же, но по TCP — обходит некоторые фильтры
    "IKEv2/IPSec",             # надёжен на мобильных (роуминг)
    "IPSec",                   # самостоятельный IPSec (site-to-site)
    "SSTP",                    # tunнелирование по TLS (Microsoft)
    "L2TP/IPSec (устарел)",    # устаревший, только с IPsec
    "PPTP (небезопасен)",      # морально устарел, небезопасен
    "SoftEther",               # мультипротокольная платформа
    "GRE",                     # site-to-site инкапсуляция
]

VPN_DEFAULT_PROTOCOL = "WireGuard"


class VPNConfigDialog:
    """Диалог настройки VPN на узле (клиент и сервер)."""

    def __init__(self, parent, node: Node, board: Board):
        self.parent = parent
        self.node = node
        self.board = board
        self.result = None

        # Создаём окно
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Настройка VPN на узле: {node.name}")
        self.dialog.geometry("600x850")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.create_widgets()
        self.center_window()

        # Загружаем существующие настройки
        self.load_existing_settings()

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
        """Создаёт основной интерфейс диалога."""
        # Единый цвет фона для всех секций
        section_bg = "#F5F5F5" if ctk.get_appearance_mode() == "Light" else "#2B2B2B"
        self.dialog.configure(fg_color=section_bg)

        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Заголовок
        ctk.CTkLabel(
            main_frame,
            text=f"Настройка VPN на {self.node.name}",
            font=("Arial", 18, "bold")
        ).pack(pady=(0, 20))

        # ===== БЛОК КЛИЕНТА =====
        client_frame = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                     border_color="#42A5F5", corner_radius=8)
        client_frame.pack(fill=tk.X, pady=(0, 15))

        # Цветная полоска-заголовок
        client_accent = ctk.CTkFrame(client_frame, fg_color="#42A5F5", height=3, corner_radius=0)
        client_accent.pack(fill=tk.X)

        client_header = ctk.CTkFrame(client_frame, fg_color="transparent")
        client_header.pack(fill=tk.X, padx=15, pady=(10, 10))

        ctk.CTkLabel(
            client_header,
            text="VPN-Клиент",
            font=("Arial", 16, "bold"),
            text_color="#1565C0"
        ).pack(side=tk.LEFT)

        self.client_enabled_var = tk.BooleanVar(value=self.node.vpn_client_enabled)
        self.client_switch = ctk.CTkSwitch(
            client_header,
            text="Включен" if self.client_enabled_var.get() else "Выключен",
            variable=self.client_enabled_var,
            command=self.on_client_toggle,
            font=("Arial", 12)
        )
        self.client_switch.pack(side=tk.RIGHT)

        # Контейнер для настроек клиента
        self.client_settings = ctk.CTkFrame(client_frame, fg_color="transparent")
        self.client_settings.pack(fill=tk.X, padx=15, pady=(0, 10))

        self.create_client_settings(self.client_settings)

        # ===== БЛОК СЕРВЕРА =====
        server_frame = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                     border_color="#66BB6A", corner_radius=8)
        server_frame.pack(fill=tk.X, pady=(0, 15))

        # Цветная полоска-заголовок
        server_accent = ctk.CTkFrame(server_frame, fg_color="#66BB6A", height=3, corner_radius=0)
        server_accent.pack(fill=tk.X)

        server_header = ctk.CTkFrame(server_frame, fg_color="transparent")
        server_header.pack(fill=tk.X, padx=15, pady=(10, 10))

        ctk.CTkLabel(
            server_header,
            text="VPN-Сервер",
            font=("Arial", 16, "bold"),
            text_color="#2E7D32"
        ).pack(side=tk.LEFT)

        self.server_enabled_var = tk.BooleanVar(value=self.node.vpn_server_enabled)
        self.server_switch = ctk.CTkSwitch(
            server_header,
            text="Включен" if self.server_enabled_var.get() else "Выключен",
            variable=self.server_enabled_var,
            command=self.on_server_toggle,
            font=("Arial", 12)
        )
        self.server_switch.pack(side=tk.RIGHT)

        # Контейнер для настроек сервера
        self.server_settings = ctk.CTkFrame(server_frame, fg_color="transparent")
        self.server_settings.pack(fill=tk.X, padx=15, pady=(0, 10))

        self.create_server_settings(self.server_settings)

        # ===== КНОПКИ =====
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkButton(
            btn_frame, text="✔ Сохранить",
            command=self.save_vpn, fg_color="#4CAF50",
            width=120, height=38, font=("Arial", 13, "bold")
        ).pack(side=tk.RIGHT, padx=5)

        ctk.CTkButton(
            btn_frame, text="✕ Отмена",
            command=self.dialog.destroy, fg_color="#CD3333",
            width=100, height=38, font=("Arial", 13)
        ).pack(side=tk.RIGHT, padx=5)

        # Устанавливаем состояние настроек
        self.on_client_toggle()
        self.on_server_toggle()

    def create_client_settings(self, parent):
        """Создаёт настройки для VPN-клиента."""
        # Протокол
        protocol_frame = ctk.CTkFrame(parent, fg_color="transparent")
        protocol_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            protocol_frame,
            text="VPN-протокол:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        current_client_protocol = getattr(self.node, "vpn_client_protocol", VPN_DEFAULT_PROTOCOL) or VPN_DEFAULT_PROTOCOL
        self.client_protocol_var = tk.StringVar(value=current_client_protocol)
        self.client_protocol_combo = ctk.CTkComboBox(
            protocol_frame,
            values=VPN_PROTOCOLS,
            variable=self.client_protocol_var,
            state="readonly",
            width=260
        )
        self.client_protocol_combo.pack(anchor=tk.W, pady=5)

        # VPN IP сервера (куда подключаемся)
        server_ip_frame = ctk.CTkFrame(parent, fg_color="transparent")
        server_ip_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            server_ip_frame,
            text="VPN IP сервера:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        self.client_server_ip = ctk.CTkEntry(
            server_ip_frame, placeholder_text="10.0.0.1", width=200
        )
        self.client_server_ip.pack(anchor=tk.W, pady=5)

        # Порт сервера
        port_frame = ctk.CTkFrame(parent, fg_color="transparent")
        port_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            port_frame,
            text="Порт сервера:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        port_row = ctk.CTkFrame(port_frame, fg_color="transparent")
        port_row.pack(fill=tk.X, pady=5)

        self.client_port = ctk.CTkEntry(
            port_row, placeholder_text="1194", width=120
        )
        self.client_port.pack(side=tk.LEFT)

        # VPN IP самого узла (клиента)
        client_ip_frame = ctk.CTkFrame(parent, fg_color="transparent")
        client_ip_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            client_ip_frame,
            text="VPN IP узла (клиента):",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        client_ip_row = ctk.CTkFrame(client_ip_frame, fg_color="transparent")
        client_ip_row.pack(fill=tk.X, pady=5)

        self.client_virtual_ip = ctk.CTkEntry(
            client_ip_row, placeholder_text="10.0.0.2", width=130
        )
        self.client_virtual_ip.pack(side=tk.LEFT)

        ctk.CTkLabel(client_ip_row, text="/", font=("Arial", 14, "bold")).pack(side=tk.LEFT, padx=5)

        self.client_virtual_mask = ctk.CTkEntry(
            client_ip_row, placeholder_text="24", width=60
        )
        self.client_virtual_mask.pack(side=tk.LEFT)

        # Статус подключения
        status_frame = ctk.CTkFrame(parent, fg_color="transparent")
        status_frame.pack(fill=tk.X, pady=(0, 5))

        ctk.CTkLabel(
            status_frame,
            text="Статус подключения:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        status_row = ctk.CTkFrame(status_frame, fg_color="transparent")
        status_row.pack(fill=tk.X, pady=5)

        self.connection_status_var = tk.StringVar(value="Отключено")
        self.status_label = ctk.CTkLabel(
            status_row,
            textvariable=self.connection_status_var,
            font=("Arial", 12, "bold"),
            text_color="red"
        )
        self.status_label.pack(side=tk.LEFT)

        ctk.CTkButton(
            status_row, text="Проверить соединение",
            command=self.check_connection, width=180, height=30
        ).pack(side=tk.RIGHT)

    def create_server_settings(self, parent):
        """Создаёт настройки для VPN-сервера."""
        # Протокол
        protocol_frame = ctk.CTkFrame(parent, fg_color="transparent")
        protocol_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            protocol_frame,
            text="VPN-протокол:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        current_server_protocol = getattr(self.node, "vpn_server_protocol", VPN_DEFAULT_PROTOCOL) or VPN_DEFAULT_PROTOCOL
        self.server_protocol_var = tk.StringVar(value=current_server_protocol)
        self.server_protocol_combo = ctk.CTkComboBox(
            protocol_frame,
            values=VPN_PROTOCOLS,
            variable=self.server_protocol_var,
            state="readonly",
            width=260
        )
        self.server_protocol_combo.pack(anchor=tk.W, pady=5)

        # VPN IP сервера
        server_ip_frame = ctk.CTkFrame(parent, fg_color="transparent")
        server_ip_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            server_ip_frame,
            text="VPN IP сервера:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        server_ip_row = ctk.CTkFrame(server_ip_frame, fg_color="transparent")
        server_ip_row.pack(fill=tk.X, pady=5)

        self.server_virtual_ip = ctk.CTkEntry(
            server_ip_row, placeholder_text="10.0.0.1", width=130
        )
        self.server_virtual_ip.pack(side=tk.LEFT)

        ctk.CTkLabel(server_ip_row, text="/", font=("Arial", 14, "bold")).pack(side=tk.LEFT, padx=5)

        self.server_virtual_mask = ctk.CTkEntry(
            server_ip_row, placeholder_text="24", width=60
        )
        self.server_virtual_mask.pack(side=tk.LEFT)

        # Порт сервера
        port_frame = ctk.CTkFrame(parent, fg_color="transparent")
        port_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(
            port_frame,
            text="Порт сервера:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        self.server_port = ctk.CTkEntry(
            port_frame, placeholder_text="1194", width=120
        )
        self.server_port.pack(anchor=tk.W, pady=5)

        # Внутренняя сеть
        network_frame = ctk.CTkFrame(parent, fg_color="transparent")
        network_frame.pack(fill=tk.X, pady=(0, 5))

        ctk.CTkLabel(
            network_frame,
            text="Внутренняя сеть:",
            font=("Arial", 12, "bold")
        ).pack(anchor=tk.W)

        network_row = ctk.CTkFrame(network_frame, fg_color="transparent")
        network_row.pack(fill=tk.X, pady=5)

        self.server_network = ctk.CTkEntry(
            network_row, placeholder_text="10.0.0.0", width=130
        )
        self.server_network.pack(side=tk.LEFT)

        ctk.CTkLabel(network_row, text="/", font=("Arial", 14, "bold")).pack(side=tk.LEFT, padx=5)

        self.server_network_mask = ctk.CTkEntry(
            network_row, placeholder_text="24", width=60
        )
        self.server_network_mask.pack(side=tk.LEFT)

    def load_existing_settings(self):
        """Загружает существующие настройки VPN."""
        # Загрузка настроек клиента
        if self.node.vpn_client_enabled:
            # VPN IP сервера
            if hasattr(self.node, 'vpn_client_server_ip') and self.node.vpn_client_server_ip:
                self.client_server_ip.insert(0, self.node.vpn_client_server_ip)

            # Порт
            if hasattr(self.node, 'vpn_client_port') and self.node.vpn_client_port:
                self.client_port.insert(0, str(self.node.vpn_client_port))

            # VPN IP клиента
            if self.node.vpn_client_tunnel_ip:
                if '/' in self.node.vpn_client_tunnel_ip:
                    ip, mask = self.node.vpn_client_tunnel_ip.split('/')
                    self.client_virtual_ip.insert(0, ip)
                    self.client_virtual_mask.insert(0, mask)

        # Загрузка настроек сервера
        if self.node.vpn_server_enabled:
            # VPN IP сервера
            if self.node.vpn_server_tunnel_ips and len(self.node.vpn_server_tunnel_ips) > 0:
                ip_with_mask = self.node.vpn_server_tunnel_ips[0]
                if '/' in ip_with_mask:
                    ip, mask = ip_with_mask.split('/')
                    self.server_virtual_ip.insert(0, ip)
                    self.server_virtual_mask.insert(0, mask)

            # Порт
            if hasattr(self.node, 'vpn_server_port') and self.node.vpn_server_port:
                self.server_port.insert(0, str(self.node.vpn_server_port))

            # Внутренняя сеть
            if self.node.vpn_server_remote_network:
                self.server_network.insert(0, self.node.vpn_server_remote_network)
                self.server_network_mask.insert(0, self.node.vpn_server_remote_mask)

    def find_vpn_server(self) -> Optional[Node]:
        """Находит узел-сервер VPN, к которому должен подключиться клиент."""
        server_ip = self.client_server_ip.get().strip()
        if not server_ip:
            return None

        # Ищем среди всех узлов на доске
        for node in self.board.nodes:
            if node.id == self.node.id:
                continue  # пропускаем самого себя

            # Проверяем, включён ли на узле VPN-сервер
            if node.vpn_server_enabled:
                # Проверяем VPN IP сервера
                for tunnel_ip in node.vpn_server_tunnel_ips:
                    if '/' in tunnel_ip:
                        ip_part = tunnel_ip.split('/')[0]
                        if ip_part == server_ip:
                            return node

                # Также проверяем реальный IP (на всякий случай)
                if node.vpn_server_real_ip == server_ip:
                    return node

        return None

    def check_connection(self):
        """Проверяет, установлено ли соединение с VPN-сервером."""
        if not self.client_enabled_var.get():
            self.connection_status_var.set("Клиент отключён")
            self.status_label.configure(text_color="orange")
            return

        server_ip = self.client_server_ip.get().strip()
        if not server_ip:
            self.connection_status_var.set("❌ Не указан VPN IP сервера")
            self.status_label.configure(text_color="red")
            return

        client_port = self.client_port.get().strip()
        if not client_port:
            self.connection_status_var.set("❌ Не указан порт сервера")
            self.status_label.configure(text_color="red")
            return

        # Ищем сервер с таким же VPN IP и портом
        server_node = self.find_vpn_server()

        if server_node:
            # Проверяем совпадение порта
            server_port = getattr(server_node, 'vpn_server_port', None)
            if server_port and str(server_port) == client_port:
                self.connection_status_var.set(f"✅ Подключено к {server_node.name}")
                self.status_label.configure(text_color="green")

                # Сохраняем ID сервера для связи
                self.node.vpn_client_peer_id = server_node.id
                self.node.vpn_client_peer_ip = server_ip
            else:
                self.connection_status_var.set(f"❌ Порт не совпадает (нужен {server_port})")
                self.status_label.configure(text_color="red")
                self.node.vpn_client_peer_id = None
                self.node.vpn_client_peer_ip = ""
        else:
            self.connection_status_var.set("❌ Сервер не найден (проверьте IP и порт)")
            self.status_label.configure(text_color="red")
            self.node.vpn_client_peer_id = None
            self.node.vpn_client_peer_ip = ""

    def on_client_toggle(self):
        """Включает/выключает настройки клиента."""
        enabled = self.client_enabled_var.get()
        self.client_switch.configure(text="Включен" if enabled else "Выключен")

        # Если клиент включается, автоматически проверяем соединение
        if enabled:
            self.dialog.after(100, self.check_connection)

        for widget in self.client_settings.winfo_children():
            self._set_widgets_state(widget, enabled)

    def on_server_toggle(self):
        """Включает/выключает настройки сервера."""
        enabled = self.server_enabled_var.get()
        self.server_switch.configure(text="Включен" if enabled else "Выключен")

        for widget in self.server_settings.winfo_children():
            self._set_widgets_state(widget, enabled)

    def _set_widgets_state(self, widget, enabled):
        """Рекурсивно устанавливает состояние виджетов."""
        state = "normal" if enabled else "disabled"

        if isinstance(widget, (ctk.CTkEntry, ctk.CTkButton, ctk.CTkRadioButton, ctk.CTkComboBox)):
            try:
                widget.configure(state=state)
            except:
                pass
        elif isinstance(widget, ctk.CTkFrame):
            for child in widget.winfo_children():
                self._set_widgets_state(child, enabled)

    def save_vpn(self):
        """Сохраняет настройки VPN."""
        # Сохраняем настройки клиента
        if self.client_enabled_var.get():
            server_ip = self.client_server_ip.get().strip()
            if not server_ip or not validate_ip(server_ip):
                messagebox.showerror("Ошибка", "Введите корректный VPN IP сервера!")
                return

            port = self.client_port.get().strip()
            if not port:
                messagebox.showerror("Ошибка", "Введите порт сервера!")
                return
            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Ошибка", "Порт должен быть числом от 1 до 65535!")
                return

            server_node = self.find_vpn_server()
            if server_node:
                server_port = getattr(server_node, 'vpn_server_port', None)
                if server_port and str(server_port) == port:
                    self.node.vpn_client_peer_id = server_node.id
                    self.node.vpn_client_peer_ip = server_ip
                else:
                    self.node.vpn_client_peer_id = None
                    self.node.vpn_client_peer_ip = ""
            else:
                self.node.vpn_client_peer_id = None
                self.node.vpn_client_peer_ip = ""

            virtual_ip = self.client_virtual_ip.get().strip()
            virtual_mask = self.client_virtual_mask.get().strip()

            if not virtual_ip or not validate_ip(virtual_ip):
                messagebox.showerror("Ошибка", "Введите корректный VPN IP узла (клиента)!")
                return

            if not virtual_mask or not validate_mask(virtual_mask):
                messagebox.showerror("Ошибка", "Введите корректную маску (0-32)!")
                return

            self.node.vpn_client_enabled = True
            self.node.vpn_client_server_ip = server_ip
            self.node.vpn_client_port = port_int
            self.node.vpn_client_tunnel_ip = f"{virtual_ip}/{virtual_mask}"
            self.node.vpn_client_protocol = self.client_protocol_var.get() or VPN_DEFAULT_PROTOCOL
        else:
            self.node.vpn_client_enabled = False
            self.node.vpn_client_server_ip = ""
            self.node.vpn_client_port = None
            self.node.vpn_client_tunnel_ip = ""

        # Сохраняем настройки сервера
        if self.server_enabled_var.get():
            virtual_ip = self.server_virtual_ip.get().strip()
            virtual_mask = self.server_virtual_mask.get().strip()

            if not virtual_ip or not validate_ip(virtual_ip):
                messagebox.showerror("Ошибка", "Введите корректный VPN IP сервера!")
                return

            if not virtual_mask or not validate_mask(virtual_mask):
                messagebox.showerror("Ошибка", "Введите корректную маску (0-32)!")
                return

            port = self.server_port.get().strip()
            if not port:
                messagebox.showerror("Ошибка", "Введите порт сервера!")
                return
            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Ошибка", "Порт должен быть числом от 1 до 65535!")
                return

            network = self.server_network.get().strip()
            network_mask = self.server_network_mask.get().strip()

            if network and not validate_ip(network):
                messagebox.showerror("Ошибка", "Введите корректный IP внутренней сети!")
                return

            if network_mask and not validate_mask(network_mask):
                messagebox.showerror("Ошибка", "Введите корректную маску внутренней сети (0-32)!")
                return

            self.node.vpn_server_enabled = True
            self.node.vpn_server_tunnel_ips = [f"{virtual_ip}/{virtual_mask}"]
            self.node.vpn_server_port = port_int
            self.node.vpn_server_remote_network = network
            self.node.vpn_server_remote_mask = network_mask
            self.node.vpn_server_protocol = self.server_protocol_var.get() or VPN_DEFAULT_PROTOCOL
        else:
            self.node.vpn_server_enabled = False
            self.node.vpn_server_tunnel_ips = []
            self.node.vpn_server_port = None
            self.node.vpn_server_remote_network = ""
            self.node.vpn_server_remote_mask = ""

        self.result = self.node
        self.dialog.destroy()