"""
Модуль диалога таблицы маршрутизации (промт 8 №7 — полный редизайн)

Структура построена на основе принципов реальной IP routing table:
- Типы маршрутов: Connected (прямо подключённая сеть), Static (ручной
  статический маршрут), Default (маршрут по умолчанию 0.0.0.0/0).
- Выбор маршрута по Longest Prefix Match, при равной длине префикса —
  по меньшей метрике (administrative distance опустили — это отдельная
  тема, которая в учебном UI избыточна).
- Connected routes отображаются автоматически по конфигурации портов
  узла (каждая подключённая подсеть) и read-only: их нельзя редактировать
  или удалять вручную — они следуют за IP портов.
- Static / Default маршруты — ручные, хранятся в node.routing_table.

Содержит классы:
- RouteEditDialog: Диалог создания/редактирования static или default маршрута.
- RoutingTableDialog: Главный диалог с таблицей маршрутов, сгруппированных
  по типу и отсортированных по longest prefix match.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from typing import List, Optional, Dict, Any

from models.node import Node
from models.route import Route
from utils.generators import uid
from utils.network_utils import calculate_network, decimal_mask_to_cidr
from utils.validators import validate_ip


# ===========================================================================
# RouteEditDialog — диалог создания/редактирования static/default маршрута
# ===========================================================================

ROUTE_TYPE_STATIC = "static"
ROUTE_TYPE_DEFAULT = "default"


class RouteEditDialog:
    """Диалог для создания/редактирования маршрута.

    Промт 8 №7: поддерживает два типа маршрутов — статический (static)
    и маршрут по умолчанию (default). Connected routes здесь не создаются —
    они автоматически отображаются в главной таблице по конфигурации
    портов узла.
    """

    def __init__(self, parent, node: Node, route: Optional[Route] = None):
        self.parent = parent
        self.node = node
        self.route = route
        self.result: Optional[Route] = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Редактирование маршрута" if route else "Новый маршрут")
        self.dialog.geometry("620x620")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Для существующего маршрута определяем его текущий тип
        if route and route.is_default_route():
            self._initial_type = ROUTE_TYPE_DEFAULT
        else:
            self._initial_type = ROUTE_TYPE_STATIC

        self.create_widgets()
        self.center_window()
        self._apply_route_type_state()  # чтобы сразу disable поля для default

    def center_window(self):
        self.dialog.update_idletasks()
        geo = self.dialog.geometry()
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

    def get_available_interfaces(self) -> List[str]:
        """Список доступных сетевых интерфейсов узла."""
        interfaces = []
        for port in self.node.ports:
            if port.get("port_type") in ["ethernet", "pon", "wifi"]:
                name = port.get("name", f"port{port.get('port_number', 0)}")
                interfaces.append(name)
        return interfaces if interfaces else ["eth0"]

    def create_widgets(self):
        section_bg = "#F5F5F5" if ctk.get_appearance_mode() == "Light" else "#2B2B2B"
        border_clr = "#CCCCCC" if ctk.get_appearance_mode() == "Light" else "#3D3D3D"
        self.dialog.configure(fg_color=section_bg)

        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Заголовок
        ctk.CTkLabel(
            main_frame, text="Параметры маршрута",
            font=("Arial", 18, "bold")
        ).pack(pady=(0, 15))

        # ===== Секция: тип маршрута =====
        type_section = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                     border_color=border_clr, corner_radius=8)
        type_section.pack(fill=tk.X, pady=(0, 10))
        type_inner = ctk.CTkFrame(type_section, fg_color="transparent")
        type_inner.pack(fill=tk.X, padx=15, pady=10)

        ctk.CTkLabel(type_inner, text="Тип маршрута:", anchor=tk.W,
                      font=("Arial", 13, "bold")).pack(fill=tk.X)

        self.route_type_var = tk.StringVar(value=self._initial_type)
        types_row = ctk.CTkFrame(type_inner, fg_color="transparent")
        types_row.pack(fill=tk.X, pady=(5, 0))

        ctk.CTkRadioButton(
            types_row, text="Static (статический)",
            variable=self.route_type_var, value=ROUTE_TYPE_STATIC,
            command=self._apply_route_type_state
        ).pack(side=tk.LEFT, padx=(0, 20))
        ctk.CTkRadioButton(
            types_row, text="Default (по умолчанию / 0.0.0.0/0)",
            variable=self.route_type_var, value=ROUTE_TYPE_DEFAULT,
            command=self._apply_route_type_state
        ).pack(side=tk.LEFT)

        ctk.CTkLabel(
            type_inner,
            text="Connected routes (прямо подключённые сети) создаются автоматически "
                 "из IP/маски портов узла и редактируются во вкладке «Сеть».",
            font=("Arial", 10), text_color="gray", wraplength=530, justify="left"
        ).pack(fill=tk.X, pady=(6, 0))

        # ===== Секция: Назначение =====
        dest_section = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                     border_color=border_clr, corner_radius=8)
        dest_section.pack(fill=tk.X, pady=(0, 10))
        dest_inner = ctk.CTkFrame(dest_section, fg_color="transparent")
        dest_inner.pack(fill=tk.X, padx=15, pady=10)

        ctk.CTkLabel(dest_inner, text="Сеть назначения:", anchor=tk.W,
                      font=("Arial", 13, "bold")).pack(fill=tk.X)
        self.dest_var = tk.StringVar(value=self.route.destination if self.route else "")
        self.dest_entry = ctk.CTkEntry(dest_inner, textvariable=self.dest_var,
                                        placeholder_text="например: 192.168.10.0",
                                        height=35)
        self.dest_entry.pack(fill=tk.X, pady=(5, 5))

        ctk.CTkLabel(dest_inner, text="Маска сети:", anchor=tk.W,
                      font=("Arial", 13, "bold")).pack(fill=tk.X, pady=(5, 0))
        mask_frame = ctk.CTkFrame(dest_inner, fg_color="transparent")
        mask_frame.pack(fill=tk.X, pady=(5, 0))
        self.mask_var = tk.StringVar(value=self.route.netmask if self.route else "")
        self.mask_entry = ctk.CTkEntry(
            mask_frame, textvariable=self.mask_var,
            placeholder_text="24 или 255.255.255.0", width=220, height=35
        )
        self.mask_entry.pack(side=tk.LEFT)
        ctk.CTkLabel(mask_frame, text="CIDR (0–32) или десятичная",
                      font=("Arial", 10), text_color="gray").pack(side=tk.LEFT, padx=(10, 0))

        # ===== Секция: Маршрутизация =====
        route_section = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                      border_color=border_clr, corner_radius=8)
        route_section.pack(fill=tk.X, pady=(0, 10))
        route_inner = ctk.CTkFrame(route_section, fg_color="transparent")
        route_inner.pack(fill=tk.X, padx=15, pady=10)

        ctk.CTkLabel(route_inner, text="Next-hop (шлюз):", anchor=tk.W,
                      font=("Arial", 13, "bold")).pack(fill=tk.X)
        gw_frame = ctk.CTkFrame(route_inner, fg_color="transparent")
        gw_frame.pack(fill=tk.X, pady=(5, 5))
        self.gw_var = tk.StringVar(value=self.route.gateway if self.route else "")
        self.gw_entry = ctk.CTkEntry(
            gw_frame, textvariable=self.gw_var, placeholder_text="192.168.1.1",
            width=220, height=35
        )
        self.gw_entry.pack(side=tk.LEFT)
        ctk.CTkLabel(gw_frame, text="IP соседнего устройства на тракте",
                      font=("Arial", 10), text_color="gray").pack(side=tk.LEFT, padx=(10, 0))

        ctk.CTkLabel(route_inner, text="Выходной интерфейс:", anchor=tk.W,
                      font=("Arial", 13, "bold")).pack(fill=tk.X, pady=(5, 0))
        interfaces = self.get_available_interfaces()
        default_iface = (self.route.interface if self.route and self.route.interface in interfaces
                          else (interfaces[0] if interfaces else ""))
        self.iface_var = tk.StringVar(value=default_iface)
        self.iface_combo = ctk.CTkComboBox(
            route_inner, values=interfaces, variable=self.iface_var, height=35
        )
        self.iface_combo.pack(fill=tk.X, pady=(5, 5))

        ctk.CTkLabel(route_inner, text="Metric (ниже = приоритетнее):", anchor=tk.W,
                      font=("Arial", 13, "bold")).pack(fill=tk.X, pady=(5, 0))
        metric_frame = ctk.CTkFrame(route_inner, fg_color="transparent")
        metric_frame.pack(fill=tk.X, pady=(5, 0))
        self.metric_var = tk.IntVar(value=self.route.metric if self.route else 10)
        ctk.CTkButton(
            metric_frame, text="-", width=40, height=35,
            command=lambda: self.metric_var.set(max(0, self.metric_var.get() - 1))
        ).pack(side=tk.LEFT, padx=2)
        self.metric_entry = ctk.CTkEntry(
            metric_frame, textvariable=self.metric_var, width=80,
            justify="center", height=35
        )
        self.metric_entry.pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(
            metric_frame, text="+", width=40, height=35,
            command=lambda: self.metric_var.set(min(999, self.metric_var.get() + 1))
        ).pack(side=tk.LEFT, padx=2)
        ctk.CTkLabel(
            metric_frame, text="обычно 1–10 для static, 10–100 для default",
            font=("Arial", 10), text_color="gray"
        ).pack(side=tk.LEFT, padx=(10, 0))

        # ===== Кнопки =====
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkButton(
            btn_frame, text="✅ Сохранить", command=self.save_route,
            fg_color="#4CAF50", width=120, height=38, font=("Arial", 13, "bold")
        ).pack(side=tk.RIGHT, padx=5)
        ctk.CTkButton(
            btn_frame, text="✕ Отмена", command=self.dialog.destroy,
            fg_color="#CD3333", width=100, height=38, font=("Arial", 13)
        ).pack(side=tk.RIGHT, padx=5)

    def _apply_route_type_state(self):
        """Disable/enable поля в зависимости от выбранного типа маршрута."""
        rtype = self.route_type_var.get()
        if rtype == ROUTE_TYPE_DEFAULT:
            # Default route: destination/mask заблокированы (всегда 0.0.0.0/0)
            self.dest_var.set("0.0.0.0")
            self.mask_var.set("0")
            try:
                self.dest_entry.configure(state="disabled")
                self.mask_entry.configure(state="disabled")
            except Exception:
                pass
        else:
            try:
                self.dest_entry.configure(state="normal")
                self.mask_entry.configure(state="normal")
            except Exception:
                pass
            # Если пришли из default → очищаем 0.0.0.0 чтобы не путать
            if self.dest_var.get() == "0.0.0.0" and self.mask_var.get() == "0":
                if not self.route:
                    self.dest_var.set("")
                    self.mask_var.set("")

    def save_route(self):
        """Сохраняет маршрут после валидации и нормализации.

        Проверки:
        - destination — валидный IPv4 (или "0.0.0.0" для default).
        - netmask — CIDR (0–32) либо десятичная маска.
        - gateway — валидный IPv4.
        - metric — целое ≥ 0.

        Нормализация:
        - destination переписывается в сетевой адрес по маске (host-биты = 0).
        - Маска приводится к CIDR.
        """
        rtype = self.route_type_var.get()
        dest = self.dest_var.get().strip()
        mask = self.mask_var.get().strip() or "0"
        gw = self.gw_var.get().strip() or "0.0.0.0"
        iface = self.iface_var.get().strip()

        try:
            metric = int(self.metric_var.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Ошибка", "Метрика должна быть целым числом.")
            return
        if metric < 0:
            messagebox.showerror("Ошибка", "Метрика не может быть отрицательной.")
            return

        # Для default route — принудительно 0.0.0.0/0
        if rtype == ROUTE_TYPE_DEFAULT:
            dest = "0.0.0.0"
            mask = "0"

        if not dest:
            messagebox.showerror("Ошибка", "Укажите сеть назначения (IP).")
            return
        if not validate_ip(dest):
            messagebox.showerror("Ошибка", f"Некорректный IP сети назначения: {dest}")
            return
        if not validate_ip(gw):
            messagebox.showerror("Ошибка", f"Некорректный IP шлюза: {gw}")
            return

        # Маска → CIDR
        if mask.isdigit():
            cidr = int(mask)
            if not (0 <= cidr <= 32):
                messagebox.showerror("Ошибка", "CIDR маски должен быть в диапазоне 0..32.")
                return
        else:
            cidr = decimal_mask_to_cidr(mask)
            if cidr == 0 and mask != "0.0.0.0":
                messagebox.showerror("Ошибка", f"Некорректная маска: {mask}")
                return

        # Нормализация destination
        normalized_dest = calculate_network(dest, str(cidr))

        # Static с маской /0 — ошибка (это должен быть default)
        if rtype == ROUTE_TYPE_STATIC and cidr == 0:
            messagebox.showerror(
                "Ошибка",
                "Маршрут с маской /0 — это маршрут по умолчанию. "
                "Выберите тип «Default»."
            )
            return

        # Default-маршрут должен иметь nonzero gateway
        if rtype == ROUTE_TYPE_DEFAULT and gw == "0.0.0.0":
            messagebox.showerror(
                "Ошибка",
                "Для default-маршрута нужно указать реальный IP шлюза (next-hop)."
            )
            return

        if self.route:
            self.route.destination = normalized_dest
            self.route.netmask = str(cidr)
            self.route.gateway = gw
            self.route.interface = iface
            self.route.metric = metric
            self.result = self.route
        else:
            self.result = Route(
                route_id=uid(),
                destination=normalized_dest,
                netmask=str(cidr),
                gateway=gw,
                interface=iface,
                metric=metric
            )

        self.dialog.destroy()


# ===========================================================================
# RoutingTableDialog — главная таблица маршрутов
# ===========================================================================


class RoutingTableDialog:
    """Главный диалог управления таблицей маршрутизации.

    Отображает маршруты, сгруппированные по типу:
    - [C] Connected — прямо подключённые сети (автоматически из портов,
      read-only, нельзя редактировать или удалить);
    - [S] Static — ручные статические маршруты (можно добавлять/править/удалять);
    - [D] Default — маршрут по умолчанию (0.0.0.0/0).

    Внутри каждой группы маршруты отсортированы по Longest Prefix Match:
    чем длиннее префикс, тем выше в списке; при равной длине — по метрике.
    """

    def __init__(self, parent, node: Node):
        self.parent = parent
        self.node = node
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Таблица маршрутизации: {node.name}")
        self.dialog.geometry("1050x640")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.create_widgets()
        self.center_window()
        self.refresh_table()

    def center_window(self):
        self.dialog.update_idletasks()
        geo = self.dialog.geometry()
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
        section_bg = "#F5F5F5" if ctk.get_appearance_mode() == "Light" else "#2B2B2B"
        border_clr = "#CCCCCC" if ctk.get_appearance_mode() == "Light" else "#3D3D3D"
        self.dialog.configure(fg_color=section_bg)

        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # ===== Заголовок =====
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(title_frame, text="📋 Таблица маршрутизации",
                      font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        ctk.CTkLabel(
            title_frame,
            text=f"   Узел: {self.node.name}   •   Longest Prefix Match",
            font=("Arial", 11), text_color="gray"
        ).pack(side=tk.LEFT, padx=(15, 0))

        # ===== Легенда =====
        legend_frame = ctk.CTkFrame(main_frame, fg_color=section_bg,
                                      border_width=1, border_color=border_clr,
                                      corner_radius=8)
        legend_frame.pack(fill=tk.X, pady=(0, 10))
        legend_inner = ctk.CTkFrame(legend_frame, fg_color="transparent")
        legend_inner.pack(fill=tk.X, padx=12, pady=8)

        for text, color, fg in [
            ("C — Connected (подключённая сеть)", "#C8E6C9", "#1B5E20"),
            ("S — Static (ручной маршрут)", "#FFFFFF", "#333333"),
            ("D — Default (0.0.0.0/0)", "#BBDEFB", "#0D47A1"),
        ]:
            pill = tk.Label(
                legend_inner, text=text, bg=color, fg=fg,
                font=("Arial", 10, "bold"), padx=8, pady=2, bd=1, relief=tk.SOLID
            )
            pill.pack(side=tk.LEFT, padx=(0, 8))

        # ===== Панель инструментов =====
        toolbar = ctk.CTkFrame(main_frame, fg_color="transparent")
        toolbar.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkButton(toolbar, text="➕ Добавить", command=self.add_route,
                       width=110, height=32).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="✏️ Изменить", command=self.edit_route,
                       width=110, height=32).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="🗑 Удалить", command=self.delete_route,
                       width=110, height=32, fg_color="#F44336").pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="📋 Копировать CLI", command=self.copy_route,
                       width=140, height=32).pack(side=tk.LEFT, padx=2)

        self.routes_count_label = ctk.CTkLabel(toolbar, text="", font=("Arial", 11))
        self.routes_count_label.pack(side=tk.LEFT, padx=(15, 0))

        ctk.CTkButton(toolbar, text="✅ Сохранить и закрыть", command=self.save,
                       width=170, height=32, fg_color="#4CAF50").pack(side=tk.RIGHT)

        # ===== Таблица маршрутов =====
        table_frame = ctk.CTkFrame(main_frame, fg_color=section_bg,
                                     border_width=1, border_color=border_clr,
                                     corner_radius=8)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Тип", "Сеть назначения", "Маска", "Next-hop", "Интерфейс", "Metric", "Источник")

        style = ttk.Style()
        if ctk.get_appearance_mode() == "Dark":
            style.theme_use("clam")
            style.configure("Routing.Treeview", background="#2b2b2b", foreground="white",
                             fieldbackground="#2b2b2b", font=("Arial", 10), rowheight=26)
            style.configure("Routing.Treeview.Heading", background="#3b3b3b", foreground="white",
                             font=("Arial", 10, "bold"))
        else:
            style.theme_use("clam")
            style.configure("Routing.Treeview", background="white", foreground="black",
                             fieldbackground="white", font=("Arial", 10), rowheight=26)
            style.configure("Routing.Treeview.Heading", background="#e0e0e0", foreground="black",
                             font=("Arial", 10, "bold"))

        tree_wrapper = ctk.CTkFrame(table_frame, fg_color="transparent")
        tree_wrapper.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        vsb = ttk.Scrollbar(tree_wrapper, orient="vertical")
        hsb = ttk.Scrollbar(tree_wrapper, orient="horizontal")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree = ttk.Treeview(
            tree_wrapper, columns=columns, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            height=18, selectmode="browse", style="Routing.Treeview"
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        col_widths = [50, 170, 90, 150, 120, 80, 280]
        col_anchors = ["center", "w", "center", "w", "w", "center", "w"]
        for col, width, anchor in zip(columns, col_widths, col_anchors):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=anchor)

        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-Button-1>", lambda e: self.edit_route())

        # Теги для раскрашивания по типу
        if ctk.get_appearance_mode() == "Light":
            self.tree.tag_configure("connected", background="#E8F5E9", foreground="#1B5E20")
            self.tree.tag_configure("default", background="#E3F2FD", foreground="#0D47A1")
            self.tree.tag_configure("static", background="#FFFFFF", foreground="#333333")
        else:
            self.tree.tag_configure("connected", background="#1B3A1B", foreground="#A5D6A7")
            self.tree.tag_configure("default", background="#1A3A4A", foreground="#90CAF9")
            self.tree.tag_configure("static", background="#2b2b2b", foreground="white")

    # -------------------------------------------------------------------
    # Connected routes — динамически из портов узла
    # -------------------------------------------------------------------
    def _get_connected_routes(self) -> List[Dict[str, Any]]:
        """Возвращает список connected routes из портов узла (read-only)."""
        connected: List[Dict[str, Any]] = []
        seen_keys = set()
        for port in self.node.ports:
            ip = port.get("ip_address", "")
            mask = port.get("subnet_mask", "")
            iface = port.get("name", "")
            if not (ip and mask):
                continue
            # Нормализуем маску → CIDR
            if str(mask).isdigit():
                cidr = int(mask)
            else:
                cidr = decimal_mask_to_cidr(mask)
            if cidr <= 0 or cidr > 32:
                continue
            try:
                network = calculate_network(ip, str(cidr))
            except Exception:
                continue
            key = (network, cidr, iface)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            connected.append({
                "destination": network,
                "cidr": cidr,
                "gateway": "0.0.0.0",
                "interface": iface,
                "metric": 0,
                "source": f"auto: IP порта {ip}/{cidr}",
                "type": "C",
            })
        return connected

    # -------------------------------------------------------------------
    # Отрисовка таблицы
    # -------------------------------------------------------------------
    def refresh_table(self):
        """Перерисовывает таблицу.

        Порядок: Connected → Static → Default. Внутри каждой группы —
        сортировка по longest prefix match (префикс ↓, метрика ↑).
        """
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not hasattr(self.node, 'routing_table'):
            self.node.routing_table = []

        # 1. Connected routes (read-only, автоматические)
        connected = self._get_connected_routes()
        connected.sort(key=lambda r: (-r["cidr"], r["metric"]))

        for r in connected:
            iid = f"connected_{r['destination']}_{r['cidr']}_{r['interface']}"
            self.tree.insert(
                "", tk.END, iid=iid,
                values=(
                    "C",
                    r["destination"],
                    f"/{r['cidr']}",
                    "— (directly)",
                    r["interface"],
                    r["metric"],
                    r["source"],
                ),
                tags=("connected",)
            )

        # 2. Static + Default (ручные — из node.routing_table)
        manual_routes = [Route.from_dict(rd) for rd in self.node.routing_table]
        manual_routes.sort(key=lambda r: (-r.prefix_length(), r.metric or 0))

        for route in manual_routes:
            is_default = route.is_default_route()
            type_tag = "default" if is_default else "static"
            type_letter = "D" if is_default else "S"
            source = "default gateway" if is_default else "static route"
            netmask_display = route.netmask if not route.netmask.isdigit() else f"/{route.netmask}"
            self.tree.insert(
                "", tk.END, iid=route.route_id,
                values=(
                    type_letter,
                    route.destination,
                    netmask_display,
                    route.gateway if route.gateway != "0.0.0.0" else "— (direct)",
                    route.interface,
                    route.metric,
                    source,
                ),
                tags=(type_tag,)
            )

        total_manual = len(manual_routes)
        total_connected = len(connected)
        self.routes_count_label.configure(
            text=(f"📊  C: {total_connected}   •   "
                  f"S: {sum(1 for r in manual_routes if not r.is_default_route())}   •   "
                  f"D: {sum(1 for r in manual_routes if r.is_default_route())}   "
                  f"(всего строк: {total_connected + total_manual})"),
            text_color="gray"
        )

    # -------------------------------------------------------------------
    # Обработчики кнопок
    # -------------------------------------------------------------------
    def get_selected_route_id(self) -> Optional[str]:
        selection = self.tree.selection()
        return selection[0] if selection else None

    def _is_connected_iid(self, iid: str) -> bool:
        return isinstance(iid, str) and iid.startswith("connected_")

    def add_route(self):
        dialog = RouteEditDialog(self.dialog, self.node)
        self.dialog.wait_window(dialog.dialog)
        if dialog.result:
            self.node.routing_table.append(dialog.result.to_dict())
            self.refresh_table()

    def edit_route(self):
        iid = self.get_selected_route_id()
        if not iid:
            messagebox.showwarning("Предупреждение", "Выберите маршрут для редактирования.")
            return

        if self._is_connected_iid(iid):
            messagebox.showinfo(
                "Connected route",
                "Это прямо подключённая сеть (connected route). Она автоматически "
                "отслеживает IP и маску порта узла.\n\n"
                "Чтобы изменить её — измените параметры соответствующего порта "
                "во вкладке «Сеть» свойств узла."
            )
            return

        route_data = None
        for rd in self.node.routing_table:
            if rd.get("route_id") == iid:
                route_data = rd
                break
        if not route_data:
            return

        route = Route.from_dict(route_data)
        dialog = RouteEditDialog(self.dialog, self.node, route)
        self.dialog.wait_window(dialog.dialog)
        if dialog.result:
            for i, rd in enumerate(self.node.routing_table):
                if rd.get("route_id") == iid:
                    self.node.routing_table[i] = dialog.result.to_dict()
                    break
            self.refresh_table()

    def delete_route(self):
        iid = self.get_selected_route_id()
        if not iid:
            messagebox.showwarning("Предупреждение", "Выберите маршрут для удаления.")
            return

        if self._is_connected_iid(iid):
            messagebox.showwarning(
                "Connected route",
                "Connected route нельзя удалить вручную — он зависит от IP порта узла.\n"
                "Чтобы убрать его из таблицы, удалите IP/маску соответствующего порта."
            )
            return

        route_data = None
        for rd in self.node.routing_table:
            if rd.get("route_id") == iid:
                route_data = rd
                break
        if route_data:
            route = Route.from_dict(route_data)
            if messagebox.askyesno(
                "Удаление маршрута",
                f"Удалить маршрут к {route.destination}/{route.netmask}?"
            ):
                self.node.routing_table = [
                    r for r in self.node.routing_table if r.get("route_id") != iid
                ]
                self.refresh_table()

    def copy_route(self):
        iid = self.get_selected_route_id()
        if not iid:
            return

        if self._is_connected_iid(iid):
            values = self.tree.item(iid, "values")
            dest, mask = values[1], values[2]
            text = f"# connected route {dest}{mask} (auto, via interface {values[4]})"
        else:
            route_data = None
            for rd in self.node.routing_table:
                if rd.get("route_id") == iid:
                    route_data = rd
                    break
            if not route_data:
                return
            route = Route.from_dict(route_data)
            # Формат Linux iproute2
            text = (
                f"ip route add {route.destination}/{route.netmask} via {route.gateway} "
                f"dev {route.interface} metric {route.metric}"
            )

        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(text)
        messagebox.showinfo("Скопировано", f"Команда скопирована в буфер:\n\n{text}")

    def save(self):
        self.result = self.node.routing_table
        self.dialog.destroy()
