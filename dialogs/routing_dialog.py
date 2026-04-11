"""
Модуль диалога таблицы маршрутизации

Содержит классы:
- RouteEditDialog: Диалог создания/редактирования одного маршрута
- RoutingTableDialog: Главный диалог управления таблицей маршрутизации
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from typing import List, Optional

from models.node import Node
from models.route import Route
from utils.generators import uid
from utils.network_utils import calculate_network, decimal_mask_to_cidr
from utils.validators import validate_ip


class RouteEditDialog:
    """Диалог для создания/редактирования одного маршрута."""

    def __init__(self, parent, node: Node, route: Optional[Route] = None):
        self.parent = parent
        self.node = node
        self.route = route
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Редактирование маршрута" if route else "Новый маршрут")
        self.dialog.geometry("550x650")
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

    def get_available_interfaces(self) -> List[str]:
        """Возвращает список доступных интерфейсов узла."""
        interfaces = []
        for port in self.node.ports:
            if port.get("port_type") in ["ethernet", "pon", "wifi"]:
                interfaces.append(port.get("name", f"port{port.get('port_number', 0)}"))
        return interfaces if interfaces else ["eth0"]

    def create_widgets(self):
        section_bg = "#F5F5F5" if ctk.get_appearance_mode() == "Light" else "#2B2B2B"
        self.dialog.configure(fg_color=section_bg)

        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Заголовок
        ctk.CTkLabel(
            main_frame, text="Параметры маршрута",
            font=("Arial", 18, "bold")
        ).pack(pady=(0, 15))

        # Секция: Назначение
        dest_section = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                     border_color="#CCCCCC", corner_radius=8)
        dest_section.pack(fill=tk.X, pady=(0, 10))
        dest_inner = ctk.CTkFrame(dest_section, fg_color="transparent")
        dest_inner.pack(fill=tk.X, padx=15, pady=10)

        ctk.CTkLabel(dest_inner, text="Сеть назначения:", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X)
        self.dest_var = tk.StringVar(value=self.route.destination if self.route else "")
        ctk.CTkEntry(dest_inner, textvariable=self.dest_var, placeholder_text="например: 192.168.1.0", height=35).pack(
            fill=tk.X, pady=(5, 5))

        ctk.CTkLabel(dest_inner, text="Маска сети:", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X, pady=(5, 0))
        mask_frame = ctk.CTkFrame(dest_inner, fg_color="transparent")
        mask_frame.pack(fill=tk.X, pady=(5, 0))
        self.mask_var = tk.StringVar(value=self.route.netmask if self.route else "")
        self.mask_entry = ctk.CTkEntry(mask_frame, textvariable=self.mask_var, placeholder_text="255.255.255.0 или 24",
                                       width=200, height=35)
        self.mask_entry.pack(side=tk.LEFT)
        ctk.CTkLabel(mask_frame, text="десятичная или CIDR", font=("Arial", 10), text_color="gray").pack(side=tk.LEFT, padx=(10, 0))

        # Секция: Маршрутизация
        route_section = ctk.CTkFrame(main_frame, fg_color=section_bg, border_width=1,
                                      border_color="#CCCCCC", corner_radius=8)
        route_section.pack(fill=tk.X, pady=(0, 10))
        route_inner = ctk.CTkFrame(route_section, fg_color="transparent")
        route_inner.pack(fill=tk.X, padx=15, pady=10)

        ctk.CTkLabel(route_inner, text="Шлюз (Gateway):", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X)
        gw_frame = ctk.CTkFrame(route_inner, fg_color="transparent")
        gw_frame.pack(fill=tk.X, pady=(5, 5))
        self.gw_var = tk.StringVar(value=self.route.gateway if self.route else "")
        self.gw_entry = ctk.CTkEntry(gw_frame, textvariable=self.gw_var, placeholder_text="192.168.1.1", width=200, height=35)
        self.gw_entry.pack(side=tk.LEFT)
        ctk.CTkLabel(gw_frame, text="0.0.0.0 для прямого подключения", font=("Arial", 10), text_color="gray").pack(side=tk.LEFT, padx=(10, 0))

        ctk.CTkLabel(route_inner, text="Интерфейс:", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X, pady=(5, 0))
        interfaces = self.get_available_interfaces()
        default_iface = self.route.interface if self.route and self.route.interface in interfaces else (
            interfaces[0] if interfaces else "")
        self.iface_var = tk.StringVar(value=default_iface)
        self.iface_combo = ctk.CTkComboBox(route_inner, values=interfaces, variable=self.iface_var, height=35)
        self.iface_combo.pack(fill=tk.X, pady=(5, 5))

        ctk.CTkLabel(route_inner, text="Метрика (приоритет):", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X, pady=(5, 0))
        metric_frame = ctk.CTkFrame(route_inner, fg_color="transparent")
        metric_frame.pack(fill=tk.X, pady=(5, 0))
        self.metric_var = tk.IntVar(value=self.route.metric if self.route else 10)
        ctk.CTkButton(metric_frame, text="-", width=40, height=35,
                      command=lambda: self.metric_var.set(max(1, self.metric_var.get() - 1))).pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(metric_frame, textvariable=self.metric_var, width=80, justify="center", height=35).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(metric_frame, text="+", width=40, height=35,
                      command=lambda: self.metric_var.set(min(999, self.metric_var.get() + 1))).pack(side=tk.LEFT, padx=2)
        ctk.CTkLabel(metric_frame, text="меньше = выше приоритет", font=("Arial", 10), text_color="gray").pack(side=tk.LEFT, padx=(10, 0))

        # Кнопки
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        ctk.CTkButton(btn_frame, text="✅ Сохранить", command=self.save_route, fg_color="#4CAF50", width=120, height=38,
                      font=("Arial", 13, "bold")).pack(side=tk.RIGHT, padx=5)
        ctk.CTkButton(btn_frame, text="✕ Отмена", command=self.dialog.destroy, fg_color="#CD3333", width=100, height=38,
                      font=("Arial", 13)).pack(side=tk.RIGHT, padx=5)

        # Подсказка
        tip_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        tip_frame.pack(fill=tk.X, pady=(15, 0))
        ctk.CTkLabel(tip_frame, text="💡 Маршрут по умолчанию: сеть 0.0.0.0, маска 0.0.0.0", font=("Arial", 10),
                     text_color="gray").pack()

    def save_route(self):
        """Сохраняет маршрут после валидации и нормализации.

        Проверки:
        - destination — валидный IPv4 (или "0.0.0.0" для маршрута по умолчанию).
        - netmask — CIDR (0–32) либо десятичная маска (255.х.х.х).
        - gateway — валидный IPv4 (или "0.0.0.0" для прямого маршрута).
        - metric — целое неотрицательное.

        Нормализация:
        - destination переписывается в сетевой адрес по маске
          (host-биты обнуляются), как это делает реальный роутер.
        - Маска приводится к CIDR для единообразия.
        """
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

        if not dest:
            messagebox.showerror("Ошибка", "Укажите сеть назначения (IP).")
            return
        if not validate_ip(dest):
            messagebox.showerror("Ошибка", f"Некорректный IP сети назначения: {dest}")
            return
        if not validate_ip(gw):
            messagebox.showerror("Ошибка", f"Некорректный IP шлюза: {gw}")
            return

        # Нормализуем маску: принимаем и «24», и «255.255.255.0»
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

        # Нормализуем destination к сетевому адресу (host-биты = 0)
        normalized_dest = calculate_network(dest, str(cidr))

        # Проверка согласованности default-маршрута
        if cidr == 0 and normalized_dest != "0.0.0.0":
            messagebox.showerror(
                "Ошибка",
                "Маршрут с маской /0 — это маршрут по умолчанию, "
                "destination должен быть 0.0.0.0."
            )
            return

        # Запрещаем явно битые сочетания (direct-route должен иметь gateway=0.0.0.0)
        if gw != "0.0.0.0":
            # Сам шлюз не должен совпадать с сетью назначения (он должен быть хостом)
            if calculate_network(gw, str(cidr)) == normalized_dest and cidr < 32:
                pass  # валидно: шлюз находится в той же подсети — типичный случай

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


class RoutingTableDialog:
    """Главный диалог управления таблицей маршрутизации."""

    def __init__(self, parent, node: Node):
        self.parent = parent
        self.node = node
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Таблица маршрутизации: {node.name}")
        self.dialog.geometry("950x550")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.create_widgets()
        self.center_window()
        self.refresh_table()

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
        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Заголовок
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(title_frame, text="📋 Таблица маршрутизации", font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        ctk.CTkLabel(title_frame, text=f"Узел: {self.node.name}", font=("Arial", 12), text_color="gray").pack(
            side=tk.LEFT, padx=(15, 0))

        # Панель инструментов
        toolbar = ctk.CTkFrame(main_frame, fg_color="transparent")
        toolbar.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkButton(toolbar, text="➕ Добавить", command=self.add_route, width=100, height=32).pack(side=tk.LEFT,
                                                                                                     padx=2)
        ctk.CTkButton(toolbar, text="✏️ Изменить", command=self.edit_route, width=100, height=32).pack(side=tk.LEFT,
                                                                                                       padx=2)
        ctk.CTkButton(toolbar, text="🗑 Удалить", command=self.delete_route, width=100, height=32,
                      fg_color="#F44336").pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="📋 Копировать", command=self.copy_route, width=100, height=32).pack(side=tk.LEFT,
                                                                                                        padx=2)

        # Информация
        info_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        info_frame.pack(fill=tk.X, pady=(0, 10))

        self.routes_count_label = ctk.CTkLabel(info_frame, text="", font=("Arial", 11))
        self.routes_count_label.pack(side=tk.LEFT)

        ctk.CTkButton(info_frame, text="✅ Сохранить и закрыть", command=self.save, width=140, height=32,
                      fg_color="#4CAF50").pack(side=tk.RIGHT)

        # Таблица
        table_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Сеть назначения", "Маска", "Шлюз", "Интерфейс", "Метрика")

        style = ttk.Style()
        if ctk.get_appearance_mode() == "Dark":
            style.theme_use("clam")
            style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
            style.configure("Treeview.Heading", background="#3b3b3b", foreground="white")
        else:
            style.theme_use("clam")
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
            style.configure("Treeview.Heading", background="#f0f0f0", foreground="black")

        vsb = ttk.Scrollbar(table_frame, orient="vertical")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            height=18, selectmode="browse"
        )

        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        col_widths = [150, 120, 150, 120, 80]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center")

        self.tree.column("Сеть назначения", anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.bind("<Double-Button-1>", lambda e: self.edit_route())

    def get_selected_route_id(self) -> Optional[str]:
        selection = self.tree.selection()
        return selection[0] if selection else None

    def refresh_table(self):
        """Обновляет таблицу из данных узла.

        Маршруты сортируются по:
        1) Длине префикса (длинная маска — более специфичный маршрут, выше);
        2) Метрике (меньше — выше);
        Это соответствует порядку Longest Prefix Match: роутер выбирает
        первый подходящий маршрут именно в таком порядке.
        """
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not hasattr(self.node, 'routing_table'):
            self.node.routing_table = []

        # Сортировка по longest prefix match → метрика → стабильный порядок
        routes = [Route.from_dict(rd) for rd in self.node.routing_table]
        routes.sort(key=lambda r: (-r.prefix_length(), r.metric or 0))

        for route in routes:
            tags = ()
            if route.is_default_route():
                tags = ('default',)
            elif route.is_connected_route():
                tags = ('connected',)

            netmask_display = route.netmask if not route.netmask.isdigit() else f"/{route.netmask}"

            self.tree.insert("", tk.END, iid=route.route_id, values=(
                route.destination, netmask_display, route.gateway, route.interface, route.metric
            ), tags=tags)

        if ctk.get_appearance_mode() == "Light":
            self.tree.tag_configure('default', background='#e3f2fd')
            self.tree.tag_configure('connected', background='#e8f5e9')
        else:
            self.tree.tag_configure('default', background='#1a3a4a')
            self.tree.tag_configure('connected', background='#1b3a1b')

        self.routes_count_label.configure(
            text=f"✅ Всего маршрутов: {len(self.node.routing_table)}   "
                 f"(сортировка: longest prefix match)",
            text_color="green"
        )

    def add_route(self):
        dialog = RouteEditDialog(self.dialog, self.node)
        self.dialog.wait_window(dialog.dialog)
        if dialog.result:
            self.node.routing_table.append(dialog.result.to_dict())
            self.refresh_table()

    def edit_route(self):
        route_id = self.get_selected_route_id()
        if not route_id:
            messagebox.showwarning("Предупреждение", "Выберите маршрут для редактирования!")
            return

        route_data = None
        for rd in self.node.routing_table:
            if rd.get("route_id") == route_id:
                route_data = rd
                break

        if route_data:
            route = Route.from_dict(route_data)
            dialog = RouteEditDialog(self.dialog, self.node, route)
            self.dialog.wait_window(dialog.dialog)
            if dialog.result:
                for i, rd in enumerate(self.node.routing_table):
                    if rd.get("route_id") == route_id:
                        self.node.routing_table[i] = dialog.result.to_dict()
                        break
                self.refresh_table()

    def delete_route(self):
        route_id = self.get_selected_route_id()
        if not route_id:
            messagebox.showwarning("Предупреждение", "Выберите маршрут для удаления!")
            return

        route_data = None
        for rd in self.node.routing_table:
            if rd.get("route_id") == route_id:
                route_data = rd
                break

        if route_data:
            route = Route.from_dict(route_data)
            if messagebox.askyesno("Удаление маршрута", f"Удалить маршрут к {route.destination}/{route.netmask}?"):
                self.node.routing_table = [r for r in self.node.routing_table if r.get("route_id") != route_id]
                self.refresh_table()

    def copy_route(self):
        route_id = self.get_selected_route_id()
        if not route_id:
            return

        for rd in self.node.routing_table:
            if rd.get("route_id") == route_id:
                route = Route.from_dict(rd)
                text = f"route add -net {route.destination} netmask {route.netmask} gw {route.gateway}"
                self.dialog.clipboard_clear()
                self.dialog.clipboard_append(text)
                messagebox.showinfo("Скопировано", "Команда маршрута скопирована в буфер обмена")
                break

    def save(self):
        self.result = self.node.routing_table
        self.dialog.destroy()