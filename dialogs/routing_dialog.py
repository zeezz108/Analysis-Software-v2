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
from utils.network_utils import calculate_network


class RouteEditDialog:
    """Диалог для создания/редактирования одного маршрута."""

    def __init__(self, parent, node: Node, route: Optional[Route] = None):
        self.parent = parent
        self.node = node
        self.route = route
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Редактирование маршрута" if route else "Новый маршрут")
        self.dialog.geometry("550x500")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.center_window()
        self.create_widgets()

    def center_window(self):
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
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
        main_frame = ctk.CTkFrame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=25)

        # Заголовок
        ctk.CTkLabel(
            main_frame, text="Параметры маршрута",
            font=("Arial", 18, "bold")
        ).pack(pady=(0, 20))

        # Сеть назначения
        ctk.CTkLabel(main_frame, text="🌐 Сеть назначения:", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X,
                                                                                                          pady=(5, 0))
        self.dest_var = tk.StringVar(value=self.route.destination if self.route else "")
        ctk.CTkEntry(main_frame, textvariable=self.dest_var, placeholder_text="например: 192.168.1.0", height=35).pack(
            fill=tk.X, pady=(0, 10))

        # Маска сети
        ctk.CTkLabel(main_frame, text="🔢 Маска сети:", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X,
                                                                                                     pady=(5, 0))
        mask_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        mask_frame.pack(fill=tk.X, pady=(0, 10))

        self.mask_var = tk.StringVar(value=self.route.netmask if self.route else "")
        self.mask_entry = ctk.CTkEntry(mask_frame, textvariable=self.mask_var, placeholder_text="255.255.255.0 или 24",
                                       width=200, height=35)
        self.mask_entry.pack(side=tk.LEFT)

        ctk.CTkLabel(mask_frame, text="(десятичная или CIDR)", font=("Arial", 10), text_color="gray").pack(side=tk.LEFT,
                                                                                                           padx=(10, 0))

        # Шлюз
        ctk.CTkLabel(main_frame, text="🚪 Шлюз (Gateway):", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X,
                                                                                                         pady=(5, 0))
        gw_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        gw_frame.pack(fill=tk.X, pady=(0, 10))

        self.gw_var = tk.StringVar(value=self.route.gateway if self.route else "")
        self.gw_entry = ctk.CTkEntry(gw_frame, textvariable=self.gw_var, placeholder_text="192.168.1.1", width=200,
                                     height=35)
        self.gw_entry.pack(side=tk.LEFT)

        ctk.CTkLabel(gw_frame, text="(0.0.0.0 для прямого подключения)", font=("Arial", 10), text_color="gray").pack(
            side=tk.LEFT, padx=(10, 0))

        # Интерфейс
        ctk.CTkLabel(main_frame, text="🔌 Интерфейс:", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X,
                                                                                                    pady=(5, 0))
        interfaces = self.get_available_interfaces()

        default_iface = self.route.interface if self.route and self.route.interface in interfaces else (
            interfaces[0] if interfaces else "")
        self.iface_var = tk.StringVar(value=default_iface)
        self.iface_combo = ctk.CTkComboBox(main_frame, values=interfaces, variable=self.iface_var, height=35)
        self.iface_combo.pack(fill=tk.X, pady=(0, 10))

        # Метрика
        ctk.CTkLabel(main_frame, text="📊 Метрика (приоритет):", anchor=tk.W, font=("Arial", 13, "bold")).pack(fill=tk.X,
                                                                                                              pady=(5,
                                                                                                                    0))
        metric_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        metric_frame.pack(fill=tk.X, pady=(0, 20))

        self.metric_var = tk.IntVar(value=self.route.metric if self.route else 10)

        ctk.CTkButton(metric_frame, text="-", width=40, height=35,
                      command=lambda: self.metric_var.set(max(1, self.metric_var.get() - 1))).pack(side=tk.LEFT, padx=2)
        ctk.CTkEntry(metric_frame, textvariable=self.metric_var, width=80, justify="center", height=35).pack(
            side=tk.LEFT, padx=2)
        ctk.CTkButton(metric_frame, text="+", width=40, height=35,
                      command=lambda: self.metric_var.set(min(999, self.metric_var.get() + 1))).pack(side=tk.LEFT,
                                                                                                     padx=2)

        ctk.CTkLabel(metric_frame, text="(меньше = выше приоритет)", font=("Arial", 10), text_color="gray").pack(
            side=tk.LEFT, padx=(10, 0))

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
        """Сохраняет маршрут."""
        dest = self.dest_var.get().strip()
        mask = self.mask_var.get().strip()
        gw = self.gw_var.get().strip()
        iface = self.iface_var.get().strip()
        metric = self.metric_var.get()

        if not dest:
            messagebox.showerror("Ошибка", "Укажите сеть назначения!")
            return

        if self.route:
            self.route.destination = dest
            self.route.netmask = mask if mask else "0.0.0.0"
            self.route.gateway = gw if gw else "0.0.0.0"
            self.route.interface = iface
            self.route.metric = metric
            self.result = self.route
        else:
            self.result = Route(
                route_id=uid(),
                destination=dest,
                netmask=mask if mask else "0.0.0.0",
                gateway=gw if gw else "0.0.0.0",
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

        self.center_window()
        self.create_widgets()
        self.refresh_table()

    def center_window(self):
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        main_frame = ctk.CTkFrame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Заголовок
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkLabel(title_frame, text="📋 Таблица маршрутизации", font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        ctk.CTkLabel(title_frame, text=f"Узел: {self.node.name}", font=("Arial", 12), text_color="gray").pack(
            side=tk.LEFT, padx=(15, 0))

        # Панель инструментов
        toolbar = ctk.CTkFrame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))

        ctk.CTkButton(toolbar, text="➕ Добавить", command=self.add_route, width=100, height=32).pack(side=tk.LEFT,
                                                                                                     padx=2)
        ctk.CTkButton(toolbar, text="✏️ Изменить", command=self.edit_route, width=100, height=32).pack(side=tk.LEFT,
                                                                                                       padx=2)
        ctk.CTkButton(toolbar, text="🗑 Удалить", command=self.delete_route, width=100, height=32,
                      fg_color="#F44336").pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="⚙️ Авто-генерация", command=self.auto_generate, width=130, height=32).pack(
            side=tk.LEFT, padx=2)
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
        table_frame = ctk.CTkFrame(main_frame)
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
        """Обновляет таблицу из данных узла."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not hasattr(self.node, 'routing_table'):
            self.node.routing_table = []

        for route_data in self.node.routing_table:
            route = Route.from_dict(route_data)

            tags = ()
            if route.destination == "0.0.0.0" and route.netmask == "0.0.0.0":
                tags = ('default',)

            self.tree.insert("", tk.END, iid=route.route_id, values=(
                route.destination, route.netmask, route.gateway, route.interface, route.metric
            ), tags=tags)

        if ctk.get_appearance_mode() == "Light":
            self.tree.tag_configure('default', background='#e3f2fd')
        else:
            self.tree.tag_configure('default', background='#1a3a4a')

        self.routes_count_label.configure(text=f"✅ Всего маршрутов: {len(self.node.routing_table)}", text_color="green")

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

    def auto_generate(self):
        """Автоматически генерирует таблицу маршрутизации."""
        if not messagebox.askyesno("Автогенерация", "Это заменит текущую таблицу маршрутизации. Продолжить?"):
            return

        new_table = []

        # Прямые маршруты
        for port in self.node.ports:
            ip = port.get("ip_address", "")
            mask = port.get("subnet_mask", "")
            port_name = port.get("name", "")

            if ip and mask:
                network = calculate_network(ip, mask)
                new_table.append(Route(
                    route_id=uid(), destination=network, netmask=mask,
                    gateway="0.0.0.0", interface=port_name, metric=1
                ).to_dict())

        # Маршрут по умолчанию
        default_gateway = None
        default_interface = None

        for port in self.node.ports:
            if port.get("connected_to") and port.get("ip_address"):
                default_interface = port.get("name", "")
                default_gateway = port.get("ip_address", "")
                break

        if default_interface:
            new_table.append(Route(
                route_id=uid(), destination="0.0.0.0", netmask="0.0.0.0",
                gateway=default_gateway if default_gateway else "192.168.1.1",
                interface=default_interface, metric=10
            ).to_dict())

        self.node.routing_table = new_table
        self.refresh_table()
        messagebox.showinfo("Успех", f"Сгенерировано {len(new_table)} маршрутов")

    def save(self):
        self.result = self.node.routing_table
        self.dialog.destroy()