"""
Модуль диалога настройки файервола

Содержит классы:
- FirewallDialog: Главный диалог настройки файервола
- FirewallRuleDialog: Диалог создания/редактирования правила
"""

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from datetime import datetime
import os
import random
from typing import Optional
from utils.theme import center_window

from models.node import Node
from models.firewall import FirewallRule, FirewallManager
from utils.generators import uid


class FirewallDialog:
    """Главный диалог настройки межсетевого экрана."""

    def __init__(self, parent, node: Node, firewall_manager=None):
        self.parent = parent
        self.node = node

        if firewall_manager:
            self.manager = firewall_manager
        else:
            self.manager = FirewallManager(node.id)
            self.add_demo_rules()

        # Флаг фиксации изменений: выставляется только при нажатии «Сохранить».
        # При закрытии окна крестиком или «Отмена» изменения не применяются.
        self.saved = False

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Настройка межсетевого экрана - {node.name}")
        self.dialog.geometry("1300x850")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        # grab_set убран
        # Закрытие через крестик = отмена изменений
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self.create_widgets()
        self.center_window()
        self.refresh_rules_list()

    def _on_cancel(self):
        """Закрытие без сохранения — изменения не применяются."""
        self.saved = False
        self.dialog.destroy()

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

    def add_demo_rules(self):
        """Добавляет демонстрационные правила."""
        # Разрешить базовые входящие
        rule1 = FirewallRule(
            name="Базовая фильтрация (входящие)",
            direction="in", action="allow", protocol="any",
            description="Разрешить входящие подключения для базовой сетевой работы"
        )
        self.manager.add_rule(rule1)

        # Разрешить базовые исходящие
        rule2 = FirewallRule(
            name="Базовая фильтрация (исходящие)",
            direction="out", action="allow", protocol="any",
            description="Разрешить исходящие подключения для базовой сетевой работы"
        )
        self.manager.add_rule(rule2)

        # Удаленный рабочий стол
        if self.node.type in ["ARM", "Laptop", "Server"]:
            rule3 = FirewallRule(
                name="Удаленный рабочий стол (RDP)",
                direction="in", action="allow", protocol="tcp",
                local_ports="3389",
                description="Разрешить входящие подключения по RDP"
            )
            self.manager.add_rule(rule3)

        # Общий доступ к файлам
        if self.node.type in ["Server", "ARM"]:
            rule4 = FirewallRule(
                name="Общий доступ к файлам (SMB)",
                direction="in", action="allow", protocol="tcp",
                local_ports="445,139",
                description="Разрешить входящие SMB-подключения"
            )
            self.manager.add_rule(rule4)

    def get_node_type_russian(self, node_type_en):
        mapping = {
            "Internet": "Интернет", "Router": "Маршрутизатор",
            "Switch": "Коммутатор", "Server": "Сервер",
            "VirtualizationServer": "Сервер виртуализации",
            "ARM": "АРМ", "Laptop": "Ноутбук"
        }
        return mapping.get(node_type_en, node_type_en)

    def create_widgets(self):
        from utils.theme import color as _ftc
        self.dialog.configure(fg_color=_ftc("dialog_bg"))

        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Верхняя панель с информацией
        top_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        top_frame.pack(fill=tk.X, pady=(0, 10))

        # Заголовок — в обводке primary
        from utils.theme import color as _tc
        title_frame = ctk.CTkFrame(top_frame, fg_color=_tc("card_bg"),
                                    border_width=2, border_color=_tc("primary"),
                                    corner_radius=10)
        title_frame.pack(fill=tk.X, padx=10, pady=10)

        ctk.CTkLabel(title_frame, text="🛡", font=("Segoe UI", 36), text_color="#1E88E5").pack(side=tk.LEFT, padx=(0, 10))

        header_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        header_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ctk.CTkLabel(header_frame, text="Межсетевой экран", font=("Segoe UI", 20, "bold")).pack(anchor=tk.W)
        ctk.CTkLabel(
            header_frame, text=f"Узел: {self.node.name} | Тип: {self.get_node_type_russian(self.node.type)}",
            font=("Segoe UI", 11), text_color="gray"
        ).pack(anchor=tk.W)

        # Статус брандмауэра (промт 8 №12: обводка только вокруг «Включен/Отключен»,
        # а не вокруг всей строки)
        status_color = "#4CAF50" if self.manager.firewall_enabled else "#F44336"
        status_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        left_status = ctk.CTkFrame(status_frame, fg_color="transparent")
        left_status.pack(side=tk.LEFT)

        ctk.CTkLabel(left_status, text="Состояние:", font=("Segoe UI", 13, "bold")).pack(side=tk.LEFT, padx=(10, 5))

        # Обводка только вокруг самого статуса
        self.status_pill = ctk.CTkFrame(
            left_status, fg_color="transparent",
            border_width=1, border_color=status_color, corner_radius=6
        )
        self.status_pill.pack(side=tk.LEFT, padx=(0, 10))

        self.status_var = tk.StringVar(value="Включен" if self.manager.firewall_enabled else "Отключен")
        self.status_label = ctk.CTkLabel(
            self.status_pill, textvariable=self.status_var,
            font=("Segoe UI", 13, "bold"),
            text_color="green" if self.manager.firewall_enabled else "red"
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=3)

        # Кнопка включения/выключения
        self.toggle_firewall_btn = ctk.CTkButton(
            status_frame, text="🔴 Выключить" if self.manager.firewall_enabled else "🟢 Включить",
            command=self.toggle_firewall, width=140, height=36,
            fg_color="#F44336" if self.manager.firewall_enabled else "#4CAF50",
            font=("Segoe UI", 12, "bold")
        )
        self.toggle_firewall_btn.pack(side=tk.RIGHT, padx=10)

        # Основная область
        content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Левая панель - фильтры
        left_panel = ctk.CTkFrame(content_frame, width=220, fg_color="transparent")
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        self.create_left_navigation(left_panel)

        # Правая панель - правила
        right_panel = ctk.CTkFrame(content_frame, fg_color="transparent")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.create_rules_panel(right_panel)

        # Нижняя панель
        bottom_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        bottom_frame.pack(fill=tk.X, pady=(10, 0))

        self.notify_var = tk.BooleanVar(value=self.manager.notification_enabled)
        ctk.CTkCheckBox(
            bottom_frame, text="Показывать уведомления о блокировках",
            variable=self.notify_var, command=self.toggle_notifications,
            font=("Segoe UI", 11)
        ).pack(side=tk.LEFT, padx=10)

        btn_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        btn_frame.pack(side=tk.RIGHT)

        ctk.CTkButton(btn_frame, text="✕ Отмена", command=self._on_cancel, width=100).pack(side=tk.RIGHT, padx=5)
        ctk.CTkButton(btn_frame, text="💾 Сохранить", command=self.save_settings, width=100, fg_color="#4CAF50").pack(
            side=tk.RIGHT, padx=5)
        ctk.CTkButton(btn_frame, text="↻ Обновить", command=self.refresh_rules_list, width=100).pack(side=tk.RIGHT,
                                                                                                     padx=5)

    def create_left_navigation(self, parent):
        """Создаёт левую панель с фильтрами."""
        # Заголовок
        ctk.CTkLabel(parent, text="🔍 Фильтры", font=("Segoe UI", 14, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 10))

        # Направление
        ctk.CTkLabel(parent, text="Направление:", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=(5, 5))

        self.direction_var = tk.StringVar(value="all")

        ctk.CTkRadioButton(parent, text="Все правила", variable=self.direction_var, value="all",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="Входящие", variable=self.direction_var, value="in",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="Исходящие", variable=self.direction_var, value="out",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)

        # Разделитель
        ctk.CTkFrame(parent, height=2, fg_color="gray").pack(fill=tk.X, padx=10, pady=15)

        # Действие
        ctk.CTkLabel(parent, text="Действие:", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=(0, 5))

        self.action_var = tk.StringVar(value="all")

        ctk.CTkRadioButton(parent, text="Все", variable=self.action_var, value="all",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="Разрешить", variable=self.action_var, value="allow",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="Блокировать", variable=self.action_var, value="block",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)

        # Разделитель
        ctk.CTkFrame(parent, height=2, fg_color="gray").pack(fill=tk.X, padx=10, pady=15)

        # Протокол
        ctk.CTkLabel(parent, text="Протокол:", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=10, pady=(0, 5))

        self.protocol_var = tk.StringVar(value="all")

        ctk.CTkRadioButton(parent, text="Любой", variable=self.protocol_var, value="all",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="TCP", variable=self.protocol_var, value="tcp",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="UDP", variable=self.protocol_var, value="udp",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)
        ctk.CTkRadioButton(parent, text="ICMP", variable=self.protocol_var, value="icmp",
                           command=self.refresh_rules_list).pack(anchor=tk.W, padx=20, pady=2)

    def create_rules_panel(self, parent):
        """Создаёт панель с правилами."""
        # Панель инструментов
        toolbar = ctk.CTkFrame(parent, fg_color="transparent")
        toolbar.pack(fill=tk.X, padx=10, pady=10)

        ctk.CTkButton(toolbar, text="➕ Создать", command=self.create_rule, width=110).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="✏️ Изменить", command=self.edit_rule, width=90).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="🗑 Удалить", command=self.delete_rule, width=90, fg_color="#F44336").pack(
            side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="⬆ Вверх", command=self.move_rule_up, width=80).pack(side=tk.LEFT, padx=2)
        ctk.CTkButton(toolbar, text="⬇ Вниз", command=self.move_rule_down, width=80).pack(side=tk.LEFT, padx=2)

        # Поиск
        search_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        search_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))

        self.search_var = tk.StringVar()
        self.search_var.trace('w', lambda *args: self.refresh_rules_list())

        ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="🔍 Поиск...", width=200).pack(
            side=tk.RIGHT)

        # Таблица правил
        list_frame = ctk.CTkFrame(parent, fg_color="transparent")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        columns = ("Статус", "Действие", "Направление", "Протокол", "Локальный порт", "Удаленный порт")

        # Стиль таблицы
        style = ttk.Style()
        if ctk.get_appearance_mode() == "Dark":
            style.theme_use("clam")
            style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
            style.configure("Treeview.Heading", background="#3b3b3b", foreground="white")
        else:
            style.theme_use("clam")
            style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
            style.configure("Treeview.Heading", background="#f0f0f0", foreground="black")

        # Скроллы
        vsb = ttk.Scrollbar(list_frame, orient="vertical")
        hsb = ttk.Scrollbar(list_frame, orient="horizontal")
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Таблица
        self.rules_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            height=18, selectmode="browse"
        )

        vsb.config(command=self.rules_tree.yview)
        hsb.config(command=self.rules_tree.xview)

        col_widths = [70, 90, 100, 80, 100, 100]
        for col, width in zip(columns, col_widths):
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=width, anchor="w")

        self.rules_tree.column("Статус", anchor="center", width=70)
        self.rules_tree.pack(fill=tk.BOTH, expand=True)

        # Привязываем события
        self.rules_tree.bind("<Double-Button-1>", lambda e: self.edit_rule())
        self.rules_tree.bind("<Button-3>", self.on_right_click)

        # Контекстное меню
        self.context_menu = tk.Menu(self.rules_tree, tearoff=0)
        self.context_menu.add_command(label="✅ Включить", command=lambda: self.toggle_rule(True))
        self.context_menu.add_command(label="❌ Отключить", command=lambda: self.toggle_rule(False))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="✏️ Изменить", command=self.edit_rule)
        self.context_menu.add_command(label="🗑️ Удалить", command=self.delete_rule)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⬆ Вверх", command=self.move_rule_up)
        self.context_menu.add_command(label="⬇ Вниз", command=self.move_rule_down)

        # Статус
        self.rules_status = ctk.CTkLabel(parent, text="", font=("Segoe UI", 11))
        self.rules_status.pack(anchor=tk.W, padx=10, pady=(0, 5))

    def on_right_click(self, event):
        try:
            selection = self.rules_tree.selection()
            if selection:
                self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def refresh_rules_list(self):
        """Обновляет список правил с учётом фильтров."""
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)

        direction_filter = self.direction_var.get()
        action_filter = self.action_var.get()
        protocol_filter = self.protocol_var.get()
        search_text = self.search_var.get().lower()

        filtered_rules = []
        for rule in self.manager.rules:
            if direction_filter != "all" and rule.direction != direction_filter:
                continue
            if action_filter != "all" and rule.action != action_filter:
                continue
            if protocol_filter != "all" and rule.protocol != protocol_filter:
                continue
            if search_text and search_text not in rule.name.lower() and search_text not in rule.description.lower():
                continue
            filtered_rules.append(rule)

        for rule in filtered_rules:
            status_icon = "✅" if rule.enabled else "⬜"
            action_display = "Разрешить" if rule.action == "allow" else "Блокировать"
            direction_display = "Входящее" if rule.direction == "in" else "Исходящее"
            protocol_display = {"any": "Любой", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}.get(rule.protocol,
                                                                                                rule.protocol)

            self.rules_tree.insert("", tk.END, values=(
                status_icon, action_display, direction_display, protocol_display,
                rule.local_ports if rule.local_ports else "Любой",
                rule.remote_ports if rule.remote_ports else "Любой"
            ), tags=('block' if rule.action == "block" else 'allow',), iid=rule.id)

        # Цвета строк
        if ctk.get_appearance_mode() == "Light":
            self.rules_tree.tag_configure('block', background='#ffebee')
            self.rules_tree.tag_configure('allow', background='#e8f5e9')
        else:
            self.rules_tree.tag_configure('block', background='#4a2511')
            self.rules_tree.tag_configure('allow', background='#1b3b1b')

        total_all = len(self.manager.rules)
        filtered = len(filtered_rules)
        self.rules_status.configure(text=f"✅ Найдено {filtered} правил (всего {total_all})",
                                    text_color="blue" if filtered != total_all else "green")

    def get_selected_rule_id(self) -> Optional[str]:
        selection = self.rules_tree.selection()
        return selection[0] if selection else None

    def toggle_rule(self, enable=None):
        rule_id = self.get_selected_rule_id()
        if not rule_id:
            messagebox.showwarning("Предупреждение", "Выберите правило!")
            return

        rule = self.manager.get_rule(rule_id)
        if rule:
            if enable is not None:
                rule.enabled = enable
            else:
                rule.enabled = not rule.enabled
            rule.modified = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.refresh_rules_list()

    def create_rule(self):
        dialog = FirewallRuleDialog(self.dialog, self.node)
        self.dialog.wait_window(dialog.dialog)
        if dialog.result:
            self.manager.add_rule(dialog.result)
            self.refresh_rules_list()

    def edit_rule(self):
        rule_id = self.get_selected_rule_id()
        if not rule_id:
            messagebox.showwarning("Предупреждение", "Выберите правило для редактирования!")
            return

        rule = self.manager.get_rule(rule_id)
        if rule:
            dialog = FirewallRuleDialog(self.dialog, self.node, rule)
            self.dialog.wait_window(dialog.dialog)
            if dialog.result:
                for key, value in dialog.result.__dict__.items():
                    if key not in ('id', 'created', 'modified'):
                        setattr(rule, key, value)
                rule.modified = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.refresh_rules_list()

    def delete_rule(self):
        rule_id = self.get_selected_rule_id()
        if not rule_id:
            messagebox.showwarning("Предупреждение", "Выберите правило для удаления!")
            return

        rule = self.manager.get_rule(rule_id)
        if rule and messagebox.askyesno("Удаление", f"Удалить правило '{rule.name}'?"):
            self.manager.remove_rule(rule_id)
            self.refresh_rules_list()

    def move_rule_up(self):
        rule_id = self.get_selected_rule_id()
        if rule_id and self.manager.move_rule_up(rule_id):
            self.refresh_rules_list()
            self.rules_tree.selection_set(rule_id)
            self.rules_tree.see(rule_id)

    def move_rule_down(self):
        rule_id = self.get_selected_rule_id()
        if rule_id and self.manager.move_rule_down(rule_id):
            self.refresh_rules_list()
            self.rules_tree.selection_set(rule_id)
            self.rules_tree.see(rule_id)

    def toggle_firewall(self):
        self.manager.firewall_enabled = not self.manager.firewall_enabled
        self.status_var.set("Включен" if self.manager.firewall_enabled else "Отключен")
        new_color = "#4CAF50" if self.manager.firewall_enabled else "#F44336"
        self.status_label.configure(text_color="green" if self.manager.firewall_enabled else "red")
        if hasattr(self, "status_pill"):
            try:
                self.status_pill.configure(border_color=new_color)
            except Exception:
                pass
        self.toggle_firewall_btn.configure(
            text="🔴 Выключить" if self.manager.firewall_enabled else "🟢 Включить",
            fg_color="#F44336" if self.manager.firewall_enabled else "#4CAF50"
        )

    def toggle_notifications(self):
        self.manager.notification_enabled = self.notify_var.get()

    def save_settings(self):
        self.saved = True
        messagebox.showinfo("Сохранение", "Настройки файервола сохранены!")
        self.dialog.destroy()


class FirewallRuleDialog:
    """Диалог создания/редактирования правила файервола."""

    def __init__(self, parent, node: Node, rule: Optional[FirewallRule] = None):
        self.parent = parent
        self.node = node
        self.rule = rule
        self.result = None

        title_text = "Создание правила" if not rule else f"Редактирование: {rule.name}"

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(title_text)
        self.dialog.geometry("750x800")
        self.dialog.resizable(True, True)
        self.dialog.transient(parent)
        # grab_set убран

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
        center_window(self.dialog, width, height)

    def create_widgets(self):
        # Промт 9 №6: современный стиль — палитра из utils.theme,
        # акцентные полоски, акцентные заголовки секций.
        from utils import theme

        surface_bg = theme.color("surface")
        card_bg = theme.color("card_bg")
        border_clr = theme.color("card_border")
        primary = theme.color("primary")
        primary_hover = theme.color("primary_hover")
        danger = theme.color("danger")
        danger_hover = theme.color("danger_hover")
        text_primary = theme.color("text_primary")
        text_muted = theme.color("text_muted")

        self.dialog.configure(fg_color=surface_bg)

        main_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Заголовок
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 15))

        ctk.CTkLabel(title_frame, text="📋" if not self.rule else "✏",
                      font=("Segoe UI", 28), text_color=primary).pack(side=tk.LEFT, padx=(0, 10))
        ctk.CTkLabel(title_frame,
                      text="Создание правила" if not self.rule else f"Редактирование: {self.rule.name}",
                      font=("Segoe UI", 18, "bold"), text_color=text_primary).pack(side=tk.LEFT)

        def section(header_text: str, subtitle: str = "") -> ctk.CTkFrame:
            """Создаёт секцию-card с акцентной полоской и заголовком."""
            frame = ctk.CTkFrame(main_frame, fg_color=card_bg,
                                  border_width=1, border_color=border_clr, corner_radius=10)
            frame.pack(fill=tk.X, pady=(0, 10))
            # Синяя полоска убрана по запросу пользователя
            header = ctk.CTkFrame(frame, fg_color="transparent")
            header.pack(fill=tk.X, padx=16, pady=(10, 4))
            ctk.CTkLabel(header, text=header_text, font=("Segoe UI", 14, "bold"),
                          text_color=text_primary, anchor="w").pack(side=tk.LEFT)
            if subtitle:
                ctk.CTkLabel(header, text=subtitle, font=("Segoe UI", 10),
                              text_color=text_muted, anchor="w").pack(side=tk.LEFT, padx=(12, 0))
            return frame

        # Выбор интерфейса
        interface_frame = section("🔌 Применить к интерфейсу",
                                   "любой или конкретный порт узла")

        network_ports = [p for p in self.node.ports if p["port_type"] in ["ethernet", "pon", "wifi"]]
        self.interface_var = tk.StringVar(value="any")

        ctk.CTkRadioButton(interface_frame, text="Любой интерфейс", variable=self.interface_var, value="any").pack(
            anchor=tk.W, padx=20, pady=2)

        for port in network_ports:
            icon = "" if port["port_type"] == "ethernet" else ("" if port["port_type"] == "pon" else "")
            ip_info = f" ({port['ip_address']})" if port.get("ip_address") else ""
            ctk.CTkRadioButton(interface_frame, text=f"{icon} {port['name']}{ip_info}", variable=self.interface_var,
                               value=port["port_id"]).pack(anchor=tk.W, padx=40, pady=2)

        # Действие и направление
        action_frame = section("⚡ Действие и направление",
                                "что делаем с трафиком и в каком направлении")

        action_row = ctk.CTkFrame(action_frame, fg_color="transparent")
        action_row.pack(fill=tk.X, padx=16, pady=5)

        ctk.CTkLabel(action_row, text="Действие:", width=100, anchor=tk.W,
                      text_color=text_primary).pack(side=tk.LEFT)
        self.action_var = tk.StringVar(value=self.rule.action if self.rule else "allow")
        ctk.CTkRadioButton(action_row, text="Разрешить", variable=self.action_var, value="allow").pack(side=tk.LEFT,
                                                                                                         padx=(10, 20))
        ctk.CTkRadioButton(action_row, text="Блокировать", variable=self.action_var, value="block").pack(side=tk.LEFT)

        dir_row = ctk.CTkFrame(action_frame, fg_color="transparent")
        dir_row.pack(fill=tk.X, padx=16, pady=(5, 10))

        ctk.CTkLabel(dir_row, text="Направление:", width=100, anchor=tk.W,
                      text_color=text_primary).pack(side=tk.LEFT)
        self.direction_var = tk.StringVar(value=self.rule.direction if self.rule else "in")
        ctk.CTkRadioButton(dir_row, text="Входящее", variable=self.direction_var, value="in").pack(side=tk.LEFT,
                                                                                                     padx=(10, 20))
        ctk.CTkRadioButton(dir_row, text="Исходящее", variable=self.direction_var, value="out").pack(side=tk.LEFT)

        # Протокол и порты
        ports_frame = section("🔀 Протокол и порты",
                               "фильтр по L4-протоколу и портам")

        proto_row = ctk.CTkFrame(ports_frame, fg_color="transparent")
        proto_row.pack(fill=tk.X, padx=16, pady=5)

        ctk.CTkLabel(proto_row, text="Протокол:", width=100, anchor=tk.W,
                      text_color=text_primary).pack(side=tk.LEFT)
        self.protocol_var = tk.StringVar(value=self.rule.protocol if self.rule else "any")

        protocols = [("Любой", "any"), ("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp")]
        for text, value in protocols:
            ctk.CTkRadioButton(proto_row, text=text, variable=self.protocol_var, value=value).pack(side=tk.LEFT, padx=5)

        # Локальный порт
        local_row = ctk.CTkFrame(ports_frame, fg_color="transparent")
        local_row.pack(fill=tk.X, padx=16, pady=5)

        ctk.CTkLabel(local_row, text="Локальный порт:", width=110, anchor=tk.W,
                      text_color=text_primary).pack(side=tk.LEFT)
        self.local_port_var = tk.StringVar(value=self.rule.local_ports if self.rule else "")
        ctk.CTkEntry(local_row, textvariable=self.local_port_var, width=150, placeholder_text="80,443").pack(
            side=tk.LEFT, padx=(10, 5))
        ctk.CTkLabel(local_row, text="(номер или список)", font=("Segoe UI", 10),
                      text_color=text_muted).pack(side=tk.LEFT)

        # Удаленный порт
        remote_row = ctk.CTkFrame(ports_frame, fg_color="transparent")
        remote_row.pack(fill=tk.X, padx=16, pady=5)

        ctk.CTkLabel(remote_row, text="Удаленный порт:", width=110, anchor=tk.W,
                      text_color=text_primary).pack(side=tk.LEFT)
        self.remote_port_var = tk.StringVar(value=self.rule.remote_ports if self.rule else "")
        ctk.CTkEntry(remote_row, textvariable=self.remote_port_var, width=150, placeholder_text="80,443").pack(
            side=tk.LEFT, padx=(10, 5))
        ctk.CTkLabel(remote_row, text="(оставьте пустым для любого)", font=("Segoe UI", 10),
                      text_color=text_muted).pack(side=tk.LEFT)

        # Удаленная сеть
        remote_net_frame = ctk.CTkFrame(ports_frame, fg_color="transparent")
        remote_net_frame.pack(fill=tk.X, padx=16, pady=(5, 12))

        ctk.CTkLabel(remote_net_frame, text="Удаленная сеть:", width=110, anchor=tk.W,
                      text_color=text_primary).pack(side=tk.LEFT)
        initial_value = self.rule.remote_addresses if self.rule and self.rule.remote_addresses != "any" else ""
        self.remote_network_var = tk.StringVar(value=initial_value)
        ctk.CTkEntry(remote_net_frame, textvariable=self.remote_network_var, width=200,
                     placeholder_text="192.168.1.0/24").pack(side=tk.LEFT, padx=(10, 5))
        ctk.CTkLabel(remote_net_frame, text="(формат: IP/маска)", font=("Segoe UI", 10),
                      text_color=text_muted).pack(side=tk.LEFT)

        # Тестовые данные
        test_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        test_frame.pack(fill=tk.X, pady=10)

        ctk.CTkButton(
            test_frame, text="🧪 Заполнить тестовыми данными",
            command=self.fill_test_data, height=34, corner_radius=8,
            fg_color=theme.color("accent"), hover_color=theme.color("accent_hover"),
            font=("Segoe UI", 12)
        ).pack(side=tk.RIGHT)

        # Кнопки
        btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        ctk.CTkButton(
            btn_frame, text="✕ Отмена", command=self.dialog.destroy,
            width=120, height=38, corner_radius=8,
            fg_color=danger, hover_color=danger_hover, font=("Segoe UI", 13)
        ).pack(side=tk.LEFT, padx=5)
        ctk.CTkButton(
            btn_frame, text="💾 Сохранить правило", command=self.save_rule,
            width=180, height=38, corner_radius=8,
            fg_color=primary, hover_color=primary_hover,
            font=("Segoe UI", 13, "bold")
        ).pack(side=tk.RIGHT, padx=5)

    def fill_test_data(self):
        """Заполняет поля тестовыми данными."""
        self.remote_network_var.set(f"192.168.{random.randint(1, 254)}.0/{random.choice(['24', '16', '8'])}")
        self.local_port_var.set(str(random.randint(1024, 65535)))
        self.remote_port_var.set(random.choice(["80", "443", "22", "3389"]))

    def save_rule(self):
        """Сохраняет правило."""
        local_address = "any"
        selected_interface = self.interface_var.get()
        if selected_interface != "any":
            for port in self.node.ports:
                if port["port_id"] == selected_interface:
                    local_address = port.get("ip_address", "any")
                    break

        remote_network = self.remote_network_var.get().strip()

        if self.rule:
            rule = self.rule
            rule.action = self.action_var.get()
            rule.direction = self.direction_var.get()
            rule.protocol = self.protocol_var.get()
            rule.local_ports = self.local_port_var.get().strip()
            rule.remote_ports = self.remote_port_var.get().strip()
            rule.local_addresses = local_address
            rule.remote_addresses = remote_network if remote_network else "any"
        else:
            rule = FirewallRule(
                direction=self.direction_var.get(),
                action=self.action_var.get(),
                protocol=self.protocol_var.get(),
                local_ports=self.local_port_var.get().strip(),
                remote_ports=self.remote_port_var.get().strip(),
                local_addresses=local_address,
                remote_addresses=remote_network if remote_network else "any",
                enabled=True
            )

        self.result = rule
        self.dialog.destroy()