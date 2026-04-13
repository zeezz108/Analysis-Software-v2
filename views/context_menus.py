"""
Модуль контекстных меню для зон и узлов

Содержит классы:
- ZoneContextMenuHandler: Контекстное меню для зоны TIM
- NodeContextMenuHandler: Контекстное меню для узла
"""

import tkinter as tk
from tkinter import Menu
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from views.canvas_view import CanvasView
    from models.zone import Zone
    from models.node import Node


class ZoneContextMenuHandler:
    """Обработчик контекстного меню для зоны TIM."""

    @staticmethod
    def show_menu(event, canvas_view: 'CanvasView', zone: 'Zone'):
        """
        Показывает контекстное меню для зоны.

        Args:
            event: Событие клика
            canvas_view: Экземпляр CanvasView
            zone: Зона, для которой показывается меню
        """
        menu = Menu(canvas_view.root, tearoff=0)

        # Основные действия
        menu.add_command(
            label="✏️ Изменить описание",
            command=lambda: canvas_view.edit_zone_description(zone)
        )
        menu.add_command(
            label="📏 Изменить размер",
            command=lambda: canvas_view.start_zone_resize(zone)
        )
        menu.add_command(
            label="🗑 Удалить зону",
            command=lambda: canvas_view.delete_zone(zone)
        )

        # Информация об узлах в зоне
        nodes_in_zone = [n for n in canvas_view.board.nodes if n.zone.id == zone.id]
        menu.add_separator()
        menu.add_command(
            label=f"Узлов в зоне: {len(nodes_in_zone)}",
            state="disabled"
        )

        # Показываем первые 5 узлов (если есть)
        if nodes_in_zone:
            menu.add_separator()
            menu.add_command(label="📌 Узлы в зоне:", state="disabled")
            for node in nodes_in_zone[:5]:
                menu.add_command(
                    label=f"  • {node.name} ({canvas_view.get_node_type_russian(node.type)})",
                    state="disabled"
                )
            if len(nodes_in_zone) > 5:
                menu.add_command(
                    label=f"  ... и ещё {len(nodes_in_zone) - 5}",
                    state="disabled"
                )

        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()


class NodeContextMenuHandler:
    """Обработчик контекстного меню для узла."""

    @staticmethod
    def show_menu(event, canvas_view: 'CanvasView', node: 'Node'):
        """
        Показывает контекстное меню для узла.

        Args:
            event: Событие клика
            canvas_view: Экземпляр CanvasView
            node: Узел, для которого показывается меню
        """
        menu = Menu(canvas_view.root, tearoff=0)

        # ===== ОСНОВНЫЕ ДЕЙСТВИЯ =====
        # Свойства (только просмотр)
        menu.add_command(
            label="📋 Свойства",
            command=lambda: canvas_view.view_node_properties(node)
        )

        # Паспорт безопасности (для всех, кроме Интернета)
        if node.type != "Internet":
            menu.add_command(
                label="🛡 Паспорт безопасности",
                command=lambda: canvas_view.show_node_security_passport(node)
            )

        # Управление ВМ (только для сервера виртуализации)
        if node.type == "VirtualizationServer":
            menu.add_command(
                label="🖥️ Управление виртуальными машинами",
                command=lambda: canvas_view.open_vm_management(node)
            )

        # ===== НАСТРОЙКИ =====
        # VPN (для всех, кроме Интернета и коммутаторов)
        if node.type not in ["Internet", "Switch"]:
            menu.add_command(
                label="🔒 Настроить VPN",
                command=lambda: canvas_view.configure_vpn(node)
            )
        else:
            menu.add_command(
                label="🔒 VPN недоступен",
                state="disabled"
            )

        # Файервол (для всех)
        menu.add_command(
            label="🛡 Настроить файервол",
            command=lambda: canvas_view.open_firewall(node)
        )

        # Таблица маршрутизации (для всех)
        menu.add_command(
            label="📋 Таблица маршрутизации",
            command=lambda: canvas_view.open_routing_table(node)
        )

        menu.add_command(
            label="📄 Дублировать узел",
            command=lambda: canvas_view.duplicate_node(node)
        )

        menu.add_separator()

        # ===== УДАЛЕНИЕ =====
        menu.add_command(
            label="🗑 Удалить узел",
            command=lambda: canvas_view.delete_node(node)
        )

        menu.add_separator()

        # ===== ВИРТУАЛЬНЫЕ МАШИНЫ (для сервера виртуализации) =====
        if node.type == "VirtualizationServer" and node.virtual_machines:
            menu.add_separator()
            menu.add_command(label=f"🖥️ ВМ: {len(node.virtual_machines)}", state="disabled")
            for vm_data in node.virtual_machines[:3]:
                vm_name = vm_data.get("name", "Без имени")
                menu.add_command(label=f"   • {vm_name}", state="disabled")
            if len(node.virtual_machines) > 3:
                menu.add_command(label=f"   ... и ещё {len(node.virtual_machines) - 3}", state="disabled")

        # ===== БЫСТРЫЕ ДЕЙСТВИЯ (для некоторых типов) =====
        if node.type in ["Router", "Switch"]:
            menu.add_separator()
            menu.add_command(
                label="🔄 Перезагрузить",
                command=lambda: NodeContextMenuHandler._quick_reload(canvas_view, node)
            )

        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()

    @staticmethod
    def _quick_reload(canvas_view: 'CanvasView', node: 'Node'):
        """
        Быстрое действие - перезагрузка узла (имитация).

        Args:
            canvas_view: Экземпляр CanvasView
            node: Узел для "перезагрузки"
        """
        from tkinter import messagebox
        messagebox.showinfo("Перезагрузка", f"Отправлен сигнал перезагрузки на {node.name}")


# Дополнительная функция для создания меню с иконками (если нужна)
def create_menu_with_icons(parent, items: list) -> Menu:
    """
    Создаёт меню с "иконками" (текстовыми эмодзи).

    Args:
        parent: Родительский виджет
        items: Список кортежей (текст, команда, иконка)

    Returns:
        Созданное меню

    Example:
        menu = create_menu_with_icons(root, [
            ("Свойства", show_properties, "⚙️"),
            ("Удалить", delete_node, "🗑️"),
            ("---", None, None),
            ("Отмена", None, "✕")
        ])
    """
    menu = Menu(parent, tearoff=0)

    for text, command, icon in items:
        if text == "---":
            menu.add_separator()
        else:
            display_text = f"{icon} {text}" if icon else text
            if command:
                menu.add_command(label=display_text, command=command)
            else:
                menu.add_command(label=display_text, state="disabled")

    return menu


# Предопределённые шаблоны меню (для быстрого использования)
ZONE_MENU_TEMPLATE = [
    ("Изменить описание", "edit", "✏️"),
    ("Изменить размер", "resize", "📏"),
    ("---", None, None),
    ("Узлов в зоне", "info", "📊")
]

NODE_MENU_TEMPLATE = [
    ("Свойства", "properties", "⚙️"),
    ("Паспорт безопасности", "security", "🛡️"),
    ("---", None, None),
    ("Настроить VPN", "vpn", "🔒"),
    ("Настроить файервол", "firewall", "🛡️"),
    ("Таблица маршрутизации", "routing", "📋"),
    ("---", None, None),
    ("Изменить размер", "resize", "📏"),
    ("Удалить узел", "delete", "🗑️")
]