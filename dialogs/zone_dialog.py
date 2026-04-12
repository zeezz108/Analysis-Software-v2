"""
Модуль диалога создания зоны TIM

Содержит класс ZoneCreationDialog для создания новой зоны на схеме.
Визуальный стиль — тёмная палитра с карточками-плитками для выбора типа
зоны (по референсу промт-стиль2).
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from PIL import Image
import os

from utils.generators import uid
from utils.theme import color, c, style_dialog, load_icon
from models.zone import Zone

# Описания типов зон для карточек
_ZONE_TYPES = [
    {
        "value": "ТИМ1 - ЛВС",
        "title": "ТИМ1 - ЛВС",
        "subtitle": "(локальная\nвычислительная сеть)",
        "icon_placeholder": "🖧",
    },
    {
        "value": "ТИМ2 - ЦОД",
        "title": "ТИМ2 - ЦОД",
        "subtitle": "(центр обработки\nданных)",
        "icon_placeholder": "🏢",
    },
    {
        "value": "ТИМ3 - Удаленный пользователь",
        "title": "ТИМ3 - Удалённый",
        "subtitle": "пользователь",
        "icon_placeholder": "🌐",
    },
]


class ZoneCreationDialog:
    """Диалог создания новой зоны TIM с карточками-плитками."""

    def __init__(self, parent, x: float, y: float, width: float, height: float, board):
        self.parent = parent
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.board = board
        self.result = None

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Создание новой зоны TIM")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.zone_type_var = tk.StringVar(value="ТИМ1 - ЛВС")
        self._card_frames = []  # для обновления стилей при выборе

        self.create_widgets()
        style_dialog(self.dialog, width=560, height=520)

    def create_widgets(self):
        """Создаёт виджеты в стиле референса промт-стиль2."""
        dialog_bg = color("dialog_bg")
        card_bg = color("card_bg")
        card_border = color("card_border")
        card_sel_brd = color("card_sel_brd")
        card_selected = color("card_selected")
        text_primary = color("text_primary")
        text_secondary = color("text_secondary")
        text_muted = color("text_muted")
        input_bg = color("input_bg")
        input_border = color("input_border")
        primary = color("primary")
        primary_hover = color("primary_hover")
        danger = color("danger")
        danger_hover = color("danger_hover")
        success = color("success")
        success_hover = color("success_hover")

        self.dialog.configure(fg_color=dialog_bg)

        main = ctk.CTkFrame(self.dialog, fg_color="transparent")
        main.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)

        # ===== Секция «Основные Сведения» =====
        section = ctk.CTkFrame(main, fg_color=card_bg, border_width=1,
                                border_color=card_border, corner_radius=12)
        section.pack(fill=tk.X, pady=(0, 16))

        section_inner = ctk.CTkFrame(section, fg_color="transparent")
        section_inner.pack(fill=tk.X, padx=20, pady=16)

        ctk.CTkLabel(section_inner, text="Основные сведения",
                      font=("Arial", 15, "bold"), text_color=text_primary,
                      anchor="w").pack(fill=tk.X, pady=(0, 12))

        # --- Тип зоны TIM: три карточки ---
        ctk.CTkLabel(section_inner, text="Тип зоны TIM:",
                      font=("Arial", 12), text_color=text_secondary,
                      anchor="w").pack(fill=tk.X, pady=(0, 8))

        cards_row = ctk.CTkFrame(section_inner, fg_color="transparent")
        cards_row.pack(fill=tk.X, pady=(0, 16))
        # Равные колонки
        for i in range(3):
            cards_row.grid_columnconfigure(i, weight=1, uniform="zone_card")

        self._card_frames = []
        for idx, zt in enumerate(_ZONE_TYPES):
            card = self._make_type_card(cards_row, zt, idx)
            card.grid(row=0, column=idx, padx=6, sticky="nsew")
            self._card_frames.append((card, zt["value"]))

        self._update_card_selection()

        # --- Название зоны ---
        ctk.CTkLabel(section_inner, text="Название зоны:",
                      font=("Arial", 12), text_color=text_secondary,
                      anchor="w").pack(fill=tk.X, pady=(0, 4))

        self.name_var = tk.StringVar(value="")
        ctk.CTkEntry(
            section_inner, textvariable=self.name_var,
            placeholder_text="Введите название зоны (необязательно)",
            height=38, corner_radius=8,
            fg_color=input_bg, border_color=input_border, border_width=1
        ).pack(fill=tk.X, pady=(0, 12))

        # --- Описание зоны ---
        ctk.CTkLabel(section_inner, text="Описание зоны:",
                      font=("Arial", 12), text_color=text_secondary,
                      anchor="w").pack(fill=tk.X, pady=(0, 4))

        self.desc_var = tk.StringVar()
        ctk.CTkEntry(
            section_inner, textvariable=self.desc_var,
            placeholder_text="Введите описание зоны (необязательно)",
            height=38, corner_radius=8,
            fg_color=input_bg, border_color=input_border, border_width=1
        ).pack(fill=tk.X)

        # ===== Кнопки =====
        btn_frame = ctk.CTkFrame(main, fg_color="transparent")
        btn_frame.pack(fill=tk.X, pady=(8, 0))

        ctk.CTkButton(
            btn_frame, text="✓  Создать", command=self.create_zone,
            fg_color=success, hover_color=success_hover,
            text_color="#FFFFFF",
            width=130, height=40, corner_radius=10,
            font=("Arial", 13, "bold")
        ).pack(side=tk.RIGHT, padx=(8, 0))

        ctk.CTkButton(
            btn_frame, text="✕  Отмена", command=self.cancel_creation,
            fg_color=danger, hover_color=danger_hover,
            text_color="#FFFFFF",
            width=110, height=40, corner_radius=10,
            font=("Arial", 13)
        ).pack(side=tk.RIGHT)

        self.dialog.bind("<Return>", lambda e: self.create_zone())
        self.dialog.bind("<Escape>", lambda e: self.cancel_creation())

    # ------------------------------------------------------------------
    # Карточки выбора типа зоны
    # ------------------------------------------------------------------

    def _make_type_card(self, parent, zone_type: dict, idx: int) -> ctk.CTkFrame:
        """Создаёт одну карточку-плитку для типа зоны."""
        card = ctk.CTkFrame(
            parent, fg_color=color("card_bg"),
            border_width=2, border_color=color("card_border"),
            corner_radius=10, cursor="hand2"
        )
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(expand=True, padx=10, pady=12)

        # Заглушка для иконки (будет заменена на реальное изображение)
        icon = load_icon(f"card_tim_{['lvs','cod','remote'][idx]}.png", size=(48, 48))
        if icon:
            ctk.CTkLabel(inner, image=icon, text="").pack(pady=(0, 8))
        else:
            ctk.CTkLabel(inner, text=zone_type["icon_placeholder"],
                          font=("Arial", 32)).pack(pady=(0, 8))

        ctk.CTkLabel(inner, text=zone_type["title"],
                      font=("Arial", 12, "bold"),
                      text_color=color("text_primary")).pack()
        ctk.CTkLabel(inner, text=zone_type["subtitle"],
                      font=("Arial", 10),
                      text_color=color("text_muted"),
                      justify="center").pack(pady=(2, 0))

        # Клик по карточке
        value = zone_type["value"]
        for widget in [card, inner] + inner.winfo_children():
            widget.bind("<Button-1>", lambda e, v=value: self._select_zone_type(v))

        return card

    def _select_zone_type(self, value: str):
        self.zone_type_var.set(value)
        self._update_card_selection()

    def _update_card_selection(self):
        """Обновляет стили карточек: выбранная — с синей обводкой."""
        selected = self.zone_type_var.get()
        for card, val in self._card_frames:
            if val == selected:
                card.configure(
                    border_color=color("card_sel_brd"),
                    fg_color=color("card_selected")
                )
            else:
                card.configure(
                    border_color=color("card_border"),
                    fg_color=color("card_bg")
                )

    # ------------------------------------------------------------------
    # Логика создания / отмены
    # ------------------------------------------------------------------

    def cancel_creation(self):
        self.result = None
        self.dialog.destroy()
        if hasattr(self.parent, 'mode'):
            self.parent.mode = "idle"
            self.parent.canvas.config(cursor="")

    def create_zone(self):
        zone_name = self.name_var.get().strip()
        zone_subtype = self.zone_type_var.get()
        description = self.desc_var.get().strip()

        zone_number = self.board.get_next_zone_number(zone_subtype)

        if self.width < 100 or self.height < 100:
            result = messagebox.askyesno(
                "Подтверждение",
                f"Создаваемая зона очень маленькая ({int(self.width)}x{int(self.height)}).\n"
                f"Рекомендуемый минимальный размер: 100x100 пикселей.\n\n"
                f"Создать зону такого размера?"
            )
            if not result:
                return

        if zone_name and self.board.is_zone_name_exists(zone_name):
            messagebox.showerror(
                "Ошибка",
                f"Зона с именем '{zone_name}' уже существует!\n"
                f"Пожалуйста, выберите другое имя."
            )
            return

        zone = Zone(
            id=uid(), name=zone_name, description=description,
            x=self.x, y=self.y, width=self.width, height=self.height,
            zone_type="tim", zone_subtype=zone_subtype, zone_number=zone_number
        )

        self.result = zone
        self.dialog.destroy()

        if hasattr(self.parent, 'mode'):
            self.parent.mode = "idle"
            self.parent.canvas.config(cursor="")

    def show(self) -> Zone:
        self.parent.wait_window(self.dialog)
        return self.result


def create_zone_dialog(parent, x, y, width, height, board) -> Zone:
    dialog = ZoneCreationDialog(parent, x, y, width, height, board)
    return dialog.show()
