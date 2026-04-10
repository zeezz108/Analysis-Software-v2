"""
Модуль диалога создания зоны TIM

Содержит класс ZoneCreationDialog для создания новой зоны на схеме.
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

from utils.generators import uid
from models.zone import Zone


class ZoneCreationDialog:
    """
    Диалог создания новой зоны TIM.

    Позволяет пользователю:
    - Выбрать тип зоны (ТИМ1-ЛВС, ТИМ2-ЦОД, ТИМ3-Удаленный пользователь)
    - Ввести название зоны (опционально)
    - Ввести описание зоны (опционально)

    После подтверждения создаёт объект Zone и возвращает его через result.
    """

    def __init__(self, parent, x: float, y: float, width: float, height: float, board):
        """
        Инициализация диалога создания зоны.

        Args:
            parent: Родительское окно
            x: Координата X левого верхнего угла зоны
            y: Координата Y левого верхнего угла зоны
            width: Ширина зоны
            height: Высота зоны
            board: Экземпляр Board для проверки уникальности имени
        """
        self.parent = parent
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.board = board
        self.result = None  # Здесь будет созданная зона

        # Создаём окно диалога
        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title("Создание новой зоны TIM")
        self.dialog.geometry("500x450")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        self.create_widgets()
        self.center_window()

    def center_window(self):
        """Центрирует окно на экране."""
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
        """Создаёт все виджеты диалога."""
        # Устанавливаем цвет фона окна
        temp_frame = ctk.CTkFrame(self.dialog)
        frame_color = temp_frame.cget("fg_color")
        temp_frame.destroy()
        self.dialog.configure(fg_color=frame_color)

        # Заголовок
        title_label = ctk.CTkLabel(
            self.dialog,
            text="Создание новой зоны TIM",
            font=("Arial", 18, "bold")
        )
        title_label.pack(pady=(15, 10))

        # ===== Фрейм для выбора типа зоны =====
        type_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        type_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

        ctk.CTkLabel(
            type_frame,
            text="Тип зоны TIM:",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.zone_type_var = tk.StringVar(value="ТИМ1 - ЛВС")

        # ТИМ1 - ЛВС
        ctk.CTkRadioButton(
            type_frame,
            text="ТИМ1 - ЛВС (локальная вычислительная сеть)",
            variable=self.zone_type_var,
            value="ТИМ1 - ЛВС",
            font=("Arial", 14)
        ).pack(anchor=tk.W, padx=20, pady=2)

        # ТИМ2 - ЦОД
        ctk.CTkRadioButton(
            type_frame,
            text="ТИМ2 - ЦОД (центр обработки данных)",
            variable=self.zone_type_var,
            value="ТИМ2 - ЦОД",
            font=("Arial", 14)
        ).pack(anchor=tk.W, padx=20, pady=2)

        # ТИМ3 - Удаленный пользователь
        ctk.CTkRadioButton(
            type_frame,
            text="ТИМ3 - Удаленный пользователь",
            variable=self.zone_type_var,
            value="ТИМ3 - Удаленный пользователь",
            font=("Arial", 14)
        ).pack(anchor=tk.W, padx=20, pady=2)

        # ===== Фрейм для названия =====
        name_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        name_frame.pack(fill=tk.X, padx=20, pady=(0, 10))

        ctk.CTkLabel(
            name_frame,
            text="Название зоны:",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.name_var = tk.StringVar(value="")
        self.name_entry = ctk.CTkEntry(
            name_frame,
            textvariable=self.name_var,
            placeholder_text="Введите название зоны (необязательно)",
            height=35
        )
        self.name_entry.pack(fill=tk.X, padx=10, pady=(0, 10))

        # ===== Фрейм для описания =====
        desc_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        desc_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        ctk.CTkLabel(
            desc_frame,
            text="Описание зоны:",
            font=("Arial", 14, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        self.desc_var = tk.StringVar()
        self.desc_entry = ctk.CTkEntry(
            desc_frame,
            textvariable=self.desc_var,
            placeholder_text="Введите описание зоны (необязательно)",
            height=35
        )
        self.desc_entry.pack(fill=tk.X, padx=10, pady=(0, 10))

        # ===== Фрейм для кнопок =====
        button_frame = ctk.CTkFrame(self.dialog, fg_color="transparent")
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 15))

        self.create_button = ctk.CTkButton(
            button_frame,
            text="✓ Создать",
            command=self.create_zone,
            fg_color="#4CAF50",
            hover_color="#45a049",
            width=100,
            height=35,
            font=("Arial", 12, "bold")
        )
        self.create_button.pack(side=tk.RIGHT, padx=5)

        ctk.CTkButton(
            button_frame,
            text="✕ Отмена",
            command=self.cancel_creation,
            fg_color="#CD3333",
            hover_color="#b71c1c",
            width=100,
            height=35,
            font=("Arial", 12)
        ).pack(side=tk.RIGHT, padx=5)

        # Привязываем Enter к созданию зоны
        self.dialog.bind("<Return>", lambda e: self.create_zone())
        self.dialog.bind("<Escape>", lambda e: self.cancel_creation())

    def cancel_creation(self):
        """Отменяет создание зоны и закрывает диалог."""
        self.result = None
        self.dialog.destroy()

        # Возвращаем режим idle, если есть родительский CanvasView
        if hasattr(self.parent, 'mode'):
            self.parent.mode = "idle"
            self.parent.canvas.config(cursor="")

    def create_zone(self):
        """Создаёт зону с введёнными параметрами."""
        zone_name = self.name_var.get().strip()
        zone_subtype = self.zone_type_var.get()
        description = self.desc_var.get().strip()

        # Получаем следующий номер для этого типа зоны
        zone_number = self.board.get_next_zone_number(zone_subtype)

        # Проверка на минимальный размер зоны
        if self.width < 100 or self.height < 100:
            result = messagebox.askyesno(
                "Подтверждение",
                f"Создаваемая зона очень маленькая ({int(self.width)}x{int(self.height)}).\n"
                f"Рекомендуемый минимальный размер: 100x100 пикселей.\n\n"
                f"Создать зону такого размера?"
            )
            if not result:
                return

        # Проверка на уникальность имени (если имя указано)
        if zone_name and self.board.is_zone_name_exists(zone_name):
            messagebox.showerror(
                "Ошибка",
                f"Зона с именем '{zone_name}' уже существует!\n"
                f"Пожалуйста, выберите другое имя."
            )
            return

        # Создаём зону
        zone = Zone(
            id=uid(),
            name=zone_name,
            description=description,
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
            zone_type="tim",
            zone_subtype=zone_subtype,
            zone_number=zone_number
        )

        self.result = zone
        self.dialog.destroy()

        # Возвращаем режим idle, если есть родительский CanvasView
        if hasattr(self.parent, 'mode'):
            self.parent.mode = "idle"
            self.parent.canvas.config(cursor="")

    def show(self) -> Zone:
        """
        Показывает диалог и возвращает созданную зону.

        Returns:
            Созданную зону или None, если пользователь отменил
        """
        self.parent.wait_window(self.dialog)
        return self.result


# Для удобства добавим функцию-обёртку
def create_zone_dialog(parent, x: float, y: float, width: float, height: float, board) -> Zone:
    """
    Удобная функция для создания диалога зоны.

    Args:
        parent: Родительское окно
        x: Координата X
        y: Координата Y
        width: Ширина зоны
        height: Высота зоны
        board: Экземпляр Board

    Returns:
        Созданную зону или None
    """
    dialog = ZoneCreationDialog(parent, x, y, width, height, board)
    return dialog.show()