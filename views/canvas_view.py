"""
Модуль основного представления Canvas

Содержит класс CanvasView для отрисовки и управления схемой сети.
"""

import tkinter as tk
from tkinter import ttk, messagebox, Menu
import customtkinter as ctk
from PIL import Image, ImageTk
from typing import Optional, Tuple, List, Dict, Any
import os

from models.zone import Zone, Board
from models.node import Node
from models.link import Link
from database.cve_db import CVEDatabase
from dialogs.zone_dialog import ZoneCreationDialog
from dialogs.node_dialog import NodeCreationDialog, NodeTypeSelectionDialog
from dialogs.link_dialog import LinkPortSelectionDialog
from dialogs.firewall_dialog import FirewallDialog
from dialogs.vpn_dialog import VPNConfigDialog
from dialogs.security_passport_dialog import SecurityPassportDialog
from dialogs.properties_dialog import PropertiesDialog
from dialogs.routing_dialog import RoutingTableDialog
from dialogs.vm_dialog import VMManagementDialog
from views.context_menus import ZoneContextMenuHandler, NodeContextMenuHandler
from config.node_config import NODE_COLORS, NODE_TYPE_RUSSIAN, ICON_FILES, RESOURCES_DIR


class CanvasView:
    """Основное представление для отрисовки и управления схемой."""

    NODE_COLORS = NODE_COLORS
    NODE_ICONS = {}
    ICON_BOUNDS_CACHE = {}

    # Размеры «мирового» холста (в логических координатах, без учёта зума)
    WORLD_WIDTH = 4000
    WORLD_HEIGHT = 3000

    # Дискретные уровни зума — шаг как у размерной сетки
    ZOOM_LEVELS = [0.25, 0.33, 0.5, 0.67, 0.75, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0]
    ZOOM_DEFAULT = 0.75  # Стартовый зум: иконки оптимального размера, холст больше окна

    def __init__(self, root: tk.Tk, board: Board):
        self.root = root
        self.board = board

        self.selected_node_id: Optional[str] = None
        self.selected_zone_id: Optional[str] = None
        self.link_start_id: Optional[str] = None
        self.link_start_node: Optional[Node] = None
        self.mode = "idle"

        # Зум холста
        self.zoom = self.ZOOM_DEFAULT

        # Drag and drop
        self.dragging = False
        self.drag_node: Optional[Node] = None
        self.drag_offset: Tuple[float, float] = (0, 0)

        self.dragging_zone = False
        self.drag_zone: Optional[Zone] = None
        self.drag_zone_offset: Tuple[float, float] = (0, 0)

        # Ресайз зоны (ресайз узлов отключён по требованию)
        self.resizing_zone = False
        self.resize_zone: Optional[Zone] = None
        self.resize_zone_corner: Optional[str] = None
        self.resize_zone_start: Optional[Tuple] = None

        # Изолированный режим редактирования размера зоны (промт 8 №8)
        self.zone_edit_mode: bool = False          # True, если активен изолированный режим
        self.zone_edit_zone: Optional[Zone] = None  # Редактируемая зона
        self.zone_edit_original: Optional[Tuple[float, float, float, float]] = None  # Для отката (x,y,w,h)
        self.zone_edit_overlay = None              # Overlay-фрейм с кнопками Save/Cancel
        self._control_buttons: list = []           # Кнопки в control_frame — для временного disable

        # Creation modes
        self.creating_zone = False
        self.creating_zone_start: Optional[Tuple[float, float]] = None
        self.creating_zone_rect: Optional[int] = None
        self.show_zone_hint = True

        self.create_link_mode_active = False
        self.delete_link_mode_active = False
        self.link_removal_node1_id: Optional[str] = None

        self.temp_elements = []

        # Сетка привязки
        self.grid_size = 10  # Шаг сетки в пикселях (по умолчанию 10)
        self.grid_enabled = True

        try:
            self.db = CVEDatabase()
        except FileNotFoundError:
            self.db = None
            print("[WARN] База данных CVE не найдена")

        self.setup_ui()
        self.load_node_icons()
        self.redraw()

    def load_node_icons(self):
        """Загружает иконки для узлов."""
        for node_type, filename in ICON_FILES.items():
            try:
                icon_path = os.path.join(RESOURCES_DIR, filename)
                if os.path.exists(icon_path):
                    img = Image.open(icon_path)
                    self.NODE_ICONS[node_type] = img
                else:
                    self.NODE_ICONS[node_type] = None
            except Exception as e:
                print(f"Ошибка загрузки иконки {filename}: {e}")
                self.NODE_ICONS[node_type] = None

    def snap_to_grid(self, value: float) -> float:
        """Округляет значение к ближайшей точке сетки."""
        if not self.grid_enabled or self.grid_size <= 1:
            return value
        return round(value / self.grid_size) * self.grid_size

    def snap_size_to_grid(self, size: float) -> float:
        """Округляет размер к ближайшему значению, кратному сетке."""
        if not self.grid_enabled or self.grid_size <= 1:
            return size
        return max(self.grid_size, round(size / self.grid_size) * self.grid_size)

    # ===== Зум: преобразование координат «мира» и холста =====
    def w2c(self, v: float) -> float:
        """World -> Canvas: умножает мировую координату/размер на текущий зум."""
        return v * self.zoom

    def c2w(self, v: float) -> float:
        """Canvas -> World: делит координату холста на текущий зум."""
        return v / self.zoom if self.zoom else v

    def canvas_event_world(self, event) -> Tuple[float, float]:
        """Возвращает мировые координаты точки события."""
        cx = self.canvas.canvasx(event.x)
        cy = self.canvas.canvasy(event.y)
        return (self.c2w(cx), self.c2w(cy))

    def font_scaled(self, base_size: int, weight: str = "normal") -> tuple:
        """Возвращает кортеж шрифта с размером, скорректированным под текущий зум."""
        size = max(6, int(round(base_size * self.zoom)))
        if weight and weight != "normal":
            return ("Arial", size, weight)
        return ("Arial", size)

    def update_scrollregion(self) -> None:
        """Обновляет область прокрутки холста под текущий зум."""
        try:
            self.canvas.configure(scrollregion=(
                0, 0,
                int(self.WORLD_WIDTH * self.zoom),
                int(self.WORLD_HEIGHT * self.zoom),
            ))
        except Exception:
            pass

    def _set_zoom(self, new_zoom: float, anchor_screen: Optional[Tuple[int, int]] = None) -> None:
        """Устанавливает новый уровень зума, стараясь сохранить точку под курсором."""
        new_zoom = max(self.ZOOM_LEVELS[0], min(self.ZOOM_LEVELS[-1], new_zoom))
        if abs(new_zoom - self.zoom) < 1e-6:
            return

        # Сохраняем мировую точку под якорем, чтобы не «уплывала» при зуме
        anchor_world = None
        if anchor_screen is not None:
            sx, sy = anchor_screen
            cx = self.canvas.canvasx(sx)
            cy = self.canvas.canvasy(sy)
            anchor_world = (self.c2w(cx), self.c2w(cy))

        # Фиксируем новый зум и обновляем scrollregion. Далее сначала
        # скроллим viewport на «куда нужно» (без рендера старого зума),
        # а только потом делаем redraw. Это устраняет «ghost frame»:
        # пользователь больше не видит промежуточный кадр, в котором
        # элементы нарисованы в новой позиции, а окно смотрит на старое.
        self.zoom = new_zoom
        self.clear_icon_bounds_cache()
        self.update_scrollregion()

        # Скроллим так, чтобы якорь остался под курсором — ДО redraw.
        if anchor_world is not None and anchor_screen is not None:
            new_cx = self.w2c(anchor_world[0])
            new_cy = self.w2c(anchor_world[1])
            region_w = max(1, self.WORLD_WIDTH * self.zoom)
            region_h = max(1, self.WORLD_HEIGHT * self.zoom)
            sx, sy = anchor_screen
            target_x = (new_cx - sx) / region_w
            target_y = (new_cy - sy) / region_h
            try:
                self.canvas.xview_moveto(max(0.0, min(1.0, target_x)))
                self.canvas.yview_moveto(max(0.0, min(1.0, target_y)))
            except Exception:
                pass

        # Теперь единым махом стираем старое и рисуем новое. Между delete
        # и create_* Tk не успевает вывести промежуточное состояние на экран,
        # т.к. мы не вызываем canvas.update() — обновление произойдёт на idle.
        self.redraw()

        # Обновляем индикатор зума, если он уже создан
        if hasattr(self, "zoom_label") and self.zoom_label is not None:
            try:
                self.zoom_label.configure(text=f"{int(round(self.zoom * 100))}%")
            except Exception:
                pass

    def zoom_in(self, anchor: Optional[Tuple[int, int]] = None) -> None:
        """Увеличивает зум до следующего уровня."""
        for level in self.ZOOM_LEVELS:
            if level > self.zoom + 1e-6:
                self._set_zoom(level, anchor_screen=anchor)
                return

    def zoom_out(self, anchor: Optional[Tuple[int, int]] = None) -> None:
        """Уменьшает зум до предыдущего уровня."""
        for level in reversed(self.ZOOM_LEVELS):
            if level < self.zoom - 1e-6:
                self._set_zoom(level, anchor_screen=anchor)
                return

    # ===== Обработчики колеса мыши =====
    def _on_mouse_wheel(self, event):
        """Колесо мыши — вертикальный скролл."""
        delta = int(-event.delta / 120) if event.delta else 0
        if delta:
            self.canvas.yview_scroll(delta, "units")
        return "break"

    def _on_shift_mouse_wheel(self, event):
        """Shift+колесо — горизонтальный скролл."""
        delta = int(-event.delta / 120) if event.delta else 0
        if delta:
            self.canvas.xview_scroll(delta, "units")
        return "break"

    def _on_ctrl_mouse_wheel(self, event):
        """Ctrl+колесо — зум с шагом (якорь — точка под курсором)."""
        anchor = (event.x, event.y)
        if event.delta > 0:
            self.zoom_in(anchor=anchor)
        elif event.delta < 0:
            self.zoom_out(anchor=anchor)
        return "break"

    def show_grid_settings(self):
        """Показывает окно настроек сетки."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Настройки сетки")
        dialog.geometry("300x200")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 300) // 2
        y = (dialog.winfo_screenheight() - 200) // 2
        dialog.geometry(f"300x200+{x}+{y}")

        ctk.CTkLabel(dialog, text="Настройки сетки", font=("Arial", 16, "bold")).pack(pady=(15, 10))

        enabled_var = tk.BooleanVar(value=self.grid_enabled)
        ctk.CTkCheckBox(dialog, text="Привязка к сетке включена", variable=enabled_var).pack(pady=5)

        size_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        size_frame.pack(pady=10)
        ctk.CTkLabel(size_frame, text="Шаг сетки (px):", font=("Arial", 12)).pack(side=tk.LEFT, padx=5)
        size_var = tk.StringVar(value=str(self.grid_size))
        ctk.CTkEntry(size_frame, textvariable=size_var, width=60).pack(side=tk.LEFT, padx=5)

        def apply():
            self.grid_enabled = enabled_var.get()
            try:
                val = int(size_var.get())
                if 1 <= val <= 100:
                    self.grid_size = val
            except ValueError:
                pass
            # Привязать все существующие узлы к сетке
            if self.grid_enabled:
                for node in self.board.nodes:
                    nx, ny = node.position
                    node.position = (self.snap_to_grid(nx), self.snap_to_grid(ny))
                    w, h = node.size
                    node.size = (self.snap_size_to_grid(w), self.snap_size_to_grid(h))
                self.clear_icon_bounds_cache()
                self.redraw()
            dialog.destroy()

        ctk.CTkButton(dialog, text="Применить", command=apply, width=120).pack(pady=10)

    def show_scale_settings(self):
        """Показывает окно выбора масштаба интерфейса."""
        from utils.scaling import SCALE_OPTIONS, load_user_scale, save_user_scale, apply_scaling

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Масштаб интерфейса")
        dialog.geometry("350x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 350) // 2
        y = (dialog.winfo_screenheight() - 250) // 2
        dialog.geometry(f"350x250+{x}+{y}")

        ctk.CTkLabel(dialog, text="Масштаб интерфейса", font=("Arial", 16, "bold")).pack(pady=(15, 5))
        ctk.CTkLabel(dialog, text="Выберите масштаб отображения элементов",
                     font=("Arial", 11), text_color="gray").pack(pady=(0, 10))

        current_scale = load_user_scale()
        scale_var = tk.StringVar(value=current_scale)

        options = list(SCALE_OPTIONS.keys())
        combo = ctk.CTkComboBox(dialog, values=options, variable=scale_var,
                                width=200, state="readonly")
        combo.pack(pady=10)

        info_label = ctk.CTkLabel(dialog, text="Изменение вступит в силу после перезапуска",
                                  font=("Arial", 10), text_color="gray")
        info_label.pack(pady=(0, 10))

        def apply_scale():
            chosen = scale_var.get()
            save_user_scale(chosen)
            apply_scaling(chosen)
            info_label.configure(text="Масштаб применён. Перезапустите для полного эффекта.",
                                text_color="#4CAF50")

        ctk.CTkButton(dialog, text="Применить", command=apply_scale, width=120).pack(pady=5)
        ctk.CTkButton(dialog, text="Закрыть", command=dialog.destroy,
                      width=100, fg_color="gray").pack(pady=5)

    def get_icon_bounds(self, node: Node):
        """Возвращает границы иконки узла для отрисовки соединений."""
        cache_key = f"{node.id}_{node.size[0]}_{node.size[1]}"

        if cache_key in self.ICON_BOUNDS_CACHE:
            bounds = self.ICON_BOUNDS_CACHE[cache_key]
            return (bounds[0] + node.position[0], bounds[1] + node.position[1],
                    bounds[2], bounds[3])

        icon = self.NODE_ICONS.get(node.type)
        if icon is None:
            return (node.position[0], node.position[1], node.size[0], node.size[1])

        try:
            img = icon.copy()
            img = img.resize((int(node.size[0]), int(node.size[1])), Image.Resampling.LANCZOS)

            if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
                if img.mode != 'RGBA':
                    img = img.convert('RGBA')

                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    data = list(img.getdata())

                min_x, min_y = node.size[0], node.size[1]
                max_x, max_y = 0, 0

                for y in range(img.height):
                    for x in range(img.width):
                        pixel = data[y * img.width + x]
                        if len(pixel) == 4 and pixel[3] > 0:
                            if x < min_x: min_x = x
                            if x > max_x: max_x = x
                            if y < min_y: min_y = y
                            if y > max_y: max_y = y

                if max_x >= min_x and max_y >= min_y:
                    width = max_x - min_x + 1
                    height = max_y - min_y + 1
                    padding = 2
                    min_x = max(0, min_x - padding)
                    min_y = max(0, min_y - padding)
                    width = min(node.size[0] - min_x, width + 2 * padding)
                    height = min(node.size[1] - min_y, height + 2 * padding)
                    bounds = (min_x, min_y, width, height)
                else:
                    bounds = (node.size[0] / 2 - 1, node.size[1] / 2 - 1, 2, 2)
            else:
                bounds = (0, 0, node.size[0], node.size[1])

            self.ICON_BOUNDS_CACHE[cache_key] = bounds
            return (bounds[0] + node.position[0], bounds[1] + node.position[1],
                    bounds[2], bounds[3])
        except Exception as e:
            print(f"Ошибка анализа границ иконки: {e}")
            return (node.position[0], node.position[1], node.size[0], node.size[1])

    def clear_icon_bounds_cache(self, node_id=None):
        if node_id:
            keys_to_delete = [k for k in self.ICON_BOUNDS_CACHE.keys() if k.startswith(node_id)]
            for key in keys_to_delete:
                del self.ICON_BOUNDS_CACHE[key]
        else:
            self.ICON_BOUNDS_CACHE.clear()

    def setup_ui(self):
        """Настраивает пользовательский интерфейс."""
        self.root.title("Автоматизированная система построения цифровых карт безопасности")

        # Левая панель управления
        control_frame = ctk.CTkFrame(self.root)
        control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=6)

        ctk.CTkLabel(control_frame, text="Режимы работы", font=("Arial", 16, "bold")).pack(anchor=tk.W, pady=(0, 4))

        self.btn_add_zone = ctk.CTkButton(control_frame, text="Структура РИС", command=self.start_zone_creation)
        self.btn_add_zone.pack(fill=tk.X, pady=2)

        self.btn_add_node = ctk.CTkButton(control_frame, text="Добавить узел", command=self.show_add_node_dialog)
        self.btn_add_node.pack(fill=tk.X, pady=2)

        self.btn_create_link = ctk.CTkButton(control_frame, text="Создание соединения", command=self.toggle_create_link_mode)
        self.btn_create_link.pack(fill=tk.X, pady=2)

        self.btn_delete_link = ctk.CTkButton(control_frame, text="Удаление соединения", command=self.toggle_delete_link_mode)
        self.btn_delete_link.pack(fill=tk.X, pady=2)

        self.btn_delete = ctk.CTkButton(control_frame, text="Удалить выбранное", command=self.delete_selected)
        self.btn_delete.pack(fill=tk.X, pady=2)

        self.btn_clear = ctk.CTkButton(control_frame, text="Очистить всё", command=self.clear_all)
        self.btn_clear.pack(fill=tk.X, pady=2)

        self.btn_connectivity = ctk.CTkButton(control_frame, text="Анализ связности", command=self.show_connectivity_report)
        self.btn_connectivity.pack(fill=tk.X, pady=2)

        ttk.Separator(control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=6)

        self.btn_grid = ctk.CTkButton(control_frame, text="Настройки сетки", command=self.show_grid_settings)
        self.btn_grid.pack(fill=tk.X, pady=2)

        self.btn_scale = ctk.CTkButton(control_frame, text="Масштаб интерфейса", command=self.show_scale_settings)
        self.btn_scale.pack(fill=tk.X, pady=2)

        # Список кнопок для временной блокировки (используется изолированным
        # режимом редактирования зоны — промт 8 №8).
        self._control_buttons = [
            self.btn_add_zone, self.btn_add_node, self.btn_create_link,
            self.btn_delete_link, self.btn_delete, self.btn_clear,
            self.btn_connectivity, self.btn_grid, self.btn_scale,
        ]

        # Правая область - холст c прокруткой
        self._canvas_frame = ttk.Frame(self.root)
        self._canvas_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        canvas_frame = self._canvas_frame

        # Скроллбары
        h_scroll = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL)
        v_scroll = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL)

        self.canvas = tk.Canvas(
            canvas_frame, bg="white", width=1000, height=700,
            scrollregion=(0, 0, int(self.WORLD_WIDTH * self.zoom), int(self.WORLD_HEIGHT * self.zoom)),
            xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set,
            highlightthickness=0,
        )

        h_scroll.config(command=self.canvas.xview)
        v_scroll.config(command=self.canvas.yview)

        # Индикатор текущего зума в нижнем правом углу (над скроллбарами).
        # Поверх холста, справа-снизу — всегда виден поверх рисунка.
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.zoom_label = tk.Label(
            self.canvas,
            text=f"{int(round(self.zoom * 100))}%",
            bg="#ffffff", fg="#333333",
            font=("Arial", 10, "bold"),
            bd=1, relief=tk.SOLID, padx=6, pady=2
        )
        # place() относительно холста — всегда в правом нижнем углу видимой области
        self.zoom_label.place(relx=1.0, rely=1.0, anchor="se", x=-6, y=-6)

        # Привязка событий
        self.canvas.bind("<Button-1>", self.on_canvas_click)
        self.canvas.bind("<B1-Motion>", self.on_canvas_drag)
        self.canvas.bind("<ButtonRelease-1>", self.on_canvas_release)
        self.canvas.bind("<Button-3>", self.on_canvas_right_click)
        self.canvas.bind("<Motion>", self.on_canvas_motion)
        self.canvas.bind("<Double-Button-1>", self.on_canvas_double_click)

        # Навигация: колесо — вертикальный скролл; Shift+колесо — горизонтальный;
        # Ctrl+колесо — зум. Фокус на холсте нужен, чтобы события ловились.
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)
        self.canvas.bind("<Shift-MouseWheel>", self._on_shift_mouse_wheel)
        self.canvas.bind("<Control-MouseWheel>", self._on_ctrl_mouse_wheel)
        self.canvas.bind("<Enter>", lambda e: self.canvas.focus_set())

        self.status_label = ttk.Label(control_frame, text="", font=("Arial", 9))
        self.status_label.pack(fill=tk.X, pady=(10, 0))

    def start_zone_creation(self):
        self.mode = "creating_zone"
        self.creating_zone_start = None
        self.creating_zone_rect = None
        self.canvas.config(cursor="cross")

        if self.show_zone_hint:
            self.show_zone_creation_hint()

    def show_zone_creation_hint(self):
        hint_window = ctk.CTkToplevel(self.root)
        hint_window.title("Создание зоны TIM")
        hint_window.geometry("500x220")
        hint_window.resizable(False, False)
        hint_window.transient(self.root)
        hint_window.grab_set()

        hint_window.update_idletasks()
        x = (hint_window.winfo_screenwidth() // 2) - (250)
        y = (hint_window.winfo_screenheight() // 2) - (140)
        hint_window.geometry(f'500x220+{x}+{y}')

        # При закрытии окна через крестик — отменяем режим создания зоны
        hint_window.protocol("WM_DELETE_WINDOW", lambda: self.cancel_zone_creation(hint_window))

        hint_text = "Создание зоны TIM\n\n"
        hint_text += "1. Нажмите и удерживайте левую кнопку мыши на холсте\n"
        hint_text += "2. Перетащите курсор, чтобы выделить прямоугольную область\n"
        hint_text += "3. Отпустите кнопку мыши, когда область будет нужного размера\n"
        hint_text += "4. Введите название и описание зоны в появившемся окне"

        ctk.CTkLabel(hint_window, text=hint_text, font=("Arial", 14), justify=tk.LEFT).pack(anchor=tk.W, padx=20,
                                                                                            pady=(20, 15))

        self.dont_show_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(hint_window, text="Больше не показывать это сообщение", variable=self.dont_show_var,
                        font=("Arial", 12)).pack(anchor=tk.W, padx=20, pady=(0, 15))

        button_frame = ctk.CTkFrame(hint_window, fg_color="transparent")
        button_frame.pack(fill=tk.X, padx=20, pady=(0, 20))

        ctk.CTkButton(button_frame, text="Понятно", command=lambda: self.close_hint_window(hint_window),
                      width=100).pack(side=tk.RIGHT)

    def show_connectivity_report(self):
        """Показывает отчёт о сетевой связности в табличном виде."""
        from models.connectivity_matrix import ConnectivityStatus

        matrix = self.board.get_connectivity_matrix()
        nodes = self.board.nodes

        if not nodes:
            messagebox.showinfo("Анализ связности", "Нет узлов для анализа.")
            return

        report_window = ctk.CTkToplevel(self.root)
        report_window.title("Анализ сетевой связности")
        report_window.geometry("900x600")
        report_window.transient(self.root)

        # Заголовок
        header = ctk.CTkFrame(report_window, fg_color="transparent")
        header.pack(fill=tk.X, padx=15, pady=(10, 5))

        ctk.CTkLabel(header, text="Матрица сетевой связности", font=("Arial", 18, "bold")).pack(side=tk.LEFT)

        # Легенда
        legend_frame = ctk.CTkFrame(report_window, fg_color="transparent")
        legend_frame.pack(fill=tk.X, padx=15, pady=(0, 10))

        legend_items = [
            ("Прямое", "#4CAF50"), ("Маршрут", "#2196F3"),
            ("VPN", "#FF9800"), ("Заблокировано", "#F44336"), ("Нет связи", "#CCCCCC")
        ]
        for text, color in legend_items:
            lf = ctk.CTkFrame(legend_frame, fg_color="transparent")
            lf.pack(side=tk.LEFT, padx=8)
            ctk.CTkFrame(lf, width=14, height=14, fg_color=color, corner_radius=3).pack(side=tk.LEFT, padx=(0, 4))
            ctk.CTkLabel(lf, text=text, font=("Arial", 10)).pack(side=tk.LEFT)

        # Таблица через Treeview
        tree_frame = ctk.CTkFrame(report_window)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))

        style = ttk.Style()
        style.configure("Connectivity.Treeview", font=("Arial", 10), rowheight=28)
        style.configure("Connectivity.Treeview.Heading", font=("Arial", 10, "bold"))

        columns = ("source", "target", "status", "reason")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                            style="Connectivity.Treeview", height=20)

        tree.heading("source", text="Узел-источник")
        tree.heading("target", text="Узел-назначение")
        tree.heading("status", text="Статус связи")
        tree.heading("reason", text="Описание")

        tree.column("source", width=180, anchor="w")
        tree.column("target", width=180, anchor="w")
        tree.column("status", width=150, anchor="center")
        tree.column("reason", width=300, anchor="w")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Теги для цветовой индикации
        tree.tag_configure("direct", background="#E8F5E9", foreground="#1B5E20")
        tree.tag_configure("routed", background="#E3F2FD", foreground="#0D47A1")
        tree.tag_configure("vpn", background="#FFF3E0", foreground="#E65100")
        tree.tag_configure("blocked", background="#FFEBEE", foreground="#B71C1C")
        tree.tag_configure("none", background="#FAFAFA", foreground="#999999")

        status_display = {
            ConnectivityStatus.DIRECT: ("Прямое соединение", "direct"),
            ConnectivityStatus.ROUTED: ("Через маршрутизатор", "routed"),
            ConnectivityStatus.VPN: ("VPN туннель", "vpn"),
            ConnectivityStatus.BLOCKED: ("Заблокировано", "blocked"),
            ConnectivityStatus.NONE: ("Нет связи", "none"),
        }

        nodes_dict = {n.id: n.name for n in nodes}

        # Заполняем данные
        for (src_id, dst_id), conn in matrix.matrix.items():
            src_name = nodes_dict.get(src_id, src_id)
            dst_name = nodes_dict.get(dst_id, dst_id)
            status_text, tag = status_display.get(conn.status, ("???", "none"))
            reason = conn.reason if conn.reason else "-"
            tree.insert("", tk.END, values=(src_name, dst_name, status_text, reason), tags=(tag,))

        # Статистика
        stats_frame = ctk.CTkFrame(report_window, fg_color="transparent")
        stats_frame.pack(fill=tk.X, padx=15, pady=(0, 10))

        total = len(matrix.matrix)
        direct_count = sum(1 for c in matrix.matrix.values() if c.status == ConnectivityStatus.DIRECT)
        routed_count = sum(1 for c in matrix.matrix.values() if c.status == ConnectivityStatus.ROUTED)
        vpn_count = sum(1 for c in matrix.matrix.values() if c.status == ConnectivityStatus.VPN)
        blocked_count = sum(1 for c in matrix.matrix.values() if c.status == ConnectivityStatus.BLOCKED)
        none_count = sum(1 for c in matrix.matrix.values() if c.status == ConnectivityStatus.NONE)

        stats_text = (
            f"Всего пар: {total}  |  "
            f"Прямых: {direct_count}  |  Маршрутов: {routed_count}  |  "
            f"VPN: {vpn_count}  |  Заблокировано: {blocked_count}  |  Нет связи: {none_count}"
        )
        ctk.CTkLabel(stats_frame, text=stats_text, font=("Arial", 11)).pack(side=tk.LEFT)

    def cancel_zone_creation(self, hint_window):
        """Отменяет режим создания зоны и закрывает окно инструкции."""
        self.mode = "idle"
        self.creating_zone_start = None
        self.creating_zone_rect = None
        self.canvas.config(cursor="")
        hint_window.destroy()

    def close_hint_window(self, hint_window):
        if self.dont_show_var and self.dont_show_var.get():
            self.show_zone_hint = False
        hint_window.destroy()

    def toggle_create_link_mode(self):
        self.create_link_mode_active = not self.create_link_mode_active

        if self.create_link_mode_active:
            if self.delete_link_mode_active:
                self.delete_link_mode_active = False
                self.btn_delete_link.configure(fg_color="#1E88E5")
            self.btn_create_link.configure(fg_color="#4CAF50")
            self.mode = "create_link"
            self.link_start_id = None
            self.link_start_node = None
            self.canvas.config(cursor="dotbox")
            self.clear_temp_elements()
        else:
            self.btn_create_link.configure(fg_color="#1E88E5")
            self.mode = "idle"
            self.link_start_id = None
            self.link_start_node = None
            self.canvas.config(cursor="")
            self.clear_temp_elements()
            self.selected_node_id = None
            self.redraw()

    def toggle_delete_link_mode(self):
        self.delete_link_mode_active = not self.delete_link_mode_active

        if self.delete_link_mode_active:
            if self.create_link_mode_active:
                self.create_link_mode_active = False
                self.btn_create_link.configure(fg_color="#1E88E5")
            self.btn_delete_link.configure(fg_color="#4CAF50")
            self.mode = "delete_link"
            self.link_removal_node1_id = None
            self.canvas.config(cursor="dotbox")
            self.clear_temp_elements()
        else:
            self.btn_delete_link.configure(fg_color="#1E88E5")
            self.mode = "idle"
            self.link_removal_node1_id = None
            self.canvas.config(cursor="")
            self.clear_temp_elements()
            self.selected_node_id = None
            self.redraw()

    def show_add_node_dialog(self):
        try:
            type_dialog = NodeTypeSelectionDialog(self.root, self.board)
            self.root.wait_window(type_dialog.dialog)

            if not type_dialog.result:
                return

            selected_type = type_dialog.result

            if selected_type == "Сервер виртуализации":
                subtype_dialog = ctk.CTkToplevel(self.root)
                subtype_dialog.title("Выбор типа сервера виртуализации")
                subtype_dialog.geometry("400x220")
                subtype_dialog.transient(self.root)
                subtype_dialog.grab_set()

                subtype_dialog.update_idletasks()
                x = (subtype_dialog.winfo_screenwidth() // 2) - 200
                y = (subtype_dialog.winfo_screenheight() // 2) - 110
                subtype_dialog.geometry(f'400x220+{x}+{y}')

                main_frame = ctk.CTkFrame(subtype_dialog)
                main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

                ctk.CTkLabel(main_frame, text="Выберите тип сервера:", font=("Arial", 14, "bold")).pack(pady=(0, 15))

                subtype_var = tk.StringVar(value="hypervisor")
                ctk.CTkRadioButton(main_frame, text="Гипервизор (VMware, Hyper-V, ...)", variable=subtype_var,
                                   value="hypervisor", font=("Arial", 12)).pack(anchor=tk.W, pady=5)
                ctk.CTkRadioButton(main_frame, text="Контейнер (Docker, LXC, ...)", variable=subtype_var,
                                   value="container", font=("Arial", 12)).pack(anchor=tk.W, pady=5)

                btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
                btn_frame.pack(fill=tk.X, pady=(15, 0))

                def on_subtype_ok():
                    chosen_subtype = subtype_var.get()
                    subtype_dialog.destroy()
                    dialog = NodeCreationDialog(self.root, self.board, selected_type)
                    dialog.virtualization_subtype = chosen_subtype
                    self.root.wait_window(dialog.dialog)
                    if dialog.result:
                        if self.board.add_node(dialog.result):
                            self.selected_node_id = dialog.result.id
                            self.redraw()

                ctk.CTkButton(btn_frame, text="OK", command=on_subtype_ok, width=100, fg_color="#4CAF50").pack(
                    side=tk.RIGHT, padx=5)
                ctk.CTkButton(btn_frame, text="Отмена", command=subtype_dialog.destroy, width=100,
                              fg_color="#F44336").pack(side=tk.RIGHT, padx=5)
                return

            dialog = NodeCreationDialog(self.root, self.board, selected_type)
            self.root.wait_window(dialog.dialog)

            if dialog.result:
                if self.board.add_node(dialog.result):
                    self.selected_node_id = dialog.result.id
                    self.selected_zone_id = None
                    self.redraw()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Неожиданная ошибка: {str(e)}")

    def on_canvas_click(self, event):
        self.canvas.focus_set()
        x, y = self.canvas_event_world(event)

        # Изолированный режим редактирования размера зоны (промт 8 №8):
        # единственная разрешённая активность — тянуть за уголки этой зоны.
        if self.zone_edit_mode and self.zone_edit_zone is not None:
            corner = self.get_zone_corner_at(x, y, self.zone_edit_zone)
            edge = self.get_zone_edge_at(x, y, self.zone_edit_zone)
            if corner or edge:
                self.resizing_zone = True
                self.resize_zone = self.zone_edit_zone
                self.resize_zone_corner = corner or edge
                zone = self.zone_edit_zone
                self.resize_zone_start = (x, y, zone.x, zone.y, zone.width, zone.height)
            # Клики по всему остальному — игнорируются
            return

        if self.mode == "creating_zone":
            sx = self.snap_to_grid(x)
            sy = self.snap_to_grid(y)
            self.creating_zone_start = (sx, sy)
            self.creating_zone_rect = self.canvas.create_rectangle(
                self.w2c(sx), self.w2c(sy), self.w2c(sx), self.w2c(sy),
                outline="blue", dash=(2, 2), width=2)
            return

        if self.mode == "create_link":
            node = self.find_node_at(x, y)
            if node:
                if self.link_start_id is None:
                    self.link_start_id = node.id
                    self.link_start_node = node
                    self.selected_node_id = node.id
                    self.canvas.config(cursor="dot")
                    self.show_temp_link_start(node)
                else:
                    if self.link_start_id != node.id:
                        dialog = LinkPortSelectionDialog(self.root, self.link_start_node, node)
                        self.root.wait_window(dialog.dialog)
                        if dialog.result:
                            self.board.add_link(self.link_start_id, node.id, dialog.result)
                            self.redraw()
                    self.link_start_id = None
                    self.link_start_node = None
                    self.selected_node_id = None
                    self.canvas.config(cursor="dotbox")
                    self.clear_temp_elements()
                    self.redraw()
            else:
                self.link_start_id = None
                self.link_start_node = None
                self.clear_temp_elements()
                self.redraw()
            return

        if self.mode == "delete_link":
            node = self.find_node_at(x, y)
            if node:
                if self.link_removal_node1_id is None:
                    self.link_removal_node1_id = node.id
                    self.selected_node_id = node.id
                    self.redraw()
                else:
                    if self.link_removal_node1_id != node.id:
                        self.board.remove_link_between_nodes(self.link_removal_node1_id, node.id)
                        self.redraw()
                    self.link_removal_node1_id = None
                    self.selected_node_id = None
                    self.redraw()
            else:
                self.link_removal_node1_id = None
                self.redraw()
            return

        # Обычный режим
        node = self.find_node_at(x, y)
        if node:
            self.dragging = True
            self.drag_node = node
            self.selected_node_id = node.id
            self.selected_zone_id = None
            node_x, node_y = node.position
            self.drag_offset = (x - node_x, y - node_y)
            self.clear_temp_elements()
            # Синяя обводка при перетаскивании — сплошная (промт 8 #9)
            temp_rect = self.canvas.create_rectangle(
                self.w2c(node_x), self.w2c(node_y),
                self.w2c(node_x + node.size[0]), self.w2c(node_y + node.size[1]),
                outline="blue", width=2)
            self.temp_elements.append(temp_rect)
        else:
            zone = self.find_tim_zone_at(x, y)
            if zone:
                # Промт 8 №8: drag-resize зоны за уголки в обычном режиме отключён.
                # Ресайз зоны доступен только через ПКМ → «Изменить размер»
                # (изолированный режим). Остаётся только перетаскивание зоны.
                self.dragging_zone = True
                self.drag_zone = zone
                self.selected_zone_id = zone.id
                center_x, center_y = zone.center()
                self.drag_zone_offset = (x - center_x, y - center_y)
                self.clear_temp_elements()
                temp_rect = self.canvas.create_rectangle(
                    self.w2c(zone.x), self.w2c(zone.y),
                    self.w2c(zone.x + zone.width), self.w2c(zone.y + zone.height),
                    outline="purple", dash=(2, 2), width=2)
                self.temp_elements.append(temp_rect)
            else:
                self.selected_node_id = None
                self.selected_zone_id = None
                self.redraw()

    def on_canvas_drag(self, event):
        x, y = self.canvas_event_world(event)

        if self.mode == "creating_zone" and self.creating_zone_start and self.creating_zone_rect:
            start_x, start_y = self.creating_zone_start
            snap_x = self.snap_to_grid(x)
            snap_y = self.snap_to_grid(y)
            self.canvas.coords(self.creating_zone_rect,
                               self.w2c(start_x), self.w2c(start_y),
                               self.w2c(snap_x), self.w2c(snap_y))
            return

        if self.dragging and self.drag_node:
            new_x = self.snap_to_grid(x - self.drag_offset[0])
            new_y = self.snap_to_grid(y - self.drag_offset[1])
            zone = self.drag_node.zone
            if zone:
                new_x = max(zone.x, min(new_x, zone.x + zone.width - self.drag_node.size[0]))
                new_y = max(zone.y, min(new_y, zone.y + zone.height - self.drag_node.size[1]))
            if self.temp_elements:
                self.canvas.coords(self.temp_elements[0],
                                   self.w2c(new_x), self.w2c(new_y),
                                   self.w2c(new_x + self.drag_node.size[0]),
                                   self.w2c(new_y + self.drag_node.size[1]))

        elif self.dragging_zone and self.drag_zone:
            new_center_x = x - self.drag_zone_offset[0]
            new_center_y = y - self.drag_zone_offset[1]
            new_x = self.snap_to_grid(new_center_x - self.drag_zone.width / 2.0)
            new_y = self.snap_to_grid(new_center_y - self.drag_zone.height / 2.0)
            if self.temp_elements:
                self.canvas.coords(self.temp_elements[0],
                                   self.w2c(new_x), self.w2c(new_y),
                                   self.w2c(new_x + self.drag_zone.width),
                                   self.w2c(new_y + self.drag_zone.height))

        elif self.resizing_zone and self.resize_zone and self.resize_zone_start:
            start_x, start_y, zone_x, zone_y, zone_w, zone_h = self.resize_zone_start
            dx = x - start_x
            dy = y - start_y

            new_x, new_y, new_w, new_h = zone_x, zone_y, zone_w, zone_h

            corner = self.resize_zone_corner
            if corner == 'nw':
                new_x = zone_x + dx; new_y = zone_y + dy
                new_w = zone_w - dx; new_h = zone_h - dy
            elif corner == 'ne':
                new_y = zone_y + dy
                new_w = zone_w + dx; new_h = zone_h - dy
            elif corner == 'sw':
                new_x = zone_x + dx
                new_w = zone_w - dx; new_h = zone_h + dy
            elif corner == 'se':
                new_w = zone_w + dx; new_h = zone_h + dy
            elif corner == 'n':
                new_y = zone_y + dy; new_h = zone_h - dy
            elif corner == 's':
                new_h = zone_h + dy
            elif corner == 'w':
                new_x = zone_x + dx; new_w = zone_w - dx
            elif corner == 'e':
                new_w = zone_w + dx

            new_w = max(100, new_w)
            new_h = max(100, new_h)
            new_x = self.snap_to_grid(new_x)
            new_y = self.snap_to_grid(new_y)
            new_w = self.snap_size_to_grid(new_w)
            new_h = self.snap_size_to_grid(new_h)

            # В изолированном режиме меняем зону напрямую и перерисовываем
            if self.zone_edit_mode and self.zone_edit_zone is self.resize_zone:
                self.board.resize_zone(self.resize_zone.id, new_x, new_y, new_w, new_h)
                self.redraw()

    def on_canvas_release(self, event):
        x, y = self.canvas_event_world(event)

        if self.mode == "creating_zone" and self.creating_zone_start and self.creating_zone_rect:
            start_x, start_y = self.creating_zone_start
            end_x = self.snap_to_grid(x)
            end_y = self.snap_to_grid(y)
            zone_x = min(start_x, end_x)
            zone_y = min(start_y, end_y)
            zone_width = self.snap_size_to_grid(abs(end_x - start_x))
            zone_height = self.snap_size_to_grid(abs(end_y - start_y))

            self.canvas.delete(self.creating_zone_rect)
            self.creating_zone_rect = None

            if zone_width > 20 and zone_height > 20:
                dialog = ZoneCreationDialog(self.root, zone_x, zone_y, zone_width, zone_height, self.board)
                self.root.wait_window(dialog.dialog)
                if dialog.result:
                    self.board.add_zone(dialog.result)
                    self.redraw()
            else:
                messagebox.showwarning("Предупреждение", "Зона слишком маленькая. Минимальный размер: 20x20 пикселей.")
            self.mode = "idle"
            self.canvas.config(cursor="")
            return

        if self.dragging and self.drag_node:
            new_x = self.snap_to_grid(x - self.drag_offset[0])
            new_y = self.snap_to_grid(y - self.drag_offset[1])
            zone = self.drag_node.zone

            # Узел "Интернет" не должен пересекать границы TIM-зон
            if self.drag_node.type == "Internet":
                node_w, node_h = self.drag_node.size
                for z in self.board.zones:
                    if z.zone_type == "tim":
                        # Проверяем пересечение
                        if (new_x < z.x + z.width and new_x + node_w > z.x and
                                new_y < z.y + z.height and new_y + node_h > z.y):
                            # Выталкиваем узел за границу зоны
                            cx_node = new_x + node_w / 2
                            cy_node = new_y + node_h / 2
                            cx_zone = z.x + z.width / 2
                            cy_zone = z.y + z.height / 2
                            if abs(cx_node - cx_zone) > abs(cy_node - cy_zone):
                                if cx_node > cx_zone:
                                    new_x = z.x + z.width + 5
                                else:
                                    new_x = z.x - node_w - 5
                            else:
                                if cy_node > cy_zone:
                                    new_y = z.y + z.height + 5
                                else:
                                    new_y = z.y - node_h - 5

            if zone:
                new_x = max(zone.x, min(new_x, zone.x + zone.width - self.drag_node.size[0]))
                new_y = max(zone.y, min(new_y, zone.y + zone.height - self.drag_node.size[1]))
            if self.drag_node.move(new_x, new_y):
                self.clear_temp_elements()
                self.redraw()
            self.dragging = False
            self.drag_node = None

        elif self.dragging_zone and self.drag_zone:
            new_center_x = x - self.drag_zone_offset[0]
            new_center_y = y - self.drag_zone_offset[1]
            new_x = self.snap_to_grid(new_center_x - self.drag_zone.width / 2.0)
            new_y = self.snap_to_grid(new_center_y - self.drag_zone.height / 2.0)
            self.board.move_zone(self.drag_zone.id, new_x, new_y)
            self.clear_temp_elements()
            self.redraw()
            self.dragging_zone = False
            self.drag_zone = None

        elif self.resizing_zone and self.resize_zone:
            # В изолированном режиме зона уже обновлена в ходе drag —
            # здесь просто сбрасываем текущее состояние drag'а.
            self.resizing_zone = False
            self.resize_zone_corner = None
            self.resize_zone_start = None
            # Не сбрасываем self.resize_zone, если остаёмся в zone_edit_mode:
            # она ещё понадобится для следующего drag за другой уголок.
            if not self.zone_edit_mode:
                self.resize_zone = None

    def on_canvas_right_click(self, event):
        x, y = self.canvas_event_world(event)

        node = self.find_node_at(x, y)
        if node:
            self.selected_node_id = node.id
            self.redraw()
            NodeContextMenuHandler.show_menu(event, self, node)
            return

        zone = self.find_tim_zone_at(x, y)
        if zone:
            self.selected_zone_id = zone.id
            self.redraw()
            ZoneContextMenuHandler.show_menu(event, self, zone)

    def on_canvas_motion(self, event):
        x, y = self.canvas_event_world(event)

        # Изолированный режим редактирования зоны — курсор показывается
        # только над уголками редактируемой зоны
        if self.zone_edit_mode and self.zone_edit_zone is not None:
            z = self.zone_edit_zone
            corner = self.get_zone_corner_at(x, y, z)
            edge = self.get_zone_edge_at(x, y, z)
            if corner:
                self.canvas.config(cursor="sizing")
            elif edge:
                self.canvas.config(cursor="sb_v_double_arrow" if edge in ['n', 's'] else "sb_h_double_arrow")
            else:
                self.canvas.config(cursor="")
            return

        if self.mode == "creating_zone":
            self.canvas.config(cursor="cross")
            return

        if self.mode in ["create_link", "delete_link"]:
            node = self.find_node_at(x, y)
            if node:
                self.canvas.config(cursor="dot")
            else:
                self.canvas.config(cursor="")
        else:
            node = self.find_node_at(x, y)
            if node:
                self.canvas.config(cursor="fleur")
            else:
                zone = self.find_tim_zone_at(x, y)
                if zone:
                    # В обычном режиме только перемещение зон (без уголков)
                    self.canvas.config(cursor="fleur")
                else:
                    self.canvas.config(cursor="")

    def on_canvas_double_click(self, event):
        x, y = self.canvas_event_world(event)
        zone = self.find_tim_zone_at(x, y)
        if zone:
            self.edit_zone_description(zone)

    def show_temp_link_start(self, node: Node):
        x, y = node.position
        w, h = node.size
        self.clear_temp_elements()
        # Сплошная синяя обводка (промт 8 #9)
        temp_rect = self.canvas.create_rectangle(
            self.w2c(x - 2), self.w2c(y - 2),
            self.w2c(x + w + 2), self.w2c(y + h + 2),
            outline="blue", width=3)
        self.temp_elements.append(temp_rect)

    def find_node_at(self, x: float, y: float) -> Optional[Node]:
        for n in reversed(self.board.nodes):
            if n.contains_point(x, y):
                return n
        return None

    def find_tim_zone_at(self, x: float, y: float) -> Optional[Zone]:
        for z in self.board.get_tim_zones():
            if z.contains_point(x, y):
                return z
        return None

    def get_zone_corner_at(self, x: float, y: float, zone: Zone) -> Optional[str]:
        corners = {
            'nw': (zone.x, zone.y),
            'ne': (zone.x + zone.width, zone.y),
            'sw': (zone.x, zone.y + zone.height),
            'se': (zone.x + zone.width, zone.y + zone.height)
        }
        for corner_name, (cx, cy) in corners.items():
            if abs(cx - x) < 10 and abs(cy - y) < 10:
                return corner_name
        return None

    def get_zone_edge_at(self, x: float, y: float, zone: Zone) -> Optional[str]:
        tolerance = 5
        if abs(y - zone.y) < tolerance and zone.x <= x <= zone.x + zone.width:
            return 'n'
        elif abs(y - (zone.y + zone.height)) < tolerance and zone.x <= x <= zone.x + zone.width:
            return 's'
        elif abs(x - zone.x) < tolerance and zone.y <= y <= zone.y + zone.height:
            return 'w'
        elif abs(x - (zone.x + zone.width)) < tolerance and zone.y <= y <= zone.y + zone.height:
            return 'e'
        return None

    def clear_temp_elements(self):
        for element in self.temp_elements:
            self.canvas.delete(element)
        self.temp_elements.clear()

    def view_node_properties(self, node: Node):
        """Показывает диалог просмотра свойств узла (только чтение)."""
        from dialogs.properties_dialog import ViewOnlyPropertiesDialog
        ViewOnlyPropertiesDialog(self.root, node, self.board, self)

    def show_node_properties(self, node: Node):
        """Показывает диалог редактирования узла."""
        node_type_mapping = {
            "ARM": "АРМ", "Laptop": "Ноутбук", "Router": "Маршрутизатор",
            "Switch": "Коммутатор", "Server": "Сервер",
            "VirtualizationServer": "Сервер виртуализации", "Internet": "Интернет"
        }
        node_type_ru = node_type_mapping.get(node.type, "АРМ")

        dialog = NodeCreationDialog(self.root, self.board, node_type_ru, existing_node=node)
        self.root.wait_window(dialog.dialog)

        if dialog.result:
            updated_node = dialog.result
            updated_node.id = node.id
            updated_node.position = node.position

            for i, n in enumerate(self.board.nodes):
                if n.id == node.id:
                    self.board.nodes[i] = updated_node
                    break

            self.redraw()

    def show_node_security_passport(self, node: Node):
        if not self.db:
            try:
                self.db = CVEDatabase()
            except FileNotFoundError:
                messagebox.showerror("Ошибка", "База данных CVE не найдена!")
                return
        try:
            SecurityPassportDialog(self.root, node)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть паспорт: {str(e)}")

    def open_firewall(self, node: Node = None):
        import copy as _copy
        if node is None and self.selected_node_id:
            node = self.board.find_node(self.selected_node_id)
        if node:
            try:
                if "firewall" in node.properties:
                    # Передаём диалогу КОПИЮ данных, чтобы отмена не мутировала оригинал
                    firewall_data = _copy.deepcopy(node.properties["firewall"])

                    class SimpleFirewallManager:
                        def __init__(self, data):
                            self.node_id = data.get("node_id", "")
                            self.rules = []
                            self.profiles = data.get("profiles", {})
                            self.firewall_enabled = data.get("firewall_enabled", True)
                            self.notification_enabled = data.get("notification_enabled", True)
                            from models.firewall import FirewallRule
                            for rule_data in data.get("rules", []):
                                rule = FirewallRule()
                                rule.id = rule_data.get("id")
                                rule.name = rule_data.get("name", "")
                                rule.direction = rule_data.get("direction", "in")
                                rule.action = rule_data.get("action", "allow")
                                rule.protocol = rule_data.get("protocol", "any")
                                rule.local_ports = rule_data.get("local_ports", "")
                                rule.remote_ports = rule_data.get("remote_ports", "")
                                rule.local_addresses = rule_data.get("local_addresses", "any")
                                rule.remote_addresses = rule_data.get("remote_addresses", "any")
                                rule.program_path = rule_data.get("program_path", "")
                                rule.enabled = rule_data.get("enabled", True)
                                rule.description = rule_data.get("description", "")
                                self.rules.append(rule)

                        def add_rule(self, rule):
                            self.rules.append(rule)

                        def remove_rule(self, rule_id):
                            self.rules = [r for r in self.rules if r.id != rule_id]

                        def get_rule(self, rule_id):
                            for rule in self.rules:
                                if rule.id == rule_id:
                                    return rule
                            return None

                        def move_rule_up(self, rule_id):
                            for i, rule in enumerate(self.rules):
                                if rule.id == rule_id and i > 0:
                                    self.rules[i], self.rules[i - 1] = self.rules[i - 1], self.rules[i]
                                    return True
                            return False

                        def move_rule_down(self, rule_id):
                            for i, rule in enumerate(self.rules):
                                if rule.id == rule_id and i < len(self.rules) - 1:
                                    self.rules[i], self.rules[i + 1] = self.rules[i + 1], self.rules[i]
                                    return True
                            return False

                        def to_dict(self):
                            return {"node_id": self.node_id, "rules": [r.__dict__ for r in self.rules],
                                    "profiles": self.profiles, "firewall_enabled": self.firewall_enabled,
                                    "notification_enabled": self.notification_enabled}

                    firewall_manager = SimpleFirewallManager(firewall_data)
                    had_firewall = True
                else:
                    from models.firewall import FirewallManager
                    firewall_manager = FirewallManager(node.id)
                    had_firewall = False

                dialog = FirewallDialog(self.root, node, firewall_manager)
                self.root.wait_window(dialog.dialog)

                # Применяем изменения ТОЛЬКО если пользователь нажал «Сохранить».
                # Закрытие крестиком / «Отмена» — изменения отбрасываются.
                if getattr(dialog, "saved", False):
                    node.properties["firewall"] = firewall_manager.to_dict()
                    node.firewall_enabled = firewall_manager.firewall_enabled
                    self.redraw()
                elif not had_firewall:
                    # Для нового узла, если пользователь отменил — не оставляем
                    # пустой заготовки в properties.
                    node.properties.pop("firewall", None)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось открыть настройки файервола: {str(e)}")
        else:
            messagebox.showwarning("Предупреждение", "Выберите узел для настройки файервола!")

    def open_routing_table(self, node: Node = None):
        if node is None and self.selected_node_id:
            node = self.board.find_node(self.selected_node_id)
        if node:
            if not hasattr(node, 'routing_table'):
                node.routing_table = []
            dialog = RoutingTableDialog(self.root, node)
            self.root.wait_window(dialog.dialog)
            self.redraw()
        else:
            messagebox.showwarning("Предупреждение", "Выберите узел для просмотра таблицы маршрутизации!")

    def configure_vpn(self, node: Node):
        dialog = VPNConfigDialog(self.root, node, self.board)
        self.root.wait_window(dialog.dialog)
        if dialog.result:
            self.redraw()

    def open_vm_management(self, node: Node):
        if node.type == "VirtualizationServer":
            VMManagementDialog(self.root, node)
            self.redraw()

    def edit_zone_description(self, zone: Zone):
        PropertiesDialog(self.root, zone.name, zone, "Зона TIM")
        self.redraw()

    def start_zone_resize(self, zone: Zone):
        """Входит в изолированный режим редактирования размера зоны
        (промт 8 №8).

        - Отключает все управляющие кнопки слева;
        - Поверх холста появляется overlay с кнопками «Сохранить» / «Отмена»;
        - Единственное разрешённое действие — тянуть за уголки/грани зоны;
        - «Отмена» возвращает исходные размеры, «Сохранить» применяет.
        """
        self.zone_edit_mode = True
        self.zone_edit_zone = zone
        self.zone_edit_original = (zone.x, zone.y, zone.width, zone.height)
        self.selected_zone_id = zone.id

        # Блокируем все управляющие кнопки
        for btn in self._control_buttons:
            try:
                btn.configure(state="disabled")
            except Exception:
                pass

        # Overlay с кнопками Save/Cancel — поверх холста, в правом нижнем углу
        self.zone_edit_overlay = tk.Frame(
            self.canvas, bg="#ffffff", bd=1, relief=tk.SOLID
        )
        title_lbl = tk.Label(
            self.zone_edit_overlay,
            text=f"Редактирование размера зоны: {zone.get_display_text()}",
            font=("Arial", 10, "bold"),
            bg="#ffffff", fg="#333333",
        )
        title_lbl.pack(side=tk.TOP, padx=10, pady=(6, 2))

        btns_row = tk.Frame(self.zone_edit_overlay, bg="#ffffff")
        btns_row.pack(side=tk.BOTTOM, padx=10, pady=(2, 6))
        save_btn = tk.Button(
            btns_row, text="✔ Сохранить", command=self._zone_edit_save,
            bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
            padx=10, pady=3, bd=0, activebackground="#3FA043",
        )
        save_btn.pack(side=tk.LEFT, padx=4)
        cancel_btn = tk.Button(
            btns_row, text="✕ Отмена", command=self._zone_edit_cancel,
            bg="#CD3333", fg="white", font=("Arial", 10),
            padx=10, pady=3, bd=0, activebackground="#B52929",
        )
        cancel_btn.pack(side=tk.LEFT, padx=4)

        # place в правом нижнем углу, выше индикатора зума
        self.zone_edit_overlay.place(relx=1.0, rely=1.0, anchor="se", x=-6, y=-40)

        # Первая отрисовка (чтобы показать уголки редактируемой зоны)
        self.redraw()

    def _zone_edit_exit(self) -> None:
        """Выход из изолированного режима — общая очистка."""
        self.zone_edit_mode = False
        self.zone_edit_zone = None
        self.zone_edit_original = None
        self.resizing_zone = False
        self.resize_zone = None
        self.resize_zone_corner = None
        self.resize_zone_start = None

        if self.zone_edit_overlay is not None:
            try:
                self.zone_edit_overlay.destroy()
            except Exception:
                pass
            self.zone_edit_overlay = None

        # Возвращаем кнопки в рабочее состояние
        for btn in self._control_buttons:
            try:
                btn.configure(state="normal")
            except Exception:
                pass

        self.clear_temp_elements()
        self.canvas.config(cursor="")
        self.redraw()

    def _zone_edit_save(self) -> None:
        """Применить изменения и выйти из режима."""
        self._zone_edit_exit()

    def _zone_edit_cancel(self) -> None:
        """Откатить к исходным размерам и выйти из режима."""
        if self.zone_edit_zone is not None and self.zone_edit_original is not None:
            zone = self.zone_edit_zone
            ox, oy, ow, oh = self.zone_edit_original
            # Используем board.resize_zone для корректности проверок
            self.board.resize_zone(zone.id, ox, oy, ow, oh)
        self._zone_edit_exit()

    def delete_node(self, node: Node):
        if messagebox.askyesno("Удаление узла", f"Удалить узел '{node.name}'?"):
            self.board.remove_node(node.id)
            if self.selected_node_id == node.id:
                self.selected_node_id = None
            self.redraw()

    def delete_zone(self, zone: Zone):
        if messagebox.askyesno("Удаление зоны", f"Удалить зону '{zone.name}' и все узлы внутри нее?"):
            self.board.remove_zone(zone.id)
            if self.selected_zone_id == zone.id:
                self.selected_zone_id = None
            self.redraw()

    def delete_selected(self):
        if self.selected_node_id:
            node = self.board.find_node(self.selected_node_id)
            if node:
                self.delete_node(node)
        elif self.selected_zone_id:
            zone = next((z for z in self.board.zones if z.id == self.selected_zone_id), None)
            if zone:
                self.delete_zone(zone)
        else:
            messagebox.showinfo("Информация", "Сначала выберите узел или зону для удаления.")

    def clear_all(self):
        if messagebox.askyesno("Очистка всего", "Вы уверены, что хотите удалить все зоны, узлы и соединения?"):
            self.board.zones.clear()
            self.board.nodes.clear()
            self.board.links.clear()
            self.selected_node_id = None
            self.selected_zone_id = None
            self.clear_temp_elements()
            self.board.create_free_zone()
            self.redraw()

    def get_node_type_russian(self, node_type_en: str) -> str:
        return NODE_TYPE_RUSSIAN.get(node_type_en, node_type_en)

    def redraw(self):
        self.canvas.delete("all")

        z_scale = self.zoom

        # Рисуем зоны TIM (без подсветки выбранной и без уголков ресайза)
        for z in self.board.get_tim_zones():
            wx1, wy1, wx2, wy2 = z.to_canvas()
            x1, y1, x2, y2 = self.w2c(wx1), self.w2c(wy1), self.w2c(wx2), self.w2c(wy2)
            # В изолированном режиме выделяем редактируемую зону оранжевым контуром
            if (self.zone_edit_mode and self.zone_edit_zone is not None
                    and z.id == self.zone_edit_zone.id):
                self.canvas.create_rectangle(x1, y1, x2, y2, outline="#FF9800",
                                              fill="#FFF8E1", width=3)
            else:
                self.canvas.create_rectangle(x1, y1, x2, y2, outline="black",
                                              fill="#f0f0f0", width=2)

            # Названия зон в мировых размерах (пропорционально самой зоне)
            main_text = z.get_display_text()
            # Базовый размер шрифта зависит от высоты зоны (мировой),
            # далее конвертируется в экранные пиксели через зум.
            base_title = max(10, min(28, int(round(z.height * 0.05))))
            base_sub = max(8, min(20, int(round(z.height * 0.035))))
            base_desc = max(7, min(16, int(round(z.height * 0.028))))

            title_y_world = 15 + base_title / 2
            self.canvas.create_text(
                (x1 + x2) / 2, y1 + title_y_world * z_scale,
                text=main_text, fill="#333333",
                font=self.font_scaled(base_title, "bold"), anchor="center")

            if z.name:
                sub_y_world = title_y_world + base_title + 4
                self.canvas.create_text(
                    (x1 + x2) / 2, y1 + sub_y_world * z_scale,
                    text=z.name, fill="black",
                    font=self.font_scaled(base_sub), anchor="center")

            if z.description:
                if z.name:
                    desc_y_world = sub_y_world + base_sub + 4
                else:
                    desc_y_world = title_y_world + base_title + 4
                self.canvas.create_text(
                    (x1 + x2) / 2, y1 + desc_y_world * z_scale,
                    text=z.description, fill="#333333",
                    font=self.font_scaled(base_desc), anchor="center")

        # Рисуем соединения
        # Подсчитываем количество линий на каждой стороне каждого узла для разведения
        side_counts = {}  # (node_id, side) -> list of link ids
        for l in self.board.links:
            a_bounds = self.get_icon_bounds(l.a)
            b_bounds = self.get_icon_bounds(l.b)
            cx_a = a_bounds[0] + a_bounds[2] / 2
            cy_a = a_bounds[1] + a_bounds[3] / 2
            cx_b = b_bounds[0] + b_bounds[2] / 2
            cy_b = b_bounds[1] + b_bounds[3] / 2
            ddx = cx_b - cx_a
            ddy = cy_b - cy_a
            if abs(ddx) > abs(ddy):
                a_side = "right" if ddx > 0 else "left"
            else:
                a_side = "bottom" if ddy > 0 else "top"
            key_a = (l.a.id, a_side)
            side_counts.setdefault(key_a, []).append(l.id)

        for l in self.board.links:
            try:
                # Определяем индекс этой линии на стороне узла A
                a_bounds = self.get_icon_bounds(l.a)
                b_bounds = self.get_icon_bounds(l.b)
                cx_a = a_bounds[0] + a_bounds[2] / 2
                cy_a = a_bounds[1] + a_bounds[3] / 2
                cx_b = b_bounds[0] + b_bounds[2] / 2
                cy_b = b_bounds[1] + b_bounds[3] / 2
                ddx = cx_b - cx_a
                ddy = cy_b - cy_a
                if abs(ddx) > abs(ddy):
                    a_side = "right" if ddx > 0 else "left"
                else:
                    a_side = "bottom" if ddy > 0 else "top"
                key_a = (l.a.id, a_side)
                links_on_side = side_counts.get(key_a, [l.id])
                link_idx = links_on_side.index(l.id) if l.id in links_on_side else 0
                total = len(links_on_side)

                points_data = l.get_bezier_coords(self, link_idx, total)
                all_points = points_data[:-6]
                line_points = [(all_points[i], all_points[i + 1]) for i in range(0, len(all_points), 2)]

                # Единый стиль для всех соединений (без стрелок — трафик двунаправленный)
                line_color = "#4CAF50"
                line_width = max(1, int(round(2 * z_scale)))

                for i in range(len(line_points) - 1):
                    self.canvas.create_line(
                        self.w2c(line_points[i][0]), self.w2c(line_points[i][1]),
                        self.w2c(line_points[i + 1][0]), self.w2c(line_points[i + 1][1]),
                        fill=line_color, width=line_width)
            except Exception as e:
                print(f"Ошибка отрисовки соединения: {e}")

        # Рисуем узлы
        self._icon_refs = []  # сбрасываем кеш ImageTk, чтобы они пересоздавались под текущий зум
        for n in self.board.nodes:
            wx, wy = n.position
            ww, wh = n.size
            # Экранные координаты/размер = мировые × зум
            x = self.w2c(wx)
            y = self.w2c(wy)
            w = ww * z_scale
            h = wh * z_scale
            # Обводка fallback-прямоугольников без выделения selected (это убрано)
            outline_color = "black"
            outline_width = 2

            icon = self.NODE_ICONS.get(n.type)
            if icon:
                try:
                    img = icon.copy()
                    img = img.resize((max(1, int(w)), max(1, int(h))), Image.Resampling.LANCZOS)
                    icon_tk = ImageTk.PhotoImage(img)
                    self._icon_refs.append(icon_tk)
                    self.canvas.create_image(x + w / 2, y + h / 2, image=icon_tk)
                    # Красная пунктирная обводка для selected убрана по требованию (промт 8 #9).
                except Exception:
                    color = self.NODE_COLORS.get(n.type, "#999999")
                    self.canvas.create_rectangle(x, y, x + w, y + h, fill=color, outline=outline_color,
                                                 width=outline_width)
            else:
                color = self.NODE_COLORS.get(n.type, "#999999")
                self.canvas.create_rectangle(x, y, x + w, y + h, fill=color, outline=outline_color, width=outline_width)

            self.canvas.create_text(x + w / 2, y + h + 5 * z_scale, text=n.name, anchor="n", fill="black",
                                    font=self.font_scaled(9))

            # Индикаторы статуса
            led_x = x + w - 8 * z_scale
            led_y = y + 8 * z_scale
            led_radius = max(2, int(round(5 * z_scale)))

            if n.vpn_client_enabled or n.vpn_server_enabled:
                self.canvas.create_oval(led_x - led_radius, led_y - led_radius, led_x + led_radius, led_y + led_radius,
                                        fill="#4CAF50", outline="#2E7D32", width=1)
                led_x -= 14 * z_scale

            if n.firewall_enabled:
                self.canvas.create_oval(led_x - led_radius, led_y - led_radius, led_x + led_radius, led_y + led_radius,
                                        fill="#F44336", outline="#B71C1C", width=1)

        # Отрисовка уголков ресайза редактируемой зоны (изолированный режим).
        # Рисуем поверх всего остального, чтобы уголки были видны всегда.
        if self.zone_edit_mode and self.zone_edit_zone is not None:
            zone = self.zone_edit_zone
            zx1 = self.w2c(zone.x)
            zy1 = self.w2c(zone.y)
            zx2 = self.w2c(zone.x + zone.width)
            zy2 = self.w2c(zone.y + zone.height)
            handle = 6
            corners = [(zx1, zy1), (zx2, zy1), (zx1, zy2), (zx2, zy2)]
            for cx, cy in corners:
                self.canvas.create_rectangle(
                    cx - handle, cy - handle, cx + handle, cy + handle,
                    fill="#FF9800", outline="#E65100", width=2
                )

        # Намеренно НЕ вызываем canvas.update() здесь — форсированный flush
        # при каждом redraw приводил к «ghost frame» при zoom. Обновление
        # выполнит Tk сам на ближайшем idle-tick.