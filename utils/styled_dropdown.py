"""
Кастомный выпадающий список в стиле приложения.

Заменяет CTkComboBox — красивый дропдаун, который:
- выпадает из строки ввода вниз
- скроллится колёсиком мыши
- фильтруется по вводу
- стилизован под тему приложения
"""

import tkinter as tk
import customtkinter as ctk
from utils.theme import color


class StyledDropdown(ctk.CTkFrame):
    """Поле ввода с кастомным выпадающим списком."""

    def __init__(self, parent, values=None, variable=None, placeholder="",
                 on_select=None, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)

        self._values = values or []
        self._variable = variable or tk.StringVar()
        self._on_select = on_select
        self._popup = None

        # Поле ввода + кнопка
        self._entry = ctk.CTkEntry(
            self, textvariable=self._variable,
            placeholder_text=placeholder,
            fg_color=color("input_bg"),
            border_color=color("input_border"),
            border_width=1,
        )
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._btn = ctk.CTkButton(
            self, text="▾", width=32, height=28,
            fg_color=color("input_bg"),
            hover_color=color("ghost_hover"),
            text_color=color("text_primary"),
            border_width=1,
            border_color=color("input_border"),
            corner_radius=4,
            command=self._toggle_popup,
        )
        self._btn.pack(side=tk.RIGHT, padx=(2, 0))

        # Открытие по клику на entry — показываем все варианты
        self._entry.bind("<Button-1>", lambda e: self._show_popup(show_all=True))
        # Фильтрация по вводу
        self._variable.trace("w", self._on_typing)

    def configure(self, **kwargs):
        if "values" in kwargs:
            self._values = kwargs.pop("values")
            # Если popup открыт — обновить
            if self._popup and self._popup.winfo_exists():
                self._fill_popup(self._values)
        super().configure(**kwargs)

    def set(self, value):
        self._variable.set(value)

    def get(self):
        return self._variable.get()

    def _toggle_popup(self):
        if self._popup and self._popup.winfo_exists():
            self._close_popup()
        else:
            self._show_popup(show_all=True)

    def _show_popup(self, show_all=False):
        if self._popup and self._popup.winfo_exists():
            return
        if not self._values:
            return

        self._popup = tk.Toplevel(self)
        self._popup.withdraw()
        self._popup.overrideredirect(True)

        # Позиция — под полем ввода
        self.update_idletasks()
        x = self._entry.winfo_rootx()
        y = self._entry.winfo_rooty() + self._entry.winfo_height() + 2
        w = self._entry.winfo_width() + self._btn.winfo_width() + 2

        # Высота: min 4 элемента, max 10
        # Popup — нативный Toplevel (не CTk), DPI не масштабирует его geometry,
        # но элементы внутри рисуются в реальных пикселях.
        # Используем winfo_fpixels для корректного расчёта.
        try:
            dpi_scale = self.winfo_fpixels('1i') / 72.0
        except Exception:
            dpi_scale = 1.0
        max_items = 10
        item_h = int(28 * dpi_scale)
        visible = max(4, min(len(self._values), max_items))
        h = visible * item_h + 8

        self._popup.geometry(f"{w}x{h}+{x}+{y}")

        # Фон
        popup_bg = color("card_bg")
        if isinstance(popup_bg, tuple):
            mode = ctk.get_appearance_mode()
            popup_bg = popup_bg[1] if mode == "Dark" else popup_bg[0]

        self._popup.configure(bg=popup_bg)

        # Рамка
        border = tk.Frame(self._popup, bg=popup_bg, highlightthickness=1,
                          highlightbackground=self._resolve_color(color("card_border")))
        border.pack(fill=tk.BOTH, expand=True)

        # Canvas + Scrollbar для прокрутки
        self._canvas = tk.Canvas(border, bg=popup_bg, highlightthickness=0, bd=0)
        self._scrollbar = tk.Scrollbar(border, orient="vertical", command=self._canvas.yview)
        self._inner = tk.Frame(self._canvas, bg=popup_bg)

        self._inner.bind("<Configure>",
                         lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0, 0), window=self._inner, anchor="nw",
                                    width=w - 18)
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Прокрутка колёсиком
        def _on_mousewheel(event):
            self._canvas.yview_scroll(-1 * (event.delta // 120), "units")

        self._canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self._popup.bind("<Destroy>",
                         lambda e: self._canvas.unbind_all("<MouseWheel>") if self._canvas else None)

        # Заполнение — при клике показываем все, при вводе фильтруем
        if show_all:
            self._fill_popup(self._values)
        else:
            search = self._variable.get().strip().lower()
            if search:
                filtered = [v for v in self._values if search in v.lower()]
            else:
                filtered = self._values
            self._fill_popup(filtered)

        self._popup.deiconify()
        self._popup.lift()

        # Закрытие при клике вне popup
        self._popup.bind("<FocusOut>", lambda e: self.after(100, self._check_focus))
        self._popup.focus_set()

    def _fill_popup(self, items):
        """Заполняет popup элементами."""
        if not hasattr(self, '_inner') or not self._inner.winfo_exists():
            return

        for w in self._inner.winfo_children():
            w.destroy()

        bg = self._resolve_color(color("card_bg"))
        fg = self._resolve_color(color("text_primary"))
        hover_bg = self._resolve_color(color("card_selected"))

        for item in items:
            lbl = tk.Label(self._inner, text=item, anchor="w",
                           bg=bg, fg=fg, font=("Segoe UI", 12),
                           padx=12, pady=6, cursor="hand2")
            lbl.pack(fill=tk.X)

            lbl.bind("<Enter>", lambda e, l=lbl: l.configure(bg=hover_bg))
            lbl.bind("<Leave>", lambda e, l=lbl: l.configure(bg=bg))
            lbl.bind("<Button-1>", lambda e, v=item: self._select_item(v))

    def _select_item(self, value):
        self._variable.set(value)
        self._close_popup()
        # Возвращаем фокус на entry чтобы не нужно было кликать повторно
        self._entry.focus_set()
        if self._on_select:
            self._on_select(value)

    def _close_popup(self):
        if self._popup and self._popup.winfo_exists():
            try:
                self._canvas.unbind_all("<MouseWheel>")
            except Exception:
                pass
            self._popup.destroy()
        self._popup = None

    def _check_focus(self):
        """Закрывает popup если фокус ушёл."""
        try:
            focused = self.focus_get()
            if self._popup and self._popup.winfo_exists():
                if focused and (focused == self._popup or
                                str(focused).startswith(str(self._popup))):
                    return
                # Не закрываем если фокус на нашем entry
                if focused == self._entry:
                    return
                self._close_popup()
        except Exception:
            self._close_popup()

    def _on_typing(self, *_):
        """Фильтрация при вводе текста."""
        if not self._popup or not self._popup.winfo_exists():
            if self._values and self._variable.get().strip():
                self._show_popup()
            return

        search = self._variable.get().strip().lower()
        if search:
            filtered = [v for v in self._values if search in v.lower()]
        else:
            filtered = self._values
        self._fill_popup(filtered)

    @staticmethod
    def _resolve_color(c):
        """Резолвит tuple-цвет темы в строку."""
        if isinstance(c, tuple):
            mode = ctk.get_appearance_mode()
            return c[1] if mode == "Dark" else c[0]
        return c
