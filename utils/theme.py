"""
Модуль темы интерфейса.

Содержит единую палитру акцентов и хелперы для:
- применения темы (светлая / тёмная) через CustomTkinter;
- сохранения выбранной темы в `config/theme.json`;
- получения цвета по роли, с автоматическим выбором оттенка под текущий
  режим (light / dark).

Используется:
- main.py — чтобы применить сохранённую тему при старте;
- views/canvas_view.py — для стилизации главного окна и переключателя темы;
- dialogs/* — для единообразного оформления диалогов.

Палитра вдохновлена современными flat/minimal-интерфейсами (VS Code,
Figma, Linear): мягкий синий как primary, фиолетовый как акцент,
нейтральные тона для фона и тонкие границы.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Tuple

import customtkinter as ctk


# ---------------------------------------------------------------------------
# DPI-масштабирование
# ---------------------------------------------------------------------------
# Базовое разрешение: 1920x1080 при DPI 96 (масштаб Windows 100%).
# На экранах с высоким DPI (например 3200x2000 при 200%) все пиксельные
# значения (rowheight, padx, width) нужно умножать на коэффициент.
# Шрифты НЕ масштабируем — система делает это сама через DPI.

_dpi_scale_cache = None


def get_dpi_scale() -> float:
    """Возвращает коэффициент масштабирования DPI (1.0 для 96 DPI / 1920x1080).

    Результат кешируется — вычисляется один раз при первом вызове.
    """
    global _dpi_scale_cache
    if _dpi_scale_cache is not None:
        return _dpi_scale_cache

    _dpi_scale_cache = 1.0

    if sys.platform == "win32":
        try:
            import ctypes
            hdc = ctypes.windll.user32.GetDC(0)
            dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
            ctypes.windll.user32.ReleaseDC(0, hdc)
            if dpi and dpi > 0:
                _dpi_scale_cache = dpi / 96.0
        except Exception:
            pass

    return _dpi_scale_cache


def sp(pixels: int) -> int:
    """Scaled Pixels — масштабирует пиксельное значение под DPI экрана.

    Использовать для: rowheight, padx/pady, width/height виджетов,
    минимальных размеров, отступов.
    НЕ использовать для: размеров шрифтов (система масштабирует их сама).

    Пример: sp(28) → 28 на 1080p, 56 на 3200x2000@200%
    """
    return max(1, int(round(pixels * get_dpi_scale())))


# ---------------------------------------------------------------------------
# Пути и имена
# ---------------------------------------------------------------------------

_THEME_FILE = os.path.join("config", "theme.json")

# ---------------------------------------------------------------------------
# Палитра (light, dark)
# Каждая запись — кортеж (светлый_оттенок, тёмный_оттенок). CustomTkinter
# умеет принимать такие кортежи напрямую в fg_color/text_color и сам
# выбирает оттенок под текущий appearance_mode.
# ---------------------------------------------------------------------------

_COLORS: dict = {
    # --- Акценты ---
    "primary":       ("#2563EB", "#3B82F6"),   # синий — основные действия
    "primary_hover": ("#1D4ED8", "#2563EB"),
    "accent":        ("#7C3AED", "#8B5CF6"),   # фиолетовый — выделение
    "accent_hover":  ("#6D28D9", "#7C3AED"),
    "success":       ("#16A34A", "#22C55E"),
    "success_hover": ("#15803D", "#16A34A"),
    "danger":        ("#DC2626", "#EF4444"),
    "danger_hover":  ("#B91C1C", "#DC2626"),
    "warning":       ("#D97706", "#F59E0B"),
    "warning_hover": ("#B45309", "#D97706"),
    "info":          ("#0891B2", "#06B6D4"),

    # --- Структура (основана на палитре референсов промт-стиль2) ---
    "window_bg":     ("#F3F4F6", "#0B1120"),   # фон окна
    "sidebar_bg":    ("#F8F9FB", "#0F172A"),   # левая панель (тёмно-синяя)
    "canvas_bg":     ("#FFFFFF", "#131A2B"),   # холст
    "card_bg":       ("#FFFFFF", "#1E293B"),   # карточки / модалки
    "card_border":   ("#E2E8F0", "#2D3A4E"),  # рамка карточки
    "card_selected": ("#DBEAFE", "#1E3A5F"),  # фон выбранной карточки
    "card_sel_brd":  ("#2563EB", "#3B82F6"),  # обводка выбранной карточки
    "dialog_bg":     ("#F9FAFB", "#131A2B"),  # фон диалоговых окон
    "surface":       ("#F1F5F9", "#111827"),  # подфон секций
    "surface_alt":   ("#EBF4FF", "#1A2332"),  # альтернативный подфон (зоны)
    "input_bg":      ("#FFFFFF", "#1E293B"),  # фон полей ввода
    "input_border":  ("#D1D5DB", "#374151"),  # рамка полей ввода
    "divider":       ("#D1D5DB", "#2D3A4E"),  # разделители
    "tab_active":    ("#2563EB", "#3B82F6"),  # активная вкладка
    "tab_inactive":  ("#E5E7EB", "#1F2937"),  # неактивная вкладка

    # --- Текст ---
    "text_primary":   ("#111827", "#E2E8F0"),
    "text_secondary": ("#4B5563", "#94A3B8"),
    "text_muted":     ("#9CA3AF", "#64748B"),
    "text_on_primary": ("#FFFFFF", "#FFFFFF"), # текст на primary-кнопках

    # --- «Призрачные» кнопки (ghost) ---
    "ghost_bg":       ("#F3F4F6", "#1A2332"),
    "ghost_hover":    ("#E5E7EB", "#2D3A4E"),
}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_theme() -> str:
    """Возвращает сохранённую тему или 'dark' по умолчанию.

    Dark — дефолтная тема по референсам промт-стиль2.
    """
    try:
        if os.path.exists(_THEME_FILE):
            with open(_THEME_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                theme = data.get("theme", "dark")
                if theme in ("light", "dark"):
                    return theme
    except Exception:
        pass
    return "dark"


def save_theme(theme_name: str) -> None:
    """Сохраняет выбор темы в config/theme.json."""
    try:
        os.makedirs(os.path.dirname(_THEME_FILE), exist_ok=True)
        with open(_THEME_FILE, "w", encoding="utf-8") as f:
            json.dump({"theme": theme_name}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Применение темы
# ---------------------------------------------------------------------------

def apply_theme(theme_name: str) -> None:
    """Применяет тему к CustomTkinter и сохраняет выбор."""
    if theme_name not in ("light", "dark"):
        theme_name = "light"
    ctk.set_appearance_mode(theme_name)
    save_theme(theme_name)


def current_mode() -> str:
    """Возвращает текущий режим 'light' или 'dark' (в нижнем регистре)."""
    return ctk.get_appearance_mode().lower()


# ---------------------------------------------------------------------------
# Доступ к цветам
# ---------------------------------------------------------------------------

def color(role: str) -> Tuple[str, str]:
    """Возвращает кортеж (light, dark) цвета для указанной роли.

    Этот кортеж можно передавать прямо в CTk-виджеты (fg_color, text_color,
    border_color) — CTk сам выберет оттенок под текущий appearance_mode.
    """
    return _COLORS.get(role, ("#111827", "#F1F5F9"))


def c(role: str) -> str:
    """Возвращает один цвет под текущий режим (удобно для tk.Canvas и
    обычных tk-виджетов, которые не понимают кортежей)."""
    light, dark = color(role)
    return dark if current_mode() == "dark" else light


# ---------------------------------------------------------------------------
# Хелпер для загрузки иконок из resources/icons/
# ---------------------------------------------------------------------------

_ICONS_DIR = os.path.join("resources", "icons")


def load_icon(name: str, size: Tuple[int, int] = (20, 20)):
    """Загружает иконку из `resources/icons/{name}` и возвращает CTkImage.

    Если файл не найден — возвращает None (код должен обработать
    этот случай, например, показав текстовую заглушку).

    Args:
        name: имя файла иконки (e.g. "sidebar_add.png")
        size: (width, height) в пикселях

    Returns:
        CTkImage или None
    """
    path = os.path.join(_ICONS_DIR, name)
    if not os.path.exists(path):
        return None
    try:
        from PIL import Image as _PILImage
        img = _PILImage.open(path)
        return ctk.CTkImage(light_image=img, dark_image=img, size=size)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Утилита для стилизации диалоговых окон (общий фон + центрирование)
# ---------------------------------------------------------------------------

def center_window(window, width: int, height: int) -> None:
    """Центрирует окно по центру экрана. Работает на любом разрешении.

    CustomTkinter при window_scaling > 1 умножает координаты из geometry()
    на коэффициент масштабирования, поэтому передаваемые x/y нужно
    предварительно разделить на этот коэффициент.
    """
    window.update_idletasks()
    screen_w = window.winfo_screenwidth()
    screen_h = window.winfo_screenheight()

    # CTk scaling: geometry() координаты умножаются на window_scaling
    try:
        scale = ctk.ScalingTracker.get_window_scaling(window)
    except Exception:
        scale = 1.0

    # width/height — логические; CTk умножает их на scale → реальный размер
    real_w = width * scale
    real_h = height * scale
    x = int((screen_w - real_w) / 2 / scale)
    y = int((screen_h - real_h) / 2 / scale)
    window.geometry(f"{width}x{height}+{x}+{y}")


def style_dialog(dialog, width: int = 500, height: int = 400) -> None:
    """Применяет единый стиль к CTkToplevel-диалогу:
    - фон dialog_bg
    - центрирование относительно родителя или экрана
    """
    dialog.configure(fg_color=color("dialog_bg"))
    center_window(dialog, width, height)
