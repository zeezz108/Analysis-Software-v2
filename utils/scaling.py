"""
Утилита ручного масштабирования интерфейса.

CustomTkinter автоматически обрабатывает DPI.
Этот модуль предоставляет функционал ручного выбора масштаба пользователем.
"""

import json
import os
import customtkinter as ctk

# Путь к файлу настроек масштабирования
_SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "scaling.json")

# Доступные уровни масштабирования
SCALE_OPTIONS = {
    "75%": 0.75,
    "80%": 0.80,
    "90%": 0.90,
    "100%": 1.0,
    "110%": 1.1,
    "125%": 1.25,
    "150%": 1.5,
    "175%": 1.75,
    "200%": 2.0,
}

DEFAULT_SCALE = "100%"


def load_user_scale() -> str:
    """Загружает сохранённый пользователем масштаб."""
    try:
        if os.path.exists(_SETTINGS_FILE):
            with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("scale", DEFAULT_SCALE)
    except Exception:
        pass
    return DEFAULT_SCALE


def save_user_scale(scale_label: str):
    """Сохраняет выбранный масштаб."""
    try:
        os.makedirs(os.path.dirname(_SETTINGS_FILE), exist_ok=True)
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump({"scale": scale_label}, f)
    except Exception:
        pass


def apply_scaling(scale_label: str = None):
    """
    Применяет масштабирование к CustomTkinter.

    Args:
        scale_label: Метка масштаба (например, "125%"). Если None — загружает из настроек.
    """
    if scale_label is None:
        scale_label = load_user_scale()

    factor = SCALE_OPTIONS.get(scale_label, 1.0)

    if factor != 1.0:
        ctk.set_widget_scaling(factor)
        ctk.set_window_scaling(factor)
    else:
        # Сброс к масштабированию по умолчанию
        ctk.set_widget_scaling(1.0)
        ctk.set_window_scaling(1.0)
