"""
Главный модуль приложения "Редактор топологии сети"
Точка входа в программу
"""

import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
import threading
import os
import sys


def show_splash_and_load(on_complete):
    """
    Показывает стартовый экран загрузки и предзагружает все базы данных.

    Args:
        on_complete: Callback, вызываемый после завершения загрузки.
                     Получает splash_window как аргумент.
    """
    splash = ctk.CTkToplevel()
    splash.title("")
    splash.overrideredirect(True)

    # Fullscreen splash
    screen_w = splash.winfo_screenwidth()
    screen_h = splash.winfo_screenheight()
    splash.geometry(f"{screen_w}x{screen_h}+0+0")
    splash.configure(fg_color="#1a1a2e")

    # Название программы
    ctk.CTkLabel(
        splash, text="Редактор топологии сети",
        font=("Arial", 22, "bold"), text_color="#e0e0e0"
    ).pack(pady=(50, 5))

    ctk.CTkLabel(
        splash, text="Analysis Software v2",
        font=("Arial", 13), text_color="#888888"
    ).pack(pady=(0, 30))

    # Статус загрузки
    status_label = ctk.CTkLabel(
        splash, text="Инициализация...",
        font=("Arial", 11), text_color="#aaaaaa"
    )
    status_label.pack(pady=(0, 10))

    # Прогресс-бар
    progress = ctk.CTkProgressBar(splash, width=350, height=8, corner_radius=4)
    progress.pack(pady=(0, 20))
    progress.set(0)

    def update_status(text, value):
        try:
            status_label.configure(text=text)
            progress.set(value)
        except Exception:
            pass

    def load_databases():
        try:
            from utils.cache import DataCache
            from config.node_config import NODE_CONFIG

            cache = DataCache()

            if cache.is_loaded():
                splash.after(0, lambda: update_status("Кеш уже загружен", 1.0))
                splash.after(300, lambda: on_complete(splash))
                return

            # Подключаемся к базам данных
            splash.after(0, lambda: update_status("Подключение к базе CVE...", 0.05))
            from database.cve_db import CVEDatabase
            db = CVEDatabase()

            # Собираем все уникальные методы из конфига
            all_tasks = []
            for node_type, config in NODE_CONFIG.items():
                for tab_group in ("hardware_tabs", "software_tabs", "hypervisor_tabs", "peripheral_tabs"):
                    for tab_config in config.get(tab_group, []):
                        cache_key = f"{node_type}_{tab_config['var_name']}"
                        method_name = tab_config["method"]
                        method = getattr(db, method_name, None)
                        if method and not cache.has_key(cache_key):
                            all_tasks.append((cache_key, method, f"{config['name']}: {tab_config['title']}"))

            total = len(all_tasks)
            for i, (cache_key, method, desc) in enumerate(all_tasks):
                splash.after(0, lambda d=desc, v=(i + 1) / max(total, 1) * 0.85:
                             update_status(f"Загрузка: {d}", v + 0.1))
                cache.get(cache_key, method)

            # Загружаем базы мышей и клавиатур
            splash.after(0, lambda: update_status("Загрузка: периферия...", 0.92))
            try:
                from database.keyboards_db import KeyboardsDatabase
                KeyboardsDatabase()
            except Exception:
                pass
            try:
                from database.mice_db import MiceDatabase
                MiceDatabase()
            except Exception:
                pass

            cache.set_loaded()
            splash.after(0, lambda: update_status("Готово!", 1.0))
            splash.after(400, lambda: on_complete(splash))

        except Exception as e:
            splash.after(0, lambda: update_status(f"Ошибка: {e}", 1.0))
            splash.after(2000, lambda: on_complete(splash))

    thread = threading.Thread(target=load_databases, daemon=True)
    thread.start()

    return splash


def main():
    """
    Главная функция запуска приложения
    """
    # Настройка темы CustomTkinter
    ctk.set_appearance_mode("light")
    ctk.set_default_color_theme("dark-blue")

    # Создаем главное окно (скрытое до завершения загрузки)
    root = ctk.CTk()
    root.title("Редактор топологии сети")
    root.minsize(800, 600)
    root.withdraw()  # Скрываем пока идёт загрузка

    def on_loading_complete(splash):
        """Вызывается когда загрузка завершена."""
        try:
            splash.destroy()
        except Exception:
            pass

        root.deiconify()
        # Отложенный zoomed — обход бага CustomTkinter
        root.after(50, lambda: root.state('zoomed'))

        from views.canvas_view import CanvasView
        from models.zone import Board

        board = Board()

        try:
            view = CanvasView(root, board)
            view.redraw()
        except FileNotFoundError as e:
            messagebox.showerror(
                "Критическая ошибка",
                f"Не найден необходимый файл:\n{str(e)}\n\n"
                "Убедитесь, что:\n"
                "1. Все необходимые файлы иконок присутствуют в папке resources/\n"
                "2. База данных CVE создана (cve_database.db)\n"
                "3. Базы данных mice.db и keyboards.db находятся в папке database/"
            )
            sys.exit(1)
        except Exception as e:
            messagebox.showerror(
                "Критическая ошибка",
                f"Программа не может быть запущена:\n{str(e)}\n\n"
                "Пожалуйста, проверьте целостность файлов проекта."
            )
            sys.exit(1)

    # Показываем splash screen и начинаем загрузку
    root.after(100, lambda: show_splash_and_load(on_loading_complete))

    root.mainloop()


if __name__ == "__main__":
    main()
