"""
Главный модуль приложения "Автоматизированная система построения цифровых карт безопасности"
Точка входа в программу
"""

import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
import threading
import os
import sys


APP_TITLE = ("Автоматизированная система "
             "\nпостроения цифровых карт безопасности")


def show_splash_and_load(on_complete):
    """
    Показывает стартовый экран загрузки (оконный режим, по центру экрана)
    и предзагружает все базы данных.

    Args:
        on_complete: Callback, вызываемый после завершения загрузки.
                     Получает splash_window как аргумент.
    """
    splash = ctk.CTkToplevel()
    splash.title(APP_TITLE)
    splash.resizable(False, False)

    # Оконный режим — небольшое окно по центру экрана
    splash_w, splash_h = 600, 400
    screen_w = splash.winfo_screenwidth()
    screen_h = splash.winfo_screenheight()
    pos_x = (screen_w - splash_w) // 2
    pos_y = (screen_h - splash_h) // 2
    # splash.geometry(f"{splash_w}x{splash_h}+{pos_x}+{pos_y}")
    splash.state("zoomed")
    splash.configure(fg_color="#1a1a2e")

    # Название программы (единственная надпись сверху)
    ctk.CTkLabel(
        splash, text=APP_TITLE,
        font=("Arial", 60, "bold"), text_color="#e0e0e0",
        wraplength=screen_w - 40, justify="center"
    ).pack(pady=(400, 400))

    # Процент загрузки вместо описательного статуса
    status_label = ctk.CTkLabel(
        splash, text="0%",
        font=("Arial", 20, "bold"), text_color="#ffffff"
    )
    status_label.pack(pady=(0, 10))

    # Прогресс-бар
    progress = ctk.CTkProgressBar(splash, width=800, height=20, corner_radius=10)
    progress.pack(pady=(0, 20))
    progress.set(0)

    def update_status(value):
        """Обновляет прогресс: показывает только проценты, без текста."""
        try:
            pct = max(0, min(100, int(round(value * 100))))
            status_label.configure(text=f"{pct}%")
            progress.set(value)
        except Exception:
            pass

    def load_databases():
        try:
            from utils.cache import DataCache
            from config.node_config import NODE_CONFIG

            cache = DataCache()

            if cache.is_loaded():
                splash.after(0, lambda: update_status(1.0))
                splash.after(300, lambda: on_complete(splash))
                return

            # Подключаемся к базам данных
            splash.after(0, lambda: update_status(0.05))
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
                            all_tasks.append((cache_key, method))

            total = len(all_tasks)
            for i, (cache_key, method) in enumerate(all_tasks):
                splash.after(0, lambda v=(i + 1) / max(total, 1) * 0.85:
                             update_status(v + 0.1))
                cache.get(cache_key, method)

            # Загружаем базы мышей и клавиатур
            splash.after(0, lambda: update_status(0.92))
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
            splash.after(0, lambda: update_status(1.0))
            splash.after(400, lambda: on_complete(splash))

        except Exception as e:
            splash.after(0, lambda: update_status(1.0))
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

    # Применяем пользовательский масштаб (если ранее сохранён)
    from utils.scaling import apply_scaling
    apply_scaling()

    # Создаем главное окно (скрытое до завершения загрузки)
    root = ctk.CTk()
    root.title(APP_TITLE)
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
