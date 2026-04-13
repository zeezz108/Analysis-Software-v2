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
        font=("Segoe UI", 60, "bold"), text_color="#e0e0e0",
        wraplength=screen_w - 40, justify="center"
    ).pack(pady=(400, 400))

    # Процент загрузки вместо описательного статуса
    status_label = ctk.CTkLabel(
        splash, text="0%",
        font=("Segoe UI", 20, "bold"), text_color="#ffffff"
    )
    status_label.pack(pady=(0, 10))

    # Прогресс-бар — Canvas-based, чтобы можно было добавить «живой» блик,
    # бегущий по заполненной части (промт 9 №5). CTkProgressBar такую
    # анимацию поверх реального значения не поддерживает.
    progress_w = 800
    progress_h = 20
    shine_w = 140
    splash_bg = "#1a1a2e"
    track_color = "#2a2a44"
    fill_color = "#42A5F5"
    shine_color = "#BBDEFB"

    progress_canvas = tk.Canvas(
        splash, width=progress_w, height=progress_h,
        highlightthickness=0, bg=splash_bg, bd=0
    )
    progress_canvas.pack(pady=(0, 20))

    progress_state = {"value": 0.0, "shine_x": -shine_w}

    # Статичные элементы (фон-«дорожка», заполнение, блик)
    progress_canvas.create_rectangle(
        0, 0, progress_w, progress_h, fill=track_color, outline="", tags=("track",)
    )
    progress_canvas.create_rectangle(
        0, 0, 0, progress_h, fill=fill_color, outline="", tags=("fill",)
    )
    progress_canvas.create_rectangle(
        -shine_w, 0, 0, progress_h, fill=shine_color, outline="", tags=("shine",)
    )

    def update_status(value):
        """Обновляет прогресс: показывает только проценты, без текста."""
        try:
            pct_value = max(0.0, min(1.0, float(value)))
            progress_state["value"] = pct_value
            pct = int(round(pct_value * 100))
            status_label.configure(text=f"{pct}%")
            fill_px = int(progress_w * pct_value)
            progress_canvas.coords("fill", 0, 0, fill_px, progress_h)
        except Exception:
            pass

    def animate_shine():
        """«Живой» блик, бегущий по заполненной части прогресс-бара.

        Двигается слева направо, обрезается под текущую ширину заполнения.
        Когда уходит за правый край — появляется снова слева. Пока
        значение прогресса 0, блик полностью скрыт.
        """
        try:
            if not splash.winfo_exists():
                return
        except Exception:
            return
        fill_px = int(progress_w * progress_state["value"])
        if fill_px <= 0:
            progress_canvas.coords("shine", -shine_w, 0, -shine_w, progress_h)
        else:
            progress_state["shine_x"] += 4
            if progress_state["shine_x"] > fill_px:
                progress_state["shine_x"] = -shine_w
            left = max(0, progress_state["shine_x"])
            right = min(fill_px, progress_state["shine_x"] + shine_w)
            if right > left:
                progress_canvas.coords("shine", left, 0, right, progress_h)
            else:
                progress_canvas.coords("shine", -shine_w, 0, -shine_w, progress_h)
        try:
            splash.after(20, animate_shine)
        except Exception:
            pass

    # Запускаем анимацию блика
    splash.after(20, animate_shine)

    # Python 3.13: splash.after() из фонового потока вызывает
    # RuntimeError: main thread is not in main loop.
    # Решение: фоновый поток пишет в queue, главный поток читает через poll.
    import queue as _queue
    _q = _queue.Queue()

    def load_databases():
        try:
            from utils.cache import DataCache
            from config.node_config import NODE_CONFIG

            cache = DataCache()

            if cache.is_loaded():
                _q.put(("progress", 1.0))
                _q.put(("done",))
                return

            _q.put(("progress", 0.05))
            from database.cve_db import CVEDatabase
            db = CVEDatabase()

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
                _q.put(("progress", (i + 1) / max(total, 1) * 0.85 + 0.1))
                cache.get(cache_key, method)

            _q.put(("progress", 0.92))
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
            _q.put(("progress", 1.0))
            _q.put(("done",))

        except Exception:
            _q.put(("progress", 1.0))
            _q.put(("done",))

    def _poll_queue():
        """Читает сообщения из очереди в главном потоке — thread-safe."""
        try:
            while True:
                msg = _q.get_nowait()
                if msg[0] == "done":
                    splash.after(400, lambda: on_complete(splash))
                    return
                elif msg[0] == "progress":
                    update_status(msg[1])
        except _queue.Empty:
            pass
        try:
            if splash.winfo_exists():
                splash.after(50, _poll_queue)
        except Exception:
            pass

    thread = threading.Thread(target=load_databases, daemon=True)
    thread.start()
    splash.after(50, _poll_queue)

    return splash


def main():
    """
    Главная функция запуска приложения
    """
    # Настройка темы CustomTkinter (загружаем сохранённую — промт 9 №7)
    from utils.theme import apply_theme, load_theme
    ctk.set_default_color_theme("dark-blue")
    apply_theme(load_theme())

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
            # Останавливаем все after-колбеки перед destroy,
            # чтобы Python 3.13 не падал на deletecommand
            splash.after_cancel("all")
        except Exception:
            pass
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

    # Защита от бага Python 3.13 при закрытии: перехватываем ошибки destroy
    def _on_closing():
        try:
            root.after_cancel("all")
        except Exception:
            pass
        try:
            root.destroy()
        except Exception:
            pass

    root.protocol("WM_DELETE_WINDOW", _on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
