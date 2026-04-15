"""
Диалог паттернов атак CAPEC для узла.

Собирает CWE из CVE компонентов узла → находит связанные CAPEC.
"""

import re
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import threading
from typing import List, Dict

from models.node import Node
from database.cve_db import CVEDatabase
from database.capec_db import CAPECDatabase
from utils.cpe_utils import extract_cpe_components
from utils.theme import center_window


class CAPECDialog:
    """Окно паттернов атак CAPEC для узла."""

    def __init__(self, parent, node: Node):
        self.parent = parent
        self.node = node

        self.db = CVEDatabase()
        self.capec_db = CAPECDatabase()

        if not self.capec_db.available:
            from tkinter import messagebox
            messagebox.showerror("Ошибка", "База данных CAPEC не найдена!")
            return

        self.dialog = ctk.CTkToplevel(parent)
        self.dialog.title(f"Паттерны атак (CAPEC): {node.name}")
        self.dialog.resizable(True, True)
        self.dialog.minsize(800, 400)
        self.dialog.transient(parent)
        # НЕ grab_set — можно открывать другие окна параллельно
        # На весь экран
        self.dialog.update_idletasks()
        try:
            self.dialog.state('zoomed')
        except Exception:
            sw = self.dialog.winfo_screenwidth()
            sh = self.dialog.winfo_screenheight()
            self.dialog.geometry(f"{sw}x{sh}+0+0")

        self._show_loading()
        self.dialog.after(100, self._load_async)

    def _show_loading(self):
        self._loading_frame = ctk.CTkFrame(self.dialog)
        self._loading_frame.pack(fill=tk.BOTH, expand=True, padx=50, pady=50)
        ctk.CTkLabel(self._loading_frame, text="Анализ уязвимостей и паттернов атак...",
                      font=("Segoe UI", 16, "bold")).pack(pady=20)
        self._progress = ctk.CTkProgressBar(self._loading_frame, width=300)
        self._progress.pack(pady=10)
        self._progress.set(0.2)

    def _load_async(self):
        def _thread():
            try:
                # Собираем CWE из CVE компонентов узла
                cwe_ids = set()
                components = []

                for item in self.node.properties.get("hardware", []):
                    components.append(item)
                for item in self.node.properties.get("software", []):
                    components.append(item)

                for comp in components:
                    # Убираем префикс "Процессор: ", CPE-суффикс "||...", trailing дефисы
                    clean = comp.split(":", 1)[-1].strip() if ":" in comp else comp
                    clean = clean.split("||")[0].strip().rstrip("- ").strip()

                    # 1. Ищем в cpe_display_map
                    vendor, product, version = "", "", ""
                    try:
                        cur = self.db._connection.cursor()
                        cur.execute("SELECT vendor, product, version FROM cpe_display_map WHERE display_name = ?", (clean,))
                        row = cur.fetchone()
                        if row:
                            vendor, product, version = row[0], row[1], row[2]
                    except Exception:
                        pass

                    # 2. Fallback на парсер
                    if not vendor:
                        cpe = extract_cpe_components(clean)
                        vendor = cpe.get("vendor", "")
                        product = cpe.get("product", "")
                        version = cpe.get("version", "")

                    if not vendor:
                        continue

                    # Ищем CVE (точный поиск)
                    cves = self.db.get_cves_exact(vendor, product, version)
                    if not cves and version:
                        cves = self.db.get_cves_exact(vendor, product)

                    # Извлекаем CWE из CVE
                    for cve in cves:
                        cwe_str = cve.get("cwe_id", "")
                        if cwe_str:
                            for part in str(cwe_str).split(","):
                                m = re.search(r'(\d+)', part.strip())
                                if m:
                                    cwe_ids.add(int(m.group(1)))

                # Ищем CAPEC по CWE
                capec_data = []
                if cwe_ids:
                    capec_data = self.capec_db.get_capecs_by_cwe_ids(cwe_ids)

                def _finish():
                    try:
                        if self.dialog.winfo_exists():
                            self._loading_frame.destroy()
                            self._build_ui(capec_data, len(cwe_ids))
                    except Exception:
                        pass

                self.dialog.after(0, _finish)

            except Exception as e:
                def _err():
                    try:
                        if self.dialog.winfo_exists():
                            self._loading_frame.destroy()
                            ctk.CTkLabel(self.dialog, text=f"Ошибка: {e}",
                                          text_color="red").pack(pady=20)
                    except Exception:
                        pass
                self.dialog.after(0, _err)

        threading.Thread(target=_thread, daemon=True).start()

    def _build_ui(self, capec_data: List[Dict], cwe_count: int):
        from utils.theme import color

        main = ctk.CTkFrame(self.dialog)
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Кнопки внизу
        btn_frame = ctk.CTkFrame(main, fg_color="transparent")
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))

        ctk.CTkButton(btn_frame, text="✕ Закрыть", command=self.dialog.destroy,
                       width=110, height=38, fg_color="#F44336").pack(side=tk.RIGHT)

        # Заголовок
        title_frame = ctk.CTkFrame(main, fg_color="transparent")
        title_frame.pack(fill=tk.X, pady=(0, 15))

        ctk.CTkLabel(title_frame, text="⚔️", font=("Segoe UI", 36),
                      text_color="#E65100").pack(side=tk.LEFT, padx=(0, 10))

        header = ctk.CTkFrame(title_frame, fg_color="transparent")
        header.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ctk.CTkLabel(header, text="Паттерны атак (CAPEC)",
                      font=("Segoe UI", 22, "bold")).pack(anchor=tk.W)

        node_type_ru = {"ARM": "АРМ", "Laptop": "Ноутбук", "Router": "Маршрутизатор",
                        "Switch": "Коммутатор", "Server": "Сервер",
                        "VirtualizationServer": "Сервер виртуализации"}.get(self.node.type, self.node.type)

        ctk.CTkLabel(header, text=f"{self.node.name} • {node_type_ru} • "
                                   f"CWE: {cwe_count} • CAPEC: {len(capec_data)}",
                      font=("Segoe UI", 13), text_color="gray").pack(anchor=tk.W)

        # Таблица
        table_card = ctk.CTkFrame(main)
        table_card.pack(fill=tk.BOTH, expand=True)

        table_container = ctk.CTkFrame(table_card)
        table_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        from utils.theme import sp
        import tkinter.font as tkfont

        style = ttk.Style()
        style.configure("Capec.Treeview", background="white", foreground="black",
                        fieldbackground="white", font=('Segoe UI', 10), rowheight=sp(28))
        style.configure("Capec.Treeview.Heading", background="#d9d9d9", foreground="black",
                        font=('Segoe UI', 10, 'bold'))

        columns = ("CAPEC ID", "Название атаки", "Уровень", "Серьёзность",
                   "Вероятность", "Связанные CWE")

        tree = ttk.Treeview(table_container, columns=columns, show="headings",
                             height=20, selectmode="browse", style="Capec.Treeview")

        tree.column("CAPEC ID", width=120, minwidth=30, anchor='center')
        tree.column("Название атаки", width=350, minwidth=80, anchor='w')
        tree.column("Уровень", width=100, minwidth=30, anchor='center')
        tree.column("Серьёзность", width=110, minwidth=30, anchor='center')
        tree.column("Вероятность", width=110, minwidth=30, anchor='center')
        tree.column("Связанные CWE", width=250, minwidth=30, anchor='w')

        vsb = ttk.Scrollbar(table_container, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(table_container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        tree.tag_configure('severity_vh', background='#FFCDD2')
        tree.tag_configure('severity_h', background='#FFE0B2')
        tree.tag_configure('severity_m', background='#FFF9C4')
        tree.tag_configure('severity_l', background='#C8E6C9')
        tree.tag_configure('severity_vl', background='#E0E0E0')

        severity_tags = {
            "Very High": "severity_vh", "High": "severity_h",
            "Medium": "severity_m", "Low": "severity_l", "Very Low": "severity_vl"
        }

        # --- Сортировка по клику на заголовке ---
        _sort_state = {}
        _sort_blocked_until = [0]  # блокировка после авторесайза
        _sev_order = {"Very High": 1, "High": 2, "Medium": 3, "Low": 4, "Very Low": 5, "—": 6, "": 7}

        def _sort_col(col_name):
            import time
            if time.time() < _sort_blocked_until[0]:
                return  # заблокировано после авторесайза
            ascending = not _sort_state.get(col_name, False)
            _sort_state[col_name] = ascending
            col_idx = columns.index(col_name)
            import re as _re

            data = [(tree.item(i, "values"), tree.item(i, "tags")) for i in tree.get_children()]

            def key_fn(row):
                val = str(row[0][col_idx]) if col_idx < len(row[0]) else ""
                if col_name == "CAPEC ID":
                    m = _re.search(r'(\d+)', val)
                    return int(m.group(1)) if m else 0
                elif col_name in ("Серьёзность", "Вероятность"):
                    return _sev_order.get(val, 7)
                elif col_name == "Связанные CWE":
                    return val.count("CWE-")
                return val.lower()

            data.sort(key=key_fn, reverse=not ascending)
            tree.delete(*tree.get_children())
            for vals, tags in data:
                tree.insert("", tk.END, values=vals, tags=tags)
            for c in columns:
                arrow = " ▲" if c == col_name and ascending else " ▼" if c == col_name else ""
                tree.heading(c, text=c + arrow, command=lambda cc=c: _sort_col(cc))

        for col in columns:
            tree.heading(col, text=col, command=lambda c=col: _sort_col(c))

        # --- Авторезайз: двойной клик на границе между колонками ---
        _font = tkfont.Font(family="Segoe UI", size=10)

        def _autofit(event):
            if tree.identify_region(event.x, event.y) != "separator":
                return
            import time
            col_num = int(tree.identify_column(event.x).replace("#", ""))
            col_idx = col_num - 1
            if col_idx < 0 or col_idx >= len(columns):
                return
            col_name = columns[col_idx]
            best = _font.measure(col_name) + 24
            for item in tree.get_children():
                vals = tree.item(item, "values")
                if col_idx < len(vals):
                    w = _font.measure(str(vals[col_idx])) + 24
                    if w > best:
                        best = w
            tree.column(col_name, width=best)
            # Блокируем сортировку на 500мс чтобы второй клик не триггерил её
            _sort_blocked_until[0] = time.time() + 0.5

        tree.bind("<Double-1>", _autofit)

        # --- Заполнение данными ---
        if not capec_data:
            tree.insert("", tk.END, values=(
                "—", "Паттерны атак не найдены", "—", "—", "—", "—"))
        else:
            for entry in capec_data:
                cwe_str = ", ".join(f"CWE-{c}" for c in entry["cwe_ids"])
                tag = severity_tags.get(entry["severity"], "")
                name = entry.get("name_ru") or entry["name"]

                tree.insert("", tk.END, values=(
                    f"CAPEC-{entry['capec_id']}",
                    name,
                    entry["abstraction"],
                    entry["severity"] or "—",
                    entry["likelihood"] or "—",
                    cwe_str,
                ), tags=(tag,) if tag else ())
