"""
Модуль визуализации разложения узла по уровням ЭМВОС.

Этап 1.0: Один узел — пустой прямоугольник с названием.
"""

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk

from models.osi_decomposition import (
    NodeDecomposition, TopologyDecomposition,
    OSILevel, LEVEL_NAMES,
)
from models.zone import Board
from models.node import Node


class OSIDecompositionView:
    """Окно визуализации разложения узла по ЭМВОС."""

    def __init__(self, parent, board: Board):
        self.parent = parent
        self.board = board
        self.topology = TopologyDecomposition(board)

        # Все узлы топологии (этап 2 — все узлы)
        self.target_node = None  # для совместимости с header

        self.window = ctk.CTkToplevel(parent)
        self.window.title("Схема разложения по ЭМВОС")
        self.window.transient(parent)
        # Разворачиваем на весь экран — сразу, без after
        self.window.update_idletasks()
        try:
            self.window.state('zoomed')
        except Exception:
            sw = self.window.winfo_screenwidth()
            sh = self.window.winfo_screenheight()
            self.window.geometry(f"{sw}x{sh}+0+0")

        from utils.theme import color
        self.window.configure(fg_color=color("dialog_bg"))

        # Защита от бага Python 3.13 при закрытии CTkToplevel
        self.window.protocol("WM_DELETE_WINDOW", self._safe_close)

        self._create_ui()
        self._draw()

    def _draw_chi_connections(self, margin, total_width):
        """Рисует маршруты уязвимостей (χ) между узлами.

        Линии идут вертикально в зазоре между узлами — от нижнего края
        одного узла к верхнему краю другого, с подписями χ.
        """
        z = self._z
        chi_color = "#F59E0B"   # жёлтый/янтарный
        chi_label_color = "#FCD34D"

        path_counter = 0
        drawn_pairs = set()  # чтобы не дублировать линии для A↔B

        for path in self.topology.vulnerability_paths:
            src = self._node_positions.get(path.source_node_id)
            dst = self._node_positions.get(path.target_node_id)
            if not src or not dst:
                continue

            # Не дублируем: рисуем только одну линию на пару
            pair_key = tuple(sorted([path.source_node_id, path.target_node_id]))
            if pair_key in drawn_pairs:
                continue
            drawn_pairs.add(pair_key)

            # Определяем верхний и нижний узел
            if src["y1"] < dst["y1"]:
                top, bottom = src, dst
            else:
                top, bottom = dst, src

            # Точки подключения: низ верхнего узла → верх нижнего
            # Смещаем каждую линию по X чтобы не наложились
            x_offset = z(40) + path_counter * z(25)
            from_x = top["x1"] + x_offset
            from_y = top["y2"]
            to_x = bottom["x1"] + x_offset
            to_y = bottom["y1"]

            # Вертикальная линия с точками на концах
            self.canvas.create_oval(
                from_x - z(4), from_y - z(4),
                from_x + z(4), from_y + z(4),
                fill=chi_color, outline=chi_color
            )
            self.canvas.create_line(
                from_x, from_y, to_x, to_y,
                fill=chi_color, width=2,
                arrow=tk.BOTH, arrowshape=(8, 10, 4)
            )
            self.canvas.create_oval(
                to_x - z(4), to_y - z(4),
                to_x + z(4), to_y + z(4),
                fill=chi_color, outline=chi_color
            )

            # Подпись χ
            mid_y = (from_y + to_y) / 2
            self.canvas.create_text(
                from_x - z(14), mid_y,
                text=path.path_id, fill=chi_label_color,
                font=("Segoe UI", self._font_z(9), "bold"), angle=90
            )

            # Имена узлов на концах
            self.canvas.create_text(
                from_x + z(14), from_y + z(8),
                text=top["node"].name, fill=chi_label_color,
                font=("Segoe UI", self._font_z(7)), anchor="w"
            )
            self.canvas.create_text(
                to_x + z(14), to_y - z(8),
                text=bottom["node"].name, fill=chi_label_color,
                font=("Segoe UI", self._font_z(7)), anchor="w"
            )

            path_counter += 1

    def _draw_extra_level_connections(self, col_centers, row_positions,
                                       row_x1, row_x2):
        """Рисует вертикальные связи между строками и столбцами ЭМВОС.

        - Ядро ОС ↔ Аппаратный (драйверы управляют оборудованием)
        - Физический уровень ЭМВОС ↔ Аппаратный (порты — это физические разъёмы)
        - Ядро ОС ↔ стек ЭМВОС (IP стек, TCP/UDP реализованы в ядре)
        - Пользовательский ↔ Прикладной уровень ЭМВОС
        """
        # Цвета связей
        KERN_COLOR = self._p("conn_kern")
        HW_COLOR = self._p("conn_hw")
        USER_COLOR = self._p("conn_user")
        LABEL_COLOR = self._p("conn_label")
        z = self._z

        kern_pos = row_positions.get(OSILevel.KERNEL)
        hw_pos = row_positions.get(OSILevel.HARDWARE)
        user_pos = row_positions.get(OSILevel.USER)

        # Связи идут СЛЕВА от столбцов ЭМВОС — Г-образный маршрут:
        #   от левого края блока-источника → горизонтально к вертикальной трассе
        #   → вниз по трассе → горизонтально к левому краю блока-цели.
        # Каждая связь — на своей трассе (с шагом trace_gap), чтобы не наложились.

        trace_base = row_x1 - z(15)  # базовый X — в левом коридоре, перед блоками
        trace_gap = z(14)       # шаг между трассами

        def _routed(from_x, from_y, to_x, to_y, trace_x,
                     color, label, width=2, dashed=False):
            """Г-образная связь через вертикальную трассу trace_x."""
            d = {"dash": (4, 4)} if dashed else {}
            # Горизонталь от from → трасса
            self.canvas.create_line(from_x, from_y, trace_x, from_y,
                                     fill=color, width=width, **d)
            # Вертикаль по трассе
            self.canvas.create_line(trace_x, from_y, trace_x, to_y,
                                     fill=color, width=width, **d)
            # Горизонталь трасса → to
            self.canvas.create_line(trace_x, to_y, to_x, to_y,
                                     fill=color, width=width,
                                     arrow=tk.LAST, arrowshape=(7, 9, 4), **d)
            # Подпись
            self.canvas.create_text(
                trace_x - z(10), (from_y + to_y) / 2,
                text=label, fill=LABEL_COLOR,
                font=("Segoe UI", self._font_z(8), "bold"), angle=90
            )

        t = 0  # счётчик трасс

        # --- Физический ЭМВОС → Аппаратный (разъёмы) ---
        phys_col = col_centers.get(OSILevel.PHYSICAL)
        if phys_col and hw_pos:
            _routed(
                phys_col[3], (phys_col[1] + phys_col[2]) / 2,
                row_x1, (hw_pos[0] + hw_pos[1]) / 2,
                trace_base - t * trace_gap,
                HW_COLOR, "Разъёмы", dashed=True
            )
            t += 1

        # --- Канальный ЭМВОС → Ядро ОС (MAC/LLC) ---
        dl_col = col_centers.get(OSILevel.DATA_LINK)
        if kern_pos and dl_col:
            _routed(
                dl_col[3], (dl_col[1] + dl_col[2]) / 2,
                row_x1, (kern_pos[0] + kern_pos[1]) / 2 - z(20),
                trace_base - t * trace_gap,
                KERN_COLOR, "MAC/LLC", width=1, dashed=True
            )
            t += 1

        # --- Сетевой ЭМВОС → Ядро ОС (IP стек) ---
        net_col = col_centers.get(OSILevel.NETWORK)
        if kern_pos and net_col:
            _routed(
                net_col[3], (net_col[1] + net_col[2]) / 2,
                row_x1, (kern_pos[0] + kern_pos[1]) / 2 - z(10),
                trace_base - t * trace_gap,
                KERN_COLOR, "IP стек", width=1, dashed=True
            )
            t += 1

        # --- Транспортный ЭМВОС → Ядро ОС (TCP/UDP) ---
        trans_col = col_centers.get(OSILevel.TRANSPORT)
        if kern_pos and trans_col:
            _routed(
                trans_col[3], (trans_col[1] + trans_col[2]) / 2,
                row_x1, (kern_pos[0] + kern_pos[1]) / 2 + z(10),
                trace_base - t * trace_gap,
                KERN_COLOR, "TCP/UDP", width=1, dashed=True
            )
            t += 1

        # --- Ядро ОС → Аппаратный (драйверы) ---
        if kern_pos and hw_pos:
            _routed(
                row_x1, (kern_pos[0] + kern_pos[1]) / 2,
                row_x1, (hw_pos[0] + hw_pos[1]) / 2,
                trace_base - t * trace_gap,
                KERN_COLOR, "Драйверы"
            )
            t += 1

        # --- Прикладной ЭМВОС → Пользовательский (UI/ПО) ---
        # Эта связь идёт СПРАВА, чтобы не путать с левыми
        app_col = col_centers.get(OSILevel.APPLICATION)
        if user_pos and app_col:
            right_trace = row_x2 + z(12)  # в правом коридоре
            _routed(
                app_col[4], (app_col[1] + app_col[2]) / 2,
                row_x2, (user_pos[0] + user_pos[1]) / 2,
                right_trace,
                USER_COLOR, "UI / ПО", width=1, dashed=True
            )

        # --- Пользовательский → Аппаратный (USB-периферия) ---
        if user_pos and hw_pos:
            right_trace2 = row_x2 + z(26)  # вторая трасса в правом коридоре
            _routed(
                row_x2, (user_pos[0] + user_pos[1]) / 2,
                row_x2, (hw_pos[0] + hw_pos[1]) / 2,
                right_trace2,
                HW_COLOR, "USB"
            )

    def _draw_hardware_level(self, rx1, ry, rx2, comps, bg, border, text_color,
                              comp_h, comp_gap):
        """Рисует аппаратный уровень со связями между компонентами.

        Центральный элемент — материнская плата. Остальные компоненты
        расположены вокруг неё и связаны линиями (шины PCI Express, SATA, DMI).
        """
        z = self._z
        row_w = rx2 - rx1
        hw_comp_w = z(170)
        hw_comp_h = z(36)

        # Разделяем компоненты по ролям
        motherboard = None
        cpu = None
        other_comps = []

        for c in comps:
            name_lower = c.name.lower()
            if "материнская" in name_lower or c.identifier == "a2":
                motherboard = c
            elif "процессор" in name_lower or c.identifier == "a1":
                cpu = c
            else:
                other_comps.append(c)

        # Высота блока
        side_rows = max(1, (len(other_comps) + 1) // 2)
        row_h = max(z(180), z(60) + side_rows * (hw_comp_h + z(8)) + z(20))

        # Рамка
        self.canvas.create_rectangle(rx1, ry, rx2, ry + row_h,
                                      fill=bg, outline=border, width=2)
        self.canvas.create_text(rx1 + 15, ry + 15, text="Аппаратный уровень",
                                 anchor="w", fill=text_color, font=("Segoe UI", self._font_z(11), "bold"))

        # Центр блока
        center_x = (rx1 + rx2) / 2
        center_y = ry + row_h / 2 + 10

        # --- Материнская плата (центр) ---
        mb_w = z(220)
        mb_h = z(42)
        mb_x1 = center_x - mb_w / 2
        mb_y1 = center_y - mb_h / 2

        if motherboard:
            mb_vuln = motherboard.has_vulnerability
            self.canvas.create_rectangle(
                mb_x1, mb_y1, mb_x1 + mb_w, mb_y1 + mb_h,
                fill=self._p("comp_vuln_bg") if mb_vuln else self._p("hw_center_bg"),
                outline=self._p("comp_vuln_border") if mb_vuln else self._p("hw_center_border"), width=2
            )
            text = self._display_name(motherboard.name)
            if len(text) > 30:
                text = text[:28] + "…"
            self.canvas.create_text(center_x, center_y,
                                     text=text, fill=self._p("hw_center_text"),
                                     font=("Segoe UI", self._font_z(9), "bold"), width=mb_w - 10)
            if mb_vuln:
                bx = mb_x1 + mb_w - z(6)
                by = mb_y1 + z(3)
                self.canvas.create_oval(
                    bx - z(8), by - z(1), bx + z(8), by + z(11),
                    fill="#F44336", outline=""
                )
                self.canvas.create_text(
                    bx, by + z(5), text=str(len(motherboard.cve_list)),
                    fill="#FFFFFF", font=("Segoe UI", self._font_z(7), "bold")
                )

        # --- Процессор (слева от мат.платы) ---
        if cpu:
            cpu_x = mb_x1 - hw_comp_w - z(30)
            cpu_y = center_y - hw_comp_h / 2
            cpu_vuln = cpu.has_vulnerability
            self.canvas.create_rectangle(
                cpu_x, cpu_y, cpu_x + hw_comp_w, cpu_y + hw_comp_h,
                fill=self._p("comp_vuln_bg") if cpu_vuln else self._p("comp_bg"),
                outline=self._p("comp_vuln_border") if cpu_vuln else self._p("hw_cpu_border"), width=2
            )
            text = self._display_name(cpu.name)
            if len(text) > 24:
                text = text[:22] + "…"
            self.canvas.create_text(cpu_x + hw_comp_w / 2, cpu_y + hw_comp_h / 2,
                                     text=text, fill=self._p("hw_cpu_text"),
                                     font=("Segoe UI", self._font_z(9)), width=hw_comp_w - 10)
            if cpu_vuln:
                bx = cpu_x + hw_comp_w - z(6)
                by = cpu_y + z(3)
                self.canvas.create_oval(
                    bx - z(8), by - z(1), bx + z(8), by + z(11),
                    fill="#F44336", outline=""
                )
                self.canvas.create_text(
                    bx, by + z(5), text=str(len(cpu.cve_list)),
                    fill="#FFFFFF", font=("Segoe UI", self._font_z(7), "bold")
                )
            # Связь CPU → Мат.плата
            self.canvas.create_line(
                cpu_x + hw_comp_w, center_y, mb_x1, center_y,
                fill=self._p("hw_bus_color"), width=2, arrow=tk.BOTH, arrowshape=(6, 8, 3)
            )
            # Подпись шины
            self.canvas.create_text(
                (cpu_x + hw_comp_w + mb_x1) / 2, center_y - 10,
                text="DMI", fill=self._p("hw_bus_color"), font=("Segoe UI", self._font_z(7), "bold")
            )

        # --- Остальные компоненты (справа от мат.платы, в столбик) ---
        start_x = mb_x1 + mb_w + z(30)
        start_y = ry + z(40)

        comp_positions = []  # (cx, cy) центры для связей

        for idx, comp in enumerate(other_comps):
            col = idx // side_rows
            row = idx % side_rows

            cx = start_x + col * (hw_comp_w + z(10))
            cy = start_y + row * (hw_comp_h + z(8))

            if comp.has_vulnerability:
                c_fill, c_out, c_w = self._p("comp_vuln_bg"), self._p("comp_vuln_border"), 2
            else:
                c_fill, c_out, c_w = self._p("comp_bg"), border, 1
            self.canvas.create_rectangle(
                cx, cy, cx + hw_comp_w, cy + hw_comp_h,
                fill=c_fill, outline=c_out, width=c_w
            )
            text = self._display_name(comp.name)
            if len(text) > 24:
                text = text[:22] + "…"
            self.canvas.create_text(
                cx + hw_comp_w / 2, cy + hw_comp_h / 2,
                text=text, fill=text_color,
                font=("Segoe UI", self._font_z(9)), width=hw_comp_w - 10
            )
            if comp.has_vulnerability:
                bx = cx + hw_comp_w - z(6)
                by = cy + z(3)
                self.canvas.create_oval(
                    bx - z(8), by - z(1), bx + z(8), by + z(11),
                    fill="#F44336", outline=""
                )
                self.canvas.create_text(
                    bx, by + z(5), text=str(len(comp.cve_list)),
                    fill="#FFFFFF", font=("Segoe UI", self._font_z(7), "bold")
                )

            comp_positions.append((cx, cy + hw_comp_h / 2))

        # Связи: каждый компонент → мат.плата (через PCI Express/SATA)
        mb_right = mb_x1 + mb_w
        for cx, cy in comp_positions:
            self.canvas.create_line(
                mb_right, center_y, cx, cy,
                fill=self._p("hw_link_color"), width=1, dash=(3, 3)
            )

        return row_h

    def _on_zoom(self, event):
        """Ctrl+колесо — zoom через полную перерисовку (чтобы шрифты масштабировались)."""
        if event.delta > 0:
            new_zoom = self._zoom * 1.15
        else:
            new_zoom = self._zoom / 1.15

        if new_zoom < 0.3 or new_zoom > 3.0:
            return

        self._zoom = new_zoom
        self._draw()

    def _on_find_vulnerabilities(self):
        """Запускает поиск CVE для всех компонентов в фоновом потоке."""
        import threading
        import queue as _queue

        self._vuln_btn.configure(text="Поиск…", state="disabled")
        q = _queue.Queue()

        def _worker():
            try:
                total = len(self.topology.decompositions)
                for i, decomp in enumerate(self.topology.decompositions.values()):
                    decomp.find_vulnerabilities()
                    q.put(("progress", i + 1, total))
                q.put(("done",))
            except Exception:
                q.put(("done",))

        def _poll():
            try:
                while True:
                    msg = q.get_nowait()
                    if msg[0] == "done":
                        self._vuln_btn.configure(
                            text="Уязвимости найдены", state="disabled",
                            fg_color="white"
                        )
                        self._draw()
                        return
                    elif msg[0] == "progress":
                        self._vuln_btn.configure(
                            text=f"Поиск… {msg[1]}/{msg[2]}"
                        )
            except _queue.Empty:
                pass
            try:
                if self.window.winfo_exists():
                    self.window.after(100, _poll)
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()
        self.window.after(100, _poll)

    def _safe_close(self):
        """Закрытие окна с защитой от бага Python 3.13 + CTkToplevel."""
        try:
            self.window.after_cancel("all")
        except Exception:
            pass
        try:
            self.window.destroy()
        except Exception:
            pass

    def _create_ui(self):
        from utils.theme import color

        # Header
        header = ctk.CTkFrame(self.window, fg_color="transparent", height=50)
        header.pack(fill=tk.X, padx=15, pady=(10, 5))
        header.pack_propagate(False)

        ctk.CTkLabel(header, text="Схема разложения узла по уровням ЭМВОС",
                      font=("Segoe UI", 16, "bold"),
                      text_color=color("text_primary")).pack(side=tk.LEFT)

        nodes = self.topology.get_ordered_nodes()
        ctk.CTkLabel(header,
                      text=f"Узлов: {len(nodes)} | Связей: {len(self.board.links)}",
                      font=("Segoe UI", 12),
                      text_color=color("text_secondary")).pack(side=tk.LEFT, padx=(20, 0))

        ctk.CTkButton(header, text="Закрыть", command=self._safe_close,
                       width=100, height=34, corner_radius=8,
                       fg_color=color("ghost_bg"), hover_color=color("ghost_hover"),
                       text_color=color("text_primary")).pack(side=tk.RIGHT)

        self._vuln_btn = ctk.CTkButton(
            header, text="Найти уязвимости", command=self._on_find_vulnerabilities,
            width=160, height=34, corner_radius=8,
            fg_color="#B71C1C", hover_color="#D32F2F",
            text_color="#FFFFFF"
        )
        self._vuln_btn.pack(side=tk.RIGHT, padx=(0, 10))

        # Canvas
        canvas_frame = ctk.CTkFrame(self.window, fg_color=color("card_bg"),
                                      border_width=1, border_color=color("card_border"),
                                      corner_radius=8)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))

        h_scroll = ttk.Scrollbar(canvas_frame, orient=tk.HORIZONTAL)
        v_scroll = ttk.Scrollbar(canvas_frame, orient=tk.VERTICAL)

        from utils.theme import c
        self.canvas = tk.Canvas(
            canvas_frame, bg=c("canvas_bg"),
            xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set,
            highlightthickness=0, bd=0
        )

        h_scroll.config(command=self.canvas.xview)
        v_scroll.config(command=self.canvas.yview)

        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.canvas.bind("<MouseWheel>",
                          lambda e: self.canvas.yview_scroll(int(-e.delta / 120), "units"))
        self.canvas.bind("<Shift-MouseWheel>",
                          lambda e: self.canvas.xview_scroll(int(-e.delta / 120), "units"))
        self.canvas.bind("<Control-MouseWheel>", self._on_zoom)
        self.canvas.bind("<Enter>", lambda e: self.canvas.focus_set())

        self._zoom = 1.0

    # Цвета столбцов ЭМВОС: dark / light
    _LEVEL_COLORS_DARK = {
        OSILevel.PHYSICAL:     {"bg": "#1B3A4B", "border": "#2196F3", "text": "#90CAF9"},
        OSILevel.DATA_LINK:    {"bg": "#1B3A2B", "border": "#4CAF50", "text": "#A5D6A7"},
        OSILevel.NETWORK:      {"bg": "#3A2B1B", "border": "#FF9800", "text": "#FFE0B2"},
        OSILevel.TRANSPORT:    {"bg": "#3A1B2B", "border": "#E91E63", "text": "#F8BBD0"},
        OSILevel.SESSION:      {"bg": "#2B1B3A", "border": "#9C27B0", "text": "#CE93D8"},
        OSILevel.PRESENTATION: {"bg": "#1B2B3A", "border": "#00BCD4", "text": "#80DEEA"},
        OSILevel.APPLICATION:  {"bg": "#2B3A1B", "border": "#8BC34A", "text": "#C5E1A5"},
    }
    _LEVEL_COLORS_LIGHT = {
        OSILevel.PHYSICAL:     {"bg": "#E3F2FD", "border": "#1565C0", "text": "#0D47A1"},
        OSILevel.DATA_LINK:    {"bg": "#E8F5E9", "border": "#2E7D32", "text": "#1B5E20"},
        OSILevel.NETWORK:      {"bg": "#FFF3E0", "border": "#E65100", "text": "#BF360C"},
        OSILevel.TRANSPORT:    {"bg": "#FCE4EC", "border": "#C2185B", "text": "#880E4F"},
        OSILevel.SESSION:      {"bg": "#F3E5F5", "border": "#7B1FA2", "text": "#4A148C"},
        OSILevel.PRESENTATION: {"bg": "#E0F7FA", "border": "#00838F", "text": "#006064"},
        OSILevel.APPLICATION:  {"bg": "#F1F8E9", "border": "#558B2F", "text": "#33691E"},
    }

    LEVEL_LABELS = {
        OSILevel.PHYSICAL: "Физический", OSILevel.DATA_LINK: "Канальный",
        OSILevel.NETWORK: "Сетевой", OSILevel.TRANSPORT: "Транспортный",
        OSILevel.SESSION: "Сеансовый", OSILevel.PRESENTATION: "Представления",
        OSILevel.APPLICATION: "Прикладной",
    }

    # Общая палитра dark / light
    _PALETTE_DARK = {
        "canvas_bg": "#0B1120", "node_bg": "#0F172A", "node_border": "#3B82F6",
        "node_title": "#E2E8F0", "node_subtitle": "#94A3B8", "node_divider": "#334155",
        "comp_bg": "#2D3748", "comp_vuln_bg": "#3D1A1A", "comp_vuln_border": "#F44336",
        "link_color": "#5A6577", "badge_bg": "#F44336", "badge_text": "#FFFFFF",
        "hw_center_bg": "#1A2332", "hw_center_border": "#607D8B", "hw_center_text": "#B0BEC5",
        "hw_cpu_border": "#FF9800", "hw_cpu_text": "#FFE0B2", "hw_bus_color": "#FF9800",
        "hw_link_color": "#455A64",
        "extra_kernel":  {"bg": "#1A1A2E", "border": "#3F51B5", "text": "#9FA8DA"},
        "extra_hw":      {"bg": "#1A1F2E", "border": "#607D8B", "text": "#B0BEC5"},
        "extra_user":    {"bg": "#2E1A1A", "border": "#F44336", "text": "#EF9A9A"},
        "conn_kern": "#7986CB", "conn_hw": "#90A4AE", "conn_user": "#EF5350",
        "conn_label": "#FFFFFF",
    }
    _PALETTE_LIGHT = {
        "canvas_bg": "#F8F9FB", "node_bg": "#FFFFFF", "node_border": "#1565C0",
        "node_title": "#1A1A1A", "node_subtitle": "#555555", "node_divider": "#D0D0D0",
        "comp_bg": "#F0F4F8", "comp_vuln_bg": "#FFEBEE", "comp_vuln_border": "#D32F2F",
        "link_color": "#90A4AE", "badge_bg": "#D32F2F", "badge_text": "#FFFFFF",
        "hw_center_bg": "#E8EAF6", "hw_center_border": "#5C6BC0", "hw_center_text": "#283593",
        "hw_cpu_border": "#E65100", "hw_cpu_text": "#BF360C", "hw_bus_color": "#E65100",
        "hw_link_color": "#90A4AE",
        "extra_kernel":  {"bg": "#E8EAF6", "border": "#3F51B5", "text": "#1A237E"},
        "extra_hw":      {"bg": "#ECEFF1", "border": "#546E7A", "text": "#263238"},
        "extra_user":    {"bg": "#FFEBEE", "border": "#D32F2F", "text": "#B71C1C"},
        "conn_kern": "#5C6BC0", "conn_hw": "#78909C", "conn_user": "#E53935",
        "conn_label": "#333333",
    }

    def _p(self, key):
        """Возвращает цвет из палитры под текущую тему."""
        from utils.theme import current_mode
        pal = self._PALETTE_LIGHT if current_mode() == "light" else self._PALETTE_DARK
        return pal[key]

    def _lc(self, level):
        """Возвращает цвета столбца ЭМВОС под текущую тему."""
        from utils.theme import current_mode
        table = self._LEVEL_COLORS_LIGHT if current_mode() == "light" else self._LEVEL_COLORS_DARK
        colors = table[level].copy()
        colors["label"] = self.LEVEL_LABELS[level]
        return colors

    @staticmethod
    def _display_name(name):
        """Сокращает длинное имя компонента для отображения на схеме."""
        # Ядро ОС: убираем «Подсистема»
        _KERN_SHORT = {
            "Подсистема драйверов устройств": "Драйверы устройств",
            "Подсистема управления доступом": "Упр. доступом",
            "Подсистема управления файлами": "Упр. файлами",
            "Подсистема управления процессами": "Упр. процессами",
        }
        if name in _KERN_SHORT:
            return _KERN_SHORT[name]
        # Аппаратный: роль видна по расположению на схеме
        for prefix in ("Процессор: ", "Видеоконтроллер: ",
                        "Материнская плата: ", "HDD/SSD: ", "Память: "):
            if name.startswith(prefix):
                return name[len(prefix):]
        return name

    # 7 уровней ЭМВОС в порядке стека (слева направо)
    OSI_STACK = [
        OSILevel.PHYSICAL, OSILevel.DATA_LINK, OSILevel.NETWORK,
        OSILevel.TRANSPORT, OSILevel.SESSION, OSILevel.PRESENTATION,
        OSILevel.APPLICATION,
    ]

    def _z(self, val):
        """Масштабирует значение под текущий zoom."""
        return val * self._zoom

    def _font_z(self, base_size):
        """Возвращает размер шрифта под текущий zoom (минимум 6)."""
        return max(6, int(round(base_size * self._zoom)))

    def _draw(self):
        """Рисует все узлы топологии, один под другим."""
        self.canvas.delete("all")

        nodes = self.topology.get_ordered_nodes()
        if not nodes:
            self.canvas.create_text(400, 200, text="Нет узлов для анализа",
                                     fill="#888888", font=("Segoe UI", 18))
            return

        z = self._z
        margin = z(60)
        node_gap = z(80)  # зазор между узлами (увеличен для χ-линий)

        current_y = margin
        total_width = 0

        # Позиции узлов: node_id → (x1, y1, x2, y2, phys_col_center_x)
        self._node_positions = {}

        for node in nodes:
            node_height, node_width = self._draw_single_node(node, margin, current_y)
            total_width = max(total_width, node_width + margin * 2)

            # Запоминаем позицию узла для χ-линий
            self._node_positions[node.id] = {
                "x1": margin,
                "y1": current_y,
                "x2": margin + node_width,
                "y2": current_y + node_height,
                "node": node,
            }

            current_y += node_height + node_gap

        # ===== Линии χ между узлами =====
        self._draw_chi_connections(margin, total_width)

        self.canvas.configure(scrollregion=(
            0, 0, total_width + z(60), current_y + margin
        ))

    def _draw_single_node(self, node, x_offset, y_offset):
        """Рисует один узел и возвращает (height, width)."""

        # ===== Размеры (масштабируемые) =====
        z = self._z
        margin = z(60)
        header_h = z(70)
        col_width = z(155)
        col_gap = z(30)
        col_header_h = z(50)
        left_corridor = z(80)   # коридор слева для вертикальных трасс связей
        right_corridor = z(35)  # коридор справа для правой трассы
        col_body_h = 300        # высота тела столбца (пока пустое)
        col_count = len(self.OSI_STACK)

        node_width = left_corridor + col_count * (col_width + col_gap) - col_gap + right_corridor + z(20)
        node_height = header_h + col_header_h + col_body_h + 20

        x1 = x_offset
        y1 = y_offset
        x2 = x1 + node_width
        y2 = y1 + node_height

        # ===== Рамка узла =====
        self.canvas.create_rectangle(
            x1, y1, x2, y2,
            outline=self._p("node_border"), fill=self._p("node_bg"), width=2
        )

        # ===== Заголовок узла =====
        self.canvas.create_text(
            (x1 + x2) / 2, y1 + 25,
            text=node.name,
            fill=self._p("node_title"), font=("Segoe UI", self._font_z(18), "bold")
        )
        self.canvas.create_text(
            (x1 + x2) / 2, y1 + 50,
            text=f"Тип: {node.type}",
            fill=self._p("node_subtitle"), font=("Segoe UI", self._font_z(11))
        )
        self.canvas.create_line(
            x1 + 20, y1 + header_h, x2 - 20, y1 + header_h,
            fill=self._p("node_divider"), width=1
        )

        # ===== Разложение узла =====
        decomp = self.topology.get_node_decomposition(node.id)

        # ===== 7 столбцов ЭМВОС =====
        comp_h = z(22)
        comp_gap = z(4)
        comp_pad = z(8)

        # Вычисляем высоту тела столбца по макс. кол-ву компонентов
        max_comps = 0
        if decomp:
            for level in self.OSI_STACK:
                count = len(decomp.get_components_by_level(level))
                max_comps = max(max_comps, count)
        col_body_h = max(200, max_comps * (comp_h + comp_gap) + comp_pad * 2)

        # Пересчитываем размер узла
        node_height = header_h + col_header_h + col_body_h + 20
        y2 = y1 + node_height

        # Перерисовываем рамку узла с правильным размером
        self.canvas.create_rectangle(
            x1, y1, x2, y2,
            outline=self._p("node_border"), fill=self._p("node_bg"), width=2
        )
        # Перерисовываем заголовок (поверх рамки)
        self.canvas.create_text(
            (x1 + x2) / 2, y1 + 25,
            text=node.name,
            fill=self._p("node_title"), font=("Segoe UI", self._font_z(18), "bold")
        )
        self.canvas.create_text(
            (x1 + x2) / 2, y1 + 50,
            text=f"Тип: {node.type}",
            fill=self._p("node_subtitle"), font=("Segoe UI", self._font_z(11))
        )
        self.canvas.create_line(
            x1 + 20, y1 + header_h, x2 - 20, y1 + header_h,
            fill=self._p("node_divider"), width=1
        )

        col_x = x1 + left_corridor  # столбцы ЭМВОС начинаются после коридора
        col_y = y1 + header_h + 10

        # Словарь для хранения координат центров столбцов (для связей)
        # level → (center_x, top_y, bottom_y)
        col_centers = {}
        comp_rects = {}  # identifier → (x1, y1, x2, y2)

        for level in self.OSI_STACK:
            colors = self._lc(level)

            # Заголовок столбца
            self.canvas.create_rectangle(
                col_x, col_y,
                col_x + col_width, col_y + col_header_h,
                fill=colors["bg"], outline=colors["border"], width=2
            )
            self.canvas.create_text(
                col_x + col_width / 2, col_y + col_header_h / 2,
                text=colors["label"],
                fill=colors["text"], font=("Segoe UI", self._font_z(10), "bold")
            )

            # Тело столбца
            body_y = col_y + col_header_h
            self.canvas.create_rectangle(
                col_x, body_y,
                col_x + col_width, body_y + col_body_h,
                fill=colors["bg"], outline=colors["border"], width=1,
                dash=(2, 4)
            )

            # Сохраняем координаты центра столбца для связей
            col_centers[level] = (
                col_x + col_width / 2,  # center_x
                col_y + col_header_h,    # top_y (верх тела)
                col_y + col_header_h + col_body_h,  # bottom_y (низ тела)
                col_x,                   # left_x
                col_x + col_width,       # right_x
            )

            # Компоненты внутри столбца
            if decomp:
                comps = decomp.get_components_by_level(level)
                cy = body_y + comp_pad
                for comp in comps:
                    # Стиль: обычный или уязвимый
                    if comp.has_vulnerability:
                        c_fill = self._p("comp_vuln_bg")
                        c_outline = self._p("comp_vuln_border")
                        c_width = 2
                    else:
                        c_fill = self._p("comp_bg")
                        c_outline = colors["border"]
                        c_width = 1
                    # Прямоугольник компонента
                    self.canvas.create_rectangle(
                        col_x + 4, cy,
                        col_x + col_width - 4, cy + comp_h,
                        fill=c_fill, outline=c_outline, width=c_width
                    )
                    # Текст
                    text = comp.name
                    if len(text) > 18:
                        text = text[:16] + "…"
                    self.canvas.create_text(
                        col_x + col_width / 2, cy + comp_h / 2,
                        text=text,
                        fill=colors["text"], font=("Segoe UI", self._font_z(8)),
                        width=col_width - 14
                    )
                    # Бейдж CVE
                    if comp.has_vulnerability:
                        badge_text = str(len(comp.cve_list))
                        bx = col_x + col_width - 4 - z(6)
                        by = cy + z(3)
                        self.canvas.create_oval(
                            bx - z(8), by - z(1),
                            bx + z(8), by + z(11),
                            fill=self._p("badge_bg"), outline=""
                        )
                        self.canvas.create_text(
                            bx, by + z(5),
                            text=badge_text, fill=self._p("badge_text"),
                            font=("Segoe UI", self._font_z(7), "bold")
                        )
                    if comp.identifier:
                        comp_rects[comp.identifier] = (
                            col_x + 4, cy,
                            col_x + col_width - 4, cy + comp_h
                        )
                    cy += comp_h + comp_gap

            col_x += col_width + col_gap

        # ===== Связи между компонентами соседних столбцов ЭМВОС =====
        _COMP_LINKS = [
            ("f2.1",  "z1"),    # IEEE 802.3 → IEEE 802
            ("f2.2",  "z1"),    # IEEE 802.11 → IEEE 802
            ("z4",    "l1"),    # ARP → IP-адрес
            ("z3",    "l6"),    # MAC-адрес → ARP-таблица
            ("l2",    "t1.1"),  # IPv4 → TCP
            ("l2",    "t2.1"),  # IPv4 → UDP
            ("t1.1",  "d5"),    # TCP → HTTPУС
            ("d5",    "r7"),    # HTTPУС → SSL/TLS
            ("r8",    "q9"),    # HTTPКД → HTTPппо-клиент
            ("r8",    "q9s"),   # HTTPКД → HTTPппо-сервер
        ]
        link_color = self._p("link_color")
        for src_id, dst_id in _COMP_LINKS:
            src = comp_rects.get(src_id)
            dst = comp_rects.get(dst_id)
            if not src or not dst:
                continue
            from_x = src[2]
            from_y = (src[1] + src[3]) / 2
            to_x = dst[0]
            to_y = (dst[1] + dst[3]) / 2
            mid_x = (from_x + to_x) / 2
            if abs(from_y - to_y) < 3:
                self.canvas.create_line(
                    from_x, from_y, to_x, to_y,
                    fill=link_color, width=1, dash=(3, 3),
                    arrow=tk.LAST, arrowshape=(5, 7, 3)
                )
            else:
                self.canvas.create_line(
                    from_x, from_y, mid_x, from_y,
                    fill=link_color, width=1, dash=(3, 3)
                )
                self.canvas.create_line(
                    mid_x, from_y, mid_x, to_y,
                    fill=link_color, width=1, dash=(3, 3)
                )
                self.canvas.create_line(
                    mid_x, to_y, to_x, to_y,
                    fill=link_color, width=1, dash=(3, 3),
                    arrow=tk.LAST, arrowshape=(5, 7, 3)
                )

        # ===== Дополнительные строки под стеком ЭМВОС =====
        _ek = self._p("extra_kernel")
        _eh = self._p("extra_hw")
        _eu = self._p("extra_user")
        extra_levels = [
            (OSILevel.KERNEL, "Подсистемы ядра ОС", _ek["bg"], _ek["border"], _ek["text"]),
            (OSILevel.HARDWARE, "Аппаратный уровень", _eh["bg"], _eh["border"], _eh["text"]),
            (OSILevel.USER, "Пользовательский уровень", _eu["bg"], _eu["border"], _eu["text"]),
        ]

        row_y = col_y + col_header_h + col_body_h + 40  # под столбцами ЭМВОС (увеличен зазор)
        row_x1 = x1 + left_corridor  # доп. строки начинаются от того же X
        row_x2 = x2 - right_corridor  # и заканчиваются перед правым коридором
        row_pad = 8

        # Позиции строк для связей: level → (y_top, y_bottom, x1, x2)
        row_positions = {}

        for level, title, bg, border, text_color in extra_levels:
            comps = decomp.get_components_by_level(level) if decomp else []

            if level == OSILevel.HARDWARE and comps:
                # ===== Аппаратный уровень — особая отрисовка со связями =====
                row_h = self._draw_hardware_level(
                    row_x1, row_y, row_x2, comps,
                    bg, border, text_color, comp_h, comp_gap
                )
            else:
                # Обычная строка — компоненты в ряд (шире чем столбцы ЭМВОС)
                extra_cw = z(200)
                items_per_row = max(1, (row_x2 - row_x1 - 20) // (extra_cw + 6))
                rows_needed = max(1, (len(comps) + items_per_row - 1) // items_per_row) if comps else 1
                row_h = 40 + rows_needed * (comp_h + comp_gap)

                self.canvas.create_rectangle(
                    row_x1, row_y, row_x2, row_y + row_h,
                    fill=bg, outline=border, width=2
                )
                self.canvas.create_text(
                    row_x1 + 15, row_y + 15,
                    text=title, anchor="w",
                    fill=text_color, font=("Segoe UI", self._font_z(11), "bold")
                )

                if comps:
                    cx = row_x1 + 10
                    cy = row_y + 32

                    for idx, comp in enumerate(comps):
                        col_in_row = idx % items_per_row
                        row_in_block = idx // items_per_row

                        comp_x = cx + col_in_row * (extra_cw + 6)
                        comp_y = cy + row_in_block * (comp_h + comp_gap)

                        if comp.has_vulnerability:
                            c_fill, c_out, c_w = self._p("comp_vuln_bg"), self._p("comp_vuln_border"), 2
                        else:
                            c_fill, c_out, c_w = self._p("comp_bg"), border, 1
                        self.canvas.create_rectangle(
                            comp_x, comp_y,
                            comp_x + extra_cw - 8, comp_y + comp_h,
                            fill=c_fill, outline=c_out, width=c_w
                        )
                        text = self._display_name(comp.name)
                        if len(text) > 26:
                            text = text[:24] + "…"
                        self.canvas.create_text(
                            comp_x + (extra_cw - 8) / 2, comp_y + comp_h / 2,
                            text=text,
                            fill=text_color, font=("Segoe UI", self._font_z(9)),
                            width=extra_cw - 16
                        )
                        if comp.has_vulnerability:
                            bx = comp_x + extra_cw - 8 - z(6)
                            by = comp_y + z(3)
                            self.canvas.create_oval(
                                bx - z(8), by - z(1), bx + z(8), by + z(11),
                                fill=self._p("badge_bg"), outline=""
                            )
                            self.canvas.create_text(
                                bx, by + z(5),
                                text=str(len(comp.cve_list)),
                                fill=self._p("badge_text"),
                                font=("Segoe UI", self._font_z(7), "bold")
                            )

            row_positions[level] = (row_y, row_y + row_h, row_x1, row_x2)
            row_y += row_h + 30  # увеличен зазор между строками для связей

        # ===== Связи между дополнительными строками =====
        self._draw_extra_level_connections(
            col_centers, row_positions, row_x1, row_x2
        )

        # ===== Пересчитываем размер узла и рамку =====
        node_height = row_y - y1 + 10
        y2 = y1 + node_height

        # Рамка узла поверх всего (перерисовка с правильным размером)
        self.canvas.create_rectangle(
            x1, y1, x2, y2,
            outline=self._p("node_border"), fill="", width=2
        )

        return (node_height, node_width)


def show_osi_decomposition(parent, board: Board):
    """Показывает окно визуализации."""
    if not board.nodes:
        from tkinter import messagebox
        messagebox.showinfo("Схема ЭМВОС", "Нет узлов для анализа.")
        return
    OSIDecompositionView(parent, board)
