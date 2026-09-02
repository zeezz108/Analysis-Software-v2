"""
Окно «Маршруты УБИ» — вектор комплексной компьютерной атаки по топологии.

Что показывает
--------------
То, что на плакате «Комплексные компьютерные атаки» выписано вручную:
четыре этапа ККА с маршрутами `ТрО №N.1 → … → ЦО №N`. Здесь это считается
автоматически волновым алгоритмом по графу компонентов всей сети.

Три панели
----------
    слева   — целевые объекты, отсортированные по критичности V,
              и отдельная вкладка с четырьмя этапами ККА
    в центре — поле волны: дорожка на каждый узел, по горизонтали — номер
              волнового фронта. Видно, как угроза расходится по сети по шагам
    справа  — развёрнутый маршрут выбранной цели, шаг за шагом

Почему поле, а не список
------------------------
Число маршрутов растёт экспоненциально: до одной цели в тестовой топологии
из восьми узлов ведёт 209 952 кратчайших маршрута. Список такой длины
бесполезен и неотрисовываем. Поле волны показывает все маршруты сразу
в сжатом виде, число считается сложением, а конкретный маршрут
разворачивается по клику.
"""

import queue
import re
import threading
import tkinter as tk
from collections import defaultdict
from tkinter import messagebox, ttk
from typing import Dict, List, Optional, Set, Tuple

import customtkinter as ctk

from models.kka import STAGE_PROFILES, KKAStage, build_kka_vector
from models.topology_graph import TopologyGraph, build_topology_graph
from models.wave import (WaveField, count_routes, iter_routes, propagate,
                         rank_routes, restore_route)
from utils.theme import c, color, sp

__all__ = ["show_kka_routes"]


# Цвета глубины волны: чем дальше фронт, тем «горячее»
_DEPTH_COLORS = ["#0E7490", "#0891B2", "#0D9488", "#65A30D",
                 "#CA8A04", "#EA580C", "#DC2626"]

# Цвета уровней критичности по таблице 2 Методики
_LEVEL_COLORS = {
    "Критический": "#DC2626",
    "Высокий":     "#EA580C",
    "Средний":     "#CA8A04",
    "Низкий":      "#16A34A",
}


_CWE_RE = re.compile(r"\d{1,4}")


def _cwe_set(cves) -> Set[int]:
    """Все номера CWE, встречающиеся в списке уязвимостей компонента.

    Нужны для отбора цели этапа ККА: у каждого этапа свой профиль классов
    слабостей — см. STAGE_PROFILES.
    """
    return {int(n) for cve in cves
            for n in _CWE_RE.findall(str(cve.get("cwe_id", "")))}


def _depth_color(depth: int, max_depth: int) -> str:
    """Цвет вершины по номеру волнового фронта."""
    if max_depth <= 0:
        return _DEPTH_COLORS[0]
    idx = int(depth / max_depth * (len(_DEPTH_COLORS) - 1))
    return _DEPTH_COLORS[min(idx, len(_DEPTH_COLORS) - 1)]


class KKARoutesView:
    """Окно расчёта маршрутов распространения УБИ."""

    def __init__(self, parent, board):
        self.parent = parent
        self.board = board

        # --- Модель ---
        self.graph: TopologyGraph = build_topology_graph(board)
        self.field: Optional[WaveField] = None
        self.counts: Dict[str, int] = {}
        self.entry_id: str = ""
        # Вершина, из которой пущена текущая волна. Совпадает с точкой входа,
        # но при показе этапа ККА волна пускается из его собственного начала
        self.wave_source: str = ""
        self._row_ids: Dict[str, str] = {}
        self.assessments: Dict[str, object] = {}
        self.cwe_map: Dict[str, Set[int]] = {}
        self.stages: List[KKAStage] = []
        self.selected_target: str = ""
        self._alt_index = 0

        # --- Отрисовка ---
        self.vpos: Dict[str, Tuple[int, int]] = {}
        self._assessed = False
        self._zoom = 1.0
        self._fitted = False
        self._content = (0, 0)   # размер поля волны в масштабе 1:1

        if not self.graph.entry_points:
            messagebox.showinfo(
                "Маршруты УБИ",
                "В топологии нет узлов с портами — точек входа УБИ не найдено.")
            return

        self.window = ctk.CTkToplevel(parent)
        self.window.title("Маршруты УБИ — вектор комплексной компьютерной атаки")
        self.window.transient(parent)
        self.window.configure(fg_color=color("dialog_bg"))
        self.window.protocol("WM_DELETE_WINDOW", self._close)

        self._build_ui()
        self.window.update_idletasks()
        try:
            self.window.state("zoomed")
        except Exception:
            self.window.geometry(
                f"{self.window.winfo_screenwidth()}x"
                f"{self.window.winfo_screenheight()}+0+0")

        # Первая волна — из первой точки входа. Поле вписывается в окно
        # по событию <Configure>, когда холст получит реальные размеры
        self._set_entry(self.graph.entry_points[0])

    # ==================================================================
    # Интерфейс
    # ==================================================================

    def _build_ui(self) -> None:
        """Собирает три панели и верхнюю строку управления."""
        root = ctk.CTkFrame(self.window, fg_color="transparent")
        root.pack(fill=tk.BOTH, expand=True, padx=sp(10), pady=sp(10))

        self._build_toolbar(root)

        body = ctk.CTkFrame(root, fg_color="transparent")
        body.pack(fill=tk.BOTH, expand=True, pady=(sp(8), 0))

        self._build_left(body)
        self._build_center(body)
        self._build_right(body)

    # ----- Верхняя строка -----

    def _build_toolbar(self, parent) -> None:
        bar = ctk.CTkFrame(parent, fg_color=color("card_bg"),
                           corner_radius=sp(8))
        bar.pack(fill=tk.X)

        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill=tk.X, padx=sp(12), pady=sp(8))

        ctk.CTkLabel(inner, text="Точка входа УБИ:",
                     font=("Segoe UI", sp(12))).pack(side=tk.LEFT)

        self._entry_names = {}
        options = []
        for vid in self.graph.entry_points:
            v = self.graph.vertices[vid]
            label = f"{v.node_name} · {v.name}"
            self._entry_names[label] = vid
            options.append(label)

        self._entry_var = ctk.StringVar(value=options[0] if options else "")
        self._entry_menu = ctk.CTkOptionMenu(
            inner, values=options, variable=self._entry_var,
            width=sp(300), font=("Segoe UI", sp(12)),
            command=self._on_entry_changed)
        self._entry_menu.pack(side=tk.LEFT, padx=(sp(8), sp(16)))

        self._assess_btn = ctk.CTkButton(
            inner, text="Оценить критичность", width=sp(190),
            font=("Segoe UI", sp(12), "bold"),
            fg_color=color("primary"), hover_color=color("primary_hover"),
            command=self._run_assessment)
        self._assess_btn.pack(side=tk.LEFT)

        self._status = ctk.CTkLabel(
            inner, text="", font=("Segoe UI", sp(12)),
            text_color=color("text_secondary"))
        self._status.pack(side=tk.LEFT, padx=sp(16))

        self._summary = ctk.CTkLabel(
            inner, text="", font=("Segoe UI", sp(12)),
            text_color=color("text_secondary"))
        self._summary.pack(side=tk.RIGHT)

    # ----- Левая панель -----

    def _build_left(self, parent) -> None:
        left = ctk.CTkFrame(parent, fg_color=color("card_bg"),
                            corner_radius=sp(8), width=sp(380))
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, sp(8)))
        left.pack_propagate(False)

        self._tabs = ctk.CTkTabview(left, fg_color="transparent",
                                    segmented_button_selected_color=color("primary"))
        self._tabs.pack(fill=tk.BOTH, expand=True, padx=sp(6), pady=sp(6))
        self._tabs.add("Целевые объекты")
        self._tabs.add("Этапы ККА")

        # --- Список целей ---
        targets_tab = self._tabs.tab("Целевые объекты")
        style = ttk.Style()
        style.configure("KKA.Treeview", font=("Segoe UI", sp(10)),
                        rowheight=sp(26))
        style.configure("KKA.Treeview.Heading", font=("Segoe UI", sp(10), "bold"))

        cols = ("Узел", "Компонент", "V", "Шаг", "Маршрутов")
        self._targets = ttk.Treeview(targets_tab, columns=cols,
                                     show="headings", style="KKA.Treeview")
        for col, width, anchor in (("Узел", sp(90), "w"),
                                   ("Компонент", sp(110), "w"),
                                   ("V", sp(45), "center"),
                                   ("Шаг", sp(40), "center"),
                                   ("Маршрутов", sp(75), "e")):
            self._targets.heading(col, text=col)
            self._targets.column(col, width=width, anchor=anchor)

        tsb = ttk.Scrollbar(targets_tab, orient="vertical",
                            command=self._targets.yview)
        self._targets.configure(yscrollcommand=tsb.set)
        self._targets.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._targets.bind("<<TreeviewSelect>>", self._on_target_selected)

        # --- Этапы ККА ---
        stages_tab = self._tabs.tab("Этапы ККА")
        self._stages_box = ctk.CTkScrollableFrame(
            stages_tab, fg_color="transparent")
        self._stages_box.pack(fill=tk.BOTH, expand=True)
        ctk.CTkLabel(
            self._stages_box,
            text="Нажмите «Оценить критичность»,\nчтобы построить вектор ККА",
            font=("Segoe UI", sp(12)), justify="left",
            text_color=color("text_muted")).pack(anchor="w", pady=sp(20))

    # ----- Центр -----

    def _build_center(self, parent) -> None:
        center = ctk.CTkFrame(parent, fg_color=color("card_bg"),
                              corner_radius=sp(8))
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = ctk.CTkFrame(center, fg_color="transparent")
        header.pack(fill=tk.X, padx=sp(12), pady=(sp(8), 0))
        ctk.CTkLabel(header, text="Поле волны — все маршруты сразу",
                     font=("Segoe UI", sp(13), "bold")).pack(side=tk.LEFT)

        # Управление масштабом: поле волны на широкой топологии не помещается
        # в экран целиком, поэтому по умолчанию оно вписывается в окно
        for text, command, width in (("−", self._zoom_out, 30),
                                     ("+", self._zoom_in, 30),
                                     ("1:1", self._zoom_reset, 44),
                                     ("Вписать", self._zoom_fit, 74)):
            ctk.CTkButton(header, text=text, width=sp(width), height=sp(24),
                          font=("Segoe UI", sp(11)),
                          fg_color=color("ghost_bg"),
                          hover_color=color("ghost_hover"),
                          text_color=color("text_primary"),
                          command=command).pack(side=tk.RIGHT, padx=sp(2))

        self._legend = ctk.CTkLabel(
            header, text="", font=("Segoe UI", sp(11)),
            text_color=color("text_secondary"))
        self._legend.pack(side=tk.RIGHT, padx=(0, sp(12)))

        wrap = tk.Frame(center, bg=c("canvas_bg"))
        wrap.pack(fill=tk.BOTH, expand=True, padx=sp(10), pady=sp(10))

        self.canvas = tk.Canvas(wrap, bg=c("canvas_bg"),
                                highlightthickness=0)
        hsb = ttk.Scrollbar(wrap, orient="horizontal",
                            command=self.canvas.xview)
        vsb = ttk.Scrollbar(wrap, orient="vertical",
                            command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=hsb.set, yscrollcommand=vsb.set)

        self.canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        self.canvas.bind("<Button-1>", self._on_canvas_click)
        # Вписываем схему, когда холст впервые получит реальные размеры.
        # Отложенный вызов через after ненадёжен: окно может быть ещё
        # не размечено, и winfo_width() возвращает 1
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        # Ctrl + колесо — масштаб, просто колесо — прокрутка
        self.canvas.bind("<Control-MouseWheel>", self._on_wheel_zoom)
        self.canvas.bind(
            "<MouseWheel>",
            lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"))
        self.canvas.bind(
            "<Shift-MouseWheel>",
            lambda e: self.canvas.xview_scroll(-1 if e.delta > 0 else 1, "units"))

    # ----- Правая панель -----

    def _build_right(self, parent) -> None:
        right = ctk.CTkFrame(parent, fg_color=color("card_bg"),
                             corner_radius=sp(8), width=sp(400))
        right.pack(side=tk.LEFT, fill=tk.Y, padx=(sp(8), 0))
        right.pack_propagate(False)

        header = ctk.CTkFrame(right, fg_color="transparent")
        header.pack(fill=tk.X, padx=sp(12), pady=(sp(10), sp(4)))
        self._route_title = ctk.CTkLabel(
            header, text="Маршрут", font=("Segoe UI", sp(13), "bold"))
        self._route_title.pack(side=tk.LEFT)

        self._alt_btn = ctk.CTkButton(
            header, text="Другой маршрут", width=sp(130), height=sp(26),
            font=("Segoe UI", sp(11)),
            fg_color=color("ghost_bg"), hover_color=color("ghost_hover"),
            text_color=color("text_primary"), command=self._next_route)
        self._alt_btn.pack(side=tk.RIGHT)

        self._route_box = ctk.CTkScrollableFrame(right, fg_color="transparent")
        self._route_box.pack(fill=tk.BOTH, expand=True, padx=sp(6),
                             pady=(0, sp(8)))
        ctk.CTkLabel(self._route_box,
                     text="Выберите цель слева\nили точку на поле волны",
                     font=("Segoe UI", sp(12)), justify="left",
                     text_color=color("text_muted")).pack(anchor="w", pady=sp(20))

    # ==================================================================
    # Волна
    # ==================================================================

    def _on_entry_changed(self, label: str) -> None:
        vid = self._entry_names.get(label)
        if vid:
            self._set_entry(vid)

    def _set_entry(self, entry_id: str) -> None:
        """Пускает волну из выбранной точки входа и перерисовывает всё."""
        self.entry_id = entry_id
        self.wave_source = entry_id
        self.field = propagate(self.graph.adjacency, [entry_id])
        self.counts = count_routes(self.field)
        self.selected_target = ""
        self._alt_index = 0

        reached = len(self.field.distance)
        total = len(self.graph.vertices)
        self._summary.configure(
            text=f"Вершин {total} · рёбер {self.graph.edge_count} · "
                 f"достигнуто {reached} · глубина {self.field.max_depth}")
        self._legend.configure(
            text="цвет — номер шага волны; размер появится после оценки")

        self._fill_targets()
        self._draw_field()
        self._clear_route()

    # ==================================================================
    # Список целей
    # ==================================================================

    def _fill_targets(self) -> None:
        """Заполняет список целевых объектов."""
        for item in self._targets.get_children():
            self._targets.delete(item)

        if not self.field:
            return

        rows = []
        for vid, vertex in self.graph.vertices.items():
            if not vertex.is_target or vid not in self.field.distance:
                continue
            assessment = self.assessments.get(vid)
            crit = getattr(assessment, "V", 0.0) if assessment else 0.0
            # До оценки показываем всё, после — только уязвимые компоненты
            if self._assessed and crit <= 0:
                continue
            rows.append((vid, vertex, crit))

        # После оценки — по критичности, до неё — по глубине волны
        if self._assessed:
            rows.sort(key=lambda r: (-r[2], self.field.distance[r[0]]))
        else:
            rows.sort(key=lambda r: (self.field.distance[r[0]], r[1].node_name))

        SHOWN_LIMIT = 400
        self._row_ids = {}
        for vid, vertex, crit in rows[:SHOWN_LIMIT]:
            item = self._targets.insert("", tk.END, values=(
                vertex.node_name,
                vertex.name[:26],
                f"{crit:.2f}" if crit else "—",
                self.field.distance[vid],
                f"{self.counts.get(vid, 0):,}".replace(",", " "),
            ))
            self._row_ids[item] = vid

        if self._assessed:
            note = (f"Уязвимых целей: {len(rows)}"
                    + (f" (показаны первые {SHOWN_LIMIT})"
                       if len(rows) > SHOWN_LIMIT else ""))
            self._status.configure(text=note,
                                   text_color=color("text_secondary"))

    def _on_target_selected(self, _event=None) -> None:
        selection = self._targets.selection()
        if not selection:
            return
        vid = self._row_ids.get(selection[0])
        if vid:
            self.selected_target = vid
            self._alt_index = 0
            self._show_route(vid)
            self._draw_field()

    # ==================================================================
    # Поле волны
    # ==================================================================

    def _zs(self, value: int) -> int:
        """Масштабирует размер под текущий зум."""
        return max(1, int(value * self._zoom))

    def _layout_field(self):
        """Считает раскладку поля волны в масштабе 1:1.

        Дорожка на каждый узел, по горизонтали — номер волнового фронта.
        Раскладка отделена от отрисовки, чтобы знать размер содержимого
        и уметь вписывать его в окно.
        """
        step_x, left_pad, top_pad = sp(46), sp(150), sp(34)
        row_h, lane_gap = sp(15), sp(22)

        # Узлы — в порядке появления волны
        first_seen: Dict[str, int] = {}
        for vid in self.field.order:
            node_id = self.graph.vertices[vid].node_id
            first_seen.setdefault(node_id, self.field.distance[vid])

        positions: Dict[str, Tuple[int, int]] = {}
        lanes: List[Tuple[str, str, int, int]] = []   # узел, имя, y, высота
        y = top_pad

        for node_id in sorted(first_seen, key=lambda n: first_seen[n]):
            by_depth: Dict[int, List[str]] = defaultdict(list)
            for vid in self.graph.by_node.get(node_id, []):
                if vid in self.field.distance:
                    by_depth[self.field.distance[vid]].append(vid)
            if not by_depth:
                continue

            height = max(len(v) for v in by_depth.values()) * row_h
            node_name = next(
                (self.graph.vertices[v].node_name
                 for v in self.graph.by_node[node_id]), node_id)
            lanes.append((node_id, node_name, y, height))

            for depth, ids in by_depth.items():
                for i, vid in enumerate(sorted(ids)):
                    positions[vid] = (left_pad + depth * step_x, y + i * row_h)

            y += height + lane_gap

        width = left_pad + (self.field.max_depth + 1) * step_x + sp(40)
        return positions, lanes, y, width

    def _draw_field(self) -> None:
        """Рисует поле волны в текущем масштабе."""
        self.canvas.delete("all")
        self.vpos.clear()
        if not self.field:
            return

        positions, lanes, content_h, content_w = self._layout_field()
        self._content = (content_w, content_h)
        z = self._zoom

        for vid, (x, y) in positions.items():
            self.vpos[vid] = (int(x * z), int(y * z))

        route = self._current_route() if self.selected_target else []
        route_set = set(route)
        label_font = ("Segoe UI", max(6, self._zs(sp(10))), "bold")
        tick_font = ("Segoe UI", max(6, self._zs(sp(9))))

        # Дорожки узлов
        for _node_id, node_name, y, height in lanes:
            self.canvas.create_rectangle(
                self._zs(sp(8)), int((y - sp(6)) * z),
                self._zs(sp(150) - sp(10)), int((y + height + sp(6)) * z),
                fill=c("surface"), outline="")
            self.canvas.create_text(
                self._zs(sp(16)), int((y + height / 2) * z), anchor="w",
                text=node_name, font=label_font, fill=c("text_primary"))

        # Сетка номеров фронтов
        for depth in range(self.field.max_depth + 1):
            x = int((sp(150) + depth * sp(46)) * z)
            self.canvas.create_line(x, self._zs(sp(20)), x, int(content_h * z),
                                    fill=c("divider"), dash=(2, 4))
            self.canvas.create_text(x, self._zs(sp(12)), text=str(depth),
                                    font=tick_font, fill=c("text_muted"))
        self.canvas.create_text(
            self._zs(sp(16)), self._zs(sp(12)), anchor="w",
            text="шаг волны →", font=tick_font, fill=c("text_muted"))

        # Маршрут — линией под вершинами
        if len(route) > 1:
            points = []
            for vid in route:
                if vid in self.vpos:
                    points.extend(self.vpos[vid])
            if len(points) >= 4:
                self.canvas.create_line(*points, fill="#D97706",
                                        width=max(1, self._zs(sp(3))))

        # Вершины
        base_r = max(2, self._zs(sp(4)))
        for vid, (x, py) in self.vpos.items():
            assessment = self.assessments.get(vid)
            crit = getattr(assessment, "V", 0.0) if assessment else 0.0

            radius = base_r + (self._zs(min(int(crit), 6)) if crit > 0 else 0)
            if crit > 0:
                fill = _LEVEL_COLORS.get(
                    getattr(assessment, "level", "Низкий"), "#16A34A")
            else:
                fill = _depth_color(self.field.distance[vid],
                                    self.field.max_depth)

            outline, width = "", 0
            if vid in route_set:
                outline, width = "#D97706", max(1, self._zs(sp(2)))
            if vid == self.wave_source:
                outline, width = "#2563EB", max(1, self._zs(sp(3)))
            if vid == self.selected_target:
                outline, width = "#DC2626", max(1, self._zs(sp(3)))

            self.canvas.create_oval(
                x - radius, py - radius, x + radius, py + radius,
                fill=fill, outline=outline or fill, width=width,
                tags=("vx", vid))

        self.canvas.configure(
            scrollregion=(0, 0, int(content_w * z), int(content_h * z)))

    # ----- Масштаб -----

    def _apply_zoom(self, value: float) -> None:
        self._zoom = max(0.15, min(3.0, value))
        self._draw_field()

    def _zoom_in(self) -> None:
        self._apply_zoom(self._zoom * 1.25)

    def _zoom_out(self) -> None:
        self._apply_zoom(self._zoom / 1.25)

    def _zoom_reset(self) -> None:
        self._apply_zoom(1.0)

    def _zoom_fit(self) -> None:
        """Вписывает поле волны в видимую область холста."""
        width, height = self._content
        if width <= 0 or height <= 0:
            return
        try:
            available_w = max(self.canvas.winfo_width(), 100)
            available_h = max(self.canvas.winfo_height(), 100)
        except Exception:
            return
        self._apply_zoom(min(available_w / width, available_h / height))

    def _on_canvas_configure(self, event) -> None:
        """Первое получение размеров холста — вписываем схему в окно."""
        if self._fitted or event.width < 50 or event.height < 50:
            return
        self._fitted = True
        self._zoom_fit()

    def _on_wheel_zoom(self, event) -> None:
        self._apply_zoom(self._zoom * (1.1 if event.delta > 0 else 1 / 1.1))


    def _on_canvas_click(self, event) -> None:
        """Выбор вершины на поле волны."""
        x = self.canvas.canvasx(event.x)
        y = self.canvas.canvasy(event.y)
        nearest = None
        best = sp(12) ** 2
        for vid, (vx, vy) in self.vpos.items():
            d = (vx - x) ** 2 + (vy - y) ** 2
            if d < best:
                best, nearest = d, vid
        if nearest:
            self.selected_target = nearest
            self._alt_index = 0
            self._show_route(nearest)
            self._draw_field()

    # ==================================================================
    # Маршрут
    # ==================================================================

    def _current_route(self) -> List[str]:
        """Маршрут до выбранной цели с учётом кнопки «Другой маршрут»."""
        if not self.field or not self.selected_target:
            return []
        if self._assessed:
            _, chosen = rank_routes(
                self.field,
                lambda v: getattr(self.assessments.get(v), "V", 0.0) or 0.0)
        else:
            chosen = None

        if self._alt_index == 0:
            return restore_route(self.field, self.selected_target, chosen)

        routes = list(iter_routes(self.field, self.selected_target,
                                  limit=self._alt_index + 1))
        if not routes:
            return []
        return routes[min(self._alt_index, len(routes) - 1)]

    def _next_route(self) -> None:
        if not self.selected_target:
            return
        self._alt_index += 1
        self._show_route(self.selected_target)
        self._draw_field()

    def _clear_route(self) -> None:
        for widget in self._route_box.winfo_children():
            widget.destroy()
        ctk.CTkLabel(self._route_box,
                     text="Выберите цель слева\nили точку на поле волны",
                     font=("Segoe UI", sp(12)), justify="left",
                     text_color=color("text_muted")).pack(anchor="w", pady=sp(20))
        self._route_title.configure(text="Маршрут")

    def _show_route(self, target_id: str) -> None:
        """Разворачивает маршрут по шагам в правой панели."""
        for widget in self._route_box.winfo_children():
            widget.destroy()

        route = self._current_route()
        if not route:
            self._clear_route()
            return

        vertex = self.graph.vertices[target_id]
        total = self.counts.get(target_id, 0)
        self._route_title.configure(text=f"Маршрут · шагов {len(route) - 1}")

        ctk.CTkLabel(
            self._route_box,
            text=f"Цель: {vertex.node_name} · {vertex.name}",
            font=("Segoe UI", sp(12), "bold"), justify="left",
            wraplength=sp(340)).pack(anchor="w", pady=(sp(4), sp(2)))
        ctk.CTkLabel(
            self._route_box,
            text=f"Всего кратчайших маршрутов: {total:,}".replace(",", " "),
            font=("Segoe UI", sp(11)), text_color=color("text_secondary")
        ).pack(anchor="w", pady=(0, sp(8)))

        for i, vid in enumerate(route):
            v = self.graph.vertices[vid]
            assessment = self.assessments.get(vid)
            crit = getattr(assessment, "V", 0.0) if assessment else 0.0

            row = ctk.CTkFrame(self._route_box, fg_color=color("surface"),
                               corner_radius=sp(5))
            row.pack(fill=tk.X, pady=sp(2))

            marker = "ω" if vid == self.wave_source else f"χ.{i}"
            ctk.CTkLabel(row, text=marker, width=sp(42),
                         font=("Consolas", sp(11), "bold"),
                         text_color=color("warning")).pack(
                side=tk.LEFT, padx=(sp(8), 0), pady=sp(5))

            box = ctk.CTkFrame(row, fg_color="transparent")
            box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=sp(6))
            ctk.CTkLabel(box, text=f"{v.node_name} · {v.name}"[:46],
                         font=("Segoe UI", sp(11)), anchor="w",
                         justify="left").pack(anchor="w")

            details = f"{v.identifier}   {v.role}"
            if crit > 0:
                cve = getattr(assessment, "cve_id", "")
                bdu = getattr(assessment, "bdu_id", "")
                details += f"   V {crit:.2f}"
                if cve:
                    details += f"   {cve}"
                if bdu:
                    details += f"   {bdu}"
            ctk.CTkLabel(box, text=details, font=("Segoe UI", sp(10)),
                         text_color=color("text_muted"), anchor="w",
                         justify="left").pack(anchor="w")

    # ==================================================================
    # Оценка критичности
    # ==================================================================

    def _run_assessment(self) -> None:
        """Ищет уязвимости для всех компонентов и считает V по методике."""
        self._assess_btn.configure(state="disabled", text="Идёт поиск…")
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                from database.bdu_db import BDUDatabase
                from database.cve_db import CVEDatabase
                from models.fstec_criticality import assess_component
                from utils.cpe_utils import (extract_cpe_components,
                                             get_protocol_cpe)
                from utils.level_filter import filter_cves_by_level

                cve_db = CVEDatabase()
                bdu_db = BDUDatabase()

                # Один и тот же компонент встречается на многих узлах —
                # результат кешируется по (уровень, имя), иначе поиск
                # занял бы минуты вместо секунд
                cache: Dict[Tuple[str, str], Tuple[list, dict]] = {}

                internet_facing = {
                    n.id for n in self.board.nodes
                    if n.type in ("Router", "Internet")
                }

                items = list(self.graph.vertices.items())
                for index, (vid, vertex) in enumerate(items):
                    if index % 10 == 0:
                        q.put(("progress", index + 1, len(items)))

                    if vertex.is_entry_point:
                        continue

                    key = (vertex.level_code, vertex.name)
                    if key in cache:
                        cves, bdu_records = cache[key]
                    else:
                        cves, bdu_records = self._lookup(
                            vertex, cve_db, bdu_db, extract_cpe_components,
                            get_protocol_cpe, filter_cves_by_level)
                        cache[key] = (cves, bdu_records)

                    if not cves:
                        continue

                    assessment = assess_component(
                        vertex.node_type, cves,
                        is_internet_facing=vertex.node_id in internet_facing,
                        bdu_records=bdu_records)
                    q.put(("vertex", vid, assessment, _cwe_set(cves)))

                q.put(("done",))
            except Exception as exc:      # noqa: BLE001 — показываем пользователю
                q.put(("error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self._poll(q)

    @staticmethod
    def _lookup(vertex, cve_db, bdu_db, extract_cpe, protocol_cpe,
                level_filter):
        """Ищет уязвимости одного компонента с отбором по уровню."""
        raw = []
        if vertex.component_type == "protocol":
            cpe = protocol_cpe(vertex.name)
            if cpe:
                raw = cve_db.get_cves_for_component(cpe["vendor"],
                                                    cpe["product"])
        elif vertex.component_type in ("hardware", "software", "peripheral"):
            key = (vertex.name.split(":", 1)[1].strip()
                   if ":" in vertex.name else vertex.name)
            cpe = extract_cpe(key)
            if cpe and cpe.get("vendor"):
                raw = cve_db.get_cves_for_component(
                    cpe["vendor"], cpe.get("product"), cpe.get("version"))

        if not raw:
            return [], {}

        cves = level_filter(raw, vertex.level_code, vertex.name, limit=10)
        if not cves:
            return [], {}

        records = {}
        if getattr(bdu_db, "available", False):
            records = bdu_db.get_many_by_cve(
                [c.get("cve_id", "") for c in cves])
        return cves, records

    def _poll(self, q: queue.Queue) -> None:
        """Забирает результаты из фонового потока (Python 3.13 safe)."""
        try:
            while True:
                message = q.get_nowait()
                kind = message[0]

                if kind == "progress":
                    done, total = message[1], message[2]
                    self._status.configure(
                        text=f"Поиск уязвимостей… {done} / {total}",
                        text_color=color("text_secondary"))

                elif kind == "vertex":
                    _, vid, assessment, cwes = message
                    self.assessments[vid] = assessment
                    self.cwe_map[vid] = cwes

                elif kind == "done":
                    self._assessed = True
                    self._assess_btn.configure(
                        state="normal", text="Пересчитать")
                    self._build_stages()
                    self._fill_targets()
                    self._draw_field()
                    self._legend.configure(
                        text="цвет — уровень критичности, размер — V")
                    return

                elif kind == "error":
                    self._assess_btn.configure(
                        state="normal", text="Оценить критичность")
                    self._status.configure(text=f"Ошибка: {message[1]}",
                                           text_color=color("danger"))
                    return
        except queue.Empty:
            pass

        try:
            self.window.after(120, lambda: self._poll(q))
        except Exception:
            pass

    # ==================================================================
    # Этапы ККА
    # ==================================================================

    def _build_stages(self) -> None:
        """Считает вектор ККА и заполняет вкладку этапов."""
        self.stages = build_kka_vector(
            self.graph.adjacency,
            self.entry_id,
            self.assessments,
            cwe_of=lambda v: self.cwe_map.get(v, set()),
            criticality_of=lambda v: getattr(
                self.assessments.get(v), "V", 0.0) or 0.0,
            node_of=lambda v: self.graph.vertices[v].node_id,
        )

        for widget in self._stages_box.winfo_children():
            widget.destroy()

        for stage in self.stages:
            card = ctk.CTkFrame(self._stages_box, fg_color=color("surface"),
                                corner_radius=sp(6))
            card.pack(fill=tk.X, pady=sp(4))

            head = ctk.CTkFrame(card, fg_color="transparent")
            head.pack(fill=tk.X, padx=sp(10), pady=(sp(8), sp(2)))
            ctk.CTkLabel(
                head, text=f"Этап {stage.profile.number}",
                font=("Segoe UI", sp(12), "bold"),
                text_color=stage.profile.color).pack(side=tk.LEFT)
            ctk.CTkLabel(
                head, text=stage.profile.attack_type,
                font=("Segoe UI", sp(10)),
                text_color=color("text_muted")).pack(side=tk.RIGHT)

            ctk.CTkLabel(
                card, text=stage.profile.name, font=("Segoe UI", sp(11)),
                anchor="w", justify="left", wraplength=sp(320)).pack(
                anchor="w", padx=sp(10))

            if stage.reachable:
                target = self.graph.vertices[stage.target_id]
                ctk.CTkLabel(
                    card,
                    text=f"ЦО №{stage.profile.number}: "
                         f"{target.node_name} · {target.name}",
                    font=("Segoe UI", sp(11), "bold"), anchor="w",
                    justify="left", wraplength=sp(320)).pack(
                    anchor="w", padx=sp(10), pady=(sp(4), 0))
                ctk.CTkLabel(
                    card,
                    text=f"шагов {stage.steps} · маршрутов "
                         f"{stage.route_count:,}".replace(",", " ")
                         + f" · V {stage.criticality:.2f}",
                    font=("Segoe UI", sp(10)),
                    text_color=color("text_secondary"), anchor="w").pack(
                    anchor="w", padx=sp(10))
                ctk.CTkLabel(
                    card, text=stage.profile.expected_result,
                    font=("Segoe UI", sp(10)), anchor="w", justify="left",
                    wraplength=sp(320),
                    text_color=color("text_muted")).pack(
                    anchor="w", padx=sp(10), pady=(0, sp(4)))

                ctk.CTkButton(
                    card, text="Показать маршрут", height=sp(24),
                    font=("Segoe UI", sp(10)),
                    fg_color=color("ghost_bg"),
                    hover_color=color("ghost_hover"),
                    text_color=color("text_primary"),
                    command=lambda s=stage: self._show_stage(s)).pack(
                    anchor="w", padx=sp(10), pady=(0, sp(8)))
            else:
                ctk.CTkLabel(
                    card, text=stage.note, font=("Segoe UI", sp(10)),
                    anchor="w", justify="left", wraplength=sp(320),
                    text_color=color("danger")).pack(
                    anchor="w", padx=sp(10), pady=(sp(4), sp(8)))

    def _show_stage(self, stage: KKAStage) -> None:
        """Показывает маршрут выбранного этапа на поле и справа."""
        # Волна для этапа пускается из его собственного начала, поэтому
        # переключается всё окно целиком: и поле, и список целей.
        # Иначе номера шагов и счётчики маршрутов в списке остались бы
        # от прежней волны и не совпадали бы с показанным маршрутом
        self.wave_source = stage.source_id
        self.field = propagate(self.graph.adjacency, [stage.source_id])
        self.counts = count_routes(self.field)
        self.selected_target = stage.target_id
        self._alt_index = 0
        self._fill_targets()
        self._show_route(stage.target_id)
        self._draw_field()

    # ==================================================================

    def _close(self) -> None:
        try:
            self.window.destroy()
        except Exception:
            pass


def show_kka_routes(parent, board) -> None:
    """Открывает окно расчёта маршрутов распространения УБИ."""
    if not board.nodes:
        messagebox.showinfo("Маршруты УБИ", "Нет узлов для анализа.")
        return
    KKARoutesView(parent, board)
