"""
Окно «Общий граф угроз» — граф компонентов всей топологии.

Чем отличается от графа одного узла
-----------------------------------
`views/threat_graph_view.py` рисует граф одного узла: вершины-компоненты
по уровням, метки ЦО и ТрО. Эталон для него — Grafy_1_ARM.jpg.

Здесь то же самое, но для всей сети сразу: каждый узел становится блоком,
блоки стоят друг под другом, а между ними идут физические связи —
единственные рёбра, выводящие угрозу за пределы узла. Эталон — общая схема
Obschaya_skhema.jpg, где маршрут χ3 спускается по стеку маршрутизатора,
пересекает кабель и поднимается по стеку сервера.

Раскладка блока повторяет эталонный граф узла
---------------------------------------------
    строка 0   ω → f → z → l → t → d → r → q     стек ЭМВОС
    строка 1   i · w · p · v                     подсистемы ядра ОС
    строка 2   а                                 аппаратный уровень
    строка 3   h                                 пользовательский уровень

Масштаб
-------
На восьми узлах это больше четырёхсот вершин, поэтому схема по умолчанию
вписывается в окно, а рассмотреть подробности можно зумом или колесом
мыши с Ctrl.
"""

import tkinter as tk
from collections import defaultdict
from tkinter import messagebox
from typing import Dict, List, Optional, Tuple

import customtkinter as ctk

from models.topology_graph import TopologyGraph, build_topology_graph
from models.wave import propagate, restore_route
from utils.theme import c, color, sp

__all__ = ["show_threat_graph_all"]


# Порядок уровней по строкам блока — как на эталонном графе узла
ROW_LEVELS: List[List[str]] = [
    ["ω", "f", "z", "l", "t", "d", "r", "q"],   # стек ЭМВОС
    ["i", "w", "p", "v"],                        # подсистемы ядра ОС
    ["a"],                                       # аппаратный уровень
    ["h"],                                       # пользовательский уровень
]

LEVEL_TITLES = {
    "ω": "Точки\nвхода",
    "f": "Физический",
    "z": "Канальный",
    "l": "Сетевой",
    "t": "Транспортный",
    "d": "Сеансовый",
    "r": "Представления",
    "q": "Прикладной",
    "i": "Драйверы",
    "w": "Разграничение\nдоступа",
    "p": "Управление\nфайлами",
    "v": "Управление\nпроцессами",
    "a": "Аппаратный уровень",
    "h": "Пользовательский уровень",
}

LEVEL_COLORS = {
    "ω": "#B45309", "f": "#0E7490", "z": "#0891B2", "l": "#0D9488",
    "t": "#65A30D", "d": "#CA8A04", "r": "#EA580C", "q": "#DC2626",
    "i": "#7C3AED", "w": "#8B5CF6", "p": "#A78BFA", "v": "#C4B5FD",
    "a": "#475569", "h": "#0F766E",
}

# Геометрия в масштабе 1:1
SUB_COL_W = 122      # ширина одной колонки вершин
V_SPACE = 44         # шаг между вершинами в колонке
V_RAD = 13           # радиус вершины
MAX_PER_COL = 6      # больше — уровень разбивается на несколько колонок
ROW_GAP = 60         # зазор между строками блока
BLOCK_GAP_X = 90     # зазор между блоками по горизонтали
BLOCK_GAP_Y = 104    # зазор между блоками по вертикали
PAD_L = 150          # слева — подпись узла
PAD_T = 56
TARGET_RATIO = 1.45  # к какому соотношению сторон стремится вся схема


class ThreatGraphAllView:
    """Граф угроз всей топологии."""

    def __init__(self, parent, board):
        self.parent = parent
        self.board = board
        self.graph: TopologyGraph = build_topology_graph(board)

        if not self.graph.vertices:
            messagebox.showinfo("Общий граф угроз", "Нет узлов для анализа.")
            return

        # Раскладка в масштабе 1:1
        self.pos: Dict[str, Tuple[int, int]] = {}
        # узел, имя, x, y, ширина, высота
        self.blocks: List[Tuple[str, str, int, int, int, int]] = []
        self._column_tops: Dict[Tuple[str, str, int], int] = {}
        self._content = (0, 0)

        self.vpos: Dict[str, Tuple[int, int]] = {}          # с учётом зума
        self._zoom = 1.0
        self._fitted = False
        self.selected: str = ""
        self.route: List[str] = []
        self._show_edges = True

        self.window = ctk.CTkToplevel(parent)
        self.window.title("Общий граф угроз — вся топология")
        self.window.transient(parent)
        self.window.configure(fg_color=color("dialog_bg"))
        self.window.protocol("WM_DELETE_WINDOW", self._close)

        self._layout()
        self._build_ui()

        self.window.update_idletasks()
        try:
            self.window.state("zoomed")
        except Exception:
            self.window.geometry(
                f"{self.window.winfo_screenwidth()}x"
                f"{self.window.winfo_screenheight()}+0+0")

        self._draw()


    # ==================================================================
    # Раскладка
    # ==================================================================

    def _node_levels(self, node_id: str) -> Dict[str, List[str]]:
        """Компоненты узла, сгруппированные по уровням.

        Точки входа выделяются в отдельный псевдоуровень «ω»: на эталонном
        графе они стоят самостоятельной колонкой слева от физического уровня.
        """
        grouped: Dict[str, List[str]] = defaultdict(list)
        for vid in self.graph.by_node.get(node_id, []):
            vertex = self.graph.vertices[vid]
            key = "ω" if vertex.is_entry_point else vertex.level_code
            grouped[key].append(vid)
        for ids in grouped.values():
            ids.sort(key=lambda v: self.graph.vertices[v].identifier)
        return grouped

    @staticmethod
    def _plan_row(grouped: Dict[str, List[str]],
                  levels: List[str]) -> Tuple[List[Tuple[str, int, int]], int, int]:
        """Планирует одну строку блока.

        Уровень с большим числом компонентов разбивается на несколько колонок,
        иначе блок вытягивается в узкую ленту и схема перестаёт помещаться
        в экран по высоте.

        Returns:
            (описание уровней, ширина строки, высота строки), где описание —
            список кортежей «уровень, число колонок, вершин в колонке»
        """
        plan: List[Tuple[str, int, int]] = []
        width = 0
        height = 0
        for lvl in levels:
            column = grouped.get(lvl)
            if not column:
                continue
            sub_cols = max(1, -(-len(column) // MAX_PER_COL))   # ceil
            per_col = -(-len(column) // sub_cols)
            plan.append((lvl, sub_cols, per_col))
            width += sub_cols * SUB_COL_W
            height = max(height, per_col * V_SPACE)
        return plan, width, height

    def _layout_block(self, node_id: str) -> Tuple[Dict[str, Tuple[int, int]], int, int]:
        """Раскладывает один узел: строки уровней, как на эталонном графе."""
        grouped = self._node_levels(node_id)
        rows = [self._plan_row(grouped, levels) for levels in ROW_LEVELS]
        rows = [r for r in rows if r[0]]
        if not rows:
            return {}, 0, 0

        block_w = max(width for _plan, width, _height in rows)
        positions: Dict[str, Tuple[int, int]] = {}
        y = 0

        for plan, width, height in rows:
            x = (block_w - width) // 2      # строка центрируется в блоке
            for lvl, sub_cols, per_col in plan:
                column = grouped[lvl]
                for index, vid in enumerate(column):
                    sub = index // per_col
                    within = index % per_col
                    count = min(per_col, len(column) - sub * per_col)
                    offset = ((per_col - count) * V_SPACE) // 2
                    positions[vid] = (x + sub * SUB_COL_W + SUB_COL_W // 2,
                                      y + offset + within * V_SPACE)
                x += sub_cols * SUB_COL_W
            y += height + ROW_GAP

        return positions, block_w, y - ROW_GAP

    def _layout(self) -> None:
        """Считает положение всех вершин в масштабе 1:1.

        Блоки узлов раскладываются сеткой, а не в один столбец: восемь узлов
        друг под другом дают ленту с соотношением сторон около 1:5, которая
        при вписывании в экран сжимается до нечитаемого масштаба.
        Число колонок подбирается так, чтобы схема получилась близкой
        по пропорциям к экрану.
        """
        self.pos.clear()
        self.blocks.clear()

        prepared = []
        for node in self.board.nodes:
            if not self.graph.by_node.get(node.id):
                continue
            positions, width, height = self._layout_block(node.id)
            if positions:
                prepared.append((node.id, node.name, positions, width, height))

        if not prepared:
            self._content = (0, 0)
            return

        cell_w = max(width for *_rest, width, _h in prepared) + BLOCK_GAP_X
        cell_h = max(height for *_rest, _w, height in prepared) + BLOCK_GAP_Y

        # Подбираем число колонок под целевое соотношение сторон
        count = len(prepared)
        best_cols, best_score = 1, None
        for cols in range(1, count + 1):
            rows = -(-count // cols)
            ratio = (cols * cell_w) / (rows * cell_h)
            score = abs(ratio - TARGET_RATIO)
            if best_score is None or score < best_score:
                best_cols, best_score = cols, score

        for index, (node_id, name, positions, width, height) in enumerate(prepared):
            col, row = index % best_cols, index // best_cols
            origin_x = PAD_L + col * cell_w
            origin_y = PAD_T + row * cell_h
            for vid, (x, y) in positions.items():
                self.pos[vid] = (origin_x + x, origin_y + y)
            self.blocks.append((node_id, name, origin_x, origin_y, width, height))

        rows = -(-count // best_cols)
        self._content = (PAD_L + best_cols * cell_w,
                         PAD_T + rows * cell_h)

        # Верхняя вершина каждой колонки — к ней крепится подпись уровня.
        # Считается один раз при раскладке: перебирать все вершины на каждой
        # перерисовке было бы квадратично по их числу
        self._column_tops: Dict[Tuple[str, str, int], int] = {}
        for vid, (x, y) in self.pos.items():
            vertex = self.graph.vertices[vid]
            lvl = "ω" if vertex.is_entry_point else vertex.level_code
            key = (vertex.node_id, lvl, x)
            if key not in self._column_tops or y < self._column_tops[key]:
                self._column_tops[key] = y

    # ==================================================================
    # Интерфейс
    # ==================================================================

    def _build_ui(self) -> None:
        root = ctk.CTkFrame(self.window, fg_color="transparent")
        root.pack(fill=tk.BOTH, expand=True, padx=sp(10), pady=sp(10))

        bar = ctk.CTkFrame(root, fg_color=color("card_bg"), corner_radius=sp(8))
        bar.pack(fill=tk.X)
        inner = ctk.CTkFrame(bar, fg_color="transparent")
        inner.pack(fill=tk.X, padx=sp(12), pady=sp(8))

        ctk.CTkLabel(
            inner,
            text=f"Узлов {len(self.blocks)} · вершин {len(self.graph.vertices)} "
                 f"· рёбер {self.graph.edge_count}",
            font=("Segoe UI", sp(12), "bold")).pack(side=tk.LEFT)

        self._edges_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            inner, text="связи внутри узлов", variable=self._edges_var,
            font=("Segoe UI", sp(11)), command=self._toggle_edges,
            checkbox_width=sp(16), checkbox_height=sp(16)).pack(
            side=tk.LEFT, padx=sp(20))

        ctk.CTkLabel(inner, text="Маршрут из точки входа:",
                     font=("Segoe UI", sp(11))).pack(side=tk.LEFT)
        self._entry_names = {"— не показывать —": ""}
        for vid in self.graph.entry_points:
            v = self.graph.vertices[vid]
            self._entry_names[f"{v.node_name} · {v.name}"] = vid
        self._entry_var = ctk.StringVar(value="— не показывать —")
        ctk.CTkOptionMenu(
            inner, values=list(self._entry_names), variable=self._entry_var,
            width=sp(250), font=("Segoe UI", sp(11)),
            command=self._on_entry_changed).pack(side=tk.LEFT, padx=sp(8))

        for text, command, width in (("−", self._zoom_out, 30),
                                     ("+", self._zoom_in, 30),
                                     ("1:1", self._zoom_reset, 44),
                                     ("Вписать", self._zoom_fit, 74)):
            ctk.CTkButton(inner, text=text, width=sp(width), height=sp(24),
                          font=("Segoe UI", sp(11)),
                          fg_color=color("ghost_bg"),
                          hover_color=color("ghost_hover"),
                          text_color=color("text_primary"),
                          command=command).pack(side=tk.RIGHT, padx=sp(2))

        body = ctk.CTkFrame(root, fg_color="transparent")
        body.pack(fill=tk.BOTH, expand=True, pady=(sp(8), 0))

        holder = ctk.CTkFrame(body, fg_color=color("card_bg"),
                              corner_radius=sp(8))
        holder.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        wrap = tk.Frame(holder, bg=c("canvas_bg"))
        wrap.pack(fill=tk.BOTH, expand=True, padx=sp(8), pady=sp(8))

        self.canvas = tk.Canvas(wrap, bg=c("canvas_bg"), highlightthickness=0)
        hsb = ttk_scroll(wrap, "horizontal", self.canvas.xview)
        vsb = ttk_scroll(wrap, "vertical", self.canvas.yview)
        self.canvas.configure(xscrollcommand=hsb.set, yscrollcommand=vsb.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        self.canvas.bind("<Button-1>", self._on_click)
        # Вписываем схему, когда холст впервые получит реальные размеры.
        # Отложенный вызов через after ненадёжен: окно может быть ещё
        # не размечено, и winfo_width() возвращает 1
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind("<Control-MouseWheel>", self._on_wheel_zoom)
        self.canvas.bind(
            "<MouseWheel>",
            lambda e: self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units"))
        self.canvas.bind(
            "<Shift-MouseWheel>",
            lambda e: self.canvas.xview_scroll(-1 if e.delta > 0 else 1, "units"))

        # Панель сведений о выбранном компоненте
        side = ctk.CTkFrame(body, fg_color=color("card_bg"),
                            corner_radius=sp(8), width=sp(320))
        side.pack(side=tk.LEFT, fill=tk.Y, padx=(sp(8), 0))
        side.pack_propagate(False)
        ctk.CTkLabel(side, text="Компонент", font=("Segoe UI", sp(13), "bold")
                     ).pack(anchor="w", padx=sp(12), pady=(sp(10), sp(4)))
        self._info = ctk.CTkScrollableFrame(side, fg_color="transparent")
        self._info.pack(fill=tk.BOTH, expand=True, padx=sp(6), pady=(0, sp(8)))
        self._clear_info()

    def _clear_info(self) -> None:
        for widget in self._info.winfo_children():
            widget.destroy()
        ctk.CTkLabel(self._info, text="Щёлкните вершину графа",
                     font=("Segoe UI", sp(12)),
                     text_color=color("text_muted")).pack(anchor="w", pady=sp(16))

    # ==================================================================
    # Отрисовка
    # ==================================================================

    def _zs(self, value: float) -> int:
        return max(1, int(value * self._zoom))

    def _draw(self) -> None:
        self.canvas.delete("all")
        self.vpos = {vid: (int(x * self._zoom), int(y * self._zoom))
                     for vid, (x, y) in self.pos.items()}

        z = self._zoom
        detailed = z >= 0.5         # подписи имеют смысл только крупно
        route_set = set(self.route)
        route_pairs = {(self.route[i], self.route[i + 1])
                       for i in range(len(self.route) - 1)}

        # --- Блоки узлов ---
        for _node_id, node_name, ox, oy, width, height in self.blocks:
            x1 = int(ox * z) - self._zs(24)
            y1 = int(oy * z) - self._zs(30)
            x2 = int((ox + width) * z) + self._zs(24)
            y2 = int((oy + height) * z) + self._zs(24)
            self.canvas.create_rectangle(
                x1, y1, x2, y2, outline=c("divider"),
                width=max(1, self._zs(1)), dash=(4, 3))
            self.canvas.create_text(
                x1 + self._zs(10), y1 + self._zs(12), anchor="w",
                text=node_name, font=("Segoe UI", max(7, self._zs(12)), "bold"),
                fill=c("text_primary"))

        # --- Рёбра ---
        if self._show_edges:
            drawn = set()
            for source, targets in self.graph.adjacency.items():
                if source not in self.vpos:
                    continue
                x1, y1 = self.vpos[source]
                same_node = self.graph.vertices[source].node_id
                for target in targets:
                    if target not in self.vpos:
                        continue
                    key = (source, target) if source < target else (target, source)
                    if key in drawn:
                        continue
                    drawn.add(key)

                    x2, y2 = self.vpos[target]
                    crosses = self.graph.vertices[target].node_id != same_node
                    on_route = ((source, target) in route_pairs
                                or (target, source) in route_pairs)

                    if on_route:
                        fill, width = "#D97706", max(2, self._zs(3))
                    elif crosses:
                        fill, width = "#2563EB", max(1, self._zs(2))
                    else:
                        fill, width = c("divider"), 1

                    self.canvas.create_line(x1, y1, x2, y2,
                                            fill=fill, width=width)

        # --- Подписи уровней: над верхней вершиной каждой колонки ---
        # Колонок у разных узлов разное число, поэтому подпись ставится
        # по фактическому положению вершин, а не по общей сетке
        if detailed:
            for (_node_id, lvl, cx), cy in self._column_tops.items():
                title = LEVEL_TITLES.get(lvl, lvl).replace(chr(10), " ")
                self.canvas.create_text(
                    int(cx * z), int(cy * z) - self._zs(V_RAD + 24),
                    text=title[:18],
                    font=("Segoe UI", max(6, self._zs(8)), "bold"),
                    fill=LEVEL_COLORS.get(lvl, c("text_muted")))

        # --- Вершины ---
        radius = max(2, self._zs(V_RAD))
        for vid, (x, y) in self.vpos.items():
            vertex = self.graph.vertices[vid]
            key = "ω" if vertex.is_entry_point else vertex.level_code
            base = LEVEL_COLORS.get(key, "#64748B")

            # Пунктир — только транзит, сплошная — цель. Как на плакате
            dash = (4, 3) if (vertex.is_transit and not vertex.is_target) else ()
            outline, width = base, max(1, self._zs(2))
            if vid in route_set:
                outline, width = "#D97706", max(2, self._zs(3))
            if vid == self.selected:
                outline, width = "#DC2626", max(2, self._zs(4))

            self.canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill=c("card_bg"), outline=outline, width=width,
                dash=dash, tags=("vx", vid))

            if detailed:
                self.canvas.create_text(
                    x, y, text=vertex.identifier[:9],
                    font=("Segoe UI", max(6, self._zs(8))),
                    fill=c("text_primary"))
                self.canvas.create_text(
                    x, y + radius + self._zs(11),
                    text=vertex.name[:22],
                    font=("Segoe UI", max(6, self._zs(8))),
                    fill=c("text_secondary"))
                self.canvas.create_text(
                    x, y - radius - self._zs(9), text=vertex.role,
                    font=("Segoe UI", max(6, self._zs(7)), "bold"),
                    fill=base)

        width_px = int(self._content[0] * z)
        height_px = int(self._content[1] * z)
        self.canvas.configure(scrollregion=(0, 0, width_px, height_px))

    # ==================================================================
    # Взаимодействие
    # ==================================================================

    def _on_click(self, event) -> None:
        x = self.canvas.canvasx(event.x)
        y = self.canvas.canvasy(event.y)
        best, nearest = (self._zs(V_RAD) + sp(6)) ** 2, None
        for vid, (vx, vy) in self.vpos.items():
            distance = (vx - x) ** 2 + (vy - y) ** 2
            if distance < best:
                best, nearest = distance, vid
        if not nearest:
            return
        self.selected = nearest
        self._show_info(nearest)
        self._draw()

    def _show_info(self, vid: str) -> None:
        vertex = self.graph.vertices[vid]
        for widget in self._info.winfo_children():
            widget.destroy()

        rows = [
            ("Узел", vertex.node_name),
            ("Идентификатор", vertex.identifier),
            ("Наименование", vertex.name),
            ("Уровень", LEVEL_TITLES.get(
                "ω" if vertex.is_entry_point else vertex.level_code,
                vertex.level_code).replace("\n", " ")),
            ("Роль", vertex.role or "—"),
            ("Тип", vertex.component_type),
        ]
        neighbours = self.graph.adjacency.get(vid, [])
        external = [n for n in neighbours
                    if self.graph.vertices[n].node_id != vertex.node_id]
        rows.append(("Связей", str(len(neighbours))))
        if external:
            rows.append(("Из них между узлами", str(len(external))))

        for title, value in rows:
            box = ctk.CTkFrame(self._info, fg_color=color("surface"),
                               corner_radius=sp(5))
            box.pack(fill=tk.X, pady=sp(2))
            ctk.CTkLabel(box, text=title, font=("Segoe UI", sp(10)),
                         text_color=color("text_muted"), anchor="w").pack(
                anchor="w", padx=sp(8), pady=(sp(4), 0))
            ctk.CTkLabel(box, text=value, font=("Segoe UI", sp(11)),
                         anchor="w", justify="left", wraplength=sp(260)).pack(
                anchor="w", padx=sp(8), pady=(0, sp(4)))

    def _on_entry_changed(self, label: str) -> None:
        """Накладывает маршрут от выбранной точки входа до выбранной вершины."""
        entry = self._entry_names.get(label, "")
        if not entry:
            self.route = []
        else:
            field = propagate(self.graph.adjacency, [entry])
            target = self.selected if self.selected in field.distance else ""
            if not target:
                # Без выбранной цели показываем путь до самой дальней вершины
                target = max(field.distance, key=lambda v: field.distance[v])
            self.route = restore_route(field, target)
        self._draw()

    def _toggle_edges(self) -> None:
        self._show_edges = bool(self._edges_var.get())
        self._draw()

    # ----- Масштаб -----

    def _apply_zoom(self, value: float) -> None:
        self._zoom = max(0.12, min(3.0, value))
        self._draw()

    def _zoom_in(self) -> None:
        self._apply_zoom(self._zoom * 1.25)

    def _zoom_out(self) -> None:
        self._apply_zoom(self._zoom / 1.25)

    def _zoom_reset(self) -> None:
        self._apply_zoom(1.0)

    def _zoom_fit(self) -> None:
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

    def _close(self) -> None:
        try:
            self.window.destroy()
        except Exception:
            pass


def ttk_scroll(parent, orient, command):
    """Полоса прокрутки в оформлении ttk."""
    from tkinter import ttk
    return ttk.Scrollbar(parent, orient=orient, command=command)


def show_threat_graph_all(parent, board) -> None:
    """Открывает общий граф угроз всей топологии."""
    if not board.nodes:
        messagebox.showinfo("Общий граф угроз", "Нет узлов для анализа.")
        return
    ThreatGraphAllView(parent, board)
