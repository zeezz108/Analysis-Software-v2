"""
Визуализация графа угроз — многорядная раскладка по шаблону.

Ряд 0: ω → f → z → l → t → d → r → q  (ЭМВОС, без разрывов)
Ряд 1: i → w → p → v (ОС ядро) + a (сетевые приложения)
Ряд 2: h₁ h₂ ... (аппаратный, горизонтально)
Ряд 3: u₁ u₂ ... (пользовательский, горизонтально)
"""

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
import math
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

from models.node import Node
from models.threat_graph import (
    ThreatGraphBuilder, ThreatGraph, GraphVertex, GraphEdge,
    GraphLevel, LEVEL_LABELS, ThreatType,
)
from utils.theme import color, c, sp, current_mode


# ============================================================================
# Раскладка: (ряд, столбец)
# ============================================================================

LAYOUT_MAP = {
    # Ряд 0 — основная цепочка ЭМВОС (БЕЗ разрыва)
    GraphLevel.ENTRY_POINT:    (0, 0),
    GraphLevel.PHYSICAL:       (0, 1),
    GraphLevel.DATA_LINK:      (0, 2),
    GraphLevel.NETWORK:        (0, 3),
    GraphLevel.TRANSPORT:      (0, 4),
    GraphLevel.SESSION:        (0, 5),
    GraphLevel.PRESENTATION:   (0, 6),
    GraphLevel.APPLICATION:    (0, 7),
    # Ряд 1 — подсистемы ОС (под Network–Session) + Сетевые приложения (справа)
    GraphLevel.DRIVERS:        (1, 2),
    GraphLevel.ACCESS_CONTROL: (1, 3),
    GraphLevel.FILE_SYSTEM:    (1, 4),
    GraphLevel.PROCESS_MGMT:   (1, 5),
    GraphLevel.NET_APPS:       (1, 7),   # под Application — соединяются ВВЕРХ к Transport
    # Ряд 2 — аппаратный
    GraphLevel.HARDWARE:       (2, 0),
    # Ряд 3 — пользовательский
    GraphLevel.USER:           (3, 0),
}

COL_W = 185
ROW_GAP = 100
V_SPACE = 75           # расстояние между вершинами в столбце
V_RAD = 24
HDR_H = 44
PAD_T = 80
PAD_L = 55
PAD_B = 35

LEVEL_COLORS = {
    GraphLevel.ENTRY_POINT: "#F59E0B", GraphLevel.PHYSICAL: "#EF4444",
    GraphLevel.DATA_LINK: "#F97316", GraphLevel.NETWORK: "#22C55E",
    GraphLevel.DRIVERS: "#6366F1", GraphLevel.ACCESS_CONTROL: "#8B5CF6",
    GraphLevel.FILE_SYSTEM: "#A855F7", GraphLevel.PROCESS_MGMT: "#D946EF",
    GraphLevel.TRANSPORT: "#0EA5E9", GraphLevel.SESSION: "#14B8A6",
    GraphLevel.PRESENTATION: "#10B981", GraphLevel.APPLICATION: "#3B82F6",
    GraphLevel.NET_APPS: "#6366F1", GraphLevel.HARDWARE: "#78716C",
    GraphLevel.USER: "#A8A29E",
}


def _ecolor(threats):
    if not threats: return "#9CA3AF"
    if len(threats) == 1:
        if threats[0] == ThreatType.CO: return "#EF4444"
        if threats[0] == ThreatType.TRO: return "#3B82F6"
        if threats[0] == ThreatType.PO: return "#22C55E"
    return "#F59E0B"


class ThreatGraphView:

    def __init__(self, parent, node: Node):
        self.parent = parent
        self.node = node
        self.vpos: Dict[str, Tuple[float, float]] = {}
        self._zoom = 1.0

        self.graph = ThreatGraphBuilder(node).build()

        self._used = self.graph.get_used_levels()
        self._row_lvls: Dict[int, List[GraphLevel]] = defaultdict(list)
        for lvl in self._used:
            r, c = LAYOUT_MAP.get(lvl, (0, 0))
            self._row_lvls[r].append(lvl)
        for r in self._row_lvls:
            self._row_lvls[r].sort(key=lambda l: LAYOUT_MAP.get(l, (0, 0))[1])

        self.window = ctk.CTkToplevel(parent)
        self.window.title(f"Граф угроз: {node.name}")
        self.window.transient(parent)
        self.window.configure(fg_color=color("dialog_bg"))
        self.window.protocol("WM_DELETE_WINDOW", self._close)

        self._ui()
        self.window.update_idletasks()
        try:
            self.window.state('zoomed')
        except Exception:
            self.window.geometry(
                f"{self.window.winfo_screenwidth()}x{self.window.winfo_screenheight()}+0+0")

        self._layout()
        self._draw()

    def _close(self):
        try: self.window.destroy()
        except: pass

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _ui(self):
        mode = current_mode()
        h = ctk.CTkFrame(self.window, fg_color="transparent")
        h.pack(fill=tk.X, padx=sp(10), pady=(sp(4), 0))
        ctk.CTkLabel(h, text="Граф угроз безопасности",
                     font=("Segoe UI", 20, "bold")).pack(side=tk.LEFT, padx=(sp(8), sp(12)))
        ctk.CTkLabel(h, text=f"{self.node.name} ({self._tru()})",
                     font=("Segoe UI", 14),
                     text_color=color("text_secondary")).pack(side=tk.LEFT)
        ctk.CTkLabel(h, text=f"Вершин: {len(self.graph.vertices)} | Рёбер: {len(self.graph.edges)}",
                     font=("Segoe UI", 12),
                     text_color=color("text_muted")).pack(side=tk.RIGHT, padx=sp(8))

        zf = ctk.CTkFrame(h, fg_color="transparent")
        zf.pack(side=tk.RIGHT, padx=sp(8))
        ctk.CTkButton(zf, text="−", width=sp(30), height=sp(28),
                       command=self._zout).pack(side=tk.LEFT, padx=1)
        self._zlbl = ctk.CTkLabel(zf, text="100%", font=("Segoe UI", 11), width=sp(45))
        self._zlbl.pack(side=tk.LEFT, padx=1)
        ctk.CTkButton(zf, text="+", width=sp(30), height=sp(28),
                       command=self._zin).pack(side=tk.LEFT, padx=1)
        ctk.CTkButton(zf, text="Сброс", width=sp(50), height=sp(28),
                       command=self._zrst).pack(side=tk.LEFT, padx=(4, 0))

        cf = ctk.CTkFrame(self.window)
        cf.pack(fill=tk.BOTH, expand=True, padx=sp(10), pady=(sp(4), sp(2)))
        bg = "#FFFFFF" if mode == "light" else "#131A2B"
        self.cv = tk.Canvas(cf, bg=bg, highlightthickness=0)
        hs = ttk.Scrollbar(cf, orient=tk.HORIZONTAL, command=self.cv.xview)
        vs = ttk.Scrollbar(cf, orient=tk.VERTICAL, command=self.cv.yview)
        self.cv.configure(xscrollcommand=hs.set, yscrollcommand=vs.set)
        hs.pack(side=tk.BOTTOM, fill=tk.X)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self.cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.cv.bind("<Control-MouseWheel>", lambda e: self._zin() if e.delta > 0 else self._zout())
        self.cv.bind("<MouseWheel>", lambda e: self.cv.yview_scroll(int(-e.delta/120), "units"))
        self.cv.bind("<Shift-MouseWheel>", lambda e: self.cv.xview_scroll(int(-e.delta/120), "units"))

        lg = ctk.CTkFrame(self.window, fg_color="transparent")
        lg.pack(fill=tk.X, padx=sp(10), pady=(0, sp(4)))
        ctk.CTkLabel(lg, text="Угрозы:", font=("Segoe UI", 11, "bold")).pack(
            side=tk.LEFT, padx=(sp(8), sp(4)))
        for t, c_ in [("ЦО", "#EF4444"), ("ТрО", "#3B82F6"),
                       ("ПО", "#22C55E"), ("ЦО+ТрО", "#F59E0B")]:
            ctk.CTkFrame(lg, width=sp(10), height=sp(10),
                         corner_radius=sp(5), fg_color=c_).pack(side=tk.LEFT, padx=(sp(10), sp(2)))
            ctk.CTkLabel(lg, text=t, font=("Segoe UI", 11)).pack(side=tk.LEFT, padx=(0, sp(6)))
        ctk.CTkButton(lg, text="Закрыть", width=sp(70), height=sp(26),
                       fg_color=color("danger"), hover_color=color("danger_hover"),
                       command=self._close).pack(side=tk.RIGHT, padx=sp(8))

    # ------------------------------------------------------------------
    # Layout — ВСЕ координаты привязаны к сетке
    # ------------------------------------------------------------------

    def _grid_step_base(self) -> int:
        """Шаг сетки в базовых пикселях (до zoom)."""
        return sp(12)

    def _snap(self, val: float) -> int:
        """Привязывает значение к сетке."""
        g = self._grid_step_base()
        return round(val / g) * g

    def _layout(self):
        g = self._grid_step_base()
        cw = self._snap(sp(COL_W))
        vs_ = self._snap(sp(V_SPACE))
        rg = self._snap(sp(ROW_GAP))

        row_maxv: Dict[int, int] = {}
        for ri in sorted(self._row_lvls):
            row_maxv[ri] = max(
                (len(self.graph.get_vertices_by_level(l)) for l in self._row_lvls[ri]), default=1)

        row_y: Dict[int, int] = {}
        yc = self._snap(sp(PAD_T) + sp(HDR_H) + sp(15))
        for ri in sorted(self._row_lvls):
            row_y[ri] = yc
            h = (row_maxv[ri] - 1) * vs_ + self._snap(sp(V_RAD) * 2 + sp(30))
            yc += h + rg

        for lvl in self._used:
            row, col = LAYOUT_MAP.get(lvl, (0, 0))
            verts = self.graph.get_vertices_by_level(lvl)
            n = len(verts)

            if row >= 2:
                total_cols = 8
                tw = total_cols * cw
                sx = self._snap(sp(PAD_L) + (tw - (n - 1) * cw) // 2)
                y = row_y.get(row, 500)
                for i, v in enumerate(verts):
                    self.vpos[v.id] = (sx + i * cw, y)
            else:
                cx = self._snap(sp(PAD_L) + col * cw + cw // 2)
                mv = row_maxv.get(row, 1)
                off = self._snap(((mv - 1) * vs_ - (n - 1) * vs_) // 2)
                sy = row_y[row] + off
                for i, v in enumerate(verts):
                    self.vpos[v.id] = (cx, sy + i * vs_)

    # ------------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------------
    def _draw(self):
        self.cv.delete("all")
        if not self.graph.vertices:
            self.cv.create_text(400, 200, text="Нет данных.", font=("Segoe UI", 16),
                                fill="#999", anchor="center")
            return
        z = self._zoom
        self._draw_bg(z)
        self._draw_edges(z)
        self._draw_verts(z)
        self._draw_hdrs(z)
        self.cv.update_idletasks()
        bb = self.cv.bbox("all")
        if bb:
            p = sp(40)
            self.cv.configure(scrollregion=(bb[0]-p, bb[1]-p, bb[2]+p, bb[3]+p))

    def _calc_row_bounds(self, z):
        """Вычисляет единые верх/низ для каждого ряда."""
        row_top: Dict[int, float] = {}
        row_bot: Dict[int, float] = {}
        for ri, lvls in self._row_lvls.items():
            top_y = bot_y = None
            for lvl in lvls:
                for v in self.graph.get_vertices_by_level(lvl):
                    if v.id in self.vpos:
                        vy = self.vpos[v.id][1]
                        if top_y is None or vy < top_y: top_y = vy
                        if bot_y is None or vy > bot_y: bot_y = vy
            if top_y is not None:
                row_top[ri] = top_y - sp(V_RAD) - sp(12)
                row_bot[ri] = bot_y + sp(V_RAD) + sp(30)
        return row_top, row_bot

    def _draw_bg(self, z):
        mode = current_mode()
        cw = sp(COL_W)
        hdr_h = sp(HDR_H)
        row_top, row_bot = self._calc_row_bounds(z)
        border_clr = "#888888" if mode == "light" else "#556677"

        for lvl in self._used:
            row, col = LAYOUT_MAP.get(lvl, (0, 0))
            verts = self.graph.get_vertices_by_level(lvl)
            pos = [self.vpos[v.id] for v in verts if v.id in self.vpos]
            if not pos:
                continue

            y1 = row_top.get(row, 0) * z
            y2 = row_bot.get(row, 100) * z

            if row >= 2:
                xs = [p[0] for p in pos]
                x1 = (min(xs) - cw * 0.4) * z
                x2 = (max(xs) + cw * 0.4) * z
            else:
                x1 = (sp(PAD_L) + col * cw) * z
                x2 = x1 + cw * z

            # Шапка заголовка — на всю ширину столбца, сверху
            base = LEVEL_COLORS.get(lvl, "#888")
            hh = hdr_h * z
            # Фон заголовка
            self.cv.create_rectangle(x1, y1 - hh, x2, y1,
                                     fill=base, outline="")
            # Текст заголовка
            fs = max(8, int(10 * z))
            self.cv.create_text((x1 + x2) / 2, y1 - hh / 2,
                                text=LEVEL_LABELS.get(lvl, "?"),
                                font=("Segoe UI", fs, "bold"), fill="white",
                                anchor="center", justify="center")

            # Фон столбца (тело)
            fill = self._lt(base, 0.93) if mode == "light" else self._dk(base, 0.85)
            self.cv.create_rectangle(x1, y1, x2, y2, fill=fill, outline="")

            # Рамка вокруг всего столбца (шапка + тело) — жирная
            self.cv.create_rectangle(x1, y1 - hh, x2, y2,
                                     fill="", outline=border_clr, width=max(2, 2.5 * z))

    def _draw_hdrs(self, z):
        """Заголовки уже отрисованы в _draw_bg — пустой метод."""
        pass

    def _draw_verts(self, z):
        mode = current_mode()
        tc = "#111827" if mode == "light" else "#E2E8F0"
        r = sp(V_RAD) * z
        for v in self.graph.vertices:
            p = self.vpos.get(v.id)
            if not p: continue
            cx, cy = p[0]*z, p[1]*z
            lc = LEVEL_COLORS.get(v.level, "#888")
            fl = "#FFF" if mode == "light" else self._dk(lc, 0.7)
            self.cv.create_oval(cx-r, cy-r, cx+r, cy+r, fill=fl, outline=lc,
                                width=max(2, 2.5*z))
            fs = max(8, int(11*z))
            self.cv.create_text(cx, cy, text=v.id, font=("Segoe UI", fs, "bold"),
                                fill=lc if mode == "light" else "#E2E8F0", anchor="center")
            lbl = v.label if len(v.label) <= 25 else v.label[:23]+"…"
            fs2 = max(7, int(9*z))
            self.cv.create_text(cx, cy+r+sp(6)*z, text=lbl, font=("Segoe UI", fs2),
                                fill=tc, anchor="n", justify="center",
                                width=sp(COL_W-25)*z)

    # ------------------------------------------------------------------
    # Edges — простые Z-маршруты с уникальными портами
    # ------------------------------------------------------------------

    def _draw_edges(self, z):
        """Каждая линия входит/выходит в уникальной точке на контуре кружка."""
        r = sp(V_RAD) * z
        drawn = set()
        edges = []

        for e in self.graph.edges:
            k = (e.source_id, e.target_id)
            if k in drawn: continue
            drawn.add(k)
            if e.source_id not in self.vpos or e.target_id not in self.vpos: continue
            sv = self._fv(e.source_id)
            dv = self._fv(e.target_id)
            if not sv or not dv: continue
            sr = LAYOUT_MAP.get(sv.level, (0, 0))
            dr = LAYOUT_MAP.get(dv.level, (0, 0))
            edges.append((e, sv, dv, sr, dr))

        # Порты на контуре
        exit_right: Dict[str, List] = defaultdict(list)
        enter_left: Dict[str, List] = defaultdict(list)
        exit_bottom: Dict[str, List] = defaultdict(list)
        enter_top: Dict[str, List] = defaultdict(list)
        exit_top: Dict[str, List] = defaultdict(list)
        enter_bottom: Dict[str, List] = defaultdict(list)

        for e, sv, dv, sr, dr in edges:
            sp_ = self.vpos[sv.id]; dp = self.vpos[dv.id]
            if sr[0] == dr[0]:
                if dp[0] > sp_[0]:
                    exit_right[sv.id].append(dv.id)
                    enter_left[dv.id].append(sv.id)
                else:
                    exit_right[dv.id].append(sv.id)
                    enter_left[sv.id].append(dv.id)
            else:
                if dp[1] > sp_[1]:
                    exit_bottom[sv.id].append(dv.id)
                    enter_top[dv.id].append(sv.id)
                else:
                    exit_top[sv.id].append(dv.id)
                    enter_bottom[dv.id].append(sv.id)

        PORT_SPACING = sp(10) * z

        def port_y(port_list, target_id, center_y):
            n = len(port_list)
            if n <= 1: return center_y
            idx = port_list.index(target_id) if target_id in port_list else 0
            return center_y + (idx - (n - 1) / 2) * PORT_SPACING

        def port_x(port_list, target_id, center_x):
            n = len(port_list)
            if n <= 1: return center_x
            idx = port_list.index(target_id) if target_id in port_list else 0
            return center_x + (idx - (n - 1) / 2) * PORT_SPACING

        # Слоты для Z-линий
        gap_groups: Dict[Tuple, List] = defaultdict(list)
        for e, sv, dv, sr, dr in edges:
            if sr[0] != dr[0]: continue
            sp_ = self.vpos[sv.id]; dp = self.vpos[dv.id]
            if abs(sp_[1] - dp[1]) < 3: continue
            c1, c2 = min(sr[1], dr[1]), max(sr[1], dr[1])
            gap_groups[(sr[0], c1, c2)].append((e.source_id, e.target_id))
        gap_slots = {}
        for key, pairs in gap_groups.items():
            for i, pair in enumerate(pairs): gap_slots[pair] = i

        row_top, row_bot = self._calc_row_bounds(z)
        LINE_W = max(1.8, 2.5 * z)
        TURN_SP = sp(14) * z

        for e, sv, dv, sr, dr in edges:
            clr = _ecolor(e.threat_types)
            sp_ = self.vpos[sv.id]; dp = self.vpos[dv.id]
            sx, sy = sp_[0] * z, sp_[1] * z
            tx, ty = dp[0] * z, dp[1] * z

            if sr[0] == dr[0]:
                # === ОДИН РЯД ===
                right = tx > sx
                if right:
                    ey = port_y(exit_right[sv.id], dv.id, sy)
                    ny = port_y(enter_left[dv.id], sv.id, ty)
                    x1, x2 = sx + r, tx - r
                else:
                    ey = port_y(exit_right[dv.id], sv.id, sy)
                    ny = port_y(enter_left[sv.id], dv.id, ty)
                    x1, x2 = sx - r, tx + r

                if abs(ey - ny) < 3:
                    self._arr([(x1, ey), (x2, ny)], clr, LINE_W, z)
                else:
                    slot = gap_slots.get((e.source_id, e.target_id), 0)
                    total = len(gap_groups.get(
                        (sr[0], min(sr[1], dr[1]), max(sr[1], dr[1])), []))
                    gap_center = (x1 + x2) / 2
                    turn_x = gap_center + (slot - (total - 1) / 2) * TURN_SP
                    self._arr([(x1, ey), (turn_x, ey),
                               (turn_x, ny), (x2, ny)], clr, LINE_W, z)
            else:
                # === РАЗНЫЕ РЯДЫ ===
                down = ty > sy
                if down:
                    ex = port_x(exit_bottom[sv.id], dv.id, sx)
                    nx = port_x(enter_top[dv.id], sv.id, tx)
                    y1, y2 = sy + r, ty - r
                else:
                    ex = port_x(exit_top[sv.id], dv.id, sx)
                    nx = port_x(enter_bottom[dv.id], sv.id, tx)
                    y1, y2 = sy - r, ty + r

                if abs(ex - nx) < 5:
                    self._arr([(ex, y1), (nx, y2)], clr, LINE_W, z)
                else:
                    if down:
                        gt = row_bot.get(sr[0], sy / z) * z + sp(15) * z
                        gb = (row_top.get(dr[0], ty / z) - sp(HDR_H)) * z - sp(15) * z
                    else:
                        gt = row_bot.get(dr[0], ty / z) * z + sp(15) * z
                        gb = (row_top.get(sr[0], sy / z) - sp(HDR_H)) * z - sp(15) * z
                    if gb < gt: gb = gt + sp(30) * z

                    n_out = len(exit_bottom[sv.id] if down else exit_top[sv.id])
                    idx = (exit_bottom[sv.id] if down else exit_top[sv.id]).index(dv.id) if dv.id in (exit_bottom[sv.id] if down else exit_top[sv.id]) else 0
                    turn_y = (gt + gb) / 2 + (idx - (n_out - 1) / 2) * TURN_SP

                    self._arr([(ex, y1), (ex, turn_y),
                               (nx, turn_y), (nx, y2)], clr, LINE_W, z)

    def _arr(self, pts, clr, lw, z):
        if len(pts) < 2: return
        for i in range(len(pts)-1):
            self.cv.create_line(pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1],
                                fill=clr, width=lw)
        x1, y1 = pts[-2]; x2, y2 = pts[-1]
        a = sp(10)*z; ang = math.atan2(y2-y1, x2-x1)
        self.cv.create_polygon(
            x2, y2,
            x2-a*math.cos(ang-.35), y2-a*math.sin(ang-.35),
            x2-a*math.cos(ang+.35), y2-a*math.sin(ang+.35),
            fill=clr, outline=clr)

    def _fv(self, vid):
        for v in self.graph.vertices:
            if v.id == vid: return v
        return None

    # Zoom
    def _zin(self):
        if self._zoom < 3: self._zoom = min(3, self._zoom+.15); self._uz()
    def _zout(self):
        if self._zoom > .2: self._zoom = max(.2, self._zoom-.15); self._uz()
    def _zrst(self): self._zoom = 1.0; self._uz()
    def _uz(self): self._zlbl.configure(text=f"{int(self._zoom*100)}%"); self._draw()

    # Helpers
    def _tru(self):
        return {"Internet":"Интернет","Router":"Маршрутизатор","Switch":"Коммутатор",
                "Server":"Сервер","VirtualizationServer":"Сервер виртуализации",
                "ARM":"АРМ","Laptop":"Ноутбук"}.get(self.node.type, self.node.type)
    @staticmethod
    def _lt(h, f):
        r,g,b = int(h[1:3],16),int(h[3:5],16),int(h[5:7],16)
        return f"#{int(r+(255-r)*f):02x}{int(g+(255-g)*f):02x}{int(b+(255-b)*f):02x}"
    @staticmethod
    def _dk(h, f):
        r,g,b = int(h[1:3],16),int(h[3:5],16),int(h[5:7],16)
        return f"#{int(r*f):02x}{int(g*f):02x}{int(b*f):02x}"
