"""
Экспорт графа угроз в самостоятельную HTML-страницу.

Зачем
-----
Холст Tkinter плохо подходит для схемы из четырёхсот вершин: ширину текста
приходится угадывать, подписи наезжают друг на друга, а мелкий масштаб
читается тяжело. SVG в браузере решает это сразу — текст меряет сам браузер,
масштаб плавный, а страницу можно распечатать в PDF или показать по ссылке.

Страница самодостаточная: ни внешних библиотек, ни интернета. Внутри —
панорама мышью, масштаб колесом, подсветка соседей по клику, боковая панель
со сведениями о компоненте и переключатели слоёв.
"""

from __future__ import annotations

import html
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = ["build_graph_html", "LEVEL_ORDER_ROWS"]


# Строки блока — как на эталонном графе узла
LEVEL_ORDER_ROWS: List[List[str]] = [
    ["ω", "f", "z", "l", "t", "d", "r", "q"],
    ["i", "w", "p", "v"],
    ["a"],
    ["h"],
]

LEVEL_TITLES = {
    "ω": "Точки входа", "f": "Физический", "z": "Канальный", "l": "Сетевой",
    "t": "Транспортный", "d": "Сеансовый", "r": "Представления",
    "q": "Прикладной", "i": "Драйверы", "w": "Разграничение доступа",
    "p": "Управление файлами", "v": "Управление процессами",
    "a": "Аппаратный", "h": "Пользовательский",
}

LEVEL_COLORS = {
    "ω": "#B45309", "f": "#0E7490", "z": "#0891B2", "l": "#0D9488",
    "t": "#4D7C0F", "d": "#A16207", "r": "#C2410C", "q": "#B91C1C",
    "i": "#6D28D9", "w": "#7C3AED", "p": "#8B5CF6", "v": "#A78BFA",
    "a": "#475569", "h": "#0F766E",
}

ROUTE_COLORS = ["#D97706", "#2563EB", "#7C3AED", "#BE123C",
                "#059669", "#DB2777"]

# Геометрия SVG
COL_W = 128
V_STEP = 62
V_RAD = 15
MAX_PER_COL = 6
ROW_GAP = 78
BLOCK_PAD = 30
BLOCK_GAP_X = 70
BLOCK_GAP_Y = 92
MARGIN = 40
TARGET_RATIO = 1.5


# ===================================================================
# Раскладка
# ===================================================================

def _group_levels(graph, node_id: str) -> Dict[str, List[str]]:
    """Компоненты узла по уровням; точки входа — отдельной колонкой ω."""
    grouped: Dict[str, List[str]] = defaultdict(list)
    for vid in graph.by_node.get(node_id, []):
        vertex = graph.vertices[vid]
        grouped["ω" if vertex.is_entry_point else vertex.level_code].append(vid)
    for ids in grouped.values():
        ids.sort(key=lambda v: graph.vertices[v].identifier)
    return grouped


def _layout_block(grouped: Dict[str, List[str]]
                  ) -> Tuple[Dict[str, Tuple[int, int]], int, int,
                             List[Tuple[str, int, int]]]:
    """Раскладывает один узел. Возвращает позиции, размер и подписи колонок."""
    positions: Dict[str, Tuple[int, int]] = {}
    headers: List[Tuple[str, int, int]] = []      # уровень, x, y
    rows = []

    for levels in LEVEL_ORDER_ROWS:
        present = [lvl for lvl in levels if grouped.get(lvl)]
        if not present:
            continue
        plan, width, height = [], 0, 0
        for lvl in present:
            column = grouped[lvl]
            sub_cols = max(1, -(-len(column) // MAX_PER_COL))
            per_col = -(-len(column) // sub_cols)
            plan.append((lvl, sub_cols, per_col))
            width += sub_cols * COL_W
            height = max(height, per_col * V_STEP)
        rows.append((plan, width, height))

    if not rows:
        return {}, 0, 0, []

    block_w = max(width for _plan, width, _h in rows)
    y = 0
    for plan, width, height in rows:
        x = (block_w - width) // 2
        for lvl, sub_cols, per_col in plan:
            column = grouped[lvl]
            headers.append((lvl, x + (sub_cols * COL_W) // 2, y - 22))
            for index, vid in enumerate(column):
                sub, within = divmod(index, per_col)
                count = min(per_col, len(column) - sub * per_col)
                offset = ((per_col - count) * V_STEP) // 2
                positions[vid] = (x + sub * COL_W + COL_W // 2,
                                  y + offset + within * V_STEP + V_RAD + 6)
            x += sub_cols * COL_W
        y += height + ROW_GAP

    return positions, block_w, y - ROW_GAP + V_RAD, headers


def _layout(graph, board):
    """Раскладывает все узлы сеткой, подбирая пропорции под экран."""
    prepared = []
    for node in board.nodes:
        if not graph.by_node.get(node.id):
            continue
        positions, width, height, headers = _layout_block(
            _group_levels(graph, node.id))
        if positions:
            prepared.append((node.id, node.name, positions, width, height, headers))

    if not prepared:
        return {}, [], (0, 0)

    cell_w = max(item[3] for item in prepared) + BLOCK_PAD * 2 + BLOCK_GAP_X
    cell_h = max(item[4] for item in prepared) + BLOCK_PAD * 2 + BLOCK_GAP_Y

    count = len(prepared)
    best_cols = min(range(1, count + 1),
                    key=lambda cols: abs(
                        (cols * cell_w) / (-(-count // cols) * cell_h) - TARGET_RATIO))

    pos: Dict[str, Tuple[int, int]] = {}
    blocks = []
    for index, (node_id, name, positions, width, height, headers) in enumerate(prepared):
        col, row = index % best_cols, index // best_cols
        ox = MARGIN + col * cell_w + BLOCK_PAD
        oy = MARGIN + row * cell_h + BLOCK_PAD + 26
        for vid, (x, y) in positions.items():
            pos[vid] = (ox + x, oy + y)
        blocks.append({
            "id": node_id, "name": name,
            "x": ox - BLOCK_PAD, "y": oy - BLOCK_PAD - 22,
            "w": width + BLOCK_PAD * 2, "h": height + BLOCK_PAD * 2 + 22,
            "headers": [(lvl, ox + hx, oy + hy) for lvl, hx, hy in headers],
        })

    rows_count = -(-count // best_cols)
    size = (MARGIN * 2 + best_cols * cell_w, MARGIN * 2 + rows_count * cell_h)
    return pos, blocks, size


# ===================================================================
# Сборка страницы
# ===================================================================

def _esc(text: str) -> str:
    return html.escape(str(text), quote=True)


def _clean(name: str) -> str:
    """Убирает служебный CPE-суффикс «||vendor|product|version».

    Он нужен только для поиска уязвимостей, на схеме мешает.
    """
    return str(name).split("||")[0].strip().rstrip("- ").strip()


def build_graph_html(graph, board,
                     routes: Optional[Sequence[Tuple[str, List[str]]]] = None,
                     title: str = "Общий граф угроз",
                     standalone: bool = True) -> str:
    """Собирает самостоятельную HTML-страницу с графом угроз.

    Args:
        graph: TopologyGraph — граф компонентов всей топологии
        board: схема сети (нужен порядок узлов и их имена)
        routes: маршруты вида [("χ1", [id вершин]), …] для наложения
        title: заголовок страницы

    Returns:
        Готовый HTML одной строкой
    """
    pos, blocks, (width, height) = _layout(graph, board)
    routes = list(routes or [])

    route_of_edge: Dict[Tuple[str, str], int] = {}
    route_of_vertex: Dict[str, List[int]] = defaultdict(list)
    for number, (_name, path) in enumerate(routes):
        for step, vid in enumerate(path):
            route_of_vertex[vid].append(number)
            if step:
                route_of_edge[(path[step - 1], vid)] = number
                route_of_edge[(vid, path[step - 1])] = number

    parts: List[str] = []

    # --- Рамки узлов ---
    for block in blocks:
        parts.append(
            f'<rect class="block" x="{block["x"]}" y="{block["y"]}" '
            f'width="{block["w"]}" height="{block["h"]}" rx="14"/>'
            f'<text class="block-title" x="{block["x"] + 14}" '
            f'y="{block["y"] + 22}">{_esc(block["name"])}</text>')
        for lvl, hx, hy in block["headers"]:
            parts.append(
                f'<text class="lvl" x="{hx}" y="{hy}" '
                f'fill="{LEVEL_COLORS.get(lvl, "#64748B")}">'
                f'{_esc(LEVEL_TITLES.get(lvl, lvl))}</text>')

    # --- Рёбра ---
    drawn = set()
    edges_intra, edges_cross, edges_route = [], [], []
    for source, targets in graph.adjacency.items():
        if source not in pos:
            continue
        x1, y1 = pos[source]
        node_a = graph.vertices[source].node_id
        for target in targets:
            if target not in pos:
                continue
            key = (source, target) if source < target else (target, source)
            if key in drawn:
                continue
            drawn.add(key)
            x2, y2 = pos[target]
            line = f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"'
            route = route_of_edge.get((source, target))
            if route is not None:
                colour = ROUTE_COLORS[route % len(ROUTE_COLORS)]
                edges_route.append(f'{line} stroke="{colour}" stroke-width="4"/>')
            elif graph.vertices[target].node_id != node_a:
                edges_cross.append(f'{line} class="cross"/>')
            else:
                edges_intra.append(f'{line} class="intra"/>')

    parts.append(f'<g id="intra">{"".join(edges_intra)}</g>')
    parts.append(f'<g id="cross">{"".join(edges_cross)}</g>')
    parts.append(f'<g id="routes">{"".join(edges_route)}</g>')

    # --- Вершины ---
    nodes_svg = []
    for vid, (x, y) in pos.items():
        vertex = graph.vertices[vid]
        level = "ω" if vertex.is_entry_point else vertex.level_code
        colour = LEVEL_COLORS.get(level, "#64748B")
        transit_only = vertex.is_transit and not vertex.is_target
        marks = "".join(f"({routes[n][0]}.{routes[n][1].index(vid) + 1})"
                        for n in route_of_vertex.get(vid, []))
        classes = "v" + (" on-route" if vid in route_of_vertex else "")
        clean = _clean(vertex.name)
        label = clean if len(clean) <= 18 else clean[:17] + "…"

        nodes_svg.append(
            f'<g class="{classes}" data-id="{_esc(vid)}" '
            f'data-node="{_esc(vertex.node_name)}" '
            f'data-name="{_esc(clean)}" '
            f'data-ident="{_esc(vertex.identifier)}" '
            f'data-level="{_esc(LEVEL_TITLES.get(level, level))}" '
            f'data-role="{_esc(vertex.role)}" '
            f'data-type="{_esc(vertex.component_type)}" '
            f'transform="translate({x},{y})">'
            f'<circle r="{V_RAD}" fill="#fff" stroke="{colour}" '
            f'stroke-width="2.4"{" stroke-dasharray=\"5 3\"" if transit_only else ""}/>'
            f'<text class="ident" y="4">{_esc(vertex.identifier[:8])}</text>'
            f'<text class="name" y="{V_RAD + 15}">{_esc(label)}</text>'
            + (f'<text class="chi" y="{V_RAD + 27}">{_esc(marks)}</text>' if marks else "")
            + f'<title>{_esc(vertex.node_name)} · {_esc(clean)}\n'
              f'{_esc(vertex.identifier)} · {_esc(vertex.role)}</title>'
            f'</g>')
    parts.append(f'<g id="nodes">{"".join(nodes_svg)}</g>')

    # --- Список маршрутов ---
    route_items = "".join(
        f'<li><span class="dot" style="background:'
        f'{ROUTE_COLORS[i % len(ROUTE_COLORS)]}"></span>'
        f'<b>{_esc(name)}</b> — {len(path)} шагов, до '
        f'{_esc(graph.vertices[path[-1]].node_name)} · '
        f'{_esc(graph.vertices[path[-1]].name)}</li>'
        for i, (name, path) in enumerate(routes) if path)

    stats = (f'узлов {len(blocks)} · вершин {len(graph.vertices)} · '
             f'рёбер {graph.edge_count}')

    template = _PAGE if standalone else _FRAGMENT
    return template.format(
        title=_esc(title), stats=_esc(stats),
        width=width, height=height,
        svg="".join(parts),
        routes_block=(f'<h3>Маршруты УБИ</h3><ul class="routes">{route_items}</ul>'
                      if route_items else ""),
    )


# ===================================================================
# Шаблон страницы
# ===================================================================

_STYLE = """<title>{title}</title>
<style>
:root {{
  --paper:#F1F4F7; --surface:#fff; --ink:#13181D; --muted:#56646F;
  --rule:#D2DAE2; --accent:#0B5D6B;
}}
@media (prefers-color-scheme:dark) {{
  :root {{ --paper:#0D1116; --surface:#151C23; --ink:#E4EAF0;
           --muted:#9AAAB7; --rule:#2A3540; --accent:#58C4D6; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--paper); color:var(--ink);
  font:14px/1.5 "Segoe UI",system-ui,sans-serif; overflow:hidden; }}
header {{ display:flex; align-items:center; gap:18px; flex-wrap:wrap;
  padding:10px 18px; background:var(--surface);
  border-bottom:1px solid var(--rule); }}
h1 {{ font-size:16px; margin:0; font-weight:600; }}
.stats {{ color:var(--muted); font-size:13px; }}
label {{ display:inline-flex; align-items:center; gap:6px;
  font-size:13px; color:var(--muted); cursor:pointer; }}
button {{ font:inherit; font-size:13px; padding:4px 12px; cursor:pointer;
  border:1px solid var(--rule); border-radius:6px;
  background:var(--surface); color:var(--ink); }}
button:hover {{ border-color:var(--accent); }}
main {{ display:flex; height:calc(100vh - 49px); }}
#stage {{ flex:1; overflow:hidden; cursor:grab; background:var(--paper); }}
#stage.drag {{ cursor:grabbing; }}
aside {{ width:300px; border-left:1px solid var(--rule);
  background:var(--surface); padding:16px; overflow:auto; }}
aside h3 {{ font-size:13px; margin:0 0 10px; text-transform:uppercase;
  letter-spacing:.06em; color:var(--muted); }}
aside dl {{ margin:0 0 18px; }}
aside dt {{ font-size:11px; color:var(--muted); margin-top:9px; }}
aside dd {{ margin:2px 0 0; font-size:13px; word-break:break-word; }}
.routes {{ list-style:none; padding:0; margin:0; font-size:12.5px; }}
.routes li {{ padding:5px 0; border-bottom:1px solid var(--rule); }}
.dot {{ display:inline-block; width:9px; height:9px; border-radius:50%;
  margin-right:7px; vertical-align:middle; }}
svg {{ display:block; }}
.block {{ fill:none; stroke:var(--rule); stroke-width:1.4;
  stroke-dasharray:7 5; }}
.block-title {{ font-size:14px; font-weight:600; fill:var(--ink); }}
.lvl {{ font-size:10.5px; font-weight:600; text-anchor:middle;
  letter-spacing:.02em; }}
.intra {{ stroke:var(--rule); stroke-width:1; opacity:.55; }}
.cross {{ stroke:#2563EB; stroke-width:2.4; opacity:.85; }}
.ident {{ font-size:9px; text-anchor:middle; fill:var(--ink); }}
.name {{ font-size:10px; text-anchor:middle; fill:var(--muted); }}
.chi {{ font-size:9.5px; font-weight:700; text-anchor:middle; fill:#B45309; }}
.v {{ cursor:pointer; }}
.v:hover circle {{ stroke-width:4; }}
.v.sel circle {{ stroke:#DC2626 !important; stroke-width:4.5; }}
.v.dim {{ opacity:.16; }}
line.dim {{ opacity:.05; }}
body.hide-intra #intra {{ display:none; }}
</style>"""

_BODY = """<header>
  <h1>{title}</h1><span class="stats">{stats}</span>
  <label><input type="checkbox" id="ti" checked> связи внутри узлов</label>
  <label><input type="checkbox" id="tc" checked> связи между узлами</label>
  <button id="fit">Вписать</button><button id="reset">Сбросить выделение</button>
  <span class="stats">колесо — масштаб, перетаскивание — панорама</span>
</header>
<main>
  <div id="stage">
    <svg id="svg" width="100%" height="100%" viewBox="0 0 {width} {height}">
      <g id="world">{svg}</g>
    </svg>
  </div>
  <aside>
    <h3>Компонент</h3>
    <dl id="info"><dd style="color:var(--muted)">Щёлкните вершину графа</dd></dl>
    {routes_block}
  </aside>
</main>
<script>
const svg=document.getElementById('svg'), world=document.getElementById('world'),
      stage=document.getElementById('stage'), info=document.getElementById('info');
const W={width}, H={height};
let s=1, tx=0, ty=0;
function apply(){{ world.setAttribute('transform',
  'translate('+tx+','+ty+') scale('+s+')'); }}
function fit(){{ const r=stage.getBoundingClientRect();
  s=Math.min(r.width/W, r.height/H)*0.98;
  tx=(r.width-W*s)/2; ty=(r.height-H*s)/2;
  svg.setAttribute('viewBox','0 0 '+r.width+' '+r.height); apply(); }}
window.addEventListener('resize', fit);
document.getElementById('fit').onclick=fit;

stage.addEventListener('wheel', e=>{{ e.preventDefault();
  const r=stage.getBoundingClientRect(), mx=e.clientX-r.left, my=e.clientY-r.top;
  const k=e.deltaY<0?1.12:1/1.12, ns=Math.max(0.05,Math.min(8,s*k));
  tx=mx-(mx-tx)*(ns/s); ty=my-(my-ty)*(ns/s); s=ns; apply(); }}, {{passive:false}});

let drag=null;
stage.addEventListener('mousedown', e=>{{ drag={{x:e.clientX-tx,y:e.clientY-ty}};
  stage.classList.add('drag'); }});
window.addEventListener('mousemove', e=>{{ if(!drag) return;
  tx=e.clientX-drag.x; ty=e.clientY-drag.y; apply(); }});
window.addEventListener('mouseup', ()=>{{ drag=null; stage.classList.remove('drag'); }});

document.getElementById('ti').onchange=e=>
  document.body.classList.toggle('hide-intra', !e.target.checked);
document.getElementById('tc').onchange=e=>
  document.getElementById('cross').style.display=e.target.checked?'':'none';

const verts=[...document.querySelectorAll('.v')];
function clearSel(){{ verts.forEach(v=>v.classList.remove('sel','dim'));
  document.querySelectorAll('line').forEach(l=>l.classList.remove('dim')); }}
document.getElementById('reset').onclick=()=>{{ clearSel();
  info.innerHTML='<dd style="color:var(--muted)">Щёлкните вершину графа</dd>'; }};

verts.forEach(v=>v.addEventListener('click', ev=>{{ ev.stopPropagation();
  clearSel(); v.classList.add('sel');
  const d=v.dataset, rows=[['Узел',d.node],['Идентификатор',d.ident],
    ['Наименование',d.name],['Уровень',d.level],['Роль',d.role||'—'],
    ['Тип',d.type]];
  info.innerHTML=rows.map(r=>'<dt>'+r[0]+'</dt><dd>'+r[1]+'</dd>').join('');
}}));
fit();
</script>
"""

# Фрагмент — для встраивания (артефакт, отчёт). Целая страница — для файла,
# который открывается в браузере и печатается в PDF.
_FRAGMENT = _STYLE + _BODY

_DOC_HEAD = (
    '<!doctype html>\n'
    '<html lang="ru"><head><meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
)

_PAGE = _DOC_HEAD + _STYLE + "</head><body>" + _BODY + "</body></html>\n"
