"""Renderers for the attack graph: mermaid, graphviz DOT, and standalone SVG.

All formats are self-contained text — the SVG needs no graphviz/browser libs
and the mermaid output drops straight into a README or mermaid.live.
"""

from __future__ import annotations

import html
import re

import networkx as nx

_KIND_STROKE = {
    "account": "#3b82f6",
    "policy": "#a78bfa",
    "role": "#34d399",
    "user": "#22d3ee",
    "group": "#fbbf24",
    "bucket": "#f472b6",
    "instance": "#f472b6",
    "security-group": "#fb7185",
}

_BG = "#0b1220"
_NODE_FILL = "#111a2e"
_ACCOUNT_FILL = "#0f2744"
_TEXT = "#e2e8f0"
_EDGE = "#64748b"
_EDGE_TEXT = "#7dd3fc"
_HIGHLIGHT = "#ef4444"
_DEFAULT_STROKE = "#94a3b8"
_FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"


def _label(g: nx.DiGraph, n) -> str:
    return str(g.nodes[n].get("label", n))


def _stroke(kind: str) -> str:
    return _KIND_STROKE.get(kind, _DEFAULT_STROKE)


def _fit(label: str, max_chars: int = 30) -> str:
    return label if len(label) <= max_chars else label[: max_chars - 1] + "…"


def to_mermaid(g: nx.DiGraph) -> str:
    ids = {n: f"n{i}" for i, n in enumerate(g)}
    lines = ["flowchart TD"]
    for n, nid in ids.items():
        lbl = _label(g, n).replace('"', "'")
        lines.append(f'  {nid}["{lbl}"]')
    for u, v, data in g.edges(data=True):
        rel = str(data.get("rel", ""))
        if rel:
            lines.append(f"  {ids[u]} -->|{rel}| {ids[v]}")
        else:
            lines.append(f"  {ids[u]} --> {ids[v]}")
    kinds = sorted({str(g.nodes[n].get("kind", "")) for n in g})
    for i, kind in enumerate(kinds):
        members = [ids[n] for n in g if str(g.nodes[n].get("kind", "")) == kind]
        if not members:
            continue
        cls = f"k{i}"
        lines.append(f"  classDef {cls} fill:{_NODE_FILL},stroke:{_stroke(kind)},color:{_TEXT}")
        lines.append(f"  class {','.join(members)} {cls}")
    return "\n".join(lines)


def to_mermaid_paths(paths: dict[str, list[str]]) -> str:
    lines = ["flowchart LR"]
    ids: dict[str, str] = {}

    def nid(label: str) -> str:
        if label not in ids:
            ids[label] = f"n{len(ids)}"
            safe = label.replace('"', "'")
            lines.append(f'  {ids[label]}["{safe}"]')
        return ids[label]

    for chain in paths.values():
        if not chain:
            continue
        for label in chain:
            nid(label)
        for a, b in zip(chain, chain[1:]):
            lines.append(f"  {ids[a]} --> {ids[b]}")
    return "\n".join(lines)


def to_dot(g: nx.DiGraph) -> str:
    def q(s) -> str:
        return str(s).replace("\\", "\\\\").replace('"', '\\"')

    lines = [
        "digraph cidag {",
        "  rankdir=TB;",
        f'  node [shape=box, style="rounded,filled", fillcolor="{_NODE_FILL}", '
        f'fontcolor="{_TEXT}", fontname="monospace"];',
        f'  edge [color="{_EDGE}", fontcolor="{_EDGE_TEXT}", fontname="monospace", fontsize=10];',
    ]
    for n in g:
        kind = str(g.nodes[n].get("kind", ""))
        lines.append(f'  "{q(n)}" [label="{q(_label(g, n))}", color="{_stroke(kind)}"];')
    for u, v, data in g.edges(data=True):
        rel = str(data.get("rel", ""))
        lbl = f', label="{q(rel)}"' if rel else ""
        lines.append(f'  "{q(u)}" -> "{q(v)}"{lbl};')
    lines.append("}")
    return "\n".join(lines)


def _layers(g: nx.DiGraph) -> dict:
    """Longest-path layering, cycle-safe via bounded relaxation."""
    rank = {n: 0 for n in g}
    for _ in range(len(g) + 1):
        changed = False
        for u, v in g.edges():
            if rank[v] < rank[u] + 1:
                rank[v] = rank[u] + 1
                changed = True
        if not changed:
            break
    return rank


def to_svg(g: nx.DiGraph, highlight: set | None = None) -> str:
    highlight = {str(x) for x in (highlight or set())}
    rank = _layers(g)

    def node_w(n) -> int:
        return min(220, max(96, 8 * len(_fit(_label(g, n))) + 28))

    node_h, gap_x, gap_y, margin, header = 36, 44, 72, 32, 34
    rows: dict[int, list] = {}
    for n in sorted(g, key=lambda x: (rank[x], _label(g, x).lower())):
        rows.setdefault(rank[n], []).append(n)

    def row_width(ns: list) -> int:
        return sum(node_w(n) for n in ns) + gap_x * (len(ns) - 1)

    width = max((row_width(ns) for ns in rows.values()), default=0) + 2 * margin
    height = margin + header
    pos: dict = {}
    for r in sorted(rows):
        ns = rows[r]
        x = (width - row_width(ns)) / 2
        for n in ns:
            w = node_w(n)
            pos[n] = (x, height, w, node_h)
            x += w + gap_x
        height += node_h + gap_y
    height = height - gap_y + margin

    marker = (
        '<marker id="arw" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{_EDGE}"/></marker>'
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" '
        f'height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'font-family="{_FONT}">',
        f"<defs>{marker}</defs>",
        f'<rect width="{width:.0f}" height="{height:.0f}" fill="{_BG}"/>',
        f'<text x="{margin}" y="{margin + 16}" font-size="14" font-weight="bold" '
        f'fill="{_TEXT}">CIDAG attack graph · {g.number_of_nodes()} nodes · '
        f"{g.number_of_edges()} edges</text>",
    ]

    for u, v, data in g.edges(data=True):
        if u not in pos or v not in pos:
            continue
        x1, y1, w1, h1 = pos[u]
        x2, y2, w2, h2 = pos[v]
        sx, sy = x1 + w1 / 2, y1 + h1
        tx, ty = x2 + w2 / 2, y2
        dy = ty - sy
        if dy > 8:
            path = (f"M {sx:.1f},{sy:.1f} C {sx:.1f},{sy + dy / 2:.1f} "
                    f"{tx:.1f},{ty - dy / 2:.1f} {tx:.1f},{ty:.1f}")
            lx, ly = (sx + tx) / 2, (sy + ty) / 2
        else:
            off = 64
            path = (f"M {sx:.1f},{sy:.1f} C {sx + off:.1f},{sy:.1f} "
                    f"{tx + off:.1f},{ty + h2:.1f} {tx:.1f},{ty + h2:.1f}")
            lx, ly = sx + off, (sy + ty + h2) / 2
        parts.append(
            f'<path d="{path}" fill="none" stroke="{_EDGE}" stroke-width="1.3" '
            f'marker-end="url(#arw)"/>'
        )
        rel = str(data.get("rel", ""))
        if rel and rel != "contains":
            parts.append(
                f'<text x="{lx:.1f}" y="{ly:.1f}" font-size="10" fill="{_EDGE_TEXT}" '
                f'text-anchor="middle">{html.escape(rel)}</text>'
            )

    for n, (x, y, w, h) in pos.items():
        data = g.nodes[n]
        kind = str(data.get("kind", ""))
        is_admin = str(n) in highlight or _label(g, n) in highlight
        stroke = _HIGHLIGHT if is_admin else _stroke(kind)
        sw = 2.4 if is_admin else 1.4
        fill = _ACCOUNT_FILL if kind == "account" else _NODE_FILL
        lbl = html.escape(_fit(_label(g, n)))
        parts.append(
            f'<g><title>{html.escape(str(n))}</title>'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h}" rx="8" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
            f'<text x="{x + w / 2:.1f}" y="{y + h / 2:.1f}" font-size="12" fill="{_TEXT}" '
            f'text-anchor="middle" dominant-baseline="central">{lbl}</text></g>'
        )
    parts.append("</svg>")
    return "\n".join(parts)
