"""Operator relationship graph — DOT generation, UI-free.

The whole-case infrastructure graph, COLOURED BY GROUP: each connected
component (operator group) gets its own colour, so the partition the Overview
asserts is visible at a glance. Nodes are domains + their named shared
signals; edges mean "this domain carries this signal". Group colours and node
ids come from clusters.py (the single source of truth), so the graph, the
Overview, and the dossier all agree.

This module used to live inside views/page_graph.py, where the graph only
existed as a DOT string handed to st.graphviz_chart — it never touched disk,
so the graph was the one analytic output that vanished without the UI. It is
now core, and `render_dot()` can write it out as an actual file.
"""
import os
import shutil
import subprocess

from clusters import case_clusters, group_color, node_id
from palette import GRAPH_EDGE, NEUTRAL_FILL

_SIG_SHAPE = {
    "tracking":     "box",
    "cert":         "octagon",
    "ads_template": "folder",
    "ads_account":  "note",
}
_SIG_LABEL = {
    "tracking": "追蹤碼", "cert": "TLS 憑證",
    "ads_template": "ads.txt 模板", "ads_account": "ads.txt 帳號",
}

# Formats `dot` can emit that make sense for an evidence file.
RENDER_FORMATS = ("svg", "png", "pdf")


def _esc(s: str) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def build_dot(groups) -> str:
    """DOT for the given groups (already filtered). Coloured per group."""
    lines = [
        "digraph rel {", "  rankdir=LR;", '  bgcolor="transparent";',
        '  graph [nodesep=0.22, ranksep=0.55];',
        '  node [fontname="Helvetica", fontsize=9];',
        f'  edge [color="{GRAPH_EDGE}", arrowhead=none];',
    ]
    for g in groups:
        clr = group_color(g["gid"])
        # cluster box per group so components are visually separated
        lines.append(f'  subgraph cluster_{g["gid"]} {{')
        lines.append(f'    label="{g["label"]}"; color="{clr}"; fontcolor="{clr}";')
        for d in g["domains"]:
            lines.append(
                f'    {node_id("dom", d)} [label="{_esc(d)}", shape=ellipse, '
                f'style=filled, fillcolor="{NEUTRAL_FILL}", color="{clr}"];'
            )
        for i, s in enumerate(g["signals"]):
            sid = node_id("sig", f'{g["gid"]}:{s["type"]}:{s["value"]}:{i}')
            shape = _SIG_SHAPE.get(s["type"], "box")
            lines.append(
                f'    {sid} [label="{_esc(s["label"])}\\n{_esc(s["value"])}", '
                f'shape={shape}, style=filled, fillcolor="{clr}", fontcolor="white"];'
            )
            for d in s["domains"]:
                lines.append(f'    {sid} -> {node_id("dom", d)};')
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines)


def case_dot(conn, case_id: int, gid: int | None = None) -> dict:
    """DOT for a whole case, or for one group when `gid` is given.

    Returns {dot, groups, scanned, group_count}. `dot` is None when there is
    nothing to draw — the caller must distinguish "no shared signals found"
    (a real, meaningful result) from "not scanned yet".
    """
    m = case_clusters(conn, case_id)
    groups = m["groups"]
    if gid is not None:
        groups = [g for g in groups if g["gid"] == gid]
        if not groups:
            raise ValueError(f"case {case_id} has no group with gid {gid}")
    return {
        "dot": build_dot(groups) if groups else None,
        "scanned": m["scanned"],
        "group_count": len(groups),
        "groups": [
            {"gid": g["gid"], "label": g["label"],
             "domain_count": g["domain_count"], "signal_count": g["signal_count"]}
            for g in groups
        ],
    }


def graphviz_available() -> bool:
    """True when the `dot` binary is on PATH.

    Graphviz is NOT a kwara dependency — the Streamlit UI renders DOT
    client-side. Writing an image file needs the real binary, so callers
    must degrade to plain .dot output rather than fail.
    """
    return shutil.which("dot") is not None


def render_dot(dot: str, out_path: str, fmt: str = "svg") -> str:
    """Write `dot` to out_path, rendering it through graphviz when needed.

    fmt="dot" writes the source directly and never shells out. Any other
    format requires the `dot` binary; RuntimeError names the missing piece
    so the caller can tell the user to install graphviz.
    """
    fmt = (fmt or "dot").lower()
    out_path = os.path.abspath(out_path)
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    if fmt == "dot":
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(dot)
        return out_path

    if fmt not in RENDER_FORMATS:
        raise ValueError(f"unsupported format {fmt!r}; use dot/{'/'.join(RENDER_FORMATS)}")
    if not graphviz_available():
        raise RuntimeError(
            f"cannot render {fmt}: the 'dot' binary is not on PATH. "
            "Install graphviz (macOS: brew install graphviz) or use --format dot."
        )

    proc = subprocess.run(
        ["dot", f"-T{fmt}", "-o", out_path],
        input=dot.encode("utf-8"),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"graphviz failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return out_path
