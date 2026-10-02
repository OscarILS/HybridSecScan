"""Dependencia productor-consumidor entre solicitudes (estilo RESTler).

A: POST /usuarios devuelve un "id"; B: GET /usuarios/{id} lo consume.

Regenerar:  python thesis/imagenes/restler_dependencias.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
LINE = "#52514e"
MUTED = "#6b6a66"
FILL = "#f4f3ef"
ACCENT = "#2a78d6"
ACCENT_DARK = "#184f95"
ACCENT_FILL = "#e8f1fc"
FS = 14
MONO = "Consolas"

plt.rcParams["font.family"] = "Arial"

W, H = 7.0, 2.75  # pulgadas; el eje usa pulgadas como unidades
fig = plt.figure(figsize=(W, H), dpi=300)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.axis("off")
renderer = fig.canvas.get_renderer()
inv = ax.transData.inverted()


def width_in(t):
    bb = t.get_window_extent(renderer)
    return inv.transform((bb.x1, 0))[0] - inv.transform((bb.x0, 0))[0]


def card(x0, x1, y0, y1):
    ax.add_patch(
        FancyBboxPatch(
            (x0, y0), x1 - x0, y1 - y0, boxstyle="round,pad=0,rounding_size=0.12", fc=FILL, ec=LINE, lw=1.4
        )
    )


def mono_line(parts, xc, y, size):
    """Escribe una línea monoespaciada centrada en xc; parts = [(texto, resaltado)]."""
    texts = []
    for txt, hl in parts:
        texts.append(
            ax.text(
                0,
                y,
                txt,
                fontsize=size,
                family=MONO,
                weight="bold",
                color=ACCENT_DARK if hl else INK,
                va="center",
                bbox=dict(boxstyle="round,pad=0.08", fc=ACCENT_FILL, ec="none") if hl else None,
            )
        )
    widths = [width_in(t) for t in texts]
    x = xc - sum(widths) / 2
    for t, w in zip(texts, widths):
        t.set_position((x, y))
        x += w


Y0, Y1 = 0.12, 2.6
AX0, AX1 = 0.12, 2.55
BX0, BX1 = 4.2, 6.88
Y_REQ, Y_DEP = 1.85, 0.95

# ── Solicitud A (productor) ─────────────────────────────────────────────────
card(AX0, AX1, Y0, Y1)
axc = (AX0 + AX1) / 2
ax.text(axc, Y1 - 0.27, "Solicitud A", ha="center", va="center", fontsize=FS + 1, weight="bold", color=INK)
mono_line([("POST /usuarios", False)], axc, Y_REQ, FS + 1)
ax.text(axc, Y_REQ - 0.4, "respuesta", ha="center", va="center", fontsize=FS - 1, color=MUTED, style="italic")
ax.add_patch(
    FancyBboxPatch(
        (axc - 0.95, Y_DEP - 0.27), 1.9, 0.54, boxstyle="round,pad=0,rounding_size=0.08", fc="white", ec="#898781", lw=1.0
    )
)
mono_line([("{ ", False), ('"id"', True), (": 42 }", False)], axc, Y_DEP, FS)

# ── Solicitud B (consumidor) ────────────────────────────────────────────────
card(BX0, BX1, Y0, Y1)
bxc = (BX0 + BX1) / 2
ax.text(bxc, Y1 - 0.27, "Solicitud B", ha="center", va="center", fontsize=FS + 1, weight="bold", color=INK)
mono_line([("GET /usuarios/", False), ("{id}", True)], bxc, Y_DEP, FS + 1)
ax.text(bxc, Y_DEP - 0.45, "usa el id recibido", ha="center", va="center", fontsize=FS - 1, color=MUTED, style="italic")

# ── Dependencia ─────────────────────────────────────────────────────────────
ax.add_patch(
    FancyArrowPatch(
        (axc + 0.95, Y_DEP),
        (BX0 + 0.12, Y_DEP),
        arrowstyle="-|>",
        mutation_scale=18,
        lw=2.0,
        color=ACCENT,
        shrinkA=2,
        shrinkB=0,
    )
)
ax.text(
    (AX1 + BX0) / 2,
    Y_DEP + 0.48,
    "productor\n→ consumidor",
    linespacing=1.3,
    ha="center",
    va="center",
    fontsize=FS - 1,
    weight="bold",
    color=ACCENT_DARK,
)

fig.savefig(OUT, dpi=300, facecolor="white")
print(OUT)
