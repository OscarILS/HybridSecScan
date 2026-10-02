"""Estructura de un JSON Web Token: cabecera . carga útil . firma, con un ejemplo genérico truncado.

Los segmentos de ejemplo son la codificación base64url real del inicio de cada parte
({"alg":"HS256"... -> eyJhbGciOi..., {"sub":... -> eyJzdWIiOi...); la firma es inventada. Sin datos reales.

Regenerar:  python thesis/imagenes/jwt_estructura.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
LINE = "#52514e"
MUTED = "#6b6a66"
FILL = "#f4f3ef"
ACCENT = "#2a78d6"
FS = 14
MONO = "Consolas"

plt.rcParams["font.family"] = "Arial"

W, H = 7.0, 3.8  # pulgadas; el eje usa pulgadas como unidades
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


# ── Token de ejemplo (tres segmentos separados por puntos) ──────────────────
Y_TOK = 3.3
segments = ["eyJhbGciOi…", "eyJzdWIiOi…", "k3Xa9fQ2…"]
seg_texts = [ax.text(0, Y_TOK, s, fontsize=FS + 1, family=MONO, weight="bold", color=INK, va="center") for s in segments]
dots = [ax.text(0, Y_TOK, ".", fontsize=FS + 16, family=MONO, weight="bold", color=ACCENT, va="center") for _ in range(2)]
widths = [width_in(t) for t in seg_texts]
w_dot = width_in(dots[0]) + 0.04
total = sum(widths) + 2 * w_dot
x = W / 2 - total / 2
seg_centers = []
for i, t in enumerate(seg_texts):
    t.set_position((x, Y_TOK))
    seg_centers.append((x + widths[i] / 2, widths[i]))
    x += widths[i]
    if i < 2:
        dots[i].set_position((x + 0.02, Y_TOK - 0.02))
        x += w_dot

# ── Bloques ─────────────────────────────────────────────────────────────────
BW = 2.12
centers = [1.22, 3.5, 5.78]
Y0, Y1 = 0.08, 2.35
blocks = [
    ("Cabecera", "algoritmo y tipo", '{\n  "alg": "HS256",\n  "typ": "JWT"\n}', MONO),
    ("Carga útil", "claims", '{\n  "sub": "usuario",\n  "exp": 1735689600\n}', MONO),
    ("Firma", "integridad del token", "HMAC-SHA256(\n  cabecera + \".\" +\n  carga útil,\n  clave secreta)", "Arial"),
]
for cx, (title, sub, body, family) in zip(centers, blocks):
    ax.add_patch(
        FancyBboxPatch(
            (cx - BW / 2, Y0), BW, Y1 - Y0, boxstyle="round,pad=0,rounding_size=0.12", fc=FILL, ec=LINE, lw=1.4
        )
    )
    ax.text(cx, Y1 - 0.25, title, ha="center", va="center", fontsize=FS + 1, weight="bold", color=INK)
    ax.text(cx, Y1 - 0.52, sub, ha="center", va="center", fontsize=FS - 1, color=MUTED, style="italic")
    ax.text(
        cx,
        Y1 - 1.38,
        body,
        ha="center",
        va="center",
        multialignment="left",
        fontsize=FS - 1,
        family=family,
        color=INK,
        linespacing=1.3,
        bbox=dict(boxstyle="round,pad=0.25,rounding_size=0.08", fc="white", ec="#898781", lw=1.0),
    )

# ── Conexión de cada segmento con su bloque ─────────────────────────────────
Y_UL = Y_TOK - 0.2
for (sx, sw), cx in zip(seg_centers, centers):
    ax.plot([sx - sw / 2, sx + sw / 2], [Y_UL, Y_UL], color=LINE, lw=1.6, solid_capstyle="butt")
    ax.annotate(
        "",
        xy=(cx, Y1 + 0.02),
        xytext=(sx, Y_UL),
        arrowprops=dict(arrowstyle="-|>", color=LINE, lw=1.6, mutation_scale=16, shrinkA=0, shrinkB=0),
    )

ax.text(
    W / 2,
    Y_TOK + 0.27,
    "base64url(cabecera) . base64url(carga útil) . firma",
    ha="center",
    va="center",
    fontsize=FS - 1,
    color=MUTED,
)

fig.savefig(OUT, dpi=300, facecolor="white")
print(OUT)
