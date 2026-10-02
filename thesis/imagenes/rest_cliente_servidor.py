"""Diagrama cliente-servidor REST: POST /users/v1/login -> 200 OK + JSON (cuerpo real del login de VAmPI), con llave "método + ruta = endpoint".

Regenerar:  python thesis/imagenes/rest_cliente_servidor.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
LINE = "#52514e"
MUTED = "#898781"
FILL = "#f4f3ef"
ACCENT = "#2a78d6"
ACCENT_DARK = "#184f95"
ACCENT_FILL = "#e8f1fc"
FS = 14
MONO = "Consolas"

plt.rcParams["font.family"] = "Arial"

W, H = 7.0, 4.75  # pulgadas; el eje usa pulgadas como unidades
fig = plt.figure(figsize=(W, H), dpi=300)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(0, H)
ax.axis("off")


def box(x0, y0, x1, y1, fc, ec, lw=1.4, ls="-"):
    ax.add_patch(
        FancyBboxPatch(
            (x0, y0), x1 - x0, y1 - y0, boxstyle="round,pad=0,rounding_size=0.12", fc=fc, ec=ec, lw=lw, ls=ls
        )
    )


def arrow(x0, x1, y):
    ax.add_patch(
        FancyArrowPatch((x0, y), (x1, y), arrowstyle="-|>", mutation_scale=18, lw=1.8, color=LINE, shrinkA=0, shrinkB=0)
    )


def brace_up(x0, x1, y, height=0.2, color=ACCENT):
    """Llave horizontal sobre [x0, x1] con la punta hacia arriba (dos medias llaves simétricas)."""
    t = np.linspace(0, 1, 400)
    k = 40

    def sig(u):
        return 1 / (1 + np.exp(-k * u))

    half = 0.5 * sig(t - 0.06) + 0.5 * sig(t - 0.94)  # curva en el extremo, tramo plano, punta al centro
    half = (half - half[0]) / (half[-1] - half[0])
    mid = (x0 + x1) / 2
    ax.plot(x0 + (mid - x0) * t, y + height * half, color=color, lw=1.8, solid_capstyle="round")
    ax.plot(x1 - (x1 - mid) * t, y + height * half, color=color, lw=1.8, solid_capstyle="round")


# ── Cliente y servidor ──────────────────────────────────────────────────────
CX0, CX1 = 0.15, 1.65
SX0, SX1 = 5.35, 6.85
YB0, YB1 = 1.6, 3.3
box(CX0, YB0, CX1, YB1, FILL, LINE)
box(SX0, YB0, SX1, YB1, FILL, LINE)
ax.text((CX0 + CX1) / 2, (YB0 + YB1) / 2, "Cliente", ha="center", va="center", fontsize=FS + 2, weight="bold", color=INK)
ax.text(
    (SX0 + SX1) / 2,
    (YB0 + YB1) / 2,
    "Servidor\nAPI REST",
    ha="center",
    va="center",
    fontsize=FS + 2,
    weight="bold",
    color=INK,
    linespacing=1.3,
)

# ── Solicitud ───────────────────────────────────────────────────────────────
Y_REQ = 2.9
arrow(CX1, SX0, Y_REQ)
ax.text(3.5, Y_REQ - 0.28, "solicitud", ha="center", va="center", fontsize=FS - 1, color=MUTED, style="italic")

renderer = fig.canvas.get_renderer()
t_met = ax.text(0, 0, "POST", fontsize=FS + 1, family=MONO, weight="bold", color=INK, va="center")
t_sp = ax.text(0, 0, " ", fontsize=FS + 1, family=MONO, va="center")
t_path = ax.text(0, 0, "/users/v1/login", fontsize=FS + 1, family=MONO, weight="bold", color=INK, va="center")
inv = ax.transData.inverted()


def width_in(t):
    bb = t.get_window_extent(renderer)
    return inv.transform((bb.x1, 0))[0] - inv.transform((bb.x0, 0))[0]


w_met, w_sp, w_path = width_in(t_met), width_in(t_sp), width_in(t_path)
total = w_met + w_sp + w_path
x_start = 3.5 - total / 2
Y_TXT = Y_REQ + 0.72
t_met.set_position((x_start, Y_TXT))
t_path.set_position((x_start + w_met + w_sp, Y_TXT))
t_sp.remove()

# Recuadro de la línea de solicitud
box(x_start - 0.12, Y_TXT - 0.2, x_start + total + 0.12, Y_TXT + 0.2, "white", LINE, lw=1.2)

# Llave sobre "POST /users/v1/login"
Y_BR = Y_TXT + 0.27
brace_up(x_start - 0.05, x_start + total + 0.05, Y_BR)
ax.text(
    3.5,
    Y_BR + 0.38,
    "método + ruta = endpoint",
    ha="center",
    va="center",
    fontsize=FS,
    weight="bold",
    color=ACCENT_DARK,
    bbox=dict(boxstyle="round,pad=0.3,rounding_size=0.15", fc=ACCENT_FILL, ec=ACCENT, lw=1.4),
)
ax.text(x_start + w_met / 2, Y_TXT - 0.36, "método", ha="center", va="center", fontsize=FS - 1, color=MUTED)
ax.text(x_start + w_met + w_sp + w_path / 2, Y_TXT - 0.36, "ruta", ha="center", va="center", fontsize=FS - 1, color=MUTED)

# ── Respuesta ───────────────────────────────────────────────────────────────
Y_RES = 1.8
arrow(SX0, CX1, Y_RES)
ax.text(3.5, Y_RES + 0.27, "200 OK", ha="center", va="center", fontsize=FS + 1, family=MONO, weight="bold", color=INK)
ax.text(
    3.5,
    Y_RES - 0.32,
    '{\n  "status": "success",\n  "message": "Successfully logged in.",\n  "auth_token": "eyJhbGciOi…"\n}',
    multialignment="left",
    ha="center",
    va="top",
    fontsize=FS - 1,
    family=MONO,
    color=INK,
    bbox=dict(boxstyle="round,pad=0.3,rounding_size=0.1", fc="white", ec=MUTED, lw=1.2, ls="--"),
)
ax.text(3.5, Y_RES - 1.66, "respuesta: cuerpo JSON", ha="center", va="center", fontsize=FS - 1, color=MUTED, style="italic")

fig.savefig(OUT, dpi=300, facecolor="white")
print(OUT)
