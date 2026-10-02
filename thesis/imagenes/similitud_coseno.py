"""Similitud coseno: dos vectores con el ángulo θ marcado; panel derecho con vectores casi ortogonales.

Valores ilustrativos (no son datos del proyecto).

Regenerar:  python thesis/imagenes/similitud_coseno.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.patches import Arc  # noqa: E402

OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
LINE = "#52514e"
MUTED = "#6b6a66"
GRID = "#d9d8d3"
ACCENT = "#2a78d6"
ACCENT_DARK = "#184f95"
FS = 14

plt.rcParams["font.family"] = "Arial"
plt.rcParams["mathtext.fontset"] = "dejavusans"


def panel(ax, ang_a, ang_b, title, len_a=1.0, len_b=0.85):
    a = len_a * np.array([np.cos(np.radians(ang_a)), np.sin(np.radians(ang_a))])
    b = len_b * np.array([np.cos(np.radians(ang_b)), np.sin(np.radians(ang_b))])
    theta = abs(ang_b - ang_a)

    ax.set_xlim(-0.12, 1.15)
    ax.set_ylim(-0.12, 1.15)
    ax.set_aspect("equal")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.plot(0, 0, "o", color=LINE, ms=5)  # origen
    ax.set_xticks([])
    ax.set_yticks([])

    for v, name, color in ((a, "a", ACCENT), (b, "b", LINE)):
        ax.annotate(
            "",
            xy=v,
            xytext=(0, 0),
            arrowprops=dict(arrowstyle="-|>", color=color, lw=2.4, mutation_scale=20, shrinkA=0, shrinkB=0),
        )
        off = v / np.linalg.norm(v) * 0.09
        ax.text(
            v[0] + off[0], v[1] + off[1], rf"$\mathbf{{{name}}}$", fontsize=FS + 4, color=color,
            ha="center", va="center",
        )

    r = 0.32
    lo, hi = sorted((ang_a, ang_b))
    ax.add_patch(Arc((0, 0), 2 * r, 2 * r, theta1=lo, theta2=hi, color=ACCENT_DARK, lw=1.8))
    mid = np.radians((lo + hi) / 2)
    rt = r + 0.1
    ax.text(rt * np.cos(mid), rt * np.sin(mid), r"$\theta$", fontsize=FS + 2, color=ACCENT_DARK, ha="center", va="center")

    ax.set_title(title, fontsize=FS, color=INK, weight="bold", pad=6)
    ax.text(
        0.55, -0.1, rf"$\theta \approx {theta:.0f}°$,  $\cos\theta \approx {np.cos(np.radians(theta)):.2f}$",
        fontsize=FS - 1, color=MUTED, ha="center", va="top", transform=ax.transData,
    )


fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 3.9), dpi=300)
fig.subplots_adjust(left=0.03, right=0.97, top=0.73, bottom=0.12, wspace=0.15)
panel(ax1, 15, 40, "Textos relacionados")
panel(ax2, 4, 89, "Textos no relacionados")

fig.text(
    0.5,
    0.92,
    r"$\mathrm{sim}(\mathbf{a},\mathbf{b}) = \cos\theta = "
    r"\dfrac{\mathbf{a}\cdot\mathbf{b}}{\|\mathbf{a}\|\;\|\mathbf{b}\|}$",
    ha="center",
    va="center",
    fontsize=FS + 2,
    color=INK,
)

fig.savefig(OUT, dpi=300, facecolor="white")
print(OUT)
