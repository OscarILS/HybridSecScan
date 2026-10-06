"""Desglose de la confianza de correlación por factor (barras horizontales apiladas).

Fuentes (valores verificados):
  - VA_002, VA_009: data/experiments/figures/tabla_evaluacion_correlacion.md
  - Juice Shop (mejor par): data/experiments/EXPERIMENTAL_RESULTS_SUMMARY.md
Los totales son los publicados en esas fuentes (VA_009: los aportes redondeados suman 0.506; el total
sin redondear es 0.507).

Regenerar:  python thesis/imagenes/desglose_confianza.py
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#898781"
BASELINE = "#c3c2b7"
SURFACE = "white"
FS = 13  # 13 pt en 7 in de ancho -> 11 pt impreso a 15 cm

plt.rcParams["font.family"] = "Arial"

# Factores en el orden de la suma; grises de luminosidad alterna y el Random Forest como único acento.
FACTORES = [
    ("Endpoint", "#5f5e5a"),
    ("Tipo", "#b9b7af"),
    ("Semántica", "#878580"),
    ("Random Forest", "#2a78d6"),
    ("Severidad", "#dddbd4"),
]
PARES = [  # (etiqueta, aportes en el orden de FACTORES, total publicado)
    ("VA_002 (inyección SQL)", [0.400, 0.350, 0.037, 0.047, 0.033], 0.867),
    ("VA_009 (modo de depuración)", [0.036, 0.350, 0.045, 0.025, 0.050], 0.507),
    ("Juice Shop (mejor par)", [0.150, 0.200, 0.016, 0.018, 0.050], 0.434),
]
UMBRAL = 0.70

fig, ax = plt.subplots(figsize=(7.0, 3.1), dpi=300)
fig.subplots_adjust(left=0.385, right=0.965, top=0.87, bottom=0.33)

ys = list(range(len(PARES)))[::-1]  # primera barra arriba
for y, (label, aportes, total) in zip(ys, PARES):
    left = 0.0
    for (name, color), v in zip(FACTORES, aportes):
        ax.barh(y, v, left=left, height=0.56, color=color, edgecolor=SURFACE, linewidth=1.5, zorder=3)
        left += v
    ax.text(left + 0.012, y, f"{total:.3f}", va="center", ha="left", fontsize=FS, color=INK, zorder=4)

# Umbral
ax.axvline(UMBRAL, color=INK2, lw=1.4, ls=(0, (5, 4)), zorder=2)
ax.text(UMBRAL, len(PARES) - 0.45, "Umbral (C > 0.70)", ha="center", va="bottom", fontsize=FS, color=INK2)

# Ejes
ax.set_xlim(0, 1)
ax.set_ylim(-0.5, len(PARES) - 0.5)
ax.set_yticks(ys)
ax.set_yticklabels([p[0] for p in PARES], fontsize=FS, color=INK)
ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
ax.set_xticklabels(["0", "0.2", "0.4", "0.6", "0.8", "1.0"], fontsize=FS, color=INK2)
ax.set_xlabel("Confianza", fontsize=FS, color=INK)
ax.tick_params(axis="y", length=0, pad=6)
ax.tick_params(axis="x", color=BASELINE)
for side in ("top", "right", "left"):
    ax.spines[side].set_visible(False)
ax.spines["bottom"].set_color(BASELINE)
ax.grid(axis="x", color="#e1e0d9", lw=0.8, zorder=0)

# Leyenda de factores debajo del gráfico
handles = [Patch(facecolor=c, edgecolor="none", label=n) for n, c in FACTORES]
fig.legend(
    handles=handles,
    loc="lower center",
    ncol=5,
    frameon=False,
    fontsize=FS,
    handlelength=1.1,
    handleheight=1.1,
    columnspacing=1.1,
    handletextpad=0.4,
    bbox_to_anchor=(0.5, 0.0),
)

fig.savefig(OUT, dpi=300, facecolor=SURFACE)
print(OUT)
