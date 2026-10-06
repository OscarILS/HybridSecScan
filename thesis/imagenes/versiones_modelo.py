"""Precisión, recall y F1 del Random Forest: versión inicial vs. final (prueba y conjunto independiente).

Fuentes (los valores se leen de los archivos, no se escriben a mano):
  - Versión inicial (prueba):           data/models/metadata_v1.json  (git d527262, antes de module_match)
  - Versión final (prueba):             data/models/metadata.json
  - Versión final (conj. independiente): data/experiments/holdout_evaluation_20261001_223335.json
Referencias triviales (predecir siempre "correlacionado"): F1 = 2·P/(n+P), con P positivos de n pares.

Regenerar:  python thesis/imagenes/versiones_modelo.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
INK2 = "#52514e"
BASELINE = "#c3c2b7"
GRID = "#e1e0d9"
SURFACE = "white"
FS = 13  # 13 pt en 7 in de ancho -> 11 pt impreso a 15 cm

plt.rcParams["font.family"] = "Arial"


def load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


v1 = load("data/models/metadata_v1.json")
fin = load("data/models/metadata.json")
hold = load("data/experiments/holdout_evaluation_20261001_223335.json")


def prf(m):
    return [m["precision"], m["recall"], m["f1_score"]]


def trivial_f1(cm):
    pos = cm["TP"] + cm["FN"]
    n = sum(cm.values())
    return 2 * pos / (n + pos)


SERIES = [  # (etiqueta, valores, color) — gris para la versión superada, azules para la final
    ("Versión inicial (prueba)", prf(v1["test"]), "#a3a19a"),
    ("Versión final (prueba)", prf(fin["test"]), "#2a78d6"),
    ("Versión final (conjunto independiente)", prf(hold["metrics"]), "#86b6ef"),
]
REFS = [
    ("Referencia trivial (prueba)", trivial_f1(fin["confusion_matrix"]), (0, (5, 3))),
    ("Referencia trivial (independiente)", trivial_f1(hold["confusion_matrix"]), (0, (1.5, 2))),
]
for name, vals, _ in SERIES:
    print(f"{name:40} P={vals[0]:.3f} R={vals[1]:.3f} F1={vals[2]:.3f}")
for name, v, _ in REFS:
    print(f"{name:40} F1={v:.3f}")

METRICAS = ["Precisión", "Recall", "F1"]
x = np.arange(len(METRICAS))
bw = 0.25

fig, ax = plt.subplots(figsize=(7.0, 4.3), dpi=300)
fig.subplots_adjust(left=0.08, right=0.98, top=0.97, bottom=0.30)

for i, (name, vals, color) in enumerate(SERIES):
    xs = x + (i - 1) * bw
    ax.bar(xs, vals, width=bw, color=color, edgecolor=SURFACE, linewidth=1.5, label=name, zorder=3)
    txt = "white" if color == "#2a78d6" else INK
    for xi, v in zip(xs, vals):
        ax.text(xi, 0.03, f"{v:.3f}", ha="center", va="bottom", rotation=90, fontsize=FS, color=txt, zorder=4)

# Referencias triviales: solo sobre el grupo F1, rotuladas a la derecha
x0, x1 = x[2] - 1.5 * bw - 0.04, x[2] + 1.5 * bw + 0.04
for (name, v, ls), va, dy in zip(REFS, ("top", "bottom"), (-0.012, 0.012)):
    ax.plot([x0, x1], [v, v], color=INK, lw=1.0, ls=ls, zorder=5)
    label = name.replace(" (", "\n(") + f" {v:.3f}"
    ax.text(x1 + 0.05, v + dy, label, ha="left", va=va, fontsize=FS, color=INK, linespacing=1.15)

ax.set_ylim(0, 1)
ax.set_xlim(-0.5, 2.5 + 1.45)
ax.set_xticks(x)
ax.set_xticklabels(METRICAS, fontsize=FS, color=INK)
ax.set_yticks(np.linspace(0, 1, 6))
ax.set_yticklabels([f"{t:.1f}" for t in np.linspace(0, 1, 6)], fontsize=FS, color=INK2)
ax.tick_params(axis="x", length=0, pad=6)
ax.tick_params(axis="y", length=0)
for side in ("top", "right", "left"):
    ax.spines[side].set_visible(False)
ax.spines["bottom"].set_color(BASELINE)
ax.spines["bottom"].set_bounds(-0.5, 2.5)
ax.grid(axis="y", color=GRID, lw=0.8, zorder=0)

fig.legend(loc="lower left", ncol=1, frameon=False, fontsize=FS, handlelength=1.1, handleheight=1.1,
           columnspacing=1.4, handletextpad=0.4, bbox_to_anchor=(0.07, 0.0))

fig.savefig(OUT, dpi=300, facecolor=SURFACE)
print(OUT)
