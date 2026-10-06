"""Vulnerabilidades del ground truth según la técnica que las detectó (barras horizontales apiladas).

Los conteos se calculan aquí desde "vulnerabilities_found" de los métodos sast y dast de:
  data/experiments/correlation_evaluation_vulnerable_app_20261001_142307.json
  data/experiments/correlation_evaluation_vampi_20261001_142307.json
Juice Shop no se incluye: esa ejecución no se comparó con un ground truth.

Regenerar:  python thesis/imagenes/solapamiento_sast_dast.py
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
EXP = ROOT / "data" / "experiments"
OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
INK2 = "#52514e"
BASELINE = "#c3c2b7"
ACCENT = "#2a78d6"
SURFACE = "white"
FS = 13  # 13 pt en 7 in de ancho -> 11 pt impreso a 15 cm

plt.rcParams["font.family"] = "Arial"

APPS = [
    ("vulnerable_app.py", "correlation_evaluation_vulnerable_app_20261001_142307.json"),
    ("VAmPI", "correlation_evaluation_vampi_20261001_142307.json"),
]
# Orden tipo diagrama de Venn: solo SAST | ambas | solo DAST | ninguna. "Ambas" es el único acento.
SEGMENTOS = [
    ("Solo SAST", "#6b6a66", "white"),
    ("Ambas (confirmables por el motor)", ACCENT, "white"),
    ("Solo DAST", "#b9b7af", INK),
    ("Ninguna", "#ecebe6", INK),
]


def conteos(path):
    d = json.loads(path.read_text(encoding="utf-8"))
    sast = set(d["methods"]["sast"]["vulnerabilities_found"])
    dast = set(d["methods"]["dast"]["vulnerabilities_found"])
    n = d["ground_truth_n"]
    both = sast & dast
    vals = [len(sast - dast), len(both), len(dast - sast), n - len(sast | dast)]
    assert sorted(both) == sorted(d["detected_by_both"])
    return n, vals


datos = [(label, *conteos(EXP / fname)) for label, fname in APPS]
for label, n, vals in datos:
    print(f"{label:18} n={n}  solo SAST={vals[0]}  ambas={vals[1]}  solo DAST={vals[2]}  ninguna={vals[3]}")

fig, ax = plt.subplots(figsize=(7.0, 3.0), dpi=300)
fig.subplots_adjust(left=0.29, right=0.98, top=0.97, bottom=0.45)

ys = list(range(len(datos)))[::-1]
for y, (label, n, vals) in zip(ys, datos):
    left = 0
    for (name, color, txt), v in zip(SEGMENTOS, vals):
        if v == 0:
            continue
        ax.barh(y, v, left=left, height=0.58, color=color, edgecolor=SURFACE, linewidth=2, zorder=3)
        ax.text(left + v / 2, y, str(v), ha="center", va="center", fontsize=FS, color=txt,
                weight="bold" if color == ACCENT else "normal", zorder=4)
        left += v
    if vals[1] == 0:  # hacer visible que no hubo ninguna detectada por ambas
        ax.text(n + 0.12, y, "ambas = 0", ha="left", va="center", fontsize=FS, color=INK, weight="bold")

n_max = max(n for _, n, _ in datos)
ax.set_xlim(0, n_max + 1.9)
ax.set_ylim(-0.55, len(datos) - 0.45)
ax.set_yticks(ys)
ax.set_yticklabels([f"{label} ({n})" for label, n, _ in datos], fontsize=FS, color=INK)
ax.set_xticks(range(0, n_max + 1))
ax.set_xticklabels([str(i) for i in range(0, n_max + 1)], fontsize=FS, color=INK2)
ax.set_xlabel("Vulnerabilidades del ground truth", fontsize=FS, color=INK)
ax.tick_params(axis="y", length=0, pad=6)
ax.tick_params(axis="x", color=BASELINE)
for side in ("top", "right", "left"):
    ax.spines[side].set_visible(False)
ax.spines["bottom"].set_color(BASELINE)
ax.spines["bottom"].set_bounds(0, n_max)

handles = [Patch(facecolor=c, edgecolor=BASELINE if c == "#ecebe6" else "none", label=name) for name, c, _ in SEGMENTOS]
fig.legend(handles=handles, loc="lower center", ncol=2, frameon=False, fontsize=FS, handlelength=1.1,
           handleheight=1.1, columnspacing=1.4, handletextpad=0.4, bbox_to_anchor=(0.5, 0.0))

fig.savefig(OUT, dpi=300, facecolor=SURFACE)
print(OUT)
