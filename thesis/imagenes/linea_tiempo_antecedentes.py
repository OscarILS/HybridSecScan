"""Línea de tiempo de antecedentes 2013–2024 (solo los hitos indicados por el autor).

Las tarjetas alternan arriba/abajo del eje; cada una se dimensiona según su texto y se separa
horizontalmente de sus vecinas para no solaparse. Una línea guía une cada tarjeta con su año.

Regenerar:  python thesis/imagenes/linea_tiempo_antecedentes.py
"""

import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

OUT = Path(__file__).with_suffix(".png")

INK = "#0b0b0b"
LINE = "#52514e"
MUTED = "#898781"
FILL = "#f4f3ef"
ACCENT = "#2a78d6"
ACCENT_DARK = "#184f95"
FS = 13  # 13 pt en 7 in de ancho -> 11 pt impreso a 15 cm

plt.rcParams["font.family"] = "Arial"

HITOS = {
    2013: ["Vulnerabilidades en ASP.NET Web API (Lakshmiraghavan)"],
    2018: ["Métricas cuantitativas en API REST (Katt y Prasher)", "WARDroid (Mendoza y Gu)"],
    2019: ["RESTler", "IAST (Pan)", "1.ª edición del OWASP API Security Top 10"],
    2020: ["Verificadores de propiedades de seguridad", "Fuzzing de datos (Godefroid et al.)"],
    2021: ["Mapeo sistemático de vulnerabilidades en API web (Díaz-Rojas et al.)"],
    2023: ["NAUTILUS", "Asignación masiva (Corradini et al.)", "OWASP API Security Top 10:2023"],
    2024: ["APIF", "KubeFuzzer", "Marco de Khan et al."],
}
ARRIBA = ([2013, 2019, 2021, 2024], 16)  # (años, caracteres por línea)
ABAJO = ([2018, 2020, 2023], 21)

W = 7.0
X0, X1 = 0.25, 6.75  # extremos del eje
GAP_V = 0.32  # distancia vertical eje-tarjeta
GAP_H = 0.1  # separación mínima entre tarjetas
PAD = 0.08  # margen interior de la tarjeta
INDENT = 0.15  # sangría tras la viñeta
LINE_H = FS * 1.22 / 72
HEAD_H = (FS + 2) * 1.3 / 72

fig = plt.figure(figsize=(W, 6.0), dpi=300)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, W)
ax.set_ylim(-3, 3)  # eje en y = 0
ax.axis("off")
renderer = fig.canvas.get_renderer()
inv = ax.transData.inverted()


def text_w(s, **kw):
    t = ax.text(0, 0, s, fontsize=FS, **kw)
    bb = t.get_window_extent(renderer)
    t.remove()
    return inv.transform((bb.x1, 0))[0] - inv.transform((bb.x0, 0))[0]


def xyear(y):
    return X0 + (y - 2013) * (X1 - X0) / (2024 - 2013)


NBSP = " "  # espacio de no separación: evita cortes como "et / al."


def keep(it):
    return it.replace(" et al.", NBSP + "et" + NBSP + "al.").replace(" y Gu", NBSP + "y" + NBSP + "Gu")


def build(year, chars):
    items = [textwrap.wrap(keep(it), chars, break_long_words=False, break_on_hyphens=False) for it in HITOS[year]]
    body_w = max(text_w(line) for lines in items for line in lines)
    width = max(INDENT + body_w, text_w(str(year), weight="bold")) + 2 * PAD
    n = sum(len(lines) for lines in items)
    height = HEAD_H + n * LINE_H + 2 * PAD
    return items, width, height


def layout(years, widths):
    """Centros lo más cerca posible de su año, sin solaparse y dentro de la figura."""
    xs = [xyear(y) for y in years]
    for _ in range(300):
        for i in range(len(xs)):
            lo, hi = widths[i] / 2 + 0.03, W - widths[i] / 2 - 0.03
            xs[i] = min(max(xs[i], lo), hi)
        for i in range(1, len(xs)):
            need = (widths[i - 1] + widths[i]) / 2 + GAP_H
            if xs[i] - xs[i - 1] < need:
                push = (need - (xs[i] - xs[i - 1])) / 2
                xs[i - 1] -= push
                xs[i] += push
    return xs


# ── Eje con marcas anuales ──────────────────────────────────────────────────
ax.plot([X0 - 0.12, X1 + 0.12], [0, 0], color=LINE, lw=2.2, solid_capstyle="round", zorder=2)
for y in range(2013, 2025):
    ax.plot([xyear(y)] * 2, [-0.05, 0.05], color=LINE, lw=1.2, zorder=2)

extent = {1: 0.0, -1: 0.0}
for (years, chars), sign in ((ARRIBA, 1), (ABAJO, -1)):
    cards = [build(y, chars) for y in years]
    centers = layout(years, [c[1] for c in cards])
    for year, cx, (items, width, height) in zip(years, centers, cards):
        edge = sign * GAP_V
        y0 = edge if sign > 0 else edge - height
        x0 = cx - width / 2
        extent[sign] = max(extent[sign], GAP_V + height)
        ax.add_patch(
            FancyBboxPatch(
                (x0, y0), width, height, boxstyle="round,pad=0,rounding_size=0.06", fc=FILL, ec=LINE, lw=1.2,
                zorder=3,
            )
        )
        ytop = y0 + height - PAD
        ax.text(x0 + PAD, ytop, str(year), fontsize=FS + 2, weight="bold", color=ACCENT_DARK, ha="left", va="top",
                zorder=4)
        yl = ytop - HEAD_H
        for lines in items:
            ax.text(x0 + PAD, yl, "•", fontsize=FS, color=INK, ha="left", va="top", zorder=4)
            ax.text(x0 + PAD + INDENT, yl, "\n".join(lines), fontsize=FS, color=INK, ha="left", va="top",
                    linespacing=1.22, zorder=4)
            yl -= len(lines) * LINE_H
        # Guía tarjeta -> año y punto del hito
        ax.plot([xyear(year), cx], [0, edge], color=MUTED, lw=1.2, zorder=1)
        ax.plot(xyear(year), 0, "o", ms=8, color=ACCENT, mec="white", mew=1.2, zorder=5)

# Recortar la figura al contenido (mismo ancho, alto justo)
top, bottom = extent[1] + 0.05, extent[-1] + 0.05
ax.set_ylim(-bottom, top)
fig.set_size_inches(W, top + bottom)
fig.savefig(OUT, dpi=300, facecolor="white")
print(OUT)
