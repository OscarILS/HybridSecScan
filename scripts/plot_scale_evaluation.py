"""
Figuras y tablas de la evaluación a escala para la tesis.

Lee el scale_evaluation_*.json más reciente (o el indicado con --file) y genera,
en data/experiments/figures/:

  fig_metricas_por_metodo.png   Precision / Recall / F1 medios por método
  fig_f1_por_aplicacion.png     F1 de cada método en cada aplicación
  fig_f1_pareado_sast_hibrido.png  F1 por aplicación: SAST → Híbrido (datos de la prueba t)
  tablas_evaluacion.md          Tablas de métricas y de pruebas t (para copiar a la tesis)

Uso:
    python scripts/plot_scale_evaluation.py
    python scripts/plot_scale_evaluation.py --file data/experiments/scale_evaluation_20260929_203402.json
"""

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Rectangle  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
EXP_DIR = REPO / "data" / "experiments"
OUT_DIR = EXP_DIR / "figures"

# Paleta categórica validada (orden fijo, CVD-safe en todos los pares para 3 series).
# Cada método tiene siempre el mismo color en todas las figuras.
METHOD_COLORS = {"SAST": "#2a78d6", "DAST": "#eb6834", "Híbrido": "#1baf7a"}
METHOD_KEYS = {"SAST": "sast", "DAST": "dast", "Híbrido": "hybrid"}
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
NEUTRAL_LINE = "#898781"

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.sans-serif": ["Arial", "Segoe UI", "DejaVu Sans"],
        "font.size": 10,
        "axes.edgecolor": AXIS,
        "axes.labelcolor": INK_2,
        "xtick.color": INK_2,
        "ytick.color": MUTED,
        "savefig.dpi": 300,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
    }
)


def latest_evaluation(path: str = None) -> Path:
    if path:
        return Path(path)
    files = sorted(EXP_DIR.glob("scale_evaluation_*.json"))
    if not files:
        raise SystemExit("No hay scale_evaluation_*.json. Ejecuta: python scripts/run_scale_evaluation.py --save")
    return files[-1]


def style_axes(ax, ylabel: str):
    ax.set_ylim(0, 1)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(axis="both", length=0)


def rounded_bar(ax, x, width, height, color, radius_pts=2.5):
    """Barra con extremo de dato redondeado y base recta (la base queda en y=0)."""
    if height <= 0:
        # Valor cero: marca mínima sobre la base para que se vea que existe
        ax.add_patch(Rectangle((x, 0), width, 0.004, facecolor=color, edgecolor="none"))
        return
    # Radio en unidades de datos, acotado para barras muy bajas
    fig = ax.figure
    px_per_unit_y = ax.transData.transform((0, 1))[1] - ax.transData.transform((0, 0))[1]
    px_per_unit_x = ax.transData.transform((1, 0))[0] - ax.transData.transform((0, 0))[0]
    r_px = radius_pts * fig.dpi / 72
    ry = min(r_px / px_per_unit_y, height / 2)
    rx = min(r_px / px_per_unit_x, width / 2)
    ax.add_patch(
        FancyBboxPatch(
            (x, 0),
            width,
            height,
            boxstyle=f"round,pad=0,rounding_size={min(rx, ry)}",
            mutation_aspect=ry / max(rx, 1e-9),
            facecolor=color,
            edgecolor="none",
        )
    )
    # Cuadra la base: tapa las esquinas redondeadas inferiores
    ax.add_patch(Rectangle((x, 0), width, min(height, ry * 1.05), facecolor=color, edgecolor="none"))


def grouped_bars(ax, groups, series, values, gap=0.012, bar_w=0.22):
    """values[s][g] -> barras agrupadas; series con color fijo por método."""
    n = len(series)
    for g_i, _ in enumerate(groups):
        start = g_i - (n * bar_w + (n - 1) * gap) / 2
        for s_i, s in enumerate(series):
            v = values[s][g_i]
            x = start + s_i * (bar_w + gap)
            rounded_bar(ax, x, bar_w, v, METHOD_COLORS[s])
            ax.text(x + bar_w / 2, v + 0.015, f"{v:.3f}", ha="center", va="bottom", fontsize=8, color=INK_2)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels(groups)
    ax.set_xlim(-0.6, len(groups) - 0.4)


def legend_for(ax, series):
    handles = [Rectangle((0, 0), 1, 1, facecolor=METHOD_COLORS[s], edgecolor="none") for s in series]
    ax.legend(handles, series, frameon=False, ncol=len(series), loc="upper left", bbox_to_anchor=(0, 1.12), fontsize=9)


def fig_metricas_por_metodo(data, out: Path):
    metrics = [("Precision", "mean_precision"), ("Recall", "mean_recall"), ("F1", "mean_f1")]
    series = list(METHOD_COLORS)
    values = {s: [data[METHOD_KEYS[s]][k] for _, k in metrics] for s in series}
    fig, ax = plt.subplots(figsize=(7, 4.2))
    style_axes(ax, "Valor medio (n = %d aplicaciones)" % data["n_apps"])
    grouped_bars(ax, [m for m, _ in metrics], series, values)
    legend_for(ax, series)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def fig_f1_por_aplicacion(data, out: Path):
    apps = list(data["per_app"])
    series = list(METHOD_COLORS)
    values = {s: [data["per_app"][a][METHOD_KEYS[s]]["f1"] for a in apps] for s in series}
    fig, ax = plt.subplots(figsize=(8, 4.2))
    style_axes(ax, "F1-Score")
    grouped_bars(ax, apps, series, values)
    legend_for(ax, series)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def fig_f1_pareado(data, out: Path):
    """Slope chart: F1 de SAST y del híbrido en cada aplicación (los pares de la prueba t)."""
    apps = list(data["per_app"])
    fig, ax = plt.subplots(figsize=(5.5, 4.4))
    style_axes(ax, "F1-Score")
    ax.set_ylim(0, 0.5)
    ax.set_yticks([0, 0.1, 0.2, 0.3, 0.4, 0.5])
    xs = (0, 1)
    for a in apps:
        s = data["per_app"][a]["sast"]["f1"]
        h = data["per_app"][a]["hybrid"]["f1"]
        ax.plot(xs, (s, h), color=NEUTRAL_LINE, linewidth=2, solid_capstyle="round", zorder=2)
        ax.scatter([0], [s], s=64, color=METHOD_COLORS["SAST"], edgecolors="white", linewidths=2, zorder=3)
        ax.scatter([1], [h], s=64, color=METHOD_COLORS["Híbrido"], edgecolors="white", linewidths=2, zorder=3)
        ax.text(1.06, h, f"{a}  ({h:.3f})", va="center", fontsize=8.5, color=INK_2)
        ax.text(-0.06, s, f"{s:.3f}", va="center", ha="right", fontsize=8.5, color=INK_2)
    ax.set_xticks(xs)
    ax.set_xticklabels(["SAST", "Híbrido"])
    ax.set_xlim(-0.35, 1.9)
    t = data.get("statistical_tests", {}).get("hybrid_vs_sast", {})
    if t:
        p2 = t.get("p_two_tailed", t.get("p"))
        ax.set_title(
            f"t = {t['t']:.2f}, p bilateral = {p2:.3f} (gl = {data['n_apps'] - 1})",
            fontsize=9,
            color=INK_2,
            loc="left",
        )
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def tablas_markdown(data, source: str) -> str:
    lines = [
        "# Tablas de la evaluación a escala",
        "",
        f"Fuente: `data/experiments/{source}` — {data['n_apps']} aplicaciones, "
        "ground truth de 5 vulnerabilidades por aplicación.",
        "",
        '"Híbrido" es la unión de los hallazgos SAST y DAST comparada contra el ground truth: mide la cobertura '
        "combinada de ambas técnicas y no aplica el motor de correlación.",
        "",
        "## Métricas medias por método",
        "",
        "| Método | Precision | Recall | F1 |",
        "|---|---|---|---|",
    ]
    for label, key in METHOD_KEYS.items():
        m = data[key]
        lines.append(f"| {label} | {m['mean_precision']:.3f} | {m['mean_recall']:.3f} | {m['mean_f1']:.3f} |")

    lines += [
        "",
        "## Resultados por aplicación",
        "",
        "| Aplicación | Método | Hallazgos | TP | FP | FN | Precision | Recall | F1 |",
    ]
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for app, r in data["per_app"].items():
        for label, key in METHOD_KEYS.items():
            m = r[key]
            lines.append(
                f"| {app} | {label} | {m['findings']} | {m['tp']} | {m['fp']} | {m['fn']} | "
                f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |"
            )

    tests = data.get("statistical_tests", {})
    df = tests.get("df", data["n_apps"] - 1)
    lines += [
        "",
        f"## Prueba t de Student emparejada (gl = {df}; H₁: híbrido > método individual)",
        "",
        "| Comparación | t | p unilateral | p bilateral | Cohen's d | Significativa (p < 0.05) |",
        "|---|---|---|---|---|---|",
    ]
    names = {
        "hybrid_vs_sast": "F1: Híbrido vs SAST",
        "hybrid_vs_dast": "F1: Híbrido vs DAST",
        "recall_hybrid_vs_sast": "Recall: Híbrido vs SAST",
    }
    for key, label in names.items():
        t = tests.get(key)
        if not t:
            continue
        d = f"{t['cohens_d']:.2f}" if "cohens_d" in t else "—"
        sig = "Sí (unilateral)" if t.get("significant") else "No"
        lines.append(
            f"| {label} | {t['t']:.2f} | {t.get('p_one_tailed', float('nan')):.3f} | "
            f"{t.get('p_two_tailed', float('nan')):.3f} | {d} | {sig} |"
        )
    lines += ["", f"Con n = {data['n_apps']} aplicaciones la potencia estadística es baja.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Figuras de la evaluación a escala")
    parser.add_argument("--file", help="scale_evaluation_*.json concreto (por defecto, el más reciente)")
    args = parser.parse_args()

    src = latest_evaluation(args.file)
    data = json.loads(src.read_text(encoding="utf-8"))
    if "p_one_tailed" not in data.get("statistical_tests", {}).get("hybrid_vs_sast", {}):
        raise SystemExit(f"{src.name} usa el formato antiguo de valores p. Regenera con run_scale_evaluation.py --save")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig_metricas_por_metodo(data, OUT_DIR / "fig_metricas_por_metodo.png")
    fig_f1_por_aplicacion(data, OUT_DIR / "fig_f1_por_aplicacion.png")
    fig_f1_pareado(data, OUT_DIR / "fig_f1_pareado_sast_hibrido.png")
    (OUT_DIR / "tablas_evaluacion.md").write_text(tablas_markdown(data, src.name), encoding="utf-8")
    print(f"Fuente: {src.name}")
    for f in sorted(OUT_DIR.iterdir()):
        print(f"  {f.relative_to(REPO)}")


if __name__ == "__main__":
    main()
