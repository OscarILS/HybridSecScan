"""
Visualización de Resultados Experimentales
==========================================

Genera gráficos y visualizaciones de los resultados experimentales
para incluir en la tesis.

Autor: Oscar Isaac Laguna Santa Cruz
Universidad: UNMSM - FISI
"""

import json
import sys
from pathlib import Path
from typing import Dict

# Intentar importar librerías de visualización
try:
    import matplotlib
    import matplotlib.pyplot as plt

    matplotlib.use("Agg")  # Backend sin interfaz gráfica
    import seaborn as sns

    PLOTTING_AVAILABLE = True

    # Configurar estilo
    sns.set_theme(style="whitegrid")
    plt.rcParams["figure.figsize"] = (12, 8)
    plt.rcParams["font.size"] = 10

except ImportError:
    PLOTTING_AVAILABLE = False
    print("⚠️ matplotlib/seaborn no disponibles.")
    print("   Instala con: pip install matplotlib seaborn")

try:
    import pandas as pd

    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

BASE_DIR = Path(__file__).parent.parent
RESULTS_DIR = BASE_DIR / "data" / "experiments" / "results"
PLOTS_DIR = BASE_DIR / "data" / "experiments" / "plots"


class ExperimentalPlotter:
    """Genera gráficos de resultados experimentales"""

    def __init__(self):
        self.results_data = None
        PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    def load_latest_results(self) -> Dict:
        """Carga el archivo de resultados más reciente"""

        if not RESULTS_DIR.exists():
            print(f"❌ Directorio de resultados no existe: {RESULTS_DIR}")
            return None

        result_files = list(RESULTS_DIR.glob("experimental_validation_*.json"))

        if not result_files:
            print("❌ No se encontraron archivos de resultados")
            return None

        latest_file = sorted(result_files, reverse=True)[0]
        print(f"📂 Cargando resultados desde: {latest_file.name}")

        with open(latest_file, "r", encoding="utf-8") as f:
            self.results_data = json.load(f)

        return self.results_data

    def plot_metrics_comparison(self):
        """Gráfico de barras comparando métricas"""

        if not PLOTTING_AVAILABLE:
            return

        print("📊 Generando gráfico de comparación de métricas...")

        aggregate = self.results_data.get("aggregate_metrics", {})

        metrics = ["Precisión", "Recall", "F1-Score"]

        data = {
            "SAST": [
                aggregate["sast"]["avg_precision"],
                aggregate["sast"]["avg_recall"],
                aggregate["sast"]["avg_f1_score"],
            ],
            "DAST": [
                aggregate["dast"]["avg_precision"],
                aggregate["dast"]["avg_recall"],
                aggregate["dast"]["avg_f1_score"],
            ],
            "HYBRID": [
                aggregate["hybrid"]["avg_precision"],
                aggregate["hybrid"]["avg_recall"],
                aggregate["hybrid"]["avg_f1_score"],
            ],
        }

        x = range(len(metrics))
        width = 0.25

        fig, ax = plt.subplots(figsize=(12, 7))

        bars1 = ax.bar([i - width for i in x], data["SAST"], width, label="SAST", color="#FF6B6B")
        bars2 = ax.bar(x, data["DAST"], width, label="DAST", color="#4ECDC4")
        bars3 = ax.bar([i + width for i in x], data["HYBRID"], width, label="HybridSecScan", color="#95E1D3")

        # Añadir valores sobre las barras
        def autolabel(bars):
            for bar in bars:
                height = bar.get_height()
                ax.annotate(
                    f"{height:.2%}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                )

        autolabel(bars1)
        autolabel(bars2)
        autolabel(bars3)

        ax.set_xlabel("Métrica", fontsize=12, fontweight="bold")
        ax.set_ylabel("Valor", fontsize=12, fontweight="bold")
        ax.set_title(
            "Comparación de Métricas de Detección de Vulnerabilidades\nHybridSecScan vs SAST vs DAST",
            fontsize=14,
            fontweight="bold",
            pad=20,
        )
        ax.set_xticks(x)
        ax.set_xticklabels(metrics)
        ax.legend(loc="upper left", fontsize=11)
        ax.set_ylim(0, 1.1)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.0%}"))
        ax.grid(axis="y", alpha=0.3)

        plt.tight_layout()
        output_file = PLOTS_DIR / "metrics_comparison.png"
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"✅ Gráfico guardado: {output_file}")

    def plot_false_positives_reduction(self):
        """Gráfico de reducción de falsos positivos"""

        if not PLOTTING_AVAILABLE:
            return

        print("📊 Generando gráfico de reducción de falsos positivos...")

        applications = []
        sast_fp = []
        hybrid_fp = []

        for result in self.results_data.get("results", []):
            if "error" in result or "false_positive_reduction" not in result:
                continue

            fp_data = result["false_positive_reduction"]
            applications.append(result["application"]["name"])
            sast_fp.append(fp_data["sast_fp"])
            hybrid_fp.append(fp_data["hybrid_fp"])

        if not applications:
            print("⚠️ No hay datos de falsos positivos")
            return

        x = range(len(applications))
        width = 0.35

        fig, ax = plt.subplots(figsize=(12, 7))

        bars1 = ax.bar([i - width / 2 for i in x], sast_fp, width, label="SAST", color="#FF6B6B", alpha=0.8)
        bars2 = ax.bar([i + width / 2 for i in x], hybrid_fp, width, label="HybridSecScan", color="#95E1D3", alpha=0.8)

        # Añadir valores sobre las barras
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax.annotate(
                    f"{int(height)}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontweight="bold",
                )

        # Calcular y mostrar porcentaje de reducción
        for i, (s, h) in enumerate(zip(sast_fp, hybrid_fp)):
            reduction = ((s - h) / s * 100) if s > 0 else 0
            ax.annotate(
                f"-{reduction:.0f}%",
                xy=(i, max(s, h) + 1),
                ha="center",
                va="bottom",
                fontsize=10,
                fontweight="bold",
                color="green",
            )

        ax.set_xlabel("Aplicación Vulnerable", fontsize=12, fontweight="bold")
        ax.set_ylabel("Número de Falsos Positivos", fontsize=12, fontweight="bold")
        ax.set_title(
            "Reducción de Falsos Positivos por Aplicación\nComparación SAST vs HybridSecScan",
            fontsize=14,
            fontweight="bold",
            pad=20,
        )
        ax.set_xticks(x)
        ax.set_xticklabels(applications, rotation=45, ha="right")
        ax.legend(loc="upper right", fontsize=11)
        ax.grid(axis="y", alpha=0.3)

        plt.tight_layout()
        output_file = PLOTS_DIR / "false_positives_reduction.png"
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"✅ Gráfico guardado: {output_file}")

    def plot_f1_score_comparison(self):
        """Gráfico de F1-Score por aplicación"""

        if not PLOTTING_AVAILABLE or not PANDAS_AVAILABLE:
            return

        print("📊 Generando gráfico de F1-Score por aplicación...")

        data_rows = []

        for result in self.results_data.get("results", []):
            if "error" in result:
                continue

            app_name = result["application"]["name"]
            metrics = result.get("metrics_comparison", {})

            if "sast" in metrics:
                data_rows.append({"App": app_name, "Method": "SAST", "F1-Score": metrics["sast"]["f1_score"]})
            if "dast" in metrics:
                data_rows.append({"App": app_name, "Method": "DAST", "F1-Score": metrics["dast"]["f1_score"]})
            if "hybrid" in metrics:
                data_rows.append({"App": app_name, "Method": "HYBRID", "F1-Score": metrics["hybrid"]["f1_score"]})

        if not data_rows:
            print("⚠️ No hay datos de F1-Score")
            return

        df = pd.DataFrame(data_rows)

        fig, ax = plt.subplots(figsize=(12, 7))

        # Gráfico de líneas con marcadores
        for method in ["SAST", "DAST", "HYBRID"]:
            method_data = df[df["Method"] == method]
            color = {"SAST": "#FF6B6B", "DAST": "#4ECDC4", "HYBRID": "#95E1D3"}[method]
            marker = {"SAST": "o", "DAST": "s", "HYBRID": "^"}[method]

            ax.plot(
                method_data["App"],
                method_data["F1-Score"],
                marker=marker,
                linewidth=2.5,
                markersize=10,
                label=method,
                color=color,
                alpha=0.8,
            )

        ax.set_xlabel("Aplicación Vulnerable", fontsize=12, fontweight="bold")
        ax.set_ylabel("F1-Score", fontsize=12, fontweight="bold")
        ax.set_title("F1-Score por Aplicación y Método de Análisis", fontsize=14, fontweight="bold", pad=20)
        ax.legend(loc="best", fontsize=11, framealpha=0.9)
        ax.set_ylim(0, 1.1)
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.1f}"))
        ax.grid(True, alpha=0.3)
        plt.xticks(rotation=45, ha="right")

        plt.tight_layout()
        output_file = PLOTS_DIR / "f1_score_by_application.png"
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"✅ Gráfico guardado: {output_file}")

    def plot_summary_dashboard(self):
        """Dashboard con múltiples métricas"""

        if not PLOTTING_AVAILABLE:
            return

        print("📊 Generando dashboard de resumen...")

        aggregate = self.results_data.get("aggregate_metrics", {})

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle("Dashboard de Validación Experimental - HybridSecScan", fontsize=16, fontweight="bold", y=0.995)

        # 1. Precisión comparativa
        methods = ["SAST", "DAST", "HYBRID"]
        precisions = [
            aggregate["sast"]["avg_precision"],
            aggregate["dast"]["avg_precision"],
            aggregate["hybrid"]["avg_precision"],
        ]
        colors = ["#FF6B6B", "#4ECDC4", "#95E1D3"]

        bars = ax1.bar(methods, precisions, color=colors, alpha=0.8)
        for bar in bars:
            height = bar.get_height()
            ax1.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{height:.1%}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        ax1.set_title("Precisión Promedio", fontsize=13, fontweight="bold")
        ax1.set_ylabel("Precisión", fontweight="bold")
        ax1.set_ylim(0, 1.1)
        ax1.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.0%}"))
        ax1.grid(axis="y", alpha=0.3)

        # 2. F1-Score comparativo
        f1_scores = [
            aggregate["sast"]["avg_f1_score"],
            aggregate["dast"]["avg_f1_score"],
            aggregate["hybrid"]["avg_f1_score"],
        ]

        bars = ax2.bar(methods, f1_scores, color=colors, alpha=0.8)
        for bar in bars:
            height = bar.get_height()
            ax2.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{height:.1%}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        ax2.set_title("F1-Score Promedio", fontsize=13, fontweight="bold")
        ax2.set_ylabel("F1-Score", fontweight="bold")
        ax2.set_ylim(0, 1.1)
        ax2.yaxis.set_major_formatter(plt.FuncFormatter(lambda y, _: f"{y:.0%}"))
        ax2.grid(axis="y", alpha=0.3)

        # 3. Falsos Positivos
        fp_values = [
            aggregate["sast"]["avg_false_positives"],
            aggregate["dast"]["avg_false_positives"],
            aggregate["hybrid"]["avg_false_positives"],
        ]

        bars = ax3.bar(methods, fp_values, color=colors, alpha=0.8)
        for bar in bars:
            height = bar.get_height()
            ax3.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{height:.1f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        ax3.set_title("Falsos Positivos Promedio", fontsize=13, fontweight="bold")
        ax3.set_ylabel("Número de FP", fontweight="bold")
        ax3.grid(axis="y", alpha=0.3)

        # 4. Reducción de FP (porcentaje)
        fp_reduction = aggregate.get("false_positive_reduction", {}).get("avg_percentage", 0)

        ax4.text(
            0.5, 0.5, f"{fp_reduction:.1f}%", ha="center", va="center", fontsize=60, fontweight="bold", color="#2ECC71"
        )
        ax4.text(
            0.5,
            0.25,
            "Reducción Promedio\nde Falsos Positivos",
            ha="center",
            va="center",
            fontsize=14,
            fontweight="bold",
        )
        ax4.set_xlim(0, 1)
        ax4.set_ylim(0, 1)
        ax4.axis("off")

        plt.tight_layout()
        output_file = PLOTS_DIR / "summary_dashboard.png"
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"✅ Dashboard guardado: {output_file}")

    def generate_all_plots(self):
        """Genera todos los gráficos"""

        print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     GENERACIÓN DE GRÁFICOS - Validación Experimental                ║
║     HybridSecScan                                                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """)

        if not PLOTTING_AVAILABLE:
            print("\n❌ matplotlib/seaborn no están instalados")
            print("   Instala con: pip install matplotlib seaborn pandas")
            return 1

        # Cargar datos
        if not self.load_latest_results():
            print("❌ No se pudieron cargar resultados")
            return 1

        # Generar gráficos
        try:
            self.plot_metrics_comparison()
            self.plot_false_positives_reduction()
            self.plot_f1_score_comparison()
            self.plot_summary_dashboard()

            print("\n" + "=" * 80)
            print("✅ TODOS LOS GRÁFICOS GENERADOS")
            print(f"📁 Ubicación: {PLOTS_DIR}")
            print("=" * 80 + "\n")

            # Listar archivos generados
            plot_files = list(PLOTS_DIR.glob("*.png"))
            print("Archivos generados:")
            for file in plot_files:
                print(f"  📊 {file.name}")

            return 0

        except Exception as e:
            print(f"\n❌ Error generando gráficos: {str(e)}")
            import traceback

            traceback.print_exc()
            return 1


def main():
    plotter = ExperimentalPlotter()
    return plotter.generate_all_plots()


if __name__ == "__main__":
    sys.exit(main())
