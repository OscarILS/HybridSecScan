"""
Análisis Estadístico de Resultados Experimentales
=================================================

Procesa y analiza los resultados de la validación experimental
generando estadísticas descriptivas y pruebas de significancia.

Autor: Oscar Isaac Laguna Santa Cruz
Universidad: UNMSM - FISI
"""

import json
import statistics
import sys
from pathlib import Path
from typing import Dict

# Intentar importar librerías científicas
try:
    import numpy as np
    import pandas as pd
    from scipy import stats

    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    print("⚠️ scipy/pandas no disponibles. Usando cálculos básicos.")

BASE_DIR = Path(__file__).parent.parent
RESULTS_DIR = BASE_DIR / "data" / "experiments" / "results"


class ExperimentalAnalyzer:
    """Analiza resultados experimentales con métodos estadísticos"""

    def __init__(self):
        self.results_data = None

    def load_latest_results(self) -> Dict:
        """Carga el archivo de resultados más reciente"""

        if not RESULTS_DIR.exists():
            print(f"❌ Directorio de resultados no existe: {RESULTS_DIR}")
            return None

        # Buscar archivos de resultados
        result_files = list(RESULTS_DIR.glob("experimental_validation_*.json"))

        if not result_files:
            print(f"❌ No se encontraron archivos de resultados en {RESULTS_DIR}")
            return None

        # Ordenar por fecha (más reciente primero)
        latest_file = sorted(result_files, reverse=True)[0]

        print(f"📂 Cargando resultados desde: {latest_file.name}")

        with open(latest_file, "r", encoding="utf-8") as f:
            self.results_data = json.load(f)

        return self.results_data

    def extract_metrics(self) -> pd.DataFrame:
        """Extrae métricas en formato tabular"""

        if not self.results_data:
            return None

        data_rows = []

        for result in self.results_data.get("results", []):
            if "error" in result:
                continue

            app_name = result["application"]["name"]
            metrics_comp = result.get("metrics_comparison", {})

            # SAST
            if "sast" in metrics_comp:
                data_rows.append(
                    {
                        "Application": app_name,
                        "Method": "SAST",
                        "Precision": metrics_comp["sast"]["precision"],
                        "Recall": metrics_comp["sast"]["recall"],
                        "F1-Score": metrics_comp["sast"]["f1_score"],
                        "False_Positives": metrics_comp["sast"]["false_positives"],
                    }
                )

            # DAST
            if "dast" in metrics_comp:
                data_rows.append(
                    {
                        "Application": app_name,
                        "Method": "DAST",
                        "Precision": metrics_comp["dast"]["precision"],
                        "Recall": metrics_comp["dast"]["recall"],
                        "F1-Score": metrics_comp["dast"]["f1_score"],
                        "False_Positives": metrics_comp["dast"]["false_positives"],
                    }
                )

            # Hybrid
            if "hybrid" in metrics_comp:
                data_rows.append(
                    {
                        "Application": app_name,
                        "Method": "HYBRID",
                        "Precision": metrics_comp["hybrid"]["precision"],
                        "Recall": metrics_comp["hybrid"]["recall"],
                        "F1-Score": metrics_comp["hybrid"]["f1_score"],
                        "False_Positives": metrics_comp["hybrid"]["false_positives"],
                    }
                )

        if SCIPY_AVAILABLE:
            return pd.DataFrame(data_rows)
        else:
            return data_rows

    def calculate_descriptive_statistics(self):
        """Calcula estadísticas descriptivas"""

        print("\n" + "=" * 80)
        print("📊 ESTADÍSTICAS DESCRIPTIVAS")
        print("=" * 80 + "\n")

        metrics_data = self.extract_metrics()

        if SCIPY_AVAILABLE and isinstance(metrics_data, pd.DataFrame):
            # Usar pandas para análisis
            for method in ["SAST", "DAST", "HYBRID"]:
                method_data = metrics_data[metrics_data["Method"] == method]

                if len(method_data) == 0:
                    continue

                print(f"\n🔍 {method}")
                print("-" * 60)

                for metric in ["Precision", "Recall", "F1-Score", "False_Positives"]:
                    values = method_data[metric].values

                    print(f"\n{metric}:")
                    print(f"  Media:       {np.mean(values):.4f}")
                    print(f"  Mediana:     {np.median(values):.4f}")
                    print(f"  Desv. Est.:  {np.std(values, ddof=1):.4f}")
                    print(f"  Mín:         {np.min(values):.4f}")
                    print(f"  Máx:         {np.max(values):.4f}")

                    if len(values) > 1:
                        # Intervalo de confianza 95%
                        ci = stats.t.interval(0.95, len(values) - 1, loc=np.mean(values), scale=stats.sem(values))
                        print(f"  IC 95%:      [{ci[0]:.4f}, {ci[1]:.4f}]")
        else:
            # Análisis básico sin pandas
            for method in ["SAST", "DAST", "HYBRID"]:
                method_data = [row for row in metrics_data if row["Method"] == method]

                if not method_data:
                    continue

                print(f"\n🔍 {method}")
                print("-" * 60)

                for metric in ["Precision", "Recall", "F1-Score", "False_Positives"]:
                    values = [row[metric] for row in method_data]

                    if values:
                        print(f"\n{metric}:")
                        print(f"  Media:       {statistics.mean(values):.4f}")
                        print(f"  Mediana:     {statistics.median(values):.4f}")
                        print(f"  Desv. Est.:  {statistics.stdev(values) if len(values) > 1 else 0:.4f}")
                        print(f"  Mín:         {min(values):.4f}")
                        print(f"  Máx:         {max(values):.4f}")

    def perform_hypothesis_testing(self):
        """Realiza pruebas de hipótesis estadísticas"""

        if not SCIPY_AVAILABLE:
            print("\n⚠️ scipy no disponible. Omitiendo pruebas de hipótesis.")
            return

        print("\n" + "=" * 80)
        print("🧪 PRUEBAS DE HIPÓTESIS")
        print("=" * 80 + "\n")

        metrics_data = self.extract_metrics()

        # H0: No hay diferencia significativa entre SAST y HYBRID
        # H1: HYBRID es significativamente mejor que SAST

        print("Hipótesis Nula (H0): μ_SAST = μ_HYBRID")
        print("Hipótesis Alternativa (H1): μ_HYBRID > μ_SAST")
        print("Nivel de significancia: α = 0.05\n")

        sast_data = metrics_data[metrics_data["Method"] == "SAST"]
        hybrid_data = metrics_data[metrics_data["Method"] == "HYBRID"]

        for metric in ["Precision", "Recall", "F1-Score"]:
            sast_values = sast_data[metric].values
            hybrid_values = hybrid_data[metric].values

            if len(sast_values) < 2 or len(hybrid_values) < 2:
                continue

            # Prueba t de Student para muestras pareadas
            t_stat, p_value = stats.ttest_rel(hybrid_values, sast_values)

            # Cohen's d (tamaño del efecto)
            pooled_std = np.sqrt((np.std(sast_values, ddof=1) ** 2 + np.std(hybrid_values, ddof=1) ** 2) / 2)
            cohens_d = (np.mean(hybrid_values) - np.mean(sast_values)) / pooled_std if pooled_std > 0 else 0

            print(f"\n📈 {metric}")
            print("-" * 60)
            print(f"  SAST (μ₁):    {np.mean(sast_values):.4f} ± {np.std(sast_values, ddof=1):.4f}")
            print(f"  HYBRID (μ₂):  {np.mean(hybrid_values):.4f} ± {np.std(hybrid_values, ddof=1):.4f}")
            print(f"  Diferencia:   {np.mean(hybrid_values) - np.mean(sast_values):.4f}")
            print(f"  t-statistic:  {t_stat:.4f}")
            print(f"  p-value:      {p_value:.4f}")
            print(f"  Cohen's d:    {cohens_d:.4f}")

            # Interpretación
            if p_value < 0.05:
                print("  ✅ Resultado: RECHAZAMOS H0 (p < 0.05)")
                print(f"     → HYBRID es significativamente mejor que SAST en {metric}")
            else:
                print("  ❌ Resultado: NO RECHAZAMOS H0 (p ≥ 0.05)")
                print("     → No hay evidencia suficiente de diferencia significativa")

            # Tamaño del efecto
            if abs(cohens_d) < 0.2:
                effect = "PEQUEÑO"
            elif abs(cohens_d) < 0.5:
                effect = "MEDIANO"
            elif abs(cohens_d) < 0.8:
                effect = "GRANDE"
            else:
                effect = "MUY GRANDE"

            print(f"  Tamaño del efecto: {effect}")

    def analyze_false_positive_reduction(self):
        """Analiza la reducción de falsos positivos"""

        print("\n" + "=" * 80)
        print("🎯 ANÁLISIS DE REDUCCIÓN DE FALSOS POSITIVOS")
        print("=" * 80 + "\n")

        reductions = []

        for result in self.results_data.get("results", []):
            if "error" in result or "false_positive_reduction" not in result:
                continue

            fp_reduction = result["false_positive_reduction"]
            app_name = result["application"]["name"]

            print(f"\n📦 {app_name}")
            print(f"  SAST FP:      {fp_reduction['sast_fp']}")
            print(f"  Hybrid FP:    {fp_reduction['hybrid_fp']}")
            print(f"  Reducción:    {fp_reduction['absolute']} ({fp_reduction['percentage']:.1f}%)")

            reductions.append(fp_reduction["percentage"])

        if reductions:
            print("\n📊 RESUMEN AGREGADO")
            print("-" * 60)
            print(f"  Reducción promedio:  {statistics.mean(reductions):.2f}%")
            print(f"  Reducción mediana:   {statistics.median(reductions):.2f}%")
            print(f"  Reducción mínima:    {min(reductions):.2f}%")
            print(f"  Reducción máxima:    {max(reductions):.2f}%")

            if len(reductions) > 1:
                print(f"  Desviación estándar: {statistics.stdev(reductions):.2f}%")

    def generate_latex_table(self):
        """Genera tabla en formato LaTeX para tesis"""

        print("\n" + "=" * 80)
        print("📄 TABLA LATEX PARA TESIS")
        print("=" * 80 + "\n")

        metrics_data = self.extract_metrics()

        if not SCIPY_AVAILABLE:
            print("⚠️ pandas no disponible. No se puede generar tabla LaTeX.")
            return

        # Tabla de métricas por método
        latex_table = """
\\begin{table}[htbp]
\\centering
\\caption{Comparación de métricas entre métodos de análisis}
\\label{tab:metrics_comparison}
\\begin{tabular}{lcccc}
\\toprule
\\textbf{Método} & \\textbf{Precisión} & \\textbf{Recall} & \\textbf{F1-Score} & \\textbf{FP Promedio} \\\\
\\midrule
"""

        for method in ["SAST", "DAST", "HYBRID"]:
            method_data = metrics_data[metrics_data["Method"] == method]

            if len(method_data) == 0:
                continue

            precision = f"{method_data['Precision'].mean():.3f}"
            recall = f"{method_data['Recall'].mean():.3f}"
            f1 = f"{method_data['F1-Score'].mean():.3f}"
            fp = f"{method_data['False_Positives'].mean():.1f}"

            latex_table += f"{method} & {precision} & {recall} & {f1} & {fp} \\\\\n"

        latex_table += """\\bottomrule
\\end{tabular}
\\end{table}
"""

        print(latex_table)

        # Guardar en archivo
        output_file = RESULTS_DIR / "metrics_table.tex"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(latex_table)

        print(f"\n✅ Tabla guardada en: {output_file}")

    def run_full_analysis(self):
        """Ejecuta análisis completo"""

        print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     ANÁLISIS ESTADÍSTICO - Validación Experimental                  ║
║     HybridSecScan                                                    ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
        """)

        # Cargar datos
        if not self.load_latest_results():
            print("❌ No se pudieron cargar resultados")
            return 1

        # Análisis
        try:
            self.calculate_descriptive_statistics()
            self.perform_hypothesis_testing()
            self.analyze_false_positive_reduction()
            self.generate_latex_table()

            print("\n" + "=" * 80)
            print("✅ ANÁLISIS COMPLETADO")
            print("=" * 80 + "\n")

            return 0

        except Exception as e:
            print(f"\n❌ Error en análisis: {str(e)}")
            import traceback

            traceback.print_exc()
            return 1


def main():
    analyzer = ExperimentalAnalyzer()
    return analyzer.run_full_analysis()


if __name__ == "__main__":
    sys.exit(main())
