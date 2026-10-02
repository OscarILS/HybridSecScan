"""Genera thesis/tablas/anexo_gt_escala.tex desde los *_ground_truth.json de la evaluación a escala.

Solo usa los campos de los JSON (application, id, type, cwe_id, owasp_category, file_path, endpoint).

Regenerar:  python thesis/tablas/anexo_gt_escala.py
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GT_DIR = ROOT / "data" / "experiments" / "ground_truth"
OUT = Path(__file__).with_suffix(".tex")
APPS = ["juiceshop", "dvwa", "nodegoat", "webgoat"]
BR = r"\allowbreak{}"


def esc(s):
    s = str(s).replace("\\", r"\textbackslash{}")
    for ch in "&%#$_{}":
        s = s.replace(ch, "\\" + ch)
    return s


def breakable(s):
    """Texto escapado con puntos de corte después de '_' (para nombres de tipo largos)."""
    return esc(s).replace(r"\_", r"\_" + BR)


def path_tt(s):
    """Ruta en monoespaciado con puntos de corte después de cada '/'."""
    return r"\texttt{" + esc(s).replace("/", "/" + BR) + "}"


rows = []
for app in APPS:
    data = json.loads((GT_DIR / f"{app}_ground_truth.json").read_text(encoding="utf-8"))
    for i, v in enumerate(data["vulnerabilities"]):
        name = esc(data["application"]) if i == 0 else ""
        loc = path_tt(v["file_path"]) + r" \newline " + path_tt(v["endpoint"])
        cells = [name, esc(v["id"]), breakable(v["type"]), esc(v["cwe_id"]), esc(v["owasp_category"]), loc]
        rows.append(" & ".join(cells) + r" \\")
    rows.append(r"\hline")

header = r"\textbf{Aplicación} & \textbf{ID} & \textbf{Tipo} & \textbf{CWE} & \textbf{Categoría OWASP 2023} & \textbf{Archivo / endpoint} \\"
lines = [
    r"\begin{table}[htbp]",
    r"\centering",
    r"\caption{Vulnerabilidades de referencia de la evaluación a escala}",
    r"\label{tab:anexo_gt_escala}",
    r"\small",
    r"\begin{tabular}{|p{1.7cm}|p{1.4cm}|p{2.6cm}|p{1.3cm}|p{1.5cm}|p{4.6cm}|}",
    r"\hline",
    header,
    r"\hline",
    *rows,
    r"\end{tabular}",
    r"\end{table}",
    r"\begin{flushleft}\textit{Nota}. Fuente: archivos *\_ground\_truth.json.\end{flushleft}",
]
OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(OUT)
