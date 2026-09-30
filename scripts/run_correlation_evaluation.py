"""
Evaluación del motor de correlación contra ground truth (caso de estudio: app vulnerable).

A diferencia de run_scale_evaluation.py (que mide la UNIÓN de hallazgos SAST+DAST),
este script mide el propio motor de correlación: compara contra el ground truth de
ProgramasPruebas/vulnerable_app.py los hallazgos de cada método y los pares que el
correlador confirma.

Métodos evaluados:
  - SAST (Bandit), DAST (escáner activo), Unión SAST+DAST
  - Correlación: solo los pares SAST↔DAST que el motor confirma (umbral 0.70)

Criterios de acierto (ver matching_rules en el ground truth):
  - SAST: línea dentro de la vulnerabilidad y CWE aceptado
  - DAST: endpoint coincidente (o falla global) y CWE aceptado
  - Correlación: ambos lados aciertan la MISMA vulnerabilidad

Precisión = hallazgos correctos / hallazgos. Recall = vulnerabilidades encontradas / total.

Uso (tras python scripts/run_vulnerable_app_experiment.py):
    python scripts/run_correlation_evaluation.py
    python scripts/run_correlation_evaluation.py --save
"""

import argparse
import io
import json
import re
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
RES_DIR = REPO / "data" / "experiments" / "results"
GT_FILE = REPO / "data" / "experiments" / "ground_truth" / "vulnerable_app_ground_truth.json"
OUT_DIR = REPO / "data" / "experiments"
FIG_DIR = OUT_DIR / "figures"
THRESHOLD = 0.70

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))


def _cwe_int(raw) -> Optional[int]:
    """'CWE-89', 89 o {'id': 89} → 89."""
    if isinstance(raw, dict):
        raw = raw.get("id")
    if raw is None:
        return None
    m = re.search(r"\d+", str(raw))
    return int(m.group()) if m else None


def _endpoint(url: str) -> str:
    return urlparse(url or "").path or "/"


def sast_matches(finding: dict, gt: List[dict]) -> Set[str]:
    """IDs de vulnerabilidades del ground truth que acierta un hallazgo de Bandit."""
    line, cwe = finding.get("line_number"), _cwe_int(finding.get("issue_cwe"))
    return {v["id"] for v in gt if v["lines"][0] <= line <= v["lines"][1] and cwe in v["accepted_cwes"]}


def dast_matches(finding: dict, gt: List[dict]) -> Set[str]:
    """IDs de vulnerabilidades del ground truth que acierta un hallazgo DAST."""
    ep, cwe = _endpoint(finding.get("url")), _cwe_int(finding.get("cwe"))
    return {
        v["id"] for v in gt if v["endpoint"] is not None and v["endpoint"] in ("*", ep) and cwe in v["accepted_cwes"]
    }


def metrics(hits_per_finding: List[Set[str]], n_gt: int) -> Dict:
    """Precisión por hallazgo y recall por vulnerabilidad."""
    n = len(hits_per_finding)
    tp = sum(1 for h in hits_per_finding if h)
    found = set().union(*hits_per_finding) if hits_per_finding else set()
    precision = tp / n if n else 0.0
    recall = len(found) / n_gt if n_gt else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "findings": n,
        "correct_findings": tp,
        "incorrect_findings": n - tp,
        "vulnerabilities_found": sorted(found),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def latest(pattern: str) -> Path:
    files = sorted(RES_DIR.glob(pattern))
    if not files:
        raise SystemExit(f"No hay {pattern} en {RES_DIR}. Ejecuta: python scripts/run_vulnerable_app_experiment.py")
    return files[-1]


def evaluate(sast_file: Path, dast_file: Path) -> Dict:
    gt = json.loads(GT_FILE.read_text(encoding="utf-8"))["vulnerabilities"]
    sast_raw = json.loads(sast_file.read_text(encoding="utf-8"))["results"]
    dast_raw = json.loads(dast_file.read_text(encoding="utf-8"))["vulnerabilities"]

    sast_hits = [sast_matches(f, gt) for f in sast_raw]
    dast_hits = [dast_matches(f, gt) for f in dast_raw]

    # Correlador: mismo mapeo y mismo motor que el experimento
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        import run_vulnerable_app_experiment as va

        from backend.correlation_engine import VulnerabilityCorrelator

        sast_v = [va.map_bandit_finding(f, str(va.APP_PATH)) for f in sast_raw]
        dast_v = [va.map_dast_finding(f) for f in dast_raw]
        correlator = VulnerabilityCorrelator()
        correlator.add_sast_findings(sast_v)
        correlator.add_dast_findings(dast_v)
        pairs = correlator.correlate_vulnerabilities(threshold=THRESHOLD)
    s_index = {id(v): i for i, v in enumerate(sast_v)}
    d_index = {id(v): i for i, v in enumerate(dast_v)}

    corr_hits, corr_detail = [], []
    for s, d, conf in pairs:
        si, di = s_index[id(s)], d_index[id(d)]
        common = sast_hits[si] & dast_hits[di]
        corr_hits.append(common)
        corr_detail.append(
            {
                "confidence": round(conf, 4),
                "sast": f"{sast_raw[si]['test_id']} línea {sast_raw[si]['line_number']}",
                "dast": f"{dast_raw[di].get('type')} @ {_endpoint(dast_raw[di].get('url'))}",
                "ground_truth": sorted(common) or None,
            }
        )

    n_gt = len(gt)
    both = set().union(*sast_hits) & set().union(*dast_hits)
    return {
        "application": "ProgramasPruebas/vulnerable_app.py",
        "ground_truth_file": GT_FILE.name,
        "ground_truth_n": n_gt,
        "sast_file": sast_file.name,
        "dast_file": dast_file.name,
        "threshold": THRESHOLD,
        "methods": {
            "sast": metrics(sast_hits, n_gt),
            "dast": metrics(dast_hits, n_gt),
            "union": metrics(sast_hits + dast_hits, n_gt),
            "correlation": metrics(corr_hits, n_gt),
        },
        # Vulnerabilidades que ambas técnicas detectaron: las únicas que el correlador puede confirmar
        "detected_by_both": sorted(both),
        "confirmed_by_correlation": sorted(set().union(*corr_hits)) if corr_hits else [],
        "correlations": corr_detail,
    }


def markdown(res: Dict) -> str:
    names = {
        "sast": "SAST (Bandit)",
        "dast": "DAST (escáner activo)",
        "union": "Unión SAST+DAST",
        "correlation": "Correlación (pares confirmados)",
    }
    out = [
        "# Evaluación del motor de correlación (caso de estudio)",
        "",
        f"Aplicación: `{res['application']}` — ground truth de {res['ground_truth_n']} vulnerabilidades "
        f"(`{res['ground_truth_file']}`). Hallazgos: `{res['sast_file']}`, `{res['dast_file']}`. "
        f"Umbral de correlación: {res['threshold']}.",
        "",
        "| Método | Hallazgos | Correctos | Incorrectos | Vulnerabilidades encontradas | Precisión | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for key, label in names.items():
        m = res["methods"][key]
        out.append(
            f"| {label} | {m['findings']} | {m['correct_findings']} | {m['incorrect_findings']} | "
            f"{len(m['vulnerabilities_found'])} de {res['ground_truth_n']} | "
            f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |"
        )
    both, conf = res["detected_by_both"], res["confirmed_by_correlation"]
    out += [
        "",
        f"Vulnerabilidades detectadas por ambas técnicas (las únicas que el correlador puede confirmar): "
        f"{len(both)} ({', '.join(both) or '—'}). Confirmadas por el correlador: {len(conf)} ({', '.join(conf) or '—'}).",
        "",
        "## Correlaciones",
        "",
        "| Confianza | SAST | DAST | Vulnerabilidad del ground truth |",
        "|---|---|---|---|",
    ]
    for c in res["correlations"]:
        out.append(
            f"| {c['confidence']:.3f} | {c['sast']} | {c['dast']} | {', '.join(c['ground_truth'] or ['ninguna'])} |"
        )
    out += [
        "",
        "Precisión = hallazgos correctos / hallazgos; recall = vulnerabilidades encontradas / total. "
        "Caso de estudio con una sola aplicación: los resultados ilustran el comportamiento del correlador, "
        "no permiten generalizar.",
        "",
    ]
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Evalúa el motor de correlación contra ground truth")
    parser.add_argument("--save", action="store_true", help="Guarda JSON y tabla Markdown")
    args = parser.parse_args()

    res = evaluate(latest("sast_bandit_vulnerable_*.json"), latest("dast_active_vulnerable_*.json"))
    print(markdown(res))
    if args.save:
        out = OUT_DIR / f"correlation_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        FIG_DIR.mkdir(parents=True, exist_ok=True)
        (FIG_DIR / "tabla_evaluacion_correlacion.md").write_text(markdown(res), encoding="utf-8")
        print(f"Guardado: {out.relative_to(REPO)} y {(FIG_DIR / 'tabla_evaluacion_correlacion.md').relative_to(REPO)}")


if __name__ == "__main__":
    main()
