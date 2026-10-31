"""
Evaluación del clasificador Random Forest ya entrenado sobre pares REALES de
hallazgos SAST–DAST etiquetados con el ground truth.

Responde a una observación del jurado: el modelo se evaluó con datos sintéticos
(metadata.json) y en un holdout sintético independiente (holdout_evaluation_*),
pero no sobre pares reales. Este script mide exactamente eso, sin reentrenar ni
modificar nada.

NO reimplementa la lógica de coincidencia hallazgo↔vulnerabilidad: reutiliza las
funciones del script que generó los archivos correlation_evaluation_*_20261001
(scripts/run_correlation_evaluation.py: sast_matches, dast_matches, el mapeo a
objetos Vulnerability y, para VAmPI, la resolución de endpoint por OpenAPI).

La probabilidad del Random Forest se calcula con EXACTAMENTE el mismo camino de
inferencia que backend/correlation_engine.py: _engineer_features_for_prediction
(mismas features, mismo feature_utils.py, mismo vectorizador TF-IDF y mismos
LabelEncoders cargados del .pkl) y ml_classifier.predict_proba.

Uso:
    py -3.11 scripts/evaluate_real_pairs.py
"""

import json
import platform
import statistics
import sys
from datetime import datetime
from pathlib import Path

import sklearn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "backend"))

# Reutilización EXACTA de la lógica existente (no se reimplementa nada):
import run_correlation_evaluation as rce  # noqa: E402  sast_matches, dast_matches, mapeo
import run_vulnerable_app_experiment as va  # noqa: E402  map_bandit_finding, map_dast_finding, APP_PATH

from backend.correlation_engine import VulnerabilityCorrelator  # noqa: E402
from backend.feature_utils import module_match  # noqa: E402  misma feature que el entrenamiento

OUT_DIR = REPO / "data" / "experiments"

# Archivos de la Tarea 3 de los que se toman sast_file / dast_file / ground_truth_file.
EVAL_JSON = {
    "vulnerable_app": OUT_DIR / "correlation_evaluation_vulnerable_app_20261001_142307.json",
    "vampi": OUT_DIR / "correlation_evaluation_vampi_20261001_142307.json",
}
# Dimensiones esperadas (SAST × DAST) según el enunciado; si no coinciden, se reporta.
EXPECTED_DIMS = {"vulnerable_app": (12, 12), "vampi": (7, 11)}

# Control de consistencia obligatorio (probabilidad RF del par representativo de
# cada vulnerabilidad detectada por ambas técnicas, según los archivos 20261001).
CONSISTENCY = {
    "vulnerable_app": {"VA_002": 0.472, "VA_009": 0.25},
}
CONSISTENCY_TOL = 0.01

# Holdout sintético independiente (para comparar la tasa de falsos positivos).
HOLDOUT_FILE = OUT_DIR / "holdout_evaluation_20261001_223335.json"

THRESHOLD = 0.5  # umbral de decisión de metadata.json (por defecto de scikit-learn)


# ── Construcción de hallazgos y etiquetas (reutilizando rce/va) ────────────────


def build_app(app_key: str) -> dict:
    """Carga los hallazgos EXACTOS de la Tarea 3 y reconstruye objetos Vulnerability,
    hits ground-truth y el correlador, usando la lógica de run_correlation_evaluation."""
    meta = json.loads(EVAL_JSON[app_key].read_text(encoding="utf-8"))
    cfg = rce.APPS[app_key]

    gt_file = rce.GT_DIR / meta["ground_truth_file"]
    sast_file = rce.RES_DIR / meta["sast_file"]
    dast_file = rce.RES_DIR / meta["dast_file"]

    gt = json.loads(gt_file.read_text(encoding="utf-8"))["vulnerabilities"]
    sast_raw = json.loads(sast_file.read_text(encoding="utf-8"))["results"]
    dast_raw = json.loads(dast_file.read_text(encoding="utf-8"))["vulnerabilities"]

    # Coincidencia hallazgo↔vulnerabilidad: funciones del script generador, sin cambios.
    sast_hits = [rce.sast_matches(f, gt) for f in sast_raw]
    dast_hits = [rce.dast_matches(f, gt) for f in dast_raw]

    # Mapeo a objetos Vulnerability: idéntico al de rce.evaluate().
    if cfg["routes"] == "flask":
        sast_v = [va.map_bandit_finding(f, str(va.APP_PATH)) for f in sast_raw]
    else:
        routes = rce.openapi_routes(cfg["source_root"] / cfg["openapi"])
        sast_v = []
        for f in sast_raw:
            v = va.map_bandit_finding(f, f.get("filename", ""))
            v.endpoint = rce.sast_endpoint_openapi(f, cfg["source_root"], routes)
            sast_v.append(v)
    dast_v = [va.map_dast_finding(f) for f in dast_raw]

    return {
        "meta": meta,
        "gt": gt,
        "sast_raw": sast_raw,
        "dast_raw": dast_raw,
        "sast_hits": sast_hits,
        "dast_hits": dast_hits,
        "sast_v": sast_v,
        "dast_v": dast_v,
        "gt_file": gt_file.name,
        "sast_file": sast_file.name,
        "dast_file": dast_file.name,
    }


def rf_probability(correlator: VulnerabilityCorrelator, sast_vuln, dast_vuln) -> float:
    """Probabilidad del Random Forest para un par, por el MISMO camino que correlation_engine.py."""
    fv = correlator._engineer_features_for_prediction(sast_vuln, dast_vuln)
    expected = correlator.model_metrics.get("n_features", 517)
    if len(fv) != expected:
        raise ValueError(f"Feature dimension mismatch: {len(fv)} vs {expected}")
    return float(correlator.ml_classifier.predict_proba(fv.reshape(1, -1))[0][1])


# ── Evaluación de pares por aplicación ─────────────────────────────────────────


def evaluate_app(app_key: str, correlator: VulnerabilityCorrelator) -> dict:
    data = build_app(app_key)
    sast_v, dast_v = data["sast_v"], data["dast_v"]
    sast_hits, dast_hits = data["sast_hits"], data["dast_hits"]
    sast_raw, dast_raw = data["sast_raw"], data["dast_raw"]

    n_sast, n_dast = len(sast_v), len(dast_v)
    dims_ok = (n_sast, n_dast) == EXPECTED_DIMS[app_key]

    # Ambigüedades: hallazgos que coinciden con más de una vulnerabilidad.
    ambiguous_sast = [
        {"index": i, "finding": f"{sast_raw[i].get('test_id')} "
         f"{Path(rce._norm_path(sast_raw[i].get('filename', ''))).name}:{sast_raw[i].get('line_number')}",
         "matches": sorted(sast_hits[i])}
        for i in range(n_sast) if len(sast_hits[i]) > 1
    ]
    ambiguous_dast = [
        {"index": j, "finding": f"{dast_raw[j].get('type')} @ {rce._endpoint(dast_raw[j].get('url'))}",
         "matches": sorted(dast_hits[j])}
        for j in range(n_dast) if len(dast_hits[j]) > 1
    ]

    pairs = []
    ambiguous_pairs = []
    for i in range(n_sast):
        for j in range(n_dast):
            common = sorted(sast_hits[i] & dast_hits[j])
            label = 1 if common else 0
            proba = rf_probability(correlator, sast_v[i], dast_v[j])
            mm = module_match(sast_v[i].file_path, dast_v[j].endpoint)
            rec = {
                "sast_index": i,
                "dast_index": j,
                "sast": f"{sast_raw[i].get('test_id')} "
                f"{Path(rce._norm_path(sast_raw[i].get('filename', ''))).name}:{sast_raw[i].get('line_number')}"
                f" → {sast_v[i].endpoint}",
                "dast": f"{dast_raw[j].get('type')} @ {rce._endpoint(dast_raw[j].get('url'))}",
                "label": label,
                "ground_truth": common or None,
                "rf_probability": round(proba, 6),
                "predicted_positive": proba >= THRESHOLD,
                "module_match": mm,
            }
            pairs.append(rec)
            if len(common) > 1:
                ambiguous_pairs.append({"sast": rec["sast"], "dast": rec["dast"], "matches": common})

    positives = [p for p in pairs if p["label"] == 1]
    negatives = [p for p in pairs if p["label"] == 0]

    # Matriz de confusión al umbral 0.5 (predicho positivo si proba >= 0.5).
    tp = sum(1 for p in positives if p["predicted_positive"])
    fn = sum(1 for p in positives if not p["predicted_positive"])
    fp = sum(1 for p in negatives if p["predicted_positive"])
    tn = sum(1 for p in negatives if not p["predicted_positive"])

    def summary(probs):
        if not probs:
            return {"n": 0, "min": None, "median": None, "mean": None, "max": None}
        return {
            "n": len(probs),
            "min": round(min(probs), 6),
            "median": round(statistics.median(probs), 6),
            "mean": round(statistics.mean(probs), 6),
            "max": round(max(probs), 6),
        }

    pos_probs = [p["rf_probability"] for p in positives]
    neg_probs = [p["rf_probability"] for p in negatives]

    def mm_dist(group):
        return {"module_match=1": sum(1 for p in group if p["module_match"] == 1),
                "module_match=0": sum(1 for p in group if p["module_match"] == 0)}

    fpr = fp / len(negatives) if negatives else None
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall) else None

    return {
        "app_key": app_key,
        "application": data["meta"]["application"],
        "sources": {"ground_truth_file": data["gt_file"], "sast_file": data["sast_file"],
                    "dast_file": data["dast_file"]},
        "n_sast_findings": n_sast,
        "n_dast_findings": n_dast,
        "expected_dims": {"sast": EXPECTED_DIMS[app_key][0], "dast": EXPECTED_DIMS[app_key][1]},
        "dims_match_expected": dims_ok,
        "n_pairs": len(pairs),
        "n_positives": len(positives),
        "n_negatives": len(negatives),
        "confusion_matrix_threshold_0.5": {"TN": tn, "FP": fp, "FN": fn, "TP": tp},
        "false_positive_rate_on_negatives": None if fpr is None else round(fpr, 6),
        "positive_pairs": [
            {"ground_truth": p["ground_truth"], "sast": p["sast"], "dast": p["dast"],
             "rf_probability": p["rf_probability"], "predicted_positive": p["predicted_positive"],
             "module_match": p["module_match"]}
            for p in sorted(positives, key=lambda p: p["rf_probability"], reverse=True)
        ],
        "probability_summary": {"positives": summary(pos_probs), "negatives": summary(neg_probs)},
        "module_match_distribution": {"positives": mm_dist(positives), "negatives": mm_dist(negatives)},
        "complementary_metrics": {
            "note": f"n_positives={len(positives)}; con tan pocos positivos estas métricas son inestables.",
            "precision": None if precision is None else round(precision, 6),
            "recall": None if recall is None else round(recall, 6),
            "f1": None if f1 is None else round(f1, 6),
        },
        "ambiguities": {
            "sast_findings_matching_multiple_vulns": ambiguous_sast,
            "dast_findings_matching_multiple_vulns": ambiguous_dast,
            "pairs_matching_multiple_vulns": ambiguous_pairs,
        },
        "_internal": {"data": data, "pairs": pairs},
    }


def consistency_check(app_key: str, result: dict, correlator: VulnerabilityCorrelator) -> list:
    """Reproduce el par representativo (máxima confianza) de cada vulnerabilidad del
    control y verifica su probabilidad RF, igual que run_correlation_evaluation."""
    checks = []
    data = result["_internal"]["data"]
    sast_v, dast_v = data["sast_v"], data["dast_v"]
    sast_hits, dast_hits = data["sast_hits"], data["dast_hits"]
    for vid, expected in CONSISTENCY.get(app_key, {}).items():
        candidates = [
            (i, j) for i in range(len(sast_v)) if vid in sast_hits[i]
            for j in range(len(dast_v)) if vid in dast_hits[j]
        ]
        if not candidates:
            checks.append({"id": vid, "status": "NO_CANDIDATES", "expected_rf": expected})
            continue
        # Par representativo = el de mayor confianza total (mismo criterio que rce.both_pairs).
        best = max(candidates, key=lambda c: correlator.confidence_breakdown(sast_v[c[0]], dast_v[c[1]])["confidence"])
        bd = correlator.confidence_breakdown(sast_v[best[0]], dast_v[best[1]])
        rf = rf_probability(correlator, sast_v[best[0]], dast_v[best[1]])
        checks.append({
            "id": vid,
            "expected_rf": expected,
            "observed_rf": round(rf, 6),
            "ml_factor_value": bd["factors"]["ml"]["value"],
            "total_confidence": round(bd["confidence"], 6),
            "n_candidate_pairs": len(candidates),
            "passed": abs(rf - expected) <= CONSISTENCY_TOL,
        })
    return checks


# ── Salida Markdown ────────────────────────────────────────────────────────────


def md_app(res: dict) -> list:
    cm = res["confusion_matrix_threshold_0.5"]
    cpl = res["complementary_metrics"]
    out = [
        f"## {res['application']}",
        "",
        f"Fuentes: ground truth `{res['sources']['ground_truth_file']}`, "
        f"SAST `{res['sources']['sast_file']}`, DAST `{res['sources']['dast_file']}`.",
        "",
        f"- Hallazgos: SAST = {res['n_sast_findings']}, DAST = {res['n_dast_findings']} "
        f"(esperado {res['expected_dims']['sast']} × {res['expected_dims']['dast']}; "
        f"{'coincide' if res['dims_match_expected'] else '**NO coincide**'}).",
        f"- Pares (SAST × DAST): **{res['n_pairs']}** — positivos: **{res['n_positives']}**, "
        f"negativos: **{res['n_negatives']}**.",
        "",
        "### 2. Matriz de confusión (umbral 0.5)",
        "",
        "| | Pred. negativo | Pred. positivo |",
        "|---|---|---|",
        f"| **Real negativo** | VN = {cm['TN']} | FP = {cm['FP']} |",
        f"| **Real positivo** | FN = {cm['FN']} | VP = {cm['TP']} |",
        "",
        "### 3. Tasa de falsos positivos sobre los negativos",
        "",
    ]
    fpr = res["false_positive_rate_on_negatives"]
    out += [
        f"- Pares reales: FP / negativos = {cm['FP']} / {res['n_negatives']} = "
        f"{'—' if fpr is None else f'{fpr:.4f}'}.",
        "",
        "### 4. Probabilidad RF de cada par positivo",
        "",
    ]
    if res["positive_pairs"]:
        out += ["| Ground truth | Prob. RF | Pred. (≥0.5) | module_match | SAST | DAST |",
                "|---|---|---|---|---|---|"]
        for p in res["positive_pairs"]:
            out.append(
                f"| {', '.join(p['ground_truth'])} | {p['rf_probability']:.4f} | "
                f"{'sí' if p['predicted_positive'] else 'no'} | {p['module_match']} | {p['sast']} | {p['dast']} |"
            )
    else:
        out.append("_No hay pares positivos (ninguna vulnerabilidad fue detectada por ambas técnicas)._")

    ps = res["probability_summary"]
    out += [
        "",
        "### 5. Resumen de probabilidades RF",
        "",
        "| Grupo | n | Mín | Mediana | Media | Máx |",
        "|---|---|---|---|---|---|",
        _summ_row("Positivos", ps["positives"]),
        _summ_row("Negativos", ps["negatives"]),
        "",
        "### 6. Distribución de module_match",
        "",
        "| Grupo | module_match = 1 | module_match = 0 |",
        "|---|---|---|",
        f"| Positivos | {res['module_match_distribution']['positives']['module_match=1']} | "
        f"{res['module_match_distribution']['positives']['module_match=0']} |",
        f"| Negativos | {res['module_match_distribution']['negatives']['module_match=1']} | "
        f"{res['module_match_distribution']['negatives']['module_match=0']} |",
        "",
        "### Métricas complementarias (inestables con pocos positivos)",
        "",
        f"- n_positivos = {res['n_positives']}. "
        f"Precisión = {_fmt(cpl['precision'])}, Recall = {_fmt(cpl['recall'])}, F1 = {_fmt(cpl['f1'])}.",
        "",
    ]
    amb = res["ambiguities"]
    n_amb = (len(amb["sast_findings_matching_multiple_vulns"])
             + len(amb["dast_findings_matching_multiple_vulns"]) + len(amb["pairs_matching_multiple_vulns"]))
    out.append(f"### Ambigüedades registradas: {n_amb}")
    out.append("")
    if n_amb == 0:
        out.append("Ninguna: ningún hallazgo ni par coincide con más de una vulnerabilidad del ground truth.")
    else:
        for a in amb["sast_findings_matching_multiple_vulns"]:
            out.append(f"- SAST `{a['finding']}` coincide con {a['matches']}.")
        for a in amb["dast_findings_matching_multiple_vulns"]:
            out.append(f"- DAST `{a['finding']}` coincide con {a['matches']}.")
        for a in amb["pairs_matching_multiple_vulns"]:
            out.append(f"- Par SAST `{a['sast']}` × DAST `{a['dast']}` coincide con {a['matches']}.")
    out.append("")
    return out


def _summ_row(label, s):
    if s["n"] == 0:
        return f"| {label} | 0 | — | — | — | — |"
    return f"| {label} | {s['n']} | {s['min']:.4f} | {s['median']:.4f} | {s['mean']:.4f} | {s['max']:.4f} |"


def _fmt(x):
    return "—" if x is None else f"{x:.4f}"


def build_markdown(payload: dict) -> str:
    env = payload["environment"]
    out = [
        "# Evaluación del Random Forest sobre pares reales SAST–DAST",
        "",
        f"Generado: {payload['generated_at']}.",
        "",
        "Mide el clasificador Random Forest ya entrenado sobre todos los pares SAST × DAST "
        "de dos aplicaciones con ground truth (Tarea 3), etiquetados como positivos cuando "
        "ambos hallazgos corresponden a la misma vulnerabilidad del ground truth. No se "
        "reentrena ni se modifica el modelo, el umbral ni los datos.",
        "",
        "## Modelo y entorno",
        "",
        f"- Versión del modelo: `{payload['model']['version']}`",
        f"- Entrenado (pkl): `{payload['model']['trained_at_pkl']}`",
        f"- Entrenado (metadata.json): `{payload['model']['trained_at_metadata']}`",
        f"- n_features: {payload['model']['n_features']}; umbral de decisión: {payload['model']['threshold']}",
        f"- Python: {env['python']}; scikit-learn: {env['sklearn']}",
        "",
        "## Control de consistencia obligatorio",
        "",
        "| Vulnerabilidad | Prob. RF esperada | Prob. RF observada | Confianza total | ¿OK? |",
        "|---|---|---|---|---|",
    ]
    for c in payload["consistency_check"]:
        if c.get("status") == "NO_CANDIDATES":
            out.append(f"| {c['id']} | {c['expected_rf']} | (sin candidatos) | — | ❌ |")
        else:
            out.append(
                f"| {c['id']} | {c['expected_rf']} | {c['observed_rf']:.4f} | "
                f"{c['total_confidence']:.4f} | {'✅' if c['passed'] else '❌'} |"
            )
    out += ["", "## Juice Shop (excluida)", "",
            "La ejecución de la Tarea 3 de OWASP Juice Shop no tiene archivo de ground truth "
            "asociado (no existe un `correlation_evaluation_juiceshop_*`), por lo que no se "
            "pueden etiquetar pares positivos/negativos y queda fuera de esta evaluación.", ""]

    # Totales
    t = payload["totals"]
    cm = t["confusion_matrix_threshold_0.5"]
    h = payload["synthetic_holdout_reference"]
    out += [
        "## Totales (ambas aplicaciones)",
        "",
        f"- Pares: **{t['n_pairs']}** — positivos: **{t['n_positives']}**, negativos: **{t['n_negatives']}**.",
        "",
        "| | Pred. negativo | Pred. positivo |",
        "|---|---|---|",
        f"| **Real negativo** | VN = {cm['TN']} | FP = {cm['FP']} |",
        f"| **Real positivo** | FN = {cm['FN']} | VP = {cm['TP']} |",
        "",
        f"- Tasa de falsos positivos (pares reales): {cm['FP']} / {t['n_negatives']} = "
        f"{'—' if t['false_positive_rate_on_negatives'] is None else format(t['false_positive_rate_on_negatives'], '.4f')}.",
    ]
    out += [
        f"- Referencia holdout sintético independiente: {h['FP']} / {h['n_negatives']} = "
        f"{h['false_positive_rate']:.4f} (fuente: `{h['source']}`).",
        "",
        "## Resultados por aplicación",
        "",
    ]
    for res in payload["per_app"]:
        out += md_app(res)
    return "\n".join(out)


# ── Main ───────────────────────────────────────────────────────────────────────


def main():
    correlator = VulnerabilityCorrelator()
    if correlator.ml_classifier is None:
        raise SystemExit("No hay modelo RF cargado; abortando (no se evalúa con fallback).")

    results = [evaluate_app(app, correlator) for app in ("vulnerable_app", "vampi")]

    # Control de consistencia: detener si no se reproduce.
    consistency = []
    for res in results:
        consistency += consistency_check(res["app_key"], res, correlator)
    failed = [c for c in consistency if not c.get("passed", False)]
    if failed:
        print("\n⛔ CONTROL DE CONSISTENCIA FALLIDO — no se reproducen las probabilidades conocidas:")
        for c in failed:
            print(f"   {c}")
        raise SystemExit("Deteniendo antes de generar reportes (según lo solicitado).")
    print("\n✅ Control de consistencia superado:")
    for c in consistency:
        print(f"   {c['id']}: esperado {c['expected_rf']}, observado {c['observed_rf']:.4f} "
              f"(confianza total {c['total_confidence']:.4f})")

    # Totales
    def agg(key):
        return sum(r[key] for r in results)

    tot_cm = {k: sum(r["confusion_matrix_threshold_0.5"][k] for r in results) for k in ("TN", "FP", "FN", "TP")}
    tot_neg = agg("n_negatives")
    totals = {
        "n_pairs": agg("n_pairs"),
        "n_positives": agg("n_positives"),
        "n_negatives": tot_neg,
        "confusion_matrix_threshold_0.5": tot_cm,
        "false_positive_rate_on_negatives": (round(tot_cm["FP"] / tot_neg, 6) if tot_neg else None),
    }

    holdout = json.loads(HOLDOUT_FILE.read_text(encoding="utf-8"))
    h_cm = holdout["confusion_matrix"]
    h_neg = h_cm["TN"] + h_cm["FP"]
    synthetic_ref = {
        "source": HOLDOUT_FILE.name,
        "FP": h_cm["FP"],
        "n_negatives": h_neg,
        "false_positive_rate": round(h_cm["FP"] / h_neg, 6),
    }

    model = {
        "version": correlator.model_metrics.get("version"),
        "trained_at_pkl": correlator.model_metrics.get("trained_at"),
        "trained_at_metadata": json.loads((REPO / "data" / "models" / "metadata.json").read_text())
        .get("training_info", {}).get("trained_at"),
        "n_features": correlator.model_metrics.get("n_features"),
        "threshold": THRESHOLD,
    }

    # Quitar datos internos del payload serializado.
    per_app = []
    for r in results:
        r2 = {k: v for k, v in r.items() if k != "_internal"}
        per_app.append(r2)

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "description": "Evaluación del Random Forest entrenado sobre pares reales SAST-DAST etiquetados con ground truth.",
        "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__},
        "model": model,
        "excluded": {"juice_shop": "La ejecución de la Tarea 3 de Juice Shop no tiene ground truth; se excluye."},
        "consistency_check": consistency,
        "synthetic_holdout_reference": synthetic_ref,
        "totals": totals,
        "per_app": per_app,
    }

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = OUT_DIR / f"real_pairs_evaluation_{stamp}.json"
    md_path = OUT_DIR / f"real_pairs_evaluation_{stamp}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(build_markdown(payload), encoding="utf-8")

    print(f"\nGuardado: {json_path.relative_to(REPO)}")
    print(f"Guardado: {md_path.relative_to(REPO)}")
    print("\n=== RESUMEN ===")
    for r in per_app:
        cm = r["confusion_matrix_threshold_0.5"]
        print(f"{r['app_key']}: pares={r['n_pairs']} pos={r['n_positives']} neg={r['n_negatives']} "
              f"| VN={cm['TN']} FP={cm['FP']} FN={cm['FN']} VP={cm['TP']} "
              f"| FPR={r['false_positive_rate_on_negatives']}")
    print(f"TOTAL: pares={totals['n_pairs']} pos={totals['n_positives']} neg={totals['n_negatives']} "
          f"| VN={tot_cm['TN']} FP={tot_cm['FP']} FN={tot_cm['FN']} VP={tot_cm['TP']} "
          f"| FPR={totals['false_positive_rate_on_negatives']}")
    print(f"Holdout sintético (ref.): FPR={synthetic_ref['false_positive_rate']} "
          f"({synthetic_ref['FP']}/{synthetic_ref['n_negatives']})")


if __name__ == "__main__":
    main()
