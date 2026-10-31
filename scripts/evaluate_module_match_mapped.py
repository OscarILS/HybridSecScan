"""
ANÁLISIS EXPLORATORIO — corrección del atributo module_match ("mapped_endpoint").

⚠️  EXPLORATORIO Y POST-HOC: este análisis se diseñó DESPUÉS de observar que, en
    real_pairs_evaluation_20261030_211257, module_match valió 0 en los 221 pares
    reales. Se evalúa sobre esas MISMAS dos aplicaciones (Flask y VAmPI), así que
    no es una validación independiente; es una exploración de qué pasaría con un
    cálculo alternativo de module_match. No se reentrena el modelo ni se cambian
    el umbral (0.5), los pesos del motor, el umbral de correlación (0.70), los
    datos ni ningún archivo de resultados existente.

Dos modos de module_match (ver backend/feature_utils.py, parámetro `mode`):
  - "file" (por defecto, comportamiento original): module_of_file(file_path SAST)
    vs module_of_endpoint(endpoint DAST).
  - "mapped_endpoint": module_of_endpoint(endpoint MAPEADO del hallazgo SAST) vs
    module_of_endpoint(endpoint DAST). Si el hallazgo SAST no tiene endpoint
    mapeado (endpoint "/unknown_line_*"), se usa el modo "file" para ese hallazgo
    y se registra.

Camino de inferencia: se reutiliza EXACTAMENTE el de correlation_engine.py
(_engineer_features_for_prediction). El modo "mapped_endpoint" solo sustituye el
elemento module_match (índice 511) del vector de features antes de predict_proba;
todo lo demás (TF-IDF, categóricas y demás numéricas) queda idéntico. El motor
nunca usa el modo "mapped_endpoint": su comportamiento por defecto no cambia.

El mapeo SAST → endpoint es el que ya existe en el pipeline (se reutiliza vía
scripts/evaluate_real_pairs.py: @app.route para Flask, operationId OpenAPI para
VAmPI). No se crea ningún mapeo nuevo.

Uso:
    py -3.11 scripts/evaluate_module_match_mapped.py
"""

import io
import json
import platform
import statistics
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path

import sklearn

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "backend"))

import evaluate_real_pairs as erp  # noqa: E402  reutiliza build_app / evaluate_app (modo "file")
import run_correlation_evaluation as rce  # noqa: E402  (solo para nombres en informes)

from backend.correlation_engine import CONFIDENCE_WEIGHTS, VulnerabilityCorrelator  # noqa: E402
from backend.feature_utils import module_match  # noqa: E402  con parámetro mode

OUT_DIR = REPO / "data" / "experiments"
PRIOR_FILE = OUT_DIR / "real_pairs_evaluation_20261030_211257.json"

TH_CLF = 0.5   # umbral del clasificador (metadata.json)
TH_CORR = 0.70  # umbral de confirmación del motor de correlación (decisión de diseño)
W_ML = CONFIDENCE_WEIGHTS["ml"]  # 0.10

# Control de regresión: probabilidades RF conocidas (modo "file").
EXPECTED_FILE_RF = {"VA_002": 0.4725, "VA_009": 0.2522}


# ── module_match en modo "mapped_endpoint" y RF ───────────────────────────────


def mm_index(correlator) -> int:
    """Índice absoluto del atributo module_match en el vector de features."""
    tfidf_dim = len(correlator.tfidf_vectorizer.get_feature_names_out())
    # orden: tfidf(500) + 8 categóricas + numéricas[type,cwe,severity,MODULE_MATCH,...]
    return tfidf_dim + 8 + 3


def has_mapped_endpoint(sast_vuln) -> bool:
    ep = sast_vuln.endpoint or ""
    return bool(ep) and not ep.startswith("/unknown_line_")


def mapped_mm_value(sast_vuln, dast_vuln):
    """(valor module_match en modo mapped_endpoint, usó_fallback_file)."""
    if has_mapped_endpoint(sast_vuln):
        return module_match(sast_vuln.endpoint, dast_vuln.endpoint, mode="mapped_endpoint"), False
    # Sin endpoint mapeado → modo "file" para este hallazgo (registrado).
    return module_match(sast_vuln.file_path, dast_vuln.endpoint, mode="file"), True


def rf_mapped(correlator, sast_vuln, dast_vuln, idx):
    """Probabilidad RF con module_match en modo mapped_endpoint; resto idéntico al motor."""
    fv = correlator._engineer_features_for_prediction(sast_vuln, dast_vuln).astype(float).copy()
    val, fallback = mapped_mm_value(sast_vuln, dast_vuln)
    fv[idx] = val
    proba = float(correlator.ml_classifier.predict_proba(fv.reshape(1, -1))[0][1])
    return proba, int(val), fallback


def factors_with_ml(factors_file: dict, p_map: float) -> dict:
    """Desglose por factor con el valor de ml sustituido por p_map (modo mapped)."""
    out = {k: dict(v) for k, v in factors_file.items()}
    out["ml"] = {**out["ml"], "value": round(p_map, 4), "contribution": round(W_ML * p_map, 4)}
    return out


# ── Evaluación por aplicación (ambos modos) ────────────────────────────────────


def summarize(probs):
    if not probs:
        return {"n": 0, "min": None, "median": None, "mean": None, "max": None}
    return {"n": len(probs), "min": round(min(probs), 6), "median": round(statistics.median(probs), 6),
            "mean": round(statistics.mean(probs), 6), "max": round(max(probs), 6)}


def confusion(pairs, proba_key):
    pos = [p for p in pairs if p["label"] == 1]
    neg = [p for p in pairs if p["label"] == 0]
    tp = sum(1 for p in pos if p[proba_key] >= TH_CLF)
    fn = sum(1 for p in pos if p[proba_key] < TH_CLF)
    fp = sum(1 for p in neg if p[proba_key] >= TH_CLF)
    tn = sum(1 for p in neg if p[proba_key] < TH_CLF)
    return {"TN": tn, "FP": fp, "FN": fn, "TP": tp}, pos, neg


def corr_metrics(confirmed, n_gt):
    """Precisión/recall del método de correlación (pares confirmados) vs ground truth."""
    correct = sum(1 for r in confirmed if r["ground_truth"])
    found = set()
    for r in confirmed:
        found |= set(r["ground_truth"] or [])
    precision = correct / len(confirmed) if confirmed else None
    recall = len(found) / n_gt if n_gt else None
    return {"n_confirmed": len(confirmed), "correct": correct,
            "vulnerabilities_confirmed": sorted(found),
            "precision": None if precision is None else round(precision, 4),
            "recall": None if recall is None else round(recall, 4)}


def evaluate_app(app_key: str, correlator, idx: int) -> dict:
    file_res = erp.evaluate_app(app_key, correlator)  # modo "file" (idéntico al run previo)
    data = file_res["_internal"]["data"]
    file_pairs = file_res["_internal"]["pairs"]
    sast_v, dast_v = data["sast_v"], data["dast_v"]
    n_gt = len(data["gt"])

    rows = []
    for p in file_pairs:
        i, j = p["sast_index"], p["dast_index"]
        sv, dv = sast_v[i], dast_v[j]
        p_file = p["rf_probability"]
        mm_file = p["module_match"]
        p_map, mm_map, fallback = rf_mapped(correlator, sv, dv, idx)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            bd = correlator.confidence_breakdown(sv, dv)
        c_file = bd["confidence"]
        vals = {k: bd["factors"][k]["value"] for k in CONFIDENCE_WEIGHTS}
        vals["ml"] = p_map
        c_map = min(sum(CONFIDENCE_WEIGHTS[k] * vals[k] for k in CONFIDENCE_WEIGHTS), 1.0)
        rows.append({
            "sast_index": i, "dast_index": j,
            "sast": p["sast"], "dast": p["dast"],
            "label": p["label"], "ground_truth": p["ground_truth"],
            "rf_file": p_file, "rf_mapped": round(p_map, 6),
            "mm_file": mm_file, "mm_mapped": mm_map, "mapped_fallback_to_file": fallback,
            "conf_file": round(c_file, 6), "conf_mapped": round(c_map, 6),
            "factors_file": bd["factors"],
        })

    positives = [r for r in rows if r["label"] == 1]
    negatives = [r for r in rows if r["label"] == 0]

    # A. Clasificador en modo mapped_endpoint (seis métricas).
    cm_map, _, _ = confusion(rows, "rf_mapped")
    fpr_map = cm_map["FP"] / len(negatives) if negatives else None
    mm_dist_map = {
        "positives": {"module_match=1": sum(r["mm_mapped"] for r in positives),
                      "module_match=0": sum(1 - r["mm_mapped"] for r in positives)},
        "negatives": {"module_match=1": sum(r["mm_mapped"] for r in negatives),
                      "module_match=0": sum(1 - r["mm_mapped"] for r in negatives)},
    }
    analysis_A = {
        "n_pairs": len(rows), "n_positives": len(positives), "n_negatives": len(negatives),
        "confusion_matrix_threshold_0.5": cm_map,
        "false_positive_rate_on_negatives": None if fpr_map is None else round(fpr_map, 6),
        "positive_pairs": [
            {"ground_truth": r["ground_truth"], "sast": r["sast"], "dast": r["dast"],
             "rf_probability_mapped": r["rf_mapped"], "predicted_positive": r["rf_mapped"] >= TH_CLF,
             "module_match_mapped": r["mm_mapped"]}
            for r in sorted(positives, key=lambda r: r["rf_mapped"], reverse=True)
        ],
        "probability_summary_mapped": {
            "positives": summarize([r["rf_mapped"] for r in positives]),
            "negatives": summarize([r["rf_mapped"] for r in negatives]),
        },
        "module_match_distribution_mapped": mm_dist_map,
    }

    # B. Comparación par a par.
    changed = [r for r in rows if r["mm_file"] != r["mm_mapped"]]
    analysis_B = {
        "pairs_module_match_changed": len(changed),
        "positive_pairs_prob_by_mode": [
            {"ground_truth": r["ground_truth"], "sast": r["sast"], "dast": r["dast"],
             "module_match_file": r["mm_file"], "module_match_mapped": r["mm_mapped"],
             "rf_file": r["rf_file"], "rf_mapped": r["rf_mapped"],
             "delta_rf": round(r["rf_mapped"] - r["rf_file"], 6)}
            for r in sorted(positives, key=lambda r: r["rf_mapped"], reverse=True)
        ],
    }

    # C. Negativos que pasan a module_match = 1.
    analysis_C = [
        {"sast": r["sast"], "dast": r["dast"], "ground_truth": r["ground_truth"],
         "module_match_file": r["mm_file"], "module_match_mapped": r["mm_mapped"],
         "rf_file": r["rf_file"], "rf_mapped": r["rf_mapped"],
         "predicted_positive_mapped": r["rf_mapped"] >= TH_CLF}
        for r in negatives if r["mm_mapped"] == 1
    ]

    # D. Motor de correlación completo (umbral 0.70) en ambos modos.
    confirmed_file = [r for r in rows if r["conf_file"] > TH_CORR]
    confirmed_map = [r for r in rows if r["conf_mapped"] > TH_CORR]

    def confirmed_detail(r, mode):
        factors = r["factors_file"] if mode == "file" else factors_with_ml(r["factors_file"], r["rf_mapped"])
        return {"sast": r["sast"], "dast": r["dast"],
                "confidence": r["conf_file"] if mode == "file" else r["conf_mapped"],
                "ground_truth": r["ground_truth"],
                "corresponds_to_gt": bool(r["ground_truth"]),
                "factors": factors}

    analysis_D = {
        "file": {"confirmed_pairs": [confirmed_detail(r, "file") for r in
                                     sorted(confirmed_file, key=lambda r: r["conf_file"], reverse=True)],
                 "correlation_metrics": corr_metrics(confirmed_file, n_gt)},
        "mapped_endpoint": {"confirmed_pairs": [confirmed_detail(r, "mapped") for r in
                                                sorted(confirmed_map, key=lambda r: r["conf_mapped"], reverse=True)],
                            "correlation_metrics": corr_metrics(confirmed_map, n_gt)},
    }

    # E. VA_002 / VA_009 (pares positivos representativos).
    analysis_E = []
    for r in sorted(positives, key=lambda r: (r["ground_truth"] or [""])[0]):
        gt = ", ".join(r["ground_truth"] or [])
        cprime_file = round(r["conf_file"] - W_ML * r["rf_file"], 6)
        cprime_map = round(r["conf_mapped"] - W_ML * r["rf_mapped"], 6)
        analysis_E.append({
            "ground_truth": gt, "sast": r["sast"], "dast": r["dast"],
            "conf_file": r["conf_file"], "conf_mapped": r["conf_mapped"],
            "confirmed_file": r["conf_file"] > TH_CORR, "confirmed_mapped": r["conf_mapped"] > TH_CORR,
            "decision_changes_file_to_mapped": (r["conf_file"] > TH_CORR) != (r["conf_mapped"] > TH_CORR),
            "rf_file": r["rf_file"], "rf_mapped": r["rf_mapped"],
            "conf_file_without_rf": cprime_file, "conf_mapped_without_rf": cprime_map,
            "confirmed_file_without_rf": cprime_file > TH_CORR,
            "confirmed_mapped_without_rf": cprime_map > TH_CORR,
            "rf_suppression_changes_decision_file": (r["conf_file"] > TH_CORR) != (cprime_file > TH_CORR),
            "rf_suppression_changes_decision_mapped": (r["conf_mapped"] > TH_CORR) != (cprime_map > TH_CORR),
        })

    # F. Hallazgos SAST sin endpoint mapeado.
    unmapped = [
        {"index": i, "endpoint": sast_v[i].endpoint,
         "sast": next((r["sast"].split(" → ")[0] for r in rows if r["sast_index"] == i), str(i))}
        for i in range(len(sast_v)) if not has_mapped_endpoint(sast_v[i])
    ]
    analysis_F = {"n_sast_without_mapped_endpoint": len(unmapped), "findings": unmapped}

    return {
        "app_key": app_key,
        "application": data["meta"]["application"],
        "sources": file_res["sources"],
        "n_sast_findings": file_res["n_sast_findings"],
        "n_dast_findings": file_res["n_dast_findings"],
        "n_gt": n_gt,
        "file_mode_reference": {
            "confusion_matrix_threshold_0.5": file_res["confusion_matrix_threshold_0.5"],
            "false_positive_rate_on_negatives": file_res["false_positive_rate_on_negatives"],
            "positive_pairs": file_res["positive_pairs"],
            "probability_summary": file_res["probability_summary"],
            "module_match_distribution": file_res["module_match_distribution"],
        },
        "A_classifier_mapped": analysis_A,
        "B_pairwise_comparison": analysis_B,
        "C_negatives_now_module_match_1": analysis_C,
        "D_correlation_engine": analysis_D,
        "E_va002_va009": analysis_E,
        "F_sast_without_mapped_endpoint": analysis_F,
        "_file_res": file_res,  # para el control de regresión
    }


# ── Control de regresión (modo "file" == run previo) ───────────────────────────


def regression_check(results) -> list:
    prior = json.loads(PRIOR_FILE.read_text(encoding="utf-8"))
    prior_by_app = {a["app_key"]: a for a in prior["per_app"]}
    problems = []
    for res in results:
        fr = res["_file_res"]
        pa = prior_by_app.get(res["app_key"])
        if pa is None:
            problems.append(f"{res['app_key']}: no está en el archivo previo")
            continue
        if fr["confusion_matrix_threshold_0.5"] != pa["confusion_matrix_threshold_0.5"]:
            problems.append(f"{res['app_key']}: matriz de confusión difiere "
                            f"{fr['confusion_matrix_threshold_0.5']} vs {pa['confusion_matrix_threshold_0.5']}")
        now = [(x["ground_truth"], x["rf_probability"]) for x in fr["positive_pairs"]]
        old = [(x["ground_truth"], x["rf_probability"]) for x in pa["positive_pairs"]]
        if now != old:
            problems.append(f"{res['app_key']}: pares positivos difieren {now} vs {old}")
        if fr["probability_summary"] != pa["probability_summary"]:
            problems.append(f"{res['app_key']}: resumen de probabilidades difiere")
        if fr["module_match_distribution"] != pa["module_match_distribution"]:
            problems.append(f"{res['app_key']}: distribución module_match difiere")
    # Probabilidades conocidas 0.4725 / 0.2522
    seen = {}
    for res in results:
        for x in res["_file_res"]["positive_pairs"]:
            for gid in x["ground_truth"]:
                seen[gid] = x["rf_probability"]
    for gid, exp in EXPECTED_FILE_RF.items():
        if gid not in seen:
            problems.append(f"No se encontró par positivo {gid}")
        elif round(seen[gid], 4) != exp:  # 0.472525 → 0.4725; 0.252235 → 0.2522
            problems.append(f"{gid}: RF file {seen[gid]} (≈{round(seen[gid], 4)}) != esperado {exp}")
    return problems


# ── Markdown ───────────────────────────────────────────────────────────────────


def fmt(x, nd=4):
    return "—" if x is None else format(x, f".{nd}f")


def summ_row(label, s):
    if s["n"] == 0:
        return f"| {label} | 0 | — | — | — | — |"
    return f"| {label} | {s['n']} | {s['min']:.4f} | {s['median']:.4f} | {s['mean']:.4f} | {s['max']:.4f} |"


def factor_lines(factors):
    order = ["endpoint", "type", "semantic", "ml", "severity"]
    labels = {"endpoint": "Endpoint", "type": "Tipo", "semantic": "Semántica",
              "ml": "Random Forest", "severity": "Severidad"}
    rows = ["| Factor | Peso | Valor | Aporte |", "|---|---|---|---|"]
    for k in order:
        f = factors[k]
        rows.append(f"| {labels[k]} | {f['weight']:.2f} | {f['value']:.4f} | {f['contribution']:.4f} |")
    return rows


def md_app(res):
    out = [f"## {res['application']}", "",
           f"Fuentes: ground truth `{res['sources']['ground_truth_file']}`, "
           f"SAST `{res['sources']['sast_file']}`, DAST `{res['sources']['dast_file']}`. "
           f"Hallazgos SAST = {res['n_sast_findings']}, DAST = {res['n_dast_findings']}; "
           f"ground truth = {res['n_gt']}.", ""]

    A = res["A_classifier_mapped"]
    cm = A["confusion_matrix_threshold_0.5"]
    out += [
        "### A. Clasificador — modo mapped_endpoint (umbral 0.5)", "",
        f"- Pares: {A['n_pairs']} — positivos: {A['n_positives']}, negativos: {A['n_negatives']}.", "",
        "| | Pred. negativo | Pred. positivo |", "|---|---|---|",
        f"| **Real negativo** | VN = {cm['TN']} | FP = {cm['FP']} |",
        f"| **Real positivo** | FN = {cm['FN']} | VP = {cm['TP']} |", "",
        f"- Tasa de FP sobre negativos: {cm['FP']} / {A['n_negatives']} = {fmt(A['false_positive_rate_on_negatives'])} "
        f"(referencia sintética: 129 / 700 = 0.1843).", "",
        "Probabilidad RF (mapped) de cada par positivo:", "",
    ]
    if A["positive_pairs"]:
        out += ["| Ground truth | Prob. RF (mapped) | Pred. (≥0.5) | module_match | SAST | DAST |",
                "|---|---|---|---|---|---|"]
        for p in A["positive_pairs"]:
            out.append(f"| {', '.join(p['ground_truth'])} | {p['rf_probability_mapped']:.4f} | "
                       f"{'sí' if p['predicted_positive'] else 'no'} | {p['module_match_mapped']} | "
                       f"{p['sast']} | {p['dast']} |")
    else:
        out.append("_Sin pares positivos._")
    ps = A["probability_summary_mapped"]
    mmd = A["module_match_distribution_mapped"]
    out += ["", "Resumen de probabilidades RF (mapped):", "",
            "| Grupo | n | Mín | Mediana | Media | Máx |", "|---|---|---|---|---|---|",
            summ_row("Positivos", ps["positives"]), summ_row("Negativos", ps["negatives"]), "",
            "Distribución de module_match (mapped):", "",
            "| Grupo | module_match = 1 | module_match = 0 |", "|---|---|---|",
            f"| Positivos | {mmd['positives']['module_match=1']} | {mmd['positives']['module_match=0']} |",
            f"| Negativos | {mmd['negatives']['module_match=1']} | {mmd['negatives']['module_match=0']} |", ""]

    B = res["B_pairwise_comparison"]
    out += ["### B. Comparación par a par (file vs mapped)", "",
            f"- Pares que cambian de module_match: **{B['pairs_module_match_changed']}** de {A['n_pairs']}.", "",
            "Probabilidad de cada par positivo en ambos modos:", "",
            "| Ground truth | mm file | mm mapped | RF file | RF mapped | Δ RF |",
            "|---|---|---|---|---|---|"]
    for p in B["positive_pairs_prob_by_mode"]:
        out.append(f"| {', '.join(p['ground_truth'])} | {p['module_match_file']} | {p['module_match_mapped']} | "
                   f"{p['rf_file']:.4f} | {p['rf_mapped']:.4f} | {p['delta_rf']:+.4f} |")
    out.append("")

    C = res["C_negatives_now_module_match_1"]
    out += [f"### C. Pares NEGATIVOS que pasan a module_match = 1: {len(C)}", ""]
    if C:
        out += ["| Ground truth | RF file | RF mapped | Pred. (≥0.5) | SAST | DAST |",
                "|---|---|---|---|---|---|"]
        for r in sorted(C, key=lambda r: r["rf_mapped"], reverse=True):
            out.append(f"| {', '.join(r['ground_truth'] or ['—'])} | {r['rf_file']:.4f} | {r['rf_mapped']:.4f} | "
                       f"{'sí' if r['predicted_positive_mapped'] else 'no'} | {r['sast']} | {r['dast']} |")
    else:
        out.append("Ninguno.")
    out.append("")

    D = res["D_correlation_engine"]
    out += ["### D. Motor de correlación (umbral 0.70, pesos actuales)", ""]
    for mode, label in (("file", "Modo file"), ("mapped_endpoint", "Modo mapped_endpoint")):
        m = D[mode]["correlation_metrics"]
        out += [f"**{label}** — pares confirmados: {m['n_confirmed']}; correctos (corresponden a GT): "
                f"{m['correct']}; vulnerabilidades confirmadas: {', '.join(m['vulnerabilities_confirmed']) or '—'}; "
                f"precisión: {fmt(m['precision'])}, recall: {fmt(m['recall'])}.", ""]
        for c in D[mode]["confirmed_pairs"]:
            out += [f"- Confianza {c['confidence']:.4f} — SAST `{c['sast']}` × DAST `{c['dast']}` — "
                    f"GT: {', '.join(c['ground_truth'] or ['ninguna'])}.", ""]
            out += factor_lines(c["factors"])
            out.append("")
    E = res["E_va002_va009"]
    out += ["### E. VA_002 / VA_009: confianza y supresión del RF", "",
            "| GT | Conf. file | ¿conf.? | Conf. mapped | ¿conf.? | ¿cambia? | C' file (−RF) | ¿conf.? | "
            "C' mapped (−RF) | ¿conf.? |", "|---|---|---|---|---|---|---|---|---|---|"]
    for e in E:
        out.append(
            f"| {e['ground_truth']} | {e['conf_file']:.4f} | {'sí' if e['confirmed_file'] else 'no'} | "
            f"{e['conf_mapped']:.4f} | {'sí' if e['confirmed_mapped'] else 'no'} | "
            f"{'SÍ' if e['decision_changes_file_to_mapped'] else 'no'} | "
            f"{e['conf_file_without_rf']:.4f} | {'sí' if e['confirmed_file_without_rf'] else 'no'} | "
            f"{e['conf_mapped_without_rf']:.4f} | {'sí' if e['confirmed_mapped_without_rf'] else 'no'} |")
    out.append("")

    F = res["F_sast_without_mapped_endpoint"]
    out += [f"### F. Hallazgos SAST sin endpoint mapeado: {F['n_sast_without_mapped_endpoint']}", ""]
    if F["findings"]:
        for f in F["findings"]:
            out.append(f"- `{f['sast']}` (endpoint: `{f['endpoint']}`)")
    else:
        out.append("Ninguno: todos los hallazgos SAST tienen endpoint mapeado.")
    out.append("")
    return out


def build_markdown(payload):
    m = payload["model"]
    env = payload["environment"]
    out = [
        "# Análisis exploratorio — module_match en modo `mapped_endpoint`", "",
        "> ⚠️ **ANÁLISIS EXPLORATORIO Y POST-HOC.** Diseñado DESPUÉS de observar que "
        "`module_match` valió 0 en los 221 pares reales de `real_pairs_evaluation_20261030_211257`, "
        "y evaluado sobre esas MISMAS dos aplicaciones (Flask y VAmPI). No es una validación "
        "independiente. No se reentrena el modelo ni se cambian el umbral (0.5), los pesos del "
        "motor, el umbral de correlación (0.70), los datos ni archivos de resultados existentes. "
        "El modo por defecto del sistema sigue siendo `file`.", "",
        f"Generado: {payload['generated_at']}. Commit: `{payload['git_commit']}`.", "",
        "## Modelo y entorno", "",
        f"- Versión del modelo: `{m['version']}`; entrenado (pkl): `{m['trained_at_pkl']}`; "
        f"metadata.json: `{m['trained_at_metadata']}`.",
        f"- n_features: {m['n_features']}; índice de module_match: {m['module_match_feature_index']}; "
        f"umbral clasificador: {TH_CLF}; umbral correlación: {TH_CORR}; peso RF: {W_ML}.",
        f"- Python: {env['python']}; scikit-learn: {env['sklearn']}.", "",
        "## Control de regresión (modo file)", "",
        f"{payload['regression_check']['status']}: {payload['regression_check']['detail']}", "",
        "## Juice Shop", "",
        "Excluida: la ejecución de la Tarea 3 de Juice Shop no tiene ground truth.", "",
    ]
    t = payload["totals"]
    for mode_key, label in (("file", "modo file"), ("mapped_endpoint", "modo mapped_endpoint")):
        cm = t[mode_key]["confusion_matrix_threshold_0.5"]
        out += [f"## Totales — {label} (ambas apps, 221 pares)", "",
                f"- Positivos: {t['n_positives']}, negativos: {t['n_negatives']}.",
                f"- Matriz: VN={cm['TN']}, FP={cm['FP']}, FN={cm['FN']}, VP={cm['TP']}; "
                f"FP sobre negativos = {cm['FP']}/{t['n_negatives']} = {fmt(t[mode_key]['fpr'])}.",
                f"- Correlación (umbral 0.70): confirmados = {t[mode_key]['n_confirmed']}, "
                f"precisión = {fmt(t[mode_key]['corr_precision'])}, recall = {fmt(t[mode_key]['corr_recall'])}.", ""]
    out += ["## Resultados por aplicación", ""]
    for res in payload["per_app"]:
        out += md_app(res)
    return "\n".join(out)


# ── Main ───────────────────────────────────────────────────────────────────────


def main():
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        correlator = VulnerabilityCorrelator()
    if correlator.ml_classifier is None:
        raise SystemExit("No hay modelo RF cargado; abortando.")
    idx = mm_index(correlator)

    results = [evaluate_app(app, correlator, idx) for app in ("vulnerable_app", "vampi")]

    # Control de regresión OBLIGATORIO antes del análisis.
    problems = regression_check(results)
    if problems:
        print("⛔ CONTROL DE REGRESIÓN FALLIDO (modo file no reproduce el run previo):")
        for p in problems:
            print("   -", p)
        raise SystemExit("Deteniendo: el modo file debe reproducir real_pairs_evaluation_20261030_211257.")
    print("✅ Control de regresión superado: el modo file reproduce real_pairs_evaluation_20261030_211257")
    print("   (RF 0.4725 y 0.2522, matrices, resúmenes y distribuciones idénticos).")

    # Totales por modo
    def totals_for(mode_key):
        n_conf = correct = 0
        found = set()
        cm = {"TN": 0, "FP": 0, "FN": 0, "TP": 0}
        neg = 0
        for res in results:
            D = res["D_correlation_engine"][mode_key]
            cmm = D["correlation_metrics"]
            n_conf += cmm["n_confirmed"]
            correct += cmm["correct"]
            found |= set(cmm["vulnerabilities_confirmed"])
            src = res["A_classifier_mapped"] if mode_key == "mapped_endpoint" else res["_file_res"]
            k = "confusion_matrix_threshold_0.5"
            for kk in cm:
                cm[kk] += src[k][kk]
            neg += (res["A_classifier_mapped"]["n_negatives"] if mode_key == "mapped_endpoint"
                    else res["_file_res"]["n_negatives"])
        n_gt_total = sum(res["n_gt"] for res in results)
        return {"confusion_matrix_threshold_0.5": cm,
                "fpr": round(cm["FP"] / neg, 6) if neg else None,
                "n_confirmed": n_conf,
                "corr_precision": round(correct / n_conf, 4) if n_conf else None,
                "corr_recall": round(len(found) / n_gt_total, 4) if n_gt_total else None}

    totals = {
        "n_pairs": sum(r["A_classifier_mapped"]["n_pairs"] for r in results),
        "n_positives": sum(r["A_classifier_mapped"]["n_positives"] for r in results),
        "n_negatives": sum(r["A_classifier_mapped"]["n_negatives"] for r in results),
        "file": totals_for("file"),
        "mapped_endpoint": totals_for("mapped_endpoint"),
    }

    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                            cwd=REPO).stdout.strip() or "desconocido"
    model = {
        "version": correlator.model_metrics.get("version"),
        "trained_at_pkl": correlator.model_metrics.get("trained_at"),
        "trained_at_metadata": json.loads((REPO / "data" / "models" / "metadata.json").read_text())
        .get("training_info", {}).get("trained_at"),
        "n_features": correlator.model_metrics.get("n_features"),
        "module_match_feature_index": idx,
    }

    per_app = [{k: v for k, v in r.items() if not k.startswith("_")} for r in results]
    payload = {
        "analysis_type": "EXPLORATORIO / POST-HOC",
        "exploratory_warning": ("Diseñado después de observar module_match=0 en real_pairs_evaluation_"
                                "20261030_211257, sobre las mismas apps (Flask y VAmPI). No es validación "
                                "independiente. No modifica modelo, umbrales, pesos, datos ni resultados previos."),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "git_commit": commit,
        "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__},
        "model": model,
        "thresholds": {"classifier": TH_CLF, "correlation": TH_CORR, "ml_weight": W_ML},
        "excluded": {"juice_shop": "Sin ground truth en la Tarea 3."},
        "regression_check": {"status": "OK", "detail": "modo file reproduce real_pairs_evaluation_20261030_211257"},
        "totals": totals,
        "per_app": per_app,
    }

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = OUT_DIR / f"module_match_mapped_evaluation_{stamp}.json"
    md_path = OUT_DIR / f"module_match_mapped_evaluation_{stamp}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(build_markdown(payload), encoding="utf-8")

    print(f"\nGuardado: {json_path.relative_to(REPO)}")
    print(f"Guardado: {md_path.relative_to(REPO)}")
    print("\n=== RESUMEN (modo mapped_endpoint) ===")
    for r in per_app:
        A = r["A_classifier_mapped"]
        cm = A["confusion_matrix_threshold_0.5"]
        D = r["D_correlation_engine"]["mapped_endpoint"]["correlation_metrics"]
        print(f"{r['app_key']}: pos={A['n_positives']} neg={A['n_negatives']} | "
              f"VN={cm['TN']} FP={cm['FP']} FN={cm['FN']} VP={cm['TP']} | "
              f"mm1(neg)={A['module_match_distribution_mapped']['negatives']['module_match=1']} | "
              f"correlación confirmados={D['n_confirmed']} prec={D['precision']} rec={D['recall']}")
    tm = totals["mapped_endpoint"]["confusion_matrix_threshold_0.5"]
    print(f"TOTAL mapped: VN={tm['TN']} FP={tm['FP']} FN={tm['FN']} VP={tm['TP']} | "
          f"FPR={totals['mapped_endpoint']['fpr']} | correlación confirmados="
          f"{totals['mapped_endpoint']['n_confirmed']}")


if __name__ == "__main__":
    main()
