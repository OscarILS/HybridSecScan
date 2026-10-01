"""
Evaluación del motor de correlación contra ground truth, por aplicación.

A diferencia de run_scale_evaluation.py (que mide la UNIÓN de hallazgos SAST+DAST),
este script mide el propio motor de correlación: compara contra el ground truth de
cada aplicación los hallazgos de SAST, DAST, su unión y los pares SAST↔DAST que el
correlador confirma (umbral 0.70).

Aplicaciones (APPS):
  - vulnerable_app: ProgramasPruebas/vulnerable_app.py (Flask, caso de estudio propio)
  - vampi:          VAmPI, API REST vulnerable (Flask/connexion, OpenAPI)

Criterios de acierto (ver matching_rules en cada ground truth):
  - SAST: archivo y línea dentro de una ubicación de la vulnerabilidad y CWE aceptado
  - DAST: endpoint coincidente ('{param}' = cualquier segmento; '*' = falla global) y CWE aceptado
  - Correlación: ambos lados aciertan la MISMA vulnerabilidad

Precisión = hallazgos correctos / hallazgos. Recall = vulnerabilidades encontradas / total.

Uso (tras generar los hallazgos SAST/DAST de cada aplicación en data/experiments/results/):
    python scripts/run_correlation_evaluation.py               # todas las aplicaciones
    python scripts/run_correlation_evaluation.py --app vampi
    python scripts/run_correlation_evaluation.py --save
"""

import argparse
import ast
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
GT_DIR = REPO / "data" / "experiments" / "ground_truth"
OUT_DIR = REPO / "data" / "experiments"
FIG_DIR = OUT_DIR / "figures"
THRESHOLD = 0.70

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

APPS: Dict[str, Dict] = {
    "vulnerable_app": {
        "label": "App vulnerable propia (Flask)",
        "gt": GT_DIR / "vulnerable_app_ground_truth.json",
        "sast": "sast_bandit_vulnerable_*.json",
        "dast": "dast_active_vulnerable_*.json",
        "routes": "flask",
        "source_root": REPO / "ProgramasPruebas",
    },
    "vampi": {
        "label": "VAmPI (API REST vulnerable)",
        "gt": GT_DIR / "vampi_ground_truth.json",
        "sast": "sast_bandit_vampi_*.json",
        "dast": "dast_active_vampi_*.json",
        "routes": "openapi",
        "source_root": REPO / "data" / "experiments" / "test_apps" / "vampi",
        "openapi": "openapi_specs/openapi3.yml",
    },
}


# ── Criterios de acierto ──────────────────────────────────────────────────────


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


def _norm_path(p: str) -> str:
    return str(p or "").replace("\\", "/")


def _locations(v: dict) -> List[dict]:
    """Ubicaciones de una vulnerabilidad: formato 'locations' o el antiguo 'lines' (app de un solo archivo)."""
    if "locations" in v:
        return v["locations"]
    return [{"file": None, "lines": v["lines"]}] if v.get("lines") else []


def sast_matches(finding: dict, gt: List[dict]) -> Set[str]:
    """IDs de vulnerabilidades del ground truth que acierta un hallazgo de Bandit."""
    line, cwe = finding.get("line_number"), _cwe_int(finding.get("issue_cwe"))
    fname = _norm_path(finding.get("filename", ""))
    hits = set()
    for v in gt:
        if cwe not in v["accepted_cwes"]:
            continue
        for loc in _locations(v):
            same_file = loc["file"] is None or fname.endswith(_norm_path(loc["file"]))
            if same_file and loc["lines"][0] <= line <= loc["lines"][1]:
                hits.add(v["id"])
    return hits


def _endpoint_matches(template: str, path: str) -> bool:
    if template == "*":
        return True
    pattern = "^" + re.sub(r"\\\{[^/]+?\\\}", "[^/]+", re.escape(template)) + "$"
    return re.match(pattern, path) is not None


def dast_matches(finding: dict, gt: List[dict]) -> Set[str]:
    """IDs de vulnerabilidades del ground truth que acierta un hallazgo DAST."""
    ep, cwe = _endpoint(finding.get("url")), _cwe_int(finding.get("cwe"))
    return {
        v["id"]
        for v in gt
        if v["endpoint"] is not None and _endpoint_matches(v["endpoint"], ep) and cwe in v["accepted_cwes"]
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


# ── Endpoint de un hallazgo SAST ──────────────────────────────────────────────


def openapi_routes(spec: Path) -> Dict[str, str]:
    """operationId ('api_views.users.update_password') → ruta ('/users/v1/{username}/password')."""
    import yaml

    doc = yaml.safe_load(spec.read_text(encoding="utf-8"))
    routes = {}
    for path, ops in (doc.get("paths") or {}).items():
        for op in ops.values():
            if isinstance(op, dict) and op.get("operationId"):
                routes[op["operationId"]] = path
    return routes


def enclosing_function(source: Path, line: int) -> Optional[str]:
    """Nombre de la función de nivel superior que contiene la línea."""
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"))
    except Exception:
        return None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= (node.end_lineno or node.lineno):
                return node.name
    return None


def sast_endpoint_openapi(finding: dict, root: Path, routes: Dict[str, str]) -> str:
    """Endpoint del hallazgo según el operationId de la función que lo contiene; '/unknown_line_N' si no hay."""
    line = finding.get("line_number", 0)
    src = Path(finding.get("filename", ""))
    if not src.is_absolute():
        src = REPO / src
    func = enclosing_function(src, line)
    if func:
        try:
            module = ".".join(src.resolve().relative_to(root.resolve()).with_suffix("").parts)
            if f"{module}.{func}" in routes:
                return routes[f"{module}.{func}"]
        except ValueError:
            pass
    return f"/unknown_line_{line}"


# ── Evaluación ────────────────────────────────────────────────────────────────


def latest(pattern: str) -> Path:
    files = sorted(RES_DIR.glob(pattern))
    if not files:
        raise SystemExit(f"No hay {pattern} en {RES_DIR}")
    return files[-1]


def gt_category(v: dict) -> str:
    """Categoría OWASP 2023 de una vulnerabilidad del ground truth (la declarada, o por su CWE)."""
    if v.get("owasp_category"):
        return v["owasp_category"]
    from backend.owasp_mapping import category_for_cwe

    return category_for_cwe(v.get("cwe_id")) or "—"


def evaluate(app: str, sast_file: Path, dast_file: Path) -> Dict:
    cfg = APPS[app]
    gt = json.loads(cfg["gt"].read_text(encoding="utf-8"))["vulnerabilities"]
    sast_raw = json.loads(sast_file.read_text(encoding="utf-8"))["results"]
    dast_raw = json.loads(dast_file.read_text(encoding="utf-8"))["vulnerabilities"]

    sast_hits = [sast_matches(f, gt) for f in sast_raw]
    dast_hits = [dast_matches(f, gt) for f in dast_raw]

    # Correlador: mismo mapeo y mismo motor que los experimentos
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        import run_vulnerable_app_experiment as va

        from backend.correlation_engine import VulnerabilityCorrelator

        if cfg["routes"] == "flask":
            sast_v = [va.map_bandit_finding(f, str(va.APP_PATH)) for f in sast_raw]
        else:
            routes = openapi_routes(cfg["source_root"] / cfg["openapi"])
            sast_v = []
            for f in sast_raw:
                v = va.map_bandit_finding(f, f.get("filename", ""))
                v.endpoint = sast_endpoint_openapi(f, cfg["source_root"], routes)
                sast_v.append(v)
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
                "sast": f"{sast_raw[si]['test_id']} {Path(_norm_path(sast_raw[si]['filename'])).name}:"
                f"{sast_raw[si]['line_number']}",
                "dast": f"{dast_raw[di].get('type')} @ {_endpoint(dast_raw[di].get('url'))}",
                "ground_truth": sorted(common) or None,
            }
        )

    n_gt = len(gt)
    sast_found = set().union(*sast_hits) if sast_hits else set()
    dast_found = set().union(*dast_hits) if dast_hits else set()
    corr_found = set().union(*corr_hits) if corr_hits else set()
    both = sast_found & dast_found

    # Para cada vulnerabilidad detectada por ambas técnicas: el par de mayor confianza y su desglose
    both_pairs = []
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        for vid in sorted(both):
            candidates = [
                (si, di, correlator.confidence_breakdown(sast_v[si], dast_v[di]))
                for si in range(len(sast_v))
                if vid in sast_hits[si]
                for di in range(len(dast_v))
                if vid in dast_hits[di]
            ]
            si, di, bd = max(candidates, key=lambda c: c[2]["confidence"])
            both_pairs.append(
                {
                    "vulnerability": vid,
                    "sast": f"{sast_raw[si]['test_id']} {Path(_norm_path(sast_raw[si]['filename'])).name}:"
                    f"{sast_raw[si]['line_number']} → {sast_v[si].endpoint}",
                    "dast": f"{dast_raw[di].get('type')} @ {_endpoint(dast_raw[di].get('url'))}",
                    "confidence": round(bd["confidence"], 4),
                    "confirmed": bd["confidence"] > THRESHOLD,
                    "factors": bd["factors"],
                }
            )

    # Detección por categoría OWASP API Top 10 (2023)
    by_category: Dict[str, Dict] = {}
    for v in gt:
        cat = gt_category(v)
        row = by_category.setdefault(cat, {"total": 0, "sast": 0, "dast": 0, "union": 0, "correlation": 0, "ids": []})
        row["total"] += 1
        row["ids"].append(v["id"])
        row["sast"] += v["id"] in sast_found
        row["dast"] += v["id"] in dast_found
        row["union"] += v["id"] in (sast_found | dast_found)
        row["correlation"] += v["id"] in corr_found

    return {
        "application": cfg["label"],
        "app_key": app,
        "ground_truth_file": cfg["gt"].name,
        "ground_truth_n": n_gt,
        "ground_truth": {
            v["id"]: {"name": v.get("name") or v.get("description"), "category": gt_category(v)} for v in gt
        },
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
        "confirmed_by_correlation": sorted(corr_found),
        "correlations": corr_detail,
        "detected_by_both_pairs": both_pairs,
        "by_owasp_category": dict(sorted(by_category.items(), key=lambda kv: int(re.sub(r"\D", "", kv[0]) or 99))),
    }


# ── Salida ────────────────────────────────────────────────────────────────────

FACTOR_LABELS = {
    "endpoint": "Similitud de endpoint",
    "type": "Tipo de vulnerabilidad",
    "semantic": "Similitud semántica",
    "ml": "Probabilidad del Random Forest",
    "severity": "Similitud de severidad",
}
METHOD_LABELS = {
    "sast": "SAST (Bandit)",
    "dast": "DAST (escáner activo)",
    "union": "Unión SAST+DAST",
    "correlation": "Correlación (pares confirmados)",
}


def markdown_app(res: Dict) -> List[str]:
    n = res["ground_truth_n"]
    out = [
        f"## {res['application']}",
        "",
        f"Ground truth: {n} vulnerabilidades (`{res['ground_truth_file']}`). "
        f"Hallazgos: `{res['sast_file']}`, `{res['dast_file']}`. Umbral de correlación: {res['threshold']}.",
        "",
        "| Método | Hallazgos | Correctos | Incorrectos | Vulnerabilidades encontradas | Precisión | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for key, label in METHOD_LABELS.items():
        m = res["methods"][key]
        out.append(
            f"| {label} | {m['findings']} | {m['correct_findings']} | {m['incorrect_findings']} | "
            f"{len(m['vulnerabilities_found'])} de {n} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} |"
        )

    out += [
        "",
        "### Detección por categoría OWASP API Top 10 (2023)",
        "",
        "| Categoría | Vulnerabilidades | SAST | DAST | Unión | Correlación |",
        "|---|---|---|---|---|---|",
    ]
    for cat, r in res["by_owasp_category"].items():
        out.append(
            f"| {cat} | {r['total']} ({', '.join(r['ids'])}) | {r['sast']} | {r['dast']} | {r['union']} | "
            f"{r['correlation']} |"
        )

    both, conf = res["detected_by_both"], res["confirmed_by_correlation"]
    out += [
        "",
        f"Vulnerabilidades detectadas por ambas técnicas (las únicas que el correlador puede confirmar): "
        f"{len(both)} ({', '.join(both) or '—'}). Confirmadas por el correlador: {len(conf)} "
        f"({', '.join(conf) or '—'}).",
    ]
    if res["correlations"]:
        out += ["", "| Confianza | SAST | DAST | Vulnerabilidad del ground truth |", "|---|---|---|---|"]
        for c in res["correlations"]:
            gt = ", ".join(c["ground_truth"] or ["ninguna"])
            out.append(f"| {c['confidence']:.3f} | {c['sast']} | {c['dast']} | {gt} |")

    pairs = res.get("detected_by_both_pairs", [])
    if pairs:
        head = " | ".join(f"{p['vulnerability']} (valor → aporte)" for p in pairs)
        out += ["", "### Desglose de la confianza (vulnerabilidades detectadas por ambas técnicas)", ""]
        for p in pairs:
            estado = "confirmada" if p["confirmed"] else f"no confirmada (< {res['threshold']})"
            out.append(f"- **{p['vulnerability']}**: SAST {p['sast']}; DAST {p['dast']} — {estado}.")
        out += ["", f"| Factor | Peso | {head} |", "|---|---|" + "---|" * len(pairs)]
        for key, label in FACTOR_LABELS.items():
            weight = pairs[0]["factors"][key]["weight"]
            cells = " | ".join(
                f"{p['factors'][key]['value']:.3f} → {p['factors'][key]['contribution']:.3f}" for p in pairs
            )
            out.append(f"| {label} | {weight:.2f} | {cells} |")
        totals = " | ".join(f"**{p['confidence']:.3f}**" for p in pairs)
        out.append(f"| **Confianza total** | 1.00 | {totals} |")
        method = pairs[0]["factors"]["semantic"].get("method", "")
        out += ["", f"Aporte = peso × valor. Similitud semántica calculada con {method}."]
    out.append("")
    return out


def markdown(results: List[Dict]) -> str:
    out = [
        "# Evaluación del motor de correlación contra ground truth",
        "",
        "Precisión = hallazgos correctos / hallazgos; recall = vulnerabilidades encontradas / total. "
        "Los pesos de la confianza son una decisión de diseño (backend/correlation_engine.py, CONFIDENCE_WEIGHTS). "
        "Cada aplicación es un caso de estudio: los resultados ilustran el comportamiento del sistema, "
        "no permiten generalizar.",
        "",
    ]
    for res in results:
        out += markdown_app(res)
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description="Evalúa el motor de correlación contra ground truth")
    parser.add_argument("--app", choices=sorted(APPS) + ["all"], default="all")
    parser.add_argument("--save", action="store_true", help="Guarda un JSON por aplicación y la tabla Markdown")
    args = parser.parse_args()

    apps = sorted(APPS) if args.app == "all" else [args.app]
    apps = [a for a in ("vulnerable_app", "vampi") if a in apps]  # orden de presentación
    results = [evaluate(a, latest(APPS[a]["sast"]), latest(APPS[a]["dast"])) for a in apps]
    md = markdown(results)
    print(md)
    if args.save:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        for res in results:
            out = OUT_DIR / f"correlation_evaluation_{res['app_key']}_{stamp}.json"
            out.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Guardado: {out.relative_to(REPO)}")
        FIG_DIR.mkdir(parents=True, exist_ok=True)
        (FIG_DIR / "tabla_evaluacion_correlacion.md").write_text(md, encoding="utf-8")
        print(f"Guardado: {(FIG_DIR / 'tabla_evaluacion_correlacion.md').relative_to(REPO)}")


if __name__ == "__main__":
    main()
