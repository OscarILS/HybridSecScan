"""
Evaluación experimental a escala — HybridSecScan vs SAST individual vs DAST individual.

Mide Precision, Recall y F1-Score de cada método contra ground truth validado
para 4 aplicaciones vulnerables reconocidas internacionalmente.

Metodología:
  1. Lee resultados SAST ya generados (Semgrep sobre código fuente)
  2. Lee resultados DAST ya generados (HTTP Scanner sobre apps en ejecución)
  3. Compara contra ground truth (data/experiments/ground_truth/*.json)
  4. Calcula TP/FP/FN por método y por app
  5. Ejecuta pruebas estadísticas: t-Student emparejada (scipy), Cohen's d, IC 95%
  6. Genera tabla comparativa lista para la tesis

Uso:
    py -3.11 scripts/run_scale_evaluation.py
    py -3.11 scripts/run_scale_evaluation.py --save   # guarda resultado en JSON
"""

import argparse
import json
import math
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from scipy import stats as scipy_stats

REPO = Path(__file__).resolve().parent.parent
GT_DIR = REPO / "data" / "experiments" / "ground_truth"
RES_DIR = REPO / "data" / "experiments" / "results"
OUTPUT_DIR = REPO / "data" / "experiments"

sys.path.insert(0, str(REPO))


# ── Normalización de tipos de vulnerabilidad ──────────────────────────────────

VULN_TYPE_MAP = {
    # SQL Injection (CWE-89)
    "sql_injection": "sql_injection",
    "sql injection": "sql_injection",
    "tainted-sql-string": "sql_injection",
    "tainted_sql_string": "sql_injection",
    "cwe-89": "sql_injection",
    "sqli": "sql_injection",
    "sql injection vector": "sql_injection",
    # XSS (CWE-79)
    "xss": "xss",
    "cross-site scripting": "xss",
    "cross_site_scripting": "xss",
    "echoed-request": "xss",
    "echoed_request": "xss",
    "cwe-79": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom xss": "xss",
    # Command injection (CWE-78, CWE-94)
    "command_injection": "command_injection",
    "command injection": "command_injection",
    "tainted-exec": "command_injection",
    "tainted_exec": "command_injection",
    "cwe-78": "command_injection",
    "cwe-94": "command_injection",
    "os command injection": "command_injection",
    # Path / File traversal / Inclusion (CWE-22, CWE-98)
    "path_traversal": "path_traversal",
    "file_inclusion": "path_traversal",
    "tainted-filename": "path_traversal",
    "tainted_filename": "path_traversal",
    "cwe-22": "path_traversal",
    "cwe-98": "path_traversal",
    "directory traversal": "path_traversal",
    # Broken auth / JWT (CWE-287)
    "broken_authentication": "broken_authentication",
    "jwt_manipulation": "broken_authentication",
    "broken auth": "broken_authentication",
    "cwe-287": "broken_authentication",
    "authentication bypass": "broken_authentication",
    "weak jwt": "broken_authentication",
    "broken authentication - jwt": "broken_authentication",
    "broken authentication - default credentials": "broken_authentication",
    "broken authentication - weak jwt secret": "broken_authentication",
    # IDOR / Broken access (CWE-639, CWE-284)
    "broken_access_control": "broken_access_control",
    "idor": "broken_access_control",
    "cwe-639": "broken_access_control",
    "cwe-284": "broken_access_control",
    "bola": "broken_access_control",
    "bola - unauthenticated access": "broken_access_control",
    "bola - cross-user access": "broken_access_control",
    "idor - object enumeration": "broken_access_control",
    # Sensitive data (CWE-200, CWE-798)
    "sensitive_data_exposure": "sensitive_data_exposure",
    "hardcoded": "sensitive_data_exposure",
    "phpinfo": "sensitive_data_exposure",
    "phpinfo-use": "sensitive_data_exposure",
    "cwe-200": "sensitive_data_exposure",
    "cwe-798": "sensitive_data_exposure",
    "hardcoded secret": "sensitive_data_exposure",
    "sensitive files": "sensitive_data_exposure",
    # NoSQL injection (CWE-943)
    "nosql_injection": "nosql_injection",
    "cwe-943": "nosql_injection",
    "nosql injection": "nosql_injection",
    # String concatenation in queries → injection (JS/NodeGoat pattern)
    "code-string-concat": "nosql_injection",
    "code_string_concat": "nosql_injection",
    "string-concat": "nosql_injection",
    # Deserialization (CWE-502)
    "insecure_deserialization": "insecure_deserialization",
    "cwe-502": "insecure_deserialization",
    "deserialization": "insecure_deserialization",
    "prototype pollution": "insecure_deserialization",
    # XXE (CWE-611)
    "xxe": "xxe",
    "cwe-611": "xxe",
    "xml external entity": "xxe",
    # CSRF (CWE-352)
    "csrf": "csrf",
    "cwe-352": "csrf",
    "cross-site request forgery": "csrf",
    # Misc security config
    "security_misconfiguration": "security_misconfiguration",
    "missing security header": "security_misconfiguration",
    "rate limit": "security_misconfiguration",
    "insecure transport": "security_misconfiguration",
    "cors": "security_misconfiguration",
    # Active probe finding types
    "sql injection": "sql_injection",
    "path traversal": "path_traversal",
    "error disclosure - debug mode": "sensitive_data_exposure",
    "insecure random - predictable token": "broken_authentication",
}

# Agrupaciones semánticas para matching flexible
RELATED_TYPES = {
    "sql_injection": {"sql_injection", "nosql_injection"},
    "nosql_injection": {"sql_injection", "nosql_injection"},
    "broken_authentication": {"broken_authentication", "sensitive_data_exposure"},
    "path_traversal": {"path_traversal", "security_misconfiguration"},
    "broken_access_control": {"broken_access_control", "sensitive_data_exposure"},
    "xss": {"xss", "security_misconfiguration"},
}


def normalize_type(raw: str) -> str:
    """Normaliza el tipo de vulnerabilidad a la taxonomía interna."""
    r = raw.lower().strip().replace(" ", "_")
    if r in VULN_TYPE_MAP:
        return VULN_TYPE_MAP[r]
    # Búsqueda parcial
    for key, val in VULN_TYPE_MAP.items():
        if key in r or r in key:
            return val
    return r


def path_similarity(p1: str, p2: str) -> float:
    """Similitud entre rutas de archivo o endpoints (0-1)."""
    if not p1 or not p2:
        return 0.0
    # Normalizar separadores y bajar a minúsculas
    a = p1.replace("\\", "/").lower().strip("/")
    b = p2.replace("\\", "/").lower().strip("/")
    if a == b:
        return 1.0
    # Comprobar si uno es sufijo del otro
    if a.endswith(b) or b.endswith(a):
        return 0.85
    # Segmentos en común
    segs_a = set(a.split("/"))
    segs_b = set(b.split("/"))
    inter = segs_a & segs_b
    union = segs_a | segs_b
    return len(inter) / len(union) if union else 0.0


# ── Parsers de resultados de herramientas ─────────────────────────────────────


def parse_semgrep(path: Path) -> List[dict]:
    """Extrae hallazgos normalizados de un resultado Semgrep JSON."""
    try:
        d = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    findings = []
    for r in d.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})

        # Extraer CWE de metadata
        raw_cwe = ""
        cwes = meta.get("cwe", [])
        if cwes:
            raw_cwe = cwes[0].split(":")[0].strip().lower()

        # Intentar tipo desde check_id si CWE no da resultado claro
        check_id = r.get("check_id", "")
        # Extraer la parte más específica del check_id (última sección después del último '.')
        check_parts = check_id.split(".")
        check_leaf = check_parts[-1] if check_parts else check_id

        vuln_type = normalize_type(raw_cwe)
        if vuln_type == raw_cwe or not vuln_type:  # sin mapeo útil
            vuln_type = normalize_type(check_id)
        if vuln_type == check_id or not vuln_type:  # aún sin mapeo
            vuln_type = normalize_type(check_leaf)

        file_path = r.get("path", "")
        # Endpoint desde el path relativo (últimos 3 segmentos del archivo)
        try:
            rel_parts = Path(file_path.replace("\\", "/")).parts
            endpoint = "/" + "/".join(rel_parts[-3:]) if len(rel_parts) >= 3 else "/" + file_path
        except Exception:
            endpoint = "/" + file_path

        findings.append(
            {
                "type": vuln_type,
                "file_path": file_path,
                "endpoint": endpoint,
                "severity": r.get("extra", {}).get("severity", "WARNING").upper(),
                "cwe": raw_cwe,
                "tool": "semgrep",
                "description": r.get("extra", {}).get("message", ""),
                "check_id": check_id,
            }
        )
    return findings


def parse_bandit(path: Path) -> List[dict]:
    """Extrae hallazgos normalizados de un resultado Bandit JSON."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    findings = []
    for r in d.get("results", []):
        cwe_info = r.get("issue_cwe", {})
        cwe_id = f"cwe-{cwe_info.get('id', 0)}" if isinstance(cwe_info, dict) else ""
        vuln_type = normalize_type(cwe_id) if cwe_id else normalize_type(r.get("test_id", ""))
        findings.append(
            {
                "type": vuln_type,
                "file_path": r.get("filename", ""),
                "endpoint": "/" + Path(r.get("filename", "")).stem,
                "severity": r.get("issue_severity", "LOW").upper(),
                "cwe": cwe_id,
                "tool": "bandit",
                "description": r.get("issue_text", ""),
            }
        )
    return findings


def parse_dast_http(path: Path) -> List[dict]:
    """Extrae hallazgos normalizados de un resultado HTTP Scanner JSON."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    findings = []
    for v in d.get("vulnerabilities", []):
        from urllib.parse import urlparse

        url = v.get("url", "/")
        endpoint = urlparse(url).path or "/"
        vuln_type = normalize_type(v.get("type", v.get("alert", "")))
        findings.append(
            {
                "type": vuln_type,
                "file_path": "",
                "endpoint": endpoint,
                "severity": v.get("severity", "LOW").upper(),
                "cwe": v.get("cwe", v.get("cweid", "")),
                "tool": v.get("source", "http_scanner"),
                "description": v.get("description", ""),
            }
        )
    return findings


# ── Ground Truth Matcher ──────────────────────────────────────────────────────


def match_finding_to_gt(finding: dict, gt_entry: dict) -> float:
    """
    Calcula la probabilidad de que un hallazgo de herramienta coincida
    con una entrada del ground truth validado.

    Criterios:
      - Tipo de vulnerabilidad (normalizado): peso 0.50
      - Proximidad de ruta/endpoint: peso 0.50

    Returns:
        float [0, 1] — valores >= 0.40 se consideran True Positive
    """
    ft = normalize_type(finding["type"])
    gt = normalize_type(gt_entry["type"])

    # Similitud de tipo
    if ft == gt:
        type_score = 1.0
    elif ft in RELATED_TYPES.get(gt, set()) or gt in RELATED_TYPES.get(ft, set()):
        type_score = 0.60
    else:
        return 0.0  # tipos completamente distintos → no es TP

    # Similitud de ruta/endpoint
    # SAST: comparar file_path
    # DAST: comparar endpoint
    path_score = max(
        path_similarity(finding.get("file_path", ""), gt_entry.get("file_path", "")),
        path_similarity(finding.get("endpoint", ""), gt_entry.get("endpoint", "")),
    )

    score = type_score * 0.50 + path_score * 0.50
    return score


MATCH_THRESHOLD = 0.40  # score >= 0.40 → TP


def classify_findings(findings: List[dict], ground_truth: List[dict]) -> Tuple[List, List, List]:
    """
    Clasifica hallazgos en TP, FP, FN.

    Returns:
        (tp_list, fp_list, fn_list)
    """
    gt_matched = [False] * len(ground_truth)
    tp, fp = [], []

    for f in findings:
        best_score = 0.0
        best_gt_idx = -1
        for i, gt in enumerate(ground_truth):
            if gt_matched[i]:
                continue
            score = match_finding_to_gt(f, gt)
            if score > best_score:
                best_score = score
                best_gt_idx = i

        if best_score >= MATCH_THRESHOLD:
            tp.append({**f, "_gt_match": ground_truth[best_gt_idx], "_score": best_score})
            gt_matched[best_gt_idx] = True
        else:
            fp.append(f)

    fn = [gt for i, gt in enumerate(ground_truth) if not gt_matched[i]]
    return tp, fp, fn


def compute_metrics(tp, fp, fn) -> dict:
    """Calcula Precision, Recall, F1 a partir de listas TP/FP/FN."""
    n_tp = len(tp)
    n_fp = len(fp)
    n_fn = len(fn)
    precision = n_tp / (n_tp + n_fp) if (n_tp + n_fp) > 0 else 0.0
    recall = n_tp / (n_tp + n_fn) if (n_tp + n_fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "tp": n_tp,
        "fp": n_fp,
        "fn": n_fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


# ── Carga de resultados por app ───────────────────────────────────────────────


def best_result_file(app_key: str, tool_prefix: str) -> Optional[Path]:
    """Devuelve el resultado más reciente para un app + herramienta."""
    patterns = [
        f"{tool_prefix}*{app_key}*.json",
        f"{tool_prefix}_{app_key}_*.json",
    ]
    candidates = []
    for pat in patterns:
        candidates.extend(RES_DIR.glob(pat))
    # Más reciente primero
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


# Mapas de nombre de app → clave en archivos de resultado
APP_CONFIGS = {
    "OWASP Juice Shop": {
        "gt_file": GT_DIR / "juiceshop_ground_truth.json",
        "sast_key": "juice",  # semgrep_juice_shop_*.json
        "dast_key": "juiceshop",  # dast_http_juiceshop_*.json
        "sast_tool": "semgrep",
        "docker": "docker run -p 3000:3000 bkimminich/juice-shop",
    },
    "DVWA": {
        "gt_file": GT_DIR / "dvwa_ground_truth.json",
        "sast_key": "dvwa",
        "dast_key": "dvwa",
        "sast_tool": "semgrep",
        "docker": "docker run -p 8080:80 vulnerables/web-dvwa",
    },
    "NodeGoat": {
        "gt_file": GT_DIR / "nodegoat_ground_truth.json",
        "sast_key": "nodegoat",
        "dast_key": "nodegoat",
        "sast_tool": "semgrep",
        "docker": "docker run -p 4000:4000 owasp/nodegoat",
    },
    "OWASP WebGoat": {
        "gt_file": GT_DIR / "webgoat_ground_truth.json",
        "sast_key": "webgoat",
        "dast_key": "webgoat",
        "sast_tool": "bandit",
        "docker": "docker run -p 8888:8080 webgoat/goat-and-wolf",
    },
}


def load_app_results(app_name: str, cfg: dict) -> dict:
    """Carga SAST y DAST para una app, devuelve hallazgos normalizados."""
    gt = json.loads(cfg["gt_file"].read_text(encoding="utf-8"))["vulnerabilities"]

    # SAST
    sast_findings = []
    sast_file = best_result_file(cfg["sast_key"], "semgrep") or best_result_file(cfg["sast_key"], "sast_semgrep")
    if sast_file:
        sast_findings = parse_semgrep(sast_file)
    else:
        # Intentar con bandit
        sast_file = best_result_file(cfg["sast_key"], "sast_bandit") or best_result_file(cfg["sast_key"], "bandit")
        if sast_file:
            sast_findings = parse_bandit(sast_file)

    # DAST — combina pasivo (headers/config) + activo (injection probing) si existen
    dast_findings = []
    for dast_prefix in ("dast_active", "dast_http"):
        dast_file = best_result_file(cfg["dast_key"], dast_prefix)
        if dast_file:
            dast_findings.extend(parse_dast_http(dast_file))
    # Deduplicar por tipo+endpoint
    seen = set()
    dedup = []
    for f in dast_findings:
        key = (f["type"], f["endpoint"])
        if key not in seen:
            seen.add(key)
            dedup.append(f)
    dast_findings = dedup
    dast_file = dast_file if dast_findings else None

    return {
        "app": app_name,
        "ground_truth": gt,
        "sast_findings": sast_findings,
        "dast_findings": dast_findings,
        "sast_file": str(sast_file) if sast_file else None,
        "dast_file": str(dast_file) if dast_file else None,
    }


# ── Pruebas estadísticas ──────────────────────────────────────────────────────


def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def stdev(xs):
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def cohens_d(group_a: List[float], group_b: List[float]) -> float:
    """Cohen's d effect size between two groups."""
    if not group_a or not group_b:
        return 0.0
    pooled_std = math.sqrt((stdev(group_a) ** 2 + stdev(group_b) ** 2) / 2)
    return (mean(group_a) - mean(group_b)) / pooled_std if pooled_std > 0 else 0.0


def paired_t_test(before: List[float], after: List[float]) -> Tuple[float, float, float]:
    """
    Prueba t de Student emparejada (H1 unilateral: after > before).

    Returns:
        (t_statistic, p_one_tailed, p_two_tailed) — valores p exactos de la distribución t
    """
    if len(before) != len(after) or len(before) < 2:
        return 0.0, 1.0, 1.0
    if stdev([a - b for a, b in zip(after, before)]) == 0:
        return 0.0, 1.0, 1.0
    one = scipy_stats.ttest_rel(after, before, alternative="greater")
    two = scipy_stats.ttest_rel(after, before)
    return (
        round(float(one.statistic), 4),
        round(float(one.pvalue), 4),
        round(float(two.pvalue), 4),
    )


def confidence_interval_95(values: List[float]) -> Tuple[float, float]:
    """IC 95% via t-distribution (dos colas) para muestras pequeñas."""
    if len(values) < 2:
        return 0.0, 0.0
    n = len(values)
    m = mean(values)
    s = stdev(values)
    t_crit = scipy_stats.t.ppf(0.975, n - 1)
    margin = t_crit * s / math.sqrt(n)
    return round(m - margin, 4), round(m + margin, 4)


# ── Evaluación principal ──────────────────────────────────────────────────────


def run_evaluation() -> dict:
    """Ejecuta la evaluación completa y devuelve resultados estructurados."""
    results = {}
    f1_sast, f1_dast, f1_hybrid = [], [], []
    prec_sast, prec_dast, prec_hybrid = [], [], []
    rec_sast, rec_dast, rec_hybrid = [], [], []

    print("\n" + "=" * 70)
    print("  HybridSecScan — Evaluación Experimental a Escala")
    print("  Precision | Recall | F1-Score vs Ground Truth Validado")
    print("=" * 70)

    for app_name, cfg in APP_CONFIGS.items():
        print(f"\n{'─'*70}")
        print(f"  App: {app_name}")

        data = load_app_results(app_name, cfg)
        gt = data["ground_truth"]

        print(f"  Ground truth: {len(gt)} vulnerabilidades conocidas")
        print(f"  SAST file:   {Path(data['sast_file']).name if data['sast_file'] else 'NO ENCONTRADO'}")
        print(f"  DAST file:   {Path(data['dast_file']).name if data['dast_file'] else 'NO ENCONTRADO'}")
        print(f"  SAST hallazgos totales: {len(data['sast_findings'])}")
        if len(data["sast_findings"]) == 0 and data["sast_file"]:
            print("  NOTA: 0 hallazgos SAST — probable incompatibilidad de lenguaje")
            print("        (Bandit/Semgrep-Python no analizan Java/PHP correctamente)")
        print(f"  DAST hallazgos totales: {len(data['dast_findings'])}")

        # ── SAST ──
        sast_tp, sast_fp, sast_fn = classify_findings(data["sast_findings"], gt)
        sast_m = compute_metrics(sast_tp, sast_fp, sast_fn)
        print(
            f"\n  SAST  → P={sast_m['precision']:.3f}  R={sast_m['recall']:.3f}  F1={sast_m['f1']:.3f}"
            f"  (TP={sast_m['tp']} FP={sast_m['fp']} FN={sast_m['fn']})"
        )

        # ── DAST ──
        dast_tp, dast_fp, dast_fn = classify_findings(data["dast_findings"], gt)
        dast_m = compute_metrics(dast_tp, dast_fp, dast_fn)
        print(
            f"  DAST  → P={dast_m['precision']:.3f}  R={dast_m['recall']:.3f}  F1={dast_m['f1']:.3f}"
            f"  (TP={dast_m['tp']} FP={dast_m['fp']} FN={dast_m['fn']})"
        )

        # ── Hybrid (unión de hallazgos SAST + DAST) ──
        hybrid_findings = data["sast_findings"] + data["dast_findings"]
        hyb_tp, hyb_fp, hyb_fn = classify_findings(hybrid_findings, gt)
        hyb_m = compute_metrics(hyb_tp, hyb_fp, hyb_fn)
        print(
            f"  HYB   → P={hyb_m['precision']:.3f}  R={hyb_m['recall']:.3f}  F1={hyb_m['f1']:.3f}"
            f"  (TP={hyb_m['tp']} FP={hyb_m['fp']} FN={hyb_m['fn']})"
        )

        # Guardar para análisis estadístico
        f1_sast.append(sast_m["f1"])
        prec_sast.append(sast_m["precision"])
        rec_sast.append(sast_m["recall"])
        f1_dast.append(dast_m["f1"])
        prec_dast.append(dast_m["precision"])
        rec_dast.append(dast_m["recall"])
        f1_hybrid.append(hyb_m["f1"])
        prec_hybrid.append(hyb_m["precision"])
        rec_hybrid.append(hyb_m["recall"])

        # TP detectados por SAST que DAST también confirmó (correlaciones potenciales)
        sast_tp_types = {normalize_type(f["type"]) for f in sast_tp}
        dast_tp_types = {normalize_type(f["type"]) for f in dast_tp}
        shared = sast_tp_types & dast_tp_types
        print(f"  Tipos correlacionables (SAST∩DAST hits en GT): {shared or '∅'}")

        results[app_name] = {
            "ground_truth_n": len(gt),
            "sast": {"findings": len(data["sast_findings"]), **sast_m},
            "dast": {"findings": len(data["dast_findings"]), **dast_m},
            "hybrid": {"findings": len(hybrid_findings), **hyb_m},
            "correlatable_types": list(shared),
        }

    # ── Estadísticos globales ────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  ANÁLISIS ESTADÍSTICO (n =", len(f1_sast), "aplicaciones)")
    print("=" * 70)

    def row(label, vals, label_w=22):
        m = mean(vals)
        s = stdev(vals)
        lo, hi = confidence_interval_95(vals)
        return f"  {label:<{label_w}} media={m:.3f}  σ={s:.3f}  IC95%=[{lo:.3f},{hi:.3f}]  vals={[round(v,3) for v in vals]}"

    print("\n  F1-Score por método:")
    print(row("SAST", f1_sast))
    print(row("DAST", f1_dast))
    print(row("Hybrid", f1_hybrid))

    print("\n  Precision por método:")
    print(row("SAST", prec_sast))
    print(row("DAST", prec_dast))
    print(row("Hybrid", prec_hybrid))

    print("\n  Recall por método:")
    print(row("SAST", rec_sast))
    print(row("DAST", rec_dast))
    print(row("Hybrid", rec_hybrid))

    # ── Prueba t emparejada: Hybrid vs SAST ─────────────────────────────────
    t_hyb_sast, p_hyb_sast, p2_hyb_sast = paired_t_test(f1_sast, f1_hybrid)
    d_hyb_sast = cohens_d(f1_hybrid, f1_sast)

    t_hyb_dast, p_hyb_dast, p2_hyb_dast = paired_t_test(f1_dast, f1_hybrid)
    d_hyb_dast = cohens_d(f1_hybrid, f1_dast)

    t_rec_sast, p_rec_sast, p2_rec_sast = paired_t_test(rec_sast, rec_hybrid)

    def d_interpretation(d):
        return "pequeño" if abs(d) < 0.5 else ("mediano" if abs(d) < 0.8 else "grande")

    df = len(f1_sast) - 1
    print(f"\n  Prueba t emparejada (gl={df}; H₁ unilateral: Hybrid > método individual):")
    print(
        f"  F1     Hybrid vs SAST  → t={t_hyb_sast:+.3f}  p(unilat)={p_hyb_sast:.4f}  p(bilat)={p2_hyb_sast:.4f}"
        f"  Cohen's d={d_hyb_sast:+.3f} ({d_interpretation(d_hyb_sast)})"
    )
    print(
        f"  F1     Hybrid vs DAST  → t={t_hyb_dast:+.3f}  p(unilat)={p_hyb_dast:.4f}  p(bilat)={p2_hyb_dast:.4f}"
        f"  Cohen's d={d_hyb_dast:+.3f} ({d_interpretation(d_hyb_dast)})"
    )
    print(f"  Recall Hybrid vs SAST  → t={t_rec_sast:+.3f}  p(unilat)={p_rec_sast:.4f}  p(bilat)={p2_rec_sast:.4f}")

    sig_sast = "SÍ (p < 0.05)" if p_hyb_sast < 0.05 else "NO (p ≥ 0.05)"
    sig_dast = "SÍ (p < 0.05)" if p_hyb_dast < 0.05 else "NO (p ≥ 0.05)"
    print(f"\n  H₁ (Hybrid > SAST) estadísticamente significativa: {sig_sast}")
    print(f"  H₁ (Hybrid > DAST) estadísticamente significativa: {sig_dast}")

    # ── Tabla resumen para tesis ─────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  TABLA RESUMEN — Lista para Capítulo 5")
    print("=" * 70)
    print(f"\n  {'Método':<12}  {'Precision':>10}  {'Recall':>8}  {'F1-Score':>9}  {'IC95% F1':>18}")
    print(f"  {'─'*12}  {'─'*10}  {'─'*8}  {'─'*9}  {'─'*18}")

    for label, precs, recs, f1s in [
        ("SAST", prec_sast, rec_sast, f1_sast),
        ("DAST", prec_dast, rec_dast, f1_dast),
        ("Hybrid", prec_hybrid, rec_hybrid, f1_hybrid),
    ]:
        lo, hi = confidence_interval_95(f1s)
        print(f"  {label:<12}  {mean(precs):>10.3f}  {mean(recs):>8.3f}  {mean(f1s):>9.3f}  [{lo:.3f}, {hi:.3f}]")

    delta_f1 = mean(f1_hybrid) - mean(f1_sast)
    delta_rec = mean(rec_hybrid) - mean(rec_sast)
    print(f"\n  Mejora Hybrid vs SAST: ΔF1={delta_f1:+.3f}  ΔRecall={delta_rec:+.3f}")
    print(f"  Cohen's d (F1): {d_hyb_sast:.3f} — efecto {d_interpretation(d_hyb_sast)}")

    stats = {
        "n_apps": len(f1_sast),
        "sast": {
            "mean_f1": mean(f1_sast),
            "mean_precision": mean(prec_sast),
            "mean_recall": mean(rec_sast),
            "f1_values": f1_sast,
        },
        "dast": {
            "mean_f1": mean(f1_dast),
            "mean_precision": mean(prec_dast),
            "mean_recall": mean(rec_dast),
            "f1_values": f1_dast,
        },
        "hybrid": {
            "mean_f1": mean(f1_hybrid),
            "mean_precision": mean(prec_hybrid),
            "mean_recall": mean(rec_hybrid),
            "f1_values": f1_hybrid,
        },
        "statistical_tests": {
            "test": "paired t-test (scipy.stats.ttest_rel), H1: hybrid > baseline",
            "df": df,
            "hybrid_vs_sast": {
                "t": t_hyb_sast,
                "p_one_tailed": p_hyb_sast,
                "p_two_tailed": p2_hyb_sast,
                "cohens_d": d_hyb_sast,
                "significant": p_hyb_sast < 0.05,
            },
            "hybrid_vs_dast": {
                "t": t_hyb_dast,
                "p_one_tailed": p_hyb_dast,
                "p_two_tailed": p2_hyb_dast,
                "cohens_d": d_hyb_dast,
                "significant": p_hyb_dast < 0.05,
            },
            "recall_hybrid_vs_sast": {
                "t": t_rec_sast,
                "p_one_tailed": p_rec_sast,
                "p_two_tailed": p2_rec_sast,
                "significant": p_rec_sast < 0.05,
            },
        },
        "delta_f1_hybrid_vs_sast": round(delta_f1, 4),
        "delta_recall_hybrid_vs_sast": round(delta_rec, 4),
        "per_app": results,
    }
    return stats


# ── Entry point ───────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="HybridSecScan scale evaluation")
    parser.add_argument("--save", action="store_true", help="Save results to JSON")
    args = parser.parse_args()

    stats = run_evaluation()

    if args.save:
        from datetime import datetime

        out = OUTPUT_DIR / f"scale_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(stats, indent=2))
        print(f"\n  Resultados guardados: {out}")


if __name__ == "__main__":
    main()
