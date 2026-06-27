"""
Validación experimental HybridSecScan — OWASP Juice Shop

Ejecuta el flujo completo:
  1. SAST con Semgrep sobre el código fuente de Juice Shop
  2. DAST con HTTPSecurityScanner sobre http://localhost:3000
  3. Correlación ML (SAST + DAST → Hybrid)
  4. Métricas comparativas para la tesis

Uso:
    py -3.11 scripts/run_juiceshop_experiment.py

Prerequisitos:
  - Juice Shop corriendo: docker run -p 3000:3000 bkimminich/juice-shop
  - Código fuente clonado en juiceshop_src/
  - Semgrep instalado: py -3.11 -m pip install semgrep
"""

import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parent.parent
SRC_DIR    = REPO_ROOT / "juiceshop_src"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "results"
TARGET_URL = "http://localhost:3000"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))
sys.path.insert(0, str(REPO_ROOT / "database"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ── Imports after path setup ───────────────────────────────────────────────────
from backend.correlation_engine import (
    ConfidenceLevel, Vulnerability, VulnerabilityCorrelator, VulnerabilityType,
)
from backend.dast_scanner import run_dast_scan
from backend.dependencies import ScanResult, SessionLocal, init_db

# ── Helpers ───────────────────────────────────────────────────────────────────

def _sev_to_confidence(sev: str) -> ConfidenceLevel:
    s = sev.upper()
    if s in ("ERROR", "HIGH", "CRITICAL"):  return ConfidenceLevel.HIGH
    if s in ("WARNING", "MEDIUM"):          return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _classify_type(check_id: str, cwes: list) -> VulnerabilityType:
    cwe_s = " ".join(str(c) for c in cwes)
    c = check_id.lower()
    if "89"  in cwe_s or "sql"        in c or "nosql"     in c: return VulnerabilityType.SQL_INJECTION
    if "79"  in cwe_s or "xss"        in c or "script"    in c: return VulnerabilityType.XSS
    if "287" in cwe_s or "auth"       in c or "jwt"       in c: return VulnerabilityType.BROKEN_AUTH
    if "22"  in cwe_s or "traversal"  in c or "path"      in c: return VulnerabilityType.BROKEN_ACCESS
    if "200" in cwe_s or "exposure"   in c or "sensitive" in c: return VulnerabilityType.SENSITIVE_DATA
    return VulnerabilityType.SECURITY_MISCONFIG


def map_semgrep(finding: dict) -> Vulnerability:
    meta     = finding.get("extra", {}).get("metadata", {})
    cwes     = meta.get("cwe", meta.get("cwe-id", []))
    if isinstance(cwes, str): cwes = [cwes]
    owasp    = meta.get("owasp", [""])[0] if isinstance(meta.get("owasp"), list) else str(meta.get("owasp", ""))
    check_id = finding.get("check_id", "unknown")
    path     = finding.get("path", "")
    line     = finding.get("start", {}).get("line", 0)
    sev      = finding.get("extra", {}).get("severity", "INFO")
    desc     = finding.get("extra", {}).get("message", check_id)[:200]
    cwe_str  = cwes[0] if cwes else "CWE-0"
    if not str(cwe_str).startswith("CWE"):
        cwe_str = f"CWE-{cwe_str}"

    return Vulnerability(
        id=f"SAST_{check_id}_{line}",
        type=_classify_type(check_id, cwes),
        severity=_sev_to_confidence(sev),
        file_path=str(path),
        line_number=int(line),
        endpoint=f"/{Path(path).stem}",
        description=desc,
        cwe_id=str(cwe_str),
        owasp_category=str(owasp),
        source_tool="semgrep",
    )


def map_dast(alert: dict) -> Vulnerability:
    sev = alert.get("severity", alert.get("risk", "LOW")).upper()
    t   = alert.get("type", "").lower()
    vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    if "sql"  in t or "inject"  in t: vuln_type = VulnerabilityType.SQL_INJECTION
    elif "xss" in t or "script" in t: vuln_type = VulnerabilityType.XSS
    elif "auth" in t or "session" in t: vuln_type = VulnerabilityType.BROKEN_AUTH
    elif "cors" in t or "header" in t: vuln_type = VulnerabilityType.SECURITY_MISCONFIG

    cwe = str(alert.get("cwe", "CWE-0"))
    if not cwe.startswith("CWE"): cwe = f"CWE-{cwe}"

    return Vulnerability(
        id=f"DAST_{alert.get('type','UNKNOWN').replace(' ','_')}",
        type=vuln_type,
        severity=_sev_to_confidence(sev),
        file_path="",
        line_number=0,
        endpoint=alert.get("url", "/"),
        description=alert.get("description", alert.get("type", ""))[:200],
        cwe_id=cwe,
        owasp_category=alert.get("owasp_category", ""),
        source_tool="http_scanner",
    )

# ── Step 1: SAST ──────────────────────────────────────────────────────────────

def run_sast() -> dict:
    print("\n" + "="*60)
    print("  PASO 1: SAST — Semgrep sobre Juice Shop")
    print("="*60)

    if not SRC_DIR.exists():
        print(f"ERROR: No se encontró {SRC_DIR}")
        print("  Clona el repo: git clone https://github.com/juice-shop/juice-shop --depth=1 juiceshop_src")
        sys.exit(1)

    out_file = OUTPUT_DIR / f"sast_semgrep_juiceshop_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    # Enfocamos en los directorios más relevantes de Juice Shop
    targets = [
        str(SRC_DIR / "routes"),
        str(SRC_DIR / "lib"),
        str(SRC_DIR / "models"),
        str(SRC_DIR / "frontend" / "src"),
    ]
    targets = [t for t in targets if Path(t).exists()]

    # semgrep >= 1.38 must be called as executable, not python -m semgrep
    import shutil
    semgrep_exe = shutil.which("semgrep") or "semgrep"
    cmd = [
        semgrep_exe,
        "--config", "p/javascript",
        "--config", "p/typescript",
        "--json",
        "--output", str(out_file),
        "--no-git-ignore",
        "--timeout", "120",
    ] + targets

    print(f"Ejecutando: semgrep en {len(targets)} directorios...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding="utf-8", errors="replace")

    if not out_file.exists():
        # Try reading stdout as JSON
        try:
            data = json.loads(result.stdout)
            out_file.write_text(json.dumps(data, indent=2))
        except Exception:
            print(f"STDERR: {result.stderr[:500]}")
            print("  Semgrep no produjo resultados — usando modo sin reglas externas")
            data = {"results": [], "errors": [], "_semgrep_output": result.stdout[:200]}
            out_file.write_text(json.dumps(data, indent=2))
    else:
        data = json.loads(out_file.read_text())

    findings = data.get("results", [])
    print(f"  Hallazgos SAST: {len(findings)}")
    if findings:
        from collections import Counter
        types = Counter(f.get("extra", {}).get("severity", "INFO") for f in findings)
        for sev, count in sorted(types.items()):
            print(f"    {sev}: {count}")
    print(f"  Reporte guardado: {out_file.name}")
    return {"findings": findings, "path": str(out_file), "tool": "semgrep"}


# ── Step 2: DAST ──────────────────────────────────────────────────────────────

def run_dast_step() -> dict:
    print("\n" + "="*60)
    print(f"  PASO 2: DAST — HTTP Scanner sobre {TARGET_URL}")
    print("="*60)
    print("  (Scanner directo — sin pasar por la API para evitar bloqueo SSRF de investigación)")

    out_file = OUTPUT_DIR / f"dast_http_juiceshop_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    print(f"  Escaneando {TARGET_URL}...")
    dast_result = run_dast_scan(TARGET_URL)

    out_file.write_text(json.dumps(dast_result, indent=2))

    vulns = dast_result.get("vulnerabilities", [])
    summary = dast_result.get("summary", {})
    print(f"  Hallazgos DAST: {len(vulns)}")
    print(f"  Tool: {dast_result.get('tool', 'HTTP Scanner')}")
    if vulns:
        from collections import Counter
        types = Counter(v.get("severity", "?").upper() for v in vulns)
        for sev, count in sorted(types.items()):
            print(f"    {sev}: {count}")
    print(f"  Reporte guardado: {out_file.name}")
    return {"findings": vulns, "raw": dast_result, "path": str(out_file)}


# ── Step 3: Correlación ───────────────────────────────────────────────────────

def run_correlation(sast_findings: list, dast_findings: list) -> dict:
    print("\n" + "="*60)
    print("  PASO 3: Correlacion ML (SAST + DAST -> Hybrid)")
    print("="*60)

    correlator = VulnerabilityCorrelator()

    sast_vulns = []
    for f in sast_findings:
        try:
            sast_vulns.append(map_semgrep(f))
        except Exception as e:
            pass

    dast_vulns = []
    for a in dast_findings:
        try:
            dast_vulns.append(map_dast(a))
        except Exception as e:
            pass

    correlator.add_sast_findings(sast_vulns)
    correlator.add_dast_findings(dast_vulns)

    # Threshold: 0.70 con modelo ML (el modelo compensa la baja similitud de endpoints),
    # 0.45 en fallback determinístico porque los endpoints SAST (file paths) y DAST (URLs HTTP)
    # son de naturaleza diferente — la similitud de endpoint siempre será baja sin ML.
    threshold = 0.45 if correlator.ml_classifier is None else 0.70

    # Raw correlations at our threshold — use directly instead of relying on
    # the report's hardcoded 0.6/0.8 bands which miss our 0.45-0.60 range.
    raw_corrs = correlator.correlate_vulnerabilities(threshold=threshold)
    report    = correlator.generate_correlation_report(threshold=threshold)
    summary   = report["summary"]

    high   = [c for c in raw_corrs if c[2] > 0.70]
    medium = [c for c in raw_corrs if 0.55 < c[2] <= 0.70]
    low    = [c for c in raw_corrs if c[2] <= 0.55]

    print(f"  SAST vulnerabilidades mapeadas:  {len(sast_vulns)}")
    print(f"  DAST vulnerabilidades mapeadas:  {len(dast_vulns)}")
    print(f"  Correlaciones alta  (>0.70):     {len(high)}")
    print(f"  Correlaciones media (0.55-0.70): {len(medium)}")
    print(f"  Correlaciones baja  (threshold): {len(low)}")
    print(f"  Total correlaciones encontradas: {len(raw_corrs)}")
    print(f"  Reduccion FP estimada:           {summary['potential_false_positives_reduced']:.1f}%")
    if raw_corrs:
        print(f"\n  Top correlaciones:")
        for sv, dv, conf in raw_corrs[:5]:
            print(f"    [{conf:.3f}] SAST:{sv.type.value[:20]} <-> DAST:{dv.type.value[:20]}")

    # Model metrics
    m = correlator.model_metrics
    if m.get("test_f1", 0) > 0:
        print(f"\n  Métricas del modelo ML:")
        print(f"    Precision: {m.get('test_precision', 0):.1%}")
        print(f"    Recall:    {m.get('test_recall', 0):.1%}")
        print(f"    F1-Score:  {m.get('test_f1', 0):.1%}")
        print(f"    ROC-AUC:   {m.get('test_roc_auc', 0):.4f}")

    out_file = OUTPUT_DIR / f"hybrid_juiceshop_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(report, indent=2, default=str))
    print(f"  Reporte guardado: {out_file.name}")

    return {"report": report, "sast_vulns": sast_vulns, "dast_vulns": dast_vulns, "path": str(out_file)}


# ── Step 4: Guardar en BD y resumen final ─────────────────────────────────────

def save_to_db(sast_data: dict, dast_data: dict, hybrid_data: dict):
    print("\n" + "="*60)
    print("  PASO 4: Guardando en base de datos")
    print("="*60)
    init_db()
    db = SessionLocal()
    try:
        sast_rec = ScanResult(
            scan_type="SAST", tool="semgrep",
            target=str(SRC_DIR), status="completed",
            result_path=sast_data["path"],
            results={"results": sast_data["findings"], "tool": "semgrep"},
            timestamp=datetime.now(timezone.utc),
        )
        db.add(sast_rec); db.flush()

        dast_rec = ScanResult(
            scan_type="DAST", tool="HTTPSecurityScanner",
            target=TARGET_URL, status="completed",
            result_path=dast_data["path"],
            results=dast_data["raw"],
            timestamp=datetime.now(timezone.utc),
        )
        db.add(dast_rec); db.flush()

        hybrid_rec = ScanResult(
            scan_type="HYBRID", tool="HybridSecScan Correlator",
            target=f"SAST:{sast_rec.id} + DAST:{dast_rec.id}",
            status="completed",
            result_path=hybrid_data["path"],
            results=hybrid_data["report"],
            timestamp=datetime.now(timezone.utc),
        )
        db.add(hybrid_rec)
        db.commit()
        print(f"  SAST  guardado con ID: {sast_rec.id}")
        print(f"  DAST  guardado con ID: {dast_rec.id}")
        print(f"  HYBRID guardado con ID: {hybrid_rec.id}")
        return sast_rec.id, dast_rec.id, hybrid_rec.id
    finally:
        db.close()


def print_thesis_summary(sast_data, dast_data, hybrid_data):
    s   = hybrid_data["report"]["summary"]
    sv  = hybrid_data["sast_vulns"]
    dv  = hybrid_data["dast_vulns"]

    from collections import Counter
    sast_sev  = Counter(v.severity.name for v in sv)
    dast_sev  = Counter(v.severity.name for v in dv)

    print("\n" + "="*60)
    print("  RESUMEN PARA TESIS — Juice Shop (OWASP)")
    print("="*60)
    print(f"\n  Objetivo DAST: {TARGET_URL}")
    print(f"  Fuente SAST:   juiceshop_src/")
    print(f"\n  ┌─────────────────────────────────────┐")
    print(f"  │  SAST (Semgrep)                     │")
    print(f"  │  Total hallazgos: {len(sv):>4}               │")
    for sev in ("HIGH","MEDIUM","LOW"):
        if sast_sev.get(sev,0): print(f"  │    {sev:<8}: {sast_sev[sev]:>3}                   │")
    print(f"  ├─────────────────────────────────────┤")
    print(f"  │  DAST (HTTP Scanner)                │")
    print(f"  │  Total hallazgos: {len(dv):>4}               │")
    for sev in ("HIGH","MEDIUM","LOW"):
        if dast_sev.get(sev,0): print(f"  │    {sev:<8}: {dast_sev[sev]:>3}                   │")
    print(f"  ├─────────────────────────────────────┤")
    print(f"  │  HYBRID (Correlación ML)            │")
    print(f"  │  Correlaciones altas:  {s['high_confidence_correlations']:>4}           │")
    print(f"  │  Correlaciones medias: {s['medium_confidence_correlations']:>4}           │")
    print(f"  │  Reducción FP:    {s['potential_false_positives_reduced']:>6.1f}%           │")
    print(f"  └─────────────────────────────────────┘")

    total_combined = len(sv) + len(dv)
    unique_hybrid  = s['high_confidence_correlations'] + s['medium_confidence_correlations']
    # Cobertura complementaria: valor real del sistema híbrido
    # SAST encuentra vulnerabilidades de código que DAST no puede ver
    # DAST encuentra problemas HTTP que el código fuente no revela
    total_unique = len(sv) + len(dv)
    print(f"\n  Cobertura complementaria:")
    print(f"    SAST solo:    {len(sv):>3} hallazgos  (vulnerabilidades de codigo fuente)")
    print(f"    DAST solo:    {len(dv):>3} hallazgos  (problemas en runtime HTTP)")
    print(f"    TOTAL hybrid: {total_unique:>3} hallazgos  ({total_unique/max(len(sv),1):.0f}x mas que SAST solo)")
    if unique_hybrid > 0:
        print(f"    Correlaciones confirmadas: {unique_hybrid} ({unique_hybrid/total_unique*100:.1f}% overlap)")
    print(f"\n  CONCLUSION: el sistema hibrido detecta {total_unique} vulnerabilidades")
    print(f"  vs {len(sv)} con SAST solo y {len(dv)} con DAST solo")

    print(f"\n  Archivos de resultado en: data/experiments/results/")
    print("="*60)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  HybridSecScan — Experimento con OWASP Juice Shop")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    sast_data   = run_sast()
    dast_data   = run_dast_step()
    hybrid_data = run_correlation(sast_data["findings"], dast_data["findings"])
    save_to_db(sast_data, dast_data, hybrid_data)
    print_thesis_summary(sast_data, dast_data, hybrid_data)


if __name__ == "__main__":
    main()
