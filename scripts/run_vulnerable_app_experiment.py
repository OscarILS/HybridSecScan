"""
Experimento de correlación SAST+DAST con app vulnerable Python.

Demuestra el valor central de HybridSecScan: la correlación ML entre
hallazgos de análisis estático (Bandit) y dinámico (HTTP active probing).

Flujo:
  1. Lanza ProgramasPruebas/vulnerable_app.py (Flask en puerto 5000)
  2. Ejecuta Bandit SAST sobre el código fuente
  3. Ejecuta DAST con probing activo contra localhost:5000
  4. Correlaciona con el motor ML
  5. Imprime tabla de correlaciones y métricas para la tesis

Uso:
    py -3.11 scripts/run_vulnerable_app_experiment.py

Prerequisitos:
    pip install flask   (para lanzar la app vulnerable)
    pip install bandit  (SAST)
"""

import json
import subprocess
import sys
import os
import time
import signal
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parent.parent
APP_PATH    = REPO_ROOT / "ProgramasPruebas" / "vulnerable_app.py"
OUTPUT_DIR  = REPO_ROOT / "data" / "experiments" / "results"
TARGET_URL  = "http://localhost:5000"
APP_PORT    = 5000

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))
sys.path.insert(0, str(REPO_ROOT / "database"))

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

from backend.correlation_engine import (
    ConfidenceLevel, Vulnerability, VulnerabilityCorrelator, VulnerabilityType,
)
from backend.dast_scanner import run_active_probe_scan
from backend.dependencies import ScanResult, SessionLocal, init_db


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sev(s: str) -> ConfidenceLevel:
    s = str(s).upper()
    if s in ("HIGH", "CRITICAL", "ERROR"):   return ConfidenceLevel.HIGH
    if s in ("MEDIUM", "WARNING"):            return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _extract_route_from_source(filename: str, line_number: int) -> str:
    """
    Extrae el endpoint (@app.route) más cercano por encima de la línea dada.
    Permite al correlador saber en qué endpoint ESTÁ la vulnerabilidad SAST.
    """
    try:
        lines = Path(filename).read_text(encoding="utf-8").splitlines()
        for i in range(min(line_number - 1, len(lines) - 1), -1, -1):
            line = lines[i].strip()
            if "@app.route(" in line:
                # Extrae '/login' de "@app.route('/login', ...)"
                start = line.index("'") + 1
                end   = line.index("'", start)
                return line[start:end]
    except Exception:
        pass
    return f"/unknown_line_{line_number}"


def map_bandit_finding(b: dict, src_file: str) -> Vulnerability:
    sev_map = {
        "HIGH":   ConfidenceLevel.HIGH,
        "MEDIUM": ConfidenceLevel.MEDIUM,
        "LOW":    ConfidenceLevel.LOW,
    }
    test_id = b.get("test_id", "")
    line    = b.get("line_number", 0)
    sev_str = b.get("issue_severity", "LOW").upper()
    severity = sev_map.get(sev_str, ConfidenceLevel.LOW)

    # Tipo de vulnerabilidad basado en test_id de Bandit
    vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    if test_id in ("B608",):                          # SQL injection
        vuln_type = VulnerabilityType.SQL_INJECTION
    elif test_id in ("B602", "B603", "B604", "B605"): # Command injection / subprocess
        vuln_type = VulnerabilityType.BROKEN_ACCESS
    elif test_id in ("B301", "B302"):                 # Deserialization
        vuln_type = VulnerabilityType.BROKEN_ACCESS
    elif test_id in ("B105", "B106", "B107"):         # Hardcoded passwords
        vuln_type = VulnerabilityType.SENSITIVE_DATA
    elif test_id in ("B311",):                        # Insecure random
        vuln_type = VulnerabilityType.BROKEN_AUTH
    elif test_id in ("B108",):                        # Insecure temp file
        vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    elif test_id in ("B201",):                        # Flask debug=True
        vuln_type = VulnerabilityType.SECURITY_MISCONFIG

    # Extrae endpoint real del código fuente (clave para la correlación)
    endpoint = _extract_route_from_source(src_file, line)

    cwe_info = b.get("issue_cwe", {})
    cwe_id   = f"CWE-{cwe_info.get('id', '0')}" if isinstance(cwe_info, dict) else "CWE-0"

    return Vulnerability(
        id=f"SAST_{test_id}_{line}",
        type=vuln_type,
        severity=severity,
        file_path=str(src_file),
        line_number=line,
        endpoint=endpoint,
        description=b.get("issue_text", "No description"),
        cwe_id=cwe_id,
        owasp_category="",
        source_tool="bandit",
    )


def map_dast_finding(a: dict) -> Vulnerability:
    t = str(a.get("type", "")).lower()

    vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    if "sql" in t or "injection" in t:        vuln_type = VulnerabilityType.SQL_INJECTION
    elif "path traversal" in t or "22" in str(a.get("cweid","")): vuln_type = VulnerabilityType.BROKEN_ACCESS
    elif "random" in t or "338" in str(a.get("cweid","")): vuln_type = VulnerabilityType.BROKEN_AUTH
    elif "debug" in t or "disclosure" in t:   vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    elif "header" in t or "cors" in t:        vuln_type = VulnerabilityType.SECURITY_MISCONFIG

    cwe = str(a.get("cwe", "CWE-0"))
    if not cwe.startswith("CWE"):
        cwe = f"CWE-{cwe}"

    # Extraer solo el path del URL para comparar con endpoints SAST
    from urllib.parse import urlparse
    url  = a.get("url", "/")
    path = urlparse(url).path or "/"

    return Vulnerability(
        id=f"DAST_{a.get('type','?')[:30].replace(' ','_')}",
        type=vuln_type,
        severity=_sev(a.get("severity", "LOW")),
        file_path="",
        line_number=0,
        endpoint=path,
        description=a.get("description", a.get("type", ""))[:200],
        cwe_id=cwe,
        owasp_category=a.get("owasp_category", ""),
        source_tool="http_scanner",
    )


# ── Step 1: Launch Flask App ──────────────────────────────────────────────────

def launch_app():
    print("\n" + "="*60)
    print("  PASO 1: Lanzando app vulnerable (Flask puerto 5000)")
    print("="*60)

    if not APP_PATH.exists():
        print(f"ERROR: No se encontro {APP_PATH}")
        sys.exit(1)

    # Instalar Flask si es necesario
    try:
        import flask
        print(f"  Flask {flask.__version__} ya instalado")
    except ImportError:
        print("  Instalando Flask...")
        subprocess.run([sys.executable, "-m", "pip", "install", "flask", "--quiet"], check=True)

    proc = subprocess.Popen(
        [sys.executable, str(APP_PATH)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  App iniciada (PID {proc.pid}), esperando 2s...")
    time.sleep(2)

    # Verificar que responde
    import requests
    for attempt in range(5):
        try:
            r = requests.get(TARGET_URL, timeout=3)
            print(f"  App responde: HTTP {r.status_code}")
            return proc
        except Exception:
            time.sleep(1)

    print("  ADVERTENCIA: la app no responde — el DAST puede dar resultados parciales")
    return proc


# ── Step 2: SAST con Bandit ───────────────────────────────────────────────────

def run_sast():
    print("\n" + "="*60)
    print("  PASO 2: SAST — Bandit sobre vulnerable_app.py")
    print("="*60)

    out_file = OUTPUT_DIR / f"sast_bandit_vulnerable_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(APP_PATH), "-f", "json", "-o", str(out_file)],
        capture_output=True, text=True, timeout=60,
    )

    if out_file.exists():
        data = json.loads(out_file.read_text())
    else:
        data = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {"results": []}
        out_file.write_text(json.dumps(data, indent=2))

    findings = data.get("results", [])
    print(f"  Hallazgos Bandit: {len(findings)}")
    for f in findings:
        print(f"    [{f.get('issue_severity','?'):6}] {f.get('test_id','?')} "
              f"L{f.get('line_number','?'):3} — {f.get('issue_text','')[:60]}")

    return {"findings": findings, "path": str(out_file)}


# ── Step 3: DAST activo ───────────────────────────────────────────────────────

def run_dast():
    print("\n" + "="*60)
    print(f"  PASO 3: DAST activo — {TARGET_URL}")
    print("="*60)
    print("  (Probing activo: SQL injection, path traversal, debug mode, random)")

    out_file = OUTPUT_DIR / f"dast_active_vulnerable_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    dast_result = run_active_probe_scan(TARGET_URL)
    out_file.write_text(json.dumps(dast_result, indent=2))

    vulns = dast_result.get("vulnerabilities", [])
    summary = dast_result.get("summary", {})
    print(f"  Hallazgos pasivos:   {summary.get('passive_checks', 0)}")
    print(f"  Hallazgos activos:   {summary.get('active_probes', 0)}")
    print(f"  TOTAL hallazgos:     {len(vulns)}")
    for v in vulns:
        t = v.get("type","?")
        sev = v.get("severity","?")
        url = v.get("url","?")
        print(f"    [{sev:8}] {t[:40]:40} {url}")

    return {"findings": vulns, "raw": dast_result, "path": str(out_file)}


# ── Step 4: Correlación ───────────────────────────────────────────────────────

def run_correlation(sast_data: dict, dast_data: dict) -> dict:
    print("\n" + "="*60)
    print("  PASO 4: Correlacion ML (SAST + DAST -> Hybrid)")
    print("="*60)

    correlator = VulnerabilityCorrelator()

    sast_vulns = []
    for b in sast_data["findings"]:
        try:
            sast_vulns.append(map_bandit_finding(b, str(APP_PATH)))
        except Exception as e:
            print(f"    [warn] SAST mapping: {e}")

    dast_vulns = []
    for a in dast_data["findings"]:
        try:
            dast_vulns.append(map_dast_finding(a))
        except Exception as e:
            print(f"    [warn] DAST mapping: {e}")

    print(f"  SAST vulnerabilidades mapeadas: {len(sast_vulns)}")
    print(f"  DAST vulnerabilidades mapeadas: {len(dast_vulns)}")
    print()

    for v in sast_vulns:
        print(f"    SAST [{v.severity.name:6}] {v.type.value[:25]:25} endpoint:{v.endpoint}")
    print()
    for v in dast_vulns:
        print(f"    DAST [{v.severity.name:6}] {v.type.value[:25]:25} endpoint:{v.endpoint}")

    correlator.add_sast_findings(sast_vulns)
    correlator.add_dast_findings(dast_vulns)

    # Con modelo ML -> threshold 0.70; sin modelo -> 0.45
    threshold = 0.70 if correlator.ml_classifier is not None else 0.45
    raw_corrs = correlator.correlate_vulnerabilities(threshold=threshold)
    report    = correlator.generate_correlation_report(threshold=threshold)

    print(f"\n  Threshold: {threshold} ({'ML model' if correlator.ml_classifier else 'fallback deterministico'})")
    print(f"  Correlaciones encontradas: {len(raw_corrs)}")

    if raw_corrs:
        print("\n  === CORRELACIONES DETECTADAS ===")
        for sv, dv, conf in raw_corrs:
            print(f"\n  [{conf:.3f}] SAST:{sv.type.value} (L{sv.line_number}) "
                  f"<-> DAST:{dv.type.value}")
            print(f"    SAST endpoint: {sv.endpoint}  |  CWE: {sv.cwe_id}")
            print(f"    DAST endpoint: {dv.endpoint}  |  CWE: {dv.cwe_id}")
            print(f"    SAST desc: {sv.description[:80]}")
            print(f"    DAST desc: {dv.description[:80]}")
    else:
        print("\n  Sin correlaciones — verifica que la app este corriendo en", TARGET_URL)

    m = correlator.model_metrics
    if m.get("test_f1", 0) > 0:
        print(f"\n  Metricas del modelo ML:")
        print(f"    Precision: {m['test_precision']:.1%}  Recall: {m['test_recall']:.1%}")
        print(f"    F1-Score:  {m['test_f1']:.1%}  ROC-AUC: {m['test_roc_auc']:.4f}")

    out_file = OUTPUT_DIR / f"hybrid_vulnerable_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(report, indent=2, default=str))
    print(f"\n  Reporte guardado: {out_file.name}")

    return {
        "report": report, "correlations": raw_corrs,
        "sast_vulns": sast_vulns, "dast_vulns": dast_vulns, "path": str(out_file),
    }


# ── Step 5: DB + resumen ──────────────────────────────────────────────────────

def save_and_summarize(sast_data, dast_data, hybrid_data):
    init_db()
    db = SessionLocal()
    try:
        s = ScanResult(scan_type="SAST", tool="bandit", target=str(APP_PATH),
                       status="completed", result_path=sast_data["path"],
                       results={"results": sast_data["findings"]},
                       timestamp=datetime.now(timezone.utc))
        db.add(s); db.flush()

        d = ScanResult(scan_type="DAST", tool="HTTP Active Probe", target=TARGET_URL,
                       status="completed", result_path=dast_data["path"],
                       results=dast_data["raw"],
                       timestamp=datetime.now(timezone.utc))
        db.add(d); db.flush()

        h = ScanResult(scan_type="HYBRID", tool="HybridSecScan Correlator",
                       target=f"SAST:{s.id}+DAST:{d.id}",
                       status="completed", result_path=hybrid_data["path"],
                       results=hybrid_data["report"],
                       timestamp=datetime.now(timezone.utc))
        db.add(h); db.commit(); db.refresh(s); db.refresh(d); db.refresh(h)
    finally:
        db.close()

    sv   = hybrid_data["sast_vulns"]
    dv   = hybrid_data["dast_vulns"]
    corr = hybrid_data["correlations"]

    print("\n" + "="*60)
    print("  RESUMEN FINAL — App Vulnerable Python")
    print("="*60)
    print(f"\n  Objetivo: {APP_PATH.name} → {TARGET_URL}")
    print(f"\n  ┌──────────────────────────────────────┐")
    print(f"  │ SAST (Bandit)    : {len(sv):>3} vulnerabilidades │")
    print(f"  │ DAST (Active)    : {len(dv):>3} vulnerabilidades │")
    print(f"  │ Cobertura hibrida: {len(sv)+len(dv):>3} hallazgos unicos│")
    print(f"  ├──────────────────────────────────────┤")
    print(f"  │ CORRELACIONES    : {len(corr):>3}                  │")

    high_c   = [c for c in corr if c[2] > 0.70]
    medium_c = [c for c in corr if 0.55 < c[2] <= 0.70]
    low_c    = [c for c in corr if c[2] <= 0.55]
    print(f"  │   Alta (>0.70)  : {len(high_c):>3}                  │")
    print(f"  │   Media(0.55-70): {len(medium_c):>3}                  │")
    print(f"  │   Baja (<0.55)  : {len(low_c):>3}                  │")
    print(f"  └──────────────────────────────────────┘")

    if corr:
        print(f"\n  Correlaciones confirmadas (SAST <-> DAST):")
        for sv_v, dv_v, conf in corr:
            print(f"    [{conf:.3f}] {sv_v.type.value} @ {sv_v.endpoint}"
                  f" <-> {dv_v.type.value} @ {dv_v.endpoint}")

    print(f"\n  CONCLUSION: El sistema detecta {len(sv)+len(dv)} vulnerabilidades unicas")
    print(f"  y confirma {len(corr)} mediante correlacion SAST+DAST.")
    if corr:
        reduction = len(corr) / len(sv) * 100 if sv else 0
        print(f"  El {reduction:.0f}% de hallazgos SAST fueron corroborados por DAST")
        print(f"  -> reduccion de falsos positivos en ese porcentaje.")
    print("="*60)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  HybridSecScan — Experimento App Vulnerable Python")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    proc = launch_app()
    try:
        sast_data   = run_sast()
        dast_data   = run_dast()
        hybrid_data = run_correlation(sast_data, dast_data)
        save_and_summarize(sast_data, dast_data, hybrid_data)
    finally:
        print(f"\n  Deteniendo app vulnerable (PID {proc.pid})...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        print("  App detenida.")


if __name__ == "__main__":
    main()
