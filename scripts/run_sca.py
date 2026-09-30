"""
Software Composition Analysis (SCA) — verifica CVEs en dependencias Python.

Usa pip-audit para detectar paquetes con vulnerabilidades conocidas en el
requirements.txt del proyecto. Complementa el análisis SAST (código propio)
con análisis de código de terceros (librerías).

Uso:
    py -3.11 scripts/run_sca.py
    py -3.11 scripts/run_sca.py --json   # salida JSON

Cubre OWASP API10:2023 — Unsafe Consumption of APIs (dependencias inseguras).
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQ_FILE = REPO_ROOT / "requirements.txt"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_sca(as_json: bool = False) -> dict:
    print("\n" + "=" * 60)
    print("  HybridSecScan — SCA (Software Composition Analysis)")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Verificar pip-audit
    check = subprocess.run(
        [sys.executable, "-m", "pip_audit", "--version"],
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        print("\n  pip-audit no instalado. Instalando...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pip-audit", "--quiet"],
            check=True,
        )

    print(f"\n  Analizando: {REQ_FILE.relative_to(REPO_ROOT)}")
    print("  Consultando base de datos de vulnerabilidades (PyPI Advisory)...\n")

    # Ejecutar pip-audit
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            str(REQ_FILE),
            "--format",
            "json",
            "--progress-spinner",
            "off",
        ],
        capture_output=True,
        text=True,
    )

    # pip-audit devuelve código != 0 si encuentra vulnerabilidades
    output = result.stdout or result.stderr
    try:
        audit_data = json.loads(output)
    except json.JSONDecodeError:
        print(f"  ERROR parseando salida de pip-audit:\n{output[:500]}")
        return {"error": output, "vulnerabilities": [], "dependencies": []}

    vulns = audit_data.get("vulnerabilities", [])
    deps = audit_data.get("dependencies", [])
    vuln_count = len(vulns)

    # ── Resumen ───────────────────────────────────────────────────────────────
    if vuln_count == 0:
        print("  RESULTADO: Sin vulnerabilidades conocidas en dependencias.")
    else:
        print(f"  RESULTADO: {vuln_count} vulnerabilidad(es) encontrada(s):\n")
        for v in vulns:
            print(f"  [{v.get('id','?')}]  {v.get('package','?')} {v.get('installed_version','?')}")
            print(f"    Fix disponible: {v.get('fix_versions', 'No disponible')}")
            print(f"    {v.get('description','')[:120]}")
            print()

    print(f"  Dependencias analizadas: {len(deps)}")
    print(f"  Con CVEs conocidos:      {vuln_count}")
    print("  Cobertura OWASP:         API10:2023 (Unsafe Consumption of APIs)")

    # ── Guardar resultado ─────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = OUTPUT_DIR / f"sca_pip_audit_{ts}.json"
    report = {
        "scan_type": "SCA",
        "tool": "pip-audit",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": str(REQ_FILE),
        "owasp": "API10:2023",
        "dependencies_total": len(deps),
        "vulnerabilities_found": vuln_count,
        "vulnerabilities": vulns,
        "dependencies": deps,
    }
    out_file.write_text(json.dumps(report, indent=2))
    print(f"\n  Reporte guardado: {out_file.name}")

    if as_json:
        print(json.dumps(report, indent=2))

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HybridSecScan SCA")
    parser.add_argument("--json", action="store_true", help="Print full JSON output")
    args = parser.parse_args()
    run_sca(as_json=args.json)
