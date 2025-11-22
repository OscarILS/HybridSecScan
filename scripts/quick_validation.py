"""
Validación Experimental RÁPIDA - HybridSecScan
==============================================

Versión optimizada para ejecución rápida con análisis enfocado.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
import logging

# Configurar PATH para Semgrep
scripts_path = os.path.expandvars(r"$LOCALAPPDATA\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts")
if os.path.exists(scripts_path):
    os.environ["PATH"] = f"{os.environ['PATH']};{scripts_path}"

# Directorios
BASE_DIR = Path(__file__).parent.parent
TEST_APPS_DIR = BASE_DIR / "data" / "experiments" / "test_apps"
RESULTS_DIR = BASE_DIR / "data" / "experiments" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Logging simple
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Aplicaciones a analizar (solo las más relevantes)
APPS = {
    "DVWA": {
        "path": TEST_APPS_DIR / "dvwa",
        "language": "PHP",
        "scan_paths": ["vulnerabilities", "includes"],
        "ground_truth_vulns": 5
    },
    "NodeGoat": {
        "path": TEST_APPS_DIR / "nodegoat",
        "language": "JavaScript",
        "scan_paths": ["app", "routes", "config"],
        "ground_truth_vulns": 5
    },
    "Juice Shop": {
        "path": TEST_APPS_DIR / "juice-shop",
        "language": "TypeScript",
        "scan_paths": ["routes", "lib", "models"],
        "ground_truth_vulns": 5
    }
}

def run_bandit_scan(app_name: str, app_path: Path):
    """Ejecuta Bandit (Python SAST)"""
    logger.info(f"\n[BANDIT] Analizando {app_name}...")
    
    report_path = RESULTS_DIR / f"bandit_{app_name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        result = subprocess.run(
            ['python', '-m', 'bandit', '-r', str(app_path), '-f', 'json', '-o', str(report_path)],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if report_path.exists():
            with open(report_path, 'r') as f:
                data = json.load(f)
                findings = data.get("results", [])
                logger.info(f"  ✓ Encontrados: {len(findings)} hallazgos")
                return len(findings)
        else:
            logger.info(f"  ✓ Sin hallazgos")
            return 0
            
    except subprocess.TimeoutExpired:
        logger.warning(f"  ! Timeout en Bandit")
        return 0
    except Exception as e:
        logger.warning(f"  ! Error: {str(e)}")
        return 0

def run_semgrep_scan(app_name: str, app_path: Path, language: str):
    """Ejecuta Semgrep (Multi-lenguaje SAST)"""
    logger.info(f"[SEMGREP] Analizando {app_name} ({language})...")
    
    report_path = RESULTS_DIR / f"semgrep_{app_name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    # Configuración específica por lenguaje
    config_rules = {
        "PHP": "p/php",
        "JavaScript": "p/javascript",
        "TypeScript": "p/typescript",
        "Java": "p/java"
    }
    
    config = config_rules.get(language, "p/security-audit")
    
    try:
        cmd = [
            'semgrep',
            '--config', config,
            '--json',
            '--output', str(report_path),
            '--timeout', '120',
            '--max-memory', '4096',
            '--metrics', 'off',
            str(app_path)
        ]
        
        logger.info(f"  Ejecutando: semgrep --config {config} {app_path.name}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        
        if report_path.exists():
            with open(report_path, 'r') as f:
                data = json.load(f)
                findings = data.get("results", [])
                logger.info(f"  ✓ Encontrados: {len(findings)} hallazgos")
                
                # Mostrar algunos hallazgos
                for finding in findings[:3]:
                    check_id = finding.get("check_id", "unknown")
                    path = finding.get("path", "")
                    logger.info(f"    - {check_id} en {Path(path).name}")
                
                if len(findings) > 3:
                    logger.info(f"    ... y {len(findings) - 3} más")
                
                return len(findings)
        else:
            logger.info(f"  ✓ Sin hallazgos")
            return 0
            
    except subprocess.TimeoutExpired:
        logger.warning(f"  ! Timeout en Semgrep")
        return 0
    except Exception as e:
        logger.warning(f"  ! Error: {str(e)}")
        if "stderr" in str(e):
            logger.debug(f"  stderr: {result.stderr[:200]}")
        return 0

def main():
    logger.info("""
╔═══════════════════════════════════════════════════════════╗
║  VALIDACIÓN EXPERIMENTAL RÁPIDA - HybridSecScan          ║
║  Versión Optimizada                                       ║
╚═══════════════════════════════════════════════════════════╝
""")
    
    # Verificar herramientas
    logger.info("[1/3] Verificando herramientas...")
    try:
        semgrep_ver = subprocess.run(['semgrep', '--version'], capture_output=True, text=True, timeout=5)
        logger.info(f"  ✓ Semgrep: {semgrep_ver.stdout.strip()}")
    except:
        logger.error("  ✗ Semgrep no disponible")
        return 1
    
    try:
        bandit_ver = subprocess.run(['python', '-m', 'bandit', '--version'], capture_output=True, text=True, timeout=5)
        logger.info(f"  ✓ Bandit instalado")
    except:
        logger.warning("  ! Bandit no disponible")
    
    # Analizar aplicaciones
    logger.info(f"\n[2/3] Analizando {len(APPS)} aplicaciones...")
    
    total_bandit = 0
    total_semgrep = 0
    
    for app_name, config in APPS.items():
        app_path = config["path"]
        
        if not app_path.exists():
            logger.warning(f"\n✗ {app_name}: No encontrado en {app_path}")
            continue
        
        logger.info(f"\n{'='*60}")
        logger.info(f"📦 {app_name} ({config['language']})")
        logger.info(f"{'='*60}")
        
        # Bandit
        bandit_findings = run_bandit_scan(app_name, app_path)
        total_bandit += bandit_findings
        
        # Semgrep
        semgrep_findings = run_semgrep_scan(app_name, app_path, config['language'])
        total_semgrep += semgrep_findings
        
        logger.info(f"\n  Ground Truth: {config['ground_truth_vulns']} vulnerabilidades")
        logger.info(f"  Total Hallazgos: {bandit_findings + semgrep_findings}")
    
    # Resumen
    logger.info(f"\n[3/3] Resumen de Análisis")
    logger.info(f"{'='*60}")
    logger.info(f"  Total Bandit:  {total_bandit} hallazgos")
    logger.info(f"  Total Semgrep: {total_semgrep} hallazgos")
    logger.info(f"  TOTAL SAST:    {total_bandit + total_semgrep} hallazgos")
    logger.info(f"\n  Archivos generados en: {RESULTS_DIR}")
    logger.info(f"{'='*60}")
    logger.info("\n✓ Análisis completado\n")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
