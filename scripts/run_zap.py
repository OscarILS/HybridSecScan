# Script para ejecutar OWASP ZAP (DAST)
import subprocess
import sys
import uuid
import json
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Any


def run_zap(target_url: str) -> Dict[str, Any]:
    """
    Ejecuta análisis OWASP ZAP con manejo mejorado de errores y parsing de resultados.
    
    Args:
        target_url: URL del API a analizar
        
    Returns:
        Diccionario con resultados parseados y metadata
    """
    # Validate URL
    parsed_url = urlparse(target_url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        return {
            "success": False,
            "error": "URL inválida. Debe incluir esquema (http:// o https://)",
            "vulnerabilities": []
        }
    
    # Generate unique report filename
    report_id = str(uuid.uuid4())
    base_dir = Path(__file__).parent.parent
    reports_dir = base_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    json_report_path = reports_dir / f"zap_report_{report_id}.json"
    html_report_path = reports_dir / f"zap_report_{report_id}.html"
    
    try:
        # Run ZAP with JSON output for parsing
        result = subprocess.run([
            'zap-cli', 'quick-scan', '--self-contained', 
            '--start-options', '-config api.disablekey=true',
            '-f', 'json',
            '--output', str(json_report_path),
            target_url
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            # Parse JSON results
            vulnerabilities = parse_zap_results(json_report_path)
            
            return {
                "success": True,
                "report_path": str(json_report_path),
                "html_report_path": str(html_report_path),
                "target_url": target_url,
                "vulnerabilities": vulnerabilities,
                "total_vulnerabilities": len(vulnerabilities),
                "severity_summary": _calculate_severity_summary(vulnerabilities)
            }
        else:
            return {
                "success": False,
                "error": f"ZAP analysis failed: {result.stderr}",
                "vulnerabilities": []
            }
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "ZAP analysis timed out after 10 minutes",
            "vulnerabilities": []
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "zap-cli not found. Please install OWASP ZAP and zap-cli",
            "vulnerabilities": []
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error running OWASP ZAP: {str(e)}",
            "vulnerabilities": []
        }


def parse_zap_results(json_path: Path) -> List[Dict[str, Any]]:
    """
    Parsea resultados JSON de ZAP a formato estructurado.
    
    Args:
        json_path: Ruta al archivo JSON de ZAP
        
    Returns:
        Lista de vulnerabilidades parseadas
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            zap_data = json.load(f)
        
        vulnerabilities = []
        
        # ZAP structure: site -> alerts
        if isinstance(zap_data, dict) and 'site' in zap_data:
            sites = zap_data['site'] if isinstance(zap_data['site'], list) else [zap_data['site']]
            
            for site in sites:
                alerts = site.get('alerts', [])
                
                for alert in alerts:
                    vuln = {
                        "id": str(uuid.uuid4()),
                        "type": _map_zap_alert_to_type(alert.get('name', 'Unknown')),
                        "severity": _map_zap_risk_level(alert.get('riskdesc', 'Low')),
                        "name": alert.get('name', 'Unknown'),
                        "description": alert.get('desc', ''),
                        "solution": alert.get('solution', ''),
                        "reference": alert.get('reference', ''),
                        "cwe_id": alert.get('cweid', ''),
                        "wasc_id": alert.get('wascid', ''),
                        "url": alert.get('url', ''),
                        "method": alert.get('method', 'GET'),
                        "evidence": alert.get('evidence', ''),
                        "confidence": _map_zap_confidence(alert.get('confidence', 'Medium')),
                        "source_tool": "OWASP ZAP",
                        "owasp_category": _map_to_owasp_api_top10(alert.get('name', ''))
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
        
    except Exception as e:
        print(f"Error parsing ZAP results: {e}")
        return []


def _map_zap_risk_level(risk_desc: str) -> str:
    """Mapea nivel de riesgo de ZAP a severidad estándar."""
    risk_lower = risk_desc.lower()
    if 'high' in risk_lower or 'critical' in risk_lower:
        return "CRITICAL"
    elif 'medium' in risk_lower:
        return "HIGH"
    elif 'low' in risk_lower:
        return "MEDIUM"
    else:
        return "LOW"


def _map_zap_confidence(confidence: str) -> str:
    """Mapea confianza de ZAP a nivel estándar."""
    conf_lower = confidence.lower()
    if 'high' in conf_lower or 'confirmed' in conf_lower:
        return "HIGH"
    elif 'medium' in conf_lower:
        return "MEDIUM"
    else:
        return "LOW"


def _map_zap_alert_to_type(alert_name: str) -> str:
    """Mapea nombre de alerta ZAP a tipo de vulnerabilidad."""
    alert_lower = alert_name.lower()
    
    if 'sql' in alert_lower or 'injection' in alert_lower:
        return "SQL_INJECTION"
    elif 'xss' in alert_lower or 'cross-site scripting' in alert_lower:
        return "XSS"
    elif 'auth' in alert_lower or 'session' in alert_lower:
        return "BROKEN_AUTH"
    elif 'access control' in alert_lower or 'authorization' in alert_lower:
        return "BROKEN_ACCESS"
    elif 'exposure' in alert_lower or 'disclosure' in alert_lower:
        return "SENSITIVE_DATA"
    elif 'config' in alert_lower or 'misconfiguration' in alert_lower:
        return "SECURITY_MISCONFIG"
    elif 'logging' in alert_lower or 'monitoring' in alert_lower:
        return "INSUFFICIENT_LOGGING"
    else:
        return "OTHER"


def _map_to_owasp_api_top10(alert_name: str) -> str:
    """Mapea alerta a categoría OWASP API Security Top 10."""
    alert_lower = alert_name.lower()
    
    mapping = {
        "API1:2023": ["auth", "broken object", "bola", "idor"],
        "API2:2023": ["broken authentication", "session", "token"],
        "API3:2023": ["broken object property", "mass assignment"],
        "API4:2023": ["resource consumption", "rate limit", "dos"],
        "API5:2023": ["broken function", "authorization"],
        "API6:2023": ["server side request forgery", "ssrf"],
        "API7:2023": ["security misconfiguration", "config"],
        "API8:2023": ["injection", "sql", "xss", "command"],
        "API9:2023": ["asset management", "inventory"],
        "API10:2023": ["unsafe api", "consumption"]
    }
    
    for category, keywords in mapping.items():
        if any(keyword in alert_lower for keyword in keywords):
            return category
    
    return "UNKNOWN"


def _calculate_severity_summary(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calcula resumen de severidades."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "LOW")
        if severity in summary:
            summary[severity] += 1
    
    return summary

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run OWASP ZAP DAST analysis')
    parser.add_argument('url', help='URL of the API to scan')
    args = parser.parse_args()
    run_zap(args.url)
