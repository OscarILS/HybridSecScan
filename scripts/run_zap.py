# Script para ejecutar OWASP ZAP (DAST)
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

def run_zap(target_url):
    """Ejecuta análisis OWASP ZAP con manejo mejorado de errores"""
    # Validate URL
    parsed_url = urlparse(target_url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        print("Error: URL inválida. Debe incluir esquema (http:// o https://)")
        return False
    
    # Generate unique report filename
    report_id = str(uuid.uuid4())
    base_dir = Path(__file__).parent.parent
    report_path = base_dir / "reports" / f"zap_report_{report_id}.html"
    
    # Ensure reports directory exists
    report_path.parent.mkdir(exist_ok=True)
    
    try:
        result = subprocess.run([
            'zap-cli', 'quick-scan', '--self-contained', 
            '--start-options', '-config api.disablekey=true',
            '--output', str(report_path),
            target_url
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            print(f'OWASP ZAP analysis completed successfully. Report: {report_path}')
            return True
        else:
            print(f'OWASP ZAP analysis failed: {result.stderr}')
            return False
            
    except subprocess.TimeoutExpired:
        print('OWASP ZAP analysis timed out after 10 minutes')
        return False
    except FileNotFoundError:
        print('Error: zap-cli not found. Please install OWASP ZAP and zap-cli')
        return False
    except Exception as e:
        print(f'Unexpected error running OWASP ZAP: {e}')
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run OWASP ZAP DAST analysis')
    parser.add_argument('url', help='URL of the API to scan')
    args = parser.parse_args()
    run_zap(args.url)
