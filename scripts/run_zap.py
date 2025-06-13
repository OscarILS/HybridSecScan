# Script para ejecutar OWASP ZAP (DAST)
import subprocess
import sys

def run_zap(target_url):
    result = subprocess.run([
        'zap-cli', 'quick-scan', '--self-contained', '--start-options', '-config api.disablekey=true', target_url
    ])
    print('OWASP ZAP analysis completed.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run OWASP ZAP DAST analysis')
    parser.add_argument('url', help='URL of the API to scan')
    args = parser.parse_args()
    run_zap(args.url)
