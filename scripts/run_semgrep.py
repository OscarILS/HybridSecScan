# Script para ejecutar Semgrep (SAST)
import subprocess
import sys

def run_semgrep(target_path):
    result = subprocess.run([
        'semgrep', '--config', 'auto', target_path, '--json', '--output', '../reports/semgrep_report.json'
    ])
    print('Semgrep analysis completed.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run Semgrep SAST analysis')
    parser.add_argument('target', help='Path to the source code to analyze')
    args = parser.parse_args()
    run_semgrep(args.target)
