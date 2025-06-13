# Script para ejecutar Bandit (SAST)
import subprocess
import sys

def run_bandit(target_path):
    result = subprocess.run([
        sys.executable, '-m', 'bandit', '-r', target_path, '-f', 'json', '-o', '../reports/bandit_report.json'
    ])
    print('Bandit analysis completed.')

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run Bandit SAST analysis')
    parser.add_argument('target', help='Path to the source code to analyze')
    args = parser.parse_args()
    run_bandit(args.target)
