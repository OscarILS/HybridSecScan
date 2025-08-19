# Script para ejecutar Bandit (SAST)
import subprocess
import sys
import os
import uuid
from pathlib import Path

def run_bandit(target_path):
    """Ejecuta análisis Bandit con manejo mejorado de errores"""
    if not os.path.exists(target_path):
        print(f"Error: La ruta {target_path} no existe")
        return False
    
    # Generate unique report filename
    report_id = str(uuid.uuid4())
    base_dir = Path(__file__).parent.parent
    report_path = base_dir / "reports" / f"bandit_report_{report_id}.json"
    
    # Ensure reports directory exists
    report_path.parent.mkdir(exist_ok=True)
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'bandit', '-r', target_path, 
            '-f', 'json', '-o', str(report_path)
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f'Bandit analysis completed successfully. Report: {report_path}')
            return True
        elif result.returncode == 1:
            print(f'Bandit analysis completed with issues found. Report: {report_path}')
            return True
        else:
            print(f'Bandit analysis failed: {result.stderr}')
            return False
            
    except subprocess.TimeoutExpired:
        print('Bandit analysis timed out after 5 minutes')
        return False
    except Exception as e:
        print(f'Unexpected error running Bandit: {e}')
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run Bandit SAST analysis')
    parser.add_argument('target', help='Path to the source code to analyze')
    args = parser.parse_args()
    run_bandit(args.target)
