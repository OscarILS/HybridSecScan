# Script para ejecutar Semgrep (SAST)
import subprocess
import sys
import os
import uuid
from pathlib import Path

def run_semgrep(target_path):
    """Ejecuta análisis Semgrep con manejo mejorado de errores"""
    if not os.path.exists(target_path):
        print(f"Error: La ruta {target_path} no existe")
        return False
    
    # Generate unique report filename
    report_id = str(uuid.uuid4())
    base_dir = Path(__file__).parent.parent
    report_path = base_dir / "reports" / f"semgrep_report_{report_id}.json"
    
    # Ensure reports directory exists
    report_path.parent.mkdir(exist_ok=True)
    
    try:
        result = subprocess.run([
            'semgrep', '--config', 'auto', target_path, 
            '--json', '--output', str(report_path)
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f'Semgrep analysis completed successfully. Report: {report_path}')
            return True
        else:
            print(f'Semgrep analysis failed: {result.stderr}')
            return False
            
    except subprocess.TimeoutExpired:
        print('Semgrep analysis timed out after 5 minutes')
        return False
    except FileNotFoundError:
        print('Error: Semgrep not found. Please install it with: pip install semgrep')
        return False
    except Exception as e:
        print(f'Unexpected error running Semgrep: {e}')
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Run Semgrep SAST analysis')
    parser.add_argument('target', help='Path to the source code to analyze')
    args = parser.parse_args()
    run_semgrep(args.target)
