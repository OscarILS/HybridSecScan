from fastapi import FastAPI, Depends, UploadFile, File, Form
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import os
import sys
import subprocess
from typing import Optional
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'database')))
from models import Base, ScanResult

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'database', 'hybridsecscan.db')}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependencia para obtener la sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "Bienvenido a HybridSecScan API - Sistema de auditoría automatizada OWASP API Top 10"}

@app.get("/scan-results")
def get_scan_results(db: Session = Depends(get_db)):
    results = db.query(ScanResult).all()
    return [
        {
            "id": r.id,
            "scan_type": r.scan_type,
            "tool": r.tool,
            "result_path": r.result_path,
            "created_at": r.created_at
        } for r in results
    ]

@app.post("/scan/sast")
def run_sast_scan(target_path: str = Form(...), tool: str = Form(...), db: Session = Depends(get_db)):
    """
    Ejecuta un análisis SAST usando Bandit o Semgrep sobre el código fuente indicado.
    """
    if tool == "bandit":
        report_path = os.path.join(BASE_DIR, "reports", "bandit_report.json")
        result = subprocess.run([
            sys.executable, '-m', 'bandit', '-r', target_path, '-f', 'json', '-o', report_path
        ])
    elif tool == "semgrep":
        report_path = os.path.join(BASE_DIR, "reports", "semgrep_report.json")
        result = subprocess.run([
            'semgrep', '--config', 'auto', target_path, '--json', '--output', report_path
        ])
    else:
        return {"error": "Herramienta SAST no soportada"}
    scan_result = ScanResult(scan_type="SAST", tool=tool, result_path=report_path)
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)
    return {"message": f"Análisis SAST con {tool} completado.", "result_id": scan_result.id}

@app.post("/scan/dast")
def run_dast_scan(target_url: str = Form(...), db: Session = Depends(get_db)):
    """
    Ejecuta un análisis DAST usando OWASP ZAP sobre la URL indicada.
    """
    report_path = os.path.join(BASE_DIR, "reports", "zap_report.html")
    result = subprocess.run([
        'zap-cli', 'quick-scan', '--self-contained', '--start-options', '-config', 'api.disablekey=true', target_url
    ])
    # Nota: zap-cli no genera un reporte por defecto, esto es un placeholder
    scan_result = ScanResult(scan_type="DAST", tool="OWASP ZAP", result_path=report_path)
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)
    return {"message": "Análisis DAST con OWASP ZAP completado.", "result_id": scan_result.id}

@app.post("/upload/")
def upload_code(file: UploadFile = File(...)):
    """
    Permite subir un archivo de código fuente para análisis.
    """
    upload_dir = os.path.join(BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    with open(file_path, "wb") as f:
        f.write(file.file.read())
    return {"message": "Archivo subido correctamente", "file_path": file_path}
