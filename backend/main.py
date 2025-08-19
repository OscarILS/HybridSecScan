from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import os
import sys
import subprocess
import uuid
import mimetypes
from pathlib import Path
from typing import Optional

# Add the database directory to the path
database_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database')
sys.path.insert(0, database_path)

try:
    from models import Base, ScanResult
except ImportError:
    # Fallback import method
    import importlib.util
    spec = importlib.util.spec_from_file_location("models", os.path.join(database_path, "models.py"))
    models = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(models)
    Base = models.Base
    ScanResult = models.ScanResult

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'database', 'hybridsecscan.db')}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="HybridSecScan API",
    description="Sistema de auditoría automatizada híbrida (SAST + DAST) para APIs REST",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Allowed file extensions for security
ALLOWED_EXTENSIONS = {'.py', '.js', '.ts', '.tsx', '.java', '.cpp', '.c', '.go', '.php', '.rb', '.cs'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

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
    # Validate tool parameter
    if tool not in ["bandit", "semgrep"]:
        raise HTTPException(status_code=400, detail="Herramienta SAST no soportada. Use 'bandit' o 'semgrep'")
    
    # Validate target path exists and is secure
    if not os.path.exists(target_path):
        raise HTTPException(status_code=400, detail="La ruta del código fuente no existe")
    
    # Generate unique report filename
    report_id = str(uuid.uuid4())
    
    try:
        if tool == "bandit":
            report_path = os.path.join(BASE_DIR, "reports", f"bandit_report_{report_id}.json")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            result = subprocess.run([
                sys.executable, '-m', 'bandit', '-r', target_path, '-f', 'json', '-o', report_path
            ], capture_output=True, text=True, timeout=300)
            
        elif tool == "semgrep":
            report_path = os.path.join(BASE_DIR, "reports", f"semgrep_report_{report_id}.json")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            result = subprocess.run([
                'semgrep', '--config', 'auto', target_path, '--json', '--output', report_path
            ], capture_output=True, text=True, timeout=300)
        
        # Check if the command was successful
        if result.returncode != 0 and result.returncode != 1:  # Bandit returns 1 if issues found
            raise HTTPException(status_code=500, detail=f"Error ejecutando {tool}: {result.stderr}")
        
        scan_result = ScanResult(scan_type="SAST", tool=tool, result_path=report_path)
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        return {"message": f"Análisis SAST con {tool} completado.", "result_id": scan_result.id, "report_path": report_path}
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail=f"Timeout ejecutando análisis con {tool}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inesperado: {str(e)}")

@app.post("/scan/dast")
def run_dast_scan(target_url: str = Form(...), db: Session = Depends(get_db)):
    """
    Ejecuta un análisis DAST usando OWASP ZAP sobre la URL indicada.
    """
    # Basic URL validation
    if not target_url.startswith(('http://', 'https://')):
        raise HTTPException(status_code=400, detail="URL debe comenzar con http:// o https://")
    
    report_id = str(uuid.uuid4())
    
    try:
        report_path = os.path.join(BASE_DIR, "reports", f"zap_report_{report_id}.html")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # ZAP command with better options
        result = subprocess.run([
            'zap-cli', 'quick-scan', '--self-contained', 
            '--start-options', '-config api.disablekey=true',
            '--output', report_path,
            target_url
        ], capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Error ejecutando OWASP ZAP: {result.stderr}")
        
        scan_result = ScanResult(scan_type="DAST", tool="OWASP ZAP", result_path=report_path)
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        return {"message": "Análisis DAST con OWASP ZAP completado.", "result_id": scan_result.id, "report_path": report_path}
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Timeout ejecutando análisis DAST")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inesperado: {str(e)}")

@app.post("/upload/")
def upload_code(file: UploadFile = File(...)):
    """
    Permite subir un archivo de código fuente para análisis.
    """
    # Validate file size
    if file.size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Archivo muy grande. Máximo 10MB permitido")
    
    # Validate file extension
    file_extension = Path(file.filename).suffix.lower()
    if file_extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"Tipo de archivo no permitido. Extensiones permitidas: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    # Generate secure filename
    secure_filename = f"{uuid.uuid4()}{file_extension}"
    upload_dir = os.path.join(BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, secure_filename)
    
    try:
        with open(file_path, "wb") as f:
            content = file.file.read()
            f.write(content)
        
        return {
            "message": "Archivo subido correctamente", 
            "file_path": file_path,
            "original_filename": file.filename,
            "secure_filename": secure_filename
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error guardando archivo: {str(e)}")

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "HybridSecScan API funcionando correctamente"}
