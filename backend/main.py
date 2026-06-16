from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import os
import sys
import subprocess
import uuid
import mimetypes
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone, timedelta
import json
from pydantic import BaseModel, EmailStr

# Importar scanner DAST real
try:
    from backend.dast_scanner import run_dast_scan as execute_dast_scan
except ImportError:
    from dast_scanner import run_dast_scan as execute_dast_scan

# Importar módulo de generación de PDF
try:
    from backend.pdf_generator import generate_pdf_report, generate_json_summary
except ImportError:
    from pdf_generator import generate_pdf_report, generate_json_summary

# Importar motor de correlación
try:
    from backend.correlation_engine import VulnerabilityCorrelator, Vulnerability, VulnerabilityType, ConfidenceLevel
except ImportError:
    from correlation_engine import VulnerabilityCorrelator, Vulnerability, VulnerabilityType, ConfidenceLevel

# Try to import python-magic, fallback to mimetypes if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logging.warning("python-magic not available, using mimetypes for file type detection")

# Configurar logging estructurado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
    handlers=[
        logging.FileHandler('hybridscan_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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

# Configuración de seguridad
ALLOWED_EXTENSIONS = {'.py', '.js', '.ts', '.tsx', '.java', '.cpp', '.c', '.go', '.php', '.rb', '.cs'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_MIME_TYPES = {
    'text/plain', 'text/x-python', 'application/javascript', 
    'text/typescript', 'text/x-java-source', 'text/x-c', 'application/json'
}

# Directorios seguros para escaneos
SECURE_SCAN_BASE = Path(tempfile.gettempdir()) / "hybridscan_secure"
SECURE_SCAN_BASE.mkdir(exist_ok=True)

def validate_scan_path(target_path: str) -> Optional[Path]:
    """
    Valida y normaliza rutas para prevenir path traversal attacks.
    
    Security Features:
    - Path normalization and resolution
    - Dangerous pattern detection
    - Whitelist of allowed directories
    - Secure temporary directory creation
    
    Args:
        target_path: Path to validate
        
    Returns:
        Validated Path object or None if invalid
    """
    try:
        # Normalizar y resolver ruta
        normalized_path = Path(target_path).resolve()
        logger.info(f"Validando ruta: {target_path} -> {normalized_path}")
        
        # Detectar patrones peligrosos
        dangerous_patterns = ['..', '~', '/etc', '/var', '/root', '/home', '/usr', '/boot']
        str_path = str(normalized_path).lower()
        
        for pattern in dangerous_patterns:
            if pattern in str_path and pattern not in ['/home/oscar', '/tmp', '/var/tmp']:
                logger.warning(f"🚨 SECURITY: Ruta rechazada por patrón peligroso '{pattern}': {target_path}")
                return None
        
        # Verificar que la ruta existe y es accesible
        if not normalized_path.exists():
            logger.warning(f"Ruta no existe: {normalized_path}")
            return None
        
        # Crear directorio seguro temporal para el escaneo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        secure_dir = SECURE_SCAN_BASE / f"scan_{timestamp}_{uuid.uuid4().hex[:8]}"
        secure_dir.mkdir(exist_ok=True)
        
        # Si es un archivo, copiarlo al directorio seguro
        if normalized_path.is_file():
            secure_file = secure_dir / normalized_path.name
            shutil.copy2(normalized_path, secure_file)
            logger.info(f"Archivo copiado a directorio seguro: {secure_file}")
            return secure_file
        
        # Si es un directorio, validar que esté en directorios permitidos
        allowed_prefixes = [
            Path.cwd(),
            Path("/tmp"),
            Path("/var/tmp"), 
            Path.home() / "Documentos",
            Path.home() / "Downloads"
        ]
        
        is_allowed = any(
            str(normalized_path).startswith(str(prefix)) 
            for prefix in allowed_prefixes
        )
        
        if not is_allowed:
            logger.warning(f"🚨 SECURITY: Ruta fuera de directorios permitidos: {target_path}")
            return None
        
        # Copiar directorio al área segura (solo archivos permitidos)
        secure_target = secure_dir / "target"
        secure_target.mkdir()
        
        for file_path in normalized_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ALLOWED_EXTENSIONS:
                relative_path = file_path.relative_to(normalized_path)
                target_file = secure_target / relative_path
                target_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, target_file)
        
        logger.info(f"Directorio copiado a área segura: {secure_target}")
        return secure_target
        
    except Exception as e:
        logger.error(f"❌ Error validando ruta {target_path}: {str(e)}")
        return None

async def validate_uploaded_file(file: UploadFile) -> dict:
    """
    Valida archivo subido de forma segura.
    
    Security validations:
    - Real file size calculation
    - MIME type validation using magic numbers
    - Filename sanitization
    - Content inspection
    
    Args:
        file: UploadFile object from FastAPI
        
    Returns:
        dict: File information if valid
        
    Raises:
        HTTPException: If validation fails
    """
    try:
        logger.info(f"Validando archivo subido: {file.filename}")
        
        # Leer contenido completo para calcular tamaño real
        content = await file.read()
        file_size = len(content)
        
        # Resetear posición del archivo
        await file.seek(0)
        
        logger.info(f"Tamaño real del archivo: {file_size} bytes")
        
        # Validar tamaño
        if file_size > MAX_FILE_SIZE:
            logger.warning(f"🚨 SECURITY: Archivo demasiado grande: {file_size} bytes")
            raise HTTPException(
                status_code=413,
                detail=f"Archivo demasiado grande: {file_size} bytes. Máximo: {MAX_FILE_SIZE} bytes"
            )
        
        # Validar que el archivo no esté vacío
        if file_size == 0:
            raise HTTPException(status_code=400, detail="El archivo está vacío")
        
        # Validar tipo de archivo usando magic numbers (primeros 1024 bytes)
        if MAGIC_AVAILABLE:
            try:
                detected_mime = magic.from_buffer(content[:1024], mime=True)
                logger.info(f"MIME type detectado: {detected_mime}")
            except Exception as e:
                logger.warning(f"Error usando python-magic: {e}")
                detected_mime = mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
                logger.warning(f"Usando fallback MIME detection: {detected_mime}")
        else:
            # Fallback si python-magic no está disponible
            detected_mime = mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
            logger.info(f"Usando mimetypes para detección: {detected_mime}")
        
        if detected_mime not in ALLOWED_MIME_TYPES and not detected_mime.startswith('text/'):
            logger.warning(f"🚨 SECURITY: Tipo de archivo no permitido: {detected_mime}")
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo no permitido: {detected_mime}"
            )
        
        # Validar nombre de archivo
        if not file.filename or '..' in file.filename or '/' in file.filename:
            logger.warning(f"🚨 SECURITY: Nombre de archivo no válido: {file.filename}")
            raise HTTPException(status_code=400, detail="Nombre de archivo no válido")
        
        # Validar extensión
        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Extensión no permitida: {file_extension}. Permitidas: {', '.join(ALLOWED_EXTENSIONS)}"
            )
        
        logger.info(f"✅ Archivo validado correctamente: {file.filename}")
        return {
            'size': file_size,
            'mime_type': detected_mime,
            'filename': file.filename,
            'extension': file_extension,
            'content': content
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error validando archivo: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno validando archivo")

def update_scan_result(scan_result, results: dict, status: str = "completed", error: str = None):
    """
    Actualiza resultado de escaneo con metadatos completos.
    
    Args:
        scan_result: Objeto ScanResult a actualizar
        results: Diccionario con resultados del escaneo  
        status: Estado final del escaneo
        error: Mensaje de error si aplica
    """
    try:
        scan_result.results = results
        scan_result.status = status
        
        if error:
            scan_result.error_message = error
            scan_result.status = "failed"
            logger.error(f"Escaneo fallido - ID: {scan_result.id}, Error: {error}")
        
        # Agregar metadatos útiles para análisis
        if results and isinstance(results, dict):
            duration = (datetime.now(timezone.utc) - scan_result.timestamp).total_seconds()
            vulnerabilities = results.get("vulnerabilities", results.get("results", []))
            
            scan_result.results.update({
                "scan_duration_seconds": duration,
                "vulnerabilities_found": len(vulnerabilities) if isinstance(vulnerabilities, list) else 0,
                "severity_breakdown": _calculate_severity_breakdown(results),
                "scan_completed_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "scan_version": "2.0",
                    "engine": "HybridSecScan",
                    "owasp_categories_detected": _extract_owasp_categories(results)
                }
            })
            
        logger.info(f"✅ Scan result actualizado - ID: {scan_result.id}, Status: {status}")
        
    except Exception as e:
        logger.error(f"❌ Error actualizando scan result {scan_result.id}: {str(e)}")
        scan_result.status = "error"
        scan_result.error_message = f"Error interno: {str(e)}"

def _calculate_severity_breakdown(results: dict) -> dict:
    """Calcula distribución de severidades encontradas"""
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Bandit uses 'results' list and each item often has 'issue_severity' (e.g. 'HIGH','MEDIUM','LOW')
    # Semgrep and other tools may use 'severity' or 'level'. Normalize several possible keys.
    vulnerabilities = results.get("vulnerabilities", results.get("results", []))

    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            # Try multiple keys used by different tools
            raw_sev = None
            for key in ("severity", "level", "issue_severity", "issue_confidence", "severity_level"):
                if key in vuln and vuln.get(key) is not None:
                    raw_sev = str(vuln.get(key))
                    break

            if raw_sev is None:
                # Some tools store severity inside nested fields or use numeric codes - fallback to 'info'
                raw_sev = "info"

            sev = raw_sev.strip().lower()

            # Normalize common values
            if sev in ("critical", "crit", "c"):
                breakdown["critical"] += 1
            elif sev in ("high", "h"):
                breakdown["high"] += 1
            elif sev in ("medium", "med", "m", "warning"):
                breakdown["medium"] += 1
            elif sev in ("low", "l"):
                breakdown["low"] += 1
            elif sev in ("info", "informational", "none"):
                breakdown["info"] += 1
            else:
                # Try to map common uppercase values (Bandit: HIGH, MEDIUM, LOW)
                u = sev.upper()
                if u == "HIGH":
                    breakdown["high"] += 1
                elif u == "MEDIUM":
                    breakdown["medium"] += 1
                elif u == "LOW":
                    breakdown["low"] += 1
                elif u == "CRITICAL":
                    breakdown["critical"] += 1
                else:
                    breakdown["info"] += 1

    return breakdown

def _extract_owasp_categories(results: dict) -> list:
    """Extrae categorías OWASP detectadas"""
    categories = set()
    vulnerabilities = results.get("vulnerabilities", results.get("results", []))
    
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                owasp = vuln.get("owasp", vuln.get("category", ""))
                if owasp:
                    categories.add(owasp)
                    
                # Mapeo de CWE a OWASP API Top 10
                cwe = vuln.get("cwe", "")
                if "89" in str(cwe):  # SQL Injection
                    categories.add("API3:2023")
                elif "79" in str(cwe):  # XSS
                    categories.add("API8:2023")
                elif "22" in str(cwe):  # Path Traversal
                    categories.add("API1:2023")
    
    return list(categories)

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


@app.get("/api/model-metrics")
def get_model_metrics():
    """
    Devuelve las métricas reales del modelo ML de correlación.

    Si el modelo no ha sido entrenado, devuelve model_available=False.
    Para entrenar: python scripts/generate_training_dataset.py
                   python backend/train_ml_model.py
    """
    metadata_path = Path(BASE_DIR) / "data" / "models" / "metadata.json"
    model_path    = Path(BASE_DIR) / "data" / "models" / "rf_correlator_v1.pkl"

    if not metadata_path.exists():
        return {
            "model_available": False,
            "message": (
                "Modelo no entrenado. Ejecuta:\n"
                "  python scripts/generate_training_dataset.py\n"
                "  python backend/train_ml_model.py"
            ),
        }

    with open(metadata_path, "r") as f:
        metadata = json.load(f)

    return {
        "model_available": True,
        "metrics":         metadata.get("test", {}),
        "validation":      metadata.get("validation", {}),
        "confusion_matrix":metadata.get("confusion_matrix", {}),
        "training_info":   metadata.get("training_info", {}),
    }

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
    
    Security Features:
    - Path traversal prevention
    - Input validation and sanitization  
    - Secure temporary directories
    - Complete audit logging
    - Error handling and recovery
    """
    try:
        logger.info(f"🔍 Iniciando escaneo SAST - Tool: {tool}, Target: {target_path}")
        
        # Validar herramienta
        if tool not in ["bandit", "semgrep"]:
            logger.warning(f"🚨 Herramienta SAST no soportada: {tool}")
            raise HTTPException(
                status_code=400, 
                detail="Herramienta SAST no soportada. Use 'bandit' o 'semgrep'"
            )
        
        # Validar y asegurar la ruta de destino
        validated_path = validate_scan_path(target_path)
        if validated_path is None:
            logger.warning(f"🚨 SECURITY: Ruta rechazada por validación de seguridad: {target_path}")
            raise HTTPException(
                status_code=400,
                detail="Ruta no válida, fuera de directorios permitidos o contiene patrones peligrosos"
            )
        
        # Crear registro inicial del escaneo
        scan_result = ScanResult(
            scan_type="SAST",
            tool=tool,
            target=str(target_path),  # Ruta original para auditoría
            status="running",
            timestamp=datetime.now(timezone.utc)
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        logger.info(f"📝 Escaneo registrado - ID: {scan_result.id}, Ruta segura: {validated_path}")
        
        # Generar reporte con ID único
        report_id = str(uuid.uuid4())
        report_dir = Path(BASE_DIR) / "reports"
        report_dir.mkdir(exist_ok=True)
        
        try:
            if tool == "bandit":
                report_path = report_dir / f"bandit_report_{report_id}.json"

                logger.info(f"🔧 Ejecutando Bandit en: {validated_path}")
                result = subprocess.run(
                    [sys.executable, '-m', 'bandit', '-r', str(validated_path), '-f', 'json', '-o', str(report_path)],
                    capture_output=True, text=True, timeout=300
                )

            elif tool == "semgrep":
                report_path = report_dir / f"semgrep_report_{report_id}.json"

                logger.info(f"🔧 Ejecutando Semgrep en: {validated_path}")
                # Preferir ejecutar semgrep como módulo de Python (si está instalado en el venv),
                # si no, intentar el ejecutable 'semgrep' (PATH).
                semgrep_cmds = [
                    [sys.executable, '-m', 'semgrep', '--config', 'auto', str(validated_path), '--json', '--output', str(report_path)],
                    ['semgrep', '--config', 'auto', str(validated_path), '--json', '--output', str(report_path)]
                ]
                last_exc = None
                for cmd in semgrep_cmds:
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                        break
                    except FileNotFoundError as fe:
                        last_exc = fe
                        logger.warning(f"Semgrep no encontrado con comando: {cmd}. Intentando siguiente opción.")
                        result = None
                if result is None:
                    error_msg = f"Semgrep no está instalado o no se encuentra en PATH. Error: {last_exc}"
                    logger.error(error_msg)
                    update_scan_result(scan_result, {}, "failed", error_msg)
                    db.commit()
                    raise HTTPException(status_code=500, detail=error_msg)
            
            # Verificar ejecución exitosa
            # Nota: Bandit retorna 1 si encuentra issues, pero no es error. Semgrep puede retornar distintos códigos.
            if result is None:
                error_msg = f"No se ejecutó el comando para {tool}."
                logger.error(error_msg)
                update_scan_result(scan_result, {}, "failed", error_msg)
                db.commit()
                raise HTTPException(status_code=500, detail=error_msg)

            if result.returncode not in [0, 1]:
                # Capturar stdout/stderr y devolver información útil
                error_msg = f"Error ejecutando {tool}. returncode={result.returncode}. stderr={result.stderr.strip()}"
                logger.error(f"❌ {error_msg}")
                update_scan_result(scan_result, {"raw_stdout": result.stdout, "raw_stderr": result.stderr}, "failed", error_msg)
                db.commit()
                raise HTTPException(status_code=500, detail=error_msg)
            
            # Cargar y procesar resultados
            try:
                if report_path.exists():
                    with open(report_path, 'r') as f:
                        try:
                            scan_results = json.load(f)
                        except json.JSONDecodeError:
                            # Guardar el contenido bruto si JSON no es válido
                            scan_results = {"results": [], "message": "Reporte generado pero JSON inválido", "raw_output": result.stdout}
                else:
                    # Reporte no generado; incluir stdout/stderr del proceso para diagnóstico
                    scan_results = {"results": [], "message": "No se generó archivo de reporte", "raw_stdout": result.stdout, "raw_stderr": result.stderr}

                logger.info(f"📊 Resultados cargados desde: {report_path} (exists={report_path.exists()})")
                
            except json.JSONDecodeError as e:
                logger.error(f"❌ Error parseando JSON del reporte: {str(e)}")
                scan_results = {"error": "Error parseando resultados", "raw_output": result.stdout}
            
            # Actualizar resultado con metadatos completos
            update_scan_result(scan_result, scan_results, "completed")
            scan_result.result_path = str(report_path)
            db.commit()
            
            # Limpiar directorio temporal de seguridad
            try:
                if validated_path.parent.name.startswith("scan_"):
                    shutil.rmtree(validated_path.parent)
                    logger.info(f"🧹 Directorio temporal limpiado: {validated_path.parent}")
            except Exception as cleanup_error:
                logger.warning(f"⚠️ No se pudo limpiar directorio temporal: {cleanup_error}")
            
            logger.info(f"✅ Escaneo SAST completado - ID: {scan_result.id}, Vulnerabilidades: {len(scan_results.get('results', []))}")

            # Leer los datos actualizados guardados en el objeto de BD (incluye severity_breakdown calculado)
            stored = scan_result.results if isinstance(scan_result.results, dict) else {}
            vulnerabilities_found = stored.get("vulnerabilities_found", len(scan_results.get("results", [])))
            scan_duration = stored.get("scan_duration_seconds", scan_results.get("scan_duration_seconds", 0))

            # Preferir valores ya calculados en el registro; si faltan, calcularlos inline
            severity_breakdown = stored.get("severity_breakdown") if isinstance(stored, dict) else None
            if not severity_breakdown:
                severity_breakdown = _calculate_severity_breakdown(stored or scan_results)

            owasp_categories = (stored.get("metadata", {}) or {}).get("owasp_categories_detected") if isinstance(stored, dict) else None
            if not owasp_categories:
                owasp_categories = _extract_owasp_categories(stored or scan_results)

            return {
                "id": scan_result.id,
                "message": f"Análisis SAST con {tool} completado exitosamente",
                "result_id": scan_result.id,
                "report_path": str(report_path),
                "vulnerabilities_found": vulnerabilities_found,
                "scan_duration": scan_duration,
                "severity_breakdown": severity_breakdown,
                "owasp_categories": owasp_categories
            }
            
        except subprocess.TimeoutExpired:
            error_msg = f"Timeout ejecutando análisis con {tool} (>5 minutos)"
            logger.error(f"⏰ {error_msg}")
            update_scan_result(scan_result, {}, "timeout", error_msg)
            db.commit()
            raise HTTPException(status_code=408, detail=error_msg)
            
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Error inesperado en escaneo SAST: {str(e)}"
        logger.error(f"❌ {error_msg}")
        
        if 'scan_result' in locals():
            update_scan_result(scan_result, {}, "error", error_msg)
            db.commit()
            
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/scan/dast")
def run_dast_scan(target_url: str = Form(...), db: Session = Depends(get_db)):
    """
    Ejecuta un análisis DAST real contra la URL indicada.

    Estrategia de escaneo (por prioridad):
      1. OWASP ZAP daemon  — si está corriendo en localhost:8080
      2. HTTP Security Scanner — probing HTTP activo sin dependencias externas

    Ambas rutas producen hallazgos reales a partir de peticiones HTTP al objetivo.
    """
    logger.info(f"🔍 Iniciando escaneo DAST real contra: {target_url}")

    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL debe comenzar con http:// o https://")

    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="URL inválida - debe incluir dominio")

    try:
        # ── Escaneo DAST real ──────────────────────────────────────────────
        dast_result = execute_dast_scan(target_url)
        dast_result["timestamp"] = datetime.now(timezone.utc).isoformat()
        dast_result["status"] = "completed"

        logger.info(
            f"✅ DAST completado — tool: {dast_result['tool']}, "
            f"hallazgos: {dast_result['summary']['total_issues']}, "
            f"ZAP disponible: {dast_result.get('zap_available', False)}"
        )

        # ── Persistir reporte en archivo ───────────────────────────────────
        report_id = str(uuid.uuid4())
        report_path = os.path.join(BASE_DIR, "reports", f"dast_report_{report_id}.json")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(dast_result, f, indent=2)

        # ── Crear registro en BD ───────────────────────────────────────────
        scan_result = ScanResult(
            scan_type="DAST",
            tool=dast_result["tool"],
            target=target_url,
            status="completed",
            result_path=report_path,
            results=dast_result,
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)

        logger.info(f"✓ Registro en BD creado con ID: {scan_result.id}")

        return {
            "id":              scan_result.id,
            "scan_type":       "DAST",
            "tool":            dast_result["tool"],
            "zap_available":   dast_result.get("zap_available", False),
            "target_url":      target_url,
            "status":          "completed",
            "vulnerabilities": dast_result.get("vulnerabilities", []),
            "summary":         dast_result.get("summary", {}),
            "report_path":     report_path,
            "message":         "Análisis DAST completado exitosamente",
        }

    except Exception as e:
        logger.error(f"❌ Error en escaneo DAST: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error ejecutando análisis DAST: {str(e)}")

def _map_bandit_to_vulnerability(bandit_issue: dict, file_path: str) -> Vulnerability:
    """Mapea hallazgo de Bandit a clase Vulnerability para correlación"""
    # Mapear severidad de Bandit (HIGH/MEDIUM/LOW) a ConfidenceLevel
    severity_map = {
        'HIGH': ConfidenceLevel.HIGH,
        'MEDIUM': ConfidenceLevel.MEDIUM,
        'LOW': ConfidenceLevel.LOW,
        'CRITICAL': ConfidenceLevel.CRITICAL
    }
    severity_str = bandit_issue.get('issue_severity', 'LOW').upper()
    severity = severity_map.get(severity_str, ConfidenceLevel.LOW)
    
    # Mapear CWE ID
    cwe_info = bandit_issue.get('issue_cwe', {})
    cwe_id = f"CWE-{cwe_info.get('id', '0')}" if isinstance(cwe_info, dict) else "CWE-0"
    
    # Determinar tipo de vulnerabilidad basado en test_id
    test_id = bandit_issue.get('test_id', '')
    vuln_type = VulnerabilityType.SECURITY_MISCONFIG  # default
    
    if 'B201' in test_id or 'B608' in test_id:
        vuln_type = VulnerabilityType.SQL_INJECTION
    elif 'B105' in test_id or 'B106' in test_id:
        vuln_type = VulnerabilityType.SENSITIVE_DATA
    elif 'B605' in test_id or 'B602' in test_id:
        vuln_type = VulnerabilityType.BROKEN_ACCESS
    
    # Extraer endpoint del file_path (simplificado)
    endpoint = f"/api/{Path(file_path).stem}" if file_path else "/unknown"
    
    return Vulnerability(
        id=f"SAST_{bandit_issue.get('test_id', 'UNKNOWN')}_{bandit_issue.get('line_number', 0)}",
        type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_number=bandit_issue.get('line_number', 0),
        endpoint=endpoint,
        description=bandit_issue.get('issue_text', 'No description'),
        cwe_id=cwe_id,
        owasp_category="",  # Se puede mapear desde CWE
        source_tool="bandit"
    )

def _map_zap_to_vulnerability(zap_alert: dict) -> Vulnerability:
    """Mapea alerta de ZAP a clase Vulnerability para correlación"""
    # Mapear severidad de ZAP
    severity_map = {
        'CRITICAL': ConfidenceLevel.CRITICAL,
        'HIGH': ConfidenceLevel.HIGH,
        'MEDIUM': ConfidenceLevel.MEDIUM,
        'LOW': ConfidenceLevel.LOW
    }
    severity_str = zap_alert.get('severity', 'LOW').upper()
    severity = severity_map.get(severity_str, ConfidenceLevel.LOW)
    
    # Mapear tipo de vulnerabilidad
    alert_type = zap_alert.get('type', '').lower()
    vuln_type = VulnerabilityType.SECURITY_MISCONFIG  # default
    
    if 'sql' in alert_type or 'injection' in alert_type:
        vuln_type = VulnerabilityType.SQL_INJECTION
    elif 'xss' in alert_type or 'script' in alert_type:
        vuln_type = VulnerabilityType.XSS
    elif 'auth' in alert_type or 'session' in alert_type:
        vuln_type = VulnerabilityType.BROKEN_AUTH
    elif 'access' in alert_type or 'idor' in alert_type:
        vuln_type = VulnerabilityType.BROKEN_ACCESS
    
    # Extraer CWE
    cwe_id = zap_alert.get('cwe', 'CWE-0')
    if not cwe_id.startswith('CWE'):
        cwe_id = f"CWE-{cwe_id}"
    
    return Vulnerability(
        id=f"DAST_{zap_alert.get('type', 'UNKNOWN').replace(' ', '_')}",
        type=vuln_type,
        severity=severity,
        file_path="",  # DAST no tiene file path
        line_number=0,
        endpoint=zap_alert.get('url', '/'),
        description=zap_alert.get('evidence', zap_alert.get('type', 'No description')),
        cwe_id=cwe_id,
        owasp_category="",
        source_tool="zap"
    )

@app.post("/scan/hybrid")
def run_hybrid_scan(
    sast_scan_id: int = Form(...),
    dast_scan_id: int = Form(...),
    db: Session = Depends(get_db)
):
    """
    Ejecuta análisis híbrido correlacionando resultados SAST y DAST.
    
    Este endpoint implementa el motor de correlación que es la característica
    principal de HybridSecScan: combinar hallazgos de análisis estático (SAST)
    y dinámico (DAST) para reducir falsos positivos y proporcionar un análisis
    más preciso.
    
    Args:
        sast_scan_id: ID del escaneo SAST previamente ejecutado
        dast_scan_id: ID del escaneo DAST previamente ejecutado
        
    Returns:
        Reporte híbrido con correlaciones y métricas de confianza
    """
    try:
        logger.info(f"🔗 Iniciando análisis híbrido - SAST ID: {sast_scan_id}, DAST ID: {dast_scan_id}")
        
        # Obtener resultados SAST
        sast_result = db.query(ScanResult).filter(ScanResult.id == sast_scan_id).first()
        if not sast_result or sast_result.scan_type != "SAST":
            raise HTTPException(status_code=404, detail=f"Escaneo SAST {sast_scan_id} no encontrado")
        
        # Obtener resultados DAST
        dast_result = db.query(ScanResult).filter(ScanResult.id == dast_scan_id).first()
        if not dast_result or dast_result.scan_type != "DAST":
            raise HTTPException(status_code=404, detail=f"Escaneo DAST {dast_scan_id} no encontrado")
        
        logger.info(f"✓ Escaneos cargados - SAST: {sast_result.tool}, DAST: {dast_result.tool}")
        
        # Parsear datos
        sast_data = sast_result.results if isinstance(sast_result.results, dict) else json.loads(sast_result.results)
        dast_data = dast_result.results if isinstance(dast_result.results, dict) else json.loads(dast_result.results)
        
        # Inicializar motor de correlación
        correlator = VulnerabilityCorrelator()
        
        # Mapear hallazgos SAST a objetos Vulnerability
        sast_vulnerabilities = []
        sast_raw = sast_data.get('results', [])
        target_file = sast_result.target
        
        logger.info(f"📊 Procesando {len(sast_raw)} hallazgos SAST...")
        for issue in sast_raw:
            if isinstance(issue, dict):
                try:
                    vuln = _map_bandit_to_vulnerability(issue, target_file)
                    sast_vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"⚠️ Error mapeando hallazgo SAST: {e}")
        
        # Mapear hallazgos DAST a objetos Vulnerability
        dast_vulnerabilities = []
        dast_raw = dast_data.get('vulnerabilities', [])
        
        logger.info(f"📊 Procesando {len(dast_raw)} hallazgos DAST...")
        for alert in dast_raw:
            if isinstance(alert, dict):
                try:
                    vuln = _map_zap_to_vulnerability(alert)
                    dast_vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"⚠️ Error mapeando hallazgo DAST: {e}")
        
        # Agregar hallazgos al correlador
        correlator.add_sast_findings(sast_vulnerabilities)
        correlator.add_dast_findings(dast_vulnerabilities)
        
        logger.info(f"🔄 Ejecutando motor de correlación...")
        
        # Generar reporte de correlación
        correlation_report = correlator.generate_correlation_report()
        
        logger.info(f"✅ Correlación completada:")
        logger.info(f"   - Hallazgos SAST: {len(sast_vulnerabilities)}")
        logger.info(f"   - Hallazgos DAST: {len(dast_vulnerabilities)}")
        logger.info(f"   - Correlaciones alta confianza: {correlation_report['summary']['high_confidence_correlations']}")
        logger.info(f"   - Reducción FP estimada: {correlation_report['summary']['potential_false_positives_reduced']:.1f}%")
        
        # Guardar reporte híbrido
        report_id = str(uuid.uuid4())
        report_dir = Path(BASE_DIR) / "reports"
        report_path = report_dir / f"hybrid_report_{report_id}.json"
        
        hybrid_data = {
            "scan_type": "HYBRID",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sast_scan_id": sast_scan_id,
            "dast_scan_id": dast_scan_id,
            "correlation_report": correlation_report,
            "model_metrics": correlator.model_metrics
        }
        
        with open(report_path, 'w') as f:
            json.dump(hybrid_data, f, indent=2)
        
        # Crear registro en BD
        scan_result = ScanResult(
            scan_type="HYBRID",
            tool="HybridSecScan Correlator",
            target=f"SAST:{sast_scan_id} + DAST:{dast_scan_id}",
            status="completed",
            result_path=str(report_path),
            results=hybrid_data
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        logger.info(f"✓ Reporte híbrido guardado - ID: {scan_result.id}")
        
        return {
            "id": scan_result.id,
            "scan_type": "HYBRID",
            "sast_scan_id": sast_scan_id,
            "dast_scan_id": dast_scan_id,
            "status": "completed",
            "summary": correlation_report['summary'],
            "correlations": correlation_report['correlations'],
            "model_metrics": correlator.model_metrics,
            "report_path": str(report_path),
            "message": "Análisis híbrido con correlación completado exitosamente"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Error en análisis híbrido: {str(e)}"
        logger.error(f"❌ {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/upload/")
async def upload_code(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Permite subir un archivo de código fuente para análisis.
    
    Security Features:
    - Real file size validation (not just headers)
    - MIME type validation using magic numbers  
    - Filename sanitization and path traversal prevention
    - Secure file storage with UUID naming
    - Complete audit trail
    """
    try:
        logger.info(f"📁 Iniciando subida de archivo: {file.filename}")
        
        # Validar archivo de forma segura
        file_info = await validate_uploaded_file(file)
        
        # Crear registro inicial de subida
        scan_result = ScanResult(
            scan_type="FILE_UPLOAD",
            tool="upload_service",
            target=file_info['filename'],
            status="uploading",
            timestamp=datetime.now(timezone.utc)
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        # Generar nombre de archivo seguro y único
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{uuid.uuid4().hex[:8]}{file_info['extension']}"
        
        # Crear directorio de uploads
        upload_dir = Path(BASE_DIR) / "uploads"
        upload_dir.mkdir(exist_ok=True)
        file_path = upload_dir / safe_filename
        
        # Guardar archivo de forma segura
        try:
            # Escribir archivo de forma síncrona en async context
            file_path.write_bytes(file_info['content'])
                
            logger.info(f"💾 Archivo guardado: {file_path}")
            
            # Validar que el archivo se guardó correctamente
            if not file_path.exists() or file_path.stat().st_size != file_info['size']:
                raise IOError(f"Error verificando integridad del archivo guardado: {file_path}")
            
            # Actualizar resultado con información completa
            upload_results = {
                "original_filename": file_info['filename'],
                "secure_filename": safe_filename,
                "file_size": file_info['size'],
                "mime_type": file_info['mime_type'],
                "file_extension": file_info['extension'],
                "upload_path": str(file_path),
                "integrity_verified": True
            }
            
            update_scan_result(scan_result, upload_results, "uploaded")
            scan_result.result_path = str(file_path)
            db.commit()
            
            logger.info(f"✅ Archivo subido exitosamente - ID: {scan_result.id}, Size: {file_info['size']} bytes")
            
            return {
                "message": "Archivo subido correctamente",
                "result_id": scan_result.id,
                "file_path": str(file_path),
                "original_filename": file_info['filename'],
                "secure_filename": safe_filename,
                "file_size": file_info['size'],
                "mime_type": file_info['mime_type'],
                "ready_for_scan": True
            }
            
        except IOError as e:
            error_msg = f"Error de E/S guardando archivo: {str(e)}"
            logger.error(f"💾 {error_msg}")
            update_scan_result(scan_result, {}, "failed", error_msg)
            db.commit()
            raise HTTPException(status_code=500, detail=error_msg)
            
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Error inesperado en subida de archivo: {str(e)}"
        logger.error(f"❌ {error_msg}")
        
        if 'scan_result' in locals():
            update_scan_result(scan_result, {}, "error", error_msg)
            db.commit()
            
        raise HTTPException(status_code=500, detail=error_msg)

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "HybridSecScan API funcionando correctamente"}


@app.get("/download/pdf/{scan_id}")
def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Descarga reporte PDF de un escaneo específico
    
    Genera un PDF profesional con los resultados del escaneo incluyendo:
    - Información del escaneo
    - Resumen de vulnerabilidades
    - Detalles de cada vulnerabilidad
    - Estadísticas y métricas
    
    Args:
        scan_id: ID del escaneo (UUID)
        
    Returns:
        PDF file stream with appropriate headers
    """
    try:
        logger.info(f"📥 Generando descarga de PDF para scan_id: {scan_id}")
        
        # Aceptar tanto IDs numéricos (ID entero de la BD) como UUIDs usados en nombres de reporte
        scan_result = None
        # Intentar como entero (id de la tabla)
        try:
            numeric_id = int(scan_id)
            scan_result = db.query(ScanResult).filter(ScanResult.id == numeric_id).first()
        except Exception:
            # Si no es entero, intentar validar formato UUID y buscar por report_path que contenga el UUID
            try:
                _ = uuid.UUID(scan_id)
                # Buscar primero por un campo que pueda contener ese UUID (p.ej. result_path)
                scan_result = db.query(ScanResult).filter(ScanResult.result_path.like(f"%{scan_id}%")).first()
            except Exception:
                logger.error(f"❌ scan_id inválido: {scan_id}")
                raise HTTPException(status_code=400, detail="Invalid scan ID format")
        
        if not scan_result:
            logger.warning(f"⚠️ Escaneo no encontrado: {scan_id}")
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Parsear datos del escaneo
        try:
            scan_data = json.loads(scan_result.results) if isinstance(scan_result.results, str) else scan_result.results
        except json.JSONDecodeError:
            logger.error(f"❌ Error al parsear JSON del escaneo: {scan_id}")
            scan_data = {"vulnerabilities": []}
        
        # CASO ESPECIAL: Escaneo HÍBRIDO con correlaciones
        if scan_result.scan_type == "HYBRID" and 'correlation_report' in scan_data:
            logger.info(f"📊 Generando PDF para escaneo híbrido con correlaciones")
            corr_report = scan_data['correlation_report']
            
            # Extraer correlaciones para el PDF
            correlations = corr_report.get('correlations', [])
            summary_data = corr_report.get('summary', {})
            
            # Obtener IDs de los escaneos originales
            sast_id = scan_data.get('sast_scan_id')
            dast_id = scan_data.get('dast_scan_id')
            
            # Construir lista de vulnerabilidades: incluir TODAS (SAST + DAST + Correlaciones)
            vulnerabilities = []
            
            # Calcular distribución de severidad real desde los datos originales
            severity_distribution = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            # Agregar vulnerabilidades SAST
            if sast_id:
                sast_scan = db.query(ScanResult).filter(ScanResult.id == sast_id).first()
                if sast_scan:
                    sast_data = sast_scan.results if isinstance(sast_scan.results, dict) else json.loads(sast_scan.results)
                    sast_vulns = sast_data.get('results', [])
                    for vuln in sast_vulns:
                        if isinstance(vuln, dict):
                            sev = str(vuln.get('issue_severity', vuln.get('severity', 'low'))).upper()
                            # Contar severidades
                            if 'CRITICAL' in sev:
                                severity_distribution['critical'] += 1
                            elif 'HIGH' in sev:
                                severity_distribution['high'] += 1
                            elif 'MEDIUM' in sev:
                                severity_distribution['medium'] += 1
                            else:
                                severity_distribution['low'] += 1
                            
                            vulnerabilities.append({
                                'source': 'SAST',
                                'tool': sast_scan.tool,
                                'type': vuln.get('test_name', vuln.get('type', 'Unknown')),
                                'severity': vuln.get('issue_severity', vuln.get('severity', 'low')),
                                'file': vuln.get('filename', ''),
                                'line': vuln.get('line_number', 0),
                                'description': vuln.get('issue_text', vuln.get('description', 'No description')),
                                'cwe': vuln.get('issue_cwe', {}).get('id', ''),
                                'recommendation': vuln.get('more_info', '')
                            })
            
            # Agregar vulnerabilidades DAST
            if dast_id:
                dast_scan = db.query(ScanResult).filter(ScanResult.id == dast_id).first()
                if dast_scan:
                    dast_data = dast_scan.results if isinstance(dast_scan.results, dict) else json.loads(dast_scan.results)
                    dast_vulns = dast_data.get('vulnerabilities', [])
                    for vuln in dast_vulns:
                        if isinstance(vuln, dict):
                            sev = str(vuln.get('risk', vuln.get('severity', 'low'))).upper()
                            # Contar severidades
                            if 'CRITICAL' in sev:
                                severity_distribution['critical'] += 1
                            elif 'HIGH' in sev:
                                severity_distribution['high'] += 1
                            elif 'MEDIUM' in sev:
                                severity_distribution['medium'] += 1
                            else:
                                severity_distribution['low'] += 1
                            
                            vulnerabilities.append({
                                'source': 'DAST',
                                'tool': dast_scan.tool,
                                'type': vuln.get('alert', vuln.get('type', 'Unknown')),
                                'alert': vuln.get('alert', ''),
                                'severity': vuln.get('risk', vuln.get('severity', 'low')),
                                'url': vuln.get('url', ''),
                                'description': vuln.get('description', 'No description'),
                                'solution': vuln.get('solution', ''),
                                'cwe': vuln.get('cweid', vuln.get('cwe', '')),
                                'cweid': vuln.get('cweid', vuln.get('cwe', '')),
                                'owasp_category': vuln.get('owasp_category', ''),
                                'evidence': vuln.get('evidence', ''),
                                'parameter': vuln.get('parameter', ''),
                                'request_payload': vuln.get('request_payload', {}),
                            })
            
            # Usar la distribución de severidad calculada directamente desde los datos
            summary = severity_distribution
            
            pdf_data = {
                'scan_type': 'HYBRID',
                'target': scan_result.target,
                'timestamp': scan_result.created_at.isoformat() if hasattr(scan_result.created_at, 'isoformat') else str(scan_result.created_at),
                'vulnerabilities': vulnerabilities,
                'correlations': correlations,
                'summary': summary,
                'hybrid_metrics': {
                    'total_sast': summary_data.get('total_sast_findings', 0),
                    'total_dast': summary_data.get('total_dast_findings', 0),
                    'fp_reduction': summary_data.get('potential_false_positives_reduced', 0)
                }
            }
        else:
            # CASO NORMAL: SAST o DAST tradicional
            # Construir estructura de datos para PDF
            # Bandit usa 'results', ZAP usa 'vulnerabilities'
            raw_vulnerabilities = scan_data.get('results', scan_data.get('vulnerabilities', [])) if isinstance(scan_data, dict) else []
            
            vulnerabilities = []
            
            # Procesar vulnerabilidades según el tipo de escaneo
            if scan_result.scan_type == "SAST":
                # Formato Bandit
                for v in raw_vulnerabilities:
                    if isinstance(v, dict):
                        vulnerabilities.append({
                            'type': v.get('test_name', 'Unknown'),
                            'severity': v.get('issue_severity', 'low'),
                            'file': v.get('filename', ''),
                            'line': v.get('line_number', 0),
                            'description': v.get('issue_text', 'No description'),
                            'cwe': v.get('issue_cwe', {}).get('id', ''),
                            'recommendation': v.get('more_info', '')
                        })
            else:
                # Formato DAST (ZAP u otros)
                for v in raw_vulnerabilities:
                    if isinstance(v, dict):
                        vulnerabilities.append({
                            'type': v.get('alert', v.get('type', 'Unknown')),
                            'severity': v.get('risk', v.get('severity', 'low')),
                            'url': v.get('url', ''),
                            'description': v.get('description', 'No description'),
                            'solution': v.get('solution', ''),
                            'cwe': v.get('cweid', v.get('cwe', '')),
                            'cweid': v.get('cweid', v.get('cwe', '')),
                            'owasp_category': v.get('owasp_category', ''),
                            'evidence': v.get('evidence', ''),
                            'parameter': v.get('parameter', ''),
                            'source': v.get('source', ''),
                            'alert': v.get('alert', ''),
                            'request_payload': v.get('request_payload', {}),
                        })

            # Normalizar severities
            for v in vulnerabilities:
                if not isinstance(v, dict):
                    continue
                if 'severity' not in v or not v.get('severity'):
                    v['severity'] = 'info'
                else:
                    # Asegurar que severity sea string lowercase
                    try:
                        v['severity'] = str(v['severity']).lower()
                    except Exception:
                        v['severity'] = 'info'

            # Preferir severity_breakdown calculado y almacenado en el registro (update_scan_result)
            stored_breakdown = None
            if isinstance(scan_data, dict):
                stored_breakdown = scan_data.get('severity_breakdown') or scan_data.get('summary')

            if isinstance(stored_breakdown, dict):
                summary = {
                    'critical': int(stored_breakdown.get('critical', 0)),
                    'high': int(stored_breakdown.get('high', 0)),
                    'medium': int(stored_breakdown.get('medium', 0)),
                    'low': int(stored_breakdown.get('low', 0)),
                }
            else:
                # Si no hay breakdown guardado, calcularlo desde la lista de vulnerabilidades
                summary = _calculate_severity_breakdown({'vulnerabilities': vulnerabilities})

            pdf_data = {
                'scan_type': scan_result.scan_type,
                'target': scan_result.target,
                'timestamp': scan_result.created_at.isoformat() if hasattr(scan_result.created_at, 'isoformat') else str(scan_result.created_at),
                'vulnerabilities': vulnerabilities,
                'summary': summary
            }
        
        # Generar PDF
        pdf_bytes = generate_pdf_report(pdf_data)
        
        # Crear nombre del archivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"HybridSecScan_Report_{scan_result.scan_type.upper()}_{timestamp}.pdf"
        
        logger.info(f"✅ PDF generado exitosamente: {filename} ({len(pdf_bytes)} bytes)")
        
        # Retornar PDF como FileResponse
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except HTTPException as he:
        raise he
    except Exception as e:
        error_msg = f"Error al generar PDF: {str(e)}"
        logger.error(f"❌ {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)


@app.get("/download/json/{scan_id}")
def download_json_summary(scan_id: str, db: Session = Depends(get_db)):
    """
    Descarga resumen JSON de un escaneo específico
    
    Args:
        scan_id: ID del escaneo (UUID)
        
    Returns:
        JSON file with scan summary
    """
    try:
        logger.info(f"📥 Generando descarga JSON para scan_id: {scan_id}")
        
        # Aceptar tanto IDs numéricos (ID entero de la BD) como UUIDs usados en nombres de reporte
        scan_result = None
        try:
            numeric_id = int(scan_id)
            scan_result = db.query(ScanResult).filter(ScanResult.id == numeric_id).first()
        except Exception:
            try:
                _ = uuid.UUID(scan_id)
                scan_result = db.query(ScanResult).filter(ScanResult.result_path.like(f"%{scan_id}%")).first()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid scan ID format")

        if not scan_result:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Parsear datos
        try:
            scan_data = json.loads(scan_result.results) if isinstance(scan_result.results, str) else scan_result.results
        except json.JSONDecodeError:
            scan_data = {"vulnerabilities": []}
        
        pdf_data = {
            'scan_type': scan_result.scan_type,
            'target': scan_result.target,
            'timestamp': scan_result.created_at.isoformat() if hasattr(scan_result.created_at, 'isoformat') else str(scan_result.created_at),
            'vulnerabilities': scan_data.get('vulnerabilities', []),
            'summary': {}
        }
        
        # Generar resumen
        json_summary = generate_json_summary(pdf_data)
        
        # Crear nombre del archivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"HybridSecScan_Summary_{scan_result.scan_type.upper()}_{timestamp}.json"
        
        logger.info(f"✅ JSON generado exitosamente: {filename}")
        
        # Retornar JSON
        return StreamingResponse(
            iter([json.dumps(json_summary, indent=2).encode()]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except HTTPException as he:
        raise he
    except Exception as e:
        error_msg = f"Error al generar JSON: {str(e)}"
        logger.error(f"❌ {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)


# ============= AUTHENTICATION ENDPOINTS =============

class UserRegister(BaseModel):
    """Modelo para registro de usuario."""
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    """Modelo para respuesta de login."""
    access_token: str
    token_type: str
    user: dict


class UserResponse(BaseModel):
    """Modelo para respuesta de información de usuario."""
    id: int
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_admin: bool
    created_at: str


@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Registra un nuevo usuario en el sistema.
    
    Args:
        user_data: Datos del usuario a registrar
        db: Sesión de base de datos
        
    Returns:
        Usuario creado
        
    Raises:
        HTTPException: Si el usuario o email ya existe
    """
    from database.models import User
    from backend.auth import get_password_hash
    
    # Verificar si el usuario ya existe
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        if existing_user.username == user_data.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El nombre de usuario ya está registrado"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El correo electrónico ya está registrado"
            )
    
    # Crear nuevo usuario
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        is_active=True,
        is_admin=False
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    logger.info(f"✅ Usuario registrado: {new_user.username} (ID: {new_user.id})")
    
    return UserResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        full_name=new_user.full_name,
        is_active=new_user.is_active,
        is_admin=new_user.is_admin,
        created_at=new_user.created_at.isoformat() if new_user.created_at else ""
    )


@app.post("/auth/login", response_model=UserLogin)
async def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Autentica un usuario y devuelve un token JWT.
    
    Args:
        form_data: Credenciales del usuario (username y password)
        db: Sesión de base de datos
        
    Returns:
        Token de acceso JWT
        
    Raises:
        HTTPException: Si las credenciales son inválidas
    """
    from backend.auth import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
    from database.models import User
    
    user = authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Actualizar último login
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    
    # Crear token de acceso
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    
    logger.info(f"✅ Usuario autenticado: {user.username} (ID: {user.id})")
    
    return UserLogin(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin
        }
    )


@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(
    current_user = Depends(lambda: __import__('backend.auth', fromlist=['get_current_active_user']).get_current_active_user)
):
    """
    Obtiene la información del usuario autenticado actual.
    
    Args:
        current_user: Usuario actual obtenido del token JWT
        
    Returns:
        Información del usuario
    """
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at.isoformat() if current_user.created_at else ""
    )
