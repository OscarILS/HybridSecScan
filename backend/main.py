from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
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
    
    vulnerabilities = results.get("vulnerabilities", results.get("results", []))
    
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                severity = vuln.get("severity", vuln.get("level", "info")).lower()
                if severity in breakdown:
                    breakdown[severity] += 1
                elif severity == "warning":
                    breakdown["medium"] += 1
                elif severity == "error":
                    breakdown["high"] += 1
    
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
                result = subprocess.run([
                    sys.executable, '-m', 'bandit', '-r', str(validated_path), 
                    '-f', 'json', '-o', str(report_path)
                ], capture_output=True, text=True, timeout=300)
                
            elif tool == "semgrep":
                report_path = report_dir / f"semgrep_report_{report_id}.json"
                
                logger.info(f"🔧 Ejecutando Semgrep en: {validated_path}")
                result = subprocess.run([
                    'semgrep', '--config', 'auto', str(validated_path), 
                    '--json', '--output', str(report_path)
                ], capture_output=True, text=True, timeout=300)
            
            # Verificar ejecución exitosa
            # Nota: Bandit retorna 1 si encuentra issues, pero no es error
            if result.returncode not in [0, 1]:
                error_msg = f"Error ejecutando {tool}: {result.stderr}"
                logger.error(f"❌ {error_msg}")
                update_scan_result(scan_result, {}, "failed", error_msg)
                db.commit()
                raise HTTPException(status_code=500, detail=error_msg)
            
            # Cargar y procesar resultados
            try:
                if report_path.exists():
                    with open(report_path, 'r') as f:
                        scan_results = json.load(f)
                else:
                    scan_results = {"results": [], "message": "No se generó archivo de reporte"}
                
                logger.info(f"📊 Resultados cargados desde: {report_path}")
                
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
            
            return {
                "message": f"Análisis SAST con {tool} completado exitosamente",
                "result_id": scan_result.id,
                "report_path": str(report_path),
                "vulnerabilities_found": len(scan_results.get("results", [])),
                "scan_duration": scan_results.get("scan_duration_seconds", 0),
                "severity_breakdown": scan_results.get("severity_breakdown", {}),
                "owasp_categories": scan_results.get("metadata", {}).get("owasp_categories_detected", [])
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
