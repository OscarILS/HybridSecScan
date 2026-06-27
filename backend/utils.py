"""
Shared utilities: constants, file/path validation, scan-result helpers,
and vulnerability mappers used by multiple routers.
"""

import logging
import mimetypes
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, UploadFile

try:
    import magic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False

try:
    from backend.correlation_engine import ConfidenceLevel, Vulnerability, VulnerabilityType
except ImportError:
    from correlation_engine import ConfidenceLevel, Vulnerability, VulnerabilityType  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".java", ".cpp", ".c", ".go", ".php", ".rb", ".cs"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
ALLOWED_MIME_TYPES = {
    "text/plain",
    "text/x-python",
    "application/javascript",
    "text/typescript",
    "text/x-java-source",
    "text/x-c",
    "application/json",
}
SECURE_SCAN_BASE = Path(tempfile.gettempdir()) / "hybridscan_secure"
SECURE_SCAN_BASE.mkdir(exist_ok=True)

# ── Path / File Validation ─────────────────────────────────────────────────────

def validate_scan_path(target_path: str) -> Optional[Path]:
    """
    Validates and sandboxes a path to prevent path-traversal attacks.
    Returns the safe copy path, or None if the path is rejected.
    """
    try:
        normalized_path = Path(target_path).resolve()
        logger.info(f"Validando ruta: {target_path} -> {normalized_path}")

        dangerous_patterns = ["..", "~", "/etc", "/var", "/root", "/home", "/usr", "/boot"]
        str_path = str(normalized_path).lower()
        for pattern in dangerous_patterns:
            if pattern in str_path and pattern not in ["/home/oscar", "/tmp", "/var/tmp"]:
                logger.warning(f"SECURITY: Ruta rechazada por patrón peligroso '{pattern}': {target_path}")
                return None

        if not normalized_path.exists():
            logger.warning(f"Ruta no existe: {normalized_path}")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        secure_dir = SECURE_SCAN_BASE / f"scan_{timestamp}_{uuid.uuid4().hex[:8]}"
        secure_dir.mkdir(exist_ok=True)

        if normalized_path.is_file():
            secure_file = secure_dir / normalized_path.name
            shutil.copy2(normalized_path, secure_file)
            logger.info(f"Archivo copiado a directorio seguro: {secure_file}")
            return secure_file

        allowed_prefixes = [
            Path.cwd(),
            Path("/tmp"),
            Path("/var/tmp"),
            Path.home() / "Documentos",
            Path.home() / "Downloads",
        ]
        if not any(str(normalized_path).startswith(str(p)) for p in allowed_prefixes):
            logger.warning(f"SECURITY: Ruta fuera de directorios permitidos: {target_path}")
            return None

        secure_target = secure_dir / "target"
        secure_target.mkdir()
        for file_path in normalized_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ALLOWED_EXTENSIONS:
                relative_path = file_path.relative_to(normalized_path)
                dest = secure_target / relative_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, dest)

        logger.info(f"Directorio copiado a área segura: {secure_target}")
        return secure_target

    except Exception as e:
        logger.error(f"Error validando ruta {target_path}: {e}")
        return None


async def validate_uploaded_file(file: UploadFile) -> dict:
    """
    Validates an uploaded file for size, MIME type, filename, and extension.
    Raises HTTPException on any validation failure.
    """
    try:
        logger.info(f"Validando archivo subido: {file.filename}")
        content = await file.read()
        file_size = len(content)
        await file.seek(0)

        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Archivo demasiado grande: {file_size} bytes. Máximo: {MAX_FILE_SIZE} bytes",
            )
        if file_size == 0:
            raise HTTPException(status_code=400, detail="El archivo está vacío")

        if _MAGIC_AVAILABLE:
            try:
                detected_mime = magic.from_buffer(content[:1024], mime=True)
            except Exception:
                detected_mime = mimetypes.guess_type(file.filename)[0] or "application/octet-stream"
        else:
            detected_mime = mimetypes.guess_type(file.filename)[0] or "application/octet-stream"

        if detected_mime not in ALLOWED_MIME_TYPES and not detected_mime.startswith("text/"):
            raise HTTPException(status_code=400, detail=f"Tipo de archivo no permitido: {detected_mime}")

        if not file.filename or ".." in file.filename or "/" in file.filename:
            raise HTTPException(status_code=400, detail="Nombre de archivo no válido")

        file_extension = Path(file.filename).suffix.lower()
        if file_extension not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Extensión no permitida: {file_extension}. Permitidas: {', '.join(ALLOWED_EXTENSIONS)}",
            )

        logger.info(f"Archivo validado correctamente: {file.filename}")
        return {
            "size": file_size,
            "mime_type": detected_mime,
            "filename": file.filename,
            "extension": file_extension,
            "content": content,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validando archivo: {e}")
        raise HTTPException(status_code=500, detail="Error interno validando archivo")


# ── Scan-Result Helpers ────────────────────────────────────────────────────────

def _calculate_severity_breakdown(results: dict) -> dict:
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vulnerabilities = results.get("vulnerabilities", results.get("results", []))
    if not isinstance(vulnerabilities, list):
        return breakdown

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        raw_sev = None
        for key in ("severity", "level", "issue_severity", "issue_confidence", "severity_level"):
            if vuln.get(key) is not None:
                raw_sev = str(vuln[key])
                break
        sev = (raw_sev or "info").strip().lower()
        if sev in ("critical", "crit", "c"):
            breakdown["critical"] += 1
        elif sev in ("high", "h"):
            breakdown["high"] += 1
        elif sev in ("medium", "med", "m", "warning"):
            breakdown["medium"] += 1
        elif sev in ("low", "l"):
            breakdown["low"] += 1
        else:
            breakdown["info"] += 1

    return breakdown


def _extract_owasp_categories(results: dict) -> list:
    categories: set = set()
    vulnerabilities = results.get("vulnerabilities", results.get("results", []))
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                owasp = vuln.get("owasp", vuln.get("category", ""))
                if owasp:
                    categories.add(owasp)
                cwe = str(vuln.get("cwe", ""))
                if "89" in cwe:
                    categories.add("API3:2023")
                elif "79" in cwe:
                    categories.add("API8:2023")
                elif "22" in cwe:
                    categories.add("API1:2023")
    return list(categories)


def update_scan_result(scan_result, results: dict, status: str = "completed", error: str = None) -> None:
    """Updates a ScanResult ORM object in-place with enriched metadata."""
    try:
        scan_result.results = results
        scan_result.status = status
        if error:
            scan_result.error_message = error
            scan_result.status = "failed"

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
                    "owasp_categories_detected": _extract_owasp_categories(results),
                },
            })
    except Exception as e:
        logger.error(f"Error actualizando scan result {getattr(scan_result, 'id', '?')}: {e}")
        scan_result.status = "error"
        scan_result.error_message = f"Error interno: {e}"


# ── Vulnerability Mappers ──────────────────────────────────────────────────────

def map_bandit_to_vulnerability(bandit_issue: dict, file_path: str) -> Vulnerability:
    severity_map = {
        "HIGH": ConfidenceLevel.HIGH,
        "MEDIUM": ConfidenceLevel.MEDIUM,
        "LOW": ConfidenceLevel.LOW,
        "CRITICAL": ConfidenceLevel.CRITICAL,
    }
    severity = severity_map.get(bandit_issue.get("issue_severity", "LOW").upper(), ConfidenceLevel.LOW)
    cwe_info = bandit_issue.get("issue_cwe", {})
    cwe_id = f"CWE-{cwe_info.get('id', '0')}" if isinstance(cwe_info, dict) else "CWE-0"

    test_id = bandit_issue.get("test_id", "")
    vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    if "B201" in test_id or "B608" in test_id:
        vuln_type = VulnerabilityType.SQL_INJECTION
    elif "B105" in test_id or "B106" in test_id:
        vuln_type = VulnerabilityType.SENSITIVE_DATA
    elif "B605" in test_id or "B602" in test_id:
        vuln_type = VulnerabilityType.BROKEN_ACCESS

    return Vulnerability(
        id=f"SAST_{bandit_issue.get('test_id', 'UNKNOWN')}_{bandit_issue.get('line_number', 0)}",
        type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_number=bandit_issue.get("line_number", 0),
        endpoint=f"/api/{Path(file_path).stem}" if file_path else "/unknown",
        description=bandit_issue.get("issue_text", "No description"),
        cwe_id=cwe_id,
        owasp_category="",
        source_tool="bandit",
    )


def map_zap_to_vulnerability(zap_alert: dict) -> Vulnerability:
    severity_map = {
        "CRITICAL": ConfidenceLevel.CRITICAL,
        "HIGH": ConfidenceLevel.HIGH,
        "MEDIUM": ConfidenceLevel.MEDIUM,
        "LOW": ConfidenceLevel.LOW,
    }
    severity = severity_map.get(zap_alert.get("severity", "LOW").upper(), ConfidenceLevel.LOW)

    alert_type = zap_alert.get("type", "").lower()
    vuln_type = VulnerabilityType.SECURITY_MISCONFIG
    if "sql" in alert_type or "injection" in alert_type:
        vuln_type = VulnerabilityType.SQL_INJECTION
    elif "xss" in alert_type or "script" in alert_type:
        vuln_type = VulnerabilityType.XSS
    elif "auth" in alert_type or "session" in alert_type:
        vuln_type = VulnerabilityType.BROKEN_AUTH
    elif "access" in alert_type or "idor" in alert_type:
        vuln_type = VulnerabilityType.BROKEN_ACCESS

    cwe_id = str(zap_alert.get("cwe", "CWE-0"))
    if not cwe_id.startswith("CWE"):
        cwe_id = f"CWE-{cwe_id}"

    return Vulnerability(
        id=f"DAST_{zap_alert.get('type', 'UNKNOWN').replace(' ', '_')}",
        type=vuln_type,
        severity=severity,
        file_path="",
        line_number=0,
        endpoint=zap_alert.get("url", "/"),
        description=zap_alert.get("evidence", zap_alert.get("type", "No description")),
        cwe_id=cwe_id,
        owasp_category="",
        source_tool="zap",
    )
