"""SAST scan and file-upload endpoints."""

import json
import logging
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

try:
    from backend.dependencies import BASE_DIR, ScanResult, get_db
    from backend.utils import (
        ALLOWED_EXTENSIONS,
        MAX_FILE_SIZE,
        _calculate_severity_breakdown,
        _extract_owasp_categories,
        update_scan_result,
        validate_scan_path,
        validate_uploaded_file,
    )
except ImportError:
    from dependencies import BASE_DIR, ScanResult, get_db  # type: ignore[no-redef]
    from utils import (  # type: ignore[no-redef]
        ALLOWED_EXTENSIONS,
        MAX_FILE_SIZE,
        _calculate_severity_breakdown,
        _extract_owasp_categories,
        update_scan_result,
        validate_scan_path,
        validate_uploaded_file,
    )

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scan/sast")
def run_sast_scan(
    target_path: str = Form(...),
    tool: str = Form(...),
    db: Session = Depends(get_db),
):
    if tool not in ("bandit", "semgrep"):
        raise HTTPException(status_code=400, detail="Herramienta SAST no soportada. Use 'bandit' o 'semgrep'")

    validated_path = validate_scan_path(target_path)
    if validated_path is None:
        raise HTTPException(
            status_code=400,
            detail="Ruta no válida, fuera de directorios permitidos o contiene patrones peligrosos",
        )

    scan_result = ScanResult(
        scan_type="SAST",
        tool=tool,
        target=str(target_path),
        status="running",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    report_id = str(uuid.uuid4())
    report_dir = Path(BASE_DIR) / "reports"
    report_dir.mkdir(exist_ok=True)

    try:
        if tool == "bandit":
            report_path = report_dir / f"bandit_report_{report_id}.json"
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", str(validated_path), "-f", "json", "-o", str(report_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        else:  # semgrep
            report_path = report_dir / f"semgrep_report_{report_id}.json"
            cmds = [
                [sys.executable, "-m", "semgrep", "--config", "auto", str(validated_path), "--json", "--output", str(report_path)],
                ["semgrep", "--config", "auto", str(validated_path), "--json", "--output", str(report_path)],
            ]
            result = None
            last_exc = None
            for cmd in cmds:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    break
                except FileNotFoundError as exc:
                    last_exc = exc
            if result is None:
                msg = f"Semgrep no está instalado o no se encuentra en PATH. Error: {last_exc}"
                update_scan_result(scan_result, {}, "failed", msg)
                db.commit()
                raise HTTPException(status_code=500, detail=msg)

        if result.returncode not in (0, 1):
            msg = f"Error ejecutando {tool}. returncode={result.returncode}. stderr={result.stderr.strip()}"
            update_scan_result(scan_result, {"raw_stdout": result.stdout, "raw_stderr": result.stderr}, "failed", msg)
            db.commit()
            raise HTTPException(status_code=500, detail=msg)

        if report_path.exists():
            try:
                scan_results = json.loads(report_path.read_text())
            except json.JSONDecodeError:
                scan_results = {"results": [], "message": "Reporte generado pero JSON inválido", "raw_output": result.stdout}
        else:
            scan_results = {"results": [], "message": "No se generó archivo de reporte", "raw_stdout": result.stdout, "raw_stderr": result.stderr}

        update_scan_result(scan_result, scan_results, "completed")
        scan_result.result_path = str(report_path)
        db.commit()

        # Clean up secure temp dir
        try:
            if validated_path.parent.name.startswith("scan_"):
                shutil.rmtree(validated_path.parent)
        except Exception as exc:
            logger.warning(f"No se pudo limpiar directorio temporal: {exc}")

        stored = scan_result.results if isinstance(scan_result.results, dict) else {}
        severity_breakdown = stored.get("severity_breakdown") or _calculate_severity_breakdown(stored or scan_results)
        owasp_categories = (stored.get("metadata") or {}).get("owasp_categories_detected") or _extract_owasp_categories(stored or scan_results)

        return {
            "id": scan_result.id,
            "message": f"Análisis SAST con {tool} completado exitosamente",
            "result_id": scan_result.id,
            "report_path": str(report_path),
            "vulnerabilities_found": stored.get("vulnerabilities_found", len(scan_results.get("results", []))),
            "scan_duration": stored.get("scan_duration_seconds", 0),
            "severity_breakdown": severity_breakdown,
            "owasp_categories": owasp_categories,
        }

    except subprocess.TimeoutExpired:
        msg = f"Timeout ejecutando análisis con {tool} (>5 minutos)"
        update_scan_result(scan_result, {}, "timeout", msg)
        db.commit()
        raise HTTPException(status_code=408, detail=msg)
    except HTTPException:
        raise
    except Exception as exc:
        msg = f"Error inesperado en escaneo SAST: {exc}"
        update_scan_result(scan_result, {}, "error", msg)
        db.commit()
        raise HTTPException(status_code=500, detail=msg)


@router.post("/upload/")
async def upload_code(file: UploadFile = File(...), db: Session = Depends(get_db)):
    file_info = await validate_uploaded_file(file)

    scan_result = ScanResult(
        scan_type="FILE_UPLOAD",
        tool="upload_service",
        target=file_info["filename"],
        status="uploading",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{timestamp}_{uuid.uuid4().hex[:8]}{file_info['extension']}"
    upload_dir = Path(BASE_DIR) / "uploads"
    upload_dir.mkdir(exist_ok=True)
    file_path = upload_dir / safe_filename

    try:
        file_path.write_bytes(file_info["content"])
        if not file_path.exists() or file_path.stat().st_size != file_info["size"]:
            raise IOError(f"Error verificando integridad del archivo guardado: {file_path}")

        upload_results = {
            "original_filename": file_info["filename"],
            "secure_filename": safe_filename,
            "file_size": file_info["size"],
            "mime_type": file_info["mime_type"],
            "file_extension": file_info["extension"],
            "upload_path": str(file_path),
            "integrity_verified": True,
        }
        update_scan_result(scan_result, upload_results, "uploaded")
        scan_result.result_path = str(file_path)
        db.commit()

        return {
            "message": "Archivo subido correctamente",
            "result_id": scan_result.id,
            "file_path": str(file_path),
            "original_filename": file_info["filename"],
            "secure_filename": safe_filename,
            "file_size": file_info["size"],
            "mime_type": file_info["mime_type"],
            "ready_for_scan": True,
        }

    except IOError as exc:
        msg = f"Error de E/S guardando archivo: {exc}"
        update_scan_result(scan_result, {}, "failed", msg)
        db.commit()
        raise HTTPException(status_code=500, detail=msg)
    except HTTPException:
        raise
    except Exception as exc:
        msg = f"Error inesperado en subida de archivo: {exc}"
        update_scan_result(scan_result, {}, "error", msg)
        db.commit()
        raise HTTPException(status_code=500, detail=msg)
