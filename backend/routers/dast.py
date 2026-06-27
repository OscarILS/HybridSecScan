"""
DAST scan endpoint.

The HTTP probing performed by dast_scanner is synchronous and IO-bound.
This router declares the endpoint as async and offloads the actual scan to
FastAPI's thread-pool via run_in_threadpool, keeping the event loop free.

SSRF prevention is applied before any network request is made.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

try:
    from backend.dependencies import BASE_DIR, ScanResult, get_db
    from backend.dast_scanner import run_dast_scan as _probe
    from backend.ssrf_validator import validate_dast_target
except ImportError:
    from dependencies import BASE_DIR, ScanResult, get_db  # type: ignore[no-redef]
    from dast_scanner import run_dast_scan as _probe  # type: ignore[no-redef]
    from ssrf_validator import validate_dast_target  # type: ignore[no-redef]

import os

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scan/dast")
async def run_dast_scan(target_url: str = Form(...), db: Session = Depends(get_db)):
    """
    Runs a real DAST scan against target_url.

    Strategy (priority order):
      1. OWASP ZAP daemon — if running on localhost:8080
      2. HTTPSecurityScanner — active HTTP probing, always available

    SSRF protection rejects any URL resolving to a private/internal address
    before the first network packet is sent.
    """
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL debe comenzar con http:// o https://")

    # ── SSRF check (raises 400 if internal address) ───────────────────────────
    validate_dast_target(target_url)

    logger.info(f"Iniciando escaneo DAST contra: {target_url}")

    try:
        # ── Run blocking I/O in a thread so the event loop stays free ─────────
        dast_result = await run_in_threadpool(_probe, target_url)
        dast_result["timestamp"] = datetime.now(timezone.utc).isoformat()
        dast_result["status"] = "completed"

        logger.info(
            f"DAST completado — tool: {dast_result['tool']}, "
            f"hallazgos: {dast_result['summary']['total_issues']}, "
            f"ZAP: {dast_result.get('zap_available', False)}"
        )

        # ── Persist report ────────────────────────────────────────────────────
        report_id = str(uuid.uuid4())
        report_path = os.path.join(str(BASE_DIR), "reports", f"dast_report_{report_id}.json")
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(dast_result, f, indent=2)

        # ── Persist to DB (back in the coroutine — session is thread-safe here)
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

        return {
            "id": scan_result.id,
            "scan_type": "DAST",
            "tool": dast_result["tool"],
            "zap_available": dast_result.get("zap_available", False),
            "target_url": target_url,
            "status": "completed",
            "vulnerabilities": dast_result.get("vulnerabilities", []),
            "summary": dast_result.get("summary", {}),
            "report_path": report_path,
            "message": "Análisis DAST completado exitosamente",
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error en escaneo DAST: {exc}")
        raise HTTPException(status_code=500, detail=f"Error ejecutando análisis DAST: {exc}")
