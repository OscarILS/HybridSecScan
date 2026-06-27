"""Hybrid scan endpoint — correlates SAST + DAST findings with the ML engine."""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session

try:
    from backend.correlation_engine import VulnerabilityCorrelator
    from backend.dependencies import BASE_DIR, ScanResult, get_db
    from backend.utils import map_bandit_to_vulnerability, map_zap_to_vulnerability
except ImportError:
    from correlation_engine import VulnerabilityCorrelator  # type: ignore[no-redef]
    from dependencies import BASE_DIR, ScanResult, get_db  # type: ignore[no-redef]
    from utils import map_bandit_to_vulnerability, map_zap_to_vulnerability  # type: ignore[no-redef]

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scan/hybrid")
def run_hybrid_scan(
    sast_scan_id: int = Form(...),
    dast_scan_id: int = Form(...),
    db: Session = Depends(get_db),
):
    try:
        sast_record = db.query(ScanResult).filter(ScanResult.id == sast_scan_id).first()
        if not sast_record or sast_record.scan_type != "SAST":
            raise HTTPException(status_code=404, detail=f"Escaneo SAST {sast_scan_id} no encontrado")

        dast_record = db.query(ScanResult).filter(ScanResult.id == dast_scan_id).first()
        if not dast_record or dast_record.scan_type != "DAST":
            raise HTTPException(status_code=404, detail=f"Escaneo DAST {dast_scan_id} no encontrado")

        sast_data = sast_record.results if isinstance(sast_record.results, dict) else json.loads(sast_record.results)
        dast_data = dast_record.results if isinstance(dast_record.results, dict) else json.loads(dast_record.results)

        correlator = VulnerabilityCorrelator()

        sast_vulns = []
        for issue in sast_data.get("results", []):
            if isinstance(issue, dict):
                try:
                    sast_vulns.append(map_bandit_to_vulnerability(issue, sast_record.target))
                except Exception as exc:
                    logger.warning(f"Error mapeando hallazgo SAST: {exc}")

        dast_vulns = []
        for alert in dast_data.get("vulnerabilities", []):
            if isinstance(alert, dict):
                try:
                    dast_vulns.append(map_zap_to_vulnerability(alert))
                except Exception as exc:
                    logger.warning(f"Error mapeando hallazgo DAST: {exc}")

        correlator.add_sast_findings(sast_vulns)
        correlator.add_dast_findings(dast_vulns)
        correlation_report = correlator.generate_correlation_report()

        report_id = str(uuid.uuid4())
        report_path = Path(BASE_DIR) / "reports" / f"hybrid_report_{report_id}.json"
        hybrid_data = {
            "scan_type": "HYBRID",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sast_scan_id": sast_scan_id,
            "dast_scan_id": dast_scan_id,
            "correlation_report": correlation_report,
            "model_metrics": correlator.model_metrics,
        }
        report_path.write_text(json.dumps(hybrid_data, indent=2))

        scan_result = ScanResult(
            scan_type="HYBRID",
            tool="HybridSecScan Correlator",
            target=f"SAST:{sast_scan_id} + DAST:{dast_scan_id}",
            status="completed",
            result_path=str(report_path),
            results=hybrid_data,
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)

        return {
            "id": scan_result.id,
            "scan_type": "HYBRID",
            "sast_scan_id": sast_scan_id,
            "dast_scan_id": dast_scan_id,
            "status": "completed",
            "summary": correlation_report["summary"],
            "correlations": correlation_report["correlations"],
            "model_metrics": correlator.model_metrics,
            "report_path": str(report_path),
            "message": "Análisis híbrido con correlación completado exitosamente",
        }

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error en análisis híbrido: {exc}")
        raise HTTPException(status_code=500, detail=f"Error en análisis híbrido: {exc}")
