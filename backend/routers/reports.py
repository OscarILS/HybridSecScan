"""PDF and JSON report download endpoints."""

import json
import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

try:
    from backend.dependencies import ScanResult, get_db
    from backend.pdf_generator import generate_json_summary, generate_pdf_report
    from backend.utils import _calculate_severity_breakdown
except ImportError:
    from dependencies import ScanResult, get_db  # type: ignore[no-redef]
    from pdf_generator import generate_json_summary, generate_pdf_report  # type: ignore[no-redef]
    from utils import _calculate_severity_breakdown  # type: ignore[no-redef]

router = APIRouter(prefix="/download")
logger = logging.getLogger(__name__)


def _resolve_scan(scan_id: str, db: Session):
    """Accepts either an integer ID or a UUID string (matched against result_path)."""
    try:
        return db.query(ScanResult).filter(ScanResult.id == int(scan_id)).first()
    except (ValueError, TypeError):
        pass
    try:
        uuid.UUID(scan_id)
        return db.query(ScanResult).filter(ScanResult.result_path.like(f"%{scan_id}%")).first()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")


def _parse_results(scan_result) -> dict:
    try:
        return json.loads(scan_result.results) if isinstance(scan_result.results, str) else (scan_result.results or {})
    except (json.JSONDecodeError, TypeError):
        return {"vulnerabilities": []}


@router.get("/pdf/{scan_id}")
def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    scan_result = _resolve_scan(scan_id, db)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = _parse_results(scan_result)

    if scan_result.scan_type == "HYBRID" and "correlation_report" in scan_data:
        corr_report = scan_data["correlation_report"]
        correlations = corr_report.get("correlations", [])
        summary_data = corr_report.get("summary", {})
        sast_id = scan_data.get("sast_scan_id")
        dast_id = scan_data.get("dast_scan_id")

        vulnerabilities = []
        severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        if sast_id:
            sast_scan = db.query(ScanResult).filter(ScanResult.id == sast_id).first()
            if sast_scan:
                sast_data = _parse_results(sast_scan)
                for vuln in sast_data.get("results", []):
                    if not isinstance(vuln, dict):
                        continue
                    sev = str(vuln.get("issue_severity", vuln.get("severity", "low"))).upper()
                    key = "critical" if "CRITICAL" in sev else "high" if "HIGH" in sev else "medium" if "MEDIUM" in sev else "low"
                    severity_distribution[key] += 1
                    vulnerabilities.append({
                        "source": "SAST", "tool": sast_scan.tool,
                        "type": vuln.get("test_name", vuln.get("type", "Unknown")),
                        "severity": vuln.get("issue_severity", vuln.get("severity", "low")),
                        "file": vuln.get("filename", ""), "line": vuln.get("line_number", 0),
                        "description": vuln.get("issue_text", vuln.get("description", "No description")),
                        "cwe": vuln.get("issue_cwe", {}).get("id", ""),
                        "recommendation": vuln.get("more_info", ""),
                    })

        if dast_id:
            dast_scan = db.query(ScanResult).filter(ScanResult.id == dast_id).first()
            if dast_scan:
                dast_data = _parse_results(dast_scan)
                for vuln in dast_data.get("vulnerabilities", []):
                    if not isinstance(vuln, dict):
                        continue
                    sev = str(vuln.get("risk", vuln.get("severity", "low"))).upper()
                    key = "critical" if "CRITICAL" in sev else "high" if "HIGH" in sev else "medium" if "MEDIUM" in sev else "low"
                    severity_distribution[key] += 1
                    vulnerabilities.append({
                        "source": "DAST", "tool": dast_scan.tool,
                        "type": vuln.get("alert", vuln.get("type", "Unknown")),
                        "alert": vuln.get("alert", ""),
                        "severity": vuln.get("risk", vuln.get("severity", "low")),
                        "url": vuln.get("url", ""),
                        "description": vuln.get("description", "No description"),
                        "solution": vuln.get("solution", ""),
                        "cwe": vuln.get("cweid", vuln.get("cwe", "")),
                        "cweid": vuln.get("cweid", vuln.get("cwe", "")),
                        "owasp_category": vuln.get("owasp_category", ""),
                        "evidence": vuln.get("evidence", ""),
                        "parameter": vuln.get("parameter", ""),
                        "request_payload": vuln.get("request_payload", {}),
                    })

        pdf_data = {
            "scan_type": "HYBRID",
            "target": scan_result.target,
            "timestamp": scan_result.created_at.isoformat() if hasattr(scan_result.created_at, "isoformat") else str(scan_result.created_at),
            "vulnerabilities": vulnerabilities,
            "correlations": correlations,
            "summary": severity_distribution,
            "hybrid_metrics": {
                "total_sast": summary_data.get("total_sast_findings", 0),
                "total_dast": summary_data.get("total_dast_findings", 0),
                "fp_reduction": summary_data.get("potential_false_positives_reduced", 0),
            },
        }
    else:
        raw_vulns = scan_data.get("results", scan_data.get("vulnerabilities", [])) if isinstance(scan_data, dict) else []
        vulnerabilities = []

        if scan_result.scan_type == "SAST":
            for v in raw_vulns:
                if isinstance(v, dict):
                    vulnerabilities.append({
                        "type": v.get("test_name", "Unknown"), "severity": v.get("issue_severity", "low"),
                        "file": v.get("filename", ""), "line": v.get("line_number", 0),
                        "description": v.get("issue_text", "No description"),
                        "cwe": v.get("issue_cwe", {}).get("id", ""), "recommendation": v.get("more_info", ""),
                    })
        else:
            for v in raw_vulns:
                if isinstance(v, dict):
                    vulnerabilities.append({
                        "type": v.get("alert", v.get("type", "Unknown")),
                        "severity": v.get("risk", v.get("severity", "low")),
                        "url": v.get("url", ""), "description": v.get("description", "No description"),
                        "solution": v.get("solution", ""),
                        "cwe": v.get("cweid", v.get("cwe", "")),
                        "cweid": v.get("cweid", v.get("cwe", "")),
                        "owasp_category": v.get("owasp_category", ""),
                        "evidence": v.get("evidence", ""), "parameter": v.get("parameter", ""),
                        "source": v.get("source", ""), "alert": v.get("alert", ""),
                        "request_payload": v.get("request_payload", {}),
                    })

        for v in vulnerabilities:
            if isinstance(v, dict):
                v["severity"] = str(v.get("severity") or "info").lower()

        stored_breakdown = scan_data.get("severity_breakdown") or scan_data.get("summary") if isinstance(scan_data, dict) else None
        if isinstance(stored_breakdown, dict):
            summary = {k: int(stored_breakdown.get(k, 0)) for k in ("critical", "high", "medium", "low")}
        else:
            summary = _calculate_severity_breakdown({"vulnerabilities": vulnerabilities})

        pdf_data = {
            "scan_type": scan_result.scan_type,
            "target": scan_result.target,
            "timestamp": scan_result.created_at.isoformat() if hasattr(scan_result.created_at, "isoformat") else str(scan_result.created_at),
            "vulnerabilities": vulnerabilities,
            "summary": summary,
        }

    try:
        pdf_bytes = generate_pdf_report(pdf_data)
        filename = f"HybridSecScan_Report_{scan_result.scan_type.upper()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as exc:
        logger.error(f"Error al generar PDF: {exc}")
        raise HTTPException(status_code=500, detail=f"Error al generar PDF: {exc}")


@router.get("/json/{scan_id}")
def download_json_summary(scan_id: str, db: Session = Depends(get_db)):
    scan_result = _resolve_scan(scan_id, db)
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = _parse_results(scan_result)
    pdf_data = {
        "scan_type": scan_result.scan_type,
        "target": scan_result.target,
        "timestamp": scan_result.created_at.isoformat() if hasattr(scan_result.created_at, "isoformat") else str(scan_result.created_at),
        "vulnerabilities": scan_data.get("vulnerabilities", []),
        "summary": {},
    }

    try:
        json_summary = generate_json_summary(pdf_data)
        filename = f"HybridSecScan_Summary_{scan_result.scan_type.upper()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        return StreamingResponse(
            iter([json.dumps(json_summary, indent=2).encode()]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as exc:
        logger.error(f"Error al generar JSON: {exc}")
        raise HTTPException(status_code=500, detail=f"Error al generar JSON: {exc}")
