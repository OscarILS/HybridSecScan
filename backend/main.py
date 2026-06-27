"""
HybridSecScan — FastAPI application factory.

Thin entry point: sets up logging, creates the app, attaches middleware,
initialises the DB, and includes all feature routers.  Business logic lives
in the routers/ package; shared helpers in utils.py / dependencies.py.
"""

import json
import logging
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

try:
    from backend.dependencies import BASE_DIR, Base, ScanResult, get_db, init_db  # noqa: F401
    from backend.routers import auth_router, dast, hybrid, reports, sast
    # Re-export names the test suite imports directly from main
    from backend.utils import (  # noqa: F401
        ALLOWED_EXTENSIONS,
        MAX_FILE_SIZE,
        validate_scan_path,
        validate_uploaded_file,
    )
except ImportError:
    from dependencies import BASE_DIR, Base, ScanResult, get_db, init_db  # type: ignore[no-redef]  # noqa: F401
    from routers import auth_router, dast, hybrid, reports, sast  # type: ignore[no-redef]
    from utils import (  # noqa: F401  # type: ignore[no-redef]
        ALLOWED_EXTENSIONS,
        MAX_FILE_SIZE,
        validate_scan_path,
        validate_uploaded_file,
    )

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
    handlers=[
        logging.FileHandler("hybridscan_audit.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="HybridSecScan API",
    description="Sistema de auditoría automatizada híbrida (SAST + DAST) para APIs REST",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── DB init ───────────────────────────────────────────────────────────────────

init_db()

# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(sast.router)
app.include_router(dast.router)
app.include_router(hybrid.router)
app.include_router(auth_router.router)
app.include_router(reports.router)

# ── Core endpoints ────────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return {"message": "Bienvenido a HybridSecScan API - Sistema de auditoría automatizada OWASP API Top 10"}


@app.get("/health")
def health_check():
    return {"status": "healthy", "message": "HybridSecScan API funcionando correctamente"}


@app.get("/scan-results")
def get_scan_results(db: Session = Depends(get_db)):
    results = db.query(ScanResult).all()
    return [
        {"id": r.id, "scan_type": r.scan_type, "tool": r.tool, "result_path": r.result_path, "created_at": r.created_at}
        for r in results
    ]


@app.get("/api/model-metrics")
def get_model_metrics():
    """
    Returns real ML model metrics.  If the model hasn't been trained yet,
    returns model_available=False with instructions.
    Run:  python scripts/setup.py   to generate data and train automatically.
    """
    metadata_path = Path(BASE_DIR) / "data" / "models" / "metadata.json"

    if not metadata_path.exists():
        return {
            "model_available": False,
            "message": (
                "Modelo no entrenado. Ejecuta:\n"
                "  python scripts/setup.py\n"
                "O manualmente:\n"
                "  python scripts/generate_training_dataset.py\n"
                "  python backend/train_ml_model.py"
            ),
        }

    metadata = json.loads(metadata_path.read_text())
    return {
        "model_available": True,
        "metrics": metadata.get("test", {}),
        "validation": metadata.get("validation", {}),
        "confusion_matrix": metadata.get("confusion_matrix", {}),
        "training_info": metadata.get("training_info", {}),
    }
