# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

HybridSecScan is an academic thesis project (UNMSM, Ingeniería de Software) implementing a hybrid SAST+DAST security auditing system for REST APIs, focused on the OWASP API Security Top 10. The key innovation is an ML-based correlation engine (Random Forest) that combines static and dynamic analysis findings to reduce false positives.

## Development Commands

### Backend
```bash
# Install dependencies
pip install -r requirements.txt

# Start backend server (from repo root)
cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_security_validations.py -v

# Run a specific test class or method
python -m pytest tests/test_security_validations.py::TestSecurityValidations::test_path_traversal_prevention -v

# Lint
flake8 backend/
black backend/
isort backend/
```

### Frontend
```bash
cd frontend
npm install
npm run dev       # Dev server at http://localhost:5173
npm run build     # Production build (runs tsc -b first)
npm run lint      # ESLint
```

### Quick Start (both services)
```bash
chmod +x run_hybridscan.sh && ./run_hybridscan.sh
```

## Architecture

### Backend (`backend/`)
- **`main.py`** — FastAPI app; all API endpoints, file upload/validation logic, subprocess invocation of Bandit/Semgrep, simulated DAST (ZAP placeholder), and JWT auth endpoints.
- **`correlation_engine.py`** — Core ML component. `VulnerabilityCorrelator` takes SAST and DAST `Vulnerability` objects, correlates them using weighted rules and a Random Forest model, and generates a correlation report with false-positive reduction metrics.
- **`auth.py`** — JWT token creation/validation, password hashing with bcrypt, `get_current_active_user` dependency.
- **`pdf_generator.py`** — Generates PDF and JSON summary reports from scan data.
- **`ml_model_manager.py`** / **`train_ml_model.py`** — ML model persistence and training utilities.
- **`evaluation_system.py`** — Comparative evaluation of scan results.
- **`cache_manager.py`** — Caching layer for scan results.

### Database (`database/`)
- SQLite via SQLAlchemy. Two models in `models.py`:
  - `ScanResult` — stores SAST, DAST, HYBRID, and FILE_UPLOAD records with JSON results column.
  - `User` — authentication with hashed passwords.
- DB file: `database/hybridsecscan.db` (auto-created on startup).

### Frontend (`frontend/src/`)
- React 19 + TypeScript + Vite.
- `App.tsx` — main application component (active version).
- `ResearchDashboard.tsx` — research/academic metrics dashboard.
- Uses `recharts` for data visualization.
- Note: `App.tsx.broken` and `App_backup.tsx` are legacy files, not used.

### Scan Flow
1. **SAST**: Upload file via `POST /upload/` → call `POST /scan/sast` with path and tool (`bandit` or `semgrep`) → subprocess runs the tool, saves JSON report to `reports/`, stores in DB.
2. **DAST**: Call `POST /scan/dast` with a URL → `dast_scanner.py` performs real HTTP probing (security headers, CORS, sensitive paths, error disclosure, rate limiting, server info, SSL/TLS). If OWASP ZAP daemon is running on port 8080, also runs spider + active scan.
3. **Hybrid**: Call `POST /scan/hybrid` with SAST and DAST scan IDs → `VulnerabilityCorrelator` maps DB records to `Vulnerability` objects, runs correlation, saves hybrid report.
4. **Reports**: `GET /download/pdf/{scan_id}` and `GET /download/json/{scan_id}` generate downloadable reports.

### Security Constraints
- `validate_scan_path()` in `main.py` enforces path traversal prevention — files are copied to a temp sandbox before scanning.
- Allowed upload extensions: `.py .js .ts .tsx .java .cpp .c .go .php .rb .cs`; max 50MB.
- CORS is configured for `localhost:3000` and `localhost:5173` only.

### Import Pattern
The backend uses try/except dual imports to handle both `cd backend && uvicorn main:app` and `uvicorn backend.main:app` invocation styles:
```python
try:
    from backend.correlation_engine import ...
except ImportError:
    from correlation_engine import ...
```
Maintain this pattern when adding new cross-module imports in `main.py`.

## ML Training Pipeline

The Random Forest correlator must be trained before the `GET /api/model-metrics` endpoint returns real data. The model lives at `data/models/rf_correlator_v1.pkl`.

```bash
# 1. Generate the training dataset (1,300 pairs, 6 categories)
python scripts/generate_training_dataset.py
# → data/processed/{training,validation,test}_set.csv

# 2. Train the Random Forest (517 features, 200 estimators)
python backend/train_ml_model.py
# → data/models/rf_correlator_v1.pkl
# → data/models/metadata.json
# → data/models/visualizations/*.png
```

Dataset design — categories that prevent trivial separability:
- **A) Clean positives**: same type + same module (type_match=1, correlated=1)
- **B) Cross-type positives**: different tool labels for same problem (type_match=0, correlated=1)
- **C) Ambiguous positives**: same type, related modules (boundary cases)
- **D) Hard negatives**: same type + different unrelated modules (type_match=1, correlated=0) ← key
- **E) Clean negatives**: different types
- **F) Tool-only negatives**: SAST-only vs DAST-only findings

Expected metrics after training: Precision ~0.66, Recall ~0.96, F1 ~0.79, ROC-AUC ~0.79. High recall is intentional — security scanners should flag all potential correlations and accept more false alarms rather than miss real threats.

## DAST Scanner

`backend/dast_scanner.py` replaced the original hash-based simulation with real HTTP probing. Public API: `run_dast_scan(target_url: str) -> Dict`. Falls back from ZAP daemon → `HTTPSecurityScanner` automatically. ZAP daemon mode: `zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true`.

## External Tools (Optional)
- **Bandit**: Installed via `requirements.txt`; invoked as `python -m bandit`.
- **Semgrep**: Optional; install with `pip install semgrep`. The code tries `python -m semgrep` first, then falls back to `semgrep` in PATH.
- **OWASP ZAP**: Optional; `dast_scanner.py` tries ZAP first, falls back to HTTP scanner if ZAP daemon is not running.
- **pip on system Python 3.13**: No sudo/venv. Install with `~/.local/bin/pip install -r requirements.txt --user --break-system-packages`.
