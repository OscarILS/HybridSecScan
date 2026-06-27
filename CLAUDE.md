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

# Run all tests with coverage
pytest tests/ --cov=backend --cov=database --cov-report=term

# Run a single test file
python -m pytest tests/test_security_validations.py -v

# Run a specific test class or method
python -m pytest tests/test_security_validations.py::TestSecurityValidations::test_path_traversal_prevention -v

# Lint (match CI flags exactly)
flake8 backend/ database/ scripts/ tests/ --max-line-length=120 --ignore=E501,W503
black --check backend/ database/ scripts/ tests/
isort --check-only backend/ database/ scripts/ tests/
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
- **`main.py`** — Thin FastAPI factory: logging, middleware, DB init, router registration. No business logic here.
- **`routers/sast.py`** — `POST /scan/sast` and `POST /upload/` endpoints.
- **`routers/dast.py`** — `POST /scan/dast` (async, runs scan in thread pool via `run_in_threadpool`; SSRF-checked before any network call).
- **`routers/hybrid.py`** — `POST /scan/hybrid` (ML correlation engine).
- **`routers/auth_router.py`** — `POST /auth/register`, `POST /auth/login`, `GET /auth/me`.
- **`routers/reports.py`** — `GET /download/pdf/{scan_id}` and `GET /download/json/{scan_id}`.
- **`dependencies.py`** — SQLAlchemy engine/session factory using an absolute path, `get_db` dependency, `init_db()`. Single source of truth for `BASE_DIR`.
- **`utils.py`** — Shared constants (`ALLOWED_EXTENSIONS`, `MAX_FILE_SIZE`), `validate_scan_path`, `validate_uploaded_file`, `update_scan_result`, severity/OWASP helpers, `map_bandit_to_vulnerability`, `map_zap_to_vulnerability`.
- **`ssrf_validator.py`** — `validate_dast_target(url)`: resolves the hostname via DNS and rejects any URL that maps to RFC1918, loopback, link-local, or other reserved ranges.
- **`correlation_engine.py`** — Core ML component. `VulnerabilityCorrelator` takes SAST and DAST `Vulnerability` objects, correlates them using weighted rules and a Random Forest model, and generates a correlation report with false-positive reduction metrics.
- **`auth.py`** — JWT token creation/validation, password hashing with bcrypt, `get_current_active_user` dependency. Loads `.env` via `python-dotenv`; prints a warning to stderr if `SECRET_KEY` is missing or using the placeholder.
- **`dast_scanner.py`** — Real HTTP probing engine. Public API: `run_dast_scan(target_url: str) -> Dict`. Falls back from ZAP daemon → `HTTPSecurityScanner` automatically.
- **`pdf_generator.py`** — Generates PDF and JSON summary reports from scan data.
- **`ml_model_manager.py`** / **`train_ml_model.py`** — ML model persistence and training utilities.
- **`evaluation_system.py`** — Comparative evaluation of scan results against ground truth.
- **`cache_manager.py`** — Caching layer for scan results.

### Database (`database/`)
- SQLite via SQLAlchemy. Two models in `models.py`:
  - `ScanResult` — stores SAST, DAST, HYBRID, and FILE_UPLOAD records with a JSON `results` column.
  - `User` — authentication with hashed passwords.
- DB file: `database/hybridsecscan.db` (auto-created on startup).

### Frontend (`frontend/src/`)
- React 19 + TypeScript + Vite.
- `App.tsx` — main application component (active version).
- `ResearchDashboard.tsx` — research/academic metrics dashboard (separate component, mounted alongside `App.tsx`).
- Uses `recharts` for data visualization.
- Note: `App.tsx.broken` and `App_backup.tsx` are legacy files, not used.

### Scan Flow
1. **SAST**: Upload file via `POST /upload/` → call `POST /scan/sast` with path and tool (`bandit` or `semgrep`) → subprocess runs the tool, saves JSON report to `reports/`, stores in DB.
2. **DAST**: Call `POST /scan/dast` with a URL → `dast_scanner.py` performs real HTTP probing (security headers, CORS, sensitive paths, error disclosure, rate limiting, server info, SSL/TLS). If OWASP ZAP daemon is running on port 8080, also runs spider + active scan.
3. **Hybrid**: Call `POST /scan/hybrid` with SAST and DAST scan IDs → `VulnerabilityCorrelator` maps DB records to `Vulnerability` objects, runs correlation, saves hybrid report.
4. **Reports**: `GET /download/pdf/{scan_id}` and `GET /download/json/{scan_id}` generate downloadable reports.

### Security Constraints
- `validate_scan_path()` in `utils.py` enforces path traversal prevention — files are copied to a temp sandbox before scanning.
- `validate_dast_target()` in `ssrf_validator.py` blocks DAST scans against RFC1918/loopback/link-local addresses (SSRF prevention).
- Allowed upload extensions: `.py .js .ts .tsx .java .cpp .c .go .php .rb .cs`; max 50MB.
- CORS is configured for `localhost:3000` and `localhost:5173` only.
- `SECRET_KEY` must be set in `.env`. `auth.py` prints a critical warning to stderr if it's missing or using the default placeholder.

### Import Pattern
The backend uses try/except dual imports to handle both `cd backend && uvicorn main:app` and `uvicorn backend.main:app` invocation styles:
```python
try:
    from backend.correlation_engine import ...
except ImportError:
    from correlation_engine import ...
```
Maintain this pattern when adding new cross-module imports in `main.py`.

## Test Suite

Three test files live in `tests/`:
- `test_security_validations.py` — path traversal prevention, file upload validation, CORS, rate limiting.
- `test_auth.py` — JWT creation/validation, login flow, password hashing.
- `test_integration.py` — end-to-end scan flow using FastAPI `TestClient`.

CI runs `test_integration.py` and `test_auth.py` separately as an integration job after the unit tests pass.

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

Real metrics from `data/models/metadata.json` (1,300 samples, 517 features):

| Set        | Accuracy | Precision | Recall | F1    | ROC-AUC |
|------------|----------|-----------|--------|-------|---------|
| Validation | 80.8%    | 69.4%     | 94.3%  | 0.800 | 0.851   |
| Test       | 76.9%    | 66.3%     | 96.5%  | 0.786 | 0.785   |
| Confusion  | TN=45    | FP=28     | FN=2   | TP=55 |         |

High recall (96.5%) is intentional — in security, missing a real vulnerability is worse than a false alarm. The model trades precision for recall. **Never hardcode these values** — `correlation_engine.py` always reads them from `metadata.json` at load time.

## DAST Scanner

`backend/dast_scanner.py` performs real HTTP probing. Public API: `run_dast_scan(target_url: str) -> Dict`. Falls back from ZAP daemon → `HTTPSecurityScanner` automatically. ZAP daemon mode: `zap.sh -daemon -port 8080 -host 127.0.0.1 -config api.disablekey=true`.

## Vulnerable Test Apps (`ProgramasPruebas/`)

This directory contains intentionally vulnerable programs to use as DAST scan targets during development and testing:
- `vulnerable_app.py` — Flask app with SQL injection, XSS, hardcoded secrets, path traversal, and other flaws.
- `vulnerable_js.js` — Node.js app with similar vulnerabilities.
- `launch_vulnerable_apps.bat` / `launch_vulnerable_apps.ps1` — launch scripts.
- `test_urls.txt` — pre-built URL list for DAST testing.

See `ProgramasPruebas/GUIA_PRUEBAS.md` for a full testing walkthrough.

## Experimental Validation Data (`data/experiments/`)

Ground-truth JSON files for four known-vulnerable apps (DVWA, Juice Shop, NodeGoat, WebGoat) live in `data/experiments/ground_truth/`. Bandit/Semgrep scan results against those apps are in `data/experiments/results/`. These are used by `evaluation_system.py` to validate correlation accuracy.

## Standalone Scripts (`scripts/`)

```bash
python scripts/setup.py                          # Generate dataset + train ML model (idempotent)
python scripts/setup.py --force                  # Regenerate everything even if already exists
python scripts/run_bandit.py /path/to/code       # Bandit SAST
python scripts/run_semgrep.py /path/to/code      # Semgrep SAST
python scripts/run_zap.py https://api.example.com  # ZAP DAST
```

## External Tools (Optional)
- **Bandit**: Installed via `requirements.txt`; invoked as `python -m bandit`.
- **Semgrep**: Optional; install with `pip install semgrep`. The code tries `python -m semgrep` first, then falls back to `semgrep` in PATH.
- **OWASP ZAP**: Optional; `dast_scanner.py` tries ZAP first, falls back to HTTP scanner if ZAP daemon is not running.
- **pip on system Python 3.13**: No sudo/venv. Install with `~/.local/bin/pip install -r requirements.txt --user --break-system-packages`.
