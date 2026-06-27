"""
HybridSecScan setup script — generates training data and trains the ML model
if either artefact is missing.  Safe to re-run: skips steps that are already done.

Usage:
    python scripts/setup.py           # run from repo root
    python scripts/setup.py --force   # regenerate everything
"""

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TRAINING_CSV = REPO_ROOT / "data" / "processed" / "training_set.csv"
MODEL_PKL = REPO_ROOT / "data" / "models" / "rf_correlator_v1.pkl"
METADATA_JSON = REPO_ROOT / "data" / "models" / "metadata.json"

DATASET_SCRIPT = REPO_ROOT / "scripts" / "generate_training_dataset.py"
TRAIN_SCRIPT = REPO_ROOT / "backend" / "train_ml_model.py"


def _run(script: Path, label: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    result = subprocess.run([sys.executable, str(script)], check=False)
    if result.returncode != 0:
        print(f"\nERROR: '{label}' falló con código {result.returncode}.", file=sys.stderr)
        sys.exit(result.returncode)
    print(f"  OK — {label} completado.")


def main() -> None:
    parser = argparse.ArgumentParser(description="HybridSecScan ML setup")
    parser.add_argument("--force", action="store_true", help="Regenerar aunque los archivos ya existan")
    args = parser.parse_args()

    print("\nHybridSecScan — ML Setup")
    print(f"Repo: {REPO_ROOT}\n")

    # ── Step 1: training dataset ──────────────────────────────────────────────
    if args.force or not TRAINING_CSV.exists():
        _run(DATASET_SCRIPT, "Generando dataset de entrenamiento")
    else:
        print(f"[OK] Dataset ya existe: {TRAINING_CSV.relative_to(REPO_ROOT)}")

    # ── Step 2: train model ───────────────────────────────────────────────────
    if args.force or not MODEL_PKL.exists() or not METADATA_JSON.exists():
        _run(TRAIN_SCRIPT, "Entrenando modelo Random Forest")
    else:
        print(f"[OK] Modelo ya existe: {MODEL_PKL.relative_to(REPO_ROOT)}")

    print("\n✓ Setup completado. El endpoint /api/model-metrics ya retorna métricas reales.\n")


if __name__ == "__main__":
    main()
