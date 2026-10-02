"""
Evaluación del modelo entrenado sobre un conjunto de prueba NUEVO e independiente.

El modelo (data/models/rf_correlator_v1.pkl) se entrenó y validó con la muestra de
semilla 42 (training/validation/test_set.csv). Este script genera una muestra fresca con
OTRA semilla usando el mismo generador (misma distribución sintética, filas independientes
que el modelo nunca vio) y reporta las métricas sobre ella.

Mide la generalización DENTRO del dominio sintético — no sobre salidas reales de
herramientas (eso es el domain shift documentado en los experimentos de correlación).

Uso:
    python scripts/evaluate_holdout.py --seed 7777 --save
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from backend.train_ml_model import CorrelationMLTrainer  # noqa: E402


def build_holdout(seed: int):
    import random

    import generate_training_dataset as gen

    random.seed(seed)
    np.random.seed(seed)
    return gen.generate_dataset()


def main():
    parser = argparse.ArgumentParser(description="Evalúa el modelo sobre una muestra nueva independiente")
    parser.add_argument("--seed", type=int, default=7777, help="Semilla para la muestra nueva (≠ 42)")
    parser.add_argument("--save", action="store_true", help="Guardar JSON de resultados")
    args = parser.parse_args()

    model_path = REPO / "data" / "models" / "rf_correlator_v1.pkl"
    pkg = joblib.load(model_path)

    df = build_holdout(args.seed)
    y = df["is_correlated"].values

    trainer = CorrelationMLTrainer()
    trainer.rf_classifier = pkg["classifier"]
    trainer.tfidf_vectorizer = pkg["tfidf_vectorizer"]
    trainer.label_encoders = pkg["label_encoders"]

    X = trainer.engineer_features(df, fit=False)
    y_pred = trainer.rf_classifier.predict(X)
    y_proba = trainer.rf_classifier.predict_proba(X)[:, 1]

    precision, recall, f1, _ = precision_recall_fscore_support(y, y_pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    result = {
        "holdout_seed": args.seed,
        "n_samples": int(len(df)),
        "n_positives": int(y.sum()),
        "model_version": pkg.get("version"),
        "model_trained_at": pkg.get("trained_at"),
        "metrics": {
            "accuracy": round(float(accuracy_score(y, y_pred)), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc_auc_score(y, y_proba)), 4),
        },
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "note": "Muestra sintética independiente (misma distribución, semilla distinta). Mide generalización dentro del dominio sintético, no transferencia a herramientas reales.",
    }

    print(f"Conjunto nuevo (semilla {args.seed}): {result['n_samples']} pares, {result['n_positives']} positivos")
    m = result["metrics"]
    print(
        f"  Accuracy {m['accuracy']}  Precision {m['precision']}  Recall {m['recall']}  F1 {m['f1_score']}  ROC-AUC {m['roc_auc']}"
    )
    print(f"  Matriz: TN={tn} FP={fp} FN={fn} TP={tp}")

    if args.save:
        out = REPO / "data" / "experiments" / f"holdout_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Guardado: {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
