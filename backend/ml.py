"""Synthetic flow benchmark, explicitly not a real-world efficacy claim."""

import argparse
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

FEATURES = [
    "duration",
    "packets",
    "bytes",
    "frequency",
    "failed_auth",
    "criticality",
    "dst_port",
]


def model_path():
    return Path(os.getenv("MODEL_PATH", "./data/model.joblib"))


def synthetic(seed=42, n=2400):
    rng = np.random.default_rng(seed)
    x = pd.DataFrame(
        {
            "duration": rng.exponential(20, n),
            "packets": rng.integers(1, 1500, n),
            "bytes": rng.integers(60, 500000, n),
            "frequency": rng.integers(1, 160, n),
            "failed_auth": rng.choice([0, 1, 2, 6, 12, 25], n),
            "criticality": rng.integers(1, 6, n),
            "dst_port": rng.choice([22, 53, 80, 443, 3306, 3389, 5432], n),
        }
    )
    # Stochastic labels with overlap; no label, rule output or IP identity in features.
    logit = -3 + x.frequency / 45 + x.failed_auth / 7 + (x.packets > 1200) * 0.5
    y = rng.binomial(1, 1 / (1 + np.exp(-logit)))
    return x, y


def train():
    x, y = synthetic()
    validate_data(x, y)
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, stratify=y, random_state=42
    )
    model = RandomForestClassifier(
        n_estimators=120, max_depth=8, min_samples_leaf=8, random_state=42, n_jobs=1
    )
    baseline = DummyClassifier(strategy="most_frequent")
    model.fit(x_train, y_train)
    baseline.fit(x_train, y_train)
    pred = model.predict(x_test)
    matrix = confusion_matrix(y_test, pred, labels=[0, 1]).tolist()
    metrics = {
        "dataset": "Synthetic stochastic flow benchmark v1; NOT real network validation",
        "seed": 42,
        "train_samples": len(x_train),
        "test_samples": len(x_test),
        "candidate": classification_report(
            y_test, pred, output_dict=True, zero_division=0
        ),
        "baseline": classification_report(
            y_test, baseline.predict(x_test), output_dict=True, zero_division=0
        ),
        "confusion_matrix": matrix,
        "false_positive_rate": matrix[0][1] / max(1, sum(matrix[0])),
        "feature_importance": dict(zip(FEATURES, model.feature_importances_.tolist())),
        "limitations": "Independent synthetic rows only. Not calibrated; temporal/group external validation required before deployment.",
    }
    path = model_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "metrics": metrics}, path)
    path.with_suffix(".json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    from backend.db import ModelMetadata, SessionLocal

    with SessionLocal() as db:
        db.add(ModelMetadata(metrics=metrics))
        db.commit()
    return metrics


def validate_data(x, y):
    if list(x.columns) != FEATURES or len(x) != len(y) or len(x) < 100:
        raise ValueError(
            "Expected at least 100 rows with the documented feature schema"
        )
    if (
        not np.isfinite(x.to_numpy(dtype=float)).all()
        or (x.to_numpy(dtype=float) < 0).any()
    ):
        raise ValueError("Features must be finite and nonnegative")
    if set(np.unique(y)) != {0, 1}:
        raise ValueError(
            "Binary benign/suspicious labels and both classes are required"
        )


_cache = None
_mtime = None


def load():
    global _cache, _mtime
    path = model_path()
    if not path.exists():
        return None
    if _mtime != path.stat().st_mtime_ns:
        _cache = joblib.load(path)  # Only server-owned artifacts; no upload endpoint.
        _mtime = path.stat().st_mtime_ns
    return _cache


def predict(features, dst_port=None):
    bundle = load()
    if not bundle:
        return {
            "available": False,
            "score": None,
            "confidence": None,
            "explanation": "Model unavailable. Run python -m backend.ml after migrations.",
        }
    row = {k: features.get(k, 0) for k in FEATURES}
    row["dst_port"] = dst_port or 0
    p = float(
        bundle["model"].predict_proba(pd.DataFrame([row], columns=FEATURES))[0][1]
    )
    return {
        "available": True,
        "score": round(p * 100, 1),
        "confidence": round(max(p, 1 - p), 3),
        "explanation": "Synthetic-model probability; uncalibrated and independent of rule risk.",
    }


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
