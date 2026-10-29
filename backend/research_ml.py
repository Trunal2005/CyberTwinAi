"""Local user-supplied CIC-style CSV evaluation; never downloads a dataset."""

import argparse
import hashlib
import json
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import classification_report, confusion_matrix

FEATURES = ["duration", "packets", "bytes", "dst_port"]


def evaluate(
    path,
    output,
    group_column,
    label_column="Label",
    provenance="User supplied; provenance must be documented",
    max_rows=100000,
):
    path = Path(path)
    if path.stat().st_size > 100_000_000:
        raise ValueError(
            "CSV exceeds 100 MB research limit; supply a documented local subset"
        )
    data = pd.read_csv(path, nrows=max_rows + 1)
    data.columns = data.columns.str.strip()
    if len(data) > max_rows:
        raise ValueError("Research row limit exceeded; choose a documented subset")
    if label_column not in data or group_column not in data:
        raise ValueError(
            "Label and independent capture/host/day group columns are required"
        )
    if set(FEATURES).issubset(data):
        x = data[FEATURES].apply(pd.to_numeric, errors="coerce")
    else:
        required = [
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Destination Port",
        ]
        if not set(required).issubset(data):
            raise ValueError(
                "Expected normalized v1 features or documented CICFlowMeter column names"
            )
        v = data[required].apply(pd.to_numeric, errors="coerce")
        x = pd.DataFrame(
            {
                "duration": v["Flow Duration"] / 1_000_000,
                "packets": v["Total Fwd Packets"] + v["Total Backward Packets"],
                "bytes": v["Total Length of Fwd Packets"]
                + v["Total Length of Bwd Packets"],
                "dst_port": v["Destination Port"],
            }
        )
    y = (
        data[label_column]
        .astype(str)
        .str.strip()
        .str.lower()
        .map(lambda s: 0 if s in ("benign", "normal", "0") else 1)
    )
    valid = (
        np.isfinite(x.to_numpy()).all(axis=1)
        & (x >= 0).all(axis=1)
        & data[group_column].notna()
        & data[label_column].notna()
    )
    valid = (
        valid
        & (x.dst_port <= 65535)
        & (x.dst_port % 1 == 0)
        & (x.packets % 1 == 0)
        & (x.bytes % 1 == 0)
    )
    dropped = int((~valid).sum())
    x = x[valid]
    y = y[valid]
    groups = data.loc[valid, group_column].astype(str)
    # Remove identical feature rows before splitting; contradictory duplicate labels are rejected.
    hashes = pd.util.hash_pandas_object(x, index=False)
    if pd.DataFrame({"h": hashes, "y": y}).groupby("h").y.nunique().max() > 1:
        raise ValueError(
            "Identical features have conflicting labels; review source quality"
        )
    keep = ~hashes.duplicated()
    duplicates = int((~keep).sum())
    x = x[keep]
    y = y[keep]
    groups = groups[keep]
    if len(x) < 100 or groups.nunique() < 2:
        raise ValueError("Need at least 100 clean rows and two independent groups")
    train, test = next(
        GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42).split(
            x, y, groups
        )
    )
    if set(y.iloc[train]) != {0, 1} or set(y.iloc[test]) != {0, 1}:
        raise ValueError("Both classes must occur in both group-disjoint partitions")
    results = {}
    models = {
        "majority": DummyClassifier(strategy="most_frequent"),
        "linear": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=1000, random_state=42)
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=120, max_depth=8, min_samples_leaf=8, random_state=42, n_jobs=1
        ),
    }
    for name, m in models.items():
        started = time.perf_counter()
        m.fit(x.iloc[train], y.iloc[train])
        fitted = time.perf_counter() - started
        started = time.perf_counter()
        pred = m.predict(x.iloc[test])
        inferred = time.perf_counter() - started
        cm = confusion_matrix(y.iloc[test], pred, labels=[0, 1]).tolist()
        results[name] = {
            "report": classification_report(
                y.iloc[test], pred, output_dict=True, zero_division=0
            ),
            "confusion_matrix": cm,
            "false_positive_rate": cm[0][1] / sum(cm[0]),
            "false_negative_rate": cm[1][0] / sum(cm[1]),
            "training_seconds": fitted,
            "test_inference_seconds": inferred,
        }
    metrics = {
        "dataset": provenance,
        "input_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "feature_schema": "network-core-v1",
        "model_version": "research-rf-core-v1",
        "feature_definitions": {
            "duration": "seconds",
            "packets": "forward + backward packet count",
            "bytes": "source flow byte counters; verify source semantics",
            "dst_port": "observed destination port",
        },
        "train_samples": len(train),
        "test_samples": len(test),
        "group_column": group_column,
        "train_groups": sorted(set(groups.iloc[train])),
        "test_groups": sorted(set(groups.iloc[test])),
        "dropped_invalid_rows": dropped,
        "removed_duplicate_features": duplicates,
        "class_distribution": {str(k): int(v) for k, v in y.value_counts().items()},
        "models": results,
        "candidate": results["random_forest"]["report"],
        "baseline": results["majority"]["report"],
        "confusion_matrix": results["random_forest"]["confusion_matrix"],
        "false_positive_rate": results["random_forest"]["false_positive_rate"],
        "false_negative_rate": results["random_forest"]["false_negative_rate"],
        "feature_importance": dict(
            zip(FEATURES, models["random_forest"].feature_importances_.tolist())
        ),
        "limitations": "User-supplied group semantics must be independently checked. Four-feature subset; no real-world performance claim. Rule IDS is a separate operational baseline, not evaluated using unavailable authentication history.",
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": models["random_forest"],
            "metrics": metrics,
            "features": FEATURES,
            "imputation": x.iloc[train].mean().to_dict(),
        },
        output,
    )
    output.with_suffix(".json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    return metrics


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("csv")
    p.add_argument("--group-column", required=True)
    p.add_argument("--label-column", default="Label")
    p.add_argument("--provenance", required=True)
    p.add_argument("--output", default="data/research-model.joblib")
    args = p.parse_args()
    print(
        json.dumps(
            evaluate(
                args.csv,
                args.output,
                args.group_column,
                args.label_column,
                args.provenance,
            ),
            indent=2,
        )
    )
