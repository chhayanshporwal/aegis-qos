#!/usr/bin/env python3
"""
AegisQoS Module 1 — Train Flow Classifier

Generates a synthetic L3/L4 flow-statistics dataset that emulates real traffic
classes using ONLY statistical metadata (zero DPI):
  - packet_size_mean, packet_size_std
  - iat_mean (inter-arrival time mean), iat_std
  - packets_per_window (count in 500ms window)
  - protocol (6=TCP, 17=UDP)
  - flow_duration_ms

Trains a LightGBM multiclass classifier and exports:
  - models/flow_classifier_lgbm.pkl  (scikit-learn compatible)
  - models/flow_classifier.onnx      (ONNX inference)

Traffic classes:
  0 = realtime_voice   (VoIP, video calls)
  1 = interactive_video (streaming, live video)
  2 = responsive_web    (web browsing, API calls)
  3 = bulk_transfer     (downloads, backups, updates)
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import lightgbm as lgb

# ONNX export (use onnxmltools for LightGBM support)
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType

# ── Feature engineering constants ──────────────────────────────────────────
FEATURE_NAMES = [
    "packet_size_mean",
    "packet_size_std",
    "iat_mean_ms",
    "iat_std_ms",
    "packets_per_window",
    "protocol",         # 6=TCP, 17=UDP
    "flow_duration_ms",
]

CLASS_NAMES = [
    "realtime_voice",
    "interactive_video",
    "responsive_web",
    "bulk_transfer",
]

NUM_CLASSES = len(CLASS_NAMES)
SAMPLES_PER_CLASS = 3000
RANDOM_SEED = 42


def generate_synthetic_dataset(n_per_class: int = SAMPLES_PER_CLASS,
                                seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Generate synthetic L3/L4 statistical flow features per traffic class."""
    rng = np.random.RandomState(seed)
    records = []

    for _ in range(n_per_class):
        # ── Class 0: realtime_voice (VoIP) ──
        records.append({
            "packet_size_mean": rng.normal(180, 30),
            "packet_size_std": rng.exponential(15),
            "iat_mean_ms": rng.normal(20, 5),
            "iat_std_ms": rng.exponential(3),
            "packets_per_window": rng.randint(20, 35),
            "protocol": 17,  # UDP
            "flow_duration_ms": rng.normal(450, 40),
            "label": 0,
        })

        # ── Class 1: interactive_video (streaming/live) ──
        records.append({
            "packet_size_mean": rng.normal(1100, 200),
            "packet_size_std": rng.normal(300, 80),
            "iat_mean_ms": rng.normal(8, 3),
            "iat_std_ms": rng.exponential(4),
            "packets_per_window": rng.randint(40, 80),
            "protocol": rng.choice([6, 17], p=[0.4, 0.6]),
            "flow_duration_ms": rng.normal(490, 15),
            "label": 1,
        })

        # ── Class 2: responsive_web (browsing, APIs) ──
        records.append({
            "packet_size_mean": rng.normal(600, 250),
            "packet_size_std": rng.normal(350, 100),
            "iat_mean_ms": rng.normal(50, 30),
            "iat_std_ms": rng.normal(40, 20),
            "packets_per_window": rng.randint(5, 25),
            "protocol": 6,  # TCP
            "flow_duration_ms": rng.normal(300, 100),
            "label": 2,
        })

        # ── Class 3: bulk_transfer (downloads, backups) ──
        records.append({
            "packet_size_mean": rng.normal(1400, 60),
            "packet_size_std": rng.exponential(30),
            "iat_mean_ms": rng.normal(1.5, 0.8),
            "iat_std_ms": rng.exponential(0.5),
            "packets_per_window": rng.randint(80, 200),
            "protocol": 6,  # TCP
            "flow_duration_ms": rng.normal(500, 5),
            "label": 3,
        })

    df = pd.DataFrame(records)
    # Clamp to positive values (physical reality)
    for col in FEATURE_NAMES:
        df[col] = df[col].clip(lower=0.01)
    return df


def train_and_export(output_dir: str = "models"):
    """Train LightGBM classifier and export pkl + ONNX artifacts."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("═" * 60)
    print(" AegisQoS — Flow Classifier Training")
    print("═" * 60)

    # 1. Generate dataset
    print("\n[1/5] Generating synthetic L3/L4 flow dataset …")
    df = generate_synthetic_dataset()
    print(f"      Total samples: {len(df)}  |  Classes: {NUM_CLASSES}")
    print(f"      Features: {FEATURE_NAMES}")

    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df["label"].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )
    print(f"      Train: {len(X_train)}  |  Test: {len(X_test)}")

    # 2. Train LightGBM
    print("\n[2/5] Training LightGBM classifier …")
    model = lgb.LGBMClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        num_leaves=31,
        objective="multiclass",
        num_class=NUM_CLASSES,
        random_state=RANDOM_SEED,
        verbose=-1,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # 3. Evaluate
    print("\n[3/5] Evaluating on held-out test set …")
    y_pred = model.predict(X_test)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    report = classification_report(
        y_test, y_pred, target_names=CLASS_NAMES, digits=4
    )
    print(report)
    print(f"  ➜ Macro-F1: {macro_f1:.4f}")
    if macro_f1 < 0.90:
        print("  ⚠ WARNING: Macro-F1 < 0.90 — model may underperform.")
    else:
        print("  ✓ PASSED: Macro-F1 ≥ 0.90")

    # 4. Save pickle
    print("\n[4/5] Exporting LightGBM pickle …")
    pkl_path = out / "flow_classifier_lgbm.pkl"
    with open(pkl_path, "wb") as f:
        pickle.dump(model, f)
    print(f"      Saved: {pkl_path}")

    # 5. Export ONNX
    print("\n[5/5] Exporting ONNX model …")
    onnx_path = out / "flow_classifier.onnx"
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model = convert_lightgbm(
        model,
        initial_types=initial_type,
        target_opset=15,
    )
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"      Saved: {onnx_path}")

    # Save metadata
    meta = {
        "feature_names": FEATURE_NAMES,
        "class_names": CLASS_NAMES,
        "macro_f1": round(macro_f1, 4),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "model_type": "LightGBM",
        "onnx_opset": 15,
    }
    meta_path = out / "classifier_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"      Metadata: {meta_path}")

    print("\n" + "═" * 60)
    print(" Training COMPLETE")
    print("═" * 60)

    return macro_f1


if __name__ == "__main__":
    model_dir = sys.argv[1] if len(sys.argv) > 1 else "models"
    f1 = train_and_export(model_dir)
    sys.exit(0 if f1 >= 0.90 else 1)
