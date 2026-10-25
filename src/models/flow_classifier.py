#!/usr/bin/env python3
"""
AegisQoS Module 1 — Flow Classifier (Inference)

500ms sliding-window statistical classifier using ONNX Runtime.
Zero DPI: only L3/L4 metadata (packet sizes, IATs, protocol, counts).

Features:
  - ONNX Runtime inference with confidence scores in [0, 1]
  - Deterministic fallback when confidence < CONFIDENCE_THRESHOLD (0.65)
  - Manual override support via override_map {flow_id: class_label}
  - Thread-safe sliding window per flow
"""

import os
import time
import pickle
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import numpy as np

try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False

# ── Constants ──────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "packet_size_mean",
    "packet_size_std",
    "iat_mean_ms",
    "iat_std_ms",
    "packets_per_window",
    "protocol",
    "flow_duration_ms",
]

CLASS_NAMES = [
    "realtime_voice",      # 0
    "interactive_video",   # 1
    "responsive_web",      # 2
    "bulk_transfer",       # 3
]

CONFIDENCE_THRESHOLD = float(os.environ.get("CLASSIFIER_CONFIDENCE_THRESHOLD", "0.65"))
WINDOW_MS = 500  # sliding window duration in milliseconds


class FlowWindow:
    """Accumulates per-flow packet metadata within a 500ms sliding window."""

    def __init__(self):
        self.packets: List[Tuple[float, int, int]] = []  # (timestamp_ms, size_bytes, protocol)
        self.lock = threading.Lock()

    def add_packet(self, timestamp_ms: float, size_bytes: int, protocol: int):
        with self.lock:
            # Evict packets older than WINDOW_MS
            cutoff = timestamp_ms - WINDOW_MS
            self.packets = [(t, s, p) for t, s, p in self.packets if t >= cutoff]
            self.packets.append((timestamp_ms, size_bytes, protocol))

    def extract_features(self) -> Optional[np.ndarray]:
        """Extract L3/L4 statistical features from the current window.

        Returns None if insufficient packets (< 3).
        """
        with self.lock:
            if len(self.packets) < 3:
                return None

            now = self.packets[-1][0]
            cutoff = now - WINDOW_MS
            window = [(t, s, p) for t, s, p in self.packets if t >= cutoff]

            if len(window) < 3:
                return None

            sizes = np.array([s for _, s, _ in window], dtype=np.float32)
            times = np.array([t for t, _, _ in window], dtype=np.float64)
            protocols = [p for _, _, p in window]

            # Inter-arrival times
            iats = np.diff(times)

            features = np.array([
                float(np.mean(sizes)),           # packet_size_mean
                float(np.std(sizes)),            # packet_size_std
                float(np.mean(iats)) if len(iats) > 0 else 0.0,   # iat_mean_ms
                float(np.std(iats)) if len(iats) > 0 else 0.0,    # iat_std_ms
                float(len(window)),              # packets_per_window
                float(max(set(protocols), key=protocols.count)),    # dominant protocol
                float(times[-1] - times[0]),     # flow_duration_ms
            ], dtype=np.float32)

            return features


def _deterministic_fallback(features: np.ndarray) -> int:
    """Rule-based classifier when ML confidence is below threshold.

    Uses simple heuristics on L3/L4 statistical features:
      - Small packets + UDP + regular IAT → realtime_voice
      - Large packets + high rate → bulk_transfer
      - Large packets + UDP → interactive_video
      - Everything else → responsive_web
    """
    pkt_size_mean = features[0]
    iat_mean = features[2]
    pkt_count = features[4]
    protocol = features[5]

    if protocol == 17 and pkt_size_mean < 400 and iat_mean < 40:
        return 0  # realtime_voice
    if pkt_size_mean > 1000 and pkt_count > 60:
        return 3  # bulk_transfer
    if protocol == 17 and pkt_size_mean > 800:
        return 1  # interactive_video
    if pkt_size_mean > 1200 and iat_mean < 5:
        return 3  # bulk_transfer
    return 2  # responsive_web


class FlowClassifier:
    """Module 1: Zero-DPI Flow Classifier with ONNX inference.

    Attributes:
        override_map: Dict mapping flow_id to forced class label (manual override).
    """

    def __init__(self, onnx_path: str = "models/flow_classifier.onnx",
                 pkl_path: str = "models/flow_classifier_lgbm.pkl",
                 confidence_threshold: float = CONFIDENCE_THRESHOLD):
        self.confidence_threshold = confidence_threshold
        self.override_map: Dict[str, int] = {}
        self._flow_windows: Dict[str, FlowWindow] = defaultdict(FlowWindow)
        self._lock = threading.Lock()
        self._session = None
        self._pkl_model = None

        # Try ONNX first, fall back to pickle
        if HAS_ONNX and os.path.exists(onnx_path):
            self._session = ort.InferenceSession(
                onnx_path,
                providers=["CPUExecutionProvider"],
            )
            self._input_name = self._session.get_inputs()[0].name
            print(f"[FlowClassifier] Loaded ONNX model: {onnx_path}")
        elif os.path.exists(pkl_path):
            with open(pkl_path, "rb") as f:
                self._pkl_model = pickle.load(f)
            print(f"[FlowClassifier] Loaded pickle model: {pkl_path}")
        else:
            print("[FlowClassifier] WARNING: No model found — deterministic fallback only")

    def add_packet(self, flow_id: str, timestamp_ms: float,
                   size_bytes: int, protocol: int):
        """Ingest a packet's L3/L4 metadata into the flow's sliding window."""
        self._flow_windows[flow_id].add_packet(timestamp_ms, size_bytes, protocol)

    def record_packet(self, flow_id: str, timestamp_ms: float,
                      pkt_len: int, proto: int):
        """Record packet metadata (alias for add_packet)."""
        self.add_packet(flow_id, timestamp_ms, pkt_len, proto)

    def get_active_flow_ids(self, active_within_ms: float = 3000.0) -> List[str]:
        """Return list of flow_ids that had packets within the last active_within_ms."""
        now = time.time() * 1000.0
        active = []
        for flow_id, win in list(self._flow_windows.items()):
            with win.lock:
                if win.packets and (now - win.packets[-1][0]) <= active_within_ms:
                    active.append(flow_id)
        return active

    def classify(self, flow_id: str,
                 features: Optional[np.ndarray] = None
                 ) -> Tuple[int, float, str]:
        """Classify a flow.

        Args:
            flow_id: Unique flow identifier (e.g. 5-tuple hash).
            features: Pre-computed feature vector, or None to extract from window.

        Returns:
            (class_label, confidence, method) where method is one of:
            "onnx", "pkl", "deterministic_fallback", "manual_override"
        """
        # 1. Check manual override first
        if flow_id in self.override_map:
            label = self.override_map[flow_id]
            return label, 1.0, "manual_override"

        # 2. Extract features if not provided
        if features is None:
            window = self._flow_windows.get(flow_id)
            if window is None:
                return 2, 0.0, "deterministic_fallback"  # default: responsive_web
            features = window.extract_features()
            if features is None:
                return 2, 0.0, "deterministic_fallback"

        # 3. ML inference
        class_label, confidence, method = self._infer(features)

        # 4. Deterministic fallback if confidence < threshold
        if confidence < self.confidence_threshold:
            fb_label = _deterministic_fallback(features)
            return fb_label, confidence, "deterministic_fallback"

        return class_label, confidence, method

    def _infer(self, features: np.ndarray) -> Tuple[int, float, str]:
        """Run ML inference on a feature vector."""
        x = features.reshape(1, -1).astype(np.float32)

        if self._session is not None:
            # ONNX inference
            outputs = self._session.run(None, {self._input_name: x})
            # outputs[0] = labels, outputs[1] = probabilities
            probabilities = outputs[1][0]  # shape: (num_classes,)
            # probabilities may be a list of dicts or ndarray depending on converter
            if isinstance(probabilities, dict):
                probs = np.array([probabilities[i] for i in range(len(CLASS_NAMES))])
            elif isinstance(probabilities, np.ndarray):
                probs = probabilities
            else:
                # List of dicts from zipmap=False
                probs = np.array(list(probabilities.values()) if isinstance(probabilities, dict)
                                 else probabilities)
            label = int(np.argmax(probs))
            confidence = float(probs[label])
            return label, confidence, "onnx"

        elif self._pkl_model is not None:
            # Pickle / sklearn inference
            probs = self._pkl_model.predict_proba(x)[0]
            label = int(np.argmax(probs))
            confidence = float(probs[label])
            return label, confidence, "pkl"

        else:
            # Pure deterministic
            label = _deterministic_fallback(features)
            return label, 0.5, "deterministic_fallback"

    def set_override(self, flow_id: str, class_label: int):
        """Manual override: force a flow's classification."""
        if 0 <= class_label < len(CLASS_NAMES):
            self.override_map[flow_id] = class_label

    def clear_override(self, flow_id: str):
        """Remove a manual override."""
        self.override_map.pop(flow_id, None)

    def get_class_name(self, label: int) -> str:
        """Return human-readable class name."""
        try:
            lbl = int(label)
            if 0 <= lbl < len(CLASS_NAMES):
                return CLASS_NAMES[lbl]
        except (ValueError, TypeError):
            pass
        return "unknown"

    @property
    def class_names(self) -> List[str]:
        return CLASS_NAMES.copy()

    @property
    def feature_names(self) -> List[str]:
        return FEATURE_NAMES.copy()
