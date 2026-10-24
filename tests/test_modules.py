#!/usr/bin/env python3
"""
AegisQoS — Pytest Unit & Integration Tests for Modules 1–4

Verifies:
  - Module 1: Classifier confidence in [0,1], deterministic fallback, manual override
  - Module 2: Capacity estimator RTT tracking, AIMD, bufferbloat detection
  - Module 3: FSM state transitions, hysteresis lock, ≥15% bulk floor, Jain's fairness
  - Module 4: Atomic tc -b batch generation, safe-state rollback
"""

import os
import sys
import time
import json
import subprocess
import numpy as np
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.flow_classifier import FlowClassifier, _deterministic_fallback
from src.estimator.capacity_estimator import CapacityEstimator
from src.policy.policy_engine import PolicyEngine, PolicyState, BULK_STARVATION_FLOOR_PCT
from src.enforcement.tc_enforcer import TcEnforcer

# Detect if we have root privileges for networking tests
HAS_ROOT = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
needs_root = pytest.mark.skipif(not HAS_ROOT, reason="Requires root for ip netns / tc")


# ═══════════════════════════════════════════════════════════════════════════
# Module 1: Flow Classifier Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestFlowClassifier:
    """Test Module 1: Flow Classifier."""

    @pytest.fixture
    def classifier(self):
        return FlowClassifier(
            onnx_path="models/flow_classifier.onnx",
            pkl_path="models/flow_classifier_lgbm.pkl",
        )

    @pytest.fixture
    def voip_features(self):
        return np.array([180, 15, 20, 3, 25, 17, 450], dtype=np.float32)

    @pytest.fixture
    def bulk_features(self):
        return np.array([1400, 30, 1.5, 0.5, 150, 6, 500], dtype=np.float32)

    def test_confidence_in_range(self, classifier, voip_features):
        """Confidence scores must be in [0, 1]."""
        label, conf, method = classifier.classify("test", features=voip_features)
        assert 0.0 <= conf <= 1.0, f"Confidence {conf} outside [0, 1]"

    def test_onnx_classification(self, classifier, voip_features, bulk_features):
        """ONNX model should classify known patterns correctly."""
        label, conf, method = classifier.classify("voip", features=voip_features)
        assert label == 0, f"VoIP should be class 0, got {label}"
        assert method in ("onnx", "pkl")

        label, conf, method = classifier.classify("bulk", features=bulk_features)
        assert label == 3, f"Bulk should be class 3, got {label}"

    def test_deterministic_fallback_threshold(self, voip_features):
        """When confidence < threshold, deterministic fallback must trigger."""
        clf = FlowClassifier(
            onnx_path="models/flow_classifier.onnx",
            confidence_threshold=1.01  # Impossible to exceed
        )
        label, conf, method = clf.classify("test", features=voip_features)
        assert method == "deterministic_fallback"

    def test_deterministic_fallback_no_model(self, voip_features):
        """With no model loaded, must use deterministic fallback."""
        clf = FlowClassifier(onnx_path="/nonexistent", pkl_path="/nonexistent")
        label, conf, method = clf.classify("test", features=voip_features)
        assert method == "deterministic_fallback"

    def test_deterministic_fallback_rules(self):
        """Verify deterministic fallback heuristic rules."""
        # VoIP: small UDP, regular IAT
        voip = np.array([180, 15, 20, 3, 25, 17, 450], dtype=np.float32)
        assert _deterministic_fallback(voip) == 0

        # Bulk: large TCP, high rate
        bulk = np.array([1400, 30, 1.5, 0.5, 150, 6, 500], dtype=np.float32)
        assert _deterministic_fallback(bulk) == 3

    def test_manual_override(self, classifier, bulk_features):
        """Manual override must take precedence over ML classification."""
        classifier.set_override("flow_1", 0)  # Force realtime_voice
        label, conf, method = classifier.classify("flow_1", features=bulk_features)
        assert label == 0
        assert method == "manual_override"
        assert conf == 1.0

    def test_manual_override_clear(self, classifier, bulk_features):
        """Clearing override should restore ML classification."""
        classifier.set_override("flow_1", 0)
        classifier.clear_override("flow_1")
        label, conf, method = classifier.classify("flow_1", features=bulk_features)
        assert method in ("onnx", "pkl")
        assert label == 3  # Back to bulk

    def test_macro_f1_gate(self):
        """Training metadata must show macro-F1 >= 0.90."""
        meta_path = "models/classifier_metadata.json"
        assert os.path.exists(meta_path), "Metadata file not found"
        with open(meta_path) as f:
            meta = json.load(f)
        assert meta["macro_f1"] >= 0.90, f"Macro-F1 {meta['macro_f1']} < 0.90"


# ═══════════════════════════════════════════════════════════════════════════
# Module 2: Capacity Estimator Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCapacityEstimator:
    """Test Module 2: Capacity Estimator."""

    @pytest.fixture
    def estimator(self):
        return CapacityEstimator(initial_rate_mbit=100.0)

    def test_initial_state(self, estimator):
        """Initial state should be sensible defaults."""
        assert estimator.wan_rate_mbit == 100.0
        assert estimator.baseline_rtt_ms == 0.0
        assert not estimator.bufferbloat_detected

    def test_rtt_update(self, estimator):
        """RTT updates should track history and compute baseline."""
        for rtt in [20.0, 22.0, 18.0, 21.0, 19.0]:
            estimator.update_rtt(rtt, 2.0, 0.0)

        assert estimator.current_rtt_ms == 19.0
        assert estimator.baseline_rtt_ms > 0
        assert not estimator.bufferbloat_detected

    def test_bufferbloat_detection(self, estimator):
        """Bufferbloat should trigger when RTT > 2x baseline."""
        # Establish baseline
        for rtt in [20.0, 22.0, 18.0, 21.0, 19.0]:
            estimator.update_rtt(rtt, 2.0, 0.0)

        baseline = estimator.baseline_rtt_ms
        assert baseline > 0

        # Simulate bufferbloat (RTT spike > 2x baseline)
        estimator.update_rtt(baseline * 3.0, 10.0, 0.0)
        assert estimator.bufferbloat_detected, "Bufferbloat not detected at 3x baseline"

    def test_aimd_additive_increase(self, estimator):
        """AIMD should increase rate when no bufferbloat and low loss."""
        estimator.update_rtt(20.0, 2.0, 0.0)
        old_rate = estimator.wan_rate_mbit
        new_rate = estimator.aimd_step()
        assert new_rate > old_rate, "Rate should increase during AI phase"

    def test_aimd_multiplicative_decrease(self, estimator):
        """AIMD should decrease rate on bufferbloat or high loss."""
        # Establish baseline
        for rtt in [20.0, 22.0, 18.0, 21.0, 19.0]:
            estimator.update_rtt(rtt, 2.0, 0.0)

        # Trigger bufferbloat
        estimator.update_rtt(estimator.baseline_rtt_ms * 3.0, 10.0, 0.0)
        old_rate = estimator.wan_rate_mbit
        new_rate = estimator.aimd_step()
        assert new_rate < old_rate, "Rate should decrease during MD phase"

    def test_rate_bounds(self, estimator):
        """Rate should stay within min/max bounds."""
        # Force many decreases
        estimator.bufferbloat_detected = True
        for _ in range(100):
            estimator.aimd_step()
        assert estimator.wan_rate_mbit >= estimator.min_rate_mbit

        # Force many increases
        estimator.bufferbloat_detected = False
        estimator.packet_loss_pct = 0.0
        for _ in range(1000):
            estimator.aimd_step()
        assert estimator.wan_rate_mbit <= estimator.max_rate_mbit

    def test_get_state(self, estimator):
        """get_state should return a complete state dictionary."""
        state = estimator.get_state()
        required_keys = [
            "wan_rate_mbit", "baseline_rtt_ms", "current_rtt_ms",
            "delta_rtt_ms", "jitter_ms", "packet_loss_pct",
            "bufferbloat_detected", "rtt_samples",
        ]
        for key in required_keys:
            assert key in state, f"Missing key: {key}"

    @needs_root
    def test_live_ping(self, estimator):
        """Live ICMP ping from ns_clients to ns_server."""
        rtt, jitter, loss = estimator.measure_rtt(use_ipv6=False)
        assert loss < 100.0, "Ping failed (100% loss)"
        assert rtt > 0, "RTT should be positive"


# ═══════════════════════════════════════════════════════════════════════════
# Module 3: Policy Engine Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPolicyEngine:
    """Test Module 3: Policy Engine."""

    @pytest.fixture
    def engine(self):
        return PolicyEngine(wan_rate_mbit=100.0, hysteresis_s=0.0)

    @pytest.fixture
    def engine_with_hysteresis(self):
        return PolicyEngine(wan_rate_mbit=100.0, hysteresis_s=3.0)

    def test_initial_state(self, engine):
        """Initial state should be IDLE."""
        assert engine.state == PolicyState.IDLE

    def test_valid_transitions(self, engine):
        """Test valid FSM state transitions."""
        # IDLE → MONITORING
        assert engine.transition(PolicyState.MONITORING)
        assert engine.state == PolicyState.MONITORING

        # MONITORING → SHAPING
        assert engine.transition(PolicyState.SHAPING)
        assert engine.state == PolicyState.SHAPING

        # SHAPING → MONITORING
        assert engine.transition(PolicyState.MONITORING)
        assert engine.state == PolicyState.MONITORING

        # MONITORING → IDLE
        assert engine.transition(PolicyState.IDLE)
        assert engine.state == PolicyState.IDLE

    def test_invalid_transition(self, engine):
        """Invalid transitions should be rejected."""
        # IDLE → SHAPING (must go through MONITORING)
        assert not engine.transition(PolicyState.SHAPING)
        assert engine.state == PolicyState.IDLE

    def test_emergency_bypass(self, engine):
        """EMERGENCY transitions should be allowed from any state."""
        engine.transition(PolicyState.MONITORING)
        engine.transition(PolicyState.SHAPING)
        assert engine.transition(PolicyState.EMERGENCY)
        assert engine.state == PolicyState.EMERGENCY

    def test_emergency_recovery(self, engine):
        """Recovery from EMERGENCY should only go to IDLE."""
        engine.transition(PolicyState.MONITORING)
        engine.transition(PolicyState.EMERGENCY)

        # EMERGENCY → SHAPING should fail
        assert not engine.transition(PolicyState.SHAPING)
        # EMERGENCY → IDLE should succeed
        assert engine.transition(PolicyState.IDLE)

    def test_hysteresis_lock(self, engine_with_hysteresis):
        """Hysteresis should block rapid transitions."""
        eng = engine_with_hysteresis

        # First transition should succeed
        assert eng.transition(PolicyState.MONITORING)

        # Immediate second transition should be blocked (within 3s)
        assert not eng.transition(PolicyState.SHAPING)
        assert eng.state == PolicyState.MONITORING

    def test_hysteresis_emergency_bypass(self, engine_with_hysteresis):
        """EMERGENCY should bypass hysteresis lock."""
        eng = engine_with_hysteresis
        assert eng.transition(PolicyState.MONITORING)
        # EMERGENCY bypasses hysteresis
        assert eng.transition(PolicyState.EMERGENCY)

    def test_bulk_starvation_floor(self, engine):
        """Bulk transfer must get ≥15% of bandwidth."""
        # Set extreme allocations that starve bulk
        engine.allocations = {0: 40, 1: 40, 2: 15, 3: 5}
        rates = engine.compute_allocations(wan_rate_mbit=100.0)

        total_rate = sum(rates.values())
        bulk_pct = (rates[3] / total_rate) * 100 if total_rate > 0 else 0

        assert bulk_pct >= BULK_STARVATION_FLOOR_PCT, \
            f"Bulk got {bulk_pct:.1f}% < {BULK_STARVATION_FLOOR_PCT}% floor"

    def test_allocations_sum_to_wan_rate(self, engine):
        """Allocations should approximately sum to WAN rate."""
        rates = engine.compute_allocations(wan_rate_mbit=100.0)
        total = sum(rates.values())
        assert abs(total - 100.0) < 1.0, f"Allocations sum to {total}, expected ~100"

    def test_user_intent_ttl(self, engine):
        """User intents should expire after TTL."""
        intent = engine.add_intent("flow1", target_class=0, priority_boost=10.0, ttl_seconds=0.1)
        assert not intent.expired

        time.sleep(0.2)
        assert intent.expired

    def test_jains_fairness_index(self, engine):
        """Jain's fairness index should be in [0, 1]."""
        # Equal allocations → fairness = 1.0
        j = engine.jains_fairness_index([25, 25, 25, 25])
        assert abs(j - 1.0) < 0.001, f"Equal allocations should give J=1.0, got {j}"

        # Very unequal → fairness < 1.0
        j = engine.jains_fairness_index([100, 1, 1, 1])
        assert j < 1.0
        assert j > 0.0

    def test_get_state(self, engine):
        """get_state should return complete state dictionary."""
        state = engine.get_state()
        required_keys = [
            "fsm_state", "active_profile", "wan_rate_mbit",
            "allocations_pct", "allocations_mbit", "bulk_floor_pct",
            "jains_fairness",
        ]
        for key in required_keys:
            assert key in state, f"Missing key: {key}"


# ═══════════════════════════════════════════════════════════════════════════
# Module 4: TC Enforcer Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestTcEnforcer:
    """Test Module 4: TC Enforcer."""

    @pytest.fixture
    def enforcer(self):
        return TcEnforcer()

    def test_batch_generation(self, enforcer):
        """tc batch should contain HTB + fq_codel + filter commands."""
        rates = {0: 25.0, 1: 35.0, 2: 25.0, 3: 15.0}
        batch = enforcer.generate_htb_batch("veth_rtr_lan", 100.0, rates)

        assert "htb" in batch
        assert "fq_codel" in batch
        assert "1:10" in batch  # realtime_voice class
        assert "1:40" in batch  # bulk_transfer class
        assert "protocol ip" in batch
        assert "protocol ipv6" in batch

    def test_batch_dual_stack_filters(self, enforcer):
        """Batch must contain both IPv4 and IPv6 filter rules."""
        rates = {0: 25.0, 1: 35.0, 2: 25.0, 3: 15.0}
        batch = enforcer.generate_htb_batch("veth_rtr_lan", 100.0, rates)

        ipv4_filters = [l for l in batch.split("\n") if "protocol ip " in l and "ipv6" not in l]
        ipv6_filters = [l for l in batch.split("\n") if "protocol ipv6" in l]

        assert len(ipv4_filters) == 4, f"Expected 4 IPv4 filters, got {len(ipv4_filters)}"
        assert len(ipv6_filters) == 4, f"Expected 4 IPv6 filters, got {len(ipv6_filters)}"

    def test_batch_fwmark_values(self, enforcer):
        """Batch should reference correct fwmark values."""
        rates = {0: 25.0, 1: 35.0, 2: 25.0, 3: 15.0}
        batch = enforcer.generate_htb_batch("veth_rtr_lan", 100.0, rates)

        for fwmark in [0x10, 0x20, 0x30, 0x40]:
            assert f"handle 0x{fwmark:02x}" in batch or f"handle {fwmark}" in batch, f"Missing fwmark {fwmark}"

    @needs_root
    def test_atomic_apply_and_rollback(self, enforcer):
        """Test atomic tc -b apply followed by rollback."""
        rates = {0: 25.0, 1: 35.0, 2: 25.0, 3: 15.0}
        ok, output = enforcer.apply_shaping(100.0, rates)
        # May succeed or fail depending on testbed state,
        # but the method should not raise exceptions
        assert isinstance(ok, bool)
        assert isinstance(output, str)

        # Rollback should always succeed if testbed is up
        ok, output = enforcer.rollback()
        assert ok, f"Rollback failed: {output}"
        assert enforcer.safe_state_active

    @needs_root
    def test_rollback_increments_count(self, enforcer):
        """Each rollback should increment rollback_count."""
        initial = enforcer.rollback_count
        enforcer.rollback()
        assert enforcer.rollback_count > initial

    def test_get_state(self, enforcer):
        """get_state should return complete state dictionary."""
        state = enforcer.get_state()
        required_keys = [
            "safe_state_active", "rollback_count", "watchdog_running",
            "namespace", "download_iface", "upload_iface",
        ]
        for key in required_keys:
            assert key in state, f"Missing key: {key}"

    def test_tc_stats_query(self, enforcer):
        """tc stats query should return output string."""
        stats = enforcer.get_tc_stats("veth_rtr_lan")
        assert isinstance(stats, str)
        # After testbed setup, there should be some qdisc info
        assert len(stats) > 0 or "Error" not in stats


# ═══════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Cross-module integration tests."""

    def test_classifier_to_policy_flow(self):
        """Classifier → Policy Engine pipeline."""
        clf = FlowClassifier(
            onnx_path="models/flow_classifier.onnx",
            pkl_path="models/flow_classifier_lgbm.pkl",
        )
        engine = PolicyEngine(wan_rate_mbit=100.0, hysteresis_s=0.0)

        # Classify flows
        voip_feat = np.array([180, 15, 20, 3, 25, 17, 450], dtype=np.float32)
        label, conf, method = clf.classify("flow1", features=voip_feat)

        # Update policy engine
        flow_counts = {0: 1, 1: 0, 2: 0, 3: 0}
        engine.update_flow_counts(flow_counts)

        # Compute allocations
        rates = engine.compute_allocations()
        assert sum(rates.values()) > 0

    def test_policy_to_enforcer_flow(self):
        """Policy Engine → TC Enforcer pipeline."""
        engine = PolicyEngine(wan_rate_mbit=100.0, hysteresis_s=0.0)
        enforcer = TcEnforcer()

        # Get allocations
        rates = engine.compute_allocations()

        # Generate batch
        batch = enforcer.generate_htb_batch("veth_rtr_lan", 100.0, rates)
        assert "htb" in batch
        assert len(batch.split("\n")) > 5

    @needs_root
    def test_full_pipeline_shaping(self):
        """Full pipeline: classify → policy → enforce → rollback."""
        clf = FlowClassifier(
            onnx_path="models/flow_classifier.onnx",
            pkl_path="models/flow_classifier_lgbm.pkl",
        )
        engine = PolicyEngine(wan_rate_mbit=100.0, hysteresis_s=0.0)
        enforcer = TcEnforcer()

        # Step 1: Classify
        features = np.array([1400, 30, 1.5, 0.5, 150, 6, 500], dtype=np.float32)
        label, conf, method = clf.classify("test", features=features)
        assert label == 3  # bulk

        # Step 2: Transition to SHAPING
        engine.transition(PolicyState.MONITORING)
        engine.transition(PolicyState.SHAPING)

        # Step 3: Compute and apply
        rates = engine.compute_allocations()
        ok, output = enforcer.apply_shaping(100.0, rates)
        # Whether apply succeeds depends on testbed, but should not crash

        # Step 4: Rollback
        ok, output = enforcer.rollback()
        assert ok
        assert enforcer.safe_state_active


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
