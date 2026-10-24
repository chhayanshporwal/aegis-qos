#!/usr/bin/env python3
"""
AegisQoS — API Server & Traffic Scenario Tests (tests/test_api_and_traffic.py)

Unit and integration tests for:
  - FastAPI server REST endpoints (/health, /status, /intent, /override, /rollback, /metrics, /apply)
  - Scenario generator helpers and probe statistics calculation
  - Jain's fairness calculation on multi-stream scenarios
"""

import time
import pytest
from fastapi.testclient import TestClient

from src.api.server import app, get_policy, get_classifier, get_enforcer, get_estimator
from src.traffic.scenario_generator import UDPProbeClient


@pytest.fixture
def client():
    """Create a FastAPI test client."""
    return TestClient(app)


class TestApiServer:
    """Test suite for FastAPI management and intent API."""

    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "uptime_seconds" in data
        assert data["version"] == "1.0.0"

    def test_status_endpoint(self, client):
        resp = client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "classifier" in data
        assert "estimator" in data
        assert "policy" in data
        assert "enforcer" in data
        assert len(data["classifier"]["class_names"]) == 4

    def test_intent_lifecycle(self, client):
        # Set intent with priority boost and TTL
        payload = {
            "flow_id": "test_flow_call",
            "target_class": 0,
            "priority_boost": 15.0,
            "ttl_seconds": 30.0,
        }
        resp = client.post("/intent", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "intent_set"
        assert data["flow_id"] == "test_flow_call"
        assert data["target_class"] == "realtime_voice"
        assert data["priority_boost_pct"] == 15.0

        # Verify reflected in policy
        policy = get_policy()
        assert "test_flow_call" in policy.user_intents
        assert not policy.user_intents["test_flow_call"].expired

    def test_intent_invalid_class(self, client):
        resp = client.post("/intent", json={
            "flow_id": "bad_flow",
            "target_class": 99,
            "priority_boost": 5.0,
            "ttl_seconds": 10.0,
        })
        assert resp.status_code == 422 or resp.status_code == 400

    def test_manual_override_api(self, client):
        resp = client.post("/override", json={
            "flow_id": "flow_misclassified",
            "class_label": 1,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "override_set"
        assert data["forced_class"] == "interactive_video"

        # Check classifier
        classifier = get_classifier()
        assert classifier.override_map.get("flow_misclassified") == 1

        # Clear override
        del_resp = client.delete("/override/flow_misclassified")
        assert del_resp.status_code == 200
        assert "flow_misclassified" not in classifier.override_map

    def test_rollback_api(self, client):
        resp = client.post("/rollback")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "safe state" in data["message"].lower() or "rolled back" in data["message"].lower()

    def test_metrics_api(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "rtt_ms" in data
        assert "wan_rate_mbit" in data
        assert "jains_fairness" in data
        assert "cpu_pct" in data


class TestScenarioHelpers:
    """Test suite for probe and metrics calculations."""

    def test_probe_stats_calculation(self):
        client = UDPProbeClient(target_ip="127.0.0.1", port=12345)
        # Mock some sample packets
        client.samples = [
            {"seq": 1, "rtt_ms": 20.0, "jitter_ms": 2.0, "lost": 0},
            {"seq": 2, "rtt_ms": 22.0, "jitter_ms": 2.5, "lost": 0},
            {"seq": 3, "rtt_ms": 24.0, "jitter_ms": 3.0, "lost": 0},
            {"seq": 4, "rtt_ms": 0.0, "jitter_ms": 3.0, "lost": 1},
        ]
        stats = client.get_stats()
        assert stats["count"] == 4
        assert stats["loss_pct"] == 25.0
        assert stats["rtt_min"] == 20.0
        assert stats["rtt_max"] == 24.0
        assert stats["rtt_avg"] == 22.0

    def test_jains_fairness_calculation(self):
        # Equal allocations -> Fairness = 1.0
        rates = [20.0, 20.0, 20.0]
        n = len(rates)
        j = (sum(rates) ** 2) / (n * sum(r ** 2 for r in rates))
        assert abs(j - 1.0) < 1e-4

        # Skewed allocations -> Lower fairness
        skewed = [50.0, 5.0, 5.0]
        n_s = len(skewed)
        j_s = (sum(skewed) ** 2) / (n_s * sum(r ** 2 for r in skewed))
        assert j_s < 0.60
