#!/usr/bin/env python3
"""
AegisQoS — FastAPI Server (Module 5a)

REST API endpoints:
  GET  /status     → System status (classifier, estimator, policy, enforcer)
  POST /intent     → Set user intent with TTL (temporary priority boost)
  POST /override   → Manual classification override (misclassification fix)
  POST /rollback   → Trigger safe-state rollback to fq_codel
  GET  /metrics    → Live metrics for dashboard consumption
  GET  /health     → Health check
"""

import os
import sys
import time
import json
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.models.flow_classifier import FlowClassifier
from src.estimator.capacity_estimator import CapacityEstimator
from src.policy.policy_engine import PolicyEngine, PolicyState
from src.enforcement.tc_enforcer import TcEnforcer

# ── App initialization ──────────────────────────────────────────────────────
app = FastAPI(
    title="AegisQoS API",
    description="Intent-Aware, Zero-DPI Adaptive QoS Engine for Mixed Home Broadband Traffic",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Module instances (lazy initialization) ──────────────────────────────────
_classifier: Optional[FlowClassifier] = None
_estimator: Optional[CapacityEstimator] = None
_policy: Optional[PolicyEngine] = None
_enforcer: Optional[TcEnforcer] = None
_start_time = time.time()


def get_classifier() -> FlowClassifier:
    global _classifier
    if _classifier is None:
        _classifier = FlowClassifier(
            onnx_path="models/flow_classifier.onnx",
            pkl_path="models/flow_classifier_lgbm.pkl",
        )
    return _classifier


def get_estimator() -> CapacityEstimator:
    global _estimator
    if _estimator is None:
        _estimator = CapacityEstimator()
    return _estimator


def get_policy() -> PolicyEngine:
    global _policy
    if _policy is None:
        _policy = PolicyEngine(wan_rate_mbit=100.0)
    return _policy


def get_enforcer() -> TcEnforcer:
    global _enforcer
    if _enforcer is None:
        _enforcer = TcEnforcer()
    return _enforcer


# ── Request/Response models ─────────────────────────────────────────────────

class IntentRequest(BaseModel):
    flow_id: str = Field(..., description="Unique flow identifier")
    target_class: int = Field(..., ge=0, le=3, description="Traffic class (0-3)")
    priority_boost: float = Field(default=10.0, ge=0, le=20, description="Extra bandwidth %")
    ttl_seconds: float = Field(default=60.0, ge=1, le=3600, description="Intent TTL in seconds")


class OverrideRequest(BaseModel):
    flow_id: str = Field(..., description="Unique flow identifier")
    class_label: int = Field(..., ge=0, le=3, description="Forced traffic class (0-3)")


class RollbackResponse(BaseModel):
    success: bool
    message: str
    rollback_count: int


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "version": "1.0.0",
    }


@app.get("/status")
async def get_status():
    """Get full system status across all modules."""
    classifier = get_classifier()
    estimator = get_estimator()
    policy = get_policy()
    enforcer = get_enforcer()

    return {
        "timestamp": time.time(),
        "classifier": {
            "class_names": classifier.class_names,
            "feature_names": classifier.feature_names,
            "active_overrides": len(classifier.override_map),
            "confidence_threshold": classifier.confidence_threshold,
        },
        "estimator": estimator.get_state(),
        "policy": policy.get_state(),
        "enforcer": enforcer.get_state(),
    }


@app.post("/intent")
async def set_intent(req: IntentRequest):
    """Set a user intent with TTL for temporary priority boost."""
    policy = get_policy()
    class_names = get_classifier().class_names

    if req.target_class >= len(class_names):
        raise HTTPException(400, f"Invalid class {req.target_class}")

    intent = policy.add_intent(
        flow_id=req.flow_id,
        target_class=req.target_class,
        priority_boost=req.priority_boost,
        ttl_seconds=req.ttl_seconds,
    )

    return {
        "status": "intent_set",
        "flow_id": req.flow_id,
        "target_class": class_names[req.target_class],
        "priority_boost_pct": req.priority_boost,
        "ttl_seconds": req.ttl_seconds,
        "expires_at": intent.created_at + intent.ttl_seconds,
    }


@app.post("/override")
async def set_override(req: OverrideRequest):
    """Manual classification override to fix misclassification."""
    classifier = get_classifier()
    class_names = classifier.class_names

    if req.class_label >= len(class_names):
        raise HTTPException(400, f"Invalid class {req.class_label}")

    classifier.set_override(req.flow_id, req.class_label)

    return {
        "status": "override_set",
        "flow_id": req.flow_id,
        "forced_class": class_names[req.class_label],
    }


@app.delete("/override/{flow_id}")
async def clear_override(flow_id: str):
    """Clear a manual classification override."""
    classifier = get_classifier()
    classifier.clear_override(flow_id)

    return {
        "status": "override_cleared",
        "flow_id": flow_id,
    }


@app.post("/rollback")
async def trigger_rollback():
    """Trigger safe-state rollback to fq_codel on all interfaces."""
    enforcer = get_enforcer()
    policy = get_policy()

    # Transition policy to EMERGENCY
    policy.transition(PolicyState.EMERGENCY)

    # Execute rollback
    success, message = enforcer.rollback()

    # Transition back to IDLE
    policy.transition(PolicyState.IDLE)

    return RollbackResponse(
        success=success,
        message=message,
        rollback_count=enforcer.rollback_count,
    )


@app.get("/metrics")
async def get_metrics():
    """Get live metrics for dashboard consumption."""
    estimator = get_estimator()
    policy = get_policy()
    enforcer = get_enforcer()

    est_state = estimator.get_state()
    pol_state = policy.get_state()

    import psutil
    cpu_pct = psutil.cpu_percent(interval=0.1)

    return {
        "timestamp": time.time(),
        "rtt_ms": est_state["current_rtt_ms"],
        "baseline_rtt_ms": est_state["baseline_rtt_ms"],
        "delta_rtt_ms": est_state["delta_rtt_ms"],
        "jitter_ms": est_state["jitter_ms"],
        "packet_loss_pct": est_state["packet_loss_pct"],
        "bufferbloat": est_state["bufferbloat_detected"],
        "wan_rate_mbit": est_state["wan_rate_mbit"],
        "allocations_mbit": pol_state["allocations_mbit"],
        "fsm_state": pol_state["fsm_state"],
        "jains_fairness": pol_state["jains_fairness"],
        "cpu_pct": cpu_pct,
        "safe_state": enforcer.safe_state_active,
        "rollback_count": enforcer.rollback_count,
    }


@app.post("/apply")
async def apply_shaping():
    """Compute and apply QoS shaping based on current policy."""
    policy = get_policy()
    enforcer = get_enforcer()
    estimator = get_estimator()

    # Transition to SHAPING if possible
    if policy.state == PolicyState.IDLE:
        policy.transition(PolicyState.MONITORING)
    if policy.state == PolicyState.MONITORING:
        policy.transition(PolicyState.SHAPING)

    # Compute allocations
    rates = policy.compute_allocations(
        wan_rate_mbit=estimator.wan_rate_mbit
    )

    # Apply
    success, output = enforcer.apply_shaping(
        estimator.wan_rate_mbit, rates
    )

    if not success:
        policy.transition(PolicyState.EMERGENCY)
        policy.transition(PolicyState.IDLE)

    return {
        "success": success,
        "output": output,
        "allocations_mbit": rates,
        "fsm_state": policy.state.value,
    }


if __name__ == "__main__":
    uvicorn.run(
        "src.api.server:app",
        host=os.environ.get("API_HOST", "0.0.0.0"),
        port=int(os.environ.get("API_PORT", "8000")),
        reload=False,
    )
