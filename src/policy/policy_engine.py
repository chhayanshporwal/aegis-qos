#!/usr/bin/env python3
"""
AegisQoS Module 3 — Policy Engine

FSM (Finite State Machine) controller that:
  - Maintains traffic class → bandwidth allocation mappings
  - Enforces 3-second hysteresis lock to prevent flapping
  - Supports User Intent TTL for temporary priority boosts
  - Guarantees ≥15% bulk starvation floor
  - Tracks Jain's fairness index across active classes

States:
  IDLE       → No active flows, system at safe defaults
  MONITORING → Flows detected, gathering statistics
  SHAPING    → Active QoS shaping applied
  EMERGENCY  → Rollback to safe-state (fq_codel)
"""

import time
import threading
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

import numpy as np


class PolicyState(str, Enum):
    IDLE = "IDLE"
    MONITORING = "MONITORING"
    SHAPING = "SHAPING"
    EMERGENCY = "EMERGENCY"


@dataclass
class UserIntent:
    """Temporary user intent with TTL."""
    flow_id: str
    target_class: int        # Desired traffic class (0-3)
    priority_boost: float    # Extra bandwidth percentage (0-20)
    created_at: float        # time.time()
    ttl_seconds: float       # Time-to-live

    @property
    def expired(self) -> bool:
        return time.time() > self.created_at + self.ttl_seconds


# ── Default bandwidth allocation profiles (% of WAN capacity) ──
# Indexed by traffic class: [realtime_voice, interactive_video, responsive_web, bulk_transfer]
DEFAULT_PROFILES = {
    "balanced": [25, 35, 25, 15],
    "gaming":   [40, 25, 20, 15],
    "streaming": [20, 45, 20, 15],
    "work":     [30, 25, 30, 15],
}

BULK_STARVATION_FLOOR_PCT = 15  # Minimum guaranteed for bulk_transfer
HYSTERESIS_LOCK_SECONDS = 3.0   # Minimum time between policy changes

# HTB class hierarchy:
#   1:0  root qdisc
#   1:1  root class (100% of WAN rate)
#   1:10 realtime_voice  (DSCP EF, fwmark 10)
#   1:20 interactive_video (DSCP AF41, fwmark 20)
#   1:30 responsive_web   (DSCP AF21, fwmark 30)
#   1:40 bulk_transfer     (DSCP BE, fwmark 40)

CLASS_TO_FWMARK = {
    0: 10,   # realtime_voice
    1: 20,   # interactive_video
    2: 30,   # responsive_web
    3: 40,   # bulk_transfer
}

CLASS_TO_HTB_CLASSID = {
    0: "1:10",
    1: "1:20",
    2: "1:30",
    3: "1:40",
}


class PolicyEngine:
    """Module 3: FSM-based QoS Policy Controller.

    Maintains traffic class allocations, enforces hysteresis,
    supports user intents with TTL, and guarantees fairness.

    Attributes:
        state: Current FSM state.
        allocations: Dict of class_label → bandwidth percentage.
        active_profile: Name of the active allocation profile.
    """

    def __init__(self,
                 wan_rate_mbit: float = 100.0,
                 profile: str = "balanced",
                 hysteresis_s: float = HYSTERESIS_LOCK_SECONDS):
        self.state = PolicyState.IDLE
        self.wan_rate_mbit = wan_rate_mbit
        self.active_profile = profile
        self.hysteresis_s = hysteresis_s

        # Bandwidth allocations (% per class)
        self.allocations: Dict[int, float] = {}
        self._set_profile(profile)

        # Hysteresis tracking
        self._last_policy_change = 0.0
        self._lock = threading.Lock()

        # User intents
        self._intents: Dict[str, UserIntent] = {}

        # State history for debugging
        self._state_history: List[Tuple[float, PolicyState]] = []

        # Flow counts per class (for fairness calculation)
        self._flow_counts: Dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0}

    def _set_profile(self, profile: str):
        """Set bandwidth allocation from a named profile."""
        if profile not in DEFAULT_PROFILES:
            profile = "balanced"
        pct = DEFAULT_PROFILES[profile]
        self.allocations = {i: float(pct[i]) for i in range(4)}
        self.active_profile = profile

    def transition(self, new_state: PolicyState) -> bool:
        """Attempt an FSM state transition with hysteresis lock.

        Returns:
            True if transition was accepted, False if locked.
        """
        with self._lock:
            now = time.time()

            # Hysteresis: block transitions within lock period
            # EMERGENCY transitions bypass hysteresis
            if (new_state != PolicyState.EMERGENCY
                    and (now - self._last_policy_change) < self.hysteresis_s):
                return False

            # Validate transition
            valid_transitions = {
                PolicyState.IDLE: {PolicyState.MONITORING, PolicyState.EMERGENCY},
                PolicyState.MONITORING: {PolicyState.SHAPING, PolicyState.IDLE, PolicyState.EMERGENCY},
                PolicyState.SHAPING: {PolicyState.MONITORING, PolicyState.IDLE, PolicyState.EMERGENCY},
                PolicyState.EMERGENCY: {PolicyState.IDLE},
            }

            if new_state not in valid_transitions.get(self.state, set()):
                return False

            old_state = self.state
            self.state = new_state
            self._last_policy_change = now
            self._state_history.append((now, new_state))
            return True

    def update_flow_counts(self, counts: Dict[int, int]):
        """Update the number of active flows per class."""
        with self._lock:
            self._flow_counts = counts.copy()

    def compute_allocations(self,
                             flow_counts: Optional[Dict[int, int]] = None,
                             wan_rate_mbit: Optional[float] = None,
                             active_classes: Optional[List[int]] = None,
                             ) -> Dict[int, float]:
        """Compute bandwidth allocations in Mbit/s.

        Applies:
          1. Base profile percentages
          2. User intent priority boosts
          3. Bulk starvation floor guarantee (≥15%)
          4. Normalization to 100%

        Returns:
            Dict of class_label → rate_mbit.
        """
        if wan_rate_mbit is not None:
            self.wan_rate_mbit = wan_rate_mbit

        if flow_counts is not None:
            self._flow_counts = flow_counts.copy()

        with self._lock:
            # Start from profile percentages
            pcts = dict(self.allocations)

            # Apply user intents (boost active intents)
            self._expire_intents()
            for intent in self._intents.values():
                if not intent.expired:
                    cls = intent.target_class
                    pcts[cls] = pcts.get(cls, 0) + intent.priority_boost

            # Enforce bulk starvation floor
            if pcts.get(3, 0) < BULK_STARVATION_FLOOR_PCT:
                deficit = BULK_STARVATION_FLOOR_PCT - pcts[3]
                pcts[3] = BULK_STARVATION_FLOOR_PCT
                # Redistribute deficit from other classes proportionally
                others_total = sum(pcts[i] for i in range(3))
                if others_total > 0:
                    for i in range(3):
                        pcts[i] -= deficit * (pcts[i] / others_total)

            # Normalize to 100%
            total = sum(pcts.values())
            if total > 0:
                for k in pcts:
                    pcts[k] = (pcts[k] / total) * 100.0

            # Convert to Mbit/s
            rates = {}
            for cls, pct in pcts.items():
                rates[cls] = round((pct / 100.0) * self.wan_rate_mbit, 2)

            return rates

    def add_intent(self, flow_id: str, target_class: int,
                   priority_boost: float = 10.0,
                   ttl_seconds: float = 60.0) -> UserIntent:
        """Add a user intent with TTL."""
        intent = UserIntent(
            flow_id=flow_id,
            target_class=target_class,
            priority_boost=min(priority_boost, 20.0),  # cap at 20%
            created_at=time.time(),
            ttl_seconds=ttl_seconds,
        )
        with self._lock:
            self._intents[flow_id] = intent
        return intent

    @property
    def user_intents(self) -> Dict[str, UserIntent]:
        """Active user intents dictionary."""
        with self._lock:
            return dict(self._intents)

    def remove_intent(self, flow_id: str):
        """Remove a user intent."""
        with self._lock:
            self._intents.pop(flow_id, None)

    def _expire_intents(self):
        """Remove expired intents."""
        expired = [k for k, v in self._intents.items() if v.expired]
        for k in expired:
            del self._intents[k]

    def jains_fairness_index(self, throughputs: Optional[List[float]] = None) -> float:
        """Compute Jain's fairness index.

        J(x) = (Σxi)² / (n · Σxi²)
        Range: [1/n, 1.0] where 1.0 = perfectly fair.
        """
        if throughputs is None or len(throughputs) == 0:
            rates = self.compute_allocations()
            throughputs = [r for r in rates.values() if r > 0]

        if len(throughputs) == 0:
            return 1.0

        x = np.array(throughputs, dtype=np.float64)
        n = len(x)
        sum_x = np.sum(x)
        sum_x2 = np.sum(x ** 2)

        if sum_x2 == 0:
            return 1.0

        return float((sum_x ** 2) / (n * sum_x2))

    def get_state(self) -> Dict:
        """Return current policy engine state."""
        rates = self.compute_allocations()
        return {
            "fsm_state": self.state.value,
            "active_profile": self.active_profile,
            "wan_rate_mbit": self.wan_rate_mbit,
            "allocations_pct": dict(self.allocations),
            "allocations_mbit": rates,
            "bulk_floor_pct": BULK_STARVATION_FLOOR_PCT,
            "hysteresis_lock_s": self.hysteresis_s,
            "active_intents": len(self._intents),
            "jains_fairness": round(self.jains_fairness_index(), 4),
            "flow_counts": dict(self._flow_counts),
        }

    def get_fwmark(self, class_label: int) -> int:
        """Get iptables fwmark for a traffic class."""
        return CLASS_TO_FWMARK.get(class_label, 40)

    def get_htb_classid(self, class_label: int) -> str:
        """Get HTB class ID for a traffic class."""
        return CLASS_TO_HTB_CLASSID.get(class_label, "1:40")
