#!/usr/bin/env python3
"""
AegisQoS Module 2 — Capacity Estimator

Passive/active ICMP ΔRTT bufferbloat detector and AIMD link-capacity estimator.

Methods:
  - Passive RTT monitoring: Tracks RTT samples from ICMP pings, detects
    bufferbloat via RTT inflation (current_rtt > 2 * baseline_rtt).
  - AIMD capacity estimation: Additive-Increase Multiplicative-Decrease
    algorithm to estimate usable link capacity without saturating the link.
  - Bandwidth utilization tracking from tc qdisc statistics.
"""

import os
import time
import threading
import subprocess
import re
from collections import deque
from typing import Optional, Tuple, Dict

import numpy as np


class CapacityEstimator:
    """Module 2: Passive/Active Link Capacity Estimator.

    Monitors RTT via ICMP pings to detect bufferbloat and estimates
    usable link capacity using an AIMD algorithm.

    Attributes:
        wan_rate_mbit: Current estimated WAN capacity in Mbit/s.
        baseline_rtt_ms: Baseline (unloaded) RTT in milliseconds.
        current_rtt_ms: Most recent RTT measurement.
        bufferbloat_detected: True if current RTT > 2x baseline.
        jitter_ms: Current jitter (RTT standard deviation).
    """

    def __init__(self,
                 target_ip: str = "10.0.3.2",
                 target_ipv6: str = "fd00:3::2",
                 initial_rate_mbit: float = 100.0,
                 min_rate_mbit: float = 5.0,
                 max_rate_mbit: float = 200.0,
                 rtt_window_size: int = 20,
                 namespace: str = "ns_clients"):
        self.target_ip = target_ip
        self.target_ipv6 = target_ipv6
        self.wan_rate_mbit = initial_rate_mbit
        self.min_rate_mbit = min_rate_mbit
        self.max_rate_mbit = max_rate_mbit
        self.namespace = namespace

        # RTT tracking
        self._rtt_history: deque = deque(maxlen=rtt_window_size)
        self._rtt_lock = threading.Lock()
        self.baseline_rtt_ms: float = 0.0
        self.current_rtt_ms: float = 0.0
        self.jitter_ms: float = 0.0
        self.packet_loss_pct: float = 0.0
        self.bufferbloat_detected: bool = False

        # AIMD state
        self._aimd_alpha = 2.0    # Additive increase (Mbit/s per cycle)
        self._aimd_beta = 0.5     # Multiplicative decrease factor
        self._last_update = time.time()

        # Monitoring thread
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def measure_rtt(self, use_ipv6: bool = False) -> Tuple[float, float, float]:
        """Measure RTT via a single ICMP ping.

        Returns:
            (rtt_ms, jitter_ms, loss_pct) tuple.
        """
        target = self.target_ipv6 if use_ipv6 else self.target_ip
        ping_cmd = "ping6" if use_ipv6 else "ping"
        ns_prefix = f"ip netns exec {self.namespace} " if self.namespace else ""
        cmd = f"{ns_prefix}{ping_cmd} -c 3 -W 2 -q {target}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr

            # Parse packet loss
            loss_match = re.search(r"(\d+)% packet loss", output)
            loss_pct = float(loss_match.group(1)) if loss_match else 100.0

            # Parse RTT stats: min/avg/max/mdev
            rtt_match = re.search(
                r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)",
                output
            )
            if rtt_match:
                rtt_avg = float(rtt_match.group(2))
                rtt_mdev = float(rtt_match.group(4))
                return rtt_avg, rtt_mdev, loss_pct
            else:
                return 0.0, 0.0, loss_pct

        except (subprocess.TimeoutExpired, Exception) as e:
            return 0.0, 0.0, 100.0

    def update_rtt(self, rtt_ms: float, jitter_ms: float, loss_pct: float):
        """Update RTT history and detect bufferbloat."""
        with self._rtt_lock:
            self.current_rtt_ms = rtt_ms
            self.jitter_ms = jitter_ms
            self.packet_loss_pct = loss_pct

            if rtt_ms > 0:
                self._rtt_history.append(rtt_ms)

            # Compute baseline from the lowest 25% of RTT samples
            if len(self._rtt_history) >= 5:
                sorted_rtt = sorted(self._rtt_history)
                q25 = sorted_rtt[:max(1, len(sorted_rtt) // 4)]
                self.baseline_rtt_ms = float(np.mean(q25))

                # Bufferbloat: current RTT > 2x baseline
                self.bufferbloat_detected = (
                    self.current_rtt_ms > 2.0 * self.baseline_rtt_ms
                    and self.baseline_rtt_ms > 0
                )
            elif rtt_ms > 0 and self.baseline_rtt_ms == 0:
                self.baseline_rtt_ms = rtt_ms

    def aimd_step(self) -> float:
        """Execute one AIMD capacity estimation step.

        Returns:
            Updated estimated WAN rate in Mbit/s.
        """
        if self.bufferbloat_detected or self.packet_loss_pct > 1.0:
            # Multiplicative Decrease
            self.wan_rate_mbit = max(
                self.min_rate_mbit,
                self.wan_rate_mbit * self._aimd_beta
            )
        else:
            # Additive Increase
            self.wan_rate_mbit = min(
                self.max_rate_mbit,
                self.wan_rate_mbit + self._aimd_alpha
            )

        self._last_update = time.time()
        return self.wan_rate_mbit

    def get_state(self) -> Dict:
        """Return current estimator state as a dictionary."""
        with self._rtt_lock:
            delta_rtt = (
                self.current_rtt_ms - self.baseline_rtt_ms
                if self.baseline_rtt_ms > 0 else 0.0
            )
            return {
                "wan_rate_mbit": round(self.wan_rate_mbit, 2),
                "baseline_rtt_ms": round(self.baseline_rtt_ms, 2),
                "current_rtt_ms": round(self.current_rtt_ms, 2),
                "delta_rtt_ms": round(delta_rtt, 2),
                "jitter_ms": round(self.jitter_ms, 2),
                "packet_loss_pct": round(self.packet_loss_pct, 2),
                "bufferbloat_detected": self.bufferbloat_detected,
                "rtt_samples": len(self._rtt_history),
            }

    def start_monitoring(self, interval_s: float = 2.0):
        """Start background RTT monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop, args=(interval_s,), daemon=True
        )
        self._thread.start()

    def stop_monitoring(self):
        """Stop background monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _monitor_loop(self, interval_s: float):
        """Background monitoring loop."""
        while self._running:
            rtt, jitter, loss = self.measure_rtt()
            self.update_rtt(rtt, jitter, loss)
            self.aimd_step()
            time.sleep(interval_s)
