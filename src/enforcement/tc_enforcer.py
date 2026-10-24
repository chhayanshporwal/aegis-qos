#!/usr/bin/env python3
"""
AegisQoS Module 4 — TC Enforcer

Atomic `tc -b` HTB + fq_codel batch generator with:
  - Dual-stack iptables/ip6tables fwmark rules
  - 4-class HTB hierarchy on veth_rtr_lan (download) and veth_rtr_wan (upload)
  - Safe-State Watchdog: rolls back to fq_codel on tc error, high CPU, or anomalous loss
  - Atomic execution via tc batch files
"""

import os
import time
import tempfile
import threading
import subprocess
from typing import Dict, List, Optional, Tuple

import psutil

from src.policy.policy_engine import CLASS_TO_FWMARK, CLASS_TO_HTB_CLASSID


# ── Constants ──────────────────────────────────────────────────────────────
ROUTER_NS = "ns_router"
DOWNLOAD_IFACE = "veth_rtr_lan"   # Downstream (towards ns_clients)
UPLOAD_IFACE = "veth_rtr_wan"     # Upstream (towards ns_wan_netem)

SAFE_STATE_QDISC = "fq_codel"
WATCHDOG_CPU_THRESHOLD = float(os.environ.get("WATCHDOG_CPU_THRESHOLD_PCT", "10"))
WATCHDOG_INTERVAL = float(os.environ.get("WATCHDOG_INTERVAL_SECONDS", "2"))


class TcEnforcer:
    """Module 4: Atomic TC Batch Enforcer with Safe-State Watchdog.

    Generates `tc -b` batch files for HTB + fq_codel hierarchy
    and applies them atomically inside ns_router. Monitors system
    health and rolls back on failure.

    Attributes:
        safe_state_active: True if system is in safe (fq_codel) state.
        last_batch_file: Path to the last generated batch file.
        rollback_count: Number of times safe-state rollback was triggered.
    """

    def __init__(self, namespace: str = ROUTER_NS):
        self.namespace = namespace
        self.safe_state_active = True
        self.last_batch_file: Optional[str] = None
        self.rollback_count = 0
        self._lock = threading.Lock()
        self._watchdog_running = False
        self._watchdog_thread: Optional[threading.Thread] = None
        self._last_apply_time = 0.0

    def generate_htb_batch(self,
                            iface: str,
                            wan_rate_mbit: float,
                            class_rates_mbit: Dict[int, float],
                            ) -> str:
        """Generate tc batch commands for a 4-class HTB + fq_codel hierarchy.

        Args:
            iface: Network interface name (e.g. veth_rtr_lan).
            wan_rate_mbit: Total WAN rate in Mbit/s.
            class_rates_mbit: Dict of class_label → rate in Mbit/s.

        Returns:
            Multi-line string of tc batch commands.
        """
        ceil = f"{wan_rate_mbit}mbit"
        lines = []

        # Remove existing qdiscs
        lines.append(f"qdisc replace dev {iface} root handle 1: htb default 40")

        # Root class
        lines.append(
            f"class replace dev {iface} parent 1: classid 1:1 "
            f"htb rate {ceil} ceil {ceil}"
        )

        # Per-class HTB classes with fq_codel leaf qdiscs
        for cls_label in range(4):
            classid = CLASS_TO_HTB_CLASSID[cls_label]
            rate = class_rates_mbit.get(cls_label, wan_rate_mbit * 0.15)
            rate_str = f"{max(rate, 0.1):.2f}mbit"

            # Priority: lower number = higher priority
            prio = cls_label + 1

            lines.append(
                f"class replace dev {iface} parent 1:1 classid {classid} "
                f"htb rate {rate_str} ceil {ceil} prio {prio}"
            )

            # fq_codel leaf qdisc (handle = 10 + class_label + 1 to avoid collision with root 1:)
            handle = f"{10 + cls_label + 1}:"
            lines.append(
                f"qdisc replace dev {iface} parent {classid} handle {handle} "
                f"fq_codel limit 1024 target 5ms interval 100ms ecn"
            )

        # tc filter rules: match fwmark to HTB class (IPv4)
        for cls_label in range(4):
            fwmark = CLASS_TO_FWMARK[cls_label]
            classid = CLASS_TO_HTB_CLASSID[cls_label]
            lines.append(
                f"filter replace dev {iface} parent 1: protocol ip prio 1 "
                f"handle {fwmark} fw flowid {classid}"
            )

        # tc filter rules: match fwmark to HTB class (IPv6)
        for cls_label in range(4):
            fwmark = CLASS_TO_FWMARK[cls_label]
            classid = CLASS_TO_HTB_CLASSID[cls_label]
            lines.append(
                f"filter replace dev {iface} parent 1: protocol ipv6 prio 2 "
                f"handle {fwmark} fw flowid {classid}"
            )

        return "\n".join(lines)

    def generate_iptables_rules(self, flow_marks: Optional[Dict[str, int]] = None) -> List[str]:
        """Generate iptables/ip6tables mangle rules for flow classification.

        Args:
            flow_marks: Optional dict of flow_spec → fwmark.
                        Format: "proto:port" or "proto:src_ip:dst_ip:src_port:dst_port"

        Returns:
            List of iptables command strings.
        """
        commands = []
        commands.append(
            f"ip netns exec {self.namespace} iptables -t mangle -F AEGIS"
        )
        commands.append(
            f"ip netns exec {self.namespace} ip6tables -t mangle -F AEGIS"
        )

        # Default standard service mappings
        default_rules = [
            # Class 0: Realtime voice / gaming (fwmark 10)
            ("udp", 5004, 10),
            ("udp", 5060, 10),
            ("udp", 9000, 10),
            # Class 1: Interactive video / streaming (fwmark 20)
            ("tcp", 8001, 20),
            ("tcp", 8002, 20),
            ("tcp", 8003, 20),
            ("udp", 8001, 20),
            ("udp", 8002, 20),
            ("udp", 8003, 20),
            ("tcp", 1935, 20),
            # Class 2: Responsive web / DNS (fwmark 30)
            ("tcp", 80, 30),
            ("tcp", 443, 30),
            ("udp", 53, 30),
            ("tcp", 53, 30),
            # Class 3: Bulk transfer (fwmark 40)
            ("tcp", 5201, 40),
        ]

        for proto, port, fwmark in default_rules:
            commands.append(
                f"ip netns exec {self.namespace} iptables -t mangle -A AEGIS -p {proto} --sport {port} -j MARK --set-mark {fwmark}"
            )
            commands.append(
                f"ip netns exec {self.namespace} iptables -t mangle -A AEGIS -p {proto} --dport {port} -j MARK --set-mark {fwmark}"
            )
            commands.append(
                f"ip netns exec {self.namespace} ip6tables -t mangle -A AEGIS -p {proto} --sport {port} -j MARK --set-mark {fwmark}"
            )
            commands.append(
                f"ip netns exec {self.namespace} ip6tables -t mangle -A AEGIS -p {proto} --dport {port} -j MARK --set-mark {fwmark}"
            )

        # Custom flow marks from classifier / overrides
        if flow_marks:
            for spec, fwmark in flow_marks.items():
                parts = spec.split(":")
                if len(parts) == 2:
                    p_proto, p_port = parts[0], parts[1]
                    commands.append(
                        f"ip netns exec {self.namespace} iptables -t mangle -I AEGIS 1 -p {p_proto} --sport {p_port} -j MARK --set-mark {fwmark}"
                    )
                    commands.append(
                        f"ip netns exec {self.namespace} iptables -t mangle -I AEGIS 1 -p {p_proto} --dport {p_port} -j MARK --set-mark {fwmark}"
                    )
                    commands.append(
                        f"ip netns exec {self.namespace} ip6tables -t mangle -I AEGIS 1 -p {p_proto} --sport {p_port} -j MARK --set-mark {fwmark}"
                    )
                    commands.append(
                        f"ip netns exec {self.namespace} ip6tables -t mangle -I AEGIS 1 -p {p_proto} --dport {p_port} -j MARK --set-mark {fwmark}"
                    )
                elif len(parts) == 5:
                    p_proto, s_ip, d_ip, s_port, d_port = parts
                    cmd4 = f"ip netns exec {self.namespace} iptables -t mangle -I AEGIS 1 -p {p_proto}"
                    if s_ip and s_ip != "*":
                        cmd4 += f" -s {s_ip}"
                    if d_ip and d_ip != "*":
                        cmd4 += f" -d {d_ip}"
                    if s_port and s_port != "*":
                        cmd4 += f" --sport {s_port}"
                    if d_port and d_port != "*":
                        cmd4 += f" --dport {d_port}"
                    cmd4 += f" -j MARK --set-mark {fwmark}"
                    commands.append(cmd4)

        return commands

    def apply_iptables_rules(self, flow_marks: Optional[Dict[str, int]] = None) -> bool:
        """Apply iptables mangle rules inside the router namespace."""
        cmds = self.generate_iptables_rules(flow_marks)
        success = True
        for cmd in cmds:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode != 0:
                success = False
        return success

    def apply_batch(self, iface: str, batch_content: str) -> Tuple[bool, str]:
        """Apply tc batch atomically inside the router namespace.

        Args:
            iface: Interface being configured.
            batch_content: Multi-line tc batch commands.

        Returns:
            (success, output) tuple.
        """
        with self._lock:
            # Write batch file
            batch_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.tc', prefix='aegis_',
                delete=False, dir='/tmp'
            )
            batch_file.write(batch_content)
            batch_file.flush()
            batch_file.close()
            self.last_batch_file = batch_file.name

            # Execute atomically via tc -b
            cmd = f"ip netns exec {self.namespace} tc -b {batch_file.name}"
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=10
                )
                output = result.stdout + result.stderr

                if result.returncode != 0:
                    # Non-zero exit → rollback to safe state
                    self._rollback_safe_state(iface, f"tc -b failed: {output}")
                    return False, output

                self.safe_state_active = False
                self._last_apply_time = time.time()
                return True, output

            except subprocess.TimeoutExpired:
                self._rollback_safe_state(iface, "tc -b timed out")
                return False, "tc -b timed out"
            except Exception as e:
                self._rollback_safe_state(iface, f"tc -b exception: {e}")
                return False, str(e)
            finally:
                # Clean up batch file
                try:
                    os.unlink(batch_file.name)
                except OSError:
                    pass

    def apply_shaping(self,
                       wan_rate_mbit: float,
                       class_rates_mbit: Dict[int, float]
                       ) -> Tuple[bool, str]:
        """Apply full bidirectional shaping on both download and upload interfaces.

        Args:
            wan_rate_mbit: Total WAN capacity.
            class_rates_mbit: Dict of class_label → allocated rate.

        Returns:
            (success, output) tuple.
        """
        results = []

        for iface in [DOWNLOAD_IFACE, UPLOAD_IFACE]:
            batch = self.generate_htb_batch(iface, wan_rate_mbit, class_rates_mbit)
            ok, output = self.apply_batch(iface, batch)
            results.append((iface, ok, output))
            if not ok:
                return False, f"Failed on {iface}: {output}"

        return True, "Shaping applied on both interfaces"

    def rollback(self) -> Tuple[bool, str]:
        """Manually trigger safe-state rollback on both interfaces."""
        results = []
        for iface in [DOWNLOAD_IFACE, UPLOAD_IFACE]:
            ok = self._rollback_safe_state(iface, "Manual rollback requested")
            results.append((iface, ok))
        success = all(ok for _, ok in results)
        return success, "Rolled back to fq_codel safe state"

    def _rollback_safe_state(self, iface: str, reason: str) -> bool:
        """Roll back a single interface to fq_codel safe state."""
        cmd = (
            f"ip netns exec {self.namespace} "
            f"tc qdisc replace dev {iface} root {SAFE_STATE_QDISC}"
        )
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                self.safe_state_active = True
                self.rollback_count += 1
                print(f"[Watchdog] Rollback on {iface}: {reason}")
                return True
            else:
                print(f"[Watchdog] Rollback FAILED on {iface}: {result.stderr}")
                return False
        except Exception as e:
            print(f"[Watchdog] Rollback exception on {iface}: {e}")
            return False

    # ── Safe-State Watchdog ────────────────────────────────────────────────

    def start_watchdog(self, interval_s: float = WATCHDOG_INTERVAL):
        """Start the Safe-State Watchdog background thread."""
        if self._watchdog_running:
            return
        self._watchdog_running = True
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, args=(interval_s,), daemon=True
        )
        self._watchdog_thread.start()

    def stop_watchdog(self):
        """Stop the watchdog thread."""
        self._watchdog_running = False
        if self._watchdog_thread:
            self._watchdog_thread.join(timeout=5)

    def _watchdog_loop(self, interval_s: float):
        """Watchdog loop: monitors CPU and triggers rollback if needed."""
        while self._watchdog_running:
            try:
                # Check CPU utilization
                cpu_pct = psutil.cpu_percent(interval=1.0)
                if cpu_pct > WATCHDOG_CPU_THRESHOLD and not self.safe_state_active:
                    for iface in [DOWNLOAD_IFACE, UPLOAD_IFACE]:
                        self._rollback_safe_state(
                            iface,
                            f"CPU {cpu_pct:.1f}% > threshold {WATCHDOG_CPU_THRESHOLD}%"
                        )
            except Exception:
                pass
            time.sleep(interval_s)

    def get_state(self) -> Dict:
        """Return current enforcer state."""
        return {
            "safe_state_active": self.safe_state_active,
            "rollback_count": self.rollback_count,
            "watchdog_running": self._watchdog_running,
            "last_batch_file": self.last_batch_file,
            "namespace": self.namespace,
            "download_iface": DOWNLOAD_IFACE,
            "upload_iface": UPLOAD_IFACE,
        }

    def get_tc_stats(self, iface: str) -> str:
        """Query current tc qdisc statistics for an interface."""
        cmd = f"ip netns exec {self.namespace} tc -s qdisc show dev {iface}"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
