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
    and applies them atomically inside ns_router or live host interface.
    Monitors system health and rolls back on failure.

    Attributes:
        safe_state_active: True if system is in safe (fq_codel) state.
        last_batch_file: Path to the last generated batch file.
        rollback_count: Number of times safe-state rollback was triggered.
    """

    def __init__(self,
                 namespace: Optional[str] = ROUTER_NS,
                 download_iface: str = DOWNLOAD_IFACE,
                 upload_iface: str = UPLOAD_IFACE):
        self.namespace = namespace
        self.download_iface = download_iface
        self.upload_iface = upload_iface
        self.safe_state_active = True
        self.last_batch_file: Optional[str] = None
        self.rollback_count = 0
        self._lock = threading.Lock()
        self._watchdog_running = False
        self._watchdog_thread: Optional[threading.Thread] = None
        self._last_apply_time = 0.0

    @property
    def ns_prefix(self) -> str:
        """Namespace execution prefix (empty string if namespace is None or '')."""
        return f"ip netns exec {self.namespace} " if self.namespace else ""

    def generate_htb_batch(self,
                            iface: str,
                            wan_rate_mbit: float,
                            class_rates_mbit: Dict[int, float],
                            headroom_factor: float = 0.90,
                            cap_bulk_ceil: bool = True,
                            ) -> str:
        """Generate tc batch commands for a 4-class HTB + fq_codel hierarchy.

        Args:
            iface: Network interface name (e.g. veth_rtr_lan).
            wan_rate_mbit: Total WAN rate in Mbit/s.
            class_rates_mbit: Dict of class_label → rate in Mbit/s.
            headroom_factor: Bottleneck ownership fraction (default: 0.90).
            cap_bulk_ceil: If True, caps bulk ceil at 70% of effective capacity.

        Returns:
            Multi-line string of tc batch commands.
        """
        # Bottleneck Ownership Rule: Shape at 90% of WAN capacity so router owns the queue
        eff_rate = round(wan_rate_mbit * headroom_factor, 2)
        ceil = f"{eff_rate:.2f}mbit"
        lines = []

        # Remove existing qdiscs
        lines.append(f"qdisc replace dev {iface} root handle 1: htb default 40")

        # Root class
        lines.append(
            f"class replace dev {iface} parent 1: classid 1:1 "
            f"htb rate {ceil} ceil {ceil}"
        )

        # Leaf qdisc parameters per class
        leaf_configs = {
            0: "fq_codel limit 1024 target 5ms interval 50ms ecn",
            1: "fq_codel limit 1024 target 5ms interval 50ms ecn",
            2: "fq_codel limit 1024 target 10ms interval 100ms ecn",
            3: "fq_codel limit 1024 target 15ms interval 100ms",
        }

        # Per-class HTB classes with fq_codel leaf qdiscs
        for cls_label in range(4):
            classid = CLASS_TO_HTB_CLASSID[cls_label]
            raw_rate = class_rates_mbit.get(cls_label, wan_rate_mbit * 0.15)
            # Scale rate to effective capacity
            rate = round(raw_rate * headroom_factor, 2)

            if cls_label == 3:
                # Guaranteed >= 15% bulk starvation floor
                rate = max(rate, round(eff_rate * 0.15, 2))
                # Bulk ceil capped at 70% to guarantee 30% instant headroom for bursty interactive flows
                cls_ceil = f"{max(rate, round(eff_rate * 0.70, 2)):.2f}mbit" if cap_bulk_ceil else ceil
            else:
                cls_ceil = ceil

            rate_str = f"{max(rate, 0.1):.2f}mbit"
            prio = cls_label + 1

            lines.append(
                f"class replace dev {iface} parent 1:1 classid {classid} "
                f"htb rate {rate_str} ceil {cls_ceil} prio {prio}"
            )

            # Unique leaf qdisc handle (11:, 12:, 13:, 14:)
            handle = f"{10 + cls_label + 1}:"
            leaf_qdisc = leaf_configs.get(cls_label, "fq_codel limit 1024 target 5ms interval 100ms ecn")
            lines.append(
                f"qdisc replace dev {iface} parent {classid} handle {handle} "
                f"{leaf_qdisc}"
            )

        # tc filter rules: match fwmark to HTB class (IPv4)
        for cls_label in range(4):
            fwmark = CLASS_TO_FWMARK[cls_label]
            classid = CLASS_TO_HTB_CLASSID[cls_label]
            lines.append(
                f"filter replace dev {iface} parent 1: protocol ip prio {cls_label + 1} "
                f"handle 0x{fwmark:02x} fw flowid {classid}"
            )

        # tc filter rules: match fwmark to HTB class (IPv6)
        for cls_label in range(4):
            fwmark = CLASS_TO_FWMARK[cls_label]
            classid = CLASS_TO_HTB_CLASSID[cls_label]
            lines.append(
                f"filter replace dev {iface} parent 1: protocol ipv6 prio {cls_label + 10} "
                f"handle 0x{fwmark:02x} fw flowid {classid}"
            )

        return "\n".join(lines)

    def generate_iptables_rules(self,
                                flow_marks: Optional[Dict[str, int]] = None,
                                include_icmp: bool = True) -> List[str]:
        """Generate iptables/ip6tables mangle rules for flow classification.

        Args:
            flow_marks: Optional dict of flow_spec → fwmark.
                        Format: "proto:port" or "proto:src_ip:dst_ip:src_port:dst_port"
            include_icmp: If True, marks ICMP/IPv6-ICMP as 0x10 for priority probing.

        Returns:
            List of iptables command strings.
        """
        commands = []
        # Create or flush AEGIS mangle chain
        for ipt in ["iptables", "ip6tables"]:
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -N AEGIS 2>/dev/null || true"
            )
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -F AEGIS"
            )
            # Ensure PREROUTING and FORWARD hook jumps to AEGIS
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -C PREROUTING -j AEGIS 2>/dev/null || "
                f"{self.ns_prefix}{ipt} -t mangle -I PREROUTING 1 -j AEGIS"
            )
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -C FORWARD -j AEGIS 2>/dev/null || "
                f"{self.ns_prefix}{ipt} -t mangle -I FORWARD 1 -j AEGIS"
            )

        # Prioritize ICMP / ICMPv6 probes with mark 0x10 (Class 1:10)
        if include_icmp:
            commands.append(
                f"{self.ns_prefix}iptables -t mangle -A AEGIS -p icmp -j MARK --set-mark 0x10"
            )
            commands.append(
                f"{self.ns_prefix}ip6tables -t mangle -A AEGIS -p ipv6-icmp -j MARK --set-mark 0x10"
            )

        # ── Control-Plane: Universal DNS Prioritization (0x10) ───────────────
        # Mark DNS traffic (-p udp --dport 53, -p udp --sport 53, -p tcp --dport 53, -p tcp --sport 53)
        # with 0x10 (Class 0: Realtime priority 1:10) so queries never get stalled behind bulk transfers
        for ipt in ["iptables", "ip6tables"]:
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -A AEGIS -p udp --dport 53 -j MARK --set-mark 0x10"
            )
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -A AEGIS -p udp --sport 53 -j MARK --set-mark 0x10"
            )
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -A AEGIS -p tcp --dport 53 -j MARK --set-mark 0x10"
            )
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -A AEGIS -p tcp --sport 53 -j MARK --set-mark 0x10"
            )

        # ── TCP Fast-Path: SYN & Small ACK Prioritization (0x10) ─────────────
        # Mark TCP SYN and small TCP ACK packets (length 0:128) with 0x10 so asymmetric
        # upload saturation never chokes downstream TCP return throughput.
        for ipt in ["iptables", "ip6tables"]:
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -A AEGIS -p tcp -m tcp --tcp-flags SYN,RST,ACK ACK -m length --length 0:128 -j MARK --set-mark 0x10"
            )
            commands.append(
                f"{self.ns_prefix}{ipt} -t mangle -A AEGIS -p tcp -m tcp --tcp-flags SYN,RST SYN -j MARK --set-mark 0x10"
            )

        # Default static standard service mappings (bidirectional: --sport AND --dport with explicit hex marks)
        # Dynamic WebRTC video call (e.g. port 55005) is deliberately NOT in static rules;
        # it requires AI FlowClassifier to classify and install dynamic flow marks.
        default_rules = [
            # Class 0: Legacy VoIP / SIP (fwmark 0x10)
            ("udp", 5060, "0x10"),
            ("udp", 5061, "0x10"),
            # Class 1: Gaming (fwmark 0x20)
            ("udp", 9000, "0x20"),
            # Class 2: Interactive video / streaming TVs / Web (fwmark 0x30)
            ("tcp", 8001, "0x30"),
            ("tcp", 8002, "0x30"),
            ("tcp", 8003, "0x30"),
            ("udp", 8001, "0x30"),
            ("udp", 8002, "0x30"),
            ("udp", 8003, "0x30"),
            ("tcp", 1935, "0x30"),
            ("tcp", 80, "0x30"),
            ("tcp", 443, "0x30"),
            # Class 3: Bulk transfer (fwmark 0x40)
            ("tcp", 5201, "0x40"),
        ]

        for proto, port, hex_mark in default_rules:
            commands.append(
                f"{self.ns_prefix}iptables -t mangle -A AEGIS -p {proto} --sport {port} -j MARK --set-mark {hex_mark}"
            )
            commands.append(
                f"{self.ns_prefix}iptables -t mangle -A AEGIS -p {proto} --dport {port} -j MARK --set-mark {hex_mark}"
            )
            commands.append(
                f"{self.ns_prefix}ip6tables -t mangle -A AEGIS -p {proto} --sport {port} -j MARK --set-mark {hex_mark}"
            )
            commands.append(
                f"{self.ns_prefix}ip6tables -t mangle -A AEGIS -p {proto} --dport {port} -j MARK --set-mark {hex_mark}"
            )

        # Custom flow marks from classifier / overrides
        if flow_marks:
            for spec, mark_val in flow_marks.items():
                m_hex = f"0x{mark_val:x}" if isinstance(mark_val, int) else (mark_val if str(mark_val).startswith("0x") else f"0x{int(mark_val):x}")
                parts = spec.split(":")
                if len(parts) == 2:
                    p_proto, p_port = parts[0], parts[1]
                    commands.append(
                        f"{self.ns_prefix}iptables -t mangle -I AEGIS 1 -p {p_proto} --sport {p_port} -j MARK --set-mark {m_hex}"
                    )
                    commands.append(
                        f"{self.ns_prefix}iptables -t mangle -I AEGIS 1 -p {p_proto} --dport {p_port} -j MARK --set-mark {m_hex}"
                    )
                    commands.append(
                        f"{self.ns_prefix}ip6tables -t mangle -I AEGIS 1 -p {p_proto} --sport {p_port} -j MARK --set-mark {m_hex}"
                    )
                    commands.append(
                        f"{self.ns_prefix}ip6tables -t mangle -I AEGIS 1 -p {p_proto} --dport {p_port} -j MARK --set-mark {m_hex}"
                    )
                elif len(parts) == 5:
                    p_proto, s_ip, d_ip, s_port, d_port = parts
                    cmd4 = f"{self.ns_prefix}iptables -t mangle -I AEGIS 1 -p {p_proto}"
                    if s_ip and s_ip != "*":
                        cmd4 += f" -s {s_ip}"
                    if d_ip and d_ip != "*":
                        cmd4 += f" -d {d_ip}"
                    if s_port and s_port != "*":
                        cmd4 += f" --sport {s_port}"
                    if d_port and d_port != "*":
                        cmd4 += f" --dport {d_port}"
                    cmd4 += f" -j MARK --set-mark {m_hex}"
                    commands.append(cmd4)

        return commands

    def apply_iptables_rules(self,
                             flow_marks: Optional[Dict[str, int]] = None,
                             include_icmp: bool = True) -> bool:
        """Apply iptables mangle rules inside the router namespace or host."""
        cmds = self.generate_iptables_rules(flow_marks, include_icmp=include_icmp)
        success = True
        for cmd in cmds:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode != 0:
                success = False
        return success

    def apply_batch(self, iface: str, batch_content: str) -> Tuple[bool, str]:
        """Apply tc batch atomically inside the router namespace or host.

        Args:
            iface: Interface being configured.
            batch_content: Multi-line tc batch commands.

        Returns:
            (success, output) tuple.
        """
        with self._lock:
            # Delete existing root qdisc to avoid HTB "Change operation not supported" error on re-application
            subprocess.run(
                f"{self.ns_prefix}tc qdisc del dev {iface} root 2>/dev/null || true",
                shell=True, capture_output=True
            )

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
            cmd = f"{self.ns_prefix}tc -b {batch_file.name}"
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
                       class_rates_mbit: Dict[int, float],
                       headroom_factor: float = 0.90,
                       cap_bulk_ceil: bool = True,
                       upload_rate_mbit: Optional[float] = None,
                       upload_class_rates_mbit: Optional[Dict[int, float]] = None
                       ) -> Tuple[bool, str]:
        """Apply bidirectional shaping on both download and upload interfaces.

        Supports asymmetric links (e.g. 50 Mbps down / 10 Mbps up).

        Args:
            wan_rate_mbit: Total download WAN capacity.
            class_rates_mbit: Dict of class_label → allocated download rate.
            headroom_factor: Bottleneck ownership fraction (default: 0.90).
            cap_bulk_ceil: If True, caps bulk ceil at 70% of effective capacity.
            upload_rate_mbit: Optional upload rate (defaults to wan_rate_mbit).
            upload_class_rates_mbit: Optional dict of class_label → allocated upload rate.

        Returns:
            (success, output) tuple.
        """
        up_rate = upload_rate_mbit if upload_rate_mbit is not None else wan_rate_mbit
        if upload_class_rates_mbit is not None:
            up_alloc = upload_class_rates_mbit
        elif upload_rate_mbit is not None and wan_rate_mbit > 0:
            scale = upload_rate_mbit / wan_rate_mbit
            up_alloc = {k: round(v * scale, 2) for k, v in class_rates_mbit.items()}
        else:
            up_alloc = class_rates_mbit

        # Download interface
        batch_down = self.generate_htb_batch(
            self.download_iface, wan_rate_mbit, class_rates_mbit,
            headroom_factor=headroom_factor,
            cap_bulk_ceil=cap_bulk_ceil
        )
        ok_d, out_d = self.apply_batch(self.download_iface, batch_down)
        if not ok_d:
            return False, f"Failed on download {self.download_iface}: {out_d}"

        # Upload interface
        batch_up = self.generate_htb_batch(
            self.upload_iface, up_rate, up_alloc,
            headroom_factor=headroom_factor,
            cap_bulk_ceil=cap_bulk_ceil
        )
        ok_u, out_u = self.apply_batch(self.upload_iface, batch_up)
        if not ok_u:
            return False, f"Failed on upload {self.upload_iface}: {out_u}"

        return True, "Shaping applied on both interfaces"

    def rollback(self) -> Tuple[bool, str]:
        """Manually trigger safe-state rollback on both interfaces."""
        results = []
        for iface in [self.download_iface, self.upload_iface]:
            ok = self._rollback_safe_state(iface, "Manual rollback requested")
            results.append((iface, ok))
        success = all(ok for _, ok in results)
        return success, "Rolled back to fq_codel safe state"

    def _rollback_safe_state(self, iface: str, reason: str) -> bool:
        """Roll back a single interface to fq_codel safe state."""
        cmd = f"{self.ns_prefix}tc qdisc replace dev {iface} root {SAFE_STATE_QDISC}"
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
                    for iface in [self.download_iface, self.upload_iface]:
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
            "download_iface": self.download_iface,
            "upload_iface": self.upload_iface,
        }

    def get_tc_stats(self, iface: str) -> str:
        """Query current tc qdisc statistics for an interface."""
        cmd = f"{self.ns_prefix}tc -s qdisc show dev {iface}"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return res.stdout
        except Exception as e:
            return f"Error querying tc stats: {e}"
