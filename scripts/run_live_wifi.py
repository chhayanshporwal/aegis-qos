#!/usr/bin/env python3
"""
AegisQoS — Live Wi-Fi & Real Network Traffic Daemon (scripts/run_live_wifi.py)

Deploys AegisQoS directly onto the live network interface (e.g. enp0s1 connected
to home/event Wi-Fi) with IFB ingress redirection:
  - Download shaping on ifb0 (redirected from enp0s1 ingress).
  - Upload shaping on enp0s1 (native egress).
  - Live Zero-DPI AF_PACKET packet sniffing (reads only 54-byte headers).
  - Continuous active ICMP probing against 1.1.1.1 to detect ISP bufferbloat.
  - Real-time ML flow classification and dynamic iptables fwmark assignment.
  - Live terminal status table and /tmp/aegis_live_state.json state publishing.
"""

import os
import sys
import time
import json
import signal
import argparse
import subprocess
import threading
from typing import Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import psutil
from src.models.flow_classifier import FlowClassifier, CLASS_NAMES
from src.estimator.capacity_estimator import CapacityEstimator
from src.policy.policy_engine import PolicyEngine, PolicyState, CLASS_TO_FWMARK
from src.enforcement.tc_enforcer import TcEnforcer
from src.telemetry.live_sniffer import LivePacketSniffer


# ── Ingress Redirection Setup & Teardown ─────────────────────────────────────

def setup_ifb_redirect(phys_iface: str = "enp0s1", ifb_iface: str = "ifb0") -> bool:
    """Configure IFB ingress redirection so download traffic can be shaped via tc."""
    print(f"[LiveWi-Fi] Setting up IFB ingress redirection: {phys_iface} -> {ifb_iface}...")
    try:
        # Load kernel IFB driver
        subprocess.run("modprobe ifb numifbs=1 2>/dev/null || true", shell=True, check=False)
        subprocess.run(f"ip link set dev {ifb_iface} up", shell=True, check=True)

        # Remove existing ingress qdisc on physical interface
        subprocess.run(f"tc qdisc del dev {phys_iface} ingress 2>/dev/null || true", shell=True, check=False)

        # Attach ingress qdisc to physical interface
        subprocess.run(f"tc qdisc add dev {phys_iface} handle ffff: ingress", shell=True, check=True)

        # Redirect all incoming frames to ifb_iface egress
        cmd = (
            f"tc filter add dev {phys_iface} parent ffff: protocol all u32 "
            f"match u32 0 0 action mirred egress redirect dev {ifb_iface}"
        )
        subprocess.run(cmd, shell=True, check=True)
        print(f"[LiveWi-Fi] Ingress redirect successfully active on {ifb_iface}.")
        return True
    except Exception as e:
        print(f"[LiveWi-Fi] Error configuring IFB redirection: {e}")
        return False


def teardown_ifb_redirect(phys_iface: str = "enp0s1", ifb_iface: str = "ifb0"):
    """Restore network interfaces and clear QoS queues."""
    print(f"\n[LiveWi-Fi] Cleaning up {phys_iface} and {ifb_iface}...")
    subprocess.run(f"tc qdisc del dev {phys_iface} ingress 2>/dev/null || true", shell=True, check=False)
    subprocess.run(f"tc qdisc del dev {phys_iface} root 2>/dev/null || true", shell=True, check=False)
    subprocess.run(f"tc qdisc del dev {ifb_iface} root 2>/dev/null || true", shell=True, check=False)
    subprocess.run(f"ip link set dev {ifb_iface} down 2>/dev/null || true", shell=True, check=False)
    subprocess.run("iptables -t mangle -F AEGIS 2>/dev/null || true", shell=True, check=False)
    subprocess.run("ip6tables -t mangle -F AEGIS 2>/dev/null || true", shell=True, check=False)
    print(f"[LiveWi-Fi] Cleanup complete.")


# ── Live Daemon Runner ───────────────────────────────────────────────────────

class LiveWifiDaemon:
    """Manages live Wi-Fi packet capture, ML classification, and TC shaping."""

    def __init__(self,
                 iface: str = "enp0s1",
                 ifb: str = "ifb0",
                 wan_rate: float = 50.0,
                 upload_rate: Optional[float] = None,
                 ping_target: str = "1.1.1.1",
                 interval: float = 2.0,
                 state_file: str = "/tmp/aegis_live_state.json"):
        self.iface = iface
        self.ifb = ifb
        self.wan_rate = wan_rate
        self.upload_rate = upload_rate if upload_rate is not None else round(wan_rate * 0.3, 1)
        self.ping_target = ping_target
        self.interval = interval
        self.state_file = state_file
        self.running = False

        # Initialize AegisQoS modules in host (namespace=None)
        self.classifier = FlowClassifier(
            onnx_path=os.path.join(PROJECT_ROOT, "models/flow_classifier.onnx"),
            pkl_path=os.path.join(PROJECT_ROOT, "models/flow_classifier_lgbm.pkl")
        )
        self.estimator = CapacityEstimator(
            target_ip=ping_target,
            initial_rate_mbit=wan_rate,
            namespace=None,
        )
        self.policy = PolicyEngine(wan_rate_mbit=wan_rate)
        self.enforcer = TcEnforcer(
            namespace=None,
            download_iface=self.ifb,
            upload_iface=self.iface
        )
        self.sniffer = LivePacketSniffer(iface=self.iface, classifier=self.classifier)

    def start(self):
        """Start the live Wi-Fi QoS daemon."""
        self.running = True

        # 1. Setup IFB redirect
        setup_ifb_redirect(self.iface, self.ifb)

        # 2. Apply initial control-plane rules
        self.enforcer.apply_iptables_rules(flow_marks=None, include_icmp=True)

        # 3. Apply baseline shaping
        initial_allocs = self.policy.compute_allocations(
            active_classes=[0, 1, 2, 3],
            wan_rate_mbit=self.wan_rate
        )
        self.enforcer.apply_shaping(
            wan_rate_mbit=self.wan_rate,
            class_rates_mbit=initial_allocs,
            headroom_factor=0.90,
            cap_bulk_ceil=True,
            upload_rate_mbit=self.upload_rate
        )

        # 4. Start sniffer thread
        self.sniffer.start()

        # 5. Transition policy FSM
        self.policy.transition(PolicyState.MONITORING)
        self.policy.transition(PolicyState.SHAPING)

        print(f"[LiveWi-Fi] Daemon running! Target: {self.ping_target} | Download: {self.wan_rate}M | Upload: {self.upload_rate}M")
        print(f"[LiveWi-Fi] State output published to {self.state_file}")

        # 6. Main 2-second adaptive control loop
        last_flow_counts: Dict[str, int] = {}
        last_time = time.time()

        try:
            while self.running:
                loop_start = time.time()
                dt = max(loop_start - last_time, 0.1)
                last_time = loop_start

                # A0. Process pending commands / user intents from dashboard
                cmd_file = "/tmp/aegis_commands.json"
                if os.path.exists(cmd_file):
                    try:
                        with open(cmd_file, "r") as f:
                            cmd = json.load(f)
                        os.remove(cmd_file)
                        action = cmd.get("action")
                        if action == "rollback":
                            print("[LiveWi-Fi] 🔴 Emergency Rollback commanded! Resetting to safe fq_codel...")
                            self.enforcer.rollback()
                            self.policy.transition(PolicyState.EMERGENCY)
                            self.policy.clear_intents()
                            self.classifier.clear_all_overrides()
                        elif action == "resume":
                            print("[LiveWi-Fi] 🟢 Resuming QoS shaping from safe state...")
                            self.policy.transition(PolicyState.IDLE)
                            self.policy.transition(PolicyState.MONITORING)
                            self.policy.transition(PolicyState.SHAPING)
                        elif action == "intent":
                            fid = cmd.get("flow_id", "")
                            t_cls = int(cmd.get("target_class", 0))
                            boost = float(cmd.get("priority_boost", 10.0))
                            ttl = float(cmd.get("ttl_seconds", 60.0))
                            self.policy.add_intent(fid, t_cls, boost, ttl)
                            self.classifier.set_override(fid, t_cls, ttl_seconds=ttl)
                            if self.policy.state in (PolicyState.EMERGENCY, PolicyState.IDLE):
                                self.policy.transition(PolicyState.IDLE)
                                self.policy.transition(PolicyState.MONITORING)
                                self.policy.transition(PolicyState.SHAPING)
                    except Exception as ex:
                        print(f"[LiveWi-Fi] Error processing command: {ex}")

                # Periodically purge expired overrides and expired intents
                self.classifier.cleanup_expired_overrides()
                self.policy._expire_intents()

                # A. Measure live RTT to 1.1.1.1
                rtt, jitter, loss = self.estimator.measure_rtt()
                if rtt > 0:
                    self.estimator.update_rtt(rtt, jitter, loss)

                # B. Inspect active flows captured by Zero-DPI sniffer
                active_ids = self.classifier.get_active_flow_ids(active_within_ms=3000.0)
                classified_flows = []
                dynamic_marks: Dict[str, int] = {}
                active_classes = set([2])  # Default responsive web

                for fid in active_ids[:20]:  # Limit top 20 active flows
                    label, conf, method = self.classifier.classify(fid)
                    active_classes.add(label)
                    mark = CLASS_TO_FWMARK.get(label, 0x30)
                    dynamic_marks[fid] = mark

                    # Calculate packet rate
                    cur_count = self.sniffer.flow_counts.get(fid, 0)
                    prev_count = last_flow_counts.get(fid, 0)
                    pps = round((cur_count - prev_count) / dt, 1) if dt > 0 else 0.0
                    last_flow_counts[fid] = cur_count

                    parts = fid.split(":")
                    p_name = parts[0] if len(parts) >= 1 else "ip"
                    src_str = f"{parts[1]}:{parts[3]}" if len(parts) >= 5 else ""
                    dst_str = f"{parts[2]}:{parts[4]}" if len(parts) >= 5 else ""

                    classified_flows.append({
                        "flow_id": fid,
                        "proto": p_name.upper(),
                        "src": src_str,
                        "dst": dst_str,
                        "pps": pps,
                        "class_label": label,
                        "class_name": self.classifier.get_class_name(label),
                        "confidence": round(conf, 3),
                        "method": method,
                        "fwmark": f"0x{mark:x}",
                    })

                # C & D. Dynamically update iptables fwmark rules & traffic shaping
                if self.policy.state == PolicyState.EMERGENCY:
                    # In safe-state EMERGENCY: maintain baseline fq_codel, do NOT re-shape
                    allocations = {0: 0.0, 1: 0.0, 2: 0.0, 3: 0.0}
                else:
                    # C. Dynamically update iptables fwmark rules
                    if dynamic_marks:
                        self.enforcer.apply_iptables_rules(flow_marks=dynamic_marks, include_icmp=True)

                    # D. Dynamically recompute and apply bandwidth allocations
                    eff_wan_rate = self.estimator.wan_rate_mbit
                    allocations = self.policy.compute_allocations(
                        active_classes=list(active_classes),
                        wan_rate_mbit=eff_wan_rate
                    )
                    self.enforcer.apply_shaping(
                        wan_rate_mbit=eff_wan_rate,
                        class_rates_mbit=allocations,
                        headroom_factor=0.90,
                        cap_bulk_ceil=True,
                        upload_rate_mbit=self.upload_rate
                    )

                # E. Print Live Terminal Table
                self._print_terminal_table(classified_flows)

                # F. Export Live JSON State for Streamlit Dashboard
                self._export_state(classified_flows, allocations)

                # Sleep remainder of interval
                elapsed = time.time() - loop_start
                sleep_time = max(0.0, self.interval - elapsed)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            print("\n[LiveWi-Fi] Received shutdown signal.")
        finally:
            self.stop()

    def stop(self):
        """Gracefully stop sniffer and restore interfaces."""
        if getattr(self, "_stopped", False):
            return
        self._stopped = True
        self.running = False
        self.sniffer.stop()
        self.enforcer.rollback()
        teardown_ifb_redirect(self.iface, self.ifb)
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
            if os.path.exists("/tmp/aegis_commands.json"):
                os.remove("/tmp/aegis_commands.json")
        except Exception:
            pass

    def _print_terminal_table(self, flows: List[Dict]):
        """Render a clean ASCII status and flow classification table."""
        os.system("clear" if os.name == "posix" else "cls")
        est_state = self.estimator.get_state()
        cpu_pct = psutil.cpu_percent(interval=None)

        print("╔═══════════════════════════════════════════════════════════════════════════════╗")
        print("║                     🛡️  AegisQoS Live Real-Wi-Fi Monitor                       ║")
        print("╠═══════════════════════════════════════════════════════════════════════════════╣")
        print(f"║  Interface: {self.iface:<10}  |  IFB: {self.ifb:<8}  |  Target: {self.ping_target:<15}  ║")
        rtt_str = f"{est_state['current_rtt_ms']:.1f} ms (Δ {est_state['delta_rtt_ms']:.1f} ms)"
        bloat_str = "⚠️  DETECTED" if est_state["bufferbloat_detected"] else "✅ CLEAN"
        print(f"║  RTT: {rtt_str:<22}  |  Jitter: {est_state['jitter_ms']:.1f} ms  |  Loss: {est_state['packet_loss_pct']:.1f}%        ║")
        print(f"║  Capacity: {est_state['wan_rate_mbit']:.1f} Mbps (Down) / {self.upload_rate:.1f} Mbps (Up)  |  Bufferbloat: {bloat_str:<12} ║")
        print(f"║  Total Pkts: {self.sniffer.packet_count:<12}  |  Total Bytes: {round(self.sniffer.byte_count/1e6, 2)} MB  |  CPU: {cpu_pct:.1f}%       ║")
        print("╠═══════════════════════════════════════════════════════════════════════════════╣")
        print("║                               Active Flows Table                              ║")
        print("╟───────────────────────────────────────────────────────────────────────────────╢")
        print("║ PROTO │ SOURCE                 │ DESTINATION            │ PPS  │ CLASS     │ CONF  │ MARK ║")
        print("╟───────┼────────────────────────┼────────────────────────┼──────┼───────────┼───────┼──────╢")

        if not flows:
            print("║   --  │ Waiting for traffic... │                        │  --  │    --     │  --   │  --  ║")
        else:
            for f in flows[:12]:
                proto = f["proto"][:5]
                src = f["src"][:22]
                dst = f["dst"][:22]
                pps = f"{f['pps']:.1f}"[:5]
                cname = f["class_name"][:10]
                conf = f"{f['confidence']:.2f}"[:5]
                mark = f["fwmark"][:5]
                print(f"║ {proto:<5} │ {src:<22} │ {dst:<22} │ {pps:>4} │ {cname:<9} │ {conf:>5} │ {mark:<4} ║")

        print("╚═══════════════════════════════════════════════════════════════════════════════╝")
        print(" Press Ctrl+C to stop and restore network interfaces.\n")

    def _export_state(self, flows: List[Dict], allocations: Dict[int, float]):
        """Publish real-time telemetry to JSON for the Streamlit dashboard."""
        est_state = self.estimator.get_state()
        data = {
            "mode": "live_wifi",
            "interface": self.iface,
            "ingress_iface": self.ifb,
            "timestamp": time.time(),
            "rtt_ms": est_state["current_rtt_ms"],
            "baseline_rtt_ms": est_state["baseline_rtt_ms"],
            "delta_rtt_ms": est_state["delta_rtt_ms"],
            "jitter_ms": est_state["jitter_ms"],
            "packet_loss_pct": est_state["packet_loss_pct"],
            "bufferbloat": est_state["bufferbloat_detected"],
            "wan_rate_mbit": est_state["wan_rate_mbit"],
            "upload_rate_mbit": self.upload_rate,
            "fsm_state": self.policy.state.value,
            "allocations_mbit": {str(k): v for k, v in allocations.items()},
            "packet_count": self.sniffer.packet_count,
            "byte_count": self.sniffer.byte_count,
            "cpu_pct": psutil.cpu_percent(interval=None),
            "active_flows": flows,
            "active_intents": [
                {
                    "flow_id": i.flow_id,
                    "target_class": i.target_class,
                    "class_name": self.classifier.get_class_name(i.target_class),
                    "priority_boost": i.priority_boost,
                    "expires_in": max(0.0, round(i.created_at + i.ttl_seconds - time.time(), 1)),
                }
                for i in self.policy.user_intents.values() if not i.expired
            ],
        }
        try:
            tmp_path = f"{self.state_file}.tmp"
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o666)
            os.replace(tmp_path, self.state_file)
        except Exception:
            try:
                with open(self.state_file, "w") as f:
                    json.dump(data, f, indent=2)
                os.chmod(self.state_file, 0o666)
            except Exception:
                pass


# ── Entrypoint ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AegisQoS Live Real-Wi-Fi Daemon")
    parser.add_argument("--iface", type=str, default="enp0s1",
                        help="Physical interface connected to Wi-Fi/Internet (default: enp0s1)")
    parser.add_argument("--ifb", type=str, default="ifb0",
                        help="Intermediate functional block device for ingress shaping (default: ifb0)")
    parser.add_argument("--wan-rate", type=float, default=50.0,
                        help="Initial download WAN rate in Mbit/s (default: 50.0)")
    parser.add_argument("--upload-rate", type=float, default=15.0,
                        help="Initial upload WAN rate in Mbit/s (default: 15.0)")
    parser.add_argument("--ping-target", type=str, default="1.1.1.1",
                        help="ICMP target to track live ISP latency and bufferbloat (default: 1.1.1.1)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Control loop adaptation interval in seconds (default: 2.0)")

    args = parser.parse_args()

    daemon = LiveWifiDaemon(
        iface=args.iface,
        ifb=args.ifb,
        wan_rate=args.wan_rate,
        upload_rate=args.upload_rate,
        ping_target=args.ping_target,
        interval=args.interval
    )

    # Register OS signals for graceful shutdown
    signal.signal(signal.SIGINT, lambda sig, frame: daemon.stop())
    signal.signal(signal.SIGTERM, lambda sig, frame: daemon.stop())

    daemon.start()


if __name__ == "__main__":
    main()
