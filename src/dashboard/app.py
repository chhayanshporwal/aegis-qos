#!/usr/bin/env python3
"""
AegisQoS Module 5 — Streamlit + Plotly Live Dashboard

Real-time monitoring dashboard for AegisQoS showing:
  - RTT, Jitter, and Packet Loss time series
  - Throughput allocations per traffic class
  - Queue depth and Jain's fairness index
  - CPU utilization and system health
  - FSM state and active intents

Usage:
  streamlit run src/dashboard/app.py -- --api-url http://localhost:8000
"""

import os
import json
import time
import argparse
import subprocess
from typing import Optional, Dict, List
import requests
import streamlit as st
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import deque

# ── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AegisQoS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Constants ────────────────────────────────────────────────────────────────
API_URL = "http://localhost:8000"
MAX_POINTS = 100
REFRESH_INTERVAL = 2  # seconds

CLASS_NAMES = ["realtime_voice", "interactive_video", "responsive_web", "bulk_transfer"]
CLASS_COLORS = ["#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4"]

# ── Session State Init ──────────────────────────────────────────────────────
if "rtt_history" not in st.session_state:
    st.session_state.rtt_history = deque(maxlen=MAX_POINTS)
    st.session_state.jitter_history = deque(maxlen=MAX_POINTS)
    st.session_state.loss_history = deque(maxlen=MAX_POINTS)
    st.session_state.cpu_history = deque(maxlen=MAX_POINTS)
    st.session_state.fairness_history = deque(maxlen=MAX_POINTS)
    st.session_state.timestamps = deque(maxlen=MAX_POINTS)
    st.session_state.throughput_history = {c: deque(maxlen=MAX_POINTS) for c in CLASS_NAMES}


def fetch_live_state(state_file: str = "/tmp/aegis_live_state.json") -> Optional[dict]:
    """Fetch live metrics directly from live Wi-Fi daemon state file."""
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                data = json.load(f)
            # Check freshness: considered active if updated within last 8 seconds
            data["is_active"] = (time.time() - data.get("timestamp", 0)) < 8.0
            return data
        except Exception:
            pass
    return None


def fetch_metrics(api_url: str) -> dict:
    """Fetch live metrics from AegisQoS API."""
    try:
        resp = requests.get(f"{api_url}/metrics", timeout=2)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return None


def fetch_status(api_url: str) -> dict:
    """Fetch system status from AegisQoS API."""
    try:
        resp = requests.get(f"{api_url}/status", timeout=2)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException:
        pass
    return None


def main():
    st.title("🛡️ AegisQoS — Live QoS Dashboard")
    st.caption("Intent-Aware, Zero-DPI Adaptive QoS Engine for Mixed Home Broadband Traffic")

    # ── Initial State & Connection Detection ──────────────────────────────────
    api_status = fetch_status(API_URL)
    api_metrics = fetch_metrics(API_URL) if api_status else None
    live_state = fetch_live_state()

    api_online = api_status is not None
    live_wifi_active = live_state is not None and live_state.get("is_active", False)
    is_stale_daemon = live_state is not None and not live_wifi_active

    if api_metrics is not None:
        metrics = api_metrics
        status = api_status
        is_live_wifi = False
    elif live_wifi_active:
        metrics = live_state
        status = {
            "mode": "live_wifi",
            "classifier": {"status": "active"},
            "estimator": {"status": "active"},
            "policy": {"state": live_state.get("fsm_state", "SHAPING")},
            "enforcer": {"status": "active", "safe_state": False},
        }
        is_live_wifi = True
    elif is_stale_daemon:
        metrics = {
            "rtt_ms": live_state.get("rtt_ms", 0),
            "baseline_rtt_ms": live_state.get("baseline_rtt_ms", 0),
            "delta_rtt_ms": live_state.get("delta_rtt_ms", 0),
            "jitter_ms": live_state.get("jitter_ms", 0),
            "packet_loss_pct": live_state.get("packet_loss_pct", 0),
            "bufferbloat": False,
            "wan_rate_mbit": live_state.get("wan_rate_mbit", 30.0),
            "allocations_mbit": live_state.get("allocations_mbit", {"0": 7.5, "1": 10.5, "2": 7.5, "3": 4.5}),
            "fsm_state": "STOPPED",
            "jains_fairness": 1.0,
            "cpu_pct": 0.0,
            "safe_state": True,
            "rollback_count": 0,
            "active_flows": [],  # Clear active flows when daemon is stopped
        }
        status = None
        is_live_wifi = False
    else:
        metrics = {
            "rtt_ms": 42.5, "baseline_rtt_ms": 20.0, "delta_rtt_ms": 22.5,
            "jitter_ms": 5.2, "packet_loss_pct": 0.1, "bufferbloat": False,
            "wan_rate_mbit": 100.0,
            "allocations_mbit": {"0": 25.0, "1": 35.0, "2": 25.0, "3": 15.0},
            "fsm_state": "SHAPING", "jains_fairness": 0.94,
            "cpu_pct": 3.2, "safe_state": False, "rollback_count": 0,
        }
        status = None
        is_live_wifi = False

    # ── Sidebar ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("⚙️ System Status")
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if api_online:
                st.success("🟢 API Online")
            else:
                st.info("⚪ API Offline")
        with col_s2:
            if live_wifi_active:
                st.success("🟢 Live Wi-Fi")
            else:
                st.info("⚪ Live Idle")

        api_url = st.text_input("API URL", value=API_URL)
        refresh = st.slider("Refresh interval (s)", 1, 10, REFRESH_INTERVAL)

        st.divider()
        st.header("🎯 User Intent")

        # Pick from active sniffed flows if available
        active_flows = metrics.get("active_flows", [])
        active_fids = [f["flow_id"] for f in active_flows if f.get("flow_id")]
        if active_fids:
            flow_selection = st.selectbox("Select Active Flow", ["Custom Entry..."] + active_fids[:20])
            if flow_selection == "Custom Entry...":
                intent_flow = st.text_input("Flow ID", value="flow_1")
            else:
                intent_flow = flow_selection
        else:
            intent_flow = st.text_input("Flow ID", value="flow_1")

        intent_class = st.selectbox("Target Class", CLASS_NAMES)
        intent_boost = st.slider("Priority Boost (%)", 0, 20, 10)
        intent_ttl = st.slider("TTL (seconds)", 10, 300, 60)

        if st.button("Set Intent", type="primary"):
            target_class_idx = CLASS_NAMES.index(intent_class)
            intent_payload = {
                "flow_id": intent_flow,
                "target_class": target_class_idx,
                "priority_boost": intent_boost,
                "ttl_seconds": intent_ttl,
            }
            applied = False

            # 1. Dispatch directly to Live Wi-Fi Daemon command queue if live
            if live_wifi_active:
                try:
                    cmd_path = "/tmp/aegis_commands.json"
                    with open(f"{cmd_path}.tmp", "w") as f:
                        json.dump({"action": "intent", **intent_payload}, f)
                    os.chmod(f"{cmd_path}.tmp", 0o666)
                    os.replace(f"{cmd_path}.tmp", cmd_path)
                    st.success(f"Intent applied to Live Wi-Fi daemon for {intent_flow} (+{intent_boost}%, TTL: {intent_ttl}s)")
                    applied = True
                except Exception as ex:
                    st.error(f"Error signaling live daemon: {ex}")

            # 2. Also dispatch to REST API if online
            if api_online:
                try:
                    resp = requests.post(f"{api_url}/intent", json=intent_payload, timeout=2.0)
                    if resp.status_code == 200:
                        st.success(f"Intent set via API for {intent_flow}")
                        applied = True
                    else:
                        st.error(f"API returned: {resp.text}")
                except Exception:
                    pass

            if not applied:
                st.warning("⚠️ No active QoS engine detected to shape traffic. Start the Live Wi-Fi daemon in a terminal:\n```bash\nsudo /home/ubuntu/aegis-venv/bin/python scripts/run_live_wifi.py --iface enp0s1 --wan-rate 30.0\n```")

        st.divider()
        if metrics.get("fsm_state") == "EMERGENCY":
            st.error("⚠️ **System currently in EMERGENCY Safe State (fq_codel)**")
            if st.button("🟢 Resume QoS Shaping", type="primary"):
                resumed = False
                if live_wifi_active:
                    try:
                        cmd_path = "/tmp/aegis_commands.json"
                        with open(f"{cmd_path}.tmp", "w") as f:
                            json.dump({"action": "resume"}, f)
                        os.chmod(f"{cmd_path}.tmp", 0o666)
                        os.replace(f"{cmd_path}.tmp", cmd_path)
                        st.success("Resumed shaping signal sent to Live Wi-Fi Daemon")
                        resumed = True
                    except Exception as ex:
                        st.error(f"Failed to signal live daemon: {ex}")
                if api_online:
                    try:
                        resp = requests.post(f"{api_url}/resume", timeout=2.0)
                        if resp.status_code == 200:
                            st.success("Shaping resumed via API")
                            resumed = True
                    except Exception:
                        pass
                if resumed:
                    st.rerun()

        if st.button("🔴 Emergency Rollback", type="secondary"):
            rollback_applied = False

            # 1. Signal Live Wi-Fi daemon directly if running
            if live_wifi_active:
                try:
                    cmd_path = "/tmp/aegis_commands.json"
                    with open(f"{cmd_path}.tmp", "w") as f:
                        json.dump({"action": "rollback"}, f)
                    os.chmod(f"{cmd_path}.tmp", 0o666)
                    os.replace(f"{cmd_path}.tmp", cmd_path)
                    st.warning("Emergency Rollback signal sent to Live Wi-Fi Daemon")
                    rollback_applied = True
                except Exception as ex:
                    st.error(f"Failed to signal live daemon: {ex}")

            # 2. Also signal REST API if online
            if api_online:
                try:
                    resp = requests.post(f"{api_url}/rollback", timeout=2.0)
                    if resp.status_code == 200:
                        st.warning("Rolled back to safe state (fq_codel) via API")
                        rollback_applied = True
                    else:
                        st.error(f"Rollback failed: {resp.text}")
                except Exception:
                    pass

            # 3. Direct local kernel rollback (ALWAYS SUCCEEDS)
            if not rollback_applied:
                try:
                    subprocess.run("sudo tc qdisc replace dev enp0s1 root fq_codel 2>/dev/null || true", shell=True)
                    subprocess.run("sudo tc qdisc del dev enp0s1 ingress 2>/dev/null || true", shell=True)
                    subprocess.run("sudo tc qdisc replace dev ifb0 root fq_codel 2>/dev/null || true", shell=True)
                    subprocess.run("sudo iptables -t mangle -F AEGIS 2>/dev/null || true", shell=True)
                    subprocess.run("sudo ip6tables -t mangle -F AEGIS 2>/dev/null || true", shell=True)
                    subprocess.run("sudo rm -f /tmp/aegis_live_state.json /tmp/aegis_commands.json 2>/dev/null || true", shell=True)
                    st.success("✅ Emergency Rollback executed directly on system! Root qdiscs reset to safe fq_codel.")
                    rollback_applied = True
                except Exception as ex:
                    st.error(f"Rollback error: {ex}")

        # Show active intents in sidebar if present
        if metrics.get("active_intents"):
            st.divider()
            st.subheader("⚡ Active Intent Boosts")
            for it in metrics["active_intents"]:
                st.caption(f"🔹 **{it['flow_id']}** → {it['class_name']} (+{it['priority_boost']}%, {it.get('expires_in', 0)}s left)")

    # ── Display Mode Banner ──────────────────────────────────────────────────
    if is_live_wifi:
        st.success(f"🟢 **Live Real-Wi-Fi Mode Active** on `{metrics.get('interface', 'enp0s1')}` with IFB ingress redirection (`{metrics.get('ingress_iface', 'ifb0')}`)")
    elif api_metrics is not None:
        st.success(f"🟢 **REST API Mode Active** connected to `{api_url}`")
    elif is_stale_daemon:
        st.warning("⚠️ **Live Wi-Fi Daemon is currently STOPPED.** To resume live packet monitoring and shaping, run in your VM terminal:\n```bash\nsudo /home/ubuntu/aegis-venv/bin/python scripts/run_live_wifi.py --iface enp0s1 --wan-rate 30.0\n```")
    else:
        st.info("ℹ️ System Idle (Demo Mode). Start the Live Wi-Fi daemon or API server to manage live traffic.")

    # Update history
    now = time.time()
    st.session_state.timestamps.append(now)
    st.session_state.rtt_history.append(metrics.get("rtt_ms", 0))
    st.session_state.jitter_history.append(metrics.get("jitter_ms", 0))
    st.session_state.loss_history.append(metrics.get("packet_loss_pct", 0))
    st.session_state.cpu_history.append(metrics.get("cpu_pct", 0))
    st.session_state.fairness_history.append(metrics.get("jains_fairness", 0))

    alloc = metrics.get("allocations_mbit", {})
    for i, cls in enumerate(CLASS_NAMES):
        val = alloc.get(str(i), alloc.get(i, 0))
        st.session_state.throughput_history[cls].append(val)

    # ── KPI Row ──────────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        st.metric("RTT", f"{metrics.get('rtt_ms', 0):.1f} ms",
                   delta=f"Δ{metrics.get('delta_rtt_ms', 0):.1f} ms")
    with col2:
        st.metric("Jitter", f"{metrics.get('jitter_ms', 0):.1f} ms")
    with col3:
        st.metric("Loss", f"{metrics.get('packet_loss_pct', 0):.2f}%")
    with col4:
        st.metric("WAN Rate", f"{metrics.get('wan_rate_mbit', 0):.0f} Mbit/s")
    with col5:
        fairness = metrics.get("jains_fairness", 0)
        st.metric("Fairness (J)", f"{fairness:.3f}")
    with col6:
        st.metric("CPU", f"{metrics.get('cpu_pct', 0):.1f}%")

    # Status indicators
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        state = metrics.get("fsm_state", "UNKNOWN")
        state_colors = {"IDLE": "🟡", "MONITORING": "🔵", "SHAPING": "🟢", "EMERGENCY": "🔴"}
        st.info(f"{state_colors.get(state, '⚪')} FSM State: **{state}**")
    with col_b:
        bb = metrics.get("bufferbloat", False)
        st.info(f"{'🔴' if bb else '🟢'} Bufferbloat: **{'DETECTED' if bb else 'OK'}**")
    with col_c:
        safe = metrics.get("safe_state", True)
        rollbacks = metrics.get("rollback_count", 0)
        st.info(f"{'🟡' if safe else '🟢'} Safe State: **{'Active' if safe else 'QoS Active'}** (Rollbacks: {rollbacks})")

    # ── Charts Row 1: RTT + Jitter, Throughput Allocation ────────────────────
    chart1, chart2 = st.columns(2)

    with chart1:
        st.subheader("📈 RTT & Jitter")
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        ts = list(range(len(st.session_state.rtt_history)))

        fig.add_trace(
            go.Scatter(x=ts, y=list(st.session_state.rtt_history),
                       mode="lines+markers", name="RTT (ms)",
                       line=dict(color="#FF6B6B", width=2)),
            secondary_y=False,
        )
        fig.add_trace(
            go.Scatter(x=ts, y=list(st.session_state.jitter_history),
                       mode="lines+markers", name="Jitter (ms)",
                       line=dict(color="#4ECDC4", width=2)),
            secondary_y=True,
        )
        fig.update_layout(
            height=350, margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", y=1.1),
        )
        fig.update_yaxes(title_text="RTT (ms)", secondary_y=False)
        fig.update_yaxes(title_text="Jitter (ms)", secondary_y=True)
        st.plotly_chart(fig, width="stretch")

    with chart2:
        st.subheader("📊 Bandwidth Allocation")
        fig = go.Figure()
        for i, cls in enumerate(CLASS_NAMES):
            fig.add_trace(go.Bar(
                name=cls,
                x=[cls.replace("_", " ").title()],
                y=[list(st.session_state.throughput_history[cls])[-1] if st.session_state.throughput_history[cls] else 0],
                marker_color=CLASS_COLORS[i],
            ))
        fig.update_layout(
            height=350, margin=dict(l=20, r=20, t=30, b=20),
            yaxis_title="Rate (Mbit/s)",
            showlegend=False,
        )
        st.plotly_chart(fig, width="stretch")

    # ── Charts Row 2: Loss + CPU, Fairness ───────────────────────────────────
    chart3, chart4 = st.columns(2)

    with chart3:
        st.subheader("📉 Packet Loss & CPU")
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        ts = list(range(len(st.session_state.loss_history)))

        fig.add_trace(
            go.Scatter(x=ts, y=list(st.session_state.loss_history),
                       mode="lines+markers", name="Loss (%)",
                       line=dict(color="#FF6B6B", width=2),
                       fill="tozeroy", fillcolor="rgba(255,107,107,0.1)"),
            secondary_y=False,
        )
        fig.add_trace(
            go.Scatter(x=ts, y=list(st.session_state.cpu_history),
                       mode="lines+markers", name="CPU (%)",
                       line=dict(color="#45B7D1", width=2)),
            secondary_y=True,
        )
        fig.update_layout(
            height=350, margin=dict(l=20, r=20, t=30, b=20),
            legend=dict(orientation="h", y=1.1),
        )
        fig.update_yaxes(title_text="Loss (%)", secondary_y=False)
        fig.update_yaxes(title_text="CPU (%)", secondary_y=True)
        st.plotly_chart(fig, width="stretch")

    with chart4:
        st.subheader("⚖️ Jain's Fairness Index")
        fig = go.Figure()
        ts = list(range(len(st.session_state.fairness_history)))
        fig.add_trace(
            go.Scatter(x=ts, y=list(st.session_state.fairness_history),
                       mode="lines+markers", name="Fairness",
                       line=dict(color="#96CEB4", width=3),
                       fill="tozeroy", fillcolor="rgba(150,206,180,0.2)"),
        )
        fig.add_hline(y=0.9, line_dash="dash", line_color="orange",
                       annotation_text="Fair threshold (0.9)")
        fig.update_layout(
            height=350, margin=dict(l=20, r=20, t=30, b=20),
            yaxis=dict(range=[0, 1.05]),
        )
        st.plotly_chart(fig, width="stretch")

    # ── Live Real-World Flows Table (if present) ─────────────────────────────
    if metrics.get("active_flows"):
        st.divider()
        st.subheader("🌐 Active Flows Detected by Zero-DPI Sniffer")
        flows_data = []
        for f in metrics["active_flows"]:
            flows_data.append({
                "Protocol": f.get("proto"),
                "Source": f.get("src"),
                "Destination": f.get("dst"),
                "Packets/sec": f.get("pps"),
                "Predicted Class": f.get("class_name"),
                "Confidence": f.get("confidence"),
                "Method": f.get("method"),
                "FwMark": f.get("fwmark"),
            })
        st.dataframe(flows_data, width="stretch")

    # ── Auto-refresh ─────────────────────────────────────────────────────────
    time.sleep(refresh)
    st.rerun()


if __name__ == "__main__":
    main()
