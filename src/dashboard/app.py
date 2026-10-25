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
                return json.load(f)
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

    # ── Sidebar ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("⚙️ Configuration")
        api_url = st.text_input("API URL", value=API_URL)
        refresh = st.slider("Refresh interval (s)", 1, 10, REFRESH_INTERVAL)

        st.divider()
        st.header("🎯 User Intent")
        intent_flow = st.text_input("Flow ID", value="flow_1")
        intent_class = st.selectbox("Target Class", CLASS_NAMES)
        intent_boost = st.slider("Priority Boost (%)", 0, 20, 10)
        intent_ttl = st.slider("TTL (seconds)", 10, 300, 60)

        if st.button("Set Intent", type="primary"):
            try:
                resp = requests.post(f"{api_url}/intent", json={
                    "flow_id": intent_flow,
                    "target_class": CLASS_NAMES.index(intent_class),
                    "priority_boost": intent_boost,
                    "ttl_seconds": intent_ttl,
                })
                if resp.status_code == 200:
                    st.success(f"Intent set for {intent_flow}")
                else:
                    st.error(f"Failed: {resp.text}")
            except Exception as e:
                st.error(f"API error: {e}")

        st.divider()
        if st.button("🔴 Emergency Rollback", type="secondary"):
            try:
                resp = requests.post(f"{api_url}/rollback")
                if resp.status_code == 200:
                    st.warning("Rolled back to safe state (fq_codel)")
                else:
                    st.error(f"Rollback failed: {resp.text}")
            except Exception as e:
                st.error(f"API error: {e}")

    # ── Fetch Data ───────────────────────────────────────────────────────────
    metrics = fetch_metrics(api_url)
    status = fetch_status(api_url)
    live_state = fetch_live_state()

    is_live_wifi = False
    if metrics is None and live_state is not None:
        metrics = live_state
        is_live_wifi = True
        st.success(f"🟢 **Live Real-Wi-Fi Mode Active** on `{live_state.get('interface', 'enp0s1')}` with IFB ingress redirection (`{live_state.get('ingress_iface', 'ifb0')}`)")
    elif metrics is None:
        st.warning("⚠️ Cannot connect to AegisQoS API and no live Wi-Fi state found. Is the server or live daemon running?")
        st.info(f"Start API server: `python -m src.api.server` or Live Wi-Fi: `sudo python scripts/run_live_wifi.py`")

        # Show demo mode with sample data
        st.divider()
        st.subheader("📊 Demo Mode (sample data)")
        metrics = {
            "rtt_ms": 42.5, "baseline_rtt_ms": 20.0, "delta_rtt_ms": 22.5,
            "jitter_ms": 5.2, "packet_loss_pct": 0.1, "bufferbloat": False,
            "wan_rate_mbit": 100.0,
            "allocations_mbit": {"0": 25.0, "1": 35.0, "2": 25.0, "3": 15.0},
            "fsm_state": "SHAPING", "jains_fairness": 0.94,
            "cpu_pct": 3.2, "safe_state": False, "rollback_count": 0,
        }

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
        st.plotly_chart(fig, use_container_width=True)

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
        st.plotly_chart(fig, use_container_width=True)

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
        st.plotly_chart(fig, use_container_width=True)

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
        st.plotly_chart(fig, use_container_width=True)

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
        st.dataframe(flows_data, use_container_width=True)

    # ── Auto-refresh ─────────────────────────────────────────────────────────
    time.sleep(refresh)
    st.rerun()


if __name__ == "__main__":
    main()
