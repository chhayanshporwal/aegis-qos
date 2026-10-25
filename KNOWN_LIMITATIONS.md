# Known Limitations — AegisQoS

## Prototype vs Production

| Aspect | AegisQoS Prototype | Production-Grade System |
|---|---|---|
| **Topology** | Dual-Mode: 4 Linux `ip netns` namespaces for reproducible evaluation & CI, plus **Live Real-Wi-Fi Mode** (`enp0s1` + `ifb0` ingress redirection) | Physical CPE router (RDK-B / OpenWrt) with native ISP uplink |
| **Traffic shaping** | `tc` HTB + `fq_codel` qdiscs on `veth` / `enp0s1` / `ifb0` | eBPF / XDP programs on NIC queues, hardware-offloaded QoS |
| **WAN emulation** | `tc netem` rate / delay / jitter / loss on `ns_wan_netem` namespace | Real ISP last-mile characteristics (DOCSIS, PON, DSL) |
| **Classification** | LightGBM / ONNX on L3/L4 statistical metadata (zero DPI) | Production ML pipeline with continuous retraining, A/B testing |
| **Capacity estimation** | Passive ΔRTT + AIMD heuristic | BBR-style in-kernel congestion sensing or ISP API (TR-369 USP) |
| **Dashboard** | Streamlit + Plotly on `localhost` | Grafana + Prometheus, multi-tenant, SSO |
| **Scale** | Single home gateway (1–20 concurrent flows) | Fleet management across thousands of CPEs |

## `tc netem` Emulation Model

- **Accuracy:** `tc netem` applies delay / jitter / loss in the **egress** path of a network namespace's veth interface. It models ISP impairment at L2/L3, but does **not** faithfully reproduce DOCSIS CMTS scheduling, PON DBA contention, or DSL interleaving artifacts.
- **Clock granularity:** Kernel timer resolution (`HZ=250` on typical Ubuntu) introduces ±4 ms jitter floor. Sub-millisecond netem delay values are unreliable.
- **Veth offloading:** TCP performance on veth pairs is distorted by GSO/GRO/TSO unless explicitly disabled via `ethtool -K`. This prototype disables all offloads.

## Future Integration Path

- **RDK-B:** The enforcement module (`tc_enforcer.py`) generates `tc -b` batch commands. On RDK-B CPE, these would be replaced by `hal_qos_*` HAL API calls.
- **eBPF/XDP:** The classifier could run as an eBPF TC program attached to the ingress qdisc, providing line-rate classification without user-space overhead.
- **TR-369 (USP):** The capacity estimator could subscribe to `Device.IP.Diagnostics.IPPing` and `Device.QoS.*` data model nodes via TR-369 for real-time telemetry.

## Privacy & Compliance

- **Zero DPI:** AegisQoS **never** decrypts or inspects L7 payloads. Classification relies exclusively on L3/L4 statistical metadata (packet sizes, inter-arrival times, protocol numbers, 5-tuple hash).
- **No PII collection:** Flow metadata is ephemeral and not persisted beyond the 500 ms sliding window.
