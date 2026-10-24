#!/usr/bin/env bash
###############################################################################
# AegisQoS — Set WAN Impairment
# Usage: sudo bash set_wan_impairment.sh [RATE_MBIT] [DELAY_MS] [JITTER_MS] [LOSS_PCT]
# Example: sudo bash set_wan_impairment.sh 20 50 10 1.0
#
# Applies tc netem on BOTH directions inside ns_wan_netem:
#   - veth_netem_in  (egress towards ns_router  = download direction)
#   - veth_netem_out (egress towards ns_server   = upload direction)
###############################################################################
set -euo pipefail

RATE="${1:-100}"       # Mbit/s
DELAY="${2:-20}"       # ms
JITTER="${3:-5}"       # ms
LOSS="${4:-0.1}"       # %

echo "=== AegisQoS WAN Impairment Update ==="
echo "  Rate:   ${RATE} Mbit/s"
echo "  Delay:  ${DELAY} ms ± ${JITTER} ms"
echo "  Loss:   ${LOSS}%"

# Download direction: veth_netem_in (egress towards ns_router)
ip netns exec ns_wan_netem tc qdisc replace dev veth_netem_in root netem \
    rate "${RATE}mbit" delay "${DELAY}ms" "${JITTER}ms" loss "${LOSS}%"

# Upload direction: veth_netem_out (egress towards ns_server)
ip netns exec ns_wan_netem tc qdisc replace dev veth_netem_out root netem \
    rate "${RATE}mbit" delay "${DELAY}ms" "${JITTER}ms" loss "${LOSS}%"

echo "[ok]   WAN impairment updated on both veth_netem_in and veth_netem_out"
echo "=== Done ==="
