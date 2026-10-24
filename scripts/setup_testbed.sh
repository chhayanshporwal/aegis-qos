#!/usr/bin/env bash
###############################################################################
# AegisQoS — Idempotent 4-Namespace Testbed Setup
# Topology:
#   ns_clients <--veth--> ns_router <--veth--> ns_wan_netem <--veth--> ns_server
#
# Subnets:
#   LAN  (ns_clients <-> ns_router):    10.0.1.0/24,  fd00:1::/64
#   WAN-int (ns_router <-> ns_wan_netem): 10.0.2.0/24, fd00:2::/64
#   WAN-ext (ns_wan_netem <-> ns_server): 10.0.3.0/24, fd00:3::/64
#
# All veth offloads (tx, rx, tso, gso, gro) are disabled.
# Dual-stack IPv4 + IPv6 with full forwarding and routing.
###############################################################################
set -euo pipefail

echo "=== AegisQoS Testbed Setup ==="

# ---------- helper: idempotent namespace creation ----------------------------
create_ns() {
    local ns="$1"
    if ip netns list | grep -qw "$ns"; then
        echo "[info] Namespace $ns already exists — skipping creation."
    else
        ip netns add "$ns"
        echo "[ok]   Created namespace $ns"
    fi
    # Enable loopback inside the namespace
    ip netns exec "$ns" ip link set lo up
}

# ---------- helper: idempotent veth pair creation ----------------------------
create_veth_pair() {
    local veth_a="$1" ns_a="$2" veth_b="$3" ns_b="$4"
    if ip netns exec "$ns_a" ip link show "$veth_a" &>/dev/null; then
        echo "[info] Veth $veth_a already exists in $ns_a — skipping."
        return 0
    fi
    ip link add "$veth_a" type veth peer name "$veth_b"
    ip link set "$veth_a" netns "$ns_a"
    ip link set "$veth_b" netns "$ns_b"
    echo "[ok]   Created veth pair $veth_a ($ns_a) <-> $veth_b ($ns_b)"
}

# ---------- helper: disable offloads on a veth inside a namespace -----------
disable_offloads() {
    local ns="$1" iface="$2"
    ip netns exec "$ns" ethtool -K "$iface" tx off rx off tso off gso off gro off 2>/dev/null || true
    echo "[ok]   Disabled offloads on $iface in $ns"
}

# ---------- helper: assign address and bring up interface --------------------
assign_addr() {
    local ns="$1" iface="$2" ipv4="$3" ipv6="$4"
    ip netns exec "$ns" ip addr flush dev "$iface" scope global 2>/dev/null || true
    ip netns exec "$ns" ip addr add "$ipv4" dev "$iface"
    ip netns exec "$ns" ip -6 addr add "$ipv6" dev "$iface"
    ip netns exec "$ns" ip link set "$iface" up
    echo "[ok]   $iface in $ns => $ipv4, $ipv6"
}

# =============================================================================
# 1. CREATE NAMESPACES
# =============================================================================
for ns in ns_clients ns_router ns_wan_netem ns_server; do
    create_ns "$ns"
done

# =============================================================================
# 2. CREATE VETH PAIRS
# =============================================================================
# LAN link: ns_clients <-> ns_router
create_veth_pair veth_cli_lan ns_clients veth_rtr_lan ns_router

# WAN-internal link: ns_router <-> ns_wan_netem
create_veth_pair veth_rtr_wan ns_router veth_netem_in ns_wan_netem

# WAN-external link: ns_wan_netem <-> ns_server
create_veth_pair veth_netem_out ns_wan_netem veth_srv_wan ns_server

# =============================================================================
# 3. DISABLE OFFLOADS ON ALL VETH INTERFACES
# =============================================================================
disable_offloads ns_clients   veth_cli_lan
disable_offloads ns_router    veth_rtr_lan
disable_offloads ns_router    veth_rtr_wan
disable_offloads ns_wan_netem veth_netem_in
disable_offloads ns_wan_netem veth_netem_out
disable_offloads ns_server    veth_srv_wan

# =============================================================================
# 4. ASSIGN IP ADDRESSES (Dual-Stack)
# =============================================================================
# LAN segment: 10.0.1.0/24, fd00:1::/64
assign_addr ns_clients veth_cli_lan "10.0.1.2/24"  "fd00:1::2/64"
assign_addr ns_router  veth_rtr_lan "10.0.1.1/24"  "fd00:1::1/64"

# WAN-internal segment: 10.0.2.0/24, fd00:2::/64
assign_addr ns_router    veth_rtr_wan  "10.0.2.1/24"  "fd00:2::1/64"
assign_addr ns_wan_netem veth_netem_in "10.0.2.2/24"  "fd00:2::2/64"

# WAN-external segment: 10.0.3.0/24, fd00:3::/64
assign_addr ns_wan_netem veth_netem_out "10.0.3.1/24"  "fd00:3::1/64"
assign_addr ns_server    veth_srv_wan   "10.0.3.2/24"  "fd00:3::2/64"

# =============================================================================
# 5. ENABLE IPv4 & IPv6 FORWARDING
# =============================================================================
for ns in ns_router ns_wan_netem; do
    ip netns exec "$ns" sysctl -w net.ipv4.ip_forward=1          >/dev/null
    ip netns exec "$ns" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
    echo "[ok]   Enabled IPv4+IPv6 forwarding in $ns"
done

# Disable DAD (duplicate address detection) delays on all namespaces
for ns in ns_clients ns_router ns_wan_netem ns_server; do
    ip netns exec "$ns" sysctl -w net.ipv6.conf.all.accept_dad=0      >/dev/null 2>&1 || true
    ip netns exec "$ns" sysctl -w net.ipv6.conf.default.accept_dad=0  >/dev/null 2>&1 || true
done

# =============================================================================
# 6. STATIC ROUTES
# =============================================================================
# ns_clients: default via ns_router LAN gateway
ip netns exec ns_clients ip route replace default via 10.0.1.1
ip netns exec ns_clients ip -6 route replace default via fd00:1::1

# ns_router: route to server subnet via ns_wan_netem
ip netns exec ns_router ip route replace 10.0.3.0/24 via 10.0.2.2
ip netns exec ns_router ip -6 route replace fd00:3::/64 via fd00:2::2

# ns_wan_netem: route to client subnet via ns_router, route to server is direct
ip netns exec ns_wan_netem ip route replace 10.0.1.0/24 via 10.0.2.1
ip netns exec ns_wan_netem ip -6 route replace fd00:1::/64 via fd00:2::1

# ns_server: default via ns_wan_netem
ip netns exec ns_server ip route replace default via 10.0.3.1
ip netns exec ns_server ip -6 route replace default via fd00:3::1

echo "[ok]   All static routes configured (dual-stack)"

# =============================================================================
# 6b. STATIC ARP & NDP NEIGHBOR POPULATION (prevents NDP resolution failure)
# =============================================================================
get_mac() {
    local ns="$1" iface="$2"
    ip netns exec "$ns" cat "/sys/class/net/$iface/address"
}

CLI_MAC=$(get_mac ns_clients veth_cli_lan)
RTR_LAN_MAC=$(get_mac ns_router veth_rtr_lan)
RTR_WAN_MAC=$(get_mac ns_router veth_rtr_wan)
NETEM_IN_MAC=$(get_mac ns_wan_netem veth_netem_in)
NETEM_OUT_MAC=$(get_mac ns_wan_netem veth_netem_out)
SRV_MAC=$(get_mac ns_server veth_srv_wan)

# LAN: ns_clients <-> ns_router
ip netns exec ns_clients ip neigh replace 10.0.1.1 lladdr "$RTR_LAN_MAC" dev veth_cli_lan nud permanent
ip netns exec ns_clients ip -6 neigh replace fd00:1::1 lladdr "$RTR_LAN_MAC" dev veth_cli_lan nud permanent
ip netns exec ns_router  ip neigh replace 10.0.1.2 lladdr "$CLI_MAC" dev veth_rtr_lan nud permanent
ip netns exec ns_router  ip -6 neigh replace fd00:1::2 lladdr "$CLI_MAC" dev veth_rtr_lan nud permanent

# WAN-int: ns_router <-> ns_wan_netem
ip netns exec ns_router    ip neigh replace 10.0.2.2 lladdr "$NETEM_IN_MAC" dev veth_rtr_wan nud permanent
ip netns exec ns_router    ip -6 neigh replace fd00:2::2 lladdr "$NETEM_IN_MAC" dev veth_rtr_wan nud permanent
ip netns exec ns_wan_netem ip neigh replace 10.0.2.1 lladdr "$RTR_WAN_MAC" dev veth_netem_in nud permanent
ip netns exec ns_wan_netem ip -6 neigh replace fd00:2::1 lladdr "$RTR_WAN_MAC" dev veth_netem_in nud permanent

# WAN-ext: ns_wan_netem <-> ns_server
ip netns exec ns_wan_netem ip neigh replace 10.0.3.2 lladdr "$SRV_MAC" dev veth_netem_out nud permanent
ip netns exec ns_wan_netem ip -6 neigh replace fd00:3::2 lladdr "$SRV_MAC" dev veth_netem_out nud permanent
ip netns exec ns_server    ip neigh replace 10.0.3.1 lladdr "$NETEM_OUT_MAC" dev veth_srv_wan nud permanent
ip netns exec ns_server    ip -6 neigh replace fd00:3::1 lladdr "$NETEM_OUT_MAC" dev veth_srv_wan nud permanent

echo "[ok]   Static ARP + NDP neighbor tables populated (nud permanent)"

# =============================================================================
# 7. DEFAULT WAN IMPAIRMENT (tc netem) on ns_wan_netem
# =============================================================================
# Download direction: veth_netem_in (egress towards ns_router)
ip netns exec ns_wan_netem tc qdisc replace dev veth_netem_in root netem \
    rate 100mbit delay 20ms 5ms loss 0.1%

# Upload direction: veth_netem_out (egress towards ns_server)
ip netns exec ns_wan_netem tc qdisc replace dev veth_netem_out root netem \
    rate 100mbit delay 20ms 5ms loss 0.1%

echo "[ok]   Default WAN impairment (100 Mbit, 20ms±5ms, 0.1% loss) applied"

# =============================================================================
# 8. DEFAULT QoS on ns_router (fq_codel — safe state)
# =============================================================================
ip netns exec ns_router tc qdisc replace dev veth_rtr_lan root fq_codel
ip netns exec ns_router tc qdisc replace dev veth_rtr_wan root fq_codel

echo "[ok]   Default fq_codel QoS on ns_router (safe state)"

# =============================================================================
# 9. iptables / ip6tables MARK rules (placeholder for policy engine)
# =============================================================================
# Flush existing mangle rules in ns_router
ip netns exec ns_router iptables  -t mangle -F 2>/dev/null || true
ip netns exec ns_router ip6tables -t mangle -F 2>/dev/null || true

# Create AEGIS chain in mangle table
ip netns exec ns_router iptables  -t mangle -N AEGIS 2>/dev/null || true
ip netns exec ns_router ip6tables -t mangle -N AEGIS 2>/dev/null || true

# Jump to AEGIS chain from FORWARD
ip netns exec ns_router iptables  -t mangle -A FORWARD -j AEGIS 2>/dev/null || true
ip netns exec ns_router ip6tables -t mangle -A FORWARD -j AEGIS 2>/dev/null || true

echo "[ok]   iptables/ip6tables mangle AEGIS chain created in ns_router"

# =============================================================================
# 10. IFB (Intermediate Functional Block) for ingress on veth_rtr_wan
# =============================================================================
ip netns exec ns_router ip link add ifb0 type ifb 2>/dev/null || true
ip netns exec ns_router ip link set ifb0 up
ip netns exec ns_router tc qdisc replace dev veth_rtr_wan handle ffff: ingress
ip netns exec ns_router tc filter replace dev veth_rtr_wan parent ffff: protocol all \
    u32 match u32 0 0 action mirred egress mirror dev ifb0
ip netns exec ns_router tc qdisc replace dev ifb0 root fq_codel

echo "[ok]   IFB ingress mirror on veth_rtr_wan -> ifb0"

# =============================================================================
# VERIFICATION
# =============================================================================
echo ""
echo "=== Testbed Verification ==="

echo "--- IPv4 ping: ns_clients -> ns_server (10.0.3.2) ---"
ip netns exec ns_clients ping -c 4 -W 2 10.0.3.2

echo ""
echo "--- IPv6 ping: ns_clients -> ns_server (fd00:3::2) ---"
ip netns exec ns_clients ping6 -c 4 -W 2 fd00:3::2

echo ""
echo "=== AegisQoS Testbed Setup COMPLETE ==="
