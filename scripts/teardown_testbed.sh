#!/usr/bin/env bash
###############################################################################
# AegisQoS — Teardown: Clean removal of all namespaces and virtual interfaces
###############################################################################
set -euo pipefail

echo "=== AegisQoS Testbed Teardown ==="

# Remove IFB device inside ns_router first (before deleting the namespace)
if ip netns list | grep -qw ns_router; then
    ip netns exec ns_router ip link del ifb0 2>/dev/null || true
    echo "[ok]   Removed ifb0 from ns_router"
fi

# Delete all namespaces (this also removes all veth pairs attached to them)
for ns in ns_clients ns_router ns_wan_netem ns_server; do
    if ip netns list | grep -qw "$ns"; then
        ip netns del "$ns"
        echo "[ok]   Deleted namespace $ns"
    else
        echo "[info] Namespace $ns does not exist — skipping."
    fi
done

echo "=== AegisQoS Testbed Teardown COMPLETE ==="
