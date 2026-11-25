#!/usr/bin/env bash
# Idempotent setup of the client/server network namespace pair.
# Safe to re-run: existing namespaces, veth pair, and addresses are reused.
set -euo pipefail

SRV_NS=srv_ns
CLI_NS=cli_ns
SRV_VETH=veth_srv
CLI_VETH=veth_cli
SRV_IP=10.0.0.1/24
CLI_IP=10.0.0.2/24

ns_exists() {
    ip netns list | awk '{print $1}' | grep -qx "$1"
}

dev_exists() {
    ip netns exec "$1" ip link show "$2" >/dev/null 2>&1
}

for ns in "$SRV_NS" "$CLI_NS"; do
    ns_exists "$ns" || ip netns add "$ns"
done

# Interrupted runs can leave server/client processes inside the namespaces.
# Kill them so stale sockets (for example UDP 4433) are released before starting.
for ns in "$SRV_NS" "$CLI_NS"; do
    stale_pids=$(ip netns pids "$ns" 2>/dev/null || true)
    if [ -n "$stale_pids" ]; then
        echo "Killing stale processes in $ns: $stale_pids"
        kill -9 $stale_pids 2>/dev/null || true
    fi
done
sleep 0.5

# Recreate the veth pair only if one of its ends is missing.
if ! dev_exists "$SRV_NS" "$SRV_VETH" || ! dev_exists "$CLI_NS" "$CLI_VETH"; then
    dev_exists "$SRV_NS" "$SRV_VETH" && ip netns exec "$SRV_NS" ip link del "$SRV_VETH"
    dev_exists "$CLI_NS" "$CLI_VETH" && ip netns exec "$CLI_NS" ip link del "$CLI_VETH"
    ip link add "$SRV_VETH" type veth peer name "$CLI_VETH"
    ip link set "$SRV_VETH" netns "$SRV_NS"
    ip link set "$CLI_VETH" netns "$CLI_NS"
fi

ip netns exec "$SRV_NS" ip addr replace "$SRV_IP" dev "$SRV_VETH"
ip netns exec "$CLI_NS" ip addr replace "$CLI_IP" dev "$CLI_VETH"

ip netns exec "$SRV_NS" ip link set "$SRV_VETH" up
ip netns exec "$CLI_NS" ip link set "$CLI_VETH" up
ip netns exec "$SRV_NS" ip link set lo up
ip netns exec "$CLI_NS" ip link set lo up

echo "network namespaces ready: $SRV_NS ($SRV_IP), $CLI_NS ($CLI_IP)"
