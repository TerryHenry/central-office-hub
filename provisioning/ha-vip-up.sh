#!/bin/bash
# Claims the HA virtual IP on this node: adds the address to the given interface and
# announces it via gratuitous ARP so peers on the LAN update their ARP caches
# immediately instead of waiting for a stale entry to time out. Run directly by
# ha-agent.js (no sudo) -- that process already holds CAP_NET_ADMIN/CAP_NET_RAW via its
# own systemd unit's AmbientCapabilities, unlike the main app's account, which crosses
# into root through a narrow sudoers-gated helper script for its own privileged actions.
#
# Idempotent: succeeds quietly if the address is already assigned (startup
# reconciliation calls this unconditionally when the agent believes it should be
# active, whether or not that's actually already true).
set -euo pipefail

CIDR="${1:?usage: ha-vip-up.sh <address/prefix> <interface>}"
IFACE="${2:?usage: ha-vip-up.sh <address/prefix> <interface>}"

ip addr add "$CIDR" dev "$IFACE" 2>/dev/null || true
ADDRESS="${CIDR%%/*}"
arping -U -c 3 -I "$IFACE" "$ADDRESS" || true
