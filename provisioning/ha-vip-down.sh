#!/bin/bash
# Releases the HA virtual IP on this node -- the mirror of ha-vip-up.sh. Fails quietly
# if the address is already gone (e.g. a repeated demote call, or demoting a node that
# never actually held it) rather than erroring: the goal state ("we don't have the VIP")
# is already true either way.
set -euo pipefail

CIDR="${1:?usage: ha-vip-down.sh <address/prefix> <interface>}"
IFACE="${2:?usage: ha-vip-down.sh <address/prefix> <interface>}"

ip addr del "$CIDR" dev "$IFACE" 2>/dev/null || true
