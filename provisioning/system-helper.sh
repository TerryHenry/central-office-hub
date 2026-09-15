#!/bin/bash
# Runs as root via a narrowly-scoped sudoers NOPASSWD rule (see setup.sh) so the
# unprivileged central-office service account can restart its own systemd unit and manage
# hostname/timezone/NTP/DNS/static-IP -- all without running the whole app as root. Takes
# structured subcommands rather than raw systemctl/nmcli/timedatectl arguments so the
# sudoers grant only ever has to trust this one fixed, reviewable script (mirrors the
# appliance's own provisioning/system-helper.sh; Wi-Fi subcommands are omitted since a
# fleet hub runs on a server/VM with no Wi-Fi hardware).
set -euo pipefail

NTP_DROPIN_DIR=/etc/systemd/timesyncd.conf.d
NTP_DROPIN_FILE="$NTP_DROPIN_DIR/50-central-office.conf"

case "${1:-}" in
  service-restart)
    # Takes no arguments -- the app can only ever restart itself, never target an
    # arbitrary unit.
    exec systemctl restart central-office.service
    ;;
  ntp-set)
    server="${2:?ntp server required}"
    mkdir -p "$NTP_DROPIN_DIR"
    printf '[Time]\nNTP=%s\n' "$server" > "$NTP_DROPIN_FILE"
    systemctl restart systemd-timesyncd
    ;;
  timezone-set)
    tz="${2:?timezone required}"
    exec timedatectl set-timezone "$tz"
    ;;
  dns-set)
    shift
    servers="$*"
    [ -n "$servers" ] || { echo "at least one DNS server required" >&2; exit 1; }
    # IPv4 only -- the app validates this before ever calling here, but re-checked since
    # this script is the actual privilege boundary. IPv6 DNS is left alone either way.
    for s in $servers; do
      case "$s" in
        *[!0-9.]*|'') echo "not an IPv4 address: $s" >&2; exit 1 ;;
      esac
    done
    # Applied to every currently-active connection (not just one) so the override holds
    # regardless of which interface ends up carrying traffic.
    nmcli -t -f NAME connection show --active | while IFS= read -r conn; do
      [ -n "$conn" ] || continue
      nmcli connection modify "$conn" ipv4.ignore-auto-dns yes ipv4.dns "$servers"
      nmcli connection up "$conn" >/dev/null
    done
    ;;
  dns-clear)
    nmcli -t -f NAME connection show --active | while IFS= read -r conn; do
      [ -n "$conn" ] || continue
      nmcli connection modify "$conn" ipv4.ignore-auto-dns no ipv4.dns ""
      nmcli connection up "$conn" >/dev/null
    done
    ;;
  ip-set)
    # The connection name (not the device name) is passed in, already resolved
    # device->connection on the Node side via the same colon-escaping-aware nmcli
    # parsing getInterfaces() already does -- this script just trusts that resolution
    # and re-validates the IP-shaped values, since it's the actual privilege boundary.
    conn="${2:?connection name required}"
    address="${3:?ip address required}"
    prefix="${4:?prefix required}"
    gateway="${5:?gateway required}"
    for v in "$address" "$gateway"; do
      case "$v" in
        *[!0-9.]*|'') echo "not an IPv4 address: $v" >&2; exit 1 ;;
      esac
    done
    case "$prefix" in
      ''|*[!0-9]*) echo "invalid prefix length: $prefix" >&2; exit 1 ;;
    esac
    nmcli connection modify "$conn" ipv4.method manual ipv4.addresses "$address/$prefix" ipv4.gateway "$gateway"
    exec nmcli connection up "$conn"
    ;;
  ip-clear)
    conn="${2:?connection name required}"
    nmcli connection modify "$conn" ipv4.method auto ipv4.addresses "" ipv4.gateway ""
    exec nmcli connection up "$conn"
    ;;
  hostname-set)
    hostname="${2:?hostname required}"
    case "$hostname" in
      ''|*[!a-zA-Z0-9-]*|-*|*-) echo "invalid hostname: $hostname" >&2; exit 1 ;;
    esac
    if [ "${#hostname}" -gt 63 ]; then
      echo "hostname too long: $hostname" >&2
      exit 1
    fi
    # No mDNS (.local) handling here -- unlike the appliance, the hub doesn't advertise
    # one, so there's nothing to keep in sync with the hostname change.
    exec hostnamectl set-hostname "$hostname"
    ;;
  *)
    echo "usage: system-helper.sh {service-restart|ntp-set <server>|timezone-set <tz>|dns-set <servers...>|dns-clear|ip-set <conn> <addr> <prefix> <gw>|ip-clear <conn>|hostname-set <name>}" >&2
    exit 1
    ;;
esac
