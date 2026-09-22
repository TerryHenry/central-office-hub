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
APP_DIR=/opt/central-office
HA_DIR="$APP_DIR/ha-agent"

case "${1:-}" in
  lldp-install)
    # Fixed package name only. Idempotent: does nothing if lldpd is already present.
    if command -v lldpd >/dev/null 2>&1; then echo "already installed"; exit 0; fi
    export DEBIAN_FRONTEND=noninteractive
    nice -n 19 apt-get update -qq
    nice -n 19 apt-get install -y --no-install-recommends lldpd
    # LLDP on by default (start now and at boot). CDP/FDP stay off -- opt-in via lldp-set.
    systemctl enable --now lldpd >/dev/null 2>&1 || true
    ;;  lldp-status)
    # Read-only: reports whether lldpd is installed/running and which discovery protocols
    # it is configured to speak, as key=value lines the app parses.
    installed=0; command -v lldpd >/dev/null 2>&1 && installed=1
    active=0; systemctl is-active --quiet lldpd 2>/dev/null && active=1
    args=""
    if [ -f /etc/default/lldpd ]; then
      args="$(sed -n 's/^DAEMON_ARGS="\(.*\)"$/\1/p' /etc/default/lldpd | head -1)"
    fi
    cdp=0; fdp=0
    case " $args " in *" -c "*) cdp=1 ;; esac
    case " $args " in *" -f "*) fdp=1 ;; esac
    showall=0
    case " $args " in *" -H 0 "*) showall=1 ;; esac
    echo "installed=$installed"
    echo "active=$active"
    echo "cdp=$cdp"
    echo "fdp=$fdp"
    echo "showall=$showall"
    ;;
  lldp-set)
    # lldp-set <enabled 0|1> <cdp 0|1> <fdp 0|1>. Fixed flags only -- nothing the caller
    # supplies is ever written into the daemon's argument line except these validated
    # switches, since this script is the actual privilege boundary.
    enabled="${2:?enabled flag required}"
    cdp="${3:?cdp flag required}"
    fdp="${4:?fdp flag required}"
    for v in "$enabled" "$cdp" "$fdp"; do
      case "$v" in 0|1) ;; *) echo "flags must be 0 or 1" >&2; exit 1 ;; esac
    done
    command -v lldpd >/dev/null 2>&1 || { echo "lldpd is not installed -- install it with: sudo apt-get install lldpd" >&2; exit 1; }
    daemon_args=""
    [ "$cdp" = "1" ] && daemon_args="$daemon_args -c"
    [ "$fdp" = "1" ] && daemon_args="$daemon_args -f"
    # lldpd hides a neighbor heard over several protocols and shows only the "best" one by
    # default (-H 15), so a switch seen over both LLDP and CDP would appear as LLDP only.
    # -H 0 turns that filtering off so every protocol heard is listed.
    if [ "$cdp" = "1" ] || [ "$fdp" = "1" ]; then daemon_args="$daemon_args -H 0"; fi
    daemon_args="${daemon_args# }"
    printf '# Managed by the terminal server admin UI.\nDAEMON_ARGS="%s"\n' "$daemon_args" > /etc/default/lldpd
    if [ "$enabled" = "1" ]; then
      systemctl enable lldpd >/dev/null 2>&1 || true
      systemctl restart lldpd
    else
      systemctl disable --now lldpd >/dev/null 2>&1 || true
    fi
    ;;
  lldp-neighbors)
    exec lldpcli -f json0 show neighbors details
    ;;
  service-restart)
    # Takes no arguments -- the app can only ever restart itself, never target an
    # arbitrary unit.
    exec systemctl restart central-office.service
    ;;
  ha-setup)
    # One-time, idempotent setup for the HA agent on this node -- everything
    # provisioning/ha-setup.sh used to require an interactive shell for, now reachable
    # from the admin UI's High Availability panel (Node Setup) since a from-scratch
    # deploy of this appliance has no OS-level login baked in. Safe to re-run: every
    # step below either checks first or overwrites idempotently.
    if ! id -u central-office-ha >/dev/null 2>&1; then
      useradd --system --home-dir "$HA_DIR" --shell /usr/sbin/nologin central-office-ha
    fi

    mkdir -p "$HA_DIR"
    chown central-office-ha:central-office-ha "$HA_DIR"
    chmod 700 "$HA_DIR"

    if [ ! -f "$HA_DIR/config.json" ]; then
      cp "$APP_DIR/ha-agent-config.example.json" "$HA_DIR/config.json"
    fi
    # Re-applied every run (not just on first creation) -- the main app's own
    # /api/ha/config handler may have already written this file as the central-office
    # user before ha-setup ever ran, which would leave it owned wrong for the agent
    # (which runs as central-office-ha) to read.
    chown central-office-ha:central-office-ha "$HA_DIR/config.json"
    chmod 600 "$HA_DIR/config.json"

    if [ ! -f "$HA_DIR/replication-key" ]; then
      sudo -u central-office-ha ssh-keygen -t ed25519 -f "$HA_DIR/replication-key" -N "" -C "central-office-ha-replication" >/dev/null
    fi
    chown central-office-ha:central-office-ha "$HA_DIR/replication-key" "$HA_DIR/replication-key.pub"
    chmod 600 "$HA_DIR/replication-key"
    chmod 644 "$HA_DIR/replication-key.pub"

    chmod +x "$APP_DIR/provisioning/ha-service-helper.sh" "$APP_DIR/provisioning/ha-vip-up.sh" "$APP_DIR/provisioning/ha-vip-down.sh"

    SUDOERS_FILE=/etc/sudoers.d/central-office-ha
    SUDOERS_TMP=$(mktemp)
    echo "central-office-ha ALL=(root) NOPASSWD: $APP_DIR/provisioning/ha-service-helper.sh" > "$SUDOERS_TMP"
    # Same atomic-validate-before-install reasoning as the sudoers drop-in below.
    if visudo -c -f "$SUDOERS_TMP" >/dev/null 2>&1; then
      install -m 440 "$SUDOERS_TMP" "$SUDOERS_FILE"
    else
      echo "WARNING: generated sudoers rule failed validation -- the agent won't be able to start/stop the main service" >&2
    fi
    rm -f "$SUDOERS_TMP"

    echo "Making the main app's data directory group-accessible to central-office-ha (for the replication pull)..."
    chmod 770 "$APP_DIR/data"

    install -m 644 "$APP_DIR/provisioning/ha-agent.service" /etc/systemd/system/ha-agent.service
    systemctl daemon-reload
    # See ha-agent.service's own comment: under HA, whether the main service actually
    # runs is the agent's call, not boot's. Disable (not stop) -- setup.sh may already
    # have started it before HA was configured here.
    systemctl disable central-office.service 2>/dev/null || true

    echo "PUBKEY:$(cat "$HA_DIR/replication-key.pub")"
    ;;
  ha-start)
    # Takes no arguments -- always this one fixed unit, mirrors service-restart above.
    exec systemctl enable --now ha-agent.service
    ;;
  ha-service-status)
    # Read-only: reports whether the ha-agent systemd unit is installed/enabled/active,
    # as key=value lines the app parses -- mirrors lldp-status.
    installed=0; [ -f /etc/systemd/system/ha-agent.service ] && installed=1
    enabled=0; systemctl is-enabled --quiet ha-agent.service 2>/dev/null && enabled=1
    active=0; systemctl is-active --quiet ha-agent.service 2>/dev/null && active=1
    echo "installed=$installed"
    echo "enabled=$enabled"
    echo "active=$active"
    ;;
  ha-trust-peer)
    # ha-trust-peer <known_hosts-formatted key line>. Writes into central-office-ha's
    # OWN known_hosts (its home dir is $HA_DIR), since that's the identity the agent's
    # StrictHostKeyChecking=yes replication pull actually authenticates as. The caller
    # (Node side) is responsible for having already shown the fingerprint to an admin
    # for out-of-band confirmation -- this script just persists whatever line it's
    # handed, the same as an admin manually approving ssh's own "are you sure" prompt.
    keyline="${2:?host key line required}"
    mkdir -p "$HA_DIR/.ssh"
    chown central-office-ha:central-office-ha "$HA_DIR" "$HA_DIR/.ssh"
    chmod 700 "$HA_DIR/.ssh"
    touch "$HA_DIR/.ssh/known_hosts"
    host_field=$(echo "$keyline" | awk '{print $1}')
    [ -n "$host_field" ] || { echo "malformed host key line" >&2; exit 1; }
    grep -v "^${host_field} " "$HA_DIR/.ssh/known_hosts" > "$HA_DIR/.ssh/known_hosts.tmp" 2>/dev/null || true
    mv "$HA_DIR/.ssh/known_hosts.tmp" "$HA_DIR/.ssh/known_hosts"
    echo "$keyline" >> "$HA_DIR/.ssh/known_hosts"
    chown central-office-ha:central-office-ha "$HA_DIR/.ssh/known_hosts"
    chmod 600 "$HA_DIR/.ssh/known_hosts"
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
    hostnamectl set-hostname "$hostname"
    # hostnamectl only changes the kernel/system hostname -- it never touches
    # /etc/hosts, so the conventional "127.0.1.1 <hostname>" line there silently keeps
    # naming the OLD hostname. The moment the two diverge, anything that resolves the
    # local hostname for itself (sudo included, for its own logging) starts failing
    # with "unable to resolve host <name>: Name or service not known" -- found live,
    # not by inspection, on a renamed box. Update that line to match, or add it fresh
    # if this image never had one.
    if grep -q '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
      sed -i "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$hostname/" /etc/hosts
    else
      printf '127.0.1.1\t%s\n' "$hostname" >> /etc/hosts
    fi
    # No mDNS (.local) handling here -- unlike the appliance, the hub doesn't advertise
    # one, so there's nothing to keep in sync with the hostname change.
    ;;
  *)
    echo "usage: system-helper.sh {lldp-install|lldp-status|lldp-set <en> <cdp> <fdp>|lldp-neighbors|service-restart|ha-setup|ha-start|ha-service-status|ha-trust-peer <keyline>|ntp-set <server>|timezone-set <tz>|dns-set <servers...>|dns-clear|ip-set <conn> <addr> <prefix> <gw>|ip-clear <conn>|hostname-set <name>}" >&2
    exit 1
    ;;
esac
