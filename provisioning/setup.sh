#!/bin/bash
# One-time setup, run by central-office-setup.service after first boot has real network
# connectivity. Installs Node.js, installs app dependencies, and hands off to the
# always-on central-office.service. Mirrors the appliance's own provisioning/setup.sh,
# trimmed of everything specific to serial ports / Wi-Fi / Raspberry Pi hardware.
set -uo pipefail

APP_DIR=/opt/central-office
DATA_DIR="$APP_DIR/data"
LOG="$DATA_DIR/setup.log"
mkdir -p "$DATA_DIR"
exec > >(tee -a "$LOG") 2>&1

echo "=== Central Office first-boot setup starting: $(date -u) ==="

retry() {
  local attempts=5
  local delay=10
  local n=1
  until "$@"; do
    if [ "$n" -ge "$attempts" ]; then
      echo "Command failed after $n attempts: $*"
      return 1
    fi
    echo "Command failed (attempt $n/$attempts), retrying in ${delay}s: $*"
    n=$((n + 1))
    sleep "$delay"
  done
}

export DEBIAN_FRONTEND=noninteractive

# This service re-runs on every boot until it succeeds (see
# central-office-setup.service's ConditionPathExists), so if a previous attempt was cut
# off mid-install by a reboot or power loss, dpkg can be left in an interrupted state,
# which blocks all further apt-get calls. Repair that unconditionally before touching apt.
echo "Repairing any interrupted dpkg state..."
dpkg --configure -a || true
apt-get install -y -f --no-install-recommends || true

retry apt-get update
if [ $? -ne 0 ]; then
  echo "FATAL: apt-get update failed" >&2
  exit 1
fi

retry apt-get install -y --no-install-recommends ca-certificates curl gnupg openssl
if [ $? -ne 0 ]; then
  echo "FATAL: failed to install base packages" >&2
  exit 1
fi

# NetworkManager (nmcli) isn't part of a minimal Debian genericcloud image, but the
# Network tab's DNS/static-IP settings depend on it -- install it and hand this box's
# interface(s) over to it now, rather than leaving that as a manual step an admin has to
# rediscover. Found the hard way: a fresh VM's interface comes up "unmanaged" by
# NetworkManager because cloud-init's own generated netplan config defaults to the
# networkd renderer, and cloud-init regenerates that file on every boot, so a one-off
# manual fix reverts on the next reboot unless cloud-init's own network management is
# also turned off.
echo "==> Installing NetworkManager for Network tab DNS/static-IP support..."
retry apt-get install -y --no-install-recommends network-manager
if [ $? -ne 0 ]; then
  echo "WARNING: failed to install network-manager -- Network tab DNS/static-IP settings won't work" >&2
else
  mkdir -p /etc/cloud/cloud.cfg.d
  cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<'EOF'
network: {config: disabled}
EOF

  # Idempotent: skip any netplan file that already specifies a renderer, so re-running
  # this script (or running it against an already-fixed VM) is harmless.
  for f in /etc/netplan/*.yaml; do
    [ -f "$f" ] || continue
    if ! grep -q '^[[:space:]]*renderer:' "$f"; then
      sed -i '/^network:/a\  renderer: NetworkManager' "$f"
    fi
  done
  chmod 600 /etc/netplan/*.yaml 2>/dev/null || true
  netplan apply || echo "WARNING: netplan apply failed -- interface may still show as unmanaged in nmcli" >&2
fi

# Debian's own "npm" package drags in a large tree of separately-packaged "node-*"
# modules whose versions frequently don't resolve against each other. NodeSource's own
# repo ships a self-contained Node.js + npm build instead.
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Installing Node.js from NodeSource..."
  NODE_MAJOR=22
  mkdir -p /etc/apt/keyrings
  retry curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /etc/apt/keyrings/nodesource.asc
  if [ $? -ne 0 ]; then
    echo "FATAL: failed to fetch NodeSource signing key" >&2
    exit 1
  fi
  chmod a+r /etc/apt/keyrings/nodesource.asc
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list

  retry apt-get update
  if [ $? -ne 0 ]; then
    echo "FATAL: apt-get update (NodeSource) failed" >&2
    exit 1
  fi

  retry apt-get install -y --no-install-recommends nodejs
  if [ $? -ne 0 ]; then
    echo "FATAL: failed to install Node.js" >&2
    exit 1
  fi
fi

if ! id -u central-office >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin central-office
fi

echo "Granting the service account scoped permission to restart its own service..."
chmod +x "$APP_DIR/provisioning/system-helper.sh"
SUDOERS_FILE=/etc/sudoers.d/central-office-system
SUDOERS_TMP=$(mktemp)
echo "central-office ALL=(root) NOPASSWD: $APP_DIR/provisioning/system-helper.sh" > "$SUDOERS_TMP"
# Validate before installing -- sudo reads the *whole* sudoers config atomically, so a
# malformed drop-in here can silently break sudo for the entire system, not just this
# rule. Never place an unvalidated file into /etc/sudoers.d/.
if visudo -c -f "$SUDOERS_TMP" >/dev/null 2>&1; then
  install -m 440 "$SUDOERS_TMP" "$SUDOERS_FILE"
else
  echo "WARNING: generated sudoers rule failed validation -- in-place updates won't be able to restart the service" >&2
fi
rm -f "$SUDOERS_TMP"

cd "$APP_DIR" || exit 1
retry npm install --omit=dev --no-audit --no-fund
if [ $? -ne 0 ]; then
  echo "FATAL: npm install failed" >&2
  exit 1
fi

chown -R central-office:central-office "$APP_DIR"

# No separate first-stage script installs these here (unlike the appliance's RPi-specific
# firstrun.sh) -- this one script does the whole job, since a generic Debian
# host/VM needs no OS-image-specific boot injection.
install -m 644 "$APP_DIR/provisioning/central-office.service" /etc/systemd/system/central-office.service
install -m 644 "$APP_DIR/provisioning/central-office-setup.service" /etc/systemd/system/central-office-setup.service
systemctl daemon-reload
systemctl enable central-office.service
systemctl start central-office.service

touch "$DATA_DIR/.setup-complete"
systemctl disable central-office-setup.service

echo "=== Central Office first-boot setup complete: $(date -u) ==="
echo "Admin UI: https://<this-host>:8443  (default admin / letmein0! -- change it on first login)"
