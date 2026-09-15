#!/bin/bash
# One-time setup for the HA agent on this node. Run manually AFTER the main app is
# already provisioned via provisioning/setup.sh -- HA is opt-in, not part of the default
# install, and this script assumes the central-office user/service already exist.
#
# This does NOT set up the cross-VM SSH trust replication needs, and does NOT edit
# ha-agent/config.json for you beyond copying the example -- both are manual, per-node
# steps documented in the README's "High Availability" section. Run this same script on
# both nodes.
set -euo pipefail

APP_DIR=/opt/central-office
HA_DIR="$APP_DIR/ha-agent"

if ! id -u central-office >/dev/null 2>&1; then
  echo "FATAL: the main central-office service account doesn't exist yet -- run provisioning/setup.sh first." >&2
  exit 1
fi

if ! id -u central-office-ha >/dev/null 2>&1; then
  useradd --system --home-dir "$HA_DIR" --shell /usr/sbin/nologin central-office-ha
fi

mkdir -p "$HA_DIR"
chown central-office-ha:central-office-ha "$HA_DIR"
chmod 700 "$HA_DIR"

if [ ! -f "$HA_DIR/config.json" ]; then
  cp "$APP_DIR/ha-agent-config.example.json" "$HA_DIR/config.json"
  chown central-office-ha:central-office-ha "$HA_DIR/config.json"
  chmod 600 "$HA_DIR/config.json"
  echo "Wrote a starter config to $HA_DIR/config.json -- fill it in for THIS node (role, peerHost, vip/dns settings) via the admin UI's Account tab > High Availability panel (preferred, validates input) before starting the service, or hand-edit the file directly."
else
  echo "$HA_DIR/config.json already exists -- leaving it alone."
fi

echo "Granting central-office-ha permission to start/stop the main service..."
chmod +x "$APP_DIR/provisioning/ha-service-helper.sh"
SUDOERS_FILE=/etc/sudoers.d/central-office-ha
SUDOERS_TMP=$(mktemp)
echo "central-office-ha ALL=(root) NOPASSWD: $APP_DIR/provisioning/ha-service-helper.sh" > "$SUDOERS_TMP"
# Validate before installing -- sudo reads the *whole* sudoers config atomically, so a
# malformed drop-in here can silently break sudo for the entire system, not just this
# rule. Never place an unvalidated file into /etc/sudoers.d/.
if visudo -c -f "$SUDOERS_TMP" >/dev/null 2>&1; then
  install -m 440 "$SUDOERS_TMP" "$SUDOERS_FILE"
else
  echo "WARNING: generated sudoers rule failed validation -- the agent won't be able to start/stop the main service" >&2
fi
rm -f "$SUDOERS_TMP"

chmod +x "$APP_DIR/provisioning/ha-vip-up.sh" "$APP_DIR/provisioning/ha-vip-down.sh"

echo "Making the main app's data directory group-accessible to central-office-ha (for the replication pull)..."
chmod 770 "$APP_DIR/data"

install -m 644 "$APP_DIR/provisioning/ha-agent.service" /etc/systemd/system/ha-agent.service
systemctl daemon-reload

# The main app's own service normally auto-starts on boot (systemctl enable, done by
# setup.sh). Under HA, whether it's actually running is the *agent's* call, not boot's --
# a standby node must come up with the main service stopped, not auto-started underneath
# the agent's back. Disabling (not stopping -- setup.sh may have started it before HA was
# configured) means only ha-agent decides when it runs from now on.
systemctl disable central-office.service 2>/dev/null || true

cat <<'EOF'

HA agent installed but not started. Next steps (see README, per node):
  1. Fill in config.json for this node (role, peerHost, listenPort/peerPort, vip or
     dns settings) via the admin UI's Account tab > High Availability panel, or by
     hand-editing /opt/central-office/ha-agent/config.json directly.
  2. Set up cross-VM SSH trust for replication: generate a keypair, place the private
     half at the sshKeyPath your config points to, and add the public half to the
     PEER's central-office account ~/.ssh/authorized_keys, restricted to rsync only,
     e.g.:
       command="rsync --server --sender -logDtprze.iLsfxCIvu . /opt/central-office/data",restrict ssh-ed25519 AAAA...
  3. systemctl enable --now ha-agent.service
EOF
