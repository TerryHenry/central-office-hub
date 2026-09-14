#!/bin/bash
# Manual recovery: restores the most recent pre-update backup and restarts the service.
# Meant to be run directly over SSH (port 22, the host's own OS SSH, not the tunnel/SSH
# listener the app itself runs on) as root -- NOT reachable through the app itself, since
# the whole point is to still work if a bad update left the app unable to serve requests
# at all.
#
#   sudo bash /opt/central-office/provisioning/rollback-update.sh
#
set -euo pipefail

APP_DIR=/opt/central-office
BACKUP_ROOT="$APP_DIR/data/backups"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root, e.g.: sudo bash $0" >&2
  exit 1
fi

LATEST=$(ls -1dt "$BACKUP_ROOT"/pre-update-* 2>/dev/null | head -n1 || true)
if [ -z "$LATEST" ]; then
  echo "No pre-update backup found under $BACKUP_ROOT -- nothing to roll back to." >&2
  exit 1
fi

echo "Rolling back to backup: $LATEST"
echo "Stopping central-office.service..."
systemctl stop central-office.service

for item in server.js package.json package-lock.json lib webui provisioning node_modules; do
  if [ -e "$LATEST/$item" ]; then
    rm -rf "${APP_DIR:?}/$item"
    cp -a "$LATEST/$item" "$APP_DIR/$item"
  fi
done
chown -R central-office:central-office "$APP_DIR"

echo "Starting central-office.service..."
systemctl start central-office.service
sleep 2
systemctl --no-pager status central-office.service || true

echo
echo "Rollback complete. If the service is active above, you're back on the previous version."
