#!/bin/bash
# Runs as root via a narrowly-scoped sudoers NOPASSWD rule (see setup.sh) so the
# unprivileged central-office service account can restart its own systemd unit -- the one
# thing an in-place update needs root for -- without running the whole app as root. Takes
# a structured subcommand rather than a raw systemctl argument so the sudoers grant only
# ever has to trust this one fixed, reviewable script (mirrors the appliance's own
# provisioning/system-helper.sh, trimmed to just what the hub needs).
set -euo pipefail

case "${1:-}" in
  service-restart)
    # Takes no arguments -- the app can only ever restart itself, never target an
    # arbitrary unit.
    exec systemctl restart central-office.service
    ;;
  *)
    echo "Unknown subcommand: ${1:-<none>}" >&2
    exit 1
    ;;
esac
