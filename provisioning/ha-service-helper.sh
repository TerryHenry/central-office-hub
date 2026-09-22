#!/bin/bash
# Runs as root via a narrowly-scoped sudoers NOPASSWD rule (see ha-setup.sh) so the
# unprivileged central-office-ha account can start/stop the *main app's* service --
# exactly the two actions promotion/demotion need -- without being root itself and
# without widening the main app's own service account's privileges. Mirrors the main
# app's own provisioning/system-helper.sh pattern: one fixed, reviewable script the
# sudoers grant has to trust, never a raw systemctl argument from the caller.
set -euo pipefail

case "${1:-}" in
  start)
    exec systemctl start central-office.service
    ;;
  stop)
    exec systemctl stop central-office.service
    ;;
  *)
    echo "usage: ha-service-helper.sh {start|stop}" >&2
    exit 1
    ;;
esac
