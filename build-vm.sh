#!/bin/bash
# Builds a bootable VM appliance (qcow2) for the Central Office hub: a Debian 12
# (bookworm) "genericcloud" image with the hub app pre-installed, its systemd service
# enabled, and cloud-init left in place for whoever deploys it to configure (SSH keys,
# hostname, network) at their own boot time -- the app starts regardless of that config.
#
# Runs the actual QEMU boot (needed to let cloud-init provision the disk image) inside a
# throwaway Debian container, since this host doesn't have a working QEMU toolchain of its
# own (Homebrew's qemu has no prebuilt bottle for this macOS version and wants to compile
# from source; UTM's bundled QEMU isn't a directly-executable CLI binary). Docker Desktop
# already provides the Linux environment QEMU + its usual packaging want.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
REPO="TerryHenry/central-office-hub"
DEBIAN_IMG_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2"
OUTPUT_QCOW2="$BUILD_DIR/central-office-hub.qcow2"
DISK_SIZE="4G"

mkdir -p "$BUILD_DIR"

echo "==> Resolving latest release of $REPO..."
RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/releases/latest")
TARBALL_URL=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name']=='central-office-app.tar.gz'))")
CHECKSUM_URL=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name']=='central-office-app.tar.gz.sha256'))")
RELEASE_TAG=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
echo "    $RELEASE_TAG -- $TARBALL_URL"

echo "==> Downloading base image (Debian 12 genericcloud, arm64)..."
BASE_IMG="$BUILD_DIR/debian-12-genericcloud-arm64.qcow2"
if [ ! -f "$BASE_IMG" ]; then
  curl -fL --progress-bar -o "$BASE_IMG" "$DEBIAN_IMG_URL"
else
  echo "    Using existing $BASE_IMG"
fi

echo "==> Preparing working copy and cloud-init seed..."
WORK_IMG="$BUILD_DIR/work.qcow2"
rm -f "$WORK_IMG"
cp "$BASE_IMG" "$WORK_IMG"

SEED_DIR="$BUILD_DIR/seed"
rm -rf "$SEED_DIR"
mkdir -p "$SEED_DIR"

cat > "$SEED_DIR/meta-data" <<EOF
instance-id: central-office-build
local-hostname: central-office
EOF

# A plain "#!" user-data is executed directly by cloud-init's scripts-user module as
# root, once, on first boot -- simplest way to drive a fully unattended install without
# writing YAML for something this procedural.
cat > "$SEED_DIR/user-data" <<USERDATA
#!/bin/bash
set -uo pipefail
exec > /var/log/central-office-build.log 2>&1
echo "=== Central Office VM build provisioning starting: \$(date -u) ==="

retry() {
  local attempts=8 delay=10 n=1
  until "\$@"; do
    if [ "\$n" -ge "\$attempts" ]; then echo "Command failed after \$n attempts: \$*"; return 1; fi
    echo "Command failed (attempt \$n/\$attempts), retrying in \${delay}s: \$*"
    n=\$((n + 1)); sleep "\$delay"
  done
}

export DEBIAN_FRONTEND=noninteractive
mkdir -p /opt/central-office
cd /opt/central-office

echo "==> Downloading $RELEASE_TAG app tarball..."
retry curl -fL -o /tmp/app.tar.gz "$TARBALL_URL"
retry curl -fL -o /tmp/app.tar.gz.sha256 "$CHECKSUM_URL"
EXPECTED_SHA=\$(cat /tmp/app.tar.gz.sha256 | awk '{print \$1}')
ACTUAL_SHA=\$(sha256sum /tmp/app.tar.gz | awk '{print \$1}')
if [ "\$EXPECTED_SHA" != "\$ACTUAL_SHA" ]; then
  echo "FATAL: checksum mismatch for downloaded app tarball" >&2
  echo "BUILD_FAILED" > /dev/console
  poweroff
  exit 1
fi
tar -xzf /tmp/app.tar.gz -C /opt/central-office
rm -f /tmp/app.tar.gz /tmp/app.tar.gz.sha256

chmod +x /opt/central-office/provisioning/*.sh
bash /opt/central-office/provisioning/setup.sh
SETUP_STATUS=\$?

sleep 3
if [ "\$SETUP_STATUS" -eq 0 ] && systemctl is-active --quiet central-office.service; then
  echo "=== Provisioning succeeded: \$(date -u) ==="
  echo "BUILD_OK" > /dev/console
else
  echo "=== Provisioning FAILED (setup exit \$SETUP_STATUS, service active: \$(systemctl is-active central-office.service || true)) ===" >&2
  echo "BUILD_FAILED" > /dev/console
fi
sync
poweroff
USERDATA

echo "==> Building qcow2 image inside a throwaway Debian container (installs QEMU there -- this host has none)..."
docker run --rm \
  -v "$BUILD_DIR:/build" \
  debian:bookworm \
  bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends qemu-system-arm qemu-utils qemu-efi-aarch64 cloud-image-utils genisoimage >/dev/null

    qemu-img resize /build/work.qcow2 '"$DISK_SIZE"'

    cloud-localds /build/seed.iso /build/seed/user-data /build/seed/meta-data

    # -M virt requires both pflash slots to be exactly 64MiB; Debian bookworm ships a
    # smaller QEMU_EFI.fd, so pad a working copy of it out to that size rather than use
    # the (read-only, system-owned) package file directly.
    FW_SRC=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd
    FW=/build/efi-code.fd
    cp "$FW_SRC" "$FW"
    truncate -s 64M "$FW"
    FW_VARS=/build/efi-vars.fd
    truncate -s 64M "$FW_VARS"

    echo "==> Booting VM to run provisioning (this can take several minutes)..."
    timeout 1800 qemu-system-aarch64 \
      -M virt -cpu max -accel tcg -smp 2 -m 2048 \
      -drive if=pflash,format=raw,readonly=on,file="$FW" \
      -drive if=pflash,format=raw,file="$FW_VARS" \
      -drive file=/build/work.qcow2,if=virtio,format=qcow2 \
      -drive file=/build/seed.iso,if=virtio,format=raw,media=cdrom \
      -netdev user,id=net0 -device virtio-net-pci,netdev=net0,romfile= \
      -nographic -serial file:/build/serial.log \
      || { echo "QEMU exited non-zero or timed out"; }

    echo "==> Provisioning boot finished; checking result..."
    tail -c 2000 /build/serial.log || true
  '

if ! grep -q "BUILD_OK" "$BUILD_DIR/serial.log"; then
  echo "FATAL: provisioning did not report success -- see $BUILD_DIR/serial.log" >&2
  exit 1
fi

echo "==> Compressing final image..."
docker run --rm -v "$BUILD_DIR:/build" debian:bookworm bash -c '
  apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-utils >/dev/null
  qemu-img convert -O qcow2 -c /build/work.qcow2 /build/central-office-hub.qcow2
'

rm -rf "$SEED_DIR" "$BUILD_DIR/seed.iso" "$BUILD_DIR/work.qcow2" "$BUILD_DIR/efi-vars.fd"

echo
echo "Done. VM appliance image:"
echo "  $OUTPUT_QCOW2"
echo
echo "Boot it with UTM, Proxmox, or plain QEMU (arm64 host). It ships with no OS-level"
echo "login configured -- attach your own cloud-init seed (SSH key, password, hostname)"
echo "at deploy time, the same way any cloud image is normally customized. The Central"
echo "Office admin UI comes up on its own regardless, at https://<vm-ip>:8443."
