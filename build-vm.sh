#!/bin/bash
# Builds a bootable VM appliance (OVA) for the Central Office hub: a Debian 12
# (bookworm, amd64) "genericcloud" image with the hub app pre-installed, its systemd
# service enabled, and cloud-init left in place for whoever deploys it to configure
# (SSH keys, hostname, network) at their own boot time -- the app starts regardless of
# that config.
#
# amd64, not arm64: an OVA is meant to import into whatever hypervisor the operator
# already has (VMware Fusion/Workstation/ESXi, VirtualBox, Proxmox), and virtually all
# of those assume an x86_64 guest -- an arm64 image would only boot on hosts that
# themselves support ARM64 guests. The tradeoff is build speed: this host is Apple
# Silicon, so building an amd64 image means the whole boot is software-emulated with no
# hardware acceleration (same as the arm64-on-arm64 case, since Docker Desktop doesn't
# expose HVF/KVM to a nested container either) -- just translating a different
# instruction set on top, which is markedly slower.
#
# Two tools do the work, neither of which this host has natively:
#   - QEMU (to run the actual boot + cloud-init provisioning) inside a throwaway
#     Debian container, since Homebrew's qemu has no prebuilt bottle for this macOS
#     version and UTM's bundled QEMU isn't a directly-executable CLI binary.
#   - VBoxManage (VirtualBox's CLI, already installed on this Mac) to package the
#     provisioned disk into a real, spec-correct OVA -- it registers a throwaway VM
#     around the disk and exports it, rather than this script hand-writing OVF XML it
#     has no way to validate against an actual hypervisor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
REPO="TerryHenry/central-office-hub"
DEBIAN_IMG_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
OUTPUT_OVA="$BUILD_DIR/central-office-hub.ova"
DISK_SIZE="4G"
VM_NAME="central-office-hub-export-$$"

command -v VBoxManage >/dev/null 2>&1 || {
  echo "FATAL: VBoxManage not found -- install VirtualBox (used only to package the" >&2
  echo "already-built disk into a real OVA; the VM itself is never powered on)." >&2
  exit 1
}

cleanup() {
  VBoxManage unregistervm "$VM_NAME" --delete >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$BUILD_DIR"

echo "==> Resolving latest release of $REPO..."
RELEASE_JSON=$(curl -fsSL -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/releases/latest")
TARBALL_URL=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name']=='central-office-app.tar.gz'))")
CHECKSUM_URL=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(next(a['browser_download_url'] for a in d['assets'] if a['name']=='central-office-app.tar.gz.sha256'))")
RELEASE_TAG=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'])")
echo "    $RELEASE_TAG -- $TARBALL_URL"

echo "==> Downloading base image (Debian 12 genericcloud, amd64)..."
BASE_IMG="$BUILD_DIR/debian-12-genericcloud-amd64.qcow2"
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

  # This disk is about to be shipped as a reusable template, deployed to hypervisors
  # this build never saw. cloud-init keys its "have I already initialized this
  # instance" cache off instance-id, which is fixed (see meta-data above) -- left as
  # is, every VM cloned from this image would see that same cached state and skip
  # re-running network/SSH-host-key setup for its own actual NIC on first real boot,
  # since cloud-init believes it's already configured (that's what silently produced
  # a VM with no IP address after import elsewhere: it kept the build environment's
  # cached DHCP config for an interface that doesn't exist on the new hypervisor,
  # instead of detecting the real one). "cloud-init clean" drops that cache so the
  # next boot re-detects everything from scratch, and clearing machine-id avoids
  # every clone sharing one systemd/dbus identity.
  echo "==> Resetting cloud-init and machine identity for a clean first boot elsewhere..."
  cloud-init clean --logs --seed
  truncate -s 0 /etc/machine-id

  echo "BUILD_OK" > /dev/console
else
  echo "=== Provisioning FAILED (setup exit \$SETUP_STATUS, service active: \$(systemctl is-active central-office.service || true)) ===" >&2
  echo "BUILD_FAILED" > /dev/console
fi
sync
poweroff
USERDATA

echo "==> Booting VM to run provisioning (amd64 under full software emulation -- this can take a while)..."
docker run --rm \
  -v "$BUILD_DIR:/build" \
  debian:bookworm \
  bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils genisoimage >/dev/null

    qemu-img resize /build/work.qcow2 '"$DISK_SIZE"'

    cloud-localds /build/seed.iso /build/seed/user-data /build/seed/meta-data

    echo "==> Booting VM to run provisioning (this can take a long while under emulation)..."
    timeout 3600 qemu-system-x86_64 \
      -M pc -cpu max -accel tcg -smp 2 -m 2048 \
      -drive file=/build/work.qcow2,if=virtio,format=qcow2 \
      -drive file=/build/seed.iso,if=virtio,format=raw,media=cdrom \
      -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
      -nographic -serial file:/build/serial.log \
      || { echo "QEMU exited non-zero or timed out"; }

    echo "==> Provisioning boot finished; checking result..."
    tail -c 2000 /build/serial.log || true
  '

if ! grep -q "BUILD_OK" "$BUILD_DIR/serial.log"; then
  echo "FATAL: provisioning did not report success -- see $BUILD_DIR/serial.log" >&2
  exit 1
fi

echo "==> Converting provisioned disk to VDI (VirtualBox's native format)..."
docker run --rm -v "$BUILD_DIR:/build" debian:bookworm bash -c '
  apt-get update -qq && apt-get install -y -qq --no-install-recommends qemu-utils >/dev/null
  qemu-img convert -O vdi /build/work.qcow2 /build/central-office-hub.vdi
'

echo "==> Packaging as OVA (registering a throwaway VirtualBox VM around the disk, never powered on)..."
VDI_PATH="$(cd "$BUILD_DIR" && pwd -P)/central-office-hub.vdi"
VBoxManage createvm --name "$VM_NAME" --ostype Debian_64 --register
VBoxManage modifyvm "$VM_NAME" --memory 2048 --cpus 2 --nic1 nat --audio none
VBoxManage storagectl "$VM_NAME" --name "SATA Controller" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "$VDI_PATH"
rm -f "$OUTPUT_OVA"
VBoxManage export "$VM_NAME" --output "$OUTPUT_OVA" --manifest --options nomacs \
  --vsys 0 --product "Central Office Hub" --version "$RELEASE_TAG" \
  --description "Fleet management hub for a Serial Killer Terminal Server appliance fleet. No OS-level login is baked in -- attach your own cloud-init/answer-file at deploy time. The app itself starts on boot regardless, at https://<vm-ip>:8443."

echo "==> Patching OVF for ESXi/VMware compatibility..."
# VBoxManage's OVF is spec-legal but trips two well-known VirtualBox-vs-ESXi
# incompatibilities: it writes the memory item's AllocationUnits as the human string
# "MegaBytes" where ESXi's strict importer requires the DMTF programmatic form
# ("byte * 2^20"), and it stamps VirtualSystemType as "virtualbox-2.2", a hardware
# family ESXi doesn't recognize at all (it wants "vmx-*" version strings). Either one
# alone produces ESXi's generic "error creating the import specification" with no
# further detail -- there's no diagnostic to react to, just these two known fixes.
PKG_DIR="$BUILD_DIR/ova-pkg"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"
tar -xf "$OUTPUT_OVA" -C "$PKG_DIR"
OVF_FILE=$(find "$PKG_DIR" -maxdepth 1 -name '*.ovf')
VMDK_FILE=$(find "$PKG_DIR" -maxdepth 1 -name '*.vmdk')
MF_FILE=$(find "$PKG_DIR" -maxdepth 1 -name '*.mf')
VMDK_BASENAME=$(basename "$VMDK_FILE")
VMDK_SIZE=$(stat -f%z "$VMDK_FILE")

sed -i '' \
  -e 's|<rasd:AllocationUnits>MegaBytes</rasd:AllocationUnits>|<rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>|' \
  -e 's|<vssd:VirtualSystemType>virtualbox-2\.2</vssd:VirtualSystemType>|<vssd:VirtualSystemType>vmx-07 vmx-08 vmx-09 vmx-10 vmx-11 vmx-13 vmx-14 vmx-15 vmx-16 vmx-17 vmx-18 vmx-19 vmx-20 vmx-21</vssd:VirtualSystemType>|' \
  -e "s|ovf:href=\"$VMDK_BASENAME\"/>|ovf:href=\"$VMDK_BASENAME\" ovf:size=\"$VMDK_SIZE\"/>|" \
  "$OVF_FILE"

# The manifest hashes the .ovf itself, so it has to be recomputed after editing it --
# the .vmdk is untouched, so its hash carries over as-is.
printf 'SHA1 (%s) = %s\nSHA1 (%s) = %s\n' \
  "$(basename "$OVF_FILE")" "$(shasum -a 1 "$OVF_FILE" | awk '{print $1}')" \
  "$VMDK_BASENAME" "$(shasum -a 1 "$VMDK_FILE" | awk '{print $1}')" > "$MF_FILE"

# macOS's default `tar` output isn't just non-portable here -- it's read by neither
# ESXi nor VirtualBox's own importer ("Document is empty"). --format ustar is required.
rm -f "$OUTPUT_OVA"
(cd "$PKG_DIR" && tar --format ustar -cf "$OUTPUT_OVA" "$(basename "$OVF_FILE")" "$VMDK_BASENAME" "$(basename "$MF_FILE")")
rm -rf "$PKG_DIR"

rm -rf "$SEED_DIR" "$BUILD_DIR/seed.iso" "$BUILD_DIR/work.qcow2" "$BUILD_DIR/central-office-hub.vdi"

echo
echo "Done. VM appliance:"
echo "  $OUTPUT_OVA"
echo
echo "Import it into VMware Fusion/Workstation/ESXi, VirtualBox, or Proxmox. It ships"
echo "with no OS-level login configured -- attach your own cloud-init seed (SSH key,"
echo "password, hostname) at deploy time, the same way any generic cloud image is"
echo "customized. The Central Office admin UI comes up on its own regardless, at"
echo "https://<vm-ip>:8443."
