# Central Office

Fleet management hub for a [Serial Killer Terminal Server](https://github.com/TerryHenry/SerialKillerTermServer)
appliance fleet. Edge boxes tunnel out to this hub over SSH (no inbound port needed at
the wiring closet); the hub gives operators one place to reach every enrolled site's
serial ports, over SSH or a browser-based console, without exposing each box directly.

## What it does

- **Reverse-tunnel site enrollment** -- an edge box connects out to this hub and
  registers its ports; the hub never needs a route in.
- **Groups & console users** -- give a person access to exactly the ports they need,
  across any number of sites, without handing them an admin account.
- **Enrollment tokens** -- generate a one-time token here, paste it into the edge box's
  own Central Office panel, and it enrolls itself (no manual public-key copy required).
- **Automatic port reporting** -- an enrolled box in managed mode heartbeats its
  configured ports and version every 30s; the hub's Sites list stays current on its own.
- **Polled in-place upgrades** -- queue an update for a site from here; it's applied on
  the box's own next heartbeat, using its own existing self-update pipeline.
- **Host-key pinning** -- an edge box can pin this hub's SSH host key, closing a
  man-in-the-middle gap on the tunnel connection.
- **Optional TOTP** -- two-factor auth for hub admin accounts, off by default.

## Quick start (development)

```bash
npm install
node server.js
```

Visit `https://localhost:8443`. First run seeds a default admin (`admin` /
`letmein0!`) that must be changed on first login. Data lives under `data/` (or wherever
`CO_DATA_DIR` points).

## Deploying

### Option A: install on an existing Debian/Ubuntu host

```bash
git clone https://github.com/TerryHenry/central-office-hub.git /opt/central-office
cd /opt/central-office
sudo bash provisioning/setup.sh
```

This installs Node.js (via NodeSource, if not already present), creates an unprivileged
`central-office` service account, installs and starts `central-office.service`, and
grants that account a narrowly-scoped `sudoers.d` rule limited to restarting its own
service -- the same privilege model the appliance itself uses.

### Option B: VM appliance

```bash
./build-vm.sh
```

Builds a self-contained qcow2 image: a Debian 12 (bookworm, arm64) "genericcloud" base
with the hub app already installed and its systemd service enabled, so it starts on
boot with no further setup. Requires Docker Desktop (used only as a throwaway Linux
environment to run QEMU + cloud-init during the build -- this host doesn't need a
working QEMU toolchain of its own). Output: `build/central-office-hub.qcow2`.

The shipped image carries no baked-in OS-level login -- attach your own cloud-init seed
(SSH key, password, hostname) at deploy time in UTM, Proxmox, or plain QEMU, the same
way any generic cloud image is customized. The app itself starts regardless of that
configuration; once it's up, reach the admin UI at `https://<vm-ip>:8443`.

## Applying updates

The Account tab's **Version & Updates** panel checks GitHub for a newer release and, if
one publishes an in-place update package, applies it directly: download, checksum
verification, syntax-check the new version before touching anything live, `npm
install`, back up the current version, swap in the new one, restart. One level of undo
(**Roll Back to Previous Version**) is available from the same panel as long as the
service is still healthy enough to serve the request; if a bad update leaves it unable
to, `sudo bash /opt/central-office/provisioning/rollback-update.sh` over SSH restores
the backup directly.

### Publishing a release

For a release to be self-update-capable (and for `build-vm.sh` to pick it up), its
GitHub Release needs two assets:

- `central-office-app.tar.gz` -- `server.js`, `package.json`/`package-lock.json`,
  `lib/`, `webui/`, `provisioning/` (no `node_modules`).
- `central-office-app.tar.gz.sha256` -- its checksum. The updater refuses to apply a
  download that doesn't match this exactly.

```bash
tar -czf build/central-office-app.tar.gz \
  --exclude='node_modules' --exclude='build' --exclude='.DS_Store' \
  server.js package.json package-lock.json lib webui provisioning
shasum -a 256 build/central-office-app.tar.gz | awk '{print $1}' > build/central-office-app.tar.gz.sha256
gh release create vX.Y build/central-office-app.tar.gz build/central-office-app.tar.gz.sha256
```

## Notes / limitations

- The admin web UI's TLS certificate is self-signed and generated locally on first boot
  (`lib/tlsCert.js`), same as the appliance -- fine for a trusted network, but browsers
  will warn until you accept it or swap in your own certificate.
- The tunnel's host-key pinning is opt-in on the *edge* side (an edge box pastes this
  hub's fingerprint into its own fleet panel); a blank fingerprint there means the
  tunnel is unverified, matching this project's default-open, opt-in-to-harden posture
  throughout.
- `build-vm.sh` targets arm64 guests (matches Apple Silicon hosts, for fast HVF-backed
  playback in UTM later) -- the build itself runs under software emulation inside
  Docker regardless of host architecture, so it works the same on Intel Macs, just
  slower.
