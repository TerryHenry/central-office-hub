# Central Office

Fleet management hub for a [Serial Killer Terminal Server](https://github.com/TerryHenry/SerialKillerTermServer)
appliance fleet. Edge boxes tunnel out to this hub over SSH (no inbound port needed at
the wiring closet); the hub gives operators one place to reach every enrolled site's
serial ports, over SSH or a browser-based console, without exposing each box directly.

This README covers building and deploying the hub itself. Already have it running and
just want to enroll a site? See [QUICKSTART.html](QUICKSTART.html). For the full
reference -- the web admin UI, permissions, session capture, and syslog forwarding --
see [HANDBOOK.html](HANDBOOK.html).

<img width="1490" height="774" alt="image" src="https://github.com/user-attachments/assets/754b305b-405e-4b25-bd7d-27f54785bac2" />


## What it does

- **Reverse-tunnel site enrollment** -- an edge box connects out to this hub and
  registers its ports; the hub never needs a route in. The tunnel listener's own port
  (System tab -- default `443`, so an edge site's outbound firewall almost never needs a
  new rule for it) is admin-configurable, though changing it is a fleet-wide operation:
  it only takes effect on the hub's next restart, and every enrolled site then needs its
  own Tunnel Port updated to match before it can reconnect.
- **Groups & console users** -- give a person access to exactly the ports they need,
  across any number of sites, without handing them an admin account.
- **Enrollment tokens** -- generate a one-time token here, paste it into the edge box's
  own Central Office panel, and it enrolls itself (no manual public-key copy required).
  Tries the tunnel/SSH listener port first (a short-lived connection authenticated only
  by holding the token itself), falling back to a direct call to this hub's web API
  port only if that doesn't work -- so an admin who's only opened the tunnel port
  through a firewall can enroll a new box over it too, not just heartbeat an existing
  one.
- **Automatic port reporting** -- an enrolled box in managed mode heartbeats its
  configured ports and version every 30s; the hub's Sites list stays current on its own.
  Once a box's tunnel is up, its heartbeat and config-backup calls prefer riding over
  that same tunnel connection too, rather than a second direct connection to this hub's
  web API port -- so with enrollment tunneled as well, an admin only ever has to keep
  the tunnel port open on an ongoing basis. The API port still matters as a fallback:
  for a box's very first heartbeat before its tunnel finishes connecting, and for
  enrollment or heartbeat whenever the tunnel itself can't be reached.
- **Polled in-place upgrades** -- queue an update for a site from here; it's applied on
  the box's own next heartbeat, using its own existing self-update pipeline.
- **Host-key pinning** -- an edge box can pin this hub's SSH host key, closing a
  man-in-the-middle gap on the tunnel connection.
- **Optional TOTP** -- two-factor auth for hub admin accounts, off by default. Multiple
  admin accounts are supported, same as the appliance's own admin-account system. The
  Password Policy panel can also *require* it for every admin account instead of
  leaving it opt-in -- an admin without it set up is walked straight into enrollment
  immediately after their next login, before reaching anything else.
- **Live device scan, site info, and TFTP push** -- request/response queries over a
  connected site's existing tunnel (not the heartbeat poll): enumerate its available
  serial devices, pull a live hostname/IP/CPU/memory snapshot, or push a file straight
  into its TFTP directory, singly or across several sites at once.
- **Remote port and TFTP-server configuration** -- add/edit/remove a site's serial ports,
  or start/stop/configure its TFTP server, queued and applied on its next heartbeat.
- **Alert webhook** -- POST a JSON payload to a URL of your choice when a site's tunnel
  drops or an admin account gets locked out after repeated failed logins, so you don't
  have to be watching the Log tab to find out. Off by default; a "Send Test Alert" button
  confirms the URL works without waiting for a real event.

- **User push and Sync Users** -- adding or editing a console user offers "Push to edge
  sites": the account is also created as a local SSH/web-console login on each checked
  site (same password, read/write or read-only), on its next heartbeat. **Sync Users**
  (per site, or for the selected sites) pushes every hub user who has access to that
  site -- via a group grant, or an explicit push -- and *replaces every user* on that
  box, like admin sync does for admins: accounts created locally there are removed, and an
  empty result is refused by the box rather than wiping its logins. Unlike admin sync,
  users are not pushed everywhere by default, since an edge box's logins can reach all of
  its ports.
- **Neighbor discovery (LLDP / CDP / FDP)** -- the Network tab shows what switch and port
  this host is plugged into, via `lldpd`, with optional CDP and FDP listening. Each
  site's row menu has **Neighbors (LLDP)**, which asks the site live over its tunnel
  and can queue an enable/disable for it. Needs `lldpd`: installed on new builds, and fetched automatically (via the
  privileged helper, needs internet) the first time an existing host starts this version.
- **Streamed TFTP push** -- files pushed to sites are spooled to disk and streamed with
  backpressure (at most three sites at a time), and the hub's own TFTP server negotiates
  block size and window size (RFC 2347/2348/2349/7440) and streams from disk, which is
  what makes large downloads fast.

- **Token-only enrollment** -- manual public-key entry is gone; sites enroll with a token. **Re-enroll (replacement box)** on a site's row issues a one-time token tied to that site, so a replacement box inherits its ports, grants and settings.
- **Batch actions** -- the Batch tab runs one script against many ports across any number
  of sites, for jobs like logging in and rebooting, factory-resetting or upgrading a rack
  of devices. Steps are one per line (`login`, `send`, `expect`, `expect-regex`, `wait`,
  `set`; any other line is typed as a command), with `{{username}}`/`{{password}}` filled
  in per device from fields that are never saved. Runs happen from the hub over the same
  tunnelled connection a web console uses, up to 5 devices at a time, and each device gets
  its own record: per-step status, the device's output, and the reason for any failure.
  A script stops on a device at its first failed step while the others carry on. Scripts
  can be saved as templates, batches can be cancelled, and the last 50 are kept.
- **Configurable dashboard** -- the Dashboard tab is a set of widgets (System, Fleet
  Topology, System Information, plus Fleet Summary, Active Sessions and Recent Activity).
  **Customize** lets you hide, show and reorder them, and toggle individual System stat
  cards. The layout is stored in the browser, so it is per-browser, not per-account.
  Clicking a connected site's port in the Fleet Topology opens that port's web console
  in a new tab.
- **Web console picker** -- drills down site -> port (a single-site user goes straight to
  the ports), scrolls when a site has many ports, and Sign Out now ends the whole
  session (it previously left an admin signed in).
- **Admin idle timeout** -- admins are signed out after a period with no mouse or
  keyboard activity (Admin Accounts tab; default 5 minutes, 0 disables it). Enforced on
  the server too, so background polling can't keep an unattended session alive.
- **Baud auto-detect** -- in Configure Ports, Detect asks the site to listen at each
  common speed (8N1, then 7E1) and pick the one that shows readable text.
- **More webhook events** -- besides site offline and lockout: site online, admin login,
  failed admin login, site enrolled, and an option to send every audit-log entry.
- **Enrollment tokens** -- unused tokens can be viewed again from the Tokens list.
- **Two-factor on hub SSH logins** -- an admin with 2FA turned on is asked for the code on
  SSH sign-in (keyboard-interactive), as the web UI already did, instead of getting in on the
  password alone.

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

### Option B: VM appliance (OVA)

```bash
./build-vm.sh
```

Builds a self-contained OVA: a Debian 12 (bookworm, amd64) "genericcloud" base with the
hub app already installed and its systemd service enabled, so it starts on boot with no
further setup. Requires Docker Desktop (used only as a throwaway Linux environment to
run QEMU + cloud-init during the build -- this host doesn't need a working QEMU
toolchain of its own) and VirtualBox's `VBoxManage` CLI (used only to package the
already-provisioned disk into a real OVA by registering a throwaway VM around it and
exporting -- that VM is never powered on). Output: `build/central-office-hub.ova`.

The shipped image carries no baked-in OS-level login -- attach your own cloud-init seed
(SSH key, password, hostname) at deploy time, the same way any generic cloud image is
customized. The app itself starts regardless of that configuration; once it's up, reach
the admin UI at `https://<vm-ip>:8443`.

## Applying updates

The Admin Accounts tab's **Version & Updates** panel checks GitHub for a newer release and, if
one publishes an in-place update package, applies it directly: download, checksum
verification, signature verification against a public key baked in at build time
(never fetched from GitHub), syntax-check the new version before touching anything
live, `npm install`, back up the current version, swap in the new one, restart. One
level of undo
(**Roll Back to Previous Version**) is available from the same panel as long as the
service is still healthy enough to serve the request; if a bad update leaves it unable
to, `sudo bash /opt/central-office/provisioning/rollback-update.sh` over SSH restores
the backup directly.

### Publishing a release

For a release to be self-update-capable (and for `build-vm.sh` to pick it up), its
GitHub Release needs three assets:

- `central-office-app.tar.gz` -- `server.js`, `package.json`/`package-lock.json`,
  `lib/`, `webui/`, `provisioning/`, `HANDBOOK.html`, `QUICKSTART.html` (no
  `node_modules`). The last two are what the Help tab's embedded Handbook actually
  serves from `APP_DIR` on a deployed box -- leaving them out of this tarball means
  every fresh OVA and every self-updated box silently loses in-app help, since neither
  provisioning path places them any other way.
- `central-office-app.tar.gz.sha256` -- its checksum. The updater refuses to apply a
  download that doesn't match this exactly.
- `central-office-app.tar.gz.sig` -- a detached Ed25519 signature over the checksum
  file, verified against `release-signing-pubkey.pem` (committed at the repo root,
  never fetched from GitHub). The checksum alone only proves a download matches what
  GitHub is *currently* serving, not who put it there -- anyone with release access
  (or a hijacked release pipeline) could otherwise publish a tarball and a matching
  checksum together. The signature is what actually proves authorship.

```bash
tar -czf build/central-office-app.tar.gz \
  --exclude='node_modules' --exclude='build' --exclude='.DS_Store' \
  server.js package.json package-lock.json lib webui provisioning HANDBOOK.html QUICKSTART.html
shasum -a 256 build/central-office-app.tar.gz | awk '{print $1}' > build/central-office-app.tar.gz.sha256
node scripts/sign-release.js build/central-office-app.tar.gz.sha256 \
  /path/to/release-signing-key.PRIVATE.pem build/central-office-app.tar.gz.sig
gh release create vX.Y build/central-office-app.tar.gz build/central-office-app.tar.gz.sha256 build/central-office-app.tar.gz.sig
```

Keep the private key out of this repo entirely (password manager, hardware key,
offline storage) and pass its path in explicitly every time -- this is a **separate
keypair from the appliance's own** (SerialKillerTermServer), so a compromise of one
doesn't hand over the other. To generate a new keypair (only ever needed once, or when
deliberately rotating): `node -e "const{publicKey,privateKey}=require('crypto').generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});console.log(publicKey,privateKey)"`
-- commit the public half as `release-signing-pubkey.pem` at the repo root, and move
the private half somewhere secure immediately. A release published without a valid
signature still shows up in **Check for Updates**, just without an **Apply Update**
button.

## Notes / limitations

- Session/request hardening: every login (admin, 2FA-completed, and the
  separate console-user login) regenerates the session id, closing session
  fixation. Every state-changing request needs a per-session CSRF token
  echoed back in a header, on top of `SameSite=Lax` (the fleet endpoints --
  enrollment, heartbeat, backup -- are exempt from this one check, since
  they're machine-to-machine and authenticated by an ed25519 signature
  instead). The web console's own WebSocket connection separately checks
  its `Origin`, since `SameSite` doesn't cover a WS handshake the way it
  covers a form POST. Responses carry `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, and HSTS. `POST
  /api/fleet/enroll` is rate-limited the same way login is.
- The admin web UI's TLS certificate is self-signed and generated locally on first boot
  (`lib/tlsCert.js`), same as the appliance -- fine for a trusted network, but browsers
  will warn until you accept it or swap in your own certificate.
- The tunnel's host-key pinning is opt-in on the *edge* side (an edge box pastes this
  hub's fingerprint into its own fleet panel); a blank fingerprint there means the
  tunnel is unverified, matching this project's default-open, opt-in-to-harden posture
  throughout.
- `build-vm.sh` targets amd64 guests, not arm64 -- an OVA is meant to import into
  whatever hypervisor the operator already has (VMware Fusion/Workstation/ESXi,
  VirtualBox, Proxmox), and virtually all of those assume an x86_64 guest. The build
  itself runs under full software emulation regardless of host architecture (Docker
  Desktop doesn't expose HVF/KVM to a nested container), so it's markedly slower on
  Apple Silicon than a same-architecture build would be, but still just a few minutes.

## License

[MIT](LICENSE)
