'use strict';

const net = require('net');
const siteRegistry = require('./siteRegistry');

// Closes the listener this long after its last connection (keeps the exposure window
// short without cutting off a browser tab someone's actively using -- a real page load
// opens several connections in quick succession, so this only fires once activity truly
// stops), and unconditionally after the hard cap regardless of activity.
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_LIFETIME_MS = 30 * 60 * 1000;

// Drawn from this fixed, narrow range instead of listen(0, ...) handing back whatever
// the OS feels like from the ephemeral range (32768-60999 on a typical Linux default) --
// that made it impractical for an admin sitting behind a firewall to ever open enough
// inbound ports to reach this feature at all. 20 ports bounds how many admin-UI tunnels
// can be open across every site at once, which comfortably covers realistic concurrent
// use without asking for a firewall rule anywhere near as wide as the full ephemeral
// range. Document this range (9200-9219) as what actually needs opening inbound.
const PORT_RANGE_START = 9200;
const PORT_RANGE_END = 9219;

function normalizeIp(ip) {
  return String(ip || '').replace(/^::ffff:/, '');
}

/**
 * Opens a short-lived, single-admin-IP-restricted raw TCP listener that pipes every
 * connection straight through to a site's own local admin UI, via the same tunnel
 * mechanism lib/siteRegistry.js already uses for serial ports -- just a different
 * handshake (see tunnelClient.js's openAdminSession on the appliance side). Pure
 * byte-for-byte passthrough: TLS is negotiated end-to-end between whichever browser
 * connects and the site's own certificate, never touched or terminated here.
 *
 * Security model: this is a bare TCP listener with no auth of its own beyond matching
 * the source IP of the admin who requested it -- proportionate to (not stronger than)
 * this app's existing trust posture elsewhere (e.g. the TFTP server has no auth at all,
 * syslog forwarding is plain unencrypted UDP, both documented as "fine on a trusted
 * network"). The idle/hard timeouts bound how long that window stays open.
 */
function openAdminTunnel(siteId, allowedIp) {
  const normalizedAllowedIp = normalizeIp(allowedIp);

  const handleConnection = (sock) => {
    if (normalizeIp(sock.remoteAddress) !== normalizedAllowedIp) {
      sock.destroy();
      return;
    }
    resetIdleTimerRef.current();
    siteRegistry
      .openAdminUi(siteId)
      .then((tunneled) => {
        sock.pipe(tunneled).pipe(sock);
        const cleanup = () => {
          sock.destroy();
          tunneled.destroy();
        };
        sock.once('close', cleanup);
        sock.once('error', cleanup);
        tunneled.once('close', cleanup);
        tunneled.once('error', cleanup);
      })
      .catch(() => sock.destroy());
  };

  // resetIdleTimer is defined once listen() actually succeeds (it needs the winning
  // server instance's own close()), but handleConnection above is wired up per attempt,
  // before that's known -- this ref is just how it reaches back to whichever attempt
  // finally wins.
  const resetIdleTimerRef = { current: () => {} };

  function attempt(port) {
    return new Promise((resolve, reject) => {
      const server = net.createServer(handleConnection);
      let idleTimer = null;
      let hardTimer = null;

      const close = () => {
        clearTimeout(idleTimer);
        clearTimeout(hardTimer);
        try {
          server.close();
        } catch {
          // already closed
        }
      };
      const resetIdleTimer = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(close, IDLE_TIMEOUT_MS);
        idleTimer.unref();
      };

      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE' && port < PORT_RANGE_END) {
          resolve(attempt(port + 1));
          return;
        }
        reject(
          err.code === 'EADDRINUSE'
            ? new Error(`all admin-UI tunnel ports (${PORT_RANGE_START}-${PORT_RANGE_END}) are currently in use`)
            : err
        );
      });
      server.listen(port, '0.0.0.0', () => {
        resetIdleTimerRef.current = resetIdleTimer;
        resetIdleTimer();
        hardTimer = setTimeout(close, MAX_LIFETIME_MS);
        hardTimer.unref();
        resolve({ port, close });
      });
    });
  }

  return attempt(PORT_RANGE_START);
}

module.exports = { openAdminTunnel };
