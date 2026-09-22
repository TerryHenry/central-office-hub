'use strict';

const net = require('net');
const siteRegistry = require('./siteRegistry');

// Closes the listener this long after its last connection (keeps the exposure window
// short without cutting off a browser tab someone's actively using -- a real page load
// opens several connections in quick succession, so this only fires once activity truly
// stops), and unconditionally after the hard cap regardless of activity.
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_LIFETIME_MS = 30 * 60 * 1000;

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
  return new Promise((resolve, reject) => {
    const normalizedAllowedIp = normalizeIp(allowedIp);
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

    const server = net.createServer((sock) => {
      if (normalizeIp(sock.remoteAddress) !== normalizedAllowedIp) {
        sock.destroy();
        return;
      }
      resetIdleTimer();
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
    });

    server.on('error', reject);
    server.listen(0, '0.0.0.0', () => {
      resetIdleTimer();
      hardTimer = setTimeout(close, MAX_LIFETIME_MS);
      hardTimer.unref();
      resolve({ port: server.address().port, close });
    });
  });
}

module.exports = { openAdminTunnel };
