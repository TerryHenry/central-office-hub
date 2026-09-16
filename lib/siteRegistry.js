'use strict';

const net = require('net');
const { EventEmitter } = require('events');

/** Shared by requestDeviceList/requestSiteInfo/uploadTftpFile: every one-shot fleet-tunnel
 * request writes exactly one JSON line as its whole answer, then ends its side -- so
 * reading a socket until it closes and parsing the full buffer as one JSON value is the
 * complete response for all three, not just device listing. */
function readOneShotResponse(sock, timeoutMs, notOkMessage) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error('timed out waiting for the site to respond'));
    }, timeoutMs);
    sock.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
    });
    sock.once('close', () => {
      clearTimeout(timer);
      let parsed;
      try {
        parsed = JSON.parse(buf.toString('utf8'));
      } catch {
        reject(new Error('site returned an invalid response'));
        return;
      }
      if (!parsed.ok) {
        reject(new Error(parsed.error || notOkMessage));
        return;
      }
      resolve(parsed);
    });
    sock.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Tracks which enrolled sites currently have an active tunnel, and provides the one thing
 * anything else needs to know: how to open a connection to a specific port on a connected
 * site. Entries appear when an edge box's tunnel comes up and disappear when it drops --
 * this is live connection state, not configuration, so it's never persisted.
 */
class SiteRegistry extends EventEmitter {
  constructor() {
    super();
    this.active = new Map(); // siteId -> { sshConn, netServer, listenPort }
  }

  register(siteId, sshConn, netServer, listenPort) {
    this.active.set(siteId, { sshConn, netServer, listenPort });
    this.emit('changed');
  }

  unregister(siteId) {
    const entry = this.active.get(siteId);
    if (!entry) return;
    this.active.delete(siteId);
    try {
      entry.netServer.close();
    } catch {
      // already closed
    }
    this.emit('changed');
  }

  isConnected(siteId) {
    return this.active.has(siteId);
  }

  connectedSiteIds() {
    return [...this.active.keys()];
  }

  /** Shared by openPort/openAdminUi: connects to a site's forward listener and sends
   * whatever one-line JSON handshake the edge box's tunnelClient expects to route the
   * rest of the stream. Resolves to a raw, bridgeable socket; rejects if the site isn't
   * tunneled in right now. */
  openTunneledConnection(siteId, handshake) {
    return new Promise((resolve, reject) => {
      const entry = this.active.get(siteId);
      if (!entry) return reject(new Error('that site is not currently connected'));
      const sock = net.connect(entry.listenPort, '127.0.0.1', () => {
        sock.write(`${JSON.stringify(handshake)}\n`);
        resolve(sock);
      });
      sock.once('error', reject);
    });
  }

  /** Opens a connection to a specific port on a connected site, through its existing tunnel. */
  openPort(siteId, portId) {
    return this.openTunneledConnection(siteId, { portId });
  }

  /** Opens a connection to a connected site's own local HTTPS admin UI, through the same
   * tunnel -- lets a hub operator reach it without direct network access to the site. */
  openAdminUi(siteId) {
    return this.openTunneledConnection(siteId, { admin: true });
  }

  /** One-shot request/response, unlike openPort/openAdminUi's indefinite bidirectional
   * bridges: asks a connected site to enumerate its available serial devices. */
  requestDeviceList(siteId, timeoutMs = 10000) {
    return this.openTunneledConnection(siteId, { listDevices: true }).then((sock) =>
      readOneShotResponse(sock, timeoutMs, 'site could not list its devices').then((parsed) => parsed.ports)
    );
  }

  /** Same one-shot shape: asks a connected site for a live snapshot of its own system
   * info -- hostname, mDNS name, IPs, CPU/memory/disk, connected clients, etc. -- the
   * same fields its own Dashboard and Network tab show about itself. */
  requestSiteInfo(siteId, timeoutMs = 10000) {
    return this.openTunneledConnection(siteId, { siteInfo: true }).then((sock) =>
      readOneShotResponse(sock, timeoutMs, 'site could not report its info').then(({ ok, ...info }) => info)
    );
  }

  /** Streams a file to a connected site's TFTP root through the tunnel: writes the
   * handshake (destination filename plus the exact byte count, so the site knows when
   * it's received everything) followed by the raw file bytes, then just waits -- same
   * shape as requestDeviceList/requestSiteInfo, which only ever write a handshake and
   * read. This deliberately does NOT end its own socket to signal completion: that was
   * tried first and broke the return path (confirmed live -- the site's response never
   * arrived, every time), because the hub's local forward-listener bridges this
   * connection with plain `.pipe()` (tunnelServer.js), and a half-close from this end
   * tore down before the site's answer could come back. Ending only ever happens from
   * the site's side, exactly like the read-only requests above. */
  // A much longer default than requestDeviceList/requestSiteInfo's 10s -- those return
  // near-instantly, but a large firmware/OS image pushed over an encrypted tunnel can
  // legitimately take minutes, not seconds.
  uploadTftpFile(siteId, filename, buffer, timeoutMs = 10 * 60 * 1000) {
    return this.openTunneledConnection(siteId, { uploadTftp: true, filename, size: buffer.length }).then((sock) => {
      const responsePromise = readOneShotResponse(sock, timeoutMs, 'site could not save the file');
      sock.write(buffer);
      return responsePromise;
    });
  }
}

module.exports = new SiteRegistry();
