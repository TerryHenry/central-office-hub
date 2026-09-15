'use strict';

const net = require('net');
const { EventEmitter } = require('events');

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
}

module.exports = new SiteRegistry();
