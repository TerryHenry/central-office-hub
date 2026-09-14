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

  /**
   * Opens a connection to a specific port on a connected site, through its existing
   * tunnel, and sends the small handshake line the edge box's tunnelClient expects.
   * Resolves to a raw, bridgeable socket; rejects if the site isn't tunneled in right now.
   */
  openPort(siteId, portId) {
    return new Promise((resolve, reject) => {
      const entry = this.active.get(siteId);
      if (!entry) return reject(new Error('that site is not currently connected'));
      const sock = net.connect(entry.listenPort, '127.0.0.1', () => {
        sock.write(`${JSON.stringify({ portId })}\n`);
        resolve(sock);
      });
      sock.once('error', reject);
    });
  }
}

module.exports = new SiteRegistry();
