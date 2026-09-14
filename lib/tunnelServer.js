'use strict';

const net = require('net');
const { Server, utils: sshUtils } = require('ssh2');
const { EventEmitter } = require('events');
const configStore = require('./configStore');
const siteRegistry = require('./siteRegistry');
const { logTimestamp } = require('./logTimestamp');

const ESCAPE_BYTE = 0x1d; // Ctrl+] -- same detach-to-menu convention as the appliance's own SSH server

/**
 * One ssh2 Server, one listener, two kinds of connection distinguished at auth time:
 *  - an edge box registering its tunnel (username "_edge", public key matched against an
 *    enrolled site's key)
 *  - a human operator wanting a shell (any other username, password auth against the hub's
 *    own admin account)
 * Mirrors pi/lib/sshServer.js's shape (EventEmitter, 'log' events, a menu-loop pattern for
 * shell sessions) so it reads the same way to anyone who's worked on the appliance.
 */
class TunnelServerManager extends EventEmitter {
  constructor() {
    super();
    this.server = null;
  }

  log(line) {
    this.emit('log', `[${logTimestamp()}] ${line}`);
  }

  start(hostKeyBuffer, port) {
    if (this.server) return;
    this.server = new Server({ hostKeys: [hostKeyBuffer] }, (client) => this.handleConnection(client));
    this.server.on('error', (err) => this.log(`Server error: ${err.message}`));
    this.server.listen(port, '0.0.0.0', () => this.log(`Tunnel/SSH server listening on port ${port}`));
  }

  handleConnection(client) {
    const sock = client._sock;
    const remoteInfo = sock ? `${sock.remoteAddress}:${sock.remotePort}` : 'unknown';
    let authedAdmin = null;
    let authedSite = null;

    client.on('authentication', (ctx) => {
      if (ctx.username === '_edge') {
        if (ctx.method !== 'publickey') return ctx.reject(['publickey']);
        // The client presents a parsed key (algo + raw bytes), not a PEM string, so this
        // can't use configStore.findSiteByPublicKey's string comparison -- parse every
        // enrolled site's stored key and compare against what was actually presented.
        // There's no per-site username; identity *is* the key, matching the design doc's
        // enrollment model (an admin pastes the exact key, once, out of band).
        const matched = configStore.listSites().find((s) => {
          try {
            const allowedKey = sshUtils.parseKey(s.publicKey);
            if (allowedKey instanceof Error || !allowedKey) return false;
            return ctx.key.algo === allowedKey.type && allowedKey.getPublicSSH().equals(ctx.key.data);
          } catch {
            return false;
          }
        });
        if (!matched) return ctx.reject(['publickey']);
        if (ctx.signature) {
          try {
            const allowedKey = sshUtils.parseKey(matched.publicKey);
            const verified = allowedKey.verify(ctx.blob, ctx.signature);
            if (verified !== true) return ctx.reject(['publickey']);
          } catch {
            return ctx.reject(['publickey']);
          }
        }
        authedSite = matched;
        return ctx.accept(); // key-probe phase also lands here and is accepted, same as sshServer.js
      }

      // Anything else: a human operator, password auth against the hub's own admin account.
      if (ctx.method !== 'password') return ctx.reject(['password']);
      const admin = configStore.findAdminByUsername(ctx.username);
      if (admin && configStore.verifyPassword(ctx.password, admin.passwordSalt, admin.passwordHash)) {
        authedAdmin = admin;
        return ctx.accept();
      }
      return ctx.reject(['password']);
    });

    client.on('ready', () => {
      if (authedSite) {
        this.log(`Site "${authedSite.name}" tunnel connected from ${remoteInfo}`);
        this.handleSiteConnection(client, authedSite, remoteInfo);
        return;
      }
      this.log(`"${authedAdmin.username}" authenticated from ${remoteInfo}`);
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (accept) => accept && accept());
        session.on('window-change', (accept) => accept && accept());
        session.on('shell', (accept) => {
          const stream = accept();
          this.runMenuLoop(authedAdmin, stream).catch((err) => {
            this.log(`Session error for "${authedAdmin.username}": ${err.message}`);
          }).finally(() => stream.end());
        });
        session.on('exec', (accept, reject) => reject());
      });
    });

    client.on('close', () => {
      if (authedSite) {
        siteRegistry.unregister(authedSite.id);
        this.log(`Site "${authedSite.name}" tunnel disconnected`);
      } else if (authedAdmin) {
        this.log(`Connection closed for "${authedAdmin.username}" (${remoteInfo})`);
      }
    });
    client.on('error', (err) => this.log(`Client error (${remoteInfo}): ${err.message}`));
  }

  /** An edge box's own connection: accept its tcpip-forward request and register the tunnel. */
  handleSiteConnection(client, site, remoteInfo) {
    client.on('request', (accept, reject, name, info) => {
      if (name !== 'tcpip-forward') {
        if (reject) reject();
        return;
      }
      // The client re-keys its own bookkeeping to the *actual* assigned port once
      // bindPort 0 ("any") gets resolved (confirmed in ssh2's own Client#forwardIn: it
      // reassigns its local `bindPort` to the real chosen port before using it as a map
      // key) -- so forwardOut has to be called with that same resolved port, not the
      // original request's bindPort (which stays 0 here), or the client can't match the
      // incoming channel to a forward it's expecting and the connection dies immediately.
      let listenPort;
      const netServer = net.createServer((sock) => {
        client.forwardOut(info.bindAddr, listenPort, sock.remoteAddress, sock.remotePort, (err, channel) => {
          if (err) {
            sock.destroy();
            return;
          }
          sock.pipe(channel).pipe(sock);
          const cleanup = () => {
            sock.destroy();
            channel.close();
          };
          sock.once('error', cleanup);
          channel.once('error', cleanup);
        });
      });
      netServer.on('error', (err) => {
        this.log(`Forward listener error for site "${site.name}": ${err.message}`);
        if (reject) reject();
      });
      netServer.listen(0, '127.0.0.1', () => {
        listenPort = netServer.address().port;
        siteRegistry.register(site.id, client, netServer, listenPort);
        if (accept) accept(listenPort);
      });
    });
  }

  /** The port-picker menu shown to a human operator: every port on every currently-connected site. */
  async runMenuLoop(admin, stream) {
    while (!stream.destroyed) {
      const choices = [];
      for (const site of configStore.listSites()) {
        if (!siteRegistry.isConnected(site.id)) continue;
        for (const port of site.ports) {
          choices.push({ site, port });
        }
      }
      if (choices.length === 0) {
        stream.write('\r\nNo sites are currently connected. Contact your administrator.\r\n');
        return;
      }
      stream.write('\r\nAvailable ports:\r\n');
      choices.forEach((c, i) => {
        stream.write(`  [${i + 1}] ${c.site.name} — ${c.port.label}\r\n`);
      });
      stream.write('\r\nEnter number (or "q" to quit): ');

      const line = await this.readLine(stream);
      if (line === null) return;
      const trimmed = line.trim().toLowerCase();
      if (trimmed === 'q' || trimmed === 'quit' || trimmed === 'exit') {
        stream.write('\r\nGoodbye.\r\n');
        return;
      }
      const idx = parseInt(trimmed, 10) - 1;
      const choice = choices[idx];
      if (!choice) {
        stream.write('\r\nInvalid selection.\r\n');
        continue;
      }
      await this.bridgeToPort(choice.site, choice.port, stream);
    }
  }

  /** Bridges an SSH shell stream to a port on a site, through its tunnel, until detach/close. */
  bridgeToPort(site, port, stream) {
    return siteRegistry
      .openPort(site.id, port.id)
      .then(
        (sock) =>
          new Promise((resolve) => {
            this.log(`Connected to "${site.name} — ${port.label}"`);
            stream.write(`\r\nConnected to ${site.name} — ${port.label}. Press Ctrl+] to return to the menu.\r\n\r\n`);

            let done = false;
            const finish = () => {
              if (done) return;
              done = true;
              stream.removeListener('data', onStreamData);
              stream.removeListener('close', onStreamClose);
              stream.removeListener('error', onStreamClose);
              sock.removeListener('data', onSockData);
              sock.removeListener('close', onSockClose);
              sock.removeListener('error', onSockError);
              sock.destroy();
              this.log(`Disconnected from "${site.name} — ${port.label}"`);
              resolve();
            };

            const onSockData = (data) => {
              if (!stream.destroyed) stream.write(data);
            };
            const onStreamData = (data) => {
              const escIdx = data.indexOf(ESCAPE_BYTE);
              if (escIdx !== -1) {
                if (escIdx > 0) sock.write(data.slice(0, escIdx));
                stream.write('\r\n[Detached]\r\n');
                finish();
                return;
              }
              sock.write(data);
            };
            const onSockClose = () => {
              stream.write(`\r\n[Connection to "${port.label}" closed]\r\n`);
              finish();
            };
            const onSockError = (err) => {
              stream.write(`\r\n[Connection error: ${err.message}]\r\n`);
              finish();
            };
            const onStreamClose = () => finish();

            stream.on('data', onStreamData);
            stream.once('close', onStreamClose);
            stream.once('error', onStreamClose);
            sock.on('data', onSockData);
            sock.once('close', onSockClose);
            sock.once('error', onSockError);
          })
      )
      .catch((err) => {
        stream.write(`\r\nCould not connect: ${err.message}\r\n`);
      });
  }

  /** Reads a single line from the raw SSH stream with manual echo/backspace handling. */
  readLine(stream) {
    return new Promise((resolve) => {
      let buf = '';
      const cleanup = () => {
        stream.removeListener('data', onData);
        stream.removeListener('close', onClose);
      };
      const onClose = () => {
        cleanup();
        resolve(null);
      };
      const onData = (data) => {
        for (const byte of data) {
          if (byte === 0x03) {
            cleanup();
            stream.write('^C\r\n');
            resolve('q');
            return;
          }
          if (byte === 0x0d || byte === 0x0a) {
            cleanup();
            stream.write('\r\n');
            resolve(buf);
            return;
          }
          if (byte === 0x7f || byte === 0x08) {
            if (buf.length > 0) {
              buf = buf.slice(0, -1);
              stream.write('\b \b');
            }
            continue;
          }
          if (byte >= 0x20 && byte <= 0x7e) {
            buf += String.fromCharCode(byte);
            stream.write(String.fromCharCode(byte));
          }
        }
      };
      stream.on('data', onData);
      stream.once('close', onClose);
    });
  }
}

module.exports = new TunnelServerManager();
