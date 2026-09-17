'use strict';

const net = require('net');
const crypto = require('crypto');
const { Server, utils: sshUtils } = require('ssh2');
const { EventEmitter } = require('events');
const configStore = require('./configStore');
const siteRegistry = require('./siteRegistry');
const sessionCapture = require('./sessionCapture');
const { logTimestamp } = require('./logTimestamp');

const ESCAPE_BYTE = 0x1d; // Ctrl+] -- same detach-to-menu convention as the appliance's own SSH server

// Loopback-only port the hub's own internal admin-API listener binds to (see server.js).
// Never exposed on any public interface -- reachable only via the 'tcpip' bridge below, or
// from this same host. Fixed rather than configurable since it's a pure implementation
// detail of the tunneled-heartbeat path, not something an admin ever needs to touch.
const INTERNAL_API_PORT = 18443;

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
    this.sessions = new Map();
  }

  log(line) {
    this.emit('log', `[${logTimestamp()}] ${line}`);
  }

  listSessions() {
    return Array.from(this.sessions.values()).map((s) => ({
      id: s.id,
      username: s.username,
      portLabel: s.portLabel,
      connectedAt: s.connectedAt,
      method: 'ssh',
      rxBytes: s.rxBytes,
      txBytes: s.txBytes
    }));
  }

  kickSession(id) {
    const session = this.sessions.get(id);
    if (session && session.stream) {
      session.stream.end();
      session.stream.destroy();
    }
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
    let authedUser = null;

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

      // A console user: password auth against configStore's users list, checked before
      // falling through to the admin table (usernames live in separate namespaces, but an
      // admin username always wins if both happen to collide).
      if (ctx.method !== 'password') return ctx.reject(['password']);
      const admin = configStore.findAdminByUsername(ctx.username);
      if (admin && configStore.verifyPassword(ctx.password, admin.passwordSalt, admin.passwordHash)) {
        authedAdmin = admin;
        return ctx.accept();
      }
      const user = configStore.findUserByUsername(ctx.username);
      if (user && configStore.verifyPassword(ctx.password, user.passwordSalt, user.passwordHash)) {
        authedUser = user;
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
      const caller = authedAdmin || authedUser;
      const label = authedAdmin ? caller.username : `${caller.username} (console user)`;
      this.log(`"${label}" authenticated from ${remoteInfo}`);
      client.on('session', (accept) => {
        const session = accept();
        session.on('pty', (accept) => accept && accept());
        session.on('window-change', (accept) => accept && accept());
        session.on('shell', (accept) => {
          const stream = accept();
          const sessionId = crypto.randomUUID();
          const sessionRecord = {
            id: sessionId,
            username: caller.username,
            portLabel: null,
            connectedAt: new Date().toISOString(),
            stream,
            rxBytes: 0,
            txBytes: 0,
            // Admins have no captureEnabled field at all, so this is always false for
            // them -- capture is a console-user-account setting, same as the appliance.
            captureEnabled: !!authedUser && !!authedUser.captureEnabled
          };
          this.sessions.set(sessionId, sessionRecord);
          this.emit('sessions-changed');
          stream.once('close', () => {
            this.sessions.delete(sessionId);
            this.emit('sessions-changed');
          });
          this.runMenuLoop(caller, !!authedAdmin, stream, sessionRecord).catch((err) => {
            this.log(`Session error for "${label}": ${err.message}`);
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
      } else if (authedUser) {
        this.log(`Connection closed for "${authedUser.username}" (console user, ${remoteInfo})`);
      }
    });
    client.on('error', (err) => this.log(`Client error (${remoteInfo}): ${err.message}`));
  }

  /** An edge box's own connection: accept its tcpip-forward request and register the tunnel. */
  handleSiteConnection(client, site, remoteInfo) {
    // The edge's own tunnelClient.js (openHubApiChannel) opens one of these per tunneled
    // heartbeat/backup request via forwardOut, with whatever host/port happens to satisfy
    // that call's own signature -- this side ignores the requested destination entirely and
    // always bridges to the hub's own internal admin API listener. Never a general-purpose
    // proxy: only an already-authenticated _edge connection reaches this handler at all.
    client.on('tcpip', (accept, reject) => {
      const channel = accept();
      const sock = net.connect(INTERNAL_API_PORT, '127.0.0.1');
      const cleanup = () => {
        sock.destroy();
        channel.close();
      };
      sock.once('connect', () => sock.pipe(channel).pipe(sock));
      sock.once('error', cleanup);
      channel.once('error', cleanup);
    });

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

  /**
   * Every (site, port) a caller is allowed to see, filtered to sites currently connected.
   * Admins see everything; console users see only what their groups' grants reach.
   * Shared with the web console path (webServer.js's /api/terminal/choices) so SSH and the
   * browser never disagree about what's visible.
   */
  visibleChoices(caller, isAdmin) {
    const choices = [];
    if (isAdmin) {
      // Admins bypass the group/grant system entirely and are always read-write --
      // there's no "admin grant" to look up a permission on.
      for (const site of configStore.listSites()) {
        if (!siteRegistry.isConnected(site.id)) continue;
        for (const port of site.ports) {
          choices.push({ site, port, permission: 'read-write' });
        }
      }
      return choices;
    }
    for (const grant of configStore.grantsForUser(caller.id)) {
      const site = configStore.findSiteById(grant.siteId);
      if (!site || !siteRegistry.isConnected(site.id)) continue;
      const port = site.ports.find((p) => p.id === grant.portId);
      if (!port) continue;
      choices.push({ site, port, permission: grant.permission });
    }
    return choices;
  }

  /** The port-picker menu shown to a human operator: every port they're allowed to reach among currently-connected sites. */
  async runMenuLoop(caller, isAdmin, stream, sessionRecord) {
    while (!stream.destroyed) {
      const choices = this.visibleChoices(caller, isAdmin);
      if (choices.length === 0) {
        stream.write('\r\nNo sites are currently connected. Contact your administrator.\r\n');
        return;
      }
      stream.write('\r\nAvailable ports:\r\n');
      choices.forEach((c, i) => {
        stream.write(`  [${i + 1}] ${c.site.name} — ${c.port.label}${c.permission === 'read-only' ? ' (read-only)' : ''}\r\n`);
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
      await this.bridgeToPort(choice.site, choice.port, stream, sessionRecord, choice.permission !== 'read-only');
    }
  }

  /** Bridges an SSH shell stream to a port on a site, through its tunnel, until detach/close.
   * canWrite (default true, for admin/menu-less callers) gates the operator->device
   * direction only -- device output always reaches the operator regardless. */
  bridgeToPort(site, port, stream, sessionRecord, canWrite = true) {
    return siteRegistry
      .openPort(site.id, port.id)
      .then(
        (sock) =>
          new Promise((resolve) => {
            this.log(`Connected to "${site.name} — ${port.label}"${canWrite ? '' : ' (read-only)'}`);
            if (sessionRecord) {
              sessionRecord.portLabel = `${site.name} — ${port.label}`;
              this.emit('sessions-changed');
            }
            stream.write(`\r\nConnected to ${site.name} — ${port.label}. Press Ctrl+] to return to the menu.\r\n`);
            if (!canWrite) stream.write('This session is read-only; your input will not be sent to the port.\r\n');
            stream.write('\r\n');

            const capture = sessionCapture.startCapture({
              username: sessionRecord ? sessionRecord.username : 'unknown',
              method: 'ssh',
              siteName: site.name,
              portLabel: port.label,
              userCaptureEnabled: !!(sessionRecord && sessionRecord.captureEnabled)
            });

            let done = false;
            const finish = () => {
              if (done) return;
              done = true;
              if (capture) capture.close();
              stream.removeListener('data', onStreamData);
              stream.removeListener('close', onStreamClose);
              stream.removeListener('error', onStreamClose);
              sock.removeListener('data', onSockData);
              sock.removeListener('close', onSockClose);
              sock.removeListener('error', onSockError);
              sock.destroy();
              this.log(`Disconnected from "${site.name} — ${port.label}"`);
              if (sessionRecord) {
                sessionRecord.portLabel = null;
                this.emit('sessions-changed');
              }
              resolve();
            };

            const onSockData = (data) => {
              if (sessionRecord) sessionRecord.rxBytes += data.length;
              if (capture) capture.write(data);
              if (!stream.destroyed) stream.write(data);
            };
            const onStreamData = (data) => {
              const escIdx = data.indexOf(ESCAPE_BYTE);
              if (escIdx !== -1) {
                // The detach escape byte always works even read-only -- only the actual
                // port-bound bytes ahead of it are subject to the write gate.
                if (escIdx > 0 && canWrite) {
                  const toWrite = data.slice(0, escIdx);
                  if (sessionRecord) sessionRecord.txBytes += toWrite.length;
                  if (capture) capture.write(toWrite);
                  sock.write(toWrite);
                }
                stream.write('\r\n[Detached]\r\n');
                finish();
                return;
              }
              if (!canWrite) return;
              if (sessionRecord) sessionRecord.txBytes += data.length;
              if (capture) capture.write(data);
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
module.exports.INTERNAL_API_PORT = INTERNAL_API_PORT;
