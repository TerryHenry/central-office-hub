'use strict';

const http = require('http');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { WebSocketServer } = require('ws');
const configStore = require('./configStore');
const siteRegistry = require('./siteRegistry');
const { logTimestamp } = require('./logTimestamp');

const WS_PATH = '/ws/shell';

/**
 * Browser-facing bridge to a real interactive shell on a connected site, through its
 * tunnel -- same shape as webConsole.js (EventEmitter, 'log'/'sessions-changed',
 * WebSocket upgrade handled on the raw http.Server before Express routing), but
 * admin-only: a full OS shell is meaningfully more powerful than serial-port console
 * access, so unlike webConsole this never checks group grants or accepts a console-user
 * session -- there's no permission model to scope it to, only "admin or not". The site
 * itself is the other half of the gate: it refuses the tunnel request outright unless
 * its own admin has separately opted in locally (see tunnelClient.js's remoteShell
 * handling on the appliance side).
 */
class SiteShellManager extends EventEmitter {
  constructor() {
    super();
    this.sessions = new Map();
  }

  log(line) {
    this.emit('log', `[${logTimestamp()}] ${line}`);
  }

  listSessions() {
    return Array.from(this.sessions.values()).map((s) => ({
      id: s.id,
      username: s.username,
      portLabel: `${s.siteName} — diagnostic shell`,
      connectedAt: s.connectedAt,
      method: 'https',
      rxBytes: s.rxBytes,
      txBytes: s.txBytes
    }));
  }

  kickSession(id) {
    const session = this.sessions.get(id);
    if (session && session.ws) session.ws.close();
  }

  attach(httpsServer, sessionMiddleware) {
    const wss = new WebSocketServer({ noServer: true });

    httpsServer.on('upgrade', (req, socket, head) => {
      if (!req.url || !req.url.startsWith(WS_PATH)) return;

      // Same reasoning as webConsole.js's identical check: sameSite: 'lax' doesn't
      // protect a WebSocket upgrade (it's technically a GET), so this is what actually
      // stops a malicious page from driving a live shell session through an admin's
      // own cookies.
      const origin = req.headers.origin;
      let sameOrigin = false;
      if (origin && req.headers.host) {
        try {
          sameOrigin = new URL(origin).host === req.headers.host;
        } catch {
          sameOrigin = false;
        }
      }
      if (!sameOrigin) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }

      const res = new http.ServerResponse(req);
      sessionMiddleware(req, res, () => {
        if (!req.session || !req.session.authenticated) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
          return;
        }
        wss.handleUpgrade(req, socket, head, (ws) => {
          wss.emit('connection', ws, req);
        });
      });
    });

    wss.on('connection', async (ws, req) => {
      const admin = configStore.findAdminById(req.session.adminId);
      if (!admin) {
        ws.close();
        return;
      }

      const url = new URL(req.url, 'https://localhost');
      const siteId = url.searchParams.get('siteId');
      const site = configStore.findSiteById(siteId);
      if (!site) {
        ws.send(JSON.stringify({ type: 'error', message: 'No such site.' }));
        ws.close();
        return;
      }

      let sock;
      try {
        sock = await siteRegistry.openShell(site.id);
      } catch (err) {
        ws.send(JSON.stringify({ type: 'error', message: err.message }));
        ws.close();
        return;
      }

      const sessionId = crypto.randomUUID();
      const sessionRecord = {
        id: sessionId,
        username: admin.username,
        siteName: site.name,
        connectedAt: new Date().toISOString(),
        ws,
        rxBytes: 0,
        txBytes: 0
      };
      this.sessions.set(sessionId, sessionRecord);
      this.emit('sessions-changed');
      this.log(`"${admin.username}" opened a diagnostic shell on "${site.name}"`);
      ws.send(JSON.stringify({ type: 'connected', label: `${site.name} — diagnostic shell` }));

      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        sock.destroy();
        this.sessions.delete(sessionId);
        this.emit('sessions-changed');
        this.log(`"${admin.username}" closed the diagnostic shell on "${site.name}"`);
      };

      // The site's own tunnelClient writes a plain-text refusal (not a JSON envelope)
      // and ends the connection when remote shell isn't enabled locally -- this first
      // chunk of data IS that refusal as often as it's real shell output, so there's no
      // clean way to tell them apart here. Left as raw terminal text either way (an
      // xterm.js pane renders it fine as plain text), rather than trying to detect and
      // re-wrap it as a structured error.
      sock.on('data', (data) => {
        sessionRecord.rxBytes += data.length;
        if (ws.readyState === ws.OPEN) ws.send(data);
      });
      sock.once('close', () => {
        if (ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: 'Connection closed.' }));
          ws.close();
        }
        finish();
      });
      sock.once('error', (err) => {
        if (ws.readyState === ws.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: err.message }));
          ws.close();
        }
        finish();
      });

      ws.on('message', (data, isBinary) => {
        if (isBinary) {
          sessionRecord.txBytes += data.length;
          sock.write(data);
        }
      });
      ws.once('close', finish);
    });
  }
}

module.exports = new SiteShellManager();
