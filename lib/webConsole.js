'use strict';

const http = require('http');
const { EventEmitter } = require('events');
const { WebSocketServer } = require('ws');
const configStore = require('./configStore');
const siteRegistry = require('./siteRegistry');
const sessionCapture = require('./sessionCapture');
const { logTimestamp } = require('./logTimestamp');

const WS_PATH = '/ws/terminal';

/**
 * Browser-facing counterpart to tunnelServer's SSH menu loop -- same idea (pick a site +
 * port, bridge to it through the tunnel), same shape as the appliance's own
 * lib/webTerminal.js (EventEmitter, 'log'/'sessions-changed', WebSocket upgrade handled on
 * the raw http.Server before Express routing).
 */
class WebConsoleManager extends EventEmitter {
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
      portLabel: `${s.siteName} — ${s.portLabel}`,
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
      const res = new http.ServerResponse(req);
      sessionMiddleware(req, res, () => {
        const isAdmin = !!(req.session && req.session.authenticated);
        const isConsoleUser = !!(req.session && req.session.consoleUser);
        if (!isAdmin && !isConsoleUser) {
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
      const isAdmin = !!(req.session && req.session.authenticated);
      const caller = isAdmin
        ? configStore.findAdminById(req.session.adminId)
        : configStore.findUserById(req.session.consoleUser.id);
      if (!caller) {
        ws.close();
        return;
      }
      const url = new URL(req.url, 'https://localhost');
      const siteId = url.searchParams.get('siteId');
      const portId = url.searchParams.get('portId');

      // Group-scope: a console user can only open a port their groups actually grant --
      // enforced here, not just left to the picker UI, since the query params come from
      // the client and can't be trusted on their own. Admins are always read-write
      // (they bypass the group/grant system entirely, same as visibleChoices does);
      // a console user's write access comes from their effective grant permission --
      // the appliance itself has no way to tell which hub console user is on the other
      // end of a forwarded connection, so this is the only place that can enforce it.
      let canWrite = true;
      if (!isAdmin) {
        const grant = configStore.grantsForUser(caller.id).find((g) => g.siteId === siteId && g.portId === portId);
        if (!grant) {
          ws.send(JSON.stringify({ type: 'error', message: 'You are not authorized for that port.' }));
          ws.close();
          return;
        }
        canWrite = grant.permission === 'read-write';
      }

      const site = configStore.findSiteById(siteId);
      const port = site && site.ports.find((p) => p.id === portId);
      if (!site || !port) {
        ws.send(JSON.stringify({ type: 'error', message: 'No such site/port.' }));
        ws.close();
        return;
      }

      let sock;
      try {
        sock = await siteRegistry.openPort(site.id, port.id);
      } catch (err) {
        ws.send(JSON.stringify({ type: 'error', message: err.message }));
        ws.close();
        return;
      }

      const sessionId = require('crypto').randomUUID();
      const sessionRecord = {
        id: sessionId,
        username: caller.username,
        siteName: site.name,
        portLabel: port.label,
        connectedAt: new Date().toISOString(),
        ws,
        rxBytes: 0,
        txBytes: 0
      };
      this.sessions.set(sessionId, sessionRecord);
      this.emit('sessions-changed');
      this.log(`"${caller.username}" connected via web console to "${site.name} — ${port.label}"${canWrite ? '' : ' (read-only)'}`);
      ws.send(JSON.stringify({ type: 'connected', label: `${site.name} — ${port.label}`, readOnly: !canWrite }));

      // Admins have no captureEnabled field, so this is always false for them --
      // capture is a console-user-account setting, same as the appliance.
      const capture = sessionCapture.startCapture({
        username: caller.username,
        method: 'https',
        siteName: site.name,
        portLabel: port.label,
        userCaptureEnabled: !isAdmin && !!caller.captureEnabled
      });

      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        if (capture) capture.close();
        sock.destroy();
        this.sessions.delete(sessionId);
        this.emit('sessions-changed');
        this.log(`"${caller.username}" disconnected web console from "${site.name} — ${port.label}"`);
      };

      sock.on('data', (data) => {
        sessionRecord.rxBytes += data.length;
        if (capture) capture.write(data);
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
        // Read-only: silently drop input rather than forward it -- nothing actually
        // reaches the device, so nothing here counts as real traffic to capture or count.
        if (isBinary && canWrite) {
          sessionRecord.txBytes += data.length;
          if (capture) capture.write(data);
          sock.write(data);
        }
      });
      ws.once('close', finish);
    });
  }
}

module.exports = new WebConsoleManager();
