'use strict';

const http = require('http');
const { EventEmitter } = require('events');
const { WebSocketServer } = require('ws');
const configStore = require('./configStore');
const siteRegistry = require('./siteRegistry');
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
      site: s.siteName,
      port: s.portLabel,
      connectedAt: s.connectedAt
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
      const portId = url.searchParams.get('portId');
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
        username: admin.username,
        siteName: site.name,
        portLabel: port.label,
        connectedAt: new Date().toISOString(),
        ws
      };
      this.sessions.set(sessionId, sessionRecord);
      this.emit('sessions-changed');
      this.log(`"${admin.username}" connected via web console to "${site.name} — ${port.label}"`);
      ws.send(JSON.stringify({ type: 'connected', label: `${site.name} — ${port.label}` }));

      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        sock.destroy();
        this.sessions.delete(sessionId);
        this.emit('sessions-changed');
        this.log(`"${admin.username}" disconnected web console from "${site.name} — ${port.label}"`);
      };

      sock.on('data', (data) => {
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
        if (isBinary) sock.write(data);
      });
      ws.once('close', finish);
    });
  }
}

module.exports = new WebConsoleManager();
