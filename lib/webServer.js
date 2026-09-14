'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const configStore = require('./configStore');
const passwordPolicy = require('./passwordPolicy');
const loginThrottle = require('./loginThrottle');
const logStore = require('./logStore');
const { logTimestamp } = require('./logTimestamp');
const siteRegistry = require('./siteRegistry');
const webConsole = require('./webConsole');

const { version: APP_VERSION } = require('../package.json');

function loadSessionSecret() {
  const secretPath = path.join(configStore.DATA_DIR, 'session-secret');
  if (fs.existsSync(secretPath)) return fs.readFileSync(secretPath, 'utf8');
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(secretPath, secret, { mode: 0o600 });
  return secret;
}

function createWebServer(tunnelServer, hostKeyPublic) {
  const app = express();
  app.use(express.json());
  const sessionMiddleware = session({
    secret: loadSessionSecret(),
    name: 'co.sid',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
  });
  app.use(sessionMiddleware);

  const sseClients = new Set();
  const broadcast = (event, data) => {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of sseClients) res.write(payload);
  };
  const onLog = (line) => {
    logStore.append(line);
    broadcast('log', line);
  };
  tunnelServer.on('log', onLog);
  webConsole.on('log', onLog);
  webConsole.on('sessions-changed', () => broadcast('sessions', webConsole.listSessions()));
  siteRegistry.on('changed', () => broadcast('sites', sitesWithStatus()));

  function audit(req, message) {
    const who = (req.session && req.session.username) || 'unknown';
    onLog(`[${logTimestamp()}] [AUDIT] "${who}" ${message}`);
  }

  function checkPassword(password) {
    return passwordPolicy.validatePassword(password, configStore.getConfig().passwordPolicy);
  }

  function sitesWithStatus() {
    return configStore.listSites().map((s) => ({
      ...s,
      connected: siteRegistry.isConnected(s.id)
    }));
  }

  function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) return next();
    return res.status(401).json({ error: 'unauthenticated' });
  }

  function requireFullAuth(req, res, next) {
    requireAuth(req, res, () => {
      const admin = configStore.findAdminById(req.session.adminId);
      if (!admin || admin.mustChangePassword) {
        return res.status(403).json({ error: 'must_change_password' });
      }
      next();
    });
  }

  // ---------- Auth ----------
  app.get('/api/session', (req, res) => {
    const authenticated = !!(req.session && req.session.authenticated);
    const admin = authenticated ? configStore.findAdminById(req.session.adminId) : null;
    res.json({
      authenticated,
      username: admin ? admin.username : null,
      mustChangePassword: !!(admin && admin.mustChangePassword)
    });
  });

  app.post('/api/login', (req, res) => {
    const { username, password } = req.body || {};
    const ip = req.ip;
    if (loginThrottle.isLocked(ip, username)) {
      const secs = loginThrottle.remainingLockSeconds(ip, username);
      return res.status(429).json({ error: `too many failed attempts — try again in ${secs}s` });
    }
    const admin = configStore.findAdminByUsername(username);
    if (admin && configStore.verifyPassword(password, admin.passwordSalt, admin.passwordHash)) {
      loginThrottle.recordSuccess(ip, username);
      req.session.authenticated = true;
      req.session.adminId = admin.id;
      req.session.username = admin.username;
      audit(req, `logged in from ${ip}`);
      return res.json({ ok: true, mustChangePassword: admin.mustChangePassword });
    }
    loginThrottle.recordFailure(ip, username);
    onLog(`[${logTimestamp()}] [AUDIT] login failed for "${username}" from ${ip}`);
    res.status(401).json({ error: 'invalid_credentials' });
  });

  app.post('/api/logout', (req, res) => {
    const who = req.session && req.session.username;
    req.session.destroy(() => {
      if (who) onLog(`[${logTimestamp()}] [AUDIT] "${who}" logged out`);
      res.json({ ok: true });
    });
  });

  app.get('/api/password-policy', (req, res) => {
    const policy = configStore.getConfig().passwordPolicy;
    res.json({ ...policy, description: passwordPolicy.describePolicy(policy) });
  });

  app.post('/api/password-policy', requireFullAuth, (req, res) => {
    const { minLength, requireMixedCase, requireDigit, requireSymbol, checkBreached } = req.body || {};
    const len = Number(minLength);
    if (!Number.isInteger(len) || len < 8 || len > 64) {
      return res.status(400).json({ error: 'minimum length must be a whole number between 8 and 64' });
    }
    const policy = configStore.updatePasswordPolicy({
      minLength: len,
      requireMixedCase: !!requireMixedCase,
      requireDigit: !!requireDigit,
      requireSymbol: !!requireSymbol,
      checkBreached: !!checkBreached
    });
    audit(req, 'updated the password policy');
    res.json({ ...policy, description: passwordPolicy.describePolicy(policy) });
  });

  app.post('/api/admin-password', requireAuth, (req, res) => {
    const { password } = req.body || {};
    if (password === configStore.DEFAULT_ADMIN_PASSWORD) {
      return res.status(400).json({ error: 'choose a password other than the default' });
    }
    const pwError = checkPassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    configStore.setAdminPassword(req.session.adminId, password);
    audit(req, 'changed their own password');
    res.json({ ok: true });
  });

  app.get('/api/host-key-fingerprint', requireFullAuth, (req, res) => {
    res.json({ fingerprint: hostKeyPublic });
  });

  app.get('/api/version', requireFullAuth, (req, res) => res.json({ version: APP_VERSION }));

  // ---------- Sites ----------
  app.get('/api/sites', requireFullAuth, (req, res) => res.json(sitesWithStatus()));

  app.post('/api/sites', requireFullAuth, (req, res) => {
    const { name, publicKey } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: 'a site name is required' });
    if (!publicKey || !publicKey.trim()) return res.status(400).json({ error: 'a public key is required' });
    if (configStore.findSiteByPublicKey(publicKey)) {
      return res.status(400).json({ error: 'that public key is already enrolled to a site' });
    }
    const site = configStore.createSite(name.trim(), publicKey);
    audit(req, `enrolled site "${site.name}"`);
    res.json({ ...site, connected: false });
  });

  app.delete('/api/sites/:id', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    configStore.deleteSite(req.params.id);
    siteRegistry.unregister(req.params.id);
    audit(req, `removed site "${site ? site.name : req.params.id}"`);
    res.json({ ok: true });
  });

  app.post('/api/sites/:id/ports', requireFullAuth, (req, res) => {
    const { portId, label } = req.body || {};
    if (!portId || !portId.trim()) return res.status(400).json({ error: 'a port id is required — must match the port id on the edge box' });
    if (!label || !label.trim()) return res.status(400).json({ error: 'a label is required' });
    try {
      const site = configStore.addPort(req.params.id, portId.trim(), label.trim());
      audit(req, `added port "${label}" to site "${site.name}"`);
      res.json({ ...site, connected: siteRegistry.isConnected(site.id) });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.delete('/api/sites/:id/ports/:portId', requireFullAuth, (req, res) => {
    try {
      const site = configStore.deletePort(req.params.id, req.params.portId);
      audit(req, `removed a port from site "${site.name}"`);
      res.json({ ...site, connected: siteRegistry.isConnected(site.id) });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // Choices for the web console's port picker -- every port on every currently-connected site.
  app.get('/api/terminal/choices', requireFullAuth, (req, res) => {
    const choices = [];
    for (const site of configStore.listSites()) {
      if (!siteRegistry.isConnected(site.id)) continue;
      for (const port of site.ports) {
        choices.push({ siteId: site.id, siteName: site.name, portId: port.id, label: port.label });
      }
    }
    res.json(choices);
  });

  app.get('/terminal', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'webui', 'terminal.html'));
  });

  // ---------- Sessions ----------
  app.get('/api/sessions', requireFullAuth, (req, res) => res.json(webConsole.listSessions()));

  app.post('/api/sessions/:id/kick', requireFullAuth, (req, res) => {
    webConsole.kickSession(req.params.id);
    audit(req, 'disconnected an active session');
    res.json({ ok: true });
  });

  // ---------- Log / live events ----------
  app.get('/api/log', requireFullAuth, (req, res) => res.json(logStore.getLines()));

  app.get('/api/events', requireFullAuth, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write('\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
  });

  // ---------- Static UI ----------
  app.use(express.static(path.join(__dirname, '..', 'webui')));

  function attachTerminalSocket(httpsServer) {
    webConsole.attach(httpsServer, sessionMiddleware);
  }

  return { app, attachTerminalSocket };
}

module.exports = { createWebServer };
