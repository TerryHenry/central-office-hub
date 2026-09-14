'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const { utils: sshUtils } = require('ssh2');

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

  // The web terminal's port picker is shared by admins and console users -- either kind
  // of session may use it, each scoped to what they're allowed to see.
  function requireTerminalCaller(req, res, next) {
    if (req.session && req.session.authenticated) {
      const admin = configStore.findAdminById(req.session.adminId);
      if (admin && !admin.mustChangePassword) {
        req.terminalCaller = { isAdmin: true, caller: admin };
        return next();
      }
    }
    if (req.session && req.session.consoleUser) {
      req.terminalCaller = { isAdmin: false, caller: req.session.consoleUser };
      return next();
    }
    return res.status(401).json({ error: 'unauthenticated' });
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

  app.post('/api/sites/:id/queue-update', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    configStore.queueCommand(site.id, 'apply-update');
    audit(req, `queued an update for site "${site.name}"`);
    res.json({ ok: true });
  });

  // ---------- Enrollment tokens ----------
  app.get('/api/enrollment-tokens', requireFullAuth, (req, res) => res.json(configStore.listEnrollmentTokens()));

  app.post('/api/enrollment-tokens', requireFullAuth, (req, res) => {
    const { name, expiresInMinutes } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: 'a site name is required' });
    const token = configStore.createEnrollmentToken(name.trim(), Number(expiresInMinutes) || null);
    audit(req, `generated an enrollment token for "${token.name}"`);
    res.json(token);
  });

  app.delete('/api/enrollment-tokens/:token', requireFullAuth, (req, res) => {
    configStore.deleteEnrollmentToken(req.params.token);
    audit(req, 'revoked an enrollment token');
    res.json({ ok: true });
  });

  // ---------- Fleet (public: edge boxes authenticate by payload, not a logged-in session) ----------
  app.post('/api/fleet/enroll', (req, res) => {
    const { token, publicKey } = req.body || {};
    if (!token || !publicKey) return res.status(400).json({ error: 'token and publicKey are required' });
    try {
      const site = configStore.redeemEnrollmentToken(token, publicKey);
      onLog(`[${logTimestamp()}] [AUDIT] site "${site.name}" self-enrolled via token`);
      res.json({ ok: true, siteName: site.name });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/api/fleet/heartbeat', (req, res) => {
    const { publicKey, payload, signature } = req.body || {};
    if (!publicKey || !payload || !signature) {
      return res.status(400).json({ error: 'publicKey, payload, and signature are required' });
    }
    const site = configStore.findSiteByPublicKey(publicKey);
    if (!site) return res.status(401).json({ error: 'unknown site' });
    // Reuses the exact same parseKey/verify primitive tunnelServer.js already proved for
    // the SSH tunnel's own publickey auth -- one crypto path for both.
    let verified;
    try {
      const key = sshUtils.parseKey(site.publicKey);
      verified = key.verify(Buffer.from(payload, 'utf8'), Buffer.from(signature, 'base64'));
    } catch {
      verified = false;
    }
    if (verified !== true) return res.status(401).json({ error: 'signature verification failed' });

    let data;
    try {
      data = JSON.parse(payload);
    } catch {
      return res.status(400).json({ error: 'payload was not valid JSON' });
    }
    configStore.recordHeartbeat(site.id, { version: data.version, ports: data.ports });
    const command = configStore.takePendingCommand(site.id);
    res.json({ ok: true, command: command ? command.command : null });
  });

  // ---------- Console users (admin-managed accounts) ----------
  function userSummary(u) {
    return { id: u.id, username: u.username, groupIds: u.groupIds, createdAt: u.createdAt };
  }

  app.get('/api/users', requireFullAuth, (req, res) => res.json(configStore.listUsers().map(userSummary)));

  app.post('/api/users', requireFullAuth, (req, res) => {
    const { username, password, groupIds } = req.body || {};
    if (!username || !username.trim()) return res.status(400).json({ error: 'a username is required' });
    const pwError = checkPassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    try {
      const user = configStore.createUser(username.trim(), password, groupIds);
      audit(req, `created console user "${user.username}"`);
      res.json(userSummary(user));
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/api/users/:id', requireFullAuth, (req, res) => {
    const { username, groupIds } = req.body || {};
    try {
      const user = configStore.updateUser(req.params.id, { username, groupIds });
      audit(req, `updated console user "${user.username}"`);
      res.json(userSummary(user));
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/api/users/:id/password', requireFullAuth, (req, res) => {
    const { password } = req.body || {};
    const pwError = checkPassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    try {
      const user = configStore.setUserPassword(req.params.id, password);
      audit(req, `reset the password for console user "${user.username}"`);
      res.json({ ok: true });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.delete('/api/users/:id', requireFullAuth, (req, res) => {
    const user = configStore.findUserById(req.params.id);
    configStore.deleteUser(req.params.id);
    audit(req, `removed console user "${user ? user.username : req.params.id}"`);
    res.json({ ok: true });
  });

  // ---------- Groups ----------
  app.get('/api/groups', requireFullAuth, (req, res) => res.json(configStore.listGroups()));

  app.post('/api/groups', requireFullAuth, (req, res) => {
    const { name } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: 'a group name is required' });
    const group = configStore.createGroup(name.trim());
    audit(req, `created group "${group.name}"`);
    res.json(group);
  });

  app.post('/api/groups/:id', requireFullAuth, (req, res) => {
    const { name } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: 'a group name is required' });
    try {
      const group = configStore.renameGroup(req.params.id, name.trim());
      audit(req, `renamed group to "${group.name}"`);
      res.json(group);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.delete('/api/groups/:id', requireFullAuth, (req, res) => {
    const group = configStore.findGroupById(req.params.id);
    configStore.deleteGroup(req.params.id);
    audit(req, `removed group "${group ? group.name : req.params.id}"`);
    res.json({ ok: true });
  });

  app.post('/api/groups/:id/grants', requireFullAuth, (req, res) => {
    const { siteId, portId } = req.body || {};
    if (!siteId || !portId) return res.status(400).json({ error: 'siteId and portId are required' });
    try {
      const group = configStore.addGrant(req.params.id, siteId, portId);
      const site = configStore.findSiteById(siteId);
      const port = site && site.ports.find((p) => p.id === portId);
      audit(req, `granted "${site ? site.name : siteId} — ${port ? port.label : portId}" to group "${group.name}"`);
      res.json(group);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.delete('/api/groups/:id/grants/:siteId/:portId', requireFullAuth, (req, res) => {
    try {
      const group = configStore.removeGrant(req.params.id, req.params.siteId, req.params.portId);
      audit(req, `removed a grant from group "${group.name}"`);
      res.json(group);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // ---------- Console users (web terminal auth, separate from admin auth) ----------
  app.get('/api/terminal/session', (req, res) => {
    const isAdmin = !!(req.session && req.session.authenticated);
    const consoleUser = req.session && req.session.consoleUser;
    const admin = isAdmin ? configStore.findAdminById(req.session.adminId) : null;
    res.json({
      authenticated: isAdmin || !!consoleUser,
      isAdmin,
      username: isAdmin ? (admin ? admin.username : null) : (consoleUser ? consoleUser.username : null)
    });
  });

  app.post('/api/terminal/login', (req, res) => {
    const { username, password } = req.body || {};
    const ip = req.ip;
    // Prefixed so a console-user login attempt can't share (or exhaust) the same lockout
    // bucket as an admin-account login attempt for a same-named account.
    const throttleUsername = `console:${username}`;
    if (loginThrottle.isLocked(ip, throttleUsername)) {
      const secs = loginThrottle.remainingLockSeconds(ip, throttleUsername);
      return res.status(429).json({ error: `too many failed attempts — try again in ${secs}s` });
    }
    const user = configStore.findUserByUsername(username);
    if (user && configStore.verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      loginThrottle.recordSuccess(ip, throttleUsername);
      req.session.consoleUser = { id: user.id, username: user.username };
      onLog(`[${logTimestamp()}] [AUDIT] "${user.username}" logged into the web terminal from ${ip}`);
      return res.json({ ok: true });
    }
    loginThrottle.recordFailure(ip, throttleUsername);
    onLog(`[${logTimestamp()}] [AUDIT] web terminal login failed for "${username}" from ${ip}`);
    res.status(401).json({ error: 'invalid_credentials' });
  });

  app.post('/api/terminal/logout', (req, res) => {
    const who = req.session && req.session.consoleUser && req.session.consoleUser.username;
    delete req.session.consoleUser;
    if (who) onLog(`[${logTimestamp()}] [AUDIT] "${who}" logged out of the web terminal`);
    res.json({ ok: true });
  });

  // Choices for the web console's port picker -- admins see every port on every
  // currently-connected site; console users see only what their groups grant.
  app.get('/api/terminal/choices', requireTerminalCaller, (req, res) => {
    const { isAdmin, caller } = req.terminalCaller;
    const choices = tunnelServer.visibleChoices(caller, isAdmin).map(({ site, port }) => ({
      siteId: site.id,
      siteName: site.name,
      portId: port.id,
      label: port.label
    }));
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
