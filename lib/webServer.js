'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const { utils: sshUtils } = require('ssh2');

const configStore = require('./configStore');
const passwordPolicy = require('./passwordPolicy');
const totp = require('./totp');
const loginThrottle = require('./loginThrottle');
const logStore = require('./logStore');
const { logTimestamp } = require('./logTimestamp');
const siteRegistry = require('./siteRegistry');
const webConsole = require('./webConsole');
const selfUpdate = require('./selfUpdate');
const hostKeys = require('./hostKeys');

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
  // SSH (tunnelServer) and web console (webConsole) sessions are tracked by their own
  // managers but shown merged everywhere the admin UI displays them, mirroring the
  // appliance's own sshServer/webTerminal split.
  function allSessions() {
    return [...tunnelServer.listSessions(), ...webConsole.listSessions()];
  }

  tunnelServer.on('log', onLog);
  tunnelServer.on('sessions-changed', () => broadcast('sessions', allSessions()));
  selfUpdate.on('log', onLog);
  webConsole.on('log', onLog);
  webConsole.on('sessions-changed', () => broadcast('sessions', allSessions()));
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
    // pendingAdminId means the password already checked out but a second-factor code
    // hasn't yet -- reported here too so a page refresh mid-2FA-prompt restores that
    // screen instead of dropping back to a blank login form.
    const pendingAdmin = !authenticated && req.session && req.session.pendingAdminId
      ? configStore.findAdminById(req.session.pendingAdminId)
      : null;
    res.json({
      authenticated,
      needsTotp: !!pendingAdmin,
      username: admin ? admin.username : null,
      mustChangePassword: !!(admin && admin.mustChangePassword),
      totpEnabled: !!(admin && admin.totpEnabled)
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
      if (admin.totpEnabled) {
        // Password alone isn't enough yet -- stage the pending admin id and wait for a
        // correct code at /api/login-totp before granting req.session.authenticated.
        req.session.pendingAdminId = admin.id;
        onLog(`[${logTimestamp()}] [AUDIT] "${admin.username}" passed password check from ${ip}, awaiting 2FA code`);
        return res.json({ ok: true, needsTotp: true });
      }
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

  app.post('/api/login-totp', (req, res) => {
    const pendingId = req.session && req.session.pendingAdminId;
    if (!pendingId) return res.status(400).json({ error: 'no login in progress' });
    const admin = configStore.findAdminById(pendingId);
    if (!admin || !admin.totpEnabled) {
      delete req.session.pendingAdminId;
      return res.status(400).json({ error: 'no login in progress' });
    }
    const { token } = req.body || {};
    const ip = req.ip;
    // Keyed separately from the password-attempt throttle above so a correct password
    // doesn't share (or exhaust) its budget with guesses at the 6-digit code.
    const throttleUsername = `2fa:${admin.username}`;
    if (loginThrottle.isLocked(ip, throttleUsername)) {
      const secs = loginThrottle.remainingLockSeconds(ip, throttleUsername);
      return res.status(429).json({ error: `too many failed attempts — try again in ${secs}s` });
    }
    if (!totp.verifyToken(admin.totpSecret, token)) {
      loginThrottle.recordFailure(ip, throttleUsername);
      onLog(`[${logTimestamp()}] [AUDIT] wrong 2FA code for "${admin.username}" from ${ip}`);
      return res.status(401).json({ error: 'invalid_code' });
    }
    loginThrottle.recordSuccess(ip, throttleUsername);
    delete req.session.pendingAdminId;
    req.session.authenticated = true;
    req.session.adminId = admin.id;
    req.session.username = admin.username;
    audit(req, `completed 2FA login from ${ip}`);
    res.json({ ok: true, mustChangePassword: admin.mustChangePassword });
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

  // ---------- Admin two-factor auth (self-service, TOTP) ----------
  app.post('/api/admin-2fa/setup', requireAuth, (req, res) => {
    const secret = totp.generateSecret();
    configStore.setAdminTotpPending(req.session.adminId, secret);
    const admin = configStore.findAdminById(req.session.adminId);
    res.json({ secret, otpauthUrl: totp.otpauthUrl(secret, admin.username, 'Central Office') });
  });

  app.post('/api/admin-2fa/confirm', requireAuth, (req, res) => {
    const admin = configStore.findAdminById(req.session.adminId);
    if (!admin || !admin.totpPendingSecret) {
      return res.status(400).json({ error: 'start setup first' });
    }
    const { token } = req.body || {};
    if (!totp.verifyToken(admin.totpPendingSecret, token)) {
      return res.status(400).json({ error: 'that code did not match -- check your authenticator app and try again' });
    }
    configStore.confirmAdminTotp(req.session.adminId);
    audit(req, 'enabled two-factor authentication on their own account');
    res.json({ ok: true });
  });

  app.post('/api/admin-2fa/disable', requireAuth, (req, res) => {
    const admin = configStore.findAdminById(req.session.adminId);
    if (!admin || !admin.totpEnabled) {
      return res.status(400).json({ error: 'two-factor authentication is not enabled' });
    }
    const { token } = req.body || {};
    if (!totp.verifyToken(admin.totpSecret, token)) {
      return res.status(400).json({ error: 'that code did not match' });
    }
    configStore.disableAdminTotp(req.session.adminId);
    audit(req, 'disabled two-factor authentication on their own account');
    res.json({ ok: true });
  });

  app.get('/api/host-key-fingerprint', requireFullAuth, (req, res) => {
    res.json({ fingerprint: hostKeyPublic });
  });

  // ---------- Backup / restore ----------
  app.get('/api/backup', requireFullAuth, (req, res) => {
    const filename = `central-office-backup-${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    const payload = { ...configStore.getConfig() };
    if (req.query.includeHostKey) {
      const hostKey = hostKeys.readHostKeyFiles(configStore.DATA_DIR);
      if (hostKey) payload._hostKeyBackup = hostKey;
    }
    audit(req, `downloaded a config backup${req.query.includeHostKey ? ' (including the SSH host key)' : ''}`);
    res.json(payload);
  });

  const restoreUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
  app.post('/api/restore', requireFullAuth, (req, res) => {
    restoreUpload.single('file')(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'no file provided' });
      let parsed;
      try {
        parsed = JSON.parse(req.file.buffer.toString('utf8'));
      } catch {
        return res.status(400).json({ error: 'that file is not valid JSON' });
      }
      let hostKeyRestored = false;
      try {
        configStore.importConfig(parsed);
        if (parsed._hostKeyBackup && parsed._hostKeyBackup.privateKey) {
          hostKeys.writeHostKeyFiles(configStore.DATA_DIR, parsed._hostKeyBackup);
          hostKeyRestored = true;
        }
      } catch (e) {
        return res.status(400).json({ error: e.message });
      }
      onLog(
        `[${logTimestamp()}] [AUDIT] "${(req.session && req.session.username) || 'unknown'}" restored config from a backup file${hostKeyRestored ? ' (including the SSH host key)' : ''}`
      );
      res.json({
        ok: true,
        hostKeyRestored,
        note: hostKeyRestored
          ? 'Restart the service for the restored SSH host key to take effect.'
          : undefined
      });
    });
  });

  app.get('/api/version', requireFullAuth, (req, res) => res.json({ version: APP_VERSION }));

  app.get('/api/check-update', requireFullAuth, async (req, res) => {
    try {
      res.json(await selfUpdate.checkForUpdate());
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  app.get('/api/update/status', requireFullAuth, async (req, res) => {
    res.json({ updating: selfUpdate.isUpdating(), hasBackup: await selfUpdate.hasBackup() });
  });

  // Applies in the background -- this can take a couple of minutes (download + npm
  // install) and the final step restarts the service, killing this very request's
  // process, so there's nothing meaningful to await here. Progress streams to the Log
  // tab exactly like everything else already does.
  app.post('/api/update/apply', requireFullAuth, (req, res) => {
    if (selfUpdate.isUpdating()) {
      return res.status(409).json({ error: 'an update is already in progress' });
    }
    audit(req, 'started an in-place update');
    res.json({ started: true });
    selfUpdate.applyUpdate().catch(() => {
      // Already logged (and audited via the log stream) inside applyUpdate itself.
    });
  });

  app.post('/api/update/rollback', requireFullAuth, (req, res) => {
    if (selfUpdate.isUpdating()) {
      return res.status(409).json({ error: 'an update is already in progress' });
    }
    audit(req, 'rolled back to the previous version');
    res.json({ started: true });
    selfUpdate.rollback().catch(() => {});
  });

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
    try {
      const group = configStore.createGroup(name.trim());
      audit(req, `created group "${group.name}"`);
      res.json(group);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
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

  // Bulk grant: "every port in this site" or "every site" from a checkbox list --
  // silently skips pairs already granted instead of erroring on the whole batch.
  app.post('/api/groups/:id/grants/bulk', requireFullAuth, (req, res) => {
    const { grants } = req.body || {};
    if (!Array.isArray(grants) || grants.length === 0) {
      return res.status(400).json({ error: 'grants must be a non-empty array of {siteId, portId}' });
    }
    for (const g of grants) {
      if (!g || !g.siteId || !g.portId) return res.status(400).json({ error: 'each grant needs a siteId and portId' });
    }
    try {
      const { group, added } = configStore.addGrants(req.params.id, grants);
      audit(req, `granted ${added} port${added === 1 ? '' : 's'} to group "${group.name}"`);
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
  app.get('/api/sessions', requireFullAuth, (req, res) => res.json(allSessions()));

  app.post('/api/sessions/:id/kick', requireFullAuth, (req, res) => {
    // Session ids are unscoped UUIDs, one manager per session -- trying both is simpler
    // than tagging/parsing ids by channel, and a miss on the wrong manager is a no-op.
    tunnelServer.kickSession(req.params.id);
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
