'use strict';

const path = require('path');
const fs = require('fs');
const http = require('http');
const os = require('os');
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
const { fetchLatestEdgeVersion } = require('./edgeVersionCheck');
const systemInfo = require('./systemInfo');
const systemStats = require('./systemStats');
const networkInfo = require('./networkInfo');
const systemControl = require('./systemControl');
const systemHelper = require('./systemHelper');
const tlsCert = require('./tlsCert');
const { parseCsvObjects } = require('./csv');
const sessionCapture = require('./sessionCapture');
const adminTunnelProxy = require('./adminTunnelProxy');
const syslogClient = require('./syslogClient');

const { version: APP_VERSION } = require('../package.json');

// The HA agent (ha-agent.js) is a separate process/service from this one -- see
// README's "High Availability" section. Same default directory both processes assume
// unless HA_AGENT_DIR is overridden identically on both. Reading its status.json
// directly (rather than calling its HTTP server) keeps this route dependency-free even
// when the agent isn't running; only the promote action needs the agent's own port,
// since that's the one thing only the agent itself can actually do.
const HA_AGENT_DIR = process.env.HA_AGENT_DIR || '/opt/central-office/ha-agent';
const HA_STATUS_PATH = path.join(HA_AGENT_DIR, 'status.json');
const HA_CONFIG_PATH = path.join(HA_AGENT_DIR, 'config.json');

/** Validates and normalizes a submitted ha-agent config. Runs here (not just in
 * ha-agent.js) because the agent might not even be running yet on a fresh node --
 * this app is what lets an admin author the config file for the first time. */
function normalizeHaConfig(body) {
  const errors = [];
  body = body || {};

  const mode = body.mode === 'dns' ? 'dns' : body.mode === 'vip' ? 'vip' : null;
  if (!mode) errors.push('failover mode must be "vip" or "dns"');
  const role = body.role === 'secondary' ? 'secondary' : body.role === 'primary' ? 'primary' : null;
  if (!role) errors.push('role must be "primary" or "secondary"');

  const peerHost = String(body.peerHost || '').trim();
  if (!peerHost) errors.push('peer host is required');

  const listenPort = Number(body.listenPort);
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) errors.push('invalid agent listen port');
  const peerPort = Number(body.peerPort);
  if (!Number.isInteger(peerPort) || peerPort < 1 || peerPort > 65535) errors.push('invalid peer agent port');

  const vipIn = body.vip || {};
  const vipAddress = String(vipIn.address || '').trim();
  const vipPrefix = Number(vipIn.prefix);
  const vipInterface = String(vipIn.interface || '').trim();
  if (mode === 'vip') {
    if (!vipAddress) errors.push('VIP address is required in virtual-IP mode');
    if (!Number.isInteger(vipPrefix) || vipPrefix < 0 || vipPrefix > 32) errors.push('VIP prefix must be between 0 and 32');
    if (!vipInterface) errors.push('VIP interface is required in virtual-IP mode');
  }

  const dnsUpdateCommand = String((body.dns && body.dns.updateCommand) || '').trim();

  const hcIn = body.healthCheck || {};
  const hcIntervalMs = Number(hcIn.intervalMs);
  const hcFailureThreshold = Number(hcIn.failureThreshold);
  const hcTimeoutMs = Number(hcIn.timeoutMs);
  if (!Number.isInteger(hcIntervalMs) || hcIntervalMs < 500) errors.push('health check interval must be at least 500ms');
  if (!Number.isInteger(hcFailureThreshold) || hcFailureThreshold < 1) errors.push('failure threshold must be at least 1');
  if (!Number.isInteger(hcTimeoutMs) || hcTimeoutMs < 100) errors.push('health check timeout must be at least 100ms');

  const repIn = body.replication || {};
  const repIntervalMs = Number(repIn.intervalMs);
  const remoteDataDir = String(repIn.remoteDataDir || '').trim();
  const sshUser = String(repIn.sshUser || '').trim();
  const sshKeyPath = String(repIn.sshKeyPath || '').trim();
  if (!Number.isInteger(repIntervalMs) || repIntervalMs < 1000) errors.push('replication interval must be at least 1000ms');
  if (!remoteDataDir) errors.push('replication remote data directory is required');
  if (!sshUser) errors.push('replication SSH user is required');
  if (!sshKeyPath) errors.push('replication SSH key path is required');

  if (errors.length) return { errors };

  return {
    config: {
      enabled: !!body.enabled,
      mode,
      role,
      peerHost,
      listenPort,
      peerPort,
      vip: { address: vipAddress, prefix: vipPrefix, interface: vipInterface },
      dns: { updateCommand: dnsUpdateCommand },
      healthCheck: { intervalMs: hcIntervalMs, failureThreshold: hcFailureThreshold, timeoutMs: hcTimeoutMs },
      replication: { intervalMs: repIntervalMs, remoteDataDir, sshUser, sshKeyPath },
      preemptOnRecovery: !!body.preemptOnRecovery
    }
  };
}

function sanitizeTftpFilename(name) {
  const base = path.basename(String(name || '').trim());
  if (!base || base === '.' || base === '..') {
    throw new Error('invalid filename');
  }
  return base;
}

function loadSessionSecret() {
  const secretPath = path.join(configStore.DATA_DIR, 'session-secret');
  if (fs.existsSync(secretPath)) return fs.readFileSync(secretPath, 'utf8');
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(secretPath, secret, { mode: 0o600 });
  return secret;
}

function createWebServer(tunnelServer, tftpServer, hostKeyPublic, hostKeyPrivate) {
  const app = express();
  app.use(express.json());

  // ---------- Basic security response headers ----------
  // Cheap, static, and safe defaults -- none of these change behavior for a legitimate
  // same-origin request, they just remove options an attacker's page would otherwise have.
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    // Always safe here -- this app has no HTTP listener at all, only HTTPS (see
    // server.js), so there's no plain-HTTP fallback mode this could ever break.
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });

  const sessionMiddleware = session({
    secret: loadSessionSecret(),
    name: 'co.sid',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
  });
  app.use(sessionMiddleware);

  // ---------- CSRF protection ----------
  // sameSite: 'lax' above already blocks a cross-site *POST* from carrying this
  // session's cookie (Lax only rides along on a top-level GET navigation), but it's a
  // browser-enforced attribute, not something this app verifies itself -- an older
  // browser, an embedded webview that mishandles SameSite, or a future GET route that
  // accidentally does something mutating would have nothing else standing in the way.
  // A synchronizer token closes that regardless of any of the above: every
  // state-changing request has to prove it already had access to this exact session
  // (by reading the token back out of an authenticated JSON response and echoing it in
  // a header), which a cross-site form or plain top-level navigation can never do.
  //
  // Exempt: the fleet endpoints are machine-to-machine (an enrolled site's own
  // fleetHeartbeat.js/pinnedHttps.js calling in) and carry no browser session or cookie
  // jar at all -- they're authenticated by an ed25519 signature over the payload
  // instead, checked inside each handler. CSRF is a browser/cookie-confusion attack;
  // it doesn't apply to a Node HTTPS client that never had a cookie to begin with, and
  // running the session/CSRF-token machinery against these would both reject every
  // legitimate heartbeat and spin up a throwaway session on every single one, forever.
  const CSRF_EXEMPT_PATHS = new Set(['/api/fleet/enroll', '/api/fleet/heartbeat', '/api/fleet/backup']);
  // Exported as a plain function, not just middleware, because a session that gets
  // regenerated (see loginSession() below) loses whatever token this already minted for
  // it earlier in the same request -- the login routes call this again themselves, on
  // the fresh session, so the response they send back carries a token that's actually
  // still valid.
  function ensureCsrfToken(req) {
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
  }
  app.use((req, res, next) => {
    if (CSRF_EXEMPT_PATHS.has(req.path)) return next();
    ensureCsrfToken(req);
    next();
  });
  const CSRF_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
  app.use((req, res, next) => {
    if (CSRF_EXEMPT_PATHS.has(req.path) || CSRF_SAFE_METHODS.has(req.method)) return next();
    const expected = req.session.csrfToken;
    const provided = req.headers['x-csrf-token'];
    const valid =
      typeof provided === 'string' &&
      provided.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
    if (!valid) {
      return res.status(403).json({ error: 'invalid_csrf_token' });
    }
    next();
  });

  // ---------- Session fixation ----------
  // Every login-success route (admin login/2FA-completed login, console-user
  // login/2FA) calls this instead of setting req.session fields directly. regenerate()
  // issues a brand-new session id and wipes the old session's data (including whatever
  // pre-auth csrfToken it had) -- callers pass a function that sets whatever fields the
  // now-empty fresh session needs. Without this, the session id a browser had *before*
  // logging in is the exact same one that's privileged *after* -- if an attacker ever got
  // their own (pre-authentication) session id into a victim's cookie jar by any means,
  // waiting for the victim to log in would hand the attacker a fully authenticated
  // session, no credential theft required. Regenerating on every privilege escalation
  // closes that regardless of how the id might have leaked.
  function loginSession(req, res, setFields, sendResponse) {
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'could not establish a session' });
      setFields(req.session);
      const csrfToken = ensureCsrfToken(req);
      sendResponse(csrfToken);
    });
  }

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
  siteRegistry.on('changed', async () => broadcast('sites', await sitesWithStatus()));
  tftpServer.on('log', onLog);
  tftpServer.on('status-changed', () => broadcast('tftp-status', { running: tftpServer.isRunning() }));
  // Without a listener here, an unhandled 'error' event (e.g. the configured port is
  // already in use) is fatal to the whole Node process, not just the TFTP feature --
  // tftpServer.js already calls stop() on its own error handler, so this only needs to
  // get the failure into the log instead of letting it crash the hub.
  tftpServer.on('error', (err) => onLog(`[${logTimestamp()}] [ERROR] TFTP server error: ${err.message}`));

  // Dashboard tab: pushes fresh CPU/memory/disk numbers to any open admin session every
  // few seconds, same cadence and shape as the appliance's own Dashboard tab.
  const statsTimer = setInterval(async () => {
    if (sseClients.size === 0) return;
    const stats = await systemStats.getStats(configStore.DATA_DIR);
    broadcast('stats', { ...stats, clientsConnected: allSessions().length });
    // Rides the same timer as the stats push above -- RX/TX counters accumulate
    // continuously on an open session (not just at connect/disconnect, when
    // 'sessions-changed' already fires), so this is what makes them visibly tick up
    // live instead of only updating on the next connect/disconnect/kick.
    broadcast('sessions', allSessions());
  }, 3000);
  statsTimer.unref();

  function audit(req, message) {
    const who = (req.session && req.session.username) || 'unknown';
    const line = `"${who}" ${message}`;
    onLog(`[${logTimestamp()}] [AUDIT] ${line}`);
    const syslog = configStore.getConfig().syslog;
    if (syslog.enabled && syslog.host) {
      syslogClient.send(syslog.host, syslog.port, syslog.facility, `[AUDIT] ${line}`);
    }
  }

  function checkPassword(password) {
    return passwordPolicy.validatePassword(password, configStore.getConfig().passwordPolicy);
  }

  // A one-way digest of {username, passwordHash} pairs -- must serialize identically to
  // the appliance's own copy of this exact function (lib/fleetHeartbeat.js) so a truly
  // matching admin table always hashes the same on both sides. passwordHash alone (no
  // salt) is enough: sync-admins copies the hash verbatim rather than re-hashing, so a
  // byte-identical hash after a real sync is as certain as comparing the salted hash
  // pair would be, and a hash collision across different salt+password combinations is
  // cryptographically infeasible.
  function adminsFingerprint(admins) {
    const normalized = admins
      .map((a) => ({ username: a.username, passwordHash: a.passwordHash }))
      .sort((a, b) => a.username.localeCompare(b.username));
    return crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
  }

  async function sitesWithStatus() {
    const latestEdge = await fetchLatestEdgeVersion();
    const hubAdminsFingerprint = adminsFingerprint(configStore.listAdmins());
    return configStore.listSites().map((s) => ({
      ...s,
      // The list view only needs to know a backup exists and when -- the actual (large,
      // sensitive) contents are a separate fetch via GET /api/sites/:id/backup.
      lastBackup: s.lastBackup ? { takenAt: s.lastBackup.takenAt } : null,
      connected: siteRegistry.isConnected(s.id),
      latestEdgeVersion: latestEdge ? latestEdge.version : null,
      latestEdgeVersionUrl: latestEdge ? latestEdge.url : null,
      updateAvailable: !!(latestEdge && s.reportedVersion && s.reportedVersion !== latestEdge.version),
      // null = unknown (box hasn't reported an admins fingerprint yet, e.g. an older
      // version or no heartbeat since this shipped) -- distinct from true/false, never
      // guessed. Compares a fingerprint of {username, passwordHash} pairs, not just
      // usernames -- two boxes that both still use the default "admin" username would
      // otherwise show as "in sync" even though Sync Admins was never actually applied
      // and their passwords are completely different.
      adminsSynced: s.reportedAdminsFingerprint ? s.reportedAdminsFingerprint === hubAdminsFingerprint : null
    }));
  }

  function requireAuth(req, res, next) {
    if (req.session && req.session.authenticated) return next();
    return res.status(401).json({ error: 'unauthenticated' });
  }

  // Stricter gate for everything except session/login/logout/admin-password/2FA setup:
  // while the logged-in admin still has a default or otherwise-forced password, nothing
  // else in the API works, so a forced change can't be bypassed by talking to the API
  // directly instead of the UI. Same treatment for a policy-mandated 2FA enrollment
  // that hasn't happened yet -- requireAdminTotp only ever blocks here, never at login
  // itself, so the admin can always reach the routes needed to actually satisfy it.
  function requireFullAuth(req, res, next) {
    requireAuth(req, res, () => {
      const admin = configStore.findAdminById(req.session.adminId);
      if (!admin || admin.mustChangePassword) {
        return res.status(403).json({ error: 'must_change_password' });
      }
      if (configStore.getConfig().passwordPolicy.requireAdminTotp && !admin.totpEnabled) {
        return res.status(403).json({ error: 'must_enable_totp' });
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
      totpEnabled: !!(admin && admin.totpEnabled),
      mustEnableTotp: !!(admin && configStore.getConfig().passwordPolicy.requireAdminTotp && !admin.totpEnabled),
      // Every state-changing request has to echo this back in an X-CSRF-Token header --
      // see the CSRF protection middleware above. Handed out here on every session
      // check (unauthenticated included) since the frontend needs it before it can even
      // submit login.
      csrfToken: req.session.csrfToken
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
      loginSession(
        req,
        res,
        (session) => {
          session.authenticated = true;
          session.adminId = admin.id;
          session.username = admin.username;
        },
        (csrfToken) => {
          configStore.recordAdminLogin(admin.id);
          audit(req, `logged in from ${ip}`);
          res.json({
            ok: true,
            mustChangePassword: admin.mustChangePassword,
            mustEnableTotp: configStore.getConfig().passwordPolicy.requireAdminTotp && !admin.totpEnabled,
            csrfToken
          });
        }
      );
      return;
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
    loginSession(
      req,
      res,
      (session) => {
        session.authenticated = true;
        session.adminId = admin.id;
        session.username = admin.username;
      },
      (csrfToken) => {
        configStore.recordAdminLogin(admin.id);
        audit(req, `completed 2FA login from ${ip}`);
        res.json({
          ok: true,
          mustChangePassword: admin.mustChangePassword,
          mustEnableTotp: configStore.getConfig().passwordPolicy.requireAdminTotp && !admin.totpEnabled,
          csrfToken
        });
      }
    );
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
    const { minLength, requireMixedCase, requireDigit, requireSymbol, checkBreached, requireAdminTotp } = req.body || {};
    const len = Number(minLength);
    if (!Number.isInteger(len) || len < 8 || len > 64) {
      return res.status(400).json({ error: 'minimum length must be a whole number between 8 and 64' });
    }
    const policy = configStore.updatePasswordPolicy({
      minLength: len,
      requireMixedCase: !!requireMixedCase,
      requireDigit: !!requireDigit,
      requireSymbol: !!requireSymbol,
      checkBreached: !!checkBreached,
      requireAdminTotp: !!requireAdminTotp
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

  // ---------- Admin accounts (multiple hub admins, same pattern as the appliance's own) ----------
  app.get('/api/admins', requireFullAuth, (req, res) => {
    res.json(
      configStore.listAdmins().map((a) => ({
        id: a.id,
        username: a.username,
        mustChangePassword: a.mustChangePassword,
        totpEnabled: !!a.totpEnabled,
        lastLoginAt: a.lastLoginAt || null,
        isSelf: a.id === req.session.adminId
      }))
    );
  });

  app.post('/api/admins', requireFullAuth, (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }
    const pwError = checkPassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    try {
      const admin = configStore.createAdmin(username, password);
      audit(req, `created admin account "${admin.username}"`);
      res.json({ id: admin.id, username: admin.username, mustChangePassword: admin.mustChangePassword });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/api/admins/:id', requireFullAuth, (req, res) => {
    const { username, password } = req.body || {};
    try {
      let admin = configStore.findAdminById(req.params.id);
      if (!admin) return res.status(404).json({ error: 'admin account not found' });
      if (username && username !== admin.username) {
        const oldUsername = admin.username;
        admin = configStore.renameAdmin(req.params.id, username);
        audit(req, `renamed admin account "${oldUsername}" to "${username}"`);
        if (req.session.adminId === admin.id) req.session.username = admin.username;
      }
      if (password) {
        const pwError = checkPassword(password);
        if (pwError) return res.status(400).json({ error: pwError });
        admin = configStore.setAdminPassword(req.params.id, password);
        audit(req, `reset the password for admin account "${admin.username}"`);
      }
      res.json({ id: admin.id, username: admin.username, mustChangePassword: admin.mustChangePassword });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.delete('/api/admins/:id', requireFullAuth, (req, res) => {
    if (req.params.id === req.session.adminId) {
      return res.status(400).json({ error: "you can't delete the account you're logged in as" });
    }
    try {
      const admin = configStore.findAdminById(req.params.id);
      configStore.deleteAdmin(req.params.id);
      audit(req, `deleted admin account "${admin ? admin.username : req.params.id}"`);
      res.json({ ok: true });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.get('/api/host-key-fingerprint', requireFullAuth, (req, res) => {
    res.json({ fingerprint: hostKeyPublic });
  });

  // ---------- Tunnel/SSH listener settings ----------
  // One listener serves both edge-site tunnel registration and admin-tunnel SSH
  // sessions (see tunnelServer.js) -- server.js reads this port once, at process
  // startup, so a saved change here only actually takes effect after a full service
  // restart (System tab's Restart Service Now), same as the appliance's own SSH
  // Server Settings panel needing a stop/start to apply a new port.
  app.get('/api/ssh-settings', requireFullAuth, (req, res) => {
    res.json(configStore.getConfig().ssh);
  });

  app.post('/api/ssh-settings', requireFullAuth, (req, res) => {
    const port = Number(req.body && req.body.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: 'port must be a whole number between 1 and 65535' });
    }
    const ssh = configStore.updateSSH({ port });
    audit(req, `changed the tunnel/SSH listener port to ${port} (takes effect on next restart)`);
    res.json(ssh);
  });

  // ---------- TLS certificate (the hub's own admin UI HTTPS cert) ----------
  app.get('/api/tls/info', requireFullAuth, (req, res) => {
    try {
      res.json(tlsCert.getCertInfo(configStore.DATA_DIR));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  const tlsUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 64 * 1024 } });
  app.post('/api/tls/upload', requireFullAuth, (req, res) => {
    tlsUpload.fields([{ name: 'cert', maxCount: 1 }, { name: 'key', maxCount: 1 }])(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      const certFile = req.files && req.files.cert && req.files.cert[0];
      const keyFile = req.files && req.files.key && req.files.key[0];
      if (!certFile || !keyFile) return res.status(400).json({ error: 'both a certificate and a private key file are required' });
      try {
        const info = tlsCert.setCert(configStore.DATA_DIR, certFile.buffer.toString('utf8'), keyFile.buffer.toString('utf8'));
        audit(req, `uploaded a custom TLS certificate (${info.subject})`);
        res.json({ ok: true, ...info });
      } catch (e) {
        res.status(400).json({ error: e.message });
      }
    });
  });

  app.post('/api/tls/revert', requireFullAuth, (req, res) => {
    try {
      const info = tlsCert.resetToSelfSigned(configStore.DATA_DIR);
      audit(req, 'reverted the TLS certificate to a freshly-generated self-signed one');
      res.json({ ok: true, ...info });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Restarts just this app (not the whole host) -- used after a TLS cert change so a
  // fresh process picks it up.
  app.post('/api/system/restart-service', requireFullAuth, (req, res) => {
    audit(req, 'restarted the service');
    res.json({ started: true });
    systemHelper.runHelper(['service-restart']).catch((err) => onLog(`[${logTimestamp()}] [ERROR] service restart failed: ${err.message}`));
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
  app.get('/api/sites', requireFullAuth, async (req, res) => res.json(await sitesWithStatus()));

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

  app.post('/api/sites/:id/rename', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    const name = String((req.body && req.body.name) || '').trim();
    if (!name) return res.status(400).json({ error: 'a site name is required' });
    const oldName = site.name;
    configStore.renameSite(site.id, name);
    audit(req, `renamed site "${oldName}" to "${name}"`);
    res.json({ ok: true, name });
  });

  app.post('/api/sites/:id/queue-update', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    configStore.queueCommand(site.id, 'apply-update');
    audit(req, `queued an upgrade for site "${site.name}"`);
    res.json({ ok: true });
  });

  // Opens a short-lived raw TCP forward so this admin's own browser can reach the
  // site's HTTPS admin UI directly, through the tunnel, without the site needing any
  // inbound network access of its own. See lib/adminTunnelProxy.js for the security
  // model (source-IP-restricted, auto-expiring).
  app.post('/api/sites/:id/admin-session', requireFullAuth, async (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    if (!siteRegistry.isConnected(site.id)) {
      return res.status(400).json({ error: 'that site is not currently connected' });
    }
    try {
      const { port } = await adminTunnelProxy.openAdminTunnel(site.id, req.ip);
      audit(req, `opened an admin-UI tunnel session to site "${site.name}"`);
      res.json({ port });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Bulk: "upgrade some or all edge devices" from a checkbox list, instead of one at a time.
  app.post('/api/sites/queue-update/bulk', requireFullAuth, (req, res) => {
    const { siteIds } = req.body || {};
    if (!Array.isArray(siteIds) || siteIds.length === 0) {
      return res.status(400).json({ error: 'siteIds must be a non-empty array' });
    }
    const queued = configStore.queueCommands(siteIds, 'apply-update');
    audit(req, `queued an upgrade for ${queued} site${queued === 1 ? '' : 's'}`);
    res.json({ ok: true, queued });
  });

  // The minimal fields an edge box needs to authenticate a login locally -- never the
  // hub's own admin ids/2FA state, just enough to replace its admin table with accounts
  // that verify against the exact same password.
  function adminsForSync() {
    return configStore.listAdmins().map((a) => ({
      username: a.username,
      passwordSalt: a.passwordSalt,
      passwordHash: a.passwordHash
    }));
  }

  app.post('/api/sites/:id/sync-admins', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    configStore.queueCommand(site.id, 'sync-admins', adminsForSync());
    audit(req, `queued an admin sync for site "${site.name}"`);
    res.json({ ok: true });
  });

  app.post('/api/sites/sync-admins/bulk', requireFullAuth, (req, res) => {
    const { siteIds } = req.body || {};
    if (!Array.isArray(siteIds) || siteIds.length === 0) {
      return res.status(400).json({ error: 'siteIds must be a non-empty array' });
    }
    const queued = configStore.queueCommands(siteIds, 'sync-admins', adminsForSync());
    audit(req, `queued an admin sync for ${queued} site${queued === 1 ? '' : 's'}`);
    res.json({ ok: true, queued });
  });

  // ---------- Site config backup / restore (via the fleet channel) ----------
  app.post('/api/sites/:id/backup/request', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    configStore.queueCommand(site.id, 'send-backup');
    audit(req, `requested a config backup from site "${site.name}"`);
    res.json({ ok: true });
  });

  app.get('/api/sites/:id/backup', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    if (!site.lastBackup) return res.status(404).json({ error: 'no backup has been received from this site yet' });
    const filename = `${site.name.replace(/[^a-z0-9-_]+/gi, '_')}-backup-${site.lastBackup.takenAt.slice(0, 10)}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    audit(req, `downloaded the stored config backup for site "${site.name}"`);
    res.json(site.lastBackup.data);
  });

  // Restores the backup the hub already has on file for this site -- no re-upload of
  // something it already stored needed. The upload endpoint below stays for pushing a
  // *different* file (another site's backup, an older one saved elsewhere, etc).
  app.post('/api/sites/:id/backup/restore-stored', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    if (!site.lastBackup) return res.status(400).json({ error: 'no backup is stored for this site yet' });
    configStore.queueCommand(site.id, 'restore-backup', site.lastBackup.data);
    audit(req, `queued a config restore for site "${site.name}" from its own stored backup`);
    res.json({ ok: true });
  });

  const siteBackupUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
  app.post('/api/sites/:id/backup/restore', requireFullAuth, (req, res) => {
    siteBackupUpload.single('file')(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      const site = configStore.findSiteById(req.params.id);
      if (!site) return res.status(404).json({ error: 'site not found' });
      if (!req.file) return res.status(400).json({ error: 'no file provided' });
      let parsed;
      try {
        parsed = JSON.parse(req.file.buffer.toString('utf8'));
      } catch {
        return res.status(400).json({ error: 'that file is not valid JSON' });
      }
      // Queued, not applied here -- only the edge box itself can safely restore its own
      // config; this just hands it the payload to apply on its next heartbeat.
      configStore.queueCommand(site.id, 'restore-backup', parsed);
      audit(req, `queued a config restore for site "${site.name}"`);
      res.json({ ok: true });
    });
  });

  // ---------- Site port configuration & local access (via the fleet channel) ----------
  // Both are queued, not applied here -- same reasoning as backup/restore above: only
  // the edge box itself can safely touch its own serial ports or SSH/web-console state,
  // this just hands it the desired end state to apply on its next heartbeat.
  // Live, synchronous(-ish) request/response through the tunnel -- distinct from the
  // rest of this section, which all queue a fire-and-forget command applied on the
  // site's next heartbeat. This one needs an answer back in time for a UI click, so it
  // goes straight over the already-open tunnel instead of waiting on the poll cycle.
  app.get('/api/sites/:id/devices', requireFullAuth, async (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    if (!siteRegistry.isConnected(site.id)) {
      return res.status(400).json({ error: 'that site is not currently connected' });
    }
    try {
      const ports = await siteRegistry.requestDeviceList(site.id);
      res.json({ ports });
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  app.get('/api/sites/:id/info', requireFullAuth, async (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    if (!siteRegistry.isConnected(site.id)) {
      return res.status(400).json({ error: 'that site is not currently connected' });
    }
    try {
      const info = await siteRegistry.requestSiteInfo(site.id);
      res.json(info);
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  app.post('/api/sites/:id/ports', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    const ports = req.body && req.body.ports;
    if (!Array.isArray(ports)) return res.status(400).json({ error: 'ports must be an array' });
    for (const p of ports) {
      if (!p || !String(p.label || '').trim() || !String(p.path || '').trim()) {
        return res.status(400).json({ error: 'each port needs a label and a device path' });
      }
    }
    configStore.queueCommand(site.id, 'set-ports', ports);
    audit(req, `queued a port configuration change for site "${site.name}" (${ports.length} port${ports.length === 1 ? '' : 's'})`);
    res.json({ ok: true });
  });

  // Deletes one port immediately from the hub's own cached view (and any group grants
  // pointing at it), rather than requiring the full "replace the whole list" flow above
  // for a single removal. removeFromEdge additionally queues a set-ports command built
  // from the site's current cached ports minus this one -- the same mechanism the bulk
  // route uses -- so the site actually stops offering it too, not just the hub's
  // display of it. Left unset, this is a hub-only removal: honest callers should know
  // (the UI says so) that it can reappear on the site's next heartbeat if the site is
  // still online and still configured with it.
  app.delete('/api/sites/:id/ports/:portId', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    const port = site.ports.find((p) => p.id === req.params.portId);
    if (!port) return res.status(404).json({ error: 'port not found' });
    const removeFromEdge = req.query.removeFromEdge === 'true';
    if (removeFromEdge) {
      const remaining = site.ports
        .filter((p) => p.id !== req.params.portId)
        .map((p) => ({ id: p.id, label: p.label, path: p.path, baudRate: p.baudRate, access: p.access, captureEnabled: p.captureEnabled }));
      configStore.queueCommand(site.id, 'set-ports', remaining);
    }
    configStore.removePort(site.id, req.params.portId);
    audit(req, `deleted port "${port.label}" from site "${site.name}"${removeFromEdge ? ' (queued removal on the site itself too)' : ' (hub view only)'}`);
    res.json({ ok: true, removeFromEdge });
  });

  app.post('/api/sites/:id/local-access', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    const sshEnabled = !!(req.body && req.body.sshEnabled);
    const webTerminalEnabled = !!(req.body && req.body.webTerminalEnabled);
    configStore.queueCommand(site.id, 'set-local-access', { sshEnabled, webTerminalEnabled });
    audit(req, `queued local access change for site "${site.name}" (SSH ${sshEnabled ? 'on' : 'off'}, web console ${webTerminalEnabled ? 'on' : 'off'})`);
    res.json({ ok: true });
  });

  app.post('/api/sites/:id/tftp-settings', requireFullAuth, (req, res) => {
    const site = configStore.findSiteById(req.params.id);
    if (!site) return res.status(404).json({ error: 'site not found' });
    const enabled = !!(req.body && req.body.enabled);
    const port = Number(req.body && req.body.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ error: 'invalid port' });
    }
    const allowUpload = !!(req.body && req.body.allowUpload);
    const autoStart = !!(req.body && req.body.autoStart);
    configStore.queueCommand(site.id, 'set-tftp', { enabled, port, allowUpload, autoStart });
    audit(req, `queued TFTP server settings for site "${site.name}" (${enabled ? 'enabled' : 'disabled'}, port ${port})`);
    res.json({ ok: true });
  });

  // ---------- Push a file to one or more sites' TFTP directories (live, over the tunnel) ----------
  // Matches the hub's own local TFTP upload limit (below) rather than an arbitrary
  // smaller cap -- firmware/OS images pushed to a site are the same kind of file either
  // way. Memory storage is still fine at this size: a bulk push reuses the one buffered
  // upload for every target site rather than holding a copy per site.
  const siteTftpUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 * 1024 } });

  app.post('/api/sites/:id/tftp-upload', requireFullAuth, (req, res) => {
    siteTftpUpload.single('file')(req, res, async (err) => {
      if (err) return res.status(400).json({ error: err.message });
      const site = configStore.findSiteById(req.params.id);
      if (!site) return res.status(404).json({ error: 'site not found' });
      if (!req.file) return res.status(400).json({ error: 'no file provided' });
      if (!siteRegistry.isConnected(site.id)) {
        return res.status(400).json({ error: 'that site is not currently connected' });
      }
      let filename;
      try {
        filename = sanitizeTftpFilename(req.file.originalname);
      } catch (e) {
        return res.status(400).json({ error: e.message });
      }
      try {
        const result = await siteRegistry.uploadTftpFile(site.id, filename, req.file.buffer);
        audit(req, `uploaded "${filename}" (${req.file.buffer.length} bytes) to site "${site.name}"'s TFTP directory`);
        res.json({ ok: true, filename: result.filename, bytesWritten: result.bytesWritten });
      } catch (e) {
        res.status(502).json({ error: e.message });
      }
    });
  });

  // Bulk: push the same file to several sites at once, in parallel -- each site succeeds
  // or fails independently (one being offline shouldn't block the others).
  app.post('/api/sites/tftp-upload/bulk', requireFullAuth, (req, res) => {
    siteTftpUpload.single('file')(req, res, async (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'no file provided' });
      let siteIds;
      try {
        siteIds = JSON.parse((req.body && req.body.siteIds) || '[]');
      } catch {
        return res.status(400).json({ error: 'siteIds must be a JSON array' });
      }
      if (!Array.isArray(siteIds) || siteIds.length === 0) {
        return res.status(400).json({ error: 'select at least one site' });
      }
      let filename;
      try {
        filename = sanitizeTftpFilename(req.file.originalname);
      } catch (e) {
        return res.status(400).json({ error: e.message });
      }
      const results = await Promise.all(
        siteIds.map(async (siteId) => {
          const site = configStore.findSiteById(siteId);
          if (!site) return { siteId, ok: false, error: 'site not found' };
          if (!siteRegistry.isConnected(siteId)) {
            return { siteId, name: site.name, ok: false, error: 'not currently connected' };
          }
          try {
            await siteRegistry.uploadTftpFile(siteId, filename, req.file.buffer);
            return { siteId, name: site.name, ok: true };
          } catch (e) {
            return { siteId, name: site.name, ok: false, error: e.message };
          }
        })
      );
      const succeeded = results.filter((r) => r.ok).map((r) => r.name);
      audit(req, `uploaded "${filename}" to ${succeeded.length} of ${results.length} selected site(s)'s TFTP directories`);
      res.json({ filename, results });
    });
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
    const ip = req.ip;
    // The token itself (crypto.randomBytes(24), 192 bits) is far too large a space to
    // meaningfully brute-force regardless of rate limiting -- this is flood protection,
    // not credential-guessing defense, matching the same reasoning as the appliance's
    // own first-run setup throttle. Keyed on a fixed string, not the token itself: a
    // per-token bucket would just let an attacker burn through unlimited buckets by
    // trying a fresh random token each time.
    if (loginThrottle.isLocked(ip, 'fleet-enroll')) {
      const secs = loginThrottle.remainingLockSeconds(ip, 'fleet-enroll');
      return res.status(429).json({ error: `too many attempts — try again in ${secs}s` });
    }
    const { token, publicKey } = req.body || {};
    if (!token || !publicKey) {
      loginThrottle.recordFailure(ip, 'fleet-enroll');
      return res.status(400).json({ error: 'token and publicKey are required' });
    }
    try {
      const site = configStore.redeemEnrollmentToken(token, publicKey);
      loginThrottle.recordSuccess(ip, 'fleet-enroll');
      onLog(`[${logTimestamp()}] [AUDIT] site "${site.name}" self-enrolled via token`);
      res.json({ ok: true, siteName: site.name });
    } catch (e) {
      loginThrottle.recordFailure(ip, 'fleet-enroll');
      res.status(400).json({ error: e.message });
    }
  });

  // Shared by /api/fleet/heartbeat and /api/fleet/backup -- both are edge-box-initiated,
  // authenticated by a signature over the JSON payload rather than a logged-in session.
  // Reuses the exact same parseKey/verify primitive tunnelServer.js already proved for
  // the SSH tunnel's own publickey auth -- one crypto path for all three.
  function verifyFleetRequest(publicKey, payload, signature) {
    const site = configStore.findSiteByPublicKey(publicKey);
    if (!site) return { site: null };
    let verified;
    try {
      const key = sshUtils.parseKey(site.publicKey);
      verified = key.verify(Buffer.from(payload, 'utf8'), Buffer.from(signature, 'base64'));
    } catch {
      verified = false;
    }
    return { site: verified === true ? site : null };
  }

  // Signs a queued command the same way an edge box signs its own heartbeat payload
  // upstream -- this direction previously had no equivalent: an edge acted on
  // {command, payload} straight off the HTTPS response body, trusting it purely because
  // the connection was HTTPS (with rejectUnauthorized: false, i.e. not even that). Since
  // sync-admins/restore-backup/apply-update/etc. all execute unattended and
  // sync-admins in particular accepts attacker-supplied {username, passwordSalt,
  // passwordHash} triples, anyone on-path between an edge box and the hub could push
  // themselves an admin account. Signing this response with the hub's own host key (the
  // same key an edge box can already pin as hubHostKeyFingerprint) closes that -- an
  // edge that has pinned the hub's key now verifies this signature before acting on
  // anything, mirroring the exact parseKey/verify primitive already used upstream.
  function signCommand(command, payload) {
    const commandPayload = JSON.stringify({ command, payload });
    const key = sshUtils.parseKey(hostKeyPrivate);
    const signature = key.sign(Buffer.from(commandPayload, 'utf8'));
    if (signature instanceof Error) throw signature;
    return { commandPayload, commandSignature: signature.toString('base64') };
  }

  app.post('/api/fleet/heartbeat', (req, res) => {
    const { publicKey, payload, signature } = req.body || {};
    if (!publicKey || !payload || !signature) {
      return res.status(400).json({ error: 'publicKey, payload, and signature are required' });
    }
    const { site } = verifyFleetRequest(publicKey, payload, signature);
    if (!site) return res.status(401).json({ error: 'unknown site or signature verification failed' });

    let data;
    try {
      data = JSON.parse(payload);
    } catch {
      return res.status(400).json({ error: 'payload was not valid JSON' });
    }
    configStore.recordHeartbeat(site.id, {
      version: data.version,
      ports: data.ports,
      sshEnabled: data.sshEnabled,
      webTerminalEnabled: data.webTerminalEnabled,
      adminsFingerprint: data.adminsFingerprint,
      tftp: data.tftp,
      hubKeyPinned: data.hubKeyPinned
    });
    const command = configStore.takePendingCommand(site.id);
    const { commandPayload, commandSignature } = signCommand(
      command ? command.command : null,
      command && command.payload !== undefined ? command.payload : null
    );
    res.json({ ok: true, commandPayload, commandSignature });
    // Fire-and-forget, after the response -- a heartbeat can report a changed port list
    // or version without any connect/disconnect happening, which is the only other thing
    // that currently pushes a live 'sites' update. Guarded on sseClients so an idle admin
    // UI (or none open at all) doesn't pay for sitesWithStatus() on every single
    // heartbeat, same guard the stats timer already uses.
    if (sseClients.size > 0) {
      sitesWithStatus().then((list) => broadcast('sites', list)).catch(() => {});
    }
  });

  // Edge box pushes its own config up in response to a queued "send-backup" command --
  // same signed-payload authentication as the heartbeat, since this is also
  // machine-to-machine, not a logged-in admin session.
  app.post('/api/fleet/backup', (req, res) => {
    const { publicKey, payload, signature } = req.body || {};
    if (!publicKey || !payload || !signature) {
      return res.status(400).json({ error: 'publicKey, payload, and signature are required' });
    }
    const { site } = verifyFleetRequest(publicKey, payload, signature);
    if (!site) return res.status(401).json({ error: 'unknown site or signature verification failed' });

    let data;
    try {
      data = JSON.parse(payload);
    } catch {
      return res.status(400).json({ error: 'payload was not valid JSON' });
    }
    configStore.recordSiteBackup(site.id, data.backup);
    onLog(`[${logTimestamp()}] [AUDIT] received a config backup from site "${site.name}"`);
    res.json({ ok: true });
  });

  // ---------- Console users (admin-managed accounts) ----------
  function userSummary(u) {
    return { id: u.id, username: u.username, groupIds: u.groupIds, captureEnabled: !!u.captureEnabled, createdAt: u.createdAt };
  }

  app.get('/api/users', requireFullAuth, (req, res) => res.json(configStore.listUsers().map(userSummary)));

  app.post('/api/users', requireFullAuth, (req, res) => {
    const { username, password, groupIds, captureEnabled } = req.body || {};
    if (!username || !username.trim()) return res.status(400).json({ error: 'a username is required' });
    const pwError = checkPassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    try {
      const user = configStore.createUser(username.trim(), password, groupIds, captureEnabled);
      audit(req, `created console user "${user.username}"`);
      res.json(userSummary(user));
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // Bulk-create console users from a CSV file (header row + username, password, groups
  // columns; groups is a semicolon- or comma-separated list of group names). Only ever
  // creates new accounts -- a row naming an existing username is skipped, not
  // overwritten, so a bad or re-run import can't silently reset someone's credentials.
  // Registered before the /api/users/:id routes below -- Express matches routes in
  // registration order, and :id would otherwise greedily match the literal "import".
  const usersImportUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });
  app.post('/api/users/import', requireFullAuth, (req, res) => {
    usersImportUpload.single('file')(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'no file provided' });

      let rows;
      try {
        rows = parseCsvObjects(req.file.buffer.toString('utf8'));
      } catch {
        return res.status(400).json({ error: 'could not parse that file as CSV' });
      }
      if (rows.length === 0) {
        return res.status(400).json({ error: 'no rows found -- the file needs a header row plus at least one data row' });
      }

      const existingUsernames = new Set(configStore.listUsers().map((u) => u.username.toLowerCase()));
      const seenInFile = new Set();
      const created = [];
      const skipped = [];

      rows.forEach((row, i) => {
        const rowNum = i + 2; // header is row 1
        const username = row.username;
        const fail = (reason) => skipped.push({ row: rowNum, username: username || '(blank)', reason });

        if (!username) return fail('missing username');
        const key = username.toLowerCase();
        if (existingUsernames.has(key)) return fail('username already exists');
        if (seenInFile.has(key)) return fail('duplicate username within this file');

        const password = row.password || '';
        const pwError = checkPassword(password);
        if (pwError) return fail(pwError);

        const groupNames = (row.groups || '').split(/[;,]/).map((g) => g.trim()).filter(Boolean);
        const groupIds = [];
        const unknownGroups = [];
        for (const name of groupNames) {
          const group = configStore.findGroupByName(name);
          if (group) groupIds.push(group.id);
          else unknownGroups.push(name);
        }

        const captureEnabled = ['1', 'true', 'yes'].includes((row.capture || '').toLowerCase());

        try {
          const user = configStore.createUser(username, password, groupIds, captureEnabled);
          seenInFile.add(key);
          created.push(
            unknownGroups.length ? `${user.username} (unknown group${unknownGroups.length === 1 ? '' : 's'} ignored: ${unknownGroups.join(', ')})` : user.username
          );
        } catch (e) {
          fail(e.message);
        }
      });

      audit(
        req,
        `bulk-imported ${created.length} user${created.length === 1 ? '' : 's'}${skipped.length ? ` (${skipped.length} skipped)` : ''} from a CSV file`
      );
      res.json({ created, skipped });
    });
  });

  app.post('/api/users/:id', requireFullAuth, (req, res) => {
    const { username, groupIds, captureEnabled } = req.body || {};
    try {
      const user = configStore.updateUser(req.params.id, { username, groupIds, captureEnabled });
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
    const { siteId, portId, permission } = req.body || {};
    if (!siteId || !portId) return res.status(400).json({ error: 'siteId and portId are required' });
    try {
      const group = configStore.addGrant(req.params.id, siteId, portId, permission);
      const site = configStore.findSiteById(siteId);
      const port = site && site.ports.find((p) => p.id === portId);
      audit(req, `granted "${site ? site.name : siteId} — ${port ? port.label : portId}" (${permission === 'read-only' ? 'read-only' : 'read-write'}) to group "${group.name}"`);
      res.json(group);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/api/groups/:id/grants/:siteId/:portId/permission', requireFullAuth, (req, res) => {
    const { permission } = req.body || {};
    if (!['read-write', 'read-only'].includes(permission)) {
      return res.status(400).json({ error: 'permission must be "read-write" or "read-only"' });
    }
    try {
      const group = configStore.updateGrantPermission(req.params.id, req.params.siteId, req.params.portId, permission);
      const site = configStore.findSiteById(req.params.siteId);
      const port = site && site.ports.find((p) => p.id === req.params.portId);
      audit(req, `set "${site ? site.name : req.params.siteId} — ${port ? port.label : req.params.portId}" to ${permission} for group "${group.name}"`);
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
      username: isAdmin ? (admin ? admin.username : null) : (consoleUser ? consoleUser.username : null),
      // Same synchronizer token as the admin session -- this is the SAME express-session
      // cookie/middleware, just a different logical "user" field on it, so the CSRF
      // middleware doesn't distinguish between the two.
      csrfToken: req.session.csrfToken
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
      loginSession(
        req,
        res,
        (session) => {
          session.consoleUser = { id: user.id, username: user.username };
        },
        (csrfToken) => {
          onLog(`[${logTimestamp()}] [AUDIT] "${user.username}" logged into the web terminal from ${ip}`);
          res.json({ ok: true, csrfToken });
        }
      );
      return;
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
    const choices = tunnelServer.visibleChoices(caller, isAdmin).map(({ site, port, permission }) => ({
      siteId: site.id,
      siteName: site.name,
      portId: port.id,
      label: port.label,
      permission
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

  // ---------- Syslog ----------
  app.get('/api/syslog', requireFullAuth, (req, res) => res.json(configStore.getConfig().syslog));

  app.post('/api/syslog', requireFullAuth, (req, res) => {
    const { enabled, host, port, facility } = req.body || {};
    const trimmedHost = String(host || '').trim();
    if (enabled && !trimmedHost) {
      return res.status(400).json({ error: 'a syslog server host is required to enable forwarding' });
    }
    const portNum = Number(port) || 514;
    if (portNum < 1 || portNum > 65535) {
      return res.status(400).json({ error: 'invalid port' });
    }
    const facilityNum = Number.isInteger(Number(facility)) ? Number(facility) : 16;
    const result = configStore.updateSyslog({ enabled: !!enabled, host: trimmedHost, port: portNum, facility: facilityNum });
    audit(req, `${enabled ? 'enabled' : 'disabled'} external syslog forwarding${trimmedHost ? ` (${trimmedHost}:${portNum})` : ''}`);
    res.json(result);
  });

  app.post('/api/syslog/test', requireFullAuth, (req, res) => {
    const syslog = configStore.getConfig().syslog;
    if (!syslog.host) return res.status(400).json({ error: 'set a syslog server host first' });
    syslogClient.send(syslog.host, syslog.port, syslog.facility, `[AUDIT] test message from ${os.hostname()}`);
    res.json({ ok: true });
  });

  // ---------- Log / live events ----------
  app.get('/api/log', requireFullAuth, (req, res) => res.json(logStore.getLines()));

  app.get('/api/log/download', requireFullAuth, (req, res) => {
    const filename = `central-office-log-${new Date().toISOString().slice(0, 10)}.txt`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(logStore.getLines().join('\n') + '\n');
  });

  app.get('/api/events', requireFullAuth, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write('\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
  });

  // ---------- Dashboard ----------
  app.get('/api/stats', requireFullAuth, async (req, res) => {
    const stats = await systemStats.getStats(configStore.DATA_DIR);
    res.json({ ...stats, clientsConnected: allSessions().length });
  });

  // ---------- System ----------
  app.get('/api/system/info', requireFullAuth, async (req, res) => {
    const [info, stats] = await Promise.all([
      Promise.resolve(systemInfo.getSystemInfo()),
      systemStats.getStats(configStore.DATA_DIR)
    ]);
    res.json({ ...info, appVersion: APP_VERSION, memory: stats.memory, disk: stats.disk, loadavg: stats.loadavg });
  });

  app.post('/api/system/hostname', requireFullAuth, async (req, res) => {
    const hostname = ((req.body && req.body.hostname) || '').trim();
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(hostname)) {
      return res.status(400).json({
        error: 'hostname must be 1-63 characters: letters, digits, and hyphens only, and cannot start or end with a hyphen'
      });
    }
    try {
      await systemControl.setHostname(hostname);
      audit(req, `changed the hostname to "${hostname}"`);
      res.json({ ok: true, hostname });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ---------- Network ----------
  app.get('/api/network', requireFullAuth, async (req, res) => {
    const [interfaces, publicIp, ntp, timezone] = await Promise.all([
      networkInfo.getInterfaces(),
      networkInfo.getPublicIp(),
      networkInfo.getNtpStatus(),
      networkInfo.getTimezone()
    ]);
    res.json({ interfaces, publicIp, ntp, timezone, dns: networkInfo.getDnsServers() });
  });

  app.get('/api/network/timezones', requireFullAuth, async (req, res) => {
    res.json(await networkInfo.listTimezones());
  });

  app.post('/api/network/ntp', requireFullAuth, async (req, res) => {
    const server = (req.body && req.body.server || '').trim();
    if (!server) return res.status(400).json({ error: 'ntp server is required' });
    try {
      await systemControl.setNtpServer(server);
      audit(req, `set the NTP server to "${server}"`);
      res.json({ ok: true, server });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/network/timezone', requireFullAuth, async (req, res) => {
    const timezone = (req.body && req.body.timezone || '').trim();
    if (!timezone) return res.status(400).json({ error: 'timezone is required' });
    try {
      await systemControl.setTimezone(timezone);
      audit(req, `set the timezone to "${timezone}"`);
      res.json({ ok: true, timezone });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/network/dns', requireFullAuth, async (req, res) => {
    const raw = (req.body && req.body.servers) || '';
    const servers = String(raw).split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    const invalid = servers.filter((s) => !networkInfo.isIpv4(s));
    if (invalid.length) {
      return res.status(400).json({ error: `not an IPv4 address: ${invalid.join(', ')}` });
    }
    try {
      await systemControl.setDns(servers);
      audit(req, servers.length ? `set DNS servers to ${servers.join(', ')}` : 'cleared the DNS override (back to DHCP-provided DNS)');
      res.json({ ok: true, servers });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Resolves a device name (eth0, ens3, ...) to its current NetworkManager connection
  // profile the same colon-escaping-aware way getInterfaces() already does, so the two
  // static-IP routes below don't duplicate that parsing.
  async function findConnectionForDevice(device) {
    const interfaces = await networkInfo.getInterfaces();
    const iface = interfaces.find((i) => i.name === device);
    return iface && iface.connection ? iface.connection : null;
  }

  app.get('/api/network/interfaces/:device/ip-config', requireFullAuth, async (req, res) => {
    const conn = await findConnectionForDevice(req.params.device);
    if (!conn) return res.status(404).json({ error: 'no active connection for that interface' });
    const config = await networkInfo.getIpConfig(conn);
    if (!config) return res.status(502).json({ error: 'could not read interface configuration' });
    res.json(config);
  });

  app.post('/api/network/interfaces/:device/ip', requireFullAuth, async (req, res) => {
    const { address, mask, gateway } = req.body || {};
    if (!networkInfo.isIpv4(address)) return res.status(400).json({ error: 'not a valid IPv4 address' });
    if (!networkInfo.isIpv4(gateway)) return res.status(400).json({ error: 'not a valid IPv4 gateway' });
    const prefix = networkInfo.maskToPrefix(mask);
    if (prefix === null) return res.status(400).json({ error: 'not a valid subnet mask (e.g. 255.255.255.0)' });
    const conn = await findConnectionForDevice(req.params.device);
    if (!conn) return res.status(404).json({ error: 'no active connection for that interface' });
    try {
      await systemControl.setStaticIp(conn, address, prefix, gateway);
      audit(req, `set a static IP (${address}/${prefix}, gateway ${gateway}) on "${req.params.device}"`);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/network/interfaces/:device/ip/clear', requireFullAuth, async (req, res) => {
    const conn = await findConnectionForDevice(req.params.device);
    if (!conn) return res.status(404).json({ error: 'no active connection for that interface' });
    try {
      await systemControl.clearStaticIp(conn);
      audit(req, `reverted "${req.params.device}" to DHCP`);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ---------- TFTP ----------
  app.get('/api/tftp-settings', requireFullAuth, (req, res) => res.json(configStore.getConfig().tftp));

  app.post('/api/tftp-settings', requireFullAuth, (req, res) => {
    const result = configStore.updateTftp(req.body || {});
    audit(req, 'updated TFTP settings');
    res.json(result);
  });

  app.get('/api/tftp/status', requireFullAuth, (req, res) => res.json({ running: tftpServer.isRunning() }));

  app.post('/api/tftp/start', requireFullAuth, (req, res) => {
    const tftp = configStore.getConfig().tftp;
    try {
      tftpServer.start(tftp.port, configStore.TFTP_ROOT_DIR, tftp.allowUpload);
      audit(req, 'started the TFTP server');
      res.json({ running: tftpServer.isRunning() });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/tftp/stop', requireFullAuth, (req, res) => {
    tftpServer.stop();
    audit(req, 'stopped the TFTP server');
    res.json({ running: tftpServer.isRunning() });
  });

  app.get('/api/tftp/files', requireFullAuth, (req, res) => {
    fs.mkdirSync(configStore.TFTP_ROOT_DIR, { recursive: true });
    fs.readdir(configStore.TFTP_ROOT_DIR, { withFileTypes: true }, (err, entries) => {
      if (err) return res.json([]);
      const files = entries
        .filter((e) => e.isFile())
        .map((e) => {
          const stat = fs.statSync(path.join(configStore.TFTP_ROOT_DIR, e.name));
          return { name: e.name, size: stat.size, modifiedAt: stat.mtime.toISOString() };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
      res.json(files);
    });
  });

  const tftpUpload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        fs.mkdirSync(configStore.TFTP_ROOT_DIR, { recursive: true });
        cb(null, configStore.TFTP_ROOT_DIR);
      },
      filename: (req, file, cb) => {
        try {
          cb(null, sanitizeTftpFilename(file.originalname));
        } catch (e) {
          cb(e);
        }
      }
    }),
    limits: { fileSize: 1024 * 1024 * 1024 }
  });

  app.post('/api/tftp/files', requireFullAuth, (req, res) => {
    tftpUpload.single('file')(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'no file provided' });
      audit(req, `uploaded TFTP file "${req.file.filename}"`);
      res.json({ ok: true, name: req.file.filename, size: req.file.size });
    });
  });

  app.get('/api/tftp/files/:name', requireFullAuth, (req, res) => {
    let name;
    try {
      name = sanitizeTftpFilename(req.params.name);
    } catch {
      return res.status(400).json({ error: 'invalid filename' });
    }
    res.download(path.join(configStore.TFTP_ROOT_DIR, name), name, (err) => {
      if (err && !res.headersSent) res.status(404).json({ error: 'not found' });
    });
  });

  app.delete('/api/tftp/files/:name', requireFullAuth, (req, res) => {
    let name;
    try {
      name = sanitizeTftpFilename(req.params.name);
    } catch {
      return res.status(400).json({ error: 'invalid filename' });
    }
    fs.unlink(path.join(configStore.TFTP_ROOT_DIR, name), (err) => {
      if (err) return res.status(404).json({ error: 'not found' });
      audit(req, `deleted TFTP file "${name}"`);
      res.json({ ok: true });
    });
  });

  // ---------- Session captures ----------
  app.get('/api/captures', requireFullAuth, (req, res) => res.json(sessionCapture.listCaptures()));

  app.get('/api/captures/:name', requireFullAuth, (req, res) => {
    let name;
    try {
      name = sessionCapture.sanitizeCaptureFilename(req.params.name);
    } catch {
      return res.status(400).json({ error: 'invalid filename' });
    }
    res.download(path.join(sessionCapture.CAPTURE_DIR, name), name, (err) => {
      if (err && !res.headersSent) res.status(404).json({ error: 'not found' });
    });
  });

  app.delete('/api/captures/:name', requireFullAuth, (req, res) => {
    let name;
    try {
      name = sessionCapture.sanitizeCaptureFilename(req.params.name);
    } catch {
      return res.status(400).json({ error: 'invalid filename' });
    }
    fs.unlink(path.join(sessionCapture.CAPTURE_DIR, name), (err) => {
      if (err) return res.status(404).json({ error: 'not found' });
      audit(req, `deleted session capture "${name}"`);
      res.json({ ok: true });
    });
  });

  // ---------- High availability (reads/drives the separate ha-agent process) ----------
  app.get('/api/ha/status', requireFullAuth, (req, res) => {
    try {
      res.json(JSON.parse(fs.readFileSync(HA_STATUS_PATH, 'utf8')));
    } catch {
      res.json({ configured: false });
    }
  });

  app.get('/api/ha/config', requireFullAuth, (req, res) => {
    try {
      res.json(JSON.parse(fs.readFileSync(HA_CONFIG_PATH, 'utf8')));
    } catch {
      res.json({ configured: false });
    }
  });

  app.post('/api/ha/config', requireFullAuth, (req, res) => {
    const { config, errors } = normalizeHaConfig(req.body);
    if (errors) return res.status(400).json({ error: errors.join('; ') });

    // The port the CURRENTLY RUNNING agent (if any) is actually bound to -- not the
    // possibly-just-edited listenPort in the new config, which it hasn't rebound to yet.
    let priorListenPort = null;
    try {
      priorListenPort = JSON.parse(fs.readFileSync(HA_CONFIG_PATH, 'utf8')).listenPort;
    } catch {
      priorListenPort = null;
    }

    try {
      fs.mkdirSync(HA_AGENT_DIR, { recursive: true });
      fs.writeFileSync(HA_CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
    } catch (e) {
      return res.status(500).json({ error: `could not write HA config: ${e.message}` });
    }
    audit(req, `updated HA configuration on this node (mode=${config.mode}, role=${config.role}, enabled=${config.enabled})`);

    // Best-effort: ask a running agent to reload live. If it's not running yet (fresh
    // setup, or its systemd service hasn't been started), the file is still saved
    // correctly for whenever it does start -- report that back rather than erroring.
    const notifyPort = priorListenPort || config.listenPort;
    const notifyReq = http.request(
      { host: '127.0.0.1', port: notifyPort, path: '/reload-config', method: 'POST', timeout: 5000 },
      (agentRes) => {
        agentRes.resume();
        res.json({ ok: true, config, agentNotified: agentRes.statusCode === 200 });
      }
    );
    notifyReq.on('error', () => res.json({ ok: true, config, agentNotified: false }));
    notifyReq.on('timeout', () => {
      notifyReq.destroy();
      res.json({ ok: true, config, agentNotified: false });
    });
    notifyReq.end();
  });

  app.post('/api/ha/promote', requireFullAuth, (req, res) => {
    let listenPort;
    try {
      listenPort = JSON.parse(fs.readFileSync(HA_CONFIG_PATH, 'utf8')).listenPort;
    } catch {
      return res.status(400).json({ error: 'HA is not configured on this node -- no ha-agent config found' });
    }
    const request = http.request(
      { host: '127.0.0.1', port: listenPort, path: '/promote', method: 'POST', timeout: 20000 },
      (agentRes) => {
        let data = '';
        agentRes.on('data', (chunk) => (data += chunk));
        agentRes.on('end', () => {
          let parsed;
          try {
            parsed = JSON.parse(data);
          } catch {
            parsed = null;
          }
          if (agentRes.statusCode !== 200) {
            return res.status(502).json({ error: (parsed && parsed.error) || 'promotion failed' });
          }
          audit(req, 'manually triggered HA promotion for this node');
          res.json({ ok: true });
        });
      }
    );
    request.on('error', (err) => res.status(502).json({ error: `could not reach the local HA agent: ${err.message}` }));
    request.on('timeout', () => request.destroy(new Error('timeout')));
    request.end();
  });

  // ---------- Docs (embedded as in-app help -- see the Help tab) ----------
  // These live at the repo root, not under webui/, so the static mount below doesn't
  // reach them -- served explicitly instead of moving/duplicating the files. Also mount
  // webui/ a second time at /webui -- the docs' own logo <img> uses the relative path
  // "webui/assets/logo.png" (correct when the file is opened straight off disk, where
  // webui/ is a direct subdirectory); serving these two files from the app's URL root
  // makes that same relative reference resolve to /webui/assets/logo.png, which only
  // this second mount, not the root one, actually answers.
  app.get('/HANDBOOK.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'HANDBOOK.html')));
  app.get('/QUICKSTART.html', (req, res) => res.sendFile(path.join(__dirname, '..', 'QUICKSTART.html')));
  app.use('/webui', express.static(path.join(__dirname, '..', 'webui')));

  // ---------- Static UI ----------
  app.use(express.static(path.join(__dirname, '..', 'webui')));

  function attachTerminalSocket(httpsServer) {
    webConsole.attach(httpsServer, sessionMiddleware);
  }

  return { app, attachTerminalSocket };
}

module.exports = { createWebServer };
