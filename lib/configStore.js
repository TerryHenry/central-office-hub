'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.CO_DATA_DIR || path.join(__dirname, '..', 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const TFTP_ROOT_DIR = path.join(DATA_DIR, 'tftp');

const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'letmein0!'; // same bootstrap convention as the appliance -- forced change on first login

const defaults = {
  // idleTimeoutMinutes: admins are signed out after this many idle minutes; 0 disables it.
  web: { port: 8443, idleTimeoutMinutes: 5 },
  // One listener: end-user shells and edge-box tunnel registration alike. Defaults to
  // 443 (not a "real" HTTPS port here -- it's still the raw SSH tunnel protocol) since
  // an edge site's outbound firewall almost always already permits 443, avoiding a new
  // firewall rule for a nonstandard port at every site. Admin-configurable either way.
  ssh: { port: 443 },
  // Off by default -- forwarding the audit log to a syslog server is an opt-in choice
  // tied to a specific network destination, not something a freshly-provisioned hub
  // should do on its own. Same shape as the appliance's own syslog config.
  syslog: {
    enabled: false,
    host: '',
    port: 514,
    facility: 16 // local0 -- the conventional facility for a custom/embedded appliance
  },
  admins: [],
  passwordPolicy: {
    minLength: 8,
    requireMixedCase: false,
    requireDigit: false,
    requireSymbol: false,
    checkBreached: true,
    // Off by default, same as every other opt-in security control here. Unlike the
    // fields above, this one only ever applies to hub admin accounts (there's no
    // console-user or OS-account login on the hub the way there is on an appliance) --
    // it lives in this object anyway rather than a separate one, since it's still "a
    // requirement enforced at admin login" in the same spirit. Enforced in
    // webServer.js's requireFullAuth: an admin without 2FA set up while this is on can
    // still log in and reach exactly the routes needed to enable it (self, 2FA
    // setup/confirm), same carve-out mustChangePassword already gets.
    requireAdminTotp: false
  },
  tftp: {
    port: 69,
    allowUpload: true,
    autoStart: false
  },
  // Off by default -- an empty webhookUrl means nothing ever gets sent, same as syslog
  // above. Two independent toggles rather than one blanket on/off: a site dropping
  // offline is routine on a flaky WAN link and an admin might want that muted while
  // still hearing about a lockout, or the reverse.
  alerts: {
    webhookUrl: '',
    notifyOnSiteOffline: true,
    notifyOnLockout: true,
    // The rest are off until an admin opts in -- routine events that would be noisy by default.
    notifyOnSiteOnline: false,
    notifyOnAdminLogin: false,
    notifyOnLoginFailure: false,
    notifyOnEnrollment: false,
    notifyOnAudit: false
  },
  // A site's own ports[] are set entirely by its heartbeat (see recordHeartbeat) --
  // there's no manual add/remove; a box in managed mode reports its real configured
  // ports on its own schedule and the hub just reflects that.
  sites: [],
  // Console users: reach ports through group grants, never touch hub admin config.
  // Admins already see every connected site/port and don't need group membership.
  users: [],
  groups: [],
  // Enrollment tokens let an edge box join by itself (POST /api/fleet/enroll) instead of
  // an admin pasting its public key in by hand -- tokens are the only way to enroll now.
  enrollmentTokens: [],
  // One flat, single-delivery queue across every site -- no retry logic yet. A site pulls
  // (and removes) its own entry on its next heartbeat.
  pendingCommands: []
};

function newAdmin(username, password, mustChangePassword) {
  const { salt, hash } = hashPassword(password);
  return {
    id: crypto.randomUUID(),
    username,
    passwordSalt: salt,
    passwordHash: hash,
    mustChangePassword: !!mustChangePassword,
    totpEnabled: false,
    totpSecret: null,
    totpPendingSecret: null
  };
}

function mergeWithDefaults(raw) {
  return {
    web: { ...defaults.web, ...raw.web },
    ssh: { ...defaults.ssh, ...raw.ssh },
    admins: Array.isArray(raw.admins) ? raw.admins : [],
    passwordPolicy: { ...defaults.passwordPolicy, ...raw.passwordPolicy },
    syslog: { ...defaults.syslog, ...raw.syslog },
    tftp: { ...defaults.tftp, ...raw.tftp },
    alerts: { ...defaults.alerts, ...raw.alerts },
    sites: Array.isArray(raw.sites) ? raw.sites : [],
    users: Array.isArray(raw.users) ? raw.users : [],
    groups: Array.isArray(raw.groups) ? raw.groups : [],
    enrollmentTokens: Array.isArray(raw.enrollmentTokens) ? raw.enrollmentTokens : [],
    pendingCommands: Array.isArray(raw.pendingCommands) ? raw.pendingCommands : []
  };
}

function load() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(CONFIG_PATH)) {
    const seeded = JSON.parse(JSON.stringify(defaults));
    seeded.admins = [newAdmin(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, true)];
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(seeded, null, 2), { mode: 0o600 });
    return seeded;
  }
  const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  return mergeWithDefaults(raw);
}

let state = load();

function persist() {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(state, null, 2), { mode: 0o600 });
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** Replaces the entire current configuration with a backup file's contents -- run through
 * the same mergeWithDefaults() a normal load() uses, so a backup from an older version
 * missing newer fields (users/groups/enrollmentTokens/pendingCommands) doesn't crash. */
function importConfig(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('not a valid backup file');
  }
  state = mergeWithDefaults(raw);
  persist();
  return state;
}

function getConfig() {
  return state;
}

function updateWeb(partial) {
  state.web = { ...state.web, ...partial };
  persist();
  return state.web;
}

function updatePasswordPolicy(partial) {
  state.passwordPolicy = { ...state.passwordPolicy, ...partial };
  persist();
  return state.passwordPolicy;
}

/** Only ever takes effect on the next process start (server.js reads ssh.port once, at
 * startup, to bind tunnelServer) -- saving this just persists the new value. */
function updateSSH(partial) {
  state.ssh = { ...state.ssh, ...partial };
  persist();
  return state.ssh;
}

function updateTftp(partial) {
  state.tftp = { ...state.tftp, ...partial };
  persist();
  return state.tftp;
}

function updateSyslog(partial) {
  state.syslog = { ...state.syslog, ...partial };
  persist();
  return state.syslog;
}

function updateAlerts(partial) {
  state.alerts = { ...state.alerts, ...partial };
  persist();
  return state.alerts;
}

// ---------- Admin accounts ----------
function listAdmins() {
  return state.admins;
}

function findAdminByUsername(username) {
  return state.admins.find((a) => a.username === username);
}

function findAdminById(id) {
  return state.admins.find((a) => a.id === id);
}

function createAdmin(username, password) {
  if (findAdminByUsername(username)) {
    throw new Error('that username is already in use');
  }
  const admin = newAdmin(username, password, false);
  state.admins.push(admin);
  persist();
  return admin;
}

function renameAdmin(id, username) {
  const admin = findAdminById(id);
  if (!admin) throw new Error('admin account not found');
  const existing = findAdminByUsername(username);
  if (existing && existing.id !== id) throw new Error('that username is already in use');
  admin.username = username;
  persist();
  return admin;
}

function setAdminPassword(id, password) {
  const admin = findAdminById(id);
  if (!admin) throw new Error('admin account not found');
  const { salt, hash } = hashPassword(password);
  admin.passwordSalt = salt;
  admin.passwordHash = hash;
  admin.mustChangePassword = false;
  persist();
  return admin;
}

function deleteAdmin(id) {
  if (state.admins.length <= 1) {
    throw new Error('cannot delete the only remaining admin account');
  }
  state.admins = state.admins.filter((a) => a.id !== id);
  persist();
}

function recordAdminLogin(id) {
  const admin = findAdminById(id);
  if (!admin) return;
  admin.lastLoginAt = new Date().toISOString();
  persist();
}

// ---------- Admin two-factor auth (TOTP) ----------
// Two-step so a secret only takes effect once the admin has proven they can actually
// generate codes with it (scanned the QR into a real app) -- setAdminTotpPending stages
// it, confirmAdminTotp promotes it after a correct code is presented.
function setAdminTotpPending(id, secret) {
  const admin = findAdminById(id);
  if (!admin) throw new Error('admin account not found');
  admin.totpPendingSecret = secret;
  persist();
  return admin;
}

function confirmAdminTotp(id) {
  const admin = findAdminById(id);
  if (!admin) throw new Error('admin account not found');
  if (!admin.totpPendingSecret) throw new Error('no pending 2FA setup for this account');
  admin.totpSecret = admin.totpPendingSecret;
  admin.totpPendingSecret = null;
  admin.totpEnabled = true;
  persist();
  return admin;
}

function disableAdminTotp(id) {
  const admin = findAdminById(id);
  if (!admin) throw new Error('admin account not found');
  admin.totpEnabled = false;
  admin.totpSecret = null;
  admin.totpPendingSecret = null;
  persist();
  return admin;
}

// ---------- Sites ----------
function listSites() {
  return state.sites;
}

function findSiteById(id) {
  return state.sites.find((s) => s.id === id);
}

/** Matches a site by its enrolled public key -- how an incoming tunnel connection is identified. */
function findSiteByPublicKey(publicKey) {
  const normalized = String(publicKey).trim();
  return state.sites.find((s) => s.publicKey.trim() === normalized);
}

function createSite(name, publicKey) {
  const site = {
    id: crypto.randomUUID(),
    name,
    publicKey: String(publicKey).trim(),
    ports: [],
    createdAt: new Date().toISOString()
  };
  state.sites.push(site);
  persist();
  return site;
}

function deleteSite(id) {
  state.sites = state.sites.filter((s) => s.id !== id);
  persist();
}

function renameSite(id, name) {
  const site = findSiteById(id);
  if (!site) throw new Error('site not found');
  site.name = name;
  persist();
  return site;
}

/** Removes a single port from the hub's cached view of a site, and cleans up any group
 * grants that referenced it -- otherwise those would dangle forever, since
 * grantsForUser() never cross-checks a grant against a site's live port list.
 * This only ever edits the hub's own cache: per recordHeartbeat's comment above,
 * site.ports is entirely overwritten by whatever the site itself reports next. If the
 * site is still online and still configured with this port, its very next heartbeat
 * reports it again and it reappears here -- a caller that wants the removal to actually
 * stick queues a 'set-ports' command (with this port left out) alongside calling this,
 * the same way the existing "Configure Ports" save already does for a full replace. */
function removePort(siteId, portId) {
  const site = findSiteById(siteId);
  if (!site) throw new Error('site not found');
  const before = site.ports.length;
  site.ports = site.ports.filter((p) => p.id !== portId);
  if (site.ports.length === before) throw new Error('port not found');
  for (const group of state.groups) {
    group.grants = group.grants.filter((g) => !(g.siteId === siteId && g.portId === portId));
  }
  persist();
  return site;
}

/** Applied by a fleet heartbeat: last-seen time, reported version, and reported ports all replace what's there -- whichever source (manual Add Port or a live heartbeat) touched a site most recently wins. */
function recordHeartbeat(siteId, { version, ports, sshEnabled, webTerminalEnabled, adminsFingerprint, tftp, hubKeyPinned }) {
  const site = findSiteById(siteId);
  if (!site) throw new Error('site not found');
  site.lastSeenAt = new Date().toISOString();
  if (version) site.reportedVersion = version;
  if (Array.isArray(ports)) {
    // present: undefined means "unknown" (an older edge box that doesn't report this
    // yet), kept distinct from true/false rather than guessed -- the UI falls back to
    // the site's own connection state for those, same as before this field existed.
    // access: the port's own access mode (exclusive/shared-rw/first-write/shared-ro),
    // purely informational here -- the hub's own per-grant permission (see
    // grantsForUser) is what it actually enforces, since the appliance has no way to
    // tell which hub console user is on the other end of a forwarded connection.
    site.ports = ports.map((p) => ({
      id: p.id,
      label: p.label,
      present: typeof p.present === 'boolean' ? p.present : undefined,
      access: typeof p.access === 'string' ? p.access : undefined,
      // path/baudRate/captureEnabled: also just mirrored from the edge box's own config
      // (undefined for older edge versions that don't report them yet) -- carried along
      // so a hub admin can see and edit a complete picture via "Configure Ports" rather
      // than only the subset the topology diagram needs.
      path: typeof p.path === 'string' ? p.path : undefined,
      baudRate: typeof p.baudRate === 'number' ? p.baudRate : undefined,
      captureEnabled: typeof p.captureEnabled === 'boolean' ? p.captureEnabled : undefined
    }));
  }
  // Older edge versions don't report these yet -- leave whatever's already there (or
  // undefined, meaning "unknown") rather than assuming a state it never actually sent.
  if (typeof sshEnabled === 'boolean') site.edgeSshEnabled = sshEnabled;
  if (typeof webTerminalEnabled === 'boolean') site.edgeWebTerminalEnabled = webTerminalEnabled;
  if (typeof adminsFingerprint === 'string') site.reportedAdminsFingerprint = adminsFingerprint;
  // Older edge versions don't report this yet -- undefined (not false) means "unknown",
  // same convention as the other optional heartbeat fields above.
  if (typeof hubKeyPinned === 'boolean') site.hubKeyPinned = hubKeyPinned;
  if (tftp && typeof tftp === 'object') {
    site.reportedTftp = {
      running: !!tftp.running,
      port: typeof tftp.port === 'number' ? tftp.port : undefined,
      allowUpload: !!tftp.allowUpload,
      autoStart: !!tftp.autoStart
    };
  }
  persist();
  return site;
}

// ---------- Enrollment tokens ----------
function listEnrollmentTokens() {
  return state.enrollmentTokens;
}

// siteId (optional) makes this a re-enrollment token: redeeming it re-keys that existing site
// (a replacement box takes over its ports, grants and settings) instead of creating a new one.
function createEnrollmentToken(name, expiresInMinutes, siteId) {
  const token = {
    token: crypto.randomBytes(24).toString('hex'),
    ...(siteId ? { siteId } : {}),
    name,
    createdAt: new Date().toISOString(),
    expiresAt: expiresInMinutes ? new Date(Date.now() + expiresInMinutes * 60000).toISOString() : null,
    used: false
  };
  state.enrollmentTokens.push(token);
  persist();
  return token;
}

function deleteEnrollmentToken(token) {
  state.enrollmentTokens = state.enrollmentTokens.filter((t) => t.token !== token);
  persist();
}

/** A token is usable once, and only before it expires -- checked here so every caller (enroll route) gets the same rule. */
function findUsableEnrollmentToken(token) {
  const entry = state.enrollmentTokens.find((t) => t.token === token);
  if (!entry || entry.used) return null;
  if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) return null;
  return entry;
}

/** Redeems a token: creates the site it names (or, for a re-enrollment token, re-keys the existing one) and marks the token spent. Returns {site, reenrolled}. */
function redeemEnrollmentToken(token, publicKey) {
  const entry = findUsableEnrollmentToken(token);
  if (!entry) throw new Error('that enrollment token is invalid, used, or expired');
  const existing = findSiteByPublicKey(publicKey);
  if (entry.siteId) {
    const site = findSiteById(entry.siteId);
    if (!site) throw new Error('the site this token was issued for no longer exists');
    if (existing && existing.id !== site.id) throw new Error('that public key is already enrolled to a different site');
    entry.used = true;
    site.publicKey = String(publicKey).trim();
    persist();
    return { site, reenrolled: true };
  }
  if (existing) throw new Error('that public key is already enrolled to a site');
  entry.used = true;
  return { site: createSite(entry.name, publicKey), reenrolled: false };
}

// ---------- Pending commands ----------
function queueCommand(siteId, command, payload) {
  if (!findSiteById(siteId)) throw new Error('site not found');
  const entry = { siteId, command, queuedAt: new Date().toISOString() };
  if (payload !== undefined) entry.payload = payload;
  state.pendingCommands.push(entry);
  persist();
}

/** Bulk version for "queue an update for some/all sites at once" -- skips any site id
 * that doesn't exist rather than failing the whole batch. */
function queueCommands(siteIds, command, payload) {
  let queued = 0;
  for (const siteId of siteIds) {
    if (!findSiteById(siteId)) continue;
    const entry = { siteId, command, queuedAt: new Date().toISOString() };
    if (payload !== undefined) entry.payload = payload;
    state.pendingCommands.push(entry);
    queued++;
  }
  if (queued > 0) persist();
  return queued;
}

function listPendingCommands() {
  return state.pendingCommands;
}

/** Single delivery: removes and returns this site's next queued command, if any. */
function takePendingCommand(siteId) {
  const idx = state.pendingCommands.findIndex((c) => c.siteId === siteId);
  if (idx === -1) return null;
  const [entry] = state.pendingCommands.splice(idx, 1);
  persist();
  return entry;
}

/** Stores the most recent backup an edge box sent up, one per site (mirrors the
 * self-update mechanism's "one level of undo" -- no history, just the latest). */
function recordSiteBackup(siteId, data) {
  const site = findSiteById(siteId);
  if (!site) throw new Error('site not found');
  site.lastBackup = { takenAt: new Date().toISOString(), data };
  persist();
  return site.lastBackup;
}

// ---------- Console users ----------
function listUsers() {
  return state.users;
}

function findUserById(id) {
  return state.users.find((u) => u.id === id);
}

function findUserByUsername(username) {
  return state.users.find((u) => u.username === username);
}

function normalizeEdgePermission(permission) {
  return permission === 'read-only' ? 'read-only' : 'read-write';
}

function createUser(username, password, groupIds, captureEnabled, edgeSiteIds, edgePermission) {
  if (findUserByUsername(username)) throw new Error('that username is already in use');
  const { salt, hash } = hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordSalt: salt,
    passwordHash: hash,
    groupIds: Array.isArray(groupIds) ? groupIds : [],
    captureEnabled: !!captureEnabled,
    // Sites this account is explicitly pushed to as a local login (beyond any site it
    // already reaches through group grants) -- see usersForSiteSync().
    edgeSiteIds: Array.isArray(edgeSiteIds) ? edgeSiteIds : [],
    edgePermission: normalizeEdgePermission(edgePermission),
    createdAt: new Date().toISOString()
  };
  state.users.push(user);
  persist();
  return user;
}

function updateUser(id, { username, groupIds, captureEnabled, edgeSiteIds, edgePermission }) {
  const user = findUserById(id);
  if (!user) throw new Error('user not found');
  if (username && username !== user.username) {
    const existing = findUserByUsername(username);
    if (existing && existing.id !== id) throw new Error('that username is already in use');
    user.username = username;
  }
  if (Array.isArray(groupIds)) user.groupIds = groupIds;
  if (typeof captureEnabled === 'boolean') user.captureEnabled = captureEnabled;
  if (Array.isArray(edgeSiteIds)) user.edgeSiteIds = edgeSiteIds;
  if (edgePermission !== undefined) user.edgePermission = normalizeEdgePermission(edgePermission);
  persist();
  return user;
}

/** The local logins a given site should carry, for a fleet "sync-users" command: every
 * hub user who either holds a grant on one of that site's ports (permission derived from
 * those grants -- read-write if any of them writes) or was explicitly pushed to the site
 * (edgeSiteIds, at edgePermission). Edge boxes don't have per-port user permissions, so
 * this is deliberately NOT "every hub user everywhere": a user with no reach into a site
 * never gets a login there. Already-hashed credentials only -- no plaintext exists here. */
function usersForSiteSync(siteId) {
  const out = [];
  for (const user of state.users) {
    const grants = grantsForUser(user.id).filter((g) => g.siteId === siteId);
    const pushed = Array.isArray(user.edgeSiteIds) && user.edgeSiteIds.includes(siteId);
    if (grants.length === 0 && !pushed) continue;
    const canWrite = grants.some((g) => g.permission === 'read-write') || (pushed && normalizeEdgePermission(user.edgePermission) === 'read-write');
    out.push({
      username: user.username,
      passwordSalt: user.passwordSalt,
      passwordHash: user.passwordHash,
      permission: canWrite ? 'read-write' : 'read-only',
      captureEnabled: !!user.captureEnabled
    });
  }
  return out;
}

function setUserPassword(id, password) {
  const user = findUserById(id);
  if (!user) throw new Error('user not found');
  const { salt, hash } = hashPassword(password);
  user.passwordSalt = salt;
  user.passwordHash = hash;
  persist();
  return user;
}

function deleteUser(id) {
  state.users = state.users.filter((u) => u.id !== id);
  persist();
}

// ---------- Groups ----------
function listGroups() {
  return state.groups;
}

function findGroupById(id) {
  return state.groups.find((g) => g.id === id);
}

/** Case-insensitive: "Students" and "students" would be just as confusing to an admin
 * picking from a list as an exact duplicate. */
function findGroupByName(name) {
  const normalized = String(name).trim().toLowerCase();
  return state.groups.find((g) => g.name.trim().toLowerCase() === normalized);
}

function createGroup(name) {
  if (findGroupByName(name)) throw new Error('a group with that name already exists');
  const group = { id: crypto.randomUUID(), name, grants: [], createdAt: new Date().toISOString() };
  state.groups.push(group);
  persist();
  return group;
}

function renameGroup(id, name) {
  const group = findGroupById(id);
  if (!group) throw new Error('group not found');
  const existing = findGroupByName(name);
  if (existing && existing.id !== id) throw new Error('a group with that name already exists');
  group.name = name;
  persist();
  return group;
}

function deleteGroup(id) {
  state.groups = state.groups.filter((g) => g.id !== id);
  // Dangling membership would otherwise silently grant nothing forever -- clean it up
  // rather than leave every user pointing at a group id that no longer resolves.
  for (const user of state.users) {
    user.groupIds = user.groupIds.filter((gid) => gid !== id);
  }
  persist();
}

/** Grants default to read-write (matches behavior before per-grant permission existed,
 * so upgrading doesn't silently lock anyone out) -- 'read-only' is the only other
 * accepted value, anything else normalizes to 'read-write' rather than erroring. */
function normalizeGrantPermission(permission) {
  return permission === 'read-only' ? 'read-only' : 'read-write';
}

function addGrant(groupId, siteId, portId, permission) {
  const group = findGroupById(groupId);
  if (!group) throw new Error('group not found');
  if (group.grants.some((g) => g.siteId === siteId && g.portId === portId)) {
    throw new Error('that port is already granted to this group');
  }
  group.grants.push({ siteId, portId, permission: normalizeGrantPermission(permission) });
  persist();
  return group;
}

/** Bulk version for "grant all ports in a site" / "grant every site" -- silently skips
 * any pair already granted rather than erroring, since a bulk selection commonly
 * overlaps with existing grants. */
function addGrants(groupId, grants) {
  const group = findGroupById(groupId);
  if (!group) throw new Error('group not found');
  let added = 0;
  for (const { siteId, portId, permission } of grants) {
    if (group.grants.some((g) => g.siteId === siteId && g.portId === portId)) continue;
    group.grants.push({ siteId, portId, permission: normalizeGrantPermission(permission) });
    added++;
  }
  if (added > 0) persist();
  return { group, added };
}

/** Changes an existing grant's permission without touching whether it exists at all --
 * a separate action from add/remove, so a grant's read-only/read-write level can be
 * adjusted without an admin having to revoke and re-add it. */
function updateGrantPermission(groupId, siteId, portId, permission) {
  const group = findGroupById(groupId);
  if (!group) throw new Error('group not found');
  const grant = group.grants.find((g) => g.siteId === siteId && g.portId === portId);
  if (!grant) throw new Error('grant not found');
  grant.permission = normalizeGrantPermission(permission);
  persist();
  return group;
}

function removeGrant(groupId, siteId, portId) {
  const group = findGroupById(groupId);
  if (!group) throw new Error('group not found');
  group.grants = group.grants.filter((g) => !(g.siteId === siteId && g.portId === portId));
  persist();
  return group;
}

/** Every (site, port) a user can reach, across all their groups, with the *effective*
 * permission for each -- the raw grant list, not filtered by connection state (callers
 * filter that live). When more than one of a user's groups grants the same port with
 * different permissions, the most permissive one wins (read-write beats read-only) --
 * same union semantics as visibility itself: any path that grants write is enough. */
function grantsForUser(userId) {
  const user = findUserById(userId);
  if (!user) return [];
  const byKey = new Map();
  for (const groupId of user.groupIds) {
    const group = findGroupById(groupId);
    if (!group) continue;
    for (const grant of group.grants) {
      const key = `${grant.siteId}:${grant.portId}`;
      const permission = normalizeGrantPermission(grant.permission);
      const existing = byKey.get(key);
      if (existing && (existing.permission === 'read-write' || permission === 'read-only')) continue;
      byKey.set(key, { siteId: grant.siteId, portId: grant.portId, permission });
    }
  }
  return Array.from(byKey.values());
}

module.exports = {
  DATA_DIR,
  TFTP_ROOT_DIR,
  DEFAULT_ADMIN_USERNAME,
  DEFAULT_ADMIN_PASSWORD,
  getConfig,
  importConfig,
  updatePasswordPolicy,
  updateWeb,
  updateSSH,
  updateTftp,
  updateSyslog,
  updateAlerts,
  listAdmins,
  findAdminByUsername,
  findAdminById,
  createAdmin,
  renameAdmin,
  setAdminPassword,
  deleteAdmin,
  recordAdminLogin,
  setAdminTotpPending,
  confirmAdminTotp,
  disableAdminTotp,
  listSites,
  findSiteById,
  findSiteByPublicKey,
  deleteSite,
  renameSite,
  removePort,
  recordHeartbeat,
  listEnrollmentTokens,
  createEnrollmentToken,
  deleteEnrollmentToken,
  findUsableEnrollmentToken,
  redeemEnrollmentToken,
  queueCommand,
  queueCommands,
  listPendingCommands,
  takePendingCommand,
  recordSiteBackup,
  listUsers,
  findUserById,
  findUserByUsername,
  createUser,
  updateUser,
  usersForSiteSync,
  setUserPassword,
  deleteUser,
  listGroups,
  findGroupById,
  createGroup,
  renameGroup,
  deleteGroup,
  findGroupByName,
  addGrant,
  addGrants,
  updateGrantPermission,
  removeGrant,
  grantsForUser,
  hashPassword,
  verifyPassword
};
