'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.CO_DATA_DIR || path.join(__dirname, '..', 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');

const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'letmein0!'; // same bootstrap convention as the appliance -- forced change on first login

const defaults = {
  web: { port: 8443 },
  ssh: { port: 2200 }, // one listener: end-user shells and edge-box tunnel registration alike
  admins: [],
  passwordPolicy: {
    minLength: 8,
    requireMixedCase: false,
    requireDigit: false,
    requireSymbol: false,
    checkBreached: true
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
  // an admin pasting its public key in by hand -- manual paste stays supported too.
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

function updatePasswordPolicy(partial) {
  state.passwordPolicy = { ...state.passwordPolicy, ...partial };
  persist();
  return state.passwordPolicy;
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

/** Applied by a fleet heartbeat: last-seen time, reported version, and reported ports all replace what's there -- whichever source (manual Add Port or a live heartbeat) touched a site most recently wins. */
function recordHeartbeat(siteId, { version, ports, sshEnabled, webTerminalEnabled, adminUsernames }) {
  const site = findSiteById(siteId);
  if (!site) throw new Error('site not found');
  site.lastSeenAt = new Date().toISOString();
  if (version) site.reportedVersion = version;
  if (Array.isArray(ports)) {
    site.ports = ports.map((p) => ({ id: p.id, label: p.label }));
  }
  // Older edge versions don't report these yet -- leave whatever's already there (or
  // undefined, meaning "unknown") rather than assuming a state it never actually sent.
  if (typeof sshEnabled === 'boolean') site.edgeSshEnabled = sshEnabled;
  if (typeof webTerminalEnabled === 'boolean') site.edgeWebTerminalEnabled = webTerminalEnabled;
  if (Array.isArray(adminUsernames)) site.reportedAdminUsernames = adminUsernames.slice().sort();
  persist();
  return site;
}

// ---------- Enrollment tokens ----------
function listEnrollmentTokens() {
  return state.enrollmentTokens;
}

function createEnrollmentToken(name, expiresInMinutes) {
  const token = {
    token: crypto.randomBytes(24).toString('hex'),
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

/** Redeems a token: creates the site it names and marks the token spent, atomically from the caller's point of view. */
function redeemEnrollmentToken(token, publicKey) {
  const entry = findUsableEnrollmentToken(token);
  if (!entry) throw new Error('that enrollment token is invalid, used, or expired');
  if (findSiteByPublicKey(publicKey)) throw new Error('that public key is already enrolled to a site');
  entry.used = true;
  const site = createSite(entry.name, publicKey);
  return site;
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

function createUser(username, password, groupIds) {
  if (findUserByUsername(username)) throw new Error('that username is already in use');
  const { salt, hash } = hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordSalt: salt,
    passwordHash: hash,
    groupIds: Array.isArray(groupIds) ? groupIds : [],
    createdAt: new Date().toISOString()
  };
  state.users.push(user);
  persist();
  return user;
}

function updateUser(id, { username, groupIds }) {
  const user = findUserById(id);
  if (!user) throw new Error('user not found');
  if (username && username !== user.username) {
    const existing = findUserByUsername(username);
    if (existing && existing.id !== id) throw new Error('that username is already in use');
    user.username = username;
  }
  if (Array.isArray(groupIds)) user.groupIds = groupIds;
  persist();
  return user;
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

function addGrant(groupId, siteId, portId) {
  const group = findGroupById(groupId);
  if (!group) throw new Error('group not found');
  if (group.grants.some((g) => g.siteId === siteId && g.portId === portId)) {
    throw new Error('that port is already granted to this group');
  }
  group.grants.push({ siteId, portId });
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
  for (const { siteId, portId } of grants) {
    if (group.grants.some((g) => g.siteId === siteId && g.portId === portId)) continue;
    group.grants.push({ siteId, portId });
    added++;
  }
  if (added > 0) persist();
  return { group, added };
}

function removeGrant(groupId, siteId, portId) {
  const group = findGroupById(groupId);
  if (!group) throw new Error('group not found');
  group.grants = group.grants.filter((g) => !(g.siteId === siteId && g.portId === portId));
  persist();
  return group;
}

/** Every (site, port) a user can reach, across all their groups -- the raw grant list, not filtered by connection state (callers filter that live). */
function grantsForUser(userId) {
  const user = findUserById(userId);
  if (!user) return [];
  const grants = [];
  const seen = new Set();
  for (const groupId of user.groupIds) {
    const group = findGroupById(groupId);
    if (!group) continue;
    for (const grant of group.grants) {
      const key = `${grant.siteId}:${grant.portId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      grants.push(grant);
    }
  }
  return grants;
}

module.exports = {
  DATA_DIR,
  DEFAULT_ADMIN_USERNAME,
  DEFAULT_ADMIN_PASSWORD,
  getConfig,
  importConfig,
  updatePasswordPolicy,
  listAdmins,
  findAdminByUsername,
  findAdminById,
  setAdminPassword,
  setAdminTotpPending,
  confirmAdminTotp,
  disableAdminTotp,
  listSites,
  findSiteById,
  findSiteByPublicKey,
  createSite,
  deleteSite,
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
  setUserPassword,
  deleteUser,
  listGroups,
  findGroupById,
  createGroup,
  renameGroup,
  deleteGroup,
  addGrant,
  addGrants,
  removeGrant,
  grantsForUser,
  hashPassword,
  verifyPassword
};
