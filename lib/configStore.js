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
  // Phase 1: one site, one port, entered by hand. Ports aren't reported by the edge box
  // yet (that's fleet inventory, a later phase) -- the id here just has to match the id
  // of a real port already configured on that edge box.
  sites: [],
  // Console users: reach ports through group grants, never touch hub admin config.
  // Admins already see every connected site/port and don't need group membership.
  users: [],
  groups: []
};

function newAdmin(username, password, mustChangePassword) {
  const { salt, hash } = hashPassword(password);
  return {
    id: crypto.randomUUID(),
    username,
    passwordSalt: salt,
    passwordHash: hash,
    mustChangePassword: !!mustChangePassword
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
    groups: Array.isArray(raw.groups) ? raw.groups : []
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

function addPort(siteId, portId, label) {
  const site = findSiteById(siteId);
  if (!site) throw new Error('site not found');
  if (site.ports.some((p) => p.id === portId)) throw new Error('a port with that id already exists on this site');
  site.ports.push({ id: portId, label });
  persist();
  return site;
}

function deletePort(siteId, portId) {
  const site = findSiteById(siteId);
  if (!site) throw new Error('site not found');
  site.ports = site.ports.filter((p) => p.id !== portId);
  persist();
  return site;
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

function createGroup(name) {
  const group = { id: crypto.randomUUID(), name, grants: [], createdAt: new Date().toISOString() };
  state.groups.push(group);
  persist();
  return group;
}

function renameGroup(id, name) {
  const group = findGroupById(id);
  if (!group) throw new Error('group not found');
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
  updatePasswordPolicy,
  listAdmins,
  findAdminByUsername,
  findAdminById,
  setAdminPassword,
  listSites,
  findSiteById,
  findSiteByPublicKey,
  createSite,
  deleteSite,
  addPort,
  deletePort,
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
  removeGrant,
  grantsForUser,
  hashPassword,
  verifyPassword
};
