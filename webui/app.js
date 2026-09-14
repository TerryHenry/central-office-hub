'use strict';

const api = {
  async get(url) {
    const res = await fetch(url);
    if (!res.ok) throw await apiError(res);
    return res.json();
  },
  async post(url, body) {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    if (!res.ok) throw await apiError(res);
    return res.json();
  },
  async del(url) {
    const res = await fetch(url, { method: 'DELETE' });
    if (!res.ok) throw await apiError(res);
    return res.json();
  }
};

async function apiError(res) {
  try {
    const body = await res.json();
    return new Error(body.error || `HTTP ${res.status}`);
  } catch {
    return new Error(`HTTP ${res.status}`);
  }
}

function show(el) { el.classList.add('active'); }
function hide(el) { el.classList.remove('active'); }

function setFieldError(fieldId, message) {
  const errorEl = document.getElementById(`${fieldId}Error`);
  if (errorEl) errorEl.textContent = message;
  const inputEl = document.getElementById(fieldId);
  if (inputEl) inputEl.classList.toggle('invalid', !!message);
}
function clearFieldError(fieldId) { setFieldError(fieldId, ''); }

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const loginScreen = document.getElementById('loginScreen');
const totpScreen = document.getElementById('totpScreen');
const forceChangeScreen = document.getElementById('forceChangeScreen');
const appRoot = document.getElementById('appRoot');

// ---------- Password policy ----------
async function loadPasswordPolicy() {
  try {
    const policy = await api.get('/api/password-policy');
    const hintText = `(${policy.description})`;
    for (const id of ['forceChangePasswordHint', 'newAdminPasswordHint']) {
      const el = document.getElementById(id);
      if (el) el.textContent = hintText;
    }
    for (const id of ['forceChangePassword', 'forceChangePasswordConfirm', 'newAdminPassword', 'newAdminPasswordConfirm']) {
      const el = document.getElementById(id);
      if (el) el.minLength = policy.minLength;
    }
    document.getElementById('policyMinLength').value = policy.minLength;
    document.getElementById('policyRequireMixedCase').checked = policy.requireMixedCase;
    document.getElementById('policyRequireDigit').checked = policy.requireDigit;
    document.getElementById('policyRequireSymbol').checked = policy.requireSymbol;
    document.getElementById('policyCheckBreached').checked = policy.checkBreached;
  } catch {
    // hints just stay at their static fallback
  }
}

document.getElementById('savePasswordPolicyBtn').addEventListener('click', async () => {
  const msg = document.getElementById('passwordPolicyMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  try {
    await api.post('/api/password-policy', {
      minLength: Number(document.getElementById('policyMinLength').value),
      requireMixedCase: document.getElementById('policyRequireMixedCase').checked,
      requireDigit: document.getElementById('policyRequireDigit').checked,
      requireSymbol: document.getElementById('policyRequireSymbol').checked,
      checkBreached: document.getElementById('policyCheckBreached').checked
    });
    await loadPasswordPolicy();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Saved.';
  } catch (err) {
    msg.textContent = err.message;
  }
});

// ---------- Auth bootstrap ----------
async function boot() {
  await loadPasswordPolicy();
  const session = await api.get('/api/session');
  if (session.needsTotp) {
    show(totpScreen);
    document.body.classList.remove('app-mode');
    return;
  }
  if (!session.authenticated) {
    show(loginScreen);
    document.body.classList.remove('app-mode');
    return;
  }
  if (session.mustChangePassword) {
    show(forceChangeScreen);
    document.body.classList.remove('app-mode');
    return;
  }
  document.body.classList.add('app-mode');
  show(appRoot);
  await initApp();
}

// Shared by the password-only login and the post-2FA login -- both return the same
// { mustChangePassword } shape once the session is actually established.
async function completeLogin(result) {
  if (result.mustChangePassword) {
    show(forceChangeScreen);
    return;
  }
  document.body.classList.add('app-mode');
  show(appRoot);
  await initApp();
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('loginError');
  errorEl.textContent = '';
  try {
    const result = await api.post('/api/login', {
      username: document.getElementById('loginUsername').value.trim(),
      password: document.getElementById('loginPassword').value
    });
    hide(loginScreen);
    if (result.needsTotp) {
      document.getElementById('totpCode').value = '';
      show(totpScreen);
      return;
    }
    await completeLogin(result);
  } catch (err) {
    errorEl.textContent = 'Invalid username or password.';
  }
});

document.getElementById('totpForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('totpError');
  errorEl.textContent = '';
  try {
    const result = await api.post('/api/login-totp', { token: document.getElementById('totpCode').value.trim() });
    hide(totpScreen);
    await completeLogin(result);
  } catch (err) {
    errorEl.textContent = err.message === 'invalid_code' ? 'Wrong code. Try again.' : err.message;
    document.getElementById('totpCode').value = '';
    document.getElementById('totpCode').focus();
  }
});

document.getElementById('forceChangeForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('forceChangeError');
  errorEl.textContent = '';
  const password = document.getElementById('forceChangePassword').value;
  const confirmPassword = document.getElementById('forceChangePasswordConfirm').value;
  if (password !== confirmPassword) {
    errorEl.textContent = 'Passwords do not match.';
    return;
  }
  try {
    await api.post('/api/admin-password', { password });
    hide(forceChangeScreen);
    document.body.classList.add('app-mode');
    show(appRoot);
    await initApp();
  } catch (err) {
    errorEl.textContent = err.message;
  }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await api.post('/api/logout');
  window.location.reload();
});

// ---------- Tabs ----------
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach((c) => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

// ---------- Sites ----------
function statusPill(connected) {
  return connected
    ? '<span class="pill ok"><span class="dot"></span>Connected</span>'
    : '<span class="pill mute"><span class="dot"></span>Disconnected</span>';
}

async function loadSites() {
  const sites = await api.get('/api/sites');
  const tbody = document.querySelector('#sitesTable tbody');
  tbody.innerHTML = '';
  for (const site of sites) {
    const tr = document.createElement('tr');
    const portsList = site.ports.length
      ? site.ports.map((p) => `<div>${escapeHtml(p.label)} <code>${escapeHtml(p.id)}</code> <a href="#" data-site="${site.id}" data-port="${p.id}" class="del-port">remove</a></div>`).join('')
      : '<span class="hint">none yet</span>';
    const lastSeen = site.lastSeenAt ? new Date(site.lastSeenAt).toLocaleString() : '<span class="hint">never</span>';
    tr.innerHTML = `
      <td>${escapeHtml(site.name)}</td>
      <td>${statusPill(site.connected)}</td>
      <td>${site.reportedVersion ? escapeHtml(site.reportedVersion) : '<span class="hint">&mdash;</span>'}</td>
      <td>${lastSeen}</td>
      <td>${portsList}</td>
      <td></td>
    `;
    const actionsCell = tr.lastElementChild;
    const addPortBtn = document.createElement('button');
    addPortBtn.textContent = '+ Port';
    addPortBtn.addEventListener('click', () => openPortModal(site.id));
    const queueBtn = document.createElement('button');
    queueBtn.textContent = 'Queue Update';
    queueBtn.style.marginLeft = '6px';
    queueBtn.addEventListener('click', async () => {
      await api.post(`/api/sites/${site.id}/queue-update`);
      alert(`An update was queued for "${site.name}" -- it applies on the box's next heartbeat.`);
    });
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.className = 'danger';
    delBtn.style.marginLeft = '6px';
    delBtn.addEventListener('click', async () => {
      if (confirm(`Remove site "${site.name}"? This does not affect the edge box itself.`)) {
        await api.del(`/api/sites/${site.id}`);
        await loadSites();
      }
    });
    actionsCell.appendChild(addPortBtn);
    actionsCell.appendChild(queueBtn);
    actionsCell.appendChild(delBtn);
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('.del-port').forEach((a) => {
    a.addEventListener('click', async (e) => {
      e.preventDefault();
      await api.del(`/api/sites/${a.dataset.site}/ports/${a.dataset.port}`);
      await loadSites();
    });
  });
}

document.getElementById('addSiteBtn').addEventListener('click', () => {
  document.getElementById('siteName').value = '';
  document.getElementById('sitePublicKey').value = '';
  clearFieldError('siteName');
  clearFieldError('sitePublicKey');
  document.getElementById('siteModalBackdrop').classList.add('open');
});
document.getElementById('cancelSiteBtn').addEventListener('click', () => {
  document.getElementById('siteModalBackdrop').classList.remove('open');
});
document.getElementById('saveSiteBtn').addEventListener('click', async () => {
  const name = document.getElementById('siteName').value.trim();
  const publicKey = document.getElementById('sitePublicKey').value.trim();
  let valid = true;
  if (!name) { setFieldError('siteName', 'A site name is required.'); valid = false; }
  if (!publicKey) { setFieldError('sitePublicKey', 'A public key is required.'); valid = false; }
  if (!valid) return;
  try {
    await api.post('/api/sites', { name, publicKey });
    document.getElementById('siteModalBackdrop').classList.remove('open');
    await loadSites();
  } catch (err) {
    setFieldError('sitePublicKey', err.message);
  }
});

function openPortModal(siteId) {
  document.getElementById('portSiteId').value = siteId;
  document.getElementById('portIdInput').value = '';
  document.getElementById('portLabelInput').value = '';
  clearFieldError('portIdInput');
  clearFieldError('portLabelInput');
  document.getElementById('portModalBackdrop').classList.add('open');
}
document.getElementById('cancelPortBtn').addEventListener('click', () => {
  document.getElementById('portModalBackdrop').classList.remove('open');
});
document.getElementById('savePortBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('portSiteId').value;
  const portId = document.getElementById('portIdInput').value.trim();
  const label = document.getElementById('portLabelInput').value.trim();
  let valid = true;
  if (!portId) { setFieldError('portIdInput', 'A port id is required.'); valid = false; }
  if (!label) { setFieldError('portLabelInput', 'A label is required.'); valid = false; }
  if (!valid) return;
  try {
    await api.post(`/api/sites/${siteId}/ports`, { portId, label });
    document.getElementById('portModalBackdrop').classList.remove('open');
    await loadSites();
  } catch (err) {
    setFieldError('portIdInput', err.message);
  }
});

// ---------- Enrollment tokens ----------
async function loadTokens() {
  const tokens = await api.get('/api/enrollment-tokens');
  const tbody = document.querySelector('#tokensTable tbody');
  tbody.innerHTML = '';
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const expired = t.expiresAt && new Date(t.expiresAt).getTime() < Date.now();
    const status = t.used ? 'Used' : expired ? 'Expired' : 'Unused';
    tr.innerHTML = `
      <td>${escapeHtml(t.name)}</td>
      <td>${new Date(t.createdAt).toLocaleString()}</td>
      <td>${t.expiresAt ? new Date(t.expiresAt).toLocaleString() : '<span class="hint">never</span>'}</td>
      <td>${escapeHtml(status)}</td>
      <td></td>
    `;
    const actionsCell = tr.lastElementChild;
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Revoke';
    delBtn.className = 'danger';
    delBtn.addEventListener('click', async () => {
      await api.del(`/api/enrollment-tokens/${t.token}`);
      await loadTokens();
    });
    actionsCell.appendChild(delBtn);
    tbody.appendChild(tr);
  }
}

document.getElementById('addTokenBtn').addEventListener('click', () => {
  document.getElementById('tokenSiteName').value = '';
  document.getElementById('tokenExpiry').value = '';
  clearFieldError('tokenSiteName');
  document.getElementById('tokenModalBackdrop').classList.add('open');
});
document.getElementById('cancelTokenBtn').addEventListener('click', () => {
  document.getElementById('tokenModalBackdrop').classList.remove('open');
});
document.getElementById('saveTokenBtn').addEventListener('click', async () => {
  const name = document.getElementById('tokenSiteName').value.trim();
  const expiresInMinutes = document.getElementById('tokenExpiry').value.trim();
  if (!name) { setFieldError('tokenSiteName', 'A site name is required.'); return; }
  try {
    const token = await api.post('/api/enrollment-tokens', { name, expiresInMinutes: expiresInMinutes || undefined });
    document.getElementById('tokenModalBackdrop').classList.remove('open');
    document.getElementById('tokenRevealValue').textContent = token.token;
    document.getElementById('tokenRevealBackdrop').classList.add('open');
    await loadTokens();
  } catch (err) {
    setFieldError('tokenSiteName', err.message);
  }
});
document.getElementById('closeTokenRevealBtn').addEventListener('click', () => {
  document.getElementById('tokenRevealBackdrop').classList.remove('open');
});

// ---------- Users ----------
let allGroups = [];

async function loadUsers() {
  const users = await api.get('/api/users');
  const tbody = document.querySelector('#usersTable tbody');
  tbody.innerHTML = '';
  for (const user of users) {
    const tr = document.createElement('tr');
    const groupNames = user.groupIds
      .map((id) => allGroups.find((g) => g.id === id))
      .filter(Boolean)
      .map((g) => escapeHtml(g.name));
    tr.innerHTML = `
      <td>${escapeHtml(user.username)}</td>
      <td>${groupNames.length ? groupNames.join(', ') : '<span class="hint">none</span>'}</td>
      <td></td>
    `;
    const actionsCell = tr.lastElementChild;
    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.addEventListener('click', () => openUserModal(user));
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.className = 'danger';
    delBtn.style.marginLeft = '6px';
    delBtn.addEventListener('click', async () => {
      if (confirm(`Remove user "${user.username}"?`)) {
        await api.del(`/api/users/${user.id}`);
        await loadUsers();
      }
    });
    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(delBtn);
    tbody.appendChild(tr);
  }
}

function openUserModal(user) {
  document.getElementById('userModalTitle').textContent = user ? 'Edit User' : 'Add User';
  document.getElementById('userEditId').value = user ? user.id : '';
  document.getElementById('userUsername').value = user ? user.username : '';
  document.getElementById('userPassword').value = '';
  document.getElementById('userPasswordHint').textContent = user ? '(leave blank to keep the current password)' : '';
  document.getElementById('userPassword').required = !user;
  clearFieldError('userUsername');
  clearFieldError('userPassword');

  const checksEl = document.getElementById('userGroupChecks');
  checksEl.innerHTML = '';
  if (allGroups.length === 0) {
    checksEl.innerHTML = '<span class="hint">No groups yet &mdash; create one on the Groups tab first.</span>';
  }
  for (const group of allGroups) {
    const label = document.createElement('label');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = group.id;
    checkbox.checked = !!(user && user.groupIds.includes(group.id));
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(group.name));
    checksEl.appendChild(label);
  }
  document.getElementById('userModalBackdrop').classList.add('open');
}

document.getElementById('addUserBtn').addEventListener('click', () => openUserModal(null));
document.getElementById('cancelUserBtn').addEventListener('click', () => {
  document.getElementById('userModalBackdrop').classList.remove('open');
});
document.getElementById('saveUserBtn').addEventListener('click', async () => {
  const id = document.getElementById('userEditId').value;
  const username = document.getElementById('userUsername').value.trim();
  const password = document.getElementById('userPassword').value;
  const groupIds = Array.from(document.querySelectorAll('#userGroupChecks input:checked')).map((c) => c.value);
  let valid = true;
  if (!username) { setFieldError('userUsername', 'A username is required.'); valid = false; }
  if (!id && !password) { setFieldError('userPassword', 'A password is required.'); valid = false; }
  if (!valid) return;
  try {
    if (id) {
      await api.post(`/api/users/${id}`, { username, groupIds });
      if (password) await api.post(`/api/users/${id}/password`, { password });
    } else {
      await api.post('/api/users', { username, password, groupIds });
    }
    document.getElementById('userModalBackdrop').classList.remove('open');
    await loadUsers();
  } catch (err) {
    setFieldError('userPassword', err.message);
  }
});

// ---------- Groups ----------
async function loadGroups() {
  allGroups = await api.get('/api/groups');
  const tbody = document.querySelector('#groupsTable tbody');
  tbody.innerHTML = '';
  const sites = await api.get('/api/sites');
  for (const group of allGroups) {
    const tr = document.createElement('tr');
    const grantsEl = document.createElement('div');
    grantsEl.className = 'grant-list';
    if (group.grants.length === 0) {
      grantsEl.innerHTML = '<span class="hint">none yet</span>';
    }
    for (const grant of group.grants) {
      const site = sites.find((s) => s.id === grant.siteId);
      const port = site && site.ports.find((p) => p.id === grant.portId);
      const item = document.createElement('div');
      item.className = 'grant-item';
      item.innerHTML = `<span>${escapeHtml(site ? site.name : grant.siteId)} — ${escapeHtml(port ? port.label : grant.portId)}</span> <a href="#" class="remove">remove</a>`;
      item.querySelector('.remove').addEventListener('click', async (e) => {
        e.preventDefault();
        await api.del(`/api/groups/${group.id}/grants/${grant.siteId}/${grant.portId}`);
        await loadGroups();
      });
      grantsEl.appendChild(item);
    }
    tr.innerHTML = `<td>${escapeHtml(group.name)}</td><td></td><td></td>`;
    tr.children[1].appendChild(grantsEl);
    const actionsCell = tr.lastElementChild;
    const grantBtn = document.createElement('button');
    grantBtn.textContent = '+ Grant';
    grantBtn.addEventListener('click', () => openGrantModal(group.id, sites));
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.className = 'danger';
    delBtn.style.marginLeft = '6px';
    delBtn.addEventListener('click', async () => {
      if (confirm(`Remove group "${group.name}"? Members lose the access it granted.`)) {
        await api.del(`/api/groups/${group.id}`);
        await loadGroups();
        await loadUsers();
      }
    });
    actionsCell.appendChild(grantBtn);
    actionsCell.appendChild(delBtn);
    tbody.appendChild(tr);
  }
}

document.getElementById('addGroupBtn').addEventListener('click', () => {
  document.getElementById('groupName').value = '';
  clearFieldError('groupName');
  document.getElementById('groupModalBackdrop').classList.add('open');
});
document.getElementById('cancelGroupBtn').addEventListener('click', () => {
  document.getElementById('groupModalBackdrop').classList.remove('open');
});
document.getElementById('saveGroupBtn').addEventListener('click', async () => {
  const name = document.getElementById('groupName').value.trim();
  if (!name) { setFieldError('groupName', 'A group name is required.'); return; }
  try {
    await api.post('/api/groups', { name });
    document.getElementById('groupModalBackdrop').classList.remove('open');
    await loadGroups();
  } catch (err) {
    setFieldError('groupName', err.message);
  }
});

function openGrantModal(groupId, sites) {
  document.getElementById('grantGroupId').value = groupId;
  document.getElementById('grantError').textContent = '';
  const siteSelect = document.getElementById('grantSiteSelect');
  siteSelect.innerHTML = sites.map((s) => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('');
  const fillPorts = () => {
    const site = sites.find((s) => s.id === siteSelect.value);
    const portSelect = document.getElementById('grantPortSelect');
    portSelect.innerHTML = site
      ? site.ports.map((p) => `<option value="${p.id}">${escapeHtml(p.label)}</option>`).join('')
      : '';
  };
  siteSelect.onchange = fillPorts;
  fillPorts();
  document.getElementById('grantModalBackdrop').classList.add('open');
}
document.getElementById('cancelGrantBtn').addEventListener('click', () => {
  document.getElementById('grantModalBackdrop').classList.remove('open');
});
document.getElementById('saveGrantBtn').addEventListener('click', async () => {
  const groupId = document.getElementById('grantGroupId').value;
  const siteId = document.getElementById('grantSiteSelect').value;
  const portId = document.getElementById('grantPortSelect').value;
  if (!siteId || !portId) {
    document.getElementById('grantError').textContent = 'This site has no ports yet.';
    return;
  }
  try {
    await api.post(`/api/groups/${groupId}/grants`, { siteId, portId });
    document.getElementById('grantModalBackdrop').classList.remove('open');
    await loadGroups();
  } catch (err) {
    document.getElementById('grantError').textContent = err.message;
  }
});

// ---------- Sessions ----------
function renderSessions(sessions) {
  const tbody = document.querySelector('#sessionsTable tbody');
  tbody.innerHTML = '';
  for (const s of sessions) {
    const tr = document.createElement('tr');
    const since = new Date(s.connectedAt).toLocaleTimeString();
    tr.innerHTML = `
      <td>${escapeHtml(s.username)}</td>
      <td>${escapeHtml(s.site)} — ${escapeHtml(s.port)}</td>
      <td>${since}</td>
      <td></td>
    `;
    const actionsCell = tr.lastElementChild;
    const kickBtn = document.createElement('button');
    kickBtn.textContent = 'Disconnect';
    kickBtn.className = 'danger';
    kickBtn.addEventListener('click', async () => {
      await api.post(`/api/sessions/${s.id}/kick`);
    });
    actionsCell.appendChild(kickBtn);
    tbody.appendChild(tr);
  }
}

// ---------- Account ----------
async function loadMyUsername() {
  const session = await api.get('/api/session');
  document.getElementById('myUsername').textContent = session.username || '—';
}

document.getElementById('changeAdminPasswordBtn').addEventListener('click', async () => {
  const msg = document.getElementById('adminPasswordMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  const password = document.getElementById('newAdminPassword').value;
  const confirmPassword = document.getElementById('newAdminPasswordConfirm').value;
  if (password !== confirmPassword) {
    msg.textContent = 'Passwords do not match.';
    return;
  }
  try {
    await api.post('/api/admin-password', { password });
    document.getElementById('newAdminPassword').value = '';
    document.getElementById('newAdminPasswordConfirm').value = '';
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Password updated.';
  } catch (err) {
    msg.textContent = err.message;
  }
});

async function loadHostKeyFingerprint() {
  const { fingerprint } = await api.get('/api/host-key-fingerprint');
  document.getElementById('hostKeyFingerprint').textContent = fingerprint;
}

// ---------- Two-factor auth (My Account) ----------
function setTotpStatusUi(enabled) {
  const pill = document.getElementById('totpStatusPill');
  const text = document.getElementById('totpStatusText');
  pill.classList.toggle('running', enabled);
  text.textContent = enabled ? 'Enabled' : 'Disabled';
  document.getElementById('enableTotpBtn').hidden = enabled;
  document.getElementById('disableTotpBtn').hidden = !enabled;
  document.getElementById('totpSetupPanel').hidden = true;
  document.getElementById('totpDisablePanel').hidden = true;
}

async function loadTotpStatus() {
  const session = await api.get('/api/session');
  setTotpStatusUi(!!session.totpEnabled);
}

document.getElementById('enableTotpBtn').addEventListener('click', async () => {
  const msg = document.getElementById('totpSetupMsg');
  msg.textContent = '';
  try {
    const { secret, otpauthUrl } = await api.post('/api/admin-2fa/setup');
    document.getElementById('totpSecretText').textContent = secret;
    document.getElementById('totpConfirmCode').value = '';
    window.renderTotpQr(document.getElementById('totpQrContainer'), otpauthUrl);
    document.getElementById('totpSetupPanel').hidden = false;
    document.getElementById('totpDisablePanel').hidden = true;
  } catch (err) {
    msg.textContent = err.message;
  }
});

document.getElementById('cancelTotpSetupBtn').addEventListener('click', () => {
  document.getElementById('totpSetupPanel').hidden = true;
  document.getElementById('totpSetupMsg').textContent = '';
});

document.getElementById('confirmTotpBtn').addEventListener('click', async () => {
  const msg = document.getElementById('totpSetupMsg');
  msg.textContent = '';
  const token = document.getElementById('totpConfirmCode').value.trim();
  try {
    await api.post('/api/admin-2fa/confirm', { token });
    await loadTotpStatus();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Two-factor authentication is now enabled.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

document.getElementById('disableTotpBtn').addEventListener('click', () => {
  document.getElementById('totpDisableCode').value = '';
  document.getElementById('totpDisablePanel').hidden = false;
  document.getElementById('totpSetupPanel').hidden = true;
});

document.getElementById('cancelTotpDisableBtn').addEventListener('click', () => {
  document.getElementById('totpDisablePanel').hidden = true;
  document.getElementById('totpSetupMsg').textContent = '';
});

document.getElementById('confirmDisableTotpBtn').addEventListener('click', async () => {
  const msg = document.getElementById('totpSetupMsg');
  msg.textContent = '';
  const token = document.getElementById('totpDisableCode').value.trim();
  try {
    await api.post('/api/admin-2fa/disable', { token });
    await loadTotpStatus();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Two-factor authentication is now disabled.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

// ---------- Log / live events ----------
async function loadLogHistory() {
  const lines = await api.get('/api/log');
  const logView = document.getElementById('logView');
  logView.textContent = lines.length ? lines.join('\n') + '\n' : '';
  logView.scrollTop = logView.scrollHeight;
}

let eventSource = null;
function connectEvents() {
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/api/events');
  const logView = document.getElementById('logView');
  eventSource.addEventListener('log', (e) => {
    logView.textContent += JSON.parse(e.data) + '\n';
    logView.scrollTop = logView.scrollHeight;
  });
  eventSource.addEventListener('sessions', (e) => renderSessions(JSON.parse(e.data)));
  eventSource.addEventListener('sites', () => loadSites());
}

// ---------- Init ----------
async function initApp() {
  await loadSites();
  await loadTokens();
  await loadGroups();
  await loadUsers();
  await loadMyUsername();
  await loadTotpStatus();
  await loadHostKeyFingerprint();
  renderSessions(await api.get('/api/sessions'));
  await loadLogHistory();
  connectEvents();
}

boot();
