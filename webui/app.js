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
  document.getElementById('sitesSelectAll').checked = false;
  for (const site of sites) {
    const tr = document.createElement('tr');
    const portsList = site.ports.length
      ? site.ports.map((p) => `<div>${escapeHtml(p.label)} <code>${escapeHtml(p.id)}</code> <a href="#" data-site="${site.id}" data-port="${p.id}" class="del-port">remove</a></div>`).join('')
      : '<span class="hint">none yet</span>';
    const lastSeen = site.lastSeenAt ? new Date(site.lastSeenAt).toLocaleString() : '<span class="hint">never</span>';
    const backupInfo = site.lastBackup
      ? `<span class="hint">${new Date(site.lastBackup.takenAt).toLocaleDateString()}</span>`
      : '<span class="hint">none yet</span>';
    tr.innerHTML = `
      <td><input type="checkbox" class="site-select" data-site="${site.id}" /></td>
      <td>${escapeHtml(site.name)}</td>
      <td>${statusPill(site.connected)}</td>
      <td>${site.reportedVersion ? escapeHtml(site.reportedVersion) : '<span class="hint">&mdash;</span>'}</td>
      <td>${lastSeen}</td>
      <td>${backupInfo}</td>
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
    const requestBackupBtn = document.createElement('button');
    requestBackupBtn.textContent = 'Request Backup';
    requestBackupBtn.style.marginLeft = '6px';
    requestBackupBtn.addEventListener('click', async () => {
      await api.post(`/api/sites/${site.id}/backup/request`);
      alert(`A config backup was requested from "${site.name}" -- it's sent on the box's next heartbeat.`);
    });
    actionsCell.appendChild(addPortBtn);
    actionsCell.appendChild(queueBtn);
    actionsCell.appendChild(requestBackupBtn);
    if (site.lastBackup) {
      const downloadBackupBtn = document.createElement('button');
      downloadBackupBtn.textContent = 'Download Backup';
      downloadBackupBtn.style.marginLeft = '6px';
      downloadBackupBtn.addEventListener('click', () => {
        window.location.href = `/api/sites/${site.id}/backup`;
      });
      actionsCell.appendChild(downloadBackupBtn);
    }
    const restoreBtn = document.createElement('button');
    restoreBtn.textContent = 'Restore Backup';
    restoreBtn.style.marginLeft = '6px';
    restoreBtn.addEventListener('click', () => openSiteRestoreModal(site));
    actionsCell.appendChild(restoreBtn);
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

document.getElementById('sitesSelectAll').addEventListener('change', (e) => {
  document.querySelectorAll('#sitesTable .site-select').forEach((cb) => (cb.checked = e.target.checked));
});

document.getElementById('bulkQueueUpdateBtn').addEventListener('click', async () => {
  const siteIds = Array.from(document.querySelectorAll('#sitesTable .site-select:checked')).map((cb) => cb.dataset.site);
  if (siteIds.length === 0) {
    alert('Select at least one site first.');
    return;
  }
  if (!confirm(`Queue an update for ${siteIds.length} site${siteIds.length === 1 ? '' : 's'}? Each applies on its own next heartbeat.`)) return;
  const result = await api.post('/api/sites/queue-update/bulk', { siteIds });
  alert(`Queued an update for ${result.queued} site${result.queued === 1 ? '' : 's'}.`);
});

function openSiteRestoreModal(site) {
  document.getElementById('siteRestoreSiteId').value = site.id;
  document.getElementById('siteRestoreSiteName').textContent = site.name;
  document.getElementById('siteRestoreFile').value = '';
  document.getElementById('siteRestoreError').textContent = '';
  const storedRow = document.getElementById('siteRestoreStoredRow');
  if (site.lastBackup) {
    storedRow.style.display = '';
    document.getElementById('siteRestoreStoredInfo').textContent =
      `Taken ${new Date(site.lastBackup.takenAt).toLocaleString()} -- no upload needed, the hub already has this.`;
  } else {
    storedRow.style.display = 'none';
  }
  document.getElementById('siteRestoreModalBackdrop').classList.add('open');
}
document.getElementById('cancelSiteRestoreBtn').addEventListener('click', () => {
  document.getElementById('siteRestoreModalBackdrop').classList.remove('open');
});
document.getElementById('saveSiteRestoreStoredBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('siteRestoreSiteId').value;
  const errEl = document.getElementById('siteRestoreError');
  if (!confirm('Restore this site\'s own last stored backup? This replaces its entire configuration the next time it heartbeats. Continue?')) return;
  try {
    await api.post(`/api/sites/${siteId}/backup/restore-stored`);
    document.getElementById('siteRestoreModalBackdrop').classList.remove('open');
    alert('Restore queued -- it applies on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});
document.getElementById('saveSiteRestoreBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('siteRestoreSiteId').value;
  const fileInput = document.getElementById('siteRestoreFile');
  const file = fileInput.files[0];
  const errEl = document.getElementById('siteRestoreError');
  if (!file) {
    errEl.textContent = 'Choose a backup file first.';
    return;
  }
  if (!confirm('This replaces the entire configuration on that edge box the next time it heartbeats. Continue?')) return;
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch(`/api/sites/${siteId}/backup/restore`, { method: 'POST', body: formData });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    document.getElementById('siteRestoreModalBackdrop').classList.remove('open');
    alert('Restore queued -- it applies on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});

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
    grantBtn.addEventListener('click', () => openGrantModal(group, sites));
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

function openGrantModal(group, sites) {
  document.getElementById('grantGroupId').value = group.id;
  document.getElementById('grantError').textContent = '';
  document.getElementById('grantSelectAllSites').checked = false;

  const tree = document.getElementById('grantSiteTree');
  tree.innerHTML = '';
  if (sites.length === 0) {
    tree.innerHTML = '<span class="hint">No sites enrolled yet.</span>';
  }
  const isGranted = (siteId, portId) => group.grants.some((g) => g.siteId === siteId && g.portId === portId);

  for (const site of sites) {
    const block = document.createElement('div');
    block.className = 'grant-site-block';

    const siteLabel = document.createElement('label');
    const siteCheck = document.createElement('input');
    siteCheck.type = 'checkbox';
    siteCheck.className = 'grant-site-check';
    siteCheck.dataset.site = site.id;
    siteLabel.appendChild(siteCheck);
    siteLabel.appendChild(document.createTextNode(site.name));
    block.appendChild(siteLabel);

    const portsEl = document.createElement('div');
    portsEl.className = 'grant-ports';
    if (site.ports.length === 0) {
      portsEl.innerHTML = '<span class="hint">no ports yet</span>';
    }
    const portChecks = [];
    for (const port of site.ports) {
      const portLabel = document.createElement('label');
      const portCheck = document.createElement('input');
      portCheck.type = 'checkbox';
      portCheck.className = 'grant-port-check';
      portCheck.dataset.site = site.id;
      portCheck.dataset.port = port.id;
      if (isGranted(site.id, port.id)) {
        portCheck.checked = true;
        portCheck.disabled = true;
        portLabel.title = 'Already granted';
      }
      portChecks.push(portCheck);
      portLabel.appendChild(portCheck);
      portLabel.appendChild(document.createTextNode(`${port.label}${portCheck.disabled ? ' (already granted)' : ''}`));
      portsEl.appendChild(portLabel);
    }
    block.appendChild(portsEl);
    tree.appendChild(block);

    // Checking a site checks every one of its (not-yet-granted) ports; unchecking
    // clears them. The site checkbox itself isn't submitted -- only real port checks are.
    siteCheck.addEventListener('change', () => {
      for (const pc of portChecks) {
        if (!pc.disabled) pc.checked = siteCheck.checked;
      }
    });
  }

  document.getElementById('grantSelectAllSites').onchange = (e) => {
    tree.querySelectorAll('.grant-site-check').forEach((cb) => {
      cb.checked = e.target.checked;
      cb.dispatchEvent(new Event('change'));
    });
  };

  document.getElementById('grantModalBackdrop').classList.add('open');
}
document.getElementById('cancelGrantBtn').addEventListener('click', () => {
  document.getElementById('grantModalBackdrop').classList.remove('open');
});
document.getElementById('saveGrantBtn').addEventListener('click', async () => {
  const groupId = document.getElementById('grantGroupId').value;
  const grants = Array.from(document.querySelectorAll('#grantSiteTree .grant-port-check:checked:not(:disabled)')).map((cb) => ({
    siteId: cb.dataset.site,
    portId: cb.dataset.port
  }));
  if (grants.length === 0) {
    document.getElementById('grantError').textContent = 'Check at least one port (or a site) first.';
    return;
  }
  try {
    await api.post(`/api/groups/${groupId}/grants/bulk`, { grants });
    document.getElementById('grantModalBackdrop').classList.remove('open');
    await loadGroups();
  } catch (err) {
    document.getElementById('grantError').textContent = err.message;
  }
});

// ---------- Sessions ----------
function methodPill(method) {
  const isHttps = method === 'https';
  return `<span class="pill ${isHttps ? 'ok' : 'mute'}"><span class="dot"></span>${isHttps ? 'HTTPS' : 'SSH'}</span>`;
}

function renderSessions(sessions) {
  const tbody = document.querySelector('#sessionsTable tbody');
  tbody.innerHTML = '';
  for (const s of sessions) {
    const tr = document.createElement('tr');
    const since = new Date(s.connectedAt).toLocaleTimeString();
    tr.innerHTML = `
      <td>${escapeHtml(s.username)}</td>
      <td>${methodPill(s.method)}</td>
      <td>${s.portLabel ? escapeHtml(s.portLabel) : '<span class="hint">at menu</span>'}</td>
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

// ---------- Version / updates ----------
async function loadVersion() {
  const { version } = await api.get('/api/version');
  document.getElementById('currentVersion').textContent = version;
}

document.getElementById('checkUpdateBtn').addEventListener('click', async () => {
  const statusEl = document.getElementById('updateStatus');
  const btn = document.getElementById('checkUpdateBtn');
  const applyBtn = document.getElementById('applyUpdateBtn');
  btn.disabled = true;
  applyBtn.hidden = true;
  statusEl.style.color = 'var(--text-dim)';
  statusEl.textContent = 'Checking…';
  try {
    const result = await api.get('/api/check-update');
    if (!result.found) {
      statusEl.style.color = 'var(--text-dim)';
      statusEl.textContent = 'No releases found yet.';
    } else if (result.upToDate) {
      statusEl.style.color = 'var(--ok)';
      statusEl.textContent = `Up to date (${result.currentVersion}).`;
    } else {
      statusEl.style.color = 'var(--accent-hover)';
      statusEl.innerHTML = `Update available: <a href="${escapeHtml(result.url)}" target="_blank" rel="noopener">${escapeHtml(result.latestVersion)}</a> (you're on ${escapeHtml(result.currentVersion)}).`;
      if (result.canApplyInPlace) {
        applyBtn.hidden = false;
        applyBtn.dataset.targetVersion = result.latestVersion;
      } else {
        statusEl.innerHTML += ' <span class="hint">(no in-place update package published for this release.)</span>';
      }
    }
  } catch (err) {
    statusEl.style.color = 'var(--danger)';
    statusEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

async function loadUpdateStatus() {
  const status = await api.get('/api/update/status');
  document.getElementById('rollbackUpdateBtn').hidden = !status.hasBackup;
}

/** Polls a no-auth-required-to-fail endpoint until it responds, since the service
 * restart this waits out also invalidates the in-memory session -- a 401 from an
 * authenticated endpoint would look identical to "still down." */
async function pollUntilBackUp(onTick, timeoutMs = 3 * 60 * 1000) {
  const start = Date.now();
  await new Promise((resolve) => setTimeout(resolve, 5000));
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch('/api/session', { cache: 'no-store' });
      if (res.ok) return true;
    } catch {
      // expected while the service is mid-restart
    }
    onTick();
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  return false;
}

async function runUpdateAction(apiPath, confirmMessage, startingMessage) {
  if (!confirm(confirmMessage)) return;
  const progressEl = document.getElementById('updateProgress');
  const applyBtn = document.getElementById('applyUpdateBtn');
  const rollbackBtn = document.getElementById('rollbackUpdateBtn');
  applyBtn.disabled = true;
  rollbackBtn.disabled = true;
  progressEl.style.color = 'var(--text-dim)';
  progressEl.textContent = startingMessage;
  try {
    await api.post(apiPath);
  } catch (err) {
    progressEl.style.color = 'var(--danger)';
    progressEl.textContent = err.message;
    applyBtn.disabled = false;
    rollbackBtn.disabled = false;
    return;
  }
  progressEl.textContent = 'In progress -- watch the Log tab for details. This page will lose its connection when the service restarts, then reconnect on its own.';
  const backUp = await pollUntilBackUp(() => {
    progressEl.textContent = 'Waiting for the service to come back...';
  });
  if (backUp) {
    progressEl.style.color = 'var(--ok)';
    progressEl.textContent = 'Service is back. Reloading…';
    setTimeout(() => window.location.reload(), 1000);
  } else {
    progressEl.style.color = 'var(--danger)';
    progressEl.textContent =
      'The service did not come back within 3 minutes. SSH in and run "systemctl status central-office", or "sudo bash /opt/central-office/provisioning/rollback-update.sh" to restore the previous version.';
    applyBtn.disabled = false;
    rollbackBtn.disabled = false;
  }
}

document.getElementById('applyUpdateBtn').addEventListener('click', () => {
  const target = document.getElementById('applyUpdateBtn').dataset.targetVersion || 'the latest version';
  runUpdateAction(
    '/api/update/apply',
    `This downloads and applies ${target}, then restarts the service. All active tunnels, sessions, and web console connections will briefly disconnect. Continue?`,
    'Starting update…'
  );
});

document.getElementById('rollbackUpdateBtn').addEventListener('click', () => {
  runUpdateAction(
    '/api/update/rollback',
    'Roll back to the previous version? This restarts the service and briefly disconnects active tunnels and sessions.',
    'Starting rollback…'
  );
});

// ---------- Backup / restore ----------
document.getElementById('downloadBackupBtn').addEventListener('click', () => {
  const includeHostKey = document.getElementById('includeHostKeyOnBackup').checked;
  window.location.href = `/api/backup${includeHostKey ? '?includeHostKey=1' : ''}`;
});

document.getElementById('restoreBtn').addEventListener('click', async () => {
  const msg = document.getElementById('restoreMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  const fileInput = document.getElementById('restoreFile');
  const file = fileInput.files[0];
  if (!file) {
    msg.textContent = 'Choose a backup file first.';
    return;
  }
  if (!confirm('This replaces all current sites, groups, users, and admin accounts with the contents of the backup file. Continue?')) {
    return;
  }
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch('/api/restore', { method: 'POST', body: formData });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    msg.style.color = 'var(--ok)';
    msg.textContent = body.note ? `Restored. ${body.note}` : 'Restored. Reloading…';
    fileInput.value = '';
    setTimeout(() => window.location.reload(), 1500);
  } catch (err) {
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
  await loadVersion();
  await loadUpdateStatus();
  renderSessions(await api.get('/api/sessions'));
  await loadLogHistory();
  connectEvents();
}

boot();
