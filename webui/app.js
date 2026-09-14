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
    if (result.mustChangePassword) {
      show(forceChangeScreen);
      return;
    }
    document.body.classList.add('app-mode');
    show(appRoot);
    await initApp();
  } catch (err) {
    errorEl.textContent = 'Invalid username or password.';
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
    tr.innerHTML = `
      <td>${escapeHtml(site.name)}</td>
      <td>${statusPill(site.connected)}</td>
      <td>${portsList}</td>
      <td></td>
    `;
    const actionsCell = tr.lastElementChild;
    const addPortBtn = document.createElement('button');
    addPortBtn.textContent = '+ Port';
    addPortBtn.addEventListener('click', () => openPortModal(site.id));
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
  await loadMyUsername();
  await loadHostKeyFingerprint();
  renderSessions(await api.get('/api/sessions'));
  await loadLogHistory();
  connectEvents();
}

boot();
