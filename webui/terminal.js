'use strict';

const loginScreen = document.getElementById('loginScreen');
const pickerScreen = document.getElementById('pickerScreen');
const terminalScreen = document.getElementById('terminalScreen');

function showScreen(el) {
  [loginScreen, pickerScreen].forEach((s) => s.classList.remove('active'));
  if (el === terminalScreen) {
    terminalScreen.style.display = 'flex';
  } else {
    terminalScreen.style.display = 'none';
    el.classList.add('active');
  }
}

// This page is a separate script from webui/app.js (it's served on its own route, not
// as part of the admin SPA) but shares the same session cookie and the same
// CSRF-protection middleware -- see that file's csrfToken comment for the full story.
let csrfToken = null;

// Auto-captured from any response that carries one -- login/login-totp regenerate the
// session server-side (closing a session-fixation gap), which wipes whatever token the
// session had a moment before, so the fresh one has to come back from that same response.
function captureCsrfToken(data) {
  if (data && typeof data.csrfToken === 'string') csrfToken = data.csrfToken;
  return data;
}

async function apiGet(url) {
  const res = await fetch(url);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return captureCsrfToken(data);
}

async function apiPost(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}) },
    body: JSON.stringify(body || {})
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return captureCsrfToken(data);
}

document.getElementById('terminalLoginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('terminalLoginError');
  errorEl.textContent = '';
  try {
    // This form is for console users only -- an admin visiting /terminal is already
    // authenticated via the session cookie shared with the main admin UI at "/" and
    // never sees this screen (see the boot check below).
    await apiPost('/api/terminal/login', {
      username: document.getElementById('terminalUsername').value.trim(),
      password: document.getElementById('terminalPassword').value
    });
    await showPicker();
    autoConnectFromQuery();
  } catch (err) {
    errorEl.textContent = err.message;
  }
});

document.getElementById('pickerSignOutBtn').addEventListener('click', async () => {
  await apiPost('/api/terminal/logout').catch(() => {});
  window.location.reload();
});

let allChoices = [];
let selectedSiteId = null;
let autoConnectDone = false;

async function showPicker() {
  const errorEl = document.getElementById('pickerError');
  errorEl.textContent = '';
  showScreen(pickerScreen);
  try {
    allChoices = await apiGet('/api/terminal/choices');
    selectedSiteId = null;
    renderPicker();
  } catch (err) {
    errorEl.textContent = err.message;
  }
}

// Two levels: sites first, then that site's ports. A single-site user skips straight to
// the ports (nothing to drill into).
function renderPicker() {
  const listEl = document.getElementById('choiceList');
  const emptyEl = document.getElementById('pickerEmpty');
  const headingEl = document.getElementById('pickerHeading');
  const backBtn = document.getElementById('pickerBackBtn');
  listEl.innerHTML = '';

  const sites = new Map();
  for (const c of allChoices) {
    if (!sites.has(c.siteId)) sites.set(c.siteId, { name: c.siteName, ports: [] });
    sites.get(c.siteId).ports.push(c);
  }
  emptyEl.style.display = sites.size ? 'none' : 'block';
  if (sites.size === 1 && !selectedSiteId) selectedSiteId = [...sites.keys()][0];

  if (selectedSiteId && sites.has(selectedSiteId)) {
    const site = sites.get(selectedSiteId);
    headingEl.textContent = site.name;
    backBtn.style.display = sites.size > 1 ? '' : 'none';
    for (const c of site.ports.sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: 'base', numeric: true }))) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = c.label + (c.permission === 'read-only' ? ' (read-only)' : '');
      btn.addEventListener('click', () => connectTerminal(c.siteId, c.portId, `${c.siteName} — ${c.label}`));
      listEl.appendChild(btn);
    }
    return;
  }

  headingEl.textContent = sites.size ? 'Choose a site' : '';
  backBtn.style.display = 'none';
  const ordered = [...sites.entries()].sort((a, b) => a[1].name.localeCompare(b[1].name, undefined, { sensitivity: 'base', numeric: true }));
  for (const [siteId, site] of ordered) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = `${site.name} (${site.ports.length} port${site.ports.length === 1 ? '' : 's'})`;
    btn.addEventListener('click', () => {
      selectedSiteId = siteId;
      renderPicker();
    });
    listEl.appendChild(btn);
  }
}

document.getElementById('pickerBackBtn').addEventListener('click', () => {
  selectedSiteId = null;
  renderPicker();
});

// A link like /terminal?siteId=...&portId=... (opened from the fleet topology) connects
// straight to that port once the caller is signed in, instead of stopping at the picker.
function autoConnectFromQuery() {
  if (autoConnectDone) return false;
  autoConnectDone = true;
  const params = new URLSearchParams(window.location.search);
  const siteId = params.get('siteId');
  const portId = params.get('portId');
  if (!siteId || !portId) return false;
  const match = allChoices.find((c) => c.siteId === siteId && c.portId === portId);
  if (!match) {
    document.getElementById('pickerError').textContent = 'That port is not available to you right now.';
    return false;
  }
  connectTerminal(match.siteId, match.portId, `${match.siteName} — ${match.label}`);
  return true;
}
let ws = null;
let term = null;

function connectTerminal(siteId, portId, label) {
  showScreen(terminalScreen);
  const container = document.getElementById('xtermContainer');
  container.innerHTML = '';

  term = new Terminal({ cursorBlink: true, convertEol: true });
  term.open(container);
  term.write('Connecting...\r\n');

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${window.location.host}/ws/terminal?siteId=${encodeURIComponent(siteId)}&portId=${encodeURIComponent(portId)}`;
  ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  ws.addEventListener('open', () => term.clear());
  ws.addEventListener('message', (event) => {
    if (typeof event.data === 'string') {
      const msg = JSON.parse(event.data);
      if (msg.type === 'connected') {
        document.getElementById('terminalTitle').textContent = (msg.label || label) + (msg.readOnly ? ' (read-only)' : '');
      } else if (msg.type === 'error') {
        term.write(`\r\n\x1b[31m[${msg.message}]\x1b[0m\r\n`);
      }
      return;
    }
    term.write(new Uint8Array(event.data));
  });
  ws.addEventListener('close', () => term.write('\r\n\x1b[33m[Disconnected]\x1b[0m\r\n'));
  ws.addEventListener('error', () => term.write('\r\n\x1b[31m[Connection error]\x1b[0m\r\n'));

  term.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data));
  });
}

document.getElementById('terminalDisconnectBtn').addEventListener('click', () => {
  if (ws) {
    ws.close();
    ws = null;
  }
  showPicker();
});

(async () => {
  try {
    const session = await apiGet('/api/terminal/session');
    if (!session.authenticated) {
      showScreen(loginScreen);
      return;
    }
    await showPicker();
    autoConnectFromQuery();
  } catch {
    showScreen(loginScreen);
  }
})();
