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

async function apiGet(url) {
  const res = await fetch(url);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiPost(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
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
  } catch (err) {
    errorEl.textContent = err.message;
  }
});

document.getElementById('pickerSignOutBtn').addEventListener('click', async () => {
  await apiPost('/api/terminal/logout').catch(() => {});
  window.location.reload();
});

async function showPicker() {
  const errorEl = document.getElementById('pickerError');
  const listEl = document.getElementById('choiceList');
  const emptyEl = document.getElementById('pickerEmpty');
  errorEl.textContent = '';
  listEl.innerHTML = '';
  showScreen(pickerScreen);
  try {
    const choices = await apiGet('/api/terminal/choices');
    emptyEl.style.display = choices.length ? 'none' : 'block';
    for (const c of choices) {
      const btn = document.createElement('button');
      btn.textContent = `${c.siteName} — ${c.label}`;
      btn.type = 'button';
      btn.addEventListener('click', () => connectTerminal(c.siteId, c.portId, `${c.siteName} — ${c.label}`));
      listEl.appendChild(btn);
    }
  } catch (err) {
    errorEl.textContent = err.message;
  }
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
  } catch {
    showScreen(loginScreen);
  }
})();
