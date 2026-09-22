'use strict';

// Standalone page, same as terminal.js -- served on its own route, not part of the
// admin SPA, but shares the same session cookie. No login/picker screens here (unlike
// terminal.js): this feature was never offered to console users, so the only two states
// are "already signed in as an admin" (the normal case, reached by clicking Open
// Diagnostic Shell from a site's row menu) and "not signed in" (a stale/expired session,
// or someone hitting the URL directly) -- there's nothing to log into from this page.

async function checkAdminSession() {
  const res = await fetch('/api/session');
  const data = await res.json().catch(() => ({}));
  return !!(res.ok && data.authenticated);
}

function connectShell(siteId) {
  document.getElementById('authRequiredScreen').style.display = 'none';
  document.getElementById('terminalScreen').style.display = 'flex';
  const container = document.getElementById('xtermContainer');
  container.innerHTML = '';

  const term = new Terminal({ cursorBlink: true, convertEol: true });
  term.open(container);
  term.write('Connecting...\r\n');

  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${proto}//${window.location.host}/ws/shell?siteId=${encodeURIComponent(siteId)}`;
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  ws.addEventListener('open', () => term.clear());
  ws.addEventListener('message', (event) => {
    if (typeof event.data === 'string') {
      const msg = JSON.parse(event.data);
      if (msg.type === 'connected') {
        document.getElementById('terminalTitle').textContent = msg.label;
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

  document.getElementById('terminalDisconnectBtn').addEventListener('click', () => {
    ws.close();
    window.close();
  });
}

(async () => {
  const isAdmin = await checkAdminSession();
  if (!isAdmin) {
    document.getElementById('authRequiredScreen').style.display = 'flex';
    return;
  }
  const siteId = new URL(window.location.href).searchParams.get('siteId');
  if (!siteId) {
    document.getElementById('authRequiredScreen').style.display = 'flex';
    document.querySelector('#authRequiredScreen .hint').textContent = 'No site specified.';
    return;
  }
  connectShell(siteId);
})();
