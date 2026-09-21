'use strict';

// Forwards tab: name a device on a site's network (host + port), then reach it from your own
// computer with an ordinary SSH port forward through the hub -- see tunnelServer.js's
// attachAdminForwarding. This page defines the forwards and builds the exact command to use.
(function forwardsUi() {
  const tabBtn = document.querySelector('[data-tab="forwards"]');
  const tab = document.getElementById('tab-forwards');
  if (!tabBtn || !tab) return;

  const $ = (id) => document.getElementById(id);
  const esc = (s) => escapeHtml(s == null ? '' : s);

  let forwards = [];
  let sites = [];
  let hubSshPort = 443;
  let username = 'admin';

  // ---------- Commands ----------
  // Suggests a local port that doesn't need admin rights (below 1024) to listen on.
  function suggestedLocalPort(targetPort) {
    const known = { 22: 2222, 23: 2323, 80: 8080, 443: 8443, 3389: 33389 };
    if (known[targetPort]) return known[targetPort];
    return targetPort < 1024 ? 8000 + targetPort : targetPort;
  }

  /** One -L per forward, bumping the local port when two forwards would collide. */
  function assignLocalPorts(list) {
    const used = new Set();
    return list.map((f) => {
      let local = suggestedLocalPort(f.port);
      while (used.has(local)) local += 1;
      used.add(local);
      return { forward: f, local };
    });
  }

  function commandFor(assigned) {
    const hub = window.location.hostname;
    const ls = assigned.map((a) => `-L ${a.local}:${a.forward.name}:${a.forward.port}`).join(' ');
    return `ssh -N ${ls} -p ${hubSshPort} ${username}@${hub}`;
  }

  function usageHint(a) {
    const { forward: f, local } = a;
    if (f.port === 443 || f.port === 8443) return `then browse to https://localhost:${local}`;
    if (f.port === 80 || f.port === 8080) return `then browse to http://localhost:${local}`;
    if (f.port === 22) return `then: ssh -p ${local} <device-user>@localhost`;
    if (f.port === 23) return `then: telnet localhost ${local}`;
    return `then connect your client to localhost:${local}`;
  }

  async function copy(text, button) {
    try {
      await navigator.clipboard.writeText(text);
      const old = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => (button.textContent = old), 1200);
    } catch {
      window.prompt('Copy this command:', text);
    }
  }

  // ---------- Table ----------
  const pill = (cls, text) => `<span class="pill ${cls}"><span class="dot"></span>${esc(text)}</span>`;

  function render() {
    const tbody = document.querySelector('#forwardsTable tbody');
    tbody.innerHTML = '';
    $('forwardsEmpty').style.display = forwards.length ? 'none' : '';
    $('forwardsAllBtn').style.display = forwards.length > 1 ? '' : 'none';
    for (const f of [...forwards].sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }))) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><code>${esc(f.name)}</code></td>
        <td>${esc(f.siteName || '(site removed)')} ${f.siteConnected ? pill('ok', 'online') : pill('mute', 'offline')}</td>
        <td><code>${esc(f.host)}:${f.port}</code></td>
        <td class="hint">${esc(f.notes)}</td><td></td>`;
      const cell = tr.lastElementChild;
      const mkBtn = (label, cls, fn) => {
        const b = document.createElement('button');
        b.textContent = label;
        if (cls) b.className = cls;
        b.style.marginRight = '6px';
        b.addEventListener('click', () => fn(b));
        cell.appendChild(b);
      };
      mkBtn('Connect', 'primary', () => openConnect([f]));
      mkBtn('Test', 'secondary', async (b) => {
        b.disabled = true;
        b.textContent = 'Testing…';
        try {
          await api.post(`/api/forwards/${f.id}/test`);
          alert(`"${f.name}" is reachable: ${f.siteName} connected to ${f.host}:${f.port}.`);
        } catch (e) {
          alert(`Could not reach "${f.name}": ${e.message}`);
        } finally {
          b.disabled = false;
          b.textContent = 'Test';
        }
      });
      mkBtn('Edit', 'secondary', () => openEditor(f));
      mkBtn('Delete', 'danger', async () => {
        if (!confirm(`Delete the forward "${f.name}"?`)) return;
        await api.del(`/api/forwards/${f.id}`);
        await load();
      });
      tbody.appendChild(tr);
    }
  }

  // ---------- Add / edit ----------
  function openEditor(f) {
    $('forwardEditTitle').textContent = f ? 'Edit Forward' : 'Add Forward';
    $('forwardId').value = f ? f.id : '';
    $('forwardName').value = f ? f.name : '';
    $('forwardHost').value = f ? f.host : '';
    $('forwardPort').value = f ? f.port : '';
    $('forwardNotes').value = f ? f.notes : '';
    $('forwardSite').innerHTML = sites.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}${s.connected ? '' : ' (offline)'}</option>`).join('');
    if (f) $('forwardSite').value = f.siteId;
    $('forwardEditError').textContent = '';
    $('forwardEditBackdrop').classList.add('open');
  }
  $('addForwardBtn').addEventListener('click', () => {
    if (!sites.length) {
      alert('Enroll a site first.');
      return;
    }
    openEditor(null);
  });
  $('cancelForwardBtn').addEventListener('click', () => $('forwardEditBackdrop').classList.remove('open'));
  $('saveForwardBtn').addEventListener('click', async () => {
    const err = $('forwardEditError');
    err.textContent = '';
    try {
      await api.post('/api/forwards', {
        id: $('forwardId').value || undefined,
        name: $('forwardName').value,
        siteId: $('forwardSite').value,
        host: $('forwardHost').value.trim(),
        port: Number($('forwardPort').value),
        notes: $('forwardNotes').value
      });
      $('forwardEditBackdrop').classList.remove('open');
      await load();
    } catch (e) {
      err.textContent = e.message;
    }
  });

  // ---------- Connect dialog ----------
  function openConnect(list) {
    const assigned = assignLocalPorts(list);
    const cmd = commandFor(assigned);
    $('forwardCommand').textContent = cmd;
    $('forwardHints').innerHTML = assigned.map((a) => `<li><code>${esc(a.forward.name)}</code> &mdash; ${esc(usageHint(a))}</li>`).join('');
    $('forwardCopyBtn').onclick = (e) => copy(cmd, e.currentTarget);
    $('forwardConnectBackdrop').classList.add('open');
  }
  $('forwardsAllBtn').addEventListener('click', () => openConnect(forwards));
  $('closeForwardConnectBtn').addEventListener('click', () => $('forwardConnectBackdrop').classList.remove('open'));

  // ---------- Loading ----------
  async function load() {
    const [fw, st, ssh, session] = await Promise.all([
      api.get('/api/forwards'),
      api.get('/api/sites'),
      api.get('/api/ssh-settings'),
      api.get('/api/session')
    ]);
    forwards = fw;
    sites = st;
    hubSshPort = ssh.port;
    username = session.username || 'admin';
    render();
  }
  tabBtn.addEventListener('click', () => load().catch(() => {}));
  setInterval(() => {
    if (appRoot.classList.contains('active') && tab.classList.contains('active') && !document.querySelector('.modal-backdrop.open')) {
      load().catch(() => {});
    }
  }, 10000);
})();
