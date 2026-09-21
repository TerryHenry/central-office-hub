'use strict';

// Populated from every response that carries one -- /api/session always does, and so
// does every login-ish endpoint that regenerates the session server-side (login,
// login-totp, terminal login), since that wipes whatever token the session had a moment
// before. Echoed back on every mutating request -- the server compares it against the
// same value it handed out for this session, so a cross-site request (which never sees
// this response) has no way to produce it, on top of whatever SameSite already blocks.
let csrfToken = null;
function csrfHeaders() {
  return csrfToken ? { 'X-CSRF-Token': csrfToken } : {};
}
function captureCsrfToken(body) {
  if (body && typeof body.csrfToken === 'string') csrfToken = body.csrfToken;
  return body;
}

const api = {
  async get(url) {
    const res = await fetch(url);
    if (!res.ok) throw await apiError(res);
    return captureCsrfToken(await res.json());
  },
  async post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...csrfHeaders() },
      body: JSON.stringify(body || {})
    });
    if (!res.ok) throw await apiError(res);
    return captureCsrfToken(await res.json());
  },
  async del(url) {
    const res = await fetch(url, { method: 'DELETE', headers: csrfHeaders() });
    if (!res.ok) throw await apiError(res);
    return captureCsrfToken(await res.json());
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
const force2faScreen = document.getElementById('force2faScreen');
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
    document.getElementById('policyRequireAdminTotp').checked = policy.requireAdminTotp;
  } catch {
    // hints just stay at their static fallback
  }
}

document.getElementById('savePasswordPolicyBtn').addEventListener('click', async () => {
  const msg = document.getElementById('passwordPolicyMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  const requireAdminTotp = document.getElementById('policyRequireAdminTotp').checked;
  // Turning this on doesn't exempt whoever's saving it -- if their own account has no
  // 2FA yet, they'll be walked into the same forced setup as anyone else on their very
  // next request, so it's worth a heads-up before that happens with no warning.
  if (requireAdminTotp && !(await api.get('/api/session')).totpEnabled) {
    if (!confirm("Your own admin account doesn't have two-factor authentication set up yet. Saving this will immediately require you to set it up too, before you can do anything else. Continue?")) {
      return;
    }
  }
  try {
    await api.post('/api/password-policy', {
      minLength: Number(document.getElementById('policyMinLength').value),
      requireMixedCase: document.getElementById('policyRequireMixedCase').checked,
      requireDigit: document.getElementById('policyRequireDigit').checked,
      requireSymbol: document.getElementById('policyRequireSymbol').checked,
      checkBreached: document.getElementById('policyCheckBreached').checked,
      requireAdminTotp
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
  if (session.mustEnableTotp) {
    await enterForce2fa();
    document.body.classList.remove('app-mode');
    return;
  }
  document.body.classList.add('app-mode');
  show(appRoot);
  await initApp();
}

// Starts (or resumes) the forced-2FA-enrollment screen: fetches a fresh secret/QR the
// same way the self-service "Enable 2FA" flow does, since this is that exact same
// setup, just presented as a screen the admin can't get past instead of a tab panel.
async function enterForce2fa() {
  const errorEl = document.getElementById('force2faError');
  errorEl.textContent = '';
  try {
    const { secret, otpauthUrl } = await api.post('/api/admin-2fa/setup');
    document.getElementById('force2faSecretText').textContent = secret;
    document.getElementById('force2faCode').value = '';
    window.renderTotpQr(document.getElementById('force2faQrContainer'), otpauthUrl);
    show(force2faScreen);
  } catch (err) {
    errorEl.textContent = err.message;
    show(force2faScreen);
  }
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
    await boot();
  } catch (err) {
    errorEl.textContent = 'Invalid username or password.';
  }
});

document.getElementById('totpForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('totpError');
  errorEl.textContent = '';
  try {
    await api.post('/api/login-totp', { token: document.getElementById('totpCode').value.trim() });
    hide(totpScreen);
    await boot();
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
    await boot();
  } catch (err) {
    errorEl.textContent = err.message;
  }
});

document.getElementById('force2faForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById('force2faError');
  errorEl.textContent = '';
  const token = document.getElementById('force2faCode').value.trim();
  try {
    await api.post('/api/admin-2fa/confirm', { token });
    hide(force2faScreen);
    await boot();
  } catch (err) {
    errorEl.textContent = err.message;
    document.getElementById('force2faCode').value = '';
    document.getElementById('force2faCode').focus();
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
    // Lazy-load the embedded Handbook only the first time its tab is opened, rather
    // than fetching it on every page load whether or not anyone looks at it.
    if (btn.dataset.tab === 'help') {
      const frame = document.getElementById('handbookFrame');
      if (!frame.src) frame.src = '/HANDBOOK.html';
    }
  });
});

// ---------- Sites ----------
function statusPill(connected) {
  return connected
    ? '<span class="pill ok"><span class="dot"></span>Connected</span>'
    : '<span class="pill mute"><span class="dot"></span>Disconnected</span>';
}

/** Port access mode, as reported by the site's own heartbeat -- purely informational
 * here (the hub can't enforce it, only the appliance owning the port can); matches the
 * appliance's own terminology exactly so the two admin UIs never disagree on wording. */
function accessLabel(access) {
  if (access === 'shared-rw') return 'Shared (read/write)';
  if (access === 'first-write') return 'Shared (first user read/write)';
  if (access === 'shared-ro') return 'Shared (read-only)';
  if (access === 'exclusive') return 'Exclusive';
  return 'Unknown';
}

function accessPill(access) {
  if (!access) return '';
  const cls = access !== 'exclusive' ? 'warn' : 'mute';
  return `<span class="pill ${cls}" title="Port access mode (reported by the site, not enforced by the hub)">${escapeHtml(accessLabel(access))}</span> `;
}

/** Reflects what the box's own last heartbeat reported about its local SSH/web console --
 * only surfaces anything when something is actually disabled, so a normal site (both
 * reachable, the default) doesn't get a pill on every row. undefined means the box
 * hasn't reported this yet (older version, or never heartbeated) -- stay silent rather
 * than guess. */
function localAccessPill(site) {
  const ssh = site.edgeSshEnabled;
  const web = site.edgeWebTerminalEnabled;
  if (ssh === false && web === false) {
    return '<br><span class="pill ok" title="Local SSH and web console are both disabled on this box"><span class="dot"></span>Local access locked down</span>';
  }
  const disabled = [];
  if (ssh === false) disabled.push('SSH');
  if (web === false) disabled.push('web console');
  if (disabled.length === 0) return '';
  return `<br><span class="pill mute" title="Local ${disabled.join(' and ')} access is disabled on this box"><span class="dot"></span>Local ${escapeHtml(disabled.join(' + '))} disabled</span>`;
}

/** Whether this site's local admin accounts (as of its last heartbeat) match the hub's
 * own -- the confirmation "Sync Admins" actually took effect, since there's no other way
 * to check that against a real remote box short of trying to log into it. null (unknown)
 * stays silent: no heartbeat with this field yet, e.g. an older edge version. */
function adminsSyncPill(site) {
  if (site.adminsSynced === true) {
    return '<br><span class="pill ok" title="This site\'s local admin accounts match the hub\'s exactly"><span class="dot"></span>Admins in sync</span>';
  }
  if (site.adminsSynced === false) {
    return '<br><span class="pill warn" title="This site\'s local admin accounts do NOT match the hub\'s -- Sync Admins hasn\'t been applied, or something changed since"><span class="dot"></span>Admins not in sync</span>';
  }
  return '';
}

/** Whether this site has pinned the hub's SSH host key -- as of the security fix that
 * signs every hub-pushed command, a site that hasn't pinned it silently discards every
 * command the hub sends (updates, backup restore, admin sync, port/access/TFTP config)
 * rather than erroring, so this is the only visible sign anything's wrong. null/unknown
 * stays silent, same convention as adminsSyncPill above (older edge version). */
function commandVerificationPill(site) {
  if (site.hubKeyPinned === false) {
    return '<br><span class="pill warn" title="This site has not pinned this hub\'s SSH host key -- it refuses every command the hub pushes (updates, backup restore, admin sync, port/access/TFTP config) rather than trusting one unverified. Pin this hub\'s fingerprint (Account tab) in the site\'s own Central Office panel to fix."><span class="dot"></span>Hub commands unverified</span>';
  }
  return '';
}

// ---------- Fleet topology diagram (Dashboard tab) ----------
// Ports carry their own reported `present` flag from the edge box's heartbeat when
// available (see configStore.recordHeartbeat) and fall back to the site's tunnel state
// for older boxes that don't report it yet -- see the per-port logic below.
let lastTopologySites = [];
let lastTopologyHaStatus = { configured: false };

function renderTopology(sites, haStatus) {
  lastTopologySites = sites;
  if (haStatus !== undefined) lastTopologyHaStatus = haStatus;
  const ha = lastTopologyHaStatus;
  const svg = document.getElementById('topologySvg');
  const empty = document.getElementById('topologyEmpty');
  if (!sites.length) {
    svg.hidden = true;
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  svg.hidden = false;

  const ROW_H = 26;
  const HUB_X = 50;
  const SITE_X = 300;
  const PORT_X = 560;
  const TOP_PAD = 20;

  let y = TOP_PAD;
  const siteLayout = [];
  for (const site of sites) {
    const rows = Math.max(site.ports.length, 1);
    const blockTop = y;
    const portYs = site.ports.map((_p, i) => blockTop + i * ROW_H + ROW_H / 2);
    const blockHeight = rows * ROW_H;
    siteLayout.push({ site, siteY: blockTop + blockHeight / 2, portYs });
    y += blockHeight;
  }
  const totalHeight = Math.max(y + TOP_PAD, 100);
  const hubY = totalHeight / 2;

  const longestLabel = sites.reduce((max, s) => {
    max = Math.max(max, s.name.length);
    for (const p of s.ports) max = Math.max(max, p.label.length);
    return max;
  }, 8);
  const width = PORT_X + Math.min(longestLabel * 7, 280) + 40;

  svg.setAttribute('viewBox', `0 0 ${width} ${totalHeight}`);
  svg.setAttribute('width', width);
  svg.setAttribute('height', totalHeight);

  const edge = (x1, y1, x2, y2) => {
    const midX = (x1 + x2) / 2;
    return `<path class="topology-edge" d="M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}" />`;
  };

  // A node's own label sits directly in the path any line leaving that node has to take
  // (both start out moving horizontally toward higher X, same as the label). Two things
  // fix that: (1) every edge is emitted into its own array and painted before ANY node,
  // so circles always paint over a crossing line instead of the reverse, and (2) every
  // label gets an opaque background chip (sized to its own text) so a line segment
  // passing behind it is hidden rather than drawn through the letters.
  const edgeParts = [];
  const nodeParts = [];
  const label = (x, y, text, opts = {}) => {
    const fontSize = opts.sub ? 10.5 : 12;
    const w = text.length * fontSize * 0.62 + 8;
    const h = fontSize + 6;
    nodeParts.push(`<rect x="${x - 4}" y="${y - fontSize + 1}" width="${w}" height="${h}" rx="2" fill="var(--bg)" />`);
    nodeParts.push(
      `<text class="${opts.sub ? 'topology-node-sub' : 'topology-node-label'}" x="${x}" y="${y}"${opts.bold ? ' font-weight="600"' : ''}>${escapeHtml(text)}</text>`
    );
  };

  const haConfigured = ha && ha.configured !== false;
  const hubTitle = haConfigured
    ? `Central Office — ${ha.isActive ? 'Active' : 'Standby'} (${ha.role === 'primary' ? 'Primary' : 'Secondary'})`
    : 'Central Office';
  nodeParts.push(
    `<circle class="topology-node hub" cx="${HUB_X}" cy="${hubY}" r="8"><title>${escapeHtml(hubTitle)}</title></circle>`
  );
  label(HUB_X + 14, hubY + 4, 'Central Office', { bold: true });

  if (haConfigured) {
    // A short dashed link straight above the hub node represents the standalone
    // ha-agent pairing -- distinct from the solid site/port edges, since it's a
    // control-plane health link, not a data tunnel. Color mirrors the same
    // "consecutiveFailures === 0" healthy/unhealthy read used by the Account tab's
    // High Availability panel, so the two views never disagree.
    const peerY = hubY - 34;
    const peerHealthy = ha.consecutiveFailures === 0;
    const peerStatusClass = peerHealthy ? 'online' : 'warn';
    const peerHealthText = peerHealthy
      ? 'Healthy'
      : `${ha.consecutiveFailures} consecutive check${ha.consecutiveFailures === 1 ? '' : 's'} failed`;
    edgeParts.push(`<path class="topology-edge ha-link" d="M ${HUB_X} ${hubY} L ${HUB_X} ${peerY}" />`);
    nodeParts.push(
      `<circle class="topology-node ${peerStatusClass}" cx="${HUB_X}" cy="${peerY}" r="6"><title>Peer controller — ${escapeHtml(peerHealthText)}</title></circle>`
    );
    label(HUB_X + 14, peerY + 4, 'Peer Controller', { sub: true });
    label(HUB_X + 14, hubY + 17, ha.isActive ? 'Active' : 'Standby', { sub: true });
  }

  for (const { site, siteY, portYs } of siteLayout) {
    const statusClass = site.connected ? 'online' : 'offline';
    edgeParts.push(edge(HUB_X, hubY, SITE_X, siteY));
    nodeParts.push(
      `<circle class="topology-node ${statusClass}" cx="${SITE_X}" cy="${siteY}" r="6"><title>${escapeHtml(site.name)} — ${site.connected ? 'Online' : 'Offline'}</title></circle>`
    );
    label(SITE_X + 12, siteY + 4, site.name);

    if (site.ports.length === 0) {
      label(SITE_X + 12, siteY + 17, 'no ports reported', { sub: true });
      continue;
    }
    site.ports.forEach((port, i) => {
      const py = portYs[i];
      // A site being connected only means its tunnel is up -- it says nothing about
      // whether the actual device behind a given port is plugged in. Use the port's own
      // reported presence when the box sends one; only fall back to the site's
      // connection state for older boxes that don't report it yet (present === undefined).
      let portOnline;
      let reachTitle;
      if (!site.connected) {
        portOnline = false;
        reachTitle = 'Unreachable (site offline)';
      } else if (port.present === false) {
        portOnline = false;
        reachTitle = 'Site online, but this device is not present';
      } else if (port.present === true) {
        portOnline = true;
        reachTitle = 'Reachable (device present)';
      } else {
        portOnline = true;
        reachTitle = 'Reachable (device presence unknown -- edge box does not report it yet)';
      }
      const portStatusClass = portOnline ? 'online' : 'offline';
      const accessSuffix = port.access ? ` — ${accessLabel(port.access)}` : '';
      edgeParts.push(edge(SITE_X, siteY, PORT_X, py));
      nodeParts.push(
        `<circle class="topology-node ${portStatusClass}" cx="${PORT_X}" cy="${py}" r="5"><title>${escapeHtml(port.label)} — ${reachTitle}${accessSuffix}</title></circle>`
      );
      label(PORT_X + 11, py + 4, port.label);
    });
  }

  svg.innerHTML = edgeParts.join('') + nodeParts.join('');
}

// ---------- Row overflow menu (used by the Sites table) ----------
function closeAllRowMenus() {
  document.querySelectorAll('.row-menu-dropdown.open').forEach((el) => el.classList.remove('open'));
}
document.addEventListener('click', (e) => {
  if (!e.target.closest('.row-menu')) closeAllRowMenus();
});

/** items: array of {label, className, onClick} entries, or the string 'divider'. */
function buildRowMenu(items) {
  const wrap = document.createElement('div');
  wrap.className = 'row-menu';
  const btn = document.createElement('button');
  btn.className = 'row-menu-btn secondary';
  btn.textContent = '⋯';
  btn.title = 'Actions';
  const dropdown = document.createElement('div');
  dropdown.className = 'row-menu-dropdown';
  for (const item of items) {
    if (item === 'divider') {
      const divider = document.createElement('div');
      divider.className = 'row-menu-divider';
      dropdown.appendChild(divider);
      continue;
    }
    const itemBtn = document.createElement('button');
    itemBtn.textContent = item.label;
    if (item.className) itemBtn.className = item.className;
    itemBtn.addEventListener('click', async (e) => {
      e.stopPropagation();
      dropdown.classList.remove('open');
      await item.onClick();
    });
    dropdown.appendChild(itemBtn);
  }
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = dropdown.classList.contains('open');
    closeAllRowMenus();
    if (!wasOpen) {
      const rect = btn.getBoundingClientRect();
      dropdown.style.top = `${rect.bottom + 4}px`;
      dropdown.style.right = `${window.innerWidth - rect.right}px`;
      dropdown.classList.add('open');
    }
  });
  wrap.appendChild(btn);
  wrap.appendChild(dropdown);
  return wrap;
}

async function loadSites() {
  const sites = await api.get('/api/sites');
  renderTopology(sites);
  const tbody = document.querySelector('#sitesTable tbody');
  // This re-renders on every SSE 'sites' broadcast -- which fires on essentially every
  // site's heartbeat, every few seconds with more than one site enrolled -- so a
  // mid-heartbeat rebuild used to silently wipe out whatever the admin had just checked
  // for a bulk action. Capture the checked set first and restore it below, rather than
  // resetting selection on every routine background refresh.
  const previouslyChecked = new Set(
    [...tbody.querySelectorAll('.site-select:checked')].map((cb) => cb.dataset.site)
  );
  tbody.innerHTML = '';
  for (const site of sites) {
    const tr = document.createElement('tr');
    const portsList = site.ports.length
      ? site.ports
          .map((p) => {
            const dotClass = p.present === true ? 'online' : p.present === false ? 'offline' : 'unknown';
            const title = p.present === true ? 'Device present' : p.present === false ? 'Device not present' : 'Presence unknown';
            return `<div><span class="topology-dot ${dotClass}" title="${title}"></span>${escapeHtml(p.label)} ${accessPill(p.access)}<code class="port-id">${escapeHtml(p.id)}</code> <button class="danger site-port-delete" data-port-id="${escapeHtml(p.id)}" title="Delete this port" style="padding:1px 8px; font-size:11px;">Delete</button></div>`;
          })
          .join('')
      : '<span class="hint">none reported yet</span>';
    const lastSeen = site.lastSeenAt ? new Date(site.lastSeenAt).toLocaleString() : '<span class="hint">never</span>';
    const backupInfo = site.lastBackup
      ? `<span class="hint">${new Date(site.lastBackup.takenAt).toLocaleDateString()}</span>`
      : '<span class="hint">none yet</span>';
    let versionInfo = site.reportedVersion ? escapeHtml(site.reportedVersion) : '<span class="hint">&mdash;</span>';
    if (site.reportedVersion && site.updateAvailable) {
      const url = site.latestEdgeVersionUrl ? escapeHtml(site.latestEdgeVersionUrl) : '#';
      versionInfo += `<br><a href="${url}" target="_blank" rel="noopener" class="pill warn"><span class="dot"></span>Update: ${escapeHtml(site.latestEdgeVersion)}</a>`;
    } else if (site.reportedVersion && site.latestEdgeVersion) {
      versionInfo += '<br><span class="pill ok"><span class="dot"></span>Up to date</span>';
    }
    tr.innerHTML = `
      <td><input type="checkbox" class="site-select" data-site="${site.id}" ${previouslyChecked.has(site.id) ? 'checked' : ''} /></td>
      <td>${escapeHtml(site.name)}</td>
      <td>${statusPill(site.connected)}${localAccessPill(site)}${adminsSyncPill(site)}${commandVerificationPill(site)}</td>
      <td>${versionInfo}</td>
      <td>${lastSeen}</td>
      <td>${backupInfo}</td>
      <td>${portsList}</td>
      <td></td>
    `;
    tr.querySelectorAll('.site-port-delete').forEach((btn) => {
      btn.addEventListener('click', () => {
        const port = site.ports.find((p) => p.id === btn.dataset.portId);
        if (port) openDeletePortModal(site.id, port.id, port.label);
      });
    });
    const actionsCell = tr.lastElementChild;
    const menuItems = [
      { label: 'Rename', onClick: () => openSiteRenameModal(site) },
      {
        label: 'Upgrade Version',
        onClick: async () => {
          await api.post(`/api/sites/${site.id}/queue-update`);
          alert(`An upgrade was queued for "${site.name}" -- it applies on the box's next heartbeat.`);
        }
      },
      {
        label: 'Request Backup',
        onClick: async () => {
          await api.post(`/api/sites/${site.id}/backup/request`);
          alert(`A config backup was requested from "${site.name}" -- it's sent on the box's next heartbeat.`);
        }
      }
    ];
    if (site.connected) {
      menuItems.push({
        label: 'Open Admin UI',
        onClick: async () => {
          try {
            const { port } = await api.post(`/api/sites/${site.id}/admin-session`);
            window.open(`https://${window.location.hostname}:${port}/`, '_blank', 'noopener');
          } catch (err) {
            alert(err.message);
          }
        }
      });
      menuItems.push({ label: 'View Site Info', onClick: () => openSiteInfoModal(site) });
      menuItems.push({ label: 'Upload to TFTP', onClick: () => openSiteTftpUploadModal([site]) });
    }
    if (site.lastBackup) {
      menuItems.push({
        label: 'Download Backup',
        onClick: () => {
          window.location.href = `/api/sites/${site.id}/backup`;
        }
      });
    }
    menuItems.push({ label: 'Restore Backup', onClick: () => openSiteRestoreModal(site) });
    menuItems.push('divider');
    menuItems.push({ label: 'Configure Ports', onClick: () => openSitePortsModal(site) });
    menuItems.push({ label: 'Local Access', onClick: () => openSiteLocalAccessModal(site) });
    menuItems.push({ label: 'Neighbors (LLDP)', onClick: () => openSiteLldpModal(site) });
    menuItems.push({ label: 'TFTP Server', onClick: () => openSiteTftpSettingsModal(site) });
    menuItems.push('divider');
    menuItems.push({
      label: 'Sync Admins',
      className: 'danger',
      onClick: async () => {
        if (!confirm(`Replace every local admin account on "${site.name}" with this hub's own admin accounts? Any admin login not from the hub will stop working on that box. Applies on its next heartbeat.`)) return;
        await api.post(`/api/sites/${site.id}/sync-admins`);
        alert(`An admin sync was queued for "${site.name}" -- it applies on the box's next heartbeat.`);
      }
    });
    menuItems.push({
      label: 'Sync Users',
      onClick: async () => {
        if (!confirm(`Push this hub's console users who have access to "${site.name}" (via group grants or an explicit push) to that box as local logins? It replaces only hub-managed logins there -- accounts created locally on the box are left alone. Applies on its next heartbeat.`)) return;
        await api.post(`/api/sites/${site.id}/sync-users`);
        alert(`A user sync was queued for "${site.name}" -- it applies on the box's next heartbeat.`);
      }
    });
    menuItems.push({
      label: 'Delete Site',
      className: 'danger',
      onClick: async () => {
        if (confirm(`Remove site "${site.name}"? This does not affect the edge box itself.`)) {
          await api.del(`/api/sites/${site.id}`);
          await loadSites();
        }
      }
    });
    actionsCell.appendChild(buildRowMenu(menuItems));
    tbody.appendChild(tr);
  }
  const rowCheckboxes = [...tbody.querySelectorAll('.site-select')];
  document.getElementById('sitesSelectAll').checked = rowCheckboxes.length > 0 && rowCheckboxes.every((cb) => cb.checked);
}

document.getElementById('sitesSelectAll').addEventListener('change', (e) => {
  document.querySelectorAll('#sitesTable .site-select').forEach((cb) => (cb.checked = e.target.checked));
});

document.getElementById('revealPortIdsBtn').addEventListener('click', (e) => {
  const table = document.getElementById('sitesTable');
  const revealed = table.classList.toggle('reveal-ids');
  e.target.textContent = revealed ? 'Hide Port IDs' : 'Reveal Port IDs';
});

document.getElementById('bulkQueueUpdateBtn').addEventListener('click', async () => {
  const siteIds = Array.from(document.querySelectorAll('#sitesTable .site-select:checked')).map((cb) => cb.dataset.site);
  if (siteIds.length === 0) {
    alert('Select at least one site first.');
    return;
  }
  if (!confirm(`Upgrade ${siteIds.length} site${siteIds.length === 1 ? '' : 's'}? Each applies on its own next heartbeat.`)) return;
  const result = await api.post('/api/sites/queue-update/bulk', { siteIds });
  alert(`Queued an upgrade for ${result.queued} site${result.queued === 1 ? '' : 's'}.`);
});

document.getElementById('bulkSyncAdminsBtn').addEventListener('click', async () => {
  const siteIds = Array.from(document.querySelectorAll('#sitesTable .site-select:checked')).map((cb) => cb.dataset.site);
  if (siteIds.length === 0) {
    alert('Select at least one site first.');
    return;
  }
  if (!confirm(`Replace every local admin account on ${siteIds.length} site${siteIds.length === 1 ? '' : 's'} with this hub's own admin accounts? Any admin login not from the hub will stop working on those boxes. Each applies on its own next heartbeat.`)) return;
  const result = await api.post('/api/sites/sync-admins/bulk', { siteIds });
  alert(`Queued an admin sync for ${result.queued} site${result.queued === 1 ? '' : 's'}.`);
});

document.getElementById('bulkSyncUsersBtn').addEventListener('click', async () => {
  const siteIds = Array.from(document.querySelectorAll('#sitesTable .site-select:checked')).map((cb) => cb.dataset.site);
  if (siteIds.length === 0) {
    alert('Select at least one site first.');
    return;
  }
  if (!confirm(`Push this hub's console users to ${siteIds.length} site${siteIds.length === 1 ? '' : 's'} as local logins? Each site gets only the users who have access to it, and only hub-managed logins there are replaced. Each applies on its own next heartbeat.`)) return;
  const result = await api.post('/api/sites/sync-users/bulk', { siteIds });
  alert(`Queued a user sync for ${result.queued} site${result.queued === 1 ? '' : 's'}.`);
});

document.getElementById('bulkTftpUploadBtn').addEventListener('click', () => {
  const siteIds = Array.from(document.querySelectorAll('#sitesTable .site-select:checked')).map((cb) => cb.dataset.site);
  if (siteIds.length === 0) {
    alert('Select at least one site first.');
    return;
  }
  const sites = lastTopologySites.filter((s) => siteIds.includes(s.id));
  openSiteTftpUploadModal(sites);
});

function openSiteRenameModal(site) {
  document.getElementById('siteRenameSiteId').value = site.id;
  document.getElementById('siteRenameName').value = site.name;
  clearFieldError('siteRenameName');
  document.getElementById('siteRenameModalBackdrop').classList.add('open');
}
document.getElementById('cancelSiteRenameBtn').addEventListener('click', () => {
  document.getElementById('siteRenameModalBackdrop').classList.remove('open');
});
document.getElementById('siteRenameName').addEventListener('input', () => clearFieldError('siteRenameName'));
document.getElementById('saveSiteRenameBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('siteRenameSiteId').value;
  const name = document.getElementById('siteRenameName').value.trim();
  if (!name) {
    setFieldError('siteRenameName', 'A site name is required.');
    return;
  }
  try {
    await api.post(`/api/sites/${siteId}/rename`, { name });
    document.getElementById('siteRenameModalBackdrop').classList.remove('open');
    await loadSites();
  } catch (err) {
    setFieldError('siteRenameName', err.message);
  }
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
    const res = await fetch(`/api/sites/${siteId}/backup/restore`, { method: 'POST', headers: csrfHeaders(), body: formData });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    document.getElementById('siteRestoreModalBackdrop').classList.remove('open');
    alert('Restore queued -- it applies on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});

// ---------- Configure ports (hub-pushed, applied on the site's next heartbeat) ----------
const ACCESS_OPTIONS = [
  ['exclusive', 'Exclusive'],
  ['shared-rw', 'Shared (read/write)'],
  ['first-write', 'Shared (first user read/write)'],
  ['shared-ro', 'Shared (read-only)']
];

function addSitePortRow(port) {
  const tbody = document.querySelector('#sitePortsTable tbody');
  const tr = document.createElement('tr');
  // Delete only ever applies to a port that already exists on the server (it calls
  // DELETE /api/sites/:id/ports/:portId immediately) -- a row added via + Add Port or
  // Scan has no portId yet, so it only ever gets Remove (a plain client-side
  // tr.remove(), staged until Queue Port Configuration is clicked).
  const deleteBtn = port?.id ? '<button class="danger delete-port-btn">Delete…</button>' : '';
  tr.innerHTML = `
    <td><input type="text" class="site-port-label" value="${escapeHtml(port?.label || '')}" placeholder="e.g. Router Console" /></td>
    <td><input type="text" class="site-port-path" value="${escapeHtml(port?.path || '')}" placeholder="/dev/ttyUSB0" /></td>
    <td><input type="number" class="site-port-baud" value="${port?.baudRate || 9600}" style="width: 5.5em" /></td>
    <td><select class="site-port-access">${ACCESS_OPTIONS.map(([v, l]) => `<option value="${v}" ${port?.access === v ? 'selected' : ''}>${l}</option>`).join('')}</select></td>
    <td><input type="checkbox" class="site-port-capture" ${port?.captureEnabled ? 'checked' : ''} /></td>
    <td><button class="secondary remove-port-row-btn">Remove</button>${deleteBtn}</td>
  `;
  tr.dataset.portId = port?.id || '';
  tr.querySelector('.remove-port-row-btn').addEventListener('click', () => tr.remove());
  const delBtn = tr.querySelector('.delete-port-btn');
  if (delBtn) {
    delBtn.addEventListener('click', () => {
      const siteId = document.getElementById('sitePortsSiteId').value;
      openDeletePortModal(siteId, port.id, tr.querySelector('.site-port-label').value.trim() || port.label || 'this port');
    });
  }
  tbody.appendChild(tr);
}

// ---------- Delete a single port immediately (hub-only, or hub + edge) ----------
function openDeletePortModal(siteId, portId, label) {
  document.getElementById('deletePortSiteId').value = siteId;
  document.getElementById('deletePortPortId').value = portId;
  document.getElementById('deletePortLabel').textContent = label;
  document.getElementById('deletePortRemoveFromEdge').checked = true;
  document.getElementById('deletePortError').textContent = '';
  document.getElementById('deletePortModalBackdrop').classList.add('open');
}
document.getElementById('cancelDeletePortBtn').addEventListener('click', () => {
  document.getElementById('deletePortModalBackdrop').classList.remove('open');
});
document.getElementById('confirmDeletePortBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('deletePortSiteId').value;
  const portId = document.getElementById('deletePortPortId').value;
  const removeFromEdge = document.getElementById('deletePortRemoveFromEdge').checked;
  const errEl = document.getElementById('deletePortError');
  errEl.textContent = '';
  try {
    await api.del(`/api/sites/${siteId}/ports/${portId}?removeFromEdge=${removeFromEdge}`);
    document.getElementById('deletePortModalBackdrop').classList.remove('open');
    // Drop the row from the still-open Configure Ports table too, so the admin sees it
    // gone immediately instead of having to reopen the modal.
    const row = document.querySelector(`#sitePortsTable tbody tr[data-port-id="${CSS.escape(portId)}"]`);
    if (row) row.remove();
    await loadSites();
  } catch (err) {
    errEl.textContent = err.message;
  }
});

function openSitePortsModal(site) {
  document.getElementById('sitePortsSiteId').value = site.id;
  document.getElementById('sitePortsSiteName').textContent = site.name;
  document.getElementById('sitePortsError').textContent = '';
  document.getElementById('sitePortsScanResults').innerHTML = '';
  const tbody = document.querySelector('#sitePortsTable tbody');
  tbody.innerHTML = '';
  for (const port of site.ports) addSitePortRow(port);
  document.getElementById('sitePortsModalBackdrop').classList.add('open');
}
document.getElementById('addSitePortRowBtn').addEventListener('click', () => addSitePortRow(null));

// Live request/response through the tunnel (GET /api/sites/:id/devices), not a queued
// command -- see siteRegistry.requestDeviceList/tunnelClient's "listDevices" handshake.
// Lets an admin pick a real device path instead of typing one blind.
document.getElementById('scanSiteDevicesBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('sitePortsSiteId').value;
  const resultsEl = document.getElementById('sitePortsScanResults');
  const errEl = document.getElementById('sitePortsError');
  errEl.textContent = '';
  resultsEl.innerHTML = '<p class="hint">Scanning the site for available devices&hellip;</p>';
  try {
    const { ports } = await api.get(`/api/sites/${siteId}/devices`);
    // Devices already in the table (existing ports, or ones just staged with + Add) aren't
    // offered again -- they're already assigned.
    const assignedPaths = () =>
      new Set([...document.querySelectorAll('#sitePortsTable .site-port-path')].map((el) => el.value.trim()));
    const available = ports.filter((dev) => !assignedPaths().has(dev.path));
    if (!available.length) {
      resultsEl.innerHTML = `<p class="hint">${
        ports.length ? 'Every device on that site is already assigned to a port.' : 'No devices found on that site.'
      }</p>`;
      return;
    }
    const list = document.createElement('div');
    list.className = 'check-list';
    for (const dev of available) {
      const detail = [dev.manufacturer, dev.serialNumber].filter(Boolean).join(' · ');
      const row = document.createElement('div');
      row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; gap:8px;';
      row.innerHTML = `
        <span><code>${escapeHtml(dev.path)}</code>${detail ? ` <span class="hint">${escapeHtml(detail)}</span>` : ''}</span>
        <button class="secondary add-scanned-device-btn">+ Add</button>
      `;
      row.querySelector('.add-scanned-device-btn').addEventListener('click', () => {
        addSitePortRow({ label: dev.manufacturer || dev.path, path: dev.path, baudRate: 9600, access: 'exclusive', captureEnabled: false });
        row.remove();
        if (!list.children.length) resultsEl.innerHTML = '<p class="hint">Every device on that site is now assigned.</p>';
      });
      list.appendChild(row);
    }
    resultsEl.innerHTML = '';
    resultsEl.appendChild(list);
  } catch (err) {
    resultsEl.innerHTML = '';
    errEl.textContent = err.message;
  }
});
document.getElementById('cancelSitePortsBtn').addEventListener('click', () => {
  document.getElementById('sitePortsModalBackdrop').classList.remove('open');
});
document.getElementById('saveSitePortsBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('sitePortsSiteId').value;
  const errEl = document.getElementById('sitePortsError');
  const rows = document.querySelectorAll('#sitePortsTable tbody tr');
  const ports = [];
  for (const row of rows) {
    const label = row.querySelector('.site-port-label').value.trim();
    const path = row.querySelector('.site-port-path').value.trim();
    if (!label || !path) {
      errEl.textContent = 'Every port needs a label and a device path.';
      return;
    }
    ports.push({
      id: row.dataset.portId || undefined,
      label,
      path,
      baudRate: Number(row.querySelector('.site-port-baud').value) || 9600,
      access: row.querySelector('.site-port-access').value,
      captureEnabled: row.querySelector('.site-port-capture').checked
    });
  }
  if (!confirm(`Queue this port configuration for this site? It replaces the site's entire port list on its next heartbeat.`)) return;
  try {
    await api.post(`/api/sites/${siteId}/ports`, { ports });
    document.getElementById('sitePortsModalBackdrop').classList.remove('open');
    alert('Port configuration queued -- it applies on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});

// ---------- Site neighbor discovery (live over the tunnel; settings queued) ----------
async function loadSiteLldp() {
  const siteId = document.getElementById('siteLldpSiteId').value;
  const stateEl = document.getElementById('siteLldpState');
  const errEl = document.getElementById('siteLldpError');
  const emptyEl = document.getElementById('siteLldpEmpty');
  errEl.textContent = '';
  emptyEl.textContent = '';
  stateEl.textContent = 'Asking the site…';
  const tbody = document.querySelector('#siteLldpTable tbody');
  tbody.innerHTML = '';
  try {
    const data = await api.get(`/api/sites/${siteId}/lldp`);
    stateEl.textContent = !data.installed ? 'lldpd is not installed on this site (sudo apt-get install lldpd).' : data.active ? 'Neighbor discovery is running on this site.' : 'Neighbor discovery is not running on this site.';
    document.getElementById('siteLldpEnabled').checked = !!data.active;
    document.getElementById('siteLldpCdp').checked = !!data.cdp;
    document.getElementById('siteLldpFdp').checked = !!data.fdp;
    renderLldpNeighborRows(tbody, data.neighbors || []);
    if (data.neighborsError) errEl.textContent = data.neighborsError;
    else if (data.active && !(data.neighbors || []).length) emptyEl.textContent = 'No neighbors discovered yet -- switches usually announce every 30 seconds.';
  } catch (err) {
    stateEl.textContent = '';
    errEl.textContent = err.message;
  }
}

function openSiteLldpModal(site) {
  document.getElementById('siteLldpSiteId').value = site.id;
  document.getElementById('siteLldpSiteName').textContent = site.name;
  document.getElementById('siteLldpModalBackdrop').classList.add('open');
  loadSiteLldp();
}
document.getElementById('closeSiteLldpBtn').addEventListener('click', () => {
  document.getElementById('siteLldpModalBackdrop').classList.remove('open');
});
document.getElementById('refreshSiteLldpBtn').addEventListener('click', () => loadSiteLldp());
document.getElementById('applySiteLldpBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('siteLldpSiteId').value;
  const errEl = document.getElementById('siteLldpError');
  errEl.textContent = '';
  try {
    await api.post(`/api/sites/${siteId}/lldp`, {
      enabled: document.getElementById('siteLldpEnabled').checked,
      cdp: document.getElementById('siteLldpCdp').checked,
      fdp: document.getElementById('siteLldpFdp').checked
    });
    alert('Neighbor-discovery settings queued -- they apply on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});
// ---------- Local access (hub-pushed, applied on the site's next heartbeat) ----------
function openSiteLocalAccessModal(site) {
  document.getElementById('siteLocalAccessSiteId').value = site.id;
  document.getElementById('siteLocalAccessSiteName').textContent = site.name;
  document.getElementById('siteLocalAccessError').textContent = '';
  document.getElementById('siteLocalAccessSsh').checked = site.edgeSshEnabled !== false;
  document.getElementById('siteLocalAccessWeb').checked = site.edgeWebTerminalEnabled === true;
  document.getElementById('siteLocalAccessModalBackdrop').classList.add('open');
}
document.getElementById('cancelSiteLocalAccessBtn').addEventListener('click', () => {
  document.getElementById('siteLocalAccessModalBackdrop').classList.remove('open');
});
document.getElementById('saveSiteLocalAccessBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('siteLocalAccessSiteId').value;
  const errEl = document.getElementById('siteLocalAccessError');
  const sshEnabled = document.getElementById('siteLocalAccessSsh').checked;
  const webTerminalEnabled = document.getElementById('siteLocalAccessWeb').checked;
  try {
    await api.post(`/api/sites/${siteId}/local-access`, { sshEnabled, webTerminalEnabled });
    document.getElementById('siteLocalAccessModalBackdrop').classList.remove('open');
    alert('Local access change queued -- it applies on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});

// ---------- Site TFTP server (hub-pushed, applied on the site's next heartbeat) ----------
function openSiteTftpSettingsModal(site) {
  const reported = site.reportedTftp || {};
  document.getElementById('siteTftpSettingsSiteId').value = site.id;
  document.getElementById('siteTftpSettingsSiteName').textContent = site.name;
  document.getElementById('siteTftpSettingsError').textContent = '';
  document.getElementById('siteTftpSettingsEnabled').checked = reported.running === true;
  document.getElementById('siteTftpSettingsPort').value = reported.port || 69;
  document.getElementById('siteTftpSettingsAllowUpload').checked = reported.allowUpload !== false;
  document.getElementById('siteTftpSettingsAutoStart').checked = reported.autoStart === true;
  document.getElementById('siteTftpSettingsModalBackdrop').classList.add('open');
}
document.getElementById('cancelSiteTftpSettingsBtn').addEventListener('click', () => {
  document.getElementById('siteTftpSettingsModalBackdrop').classList.remove('open');
});
document.getElementById('saveSiteTftpSettingsBtn').addEventListener('click', async () => {
  const siteId = document.getElementById('siteTftpSettingsSiteId').value;
  const errEl = document.getElementById('siteTftpSettingsError');
  const enabled = document.getElementById('siteTftpSettingsEnabled').checked;
  const port = Number(document.getElementById('siteTftpSettingsPort').value);
  const allowUpload = document.getElementById('siteTftpSettingsAllowUpload').checked;
  const autoStart = document.getElementById('siteTftpSettingsAutoStart').checked;
  try {
    await api.post(`/api/sites/${siteId}/tftp-settings`, { enabled, port, allowUpload, autoStart });
    document.getElementById('siteTftpSettingsModalBackdrop').classList.remove('open');
    alert('TFTP server settings queued -- they apply on the box\'s next heartbeat.');
  } catch (err) {
    errEl.textContent = err.message;
  }
});

// ---------- Site info (live, over the tunnel) ----------
async function openSiteInfoModal(site) {
  document.getElementById('siteInfoSiteName').textContent = site.name;
  document.getElementById('siteInfoTable').hidden = true;
  document.getElementById('refreshSiteInfoBtn').hidden = true;
  document.getElementById('siteInfoError').textContent = '';
  const loadingEl = document.getElementById('siteInfoLoading');
  loadingEl.hidden = false;
  loadingEl.textContent = 'Fetching a live snapshot from the site…';
  document.getElementById('siteInfoModalBackdrop').classList.add('open');

  try {
    const info = await api.get(`/api/sites/${site.id}/info`);
    loadingEl.hidden = true;
    const ips = (info.interfaces || []).filter((i) => i.ip).map((i) => `${i.ip} (${i.name})`);
    document.getElementById('siteInfoHostname').textContent = info.hostname || '—';
    document.getElementById('siteInfoMdns').textContent = info.mdnsName || '—';
    document.getElementById('siteInfoIps').innerHTML = ips.length ? ips.map(escapeHtml).join('<br>') : '<span class="hint">none reported</span>';
    document.getElementById('siteInfoPublicIp').textContent = info.publicIp || '—';
    document.getElementById('siteInfoClients').textContent = info.clientsConnected != null ? info.clientsConnected : '—';
    document.getElementById('siteInfoOs').textContent = info.osRelease || '—';
    document.getElementById('siteInfoKernel').textContent = info.kernel || '—';
    document.getElementById('siteInfoArch').textContent = info.arch || '—';
    document.getElementById('siteInfoCpu').textContent = info.cpuModel
      ? `${info.cpuModel} (${info.cpuCores} core${info.cpuCores === 1 ? '' : 's'})${info.cpuPercent != null ? ` — ${info.cpuPercent}% used` : ''}`
      : '—';
    document.getElementById('siteInfoMemory').textContent = info.memory
      ? `${formatBytes(info.memory.used)} / ${formatBytes(info.memory.total)} (${info.memory.percent}%)`
      : '—';
    document.getElementById('siteInfoDisk').textContent = info.disk
      ? `${formatBytes(info.disk.used)} / ${formatBytes(info.disk.total)} (${info.disk.percent}%)${info.disk.mount ? ` on ${info.disk.mount}` : ''}`
      : '<span class="hint">unavailable</span>';
    document.getElementById('siteInfoUptime').textContent = info.uptimeSec != null ? formatUptime(info.uptimeSec) : '—';
    document.getElementById('siteInfoNode').textContent = info.nodeVersion || '—';
    document.getElementById('siteInfoAppVersion').textContent = info.appVersion || '—';
    document.getElementById('siteInfoTable').hidden = false;
    document.getElementById('refreshSiteInfoBtn').hidden = false;
  } catch (err) {
    loadingEl.hidden = true;
    document.getElementById('siteInfoError').textContent = err.message;
    document.getElementById('refreshSiteInfoBtn').hidden = false;
  }
  document.getElementById('refreshSiteInfoBtn').onclick = () => openSiteInfoModal(site);
}
document.getElementById('closeSiteInfoBtn').addEventListener('click', () => {
  document.getElementById('siteInfoModalBackdrop').classList.remove('open');
});

// ---------- Upload to TFTP (live, over the tunnel; one or many sites) ----------
function openSiteTftpUploadModal(sites) {
  document.getElementById('siteTftpUploadFile').value = '';
  document.getElementById('siteTftpUploadError').textContent = '';
  document.getElementById('siteTftpUploadResults').innerHTML = '';
  const targetsEl = document.getElementById('siteTftpUploadTargets');
  targetsEl.innerHTML = '';
  targetsEl.dataset.siteIds = JSON.stringify(sites.map((s) => s.id));
  for (const site of sites) {
    const row = document.createElement('div');
    row.textContent = site.name + (site.connected ? '' : ' (offline)');
    if (!site.connected) row.classList.add('hint');
    targetsEl.appendChild(row);
  }
  document.getElementById('saveSiteTftpUploadBtn').hidden = false;
  document.getElementById('cancelSiteTftpUploadBtn').textContent = 'Cancel';
  document.getElementById('siteTftpUploadModalBackdrop').classList.add('open');
}
document.getElementById('cancelSiteTftpUploadBtn').addEventListener('click', () => {
  document.getElementById('siteTftpUploadModalBackdrop').classList.remove('open');
});
document.getElementById('saveSiteTftpUploadBtn').addEventListener('click', async () => {
  const errEl = document.getElementById('siteTftpUploadError');
  const resultsEl = document.getElementById('siteTftpUploadResults');
  errEl.textContent = '';
  resultsEl.innerHTML = '';
  const fileInput = document.getElementById('siteTftpUploadFile');
  const file = fileInput.files[0];
  if (!file) {
    errEl.textContent = 'Choose a file first.';
    return;
  }
  const siteIds = JSON.parse(document.getElementById('siteTftpUploadTargets').dataset.siteIds || '[]');
  const formData = new FormData();
  formData.append('file', file);
  try {
    if (siteIds.length === 1) {
      const res = await fetch(`/api/sites/${siteIds[0]}/tftp-upload`, { method: 'POST', headers: csrfHeaders(), body: formData });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
      resultsEl.innerHTML = `<p class="hint">Uploaded "${escapeHtml(body.filename)}" (${formatBytes(body.bytesWritten)}).</p>`;
    } else {
      formData.append('siteIds', JSON.stringify(siteIds));
      const res = await fetch('/api/sites/tftp-upload/bulk', { method: 'POST', headers: csrfHeaders(), body: formData });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
      resultsEl.innerHTML = body.results
        .map((r) => `<p class="hint">${r.ok ? '✓' : '✗'} ${escapeHtml(r.name || r.siteId)}${r.ok ? '' : ` — ${escapeHtml(r.error)}`}</p>`)
        .join('');
    }
    // Done -- swap "Upload"/"Cancel" for a single "OK" so the result stays on screen
    // until the admin dismisses it, instead of implying there's still something to
    // upload or cancel.
    document.getElementById('saveSiteTftpUploadBtn').hidden = true;
    document.getElementById('cancelSiteTftpUploadBtn').textContent = 'OK';
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
    const capturePill = user.captureEnabled
      ? '<span class="pill ok"><span class="dot"></span>On</span>'
      : '<span class="pill mute"><span class="dot"></span>Off</span>';
    tr.innerHTML = `
      <td>${escapeHtml(user.username)}</td>
      <td>${groupNames.length ? groupNames.join(', ') : '<span class="hint">none</span>'}</td>
      <td>${capturePill}</td>
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

async function openUserModal(user) {
  document.getElementById('userModalTitle').textContent = user ? 'Edit User' : 'Add User';
  document.getElementById('userEditId').value = user ? user.id : '';
  document.getElementById('userUsername').value = user ? user.username : '';
  document.getElementById('userPassword').value = '';
  document.getElementById('userPasswordHint').textContent = user ? '(leave blank to keep the current password)' : '';
  document.getElementById('userPassword').required = !user;
  document.getElementById('userCaptureEnabled').checked = !!(user && user.captureEnabled);
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

  document.getElementById('userEdgePermission').value = (user && user.edgePermission) || 'read-write';
  const edgeChecksEl = document.getElementById('userEdgeSiteChecks');
  edgeChecksEl.innerHTML = '';
  try {
    const sites = await api.get('/api/sites');
    if (sites.length === 0) edgeChecksEl.innerHTML = '<span class="hint">No sites enrolled yet.</span>';
    for (const site of sites) {
      const label = document.createElement('label');
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.value = site.id;
      checkbox.checked = !!(user && (user.edgeSiteIds || []).includes(site.id));
      label.appendChild(checkbox);
      label.appendChild(document.createTextNode(site.name));
      edgeChecksEl.appendChild(label);
    }
  } catch {
    edgeChecksEl.innerHTML = '<span class="hint">Could not load sites.</span>';
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
  const captureEnabled = document.getElementById('userCaptureEnabled').checked;
  const edgeSiteIds = Array.from(document.querySelectorAll('#userEdgeSiteChecks input:checked')).map((c) => c.value);
  const edgePermission = document.getElementById('userEdgePermission').value;
  let valid = true;
  if (!username) { setFieldError('userUsername', 'A username is required.'); valid = false; }
  if (!id && !password) { setFieldError('userPassword', 'A password is required.'); valid = false; }
  if (!valid) return;
  try {
    if (id) {
      await api.post(`/api/users/${id}`, { username, groupIds, captureEnabled, edgeSiteIds, edgePermission });
      if (password) await api.post(`/api/users/${id}/password`, { password });
    } else {
      await api.post('/api/users', { username, password, groupIds, captureEnabled, edgeSiteIds, edgePermission });
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
      item.innerHTML = `<span>${escapeHtml(site ? site.name : grant.siteId)} — ${escapeHtml(port ? port.label : grant.portId)}</span>`;
      const permSelect = document.createElement('select');
      permSelect.className = 'grant-permission-select';
      permSelect.innerHTML = '<option value="read-write">Read/write</option><option value="read-only">Read-only</option>';
      permSelect.value = grant.permission === 'read-only' ? 'read-only' : 'read-write';
      permSelect.addEventListener('change', async () => {
        try {
          await api.post(`/api/groups/${group.id}/grants/${grant.siteId}/${grant.portId}/permission`, { permission: permSelect.value });
        } catch (err) {
          alert(err.message);
          await loadGroups();
        }
      });
      item.appendChild(permSelect);
      const removeLink = document.createElement('a');
      removeLink.href = '#';
      removeLink.className = 'remove';
      removeLink.textContent = 'remove';
      removeLink.addEventListener('click', async (e) => {
        e.preventDefault();
        await api.del(`/api/groups/${group.id}/grants/${grant.siteId}/${grant.portId}`);
        await loadGroups();
      });
      item.appendChild(removeLink);
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
      const row = document.createElement('div');
      row.className = 'grant-port-row';
      const portLabel = document.createElement('label');
      const portCheck = document.createElement('input');
      portCheck.type = 'checkbox';
      portCheck.className = 'grant-port-check';
      portCheck.dataset.site = site.id;
      portCheck.dataset.port = port.id;
      const alreadyGranted = isGranted(site.id, port.id);
      if (alreadyGranted) {
        portCheck.checked = true;
        portCheck.disabled = true;
        portLabel.title = 'Already granted -- change its permission from the Groups tab grant list';
      }
      portChecks.push(portCheck);
      portLabel.appendChild(portCheck);
      portLabel.appendChild(
        document.createTextNode(`${port.label}${port.access ? ` (${accessLabel(port.access)})` : ''}${alreadyGranted ? ' (already granted)' : ''}`)
      );
      row.appendChild(portLabel);
      if (!alreadyGranted) {
        const permSelect = document.createElement('select');
        permSelect.className = 'grant-port-permission';
        permSelect.dataset.site = site.id;
        permSelect.dataset.port = port.id;
        permSelect.innerHTML = '<option value="read-write">Read/write</option><option value="read-only">Read-only</option>';
        row.appendChild(permSelect);
      }
      portsEl.appendChild(row);
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
  const grants = Array.from(document.querySelectorAll('#grantSiteTree .grant-port-check:checked:not(:disabled)')).map((cb) => {
    const permSelect = document.querySelector(`.grant-port-permission[data-site="${cb.dataset.site}"][data-port="${cb.dataset.port}"]`);
    return {
      siteId: cb.dataset.site,
      portId: cb.dataset.port,
      permission: permSelect ? permSelect.value : 'read-write'
    };
  });
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
      <td>${formatBytes(s.rxBytes || 0)} / ${formatBytes(s.txBytes || 0)}</td>
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

// ---------- Admin accounts (multiple hub admins, same shape as the appliance's own) ----------
function formatLastLogin(iso) {
  return iso ? new Date(iso).toLocaleString() : '<span class="hint">Never</span>';
}

async function loadAdminsTable() {
  const admins = await api.get('/api/admins');
  admins.sort((a, b) => a.username.localeCompare(b.username, undefined, { sensitivity: 'base' }));
  const tbody = document.querySelector('#adminsTable tbody');
  tbody.innerHTML = '';
  for (const a of admins) {
    const tr = document.createElement('tr');
    const statusPillHtml = a.mustChangePassword
      ? '<span class="pill mute"><span class="dot"></span>Must change password</span>'
      : '<span class="pill ok"><span class="dot"></span>Active</span>';
    const totpPill = a.totpEnabled
      ? '<span class="pill ok"><span class="dot"></span>On</span>'
      : '<span class="pill mute"><span class="dot"></span>Off</span>';
    tr.innerHTML = `
      <td>${escapeHtml(a.username)}${a.isSelf ? ' <span class="hint">(you)</span>' : ''}</td>
      <td>${statusPillHtml}</td>
      <td>${totpPill}</td>
      <td>${formatLastLogin(a.lastLoginAt)}</td>
      <td></td>
    `;
    const actionsCell = tr.lastElementChild;
    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.addEventListener('click', () => openAdminModal(a));
    actionsCell.appendChild(editBtn);
    if (!a.isSelf) {
      const delBtn = document.createElement('button');
      delBtn.textContent = 'Delete';
      delBtn.className = 'danger';
      delBtn.style.marginLeft = '6px';
      delBtn.addEventListener('click', async () => {
        if (confirm(`Delete admin account "${a.username}"?`)) {
          try {
            await api.del(`/api/admins/${a.id}`);
            await loadAdminsTable();
          } catch (err) {
            alert(err.message);
          }
        }
      });
      actionsCell.appendChild(delBtn);
    }
    tbody.appendChild(tr);
  }
}

function openAdminModal(admin) {
  document.getElementById('adminModalTitle').textContent = admin ? 'Edit Admin' : 'Add Admin';
  document.getElementById('adminId').value = admin?.id || '';
  document.getElementById('adminUsername').value = admin?.username || '';
  document.getElementById('adminPassword').value = '';
  document.getElementById('adminPasswordConfirm').value = '';
  document.getElementById('adminPasswordHint').style.display = admin ? 'inline' : 'none';
  clearFieldError('adminUsername');
  clearFieldError('adminPassword');
  document.getElementById('adminModalBackdrop').classList.add('open');
}

function closeAdminModal() {
  document.getElementById('adminModalBackdrop').classList.remove('open');
}

document.getElementById('addAdminBtn').addEventListener('click', () => openAdminModal(null));
document.getElementById('cancelAdminBtn').addEventListener('click', closeAdminModal);
document.getElementById('adminUsername').addEventListener('input', () => clearFieldError('adminUsername'));
document.getElementById('adminPassword').addEventListener('input', () => clearFieldError('adminPassword'));

document.getElementById('saveAdminBtn').addEventListener('click', async () => {
  const id = document.getElementById('adminId').value;
  const username = document.getElementById('adminUsername').value.trim();
  const password = document.getElementById('adminPassword').value;
  const confirmPassword = document.getElementById('adminPasswordConfirm').value;
  let valid = true;
  if (!username) {
    setFieldError('adminUsername', 'Username is required.');
    valid = false;
  }
  if (!id && !password) {
    setFieldError('adminPassword', 'A password is required for a new admin.');
    valid = false;
  }
  if (password && password.length < 8) {
    setFieldError('adminPassword', 'Password must be at least 8 characters.');
    valid = false;
  }
  if (password && password !== confirmPassword) {
    setFieldError('adminPassword', 'Passwords do not match.');
    valid = false;
  }
  if (!valid) return;
  try {
    if (id) {
      await api.post(`/api/admins/${id}`, { username, password: password || undefined });
    } else {
      await api.post('/api/admins', { username, password });
    }
    closeAdminModal();
    await loadAdminsTable();
    await loadMyUsername();
  } catch (err) {
    setFieldError('adminUsername', err.message);
  }
});

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

// ---------- Tunnel/SSH listener settings ----------
async function loadSshSettings() {
  const ssh = await api.get('/api/ssh-settings');
  document.getElementById('sshPort').value = ssh.port;
}
document.getElementById('saveSshSettingsBtn').addEventListener('click', async () => {
  const msg = document.getElementById('sshSettingsMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  const port = Number(document.getElementById('sshPort').value);
  if (!confirm(`Save port ${port} as the tunnel/SSH listener port? This only takes effect after the service restarts -- every currently-connected site will need its own Tunnel Port updated to match before it can reconnect.`)) {
    return;
  }
  try {
    await api.post('/api/ssh-settings', { port });
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Saved -- restart the service (below) to apply it.';
  } catch (err) {
    msg.textContent = err.message;
  }
});

// ---------- High availability ----------
const HA_DEFAULTS = {
  enabled: false,
  mode: 'vip',
  role: 'primary',
  peerHost: '',
  listenPort: 8555,
  peerPort: 8555,
  vip: { address: '', prefix: 24, interface: 'eth0' },
  dns: { updateCommand: '' },
  healthCheck: { intervalMs: 3000, failureThreshold: 3, timeoutMs: 2000 },
  replication: { intervalMs: 5000, remoteDataDir: '/opt/central-office/data', sshUser: 'central-office', sshKeyPath: '/opt/central-office/ha-agent/replication-key' },
  preemptOnRecovery: false
};

function applyHaModeVisibility() {
  const mode = document.getElementById('haModeSelect').value;
  document.getElementById('haVipFields').hidden = mode !== 'vip';
  document.getElementById('haDnsFields').hidden = mode !== 'dns';
}

function fillHaConfigForm(cfg) {
  document.getElementById('haEnabled').checked = !!cfg.enabled;
  document.getElementById('haRoleSelect').value = cfg.role || 'primary';
  document.getElementById('haModeSelect').value = cfg.mode || 'vip';
  document.getElementById('haPeerHost').value = cfg.peerHost || '';
  document.getElementById('haListenPort').value = cfg.listenPort || 8555;
  document.getElementById('haPeerPort').value = cfg.peerPort || 8555;
  const vip = cfg.vip || {};
  document.getElementById('haVipAddress').value = vip.address || '';
  document.getElementById('haVipPrefix').value = vip.prefix != null ? vip.prefix : 24;
  document.getElementById('haVipInterface').value = vip.interface || 'eth0';
  document.getElementById('haDnsCommand').value = (cfg.dns && cfg.dns.updateCommand) || '';
  const hc = cfg.healthCheck || {};
  document.getElementById('haHcInterval').value = hc.intervalMs || 3000;
  document.getElementById('haHcThreshold').value = hc.failureThreshold || 3;
  document.getElementById('haHcTimeout').value = hc.timeoutMs || 2000;
  const rep = cfg.replication || {};
  document.getElementById('haRepInterval').value = rep.intervalMs || 5000;
  document.getElementById('haRepRemoteDir').value = rep.remoteDataDir || '';
  document.getElementById('haRepSshUser').value = rep.sshUser || '';
  document.getElementById('haRepSshKey').value = rep.sshKeyPath || '';
  document.getElementById('haPreempt').checked = !!cfg.preemptOnRecovery;
  applyHaModeVisibility();
}

function readHaConfigForm() {
  return {
    enabled: document.getElementById('haEnabled').checked,
    role: document.getElementById('haRoleSelect').value,
    mode: document.getElementById('haModeSelect').value,
    peerHost: document.getElementById('haPeerHost').value.trim(),
    listenPort: Number(document.getElementById('haListenPort').value),
    peerPort: Number(document.getElementById('haPeerPort').value),
    vip: {
      address: document.getElementById('haVipAddress').value.trim(),
      prefix: Number(document.getElementById('haVipPrefix').value),
      interface: document.getElementById('haVipInterface').value.trim()
    },
    dns: { updateCommand: document.getElementById('haDnsCommand').value.trim() },
    healthCheck: {
      intervalMs: Number(document.getElementById('haHcInterval').value),
      failureThreshold: Number(document.getElementById('haHcThreshold').value),
      timeoutMs: Number(document.getElementById('haHcTimeout').value)
    },
    replication: {
      intervalMs: Number(document.getElementById('haRepInterval').value),
      remoteDataDir: document.getElementById('haRepRemoteDir').value.trim(),
      sshUser: document.getElementById('haRepSshUser').value.trim(),
      sshKeyPath: document.getElementById('haRepSshKey').value.trim()
    },
    preemptOnRecovery: document.getElementById('haPreempt').checked
  };
}

async function loadHaConfig() {
  const cfg = await api.get('/api/ha/config');
  fillHaConfigForm(cfg.configured === false ? HA_DEFAULTS : cfg);
}

document.getElementById('haModeSelect').addEventListener('change', applyHaModeVisibility);

document.getElementById('haReloadConfigBtn').addEventListener('click', () => {
  const msg = document.getElementById('haConfigMsg');
  msg.textContent = '';
  loadHaConfig().catch((err) => {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  });
});

document.getElementById('haSaveConfigBtn').addEventListener('click', async () => {
  const msg = document.getElementById('haConfigMsg');
  msg.textContent = '';
  try {
    const result = await api.post('/api/ha/config', readHaConfigForm());
    msg.style.color = 'var(--ok)';
    msg.textContent = result.agentNotified
      ? 'Saved and applied live to the running ha-agent.'
      : 'Saved. The ha-agent on this node is not reachable yet -- start its systemd service to apply this (see README).';
    await loadHaStatus();
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

async function loadHaStatus() {
  const status = await api.get('/api/ha/status');
  renderTopology(lastTopologySites, status);
  const section = document.getElementById('haStatusSection');
  if (status.configured === false) {
    section.hidden = true;
    return;
  }
  section.hidden = false;
  document.getElementById('haRole').textContent = status.role === 'primary' ? 'Primary' : 'Secondary';
  document.getElementById('haIsActive').innerHTML = status.isActive
    ? '<span class="pill ok"><span class="dot"></span>Active</span>'
    : '<span class="pill mute"><span class="dot"></span>Standby</span>';
  document.getElementById('haMode').textContent = status.mode === 'vip' ? 'Virtual IP' : 'DNS update';
  const peerHealthy = status.consecutiveFailures === 0;
  document.getElementById('haPeerHealth').innerHTML = peerHealthy
    ? '<span class="pill ok"><span class="dot"></span>Healthy</span>'
    : `<span class="pill warn"><span class="dot"></span>${status.consecutiveFailures} consecutive check${status.consecutiveFailures === 1 ? '' : 's'} failed</span>`;
  document.getElementById('haLastReplication').innerHTML = status.isActive
    ? '<span class="hint">n/a -- this node is active, it does not pull</span>'
    : status.lastReplicationAt
      ? `${new Date(status.lastReplicationAt).toLocaleString()}${status.lastReplicationError ? ` <span class="pill warn">last attempt failed: ${escapeHtml(status.lastReplicationError)}</span>` : ''}`
      : '<span class="hint">never</span>';
  document.getElementById('haPromotedAt').textContent = status.promotedAt ? new Date(status.promotedAt).toLocaleString() : 'never';
  // Reclaiming only makes sense from a node that's currently standby -- promoting an
  // already-active node is a no-op the agent itself already guards, but hiding the
  // button here avoids implying there's something to reclaim when there isn't.
  document.getElementById('haPromoteBtn').hidden = status.isActive;
}

document.getElementById('haRefreshBtn').addEventListener('click', () => loadHaStatus().catch((err) => alert(err.message)));

document.getElementById('haPromoteBtn').addEventListener('click', async () => {
  if (!confirm('Reclaim the primary role on this node? This claims the virtual IP (or updates DNS) and starts the main service here -- only do this once you\'re sure the other node has actually stepped down, to avoid both nodes being active at once.')) {
    return;
  }
  const msg = document.getElementById('haMsg');
  msg.textContent = '';
  try {
    await api.post('/api/ha/promote');
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Promotion requested.';
    await loadHaStatus();
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

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
document.getElementById('downloadLogBtn').addEventListener('click', () => {
  window.location.href = '/api/log/download';
});

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
    const res = await fetch('/api/restore', { method: 'POST', headers: csrfHeaders(), body: formData });
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

// ---------- External syslog server ----------
async function loadSyslogSettings() {
  const syslog = await api.get('/api/syslog');
  document.getElementById('syslogEnabled').checked = syslog.enabled;
  document.getElementById('syslogHost').value = syslog.host;
  document.getElementById('syslogPort').value = syslog.port;
  document.getElementById('syslogFacility').value = String(syslog.facility);
}

document.getElementById('saveSyslogBtn').addEventListener('click', async () => {
  const msg = document.getElementById('syslogMsg');
  msg.textContent = '';
  try {
    await api.post('/api/syslog', {
      enabled: document.getElementById('syslogEnabled').checked,
      host: document.getElementById('syslogHost').value.trim(),
      port: Number(document.getElementById('syslogPort').value) || 514,
      facility: Number(document.getElementById('syslogFacility').value)
    });
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Saved.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

document.getElementById('testSyslogBtn').addEventListener('click', async () => {
  const msg = document.getElementById('syslogMsg');
  msg.textContent = '';
  try {
    await api.post('/api/syslog/test');
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Test message sent.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

async function loadAlertsSettings() {
  const alerts = await api.get('/api/alerts');
  document.getElementById('alertsWebhookUrl').value = alerts.webhookUrl;
  document.getElementById('alertsNotifyOnSiteOffline').checked = alerts.notifyOnSiteOffline;
  document.getElementById('alertsNotifyOnLockout').checked = alerts.notifyOnLockout;
}

document.getElementById('saveAlertsBtn').addEventListener('click', async () => {
  const msg = document.getElementById('alertsMsg');
  msg.textContent = '';
  try {
    await api.post('/api/alerts', {
      webhookUrl: document.getElementById('alertsWebhookUrl').value.trim(),
      notifyOnSiteOffline: document.getElementById('alertsNotifyOnSiteOffline').checked,
      notifyOnLockout: document.getElementById('alertsNotifyOnLockout').checked
    });
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Saved.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

document.getElementById('testAlertsBtn').addEventListener('click', async () => {
  const msg = document.getElementById('alertsMsg');
  msg.textContent = '';
  try {
    await api.post('/api/alerts/test');
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Test alert sent.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

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
  eventSource.addEventListener('stats', (e) => renderStats(JSON.parse(e.data)));
  eventSource.addEventListener('tftp-status', (e) => setTftpStatus(JSON.parse(e.data).running));
}

// ---------- Formatting helpers ----------
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

function formatUptime(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (days || hours) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  return parts.join(' ');
}

// ---------- Dashboard / system info ----------
function setBar(fillEl, percent) {
  const pct = Math.max(0, Math.min(100, percent || 0));
  fillEl.style.width = `${pct}%`;
  fillEl.classList.toggle('warn', pct >= 70 && pct < 90);
  fillEl.classList.toggle('danger', pct >= 90);
}

function renderStats(stats) {
  document.getElementById('statCpu').textContent = `${stats.cpuPercent.toFixed(1)}%`;
  setBar(document.getElementById('statCpuBar'), stats.cpuPercent);

  document.getElementById('statMem').textContent = `${stats.memory.percent.toFixed(1)}%`;
  setBar(document.getElementById('statMemBar'), stats.memory.percent);
  document.getElementById('statMemSub').textContent =
    `${formatBytes(stats.memory.used)} / ${formatBytes(stats.memory.total)}`;

  if (stats.disk) {
    document.getElementById('statDisk').textContent = `${stats.disk.percent.toFixed(1)}%`;
    setBar(document.getElementById('statDiskBar'), stats.disk.percent);
    document.getElementById('statDiskSub').textContent =
      `${formatBytes(stats.disk.used)} / ${formatBytes(stats.disk.total)}`;
  }

  document.getElementById('systemUptime').textContent = formatUptime(stats.uptimeSec);
  document.getElementById('statClients').textContent = stats.clientsConnected;
}

async function loadSystemInfo() {
  const info = await api.get('/api/system/info');
  document.getElementById('systemHostname').value = info.hostname;
  document.getElementById('infoHostname').textContent = info.hostname;
  document.getElementById('infoOsRelease').textContent = info.osRelease || 'Unknown';
  document.getElementById('infoKernel').textContent = info.kernel;
  document.getElementById('infoArch').textContent = info.arch;
  document.getElementById('infoCpu').textContent = `${info.cpuModel} (${info.cpuCores} core${info.cpuCores === 1 ? '' : 's'})`;
  document.getElementById('infoMemory').textContent = formatBytes(info.totalMemory);
  document.getElementById('infoDisk').textContent = info.disk
    ? `${formatBytes(info.disk.used)} / ${formatBytes(info.disk.total)} used (${info.disk.mount})`
    : 'Unknown';
  document.getElementById('infoNode').textContent = info.nodeVersion;
  document.getElementById('infoAppVersion').textContent = info.appVersion;
}

document.getElementById('refreshSystemInfoBtn').addEventListener('click', () => loadSystemInfo().catch((err) => alert(err.message)));

document.getElementById('saveHostnameBtn').addEventListener('click', async () => {
  const msg = document.getElementById('systemControlMsg');
  msg.textContent = '';
  const hostname = document.getElementById('systemHostname').value.trim();
  try {
    const result = await api.post('/api/system/hostname', { hostname });
    msg.style.color = 'var(--ok)';
    msg.textContent = `Hostname updated to "${result.hostname}".`;
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

// ---------- Network ----------
function renderNetworkInterfaces(interfaces) {
  const tbody = document.querySelector('#networkInterfacesTable tbody');
  const empty = document.getElementById('networkInterfacesEmpty');
  tbody.innerHTML = '';
  empty.style.display = interfaces.length ? 'none' : '';
  for (const iface of interfaces) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(iface.name)}</td>
      <td>${escapeHtml(iface.type)}</td>
      <td><span class="status-pill inline${iface.state === 'connected' ? ' running' : ''}"><span class="dot"></span>${escapeHtml(iface.state)}</span></td>
      <td>${escapeHtml(iface.ip || '—')}</td>
      <td>${escapeHtml(iface.connection || '—')}</td>
    `;
    tbody.appendChild(tr);
  }
}

let timezonesLoaded = false;
async function loadTimezoneList() {
  if (timezonesLoaded) return;
  const zones = await api.get('/api/network/timezones');
  const select = document.getElementById('timezoneInput');
  const saveBtn = document.getElementById('saveTimezoneBtn');
  if (zones.length === 0) {
    select.innerHTML = '<option value="">Unavailable in this environment</option>';
    select.disabled = true;
    saveBtn.disabled = true;
    saveBtn.title = 'Requires timedatectl (systemd), which this host does not have.';
    return;
  }
  select.disabled = false;
  saveBtn.disabled = false;
  saveBtn.title = '';
  select.innerHTML = zones.map((z) => `<option value="${escapeHtml(z)}">${escapeHtml(z)}</option>`).join('');
  timezonesLoaded = true;
}

function setTimezoneUi(timezone) {
  const select = document.getElementById('timezoneInput');
  if (select.disabled) return;
  if (timezone && ![...select.options].some((o) => o.value === timezone)) {
    select.insertAdjacentHTML('afterbegin', `<option value="${escapeHtml(timezone)}">${escapeHtml(timezone)}</option>`);
  }
  select.value = timezone || '';
}

function setNtpSyncUi(synchronized) {
  const pill = document.getElementById('ntpSyncPill');
  const text = document.getElementById('ntpSyncText');
  pill.classList.toggle('running', synchronized === true);
  text.textContent = synchronized === true ? 'Synced' : synchronized === false ? 'Not synced' : 'Unknown';
}

function prefixToMask(prefix) {
  const bits = '1'.repeat(prefix).padEnd(32, '0');
  return [0, 8, 16, 24].map((i) => parseInt(bits.slice(i, i + 8), 2)).join('.');
}

function populateStaticIpDevices(interfaces) {
  const select = document.getElementById('staticIpDevice');
  const previous = select.value;
  select.innerHTML = interfaces
    .map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)} (${escapeHtml(i.type)})</option>`)
    .join('');
  if (previous && [...select.options].some((o) => o.value === previous)) {
    select.value = previous;
  }
}

async function loadStaticIpConfig() {
  const device = document.getElementById('staticIpDevice').value;
  const msg = document.getElementById('staticIpMsg');
  const pill = document.getElementById('staticIpModePill');
  const text = document.getElementById('staticIpModeText');
  msg.textContent = '';
  if (!device) {
    pill.classList.remove('running');
    text.textContent = '—';
    return;
  }
  try {
    const config = await api.get(`/api/network/interfaces/${encodeURIComponent(device)}/ip-config`);
    const isManual = config.method === 'manual';
    pill.classList.toggle('running', isManual);
    text.textContent = isManual ? 'Static' : 'DHCP';
    document.getElementById('staticIpAddress').value = config.address || '';
    document.getElementById('staticIpMask').value = config.prefix != null ? prefixToMask(config.prefix) : '';
    document.getElementById('staticIpGateway').value = config.gateway || '';
  } catch (err) {
    pill.classList.remove('running');
    text.textContent = '—';
    document.getElementById('staticIpAddress').value = '';
    document.getElementById('staticIpMask').value = '';
    document.getElementById('staticIpGateway').value = '';
    msg.textContent = err.message;
  }
}

document.getElementById('staticIpDevice').addEventListener('change', () => loadStaticIpConfig());

async function loadNetwork() {
  const data = await api.get('/api/network');
  renderNetworkInterfaces(data.interfaces);
  document.getElementById('publicIpValue').textContent = data.publicIp || 'unavailable';
  document.getElementById('ntpServer').value = data.ntp.server;
  setNtpSyncUi(data.ntp.synchronized);
  document.getElementById('dnsServers').value = data.dns.join(', ');
  await loadTimezoneList();
  setTimezoneUi(data.timezone);
  populateStaticIpDevices(data.interfaces);
  await loadStaticIpConfig();
  loadLldp().catch((err) => {
    document.getElementById('lldpMsg').textContent = err.message;
  });
}

document.getElementById('refreshNetworkBtn').addEventListener('click', () => loadNetwork());
// ---------- Neighbor discovery (LLDP / CDP / FDP) ----------
function renderLldpNeighborRows(tbody, neighbors) {
  tbody.innerHTML = '';
  for (const n of neighbors) {
    const tr = document.createElement('tr');
    const neighborLabel = n.chassisName || n.chassisId || '';
    const neighborTitle = [n.description, n.chassisId && n.chassisName ? `Chassis ID: ${n.chassisId}` : ''].filter(Boolean).join('\n');
    tr.innerHTML = `
      <td>${escapeHtml(n.localInterface || '')}</td>
      <td>${escapeHtml(n.protocol || '')}</td>
      <td title="${escapeHtml(neighborTitle)}">${escapeHtml(neighborLabel)}</td>
      <td title="${escapeHtml(n.portDescription || '')}">${escapeHtml(n.portId || '')}</td>
      <td>${n.managementIps.length ? n.managementIps.map(escapeHtml).join('<br>') : '<span class="hint">&mdash;</span>'}</td>
      <td>${escapeHtml(n.vlan || '')}</td>
      <td>${escapeHtml((n.capabilities || []).join(', '))}</td>
      <td>${escapeHtml(n.age || '')}</td>
    `;
    tbody.appendChild(tr);
  }
}

function applyLldpStatus(data) {
  document.getElementById('lldpEnabled').checked = !!data.active;
  document.getElementById('lldpCdp').checked = !!data.cdp;
  document.getElementById('lldpFdp').checked = !!data.fdp;
  const pill = document.getElementById('lldpStatusPill');
  pill.classList.toggle('running', !!data.active);
  document.getElementById('lldpStatusText').textContent = !data.installed ? 'lldpd not installed' : data.active ? 'Running' : 'Stopped';
  const msg = document.getElementById('lldpMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = !data.installed ? 'lldpd is not installed on this host (sudo apt-get install lldpd).' : data.neighborsError || '';
  const neighbors = data.neighbors || [];
  renderLldpNeighborRows(document.querySelector('#lldpNeighborsTable tbody'), neighbors);
  const empty = document.getElementById('lldpNeighborsEmpty');
  empty.style.display = neighbors.length ? 'none' : '';
  empty.textContent = data.active ? 'No neighbors discovered yet -- switches usually announce every 30 seconds.' : 'Neighbor discovery is not running.';
}

async function loadLldp() {
  applyLldpStatus(await api.get('/api/lldp'));
}

document.getElementById('refreshLldpBtn').addEventListener('click', () => loadLldp().catch((err) => (document.getElementById('lldpMsg').textContent = err.message)));
document.getElementById('saveLldpBtn').addEventListener('click', async () => {
  const msg = document.getElementById('lldpMsg');
  msg.textContent = '';
  try {
    applyLldpStatus(
      await api.post('/api/lldp', {
        enabled: document.getElementById('lldpEnabled').checked,
        cdp: document.getElementById('lldpCdp').checked,
        fdp: document.getElementById('lldpFdp').checked
      })
    );
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

document.getElementById('saveStaticIpBtn').addEventListener('click', async () => {
  const device = document.getElementById('staticIpDevice').value;
  const msg = document.getElementById('staticIpMsg');
  msg.textContent = '';
  if (!device) {
    msg.style.color = 'var(--danger)';
    msg.textContent = 'Choose an interface first.';
    return;
  }
  const address = document.getElementById('staticIpAddress').value.trim();
  const mask = document.getElementById('staticIpMask').value.trim();
  const gateway = document.getElementById('staticIpGateway').value.trim();
  if (
    !confirm(
      `Set a static IP on ${device}? If anything here is wrong, this interface -- possibly including this admin UI, if you're reaching it through here -- could become unreachable until someone fixes it via SSH or the hypervisor console.`
    )
  ) {
    return;
  }
  try {
    await api.post(`/api/network/interfaces/${encodeURIComponent(device)}/ip`, { address, mask, gateway });
    await loadStaticIpConfig();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Saved.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

document.getElementById('clearStaticIpBtn').addEventListener('click', async () => {
  const device = document.getElementById('staticIpDevice').value;
  const msg = document.getElementById('staticIpMsg');
  msg.textContent = '';
  if (!device) return;
  if (!confirm(`Revert ${device} to DHCP?`)) return;
  try {
    await api.post(`/api/network/interfaces/${encodeURIComponent(device)}/ip/clear`);
    await loadStaticIpConfig();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Reverted to DHCP.';
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

document.getElementById('saveNtpBtn').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const msgEl = document.getElementById('timeDnsMsg');
  msgEl.textContent = '';
  const server = document.getElementById('ntpServer').value.trim();
  if (!server) {
    msgEl.textContent = 'NTP server is required';
    return;
  }
  btn.disabled = true;
  try {
    await api.post('/api/network/ntp', { server });
    await loadNetwork();
  } catch (err) {
    msgEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('saveTimezoneBtn').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const msgEl = document.getElementById('timeDnsMsg');
  msgEl.textContent = '';
  const timezone = document.getElementById('timezoneInput').value.trim();
  if (!timezone) {
    msgEl.textContent = 'Timezone is required';
    return;
  }
  btn.disabled = true;
  try {
    await api.post('/api/network/timezone', { timezone });
    await loadNetwork();
  } catch (err) {
    msgEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('saveDnsBtn').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const msgEl = document.getElementById('timeDnsMsg');
  msgEl.textContent = '';
  btn.disabled = true;
  try {
    await api.post('/api/network/dns', { servers: document.getElementById('dnsServers').value });
    await loadNetwork();
  } catch (err) {
    msgEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('clearDnsBtn').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const msgEl = document.getElementById('timeDnsMsg');
  msgEl.textContent = '';
  btn.disabled = true;
  try {
    await api.post('/api/network/dns', { servers: '' });
    await loadNetwork();
  } catch (err) {
    msgEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

// ---------- TFTP ----------
function setTftpStatus(running) {
  const pill = document.getElementById('tftpStatusPill');
  const text = document.getElementById('tftpStatusText');
  const btn = document.getElementById('toggleTftpBtn');
  pill.classList.toggle('running', running);
  text.textContent = running ? 'Running' : 'Stopped';
  btn.textContent = running ? 'Stop Server' : 'Start Server';
}

async function loadTftpSettings() {
  const config = await api.get('/api/tftp-settings');
  document.getElementById('tftpPort').value = config.port;
  document.getElementById('tftpAllowUpload').checked = config.allowUpload;
  document.getElementById('tftpAutoStart').checked = config.autoStart;
  const status = await api.get('/api/tftp/status');
  setTftpStatus(status.running);
}

document.getElementById('saveTftpSettingsBtn').addEventListener('click', async () => {
  await api.post('/api/tftp-settings', {
    port: Number(document.getElementById('tftpPort').value),
    allowUpload: document.getElementById('tftpAllowUpload').checked,
    autoStart: document.getElementById('tftpAutoStart').checked
  });
});

document.getElementById('toggleTftpBtn').addEventListener('click', async () => {
  const status = await api.get('/api/tftp/status');
  try {
    const result = status.running ? await api.post('/api/tftp/stop') : await api.post('/api/tftp/start');
    setTftpStatus(result.running);
  } catch (err) {
    alert(err.message);
  }
});

async function loadTftpFiles() {
  const files = await api.get('/api/tftp/files');
  const tbody = document.querySelector('#tftpFilesTable tbody');
  const empty = document.getElementById('tftpFilesEmpty');
  tbody.innerHTML = '';
  empty.style.display = files.length ? 'none' : 'block';
  for (const f of files) {
    const tr = document.createElement('tr');
    const nameCell = document.createElement('td');
    const link = document.createElement('a');
    link.href = `/api/tftp/files/${encodeURIComponent(f.name)}`;
    link.textContent = f.name;
    nameCell.appendChild(link);
    tr.appendChild(nameCell);
    const sizeCell = document.createElement('td');
    sizeCell.textContent = formatBytes(f.size);
    tr.appendChild(sizeCell);
    const modCell = document.createElement('td');
    modCell.textContent = new Date(f.modifiedAt).toLocaleString();
    tr.appendChild(modCell);
    const actionsCell = document.createElement('td');
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.className = 'danger';
    delBtn.addEventListener('click', async () => {
      if (confirm(`Delete "${f.name}"?`)) {
        await api.del(`/api/tftp/files/${encodeURIComponent(f.name)}`);
        await loadTftpFiles();
      }
    });
    actionsCell.appendChild(delBtn);
    tr.appendChild(actionsCell);
    tbody.appendChild(tr);
  }
}

document.getElementById('tftpUploadBtn').addEventListener('click', () => {
  document.getElementById('tftpUploadInput').click();
});

document.getElementById('tftpUploadInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  const msg = document.getElementById('tftpUploadMsg');
  msg.textContent = '';
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch('/api/tftp/files', { method: 'POST', headers: csrfHeaders(), body: formData });
    if (!res.ok) throw await apiError(res);
    await loadTftpFiles();
  } catch (err) {
    msg.textContent = err.message;
  }
});

// ---------- Session captures ----------
async function loadCaptures() {
  const captures = await api.get('/api/captures');
  const tbody = document.querySelector('#capturesTable tbody');
  const empty = document.getElementById('capturesEmpty');
  tbody.innerHTML = '';
  empty.style.display = captures.length ? 'none' : 'block';
  for (const c of captures) {
    const tr = document.createElement('tr');
    const nameCell = document.createElement('td');
    const link = document.createElement('a');
    link.href = `/api/captures/${encodeURIComponent(c.name)}`;
    link.textContent = c.name;
    nameCell.appendChild(link);
    tr.appendChild(nameCell);
    const sizeCell = document.createElement('td');
    sizeCell.textContent = formatBytes(c.size);
    tr.appendChild(sizeCell);
    const modCell = document.createElement('td');
    modCell.textContent = new Date(c.modifiedAt).toLocaleString();
    tr.appendChild(modCell);
    const actionsCell = document.createElement('td');
    const delBtn = document.createElement('button');
    delBtn.textContent = 'Delete';
    delBtn.className = 'danger';
    delBtn.addEventListener('click', async () => {
      if (confirm(`Delete capture "${c.name}"?`)) {
        await api.del(`/api/captures/${encodeURIComponent(c.name)}`);
        await loadCaptures();
      }
    });
    actionsCell.appendChild(delBtn);
    tr.appendChild(actionsCell);
    tbody.appendChild(tr);
  }
}

document.getElementById('refreshCapturesBtn').addEventListener('click', () => loadCaptures());

// ---------- TLS certificate ----------
async function loadTlsInfo() {
  try {
    const info = await api.get('/api/tls/info');
    document.getElementById('tlsType').textContent = info.selfSigned ? 'Self-signed (auto-generated)' : 'Custom';
    document.getElementById('tlsSubject').textContent = info.subject;
    document.getElementById('tlsIssuer').textContent = info.issuer;
    document.getElementById('tlsValidity').textContent =
      `${new Date(info.validFrom).toLocaleDateString()} – ${new Date(info.validTo).toLocaleDateString()}` +
      (info.expired ? ' (expired)' : '');
    document.getElementById('tlsFingerprint').textContent = info.fingerprint;
  } catch (err) {
    document.getElementById('tlsMsg').textContent = err.message;
  }
}

document.getElementById('uploadTlsCertBtn').addEventListener('click', async () => {
  const msg = document.getElementById('tlsMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  const certFile = document.getElementById('tlsCertFile').files[0];
  const keyFile = document.getElementById('tlsKeyFile').files[0];
  if (!certFile || !keyFile) {
    msg.textContent = 'Choose both a certificate file and a private key file.';
    return;
  }
  const formData = new FormData();
  formData.append('cert', certFile);
  formData.append('key', keyFile);
  try {
    const res = await fetch('/api/tls/upload', { method: 'POST', headers: csrfHeaders(), body: formData });
    if (!res.ok) throw await apiError(res);
    document.getElementById('tlsCertFile').value = '';
    document.getElementById('tlsKeyFile').value = '';
    await loadTlsInfo();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Certificate uploaded. Restart the service for it to take effect.';
  } catch (err) {
    msg.textContent = err.message;
  }
});

document.getElementById('revertTlsCertBtn').addEventListener('click', async () => {
  if (!confirm('Discard the current certificate and generate a fresh self-signed one?')) return;
  const msg = document.getElementById('tlsMsg');
  msg.style.color = 'var(--danger)';
  msg.textContent = '';
  try {
    await api.post('/api/tls/revert');
    await loadTlsInfo();
    msg.style.color = 'var(--ok)';
    msg.textContent = 'Reverted to a self-signed certificate. Restart the service for it to take effect.';
  } catch (err) {
    msg.textContent = err.message;
  }
});

document.getElementById('restartServiceBtn').addEventListener('click', async () => {
  if (!confirm('Restart the service now? Active tunnels and web/SSH sessions will briefly disconnect.')) return;
  const msg = document.getElementById('tlsMsg');
  msg.style.color = 'var(--text-dim)';
  msg.textContent = 'Restarting…';
  try {
    await api.post('/api/system/restart-service');
    const backUp = await pollUntilBackUp(() => {
      msg.textContent = 'Waiting for the service to come back...';
    });
    if (backUp) {
      msg.style.color = 'var(--ok)';
      msg.textContent = 'Back up. Reloading…';
      setTimeout(() => window.location.reload(), 1000);
    } else {
      msg.style.color = 'var(--danger)';
      msg.textContent = 'Did not come back within 3 minutes — check on it directly.';
    }
  } catch (err) {
    msg.style.color = 'var(--danger)';
    msg.textContent = err.message;
  }
});

// ---------- Users: CSV import ----------
document.getElementById('downloadUserTemplateBtn').addEventListener('click', () => {
  const template =
    'username,password,groups,capture\n' + 'alice,changeme123,NOC Team,yes\n' + 'bob,changeme456,"NOC Team;Lab Access",\n';
  const blob = new Blob([template], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'users-template.csv';
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById('importUsersBtn').addEventListener('click', () => {
  document.getElementById('importUsersInput').click();
});

document.getElementById('importUsersInput').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  const msg = document.getElementById('importUsersMsg');
  msg.textContent = '';
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch('/api/users/import', { method: 'POST', headers: csrfHeaders(), body: formData });
    if (!res.ok) throw await apiError(res);
    const result = await res.json();
    let summary = `Imported ${result.created.length} user${result.created.length === 1 ? '' : 's'}.`;
    if (result.skipped.length) {
      summary +=
        `\n\nSkipped ${result.skipped.length}:\n` +
        result.skipped.map((s) => `Row ${s.row} (${s.username}): ${s.reason}`).join('\n');
    }
    alert(summary);
    await loadUsers();
  } catch (err) {
    msg.textContent = err.message;
  }
});

// ---------- Init ----------
async function initApp() {
  renderStats(await api.get('/api/stats'));
  await loadSystemInfo();
  await loadSites();
  await loadTokens();
  await loadGroups();
  await loadUsers();
  await loadNetwork();
  await loadTftpSettings();
  await loadTftpFiles();
  await loadMyUsername();
  await loadAdminsTable();
  await loadTotpStatus();
  await loadHostKeyFingerprint();
  await loadSshSettings();
  await loadHaConfig();
  await loadHaStatus();
  await loadTlsInfo();
  await loadVersion();
  await loadUpdateStatus();
  renderSessions(await api.get('/api/sessions'));
  await loadCaptures();
  await loadLogHistory();
  await loadSyslogSettings();
  await loadAlertsSettings();
  connectEvents();
}

boot();
