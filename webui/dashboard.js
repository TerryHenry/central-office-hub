'use strict';

// Configurable Dashboard: every panel directly under the Dashboard tab is a "widget" that
// can be hidden, shown again, and reordered, and the stat cards inside the System widget
// can be toggled individually. A few extra widgets (recent activity, active sessions, and
// -- on the hub -- a fleet summary) are added here. The layout is stored in this browser's
// localStorage, so it is per-browser rather than per-account.
(function dashboardWidgets() {
  const tab = document.getElementById('tab-dashboard');
  if (!tab) return;
  const STORAGE_KEY = 'dashboardLayout.v1';
  const isHub = !!document.getElementById('topologySvg');

  const slug = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------- Extra widgets ----------
  function addWidget(id, title, bodyHtml) {
    const panel = document.createElement('div');
    panel.className = 'panel';
    panel.dataset.widget = id;
    panel.innerHTML = `<h2>${esc(title)}</h2>${bodyHtml}`;
    tab.appendChild(panel);
    return panel;
  }

  if (isHub) {
    addWidget(
      'fleet-summary',
      'Fleet Summary',
      '<div class="stat-grid" id="dashFleetGrid"><span class="hint">Loading&hellip;</span></div>'
    );
  }
  addWidget(
    'active-sessions',
    'Active Sessions',
    '<table class="data-table" id="dashSessionsTable"><thead><tr><th>User</th><th>Via</th><th>Port</th><th>Since</th></tr></thead><tbody></tbody></table><p class="hint" id="dashSessionsEmpty">No one is connected.</p>'
  );
  addWidget('recent-activity', 'Recent Activity', '<pre class="log-tail" id="dashRecentLog">Loading&hellip;</pre>');

  // ---------- Identify widgets and stat cards ----------
  const panels = [...tab.querySelectorAll(':scope > .panel')];
  const widgets = panels.map((panel) => {
    const title = (panel.querySelector('h2') || {}).textContent || 'Widget';
    if (!panel.dataset.widget) panel.dataset.widget = slug(title);
    return { id: panel.dataset.widget, title: title.trim(), panel };
  });
  const statCards = [...tab.querySelectorAll('.stat-card')]
    .filter((card) => card.closest('[data-widget]') && card.closest('[data-widget]').dataset.widget === 'system')
    .map((card) => {
      const label = (card.querySelector('.stat-label') || {}).textContent || 'Stat';
      card.dataset.stat = slug(label);
      return { id: card.dataset.stat, title: label.trim(), card };
    });

  // ---------- Persistence ----------
  function loadLayout() {
    try {
      const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
      if (raw && Array.isArray(raw.order) && Array.isArray(raw.hidden)) {
        return { order: raw.order, hidden: raw.hidden, hiddenStats: Array.isArray(raw.hiddenStats) ? raw.hiddenStats : [] };
      }
    } catch {
      // storage unavailable or corrupt -- fall through to the default layout
    }
    return { order: [], hidden: [], hiddenStats: [] };
  }
  let layout = loadLayout();
  function saveLayout() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
    } catch {
      // private mode etc. -- the layout just won't persist
    }
  }

  // The effective order: saved order first (dropping widgets that no longer exist), then
  // any widget the saved layout has never seen, in its natural position.
  function currentOrder() {
    const known = new Set(widgets.map((w) => w.id));
    const saved = layout.order.filter((id) => known.has(id));
    return [...saved, ...widgets.map((w) => w.id).filter((id) => !saved.includes(id))];
  }

  // ---------- Toolbar ----------
  const toolbar = document.createElement('div');
  toolbar.className = 'dash-toolbar';
  toolbar.innerHTML = `
    <span class="hint" id="dashEditHint" style="display:none;">Reorder, hide, or show widgets. Saved in this browser.</span>
    <button type="button" class="secondary" id="dashResetBtn" style="display:none;">Reset layout</button>
    <button type="button" class="secondary" id="dashCustomizeBtn">Customize</button>`;
  tab.insertBefore(toolbar, tab.firstChild);
  const customizeBtn = toolbar.querySelector('#dashCustomizeBtn');
  const resetBtn = toolbar.querySelector('#dashResetBtn');
  const editHint = toolbar.querySelector('#dashEditHint');
  const hiddenBar = document.createElement('div');
  hiddenBar.className = 'dash-hidden-bar';
  tab.insertBefore(hiddenBar, toolbar.nextSibling);

  let editing = false;

  function render() {
    const order = currentOrder();
    for (const id of order) tab.appendChild(widgets.find((w) => w.id === id).panel);

    order.forEach((id, index) => {
      const w = widgets.find((x) => x.id === id);
      const hidden = layout.hidden.includes(id);
      w.panel.classList.toggle('widget-hidden', hidden);
      let bar = w.panel.querySelector(':scope > .widget-bar');
      if (bar) bar.remove();
      if (!editing || hidden) return;
      bar = document.createElement('div');
      bar.className = 'widget-bar';
      bar.innerHTML = `<span class="grow">${esc(w.title)}</span>
        <button type="button" class="secondary" data-act="up" ${index === 0 ? 'disabled' : ''} title="Move up">&uarr;</button>
        <button type="button" class="secondary" data-act="down" ${index === order.length - 1 ? 'disabled' : ''} title="Move down">&darr;</button>
        <button type="button" class="danger" data-act="hide" title="Hide this widget">Hide</button>`;
      if (id === 'system') {
        const toggles = document.createElement('div');
        toggles.className = 'widget-stat-toggles';
        for (const s of statCards) {
          const label = document.createElement('label');
          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = !layout.hiddenStats.includes(s.id);
          cb.addEventListener('change', () => {
            layout.hiddenStats = cb.checked ? layout.hiddenStats.filter((x) => x !== s.id) : [...layout.hiddenStats, s.id];
            saveLayout();
            applyStats();
          });
          label.appendChild(cb);
          label.appendChild(document.createTextNode(` ${s.title}`));
          toggles.appendChild(label);
        }
        bar.appendChild(toggles);
      }
      bar.addEventListener('click', (e) => {
        const act = e.target.dataset && e.target.dataset.act;
        if (!act) return;
        const o = currentOrder();
        const i = o.indexOf(id);
        if (act === 'up' && i > 0) [o[i - 1], o[i]] = [o[i], o[i - 1]];
        if (act === 'down' && i < o.length - 1) [o[i + 1], o[i]] = [o[i], o[i + 1]];
        if (act === 'hide') layout.hidden = [...layout.hidden, id];
        layout.order = o;
        saveLayout();
        render();
      });
      w.panel.insertBefore(bar, w.panel.firstChild);
    });

    // Hidden widgets can be brought back while customizing.
    hiddenBar.innerHTML = '';
    if (editing) {
      for (const id of layout.hidden.filter((h) => widgets.some((w) => w.id === h))) {
        const w = widgets.find((x) => x.id === id);
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'secondary';
        btn.textContent = `+ ${w.title}`;
        btn.addEventListener('click', () => {
          layout.hidden = layout.hidden.filter((x) => x !== id);
          saveLayout();
          render();
        });
        hiddenBar.appendChild(btn);
      }
    }
    applyStats();
    refreshAll();
  }

  function applyStats() {
    for (const s of statCards) s.card.classList.toggle('widget-hidden', layout.hiddenStats.includes(s.id));
  }

  customizeBtn.addEventListener('click', () => {
    editing = !editing;
    customizeBtn.textContent = editing ? 'Done' : 'Customize';
    customizeBtn.classList.toggle('primary', editing);
    customizeBtn.classList.toggle('secondary', !editing);
    resetBtn.style.display = editing ? '' : 'none';
    editHint.style.display = editing ? '' : 'none';
    render();
  });
  resetBtn.addEventListener('click', () => {
    layout = { order: [], hidden: [], hiddenStats: [] };
    saveLayout();
    render();
  });

  // ---------- Live data for the added widgets ----------
  const isVisible = (id) => {
    const w = widgets.find((x) => x.id === id);
    const loggedIn = document.getElementById('appRoot') && document.getElementById('appRoot').classList.contains('active');
    return loggedIn && w && !layout.hidden.includes(id) && tab.classList.contains('active');
  };

  async function getJson(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function refreshSessions() {
    if (!isVisible('active-sessions')) return;
    try {
      const sessions = await getJson('/api/sessions');
      const tbody = document.querySelector('#dashSessionsTable tbody');
      tbody.innerHTML = sessions
        .map(
          (s) =>
            `<tr><td>${esc(s.username)}</td><td>${esc(s.method || '')}</td><td>${s.portLabel ? esc(s.portLabel) : '<span class="hint">at menu</span>'}</td><td>${esc(new Date(s.connectedAt).toLocaleTimeString())}</td></tr>`
        )
        .join('');
      document.getElementById('dashSessionsEmpty').style.display = sessions.length ? 'none' : '';
    } catch {
      // transient -- try again next tick
    }
  }

  async function refreshLog() {
    if (!isVisible('recent-activity')) return;
    try {
      const lines = await getJson('/api/log');
      const el = document.getElementById('dashRecentLog');
      el.textContent = lines.slice(-10).join('\n') || 'Nothing logged yet.';
    } catch {
      // transient
    }
  }

  async function refreshFleet() {
    if (!isHub || !isVisible('fleet-summary')) return;
    try {
      const sites = await getJson('/api/sites');
      const online = sites.filter((s) => s.connected).length;
      const ports = sites.reduce((n, s) => n + s.ports.length, 0);
      const updates = sites.filter((s) => s.updateAvailable).length;
      const card = (label, value, sub) =>
        `<div class="stat-card"><span class="stat-label">${label}</span><span class="stat-value">${value}</span>${sub ? `<span class="stat-sub">${sub}</span>` : ''}</div>`;
      document.getElementById('dashFleetGrid').innerHTML =
        card('Sites Online', `${online} / ${sites.length}`, sites.length - online ? `${sites.length - online} offline` : 'all connected') +
        card('Ports Reported', ports, '') +
        card('Updates Available', updates, updates ? 'sites behind the latest version' : 'all up to date');
    } catch {
      // transient
    }
  }

  function refreshAll() {
    refreshSessions();
    refreshLog();
    refreshFleet();
  }
  setInterval(refreshAll, 8000);
  render();
})();
