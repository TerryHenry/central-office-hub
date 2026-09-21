'use strict';

// Batch tab: write a script, pick ports (on the hub: across any number of sites; on an edge
// box: its own ports), run it, and watch a per-device record of what happened. The work
// itself happens server-side (lib/batchRunner.js). This file is shared by both apps.
(function batchUi() {
  const tabBtn = document.querySelector('[data-tab="batch"]');
  const tab = document.getElementById('tab-batch');
  if (!tabBtn || !tab) return;

  const IS_HUB = !!document.querySelector('[data-tab="sites"]');
  const $ = (id) => document.getElementById(id);
  const esc = (s) => escapeHtml(s == null ? '' : s);

  // Starting points only -- prompts differ between vendors and firmware, so each one says to
  // check it against your own device (ideally on a single port first).
  const PRESETS = [
    {
      name: 'Log in and run a command',
      script: '# Logs in, then runs a command on each device.\nlogin {{username}} {{password}}\nshow version\n'
    },
    {
      name: 'Ruckus ICX - Show Version',
      script:
        '# Ruckus ICX: log in, show the version, log out. The first quit clears any session left open;\n' +
        '# skip / page turn the pager off and back on. Check the prompts on one device first.\n' +
        'quit\n' +
        'login {{username}} {{password}}\n' +
        'enable\n' +
        'skip\n' +
        'show version\n' +
        'page\n' +
        'quit\n'
    },
    {
      name: 'Reboot (Cisco IOS style)',
      script:
        '# Example -- check the prompts against your device first, on one port.\n' +
        'login {{username}} {{password}}\n' +
        'enable\n' +
        'expect Password\n' +
        'send {{password}}\n' +
        'reload\n' +
        'expect-regex \\[(yes/no|confirm)\\] timeout=20\n' +
        'send\n'
    },
    {
      name: 'Factory reset (Cisco IOS style)',
      script:
        '# DESTRUCTIVE: erases the startup configuration and reloads.\n' +
        '# Example only -- confirm every prompt on one device before running it on many.\n' +
        'login {{username}} {{password}}\n' +
        'enable\n' +
        'expect Password\n' +
        'send {{password}}\n' +
        'write erase\n' +
        'expect confirm\n' +
        'send\n' +
        'reload\n' +
        'expect-regex \\[(yes/no|confirm)\\] timeout=20\n' +
        'send n\n' +
        'expect confirm\n' +
        'send\n'
    },
    {
      name: 'Reboot (Linux shell)',
      script: '# Logs in to a Linux console and reboots it.\nlogin {{username}} {{password}}\nsudo reboot\n'
    }
  ];

  const selectedPorts = new Set(); // "siteId:portId"
  let detailId = null;
  let detailTimer = null;
  const openTargets = new Set(); // detail rows the user expanded

  // ---------- Presets and templates ----------
  const presetSel = $('batchPreset');
  presetSel.innerHTML = '<option value="">Insert an example&hellip;</option>' + PRESETS.map((p, i) => `<option value="${i}">${esc(p.name)}</option>`).join('');
  presetSel.addEventListener('change', () => {
    const preset = PRESETS[presetSel.value];
    presetSel.value = '';
    if (!preset) return;
    const box = $('batchScript');
    if (box.value.trim() && !confirm('Replace the current script with this example?')) return;
    box.value = preset.script;
    if (!$('batchName').value.trim()) $('batchName').value = preset.name;
  });

  let templates = [];
  async function loadTemplates() {
    templates = await api.get('/api/batch-templates');
    const sel = $('batchTemplate');
    sel.innerHTML = '<option value="">Saved scripts&hellip;</option>' + templates.map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('');
  }
  $('batchTemplate').addEventListener('change', () => {
    const t = templates.find((x) => x.id === $('batchTemplate').value);
    if (!t) return;
    const box = $('batchScript');
    if (box.value.trim() && box.value !== t.script && !confirm('Replace the current script with the saved one?')) {
      $('batchTemplate').value = '';
      return;
    }
    box.value = t.script;
    $('batchName').value = t.name;
  });
  $('batchSaveTemplateBtn').addEventListener('click', async () => {
    const err = $('batchError');
    err.textContent = '';
    const name = prompt('Save this script as:', $('batchName').value.trim());
    if (!name || !name.trim()) return;
    try {
      const saved = await api.post('/api/batch-templates', { name: name.trim(), script: $('batchScript').value });
      await loadTemplates();
      $('batchTemplate').value = saved.id;
    } catch (e) {
      err.textContent = e.message;
    }
  });
  $('batchDeleteTemplateBtn').addEventListener('click', async () => {
    const t = templates.find((x) => x.id === $('batchTemplate').value);
    if (!t) return;
    if (!confirm(`Delete the saved script "${t.name}"?`)) return;
    await api.del(`/api/batch-templates/${t.id}`);
    await loadTemplates();
  });

  // ---------- Port picker ----------
  // On an edge box the only "site" is itself: its own serial ports, keyed "local:<portId>".
  async function loadLocalTargets() {
    const ports = (await api.get('/api/ports')).sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }));
    const wrap = $('batchTargets');
    wrap.innerHTML = '';
    if (!ports.length) {
      wrap.innerHTML = '<p class="hint">No serial ports are configured on this box yet.</p>';
      updateSelectedCount();
      return;
    }
    const block = document.createElement('div');
    block.className = 'batch-site';
    block.innerHTML = '<label class="batch-site-head"><input type="checkbox" class="batch-site-all" /> <strong>This box</strong></label><div class="batch-ports"></div>';
    const portsEl = block.querySelector('.batch-ports');
    for (const port of ports) {
      const key = `local:${port.id}`;
      const label = document.createElement('label');
      label.className = 'batch-port';
      label.innerHTML = `<input type="checkbox" ${selectedPorts.has(key) ? 'checked' : ''} /> ${esc(port.label)}`;
      label.querySelector('input').addEventListener('change', (e) => {
        if (e.target.checked) selectedPorts.add(key);
        else selectedPorts.delete(key);
        updateSelectedCount();
      });
      portsEl.appendChild(label);
    }
    block.querySelector('.batch-site-all').addEventListener('change', (e) => {
      block.querySelectorAll('.batch-port input').forEach((cb) => {
        cb.checked = e.target.checked;
        cb.dispatchEvent(new Event('change'));
      });
    });
    wrap.appendChild(block);
    updateSelectedCount();
  }

  async function loadTargets() {
    if (!IS_HUB) return loadLocalTargets();
    const sites = await api.get('/api/sites');
    const wrap = $('batchTargets');
    wrap.innerHTML = '';
    if (!sites.length) {
      wrap.innerHTML = '<p class="hint">No sites enrolled yet.</p>';
      return;
    }
    for (const site of sites.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }))) {
      const block = document.createElement('div');
      block.className = 'batch-site';
      const ports = [...site.ports].sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }));
      block.innerHTML = `<label class="batch-site-head"><input type="checkbox" class="batch-site-all" ${site.connected && ports.length ? '' : 'disabled'} /> <strong>${esc(site.name)}</strong> ${
        site.connected ? '' : '<span class="pill mute"><span class="dot"></span>offline</span>'
      }</label><div class="batch-ports"></div>`;
      const portsEl = block.querySelector('.batch-ports');
      if (!ports.length) portsEl.innerHTML = '<span class="hint">no ports reported</span>';
      for (const port of ports) {
        const key = `${site.id}:${port.id}`;
        const label = document.createElement('label');
        label.className = 'batch-port';
        label.innerHTML = `<input type="checkbox" ${site.connected ? '' : 'disabled'} ${selectedPorts.has(key) ? 'checked' : ''} /> ${esc(port.label)}`;
        label.querySelector('input').addEventListener('change', (e) => {
          if (e.target.checked) selectedPorts.add(key);
          else selectedPorts.delete(key);
          updateSelectedCount();
        });
        label.dataset.key = key;
        portsEl.appendChild(label);
      }
      block.querySelector('.batch-site-all').addEventListener('change', (e) => {
        block.querySelectorAll('.batch-port input').forEach((cb) => {
          cb.checked = e.target.checked;
          cb.dispatchEvent(new Event('change'));
        });
      });
      wrap.appendChild(block);
    }
    updateSelectedCount();
  }
  function updateSelectedCount() {
    $('batchSelectedCount').textContent = `${selectedPorts.size} port${selectedPorts.size === 1 ? '' : 's'} selected`;
  }

  // ---------- Run ----------
  $('batchRunBtn').addEventListener('click', async () => {
    const err = $('batchError');
    err.textContent = '';
    if (!$('batchScript').value.trim()) {
      err.textContent = 'Write a script first.';
      return;
    }
    if (!selectedPorts.size) {
      err.textContent = 'Choose at least one port.';
      return;
    }
    const name = $('batchName').value.trim() || 'Batch';
    if (!confirm(`Run "${name}" on ${selectedPorts.size} port${selectedPorts.size === 1 ? '' : 's'}? The script's commands are typed into each device's console, and can't be undone.`)) return;
    const targets = [...selectedPorts].map((k) => {
      const [siteId, portId] = k.split(':');
      return { siteId, portId };
    });
    $('batchRunBtn').disabled = true;
    try {
      const run = await api.post('/api/batches', {
        name,
        script: $('batchScript').value,
        targets,
        username: $('batchUsername').value,
        password: $('batchPassword').value
      });
      await loadHistory();
      openDetail(run.id);
    } catch (e) {
      err.textContent = e.message;
    } finally {
      $('batchRunBtn').disabled = false;
    }
  });

  // ---------- History ----------
  const STATUS_PILL = {
    running: 'accent',
    queued: 'mute',
    completed: 'ok',
    succeeded: 'ok',
    failed: 'bad',
    cancelled: 'mute',
    interrupted: 'warn'
  };
  const pill = (status) => `<span class="pill ${STATUS_PILL[status] || 'mute'}"><span class="dot"></span>${esc(status)}</span>`;
  const when = (iso) => (iso ? new Date(iso).toLocaleString() : '\u2014');

  async function loadHistory() {
    const runs = await api.get('/api/batches');
    const tbody = document.querySelector('#batchHistoryTable tbody');
    tbody.innerHTML = '';
    $('batchHistoryEmpty').style.display = runs.length ? 'none' : '';
    for (const run of runs) {
      const c = run.counts;
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${esc(run.name)}</td><td>${esc(when(run.startedAt))}</td><td>${pill(run.status)}</td>
        <td>${c.succeeded} ok${c.failed ? `, <strong style="color:var(--danger)">${c.failed} failed</strong>` : ''}${c.cancelled ? `, ${c.cancelled} cancelled` : ''}${c.running + c.queued ? `, ${c.running + c.queued} pending` : ''} <span class="hint">of ${run.targetCount}</span></td><td></td>`;
      const cell = tr.lastElementChild;
      const view = document.createElement('button');
      view.textContent = 'View';
      view.addEventListener('click', () => openDetail(run.id));
      cell.appendChild(view);
      if (!run.finishedAt) {
        const stop = document.createElement('button');
        stop.textContent = 'Cancel';
        stop.className = 'danger';
        stop.style.marginLeft = '6px';
        stop.addEventListener('click', async () => {
          if (!confirm(`Cancel "${run.name}"? Devices already mid-script are stopped where they are.`)) return;
          await api.post(`/api/batches/${run.id}/cancel`).catch((e) => alert(e.message));
          loadHistory();
        });
        cell.appendChild(stop);
      } else {
        const del = document.createElement('button');
        del.textContent = 'Delete';
        del.className = 'danger';
        del.style.marginLeft = '6px';
        del.addEventListener('click', async () => {
          if (!confirm(`Delete "${run.name}" from the history?`)) return;
          await api.del(`/api/batches/${run.id}`).catch((e) => alert(e.message));
          loadHistory();
        });
        cell.appendChild(del);
      }
      tbody.appendChild(tr);
    }
  }

  // ---------- Detail ----------
  const STEP_MARK = { ok: '\u2713', failed: '\u2717', running: '\u2026', skipped: '\u2013', pending: '\u25CB', cancelled: '\u25A0' };

  function renderDetail(run) {
    $('batchDetailTitle').textContent = run.name;
    $('batchDetailMeta').innerHTML = `${pill(run.status)} &nbsp; started ${esc(when(run.startedAt))}${run.startedBy ? ` by ${esc(run.startedBy)}` : ''}${run.finishedAt ? `, finished ${esc(when(run.finishedAt))}` : ''}`;
    $('batchDetailScript').textContent = run.script;
    const wrap = $('batchDetailTargets');
    // Rebuilding on every poll would collapse rows the user opened, so remember them.
    wrap.querySelectorAll('details').forEach((d) => {
      if (d.open) openTargets.add(d.dataset.key);
      else openTargets.delete(d.dataset.key);
    });
    wrap.innerHTML = '';
    run.targets.forEach((t, i) => {
      const key = `${run.id}:${i}`;
      const done = t.steps.filter((s) => s.status === 'ok').length;
      const d = document.createElement('details');
      d.className = 'batch-target';
      d.dataset.key = key;
      d.open = openTargets.has(key) || (run.targets.length === 1);
      d.innerHTML = `<summary>${esc(t.siteName)} / <strong>${esc(t.portLabel)}</strong> &nbsp; ${pill(t.status)} <span class="hint">${done}/${t.steps.length} steps</span>${t.error ? ` <span style="color:var(--danger)">${esc(t.error)}</span>` : ''}</summary>
        <table class="data-table batch-steps"><tbody>${t.steps
          .map((s) => `<tr><td style="width:2em">${STEP_MARK[s.status] || ''}</td><td><code>${esc(s.text)}</code></td><td class="hint">${esc(s.note || '')}</td></tr>`)
          .join('')}</tbody></table>
        <div class="hint">Device output${t.truncated ? ' (earlier output trimmed)' : ''}:</div>
        <pre class="code-block batch-transcript">${esc(t.transcript) || '(nothing received)'}</pre>`;
      wrap.appendChild(d);
    });
  }

  async function refreshDetail() {
    if (!detailId) return;
    try {
      const run = await api.get(`/api/batches/${detailId}`);
      renderDetail(run);
      if (run.finishedAt) stopDetailPolling();
    } catch {
      stopDetailPolling();
    }
  }
  function stopDetailPolling() {
    clearInterval(detailTimer);
    detailTimer = null;
  }
  async function openDetail(id) {
    detailId = id;
    openTargets.clear();
    $('batchDetailBackdrop').classList.add('open');
    await refreshDetail();
    if (!detailTimer && detailId) detailTimer = setInterval(refreshDetail, 2000);
  }
  $('batchDetailCloseBtn').addEventListener('click', () => {
    detailId = null;
    stopDetailPolling();
    $('batchDetailBackdrop').classList.remove('open');
    loadHistory().catch(() => {});
  });

  // ---------- Loading ----------
  async function loadAll() {
    await Promise.all([loadTemplates(), loadTargets(), loadHistory()]);
  }
  tabBtn.addEventListener('click', () => loadAll().catch(() => {}));
  $('batchRefreshTargetsBtn').addEventListener('click', () => loadTargets().catch(() => {}));
  setInterval(() => {
    if (appRoot.classList.contains('active') && tab.classList.contains('active')) loadHistory().catch(() => {});
  }, 3000);
})();
