'use strict';

const systemHelper = require('./systemHelper');

/** First scalar found in whatever shape lldpcli's json0 output uses for a field: a bare
 * string, {value: ...}, or either of those wrapped in one or more single-item arrays. */
function val(x) {
  if (x === null || x === undefined) return null;
  if (Array.isArray(x)) {
    for (const item of x) {
      const v = val(item);
      if (v !== null) return v;
    }
    return null;
  }
  if (typeof x === 'object') return 'value' in x ? val(x.value) : null;
  const s = String(x).trim();
  return s === '' ? null : s;
}

function asArray(x) {
  if (x === null || x === undefined) return [];
  return Array.isArray(x) ? x : [x];
}

/** Every scalar value under a field (e.g. several management IPs). */
function vals(x) {
  return asArray(x).map(val).filter((v) => v !== null);
}

/** Turns `lldpcli -f json0 show neighbors details` output into a flat, UI-friendly list:
 * one entry per neighbor, whichever discovery protocol (LLDP/CDP/FDP/...) it was heard on. */
function parseNeighbors(raw) {
  let doc;
  try {
    doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch {
    throw new Error('could not parse lldpcli output');
  }
  const neighbors = [];
  for (const lldp of asArray(doc && doc.lldp)) {
    for (const iface of asArray(lldp && lldp.interface)) {
      const chassis = asArray(iface.chassis)[0] || {};
      const port = asArray(iface.port)[0] || {};
      const capabilities = asArray(chassis.capability)
        .filter((c) => c && c.enabled !== false)
        .map((c) => c.type)
        .filter(Boolean);
      const chassisId = asArray(chassis.id)[0] || {};
      const portId = asArray(port.id)[0] || {};
      const vlan = asArray(iface.vlan)[0] || null;
      neighbors.push({
        localInterface: val(iface.name),
        protocol: val(iface.via),
        age: val(iface.age),
        chassisName: val(chassis.name),
        chassisId: val(chassisId.value),
        chassisIdType: val(chassisId.type),
        description: val(chassis.descr),
        managementIps: vals(chassis['mgmt-ip']),
        capabilities,
        portId: val(portId.value),
        portIdType: val(portId.type),
        portDescription: val(port.descr),
        ttl: val(port.ttl),
        vlan: vlan ? val(vlan['vlan-id']) : null
      });
    }
  }
  return neighbors;
}

function parseStatus(text) {
  const kv = {};
  for (const line of String(text).split('\n')) {
    const m = line.match(/^(\w+)=(\d)$/);
    if (m) kv[m[1]] = m[2] === '1';
  }
  return {
    installed: !!kv.installed,
    active: !!kv.active,
    cdp: !!kv.cdp,
    fdp: !!kv.fdp,
    showAll: !!kv.showall
  };
}

async function getStatus() {
  try {
    return parseStatus(await systemHelper.runHelper(['lldp-status']));
  } catch (err) {
    return { installed: false, active: false, cdp: false, fdp: false, showAll: false, error: err.message };
  }
}

/** Installs lldpd through the privileged helper if it's missing (needs internet; apt can
 * take a couple of minutes). Resolves to the resulting status; rejects if the install itself fails. */
let installing = null;
function ensureInstalled() {
  if (installing) return installing;
  installing = (async () => {
    const status = await getStatus();
    if (status.installed || process.platform !== 'linux') return status;
    await systemHelper.runHelper(['lldp-install'], undefined, 5 * 60 * 1000);
    return getStatus();
  })().finally(() => {
    installing = null;
  });
  return installing;
}

/** Enables/disables lldpd and chooses whether it also speaks CDP and FDP (LLDP itself is
 * always on when the daemon is). Throws with the helper's message when lldpd isn't
 * installed. */
async function setConfig({ enabled, cdp, fdp }) {
  if (enabled) await ensureInstalled();
  await systemHelper.runHelper(['lldp-set', enabled ? '1' : '0', cdp ? '1' : '0', fdp ? '1' : '0']);
  return getStatus();
}

async function getNeighbors() {
  const out = await systemHelper.runHelper(['lldp-neighbors']);
  return parseNeighbors(out);
}

module.exports = { ensureInstalled, getStatus, setConfig, getNeighbors, parseNeighbors, parseStatus };
