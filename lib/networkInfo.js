'use strict';

const os = require('os');
const fs = require('fs');
const { execFile } = require('child_process');

const PUBLIC_IP_TIMEOUT_MS = 3000;
const PUBLIC_IP_URL = 'https://api.ipify.org?format=json';
const NTP_DROPIN_PATH = '/etc/systemd/timesyncd.conf.d/50-central-office.conf';
const DEFAULT_NTP_SERVER = 'pool.ntp.org';

function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 4000 }, (err, stdout) => {
      resolve(err ? null : stdout);
    });
  });
}

/** IPv4 addresses per network interface, from Node's own view of the OS (always available). */
function localAddresses() {
  const nets = os.networkInterfaces();
  const byName = {};
  for (const [name, addrs] of Object.entries(nets)) {
    const ipv4 = (addrs || []).find((a) => a.family === 'IPv4' && !a.internal);
    if (ipv4) byName[name] = ipv4.address;
  }
  return byName;
}

/**
 * Richer per-interface status (connected/disconnected, connection name) via nmcli, which
 * is what Raspberry Pi OS Bookworm (and many Debian/Ubuntu hosts) manage networking
 * with. Falls back to just the interfaces Node can see if nmcli isn't available (e.g. a
 * generic Debian cloud VM without NetworkManager, or a non-Linux dev machine).
 */
async function getInterfaces() {
  const addresses = localAddresses();
  const nmcliOut = await run('nmcli', ['-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device', 'status']);

  if (!nmcliOut) {
    return Object.entries(addresses)
      .filter(([name]) => name !== 'lo')
      .map(([name, ip]) => ({ name, type: 'ethernet', state: 'unknown', ip, connection: null }));
  }

  return nmcliOut
    .trim()
    .split('\n')
    // nmcli -t escapes literal colons within a field as "\:" -- split only on unescaped
    // ones so a connection name containing ":" doesn't get chopped apart.
    .map((line) => line.split(/(?<!\\):/).map((s) => s.replace(/\\:/g, ':')))
    .filter(([, type]) => type === 'ethernet' || type === 'wifi')
    .map(([name, type, state, connection]) => ({
      name,
      type,
      state, // 'connected' | 'disconnected' | 'unavailable' | 'unmanaged' | ...
      ip: addresses[name] || null,
      connection: connection && connection !== '--' ? connection : null
    }));
}

async function getPublicIp() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), PUBLIC_IP_TIMEOUT_MS);
    const res = await fetch(PUBLIC_IP_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    return data.ip || null;
  } catch {
    return null;
  }
}

/**
 * Reads our own timesyncd drop-in directly rather than asking systemd-timesyncd over
 * D-Bus (via `timedatectl show-timesync`), which reflects the currently active pool
 * member rather than the configured pool name and isn't reliably available on every
 * systemd version. Falls back to the documented default when we haven't written one yet
 * (fresh hub) or aren't on Linux (dev machine).
 */
function getConfiguredNtpServer() {
  try {
    const content = fs.readFileSync(NTP_DROPIN_PATH, 'utf8');
    const match = content.match(/^NTP=(.+)$/m);
    return match ? match[1].trim() : DEFAULT_NTP_SERVER;
  } catch {
    return DEFAULT_NTP_SERVER;
  }
}

/** { server, synchronized: true|false|null (unknown, e.g. non-Linux dev machine) } */
async function getNtpStatus() {
  const out = await run('timedatectl', ['show', '--property=NTPSynchronized', '--value']);
  return {
    server: getConfiguredNtpServer(),
    synchronized: out ? out.trim() === 'yes' : null
  };
}

/** IANA zone name (e.g. "America/New_York"), or null if unavailable (e.g. non-Linux). */
async function getTimezone() {
  const out = await run('timedatectl', ['show', '--property=Timezone', '--value']);
  return out ? out.trim() : null;
}

/** All IANA zone names timedatectl knows about, for a picker; [] if unavailable. */
async function listTimezones() {
  const out = await run('timedatectl', ['list-timezones']);
  if (!out) return [];
  return out.trim().split('\n').filter(Boolean);
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4(value) {
  return IPV4_RE.test(value) && value.split('.').every((octet) => Number(octet) <= 255);
}

/** Dotted-decimal subnet mask (e.g. "255.255.255.0") -> CIDR prefix length (e.g. 24), or null if invalid. */
function maskToPrefix(mask) {
  if (!isIpv4(mask)) return null;
  const bits = mask
    .split('.')
    .map((octet) => Number(octet).toString(2).padStart(8, '0'))
    .join('');
  // A valid mask is a contiguous run of 1s followed by 0s (11111111...000000).
  if (!/^1*0*$/.test(bits)) return null;
  return (bits.match(/1/g) || []).length;
}

/**
 * The static-vs-DHCP configuration of a NetworkManager connection profile (as opposed to
 * getInterfaces()'s live device status) -- what's actually configured, not just what's
 * currently active, since the two can briefly disagree right after a change.
 */
async function getIpConfig(connectionName) {
  const out = await run('nmcli', ['-t', '-f', 'ipv4.method,ipv4.addresses,ipv4.gateway', 'connection', 'show', connectionName]);
  if (!out) return null;
  const fields = {};
  for (const line of out.trim().split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    fields[line.slice(0, idx)] = line.slice(idx + 1).trim();
  }
  const [address, prefix] = (fields['ipv4.addresses'] || '').split('/');
  return {
    method: fields['ipv4.method'] === 'manual' ? 'manual' : 'auto',
    address: address || null,
    prefix: prefix ? Number(prefix) : null,
    gateway: fields['ipv4.gateway'] || null
  };
}

/**
 * The DNS servers actually in effect right now, read straight from /etc/resolv.conf --
 * this reflects reality regardless of whether NetworkManager, systemd-resolved, or DHCP
 * put them there, unlike asking any one of those services directly. IPv4 only: a
 * resolv.conf on a dual-stack link often also lists IPv6 (and link-local) resolvers, which
 * this hub's DNS override doesn't manage -- listing them here would just be noise the
 * admin can't act on from this field.
 */
function getDnsServers() {
  try {
    const content = fs.readFileSync('/etc/resolv.conf', 'utf8');
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('nameserver '))
      .map((line) => line.slice('nameserver '.length).trim())
      .filter(isIpv4);
  } catch {
    return [];
  }
}

module.exports = {
  getInterfaces,
  getPublicIp,
  getNtpStatus,
  getTimezone,
  listTimezones,
  getDnsServers,
  isIpv4,
  maskToPrefix,
  getIpConfig
};
