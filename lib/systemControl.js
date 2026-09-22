'use strict';

const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { execFile } = require('child_process');
const { runHelper } = require('./systemHelper');
const configStore = require('./configStore');

async function setNtpServer(server) {
  await runHelper(['ntp-set', server]);
}

async function setTimezone(timezone) {
  await runHelper(['timezone-set', timezone]);
  // timedatectl updates /etc/localtime immediately, but this already-running Node
  // process cached the old zone at startup and won't notice on its own -- setting
  // process.env.TZ directly makes every Date call (log timestamps, session times, etc.)
  // pick up the change right away, no restart required.
  process.env.TZ = timezone;
}

/** Pass an empty/undefined `servers` array to revert to DHCP-provided DNS. */
async function setDns(servers) {
  if (!servers || servers.length === 0) {
    await runHelper(['dns-clear']);
    return;
  }
  await runHelper(['dns-set', ...servers]);
}

async function setStaticIp(connectionName, address, prefix, gateway) {
  await runHelper(['ip-set', connectionName, address, String(prefix), gateway]);
}

async function clearStaticIp(connectionName) {
  await runHelper(['ip-clear', connectionName]);
}

async function setHostname(hostname) {
  await runHelper(['hostname-set', hostname]);
}

/** Restarts just this app (not the whole host) -- e.g. to pick up a new TLS cert. */
async function restartService() {
  await runHelper(['service-restart']);
}

function parseHelperFlags(output) {
  const result = {};
  for (const line of output.split('\n')) {
    const idx = line.indexOf('=');
    if (idx === -1) continue;
    result[line.slice(0, idx).trim()] = line.slice(idx + 1).trim() === '1';
  }
  return result;
}

// The exact restricted command ha-setup.sh has always documented pasting into a peer's
// authorized_keys, rebuilt here so the setup UI can hand it over ready-to-paste instead
// of the admin having to type it out from the README by hand. Points at THIS node's own
// data dir, since it's what a peer pulling FROM here would be served.
function buildHaAuthorizedKeysLine(publicKey) {
  const dataDir = configStore.DATA_DIR;
  return `command="rsync --server --sender -logDtprze.iLsfxCIvu . ${dataDir}",restrict ${publicKey}`;
}

/** One-time, idempotent node setup for the HA agent -- see provisioning/system-helper.sh's
 * ha-setup case for exactly what this does. Returns this node's freshly-generated (or
 * pre-existing) replication public key, plus the ready-to-paste authorized_keys line for
 * the peer. */
async function setupHighAvailability() {
  const output = await runHelper(['ha-setup'], 30000);
  const match = output.match(/^PUBKEY:(.*)$/m);
  const publicKey = match ? match[1].trim() : null;
  return {
    publicKey,
    authorizedKeysLine: publicKey ? buildHaAuthorizedKeysLine(publicKey) : null
  };
}

async function startHaAgentService() {
  await runHelper(['ha-start']);
}

async function getHaServiceStatus() {
  const output = await runHelper(['ha-service-status']);
  return parseHelperFlags(output);
}

async function trustHaPeerHostKey(keyLine) {
  await runHelper(['ha-trust-peer', keyLine]);
}

/** Fetches the peer's SSH host key over the network (no privilege needed -- this is just
 * an outbound TCP connection to read its public banner) and returns its fingerprint for
 * an admin to visually confirm out-of-band before trustHaPeerHostKey() persists it. This
 * is the same trust decision ssh's own interactive "are you sure you want to continue
 * connecting" prompt asks for -- just surfaced in the UI since there's no shell here to
 * ask it in. */
function scanHaPeerHostKey(host) {
  return new Promise((resolve, reject) => {
    execFile('ssh-keyscan', ['-t', 'ed25519', '-T', '5', host], { timeout: 10000 }, (err, stdout, stderr) => {
      const keyLine = stdout
        .split('\n')
        .map((l) => l.trim())
        .find((l) => l && !l.startsWith('#'));
      if (!keyLine) {
        return reject(new Error((stderr || '').trim() || `no SSH host key returned for ${host}`));
      }

      const tmpFile = path.join(os.tmpdir(), `co-ha-hostkey-${crypto.randomBytes(8).toString('hex')}`);
      fs.writeFileSync(tmpFile, `${keyLine}\n`, { mode: 0o600 });
      execFile('ssh-keygen', ['-lf', tmpFile], { timeout: 5000 }, (fpErr, fpOut) => {
        fs.unlink(tmpFile, () => {});
        if (fpErr) return reject(new Error('could not compute the fetched host key\'s fingerprint'));
        resolve({ keyLine, fingerprint: fpOut.trim() });
      });
    });
  });
}

module.exports = {
  setNtpServer,
  setTimezone,
  setDns,
  setStaticIp,
  clearStaticIp,
  setHostname,
  restartService,
  setupHighAvailability,
  startHaAgentService,
  getHaServiceStatus,
  trustHaPeerHostKey,
  scanHaPeerHostKey
};
