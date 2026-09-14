'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function ensureHostKey(dataDir) {
  const keyDir = path.join(dataDir, 'ssh');
  fs.mkdirSync(keyDir, { recursive: true });
  const keyPath = path.join(keyDir, 'host_ed25519_key');
  const pubPath = `${keyPath}.pub`;

  if (!fs.existsSync(keyPath)) {
    execFileSync('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-C', 'terminalserver-host-key']);
    fs.chmodSync(keyPath, 0o600);
  }

  return {
    privateKey: fs.readFileSync(keyPath),
    publicKey: fs.existsSync(pubPath) ? fs.readFileSync(pubPath, 'utf8').trim() : null,
    keyPath
  };
}

/** Reads the host key pair as strings, for an optional inclusion in a config backup. */
function readHostKeyFiles(dataDir) {
  const keyPath = path.join(dataDir, 'ssh', 'host_ed25519_key');
  const pubPath = `${keyPath}.pub`;
  if (!fs.existsSync(keyPath)) return null;
  return {
    privateKey: fs.readFileSync(keyPath, 'utf8'),
    publicKey: fs.existsSync(pubPath) ? fs.readFileSync(pubPath, 'utf8') : null
  };
}

/** Writes a host key pair from a restored backup. Takes effect on next server start. */
function writeHostKeyFiles(dataDir, { privateKey, publicKey }) {
  const keyDir = path.join(dataDir, 'ssh');
  fs.mkdirSync(keyDir, { recursive: true });
  const keyPath = path.join(keyDir, 'host_ed25519_key');
  fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });
  if (publicKey) fs.writeFileSync(`${keyPath}.pub`, publicKey, { mode: 0o644 });
}

module.exports = { ensureHostKey, readHostKeyFiles, writeHostKeyFiles };
