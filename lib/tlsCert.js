'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const crypto = require('crypto');

function certPaths(dataDir) {
  const certDir = path.join(dataDir, 'tls');
  return { certDir, keyPath: path.join(certDir, 'web_key.pem'), certPath: path.join(certDir, 'web_cert.pem') };
}

function generateSelfSigned(keyPath, certPath) {
  execFileSync('openssl', [
    'req', '-x509',
    '-newkey', 'rsa:2048',
    '-keyout', keyPath,
    '-out', certPath,
    '-days', '3650',
    '-nodes',
    '-subj', '/CN=terminalserver',
    '-addext', 'subjectAltName=DNS:terminalserver,DNS:terminalserver.local'
  ]);
  fs.chmodSync(keyPath, 0o600);
}

function ensureTlsCert(dataDir) {
  const { certDir, keyPath, certPath } = certPaths(dataDir);
  fs.mkdirSync(certDir, { recursive: true });

  if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    generateSelfSigned(keyPath, certPath);
  }

  return {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath)
  };
}

/**
 * Parses a cert (and validates it against a private key, if given) entirely in memory --
 * nothing here touches disk. Used both to validate an upload before it's ever written to
 * the live cert files, and to report on whatever's currently installed.
 */
function inspectCert(certPem, keyPem) {
  let cert;
  try {
    cert = new crypto.X509Certificate(certPem);
  } catch (e) {
    throw new Error(`not a valid PEM certificate: ${e.message}`);
  }
  if (keyPem !== undefined) {
    let privateKey;
    try {
      privateKey = crypto.createPrivateKey(keyPem);
    } catch (e) {
      throw new Error(`not a valid PEM private key: ${e.message}`);
    }
    const certKeyDer = cert.publicKey.export({ type: 'spki', format: 'der' });
    const privKeyDer = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    if (!certKeyDer.equals(privKeyDer)) {
      throw new Error('the certificate and private key do not match');
    }
  }
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: new Date(cert.validFrom).toISOString(),
    validTo: new Date(cert.validTo).toISOString(),
    expired: new Date(cert.validTo) < new Date(),
    fingerprint: cert.fingerprint256,
    // Self-signed certs (including the auto-generated default) always have a matching
    // issuer and subject; a CA-issued one essentially never does.
    selfSigned: cert.issuer === cert.subject
  };
}

function getCertInfo(dataDir) {
  const { certPath } = certPaths(dataDir);
  return inspectCert(fs.readFileSync(certPath, 'utf8'));
}

/** Validates the pair, then writes it as the live cert. Takes effect on the next restart. */
function setCert(dataDir, certPem, keyPem) {
  const info = inspectCert(certPem, keyPem);
  const { certDir, keyPath, certPath } = certPaths(dataDir);
  fs.mkdirSync(certDir, { recursive: true });
  fs.writeFileSync(keyPath, keyPem, { mode: 0o600 });
  fs.writeFileSync(certPath, certPem);
  return info;
}

/** Discards whatever cert is installed and mints a fresh self-signed one. */
function resetToSelfSigned(dataDir) {
  const { certDir, keyPath, certPath } = certPaths(dataDir);
  fs.mkdirSync(certDir, { recursive: true });
  fs.rmSync(keyPath, { force: true });
  fs.rmSync(certPath, { force: true });
  generateSelfSigned(keyPath, certPath);
  return getCertInfo(dataDir);
}

module.exports = { ensureTlsCert, getCertInfo, setCert, resetToSelfSigned };
