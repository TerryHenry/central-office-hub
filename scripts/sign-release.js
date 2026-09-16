#!/usr/bin/env node
'use strict';

/**
 * Signs a release's checksum file with the maintainer's Ed25519 release-signing
 * private key, producing the detached signature asset (central-office-app.tar.gz.sig)
 * that lib/selfUpdate.js verifies before this hub will self-apply an update.
 *
 * Signs the checksum FILE's exact bytes (not a re-derived digest) so the verifier can
 * check the signature against exactly what it already downloaded for the checksum
 * comparison, with no re-encoding to get wrong on either side. Since that file's
 * contents are the tarball's own sha256, this transitively authenticates the tarball
 * too -- a tampered tarball would already fail the existing checksum comparison
 * before signature verification is ever reached.
 *
 * This is a separate keypair from the appliance's own (SerialKillerTermServer) --
 * different repos, different release artifacts, so a compromise of one doesn't hand
 * over the other. The private key never lives in this repo and this script never asks
 * for one by a default path -- always pass it explicitly, from wherever you actually
 * keep it (password manager export, hardware key, offline USB), so there's no default
 * location an automated build could accidentally pick up and bundle.
 *
 * Usage:
 *   node scripts/sign-release.js <checksum-file> <private-key-pem> [output-sig-file]
 *
 * Example:
 *   node scripts/sign-release.js build/central-office-app.tar.gz.sha256 \
 *     /path/to/release-signing-key.PRIVATE.pem \
 *     build/central-office-app.tar.gz.sig
 */

const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

function main() {
  const [checksumPath, privateKeyPath, outputPath] = process.argv.slice(2);
  if (!checksumPath || !privateKeyPath) {
    console.error('usage: node scripts/sign-release.js <checksum-file> <private-key-pem> [output-sig-file]');
    process.exit(1);
  }
  const sigPath = outputPath || `${checksumPath.replace(/\.sha256$/, '')}.sig`;

  const message = fs.readFileSync(checksumPath);
  const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
  const privateKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem' });
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    console.error(`expected an ed25519 private key, got "${privateKey.asymmetricKeyType}"`);
    process.exit(1);
  }

  // Ed25519 signs the message directly (it does its own hashing internally per
  // RFC 8032) -- passing an algorithm name here would be an error, unlike RSA/ECDSA.
  const signature = crypto.sign(null, message, privateKey);

  fs.mkdirSync(path.dirname(sigPath), { recursive: true });
  fs.writeFileSync(sigPath, `${signature.toString('base64')}\n`);
  console.log(`signed ${checksumPath} -> ${sigPath}`);
}

main();
