'use strict';

const fs = require('fs');
const path = require('path');
const configStore = require('./configStore');

const CAPTURE_DIR = path.join(configStore.DATA_DIR, 'captures');

function sanitizePart(name) {
  return String(name || '').replace(/[^a-zA-Z0-9_-]+/g, '_').slice(0, 40) || 'unknown';
}

// Filenames are flat (no per-user subdirectories) and self-describing, same approach the
// appliance's own lib/sessionCapture.js and this hub's TFTP file browser both use --
// keeps "is this path still inside CAPTURE_DIR" trivial to check for the download/delete
// routes.
function sanitizeCaptureFilename(name) {
  const base = path.basename(String(name || '').trim());
  if (!base || base === '.' || base === '..') {
    throw new Error('invalid filename');
  }
  return base;
}

/**
 * Starts a capture file for one bridged session if the connecting console user has
 * capture enabled on their account. Unlike the appliance (which also has a per-port
 * capture toggle), the hub has no local notion of a port to hang that setting on --
 * ports belong to each site's own config -- so this is per-user only. Admin sessions
 * are never captured this way (admins have no captureEnabled field), matching the
 * appliance's own choice not to single out its trusted operators.
 * Returns null when disabled, otherwise an object with write(data) (call for both
 * directions, in event order, so the file reads like the session actually happened) and
 * close().
 */
function startCapture(meta) {
  if (!meta || !meta.userCaptureEnabled) return null;
  fs.mkdirSync(CAPTURE_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `${stamp}_${sanitizePart(meta.username)}_${sanitizePart(meta.siteName)}-${sanitizePart(meta.portLabel)}.log`;
  const filePath = path.join(CAPTURE_DIR, filename);
  const stream = fs.createWriteStream(filePath, { flags: 'a', mode: 0o600 });
  stream.write(
    `=== Session capture started ${new Date().toISOString()} — user "${meta.username}" via ${meta.method} to "${meta.siteName} — ${meta.portLabel}" ===\n`
  );
  let closed = false;
  return {
    write(data) {
      if (!closed) stream.write(data);
    },
    close() {
      if (closed) return;
      closed = true;
      stream.write(`\n=== Session capture ended ${new Date().toISOString()} ===\n`);
      stream.end();
    }
  };
}

function listCaptures() {
  fs.mkdirSync(CAPTURE_DIR, { recursive: true });
  return fs
    .readdirSync(CAPTURE_DIR, { withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => {
      const stat = fs.statSync(path.join(CAPTURE_DIR, e.name));
      return { name: e.name, size: stat.size, modifiedAt: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
}

module.exports = { CAPTURE_DIR, startCapture, listCaptures, sanitizeCaptureFilename };
