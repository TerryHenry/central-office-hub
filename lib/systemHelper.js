'use strict';

const path = require('path');
const { execFile } = require('child_process');
const configStore = require('./configStore');

const HELPER_PATH = path.join(configStore.DATA_DIR, '..', 'provisioning', 'system-helper.sh');

/**
 * Runs the one fixed, sudoers-whitelisted helper script as root -- today just
 * service-restart, the one step an in-place update genuinely needs root for. Mirrors the
 * appliance's own lib/systemHelper.js.
 */
function runHelper(args) {
  return new Promise((resolve, reject) => {
    // execFile (not exec) with an argv array -- never shell-interpolated.
    execFile('sudo', [HELPER_PATH, ...args], { timeout: 20000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message || 'command failed').trim()));
      resolve(stdout);
    });
  });
}

module.exports = { runHelper };
