'use strict';

const os = require('os');
const fs = require('fs');

function getOsRelease() {
  try {
    const content = fs.readFileSync('/etc/os-release', 'utf8');
    const match = content.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
    if (match) return match[1];
  } catch {
    // Not a Linux host -- real deployments always are (Debian/genericcloud for this
    // hub), so this only matters for local dev testing off-Linux.
  }
  if (process.platform === 'win32') return os.version();
  if (process.platform === 'darwin') return `macOS ${os.release()}`;
  return null;
}

function getSystemInfo() {
  const cpus = os.cpus();
  return {
    hostname: os.hostname(),
    osRelease: getOsRelease(),
    kernel: os.release(),
    arch: os.arch(),
    cpuModel: cpus[0] ? cpus[0].model : 'unknown',
    cpuCores: cpus.length,
    totalMemory: os.totalmem(),
    uptimeSec: os.uptime(),
    nodeVersion: process.version
  };
}

module.exports = { getSystemInfo };
