'use strict';

const os = require('os');
const { execFile } = require('child_process');

let lastCpuTimes = sampleCpuTimes();
let cpuPercent = 0;

function sampleCpuTimes() {
  return os.cpus().map((c) => ({ ...c.times }));
}

function updateCpuPercent() {
  const current = sampleCpuTimes();
  let idleDiff = 0;
  let totalDiff = 0;
  for (let i = 0; i < current.length && i < lastCpuTimes.length; i++) {
    const prev = lastCpuTimes[i];
    const curr = current[i];
    const prevTotal = prev.user + prev.nice + prev.sys + prev.idle + prev.irq;
    const currTotal = curr.user + curr.nice + curr.sys + curr.idle + curr.irq;
    totalDiff += currTotal - prevTotal;
    idleDiff += curr.idle - prev.idle;
  }
  if (totalDiff > 0) {
    cpuPercent = Math.round((1 - idleDiff / totalDiff) * 1000) / 10;
  }
  lastCpuTimes = current;
}

const cpuTimer = setInterval(updateCpuPercent, 2000);
cpuTimer.unref();

function getMemory() {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  return { total, free, used, percent: total > 0 ? Math.round((used / total) * 1000) / 10 : 0 };
}

function getDisk(targetPath) {
  return new Promise((resolve) => {
    execFile('df', ['-Pk', targetPath], (err, stdout) => {
      if (err) return resolve(null);
      const lines = stdout.trim().split('\n');
      const cols = lines[lines.length - 1].trim().split(/\s+/);
      if (cols.length < 6) return resolve(null);
      const total = Number(cols[1]) * 1024;
      const used = Number(cols[2]) * 1024;
      const free = Number(cols[3]) * 1024;
      resolve({
        total,
        used,
        free,
        percent: total > 0 ? Math.round((used / total) * 1000) / 10 : 0,
        mount: cols[5]
      });
    });
  });
}

async function getStats(diskPath) {
  return {
    cpuPercent,
    loadavg: os.loadavg(),
    uptimeSec: os.uptime(),
    memory: getMemory(),
    disk: await getDisk(diskPath)
  };
}

module.exports = { getStats };
