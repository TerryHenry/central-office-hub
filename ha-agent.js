'use strict';

// Standalone HA agent for central-office-hub -- runs independently of the main app
// (server.js), on both nodes, at all times. See README's "High Availability" section
// for the full two-node setup procedure. This file intentionally has no dependency on
// anything in lib/ -- it must keep working (health-checking, replicating, and being
// ready to promote) even when the main app has crashed or was never started, so it
// can't share code that assumes the main app's process is alive.
//
// Responsibilities:
//   - Health-check the peer agent on a private management port.
//   - If standby: periodically rsync-pull the peer's data directory, keep the main
//     app's service stopped (never half-running against stale state).
//   - If the peer goes unreachable past a failure threshold: promote (final replication
//     pull, claim the VIP or run the DNS update command, start the main service).
//   - Expose /health (for the peer to poll), /status (read by the main app's UI), and
//     /promote (localhost-only manual failback trigger).

const fs = require('fs');
const path = require('path');
const http = require('http');
const { execFile } = require('child_process');

const AGENT_DIR = process.env.HA_AGENT_DIR || '/opt/central-office/ha-agent';
const CONFIG_PATH = path.join(AGENT_DIR, 'config.json');
const STATUS_PATH = path.join(AGENT_DIR, 'status.json');
const PROVISIONING_DIR = path.join(__dirname, 'provisioning');
const VIP_UP_SCRIPT = path.join(PROVISIONING_DIR, 'ha-vip-up.sh');
const VIP_DOWN_SCRIPT = path.join(PROVISIONING_DIR, 'ha-vip-down.sh');
const SERVICE_HELPER_SCRIPT = path.join(PROVISIONING_DIR, 'ha-service-helper.sh');
const LOCALHOST_RE = /^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$/;
// Floor under how often a repeatedly-failing promotion gets retried, independent of
// healthCheck.intervalMs -- see the comment at its use site in startHealthCheckLoop().
const MIN_PROMOTION_RETRY_MS = 5000;

function log(line) {
  console.log(`[${new Date().toISOString()}] [ha-agent] ${line}`);
}

function loadConfig() {
  const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  const config = JSON.parse(raw);
  config.localDataDir = config.localDataDir || '/opt/central-office/data';
  return config;
}

function readStatus() {
  try {
    return JSON.parse(fs.readFileSync(STATUS_PATH, 'utf8'));
  } catch {
    return null;
  }
}

/** No shell interpolation anywhere -- always an argv array via execFile, never exec. */
function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 20000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message || 'command failed').trim()));
      resolve(stdout);
    });
  });
}

class HaAgent {
  constructor(config) {
    this.config = config;
    this.consecutiveFailures = 0;
    this.lastReplicationAt = null;
    this.lastReplicationError = null;
    this.promotedAt = null;
    this.lastPromotionAttemptAt = null;
    // Seeded from disk (not just config.role) so a restarted agent doesn't forget it
    // was already active and either double-claim the VIP or wrongly abandon it. Falls
    // back to "primary starts active" only on a genuinely fresh install with no status
    // file yet.
    const existing = readStatus();
    this.isActive = existing ? !!existing.isActive : this.config.role === 'primary';
  }

  start() {
    log(`starting -- role=${this.config.role} mode=${this.config.mode} initial isActive=${this.isActive}`);
    this.writeCurrentStatus('startup');
    // Reconcile reality with intent on boot: if we think we should be active, make sure
    // the VIP/DNS and the main service are actually in that state rather than trusting
    // the flag blindly (covers "ha-agent restarted, but the main service crashed too").
    if (this.isActive) {
      this.activate('startup reconciliation').catch((e) => log(`startup reconciliation failed: ${e.message}`));
    }
    this.startHealthCheckLoop();
    this.startReplicationLoop();
    this.startHttpServer();
  }

  // ---------- Health checking ----------
  startHealthCheckLoop() {
    const tick = async () => {
      const healthy = await this.checkPeerHealth();
      if (healthy) {
        this.consecutiveFailures = 0;
      } else {
        this.consecutiveFailures += 1;
        log(`peer health check failed (${this.consecutiveFailures}/${this.config.healthCheck.failureThreshold})`);
      }
      // A failed promotion attempt (e.g. misconfigured sudoers, missing arping binary)
      // leaves isActive false, so this condition stays true on every subsequent tick
      // until it actually succeeds -- without a minimum retry gap, a genuinely broken
      // promotion path would get hammered once per health-check interval indefinitely.
      // MIN_PROMOTION_RETRY_MS puts a floor under that independent of how aggressively
      // healthCheck.intervalMs is configured.
      const sinceLastAttempt = this.lastPromotionAttemptAt ? Date.now() - this.lastPromotionAttemptAt : Infinity;
      if (
        !this.isActive &&
        !healthy &&
        this.consecutiveFailures >= this.config.healthCheck.failureThreshold &&
        sinceLastAttempt >= MIN_PROMOTION_RETRY_MS
      ) {
        this.lastPromotionAttemptAt = Date.now();
        await this.promote(`peer unreachable after ${this.consecutiveFailures} consecutive failed checks`);
      }
      this.writeCurrentStatus('health-tick');
    };
    this.healthTimer = setInterval(() => tick().catch((e) => log(`health tick error: ${e.message}`)), this.config.healthCheck.intervalMs);
    this.healthTimer.unref();
    tick().catch((e) => log(`health tick error: ${e.message}`));
  }

  checkPeerHealth() {
    return new Promise((resolve) => {
      const req = http.get(
        {
          host: this.config.peerHost,
          port: this.config.peerPort,
          path: '/health',
          timeout: this.config.healthCheck.timeoutMs
        },
        (res) => {
          res.resume();
          resolve(res.statusCode === 200);
        }
      );
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', () => resolve(false));
    });
  }

  // ---------- Replication (standby only -- never pull data into the live node) ----------
  startReplicationLoop() {
    const tick = async () => {
      if (this.isActive) return;
      try {
        await this.replicateFromPeer();
        this.lastReplicationAt = new Date().toISOString();
        this.lastReplicationError = null;
      } catch (e) {
        this.lastReplicationError = e.message;
        log(`replication failed: ${e.message}`);
      }
      this.writeCurrentStatus('replication-tick');
    };
    this.replicationTimer = setInterval(
      () => tick().catch((e) => log(`replication tick error: ${e.message}`)),
      this.config.replication.intervalMs
    );
    this.replicationTimer.unref();
    tick().catch((e) => log(`replication tick error: ${e.message}`));
  }

  replicateFromPeer() {
    const { sshUser, sshKeyPath, remoteDataDir } = this.config.replication;
    const sshCmd = `ssh -i ${sshKeyPath} -o StrictHostKeyChecking=yes -o BatchMode=yes`;
    const source = remoteDataDir.replace(/\/?$/, '/');
    const dest = this.config.localDataDir.replace(/\/?$/, '/');
    return run('rsync', ['-az', '--delete', '-e', sshCmd, `${sshUser}@${this.config.peerHost}:${source}`, dest]);
  }

  // ---------- Promotion / demotion ----------
  async promote(reason) {
    if (this.isActive) return;
    log(`PROMOTING: ${reason}`);
    await this.activate(reason);
  }

  /** The actual action sequence, shared by promote() and startup reconciliation --
   * idempotent (safe to re-run against a node that's already active). */
  async activate(reason) {
    try {
      await this.replicateFromPeer();
    } catch (e) {
      log(`replication pull before activation failed (proceeding anyway): ${e.message}`);
    }
    if (this.config.mode === 'vip') {
      await this.claimVip();
    } else {
      await this.runDnsUpdate('promote');
    }
    await this.startMainService();
    this.isActive = true;
    this.promotedAt = new Date().toISOString();
    this.writeCurrentStatus(reason);
    log(`now active: ${reason}`);
  }

  /** Manual failback only -- there's no automatic demotion (a recovered peer doesn't
   * silently take back over unless preemptOnRecovery is set, which this build doesn't
   * implement yet since it's off by default; demote() exists for the admin-triggered
   * "step down" side of a manual failback, called from the node giving up the role). */
  async demote(reason) {
    if (!this.isActive) return;
    log(`DEMOTING: ${reason}`);
    await this.stopMainService().catch((e) => log(`stop service failed: ${e.message}`));
    if (this.config.mode === 'vip') {
      await this.releaseVip().catch((e) => log(`release VIP failed: ${e.message}`));
    } else {
      await this.runDnsUpdate('demote').catch((e) => log(`dns demote failed: ${e.message}`));
    }
    this.isActive = false;
    this.writeCurrentStatus(reason);
    log(`now standby: ${reason}`);
  }

  // Crosses into root via the sudoers-gated helper script -- this account has no
  // capability that covers systemd unit control, unlike the VIP methods below.
  startMainService() {
    return run('sudo', [SERVICE_HELPER_SCRIPT, 'start']);
  }

  stopMainService() {
    return run('sudo', [SERVICE_HELPER_SCRIPT, 'stop']);
  }

  // No sudo for VIP claim/release -- this agent's own systemd unit already grants it
  // CAP_NET_ADMIN/CAP_NET_RAW directly (AmbientCapabilities), unlike starting/stopping
  // the main service, which is a different account's territory and does need sudo.
  claimVip() {
    const { address, prefix, interface: iface } = this.config.vip;
    return run(VIP_UP_SCRIPT, [`${address}/${prefix}`, iface]);
  }

  releaseVip() {
    const { address, prefix, interface: iface } = this.config.vip;
    return run(VIP_DOWN_SCRIPT, [`${address}/${prefix}`, iface]);
  }

  runDnsUpdate(action) {
    if (!this.config.dns || !this.config.dns.updateCommand) return Promise.resolve();
    return run(this.config.dns.updateCommand, [action]);
  }

  // ---------- Manual failback (triggered via POST /promote) ----------
  manualPromote() {
    return this.activate('manual promotion requested via API');
  }

  // ---------- Live config reload (triggered via POST /reload-config, after the main
  // app's web UI writes a new config.json) ----------
  reloadConfig() {
    const fresh = loadConfig();
    const wasEnabled = this.config.enabled;
    const oldHealthInterval = this.config.healthCheck.intervalMs;
    const oldReplicationInterval = this.config.replication.intervalMs;
    const oldListenPort = this.config.listenPort;
    this.config = fresh;
    log(`config reloaded -- role=${this.config.role} mode=${this.config.mode} enabled=${this.config.enabled}`);

    if (this.config.listenPort !== oldListenPort) {
      log(`agent listen port changed ${oldListenPort} -> ${this.config.listenPort}, rebinding HTTP server`);
      // Bind the new port right away rather than waiting for the old server's close()
      // callback -- that callback only fires once every existing connection (including
      // the very request that triggered this reload, which may be kept alive) finishes,
      // which left a multi-second gap where neither port answered in testing.
      const oldServer = this.httpServer;
      this.startHttpServer();
      oldServer.close(() => log(`old HTTP server on port ${oldListenPort} closed`));
    }

    // Toggling `enabled` only starts/stops the monitoring loops -- it never touches VIP
    // or main-service state on its own, since silently stopping a live primary's service
    // just because HA was disabled would itself cause an outage.
    if (wasEnabled && !this.config.enabled) {
      log('HA disabled via config update -- stopping health-check and replication loops (current active/standby state left as-is)');
      clearInterval(this.healthTimer);
      clearInterval(this.replicationTimer);
      return;
    }
    if (!wasEnabled && this.config.enabled) {
      log('HA re-enabled via config update -- resuming health-check and replication loops');
      this.startHealthCheckLoop();
      this.startReplicationLoop();
      return;
    }
    if (this.config.enabled) {
      if (this.config.healthCheck.intervalMs !== oldHealthInterval) {
        clearInterval(this.healthTimer);
        this.startHealthCheckLoop();
      }
      if (this.config.replication.intervalMs !== oldReplicationInterval) {
        clearInterval(this.replicationTimer);
        this.startReplicationLoop();
      }
    }
  }

  // ---------- Status ----------
  writeCurrentStatus(event) {
    const status = {
      role: this.config.role,
      mode: this.config.mode,
      isActive: this.isActive,
      consecutiveFailures: this.consecutiveFailures,
      lastReplicationAt: this.lastReplicationAt,
      lastReplicationError: this.lastReplicationError,
      promotedAt: this.promotedAt,
      lastEvent: event,
      updatedAt: new Date().toISOString()
    };
    try {
      fs.writeFileSync(STATUS_PATH, JSON.stringify(status, null, 2));
    } catch (e) {
      log(`failed to write status file: ${e.message}`);
    }
    return status;
  }

  // ---------- Local HTTP server ----------
  startHttpServer() {
    const server = http.createServer((req, res) => {
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (req.method === 'GET' && req.url === '/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(readStatus() || { configured: false }));
        return;
      }
      if (req.method === 'POST' && req.url === '/reload-config') {
        // Only meaningful from the main app running on this same host, same as /promote.
        const remote = req.socket.remoteAddress || '';
        if (!LOCALHOST_RE.test(remote)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'forbidden' }));
          return;
        }
        try {
          this.reloadConfig();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: true }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
        return;
      }
      if (req.method === 'POST' && req.url === '/promote') {
        // Only meaningful from the main app running on this same host -- never exposed
        // for the peer or anyone else to trigger remotely.
        const remote = req.socket.remoteAddress || '';
        if (!LOCALHOST_RE.test(remote)) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'forbidden' }));
          return;
        }
        this.manualPromote()
          .then(() => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
          })
          .catch((e) => {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: e.message }));
          });
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
    });
    server.listen(this.config.listenPort, '0.0.0.0', () => {
      log(`agent HTTP server listening on ${this.config.listenPort}`);
    });
    this.httpServer = server;
  }

  stop() {
    if (this.healthTimer) clearInterval(this.healthTimer);
    if (this.replicationTimer) clearInterval(this.replicationTimer);
    if (this.httpServer) this.httpServer.close();
  }
}

function main() {
  let config;
  try {
    config = loadConfig();
  } catch (e) {
    console.error(`Could not read HA agent config at ${CONFIG_PATH}: ${e.message}`);
    process.exit(1);
  }
  if (!config.enabled) {
    log('config has enabled=false -- exiting');
    process.exit(0);
  }

  const agent = new HaAgent(config);
  agent.start();

  const shutdown = () => {
    agent.stop();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (require.main === module) {
  main();
}

module.exports = { HaAgent, loadConfig, readStatus };
