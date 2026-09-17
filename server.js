'use strict';

const path = require('path');
const https = require('https');
const http = require('http');

const configStore = require('./lib/configStore');
const { ensureHostKey } = require('./lib/hostKeys');
const { ensureTlsCert } = require('./lib/tlsCert');
const logStore = require('./lib/logStore');
const tunnelServer = require('./lib/tunnelServer');
const tftpServer = require('./lib/tftpServer');
const { createWebServer } = require('./lib/webServer');

logStore.init(configStore.DATA_DIR);

const hostKey = ensureHostKey(configStore.DATA_DIR);
const tlsCertPair = ensureTlsCert(configStore.DATA_DIR);

const { app, attachTerminalSocket } = createWebServer(tunnelServer, tftpServer, hostKey.publicKey, hostKey.privateKey);

const webPort = configStore.getConfig().web.port;
const httpsServer = https.createServer({ key: tlsCertPair.key, cert: tlsCertPair.cert }, app);
attachTerminalSocket(httpsServer);
httpsServer.listen(webPort, '0.0.0.0', () => {
  console.log(`Central Office admin UI listening on https://0.0.0.0:${webPort}`);
});

tunnelServer.start(hostKey.privateKey, configStore.getConfig().ssh.port);
tunnelServer.on('log', (line) => console.log(line));

// Loopback-only, plain HTTP -- reachable only from this host itself or via
// tunnelServer's 'tcpip' bridge (which only exists inside an already-authenticated
// edge tunnel connection). Same Express app as the external HTTPS listener: the
// fleet routes it serves (/api/fleet/heartbeat, /api/fleet/backup) are already
// CSRF-exempt and authenticated by their own ed25519 signature regardless of
// transport, so plain HTTP here doesn't weaken anything -- see fleetHeartbeat.js's
// postJsonOverTunnel for why the appliance side skips TLS on this path too.
const internalApiServer = http.createServer(app);
internalApiServer.listen(tunnelServer.INTERNAL_API_PORT, '127.0.0.1', () => {
  console.log(`Internal admin API (tunneled heartbeat bridge) listening on 127.0.0.1:${tunnelServer.INTERNAL_API_PORT}`);
});

const tftpConfig = configStore.getConfig().tftp;
if (tftpConfig.autoStart) {
  tftpServer.start(tftpConfig.port, path.join(configStore.DATA_DIR, 'tftp'), tftpConfig.allowUpload);
}
tftpServer.on('log', (line) => console.log(line));

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
