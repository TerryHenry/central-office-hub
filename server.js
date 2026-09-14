'use strict';

const https = require('https');

const configStore = require('./lib/configStore');
const { ensureHostKey } = require('./lib/hostKeys');
const { ensureTlsCert } = require('./lib/tlsCert');
const logStore = require('./lib/logStore');
const tunnelServer = require('./lib/tunnelServer');
const { createWebServer } = require('./lib/webServer');

logStore.init(configStore.DATA_DIR);

const hostKey = ensureHostKey(configStore.DATA_DIR);
const tlsCertPair = ensureTlsCert(configStore.DATA_DIR);

const { app, attachTerminalSocket } = createWebServer(tunnelServer, hostKey.publicKey);

const webPort = configStore.getConfig().web.port;
const httpsServer = https.createServer({ key: tlsCertPair.key, cert: tlsCertPair.cert }, app);
attachTerminalSocket(httpsServer);
httpsServer.listen(webPort, '0.0.0.0', () => {
  console.log(`Central Office admin UI listening on https://0.0.0.0:${webPort}`);
});

tunnelServer.start(hostKey.privateKey, configStore.getConfig().ssh.port);
tunnelServer.on('log', (line) => console.log(line));

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
