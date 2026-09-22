'use strict';

const { runHelper } = require('./systemHelper');

async function setNtpServer(server) {
  await runHelper(['ntp-set', server]);
}

async function setTimezone(timezone) {
  await runHelper(['timezone-set', timezone]);
  // timedatectl updates /etc/localtime immediately, but this already-running Node
  // process cached the old zone at startup and won't notice on its own -- setting
  // process.env.TZ directly makes every Date call (log timestamps, session times, etc.)
  // pick up the change right away, no restart required.
  process.env.TZ = timezone;
}

/** Pass an empty/undefined `servers` array to revert to DHCP-provided DNS. */
async function setDns(servers) {
  if (!servers || servers.length === 0) {
    await runHelper(['dns-clear']);
    return;
  }
  await runHelper(['dns-set', ...servers]);
}

async function setStaticIp(connectionName, address, prefix, gateway) {
  await runHelper(['ip-set', connectionName, address, String(prefix), gateway]);
}

async function clearStaticIp(connectionName) {
  await runHelper(['ip-clear', connectionName]);
}

async function setHostname(hostname) {
  await runHelper(['hostname-set', hostname]);
}

/** Restarts just this app (not the whole host) -- e.g. to pick up a new TLS cert. */
async function restartService() {
  await runHelper(['service-restart']);
}

module.exports = {
  setNtpServer,
  setTimezone,
  setDns,
  setStaticIp,
  clearStaticIp,
  setHostname,
  restartService
};
