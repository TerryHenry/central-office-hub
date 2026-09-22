'use strict';

const dgram = require('dgram');
const os = require('os');

const SEVERITY_NOTICE = 5;

// Minimal RFC 3164 (BSD syslog) sender over UDP -- the format nearly every syslog
// server/collector still understands out of the box, without needing TLS/RFC 5424
// framing for what's just a one-way, best-effort audit mirror. Same implementation as
// the appliance's own lib/syslogClient.js, just tagged "central-office" instead of
// "terminalserver" in the packet.
function rfc3164Timestamp(date) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const day = String(date.getDate()).padStart(2, ' ');
  const time = date.toTimeString().slice(0, 8);
  return `${months[date.getMonth()]} ${day} ${time}`;
}

/** Fire-and-forget: never throws, since a syslog server being unreachable shouldn't affect the app. */
function send(host, port, facility, message) {
  try {
    const pri = Number(facility) * 8 + SEVERITY_NOTICE;
    const hostname = os.hostname().replace(/\s+/g, '-');
    const packet = `<${pri}>${rfc3164Timestamp(new Date())} ${hostname} central-office: ${message}`;
    const client = dgram.createSocket('udp4');
    client.send(packet, Number(port), host, () => client.close());
  } catch {
    // best-effort
  }
}

module.exports = { send };
