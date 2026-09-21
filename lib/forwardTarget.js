'use strict';

const net = require('net');

const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

/** True for addresses that would point a forward back at the box itself. */
function isLoopbackAddress(addr) {
  if (!addr) return false;
  const a = String(addr).toLowerCase().replace(/^::ffff:/, '');
  if (net.isIPv4(a)) return a.startsWith('127.') || a.startsWith('0.');
  if (net.isIPv6(a)) return a === '::1' || a === '::';
  return a === 'localhost' || a.endsWith('.localhost');
}

/** Returns a reason string if host/port isn't an acceptable forward destination, else null.
 * The hub only ever asks for a device on this box's network, so loopback is refused (it would
 * expose this box's own internal services), as is anything that isn't a plain host or IP. */
function validateForwardTarget(host, port) {
  if (typeof host !== 'string' || !host) return 'no destination host';
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 'invalid destination port';
  if (!(net.isIP(host) || HOSTNAME_RE.test(host))) return 'invalid destination host';
  if (isLoopbackAddress(host)) return 'loopback destinations are not allowed';
  return null;
}

module.exports = { validateForwardTarget, isLoopbackAddress, HOSTNAME_RE };
