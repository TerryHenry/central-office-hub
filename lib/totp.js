'use strict';

const crypto = require('crypto');

// RFC 4648 base32, no padding -- the standard encoding authenticator apps expect for a
// TOTP secret (no external dependency needed for something this small).
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** A fresh random secret, base32-encoded, ready to hand to an authenticator app. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

// RFC 4226 HOTP: HMAC-SHA1 over an 8-byte big-endian counter, then "dynamic truncation"
// down to a fixed number of decimal digits.
function hotp(keyBuffer, counter, digits = 6) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', keyBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

// RFC 6238 TOTP: HOTP keyed by the current 30-second time step instead of an incrementing
// counter.
function totp(secretBase32, atTimeMs = Date.now(), step = 30, digits = 6) {
  const counter = Math.floor(atTimeMs / 1000 / step);
  return hotp(base32Decode(secretBase32), counter, digits);
}

/**
 * Accepts a code from one step early or late (±30s) too, so a slightly-off device clock
 * or the natural delay of typing the code in doesn't spuriously fail. Comparisons are
 * constant-time to avoid leaking which digit differs via timing.
 */
function verifyToken(secretBase32, token, window = 1) {
  if (!/^\d{6}$/.test(String(token || ''))) return false;
  const tokenBuffer = Buffer.from(String(token));
  const now = Date.now();
  for (let stepOffset = -window; stepOffset <= window; stepOffset++) {
    const candidate = totp(secretBase32, now + stepOffset * 30 * 1000);
    const candidateBuffer = Buffer.from(candidate);
    if (crypto.timingSafeEqual(tokenBuffer, candidateBuffer)) return true;
  }
  return false;
}

function otpauthUrl(secretBase32, accountName, issuer = 'Serial Killer Terminal Server') {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = { generateSecret, verifyToken, otpauthUrl, base32Encode, base32Decode, hotp, totp };
