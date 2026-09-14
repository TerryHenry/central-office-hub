'use strict';

// In-memory brute-force protection for the web admin login. Tracked per
// IP+username pair so one bad actor can't lock out a legitimate admin from a
// different address, and a typo'd username on one account doesn't burn down
// the attempt budget for a different one.
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 5 * 60 * 1000;
const WINDOW_MS = 15 * 60 * 1000;

const attempts = new Map();

function key(ip, username) {
  return `${ip}:${username}`;
}

function isLocked(ip, username) {
  const rec = attempts.get(key(ip, username));
  return !!rec && !!rec.lockedUntil && Date.now() < rec.lockedUntil;
}

function remainingLockSeconds(ip, username) {
  const rec = attempts.get(key(ip, username));
  if (!rec || !rec.lockedUntil) return 0;
  return Math.max(0, Math.ceil((rec.lockedUntil - Date.now()) / 1000));
}

function recordFailure(ip, username) {
  const k = key(ip, username);
  const now = Date.now();
  let rec = attempts.get(k);
  if (!rec || now - rec.lastAttempt > WINDOW_MS) {
    rec = { count: 0, lastAttempt: now, lockedUntil: 0 };
  }
  rec.count += 1;
  rec.lastAttempt = now;
  if (rec.count >= MAX_ATTEMPTS) {
    rec.lockedUntil = now + LOCKOUT_MS;
  }
  attempts.set(k, rec);
}

function recordSuccess(ip, username) {
  attempts.delete(key(ip, username));
}

module.exports = { isLocked, remainingLockSeconds, recordFailure, recordSuccess };
