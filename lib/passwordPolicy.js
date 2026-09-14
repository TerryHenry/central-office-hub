'use strict';

const fs = require('fs');
const path = require('path');

// Loaded once at startup into a Set for O(1) lookups -- a bundled list, not a live API
// call, so this never depends on the Pi having internet access and never sends a
// candidate password anywhere. Source: SecLists' 10k-most-common.txt, lowercased and
// deduplicated. Matched case-insensitively: "Password1" is exactly as weak as
// "password1", and a real attacker's list doesn't care about capitalization either.
const COMMON_PASSWORDS = new Set(
  fs
    .readFileSync(path.join(__dirname, 'data', 'common-passwords.txt'), 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
);

const MAX_LENGTH = 128; // sane upper bound -- scrypt hashing an unbounded input is a cheap DoS lever

function isCommonPassword(password) {
  return COMMON_PASSWORDS.has(password.toLowerCase());
}

/**
 * Validates a candidate password against the given policy. Returns null if valid,
 * or a user-facing error string describing exactly what's wrong.
 */
function validatePassword(password, policy) {
  if (typeof password !== 'string' || password.length === 0) {
    return 'a password is required';
  }
  if (password.length > MAX_LENGTH) {
    return `password must be ${MAX_LENGTH} characters or fewer`;
  }
  if (password.length < policy.minLength) {
    return `password must be at least ${policy.minLength} characters`;
  }
  if (policy.requireMixedCase && !(/[a-z]/.test(password) && /[A-Z]/.test(password))) {
    return 'password must include both uppercase and lowercase letters';
  }
  if (policy.requireDigit && !/[0-9]/.test(password)) {
    return 'password must include at least one digit';
  }
  if (policy.requireSymbol && !/[^a-zA-Z0-9]/.test(password)) {
    return 'password must include at least one symbol';
  }
  if (policy.checkBreached && isCommonPassword(password)) {
    return 'that password is on a list of commonly breached passwords -- choose a different one';
  }
  return null;
}

/** A short, human-readable summary of the current policy, for hint text in the UI. */
function describePolicy(policy) {
  const parts = [`at least ${policy.minLength} characters`];
  if (policy.requireMixedCase) parts.push('upper & lowercase letters');
  if (policy.requireDigit) parts.push('a digit');
  if (policy.requireSymbol) parts.push('a symbol');
  let text = parts.join(', ');
  if (policy.checkBreached) text += '; not a commonly breached password';
  return text;
}

module.exports = { validatePassword, describePolicy, isCommonPassword };
