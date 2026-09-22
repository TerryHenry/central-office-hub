'use strict';

// Fire-and-forget, same philosophy as lib/syslogClient.js's UDP send: a webhook
// endpoint being slow, wrong, or unreachable should never affect anything else in this
// app. Unlike UDP, HTTP actually reports success/failure, so this returns a promise the
// caller can use to log the outcome (see the "Send Test Alert" button) -- but nothing in
// here ever throws, and nothing that triggers an alert (a site disconnecting, a lockout)
// awaits this before moving on with its own work.
const TIMEOUT_MS = 10000;

async function send(webhookUrl, event, data) {
  const payload = JSON.stringify({ event, timestamp: new Date().toISOString(), ...data });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload,
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`webhook returned HTTP ${res.status}`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.name === 'AbortError' ? 'timed out' : err.message };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { send };
