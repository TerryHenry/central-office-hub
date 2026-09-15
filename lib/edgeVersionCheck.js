'use strict';

// Separate from lib/selfUpdate.js (which checks *this hub's own* repo) -- this checks the
// latest published release of the edge appliance's repo, so the Sites tab can flag a site
// running an older version. Cached: the Sites tab can be loaded/polled often, and this is
// the same public, unauthenticated GitHub API every other "check for update" call here
// already uses, which is rate-limited per source IP.
const EDGE_REPO = 'TerryHenry/SerialKillerTermServer';
const CACHE_MS = 10 * 60 * 1000;

let cached = null;
let cachedAt = 0;

async function fetchLatestEdgeVersion() {
  if (cached && Date.now() - cachedAt < CACHE_MS) return cached;
  try {
    const res = await fetch(`https://api.github.com/repos/${EDGE_REPO}/releases/latest`, {
      headers: { 'User-Agent': 'central-office', Accept: 'application/vnd.github+json' }
    });
    if (!res.ok) return cached; // keep serving a stale (or null) result rather than erroring the Sites tab
    const data = await res.json();
    cached = { version: String(data.tag_name || '').replace(/^v/i, ''), url: data.html_url };
    cachedAt = Date.now();
  } catch {
    // Network hiccup -- keep whatever was cached, if anything.
  }
  return cached;
}

module.exports = { fetchLatestEdgeVersion };
