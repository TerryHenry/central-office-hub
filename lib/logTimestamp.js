'use strict';

// Shared "[prefix]" timestamp for every log line (server activity, TFTP, [AUDIT] entries).
// A fixed YYYY-MM-DD HH:MM:SS format rather than toLocaleString() -- sortable, unambiguous
// across locales (no MM/DD vs DD/MM confusion), and consistent regardless of which module
// built the line.
function logTimestamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}

module.exports = { logTimestamp };
