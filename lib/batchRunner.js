'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');

// ---------------------------------------------------------------------------------------
// Batch actions: run one script against many serial-console devices and keep a per-device
// record of what happened. The script language is deliberately tiny -- one step per line:
//
//   # comment
//   login <user> <password>     log in (skips itself if a prompt is already showing)
//   send <text>                 type the text and press Enter (a bare "send" just presses Enter)
//   <text>                      any other line is the same as "send <text>"
//   send-raw <text>             type the text with no Enter (\r \n \t \e \xNN escapes work)
//   expect <text>               wait until the device prints this text (case-insensitive)
//   expect-regex <pattern> [timeout=N]
//   wait <seconds>
//   set idle <ms> | set timeout <seconds>
//
// {{username}} {{password}} {{site}} {{port}} are substituted at run time, so credentials
// never have to be saved in the script itself.
// ---------------------------------------------------------------------------------------

const MAX_TRANSCRIPT = 32 * 1024;
const MAX_RUNS = 50;
const MAX_TARGETS = 100;
const MAX_SCRIPT_CHARS = 20000;
const MAX_STEPS = 500;
const CONCURRENCY = 5;
const DEFAULT_EXPECT_MS = 30000;
const DEFAULT_IDLE_MS = 1500;
const MAX_IDLE_WAIT_MS = 20000;
const LOGIN_STEP_MS = 15000;
const PROMPT_RE = /[>#$%]\s*$/;
const VARIABLES = new Set(['username', 'password', 'site', 'port']);

function stripTerminalNoise(s) {
  return s
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\x1b[@-Z\\-_]/g, '')
    .replace(/\r/g, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}

function unescapeText(s) {
  return s.replace(/\\(r|n|t|e|\\|x[0-9a-fA-F]{2})/g, (_, c) => {
    if (c === 'r') return '\r';
    if (c === 'n') return '\n';
    if (c === 't') return '\t';
    if (c === 'e') return '\x1b';
    if (c === '\\') return '\\';
    return String.fromCharCode(parseInt(c.slice(1), 16));
  });
}

/** Parses a script into steps, throwing an Error naming the offending line. */
function parseScript(script) {
  if (typeof script !== 'string' || !script.trim()) throw new Error('the script is empty');
  if (script.length > MAX_SCRIPT_CHARS) throw new Error(`the script is too long (max ${MAX_SCRIPT_CHARS} characters)`);
  const steps = [];
  const lines = script.replace(/\r\n/g, '\n').split('\n');
  lines.forEach((rawLine, i) => {
    const n = i + 1;
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) return;
    const fail = (msg) => {
      throw new Error(`line ${n}: ${msg}`);
    };
    const [word, ...restParts] = line.split(/\s+/);
    const rest = line.slice(word.length).trim();
    const keyword = word.toLowerCase();
    let step;
    if (keyword === 'wait') {
      const secs = Number(rest);
      if (!Number.isFinite(secs) || secs < 0 || secs > 600) fail('wait needs a number of seconds from 0 to 600');
      step = { type: 'wait', seconds: secs };
    } else if (keyword === 'send') {
      step = { type: 'send', text: rest, raw: false };
    } else if (keyword === 'send-raw') {
      step = { type: 'send', text: rest, raw: true };
    } else if (keyword === 'expect') {
      if (!rest) fail('expect needs the text to wait for');
      step = { type: 'expect', text: rest, regex: null, timeoutMs: null };
    } else if (keyword === 'expect-regex') {
      const m = rest.match(/^(.*?)(?:\s+timeout=(\d+))?$/);
      if (!m[1]) fail('expect-regex needs a pattern');
      let re;
      try {
        re = new RegExp(m[1], 'i');
      } catch (e) {
        fail(`invalid pattern: ${e.message}`);
      }
      step = { type: 'expect', text: m[1], regex: re, timeoutMs: m[2] ? Number(m[2]) * 1000 : null };
    } else if (keyword === 'login') {
      if (restParts.length < 2) fail('login needs a username and a password: login <user> <password>');
      step = { type: 'login', username: restParts[0], password: rest.slice(restParts[0].length).trim() };
    } else if (keyword === 'set') {
      const [what, value] = restParts;
      const num = Number(value);
      if (what === 'idle' && Number.isFinite(num) && num >= 0 && num <= MAX_IDLE_WAIT_MS) step = { type: 'set', idleMs: num };
      else if (what === 'timeout' && Number.isFinite(num) && num > 0 && num <= 600) step = { type: 'set', expectMs: num * 1000 };
      else fail('use "set idle <ms>" (0-20000) or "set timeout <seconds>" (1-600)');
    } else {
      step = { type: 'send', text: line, raw: false };
    }
    for (const value of [step.text, step.username, step.password]) {
      if (typeof value !== 'string') continue;
      for (const v of value.matchAll(/\{\{\s*([a-zA-Z]+)\s*\}\}/g)) {
        if (!VARIABLES.has(v[1])) fail(`unknown variable {{${v[1]}}} (available: ${[...VARIABLES].join(', ')})`);
      }
    }
    // What's shown in the history: a literal password on a login line is masked.
    step.line = n;
    step.display = step.type === 'login' && !/^\{\{/.test(step.password) ? `login ${step.username} ********` : line;
    steps.push(step);
  });
  if (!steps.length) throw new Error('the script has no steps');
  if (steps.length > MAX_STEPS) throw new Error(`too many steps (max ${MAX_STEPS})`);
  return steps;
}

/** The device's side of a session: buffers output, and lets steps wait for things to appear. */
class DeviceConsole {
  constructor(stream, onText) {
    this.stream = stream;
    this.text = '';
    this.pos = 0; // start of the output no step has consumed yet
    this.lastData = Date.now();
    this.closed = false;
    this.cancelled = false;
    this.waiters = new Set();
    stream.on('data', (chunk) => {
      const s = stripTerminalNoise(chunk.toString('latin1'));
      this.lastData = Date.now();
      if (s) {
        this.text += s;
        if (this.text.length > 512 * 1024) {
          const drop = this.text.length - 256 * 1024;
          this.text = this.text.slice(drop);
          this.pos = Math.max(0, this.pos - drop);
        }
        if (onText) onText(s);
      }
      this.notify();
    });
    const onEnd = () => {
      this.closed = true;
      this.notify();
    };
    stream.on('close', onEnd);
    stream.on('end', onEnd);
    stream.on('error', onEnd);
  }

  notify() {
    for (const w of [...this.waiters]) w();
  }

  unread() {
    return this.text.slice(this.pos);
  }

  cancel() {
    this.cancelled = true;
    this.notify();
  }

  write(s) {
    if (this.closed) throw new Error('the connection closed');
    this.stream.write(Buffer.from(s, 'latin1'));
  }

  /** Resolves true once predicate() holds, false on timeout; rejects if the session ends or is cancelled first. */
  waitUntil(predicate, timeoutMs) {
    return new Promise((resolve, reject) => {
      let timer;
      let poll;
      const done = (fn, value) => {
        clearTimeout(timer);
        clearInterval(poll);
        this.waiters.delete(check);
        fn(value);
      };
      const check = () => {
        if (this.cancelled) return done(reject, new Error('cancelled'));
        if (predicate()) return done(resolve, true);
        if (this.closed) {
          const tail = this.unread().trim().slice(-160);
          return done(reject, new Error(`the connection closed${tail ? ` (device said: ${tail})` : ''}`));
        }
      };
      this.waiters.add(check);
      timer = setTimeout(() => done(resolve, false), timeoutMs);
      poll = setInterval(check, 100);
      check();
    });
  }
}

function substitute(text, vars) {
  return text.replace(/\{\{\s*([a-zA-Z]+)\s*\}\}/g, (_, name) => (vars[name] !== undefined ? String(vars[name]) : ''));
}

/** Runs parsed steps against a console. onStep(i, status, note) reports progress; throws on the first failure. */
async function runSteps(con, steps, vars, onStep, opts = {}) {
  const loginMs = opts.loginMs || LOGIN_STEP_MS;
  let idleMs = opts.idleMs !== undefined ? opts.idleMs : DEFAULT_IDLE_MS;
  let expectMs = DEFAULT_EXPECT_MS;

  const sendText = (text, raw) => {
    con.pos = con.text.length; // only output produced after this counts as the reply
    con.write(raw ? unescapeText(text) : `${text}\r`);
  };
  const waitQuiet = async () => {
    const sentAt = Date.now();
    try {
      await con.waitUntil(() => Date.now() - con.lastData >= idleMs && Date.now() - sentAt >= idleMs, MAX_IDLE_WAIT_MS);
    } catch (e) {
      // A device that reboots or resets right after a command may drop the session -- that's the
      // command taking effect, not a failure. (A later step that needs the device still fails.)
      if (!/^the connection closed/.test(e.message)) throw e;
    }
  };

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    onStep(i, 'running');
    try {
      let note;
      if (step.type === 'wait') {
        const until = Date.now() + step.seconds * 1000;
        await con.waitUntil(() => Date.now() >= until, step.seconds * 1000 + 500);
      } else if (step.type === 'set') {
        if (step.idleMs !== undefined) idleMs = step.idleMs;
        if (step.expectMs !== undefined) expectMs = step.expectMs;
      } else if (step.type === 'send') {
        sendText(substitute(step.text, vars), step.raw);
        // Wait for the device to go quiet -- unless the next step is an expect, which waits anyway.
        const next = steps[i + 1];
        if (!step.raw && !(next && (next.type === 'expect' || next.type === 'login'))) await waitQuiet();
      } else if (step.type === 'expect') {
        const needle = step.regex ? null : substitute(step.text, vars).toLowerCase();
        let matchEnd = -1;
        const found = await con.waitUntil(() => {
          const unread = con.unread();
          if (step.regex) {
            const m = step.regex.exec(unread);
            if (m) matchEnd = m.index + m[0].length;
          } else {
            const idx = unread.toLowerCase().indexOf(needle);
            if (idx >= 0) matchEnd = idx + needle.length;
          }
          return matchEnd >= 0;
        }, step.timeoutMs || expectMs);
        if (!found) {
          const secs = Math.round((step.timeoutMs || expectMs) / 1000);
          throw new Error(`timed out after ${secs}s waiting for "${step.text}"`);
        }
        con.pos += matchEnd;
      } else if (step.type === 'login') {
        const user = substitute(step.username, vars);
        const pass = substitute(step.password, vars);
        con.pos = con.text.length;
        con.write('\r');
        const atPrompt = () => /(login|username|user name)\s*:\s*$/i.test(con.unread()) || PROMPT_RE.test(con.unread());
        if (!(await con.waitUntil(atPrompt, loginMs))) throw new Error('no login or command prompt appeared (is the device on and cabled?)');
        if (/(login|username|user name)\s*:\s*$/i.test(con.unread())) {
          sendText(user, false);
          if (!(await con.waitUntil(() => /password\s*:\s*$/i.test(con.unread()), loginMs))) throw new Error('no password prompt appeared');
          sendText(pass, false);
          let failed = false;
          const ok = await con.waitUntil(() => {
            const u = con.unread();
            if (/(incorrect|invalid|failed|denied|bad password|authentication fail)/i.test(u)) {
              failed = true;
              return true;
            }
            return PROMPT_RE.test(u);
          }, loginMs);
          if (failed) throw new Error('login was rejected by the device');
          if (!ok) throw new Error('no command prompt appeared after logging in');
          note = 'logged in';
        } else {
          note = 'already at a prompt';
        }
        con.pos = con.text.length;
      }
      onStep(i, 'ok', note);
    } catch (e) {
      onStep(i, e.message === 'cancelled' ? 'cancelled' : 'failed', e.message);
      for (let j = i + 1; j < steps.length; j++) onStep(j, 'skipped');
      throw e;
    }
  }
}

/**
 * Owns batch runs. deps: { openPort(siteId, portId) -> Promise<duplex stream>,
 * describe(siteId, portId) -> {siteName, portLabel} | null, dataDir, log(line) }.
 */
class BatchManager extends EventEmitter {
  constructor(deps) {
    super();
    this.deps = deps;
    this.runs = []; // newest first
    this.consoles = new Map(); // "runId:targetIndex" -> DeviceConsole
    this.queue = [];
    this.active = 0;
    this.file = deps.dataDir ? path.join(deps.dataDir, 'batch-runs.json') : null;
    this.saveTimer = null;
    this.load();
  }

  load() {
    if (!this.file || !fs.existsSync(this.file)) return;
    try {
      const data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      this.runs = Array.isArray(data.runs) ? data.runs : [];
    } catch {
      this.runs = [];
    }
    // A restart interrupts anything that was mid-flight.
    for (const run of this.runs) {
      if (run.status === 'queued' || run.status === 'running') {
        run.status = 'interrupted';
        run.finishedAt = run.finishedAt || new Date().toISOString();
        for (const t of run.targets) {
          if (t.status === 'queued' || t.status === 'running') {
            t.status = 'failed';
            t.error = 'the hub restarted while this was running';
          }
        }
      }
    }
  }

  save() {
    if (!this.file) return;
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      fs.writeFile(this.file, JSON.stringify({ runs: this.runs }), { mode: 0o600 }, () => {});
    }, 300);
    this.saveTimer.unref();
  }

  summary(run) {
    const counts = { queued: 0, running: 0, succeeded: 0, failed: 0, cancelled: 0 };
    for (const t of run.targets) counts[t.status] = (counts[t.status] || 0) + 1;
    return {
      id: run.id,
      name: run.name,
      status: run.status,
      startedAt: run.startedAt,
      finishedAt: run.finishedAt,
      targetCount: run.targets.length,
      counts
    };
  }

  list() {
    return this.runs.map((r) => this.summary(r));
  }

  get(id) {
    return this.runs.find((r) => r.id === id) || null;
  }

  /** Validates everything up front (so a typo never reaches a device), then queues the run. */
  start({ name, script, vars, targets, startedBy }) {
    const steps = parseScript(script);
    if (!Array.isArray(targets) || targets.length === 0) throw new Error('choose at least one port');
    if (targets.length > MAX_TARGETS) throw new Error(`too many ports (max ${MAX_TARGETS} per batch)`);
    const seen = new Set();
    const resolved = [];
    for (const t of targets) {
      const key = `${t && t.siteId}:${t && t.portId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const info = this.deps.describe(t && t.siteId, t && t.portId);
      if (!info) throw new Error('one of the chosen ports no longer exists');
      resolved.push({ siteId: t.siteId, portId: t.portId, ...info });
    }
    const run = {
      id: crypto.randomUUID(),
      name: String(name || 'Batch').trim().slice(0, 80) || 'Batch',
      status: 'running',
      startedAt: new Date().toISOString(),
      startedBy: startedBy || null,
      finishedAt: null,
      script: steps.map((s) => s.display).join('\n'),
      cancelled: false,
      targets: resolved.map((r) => ({
        siteId: r.siteId,
        siteName: r.siteName,
        portId: r.portId,
        portLabel: r.portLabel,
        status: 'queued',
        startedAt: null,
        finishedAt: null,
        error: null,
        steps: steps.map((s) => ({ line: s.line, text: s.display, status: 'pending', note: null })),
        transcript: '',
        truncated: false
      }))
    };
    const safeVars = { username: (vars && vars.username) || '', password: (vars && vars.password) || '' };
    this.runs.unshift(run);
    // Keep the history bounded: drop the oldest runs that have finished.
    while (this.runs.length > MAX_RUNS) {
      let drop = -1;
      for (let i = this.runs.length - 1; i >= 0; i--) {
        if (this.runs[i].finishedAt) {
          drop = i;
          break;
        }
      }
      if (drop < 0) break;
      this.runs.splice(drop, 1);
    }
    run.targets.forEach((target, index) => this.queue.push({ run, target, index, steps, vars: safeVars }));
    this.deps.log(`batch "${run.name}" started on ${run.targets.length} port${run.targets.length === 1 ? '' : 's'}`);
    this.save();
    this.pump();
    return this.summary(run);
  }

  pump() {
    while (this.active < CONCURRENCY && this.queue.length) {
      const job = this.queue.shift();
      if (job.run.cancelled) {
        job.target.status = 'cancelled';
        job.target.finishedAt = new Date().toISOString();
        this.finishIfDone(job.run);
        continue;
      }
      this.active++;
      this.runTarget(job).finally(() => {
        this.active--;
        this.pump();
      });
    }
  }

  async runTarget({ run, target, index, steps, vars }) {
    target.status = 'running';
    target.startedAt = new Date().toISOString();
    const setStep = (i, status, note) => {
      target.steps[i].status = status;
      if (note) target.steps[i].note = note;
    };
    let stream;
    try {
      stream = await this.deps.openPort(target.siteId, target.portId);
    } catch (e) {
      target.status = 'failed';
      target.error = `could not open the port: ${e.message}`;
      target.finishedAt = new Date().toISOString();
      target.steps.forEach((s) => (s.status = 'skipped'));
      this.deps.log(`batch "${run.name}": ${target.siteName} / ${target.portLabel} failed -- ${target.error}`);
      this.finishIfDone(run);
      return;
    }
    const con = new DeviceConsole(stream, (text) => {
      target.transcript += text;
      if (target.transcript.length > MAX_TRANSCRIPT) {
        target.transcript = target.transcript.slice(-MAX_TRANSCRIPT);
        target.truncated = true;
      }
    });
    const key = `${run.id}:${index}`;
    this.consoles.set(key, con);
    const runVars = { ...vars, site: target.siteName, port: target.portLabel };
    try {
      if (run.cancelled) con.cancel();
      await runSteps(con, steps, runVars, setStep, this.deps.timing);
      target.status = 'succeeded';
    } catch (e) {
      target.status = e.message === 'cancelled' ? 'cancelled' : 'failed';
      target.error = e.message;
    } finally {
      this.consoles.delete(key);
      try {
        stream.destroy();
      } catch {
        // already closed
      }
      target.finishedAt = new Date().toISOString();
      this.deps.log(
        `batch "${run.name}": ${target.siteName} / ${target.portLabel} ${target.status}${target.error ? ` -- ${target.error}` : ''}`
      );
      this.finishIfDone(run);
    }
  }

  finishIfDone(run) {
    this.save();
    if (run.finishedAt || run.targets.some((t) => t.status === 'queued' || t.status === 'running')) return;
    run.finishedAt = new Date().toISOString();
    const failed = run.targets.some((t) => t.status === 'failed');
    run.status = run.cancelled ? 'cancelled' : failed ? 'failed' : 'completed';
    this.deps.log(`batch "${run.name}" finished: ${run.status}`);
    this.save();
  }

  cancel(id) {
    const run = this.get(id);
    if (!run) throw new Error('batch not found');
    if (run.finishedAt) throw new Error('that batch has already finished');
    run.cancelled = true;
    // Targets that haven't started are cancelled on the spot.
    this.queue = this.queue.filter((job) => {
      if (job.run !== run) return true;
      job.target.status = 'cancelled';
      job.target.finishedAt = new Date().toISOString();
      return false;
    });
    run.targets.forEach((t, index) => {
      const con = this.consoles.get(`${run.id}:${index}`);
      if (con) con.cancel();
    });
    this.finishIfDone(run);
  }

  remove(id) {
    const run = this.get(id);
    if (!run) throw new Error('batch not found');
    if (!run.finishedAt) throw new Error('cancel the batch before deleting it');
    this.runs = this.runs.filter((r) => r.id !== id);
    this.save();
  }
}

module.exports = { BatchManager, parseScript, runSteps, DeviceConsole, stripTerminalNoise };
