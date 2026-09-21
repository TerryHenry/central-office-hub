'use strict';

const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { logTimestamp } = require('./logTimestamp');

const OP = { RRQ: 1, WRQ: 2, DATA: 3, ACK: 4, ERROR: 5, OACK: 6 };
const DEFAULT_BLOCK_SIZE = 512;
const MAX_BLOCK_SIZE = 8192; // RFC 2348 allows up to 65464; capped to stay friendly to slow/embedded links
const MAX_WINDOW_SIZE = 16; // RFC 7440
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_RETRIES = 5;

/** opcode(2) + filename\0 + mode\0 [+ optname\0 optval\0 ...] (RFC 2347 options). */
function parseRequest(msg) {
  const nul1 = msg.indexOf(0, 2);
  if (nul1 === -1) return null;
  const filename = msg.toString('binary', 2, nul1);
  const nul2 = msg.indexOf(0, nul1 + 1);
  if (nul2 === -1) return null;
  const mode = msg.toString('ascii', nul1 + 1, nul2).toLowerCase();

  const options = {};
  let pos = nul2 + 1;
  while (pos < msg.length) {
    const nameEnd = msg.indexOf(0, pos);
    if (nameEnd === -1) break;
    const valEnd = msg.indexOf(0, nameEnd + 1);
    if (valEnd === -1) break;
    options[msg.toString('ascii', pos, nameEnd).toLowerCase()] = msg.toString('ascii', nameEnd + 1, valEnd);
    pos = valEnd + 1;
  }
  return { filename, mode, options };
}

function encodeError(code, message) {
  const msgBuf = Buffer.from(message, 'ascii');
  const buf = Buffer.alloc(4 + msgBuf.length + 1);
  buf.writeUInt16BE(OP.ERROR, 0);
  buf.writeUInt16BE(code, 2);
  msgBuf.copy(buf, 4);
  buf[4 + msgBuf.length] = 0;
  return buf;
}

function encodeAck(block) {
  const buf = Buffer.alloc(4);
  buf.writeUInt16BE(OP.ACK, 0);
  buf.writeUInt16BE(block & 0xffff, 2);
  return buf;
}

function encodeOack(accepted) {
  const parts = [];
  for (const [k, v] of Object.entries(accepted)) parts.push(Buffer.from(`${k}\0${v}\0`, 'ascii'));
  return Buffer.concat([Buffer.from([0, OP.OACK]), ...parts]);
}

/** Decides which of the client's requested options to accept. Unknown options are simply
 * left out of the OACK, as RFC 2347 requires. `fileSize` is set for reads (answers tsize=0). */
function negotiate(options, { isRead, fileSize }) {
  const accepted = {};
  const neg = { blksize: DEFAULT_BLOCK_SIZE, windowsize: 1, timeoutMs: DEFAULT_TIMEOUT_MS };

  const blk = parseInt(options.blksize, 10);
  if (blk >= 8) {
    neg.blksize = Math.min(blk, MAX_BLOCK_SIZE);
    accepted.blksize = String(neg.blksize);
  }
  const tmo = parseInt(options.timeout, 10);
  if (tmo >= 1 && tmo <= 255) {
    neg.timeoutMs = tmo * 1000;
    accepted.timeout = String(tmo);
  }
  if (options.tsize !== undefined) {
    if (isRead) accepted.tsize = String(fileSize);
    else if (/^\d+$/.test(options.tsize)) accepted.tsize = options.tsize;
  }
  // Windowing is only implemented for sending; for uploads it's omitted from the OACK,
  // which tells the client to fall back to a window of 1.
  const win = parseInt(options.windowsize, 10);
  if (isRead && win >= 1) {
    neg.windowsize = Math.min(win, MAX_WINDOW_SIZE);
    accepted.windowsize = String(neg.windowsize);
  }
  neg.oack = Object.keys(accepted).length ? encodeOack(accepted) : null;
  return neg;
}

class TftpServer extends EventEmitter {
  constructor() {
    super();
    this.socket = null;
    this.rootDir = null;
    this.allowUpload = true;
  }

  log(line) {
    this.emit('log', `[${logTimestamp()}] [TFTP] ${line}`);
  }

  isRunning() {
    return !!this.socket;
  }

  /** Resolves a client-supplied filename to a safe path inside rootDir, or null if it escapes. */
  resolvePath(filename) {
    const cleaned = filename.replace(/\\/g, '/').replace(/^\/+/, '');
    const resolved = path.normalize(path.join(this.rootDir, cleaned));
    const rootWithSep = this.rootDir.endsWith(path.sep) ? this.rootDir : this.rootDir + path.sep;
    if (resolved !== this.rootDir && !resolved.startsWith(rootWithSep)) return null;
    return resolved;
  }

  start(port, rootDir, allowUpload) {
    if (this.socket) return;
    this.rootDir = rootDir;
    this.allowUpload = !!allowUpload;
    fs.mkdirSync(this.rootDir, { recursive: true });

    this.socket = dgram.createSocket('udp4');

    this.socket.on('error', (err) => {
      this.log(`Server error: ${err.message}`);
      this.emit('error', err);
      this.stop();
    });

    this.socket.on('message', (msg, rinfo) => this.handleRequest(msg, rinfo));

    this.socket.bind(port, '0.0.0.0', () => {
      this.log(`Listening on UDP ${port}, serving ${this.rootDir}`);
      this.emit('status-changed');
    });
  }

  stop() {
    if (!this.socket) return;
    try {
      this.socket.close();
    } catch {
      // already closing
    }
    this.socket = null;
    this.log('Server stopped');
    this.emit('status-changed');
  }

  handleRequest(msg, rinfo) {
    if (msg.length < 4) return;
    const opcode = msg.readUInt16BE(0);
    if (opcode !== OP.RRQ && opcode !== OP.WRQ) return;

    const parsed = parseRequest(msg);
    if (!parsed) return;

    const conn = dgram.createSocket('udp4');
    conn.bind(0, '0.0.0.0');
    // One of these ephemeral per-transfer sockets is created for every RRQ/WRQ -- without
    // a listener here, an unhandled 'error' (e.g. an ICMP port-unreachable from a client
    // that vanished mid-transfer) is fatal to the whole process, not just this transfer.
    conn.on('error', (err) => {
      this.log(`${rinfo.address}:${rinfo.port} transfer socket error: ${err.message}`);
      try {
        conn.close();
      } catch {
        // already closing/closed
      }
    });

    const fail = (code, message) => {
      this.log(`${rinfo.address}:${rinfo.port} ${message}`);
      conn.send(encodeError(code, message), rinfo.port, rinfo.address, () => {
        try {
          conn.close();
        } catch {
          // already closed
        }
      });
    };

    if (parsed.mode !== 'octet') {
      return fail(0, 'Only octet (binary) transfer mode is supported');
    }

    const target = this.resolvePath(parsed.filename);
    if (!target) {
      return fail(2, 'Access violation');
    }

    if (opcode === OP.RRQ) {
      fs.open(target, 'r', (err, fd) => {
        if (err) return fail(1, 'File not found');
        fs.fstat(fd, (statErr, stat) => {
          if (statErr || !stat.isFile()) {
            fs.close(fd, () => {});
            return fail(1, 'File not found');
          }
          const neg = negotiate(parsed.options, { isRead: true, fileSize: stat.size });
          this.log(
            `${rinfo.address}:${rinfo.port} reading "${parsed.filename}" (${stat.size} bytes, block ${neg.blksize}, window ${neg.windowsize})`
          );
          this.sendFile(conn, rinfo, fd, stat.size, neg);
        });
      });
    } else {
      if (!this.allowUpload) return fail(2, 'Uploads are disabled');
      const neg = negotiate(parsed.options, { isRead: false });
      this.log(`${rinfo.address}:${rinfo.port} writing "${parsed.filename}" (block ${neg.blksize})`);
      this.receiveFile(conn, rinfo, target, neg);
    }
  }

  /** Streams a file from disk (never loading it whole into memory) using a sliding window
   * of `neg.windowsize` unacknowledged blocks (1 = classic lock-step TFTP). */
  sendFile(conn, rinfo, fd, fileSize, neg) {
    const { blksize, windowsize, timeoutMs } = neg;
    const totalBlocks = Math.floor(fileSize / blksize) + 1; // the last block is short (possibly empty)
    let base = 0; // highest block number acknowledged so far
    let nextToSend = 1;
    let retries = 0;
    let timer = null;
    let pumping = false;
    let finished = false;
    let oackPending = !!neg.oack;

    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      conn.removeListener('message', onMessage);
      fs.close(fd, () => {});
      try {
        conn.close();
      } catch {
        // already closed
      }
    };

    const armTimer = () => {
      clearTimeout(timer);
      timer = setTimeout(onTimeout, timeoutMs);
    };

    const sendBlock = (n, cb) => {
      const pos = (n - 1) * blksize;
      const len = Math.max(0, Math.min(blksize, fileSize - pos));
      const buf = Buffer.alloc(4 + len);
      buf.writeUInt16BE(OP.DATA, 0);
      buf.writeUInt16BE(n & 0xffff, 2);
      fs.read(fd, buf, 4, len, pos, (err, bytesRead) => {
        if (finished) return;
        if (err) {
          this.log(`${rinfo.address}:${rinfo.port} read error: ${err.message}`);
          conn.send(encodeError(0, 'Read error'), rinfo.port, rinfo.address);
          finish();
          return;
        }
        conn.send(buf.subarray(0, 4 + bytesRead), rinfo.port, rinfo.address);
        cb();
      });
    };

    const pump = () => {
      if (pumping || finished) return;
      pumping = true;
      const step = () => {
        if (finished) return;
        if (nextToSend > totalBlocks || nextToSend > base + windowsize) {
          pumping = false;
          return;
        }
        const n = nextToSend++;
        sendBlock(n, step);
      };
      armTimer();
      step();
    };

    const onTimeout = () => {
      retries += 1;
      if (retries > MAX_RETRIES) {
        this.log(`${rinfo.address}:${rinfo.port} timed out, aborting transfer`);
        finish();
        return;
      }
      if (oackPending) {
        conn.send(neg.oack, rinfo.port, rinfo.address);
        armTimer();
        return;
      }
      nextToSend = base + 1; // go back and resend the whole unacknowledged window
      pump();
    };

    const onMessage = (reply) => {
      if (reply.length < 4 || reply.readUInt16BE(0) !== OP.ACK) return;
      const wire = reply.readUInt16BE(2);

      if (oackPending) {
        if (wire !== 0) return;
        oackPending = false;
        retries = 0;
        pump();
        return;
      }

      // Map the 16-bit wire block number back onto our absolute counter (files bigger
      // than 65535 blocks wrap around on the wire).
      let acked = -1;
      for (let a = base + 1; a <= nextToSend - 1; a += 1) {
        if ((a & 0xffff) === wire) {
          acked = a;
          break;
        }
      }
      if (acked === -1) return;
      base = acked;
      retries = 0;
      if (base >= totalBlocks) {
        finish();
        return;
      }
      pump();
    };

    conn.on('message', onMessage);
    if (oackPending) {
      conn.send(neg.oack, rinfo.port, rinfo.address);
      armTimer();
    } else {
      pump();
    }
  }

  receiveFile(conn, rinfo, targetPath, neg) {
    const { blksize, timeoutMs } = neg;
    // Written to a temp name and renamed only once the transfer completes, so a client
    // that vanishes mid-upload never leaves a truncated file at the real name.
    const tmpPath = `${targetPath}.uploading`;
    const out = fs.createWriteStream(tmpPath);
    let received = 0;
    let expectedBlock = 1;
    let finalBlock = null; // set once the last DATA block has been received & ack'd
    let timer = null;
    let retries = 0;
    let closed = false;

    out.on('error', (err) => {
      this.log(`Failed to write "${targetPath}": ${err.message}`);
      conn.send(encodeError(3, 'Disk write error'), rinfo.port, rinfo.address);
      abort();
    });

    const cleanup = () => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      conn.removeListener('message', onMessage);
      try {
        conn.close();
      } catch {
        // already closed
      }
    };

    const abort = () => {
      cleanup();
      out.destroy();
      fs.unlink(tmpPath, () => {});
    };

    const sendAck = (block) => {
      conn.send(encodeAck(block), rinfo.port, rinfo.address);
    };

    const onTimeout = () => {
      if (finalBlock !== null) {
        // Linger window elapsed with no retransmit: the client got our final ACK. Done.
        cleanup();
        return;
      }
      retries += 1;
      if (retries > MAX_RETRIES) {
        this.log(`${rinfo.address}:${rinfo.port} timed out, aborting upload`);
        abort();
        return;
      }
      if (expectedBlock === 1 && neg.oack) conn.send(neg.oack, rinfo.port, rinfo.address);
      else sendAck((expectedBlock - 1) & 0xffff);
      timer = setTimeout(onTimeout, timeoutMs);
    };

    const onMessage = (reply) => {
      if (reply.length < 4 || reply.readUInt16BE(0) !== OP.DATA) return;
      const block = reply.readUInt16BE(2);
      const payload = reply.subarray(4);

      if (finalBlock !== null) {
        // The client didn't see our final ACK and retransmitted the last block;
        // resend the ACK and give it another linger window to notice.
        if (block === finalBlock) {
          sendAck(block);
          clearTimeout(timer);
          timer = setTimeout(onTimeout, timeoutMs);
        }
        return;
      }

      if (block !== (expectedBlock & 0xffff)) {
        // Duplicate/out-of-order block: re-ack the last good block.
        sendAck((expectedBlock - 1) & 0xffff);
        return;
      }

      clearTimeout(timer);
      retries = 0;
      received += payload.length;
      out.write(payload);
      sendAck(block);

      if (payload.length < blksize) {
        finalBlock = block;
        out.end(() => {
          fs.rename(tmpPath, targetPath, (err) => {
            if (err) this.log(`Failed to write "${targetPath}": ${err.message}`);
            else this.log(`${rinfo.address}:${rinfo.port} upload complete (${received} bytes)`);
          });
        });
        timer = setTimeout(onTimeout, timeoutMs);
        return;
      }
      expectedBlock += 1;
      timer = setTimeout(onTimeout, timeoutMs);
    };

    conn.on('message', onMessage);
    if (neg.oack) conn.send(neg.oack, rinfo.port, rinfo.address);
    else sendAck(0);
    timer = setTimeout(onTimeout, timeoutMs);
  }
}

module.exports = new TftpServer();
