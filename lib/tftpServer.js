'use strict';

const dgram = require('dgram');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const { logTimestamp } = require('./logTimestamp');

const OP = { RRQ: 1, WRQ: 2, DATA: 3, ACK: 4, ERROR: 5 };
const BLOCK_SIZE = 512;
const TIMEOUT_MS = 3000;
const MAX_RETRIES = 5;

function parseRequest(msg) {
  // opcode(2) + filename\0 + mode\0 [+ options...]
  const nul1 = msg.indexOf(0, 2);
  if (nul1 === -1) return null;
  const filename = msg.toString('binary', 2, nul1);
  const nul2 = msg.indexOf(0, nul1 + 1);
  if (nul2 === -1) return null;
  const mode = msg.toString('ascii', nul1 + 1, nul2).toLowerCase();
  return { filename, mode };
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

function encodeData(block, chunk) {
  const buf = Buffer.alloc(4 + chunk.length);
  buf.writeUInt16BE(OP.DATA, 0);
  buf.writeUInt16BE(block & 0xffff, 2);
  chunk.copy(buf, 4);
  return buf;
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
      conn.send(encodeError(code, message), rinfo.port, rinfo.address, () => conn.close());
    };

    if (parsed.mode !== 'octet') {
      return fail(0, 'Only octet (binary) transfer mode is supported');
    }

    const target = this.resolvePath(parsed.filename);
    if (!target) {
      return fail(2, 'Access violation');
    }

    if (opcode === OP.RRQ) {
      fs.readFile(target, (err, data) => {
        if (err) return fail(1, 'File not found');
        this.log(`${rinfo.address}:${rinfo.port} reading "${parsed.filename}" (${data.length} bytes)`);
        this.sendFile(conn, rinfo, data);
      });
    } else {
      if (!this.allowUpload) return fail(2, 'Uploads are disabled');
      this.log(`${rinfo.address}:${rinfo.port} writing "${parsed.filename}"`);
      this.receiveFile(conn, rinfo, target);
    }
  }

  sendFile(conn, rinfo, data) {
    let block = 0;
    let offset = 0;
    let retries = 0;
    let timer = null;

    const sendBlock = () => {
      const chunk = data.slice(offset, offset + BLOCK_SIZE);
      conn.send(encodeData(block + 1, chunk), rinfo.port, rinfo.address);
      timer = setTimeout(onTimeout, TIMEOUT_MS);
    };

    const onTimeout = () => {
      retries += 1;
      if (retries > MAX_RETRIES) {
        this.log(`${rinfo.address}:${rinfo.port} timed out, aborting transfer`);
        cleanup();
        return;
      }
      sendBlock();
    };

    const cleanup = () => {
      clearTimeout(timer);
      conn.removeListener('message', onMessage);
      conn.close();
    };

    const onMessage = (reply) => {
      if (reply.length < 4 || reply.readUInt16BE(0) !== OP.ACK) return;
      if (reply.readUInt16BE(2) !== ((block + 1) & 0xffff)) return;
      clearTimeout(timer);
      const wasLast = data.length - offset < BLOCK_SIZE;
      if (wasLast) {
        cleanup();
        return;
      }
      block += 1;
      offset += BLOCK_SIZE;
      retries = 0;
      sendBlock();
    };

    conn.on('message', onMessage);
    sendBlock();
  }

  receiveFile(conn, rinfo, targetPath) {
    const chunks = [];
    let expectedBlock = 1;
    let finalBlock = null; // set once the last DATA block has been received & ack'd
    let timer = null;
    let retries = 0;

    const cleanup = () => {
      clearTimeout(timer);
      conn.removeListener('message', onMessage);
      conn.close();
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
        cleanup();
        return;
      }
      sendAck((expectedBlock - 1) & 0xffff);
      timer = setTimeout(onTimeout, TIMEOUT_MS);
    };

    const onMessage = (reply) => {
      if (reply.length < 4 || reply.readUInt16BE(0) !== OP.DATA) return;
      const block = reply.readUInt16BE(2);
      const payload = reply.slice(4);

      if (finalBlock !== null) {
        // The client didn't see our final ACK and retransmitted the last block;
        // resend the ACK and give it another linger window to notice.
        if (block === finalBlock) {
          sendAck(block);
          clearTimeout(timer);
          timer = setTimeout(onTimeout, TIMEOUT_MS);
        }
        return;
      }

      if (block !== (expectedBlock & 0xffff)) {
        // Duplicate/out-of-order block: re-ack the last good block.
        sendAck((expectedBlock - 1) & 0xffff);
        return;
      }

      clearTimeout(timer);
      chunks.push(payload);
      retries = 0;
      sendAck(block);

      if (payload.length < BLOCK_SIZE) {
        finalBlock = block;
        fs.writeFile(targetPath, Buffer.concat(chunks), (err) => {
          if (err) this.log(`Failed to write "${targetPath}": ${err.message}`);
          else this.log(`${rinfo.address}:${rinfo.port} upload complete (${Buffer.concat(chunks).length} bytes)`);
        });
        timer = setTimeout(onTimeout, TIMEOUT_MS);
        return;
      }
      expectedBlock += 1;
      timer = setTimeout(onTimeout, TIMEOUT_MS);
    };

    conn.on('message', onMessage);
    sendAck(0);
    timer = setTimeout(onTimeout, TIMEOUT_MS);
  }
}

module.exports = new TftpServer();
