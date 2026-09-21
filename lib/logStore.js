'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_MAX_LINES = 1000;

// Keeps recent log lines in memory (for fast reads) and mirrors them to a
// capped file on disk, so the admin UI's Log tab survives a page reload or a
// server restart instead of only ever showing events since the tab opened.
class LogStore {
  constructor() {
    this.lines = [];
    this.filePath = null;
    this.max = DEFAULT_MAX_LINES;
  }

  init(dataDir, maxLines) {
    if (Number.isInteger(maxLines) && maxLines > 0) this.max = maxLines;
    const dir = path.join(dataDir, 'logs');
    fs.mkdirSync(dir, { recursive: true });
    this.filePath = path.join(dir, 'server.log');
    if (fs.existsSync(this.filePath)) {
      const content = fs.readFileSync(this.filePath, 'utf8');
      this.lines = content.split('\n').filter(Boolean).slice(-this.max);
    }
  }

  append(line) {
    this.lines.push(line);
    if (this.lines.length > this.max) {
      this.lines = this.lines.slice(-this.max);
      if (this.filePath) fs.writeFile(this.filePath, this.lines.join('\n') + '\n', () => {});
    } else if (this.filePath) {
      fs.appendFile(this.filePath, line + '\n', () => {});
    }
  }

  /** Changes the cap; trims what's kept (in memory and on disk) if it is now over it. */
  setMaxLines(n) {
    this.max = n;
    if (this.lines.length > n) {
      this.lines = this.lines.slice(-n);
      if (this.filePath) fs.writeFile(this.filePath, this.lines.join('\n') + '\n', () => {});
    }
  }

  getLines() {
    return this.lines;
  }
}

module.exports = new LogStore();
