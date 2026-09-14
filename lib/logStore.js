'use strict';

const fs = require('fs');
const path = require('path');

const MAX_LINES = 2000;

// Keeps recent log lines in memory (for fast reads) and mirrors them to a
// capped file on disk, so the admin UI's Log tab survives a page reload or a
// server restart instead of only ever showing events since the tab opened.
class LogStore {
  constructor() {
    this.lines = [];
    this.filePath = null;
  }

  init(dataDir) {
    const dir = path.join(dataDir, 'logs');
    fs.mkdirSync(dir, { recursive: true });
    this.filePath = path.join(dir, 'server.log');
    if (fs.existsSync(this.filePath)) {
      const content = fs.readFileSync(this.filePath, 'utf8');
      this.lines = content.split('\n').filter(Boolean).slice(-MAX_LINES);
    }
  }

  append(line) {
    this.lines.push(line);
    if (this.lines.length > MAX_LINES) {
      this.lines = this.lines.slice(-MAX_LINES);
      if (this.filePath) fs.writeFile(this.filePath, this.lines.join('\n') + '\n', () => {});
    } else if (this.filePath) {
      fs.appendFile(this.filePath, line + '\n', () => {});
    }
  }

  getLines() {
    return this.lines;
  }
}

module.exports = new LogStore();
