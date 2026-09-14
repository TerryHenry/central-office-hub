'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { execFile } = require('child_process');
const { promisify } = require('util');
const configStore = require('./configStore');
const { runHelper } = require('./systemHelper');
const { logTimestamp } = require('./logTimestamp');

const execFileAsync = promisify(execFile);

const { version: CURRENT_VERSION, name: PACKAGE_NAME } = require('../package.json');
const RELEASES_API_URL = 'https://api.github.com/repos/TerryHenry/central-office-hub/releases/latest';
const APP_TARBALL_NAME = 'central-office-app.tar.gz';
const CHECKSUM_NAME = 'central-office-app.tar.gz.sha256';
const MIN_FREE_MB = 500;
const APP_DIR = path.join(configStore.DATA_DIR, '..');
const BACKUP_ROOT = path.join(configStore.DATA_DIR, 'backups');
const STAGING_DIR = path.join(configStore.DATA_DIR, 'update-staging');
const DOWNLOAD_PATH = path.join(configStore.DATA_DIR, 'update-download.tar.gz');
const SWAP_ITEMS = ['server.js', 'package.json', 'package-lock.json', 'lib', 'webui', 'provisioning', 'node_modules'];

function normalizeVersion(v) {
  return String(v || '').trim().replace(/^v/i, '');
}

/**
 * In-place update manager, mirroring the appliance's own lib/selfUpdate.js exactly (same
 * download/verify/stage/validate/backup/swap/restart flow) against this hub's own
 * separate GitHub repo and release asset names.
 */
class SelfUpdateManager extends EventEmitter {
  constructor() {
    super();
    this.updating = false;
  }

  isUpdating() {
    return this.updating;
  }

  log(line) {
    this.emit('log', `[${logTimestamp()}] [UPDATE] ${line}`);
  }

  async fetchLatestRelease() {
    const res = await fetch(RELEASES_API_URL, {
      headers: { 'User-Agent': PACKAGE_NAME, Accept: 'application/vnd.github+json' }
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub returned HTTP ${res.status}`);
    return res.json();
  }

  /** Public status used by the "Check for Updates" button -- no side effects. */
  async checkForUpdate() {
    let release;
    try {
      release = await this.fetchLatestRelease();
    } catch {
      throw new Error('could not reach GitHub — check this host has internet access');
    }
    if (!release) {
      return { currentVersion: CURRENT_VERSION, found: false };
    }
    const tarballAsset = release.assets.find((a) => a.name === APP_TARBALL_NAME);
    const checksumAsset = release.assets.find((a) => a.name === CHECKSUM_NAME);
    return {
      currentVersion: CURRENT_VERSION,
      found: true,
      latestVersion: release.tag_name,
      upToDate: normalizeVersion(release.tag_name) === normalizeVersion(CURRENT_VERSION),
      url: release.html_url,
      // Older releases (published before this feature existed) won't carry these assets --
      // still reported as "an update exists," just not one this hub can self-apply.
      canApplyInPlace: !!(tarballAsset && checksumAsset)
    };
  }

  async checkFreeSpace() {
    const { stdout } = await execFileAsync('df', ['-Pk', configStore.DATA_DIR]);
    const line = stdout.trim().split('\n')[1] || '';
    const availKb = Number(line.trim().split(/\s+/)[3]);
    if (!Number.isFinite(availKb)) return; // couldn't parse -- don't block on a soft check
    if (availKb / 1024 < MIN_FREE_MB) {
      throw new Error(`only ${Math.round(availKb / 1024)}MB free — need at least ${MIN_FREE_MB}MB to apply an update safely`);
    }
  }

  async downloadFile(url, destPath) {
    const res = await fetch(url, { headers: { 'User-Agent': PACKAGE_NAME } });
    if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
    await fsp.mkdir(path.dirname(destPath), { recursive: true });
    const fileStream = fs.createWriteStream(destPath);
    await new Promise((resolve, reject) => {
      const { Readable } = require('stream');
      Readable.fromWeb(res.body).pipe(fileStream).on('finish', resolve).on('error', reject);
    });
  }

  async sha256File(filePath) {
    const hash = crypto.createHash('sha256');
    await new Promise((resolve, reject) => {
      fs.createReadStream(filePath).on('data', (chunk) => hash.update(chunk)).on('end', resolve).on('error', reject);
    });
    return hash.digest('hex');
  }

  /**
   * Strips macOS build-artifact cruft (AppleDouble "._*" sidecar files -- the release
   * tarball is built on a Mac; GNU tar on Linux doesn't understand the xattr PAX headers
   * macOS's tar writes and materializes them as separate "._name" files instead of
   * ignoring them, and .DS_Store, in case one snuck in) so they can't end up in the live
   * app directory or trip up the syntax check below.
   */
  async stripMacCruft(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.name.startsWith('._') || entry.name === '.DS_Store') {
        await this.rmrf(full);
      } else if (entry.isDirectory()) {
        await this.stripMacCruft(full);
      }
    }
  }

  /** Recursively chmod +x's every .sh file under dir. */
  async chmodExecutable(dir) {
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return; // dir doesn't exist -- nothing to do
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await this.chmodExecutable(full);
      } else if (entry.name.endsWith('.sh')) {
        await fsp.chmod(full, 0o755);
      }
    }
  }

  /** Recursively `node --check`s every .js file under dir (skipping node_modules). */
  async checkAllSyntax(dir) {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name.startsWith('._')) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await this.checkAllSyntax(full);
      } else if (entry.name.endsWith('.js')) {
        await execFileAsync(process.execPath, ['--check', full]);
      }
    }
  }

  async rmrf(target) {
    await fsp.rm(target, { recursive: true, force: true });
  }

  async pruneOldBackups() {
    await fsp.mkdir(BACKUP_ROOT, { recursive: true });
    const entries = await fsp.readdir(BACKUP_ROOT);
    const backups = entries.filter((e) => e.startsWith('pre-update-')).sort();
    // Keep only the single most recent backup -- one level of undo, without letting
    // backups (which include a full node_modules copy) accumulate and fill the disk.
    for (const old of backups) {
      await this.rmrf(path.join(BACKUP_ROOT, old));
    }
  }

  async copyInto(srcDir, destDir, items) {
    await fsp.mkdir(destDir, { recursive: true });
    for (const item of items) {
      const src = path.join(srcDir, item);
      if (!fs.existsSync(src)) continue;
      await fsp.cp(src, path.join(destDir, item), { recursive: true });
    }
  }

  /**
   * The whole apply flow: download, verify, stage, validate, back up, swap in, restart.
   * Everything up through the backup step is fully reversible with no live impact --
   * the running service is never touched until the very last step.
   */
  async applyUpdate() {
    if (this.updating) {
      const err = new Error('an update is already in progress');
      this.log(`FAILED: ${err.message}`);
      throw err;
    }
    this.updating = true;
    try {
      this.log('checking latest release...');
      const release = await this.fetchLatestRelease();
      if (!release) throw new Error('no releases found');
      const targetVersion = release.tag_name;
      const tarballAsset = release.assets.find((a) => a.name === APP_TARBALL_NAME);
      const checksumAsset = release.assets.find((a) => a.name === CHECKSUM_NAME);
      if (!tarballAsset || !checksumAsset) {
        throw new Error(`release ${targetVersion} does not publish an in-place update package`);
      }
      if (normalizeVersion(targetVersion) === normalizeVersion(CURRENT_VERSION)) {
        throw new Error(`already on ${CURRENT_VERSION}`);
      }

      await this.checkFreeSpace();

      this.log(`downloading ${targetVersion}...`);
      await this.downloadFile(tarballAsset.browser_download_url, DOWNLOAD_PATH);

      this.log('verifying checksum...');
      const checksumRes = await fetch(checksumAsset.browser_download_url, { headers: { 'User-Agent': PACKAGE_NAME } });
      if (!checksumRes.ok) throw new Error(`could not fetch checksum: HTTP ${checksumRes.status}`);
      const checksumText = await checksumRes.text();
      const expectedSha = (checksumText.trim().split(/\s+/)[0] || '').toLowerCase();
      const actualSha = await this.sha256File(DOWNLOAD_PATH);
      if (!expectedSha || expectedSha !== actualSha) {
        throw new Error('checksum mismatch -- downloaded file does not match the published release, refusing to apply it');
      }

      this.log('extracting...');
      await this.rmrf(STAGING_DIR);
      await fsp.mkdir(STAGING_DIR, { recursive: true });
      await execFileAsync('tar', ['-xzf', DOWNLOAD_PATH, '-C', STAGING_DIR]);
      await this.stripMacCruft(STAGING_DIR);

      const stagedPkgPath = path.join(STAGING_DIR, 'package.json');
      if (!fs.existsSync(path.join(STAGING_DIR, 'server.js')) || !fs.existsSync(stagedPkgPath)) {
        throw new Error('extracted update package is missing expected files');
      }
      const stagedPkg = JSON.parse(await fsp.readFile(stagedPkgPath, 'utf8'));
      if (stagedPkg.name !== PACKAGE_NAME) {
        throw new Error('extracted update package does not look like this application');
      }

      this.log('checking syntax of the new version before touching anything live...');
      await this.checkAllSyntax(STAGING_DIR);

      this.log('installing dependencies for the new version (this can take a minute)...');
      await execFileAsync('npm', ['install', '--omit=dev', '--no-audit', '--no-fund'], {
        cwd: STAGING_DIR,
        timeout: 10 * 60 * 1000
      });

      this.log('backing up the current version...');
      await this.pruneOldBackups();
      const backupDir = path.join(BACKUP_ROOT, `pre-update-${normalizeVersion(CURRENT_VERSION)}-${Date.now()}`);
      await this.copyInto(APP_DIR, backupDir, SWAP_ITEMS);

      this.log('swapping in the new version...');
      for (const item of SWAP_ITEMS) {
        await this.rmrf(path.join(APP_DIR, item));
        const staged = path.join(STAGING_DIR, item);
        if (fs.existsSync(staged)) {
          await fsp.rename(staged, path.join(APP_DIR, item));
        }
      }
      await this.chmodExecutable(path.join(APP_DIR, 'provisioning'));

      await this.rmrf(STAGING_DIR);
      await this.rmrf(DOWNLOAD_PATH);

      this.log(`update to ${targetVersion} staged successfully -- restarting the service now`);
      // The HTTP response for the request that triggered this has already been sent by
      // the caller; this process is about to be killed by the restart it's requesting.
      await runHelper(['service-restart']);
    } catch (err) {
      this.log(`FAILED: ${err.message}`);
      throw err;
    } finally {
      this.updating = false;
    }
  }

  async latestBackupDir() {
    if (!fs.existsSync(BACKUP_ROOT)) return null;
    const entries = (await fsp.readdir(BACKUP_ROOT)).filter((e) => e.startsWith('pre-update-')).sort();
    return entries.length ? path.join(BACKUP_ROOT, entries[entries.length - 1]) : null;
  }

  async hasBackup() {
    return !!(await this.latestBackupDir());
  }

  /**
   * Restores the most recent pre-update backup while the app is still healthy enough to
   * serve this request -- for "the update applied fine but I don't want it" cases. If the
   * new version won't even start, use provisioning/rollback-update.sh over SSH instead;
   * that one works even when this app can't.
   */
  async rollback() {
    if (this.updating) {
      const err = new Error('an update is already in progress');
      this.log(`ROLLBACK FAILED: ${err.message}`);
      throw err;
    }
    const backupDir = await this.latestBackupDir();
    if (!backupDir) {
      const err = new Error('no backup found to roll back to');
      this.log(`ROLLBACK FAILED: ${err.message}`);
      throw err;
    }
    this.updating = true;
    try {
      this.log(`rolling back to backup at ${backupDir}...`);
      for (const item of SWAP_ITEMS) {
        const backed = path.join(backupDir, item);
        if (!fs.existsSync(backed)) continue;
        await this.rmrf(path.join(APP_DIR, item));
        await fsp.cp(backed, path.join(APP_DIR, item), { recursive: true });
      }
      this.log('rollback staged -- restarting the service now');
      await runHelper(['service-restart']);
    } catch (err) {
      this.log(`ROLLBACK FAILED: ${err.message}`);
      throw err;
    } finally {
      this.updating = false;
    }
  }
}

module.exports = new SelfUpdateManager();
