'use strict';

const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const { getDb, getSetting } = require('../db/index');

const DB_PATH = process.env.DB_PATH || './data/yourddns.db';
const BACKUP_DIR = path.join(path.dirname(path.resolve(DB_PATH)), 'backups');

function ensureBackupDir() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function createBackup() {
  ensureBackupDir();
  const db = getDb();

  // Flush WAL to main file so the copy is consistent
  db.exec('PRAGMA wal_checkpoint(FULL)');

  const now = new Date();
  const ts = now.toISOString().slice(0, 19).replace(/:/g, '-');
  const filename = `yourddns_backup_${ts}Z.zip`;
  const zipPath = path.join(BACKUP_DIR, filename);

  const zip = new AdmZip();
  zip.addLocalFile(path.resolve(DB_PATH), '', 'yourddns.db');
  zip.addFile('backup_meta.json', Buffer.from(JSON.stringify({
    created_at: now.toISOString(),
    site_name: getSetting('site_name') || 'YourDDNS',
  }, null, 2)));
  zip.writeZip(zipPath);

  console.log(`[backup] Created: ${filename}`);
  return filename;
}

function pruneBackups() {
  ensureBackupDir();
  const retentionDays = parseInt(getSetting('backup_retention_days') || '30', 10);
  if (retentionDays <= 0) return;

  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  let pruned = 0;
  for (const file of fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.zip'))) {
    const filePath = path.join(BACKUP_DIR, file);
    if (fs.statSync(filePath).mtimeMs < cutoff) {
      fs.unlinkSync(filePath);
      pruned++;
      console.log(`[backup] Pruned: ${file}`);
    }
  }
  return pruned;
}

function listBackups() {
  ensureBackupDir();
  return fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.zip'))
    .map(f => {
      const stat = fs.statSync(path.join(BACKUP_DIR, f));
      return { filename: f, size: stat.size, created_at: stat.mtime.toISOString() };
    })
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
}

function startBackupJob() {
  // Check every hour whether a scheduled backup is due
  setInterval(() => {
    try {
      const intervalHours = parseInt(getSetting('backup_interval_hours') || '0', 10);
      if (intervalHours <= 0) return;

      const intervalMs = intervalHours * 60 * 60 * 1000;
      const backups = listBackups();
      const lastBackupAge = backups.length > 0
        ? Date.now() - new Date(backups[0].created_at).getTime()
        : Infinity;

      if (lastBackupAge >= intervalMs) {
        createBackup();
        pruneBackups();
      }
    } catch (err) {
      console.error('[backup] Scheduled backup error:', err.message);
    }
  }, 60 * 60 * 1000).unref();

  console.log('[backup] Backup job scheduled (checks every hour)');
}

module.exports = { createBackup, pruneBackups, listBackups, startBackupJob, BACKUP_DIR };
