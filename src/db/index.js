'use strict';

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

let db;

function getDb() {
  if (!db) throw new Error('Database not initialized');
  return db;
}

// Helper: run a function inside a BEGIN/COMMIT transaction
function withTransaction(fn) {
  db.exec('BEGIN');
  try {
    fn();
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

async function initDb() {
  const dbPath = process.env.DB_PATH || './data/yourddns.db';
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=WAL');
  db.exec('PRAGMA foreign_keys=ON');

  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  db.exec(schema);

  // Migrations for existing databases
  const ddnsCols = db.prepare('PRAGMA table_info(ddns_records)').all().map(c => c.name);
  if (!ddnsCols.includes('ip6_address')) {
    db.exec('ALTER TABLE ddns_records ADD COLUMN ip6_address TEXT');
    console.log('[db] Migration: added ip6_address to ddns_records');
  }
  if (!ddnsCols.includes('hit_count')) {
    db.exec('ALTER TABLE ddns_records ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 0');
    console.log('[db] Migration: added hit_count to ddns_records');
  }

  // Zone migrations
  const zoneCols = db.prepare('PRAGMA table_info(zones)').all().map(c => c.name);
  if (!zoneCols.includes('user_id')) {
    db.exec('ALTER TABLE zones ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE');
  }
  if (!zoneCols.includes('validated')) {
    db.exec('ALTER TABLE zones ADD COLUMN validated INTEGER NOT NULL DEFAULT 1');
  }
  if (!zoneCols.includes('zone_type')) {
    db.exec("ALTER TABLE zones ADD COLUMN zone_type TEXT NOT NULL DEFAULT 'full'");
  }

  // Tier migrations
  const tierCols = db.prepare('PRAGMA table_info(tiers)').all().map(c => c.name);
  if (!tierCols.includes('max_custom_domains')) {
    db.exec('ALTER TABLE tiers ADD COLUMN max_custom_domains INTEGER NOT NULL DEFAULT 0');
  }
  if (!tierCols.includes('max_records_per_day')) {
    db.exec('ALTER TABLE tiers ADD COLUMN max_records_per_day INTEGER NOT NULL DEFAULT 10');
    console.log('[db] Migration: added max_records_per_day to tiers');
  }

  // Ensure new settings exist on existing deployments (INSERT OR IGNORE — safe to always run)
  const ensureSettings = db.prepare('INSERT OR IGNORE INTO admin_settings (key, value, description) VALUES (?, ?, ?)');
  ensureSettings.run('global_min_ttl',                '1',                                             'Global minimum TTL (seconds) — floor for all tiers');
  ensureSettings.run('ns_primary',                    process.env.NS_PRIMARY   || 'ns1.yourddns.com', 'Primary nameserver hostname');
  ensureSettings.run('ns_secondary',                  process.env.NS_SECONDARY || 'ns2.yourddns.com', 'Secondary nameserver hostname');
  ensureSettings.run('zone_validation_timeout_hours', '48',                                            'Hours before a pending custom domain is removed if not validated');
  ensureSettings.run('site_ip',                       '',                                              'Server IP address — auto-added as apex A record when zones are created');
  ensureSettings.run('subscriptions_enabled',         'false',                                         'Show paid plans and upgrade prompts');
  ensureSettings.run('github_sponsors_url',           'https://github.com/sponsors/ryangriggs',        'GitHub Sponsors link shown on the /donate page');
  ensureSettings.run('paypal_donation_url',           '',                                              'PayPal donation link shown on the /donate page (optional)');
  ensureSettings.run('backup_interval_hours',         '24',                                            'Auto-backup every X hours (0 = disabled)');
  ensureSettings.run('backup_retention_days',         '30',                                            'Delete backups older than X days (0 = keep forever)');

  // zone_api_keys — added when zone API was introduced
  const apiKeyTables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='zone_api_keys'").get();
  if (!apiKeyTables) {
    db.exec(`CREATE TABLE IF NOT EXISTS zone_api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      zone_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_used_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
    )`);
    console.log('[db] Migration: created zone_api_keys table');
  }

  await seedDefaultData();
  await bootstrapAdmin();
  return db;
}

async function seedDefaultData() {
  const existing = db.prepare('SELECT COUNT(*) as c FROM tiers').get();
  if (existing.c > 0) return;

  const insertTier = db.prepare(`
    INSERT OR IGNORE INTO tiers (name, display_name, max_entries, min_ttl, max_resolutions_per_hour, max_updates_per_hour, min_subdomain_length, history_days, price_monthly, sort_order, max_custom_domains, max_records_per_day)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  withTransaction(() => {
    //                name      display   ent  ttl  res/hr  upd/hr  sublen hist  price ord  cdom  rec/day
    insertTier.run('free',    'Free',    3,   300, 1000,  10,     4,     7,   0,    0,   0,    3);
    insertTier.run('starter', 'Starter', 10,  120, 5000,  30,     3,     30,  500,  1,   1,    10);
    insertTier.run('pro',     'Pro',     50,  60,  20000, 60,     2,     90,  1500, 2,   5,    50);
  });

  const settings = [
    ['site_name',                   process.env.SITE_NAME || 'YourDDNS',            'Site display name'],
    ['site_domain',                 process.env.SITE_DOMAIN || 'yourddns.com',      'Primary domain'],
    ['site_url',                    process.env.SITE_URL || 'https://yourddns.com', 'Full site URL'],
    ['support_email',               process.env.SUPPORT_EMAIL || 'support@yourddns.com', 'Support email'],
    ['otp_resend_interval_minutes', '30',    'Minutes between OTP sends per user'],
    ['otp_max_attempts_per_hour',   '5',     'Max OTP code attempts per hour per user'],
    ['password_max_attempts_per_hour', '10', 'Max password login attempts per hour'],
    ['registration_enabled',        'true',  'Allow new user registrations'],
    ['subscriptions_enabled',       'false', 'Show paid plans and upgrade prompts'],
    ['github_sponsors_url',         'https://github.com/sponsors/ryangriggs', 'GitHub Sponsors link shown on the /donate page'],
    ['paypal_donation_url',         '',      'PayPal donation link shown on the /donate page (optional)'],
    ['backup_interval_hours',       '24',   'Auto-backup every X hours (0 = disabled)'],
    ['backup_retention_days',       '30',   'Delete backups older than X days (0 = keep forever)'],
    ['stripe_enabled',              'false', 'Enable Stripe billing'],
    ['stripe_publishable_key',      process.env.STRIPE_PUBLISHABLE_KEY || '', 'Stripe publishable key'],
    ['landing_title',               'Dynamic DNS for Everyone', 'Hero headline on the landing page'],
    ['news_content',                '', 'News/announcement block shown on landing page'],
    ['global_min_ttl',              '1', 'Global minimum TTL (seconds) — floor for all tiers'],
    ['ns_primary',   process.env.NS_PRIMARY || 'ns1.yourddns.com',   'Primary nameserver hostname'],
    ['ns_secondary', process.env.NS_SECONDARY || 'ns2.yourddns.com', 'Secondary nameserver hostname'],
  ];

  const insertSetting = db.prepare('INSERT OR IGNORE INTO admin_settings (key, value, description) VALUES (?, ?, ?)');
  withTransaction(() => { for (const s of settings) insertSetting.run(...s); });
}

async function bootstrapAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminEmail || !adminPassword) return;

  const existing = db.prepare('SELECT id FROM users WHERE is_admin = 1').get();
  if (existing) return;

  const hash = await bcrypt.hash(adminPassword, 12);
  db.prepare(`
    INSERT OR IGNORE INTO users (email, password_hash, email_verified, is_admin, tier_id)
    VALUES (?, ?, 1, 1, (SELECT id FROM tiers WHERE name = 'pro' LIMIT 1))
  `).run(adminEmail, hash);

  console.log(`[db] Admin user created: ${adminEmail}`);
}

function closeDb() {
  if (db) {
    try { db.exec('PRAGMA wal_checkpoint(FULL)'); } catch {}
    try { db.close(); } catch {}
    db = null;
  }
}

async function restoreFromFile(newDbFilePath) {
  closeDb();
  const dbPath = process.env.DB_PATH || './data/yourddns.db';
  fs.copyFileSync(newDbFilePath, dbPath);
  await initDb();
}

function getSetting(key) {
  const row = db.prepare('SELECT value FROM admin_settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function getAllSettings() {
  const rows = db.prepare('SELECT key, value, description FROM admin_settings ORDER BY key').all();
  const out = {};
  for (const r of rows) out[r.key] = r;
  return out;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT OR REPLACE INTO admin_settings (key, value, description)
    VALUES (?, ?, COALESCE((SELECT description FROM admin_settings WHERE key = ?), ''))
  `).run(key, value, key);
}

module.exports = { initDb, getDb, getSetting, getAllSettings, setSetting, withTransaction, closeDb, restoreFromFile };
