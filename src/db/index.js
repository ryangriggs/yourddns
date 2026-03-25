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

  await seedDefaultData();
  await bootstrapAdmin();
  return db;
}

async function seedDefaultData() {
  const existing = db.prepare('SELECT COUNT(*) as c FROM tiers').get();
  if (existing.c > 0) return;

  const insertTier = db.prepare(`
    INSERT OR IGNORE INTO tiers (name, display_name, max_entries, min_ttl, max_resolutions_per_hour, max_updates_per_hour, min_subdomain_length, history_days, price_monthly, sort_order)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  withTransaction(() => {
    insertTier.run('free',    'Free',    3,   300, 1000,  10, 4, 7,   0,    0);
    insertTier.run('starter', 'Starter', 10,  120, 5000,  30, 3, 30,  500,  1);
    insertTier.run('pro',     'Pro',     50,  60,  20000, 60, 2, 90,  1500, 2);
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
    ['stripe_enabled',              'false', 'Enable Stripe billing'],
    ['stripe_publishable_key',      process.env.STRIPE_PUBLISHABLE_KEY || '', 'Stripe publishable key'],
    ['news_content',                '', 'News/announcement block shown on landing page'],
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

module.exports = { initDb, getDb, getSetting, getAllSettings, setSetting, withTransaction };
