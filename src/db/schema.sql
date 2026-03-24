PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  is_disabled INTEGER NOT NULL DEFAULT 0,
  tier_id INTEGER NOT NULL DEFAULT 1,
  stripe_customer_id TEXT,
  impersonated_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (tier_id) REFERENCES tiers(id)
);

CREATE TABLE IF NOT EXISTS email_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  last_sent_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tiers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  max_entries INTEGER NOT NULL DEFAULT 3,
  min_ttl INTEGER NOT NULL DEFAULT 300,
  max_resolutions_per_hour INTEGER NOT NULL DEFAULT 1000,
  max_updates_per_hour INTEGER NOT NULL DEFAULT 10,
  min_subdomain_length INTEGER NOT NULL DEFAULT 4,
  history_days INTEGER NOT NULL DEFAULT 7,
  price_monthly INTEGER NOT NULL DEFAULT 0,
  stripe_price_id TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT UNIQUE NOT NULL COLLATE NOCASE,
  display_name TEXT,
  ns_hostnames TEXT NOT NULL DEFAULT '[]',
  soa_email TEXT NOT NULL DEFAULT 'hostmaster@yourddns.com',
  soa_serial INTEGER NOT NULL DEFAULT 1,
  default_ttl INTEGER NOT NULL DEFAULT 300,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Static DNS records admin can manage per zone (A, MX, CNAME, TXT, etc.)
CREATE TABLE IF NOT EXISTS zone_static_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  zone_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 300,
  priority INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS zone_tiers (
  zone_id INTEGER NOT NULL,
  tier_id INTEGER NOT NULL,
  PRIMARY KEY (zone_id, tier_id),
  FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
  FOREIGN KEY (tier_id) REFERENCES tiers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ddns_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  zone_id INTEGER NOT NULL,
  subdomain TEXT NOT NULL COLLATE NOCASE,
  ip_address TEXT,
  ttl INTEGER NOT NULL DEFAULT 300,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  pat_hash TEXT,
  hit_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_update_received_at TEXT,
  UNIQUE (zone_id, subdomain),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id INTEGER NOT NULL,
  queried_at TEXT NOT NULL DEFAULT (datetime('now')),
  client_ip TEXT,
  query_type TEXT DEFAULT 'A',
  FOREIGN KEY (record_id) REFERENCES ddns_records(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS update_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  record_id INTEGER NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  requester_ip TEXT,
  user_agent TEXT,
  new_ip TEXT,
  success INTEGER NOT NULL DEFAULT 1,
  error_message TEXT,
  FOREIGN KEY (record_id) REFERENCES ddns_records(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blocked_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT UNIQUE NOT NULL,
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by INTEGER,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS admin_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  description TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_ddns_records_zone_sub ON ddns_records(zone_id, subdomain);
CREATE INDEX IF NOT EXISTS idx_ddns_records_user ON ddns_records(user_id);
CREATE INDEX IF NOT EXISTS idx_ddns_records_pat ON ddns_records(pat_hash);
CREATE INDEX IF NOT EXISTS idx_dns_hits_record_time ON dns_hits(record_id, queried_at);
CREATE INDEX IF NOT EXISTS idx_update_logs_record_time ON update_logs(record_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_blocked_ips ON blocked_ips(ip_address);
