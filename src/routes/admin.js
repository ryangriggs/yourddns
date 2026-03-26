'use strict';

const bcrypt = require('bcryptjs');
const { getDb, getSetting, getAllSettings, setSetting, withTransaction } = require('../db/index');

function flash(req) {
  const f = req.session.flash;
  delete req.session.flash;
  return f;
}

module.exports = async function adminRoutes(fastify) {
  fastify.addHook('preHandler', fastify.requireAdmin);

  // GET /admin — redirect to users
  fastify.get('/admin', async (req, reply) => reply.redirect('/admin/users'));

  // ── Users ──────────────────────────────────────────────────────────────────

  fastify.get('/admin/users', async (req, reply) => {
    const db = getDb();
    const users = db.prepare(`
      SELECT u.*, t.display_name as tier_name,
        (SELECT COUNT(*) FROM ddns_records WHERE user_id = u.id) as record_count,
        (SELECT COUNT(*) FROM zones WHERE user_id = u.id) as custom_domain_count
      FROM users u JOIN tiers t ON t.id = u.tier_id
      ORDER BY u.created_at DESC
    `).all();
    const tiers = db.prepare('SELECT * FROM tiers ORDER BY sort_order').all();
    return reply.view('admin/users.njk', { title: 'Users', users, tiers, flash: flash(req) });
  });

  fastify.get('/admin/users/:id/custom-domains', async (req, reply) => {
    const db = getDb();
    const target = db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.params.id);
    if (!target) {
      req.session.flash = { type: 'error', message: 'User not found.' };
      return reply.redirect('/admin/users');
    }
    const zones = db.prepare(`
      SELECT z.*,
        (SELECT COUNT(*) FROM ddns_records WHERE zone_id = z.id) as record_count
      FROM zones z WHERE z.user_id = ? ORDER BY z.domain
    `).all(req.params.id);
    return reply.view('admin/user-custom-domains.njk', {
      title: `Custom Domains — ${target.email}`,
      target,
      zones,
      flash: flash(req),
    });
  });

  fastify.post('/admin/users/:id/custom-domains/:zoneId/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM zones WHERE id = ? AND user_id = ?').run(req.params.zoneId, req.params.id);
    req.session.flash = { type: 'success', message: 'Zone deleted.' };
    return reply.redirect(`/admin/users/${req.params.id}/custom-domains`);
  });

  fastify.post('/admin/users/:id/disable', async (req, reply) => {
    const db = getDb();
    db.prepare('UPDATE users SET is_disabled = 1 WHERE id = ?').run(req.params.id);
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/enable', async (req, reply) => {
    const db = getDb();
    db.prepare('UPDATE users SET is_disabled = 0 WHERE id = ?').run(req.params.id);
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    req.session.flash = { type: 'success', message: 'User deleted.' };
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/tier', async (req, reply) => {
    const db = getDb();
    const { tier_id } = req.body || {};
    db.prepare('UPDATE users SET tier_id = ? WHERE id = ?').run(tier_id, req.params.id);
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/promote', async (req, reply) => {
    const db = getDb();
    db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(req.params.id);
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/demote', async (req, reply) => {
    const db = getDb();
    // Cannot demote self
    if (parseInt(req.params.id) === req.user.id) {
      req.session.flash = { type: 'error', message: 'Cannot demote yourself.' };
      return reply.redirect('/admin/users');
    }
    db.prepare('UPDATE users SET is_admin = 0 WHERE id = ?').run(req.params.id);
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/set-password', async (req, reply) => {
    const db = getDb();
    const { new_password } = req.body || {};
    if (!new_password || new_password.length < 8) {
      req.session.flash = { type: 'error', message: 'Password must be at least 8 characters.' };
      return reply.redirect('/admin/users');
    }
    const hash = await bcrypt.hash(new_password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.params.id);
    req.session.flash = { type: 'success', message: 'Password updated.' };
    return reply.redirect('/admin/users');
  });

  fastify.post('/admin/users/:id/login-as', async (req, reply) => {
    const db = getDb();
    const target = db.prepare('SELECT id, is_disabled FROM users WHERE id = ?').get(req.params.id);
    if (!target || target.is_disabled) {
      req.session.flash = { type: 'error', message: 'User not found or disabled.' };
      return reply.redirect('/admin/users');
    }
    req.session.impersonatingUserId = parseInt(req.params.id);
    return reply.redirect('/dashboard');
  });

  // ── Domains / Zones ────────────────────────────────────────────────────────

  fastify.get('/admin/domains', async (req, reply) => {
    const db = getDb();
    const zones = db.prepare(`
      SELECT z.*,
        (SELECT COUNT(*) FROM ddns_records WHERE zone_id = z.id) as record_count,
        (SELECT GROUP_CONCAT(tier_id) FROM zone_tiers WHERE zone_id = z.id) as tier_ids
      FROM zones z WHERE z.user_id IS NULL ORDER BY z.domain
    `).all();
    const tiers = db.prepare('SELECT * FROM tiers ORDER BY sort_order').all();
    // Attach static records per zone
    for (const zone of zones) {
      zone.static_records = db.prepare('SELECT * FROM zone_static_records WHERE zone_id = ? ORDER BY type, name').all(zone.id);
      zone.ns_list = JSON.parse(zone.ns_hostnames || '[]');
    }
    return reply.view('admin/domains.njk', { title: 'Domains', zones, tiers, settings: getAllSettings(), flash: flash(req) });
  });

  fastify.post('/admin/domains', async (req, reply) => {
    const db = getDb();
    const { domain, display_name, ns_hostnames, soa_email, default_ttl, tier_ids } = req.body || {};
    if (!domain) {
      req.session.flash = { type: 'error', message: 'Domain is required.' };
      return reply.redirect('/admin/domains');
    }
    const nsArray = (ns_hostnames || '').split('\n').map(s => s.trim()).filter(Boolean);
    const r = db.prepare(`
      INSERT INTO zones (domain, display_name, ns_hostnames, soa_email, default_ttl)
      VALUES (?, ?, ?, ?, ?)
    `).run(domain.trim().toLowerCase(), display_name || domain, JSON.stringify(nsArray), soa_email || `hostmaster@${domain}`, parseInt(default_ttl || 300, 10));

    const zoneId = Number(r.lastInsertRowid);
    const tIds = Array.isArray(tier_ids) ? tier_ids : (tier_ids ? [tier_ids] : []);
    const ins = db.prepare('INSERT OR IGNORE INTO zone_tiers (zone_id, tier_id) VALUES (?, ?)');
    withTransaction(() => { for (const t of tIds) ins.run(zoneId, t); });

    const siteIp = getSetting('site_ip') || '';
    if (siteIp) {
      db.prepare('INSERT OR IGNORE INTO zone_static_records (zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)').run(zoneId, '@', 'A', siteIp, 300);
    }

    req.session.flash = { type: 'success', message: 'Zone created.' };
    return reply.redirect('/admin/domains');
  });

  fastify.post('/admin/domains/:id/update', async (req, reply) => {
    const db = getDb();
    const { display_name, ns_hostnames, soa_email, default_ttl, is_active, tier_ids } = req.body || {};
    const nsArray = (ns_hostnames || '').split('\n').map(s => s.trim()).filter(Boolean);
    db.prepare(`
      UPDATE zones SET display_name=?, ns_hostnames=?, soa_email=?, default_ttl=?, is_active=?,
      soa_serial = soa_serial + 1
      WHERE id = ?
    `).run(display_name, JSON.stringify(nsArray), soa_email, parseInt(default_ttl || 300, 10), is_active ? 1 : 0, req.params.id);

    db.prepare('DELETE FROM zone_tiers WHERE zone_id = ?').run(req.params.id);
    const tIds = Array.isArray(tier_ids) ? tier_ids : (tier_ids ? [tier_ids] : []);
    const ins = db.prepare('INSERT OR IGNORE INTO zone_tiers (zone_id, tier_id) VALUES (?, ?)');
    withTransaction(() => { for (const t of tIds) ins.run(req.params.id, t); });

    req.session.flash = { type: 'success', message: 'Zone updated.' };
    return reply.redirect('/admin/domains');
  });

  fastify.post('/admin/domains/:id/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM zones WHERE id = ?').run(req.params.id);
    req.session.flash = { type: 'success', message: 'Zone deleted.' };
    return reply.redirect('/admin/domains');
  });

  // Zone static records
  fastify.post('/admin/domains/:id/static-records', async (req, reply) => {
    const db = getDb();
    const { name, type, value, ttl, priority } = req.body || {};
    if (!name || !type || !value) {
      req.session.flash = { type: 'error', message: 'Name, type, and value are required.' };
      return reply.redirect('/admin/domains');
    }
    db.prepare('INSERT INTO zone_static_records (zone_id, name, type, value, ttl, priority) VALUES (?, ?, ?, ?, ?, ?)').run(req.params.id, name, type.toUpperCase(), value, parseInt(ttl || 300, 10), priority || null);
    req.session.flash = { type: 'success', message: 'Static record added.' };
    return reply.redirect('/admin/domains');
  });

  fastify.post('/admin/domains/static-records/:id/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM zone_static_records WHERE id = ?').run(req.params.id);
    req.session.flash = { type: 'success', message: 'Record deleted.' };
    return reply.redirect('/admin/domains');
  });

  fastify.post('/admin/domains/:id/add-apex-a', async (req, reply) => {
    const db = getDb();
    const siteIp = getSetting('site_ip') || '';
    if (!siteIp) {
      req.session.flash = { type: 'error', message: 'Server IP is not configured in Settings.' };
      return reply.redirect('/admin/domains');
    }
    db.prepare('INSERT OR IGNORE INTO zone_static_records (zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)').run(req.params.id, '@', 'A', siteIp, 300);
    req.session.flash = { type: 'success', message: 'A record added.' };
    return reply.redirect('/admin/domains');
  });

  // ── DDNS Records ───────────────────────────────────────────────────────────

  fastify.get('/admin/records', async (req, reply) => {
    const db = getDb();
    const records = db.prepare(`
      SELECT r.*, z.domain as zone_domain, u.email as user_email
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      JOIN users u ON u.id = r.user_id
      ORDER BY r.created_at DESC
    `).all();
    return reply.view('admin/records.njk', { title: 'All Records', records, flash: flash(req) });
  });

  fastify.post('/admin/records/:id/enable', async (req, reply) => {
    const db = getDb();
    db.prepare('UPDATE ddns_records SET is_enabled = 1 WHERE id = ?').run(req.params.id);
    return reply.redirect('/admin/records');
  });

  fastify.post('/admin/records/:id/disable', async (req, reply) => {
    const db = getDb();
    db.prepare('UPDATE ddns_records SET is_enabled = 0 WHERE id = ?').run(req.params.id);
    return reply.redirect('/admin/records');
  });

  fastify.post('/admin/records/:id/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM ddns_records WHERE id = ?').run(req.params.id);
    req.session.flash = { type: 'success', message: 'Record deleted.' };
    return reply.redirect('/admin/records');
  });

  // ── Blocked IPs ────────────────────────────────────────────────────────────

  fastify.get('/admin/blocked-ips', async (req, reply) => {
    const db = getDb();
    const ips = db.prepare(`
      SELECT b.*, u.email as created_by_email
      FROM blocked_ips b LEFT JOIN users u ON u.id = b.created_by
      ORDER BY b.created_at DESC
    `).all();
    return reply.view('admin/blocked-ips.njk', { title: 'Blocked IPs', ips, flash: flash(req) });
  });

  fastify.post('/admin/blocked-ips', async (req, reply) => {
    const db = getDb();
    const { ip_address, reason } = req.body || {};
    if (!ip_address) {
      req.session.flash = { type: 'error', message: 'IP address is required.' };
      return reply.redirect('/admin/blocked-ips');
    }
    db.prepare('INSERT OR IGNORE INTO blocked_ips (ip_address, reason, created_by) VALUES (?, ?, ?)').run(ip_address.trim(), reason || null, req.user.id);
    req.session.flash = { type: 'success', message: 'IP blocked.' };
    return reply.redirect('/admin/blocked-ips');
  });

  fastify.post('/admin/blocked-ips/:id/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM blocked_ips WHERE id = ?').run(req.params.id);
    req.session.flash = { type: 'success', message: 'IP unblocked.' };
    return reply.redirect('/admin/blocked-ips');
  });

  // ── Settings ───────────────────────────────────────────────────────────────

  fastify.get('/admin/settings', async (req, reply) => {
    const settings = getAllSettings();
    const tiers = getDb().prepare(`
      SELECT t.*, COUNT(u.id) as user_count
      FROM tiers t LEFT JOIN users u ON u.tier_id = t.id
      GROUP BY t.id ORDER BY t.sort_order
    `).all();
    return reply.view('admin/settings.njk', { title: 'Settings', settings, tiers, flash: flash(req) });
  });

  fastify.post('/admin/settings', async (req, reply) => {
    const textFields = ['site_name','site_domain','site_url','site_ip','support_email','otp_resend_interval_minutes','otp_max_attempts_per_hour','password_max_attempts_per_hour','stripe_publishable_key','news_content','global_min_ttl','ns_primary','ns_secondary','zone_validation_timeout_hours','github_sponsors_url','paypal_donation_url'];
    const checkboxFields = ['registration_enabled','stripe_enabled','subscriptions_enabled'];
    for (const key of textFields) {
      if (req.body[key] !== undefined) setSetting(key, req.body[key]);
    }
    // Checkboxes: if not present in body, they were unchecked → set false
    for (const key of checkboxFields) {
      setSetting(key, req.body[key] === 'true' ? 'true' : 'false');
    }
    req.session.flash = { type: 'success', message: 'Settings saved.' };
    return reply.redirect('/admin/settings');
  });

  // Tier management
  fastify.post('/admin/tiers', async (req, reply) => {
    const db = getDb();
    const { id, name, display_name, max_entries, min_ttl, max_resolutions_per_hour, max_updates_per_hour, min_subdomain_length, history_days, price_monthly, stripe_price_id, sort_order, max_custom_domains } = req.body || {};
    if (id) {
      db.prepare(`UPDATE tiers SET display_name=?,max_entries=?,min_ttl=?,max_resolutions_per_hour=?,max_updates_per_hour=?,min_subdomain_length=?,history_days=?,price_monthly=?,stripe_price_id=?,sort_order=?,max_custom_domains=? WHERE id=?`).run(display_name,max_entries,min_ttl,max_resolutions_per_hour,max_updates_per_hour,min_subdomain_length,history_days,price_monthly,stripe_price_id||null,sort_order||0,max_custom_domains||0,id);
    } else {
      db.prepare(`INSERT INTO tiers (name,display_name,max_entries,min_ttl,max_resolutions_per_hour,max_updates_per_hour,min_subdomain_length,history_days,price_monthly,stripe_price_id,sort_order,max_custom_domains) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(name,display_name,max_entries||3,min_ttl||300,max_resolutions_per_hour||1000,max_updates_per_hour||10,min_subdomain_length||4,history_days||7,price_monthly||0,stripe_price_id||null,sort_order||0,max_custom_domains||0);
    }
    req.session.flash = { type: 'success', message: 'Tier saved.' };
    return reply.redirect('/admin/settings');
  });

  fastify.post('/admin/tiers/:id/delete', async (req, reply) => {
    const db = getDb();
    const row = db.prepare('SELECT COUNT(*) as c FROM users WHERE tier_id = ?').get(req.params.id);
    if (row.c > 0) {
      req.session.flash = { type: 'error', message: `Cannot delete tier: ${row.c} user(s) are on this plan.` };
      return reply.redirect('/admin/settings');
    }
    db.prepare('DELETE FROM tiers WHERE id = ?').run(req.params.id);
    req.session.flash = { type: 'success', message: 'Tier deleted.' };
    return reply.redirect('/admin/settings');
  });

  // ── Stats (admin version) ──────────────────────────────────────────────────

  fastify.get('/admin/stats', async (req, reply) => {
    const db = getDb();
    const records = db.prepare(`
      SELECT r.id, r.subdomain, z.domain as zone_domain, u.email as user_email
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      JOIN users u ON u.id = r.user_id
      ORDER BY r.subdomain
    `).all();
    return reply.view('admin/stats.njk', { title: 'Stats', records });
  });

  fastify.get('/admin/stats/data', async (req, reply) => {
    const db = getDb();
    const { records: recordIds, from, to } = req.query || {};
    if (!recordIds) return reply.send({ datasets: [] });
    const ids = (Array.isArray(recordIds) ? recordIds : [recordIds]).map(Number).filter(Boolean);
    if (!ids.length) return reply.send({ datasets: [] });

    const fromDate = from || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const toDate = to || new Date().toISOString().split('T')[0];
    const datasets = [];
    for (const id of ids) {
      const record = db.prepare('SELECT r.subdomain, z.domain as zone_domain, u.email FROM ddns_records r JOIN zones z ON z.id = r.zone_id JOIN users u ON u.id = r.user_id WHERE r.id = ?').get(id);
      if (!record) continue;
      const hits = db.prepare(`SELECT date(queried_at) as day, COUNT(*) as count FROM dns_hits WHERE record_id = ? AND date(queried_at) >= ? AND date(queried_at) <= ? GROUP BY day ORDER BY day`).all(id, fromDate, toDate);
      datasets.push({ id, label: `${record.subdomain}.${record.zone_domain} (${record.email})`, data: hits });
    }
    return reply.send({ datasets, from: fromDate, to: toDate });
  });
};
