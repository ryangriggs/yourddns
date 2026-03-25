'use strict';

const { getDb, getSetting } = require('../db/index');
const { generatePat, hashPat } = require('../services/pat');

module.exports = async function dashboardRoutes(fastify) {
  fastify.addHook('preHandler', fastify.requireAuth);

  // Stop impersonating — must be accessible while impersonating (real user is admin)
  fastify.post('/admin/stop-impersonating', async (req, reply) => {
    delete req.session.impersonatingUserId;
    return reply.redirect('/admin/users');
  });

  // GET /dashboard
  fastify.get('/dashboard', async (req, reply) => {
    const db = getDb();
    const records = db.prepare(`
      SELECT r.*, z.domain as zone_domain
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      WHERE r.user_id = ?
      ORDER BY r.created_at DESC
    `).all(req.user.id);

    const zones = db.prepare(`
      SELECT z.* FROM zones z
      JOIN zone_tiers zt ON zt.zone_id = z.id
      WHERE zt.tier_id = ? AND z.is_active = 1
      ORDER BY z.domain
    `).all(req.user.tier_id);

    const tier = {
      max_entries: req.user.max_entries,
      min_ttl: req.user.min_ttl,
      min_subdomain_length: req.user.min_subdomain_length,
    };

    const flash = req.session.flash;
    const newPat = req.session.newPat;
    // Clear one-time session values after reading
    delete req.session.flash;
    delete req.session.newPat;

    return reply.view('dashboard/index.njk', {
      title: 'Dashboard',
      records,
      zones,
      tier,
      flash,
      newPat,
      clientIp: req.ip,
    });
  });

  // POST /dashboard/records  — create
  fastify.post('/dashboard/records', async (req, reply) => {
    const db = getDb();
    const { subdomain, zone_id, ttl, ip } = req.body || {};

    // Clear session flash
    req.session.flash = null;
    req.session.newPat = null;

    if (!subdomain || !zone_id) {
      req.session.flash = { type: 'error', message: 'Subdomain and zone are required.' };
      return reply.redirect('/dashboard');
    }

    const sub = subdomain.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (sub !== subdomain.trim().toLowerCase()) {
      req.session.flash = { type: 'error', message: 'Subdomain can only contain letters, numbers, and hyphens.' };
      return reply.redirect('/dashboard');
    }

    const minLen = req.user.min_subdomain_length || 4;
    if (sub.length < minLen) {
      req.session.flash = { type: 'error', message: `Subdomain must be at least ${minLen} characters.` };
      return reply.redirect('/dashboard');
    }

    // Check tier entry limit
    const count = db.prepare('SELECT COUNT(*) as c FROM ddns_records WHERE user_id = ?').get(req.user.id).c;
    if (count >= req.user.max_entries) {
      req.session.flash = { type: 'error', message: `Your ${req.user.tier_display_name} plan allows up to ${req.user.max_entries} records. Please upgrade to add more.` };
      return reply.redirect('/dashboard');
    }

    // Verify zone is accessible to user's tier
    const zone = db.prepare(`
      SELECT z.* FROM zones z
      JOIN zone_tiers zt ON zt.zone_id = z.id
      WHERE z.id = ? AND zt.tier_id = ? AND z.is_active = 1
    `).get(zone_id, req.user.tier_id);
    if (!zone) {
      req.session.flash = { type: 'error', message: 'Zone not available for your plan.' };
      return reply.redirect('/dashboard');
    }

    const minTtl = req.user.min_ttl || 300;
    const resolvedTtl = Math.max(minTtl, parseInt(ttl || minTtl, 10));

    // Duplicate check
    const exists = db.prepare('SELECT id FROM ddns_records WHERE zone_id = ? AND LOWER(subdomain) = LOWER(?)').get(zone_id, sub);
    if (exists) {
      req.session.flash = { type: 'error', message: 'That subdomain is already taken in this zone.' };
      return reply.redirect('/dashboard');
    }

    const pat = generatePat();
    const patHash = hashPat(pat);

    const ipVal = (ip && ip.trim()) ? ip.trim() : null;
    db.prepare('INSERT INTO ddns_records (user_id, zone_id, subdomain, ttl, pat_hash, ip_address) VALUES (?, ?, ?, ?, ?, ?)').run(req.user.id, zone_id, sub, resolvedTtl, patHash, ipVal);

    req.session.newPat = { subdomain: sub, zone: zone.domain, pat };
    req.session.flash = { type: 'success', message: 'Record created. Save your API key — it will only be shown once.' };
    return reply.redirect('/dashboard');
  });

  // POST /dashboard/records/:id/toggle
  fastify.post('/dashboard/records/:id/toggle', async (req, reply) => {
    const db = getDb();
    const record = db.prepare('SELECT * FROM ddns_records WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send('Not found');
    db.prepare('UPDATE ddns_records SET is_enabled = ? WHERE id = ?').run(record.is_enabled ? 0 : 1, record.id);
    return reply.redirect('/dashboard');
  });

  // POST /dashboard/records/:id/delete
  fastify.post('/dashboard/records/:id/delete', async (req, reply) => {
    const db = getDb();
    const record = db.prepare('SELECT * FROM ddns_records WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send('Not found');
    db.prepare('DELETE FROM ddns_records WHERE id = ?').run(record.id);
    req.session.flash = { type: 'success', message: 'Record deleted.' };
    return reply.redirect('/dashboard');
  });

  // POST /dashboard/records/:id/update-ttl
  fastify.post('/dashboard/records/:id/update-ttl', async (req, reply) => {
    const db = getDb();
    const record = db.prepare('SELECT * FROM ddns_records WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send('Not found');
    const minTtl = req.user.min_ttl || 300;
    const ttl = Math.max(minTtl, parseInt(req.body.ttl || minTtl, 10));
    db.prepare('UPDATE ddns_records SET ttl = ? WHERE id = ?').run(ttl, record.id);
    return reply.redirect('/dashboard');
  });

  // POST /dashboard/records/:id/regenerate-pat
  fastify.post('/dashboard/records/:id/regenerate-pat', async (req, reply) => {
    const db = getDb();
    const record = db.prepare('SELECT * FROM ddns_records WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send('Not found');

    const pat = generatePat();
    const patHash = hashPat(pat);
    db.prepare('UPDATE ddns_records SET pat_hash = ? WHERE id = ?').run(patHash, record.id);

    const zone = db.prepare('SELECT domain FROM zones WHERE id = ?').get(record.zone_id);
    req.session.newPat = { subdomain: record.subdomain, zone: zone.domain, pat };
    req.session.flash = { type: 'success', message: 'API key regenerated. Save your new key — it will only be shown once.' };
    return reply.redirect('/dashboard');
  });

  // GET /dashboard/records/:id/setup — returns setup instructions HTML fragment
  fastify.get('/dashboard/records/:id/setup', async (req, reply) => {
    const db = getDb();
    const record = db.prepare(`
      SELECT r.*, z.domain as zone_domain
      FROM ddns_records r JOIN zones z ON z.id = r.zone_id
      WHERE r.id = ? AND r.user_id = ?
    `).get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send('Not found');

    const siteUrl = getSetting('site_url') || 'https://yourddns.com';
    const fqdn = `${record.subdomain}.${record.zone_domain}`;
    const updateUrl = `${siteUrl}/api/update`;

    return reply.view('dashboard/setup-modal.njk', { record, fqdn, updateUrl, siteUrl });
  });

  // GET /dashboard/profile
  fastify.get('/dashboard/profile', async (req, reply) => {
    const flash = req.session.flash;
    delete req.session.flash;
    return reply.view('dashboard/profile.njk', {
      title: 'Profile',
      flash,
    });
  });

  // POST /dashboard/profile/change-password
  fastify.post('/dashboard/profile/change-password', async (req, reply) => {
    const bcrypt = require('bcryptjs');
    const { current_password, new_password, new_password2 } = req.body || {};
    req.session.flash = null;
    if (!current_password || !new_password) {
      req.session.flash = { type: 'error', message: 'All fields required.' };
      return reply.redirect('/dashboard/profile');
    }
    if (new_password !== new_password2) {
      req.session.flash = { type: 'error', message: 'New passwords do not match.' };
      return reply.redirect('/dashboard/profile');
    }
    if (new_password.length < 8) {
      req.session.flash = { type: 'error', message: 'Password must be at least 8 characters.' };
      return reply.redirect('/dashboard/profile');
    }
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user.password_hash || !(await bcrypt.compare(current_password, user.password_hash))) {
      req.session.flash = { type: 'error', message: 'Current password incorrect.' };
      return reply.redirect('/dashboard/profile');
    }
    const hash = await bcrypt.hash(new_password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
    req.session.flash = { type: 'success', message: 'Password updated.' };
    return reply.redirect('/dashboard/profile');
  });
};
