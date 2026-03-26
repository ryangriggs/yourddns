'use strict';

const net = require('net');
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
      LEFT JOIN zone_tiers zt ON zt.zone_id = z.id AND zt.tier_id = ?
      WHERE z.is_active = 1
        AND z.validated = 1
        AND (
          (z.user_id IS NULL AND zt.zone_id IS NOT NULL)
          OR z.user_id = ?
        )
      ORDER BY z.domain
    `).all(req.user.tier_id, req.user.id);

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

  // GET /dashboard/records/check — real-time subdomain availability
  fastify.get('/dashboard/records/check', async (req, reply) => {
    const { subdomain, zone_id } = req.query || {};
    if (!subdomain || !zone_id) return reply.send({ available: false, reason: 'missing' });

    const sub = subdomain.trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (sub !== subdomain.trim().toLowerCase()) {
      return reply.send({ available: false, reason: 'Letters, numbers, and hyphens only.' });
    }
    if (sub.length === 0) return reply.send({ available: false, reason: 'missing' });

    const db = getDb();

    // Verify zone is accessible to this user
    const zone = db.prepare(`
      SELECT z.* FROM zones z
      LEFT JOIN zone_tiers zt ON zt.zone_id = z.id AND zt.tier_id = ?
      WHERE z.id = ? AND z.is_active = 1 AND z.validated = 1
        AND ((z.user_id IS NULL AND zt.zone_id IS NOT NULL) OR z.user_id = ?)
    `).get(req.user.tier_id, zone_id, req.user.id);
    if (!zone) return reply.send({ available: false, reason: 'Zone not available.' });

    const isCustomZone = zone.user_id === req.user.id;
    if (!isCustomZone) {
      const minLen = req.user.min_subdomain_length || 4;
      if (sub.length < minLen) {
        return reply.send({ available: false, reason: `Min ${minLen} characters on your plan.` });
      }
    }

    const exists = db.prepare('SELECT id FROM ddns_records WHERE zone_id = ? AND LOWER(subdomain) = ?').get(zone_id, sub);
    if (exists) return reply.send({ available: false, reason: 'Already taken.' });

    return reply.send({ available: true });
  });

  // POST /dashboard/records  — create
  fastify.post('/dashboard/records', async (req, reply) => {
    const db = getDb();
    const { subdomain, zone_id, ttl, ip, ip6 } = req.body || {};

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

    // Check tier entry limit
    const count = db.prepare('SELECT COUNT(*) as c FROM ddns_records WHERE user_id = ?').get(req.user.id).c;
    if (count >= req.user.max_entries) {
      req.session.flash = { type: 'error', message: `Your ${req.user.tier_display_name} plan allows up to ${req.user.max_entries} records. Please upgrade to add more.` };
      return reply.redirect('/dashboard');
    }

    // Check daily creation rate limit
    const maxPerDay = req.user.max_records_per_day || 10;
    const createdToday = db.prepare(
      "SELECT COUNT(*) as c FROM ddns_records WHERE user_id = ? AND created_at >= datetime('now', '-1 day')"
    ).get(req.user.id).c;
    if (createdToday >= maxPerDay) {
      req.session.flash = { type: 'error', message: `You can create up to ${maxPerDay} records per day on your plan. Try again tomorrow.` };
      return reply.redirect('/dashboard');
    }

    // Verify zone is accessible: either a tier-linked shared zone or the user's own validated custom zone
    const zone = db.prepare(`
      SELECT z.* FROM zones z
      LEFT JOIN zone_tiers zt ON zt.zone_id = z.id AND zt.tier_id = ?
      WHERE z.id = ?
        AND z.is_active = 1
        AND z.validated = 1
        AND (
          (z.user_id IS NULL AND zt.zone_id IS NOT NULL)
          OR z.user_id = ?
        )
    `).get(req.user.tier_id, zone_id, req.user.id);
    if (!zone) {
      req.session.flash = { type: 'error', message: 'Zone not available for your plan.' };
      return reply.redirect('/dashboard');
    }

    // Min subdomain length: skipped for user's own custom zones
    const isCustomZone = zone.user_id === req.user.id;
    if (!isCustomZone) {
      const minLen = req.user.min_subdomain_length || 4;
      if (sub.length < minLen) {
        req.session.flash = { type: 'error', message: `Subdomain must be at least ${minLen} characters.` };
        return reply.redirect('/dashboard');
      }
    }

    const globalMinTtl = parseInt(getSetting('global_min_ttl') || 1, 10);
    const minTtl = Math.max(globalMinTtl, req.user.min_ttl || 300);
    const resolvedTtl = Math.max(minTtl, parseInt(ttl || minTtl, 10));

    // Duplicate check
    const exists = db.prepare('SELECT id FROM ddns_records WHERE zone_id = ? AND LOWER(subdomain) = LOWER(?)').get(zone_id, sub);
    if (exists) {
      req.session.flash = { type: 'error', message: 'That subdomain is already taken in this zone.' };
      return reply.redirect('/dashboard');
    }

    const pat = generatePat();
    const patHash = hashPat(pat);

    const ipVal  = (ip  && ip.trim())  ? ip.trim()  : null;
    const ip6Val = (ip6 && ip6.trim()) ? ip6.trim() : null;
    db.prepare('INSERT INTO ddns_records (user_id, zone_id, subdomain, ttl, pat_hash, ip_address, ip6_address) VALUES (?, ?, ?, ?, ?, ?, ?)').run(req.user.id, zone_id, sub, resolvedTtl, patHash, ipVal, ip6Val);

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
    const globalMinTtl = parseInt(getSetting('global_min_ttl') || 1, 10);
    const minTtl = Math.max(globalMinTtl, req.user.min_ttl || 300);
    const ttl = Math.max(minTtl, parseInt(req.body.ttl || minTtl, 10));
    db.prepare('UPDATE ddns_records SET ttl = ? WHERE id = ?').run(ttl, record.id);
    return reply.redirect('/dashboard');
  });

  // POST /dashboard/records/:id/edit
  fastify.post('/dashboard/records/:id/edit', async (req, reply) => {
    const db = getDb();
    const record = db.prepare('SELECT * FROM ddns_records WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send('Not found');

    const { ip, ip6, ttl } = req.body || {};
    const ipVal  = (ip  && ip.trim())  ? ip.trim()  : null;
    const ip6Val = (ip6 && ip6.trim()) ? ip6.trim() : null;

    if (ipVal && !net.isIPv4(ipVal)) {
      req.session.flash = { type: 'error', message: 'Invalid IPv4 address.' };
      return reply.redirect('/dashboard');
    }
    if (ip6Val && !net.isIPv6(ip6Val)) {
      req.session.flash = { type: 'error', message: 'Invalid IPv6 address.' };
      return reply.redirect('/dashboard');
    }

    const globalMinTtl = parseInt(getSetting('global_min_ttl') || 1, 10);
    const minTtl = Math.max(globalMinTtl, req.user.min_ttl || 300);
    const resolvedTtl = Math.max(minTtl, parseInt(ttl || minTtl, 10));

    db.prepare('UPDATE ddns_records SET ip_address = ?, ip6_address = ?, ttl = ? WHERE id = ?').run(ipVal, ip6Val, resolvedTtl, record.id);
    req.session.flash = { type: 'success', message: 'Record updated.' };
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

  // GET /dashboard/records/:id/history — last 10 update log entries (JSON)
  fastify.get('/dashboard/records/:id/history', async (req, reply) => {
    const db = getDb();
    const record = db.prepare('SELECT id FROM ddns_records WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!record) return reply.code(404).send({ error: 'Not found' });

    const rows = db.prepare(`
      SELECT updated_at, new_ip, new_ip6, requester_ip, computer_name
      FROM update_logs
      WHERE record_id = ?
      ORDER BY updated_at DESC
      LIMIT 10
    `).all(record.id);
    return reply.send(rows);
  });

  // GET /dashboard/profile
  fastify.get('/dashboard/profile', async (req, reply) => {
    const db = getDb();
    const tiers = db.prepare('SELECT * FROM tiers ORDER BY sort_order').all();
    const oauthAccounts = db.prepare('SELECT provider FROM oauth_accounts WHERE user_id = ?').all(req.user.id);
    const linkedProviders = new Set(oauthAccounts.map(a => a.provider));
    const flash = req.session.flash;
    delete req.session.flash;
    return reply.view('dashboard/profile.njk', {
      title: 'Profile',
      tiers,
      linkedProviders: [...linkedProviders],
      googleEnabled: !!process.env.GOOGLE_CLIENT_ID,
      flash,
    });
  });

  // POST /dashboard/profile/change-plan
  fastify.post('/dashboard/profile/change-plan', async (req, reply) => {
    const db = getDb();
    const { tier_id } = req.body || {};
    const tier = db.prepare('SELECT * FROM tiers WHERE id = ?').get(tier_id);
    if (!tier) {
      req.session.flash = { type: 'error', message: 'Invalid plan selected.' };
      return reply.redirect('/dashboard/profile');
    }
    db.prepare('UPDATE users SET tier_id = ? WHERE id = ?').run(tier.id, req.user.id);
    req.session.flash = { type: 'success', message: `Plan changed to ${tier.display_name}.` };
    return reply.redirect('/dashboard/profile');
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

  // POST /dashboard/profile/set-password  (OAuth users with no password yet)
  fastify.post('/dashboard/profile/set-password', async (req, reply) => {
    const bcrypt = require('bcryptjs');
    const { new_password, new_password2 } = req.body || {};
    req.session.flash = null;
    const db = getDb();
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    if (user.password_hash) {
      // Already has a password — use change-password instead
      req.session.flash = { type: 'error', message: 'Use the change password form.' };
      return reply.redirect('/dashboard/profile');
    }
    if (!new_password) {
      req.session.flash = { type: 'error', message: 'Password is required.' };
      return reply.redirect('/dashboard/profile');
    }
    if (new_password !== new_password2) {
      req.session.flash = { type: 'error', message: 'Passwords do not match.' };
      return reply.redirect('/dashboard/profile');
    }
    if (new_password.length < 8) {
      req.session.flash = { type: 'error', message: 'Password must be at least 8 characters.' };
      return reply.redirect('/dashboard/profile');
    }
    const hash = await bcrypt.hash(new_password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
    req.session.flash = { type: 'success', message: 'Password set. You can now sign in with email and password.' };
    return reply.redirect('/dashboard/profile');
  });

  // POST /dashboard/profile/unlink-google
  fastify.post('/dashboard/profile/unlink-google', async (req, reply) => {
    const db = getDb();
    const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.id);
    if (!user.password_hash) {
      req.session.flash = { type: 'error', message: 'Set a password before unlinking Google.' };
      return reply.redirect('/dashboard/profile');
    }
    db.prepare("DELETE FROM oauth_accounts WHERE user_id = ? AND provider = 'google'").run(req.user.id);
    req.session.flash = { type: 'success', message: 'Google account unlinked.' };
    return reply.redirect('/dashboard/profile');
  });

  // GET /dashboard/api-keys
  fastify.get('/dashboard/api-keys', async (req, reply) => {
    const db = getDb();
    const { sort = 'created', dir = 'desc' } = req.query || {};
    const validSorts = { name: 'k.name', zone: 'z.domain', created: 'k.created_at', last_used: 'k.last_used_at' };
    const sortCol = validSorts[sort] || 'k.created_at';
    const sortDir = dir === 'asc' ? 'ASC' : 'DESC';

    const keys = db.prepare(`
      SELECT k.*, z.domain as zone_domain
      FROM zone_api_keys k
      JOIN zones z ON z.id = k.zone_id
      WHERE k.user_id = ?
      ORDER BY ${sortCol} ${sortDir}
    `).all(req.user.id);

    const zones = db.prepare(`
      SELECT * FROM zones WHERE user_id = ? AND validated = 1 ORDER BY domain
    `).all(req.user.id);

    const flash = req.session.flash;
    const newKey = req.session.newApiKey;
    delete req.session.flash;
    delete req.session.newApiKey;

    return reply.view('dashboard/api-keys.njk', {
      title: 'API Keys',
      keys,
      zones,
      flash,
      newKey,
      sort,
      dir,
      siteUrl: getSetting('site_url') || '',
    });
  });

  // POST /dashboard/api-keys
  fastify.post('/dashboard/api-keys', async (req, reply) => {
    const { zone_id, name } = req.body || {};
    if (!zone_id || !name || !name.trim()) {
      req.session.flash = { type: 'error', message: 'Zone and key name are required.' };
      return reply.redirect('/dashboard/api-keys');
    }

    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ? AND validated = 1').get(zone_id, req.user.id);
    if (!zone) {
      req.session.flash = { type: 'error', message: 'Zone not found or not validated.' };
      return reply.redirect('/dashboard/api-keys');
    }

    const rawKey = generatePat().replace('yddns_', 'zak_');
    const keyHash = hashPat(rawKey);

    db.prepare('INSERT INTO zone_api_keys (user_id, zone_id, name, key_hash) VALUES (?, ?, ?, ?)').run(req.user.id, zone.id, name.trim(), keyHash);

    req.session.newApiKey = { key: rawKey, zone: zone.domain, name: name.trim() };
    req.session.flash = { type: 'success', message: 'API key created. Copy it now — it will not be shown again.' };
    return reply.redirect('/dashboard/api-keys');
  });

  // POST /dashboard/api-keys/:id/delete
  fastify.post('/dashboard/api-keys/:id/delete', async (req, reply) => {
    const db = getDb();
    db.prepare('DELETE FROM zone_api_keys WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
    req.session.flash = { type: 'success', message: 'API key deleted.' };
    return reply.redirect('/dashboard/api-keys');
  });
};
