'use strict';

const net = require('net');
const { getDb, getSetting } = require('../db/index');
const { generatePat, hashPat } = require('../services/pat');

module.exports = async function apiRoutes(fastify) {
  // GET /api/update?key=...&subdomain=...&ip=...&ip6=...
  fastify.get('/api/update', async (req, reply) => {
    const { key, subdomain, ip, ip6, name } = req.query || {};
    const computerName = name ? String(name).slice(0, 64).replace(/[^\w\-. ]/g, '') : null;
    const clientIp = req.ip;
    const db = getDb();

    reply.header('Content-Type', 'text/plain');

    if (!key || !subdomain) return reply.code(400).send('badrequest');

    // Block listed IPs
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return reply.code(403).send('blocked');
    }

    // Look up record by PAT hash
    const patHash = hashPat(key);
    const record = db.prepare(`
      SELECT r.*, z.domain as zone_domain
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      WHERE r.pat_hash = ? AND z.is_active = 1
    `).get(patHash);

    if (!record) return reply.code(401).send('badauth');

    // Optionally verify subdomain matches (accepts FQDN or bare subdomain)
    const subLower = subdomain.trim().toLowerCase();
    const fqdn = `${record.subdomain}.${record.zone_domain}`.toLowerCase();
    if (subLower !== fqdn && subLower !== record.subdomain.toLowerCase()) {
      return reply.code(401).send('badauth');
    }

    if (!record.is_enabled) return reply.code(403).send('disabled');

    // Rate limiting
    const user = db.prepare('SELECT u.*, t.max_updates_per_hour FROM users u JOIN tiers t ON t.id = u.tier_id WHERE u.id = ?').get(record.user_id);
    const maxUpdates = user ? user.max_updates_per_hour : 10;
    const recentUpdates = db.prepare(`
      SELECT COUNT(*) as c FROM update_logs
      WHERE record_id = ? AND updated_at >= datetime('now', '-1 hour')
    `).get(record.id).c;
    if (recentUpdates >= maxUpdates) return reply.code(429).send('abuse');

    // Determine what to update
    let newIp = null;
    let newIp6 = null;

    if (ip !== undefined || ip6 !== undefined) {
      // Explicit params provided — only update what's specified
      if (ip !== undefined) {
        const v = ip.trim();
        if (!net.isIPv4(v)) return reply.code(400).send('badip');
        newIp = v;
      }
      if (ip6 !== undefined) {
        const v = ip6.trim();
        if (!net.isIPv6(v)) return reply.code(400).send('badip');
        newIp6 = v;
      }
    } else {
      // Auto-detect from client connection type
      if (net.isIPv6(clientIp)) {
        newIp6 = clientIp;
      } else if (net.isIPv4(clientIp)) {
        newIp = clientIp;
      } else {
        return reply.code(400).send('badip');
      }
    }

    // Build UPDATE
    const setClauses = [];
    const runParams = [];
    if (newIp !== null)  { setClauses.push('ip_address = ?');  runParams.push(newIp); }
    if (newIp6 !== null) { setClauses.push('ip6_address = ?'); runParams.push(newIp6); }
    setClauses.push("last_update_received_at = datetime('now')");
    runParams.push(record.id);

    db.prepare(`UPDATE ddns_records SET ${setClauses.join(', ')} WHERE id = ?`).run(...runParams);

    db.prepare(`
      INSERT INTO update_logs (record_id, requester_ip, user_agent, new_ip, new_ip6, computer_name)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(record.id, clientIp, req.headers['user-agent'] || null, newIp, newIp6, computerName);

    const changed = (newIp !== null && newIp !== record.ip_address) || (newIp6 !== null && newIp6 !== record.ip6_address);
    const responseIps = [newIp, newIp6].filter(Boolean).join(' ');
    return reply.send(changed ? `good ${responseIps}` : `nochg ${responseIps}`);
  });

  // GET /api/status — health check
  fastify.get('/api/status', async (req, reply) => {
    return { status: 'ok', time: new Date().toISOString() };
  });

  // ── Zone API v1 ────────────────────────────────────────────────────────────
  // Auth: Authorization: Bearer <zone-api-key>  OR  ?key=<zone-api-key>

  function resolveZoneKey(req) {
    const db = getDb();

    // Block listed IPs (same as /api/update)
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(req.ip)) return null;

    const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim()
      || (req.query.key || '').trim();
    if (!raw) return null;
    const keyHash = hashPat(raw);
    const keyRow = db.prepare(`
      SELECT k.*, z.domain as zone_domain, z.is_active, z.validated,
             u.tier_id, t.max_entries, t.min_ttl, t.min_subdomain_length,
             t.max_updates_per_hour, t.max_records_per_day
      FROM zone_api_keys k
      JOIN zones z ON z.id = k.zone_id
      JOIN users u ON u.id = k.user_id
      JOIN tiers t ON t.id = u.tier_id
      WHERE k.key_hash = ? AND z.validated = 1 AND z.is_active = 1 AND u.is_disabled = 0
    `).get(keyHash);
    if (keyRow) {
      db.prepare("UPDATE zone_api_keys SET last_used_at = datetime('now') WHERE id = ?").run(keyRow.id);
    }
    return keyRow || null;
  }

  // GET /api/v1/zones — info about the zone this key belongs to
  fastify.get('/api/v1/zones', async (req, reply) => {
    const keyRow = resolveZoneKey(req);
    if (!keyRow) return reply.code(401).send({ error: 'badauth' });
    const db = getDb();
    const records = db.prepare('SELECT COUNT(*) as c FROM ddns_records WHERE zone_id = ? AND user_id = ?').get(keyRow.zone_id, keyRow.user_id);
    return reply.send({
      zone: keyRow.zone_domain,
      record_count: records.c,
      max_entries: keyRow.max_entries,
    });
  });

  // GET /api/v1/zones/:zone/records
  fastify.get('/api/v1/zones/:zone/records', async (req, reply) => {
    const keyRow = resolveZoneKey(req);
    if (!keyRow) return reply.code(401).send({ error: 'badauth' });
    if (req.params.zone.toLowerCase() !== keyRow.zone_domain.toLowerCase()) {
      return reply.code(403).send({ error: 'forbidden' });
    }
    const db = getDb();
    const records = db.prepare(`
      SELECT subdomain, ip_address, ip6_address, ttl, is_enabled, hit_count,
             created_at, last_update_received_at
      FROM ddns_records WHERE zone_id = ? AND user_id = ?
      ORDER BY subdomain
    `).all(keyRow.zone_id, keyRow.user_id);
    return reply.send({ zone: keyRow.zone_domain, records });
  });

  // POST /api/v1/zones/:zone/records — create a record
  fastify.post('/api/v1/zones/:zone/records', { config: { rateLimit: { max: 30, timeWindow: '1 hour' } } }, async (req, reply) => {
    const keyRow = resolveZoneKey(req);
    if (!keyRow) return reply.code(401).send({ error: 'badauth' });
    if (req.params.zone.toLowerCase() !== keyRow.zone_domain.toLowerCase()) {
      return reply.code(403).send({ error: 'forbidden' });
    }

    const { subdomain, ip, ip6, ttl } = req.body || {};
    if (!subdomain) return reply.code(400).send({ error: 'subdomain is required' });

    const sub = subdomain.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (sub !== subdomain.trim().toLowerCase()) {
      return reply.code(400).send({ error: 'Subdomain may only contain letters, numbers, hyphens, and underscores.' });
    }
    if (sub.length === 0) return reply.code(400).send({ error: 'subdomain is required' });

    const db = getDb();

    // Check tier entry limit
    const count = db.prepare('SELECT COUNT(*) as c FROM ddns_records WHERE user_id = ?').get(keyRow.user_id).c;
    if (count >= keyRow.max_entries) {
      return reply.code(429).send({ error: `Record limit reached (${keyRow.max_entries}).` });
    }

    // Check daily creation rate
    const maxPerDay = keyRow.max_records_per_day || 10;
    const createdToday = db.prepare(
      "SELECT COUNT(*) as c FROM ddns_records WHERE user_id = ? AND created_at >= datetime('now', '-1 day')"
    ).get(keyRow.user_id).c;
    if (createdToday >= maxPerDay) {
      return reply.code(429).send({ error: `Daily record creation limit reached (${maxPerDay}/day).` });
    }

    // Duplicate check
    const exists = db.prepare('SELECT id FROM ddns_records WHERE zone_id = ? AND LOWER(subdomain) = ?').get(keyRow.zone_id, sub);
    if (exists) return reply.code(409).send({ error: 'Subdomain already exists in this zone.' });

    // IP validation
    const ipVal  = ip  ? ip.trim()  : null;
    const ip6Val = ip6 ? ip6.trim() : null;
    if (ipVal  && !net.isIPv4(ipVal))  return reply.code(400).send({ error: 'Invalid IPv4 address.' });
    if (ip6Val && !net.isIPv6(ip6Val)) return reply.code(400).send({ error: 'Invalid IPv6 address.' });

    const globalMinTtl = parseInt(getSetting('global_min_ttl') || 1, 10);
    const minTtl = Math.max(globalMinTtl, keyRow.min_ttl || 300);
    const resolvedTtl = Math.max(minTtl, parseInt(ttl || minTtl, 10));

    const pat = generatePat();
    const patHash = hashPat(pat);
    db.prepare('INSERT INTO ddns_records (user_id, zone_id, subdomain, ttl, pat_hash, ip_address, ip6_address) VALUES (?, ?, ?, ?, ?, ?, ?)').run(keyRow.user_id, keyRow.zone_id, sub, resolvedTtl, patHash, ipVal, ip6Val);

    return reply.code(201).send({
      subdomain: sub,
      fqdn: `${sub}.${keyRow.zone_domain}`,
      ip_address: ipVal,
      ip6_address: ip6Val,
      ttl: resolvedTtl,
      api_key: pat,
    });
  });

  // DELETE /api/v1/zones/:zone/records/:subdomain
  fastify.delete('/api/v1/zones/:zone/records/:subdomain', { config: { rateLimit: { max: 60, timeWindow: '1 hour' } } }, async (req, reply) => {
    const keyRow = resolveZoneKey(req);
    if (!keyRow) return reply.code(401).send({ error: 'badauth' });
    if (req.params.zone.toLowerCase() !== keyRow.zone_domain.toLowerCase()) {
      return reply.code(403).send({ error: 'forbidden' });
    }

    const sub = req.params.subdomain.trim().toLowerCase();
    const db = getDb();
    const record = db.prepare('SELECT id FROM ddns_records WHERE zone_id = ? AND user_id = ? AND LOWER(subdomain) = ?').get(keyRow.zone_id, keyRow.user_id, sub);
    if (!record) return reply.code(404).send({ error: 'Record not found.' });

    db.prepare('DELETE FROM ddns_records WHERE id = ?').run(record.id);
    return reply.code(200).send({ deleted: true, subdomain: sub, zone: keyRow.zone_domain });
  });
};
