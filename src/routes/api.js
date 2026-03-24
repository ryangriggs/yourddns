'use strict';

const { getDb } = require('../db/index');
const { hashPat } = require('../services/pat');

module.exports = async function apiRoutes(fastify) {
  // GET /api/update?key=...&subdomain=...&ip=...
  fastify.get('/api/update', async (req, reply) => {
    const { key, subdomain, ip } = req.query || {};
    const clientIp = req.ip;
    const db = getDb();

    reply.header('Content-Type', 'text/plain');

    if (!key || !subdomain) return reply.code(400).send('badrequest');

    // Block listed IPs
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return reply.code(403).send('blocked');
    }

    // Look up record by PAT hash directly (O(1) not O(n))
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

    // Rate limiting: check updates per hour for user's tier
    const user = db.prepare('SELECT u.*, t.max_updates_per_hour FROM users u JOIN tiers t ON t.id = u.tier_id WHERE u.id = ?').get(record.user_id);
    const maxUpdates = user ? user.max_updates_per_hour : 10;
    const recentUpdates = db.prepare(`
      SELECT COUNT(*) as c FROM update_logs
      WHERE record_id = ? AND updated_at >= datetime('now', '-1 hour')
    `).get(record.id).c;
    if (recentUpdates >= maxUpdates) return reply.code(429).send('abuse');

    // Determine IP to set
    let newIp = ip ? ip.trim() : clientIp;

    // Basic IPv4 validation
    const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Re.test(newIp)) return reply.code(400).send('badip');

    const oldIp = record.ip_address;

    db.prepare(`
      UPDATE ddns_records
      SET ip_address = ?, last_update_received_at = datetime('now')
      WHERE id = ?
    `).run(newIp, record.id);

    db.prepare(`
      INSERT INTO update_logs (record_id, requester_ip, user_agent, new_ip)
      VALUES (?, ?, ?, ?)
    `).run(record.id, clientIp, req.headers['user-agent'] || null, newIp);

    const changed = newIp !== oldIp;
    return reply.send(changed ? `good ${newIp}` : `nochg ${newIp}`);
  });

  // GET /api/status — health check
  fastify.get('/api/status', async (req, reply) => {
    return { status: 'ok', time: new Date().toISOString() };
  });
};
