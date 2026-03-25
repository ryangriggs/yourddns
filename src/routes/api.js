'use strict';

const net = require('net');
const { getDb } = require('../db/index');
const { hashPat } = require('../services/pat');

module.exports = async function apiRoutes(fastify) {
  // GET /api/update?key=...&subdomain=...&ip=...&ip6=...
  fastify.get('/api/update', async (req, reply) => {
    const { key, subdomain, ip, ip6 } = req.query || {};
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

    const logIp = newIp || newIp6;
    db.prepare(`
      INSERT INTO update_logs (record_id, requester_ip, user_agent, new_ip)
      VALUES (?, ?, ?, ?)
    `).run(record.id, clientIp, req.headers['user-agent'] || null, logIp);

    const changed = (newIp !== null && newIp !== record.ip_address) || (newIp6 !== null && newIp6 !== record.ip6_address);
    const responseIps = [newIp, newIp6].filter(Boolean).join(' ');
    return reply.send(changed ? `good ${responseIps}` : `nochg ${responseIps}`);
  });

  // GET /api/status — health check
  fastify.get('/api/status', async (req, reply) => {
    return { status: 'ok', time: new Date().toISOString() };
  });
};
