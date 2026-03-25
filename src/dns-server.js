'use strict';

const dns2 = require('dns2');
const { Packet } = dns2;

// dns2 does not export RCODE constants — use raw values
const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };
const { getDb } = require('./db/index');

let server;

// In-memory resolution rate tracker: userId -> { count, windowStart }
const resolutionTracker = new Map();
function checkResolutionRate(userId, maxPerHour) {
  const now = Date.now();
  const window = 60 * 60 * 1000; // 1 hour
  let entry = resolutionTracker.get(userId);
  if (!entry || now - entry.windowStart >= window) {
    entry = { count: 0, windowStart: now };
  }
  entry.count++;
  resolutionTracker.set(userId, entry);
  return entry.count <= maxPerHour;
}

function getClientIp(rinfo) {
  return rinfo && rinfo.address ? rinfo.address : null;
}

function incrementHit(db, recordId, clientIp, qtype) {
  try {
    db.prepare('INSERT INTO dns_hits (record_id, client_ip, query_type) VALUES (?, ?, ?)').run(recordId, clientIp, qtype);
  } catch (e) {
    console.error('[dns] hit log error:', e.message);
  }
  try {
    db.prepare('UPDATE ddns_records SET hit_count = hit_count + 1 WHERE id = ?').run(recordId);
  } catch (_) { /* hit_count column may not exist on old schema */ }
}

function isBlocked(db, ip) {
  if (!ip) return false;
  return !!db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(ip);
}

function buildSoa(zone) {
  const ns = JSON.parse(zone.ns_hostnames || '[]')[0] || `ns1.${zone.domain}`;
  const email = (zone.soa_email || 'hostmaster@yourddns.com').replace('@', '.');
  return {
    mname: ns,
    rname: email,
    serial: zone.soa_serial || 1,
    refresh: 3600,
    retry: 900,
    expire: 604800,
    minimum: 300,
  };
}

async function handleQuery(request, send, rinfo) {
  const response = Packet.createResponseFromRequest(request);
  const db = getDb();
  const clientIp = getClientIp(rinfo);

  // Block listed IPs from DNS resolution
  if (clientIp && isBlocked(db, clientIp)) {
    response.header.rcode = RCODE.REFUSED;
    return send(response);
  }

  for (const question of request.questions) {
    const qname = question.name.toLowerCase().replace(/\.$/, '');
    const qtype = question.type;

    // Find which zone this query belongs to
    const zones = db.prepare('SELECT * FROM zones WHERE is_active = 1 ORDER BY length(domain) DESC').all();
    let matchedZone = null;
    let subdomain = null;

    for (const zone of zones) {
      const zd = zone.domain.toLowerCase();
      if (qname === zd) {
        matchedZone = zone;
        subdomain = '@';
        break;
      }
      if (qname.endsWith('.' + zd)) {
        matchedZone = zone;
        subdomain = qname.slice(0, qname.length - zd.length - 1);
        break;
      }
    }

    if (!matchedZone) {
      response.header.rcode = RCODE.REFUSED;
      continue;
    }

    // SOA queries
    if (qtype === Packet.TYPE.SOA || qtype === Packet.TYPE.ANY) {
      const soa = buildSoa(matchedZone);
      response.answers.push({
        name: matchedZone.domain,
        type: Packet.TYPE.SOA,
        class: Packet.CLASS.IN,
        ttl: 3600,
        primary: soa.mname,
        admin: soa.rname,
        serial: soa.serial,
        refresh: soa.refresh,
        retry: soa.retry,
        expiration: soa.expire,
        minimum: soa.minimum,
      });
    }

    // NS queries
    if (qtype === Packet.TYPE.NS || qtype === Packet.TYPE.ANY) {
      const nsList = JSON.parse(matchedZone.ns_hostnames || '[]');
      for (const ns of nsList) {
        response.answers.push({
          name: matchedZone.domain,
          type: Packet.TYPE.NS,
          class: Packet.CLASS.IN,
          ttl: 3600,
          ns,
        });
      }
    }

    // Static zone records
    if (subdomain !== null) {
      const nameToLookup = subdomain === '@' ? matchedZone.domain : `${subdomain}.${matchedZone.domain}`;
      const staticTypeMap = { [Packet.TYPE.A]: 'A', [Packet.TYPE.AAAA]: 'AAAA', [Packet.TYPE.CNAME]: 'CNAME', [Packet.TYPE.MX]: 'MX', [Packet.TYPE.TXT]: 'TXT' };
      const typeFilter = staticTypeMap[qtype];

      const staticRecords = db.prepare(`
        SELECT * FROM zone_static_records
        WHERE zone_id = ? AND LOWER(name) = LOWER(?)
        ${typeFilter ? "AND type = ?" : ""}
      `).all(...(typeFilter ? [matchedZone.id, subdomain === '@' ? '@' : subdomain, typeFilter] : [matchedZone.id, subdomain === '@' ? '@' : subdomain]));

      for (const rec of staticRecords) {
        const entry = { name: nameToLookup, class: Packet.CLASS.IN, ttl: rec.ttl };
        if (rec.type === 'A') {
          entry.type = Packet.TYPE.A;
          entry.address = rec.value;
        } else if (rec.type === 'AAAA') {
          entry.type = Packet.TYPE.AAAA;
          entry.address = rec.value;
        } else if (rec.type === 'CNAME') {
          entry.type = Packet.TYPE.CNAME;
          entry.domain = rec.value;
        } else if (rec.type === 'MX') {
          entry.type = Packet.TYPE.MX;
          entry.exchange = rec.value;
          entry.priority = rec.priority || 10;
        } else if (rec.type === 'TXT') {
          entry.type = Packet.TYPE.TXT;
          entry.data = rec.value;
        }
        if (entry.type !== undefined) response.answers.push(entry);
      }

      // DDNS A record lookup (only for non-apex queries)
      if (subdomain && subdomain !== '@' && (qtype === Packet.TYPE.A || qtype === Packet.TYPE.ANY)) {
        const record = db.prepare(`
          SELECT r.* FROM ddns_records r
          WHERE r.zone_id = ? AND LOWER(r.subdomain) = LOWER(?) AND r.is_enabled = 1 AND r.ip_address IS NOT NULL
        `).get(matchedZone.id, subdomain);

        if (record) {
          const owner = db.prepare('SELECT u.id, t.max_resolutions_per_hour FROM users u JOIN tiers t ON t.id = u.tier_id WHERE u.id = ?').get(record.user_id);
          if (!owner || checkResolutionRate(owner.id, owner.max_resolutions_per_hour)) {
            incrementHit(db, record.id, clientIp, 'A');
          }
          response.answers.push({
            name: qname,
            type: Packet.TYPE.A,
            class: Packet.CLASS.IN,
            ttl: record.ttl,
            address: record.ip_address,
          });
        }
      }

      // DDNS AAAA record lookup (only for non-apex queries)
      if (subdomain && subdomain !== '@' && (qtype === Packet.TYPE.AAAA || qtype === Packet.TYPE.ANY)) {
        const record = db.prepare(`
          SELECT r.* FROM ddns_records r
          WHERE r.zone_id = ? AND LOWER(r.subdomain) = LOWER(?) AND r.is_enabled = 1 AND r.ip6_address IS NOT NULL
        `).get(matchedZone.id, subdomain);

        if (record) {
          const owner = db.prepare('SELECT u.id, t.max_resolutions_per_hour FROM users u JOIN tiers t ON t.id = u.tier_id WHERE u.id = ?').get(record.user_id);
          if (!owner || checkResolutionRate(owner.id, owner.max_resolutions_per_hour)) {
            incrementHit(db, record.id, clientIp, 'AAAA');
          }
          response.answers.push({
            name: qname,
            type: Packet.TYPE.AAAA,
            class: Packet.CLASS.IN,
            ttl: record.ttl,
            address: record.ip6_address,
          });
        }
      }
    }

    if (response.answers.length === 0 && (qtype === Packet.TYPE.A || qtype === Packet.TYPE.AAAA)) {
      // NXDOMAIN for unknown names in our zone
      response.header.rcode = RCODE.NXDOMAIN;
      const soa = buildSoa(matchedZone);
      response.authorities.push({
        name: matchedZone.domain,
        type: Packet.TYPE.SOA,
        class: Packet.CLASS.IN,
        ttl: 300,
        primary: soa.mname,
        admin: soa.rname,
        serial: soa.serial,
        refresh: soa.refresh,
        retry: soa.retry,
        expiration: soa.expire,
        minimum: soa.minimum,
      });
    }
  }

  send(response);
}

function startDnsServer() {
  const port = parseInt(process.env.DNS_PORT || '53', 10);
  const host = process.env.DNS_HOST || '0.0.0.0';

  server = dns2.createServer({ udp: true, tcp: true, handle: handleQuery });

  server.on('error', (err) => console.error('[dns] error:', err.message));

  server.listen({ udp: { port, address: host }, tcp: { port, address: host } });
  console.log(`[dns] Listening on ${host}:${port}`);
  return server;
}

function stopDnsServer() {
  if (server) server.close();
}

module.exports = { startDnsServer, stopDnsServer };
