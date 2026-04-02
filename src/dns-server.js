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

// Return A/AAAA records for a hostname if it falls within any zone we serve.
// Used to populate the additional section for NS glue and MX exchange hints.
function lookupAdditional(db, zones, hostname) {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  for (const zone of zones) {
    const zd = zone.domain.toLowerCase();
    let sub = null;
    if (h === zd) sub = '@';
    else if (h.endsWith('.' + zd)) sub = h.slice(0, h.length - zd.length - 1);
    if (sub === null) continue;

    const results = [];
    const statics = db.prepare(`
      SELECT value, ttl, type FROM zone_static_records
      WHERE zone_id = ? AND LOWER(name) = LOWER(?) AND type IN ('A', 'AAAA')
    `).all(zone.id, sub);
    for (const r of statics) {
      results.push({ name: hostname, type: r.type === 'A' ? Packet.TYPE.A : Packet.TYPE.AAAA, class: Packet.CLASS.IN, ttl: r.ttl, address: r.value });
    }
    if (sub !== '@') {
      const ddns = db.prepare(`
        SELECT ip_address, ip6_address, ttl FROM ddns_records
        WHERE zone_id = ? AND LOWER(subdomain) = LOWER(?) AND is_enabled = 1
      `).get(zone.id, sub);
      if (ddns) {
        if (ddns.ip_address)  results.push({ name: hostname, type: Packet.TYPE.A,    class: Packet.CLASS.IN, ttl: ddns.ttl, address: ddns.ip_address });
        if (ddns.ip6_address) results.push({ name: hostname, type: Packet.TYPE.AAAA, class: Packet.CLASS.IN, ttl: ddns.ttl, address: ddns.ip6_address });
      }
    }
    return results; // zone matched — return what we found (may be empty if no A/AAAA exists)
  }
  return []; // hostname not within any zone we serve
}

async function handleQuery(request, send, rinfo) {
  const response = Packet.createResponseFromRequest(request);
  response.header.ra = 0; // authoritative-only — we do not support recursion
  const db = getDb();
  const clientIp = getClientIp(rinfo);

  try {
    if (clientIp && isBlocked(db, clientIp)) {
      response.header.rcode = RCODE.REFUSED;
    } else if (request.header.opcode !== 0) {
      // Only handle standard QUERY (opcode 0); all others are not implemented (RFC 1035 §4.1.1)
      response.header.rcode = RCODE.NOTIMP;
    } else if (!request.questions || request.questions.length === 0) {
      response.header.rcode = RCODE.FORMERR;
    } else {
      // Hoist zone list outside the question loop — same result for every question
      const zones = db.prepare('SELECT * FROM zones WHERE is_active = 1 ORDER BY length(domain) DESC').all();

      for (const question of request.questions) {
        const qname = question.name.toLowerCase().replace(/\.$/, '');
        const qtype = question.type;

        // We only serve class IN; anything else (CHAOS, HESIOD, etc.) is not implemented
        if (question.class !== Packet.CLASS.IN) {
          if (response.header.rcode === RCODE.NOERROR) response.header.rcode = RCODE.NOTIMP;
          continue;
        }

        // Find which zone this query belongs to
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
          // Only set REFUSED if a prior question hasn't already produced an answer
          if (response.header.rcode === RCODE.NOERROR) response.header.rcode = RCODE.REFUSED;
          continue;
        }

        // We are authoritative for this zone — clear any error from a prior question
        response.header.rcode = RCODE.NOERROR;
        response.header.aa = 1;

        // Track answer count before this question so negative-response logic is per-question
        const answerCountBefore = response.answers.length;

        // SOA queries — only at the zone apex (SOA is an apex record, not a per-name record)
        if (subdomain === '@' && (qtype === Packet.TYPE.SOA || qtype === Packet.TYPE.ANY)) {
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

        // NS queries — only at the zone apex
        if (subdomain === '@' && (qtype === Packet.TYPE.NS || qtype === Packet.TYPE.ANY)) {
          const nsList = JSON.parse(matchedZone.ns_hostnames || '[]');
          for (const ns of nsList) {
            response.answers.push({
              name: matchedZone.domain,
              type: Packet.TYPE.NS,
              class: Packet.CLASS.IN,
              ttl: 3600,
              ns,
            });
            // Glue records: if the NS hostname is within our zone, include its A/AAAA
            // in the additional section so resolvers can bootstrap (RFC 1034 §4.3.2)
            for (const glue of lookupAdditional(db, zones, ns)) {
              if (!response.additionals.some(a => a.name === glue.name && a.type === glue.type && a.address === glue.address)) {
                response.additionals.push(glue);
              }
            }
          }
        }

        // Static zone records
        if (subdomain !== null) {
          const nameToLookup = subdomain === '@' ? matchedZone.domain : `${subdomain}.${matchedZone.domain}`;
          const staticTypeMap = { [Packet.TYPE.A]: 'A', [Packet.TYPE.AAAA]: 'AAAA', [Packet.TYPE.CNAME]: 'CNAME', [Packet.TYPE.MX]: 'MX', [Packet.TYPE.TXT]: 'TXT' };
          const typeFilter = staticTypeMap[qtype];
          // For unrecognized types (SOA, NS, PTR, SRV, etc.) we hold no data — skip static/DDNS
          // lookups entirely. For ANY, typeFilter is undefined but we still want all records.
          const doStaticLookup = typeFilter !== undefined || qtype === Packet.TYPE.ANY;

          // CNAME takes precedence over all other types (RFC 1034 §3.6.2) — must be returned
          // regardless of the query type. Check exact name first, then wildcard fallback.
          // Apex excluded: CNAME cannot coexist with SOA/NS (RFC 1034 §3.6.2).
          // Wildcard excluded for multi-label subdomains: RFC 4592 §2.1 — * matches exactly
          // one label, so *.example.com does NOT match foo.bar.example.com.
          const namesToCheck = subdomain !== '@'
            ? (subdomain.includes('.') ? [subdomain] : [subdomain, '*'])
            : [];
          let cnameDone = false;
          for (const checkName of namesToCheck) {
            const cnameRecord = db.prepare(`
              SELECT * FROM zone_static_records
              WHERE zone_id = ? AND LOWER(name) = LOWER(?) AND type = 'CNAME'
            `).get(matchedZone.id, checkName);
            if (cnameRecord) {
              response.answers.push({
                name: nameToLookup,
                type: Packet.TYPE.CNAME,
                class: Packet.CLASS.IN,
                ttl: cnameRecord.ttl,
                domain: cnameRecord.value,
              });
              cnameDone = true;
              break;
            }
          }

          if (!cnameDone && doStaticLookup) {
            // Type-filtered static lookup; wildcard fallback if exact name returns nothing
            let staticRecords = db.prepare(`
              SELECT * FROM zone_static_records
              WHERE zone_id = ? AND LOWER(name) = LOWER(?)
              ${typeFilter ? "AND type = ?" : ""}
            `).all(...(typeFilter ? [matchedZone.id, subdomain, typeFilter] : [matchedZone.id, subdomain]));

            // Wildcard fallback — only for single-label subdomains (RFC 4592 §2.1)
            if (staticRecords.length === 0 && subdomain !== '@' && !subdomain.includes('.')) {
              staticRecords = db.prepare(`
                SELECT * FROM zone_static_records
                WHERE zone_id = ? AND name = '*'
                ${typeFilter ? "AND type = ?" : ""}
              `).all(...(typeFilter ? [matchedZone.id, typeFilter] : [matchedZone.id]));
            }

            const mxExchanges = new Set();
            for (const rec of staticRecords) {
              const entry = { name: nameToLookup, class: Packet.CLASS.IN, ttl: rec.ttl };
              if (rec.type === 'A') { entry.type = Packet.TYPE.A; entry.address = rec.value; }
              else if (rec.type === 'AAAA') { entry.type = Packet.TYPE.AAAA; entry.address = rec.value; }
              else if (rec.type === 'MX') { entry.type = Packet.TYPE.MX; entry.exchange = rec.value; entry.priority = rec.priority || 10; mxExchanges.add(rec.value); }
              else if (rec.type === 'TXT') { entry.type = Packet.TYPE.TXT; entry.data = rec.value; }
              if (entry.type !== undefined) response.answers.push(entry);
            }
            // Additional section: A/AAAA hints for MX exchange hosts (RFC 1035 §3.3.9 SHOULD)
            for (const exchange of mxExchanges) {
              for (const additional of lookupAdditional(db, zones, exchange)) {
                if (!response.additionals.some(a => a.name === additional.name && a.type === additional.type && a.address === additional.address)) {
                  response.additionals.push(additional);
                }
              }
            }

            // DDNS A record lookup — skip if a static A record was already found
            if (subdomain && subdomain !== '@' && (qtype === Packet.TYPE.A || qtype === Packet.TYPE.ANY)
                && !response.answers.some(a => a.type === Packet.TYPE.A)) {
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

            // DDNS AAAA record lookup — skip if a static AAAA record was already found
            if (subdomain && subdomain !== '@' && (qtype === Packet.TYPE.AAAA || qtype === Packet.TYPE.ANY)
                && !response.answers.some(a => a.type === Packet.TYPE.AAAA)) {
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
        }

        // Negative response handling (RFC 2308) — fires when this question produced no answers
        if (response.answers.length === answerCountBefore) {
          // Distinguish NXDOMAIN (name doesn't exist) from NODATA (name exists, wrong type).
          // The apex always exists; for subdomains, check both record tables.
          const nameExists = subdomain === '@' || !!db.prepare(`
            SELECT 1 FROM zone_static_records WHERE zone_id = ? AND LOWER(name) = LOWER(?)
            UNION ALL
            SELECT 1 FROM ddns_records WHERE zone_id = ? AND LOWER(subdomain) = LOWER(?) AND is_enabled = 1
            LIMIT 1
          `).get(matchedZone.id, subdomain, matchedZone.id, subdomain);

          if (!nameExists) response.header.rcode = RCODE.NXDOMAIN;

          // SOA in authority for all negative responses (NXDOMAIN and NODATA)
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
    }
  } catch (err) {
    console.error('[dns] unhandled error:', err.message);
    response.header.rcode = RCODE.SERVFAIL;
    response.answers = [];
    response.authorities = [];
    response.additionals = [];
  }

  // KNOWN LIMITATION — UDP truncation (TC bit) and EDNS(0) are not implemented.
  // dns2 does not expose the encoded wire size before sending, and does not parse
  // OPT records from requests. Responses that exceed 512 bytes over UDP are sent
  // as-is without setting TC=1; clients will not know to retry over TCP.
  // In practice this only affects zones with many MX records or long TXT records.
  // TCP is enabled, so manual retries over TCP work correctly.
  // See: RFC 1035 §4.2.1 (truncation), RFC 6891 (EDNS).
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
