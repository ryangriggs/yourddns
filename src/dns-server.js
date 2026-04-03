'use strict';

const dns2 = require('dns2');
const { Packet } = dns2;

// dns2 does not export RCODE constants — use raw values
const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };
// BADVERS (16) cannot fit in the 4-bit header RCODE; it is encoded via extended RCODE
// in the OPT record TTL field (upper 8 bits = 1). See RFC 6891 §6.1.3 and buildBadvers().

// EDNS(0) — RFC 6891
// OPT record type value (decimal 41)
const EDNS_TYPE = Packet.TYPE.EDNS; // 0x29
// Maximum UDP payload size we advertise in our OPT record.
// 4096 is the conventional value used by BIND, Unbound, etc.
const EDNS_ADVERTISED_UDP = 4096;
// RFC 1035 §4.2.1 hard limit for clients that send no EDNS OPT record.
const LEGACY_UDP_MAX = 512;

// IXFR (RFC 1995) is not defined by dns2.
const IXFR_TYPE = 251;

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

// Build an OPT record for BADVERS (RCODE 16, RFC 6891 §6.1.3).
// RCODE 16 doesn't fit in the 4-bit DNS header rcode field.
// Encoding: header.rcode = 0 (lower 4 bits of 16), OPT TTL upper 8 bits = 1.
function buildBadversOpt() {
  return { name: '', type: EDNS_TYPE, class: EDNS_ADVERTISED_UDP, ttl: 0x01000000, rdata: [] };
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

// ── EDNS(0) and UDP truncation (RFC 6891, RFC 1035 §4.2.1) ───────────────────
//
// Called after the response is fully built, immediately before send().
// For TCP (rinfo is a net.Socket — has a .write() method) there is no size
// constraint; we return immediately.  For UDP we:
//   1. Read the client's EDNS OPT record (if any) to learn its announced
//      maximum UDP payload size.
//   2. Add our own OPT record to the response additionals advertising
//      EDNS_ADVERTISED_UDP bytes (RFC 6891 §7 — required when client sends OPT).
//   3. If the encoded response already fits, we're done.
//   4. Otherwise trim one record at a time from the end of each section
//      (additionals → authorities → answers), re-encoding after every removal,
//      until the response fits.  The OPT record in additionals is never removed.
//   5. Set TC=1 if any record was removed.
//
function finalizeUdpResponseFor(request, response, isUdp) {
  if (!isUdp) return; // TCP has no size constraint

  // ── Step 1: read client EDNS OPT ─────────────────────────────────────────
  const reqOpt = (request.additionals || []).find(r => r.type === EDNS_TYPE);
  // The OPT CLASS field carries the client's max UDP payload size (RFC 6891 §6.1.2).
  // Clamp to at least 512 (malformed OPT with class=0 should still behave sane).
  const clientUdpMax = reqOpt ? Math.max(reqOpt.class || 0, LEGACY_UDP_MAX) : LEGACY_UDP_MAX;
  const limit = Math.min(clientUdpMax, EDNS_ADVERTISED_UDP);

  // ── Step 2: add OPT to our response (RFC 6891 §7) ────────────────────────
  // Only when the client sent an OPT — legacy clients that sent no OPT must not
  // receive one in the response (RFC 6891 §7: "SHOULD add ... if and only if ...").
  if (reqOpt) {
    response.additionals.push({
      name  : '',              // OPT owner name is always root (empty)
      type  : EDNS_TYPE,       // 41
      class : EDNS_ADVERTISED_UDP, // our max UDP payload size
      ttl   : 0,               // extended RCODE (0) and flags (0) — DNSSEC DO=0
      rdata : [],              // no EDNS options in this response
    });
  }

  // ── Step 3: check if it already fits ─────────────────────────────────────
  if (response.toBuffer().length <= limit) return;

  // ── Step 4: byte-accurate truncation ─────────────────────────────────────
  // Remove one record at a time from the end, re-check after each removal.
  // OPT in additionals is never removed (it must accompany every EDNS response).
  // Order: additionals (non-OPT) → authorities → answers.
  const sections = ['additionals', 'authorities', 'answers'];

  for (const section of sections) {
    let i = response[section].length - 1;
    while (i >= 0) {
      // Never remove the OPT record we just added to additionals.
      if (response[section][i].type === EDNS_TYPE) { i--; continue; }
      response[section].splice(i, 1);
      if (response.toBuffer().length <= limit) {
        response.header.tc = 1;
        return;
      }
      i--;
    }
  }

  // ── Step 5: couldn't fit even with empty sections — set TC and send bare ─
  // This is theoretically possible only with a pathologically large single
  // record (e.g. a 4000-byte TXT) sent to a non-EDNS legacy client.
  response.header.tc = 1;
}

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
  // net.Socket (TCP) has a .write() method; plain UDP rinfo objects do not.
  const isUdp = !(rinfo && typeof rinfo.write === 'function');

  try {
    // Silently drop DNS response messages — RFC 1035 §4.1.1 (QR=1 means response, not query)
    if (request.header.qr === 1) { return; }

    // EDNS(0) validation — RFC 6891
    const ednsOpts = (request.additionals || []).filter(r => r.type === EDNS_TYPE);
    if (ednsOpts.length > 1) {
      // RFC 6891 §6.1.1: at most one OPT record per message
      response.header.rcode = RCODE.FORMERR;
    } else if (ednsOpts.length === 1) {
      const ednsVersion = (ednsOpts[0].ttl >>> 16) & 0xFF;
      if (ednsVersion !== 0) {
        // RFC 6891 §6.1.3: unsupported EDNS version → BADVERS (RCODE 16)
        response.header.rcode = 0; // lower 4 bits of RCODE 16
        response.additionals.push(buildBadversOpt());
        send(response);
        return; // bypass normal zone processing
      }
    }

    if (response.header.rcode !== RCODE.NOERROR) {
      // Already set to FORMERR above — fall through to send
    } else if (clientIp && isBlocked(db, clientIp)) {
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

        // AXFR and IXFR are zone transfer requests — refuse them (RFC 5936 §2.2, RFC 1995)
        if (qtype === Packet.TYPE.AXFR || qtype === IXFR_TYPE) {
          response.header.rcode = RCODE.REFUSED;
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
        // Hoisted here so the negative-response block below (outside the subdomain !== null block)
        // can access it without a second DB query. Default true so apex-only queries (SOA/NS)
        // that skip the subdomain block are treated as NODATA rather than NXDOMAIN.
        let exactNameExists = true;

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

          // Determine up-front whether this exact name has any records at all.
          // Used for two purposes:
          //   1. Wildcard suppression — RFC 4592 §4.3.3: if a name has ANY explicit record
          //      (regardless of type), wildcards must not apply to it.
          //   2. NXDOMAIN vs NODATA distinction at the bottom of this question's processing.
          exactNameExists = subdomain === '@' || !!db.prepare(`
            SELECT 1 FROM zone_static_records WHERE zone_id = ? AND LOWER(name) = LOWER(?)
            UNION ALL
            SELECT 1 FROM ddns_records WHERE zone_id = ? AND LOWER(subdomain) = LOWER(?) AND is_enabled = 1
            LIMIT 1
          `).get(matchedZone.id, subdomain, matchedZone.id, subdomain);

          // CNAME takes precedence over all other types (RFC 1034 §3.6.2) — must be returned
          // regardless of the query type. Check exact name first, then wildcard fallback.
          // Apex excluded: CNAME cannot coexist with SOA/NS (RFC 1034 §3.6.2).
          // Wildcard: RFC 4592 §2.1 — strip the first label and prepend *, so x.test tries
          // *.test (not *). This means * matches x but not x.test; *.test matches x.test
          // but not x.y.test. Each subdomain depth has its own wildcard.
          // Wildcard suppressed when exact name has any records (RFC 4592 §4.3.3).
          const wildcardName = subdomain.includes('.')
            ? '*.' + subdomain.slice(subdomain.indexOf('.') + 1)
            : '*';
          const namesToCheck = subdomain !== '@'
            ? (exactNameExists ? [subdomain] : [subdomain, wildcardName])
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

            // Wildcard fallback (RFC 4592 §2.1 + §4.3.3): strip the first label and prepend *.
            // x      → *        x.test  → *.test        x.y.test → *.y.test
            // Suppressed when the exact name already has records of any type (§4.3.3).
            if (staticRecords.length === 0 && subdomain !== '@' && !exactNameExists) {
              staticRecords = db.prepare(`
                SELECT * FROM zone_static_records
                WHERE zone_id = ? AND LOWER(name) = LOWER(?)
                ${typeFilter ? "AND type = ?" : ""}
              `).all(...(typeFilter ? [matchedZone.id, wildcardName, typeFilter] : [matchedZone.id, wildcardName]));
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
                  name: nameToLookup,
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
                  name: nameToLookup,
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
          // exactNameExists was computed above; reuse it here to avoid a second DB query.
          if (!exactNameExists) response.header.rcode = RCODE.NXDOMAIN;

          // SOA in authority for all negative responses (NXDOMAIN and NODATA)
          const soa = buildSoa(matchedZone);
          response.authorities.push({
            name: matchedZone.domain,
            type: Packet.TYPE.SOA,
            class: Packet.CLASS.IN,
            ttl: soa.minimum, // RFC 2308 §3: negative cache TTL is capped by SOA minimum
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
    console.error('[dns] unhandled error:', err.stack || err.message);
    response.header.rcode = RCODE.SERVFAIL;
    response.header.aa = 0; // RFC 2181 §5.2: SERVFAIL is not authoritative
    response.answers = [];
    response.authorities = [];
    response.additionals = [];
  }

  // Apply EDNS(0) OPT response record and UDP truncation (RFC 6891, RFC 1035 §4.2.1).
  // For TCP responses this is a no-op.  For UDP it reads the client OPT (if any),
  // adds our OPT advertising EDNS_ADVERTISED_UDP bytes, then trims and sets TC=1
  // if the encoded response exceeds the negotiated limit.
  finalizeUdpResponseFor(request, response, isUdp);
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
