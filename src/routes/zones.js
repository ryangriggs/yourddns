'use strict';

const { Resolver } = require('dns').promises;
const { getDb, getSetting } = require('../db/index');

async function validateNs(domain, zoneType, nsPrimary, nsSecondary) {
  const resolver = new Resolver();
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  let nsRecords;
  try {
    nsRecords = await resolver.resolveNs(domain);
  } catch (e) {
    return { valid: false, error: `Could not look up NS records for ${domain}. DNS changes may not have propagated yet.` };
  }

  const normalized = nsRecords.map(ns => ns.toLowerCase().replace(/\.$/, ''));
  const primary = nsPrimary.toLowerCase().replace(/\.$/, '');
  const secondary = nsSecondary.toLowerCase().replace(/\.$/, '');

  if (zoneType === 'full') {
    if (!normalized.includes(primary) || !normalized.includes(secondary)) {
      return { valid: false, error: `Both ${nsPrimary} and ${nsSecondary} must be set as nameservers for ${domain}. Found: ${nsRecords.join(', ') || 'none'}` };
    }
  } else {
    if (!normalized.includes(primary) && !normalized.includes(secondary)) {
      return { valid: false, error: `At least one of ${nsPrimary} or ${nsSecondary} must be set as an NS record for ${domain}. Found: ${nsRecords.join(', ') || 'none'}` };
    }
  }

  return { valid: true };
}

function normalizeDomain(raw) {
  return (raw || '').trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/$/, '')
    .replace(/\.$/, '');
}

function isValidDomain(domain) {
  const labelRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^[a-z0-9]$/;
  const parts = domain.split('.');
  if (parts.length < 2) return false;
  return parts.every(p => p.length > 0 && p.length <= 63 && labelRe.test(p));
}

// Validate a static DNS record before insert. Returns null on success, error string on failure.
function validateStaticRecord(name, type, value, priority) {
  // Name validation
  const trimmedName = (name || '').trim();
  if (!trimmedName) return 'Name is required.';
  if (trimmedName.endsWith('.')) return 'Name must not end with a dot. Enter a relative label (e.g. "www" or "@"), not a fully-qualified name.';

  const isApex = trimmedName === '@';

  // Validate each label of the name (allow wildcard '*' as first label)
  if (!isApex) {
    const labelRe = /^[a-z0-9*]([a-z0-9-]*[a-z0-9])?$|^[a-z0-9*]$/i;
    const labels = trimmedName.split('.');
    for (const label of labels) {
      if (label === '*') continue; // wildcard label
      if (label.length === 0 || label.length > 63 || !labelRe.test(label)) {
        return `Invalid name label: "${label}". Use alphanumeric characters and hyphens only.`;
      }
    }
  }

  const trimmedValue = (value || '').trim();
  if (!trimmedValue) return 'Value is required.';

  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(trimmedValue) &&
    trimmedValue.split('.').every(n => parseInt(n, 10) <= 255);
  const isIPv6 = /^[0-9a-f:]+$/i.test(trimmedValue) && trimmedValue.includes(':');
  const isHostname = (h) => {
    const clean = h.replace(/\.$/, '');
    if (!clean) return false;
    const labelRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$|^[a-z0-9]$/i;
    return clean.split('.').every(l => l.length > 0 && l.length <= 63 && labelRe.test(l));
  };

  if (type === 'A') {
    if (!isIPv4) return 'A record value must be a valid IPv4 address (e.g. 1.2.3.4).';
  } else if (type === 'AAAA') {
    if (!isIPv6) return 'AAAA record value must be a valid IPv6 address.';
  } else if (type === 'CNAME') {
    if (isApex) return 'CNAME records cannot be set at the zone apex (@).';
    if (isIPv4 || isIPv6) return 'CNAME record value must be a hostname, not an IP address.';
    if (!isHostname(trimmedValue)) return 'CNAME record value must be a valid hostname (e.g. target.example.com).';
  } else if (type === 'MX') {
    if (isIPv4 || isIPv6) return 'MX record value must be a hostname (mail server name), not an IP address.';
    if (!isHostname(trimmedValue)) return 'MX record value must be a valid hostname (e.g. mail.example.com).';
    const prio = parseInt(priority, 10);
    if (priority !== undefined && priority !== null && priority !== '' && (isNaN(prio) || prio < 0 || prio > 65535)) {
      return 'MX priority must be a number between 0 and 65535.';
    }
  } else if (type === 'TXT') {
    if (trimmedValue.length > 65535) return 'TXT record value is too long.';
  } else {
    return `Unsupported record type: ${type}.`;
  }

  return null; // valid
}

module.exports = async function zonesRoutes(fastify) {
  fastify.addHook('preHandler', fastify.requireAuth);

  // GET /dashboard/zones
  fastify.get('/dashboard/zones', async (req, reply) => {
    const db = getDb();
    const zones = db.prepare(`
      SELECT z.*,
        (SELECT COUNT(*) FROM zone_static_records WHERE zone_id = z.id) as static_count,
        (SELECT COUNT(*) FROM ddns_records WHERE zone_id = z.id AND user_id = ?) as ddns_count
      FROM zones z
      WHERE z.user_id = ?
      ORDER BY z.validated DESC, z.created_at DESC
    `).all(req.user.id, req.user.id);

    const nsPrimary = getSetting('ns_primary') || 'ns1.yourddns.com';
    const nsSecondary = getSetting('ns_secondary') || 'ns2.yourddns.com';
    const flash = req.session.flash;
    delete req.session.flash;

    return reply.view('dashboard/zones.njk', {
      title: 'My Domains',
      zones,
      nsPrimary,
      nsSecondary,
      flash,
      tier: { max_custom_domains: req.user.max_custom_domains || 0 },
    });
  });

  // POST /dashboard/zones — add new zone
  fastify.post('/dashboard/zones', async (req, reply) => {
    const db = getDb();
    const { domain: rawDomain, zone_type } = req.body || {};
    const domain = normalizeDomain(rawDomain);
    const zoneType = zone_type === 'subdomain' ? 'subdomain' : 'full';

    if (!domain || !isValidDomain(domain)) {
      req.session.flash = { type: 'error', message: 'Invalid domain name.' };
      return reply.redirect('/dashboard/zones');
    }

    const maxCustom = req.user.max_custom_domains || 0;
    if (maxCustom === 0) {
      req.session.flash = { type: 'error', message: 'Your plan does not include custom domains. Please upgrade.' };
      return reply.redirect('/dashboard/zones');
    }

    const count = db.prepare('SELECT COUNT(*) as c FROM zones WHERE user_id = ?').get(req.user.id).c;
    if (count >= maxCustom) {
      req.session.flash = { type: 'error', message: `Your plan allows up to ${maxCustom} custom domain(s).` };
      return reply.redirect('/dashboard/zones');
    }

    // Check if this domain already exists in any state
    const existingZone = db.prepare('SELECT id, user_id, validated FROM zones WHERE LOWER(domain) = ?').get(domain);
    if (existingZone) {
      if (existingZone.user_id === req.user.id) {
        // User already has it — redirect to it
        return reply.redirect(`/dashboard/zones/${existingZone.id}`);
      }
      if (existingZone.validated || existingZone.user_id === null) {
        req.session.flash = { type: 'error', message: 'That domain is already in use.' };
      } else {
        req.session.flash = { type: 'error', message: 'That domain is already pending validation by another user.' };
      }
      return reply.redirect('/dashboard/zones');
    }

    const nsPrimary = getSetting('ns_primary') || 'ns1.yourddns.com';
    const nsSecondary = getSetting('ns_secondary') || 'ns2.yourddns.com';
    const nsHostnames = JSON.stringify([nsPrimary, nsSecondary]);

    db.prepare(`
      INSERT INTO zones (domain, display_name, ns_hostnames, soa_email, user_id, validated, zone_type, is_active)
      VALUES (?, ?, ?, ?, ?, 0, ?, 1)
    `).run(domain, domain, nsHostnames, `hostmaster@${domain}`, req.user.id, zoneType);

    const newZone = db.prepare('SELECT id FROM zones WHERE LOWER(domain) = ? AND user_id = ?').get(domain, req.user.id);
    req.session.flash = { type: 'success', message: 'Domain added. Follow the instructions below, then click Validate.' };
    return reply.redirect(`/dashboard/zones/${newZone.id}`);
  });

  // GET /dashboard/zones/:id — zone detail
  fastify.get('/dashboard/zones/:id', async (req, reply) => {
    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!zone) return reply.code(404).view('errors/404.njk', { title: '404 Not Found' });

    const staticRecords = db.prepare('SELECT * FROM zone_static_records WHERE zone_id = ? ORDER BY type, name').all(zone.id);
    const nsPrimary = getSetting('ns_primary') || 'ns1.yourddns.com';
    const nsSecondary = getSetting('ns_secondary') || 'ns2.yourddns.com';
    const siteIp = getSetting('site_ip') || '';
    const siteDomain = getSetting('site_domain') || '';
    const hasApexA = staticRecords.some(r => r.name === '@' && r.type === 'A');
    const flash = req.session.flash;
    delete req.session.flash;

    return reply.view('dashboard/zone-detail.njk', {
      title: zone.domain,
      zone,
      staticRecords,
      nsPrimary,
      nsSecondary,
      hasApexA,
      siteIp,
      siteDomain,
      flash,
    });
  });

  // POST /dashboard/zones/:id/validate
  fastify.post('/dashboard/zones/:id/validate', async (req, reply) => {
    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!zone) return reply.code(404).send('Not found');

    if (zone.validated) {
      req.session.flash = { type: 'success', message: 'Domain is already validated.' };
      return reply.redirect(`/dashboard/zones/${zone.id}`);
    }

    // Check if domain was claimed while pending
    const claimed = db.prepare('SELECT id FROM zones WHERE LOWER(domain) = ? AND validated = 1 AND id != ?').get(zone.domain.toLowerCase(), zone.id);
    if (claimed) {
      db.prepare('DELETE FROM zones WHERE id = ?').run(zone.id);
      req.session.flash = { type: 'error', message: 'This domain has been validated by another user. Your pending entry has been removed.' };
      return reply.redirect('/dashboard/zones');
    }

    const nsPrimary = getSetting('ns_primary') || 'ns1.yourddns.com';
    const nsSecondary = getSetting('ns_secondary') || 'ns2.yourddns.com';

    const result = await validateNs(zone.domain, zone.zone_type, nsPrimary, nsSecondary);
    if (!result.valid) {
      req.session.flash = { type: 'error', message: result.error };
      return reply.redirect(`/dashboard/zones/${zone.id}`);
    }

    db.prepare('UPDATE zones SET validated = 1, is_active = 1 WHERE id = ?').run(zone.id);
    // Remove other users' pending claims on the same domain
    db.prepare('DELETE FROM zones WHERE LOWER(domain) = ? AND user_id != ? AND validated = 0').run(zone.domain.toLowerCase(), req.user.id);

    // Auto-add apex A record if site_ip is configured and no A record exists yet
    const siteIp = getSetting('site_ip') || '';
    if (siteIp) {
      db.prepare('INSERT OR IGNORE INTO zone_static_records (zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)').run(zone.id, '@', 'A', siteIp, 300);
    }

    req.session.flash = { type: 'success', message: `${zone.domain} has been validated and is now active.` };
    return reply.redirect(`/dashboard/zones/${zone.id}`);
  });

  // POST /dashboard/zones/:id/delete
  fastify.post('/dashboard/zones/:id/delete', async (req, reply) => {
    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!zone) return reply.code(404).send('Not found');

    db.prepare('DELETE FROM ddns_records WHERE zone_id = ? AND user_id = ?').run(zone.id, req.user.id);
    db.prepare('DELETE FROM zones WHERE id = ?').run(zone.id);

    req.session.flash = { type: 'success', message: `${zone.domain} and all its records have been deleted.` };
    return reply.redirect('/dashboard/zones');
  });

  // POST /dashboard/zones/:id/add-apex-a
  fastify.post('/dashboard/zones/:id/add-apex-a', async (req, reply) => {
    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ? AND validated = 1').get(req.params.id, req.user.id);
    if (!zone) return reply.code(404).send('Not found');
    const siteIp = getSetting('site_ip') || '';
    if (!siteIp) {
      req.session.flash = { type: 'error', message: 'Server IP is not configured. Contact support.' };
      return reply.redirect(`/dashboard/zones/${zone.id}`);
    }
    db.prepare('INSERT OR IGNORE INTO zone_static_records (zone_id, name, type, value, ttl) VALUES (?, ?, ?, ?, ?)').run(zone.id, '@', 'A', siteIp, 300);
    db.prepare('UPDATE zones SET soa_serial = soa_serial + 1 WHERE id = ?').run(zone.id);
    req.session.flash = { type: 'success', message: 'A record added.' };
    return reply.redirect(`/dashboard/zones/${zone.id}`);
  });

  // POST /dashboard/zones/:id/records — add static record
  fastify.post('/dashboard/zones/:id/records', async (req, reply) => {
    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ? AND validated = 1').get(req.params.id, req.user.id);
    if (!zone) return reply.code(404).send('Not found');

    const { name, type, value, ttl, priority } = req.body || {};
    const allowedTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT'];
    if (!name || !type || !value || !allowedTypes.includes(type)) {
      req.session.flash = { type: 'error', message: 'Name, type, and value are required.' };
      return reply.redirect(`/dashboard/zones/${zone.id}`);
    }

    const validationError = validateStaticRecord(name, type, value, priority);
    if (validationError) {
      req.session.flash = { type: 'error', message: validationError };
      return reply.redirect(`/dashboard/zones/${zone.id}`);
    }

    db.prepare('INSERT INTO zone_static_records (zone_id, name, type, value, ttl, priority) VALUES (?, ?, ?, ?, ?, ?)').run(
      zone.id, name.trim(), type, value.trim(), parseInt(ttl || 300, 10), priority ? parseInt(priority, 10) : null
    );
    db.prepare('UPDATE zones SET soa_serial = soa_serial + 1 WHERE id = ?').run(zone.id);

    req.session.flash = { type: 'success', message: 'Record added.' };
    return reply.redirect(`/dashboard/zones/${zone.id}`);
  });

  // POST /dashboard/zones/:id/records/:rid/delete
  fastify.post('/dashboard/zones/:id/records/:rid/delete', async (req, reply) => {
    const db = getDb();
    const zone = db.prepare('SELECT * FROM zones WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
    if (!zone) return reply.code(404).send('Not found');

    db.prepare('DELETE FROM zone_static_records WHERE id = ? AND zone_id = ?').run(req.params.rid, zone.id);
    db.prepare('UPDATE zones SET soa_serial = soa_serial + 1 WHERE id = ?').run(zone.id);
    req.session.flash = { type: 'success', message: 'Record deleted.' };
    return reply.redirect(`/dashboard/zones/${zone.id}`);
  });
};

module.exports.validateStaticRecord = validateStaticRecord;
