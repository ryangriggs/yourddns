'use strict';

const { getDb } = require('../db/index');

module.exports = async function reportsRoutes(fastify) {
  fastify.addHook('preHandler', fastify.requireAuth);

  // Redirect old /reports URL
  fastify.get('/reports', async (req, reply) => reply.redirect('/stats'));
  fastify.get('/reports/data', async (req, reply) => reply.redirect(307, '/stats/data?' + new URLSearchParams(req.query).toString()));

  // GET /stats
  fastify.get('/stats', async (req, reply) => {
    const db = getDb();
    const allRecords = db.prepare(`
      SELECT r.id, r.subdomain, z.domain as zone_domain, u.email as user_email
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      JOIN users u ON u.id = r.user_id
      WHERE r.user_id = ?
      ORDER BY r.subdomain ASC
    `).all(req.user.id);

    return reply.view('stats.njk', {
      title: 'Stats', layout: 'layouts/base.njk',
      allRecords, showUser: false, dataUrl: '/stats/data', hitsUrl: '/stats/hits',
    });
  });

  // GET /stats/hits — paginated DNS hit log for selected records (user-scoped)
  fastify.get('/stats/hits', async (req, reply) => {
    const db = getDb();
    const { records: recordIds, from, to, page = '1', per = '50' } = req.query || {};
    if (!recordIds) return reply.send({ hits: [], total: 0, page: 1, totalPages: 1 });
    const ids = (Array.isArray(recordIds) ? recordIds : [recordIds]).map(Number).filter(Boolean);
    if (!ids.length) return reply.send({ hits: [], total: 0, page: 1, totalPages: 1 });

    const owned = db.prepare(
      `SELECT id FROM ddns_records WHERE id IN (${ids.map(() => '?').join(',')}) AND user_id = ?`
    ).all(...ids, req.user.id).map(r => r.id);
    if (!owned.length) return reply.send({ hits: [], total: 0, page: 1, totalPages: 1 });

    const fromDate = from || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const toDate = to || new Date().toISOString().split('T')[0];
    const perPage = Math.min(Math.max(parseInt(per) || 50, 1), 500);
    const pageNum = Math.max(1, parseInt(page) || 1);
    const offset = (pageNum - 1) * perPage;
    const inClause = owned.map(() => '?').join(',');

    const total = db.prepare(
      `SELECT COUNT(*) as c FROM dns_hits WHERE record_id IN (${inClause}) AND date(queried_at) >= ? AND date(queried_at) <= ?`
    ).get(...owned, fromDate, toDate).c;

    const hits = db.prepare(`
      SELECT h.id, h.queried_at, h.query_type, h.client_ip,
             r.subdomain, z.domain as zone_domain
      FROM dns_hits h
      JOIN ddns_records r ON r.id = h.record_id
      JOIN zones z ON z.id = r.zone_id
      WHERE h.record_id IN (${inClause}) AND date(h.queried_at) >= ? AND date(h.queried_at) <= ?
      ORDER BY h.queried_at DESC LIMIT ? OFFSET ?
    `).all(...owned, fromDate, toDate, perPage, offset);

    return reply.send({ hits, total, page: pageNum, totalPages: Math.max(1, Math.ceil(total / perPage)) });
  });

  // GET /stats/data — JSON chart data (user-scoped)
  fastify.get('/stats/data', async (req, reply) => {
    const db = getDb();
    const { records: recordIds, from, to } = req.query || {};

    if (!recordIds) return reply.send({ datasets: [] });
    const ids = (Array.isArray(recordIds) ? recordIds : [recordIds]).map(Number).filter(Boolean);
    if (!ids.length) return reply.send({ datasets: [] });

    // Verify ownership
    const owned = db.prepare(
      `SELECT id FROM ddns_records WHERE id IN (${ids.map(() => '?').join(',')}) AND user_id = ?`
    ).all(...ids, req.user.id).map(r => r.id);

    if (!owned.length) return reply.send({ datasets: [] });

    const fromDate = from || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const toDate = to || new Date().toISOString().split('T')[0];

    const datasets = [];
    for (const id of owned) {
      const record = db.prepare('SELECT r.subdomain, z.domain as zone_domain FROM ddns_records r JOIN zones z ON z.id = r.zone_id WHERE r.id = ?').get(id);
      if (!record) continue;
      const hits = db.prepare(`
        SELECT date(queried_at) as day, COUNT(*) as count
        FROM dns_hits
        WHERE record_id = ? AND date(queried_at) >= ? AND date(queried_at) <= ?
        GROUP BY day ORDER BY day
      `).all(id, fromDate, toDate);
      datasets.push({ id, label: `${record.subdomain}.${record.zone_domain}`, data: hits });
    }

    return reply.send({ datasets, from: fromDate, to: toDate });
  });
};
