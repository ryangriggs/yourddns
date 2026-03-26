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
    const { sort = 'subdomain', dir = 'asc', page = '1', per = '50' } = req.query || {};
    const validSorts = { subdomain: 'r.subdomain', zone: 'z.domain', ip: 'r.ip_address', hits: 'r.hit_count', updated: 'r.last_update_received_at' };
    const sortCol = validSorts[sort] || 'r.subdomain';
    const sortDir = dir === 'desc' ? 'DESC' : 'ASC';
    const perPage = [10, 50, 100, 500].includes(Number(per)) ? Number(per) : 50;
    const pageNum = Math.max(1, parseInt(page) || 1);
    const offset = (pageNum - 1) * perPage;

    const total = db.prepare('SELECT COUNT(*) as c FROM ddns_records WHERE user_id = ?').get(req.user.id).c;
    const totalPages = Math.max(1, Math.ceil(total / perPage));

    const records = db.prepare(`
      SELECT r.id, r.subdomain, r.ip_address, r.ip6_address, r.hit_count, r.last_update_received_at,
             z.domain as zone_domain, u.email as user_email
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      JOIN users u ON u.id = r.user_id
      WHERE r.user_id = ?
      ORDER BY ${sortCol} ${sortDir} LIMIT ? OFFSET ?
    `).all(req.user.id, perPage, offset);

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
      records, allRecords, sort, dir, page: pageNum, per: perPage, total, totalPages,
      showUser: false, dataUrl: '/stats/data',
    });
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
