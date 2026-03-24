'use strict';

const { getDb } = require('../db/index');

module.exports = async function reportsRoutes(fastify) {
  fastify.addHook('preHandler', fastify.requireAuth);

  // GET /reports
  fastify.get('/reports', async (req, reply) => {
    const db = getDb();
    const records = db.prepare(`
      SELECT r.id, r.subdomain, z.domain as zone_domain
      FROM ddns_records r
      JOIN zones z ON z.id = r.zone_id
      WHERE r.user_id = ?
      ORDER BY r.subdomain
    `).all(req.user.id);

    return reply.view('reports/index.njk', { title: 'Reports', records });
  });

  // GET /reports/data — JSON API for chart
  fastify.get('/reports/data', async (req, reply) => {
    const db = getDb();
    const { records: recordIds, from, to } = req.query || {};

    if (!recordIds) return reply.send({ datasets: [] });
    const ids = (Array.isArray(recordIds) ? recordIds : [recordIds]).map(Number).filter(Boolean);
    if (!ids.length) return reply.send({ datasets: [] });

    // Verify ownership
    const owned = db.prepare(`
      SELECT id FROM ddns_records WHERE id IN (${ids.map(() => '?').join(',')}) AND user_id = ?
    `).all(...ids, req.user.id).map(r => r.id);

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
