'use strict';

const fp = require('fastify-plugin');
const { getDb } = require('../db/index');

async function authPlugin(fastify) {
  fastify.decorateRequest('user', null);

  fastify.addHook('preHandler', async (req, reply) => {
    const session = req.session;
    if (!session || !session.userId) return;

    const db = getDb();
    const userId = session.impersonatingUserId || session.userId;
    const user = db.prepare(`
      SELECT u.*, t.name as tier_name, t.display_name as tier_display_name,
             t.max_entries, t.min_ttl, t.max_resolutions_per_hour, t.max_updates_per_hour,
             t.min_subdomain_length, t.history_days
      FROM users u
      JOIN tiers t ON t.id = u.tier_id
      WHERE u.id = ? AND u.is_disabled = 0
    `).get(userId);

    if (user) {
      req.user = user;
      req.user.isImpersonated = !!session.impersonatingUserId;
      req.user.realUserId = session.userId;
    }
  });

  fastify.decorate('requireAuth', async function (req, reply) {
    if (!req.user) return reply.redirect('/auth/login');
  });

  fastify.decorate('requireAdmin', async function (req, reply) {
    if (!req.user) return reply.redirect('/auth/login');
    const db = getDb();
    const realUser = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
    if (!realUser || !realUser.is_admin) return reply.code(403).send('Forbidden');
  });
}

module.exports = fp(authPlugin);
