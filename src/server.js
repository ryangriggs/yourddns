'use strict';

require('dotenv').config();

const path = require('path');
const fastify = require('fastify')({
  logger: { level: process.env.NODE_ENV === 'production' ? 'warn' : 'info' },
  trustProxy: true,  // trust X-Forwarded-For from nginx
});
const nunjucks = require('nunjucks');
const { initDb, getDb, getSetting } = require('./db/index');
const { startDnsServer } = require('./dns-server');
const SQLiteSessionStore = require('./plugins/session-store');
const { startMaintenanceJob } = require('./services/maintenance');

async function build() {
  // ── Plugins ──────────────────────────────────────────────────────────────
  await fastify.register(require('@fastify/helmet'), {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'cdn.jsdelivr.net'],
        styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'cdn.jsdelivr.net'],
        fontSrc: ["'self'", 'fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        scriptSrcAttr: ["'unsafe-inline'"],
      },
    },
  });

  await fastify.register(require('@fastify/static'), {
    root: path.join(__dirname, '..', 'public'),
    prefix: '/public/',
  });

  await fastify.register(require('@fastify/formbody'));

  await fastify.register(require('@fastify/cookie'));

  await fastify.register(require('@fastify/session'), {
    cookieName: 'sid',
    secret: process.env.SESSION_SECRET || 'default-secret-change-this-in-production-min32chars!!',
    store: new SQLiteSessionStore(getDb()),
    saveUninitialized: false,
    cookie: {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
    },
  });

  // Nunjucks setup
  const viewsPath = path.join(__dirname, 'views');

  await fastify.register(require('@fastify/view'), {
    engine: { nunjucks },
    root: viewsPath,
    options: {
      autoescape: true,
      noCache: process.env.NODE_ENV !== 'production',
      onConfigure: (env) => {
        env.addFilter('date', (val, fmt) => {
          if (!val) return '—';
          const d = new Date(val);
          if (isNaN(d)) return val;
          if (fmt === 'relative') {
            const diff = Date.now() - d.getTime();
            const mins = Math.floor(diff / 60000);
            if (mins < 1) return 'just now';
            if (mins < 60) return `${mins}m ago`;
            const hrs = Math.floor(mins / 60);
            if (hrs < 24) return `${hrs}h ago`;
            const days = Math.floor(hrs / 24);
            return `${days}d ago`;
          }
          return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
        });
        env.addFilter('json', (val) => new nunjucks.runtime.SafeString(JSON.stringify(val)));
      },
    },
    defaultContext: {},
  });

  await fastify.register(require('@fastify/rate-limit'), {
    global: false,
  });

  // Auth plugin
  await fastify.register(require('./plugins/auth'));

  // Add per-request locals (user, siteName) available in all templates
  fastify.addHook('preHandler', async (req, reply) => {
    reply.locals = {
      user: req.user || null,
      siteName: getSetting('site_name') || 'YourDDNS',
      siteUrl: getSetting('site_url') || '',
    };
  });

  // ── Routes ────────────────────────────────────────────────────────────────
  fastify.get('/', async (req, reply) => {
    if (req.user) return reply.redirect('/dashboard');
    const db = getDb();
    const tiers = db.prepare("SELECT * FROM tiers ORDER BY sort_order").all();
    const newsContent = getSetting('news_content') || '';
    const registrationEnabled = getSetting('registration_enabled') !== 'false';
    return reply.view('landing.njk', { title: 'Dynamic DNS for Everyone', tiers, newsContent, registrationEnabled });
  });

  await fastify.register(require('./routes/auth'));
  await fastify.register(require('./routes/dashboard'));
  await fastify.register(require('./routes/zones'));
  await fastify.register(require('./routes/reports'));
  await fastify.register(require('./routes/admin'));
  await fastify.register(require('./routes/api'));

  // Stripe (placeholder)
  fastify.post('/stripe/webhook', {
    config: { rawBody: true },
  }, async (req, reply) => {
    // TODO: implement Stripe webhook handling
    return reply.send({ received: true });
  });

  // 404
  fastify.setNotFoundHandler(async (req, reply) => {
    return reply.code(404).view('errors/404.njk', { title: '404 Not Found' });
  });

  // Error handler
  fastify.setErrorHandler(async (err, req, reply) => {
    fastify.log.error(err);
    return reply.code(err.statusCode || 500).view('errors/500.njk', { title: 'Error', message: err.message });
  });

  return fastify;
}

async function start() {
  await initDb();
  const app = await build();
  const port = parseInt(process.env.PORT || '3000', 10);
  const host = process.env.HOST || '0.0.0.0';
  await app.listen({ port, host });
  console.log(`[web] Listening on ${host}:${port}`);
  startDnsServer();
  startMaintenanceJob();
}

start().catch(err => {
  console.error(err);
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('[app] SIGTERM received, exiting');
  process.exit(0);
});
