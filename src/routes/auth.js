'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb, getSetting } = require('../db/index');
const { sendVerificationEmail, sendPasswordResetEmail, sendOtpEmail } = require('../services/email');

// Only allow relative redirects — prevents open redirect via returnTo
function isSafeRedirect(url) {
  return typeof url === 'string' && url.startsWith('/') && !url.startsWith('//') && !url.startsWith('/\\');
}

module.exports = async function authRoutes(fastify) {
  // GET /auth/login
  fastify.get('/auth/login', async (req, reply) => {
    if (req.user) return reply.redirect('/dashboard');
    return reply.view('auth/login.njk', { title: 'Sign In', error: req.query.error, message: req.query.message });
  });

  // POST /auth/login
  fastify.post('/auth/login', { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (req, reply) => {
    const { email, password } = req.body || {};
    if (!email || !password) return reply.redirect('/auth/login?error=missing');

    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email.trim());

    const maxAttempts = parseInt(getSetting('password_max_attempts_per_hour') || '10', 10);
    // Simple rate check via session counter (full rate limiting via @fastify/rate-limit on route)
    if (!user || !user.password_hash) return reply.redirect('/auth/login?error=invalid');
    if (user.is_disabled) return reply.redirect('/auth/login?error=disabled');

    // Check blocked IP
    const clientIp = req.ip;
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return reply.redirect('/auth/login?error=blocked');
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return reply.redirect('/auth/login?error=invalid');

    if (!user.email_verified) return reply.redirect('/auth/login?error=unverified&email=' + encodeURIComponent(email));

    const dest = isSafeRedirect(req.session.returnTo) ? req.session.returnTo : '/dashboard';
    await req.session.regenerate();
    req.session.userId = user.id;
    return reply.redirect(dest);
  });

  // GET /auth/register
  fastify.get('/auth/register', async (req, reply) => {
    const regEnabled = getSetting('registration_enabled');
    if (regEnabled === 'false') return reply.redirect('/auth/login?error=registration_disabled');
    if (req.user) return reply.redirect('/dashboard');
    return reply.view('auth/register.njk', { title: 'Create Account', error: req.query.error });
  });

  // POST /auth/register
  fastify.post('/auth/register', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (req, reply) => {
    const regEnabled = getSetting('registration_enabled');
    if (regEnabled === 'false') return reply.redirect('/auth/login?error=registration_disabled');

    const { email, password, password2, agree_terms } = req.body || {};
    if (!email || !password) return reply.redirect('/auth/register?error=missing');
    if (!agree_terms) return reply.redirect('/auth/register?error=terms');
    if (password !== password2) return reply.redirect('/auth/register?error=password_mismatch');
    if (password.length < 8) return reply.redirect('/auth/register?error=password_short');

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) return reply.redirect('/auth/register?error=invalid_email');

    const db = getDb();
    const clientIp = req.ip;
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return reply.redirect('/auth/register?error=blocked');
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email.trim());
    if (existing) return reply.redirect('/auth/register?error=email_taken');

    const hash = await bcrypt.hash(password, 12);
    const freeTier = db.prepare("SELECT id FROM tiers WHERE name = 'free'").get();
    const result = db.prepare('INSERT INTO users (email, password_hash, tier_id) VALUES (?, ?, ?)').run(email.trim().toLowerCase(), hash, freeTier ? freeTier.id : 1);
    const userId = Number(result.lastInsertRowid);

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO email_verifications (user_id, token, expires_at) VALUES (?, ?, ?)').run(userId, token, expires);

    await sendVerificationEmail(email.trim(), token);
    return reply.redirect('/auth/login?message=verify_email');
  });

  // GET /auth/verify-email
  fastify.get('/auth/verify-email', async (req, reply) => {
    const { token } = req.query || {};
    if (!token) return reply.redirect('/auth/login?error=invalid_token');

    const db = getDb();
    const ev = db.prepare('SELECT * FROM email_verifications WHERE token = ?').get(token);
    if (!ev) return reply.redirect('/auth/login?error=invalid_token');
    if (new Date(ev.expires_at) < new Date()) return reply.redirect('/auth/login?error=token_expired');

    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(ev.user_id);
    db.prepare('DELETE FROM email_verifications WHERE id = ?').run(ev.id);
    return reply.redirect('/auth/login?message=email_verified');
  });

  // GET /auth/resend-verification
  fastify.get('/auth/resend-verification', async (req, reply) => {
    const { email } = req.query || {};
    if (!email) return reply.redirect('/auth/login');
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE AND email_verified = 0').get(email);
    if (user) {
      db.prepare('DELETE FROM email_verifications WHERE user_id = ?').run(user.id);
      const token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      db.prepare('INSERT INTO email_verifications (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, expires);
      await sendVerificationEmail(email, token);
    }
    return reply.redirect('/auth/login?message=verify_resent');
  });

  // GET /auth/forgot-password
  fastify.get('/auth/forgot-password', async (req, reply) => {
    return reply.view('auth/forgot-password.njk', { title: 'Reset Password', message: req.query.message, error: req.query.error });
  });

  // POST /auth/forgot-password
  fastify.post('/auth/forgot-password', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (req, reply) => {
    const { email } = req.body || {};
    if (!email) return reply.redirect('/auth/forgot-password?error=missing');
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email.trim());
    if (user && user.email_verified && user.password_hash) {
      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ?').run(user.id);
      db.prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)').run(user.id, tokenHash, expires);
      await sendPasswordResetEmail(email.trim(), token);
    }
    return reply.redirect('/auth/forgot-password?message=sent');
  });

  // GET /auth/reset-password
  fastify.get('/auth/reset-password', async (req, reply) => {
    const { token } = req.query || {};
    if (!token) return reply.redirect('/auth/login?error=invalid_token');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const db = getDb();
    const rec = db.prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL').get(tokenHash);
    if (!rec || new Date(rec.expires_at) < new Date()) {
      return reply.redirect('/auth/forgot-password?error=token_expired');
    }
    return reply.view('auth/reset-password.njk', { title: 'Set New Password', token, error: req.query.error });
  });

  // POST /auth/reset-password
  fastify.post('/auth/reset-password', async (req, reply) => {
    const { token, password, password2 } = req.body || {};
    if (!token || !password) return reply.redirect('/auth/login?error=invalid');
    if (password !== password2) return reply.redirect(`/auth/reset-password?token=${token}&error=mismatch`);
    if (password.length < 8) return reply.redirect(`/auth/reset-password?token=${token}&error=short`);

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const db = getDb();
    const rec = db.prepare('SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL').get(tokenHash);
    if (!rec || new Date(rec.expires_at) < new Date()) return reply.redirect('/auth/forgot-password?error=token_expired');

    const hash = await bcrypt.hash(password, 12);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, rec.user_id);
    db.prepare("UPDATE password_reset_tokens SET used_at = datetime('now') WHERE id = ?").run(rec.id);
    return reply.redirect('/auth/login?message=password_reset');
  });

  // GET /auth/otp
  fastify.get('/auth/otp', async (req, reply) => {
    if (req.user) return reply.redirect('/dashboard');
    return reply.view('auth/otp.njk', { title: 'Sign In with Code', error: req.query.error, message: req.query.message, email: req.query.email });
  });

  // POST /auth/otp/request
  fastify.post('/auth/otp/request', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (req, reply) => {
    const { email } = req.body || {};
    const ajax = req.body.ajax === '1';
    if (!email) {
      return ajax ? reply.send({ ok: false, error: 'missing' }) : reply.redirect('/auth/otp?error=missing');
    }

    const db = getDb();
    const clientIp = req.ip;
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return ajax ? reply.send({ ok: false, error: 'blocked' }) : reply.redirect('/auth/otp?error=blocked');
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE AND email_verified = 1 AND is_disabled = 0').get(email.trim());
    if (!user) {
      // Don't reveal if user exists
      return ajax ? reply.send({ ok: true }) : reply.redirect(`/auth/otp?message=sent&email=${encodeURIComponent(email)}`);
    }

    const intervalMinutes = parseInt(getSetting('otp_resend_interval_minutes') || '30', 10);
    const existing = db.prepare('SELECT * FROM otp_codes WHERE user_id = ?').get(user.id);
    if (existing) {
      const lastSent = new Date(existing.last_sent_at).getTime();
      const waitMs = intervalMinutes * 60 * 1000;
      if (Date.now() - lastSent < waitMs) {
        const waitLeft = Math.ceil((waitMs - (Date.now() - lastSent)) / 60000);
        return ajax
          ? reply.send({ ok: false, error: 'rate_limit', wait: waitLeft })
          : reply.redirect(`/auth/otp?error=rate_limit&wait=${waitLeft}&email=${encodeURIComponent(email)}`);
      }
    }

    const code = crypto.randomInt(100000, 1000000).toString();
    const codeHash = await bcrypt.hash(code, 10);
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    db.prepare('DELETE FROM otp_codes WHERE user_id = ?').run(user.id);
    db.prepare("INSERT INTO otp_codes (user_id, code_hash, expires_at, last_sent_at) VALUES (?, ?, ?, datetime('now'))").run(user.id, codeHash, expires);

    await sendOtpEmail(email.trim(), code);
    if (req.body.ajax === '1') return reply.send({ ok: true });
    return reply.redirect(`/auth/otp?message=sent&email=${encodeURIComponent(email.trim())}`);
  });

  // POST /auth/otp/verify
  fastify.post('/auth/otp/verify', { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (req, reply) => {
    const { email, code } = req.body || {};
    if (!email || !code) return reply.redirect('/auth/otp?error=missing');

    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE AND is_disabled = 0').get(email.trim());
    if (!user) return reply.redirect('/auth/otp?error=invalid');

    const maxAttempts = parseInt(getSetting('otp_max_attempts_per_hour') || '5', 10);
    const otpRec = db.prepare('SELECT * FROM otp_codes WHERE user_id = ?').get(user.id);
    if (!otpRec) return reply.redirect(`/auth/otp?error=no_code&email=${encodeURIComponent(email)}`);
    if (new Date(otpRec.expires_at) < new Date()) {
      db.prepare('DELETE FROM otp_codes WHERE user_id = ?').run(user.id);
      return reply.redirect(`/auth/otp?error=expired&email=${encodeURIComponent(email)}`);
    }
    if (otpRec.attempts >= maxAttempts) {
      db.prepare('DELETE FROM otp_codes WHERE user_id = ?').run(user.id);
      return reply.redirect(`/auth/otp?error=too_many_attempts&email=${encodeURIComponent(email)}`);
    }

    const valid = await bcrypt.compare(code.trim(), otpRec.code_hash);
    if (!valid) {
      db.prepare('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?').run(otpRec.id);
      return reply.redirect(`/auth/otp?error=invalid_code&email=${encodeURIComponent(email)}`);
    }

    db.prepare('DELETE FROM otp_codes WHERE user_id = ?').run(user.id);
    if (!user.email_verified) {
      db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
    }

    const dest = isSafeRedirect(req.session.returnTo) ? req.session.returnTo : '/dashboard';
    await req.session.regenerate();
    req.session.userId = user.id;
    return reply.redirect(dest);
  });

  // POST /auth/logout
  fastify.post('/auth/logout', async (req, reply) => {
    await req.session.destroy();
    return reply.redirect('/auth/login');
  });

  // ── Google OAuth ───────────────────────────────────────────────────────────

  // GET /auth/google
  fastify.get('/auth/google', async (req, reply) => {
    if (!process.env.GOOGLE_CLIENT_ID) return reply.redirect('/auth/login?error=oauth_unavailable');
    const state = crypto.randomBytes(16).toString('hex');
    req.session.oauthState = state;
    const siteUrl = getSetting('site_url') || '';
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: `${siteUrl}/auth/google/callback`,
      response_type: 'code',
      scope: 'openid email',
      state,
      prompt: 'select_account',
    });
    return reply.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });

  // GET /auth/google/callback
  fastify.get('/auth/google/callback', async (req, reply) => {
    const { code, state, error } = req.query || {};
    if (error || !code) return reply.redirect('/auth/login?error=oauth_failed');
    if (!state || state !== req.session.oauthState) return reply.redirect('/auth/login?error=oauth_failed');
    delete req.session.oauthState;

    const siteUrl = getSetting('site_url') || '';

    // Exchange code for tokens
    let tokenData;
    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: `${siteUrl}/auth/google/callback`,
          grant_type: 'authorization_code',
        }),
      });
      tokenData = await tokenRes.json();
    } catch (e) {
      return reply.redirect('/auth/login?error=oauth_failed');
    }
    if (!tokenData.access_token) return reply.redirect('/auth/login?error=oauth_failed');

    // Fetch user info
    let userInfo;
    try {
      const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      userInfo = await userInfoRes.json();
    } catch (e) {
      return reply.redirect('/auth/login?error=oauth_failed');
    }
    if (!userInfo.email || !userInfo.email_verified) return reply.redirect('/auth/login?error=oauth_email');

    const db = getDb();
    const clientIp = req.ip;
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return reply.redirect('/auth/login?error=blocked');
    }

    const googleId = String(userInfo.sub);
    const email = userInfo.email.toLowerCase();

    // Check if this Google account is already linked
    const oauthAccount = db.prepare('SELECT * FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?').get('google', googleId);
    if (oauthAccount) {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(oauthAccount.user_id);
      if (!user || user.is_disabled) return reply.redirect('/auth/login?error=disabled');
      const dest = isSafeRedirect(req.session.returnTo) ? req.session.returnTo : '/dashboard';
      await req.session.regenerate();
      req.session.userId = user.id;
      return reply.redirect(dest);
    }

    // Look up existing user by email
    let user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email);
    if (user) {
      if (user.is_disabled) return reply.redirect('/auth/login?error=disabled');
      // Link Google to existing account
      db.prepare('INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_user_id) VALUES (?, ?, ?)').run(user.id, 'google', googleId);
      if (!user.email_verified) {
        db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(user.id);
      }
    } else {
      // New user — check registration is open
      if (getSetting('registration_enabled') === 'false') return reply.redirect('/auth/login?error=registration_disabled');
      const freeTier = db.prepare("SELECT id FROM tiers WHERE name = 'free'").get();
      const result = db.prepare('INSERT INTO users (email, email_verified, tier_id) VALUES (?, 1, ?)').run(email, freeTier ? freeTier.id : 1);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(result.lastInsertRowid));
      db.prepare('INSERT INTO oauth_accounts (user_id, provider, provider_user_id) VALUES (?, ?, ?)').run(user.id, 'google', googleId);
    }

    const dest = isSafeRedirect(req.session.returnTo) ? req.session.returnTo : '/dashboard';
    await req.session.regenerate();
    req.session.userId = user.id;
    return reply.redirect(dest);
  });
};
