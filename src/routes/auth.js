'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb, getSetting } = require('../db/index');
const { sendVerificationEmail, sendPasswordResetEmail, sendOtpEmail } = require('../services/email');

module.exports = async function authRoutes(fastify) {
  // GET /auth/login
  fastify.get('/auth/login', async (req, reply) => {
    if (req.user) return reply.redirect('/dashboard');
    return reply.view('auth/login.njk', { title: 'Sign In', error: req.query.error, message: req.query.message });
  });

  // POST /auth/login
  fastify.post('/auth/login', async (req, reply) => {
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

    req.session.userId = user.id;
    delete req.session.impersonatingUserId;
    const dest = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
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
  fastify.post('/auth/register', async (req, reply) => {
    const regEnabled = getSetting('registration_enabled');
    if (regEnabled === 'false') return reply.redirect('/auth/login?error=registration_disabled');

    const { email, password, password2 } = req.body || {};
    if (!email || !password) return reply.redirect('/auth/register?error=missing');
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
  fastify.post('/auth/forgot-password', async (req, reply) => {
    const { email } = req.body || {};
    if (!email) return reply.redirect('/auth/forgot-password?error=missing');
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email.trim());
    if (user && user.email_verified) {
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
  fastify.post('/auth/otp/request', async (req, reply) => {
    const { email } = req.body || {};
    if (!email) return reply.redirect('/auth/otp?error=missing');

    const db = getDb();
    const clientIp = req.ip;
    if (db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(clientIp)) {
      return reply.redirect('/auth/otp?error=blocked');
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE AND email_verified = 1 AND is_disabled = 0').get(email.trim());
    if (!user) {
      // Don't reveal if user exists
      return reply.redirect(`/auth/otp?message=sent&email=${encodeURIComponent(email)}`);
    }

    const intervalMinutes = parseInt(getSetting('otp_resend_interval_minutes') || '30', 10);
    const existing = db.prepare('SELECT * FROM otp_codes WHERE user_id = ?').get(user.id);
    if (existing) {
      const lastSent = new Date(existing.last_sent_at).getTime();
      const waitMs = intervalMinutes * 60 * 1000;
      if (Date.now() - lastSent < waitMs) {
        const waitLeft = Math.ceil((waitMs - (Date.now() - lastSent)) / 60000);
        return reply.redirect(`/auth/otp?error=rate_limit&wait=${waitLeft}&email=${encodeURIComponent(email)}`);
      }
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = await bcrypt.hash(code, 10);
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    db.prepare('DELETE FROM otp_codes WHERE user_id = ?').run(user.id);
    db.prepare("INSERT INTO otp_codes (user_id, code_hash, expires_at, last_sent_at) VALUES (?, ?, ?, datetime('now'))").run(user.id, codeHash, expires);

    await sendOtpEmail(email.trim(), code);
    return reply.redirect(`/auth/otp?message=sent&email=${encodeURIComponent(email.trim())}`);
  });

  // POST /auth/otp/verify
  fastify.post('/auth/otp/verify', async (req, reply) => {
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

    req.session.userId = user.id;
    const dest = req.session.returnTo || '/dashboard';
    delete req.session.returnTo;
    return reply.redirect(dest);
  });

  // POST /auth/logout
  fastify.post('/auth/logout', async (req, reply) => {
    await req.session.destroy();
    return reply.redirect('/auth/login');
  });
};
