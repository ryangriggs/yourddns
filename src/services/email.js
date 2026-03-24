'use strict';

const { Resend } = require('resend');
const { getSetting } = require('../db/index');

let resend;
function getResend() {
  if (!resend) resend = new Resend(process.env.RESEND_API_KEY);
  return resend;
}

async function sendEmail({ to, subject, html }) {
  const from = process.env.EMAIL_FROM || `noreply@${getSetting('site_domain') || 'yourddns.com'}`;
  try {
    const result = await getResend().emails.send({ from, to, subject, html });
    return { ok: true, result };
  } catch (err) {
    console.error('[email] send failed:', err.message);
    return { ok: false, error: err.message };
  }
}

async function sendVerificationEmail(email, token) {
  const url = getSetting('site_url') || 'https://yourddns.com';
  const siteName = getSetting('site_name') || 'YourDDNS';
  const link = `${url}/auth/verify-email?token=${token}`;
  return sendEmail({
    to: email,
    subject: `Verify your ${siteName} email`,
    html: emailLayout(siteName, `
      <h2>Verify your email</h2>
      <p>Click the link below to verify your email address.</p>
      <p><a href="${link}" style="background:#2563eb;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block">Verify Email</a></p>
      <p>Or copy this link: <code>${link}</code></p>
      <p>This link expires in 24 hours.</p>
    `),
  });
}

async function sendPasswordResetEmail(email, token) {
  const url = getSetting('site_url') || 'https://yourddns.com';
  const siteName = getSetting('site_name') || 'YourDDNS';
  const link = `${url}/auth/reset-password?token=${token}`;
  return sendEmail({
    to: email,
    subject: `Reset your ${siteName} password`,
    html: emailLayout(siteName, `
      <h2>Reset your password</h2>
      <p>Click the link below to reset your password.</p>
      <p><a href="${link}" style="background:#2563eb;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block">Reset Password</a></p>
      <p>Or copy this link: <code>${link}</code></p>
      <p>This link expires in 1 hour. If you didn't request this, ignore this email.</p>
    `),
  });
}

async function sendOtpEmail(email, code) {
  const siteName = getSetting('site_name') || 'YourDDNS';
  return sendEmail({
    to: email,
    subject: `Your ${siteName} sign-in code`,
    html: emailLayout(siteName, `
      <h2>Your sign-in code</h2>
      <p>Use the following code to sign in. It expires in 10 minutes.</p>
      <p style="font-size:2rem;font-weight:700;letter-spacing:0.3em;text-align:center;margin:24px 0">${code}</p>
      <p>If you didn't request this, ignore this email.</p>
    `),
  });
}

function emailLayout(siteName, content) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;margin:0;padding:0}
    .wrap{max-width:520px;margin:40px auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:32px}
    h2{margin-top:0;color:#111827;font-size:1.25rem}
    p{color:#374151;line-height:1.6}
    code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:0.875rem;word-break:break-all}
    .footer{margin-top:32px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:0.75rem;color:#6b7280}
  </style></head><body>
    <div class="wrap">
      <div style="font-weight:700;font-size:1rem;margin-bottom:24px;color:#111827">${siteName}</div>
      ${content}
      <div class="footer">You received this email from ${siteName}.</div>
    </div>
  </body></html>`;
}

module.exports = { sendEmail, sendVerificationEmail, sendPasswordResetEmail, sendOtpEmail };
