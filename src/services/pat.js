'use strict';

const crypto = require('crypto');

function generatePat() {
  return 'yddns_' + crypto.randomBytes(32).toString('hex');
}

function hashPat(pat) {
  const secret = process.env.PAT_HMAC_SECRET || 'default-secret-change-me';
  return crypto.createHmac('sha256', secret).update(pat).digest('hex');
}

function verifyPat(pat, hash) {
  const expected = hashPat(pat);
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(hash, 'hex'));
  } catch {
    return false;
  }
}

module.exports = { generatePat, hashPat, verifyPat };
