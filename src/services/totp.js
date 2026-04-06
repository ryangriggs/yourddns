'use strict';

const crypto = require('crypto');

// Base32 alphabet (RFC 4648)
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const str = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  const buf = [];
  let bits = 0, val = 0;
  for (const ch of str) {
    const idx = BASE32.indexOf(ch);
    if (idx < 0) throw new Error('Invalid base32 character: ' + ch);
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      buf.push((val >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(buf);
}

function base32Encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const byte of buf) {
    val = (val << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(val << (5 - bits)) & 31];
  return out;
}

function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function hotp(key, counter) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8)  |
     (hmac[offset + 3] & 0xff)
  ) % 1000000;
  return code.toString().padStart(6, '0');
}

function generateTotp(secret, windowOffset = 0) {
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / 30) + windowOffset;
  return hotp(key, counter);
}

// Allow ±1 window (90 seconds total) to account for clock drift
function verifyTotp(secret, token, drift = 1) {
  const t = (token || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(t)) return false;
  for (let w = -drift; w <= drift; w++) {
    if (generateTotp(secret, w) === t) return true;
  }
  return false;
}

function getTotpUri(secret, email, issuer) {
  return (
    'otpauth://totp/' +
    encodeURIComponent(issuer + ':' + email) +
    '?secret=' + secret +
    '&issuer=' + encodeURIComponent(issuer) +
    '&algorithm=SHA1&digits=6&period=30'
  );
}

// Generate 8 backup codes in XXXXXX-XXXXXX format (48 bits of entropy each)
function generateBackupCodes() {
  const codes = [];
  for (let i = 0; i < 8; i++) {
    const a = crypto.randomBytes(3).toString('hex').toUpperCase();
    const b = crypto.randomBytes(3).toString('hex').toUpperCase();
    codes.push(`${a}-${b}`);
  }
  return codes;
}

// Returns array of SHA-256 hashes for storage
function hashBackupCodes(codes) {
  return codes.map(code =>
    crypto.createHash('sha256').update(code.toUpperCase().replace(/\s/g, '')).digest('hex')
  );
}

// Returns remaining hashes array if code is valid, false otherwise
function verifyAndConsumeBackupCode(inputCode, storedHashes) {
  const normalized = (inputCode || '').toUpperCase().replace(/\s/g, '');
  const inputHash = crypto.createHash('sha256').update(normalized).digest('hex');
  const idx = storedHashes.indexOf(inputHash);
  if (idx < 0) return false;
  const remaining = [...storedHashes];
  remaining.splice(idx, 1);
  return remaining;
}

module.exports = {
  generateSecret,
  verifyTotp,
  getTotpUri,
  generateBackupCodes,
  hashBackupCodes,
  verifyAndConsumeBackupCode,
};
