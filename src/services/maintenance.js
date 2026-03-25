'use strict';

const { getDb, getSetting } = require('../db/index');

/**
 * Prune old DNS hits and update logs based on each user's tier history_days setting.
 * Runs periodically to keep the database lean.
 */
function pruneOldHits() {
  const db = getDb();
  try {
    // Prune dns_hits older than the user's tier history_days
    db.prepare(`
      DELETE FROM dns_hits
      WHERE id IN (
        SELECT h.id FROM dns_hits h
        JOIN ddns_records r ON r.id = h.record_id
        JOIN users u ON u.id = r.user_id
        JOIN tiers t ON t.id = u.tier_id
        WHERE h.queried_at < datetime('now', '-' || t.history_days || ' days')
      )
    `).run();

    // Prune update_logs older than history_days
    db.prepare(`
      DELETE FROM update_logs
      WHERE id IN (
        SELECT l.id FROM update_logs l
        JOIN ddns_records r ON r.id = l.record_id
        JOIN users u ON u.id = r.user_id
        JOIN tiers t ON t.id = u.tier_id
        WHERE l.updated_at < datetime('now', '-' || t.history_days || ' days')
      )
    `).run();

    // Clean up expired sessions
    db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();

    // Clean up expired OTP codes
    db.prepare("DELETE FROM otp_codes WHERE expires_at < datetime('now')").run();

    // Clean up expired password reset tokens
    db.prepare("DELETE FROM password_reset_tokens WHERE expires_at < datetime('now')").run();

    // Clean up expired email verifications
    db.prepare("DELETE FROM email_verifications WHERE expires_at < datetime('now')").run();

    // Remove pending custom domains that exceeded the validation timeout
    const timeoutHours = parseInt(getSetting('zone_validation_timeout_hours') || '48', 10);
    db.prepare(`
      DELETE FROM zones
      WHERE user_id IS NOT NULL AND validated = 0
        AND created_at < datetime('now', '-' || ? || ' hours')
    `).run(timeoutHours);

  } catch (err) {
    console.error('[maintenance] prune error:', err.message);
  }
}

function startMaintenanceJob() {
  // Run immediately then every hour
  pruneOldHits();
  setInterval(pruneOldHits, 60 * 60 * 1000).unref();
  console.log('[maintenance] Scheduled hourly cleanup');
}

module.exports = { startMaintenanceJob };
