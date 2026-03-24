'use strict';

/**
 * A simple synchronous SQLite-backed session store compatible with @fastify/session.
 */
class SQLiteSessionStore {
  constructor(db) {
    this.db = db;
  }

  get(sessionId, callback) {
    try {
      const row = this.db.prepare(
        "SELECT data FROM sessions WHERE id = ? AND expires_at > datetime('now')"
      ).get(sessionId);
      callback(null, row ? JSON.parse(row.data) : null);
    } catch (err) {
      callback(err);
    }
  }

  set(sessionId, session, callback) {
    try {
      const maxAge = session.cookie?.maxAge || 7 * 24 * 60 * 60; // seconds
      const expires = new Date(Date.now() + maxAge * 1000).toISOString();
      this.db.prepare(
        'INSERT OR REPLACE INTO sessions (id, data, expires_at) VALUES (?, ?, ?)'
      ).run(sessionId, JSON.stringify(session), expires);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }

  destroy(sessionId, callback) {
    try {
      this.db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
      callback(null);
    } catch (err) {
      callback(err);
    }
  }
}

module.exports = SQLiteSessionStore;
