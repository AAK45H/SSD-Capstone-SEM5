// ---------------------------------------------------------------------------
// db.js — SQLite database initialisation (sql.js — pure JS, no native build)
// ---------------------------------------------------------------------------
// sql.js provides a synchronous API similar to better-sqlite3 once loaded.
// We wrap it to expose the same .prepare().get() / .all() / .run() interface
// that the rest of the app expects.
// ---------------------------------------------------------------------------

const initSqlJs = require('sql.js');
const fs        = require('fs');
const path      = require('path');

const DB_PATH = process.env.VERCEL
  ? path.join('/tmp', 'securetasker.db')
  : path.join(__dirname, 'securetasker.db');

let _db = null; // raw sql.js Database instance

// ── Initialise synchronously by blocking on the WASM load ────────────────
// sql.js needs to load its WASM binary asynchronously once.  We cache the
// compiled database to disk so every subsequent require() is instant.
function getDb() {
  if (_db) return _db;
  throw new Error('Database not initialised. Call initDb() first.');
}

// ── Thin wrapper that mirrors the better-sqlite3 API ─────────────────────
const wrapper = {
  /** db.exec(sql) — run raw SQL (DDL, multiple statements, etc.) */
  exec(sql) {
    getDb().run(sql);
  },

  /** db.pragma(str) — no-op for sql.js (WAL not applicable) */
  pragma() {},

  /**
   * db.prepare(sql) → returns an object with .get(), .all(), .run()
   * Placeholders: use ? positional params.
   */
  prepare(sql) {
    return {
      get(...params) {
        const stmt = getDb().prepare(sql);
        stmt.bind(params.length ? params : undefined);
        if (stmt.step()) {
          const cols = stmt.getColumnNames();
          const vals = stmt.get();
          const row  = {};
          cols.forEach((c, i) => (row[c] = vals[i]));
          stmt.free();
          return row;
        }
        stmt.free();
        return undefined;
      },
      all(...params) {
        const rows = [];
        const stmt = getDb().prepare(sql);
        stmt.bind(params.length ? params : undefined);
        while (stmt.step()) {
          const cols = stmt.getColumnNames();
          const vals = stmt.get();
          const row  = {};
          cols.forEach((c, i) => (row[c] = vals[i]));
          rows.push(row);
        }
        stmt.free();
        return rows;
      },
      run(...params) {
        getDb().run(sql, params.length ? params : undefined);
        return { changes: getDb().getRowsModified() };
      },
    };
  },

  /** Persist the in-memory database to disk */
  save() {
    const data = getDb().export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  },

  /** Close the database */
  close() {
    if (_db) { _db.close(); _db = null; }
  },
};

// ── Async init (called once at startup before listen()) ──────────────────
async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    _db = new SQL.Database(buf);
  } else {
    _db = new SQL.Database();
  }

  // Create tables
  _db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT    UNIQUE NOT NULL,
      password TEXT    NOT NULL
    );
  `);
  _db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id          INTEGER  PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER  NOT NULL,
      title       TEXT     NOT NULL,
      description TEXT     DEFAULT '',
      status      TEXT     DEFAULT 'pending',
      file_path   TEXT,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  // Auto-save to disk on every request via a hook set in server.js
  wrapper.save();
  return wrapper;
}

module.exports        = wrapper;
module.exports.initDb = initDb;
