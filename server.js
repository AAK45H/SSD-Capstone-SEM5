// ---------------------------------------------------------------------------
// server.js — SecureTasker entry point
// ---------------------------------------------------------------------------
const express = require('express');
const session = require('express-session');
const path    = require('path');

// CWE-1104 (Vulnerability #10): lodash 4.17.15 is imported here so that
// dependency-audit tools (npm audit, Snyk, SonarQube) flag it.
// Pinned version has known prototype-pollution CVEs:
//   CVE-2020-28500, CVE-2021-23337
const _ = require('lodash');

const db       = require('./db');
const { initDb } = require('./db');

const app = express();

// ── View engine ──────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── Body parsers ─────────────────────────────────────────────────────────
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Static files ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ── Session ──────────────────────────────────────────────────────────────
// ── Vulnerability #7 ─────────────────────────────────────────────────────
// VULNERABLE: CWE-614, session cookie missing httpOnly, secure, and sameSite flags
app.use(session({
  secret: 'keyboard-cat',
  resave: false,
  saveUninitialized: false,
  cookie: {}                          // no httpOnly, no secure, no sameSite
}));

/* PATCHED (uncomment to apply fix):
app.use(session({
  secret: require('crypto').randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   true,                   // requires HTTPS
    sameSite: 'strict',
  }
}));
*/

// ── Make session user available to all EJS views ─────────────────────────
app.use((req, res, next) => {
  res.locals.user = req.session.userId
    ? { id: req.session.userId, username: req.session.username }
    : null;
  next();
});

// ── Auto-save disabled to prevent crash ──────────────────────────────
/*
app.use((req, res, next) => {
  res.on('finish', () => {
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      try { db.save(); } catch (_) { }
    }
  });
  next();
});
*/

// ── Auth middleware (applied to protected route groups) ───────────────────
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

// ── Routes ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/tasks' : '/login');
});

app.use('/', require('./routes/auth'));
app.use('/', requireLogin, require('./routes/tasks'));
app.use('/', requireLogin, require('./routes/admin'));

// ── 404 handler ──────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('error', { error: 'Page not found.' });
});

// ── Error handler ────────────────────────────────────────────────────────
// ── Vulnerability #6 ─────────────────────────────────────────────────────
// VULNERABLE: CWE-209, verbose error handler leaking full stack trace to client
app.use((err, req, res, next) => {
  res.status(500).render('error', { error: err.stack });
});

/* PATCHED (uncomment to apply fix):
app.use((err, req, res, next) => {
  console.error(err.stack);           // log internally only
  res.status(500).render('error', { error: 'An internal server error occurred.' });
});
*/

// ── Start (async — wait for sql.js WASM to load) ─────────────────────────
const PORT = process.env.PORT || 3000;

if (process.env.VERCEL) {
  // Export a wrapped handler for Vercel Serverless Functions
  let dbInitialized = false;
  module.exports = async (req, res) => {
    try {
      if (!dbInitialized) {
        await initDb();
        // On Vercel, ensure the DB is seeded if it's completely empty
        try {
          const users = require('./db').prepare('SELECT count(*) as c FROM users').get();
          if (users && users.c === 0) {
            await require('./seed').seed(); 
          }
        } catch (e) {
          console.error("Seed error:", e);
        }
        dbInitialized = true;
      }
      return app(req, res);
    } catch (err) {
      console.error("Vercel Init Error:", err);
      res.status(500).send(`Vercel Init Error: ${err.message}\nStack: ${err.stack}`);
    }
  };
} else {
  // Local development
  initDb().then(() => {
    app.listen(PORT, () => {
      console.log(`\n  🔒 SecureTasker running → http://localhost:${PORT}\n`);
    });
  }).catch(err => {
    console.error('Failed to initialise database:', err);
    process.exit(1);
  });
}
