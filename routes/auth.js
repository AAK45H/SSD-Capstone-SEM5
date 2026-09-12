// ---------------------------------------------------------------------------
// routes/auth.js — Login, Registration, Logout
// ---------------------------------------------------------------------------
const express = require('express');
const router  = express.Router();
const db      = require('../db');

// ======================== GET /login ========================================
router.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// ======================== POST /login =======================================
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  // ── Vulnerability #13 ──────────────────────────────────────────────────
  // VULNERABLE: CERT-LOG, logs plaintext password; no rate-limit on failed logins
  console.log(`[LOGIN] user=${username} password=${password}`);

  /* PATCHED (uncomment to apply fix):
  console.log(`[LOGIN] user=${username} [password=REDACTED] at ${new Date().toISOString()}`);
  // Also apply express-rate-limit to this route (see server.js):
  //   const rateLimit = require('express-rate-limit');
  //   const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5,
  //       message: 'Too many login attempts — try again later.' });
  //   router.post('/login', loginLimiter, handler);
  */

  // ── Vulnerability #1 ──────────────────────────────────────────────────
  // VULNERABLE: CWE-89, SQL Injection via string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  const user  = db.prepare(query).get();
  if (!user) return res.render('login', { error: 'Invalid credentials.' });

  /* PATCHED (uncomment to apply fix):
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !require('bcrypt').compareSync(password, user.password)) {
    return res.render('login', { error: 'Invalid credentials.' });
  }
  */

  req.session.userId   = user.id;
  req.session.username = user.username;
  res.redirect('/tasks');
});

// ======================== GET /register =====================================
router.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// ======================== POST /register ====================================
router.post('/register', (req, res) => {

  // ── Vulnerability #14 ─────────────────────────────────────────────────
  // VULNERABLE: CWE-20, no server-side input validation
  const { username, password } = req.body;

  /* PATCHED (uncomment to apply fix):
  const Joi    = require('joi');
  const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(8).max(72).required(),
  });
  const { error: valErr, value } = schema.validate(req.body);
  if (valErr) return res.render('register', { error: valErr.details[0].message });
  const { username, password } = value;
  */

  // ── Vulnerability #4 ──────────────────────────────────────────────────
  // VULNERABLE: CWE-256, plaintext password storage
  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, password);
  } catch (e) {
    return res.render('register', { error: 'Username already taken.' });
  }

  /* PATCHED (uncomment to apply fix):
  const bcrypt = require('bcrypt');
  const hashed = bcrypt.hashSync(password, 12);
  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashed);
  } catch (e) {
    return res.render('register', { error: 'Username already taken.' });
  }
  */

  res.redirect('/login');
});

// ======================== GET /logout ========================================
router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

module.exports = router;
