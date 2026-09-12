// ---------------------------------------------------------------------------
// routes/admin.js — Admin diagnostics (ping) and JSON task import
// ---------------------------------------------------------------------------
const express      = require('express');
const router       = express.Router();
const { exec }     = require('child_process');
const db           = require('../db');

// ======================== GET /admin =========================================
router.get('/admin', (req, res) => {
  res.render('admin', { pingResult: null, importResult: null });
});

// ======================== POST /diagnostics/ping =============================
router.post('/diagnostics/ping', (req, res) => {
  const { host } = req.body;

  // ── Vulnerability #11 ─────────────────────────────────────────────────
  // VULNERABLE: CWE-78, OS command injection via unsanitised user input
  exec('ping -n 4 ' + host, { timeout: 15000 }, (err, stdout, stderr) => {
    const output = stdout || stderr || (err ? err.message : 'No output.');
    res.render('admin', { pingResult: output, importResult: null });
  });

  /* PATCHED (uncomment to apply fix):
  const { execFile } = require('child_process');
  if (!/^[a-zA-Z0-9.\-:]+$/.test(host)) {
    return res.render('admin', {
      pingResult: 'Invalid hostname — alphanumeric, dots, hyphens only.',
      importResult: null
    });
  }
  execFile('ping', ['-n', '4', host], { timeout: 15000 }, (err, stdout, stderr) => {
    const output = stdout || stderr || (err ? err.message : 'No output.');
    res.render('admin', { pingResult: output, importResult: null });
  });
  */
});

// ======================== POST /import =======================================
router.post('/import', (req, res) => {
  const body = req.body.jsonData || '';

  // ── Vulnerability #9 ──────────────────────────────────────────────────
  // VULNERABLE: CWE-502, insecure deserialization — eval() instead of JSON.parse
  let data;
  try {
    data = eval('(' + body + ')');
  } catch (e) {
    return res.render('admin', {
      pingResult: null,
      importResult: 'Invalid JSON: ' + e.message,
    });
  }

  /* PATCHED (uncomment to apply fix):
  let data;
  try {
    data = JSON.parse(body);
  } catch (e) {
    return res.render('admin', {
      pingResult: null,
      importResult: 'Invalid JSON: ' + e.message,
    });
  }
  */

  if (!Array.isArray(data)) {
    return res.render('admin', {
      pingResult: null,
      importResult: 'JSON must be an array of task objects.',
    });
  }

  const insert = db.prepare(
    'INSERT INTO tasks (user_id, title, description, status) VALUES (?, ?, ?, ?)'
  );
  let count = 0;
  data.forEach((t) => {
    if (t && t.title) {
      insert.run(req.session.userId, t.title, t.description || '', t.status || 'pending');
      count++;
    }
  });

  res.render('admin', {
    pingResult: null,
    importResult: `✔ Successfully imported ${count} task(s).`,
  });
});

module.exports = router;
