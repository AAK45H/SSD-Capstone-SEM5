// ---------------------------------------------------------------------------
// routes/tasks.js — Task CRUD, Search, File Upload
// ---------------------------------------------------------------------------
const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const path    = require('path');
const db      = require('../db');

const upload = multer({ dest: path.join(__dirname, '..', 'uploads') });

// ======================== GET /tasks ========================================
router.get('/tasks', (req, res) => {
  const tasks = db.prepare(
    'SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC'
  ).all(req.session.userId);
  res.render('tasks', { tasks });
});

// ======================== POST /tasks (create) ==============================
router.post('/tasks', upload.single('attachment'), (req, res) => {
  const { title, description, status } = req.body;
  const filePath = req.file ? req.file.filename : null;

  // ── Vulnerability #12 ─────────────────────────────────────────────────
  // VULNERABLE: CWE-908, Buffer.allocUnsafe without full overwrite — stale memory may leak
  if (req.file) {
    const thumbSize   = parseInt(req.body.thumbSize) || 256;
    const thumbnailBuf = Buffer.allocUnsafe(thumbSize);
    thumbnailBuf.write('THUMB', 0);                         // only 5 bytes written
    console.log('[UPLOAD] thumbnail hex:', thumbnailBuf.toString('hex'));
  }

  /* PATCHED (uncomment to apply fix):
  if (req.file) {
    const thumbSize    = Math.min(parseInt(req.body.thumbSize) || 256, 1024);
    const thumbnailBuf = Buffer.alloc(thumbSize);            // zero-filled — safe
    thumbnailBuf.write('THUMB', 0);
    console.log('[UPLOAD] thumbnail hex:', thumbnailBuf.toString('hex'));
  }
  */

  db.prepare(
    'INSERT INTO tasks (user_id, title, description, status, file_path) VALUES (?, ?, ?, ?, ?)'
  ).run(req.session.userId, title, description || '', status || 'pending', filePath);

  res.redirect('/tasks');
});

// ======================== GET /task/:id (view) ==============================
router.get('/task/:id', (req, res) => {

  // ── Vulnerability #5 ──────────────────────────────────────────────────
  // VULNERABLE: CWE-639, IDOR — no ownership check against session user
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id);

  /* PATCHED (uncomment to apply fix):
  const task = db.prepare(
    'SELECT * FROM tasks WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.session.userId);
  */

  if (!task) return res.status(404).render('error', { error: 'Task not found.' });
  res.render('task', { task });
});

// ======================== POST /task/:id/delete =============================
// ── Vulnerability #8 ─────────────────────────────────────────────────────
// VULNERABLE: CWE-352, no CSRF token on destructive action
router.post('/task/:id/delete', (req, res) => {
  db.prepare('DELETE FROM tasks WHERE id = ?').run(req.params.id);
  res.redirect('/tasks');
});

/* PATCHED (uncomment to apply fix):
// 1. In server.js add:  const csrf = require('csurf'); app.use(csrf({ cookie: false }));
// 2. Pass csrfToken to views:
//      app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });
// 3. In the delete form add:  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
// 4. Also add ownership check:
// router.post('/task/:id/delete', (req, res) => {
//   db.prepare('DELETE FROM tasks WHERE id = ? AND user_id = ?')
//     .run(req.params.id, req.session.userId);
//   res.redirect('/tasks');
// });
*/

// ======================== GET /search ========================================
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  const tasks = db.prepare(
    'SELECT * FROM tasks WHERE user_id = ? AND (title LIKE ? OR description LIKE ?)'
  ).all(req.session.userId, `%${q}%`, `%${q}%`);
  // Reflected XSS is in the view — see search.ejs, Vulnerability #3
  res.render('search', { query: q, tasks });
});

module.exports = router;
