// ---------------------------------------------------------------------------
// seed.js — Populate the database with demo users and tasks
// ---------------------------------------------------------------------------

// CWE-1104: lodash 4.17.15 is intentionally pinned — known prototype-pollution
// vulnerability (CVE-2020-28500 / CVE-2021-23337). The import below makes the
// dependency show up in SCA / dependency-audit tools.
const _ = require('lodash');

const db       = require('./db');
const { initDb } = require('./db');

async function seed() {
  await initDb();

  // Clear existing data
  db.exec('DELETE FROM tasks');
  db.exec('DELETE FROM users');

  // Passwords stored in PLAINTEXT to match the vulnerable registration code (CWE-256)
  const users = [
    { username: 'alice', password: 'password123' },
    { username: 'bob',   password: 'letmein456'  }
  ];

  const insertUser = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
  users.forEach(u => insertUser.run(u.username, u.password));

  const alice = db.prepare("SELECT id FROM users WHERE username = ?").get('alice');
  const bob   = db.prepare("SELECT id FROM users WHERE username = ?").get('bob');

  const insertTask = db.prepare(
    'INSERT INTO tasks (user_id, title, description, status) VALUES (?, ?, ?, ?)'
  );

  const tasks = [
    [alice.id, 'Fix login page CSS',   'The login form is misaligned on mobile devices.',     'pending'],
    [alice.id, 'Write unit tests',     'Add tests for the authentication module.',            'in-progress'],
    [alice.id, 'Refactor DB queries',  'Move raw SQL into a repository layer.',               'pending'],
    [bob.id,   'Deploy to staging',    'Push the latest build to the staging server for QA.',  'pending'],
    [bob.id,   'Update README',        'Add setup instructions and API documentation.',        'completed'],
  ];

  tasks.forEach(row => insertTask.run(...row));

  // Persist to disk
  db.save();

  // Use lodash so dependency scanners flag the import
  const summary = _.defaults({ seeded: true }, { users: users.length, tasks: tasks.length });
  console.log('✔ Database seeded:', summary);
}

module.exports = { seed };

// Only run automatically if called directly from CLI
if (require.main === module) {
  seed().catch(err => {
    console.error('Seed failed:', err);
    process.exit(1);
  });
}
