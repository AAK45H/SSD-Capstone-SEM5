const db = require('./db');
db.initDb().then(() => {
  const query = "SELECT * FROM users WHERE username = 'alice' AND password = 'password123'";
  const res = db.prepare(query).get();
  console.log(res);
});
