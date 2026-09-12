const db = require('./db');
db.initDb().then(() => {
  console.log("DB initialized.");
  try {
    db.save();
    console.log("Save successful.");
  } catch(e) {
    console.error("Save error:", e);
  }
});
