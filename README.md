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

> **Screenshot:** Bandit and pip-audit results from the GitHub Actions tab —
> see `screenshots/ci-pipeline.png` (to be added after first push).

---

## 4. Selected Vulnerability (CVE)

> Details to be filled in after the Vulhub reproduction.

- **CVE ID:** _(pending)_
- **Description:** _(pending)_

### 4.1 Reproduction Steps

_(pending)_

### 4.2 Root Cause Analysis

_(pending)_

### 4.3 Applied Fix

_(pending)_

### 4.4 Proof of Fix

_(pending)_

---

## 5. Repository Structure

```
.
├── app.py                  # Flask application
├── requirements.txt        # Python dependencies
├── .github/workflows/ci.yml
├── users.db                # SQLite database (auto-created)
└── README.md
```
