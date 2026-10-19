"""
Secure REST API — Lab 1 (HDU Information Security)
Student: Li Zetao (23320332)

Endpoints:
  POST /auth/login      -> authenticate, receive a JWT
  GET  /api/data        -> list posts (auth required)
  POST /api/posts       -> create a post (auth required)   [extra endpoint]
  GET  /api/profile     -> show current user (auth required) [extra endpoint]

Security measures implemented:
  - SQL injection protection: parameterized queries (sqlite3 ? placeholders),
    NO string concatenation.
  - XSS protection: all user-controlled strings are HTML-escaped with
    markupsafe.escape() before being returned in responses.
  - Broken authentication protection: JWT issued on login, verified by a
    middleware on every protected endpoint.
  - Passwords: hashed with bcrypt (never stored in plaintext).
"""

import datetime
import functools
import os
import sqlite3

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

app = Flask(__name__)

# Secret key is read from an environment variable; a dev-only fallback is used
# locally. In production this MUST be set via the environment / secret store.
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "lab1-dev-only-fallback-do-not-use-in-prod"
)
DATABASE = "users.db"


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(_exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed one demo user (password hashed with bcrypt)."""
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id            INTEGER PRIMARY KEY AUTOINCREMENT,
                   username      TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL
               )"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS posts (
                   id         INTEGER PRIMARY KEY AUTOINCREMENT,
                   title      TEXT NOT NULL,
                   content    TEXT NOT NULL,
                   author_id  INTEGER NOT NULL,
                   FOREIGN KEY (author_id) REFERENCES users (id)
               )"""
        )
        # Seed demo user: alice / SecurePass123!
        cur.execute("SELECT id FROM users WHERE username = ?", ("alice",))
        if cur.fetchone() is None:
            hashed = bcrypt.hashpw(b"SecurePass123!", bcrypt.gensalt())
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("alice", hashed.decode("utf-8")),
            )
            # A sample post so /api/data is not empty
            cur.execute(
                "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
                ("Hello World", "This is the first secure post.", 1),
            )
        db.commit()


# --------------------------------------------------------------------------- #
# Auth middleware — verifies JWT on every protected endpoint
# --------------------------------------------------------------------------- #
def token_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"message": "Missing or malformed Authorization header"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        user = (
            get_db()
            .execute("SELECT * FROM users WHERE id = ?", (payload["user_id"],))
            .fetchone()
        )
        if user is None:
            return jsonify({"message": "User no longer exists"}), 401
        g.user = user
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.route("/auth/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username")
    password = body.get("password")
    if not username or not password:
        return jsonify({"message": "username and password are required"}), 400

    # Parameterized query — no SQL injection possible
    user = (
        get_db()
        .execute("SELECT * FROM users WHERE username = ?", (username,))
        .fetchone()
    )

    # bcrypt.verify — constant-time compare against the stored hash
    if user and bcrypt.checkpw(
        password.encode("utf-8"), user["password_hash"].encode("utf-8")
    ):
        token = jwt.encode(
            {
                "user_id": user["id"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )
        return jsonify({"token": token, "token_type": "Bearer"})  # nosec B105 — this is a token TYPE label, not a password

    return jsonify({"message": "Invalid username or password"}), 401


@app.route("/api/data", methods=["GET"])
@token_required
def list_posts():
    rows = (
        get_db()
        .execute(
            """SELECT p.id, p.title, p.content, u.username AS author
                   FROM posts p JOIN users u ON p.author_id = u.id"""
        )
        .fetchall()
    )
    result = []
    for r in rows:
        result.append(
            {
                "id": r["id"],
                # XSS protection: escape every user-controlled field before output
                "title": str(escape(r["title"])),
                "content": str(escape(r["content"])),
                "author": r["author"],
            }
        )
    return jsonify({"count": len(result), "data": result})


@app.route("/api/posts", methods=["POST"])
@token_required
def create_post():
    body = request.get_json(silent=True) or {}
    title = body.get("title")
    content = body.get("content")
    if not title or not content:
        return jsonify({"message": "title and content are required"}), 400

    db = get_db()
    # Parameterized query — values are never concatenated into the SQL string
    db.execute(
        "INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)",
        (title, content, g.user["id"]),
    )
    db.commit()
    return (
        jsonify(
            {
                "message": "post created",
                "title": str(escape(title)),
                "author": g.user["username"],
            }
        ),
        201,
    )


@app.route("/api/profile", methods=["GET"])
@token_required
def profile():
    return jsonify({"id": g.user["id"], "username": g.user["username"]})


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        {
            "service": "secure-rest-api-lab",
            "student": "Li Zetao (23320332)",
            "endpoints": [
                "POST /auth/login",
                "GET  /api/data",
                "POST /api/posts",
                "GET  /api/profile",
            ],
        }
    )


if __name__ == "__main__":
    init_db()
    # debug=False — never run the Werkzeug debugger in a deployed service
    app.run(host="0.0.0.0", port=5000, debug=False)  # nosec B104 — 0.0.0.0 required for container/Docker deployment
