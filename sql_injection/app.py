#!/usr/bin/env python3
"""
SQL Injection Demo
------------------
Demonstrates a vulnerable login and a secure login side by side.

Run:
    pip install flask
    python app.py
Then open http://localhost:5002
"""

import sqlite3
import os
from flask import Flask, request, jsonify, render_template, g

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    """Create the users table and seed demo users."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        )
    """)
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("admin",   "super_secret_123", "admin"),
            ("alice",   "alice_pass_456",   "user"),
            ("bob",     "bob_pass_789",     "user"),
        ],
    )
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Vulnerable login  ← SQL Injection possible here
# ---------------------------------------------------------------------------

@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    data     = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()

    # ⚠️  VULNERABLE: user input is injected directly into the query string
    query = (
        f"SELECT * FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        cur  = db.execute(query)
        user = cur.fetchone()
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Database error: {e}",
            "query":   query,
        })

    if user:
        return jsonify({
            "success": True,
            "message": f"Logged in as '{user['username']}' (role: {user['role']})",
            "query":   query,
            "user":    dict(user),
        })
    return jsonify({
        "success": False,
        "message": "Invalid username or password.",
        "query":   query,
    })

# ---------------------------------------------------------------------------
# Secure login  ← parameterised query, injection impossible
# ---------------------------------------------------------------------------

@app.route("/login/secure", methods=["POST"])
def login_secure():
    data     = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()

    # ✅  SECURE: placeholders (?) keep data separate from SQL structure
    query = "SELECT * FROM users WHERE username = ? AND password = ?"

    try:
        cur  = db.execute(query, (username, password))
        user = cur.fetchone()
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Database error: {e}",
            "query":   query + f"  -- params: ({username!r}, {password!r})",
        })

    if user:
        return jsonify({
            "success": True,
            "message": f"Logged in as '{user['username']}' (role: {user['role']})",
            "query":   query + f"  -- params: ({username!r}, {password!r})",
            "user":    dict(user),
        })
    return jsonify({
        "success": False,
        "message": "Invalid username or password.",
        "query":   query + f"  -- params: ({username!r}, {password!r})",
    })

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/users")
def list_users():
    """Debug endpoint — shows all users in the DB."""
    db    = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(u) for u in users])

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("Database initialised with demo users.")
    print("  admin / super_secret_123")
    print("  alice / alice_pass_456")
    print("  bob   / bob_pass_789")
    app.run(debug=False, port=5002)