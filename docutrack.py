"""
DocuTrack - Student Document Expiry & Renewal Reminder System
-------------------------------------------------------------
HOW TO RUN (no installation needed, only Python 3.8+):

    python docutrack.py          (Windows)
    python3 docutrack.py         (Mac / Linux)

The browser opens automatically at http://localhost:8000
Data is stored in a file called docutrack_data.db next to this script.

CONCEPT MAP (search for these tags in the code):
  [DBMS]      primary/foreign keys, constraints, index, view, transaction (ACID)
  [DP-900]    relational data, OLTP workload, SQL DDL/DML, GROUP BY analytics,
              JSON export (semi-structured data), Azure SQL Database mapping
  [DESIGN]    3-tier client-server, stateless REST + JSON API, separation of concerns
  [SECURITY]  salted password hashing, SQL-injection and XSS protection, secure cookies,
              session expiry, per-user data isolation, rate limiting, audit log, CSP headers
"""

import hashlib
import http.server
import json
import os
import re
import secrets
import socketserver
import sqlite3
import threading
import time
import webbrowser
from datetime import date, datetime, timedelta, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "docutrack_data.db")
CATEGORIES = ["Identity", "Certificate", "Licence", "Passport / Visa", "Insurance", "Other"]

# [DBMS] [DP-900] Relational schema (DDL).
#   categories 1---N docs     (lookup table -> removes repeated text, normalisation)
#   users      1---N docs     (every document belongs to exactly one user)
#   docs       1---N renewals (full renewal history)
# Constraints: PRIMARY KEY, FOREIGN KEY (ON DELETE CASCADE), UNIQUE, NOT NULL, CHECK.
SCHEMA = """
CREATE TABLE IF NOT EXISTS categories(name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL CHECK(instr(email,'@') > 1),
    salt TEXT NOT NULL, pw TEXT NOT NULL, created TEXT);
CREATE TABLE IF NOT EXISTS sessions(
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS docs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK(length(name) > 0),
    category TEXT NOT NULL REFERENCES categories(name),
    number TEXT, expiry TEXT NOT NULL, notes TEXT,
    renewed_count INTEGER DEFAULT 0 CHECK(renewed_count >= 0),
    last_renewed TEXT, created TEXT);
CREATE INDEX IF NOT EXISTS idx_docs_user_expiry ON docs(user_id, expiry);
CREATE TABLE IF NOT EXISTS renewals(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id INTEGER NOT NULL REFERENCES docs(id) ON DELETE CASCADE,
    old_expiry TEXT NOT NULL, new_expiry TEXT NOT NULL, renewed_on TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, event TEXT NOT NULL, detail TEXT, at TEXT NOT NULL);
-- [DBMS] A VIEW: a saved query that computes the status of each document inside the database.
CREATE VIEW IF NOT EXISTS v_doc_status AS
    SELECT id, user_id, name, category, expiry,
           CASE WHEN expiry < date('now') THEN 'expired'
                WHEN expiry <= date('now','+30 days') THEN 'soon'
                ELSE 'active' END AS status
    FROM docs;
"""


# ----------------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # [DBMS] enforce referential integrity
    return conn


def init_db():
    conn = db()
    conn.executescript(SCHEMA)
    conn.executemany("INSERT OR IGNORE INTO categories(name) VALUES(?)", [(c,) for c in CATEGORIES])
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def audit(conn, user_id, event, detail=""):
    """[SECURITY] Audit log: who did what, and when (like Azure Monitor / activity logs)."""
    conn.execute(
        "INSERT INTO audit_log(user_id,event,detail,at) VALUES(?,?,?,?)",
        (user_id, event, str(detail or "")[:120], now_iso()),
    )


# [SECURITY] Brute-force protection: max 5 failed logins per 5 minutes per email + IP.
FAILS = {}
FAIL_LOCK = threading.Lock()


def too_many_fails(key):
    now = time.time()
    with FAIL_LOCK:
        FAILS[key] = [t for t in FAILS.get(key, []) if now - t < 300]
        return len(FAILS[key]) >= 5


def note_fail(key):
    with FAIL_LOCK:
        FAILS.setdefault(key, []).append(time.time())


def clear_fails(key):
    with FAIL_LOCK:
        FAILS.pop(key, None)


def hash_pw(password, salt):
    # [SECURITY] Passwords are never stored in plain text: salted PBKDF2-SHA256 (100,000 rounds)
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000).hex()


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def clean_doc(b):
    name = (b.get("name") or "").strip()[:80]
    if not name:
        raise ApiError(400, "Document name is required.")
    try:
        expiry = date.fromisoformat((b.get("expiry") or "").strip()).isoformat()
    except ValueError:
        raise ApiError(400, "Please choose a valid expiry date.")
    cat = b.get("category") if b.get("category") in CATEGORIES else "Other"
    return name, cat, (b.get("number") or "").strip()[:60], expiry, (b.get("notes") or "").strip()[:300]


def doc_dict(r):
    return {k: r[k] for k in ("id", "name", "category", "number", "expiry", "notes", "renewed_count", "last_renewed")}


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep the terminal clean

    # ---- low level helpers
    def send_bytes(self, code, data, ctype, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        # [SECURITY] Defensive HTTP headers (clickjacking, MIME sniffing, XSS, data leaks)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj, headers=None):
        self.send_bytes(code, json.dumps(obj).encode(), "application/json", headers)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            raise ApiError(400, "Invalid request.")

    def current_user(self, conn):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie()
        c.load(raw)
        if "dt_session" not in c:
            return None
        # [SECURITY] sessions expire; a parameterised query (?) prevents SQL injection
        return conn.execute(
            "SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=? AND s.expires > ?",
            (c["dt_session"].value, now_iso()),
        ).fetchone()

    # ---- routing
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_PUT(self):
        self.handle_request("PUT")

    def do_DELETE(self):
        self.handle_request("DELETE")

    def handle_request(self, method):
        path = urlparse(self.path).path
        if len(path) > 1:
            path = path.rstrip("/")
        if method == "GET" and path in ("/", "/index.html"):
            return self.send_bytes(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if not path.startswith("/api/"):
            return self.send_json(404, {"error": "Not found"})
        # [SECURITY] Only accept JSON for state-changing calls (blocks simple cross-site form posts / CSRF)
        if method in ("POST", "PUT", "DELETE") and "application/json" not in (self.headers.get("Content-Type") or ""):
            return self.send_json(415, {"error": "JSON requests only."})
        conn = db()
        try:
            body = self.read_json() if method in ("POST", "PUT") else {}
            code, data, headers = self.api(method, path, body, conn)
            conn.commit()
            self.send_json(code, data, headers)
        except ApiError as e:
            self.send_json(e.code, {"error": str(e)})
        except Exception as e:  # pragma: no cover
            print("Server error:", e)
            self.send_json(500, {"error": "Something went wrong on the server."})
        finally:
            conn.close()

    # ---- API
    def api(self, method, path, b, conn):
        # ---------- auth ----------
        if path == "/api/register" and method == "POST":
            name = (b.get("name") or "").strip()[:60]
            email = (b.get("email") or "").strip().lower()
            pw = b.get("password") or ""
            if not name:
                raise ApiError(400, "Please enter your name.")
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                raise ApiError(400, "Please enter a valid email address.")
            if len(pw) < 6:
                raise ApiError(400, "Password must be at least 6 characters.")
            if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                raise ApiError(409, "An account with this email already exists.")
            salt = secrets.token_hex(16)
            cur = conn.execute(
                "INSERT INTO users(name,email,salt,pw,created) VALUES(?,?,?,?,?)",
                (name, email, salt, hash_pw(pw, salt), date.today().isoformat()),
            )
            audit(conn, cur.lastrowid, "register", "")
            return self.start_session(conn, cur.lastrowid, name, email)

        if path == "/api/login" and method == "POST":
            email = (b.get("email") or "").strip().lower()
            key = email + "|" + self.client_address[0]
            if too_many_fails(key):
                audit(conn, None, "login_blocked", email)
                conn.commit()
                raise ApiError(429, "Too many failed attempts. Please wait 5 minutes and try again.")
            u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not u or not secrets.compare_digest(u["pw"], hash_pw(b.get("password") or "", u["salt"])):
                note_fail(key)
                audit(conn, u["id"] if u else None, "login_failed", email)
                conn.commit()
                raise ApiError(401, "Incorrect email or password.")
            clear_fails(key)
            conn.execute("DELETE FROM sessions WHERE expires < ?", (now_iso(),))  # tidy old sessions
            audit(conn, u["id"], "login_ok", "")
            return self.start_session(conn, u["id"], u["name"], u["email"])

        if path == "/api/logout" and method == "POST":
            who = self.current_user(conn)
            if who:
                audit(conn, who["id"], "logout", "")
            raw = self.headers.get("Cookie")
            if raw:
                c = SimpleCookie()
                c.load(raw)
                if "dt_session" in c:
                    conn.execute("DELETE FROM sessions WHERE token=?", (c["dt_session"].value,))
            return 200, {"ok": True}, {"Set-Cookie": "dt_session=; Path=/; Max-Age=0"}

        user = self.current_user(conn)
        if not user:
            raise ApiError(401, "Please log in.")

        if path == "/api/me" and method == "GET":
            return 200, {"name": user["name"], "email": user["email"]}, {}

        # [DP-900] Analytical-style queries (GROUP BY aggregates) on top of transactional data.
        if path == "/api/analytics" and method == "GET":
            uid = user["id"]
            by_category = conn.execute(
                "SELECT category, COUNT(*) AS n FROM docs WHERE user_id=? GROUP BY category ORDER BY n DESC", (uid,)
            ).fetchall()
            by_status = conn.execute(
                "SELECT status, COUNT(*) AS n FROM v_doc_status WHERE user_id=? GROUP BY status", (uid,)
            ).fetchall()
            by_month = conn.execute(
                "SELECT strftime('%Y-%m', expiry) AS month, COUNT(*) AS n FROM docs "
                "WHERE user_id=? AND expiry >= date('now') AND expiry < date('now','+12 months') "
                "GROUP BY month ORDER BY month", (uid,)
            ).fetchall()
            renewals = conn.execute(
                "SELECT COUNT(*) FROM renewals r JOIN docs d ON d.id=r.doc_id WHERE d.user_id=?", (uid,)
            ).fetchone()[0]
            return 200, {
                "by_category": [dict(r) for r in by_category],
                "by_status": [dict(r) for r in by_status],
                "by_month": [dict(r) for r in by_month],
                "renewals": renewals,
            }, {}

        if path == "/api/audit" and method == "GET":
            rows = conn.execute(
                "SELECT event, detail, at FROM audit_log WHERE user_id=? ORDER BY id DESC LIMIT 12", (user["id"],)
            ).fetchall()
            return 200, [dict(r) for r in rows], {}

        # [DP-900] Semi-structured (JSON) export of relational data
        if path == "/api/export" and method == "GET":
            rows = conn.execute("SELECT * FROM docs WHERE user_id=? ORDER BY expiry", (user["id"],)).fetchall()
            audit(conn, user["id"], "data_exported", "%d documents" % len(rows))
            return 200, {
                "user": {"name": user["name"], "email": user["email"]},
                "exported_at": now_iso() + "Z",
                "documents": [doc_dict(r) for r in rows],
            }, {}

        # ---------- documents ----------
        if path == "/api/docs" and method == "GET":
            rows = conn.execute("SELECT * FROM docs WHERE user_id=? ORDER BY expiry ASC", (user["id"],)).fetchall()
            return 200, [doc_dict(r) for r in rows], {}

        if path == "/api/docs" and method == "POST":
            name, cat, number, expiry, notes = clean_doc(b)
            conn.execute(
                "INSERT INTO docs(user_id,name,category,number,expiry,notes,created) VALUES(?,?,?,?,?,?,?)",
                (user["id"], name, cat, number, expiry, notes, date.today().isoformat()),
            )
            audit(conn, user["id"], "doc_added", name)
            return 201, {"ok": True}, {}

        if path == "/api/seed" and method == "POST":
            t = date.today()
            samples = [
                ("Student ID Card", "Identity", "STU-2023-1187", t + timedelta(days=-12), "Visit the admin office for a replacement."),
                ("Library Membership", "Identity", "LIB-55021", t + timedelta(days=5), "Renew at the library desk."),
                ("Learner's Driving Licence", "Licence", "DL-UP32-8841", t + timedelta(days=18), "Apply online before it lapses."),
                ("Health Insurance", "Insurance", "HLT-90210", t + timedelta(days=-40), "Policy from the university plan."),
                ("Exam Hall Ticket", "Certificate", "HT-2026-044", t + timedelta(days=60), ""),
                ("Bonafide Certificate", "Certificate", "BON-778", t + timedelta(days=200), "Needed for scholarship forms."),
                ("Passport", "Passport / Visa", "P1234567", t + timedelta(days=640), "Valid for 10 years."),
            ]
            for n, c, num, exp, notes in samples:
                conn.execute(
                    "INSERT INTO docs(user_id,name,category,number,expiry,notes,created) VALUES(?,?,?,?,?,?,?)",
                    (user["id"], n, c, num, exp.isoformat(), notes, t.isoformat()),
                )
            audit(conn, user["id"], "sample_data", "7 documents")
            return 201, {"ok": True}, {}

        m = re.fullmatch(r"/api/docs/(\d+)(/renew)?", path)
        if m:
            doc_id, renew = int(m.group(1)), bool(m.group(2))
            # [SECURITY] Authorisation: "AND user_id=?" means nobody can touch another user's document
            row = conn.execute("SELECT * FROM docs WHERE id=? AND user_id=?", (doc_id, user["id"])).fetchone()
            if not row:
                raise ApiError(404, "Document not found.")
            if renew and method == "POST":
                try:
                    new_exp = date.fromisoformat((b.get("expiry") or "").strip())
                except ValueError:
                    raise ApiError(400, "Please choose a valid new expiry date.")
                if new_exp <= date.today():
                    raise ApiError(400, "The new expiry date must be in the future.")
                # [DBMS] ONE TRANSACTION (ACID): update + history row + audit row are saved together,
                # or not at all. If anything fails, the database rolls back to the previous state.
                conn.execute(
                    "UPDATE docs SET expiry=?, renewed_count=renewed_count+1, last_renewed=? WHERE id=?",
                    (new_exp.isoformat(), date.today().isoformat(), doc_id),
                )
                conn.execute(
                    "INSERT INTO renewals(doc_id,old_expiry,new_expiry,renewed_on) VALUES(?,?,?,?)",
                    (doc_id, row["expiry"], new_exp.isoformat(), date.today().isoformat()),
                )
                audit(conn, user["id"], "doc_renewed", row["name"])
                return 200, {"ok": True}, {}
            if not renew and method == "PUT":
                name, cat, number, expiry, notes = clean_doc(b)
                conn.execute(
                    "UPDATE docs SET name=?,category=?,number=?,expiry=?,notes=? WHERE id=?",
                    (name, cat, number, expiry, notes, doc_id),
                )
                audit(conn, user["id"], "doc_edited", name)
                return 200, {"ok": True}, {}
            if not renew and method == "DELETE":
                conn.execute("DELETE FROM docs WHERE id=?", (doc_id,))  # renewals are removed by ON DELETE CASCADE
                audit(conn, user["id"], "doc_deleted", row["name"])
                return 200, {"ok": True}, {}

        raise ApiError(404, "Not found.")

    def start_session(self, conn, user_id, name, email):
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
        conn.execute("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)", (token, user_id, expires))
        cookie = "dt_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000" % token
        return 200, {"name": name, "email": email}, {"Set-Cookie": cookie}


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    init_db()
    server = None
    port = 8000
    while port < 8020:
        try:
            server = Server(("127.0.0.1", port), Handler)
            break
        except OSError:
            port += 1
    if server is None:
        print("Could not find a free port. Close other programs and try again.")
        return
    url = "http://localhost:%d" % port
    print("\n  DocuTrack is running!  ->  %s" % url)
    print("  (Press Ctrl + C in this terminal to stop)\n")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped. Bye!")
        server.server_close()


# ----------------------------------------------------------------------------
# The whole front-end (HTML + CSS + JavaScript) lives in this one string
# ----------------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DocuTrack - Never miss a renewal</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📑</text></svg>">
<style>
:root{
  --primary:#6366f1; --primary-d:#4f46e5; --ink:#1e1b4b; --muted:#6b7280;
  --bg:#f3f4fb; --card:#ffffff; --line:#e8eaf3;
  --ok:#10b981; --warn:#f59e0b; --bad:#ef4444;
  --ok-bg:#d1fae5; --warn-bg:#fef3c7; --bad-bg:#fee2e2;
  --radius:18px; --shadow:0 10px 30px -12px rgba(49,46,129,.25);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:"Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);-webkit-font-smoothing:antialiased}
button{font:inherit;cursor:pointer;border:none}
input,select,textarea{font:inherit;color:inherit}
[hidden]{display:none!important}

/* ---------- Auth screen ---------- */
#auth{min-height:100vh;display:grid;grid-template-columns:1.1fr 1fr}
.hero{position:relative;overflow:hidden;color:#fff;padding:56px;display:flex;flex-direction:column;justify-content:space-between;
  background:linear-gradient(135deg,#1e1b4b 0%,#4338ca 55%,#7c3aed 100%)}
.hero::before,.hero::after{content:"";position:absolute;border-radius:50%;filter:blur(60px);opacity:.55;animation:float 9s ease-in-out infinite}
.hero::before{width:340px;height:340px;background:#22d3ee;top:-80px;right:-60px}
.hero::after{width:300px;height:300px;background:#f472b6;bottom:-90px;left:-50px;animation-delay:-4s}
@keyframes float{50%{transform:translate(30px,25px) scale(1.1)}}
.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:26px;letter-spacing:-.5px;position:relative;z-index:1}
.logo{width:44px;height:44px;border-radius:14px;background:rgba(255,255,255,.18);display:grid;place-items:center;font-size:24px;backdrop-filter:blur(6px);border:1px solid rgba(255,255,255,.3)}
.hero h1{font-size:46px;line-height:1.1;letter-spacing:-1.5px;margin-bottom:18px;position:relative;z-index:1}
.hero p.lead{font-size:18px;opacity:.88;max-width:440px;line-height:1.55;position:relative;z-index:1}
.perks{list-style:none;display:grid;gap:12px;margin-top:30px;position:relative;z-index:1}
.perks li{display:flex;align-items:center;gap:12px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.2);padding:12px 16px;border-radius:14px;backdrop-filter:blur(6px);max-width:420px}
.hero small{opacity:.7;position:relative;z-index:1}
.auth-side{display:grid;place-items:center;padding:32px;background:#fff}
.auth-card{width:100%;max-width:400px}
.auth-card h2{font-size:30px;letter-spacing:-.8px;margin-bottom:6px}
.auth-card .sub{color:var(--muted);margin-bottom:24px}
.tabs{display:flex;background:var(--bg);padding:5px;border-radius:14px;margin-bottom:22px}
.tabs button{flex:1;padding:10px;border-radius:10px;background:transparent;color:var(--muted);font-weight:600;transition:.2s}
.tabs button.on{background:#fff;color:var(--primary-d);box-shadow:0 2px 8px rgba(0,0,0,.08)}
.field{margin-bottom:15px}
.field label{display:block;font-size:13px;font-weight:600;margin-bottom:6px;color:#374151}
.field input,.field select,.field textarea{width:100%;padding:12px 14px;border:1.5px solid var(--line);border-radius:12px;background:#fafbff;outline:none;transition:.15s}
.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(99,102,241,.15);background:#fff}
.btn{padding:12px 20px;border-radius:12px;font-weight:700;transition:.15s;display:inline-flex;align-items:center;justify-content:center;gap:8px}
.btn-primary{background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff;box-shadow:0 8px 20px -8px rgba(99,102,241,.8)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 12px 24px -8px rgba(99,102,241,.9)}
.btn-ghost{background:var(--bg);color:var(--ink)}
.btn-ghost:hover{background:#e6e8f5}
.btn-block{width:100%;padding:14px}
.err{background:var(--bad-bg);color:#b91c1c;padding:10px 14px;border-radius:10px;font-size:14px;margin-bottom:14px}

/* ---------- App layout ---------- */
#app{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
aside{background:linear-gradient(180deg,#1e1b4b,#312e81);color:#fff;padding:26px 18px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
aside .brand{font-size:22px;margin-bottom:34px;padding:0 8px}
aside .logo{width:38px;height:38px;font-size:20px}
nav{display:grid;gap:6px}
nav button{display:flex;align-items:center;gap:12px;padding:13px 14px;border-radius:12px;background:transparent;color:rgba(255,255,255,.7);font-weight:600;text-align:left;transition:.15s}
nav button:hover{background:rgba(255,255,255,.08);color:#fff}
nav button.on{background:rgba(255,255,255,.16);color:#fff}
nav .badge{margin-left:auto;background:var(--bad);color:#fff;font-size:12px;padding:2px 9px;border-radius:99px}
.me{margin-top:auto;background:rgba(255,255,255,.1);border-radius:16px;padding:14px;display:flex;align-items:center;gap:12px}
.avatar{width:40px;height:40px;border-radius:50%;background:linear-gradient(135deg,#22d3ee,#a78bfa);display:grid;place-items:center;font-weight:800;flex:none}
.me .who{min-width:0;flex:1}
.me .who b{display:block;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.me .who span{font-size:12px;opacity:.65;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
.me button{background:rgba(255,255,255,.15);color:#fff;border-radius:10px;padding:8px 10px;font-size:13px}
.me button:hover{background:rgba(255,255,255,.28)}
main{padding:34px 40px 60px;max-width:1200px;width:100%}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:26px}
.topbar h1{font-size:30px;letter-spacing:-.9px}
.topbar p{color:var(--muted);margin-top:4px}

/* ---------- Stat cards ---------- */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat{background:var(--card);border-radius:var(--radius);padding:20px;box-shadow:var(--shadow);position:relative;overflow:hidden;cursor:pointer;transition:.2s;border:1px solid var(--line)}
.stat:hover{transform:translateY(-4px)}
.stat .ico{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-size:20px;margin-bottom:14px}
.stat .num{font-size:36px;font-weight:800;letter-spacing:-1px;line-height:1}
.stat .lbl{color:var(--muted);font-size:14px;margin-top:6px;font-weight:600}
.stat.s-total .ico{background:#e0e7ff}.stat.s-ok .ico{background:var(--ok-bg)}.stat.s-soon .ico{background:var(--warn-bg)}.stat.s-bad .ico{background:var(--bad-bg)}
.stat.s-ok .num{color:var(--ok)}.stat.s-soon .num{color:#d97706}.stat.s-bad .num{color:var(--bad)}

/* ---------- Panels ---------- */
.grid2{display:grid;grid-template-columns:1.5fr 1fr;gap:20px;margin-bottom:24px}
.panel{background:var(--card);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);border:1px solid var(--line)}
.panel h3{font-size:18px;letter-spacing:-.3px;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.panel .hint{color:var(--muted);font-size:13px;margin-bottom:16px}
.alert{display:flex;align-items:center;gap:14px;padding:14px 16px;border-radius:14px;margin-bottom:10px;border:1px solid transparent;animation:pop .4s ease both}
@keyframes pop{from{opacity:0;transform:translateY(8px)}}
.alert.expired{background:var(--bad-bg);border-color:#fecaca}
.alert.soon{background:var(--warn-bg);border-color:#fde68a}
.alert .txt{flex:1;min-width:0}
.alert .txt b{display:block}
.alert .txt span{font-size:13px;color:#4b5563}
.alert .btn{padding:8px 14px;font-size:14px;background:#fff;color:var(--ink);box-shadow:0 2px 6px rgba(0,0,0,.08)}
.alert .btn:hover{background:var(--ink);color:#fff}
.allgood{text-align:center;padding:30px 10px;color:var(--muted)}
.allgood .big{font-size:48px;margin-bottom:8px}
.donut-wrap{display:grid;place-items:center;margin:8px 0 20px}
.donut{width:180px;height:180px;border-radius:50%;display:grid;place-items:center;transition:.4s}
.donut .hole{width:120px;height:120px;border-radius:50%;background:#fff;display:grid;place-items:center;text-align:center}
.donut .hole b{font-size:34px;line-height:1;display:block}
.donut .hole span{font-size:12px;color:var(--muted)}
.legend{display:grid;gap:8px;font-size:14px}
.legend div{display:flex;align-items:center;gap:10px}
.legend i{width:12px;height:12px;border-radius:4px;display:inline-block}
.legend b{margin-left:auto}
.timeline{display:grid;gap:0}
.tl{display:flex;gap:16px;align-items:center;padding:12px 0;border-bottom:1px dashed var(--line)}
.tl:last-child{border:none}
.datebox{width:54px;text-align:center;border-radius:12px;padding:6px 0;background:var(--bg);flex:none}
.datebox b{display:block;font-size:20px;line-height:1.1}
.datebox span{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:700;letter-spacing:.5px}
.tl .info{flex:1;min-width:0}
.tl .info b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tl .info span{font-size:13px;color:var(--muted)}

/* ---------- Chips and doc cards ---------- */
.chip{display:inline-block;padding:4px 11px;border-radius:99px;font-size:12px;font-weight:700}
.chip.active{background:var(--ok-bg);color:#047857}
.chip.soon{background:var(--warn-bg);color:#b45309}
.chip.expired{background:var(--bad-bg);color:#b91c1c}
.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:20px}
.filters{display:flex;gap:8px;flex-wrap:wrap}
.filters button{padding:9px 16px;border-radius:99px;background:#fff;border:1.5px solid var(--line);font-weight:600;color:var(--muted);transition:.15s}
.filters button:hover{border-color:var(--primary);color:var(--primary)}
.filters button.on{background:var(--ink);border-color:var(--ink);color:#fff}
.search{margin-left:auto;padding:10px 16px;border:1.5px solid var(--line);border-radius:99px;min-width:240px;outline:none;background:#fff}
.search:focus{border-color:var(--primary)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:18px}
.dcard{background:var(--card);border-radius:var(--radius);padding:20px 20px 16px;box-shadow:var(--shadow);border:1px solid var(--line);position:relative;overflow:hidden;transition:.2s;animation:pop .4s ease both}
.dcard:hover{transform:translateY(-4px)}
.dcard::before{content:"";position:absolute;left:0;top:0;bottom:0;width:6px}
.dcard.active::before{background:var(--ok)}.dcard.soon::before{background:var(--warn)}.dcard.expired::before{background:var(--bad)}
.dhead{display:flex;gap:14px;align-items:center;margin-bottom:14px}
.dico{width:48px;height:48px;border-radius:14px;background:var(--bg);display:grid;place-items:center;font-size:24px;flex:none}
.dhead .t{min-width:0;flex:1}
.dhead .t b{display:block;font-size:17px;letter-spacing:-.3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dhead .t span{font-size:13px;color:var(--muted)}
.meta{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.meta .when{font-size:14px;color:#374151}
.meta .when small{display:block;color:var(--muted);font-size:12px}
.bar{height:7px;background:var(--bg);border-radius:99px;overflow:hidden;margin-bottom:12px}
.bar i{display:block;height:100%;border-radius:99px}
.active .bar i{background:var(--ok)}.soon .bar i{background:var(--warn)}.expired .bar i{background:var(--bad)}
.note{font-size:13px;color:var(--muted);margin-bottom:12px;background:var(--bg);padding:8px 12px;border-radius:10px}
.renewed-tag{font-size:12px;color:#6d28d9;background:#ede9fe;display:inline-block;padding:3px 10px;border-radius:99px;font-weight:700;margin-bottom:12px}
.acts{display:flex;gap:8px}
.acts .btn{padding:9px 12px;font-size:14px;flex:1}
.acts .renew{background:var(--ink);color:#fff;flex:2}
.acts .renew:hover{background:var(--primary-d)}
.acts .ico-btn{flex:none;width:40px;background:var(--bg)}
.acts .ico-btn:hover{background:#e6e8f5}
.acts .del:hover{background:var(--bad-bg)}
.empty{grid-column:1/-1;text-align:center;padding:60px 20px;background:#fff;border-radius:var(--radius);border:2px dashed var(--line)}
.empty .big{font-size:56px;margin-bottom:10px}
.empty p{color:var(--muted);margin:6px 0 20px}
.empty .row{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}

/* ---------- Modal + toast ---------- */
dialog{border:none;border-radius:22px;padding:28px;width:min(480px,94vw);box-shadow:0 30px 80px -20px rgba(30,27,75,.5);margin:auto;animation:pop .25s ease}
dialog::backdrop{background:rgba(30,27,75,.55);backdrop-filter:blur(3px)}
dialog h3{font-size:22px;letter-spacing:-.5px;margin-bottom:4px}
dialog .sub{color:var(--muted);margin-bottom:20px;font-size:14px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.mact{display:flex;gap:10px;justify-content:flex-end;margin-top:8px}
.quick{display:flex;gap:8px;margin-top:10px}
.quick button{padding:7px 14px;border-radius:99px;background:var(--bg);font-weight:600;font-size:13px}
.quick button:hover{background:var(--primary);color:#fff}
#toast{position:fixed;bottom:26px;left:50%;transform:translate(-50%,120px);background:var(--ink);color:#fff;padding:14px 22px;border-radius:14px;font-weight:600;box-shadow:0 14px 40px rgba(0,0,0,.3);transition:.35s;z-index:99}
#toast.show{transform:translate(-50%,0)}

.sm{display:block;font-size:13px;font-weight:700;margin:14px 0 8px;color:#374151}
.barrow{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}
.barrow span{width:130px;flex:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.barrow .track{flex:1;height:10px;background:var(--bg);border-radius:99px;overflow:hidden}
.barrow .track i{display:block;height:100%;background:linear-gradient(90deg,var(--primary),#a78bfa);border-radius:99px;transition:.5s}
.barrow b{width:24px;text-align:right}
.logrow{display:flex;gap:12px;align-items:center;padding:10px 0;border-bottom:1px dashed var(--line);font-size:14px}
.logrow:last-child{border:none}
.logrow small{display:block;color:var(--muted);font-size:12px}
.flow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:6px 0 10px}
.flow .node{flex:1;min-width:150px;background:var(--bg);border-radius:14px;padding:14px;text-align:center;font-weight:700;font-size:14px}
.flow .node small{display:block;font-weight:500;color:var(--muted);margin-top:4px}
.flow .arrow{font-size:22px;color:var(--primary)}
.cloudmap{background:#eef2ff;border-radius:12px;padding:12px 14px;font-size:13px;margin-bottom:18px;color:#3730a3;line-height:1.5}
.concepts{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}
.concept{border:1px solid var(--line);border-radius:16px;padding:16px}
.concept h4{font-size:15px;margin-bottom:8px}
.concept ul{padding-left:18px;font-size:13px;color:#4b5563;display:grid;gap:5px}
.concept code{background:var(--bg);padding:1px 6px;border-radius:6px;font-size:12px}
.actrow{margin-top:18px}
@media (max-width:980px){
  #auth{grid-template-columns:1fr}.hero{display:none}
  #app{grid-template-columns:1fr}
  aside{position:static;height:auto;flex-direction:row;align-items:center;padding:14px;gap:12px;flex-wrap:wrap}
  aside .brand{margin:0}nav{display:flex}.me{margin:0 0 0 auto;padding:8px}.me .who{display:none}
  main{padding:22px 16px 50px}
  .stats{grid-template-columns:1fr 1fr}.grid2,.grid2.even,.concepts{grid-template-columns:1fr}
  .search{margin-left:0;width:100%}
}
</style>
</head>
<body>

<!-- ===================== AUTH ===================== -->
<section id="auth" hidden>
  <div class="hero">
    <div class="brand"><div class="logo">📑</div>DocuTrack</div>
    <div>
      <h1>Never miss a<br>document renewal again.</h1>
      <p class="lead">One smart place for your ID cards, certificates and licences. See what is expiring before it becomes a problem.</p>
      <ul class="perks">
        <li>🔔 <span>Smart reminders on your dashboard</span></li>
        <li>🟢 <span>Active vs expired at a glance</span></li>
        <li>✅ <span>Mark documents as renewed in one click</span></li>
      </ul>
    </div>
    <small>Built for students. Simple, fast and private.</small>
  </div>
  <div class="auth-side">
    <div class="auth-card">
      <h2 id="authTitle">Welcome back 👋</h2>
      <p class="sub" id="authSub">Log in to see your document dashboard.</p>
      <div class="tabs">
        <button id="tabLogin" class="on" data-action="authTab" data-mode="login">Log in</button>
        <button id="tabReg" data-action="authTab" data-mode="register">Sign up</button>
      </div>
      <div id="authErr" class="err" hidden></div>
      <div class="field" id="nameField" hidden><label>Full name</label><input id="aName" placeholder="e.g. Aarav Sharma" autocomplete="name"></div>
      <div class="field"><label>Email</label><input id="aEmail" type="email" placeholder="you@college.edu" autocomplete="email"></div>
      <div class="field"><label>Password</label><input id="aPass" type="password" placeholder="At least 6 characters" autocomplete="current-password"></div>
      <button class="btn btn-primary btn-block" id="authBtn" data-action="authSubmit">Log in</button>
    </div>
  </div>
</section>

<!-- ===================== APP ===================== -->
<div id="app" hidden>
  <aside>
    <div class="brand"><div class="logo">📑</div>DocuTrack</div>
    <nav>
      <button data-action="view" data-view="dashboard" class="on">🏠 Dashboard</button>
      <button data-action="view" data-view="documents">🗂️ My Documents <span class="badge" id="navBadge" hidden></span></button>
      <button data-action="view" data-view="insights">🧠 Insights &amp; Design</button>
    </nav>
    <div class="me">
      <div class="avatar" id="avatar">A</div>
      <div class="who"><b id="meName"></b><span id="meEmail"></span></div>
      <button data-action="logout" title="Log out">Logout</button>
    </div>
  </aside>

  <main>
    <div class="topbar">
      <div><h1 id="pageTitle">Dashboard</h1><p id="pageSub"></p></div>
      <button class="btn btn-primary" data-action="add">＋ Add document</button>
    </div>

    <!-- Dashboard view -->
    <div id="vDash">
      <div class="stats">
        <div class="stat s-total" data-action="goFilter" data-f="all"><div class="ico">📚</div><div class="num" id="nTotal">0</div><div class="lbl">Total documents</div></div>
        <div class="stat s-ok" data-action="goFilter" data-f="active"><div class="ico">✅</div><div class="num" id="nOk">0</div><div class="lbl">Active</div></div>
        <div class="stat s-soon" data-action="goFilter" data-f="soon"><div class="ico">⏳</div><div class="num" id="nSoon">0</div><div class="lbl">Expiring soon</div></div>
        <div class="stat s-bad" data-action="goFilter" data-f="expired"><div class="ico">⚠️</div><div class="num" id="nBad">0</div><div class="lbl">Expired</div></div>
      </div>

      <div class="grid2">
        <div class="panel">
          <h3>🔔 Reminders</h3>
          <p class="hint">Documents that need your attention right now.</p>
          <div id="reminders"></div>
        </div>
        <div class="panel">
          <h3>📊 Document health</h3>
          <p class="hint">Overall status of your records.</p>
          <div class="donut-wrap"><div class="donut" id="donut"><div class="hole"><div><b id="dTotal">0</b><span>documents</span></div></div></div></div>
          <div class="legend">
            <div><i style="background:var(--ok)"></i>Active<b id="lgOk">0</b></div>
            <div><i style="background:var(--warn)"></i>Expiring soon<b id="lgSoon">0</b></div>
            <div><i style="background:var(--bad)"></i>Expired<b id="lgBad">0</b></div>
          </div>
        </div>
      </div>

      <div class="panel">
        <h3>📅 Upcoming deadlines</h3>
        <p class="hint" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <span>Your next expiry dates, soonest first.</span>
          <span>Remind me within
            <select id="winSel" style="padding:5px 8px;border-radius:8px;border:1.5px solid var(--line)">
              <option value="15">15 days</option><option value="30">30 days</option>
              <option value="60">60 days</option><option value="90">90 days</option>
            </select></span>
        </p>
        <div class="timeline" id="timeline"></div>
      </div>
    </div>

    <!-- Documents view -->
    <div id="vDocs" hidden>
      <div class="toolbar">
        <div class="filters" id="filters">
          <button data-action="filter" data-f="all" class="on">All</button>
          <button data-action="filter" data-f="active">Active</button>
          <button data-action="filter" data-f="soon">Expiring soon</button>
          <button data-action="filter" data-f="expired">Expired</button>
        </div>
        <input class="search" id="search" placeholder="🔍  Search documents...">
      </div>
      <div class="cards" id="cards"></div>
    </div>

    <!-- Insights view: analytics + security + concept map -->
    <div id="vInsights" hidden>
      <div class="grid2 even">
        <div class="panel">
          <h3>📈 Analytics</h3>
          <p class="hint">Calculated by the database with SQL <code>GROUP BY</code> queries.</p>
          <b class="sm">Documents by category</b><div id="chCat"></div>
          <b class="sm">Expiries in the next 12 months</b><div id="chMonth"></div>
          <div class="actrow"><span id="renCount" class="chip active" style="margin-right:10px"></span>
            <button class="btn btn-ghost" data-action="export">⬇️ Export my data (JSON)</button></div>
        </div>
        <div class="panel">
          <h3>🛡️ Security activity</h3>
          <p class="hint">Audit log: recent actions on your account.</p>
          <div id="auditList"></div>
        </div>
      </div>

      <div class="panel" style="margin-bottom:24px">
        <h3>🏗️ How DocuTrack is built</h3>
        <p class="hint">A quick concept map: DBMS, DP-900, system design and cloud security.</p>
        <div class="flow">
          <div class="node">🖥️ Browser UI<small>HTML · CSS · JavaScript</small></div><div class="arrow">⇄</div>
          <div class="node">⚙️ REST API<small>Python · JSON · sessions</small></div><div class="arrow">⇄</div>
          <div class="node">🗄️ Relational DB<small>SQLite · SQL</small></div>
        </div>
        <div class="cloudmap">☁️ <b>Same design on Azure:</b> Static Web Apps / App Service (UI + API) → <b>Azure SQL Database</b> (data) · <b>Key Vault</b> (secrets) · <b>Microsoft Entra ID</b> (login) · <b>Azure Monitor</b> (logs and alerts)</div>
        <div class="concepts">
          <div class="concept"><h4>🗃️ DBMS</h4><ul>
            <li>Tables linked by <b>primary and foreign keys</b> (users → docs → renewals)</li>
            <li><b>Constraints</b>: <code>UNIQUE</code>, <code>NOT NULL</code>, <code>CHECK</code></li>
            <li><b>Index</b> on <code>(user_id, expiry)</code> for fast lookups</li>
            <li>A <b>VIEW</b> (<code>v_doc_status</code>) computes status in SQL</li>
            <li>Renewing is one <b>transaction</b> (ACID: all or nothing)</li></ul></div>
          <div class="concept"><h4>📘 DP-900 (Azure Data Fundamentals)</h4><ul>
            <li><b>Relational data</b> with an <b>OLTP</b> (transactional) workload</li>
            <li><b>DDL</b> (CREATE TABLE) and <b>DML</b> (INSERT, UPDATE, DELETE, SELECT)</li>
            <li><b>Analytics</b> with <code>GROUP BY</code> aggregates (above)</li>
            <li><b>JSON export</b> = semi-structured data</li>
            <li>Cloud equivalent: <b>Azure SQL Database</b></li></ul></div>
          <div class="concept"><h4>📐 System design</h4><ul>
            <li><b>3-tier</b> client-server architecture</li>
            <li><b>Stateless REST API</b> exchanging JSON</li>
            <li><b>Separation of concerns</b>: UI, API and data layers</li>
            <li>Scales up by swapping SQLite for Azure SQL and running several API copies behind a load balancer</li></ul></div>
          <div class="concept"><h4>🔐 Cloud security</h4><ul>
            <li><b>Salted password hashing</b> (PBKDF2); no plain-text passwords</li>
            <li><b>SQL injection</b> blocked with parameterised queries; <b>XSS</b> blocked by escaping + CSP header</li>
            <li><b>HttpOnly + SameSite cookies</b>, expiring sessions</li>
            <li><b>Least privilege</b>: every query is filtered by <code>user_id</code></li>
            <li><b>Rate limiting</b> on login and an <b>audit log</b></li>
            <li>Shared responsibility: the cloud secures the platform, you secure the app, identities and data</li></ul></div>
        </div>
      </div>
    </div>
  </main>
</div>

<!-- ===================== MODALS ===================== -->
<dialog id="docModal">
  <h3 id="mTitle">Add a document</h3>
  <p class="sub">Keep the details handy so you never have to search for them.</p>
  <div id="mErr" class="err" hidden></div>
  <div class="field"><label>Document name *</label><input id="fName" placeholder="e.g. Student ID Card" maxlength="80"></div>
  <div class="two">
    <div class="field"><label>Category</label><select id="fCat"></select></div>
    <div class="field"><label>Expiry date *</label><input id="fExp" type="date"></div>
  </div>
  <div class="field"><label>Document / ID number (optional)</label><input id="fNum" placeholder="e.g. STU-2026-1187" maxlength="60"></div>
  <div class="field"><label>Notes (optional)</label><textarea id="fNotes" rows="2" placeholder="Where to renew, fees, etc." maxlength="300"></textarea></div>
  <div class="mact">
    <button class="btn btn-ghost" data-action="closeModal">Cancel</button>
    <button class="btn btn-primary" data-action="saveDoc">Save document</button>
  </div>
</dialog>

<dialog id="renewModal">
  <h3>✅ Mark as renewed</h3>
  <p class="sub" id="rSub"></p>
  <div id="rErr" class="err" hidden></div>
  <div class="field"><label>New expiry date</label><input id="rExp" type="date"></div>
  <div class="quick">
    <button data-action="quickYears" data-y="1">+1 year</button>
    <button data-action="quickYears" data-y="2">+2 years</button>
    <button data-action="quickYears" data-y="5">+5 years</button>
    <button data-action="quickYears" data-y="10">+10 years</button>
  </div>
  <div class="mact" style="margin-top:20px">
    <button class="btn btn-ghost" data-action="closeModal">Cancel</button>
    <button class="btn btn-primary" data-action="confirmRenew">Confirm renewal</button>
  </div>
</dialog>

<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const ICONS = {"Identity":"🪪","Certificate":"🎓","Licence":"🚗","Passport / Visa":"🛂","Insurance":"🛡️","Other":"📄"};
const CATS = Object.keys(ICONS);
let docs = [], me = null, view = "dashboard", filter = "all", query = "";
let WINDOW = parseInt(localStorage.getItem("dt_win") || "30", 10);
let editingId = null, renewId = null, authMode = "login";

/* ---------- helpers ---------- */
async function api(path, method = "GET", body) {
  const r = await fetch(path, { method, headers: {"Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "Something went wrong.");
  return d;
}
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function parse(iso) { const [y, m, d] = iso.split("-").map(Number); return new Date(y, m - 1, d); }
function daysLeft(iso) {
  const [y, m, d] = iso.split("-").map(Number), t = new Date();
  return Math.round((Date.UTC(y, m - 1, d) - Date.UTC(t.getFullYear(), t.getMonth(), t.getDate())) / 864e5);
}
function statusOf(d) { const n = daysLeft(d.expiry); return n < 0 ? "expired" : n <= WINDOW ? "soon" : "active"; }
function fmt(iso) { return parse(iso).toLocaleDateString("en-IN", {day: "numeric", month: "short", year: "numeric"}); }
function plural(n, w) { return n + " " + w + (n === 1 ? "" : "s"); }
function whenText(d) {
  const n = daysLeft(d.expiry);
  if (n < 0) return "Expired " + plural(-n, "day") + " ago";
  if (n === 0) return "Expires today!";
  if (n > 365) return "In " + (n / 365).toFixed(1) + " years";
  return plural(n, "day") + " left";
}
function addYears(iso, y) {
  const base = daysLeft(iso) < 0 ? new Date() : parse(iso);
  base.setFullYear(base.getFullYear() + y);
  return base.getFullYear() + "-" + String(base.getMonth() + 1).padStart(2, "0") + "-" + String(base.getDate()).padStart(2, "0");
}
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("show"), 2600);
}

/* ---------- boot ---------- */
async function boot() {
  try { me = await api("/api/me"); await enterApp(); }
  catch (e) { $("#auth").hidden = false; $("#app").hidden = true; }
}
async function enterApp() {
  $("#auth").hidden = true; $("#app").hidden = false;
  $("#meName").textContent = me.name; $("#meEmail").textContent = me.email;
  $("#avatar").textContent = me.name.trim()[0].toUpperCase();
  $("#fCat").innerHTML = CATS.map(c => `<option>${c}</option>`).join("");
  $("#winSel").value = String(WINDOW);
  await load();
}
async function load() { docs = await api("/api/docs"); render(); }

/* ---------- render ---------- */
function render() {
  const sets = {active: [], soon: [], expired: []};
  docs.forEach(d => sets[statusOf(d)].push(d));
  const total = docs.length, ok = sets.active.length, soon = sets.soon.length, bad = sets.expired.length;

  $("#nTotal").textContent = total; $("#nOk").textContent = ok; $("#nSoon").textContent = soon; $("#nBad").textContent = bad;
  $("#dTotal").textContent = total; $("#lgOk").textContent = ok; $("#lgSoon").textContent = soon; $("#lgBad").textContent = bad;
  const nb = $("#navBadge"); nb.hidden = (bad + soon) === 0; nb.textContent = bad + soon;

  // donut
  if (!total) { $("#donut").style.background = "#eceefb"; }
  else {
    const a = ok / total * 100, b = a + soon / total * 100;
    $("#donut").style.background = `conic-gradient(var(--ok) 0 ${a}%, var(--warn) ${a}% ${b}%, var(--bad) ${b}% 100%)`;
  }

  // reminders
  const urgent = [...sets.expired.sort((x, y) => x.expiry.localeCompare(y.expiry)), ...sets.soon.sort((x, y) => x.expiry.localeCompare(y.expiry))];
  $("#reminders").innerHTML = urgent.length ? urgent.map(d => {
    const s = statusOf(d), n = daysLeft(d.expiry);
    const msg = s === "expired" ? `Expired ${plural(-n, "day")} ago - renew it as soon as possible.`
              : n === 0 ? "Expires TODAY - renew now!" : `Expires in ${plural(n, "day")} (${fmt(d.expiry)}).`;
    return `<div class="alert ${s}"><div style="font-size:26px">${s === "expired" ? "🚨" : "⏰"}</div>
      <div class="txt"><b>${esc(d.name)}</b><span>${msg}</span></div>
      <button class="btn" data-action="renew" data-id="${d.id}">Renew</button></div>`;
  }).join("") : `<div class="allgood"><div class="big">🎉</div><b>You're all caught up!</b><br>${total ? "No documents need attention right now." : "Add your first document to get started."}</div>`;

  // timeline (next 6 non-expired)
  const next = docs.filter(d => daysLeft(d.expiry) >= 0).sort((x, y) => x.expiry.localeCompare(y.expiry)).slice(0, 6);
  $("#timeline").innerHTML = next.length ? next.map(d => {
    const dt = parse(d.expiry), s = statusOf(d);
    return `<div class="tl"><div class="datebox"><b>${dt.getDate()}</b><span>${dt.toLocaleDateString("en-IN", {month: "short"})} ${String(dt.getFullYear()).slice(2)}</span></div>
      <div class="info"><b>${ICONS[d.category] || "📄"} ${esc(d.name)}</b><span>${esc(d.category || "Other")}${d.number ? " · " + esc(d.number) : ""}</span></div>
      <span class="chip ${s}">${whenText(d)}</span></div>`;
  }).join("") : `<div class="allgood">No upcoming deadlines yet.</div>`;

  renderDocs();
  const hr = new Date().getHours(), g = hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
  if (view === "dashboard") { $("#pageTitle").textContent = g + ", " + me.name.split(" ")[0] + " 👋"; $("#pageSub").textContent = total ? `You have ${bad + soon} document${bad + soon === 1 ? "" : "s"} needing attention.` : "Let's add your first document."; }
  else if (view === "documents") { $("#pageTitle").textContent = "My Documents"; $("#pageSub").textContent = `${total} record${total === 1 ? "" : "s"} tracked`; }
  else { $("#pageTitle").textContent = "Insights & Design"; $("#pageSub").textContent = "Analytics, security activity and how DocuTrack is built."; loadInsights(); }
}

function renderDocs() {
  let list = docs.filter(d => (filter === "all" || statusOf(d) === filter) &&
    (!query || (d.name + " " + (d.number || "") + " " + (d.category || "")).toLowerCase().includes(query)));
  if (!docs.length) {
    $("#cards").innerHTML = `<div class="empty"><div class="big">📂</div><h3>No documents yet</h3><p>Add your ID card, certificates or licences and DocuTrack will remind you before they expire.</p>
      <div class="row"><button class="btn btn-primary" data-action="add">＋ Add document</button><button class="btn btn-ghost" data-action="seed">✨ Load sample data</button></div></div>`;
    return;
  }
  if (!list.length) { $("#cards").innerHTML = `<div class="empty"><div class="big">🔍</div><h3>Nothing found</h3><p>Try a different filter or search term.</p></div>`; return; }
  $("#cards").innerHTML = list.map((d, i) => {
    const s = statusOf(d), n = daysLeft(d.expiry);
    const pct = s === "expired" ? 100 : Math.max(6, 100 - Math.min(n, 365) / 365 * 100);
    return `<div class="dcard ${s}" style="animation-delay:${i * 40}ms">
      <div class="dhead"><div class="dico">${ICONS[d.category] || "📄"}</div>
        <div class="t"><b>${esc(d.name)}</b><span>${esc(d.category || "Other")}${d.number ? " · " + esc(d.number) : ""}</span></div></div>
      <div class="meta"><div class="when">${fmt(d.expiry)}<small>${whenText(d)}</small></div>
        <span class="chip ${s}">${s === "soon" ? "Expiring soon" : s === "expired" ? "Expired" : "Active"}</span></div>
      <div class="bar"><i style="width:${pct}%"></i></div>
      ${d.renewed_count ? `<div class="renewed-tag">♻️ Renewed ${d.renewed_count}× · last ${fmt(d.last_renewed)}</div>` : ""}
      ${d.notes ? `<div class="note">📝 ${esc(d.notes)}</div>` : ""}
      <div class="acts">
        <button class="btn renew" data-action="renew" data-id="${d.id}">✅ Mark renewed</button>
        <button class="btn ico-btn" data-action="edit" data-id="${d.id}" title="Edit">✏️</button>
        <button class="btn ico-btn del" data-action="del" data-id="${d.id}" title="Delete">🗑️</button>
      </div></div>`;
  }).join("");
}

/* ---------- insights (analytics + audit log) ---------- */
const EVENTS = {register: "🎉 Account created", login_ok: "🔓 Logged in", login_failed: "⚠️ Failed login attempt", login_blocked: "⛔ Login blocked (too many attempts)",
  logout: "👋 Logged out", doc_added: "➕ Document added", doc_edited: "✏️ Document edited", doc_deleted: "🗑️ Document deleted",
  doc_renewed: "✅ Document renewed", sample_data: "✨ Sample data loaded", data_exported: "⬇️ Data exported"};
function bars(arr, label) {
  if (!arr.length) return `<div class="allgood" style="padding:10px">No data yet.</div>`;
  const m = Math.max(1, ...arr.map(x => x.n));
  return arr.map(x => `<div class="barrow"><span>${esc(label(x))}</span><div class="track"><i style="width:${x.n / m * 100}%"></i></div><b>${x.n}</b></div>`).join("");
}
async function loadInsights() {
  try {
    const [a, log] = await Promise.all([api("/api/analytics"), api("/api/audit")]);
    $("#chCat").innerHTML = bars(a.by_category, x => (ICONS[x.category] || "📄") + " " + x.category);
    $("#chMonth").innerHTML = bars(a.by_month, x => { const [y, m] = x.month.split("-"); return new Date(+y, +m - 1, 1).toLocaleDateString("en-IN", {month: "short", year: "numeric"}); });
    $("#renCount").textContent = "♻️ " + a.renewals + " renewal" + (a.renewals === 1 ? "" : "s") + " recorded";
    $("#auditList").innerHTML = log.length ? log.map(r => `<div class="logrow"><div style="flex:1"><b>${EVENTS[r.event] || esc(r.event)}</b>${r.detail ? `<small>${esc(r.detail)}</small>` : ""}</div>
      <small>${new Date(r.at + "Z").toLocaleString("en-IN", {day: "numeric", month: "short", hour: "2-digit", minute: "2-digit"})}</small></div>`).join("")
      : `<div class="allgood" style="padding:10px">No activity yet.</div>`;
  } catch (e) { toast(e.message); }
}

/* ---------- navigation ---------- */
function setView(v) {
  view = v;
  $("#vDash").hidden = v !== "dashboard"; $("#vDocs").hidden = v !== "documents"; $("#vInsights").hidden = v !== "insights";
  document.querySelectorAll("nav button").forEach(b => b.classList.toggle("on", b.dataset.view === v));
  render();
}
function setFilter(f) {
  filter = f;
  document.querySelectorAll("#filters button").forEach(b => b.classList.toggle("on", b.dataset.f === f));
  renderDocs();
}

/* ---------- auth ---------- */
function setAuthMode(m) {
  authMode = m;
  $("#tabLogin").classList.toggle("on", m === "login"); $("#tabReg").classList.toggle("on", m === "register");
  $("#nameField").hidden = m === "login";
  $("#authTitle").textContent = m === "login" ? "Welcome back 👋" : "Create your account ✨";
  $("#authSub").textContent = m === "login" ? "Log in to see your document dashboard." : "It takes less than a minute.";
  $("#authBtn").textContent = m === "login" ? "Log in" : "Create account";
  $("#aPass").autocomplete = m === "login" ? "current-password" : "new-password";
  $("#authErr").hidden = true;
}
async function authSubmit() {
  const btn = $("#authBtn"); btn.disabled = true;
  try {
    me = await api(authMode === "login" ? "/api/login" : "/api/register", "POST",
      {name: $("#aName").value, email: $("#aEmail").value, password: $("#aPass").value});
    $("#aPass").value = ""; await enterApp();
    toast(authMode === "login" ? "Welcome back, " + me.name.split(" ")[0] + "!" : "Account created. Welcome to DocuTrack!");
  } catch (e) { $("#authErr").textContent = e.message; $("#authErr").hidden = false; }
  btn.disabled = false;
}

/* ---------- document modal ---------- */
function openDoc(id) {
  editingId = id || null; $("#mErr").hidden = true;
  const d = docs.find(x => x.id === id);
  $("#mTitle").textContent = d ? "Edit document" : "Add a document";
  $("#fName").value = d ? d.name : ""; $("#fCat").value = d ? d.category : "Identity";
  $("#fExp").value = d ? d.expiry : ""; $("#fNum").value = d ? d.number || "" : ""; $("#fNotes").value = d ? d.notes || "" : "";
  $("#docModal").showModal(); $("#fName").focus();
}
async function saveDoc() {
  const body = {name: $("#fName").value, category: $("#fCat").value, expiry: $("#fExp").value, number: $("#fNum").value, notes: $("#fNotes").value};
  try {
    if (editingId) await api("/api/docs/" + editingId, "PUT", body); else await api("/api/docs", "POST", body);
    $("#docModal").close(); await load(); toast(editingId ? "Document updated ✏️" : "Document added 🎉");
  } catch (e) { $("#mErr").textContent = e.message; $("#mErr").hidden = false; }
}
function openRenew(id) {
  const d = docs.find(x => x.id === id); if (!d) return;
  renewId = id; $("#rErr").hidden = true;
  $("#rSub").textContent = d.name + " - currently " + (daysLeft(d.expiry) < 0 ? "expired on " : "valid until ") + fmt(d.expiry) + ".";
  $("#rExp").value = addYears(d.expiry, 1); $("#renewModal").showModal();
}
async function confirmRenew() {
  try {
    await api("/api/docs/" + renewId + "/renew", "POST", {expiry: $("#rExp").value});
    $("#renewModal").close(); await load(); toast("Marked as renewed ✅ Nice work!");
  } catch (e) { $("#rErr").textContent = e.message; $("#rErr").hidden = false; }
}

/* ---------- one click handler for everything ---------- */
document.addEventListener("click", async e => {
  const el = e.target.closest("[data-action]"); if (!el) return;
  const a = el.dataset.action, id = parseInt(el.dataset.id, 10);
  try {
    if (a === "authTab") setAuthMode(el.dataset.mode);
    else if (a === "authSubmit") authSubmit();
    else if (a === "logout") { await api("/api/logout", "POST"); me = null; docs = []; $("#app").hidden = true; $("#auth").hidden = false; setAuthMode("login"); toast("Logged out. See you soon!"); }
    else if (a === "view") setView(el.dataset.view);
    else if (a === "goFilter") { setView("documents"); setFilter(el.dataset.f); }
    else if (a === "filter") setFilter(el.dataset.f);
    else if (a === "add") openDoc();
    else if (a === "edit") openDoc(id);
    else if (a === "saveDoc") saveDoc();
    else if (a === "renew") openRenew(id);
    else if (a === "confirmRenew") confirmRenew();
    else if (a === "quickYears") { const d = docs.find(x => x.id === renewId); $("#rExp").value = addYears(d.expiry, parseInt(el.dataset.y, 10)); }
    else if (a === "closeModal") el.closest("dialog").close();
    else if (a === "del") { const d = docs.find(x => x.id === id); if (confirm('Delete "' + d.name + '"? This cannot be undone.')) { await api("/api/docs/" + id, "DELETE"); await load(); toast("Document deleted 🗑️"); } }
    else if (a === "export") {
      const d = await api("/api/export"), u = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], {type: "application/json"}));
      const l = document.createElement("a"); l.href = u; l.download = "docutrack-export.json"; l.click(); URL.revokeObjectURL(u);
      toast("Data exported ⬇️"); loadInsights();
    }
    else if (a === "seed") { await api("/api/seed", "POST"); await load(); toast("Sample documents loaded ✨"); }
  } catch (err) { toast(err.message); }
});
$("#search").addEventListener("input", e => { query = e.target.value.trim().toLowerCase(); renderDocs(); });
$("#winSel").addEventListener("change", e => { WINDOW = parseInt(e.target.value, 10); localStorage.setItem("dt_win", WINDOW); render(); });
["aName", "aEmail", "aPass"].forEach(id => $("#" + id).addEventListener("keydown", e => { if (e.key === "Enter") authSubmit(); }));
document.querySelectorAll("dialog").forEach(d => d.addEventListener("click", e => { if (e.target === d) d.close(); }));
boot();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()