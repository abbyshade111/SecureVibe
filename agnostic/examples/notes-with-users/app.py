"""A small notes app with accounts, written to show what `sv run` asks a signed-in user.

Standard library only, because the app runs inside a network fence with nothing to install from.
Data lives in /tmp: the app's own folder is mounted read-only while `sv` runs it.
"""

import hashlib
import hmac
import html
import os
import secrets
import sqlite3
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

DB = os.environ.get("NOTES_DB", "/tmp/notes.db")
# The 3000 most common passwords, refused at sign-up (ASVS V6.2.4). Length is the only other rule:
# at least 8 characters (V6.2.1; 15 is the recommendation), and nothing about which kinds of character
# a password must contain (V6.2.5).
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "common-passwords.txt")) as f:
    COMMON = {line.strip() for line in f if line.strip()}
OWN_ORIGINS = {f"http://{h}" for h in ("localhost", "127.0.0.1")}


def db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "create table if not exists users (email text primary key, hash text, salt text, admin int)"
    )
    conn.execute("create table if not exists sessions (id text primary key, email text, csrf text)")
    conn.execute(
        "create table if not exists notes (id integer primary key, owner text, text text)"
    )
    return conn


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()


def page(title, body):
    return f"<!doctype html><title>{html.escape(title)}</title>{body}".encode()


class Handler(BaseHTTPRequestHandler):
    def session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie["sid"].value if "sid" in cookie else None
        if not sid:
            return None, None, None
        row = db().execute("select email, csrf from sessions where id = ?", (sid,)).fetchone()
        return (sid, row[0], row[1]) if row else (None, None, None)

    def new_session(self, email):
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with db() as conn:
            conn.execute("insert into sessions values (?, ?, ?)", (sid, email, csrf))
        return sid, csrf

    def send(self, status, body=b"", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def cookie(self, sid):
        return ("Set-Cookie", f"sid={sid}; Path=/; HttpOnly; SameSite=Lax")

    def form(self):
        length = int(self.headers.get("Content-Length", 0))
        fields = parse_qs(self.rfile.read(length).decode())
        return {k: v[0] for k, v in fields.items()}

    def forged(self, form, csrf):
        origin = self.headers.get("Origin")
        if origin and origin not in OWN_ORIGINS:
            return True
        return not csrf or not hmac.compare_digest(form.get("csrf_token", ""), csrf)

    def do_GET(self):
        sid, email, csrf = self.session()
        if self.path == "/":
            return self.send(200, page("Notes", "<a href='/login'>Sign in</a>"))
        if self.path in ("/login", "/signup"):
            # A session before sign-in, for the form's token. Sign-in replaces it.
            sid, csrf = self.new_session(None)
            form = (
                f"<form method=post><input type=hidden name=csrf_token value='{csrf}'>"
                "<label>Email <input type=email name=email autocomplete=username></label>"
                "<label>Password <input type=password name=password></label>"
                "<button>Go</button></form>"
            )
            title = "Sign in" if self.path == "/login" else "Sign up"
            return self.send(200, page(title, form), [self.cookie(sid)])
        if not email:
            return self.send(302, headers=[("Location", "/login")])
        if self.path == "/account":
            return self.send(200, page("Account", f"Signed in as {html.escape(email)}"))
        if self.path == "/admin":
            admin = db().execute("select admin from users where email = ?", (email,)).fetchone()
            if not admin or not admin[0]:
                return self.send(403, page("No", "Not for you."))
            return self.send(200, page("Admin", "Everyone's notes."))
        if self.path == "/notes":
            form = f"<form method=post><input type=hidden name=csrf_token value='{csrf}'></form>"
            return self.send(200, page("New note", form))
        if self.path.startswith("/notes/"):
            note = db().execute(
                "select text from notes where id = ? and owner = ?",
                (self.path.rsplit("/", 1)[1], email),
            ).fetchone()
            if not note:
                return self.send(404, page("Not found", "No such note."))
            return self.send(200, page("Note", f"<p>{html.escape(note[0])}</p>"))
        return self.send(404, page("Not found", "No such page."))

    def do_POST(self):
        sid, email, csrf = self.session()
        form = self.form()
        if self.path == "/login":
            if self.forged(form, csrf):
                return self.send(403, page("No", "Refused."))
            row = db().execute(
                "select hash, salt from users where email = ?", (form.get("email", ""),)
            ).fetchone()
            if not row or not hmac.compare_digest(
                row[0], hash_password(form.get("password", ""), row[1])
            ):
                return self.send(403, page("No", "Wrong email or password."))
            with db() as conn:
                conn.execute("delete from sessions where id = ?", (sid,))
            new_sid, _ = self.new_session(form["email"])
            return self.send(303, headers=[("Location", "/account"), self.cookie(new_sid)])
        if self.path == "/signup":
            if self.forged(form, csrf):
                return self.send(403, page("No", "Refused."))
            new_email, password = form.get("email", ""), form.get("password", "")
            if len(password) < 8 or password in COMMON:
                return self.send(422, page("No", "Choose a longer or less common password."))
            salt = secrets.token_hex(16)
            try:
                with db() as conn:
                    conn.execute(
                        "insert into users values (?, ?, ?, 0)",
                        (new_email, hash_password(password, salt), salt),
                    )
            except sqlite3.IntegrityError:
                return self.send(422, page("No", "That account exists."))
            return self.send(303, headers=[("Location", "/login")])
        if not email:
            return self.send(302, headers=[("Location", "/login")])
        if self.forged(form, csrf):
            return self.send(403, page("No", "Refused."))
        if self.path == "/logout":
            with db() as conn:
                conn.execute("delete from sessions where id = ?", (sid,))
            return self.send(303, headers=[("Location", "/"), ("Set-Cookie", "sid=; Max-Age=0")])
        if self.path == "/notes":
            with db() as conn:
                cur = conn.execute(
                    "insert into notes (owner, text) values (?, ?)", (email, form.get("text", ""))
                )
            return self.send(303, headers=[("Location", f"/notes/{cur.lastrowid}")])
        return self.send(404, page("Not found", "No such page."))

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    db().close()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
