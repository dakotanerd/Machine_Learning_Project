# web_app_v1.py
# Intentionally vulnerable demo web app - for dataset training only.
# Vulnerabilities: SQL injection (sqlite), XSS (unescaped template), hardcoded secret, unsafe pickle usage.

import sqlite3
import pickle
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

DB_PATH = "example.db"
ADMIN_TOKEN = "SuperSecretAdminToken123"  # hardcoded secret

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, bio TEXT)")
    cur.execute("INSERT OR IGNORE INTO users (id, username, bio) VALUES (1, 'alice', 'Hello <b>world</b>')")
    conn.commit()
    conn.close()

def get_user_by_name_insecure(name: str):
    # SQL injection: directly concatenating user input into query
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    q = "SELECT id, username, bio FROM users WHERE username = '%s'" % name
    cur.execute(q)
    row = cur.fetchone()
    conn.close()
    return row

def deserialize_profile_insecure(serialized: bytes):
    # Dangerous: untrusted pickle deserialization
    # attacker could craft object payloads
    return pickle.loads(serialized)

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/user"):
            # parse ?name=...
            qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            name = qs.get("name", ["alice"])[0]
            user = get_user_by_name_insecure(name)
            if user:
                # XSS vulnerability if bio contains HTML and is rendered unescaped
                html_resp = f"<html><body><h1>{user[1]}</h1><div>{user[2]}</div></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html_resp.encode("utf-8"))
            else:
                self.send_error(404, "User not found")
        elif self.path.startswith("/admin"):
            # Using hardcoded token for admin endpoint
            qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            token = qs.get("token", [""])[0]
            if token == ADMIN_TOKEN:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Welcome, admin.")
            else:
                self.send_error(403, "Forbidden")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    def do_POST(self):
        if self.path == "/profile_upload":
            length = int(self.headers.get('content-length', 0))
            data = self.rfile.read(length)
            # This expects a pickled profile (unsafe)
            try:
                profile = deserialize_profile_insecure(data)
                # pretend to process profile
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Profile processed")
            except Exception as e:
                self.send_error(400, "Bad data")

if __name__ == "__main__":
    init_db()
    httpd = HTTPServer(("localhost", 8000), SimpleHandler)
    print("Vulnerable web app running on http://localhost:8000")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
