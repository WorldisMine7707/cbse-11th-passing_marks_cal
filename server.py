#!/usr/bin/env python3
import json
import os
import re
import sqlite3
import secrets
import hashlib
from datetime import datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import cgi

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "platform.db"
UPLOAD_DIR = ROOT / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXT = {"pdf", "doc", "docx"}
MAX_FILE_SIZE = 5 * 1024 * 1024


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_conn()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            userID INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            class INTEGER NOT NULL,
            section TEXT NOT NULL,
            dob TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            passwordHash TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            badge TEXT NOT NULL,
            status TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student'
        );

        CREATE TABLE IF NOT EXISTS pending_verifications (
            email TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            code TEXT NOT NULL,
            createdAt TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            userID INTEGER NOT NULL,
            createdAt TEXT NOT NULL,
            FOREIGN KEY(userID) REFERENCES users(userID)
        );

        CREATE TABLE IF NOT EXISTS messages (
            messageID INTEGER PRIMARY KEY AUTOINCREMENT,
            userID INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            reportCount INTEGER NOT NULL DEFAULT 0,
            flagged INTEGER NOT NULL DEFAULT 0,
            hidden INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(userID) REFERENCES users(userID)
        );

        CREATE TABLE IF NOT EXISTS files (
            fileID INTEGER PRIMARY KEY AUTOINCREMENT,
            uploadedBy INTEGER NOT NULL,
            title TEXT NOT NULL,
            fileName TEXT NOT NULL,
            fileURL TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            reportCount INTEGER NOT NULL DEFAULT 0,
            flagged INTEGER NOT NULL DEFAULT 0,
            hidden INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(uploadedBy) REFERENCES users(userID)
        );

        CREATE TABLE IF NOT EXISTS reports (
            reportID INTEGER PRIMARY KEY AUTOINCREMENT,
            messageID2 INTEGER,
            fileID2 INTEGER,
            targetType TEXT NOT NULL,
            targetID INTEGER NOT NULL,
            reportedBy INTEGER NOT NULL,
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(reportedBy) REFERENCES users(userID)
        );
        """
    )
    admin = cur.execute("SELECT userID FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        cur.execute(
            """
            INSERT INTO users(name, class, section, dob, email, passwordHash, username, badge, status, role)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "KV Admin",
                12,
                "A",
                "2000-01-01",
                "admin@kvmanesar.local",
                hash_password("Admin@123"),
                "admin_kvmanesar",
                "Verified Admin",
                "Active",
                "admin",
            ),
        )
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def make_username(conn, name: str):
    base = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "student"
    while True:
        username = f"{base}_{secrets.randbelow(9000) + 1000}"
        exists = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            return username


def now_iso():
    return datetime.utcnow().isoformat() + "Z"


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _serve_file(self, path: Path, content_type="text/html"):
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def _auth(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        conn = db_conn()
        row = conn.execute(
            """
            SELECT u.* FROM sessions s JOIN users u ON u.userID=s.userID
            WHERE s.token=?
            """,
            (token,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/marks.html":
            return self._serve_file(ROOT / "marks.html")
        if parsed.path.startswith("/uploads/"):
            file_path = ROOT / parsed.path.lstrip("/")
            return self._serve_file(file_path, "application/octet-stream")

        if parsed.path == "/api/me":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            user.pop("passwordHash", None)
            return self._json(200, user)

        if parsed.path == "/api/messages":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = db_conn()
            rows = conn.execute(
                """
                SELECT m.*, u.username FROM messages m JOIN users u ON u.userID=m.userID
                WHERE (?='admin' OR m.hidden=0)
                ORDER BY m.messageID DESC
                """,
                (user["role"],),
            ).fetchall()
            conn.close()
            return self._json(200, [dict(r) for r in rows])

        if parsed.path == "/api/files":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = db_conn()
            rows = conn.execute(
                """
                SELECT f.*, u.username FROM files f JOIN users u ON u.userID=f.uploadedBy
                WHERE (?='admin' OR f.hidden=0)
                ORDER BY f.fileID DESC
                """,
                (user["role"],),
            ).fetchall()
            conn.close()
            return self._json(200, [dict(r) for r in rows])

        if parsed.path == "/api/reports/mine":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            conn = db_conn()
            rows = conn.execute(
                "SELECT * FROM reports WHERE reportedBy=? ORDER BY reportID DESC",
                (user["userID"],),
            ).fetchall()
            conn.close()
            return self._json(200, [dict(r) for r in rows])

        if parsed.path == "/api/admin/overview":
            user = self._auth()
            if not user or user["role"] != "admin":
                return self._json(403, {"error": "Forbidden"})
            conn = db_conn()
            reports = [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY reportID DESC LIMIT 50").fetchall()]
            flagged_messages = [dict(r) for r in conn.execute("SELECT * FROM messages WHERE flagged=1 ORDER BY messageID DESC").fetchall()]
            flagged_files = [dict(r) for r in conn.execute("SELECT * FROM files WHERE flagged=1 ORDER BY fileID DESC").fetchall()]
            users = [dict(r) for r in conn.execute("SELECT userID,name,username,class,status,role FROM users ORDER BY userID DESC").fetchall()]
            conn.close()
            return self._json(200, {
                "reports": reports,
                "flaggedMessages": flagged_messages,
                "flaggedFiles": flagged_files,
                "users": users,
            })

        return self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/register/init":
            data = self._read_json()
            for req in ["name", "classLevel", "section", "dob", "email", "password"]:
                if not data.get(req):
                    return self._json(400, {"error": "Missing required fields"})
            if int(data["classLevel"]) < 8:
                return self._json(400, {"error": "Registration is restricted to Class 8 and above."})
            conn = db_conn()
            exists = conn.execute("SELECT 1 FROM users WHERE email=?", (data["email"].lower(),)).fetchone()
            if exists:
                conn.close()
                return self._json(409, {"error": "Email already registered."})
            code = str(secrets.randbelow(900000) + 100000)
            payload = {
                "name": data["name"],
                "class": int(data["classLevel"]),
                "section": data["section"],
                "dob": data["dob"],
                "email": data["email"].lower(),
                "password": hash_password(data["password"]),
            }
            conn.execute(
                "REPLACE INTO pending_verifications(email,payload,code,createdAt) VALUES(?,?,?,?)",
                (payload["email"], json.dumps(payload), code, now_iso()),
            )
            conn.commit()
            conn.close()
            return self._json(200, {"message": "Verification code generated.", "devCode": code})

        if parsed.path == "/api/register/verify":
            data = self._read_json()
            email = data.get("email", "").lower()
            code = data.get("code", "")
            conn = db_conn()
            row = conn.execute("SELECT * FROM pending_verifications WHERE email=?", (email,)).fetchone()
            if not row or row["code"] != code:
                conn.close()
                return self._json(400, {"error": "Invalid verification code."})
            payload = json.loads(row["payload"])
            username = make_username(conn, payload["name"])
            conn.execute(
                """
                INSERT INTO users(name,class,section,dob,email,passwordHash,username,badge,status,role)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    payload["name"],
                    payload["class"],
                    payload["section"],
                    payload["dob"],
                    payload["email"],
                    payload["password"],
                    username,
                    "Unverified Student",
                    "Active",
                    "student",
                ),
            )
            conn.execute("DELETE FROM pending_verifications WHERE email=?", (email,))
            conn.commit()
            conn.close()
            return self._json(201, {"message": "Account created", "username": username})

        if parsed.path == "/api/login":
            data = self._read_json()
            email = data.get("email", "").lower()
            password = hash_password(data.get("password", ""))
            conn = db_conn()
            user = conn.execute("SELECT * FROM users WHERE email=? AND passwordHash=?", (email, password)).fetchone()
            if not user:
                conn.close()
                return self._json(401, {"error": "Invalid email or password."})
            if user["status"] == "Banned":
                conn.close()
                return self._json(403, {"error": "Your account has been restricted."})
            token = secrets.token_hex(24)
            conn.execute("INSERT INTO sessions(token,userID,createdAt) VALUES(?,?,?)", (token, user["userID"], now_iso()))
            conn.commit()
            conn.close()
            return self._json(200, {"token": token})

        if parsed.path == "/api/logout":
            user = self._auth()
            if not user:
                return self._json(200, {"message": "ok"})
            token = self.headers.get("Authorization", "")[7:]
            conn = db_conn()
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()
            conn.close()
            return self._json(200, {"message": "Logged out"})

        if parsed.path == "/api/messages":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            data = self._read_json()
            content = data.get("content", "").strip()
            if not content:
                return self._json(400, {"error": "Empty content"})
            conn = db_conn()
            conn.execute(
                "INSERT INTO messages(userID,content,timestamp,reportCount,flagged,hidden) VALUES(?,?,?,?,?,?)",
                (user["userID"], content, now_iso(), 0, 0, 0),
            )
            conn.commit()
            conn.close()
            return self._json(201, {"message": "Sent"})

        if parsed.path == "/api/files/upload":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": self.headers.get("Content-Type")})
            title = (form.getvalue("title") or "").strip()
            file_item = form["file"] if "file" in form else None
            if not title or not file_item or not file_item.filename:
                return self._json(400, {"error": "Title and file are required."})
            filename = os.path.basename(file_item.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_EXT:
                return self._json(400, {"error": "Only PDF, DOC, DOCX are allowed."})
            data = file_item.file.read()
            if len(data) > MAX_FILE_SIZE:
                return self._json(400, {"error": "File too large. Max 5 MB."})
            safe_name = f"{secrets.token_hex(8)}_{filename}"
            path = UPLOAD_DIR / safe_name
            path.write_bytes(data)
            url = f"/uploads/{safe_name}"
            conn = db_conn()
            conn.execute(
                "INSERT INTO files(uploadedBy,title,fileName,fileURL,timestamp,reportCount,flagged,hidden) VALUES(?,?,?,?,?,?,?,?)",
                (user["userID"], title, filename, url, now_iso(), 0, 0, 0),
            )
            conn.commit()
            conn.close()
            return self._json(201, {"message": "Uploaded"})

        if parsed.path == "/api/report":
            user = self._auth()
            if not user:
                return self._json(401, {"error": "Unauthorized"})
            data = self._read_json()
            target_type = data.get("targetType")
            target_id = int(data.get("targetID", 0))
            reason = data.get("reason", "Other")
            if reason not in ["Abuse", "Spam", "Harassment", "Other"]:
                reason = "Other"
            if target_type not in ["message", "file"] or target_id <= 0:
                return self._json(400, {"error": "Invalid target"})
            conn = db_conn()
            conn.execute(
                "INSERT INTO reports(messageID2,fileID2,targetType,targetID,reportedBy,reason,timestamp) VALUES(?,?,?,?,?,?,?)",
                (target_id if target_type == "message" else None, target_id if target_type == "file" else None, target_type, target_id, user["userID"], reason, now_iso()),
            )
            table = "messages" if target_type == "message" else "files"
            id_col = "messageID" if target_type == "message" else "fileID"
            conn.execute(f"UPDATE {table} SET reportCount = reportCount + 1 WHERE {id_col}=?", (target_id,))
            row = conn.execute(f"SELECT reportCount FROM {table} WHERE {id_col}=?", (target_id,)).fetchone()
            if row and row["reportCount"] >= 3:
                conn.execute(f"UPDATE {table} SET flagged=1, hidden=1 WHERE {id_col}=?", (target_id,))
            conn.commit()
            conn.close()
            return self._json(201, {"message": "Reported"})

        if parsed.path.startswith("/api/admin/"):
            user = self._auth()
            if not user or user["role"] != "admin":
                return self._json(403, {"error": "Forbidden"})
            data = self._read_json()
            conn = db_conn()
            if parsed.path == "/api/admin/message/delete":
                conn.execute("DELETE FROM messages WHERE messageID=?", (int(data.get("messageID", 0)),))
            elif parsed.path == "/api/admin/message/unflag":
                conn.execute("UPDATE messages SET flagged=0, hidden=0 WHERE messageID=?", (int(data.get("messageID", 0)),))
            elif parsed.path == "/api/admin/file/delete":
                fid = int(data.get("fileID", 0))
                row = conn.execute("SELECT fileURL FROM files WHERE fileID=?", (fid,)).fetchone()
                if row:
                    try:
                        (ROOT / row["fileURL"].lstrip("/")).unlink(missing_ok=True)
                    except Exception:
                        pass
                conn.execute("DELETE FROM files WHERE fileID=?", (fid,))
            elif parsed.path == "/api/admin/user/ban":
                uid = int(data.get("userID", 0))
                conn.execute("UPDATE users SET status='Banned' WHERE userID=? AND role!='admin'", (uid,))
            else:
                conn.close()
                return self.send_error(404)
            conn.commit()
            conn.close()
            return self._json(200, {"message": "Done"})

        return self.send_error(404)


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "4173"))
    print(f"KV platform server running on http://0.0.0.0:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
