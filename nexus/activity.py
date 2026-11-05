"""Auditoria persistente sem argumentos de ferramentas ou segredos por padrão."""
import json
import sqlite3
from datetime import datetime, timezone

class Activity:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp TEXT, kind TEXT, data TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS summary_cursor(session_id TEXT PRIMARY KEY, count INTEGER)")

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn

    def add(self, kind, data):
        with self.connect() as conn:
            conn.execute("INSERT INTO audit(timestamp,kind,data) VALUES(?,?,?)", (datetime.now(timezone.utc).isoformat(), kind, json.dumps(data, ensure_ascii=False)))

    def list(self, limit=30):
        with self.connect() as conn:
            return [{"id": row["id"], "timestamp": row["timestamp"], "kind": row["kind"], **json.loads(row["data"])} for row in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (min(200, max(1, limit)),))]

    def cursor(self, session_id):
        with self.connect() as conn:
            row = conn.execute("SELECT count FROM summary_cursor WHERE session_id=?", (session_id,)).fetchone()
            return row[0] if row else 0

    def set_cursor(self, session_id, count):
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO summary_cursor VALUES(?,?)", (session_id, count))
