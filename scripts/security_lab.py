"""Loopback-only, deliberately vulnerable application with fictitious records.

Run with --fixed for regression. --root points to a local lab project containing
settings.json {"fixed": false}; this controls authentication/session fixtures.
An optional queries.py selects one of the two exact, shipped SQL fixture sources
below. A real branch diff can replace the unsafe SQL expression with parameters;
only bytes matching a known source and SHA-256 are compiled, never project code
with arbitrary contents. Without queries.py the original fixed-mode SQL behavior
is preserved. No commands, uploaded code or unknown binaries are executed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
from urllib.parse import parse_qs, urlsplit


VULNERABLE_QUERY_SOURCE = (
    "def lookup_name(db, name):\n"
    "    return db.execute(f\"SELECT marker FROM records WHERE name = '{name}'\").fetchall()\n"
)
FIXED_QUERY_SOURCE = (
    "def lookup_name(db, name):\n"
    "    return db.execute(\"SELECT marker FROM records WHERE name = ?\", (name,)).fetchall()\n"
)
_QUERY_FIXTURES = {
    hashlib.sha256(source.encode("utf-8")).hexdigest(): (source.encode("utf-8"), mode)
    for source, mode in ((VULNERABLE_QUERY_SOURCE, "vulnerable"), (FIXED_QUERY_SOURCE, "parameterized"))
}


class LabFixtureError(ValueError):
    """The optional lab file is not one of the two shipped source fixtures."""


def _load_query_fixture(root):
    """Read/compile exact known bytes, with no import machinery or user globals.

    Both SHA and byte equality are checked. Metadata is observed through one
    file descriptor. Aliases and unknown source fail closed with a generic error.
    """
    if root is None:
        return None
    source = Path(root).absolute() / "queries.py"
    try:
        for path in (source, *source.parents):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
                raise LabFixtureError("unapproved synthetic query fixture")
        try:
            info = source.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
            raise LabFixtureError("unapproved synthetic query fixture")
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            observed = os.fstat(descriptor)
            if ((observed.st_dev, observed.st_ino) != (info.st_dev, info.st_ino) or
                    observed.st_nlink != 1 or not stat.S_ISREG(observed.st_mode) or observed.st_size > 4096):
                raise LabFixtureError("unapproved synthetic query fixture")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                payload = stream.read(4097)
        finally:
            os.close(descriptor)
        fingerprint = hashlib.sha256(payload).hexdigest()
        known = _QUERY_FIXTURES.get(fingerprint)
        if known is None or payload != known[0]:
            raise LabFixtureError("unapproved synthetic query fixture")
        namespace = {"__builtins__": {}}
        # This compiles the branch's exact bytes only after matching a shipped
        # constant, not an arbitrary Python module or an approximate AST shape.
        exec(compile(payload, "nexus-synthetic-known-queries.py", "exec"), namespace)
        return namespace["lookup_name"], {"mode": known[1], "sha256": fingerprint, "known_fixture": True}
    except (OSError, UnicodeError) as exc:
        raise LabFixtureError("unapproved synthetic query fixture") from exc


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address=("127.0.0.1", 0), *, fixed=False, root=None):
        if address[0] != "127.0.0.1":
            raise ValueError("Este laboratório aceita somente loopback 127.0.0.1.")
        super().__init__(address, LabHandler)
        self.fixed, self.root = bool(fixed), Path(root).resolve() if root else None
        # Retain the user's lexical path so an alias is not hidden by resolve().
        self.query_root = Path(root).absolute() if root else None
        self.lock, self.sessions, self.observations = threading.Lock(), {}, []
        self.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.database.execute("CREATE TABLE records(name TEXT PRIMARY KEY, marker TEXT NOT NULL)")
        self.database.executemany("INSERT INTO records VALUES(?,?)", [("NEXUS_LAB_A", "NEXUS_LAB_SQLI_MARKER_A"), ("NEXUS_LAB_B", "NEXUS_LAB_SQLI_MARKER_B")])
        self.users = {name: hashlib.pbkdf2_hmac("sha256", ("NEXUS_LAB_PASSWORD_" + name[-1]).encode(), b"nexus-synthetic-lab-only", 20000)
                      for name in ("NEXUS_LAB_A", "NEXUS_LAB_B")}

    @property
    def url(self):
        return "http://127.0.0.1:" + str(self.server_port)

    def fixed_mode(self):
        if self.root:
            source = self.root / "settings.json"
            if source.is_file() and not source.is_symlink() and source.stat().st_size < 1024:
                try:
                    value = json.loads(source.read_text(encoding="utf-8"))
                    if isinstance(value, dict) and type(value.get("fixed")) is bool:
                        return value["fixed"]
                except (ValueError, OSError):
                    pass
            # An invalid or missing lab config must fail closed, not restore flaws.
            return True
        return self.fixed

    def query_fixture(self):
        return _load_query_fixture(self.query_root)

    def server_close(self):
        super().server_close()
        self.database.close()


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        pass

    def _record(self):
        with self.server.lock:
            # Keep only method and path; never login bodies, cookies or query data.
            self.server.observations.append({"method": self.command, "path": urlsplit(self.path).path})
            self.server.observations[:] = self.server.observations[-100:]

    def _respond(self, status, value, *, cookie=None):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        origin = self.headers.get("Origin")
        if origin and (not self.server.fixed_mode() or origin == self.server.url):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _session(self):
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            return None, None
        session = jar.get("nexus_lab_session")
        key = session.value if session else None
        return key, self.server.sessions.get(key)

    def do_HEAD(self):
        self._record()
        self._respond(200, {"application": "NEXUS fictitious loopback lab"})

    def do_GET(self):
        self._record()
        path = urlsplit(self.path)
        if path.path in {"/", "/health"}:
            return self._respond(200, {"application": "NEXUS fictitious loopback lab", "fixed": self.server.fixed_mode(), "real_data": False})
        if path.path == "/sqli":
            name = parse_qs(path.query, keep_blank_values=True).get("name", [""])[0]
            if len(name) > 256:
                return self._respond(400, {"error": "input size"})
            try:
                with self.server.lock:
                    fixture = self.server.query_fixture()
                    if fixture is not None:
                        lookup, source_info = fixture
                        rows = lookup(self.server.database, name)
                    elif self.server.fixed_mode():
                        rows = self.server.database.execute("SELECT marker FROM records WHERE name = ?", (name,)).fetchall()
                    else:
                        # Deliberately unsafe ONLY in this synthetic loopback lab.
                        rows = self.server.database.execute(f"SELECT marker FROM records WHERE name = '{name}'").fetchall()
                result = {"markers": [row[0] for row in rows[:2]]}
                if fixture is not None:
                    result["query_source"] = source_info
                return self._respond(200, result)
            except LabFixtureError:
                return self._respond(503, {"error": "unapproved synthetic query fixture", "code": "unapproved_query_fixture"})
            except sqlite3.Error:
                return self._respond(500, {"error": "synthetic SQL fixture failure"})
        if path.path.startswith("/api/objects/"):
            owner = path.path.rsplit("/", 1)[-1]
            if owner not in self.server.users:
                return self._respond(404, {"error": "unknown synthetic resource"})
            _, user = self._session()
            if not user:
                return self._respond(401, {"error": "authentication required"})
            if self.server.fixed_mode() and user != owner:
                return self._respond(403, {"error": "owner authorization required"})
            return self._respond(200, {"marker": "NEXUS_LAB_RESOURCE_" + owner[-1]})
        return self._respond(404, {"error": "unknown endpoint"})

    def do_POST(self):
        self._record()
        length = self.headers.get("Content-Length", "0")
        if not length.isdecimal() or not 0 <= int(length) <= 2048:
            return self._respond(400, {"error": "invalid length"})
        form = parse_qs(self.rfile.read(int(length)).decode("ascii", errors="replace"))
        path = urlsplit(self.path).path
        if path == "/login":
            username = form.get("username", [""])[0]
            candidate = hashlib.pbkdf2_hmac("sha256", form.get("password", [""])[0].encode(), b"nexus-synthetic-lab-only", 20000)
            expected = self.server.users.get(username, b"\0" * 32)
            if username not in self.server.users or not hmac.compare_digest(candidate, expected):
                return self._respond(401, {"error": "synthetic login failed"})
            token = secrets.token_urlsafe(24)
            with self.server.lock:
                self.server.sessions[token] = username
            suffix = "; Path=/; HttpOnly; SameSite=Strict" if self.server.fixed_mode() else "; Path=/"
            return self._respond(200, {"authenticated": True}, cookie="nexus_lab_session=" + token + suffix)
        if path == "/logout":
            key, _ = self._session()
            if self.server.fixed_mode():
                with self.server.lock:
                    self.server.sessions.pop(key, None)
            return self._respond(200, {"logged_out": True}, cookie="nexus_lab_session=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        return self._respond(404, {"error": "unknown endpoint"})


@contextmanager
def lab_server(*, fixed=False, root=None):
    server = LabServer(fixed=fixed, root=root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--fixed", action="store_true")
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Porta inválida.")
    server = LabServer(("127.0.0.1", args.port), fixed=args.fixed, root=args.root)
    print("Laboratório fictício em " + server.url + "; Ctrl+C encerra. Não contém dados reais.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
