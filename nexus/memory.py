"""Local, bounded project knowledge and conversation storage.

SQLite is the source of truth. FTS5 and already-installed Ollama embedding
models improve retrieval when available; neither is required to work offline.
Project documents are untrusted data, never instructions for the agent.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import sqlite3
import stat
import threading
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tokens(text: str) -> set[str]:
    normalized = unicodedata.normalize("NFKD", text.casefold())
    normalized = "".join(c for c in normalized if not unicodedata.combining(c))
    return set(re.findall(r"\w+", normalized, flags=re.UNICODE))


def redact_secrets(text: str) -> str:
    """Remove recognizable credentials before persistence or export.

    This is a conservative guard, not a claim that arbitrary prose can be
    classified perfectly. Credential files are excluded before reading.
    """
    text = re.sub(
        r"-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?"
        r"-----END [^-\r\n]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]", text,
    )
    text = re.sub(
        r"(?i)\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
        r"gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
        r"sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,})\b",
        "[REDACTED TOKEN]", text,
    )
    # Preserve variable names and syntax while removing assigned values.
    assignment = re.compile(
        r"(?im)([\"']?\b(?:[\w.-]*(?:password|passwd|api[_-]?key|"
        r"access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|"
        r"private[_-]?key|secret(?:[_-]access)?[_-]?key|credentials)[\w.-]*|"
        r"token|secret)[\"']?\s*[:=]\s*)"
        r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\r\n]+)"
    )
    text = assignment.sub(lambda match: match.group(1) + '"[REDACTED]"', text)
    text = re.sub(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/-]{8,}=*", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    return text


class Memory:
    """Thread-safe persistent memory restricted to an explicit workspace."""

    MAX_FILES = 1200
    MAX_FILE_BYTES = 512 * 1024
    MAX_TOTAL_BYTES = 32 * 1024 * 1024
    MAX_SCAN_ENTRIES = 20000
    MAX_CHUNKS = 16000
    CHUNK_CHARS = 1800
    CHUNK_OVERLAP = 180
    MAX_MESSAGE_CHARS = 2_000_000

    _EXCLUDED_DIRS = {
        ".git", ".hg", ".svn", ".aws", ".ssh", ".azure", ".kube",
        ".gnupg", ".venv", "venv", "env", "node_modules", "__pycache__",
        ".pytest_cache", ".mypy_cache", ".next", "dist", "build", "coverage",
        "secrets", "credentials", ".secrets", ".credentials",
    }
    _SECRET_SUFFIXES = {
        ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx",
        ".db", ".db3", ".sqlite", ".sqlite3", ".log", ".bak",
    }
    _TEXT_SUFFIXES = {
        ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".md", ".mdx", ".txt", ".rst", ".html", ".htm", ".css",
        ".scss", ".sass", ".sql", ".sh", ".bash", ".bat", ".cmd",
        ".ps1", ".xml", ".csv", ".c", ".cc", ".cpp", ".h", ".hpp",
        ".rs", ".go", ".java", ".php", ".kt", ".swift", ".rb", ".lua",
        ".vue", ".svelte", ".r", ".ex", ".exs", ".graphql", ".proto",
        ".dockerignore", ".gitignore", ".editorconfig",
    }

    def __init__(
        self, db_path: str | Path, workspace_root: str | Path,
        ollama_url: str = "http://127.0.0.1:11434", embedding_model: str = "",
    ) -> None:
        self.workspace_root = Path(os.path.abspath(Path(workspace_root).expanduser()))
        self._check_links(self.workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.workspace_root = self.workspace_root.resolve(strict=True)
        self._validate_ollama_url(ollama_url)
        self.ollama_url = ollama_url.rstrip("/")
        self.embedding_model = embedding_model.strip()
        self.embedding_error = ""
        self.embedding_mode = "lexical"
        self.embedding_dimension = 0
        self._lock = threading.RLock()
        db_name = str(db_path)
        if db_name != ":memory:":
            database = Path(db_path).expanduser().absolute()
            self._check_links(database)
            database.parent.mkdir(parents=True, exist_ok=True)
            db_name = str(database)
        self._db = sqlite3.connect(db_name, timeout=60, check_same_thread=False)
        self._db_path = db_name
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=60000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._initialize()

    @staticmethod
    def _validate_ollama_url(url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("Ollama deve usar uma URL HTTP local, sem credenciais.")
        host = parsed.hostname or ""
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = host.casefold() == "localhost"
        if not local or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Embeddings só podem ser enviados ao Ollama em loopback local.")

    @staticmethod
    def _check_links(path: Path) -> None:
        """Check every existing component, including Windows junctions."""
        for component in reversed((path, *path.parents)):
            try:
                info = component.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Links simbólicos, junctions e reparse points não são permitidos.")

    def _safe_project_path(self, value: str | Path) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        candidate = Path(os.path.abspath(candidate))
        try:
            relative = candidate.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ValueError("O projeto deve estar dentro da pasta de trabalho autorizada.") from exc
        if any(self._excluded(Path(part), directory=True) for part in relative.parts):
            raise ValueError("Pastas de credenciais, metadados e ambientes são excluídas da memória.")
        self._check_links(candidate)
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise ValueError("O projeto saiu da pasta de trabalho autorizada.") from exc
        if not resolved.is_dir():
            raise ValueError("O caminho do projeto deve ser uma pasta existente.")
        return resolved

    @classmethod
    def _excluded(cls, path: Path, directory: bool = False) -> bool:
        name = path.name.casefold()
        if name in cls._EXCLUDED_DIRS or name.startswith(".env"):
            return True
        if directory:
            return False
        if path.suffix.casefold() in cls._SECRET_SUFFIXES:
            return True
        return bool(
            re.search(r"(?:^|[._-])(?:credentials?|secrets?|passwords?|tokens?)(?:[._-]|$)", name)
            or name.startswith(("id_rsa", "id_ed25519", "id_ecdsa"))
            or name in {".npmrc", ".pypirc", ".netrc", "authorized_keys", "known_hosts"}
        )

    def _initialize(self) -> None:
        with self._db:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL, indexed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS files (
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    path TEXT NOT NULL, digest TEXT NOT NULL, size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL, PRIMARY KEY(project_id,path)
                );
                CREATE TABLE IF NOT EXISTS chunks (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    path TEXT NOT NULL, chunk_index INTEGER NOT NULL, text TEXT NOT NULL,
                    vector TEXT, vector_model TEXT,
                    UNIQUE(project_id,path,chunk_index)
                );
                CREATE INDEX IF NOT EXISTS chunks_project ON chunks(project_id,path);
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY, text TEXT NOT NULL, kind TEXT NOT NULL,
                    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
                    vector TEXT, vector_model TEXT, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL,
                    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
                    summary TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    role TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS messages_session ON messages(session_id,id);
                CREATE TABLE IF NOT EXISTS message_metadata (
                    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
                    document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS session_metadata (
                    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
                    document TEXT NOT NULL
                );
                PRAGMA user_version=1;
            """)
            try:
                self._db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS search_index
                    USING fts5(text, path UNINDEXED, kind UNINDEXED,
                               source_id UNINDEXED, source_type UNINDEXED,
                               project_id UNINDEXED, tokenize='unicode61 remove_diacritics 2')""")
                self._fts = True
                # Rebuild only if an older/fallback-created database lacks its index.
                documents = self._db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
                documents += self._db.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
                if self._db.execute("SELECT COUNT(*) FROM search_index").fetchone()[0] != documents:
                    self._db.execute("DELETE FROM search_index")
                    for row in self._db.execute("SELECT id,project_id,path,text FROM chunks").fetchall():
                        self._fts_add(row["id"], "chunk", row["text"], row["path"], "project", row["project_id"])
                    for row in self._db.execute("SELECT id,project_id,kind,text FROM memories").fetchall():
                        self._fts_add(row["id"], "memory", row["text"], "", row["kind"], row["project_id"])
            except sqlite3.OperationalError:
                self._fts = False

    def _fts_add(self, source_id: str, source_type: str, text: str, path: str,
                 kind: str, project_id: str | None) -> None:
        if self._fts:
            self._db.execute(
                "INSERT INTO search_index(text,path,kind,source_id,source_type,project_id) VALUES(?,?,?,?,?,?)",
                (text, path, kind, source_id, source_type, project_id or ""),
            )

    def _delete_file(self, project_id: str, path: str) -> None:
        if self._fts:
            self._db.execute(
                "DELETE FROM search_index WHERE source_type='chunk' AND project_id=? AND path=?",
                (project_id, path),
            )
        self._db.execute("DELETE FROM chunks WHERE project_id=? AND path=?", (project_id, path))
        self._db.execute("DELETE FROM files WHERE project_id=? AND path=?", (project_id, path))

    def _project(self, project_id: str) -> sqlite3.Row:
        row = self._db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            raise ValueError("Projeto não encontrado.")
        return row

    def _embedding(self, texts: list[str]) -> list[list[float]] | None:
        if not self.embedding_model or not texts:
            return None
        try:
            import httpx
            with httpx.Client(timeout=45, trust_env=False, follow_redirects=False) as client:
                response = client.post(
                    self.ollama_url + "/api/embed",
                    json={"model": self.embedding_model, "input": texts,
                          "keep_alive": "0", "truncate": True,
                          "options": {"num_gpu": 0, "num_thread": 4}},
                )
                response.raise_for_status()
                vectors = response.json().get("embeddings")
            if not isinstance(vectors, list) or len(vectors) != len(texts):
                raise ValueError("Resposta de embeddings inválida.")
            dimension = len(vectors[0]) if vectors else 0
            if not 1 <= dimension <= 8192:
                raise ValueError("Dimensão de embedding inválida.")
            for vector in vectors:
                if not isinstance(vector, list) or len(vector) != dimension:
                    raise ValueError("Embeddings com dimensões diferentes.")
                if any(isinstance(x, bool) or not isinstance(x, (float, int)) or not math.isfinite(x) for x in vector):
                    raise ValueError("Embedding contém valores inválidos.")
            self.embedding_error = ""
            self.embedding_mode = "hybrid"
            self.embedding_dimension = dimension
            return vectors
        except Exception as exc:
            self.embedding_mode = "lexical"
            self.embedding_error = (
                f"Embeddings indisponíveis ({type(exc).__name__}); busca lexical ativa. "
                "Nenhum modelo foi baixado."
            )
            return None

    def projects(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._db.execute("SELECT * FROM projects ORDER BY name COLLATE NOCASE")]

    def register_project(self, name: str, path: str | Path) -> dict[str, Any]:
        resolved = self._safe_project_path(path)
        name = redact_secrets(name.strip())[:160]
        if not name:
            raise ValueError("Informe o nome do projeto.")
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO projects(id,name,path,created_at) VALUES(?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET name=excluded.name""",
                (uuid.uuid4().hex, name, str(resolved), _now()),
            )
            return dict(self._db.execute("SELECT * FROM projects WHERE path=?", (str(resolved),)).fetchone())

    def _walk_files(self, root: Path):
        pending = [root]
        scanned = 0
        while pending:
            directory = pending.pop()
            # Recheck before opening each directory; never intentionally follow links.
            self._check_links(directory)
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    scanned += 1
                    if scanned > self.MAX_SCAN_ENTRIES:
                        yield None
                        return
                    entries.append(entry)
            for entry in sorted(entries, key=lambda item: item.name.casefold()):
                path = Path(entry.path)
                try:
                    # DirEntry.stat on Windows can report st_nlink/st_ino as 0.
                    # A real lstat is required to validate hardlinks and identity.
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if not self._excluded(path, directory=True):
                            pending.append(path)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not self._excluded(path):
                        if path.suffix.casefold() in self._TEXT_SUFFIXES or not path.suffix:
                            yield path
                except (OSError, ValueError):
                    continue

    @classmethod
    def _chunks(cls, text: str) -> list[str]:
        result = []
        offset = 0
        while offset < len(text):
            end = min(offset + cls.CHUNK_CHARS, len(text))
            if end < len(text):
                newline = text.rfind("\n", offset + cls.CHUNK_CHARS // 2, end)
                if newline > offset:
                    end = newline + 1
            chunk = text[offset:end].strip()
            if chunk:
                result.append(chunk)
            if end >= len(text):
                break
            offset = max(offset + 1, end - cls.CHUNK_OVERLAP)
        return result

    def index_project(self, project_id: str) -> dict[str, Any]:
        # Keep this instance consistent, but never hold a SQLite write
        # transaction while Ollama performs an HTTP request. Other processes
        # can reopen the database and read the last committed file versions.
        with self._lock:
            project = self._project(project_id)
            root = self._safe_project_path(project["path"])
            known = {row["path"]: dict(row) for row in self._db.execute(
                "SELECT * FROM files WHERE project_id=?", (project_id,)
            )}
            observed: set[str] = set()
            changed = unchanged = skipped = total_bytes = file_count = chunk_count = 0
            limited = False
            for path in self._walk_files(root):
                if path is None:
                    limited = True
                    break
                relative = path.relative_to(root).as_posix()
                observed.add(relative)
                try:
                    self._check_links(path)
                    info = path.stat(follow_symlinks=False)
                    if info.st_size > self.MAX_FILE_BYTES:
                        skipped += 1
                        with self._db:
                            self._delete_file(project_id, relative)
                        continue
                    if file_count >= self.MAX_FILES or total_bytes + info.st_size > self.MAX_TOTAL_BYTES:
                        limited = True
                        break
                    # O_NOFOLLOW protects the final component on platforms supporting it.
                    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(path, flags)
                    with os.fdopen(descriptor, "rb") as handle:
                        opened = os.fstat(handle.fileno())
                        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev) or opened.st_nlink != 1:
                            raise ValueError("O arquivo mudou durante a leitura.")
                        raw = handle.read(self.MAX_FILE_BYTES + 1)
                    if len(raw) > self.MAX_FILE_BYTES or b"\x00" in raw:
                        skipped += 1
                        with self._db:
                            self._delete_file(project_id, relative)
                        continue
                    text = redact_secrets(raw.decode("utf-8-sig"))
                except (OSError, UnicodeError, ValueError):
                    skipped += 1
                    with self._db:
                        self._delete_file(project_id, relative)
                    continue
                file_count += 1
                total_bytes += len(raw)
                digest = hashlib.sha256(raw).hexdigest()
                old = known.get(relative)
                if old and old["digest"] == digest:
                    unchanged += 1
                    chunk_count += self._db.execute(
                        "SELECT COUNT(*) FROM chunks WHERE project_id=? AND path=?",
                        (project_id, relative),
                    ).fetchone()[0]
                    continue
                chunks = self._chunks(text)
                if chunk_count + len(chunks) > self.MAX_CHUNKS:
                    limited = True
                    break
                # Stage this bounded file's vectors before starting its atomic
                # replacement. A slow/missing model must not lock SQLite.
                staged_vectors: list[list[float] | None] = []
                for batch_start in range(0, len(chunks), 4):
                    batch = chunks[batch_start:batch_start + 4]
                    vectors = self._embedding(batch)
                    staged_vectors.extend(vectors if vectors else [None] * len(batch))
                with self._db:
                    self._delete_file(project_id, relative)
                    self._db.execute(
                        "INSERT INTO files(project_id,path,digest,size,mtime_ns) VALUES(?,?,?,?,?)",
                        (project_id, relative, digest, len(raw), info.st_mtime_ns),
                    )
                    for number, (chunk, vector) in enumerate(zip(chunks, staged_vectors)):
                        chunk_id = uuid.uuid4().hex
                        self._db.execute(
                            """INSERT INTO chunks(id,project_id,path,chunk_index,text,vector,vector_model)
                               VALUES(?,?,?,?,?,?,?)""",
                            (chunk_id, project_id, relative, number, chunk,
                             json.dumps(vector) if vector else None,
                             self.embedding_model if vector else None),
                        )
                        self._fts_add(chunk_id, "chunk", chunk, relative, "project", project_id)
                changed += 1
                chunk_count += len(chunks)
            removed = 0
            with self._db:
                if not limited:
                    for stale in known.keys() - observed:
                        self._delete_file(project_id, stale)
                        removed += 1
                self._db.execute("UPDATE projects SET indexed_at=? WHERE id=?", (_now(), project_id))
            indexed_files = self._db.execute("SELECT COUNT(*) FROM files WHERE project_id=?", (project_id,)).fetchone()[0]
            chunks_total = self._db.execute("SELECT COUNT(*) FROM chunks WHERE project_id=?", (project_id,)).fetchone()[0]
            return {
                "project_id": project_id, "indexed_files": indexed_files,
                "changed_files": changed, "unchanged_files": unchanged,
                "removed_files": removed, "skipped_files": skipped,
                "chunks": chunks_total, "limited": limited,
                "embedding_mode": self.embedding_mode, "embedding_error": self.embedding_error,
            }

    def _documents(self, project_id: str | None = None, scope="all") -> list[dict[str, Any]]:
        chunk_filter = " WHERE project_id=?" if project_id else ""
        memory_filter = " WHERE project_id=? OR project_id IS NULL" if project_id else ""
        if scope == "project" and not project_id:
            chunk_filter, memory_filter = " WHERE 0", " WHERE project_id IS NULL"
        parameters = (project_id,) if project_id else ()
        chunks = [dict(row) for row in self._db.execute(
            "SELECT id,project_id,path,text,vector,vector_model,'project' AS kind FROM chunks" + chunk_filter,
            parameters,
        )]
        chunks.extend(dict(row) for row in self._db.execute(
            "SELECT id,project_id,'' AS path,text,vector,vector_model,kind FROM memories" + memory_filter,
            parameters,
        ))
        return chunks

    def search(self, query: str, project_id: str | None = None, limit: int = 6, scope="all") -> list[dict[str, Any]]:
        if scope not in {"all", "project"}:
            raise ValueError("Escopo de memória inválido.")
        query = query.strip()[:4000]
        terms = _tokens(query)
        if not terms or limit <= 0:
            return []
        limit = min(int(limit), 50)
        with self._lock:
            if project_id:
                self._project(project_id)
            documents = self._documents(project_id, scope)
            fts_ranks: dict[str, float] = {}
            if self._fts:
                expression = " OR ".join('"' + token.replace('"', '""') + '"' for token in sorted(terms)[:32])
                sql = "SELECT source_id,bm25(search_index) AS rank FROM search_index WHERE search_index MATCH ?"
                args: list[Any] = [expression]
                if project_id:
                    sql += " AND (project_id=? OR project_id='')"
                    args.append(project_id)
                elif scope == "project":
                    sql += " AND project_id=''"
                sql += " ORDER BY rank LIMIT 200"
                try:
                    fts_ranks = {row["source_id"]: row["rank"] for row in self._db.execute(sql, args)}
                except sqlite3.OperationalError:
                    pass  # FTS syntax/build differences must not disable local search.
            embedded = self._embedding([redact_secrets(query)])
            query_vector = embedded[0] if embedded else None
            results = []
            for document in documents:
                document_terms = _tokens(document["text"] + " " + document["path"])
                overlap = len(terms & document_terms) / len(terms)
                lexical = overlap + (0.15 if query.casefold() in document["text"].casefold() else 0)
                semantic = None
                if query_vector and document["vector"] and document["vector_model"] == self.embedding_model:
                    try:
                        vector = json.loads(document["vector"])
                        if len(vector) == len(query_vector):
                            denominator = math.sqrt(sum(x * x for x in vector) * sum(x * x for x in query_vector))
                            semantic = sum(x * y for x, y in zip(vector, query_vector)) / denominator if denominator else 0
                    except (TypeError, ValueError):
                        semantic = None
                if overlap == 0 and (semantic is None or semantic < 0.3):
                    continue
                score = 0.35 * lexical + 0.65 * max(0, semantic) if semantic is not None else lexical
                document.update(score=round(score, 6), retrieval="hybrid" if semantic is not None else "lexical")
                document["_fts_rank"] = fts_ranks.get(document["id"], 0)
                results.append(document)
            results.sort(key=lambda item: (-item["score"], item["_fts_rank"], item["path"], item["id"]))
            return [
                {key: row[key] for key in ("id", "project_id", "text", "path", "score", "kind", "retrieval")}
            for row in results[:limit]
            ]

    def remember(self, text: str, kind: str = "preference", project_id: str | None = None) -> dict[str, Any]:
        text = redact_secrets(text.strip())
        if not text or len(text) > 32000:
            raise ValueError("A memória deve conter de 1 a 32000 caracteres.")
        if not re.fullmatch(r"[\w-]{1,40}", kind):
            raise ValueError("Tipo de memória inválido.")
        with self._lock:
            if project_id:
                self._project(project_id)
            memory_id = uuid.uuid4().hex
            vectors = self._embedding([text])
            vector = vectors[0] if vectors else None
            created = _now()
            with self._db:
                self._db.execute(
                    "INSERT INTO memories(id,text,kind,project_id,vector,vector_model,created_at) VALUES(?,?,?,?,?,?,?)",
                    (memory_id, text, kind, project_id, json.dumps(vector) if vector else None,
                     self.embedding_model if vector else None, created),
                )
                self._fts_add(memory_id, "memory", text, "", kind, project_id)
            return {"id": memory_id, "text": text, "kind": kind, "project_id": project_id, "created_at": created}

    def create_session(self, title: str = "Nova conversa", project_id: str | None = None, metadata=None) -> str:
        title = redact_secrets(title.strip())[:160] or "Nova conversa"
        with self._lock, self._db:
            if project_id:
                self._project(project_id)
            session_id, created = uuid.uuid4().hex, _now()
            self._db.execute(
                "INSERT INTO sessions(id,title,project_id,created_at,updated_at) VALUES(?,?,?,?,?)",
                (session_id, title, project_id, created, created),
            )
            if metadata:
                self._db.execute("INSERT INTO session_metadata VALUES(?,?)", (session_id, self._metadata(metadata)))
            return session_id

    def sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{**{key: row[key] for key in row.keys() if key != "metadata"}, **json.loads(row["metadata"] or "{}")} for row in self._db.execute(
                "SELECT s.*,m.document AS metadata FROM sessions s LEFT JOIN session_metadata m ON s.id=m.session_id ORDER BY s.updated_at DESC,s.id"
            )]

    @staticmethod
    def _metadata(value):
        if not isinstance(value, dict) or len(json.dumps(value)) > 16000:
            raise ValueError("Metadados de conversa inválidos ou excessivos.")
        return json.dumps({key: item for key, item in value.items() if key in
            {"model", "models_used", "review_model", "agent", "agent_name", "workspace_mode", "operation_mode", "profile", "research_performed"}}, ensure_ascii=False)

    def session(self, session_id):
        with self._lock:
            row = dict(self._session(session_id))
            meta = self._db.execute("SELECT document FROM session_metadata WHERE session_id=?", (session_id,)).fetchone()
            return {**row, **(json.loads(meta[0]) if meta else {})}

    def update_session_metadata(self, session_id, metadata):
        with self._lock, self._db:
            self._session(session_id)
            self._db.execute("INSERT INTO session_metadata VALUES(?,?) ON CONFLICT(session_id) DO UPDATE SET document=excluded.document", (session_id, self._metadata(metadata)))

    def _session(self, session_id: str) -> sqlite3.Row:
        session = self._db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if session is None:
            raise ValueError("Conversa não encontrada.")
        return session

    def messages(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self._session(session_id)
            return [self._message_row(row) for row in self._db.execute(
                "SELECT m.id,m.session_id,m.role,m.content,m.created_at,x.document AS metadata FROM messages m LEFT JOIN message_metadata x ON m.id=x.message_id WHERE m.session_id=? ORDER BY m.id",
                (session_id,),
            )]

    @staticmethod
    def _message_row(row):
        result = dict(row)
        source = result.pop("metadata", None)
        if source:
            result["metadata"] = json.loads(source)
        return result

    def add_message(self, session_id: str, role: str, content: str, metadata=None) -> None:
        if role not in {"user", "assistant", "system", "tool"}:
            raise ValueError("Papel da mensagem inválido.")
        if len(content) > self.MAX_MESSAGE_CHARS:
            raise ValueError("Mensagem excede o limite técnico de 2 milhões de caracteres.")
        with self._lock, self._db:
            self._session(session_id)
            created = _now()
            cursor = self._db.execute(
                "INSERT INTO messages(session_id,role,content,created_at) VALUES(?,?,?,?)",
                (session_id, role, redact_secrets(content), created),
            )
            if metadata:
                self._db.execute("INSERT INTO message_metadata VALUES(?,?)", (cursor.lastrowid, self._metadata(metadata)))
            self._db.execute("UPDATE sessions SET updated_at=? WHERE id=?", (created, session_id))

    def get_summary(self, session_id: str) -> str:
        with self._lock:
            return str(self._session(session_id)["summary"])

    def set_summary(self, session_id: str, text: str) -> None:
        if len(text) > self.MAX_MESSAGE_CHARS:
            raise ValueError("Resumo excede o limite técnico de armazenamento.")
        with self._lock, self._db:
            self._session(session_id)
            self._db.execute(
                "UPDATE sessions SET summary=?,updated_at=? WHERE id=?",
                (redact_secrets(text), _now(), session_id),
            )

    def export(self) -> dict[str, Any]:
        with self._lock:
            result = {
                "format_version": 1, "exported_at": _now(), "projects": self.projects(),
                "memories": [dict(row) for row in self._db.execute(
                    "SELECT id,text,kind,project_id,created_at FROM memories ORDER BY created_at,id"
                )],
                "sessions": self.sessions(),
                "messages": [self._message_row(row) for row in self._db.execute(
                    "SELECT m.id,m.session_id,m.role,m.content,m.created_at,x.document AS metadata FROM messages m LEFT JOIN message_metadata x ON m.id=x.message_id ORDER BY m.id"
                )],
                "documents": [dict(row) for row in self._db.execute(
                    "SELECT id,project_id,path,chunk_index,text FROM chunks ORDER BY project_id,path,chunk_index"
                )],
            }
            # Reapply filtering for databases written by an earlier application version.
            # Transform strings before serialization, preserving JSON escaping.
            def sanitize(value):
                if isinstance(value, str):
                    return redact_secrets(value)
                if isinstance(value, list):
                    return [sanitize(item) for item in value]
                if isinstance(value, dict):
                    return {key: sanitize(item) for key, item in value.items()}
                return value
            return sanitize(result)

    def delete_session(self, session_id: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def delete_memory(self, memory_id: str) -> None:
        with self._lock, self._db:
            if self._fts:
                self._db.execute(
                    "DELETE FROM search_index WHERE source_id=? AND source_type='memory'", (memory_id,)
                )
            self._db.execute("DELETE FROM memories WHERE id=?", (memory_id,))

    def status(self) -> dict[str, Any]:
        with self._lock:
            vectors = self._db.execute("""SELECT COUNT(*),COALESCE(SUM(LENGTH(vector)),0)
                FROM (SELECT vector FROM chunks WHERE vector IS NOT NULL
                      UNION ALL SELECT vector FROM memories WHERE vector IS NOT NULL)""").fetchone()
            database_bytes = 0
            if self._db_path != ":memory:":
                for suffix in ("", "-wal", "-shm"):
                    try:
                        database_bytes += Path(self._db_path + suffix).stat().st_size
                    except OSError:
                        pass
            return {
                "fts5": self._fts, "embedding_model": self.embedding_model,
                "embedding_mode": self.embedding_mode, "embedding_error": self.embedding_error,
                "embedding_dimension": self.embedding_dimension,
                "embedding_execution": "cpu; num_gpu=0; keep_alive=0",
                "embedding_vectors": vectors[0], "embedding_storage_bytes": vectors[1],
                "database_bytes": database_bytes,
                "projects": self._db.execute("SELECT COUNT(*) FROM projects").fetchone()[0],
                "documents": self._db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
                "memories": self._db.execute("SELECT COUNT(*) FROM memories").fetchone()[0],
                "limits": {"files": self.MAX_FILES, "file_bytes": self.MAX_FILE_BYTES,
                           "total_bytes": self.MAX_TOTAL_BYTES, "chunks": self.MAX_CHUNKS},
            }

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
