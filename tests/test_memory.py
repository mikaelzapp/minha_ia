"""Integration tests using real temporary files and persistent SQLite databases."""

import json
import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from nexus.memory import Memory, redact_secrets


class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.workspace = self.base / "workspaces"
        self.workspace.mkdir()
        self.project_path = self.workspace / "demo"
        self.project_path.mkdir()
        self.database = self.base / "data" / "memory.sqlite3"
        self.memory = Memory(self.database, self.workspace)
        self.project = self.memory.register_project("Demo", self.project_path)

    def tearDown(self):
        self.memory.close()
        self.temp.cleanup()

    def write(self, name, text):
        target = self.project_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def test_persistence_across_instances_and_session_deletion(self):
        item = self.memory.remember("Prefiro testes em Python", project_id=self.project["id"])
        session = self.memory.create_session("Programação", self.project["id"])
        self.memory.add_message(session, "user", "Como implementar um parser?")
        self.memory.add_message(session, "assistant", "Vamos definir a gramática.")
        self.memory.set_summary(session, "O usuário quer implementar um parser.")
        self.memory.close()
        self.memory = Memory(self.database, self.workspace)
        self.assertEqual(self.memory.projects()[0]["id"], self.project["id"])
        self.assertEqual(self.memory.messages(session)[0]["role"], "user")
        self.assertIn("parser", self.memory.get_summary(session))
        self.assertEqual(self.memory.search("Python")[0]["id"], item["id"])
        self.memory.delete_memory(item["id"])
        self.assertEqual(self.memory.search("Python"), [])
        self.memory.delete_session(session)
        self.assertEqual(self.memory.sessions(), [])
        self.assertEqual(self.memory.export()["messages"], [])

    def test_incremental_content_hash_and_removed_files(self):
        target = self.write("module.py", "def original():\n    return 'sqlite'\n")
        first = self.memory.index_project(self.project["id"])
        original_id = self.memory.search("original")[0]["id"]
        second = self.memory.index_project(self.project["id"])
        self.assertEqual(first["changed_files"], 1)
        self.assertEqual(second["changed_files"], 0)
        self.assertEqual(second["unchanged_files"], 1)
        self.assertEqual(self.memory.search("original")[0]["id"], original_id)
        old_stat = target.stat()
        target.write_text("def modified():\n    return 'sqlite'\n", encoding="utf-8")
        os.utime(target, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
        changed = self.memory.index_project(self.project["id"])
        self.assertEqual(changed["changed_files"], 1)
        self.assertEqual(self.memory.search("original"), [])
        self.assertIn("modified", self.memory.search("modified")[0]["text"])
        target.unlink()
        final = self.memory.index_project(self.project["id"])
        self.assertEqual(final["removed_files"], 1)
        self.assertEqual(final["indexed_files"], 0)
        self.assertEqual(self.memory.search("modified"), [])

    def test_secret_files_are_excluded_and_inline_credentials_redacted(self):
        secret = "ultra_confidential_123456789"
        for name in (".env", ".env.production", ".git/config", ".aws/credentials",
                     "credentials.json", "service-account-secret.json", "id_rsa", "private.pem"):
            self.write(name, "secretneedle=" + secret)
        self.write("app.py", f'API_KEY = "{secret}"\nPASSWORD="{secret}"\nprint("safe_marker")')
        result = self.memory.index_project(self.project["id"])
        self.assertEqual(result["indexed_files"], 1)
        self.assertEqual(self.memory.search("secretneedle"), [])
        found = self.memory.search("safe_marker")[0]
        self.assertNotIn(secret, found["text"])
        self.assertIn("[REDACTED]", found["text"])
        exported = json.dumps(self.memory.export())
        self.assertNotIn(secret, exported)
        self.assertNotIn("secretneedle", exported)

    def test_traversal_outside_absolute_and_excluded_roots_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        for path in (outside, "../outside", self.workspace / "demo" / ".." / ".." / "outside"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.memory.register_project("Outside", path)
        gitdir = self.project_path / ".git"
        gitdir.mkdir()
        with self.assertRaises(ValueError):
            self.memory.register_project("Git internals", gitdir)

    def test_symbolic_links_are_not_followed(self):
        outside = self.base / "external"
        outside.mkdir()
        (outside / "stolen.txt").write_text("external_private_marker", encoding="utf-8")
        link = self.project_path / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            if os.name != "nt":
                self.skipTest(f"Sistema não permite criar symlinks neste processo: {exc}")
            # NTFS junctions need no symlink privilege and exercise the actual
            # reparse-point protection on ordinary Windows installations.
            import _winapi
            try:
                _winapi.CreateJunction(str(outside), str(link))
            except OSError as junction_error:
                self.skipTest(f"Symlink e junction indisponíveis: {junction_error}")
        self.write("safe.txt", "authorized_marker")
        self.memory.index_project(self.project["id"])
        self.assertEqual(self.memory.search("external_private_marker"), [])
        self.assertTrue(self.memory.search("authorized_marker"))
        with self.assertRaises(ValueError):
            self.memory.register_project("Linked", link)

    def test_hardlinked_files_are_excluded(self):
        original = self.base / "credential.txt"
        original.write_text("hardlink_private_marker", encoding="utf-8")
        try:
            os.link(original, self.project_path / "linked.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"Hardlink indisponível: {exc}")
        result = self.memory.index_project(self.project["id"])
        self.assertEqual(result["indexed_files"], 0)
        self.assertEqual(self.memory.search("hardlink_private_marker"), [])

    def test_size_limits_and_binary_content(self):
        self.write("small.txt", "small_marker")
        self.write("oversized.txt", "X" * 90)
        (self.project_path / "binary.txt").write_bytes(b"binary_marker\x00bad")
        with patch.object(self.memory, "MAX_FILE_BYTES", 80):
            result = self.memory.index_project(self.project["id"])
        self.assertEqual(result["indexed_files"], 1)
        self.assertEqual(result["skipped_files"], 2)
        self.assertTrue(self.memory.search("small_marker"))
        self.assertEqual(self.memory.search("binary_marker"), [])

    def test_file_limit_keeps_already_indexed_unvisited_files(self):
        self.write("a.txt", "apple_marker")
        self.write("b.txt", "banana_marker")
        self.memory.index_project(self.project["id"])
        with patch.object(self.memory, "MAX_FILES", 1):
            result = self.memory.index_project(self.project["id"])
        self.assertTrue(result["limited"])
        self.assertEqual(result["indexed_files"], 2)
        self.assertTrue(self.memory.search("banana_marker"))

    def test_lexical_fallback_and_project_scoping(self):
        other_path = self.workspace / "other"
        other_path.mkdir()
        other = self.memory.register_project("Other", other_path)
        self.memory._fts = False
        global_memory = self.memory.remember("Preferência: programação com SQLite")
        private_memory = self.memory.remember("SQLite privado de outro projeto", project_id=other["id"])
        results = self.memory.search("programacao SQLite", project_id=self.project["id"])
        self.assertIn(global_memory["id"], {result["id"] for result in results})
        self.assertNotIn(private_memory["id"], {result["id"] for result in results})
        self.assertTrue(all(item["retrieval"] == "lexical" for item in results))
        self.assertEqual(self.memory.search("' OR 1=1; DROP TABLE projects --"), [])

    def test_messages_export_redacts_and_preserves_serialization(self):
        secret = "private_message_987654321"
        session = self.memory.create_session()
        self.memory.add_message(session, "user", f'Use password="{secret}" e uma aspa \\".')
        self.memory.set_summary(session, f"api_key='{secret}'")
        self.memory.remember(f"token='{secret}'")
        exported = self.memory.export()
        encoded = json.dumps(exported, ensure_ascii=False)
        self.assertNotIn(secret, encoded)
        self.assertEqual(json.loads(encoded)["messages"][0]["role"], "user")
        self.assertIn("[REDACTED]", self.memory.messages(session)[0]["content"])

    def test_concurrent_messages_are_committed_without_loss(self):
        session = self.memory.create_session()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda index: self.memory.add_message(session, "user", f"message {index}"), range(40)))
        messages = self.memory.messages(session)
        self.assertEqual(len(messages), 40)
        self.assertEqual(len({message["id"] for message in messages}), 40)

    def test_embedding_options_and_explicit_offline_fallback(self):
        captured = []

        class LocalClient:
            def __init__(self, **kwargs):
                captured.append(kwargs)
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return None
            def post(self, url, json):
                captured.append((url, json))
                return SimpleNamespace(
                    raise_for_status=lambda: None,
                    json=lambda: {"embeddings": [[1.0, 0.0, 0.5] for _ in json["input"]]},
                )

        self.memory.embedding_model = "embeddinggemma"
        with patch.dict("sys.modules", {"httpx": SimpleNamespace(Client=LocalClient)}):
            item = self.memory.remember("Explain persistent semantic search")
            results = self.memory.search("persistent")
        self.assertEqual(results[0]["id"], item["id"])
        self.assertEqual(results[0]["retrieval"], "hybrid")
        self.assertEqual(self.memory.status()["embedding_dimension"], 3)
        self.assertEqual(self.memory.status()["embedding_vectors"], 1)
        for value in captured:
            if isinstance(value, tuple):
                self.assertEqual(value[0], "http://127.0.0.1:11434/api/embed")
                self.assertEqual(value[1]["options"]["num_gpu"], 0)
                self.assertEqual(value[1]["keep_alive"], "0")
            else:
                self.assertFalse(value["trust_env"])
                self.assertFalse(value["follow_redirects"])
        with patch.dict("sys.modules", {"httpx": SimpleNamespace(Client=lambda **_: (_ for _ in ()).throw(OSError("offline")))}):
            results = self.memory.search("persistent")
        self.assertTrue(results)
        self.assertEqual(self.memory.status()["embedding_mode"], "lexical")
        self.assertIn("Nenhum modelo foi baixado", self.memory.status()["embedding_error"])

    def test_remote_embedding_url_rejected(self):
        for url in ("https://example.com", "http://127.0.0.1.evil.test", "http://u:p@localhost:11434"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Memory(":memory:", self.workspace, ollama_url=url)

    def test_slow_embedding_http_does_not_lock_second_instance_initialization_or_reads(self):
        try:
            import httpx  # noqa: F401 -- optional embedding dependency
        except ImportError:
            self.skipTest("httpx não instalado; embeddings são opcionais.")
        requested, release = threading.Event(), threading.Event()

        class SlowEmbeddingHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requested.set()
                release.wait(timeout=5)
                body = json.dumps({"embeddings": [[1.0, 0.0, 0.5] for _ in payload["input"]]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        target = self.write("code.txt", "original_committed_marker")
        self.memory.index_project(self.project["id"])
        target.write_text("updated_after_embedding_marker", encoding="utf-8")
        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowEmbeddingHandler)
        server_thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        server_thread.start()
        self.memory.ollama_url = f"http://127.0.0.1:{server.server_port}"
        self.memory.embedding_model = "slow-test-model"

        def reopen_and_read():
            with Memory(self.database, self.workspace, embedding_model="") as second:
                projects = second.projects()
                existing = second.search("original_committed_marker")
                saved = second.remember("concurrent_writer_marker")
                return projects, existing, saved

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                indexing = pool.submit(self.memory.index_project, self.project["id"])
                try:
                    self.assertTrue(requested.wait(timeout=3), "The test embedding HTTP request did not start.")
                    self.assertFalse(self.memory._db.in_transaction, "Embedding HTTP must run outside SQLite transactions.")
                    reopened = pool.submit(reopen_and_read)
                    projects, existing, saved = reopened.result(timeout=1.5)
                    self.assertEqual(projects[0]["id"], self.project["id"])
                    self.assertTrue(existing, "Readers should retain the previous committed file during embedding.")
                    self.assertIn("concurrent_writer_marker", saved["text"])
                finally:
                    release.set()
                self.assertEqual(indexing.result(timeout=3)["changed_files"], 1)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)
            self.memory.embedding_model = ""
        self.assertTrue(self.memory.search("updated_after_embedding_marker"))
        self.assertEqual(self.memory.search("original_committed_marker"), [])
        self.assertTrue(self.memory.search("concurrent_writer_marker"))

    def test_known_tokens_and_private_keys_redacted(self):
        values = ["ghp_" + "A" * 36, "sk-" + "x" * 32, "AKIA" + "A" * 16]
        for value in values:
            self.assertNotIn(value, redact_secrets(value))
        private_key = "-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----"
        self.assertNotIn("abc123", redact_secrets(private_key))


if __name__ == "__main__":
    unittest.main()
