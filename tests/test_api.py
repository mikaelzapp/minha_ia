"""API integration tests with isolated SQLite and a deterministic local model.

No model, browser, network call, user database, or real command is used.
FastAPI's actual middleware, policies, approval route and NDJSON stream run.
"""

import asyncio
import atexit
import base64
import copy
import importlib
import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from nexus import config as nexus_config
from nexus.memory import Memory
from nexus.tools import Tools


# Importing the application constructs its singletons. Redirect those paths
# before import, so test collection never opens the user's SQLite database or
# waits behind a real benchmark/indexing transaction. Restore config globals
# immediately; the test module keeps its own isolated application singletons.
_import_temp = tempfile.TemporaryDirectory(prefix="nexus-api-import-")
_import_root = Path(_import_temp.name)
_import_data = _import_root / "data"
_import_workspaces = _import_root / "workspaces"
_import_data.mkdir()
_import_workspaces.mkdir()
with patch.object(nexus_config, "DATA", _import_data), patch.object(nexus_config, "WORKSPACES", _import_workspaces):
    api = importlib.import_module("nexus.app")


def _cleanup_import_singletons():
    if api.DATA == _import_data:
        api.memory.close()
    _import_temp.cleanup()


atexit.register(_cleanup_import_singletons)


MODEL = "nexus-test:local"
PNG_BYTES = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j0GQAAAAASUVORK5CYII=")


def call(name, arguments):
    return {"type": "call", "call": {"function": {"name": name, "arguments": arguments}}}


class FakeOllama:
    """Same async inventory/stream contract as the real Ollama adapter."""

    def __init__(self):
        self.turns = [[{"type": "token", "content": "Resposta local."}]]
        self.requests = []

    async def inventory(self):
        return {"connected": True, "models": [{"name": MODEL}], "running": []}

    async def stream(self, model, messages, **kwargs):
        self.requests.append({"model": model, "messages": copy.deepcopy(messages), **copy.deepcopy(kwargs)})
        events = self.turns.pop(0) if self.turns else [{"type": "token", "content": "Concluído."}]
        for event in events:
            await asyncio.sleep(0)
            yield copy.deepcopy(event)
        yield {"type": "metrics", "model": model, "tokens": 3, "tokens_per_second": 1}

    async def complete(self, *_args, **_kwargs):
        return "Resumo de teste."


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.workspace = self.base / "workspaces"
        self.workspace.mkdir()
        self.project_root = self.workspace / "demo"
        self.project_root.mkdir()
        self.data = self.base / "api-data"
        self.data.mkdir()
        with patch.object(nexus_config, "DATA", self.data):
            self.settings = nexus_config.Settings()
        self.settings.update({"model": MODEL, "context": 4096, "temperature": 0.3, "thinking": False}, save=False)
        self.memory = Memory(self.base / "memory.sqlite3", self.workspace, embedding_model="")
        self.session = self.memory.create_session("Teste isolado")
        self.engine = FakeOllama()
        self.tools = Tools(self.workspace, self.base / "tool-data")
        self.execute = MagicMock(wraps=self.tools.execute)
        self.tools.execute = self.execute
        self.audit = MagicMock()
        self.audit.cursor.return_value = 0
        self.audit.list.return_value = []
        self.patches = [
            patch.object(api, "memory", self.memory),
            patch.object(api, "engine", self.engine),
            patch.object(api, "activity", self.audit),
            patch.object(api, "WORKSPACES", self.workspace),
            patch.object(api, "DATA", self.data),
            patch.object(api, "AUTH_TOKEN", "test-only-local-token"),
            patch.object(api, "settings", self.settings),
            patch.object(api, "system_status", return_value={"test": True}),
            patch.object(api, "inference", asyncio.Semaphore(1)),
            patch.object(api, "session_locks", {}),
            patch.object(api, "pending", {}),
            patch.object(api, "get_tools", return_value=self.tools),
        ]
        for item in self.patches:
            item.start()
        self.client = TestClient(api.app, base_url="http://testserver", raise_server_exceptions=False)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.tools.close()
        self.memory.close()
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def authenticate(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        return response

    def chat_payload(self, **changes):
        payload = {"session_id": self.session, "message": "Ajude com meu projeto", "mode": "CHAT", "agent": "auto"}
        payload.update(changes)
        return payload

    def events(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("application/x-ndjson", response.headers["content-type"])
        events = [json.loads(line) for line in response.text.splitlines() if line.strip()]
        self.assertEqual(events[-1], {"type": "done"})
        self.assertFalse([event for event in events if event["type"] == "error"], events)
        return events

    def wait_approval(self, *, excluding=(), future=None):
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            for approval_id in list(api.pending):
                if approval_id not in excluding:
                    return approval_id
            if future is not None and future.done():
                self.fail(f"Geração terminou sem pedir aprovação: {future.result().text}")
            time.sleep(0.01)
        self.fail("Aprovação não apareceu em seis segundos.")

    def test_api_requires_token(self):
        response = self.client.get("/api/sessions")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.post("/api/chat", json=self.chat_payload()).status_code, 401)
        self.assertEqual(self.engine.requests, [])

    def test_bootstrap_cookie_authenticates_and_is_http_only(self):
        response = self.authenticate()
        cookie = response.headers["set-cookie"].casefold()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertNotIn("test-only-local-token", response.text)
        self.assertEqual(self.client.get("/api/sessions").status_code, 200)
        self.assertEqual(response.headers["x-frame-options"], "DENY")

    def test_bearer_authentication_works_without_cookie(self):
        response = self.client.get("/api/sessions", headers={"Authorization": "Bearer test-only-local-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.cookies, {})

    def test_external_origin_host_and_fetch_site_are_blocked(self):
        self.authenticate()
        for headers in ({"Origin": "https://attacker.example"},
                        {"Origin": "http://testserver:9999"},
                        {"Origin": "null"},
                        {"Sec-Fetch-Site": "cross-site"},
                        {"Host": "attacker.example"}):
            with self.subTest(headers=headers):
                response = self.client.post("/api/sessions", json={"title": "injected"}, headers=headers)
                self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.memory.sessions()), 1)

    def test_same_origin_is_allowed(self):
        self.authenticate()
        response = self.client.get("/api/sessions", headers={"Origin": "http://testserver"})
        self.assertEqual(response.status_code, 200)

    def test_thinking_setting_roundtrips_and_persists(self):
        self.authenticate()
        for enabled in (True, False):
            with self.subTest(thinking=enabled):
                saved = self.client.post("/api/settings", json={"thinking": enabled})
                self.assertEqual(saved.status_code, 200)
                self.assertIs(saved.json()["thinking"], enabled)
                status = self.client.get("/api/status")
                self.assertEqual(status.status_code, 200)
                self.assertIs(status.json()["settings"]["thinking"], enabled)
                with patch.object(nexus_config, "DATA", self.data):
                    reloaded = nexus_config.Settings()
                self.assertIs(reloaded["thinking"], enabled)

    def test_chat_passes_default_and_explicit_thinking_to_engine(self):
        self.authenticate()
        self.assertEqual(self.client.post("/api/settings", json={"thinking": True}).status_code, 200)
        for override, expected in ((None, True), (False, False), (True, True)):
            with self.subTest(override=override):
                changes = {} if override is None else {"thinking": override}
                self.events(self.client.post("/api/chat", json=self.chat_payload(**changes)))
                self.assertIs(self.engine.requests[-1]["thinking"], expected)
        self.assertIs(self.settings["thinking"], True, "A per-message override must not change saved settings.")

    def test_screenshots_require_auth_and_are_served_as_png(self):
        folder = self.data / "screenshots"
        folder.mkdir()
        filename = "a" * 32 + ".png"
        (folder / filename).write_bytes(PNG_BYTES)
        route = "/api/screenshots/" + filename
        self.assertEqual(self.client.get(route).status_code, 401)
        self.authenticate()
        response = self.client.get(route)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, PNG_BYTES)
        self.assertEqual(response.headers["content-type"], "image/png")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(self.client.get("/api/screenshots/" + "b" * 32 + ".png").status_code, 404)

    def test_screenshot_identifiers_reject_traversal_and_other_file_types(self):
        self.authenticate()
        (self.data / "auth.secret").write_text("private_test_marker", encoding="utf-8")
        filenames = (
            "../auth.secret", "%2e%2e%2fauth.secret", "%2e%2e%5cauth.secret",
            "auth.secret", "a" * 32 + ".txt", "a" * 32 + ".svg",
            "a" * 32 + ".PNG", "a" * 31 + ".png", "g" * 32 + ".png",
            "a" * 32 + ".png%00.txt", "a" * 32 + ".png/extra",
        )
        for filename in filenames:
            with self.subTest(filename=filename):
                response = self.client.get("/api/screenshots/" + filename)
                self.assertIn(response.status_code, (400, 404))
                self.assertNotIn("private_test_marker", response.text)

    def test_screenshot_directory_cannot_escape_through_junction_or_symlink(self):
        self.authenticate()
        outside = self.base / "external-screenshots"
        outside.mkdir()
        filename = "c" * 32 + ".png"
        (outside / filename).write_bytes(PNG_BYTES)
        folder = self.data / "screenshots"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside), str(folder))
        else:
            folder.symlink_to(outside, target_is_directory=True)
        response = self.client.get("/api/screenshots/" + filename)
        self.assertIn(response.status_code, (400, 404), "Screenshot route followed a directory link outside its data root.")

    def test_chat_stream_has_no_tools_and_ends_with_done(self):
        self.authenticate()
        self.engine.turns = [[{"type": "token", "content": "Olá "}, {"type": "token", "content": "mundo."}]]
        response = self.client.post("/api/chat", json=self.chat_payload())
        events = self.events(response)
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        self.assertEqual("".join(event["content"] for event in events if event["type"] == "token"), "Olá mundo.")
        self.assertEqual(self.engine.requests[0]["tools"], [])
        self.execute.assert_not_called()
        messages = self.memory.messages(self.session)
        self.assertEqual([message["role"] for message in messages], ["user", "assistant"])
        self.assertEqual(messages[-1]["content"], "Olá mundo.")

    def test_chat_rejects_unsolicited_tool_calls(self):
        self.authenticate()
        self.engine.turns = [[call("write_file", {"path": "demo/forbidden.txt", "content": "bad"})],
                             [{"type": "token", "content": "Sem alterações."}]]
        events = self.events(self.client.post("/api/chat", json=self.chat_payload()))
        self.execute.assert_not_called()
        self.assertFalse(any(event["type"] == "approval" for event in events))
        errors = [event["result"]["error"] for event in events if event["type"] == "tool"]
        self.assertTrue(errors)
        self.assertFalse((self.project_root / "forbidden.txt").exists())

    def test_plan_cannot_write_even_if_model_requests_it(self):
        self.authenticate()
        self.engine.turns = [[call("write_file", {"path": "demo/plan.txt", "content": "bad"})],
                             [{"type": "token", "content": "Plano pronto."}]]
        events = self.events(self.client.post("/api/chat", json=self.chat_payload(mode="PLAN")))
        names = {schema["function"]["name"] for schema in self.engine.requests[0]["tools"]}
        self.assertNotIn("write_file", names)
        self.assertNotIn("run_command", names)
        self.execute.assert_not_called()
        self.assertFalse(any(event["type"] == "approval" for event in events))
        self.assertFalse((self.project_root / "plan.txt").exists())

    def test_refused_approval_never_executes(self):
        self.authenticate()
        self.engine.turns = [[call("write_file", {"path": "demo/refused.txt", "content": "bad"})],
                             [{"type": "token", "content": "Operação recusada."}]]
        with ThreadPoolExecutor(max_workers=1) as pool:
            response_future = pool.submit(self.client.post, "/api/chat", json=self.chat_payload(mode="CODE"))
            approval_id = self.wait_approval(future=response_future)
            decision = self.client.post(f"/api/approvals/{approval_id}", json={"approved": False})
            self.assertEqual(decision.status_code, 200)
            events = self.events(response_future.result(timeout=8))
        self.execute.assert_not_called()
        self.assertFalse((self.project_root / "refused.txt").exists())
        self.assertEqual(api.pending, {})
        tool_event = next(event for event in events if event["type"] == "tool")
        self.assertIn("recusada", tool_event["result"]["error"])

    def test_approval_is_exact_single_use_and_does_not_authorize_another_write(self):
        self.authenticate()
        approved_args = {"path": "demo/approved.txt", "content": "approved content"}
        other_args = {"path": "demo/unapproved.txt", "content": "different content"}
        self.engine.turns = [[call("write_file", approved_args)], [call("write_file", other_args)],
                             [{"type": "token", "content": "Concluído."}]]
        with ThreadPoolExecutor(max_workers=1) as pool:
            response_future = pool.submit(self.client.post, "/api/chat", json=self.chat_payload(mode="CODE"))
            first = self.wait_approval(future=response_future)
            self.assertEqual(self.client.post(f"/api/approvals/{first}", json={"approved": True}).status_code, 200)
            self.assertEqual(self.client.post(f"/api/approvals/{first}", json={"approved": True}).status_code, 404)
            second = self.wait_approval(excluding={first}, future=response_future)
            self.assertNotEqual(first, second)
            self.assertEqual(self.client.post(f"/api/approvals/{second}", json={"approved": False}).status_code, 200)
            events = self.events(response_future.result(timeout=8))
        self.execute.assert_called_once()
        self.assertEqual(self.execute.call_args.args[0], "write_file")
        # The orchestrator may add a before-hash to bind an approved diff.
        for key, value in approved_args.items():
            self.assertEqual(self.execute.call_args.args[1][key], value)
        self.assertEqual((self.project_root / "approved.txt").read_text(encoding="utf-8"), approved_args["content"])
        self.assertFalse((self.project_root / "unapproved.txt").exists())
        approvals = [event for event in events if event["type"] == "approval"]
        self.assertEqual(len(approvals), 2)
        self.assertEqual(approvals[0]["arguments"], approved_args)
        self.assertEqual(api.pending, {})

    def test_post_project_rejects_paths_outside_workspace(self):
        self.authenticate()
        outside = self.base / "outside"
        outside.mkdir()
        for value in (str(outside), "../outside"):
            with self.subTest(path=value):
                response = self.client.post("/api/projects", json={"name": "escape", "path": value})
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/api/projects").json(), [])

    def test_file_changed_after_approval_preview_is_not_overwritten(self):
        self.authenticate()
        target = self.project_root / "concurrent.txt"
        target.write_text("original content", encoding="utf-8")
        self.engine.turns = [[call("write_file", {"path": "demo/concurrent.txt", "content": "model replacement"})],
                             [{"type": "token", "content": "A alteração concorrente foi preservada."}]]
        with ThreadPoolExecutor(max_workers=1) as pool:
            response_future = pool.submit(self.client.post, "/api/chat", json=self.chat_payload(mode="CODE"))
            approval_id = self.wait_approval(future=response_future)
            target.write_text("concurrent human edit", encoding="utf-8")
            self.assertEqual(self.client.post(f"/api/approvals/{approval_id}", json={"approved": True}).status_code, 200)
            events = self.events(response_future.result(timeout=8))
        self.assertEqual(target.read_text(encoding="utf-8"), "concurrent human edit")
        tool_event = next(event for event in events if event["type"] == "tool")
        self.assertTrue(tool_event["result"].get("error"), tool_event)
        self.assertIn("expected_sha256", self.execute.call_args.args[1])

    def test_get_project_memory_rejects_escaped_or_unknown_project(self):
        self.authenticate()
        for project_id in ("../outside", str(self.base / "outside"), "unknown-project"):
            with self.subTest(project_id=project_id):
                response = self.client.get("/api/memory/search", params={"q": "private", "project_id": project_id})
                self.assertIn(response.status_code, (400, 404), response.text)

    def test_project_registration_and_get_return_only_authorized_project(self):
        self.authenticate()
        response = self.client.post("/api/projects", json={"name": "Demo", "path": str(self.project_root)})
        self.assertEqual(response.status_code, 200)
        project = response.json()
        self.assertEqual(Path(project["path"]), self.project_root)
        self.assertEqual(self.client.get("/api/projects").json()[0]["id"], project["id"])
        outside_response = self.client.post("/api/chat", json=self.chat_payload(project_id="../outside"))
        self.assertEqual(outside_response.status_code, 404)
        self.assertEqual(self.engine.requests, [])

    def test_unknown_model_is_rejected_without_generation(self):
        self.authenticate()
        response = self.client.post("/api/chat", json=self.chat_payload(model="not-installed:large"))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.engine.requests, [])
        self.assertEqual(self.memory.messages(self.session), [])

    def test_stream_backpressure_and_close_release_generation(self):
        class ProbeEngine(FakeOllama):
            produced = 0
            closed = False
            async def stream(self, *_args, **_kwargs):
                try:
                    for text in ("partial", " never consumed"):
                        self.produced += 1
                        yield {"type": "token", "content": text}
                finally:
                    self.closed = True

        class Request:
            async def is_disconnected(self):
                return False

        probe = ProbeEngine()
        async def scenario():
            with patch.object(api, "engine", probe):
                response = await api.chat(api.ChatInput(**self.chat_payload()), Request())
                stream = response.body_iterator
                while json.loads(await anext(stream))["type"] != "token":
                    pass
                self.assertEqual(probe.produced, 1)
                await asyncio.sleep(0)
                self.assertEqual(probe.produced, 1, "The model must not be drained in the background.")
                self.assertTrue(api.inference.locked())
                await stream.aclose()
                self.assertTrue(probe.closed)
                self.assertFalse(api.inference.locked())
                self.assertFalse(api.session_locks[self.session].locked())
                self.assertEqual(api.pending, {})
        asyncio.run(scenario())
        self.assertEqual(self.memory.messages(self.session)[-1]["content"], "partial")

    def test_disconnect_closes_source_before_releasing_inference(self):
        class Request:
            disconnected = False
            async def is_disconnected(self):
                return self.disconnected

        request = Request()
        closed_while_locked = []

        async def source(*_args, **_kwargs):
            try:
                yield {"type": "token", "content": "partial"}
                yield {"type": "token", "content": "discarded"}
            finally:
                closed_while_locked.append(api.inference.locked())

        async def scenario():
            with patch.object(self.engine, "stream", source):
                response = await api.chat(api.ChatInput(**self.chat_payload()), request)
                stream = response.body_iterator
                while json.loads(await anext(stream))["type"] != "token":
                    pass
                request.disconnected = True
                with self.assertRaises(StopAsyncIteration):
                    await anext(stream)
                self.assertEqual(closed_while_locked, [True])
                self.assertFalse(api.inference.locked())
                self.assertFalse(api.session_locks[self.session].locked())
        asyncio.run(scenario())
        self.assertEqual(self.memory.messages(self.session)[-1]["content"], "partial")

    def test_closing_approval_stream_removes_pending_without_execution(self):
        class Request:
            async def is_disconnected(self):
                return False

        self.engine.turns = [[call("write_file", {"path": "demo/canceled.txt", "content": "bad"})]]
        async def scenario():
            response = await api.chat(api.ChatInput(**self.chat_payload(mode="CODE")), Request())
            stream = response.body_iterator
            while json.loads(await anext(stream))["type"] != "approval":
                pass
            self.assertEqual(len(api.pending), 1)
            await stream.aclose()
            self.assertEqual(api.pending, {})
            self.assertFalse(api.inference.locked())
            self.assertFalse(api.session_locks[self.session].locked())
        asyncio.run(scenario())
        self.execute.assert_not_called()
        self.assertFalse((self.project_root / "canceled.txt").exists())

    def test_cancelled_worker_holds_inference_until_thread_finishes(self):
        started, release = threading.Event(), threading.Event()

        def worker():
            started.set()
            release.wait(timeout=3)

        async def scenario():
            async def run_worker():
                async with api.inference:
                    await api.blocking(worker)
            task = asyncio.create_task(run_worker())
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 1))
                task.cancel()
                await asyncio.sleep(0)
                self.assertTrue(api.inference.locked(), "Cancellation must not release inference while its worker is active.")
            finally:
                release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertFalse(api.inference.locked())
        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
