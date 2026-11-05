"""Snapshots and real file rollback, including Windows handle-based deletion."""
import asyncio
import hashlib
import os
from pathlib import Path
import time
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from nexus.developer import DeveloperHistory, EMPTY_SHA256, HistoryError, install_developer_routes
from nexus.tools import MAX_FILE, ToolError, Tools


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def case(tmp_path):
    data = tmp_path / "data"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tools = Tools(workspace, data)
    history = DeveloperHistory(data)
    opened = []
    def factory(root_id):
        assert root_id is None
        executor = Tools(workspace, data)
        opened.append(executor)
        return executor
    yield SimpleNamespace(history=history, tools=tools, factory=factory, workspace=workspace, data=data, opened=opened)
    tools.close()


def write(case, path="example.py", content="print('after')\n"):
    before = case.workspace / path
    expected = sha(before.read_bytes()) if before.exists() else EMPTY_SHA256
    result = case.history.execute_write(case.tools, {"path": path, "content": content, "expected_sha256": expected})
    assert result["ok"] is True, result
    return result


def test_modified_file_restores_exact_bytes_including_bom_crlf(case):
    original = b"\xef\xbb\xbf# original\r\nprint('before')\r\n"
    target = case.workspace / "example.py"
    target.write_bytes(original)
    result = write(case)
    change = case.history.list()[0]
    assert change["status"] == "applied" and change["before_exists"] == 1
    assert change["before_sha256"] == sha(original)
    assert "before_data" not in change and "after_data" not in change
    preview = case.history.preview(result["change_id"], case.factory)
    assert preview["action"] == "restore_file" and "before" in preview["diff"]
    restored = case.history.restore(result["change_id"], case.factory, preview["current_sha256"])
    assert restored["ok"] is True and target.read_bytes() == original
    changes = case.history.list()
    assert len(changes) == 2 and changes[0]["restore_of"] == result["change_id"]
    assert changes[1]["restored_at"]
    with pytest.raises(HistoryError) as error:
        case.history.preview(result["change_id"], case.factory)
    assert error.value.code == "history_not_restorable"


def test_new_file_undo_removes_only_file_and_inverse_can_restore_it(case):
    result = write(case, "new/folder.txt", "created\n")
    target = case.workspace / "new" / "folder.txt"
    preview = case.history.preview(result["change_id"], case.factory)
    assert preview["removes_created_file"] is True
    undone = case.history.restore(result["change_id"], case.factory, preview["current_sha256"])
    assert not target.exists() and target.parent.is_dir()
    assert undone["removed_created_file"] is True
    inverse = case.history.preview(undone["change_id"], case.factory)
    assert inverse["restores_missing"] is True
    redone = case.history.restore(undone["change_id"], case.factory, inverse["current_sha256"])
    assert redone["ok"] is True and target.read_text() == "created\n"


def test_preexisting_empty_file_is_restored_instead_of_deleted(case):
    target = case.workspace / "example.py"
    target.write_bytes(b"")
    result = write(case)
    preview = case.history.preview(result["change_id"], case.factory)
    assert preview["removes_created_file"] is False
    case.history.restore(result["change_id"], case.factory, preview["current_sha256"])
    assert target.is_file() and target.read_bytes() == b""


def test_restart_preserves_snapshots_and_unrelated_data(case):
    sentinel = case.data / "memory.sqlite3"
    sentinel.write_bytes(b"original unrelated database")
    result = write(case)
    restarted = DeveloperHistory(case.data)
    assert restarted.list() == case.history.list()
    preview = restarted.preview(result["change_id"], case.factory)
    restarted.restore(result["change_id"], case.factory, preview["current_sha256"])
    assert sentinel.read_bytes() == b"original unrelated database"


def test_later_edits_are_not_overwritten_or_deleted(case):
    result = write(case)
    target = case.workspace / "example.py"
    target.write_text("user edited later", encoding="utf-8")
    with pytest.raises(HistoryError) as error:
        case.history.preview(result["change_id"], case.factory)
    assert error.value.code == "history_file_changed"
    with pytest.raises(HistoryError):
        case.history.restore(result["change_id"], case.factory, sha(b"print('after')\n"))
    assert target.read_text() == "user edited later" and len(case.history.list()) == 1


def test_change_between_preview_and_approval_is_rejected(case):
    result = write(case)
    preview = case.history.preview(result["change_id"], case.factory)
    target = case.workspace / "example.py"
    target.write_text("different", encoding="utf-8")
    with pytest.raises(HistoryError) as error:
        case.history.restore(result["change_id"], case.factory, preview["current_sha256"])
    assert error.value.code == "history_file_changed" and target.read_text() == "different"


def test_snapshot_does_not_replace_cas_hash_from_original_approval(case, monkeypatch):
    target = case.workspace / "example.py"
    target.write_bytes(b"before")
    original_snapshot = case.history._snapshot
    changed = False
    def race(tools, relative):
        nonlocal changed
        if not changed:
            changed = True
            target.write_bytes(b"external change after approved diff")
        return original_snapshot(tools, relative)
    monkeypatch.setattr(case.history, "_snapshot", race)
    result = case.history.execute_write(case.tools, {"path": "example.py", "content": "after", "expected_sha256": sha(b"before")})
    assert result["ok"] is False and result["code"] == "history_file_changed"
    assert target.read_bytes() == b"external change after approved diff" and case.history.list() == []


def test_failed_tool_and_unconfirmed_after_state_are_not_restorable(case, monkeypatch):
    monkeypatch.setattr(case.tools, "execute", lambda name, args: {"ok": False, "error": "tool failed"})
    result = case.history.execute_write(case.tools, {"path": "example.py", "content": "after"})
    assert not result["ok"] and case.history.list()[0]["status"] == "failed"
    assert not (case.workspace / "example.py").exists()
    with pytest.raises(HistoryError, match="Só alterações"):
        case.history.preview(result["change_id"], case.factory)
    def changed_after_success(name, args):
        (case.workspace / "example.py").write_text("external", encoding="utf-8")
        return {"ok": True}
    monkeypatch.setattr(case.tools, "execute", changed_after_success)
    result = case.history.execute_write(case.tools, {"path": "example.py", "content": "after"})
    assert not result["ok"] and case.history.list()[0]["status"] == "failed"
    assert (case.workspace / "example.py").read_text() == "external"


@pytest.mark.parametrize("args", [
    {"path": "../outside.py", "content": "x"}, {"path": ".env", "content": "x"},
    {"path": "passwords.txt", "content": "x"}, {"path": "x.py", "content": "\x00"},
    {"path": "x.py", "content": "x" * (MAX_FILE + 1)}, {"path": "x.py", "content": 1},
    {"path": "x.py", "content": "x", "root_id": "forged"},
])
def test_invalid_write_has_no_snapshot_or_mutation(case, args):
    result = case.history.execute_write(case.tools, args)
    assert result["ok"] is False and case.history.list() == []
    assert list(case.workspace.iterdir()) == []


def test_revoked_grant_and_root_replacement_are_checked_at_restore(case, tmp_path):
    root_id = "a" * 16
    result = case.history.execute_write(case.tools, {"path": "pc.py", "content": "after"}, root_id=root_id)
    assert result["ok"] is True
    def revoked(identity):
        assert identity == root_id
        raise ToolError("Pasta não autorizada ou autorização revogada")
    with pytest.raises(ToolError, match="revogada"):
        case.history.preview(result["change_id"], revoked)
    other = tmp_path / "different-root"
    other.mkdir()
    (other / "pc.py").write_text("after")
    with pytest.raises(HistoryError) as error:
        case.history.preview(result["change_id"], lambda identity: Tools(other, case.data))
    assert error.value.code == "history_root_changed"
    assert (case.workspace / "pc.py").read_text() == "after" and (other / "pc.py").read_text() == "after"


def test_preview_diff_redacts_recognized_credentials_but_snapshot_restores_exact_bytes(case):
    old = "api_key = 'private-original-value'\n"
    target = case.workspace / "example.py"
    target.write_text(old, encoding="utf-8")
    result = write(case, content="api_key = 'private-new-value'\n")
    preview = case.history.preview(result["change_id"], case.factory)
    assert "private-original-value" not in preview["diff"] and "private-new-value" not in preview["diff"]
    assert preview["diff_redacted"] is True and "REDACTED" in preview["diff"]
    assert "private-original-value" not in str(case.history.list())
    case.history.restore(result["change_id"], case.factory, preview["current_sha256"])
    assert target.read_text(encoding="utf-8") == old


def test_tampered_snapshots_fail_hash_check(case):
    result = write(case)
    with case.history.connection() as db:
        db.execute("UPDATE changes SET before_data=? WHERE id=?", (b"tampered", result["change_id"]))
    with pytest.raises(HistoryError) as error:
        case.history.preview(result["change_id"], case.factory)
    assert error.value.code == "history_snapshot_invalid"


def test_target_hardlink_and_history_hardlink_rejected(case, tmp_path):
    result = write(case)
    target = case.workspace / "example.py"
    outside = tmp_path / "linked-file.py"
    os.link(target, outside)
    with pytest.raises((HistoryError, ToolError)):
        case.history.preview(result["change_id"], case.factory)
    assert outside.read_bytes() == target.read_bytes()
    db_link = tmp_path / "db-link.sqlite3"
    os.link(case.history.path, db_link)
    with pytest.raises(HistoryError, match="links"):
        case.history.list()


def test_history_quota_prevents_unlogged_write(case, monkeypatch):
    monkeypatch.setattr("nexus.developer.MAX_HISTORY_BYTES", 2)
    result = case.history.execute_write(case.tools, {"path": "example.py", "content": "too large for history"})
    assert not result["ok"] and result["code"] == "history_storage_limit"
    assert not (case.workspace / "example.py").exists()


@pytest.fixture
def http_case(case):
    app = FastAPI()
    activity = Mock()
    semaphore = asyncio.Semaphore(1)
    async def blocking(function, *args):
        return await asyncio.to_thread(function, *args)
    pending = install_developer_routes(app, lambda: case.history, case.factory, blocking, lambda: semaphore, lambda: activity)
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, pending=pending, activity=activity, case=case)


def test_http_approval_is_required_and_single_use(http_case):
    case, client = http_case.case, http_case.client
    result = write(case)
    assert client.get("/api/developer/changes").json()["changes"][0]["id"] == result["change_id"]
    prepared = client.post(f"/api/developer/changes/{result['change_id']}/preview").json()
    assert prepared["requires_approval"] is True and (case.workspace / "example.py").exists()
    path = f"/api/developer/changes/{prepared['approval_id']}/decision"
    approved = client.post(path, json={"approved": True})
    assert approved.status_code == 200 and approved.json()["ok"] is True
    assert not (case.workspace / "example.py").exists()
    assert client.post(path, json={"approved": True}).status_code == 404
    names = [call.args[0] for call in http_case.activity.add.call_args_list]
    assert names == ["developer_restore_requested", "developer_restore_approved", "developer_restore_finished"]


def test_http_denied_expired_and_tampered_decisions_do_not_execute(http_case):
    case, client = http_case.case, http_case.client
    result = write(case)
    preview_path = f"/api/developer/changes/{result['change_id']}/preview"
    prepared = client.post(preview_path).json()
    response = client.post(f"/api/developer/changes/{prepared['approval_id']}/decision", json={"approved": False})
    assert response.status_code == 200 and response.json()["executed"] is False
    assert (case.workspace / "example.py").exists()
    prepared = client.post(preview_path).json()
    http_case.pending[prepared["approval_id"]]["deadline"] = time.monotonic() - 1
    assert client.post(f"/api/developer/changes/{prepared['approval_id']}/decision", json={"approved": True}).status_code == 404
    prepared = client.post(preview_path).json()
    http_case.pending[prepared["approval_id"]]["preview"]["current_sha256"] = "f" * 64
    assert client.post(f"/api/developer/changes/{prepared['approval_id']}/decision", json={"approved": True}).status_code == 409
    assert (case.workspace / "example.py").read_text() == "print('after')\n"


def test_http_change_after_approval_preview_blocks_restore(http_case):
    case, client = http_case.case, http_case.client
    result = write(case)
    prepared = client.post(f"/api/developer/changes/{result['change_id']}/preview").json()
    target = case.workspace / "example.py"
    target.write_text("user change", encoding="utf-8")
    response = client.post(f"/api/developer/changes/{prepared['approval_id']}/decision", json={"approved": True})
    assert response.status_code == 409 and response.json()["code"] == "history_file_changed"
    assert target.read_text() == "user change"


def test_http_decision_cannot_replace_frozen_arguments(http_case):
    case, client = http_case.case, http_case.client
    result = write(case)
    prepared = client.post(f"/api/developer/changes/{result['change_id']}/preview").json()
    path = f"/api/developer/changes/{prepared['approval_id']}/decision"
    response = client.post(path, json={"approved": True, "path": "different-file.py"})
    assert response.status_code == 422 and (case.workspace / "example.py").exists()


@pytest.mark.parametrize("value", [1, "true", None])
def test_http_decision_requires_an_actual_boolean(http_case, value):
    case, client = http_case.case, http_case.client
    result = write(case)
    prepared = client.post(f"/api/developer/changes/{result['change_id']}/preview").json()
    response = client.post(f"/api/developer/changes/{prepared['approval_id']}/decision", json={"approved": value})
    assert response.status_code == 422 and (case.workspace / "example.py").exists()
