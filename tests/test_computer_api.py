"""PC API/approval integration: isolated SQLite, fake model, no real installer."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from unittest.mock import patch

import pytest

import test_api as support
from nexus.access import Access, AgentTools
from nexus.computer import Computer


@pytest.fixture
def case(monkeypatch):
    scenario = support.ApiTests(methodName="runTest")
    scenario.setUp()
    profile = scenario.base / "isolated-profile"
    profile.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: profile))
    scenario.settings.update({"computer_enabled": True, "quality_mode": "balanced"}, save=False)
    # Reuse the established API fixture without collecting/re-running its tests.
    scenario.patches[-1].stop()
    tools = AgentTools(scenario.tools, Access(scenario.data, scenario.workspace),
                       lambda: scenario.settings["computer_enabled"])
    replacement = patch.object(support.api, "get_tools", return_value=tools)
    replacement.start()
    scenario.patches[-1] = replacement
    try:
        yield scenario
    finally:
        scenario.tearDown()


@pytest.fixture
def grant(case):
    case.authenticate()
    folder = case.base / "authorized-project"
    folder.mkdir()
    response = case.client.post("/api/computer/roots", json={"path": str(folder)})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def winget(monkeypatch):
    calls = []
    def fake(self, argv, *, timeout):
        calls.append(argv)
        if argv[:2] == ["source", "export"]:
            output = json.dumps({"Name": "winget", "Arg": "https://cdn.winget.microsoft.com/cache",
                                 "Type": "Microsoft.PreIndexed.Package"})
        elif argv[0] == "show":
            output = "Found Example [Publisher.App]\nVersion: 1.2.3\nPublisher: Example Publisher\nLicense: MIT\nLicense Url: https://example.test/license\nInstaller Url: https://example.test/app.exe\n"
        elif argv[0] == "install":
            output = "Synthetic installation completed; no process was launched."
        else:
            raise AssertionError(f"Unexpected synthetic WinGet call: {argv}")
        return {"exit_code": 0, "output": output, "truncated": False}
    monkeypatch.setattr(Computer, "_winget", fake)
    monkeypatch.setattr(Computer, "_winget_exe", staticmethod(lambda: "mock-winget.exe"))
    return calls


def start_tool(case, name, args, *, agent="coder", mode="AGENT"):
    case.engine.turns = [[support.call(name, args)], [{"type": "token", "content": "Fim da operação de teste."}]]
    return case.chat_payload(mode=mode, agent=agent, message="Trabalhe na pasta autorizada do computador.")


def test_computer_routes_require_authenticated_local_origin(case):
    assert case.client.get("/api/computer").status_code == 401
    assert case.client.post("/api/computer/roots", json={"path": str(case.base)}).status_code == 401
    case.authenticate()
    response = case.client.post("/api/computer/roots", json={"path": str(case.base)},
                                headers={"Origin": "https://external.example"})
    assert response.status_code == 403
    assert case.client.get("/api/computer").json()["roots"] == []


def test_disabled_access_refuses_new_grants(case):
    case.authenticate()
    case.settings.update({"computer_enabled": False}, save=False)
    response = case.client.post("/api/computer/roots", json={"path": str(case.project_root)})
    assert response.status_code == 403
    assert case.client.get("/api/computer").json() == {
        "enabled": False, "roots": [], "winget_available": bool(support.api.shutil.which("winget"))}


def test_grant_roundtrip_revoke_and_stable_identity(case, grant):
    status = case.client.get("/api/computer").json()
    assert status["enabled"] and status["roots"] == [grant]
    duplicate = case.client.post("/api/computer/roots", json={"path": grant["path"]})
    assert duplicate.status_code == 200 and duplicate.json()["id"] == grant["id"]
    assert len(case.client.get("/api/computer").json()["roots"]) == 1
    assert case.client.delete("/api/computer/roots/" + grant["id"]).status_code == 200
    assert case.client.get("/api/computer").json()["roots"] == []
    assert case.client.delete("/api/computer/roots/" + grant["id"]).status_code == 404


def test_api_rejects_entire_profile_secrets_missing_and_traversal_grants(case):
    case.authenticate()
    private = case.base / ".ssh"
    private.mkdir()
    public = case.base / "public"
    public.mkdir()
    for path in (str(Path.home()), str(private), str(case.base / "absent"), "../outside",
                 str(public / ".." / "public"), str(Path(case.base.anchor))):
        response = case.client.post("/api/computer/roots", json={"path": path})
        assert response.status_code == 400, (path, response.text)
    assert case.client.get("/api/computer").json()["roots"] == []


def test_api_never_persists_grants_covering_internal_control_store(case):
    case.authenticate()
    installation = case.base / "application"
    control = installation / "data"
    child = control / "ordinary-folder"
    child.mkdir(parents=True)
    external = case.base / "independent-project"
    external.mkdir()
    with patch.object(support.api, "DATA", control):
        for candidate in (installation, control, child):
            response = case.client.post("/api/computer/roots", json={"path": str(candidate)})
            assert response.status_code == 400, (str(candidate), response.text)
            assert not (control / "computer-access.json").exists()
            assert case.client.get("/api/computer").json()["roots"] == []
        allowed = case.client.post("/api/computer/roots", json={"path": str(external)})
        assert allowed.status_code == 200
        assert case.client.get("/api/computer").json()["roots"] == [allowed.json()]


def test_model_cannot_authorize_its_own_root(case):
    case.authenticate()
    payload = start_tool(case, "grant_root", {"path": str(case.project_root)})
    events = case.events(case.client.post("/api/chat", json=payload))
    result = next(row["result"] for row in events if row["type"] == "tool")
    assert "não permitida" in result["error"]
    assert not any(row["type"] == "approval" for row in events)
    assert case.client.get("/api/computer").json()["roots"] == []


@pytest.mark.parametrize("path", ["../private.txt", ".env", "token.json", "C:\\Windows\\private.txt"])
def test_model_read_cannot_escape_granted_root_or_read_secrets(case, grant, path):
    payload = start_tool(case, "pc_read_file", {"root_id": grant["id"], "path": path})
    events = case.events(case.client.post("/api/chat", json=payload))
    result = next(row["result"] for row in events if row["type"] == "tool")
    assert not result["ok"] and result["error"]


def test_pending_write_cannot_restore_revoked_root(case, grant):
    target = Path(grant["path"]) / "blocked.py"
    payload = start_tool(case, "pc_write_file", {"root_id": grant["id"], "path": "blocked.py", "content": "print(1)\n"})
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(case.client.post, "/api/chat", json=payload)
        approval_id = case.wait_approval(future=future)
        assert case.client.delete("/api/computer/roots/" + grant["id"]).status_code == 200
        # Add another grant while the old decision is pending; the ID cannot shift.
        other = case.base / "other-project"
        other.mkdir()
        assert case.client.post("/api/computer/roots", json={"path": str(other)}).status_code == 200
        assert case.client.post(f"/api/approvals/{approval_id}", json={"approved": True}).status_code == 200
        events = case.events(future.result(timeout=8))
    result = next(row["result"] for row in events if row["type"] == "tool")
    assert not result["ok"] and "não autorizada" in result["error"]
    assert not target.exists() and not (other / "blocked.py").exists()


def test_pending_write_is_cancelled_when_pc_access_is_disabled(case, grant):
    payload = start_tool(case, "pc_write_file", {"root_id": grant["id"], "path": "disabled.py", "content": "print(1)\n"})
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(case.client.post, "/api/chat", json=payload)
        approval_id = case.wait_approval(future=future)
        assert case.client.post("/api/settings", json={"computer_enabled": False}).status_code == 200
        assert case.client.post(f"/api/approvals/{approval_id}", json={"approved": True}).status_code == 200
        events = case.events(future.result(timeout=8))
    result = next(row["result"] for row in events if row["type"] == "tool")
    assert not result["ok"] and "desativado" in result["error"]
    assert not (Path(grant["path"]) / "disabled.py").exists()


def test_refused_install_never_reaches_installer(case, winget):
    case.authenticate()
    payload = start_tool(case, "install_app", {"package_id": "Publisher.App", "version": "1.2.3"}, agent="devops")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(case.client.post, "/api/chat", json=payload)
        approval_id = case.wait_approval(future=future)
        assert not any(argv[0] == "install" for argv in winget)
        assert case.client.post(f"/api/approvals/{approval_id}", json={"approved": False}).status_code == 200
        events = case.events(future.result(timeout=8))
    preview = next(row for row in events if row["type"] == "approval")
    assert preview["publisher"] == "Example Publisher" and preview["license"] == "MIT"
    assert preview["version"] == "1.2.3" and preview["scope"] == "user"
    assert not any(argv[0] == "install" for argv in winget)


def test_approved_synthetic_install_preserves_reviewed_id_scope_and_version(case, winget):
    case.authenticate()
    args = {"package_id": "Publisher.App", "version": "1.2.3", "scope": "machine"}
    payload = start_tool(case, "install_app", args, agent="devops")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(case.client.post, "/api/chat", json=payload)
        approval_id = case.wait_approval(future=future)
        assert case.client.post(f"/api/approvals/{approval_id}", json={"approved": True}).status_code == 200
        events = case.events(future.result(timeout=8))
    preview = next(row for row in events if row["type"] == "approval")
    executed = next(argv for argv in winget if argv[0] == "install")
    assert preview["args"][1:] == executed
    assert executed[executed.index("--scope") + 1] == "machine"
    assert executed[executed.index("--version") + 1] == "1.2.3"
    assert "--accept-source-agreements" not in executed
    assert next(row["result"] for row in events if row["type"] == "tool")["ok"]


def test_code_mode_cannot_install_even_if_model_requests_it(case, winget):
    case.authenticate()
    payload = start_tool(case, "install_app", {"package_id": "Publisher.App", "version": "1.2.3"},
                         agent="devops", mode="CODE")
    events = case.events(case.client.post("/api/chat", json=payload))
    assert not any(row["type"] == "approval" for row in events)
    assert not winget
    assert "não permitida" in next(row["result"] for row in events if row["type"] == "tool")["error"]
