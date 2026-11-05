"""PC grants and installer review use only temporary files and mocked WinGet."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from nexus.computer import Computer
from nexus.tools import ToolError, Tools


@pytest.fixture(autouse=True)
def isolated_user_profile(tmp_path, monkeypatch):
    # Windows pytest temp is normally beneath real AppData, which production
    # grants correctly forbid. Isolate the profile without weakening policy.
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: profile))


@pytest.fixture
def computer(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    projects = tmp_path / "projects"
    projects.mkdir()
    return Computer(tmp_path / "data", workspace, [str(projects)])


def root(computer):
    return computer.roots()[0]


def tool_names(computer, mode):
    return {row["function"]["name"] for row in computer.schemas(mode)}


def test_capabilities_match_modes_and_explicit_grants(computer, tmp_path):
    assert tool_names(computer, "CHAT") == set()
    assert "pc_read_file" in tool_names(computer, "PLAN")
    assert "pc_write_file" not in tool_names(computer, "PLAN")
    assert "pc_write_file" in tool_names(computer, "CODE")
    assert "install_app" not in tool_names(computer, "CODE")
    assert "install_app" in tool_names(computer, "AGENT")
    assert "app_details" in tool_names(computer, "AGENT")
    assert "list_apps" in tool_names(computer, "PLAN")
    no_grants = Computer(tmp_path / "data", tmp_path / "workspace")
    assert not any(name.startswith("pc_") for name in tool_names(no_grants, "AGENT"))
    assert "computer_info" in tool_names(no_grants, "PLAN")
    schemas = computer.schemas("AGENT")
    schemas[0]["function"]["name"] = "tampered"
    assert "tampered" not in tool_names(computer, "AGENT")


def test_grant_ids_survive_reordering_and_revocation_cannot_shift_root(computer, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    before = root(computer)
    reordered = Computer(tmp_path / "data", tmp_path / "workspace", [str(other), before["path"]])
    assert reordered.roots()[1]["id"] == before["id"]
    expected_id = hashlib.sha256(os.path.normcase(str(Path(before["path"]).resolve())).encode()).hexdigest()[:16]
    assert before["id"] == expected_id
    revoked = Computer(tmp_path / "data", tmp_path / "workspace", [str(other)])
    assert not revoked.execute("pc_list_files", {"root_id": before["id"]})["ok"]


def test_grant_validation_rejects_sensitive_whole_home_and_nonexistent_paths(tmp_path):
    secret = tmp_path / ".ssh"
    secret.mkdir()
    private_data = Path.home() / "AppData" / "Local"
    private_data.mkdir(parents=True)
    for paths in [[str(Path.home())], [str(Path(tmp_path.anchor))], [str(secret)],
                  [str(tmp_path / "missing")], ["relative"], [123], "wrong", [str(tmp_path)] * 17,
                  [str(private_data)]]:
        with pytest.raises(ToolError):
            Computer.validate_roots(paths)
    public = tmp_path / "public"
    public.mkdir()
    assert Computer.validate_roots([str(public), str(public)]) == [str(public.resolve())]


def test_grant_validation_rechecks_ancestor_reparse_points(computer, monkeypatch):
    real = Tools._is_link
    parent = Path(root(computer)["path"]).parent
    monkeypatch.setattr(Tools, "_is_link", staticmethod(lambda path: path == parent or real(path)))
    result = computer.execute("pc_list_files", {"root_id": root(computer)["id"]})
    assert not result["ok"] and "junction" in result["error"]


def test_internal_control_store_cannot_be_granted_through_parent_same_or_child(tmp_path):
    installation = tmp_path / "application"
    control = installation / "data"
    child = control / "ordinary-folder"
    child.mkdir(parents=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    for candidate in (installation, control, child):
        with pytest.raises(ToolError):
            Computer(control, workspace, [str(candidate)])
    project = tmp_path / "independent-project"
    project.mkdir()
    permitted = Computer(control, workspace, [str(project)])
    assert permitted.roots()[0]["path"] == str(project.resolve())


@pytest.mark.parametrize("path", ["../outside.txt", "nested/../../outside.txt", ".env", ".ssh/config", "token.json",
                                  "C:\\Windows\\file.txt", "\\\\server\\share", "file.txt:private", "CON.txt"])
def test_granted_file_apis_preserve_workspace_boundary(computer, path):
    args = {"root_id": root(computer)["id"], "path": path}
    assert not computer.execute("pc_read_file", args)["ok"]
    with pytest.raises(ToolError):
        computer.approval("pc_write_file", {**args, "content": "x"})


def test_granted_write_has_absolute_root_review_diff_and_stale_hash_protection(computer):
    grant = root(computer)
    target = Path(grant["path"]) / "main.py"
    target.write_text("print(1)\n", encoding="utf-8")
    read = computer.execute("pc_read_file", {"root_id": grant["id"], "path": "main.py"})
    args = {"root_id": grant["id"], "path": "main.py", "content": "print(2)\n", "expected_sha256": read["sha256"]}
    preview = computer.approval("pc_write_file", args)
    assert preview["action"] == "pc_write_file"
    assert preview["authorized_root"] == grant["path"]
    assert "-print(1)" in preview["diff"] and "+print(2)" in preview["diff"]
    assert target.read_text() == "print(1)\n"
    target.write_text("edited concurrently", encoding="utf-8")
    assert not computer.execute("pc_write_file", args)["ok"]
    assert target.read_text() == "edited concurrently"


def test_granted_files_do_not_expose_secret_entries(computer):
    grant = root(computer)
    (Path(grant["path"]) / "public.txt").write_text("visible", encoding="utf-8")
    (Path(grant["path"]) / ".env").write_text("PRIVATE", encoding="utf-8")
    result = computer.execute("pc_list_files", {"root_id": grant["id"]})
    assert result["ok"] and [row["path"] for row in result["entries"]] == ["public.txt"]


@pytest.mark.parametrize("command", [["powershell", "-Command", "echo x"], ["cmd", "/c", "dir"],
                                    ["winget", "install", "Git.Git"], ["msiexec.exe", "/i", "app.msi"],
                                    ["choco", "install", "git"], ["scoop", "install", "git"]])
def test_pc_commands_keep_shells_blocked_and_route_installs_through_review(computer, command):
    with pytest.raises(ToolError):
        computer.approval("pc_run_command", {"root_id": root(computer)["id"], "args": command})


def fake_winget(monkeypatch, stdout=b"Found App [Publisher.App]\nVersion: 1.2.3\nPublisher: Example Inc\nLicense: MIT\nLicense Url: https://example.test/license\nInstaller Url: https://example.test/app.exe\n", returncode=0):
    calls = []
    monkeypatch.setattr("nexus.computer.shutil.which", lambda name: "C:\\WindowsApps\\winget.exe")
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[1:3] == ["source", "export"]:
            source = {"Name": "winget", "Arg": "https://cdn.winget.microsoft.com/cache", "Type": "Microsoft.PreIndexed.Package"}
            return SimpleNamespace(stdout=json.dumps(source).encode(), stderr=b"", returncode=0)
        return SimpleNamespace(stdout=stdout, stderr=b"", returncode=returncode)
    monkeypatch.setattr("nexus.computer.subprocess.run", run)
    return calls


def test_search_and_details_are_readonly_without_accepting_terms(computer, monkeypatch):
    calls = fake_winget(monkeypatch)
    assert computer.execute("search_apps", {"query": "visual studio", "max_results": 500})["ok"]
    assert computer.execute("app_details", {"package_id": "Publisher.App"})["ok"]
    assert computer.execute("app_details", {"package_id": "Publisher.App", "version": "1.2.3"})["ok"]
    assert calls[1][0][1] == "search" and calls[1][0][calls[1][0].index("--count") + 1] == "50"
    for argv, kwargs in calls:
        if argv[1:3] == ["source", "export"]:
            assert "--accept-source-agreements" not in argv
            continue
        assert argv[1] in {"search", "show"}
        assert argv[argv.index("--source") + 1] == "winget"
        assert "--disable-interactivity" in argv
        assert not any(a.startswith("--accept") for a in argv)
        assert kwargs["shell"] is False and kwargs["stdin"] == subprocess.DEVNULL


def test_list_apps_uses_readonly_official_source_and_optional_exact_id(computer, monkeypatch):
    calls = fake_winget(monkeypatch, b"Name       Id            Version\nExample    Publisher.App 1.2.3\n")
    assert computer.approval("list_apps", {}) is None
    unfiltered = computer.execute("list_apps", {})
    filtered = computer.execute("list_apps", {"package_id": "Publisher.App"})
    assert unfiltered["ok"] and filtered["ok"]
    assert "Publisher.App" in filtered["output"]
    assert "installed" not in filtered and "installed" not in unfiltered
    actual = [(argv, kwargs) for argv, kwargs in calls if argv[1] == "list"]
    assert actual[0][0][1:] == ["list", "--source", "winget", "--disable-interactivity"]
    assert actual[1][0][1:] == ["list", "--source", "winget", "--disable-interactivity", "--exact", "--id", "Publisher.App"]
    for argv, kwargs in actual:
        assert kwargs["shell"] is False and kwargs["timeout"] == 45
        assert not any(option.startswith("--accept") for option in argv)
    assert not any(argv[1] == "install" for argv, _ in calls)
    assert sum(argv[1:3] == ["source", "export"] for argv, _ in calls) == 2


@pytest.mark.parametrize("package_id", ["", "--accept-source-agreements", "Publisher.App --override x", "https://example.test/app.exe"])
def test_list_apps_invalid_filter_never_spawns(computer, monkeypatch, package_id):
    calls = fake_winget(monkeypatch)
    assert not computer.execute("list_apps", {"package_id": package_id})["ok"]
    assert calls == []


def test_install_preview_is_readonly_displays_license_and_pins_approved_scope_version(computer, monkeypatch):
    calls = fake_winget(monkeypatch)
    args = {"package_id": "Publisher.App", "version": "1.2.3"}
    preview = computer.approval("install_app", args)
    assert len(calls) == 2 and calls[1][0][1] == "show"
    assert preview["publisher"] == "Example Inc"
    assert preview["license"] == "MIT" and preview["license_url"] == "https://example.test/license"
    assert preview["scope"] == "user" and preview["version"] == "1.2.3"
    assert preview["accept_package_agreements"] is True and preview["accept_source_agreements"] is False
    assert "licença" in preview["reason"] and "UAC" in preview["reason"]
    executed = computer.execute("install_app", args)
    assert executed["ok"]
    argv, kwargs = calls[-1]
    assert argv == preview["args"]
    assert argv[1] == "install" and "--exact" in argv and "--no-upgrade" in argv
    assert "--accept-package-agreements" in argv
    assert "--accept-source-agreements" not in argv
    assert not any(a in argv for a in ["--force", "--ignore-security-hash", "--override", "--silent"])
    assert kwargs["timeout"] == 600 and kwargs["shell"] is False


def test_machine_install_requires_concrete_scope_in_preview(computer, monkeypatch):
    fake_winget(monkeypatch)
    preview = computer.approval("install_app", {"package_id": "Publisher.App", "version": "1.2.3", "scope": "machine"})
    assert preview["scope"] == "machine"
    assert preview["args"][preview["args"].index("--scope") + 1] == "machine"


@pytest.mark.parametrize("args", [
    {"package_id": "Publisher.App"},
    {"package_id": "--accept-source-agreements", "version": "1.0"},
    {"package_id": "Publisher.App --override x", "version": "1.0"},
    {"package_id": "https://example.test/app.exe", "version": "1.0"},
    {"package_id": "Publisher.App", "version": "--latest"},
    {"package_id": "Publisher.App", "version": "latest"},
    {"package_id": "Publisher.App", "version": "1.0", "scope": "admin"},
    {"package_id": "Publisher.App", "version": "1.0", "source": "custom"},
    {"package_id": "Publisher.App", "version": "1.0", "accept_source_agreements": True},
])
def test_invalid_installer_arguments_never_spawn(computer, monkeypatch, args):
    calls = fake_winget(monkeypatch)
    with pytest.raises(ToolError):
        computer.approval("install_app", args)
    assert not computer.execute("install_app", args)["ok"]
    assert calls == []


def test_failed_or_truncated_package_details_prevent_approval(computer, monkeypatch):
    fake_winget(monkeypatch, b"Source agreements must be accepted", returncode=1)
    with pytest.raises(ToolError):
        computer.approval("install_app", {"package_id": "Publisher.App", "version": "1.2.3"})
    fake_winget(monkeypatch, b"x" * 40_001)
    with pytest.raises(ToolError):
        computer.approval("install_app", {"package_id": "Publisher.App", "version": "1.2.3"})


def test_installer_timeout_is_reported_without_claiming_success(computer, monkeypatch):
    fake_winget(monkeypatch)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr("nexus.computer.subprocess.run", timeout)
    result = computer.execute("install_app", {"package_id": "Publisher.App", "version": "1.2.3"})
    assert not result["ok"] and "Verifique o estado" in result["error"]


def test_installer_nonzero_exit_is_an_error_for_orchestrator(computer, monkeypatch):
    fake_winget(monkeypatch, b"Installation declined by user", returncode=123)
    result = computer.execute("install_app", {"package_id": "Publisher.App", "version": "1.2.3"})
    assert not result["ok"] and "123" in result["error"]


@pytest.mark.parametrize("source", [{"Name": "winget", "Arg": "https://attacker.test/cache", "Type": "Microsoft.PreIndexed.Package"},
    {"Name": "winget", "Arg": "https://cdn.winget.microsoft.com/cache", "Type": "Microsoft.Rest"},
    {"Name": "custom", "Arg": "https://cdn.winget.microsoft.com/cache", "Type": "Microsoft.PreIndexed.Package"}])
def test_redirected_or_custom_catalog_never_reaches_install(computer, monkeypatch, source):
    calls = []
    monkeypatch.setattr("nexus.computer.shutil.which", lambda name: "winget.exe")
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout=json.dumps(source).encode(), stderr=b"", returncode=0)
    monkeypatch.setattr("nexus.computer.subprocess.run", run)
    assert not computer.execute("install_app", {"package_id": "Publisher.App", "version": "1.0"})["ok"]
    assert len(calls) == 1 and calls[0][1:3] == ["source", "export"]


def test_computer_info_does_not_read_env_or_return_user_machine_secrets(computer, monkeypatch):
    monkeypatch.setenv("PRIVATE_API_KEY", "do-not-expose-this")
    result = computer.execute("computer_info", {})
    assert result["ok"] and result["ram_total_bytes"] > 0
    assert result["command_sandbox"] is False
    assert "do-not-expose-this" not in json.dumps(result)
    assert result["authorized_roots"] == computer.roots()


@pytest.mark.parametrize("name,args", [("unknown", {}), ("computer_info", {"unexpected": "x"}),
    ("pc_read_file", {"root_id": 0, "path": "a"}), ("search_apps", {"query": "--accept-source-agreements"}),
    ("search_apps", {"query": "vscode", "max_results": True}), ("computer_info", "{invalid")])
def test_unknown_and_untrusted_arguments_fail_closed(computer, name, args):
    assert not computer.execute(name, args)["ok"]
