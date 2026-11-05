"""Concurrent web/chat discovery must share one workbench; no user DB access."""
from concurrent.futures import ThreadPoolExecutor
import threading
import time

import test_api as support
import pytest
from nexus.tools import Tools


def test_web_and_chat_threads_construct_only_one_workbench(tmp_path, monkeypatch):
    # test_api redirects application imports to disposable paths before import.
    api = support.api
    monkeypatch.setattr(api, "DATA", tmp_path)
    monkeypatch.setattr(api, "_security_workbenches", {})
    count_lock = threading.Lock()
    created = []
    gate = threading.Barrier(8)
    class InstrumentedWorkbench:
        def __init__(self, *args, **kwargs):
            with count_lock:
                created.append(self)
            time.sleep(.05)  # Expose interleaving while the initial construction is incomplete.
    monkeypatch.setattr(api, "Workbench", InstrumentedWorkbench)
    def load(_):
        gate.wait(timeout=5)
        return api.get_workbench()
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(load, range(8)))
    assert len(created) == 1
    assert all(value is values[0] for value in values)


@pytest.mark.parametrize("specialist", ["auth_auditor", "database_auditor", "remediation_engineer"])
def test_security_specialists_keep_writes_in_supervised_pipeline_while_developer_retains_tools(tmp_path, specialist):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tools = Tools(workspace, tmp_path / "data")
    try:
        message = "Corrija a consulta no código original e execute os testes agora."
        specialized = {s["function"]["name"] for s in support.api.select_schemas(tools, "AGENT", specialist, message)}
        developer = {s["function"]["name"] for s in support.api.select_schemas(tools, "AGENT", "coder", message)}
        assert not specialized & {"write_file", "run_command", "pc_write_file", "pc_run_command", "install_app"}
        assert {"list_files", "read_file"} <= specialized
        assert {"write_file", "run_command"} <= developer
    finally:
        tools.close()
