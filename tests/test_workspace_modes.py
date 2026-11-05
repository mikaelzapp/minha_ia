"""Workspace capabilities are a reduction over operational schemas and grants."""
from copy import deepcopy

import pytest

from nexus import modes
from nexus.research import DEFINITIONS as RESEARCH_TOOLS
from nexus.security.center import SecurityCenter
from nexus.tools import Tools, _definition


def schemas(*names):
    return [_definition(name, name, {}) for name in names]


def names(rows):
    return {row["function"]["name"] for row in rows}


def custom(tools, **permissions):
    return {"builtin": False, "tool_allowlist": list(tools),
            "permissions": {"file_read": True, "file_write": True, "terminal": True, "external_network": True, **permissions},
            "search": {"tor_enabled": True}}


def test_six_workspace_modes_have_distinct_operational_defaults_and_declared_capabilities():
    catalog = {row["id"]: row for row in modes.catalog("qwen3.5:4b-q4_K_M")}
    assert set(catalog) == {"chat", "search", "tor", "pentest", "developer", "security"}
    assert catalog["chat"]["operation_mode"] == "CHAT"
    assert catalog["search"]["operation_mode"] == catalog["tor"]["operation_mode"] == "RESEARCH"
    assert catalog["developer"]["operation_mode"] == "CODE"
    assert catalog["pentest"]["operation_mode"] == "AGENT"
    assert catalog["security"]["operation_mode"] == "REVIEW"
    for identity, row in catalog.items():
        assert row["required_capabilities"] == (["completion"] if identity == "chat" else ["completion", "tools"])
        assert row["recommended_model"] == "qwen3.5:4b-q4_K_M"
        assert modes.instructions(identity).strip()


@pytest.mark.parametrize("identity", ["unknown", "../developer", None, [], {}])
def test_unknown_or_malformed_workspace_mode_is_a_validation_error(identity):
    with pytest.raises(ValueError):
        modes.definition(identity)


def test_definition_and_catalog_cannot_mutate_global_capability_sets():
    first = modes.definition("developer")
    first["tools"].add("grant_root")
    first["name"] = "changed"
    assert "grant_root" not in modes.definition("developer")["tools"]
    assert modes.definition("developer")["name"] == "Developer"
    listed = modes.catalog("model:tag")
    next(row for row in listed if row["id"] == "developer")["tools"].append("grant_root")
    assert "grant_root" not in modes.definition("developer")["tools"]


@pytest.mark.parametrize("identity,allowed,blocked", [
    ("search", {"search_web", "search_many", "fetch_page", "browser_open", "research_report"}, {"run_command", "write_file", "security_nmap", "tor_read"}),
    ("tor", {"tor_check", "tor_read", "tor_search", "tor_browser_open", "research_report"}, {"search_web", "search_many", "fetch_page", "browser_open", "run_command"}),
    ("security", {"security_windows", "security_static_file", "security_rea", "security_report"}, {"run_command", "write_file", "security_nmap", "pc_write_file"}),
    ("pentest", {"security_nmap", "security_http", "security_code_audit", "read_file"}, {"run_command", "write_file", "pc_write_file", "tor_read"}),
    ("developer", {"run_command", "write_file", "read_file", "consult_coder"}, {"security_nmap", "security_windows", "tor_read"}),
])
def test_workspace_capabilities_do_not_expand_tools(identity, allowed, blocked):
    offered = schemas(*(allowed | blocked))
    original = deepcopy(offered)
    filtered = modes.filter_schemas(offered, identity, tor_enabled=True)
    assert names(filtered) == allowed and offered == original


def test_custom_agent_allowlist_and_permissions_both_reduce_capabilities():
    offered = schemas("read_file", "write_file", "run_command", "search_web", "security_nmap", "grant_root")
    agent = custom({"read_file", "write_file", "run_command", "search_web", "security_nmap", "grant_root"},
                   file_read=False, file_write=False, terminal=False, external_network=False)
    assert modes.filter_schemas(offered, "developer", agent, True) == []
    agent["permissions"]["file_read"] = True
    assert names(modes.filter_schemas(offered, "developer", agent, True)) == {"read_file"}
    agent["tool_allowlist"] = []
    assert modes.filter_schemas(offered, "developer", agent, True) == []


def test_custom_agent_cannot_grant_an_operationally_unavailable_tool(tmp_path):
    workspace, data = tmp_path / "workspace", tmp_path / "data"
    base = Tools(workspace, data)
    center = SecurityCenter(data, workspace, lambda: [])
    try:
        all_desired = {"read_file", "write_file", "run_command", "security_nmap", "security_http"}
        agent = custom(all_desired)
        offered = base.schemas("PLAN") + center.schemas("PLAN")
        assert "security_nmap" not in names(offered) and "write_file" not in names(offered)
        assert names(modes.filter_schemas(offered, "pentest", agent, True)) == {"read_file"}
        assert modes.filter_schemas(base.schemas("CHAT"), "developer", agent, True) == []
    finally:
        base.close()


def test_tor_requires_both_global_activation_and_custom_agent_permission():
    offered = schemas("tor_read", "tor_check", "research_report")
    agent = custom({"tor_read", "tor_check", "research_report"})
    assert names(modes.filter_schemas(offered, "tor", agent, False)) == {"research_report"}
    agent["search"]["tor_enabled"] = False
    assert names(modes.filter_schemas(offered, "tor", agent, True)) == {"research_report"}
    agent["search"]["tor_enabled"] = True
    assert names(modes.filter_schemas(offered, "tor", agent, True)) == {"tor_read", "tor_check", "research_report"}


def test_local_research_report_does_not_require_external_network_permission():
    agent = custom({"research_report", "search_web"}, external_network=False)
    assert names(modes.filter_schemas(schemas("research_report", "search_web"), "search", agent)) == {"research_report"}


def test_schema_filter_preserves_original_function_parameter_definitions():
    offered = [deepcopy(RESEARCH_TOOLS["search_many"])]
    filtered = modes.filter_schemas(offered, "search")
    assert filtered == offered
    assert filtered[0]["function"]["parameters"]["required"] == ["queries"]
