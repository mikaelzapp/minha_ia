"""Modalidades de trabalho separadas dos modos operacionais e permissões."""
import copy
from pathlib import Path

from .config import ROOT

FILES = {"list_files", "read_file", "grep_files"}
PUBLIC = {"search_web", "search_many", "fetch_page", "browser_open", "research_report"}
TOR = {"tor_check", "tor_fetch", "tor_read", "tor_search", "tor_browser_open", "research_report"}
SECURITY = {"security_context", "security_report", "security_static_file", "security_rea", "security_investigate",
            "security_windows", "security_code_audit", "security_dork", "security_osint", "security_cve", "security_workbench"}
PENTEST = SECURITY | {"security_http", "security_tls", "security_tcp", "security_nmap", "security_audit_v2"} | FILES
DEV = FILES | PUBLIC | {"write_file", "run_command", "download_file", "consult_coder", "computer_info",
    "pc_list_files", "pc_read_file", "pc_write_file", "pc_run_command", "list_apps", "search_apps", "app_details", "install_app", "security_code_audit"}
DEFINITIONS = {
    "chat": {"name": "Chat", "agent": "auto", "operation_mode": "CHAT", "description": "Conversa local; o controle operacional existente continua disponível.", "tools": None},
    "search": {"name": "Search Normal", "agent": "researcher", "operation_mode": "RESEARCH", "description": "Pesquisa pública com consultas, fontes, extração e exportação reais.", "tools": PUBLIC},
    "tor": {"name": "Search Deep Web / Tor", "agent": "researcher", "operation_mode": "RESEARCH", "description": "Leitura pública/onion por Tor ativado explicitamente, sem fallback direto.", "tools": TOR},
    "pentest": {"name": "Hacking / Pentest", "agent": "red_team", "operation_mode": "AGENT", "description": "Verificações autorizadas com escopos, evidências e aprovações.", "tools": PENTEST},
    "developer": {"name": "Developer", "agent": "coder", "operation_mode": "CODE", "description": "Arquivos, terminal aprovado, testes e histórico de escritas com reversão.", "tools": DEV},
    "security": {"name": "Security / Antivirus", "agent": "blue_team", "operation_mode": "REVIEW", "description": "Windows, REA e arquivos em análise estática; nenhuma execução de amostra.", "tools": SECURITY | {"search_web", "search_many", "research_report"}},
}


def definition(identity):
    if not isinstance(identity, str) or identity not in DEFINITIONS:
        raise ValueError("Modalidade desconhecida. Escolha chat, search, tor, pentest, developer ou security.")
    return copy.deepcopy(DEFINITIONS[identity])


def catalog(default_model):
    return [{"id": identity, **{key: sorted(value) if isinstance(value, set) else value for key, value in definition(identity).items()},
             "required_capabilities": ["completion"] if identity == "chat" else ["completion", "tools"],
             "recommended_model": default_model, "context_panel": identity} for identity in DEFINITIONS]


def instructions(identity):
    definition(identity)
    path = ROOT / "profiles" / "modes" / (identity + ".md")
    if path.is_symlink() or path.parent.is_symlink() or path.stat().st_size > 16000:
        raise ValueError("Instruções da modalidade precisam ser arquivos locais de até 16 KB.")
    return path.read_text(encoding="utf-8-sig").strip()


def filter_schemas(schemas, identity, agent=None, tor_enabled=False):
    allowed = definition(identity)["tools"]
    permissions = (agent or {}).get("permissions", {})
    selected = []
    for schema in schemas:
        name = schema["function"]["name"]
        if allowed is not None and name not in allowed:
            continue
        if agent and not agent.get("builtin", False):
            if name not in agent.get("tool_allowlist", []):
                continue
            if name in {"list_files", "read_file", "grep_files", "pc_list_files", "pc_read_file", "security_code_audit", "security_static_file", "security_rea", "security_investigate"} and not permissions.get("file_read", False):
                continue
            if name in {"write_file", "pc_write_file"} and not permissions.get("file_write", False):
                continue
            if name in {"run_command", "pc_run_command", "install_app"} and not permissions.get("terminal", False):
                continue
            external = name in (PUBLIC | TOR | {"download_file", "browser_interact", "security_http", "security_tls", "security_tcp", "security_nmap", "security_osint", "security_cve", "security_audit_v2", "search_apps", "app_details", "install_app"}) - {"research_report"}
            if external and not permissions.get("external_network", False):
                continue
            if name in TOR and name != "research_report" and not agent.get("search", {}).get("tor_enabled", False):
                continue
        if name.startswith("tor_") and not tor_enabled:
            continue
        selected.append(schema)
    return selected
