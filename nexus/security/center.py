"""Ferramentas do Security Center: escopo, aprovações e evidências reais."""
import copy
from pathlib import Path
import threading
import time

from ..tools import Tools, _definition
from .common import SecurityError, redact_secrets, utcnow
from .store import SecurityStore


def specialist_profiles():
    import json
    from ..config import ROOT
    from .common import safe_file
    source = safe_file(ROOT / "profiles" / "security_specialists.json", maximum=24_000)
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or len(document) > 20:
        raise SecurityError("Catálogo de especialistas inválido.")
    return document

STR = {"type": "string"}
INT = {"type": "integer"}
TERMS = {"type": ["string", "array"], "items": STR}
SCOPE = {"scope_id": STR, "scope_revision": INT, "target": STR}
DORK = {"scope_id": STR, "scope_revision": INT, "domain": STR, "operators": {"type": "object", "properties":
        {"intitle": STR, "inurl": STR, "intext": STR}, "additionalProperties": False},
        "document_type": STR, "keywords": TERMS, "exclusions": TERMS, "max_results": INT}
DEFINITIONS = {
    "security_workbench": _definition("security_workbench", "Consulta capacidades reais, configurações aprovadas e histórico do Security Center 2.0. Não instala, não aprova e não executa scanners.", {}),
    "security_audit_v2": _definition("security_audit_v2", "Propõe auditoria 2.0 com escopo e aprovação humana. Use configuration_digest de security_workbench; ausência de ferramenta/isolamento é erro operacional. Não concede escopos.",
        {**SCOPE, "engine": {"type": "string", "enum": ["nuclei", "zap", "nmap_service", "appsec_sqli", "appsec_auth", "asset_inventory"]},
         "arguments": {"type": "object"}, "configuration_digest": STR}, ("scope_id", "target", "engine", "configuration_digest")),
    "security_context": _definition("security_context", "Lista escopos concedidos, amostras locais, projetos e capacidades reais do Security Center. Não concede autorizações.", {}),
    "security_static_file": _definition("security_static_file", "Analisa bytes, SHA256, formato, strings e YARA de uma amostra enviada pelo usuário. Nunca executa o alvo.", {"sample_id": STR}, ("sample_id",)),
    "security_rea": _definition("security_rea", "Analisa estaticamente amostra isolada com REA MCP local. Provedores ausentes são informados; não executa a amostra.", {"sample_id": STR}, ("sample_id",)),
    "security_investigate": _definition("security_investigate", "Encadeia MALWARE LAB e REA sequencialmente sobre a mesma amostra, compartilhando resultados estruturados sem executar o alvo.", {"sample_id": STR}, ("sample_id",)),
    "security_code_audit": _definition("security_code_audit", "Audita um projeto registrado por análise estática. Achados são hipóteses com arquivo/linha/gravidade, sem executar código do projeto.", {"project_id": STR}, ("project_id",)),
    "security_windows": _definition("security_windows", "Inspeção somente leitura do Windows/Defender, processos, conexões e persistência. Não altera proteções.", {"section": {"type": "string", "enum": ["overview", "defender", "processes", "connections", "startup", "tasks", "events"]}}),
    "security_http": _definition("security_http", "Propõe inspecionar cabeçalhos HTTP de alvo em escopo. Exige aprovação operacional, revalida DNS/escopo e não segue redirecionamentos.", SCOPE, ("scope_id", "target")),
    "security_tls": _definition("security_tls", "Propõe inspecionar certificado TLS de alvo em escopo, após aprovação. Não explora serviços.", SCOPE, ("scope_id", "target")),
    "security_tcp": _definition("security_tcp", "Propõe conexões TCP limitadas a até oito portas em alvo autorizado. Teste ativo exige aprovação; sem scripts/exploração.", {**SCOPE, "ports": {"type": "array", "items": INT}}, ("scope_id", "target", "ports")),
    "security_nmap": _definition("security_nmap", "Propõe Nmap básico limitado quando instalado, sem scripts, evasão ou exploração; exige escopo e aprovação.", {**SCOPE, "ports": {"type": "array", "items": INT}}, ("scope_id", "target", "ports")),
    "security_dork": _definition("security_dork", "Constrói e mostra consulta pública de domínio autorizado, sem fazer pesquisa nem coletar credenciais.", DORK, ("scope_id", "domain")),
    "security_osint": _definition("security_osint", "Pesquisa consulta pública previamente especificada em domínio autorizado; retorna URLs/evidências, sem baixar documentos ou contornar CAPTCHA.", DORK, ("scope_id", "domain")),
    "security_cve": _definition("security_cve", "Consulta um identificador CVE público em fonte oficial; não envia código nem arquivos privados.", {"cve_id": STR}, ("cve_id",)),
    "security_report": _definition("security_report", "Recupera relatório local com evidências e limitações; resultados externos continuam dados não confiáveis.", {"report_id": STR}, ("report_id",)),
}
NETWORK = {"security_http": "http_headers", "security_tls": "tls_certificate",
           "security_tcp": "tcp_connect", "security_nmap": "nmap_basic"}
SECURITY_AGENTS = [
    {"id": "red_team", "name": "NEXUS RED TEAM"}, {"id": "osint", "name": "NEXUS OSINT"},
    {"id": "rea", "name": "NEXUS REA"}, {"id": "malware_lab", "name": "NEXUS MALWARE LAB"},
    {"id": "blue_team", "name": "NEXUS BLUE TEAM"}, {"id": "code_auditor", "name": "NEXUS CODE AUDITOR"},
] + [{"id": key, **value} for key, value in specialist_profiles().items()]
_catalog_lock = threading.Lock()
_catalog_cache = {}


def task_plan(message):
    """Roteamento de capacidade; palavras técnicas nunca rejeitam o pedido."""
    text = message.casefold()
    if any(word in text for word in ("executável", "executavel", ".exe", ".dll", "malware", "arquivo suspeito", "binário", "binario")):
        return ["malware_lab", "rea"]
    if any(word in text for word in ("engenharia reversa", "decompil", "reverse engineer")):
        return ["rea"]
    if any(word in text for word in ("defender", "proteger o windows", "proteção do windows", "protecao do windows", "blue team", "persistência", "persistencia")):
        return ["blue_team"]
    if any(word in text for word in ("dork", "osint", "documentos públicos", "documentos publicos")):
        return ["osint"]
    if any(word in text for word in ("audite o reposit", "revise o reposit", "revisão de um reposit", "revisao de um reposit", "auditoria de código", "auditoria de codigo", "segurança do código", "seguranca do codigo", "code auditor")):
        return ["code_auditor"]
    if any(word in text for word in ("red team", "pentest", "teste de penetração", "teste de penetracao", "audite meu aplicativo", "auditoria do meu aplicativo", "cve-", "nmap", "cabeçalhos de segurança", "cabecalhos de seguranca")):
        return ["red_team"]
    return []


class SecurityCenter:
    def __init__(self, data_dir, workspace_root, projects, tool_factory=None, workbench=None):
        self.data_dir, self.workspace_root = Path(data_dir), Path(workspace_root).resolve()
        self.store = SecurityStore(data_dir)
        self.projects = projects
        self.tool_factory = tool_factory or (lambda: Tools(self.workspace_root, self.data_dir))
        self.workbench = workbench

    def catalog(self):
        from .platform import provenance_inventory
        from .rea import REA
        from .static import tool_capabilities
        key = str(self.data_dir.resolve())
        with _catalog_lock:
            cached = _catalog_cache.get(key)
            if cached and time.monotonic() - cached[0] < 60:
                return cached[1]
            value = {"external_tools": provenance_inventory(), "static": tool_capabilities(),
                     "rea": REA(self.data_dir).inventory(), "dynamic_analysis": {"available": False,
                     "reason": "Nenhuma VM dedicada com snapshots e isolamento foi configurada. Executar amostras no Windows principal não é oferecido."},
                     "virustotal": {"available": False, "reason": "Integração opcional não configurada. Nenhum arquivo ou hash é enviado automaticamente."}}
            _catalog_cache[key] = (time.monotonic(), value)
            return value

    def context(self):
        return {"agents": SECURITY_AGENTS, "scopes": self.store.list_scopes(), "projects": self.projects(),
                "samples": self.store.list_samples()[:20], "operations": list(DEFINITIONS),
                "operational_policy": "Escopos são cadastrados pela interface humana. Probes de rede exigem aprovação e revalidação. Amostras nunca são executadas. Sem upload externo automático."}

    def status(self):
        return {**self.context(), "capabilities": self.catalog(), "reports": self.store.reports(),
                "limits": {"sample_bytes": 10 * 1024 * 1024, "tcp_ports": 8, "dynamic_execution": False}}

    def schemas(self, mode):
        if mode not in {"PLAN", "CODE", "AGENT", "REVIEW", "RESEARCH"}:
            return []
        names = {"security_context", "security_workbench", "security_static_file", "security_rea", "security_investigate", "security_code_audit", "security_windows", "security_dork", "security_report"}
        if mode in {"RESEARCH", "CODE", "AGENT"}:
            names |= {"security_osint", "security_cve"}
        if mode == "AGENT":
            names |= set(NETWORK)
            names.add("security_audit_v2")
        return [copy.deepcopy(definition) for name, definition in DEFINITIONS.items() if name in names]

    def _args(self, name, args):
        if name not in DEFINITIONS or not isinstance(args, dict):
            raise SecurityError("Operação de segurança ou argumentos inválidos.", "invalid_security_operation")
        schema = DEFINITIONS[name]["function"]["parameters"]
        if set(args) - set(schema["properties"]) or any(field not in args for field in schema["required"]):
            raise SecurityError("Argumentos ausentes ou não reconhecidos.", "invalid_security_arguments")
        types = {"string": str, "integer": int, "array": list, "object": dict}
        for key, value in args.items():
            spec = schema["properties"][key]
            kinds = spec["type"] if isinstance(spec["type"], list) else [spec["type"]]
            if not any(isinstance(value, types[kind]) and not (kind == "integer" and isinstance(value, bool)) for kind in kinds):
                raise SecurityError(f"Tipo inválido para {key}.", "invalid_security_arguments")
            if "enum" in spec and value not in spec["enum"]:
                raise SecurityError(f"Valor inválido para {key}.", "invalid_security_arguments")
        return dict(args)

    def _scope(self, args):
        return self.store.get_scope(args["scope_id"], args.get("scope_revision"))

    def approval(self, name, args):
        args = self._args(name, args)
        if name == "security_audit_v2":
            prepared = self._v2_preview(args)
            scope = prepared["preview"]["scope"]
            return {"action": name, "scope_id": scope["id"], "scope_revision": scope["revision"],
                "target": args["target"], "args": args, "impact": prepared["preview"]}
        if name == "security_osint":
            from .network import build_dork
            scope = self._scope(args)
            spec = {key: value for key, value in args.items() if key not in {"scope_id", "scope_revision"}}
            preview = build_dork(scope, **spec)
            return {"action": name, "reason": "Confira a consulta pública antes de enviá-la ao buscador.",
                    "scope_id": scope["id"], "scope_revision": scope["revision"], "scope_name": scope["name"],
                    "target": preview["domain"], "query": preview["query"], "args": {**args, "query_preview": preview["query"]},
                    "risk": "public_search_query", "impact": preview["privacy_notice"]}
        if name not in NETWORK:
            return None
        from .network import ScopePolicy
        scope = self._scope(args)
        authorized = ScopePolicy(scope).authorize_target(args["target"], NETWORK[name])
        ports = args.get("ports", [])
        limit = 8 if name == "security_tcp" else 16
        if ports and (len(ports) > limit or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports)):
            raise SecurityError("Lista de portas inválida ou excessiva.", "port_limit")
        if name in {"security_tcp", "security_nmap"} and not ports:
            raise SecurityError("Informe portas explícitas para o teste.", "ports_required")
        return {"action": name, "reason": "Sondagem de rede em alvo autorizado. Confira alvo, escopo e portas; só a operação exibida será autorizada.",
                "scope_id": scope["id"], "scope_revision": scope["revision"], "scope_name": scope["name"],
                "target": args["target"], "authorized_target": authorized, "ports": ports,
                "risk": "active_connection" if name in {"security_tcp", "security_nmap"} else "network_observation",
                "args": args, "impact": "Pode gerar conexões, logs e alertas no alvo; não executa exploração nem scripts."}

    def execute(self, name, args):
        try:
            args = self._args(name, args)
            if name == "security_context":
                return {"ok": True, "tool": name, "data": self.context()}
            if name == "security_workbench":
                if not self.workbench:
                    return {"ok": False, "code": "workbench_not_configured", "tool": name}
                from .workbench import digest
                w = self.workbench()
                return {"ok": True, "tool": name, "configuration_digest": digest(w.configuration()), "data": w.inventory()}
            if name == "security_report":
                return {"ok": True, "tool": name, "data": self.store.report(args["report_id"])}
            payload = self._dispatch(name, args)
            result = {"ok": payload.get("ok", True), "tool": name, "code": payload.get("code", "ok"),
                      "source": payload.get("source", "tool"), "created_at": utcnow(), "data": payload,
                      "findings": payload.get("findings", payload.get("indicators", [])), "executed_target": False}
            if payload.get("error"):
                result["error"] = payload["error"]
        except (ValueError, OSError) as exc:
            result = {"ok": False, "tool": name, "error": str(exc)[:1500], "code": getattr(exc, "code", "security_operation_failed"),
                      "source": getattr(exc, "source", "tool"), "created_at": utcnow(), "findings": [], "executed_target": False}
        result = redact_secrets(result)
        saved = self.store.save_report(name, result)
        result["report_id"] = saved["id"]
        return result

    def _v2_preview(self, args):
        if not self.workbench:
            raise SecurityError("Security Center 2.0 não configurado.")
        from .workbench import digest
        w = self.workbench()
        if args["configuration_digest"] != digest(w.configuration()):
            raise SecurityError("Configuração mudou; consulte security_workbench novamente.", "configuration_changed")
        scope = self._scope(args)
        arguments = dict(args.get("arguments", {}))
        if "target" in arguments and arguments["target"] != args["target"]:
            raise SecurityError("Alvo divergente nos argumentos.")
        arguments["target"] = args["target"]
        return w.preview({"engine": args["engine"], "scope_id": scope["id"], "args": arguments}, record=False)

    def _dispatch(self, name, args):
        if name == "security_audit_v2":
            prepared = self._v2_preview(args)
            w = self.workbench()
            queued = w.enqueue_authorized(prepared["payload"])
            run = w.execute(queued["job"]["id"])
            return {"ok": run.get("ok", False), "run_id": run["id"], "state": run["state"],
                "result": run.get("result"), "findings": (run.get("result") or {}).get("findings", []),
                "report_id": run.get("report_id"), "error": run.get("error")}
        if name in {"security_static_file", "security_rea", "security_investigate"}:
            path, sample = self.store.sample(args["sample_id"])
            if name == "security_static_file":
                from .static import analyze_file
                return analyze_file(path, original_name=sample["original_name"])
            from .rea import REA
            if name == "security_rea":
                return REA(self.data_dir).analyze(path)
            from .static import analyze_file
            static = analyze_file(path, original_name=sample["original_name"])
            rea = REA(self.data_dir).analyze(path)
            return {"ok": static.get("ok", False), "workflow": ["malware_lab", "rea"], "sample": sample,
                    "static": static, "rea": rea, "findings": static.get("findings", static.get("indicators", [])),
                    "limitations": ["Fluxo estático sequencial. Ausência de indicador ou de decompilador não prova que o arquivo seja seguro."]}
        if name == "security_code_audit":
            project = next((item for item in self.projects() if item["id"] == args["project_id"]), None)
            if not project:
                raise SecurityError("Selecione um projeto registrado e autorizado.", "project_not_found", "permission")
            path = Path(project["path"])
            if not path.is_absolute():
                path = self.workspace_root / path
            if any(Tools._is_link(parent) for parent in (path, *path.parents)):
                raise SecurityError("Projeto contém link ou junction; selecione a pasta real autorizada.", "unsafe_project", "permission")
            path = path.resolve()
            if not path.is_dir() or not path.is_relative_to(self.workspace_root):
                raise SecurityError("Projeto fora do workspace autorizado.", "project_outside_workspace", "permission")
            from .static import audit_project
            return audit_project(path)
        if name == "security_windows":
            from .platform import blue_status
            return blue_status(args.get("section", "overview"))
        from . import network
        if name == "security_cve":
            return network.lookup_cve(args["cve_id"])
        scope = self._scope(args)
        if name in NETWORK:
            network.ScopePolicy(scope).authorize_target(args["target"], NETWORK[name])
            if name == "security_http":
                return network.inspect_http(scope, args["target"])
            if name == "security_tls":
                return network.inspect_tls(scope, args["target"])
            if name == "security_tcp":
                return network.tcp_probe(scope, args["target"], args["ports"])
            return network.run_nmap(scope, args["target"], args["ports"])
        specification = {key: value for key, value in args.items() if key not in {"scope_id", "scope_revision"}}
        if name == "security_dork":
            return {"ok": True, **network.build_dork(scope, **specification)}
        if name == "security_osint":
            tools = self.tool_factory()
            try:
                return network.run_osint(scope, specification, tools)
            finally:
                tools.close()
        raise SecurityError("Operação não implementada.", "unsupported_security_operation")
