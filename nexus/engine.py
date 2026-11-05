"""Cliente Ollama local: streaming, métricas e seleção de agentes especializados."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import httpx
from .coding import _remote, _cloud_name
from .profiles import load_profile, role_instructions
from .security.center import SECURITY_AGENTS, task_plan, specialist_profiles


class ModelError(ValueError):
    """Falha técnica identificada por origem; nunca classifica o assunto."""
    def __init__(self, message, code="model_error", source="model_service"):
        super().__init__(message)
        self.code = code
        self.source = source

AGENTS = [
    {"id": "auto", "name": "NEXUS · Automático"},
    {"id": "architect", "name": "NEXUS ARCHITECT"},
    {"id": "coder", "name": "NEXUS CODER"},
    {"id": "debugger", "name": "NEXUS DEBUGGER"},
    {"id": "researcher", "name": "NEXUS RESEARCHER"},
    {"id": "devops", "name": "NEXUS DEVOPS"},
    {"id": "database", "name": "NEXUS DATABASE"},
    {"id": "security", "name": "NEXUS SECURITY"},
    {"id": "browser", "name": "NEXUS BROWSER"},
    {"id": "memory", "name": "NEXUS MEMORY"},
] + SECURITY_AGENTS
MODES = ["CHAT", "PLAN", "CODE", "AGENT", "REVIEW", "RESEARCH"]
SPECIALTIES = {agent["id"] for agent in AGENTS if agent["id"] != "auto"}

def route_agent(agent: str, mode: str, message: str) -> str:
    if agent in SPECIALTIES:
        return agent
    plan = task_plan(message)
    if plan:
        return plan[0]
    if mode == "RESEARCH":
        return "researcher"
    if mode == "PLAN":
        return "architect"
    if mode == "REVIEW":
        return "security"
    text = message.casefold()
    if any(word in text for word in ("instalar", "instale ", "instalação", "instalacao", "instala o", "instala um")):
        return "devops"
    for words, selected in [(("traceback", "erro", "bug", "falha", "test"), "debugger"), (("sql", "banco", "database"), "database"), (("docker", "deploy", "servidor"), "devops"), (("pesquis", "documentação", "fonte"), "researcher"), (("naveg", "página", "browser"), "browser")]:
        if any(word in text for word in words):
            return selected
    return "coder"

def system_prompt(agent: str, mode: str, workspace: str, project: dict | None = None, profile="standard") -> str:
    date = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d")
    selected = load_profile(profile)
    operational = role_instructions("security_center") if agent in {item["id"] for item in SECURITY_AGENTS} else ""
    specialist = specialist_profiles().get(agent, {}).get("description", "")
    if specialist:
        operational += "\nEspecialidade Security Center 2.0: " + specialist + "\nUse apenas ferramentas oferecidas nesta execução. Nuclei, ZAP, Ghidra e correção supervisionada têm aprovações específicas no painel Security Center 2.0; não afirme executá-los por mencionar seus nomes."
    return f"""Você é NEXUS AI, assistente pessoal local em português brasileiro, salvo idioma pedido pelo usuário. Data: {date}.
Perfil: {selected.name}.
Especialidade: {selected.specialties.get(agent, selected.specialties.get('coder', ''))}
Modo: {mode}. CHAT apenas responde. PLAN estuda sem modificar. REVIEW apenas inspeciona.
CODE propõe alterações; AGENT planeja, implementa e testa dentro das permissões. RESEARCH pesquisa e cita fontes.
Workspace autorizado: {workspace}. Projeto selecionado: {json.dumps(project, ensure_ascii=False)}.
{selected.instructions}
Regras de operação (não concedem nem retiram permissões do executor):
{selected.operations}
{operational}
"""

class Ollama:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self._managed_models = set()

    async def inventory(self):
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=8) as client:
                tags = await client.get(self.url + "/api/tags")
                tags.raise_for_status()
                running = await client.get(self.url + "/api/ps")
                installed = tags.json().get("models", [])
                chat_models = [m for m in installed if not _remote(m) and ("embedding" not in m.get("capabilities", []) or "completion" in m.get("capabilities", []))]
                return {"connected": True, "models": chat_models, "all_models": installed, "running": running.json().get("models", []) if running.is_success else []}
        except (httpx.HTTPError, ValueError) as exc:
            return {"connected": False, "models": [], "running": [], "error": str(exc)}

    async def capabilities(self, model):
        if _cloud_name(model):
            raise ModelError("O NEXUS executa inferência local; modelos cloud não são permitidos.", "local_model_policy", "application")
        async with httpx.AsyncClient(trust_env=False, timeout=15) as client:
            response = await client.post(self.url + "/api/show", json={"model": model})
            response.raise_for_status()
            try:
                details = response.json()
            except ValueError as exc:
                raise ModelError("Ollama retornou metadados de modelo inválidos.", "model_protocol_error") from exc
            if not isinstance(details, dict):
                raise ModelError("Ollama retornou metadados de modelo inválidos.", "model_protocol_error")
            if _remote(details):
                raise ModelError("Modelo remoto bloqueado: conteúdo privado deve permanecer no computador.", "local_model_policy", "application")
            return details.get("capabilities", [])

    async def prepare(self, target, managed_models):
        """Descarrega modelos configurados/usados por esta instância do NEXUS."""
        managed = set(managed_models) | self._managed_models
        inventory = await self.inventory()
        for model in inventory.get("running", []):
            name = model.get("name", "")
            if name != target and name in managed:
                await self.unload(name)
        self._managed_models.add(target)

    async def unload(self, model):
        async with httpx.AsyncClient(trust_env=False, timeout=45) as client:
            response = await client.post(self.url + "/api/generate", json={"model": model, "keep_alive": 0, "stream": False})
            response.raise_for_status()

    async def stream(self, model, messages, *, context=4096, temperature=0.3, tools=None, max_tokens=1024, thinking=False, preserve_original=False):
        payload = {"model": model, "messages": messages, "stream": True, "keep_alive": "5m", "options": {"num_ctx": context, "temperature": temperature, "num_predict": max_tokens, "num_batch": 128}}
        capabilities = await self.capabilities(model)
        if "thinking" in capabilities:
            payload["think"] = bool(thinking)
        if tools:
            if "tools" not in capabilities:
                raise ModelError("Este modelo não anuncia suporte a ferramentas. Selecione um modelo compatível ou use CHAT.", "model_tools_unsupported")
            payload["tools"] = tools
        async with httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(300, connect=10)) as client:
            for attempt in range(2):
                started = time.perf_counter()
                first = None
                thinking_status = visible = called = finished = False
                async with client.stream("POST", self.url + "/api/chat", json=payload) as response:
                    if not response.is_success:
                        body = (await response.aread()).decode("utf-8", errors="replace")[:1500]
                        raise ModelError(f"Ollama HTTP {response.status_code}: {body}", "model_http_error")
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except ValueError as exc:
                            raise ModelError("Ollama retornou um evento de streaming inválido.", "model_protocol_error") from exc
                        if "error" in chunk:
                            raise ModelError(chunk["error"])
                        message = chunk.get("message", {})
                        if message.get("thinking") and not thinking_status:
                            thinking_status = True
                            yield {"type": "status", "content": "Raciocínio local em andamento…"}
                        if message.get("content"):
                            first = first or time.perf_counter()
                            visible = visible or bool(message["content"].strip())
                            yield {"type": "token", "content": message["content"]}
                        for call in message.get("tool_calls", []):
                            called = True
                            yield {"type": "call", "call": call}
                        if chunk.get("done"):
                            finished = True
                            duration = chunk.get("eval_duration", 0) / 1e9
                            yield {"type": "metrics", "model": model, "tokens": chunk.get("eval_count", 0), "prompt_tokens": chunk.get("prompt_eval_count", 0), "done_reason": chunk.get("done_reason"), "attempt": attempt + 1, "tokens_per_second": round(chunk.get("eval_count", 0) / duration, 2) if duration else 0, "latency_seconds": round(time.perf_counter() - started, 3), "first_token_seconds": round(first - started, 3) if first else None, "load_seconds": round(chunk.get("load_duration", 0) / 1e9, 3)}
                            break
                if not finished:
                    raise ModelError("Ollama interrompeu a resposta sem confirmar a conclusão; nenhuma recuperação automática foi executada.", "model_stream_incomplete")
                if visible or called or preserve_original:
                    return
                if attempt:
                    raise ModelError("O modelo retornou duas respostas vazias, mesmo sem raciocínio adicional. Tente uma tarefa menor ou outro modelo local.", "model_empty_response")
                if payload.get("think") is not True:
                    raise ModelError("O modelo retornou uma resposta vazia. Tente uma tarefa menor ou outro modelo local.", "model_empty_response")
                # Só uma conclusão realmente vazia pode ser repetida; chamadas,
                # texto e erros nunca disparam uma segunda execução automática.
                payload["think"] = False
                yield {"type": "status", "content": "O modelo não produziu uma resposta. Tentando uma vez sem raciocínio adicional…"}

    async def complete(self, model, messages, **kwargs):
        content = ""
        async for event in self.stream(model, messages, **kwargs):
            if event["type"] == "token":
                content += event["content"]
        return content
