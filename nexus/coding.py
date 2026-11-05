"""Text-only local coding consultation; proposals never execute computer actions."""
from __future__ import annotations

import httpx

from .config import loopback_url
from .tools import _definition
from .profiles import load_profile, role_instructions


NOTICE = "Proposta de programação: precisa ser revisada e testada antes de usar. Nada foi executado."


def _cloud_name(name):
    name = str(name).casefold()
    return name.endswith(("-cloud", ":cloud")) or "-cloud:" in name


def _remote(record):
    if not isinstance(record, dict):
        return False
    if any(record.get(key) for key in ("remote_name", "remote_model", "remote_host", "cloud_host")):
        return True
    return _cloud_name(record.get("name", "")) or _cloud_name(record.get("model", "")) or _remote(record.get("details"))


def _json(response):
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict):
        raise ValueError("Resposta inválida do Ollama local.")
    if result.get("error"):
        raise ValueError("Ollama local: " + str(result["error"])[:500])
    return result


class Coding:
    def __init__(self, ollama_url, model: str, primary_model: str, profile="standard"):
        self.url = loopback_url(ollama_url)
        self.model = model
        self.primary_model = primary_model
        self.profile = profile

    def schema(self):
        return _definition(
            "consult_coder",
            "Consulta o especialista local de programação para propor código, corrigir ou revisar. "
            "Passe trechos relevantes no contexto; ele não lê arquivos, não executa e não instala. "
            "A proposta exige revisão/testes. Limite conjunto: 5.000 caracteres.",
            {"task": {"type": "string", "minLength": 1, "maxLength": 2000},
             "context": {"type": "string", "maxLength": 4000}},
            ("task",),
        )

    @staticmethod
    def _arguments(args):
        if not isinstance(args, dict) or set(args) - {"task", "context"}:
            raise ValueError("A consulta aceita somente task e context.")
        task, context = args.get("task"), args.get("context", "")
        if not isinstance(task, str) or not task.strip() or len(task) > 2000:
            raise ValueError("A tarefa deve conter de 1 a 2.000 caracteres.")
        if not isinstance(context, str) or len(context) > 4000 or len(task) + len(context) > 5000:
            raise ValueError("Contexto limitado a 4.000 caracteres; tarefa e contexto somam no máximo 5.000.")
        return task, context

    @staticmethod
    def _unload(client, url, model):
        _json(client.post(url + "/api/generate", json={"model": model, "keep_alive": 0, "stream": False}, timeout=45))

    def execute(self, args) -> dict:
        result = {"ok": False, "model": self.model, "executed": False}
        try:
            task, context = self._arguments(args)
            profile = load_profile(self.profile)
            if not isinstance(self.model, str) or not self.model.strip() or len(self.model) > 200:
                raise ValueError("Configure um modelo local de programação válido.")
            if _cloud_name(self.model):
                raise ValueError("Consultas de programação usam somente modelos locais; modelos cloud são bloqueados.")
            with httpx.Client(trust_env=False, follow_redirects=False, timeout=httpx.Timeout(300, connect=10)) as client:
                tags = _json(client.get(self.url + "/api/tags", timeout=15))
                installed = next((row for row in tags.get("models", []) if isinstance(row, dict)
                                  and self.model in (row.get("name"), row.get("model"))), None)
                if installed is None:
                    raise ValueError("O especialista precisa estar instalado no Ollama. Nenhum modelo foi baixado.")
                if _remote(installed):
                    raise ValueError("Modelo remoto/cloud bloqueado; o contexto deve permanecer no computador.")
                details = _json(client.post(self.url + "/api/show", json={"model": self.model}, timeout=15))
                if _remote(details):
                    raise ValueError("Modelo remoto/cloud bloqueado; o contexto deve permanecer no computador.")
                if "completion" not in details.get("capabilities", []):
                    raise ValueError("O modelo selecionado não anuncia geração de texto (completion).")
                running = _json(client.get(self.url + "/api/ps", timeout=15))
                if self.primary_model and self.primary_model != self.model and any(
                    isinstance(row, dict) and self.primary_model in (row.get("name"), row.get("model"))
                    for row in running.get("models", [])
                ):
                    self._unload(client, self.url, self.primary_model)
                try:
                    response = _json(client.post(self.url + "/api/chat", json={
                        "model": self.model,
                        "messages": [{"role": "system", "content": role_instructions("coder") + "\n" + profile.instructions},
                                     {"role": "user", "content": "Tarefa:\n" + task + "\nContexto fornecido:\n" + context}],
                        "stream": False, "keep_alive": 0,
                        "options": {"num_ctx": 4096, "temperature": 0.2, "num_predict": 1536, "num_batch": 128},
                    }))
                    message = response.get("message", {})
                    proposal = message.get("content", "") if isinstance(message, dict) else ""
                    if not isinstance(proposal, str) or not proposal.strip():
                        raise ValueError("O especialista retornou uma resposta vazia; nenhuma proposta foi produzida.")
                    if response.get("done") is not True:
                        raise ValueError("O especialista não concluiu a resposta; a proposta não foi confirmada.")
                    duration = response.get("eval_duration", 0) / 1e9
                    metrics = {"tokens": response.get("eval_count", 0),
                               "prompt_tokens": response.get("prompt_eval_count", 0),
                               "tokens_per_second": round(response.get("eval_count", 0) / duration, 2) if duration else 0,
                               "load_seconds": round(response.get("load_duration", 0) / 1e9, 3)}
                    result.update(ok=True, proposal=proposal, metrics=metrics, notice=NOTICE)
                finally:
                    try:
                        self._unload(client, self.url, self.model)
                    except (httpx.HTTPError, ValueError) as exc:
                        result["unload_warning"] = "Não foi possível confirmar a descarga do especialista: " + type(exc).__name__
            return result
        except httpx.HTTPStatusError as exc:
            result["error"] = f"Ollama local retornou HTTP {exc.response.status_code}. Nenhuma execução foi realizada."
        except httpx.HTTPError as exc:
            result["error"] = "Falha de comunicação com o Ollama local: " + type(exc).__name__
        except (ValueError, TypeError) as exc:
            result["error"] = str(exc)[:700]
        return result
