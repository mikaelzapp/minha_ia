"""Biblioteca Ollama local: operações humanas aprovadas, sem executar modelos como código."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import struct
import time
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlsplit
import uuid

import httpx

from ..coding import _cloud_name, _remote
from ..config import loopback_url
from ..diagnostics import system_status
from ..memory import redact_secrets
from ..tools import Tools

MAX_UPLOAD = 16 * 1024**3
DISK_RESERVE = 2 * 1024**3
MAX_METADATA = 16 * 1024**2
NAME = re.compile(r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)?(?::[A-Za-z0-9][A-Za-z0-9._-]*)?\Z")
SHA = re.compile(r"[a-fA-F0-9]{64}\Z")
ARCHITECTURES = frozenset({
    "llama", "qwen2", "qwen2moe", "qwen3", "qwen3moe", "qwen35", "qwen35moe",
    "gemma", "gemma2", "gemma3", "gemma3n", "phi2", "phi3", "phimoe", "phi4",
    "starcoder", "starcoder2", "gpt2", "gptj", "gptneox", "bert", "nomic-bert",
    "nomic-bert-moe", "deepseek", "deepseek2", "command-r", "cohere2", "olmo",
    "olmo2", "granite", "granitemoe", "granitehybrid", "internlm2", "stablelm",
    "refact", "bloom", "mamba", "mamba2", "falcon", "falcon-h1", "chatglm",
    "baichuan", "orion", "dbrx", "exaone", "exaone4", "rwkv6", "rwkv6qwen2",
    "jina-bert-v2", "modern-bert", "arctic", "minicpm", "minicpm3", "minimax",
})
ACTIONS = {"pull", "hf", "variant", "import", "delete", "unload", "default", "test"}
TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


class LibraryError(ValueError):
    def __init__(self, message, code="library_input", source="application"):
        super().__init__(message)
        self.code, self.source = code, source


def now():
    return datetime.now(timezone.utc).isoformat()


def _redact(value):
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def model_name(value):
    if not isinstance(value, str) or len(value) > 160 or not NAME.fullmatch(value) or ".." in value or _cloud_name(value):
        raise LibraryError("Nome local inválido. Use modelo:tag ou autor/modelo:tag, sem URL, caminho ou sufixo cloud.")
    return value if ":" in value else value + ":latest"


def _safe(path: Path, *, regular=False):
    for item in [path, *path.parents]:
        try:
            if Tools._is_link(item):
                raise LibraryError("Links e junções não são aceitos no armazenamento da biblioteca.", "library_storage")
        except FileNotFoundError:
            continue
    if regular and (not path.is_file() or path.stat().st_nlink != 1):
        raise LibraryError("Arquivo ausente, não regular ou com hardlink.", "library_storage")
    return path


def _atomic(path, value):
    _safe(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _file_hash(path):
    _safe(path, regular=True)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024**2), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_gguf(path):
    """Parse limitado de metadados e tabela de tensores; não carrega pesos nem scripts."""
    path = _safe(Path(path), regular=True)
    size = path.stat().st_size
    with path.open("rb") as handle:
        def read(length):
            if length < 0 or handle.tell() + length > min(size, MAX_METADATA):
                raise LibraryError("Cabeçalho GGUF truncado ou maior que 16 MiB.", "gguf_invalid")
            value = handle.read(length)
            if len(value) != length:
                raise LibraryError("GGUF truncado.", "gguf_invalid")
            return value

        def number(fmt):
            return struct.unpack("<" + fmt, read(struct.calcsize(fmt)))[0]

        def string(keep=True):
            length = number("Q")
            if length > MAX_METADATA:
                raise LibraryError("String GGUF excessiva.", "gguf_invalid")
            raw = read(length)
            if not keep:
                return None
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LibraryError("Metadado GGUF não é UTF-8 válido.", "gguf_invalid") from exc

        formats = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}

        def value(kind, keep=False, nested=False):
            if kind in formats:
                return number(formats[kind])
            if kind == 8:
                return string(keep)
            if kind == 9 and not nested:
                subtype, count = number("I"), number("Q")
                if count > 2_000_000 or subtype == 9:
                    raise LibraryError("Array GGUF inválido ou excessivo.", "gguf_invalid")
                if subtype in formats:
                    read(struct.calcsize(formats[subtype]) * count)
                else:
                    for _ in range(count):
                        value(subtype, False, True)
                return None
            raise LibraryError("Tipo de metadado GGUF desconhecido.", "gguf_invalid")

        if read(4) != b"GGUF":
            raise LibraryError("O arquivo não possui assinatura GGUF.", "gguf_invalid")
        version = number("I")
        if version not in (2, 3):
            raise LibraryError("A importação aceita GGUF versões 2 e 3 little-endian.", "gguf_unsupported")
        tensors, pairs = number("Q"), number("Q")
        if not 1 <= tensors <= 1_000_000 or not 1 <= pairs <= 100_000:
            raise LibraryError("GGUF precisa conter tensores e metadados limitados.", "gguf_invalid")
        metadata = {}
        keys = set()
        for _ in range(pairs):
            key = string()
            if len(key) > 512 or key in keys:
                raise LibraryError("Chave GGUF repetida ou excessiva.", "gguf_invalid")
            keys.add(key)
            keep = key in {"general.architecture", "general.name", "general.file_type", "general.alignment", "split.count"} or key.endswith(".context_length")
            parsed = value(number("I"), keep)
            if keep and isinstance(parsed, (str, int, bool)):
                if isinstance(parsed, str) and len(parsed) > 4096:
                    raise LibraryError("Metadado textual GGUF excessivo.", "gguf_invalid")
                metadata[key] = parsed
        architecture = metadata.get("general.architecture")
        if architecture not in ARCHITECTURES:
            raise LibraryError(f"Arquitetura GGUF não habilitada pelo importador: {str(architecture)[:80]}. A compatibilidade final depende do Ollama instalado.", "gguf_architecture")
        if metadata.get("split.count", 1) != 1:
            raise LibraryError("GGUF dividido em shards requer importador multiarquivo; este assistente aceita um GGUF completo.", "gguf_split_unsupported")
        offsets = []
        for _ in range(tensors):
            name = string()
            dimensions = number("I")
            if not name or len(name) > 2048 or not 1 <= dimensions <= 8:
                raise LibraryError("Tabela de tensores GGUF inválida.", "gguf_invalid")
            shape = [number("Q") for _ in range(dimensions)]
            if not all(shape) or math.prod(shape) > 2**63:
                raise LibraryError("Dimensão de tensor GGUF inválida.", "gguf_invalid")
            tensor_type, offset = number("I"), number("Q")
            if tensor_type > 100 or offset >= size:
                raise LibraryError("Tipo ou offset de tensor GGUF inválido.", "gguf_invalid")
            offsets.append(offset)
        alignment = metadata.get("general.alignment", 32)
        if type(alignment) is not int or alignment < 1 or alignment > 4096 or alignment & (alignment - 1):
            raise LibraryError("Alinhamento GGUF inválido.", "gguf_invalid")
        data_start = (handle.tell() + alignment - 1) // alignment * alignment
        if data_start + max(offsets) >= size:
            raise LibraryError("GGUF sem dados para os tensores declarados.", "gguf_invalid")
    return {"version": version, "architecture": architecture, "tensor_count": tensors,
            "metadata": metadata, "size": size, "validation": "header_and_tensor_table_only", "load_tested": False}


def check_compatibility(metadata, required=()):
    capabilities = metadata.get("capabilities", [])
    missing = sorted(set(required) - set(capabilities))
    local = not _remote(metadata) and not _cloud_name(metadata.get("name", ""))
    return {"compatible": local and not missing, "missing": missing, "local": local,
            "reason": "Modelo remoto não habilitado para inferência privada local." if not local else
                      ("O modelo não declara: " + ", ".join(missing) if missing else "Capacidades declaradas atendem ao modo; isso não garante qualidade da resposta.")}


def test_budget(model, resources):
    """Margem preventiva local, não requisito de fabricante nem estimativa exata de KV."""
    size = model.get("size", 0)
    size = size if type(size) is int and size >= 0 else 0
    weight_gb = size / 1024**3
    free_gpu = sum(max(0, gpu.get("memory_total_mb", 0) - gpu.get("memory_used_mb", 0)) / 1024
                   for gpu in resources.get("gpu", []))
    baseline = .5 if 0 < size <= 512 * 1024**2 else 4 if size > 5 * 1024**3 else 1
    minimum = round(max(baseline, weight_gb - free_gpu + .5), 2) if free_gpu else baseline
    available = resources.get("ram_available_gb", 0)
    return {"weights_gb": round(weight_gb, 3), "gpu_free_gb": round(free_gpu, 2),
            "ram_available_gb": available, "minimum_ram_available_gb": minimum,
            "can_test": isinstance(available, (int, float)) and available >= minimum,
            "basis": "Margem preventiva do NEXUS para um teste curto, sem garantia de consumo exato. Pesos até 512 MiB: pelo menos 0,5 GiB livre; acima de 5 GiB: pelo menos 4 GiB; demais: pelo menos 1 GiB. Pesos que excedam a VRAM livre aumentam a margem quando a GPU é detectada."}


class ModelLibrary:
    def __init__(self, data_dir, settings, update_settings, *, client_factory=None, resources=None):
        self.root = _safe(Path(data_dir) / "library")
        self.upload_dir = _safe(self.root / "uploads")
        self.root.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(exist_ok=True)
        self.settings = settings
        self.update_settings = update_settings
        self.client_factory = client_factory or (lambda: httpx.AsyncClient(trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(60, connect=10)))
        self.resources = resources or system_status
        self.pending = {}
        self.jobs = {}
        self.tasks = {}
        self.upload_lock = asyncio.Lock()
        self.operation_lock = asyncio.Lock()
        self._last_save = {}
        self._load_jobs()

    @staticmethod
    def check_compatibility(metadata, required=()):
        return check_compatibility(metadata, required)

    @property
    def url(self):
        return loopback_url(self.settings()["ollama_url"])

    def _load_jobs(self):
        path = self.root / "jobs.json"
        if path.exists():
            _safe(path, regular=True)
            if path.stat().st_size > 4 * 1024**2:
                raise LibraryError("Histórico da biblioteca excedeu o limite de leitura.", "library_storage")
            for item in json.loads(path.read_text(encoding="utf-8"))[-100:]:
                if item.get("status") not in TERMINAL:
                    item.update(status="interrupted", error="O NEXUS reiniciou; o estado do Ollama precisa ser consultado antes de repetir a operação.", finished_at=now())
                self.jobs[item["id"]] = item

    def _save(self, force=False, identity=None):
        stamp = time.monotonic()
        if not force and identity and stamp - self._last_save.get(identity, 0) < .5:
            return
        if identity:
            self._last_save[identity] = stamp
        rows = []
        for item in list(self.jobs.values())[-100:]:
            saved = self._public_job(item)
            saved["events"] = saved.get("events", [])[-10:]
            rows.append(_redact(saved))
        _atomic(self.root / "jobs.json", rows)

    async def _json(self, method, endpoint, payload=None):
        async with self.client_factory() as client:
            response = await client.request(method, self.url + endpoint, json=payload)
            response.raise_for_status()
            if not response.content:
                return {}
            value = response.json()
            if not isinstance(value, dict):
                raise LibraryError("Resposta inesperada do Ollama.", "ollama_protocol", "model_service")
            if value.get("error"):
                raise LibraryError(str(value["error"])[:2000], "ollama_error", "model_service")
            return value

    async def inventory(self):
        resources = await asyncio.to_thread(self.resources)
        try:
            tags = await self._json("GET", "/api/tags")
            running = await self._json("GET", "/api/ps")
        except (httpx.HTTPError, ValueError) as exc:
            return {"connected": False, "models": [], "running": [], "error": str(exc)[:1000],
                    "default_model": self.settings().get("model"), "resources": resources,
                    "uploads": self.uploads(), "jobs": self.job_list()}
        models = []
        loaded = {item.get("name", item.get("model")): item for item in running.get("models", [])}
        for tag in tags.get("models", []):
            item = copy.deepcopy(tag)
            name = item.get("name", item.get("model", ""))
            try:
                model_name(name)
                show = await self._json("POST", "/api/show", {"model": name})
            except (httpx.HTTPError, ValueError) as exc:
                show = {}
                item["metadata_error"] = str(exc)[:300]
            details = show.get("details", item.get("details", {}))
            capabilities = show.get("capabilities", item.get("capabilities", []))
            context = details.get("context_length")
            if context is None:
                context = next((value for key, value in show.get("model_info", {}).items() if key.endswith(".context_length") and type(value) is int), None)
            item.update(name=name, details=details, capabilities=capabilities, tools="tools" in capabilities,
                        vision="vision" in capabilities, quantization=details.get("quantization_level"),
                        parameter_size=details.get("parameter_size"), context_length=context,
                        loaded=name in loaded, size_vram=loaded.get(name, {}).get("size_vram"),
                        default=name == model_name(self.settings()["model"]), local=not _remote(show or item) and not _cloud_name(name))
            models.append(item)
        return {"connected": True, "models": models, "running": running.get("models", []),
                "default_model": self.settings()["model"], "resources": resources,
                "uploads": self.uploads(), "jobs": self.job_list()}

    async def _installed(self):
        value = await self._json("GET", "/api/tags")
        return {model_name(item.get("name", item.get("model", ""))): item for item in value.get("models", [])}

    def uploads(self):
        output = []
        for path in sorted(self.upload_dir.glob("*.json"))[-20:]:
            _safe(path, regular=True)
            if path.stat().st_size <= 65536:
                output.append(json.loads(path.read_text(encoding="utf-8")))
        return output

    def get_upload(self, identity):
        if not isinstance(identity, str) or not re.fullmatch("[a-f0-9]{32}", identity):
            raise LibraryError("Identificador de upload inválido.")
        meta = _safe(self.upload_dir / (identity + ".json"), regular=True)
        if meta.stat().st_size > 65536:
            raise LibraryError("Metadados do upload excedem o limite.", "library_storage")
        value = json.loads(meta.read_text(encoding="utf-8"))
        path = _safe(self.upload_dir / (identity + ".gguf"), regular=True)
        if path.stat().st_size != value["size"]:
            raise LibraryError("O arquivo importado mudou de tamanho.", "upload_changed")
        return path, value

    async def ingest(self, stream, name, expected_hash=None, source=None):
        if not isinstance(name, str) or len(name) > 200 or not re.fullmatch(r"[\w .()\-]+\.gguf", name, re.IGNORECASE) or ".." in name:
            raise LibraryError("Escolha um nome de arquivo .gguf simples, sem caminho.")
        if expected_hash and not SHA.fullmatch(expected_hash):
            raise LibraryError("SHA-256 esperado inválido.")
        async with self.upload_lock:
            if len(self.uploads()) >= 20:
                raise LibraryError("Limite de 20 uploads. Remova uma cópia de importação antes de enviar outra.", "upload_limit")
            identity = uuid.uuid4().hex
            path = _safe(self.upload_dir / (identity + ".gguf"))
            total, digest, prefix = 0, hashlib.sha256(), bytearray()
            try:
                with path.open("xb") as handle:
                    async for chunk in stream:
                        if not isinstance(chunk, bytes):
                            chunk = bytes(chunk)
                        total += len(chunk)
                        if total > MAX_UPLOAD:
                            raise LibraryError("Limite de upload GGUF: 16 GiB.", "upload_too_large")
                        if shutil.disk_usage(self.upload_dir).free < len(chunk) + DISK_RESERVE:
                            raise LibraryError("Espaço livre insuficiente; reserva mínima de 2 GiB.", "disk_space")
                        if len(prefix) < 4:
                            prefix.extend(chunk[:4 - len(prefix)])
                            if len(prefix) == 4 and prefix != b"GGUF":
                                raise LibraryError("O arquivo não possui assinatura GGUF.", "gguf_invalid")
                        digest.update(chunk)
                        await asyncio.to_thread(handle.write, chunk)
                    await asyncio.to_thread(handle.flush)
                actual = digest.hexdigest()
                if expected_hash and actual != expected_hash.lower():
                    raise LibraryError("SHA-256 do GGUF não corresponde ao esperado.", "integrity_mismatch")
                metadata = await asyncio.to_thread(inspect_gguf, path)
                result = {"id": identity, "name": name, "size": total, "sha256": actual,
                          "integrity": "matched_expected_sha256" if expected_hash else "computed_without_external_reference",
                          "source": source or {"kind": "local_upload"}, "created_at": now(), **metadata}
                _atomic(self.upload_dir / (identity + ".json"), result)
                return result
            except BaseException:
                path.unlink(missing_ok=True)
                (self.upload_dir / (identity + ".json")).unlink(missing_ok=True)
                raise

    def remove_upload(self, identity):
        path, value = self.get_upload(identity)
        if any(job.get("status") not in TERMINAL and job.get("args", {}).get("upload_id") == identity for job in self.jobs.values()):
            raise LibraryError("Esse upload está sendo usado por uma operação.", "upload_in_use")
        path.unlink()
        _safe(self.upload_dir / (identity + ".json"), regular=True).unlink()
        return {"ok": True, "removed_upload": identity, "ollama_model_removed": False}

    async def _manifest(self, model):
        base, tag = model.rsplit(":", 1)
        if "/" not in base:
            base = "library/" + base
        url = f"https://registry.ollama.ai/v2/{base}/manifests/{quote(tag, safe='')}"
        try:
            async with self.client_factory() as client:
                response = await client.get(url, headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"}, timeout=12)
                response.raise_for_status()
                if len(response.content) > 1024**2:
                    raise LibraryError("Manifesto remoto excessivo.")
                data = response.json()
                layers = data.get("layers", []) + [data.get("config", {})]
                size = sum(item["size"] for item in layers)
                if size <= 0 or any(type(item.get("size")) is not int or item["size"] < 0 for item in layers):
                    raise LibraryError("Manifesto sem tamanhos válidos.")
                return {"url": url, "kind": "ollama_registry", "manifest_sha256": hashlib.sha256(response.content).hexdigest(),
                        "estimated_download_bytes": size, "layers": [{"digest": item.get("digest"), "size": item["size"]} for item in layers],
                        "size_note": "Soma dos blobs no manifesto; blobs já em cache podem reduzir o tráfego real. A tag do registro pode mudar."}
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404:
                raise LibraryError("Modelo ou tag inexistente no registro Ollama.", "model_not_found") from exc
            return {"kind": "ollama_registry", "url": url, "estimated_download_bytes": None,
                    "metadata_error": str(exc)[:300], "size_note": "Tamanho desconhecido; a aprovação autoriza um download cujo total ainda não foi informado pelo registro."}

    async def _hf_metadata(self, args):
        repo, filename, revision = args.get("repo", ""), args.get("filename", ""), args.get("revision", "main")
        if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", repo) or ".." in repo:
            raise LibraryError("Referência Hugging Face deve ser autor/repositório.")
        if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){0,4}\.gguf", filename, re.IGNORECASE) or ".." in filename:
            raise LibraryError("Informe um arquivo GGUF explícito do repositório, sem caminho relativo.")
        if not isinstance(revision, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", revision) or ".." in revision:
            raise LibraryError("Revisão Hugging Face inválida.")
        async with self.client_factory() as client:
            response = await client.get(f"https://huggingface.co/api/models/{repo}/revision/{revision}", params={"blobs": "true"}, timeout=20)
            response.raise_for_status()
            if len(response.content) > 4 * 1024**2:
                raise LibraryError("Metadados Hugging Face excessivos.")
            data = response.json()
        if not isinstance(data, dict):
            raise LibraryError("Metadados Hugging Face não são um objeto válido.", "hf_provenance")
        commit = data.get("sha", "")
        if not isinstance(commit, str) or not re.fullmatch("[a-fA-F0-9]{40}", commit):
            raise LibraryError("O provedor não informou commit fixo válido.", "hf_provenance")
        selected = next((item for item in data.get("siblings", []) if item.get("rfilename") == filename), None)
        if selected is None:
            raise LibraryError("Arquivo GGUF não encontrado na revisão consultada.", "hf_file_missing")
        lfs = selected.get("lfs") or {}
        digest = lfs.get("sha256") or lfs.get("oid")
        if digest and not SHA.fullmatch(digest):
            raise LibraryError("Hash LFS inválido no provedor.", "hf_provenance")
        size = lfs.get("size", selected.get("size"))
        if size is not None and (type(size) is not int or size <= 0 or size > MAX_UPLOAD):
            raise LibraryError("GGUF remoto excede o limite de 16 GiB ou possui tamanho inválido.", "hf_size")
        card = data.get("cardData") or {}
        declared = data.get("gguf") or {}
        architecture = declared.get("architecture") if isinstance(declared, dict) else None
        if architecture is not None and architecture not in ARCHITECTURES:
            raise LibraryError("Arquitetura GGUF declarada pelo provedor não habilitada neste importador: " + str(architecture)[:80], "gguf_architecture")
        return {"kind": "huggingface", "repo": repo, "filename": filename, "revision": revision, "commit": commit.lower(),
                "url": f"https://huggingface.co/{repo}/resolve/{commit}/{quote(filename, safe='/')}",
                "sha256": digest.lower() if digest else None, "estimated_download_bytes": size,
                "license": card.get("license") if isinstance(card, dict) else None,
                "architecture": architecture, "architecture_validation": "declared_only_until_GGUF_parsed" if architecture else "checked_after_download",
                "provenance": "Publicador e commit identificados; isso não certifica a confiança do autor ou a compatibilidade dos pesos.",
                "scripts_executed": False}

    async def preview(self, payload):
        if not isinstance(payload, dict) or set(payload) - {"action", "model", "base", "system", "context", "temperature", "upload_id", "repo", "filename", "revision", "prompt"}:
            raise LibraryError("Campos desconhecidos na operação de modelo.")
        action, model = payload.get("action"), model_name(payload.get("model"))
        if action not in ACTIONS:
            raise LibraryError("Operação de biblioteca desconhecida.")
        args = {"action": action, "model": model, "ollama_url": self.url}
        installed = await self._installed()
        if action in {"pull", "hf", "variant", "import"} and model in installed:
            raise LibraryError("Esse nome já está instalado. Escolha outro nome; a biblioteca preserva tags existentes.", "model_exists")
        if action in {"delete", "unload", "default", "test"} and model not in installed:
            raise LibraryError("Modelo não instalado.", "model_not_installed")
        resource = await asyncio.to_thread(self.resources)
        source = {"kind": "installed_model"}
        warnings = []
        preview = {"action": action, "model": model, "estimated_download_bytes": 0, "resources": resource,
                   "warnings": warnings, "requires_confirmation": action == "delete", "ollama_url": self.url}
        if action == "pull":
            source = await self._manifest(model)
        if action == "hf":
            source = await self._hf_metadata(payload)
        if action in {"variant", "import", "hf"}:
            context, temperature = payload.get("context", 4096), payload.get("temperature", .3)
            system = payload.get("system", "")
            if type(context) is not int or not 512 <= context <= 32768:
                raise LibraryError("Contexto da variante deve ficar entre 512 e 32768 tokens.")
            if type(temperature) not in (int, float) or not math.isfinite(temperature) or not 0 <= temperature <= 2:
                raise LibraryError("Temperatura deve ficar entre 0 e 2.")
            if not isinstance(system, str) or len(system) > 16000 or "\x00" in system:
                raise LibraryError("Prompt de sistema inválido ou maior que 16000 caracteres.")
            args.update(context=context, temperature=temperature, system=system)
            if context > 8192:
                warnings.append("Contexto acima de 8192 pode aumentar significativamente RAM e VRAM neste computador.")
            if action == "variant":
                base = model_name(payload.get("base"))
                if base not in installed:
                    raise LibraryError("A variante exige um modelo base instalado; não fará download implícito.", "base_not_installed")
                show = await self._json("POST", "/api/show", {"model": base})
                if _remote(show):
                    raise LibraryError("Modelo base remoto não pode criar variante local.", "local_model_policy")
                args.update(base=base, base_digest=installed[base].get("digest"))
                source = {"kind": "installed_model", "base": base, "digest": installed[base].get("digest")}
                warnings.append("Criar uma variante altera instruções e parâmetros; não treina novos pesos.")
            if action == "import":
                path, upload = self.get_upload(payload.get("upload_id"))
                args.update(upload_id=upload["id"], upload_sha256=upload["sha256"])
                preview["upload"] = upload
                source = {"kind": "local_upload", "sha256": upload["sha256"], "name": upload["name"], "size": upload["size"],
                          "architecture": upload["architecture"], "integrity": upload["integrity"]}
                warnings.append("A importação mantém uma cópia local e envia o blob ao Ollama; planeje espaço para ambas.")
            base_display = args.get("base", "sha256:" + source.get("sha256", "GGUF_validado"))
            preview["modelfile"] = "FROM " + base_display + "\nPARAMETER num_ctx " + str(context) + "\nPARAMETER temperature " + str(temperature) + "\nSYSTEM " + json.dumps(system, ensure_ascii=False)
            preview["modelfile_note"] = "Prévia equivalente. O backend usa campos estruturados /api/create; não interpreta comandos de Modelfile nem executa scripts."
        if action in {"default", "test"}:
            show = await self._json("POST", "/api/show", {"model": model})
            if _remote(show) or "completion" not in show.get("capabilities", installed[model].get("capabilities", [])):
                raise LibraryError("Selecione um modelo de conversação local, com capacidade completion declarada.", "model_incompatible")
        if action == "test":
            prompt = payload.get("prompt", "Responda apenas: NEXUS OK")
            if not isinstance(prompt, str) or not 1 <= len(prompt) <= 1000:
                raise LibraryError("Prompt de teste deve ter entre 1 e 1000 caracteres.")
            args["prompt"] = prompt
            preview["test"] = {"prompt": prompt, "context": 2048, "max_tokens": 48, "unload_after": True}
            budget = test_budget(installed[model], resource)
            preview["test"]["budget"] = budget
            if not budget["can_test"]:
                raise LibraryError(f"Margem preventiva para este teste: {budget['minimum_ram_available_gb']} GiB de RAM livre; disponíveis {budget['ram_available_gb']} GiB. Libere memória e prepare nova prévia. Isso é uma margem local, não um requisito oficial do modelo.", "memory_low")
        if action == "delete":
            references = [key for key in ("model", "coding_model", "embedding_model") if self.settings().get(key) and model_name(self.settings()[key]) == model]
            if references:
                raise LibraryError("Modelo em uso nas configurações: " + ", ".join(references) + ". Troque essa configuração antes de remover.", "model_referenced")
            args["model_digest"] = installed[model].get("digest")
            warnings.append("A remoção apaga a tag local; blobs compartilhados dependem do gerenciamento do Ollama.")
        if action in {"unload", "default", "test"}:
            args["model_digest"] = installed[model].get("digest")
        args["source"] = source
        preview["source"] = source
        preview["estimated_download_bytes"] = source.get("estimated_download_bytes", 0)
        size = preview["estimated_download_bytes"]
        if action in {"pull", "hf", "import"}:
            available = shutil.disk_usage(self.root).free
            expected = source.get("size", size) or 0
            multiplier = 2 if action == "hf" else 1
            if expected and expected * multiplier + DISK_RESERVE > available:
                raise LibraryError("Espaço livre insuficiente para a operação e reserva de 2 GiB.", "disk_space")
            if size is None:
                warnings.append("Tamanho de download desconhecido; o progresso só exibirá totais recebidos do provedor.")
            if expected > 5 * 1024**3:
                warnings.append("Modelo maior que aproximadamente 5 GiB: pode precisar de RAM e CPU além dos 6 GiB de VRAM.")
        if resource.get("ram_available_gb", 0) < 2:
            warnings.append("Há menos de 2 GiB de RAM livre. Downloads não carregam pesos, mas o teste de inferência pode causar lentidão.")
        warnings.append("Operações aguardam a mesma fila de recursos usada pelo chat e pelo Security Center.")
        self.pending = {key: item for key, item in self.pending.items() if item["deadline"] > time.monotonic()}
        if len(self.pending) >= 32:
            raise LibraryError("Resolva as aprovações pendentes antes de preparar novas operações.", "approval_limit")
        identity = uuid.uuid4().hex
        self.pending[identity] = {"args": args, "digest": self._digest(args), "deadline": time.monotonic() + 300}
        return {"ok": True, "approval_id": identity, "expires_in": 300, "preview": preview}

    @staticmethod
    def _digest(args):
        return hashlib.sha256(json.dumps(args, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()

    def approve(self, identity, approved, confirmation=None):
        item = self.pending.get(identity)
        if not item or item["deadline"] < time.monotonic():
            self.pending.pop(identity, None)
            raise LibraryError("Prévia inexistente, consumida ou expirada.", "approval_expired", "permission")
        if approved is not True:
            self.pending.pop(identity)
            return None
        if item["digest"] != self._digest(item["args"]):
            self.pending.pop(identity)
            raise LibraryError("Argumentos mudaram. Prepare uma nova prévia.", "approval_changed", "permission")
        if item["args"]["action"] == "delete" and confirmation != item["args"]["model"]:
            raise LibraryError("Digite o nome completo e a tag para confirmar a remoção.", "confirmation_required", "permission")
        if sum(job.get("status") not in TERMINAL for job in self.jobs.values()) >= 8:
            raise LibraryError("Há oito operações aguardando ou executando. Aguarde ou cancele uma delas.", "queue_limit")
        self.pending.pop(identity)
        job_id = uuid.uuid4().hex
        args = copy.deepcopy(item["args"])
        job = {"id": job_id, "status": "queued", "action": args["action"], "model": args["model"], "args": args,
               "created_at": now(), "progress": {"status": "Aguardando a fila compartilhada", "percent": None}, "events": [],
               "cancel_supported": "best_effort_close_connection", "cancellation_note": "Fechar a conexão interrompe o cliente NEXUS. O Ollama pode continuar um pull compartilhado; blobs parciais podem permanecer em cache."}
        self.jobs[job_id] = job
        for old_id in list(self.jobs)[:-100]:
            if self.jobs[old_id].get("status") in TERMINAL:
                self.jobs.pop(old_id)
        self._save(force=True)
        return job

    def job(self, identity):
        if identity not in self.jobs:
            raise LibraryError("Operação inexistente.", "job_not_found")
        # Prompts de configuração não são copiados para o histórico de operações.
        return self._public_job(self.jobs[identity])

    @staticmethod
    def _public_job(job):
        value = copy.deepcopy(job)
        value.pop("args", None)
        return value

    def job_list(self):
        return [self._public_job(item) for item in list(self.jobs.values())[-100:]][::-1]

    def _event(self, job, value):
        event = {key: value[key] for key in ("status", "digest", "total", "completed", "error") if key in value}
        event = _redact(event)
        for key, limit in (("status", 512), ("digest", 128), ("error", 1000)):
            if key in event:
                event[key] = str(event[key])[:limit]
        event["at"] = now()
        for key in ("total", "completed"):
            if key in event and (type(event[key]) is not int or event[key] < 0):
                event.pop(key)
        total, completed = event.get("total"), event.get("completed")
        event["percent"] = round(min(100, 100 * completed / total), 2) if total and completed is not None else None
        job["events"].append(event)
        job["events"] = job["events"][-150:]
        job["progress"] = event
        self._save(identity=job["id"])

    async def _stream(self, job, endpoint, payload):
        success = False
        async with self.client_factory() as client:
            async with client.stream("POST", self.url + endpoint, json=payload, timeout=httpx.Timeout(None, connect=10)) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line:
                        continue
                    if len(line) > 65536:
                        raise LibraryError("Evento de progresso do Ollama excessivo.", "ollama_protocol", "model_service")
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise LibraryError("Evento de progresso inválido.", "ollama_protocol", "model_service")
                    self._event(job, value)
                    if value.get("error"):
                        raise LibraryError(str(value["error"])[:2000], "ollama_error", "model_service")
                    success = value.get("status") == "success" or success
        if not success:
            raise LibraryError("O Ollama encerrou o stream sem confirmar sucesso.", "ollama_stream_incomplete", "model_service")

    async def _upload_blob(self, job, path, expected):
        actual = await asyncio.to_thread(_file_hash, path)
        if actual != expected:
            raise LibraryError("GGUF mudou após a aprovação; importação cancelada.", "integrity_mismatch")
        await asyncio.to_thread(inspect_gguf, path)
        digest = "sha256:" + actual
        async with self.client_factory() as client:
            head = await client.head(self.url + "/api/blobs/" + digest)
            if head.status_code == 200:
                self._event(job, {"status": "Blob já presente no Ollama", "completed": path.stat().st_size, "total": path.stat().st_size})
                return digest
            if head.status_code != 404:
                head.raise_for_status()
            async def chunks():
                count = 0
                with _safe(path, regular=True).open("rb") as handle:
                    while True:
                        chunk = await asyncio.to_thread(handle.read, 1024**2)
                        if not chunk:
                            break
                        count += len(chunk)
                        self._event(job, {"status": "Enviando blob ao Ollama", "completed": count, "total": path.stat().st_size})
                        yield chunk
            response = await client.post(self.url + "/api/blobs/" + digest, content=chunks(),
                                         headers={"Content-Type": "application/octet-stream", "Content-Length": str(path.stat().st_size)}, timeout=None)
            response.raise_for_status()
        return digest

    @staticmethod
    def _hf_redirect(url):
        value = urlsplit(url)
        host = value.hostname or ""
        if value.scheme != "https" or value.username or value.password or value.port not in (None, 443) or not (
            host == "huggingface.co" or host == "cdn-lfs.huggingface.co" or host.endswith(".huggingface.co") or
            host == "cas-bridge.xethub.hf.co" or host.endswith(".xethub.hf.co") or host.endswith(".cloudfront.net")):
            raise LibraryError("Redirecionamento de download fora dos hosts de entrega permitidos para Hugging Face.", "hf_redirect")
        return url

    async def _download_hf(self, job, source):
        url = source["url"]
        async with self.client_factory() as client:
            for _ in range(6):
                self._hf_redirect(url)
                async with client.stream("GET", url, timeout=httpx.Timeout(120, connect=15)) as response:
                    if response.is_redirect:
                        url = urljoin(url, response.headers.get("location", ""))
                        continue
                    response.raise_for_status()
                    announced = response.headers.get("content-length")
                    size = int(announced) if announced and announced.isdigit() else source.get("estimated_download_bytes")
                    if size and size > MAX_UPLOAD:
                        raise LibraryError("GGUF remoto excede 16 GiB.", "hf_size")
                    completed = 0
                    async def chunks():
                        nonlocal completed
                        async for chunk in response.aiter_bytes(1024**2):
                            completed += len(chunk)
                            self._event(job, {"status": "Baixando GGUF Hugging Face", "completed": completed, **({"total": size} if size else {})})
                            yield chunk
                    result = await self.ingest(chunks(), Path(source["filename"]).name, source.get("sha256"), source)
                    if source.get("estimated_download_bytes") and result["size"] != source["estimated_download_bytes"]:
                        self.remove_upload(result["id"])
                        raise LibraryError("O tamanho baixado diverge dos metadados aprovados.", "integrity_mismatch")
                    return result
        raise LibraryError("Excesso de redirecionamentos do Hugging Face.", "hf_redirect")

    async def _perform(self, job):
        args, model, action = job["args"], job["model"], job["action"]
        if self.url != args.get("ollama_url"):
            raise LibraryError("O serviço Ollama mudou após a prévia. Prepare uma aprovação para o endereço atual.", "ollama_changed")
        installed = await self._installed()
        if action in {"pull", "hf", "variant", "import"} and model in installed:
            raise LibraryError("O nome passou a existir após a prévia. Nada foi sobrescrito.", "model_exists")
        if action in {"delete", "default", "unload", "test"}:
            if model not in installed or installed[model].get("digest") != args.get("model_digest"):
                raise LibraryError("O modelo mudou ou foi removido após a prévia.", "model_changed")
        if action in {"pull", "hf", "import"}:
            source = args["source"]
            size = source.get("estimated_download_bytes", source.get("size")) or 0
            if size * (2 if action == "hf" else 1) + DISK_RESERVE > shutil.disk_usage(self.root).free:
                raise LibraryError("Espaço livre diminuiu após a prévia; a operação precisa de uma nova aprovação depois de liberar armazenamento.", "disk_space")
        if action == "pull":
            old = args["source"]
            current = await self._manifest(model)
            if old.get("manifest_sha256") and current.get("manifest_sha256") != old["manifest_sha256"]:
                raise LibraryError("O manifesto mudou ou não pôde ser revalidado. Prepare uma nova aprovação.", "manifest_changed")
            await self._stream(job, "/api/pull", {"model": model, "stream": True})
        elif action in {"variant", "import", "hf"}:
            payload = {"model": model, "stream": True, "system": args["system"],
                       "parameters": {"temperature": args["temperature"], "num_ctx": args["context"]}}
            if action == "variant":
                base = args["base"]
                if base not in installed or installed[base].get("digest") != args.get("base_digest"):
                    raise LibraryError("O modelo base mudou após a aprovação.", "base_changed")
                payload["from"] = base
            else:
                if action == "hf":
                    upload = await self._download_hf(job, args["source"])
                    job["upload_id"] = upload["id"]
                    path, upload = self.get_upload(upload["id"])
                else:
                    path, upload = self.get_upload(args["upload_id"])
                    if upload["sha256"] != args["upload_sha256"]:
                        raise LibraryError("O upload mudou após a aprovação.", "upload_changed")
                digest = await self._upload_blob(job, path, upload["sha256"])
                payload["files"] = {"model.gguf": digest}
            await self._stream(job, "/api/create", payload)
        elif action == "delete":
            references = [key for key in ("model", "coding_model", "embedding_model") if self.settings().get(key) and model_name(self.settings()[key]) == model]
            if references:
                raise LibraryError("Esse modelo passou a ser usado nas configurações. Troque-o antes de remover.", "model_referenced")
            await self._json("DELETE", "/api/delete", {"model": model})
        elif action == "unload":
            await self._json("POST", "/api/generate", {"model": model, "keep_alive": 0, "stream": False})
        elif action == "default":
            show = await self._json("POST", "/api/show", {"model": model})
            if _remote(show) or "completion" not in show.get("capabilities", []):
                raise LibraryError("O modelo deixou de declarar conversação local compatível.", "model_incompatible")
            result = self.update_settings({"model": model})
            if asyncio.iscoroutine(result):
                await result
        elif action == "test":
            resource = await asyncio.to_thread(self.resources)
            budget = test_budget(installed[model], resource)
            if not budget["can_test"]:
                raise LibraryError(f"RAM disponível diminuiu após a prévia: {budget['ram_available_gb']} GiB; margem preventiva deste teste {budget['minimum_ram_available_gb']} GiB. Teste adiado.", "memory_low")
            running = await self._json("GET", "/api/ps")
            others = [item for item in running.get("models", []) if item.get("name", item.get("model")) != model]
            if others:
                raise LibraryError("Descarregue o outro modelo antes do teste para evitar carregar dois modelos grandes.", "model_already_loaded")
            show = await self._json("POST", "/api/show", {"model": model})
            payload = {"model": model, "prompt": args["prompt"], "stream": False, "keep_alive": 0,
                       "options": {"num_ctx": 2048, "num_predict": 48, "temperature": 0, "num_batch": 64}}
            if "thinking" in show.get("capabilities", []):
                payload["think"] = False
            started = time.perf_counter()
            value = await self._json("POST", "/api/generate", payload)
            duration = value.get("eval_duration", 0)
            if not value.get("done"):
                raise LibraryError("Teste sem confirmação de conclusão do Ollama.", "ollama_stream_incomplete")
            return {"ok": True, "model": model, "response": value.get("response", "")[:8000], "load_tested": True,
                    "budget": budget, "metrics": {"elapsed_seconds": round(time.perf_counter() - started, 3), "tokens": value.get("eval_count", 0),
                                "tokens_per_second": round(value.get("eval_count", 0) * 1e9 / duration, 2) if duration else None,
                                "load_seconds": value.get("load_duration", 0) / 1e9}, "unload_after": True}
        return {"ok": True, "action": action, "model": model, "training_performed": False}

    async def run(self, identity, inference, activity):
        job = self.jobs[identity]
        try:
            async with self.operation_lock, inference():
                job.update(status="running", started_at=now())
                self._event(job, {"status": "Executando operação aprovada"})
                activity().add("model_operation_started", {"id": identity, "action": job["action"], "model": job["model"]})
                job["result"] = await self._perform(job)
                job.update(status="completed", finished_at=now())
        except asyncio.CancelledError:
            job.update(status="cancelled", finished_at=now(), error="Cancelamento solicitado; a conexão do NEXUS foi encerrada. Consulte a biblioteca para confirmar o estado final no Ollama.")
        except (Exception,) as exc:
            job.update(status="failed", finished_at=now(), error=redact_secrets(str(exc))[:2000],
                       code=getattr(exc, "code", "ollama_http_error" if isinstance(exc, httpx.HTTPError) else "library_error"),
                       source=getattr(exc, "source", "model_service" if isinstance(exc, httpx.HTTPError) else "application"))
        finally:
            self._save(force=True)
            activity().add("model_operation_finished", {"id": identity, "action": job["action"], "model": job["model"], "status": job["status"], "code": job.get("code")})
            self.tasks.pop(identity, None)

    def start(self, identity, inference, activity):
        task = asyncio.create_task(self.run(identity, inference, activity))
        self.tasks[identity] = task
        def finished(_task):
            if self.jobs[identity]["status"] not in TERMINAL:
                self.jobs[identity].update(status="cancelled" if _task.cancelled() else "failed", finished_at=now(),
                    error="Operação interrompida antes de executar; consulte o estado da biblioteca.")
                self._save(force=True)
            self.tasks.pop(identity, None)
        task.add_done_callback(finished)

    def cancel(self, identity):
        job = self.jobs.get(identity)
        if not job:
            raise LibraryError("Operação inexistente.", "job_not_found")
        if job["status"] in TERMINAL:
            return {"ok": True, "cancelled": False, "job": self.job(identity)}
        task = self.tasks.get(identity)
        if task:
            task.cancel()
        if job["status"] == "queued":
            job.update(status="cancelled", finished_at=now(), error="Cancelado antes de iniciar.")
            self._save(force=True)
        return {"ok": True, "cancel_requested": True, "job_id": identity, "note": job["cancellation_note"]}

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
