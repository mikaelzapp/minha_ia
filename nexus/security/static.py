"""Bounded, read-only static inspection. No sample or project code is executed.

The caller owns authorization of the target path. These checks are a second
boundary against links and credential files, not an operating-system sandbox.
All code findings and binary indicators are hypotheses requiring validation.
"""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import time
import tomllib
from typing import Any

from ..memory import redact_secrets
from ..tools import Tools


MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024
MAX_PROJECT_BYTES = 8 * 1024 * 1024
MAX_PROJECT_FILES = 250
MAX_ENTRIES = 5_000
MAX_FINDINGS = 200
MAX_STRINGS = 160
MAX_STRING_CHARS = 240
MAX_STRING_TOTAL = 24_000
MAX_RULE_BYTES = 256 * 1024
MAX_SECTION_ENTROPY_BYTES = 1024 * 1024
SCAN_SECONDS = 20

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".next", "dist", "build",
    "coverage", "vendor", ".ssh", ".aws", ".azure", ".gnupg", ".kube",
    ".codex", ".agents", ".docker", "secrets", "credentials", "data",
    ".secrets", ".credentials", ".runtime",
}
SECRET_SUFFIXES = {".db", ".db3", ".sqlite", ".sqlite3", ".pem", ".key", ".p12",
                   ".pfx", ".kdbx", ".keystore", ".log", ".bak", ".jks"}
SOURCE_SUFFIXES = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
                   ".php", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
                   ".conf", ".dockerfile", ".sh", ".ps1", ".sql", ".tf"}
MANIFEST_NAMES = {"package.json", "package-lock.json", "requirements.txt", "pyproject.toml",
                  "poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock", "composer.json",
                  "composer.lock", "Cargo.toml", "Cargo.lock", "go.mod"}
NOTICE = ("Análise estática: os indicadores são hipóteses; presença não confirma malware "
          "e ausência não comprova segurança. Nenhuma amostra ou código do projeto foi executado.")

# Small transparent descriptors, not a malware-signature feed. No rule download.
DEFAULT_YARA_SOURCE = '''
rule NEXUS_PE_Header : descriptor {
    meta: description = "Cabecalho MZ; nao identifica malware"
    condition: uint16(0) == 0x5a4d
}
rule NEXUS_ELF_Header : descriptor {
    meta: description = "Cabecalho ELF; nao identifica malware"
    condition: uint32(0) == 0x464c457f
}
rule NEXUS_Shell_Reference : hypothesis {
    meta: description = "Referencia textual a interpretador; requer contexto"
    strings: $a = "powershell" ascii wide nocase
             $b = "/bin/sh" ascii wide
    condition: any of them
}
'''


class StaticError(ValueError):
    """A target cannot be inspected within the read-only policy."""


def _clean(value: Any, limit: int = 500) -> str:
    text = redact_secrets(str(value))
    return "".join(c if c in "\n\t" or ord(c) >= 32 else "�" for c in text)[:limit]


def _sensitive(name: str) -> bool:
    return (Tools._sensitive(name) or Path(name).suffix.casefold() in SECRET_SUFFIXES
            or name.casefold() in {"auth.secret", "computer-access.json", "config.json"})


def _linked(info: os.stat_result) -> bool:
    return (stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)
            or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1))


def _checked(path: Path, *, directory: bool = False) -> tuple[Path, os.stat_result]:
    raw = os.fspath(path)
    if not raw or len(raw) > 2048 or "\x00" in raw or raw.startswith(("\\\\", "//")):
        raise StaticError("Caminho local inválido.")
    supplied = Path(raw)
    if ".." in supplied.parts:
        raise StaticError("Travessia de diretório não é permitida.")
    absolute = supplied.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:] if absolute.anchor else absolute.parts:
        if ":" in part or part.endswith((" ", ".")):
            raise StaticError("Fluxos alternativos ou nomes ambíguos não são permitidos.")
        if _sensitive(part):
            raise StaticError("Arquivo ou diretório de credenciais protegido.")
        current = current / part
        info = current.lstat()
        if _linked(info):
            raise StaticError("Links, junctions, reparse points e hardlinks são recusados.")
    info = absolute.lstat()
    if _linked(info) or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)):
        raise StaticError("O alvo precisa ser um diretório regular." if directory
                          else "O alvo precisa ser um arquivo regular, sem links.")
    return absolute, info


def _read(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    checked, before = _checked(path)
    if before.st_size > limit:
        raise StaticError(f"Arquivo excede o limite de {limit} bytes.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(checked, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (_linked(opened) or not stat.S_ISREG(opened.st_mode)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise StaticError("Arquivo mudou antes da leitura.")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    _, current = _checked(checked)
    if (len(data) > limit or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)):
        raise StaticError("Arquivo mudou durante a leitura ou excedeu o limite.")
    return data


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 4)


def _format(data: bytes) -> str:
    signatures = ((b"MZ", "PE/DOS"), (b"\x7fELF", "ELF"), (b"%PDF-", "PDF"),
                  (b"PK\x03\x04", "ZIP"), (b"PK\x05\x06", "ZIP"),
                  (b"\x1f\x8b", "GZIP"), (b"7z\xbc\xaf\x27\x1c", "7ZIP"),
                  (b"Rar!", "RAR"), (b"\x89PNG\r\n\x1a\n", "PNG"),
                  (b"\xff\xd8\xff", "JPEG"), (b"\x00asm", "WebAssembly"),
                  (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
                  (b"\xcf\xfa\xed\xfe", "Mach-O 64"), (b"\xce\xfa\xed\xfe", "Mach-O"))
    for magic, name in signatures:
        if data.startswith(magic):
            return name
    if data and b"\0" not in data[:4096]:
        try:
            data[:4096].decode("utf-8")
            return "UTF-8 text"
        except UnicodeDecodeError:
            pass
    return "unknown" if data else "empty"


def _strings(data: bytes) -> tuple[list[dict], bool]:
    result: list[dict] = []
    total = 0
    seen: set[tuple[int, str]] = set()
    for encoding, pattern in (("ASCII", rb"[\x20-\x7e]{6,}"),
                              ("UTF-16LE", rb"(?:[\x20-\x7e]\x00){6,}"),
                              ("UTF-16BE", rb"(?:\x00[\x20-\x7e]){6,}")):
        for match in re.finditer(pattern, data):
            # Redact the complete candidate before truncation so long keys cannot leak.
            value = _clean(match.group().decode("ascii" if encoding == "ASCII" else encoding.lower()),
                           MAX_STRING_CHARS)
            key = (match.start(), value)
            if key in seen:
                continue
            if len(result) >= MAX_STRINGS or total + len(value) > MAX_STRING_TOTAL:
                return result, True
            seen.add(key)
            result.append({"offset": match.start(), "encoding": encoding, "text": value,
                           "truncated": len(match.group()) > MAX_STRING_CHARS * (1 if encoding == "ASCII" else 2)})
            total += len(value)
    return sorted(result, key=lambda item: item["offset"]), False


def _pe(data: bytes) -> dict | None:
    if not data.startswith(b"MZ"):
        return None
    result: dict = {"valid_pe_header": False, "architecture": "unknown", "sections": []}
    if len(data) < 64:
        result["error"] = "Cabeçalho DOS truncado."
        return result
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if offset > len(data) - 24 or data[offset:offset + 4] != b"PE\0\0":
        result["error"] = "Assinatura PE ausente ou fora do arquivo."
        return result
    machine, number, stamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, offset + 4)
    result.update(valid_pe_header=True, architecture={0x14C: "x86", 0x8664: "x86-64",
                  0xAA64: "ARM64", 0x1C4: "ARMv7"}.get(machine, f"machine_0x{machine:04x}"),
                  machine=machine, section_count=number, timestamp_raw=stamp,
                  characteristics=f"0x{characteristics:04x}")
    optional = offset + 24
    if optional_size and optional + optional_size <= len(data) and optional_size >= 20:
        magic = struct.unpack_from("<H", data, optional)[0]
        result["optional_magic"] = f"0x{magic:04x}"
        result["entry_point_rva"] = struct.unpack_from("<I", data, optional + 16)[0]
    start = optional + optional_size
    entropy_budget = MAX_SECTION_ENTROPY_BYTES
    for index in range(min(number, 96)):
        position = start + index * 40
        if position > len(data) - 40:
            result["section_table_truncated"] = True
            break
        name = data[position:position + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, size, raw_offset = struct.unpack_from("<IIII", data, position + 8)
        flags = struct.unpack_from("<I", data, position + 36)[0]
        bounded = raw_offset <= len(data) and size <= len(data) - raw_offset
        section = {"name": _clean(name, 32), "virtual_size": virtual_size, "virtual_address": virtual_address,
                   "raw_size": size, "raw_offset": raw_offset, "data_within_file": bounded,
                   "writable_executable": bool(flags & 0x80000000 and flags & 0x20000000)}
        if bounded and entropy_budget:
            sample_size = min(size, 64 * 1024, entropy_budget)
            section["entropy"] = _entropy(data[raw_offset:raw_offset + sample_size])
            section["entropy_sample_bytes"] = sample_size
            section["entropy_sampled"] = sample_size < size
            entropy_budget -= sample_size
        result["sections"].append(section)
    if number > 96:
        result["sections_truncated"] = True
    return result


def _elf(data: bytes) -> dict | None:
    if not data.startswith(b"\x7fELF"):
        return None
    result = {"valid_header": False, "architecture": "unknown"}
    if len(data) < 20 or data[4] not in {1, 2} or data[5] not in {1, 2}:
        return result
    endian = "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    result.update(valid_header=True, bits=32 if data[4] == 1 else 64,
                  byte_order="little" if data[5] == 1 else "big", machine=machine,
                  architecture={3: "x86", 62: "x86-64", 40: "ARM", 183: "ARM64",
                                8: "MIPS", 243: "RISC-V"}.get(machine, f"machine_{machine}"))
    return result


def tool_capabilities() -> dict:
    """Inventory only: discovering a CLI never executes it or downloads rules."""
    engines = {}
    try:
        present = importlib.util.find_spec("yara_x") is not None
    except (ImportError, ValueError):
        present = False
    try:
        version = importlib.metadata.version("yara-x") if present else None
    except importlib.metadata.PackageNotFoundError:
        version = None
    engines["yara_x"] = {"installed": present, "available": present, "version": version,
                         "mode": "in-process static bytes", "default_rules": "3 descriptive rules; no malware feed"}
    for name, executable in (("capa", "capa"), ("floss", "floss"), ("semgrep", "semgrep"), ("trivy", "trivy")):
        engines[name] = {"installed": bool(shutil.which(executable)), "available": False,
                         "reason": "Não executado: adapter/recursos locais ainda não configurados e validados."}
    engines["decompile"] = {"available": False, "reason": "Descompilador não integrado; sem execução da amostra."}
    return engines


def inventory_optional_engines() -> dict:
    """Public inventory alias used by the Security Center API."""
    return tool_capabilities()


def _yara_data(data: bytes, rulesfile: Path | None = None) -> dict:
    engines = tool_capabilities()
    status = engines["yara_x"]
    if not status["available"]:
        return {"ok": False, "available": False, "engine": "yara-x", "error": "YARA-X não está instalado.",
                "matches": [], "scanned": False}
    try:
        import yara_x
        source = (_read(rulesfile, MAX_RULE_BYTES).decode("utf-8-sig") if rulesfile is not None
                  else DEFAULT_YARA_SOURCE)
        compiler = yara_x.Compiler()
        compiler.enable_includes(False)
        compiler.add_source(source)
        scanner = yara_x.Scanner(compiler.build())
        scanner.set_timeout(5)
        scanner.max_matches_per_pattern(20)
        results = scanner.scan(data)
        matches = []
        for rule in results.matching_rules[:100]:
            matches.append({"rule": _clean(rule.identifier, 200), "namespace": _clean(rule.namespace, 100),
                            "pattern_offsets": [{"pattern": _clean(pattern.identifier, 100),
                                "offsets": [match.offset for match in pattern.matches[:20]]}
                                for pattern in rule.patterns[:20]], "validation": "unconfirmed"})
        return {"ok": True, "available": True, "scanned": True, "engine": "yara-x",
                "version": status["version"], "rules_source": "custom local file" if rulesfile else "built-in descriptors",
                "matches": matches, "notice": "Correspondência de regra não confirma malware; verifique regra e contexto."}
    except Exception as exc:
        return {"ok": False, "available": True, "scanned": False, "engine": "yara-x", "matches": [],
                "error": _clean(f"{type(exc).__name__}: a regra ou a análise falhou; nenhum resultado foi confirmado.", 400)}


def scan_yara(path: Path, rulesfile: Path | None = None) -> dict:
    """Real optional YARA-X scan on bounded bytes; includes/network are disabled."""
    try:
        return _yara_data(_read(Path(path)), Path(rulesfile) if rulesfile is not None else None)
    except (OSError, ValueError) as exc:
        return {"ok": False, "available": tool_capabilities()["yara_x"]["available"], "scanned": False,
                "engine": "yara-x", "matches": [], "error": _clean(str(exc))}


def analyze_file(path: Path, *, original_name: str | None = None) -> dict:
    """Inspect authorized bytes only, without extraction, imports or execution."""
    try:
        data = _read(Path(path))
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": _clean(str(exc)), "executed": False}
    strings, truncated = _strings(data)
    entropy = _entropy(data)
    pe = _pe(data)
    elf = _elf(data)
    indicators = []
    if len(data) >= 1024 and entropy >= 7.2:
        indicators.append({"id": "high_entropy", "severity": "info", "confidence": "low",
                           "title": "Entropia elevada: hipótese de compressão, criptografia ou empacotamento.",
                           "validation": "unconfirmed"})
    if pe and any(section["writable_executable"] for section in pe["sections"]):
        indicators.append({"id": "pe_writable_executable", "severity": "medium", "confidence": "medium",
                           "title": "Seção PE gravável e executável: revisar proteções e contexto.",
                           "validation": "unconfirmed"})
    patterns = {"process_api": rb"(?i)(?:CreateRemoteThread|VirtualAllocEx|WriteProcessMemory)",
                "shell_reference": rb"(?i)(?:powershell(?:\.exe)?|cmd\.exe|/bin/(?:sh|bash))",
                "network_reference": rb"(?i)(?:https?://|WinHttpOpen|InternetOpen[AW]?)",
                "persistence_reference": rb"(?i)(?:CurrentVersion\\Run(?:Once)?|schtasks(?:\.exe)?|Start Menu\\Programs\\Startup)"}
    for identifier, pattern in patterns.items():
        count = sum(1 for _ in re.finditer(pattern, data))
        if count:
            indicators.append({"id": identifier, "severity": "info", "confidence": "low", "count": count,
                               "title": f"Referência estática ({identifier}); hipótese dependente do contexto.",
                               "validation": "unconfirmed"})
    name = Path((original_name or Path(path).name).replace("\\", "/")).name
    return {"ok": True, "name": _clean(name, 240), "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "format": _format(data), "entropy": entropy,
            "pe": pe, "elf": elf, "architecture": (pe or elf or {}).get("architecture", "unknown"),
            "strings": strings, "strings_truncated": truncated, "indicators": indicators,
            "yara": _yara_data(data), "capabilities": tool_capabilities(), "executed": False,
            "notice": NOTICE, "limits": {"max_file_bytes": MAX_FILE_BYTES, "max_strings": MAX_STRINGS,
                                           "max_string_chars": MAX_STRING_CHARS}}


def _finding(identifier: str, title: str, severity: str, confidence: str, file: str,
             line: int, impact: str, recommendation: str, evidence: str) -> dict:
    return {"id": identifier, "title": title, "severity": severity, "confidence": confidence,
            "file": _clean(file, 500), "line": max(1, line), "impact": impact,
            "recommendation": recommendation, "evidence": _clean(evidence, 320), "validation": "unconfirmed"}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


class _PythonAudit(ast.NodeVisitor):
    def __init__(self, text: str, file: str):
        self.lines = text.splitlines()
        self.file = file
        self.findings: list[dict] = []
        self.aliases: dict[str, str] = {}
        self.dynamic: set[str] = set()

    def add(self, node: ast.AST, identifier: str, title: str, severity: str,
            impact: str, recommendation: str, confidence: str = "medium") -> None:
        line = getattr(node, "lineno", 1)
        source = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append(_finding(identifier, title, severity, confidence, self.file, line,
                                           impact, recommendation, source))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.aliases[alias.asname or alias.name] = f"{node.module or ''}.{alias.name}".strip(".")

    def canonical(self, node: ast.AST) -> str:
        name = _call_name(node)
        first, separator, rest = name.partition(".")
        return self.aliases.get(first, first) + (separator + rest if separator else "")

    @staticmethod
    def _dynamic_sql(node: ast.AST) -> bool:
        return (isinstance(node, (ast.JoinedStr, ast.BinOp)) or
                isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format")

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and self._dynamic_sql(node.value):
                self.dynamic.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.canonical(node.func)
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            self.add(node, "PY-DYNAMIC-CODE", "Avaliação dinâmica de código", "high",
                     "Entrada não confiável pode tornar-se código executável.",
                     "Evite eval/exec para dados; prefira parser ou operações explicitamente permitidas.")
        if name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads", "shelve.open"}:
            self.add(node, "PY-UNSAFE-DESERIALIZATION", "Desserialização que pode executar código", "high",
                     "Objetos serializados não confiáveis podem executar código durante a leitura.",
                     "Use formatos de dados sem código e valide a origem; não desserialize entradas não confiáveis.")
        if name in {"yaml.load", "yaml.unsafe_load"}:
            loader = next((self.canonical(item.value) for item in node.keywords if item.arg == "Loader"), "")
            if name == "yaml.unsafe_load" or loader not in {"yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader"}:
                self.add(node, "PY-YAML-LOAD", "Carregamento YAML sem SafeLoader comprovado", "high",
                         "Alguns loaders podem construir objetos com efeitos de execução.",
                         "Use yaml.safe_load ou SafeLoader e valide a estrutura de dados.")
        shell = next((item.value for item in node.keywords if item.arg == "shell"), None)
        shell_true = isinstance(shell, ast.Constant) and shell.value is True
        if name in {"os.system", "os.popen"} or (name.startswith("subprocess.") and shell_true):
            self.add(node, "PY-SHELL-COMMAND", "Comando interpretado pelo shell", "high",
                     "Concatenação de entrada não confiável pode causar injeção de comandos.",
                     "Prefira argv fixo com shell=False; valide argumentos e mantenha privilégios mínimos.")
        if name.rsplit(".", 1)[-1] in {"execute", "executemany", "executescript"} and node.args:
            query = node.args[0]
            if self._dynamic_sql(query) or isinstance(query, ast.Name) and query.id in self.dynamic:
                self.add(node, "PY-SQL-CONSTRUCTION", "Consulta SQL construída dinamicamente", "high",
                         "Dados interpolados podem alterar a consulta SQL; origem não é comprovada por esta análise.",
                         "Use parâmetros preparados; selecione identificadores por lista permitida.")
        if name.startswith(("requests.", "httpx.")):
            verify = next((item.value for item in node.keywords if item.arg == "verify"), None)
            if isinstance(verify, ast.Constant) and verify.value is False:
                self.add(node, "PY-TLS-VERIFY", "Verificação TLS desativada", "medium",
                         "Uma conexão remota pode aceitar certificados não confiáveis.",
                         "Ative a validação TLS e configure a autoridade certificadora esperada.", "high")
        self.generic_visit(node)


_REGEX_RULES = [
    ("JS-DYNAMIC-CODE", {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
     r"\b(?:eval\s*\(|new\s+Function\s*\()", "Avaliação dinâmica em JavaScript", "high",
     "Texto variável pode ser executado como código.", "Troque avaliação por parsing e operações explicitamente permitidas."),
    ("JS-CHILD-EXEC", {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
     r"\b(?:exec|execSync)\s*\(", "Execução potencial por shell em JavaScript", "high",
     "A chamada pode interpolar argumentos no shell; confirme a função e a origem dos dados.",
     "Prefira spawn/execFile com argumentos separados e shell desativado."),
    ("WEB-DOM-HTML", {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
     r"(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*=|document\.write\s*\()", "HTML dinâmico no DOM", "medium",
     "Conteúdo não confiável pode resultar em XSS; o fluxo de dados ainda precisa ser verificado.",
     "Use textContent ou sanitização HTML adequada ao contexto."),
    ("PHP-CODE-EVAL", {".php"}, r"\b(?:eval|assert)\s*\(", "Avaliação dinâmica em PHP", "high",
     "Entrada variável pode alterar o comportamento da aplicação; assert depende da versão/configuração.",
     "Evite executar texto como código e valide a origem dos dados."),
    ("PHP-COMMAND", {".php"}, r"\b(?:shell_exec|system|passthru|exec)\s*\(", "Execução de comando em PHP", "high",
     "Parâmetros controláveis podem alcançar um interpretador de comandos.",
     "Remova comandos dinâmicos ou use uma API específica e argumentos rigorosamente validados."),
    ("PHP-DESERIALIZATION", {".php"}, r"\bunserialize\s*\(", "Desserialização PHP", "high",
     "Dados não confiáveis podem construir objetos com métodos de efeito colateral.",
     "Prefira JSON e esquemas de dados; não aceite serialização de objetos não confiáveis."),
    ("CONFIG-DEBUG", {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".py"},
     r"(?i)[\"']?\bdebug[\"']?\s*[:=]\s*(?:true|1)\b", "Modo de depuração habilitado", "low",
     "Debug pode expor detalhes quando usado fora do desenvolvimento; confirme o ambiente.",
     "Desative debug em produção e limite a interface de escuta."),
    ("CONFIG-CORS-WILDCARD", {".json", ".yaml", ".yml", ".toml", ".py", ".js", ".ts"},
     r"(?i)(?:allow_origins|access-control-allow-origin|origin)\s*[\"']?\s*[:=].{0,30}[\"']\*[\"']",
     "Origem CORS curinga", "low", "Uma origem ampla pode ampliar exposição dependendo de credenciais e endpoints.",
     "Restrinja origens e verifique autenticação/credenciais no contexto da API."),
]
_ASSIGNED_LITERAL = re.compile(
    r"(?i)(?:[\"']?\b[\w.-]*(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|token|secret)[\w.-]*[\"']?)"
    r"\s*[:=]\s*([\"'])([^\r\n]{4,200}?)\1")
_TOKEN_SIGNATURE = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{16,}|"
                              r"github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,})\b")


def _text_findings(text: str, file: str, suffix: str) -> tuple[list[dict], str | None]:
    findings: list[dict] = []
    syntax_error = None
    if suffix in {".py", ".pyi"}:
        try:
            tree = ast.parse(text, filename=file)
            auditor = _PythonAudit(text, file)
            auditor.visit(tree)
            findings.extend(auditor.findings)
        except (SyntaxError, RecursionError, ValueError, MemoryError) as exc:
            syntax_error = f"AST não disponível: {type(exc).__name__}"
    is_docker = Path(file).name.casefold() == "dockerfile" or suffix == ".dockerfile"
    docker_has_user = False
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*", ";")):
            continue
        for identifier, suffixes, pattern, title, severity, impact, recommendation in _REGEX_RULES:
            if suffix in suffixes and re.search(pattern, line):
                findings.append(_finding(identifier, title, severity, "low", file, line_number, impact,
                                          recommendation, line))
        literal = _ASSIGNED_LITERAL.search(line)
        if literal and not re.search(r"(?i)(?:\$\{|process\.env|os\.environ|example|placeholder|changeme|redacted|your[_-])", literal.group(2)):
            # Never display the line containing a suspected value, including an unrecognized credential form.
            findings.append(_finding("HARDCODED-CREDENTIAL", "Possível credencial literal no código", "high", "medium",
                                      file, line_number, "Credenciais embutidas podem vazar com o repositório ou artefatos.",
                                      "Confirme se é um valor real, revogue se exposto e use um gerenciador de segredos.",
                                      "Atribuição de credencial literal: [REDACTED]"))
        elif _TOKEN_SIGNATURE.search(line):
            findings.append(_finding("HARDCODED-TOKEN", "Padrão reconhecível de token no código", "high", "medium",
                                      file, line_number, "Um valor com formato de credencial pode ser publicado com o código.",
                                      "Confirme se é real, revogue se exposto e remova do histórico conforme necessário.",
                                      "Padrão de token reconhecível: [REDACTED]"))
        if is_docker:
            if re.match(r"(?i)^USER\s+", stripped):
                docker_has_user = True
                if re.match(r"(?i)^USER\s+(?:root|0)(?:\s|:|$)", stripped):
                    findings.append(_finding("DOCKER-ROOT", "Container configurado como root", "medium", "high", file,
                                              line_number, "O processo terá privilégios de root dentro do container.",
                                              "Use usuário dedicado e privilégios mínimos quando compatível.", line))
            if re.match(r"(?i)^FROM\s+[^\s]+:latest(?:\s|$)", stripped):
                findings.append(_finding("DOCKER-MUTABLE-TAG", "Imagem base usa tag latest", "low", "high", file,
                                          line_number, "A mesma configuração pode resolver para conteúdo diferente futuramente.",
                                          "Fixe versão e, quando viável, digest verificado da imagem base.", line))
        if len(findings) >= MAX_FINDINGS:
            return findings[:MAX_FINDINGS], syntax_error
    if is_docker and not docker_has_user:
        findings.append(_finding("DOCKER-USER-UNSPECIFIED", "Usuário de container não definido neste Dockerfile", "info", "low",
                                  file, 1, "O usuário efetivo é herdado da imagem base; não foi determinado pela análise.",
                                  "Verifique o usuário da imagem base e adicione USER quando necessário.", "Nenhuma instrução USER encontrada."))
    return findings[:MAX_FINDINGS], syntax_error


def _manifest(text: str, name: str) -> dict:
    """Bounded direct-dependency inventory. Never invoke a package manager."""
    packages: list[dict] = []
    note = "Inventário estático; versões declaradas não são prova da versão instalada. CVEs não consultadas."
    item = {"file": _clean(name), "packages": packages, "vulnerabilities_checked": False,
            "notice": note, "truncated": False}

    def add(package: Any, version: Any, scope: str = "declared") -> None:
        if len(packages) < 120 and isinstance(package, str) and isinstance(version, (str, int, float)):
            # URLs and local paths are not persisted as version evidence.
            safe_version = str(version)
            if re.search(r"(?:https?://|git\+|file:|[/\\])", safe_version):
                safe_version = "[source/location omitted]"
            packages.append({"name": _clean(package, 180), "version": _clean(safe_version, 120), "scope": scope})
        elif len(packages) >= 120:
            item["truncated"] = True
    try:
        base = Path(name).name
        if base in {"package.json", "composer.json"}:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("Expected object")
            groups = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies") if base == "package.json" else ("require", "require-dev")
            for group in groups:
                values = data.get(group, {})
                if isinstance(values, dict):
                    for package, version in values.items():
                        add(package, version, group)
        elif base in {"pyproject.toml", "Cargo.toml", "Cargo.lock", "poetry.lock", "uv.lock"}:
            data = tomllib.loads(text)
            if base == "pyproject.toml":
                project = data.get("project", {})
                for dependency in project.get("dependencies", []) if isinstance(project, dict) else []:
                    if isinstance(dependency, str):
                        match = re.match(r"([A-Za-z0-9_.-]+)(.*)", dependency)
                        if match:
                            add(match[1], match[2] or "unversioned", "project.dependencies")
                poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                if isinstance(poetry, dict):
                    for package, version in poetry.items():
                        if isinstance(version, str):
                            add(package, version, "tool.poetry.dependencies")
            elif base == "Cargo.toml":
                for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                    values = data.get(group, {})
                    if isinstance(values, dict):
                        for package, version in values.items():
                            add(package, version.get("version", "unversioned") if isinstance(version, dict) else version, group)
            else:
                values = data.get("package", [])
                if isinstance(values, list):
                    for package in values[:500]:
                        if isinstance(package, dict):
                            add(package.get("name"), package.get("version", "unversioned"), "lock")
        elif base == "requirements.txt":
            for line in text.splitlines():
                match = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]{1,80}\])?\s*((?:===|==|~=|>=|<=|>|<|!=)[^#;]{1,100})?\s*(?:;[^#]*)?(?:#.*)?$", line)
                if match:
                    add(match[1], (match[2] or "unversioned").strip())
        elif base == "go.mod":
            inside = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped == "require (":
                    inside = True
                elif stripped == ")":
                    inside = False
                else:
                    match = re.match(r"(?:require\s+)?([\w./-]+)\s+(v[^\s]+)", stripped)
                    if match and (inside or stripped.startswith("require ")):
                        add(match[1], match[2])
        else:
            item["notice"] = "Manifesto identificado; formato lock não interpretado. Nenhuma consulta de vulnerabilidade."
    except (ValueError, TypeError, AttributeError, RecursionError) as exc:
        item["parse_error"] = type(exc).__name__
    return item


def audit_project(path: Path) -> dict:
    """Walk a bounded authorized directory; parse source as data, never import it."""
    try:
        root, _ = _checked(Path(path), directory=True)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": _clean(str(exc)), "executed": False}
    started = time.monotonic()
    files: list[dict] = []
    findings: list[dict] = []
    skipped: list[dict] = []
    manifests: list[dict] = []
    pending = [root]
    total = entries = skipped_count = 0
    reasons: set[str] = set()

    def skip(file: str, reason: str) -> None:
        nonlocal skipped_count
        skipped_count += 1
        if len(skipped) < 100:
            skipped.append({"file": _clean(file, 400), "reason": reason})

    while pending:
        if time.monotonic() - started > SCAN_SECONDS:
            reasons.add("time_budget")
            break
        directory = pending.pop()
        try:
            _checked(directory, directory=True)
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries += 1
                    if entries > MAX_ENTRIES:
                        reasons.add("entry_budget")
                        break
                    if time.monotonic() - started > SCAN_SECONDS:
                        reasons.add("time_budget")
                        break
                    target = Path(entry.path)
                    relative = target.relative_to(root).as_posix()
                    if _sensitive(entry.name):
                        skip(relative, "sensitive_file_or_directory")
                        continue
                    try:
                        # Path.lstat rather than DirEntry.stat: Windows may omit nlink/ino there.
                        info = target.lstat()
                        if _linked(info):
                            skip(relative, "link_or_hardlink")
                        elif stat.S_ISDIR(info.st_mode):
                            if entry.name.casefold() in SKIP_DIRS:
                                skip(relative, "excluded_directory")
                            else:
                                pending.append(target)
                        elif stat.S_ISREG(info.st_mode):
                            suffix = target.suffix.casefold()
                            is_manifest = entry.name in MANIFEST_NAMES
                            if suffix not in SOURCE_SUFFIXES and entry.name.casefold() != "dockerfile" and not is_manifest:
                                continue
                            if len(files) >= MAX_PROJECT_FILES:
                                reasons.add("file_budget")
                                break
                            if info.st_size > MAX_SOURCE_BYTES:
                                skip(relative, "source_file_size_limit")
                                continue
                            if total + info.st_size > MAX_PROJECT_BYTES:
                                reasons.add("byte_budget")
                                break
                            data = _read(target, min(MAX_SOURCE_BYTES, MAX_PROJECT_BYTES - total))
                            total += len(data)
                            if b"\0" in data:
                                skip(relative, "binary_data_not_parsed")
                                continue
                            try:
                                text = data.decode("utf-8-sig")
                            except UnicodeDecodeError:
                                skip(relative, "unsupported_encoding")
                                continue
                            file_report = {"file": _clean(relative, 400), "sha256": hashlib.sha256(data).hexdigest(),
                                           "size_bytes": len(data)}
                            if is_manifest:
                                manifests.append(_manifest(text, relative))
                            file_findings, parse_error = _text_findings(text, relative, suffix)
                            if parse_error:
                                file_report["parse_error"] = parse_error
                            available = MAX_FINDINGS - len(findings)
                            findings.extend(file_findings[:available])
                            if len(file_findings) > available or len(findings) >= MAX_FINDINGS:
                                reasons.add("finding_budget")
                            files.append(file_report)
                    except (OSError, ValueError) as exc:
                        skip(relative, "read_denied_or_changed: " + _clean(type(exc).__name__, 60))
        except (OSError, ValueError):
            skip(directory.relative_to(root).as_posix(), "directory_denied_or_changed")
        if reasons & {"entry_budget", "file_budget", "byte_budget", "time_budget"}:
            break
    # Stable severity-first presentation, not a risk score or proof of exploitability.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order[item["severity"]], item["file"], item["line"], item["id"]))
    return {"ok": True, "engine": "NEXUS CodeAuditor AST/heuristics", "executed": False,
            "files_scanned": len(files), "bytes_read": total, "entries_seen": entries,
            "files": files, "findings": findings, "dependency_manifests": manifests, "skipped": skipped,
            "skipped_count": skipped_count, "skipped_truncated": skipped_count > len(skipped),
            "truncated": bool(reasons), "limit_reasons": sorted(reasons), "capabilities": tool_capabilities(),
            "notice": NOTICE + " O scanner não faz análise de fluxo completa e pode ter falsos positivos/negativos.",
            "limits": {"max_files": MAX_PROJECT_FILES, "max_source_bytes": MAX_SOURCE_BYTES,
                       "max_total_bytes": MAX_PROJECT_BYTES, "max_entries": MAX_ENTRIES,
                       "max_findings": MAX_FINDINGS, "max_seconds": SCAN_SECONDS}}
