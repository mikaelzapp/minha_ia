"""Optional, reviewed scanner adapters. No download, shell or implicit grant.

The caller owns human approval and must bind it to ``preview`` and current scope
revision. Findings and diagnostics are untrusted data, never agent instructions.
"""
from __future__ import annotations

import copy
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

import psutil

from .common import SecurityError, redact_secrets, safe_file, sha256_file, utcnow
from . import network
from ..tools import Tools


ENGINES = frozenset({"nuclei", "zap", "nmap_service"})
LEVELS = frozenset({"PASSIVE", "SAFE ACTIVE", "STAGING FULL"})
MAX_OUTPUT = 2 * 1024 * 1024
MAX_RESULTS = 200
TEMPLATE_VERSION = "nexus-reviewed-http-v1"
MAX_OPENAPI_BYTES = 128 * 1024
NOTICE = "Nenhum achado nesta cobertura não constitui garantia de segurança."
_RUN_LOCK = threading.Lock()


class _ScopedProxy:
    """Per-run HTTP guard for exact-origin lab traffic; not an OS sandbox.

    HTTPS is intentionally unavailable: blind CONNECT cannot enforce individual
    requests, methods or budgets. No local CA is installed to work around this.
    """
    def __init__(self, destination, *, rate, maximum, check, cancel):
        if destination["scheme"] != "http":
            raise SecurityError("Scanners externos exigem laboratório HTTP nesta versão; HTTPS requer egress por requisição validado.", "isolation_requirement")
        self.destination, self.rate, self.maximum = destination, rate, maximum
        self.check, self.cancel = check, cancel
        self.closing = threading.Event()
        self.lock = threading.Lock()
        self.requests = self.denied = self.failures = 0
        self.next_request = 0.0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def do_CONNECT(self):
                owner.denied += 1
                self.send_error(403, "CONNECT not permitted")

            def do_GET(self):
                owner._handle(self)

            do_HEAD = do_GET
            do_OPTIONS = do_GET

            def do_POST(self):
                owner.denied += 1
                self.send_error(403, "Method not permitted")

            do_PUT = do_POST
            do_DELETE = do_POST
            do_PATCH = do_POST

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            request_queue_size = 2

            def get_request(self):
                handle, address = super().get_request()
                handle.settimeout(3)
                return handle, address

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def _handle(self, handler):
        connection = None
        try:
            self.check()
            target = urlsplit(handler.path)
            expected = self.destination
            decoded_path = target.path
            for _ in range(3):
                decoded_path = unquote(decoded_path)
            if (self.cancel.is_set() or self.closing.is_set() or target.scheme != "http" or target.hostname != expected["host"] or
                    (target.port or 80) != expected["port"] or target.username is not None or target.password is not None or
                    len(handler.path) > 4096 or len(str(handler.headers)) > 16384 or target.fragment or
                    "\\" in decoded_path or any(ord(char) < 32 for char in decoded_path) or
                    any(part in {".", ".."} for part in decoded_path.split("/")) or
                    not target.path.startswith(expected["path"].rstrip("/") + "/") and target.path != expected["path"] or
                    handler.headers.get("Transfer-Encoding") or handler.headers.get("Content-Length") not in {None, "0"}):
                raise SecurityError("Proxy recusou requisição fora do efeito aprovado.", "scope_denied")
            # Sequential gate includes the bounded target exchange, so scanners
            # cannot raise the effective concurrency with their own workers.
            with self.lock:
                if self.cancel.is_set() or self.closing.is_set() or self.requests >= self.maximum or self.failures >= 3:
                    raise SecurityError("Orçamento ou integridade da tarefa esgotados.", "request_budget")
                wait = self.next_request - time.monotonic()
                if wait > 0 and self.cancel.wait(wait):
                    raise SecurityError("Tarefa interrompida.", "cancelled")
                self.check()
                self.requests += 1
                self.next_request = time.monotonic() + 1 / self.rate
                connection = http.client.HTTPConnection(expected["addresses"][0], expected["port"], timeout=3)
                headers = {"Host": expected["authority"], "User-Agent": "NEXUS-ReviewedScanner/2.0", "Connection": "close"}
                # Only harmless content negotiation is forwarded. No scanner
                # environment, Authorization header or client cookies escape.
                if handler.headers.get("Accept"):
                    headers["Accept"] = handler.headers["Accept"][:200]
                path = target.path or "/"
                if target.query:
                    path += "?" + target.query
                connection.request(handler.command, path, headers=headers)
                response = connection.getresponse()
                body = response.read(262145)
                if len(body) > 262144 or len(str(response.headers)) > 16384:
                    raise SecurityError("Resposta excedeu orçamento do proxy.", "response_limit")
                handler.send_response(response.status)
                for name, value in response.getheaders():
                    # Redirects are never followed, including redirects to
                    # another port on the same host. Removing Location is
                    # disclosed as a coverage limit, not hidden from reports.
                    if name.lower() not in {"location", "connection", "transfer-encoding", "content-length", "proxy-authenticate"}:
                        handler.send_header(name, value)
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                if handler.command != "HEAD":
                    handler.wfile.write(body)
        except Exception:
            self.denied += 1
            self.failures += 1
            if self.failures >= 3:
                self.cancel.set()
            try:
                handler.send_error(403, "NEXUS scope or resource budget denied")
            except OSError:
                pass
        finally:
            if connection:
                connection.close()

    def __exit__(self, *args):
        self.closing.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)


def _template(name, title, severity, path, matcher):
    return {"id": name, "info": {"name": title, "author": "NEXUS", "severity": severity,
            "description": "Verificação HTTP revisada e limitada; confirmar o contexto do resultado."},
            "http": [{"method": "GET", "path": ["{{BaseURL}}" + path], "redirects": False,
                      "matchers-condition": "and", "matchers": matcher}]}


# Deliberately small local pack. No arbitrary template, workflow, code, DNS,
# browser, raw request, OAST, fuzzing, credential or external URL execution.
REVIEWED_TEMPLATES = {
    "nexus-http-baseline": _template("nexus-http-baseline", "HTTP responde no alvo autorizado", "info", "",
        [{"type": "status", "status": [200, 204, 301, 302, 401, 403]}]),
    "nexus-exposed-openapi": _template("nexus-exposed-openapi", "Documento OpenAPI publicamente legível", "info", "/openapi.json",
        [{"type": "status", "status": [200]}, {"type": "word", "part": "body", "words": ['"openapi"', '"swagger"'], "condition": "or"}]),
    "nexus-lab-synthetic-exposure": _template("nexus-lab-synthetic-exposure", "Marcador fictício de exposição do laboratório", "medium", "/nexus-lab-marker",
        [{"type": "status", "status": [200]}, {"type": "word", "part": "body", "words": ["NEXUS_SYNTHETIC_EXPOSURE_V1"]}]),
}


def _canonical(data):
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _bounded_int(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise SecurityError(f"{name}: informe inteiro entre {low} e {high}.", "invalid_scanner_input")
    return value


def _safe_directory(path):
    path = Path(path).absolute()
    if any(item.is_symlink() or item.exists() and Tools._is_link(item) for item in (path, *path.parents)):
        raise SecurityError("Diretório do scanner contém link ou junction.", "unsafe_scanner_path")
    path.mkdir(parents=True, exist_ok=True)
    if any(Tools._is_link(item) for item in (path, *path.parents)) or not path.is_dir() or path.resolve() != path:
        raise SecurityError("Diretório de scanner inválido.", "unsafe_scanner_path")
    return path


def _environment(home):
    # Do not inherit API keys, proxy credentials, browser profiles, JAVA_TOOL_OPTIONS
    # or any model-controlled executable resolution.
    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "COMSPEC", "SYSTEMDRIVE") if key in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "appdata"),
               LOCALAPPDATA=str(home / "localappdata"), TMP=str(home), TEMP=str(home),
               XDG_CONFIG_HOME=str(home / "config"), XDG_CACHE_HOME=str(home / "cache"),
               DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD="true",
               DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD="true",
               DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD="true",
               DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD="true",
               DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD="true",
               PDCP_DISABLE_TELEMETRY="true", NO_COLOR="1")
    return env


def _check_scope(scope, loader):
    current = loader() if loader else scope
    try:
        network.ScopePolicy(current)
    except ValueError as exc:
        raise SecurityError("Escopo inválido, desativado ou revogado durante a tarefa.", "scope_revoked") from exc
    if current.get("id") != scope.get("id") or current.get("revision") != scope.get("revision"):
        raise SecurityError("O escopo mudou durante a tarefa; execução interrompida.", "scope_revoked")
    return current


def run_bounded(argv, *, cwd, env, timeout=60, max_output=MAX_OUTPUT,
                cancel_event=None, scope_check=None, emit=None, memory_limit=768 * 1024 * 1024,
                output_files=()):
    """Capture bounded files, enforce time/RSS/cancel and reap process trees.

    RSS is observed every 50 ms, not an OS hard limit or a VM. No arbitrary child
    sample is started. Events contain counters only, never raw scanner output.
    """
    started = time.monotonic()
    cancel_event = cancel_event or threading.Event()
    if cancel_event.is_set():
        return {"ok": False, "code": "cancelled", "exit_code": None, "stdout": b"", "stderr": b"", "duration_seconds": 0}
    if scope_check:
        scope_check()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, cwd=cwd, env=env, shell=False, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        code, peak, next_event = "ok", 0, started
        try:
            while process.poll() is None:
                now = time.monotonic()
                sizes = [os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size]
                sizes.extend(Path(p).stat().st_size for p in output_files if Path(p).is_file())
                if cancel_event.is_set():
                    code = "cancelled"
                    break
                if now - started >= timeout:
                    code = "tool_timeout"
                    break
                if sum(sizes) > max_output:
                    code = "output_limit"
                    break
                if scope_check:
                    scope_check()
                try:
                    proc = psutil.Process(process.pid)
                    rss = proc.memory_info().rss
                    for child in proc.children(recursive=True):
                        try:
                            rss += child.memory_info().rss
                        except psutil.Error:
                            pass
                    peak = max(peak, rss)
                    if rss > memory_limit:
                        code = "memory_limit"
                        break
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    code = "resource_monitor_unavailable"
                    break
                if emit and now >= next_event:
                    emit({"type": "progress", "elapsed_seconds": round(now - started, 2),
                          "output_bytes": sum(sizes), "rss_bytes": peak})
                    next_event = now + 1
                time.sleep(0.05)
        finally:
            # Also handles exceptions from scope loader or event consumers.
            if process.poll() is None:
                Tools._kill_tree(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                Tools._kill_tree(process)
                process.wait(timeout=5)
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(max_output + 1), err.read(max_output + 1)
        total = len(stdout) + len(stderr)
        total += sum(Path(p).stat().st_size for p in output_files if Path(p).is_file())
        if total > max_output:
            code = "output_limit"
        return {"ok": code == "ok" and process.returncode in {0, 2}, "code": code,
                "exit_code": process.returncode, "stdout": stdout[:max_output], "stderr": stderr[:max_output],
                "duration_seconds": round(time.monotonic() - started, 3), "peak_rss_bytes": peak,
                "resource_enforcement": "observed_rss_and_process_termination"}


def _clean_url(value):
    try:
        p = urlsplit(str(value))
        if p.scheme not in {"http", "https"} or not p.hostname:
            return "[URL omitida]"
        host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
        if p.port:
            host += f":{p.port}"
        # Never retain scanner-controlled query strings, credentials or fragments.
        return redact_secrets(f"{p.scheme}://{host}{p.path}")[:2048]
    except ValueError:
        return "[URL inválida omitida]"


def _verify_origin(endpoint, target):
    if target is None:
        return
    value, expected = urlsplit(endpoint), urlsplit(target)
    if (value.scheme, value.hostname, value.port or 80) != (expected.scheme, expected.hostname, expected.port or 80):
        raise SecurityError("Scanner retornou endpoint fora da origem aprovada.", "invalid_tool_output")


def _zap_requests(args):
    """Pure local discovery from approved literal paths; never import/fetch a URL.

    The OpenAPI document is inspected as data. Schemas, auth examples and local
    references are not resolved, expanded, executed or copied into the AF plan.
    """
    target = network._url(args["target"])
    requested = [{"url": target["url"], "method": "GET"}]
    seen = {(target["url"], "GET")}
    endpoints = args.get("endpoints", [])
    if not isinstance(endpoints, list) or len(endpoints) > 10:
        raise SecurityError("endpoints deve conter até dez caminhos literais relativos à origem.", "invalid_zap_discovery")
    coverage = {"method": "explicit_requestor_only", "manual_paths": [], "openapi_paths": [],
                "openapi_skipped": [], "remote_definitions_fetched": False, "spider_executed": False}

    def literal_url(path):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or len(path) > 2048:
            raise SecurityError("Endpoint deve ser caminho literal iniciado por /, sem domínio.", "invalid_zap_discovery")
        if "{" in path or "}" in path or "?" in path or "#" in path:
            raise SecurityError("Endpoint exige caminho literal sem parâmetros, consulta ou fragmento.", "invalid_zap_discovery")
        destination = network._url(target["scheme"] + "://" + target["authority"] + path)
        if destination["path"] != target["path"] and not destination["path"].startswith(target["path"].rstrip("/") + "/"):
            raise SecurityError("Endpoint está fora do caminho base aprovado.", "invalid_zap_discovery")
        return destination["url"]

    def add(path, method, source):
        url = literal_url(path)
        if (url, method) not in seen:
            requested.append({"url": url, "method": method})
            seen.add((url, method))
        coverage[source].append({"path": path, "method": method})

    for path in endpoints:
        add(path, "GET", "manual_paths")

    definition = args.get("openapi")
    if definition is not None:
        if not isinstance(definition, dict):
            raise SecurityError("openapi deve ser objeto JSON local já analisado, nunca URL ou arquivo remoto.", "invalid_openapi")
        version = definition.get("openapi", definition.get("swagger"))
        if not isinstance(version, str) or not (version.startswith("3.") or version == "2.0"):
            raise SecurityError("Forneça especificação OpenAPI 3.x ou Swagger 2.0.", "invalid_openapi")
        paths = definition.get("paths")
        if not isinstance(paths, dict) or len(paths) > 1000:
            raise SecurityError("OpenAPI exige paths como objeto limitado a mil entradas.", "invalid_openapi")
        stack = [(definition, 0)]
        visited, text_size = 0, 0
        while stack:
            value, depth = stack.pop()
            visited += 1
            if visited > 10000 or depth > 32:
                raise SecurityError("OpenAPI excede limites de complexidade.", "invalid_openapi")
            if isinstance(value, dict):
                if len(value) + len(stack) + visited > 10000:
                    raise SecurityError("OpenAPI excede limites de complexidade.", "invalid_openapi")
                text_size += sum(len(str(key)) for key in value)
                if any(key in value for key in ("servers", "callbacks", "webhooks", "host", "basePath", "schemes")):
                    raise SecurityError("OpenAPI não pode definir servidores, callbacks, webhooks ou autoridade alternativa.", "openapi_external_effect")
                reference = value.get("$ref")
                if reference is not None and (not isinstance(reference, str) or not reference.startswith("#/") or len(reference) > 2048):
                    raise SecurityError("Referência OpenAPI externa não é permitida.", "openapi_external_ref")
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                if len(value) + len(stack) + visited > 10000:
                    raise SecurityError("OpenAPI excede limites de complexidade.", "invalid_openapi")
                stack.extend((item, depth + 1) for item in value)
            elif isinstance(value, str):
                text_size += len(value)
            if text_size > MAX_OPENAPI_BYTES:
                raise SecurityError("OpenAPI excede o limite de 128 KiB.", "openapi_size")
        try:
            raw = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        except (ValueError, TypeError, RecursionError) as exc:
            raise SecurityError("OpenAPI deve ser JSON finito, sem referências circulares de objetos.", "invalid_openapi") from exc
        if len(raw) > MAX_OPENAPI_BYTES:
            raise SecurityError("OpenAPI excede o limite de 128 KiB.", "openapi_size")
        discovered = 0
        for path, item in paths.items():
            if not isinstance(path, str) or not isinstance(item, dict):
                raise SecurityError("Cada path OpenAPI precisa ser texto associado a um objeto.", "invalid_openapi")
            if not path.startswith("/") or path.startswith("//") or len(path) > 2048:
                raise SecurityError("Path OpenAPI deve ser caminho relativo à origem, iniciado por /.", "invalid_openapi")
            if "{" in path or "}" in path:
                if len(coverage["openapi_skipped"]) < 30:
                    coverage["openapi_skipped"].append({"path": path[:200], "reason": "path_parameters_require_explicit_synthetic_values"})
                continue
            # Validate even non-GET paths: no malicious authority is accepted as
            # an inert-looking POST declaration that could later be enabled.
            literal_url(path)
            for method, operation in item.items():
                if not isinstance(method, str):
                    raise SecurityError("Nomes de operações OpenAPI devem ser texto.", "invalid_openapi")
                if method.lower() in {"get", "head"}:
                    if not isinstance(operation, dict):
                        raise SecurityError("Operação OpenAPI deve ser objeto JSON.", "invalid_openapi")
                    if discovered >= 10:
                        if len(coverage["openapi_skipped"]) < 30:
                            coverage["openapi_skipped"].append({"path": path[:200], "method": method[:12], "reason": "ten_operations_budget"})
                        continue
                    add(path, method.upper(), "openapi_paths")
                    discovered += 1
                elif method.lower() in {"post", "put", "patch", "delete", "options", "trace", "connect"}:
                    if len(coverage["openapi_skipped"]) < 30:
                        coverage["openapi_skipped"].append({"path": path[:200], "method": method[:12], "reason": "only_get_head_discovery"})
        coverage.update(openapi_sha256=hashlib.sha256(raw).hexdigest(), openapi_bytes=len(raw), openapi_version=version)
    coverage["requests_planned"] = len(requested)
    coverage["limitation"] = "Descoberta limitada a caminhos explícitos e GET/HEAD literais; sem crawl, resolução de schemas, substituição de parâmetros ou autenticação."
    return requested, coverage


def parse_nuclei(data, selected, target=None):
    if len(data) > MAX_OUTPUT:
        raise SecurityError("JSONL Nuclei excede o limite.", "output_limit")
    rows = []
    for line in data.decode("utf-8-sig").splitlines():
        if not line.strip():
            continue
        if len(rows) >= MAX_RESULTS or len(line) > 64 * 1024:
            raise SecurityError("Quantidade ou tamanho de achados excedeu o limite.", "output_limit")
        item = json.loads(line)
        if not isinstance(item, dict) or item.get("template-id") not in selected:
            raise SecurityError("Saída menciona template não revisado para esta tarefa.", "invalid_tool_output")
        template = REVIEWED_TEMPLATES[item["template-id"]]
        endpoint = _clean_url(item.get("matched-at", item.get("host", "")))
        _verify_origin(endpoint, target)
        rows.append({"title": template["info"]["name"], "severity": template["info"]["severity"],
                     "confidence": "medium", "confirmed": False, "status": "scanner_indication",
                     "template_id": item["template-id"], "source": "nuclei",
                     "endpoint": endpoint,
                     "evidence": {"matcher": str(item.get("matcher-name", ""))[:200],
                                  "timestamp": str(item.get("timestamp", ""))[:80],
                                  "raw_request_response_retained": False},
                     "references": [], "recommendation": "Validar contexto e restringir exposição quando não intencional."})
    return redact_secrets(rows)


def parse_zap(data, target=None):
    if len(data) > MAX_OUTPUT:
        raise SecurityError("Relatório ZAP excede o limite.", "output_limit")
    doc = json.loads(data.decode("utf-8-sig"))
    if not isinstance(doc, dict) or not isinstance(doc.get("site"), list):
        raise SecurityError("Relatório ZAP não possui sites estruturados.", "invalid_tool_output")
    rows = []
    for site in doc["site"]:
        if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
            raise SecurityError("Formato de alertas ZAP inválido.", "invalid_tool_output")
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict) or len(rows) >= MAX_RESULTS:
                raise SecurityError("Formato ou quantidade de alertas ZAP inválido.", "output_limit")
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                raise SecurityError("Formato das ocorrências ZAP inválido.", "invalid_tool_output")
            # Raw evidence/otherinfo/attack can contain whole customer data or
            # tokens. Keep only endpoint and parameter; no request bodies/cookies.
            evidence = [{"endpoint": _clean_url(x.get("uri", "")), "method": str(x.get("method", ""))[:12],
                         "parameter": redact_secrets(str(x.get("param", ""))[:100])}
                        for x in instances[:20] if isinstance(x, dict)]
            for instance in evidence:
                _verify_origin(instance["endpoint"], target)
            risk = str(alert.get("riskcode", "0"))
            plugin = str(alert.get("pluginid", alert.get("alertRef", "")))[:30]
            rows.append({"title": redact_secrets(str(alert.get("name", alert.get("alert", "Alerta ZAP")))[:300]),
                         "severity": {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(risk, "info"),
                         "confidence": {"0": "low", "1": "low", "2": "medium", "3": "high", "4": "high"}.get(str(alert.get("confidence", "1")), "low"),
                         "confirmed": False, "status": "scanner_indication", "source": "zap", "rule_id": plugin,
                         "cwe": str(alert.get("cweid", ""))[:30], "endpoint": evidence[0]["endpoint"] if evidence else _clean_url(site.get("@name", "")),
                         "evidence": {"instances": evidence, "total_instances": len(instances), "raw_messages_retained": False},
                         "recommendation": redact_secrets(str(alert.get("solution", "Validar e corrigir conforme contexto."))[:2000]),
                         "references": ["https://www.zaproxy.org/docs/alerts/" + plugin.split("-")[0] + "/"] if re.fullmatch(r"[0-9]+(?:-[0-9]+)?", plugin) else []})
    return rows


def parse_nmap(data, ports, address, service_detection):
    if len(data) > MAX_OUTPUT:
        raise SecurityError("XML Nmap excede o limite.", "output_limit")
    text = data.decode("utf-8-sig")
    if "\x00" in text:
        raise SecurityError("XML Nmap contém codificação ambígua.", "invalid_tool_output")
    text = re.sub(r'<!DOCTYPE nmaprun(?: SYSTEM [\'"]nmap\.dtd[\'"])?\s*>', "", text)
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise SecurityError("DTD ou entidade não permitida.", "invalid_tool_output")
    root = ET.fromstring(text)
    if root.tag != "nmaprun":
        raise SecurityError("Documento não é XML Nmap.", "invalid_tool_output")
    rows = []
    for host in root.findall("./host")[:2]:
        addresses = [x.get("addr") for x in host.findall("address") if x.get("addrtype") in {"ipv4", "ipv6"}]
        if addresses and addresses != [address]:
            raise SecurityError("Saída Nmap contém ativo diferente do alvo aprovado.", "invalid_tool_output")
        for item in host.findall("./ports/port"):
            port = int(item.get("portid", "0"))
            if port not in ports or item.get("protocol") != "tcp":
                continue
            state, service = item.find("state"), item.find("service")
            proven = bool(service_detection and service is not None and service.get("method") == "probed")
            rows.append({"host": address, "port": port, "protocol": "tcp",
                         "state": state.get("state", "unknown") if state is not None else "unknown",
                         "service": service.get("name") if proven else None,
                         "version": " ".join(filter(None, [service.get("product"), service.get("version"), service.get("extrainfo")]))[:400] if proven else None,
                         "service_hint": service.get("name") if service is not None and not proven else None,
                         "service_identification": "probe" if proven else "port_hint_only",
                         "possible_risks": ["Acesso administrativo ou de banco de dados pode exigir restrição de rede."] if port in {22, 23, 3389, 5432, 3306, 6379, 27017, 9200} else [],
                         "recommendation": "Verificar se a exposição é intencional e limitar origem de acesso.",
                         "evidence": {"reason": state.get("reason") if state is not None else None,
                                      "service_method": service.get("method") if service is not None else None},
                         "notice": "Porta aberta ou número de porta não confirma serviço nem vulnerabilidade."})
    if len(rows) > len(ports):
        raise SecurityError("XML excede a cobertura aprovada.", "invalid_tool_output")
    returned = {row["port"] for row in rows}
    remaining = [port for port in ports if port not in returned]
    summaries = root.findall("./host/ports/extraports")
    summary = summaries[0] if len(summaries) == 1 else None
    summarized = bool(summary is not None and summary.get("count") == str(len(remaining)) and
                      summary.get("state") in {"closed", "filtered", "open|filtered"})
    for port in remaining:
        rows.append({"host": address, "port": port, "protocol": "tcp",
                     "state": summary.get("state") if summarized else "not_reported",
                     "service": None, "version": None, "service_hint": None, "service_identification": "not_probed",
                     "possible_risks": [], "recommendation": "Repetir inspeção limitada se a cobertura for inconclusiva.",
                     "evidence": {"source": "nmap_extraports_complement" if summarized else "absent_from_xml",
                                  "reason": summary.find("extrareasons").get("reason") if summarized and summary.find("extrareasons") is not None else None},
                     "notice": "Ausência de resposta ou de linha no XML não equivale a porta fechada nem garantia de segurança."})
    return redact_secrets(rows)


class ScannerAdapters:
    def __init__(self, data_dir, config=None):
        self.root = Path(data_dir).absolute() / "security" / "scanners"
        if config is not None and (not isinstance(config, dict) or any(key not in ENGINES or not isinstance(value, dict) for key, value in config.items())):
            raise SecurityError("Configuração de scanners deve mapear motores conhecidos para objetos.", "invalid_scanner_configuration")
        self.config = copy.deepcopy(config or {})

    def inventory(self):
        rows = []
        names = {"nuclei": ("nuclei", "nuclei.exe"), "zap": ("zap.bat", "zap.sh", "ZAP.exe"),
                 "nmap_service": ("nmap", "nmap.exe")}
        for engine, candidates in names.items():
            config = self.config.get(engine, {})
            found = config.get("jar" if engine == "zap" else "path") or next((p for n in candidates if (p := shutil.which(n))), None)
            valid, reason = False, "Não configurado; descoberta no PATH não autoriza execução."
            try:
                self._binary(engine)
                valid, reason = True, "Bytes locais aprovados; versão e contrato são verificados antes da execução."
            except (ValueError, OSError) as exc:
                reason = str(exc)
            rows.append({"id": engine, "available": bool(found and Path(found).is_file()), "configured": valid,
                         "path": str(found) if found else None, "version": None, "version_verified": False,
                         "executed": False, "code": "configured_unverified_version" if valid else "unavailable_or_unapproved",
                         "note": reason, "official_url": {"nuclei": "https://github.com/projectdiscovery/nuclei/releases",
                         "zap": "https://www.zaproxy.org/download/", "nmap_service": "https://nmap.org/download.html"}[engine]})
        return {"ok": True, "tools": rows, "templates": self.templates(), "dynamic_execution": False,
                "limitations": ["Nenhuma ferramenta é instalada ou executada durante a descoberta.",
                                "Não há VM, isolamento do Windows ou autenticação de assinatura implícitos."]}

    def templates(self):
        return [{"id": key, "version": TEMPLATE_VERSION, "sha256": hashlib.sha256(_canonical(value)).hexdigest(),
                 "name": value["info"]["name"], "severity": value["info"]["severity"], "reviewed": True,
                 "protocol": "HTTP GET", "requests": 1, "cve_coverage": False} for key, value in REVIEWED_TEMPLATES.items()]

    def _binary(self, engine):
        value = self.config.get(engine, {})
        if not isinstance(value, dict) or value.get("approved") is not True:
            raise SecurityError("Ferramenta ausente ou caminho/hash ainda não aprovado pelo usuário.", "tool_unavailable")
        field = "jar" if engine == "zap" else "path"
        raw = value.get(field)
        if not isinstance(raw, str) or not Path(raw).is_absolute():
            raise SecurityError("Configure caminho absoluto da ferramenta.", "invalid_scanner_configuration")
        path = safe_file(raw, maximum=300 * 1024 * 1024)
        digest = value.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or sha256_file(path) != digest:
            raise SecurityError("Bytes da ferramenta divergem do hash aprovado; revise a configuração.", "scanner_integrity")
        if engine == "zap":
            if path.suffix.lower() != ".jar":
                raise SecurityError("ZAP requer o JAR oficial e Java explícito; launchers de shell não são aceitos.", "invalid_scanner_configuration")
            java = value.get("java")
            if not isinstance(java, str) or not Path(java).is_absolute():
                raise SecurityError("Configure caminho absoluto de Java 17 ou superior.", "tool_unavailable")
            java_path = safe_file(java, maximum=100 * 1024 * 1024)
            if sha256_file(java_path) != value.get("java_sha256"):
                raise SecurityError("Java diverge do hash aprovado.", "scanner_integrity")
            return path, java_path
        if os.name == "nt" and path.suffix.lower() != ".exe":
            raise SecurityError("Ferramenta requer executável nativo .exe, sem .bat/.cmd.", "invalid_scanner_configuration")
        return path, None

    def preview(self, engine, scope, args):
        if engine not in ENGINES or not isinstance(args, dict):
            raise SecurityError("Scanner ou argumentos desconhecidos.", "invalid_scanner_input")
        allowed = {"target", "level", "ports", "service_detection", "expanded_ports_approved", "templates", "duration_seconds", "rate_limit", "endpoints", "openapi"}
        if set(args) - allowed:
            raise SecurityError("Argumentos de scanner não reconhecidos; comandos e planos livres não são aceitos.", "invalid_scanner_input")
        if engine != "zap" and any(key in args for key in ("endpoints", "openapi")):
            raise SecurityError("Descoberta por endpoints/OpenAPI está disponível somente no adaptador ZAP.", "invalid_scanner_input")
        level = args.get("level", "PASSIVE")
        if level not in LEVELS:
            raise SecurityError("Nível deve ser PASSIVE, SAFE ACTIVE ou STAGING FULL.", "invalid_scanner_input")
        destination = network.ScopePolicy(scope).authorize_target(args.get("target"), engine, resolve=False)
        granted_ports = scope.get("allowed_ports")
        if not isinstance(granted_ports, list) or not granted_ports:
            raise SecurityError("Scanners 2.0 requerem portas explicitamente cadastradas em allowed_ports.", "scope_port_denied")
        if engine in {"nuclei", "zap"}:
            if destination["port"] not in granted_ports:
                raise SecurityError("Porta não pertence ao escopo autorizado.", "scope_port_denied")
            if destination["scheme"] != "http":
                raise SecurityError("Scanners externos exigem laboratório HTTP nesta versão; HTTPS requer egress por requisição validado.", "isolation_requirement")
            try:
                address = ipaddress.ip_address(destination["host"])
            except ValueError:
                raise SecurityError("Scanner externo aceita somente IP literal de laboratório; domínio exige isolamento de egress e DNS ainda não configurado.", "isolation_requirement") from None
            if not (address.is_loopback or address.is_private) or address.is_reserved:
                raise SecurityError("Nuclei/ZAP estão limitados a IP local ou privado de laboratório/homologação.", "isolation_requirement")
            environment = str(scope.get("environment", "")).casefold().strip()
            environment_class = scope.get("environment_class")
            if (environment_class is not None and environment_class not in {"lab", "staging"} or
                    environment_class is None and environment not in {"lab", "laboratório", "laboratorio", "homologação", "homologacao", "staging", "laboratory"}):
                raise SecurityError("Scanner externo requer ambiente declarado de laboratório ou homologação.", "environment_not_allowed")
            if level != "PASSIVE" and args.get("level") is None:
                raise SecurityError("Teste ativo exige seleção explícita do nível.", "active_approval_required")
        duration = _bounded_int(args.get("duration_seconds", 45 if engine == "nmap_service" else 90), "duration_seconds", 5, 180)
        rate = _bounded_int(args.get("rate_limit", 2), "rate_limit", 1, 5)
        normalized = {"target": destination["url"], "level": level, "duration_seconds": duration, "rate_limit": rate}
        impact = ["Tráfego somente no alvo e porta aprovados; saída é dado não confiável."]
        if engine == "nmap_service":
            maximum = 64 if args.get("expanded_ports_approved") is True else 8
            ports = network._ports(args.get("ports", [80, 443]), maximum)
            if any(port not in granted_ports for port in ports):
                raise SecurityError("Porta não pertence ao escopo autorizado.", "scope_port_denied")
            services = args.get("service_detection", False)
            if type(services) is not bool:
                raise SecurityError("service_detection deve ser booleano.", "invalid_scanner_input")
            if services and level == "PASSIVE":
                raise SecurityError("Detecção de versão envia probes e requer SAFE ACTIVE ou STAGING FULL.", "active_approval_required")
            normalized.update(ports=ports, service_detection=services, expanded_ports_approved=maximum == 64)
            impact.append("Conexões TCP, sem scripts NSE, UDP, SO, evasão ou exploração.")
            if services:
                impact.append("Probes Nmap -sV --version-light podem interagir com serviços; versão só quando comprovada por probe.")
        elif engine == "nuclei":
            selected = args.get("templates", ["nexus-http-baseline", "nexus-exposed-openapi"])
            if not isinstance(selected, list) or not selected or len(selected) > len(REVIEWED_TEMPLATES) or any(not isinstance(x, str) or x not in REVIEWED_TEMPLATES for x in selected):
                raise SecurityError("Selecione somente templates revisados deste catálogo.", "unreviewed_template")
            normalized["templates"] = list(dict.fromkeys(selected))
            impact.append("GET limitado; sem OAST/cloud, atualizações, redirecionamentos ou templates externos. Não é observação sem tráfego.")
        else:
            impact.append("PASSIVE envia um GET ao endpoint e executa somente regras passivas; não usa spider automático.")
            for key in ("endpoints", "openapi"):
                if key in args:
                    normalized[key] = args[key]
            requests, discovery = _zap_requests(normalized)
            for key in ("endpoints", "openapi"):
                if key in normalized:
                    normalized[key] = copy.deepcopy(normalized[key])
            impact.append(f"Descoberta explícita: até {len(requests)} requisições GET/HEAD planejadas a caminhos validados, dentro do orçamento compartilhado do proxy.")
            if level != "PASSIVE":
                impact.append("GET de laboratório e regras ativas revisadas: XSS refletido (40012) e SQL injection (40018), sem extração de dados; nível STAGING amplia somente duração, nunca regras destrutivas.")
        result = {"engine": engine, "scope_id": scope.get("id"), "scope_revision": scope.get("revision"),
                "args": normalized, "impact": impact, "requires_approval": True,
                "configuration_sha256": hashlib.sha256(_canonical(self.config.get(engine, {}))).hexdigest(),
                "template_version": TEMPLATE_VERSION if engine == "nuclei" else None,
                "limitations": [NOTICE, "Sem sandbox de SO; alvos externos exigem configuração de isolamento adicional.",
                                "Proxy retira Location e limita corpo/cabeçalhos; não é uma auditoria de redirecionamentos."]}
        if engine == "zap":
            result["discovery"] = discovery
        return result

    def _version(self, engine, binary, java, home, cancel_event, check):
        argv = [str(binary), "-version"] if engine == "nuclei" else [str(binary), "--version"]
        if engine == "zap":
            argv = [str(java), "-Xmx512m", "-Djava.awt.headless=true", "-jar", str(binary), "-dir", str(home), "-version"]
        done = run_bounded(argv, cwd=binary.parent, env=_environment(home), timeout=15,
                           max_output=64 * 1024, cancel_event=cancel_event, scope_check=check)
        if not done["ok"] or done["exit_code"] != 0:
            raise SecurityError("Não foi possível verificar versão da ferramenta aprovada.", done["code"] if done["code"] != "ok" else "version_check_failed")
        output = (done["stdout"] + done["stderr"]).decode("utf-8", "replace")
        pattern = {"nuclei": r"(?:Nuclei Engine Version:|Current Version:|Nuclei\s+version)\s*v?(\d+\.\d+\.\d+)",
                   "zap": r"(?:ZAP\s*)?(\d+\.\d+\.\d+)", "nmap_service": r"Nmap version\s+(\d+\.\d+(?:\.\d+)?)"}[engine]
        match = re.search(pattern, output, re.IGNORECASE)
        if not match:
            raise SecurityError("Versão não reconhecida; motor não será anunciado como operacional.", "version_check_failed")
        version = match[1]
        major = int(version.split(".")[0])
        if engine == "nuclei" and major != 3 or engine == "zap" and major != 2 or engine == "nmap_service" and major != 7:
            raise SecurityError("Versão principal fora do contrato revisado do adaptador.", "unsupported_tool_version")
        return version

    def zap_plan(self, args, report_dir):
        target, level = args["target"], args["level"]
        requests, _ = _zap_requests(args)
        jobs = [{"type": "passiveScan-config", "parameters": {"maxAlertsPerRule": 20, "scanOnlyInScope": True}},
                {"type": "requestor", "requests": requests},
                {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}}]
        if level != "PASSIVE":
            jobs.append({"type": "activeScan", "parameters": {"context": "nexus-authorized", "url": target,
                         "maxRuleDurationInMins": 1, "maxScanDurationInMins": 1 if level == "SAFE ACTIVE" else 2,
                         "delayInMs": max(200, 1000 // args["rate_limit"]), "threadPerHost": 1,
                         "maxAlertsPerRule": 20, "handleAntiCSRFTokens": False, "scanHeadersAllRequests": False,
                         "addQueryParam": False}, "policyDefinition": {"defaultStrength": "Low", "defaultThreshold": "Off",
                         "rules": [{"id": 40012, "strength": "Low", "threshold": "Medium"}, {"id": 40018, "strength": "Low", "threshold": "Medium"}]}})
        jobs.extend([{"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                     {"type": "report", "parameters": {"template": "traditional-json", "reportDir": str(report_dir),
                       "reportFile": "nexus-zap", "displayReport": False}}])
        return {"env": {"contexts": [{"name": "nexus-authorized", "urls": [target],
                        "includePaths": [re.escape(url) + r"(?:\?.*)?$" for url in dict.fromkeys(item["url"] for item in requests)]}],
                        "parameters": {"failOnError": True, "failOnWarning": False, "continueOnFailure": False,
                                       "progressToStdout": True},
                        "configs": {"autoupdate.checkOnStart": False, "autoupdate.installAddonUpdates": False,
                                    "autoupdate.downloadNewRelease": False, "api.disablekey": False,
                                    "connection.timeoutInSecs": 5, "network.connection.timeoutInSecs": 5,
                                    "stats.inMemoryEnabled": False}}, "jobs": jobs}

    def run(self, engine, scope, args, cancel_event=None, emit=None, scope_loader=None):
        started = time.monotonic()
        try:
            preview = self.preview(engine, scope, args)
            args = preview["args"]
            if not _RUN_LOCK.acquire(blocking=False):
                raise SecurityError("Outro scanner externo está em execução; aguarde para preservar memória.", "scanner_busy")
            try:
                return self._run(engine, scope, args, preview, cancel_event, emit, scope_loader)
            finally:
                _RUN_LOCK.release()
        except Exception as exc:
            return {"ok": False, "tool": engine, "code": getattr(exc, "code", "scanner_failed"),
                    "error": redact_secrets(str(exc))[:1000], "findings": [], "evidence": {},
                    "duration_seconds": round(time.monotonic() - started, 3), "untrusted_external_data": True}

    def _run(self, engine, scope, args, preview, cancel_event, emit, scope_loader):
        binary, java = self._binary(engine)
        check = lambda: _check_scope(scope, scope_loader)
        check()
        memory = psutil.virtual_memory()
        required = 1024 * 1024 * 1024 if engine == "zap" else 512 * 1024 * 1024
        if memory.available < required:
            raise SecurityError("RAM livre insuficiente para este scanner; descarregue modelos ou feche aplicativos.", "resource_budget")
        root = _safe_directory(self.root)
        with tempfile.TemporaryDirectory(prefix=engine + "-", dir=root) as temporary:
            home = _safe_directory(Path(temporary))
            version = self._version(engine, binary, java, home, cancel_event, check)
            # Version probe and scan must use exactly the approved bytes.
            if self._binary(engine) != (binary, java):
                raise SecurityError("Ferramenta mudou após verificação de versão.", "scanner_integrity")
            destination = network.ScopePolicy(check()).authorize_target(args["target"], engine)
            address = destination["addresses"][0]
            output_files = []
            if engine == "nuclei":
                files = []
                for key in args["templates"]:
                    path = home / (key + ".yaml")
                    path.write_bytes(_canonical(REVIEWED_TEMPLATES[key]))
                    files.append(str(path))
                argv = [str(binary), "-u", args["target"], "-t", ",".join(files), "-jsonl", "-silent", "-nc", "-duc", "-ni", "-dr", "-or",
                        "-rl", str(args["rate_limit"]), "-c", "1", "-bs", "1", "-timeout", "5", "-retries", "0",
                        "-rsr", "262144", "-rss", "4096", "-mhe", "3", "-no-stdin"]
            elif engine == "zap":
                plan = self.zap_plan(args, home)
                plan_file = home / "plan.yaml"
                plan_file.write_bytes(_canonical(plan))
                report = home / "nexus-zap.json"
                output_files = [report]
                argv = [str(java), "-Xmx512m", "-Djava.awt.headless=true", "-jar", str(binary), "-dir", str(home), "-cmd", "-silent", "-autorun", str(plan_file),
                        "-config", "api.enabled=false", "-config", "autoupdate.checkOnStart=false", "-config", "autoupdate.installAddonUpdates=false"]
            else:
                argv = [str(binary), "-sT", "-Pn", "-n", "--unprivileged", "--disable-arp-ping", "--max-retries", "0", "--max-parallelism", "1",
                        "--scan-delay", "250ms", "--host-timeout", str(max(5, args["duration_seconds"] - 5)) + "s", "-p", ",".join(map(str, args["ports"])), "-oX", "-"]
                if args["service_detection"]:
                    argv.extend(["-sV", "--version-light", "--version-intensity", "2"])
                if ":" in address:
                    argv.append("-6")
                argv.append(address)
            if emit:
                emit({"type": "started", "engine": engine, "version": version, "target": args["target"]})
            proxy_evidence = None
            cancel_event = cancel_event or threading.Event()
            if engine in {"nuclei", "zap"}:
                maximum = 80 if args["level"] == "STAGING FULL" else 40
                with _ScopedProxy(destination, rate=args["rate_limit"], maximum=maximum, check=check, cancel=cancel_event) as proxy:
                    if engine == "nuclei":
                        argv.extend(["-proxy", proxy.url, "-pi"])
                    else:
                        for key, value in {"network.connection.httpProxy.enabled": "true", "network.connection.httpProxy.host": "127.0.0.1",
                                           "network.connection.httpProxy.port": str(proxy.server.server_port),
                                           "network.connection.httpProxy.authEnabled": "false", "network.connection.socksProxy.enabled": "false"}.items():
                            argv.extend(["-config", key + "=" + value])
                    done = run_bounded(argv, cwd=binary.parent, env=_environment(home), timeout=args["duration_seconds"],
                                       cancel_event=cancel_event, scope_check=check, emit=emit, output_files=output_files)
                    proxy_evidence = {"requests": proxy.requests, "denied": proxy.denied, "remote_failures": proxy.failures,
                                      "maximum_requests": maximum, "rate_limit": args["rate_limit"], "concurrency": 1,
                                      "origin_pinned": True, "redirect_location_forwarded": False, "https_supported": False}
            else:
                done = run_bounded(argv, cwd=binary.parent, env=_environment(home), timeout=args["duration_seconds"],
                                   cancel_event=cancel_event, scope_check=check, emit=emit, output_files=output_files)
            evidence = {"version": version, "sha256": sha256_file(binary), "scope_id": scope.get("id"),
                        "scope_revision": scope.get("revision"), "address": address, "config": {key: value for key, value in args.items() if key != "openapi"},
                        "coverage": preview["impact"], "exit_code": done["exit_code"], "timestamp": utcnow(),
                        "duration_seconds": done["duration_seconds"], "peak_rss_bytes": done.get("peak_rss_bytes"),
                        "resource_enforcement": done.get("resource_enforcement"), "untrusted_external_data": True,
                        "raw_diagnostics_retained": False}
            if proxy_evidence is not None:
                evidence["network_guard"] = proxy_evidence
            if not done["ok"] or engine != "zap" and done["exit_code"] != 0:
                return {"ok": False, "tool": engine, "code": done["code"] if done["code"] != "ok" else "tool_failed",
                        "error": "Scanner interrompido ou não concluiu. Resultado parcial não comprova cobertura.", "findings": [], "evidence": evidence}
            check()
            if engine == "nuclei":
                findings = parse_nuclei(done["stdout"], args["templates"], args["target"])
                evidence.update(template_version=TEMPLATE_VERSION, templates=[x for x in self.templates() if x["id"] in args["templates"]])
            elif engine == "zap":
                if not report.is_file():
                    raise SecurityError("ZAP não gerou relatório JSON; verificar addons Automation Framework e Report Generation.", "missing_zap_report")
                findings = parse_zap(safe_file(report, maximum=MAX_OUTPUT).read_bytes(), args["target"])
                evidence.update(plan_sha256=hashlib.sha256(_canonical(plan)).hexdigest(), warnings=done["exit_code"] == 2,
                                discovery=preview["discovery"], active_rules=[40012, 40018] if args["level"] != "PASSIVE" else [])
            else:
                rows = parse_nmap(done["stdout"], args["ports"], address, args["service_detection"])
                findings = []
                evidence["ports"] = rows
                evidence["cve_association"] = "Não realizada automaticamente; versão ou porta isolada não confirma CVE."
            return {"ok": True, "tool": engine, "code": "ok", "target": args["target"], "findings": findings,
                    "evidence": evidence, "notice": NOTICE, "limitations": preview["limitations"]}
