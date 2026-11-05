"""Small, bounded adapters for explicitly authorized network scopes.

These functions do not grant permission or manufacture user approval. The caller
must reload the scope and obtain human operation approval immediately before a
network operation. Remote bytes are evidence, never instructions for the agent.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from nexus.tools import Tools, ToolError


ALLOWED_TESTS = frozenset({"http_headers", "tls_certificate", "tcp_connect", "nmap_basic", "osint",
    "nuclei", "zap", "nmap_service", "appsec_sqli", "appsec_auth", "asset_inventory"})
DNS_TIMEOUT = 3.0
NETWORK_TIMEOUT = 6.0
MAX_HEADERS = 16_384
MAX_NMAP_XML = 1_000_000
_DNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="nexus-scope-dns")


class ProtocolEvidenceError(ValueError):
    """Remote or optional-tool output is malformed, not a scope rejection."""


def _text(value: Any, field: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"{field}: texto inválido ou maior que {limit} caracteres.")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field}: informe um valor.")
    return value


def _ip(value: str):
    if "%" in value:
        raise ValueError("Identificadores de interface IPv6 não são permitidos.")
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        raise ValueError("Endereço não especificado, multicast ou link-local não permitido.")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        raise ValueError("Use o endereço IPv4 diretamente, sem IPv6 mapeado.")
    return address


def _host(value: str) -> str:
    value = _text(value, "host", 253).rstrip(".").lower()
    try:
        return str(_ip(value))
    except ValueError:
        # A malformed numeric IP must not become a hostname interpreted by the OS.
        if (":" in value or "%" in value or re.fullmatch(r"[0-9.]+", value) or
                re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", value)):
            raise ValueError("Endereço IP inválido ou não permitido.") from None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domínio inválido.") from exc
    labels = value.split(".")
    if (len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                              for label in labels) or labels[-1].isdigit()):
        raise ValueError("Domínio inválido; informe somente domínio ou IP canônico.")
    return value


def _scope_target(value: str) -> str:
    value = _text(value, "target", 253)
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError("Rede CIDR deve ser canônica, sem bits de host.") from exc
        if network.prefixlen == 0:
            raise ValueError("Escopo aberto /0 não permitido.")
        # Refuse networks spanning special destinations, not merely their first IP.
        forbidden = [ipaddress.ip_network(v) for v in
                     (["0.0.0.0/32", "224.0.0.0/4", "169.254.0.0/16"] if network.version == 4 else
                      ["::/128", "ff00::/8", "fe80::/10", "::ffff:0:0/96"])]
        if any(network.overlaps(item) for item in forbidden):
            raise ValueError("Rede inclui destinos não especificados, multicast, link-local ou mapeados.")
        return str(network)
    return _host(value)


def normalize_scope(payload: dict) -> dict:
    """Normalize a human-created grant; IDs/revisions belong to the caller's store."""
    if not isinstance(payload, dict) or payload.get("authorization_confirmed") is not True:
        raise ValueError("Confirme explicitamente a responsabilidade e autorização do escopo.")
    targets = payload.get("targets")
    tests = payload.get("allowed_tests")
    if not isinstance(targets, list) or not 1 <= len(targets) <= 100:
        raise ValueError("Informe de 1 a 100 domínios, IPs ou redes autorizadas.")
    if not isinstance(tests, list) or not tests or any(not isinstance(t, str) or t not in ALLOWED_TESTS for t in tests):
        raise ValueError("Tipos de teste inválidos; selecione os testes permitidos.")
    subdomains = payload.get("include_subdomains", False)
    if not isinstance(subdomains, bool):
        raise ValueError("include_subdomains deve ser booleano.")
    extras = {}
    if "allowed_ports" in payload:
        extras["allowed_ports"] = _ports(payload["allowed_ports"], 64)
    if "environment_class" in payload:
        if payload["environment_class"] not in {"lab", "staging", "production"}:
            raise ValueError("environment_class deve ser lab, staging ou production.")
        extras["environment_class"] = payload["environment_class"]
    if "hosting" in payload:
        if payload["hosting"] not in {"own", "shared", "vercel", "other"}:
            raise ValueError("hosting inválido.")
        extras["hosting"] = payload["hosting"]
    if "provider_authorization" in payload:
        if type(payload["provider_authorization"]) is not bool:
            raise ValueError("provider_authorization deve ser booleano.")
        extras["provider_authorization"] = payload["provider_authorization"]
    return {**extras, "name": _text(payload.get("name"), "name", 120),
            "targets": list(dict.fromkeys(_scope_target(t) for t in targets)),
            "allowed_tests": sorted(set(tests)),
            "environment": _text(payload.get("environment", "laboratório"), "environment", 120),
            "purpose": _text(payload.get("purpose", "Verificação autorizada"), "purpose", 500),
            "authorization_confirmed": True, "include_subdomains": subdomains}


def _resolve(host: str, port: int) -> list[str]:
    try:
        return [str(_ip(host))]
    except ValueError:
        pass
    future = _DNS_POOL.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
    try:
        records = future.result(timeout=DNS_TIMEOUT)
    except concurrent.futures.TimeoutError as exc:
        future.cancel()
        raise ValueError("Resolução DNS excedeu o limite de 3 segundos.") from exc
    except OSError as exc:
        raise ValueError("Não foi possível resolver o domínio autorizado.") from exc
    addresses = list(dict.fromkeys(str(_ip(row[4][0])) for row in records))
    if not addresses or len(addresses) > 32:
        raise ValueError("DNS sem endereços utilizáveis ou com mais de 32 respostas.")
    return addresses


def _url(target: str) -> dict:
    target = _text(target, "target", 2048)
    if "\\" in target or target.startswith("//"):
        raise ValueError("URL com caminho ou autoridade ambígua.")
    # Plain IPv6 literals are accepted; brackets are needed when adding a port.
    try:
        literal = str(_ip(target))
    except ValueError:
        literal = None
    if literal:
        target = "https://" + (f"[{literal}]" if ":" in literal else literal) + "/"
    elif "://" not in target:
        target = "https://" + target
    try:
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Use somente URL HTTP ou HTTPS com host explícito.")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise ValueError("Credenciais em URL não são permitidas.")
        host = _host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"URL inválida: {exc}") from exc
    if not 1 <= port <= 65535 or parsed.fragment or parsed.query:
        raise ValueError("URL exige porta válida, sem fragmentos ou parâmetros de consulta.")
    path = parsed.path or "/"
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    if ("\\" in decoded or "%25" in path.lower() or
            any(part in {".", ".."} for part in decoded.split("/")) or
            any(ord(c) < 32 for c in decoded)):
        raise ValueError("Caminho de URL contém escape ou segmento ambíguo.")
    if not path.isascii() or " " in path or re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise ValueError("Codifique caracteres não ASCII/espaços no caminho e use escapes percentuais válidos.")
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if parsed.scheme == "https" else 80):
        authority += f":{port}"
    return {"host": host, "scheme": parsed.scheme, "port": port, "path": path,
            "url": urlunsplit((parsed.scheme, authority, path, "", "")), "authority": authority}


class ScopePolicy:
    def __init__(self, scope: dict):
        self.scope = normalize_scope(scope)
        self.scope.update({key: scope[key] for key in ("id", "revision", "enabled") if key in scope})
        if self.scope.get("enabled", True) is not True:
            raise ValueError("Escopo desativado ou revogado.")
        self.networks = []
        self.domains = []
        for target in self.scope["targets"]:
            try:
                self.networks.append(ipaddress.ip_network(target, strict=True))
            except ValueError:
                self.domains.append(target)

    def _granted_ip(self, address) -> bool:
        return any(address.version == network.version and address in network for network in self.networks)

    def _granted_domain(self, host: str) -> bool:
        return any(host == domain or (self.scope["include_subdomains"] and host.endswith("." + domain))
                   for domain in self.domains)

    def authorize_target(self, target: str, test: str, *, resolve: bool = True) -> dict:
        if test not in self.scope["allowed_tests"]:
            raise ValueError("Este tipo de teste não foi autorizado no escopo.")
        destination = _url(target)
        if "allowed_ports" in self.scope and destination["port"] not in self.scope["allowed_ports"] and test not in {"tcp_connect", "nmap_basic", "nmap_service", "osint"}:
            raise ValueError("Porta fora do escopo autorizado.")
        if test in {"tcp_connect", "nmap_basic", "nmap_service"} and destination["path"] != "/":
            raise ValueError("Teste de portas recebe um host individual, sem caminho ou rede CIDR.")
        host = destination["host"]
        try:
            address = _ip(host)
        except ValueError:
            address = None
        if address is not None:
            if not self._granted_ip(address):
                raise ValueError("IP fora do escopo autorizado.")
        elif not self._granted_domain(host):
            raise ValueError("Domínio fora do escopo autorizado.")
        addresses = _resolve(host, destination["port"]) if resolve else []
        for value in addresses:
            resolved = _ip(value)
            # A domain grant never implicitly grants internal or loopback services.
            if (not resolved.is_global or address is not None) and not self._granted_ip(resolved):
                raise ValueError("DNS aponta para endereço interno não explicitamente autorizado.")
        return {**destination, "addresses": addresses,
                "scope_id": self.scope.get("id"), "scope_revision": self.scope.get("revision")}


def _failure(tool: str, exc: Exception, *, target: str | None = None) -> dict:
    if isinstance(exc, ssl.SSLCertVerificationError):
        code, message = "TLS_CERTIFICATE_INVALID", "Falha de validação do certificado TLS; conexão não foi repetida sem validação."
    elif isinstance(exc, (socket.timeout, TimeoutError, subprocess.TimeoutExpired)):
        code, message = "TIMEOUT", "Tempo limite da operação excedido."
    elif isinstance(exc, ProtocolEvidenceError):
        code, message = "PROTOCOL_ERROR", str(exc)
    elif isinstance(exc, (ValueError, ToolError)):
        code, message = "SCOPE_OR_INPUT", str(exc)
    elif isinstance(exc, OSError):
        code, message = "NETWORK_ERROR", f"Falha de rede ({type(exc).__name__}); não representa recusa do modelo."
    else:
        code, message = "ADAPTER_ERROR", f"Falha do adaptador ({type(exc).__name__})."
    return {"ok": False, "tool": tool, "code": code, "error": message,
            "target": target, "findings": [], "evidence": {}}


def _connect(destination: dict, deadline: float):
    # Connect a literal address; never ask a second networking library to resolve it.
    last_error = None
    for address in destination["addresses"]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        handle = socket.socket(family, socket.SOCK_STREAM)
        handle.settimeout(remaining)
        try:
            handle.connect((address, destination["port"]))
            return handle, address
        except OSError as exc:
            last_error = exc
            handle.close()
    raise last_error or OSError("No address")


def _tls(handle, destination: dict, deadline: float):
    handle.settimeout(max(0.01, deadline - time.monotonic()))
    try:
        return ssl.create_default_context().wrap_socket(handle, server_hostname=destination["host"])
    except Exception:
        handle.close()
        raise


def inspect_http(scope: dict, target: str) -> dict:
    """One HEAD request with no redirects, cookies, proxy, credentials or body fetch."""
    handle = None
    try:
        policy = ScopePolicy(scope)
        destination = policy.authorize_target(target, "http_headers")
        deadline = time.monotonic() + NETWORK_TIMEOUT
        handle, address = _connect(destination, deadline)
        if destination["scheme"] == "https":
            handle = _tls(handle, destination, deadline)
        request = (f"HEAD {destination['path']} HTTP/1.1\r\nHost: {destination['authority']}\r\n"
                   "User-Agent: NEXUS-SecurityCenter/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        handle.sendall(request.encode("ascii"))
        data = bytearray()
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            handle.settimeout(remaining)
            chunk = handle.recv(min(2048, MAX_HEADERS + 1 - len(data)))
            if not chunk:
                raise ProtocolEvidenceError("Servidor encerrou a resposta antes dos cabeçalhos completos.")
            data.extend(chunk)
            if len(data) > MAX_HEADERS:
                raise ProtocolEvidenceError("Cabeçalhos excedem o limite de 16 KiB.")
        header_block = bytes(data).split(b"\r\n\r\n", 1)[0]
        status, _, raw_headers = header_block.partition(b"\r\n")
        match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3})(?: .*)?", status)
        if not match:
            raise ProtocolEvidenceError("Resposta HTTP inválida.")
        headers = http.client.parse_headers(io.BytesIO(raw_headers + b"\r\n\r\n"))
        selected = {name.lower(): str(value)[:1000] for name, value in headers.items()
                    if name.lower() in {"content-security-policy", "strict-transport-security",
                        "x-content-type-options", "x-frame-options", "referrer-policy",
                        "permissions-policy", "cross-origin-opener-policy", "server", "content-type"}}
        findings = []
        expected = ["content-security-policy", "x-content-type-options", "referrer-policy"]
        if destination["scheme"] == "https":
            expected.append("strict-transport-security")
        for name in expected:
            if name not in selected:
                findings.append({"title": f"Cabeçalho {name} não observado", "severity": "info",
                    "confidence": "medium", "confirmed": False,
                    "recommendation": "Avaliar necessidade conforme o tipo de resposta e arquitetura; ausência isolada não confirma vulnerabilidade."})
        redirect = None
        location = headers.get("Location")
        if location:
            try:
                proposed = policy.authorize_target(urljoin(destination["url"], location), "http_headers", resolve=False)
                redirect = {"url": proposed["url"], "in_scope": True, "followed": False}
            except ValueError:
                redirect = {"in_scope": False, "followed": False, "reason": "Redirecionamento não seguido ou fora do escopo."}
        return {"ok": True, "tool": "http_headers", "target": destination["url"], "findings": findings,
                "evidence": {"method": "HEAD", "status": int(match[1]), "address": address,
                    "headers": selected, "header_bytes": len(header_block), "redirect": redirect,
                    "cookies_returned": len(headers.get_all("Set-Cookie", [])), "body_fetched": False,
                    "untrusted_external_data": True}}
    except Exception as exc:
        return _failure("http_headers", exc, target=target)
    finally:
        if handle is not None:
            handle.close()


def inspect_tls(scope: dict, target: str) -> dict:
    handle = None
    try:
        destination = ScopePolicy(scope).authorize_target(target, "tls_certificate")
        if destination["scheme"] != "https":
            raise ValueError("Inspeção TLS requer URL https://.")
        deadline = time.monotonic() + NETWORK_TIMEOUT
        handle, address = _connect(destination, deadline)
        handle = _tls(handle, destination, deadline)
        certificate = handle.getpeercert()
        evidence = {"address": address, "verified": True, "sha256": hashlib.sha256(handle.getpeercert(binary_form=True)).hexdigest(),
                    "not_before": certificate.get("notBefore"), "not_after": certificate.get("notAfter"),
                    "subject": certificate.get("subject"), "issuer": certificate.get("issuer"),
                    "subject_alt_names": certificate.get("subjectAltName", [])[:100],
                    "tls_version": handle.version(), "cipher": handle.cipher(), "untrusted_external_data": True}
        return {"ok": True, "tool": "tls_certificate", "target": destination["url"], "evidence": evidence, "findings": []}
    except Exception as exc:
        return _failure("tls_certificate", exc, target=target)
    finally:
        if handle is not None:
            handle.close()


def _ports(ports: list[int], maximum: int) -> list[int]:
    if (not isinstance(ports, list) or not 1 <= len(ports) <= maximum or
            any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports)):
        raise ValueError(f"Informe de 1 a {maximum} portas TCP inteiras de 1 a 65535.")
    return list(dict.fromkeys(ports))


def tcp_probe(scope: dict, target: str, ports: list[int]) -> dict:
    try:
        ports = _ports(ports, 8)
        if "allowed_ports" in scope and any(port not in scope["allowed_ports"] for port in ports):
            raise ValueError("Porta fora do escopo autorizado.")
        destination = ScopePolicy(scope).authorize_target(target, "tcp_connect")
        deadline = time.monotonic() + 15
        rows = []
        # One pinned address and one connection at a time; never a network sweep.
        for port in ports:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                rows.append({"port": port, "state": "not_tested", "reason": "total_timeout"})
                continue
            probe = {**destination, "port": port, "addresses": destination["addresses"][:1]}
            started = time.monotonic()
            try:
                handle, address = _connect(probe, time.monotonic() + min(1.5, remaining))
                handle.close()
                rows.append({"port": port, "state": "open", "address": address,
                             "elapsed_ms": round((time.monotonic() - started) * 1000, 2)})
            except ConnectionRefusedError:
                rows.append({"port": port, "state": "closed"})
            except (TimeoutError, OSError) as exc:
                rows.append({"port": port, "state": "unknown", "reason": type(exc).__name__})
        return {"ok": True, "tool": "tcp_connect", "target": destination["host"],
                "evidence": {"ports": rows, "concurrency": 1, "payload_sent": False}, "findings": []}
    except Exception as exc:
        return _failure("tcp_connect", exc, target=target)


def _nmap_path() -> Path | None:
    if os.name == "nt":
        candidates = [Path(os.environ.get(key, "C:/Program Files")) / "Nmap/nmap.exe"
                      for key in ("ProgramFiles", "ProgramFiles(x86)")]
    else:
        candidates = [Path("/usr/bin/nmap"), Path("/usr/local/bin/nmap")]
    for candidate in candidates:
        try:
            if candidate.is_file() and not candidate.is_symlink() and candidate.resolve() == candidate.absolute():
                return candidate
        except OSError:
            continue
    return None


def _run_nmap_capture(argv: list[str]) -> tuple[int, bytes, bytes]:
    """Bound output while the process runs, without unbounded PIPE buffering."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        with subprocess.Popen(argv, stdout=stdout, stderr=stderr, shell=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)) as process:
            deadline = time.monotonic() + 30
            try:
                while process.poll() is None:
                    if os.fstat(stdout.fileno()).st_size > MAX_NMAP_XML or os.fstat(stderr.fileno()).st_size > 64_000:
                        raise ValueError("Saída Nmap excedeu o limite permitido.")
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(argv, 30)
                    time.sleep(0.03)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            stdout.seek(0)
            stderr.seek(0)
            result, errors = stdout.read(MAX_NMAP_XML + 1), stderr.read(64_001)
            if len(result) > MAX_NMAP_XML or len(errors) > 64_000:
                raise ValueError("Saída Nmap excedeu o limite permitido.")
            return process.returncode, result, errors


def run_nmap(scope: dict, target: str, ports: list[int]) -> dict:
    try:
        ports = _ports(ports, 16)
        if "allowed_ports" in scope and any(port not in scope["allowed_ports"] for port in ports):
            raise ValueError("Porta fora do escopo autorizado.")
        destination = ScopePolicy(scope).authorize_target(target, "nmap_basic")
        executable = _nmap_path()
        if executable is None:
            return {"ok": False, "tool": "nmap_basic", "code": "TOOL_UNAVAILABLE", "available": False,
                    "error": "Nmap não encontrado em instalação canônica; nenhuma instalação foi iniciada.",
                    "findings": [], "evidence": {}}
        if executable.stat().st_size > 100_000_000:
            raise ValueError("Executável Nmap excede o limite de procedência.")
        fingerprint = hashlib.sha256(executable.read_bytes()).hexdigest()
        address = destination["addresses"][0]
        argv = [str(executable), "-sT", "-Pn", "-n", "--unprivileged", "--disable-arp-ping", "--max-retries", "0",
                "--max-parallelism", "1", "--scan-delay", "100ms", "--host-timeout", "20s",
                "-p", ",".join(map(str, ports)), "-oX", "-"]
        if ":" in address:
            argv.append("-6")
        argv.append(address)
        # No shell, scripts, service fingerprints, UDP, raw probes or caller argv.
        exit_code, stdout, _ = _run_nmap_capture(argv)
        if exit_code != 0:
            return {"ok": False, "tool": "nmap_basic", "code": "TOOL_FAILED", "available": True,
                    "error": "Nmap não concluiu o teste; consulte os argumentos e a instalação.",
                    "evidence": {"exit_code": exit_code, "args": argv, "sha256": fingerprint}, "findings": []}
        try:
            xml_text = stdout.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ProtocolEvidenceError("Saída XML Nmap não usa UTF-8.") from exc
        if "\x00" in xml_text:
            raise ProtocolEvidenceError("Saída XML Nmap contém codificação ambígua.")
        # A normal Nmap XML document may contain its plain external nmap.dtd
        # declaration. Strip only this exact declaration; refuse all entities.
        if "<!ENTITY" in xml_text.upper() or "<!DOCTYPE" in xml_text.upper():
            xml_text = re.sub(r'<!DOCTYPE nmaprun(?: SYSTEM [\'"]nmap\.dtd[\'"])?\s*>', "", xml_text)
            if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
                raise ProtocolEvidenceError("XML Nmap contém DTD ou entidade não permitida.")
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise ProtocolEvidenceError("Saída XML Nmap malformada.") from exc
        if root.tag != "nmaprun":
            raise ProtocolEvidenceError("Documento não é saída XML Nmap.")
        rows = []
        for item in root.findall("./host/ports/port")[:16]:
            port = int(item.get("portid", "0"))
            if port not in ports or item.get("protocol") != "tcp":
                continue
            state = item.find("state")
            service = item.find("service")
            rows.append({"port": port, "protocol": "tcp", "state": state.get("state") if state is not None else "unknown",
                         "service_hint": service.get("name") if service is not None else None})
        return {"ok": True, "tool": "nmap_basic", "target": destination["host"], "available": True,
                "evidence": {"address": address, "args": argv, "exit_code": exit_code,
                    "executable": str(executable), "sha256": fingerprint, "signature_verified": False,
                    "provenance": "canonical_install_path", "ports": rows, "untrusted_external_data": True}, "findings": []}
    except Exception as exc:
        return _failure("nmap_basic", exc, target=target)


def _terms(value: str | list[str], field: str, maximum: int = 10) -> list[str]:
    if isinstance(value, str):
        value = [value] if value.strip() else []
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{field}: informe até {maximum} termos.")
    return [_text(item, field, 100) for item in value]


def _quote(value: str) -> str:
    # Operator syntax cannot be introduced through free-text fields.
    if '"' in value or "\\" in value:
        raise ValueError("Aspas e barras invertidas não são permitidas nos termos da consulta.")
    return '"' + value + '"'


def build_dork(scope: dict, domain: str, operators: dict | list | None = None,
               document_type: str = "", keywords: str | list[str] = "",
               exclusions: str | list[str] = "", max_results: int = 5) -> dict:
    """Construct a public query without making DNS requests or contacting a host."""
    policy = ScopePolicy(scope)
    domain = _host(domain)
    policy.authorize_target(domain, "osint", resolve=False)
    if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= 10:
        raise ValueError("max_results deve ficar entre 1 e 10.")
    document_type = _text(document_type, "document_type", 10, required=False)
    if document_type and not re.fullmatch(r"[a-zA-Z0-9]{1,10}", document_type):
        raise ValueError("Tipo de documento deve ser uma extensão de até 10 caracteres.")
    operators = operators or {}
    if isinstance(operators, list):
        mapped = {}
        for value in operators:
            if not isinstance(value, str) or ":" not in value:
                raise ValueError("Operadores devem usar intitle:valor, inurl:valor ou intext:valor.")
            key, content = value.split(":", 1)
            if key in mapped:
                raise ValueError("Operador repetido na consulta.")
            mapped[key] = content
        operators = mapped
    if not isinstance(operators, dict) or set(operators) - {"intitle", "inurl", "intext"}:
        raise ValueError("Operador não permitido; use intitle, inurl ou intext.")
    terms = _terms(keywords, "keywords")
    excluded = _terms(exclusions, "exclusions")
    query = [f"site:{domain}"]
    query += [f"{key}:{_quote(_text(value, key, 100))}" for key, value in operators.items()]
    if document_type:
        query.append("filetype:" + document_type.lower())
    query += [_quote(term) for term in terms]
    query += ["-" + _quote(term) for term in excluded]
    query_text = " ".join(query)
    Tools._search_query(query_text)
    return {"query": query_text, "domain": domain, "operators": dict(operators),
            "document_type": document_type.lower(), "keywords": terms, "exclusions": excluded,
            "max_results": max_results, "scope_id": policy.scope.get("id"),
            "scope_revision": policy.scope.get("revision"), "preview_only": True,
            "privacy_notice": "A execução envia somente esta consulta pública ao mecanismo de busca; não envie credenciais ou código privado."}


def run_osint(scope: dict, queryspec: dict, tools: Tools) -> dict:
    try:
        if not isinstance(queryspec, dict):
            raise ValueError("Informe a especificação estruturada da consulta.")
        allowed = {key: queryspec[key] for key in ("domain", "operators", "document_type", "keywords", "exclusions", "max_results") if key in queryspec}
        # Never execute a caller-supplied raw query instead of the constrained builder.
        built = build_dork(scope, **allowed)
        result = tools.execute("search_web", {"query": built["query"], "max_results": built["max_results"]})
        if not result.get("ok"):
            return {"ok": False, "tool": "osint", "code": "SEARCH_FAILED", "error": result.get("error", "Pesquisa indisponível."),
                    "evidence": {"query": built["query"]}, "findings": []}
        policy = ScopePolicy(scope)
        rows = []
        for row in result.get("results", [])[:50]:
            if not isinstance(row, dict):
                continue
            try:
                destination = policy.authorize_target(row.get("url", ""), "osint", resolve=False)
                # The builder limits to one domain, even when the scope has more.
                if not (destination["host"] == built["domain"] or
                        (policy.scope["include_subdomains"] and destination["host"].endswith("." + built["domain"]))):
                    continue
            except ValueError:
                continue
            rows.append({"url": destination["url"], "title": str(row.get("title", ""))[:300],
                         "snippet": str(row.get("snippet", ""))[:1000],
                         "published_date": row.get("published_date"), "confirmed": False})
            if len(rows) >= built["max_results"]:
                break
        return {"ok": True, "tool": "osint", "target": built["domain"], "findings": [],
                "evidence": {"query": built["query"], "provider": result.get("provider"), "results": rows,
                    "pages_fetched_by_adapter": False, "untrusted_external_data": True,
                    "notice": "Resultados públicos são pistas; nenhum conteúdo privado, CAPTCHA ou credencial é coletado pelo adaptador."}}
    except Exception as exc:
        return _failure("osint", exc)


def lookup_cve(cve_id: str) -> dict:
    """Public official CVE record, no API key, uploaded code, or files."""
    handle = None
    try:
        if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve_id.upper()):
            raise ValueError("Identificador deve usar CVE-AAAA-NNNN.")
        cve_id = cve_id.upper()
        endpoint = "https://cveawg.mitre.org/api/cve/" + cve_id
        # Use the same scoped/pinned verified transport; this fixed public service
        # is a lookup provider, not a user-provided assessment target.
        scope = {"name": "CVE público", "targets": ["cveawg.mitre.org"],
                 "allowed_tests": ["http_headers"], "authorization_confirmed": True}
        destination = ScopePolicy(scope).authorize_target(endpoint, "http_headers")
        deadline = time.monotonic() + NETWORK_TIMEOUT
        handle, _ = _connect(destination, deadline)
        handle = _tls(handle, destination, deadline)
        request = (f"GET {destination['path']} HTTP/1.1\r\nHost: {destination['authority']}\r\n"
                   "User-Agent: NEXUS-SecurityCenter/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
        handle.sendall(request.encode("ascii"))
        # Bound complete HTTP bytes, including chunk framing. No compression is requested.
        data = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            handle.settimeout(remaining)
            chunk = handle.recv(min(8192, 1_000_001 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 1_000_000:
                raise ProtocolEvidenceError("Registro CVE excede o limite de 1 MB.")
        class ResponseSocket:
            def makefile(self, *args, **kwargs):
                return io.BytesIO(data)
        response = http.client.HTTPResponse(ResponseSocket())
        response.begin()
        if response.status != 200:
            return {"ok": False, "tool": "cve_lookup", "code": "PROVIDER_HTTP", "error": f"CVE Services retornou HTTP {response.status}.",
                    "evidence": {"source": endpoint, "status": response.status}, "findings": []}
        try:
            record = json.loads(response.read(1_000_001))
        except (ValueError, UnicodeError) as exc:
            raise ProtocolEvidenceError("CVE Services retornou JSON inválido.") from exc
        if not isinstance(record, dict) or record.get("cveMetadata", {}).get("cveId") != cve_id:
            raise ProtocolEvidenceError("Registro retornado não corresponde ao CVE solicitado.")
        container = record.get("containers", {}).get("cna", {})
        return {"ok": True, "tool": "cve_lookup", "target": cve_id, "findings": [],
                "evidence": {"source": endpoint, "record_url": "https://www.cve.org/CVERecord?id=" + cve_id,
                    "state": record.get("cveMetadata", {}).get("state"),
                    "title": str(container.get("title", ""))[:1000],
                    "descriptions": container.get("descriptions", [])[:10],
                    "affected": container.get("affected", [])[:50], "metrics": container.get("metrics", [])[:20],
                    "references": container.get("references", [])[:50], "untrusted_external_data": True,
                    "notice": "Presença de um CVE não confirma que um sistema específico esteja vulnerável."}}
    except Exception as exc:
        return _failure("cve_lookup", exc)
    finally:
        if handle is not None:
            handle.close()
