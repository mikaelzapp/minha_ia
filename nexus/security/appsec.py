"""Bounded application-security checks against explicitly approved synthetic fixtures.

HTTP bytes are never copied to evidence. This adapter does not enumerate data,
guess passwords, follow redirects, run SQL statements, or perform timing probes.
Approval belongs to the caller; these functions recheck the scope per request.
"""
from __future__ import annotations

import http.client
from http.cookies import SimpleCookie, CookieError
import io
import re
import time
from urllib.parse import urlencode, urlsplit

from . import network
from .common import SecurityError, redact_secrets, utcnow

MAX_REQUESTS = 16
MAX_RESPONSE = 128 * 1024
MAX_HEADERS = 16 * 1024
MAX_SECONDS = 30
ENVIRONMENTS = frozenset({"lab", "laboratorio", "laboratório", "staging", "homologacao", "homologação"})
LAB_PATTERN = re.compile(r"NEXUS_LAB_[A-Za-z0-9_-]{1,96}\Z")
DEFAULT_FIXTURE = {
    "login_path": "/login", "logout_path": "/logout",
    "username_field": "username", "password_field": "password",
    "account_a": {"username": "NEXUS_LAB_A", "password": "NEXUS_LAB_PASSWORD_A", "resource": "/api/objects/NEXUS_LAB_A", "marker": "NEXUS_LAB_RESOURCE_A"},
    "account_b": {"username": "NEXUS_LAB_B", "password": "NEXUS_LAB_PASSWORD_B", "resource": "/api/objects/NEXUS_LAB_B", "marker": "NEXUS_LAB_RESOURCE_B"},
}


def _synthetic(value, field):
    if not isinstance(value, str) or not LAB_PATTERN.fullmatch(value):
        raise SecurityError(f"{field}: use somente identificadores fictícios NEXUS_LAB_*.", "synthetic_fixture_required")
    return value


def _field(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value):
        raise SecurityError("Nome de parâmetro inválido.", "invalid_appsec_input")
    return value


def _path(value):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        raise SecurityError("Informe um caminho relativo à origem, iniciado por /.", "invalid_appsec_input")
    return network._url("http://nexus-lab.example" + value)["path"]


def _environment(scope, lab_confirmation):
    classification = scope.get("environment_class")
    allowed = classification in {"lab", "staging"} if classification is not None else str(scope.get("environment", "")).strip().casefold() in ENVIRONMENTS
    if lab_confirmation is not True or not allowed:
        raise SecurityError("Teste ativo exige ambiente lab/staging e confirmação explícita de dados fictícios.", "lab_approval_required", "permission")


def _preview(scope, target, test, lab_confirmation):
    _environment(scope, lab_confirmation)
    destination = network.ScopePolicy(scope).authorize_target(target, test, resolve=False)
    return {"tool": test, "target": destination["url"], "scope_id": scope.get("id"),
            "scope_revision": scope.get("revision"), "environment": scope.get("environment"),
            "limits": {"requests": MAX_REQUESTS, "seconds": MAX_SECONDS, "response_bytes": MAX_RESPONSE,
                       "concurrency": 1, "redirects": False},
            "impact": "Requisições HTTP limitadas em registros e contas fictícios. Pode gerar logs; não extrai tabelas ou credenciais.",
            "approval_required": True}


def preview_sqli(scope, target, parameter="name", baseline="NEXUS_LAB_A", marker="NEXUS_LAB_SQLI_MARKER_A", lab_confirmation=False):
    result = _preview(scope, target, "appsec_sqli", lab_confirmation)
    result.update(parameter=_field(parameter), baseline=_synthetic(baseline, "baseline"),
                  marker=_synthetic(marker, "marker"), requests_planned=6,
                  checks=["baseline_synthetic_marker", "quoted_value", "boolean_and_pair_repeated"],
                  exclusions=["OR/UNION", "time-based probes", "database enumeration", "writes"])
    return result


def _fixture(value):
    source = DEFAULT_FIXTURE if value is None else value
    if not isinstance(source, dict) or set(source) - set(DEFAULT_FIXTURE):
        raise SecurityError("Configuração de contas fictícias inválida.", "invalid_appsec_input")
    result = {}
    for name in ("login_path", "logout_path"):
        result[name] = _path(source.get(name, DEFAULT_FIXTURE[name]))
    for name in ("username_field", "password_field"):
        result[name] = _field(source.get(name, DEFAULT_FIXTURE[name]))
    for name in ("account_a", "account_b"):
        row = source.get(name, DEFAULT_FIXTURE[name])
        if not isinstance(row, dict) or set(row) != {"username", "password", "resource", "marker"}:
            raise SecurityError("Cada conta exige username/password/resource/marker fictícios.", "invalid_appsec_input")
        result[name] = {key: _synthetic(row[key], key) for key in ("username", "password", "marker")}
        result[name]["resource"] = _path(row["resource"])
        if "NEXUS_LAB_" not in result[name]["resource"]:
            raise SecurityError("O recurso deve identificar explicitamente o registro NEXUS_LAB_*.", "synthetic_fixture_required")
    if (result["account_a"]["username"] == result["account_b"]["username"] or
            result["account_a"]["resource"] == result["account_b"]["resource"] or
            result["account_a"]["marker"] == result["account_b"]["marker"]):
        raise SecurityError("Use contas, recursos e marcadores A e B distintos.", "invalid_appsec_input")
    return result


def preview_auth(scope, target, fixture=None, synthetic_accounts_confirmed=False, lab_confirmation=False):
    result = _preview(scope, target, "appsec_auth", lab_confirmation)
    if network._url(target)["path"] != "/":
        raise SecurityError("AUTH recebe a origem com caminho /; configure os endpoints na fixture.", "invalid_appsec_input")
    if synthetic_accounts_confirmed is not True:
        raise SecurityError("Confirme que ambas as contas e dados são fictícios e preparados para auditoria.", "synthetic_accounts_required", "permission")
    config = _fixture(fixture)
    result.update(login_path=config["login_path"], logout_path=config["logout_path"],
                  resources=[config["account_a"]["resource"], config["account_b"]["resource"]],
                  requests_planned=12, checks=["anonymous_A_B", "account_A_B_access_matrix", "cookie_attributes", "logout_replay", "cors_untrusted_origin"],
                  exclusions=["password guessing", "real credentials", "password recovery", "token expiration clock", "full CSRF validation", "password storage"])
    return result


class _Transport:
    def __init__(self, scope, test, cancel=None, scope_loader=None):
        self.scope, self.test, self.cancel, self.scope_loader = scope, test, cancel, scope_loader
        self.started, self.requests, self.failures = time.monotonic(), 0, 0

    def check(self):
        stopped = self.cancel.is_set() if hasattr(self.cancel, "is_set") else self.cancel() if self.cancel else False
        if stopped:
            raise SecurityError("Auditoria interrompida; ações já feitas não são desfeitas.", "cancelled")
        if time.monotonic() - self.started >= MAX_SECONDS:
            raise SecurityError("Orçamento de tempo esgotado.", "appsec_timeout")
        if self.requests >= MAX_REQUESTS or self.failures >= 3:
            raise SecurityError("Limite de requisições ou erros consecutivos atingido.", "appsec_limit")
        fresh = self.scope_loader() if self.scope_loader else self.scope
        if any(fresh.get(k) != self.scope.get(k) for k in ("id", "revision")):
            raise SecurityError("Escopo alterado durante a execução.", "scope_changed", "permission")
        _environment(fresh, True)
        return fresh

    def request(self, url, *, method="GET", query=None, form=None, cookies=None, origin=None):
        scope = self.check()
        destination = network.ScopePolicy(scope).authorize_target(url, self.test)
        if method not in {"GET", "POST"}:
            raise SecurityError("Método não permitido.", "invalid_appsec_input")
        path = destination["path"] + ("?" + urlencode(query) if query else "")
        body = urlencode(form).encode("ascii") if form else b""
        headers = {"Host": destination["authority"], "User-Agent": "NEXUS-AppSec/2.0", "Accept": "application/json,text/plain",
                   "Accept-Encoding": "identity", "Connection": "close"}
        if body:
            headers.update({"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))})
        if cookies:
            headers["Cookie"] = cookies
        if origin:
            headers["Origin"] = origin
        if any(any(ord(c) < 32 or ord(c) == 127 for c in value) for value in headers.values()):
            raise SecurityError("Cabeçalho inválido.", "invalid_appsec_input")
        deadline = min(self.started + MAX_SECONDS, time.monotonic() + network.NETWORK_TIMEOUT)
        handle = None
        self.requests += 1
        try:
            handle, address = network._connect(destination, deadline)
            if destination["scheme"] == "https":
                handle = network._tls(handle, destination, deadline)
            handle.sendall((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii") + body)
            data = bytearray()
            while True:
                self.check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                handle.settimeout(min(remaining, 0.5))
                try:
                    block = handle.recv(min(8192, MAX_RESPONSE + MAX_HEADERS + 1 - len(data)))
                except TimeoutError:
                    continue
                if not block:
                    break
                data.extend(block)
                header_end = data.find(b"\r\n\r\n")
                if (header_end < 0 and len(data) > MAX_HEADERS or header_end > MAX_HEADERS or
                        len(data) > MAX_RESPONSE + MAX_HEADERS):
                    raise network.ProtocolEvidenceError("Resposta excede o limite do adaptador.")
            class BufferedSocket:
                def makefile(self, *_args, **_kwargs):
                    return io.BytesIO(data)
            response = http.client.HTTPResponse(BufferedSocket())
            response.begin()
            if response.getheader("Content-Encoding", "identity").lower() not in {"identity", ""}:
                raise network.ProtocolEvidenceError("Resposta comprimida não foi aceita.")
            content = response.read(MAX_RESPONSE + 1)
            if len(content) > MAX_RESPONSE:
                raise network.ProtocolEvidenceError("Corpo excede o limite do adaptador.")
            self.failures = self.failures + 1 if response.status >= 500 or response.status in {429, 503} else 0
            return {"status": response.status, "body": content, "headers": response.headers,
                    "address": address, "redirect_followed": False}
        finally:
            if handle is not None:
                handle.close()


def _finding(identifier, title, severity, evidence, recommendation, *, confirmed=True, cwe=None):
    return {"id": identifier, "title": title, "severity": severity, "confidence": "high" if confirmed else "medium",
            "confirmed": confirmed, "validation": "confirmed_controlled" if confirmed else "dynamic_indication",
            "cwe": cwe, "evidence": evidence, "recommendation": recommendation}


def _result(tool, target, transport, findings, evidence, **extra):
    return redact_secrets({"ok": True, "tool": tool, "target": target, "created_at": utcnow(),
                          "duration_seconds": round(time.monotonic() - transport.started, 3),
                          "requests": transport.requests, "findings": findings, "evidence": evidence,
                          "coverage": "bounded synthetic fixtures", "raw_responses_retained": False,
                          "limitations": ["Sem cobertura de todos os parâmetros, dialetos SQL ou fluxos de autenticação.",
                                          "Nenhum achado nesta cobertura não garante segurança."], **extra})


def _error(tool, target, exc, transport, findings=None):
    # Never include exception text from HTTP parsers or application content.
    code = getattr(exc, "code", "APPSEC_PROTOCOL" if isinstance(exc, (http.client.HTTPException, network.ProtocolEvidenceError)) else "APPSEC_FAILED")
    try:
        safe_target = network._url(target)["url"]
    except (ValueError, TypeError):
        safe_target = "[URL inválida omitida]"
    return {"ok": False, "tool": tool, "target": safe_target, "code": code,
            "error": str(exc) if isinstance(exc, SecurityError) else f"Falha técnica ({type(exc).__name__}); dados HTTP omitidos.",
            "requests": transport.requests, "findings": findings or [], "raw_responses_retained": False}


def run_sqli(scope, target, parameter="name", baseline="NEXUS_LAB_A", marker="NEXUS_LAB_SQLI_MARKER_A", lab_confirmation=False, *, cancel=None, scope_loader=None):
    transport = _Transport(scope, "appsec_sqli", cancel, scope_loader)
    try:
        preview_sqli(scope, target, parameter, baseline, marker, lab_confirmation)
        rows = []
        values = [("baseline", baseline), ("quote", baseline + "'"),
                  ("true_1", baseline + "' AND '1'='1"), ("false_1", baseline + "' AND '1'='2"),
                  ("true_2", baseline + "' AND '1'='1"), ("false_2", baseline + "' AND '1'='2")]
        for label, value in values:
            response = transport.request(target, query={parameter: value})
            rows.append({"case": label, "status": response["status"], "synthetic_marker_present": marker.encode() in response["body"]})
        present = {row["case"]: row["synthetic_marker_present"] and 200 <= row["status"] < 300 for row in rows}
        confirmed = all(present[k] for k in ("baseline", "true_1", "true_2")) and all(not present[k] for k in ("false_1", "false_2")) and all(200 <= row["status"] < 300 for row in rows if row["case"].startswith("false"))
        findings = []
        if confirmed:
            findings.append(_finding("APPSEC-SQLI-BOOLEAN", "SQL Injection confirmada com marcador fictício", "high", {"parameter": parameter, "cases": rows},
                                     "Use consultas parametrizadas e privilégios mínimos; repita a regressão com os mesmos marcadores.", cwe="CWE-89"))
        elif present["baseline"] and rows[1]["status"] >= 500:
            findings.append(_finding("APPSEC-SQLI-INDICATION", "Indício de erro com aspas; SQLi não confirmada", "medium", {"parameter": parameter, "cases": rows},
                                     "Correlacione com o Code Auditor e diagnóstico local; erro HTTP isolado não confirma SQLi.", confirmed=False, cwe="CWE-89"))
        for finding in findings:
            finding.update(endpoint=network._url(target)["url"], parameter=parameter)
        status = "confirmed_controlled" if confirmed else "dynamic_indication" if findings else "no_finding_in_coverage" if present["baseline"] else "inconclusive"
        return _result("appsec_sqli", target, transport, findings, {"parameter": parameter, "cases": rows, "no_data_expansion": True}, validation=status)
    except (ValueError, OSError, http.client.HTTPException) as exc:
        return _error("appsec_sqli", target, exc, transport)


def _cookies(response):
    values, flags = [], []
    for raw in response["headers"].get_all("Set-Cookie", [])[:8]:
        if len(raw) > 4096:
            continue
        parsed = SimpleCookie()
        try:
            parsed.load(raw)
        except CookieError:
            continue
        for name, morsel in parsed.items():
            if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name) and re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,512}", morsel.value):
                values.append(name + "=" + morsel.value)
                flags.append({"name": name, "httponly": bool(morsel["httponly"]), "secure": bool(morsel["secure"]),
                              "samesite": morsel["samesite"].lower() if morsel["samesite"].lower() in {"strict", "lax", "none"} else "missing_or_unknown"})
    return "; ".join(values), flags


def run_auth(scope, target, fixture=None, synthetic_accounts_confirmed=False, lab_confirmation=False, *, cancel=None, scope_loader=None):
    transport = _Transport(scope, "appsec_auth", cancel, scope_loader)
    findings, matrix, cookie_flags = [], [], []
    try:
        preview_auth(scope, target, fixture, synthetic_accounts_confirmed, lab_confirmation)
        config = _fixture(fixture)
        parsed = urlsplit(network._url(target)["url"])
        base = parsed.scheme + "://" + parsed.netloc
        accounts = {"A": config["account_a"], "B": config["account_b"]}
        cookies = {}
        def access(actor, owner, jar=None, origin=None):
            account = accounts[owner]
            response = transport.request(base + account["resource"], cookies=jar, origin=origin)
            present = account["marker"].encode() in response["body"]
            row = {"actor": actor, "resource_owner": owner, "endpoint": account["resource"],
                   "status": response["status"], "synthetic_marker_present": present}
            matrix.append(row)
            return response, row
        for owner in ("A", "B"):
            _, row = access("anonymous", owner)
            if row["synthetic_marker_present"] and 200 <= row["status"] < 300:
                findings.append(_finding("APPSEC-AUTH-ANONYMOUS", "Recurso fictício acessível sem autenticação", "high", row,
                                         "Exija autenticação e autorização por objeto.", cwe="CWE-306"))
        for actor in ("A", "B"):
            account = accounts[actor]
            response = transport.request(base + config["login_path"], method="POST", form={config["username_field"]: account["username"], config["password_field"]: account["password"]})
            jar, flags = _cookies(response)
            cookie_flags.extend({"account": actor, **row} for row in flags)
            cookies[actor] = jar
            if not 200 <= response["status"] < 300 or not jar:
                raise SecurityError(f"Login da conta fictícia {actor} não comprovado; resultado inconclusivo.", "fixture_login_failed")
            _, own = access(actor, actor, jar)
            if not (200 <= own["status"] < 300 and own["synthetic_marker_present"]):
                raise SecurityError(f"Recurso próprio da conta {actor} não comprovado; matriz inconclusiva.", "fixture_resource_failed")
            other = "B" if actor == "A" else "A"
            _, cross = access(actor, other, jar)
            if 200 <= cross["status"] < 300 and cross["synthetic_marker_present"]:
                findings.append(_finding("APPSEC-BOLA", "Acesso entre contas fictícias confirmado", "high", cross,
                                         "Valide o proprietário e as permissões do objeto no servidor em cada requisição.", cwe="CWE-639"))
        response, _ = access("A_cors", "A", cookies["A"], "https://nexus-untrusted.invalid")
        allowed = response["headers"].get("Access-Control-Allow-Origin", "")
        credentialed = response["headers"].get("Access-Control-Allow-Credentials", "").lower() == "true"
        cors = {"untrusted_origin_reflected": allowed == "https://nexus-untrusted.invalid", "allow_credentials": credentialed,
                "wildcard_origin": allowed == "*"}
        if cors["untrusted_origin_reflected"] and credentialed:
            findings.append(_finding("APPSEC-CORS-CREDENTIALS", "CORS aceita origem não confiável com credenciais", "medium", cors,
                                     "Use lista explícita de origens confiáveis e revise necessidade de credenciais.", cwe="CWE-942"))
        logout = transport.request(base + config["logout_path"], method="POST", cookies=cookies["A"])
        _, replay = access("A_after_logout", "A", cookies["A"])
        if 200 <= logout["status"] < 300 and 200 <= replay["status"] < 300 and replay["synthetic_marker_present"]:
            findings.append(_finding("APPSEC-SESSION-LOGOUT", "Sessão fictícia continua válida após logout", "medium", replay,
                                     "Invalide a sessão no servidor e repita o teste com a sessão anterior.", cwe="CWE-613"))
        transport.request(base + config["logout_path"], method="POST", cookies=cookies["B"])
        for flags in cookie_flags:
            missing = [name for name in ("httponly", "secure") if not flags[name] and (name != "secure" or parsed.scheme == "https")]
            if flags["samesite"] == "missing_or_unknown":
                missing.append("samesite")
            if missing:
                findings.append(_finding("APPSEC-COOKIE-ATTRIBUTES", "Atributos de cookie de sessão ausentes", "low", {**flags, "missing": missing},
                                         "Configure HttpOnly, Secure em HTTPS e SameSite compatível com a aplicação.", cwe="CWE-614"))
        for finding in findings:
            endpoint = finding["evidence"].get("endpoint")
            if not endpoint:
                endpoint = accounts["A"]["resource"] if finding["id"] == "APPSEC-CORS-CREDENTIALS" else config["login_path"]
            finding["endpoint"] = base + endpoint
        return _result("appsec_auth", target, transport, findings, {"access_matrix": matrix, "cookie_attributes": cookie_flags,
                       "cors": cors, "logout_status": logout["status"], "credentials_retained": False,
                       "http_lab_secure_cookie_not_asserted": parsed.scheme != "https"},
                       not_tested=["token expiration", "password recovery", "password hashing", "CSRF state-changing workflows", "account enumeration", "administrator roles"])
    except (ValueError, OSError, http.client.HTTPException) as exc:
        return _error("appsec_auth", target, exc, transport, findings)
