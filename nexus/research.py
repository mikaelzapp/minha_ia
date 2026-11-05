"""Pesquisa verificável, relatórios e navegação Tor separada do tráfego direto."""
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import ipaddress
import json
import shutil
from pathlib import Path
import socket
import sqlite3
import uuid
from urllib.parse import urlencode, urljoin, urlsplit

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from .security.common import redact_secrets
from .tools import Tools, ToolError, _definition, STR, INT, MAX_RESPONSE

DEFINITIONS = {
    "search_many": _definition("search_many", "Pesquisa de uma a três consultas públicas sequenciais com fontes reais, provedores, erros e datas fornecidas. Não inventa resultados.", {"queries": {"type": "array", "items": STR}, "max_results": INT}, ("queries",)),
    "tor_read": _definition("tor_read", "Lê página pública HTTP/HTTPS ou onion v3 somente por Tor explicitamente ativado e verificado, sem fallback direto e sem cookies pessoais.", {"url": STR}, ("url",)),
    "tor_search": _definition("tor_search", "Consulta DuckDuckGo público através de Tor verificado e retorna URLs públicas/onion, sem baixar documentos, contornar CAPTCHA ou fabricar índices onion.", {"query": STR, "max_results": INT}, ("query",)),
    "tor_browser_open": _definition("tor_browser_open", "Renderiza URL pública/onion no Chromium isolado, com rede atendida somente pelo transporte Tor, sem downloads ou ações de escrita.", {"url": STR}, ("url",)),
    "research_report": _definition("research_report", "Recupera evidência de pesquisa desta conversa/projeto pelo report_id.", {"report_id": STR}, ("report_id",)),
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def tor_url(base, url):
    if not isinstance(url, str) or len(url) > 4096:
        raise ToolError("URL Tor inválida ou maior que 4096 caracteres.")
    host = (urlsplit(url).hostname or "").lower()
    if host.endswith(".onion"):
        parsed = base._onion_url(url)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        parsed, host, port = Tools._url(url)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not Tools._public_ip(str(address)):
            raise ToolError("Endereço privado ou reservado não é uma página pública Tor.")
    if port not in {80, 443}:
        raise ToolError("A leitura Tor permite somente HTTP/HTTPS nas portas padrão.")
    return parsed, host, port


def tor_details(base, response):
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(response["body"], "html.parser")
    links, seen = [], set()
    for anchor in soup.find_all("a", href=True):
        target = urljoin(response["url"], anchor["href"])
        try:
            tor_url(base, target)
        except (ValueError, ToolError):
            continue
        if target not in seen:
            seen.add(target)
            links.append({"text": anchor.get_text(" ", strip=True)[:200], "url": target})
        if len(links) >= 60:
            break
    return {"links": links, "tables": Tools._html_details(soup, response["url"])["tables"]}


class TorBrowser(Tools):
    """Rede do Chromium bloqueada; cada requisição permitida usa requests+SOCKS5H."""
    def __init__(self, base):
        super().__init__(base.root, base.data_dir / "research-tor", tor_enabled=base.tor_enabled, tor_proxy=base.tor_proxy)
        self.validator = base

    def _url(self, url, **_kwargs):
        return tor_url(self.validator, url)

    def _browser_open(self, url):
        _, host, _ = self._url(url)
        self.validator._tor_check()
        self._start_browser()
        self._browser_host = host
        self._browser_write = False
        self._browser_errors.clear()
        response = self._page.goto(url, wait_until="domcontentloaded")
        if response is None or not 200 <= response.status < 300:
            raise ToolError("Navegação Tor não retornou página HTTP bem-sucedida.")
        result = self._snapshot()
        result.update(via_tor=True, notice="Navegador isolado, proxy direto bloqueado e transporte exclusivamente Tor. Sem garantia de anonimato absoluto.")
        return result

    def _browser_route(self, route):
        request = route.request
        try:
            _, host, _ = self._url(request.url)
            if host != self._browser_host or request.method not in {"GET", "HEAD"}:
                raise ToolError("Apenas leitura do domínio selecionado é permitida no navegador Tor.")
            result = self.validator._tor_request(request.url)
            headers = {key: value for key, value in result["headers"].items() if key not in
                       {"content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie"}}
            if "attachment" in headers.get("content-disposition", "").lower():
                raise ToolError("Downloads Tor não são automáticos.")
            route.fulfill(status=result["status"], headers=headers, body=result["body"])
        except Exception as exc:
            self._record_browser_error("blocked_tor_request", str(exc) if isinstance(exc, ToolError) else type(exc).__name__)
            route.abort("blockedbyclient")

    def _html_details(self, soup, url):
        return tor_details(self.validator, {"body": str(soup).encode(), "url": url})

    def _snapshot(self):
        result = super()._snapshot()
        # Contexto/cookies ficam separados; screenshots usam o endpoint local
        # existente, que só serve nomes PNG gerados pelo próprio NEXUS.
        source = self.data_dir / result["screenshot"]
        destination = self.validator.data_dir / result["screenshot"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as target, source.open("rb") as current:
            shutil.copyfileobj(current, target)
        source.unlink()
        return result


class Research:
    def __init__(self, base, data_dir, session_id=None, project_id=None, search=None):
        self.base, self.root = base, Path(data_dir) / "research"
        self.session_id, self.project_id = session_id, project_id
        self.search = search or {}
        self.browser = None
        for path in (self.root, *self.root.parents):
            if path.exists() and Tools._is_link(path):
                raise ToolError("Armazenamento de pesquisa não pode atravessar links.")
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "research.sqlite3"
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,session_id TEXT,project_id TEXT,created_at TEXT,result TEXT NOT NULL)")

    @contextmanager
    def connection(self):
        for path in (self.root, *self.root.parents):
            if Tools._is_link(path):
                raise ToolError("Armazenamento de pesquisa alterado.")
        for candidate in (self.database, *(Path(str(self.database) + suffix) for suffix in ("-journal", "-wal", "-shm"))):
            if (candidate.exists() or candidate.is_symlink()) and (Tools._is_link(candidate) or candidate.stat().st_nlink > 1 or not candidate.is_file()):
                raise ToolError("Banco de pesquisa ou arquivo auxiliar inválido.")
        db = sqlite3.connect(self.database, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def schemas(self, mode):
        if mode not in {"RESEARCH", "AGENT", "CODE"}:
            return []
        return [copy.deepcopy(spec) for name, spec in DEFINITIONS.items() if not name.startswith("tor_") or self.base.tor_enabled]

    @staticmethod
    def arguments(name, args):
        if name not in DEFINITIONS or not isinstance(args, dict):
            raise ToolError("Ferramenta de pesquisa ou argumentos inválidos.")
        spec = DEFINITIONS[name]["function"]["parameters"]
        if set(args) - set(spec["properties"]) or any(key not in args for key in spec["required"]):
            raise ToolError("Argumentos de pesquisa ausentes ou desconhecidos.")
        for key, value in args.items():
            kind = spec["properties"][key]["type"]
            if not isinstance(value, {"string": str, "array": list, "integer": int}[kind]) or kind == "integer" and isinstance(value, bool):
                raise ToolError("Tipo inválido no argumento de pesquisa.")
        if "max_results" in args and not 1 <= args["max_results"] <= 10:
            raise ToolError("Quantidade de resultados deve ser de 1 a 10.")
        return dict(args)

    def approval(self, name, args):
        self.arguments(name, args)
        return None

    def save(self, result):
        identity = uuid.uuid4().hex
        safe = redact_secrets(result)
        text = json.dumps(safe, ensure_ascii=False)
        if len(text.encode()) > 2 * 1024 * 1024:
            raise ToolError("Relatório de pesquisa excedeu 2 MiB.")
        with self.connection() as db:
            db.execute("INSERT INTO reports VALUES(?,?,?,?,?)", (identity, self.session_id, self.project_id, _now(), text))
        return {**safe, "report_id": identity}

    def reports(self):
        with self.connection() as db:
            conditions, args = [], []
            for key, value in (("project_id", self.project_id), ("session_id", self.session_id)):
                if value is not None:
                    conditions.append(key + "=?")
                    args.append(value)
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            rows = db.execute("SELECT id,session_id,project_id,created_at,json_extract(result,'$.tool') AS tool,json_extract(result,'$.ok') AS ok FROM reports" + where + " ORDER BY created_at DESC LIMIT 100", args).fetchall()
        return [{**dict(row), "ok": bool(row["ok"])} for row in rows]

    def report(self, identity):
        if not isinstance(identity, str) or len(identity) != 32 or any(char not in "0123456789abcdef" for char in identity):
            raise ToolError("ID de relatório inválido.")
        with self.connection() as db:
            row = db.execute("SELECT * FROM reports WHERE id=?", (identity,)).fetchone()
        if not row or self.project_id is not None and row["project_id"] != self.project_id or self.session_id is not None and row["session_id"] != self.session_id:
            raise ToolError("Relatório não pertence à conversa/projeto atual.")
        return {**dict(row), "result": json.loads(row["result"])}

    def execute(self, name, args):
        try:
            args = self.arguments(name, args)
            if name == "research_report":
                return {"ok": True, "data": self.report(args["report_id"])}
            if name == "search_many":
                queries = args["queries"]
                if not 1 <= len(queries) <= 3 or any(not isinstance(query, str) or not query.strip() or len(query) > 500 for query in queries):
                    raise ToolError("Forneça de uma a três consultas de até 500 caracteres.")
                rows = []
                for query in dict.fromkeys(queries):
                    rows.append({"query": query, **self.base.execute("search_web", {"query": query, "max_results": min(args.get("max_results", 5), self.search.get("max_results", 10))})})
                result = {"ok": any(row.get("ok") and row.get("results") for row in rows), "queries": rows,
                          "performed": any(row.get("ok") and row.get("results") for row in rows), "via_tor": False}
            elif name == "tor_read":
                self.base._validate_tor_proxy()
                tor_url(self.base, args["url"])
                self.base._tor_check()
                current = args["url"]
                for hop in range(5):
                    tor_url(self.base, current)
                    raw = self.base._tor_request(current)
                    if raw["status"] in {301, 302, 303, 307, 308}:
                        if hop == 4 or not raw["headers"].get("location"):
                            raise ToolError("Redirecionamento Tor excessivo ou incompleto.")
                        current = urljoin(current, raw["headers"]["location"])
                        continue
                    result = {"ok": True, **Tools._page_text(raw), **tor_details(self.base, raw), "via_tor": True, "performed": True}
                    break
            elif name == "tor_search":
                query = args["query"]
                self.base._search_query(query)
                self.base._tor_check()
                raw = self.base._tor_request("https://html.duckduckgo.com/html/?" + urlencode({"q": query}))
                if raw["status"] != 200:
                    raise ToolError("O buscador via Tor não retornou HTTP 200; nenhum resultado foi inventado.")
                found = []
                limit = min(args.get("max_results", 5), self.search.get("max_results", 10))
                for row in Tools._parse_duckduckgo(raw):
                    try:
                        tor_url(self.base, row["url"])
                    except (ToolError, ValueError):
                        continue
                    found.append({"title": row["title"], "url": row["url"], "snippet": row.get("content", "")[:1000], "published_date": None})
                    if len(found) >= limit:
                        break
                result = {"ok": bool(found), "performed": bool(found), "query": query, "results": found, "via_tor": True,
                          "provider": "duckduckgo/html via Tor", "note": "Busca pública via Tor; não é índice onion garantido. Não contorna CAPTCHA."}
                if not found:
                    result["error"] = "Sem resultados verificáveis; buscador pode restringir saídas Tor."
            elif name == "tor_browser_open":
                if self.browser is None:
                    self.browser = TorBrowser(self.base)
                result = self.browser.execute("browser_open", args)
                result.update(via_tor=True, performed=result.get("ok", False))
            else:
                raise ToolError("Operação de pesquisa indisponível.")
            result.update(tool=name, retrieved_at=_now(), untrusted_external_data=True)
        except (ValueError, OSError) as exc:
            result = {"ok": False, "tool": name, "performed": False, "error": str(exc)[:1500], "source": "tool", "code": "research_error"}
        return self.save(result)

    def tor_status(self):
        parsed = urlsplit(self.base.tor_proxy)
        configured, reachable, reason = False, False, ""
        try:
            # Validates syntax without enabling Tor or making public requests.
            probe = Tools(self.base.root, self.base.data_dir, tor_enabled=True, tor_proxy=self.base.tor_proxy)
            try:
                probe._validate_tor_proxy()
                configured = True
            finally:
                probe.close()
            with socket.create_connection((parsed.hostname, parsed.port), timeout=0.3):
                reachable = True
        except (ValueError, OSError) as exc:
            reason = "Proxy local indisponível ou configuração inválida: " + type(exc).__name__
        return {"enabled": self.base.tor_enabled, "proxy": self.base.tor_proxy, "configured": configured,
                "reachable": reachable, "connected": False, "verified": False, "reason": reason or "Porta acessível não confirma saída Tor; use Verificar conexão."}

    def close(self):
        if self.browser:
            self.browser.close()


def install_research_routes(app, factory, blocking, inference, activity):
    router = APIRouter(prefix="/api/research")

    async def execute(tool, args, project_id=None, session_id=None):
        research = factory(session_id, project_id)
        try:
            async with inference():
                if tool == "tor_check":
                    result = await blocking(research.base.execute, tool, args)
                else:
                    result = await blocking(research.execute, tool, args)
            activity().add("research", {"tool": tool, "ok": result.get("ok", False), "report_id": result.get("report_id")})
            return result
        finally:
            await blocking(research.close)
            await blocking(research.base.close)

    @router.get("/tor/status")
    async def tor_status():
        research = factory()
        try:
            return await blocking(research.tor_status)
        finally:
            research.base.close()

    @router.post("/tor/check")
    async def tor_check():
        return await execute("tor_check", {})

    @router.post("/search")
    async def search(payload: dict):
        return await execute("search_many", payload)

    @router.get("/reports")
    async def reports(project_id: str | None = None):
        research = factory(None, project_id)
        try:
            return {"reports": await blocking(research.reports)}
        finally:
            research.base.close()

    @router.get("/reports/{identity}")
    async def report(identity: str, format: str = "json"):
        research = factory()
        try:
            value = await blocking(research.report, identity)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        finally:
            research.base.close()
        if format == "json":
            return JSONResponse(value, headers={"Content-Disposition": f'attachment; filename="nexus-research-{identity}.json"'})
        if format != "md":
            raise HTTPException(400, "Formato esperado: json ou md.")
        text = "# Pesquisa NEXUS\n\nData da consulta: " + value["created_at"] + "\n\n```json\n" + json.dumps(value["result"], ensure_ascii=False, indent=2) + "\n```\n"
        return PlainTextResponse(text, media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="nexus-research-{identity}.md"'})

    app.include_router(router)
