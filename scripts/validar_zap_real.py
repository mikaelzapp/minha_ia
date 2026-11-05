"""Validate the installed ZAP through the authenticated human API on owned fixtures.

No download or public target is accepted. Creates only one temporary loopback
HTTP service, persisted test reports and a scope that is revoked on completion.
The host must have at least 3 GiB available RAM before each native execution.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.security.reporting import sanitize


@contextmanager
def local_lab():
    observations = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            observations.append({"path": parsed.path, "method": self.command,
                                 "query_present": bool(parsed.query)})
            # All data and this reflection are synthetic; no browser executes it.
            query = parse_qs(parsed.query)
            reflected = next(iter(query.values()), ["NEXUS_ZAP_SYNTHETIC"])[0][:2048]
            if parsed.path == "/health":
                body = b'{"status":"synthetic-ok"}'
                content_type = "application/json"
            else:
                body = ("<!doctype html><html><head><title>NEXUS ZAP local fixture</title></head>"
                        "<body><h1>Owned synthetic fixture</h1><p>" + reflected + "</p></body></html>").encode()
                content_type = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # Intentionally missing CSP and anti-frame headers for passive rules.
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_HEAD = do_GET

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, observations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorized-test", action="store_true", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--report", default="security2-zap-runtime.json")
    parser.add_argument("--levels", nargs="+", choices=["PASSIVE", "SAFE ACTIVE"], default=["PASSIVE", "SAFE ACTIVE"])
    args = parser.parse_args()
    if args.base_url not in {"http://127.0.0.1:8765", "http://localhost:8765"}:
        parser.error("Somente a instância NEXUS local na porta 8765 é aceita.")
    if Path(args.report).name != args.report or not args.report.endswith(".json"):
        parser.error("Use somente um nome JSON dentro de reports.")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "native_tool": "zap",
              "real_authenticated_api": True, "authenticated_api_used": False,
              "native_jobs_submitted": 0, "owned_loopback_fixture": True,
              "public_targets": False, "downloads": False, "model_inference": False,
              "minimum_free_ram_bytes": 3 * 1024**3, "tests": {}, "errors": [],
              "raw_request_query_or_response_retained": False, "scope_cleanup": []}
    scope_id, live_job = None, None
    token = (ROOT / "data/auth.secret").read_text(encoding="ascii").strip()
    with httpx.Client(base_url=args.base_url, headers={"Authorization": "Bearer " + token},
                      timeout=30, trust_env=False) as client:
        def request(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            report["authenticated_api_used"] = True
            response.raise_for_status()
            return response.json()

        def resource_check():
            available = psutil.virtual_memory().available
            report["available_ram_last_precheck_bytes"] = available
            report["resource_precheck_passed"] = available >= report["minimum_free_ram_bytes"]
            if available < report["minimum_free_ram_bytes"]:
                raise RuntimeError("resource_budget: RAM livre inferior a 3 GiB; nenhum processo pesado adicional iniciado.")
            return available

        def preview(payload):
            return request("POST", "/api/security/v2/preview", json=payload)

        def decision(value, approved):
            return request("POST", "/api/security/v2/approvals/" + value["approval_id"] + "/decision",
                           json={"approved": approved})

        def wait(identity):
            deadline = time.monotonic() + 210
            while time.monotonic() < deadline:
                value = request("GET", "/api/security/v2/runs/" + identity)
                if value["state"] not in {"queued", "running", "cancelling"}:
                    return value
                time.sleep(.25)
            raise RuntimeError("Tarefa ZAP não encerrou dentro do prazo do ensaio.")

        try:
            report["available_ram_before_bytes"] = resource_check()
            status = request("GET", "/api/security/v2/status")
            configured = status.get("configuration", {}).get("zap", {})
            if configured.get("approved") is not True:
                raise RuntimeError("tool_unavailable: ZAP precisa estar configurado e aprovado previamente no painel.")
            report["configuration_digest"] = status["configuration_digest"]
            report["entrypoint_hashes"] = {key: configured.get(key) for key in ("sha256", "java_sha256")}
            with local_lab() as (server, observed):
                target = f"http://127.0.0.1:{server.server_port}/"
                report["lab_target"] = target
                scope = request("POST", "/api/security/scopes", json={
                    "name": "ZAP nativo — laboratório fictício " + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
                    "targets": ["127.0.0.1"], "allowed_ports": [server.server_port],
                    "allowed_tests": ["zap"], "environment": "lab", "environment_class": "lab",
                    "hosting": "own", "authorization_confirmed": True,
                    "purpose": "Validação do ZAP portátil somente no servidor loopback sintético deste script."})
                scope_id = scope["id"]
                report["scope_id"] = scope_id
                definition = {"openapi": "3.0.3", "paths": {
                    "/health": {"get": {"responses": {"200": {"description": "Synthetic fixture"}}}},
                    "/metadata": {"head": {}}, "/never-post": {"post": {}},
                    "/records/{id}": {"get": {}}}}
                base = {"engine": "zap", "scope_id": scope_id, "args": {
                    "target": target, "level": "PASSIVE", "duration_seconds": 180,
                    "rate_limit": 2, "openapi": definition}}
                count = len(observed)
                denied = decision(preview(base), False)
                assert denied.get("executed") is False and len(observed) == count
                report["tests"]["denied_approval_no_traffic"] = {"status": "passed", "requests": 0}
                for level in dict.fromkeys(args.levels):
                    free_ram = resource_check()
                    payload = {**base, "args": {**base["args"], "level": level}}
                    prepared = preview(payload)
                    count = len(observed)
                    started = time.monotonic()
                    approved = decision(prepared, True)
                    report["native_jobs_submitted"] += 1
                    live_job = approved["job"]["id"]
                    run = wait(live_job)
                    live_job = None
                    rows = observed[count:]
                    result = run.get("result", {})
                    evidence = result.get("evidence", {})
                    current = {"status": "passed" if run.get("ok") is True else "failed",
                               "run_id": run["id"], "report_id": run.get("report_id"),
                               "seconds": round(time.monotonic() - started, 3),
                               "available_ram_before_bytes": free_ram,
                               "result": result, "state": run["state"],
                               "operational_code": run.get("code"), "error": run.get("error"),
                               "observed_paths_methods": rows, "observed_requests": len(rows),
                               "observed_query_requests": sum(row["query_present"] for row in rows),
                               "active_input_coverage_confirmed": level != "PASSIVE" and any(row["query_present"] for row in rows)}
                    report["tests"][level.lower().replace(" ", "_") + "_openapi"] = current
                    if not run.get("ok"):
                        report["errors"].append(level + ": " + str(result.get("code") or run.get("code") or run["state"]))
                        break
                    assert evidence.get("version") == "2.17.0", "Versão nativa inesperada"
                    assert evidence.get("network_guard", {}).get("requests") == len(rows), "Tráfego observado diverge do proxy"
                    assert evidence.get("network_guard", {}).get("origin_pinned") is True
                    assert 0 < len(rows) <= evidence["network_guard"]["maximum_requests"]
                    assert {row["method"] for row in rows} <= {"GET", "HEAD"}
                    assert all(row["path"] != "/never-post" for row in rows)
                    assert {"/", "/health", "/metadata"} <= {row["path"] for row in rows}
                    assert evidence.get("discovery", {}).get("remote_definitions_fetched") is False
                    assert evidence.get("active_rules") == ([] if level == "PASSIVE" else [40012, 40018])
                    if level == "PASSIVE":
                        assert result.get("findings"), "Fixture sem CSP/anti-frame deve produzir indicação passiva"
                    exported = request("GET", "/api/security/v2/reports/" + run["report_id"])
                    assert exported["result"]["ok"] is True
                    current["persisted_report_verified"] = True
        except Exception as exc:
            report["fatal_error"] = sanitize(str(exc))[:1500]
            report["errors"].append(type(exc).__name__)
        finally:
            if live_job:
                try:
                    request("POST", "/api/security/v2/runs/" + live_job + "/cancel")
                    stopped = wait(live_job)
                    report["interrupted_job_cleanup"] = {"id": live_job, "state": stopped["state"]}
                except Exception as exc:
                    report["interrupted_job_cleanup"] = {"id": live_job, "error": sanitize(str(exc))[:500]}
            if scope_id:
                try:
                    revoked = request("DELETE", "/api/security/scopes/" + scope_id)
                    report["scope_cleanup"].append({"id": scope_id, "revoked": revoked.get("enabled") is False})
                except Exception as exc:
                    report["scope_cleanup"].append({"id": scope_id, "revoked": False, "error": sanitize(str(exc))[:500]})
    report["available_ram_after_bytes"] = psutil.virtual_memory().available
    report["ok"] = not report["errors"] and all(row["revoked"] for row in report["scope_cleanup"])
    report["limitations"] = [
        "Valida somente este laboratório HTTP loopback, sem alvos públicos, HTTPS, autenticação ou spider.",
        "Planos e regras ativas configurados não comprovam que todos os vetores foram testados.",
        "Achados do scanner são indicações a revisar; a fixture deliberadamente omite cabeçalhos de proteção.",
        "O proxy restringe requisições; RSS observado e diretório temporário não constituem sandbox de sistema operacional."]
    path = ROOT / "reports" / args.report
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(sanitize(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "report": str(path), "tests": list(report["tests"]),
                      "errors": report["errors"], "fatal_error": report.get("fatal_error")}, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
