"""Run the approved native Nuclei against one owned synthetic loopback fixture.

Uses the authenticated human API, three locally reviewed templates and a scope
revoked after the test. No template download, public target or model inference.
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
from urllib.parse import urlsplit

import httpx
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.security.reporting import sanitize

TEMPLATES = ["nexus-http-baseline", "nexus-exposed-openapi", "nexus-lab-synthetic-exposure"]
MIN_FREE_RAM = 512 * 1024**2


@contextmanager
def local_lab():
    observations = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            parsed = urlsplit(self.path)
            observations.append({"method": self.command, "path": parsed.path,
                                 "query_present": bool(parsed.query)})
            if parsed.path == "/openapi.json":
                body = b'{"openapi":"3.0.3","info":{"title":"NEXUS synthetic lab","version":"1.0"},"paths":{}}'
                content_type = "application/json"
            elif parsed.path == "/nexus-lab-marker":
                body = b"NEXUS_SYNTHETIC_EXPOSURE_V1"
                content_type = "text/plain"
            else:
                body = b"NEXUS owned synthetic HTTP fixture"
                content_type = "text/plain"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
    parser.add_argument("--report", default="security-runtime-nuclei-real.json")
    args = parser.parse_args()
    if args.base_url not in {"http://127.0.0.1:8765", "http://localhost:8765"}:
        parser.error("Somente a instância NEXUS local na porta 8765 é aceita.")
    if Path(args.report).name != args.report or not args.report.endswith(".json"):
        parser.error("Use somente um nome JSON dentro de reports.")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "native_tool": "nuclei",
              "real_authenticated_api": True, "authenticated_api_used": False,
              "native_jobs_submitted": 0, "owned_loopback_fixture": True,
              "public_targets": False, "downloads": False, "model_inference": False,
              "minimum_free_ram_bytes": MIN_FREE_RAM, "tests": {}, "errors": [],
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
            report["resource_precheck_passed"] = available >= MIN_FREE_RAM
            if available < MIN_FREE_RAM:
                raise RuntimeError("resource_budget: RAM livre inferior a 512 MiB; nenhum scanner iniciado.")
            return available

        def prepare(payload):
            return request("POST", "/api/security/v2/preview", json=payload)

        def decide(value, approved):
            return request("POST", "/api/security/v2/approvals/" + value["approval_id"] + "/decision",
                           json={"approved": approved})

        def wait(identity):
            deadline = time.monotonic() + 115
            while time.monotonic() < deadline:
                value = request("GET", "/api/security/v2/runs/" + identity)
                if value["state"] not in {"queued", "running", "cancelling"}:
                    return value
                time.sleep(.2)
            raise RuntimeError("Tarefa Nuclei não encerrou dentro do prazo do ensaio.")

        try:
            report["available_ram_before_bytes"] = resource_check()
            status = request("GET", "/api/security/v2/status")
            configured = status.get("configuration", {}).get("nuclei", {})
            if configured.get("approved") is not True:
                raise RuntimeError("tool_unavailable: Nuclei precisa estar configurado e aprovado previamente no painel.")
            report["configuration_digest"] = status["configuration_digest"]
            report["entrypoint_sha256"] = configured.get("sha256")
            with local_lab() as (server, observed):
                target = f"http://127.0.0.1:{server.server_port}/"
                report["lab_target"] = target
                scope = request("POST", "/api/security/scopes", json={
                    "name": "Nuclei nativo — laboratório fictício " + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
                    "targets": ["127.0.0.1"], "allowed_ports": [server.server_port], "allowed_tests": ["nuclei"],
                    "environment": "lab", "environment_class": "lab", "hosting": "own", "authorization_confirmed": True,
                    "purpose": "Validação somente dos três templates locais revisados no servidor loopback sintético deste script."})
                scope_id = scope["id"]
                report["scope_id"] = scope_id
                payload = {"engine": "nuclei", "scope_id": scope_id, "args": {
                    "target": target, "level": "PASSIVE", "duration_seconds": 90,
                    "rate_limit": 2, "templates": TEMPLATES}}
                count = len(observed)
                denied = decide(prepare(payload), False)
                assert denied.get("executed") is False and len(observed) == count
                report["tests"]["denied_approval_no_traffic"] = {"status": "passed", "requests": 0}
                report["available_ram_before_native_bytes"] = resource_check()
                prepared = prepare(payload)
                count = len(observed)
                started = time.monotonic()
                approved = decide(prepared, True)
                report["native_jobs_submitted"] += 1
                live_job = approved["job"]["id"]
                run = wait(live_job)
                live_job = None
                result = run.get("result", {})
                evidence = result.get("evidence", {})
                rows = observed[count:]
                current = {"status": "passed" if run.get("ok") is True else "failed",
                           "run_id": run["id"], "report_id": run.get("report_id"),
                           "seconds": round(time.monotonic() - started, 3), "result": result,
                           "state": run["state"], "operational_code": run.get("code"), "error": run.get("error"),
                           "observed_paths_methods": rows, "observed_requests": len(rows)}
                report["tests"]["reviewed_pack_native"] = current
                if not run.get("ok"):
                    report["errors"].append(str(result.get("code") or run.get("code") or run["state"]))
                else:
                    assert evidence.get("version") == "3.11.1", "Versão nativa inesperada"
                    assert evidence.get("network_guard", {}).get("requests") == len(rows), "Tráfego observado diverge do proxy"
                    assert evidence.get("network_guard", {}).get("origin_pinned") is True
                    assert 0 < len(rows) <= evidence["network_guard"]["maximum_requests"]
                    assert {row["method"] for row in rows} == {"GET"}
                    assert {row["path"] for row in rows} == {"/", "/openapi.json", "/nexus-lab-marker"}
                    assert not any(row["query_present"] for row in rows)
                    assert {row["template_id"] for row in result.get("findings", [])} == set(TEMPLATES)
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
        "Valida somente três templates GET locais revisados no laboratório HTTP loopback.",
        "Não equivale ao catálogo de CVEs, a pentest completo, a exploração ou a auditoria de alvos públicos.",
        "O marcador de exposição é fictício e todas as indicações exigem revisão contextual.",
        "Proxy, monitoramento de RSS e diretório temporário não constituem sandbox do sistema operacional."]
    path = ROOT / "reports" / args.report
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(sanitize(report), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "report": str(path), "tests": list(report["tests"]),
                      "errors": report["errors"], "fatal_error": report.get("fatal_error")}, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
