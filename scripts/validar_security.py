"""Integração real: API autenticada, laboratório loopback e arquivos inofensivos.

Cria/retém um laboratório registrado e relatórios. Revoga os escopos de teste.
Não baixa modelos/amostras, não executa arquivos analisados, não faz inferência.
Use --public-research para validar consulta CVE e pesquisa de documentação pública.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class LabHandler(BaseHTTPRequestHandler):
    observations = 0

    def do_HEAD(self):
        type(self).observations += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--public-research", action="store_true")
    parser.add_argument("--report", default="security-integration.json")
    args = parser.parse_args()
    if Path(args.report).name != args.report or not args.report.endswith(".json"):
        parser.error("Informe somente o nome de um relatório JSON dentro de reports.")
    if args.base_url not in {"http://127.0.0.1:8765", "http://localhost:8765"}:
        parser.error("Este ensaio usa somente a instância loopback na porta 8765.")
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "real_api": True,
              "model_inference": False, "malware_executed": False, "tests": {}, "errors": []}
    tests, scope_ids = result["tests"], []
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = (ROOT / "data/auth.secret").read_text(encoding="ascii").strip()
    with httpx.Client(base_url=args.base_url, headers={"Authorization": "Bearer " + token},
                      trust_env=False, timeout=90) as client:
        def request(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()

        def job(tool, payload, mode="AGENT"):
            return request("POST", "/api/security/jobs", json={"tool": tool, "args": payload, "mode": mode})

        def record(name, callback):
            start = time.perf_counter()
            try:
                data = callback()
                tests[name] = {"status": "passed", "seconds": round(time.perf_counter() - start, 3), "evidence": data}
            except Exception as exc:
                tests[name] = {"status": "failed", "seconds": round(time.perf_counter() - start, 3), "error": str(exc)}
                result["errors"].append(name)

        try:
            record("authenticated_inventory", lambda: request("GET", "/api/security/status"))
            record("ollama_local_inventory", lambda: {"models": [item["name"] for item in request("GET", "/api/status")["ollama"]["models"]]})
            scope = request("POST", "/api/security/scopes", json={"name": "Laboratório local de validação Security Center",
                "targets": ["127.0.0.1", "localhost"], "environment": "laboratório loopback criado pelo ensaio",
                "purpose": "Somente o servidor HTTP efêmero deste script; sem alvos externos.",
                "allowed_tests": ["http_headers", "tcp_connect", "osint"], "authorization_confirmed": True})
            scope_ids.append(scope["id"])
            target = f"http://127.0.0.1:{server.server_port}/"

            def deny():
                before = LabHandler.observations
                prepared = job("security_http", {"scope_id": scope["id"], "target": target})
                assert prepared["requires_approval"] and LabHandler.observations == before
                denied = request("POST", f'/api/security/jobs/{prepared["approval_id"]}/decision', json={"approved": False})
                assert denied["executed"] is False and LabHandler.observations == before
                return {"code": denied["code"], "http_requests": 0}
            record("denied_approval_no_connection", deny)

            def head():
                prepared = job("security_http", {"scope_id": scope["id"], "target": target})
                data = request("POST", f'/api/security/jobs/{prepared["approval_id"]}/decision', json={"approved": True})
                assert data["ok"] and data["data"]["evidence"]["status"] == 200
                return data
            record("approved_http_loopback", head)

            def tcp():
                prepared = job("security_tcp", {"scope_id": scope["id"], "target": "127.0.0.1", "ports": [server.server_port]})
                data = request("POST", f'/api/security/jobs/{prepared["approval_id"]}/decision', json={"approved": True})
                assert data["ok"]
                return data
            record("approved_tcp_loopback", tcp)

            def preview():
                data = request("POST", "/api/security/dorks/preview", json={"scope_id": scope["id"], "domain": "localhost",
                    "operators": {"intitle": "documentação"}, "document_type": "pdf", "keywords": "manual", "max_results": 3})
                assert data["ok"] and "site:localhost" in data["data"]["query"]
                return data
            record("dork_preview_no_search", preview)

            def revoked():
                before = LabHandler.observations
                prepared = job("security_http", {"scope_id": scope["id"], "target": target})
                request("DELETE", "/api/security/scopes/" + scope["id"])
                data = request("POST", f'/api/security/jobs/{prepared["approval_id"]}/decision', json={"approved": True})
                assert not data["ok"] and data["code"] == "scope_revoked" and LabHandler.observations == before
                return {"code": data["code"], "source": data["source"], "http_requests": 0}
            record("revoked_scope_blocks_pending_approval", revoked)

            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as bundle:
                bundle.writestr("README.txt", "NEXUS harmless static analysis laboratory. No executable content.")
                bundle.writestr("metadata.json", '{"lab":true,"value":42}')
            content = buffer.getvalue()
            sample = request("POST", "/api/security/samples", params={"name": "nexus-harmless-lab.zip"},
                             content=content, headers={"Content-Type": "application/octet-stream"})
            assert sample["sha256"] == hashlib.sha256(content).hexdigest()
            result["sample"] = sample

            def static():
                data = job("security_static_file", {"sample_id": sample["id"]})
                assert data["ok"] and data["data"]["sha256"] == sample["sha256"] and data["data"]["executed"] is False
                assert data["data"]["yara"]["available"]
                return data
            record("static_hash_yara", static)

            def investigate():
                data = job("security_investigate", {"sample_id": sample["id"]})
                assert data["ok"] and data["data"]["rea"]["ok"]
                assert data["data"]["workflow"] == ["malware_lab", "rea"]
                return data
            record("static_and_rea_sequential_zip", investigate)

            lab = ROOT / "workspaces/security-center-lab"
            lab.mkdir(exist_ok=True)
            fixtures = {"audit_fixture.py": '# Laboratório estático. Função deliberadamente insegura, nunca chamada.\ndef interpret(text):\n    return eval(text)\n',
                        "README.md": "# Laboratório do Security Center\n\nArquivos inofensivos para análise estática. Não implante nem execute a função deliberadamente insegura.\n"}
            for name, text in fixtures.items():
                path = lab / name
                if not path.exists():
                    path.write_text(text, encoding="utf-8")
            project = next((item for item in request("GET", "/api/projects") if Path(item["path"]).name == lab.name), None)
            if not project:
                project = request("POST", "/api/projects", json={"name": "Security Center — laboratório inofensivo", "path": lab.name})
            result["project_id"] = project["id"]

            def audit():
                data = job("security_code_audit", {"project_id": project["id"]}, "REVIEW")
                assert data["ok"] and any(item["file"] == "audit_fixture.py" for item in data["findings"])
                return data
            record("registered_project_static_audit", audit)

            def windows():
                data = job("security_windows", {"section": "defender"}, "REVIEW")
                assert data["ok"], data.get("error")
                return data
            record("windows_defender_readonly", windows)

            def export():
                reports = request("GET", "/api/security/reports")["reports"]
                assert reports
                identity = reports[0]["id"]
                json_response = client.get(f"/api/security/reports/{identity}")
                md_response = client.get(f"/api/security/reports/{identity}", params={"format": "md"})
                assert json_response.status_code == md_response.status_code == 200
                assert "attachment" in md_response.headers["content-disposition"]
                assert "```json" in md_response.text
                return {"json": 200, "markdown": 200, "count": len(reports)}
            record("report_exports", export)

            if args.public_research:
                def cve():
                    data = job("security_cve", {"cve_id": "CVE-2021-44228"}, "RESEARCH")
                    assert data["ok"], data.get("error")
                    return data
                record("official_public_cve", cve)

                def search():
                    from nexus.tools import Tools
                    tools = Tools(ROOT / "workspaces", ROOT / "data")
                    try:
                        data = tools.execute("search_web", {"query": "YARA-X official Python documentation", "max_results": 3})
                        assert data.get("results"), data.get("error")
                        return data
                    finally:
                        tools.close()
                record("existing_public_technical_search", search)
            else:
                tests["public_research"] = {"status": "not_run", "reason": "Use --public-research; envia somente termos públicos e ID CVE, nunca amostras."}
        except Exception as exc:
            result["errors"].append(str(exc))
        finally:
            for identity in scope_ids:
                try:
                    request("DELETE", "/api/security/scopes/" + identity)
                except Exception as exc:
                    result["errors"].append("Falha ao revogar escopo de laboratório: " + str(exc))
            server.shutdown()
            server.server_close()
    result["ok"] = not result["errors"]
    destination = ROOT / "reports" / args.report
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": result["ok"], "tests": {key: item["status"] for key, item in tests.items()},
                      "errors": result["errors"], "report": str(destination)}, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
