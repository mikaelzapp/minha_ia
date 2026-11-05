"""Real authenticated Security Center 2 lab/copy/regression validation.

Creates only a new, synthetic project, two owned loopback services, reports and
revoked test scopes. No public hosts, models, downloads or unknown sample code.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import sys
import threading
import time

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.security_lab import LabServer, LabHandler, VULNERABLE_QUERY_SOURCE, FIXED_QUERY_SOURCE
from nexus.security.reporting import sanitize


@contextmanager
def running_lab(root, port=0):
    server = LabServer(("127.0.0.1", port), root=root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--report", default="security2-integration.json")
    args = parser.parse_args()
    if args.base_url not in {"http://127.0.0.1:8765", "http://localhost:8765"}:
        parser.error("Somente a instância local na porta 8765 é aceita.")
    if Path(args.report).name != args.report or not args.report.endswith(".json"):
        parser.error("Use somente um nome JSON dentro de reports.")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "real_authenticated_api": True,
        "public_network": False, "downloads": False, "model_inference": False,
        "unknown_sample_execution": False, "tests": {}, "errors": [], "scope_cleanup": []}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    project_dir = ROOT / "workspaces" / ("security2-lab-" + stamp)
    project_dir.mkdir(parents=True, exist_ok=False)
    (project_dir / "settings.json").write_text('{"fixed": false}\n', encoding="utf-8")
    (project_dir / "queries.py").write_text(VULNERABLE_QUERY_SOURCE, encoding="utf-8", newline="\n")
    (project_dir / "README.md").write_text(
        "# NEXUS Security Center 2 — laboratório fictício\n\n"
        "Este projeto foi criado pelo validador, sem dados reais. O serviço conhecido scripts/security_lab.py "
        "lê queries.py somente quando corresponde aos bytes/SHA de uma das duas fixtures conhecidas. "
        "O ensaio troca SQL construído por f-string por uma consulta com parâmetros, apenas na cópia supervisionada. "
        "Código desconhecido não é executado pelo serviço. settings.json fixed=false preserva o modo vulnerável "
        "de autenticação para a auditoria independente; esta correção cobre SQLi.\n", encoding="utf-8")
    (project_dir / "test_regression.py").write_text(
        "import sqlite3\nimport unittest\nfrom queries import lookup_name\n\n"
        "class ParameterizedQueryRegression(unittest.TestCase):\n"
        "    def test_owned_synthetic_record_is_preserved(self):\n"
        "        with sqlite3.connect(':memory:') as db:\n"
        "            db.execute('CREATE TABLE records(name TEXT, marker TEXT)')\n"
        "            db.execute('INSERT INTO records VALUES(?,?)', ('NEXUS_LAB_A', 'SYNTHETIC_MARKER'))\n"
        "            self.assertEqual(lookup_name(db, 'NEXUS_LAB_A'), [('SYNTHETIC_MARKER',)])\n\n"
        "    def test_boolean_sql_input_is_only_data(self):\n"
        "        with sqlite3.connect(':memory:') as db:\n"
        "            db.execute('CREATE TABLE records(name TEXT, marker TEXT)')\n"
        "            db.execute('INSERT INTO records VALUES(?,?)', ('NEXUS_LAB_A', 'SYNTHETIC_MARKER'))\n"
        "            self.assertEqual(lookup_name(db, \"NEXUS_LAB_A' AND '1'='1\"), [])\n", encoding="utf-8")
    report["project_path"] = str(project_dir)
    scope_ids = []
    token = (ROOT / "data/auth.secret").read_text(encoding="ascii").strip()
    with httpx.Client(base_url=args.base_url, headers={"Authorization": "Bearer " + token},
                      trust_env=False, timeout=60) as client:
        def request(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()

        def record(name, fn):
            started = time.perf_counter()
            try:
                evidence = fn()
                report["tests"][name] = {"status": "passed", "seconds": round(time.perf_counter() - started, 3), "evidence": evidence}
                return evidence
            except Exception as exc:
                report["tests"][name] = {"status": "failed", "seconds": round(time.perf_counter() - started, 3), "error": str(exc)}
                report["errors"].append(name)
                raise

        def preview(engine, args=None, **kwargs):
            return request("POST", "/api/security/v2/preview", json={"engine": engine, "args": args or {}, **kwargs})

        def approve(value):
            return request("POST", "/api/security/v2/approvals/" + value["approval_id"] + "/decision", json={"approved": True})

        def wait(identity, *, success=True):
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                result = request("GET", "/api/security/v2/runs/" + identity)
                if result["state"] not in {"queued", "running", "cancelling"}:
                    if success:
                        assert result["ok"], {key: result.get(key) for key in ("state", "code", "error", "result")}
                    return result
                time.sleep(.05)
            raise AssertionError("A tarefa local não encerrou em 45 segundos: " + identity)

        def execute(engine, args=None, **kwargs):
            return wait(approve(preview(engine, args, **kwargs))["job"]["id"])

        try:
            def inventory():
                value = request("GET", "/api/security/v2/status")
                assert len(value["modules"]) == 10
                return {"modules": [x["id"] for x in value["modules"]],
                        "native_scanners": value["scanners"], "ghidra": value["ghidra"], "limits": value["limits"]}
            record("tool_discovery", inventory)
            project = request("POST", "/api/projects", json={"name": "Security Center 2 — ensaio fictício " + stamp, "path": project_dir.name})
            report["project_id"] = project["id"]
            with running_lab(project_dir) as original, socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                fixed_port = reservation.getsockname()[1]
                scope_payload = {"name": "Security 2 QA loopback " + stamp, "targets": ["127.0.0.1"],
                    "allowed_ports": [original.server_port, fixed_port], "environment": "lab", "environment_class": "lab",
                    "hosting": "own", "authorization_confirmed": True,
                    "allowed_tests": ["http_headers", "tcp_connect", "appsec_sqli", "appsec_auth", "asset_inventory"],
                    "purpose": "Somente dois serviços loopback fictícios deste ensaio; nenhuma infraestrutura externa."}
                scope = request("POST", "/api/security/scopes", json=scope_payload)
                scope_ids.append(scope["id"])
                shared = {"scope_id": scope["id"], "project_id": project["id"]}
                report["lab_ports"] = [original.server_port, fixed_port]

                def denied():
                    count = len(original.observations)
                    value = preview("http_headers", {"target": original.url}, **shared)
                    result = request("POST", "/api/security/v2/approvals/" + value["approval_id"] + "/decision", json={"approved": False})
                    assert result["executed"] is False and len(original.observations) == count
                    return {"decision": result, "additional_http_requests": 0}
                record("approval_denied_no_network", denied)

                def sqli_before():
                    run = execute("appsec_sqli", {"target": original.url + "/sqli", "lab_confirmation": True}, **shared)
                    assert run["result"]["validation"] == "confirmed_controlled"
                    assert run["findings_count"] >= 1
                    return {"run_id": run["id"], "report_id": run["report_id"], "validation": run["result"]["validation"], "requests": run["result"]["requests"]}
                before = record("controlled_sqli_confirmed", sqli_before)

                def auth_before():
                    run = execute("appsec_auth", {"target": original.url, "lab_confirmation": True, "synthetic_accounts_confirmed": True}, **shared)
                    assert run["findings_count"] >= 4
                    value = request("GET", "/api/security/v2/reports/" + run["report_id"])
                    serialized = json.dumps(value)
                    assert "NEXUS_LAB_PASSWORD" not in serialized
                    assert all(session not in serialized for session in original.sessions)
                    return {"run_id": run["id"], "report_id": run["report_id"], "findings_count": run["findings_count"], "synthetic_credentials_retained": False}
                record("auth_bola_sessions_cookies_and_redaction", auth_before)

                def tcp():
                    run = execute("tcp_connect", {"target": "127.0.0.1", "ports": [original.server_port]}, **shared)
                    return {"run_id": run["id"], "report_id": run["report_id"], "result": run["result"]}
                record("authorized_tcp_probe", tcp)

                def exports():
                    values = {}
                    for format in ("json", "md", "html", "pdf"):
                        response = client.get("/api/security/v2/reports/" + before["report_id"], params={"format": format})
                        if format == "pdf" and response.status_code == 424:
                            values[format] = {"available": False, "code": 424, "reason": "Dependência opcional ausente; não foi instalada."}
                            continue
                        response.raise_for_status()
                        assert response.content
                        if format == "html":
                            assert "default-src 'none'" in response.text
                        values[format] = {"available": True, "bytes": len(response.content), "content_type": response.headers.get("content-type")}
                    return values
                record("report_exports_and_optional_pdf", exports)

                def outside_scope():
                    count = len(original.observations)
                    response = client.post("/api/security/v2/preview", json={"engine": "http_headers", "scope_id": scope["id"], "args": {"target": "http://127.0.0.2:" + str(original.server_port)}})
                    assert response.status_code == 400 and len(original.observations) == count
                    return {"status": response.status_code, "source": response.json().get("source"), "additional_http_requests": 0}
                record("out_of_scope_denied", outside_scope)

                def revoked():
                    extra = request("POST", "/api/security/scopes", json={**scope_payload, "name": "Security2 revocation " + stamp})
                    scope_ids.append(extra["id"])
                    pending = preview("http_headers", {"target": original.url}, scope_id=extra["id"])
                    request("DELETE", "/api/security/scopes/" + extra["id"])
                    count = len(original.observations)
                    response = client.post("/api/security/v2/approvals/" + pending["approval_id"] + "/decision", json={"approved": True})
                    assert response.status_code == 400 and response.json()["code"] == "scope_revoked"
                    assert len(original.observations) == count
                    return {"scope_id": extra["id"], "code": response.json()["code"], "additional_http_requests": 0}
                record("revocation_blocks_pending_approval", revoked)

                def cancel_queued():
                    entered, release = threading.Event(), threading.Event()
                    class HoldingHandler(LabHandler):
                        def do_HEAD(self):
                            if self.path == "/hold":
                                entered.set()
                                release.wait(5)
                            super().do_HEAD()
                    original.RequestHandlerClass = HoldingHandler
                    try:
                        first = approve(preview("http_headers", {"target": original.url + "/hold"}, **shared))["job"]["id"]
                        assert entered.wait(3), "O primeiro trabalho não entrou no laboratório controlado."
                        second = approve(preview("tcp_connect", {"target": "127.0.0.1", "ports": [original.server_port]}, **shared))["job"]["id"]
                        queued = request("GET", "/api/security/v2/runs/" + second)
                        assert queued["state"] == "queued"
                        decision = request("POST", "/api/security/v2/runs/" + second + "/cancel")
                        assert decision["cancellable"]
                        release.set()
                        assert wait(first)["ok"]
                        result = wait(second, success=False)
                        assert result["state"] == "cancelled" and not result.get("started_at")
                        return {"holding_run_id": first, "cancelled_run_id": second, "state": result["state"], "adapter_started": False}
                    finally:
                        release.set()
                        original.RequestHandlerClass = LabHandler
                record("cancel_queued_real_api", cancel_queued)

                def prepare():
                    source = request("GET", "/api/security/v2/reports/" + before["report_id"])
                    selected = next(f for f in source["result"]["findings"] if f.get("cwe") == "CWE-89")
                    value = request("POST", "/api/security/v2/remediation/preview", json={"report_id": before["report_id"],
                        "project_id": project["id"], "finding_ids": [selected["id"]],
                        "edits": [{"path": "queries.py", "content": FIXED_QUERY_SOURCE}],
                        "tests": [["python", "-m", "unittest", "discover", "-s", ".", "-p", "test_regression.py"]], "tests_authorized": True})
                    assert value["requires_approval"] and value["preview"]["diffs"]
                    plan_id = value["preview"]["plan_id"]
                    assert json.loads((project_dir / "settings.json").read_text())["fixed"] is False
                    run = wait(approve(value)["job"]["id"])
                    plan = request("GET", "/api/security/v2/remediation/" + plan_id)
                    assert plan["state"] == "prepared"
                    assert Path(plan["branch_path"], "queries.py").read_text(encoding="utf-8") == VULNERABLE_QUERY_SOURCE
                    return {"run_id": run["id"], "plan_id": plan_id, "branch_path": plan["branch_path"], "branch": plan["branch"], "original_modified": False}
                prepared = record("supervised_prepare_approved_copy_and_diff", prepare)

                def apply():
                    value = request("POST", "/api/security/v2/remediation/" + prepared["plan_id"] + "/apply-preview")
                    run = wait(approve(value)["job"]["id"])
                    plan = request("GET", "/api/security/v2/remediation/" + prepared["plan_id"])
                    assert plan["state"] == "applied" and plan["tests_ok"] is True
                    assert Path(plan["branch_path"], "queries.py").read_text(encoding="utf-8") == FIXED_QUERY_SOURCE
                    assert (project_dir / "queries.py").read_text(encoding="utf-8") == VULNERABLE_QUERY_SOURCE
                    assert json.loads((project_dir / "settings.json").read_text())["fixed"] is False
                    assert any(t["kind"] == "approved_project_test" and t["ok"] for t in plan["tests"])
                    return {"run_id": run["id"], "plan_id": plan["id"], "tests": plan["tests"], "changes": plan["changes"], "original_modified": False}
                record("apply_diff_and_run_approved_regression", apply)

                reservation.close()
                with running_lab(Path(prepared["branch_path"]), fixed_port) as corrected:
                    def revalidate():
                        value = request("POST", "/api/security/v2/remediation/" + prepared["plan_id"] + "/revalidate-preview", json={
                            "scope_id": scope["id"], "args": {"target": corrected.url + "/sqli", "lab_confirmation": True}})
                        run = wait(approve(value)["job"]["id"])
                        plan = request("GET", "/api/security/v2/remediation/" + prepared["plan_id"])
                        assert plan["state"] == "revalidated" and plan["revalidation"]["ok"]
                        assert all(x["status"] == "absent_in_revalidated_coverage" for x in plan["revalidation"]["comparison"])
                        assert not original.fixed_mode() and not corrected.fixed_mode()
                        return {"run_id": run["id"], "report_id": run["report_id"], "plan_id": plan["id"],
                            "comparison": plan["revalidation"]["comparison"], "validation": plan["revalidation"]["result"]["validation"],
                            "original_mode": "vulnerable_synthetic_fixture", "copy_mode": "parameterized_synthetic_fixture", "deployment": False}
                    record("revalidate_corrected_copy_actual_http", revalidate)

                def original_preserved():
                    run = execute("appsec_sqli", {"target": original.url + "/sqli", "lab_confirmation": True}, **shared)
                    assert run["result"]["validation"] == "confirmed_controlled"
                    assert json.loads((project_dir / "settings.json").read_text())["fixed"] is False
                    assert (project_dir / "queries.py").read_text(encoding="utf-8") == VULNERABLE_QUERY_SOURCE
                    return {"run_id": run["id"], "report_id": run["report_id"], "validation": run["result"]["validation"], "original_modified": False}
                preserved = record("original_project_and_server_preserved", original_preserved)

                def legacy_specialist_bridge():
                    configuration = request("GET", "/api/security/v2/status")["configuration_digest"]
                    count = len(original.observations)
                    value = request("POST", "/api/security/jobs", json={"tool": "security_audit_v2", "mode": "AGENT", "args": {
                        "engine": "appsec_sqli", "scope_id": scope["id"], "scope_revision": scope["revision"],
                        "target": original.url + "/sqli", "arguments": {"lab_confirmation": True}, "configuration_digest": configuration}})
                    assert value["requires_approval"] and len(original.observations) == count
                    result = request("POST", "/api/security/jobs/" + value["approval_id"] + "/decision", json={"approved": True})
                    assert result["ok"] and result["data"]["state"] == "completed"
                    run = request("GET", "/api/security/v2/runs/" + result["data"]["run_id"])
                    assert run["ok"] and run["scope_id"] == scope["id"]
                    assert run["result"]["validation"] == "confirmed_controlled"
                    native_report = request("GET", "/api/security/v2/reports/" + run["report_id"])
                    assert native_report["result"]["scope"]["id"] == scope["id"]
                    assert len(original.observations) > count
                    return {"run_id": run["id"], "report_id": run["report_id"], "legacy_report_id": result["report_id"],
                            "scope_id": scope["id"], "validation": run["result"]["validation"], "model_inference": False,
                            "requests": run["result"]["requests"], "tool": "security_audit_v2", "mode": "AGENT"}
                record("specialist_bridge_approved_actual_http_no_model", legacy_specialist_bridge)

                def static_remediation():
                    before_run = execute("code_audit", project_id=project["id"])
                    source = request("GET", "/api/security/v2/reports/" + before_run["report_id"])
                    selected = next(f for f in source["result"]["findings"] if f.get("rule_id") == "PY-SQL-CONSTRUCTION" and f.get("file") == "queries.py")
                    proposal = request("POST", "/api/security/v2/remediation/preview", json={"report_id": before_run["report_id"],
                        "project_id": project["id"], "finding_ids": [selected["id"]],
                        "edits": [{"path": "queries.py", "content": FIXED_QUERY_SOURCE}],
                        "tests": [["python", "-m", "unittest", "discover", "-s", ".", "-p", "test_regression.py"]], "tests_authorized": True})
                    assert proposal["requires_approval"] and proposal["preview"]["diffs"]
                    plan_id = proposal["preview"]["plan_id"]
                    prepared_run = wait(approve(proposal)["job"]["id"])
                    apply_preview = request("POST", "/api/security/v2/remediation/" + plan_id + "/apply-preview")
                    applied_run = wait(approve(apply_preview)["job"]["id"])
                    validation_preview = request("POST", "/api/security/v2/remediation/" + plan_id + "/revalidate-preview", json={})
                    assert validation_preview["preview"]["action"] == "revalidate_static_code"
                    revalidated_run = wait(approve(validation_preview)["job"]["id"])
                    plan = request("GET", "/api/security/v2/remediation/" + plan_id)
                    assert plan["state"] == "revalidated" and plan["tests_ok"] is True
                    assert plan["revalidation"]["ok"] is True
                    assert all(item["status"] == "absent_in_revalidated_coverage" for item in plan["revalidation"]["comparison"])
                    assert Path(plan["branch_path"], "queries.py").read_text(encoding="utf-8") == FIXED_QUERY_SOURCE
                    assert (project_dir / "queries.py").read_text(encoding="utf-8") == VULNERABLE_QUERY_SOURCE
                    assert any(t["kind"] == "approved_project_test" and t["ok"] for t in plan["tests"])
                    return {"source_run_id": before_run["id"], "source_report_id": before_run["report_id"],
                            "prepared_run_id": prepared_run["id"], "applied_run_id": applied_run["id"],
                            "revalidated_run_id": revalidated_run["id"], "report_id": revalidated_run["report_id"],
                            "plan_id": plan_id, "source_engine": "code_audit", "branch_path": plan["branch_path"],
                            "comparison": plan["revalidation"]["comparison"], "tests": plan["tests"], "original_modified": False,
                            "static_revalidation_executes_project": False, "approved_unit_tests_execute_fixture": True}
                record("actual_code_auditor_patch_regression_and_static_revalidation", static_remediation)

                def correlation():
                    value = request("POST", "/api/security/v2/reports/correlate", json={"report_ids": [before["report_id"], preserved["report_id"]]})
                    rows = value["result"]["findings"]
                    assert len(rows) == 1 and rows[0]["occurrences"] == 2
                    return {"report_id": value["id"], "source_reports": [before["report_id"], preserved["report_id"]],
                            "deduplicated_findings": len(rows), "occurrences": rows[0]["occurrences"]}
                record("report_correlation_and_deduplication", correlation)
        except Exception as exc:
            report["fatal_error"] = sanitize(str(exc))
        finally:
            for identity in scope_ids:
                try:
                    value = request("DELETE", "/api/security/scopes/" + identity)
                    report["scope_cleanup"].append({"id": identity, "revoked": value.get("enabled") is False})
                except Exception as exc:
                    report["scope_cleanup"].append({"id": identity, "revoked": False, "error": sanitize(str(exc))})
    report["ok"] = not report["errors"] and "fatal_error" not in report and all(s["revoked"] for s in report["scope_cleanup"])
    report["limitations"] = ["Integrações Ghidra/Nuclei/ZAP constam apenas no inventário; este ensaio não executa esses motores externos.",
        "Correção demonstrada é um patch SQL parametrizado em queries.py de um laboratório fictício conhecido; não altera uma aplicação real anterior do usuário.",
        "O teste unitário autorizado executa somente o código sintético criado por este ensaio; serviços leem a configuração como dados.",
        "Ausência de achados refere-se somente aos marcadores e cobertura registrados. Nenhum deploy realizado."]
    destination = ROOT / "reports" / args.report
    destination.write_text(json.dumps(sanitize(report), ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "report": str(destination), "tests": {key: value["status"] for key, value in report["tests"].items()},
                      "errors": report["errors"], "scope_cleanup": report["scope_cleanup"]}, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
