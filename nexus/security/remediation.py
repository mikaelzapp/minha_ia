"""Correções revisáveis em cópia/branch local, sem deploy ou escrita no original."""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import psutil

from ..developer import DeveloperHistory
from ..tools import Tools
from .common import SecurityError, safe_file, sha256_file, utcnow, run_process
from .reporting import sanitize
from .workbench import digest, valid_id

MAX_COPY = 20 * 1024**2
EXCLUDE = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".runtime", ".aws", ".ssh", ".codex", ".agents", "reports", "data", "dist", "build"}


def semantic_key(row):
    from urllib.parse import urlsplit
    location = row.get("file") or row.get("location") or row.get("endpoint") or row.get("url") or ""
    try:
        p = urlsplit(location)
        if p.scheme in {"http", "https"}:
            location = p.path or "/"
    except ValueError:
        pass
    return digest([row.get("cwe") or row.get("cwe_id") or row.get("rule_id") or row.get("title"), location, row.get("parameter", "")])


class Remediation:
    def __init__(self, workbench):
        self.w = workbench

    def project(self, identity):
        center = self.w.center_factory()
        project = next((p for p in center.projects() if p["id"] == identity), None)
        if not project:
            raise SecurityError("Projeto cadastrado necessário.", "project_not_found")
        path = Path(project["path"])
        if not path.is_absolute():
            path = center.workspace_root / path
        if any(Tools._is_link(p) for p in (path, *path.parents)):
            raise SecurityError("Projeto contém links/junctions.")
        path = path.resolve()
        if not path.is_dir() or not path.is_relative_to(center.workspace_root):
            raise SecurityError("Projeto fora do workspace autorizado.")
        return path

    def get(self, identity):
        if not valid_id(identity):
            raise SecurityError("Plano inválido.")
        with self.w.store.connection() as db:
            row = db.execute("SELECT document FROM v2_plans WHERE id=?", (identity,)).fetchone()
        if not row:
            raise SecurityError("Plano não encontrado.")
        return json.loads(row[0])

    def list(self):
        with self.w.store.connection() as db:
            rows = db.execute("SELECT id,document FROM v2_plans ORDER BY created_at DESC LIMIT 50").fetchall()
        return {"plans": [{k: v for k, v in json.loads(row["document"]).items() if k not in {"edits", "source_findings", "manifest"}} for row in rows]}

    def save(self, plan):
        if len(json.dumps(plan).encode()) > 2 * 1024**2:
            raise SecurityError("Plano excedeu o limite local.")
        with self.w.store.connection() as db:
            db.execute("INSERT INTO v2_plans VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document",
                (plan["id"], json.dumps(plan, ensure_ascii=False), plan["created_at"]))

    def _files(self, root):
        files, size = [], 0
        for directory, folders, names in os.walk(root, followlinks=False):
            folders[:] = sorted(f for f in folders if f not in EXCLUDE and not f.startswith(".") and not Tools._sensitive(f) and not Tools._is_link(Path(directory) / f))
            for name in sorted(names):
                path = Path(directory) / name
                if name.startswith(".") or Tools._sensitive(path.name) or path.suffix.lower() in {".sqlite", ".sqlite3", ".db", ".key", ".pem", ".p12", ".pfx"}:
                    continue
                path = safe_file(path, maximum=2 * 1024**2)
                size += path.stat().st_size
                if size > MAX_COPY or len(files) >= 1000:
                    raise SecurityError("Cópia supervisionada limitada a mil arquivos/20 MiB. Selecione um subprojeto menor.")
                files.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
        return files

    def preview(self, value):
        if not isinstance(value, dict) or set(value) - {"report_id", "project_id", "finding_ids", "edits", "tests", "tests_authorized"}:
            raise SecurityError("Campos do plano inválidos.")
        report = self.w.store.report(value.get("report_id"))
        result = report["result"]
        if result.get("schema") != "nexus-security-report/2" or not result.get("ok"):
            raise SecurityError("Selecione um relatório 2.0 concluído, com evidências.")
        source = self.project(value.get("project_id"))
        if result.get("project_id") and result["project_id"] != value["project_id"]:
            raise SecurityError("O relatório pertence a outro projeto.")
        ids = value.get("finding_ids")
        selected = [f for f in result.get("findings", []) if isinstance(ids, list) and f["id"] in ids]
        if not selected or len(set(ids)) != len(ids) or set(ids) != {f["id"] for f in selected}:
            raise SecurityError("Selecione achados existentes, sem duplicações.")
        edits = value.get("edits")
        if not isinstance(edits, list) or not 1 <= len(edits) <= 10:
            raise SecurityError("Forneça de uma a dez alterações específicas para revisão.")
        manifest = self._files(source)
        manifest_paths = {f["path"] for f in manifest}
        normalized, diffs, seen = [], [], set()
        tools = Tools(source, self.w.root.parent)
        try:
            for edit in edits:
                if not isinstance(edit, dict) or set(edit) != {"path", "content"}:
                    raise SecurityError("Cada alteração exige somente path/content.")
                if not isinstance(edit["path"], str) or not isinstance(edit["content"], str):
                    raise SecurityError("path/content precisam ser textos.")
                relative = Path(edit["path"]).as_posix()
                target, old, content = tools._prepare_write(relative, edit["content"])
                relative = target.relative_to(source).as_posix()
                if relative in seen or relative not in manifest_paths:
                    raise SecurityError("Nesta versão, altere apenas arquivos existentes da cópia permitida, sem duplicações.")
                seen.add(relative)
                before = safe_file(target).read_bytes()
                diff = "".join(difflib.unified_diff(before.decode("utf-8").splitlines(keepends=True), content.splitlines(keepends=True), fromfile=relative, tofile=relative))
                if not diff or len(diff) > 100_000:
                    raise SecurityError("A proposta precisa de um diff não vazio de até 100 mil caracteres.")
                normalized.append({"path": relative, "content": content, "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(content.encode()).hexdigest()})
                diffs.append({"path": relative, "diff": sanitize(diff)})
        finally:
            tools.close()
        tests = value.get("tests", [])
        if not isinstance(tests, list) or len(tests) > 3:
            raise SecurityError("Selecione até três comandos de teste.")
        if tests and value.get("tests_authorized") is not True:
            raise SecurityError("Executar testes do projeto exige autorização explícita; os testes executam código com sua conta.")
        for command in tests:
            if (not isinstance(command, list) or not command or len(command) > 16 or
                any(not isinstance(arg, str) or len(arg) > 256 for arg in command) or
                command[:3] not in (["python", "-m", "pytest"], ["python", "-m", "unittest"])):
                raise SecurityError("Testes integrados aceitam python -m pytest/unittest com argumentos limitados, sempre após aprovação.")
        identity = uuid.uuid4().hex
        plan = {"id": identity, "revision": 1, "created_at": utcnow(), "state": "proposed",
            "project_id": value["project_id"], "source_root": str(source), "source_report_id": report["id"],
            "source_findings": selected, "source_target": result.get("target"), "source_engine": result.get("engine"),
            "scope": result.get("scope"), "manifest": manifest, "edits": normalized, "diffs": diffs,
            "tests": tests, "tests_authorized": value.get("tests_authorized", False), "history": [],
            "original_modified": False, "deployment_performed": False}
        return self.w._pending({"kind": "remediation_prepare", "engine": "remediation_prepare", "plan": plan,
            "config_digest": digest(self.w.configuration())}, {"question": "Deseja que o NEXUS prepare as correções para as vulnerabilidades encontradas?",
            "plan_id": identity, "findings": selected, "diffs": diffs, "files_copied": len(manifest),
            "copy_bytes": sum(f["bytes"] for f in manifest), "tests": tests,
            "impact": "Cria cópia isolada do projeto e branch Git local quando Git está disponível. Arquivos sensíveis e dependências são omitidos. Os originais são preservados; aplicar o diff exige outra aprovação. Diretório separado não é sandbox do Windows."})

    def prepare(self, payload, cancel, emit):
        plan = payload["plan"]
        self.w.store.report(plan["source_report_id"])
        source = self.project(plan["project_id"])
        if str(source) != plan["source_root"] or self._files(source) != plan["manifest"]:
            raise SecurityError("Projeto alterado após a proposta; prepare um novo diff.", "source_changed")
        destination = self.w.root / "remediation" / plan["id"] / "workspace"
        if psutil.disk_usage(str(self.w.root)).free < sum(row["bytes"] for row in plan["manifest"]) * 2 + 128 * 1024**2:
            raise SecurityError("Espaço livre insuficiente para preparar a cópia com margem de segurança.", "disk_budget")
        for p in (destination, *destination.parents):
            if (p.exists() or p.is_symlink()) and Tools._is_link(p):
                raise SecurityError("Destino contém links/junctions.")
        destination.mkdir(parents=True, exist_ok=False)
        copied = []
        for row in plan["manifest"]:
            if cancel.is_set():
                raise SecurityError("Preparação cancelada; cópia parcial preservada para inspeção.", "cancelled")
            path = safe_file(source / row["path"], maximum=2 * 1024**2)
            if sha256_file(path) != row["sha256"]:
                raise SecurityError("Projeto mudou durante a cópia.")
            target = destination / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            if sha256_file(target) != row["sha256"]:
                raise SecurityError("Hash da cópia não confere.")
            copied.append(row["path"])
        branch = "nexus-remediation/" + plan["id"][:12]
        git = shutil.which("git")
        plan.update(branch_path=str(destination), branch=None, isolation="verified_copy")
        if git:
            env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP") if key in os.environ}
            env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="NEXUS local", GIT_AUTHOR_EMAIL="nexus@localhost", GIT_COMMITTER_NAME="NEXUS local", GIT_COMMITTER_EMAIL="nexus@localhost")
            base = [git, "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", "-C", str(destination)]
            outputs = []
            for args in (["init", "-b", branch], ["add", "--", "."], ["commit", "-m", "Snapshot anterior à correção supervisionada"]):
                outcome = run_process(base + args, timeout=15, max_output=32_000, cwd=destination, env=env, cancel=cancel)
                outputs.append({"args": args, "ok": outcome["ok"]})
                if not outcome["ok"]:
                    break
            plan["git_steps"] = outputs
            if all(o["ok"] for o in outputs):
                plan.update(branch=branch, isolation="git_branch_in_verified_copy")
        plan.update(state="prepared", revision=2)
        plan["history"].append({"at": utcnow(), "action": "prepared", "files": len(copied)})
        self.save(plan)
        emit({"stage": "branch_prepared", "plan_id": plan["id"], "isolation": plan["isolation"]})
        return {"ok": True, "plan_id": plan["id"], "branch": plan["branch"], "branch_path": plan["branch_path"], "findings": [],
            "limitations": ["Cópia local não isola permissões de processos. Nenhum arquivo original foi modificado."]}

    def _branch(self, plan):
        self.project(plan["project_id"])  # A deleted project cannot retain pending authorization.
        expected = self.w.root / "remediation" / plan["id"] / "workspace"
        if Path(plan.get("branch_path", "")) != expected or not expected.is_dir():
            raise SecurityError("Cópia de correção indisponível.")
        if any(Tools._is_link(p) for p in (expected, *expected.parents)):
            raise SecurityError("A cópia foi substituída por um link.")
        return expected

    def apply_preview(self, identity):
        plan = self.get(identity)
        if plan["state"] != "prepared":
            raise SecurityError("Plano precisa estar preparado e ainda não aplicado.")
        branch = self._branch(plan)
        for edit in plan["edits"]:
            if sha256_file(safe_file(branch / edit["path"])) != edit["before_sha256"]:
                raise SecurityError("Arquivo mudou após o diff aprovado.", "branch_changed")
        return self.w._pending({"kind": "remediation_apply", "engine": "remediation_apply", "plan_id": identity,
            "revision": plan["revision"], "config_digest": digest(self.w.configuration())},
            {"action": "apply_to_isolated_branch", "plan_id": identity, "branch_path": str(branch),
             "diffs": plan["diffs"], "tests": plan["tests"], "impact": "Escreve somente os diffs aprovados na cópia. Testes selecionados executam código com as permissões da conta atual. Não publica, não altera originais e não concede novos acessos."})

    def apply(self, payload, cancel, emit):
        plan = self.get(payload["plan_id"])
        if plan["revision"] != payload["revision"] or plan["state"] != "prepared":
            raise SecurityError("Plano alterado ou já aplicado.")
        branch = self._branch(plan)
        for edit in plan["edits"]:
            if sha256_file(safe_file(branch / edit["path"])) != edit["before_sha256"]:
                raise SecurityError("Arquivo mudou; nenhum diff foi aplicado.", "branch_changed")
        tools = Tools(branch, self.w.root.parent)
        history = self.w.history() if self.w.history else DeveloperHistory(self.w.root.parent)
        results, tests = [], []
        try:
            for edit in plan["edits"]:
                if cancel.is_set():
                    break
                result = history.execute_write(tools, {"path": edit["path"], "content": edit["content"], "expected_sha256": edit["before_sha256"]})
                results.append({"path": edit["path"], **result})
                if not result.get("ok"):
                    break
                if edit["path"].endswith(".py"):
                    try:
                        ast.parse(edit["content"], filename=edit["path"])
                        tests.append({"kind": "python_ast", "path": edit["path"], "ok": True, "executes_project_code": False})
                    except SyntaxError as exc:
                        tests.append({"kind": "python_ast", "path": edit["path"], "ok": False, "line": exc.lineno})
                elif edit["path"].endswith(".json"):
                    try:
                        json.loads(edit["content"])
                        tests.append({"kind": "json_parse", "path": edit["path"], "ok": True})
                    except ValueError:
                        tests.append({"kind": "json_parse", "path": edit["path"], "ok": False})
            if not cancel.is_set() and len(results) == len(plan["edits"]) and all(r.get("ok") for r in results):
                import sys
                for command in plan["tests"]:
                    if cancel.is_set():
                        break
                    # Approved project tests have genuine execution privileges, documented in the preview.
                    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP") if key in os.environ}
                    env.update(PYTHONNOUSERSITE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
                    outcome = run_process([sys.executable, "-I"] + command[1:], timeout=30, max_output=64_000, cwd=branch, env=env, cancel=cancel)
                    tests.append({"kind": "approved_project_test", "command": command, **outcome})
            success = len(results) == len(plan["edits"]) and all(r.get("ok") for r in results) and not cancel.is_set()
            plan.update(state="applied" if success else "partial_or_failed", revision=plan["revision"] + 1,
                changes=sanitize(results), tests=sanitize(tests), tests_ok=all(t.get("ok") for t in tests) if tests else None)
            plan["history"].append({"at": utcnow(), "action": plan["state"]})
            self.save(plan)
            emit({"stage": plan["state"], "plan_id": plan["id"]})
            return {"ok": success, "plan_id": plan["id"], "changes": results, "tests": tests,
                "findings": [], "original_modified": False, "resolved": False,
                "limitations": ["Aplicar um diff e passar nos testes de sintaxe não confirma a correção da vulnerabilidade. Revalide o alvo de homologação."]}
        finally:
            tools.close()

    def revalidate_preview(self, identity, value=None):
        value = value or {}
        if not isinstance(value, dict) or set(value) - {"scope_id", "target", "args"}:
            raise SecurityError("Informe somente scope_id/target/args da revalidação.")
        plan = self.get(identity)
        if plan["state"] not in {"applied", "revalidated"}:
            raise SecurityError("Aplique o plano na cópia antes de revalidar.")
        source = self.w.store.report(plan["source_report_id"])["result"]
        run = self.w.run(source["run_id"])
        engine = plan["source_engine"]
        if engine == "code_audit":
            branch = self._branch(plan)
            return self.w._pending({"kind": "remediation_revalidate", "engine": "remediation_revalidate", "plan_id": identity,
                "revision": plan["revision"], "args": {}, "config_digest": digest(self.w.configuration())},
                {"action": "revalidate_static_code", "plan_id": identity, "branch_path": str(branch),
                    "impact": "Reexecuta o Code Auditor estático apenas na cópia corrigida; não executa o projeto e não acessa a rede."})
        if engine not in {"appsec_sqli", "appsec_auth"}:
            raise SecurityError("Revalidação dinâmica integrada disponível para SQLi/Auth. Reexecute os outros adaptadores separadamente e correlacione os relatórios.", "revalidation_not_configured")
        scope = self.w.store.get_scope(value.get("scope_id") or source["scope"]["id"])
        args = value.get("args") or {"target": value.get("target") or source["target"], "lab_confirmation": True}
        if engine == "appsec_auth":
            args.setdefault("synthetic_accounts_confirmed", True)
        self._validate_coverage(plan, args)
        from .appsec import preview_auth, preview_sqli
        detail = (preview_sqli if engine == "appsec_sqli" else preview_auth)(scope, **args)
        return self.w._pending({"kind": "remediation_revalidate", "engine": "remediation_revalidate", "plan_id": identity,
            "revision": plan["revision"], "scope_id": scope["id"], "scope_revision": scope["revision"],
            "args": args, "config_digest": digest(self.w.configuration())}, {"action": "revalidate", "plan_id": identity,
            "detail": detail, "impact": "Reexecuta a auditoria no alvo indicado. Inicie a cópia corrigida na porta autorizada antes. Resultado se refere somente a esse alvo; o projeto original e produção não são modificados."})

    def _validate_coverage(self, plan, args):
        from urllib.parse import urlsplit
        from .appsec import _fixture
        source = self.w.store.report(plan["source_report_id"])["result"]
        original = source.get("test_spec") if isinstance(source.get("test_spec"), dict) else {}
        mismatch = (urlsplit(args.get("target", "")).path or "/") != (urlsplit(source.get("target") or "").path or "/")
        if plan["source_engine"] == "appsec_sqli":
            defaults = {"parameter": "name", "baseline": "NEXUS_LAB_A", "marker": "NEXUS_LAB_SQLI_MARKER_A"}
            mismatch |= any(args.get(key, default) != original.get(key, default) for key, default in defaults.items())
        elif plan["source_engine"] == "appsec_auth":
            configured = original.get("fixture")
            if configured:
                new = _fixture(args.get("fixture"))
                expected = _fixture(None)
                for name in ("login_path", "logout_path", "username_field"):
                    if name in configured:
                        expected[name] = configured[name]
                for actor in ("account_a", "account_b"):
                    expected[actor].update({key: val for key, val in configured.get(actor, {}).items() if key != "password"})
                for name in ("login_path", "logout_path", "username_field"):
                    if name in expected:
                        mismatch |= new.get(name) != expected[name]
                for actor in ("account_a", "account_b"):
                    for key in ("username", "resource", "marker"):
                        if key in expected.get(actor, {}):
                            mismatch |= new[actor][key] != expected[actor][key]
            else:
                mismatch |= _fixture(args.get("fixture")) != _fixture(None)
        if mismatch:
            raise SecurityError("A revalidação deve repetir o mesmo caminho, parâmetro e marcadores/contas. A origem e porta podem mudar para a cópia autorizada. Prepare auditoria independente para outra cobertura.", "revalidation_coverage_changed")

    def revalidate(self, payload, cancel, emit):
        plan = self.get(payload["plan_id"])
        if plan["revision"] != payload["revision"]:
            raise SecurityError("Plano mudou desde a aprovação.")
        branch = self._branch(plan)
        self._validate_coverage(plan, payload["args"])
        if plan["source_engine"] == "code_audit":
            from .static import audit_project
            if cancel.is_set():
                raise SecurityError("Revalidação cancelada.", "cancelled")
            result = audit_project(branch)
        else:
            scope_loader = lambda: self.w.scope(payload)
            from .appsec import run_auth, run_sqli
            result = (run_sqli if plan["source_engine"] == "appsec_sqli" else run_auth)(scope_loader(), **payload["args"], cancel=cancel, scope_loader=scope_loader)
        from .reporting import correlate
        new = correlate(result.get("findings", []), plan["source_engine"], payload["args"].get("target"))
        keys = {semantic_key(f) for f in new}
        before = plan["source_findings"]
        complete = result.get("ok") is True and result.get("validation") != "inconclusive" and not cancel.is_set()
        if plan["source_engine"] == "code_audit":
            scanned = {row["file"]: row for row in result.get("files", []) if isinstance(row, dict) and "file" in row}
            required = {row["file"] for row in before if row.get("file")}
            complete &= not result.get("truncated", False) and bool(required) and required <= scanned.keys() and not any(scanned[name].get("parse_error") for name in required if name in scanned)
        if plan["tests_ok"] is False:
            complete = False
        if plan["source_engine"] == "appsec_auth" and not 200 <= result.get("evidence", {}).get("logout_status", 0) < 300:
            complete = False
        comparison = [{"finding_id": f["id"], "title": f["title"],
            "status": "absent_in_revalidated_coverage" if complete and semantic_key(f) not in keys else "still_present" if complete else "inconclusive"} for f in before]
        plan.update(state="revalidated", revision=plan["revision"] + 1,
            revalidation={"at": utcnow(), "target": payload["args"].get("target") or str(branch), "ok": complete, "comparison": comparison, "result": sanitize(result)})
        plan["history"].append({"at": utcnow(), "action": "revalidated", "ok": complete})
        self.save(plan)
        return {"ok": complete, "plan_id": plan["id"], "comparison": comparison, "findings": new, "result": result,
            "coverage": result.get("coverage", {}), "original_modified": False,
            "limitations": ["Ausência se refere apenas aos marcadores e cobertura revalidados neste alvo. Não é prova de segurança geral; deploy e integração ao original exigem autorização separada."]}
