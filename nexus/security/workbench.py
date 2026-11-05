"""Security Center 2: adaptadores, aprovações e histórico persistente de tarefas."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import uuid
from datetime import datetime, timezone

import psutil

from .common import SecurityError, safe_file, sha256_file, utcnow
from .reporting import correlate, sanitize

MODULES = [
    ("web", "WEB PENTEST", ["nuclei", "zap", "http_headers"]),
    ("network", "NETWORK SECURITY", ["tcp_connect", "nmap_service", "tls_certificate"]),
    ("auth", "AUTH & DATABASE SECURITY", ["appsec_sqli", "appsec_auth"]),
    ("code", "CODE SECURITY", ["code_audit"]),
    ("malware", "MALWARE ANALYSIS", ["static_file", "investigate"]),
    ("reverse", "REVERSE ENGINEERING", ["ghidra", "rea"]),
    ("osint", "OSINT & INVESTIGATION", ["asset_inventory", "osint", "cve"]),
    ("blue", "BLUE TEAM", ["windows"]),
    ("remediation", "AUTO-REMEDIATION", []),
    ("reports", "REPORT CENTER", []),
]
NETWORK_ENGINES = {"nuclei", "zap", "nmap_service", "appsec_sqli", "appsec_auth", "asset_inventory", "http_headers", "tcp_connect", "tls_certificate", "osint"}
LOCAL_MAP = {"code_audit": "security_code_audit", "static_file": "security_static_file", "investigate": "security_investigate",
    "rea": "security_rea", "windows": "security_windows", "cve": "security_cve"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def valid_id(value):
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


class Workbench:
    def __init__(self, center_factory, *, coder=None, history=None):
        self.center_factory = center_factory
        self.store = center_factory().store
        self.root = self.store.root
        self.config_path = self.root / "modules.json"
        self.lock = threading.RLock()
        self.pending = {}
        self.live = {}
        self.coder = coder
        self.history = history
        with self.store.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS v2_runs(id TEXT PRIMARY KEY, engine TEXT NOT NULL,
                    state TEXT NOT NULL, document TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS v2_assets(id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                    target TEXT NOT NULL, document TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS v2_plans(id TEXT PRIMARY KEY, document TEXT NOT NULL, created_at TEXT NOT NULL);
            """)
            # A restart cannot prove an interrupted native process finished successfully.
            rows = db.execute("SELECT id,document FROM v2_runs WHERE state IN ('queued','running','cancelling')").fetchall()
            for row in rows:
                doc = json.loads(row["document"])
                doc.update(state="interrupted", ok=False, error="Servidor reiniciado; a conclusão desta tarefa não foi confirmada.")
                db.execute("UPDATE v2_runs SET state=?,document=? WHERE id=?", ("interrupted", json.dumps(doc), row["id"]))

    def configuration(self):
        with self.store.connection():
            pass  # Recheck the storage ancestry even when modules.json does not exist yet.
        if not self.config_path.exists():
            return {}
        path = safe_file(self.config_path, maximum=64 * 1024)
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise SecurityError("Configuração de módulos inválida.")
        return value

    def scanner_config(self):
        return {k: v for k, v in self.configuration().items() if k in {"nuclei", "zap", "nmap_service"}}

    def config_preview(self, engine, config):
        if engine not in {"nuclei", "zap", "nmap_service", "ghidra"} or not isinstance(config, dict):
            raise SecurityError("Selecione um motor configurável.")
        allowed = {"nuclei": {"path", "sha256"}, "nmap_service": {"path", "sha256"},
            "zap": {"jar", "sha256", "java", "java_sha256"},
            "ghidra": {"install_dir", "java_home", "timeout_seconds", "max_input_bytes", "max_functions", "max_strings", "max_references", "heap_mib", "rss_mib", "decompile", "isolation_acknowledged"}}[engine]
        if set(config) - allowed:
            raise SecurityError("Campos de configuração desconhecidos.")
        clean = copy.deepcopy(config)
        if engine != "ghidra":
            for key, hashkey in (("java", "java_sha256"), ("jar" if engine == "zap" else "path", "sha256")):
                if key == "java" and engine != "zap":
                    continue
                if not isinstance(clean.get(key), str) or not Path(clean[key]).is_absolute():
                    raise SecurityError("Informe um caminho absoluto para a ferramenta.")
                path = safe_file(clean[key], maximum=512 * 1024**2)
                observed = sha256_file(path)
                if clean.get(hashkey) and clean[hashkey] != observed:
                    raise SecurityError("Hash informado não corresponde ao executável selecionado.")
                clean[key], clean[hashkey] = str(path), observed
        else:
            if clean.get("isolation_acknowledged") is not True:
                raise SecurityError("Confirme que o diretório separado não é uma VM nem sandbox do Windows.")
            from .ghidra import Ghidra
            inv = Ghidra(self.root.parent, clean).inventory()
            if not inv.get("available"):
                raise SecurityError("Ghidra/JDK indisponível: " + str(inv.get("reason") or inv.get("error") or inv.get("limitations", "verifique os caminhos")))
            clean["install_dir"], clean["java_home"] = inv["install_dir"], inv["java_home"]
            for key in ("java_sha256", "utility_sha256", "launcher_sha256", "exporter_sha256"):
                clean[key] = inv[key]
        clean["approved"] = True
        return self._pending({"kind": "configuration", "engine": engine, "config": clean,
            "config_digest": digest(self.configuration())}, {"action": "configure_tool", "engine": engine,
            "config": clean, "impact": "Autoriza a ferramenta e suas dependências na instalação local selecionada. Os hashes identificam pontos de entrada, não todo o pacote nem sua autenticidade. Nenhum download é realizado."})

    def installation_preview(self, value):
        if not isinstance(value, dict) or value != {"tool": "nuclei"}:
            raise SecurityError("Instalação portátil integrada disponível apenas para Nuclei Windows AMD64.")
        from .installers import NucleiInstaller
        detail = NucleiInstaller(self.root.parent).preview()
        fields = ("version", "source_url", "download_bytes", "archive_sha256", "destination")
        return self._pending({"kind": "run", "engine": "install_nuclei", "args": {},
            "artifact_digest": digest({k: detail[k] for k in fields}), "config_digest": digest(self.configuration())},
            {"action": "install_portable_nuclei", **detail})

    def _pending(self, payload, preview):
        with self.lock:
            now = time.monotonic()
            self.pending = {k: v for k, v in self.pending.items() if v["deadline"] > now}
            if len(self.pending) >= 32:
                raise SecurityError("Resolva aprovações pendentes antes de criar novas.", "approval_limit")
            identity = uuid.uuid4().hex
            self.pending[identity] = {"payload": copy.deepcopy(payload), "digest": digest(payload), "deadline": now + 300}
        return {"ok": True, "requires_approval": True, "approval_id": identity, "preview": sanitize(preview), "expires_seconds": 300}

    def scope(self, payload):
        if not valid_id(payload.get("scope_id")):
            raise SecurityError("Selecione um escopo cadastrado.", "scope_required")
        return self.store.get_scope(payload["scope_id"], payload.get("scope_revision"))

    def preview(self, payload, record=True):
        if not isinstance(payload, dict) or set(payload) - {"engine", "args", "scope_id", "project_id", "sample_id"}:
            raise SecurityError("Argumentos de tarefa inválidos.")
        payload = copy.deepcopy(payload)
        engine, args = payload.get("engine"), payload.get("args", {})
        if engine not in NETWORK_ENGINES | set(LOCAL_MAP) | {"ghidra"} or not isinstance(args, dict):
            raise SecurityError("Motor ou parâmetros desconhecidos.")
        scope = None
        if engine in NETWORK_ENGINES:
            scope = self.scope(payload)
            payload["scope_revision"] = scope["revision"]
            if engine not in {"http_headers", "tcp_connect", "tls_certificate", "osint"} and not scope.get("allowed_ports"):
                raise SecurityError("Os testes 2.0 exigem portas explicitamente cadastradas no escopo.", "explicit_ports_required")
            if engine in {"nuclei", "zap", "nmap_service", "appsec_sqli", "appsec_auth"}:
                if scope.get("hosting") in {"shared", "vercel", "other"} and not scope.get("provider_authorization"):
                    raise SecurityError("Testes ativos em hospedagem terceirizada exigem autorização do provedor; prefira laboratório próprio.", "provider_authorization_required")
        configuration = self.configuration()
        payload["config_digest"] = digest(configuration)
        if engine in {"nuclei", "zap", "nmap_service"}:
            from .scanners import ScannerAdapters
            detail = ScannerAdapters(self.root.parent, self.scanner_config()).preview(engine, scope, args)
        elif engine in {"appsec_sqli", "appsec_auth"}:
            from .appsec import preview_auth, preview_sqli
            allowed_args = {"target", "parameter", "baseline", "marker", "lab_confirmation"} if engine == "appsec_sqli" else {"target", "fixture", "synthetic_accounts_confirmed", "lab_confirmation"}
            if set(args) - allowed_args or not args.get("target"):
                raise SecurityError("Parâmetros de auditoria de aplicação inválidos.")
            detail = (preview_sqli if engine == "appsec_sqli" else preview_auth)(scope, **args)
        elif engine == "ghidra":
            from .ghidra import Ghidra
            path, sample = self.store.sample(payload.get("sample_id"))
            if args:
                raise SecurityError("Ghidra usa somente a configuração humana, sem argumentos livres.")
            inv = Ghidra(self.root.parent, configuration.get("ghidra", {})).inventory()
            detail = {"sample": sample, "inventory": inv, "impact": "Análise estática de bytes; não executa a amostra. Diretório separado não é sandbox do sistema operacional."}
        elif engine in LOCAL_MAP:
            cargs = dict(args)
            if engine == "code_audit":
                cargs["project_id"] = payload.get("project_id")
            elif engine in {"static_file", "rea", "investigate"}:
                cargs["sample_id"] = payload.get("sample_id")
            self.center_factory()._args(LOCAL_MAP[engine], cargs)
            detail = {"operation": LOCAL_MAP[engine], "args": cargs, "impact": "Inspeção limitada, sem executar a amostra ou modificar o projeto."}
        elif engine == "asset_inventory":
            from .investigation import preview_assets
            detail = preview_assets(scope, **args)
        else:
            name = {"http_headers": "security_http", "tcp_connect": "security_tcp", "tls_certificate": "security_tls", "osint": "security_osint"}[engine]
            detail = self.center_factory().approval(name, {**args, "scope_id": scope["id"], "scope_revision": scope["revision"]})
        prepared = {"kind": "run", **payload}
        display = {"engine": engine, "scope": scope,
            "project_id": payload.get("project_id"), "detail": detail,
            "notice": "Nenhum achado nesta cobertura não é garantia de segurança. Dados externos são evidências não confiáveis."}
        return self._pending(prepared, display) if record else {"payload": prepared, "preview": display}

    def decision(self, identity, approved):
        if type(approved) is not bool:
            raise SecurityError("approved deve ser booleano.")
        with self.lock:
            item = self.pending.pop(identity, None)
            if not item or item["deadline"] <= time.monotonic() or item["digest"] != digest(item["payload"]):
                raise SecurityError("Aprovação inexistente, expirada ou alterada.", "approval_invalid")
            if not approved:
                return {"ok": True, "executed": False, "code": "approval_denied"}
            payload = item["payload"]
            if payload.get("config_digest") != digest(self.configuration()):
                raise SecurityError("Configuração mudou; prepare a operação novamente.", "configuration_changed")
            if payload["kind"] == "configuration":
                cfg = self.configuration()
                cfg[payload["engine"]] = payload["config"]
                temporary = self.config_path.with_suffix(".tmp")
                if temporary.exists() or temporary.is_symlink():
                    raise SecurityError("Arquivo temporário de configuração já existe.")
                with temporary.open("x", encoding="utf-8") as stream:
                    json.dump(cfg, stream, ensure_ascii=False, indent=2)
                temporary.replace(self.config_path)
                return {"ok": True, "configured": payload["engine"]}
            if payload["kind"] == "delete_report":
                with self.store.connection() as db:
                    db.execute("DELETE FROM reports WHERE id=?", (payload["report_id"],))
                    rows = db.execute("SELECT id,document FROM v2_runs").fetchall()
                    for row in rows:
                        doc = json.loads(row["document"])
                        if doc.get("report_id") == payload["report_id"]:
                            doc.pop("result", None)
                            doc["result_deleted_at"] = utcnow()
                            db.execute("UPDATE v2_runs SET document=? WHERE id=?", (json.dumps(doc), row["id"]))
                return {"ok": True, "deleted": payload["report_id"]}
            if payload["kind"] == "retention":
                with self.store.connection() as db:
                    protected = {json.loads(row[0]).get("source_report_id") for row in db.execute("SELECT document FROM v2_plans")}
                    protected |= {entry.get("payload", {}).get("plan", {}).get("source_report_id") for entry in list(self.live.values()) + list(self.pending.values())}
                    protected.discard(None)
                    if any(row.get("report_id") in protected for row in payload["runs"]):
                        raise SecurityError("Um relatório passou a ser usado por um plano; prepare novamente a limpeza.", "retention_changed")
                    for row in payload["runs"]:
                        current = db.execute("SELECT state FROM v2_runs WHERE id=?", (row["id"],)).fetchone()
                        if not current or current[0] in {"queued", "running", "cancelling"} or row["id"] in self.live:
                            raise SecurityError("O histórico mudou; prepare novamente a limpeza.", "retention_changed")
                    for row in payload["runs"]:
                        if row.get("report_id"):
                            db.execute("DELETE FROM reports WHERE id=?", (row["report_id"],))
                        db.execute("DELETE FROM v2_runs WHERE id=?", (row["id"],))
                return {"ok": True, "deleted_runs": len(payload["runs"]), "deleted_reports": sum(bool(r.get("report_id")) for r in payload["runs"])}
            return self.enqueue_authorized(payload)

    def retention_preview(self, value):
        if not isinstance(value, dict) or set(value) != {"before"} or not isinstance(value["before"], str):
            raise SecurityError("Informe a data before no formato AAAA-MM-DD.")
        try:
            cutoff = datetime.strptime(value["before"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise SecurityError("Data de retenção inválida.") from exc
        with self.store.connection() as db:
            plan_rows = db.execute("SELECT document FROM v2_plans").fetchall()
            protected = {json.loads(row[0]).get("source_report_id") for row in plan_rows}
            protected |= {entry.get("payload", {}).get("plan", {}).get("source_report_id") for entry in list(self.live.values()) + list(self.pending.values())}
            protected.discard(None)
            rows = db.execute("SELECT document FROM v2_runs WHERE state NOT IN ('queued','running','cancelling') AND created_at < ? ORDER BY created_at LIMIT 500", (cutoff.isoformat(),)).fetchall()
        selected = []
        for row in rows:
            doc = json.loads(row[0])
            if doc.get("report_id") not in protected and doc["id"] not in self.live:
                selected.append({key: doc[key] for key in ("id", "report_id", "created_at", "engine") if key in doc})
        return self._pending({"kind": "retention", "runs": selected, "config_digest": digest(self.configuration())},
            {"action": "delete_old_results", "before_utc": cutoff.isoformat(), "runs": selected,
             "impact": "Exclui somente estas tarefas 2.0 encerradas e seus relatórios. Tarefas ativas, relatórios usados por planos, painel antigo, amostras, cópias de código e backups são preservados. Não é limpeza forense. Exporte antes."})

    def enqueue_authorized(self, payload):
        """Internal executor contract: caller has obtained approval for this frozen payload."""
        with self.lock:
            with self.store.connection() as db:
                if db.execute("SELECT count(*) FROM v2_runs").fetchone()[0] >= 500 or self.store.path.stat().st_size >= 256 * 1024**2:
                    raise SecurityError("Histórico local atingiu o limite. Exporte resultados e faça manutenção antes de novas tarefas.", "history_limit")
            if payload.get("scope_id"):
                self.scope(payload)
            if len(self.live) >= 4:
                raise SecurityError("Fila cheia; limite de quatro tarefas.", "queue_limit")
            identity = uuid.uuid4().hex
            run = {"id": identity, "engine": payload["engine"], "state": "queued", "created_at": utcnow(),
                "scope_id": payload.get("scope_id"), "scope_revision": payload.get("scope_revision"),
                "project_id": payload.get("project_id"), "sample_id": payload.get("sample_id"),
                "target": payload.get("args", {}).get("target") or payload.get("args", {}).get("domain"),
                "events": [], "configuration_digest": payload["config_digest"], "ok": None}
            self.live[identity] = {"payload": payload, "cancel": threading.Event()}
            self._save(run)
            return {"ok": True, "job": run, "queued": True}

    def _save(self, run):
        safe = sanitize(run)
        text = json.dumps(safe, ensure_ascii=False)
        if len(text.encode()) > 2 * 1024**2:
            raise SecurityError("Histórico da tarefa excede 2 MiB.", "run_size")
        with self.store.connection() as db:
            db.execute("INSERT INTO v2_runs VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,document=excluded.document",
                (run["id"], run["engine"], run["state"], text, run["created_at"]))

    def runs(self):
        with self.store.connection() as db:
            rows = db.execute("SELECT document FROM v2_runs ORDER BY created_at DESC LIMIT 100").fetchall()
        return [{k: v for k, v in json.loads(row[0]).items() if k not in {"events", "result"}} for row in rows]

    def run(self, identity):
        if not valid_id(identity):
            raise SecurityError("Identificador inválido.")
        with self.store.connection() as db:
            row = db.execute("SELECT document FROM v2_runs WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise SecurityError("Tarefa não encontrada.", "run_not_found")
        return json.loads(row[0])

    def cancel(self, identity):
        run = self.run(identity)
        with self.lock:
            live = self.live.get(identity)
            if not live:
                return {"ok": True, "state": run["state"], "cancellable": False}
            live["cancel"].set()
            run["state"] = "cancelling"
            self._save(run)
        return {"ok": True, "state": "cancelling", "cancellable": True}

    def execute(self, identity):
        with self.lock:
            live = self.live.get(identity)
            if live is None:
                return self.run(identity)
            payload, cancel = live["payload"], live["cancel"]
        run = self.run(identity)
        started = time.monotonic()
        def emit(event):
            with self.lock:
                if len(run["events"]) < 100:
                    run["events"].append({"at": utcnow(), **sanitize(event)})
                self._save(run)
        def scope_loader():
            return self.scope(payload)
        try:
            if cancel.is_set():
                raise SecurityError("Tarefa cancelada antes de iniciar.", "cancelled")
            if payload["config_digest"] != digest(self.configuration()):
                raise SecurityError("Configuração alterada enquanto a tarefa aguardava.", "configuration_changed")
            scope = scope_loader() if payload.get("scope_id") else None
            engine, args = payload["engine"], payload.get("args", {})
            resource = psutil.virtual_memory()
            heavy = engine in {"zap", "ghidra"} and self.configuration().get(engine, {}).get("approved") is True
            if resource.available < (3 * 1024**3 if heavy else 256 * 1024**2):
                raise SecurityError("RAM livre insuficiente para este motor. Descarregue modelos ou feche aplicações e prepare novamente.", "resource_budget")
            run.update(state="running", started_at=utcnow(), resources_before={"available_ram": resource.available, "percent": resource.percent})
            emit({"stage": "started", "engine": engine})
            if engine == "install_nuclei":
                from .installers import NucleiInstaller
                installer = NucleiInstaller(self.root.parent)
                detail = installer.preview()
                fields = ("version", "source_url", "download_bytes", "archive_sha256", "destination")
                if digest({k: detail[k] for k in fields}) != payload["artifact_digest"]:
                    raise SecurityError("Artefato/destino mudou; prepare a instalação novamente.", "installation_changed")
                result = installer.run(cancel=cancel, emit=emit)
            elif engine.startswith("remediation_"):
                from .remediation import Remediation
                function = {"remediation_prepare": "prepare", "remediation_apply": "apply", "remediation_revalidate": "revalidate"}[engine]
                result = getattr(Remediation(self), function)(payload, cancel, emit)
            elif engine in {"nuclei", "zap", "nmap_service"}:
                from .scanners import ScannerAdapters
                result = ScannerAdapters(self.root.parent, self.scanner_config()).run(engine, scope, args,
                    cancel_event=cancel, emit=emit, scope_loader=scope_loader)
            elif engine in {"appsec_sqli", "appsec_auth"}:
                from .appsec import run_auth, run_sqli
                result = (run_sqli if engine == "appsec_sqli" else run_auth)(scope, **args, cancel=cancel, scope_loader=scope_loader)
            elif engine == "ghidra":
                from .ghidra import Ghidra
                path, sample = self.store.sample(payload["sample_id"])
                result = Ghidra(self.root.parent, self.configuration().get("ghidra", {})).analyze(path,
                    expected_sha256=sample["sha256"], cancel=cancel, on_event=emit)
            elif engine == "asset_inventory":
                from .investigation import inspect_assets
                result = inspect_assets(scope, **args, cancel=cancel, scope_loader=scope_loader)
                if result.get("ok"):
                    self.save_asset(scope["id"], args["target"], result)
            else:
                cargs = dict(args)
                if engine in LOCAL_MAP:
                    name = LOCAL_MAP[engine]
                    if engine == "code_audit":
                        cargs["project_id"] = payload.get("project_id")
                    elif engine in {"static_file", "rea", "investigate"}:
                        cargs["sample_id"] = payload.get("sample_id")
                else:
                    name = {"http_headers": "security_http", "tcp_connect": "security_tcp", "tls_certificate": "security_tls", "osint": "security_osint"}[engine]
                    cargs.update(scope_id=scope["id"], scope_revision=scope["revision"])
                result = self.center_factory().execute(name, cargs)
            result = sanitize(result)
            findings = correlate(result.get("findings", []), engine, run.get("target"))
            duration = round(time.monotonic() - started, 3)
            data = result.get("data") if isinstance(result.get("data"), dict) else {}
            evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else data.get("evidence", {})
            coverage = result.get("coverage") or data.get("coverage") or (evidence.get("coverage") if isinstance(evidence, dict) else None)
            if not coverage and "files_scanned" in data:
                coverage = {key: data[key] for key in ("files_scanned", "bytes_read", "skipped_count", "truncated", "limit_reasons", "limits") if key in data}
            report = {"schema": "nexus-security-report/2", "run_id": identity, "engine": engine,
                "project_id": run.get("project_id"), "sample_id": run.get("sample_id"), "target": run.get("target"), "scope": scope,
                "started_at": run.get("started_at"), "duration_seconds": duration,
                "configuration_digest": payload["config_digest"], "findings": findings,
                "test_spec": sanitize(args) if engine in {"appsec_sqli", "appsec_auth"} else {},
                "coverage": coverage or {},
                "limitations": result.get("limitations", ["Somente as ferramentas e testes registrados foram executados; ausência de achados não prova segurança."]),
                "tools_used": [engine] if result.get("ok") else [], "result": result,
                "ok": result.get("ok", False), "cancelled": cancel.is_set(), "correction_history": []}
            saved = self.store.save_report("v2:" + engine, report)
            run.update(ok=result.get("ok", False), state="cancelled" if cancel.is_set() else "completed" if result.get("ok") else "failed",
                result=result, report_id=saved["id"], findings_count=len(findings), duration_seconds=duration)
            emit({"stage": run["state"], "findings": len(findings)})
        except Exception as exc:
            run.update(ok=False, state="cancelled" if cancel.is_set() else "failed", error=sanitize(str(exc))[:1500],
                code=getattr(exc, "code", "adapter_error"), duration_seconds=round(time.monotonic() - started, 3))
        finally:
            run["finished_at"] = utcnow()
            run["resources_after"] = {"available_ram": psutil.virtual_memory().available}
            with self.lock:
                self._save(run)
                self.live.pop(identity, None)  # Drops transient fictitious fixture credentials.
        return self.run(identity)

    def save_asset(self, scope_id, target, result):
        with self.store.connection() as db:
            db.execute("INSERT INTO v2_assets VALUES(?,?,?,?,?)", (uuid.uuid4().hex, scope_id, target, json.dumps(sanitize(result)), utcnow()))

    def assets(self, scope_id=None):
        with self.store.connection() as db:
            rows = db.execute("SELECT * FROM v2_assets WHERE (? IS NULL OR scope_id=?) ORDER BY created_at DESC LIMIT 30", (scope_id, scope_id)).fetchall()
        return [{**dict(row), "document": json.loads(row["document"])} for row in rows]

    def inventory(self):
        import importlib.util
        from .scanners import ScannerAdapters
        from .ghidra import Ghidra
        from .installers import NucleiInstaller
        config = self.configuration()
        return {"modules": [{"id": identity, "name": name, "engines": engines} for identity, name, engines in MODULES],
            "scanners": ScannerAdapters(self.root.parent, self.scanner_config()).inventory(),
            "ghidra": Ghidra(self.root.parent, config.get("ghidra", {})).inventory(),
            "installation": NucleiInstaller(self.root.parent).inventory(),
            "integrated_engines": sorted(set(LOCAL_MAP) | {"appsec_sqli", "appsec_auth", "asset_inventory", "http_headers", "tcp_connect", "tls_certificate", "osint"}),
            "configuration": config, "configuration_digest": digest(config), "runs": self.runs(), "retention": {"policy": "manual", "automatic_deletion": False,
                "recommendation_days": 30, "export_before_delete": True},
            "export_formats": {"json": True, "html": True, "md": True, "pdf": importlib.util.find_spec("reportlab") is not None},
            "limits": {"concurrency": 1, "queue": 4, "approval_seconds": 300, "run_bytes": 2 * 1024**2, "history_runs": 500, "database_bytes": 256 * 1024**2,
                "heavy_scanner_free_ram_gib": 3, "sandbox": False, "dynamic_sample_execution": False}}
