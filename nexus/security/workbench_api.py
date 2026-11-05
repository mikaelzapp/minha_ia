"""Rotas humanas do Security Center 2.0; tarefas reais com cancelamento cooperativo."""
import asyncio
from contextlib import suppress
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, StrictBool

from .common import SecurityError
from .reporting import correlate, html_report, markdown, sanitize
from .workbench import digest


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved: StrictBool


def install_workbench_routes(app, factory, blocking, inference, activity):
    router = APIRouter(prefix="/api/security/v2")
    tasks = {}

    def failure(exc):
        return JSONResponse({"ok": False, "code": getattr(exc, "code", "security_v2_input"),
            "error": sanitize(str(exc)), "source": "operational"}, status_code=400)

    async def invoke(fn, *args):
        try:
            return await blocking(fn, *args)
        except (ValueError, OSError) as exc:
            return failure(exc)

    async def run(identity):
        try:
            async with inference():
                result = await blocking(factory().execute, identity)
            activity().add("security_v2_finished", {"id": identity, "state": result["state"], "report_id": result.get("report_id")})
        finally:
            tasks.pop(identity, None)

    @router.get("/status")
    async def status():
        return await invoke(factory().inventory)

    @router.post("/configuration/preview")
    async def config_preview(value: dict):
        if set(value) != {"engine", "config"}:
            return failure(SecurityError("Informe engine/config."))
        return await invoke(factory().config_preview, value["engine"], value["config"])

    @router.post("/installations/preview")
    async def installation_preview(value: dict):
        return await invoke(factory().installation_preview, value)

    @router.post("/preview")
    async def preview(value: dict):
        return await invoke(factory().preview, value)

    @router.post("/approvals/{identity}/decision")
    async def decide(identity: str, value: Decision):
        result = await invoke(factory().decision, identity, value.approved)
        if isinstance(result, dict):
            activity().add("security_v2_decision", {"id": identity, "approved": value.approved, "queued": result.get("queued", False)})
            if result.get("queued"):
                job_id = result["job"]["id"]
                tasks[job_id] = asyncio.create_task(run(job_id))
        return result

    @router.get("/runs")
    async def runs():
        return {"runs": await blocking(factory().runs)}

    @router.get("/runs/{identity}")
    async def get_run(identity: str):
        return await invoke(factory().run, identity)

    @router.post("/runs/{identity}/cancel")
    async def cancel(identity: str):
        result = await invoke(factory().cancel, identity)
        activity().add("security_v2_cancel_requested", {"id": identity})
        return result

    @router.get("/assets")
    async def assets(scope_id: str | None = None):
        return {"assets": await blocking(factory().assets, scope_id)}

    @router.post("/retention/preview")
    async def retention(value: dict):
        return await invoke(factory().retention_preview, value)

    @router.get("/reports/{identity}")
    async def report(identity: str, format: str = "json"):
        try:
            value = await blocking(factory().store.report, identity)
        except (ValueError, OSError) as exc:
            return failure(exc)
        filename = "nexus-security-" + value["id"]
        headers = {"Content-Disposition": f'attachment; filename="{filename}.{format}"'}
        if format == "json":
            return JSONResponse(sanitize(value), headers=headers)
        if format == "md":
            return PlainTextResponse(markdown(value), headers=headers)
        if format == "html":
            return HTMLResponse(html_report(value), headers=headers)
        if format == "pdf":
            try:
                # Text-only PDF: no HTML renderer, external assets, JavaScript or URL fetches.
                from reportlab.pdfgen.canvas import Canvas
                from io import BytesIO
                import textwrap
            except ImportError:
                raise HTTPException(424, "PDF indisponível: dependência opcional reportlab não instalada. JSON, HTML e Markdown estão disponíveis.")
            stream = BytesIO()
            canvas = Canvas(stream)
            y = 800
            for line in json.dumps(sanitize(value), ensure_ascii=False, indent=2).splitlines():
                for part in textwrap.wrap(line, 100, replace_whitespace=False) or [""]:
                    if y < 40:
                        canvas.showPage()
                        y = 800
                    canvas.setFont("Helvetica", 8)
                    canvas.drawString(32, y, part)
                    y -= 11
            canvas.save()
            return Response(stream.getvalue(), media_type="application/pdf", headers=headers)
        raise HTTPException(400, "Use json, md, html ou pdf.")

    @router.post("/reports/correlate")
    async def correlate_reports(value: dict):
        ids = value.get("report_ids", [])
        if not isinstance(ids, list) or not 1 <= len(ids) <= 10:
            return failure(SecurityError("Selecione de um a dez relatórios."))
        try:
            rows = [await blocking(factory().store.report, i) for i in ids]
            targets = {r["result"].get("target") for r in rows}
            projects = {r["result"].get("project_id") for r in rows}
            samples = {r["result"].get("sample_id") for r in rows}
            if len(targets) > 1 or len(projects) > 1 or len(samples) > 1:
                raise SecurityError("Correlacione somente relatórios do mesmo alvo e projeto.")
            if targets == projects == samples == {None} and len(rows) > 1 and not all(r["result"].get("engine") == "windows" for r in rows):
                raise SecurityError("Relatórios sem identidade de alvo/projeto/amostra não podem ser agrupados automaticamente.")
            findings = []
            for row in rows:
                for finding in row["result"].get("findings", []):
                    findings.append({**finding, "engine": row["operation"]})
            result = {"schema": "nexus-security-report/2", "ok": True, "source_reports": ids,
                "target": next(iter(targets)), "project_id": next(iter(projects)), "sample_id": next(iter(samples)), "findings": correlate(findings),
                "coverage": {"source_reports": len(ids)}, "limitations": ["Correlação conservadora por fraqueza/local/parâmetro; similaridade textual não confirma identidade."],
                "tools_used": [], "correction_history": []}
            return await blocking(factory().store.save_report, "v2:correlation", result)
        except (ValueError, OSError) as exc:
            return failure(exc)

    @router.post("/reports/{identity}/delete-preview")
    async def delete_preview(identity: str):
        try:
            row = await blocking(factory().store.report, identity)
            return factory()._pending({"kind": "delete_report", "report_id": identity,
                "config_digest": digest(factory().configuration())},
                {"action": "delete_report", "report_id": identity, "operation": row["operation"],
                 "impact": "Exclui este relatório e a cópia do resultado na tarefa associada. Metadados da tarefa, planos relacionados e backups permanecem. Exporte antes; não é limpeza forense do SQLite."})
        except (ValueError, OSError) as exc:
            return failure(exc)

    @router.get("/remediation/plans")
    async def plans():
        from .remediation import Remediation
        return await invoke(Remediation(factory()).list)

    @router.post("/remediation/preview")
    async def remediation_preview(value: dict):
        from .remediation import Remediation
        return await invoke(Remediation(factory()).preview, value)

    @router.post("/remediation/{identity}/apply-preview")
    async def remediation_apply_preview(identity: str):
        from .remediation import Remediation
        return await invoke(Remediation(factory()).apply_preview, identity)

    @router.post("/remediation/{identity}/revalidate-preview")
    async def revalidate_preview(identity: str, value: dict = None):
        from .remediation import Remediation
        return await invoke(Remediation(factory()).revalidate_preview, identity, value)

    @router.get("/remediation/{identity}")
    async def plan(identity: str):
        from .remediation import Remediation
        return await invoke(Remediation(factory()).get, identity)

    @router.post("/remediation/consult")
    async def consult(value: dict):
        # Explicit click, bounded local context and shared inference budget; never executes proposal.
        if not factory().coder:
            raise HTTPException(424, "Consultor local não configurado.")
        async with inference():
            import psutil
            if psutil.virtual_memory().available < 1024**3:
                return failure(SecurityError("RAM livre inferior a 1 GiB. Descarregue modelos na AI Library ou feche aplicações antes de consultar o Coder.", "resource_budget"))
            return await invoke(factory().coder().execute, value)

    async def close():
        for identity in list(tasks):
            with suppress(ValueError, OSError):
                factory().cancel(identity)
        if tasks:
            await asyncio.gather(*list(tasks.values()), return_exceptions=True)

    app.include_router(router)
    return close
