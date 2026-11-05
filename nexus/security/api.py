"""Rotas humanas do Security Center; decisões não são ferramentas do modelo."""
import copy
import hashlib
import json
import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .store import MAX_SAMPLE


class SecurityJob(BaseModel):
    tool: str = Field(max_length=80)
    args: dict = Field(default_factory=dict)
    mode: str = "AGENT"


class SecurityDecision(BaseModel):
    approved: bool


def _digest(tool, args):
    return hashlib.sha256((tool + json.dumps(args, sort_keys=True)).encode()).hexdigest()


def install_security_routes(app, factory, blocking, inference, activity):
    router = APIRouter(prefix="/api/security")
    pending = {}

    def fail(exc):
        return JSONResponse({"ok": False, "error": str(exc), "code": getattr(exc, "code", "SECURITY_INPUT"),
                             "source": getattr(exc, "source", "application")}, status_code=400)

    async def execute(tool, args):
        async with inference():
            result = await blocking(factory().execute, tool, args)
        activity().add("security_operation", {"tool": tool, "ok": result.get("ok", False), "report_id": result.get("report_id")})
        return result

    @router.get("/status")
    async def status():
        async with inference():
            return await blocking(factory().status)

    @router.get("/scopes")
    async def scopes():
        return {"scopes": await blocking(factory().store.list_scopes)}

    @router.post("/scopes")
    async def create_scope(payload: dict):
        try:
            result = await blocking(factory().store.create_scope, payload)
        except (ValueError, OSError) as exc:
            return fail(exc)
        activity().add("security_scope_created", {"id": result["id"], "name": result["name"], "targets": result["targets"]})
        return result

    @router.delete("/scopes/{identity}")
    async def revoke_scope(identity: str):
        try:
            result = await blocking(factory().store.revoke_scope, identity)
        except (ValueError, OSError) as exc:
            return fail(exc)
        activity().add("security_scope_revoked", {"id": identity})
        return result

    @router.get("/samples")
    async def samples():
        return {"samples": await blocking(factory().store.list_samples)}

    @router.post("/samples")
    async def upload_sample(request: Request, name: str = "amostra.bin"):
        payload = bytearray()
        async for chunk in request.stream():
            if len(payload) + len(chunk) > MAX_SAMPLE:
                raise HTTPException(413, "Limite de amostra: 10 MiB.")
            payload.extend(chunk)
        try:
            result = await blocking(factory().store.ingest, name, bytes(payload))
        except (ValueError, OSError) as exc:
            return fail(exc)
        activity().add("security_sample_uploaded", {"id": result["id"], "sha256": result["sha256"], "size": result["size"]})
        return result

    @router.post("/dorks/preview")
    async def dork_preview(payload: dict):
        return await execute("security_dork", payload)

    @router.post("/jobs")
    async def run_job(value: SecurityJob):
        center = factory()
        allowed = {schema["function"]["name"] for schema in center.schemas(value.mode.upper())}
        if value.mode.upper() not in {"PLAN", "CODE", "AGENT", "REVIEW", "RESEARCH"} or value.tool not in allowed:
            return JSONResponse({"ok": False, "code": "tool_not_allowed", "source": "permission",
                                 "error": "Operação não permitida neste modo."}, status_code=403)
        try:
            preview = await blocking(center.approval, value.tool, value.args)
        except (ValueError, OSError) as exc:
            return fail(exc)
        if preview is None:
            return await execute(value.tool, value.args)
        # Cada aprovação é consumida uma vez; o escopo será consultado novamente
        # ao executar e a revisão impede reaproveitar permissões antigas.
        now = time.monotonic()
        for key in [key for key, item in pending.items() if item["deadline"] < now]:
            pending.pop(key, None)
        if len(pending) >= 32:
            raise HTTPException(429, "Resolva as aprovações pendentes antes de preparar novas operações.")
        identity = uuid.uuid4().hex
        args = copy.deepcopy(value.args)
        args["scope_revision"] = preview["scope_revision"]
        pending[identity] = {"tool": value.tool, "args": args, "digest": _digest(value.tool, args), "deadline": now + 300}
        activity().add("security_approval_requested", {"id": identity, "tool": value.tool, "scope_id": preview["scope_id"]})
        return {"ok": True, "requires_approval": True, "approval_id": identity, "preview": preview}

    @router.post("/jobs/{identity}/decision")
    async def decide_job(identity: str, decision: SecurityDecision):
        item = pending.pop(identity, None)
        if item is None or item["deadline"] < time.monotonic():
            raise HTTPException(404, "Aprovação inexistente, já resolvida ou expirada.")
        if not decision.approved:
            activity().add("security_approval_denied", {"id": identity, "tool": item["tool"]})
            return {"ok": True, "executed": False, "code": "approval_denied", "source": "permission"}
        if item["digest"] != _digest(item["tool"], item["args"]):
            raise HTTPException(409, "Os argumentos mudaram; prepare a operação novamente.")
        activity().add("security_approval_granted", {"id": identity, "tool": item["tool"]})
        return await execute(item["tool"], item["args"])

    @router.get("/reports")
    async def reports():
        return {"reports": await blocking(factory().store.reports)}

    @router.get("/reports/{identity}")
    async def report(identity: str, format: str = "json"):
        if len(identity) != 32 or any(char not in "0123456789abcdef" for char in identity):
            raise HTTPException(400, "Identificador de relatório inválido.")
        try:
            result = await blocking(factory().store.report, identity)
        except (ValueError, OSError) as exc:
            return fail(exc)
        if format == "md":
            text = "# NEXUS Security Center\n\nOperação: " + result["operation"] + "\n\nData: " + result["created_at"]
            text += "\n\nResultados e evidências (achados exigem validação):\n\n```json\n" + json.dumps(result["result"], ensure_ascii=False, indent=2) + "\n```\n"
            return PlainTextResponse(text, media_type="text/markdown", headers={"Content-Disposition": 'attachment; filename="nexus-security-' + identity[:32] + '.md"'})
        if format != "json":
            raise HTTPException(400, "Formato esperado: json ou md.")
        return JSONResponse(result, headers={"Content-Disposition": 'attachment; filename="nexus-security-' + identity[:32] + '.json"'})

    app.include_router(router)
    return pending
