"""API humana AI Library. Autorizações não são ferramentas expostas aos modelos."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from .models import LibraryError, MAX_UPLOAD
import httpx


class ModelDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approval_id: str = Field(min_length=32, max_length=32)
    approved: StrictBool
    confirmation: str | None = Field(default=None, max_length=200)


def install_model_routes(app, factory, inference, activity):
    """factory retorna instância estável; inference() compartilha a fila existente."""
    router = APIRouter(prefix="/api/library/models")

    def fail(exc):
        code = getattr(exc, "code", "ollama_http_error" if isinstance(exc, httpx.HTTPError) else "library_input")
        status = 404 if code == "job_not_found" else 413 if code == "upload_too_large" else 400
        return JSONResponse({"ok": False, "error": str(exc)[:2000], "code": code,
                             "source": getattr(exc, "source", "model_service" if isinstance(exc, httpx.HTTPError) else "application")}, status_code=status)

    @router.get("")
    async def inventory():
        try:
            return await factory().inventory()
        except (ValueError, OSError, httpx.HTTPError) as exc:
            return fail(exc)

    @router.post("/preview")
    async def preview(payload: dict):
        try:
            value = await factory().preview(payload)
            activity().add("model_approval_requested", {"id": value["approval_id"], "action": value["preview"]["action"], "model": value["preview"]["model"]})
            return value
        except (ValueError, OSError, httpx.HTTPError) as exc:
            return fail(exc)

    @router.post("/jobs")
    async def launch(value: ModelDecision):
        manager = factory()
        try:
            job = manager.approve(value.approval_id, value.approved, value.confirmation)
            if job is None:
                activity().add("model_approval_denied", {"id": value.approval_id})
                return {"ok": True, "executed": False, "code": "approval_denied", "source": "permission"}
            activity().add("model_approval_granted", {"id": value.approval_id, "job_id": job["id"], "action": job["action"], "model": job["model"]})
            manager.start(job["id"], inference, activity)
            return {"ok": True, "job_id": job["id"], "job": manager.job(job["id"])}
        except (ValueError, OSError) as exc:
            return fail(exc)

    @router.get("/jobs")
    async def jobs():
        return {"jobs": factory().job_list()}

    @router.get("/jobs/{identity}")
    async def job(identity: str):
        try:
            return factory().job(identity)
        except ValueError as exc:
            return fail(exc)

    @router.post("/jobs/{identity}/cancel")
    async def cancel(identity: str):
        try:
            result = factory().cancel(identity)
            activity().add("model_cancel_requested", {"id": identity})
            return result
        except ValueError as exc:
            return fail(exc)

    @router.post("/uploads")
    async def upload(request: Request, name: str = "modelo.gguf", sha256: str | None = None):
        try:
            length = request.headers.get("content-length")
            if length and (not length.isdigit() or int(length) > MAX_UPLOAD):
                raise LibraryError("GGUF deve ter até 16 GiB e Content-Length válido.", "upload_too_large")
            value = await factory().ingest(request.stream(), name, sha256)
            activity().add("model_gguf_uploaded", {"id": value["id"], "sha256": value["sha256"], "size": value["size"], "architecture": value["architecture"]})
            return value
        except (ValueError, OSError) as exc:
            return fail(exc)

    @router.delete("/uploads/{identity}")
    async def delete_upload(identity: str):
        try:
            result = factory().remove_upload(identity)
            activity().add("model_upload_removed", {"id": identity})
            return result
        except (ValueError, OSError) as exc:
            return fail(exc)

    app.include_router(router)
    return router
