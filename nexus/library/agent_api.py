"""API humana de agentes: configuração JSON sem comandos ou concessão de acesso."""
import sqlite3
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from .agents import AgentLibraryError


def install_agent_routes(app, factory, blocking, activity):
    """Reutiliza autenticação/origin do aplicativo; callbacks evitam estado capturado."""
    router = APIRouter(prefix="/api/library/agents")

    def failure(exc):
        return JSONResponse({"ok": False, "error": str(exc), "code": getattr(exc, "code", "agent_storage_error"),
                             "source": "agent_library"}, status_code=getattr(exc, "status_code", 400))

    async def execute(method, *args):
        try:
            return await blocking(getattr(factory(), method), *args)
        except (AgentLibraryError, OSError) as exc:
            return failure(exc)
        except sqlite3.DatabaseError:
            return failure(AgentLibraryError("Banco de agentes indisponível ou inválido. Restaure o backup se necessário.", "agent_storage_error"))

    def record(kind, result):
        if isinstance(result, dict):
            activity().add(kind, {"id": result.get("id"), "revision": result.get("revision")})
        return result

    @router.get("")
    async def catalog():
        return await execute("catalog")

    @router.post("")
    async def create(payload: dict):
        return record("agent_created", await execute("create", payload))

    # Declare fixed paths before /{identity}, so import is never treated as an ID.
    @router.post("/import")
    async def import_agent(payload: dict):
        return record("agent_imported", await execute("import_agent", payload))

    @router.get("/{identity}/export")
    async def export_agent(identity: str):
        result = await execute("export", identity)
        if isinstance(result, JSONResponse):
            return result
        return JSONResponse(result, headers={"Content-Disposition": f'attachment; filename="nexus-agent-{identity}.json"'})

    @router.post("/{identity}/duplicate")
    async def duplicate_agent(identity: str, payload: dict | None = None):
        return record("agent_duplicated", await execute("duplicate", identity, payload))

    @router.get("/{identity}")
    async def get_agent(identity: str):
        return await execute("get", identity)

    @router.put("/{identity}")
    async def update_agent(identity: str, payload: dict):
        configuration = dict(payload)
        revision = configuration.pop("revision", None)
        return record("agent_updated", await execute("update", identity, configuration, revision))

    @router.delete("/{identity}")
    async def delete_agent(identity: str, revision: int = Query(..., ge=1)):
        return record("agent_deleted", await execute("delete", identity, revision))

    app.include_router(router)
