"""Compara os perfis pela API real sem aprovar operações do modelo."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent


async def main():
    token = (ROOT / "data" / "auth.secret").read_text(encoding="ascii").strip()
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": "real_http_and_local_model",
              "approved_actions": 0, "tests": {}}
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8765", trust_env=False,
                                 headers={"Authorization": "Bearer " + token}, timeout=600) as client:
        response = await client.get("/api/status")
        response.raise_for_status()
        before = response.json()["settings"]
        report["settings_before"] = before
        catalog = await client.get("/api/profiles")
        catalog.raise_for_status()
        report["catalog"] = catalog.json()
        session = await client.post("/api/sessions", json={"title": "Validação HTTP — perfis locais"})
        session.raise_for_status()
        session_id = session.json()["id"]
        for profile in ("standard", "unrestricted_local"):
            events = []
            async with client.stream("POST", "/api/chat", json={"session_id": session_id,
                "message": "Responda exatamente NEXUS-PERFIL-OK, sem markdown nem explicação.",
                "model": before["model"], "profile": profile, "mode": "CHAT", "agent": "auto",
                "context": 2048, "thinking": False, "temperature": 0}) as stream:
                stream.raise_for_status()
                async for line in stream.aiter_lines():
                    if not line: continue
                    event = json.loads(line)
                    events.append(event)
                    if event["type"] == "approval":
                        decision = await client.post("/api/approvals/" + event["id"], json={"approved": False})
                        decision.raise_for_status()
                    if event["type"] in {"status", "error", "notice"}:
                        print(profile + ": " + event.get("content", ""), flush=True)
            answer = "".join(event["content"] for event in events if event["type"] == "token")
            reviews = [event for event in events if event.get("phase") == "review"]
            errors = [event for event in events if event["type"] == "error"]
            expected_review = profile == "standard" and before["quality_mode"] == "careful"
            ok = answer == "NEXUS-PERFIL-OK" and bool(reviews) == expected_review and not errors
            report["tests"][profile] = {"status": "passed" if ok else "failed", "answer": answer,
                "review_passes": len(reviews), "events": events}
            (ROOT / "reports" / "integracao-unrestricted.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        after_response = await client.get("/api/status")
        after_response.raise_for_status()
        after = after_response.json()["settings"]
        history = await client.get("/api/sessions/" + session_id)
        history.raise_for_status()
        report["settings_after"] = after
        report["tests"]["settings_unchanged"] = {"status": "passed" if before == after else "failed"}
        report["tests"]["same_conversation_preserved"] = {
            "status": "passed" if [m["role"] for m in history.json()["messages"]] == ["user", "assistant", "user", "assistant"] else "failed",
            "session_id": session_id, "messages": len(history.json()["messages"])}
        (ROOT / "reports" / "integracao-unrestricted.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return int(any(item["status"] != "passed" for item in report["tests"].values()))


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
