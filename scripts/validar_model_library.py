"""Teste real autorizado da AI Library; altera somente modelos temporários identificados.

Usar apenas depois de iniciar o NEXUS atualizado e obter autorização para os
271 MB do smollm2:135m. O script se recusa a começar se essa tag já existir.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
BASE = "/api/library/models"
TEST_MODEL = "smollm2:135m"
TEST_WEIGHT = "f535f83ec568d040f88ddc04a199fa6da90923bbb41d4dcaed02caa924d6ef57"
TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorized-test", action="store_true", help="Confirma autorização prévia do usuário para baixar/testar/remover somente o modelo de teste e variantes temporárias.")
    parser.add_argument("--url", default="http://127.0.0.1:8765")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    if not args.authorized_test:
        parser.error("Falta --authorized-test: não há download automático sem autorização explícita.")
    from urllib.parse import urlsplit
    parsed = urlsplit(args.url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
        parser.error("A validação exige URL HTTP local sem credenciais.")
    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    variants = ["nexus-qa-variant:" + suffix, "nexus-qa-import:" + suffix]
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "test_model": TEST_MODEL,
              "authorized_download_bytes": 270898672, "variants": variants, "steps": [],
              "effects": "Somente instalação/teste/limpeza do SmolLM2 135M ausente no início e variantes temporárias.", "ok": False}
    target = ROOT / "reports" / "model-library-runtime.json"
    original = None
    uploads = []

    with httpx.Client(base_url=args.url.rstrip("/"), trust_env=False, timeout=60) as client:
        client.get("/").raise_for_status()

        def request(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            response.raise_for_status()
            result = response.json()
            if result.get("ok") is False:
                raise RuntimeError(json.dumps(result, ensure_ascii=False))
            return result

        def inventory():
            result = request("GET", BASE)
            if not result.get("connected"):
                raise RuntimeError("Ollama desconectado: " + str(result.get("error")))
            return result

        def snapshot(value):
            return {item["name"]: item.get("digest") for item in value["models"]}

        def record(name, result):
            report["steps"].append({"name": name, "result": result})
            target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            print(name + ": " + str(result.get("status", result.get("ok", "registrado"))), flush=True)

        def launch(payload):
            prepared = request("POST", BASE + "/preview", json=payload)
            preview = prepared["preview"]
            approved = {"approval_id": prepared["approval_id"], "approved": True}
            if payload["action"] == "delete":
                name = preview["model"]
                if name != TEST_MODEL and name not in variants:
                    raise RuntimeError("Tentativa de limpar modelo fora da lista temporária.")
                if original and name in original:
                    raise RuntimeError("Modelo original jamais pode ser removido pelo teste.")
                approved["confirmation"] = name
            launched = request("POST", BASE + "/jobs", json=approved)
            return launched["job_id"], preview

        def wait(identity):
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                value = request("GET", BASE + "/jobs/" + identity)
                if value["status"] in TERMINAL:
                    return value
                time.sleep(.1)
            request("POST", BASE + "/jobs/" + identity + "/cancel")
            raise TimeoutError("Teste excedeu o tempo permitido; cancelamento solicitado.")

        def run(name, payload):
            identity, preview = launch(payload)
            value = wait(identity)
            record(name, {"preview": preview, **value})
            if value["status"] != "completed":
                raise RuntimeError(name + " falhou: " + str(value.get("error")))
            return value

        try:
            initial = inventory()
            original = snapshot(initial)
            report["original_models"] = original
            report["original_default"] = initial.get("default_model")
            if TEST_MODEL in original or any(name in original for name in variants):
                raise RuntimeError("Uma tag de teste já existe. Validação interrompida antes de qualquer alteração para preservar os modelos existentes.")
            record("inventory", {"ok": True, "models": original, "resources": initial.get("resources")})

            identity, preview = launch({"action": "pull", "model": TEST_MODEL})
            deadline = time.monotonic() + 120
            observed = None
            while time.monotonic() < deadline:
                observed = request("GET", BASE + "/jobs/" + identity)
                real_events = [item for item in observed.get("events", []) if item.get("status") != "Executando operação aprovada"]
                if real_events or observed["status"] in TERMINAL:
                    break
                time.sleep(.025)
            cancellation = request("POST", BASE + "/jobs/" + identity + "/cancel")
            cancelled = wait(identity)
            record("cancel_pull", {"preview": preview, "before_cancel": observed, "cancel_response": cancellation, **cancelled})
            if cancelled["status"] != "cancelled":
                report["cancel_note"] = "O servidor concluiu antes de o cancelamento chegar; o efeito do cancelamento em transferência não foi demonstrado nesta rodada."

            current = inventory()
            if TEST_MODEL not in snapshot(current):
                run("pull_resume", {"action": "pull", "model": TEST_MODEL})
            else:
                record("pull_already_completed", {"ok": True, "status": "completed", "note": "A tag foi concluída pelo Ollama antes/depois do fechamento do cliente."})

            run("variant_create", {"action": "variant", "model": variants[0], "base": TEST_MODEL,
                "system": "Você é um modelo temporário de validação do NEXUS. Responda objetivamente.", "context": 2048, "temperature": 0})
            run("variant_load_test", {"action": "test", "model": variants[0], "prompt": "Responda apenas: NEXUS OK"})
            run("variant_unload", {"action": "unload", "model": variants[0]})

            # Lê apenas o blob público específico recém-baixado. Não abre caminhos informados por respostas do modelo.
            model_dir = Path(os.environ.get("OLLAMA_MODELS", str(Path.home() / ".ollama" / "models")))
            blob = model_dir / "blobs" / ("sha256-" + TEST_WEIGHT)
            if blob.is_file():
                def chunks():
                    with blob.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024**2), b""):
                            yield chunk
                uploaded = request("POST", BASE + "/uploads", params={"name": "smollm2-135m-test.gguf", "sha256": TEST_WEIGHT},
                    content=chunks(), headers={"Content-Type": "application/octet-stream", "Content-Length": str(blob.stat().st_size)})
                uploads.append(uploaded["id"])
                record("gguf_upload", uploaded)
                run("gguf_import", {"action": "import", "model": variants[1], "upload_id": uploaded["id"], "context": 2048, "temperature": 0})
                run("gguf_load_test", {"action": "test", "model": variants[1], "prompt": "NEXUS OK"})
            else:
                record("gguf_import", {"ok": False, "status": "not_tested", "reason": "Blob público específico não localizado no diretório padrão; nenhuma busca por arquivos privados foi realizada."})
            report["ok"] = True
        except Exception as exc:
            report["error"] = str(exc)[:4000]
            print("Falha: " + report["error"], flush=True)
        finally:
            # Só limpa se a rodada começou sem nenhuma tag temporária preexistente.
            if original is not None and TEST_MODEL not in original and not any(name in original for name in variants):
                try:
                    names = snapshot(inventory())
                    for name in [*reversed(variants), TEST_MODEL]:
                        if name in names and name not in original:
                            run("cleanup_" + name, {"action": "delete", "model": name})
                    for identity in uploads:
                        record("cleanup_upload", request("DELETE", BASE + "/uploads/" + identity))
                    final = inventory()
                    remaining = snapshot(final)
                    report["final_models"] = remaining
                    report["original_models_preserved"] = all(remaining.get(name) == digest for name, digest in original.items())
                    report["temporary_models_removed"] = all(name not in remaining for name in [TEST_MODEL, *variants])
                    report["default_preserved"] = final.get("default_model") == report.get("original_default")
                    if not all(report.get(key) for key in ("original_models_preserved", "temporary_models_removed", "default_preserved")):
                        report["ok"] = False
                except Exception as exc:
                    report["cleanup_error"] = str(exc)[:4000]
                    report["ok"] = False
            report["finished_at"] = datetime.now(timezone.utc).isoformat()
            target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
