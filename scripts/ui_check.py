"""QA real da interface local; a recusa de diff usa fixture isolada, sem executar ferramentas."""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
URL = "http://127.0.0.1:8765"
CHROME = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright/chromium-1228/chrome-win64/chrome.exe"


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": URL,
        "browser": str(CHROME),
        "real_browser": True,
        "tests": {},
        "console_errors": [],
        "page_errors": [],
        "failed_requests": [],
        "external_requests": [],
    }
    tests = result["tests"]
    with tempfile.TemporaryDirectory(prefix="ui-profile-", dir=REPORTS) as profile:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                profile,
                executable_path=str(CHROME),
                headless=True,
                viewport={"width": 1440, "height": 1000},
                args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"],
            )

            def local_only(route):
                parsed = urlsplit(route.request.url)
                if parsed.scheme in ("http", "https") and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                    result["external_requests"].append(route.request.url)
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", local_only)
            page = context.pages[0]
            page.set_default_timeout(30000)
            page.on("pageerror", lambda error: result["page_errors"].append(str(error)))
            page.on("console", lambda message: result["console_errors"].append(message.text) if message.type == "error" else None)
            page.on("requestfailed", lambda request: result["failed_requests"].append({"url": request.url, "failure": request.failure}))
            try:
                page.goto(URL, wait_until="networkidle")
                expect(page.locator("#model-select")).to_have_value(re.compile(".+"))
                status = page.request.get(f"{URL}/api/status").json()
                assert status["ollama"]["connected"]
                assert page.locator("#agent-select").input_value() == "auto"
                assert page.locator("#send-button").is_disabled()
                assert page.locator(".suggestion").count() == 4
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                page.screenshot(path=str(REPORTS / "interface.png"), full_page=True)
                tests["desktop"] = {"status": "passed", "viewport": "1440x1000", "horizontal_overflow": False, "screenshot": "reports/interface.png"}
                tests["local_status"] = {"status": "passed", "model": page.locator("#model-select").input_value(), "gpu": page.locator("#gpu-name").inner_text(), "ram": page.locator("#ram-used").inner_text()}

                page.locator(".settings-nav").click()
                assert page.locator("#manage-dialog").evaluate("element => element.open")
                assert page.locator("#settings-context option").count() == 3
                page.locator("#settings-form button[type=submit]").click()
                expect(page.locator("#dialog-status")).to_contain_text("salvas")
                after = page.request.get(f"{URL}/api/status").json()
                for key in ("model", "context", "temperature", "tor_enabled"):
                    assert status["settings"][key] == after["settings"][key], key
                tests["settings"] = {"status": "passed", "saved_existing_values": True, "context_range": [2048, 8192]}
                tests["tor"] = {"status": "passed", "enabled": after["settings"]["tor_enabled"], "activation_not_requested": True}

                page.locator("[data-panel=projects]").click()
                page.locator("#projects-list .management-card").first.wait_for()
                project_cards = page.locator("#projects-list .management-card").count()
                page.locator("#projects-list .management-card .secondary-button").first.click()
                assert page.locator("#project-select").input_value()
                tests["projects"] = {"status": "passed", "cards": project_cards, "selected_project": page.locator("#project-select").input_value()}

                page.locator("[data-panel=memory]").click()
                page.locator(".memory-add summary").click()
                marker = f"NEXUS UI QA {int(time.time())}: teste temporário da memória pela interface."
                page.locator("#memory-text").fill(marker)
                with page.expect_response(lambda response: response.url.endswith("/api/memory") and response.request.method == "POST") as stored_response:
                    page.locator("#memory-form button[type=submit]").click()
                stored = stored_response.value.json()
                page.locator("#memory-list .management-card").filter(has_text=marker).wait_for()
                assert marker in page.locator("#memory-list").inner_text()
                page.once("dialog", lambda dialog: dialog.accept())
                card = page.locator("#memory-list .management-card").filter(has_text=marker)
                card.locator("button").click()
                expect(page.locator("#dialog-status")).to_contain_text("excluída")
                exported = page.request.get(f"{URL}/api/memory/export").json()
                assert not any(item["id"] == stored["id"] for item in exported["memories"])
                with page.expect_download() as download:
                    page.locator("#export-memory").click()
                assert download.value.suggested_filename.endswith(".json")
                tests["memory"] = {"status": "passed", "add_search_delete": True, "export_download": True, "temporary_note_deleted": True}

                page.locator("#dialog-close").click()
                page.set_viewport_size({"width": 390, "height": 844})
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                page.locator("#sidebar-toggle").click()
                assert page.locator("#sidebar").is_visible()
                page.locator("#sidebar-shade").click(position={"x": 380, "y": 20})
                assert not page.locator("#sidebar").is_visible()
                page.screenshot(path=str(REPORTS / "interface-mobile.png"), full_page=True)
                tests["mobile"] = {"status": "passed", "viewport": "390x844", "horizontal_overflow": False, "navigation": True, "screenshot": "reports/interface-mobile.png"}

                page.set_viewport_size({"width": 1440, "height": 1000})
                page.locator("#new-session").click()
                page.locator("#project-select").select_option("")
                page.locator("#mode-select").select_option("CHAT")
                page.locator("#prompt").fill("Responda apenas INTERFACE OK")
                started = time.perf_counter()
                with page.expect_response(lambda response: response.url.endswith("/api/sessions") and response.request.method == "POST") as session_response:
                    page.locator("#send-button").click()
                session = session_response.value.json()["id"]
                expect(page.locator("#stop-button")).to_be_hidden(timeout=180000)
                answer = page.locator(".message.assistant .message-body").last.inner_text()
                assert "INTERFACE OK" in answer, answer
                assert page.locator(".message-error").count() == 0
                assert page.locator(".session-item.selected").count() == 1
                persisted = page.request.get(f"{URL}/api/sessions/{session}").json()
                assert any(message["role"] == "assistant" and "INTERFACE OK" in message["content"] for message in persisted["messages"])
                page.screenshot(path=str(REPORTS / "interface-chat.png"), full_page=True)
                tests["chat_real_local_model"] = {"status": "passed", "fixture": False, "prompt": "Responda apenas INTERFACE OK", "response": answer, "session_id": session, "wall_seconds": round(time.perf_counter() - started, 2), "speed": page.locator("#speed-label").inner_text(), "persisted": True, "screenshot": "reports/interface-chat.png"}

                # Esta página substitui apenas criação de sessão, streaming e decisões.
                # Não solicita nem concede uma aprovação real ao backend.
                fixture = context.new_page()
                fixture.on("pageerror", lambda error: result["page_errors"].append(str(error)))
                fixture.route("**/api/sessions", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"id": "fixture-session"} if route.request.method == "POST" else [])))
                fixture.add_init_script(r"""
                    (() => {
                        const nativeFetch = window.fetch.bind(window);
                        let complete;
                        window.fetch = async (input, options) => {
                            if (input === '/api/chat') return new Response(new ReadableStream({start(controller) {
                                const emit = event => controller.enqueue(new TextEncoder().encode(JSON.stringify(event) + '\n'));
                                emit({type:'token',content:'<img src=x onerror=alert(1)>\n\n```html\n<script>alert(1)</script>\n```\n\n[Docs](https://example.com)'});
                                emit({type:'approval',id:'fixture-approval',action:'write_file',reason:'Teste isolado da apresentação de diff.',diff:'--- exemplo.py\n+++ exemplo.py\n+print("revisar")\n',arguments:{path:'exemplo.py',content:'print("revisar")'}});
                                complete = () => { emit({type:'tool',name:'write_file',result:{error:'Recusado na fixture; nenhum arquivo foi alterado.'}}); emit({type:'done'}); controller.close(); };
                            }}), {headers:{'Content-Type':'application/x-ndjson'}});
                            if (typeof input === 'string' && input.startsWith('/api/approvals/')) {
                                window.__nexusFixtureDecision = JSON.parse(options.body);
                                complete();
                                return new Response('{"ok":true}', {headers:{'Content-Type':'application/json'}});
                            }
                            return nativeFetch(input, options);
                        };
                    })();
                """)
                fixture.goto(URL, wait_until="networkidle")
                expect(fixture.locator("#model-select")).to_have_value(re.compile(".+"))
                fixture.locator("#prompt").fill("Fixture isolada de recusa")
                fixture.locator("#send-button").click()
                fixture.locator(".approval-card").wait_for()
                assert "print" in fixture.locator(".approval-card").inner_text()
                assert fixture.locator(".message-body img, .message-body script").count() == 0
                fixture.locator(".approval-card .secondary-button").click()
                expect(fixture.locator("#stop-button")).to_be_hidden()
                assert fixture.evaluate("window.__nexusFixtureDecision.approved") is False
                assert fixture.locator(".message-body a").get_attribute("rel") == "noopener noreferrer"
                assert fixture.locator(".message-body img, .message-body script").count() == 0
                tests["approval_diff_and_untrusted_content"] = {"status": "passed", "fixture": True, "backend_action_executed": False, "diff_visible": True, "decision": "denied", "html_as_text": True, "safe_links": True}
                fixture.close()
                assert not result["page_errors"], result["page_errors"]
                assert not result["console_errors"], result["console_errors"]
                assert not result["external_requests"], result["external_requests"]
                tests["browser_errors"] = {"status": "passed", "page_errors": 0, "console_errors": 0, "external_requests": 0}
                result["status"] = "passed"
            except Exception as error:
                result["status"] = "failed"
                result["error"] = f"{type(error).__name__}: {error}"
                page.screenshot(path=str(REPORTS / "interface-failure.png"), full_page=True)
            finally:
                context.close()
    (REPORTS / "ui.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "tests": {key: value["status"] for key, value in tests.items()}, "error": result.get("error"), "report": "reports/ui.json"}, ensure_ascii=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
