"""Real headless Ghidra validation using a generated harmless ELF, never run.

Uses the authenticated human preview/approval/task API and the existing 3 GiB
guard. This script does not install or configure engines or change RAM limits.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

import httpx
import psutil

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def laboratory_elf() -> bytes:
    """Two named x86-64 functions plus a marker in a complete ELF64 container.

    These bytes are a static parser fixture. No subprocess ever receives them
    as an executable, including during fixture construction.
    """
    data = bytearray(0x1300)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x401000, 64, 0x1180, 0, 64, 56, 1, 64, 6, 5)
    data[64:120] = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, len(data), len(data), 0x1000)
    # _start: call a tiny arithmetic helper, then an exit syscall; never run.
    code = b"\xbf\x07\x00\x00\x00\xe8\x16\x00\x00\x00\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05"
    data[0x1000:0x1000 + len(code)] = code
    data[0x1020:0x1024] = b"\x8d\x47\x03\xc3"  # add_three(int)
    marker = b"NEXUS_LAB_STATIC_ONLY\x00"
    data[0x1040:0x1040 + len(marker)] = marker
    strings = b"\x00_start\x00add_three\x00"
    data[0x1080:0x1080 + len(strings)] = strings
    data[0x10c0:0x10d8] = bytes(24)
    data[0x10d8:0x10f0] = struct.pack("<IBBHQQ", 1, 0x12, 0, 1, 0x401000, len(code))
    data[0x10f0:0x1108] = struct.pack("<IBBHQQ", 8, 0x12, 0, 1, 0x401020, 4)
    names = b"\x00.text\x00.rodata\x00.symtab\x00.strtab\x00.shstrtab\x00"
    data[0x1120:0x1120 + len(names)] = names
    sections = [bytes(64),
        struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0x401000, 0x1000, 0x24, 0, 0, 16, 0),
        struct.pack("<IIQQQQIIQQ", 7, 1, 2, 0x401040, 0x1040, len(marker), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 15, 2, 0, 0, 0x10c0, 72, 4, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", 23, 3, 0, 0, 0x1080, len(strings), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 31, 3, 0, 0, 0x1120, len(names), 0, 0, 1, 0)]
    data[0x1180:0x1300] = b"".join(sections)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="security-runtime-ghidra-real.json")
    args = parser.parse_args()
    if Path(args.report).name != args.report or not args.report.endswith(".json"):
        parser.error("Provide a JSON basename within reports only")
    output = ROOT / "reports" / args.report
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "ok": False,
              "real_authenticated_api": True, "authenticated_api_used": False, "native_jobs_submitted": 0,
              "target_executed": False, "downloads": False,
              "public_network": False, "fixture_type": "generated harmless ELF64 with two known arithmetic functions",
              "tests": {}, "errors": []}
    try:
        available = psutil.virtual_memory().available
        report["available_ram_bytes"] = available
        if available < 3 * 1024 ** 3:
            report.update(code="resource_budget", reason="Less than the existing 3 GiB RAM guard; no Java or analysis started")
            return report
        token = (ROOT / "data/auth.secret").read_text(encoding="ascii").strip()
        with httpx.Client(base_url="http://127.0.0.1:8765", headers={"Authorization": "Bearer " + token},
                          trust_env=False, timeout=30) as client:
            def request(method, path, **kwargs):
                result = client.request(method, path, **kwargs)
                report["authenticated_api_used"] = True
                result.raise_for_status()
                return result.json()

            state = request("GET", "/api/security/v2/status")["ghidra"]
            assert state["available"], state
            report["inventory"] = state
            data = laboratory_elf()
            sha = hashlib.sha256(data).hexdigest()
            sample = request("POST", "/api/security/samples", params={"name": "nexus-two-functions-static-lab.elf"},
                             content=data, headers={"Content-Type": "application/octet-stream"})
            assert sample["sha256"] == sha
            report["sample"] = {"id": sample["id"], "sha256": sha, "bytes": len(data), "target_executed": False}
            preview = request("POST", "/api/security/v2/preview", json={"engine": "ghidra", "sample_id": sample["id"], "args": {}})
            assert preview["requires_approval"] is True
            approved = request("POST", "/api/security/v2/approvals/" + preview["approval_id"] + "/decision", json={"approved": True})
            identity = approved["job"]["id"]
            report["native_jobs_submitted"] += 1
            report["run_id"] = identity
            deadline = time.monotonic() + 330
            while time.monotonic() < deadline:
                run = request("GET", "/api/security/v2/runs/" + identity)
                if run["state"] not in {"queued", "running", "cancelling"}:
                    break
                time.sleep(.3)
            else:
                request("POST", "/api/security/v2/runs/" + identity + "/cancel")
                raise AssertionError("Ghidra run exceeded the existing bounded task deadline")
            report["run"] = run
            assert run["ok"], {key: run.get(key) for key in ("state", "code", "error", "result")}
            result = run["result"]
            assert result["sha256"] == sha and result["target_executed"] is False
            functions = result["functions"]
            assert len(functions) >= 2, functions
            assert any(item["name"] == "add_three" for item in functions), functions
            assert result["decompiler"]["available"] is True, result["decompiler"]
            assert result["decompiler"]["functions_decompiled"] >= 1, result["decompiler"]
            assert any(item.get("pseudocode") for item in functions), functions
            report["tests"]["real_static_analysis_and_native_decompilation"] = {
                "status": "passed", "functions": len(functions), "decompiled": result["decompiler"]["functions_decompiled"],
                "references": len(result["references"]), "coverage": result["coverage"], "runtime": result["runtime"]}
            exports = {}
            for fmt in ("json", "md", "html"):
                exported = client.get("/api/security/v2/reports/" + run["report_id"], params={"format": fmt})
                exported.raise_for_status()
                assert exported.content
                exports[fmt] = {"bytes": len(exported.content), "content_type": exported.headers.get("content-type")}
            report["tests"]["authenticated_report_exports"] = {"status": "passed", "formats": exports}
            report.update(ok=True, code="validated_native_headless")
    except Exception as exc:
        report["errors"].append(type(exc).__name__ + ": " + str(exc)[:8000])
        raise
    finally:
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"ok": report["ok"], "code": report.get("code"), "report": str(output)}, ensure_ascii=True))
    return report


if __name__ == "__main__":
    result = main()
    raise SystemExit(0 if result["ok"] else 2)
