"""Bounded Ghidra headless adapter. Static import is not target execution.

The private workspace is deliberately not called an OS sandbox. Running parsers
requires a separate human acknowledgement; hostile inputs belong in a VM.
No downloads, shell launchers, target execution, or arbitrary scripts are exposed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

import psutil

from .common import SecurityError, redact_secrets, safe_file, sha256_file
from .static import _read as read_artifact
from ..tools import Tools


MIB = 1024 * 1024
MAX_OUTPUT = 2 * MIB
SCRIPT = Path(__file__).resolve().parents[2] / "integrations/ghidra/NexusExport.java"
DEFAULTS = {"timeout_seconds": 180, "max_input_bytes": 10 * MIB,
            "max_functions": 100, "max_strings": 300, "max_references": 500,
            "heap_mib": 768, "rss_mib": 1536, "decompile": True,
            "isolation_acknowledged": False}
RANGES = {"timeout_seconds": (30, 300), "max_input_bytes": (1, 10 * MIB),
          "max_functions": (1, 200), "max_strings": (1, 500),
          "max_references": (1, 1000), "heap_mib": (256, 768), "rss_mib": (512, 1536)}
LIMITATIONS = ["Análise estática não comprova execução, explorabilidade nem ausência de malware.",
               "Diretório e perfil privados não isolam o parser do Windows, arquivos ou rede; não são uma VM/sandbox.",
               "Strings, chamadas e pseudocódigo são inferências do Ghidra e podem estar incompletos.",
               "Amostras não são executadas. Entradas hostis devem ser analisadas em VM isolada apropriada."]


def _config(value):
    if value is not None and not isinstance(value, dict):
        raise SecurityError("Configuração Ghidra deve ser um objeto.", "invalid_ghidra_config")
    result = dict(DEFAULTS)
    result.update(value or {})
    for key, (minimum, maximum) in RANGES.items():
        if type(result[key]) is not int or not minimum <= result[key] <= maximum:
            raise SecurityError("Limite Ghidra inválido: " + key, "invalid_ghidra_config")
    for key in ("decompile", "isolation_acknowledged"):
        if type(result[key]) is not bool:
            raise SecurityError("Opção Ghidra deve ser booleana: " + key, "invalid_ghidra_config")
    if result["heap_mib"] + 256 > result["rss_mib"]:
        raise SecurityError("Memória total precisa acomodar heap e pelo menos 256 MiB adicionais.", "invalid_ghidra_config")
    for key in ("install_dir", "java_home"):
        if result.get(key) and (not isinstance(result[key], str) or not Path(result[key]).is_absolute()):
            raise SecurityError("Use caminho absoluto em " + key, "invalid_ghidra_config")
    return result


def _properties(path):
    path = safe_file(path, maximum=128 * 1024)
    result = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if "=" in line and not line.lstrip().startswith(("#", "!")):
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"')
    return result


def _safe_dir(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        try:
            linked = Tools._is_link(item)
        except FileNotFoundError:
            continue
        if linked:
            raise SecurityError("Diretório Ghidra não pode conter links ou junctions.", "unsafe_runtime_path")
    return path


def _java_candidates(config):
    roots = [config.get("java_home"), os.environ.get("JAVA_HOME")]
    for name in ("ProgramFiles", "ProgramW6432"):
        if os.environ.get(name):
            for vendor in ("Java", "Eclipse Adoptium", "Microsoft"):
                parent = Path(os.environ[name]) / vendor
                if parent.is_dir() and not Tools._is_link(parent):
                    roots.extend(str(item) for item in sorted(parent.iterdir())[:30]
                                 if item.is_dir() and item.name.lower().startswith(("jdk", "openjdk", "temurin")))
    return list(dict.fromkeys(str(item) for item in roots if item))[:64]


class _WindowsJob:
    """Kernel memory/process limits, assigned while the child is suspended.

    A Windows Job is a resource boundary, not a file/network security sandbox.
    """
    def __init__(self, memory_bytes):
        if os.name != "nt":
            raise SecurityError("Este runner exige Windows Job Object; nenhum limite equivalente foi assumido.", "resource_boundary_unavailable")
        import ctypes
        from ctypes import wintypes as w
        self.ctypes = ctypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        class Basic(ctypes.Structure):
            _fields_ = [("ProcessTime", ctypes.c_int64), ("JobTime", ctypes.c_int64),
                        ("LimitFlags", w.DWORD), ("MinWorkingSet", ctypes.c_size_t),
                        ("MaxWorkingSet", ctypes.c_size_t), ("ActiveProcesses", w.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]
        class Extended(ctypes.Structure):
            _fields_ = [("Basic", Basic), ("IO", IO), ("ProcessMemory", ctypes.c_size_t),
                        ("JobMemory", ctypes.c_size_t), ("PeakProcess", ctypes.c_size_t), ("PeakJob", ctypes.c_size_t)]
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenThread.restype = w.HANDLE
        self.kernel.ResumeThread.argtypes = [w.HANDLE]
        self.kernel.ResumeThread.restype = w.DWORD
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise SecurityError("Windows não criou o limite de recursos.", "resource_boundary_unavailable")
        limits = Extended()
        limits.Basic.LimitFlags = 0x2000 | 0x100 | 0x200 | 0x8
        limits.Basic.ActiveProcesses = 8
        limits.ProcessMemory = memory_bytes
        limits.JobMemory = memory_bytes
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise SecurityError("Windows recusou o limite de memória/processos.", "resource_boundary_unavailable")

    def attach_and_resume(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise SecurityError("Não foi possível limitar o analisador antes da execução.", "resource_boundary_unavailable")
        threads = psutil.Process(process.pid).threads()
        if len(threads) != 1:
            raise SecurityError("Estado inesperado do processo suspenso.", "resource_boundary_unavailable")
        handle = self.kernel.OpenThread(0x2, False, threads[0].id)
        if not handle:
            raise SecurityError("Não foi possível iniciar o analisador limitado.", "resource_boundary_unavailable")
        try:
            if self.kernel.ResumeThread(handle) == 0xFFFFFFFF:
                raise SecurityError("Windows recusou iniciar o analisador limitado.", "resource_boundary_unavailable")
        finally:
            self.kernel.CloseHandle(handle)

    def close(self):
        if getattr(self, "handle", None):
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _work_size(root):
    total = entries = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            entries += 1
            path = Path(parent) / name
            if entries > 10000 or Tools._is_link(path):
                raise SecurityError("Workspace alterado ou com entradas excessivas.", "workspace_limit")
            if name in files:
                total += path.stat().st_size
                if total > 256 * MIB:
                    raise SecurityError("Workspace Ghidra excedeu 256 MiB.", "workspace_limit")
    return total


def _run(argv, workdir, env, *, timeout, memory_bytes, cancel=None, on_event=None):
    started = time.monotonic()
    job = _WindowsJob(memory_bytes)
    process = None
    peak_rss = 0
    code = "ok"
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(argv, cwd=str(workdir), env=env, shell=False,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                       creationflags=0x08000000 | 0x4, close_fds=True)
            job.attach_and_resume(process)
            if on_event:
                on_event({"event": "analyzer_started", "engine": "Ghidra", "pid": process.pid})
            next_disk_check = 0
            while process.poll() is None:
                now = time.monotonic()
                if cancel is not None and cancel.is_set():
                    code = "cancelled"
                    break
                if now - started >= timeout:
                    code = "tool_timeout"
                    break
                if os.fstat(output.fileno()).st_size > 512 * 1024:
                    code = "output_limit"
                    break
                try:
                    parent = psutil.Process(process.pid)
                    rss = sum(item.memory_info().rss for item in [parent] + parent.children(recursive=True))
                    peak_rss = max(peak_rss, rss)
                    if rss > memory_bytes:
                        code = "memory_limit"
                        break
                except psutil.NoSuchProcess:
                    pass
                except psutil.Error:
                    code = "resource_monitor_failed"
                    break
                if now >= next_disk_check:
                    _work_size(workdir)
                    next_disk_check = now + .5
                time.sleep(.05)
            if code != "ok":
                job.close()
            process.wait(timeout=5)
            # Closing also terminates decompiler descendants left by a failed Java parent.
            job.close()
            output.seek(0)
            text = output.read(512 * 1024).decode("utf-8", errors="replace")
            if code == "ok" and process.returncode != 0:
                code = "analyzer_failed"
            if code == "ok" and os.fstat(output.fileno()).st_size > 512 * 1024:
                code = "output_limit"
            return {"ok": code == "ok", "code": code, "exit_code": process.returncode,
                    "duration_seconds": round(time.monotonic() - started, 3), "peak_rss_bytes": peak_rss,
                    "output": redact_secrets(text), "resource_boundary": "Windows Job Object: committed memory + 8 processes; RSS watchdog"}
    finally:
        job.close()
        if process is not None and process.poll() is None:
            Tools._kill_tree(process)
            process.wait(timeout=5)


class Ghidra:
    def __init__(self, data_dir: Path, config=None):
        self.data_dir = Path(data_dir).absolute()
        self.config = _config(config)

    def inventory(self):
        result = {"id": "ghidra", "engine": "Ghidra headless", "available": False, "ok": False,
                  "code": "ghidra_unavailable", "version": None, "executed": False,
                  "target_executed": False, "limitations": list(LIMITATIONS),
                  "isolation": {"private_workspace": True, "os_sandbox": False, "vm_verified": False},
                  "configuration_help": "Configure install_dir para a distribuição oficial extraída e java_home para um JDK compatível; confirme a execução estática sem sandbox separadamente."}
        try:
            result["exporter_sha256"] = sha256_file(safe_file(SCRIPT, maximum=128 * 1024))
        except (OSError, ValueError) as exc:
            return {**result, "code": "exporter_unavailable", "error": str(exc)[:1000]}
        install = self.config.get("install_dir") or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
        if not install:
            discovered = shutil.which("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
            install = str(Path(discovered).parent.parent) if discovered else None
        try:
            if not install:
                return result
            root = _safe_dir(install)
            props = _properties(root / "Ghidra/application.properties")
            version = props.get("application.version", "")
            if not re.fullmatch(r"\d{1,2}\.\d{1,2}(?:\.\d{1,2})?", version):
                raise SecurityError("Versão Ghidra ausente ou inválida.", "invalid_installation")
            minimum = int(props.get("application.java.min", "21"))
            maximum = props.get("application.java.max", "")
            maximum = int(maximum) if maximum else None
            if not 17 <= minimum <= 30:
                raise SecurityError("Requisito Java desconhecido; valide a distribuição.", "unsupported_java_requirement")
            utility = safe_file(root / "Ghidra/Framework/Utility/lib/Utility.jar", maximum=64 * MIB)
            launcher = safe_file(root / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"), maximum=MIB)
            result.update(version=version, install_dir=str(root), utility_jar=str(utility),
                          utility_sha256=sha256_file(utility), launcher=str(launcher),
                          launcher_sha256=sha256_file(launcher), java_required_min=minimum, java_required_max=maximum,
                          installation_verified=False, signature_verified=False,
                          version_source="Ghidra/application.properties", code="jdk_unavailable")
            for candidate in _java_candidates(self.config):
                try:
                    jdk = _safe_dir(candidate)
                    release = _properties(jdk / "release")
                    match = re.match(r"(\d+)", release.get("JAVA_VERSION", ""))
                    major = int(match[1]) if match else 0
                    if major < minimum or (maximum is not None and major > maximum):
                        continue
                    java = safe_file(jdk / "bin" / ("java.exe" if os.name == "nt" else "java"), maximum=64 * MIB)
                    safe_file(jdk / "bin" / ("javac.exe" if os.name == "nt" else "javac"), maximum=64 * MIB)
                    result.update(java_home=str(jdk), java_path=str(java), java_version=release["JAVA_VERSION"],
                                  java_version_source="JDK/release", java_sha256=sha256_file(java), code="ready_unvalidated",
                                  available=os.name == "nt", ok=os.name == "nt")
                    if os.name != "nt":
                        result.update(code="resource_boundary_unavailable")
                    break
                except (OSError, ValueError):
                    continue
            return redact_secrets(result)
        except (OSError, ValueError) as exc:
            result.update(code=getattr(exc, "code", "invalid_installation"), error=str(exc)[:1000])
            return result

    def _environment(self, workspace, java_home):
        env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "LANG") if key in os.environ}
        for child in ("profile", "tmp", "cache", "appdata", "scripts", "projects"):
            (workspace / child).mkdir()
        env.update(JAVA_HOME=java_home, PATH=str(Path(java_home) / "bin"),
                   USERPROFILE=str(workspace / "profile"), APPDATA=str(workspace / "appdata"),
                   LOCALAPPDATA=str(workspace / "appdata"), TEMP=str(workspace / "tmp"), TMP=str(workspace / "tmp"),
                   XDG_CONFIG_HOME=str(workspace / "profile"), XDG_CACHE_HOME=str(workspace / "cache"))
        return env

    def _workspace(self):
        root = _safe_dir(self.data_dir / "security/ghidra")
        root.mkdir(parents=True, exist_ok=True)
        _safe_dir(root)
        return tempfile.TemporaryDirectory(prefix="run-", dir=root)

    def validate(self):
        state = self.inventory()
        if not state["available"]:
            return state
        try:
            with self._workspace() as folder:
                work = Path(folder)
                env = self._environment(work, state["java_home"])
                run = _run([state["java_path"], "-version"], work, env, timeout=10,
                           memory_bytes=self.config["rss_mib"] * MIB)
            state.update(ok=run["ok"], code="validated_dependencies" if run["ok"] else run["code"],
                         executed=True, validation=run, headless_analyzer_tested=False)
            # Metadata alone is not proof that the executable matches it.
            match = re.search(r'(?:java|openjdk) version "(\d+)', run["output"], re.IGNORECASE)
            if run["ok"] and (not match or int(match[1]) < state["java_required_min"]
                              or int(match[1]) != int(state["java_version"].split(".")[0])
                              or (state["java_required_max"] is not None and int(match[1]) > state["java_required_max"])):
                state.update(ok=False, code="java_version_mismatch")
            return redact_secrets(state)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            return {**state, "ok": False, "code": getattr(exc, "code", "validation_failed"), "error": str(exc)[:1000]}

    def _argv(self, state, work, source):
        cfg = self.config
        return [state["java_path"], "-Xmx" + str(cfg["heap_mib"]) + "m", "-Xshare:off",
                "-Djava.system.class.loader=ghidra.GhidraClassLoader", "-Djava.awt.headless=true",
                "-Dfile.encoding=UTF8", "-Duser.language=en", "-Duser.country=US",
                "-Duser.home=" + str(work / "profile"), "-Djava.io.tmpdir=" + str(work / "tmp"),
                "-Dapplication.settingsdir=" + str(work / "profile"),
                "-Dapplication.cachedir=" + str(work / "cache"),
                "-Dapplication.tempdir=" + str(work / "tmp"), "-Dcpu.core.limit=1",
                "-Djavax.xml.accessExternalDTD=", "-Djavax.xml.accessExternalSchema=",
                "-Djavax.xml.accessExternalStylesheet=", "--enable-native-access=ALL-UNNAMED",
                "-cp", state["utility_jar"], "ghidra.GhidraLauncher", "ghidra.app.util.headless.AnalyzeHeadless",
                str(work / "projects"), "NexusPrivate", "-import", str(source),
                "-readOnly", "-deleteProject", "-max-cpu", "1",
                "-analysisTimeoutPerFile", str(max(10, cfg["timeout_seconds"] - 30)),
                "-scriptPath", str(work / "scripts"), "-postScript", "NexusExport.java",
                str(work / "result.json"), str(cfg["max_functions"]), str(cfg["max_strings"]),
                str(cfg["max_references"]), "true" if cfg["decompile"] else "false",
                "-log", str(work / "analysis.log"), "-scriptlog", str(work / "script.log")]

    def analyze(self, path, *, expected_sha256=None, cancel=None, on_event=None):
        base = {"engine": "Ghidra headless", "target_executed": False,
                "limitations": list(LIMITATIONS), "limits": {key: self.config[key] for key in DEFAULTS}, "untrusted_content": True,
                "isolation": {"private_workspace": True, "os_sandbox": False, "vm_verified": False}}
        try:
            if not Path(path).is_absolute():
                raise SecurityError("Amostra deve usar caminho absoluto do armazenamento cadastrado.", "outside_sample_store")
            source = safe_file(path, maximum=self.config["max_input_bytes"])
            sample_root = _safe_dir(self.data_dir / "security/samples").resolve()
            if source.parent != sample_root:
                raise SecurityError("Somente amostras cadastradas no armazenamento Security Center.", "outside_sample_store")
            digest = sha256_file(source)
            if expected_sha256 is not None and digest != expected_sha256:
                raise SecurityError("O hash da amostra mudou desde a aprovação.", "artifact_changed")
            with source.open("rb") as stream:
                header = stream.read(4)
            supported = header[:2] == b"MZ" or header in {b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
            if not supported:
                raise SecurityError("Importação limitada a PE, ELF e Mach-O simples; arquitetura final é detectada pelo Ghidra.", "unsupported_static_format")
            state = self.inventory()
            base.update(version=state.get("version"), sha256=digest, size_bytes=source.stat().st_size)
            if not state["available"]:
                return {**base, "ok": False, "code": state["code"], "availability": state}
            if not self.config["isolation_acknowledged"]:
                raise SecurityError("A execução estática sem VM/sandbox requer ciência e aprovação humana específica.", "isolation_acknowledgement_required")
            if cancel is not None and cancel.is_set():
                return {**base, "ok": False, "code": "cancelled"}
            if psutil.virtual_memory().available < (self.config["rss_mib"] + 256) * MIB:
                raise SecurityError("RAM livre insuficiente para o orçamento Ghidra; descarregue modelos antes de tentar.", "insufficient_memory")
            for key in ("utility_sha256", "java_sha256", "launcher_sha256", "exporter_sha256"):
                if self.config.get(key) and self.config[key] != state.get(key):
                    raise SecurityError("A instalação Ghidra/JDK mudou desde a aprovação.", "installation_changed")
            with self._workspace() as folder:
                work = Path(folder)
                env = self._environment(work, state["java_home"])
                snapshot = work / "sample.bin"
                # Bounded immutable snapshot; subprocess never receives the original path.
                content = read_artifact(source, self.config["max_input_bytes"])
                if hashlib.sha256(content).hexdigest() != digest:
                    raise SecurityError("A amostra mudou durante a cópia.", "artifact_changed")
                snapshot.write_bytes(content)
                del content
                snapshot.chmod(0o400)
                exporter = safe_file(SCRIPT, maximum=128 * 1024)
                shutil.copyfile(exporter, work / "scripts/NexusExport.java")
                run = _run(self._argv(state, work, snapshot), work, env,
                           timeout=self.config["timeout_seconds"], memory_bytes=self.config["rss_mib"] * MIB,
                           cancel=cancel, on_event=on_event)
                base.update(runtime={key: value for key, value in run.items() if key != "output"},
                            exporter_sha256=sha256_file(exporter),
                            tool_provenance={key: state.get(key) for key in ("version", "utility_sha256", "java_version", "java_sha256")})
                if not run["ok"]:
                    return redact_secrets({**base, "ok": False, "code": run["code"], "diagnostic": run["output"][-4000:]})
                result_path = safe_file(work / "result.json", maximum=MAX_OUTPUT)
                evidence = json.loads(result_path.read_text(encoding="utf-8"))
                self._validate_evidence(evidence, digest)
                if sha256_file(safe_file(source, maximum=self.config["max_input_bytes"])) != digest:
                    raise SecurityError("A amostra original mudou durante a análise; evidências descartadas.", "artifact_changed")
                return redact_secrets({**base, "ok": True, "code": "partial" if evidence.get("analysis_timed_out") else "ok",
                                       "source": "Ghidra headless / NexusExport.java", **evidence})
        except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError) as exc:
            return redact_secrets({**base, "ok": False, "code": getattr(exc, "code", "ghidra_analysis_failed"),
                                   "error": str(exc)[:2000]})

    def _validate_evidence(self, evidence, digest):
        if (not isinstance(evidence, dict) or evidence.get("schema") != "nexus-ghidra-v1"
                or not isinstance(evidence.get("sha256"), str) or evidence["sha256"].lower() != digest):
            raise SecurityError("Exportação Ghidra não corresponde ao esquema/hash da amostra.", "invalid_tool_output")
        # Do not permit untrusted scanner fields to overwrite runtime integrity metadata.
        allowed = {"schema", "sha256", "language_id", "compiler_spec", "executable_format", "image_base", "entry_points",
                   "functions", "strings", "imports", "exports", "references", "analysis_timed_out", "coverage", "decompiler"}
        if set(evidence) - allowed:
            raise SecurityError("Exportação Ghidra contém campos inesperados.", "invalid_tool_output")
        caps = {"functions": self.config["max_functions"], "strings": self.config["max_strings"],
                "references": self.config["max_references"], "imports": 500, "exports": 500, "entry_points": 100}
        for key, maximum in caps.items():
            if not isinstance(evidence.get(key), list) or len(evidence[key]) > maximum:
                raise SecurityError("Coleção Ghidra inválida ou acima do limite: " + key, "invalid_tool_output")
            expected_type = str if key == "entry_points" else dict
            if any(not isinstance(item, expected_type) for item in evidence[key]):
                raise SecurityError("Tipo inválido em coleção Ghidra: " + key, "invalid_tool_output")
        if (type(evidence.get("analysis_timed_out")) is not bool
                or not isinstance(evidence.get("coverage"), dict)
                or not isinstance(evidence.get("decompiler"), dict)):
            raise SecurityError("Metadados de cobertura Ghidra inválidos.", "invalid_tool_output")
        # Scanner JSON remains untrusted even when produced by a local process.
        stack = [(evidence, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > 25000 or depth > 10:
                raise SecurityError("Estrutura Ghidra excedeu os limites de complexidade.", "invalid_tool_output")
            if isinstance(value, dict):
                if any(not isinstance(key, str) or len(key) > 200 for key in value):
                    raise SecurityError("Chave Ghidra inválida.", "invalid_tool_output")
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                stack.extend((item, depth + 1) for item in value)
            elif isinstance(value, str) and len(value) > 10000:
                raise SecurityError("Campo textual Ghidra excedeu o limite.", "invalid_tool_output")
            elif isinstance(value, float):
                import math
                if not math.isfinite(value):
                    raise SecurityError("Número Ghidra inválido.", "invalid_tool_output")
