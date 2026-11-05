"""Instala motores portateis fixados; sem argumentos, apenas verifica offline.

Use --instalar somente para baixar Nuclei, JDK, Ghidra e ZAP. A configuracao
gerada nao aprova scanners, analises ou a execucao de parsers fora de uma VM.
Revise os novos caminhos em Security Center 2.0 > Ferramentas antes de usar.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import install_security_runtime as runtime
from nexus.security.ghidra import Ghidra
from nexus.security.installers import NucleiInstaller, VERSION as NUCLEI_VERSION


MAX_CONFIG_BYTES = 64 * 1024


def emit(**value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


def read_configuration(path):
    path = runtime.safe(path)
    if not path.exists():
        return None, {}
    if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("modules.json precisa ser um arquivo regular de ate 64 KiB.")
    original = path.read_bytes()
    value = json.loads(original.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("modules.json precisa conter um objeto JSON.")
    return original, value


def same_path(value, expected):
    if not isinstance(value, str) or not Path(value).is_absolute():
        return False
    return os.path.normcase(os.path.abspath(value)) == os.path.normcase(os.path.abspath(expected))


def merge_configuration(current, candidates):
    """Preserve custom paths and unrelated settings; new identities lose approval."""
    result = copy.deepcopy(current)
    notices = []
    fields = {"nuclei": ("path",), "zap": ("jar", "java"),
              "ghidra": ("install_dir", "java_home")}
    for engine, candidate in candidates.items():
        previous = current.get(engine, {})
        if not isinstance(previous, dict):
            notices.append({"engine": engine, "code": "custom_configuration_preserved",
                            "message": "Configuracao existente nao e um objeto; revise pelo painel."})
            continue
        if any(previous.get(key) is not None and not same_path(previous[key], candidate[key])
               for key in fields[engine]):
            notices.append({"engine": engine, "code": "custom_paths_preserved",
                            "message": "Caminhos personalizados foram preservados. O pacote portatil nao os substituiu."})
            continue
        merged = {**previous, **candidate}
        identity = (*fields[engine], *(key for key in candidate if key.endswith("sha256")))
        unchanged = all((same_path(previous.get(key), candidate[key]) if key in fields[engine]
                         else previous.get(key) == candidate[key]) for key in identity)
        # Installation is separate from the human approval owned by the panel.
        if not unchanged:
            merged["approved"] = False
            if engine == "ghidra":
                merged["isolation_acknowledged"] = False
        else:
            merged.setdefault("approved", False)
            if engine == "ghidra":
                merged.setdefault("isolation_acknowledged", False)
        result[engine] = merged
        notices.append({"engine": engine, "code": "configuration_unchanged" if merged == previous else "paths_prepared",
                        "requires_configuration_approval": merged.get("approved") is not True})
    return result, notices


def write_configuration(path, original, value):
    payload = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(payload) > MAX_CONFIG_BYTES:
        raise ValueError("Configuracao resultante excede 64 KiB; nada foi gravado.")
    path = runtime.safe(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    runtime.safe(path.parent)
    temporary = runtime.safe(path.with_name(".modules-" + secrets.token_hex(12) + ".tmp"))
    try:
        with temporary.open("xb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        observed, _ = read_configuration(path)
        if observed != original:
            raise ValueError("modules.json mudou durante a instalacao; configuracao concorrente preservada.")
        temporary.replace(path)
    finally:
        if temporary.exists():
            runtime.safe(temporary).unlink()


def collect(data_dir, *, install=False):
    base = data_dir / "security/tools"
    states = {}
    for name, package in runtime.PACKAGES.items():
        emit(tool=name, stage="verification", version=package.version)
        if install:
            runtime.install(package, base=base, emit=emit)
        state = runtime.inventory(package, base=base)
        states[name] = state
        emit(tool=name, version=package.version, **state)
    installer = NucleiInstaller(data_dir)
    if install:
        installed = installer.run(emit=lambda value: emit(tool="nuclei", **value))
        if not installed.get("ok"):
            raise ValueError("Nuclei: " + str(installed.get("error") or installed.get("code")))
    states["nuclei"] = installer.inventory()
    if states["nuclei"].get("ok") is False:
        raise ValueError("Nuclei: " + str(states["nuclei"].get("error") or states["nuclei"].get("code")))
    emit(**states["nuclei"])
    return states


def configuration_candidates(data_dir, states):
    candidates = {}
    nuclei = states["nuclei"]
    if nuclei.get("installed"):
        candidates["nuclei"] = {"path": nuclei["path"], "sha256": nuclei["sha256"],
                                 "version": NUCLEI_VERSION}
    if states["java"].get("installed") and states["zap"].get("installed"):
        java = runtime.safe(Path(states["java"]["path"]) / "bin/java.exe")
        jar = runtime.safe(Path(states["zap"]["path"]) / ("zap-" + runtime.PACKAGES["zap"].version + ".jar"))
        candidates["zap"] = {"jar": str(jar), "sha256": runtime.digest_file(jar),
                             "java": str(java), "java_sha256": runtime.digest_file(java),
                             "version": runtime.PACKAGES["zap"].version}
    if states["java"].get("installed") and states["ghidra"].get("installed"):
        paths = {"install_dir": states["ghidra"]["path"], "java_home": states["java"]["path"]}
        state = Ghidra(data_dir, paths).inventory()
        if not state.get("available"):
            raise ValueError("Ghidra/JDK: " + str(state.get("error") or state.get("code")))
        candidates["ghidra"] = {**paths, "version": state["version"],
            **{key: state[key] for key in ("java_sha256", "utility_sha256", "launcher_sha256", "exporter_sha256")}}
    return candidates


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--instalar", action="store_true", help="Baixar pacotes fixados e preparar caminhos locais, sem aprovar execucao.")
    mode.add_argument("--verificar", action="store_true", help="Verificar instalacoes locais sem rede ou alteracoes (padrao).")
    args = parser.parse_args(argv)
    try:
        data_dir = runtime.safe(ROOT / "data")
        path = data_dir / "security/modules.json"
        original, current = read_configuration(path)
        states = collect(data_dir, install=args.instalar)
        candidates = configuration_candidates(data_dir, states)
        updated, notices = merge_configuration(current, candidates)
        changed = updated != current
        if args.instalar and changed:
            write_configuration(path, original, updated)
        for notice in notices:
            emit(**notice)
        emit(ok=True, preview_only=not args.instalar, configuration_changed=args.instalar and changed,
             configuration_would_change=changed, executed=False,
             message="Revise novos caminhos e aprove as ferramentas pelo painel. Instalacao nao comprova execucao nativa.")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        emit(ok=False, executed=False, error=str(exc),
             message="Instalacoes verificadas foram preservadas. Nenhuma aprovacao foi criada.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
