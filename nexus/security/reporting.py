"""Relatórios de evidências: normalização conservadora e exportação inerte."""
from __future__ import annotations

import hashlib
import html
import json
import re
from urllib.parse import urlsplit, urlunsplit, urljoin

from .common import redact_secrets

SECRET_KEY = re.compile(r"(?i)(?:^|[_-])(?:password|passwd|secret|token|authorization|cookie|api[_-]?key|credentials?)(?:$|[_-])")
SAFE_METADATA = {"cookie_attributes", "cookie_flags", "cookie_security", "cookies_returned"}
SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}


def sanitize(value, depth=0):
    if depth > 20:
        return "[limite de profundidade]"
    if isinstance(value, dict):
        return {str(k)[:200]: "[redigido]" if SECRET_KEY.search(str(k)) and str(k) not in SAFE_METADATA and not isinstance(v, bool) else sanitize(v, depth + 1)
                for k, v in list(value.items())[:1000]}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, depth + 1) for v in value[:2000]]
    if isinstance(value, str):
        value = redact_secrets(value[:100_000])
        value = re.sub(r"(?im)\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]+", r"\1: [redigido]", value)
        return value
    return value if isinstance(value, (bool, int, float, type(None))) else str(value)[:1000]


def _location(row):
    url = row.get("endpoint") or row.get("matched-at") or row.get("url") or row.get("target")
    if url:
        try:
            p = urlsplit(str(url))
            if p.scheme in {"http", "https"}:
                return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", ""))
        except ValueError:
            pass
    path = row.get("file") or row.get("path")
    if path:
        return f"{path}:{row.get('line', '')}"
    return ""


def correlate(findings, engine="unknown", target=None):
    """Merge only same weakness+location+parameter; never merge all CVEs at a URL."""
    if not isinstance(findings, list):
        raise ValueError("Achados do adaptador precisam ser uma lista estruturada.")
    rows = {}
    for raw in findings[:1000]:
        if not isinstance(raw, dict):
            continue
        row = sanitize(raw)
        evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
        if not row.get("parameter") and evidence.get("parameter"):
            row["parameter"] = evidence["parameter"]
        if not row.get("endpoint") and evidence.get("endpoint"):
            row["endpoint"] = urljoin(target or "", str(evidence["endpoint"]))
        if target and not any(row.get(k) for k in ("endpoint", "matched-at", "url", "target", "file", "path")):
            row["target"] = target
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cwe = row.get("cwe") or row.get("cwe_id") or classification.get("cwe-id")
        if isinstance(cwe, list):
            cwe = ",".join(sorted(map(str, cwe)))
        cve = row.get("cve") or classification.get("cve-id") or ""
        if isinstance(cve, list):
            cve = ",".join(sorted(map(str, cve)))
        weakness = str(cwe or row.get("cve") or row.get("rule_id") or row.get("id") or row.get("template-id") or row.get("title") or "unclassified")
        location = _location(row)
        # Unknown-location observations are not assumed to be the same problem.
        key = json.dumps([weakness, str(cve), location or raw, row.get("parameter", "")], sort_keys=True, default=str)
        fingerprint = hashlib.sha256(key.encode()).hexdigest()[:24]
        source = str(row.get("engine") or row.get("source") or engine)
        severity = str(row.get("severity") or info.get("severity") or "info").lower()
        confirmed = row.get("confirmed") is True
        normalized = {**row, "id": fingerprint, "rule_id": row.get("rule_id") or row.get("id") or row.get("template-id"),
            "title": str(row.get("title") or info.get("name") or weakness),
            "severity": severity if severity in SEVERITY else "info", "location": location,
            "confirmation": row.get("confirmation") or row.get("validation") or ("scanner_evidence" if confirmed else "unconfirmed"),
            "confirmed": confirmed, "sources": [source], "occurrences": 1,
            "evidence": [row.get("evidence", row.get("description", ""))]}
        if fingerprint not in rows:
            rows[fingerprint] = normalized
        else:
            prior = rows[fingerprint]
            prior["sources"] = sorted(set(prior["sources"] + [source]))
            prior["occurrences"] += 1
            if len(prior["evidence"]) < 10:
                prior["evidence"].append(normalized["evidence"][0])
            if SEVERITY[normalized["severity"]] > SEVERITY[prior["severity"]]:
                prior["severity"] = normalized["severity"]
            prior["confirmed"] |= confirmed
            levels = {"unconfirmed": 0, "dynamic_indication": 1, "scanner_evidence": 2, "confirmed_controlled": 3}
            if levels.get(normalized["confirmation"], 0) > levels.get(prior["confirmation"], 0):
                prior["confirmation"] = normalized["confirmation"]
    return sorted(rows.values(), key=lambda r: (-SEVERITY[r["severity"]], r["id"]))


def markdown(report):
    report = sanitize(report)
    return "# NEXUS Security Center 2.0\n\nEvidências limitadas à cobertura registrada.\n\n```json\n" + json.dumps(report, ensure_ascii=False, indent=2).replace("```", "` ` `") + "\n```\n"


def html_report(report):
    content = html.escape(json.dumps(sanitize(report), ensure_ascii=False, indent=2))
    return '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>NEXUS Security Center 2.0</title><style>body{max-width:1100px;margin:2rem auto;padding:1rem;font:16px system-ui;color:#182333}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>NEXUS Security Center 2.0</h1><p>Evidências limitadas à cobertura registrada.</p><pre>' + content + '</pre></html>'
