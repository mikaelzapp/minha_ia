"""Inventário limitado de um ativo: DNS, HTTP, TLS e histórico sem crawlers."""
from . import network
from .common import SecurityError


def preview_assets(scope, target, known_subdomains=None):
    destination = network.ScopePolicy(scope).authorize_target(target, "asset_inventory", resolve=False)
    known_subdomains = known_subdomains or []
    if not isinstance(known_subdomains, list) or len(known_subdomains) > 5:
        raise SecurityError("Informe até cinco subdomínios conhecidos; não há enumeração por força bruta.")
    normalized = []
    for name in known_subdomains:
        item = network.ScopePolicy(scope).authorize_target(name, "asset_inventory", resolve=False)
        if not item["host"].endswith("." + destination["host"]):
            raise SecurityError("Subdomínio deve pertencer ao domínio principal autorizado.")
        normalized.append(item["host"])
    return {"target": destination["url"], "known_subdomains": normalized,
        "operations": ["DNS A/AAAA", "HTTP HEAD sem redirects", "TLS validado se HTTPS", "DNS de até cinco nomes informados"],
        "limits": {"hosts": 6, "requests_per_host": 1, "concurrency": 1},
        "exclusions": ["DNS brute force", "MX/TXT", "certificate transparency providers", "private information", "credential collection"]}


def inspect_assets(scope, target, known_subdomains=None, *, cancel=None, scope_loader=None):
    preview = preview_assets(scope, target, known_subdomains)
    def check():
        if cancel and cancel.is_set():
            raise SecurityError("Investigação cancelada.", "cancelled")
        fresh = scope_loader() if scope_loader else scope
        if fresh.get("revision") != scope.get("revision"):
            raise SecurityError("Escopo alterado.", "scope_changed")
        return fresh
    fresh = check()
    destination = network.ScopePolicy(fresh).authorize_target(target, "asset_inventory")
    delegated = {**fresh, "allowed_tests": sorted(set(fresh["allowed_tests"]) | {"http_headers", "tls_certificate"})}
    http = network.inspect_http(delegated, target)
    check()
    tls = network.inspect_tls(delegated, target) if destination["scheme"] == "https" else {"ok": False, "code": "not_applicable"}
    hosts = []
    for name in preview["known_subdomains"]:
        fresh = check()
        try:
            row = network.ScopePolicy(fresh).authorize_target(name, "asset_inventory")
            hosts.append({"host": name, "addresses": row["addresses"]})
        except ValueError as exc:
            hosts.append({"host": name, "error": str(exc)})
    return {"ok": http.get("ok", False), "engine": "asset_inventory", "target": destination["url"],
        "dns": {"host": destination["host"], "addresses": destination["addresses"], "record_types": ["A", "AAAA"]},
        "http": http, "tls": tls, "known_subdomains": hosts, "findings": http.get("findings", []),
        "coverage": preview, "limitations": ["Headers podem sugerir tecnologia; não comprovam versão ou CVE.",
            "Subdomínios são informados pelo usuário. Nenhuma enumeração ou fonte externa de certificados foi consultada."]}
