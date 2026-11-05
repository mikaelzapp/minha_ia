"""Security boundary tests; every network response is synthetic."""
import base64
import hashlib
import json
from pathlib import Path
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nexus.tools import MAX_FILE, ToolError, Tools


@pytest.fixture
def registry(tmp_path):
    instance = Tools(tmp_path / "workspace", tmp_path / "data")
    yield instance
    instance.close()


def names(instance, mode):
    return {tool["function"]["name"] for tool in instance.schemas(mode)}


def test_mode_capabilities_are_explicit(registry):
    assert names(registry, "CHAT") == set()
    assert names(registry, "unknown") == set()
    assert names(registry, "PLAN") == {"list_files", "read_file", "grep_files"}
    assert names(registry, "REVIEW") == names(registry, "PLAN")
    assert "write_file" in names(registry, "CODE")
    assert "write_file" not in names(registry, "RESEARCH")
    assert "browser_interact" not in names(registry, "CODE")
    assert "browser_interact" in names(registry, "AGENT")
    assert "tor_fetch" not in names(registry, "AGENT")
    registry.tor_enabled = True
    assert "tor_fetch" in names(registry, "RESEARCH")


def test_returned_schemas_cannot_change_registry(registry):
    schema = registry.schemas("PLAN")
    schema[0]["function"]["name"] = "evil"
    assert "evil" not in names(registry, "PLAN")


@pytest.mark.parametrize("path", ["../outside.txt", "nested/../../outside.txt", "/etc/passwd",
    "C:\\Users\\someone\\file.txt", "\\\\server\\share", "file.txt:secret", "dir./file", "dir /file",
    "NUL.txt", "dir/CON", "COM1"])
def test_traversal_absolute_paths_and_ads_are_refused(registry, path):
    assert not registry.execute("read_file", {"path": path})["ok"]
    assert not registry.execute("write_file", {"path": path, "content": "x"})["ok"]


@pytest.mark.parametrize("path", [".env", ".env.local", "sub/.env.prod", "id_rsa", "tls.key",
    "credentials.json", "secrets.py", ".aws/config", ".ssh/config", ".git/config", "keys.json",
    ".npmrc", ".netrc", ".git-credentials", ".docker/config.json"])
def test_secret_files_never_read_or_written(registry, path):
    target = registry.root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("private", encoding="utf-8")
    assert not registry.execute("read_file", {"path": path})["ok"]
    with pytest.raises(ToolError):
        registry.approval("write_file", {"path": path, "content": "changed"})
    assert target.read_text() == "private"


def test_secret_files_are_not_in_list_or_grep(registry):
    (registry.root / "public.py").write_text("hello public\nneedle", encoding="utf-8")
    (registry.root / ".env").write_text("needle SECRET", encoding="utf-8")
    result = registry.execute("list_files", {"recursive": True})
    assert [entry["path"] for entry in result["entries"]] == ["public.py"]
    matches = registry.execute("grep_files", {"query": "needle"})
    assert [entry["path"] for entry in matches["matches"]] == ["public.py"]


def test_link_and_dangling_link_are_refused(registry, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    link = registry.root / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Criação de symlink exige privilégio no Windows.")
    assert not registry.execute("read_file", {"path": "link.txt"})["ok"]
    assert not registry.execute("write_file", {"path": "link.txt", "content": "overwrite"})["ok"]
    outside.unlink()
    assert not registry.execute("write_file", {"path": "link.txt", "content": "create outside"})["ok"]
    assert not outside.exists()


def test_windows_reparse_points_are_refused_without_following(registry, monkeypatch):
    (registry.root / "junction").mkdir()
    real = registry._is_link
    monkeypatch.setattr(registry, "_is_link", lambda path: path.name == "junction" or real(path))
    assert not registry.execute("write_file", {"path": "junction/new.txt", "content": "x"})["ok"]
    assert not (registry.root / "junction/new.txt").exists()


def test_hardlinks_to_private_files_are_refused(registry, tmp_path):
    outside = tmp_path / "private.txt"
    outside.write_text("private", encoding="utf-8")
    linked = registry.root / "innocent.txt"
    try:
        linked.hardlink_to(outside)
    except OSError:
        pytest.skip("Sistema de arquivos sem suporte a hardlink.")
    assert not registry.execute("read_file", {"path": "innocent.txt"})["ok"]
    assert registry.execute("list_files", {})["entries"] == []


def test_write_requires_reviewable_diff_and_rejects_stale_versions(registry):
    path = registry.root / "hello.py"
    path.write_text("print(1)\n", encoding="utf-8")
    before = registry.execute("read_file", {"path": "hello.py"})
    args = {"path": "hello.py", "content": "print(2)\n", "expected_sha256": before["sha256"]}
    preview = registry.approval("write_file", args)
    assert "-print(1)" in preview["diff"] and "+print(2)" in preview["diff"]
    assert path.read_text() == "print(1)\n"
    path.write_text("concurrent edit", encoding="utf-8")
    assert not registry.execute("write_file", args)["ok"]
    assert path.read_text() == "concurrent edit"


def test_write_creates_parents_but_cannot_write_binary_or_large_files(registry):
    args = {"path": "new/module.py", "content": "print('olá')\n"}
    assert registry.approval("write_file", args)["action"] == "write_file"
    assert registry.execute("write_file", args)["ok"]
    assert registry.execute("read_file", {"path": "new/module.py"})["content"] == "print('olá')"
    assert not registry.execute("write_file", {"path": "bad", "content": "\x00"})["ok"]
    assert not registry.execute("write_file", {"path": "big", "content": "x" * (MAX_FILE + 1)})["ok"]


@pytest.mark.parametrize("name,args", [("unknown", {}), ("list_files", {"extra": "x"}),
    ("read_file", {}), ("read_file", {"path": 1}), ("list_files", {"max_results": True}),
    ("read_file", "{bad json"), ("read_file", [])])
def test_untrusted_tool_arguments_are_rejected(registry, name, args):
    result = registry.execute(name, args)
    assert result["ok"] is False and result["error"]


@pytest.mark.parametrize("argv", [["cmd.exe", "/c", "echo bad"], ["powershell", "-Command", "Get-Process"],
    ["runas", "/user:Administrator", "python"], ["rm", "file"], ["script.cmd"], ["git", "reset", "--hard"],
    ["python", "-c", "import shutil; shutil.rmtree('folder')"], ["python", "../outside.py"]])
def test_shell_admin_and_obvious_destructive_commands_are_blocked(registry, argv):
    with pytest.raises(ToolError):
        registry.approval("run_command", {"args": argv})


def test_every_command_requires_approval_even_python_and_pytest(registry, monkeypatch):
    monkeypatch.setattr("nexus.tools.shutil.which", lambda name: "python.exe")
    for argv in (["python", "-c", "print(1)"], ["python", "-m", "pytest"], ["git", "status"]):
        result = registry.approval("run_command", {"args": argv})
        assert result["action"] == "run_command"
        assert "sandbox" in result["reason"]
    assert registry.approval("read_file", {"path": "missing"}) is None


def test_command_execution_uses_argv_no_shell_and_kills_timeout(registry, monkeypatch):
    monkeypatch.setattr("nexus.tools.shutil.which", lambda name: "python.exe")
    proc = Mock()
    proc.poll.return_value = None
    proc.returncode = -9
    popen = Mock(return_value=proc)
    monkeypatch.setattr("nexus.tools.subprocess.Popen", popen)
    times = iter([0, 2, 2.1])
    monkeypatch.setattr("nexus.tools.time.monotonic", lambda: next(times))
    kill = Mock()
    monkeypatch.setattr(registry, "_kill_tree", kill)
    result = registry.execute("run_command", {"args": ["python", "-c", "print('a; echo b')"], "timeout": 1})
    assert result["ok"] and result["timed_out"]
    assert popen.call_args.kwargs["shell"] is False
    assert popen.call_args.args[0][-1] == "print('a; echo b')"
    kill.assert_called()


def dns(*addresses):
    return [(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))
            for address in addresses]


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1"])
def test_ssrf_denies_all_internal_ip_families(registry, monkeypatch, address):
    monkeypatch.setattr("nexus.tools.socket.getaddrinfo", lambda *a, **kw: dns(address))
    with pytest.raises(ToolError):
        registry._resolve("public-looking.example", 443)


def test_ssrf_denies_mixed_public_private_dns_answer(registry, monkeypatch):
    monkeypatch.setattr("nexus.tools.socket.getaddrinfo", lambda *a, **kw: dns("1.1.1.1", "10.0.0.1"))
    with pytest.raises(ToolError):
        registry._resolve("mixed.example", 443)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/file", "http://localhost/",
    "https://user:password@example.com", "http://example.com\\@localhost", "https://example.com/\nprivate",
    "http://foo.onion/", "http://service.internal/", "http://host:bogus/", "http://host:0/"])
def test_unsafe_url_syntax_rejected(registry, url):
    with pytest.raises(ToolError):
        registry._url(url)


class Response:
    def __init__(self, status=200, headers=None, body=b"<title>Public</title><p>text</p>"):
        self.status_code = status
        self.headers = headers or {"content-type": "text/html"}
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_bytes(self):
        yield self.body


def fake_http(monkeypatch, responses):
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    client.stream.side_effect = responses
    constructor = Mock(return_value=client)
    monkeypatch.setattr("httpx.Client", constructor)
    return client, constructor


def test_connection_pins_public_ip_and_preserves_tls_hostname(registry, monkeypatch):
    monkeypatch.setattr("nexus.tools.socket.getaddrinfo", lambda *a, **kw: dns("1.1.1.1"))
    client, ctor = fake_http(monkeypatch, [Response()])
    result = registry.execute("fetch_page", {"url": "https://public.example/article"})
    assert result["ok"] and result["title"] == "Public"
    assert result["url"] == "https://public.example/article"
    request = client.stream.call_args
    assert request.args[1] == "https://1.1.1.1:443/article"
    assert request.kwargs["headers"]["Host"] == "public.example"
    assert request.kwargs["extensions"]["sni_hostname"] == "public.example"
    assert ctor.call_args.kwargs["trust_env"] is False


def test_redirect_revalidates_destination_before_network(registry, monkeypatch):
    def addresses(host, *args, **kwargs):
        return dns("127.0.0.1" if host == "127.0.0.1" else "1.1.1.1")
    monkeypatch.setattr("nexus.tools.socket.getaddrinfo", addresses)
    client, _ = fake_http(monkeypatch, [Response(302, {"location": "http://127.0.0.1/private"})])
    result = registry.execute("fetch_page", {"url": "https://public.example"})
    assert not result["ok"]
    assert client.stream.call_count == 1


def test_response_size_limit_and_binary_fetch_refusal(registry, monkeypatch):
    monkeypatch.setattr("nexus.tools.socket.getaddrinfo", lambda *a, **kw: dns("1.1.1.1"))
    fake_http(monkeypatch, [Response(body=b"x" * 11)])
    with pytest.raises(ToolError, match="bytes"):
        registry._fetch_response("https://public.example", max_bytes=10)
    with pytest.raises(ToolError, match="textual"):
        registry._page_text({"url": "https://example.com/a.exe", "status": 200,
            "headers": {"content-type": "application/octet-stream"}, "body": b"binary"})


@pytest.mark.parametrize("query", ["Bearer abcdef123456", "api_key=privatevalue", "token: abc123",
    "sk-abcdefghijklmnopqrst", "C:\\Users\\Person\\private.py", "/home/person/private",
    "line1\nline2", "https://user:password@example.com", "-----BEGIN RSA PRIVATE KEY-----"])
def test_private_search_queries_never_reach_network(registry, monkeypatch, query):
    network = Mock(side_effect=AssertionError("Must not contact network"))
    monkeypatch.setattr(registry, "_fetch_response", network)
    assert not registry.execute("search_web", {"query": query})["ok"]
    network.assert_not_called()


def test_search_rows_preserve_real_urls_and_do_not_invent_dates(registry):
    rows = [{"title": "Official", "href": "https://docs.python.org/3/", "body": "Documentation"},
            {"title": "Dated", "url": "https://example.com/news", "publishedDate": "2026-11-05"},
            {"title": "bad", "url": "file:///private"}]
    result = registry._search_rows(rows, 5)
    assert len(result) == 2
    assert result[0]["published_date"] is None
    assert result[1]["published_date"] == "2026-11-05"


def test_download_requires_approval_and_cannot_overwrite(registry, monkeypatch):
    args = {"url": "https://example.com/info.pdf", "path": "downloads/info.pdf"}
    assert registry.approval("download_file", args)["action"] == "download_file"
    monkeypatch.setattr(registry, "_fetch_response", lambda url: {
        "url": url, "status": 200, "headers": {}, "body": b"%PDF public"})
    assert registry.execute("download_file", args)["ok"]
    assert not registry.execute("download_file", args)["ok"]
    assert (registry.root / args["path"]).read_bytes() == b"%PDF public"


def valid_onion():
    public_key = bytes(range(32))
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode().lower() + ".onion"


@pytest.mark.parametrize("proxy", ["socks5://127.0.0.1:9050", "socks5h://remote.example:9050",
    "socks5h://user:pass@127.0.0.1:9050", "socks5h://127.0.0.1", "http://127.0.0.1:9050"])
def test_tor_proxy_must_be_explicit_loopback_socks5h(registry, proxy):
    registry.tor_enabled = True
    registry.tor_proxy = proxy
    with pytest.raises(ToolError):
        registry._validate_tor_proxy()


def test_tor_disabled_by_default_no_network(registry, monkeypatch):
    network = Mock(side_effect=AssertionError("network forbidden"))
    monkeypatch.setattr(registry, "_tor_request", network)
    assert not registry.execute("tor_check", {})["ok"]
    assert not registry.execute("tor_fetch", {"url": "http://" + valid_onion()})["ok"]
    network.assert_not_called()


def test_onion_v3_requires_checksum_and_never_uses_local_dns(registry, monkeypatch):
    registry.tor_enabled = True
    monkeypatch.setattr("nexus.tools.socket.getaddrinfo", Mock(side_effect=AssertionError("DNS leak")))
    checked = registry._onion_url("http://" + valid_onion() + "/docs")
    assert checked.hostname == valid_onion()
    with pytest.raises(ToolError):
        registry._onion_url("http://" + "a" * 56 + ".onion/")
    with pytest.raises(ToolError):
        registry._onion_url("http://example.com")
    with pytest.raises(ToolError):
        registry._onion_url("http://abcdefghijklmnop.onion")


def test_tor_fetch_checks_network_first_and_rejects_clearnet_redirect(registry, monkeypatch):
    registry.tor_enabled = True
    request = Mock(side_effect=[{"status": 200, "body": b'{"IsTor": true, "IP": "1.1.1.1"}'},
        {"status": 302, "headers": {"location": "https://example.com"}, "body": b""}])
    monkeypatch.setattr(registry, "_tor_request", request)
    result = registry.execute("tor_fetch", {"url": "http://" + valid_onion()})
    assert not result["ok"]
    assert request.call_count == 2
    assert request.call_args_list[0].args[0] == "https://check.torproject.org/api/ip"


def test_tor_check_false_never_fetches_onion(registry, monkeypatch):
    registry.tor_enabled = True
    request = Mock(return_value={"status": 200, "body": b'{"IsTor": false}'})
    monkeypatch.setattr(registry, "_tor_request", request)
    assert not registry.execute("tor_fetch", {"url": "http://" + valid_onion()})["ok"]
    assert request.call_count == 1


def test_browser_readonly_blocks_form_and_foreign_domain_requests(registry, monkeypatch):
    registry._browser_host = "example.com"
    fetch = Mock()
    monkeypatch.setattr(registry, "_fetch_response", fetch)
    for method, url in [("POST", "https://example.com/submit"), ("GET", "https://other.example/")]:
        route = Mock()
        route.request = SimpleNamespace(url=url, method=method)
        registry._browser_route(route)
        route.abort.assert_called_once()
    fetch.assert_not_called()


def test_browser_uses_validated_fetch_and_blocks_attachments(registry, monkeypatch):
    registry._browser_host = "example.com"
    fetch = Mock(return_value={"url": "https://example.com/download", "status": 200,
        "headers": {"content-disposition": "attachment; filename=download.exe"}, "body": b"binary"})
    monkeypatch.setattr(registry, "_fetch_response", fetch)
    route = Mock()
    route.request = SimpleNamespace(url="https://example.com/download", method="GET", post_data_buffer=None, headers={})
    registry._browser_route(route)
    route.abort.assert_called_once()
    route.fulfill.assert_not_called()
    assert fetch.call_args.kwargs["allowed_host"] == "example.com"


def test_every_browser_interaction_requires_exact_page_approval(registry):
    args = {"action": "click", "selector": "button", "page_url": "https://example.com/form"}
    assert registry.approval("browser_interact", args)["action"] == "browser_interact"
    registry._page = SimpleNamespace(url="https://example.com/changed")
    with pytest.raises(ToolError, match="mudou"):
        registry._browser_interact(**args)
    registry._page = None


def test_http_error_is_never_reported_as_successful_page(registry, monkeypatch):
    monkeypatch.setattr(registry, "_fetch_response", lambda url: {
        "url": url, "status": 403, "headers": {"content-type": "text/html"}, "body": b"<title>Denied</title>"})
    result = registry.execute("fetch_page", {"url": "https://example.com/private"})
    assert result["ok"] is False
    assert "403" in result["error"]


def test_html_extraction_includes_real_links_tables_and_source_date(registry):
    result = registry._page_text({"url": "https://example.com/articles/read", "status": 200,
        "headers": {"content-type": "text/html"}, "body": b'''<title>Research</title>
        <meta property="article:published_time" content="2026-11-05">
        <a href="../source">Original source</a><a href="file:///private">Blocked</a>
        <a href="http://127.0.0.1/">Internal</a><a href="javascript:alert(1)">Script</a>
        <table><caption>Data</caption><tr><th>Year</th><th>Count</th></tr>
        <tr><td>2026</td><td>4</td></tr></table>'''})
    assert result["links"] == [{"text": "Original source", "url": "https://example.com/source"}]
    assert result["tables"][0]["rows"] == [["Year", "Count"], ["2026", "4"]]
    assert result["published_date"] == "2026-11-05"


def test_duckduckgo_html_and_lite_parsers_extract_actual_results(registry):
    body = b'''<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fdocs.python.org%2F3%2F">Python</a>
      <div class="result__snippet">Official documentation</div></div>
      <table><tr><td><a class="result-link" href="https://example.com/lite">Lite result</a></td></tr>
      <tr><td class="result-snippet">Actual lite snippet</td></tr></table>'''
    rows = registry._parse_duckduckgo({"url": "https://html.duckduckgo.com/html/", "body": body})
    assert rows[0]["url"] == "https://docs.python.org/3/"
    assert rows[1]["content"] == "Actual lite snippet"
    with pytest.raises(ToolError, match="CAPTCHA"):
        registry._parse_duckduckgo({"url": "https://html.duckduckgo.com/", "body": b'<form id="challenge-form"></form>'})


def test_site_path_normalization_preserves_source_scope(registry):
    original = "site:docs.python.org/3/library/pathlib.html Path documentation"
    used, scope = registry._search_scope(original)
    assert "site:docs.python.org " in used
    assert "pathlib" in used
    rows = [{"title": "Actual", "url": "https://docs.python.org/3/library/pathlib.html"},
            {"title": "Wrong source", "url": "https://dictionary.example/path"},
            {"title": "Wrong path", "url": "https://docs.python.org/3/library/random.html"}]
    assert [row["title"] for row in registry._search_rows(rows, 5, scope)] == ["Actual"]


def test_search_fallback_is_labelled_bing_and_uses_feed_date_honestly(registry, monkeypatch):
    rss = b'''<rss><channel><item><title>Official</title><link>https://docs.python.org/3/</link>
      <description>Actual source description</description><pubDate>2026-11-05</pubDate></item></channel></rss>'''
    network = Mock(side_effect=[{"status": 202}, {"status": 403}, {"status": 200, "body": rss}])
    monkeypatch.setattr(registry, "_fetch_response", network)
    result = registry.execute("search_web", {"query": "Python documentation", "max_results": 2})
    assert result["ok"] and result["provider"] == "bing/rss"
    assert result["results"][0]["published_date"] is None
    assert result["results"][0]["source_date"] == "2026-11-05"
    assert [row["error"] for row in result["fallback_attempts"]] == ["HTTP 202", "HTTP 403"]
    assert network.call_count == 3


def test_exact_source_fallback_loads_actual_user_supplied_url(registry, monkeypatch):
    calls = []
    def network(url):
        calls.append(url)
        if url == "https://docs.python.org/3/library/pathlib.html":
            return {"url": url, "status": 200, "headers": {"content-type": "text/html"},
                    "body": b"<title>Official pathlib</title><p>Path documentation</p>"}
        if "bing.com" in url:
            return {"status": 200, "body": b"<rss><channel></channel></rss>"}
        return {"status": 403}
    monkeypatch.setattr(registry, "_fetch_response", network)
    result = registry.execute("search_web", {"query": "site:docs.python.org/3/library/pathlib.html Path"})
    assert result["ok"] and result["provider"] == "direct/url-verification"
    assert result["results"][0]["verification"] == "explicit_url_loaded"
    assert result["results"][0]["title"] == "Official pathlib"
    assert calls[-1] == "https://docs.python.org/3/library/pathlib.html"
    assert "notice" in result


def test_no_results_or_blocked_source_never_fabricates_hits(registry, monkeypatch):
    monkeypatch.setattr(registry, "_fetch_response", lambda url: {
        "url": url, "status": 403, "headers": {}, "body": b"Denied"})
    result = registry.execute("search_web", {"query": "site:docs.python.org/3/library/pathlib.html Path"})
    assert result["ok"] is False
    assert "results" not in result and "HTTP 403" in result["error"]


def test_rss_parser_rejects_html_and_external_entities(registry):
    for body in (b"<html><title>Challenge</title></html>", b"<!DOCTYPE rss><rss></rss>", b"not XML"):
        with pytest.raises(ToolError):
            registry._parse_search_rss(body)


def test_browser_http_errors_are_not_successful_rendering(registry, monkeypatch):
    monkeypatch.setattr(registry, "_resolve", lambda *a, **kw: "1.1.1.1")
    monkeypatch.setattr(registry, "_start_browser", lambda: None)
    registry._page = SimpleNamespace(goto=Mock(return_value=SimpleNamespace(status=403)))
    result = registry.execute("browser_open", {"url": "https://example.com"})
    assert result["ok"] is False and "403" in result["error"]
    assert "browser_errors" in result
    registry._page = None


def test_browser_javascript_console_and_request_failures_are_collected(registry):
    events = {}
    page = SimpleNamespace(on=lambda name, callback: events.update({name: callback}))
    registry._new_page(page)
    events["pageerror"]("script failed")
    events["console"](SimpleNamespace(type="error", text="console failure"))
    events["requestfailed"](SimpleNamespace(method="GET", url="https://example.com/missing", failure="blocked"))
    assert [row["type"] for row in registry._browser_errors] == ["javascript", "console", "request_failed"]
