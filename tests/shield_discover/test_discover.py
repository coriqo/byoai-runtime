import json
from pathlib import Path

from byoai.integrations import shield_discover as sd

SECRET = "sk-live-SECRETVALUE123"


def _write(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data))


def _run(home: Path, platform="darwin", **kw):
    return sd.discover(platform=platform, home=home, env={"PATH": ""}, probe=False,
                       exists=lambda _p: False, **kw)


def test_claude_desktop_servers_are_described_without_secrets(tmp_path):
    _write(tmp_path / "Library/Application Support/Claude/claude_desktop_config.json", {"mcpServers": {
        "files": {"command": "/usr/local/bin/npx", "args": ["-y", "pkg", f"--token={SECRET}"],
                  "env": {"API_KEY": SECRET}},
        "remote": {"url": f"https://user:{SECRET}@mcp.example.com/path?key={SECRET}",
                   "headers": {"Authorization": f"Bearer {SECRET}"}},
    }})
    report = _run(tmp_path)
    blob = json.dumps(report)
    assert SECRET not in blob and "user:" not in blob and "/path" not in blob and str(tmp_path) not in blob
    by = {i["server"]: i for i in report["items"] if i["kind"] == "mcp_server"}
    assert by["files"]["program"] == "npx" and by["files"]["transport"] == "stdio"
    assert by["files"]["env_names"] == ["API_KEY"]
    assert by["remote"]["host"] == "mcp.example.com" and by["remote"]["header_names"] == ["Authorization"]
    assert by["files"]["config"].startswith("~/Library/")
    assert report["attestation"] == "unattested"


def test_vscode_servers_key_and_claude_code_projects(tmp_path):
    _write(tmp_path / "Library/Application Support/Code/User/mcp.json", {"servers": {"a": {"command": "uvx"}}})
    _write(tmp_path / ".claude.json", {"mcpServers": {"g": {"command": "node"}},
                                       "projects": {"/x": {"mcpServers": {"p": {"type": "sse", "url": "https://h.example/s"}}}}})
    items = {(i["client"], i["server"]): i for i in _run(tmp_path)["items"] if i["kind"] == "mcp_server"}
    assert set(items) == {("vscode", "a"), ("claude_code", "g"), ("claude_code", "p")}
    assert items[("claude_code", "p")]["transport"] == "sse"


def test_malformed_oversized_and_outside_home_are_skipped(tmp_path):
    cfg = tmp_path / ".cursor/mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{not json")
    report = _run(tmp_path)
    assert report["items"] == [] and report["skipped"][0]["reason"] == "not valid JSON"

    cfg.write_text(" " * (sd.MAX_CONFIG_BYTES + 1))
    assert _run(tmp_path)["skipped"][0]["reason"] == "larger than 1 MiB"

    other = tmp_path / "other/secret.json"
    _write(other, {"mcpServers": {"x": {"command": "evil"}}})
    cfg.unlink()
    cfg.symlink_to(other)
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor/mcp.json").symlink_to(other)
    report = _run(home)
    assert report["items"] == [] and report["skipped"][0]["reason"] == "outside the home directory"


def test_wrong_shapes_do_not_raise(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"a": "text", "b": None, "c": {"command": 5}}})
    _write(tmp_path / ".claude.json", [1, 2])
    items = _run(tmp_path)["items"]
    assert [i["server"] for i in items if i["kind"] == "mcp_server"] == ["c"]


def test_apps_and_runtimes(tmp_path):
    (tmp_path / "Applications/Cursor.app").mkdir(parents=True)
    models = tmp_path / ".ollama/models/manifests/registry.ollama.ai/library/llama3"
    models.mkdir(parents=True)
    (models / "latest").mkdir()
    report = sd.discover(platform="darwin", home=tmp_path, env={}, probe=True,
                         port_open=lambda p: p == 11434,
                         exists=lambda p: p == tmp_path / "Applications/Cursor.app")
    kinds = {(i["kind"], i.get("app") or i.get("runtime")) for i in report["items"]}
    assert ("app", "cursor") in kinds and ("runtime", "ollama") in kinds
    ollama = next(i for i in report["items"] if i.get("runtime") == "ollama")
    assert ollama["listening"] is True and ollama["models"] == ["library/llama3"]


def test_no_probe_never_opens_a_socket(tmp_path):
    def boom(_p):
        raise AssertionError("probed")
    sd.discover(platform="linux", home=tmp_path, env={}, probe=False, port_open=boom)


def test_cli_dry_run_and_out_file(tmp_path, capsys):
    import io
    out = io.StringIO()
    assert sd.run_discover(["--dry-run"], out=out, platform="darwin", home=tmp_path, env={}) == 0
    assert "~/.cursor/mcp.json" in out.getvalue()
    target = tmp_path / "r.json"
    err = io.StringIO()
    assert sd.run_discover(["--no-probe", "--out", str(target)], err=err, platform="darwin",
                           home=tmp_path, env={}) == 0
    assert json.loads(target.read_text())["schema"] == sd.SCHEMA
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_signature_file_is_valid():
    sigs = sd.load_signatures()
    assert sigs["version"] and all("client" in c and "paths" in c for c in sigs["mcp_clients"])
    assert all(isinstance(r["port"], int) for r in sigs["runtimes"])


def test_program_name_never_takes_text_from_an_argument():
    assert sd.describe_server("x", {"command": "curl -H Authorization:Bearer/sk-live-SECRET"})["program"] == "curl"
    assert sd.describe_server("x", {"command": '"C:\\bin\\node.exe" --key a/b'})["program"] == "node.exe"


def test_deeply_nested_config_is_skipped_not_fatal(tmp_path):
    cfg = tmp_path / ".cursor/mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("[" * 200000)
    assert _run(tmp_path)["skipped"][0]["reason"] == "not valid JSON"


def test_out_resets_mode_of_an_existing_file(tmp_path):
    import io
    target = tmp_path / "o.json"
    target.write_text("old")
    target.chmod(0o644)
    assert sd.run_discover(["--no-probe", "--out", str(target)], err=io.StringIO(), platform="darwin",
                           home=tmp_path, env={}) == 0
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_program_name_drops_anything_not_shaped_like_a_file_name():
    for cmd in ("API_KEY=sk-live-SECRET node", "user:pass@host", "sk-live-SECRET/..", "a\u202eb", "x" * 81):
        assert sd.describe_server("x", {"command": cmd})["program"] is None
    assert sd.describe_server("x", {"command": "/opt/bin/mcp-server_1.2+x"})["program"] == "mcp-server_1.2+x"
