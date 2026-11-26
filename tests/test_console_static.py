"""Tests for the /console static mount on the context-cache proxy.

The built SPA is not committed, so these tests point the module's STATIC_DIR at
a tmp_path standing in for a build — that also lets the "no build present" case
be exercised, which is the one a source checkout actually hits.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from byoai.agent_context_cache import console as console_mod
from byoai.agent_context_cache import main as acc_main


@pytest.fixture
def client():
    with TestClient(acc_main.app) as c:
        yield c


@pytest.fixture
def built(tmp_path, monkeypatch):
    """A stand-in for a completed `npm run build`."""
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>ByoAI Console</title>")
    (tmp_path / "assets" / "index-abc123.js").write_text("console.log(1)")
    monkeypatch.setattr(console_mod, "STATIC_DIR", tmp_path)
    monkeypatch.setattr(console_mod, "INDEX_FILE", tmp_path / "index.html")
    return tmp_path


def test_missing_build_is_503_naming_the_build_command(client, tmp_path, monkeypatch):
    monkeypatch.setattr(console_mod, "STATIC_DIR", tmp_path)
    monkeypatch.setattr(console_mod, "INDEX_FILE", tmp_path / "index.html")
    res = client.get("/console/")
    assert res.status_code == 503
    assert "npm --prefix web run build" in res.text


def test_index_is_served(client, built):
    res = client.get("/console/")
    assert res.status_code == 200
    assert "ByoAI Console" in res.text


def test_deep_client_route_falls_back_to_index(client, built):
    res = client.get("/console/acme/fleet/coverage")
    assert res.status_code == 200
    assert "ByoAI Console" in res.text


def test_hashed_assets_are_cached_immutably(client, built):
    res = client.get("/console/assets/index-abc123.js")
    assert res.status_code == 200
    assert "immutable" in res.headers["cache-control"]
    assert client.get("/console/").headers["cache-control"] == "no-cache"


def test_bare_console_redirects_to_slash(client, built):
    res = client.get("/console", follow_redirects=False)
    assert res.status_code == 307
    assert res.headers["location"] == "/console/"


def test_traversal_cannot_escape_the_static_root(built):
    # Asserted on the resolver, not through the client: httpx normalises "../"
    # out of the URL before it is ever sent, so the client can't express this.
    assert console_mod.resolve_asset("../../pyproject.toml") is None
    assert console_mod.resolve_asset("index.html") == built / "index.html"


def test_console_can_be_disabled(client, built, monkeypatch):
    monkeypatch.setenv("BYOAI_CONSOLE", "0")
    assert client.get("/console/").status_code == 404


def test_console_mount_does_not_shadow_v1(client, built):
    # /v1/stats is a real route, not the console's fallback.
    res = client.get("/v1/stats")
    assert res.status_code == 200
    assert "optimizer_enabled" in res.json()


def test_stale_build_is_reported_with_the_rebuild_command(built, tmp_path, monkeypatch):
    src = tmp_path.parent / (tmp_path.name + "_web_src")
    src.mkdir()
    (src / "app.tsx").write_text("x")
    monkeypatch.setattr(console_mod, "WEB_SRC", src)
    import os
    old = (built / "index.html").stat().st_mtime
    os.utime(src / "app.tsx", (old + 100, old + 100))
    assert "npm --prefix web run build" in console_mod.stale_reason()
    os.utime(src / "app.tsx", (old - 100, old - 100))
    assert console_mod.stale_reason() is None


def test_installed_package_without_source_is_never_stale(built, tmp_path, monkeypatch):
    monkeypatch.setattr(console_mod, "WEB_SRC", tmp_path / "nope")
    assert console_mod.stale_reason() is None
