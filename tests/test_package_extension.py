"""The store build must not ship the dev-only localhost externally_connectable entry."""
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("package_extension", ROOT / "scripts" / "package_extension.py")
pe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pe)


def _manifest(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("manifest.json"))


def test_store_build_strips_localhost(tmp_path):
    m = _manifest(pe.build(tmp_path))
    matches = m["externally_connectable"]["matches"]
    assert matches and all(x.startswith("https://") for x in matches)
    assert "localhost" not in json.dumps(m["externally_connectable"])


def test_dev_build_keeps_localhost(tmp_path):
    m = _manifest(pe.build(tmp_path, keep_key=True))
    assert any("localhost" in x for x in m["externally_connectable"]["matches"])


def test_check_rejects_a_store_manifest_with_localhost():
    with pytest.raises(SystemExit):
        pe.check_store_manifest({"externally_connectable": {"matches": ["http://localhost/join*"]}})


def test_store_build_keeps_host_permissions(tmp_path):
    src = json.loads((ROOT / "src/byoai/browser_extension/manifest.json").read_text())
    assert src["host_permissions"] == ["http://127.0.0.1/*", "http://localhost/*"]
    assert _manifest(pe.build(tmp_path))["host_permissions"] == src["host_permissions"]
