"""The extension's popup and welcome page wear the same design tokens as the
Shield window: one source (web/src/styles/tokens.css), one generated copy."""
import importlib.util
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "src" / "byoai" / "browser_extension"


def _script():
    spec = importlib.util.spec_from_file_location("gen_extension_tokens", ROOT / "scripts" / "gen_extension_tokens.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_extension_token_copy_matches_the_web_tokens():
    mod = _script()
    assert (EXT / "shield-tokens.css").read_text() == mod.render(), (
        "shield-tokens.css is stale: run python scripts/gen_extension_tokens.py")
    assert mod.main(["--check"]) == 0


def test_every_extension_page_links_the_tokens_before_its_own_rules():
    for page in ("popup.html", "welcome.html", "login.html"):
        html = (EXT / page).read_text()
        link = html.index('href="shield-tokens.css"')
        assert link < html.index("<style>"), page


def test_the_login_page_names_tokens_and_has_no_colour_literals():
    import re
    html = (EXT / "login.html").read_text()
    style = html[html.index("<style>"):html.index("</style>")]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", style), "use a token from shield-tokens.css"
    for token in re.findall(r"var\((--[a-z0-9-]+)\)", style):
        assert f"{token}:" in (EXT / "shield-tokens.css").read_text(), f"{token} is not a token"


def test_the_store_package_ships_the_tokens_file(tmp_path):
    spec = importlib.util.spec_from_file_location("package_extension", ROOT / "scripts" / "package_extension.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert "shield-tokens.css" in zipfile.ZipFile(mod.build(tmp_path / "s")).namelist()


def test_the_popup_privacy_line_says_the_words_are_checked_and_never_stored():
    # Accuracy: the page reads the message to match rules, then discards it.
    popup = (EXT / "popup.html").read_text()
    assert "does not read what you wrote" not in popup
    assert "not stored or sent" in popup and "never stored" not in popup


def test_the_toolbar_icons_are_the_seal_on_the_navy_tile_at_four_sizes():
    import json

    pytest.importorskip("PIL", reason="Pillow draws and reads the icons")
    from PIL import Image

    manifest = json.loads((EXT / "manifest.json").read_text())
    assert manifest["action"]["default_icon"] == {
        str(s): f"icons/icon{s}.png" for s in (16, 32, 48, 128)}
    for size in (16, 32, 48, 128):
        img = Image.open(EXT / "icons" / f"icon{size}.png").convert("RGBA")
        assert img.size == (size, size)
        centre = img.getpixel((size // 2, size // 2))
        assert centre[2] > 200 and centre[0] < 100, "core is seal blue (#3F7BFF), not the old teal shield"
        mid = img.getpixel((size // 2, size // 5))  # on the ring or tile, never teal
        assert not (mid[1] > mid[2] and mid[1] > 100), "old teal shield colours are gone"
        assert img.getpixel((size // 2, 0 if size > 16 else 1))[:3] == (10, 24, 52) or size == 16


def test_the_toolbar_icons_match_their_generator():
    pytest.importorskip("PIL", reason="Pillow draws and reads the icons")
    spec = importlib.util.spec_from_file_location("gen_extension_icons", ROOT / "scripts" / "gen_extension_icons.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(["--check"]) == 0
