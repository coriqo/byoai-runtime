"""Build the Chrome Web Store upload: dist/coriqo-shield-<version>.zip.

    python scripts/package_extension.py --minify   # store upload (no "key", minified JS)
    python scripts/package_extension.py            # same, readable JS
    python scripts/package_extension.py --keep-key # dev build with the fixed ID (keeps the localhost join match)

--minify runs each .js through esbuild (web/node_modules, installed by
`npm ci` in web/) with no sourcemap and no wrapper, so top-level names keep
their meaning across the scripts the manifest loads together. HTML, JSON,
icons and PRIVACY.md ship unchanged. The readable source stays in the repo.

The manifest's "key" pins a development ID (see README). The store assigns its
own ID, so the upload leaves "key" out; after the first upload, copy the public
key from the dashboard (Package -> View public key) into the manifest so the
published and unpacked copies share one ID.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import zipfile
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "byoai" / "browser_extension"
# Only what an extension ships; stray files (.DS_Store, drafts, caches) stay out.
SHIP = {".js", ".html", ".json", ".md", ".png", ".css"}
ESBUILD = Path(__file__).resolve().parent.parent / "web" / "node_modules" / ".bin" / "esbuild"


def _minify(path: Path) -> bytes:
    if not ESBUILD.exists():
        raise SystemExit("esbuild not found: run `npm ci` in web/ first")
    out = subprocess.run(
        [str(ESBUILD), str(path), "--minify", "--target=chrome120", "--legal-comments=none"],
        check=True, capture_output=True,
    )
    return out.stdout


def store_safe_match(m: str) -> bool:
    """A store build lets only https pages, never this computer, message the extension."""
    return m.startswith("https://") and "localhost" not in m and "127.0.0.1" not in m


def check_store_manifest(manifest: dict) -> None:
    """A store build never lets a page on this computer (or plain http) message the extension."""
    for m in manifest.get("externally_connectable", {}).get("matches", []):
        if not store_safe_match(m):
            raise SystemExit(f"store manifest must not list {m!r} under externally_connectable")


def build(out_dir: Path, keep_key: bool = False, minify: bool = False) -> Path:
    manifest = json.loads((SRC / "manifest.json").read_text())
    if not keep_key:
        manifest.pop("key", None)
        ec = manifest.get("externally_connectable")
        if ec:  # the localhost match is for the unpacked dev build only
            ec["matches"] = [m for m in ec.get("matches", []) if store_safe_match(m)]
        check_store_manifest(manifest)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"coriqo-shield-{manifest['version']}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(SRC.rglob("*")):
            if path.is_dir() or path.suffix not in SHIP or path.name.startswith(".") or "__pycache__" in path.parts:
                continue
            rel = path.relative_to(SRC).as_posix()
            if rel == "manifest.json":
                zf.writestr(rel, json.dumps(manifest, indent=2) + "\n")
            elif minify and path.suffix == ".js":
                zf.writestr(rel, _minify(path))
            else:
                zf.write(path, rel)
    return target


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="dist", help="output directory (default: dist)")
    ap.add_argument("--keep-key", action="store_true", help='keep the manifest "key" (development ID)')
    ap.add_argument("--minify", action="store_true", help="minify every .js with esbuild (store upload)")
    args = ap.parse_args()
    print(build(Path(args.out), args.keep_key, args.minify))


if __name__ == "__main__":
    main()
