"""Serving for the built console SPA (``web/`` → ``byoai/console_static/``).

The front end is a Vite build, not Python source: it is produced by
``npm --prefix web run build`` and written straight into the package so it
ships inside the wheel. A user who ``pip install``s the package therefore gets
a working UI with no Node toolchain; a user working from a source checkout has
to build it once, and this module is what tells them so.
"""

import os
from pathlib import Path

# Assets live inside the package (not at repo root) so hatchling picks them up
# as package data. The directory is git-ignored — it only exists after a build.
STATIC_DIR = Path(__file__).resolve().parent.parent / "console_static"
INDEX_FILE = STATIC_DIR / "index.html"

BUILD_COMMAND = "npm --prefix web install && npm --prefix web run build"

MISSING_BUILD_MESSAGE = (
    "The ByoAI console has not been built.\n"
    "\n"
    "This copy of byoai-runtime is running from a source checkout, where the\n"
    "front end is not committed. Build it once:\n"
    "\n"
    f"    {BUILD_COMMAND}\n"
    "\n"
    f"That writes the compiled assets to {STATIC_DIR}, and /console/ starts\n"
    "serving them immediately — no restart needed.\n"
    "\n"
    "Installing the published wheel (pip install byoai-runtime) ships the\n"
    "console prebuilt and skips this step entirely.\n"
)


def assets_available() -> bool:
    """Whether a usable build is present. Checked per request, not at import,
    so building the front end while the proxy is running just works."""
    return INDEX_FILE.is_file()


WEB_SRC = STATIC_DIR.parent.parent.parent / "web" / "src"


def stale_reason() -> str | None:
    """Why the built console is older than its source, or None.

    Only a source checkout has ``web/src`` beside the package; an installed
    wheel never does, so it is never reported stale. The build is git-ignored,
    so after a pull that changes the UI the old build keeps being served until
    someone rebuilds. Cheap: stats the source tree, no reads.
    """
    if not INDEX_FILE.is_file() or not WEB_SRC.is_dir():
        return None
    built = INDEX_FILE.stat().st_mtime
    newest = max((p.stat().st_mtime for p in WEB_SRC.rglob("*") if p.is_file()),
                 default=0.0)
    if newest <= built:
        return None
    return (
        "The console in this checkout was built before its source last "
        "changed, so the window still shows the older design. Rebuild it: "
        f"{BUILD_COMMAND}  (no restart needed; reload the page)."
    )


def resolve_asset(rel_path: str) -> Path | None:
    """Map a URL path under ``/console/`` onto a file inside ``STATIC_DIR``.

    Returns ``None`` when the path is not an existing file — including when it
    escapes the static root via ``..`` or a symlink, which is why the resolved
    path is re-checked against the resolved root rather than trusting the
    joined string.
    """
    rel_path = rel_path.lstrip("/")
    if not rel_path:
        return None
    candidate = (STATIC_DIR / rel_path).resolve()
    try:
        candidate.relative_to(STATIC_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def console_url(base_url: str) -> str:
    """The clickable console address for a given proxy base URL."""
    return f"{base_url.rstrip('/')}/console/"


def _is_hashed_asset(rel_path: str) -> bool:
    # Vite fingerprints everything under assets/ with a content hash, so those
    # are safe to cache forever; index.html must never be, or a redeploy keeps
    # serving the old bundle references.
    return rel_path.lstrip("/").startswith("assets/")


def cache_headers(rel_path: str) -> dict[str, str]:
    if _is_hashed_asset(rel_path):
        return {"Cache-Control": "public, max-age=31536000, immutable"}
    return {"Cache-Control": "no-cache"}


def env_flag_disabled() -> bool:
    """``BYOAI_CONSOLE=0`` turns the UI off on a headless deployment."""
    return os.getenv("BYOAI_CONSOLE", "1").strip().lower() in ("0", "false", "no", "off")
