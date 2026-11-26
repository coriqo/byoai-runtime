"""`byoai-shield enrol`: enrol this computer without opening the Shield window.

This is the command an IT admin's device-management tool (Jamf, Intune,
Kandji, a Windows startup script) runs so nobody has to paste a token on each
machine. The token and the server address come from, in order:

1. ``--token`` / ``--server`` on the command line (visible in the process
   list while it runs: prefer the next two for anything but a test);
2. ``--token-file``: a file holding only the token;
3. the managed location for the platform, written by the admin's tool:
   Windows registry ``HKLM\\SOFTWARE\\Policies\\Coriqo\\Shield``
   (``EnrolToken``, ``ServerUrl``), a macOS managed preference
   (``/Library/Managed Preferences/com.coriqo.shield.plist``, same keys), or a
   JSON file ``{"token": ..., "server_url": ...}`` at a fixed per-platform path.

A managed source is trusted only where an ordinary user cannot have written
it: the file must not be writable by group or other, and on macOS/Linux must
be owned by root or by the user running the command. A server address anyone
could change would let them collect the one-time token.

The token is a credential: it is never printed, logged or put in an error.
Already enrolled is success (the command can run on every login); ``--force``
re-enrols. The command runs as the user whose Shield it sets up, because the
device key lives under that user's ``~/.byoai/shield``.
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import random
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from byoai.recorder.enroll import EnrollmentError, enroll, load_enrollment_state

REGISTRY_KEY = r"SOFTWARE\Policies\Coriqo\Shield"
PLIST_DOMAIN = "com.coriqo.shield"
TRANSIENT = ("HTTP 429", "HTTP 502", "HTTP 503", "HTTP 504")
MAX_ATTEMPTS = 3
MAX_JITTER_S = 900  # a push to many machines should spread out; never wait longer than this


class EnrolInputError(ValueError):
    """Missing or unacceptable input; the message says what to set and where."""


@dataclass(frozen=True)
class ManagedEnrolment:
    token: str = field(repr=False)  # never in a repr, so never in a log line
    server_url: str | None
    source: str                     # where it came from, for the one-line report


def managed_file_path(platform: str, env: dict) -> Path:
    if platform == "win32":
        return Path(env.get("ProgramData", r"C:\ProgramData")) / "Coriqo" / "Shield" / "enrol.json"
    if platform == "darwin":
        return Path("/Library/Application Support/Coriqo/Shield/enrol.json")
    return Path("/etc/coriqo/shield/enrol.json")


def managed_plist_path() -> Path:
    return Path("/Library/Managed Preferences") / f"{PLIST_DOMAIN}.plist"


def _read_registry() -> dict:
    """HKLM only: a standard user cannot write there. Missing key means {}."""
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return {}
    out: dict = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REGISTRY_KEY) as key:
            for name in ("EnrolToken", "ServerUrl"):
                try:
                    value, _kind = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    continue
                out[name] = value
    except OSError:
        return {}
    return out


def _is_trusted(path: Path, *, uid: int | None) -> str | None:
    """None when the file may be believed, else why not."""
    try:
        st = path.stat()
    except OSError as exc:
        return f"cannot read {path}: {exc.strerror or exc}"
    if sys.platform == "win32" or uid is None:
        return None  # Windows ACLs are not checked here; the registry route is the hardened one
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} is writable by group or other; run: chmod go-w '{path}'"
    if st.st_uid not in (0, uid):
        return f"{path} is owned by another user; it must be owned by root or by this user"
    return None


def _clean(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def read_managed(*, platform: str | None = None, env: dict | None = None,
                 registry: Callable[[], dict] | None = None,
                 plist_path: Path | None = None, file_path: Path | None = None,
                 uid: int | None = None) -> ManagedEnrolment | None:
    """The first managed source that holds a token, or None.

    A source that exists but is untrusted raises :class:`EnrolInputError`
    rather than being skipped: silently falling through to another source
    would hide a mis-set permission."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    if uid is None and hasattr(os, "getuid"):
        uid = os.getuid()

    if platform == "win32":
        values = (registry or _read_registry)()
        token = _clean(values.get("EnrolToken"))
        if token:
            return ManagedEnrolment(token, _clean(values.get("ServerUrl")),
                                    f"registry HKLM\\{REGISTRY_KEY}")

    if platform == "darwin":
        plist = plist_path or managed_plist_path()
        if plist.exists():
            why = _is_trusted(plist, uid=uid)
            if why:
                raise EnrolInputError(why)
            try:
                data = plistlib.loads(plist.read_bytes())
            except (plistlib.InvalidFileException, ValueError, OSError) as exc:
                raise EnrolInputError(f"{plist} is not a readable property list: {exc}") from None
            token = _clean(data.get("EnrolToken")) if isinstance(data, dict) else None
            if token:
                return ManagedEnrolment(token, _clean(data.get("ServerUrl")), f"managed preference {plist}")

    path = file_path or managed_file_path(platform, env)
    if path.exists():
        why = _is_trusted(path, uid=uid)
        if why:
            raise EnrolInputError(why)
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            raise EnrolInputError(f"{path} is not valid JSON: {exc}") from None
        token = _clean(data.get("token")) if isinstance(data, dict) else None
        if token:
            return ManagedEnrolment(token, _clean(data.get("server_url")), f"file {path}")
    return None


def check_server_url(url: str) -> str:
    """https, or http to this computer only; the token must not cross a network in the clear."""
    from urllib.parse import urlsplit
    url = url.strip().rstrip("/")
    parts = urlsplit(url)
    local = (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise EnrolInputError("The server address must start with https:// (set ServerUrl or --server).")
    if not parts.hostname:
        raise EnrolInputError("The server address has no host name.")
    return url


def resolve(*, token: str | None, token_file: Path | None, server: str | None,
            use_managed: bool = True, **managed_kw) -> tuple[str, str, str]:
    """(token, server_url, source) from the arguments, then the managed locations."""
    source = "command line"
    server_url = _clean(server)
    tok = _clean(token)
    if tok is None and token_file is not None:
        try:
            tok = _clean(token_file.read_text())
        except OSError as exc:
            raise EnrolInputError(f"cannot read the token file: {exc.strerror or exc}") from None
        if tok is None:
            raise EnrolInputError("The token file is empty.")
        source = "token file"
    if tok is None and use_managed:
        managed = read_managed(**managed_kw)
        if managed is not None:
            tok, source = managed.token, managed.source
            server_url = server_url or managed.server_url
    if tok is None:
        raise EnrolInputError(
            "No enrolment token found. Pass --token-file, or have your device-management tool set "
            "EnrolToken and ServerUrl (see docs/msp-zero-touch.md for the registry key, managed "
            "preference and file locations).")
    if server_url is None:
        raise EnrolInputError("No server address found. Pass --server, or set ServerUrl next to the token.")
    return tok, check_server_url(server_url), source


def run_enrol(argv: list[str], *, key_dir: Path | None = None,
              http_client: httpx.Client | None = None,
              sleep: Callable[[float], None] = time.sleep,
              rand: Callable[[], float] = random.random,
              out=None, err=None, **managed_kw) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(
        prog="byoai-shield enrol",
        description="Enrol this computer with a Coriqo or Shield server using a one-time token.")
    ap.add_argument("--token", help="the token (visible in the process list; prefer --token-file or a managed setting)")
    ap.add_argument("--token-file", type=Path, help="file holding only the token")
    ap.add_argument("--server", help="server address, https://... (default: the managed ServerUrl)")
    ap.add_argument("--no-managed", action="store_true", help="ignore the registry, managed preference and managed file")
    ap.add_argument("--force", action="store_true", help="enrol again even if already enrolled")
    ap.add_argument("--jitter-seconds", type=float, default=0.0,
                    help=f"wait a random 0..N seconds first, so a push to many computers does not arrive at once (max {MAX_JITTER_S})")
    args = ap.parse_args(argv)

    if key_dir is None:
        from byoai.integrations.shield import DATA_DIR
        key_dir = DATA_DIR / "keys"
    try:
        if not args.force and load_enrollment_state(key_dir) is not None:
            print("Already enrolled; nothing to do. Use --force to enrol again.", file=out)
            return 0
        token, server_url, source = resolve(
            token=args.token, token_file=args.token_file, server=args.server,
            use_managed=not args.no_managed, **managed_kw)
    except (EnrolInputError, EnrollmentError) as exc:
        print(f"Cannot enrol: {exc}", file=err)
        return 2

    jitter = min(max(args.jitter_seconds, 0.0), MAX_JITTER_S)
    if jitter:
        sleep(rand() * jitter)

    owns = http_client is None
    client = http_client or httpx.Client(timeout=15.0, trust_env=False)
    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                state = enroll(coriqo_base_url=server_url, token=token, key_dir=key_dir,
                               force=True, http_client=client)
                break
            except EnrollmentError as exc:
                msg = str(exc)
                if token in msg:  # a server that echoes the token must not put it in our log
                    msg = msg.replace(token, "<token>")
                if attempt < MAX_ATTEMPTS and any(t in msg for t in TRANSIENT):
                    sleep((2 ** attempt) * (0.5 + rand()))
                    continue
                print(f"Enrolment failed: {msg}", file=err)
                return 1
    finally:
        if owns:
            client.close()
    print(f"Enrolled with {state.coriqo_base_url} (tenant {state.tenant_slug or 'unknown'}, "
          f"device {state.device_id}); token read from {source}.", file=out)
    return 0
