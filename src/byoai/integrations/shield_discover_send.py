"""`byoai-shield discover --send`: upload the discover report to Coriqo.

The scan itself stays offline. Upload is a separate, explicit step that only
runs when ``--send`` is given. What is sent is exactly the scanner's own report
(``byoai.shield.discovery/1``): no hostname, username, device id or any other
identifier is added. The tenant is named by the discovery key, never the body.

The key (``cik_disc_<workspace>.<secret>``) and the server address come from,
in order: ``--key`` / ``--server``; ``--key-file``; then the managed location,
written by the admin's tool: Windows registry
``HKLM\\SOFTWARE\\Policies\\Coriqo\\Shield`` (``DiscoveryKey``, ``ServerUrl``),
a macOS managed preference (``com.coriqo.shield.plist``, same keys), or a JSON
file ``{"key": ..., "server_url": ...}`` at ``.../Shield/discover.json``.
Trust rules are the same as ``enrol``: a managed file must not be writable by
group or other and must be owned by root or the user; https only.

The key is never printed, logged or put in an error. Server text is never
echoed either: each refusal maps to one fixed line and its own exit code.
"""
from __future__ import annotations

import json
import os
import plistlib
import random
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from byoai.integrations.shield_enrol import (
    MAX_ATTEMPTS,
    MAX_JITTER_S,
    REGISTRY_KEY,
    EnrolInputError,
    _clean,
    _is_trusted,
    check_server_url,
    managed_plist_path,
)

KEY_SCHEME = "cik_disc_"
ROUTE = "/api/v1/discovery/endpoint-reports"
MAX_BODY_BYTES = 256 * 1024          # the server refuses larger reports
MAX_RETRY_AFTER_S = 60               # a longer Retry-After is a real limit, not a blip

EXIT_OK = 0
EXIT_FAILED = 1        # network trouble or an unexpected answer, after retries
EXIT_INPUT = 2         # no key / no server / untrusted managed source / bad address
EXIT_UNENTITLED = 10   # 403: endpoint discovery is not on for this workspace
EXIT_BAD_KEY = 11      # 401: key unknown, revoked or mistyped
EXIT_RATE_LIMIT = 12   # 429
EXIT_TOO_LARGE = 13    # 413, or over the limit before sending
EXIT_REJECTED = 14     # 400 / 415 / 422: the server does not accept this report
EXIT_LOCKED = 15       # 423: workspace in read-only lockdown

_REFUSALS: dict[int, tuple[int, str]] = {
    401: (EXIT_BAD_KEY, "The discovery key was not accepted (unknown, revoked or mistyped). Ask your administrator for a new key."),
    403: (EXIT_UNENTITLED, "Endpoint discovery is not turned on for this workspace. Ask your Coriqo contact to enable it."),
    413: (EXIT_TOO_LARGE, "The report is larger than the server accepts (256 KiB). Nothing was stored."),
    400: (EXIT_REJECTED, "The server could not read the report. Update byoai-shield. Nothing was stored."),
    415: (EXIT_REJECTED, "The server could not read the report. Update byoai-shield. Nothing was stored."),
    422: (EXIT_REJECTED, "The server does not accept this report format. Update byoai-shield. Nothing was stored."),
    423: (EXIT_LOCKED, "The workspace is in read-only lockdown. Reports resume once an administrator clears it."),
}
_TRANSIENT_STATUS = {409, 502, 503, 504}


@dataclass(frozen=True)
class ManagedKey:
    key: str = field(repr=False)     # never in a repr, so never in a log line
    server_url: str | None
    source: str


def managed_file_path(platform: str, env: Mapping[str, str]) -> Path:
    if platform == "win32":
        return Path(env.get("ProgramData", r"C:\ProgramData")) / "Coriqo" / "Shield" / "discover.json"
    if platform == "darwin":
        return Path("/Library/Application Support/Coriqo/Shield/discover.json")
    return Path("/etc/coriqo/shield/discover.json")


def _read_registry() -> dict:
    if sys.platform != "win32":
        return {}
    try:
        import winreg  # pyright: ignore[reportMissingImports]
    except ImportError:
        return {}
    out: dict = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REGISTRY_KEY) as hk:
            for name in ("DiscoveryKey", "ServerUrl"):
                try:
                    out[name] = winreg.QueryValueEx(hk, name)[0]
                except FileNotFoundError:
                    continue
    except OSError:
        return {}
    return out


def read_managed(*, platform: str | None = None, env: Mapping[str, str] | None = None,
                 registry: Callable[[], dict] | None = None,
                 plist_path: Path | None = None, file_path: Path | None = None,
                 uid: int | None = None) -> ManagedKey | None:
    """First managed source holding a key, or None. An untrusted source raises."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    if uid is None and hasattr(os, "getuid"):
        uid = os.getuid()

    if platform == "win32":
        values = (registry or _read_registry)()
        key = _clean(values.get("DiscoveryKey"))
        if key:
            return ManagedKey(key, _clean(values.get("ServerUrl")), f"registry HKLM\\{REGISTRY_KEY}")

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
            key = _clean(data.get("DiscoveryKey")) if isinstance(data, dict) else None
            if key:
                return ManagedKey(key, _clean(data.get("ServerUrl")), f"managed preference {plist}")

    path = file_path or managed_file_path(platform, env)
    if path.exists():
        why = _is_trusted(path, uid=uid)
        if why:
            raise EnrolInputError(why)
        try:
            data = json.loads(path.read_text())
        except (ValueError, OSError):
            # no parser detail: a malformed file may quote the key
            raise EnrolInputError(f"{path} is not valid JSON.") from None
        key = _clean(data.get("key")) if isinstance(data, dict) else None
        if key:
            return ManagedKey(key, _clean(data.get("server_url")), f"file {path}")
    return None


def resolve(*, key: str | None, key_file: Path | None, server: str | None,
            use_managed: bool = True, **managed_kw) -> tuple[str, str, str]:
    """(key, server_url, source) from the arguments, then the managed locations."""
    source = "command line"
    server_url = _clean(server)
    k = _clean(key)
    if k is None and key_file is not None:
        try:
            k = _clean(key_file.read_text())
        except OSError as exc:
            raise EnrolInputError(f"cannot read the key file: {exc.strerror or exc}") from None
        if k is None:
            raise EnrolInputError("The key file is empty.")
        source = "key file"
    if k is None and use_managed:
        managed = read_managed(**managed_kw)
        if managed is not None:
            k, source = managed.key, managed.source
            server_url = server_url or managed.server_url
    if k is None:
        raise EnrolInputError(
            "No discovery key found. Pass --key-file, or have your device-management tool set "
            "DiscoveryKey and ServerUrl (see docs/msp-zero-touch.md).")
    if not k.startswith(KEY_SCHEME) or "." not in k or any(c.isspace() for c in k):
        raise EnrolInputError("That is not a discovery key (it should start with cik_disc_). "
                              "An enrolment token cannot be used here.")
    if server_url is None:
        raise EnrolInputError("No server address found. Pass --server, or set ServerUrl next to the key.")
    return k, check_server_url(server_url), source


def _retry_after(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("retry-after", "")
    return float(raw) if raw.isdigit() else None


def send_report(body: bytes, *, key: str, server_url: str,
                http_client: httpx.Client | None = None,
                sleep: Callable[[float], None] = time.sleep,
                rand: Callable[[], float] = random.random) -> tuple[int, str]:
    """POST ``body`` (the report, byte for byte). Returns (exit code, one line)."""
    if len(body) > MAX_BODY_BYTES:
        return EXIT_TOO_LARGE, _REFUSALS[413][1]
    owns = http_client is None
    client = http_client or httpx.Client(timeout=15.0, trust_env=False, follow_redirects=False)
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            last = attempt == MAX_ATTEMPTS
            try:
                resp = client.post(server_url + ROUTE, content=body, headers=headers)
            except httpx.HTTPError as exc:
                if not last:
                    sleep((2 ** attempt) * (0.5 + rand()))
                    continue
                # the exception class only: its text can carry the address and proxy detail
                return EXIT_FAILED, f"Could not reach the server ({type(exc).__name__})."
            status = resp.status_code
            if status in (200, 201):
                return EXIT_OK, "Report sent."
            if status == 429:
                wait = _retry_after(resp)
                if wait is not None and wait <= MAX_RETRY_AFTER_S and not last:
                    sleep(wait + rand())
                    continue
                return EXIT_RATE_LIMIT, "The server is rate limiting this key. Try again later."
            if status in _TRANSIENT_STATUS and not last:
                sleep((2 ** attempt) * (0.5 + rand()))
                continue
            if status in _REFUSALS:
                return _REFUSALS[status]
            return EXIT_FAILED, f"The server answered HTTP {status}; the report was not confirmed stored."
    finally:
        if owns:
            client.close()
    return EXIT_FAILED, "The report was not confirmed stored."  # pragma: no cover


def run_send(report_text: str, args, *, err, out, http_client: httpx.Client | None = None,
             sleep: Callable[[float], None] = time.sleep,
             rand: Callable[[], float] = random.random, **managed_kw) -> int:
    """Resolve credentials, wait the jitter, send. ``args`` is the parsed discover namespace."""
    try:
        key, server_url, source = resolve(key=args.key, key_file=args.key_file, server=args.server,
                                          use_managed=not args.no_managed, **managed_kw)
    except EnrolInputError as exc:
        print(f"Cannot send: {exc}", file=err)
        return EXIT_INPUT
    jitter = min(max(args.jitter_seconds, 0.0), MAX_JITTER_S)
    if jitter:
        sleep(rand() * jitter)
    code, line = send_report(report_text.encode("utf-8"), key=key, server_url=server_url,
                             http_client=http_client, sleep=sleep, rand=rand)
    if code == EXIT_OK:
        print(f"{line} Key read from {source}.", file=out)
    else:
        print(f"Send failed: {line}", file=err)
    return code
