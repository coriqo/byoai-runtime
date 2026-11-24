"""The runtime's own view of the tools an MCP server offers (tool pinning).

``coriqo-mcp`` sits between a host and a server, but the host's ``tools/list``
requests are not enough to check pins: the host may page, may never list, and
may call a tool the server changed after the last list. So the runtime asks the
server for the whole list itself, and keeps a hash of each tool.

The rules this module keeps, because it talks to a server nobody asked it to
talk to:

- its requests use string ids that start with :data:`PIN_ID_PREFIX`, followed by
  a random per-process token; a host request carrying that prefix is refused,
  so a host id can never collide with one of ours;
- nothing is sent before the transport says it is ready (on stdio, once the
  host has sent ``notifications/initialized``);
- one request in flight at a time per connection or session, and one paged
  fetch per upstream per :data:`MIN_FETCH_INTERVAL_S` seconds across every
  session (:class:`FetchLimiter`), so many sessions cannot hammer a server;
  at most :data:`MAX_PAGES` pages, at most :data:`MAX_TOOLS` entries, each
  request bounded by the hold timeout;
- a failed fetch backs off (2, 4, 8 ... up to 300 seconds) before the next;
  a call to a name that was not in the last list triggers a new fetch at most
  once every :data:`MIN_UNSEEN_REFETCH_S` seconds;
- a ``tools/call`` is held (up to the hold timeout) while a fetch is running
  or needed. When the timeout passes, the tool counts as not seen and checked,
  which the pin policy treats as unpinned. It is never waved through.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from ..recorder.tool_pins import ToolHashes, hash_tool

__all__ = [
    "DEFAULT_HOLD_TIMEOUT_S",
    "MAX_PAGES",
    "MIN_FETCH_INTERVAL_S",
    "FetchLimiter",
    "MAX_TOOLS",
    "PIN_ID_PREFIX",
    "ToolInventory",
    "is_own_id",
]

log = logging.getLogger("byoai.coriqo_mcp")

#: Every JSON-RPC id the runtime sends on its own starts with this.
PIN_ID_PREFIX = "byoai-pin-"
DEFAULT_HOLD_TIMEOUT_S = 10.0
MAX_PAGES = 100
MAX_TOOLS = 5000
#: A call to a name missing from the last list refetches at most this often.
MIN_UNSEEN_REFETCH_S = 5.0
#: Shortest time between two paged fetches to one upstream, across all of its
#: sessions and connections. Raise it to be gentler; a call that has to wait for
#: its turn is held within the hold timeout like any other fetch.
MIN_FETCH_INTERVAL_S = 1.0
#: Longest the whole paged fetch may take.
MAX_FETCH_TOTAL_S = 60.0
_MAX_BACKOFF_S = 300.0

#: Sends one ``tools/list`` request with these params and returns the JSON-RPC
#: response (or ``None`` when there is no answer in time).
Request = Callable[[dict[str, Any]], Awaitable["dict[str, Any] | None"]]


def is_own_id(message_id: Any) -> bool:
    return isinstance(message_id, str) and message_id.startswith(PIN_ID_PREFIX)


class FetchLimiter:
    """Spaces paged fetches to one upstream at least ``interval_s`` apart.

    One per upstream, shared by every inventory that talks to it, so a client
    that churns session ids cannot multiply the load on the server."""

    def __init__(
        self,
        interval_s: float | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.interval_s = MIN_FETCH_INTERVAL_S if interval_s is None else interval_s
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0

    async def acquire(self) -> None:
        now = self._clock()
        at = max(now, self._next)
        self._next = at + self.interval_s
        if at > now:
            await self._sleep(at - now)


class ToolInventory:
    """The hashes of one server's tools, as the runtime last fetched them."""

    def __init__(
        self,
        *,
        hold_timeout_s: float = DEFAULT_HOLD_TIMEOUT_S,
        clock: Callable[[], float] = time.monotonic,
        limiter: FetchLimiter | None = None,
    ) -> None:
        self.hold_timeout_s = hold_timeout_s
        self._limiter = limiter
        #: Transport-specific data the request function needs (HTTP: the URL
        #: and the host's headers, including its ``Mcp-Session-Id``).
        self.context: Any = None
        #: Called with the new ``{name: hashes | None}`` after each fetch.
        self.on_refresh: Callable[[Mapping[str, ToolHashes | None]], None] | None = None
        self._clock = clock
        self._request: Request | None = None
        self._ready = False
        self._stale = False
        self._disabled = False
        #: What the host was shown for each tool in its own tools/list answers
        #: (``None``: shown a definition that cannot be hashed).
        self._host_seen: dict[str, ToolHashes | None] = {}
        #: Names the host's list showed with different definitions (possibly on
        #: different pages of one list).
        self._host_ambiguous: set[str] = set()
        self._again = False
        self._tools: dict[str, ToolHashes | None] = {}
        self._fetched_at: float | None = None
        self._task: asyncio.Task[None] | None = None
        self._failures = 0
        self._blocked_until = 0.0
        self._nonce = secrets.token_hex(4)
        self._counter = itertools.count(1)

    # -- wiring ------------------------------------------------------------

    def bind(self, request: Request) -> None:
        self._request = request

    def set_ready(self) -> None:
        """The transport may now send. On stdio: the host's initialize is done."""
        self._ready = True

    def next_id(self) -> str:
        return f"{PIN_ID_PREFIX}{self._nonce}-{next(self._counter)}"

    def close(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = None

    def disable(self) -> None:
        """Stop fetching on this transport. Every tool stays unchecked."""
        self._disabled = True  # a fetch already running ends on its own

    @property
    def disabled(self) -> bool:
        return self._disabled

    def note_host_seen(self, name: str, hashes: ToolHashes | None) -> None:
        """Remember what the host was shown for ``name`` (bounded). A name shown
        again with a different hash, on the same page or a later page of the
        same list, becomes ambiguous: it matches no pin."""
        if name in self._host_ambiguous:
            return
        if name in self._host_seen:
            if self._host_seen[name] != hashes:
                self._host_seen[name] = None
                self._host_ambiguous.add(name)
        elif len(self._host_seen) < MAX_TOOLS:
            self._host_seen[name] = hashes

    def host_ambiguous(self, name: str) -> bool:
        return name in self._host_ambiguous

    def reset_host_seen(self) -> None:
        """The host starts a new list (a ``tools/list`` with no cursor)."""
        self._host_seen.clear()
        self._host_ambiguous.clear()

    def host_seen(self, name: str) -> tuple[bool, ToolHashes | None]:
        """``(seen, hashes)`` for what the host was last shown for ``name``."""
        if name in self._host_seen:
            return True, self._host_seen[name]
        return False, None

    def defer(self, seconds: float) -> None:
        """A server asked us to wait (``Retry-After``)."""
        self._blocked_until = max(self._blocked_until, self._clock() + min(max(seconds, 0.0), _MAX_BACKOFF_S))

    # -- state -------------------------------------------------------------

    @property
    def has_data(self) -> bool:
        return self._fetched_at is not None

    @property
    def fetching(self) -> bool:
        return self._task is not None and not self._task.done()

    def lookup(self, name: str) -> tuple[ToolHashes | None, bool]:
        """``(hashes, hashable)`` for a tool seen and checked.

        ``(None, True)``: not seen, or the list is out of date after a
        ``list_changed`` that has not been refetched. ``(None, False)``: seen,
        but its definition cannot be hashed.
        """
        if self._stale or name not in self._tools:
            return None, True
        hashes = self._tools[name]
        return hashes, hashes is not None

    # -- fetching ----------------------------------------------------------

    def mark_changed(self) -> None:
        """The server said its tools changed: everything seen is out of date."""
        self._stale = True
        self.reset_host_seen()  # the host must list again before this is compared
        self.request_refresh()

    def request_refresh(self) -> None:
        if self._request is None or not self._ready or self._disabled:
            return
        if self.fetching:
            self._again = True
            return
        if self._clock() < self._blocked_until:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._task = loop.create_task(self._run())

    async def settle(self, name: str) -> bool:
        """Hold until ``name`` can be checked. False when the hold timed out."""
        if self._request is None or not self._ready or self._disabled:
            return True
        if not self.fetching:
            unseen = name not in self._tools
            if self._stale or (
                unseen
                and (
                    self._fetched_at is None
                    or self._clock() - self._fetched_at >= MIN_UNSEEN_REFETCH_S
                )
            ):
                self.request_refresh()
        task = self._task
        if task is None or task.done():
            return True
        try:
            await asyncio.wait_for(asyncio.shield(task), self.hold_timeout_s)
        except asyncio.TimeoutError:
            log.warning("coriqo-mcp: the tool list was not refreshed in %.0fs; "
                        "the call is treated as not checked", self.hold_timeout_s)
            return False
        return True

    async def _run(self) -> None:
        await asyncio.sleep(0)  # let the line that readied us reach the server first
        while True:
            self._again = False
            ok = await self._fetch_once()
            if not ok or not self._again:
                return

    async def _fetch_once(self) -> bool:
        tools: dict[str, ToolHashes | None] | None = None
        try:
            if self._limiter is not None:
                await self._limiter.acquire()
            tools = await asyncio.wait_for(self._collect(), MAX_FETCH_TOTAL_S)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed fetch leaves the tools unchecked
            log.debug("coriqo-mcp: tool list fetch failed", exc_info=True)
        if tools is None:
            self._failures += 1
            self._blocked_until = max(
                self._blocked_until, self._clock() + min(2.0**self._failures, _MAX_BACKOFF_S)
            )
            log.warning("coriqo-mcp: could not fetch the server's tool list; tools "
                        "not yet checked count as unpinned")
            return False
        self._failures = 0
        self._tools = tools
        self._fetched_at = self._clock()
        if not self._again:
            self._stale = False
        if self.on_refresh is not None:
            with contextlib.suppress(Exception):
                self.on_refresh(tools)
        return True

    async def _collect(self) -> dict[str, ToolHashes | None] | None:
        request = self._request
        if request is None:
            return None
        out: dict[str, ToolHashes | None] = {}
        cursor: str | None = None
        cursors: set[str] = set()
        entries = 0
        for _ in range(MAX_PAGES):
            message = await request({} if cursor is None else {"cursor": cursor})
            result = message.get("result") if isinstance(message, dict) else None
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                return None
            for tool in result["tools"]:
                # Every entry counts, so a list of junk stays bounded too.
                entries += 1
                if entries > MAX_TOOLS:
                    return None
                name = tool.get("name") if isinstance(tool, dict) else None
                if not isinstance(name, str):
                    continue
                hashes = hash_tool(tool)
                # The same name listed twice with different definitions cannot
                # be told apart by a call, so it matches no pin.
                out[name] = hashes if name not in out or out[name] == hashes else None
                if len(out) > MAX_TOOLS:
                    return None
            cursor = result.get("nextCursor")
            if not cursor:
                return out
            if not isinstance(cursor, str) or cursor in cursors:
                return None
            cursors.add(cursor)
        return None  # still paging after MAX_PAGES
