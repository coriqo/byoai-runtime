"""Redis/Valkey cache adapter with non-invasive state management.

* All writes go under an isolated namespace (default ``byoai:``) — existing
  application keys are never touched.
* ``session_reader`` reads existing application state (chat histories, session
  blobs) read-only through a key-pattern mapping, so ByoAI can reuse what your
  app already stores without migration.

Requires the ``redis`` extra: ``pip install byoai-runtime[redis]``.
"""

from __future__ import annotations

from typing import Any

from .. import _json as json
from ..errors import CacheError, ConfigurationError


def make_redis_client(
    *,
    url: str = "redis://localhost:6379",
    mode: str = "standalone",
    sentinels: list[tuple[str, int]] | list[list] | None = None,
    service_name: str | None = None,
    **client_kwargs: Any,
) -> Any:
    """Build an async Redis client for the deployment you already run.

    * ``standalone`` (default) — single node or Valkey, via ``url``.
    * ``cluster`` — Redis Cluster, via ``url`` pointing at any node.
    * ``sentinel`` — Sentinel-managed master: pass ``sentinels`` as
      ``[(host, port), ...]`` and the ``service_name``.

    Requires the ``redis`` extra: ``pip install byoai-runtime[redis]``.
    """
    try:
        import redis.asyncio as aioredis
    except ImportError as exc:  # pragma: no cover
        raise ConfigurationError(
            "Redis support requires the redis package: pip install 'byoai-runtime[redis]'"
        ) from exc

    if mode != "sentinel" and (sentinels or service_name):
        raise ConfigurationError(
            f"sentinels/service_name were given but mode={mode!r} — they're only used "
            "when mode='sentinel', so this would silently connect without them"
        )
    client_kwargs.setdefault("decode_responses", True)
    if mode == "standalone":
        return aioredis.from_url(url, **client_kwargs)
    if mode == "cluster":
        from redis.asyncio.cluster import RedisCluster

        return RedisCluster.from_url(url, **client_kwargs)
    if mode == "sentinel":
        if not sentinels or not service_name:
            raise ConfigurationError(
                "sentinel mode requires 'sentinels' ([(host, port), ...]) and 'service_name'"
            )
        from redis.asyncio.sentinel import Sentinel

        sentinel = Sentinel([(str(s[0]), int(s[1])) for s in sentinels], **client_kwargs)
        return sentinel.master_for(service_name)
    raise ConfigurationError(
        f"unknown redis mode {mode!r} (expected standalone, cluster, or sentinel)"
    )


class RedisCache:
    def __init__(
        self,
        *,
        url: str = "redis://localhost:6379",
        namespace: str = "byoai:",
        session_reader: dict[str, str] | None = None,
        client: Any | None = None,
        default_ttl: int | None = 3600,
        mode: str = "standalone",
        sentinels: list | None = None,
        service_name: str | None = None,
        **client_kwargs: Any,
    ) -> None:
        """``**client_kwargs`` (e.g. ``socket_timeout``, ``socket_connect_timeout``,
        ``retry_on_timeout``, ``health_check_interval``, ``ssl``, ``ssl_ca_certs``)
        are forwarded to the underlying redis-py client when ``client=`` isn't
        supplied directly — see redis-py's connection docs for the full set."""
        if client is None:
            client = make_redis_client(
                url=url, mode=mode, sentinels=sentinels, service_name=service_name,
                **client_kwargs,
            )
        # Explicitly typed (not just inferred): the `client is None` branch above
        # reassigns the same declared-Optional parameter, and pyright doesn't
        # narrow a reassigned `Any | None` parameter across the branch merge —
        # without this it treats every `self._client.foo()` below as Optional.
        self._client: Any = client
        self.namespace = namespace
        self.default_ttl = default_ttl
        session_reader = session_reader or {}
        self._session_pattern: str | None = session_reader.get("pattern")
        self._session_format: str = session_reader.get("format", "json")

    def _key(self, key: str) -> str:
        return key if key.startswith(self.namespace) else f"{self.namespace}{key}"

    async def get(self, key: str) -> Any | None:
        try:
            raw = await self._client.get(self._key(key))
        except Exception as exc:
            raise CacheError(f"redis get failed: {exc}") from exc
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw

    async def set(self, key: str, value: Any, *, ttl: int | None = None) -> None:
        # Always JSON-encode (strings included) so get() round-trips the exact
        # value and type — set("flag", "true") must come back as the str "true".
        # Caveat: values must be JSON-representable; non-finite floats
        # (NaN/Infinity) are not round-trip-safe (see byoai._json).
        payload = json.dumps(value, default=str)
        effective_ttl = ttl if ttl is not None else self.default_ttl
        if effective_ttl is not None and effective_ttl <= 0:
            return  # a non-positive TTL means "expire immediately": don't store
        try:
            await self._client.set(self._key(key), payload, ex=effective_ttl)
        except Exception as exc:
            raise CacheError(f"redis set failed: {exc}") from exc

    async def delete(self, key: str) -> None:
        try:
            await self._client.delete(self._key(key))
        except Exception as exc:
            raise CacheError(f"redis delete failed: {exc}") from exc

    async def read_session(self, **params: str) -> Any | None:
        """Read existing app state via the configured key pattern. Never writes.

        Two sequential round trips (``TYPE`` then ``LRANGE``/``GET``) — the
        key's shape isn't known ahead of time, and Redis has no single
        command that fetches "whatever this key is." ``ContextResolver``
        calls this on every request that has both ``cache=`` and history
        reading enabled (``max_history_messages`` > 0, the default), so this
        is real per-request Redis latency on top of the LLM call itself, not
        a one-time cost.
        """
        if not self._session_pattern:
            return None
        key = self._session_pattern.format(**params)
        try:
            key_type = await self._client.type(key)
            if key_type in ("none", b"none"):
                return None
            if key_type in ("list", b"list"):
                items = await self._client.lrange(key, 0, -1)
                return [self._decode(i) for i in items]
            raw = await self._client.get(key)
        except Exception as exc:
            raise CacheError(f"redis session read failed: {exc}") from exc
        return self._decode(raw)

    def _decode(self, raw: Any) -> Any:
        if raw is None or self._session_format != "json":
            return raw
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return raw

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except AttributeError:  # older redis-py
            await self._client.close()
