"""Anthropic on AWS Bedrock / Google Vertex AI — via the ``anthropic`` SDK.

Every other adapter in this package is hand-rolled httpx (no provider SDK
dependency, by design — see CONTRIBUTING.md). This one is the deliberate
exception: Bedrock auth is AWS SigV4 request signing, Vertex auth is GCP
OAuth service-account tokens, and neither is a reasonable thing to hand-roll
from scratch. The ``anthropic`` SDK's ``AsyncAnthropicBedrock``/
``AsyncAnthropicVertex`` already implement both correctly, so we use them
for auth/signing only — message translation and error classification stay
consistent with the rest of byoai (:func:`raise_for_status` on the SDK's own
``httpx.Response`` object, so 429→RateLimitError and Retry-After parsing
work identically to every other adapter).

Requires the ``bedrock`` or ``vertex`` extra: ``pip install
byoai-runtime[bedrock]`` / ``byoai-runtime[vertex]``.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

from ..errors import ConfigurationError, ProviderError
from ..types import Message, ProviderResponse, StreamChunk, ToolCallDelta, Usage
from .base import DEFAULT_RETRYABLE_STATUS, build_anthropic_system_field, raise_for_status

# 529 = Anthropic's "overloaded" status, retryable like a 503 — same as the
# direct-API AnthropicProvider.
DEFAULT_RETRYABLE_STATUS_ANTHROPIC = DEFAULT_RETRYABLE_STATUS | {529}


class _AnthropicSDKProviderBase:
    """Shared complete()/stream()/close() over any anthropic SDK async
    client. Message translation mirrors the httpx-based AnthropicProvider
    exactly; only client construction (in the two subclasses below) differs.
    """

    name: str
    model: str
    max_tokens: int
    cache_system: bool
    _client: Any
    _owns_client: bool
    _retryable_status: frozenset[int]

    @staticmethod
    def _sdk_usage(usage: Any) -> Usage:
        """Shared by complete()/stream() — both read the same fields off an
        SDK usage object (``response.usage``/``final.usage``)."""
        return Usage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
        )

    def _payload(self, messages: list[Message], options: dict[str, Any]) -> dict[str, Any]:
        chat = [m.to_dict() for m in messages if m.role != "system"]
        payload: dict[str, Any] = {
            "model": options.pop("model", self.model),
            "max_tokens": options.pop("max_tokens", self.max_tokens),
            "messages": chat,
            **options,
        }
        system = build_anthropic_system_field(messages, cache_system=self.cache_system)
        if system is not None:
            payload["system"] = system
        return payload

    async def complete(self, messages: list[Message], **options: Any) -> ProviderResponse:
        import anthropic

        payload = self._payload(messages, options)
        try:
            response = await self._client.messages.create(**payload)
        except anthropic.APIStatusError as exc:
            raise_for_status(
                exc.response,  # pyright: ignore[reportArgumentType]  # newer SDKs return httpx2.Response; raise_for_status only reads status_code, headers, json() and text
                provider=self.name,
                retryable_status=self._retryable_status,
            )
            raise AssertionError("unreachable: raise_for_status always raises for 4xx/5xx") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError(
                f"{self.name}: transport error: {exc}", provider=self.name, retryable=True
            ) from exc
        content = "".join(block.text for block in response.content if block.type == "text")
        return ProviderResponse(
            content=content,
            model=response.model,
            provider=self.name,
            usage=self._sdk_usage(response.usage),
            finish_reason=response.stop_reason,
            raw=response,
        )

    async def stream(
        self, messages: list[Message], **options: Any
    ) -> AsyncIterator[StreamChunk]:
        import anthropic

        payload = self._payload(messages, options)
        model = payload["model"]
        try:
            async with self._client.messages.stream(**payload) as stream:
                # Raw SDK events, not stream.text_stream — text_stream only
                # surfaces text_delta and silently drops input_json_delta, so a
                # forced tool_choice call (the only content a tool-only turn
                # produces) yielded zero content chunks through stream().
                async for event in stream:
                    is_tool_start = (
                        event.type == "content_block_start"
                        and event.content_block.type == "tool_use"
                    )
                    if is_tool_start:
                        block = event.content_block
                        yield StreamChunk(
                            tool_call=ToolCallDelta(
                                index=event.index, id=block.id, name=block.name
                            ),
                            model=model,
                            provider=self.name,
                            raw=event,
                        )
                    elif event.type == "content_block_delta":
                        delta = event.delta
                        if delta.type == "text_delta" and delta.text:
                            yield StreamChunk(
                                delta=delta.text, model=model, provider=self.name, raw=event
                            )
                        elif delta.type == "input_json_delta":
                            yield StreamChunk(
                                tool_call=ToolCallDelta(
                                    index=event.index, partial_json=delta.partial_json
                                ),
                                model=model,
                                provider=self.name,
                                raw=event,
                            )
                final = await stream.get_final_message()
        except anthropic.APIStatusError as exc:
            raise_for_status(
                exc.response,  # pyright: ignore[reportArgumentType]  # newer SDKs return httpx2.Response; raise_for_status only reads status_code, headers, json() and text
                provider=self.name,
                retryable_status=self._retryable_status,
            )
            raise AssertionError("unreachable: raise_for_status always raises for 4xx/5xx") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError(
                f"{self.name}: transport error: {exc}", provider=self.name, retryable=True
            ) from exc
        yield StreamChunk(
            done=True,
            model=final.model,
            provider=self.name,
            usage=self._sdk_usage(final.usage),
            finish_reason=final.stop_reason,
            raw=final,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self._client.close()


class AnthropicBedrockProvider(_AnthropicSDKProviderBase):
    """Anthropic models via AWS Bedrock.

    Only ``aws_region`` is required here; credentials come from the standard
    AWS chain (env vars, ``~/.aws``, or an instance/task role) unless passed
    explicitly. Declarative: ``llm={"provider": "bedrock", "model": "...",
    "aws_region": "us-east-1"}``.
    """

    def __init__(
        self,
        *,
        model: str,
        name: str = "bedrock",
        max_tokens: int = 4096,
        aws_region: str | None = None,
        aws_access_key: str | None = None,
        aws_secret_key: str | None = None,
        aws_session_token: str | None = None,
        aws_profile: str | None = None,
        default_headers: dict[str, str] | None = None,
        retryable_status: frozenset[int] | set[int] | None = None,
        client: Any | None = None,
        cache_system: bool = False,
    ) -> None:
        self.name = name
        self.model = model
        self.max_tokens = max_tokens
        self.cache_system = cache_system
        self._retryable_status = (
            frozenset(retryable_status)
            if retryable_status is not None
            else DEFAULT_RETRYABLE_STATUS_ANTHROPIC
        )
        if client is not None:
            self._client = client
            self._owns_client = False
            return
        try:
            # pyright flags this as a private-module re-export, but it's the
            # SDK's own documented public import path (confirmed at runtime).
            from anthropic import AsyncAnthropicBedrock  # pyright: ignore[reportPrivateImportUsage]
        except ImportError as exc:
            raise ConfigurationError(
                "AnthropicBedrockProvider requires the anthropic[bedrock] package: "
                "pip install 'byoai-runtime[bedrock]'"
            ) from exc
        region = aws_region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if not region:
            raise ConfigurationError(
                "AnthropicBedrockProvider requires aws_region (or $AWS_REGION / "
                "$AWS_DEFAULT_REGION); AWS credentials themselves come from the standard "
                "chain (env vars, ~/.aws, or an instance/task role) unless passed explicitly."
            )
        kwargs: dict[str, Any] = {"aws_region": region}
        if aws_access_key:
            kwargs["aws_access_key"] = aws_access_key
        if aws_secret_key:
            kwargs["aws_secret_key"] = aws_secret_key
        if aws_session_token:
            kwargs["aws_session_token"] = aws_session_token
        if aws_profile:
            kwargs["aws_profile"] = aws_profile
        if default_headers:
            kwargs["default_headers"] = default_headers
        self._client = AsyncAnthropicBedrock(**kwargs)
        self._owns_client = True


class AnthropicVertexProvider(_AnthropicSDKProviderBase):
    """Anthropic models via Google Vertex AI.

    ``project_id`` and ``region`` are required; credentials come from
    Application Default Credentials unless ``access_token``/``credentials``
    is passed explicitly. Declarative: ``llm={"provider": "vertex",
    "model": "...", "project_id": "...", "region": "us-east5"}``.
    """

    def __init__(
        self,
        *,
        model: str,
        name: str = "vertex",
        max_tokens: int = 4096,
        project_id: str | None = None,
        region: str | None = None,
        access_token: str | None = None,
        credentials: Any | None = None,
        default_headers: dict[str, str] | None = None,
        retryable_status: frozenset[int] | set[int] | None = None,
        client: Any | None = None,
        cache_system: bool = False,
    ) -> None:
        self.name = name
        self.model = model
        self.max_tokens = max_tokens
        self.cache_system = cache_system
        self._retryable_status = (
            frozenset(retryable_status)
            if retryable_status is not None
            else DEFAULT_RETRYABLE_STATUS_ANTHROPIC
        )
        if client is not None:
            self._client = client
            self._owns_client = False
            return
        try:
            # See the matching note in AnthropicBedrockProvider above.
            from anthropic import AsyncAnthropicVertex  # pyright: ignore[reportPrivateImportUsage]
        except ImportError as exc:
            raise ConfigurationError(
                "AnthropicVertexProvider requires the anthropic[vertex] package: "
                "pip install 'byoai-runtime[vertex]'"
            ) from exc
        resolved_project = (
            project_id
            or os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
        )
        resolved_region = (
            region or os.environ.get("ANTHROPIC_VERTEX_REGION") or os.environ.get("CLOUD_ML_REGION")
        )
        if not (resolved_project and resolved_region):
            raise ConfigurationError(
                "AnthropicVertexProvider requires project_id and region (or "
                "$ANTHROPIC_VERTEX_PROJECT_ID/$GOOGLE_CLOUD_PROJECT and "
                "$ANTHROPIC_VERTEX_REGION/$CLOUD_ML_REGION); GCP credentials themselves "
                "come from Application Default Credentials unless access_token/credentials "
                "is passed explicitly."
            )
        kwargs: dict[str, Any] = {"project_id": resolved_project, "region": resolved_region}
        if access_token:
            kwargs["access_token"] = access_token
        if credentials is not None:
            kwargs["credentials"] = credentials
        if default_headers:
            kwargs["default_headers"] = default_headers
        self._client = AsyncAnthropicVertex(**kwargs)
        self._owns_client = True
