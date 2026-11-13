"""Server-owned Discord approval notifications, independent of authorization.

The destination comes from deployer configuration, never a request. Webhook
credentials must not appear in raised errors, logs or audit summaries.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

USER_AGENT = "privilege-broker-notify/1"
TIMEOUT_SECONDS = 5
REASON_LIMIT = 300
_MARKDOWN = re.compile(r"([\\*_~`|>#\[\]()-])")
Transport = Callable[[str, dict[str, Any]], None]


class NotificationError(RuntimeError):
    """A transport failure with no destination, token or provider response."""

    def __init__(self, status: int | None = None) -> None:
        self.status = status
        super().__init__("notification delivery failed")


def _post(url: str, payload: dict[str, Any]) -> None:
    try:
        request = urllib.request.Request(
            url,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            data=json.dumps(payload).encode("utf-8"),
        )
        # Internet egress uses the deployer's normal proxy configuration.
        with urllib.request.build_opener().open(request, timeout=TIMEOUT_SECONDS):
            pass
    except urllib.error.HTTPError as exc:
        raise NotificationError(exc.code) from None
    except Exception:
        # urllib exceptions can contain the complete credential-bearing URL.
        raise NotificationError() from None


def describe_error(exc: BaseException) -> str:
    """Return only an error class and, when present, an HTTP status."""
    if isinstance(exc, NotificationError) and exc.status is not None:
        return f"NotificationError {exc.status}"
    return type(exc).__name__


def neutralise(text: str, limit: int = REASON_LIMIT) -> str:
    """One line, no agent-controlled markup, mentions or clickable links."""
    flat = " ".join(text.split())
    if len(flat) > limit:
        flat = flat[: limit - 1] + "…"
    escaped = _MARKDOWN.sub(r"\\\1", flat)
    return escaped.replace("@", "@\u200b").replace("://", ":\u200b//")


def approval_message(*, action: str, ct_id: int, reason: str, expires_at: int, approval_url: str) -> str:
    expiry = datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"🔐 Approval requested: {neutralise(action, 64)} on CT {int(ct_id)}\n"
        f"Reason: {neutralise(reason)}\n"
        f"Expires: {expiry}\n"
        f"{approval_url}"
    )


class DiscordNotifier:
    """Send to one server-configured destination; failures grant no authority."""

    def __init__(self, webhook_url: str, transport: Transport | None = None) -> None:
        self._url = webhook_url
        self._transport = transport or _post

    @classmethod
    def from_file(cls, path: str, transport: Transport | None = None) -> DiscordNotifier | None:
        """Return None when delivery is unconfigured, unreadable or empty."""
        if not path:
            return None
        try:
            url = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return cls(url, transport) if url else None

    def send(self, content: str) -> None:
        self._transport(
            self._url,
            {"content": content[:2000], "allowed_mentions": {"parse": []}, "flags": 4},
        )
