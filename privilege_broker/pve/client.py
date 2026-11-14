"""mTLS HTTP client for the approval broker, with explicit configuration only.

The client never reads deployment state from the environment: the broker URL,
the trust root and the client certificate pair are constructor arguments, so a
missing value fails closed instead of silently dialling a built-in address.
"""

from __future__ import annotations

import http.client
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

#: Statuses that say "later", not "no": rate limiting and an unavailable
#: upstream behind the broker's TLS front end.
_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})

#: Upper bound on a response body the client reads; anything larger is refused.
_MAX_BODY_BYTES = 1024 * 1024

#: Error detail kept in exceptions; the broker's own message, truncated.
_DETAIL_LIMIT = 1024


class BrokerUnavailable(RuntimeError):
    """The broker was not reached, or asked the caller to come back later.

    A network or timeout failure, or HTTP 429, 502, 503 or 504. The same call
    may be repeated later.
    """


class BrokerHTTPError(RuntimeError):
    """The broker refused the call with any other HTTP status."""

    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class BrokerClientConfig:
    """Explicit broker endpoint and mTLS trust material.

    No field carries a deployment default: the caller (bridge, worker or a
    deployment adapter) supplies every value.
    """

    #: ``https://`` URL of the broker's TLS front end.
    broker_url: str
    #: Path to the PEM client certificate presented to the broker.
    cert_path: str
    #: Path to the PEM private key matching ``cert_path``.
    key_path: str
    #: Optional path to the PEM CA bundle that signed the broker's certificate.
    ca_path: str | None = None
    #: Per-request timeout in seconds.
    timeout: float = 15.0

    def __post_init__(self) -> None:
        if not self.broker_url.startswith("https://"):
            raise ValueError("broker_url must be an https:// URL")
        if not self.cert_path or not self.key_path:
            raise ValueError("mTLS client certificate and key paths are required")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")


def _truncate(text: str, limit: int = _DETAIL_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep every request at its configured endpoint, including mTLS credentials."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Returning None makes urllib raise HTTPError without opening newurl.
        return None


class BrokerClient:
    """mTLS HTTP client for the PVE approval broker.

    Failures are classified so callers can distinguish a transient
    ``BrokerUnavailable`` (retry later) from a final ``BrokerHTTPError``.
    """

    def __init__(
        self,
        config: BrokerClientConfig,
        *,
        ssl_context: ssl.SSLContext | None = None,
        opener: Any = None,
    ) -> None:
        self._config = config
        if ssl_context is None:
            ssl_context = ssl.create_default_context(cafile=config.ca_path or None)
            ssl_context.load_cert_chain(config.cert_path, config.key_path)
            ssl_context.check_hostname = True
        self._context = ssl_context
        if opener is None:
            # ProxyHandler({}) disables environment proxies: the mTLS channel
            # must reach the broker directly.
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _RejectRedirects(),
                urllib.request.HTTPSHandler(context=ssl_context),
            )
        self._opener = opener
        self._broker_url = config.broker_url.rstrip("/")

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send one JSON request and return the decoded object.

        Raises ``BrokerUnavailable`` for transient failures, ``BrokerHTTPError``
        for final HTTP refusals and ``RuntimeError`` for unusable bodies.
        """
        if not path.startswith("/"):
            raise ValueError("path must start with '/'")
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            f"{self._broker_url}{path}",
            method=method,
            data=body,
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with self._opener.open(request, timeout=self._config.timeout) as response:
                expected_length = None
                declared_length = response.headers.get("Content-Length")
                # Match the transport's chunked framing decision. A bounded
                # read alone does not detect EOF in a fixed-length response.
                chunked = response.headers.get("Transfer-Encoding", "").lower() == "chunked"
                if declared_length is not None and not chunked:
                    try:
                        expected_length = int(declared_length)
                    except ValueError as exc:
                        raise RuntimeError("broker response length is invalid") from exc
                    if expected_length < 0:
                        raise RuntimeError("broker response length is invalid")
                    if expected_length > _MAX_BODY_BYTES:
                        raise RuntimeError("broker response too large")
                raw = response.read(_MAX_BODY_BYTES + 1)
                if expected_length is not None and len(raw) < expected_length:
                    raise BrokerUnavailable("broker unavailable: incomplete response body")
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(_DETAIL_LIMIT + 1).decode("utf-8", errors="replace")
            except (OSError, http.client.HTTPException):
                # The status is authoritative even when its detail stream is
                # truncated or malformed; do not reclassify a final refusal.
                detail = ""
            finally:
                exc.close()
            message = f"broker HTTP {exc.status}: {_truncate(detail)}"
            if exc.status in _RETRYABLE_STATUSES:
                raise BrokerUnavailable(message) from exc
            raise BrokerHTTPError(exc.status, message) from exc
        except (urllib.error.URLError, TimeoutError, OSError, http.client.IncompleteRead) as exc:
            raise BrokerUnavailable(f"broker unavailable: {type(exc).__name__}") from exc
        except http.client.HTTPException as exc:
            raise RuntimeError("broker HTTP response is unusable") from exc
        if len(raw) > _MAX_BODY_BYTES:
            raise RuntimeError("broker response too large")
        try:
            result = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            # Includes UTF-8/JSON syntax failures and decoder limits such as
            # Python's integer-conversion guard, not just JSONDecodeError.
            raise RuntimeError("broker returned unusable JSON") from exc
        # A body that is not a JSON object carries no usable answer.
        return result if isinstance(result, dict) else {}
