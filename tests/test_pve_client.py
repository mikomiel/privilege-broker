"""Tests for the explicit-config mTLS broker client."""

from __future__ import annotations

import io
import json
import ssl
import urllib.error
import urllib.request
import urllib.response
from email.message import Message

import pytest

from privilege_broker.pve.client import BrokerClient, BrokerClientConfig, BrokerHTTPError, BrokerUnavailable

CONFIG = BrokerClientConfig(
    broker_url="https://broker.example.test",
    cert_path="/etc/example/agent-cert.pem",
    key_path="/etc/example/agent-key.pem",
    ca_path="/etc/example/broker-ca.pem",
    timeout=15.0,
)


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int = -1) -> bytes:
        return self._body[:limit] if limit >= 0 else self._body


class _FakeOpener:
    """Stands in for urllib's opener; records requests and answers scripted."""

    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes = list(outcomes)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float = 0) -> object:
        self.requests.append(request)
        if not self._outcomes:
            raise AssertionError("no scripted outcome left")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _client(opener: _FakeOpener) -> BrokerClient:
    return BrokerClient(CONFIG, ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), opener=opener)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_config_requires_https_broker_url() -> None:
    with pytest.raises(ValueError, match="https://"):
        BrokerClientConfig(broker_url="http://broker.example.test", cert_path="c", key_path="k")


def test_config_requires_client_certificate_and_key() -> None:
    with pytest.raises(ValueError, match="certificate and key"):
        BrokerClientConfig(broker_url="https://broker.example.test", cert_path="", key_path="k")
    with pytest.raises(ValueError, match="certificate and key"):
        BrokerClientConfig(broker_url="https://broker.example.test", cert_path="c", key_path="")


def test_config_requires_positive_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        BrokerClientConfig(broker_url="https://broker.example.test", cert_path="c", key_path="k", timeout=0)


def test_default_context_loads_the_configured_pair_and_verifies_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The client builds its mTLS context from the explicit config paths only."""

    class _RecordingContext:
        check_hostname = False

        def __init__(self) -> None:
            self.loaded: list[tuple[str, str]] = []

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            self.loaded.append((certfile, keyfile))

    context = _RecordingContext()
    monkeypatch.setattr(ssl, "create_default_context", lambda **kwargs: context)
    client = BrokerClient(CONFIG)
    assert context.loaded == [(CONFIG.cert_path, CONFIG.key_path)]
    assert context.check_hostname is True
    assert client._context is context


# ---------------------------------------------------------------------------
# Request handling and failure classification
# ---------------------------------------------------------------------------


def test_request_sends_method_path_and_json_body() -> None:
    opener = _FakeOpener([_FakeResponse(b'{"status": "pending"}')])
    client = _client(opener)
    assert client.request("POST", "/v1/broker/requests", {"action": "ct.reboot"}) == {"status": "pending"}
    (request,) = opener.requests
    assert request.full_url == "https://broker.example.test/v1/broker/requests"
    assert request.get_method() == "POST"
    assert request.headers["Content-type"] == "application/json"
    assert json.loads(request.data.decode()) == {"action": "ct.reboot"}


def test_request_without_payload_sends_no_body() -> None:
    opener = _FakeOpener([_FakeResponse(b'{"status": "ok"}')])
    assert _client(opener).request("GET", "/health") == {"status": "ok"}
    assert opener.requests[0].data is None


def test_request_rejects_a_path_without_leading_slash() -> None:
    with pytest.raises(ValueError, match="path"):
        _client(_FakeOpener([])).request("GET", "v1/broker/requests")


def test_non_object_json_response_becomes_empty_dict() -> None:
    opener = _FakeOpener([_FakeResponse(b'["not", "an", "object"]')])
    assert _client(opener).request("GET", "/x") == {}


def test_invalid_json_body_is_a_refusal() -> None:
    opener = _FakeOpener([_FakeResponse(b"not json at all")])
    with pytest.raises(RuntimeError, match="non-JSON"):
        _client(opener).request("GET", "/x")


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_retryable_statuses_are_broker_unavailable(status: int) -> None:
    error = urllib.error.HTTPError(
        "https://broker.example.test/x", status, "err", None, io.BytesIO(b'{"detail": "busy"}')
    )
    with pytest.raises(BrokerUnavailable, match=f"broker HTTP {status}"):
        _client(_FakeOpener([error])).request("GET", "/x")


def test_final_http_status_is_broker_http_error_with_status() -> None:
    error = urllib.error.HTTPError(
        "https://broker.example.test/x", 409, "err", None, io.BytesIO(b'{"detail": "already fetched"}')
    )
    with pytest.raises(BrokerHTTPError, match="already fetched") as excinfo:
        _client(_FakeOpener([error])).request("GET", "/x")
    assert excinfo.value.status == 409


def test_http_error_detail_is_truncated() -> None:
    error = urllib.error.HTTPError("https://broker.example.test/x", 400, "err", None, io.BytesIO(b"x" * 5000))
    with pytest.raises(BrokerHTTPError) as excinfo:
        _client(_FakeOpener([error])).request("GET", "/x")
    assert len(str(excinfo.value)) <= len("broker HTTP 400: ") + 1024 + 3


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError("connection refused"),
        TimeoutError("timed out"),
        ConnectionResetError("reset"),
    ],
)
def test_transport_failures_are_broker_unavailable(failure: Exception) -> None:
    with pytest.raises(BrokerUnavailable, match="broker unavailable"):
        _client(_FakeOpener([failure])).request("GET", "/x")


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "location",
    [
        "http://broker.example.test/redirected",
        "https://other.example.test/redirected",
        "https://broker.example.test/redirected",
    ],
)
def test_default_opener_rejects_redirects_before_contacting_the_destination(status: int, location: str) -> None:
    """Use urllib's real error/redirect chain; replace only network transport."""
    contacted = []

    class Transport(urllib.request.BaseHandler):
        def default_open(self, request):
            contacted.append(request.full_url)
            headers = Message()
            code = status if len(contacted) == 1 else 200
            if code != 200:
                headers["Location"] = location
            response = urllib.response.addinfourl(
                io.BytesIO(b'{"status":"approved"}'), headers, request.full_url, code
            )
            response.msg = "Found" if code != 200 else "OK"
            return response

    client = BrokerClient(CONFIG, ssl_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    client._opener.add_handler(Transport())
    with pytest.raises(BrokerHTTPError) as excinfo:
        client.request("GET", "/x")
    assert excinfo.value.status == status
    assert contacted == ["https://broker.example.test/x"]


@pytest.mark.parametrize("status", [409, 429, 502, 503, 504])
def test_error_body_read_is_bounded_and_response_is_closed(status: int) -> None:
    class ErrorBody(io.BytesIO):
        def __init__(self):
            super().__init__(b"x" * 5000)
            self.read_sizes = []

        def read(self, size=-1):
            self.read_sizes.append(size)
            assert 0 < size <= 1025, "error body must never be read without a finite detail limit"
            return super().read(size)

    body = ErrorBody()
    error = urllib.error.HTTPError("https://broker.example.test/x", status, "err", None, body)
    expected = BrokerHTTPError if status == 409 else BrokerUnavailable
    with pytest.raises(expected, match=f"broker HTTP {status}") as excinfo:
        _client(_FakeOpener([error])).request("GET", "/x")
    assert body.read_sizes == [1025]
    assert body.closed
    assert len(str(excinfo.value)) <= len(f"broker HTTP {status}: ") + 1024 + 3


def test_error_response_is_closed_when_its_body_read_fails() -> None:
    class BrokenBody(io.BytesIO):
        def read(self, size=-1):
            raise OSError("synthetic stream failure")

    body = BrokenBody()
    error = urllib.error.HTTPError("https://broker.example.test/x", 503, "err", None, body)
    with pytest.raises(BrokerUnavailable, match="broker HTTP 503"):
        _client(_FakeOpener([error])).request("GET", "/x")
    assert body.closed
