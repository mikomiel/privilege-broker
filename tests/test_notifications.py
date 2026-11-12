"""Notification content and transport safety without contacting a provider."""

import traceback
import urllib.error
from unittest.mock import Mock

import pytest

from privilege_broker import notifications as notify


@pytest.mark.parametrize(
    "content", ["@everyone", "**bold** [click](https://other.example.test)", "line\n\rbreak", "x" * 500]
)
def test_untrusted_text_is_inert(content):
    result = notify.neutralise(content)
    assert "@everyone" not in result
    assert "https://" not in result
    assert "\n" not in result and "\r" not in result
    assert "[click]" not in result
    if len(content) > notify.REASON_LIMIT:
        assert result.endswith("…")
        assert len(result) == notify.REASON_LIMIT


def test_fixed_destination_and_explicit_mentions_and_embeds_policy(tmp_path):
    destination = "https://notify.example.test/synthetic-only"
    path = tmp_path / "webhook"
    path.write_text(destination)
    transport = Mock()
    notifier = notify.DiscordNotifier.from_file(str(path), transport)
    assert notifier is not None
    message = notify.approval_message(
        action="ct.reboot",
        ct_id=9001,
        reason="@everyone https://other.example.test/try-to-redirect",
        expires_at=1_800_000_000,
        approval_url="https://broker.example.test/v1/broker/requests/synthetic/approval",
    )
    notifier.send(message)
    url, payload = transport.call_args.args
    assert url == destination
    assert payload["allowed_mentions"] == {"parse": []}
    assert payload["flags"] == 4
    assert "@everyone" not in payload["content"]
    assert "https://other.example.test" not in payload["content"]
    assert "UTC" in payload["content"]
    assert payload["content"].endswith("/synthetic/approval")


def test_unconfigured_missing_and_empty_files_disable_delivery(tmp_path):
    assert notify.DiscordNotifier.from_file("") is None
    assert notify.DiscordNotifier.from_file(str(tmp_path / "missing")) is None
    empty = tmp_path / "empty"
    empty.write_text(" \n")
    assert notify.DiscordNotifier.from_file(str(empty)) is None


@pytest.mark.parametrize("http_error", [True, False], ids=["http-status", "network-error"])
def test_transport_errors_never_expose_a_credential_bearing_destination(monkeypatch, http_error):
    destination = "https://notify.example.test/synthetic-sensitive-path"
    opener = Mock()
    if http_error:
        opener.open.side_effect = urllib.error.HTTPError(destination, 403, destination, {}, None)
    else:
        opener.open.side_effect = urllib.error.URLError(destination)
    monkeypatch.setattr(notify.urllib.request, "build_opener", lambda: opener)
    with pytest.raises(notify.NotificationError) as raised:
        notify.DiscordNotifier(destination).send("synthetic message")
    assert destination not in "".join(traceback.format_exception(raised.value))
    assert destination not in notify.describe_error(raised.value)
    assert raised.value.status == (403 if http_error else None)
    assert opener.open.call_args.kwargs["timeout"] == notify.TIMEOUT_SECONDS


def test_message_limit_and_safe_error_description():
    transport = Mock()
    notify.DiscordNotifier("https://notify.example.test/synthetic-only", transport).send("x" * 2500)
    assert len(transport.call_args.args[1]["content"]) == 2000
    assert notify.describe_error(RuntimeError("must not be exposed")) == "RuntimeError"
