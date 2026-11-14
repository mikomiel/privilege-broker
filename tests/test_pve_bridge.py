"""Tests for the agent-facing approval request bridge."""

from __future__ import annotations

import io
import json
import os
import stat
import uuid
from pathlib import Path

import pytest

from privilege_broker.pve import bridge as bridge_module
from privilege_broker.pve.bridge import ApprovalBridge, BridgeConfig
from privilege_broker.pve.client import BrokerHTTPError, BrokerUnavailable

VALID_ID = "123e4567-e89b-42d3-a456-426614174000"


class FakeBroker:
    """Records requests and answers with a scripted create response or error."""

    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self._response = (
            {"request_id": VALID_ID, "status": "pending", "expires_at": 1_800_000_000}
            if response is None
            else response
        )
        self._error = error
        self.calls: list[tuple[str, str, object]] = []

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        self.calls.append((method, path, payload))
        if self._error is not None:
            raise self._error
        if not isinstance(self._response, dict):
            return self._response
        return dict(self._response)


@pytest.fixture
def config(tmp_path: Path) -> BridgeConfig:
    return BridgeConfig(
        state_dir=tmp_path,
        public_url="https://broker.example.test",
        requester="example-agent",
    )


@pytest.fixture
def bridge(config: BridgeConfig) -> ApprovalBridge:
    return ApprovalBridge(config)


def _key_files(config: BridgeConfig) -> list[Path]:
    keys = config.state_dir / "keys"
    return list(keys.iterdir()) if keys.is_dir() else []


def _input_files(config: BridgeConfig) -> list[Path]:
    inputs = config.state_dir / "input"
    return list(inputs.iterdir()) if inputs.is_dir() else []


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_config_requires_https_public_url(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="https://"):
        BridgeConfig(state_dir=tmp_path, public_url="http://broker.example.test", requester="agent")


def test_config_requires_a_requester(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requester"):
        BridgeConfig(state_dir=tmp_path, public_url="https://broker.example.test", requester="  ")


# ---------------------------------------------------------------------------
# Input validation — refusals happen before any broker call or key write
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["shell", "ct.exec", "", "CT.START"])
def test_untyped_action_is_refused(bridge: ApprovalBridge, action: str) -> None:
    broker = FakeBroker()
    with pytest.raises(ValueError, match="action"):
        bridge.request_mutation(action, 9001, "reason", broker)
    assert broker.calls == []
    assert _key_files(bridge._config) == []


@pytest.mark.parametrize("ct_id", [0, -1, 1.5, True, "9001", None])
def test_invalid_ct_id_is_refused(bridge: ApprovalBridge, ct_id: object) -> None:
    broker = FakeBroker()
    with pytest.raises(ValueError, match="ct_id"):
        bridge.request_mutation("ct.reboot", ct_id, "reason", broker)  # type: ignore[arg-type]
    assert broker.calls == []
    assert _key_files(bridge._config) == []


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501, 42])
def test_invalid_reason_is_refused(bridge: ApprovalBridge, reason: object) -> None:
    broker = FakeBroker()
    with pytest.raises(ValueError, match="reason"):
        bridge.request_mutation("ct.reboot", 9001, reason, broker)  # type: ignore[arg-type]
    assert broker.calls == []
    assert _key_files(bridge._config) == []


# ---------------------------------------------------------------------------
# Successful request
# ---------------------------------------------------------------------------


def test_success_writes_input_and_ephemeral_key(bridge: ApprovalBridge, config: BridgeConfig) -> None:
    broker = FakeBroker()
    result = bridge.request_mutation("ct.reboot", 9001, "Apply kernel update", broker)

    assert result == {
        "request_id": VALID_ID,
        "status": "pending",
        "expires_at": 1_800_000_000,
        "approval_url": f"https://broker.example.test/v1/broker/requests/{VALID_ID}/approval",
    }
    ((method, path, payload),) = broker.calls
    assert (method, path) == ("POST", "/v1/broker/requests")
    assert payload["action"] == "ct.reboot"
    assert payload["ct_id"] == 9001
    assert payload["reason"] == "Apply kernel update"
    assert payload["requester"] == "example-agent"
    public_key = payload["ssh_public_key"]
    assert public_key.startswith("ssh-ed25519 ")

    (input_file,) = _input_files(config)
    input_data = json.loads(input_file.read_text(encoding="utf-8"))
    assert input_data["request_id"] == VALID_ID
    assert input_data["action"] == "ct.reboot"
    assert input_data["public_key"] == public_key
    # The input file carries the public key only, never the private key.
    assert "PRIVATE KEY" not in input_file.read_text(encoding="utf-8")

    (key_file,) = _key_files(config)
    assert key_file.name == f"{input_data['key_id']}.key"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert key_file.read_bytes().startswith(b"-----BEGIN OPENSSH")


# ---------------------------------------------------------------------------
# Broker and response failures clean up the ephemeral key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        BrokerHTTPError(409, "broker HTTP 409: not permitted by the operate policy"),
        BrokerUnavailable("broker unavailable: URLError"),
        RuntimeError("unexpected"),
    ],
)
def test_broker_failure_removes_the_private_key(
    bridge: ApprovalBridge, config: BridgeConfig, error: Exception
) -> None:
    with pytest.raises(type(error)):
        bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker(error=error))
    assert _key_files(config) == []
    assert _input_files(config) == []


@pytest.mark.parametrize(
    "response",
    [
        ["not", "an", "object"],
        {},
        {"request_id": "not-a-uuid", "status": "pending", "expires_at": 1},
        {"request_id": VALID_ID + "\n", "status": "pending", "expires_at": 1},
        {"request_id": "../../etc/passwd", "status": "pending", "expires_at": 1},
        {"request_id": VALID_ID, "status": "approved", "expires_at": 1},
        {"request_id": VALID_ID, "status": "pending"},
        {"request_id": VALID_ID, "status": "pending", "expires_at": "1"},
        {"request_id": VALID_ID, "status": "pending", "expires_at": True},
    ],
)
def test_invalid_create_response_rejects_and_cleans_up(
    bridge: ApprovalBridge, config: BridgeConfig, response: object
) -> None:
    with pytest.raises(ValueError):
        bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker(response=response))
    assert _key_files(config) == []
    assert _input_files(config) == []


# ---------------------------------------------------------------------------
# Status reads
# ---------------------------------------------------------------------------


def test_read_status_returns_the_worker_result(bridge: ApprovalBridge, config: BridgeConfig) -> None:
    results = config.state_dir / "results"
    results.mkdir(parents=True)
    (results / f"{VALID_ID}.json").write_text(json.dumps({"status": "succeeded", "node": "ops@node-a"}))
    assert bridge.read_status(VALID_ID) == {"status": "succeeded", "node": "ops@node-a"}


def test_read_status_pending_for_active_input(bridge: ApprovalBridge, config: BridgeConfig) -> None:
    broker = FakeBroker()
    bridge.request_mutation("ct.reboot", 9001, "reason", broker)
    assert bridge.read_status(VALID_ID) == {"status": "pending"}


def test_read_status_unknown_for_missing_request(bridge: ApprovalBridge) -> None:
    assert bridge.read_status(VALID_ID) == {"status": "unknown", "error": "request not found or expired"}


@pytest.mark.parametrize("request_id", ["not-a-uuid", "../../etc/passwd", "", VALID_ID + "x"])
def test_read_status_rejects_non_canonical_ids(bridge: ApprovalBridge, request_id: str) -> None:
    with pytest.raises(ValueError, match="UUID"):
        bridge.read_status(request_id)


def test_input_directory_failure_removes_the_private_key(bridge, config) -> None:
    input_path = config.state_dir / "input"
    input_path.write_text("existing file", encoding="utf-8")
    broker = FakeBroker()
    with pytest.raises(OSError):
        bridge.request_mutation("ct.reboot", 9001, "reason", broker)
    assert len(broker.calls) == 1
    assert _key_files(config) == []
    assert input_path.read_text(encoding="utf-8") == "existing file"


def test_private_key_has_mode_600_from_creation(bridge, config, monkeypatch) -> None:
    real_open = os.open
    creation_modes = []

    def observe_open(path, flags, mode=0o777, **kwargs):
        fd = real_open(path, flags, mode, **kwargs)
        if Path(path).suffix == ".key":
            creation_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
        return fd

    monkeypatch.setattr(os, "open", observe_open)
    old_umask = os.umask(0)
    try:
        bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker())
    finally:
        os.umask(old_umask)
    assert creation_modes == [0o600]
    assert stat.S_IMODE(_key_files(config)[0].stat().st_mode) == 0o600


def test_partial_private_key_write_is_cleaned_up(bridge, config, monkeypatch) -> None:
    real_open = io.open

    class BrokenWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, data):
            self.stream.write(data[:8])
            self.stream.flush()
            raise OSError("synthetic key write failure")

    def broken_open(file, mode="r", *args, **kwargs):
        stream = real_open(file, mode, *args, **kwargs)
        return BrokenWriter(stream) if mode == "wb" else stream

    monkeypatch.setattr(io, "open", broken_open)
    broker = FakeBroker()
    with pytest.raises(OSError, match="synthetic key write failure"):
        bridge.request_mutation("ct.reboot", 9001, "reason", broker)
    assert broker.calls == []
    assert _key_files(config) == []
    assert _input_files(config) == []


def test_pending_json_is_not_visible_until_complete(bridge, config, monkeypatch) -> None:
    real_dump = json.dump
    observed = []
    final_path = config.state_dir / "input" / f"{VALID_ID}.json"

    def observe_dump(data, stream, **kwargs):
        assert not final_path.exists()
        stream.write("partial")
        stream.flush()
        assert not final_path.exists()
        observed.append(stat.S_IMODE(os.fstat(stream.fileno()).st_mode))
        stream.seek(0)
        stream.truncate()
        return real_dump(data, stream, **kwargs)

    monkeypatch.setattr(json, "dump", observe_dump)
    bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker())
    assert observed == [0o600]
    assert json.loads(final_path.read_text(encoding="utf-8"))["request_id"] == VALID_ID
    assert _input_files(config) == [final_path]


def test_partial_pending_json_and_key_are_removed(bridge, config, monkeypatch) -> None:
    def broken_dump(data, stream, **kwargs):
        stream.write("partial")
        stream.flush()
        raise OSError("synthetic pending write failure")

    monkeypatch.setattr(json, "dump", broken_dump)
    with pytest.raises(OSError, match="synthetic pending write failure"):
        bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker())
    assert _key_files(config) == []
    assert _input_files(config) == []


def test_pending_publication_failure_removes_temp_file_and_key(bridge, config, monkeypatch) -> None:
    def fail_replace(*args, **kwargs):
        raise OSError("synthetic publication failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="synthetic publication failure"):
        bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker())
    assert _key_files(config) == []
    assert _input_files(config) == []


def test_existing_key_is_not_overwritten_or_removed(bridge, config, monkeypatch) -> None:
    fixed_id = uuid.UUID(VALID_ID)
    monkeypatch.setattr(bridge_module.uuid, "uuid4", lambda: fixed_id)
    keys = config.state_dir / "keys"
    keys.mkdir()
    existing = keys / f"{fixed_id.hex}.key"
    existing.write_text("owned by another request", encoding="utf-8")
    broker = FakeBroker()
    with pytest.raises(FileExistsError):
        bridge.request_mutation("ct.reboot", 9001, "reason", broker)
    assert existing.read_text(encoding="utf-8") == "owned by another request"
    assert broker.calls == []


def test_result_handoff_never_looks_like_a_missing_request(bridge, config, monkeypatch) -> None:
    bridge.request_mutation("ct.reboot", 9001, "reason", FakeBroker())
    input_path = config.state_dir / "input" / f"{VALID_ID}.json"
    result_path = config.state_dir / "results" / f"{VALID_ID}.json"
    real_exists = Path.exists
    published = False

    def handoff_exists(path):
        nonlocal published
        if path == result_path and not published:
            # The result check happened just before the worker published and
            # removed its input. Preserve that observed False for this call.
            published = True
            result_path.parent.mkdir()
            result_path.write_text(json.dumps({"status": "denied"}), encoding="utf-8")
            input_path.unlink()
            return False
        return real_exists(path)

    monkeypatch.setattr(Path, "exists", handoff_exists)
    first = bridge.read_status(VALID_ID)
    assert first in ({"status": "pending"}, {"status": "denied"})
    assert bridge.read_status(VALID_ID) == {"status": "denied"}
