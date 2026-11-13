"""Tests for the poll-and-dispatch worker.

All broker and SSH effects are fakes; no test opens a socket, contacts PVE or
touches a real host. State lives in a temporary directory.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from privilege_broker.pve.client import BrokerHTTPError, BrokerUnavailable
from privilege_broker.pve.worker import WorkerConfig, process_pending_once

NOW = 1_800_000_000
PUB_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyMaterialForTestsOnly"
FAKE_CERT = "FAKE-CERT-MATERIAL"
FAKE_KEY_CONTENT = "fake-key-content"
_NOT_HERE = json.dumps({"error": "not_on_this_node", "exit_code": 3})

LEASE = {
    "lease_id": "lease-1",
    "signature": "AAAA",
    "audience": "pve-privileged-executor",
    "policy_version": "pve-operate-v1",
    "issued_at": 0,
    "expires_at": 9_999_999_999,
    "max_dispatches": 1,
    "approval_id": "approval-001",
    "approval_binding": {"canonicalization": "pve-approval-v1", "request_digest": "aa" * 32},
    "execution_binding": {"canonicalization": "pve-execution-v1", "arguments_digest": "bb" * 32},
}


class FakeBroker:
    def __init__(
        self,
        status: str,
        *,
        lease_error: Exception | None = None,
        cert_error: Exception | None = None,
        status_response: dict | None = None,
    ) -> None:
        self._status = status
        self._lease_error = lease_error
        self._cert_error = cert_error
        self._status_response = status_response
        self.calls = 0
        self.fetched_lease = 0
        self.fetched_cert = 0
        self.cert_payloads: list[dict | None] = []

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        self.calls += 1
        if method == "GET" and path.endswith("/lease"):
            self.fetched_lease += 1
            if self._lease_error is not None:
                raise self._lease_error
            return dict(LEASE)
        if method == "POST" and path.endswith("/certificate"):
            self.fetched_cert += 1
            self.cert_payloads.append(payload)
            if self._cert_error is not None:
                raise self._cert_error
            return {"status": "issued", "certificate": FAKE_CERT}
        if method == "GET":
            return self._status_response if self._status_response is not None else {"status": self._status}
        raise AssertionError(f"unexpected {method} {path}")


class UnavailableBroker:
    """Every call is a transient failure."""

    def __init__(self) -> None:
        self.calls = 0

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        self.calls += 1
        raise BrokerUnavailable("broker unavailable: URLError")


class ScriptedSsh:
    """Answers successive SSH calls from scripted (returncode, stdout) pairs."""

    def __init__(self, outcomes: list[tuple[int, str] | subprocess.TimeoutExpired]) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> CompletedProcess[str]:
        self.calls.append((argv, kwargs))
        if not self._outcomes:
            raise AssertionError("no scripted SSH outcome left")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, subprocess.TimeoutExpired):
            raise outcome
        code, stdout = outcome
        return CompletedProcess(argv, code, stdout, "")


@pytest.fixture
def config(tmp_path: Path) -> WorkerConfig:
    return WorkerConfig(
        state_dir=tmp_path,
        targets=("ops@node-a", "ops@node-b"),
        ssh_port=8922,
        known_hosts_path=str(tmp_path / "known_hosts"),
        poll_interval=5,
        ssh_timeout=240,
        expiry_grace=60,
    )


def _write_input(config: WorkerConfig, request_id: str = "req-1", *, expires_at: int = NOW + 300) -> Path:
    input_dir = config.state_dir / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    input_file = input_dir / f"{request_id}.json"
    input_file.write_text(
        json.dumps(
            {
                "action": "ct.start",
                "ct_id": 9001,
                "reason": "synthetic",
                "public_key": PUB_KEY,
                "key_id": "key-1",
                "expires_at": expires_at,
            }
        ),
        encoding="utf-8",
    )
    keys = config.state_dir / "keys"
    keys.mkdir(exist_ok=True)
    key_path = keys / "key-1.key"
    key_path.write_text(FAKE_KEY_CONTENT)
    key_path.chmod(0o600)
    return input_file


def _result(config: WorkerConfig, request_id: str = "req-1") -> dict:
    return json.loads((config.state_dir / "results" / f"{request_id}.json").read_text(encoding="utf-8"))


def _key_and_cert_exist(config: WorkerConfig) -> bool:
    keys = config.state_dir / "keys"
    return (keys / "key-1.key").exists() or (keys / "key-1-cert.pub").exists()


# ---------------------------------------------------------------------------
# Dispatch classification
# ---------------------------------------------------------------------------


def test_approved_request_dispatches_and_succeeds(config: WorkerConfig) -> None:
    input_file = _write_input(config)
    ssh = ScriptedSsh([(0, json.dumps({"exit_code": 0, "lease_id": "lease-1", "replayed": False}))])
    broker = FakeBroker("approved")

    process_pending_once(broker, config, now=NOW, ssh_runner=ssh)

    result = _result(config)
    assert result["status"] == "succeeded"
    assert result["node"] == "ops@node-a"
    assert result["exit_code"] == 0
    assert result["dispatcher_lease_id"] == "lease-1"
    assert not input_file.exists()
    assert not _key_and_cert_exist(config)

    # The dispatcher wire contract on stdin is unchanged: action, ct_id, the
    # lease claims without the signature, and the signature separately.
    ((argv, kwargs),) = ssh.calls
    payload = json.loads(kwargs["input"])
    assert payload["action"] == "ct.start"
    assert payload["ct_id"] == 9001
    assert payload["signature"] == "AAAA"
    assert "signature" not in payload["lease"]
    assert payload["lease"]["lease_id"] == "lease-1"
    assert kwargs["timeout"] == 240

    # The certificate request carries only the public key; the broker picks the serial.
    assert broker.cert_payloads == [{"ssh_public_key": PUB_KEY}]

    # Fixed, non-interactive SSH options with the configured trust material.
    assert argv[0] == "ssh"
    assert "-F" in argv and "/dev/null" in argv
    assert f"CertificateFile={config.state_dir / 'keys' / 'key-1-cert.pub'}" in argv
    fixed_options = (
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "RequestTTY=no",
        "ConnectTimeout=10",
        "StrictHostKeyChecking=yes",
    )
    for option in fixed_options:
        assert option in argv
    assert f"UserKnownHostsFile={config.known_hosts_path}" in argv
    assert argv[argv.index("-p") + 1] == "8922"
    assert argv[-1] == "ops@node-a"


def test_nonzero_dispatcher_exit_is_failed_not_dispatched(config: WorkerConfig) -> None:
    _write_input(config)
    ssh = ScriptedSsh([(255, "CT 9001 already running\n")])
    process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ssh)
    result = _result(config)
    assert result["status"] == "failed"
    assert result["exit_code"] == 255
    # Non-JSON stdout lifts no dispatcher fields; the exit code is the verdict.
    assert not [key for key in result if key.startswith("dispatcher_")]


def test_ssh_timeout_is_unknown_and_never_retried(config: WorkerConfig) -> None:
    _write_input(config)
    ssh = ScriptedSsh([subprocess.TimeoutExpired(cmd="ssh", timeout=240)])
    process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ssh)
    result = _result(config)
    assert result["status"] == "unknown"
    assert result["node"] == "ops@node-a"
    assert "240" in result["error"]
    # A lost reply is not a reason to dispatch again: exactly one attempt.
    assert len(ssh.calls) == 1


def test_wrong_node_moves_to_the_next_target_with_the_same_certificate(config: WorkerConfig) -> None:
    _write_input(config)
    ssh = ScriptedSsh([(3, _NOT_HERE), (0, json.dumps({"exit_code": 0, "lease_id": "lease-1"}))])
    process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ssh)

    result = _result(config)
    assert result["status"] == "succeeded"
    assert result["node"] == "ops@node-b"
    assert [call[0][-1] for call in ssh.calls] == ["ops@node-a", "ops@node-b"]
    # Same key, certificate, payload and options; only the target differs.
    assert ssh.calls[0][0][:-1] == ssh.calls[1][0][:-1]
    assert ssh.calls[0][1]["input"] == ssh.calls[1][1]["input"]


def test_exit_3_without_the_dispatcher_marker_is_final(config: WorkerConfig) -> None:
    """pct exit codes pass through the dispatcher; only its JSON says wrong node."""
    _write_input(config)
    ssh = ScriptedSsh([(3, json.dumps({"exit_code": 3, "stdout": "", "stderr": "x"}))])
    process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ssh)
    result = _result(config)
    assert result["status"] == "failed"
    assert result["node"] == "ops@node-a"
    assert len(ssh.calls) == 1


def test_no_hosting_node_is_an_error(config: WorkerConfig) -> None:
    _write_input(config)
    ssh = ScriptedSsh([(3, _NOT_HERE), (3, _NOT_HERE)])
    process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ssh)
    assert _result(config) == {"status": "error", "error": "container not found on any configured node"}
    assert not _key_and_cert_exist(config)


# ---------------------------------------------------------------------------
# Terminal broker decisions and transient failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["denied", "cancelled", "expired"])
def test_terminal_broker_status_never_dispatches(config: WorkerConfig, status: str) -> None:
    input_file = _write_input(config)
    ssh = ScriptedSsh([])
    process_pending_once(FakeBroker(status), config, now=NOW, ssh_runner=ssh)
    assert _result(config) == {"status": status}
    assert ssh.calls == []
    assert not input_file.exists()


def test_unavailable_status_poll_preserves_the_request(config: WorkerConfig) -> None:
    input_file = _write_input(config)
    ssh = ScriptedSsh([])
    broker = UnavailableBroker()
    process_pending_once(broker, config, now=NOW, ssh_runner=ssh)
    assert not (config.state_dir / "results" / "req-1.json").exists()
    assert input_file.exists()
    assert ssh.calls == []


def test_broker_unavailable_before_dispatch_is_retried_on_the_next_poll(config: WorkerConfig) -> None:
    """A transient lease/certificate failure keeps the request; nothing ran yet."""
    input_file = _write_input(config)
    broker = FakeBroker("approved", lease_error=BrokerUnavailable("broker unavailable: URLError"))
    process_pending_once(broker, config, now=NOW, ssh_runner=ScriptedSsh([]))
    assert not (config.state_dir / "results" / "req-1.json").exists()
    assert input_file.exists()

    # Second poll: the broker answers, dispatch proceeds.
    broker2 = FakeBroker("approved")
    ssh = ScriptedSsh([(0, "")])
    process_pending_once(broker2, config, now=NOW, ssh_runner=ssh)
    assert _result(config)["status"] == "succeeded"
    assert broker.fetched_lease == 1 and broker2.fetched_lease == 1


def test_a_repeated_certificate_fetch_is_a_terminal_error(config: WorkerConfig) -> None:
    """HTTP 409 after a lost certificate reply is terminal: no re-mint, no replay."""
    _write_input(config)
    ssh = ScriptedSsh([])
    broker = FakeBroker(
        "approved",
        cert_error=BrokerHTTPError(409, "broker HTTP 409: certificate has already been fetched"),
    )
    process_pending_once(broker, config, now=NOW, ssh_runner=ssh)
    result = _result(config)
    assert result["status"] == "error"
    assert "already been fetched" in result["error"]
    assert broker.fetched_cert == 1
    assert ssh.calls == []


# ---------------------------------------------------------------------------
# Local expiry bounds polling without asking the broker
# ---------------------------------------------------------------------------


def test_past_deadline_plus_grace_expires_locally_without_a_broker_call(config: WorkerConfig) -> None:
    _write_input(config, expires_at=NOW - 61)
    broker = FakeBroker("approved")
    process_pending_once(broker, config, now=NOW, ssh_runner=ScriptedSsh([]))
    assert _result(config) == {"status": "expired"}
    assert broker.calls == 0


def test_within_grace_period_still_asks_the_broker(config: WorkerConfig) -> None:
    _write_input(config, expires_at=NOW - 50)
    broker = FakeBroker("pending")
    process_pending_once(broker, config, now=NOW, ssh_runner=ScriptedSsh([]))
    assert broker.calls == 1
    assert not (config.state_dir / "results" / "req-1.json").exists()


# ---------------------------------------------------------------------------
# Malformed or completed input
# ---------------------------------------------------------------------------


def test_malformed_input_file_is_preserved_and_skipped(config: WorkerConfig) -> None:
    input_dir = config.state_dir / "input"
    input_dir.mkdir(parents=True)
    bad = input_dir / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    broker = FakeBroker("approved")
    process_pending_once(broker, config, now=NOW, ssh_runner=ScriptedSsh([]))
    assert bad.exists()
    assert broker.calls == 0
    assert not (config.state_dir / "results" / "bad.json").exists()


def test_existing_result_skips_the_input(config: WorkerConfig) -> None:
    _write_input(config)
    results = config.state_dir / "results"
    results.mkdir(parents=True)
    (results / "req-1.json").write_text(json.dumps({"status": "succeeded"}))
    broker = FakeBroker("approved")
    process_pending_once(broker, config, now=NOW, ssh_runner=ScriptedSsh([]))
    assert broker.calls == 0


def test_missing_input_dir_is_a_noop(config: WorkerConfig) -> None:
    process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ScriptedSsh([]))


def test_status_response_without_status_field_is_preserved(config: WorkerConfig) -> None:
    _write_input(config)
    broker = FakeBroker("approved", status_response={})
    process_pending_once(broker, config, now=NOW, ssh_runner=ScriptedSsh([]))
    assert not (config.state_dir / "results" / "req-1.json").exists()


# ---------------------------------------------------------------------------
# Secrets never reach results or logs
# ---------------------------------------------------------------------------


def test_result_and_logs_carry_no_key_or_certificate_material(
    config: WorkerConfig, caplog: pytest.LogCaptureFixture
) -> None:
    _write_input(config)
    ssh = ScriptedSsh([(0, json.dumps({"exit_code": 0, "lease_id": "lease-1", "stdout": "ok"}))])
    with caplog.at_level(logging.INFO, logger="privilege_broker.pve.worker"):
        process_pending_once(FakeBroker("approved"), config, now=NOW, ssh_runner=ssh)
    result_text = json.dumps(_result(config))
    assert FAKE_KEY_CONTENT not in result_text
    assert FAKE_CERT not in result_text
    assert PUB_KEY not in result_text
    assert FAKE_KEY_CONTENT not in caplog.text
    assert FAKE_CERT not in caplog.text


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def test_config_requires_targets_and_trust(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="targets"):
        WorkerConfig(state_dir=tmp_path, targets=(), ssh_port=22, known_hosts_path="kh")
    with pytest.raises(ValueError, match="ssh_port"):
        WorkerConfig(state_dir=tmp_path, targets=("ops@node-a",), ssh_port=0, known_hosts_path="kh")
    with pytest.raises(ValueError, match="ssh_port"):
        WorkerConfig(
            state_dir=tmp_path,
            targets=("ops@node-a",),
            ssh_port=True,
            known_hosts_path="kh",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="known_hosts_path"):
        WorkerConfig(state_dir=tmp_path, targets=("ops@node-a",), ssh_port=22, known_hosts_path="")
    with pytest.raises(ValueError, match="positive"):
        WorkerConfig(state_dir=tmp_path, targets=("ops@node-a",), ssh_port=22, known_hosts_path="kh", ssh_timeout=0)


def test_config_accepts_a_list_of_targets_and_string_state_dir(tmp_path: Path) -> None:
    config = WorkerConfig(
        state_dir=str(tmp_path),  # type: ignore[arg-type]
        targets=["ops@node-a"],
        ssh_port=22,
        known_hosts_path="kh",
    )
    assert config.targets == ("ops@node-a",)
    assert config.state_dir == tmp_path
