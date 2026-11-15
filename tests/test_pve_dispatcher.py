"""Synthetic tests for the target-side dispatcher and its durable claim store.

No test opens an SSH connection, calls ``pct`` or touches a real host: the
command runner is injected, the policy and keys are temporary files, and the
claim store lives in a temporary directory.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sqlite3
import threading
import time
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from privilege_broker.pve.common import canonical_json, execution_arguments_digest
from privilege_broker.pve.dispatcher import (
    AUDIENCE,
    MAX_REQUEST_BYTES,
    NOT_ON_THIS_NODE_EXIT,
    CapabilityLease,
    ClaimStore,
    DispatchConfig,
    dispatch,
    main,
    parse_request,
    read_request,
    verify_lease,
)
from privilege_broker.pve.worker import WorkerConfig, process_pending_once

NOW = 1_800_000_000
CT_ID = 9001
LEASE_ID = "6f1d2c3a-4b5a-4c6d-8e9f-0a1b2c3d4e5f"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _binding(action: str, ct_id: int = CT_ID) -> dict[str, str]:
    return {
        "canonicalization": "pve-execution-v1",
        "arguments_digest": execution_arguments_digest(action, ct_id, "pve-execution-v1"),
    }


def _lease_claims(action: str = "ct.start", ct_id: int = CT_ID, **overrides: object) -> dict:
    claims: dict = {
        "lease_id": overrides.pop("lease_id", LEASE_ID),
        "profile": overrides.pop("profile", "operate"),
        "action_classes": overrides.pop("action_classes", [action]),
        "target_cts": overrides.pop("target_cts", [ct_id]),
        "approval_id": "approval-1",
        "approval_binding": {"canonicalization": "pve-approval-v1", "request_digest": "aa" * 32},
        "execution_binding": overrides.pop("execution_binding", _binding(action, ct_id)),
        "audience": overrides.pop("audience", AUDIENCE),
        "policy_version": "pve-operate-v1",
        "issued_at": overrides.pop("issued_at", NOW),
        "expires_at": overrides.pop("expires_at", NOW + 60),
        "max_dispatches": overrides.pop("max_dispatches", 1),
    }
    claims.update(overrides)
    return claims


def _request_json(
    private_key: Ed25519PrivateKey, action: str = "ct.start", ct_id: int = CT_ID, **overrides: object
) -> str:
    claims = _lease_claims(action, ct_id, **overrides)
    signature = private_key.sign(canonical_json(claims).encode("ascii"))
    return json.dumps({"action": action, "ct_id": ct_id, "lease": claims, "signature": _b64(signature)})


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def config(tmp_path: Path, private_key: Ed25519PrivateKey) -> DispatchConfig:
    policy = {
        "version": 2,
        "grants": {
            action: [CT_ID]
            for action in ("ct.start", "ct.stop", "ct.reboot", "ct.shutdown", "ct.snapshot", "ct.snapshot_prune")
        },
        "snapshot_retention_days": 7,
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    key_path = tmp_path / "lease.pub"
    key_path.write_bytes(
        private_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH) + b" synthetic\n"
    )
    lxc = tmp_path / "lxc"
    lxc.mkdir()
    (lxc / f"{CT_ID}.conf").write_text("", encoding="utf-8")
    return DispatchConfig(
        policy_path=policy_path,
        lease_public_key_path=key_path,
        claim_db_path=tmp_path / "claims.sqlite3",
        lxc_conf_dir=lxc,
        sudo_path="/usr/bin/sudo",
        pct_path="/usr/sbin/pct",
        command_timeout=30,
    )


class Runner:
    """Records argv and answers scripted outcomes."""

    def __init__(self, outcomes: list[object] | None = None) -> None:
        self._outcomes = list(outcomes or [CompletedProcess([], 0, "ok", "")])
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> CompletedProcess[str]:
        self.calls.append((list(argv), dict(kwargs)))
        outcome = self._outcomes.pop(0) if len(self._outcomes) > 1 else self._outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _run(config: DispatchConfig, private_key: Ed25519PrivateKey, text: str, runner: Runner, *, now: int = NOW):
    request = parse_request(text)
    return dispatch(request, config, public_key=private_key.public_key(), now=now, runner=runner)


def test_each_fixed_action_dispatches_once(config: DispatchConfig, private_key: Ed25519PrivateKey) -> None:
    runner = Runner()
    actions = ("ct.start", "ct.stop", "ct.reboot", "ct.shutdown")
    for index, action in enumerate(actions):
        # One lease authorizes exactly one dispatch, so each action needs its own.
        lease_id = f"6f1d2c3a-4b5a-4c6d-8e9f-0a1b2c3d4e{index:02d}"
        exit_code, output = _run(
            config, private_key, _request_json(private_key, action, lease_id=lease_id), runner, now=NOW
        )
        assert exit_code == 0
        assert output == {"exit_code": 0, "stdout": "ok", "stderr": "", "lease_id": lease_id}
    assert [call[0] for call in runner.calls] == [
        ["/usr/bin/sudo", "/usr/sbin/pct", "start", "9001"],
        ["/usr/bin/sudo", "/usr/sbin/pct", "stop", "9001"],
        ["/usr/bin/sudo", "/usr/sbin/pct", "reboot", "9001"],
        ["/usr/bin/sudo", "/usr/sbin/pct", "shutdown", "9001"],
    ]
    # Never a shell, and the timeout is the configured bound.
    assert all(call[1]["shell"] is False for call in runner.calls)
    assert all(call[1]["timeout"] == 30 for call in runner.calls)


def test_snapshot_name_is_derived_from_the_lease(config: DispatchConfig, private_key: Ed25519PrivateKey) -> None:
    runner = Runner()
    _run(config, private_key, _request_json(private_key, "ct.snapshot"), runner)
    argv = runner.calls[0][0]
    assert argv[:4] == ["/usr/bin/sudo", "/usr/sbin/pct", "snapshot", "9001"]
    assert argv[4] == "broker-6f1d2c3a4b5a"


def test_snapshot_requires_a_uuid_lease_id(config: DispatchConfig, private_key: Ed25519PrivateKey) -> None:
    runner = Runner()
    claims = _lease_claims("ct.snapshot", lease_id="not-a-uuid")
    signature = private_key.sign(canonical_json(claims).encode("ascii"))
    text = json.dumps({"action": "ct.snapshot", "ct_id": CT_ID, "lease": claims, "signature": _b64(signature)})
    exit_code, output = _run(config, private_key, text, runner)
    assert exit_code == 1
    assert output == {"error": "snapshot requires a lowercase UUID lease_id", "exit_code": 1}
    assert runner.calls == []


def test_policy_refuses_an_ungranted_target(config: DispatchConfig, private_key: Ed25519PrivateKey) -> None:
    config.policy_path.write_text(
        json.dumps({"version": 2, "grants": {"ct.start": [9999]}, "snapshot_retention_days": 7}), encoding="utf-8"
    )
    runner = Runner()
    exit_code, output = _run(config, private_key, _request_json(private_key), runner)
    assert exit_code == 1
    assert output["error"] == "action is not permitted by the dispatcher policy"
    assert runner.calls == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"expires_at": NOW - 1}, "lease has expired"),
        ({"issued_at": NOW + 5}, "lease is not yet valid"),
        ({"expires_at": NOW + 301}, "lease TTL exceeds the dispatcher maximum"),
        ({"audience": "someone-else"}, "lease audience is invalid"),
        ({"profile": "observe"}, "lease profile is not allowed to execute"),
        ({"max_dispatches": 2}, "lease max_dispatches must be 1"),
        ({"action_classes": ["ct.stop"]}, "action is not within the lease scope"),
        ({"target_cts": [7777]}, "target is not within the lease scope"),
        ({"approval_binding": {"canonicalization": "wrong", "request_digest": "aa" * 32}}, "approval binding"),
        (
            {"execution_binding": {"canonicalization": "pve-execution-v1", "arguments_digest": "bb" * 32}},
            "execution digest",
        ),
    ],
)
def test_lease_refusals(config, private_key, overrides, message) -> None:
    runner = Runner()
    exit_code, output = _run(config, private_key, _request_json(private_key, **overrides), runner)
    assert exit_code == 1
    assert message in output["error"]
    assert runner.calls == []


def test_tampered_signature_is_refused(config: DispatchConfig, private_key: Ed25519PrivateKey) -> None:
    claims = _lease_claims()
    forged = private_key.sign(canonical_json({**claims, "issued_at": NOW - 1}).encode("ascii"))
    text = json.dumps({"action": "ct.start", "ct_id": CT_ID, "lease": claims, "signature": _b64(forged)})
    runner = Runner()
    exit_code, output = _run(config, private_key, text, runner)
    assert exit_code == 1
    assert output["error"] == "lease signature is invalid"
    assert runner.calls == []


def test_wrong_node_reports_before_claiming(config: DispatchConfig, private_key: Ed25519PrivateKey) -> None:
    (config.lxc_conf_dir / f"{CT_ID}.conf").unlink()
    runner = Runner()
    exit_code, output = _run(config, private_key, _request_json(private_key), runner)
    assert exit_code == NOT_ON_THIS_NODE_EXIT
    assert output == {"error": "not_on_this_node", "exit_code": NOT_ON_THIS_NODE_EXIT}
    assert runner.calls == []
    # No authority is consumed: the next node can still claim the lease.
    assert not config.claim_db_path.exists()


def test_replay_returns_the_stored_result_without_executing(config, private_key) -> None:
    runner = Runner([CompletedProcess([], 0, "done", "")])
    text = _request_json(private_key)
    assert _run(config, private_key, text, runner)[0] == 0
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "SUCCEEDED"

    # A fresh store instance models a restarted dispatcher process.
    replay = Runner([])
    with ClaimStore(config.claim_db_path) as store:
        exit_code, output = dispatch(
            parse_request(text), config, public_key=private_key.public_key(), now=NOW + 1, store=store, runner=replay
        )
    assert exit_code == 0
    assert output == {"exit_code": 0, "stdout": "done", "stderr": "", "lease_id": LEASE_ID, "replayed": True}
    assert replay.calls == []


def test_concurrent_dispatch_executes_exactly_once(config, private_key) -> None:
    runner = Runner([CompletedProcess([], 0, "done", "")])
    text = _request_json(private_key)
    barrier = threading.Barrier(2)
    results: list[tuple[int, dict]] = []
    lock = threading.Lock()

    def worker() -> None:
        with ClaimStore(config.claim_db_path) as store:
            barrier.wait(timeout=5)
            outcome = dispatch(
                parse_request(text), config, public_key=private_key.public_key(), now=NOW, store=store, runner=runner
            )
            with lock:
                results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert len(runner.calls) == 1
    assert len(results) == 2
    executed = [output for code, output in results if code == 0]
    refused = [output for code, output in results if code == 1]
    assert len(executed) + len(refused) == 2
    assert refused == [] or refused[0]["error"] == "previous dispatch outcome is unknown; it is never retried"


def test_stored_claim_for_other_arguments_is_unknown(config, private_key) -> None:
    with ClaimStore(config.claim_db_path) as store:
        store.claim(LEASE_ID, "ct.stop", CT_ID, NOW)
        store.complete(LEASE_ID, "SUCCEEDED", 0, "done", "", NOW)
    runner = Runner([])
    exit_code, output = _run(config, private_key, _request_json(private_key, "ct.start"), runner)
    assert exit_code == 1
    assert output == {
        "error": "previous dispatch outcome is unknown; it is never retried",
        "exit_code": 1,
        "outcome": "unknown",
    }
    assert runner.calls == []


def test_crashed_claim_becomes_unknown_and_never_runs(config, private_key) -> None:
    with ClaimStore(config.claim_db_path) as store:
        assert store.claim(LEASE_ID, "ct.start", CT_ID, NOW) == ("CLAIMED", None)
    runner = Runner([])
    exit_code, output = _run(config, private_key, _request_json(private_key), runner)
    assert exit_code == 1
    assert "unknown" in output["error"]
    assert runner.calls == []
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "UNKNOWN"


def test_failed_command_is_stored_and_replayed(config, private_key) -> None:
    runner = Runner([CompletedProcess([], 2, "partial", "boom")])
    text = _request_json(private_key)
    exit_code, output = _run(config, private_key, text, runner)
    assert exit_code == 2
    assert output["exit_code"] == 2 and output["stderr"] == "boom"

    replay = Runner([])
    with ClaimStore(config.claim_db_path) as store:
        replay_code, replayed = dispatch(
            parse_request(text), config, public_key=private_key.public_key(), now=NOW + 1, store=store, runner=replay
        )
    assert replay_code == 2
    assert replayed["replayed"] is True and replayed["stdout"] == "partial"
    assert replay.calls == []


def test_timeout_is_unknown_and_never_retried(config, private_key) -> None:
    from subprocess import TimeoutExpired

    runner = Runner([TimeoutExpired(cmd="pct", timeout=30)])
    text = _request_json(private_key)
    exit_code, output = _run(config, private_key, text, runner)
    assert exit_code == 1
    assert "timed out" in output["error"]
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "UNKNOWN"

    replay = Runner([])
    exit_code, output = _run(config, private_key, text, replay, now=NOW + 1)
    assert exit_code == 1
    assert replay.calls == []


def test_spawn_failure_is_stored_as_failed(config, private_key) -> None:
    runner = Runner([OSError("no such binary")])
    exit_code, output = _run(config, private_key, _request_json(private_key), runner)
    assert exit_code == 1
    assert output["error"] == "operation could not be started"
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "FAILED"


def test_stored_output_is_truncated(config, private_key) -> None:
    runner = Runner([CompletedProcess([], 0, "x" * 5000, "y" * 5000)])
    _run(config, private_key, _request_json(private_key), runner)
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None
    assert len(stored["stdout"].encode()) == 4096
    assert len(stored["stderr"].encode()) == 4096


def test_claim_store_is_private(config) -> None:
    with ClaimStore(config.claim_db_path) as store:
        assert store.synchronous_level == 2
    assert config.claim_db_path.stat().st_mode & 0o777 == 0o600
    assert config.claim_db_path.parent.stat().st_mode & 0o777 == 0o700


def test_claim_is_committed_before_the_command_runs(config, private_key) -> None:
    observed: list[str] = []

    def inspecting_runner(argv, **kwargs):
        # A separate connection models another reader after a crash; seeing the
        # claim here proves the claim was committed before the operation started.
        with sqlite3.connect(config.claim_db_path) as other:
            row = other.execute("SELECT state FROM dispatch_claims WHERE lease_id = ?", (LEASE_ID,)).fetchone()
        observed.append(row[0] if row else "MISSING")
        return CompletedProcess(argv, 0, "done", "")

    exit_code, _ = _run(config, private_key, _request_json(private_key), inspecting_runner)
    assert exit_code == 0
    assert observed == ["CLAIMED"]


def test_separate_claim_databases_do_not_share_claims(config, private_key, tmp_path) -> None:
    """Documents the deployment requirement, not a happy path.

    Each node keeps local state, so the same lease can run once per database.
    The supported model is exactly one eligible executor per target; the WAL
    database is never shared across hosts.
    """
    other = DispatchConfig(
        policy_path=config.policy_path,
        lease_public_key_path=config.lease_public_key_path,
        claim_db_path=tmp_path / "other-node" / "claims.sqlite3",
        lxc_conf_dir=config.lxc_conf_dir,
    )
    runner = Runner([CompletedProcess([], 0, "done", "")])
    assert _run(config, private_key, _request_json(private_key), runner)[0] == 0
    assert _run(other, private_key, _request_json(private_key), runner)[0] == 0
    assert len(runner.calls) == 2


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("not json", "not valid JSON"),
        (json.dumps([]), "must be a JSON object"),
        (json.dumps({"action": "ct.destroy", "ct_id": 1}), "supported typed action"),
        (json.dumps({"action": "ct.start", "ct_id": "1"}), "positive integer"),
        (json.dumps({"action": "ct.start", "ct_id": 1}), "lease is required"),
    ],
)
def test_parse_request_refusals(document, message) -> None:
    with pytest.raises(ValueError, match=message):
        parse_request(document)


def test_main_prints_one_json_document(config, private_key) -> None:
    runner = Runner([CompletedProcess([], 0, "ok", "")])
    out = io.StringIO()
    exit_code = main(
        [
            "--policy",
            str(config.policy_path),
            "--lease-public-key",
            str(config.lease_public_key_path),
            "--claim-db",
            str(config.claim_db_path),
            "--lxc-conf-dir",
            str(config.lxc_conf_dir),
        ],
        stdin=io.StringIO(_request_json(private_key)),
        stdout=out,
        runner=runner,
        clock=lambda: NOW,
    )
    assert exit_code == 0
    assert json.loads(out.getvalue()) == {
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "lease_id": LEASE_ID,
    }
    assert runner.calls[0][0] == ["/usr/bin/sudo", "/usr/sbin/pct", "start", "9001"]


def test_main_rejects_a_bad_public_key(config, private_key) -> None:
    config.lease_public_key_path.write_text("not a key", encoding="utf-8")
    out = io.StringIO()
    exit_code = main(
        [
            "--policy",
            str(config.policy_path),
            "--lease-public-key",
            str(config.lease_public_key_path),
            "--claim-db",
            str(config.claim_db_path),
            "--lxc-conf-dir",
            str(config.lxc_conf_dir),
        ],
        stdin=io.StringIO(_request_json(private_key)),
        stdout=out,
        runner=Runner([]),
        clock=lambda: NOW,
    )
    assert exit_code == 1
    assert json.loads(out.getvalue())["error"] == "lease public key is unreadable"


class _BrokenStore:
    """Claim store whose chosen operation fails after the runner returns."""

    def __init__(self, *, fail_claim: bool = False, fail_complete: bool = False) -> None:
        self.fail_claim = fail_claim
        self.fail_complete = fail_complete
        self.claim_calls = 0
        self.complete_calls = 0
        self.states: list[str] = []

    def claim(self, lease_id: str, action: str, ct_id: int, now: int):
        self.claim_calls += 1
        if self.fail_claim:
            raise sqlite3.OperationalError("database or disk is full")
        return ("CLAIMED", None)

    def complete(self, lease_id: str, state: str, exit_code, stdout: str, stderr: str, now: int) -> None:
        self.complete_calls += 1
        self.states.append(state)
        if self.fail_complete:
            raise sqlite3.OperationalError("database or disk is full")

    def close(self) -> None:
        raise AssertionError("an injected store is owned by its caller")


def test_claim_store_failure_before_execution_refuses_without_running(config, private_key) -> None:
    store = _BrokenStore(fail_claim=True)
    runner = Runner([])
    exit_code, output = dispatch(
        parse_request(_request_json(private_key)),
        config,
        public_key=private_key.public_key(),
        now=NOW,
        store=store,
        runner=runner,
    )
    assert exit_code == 1
    assert output == {"error": "claim store is unavailable; nothing was executed", "exit_code": 1}
    assert runner.calls == []
    assert store.claim_calls == 1


def test_result_persistence_failure_reports_uncertainty_without_reexecution(config, private_key) -> None:
    class FailingComplete(ClaimStore):
        def complete(self, *args: object, **kwargs: object) -> None:
            raise sqlite3.OperationalError("database or disk is full")

    runner = Runner([CompletedProcess([], 0, "done", "")])
    with FailingComplete(config.claim_db_path) as store:
        exit_code, output = dispatch(
            parse_request(_request_json(private_key)),
            config,
            public_key=private_key.public_key(),
            now=NOW,
            store=store,
            runner=runner,
        )
    assert exit_code == 1
    assert output == {
        "error": "operation ran but its result could not be recorded; outcome unknown",
        "exit_code": 1,
        "outcome": "unknown",
    }
    assert len(runner.calls) == 1

    # The durable row is still CLAIMED, so a later presentation cannot execute.
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "CLAIMED"
    replay = Runner([])
    replay_code, replay_output = _run(config, private_key, _request_json(private_key), replay, now=NOW + 1)
    assert replay_code == 1
    assert "unknown" in replay_output["error"]
    assert replay.calls == []


def test_unusable_claim_store_is_refused_without_running(config, private_key) -> None:
    config.claim_db_path.parent.mkdir(parents=True, exist_ok=True)
    config.claim_db_path.write_bytes(b"not a sqlite database")
    runner = Runner([])
    out = io.StringIO()
    exit_code = main(
        [
            "--policy",
            str(config.policy_path),
            "--lease-public-key",
            str(config.lease_public_key_path),
            "--claim-db",
            str(config.claim_db_path),
            "--lxc-conf-dir",
            str(config.lxc_conf_dir),
        ],
        stdin=io.StringIO(_request_json(private_key)),
        stdout=out,
        runner=runner,
        clock=lambda: NOW,
    )
    assert exit_code == 1
    assert json.loads(out.getvalue()) == {
        "error": "claim store is unavailable; nothing was executed",
        "exit_code": 1,
    }
    assert runner.calls == []


def test_undecodable_output_is_unknown_and_never_reexecuted(config, private_key) -> None:
    def bad_output(argv, **kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    text = _request_json(private_key)
    exit_code, output = _run(config, private_key, text, bad_output)
    assert exit_code == 1
    assert output == {
        "error": "command output could not be decoded; outcome unknown",
        "exit_code": 1,
        "outcome": "unknown",
    }
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "UNKNOWN"
    replay = Runner([])
    assert _run(config, private_key, text, replay, now=NOW + 1)[0] == 1
    assert replay.calls == []


def test_oversized_request_is_refused_without_running(config, private_key) -> None:
    oversized = "x" * (MAX_REQUEST_BYTES + 1)
    runner = Runner([])
    out = io.StringIO()
    exit_code = main(
        [
            "--policy",
            str(config.policy_path),
            "--lease-public-key",
            str(config.lease_public_key_path),
            "--claim-db",
            str(config.claim_db_path),
            "--lxc-conf-dir",
            str(config.lxc_conf_dir),
        ],
        stdin=io.StringIO(oversized),
        stdout=out,
        runner=runner,
        clock=lambda: NOW,
    )
    assert exit_code == 1
    assert json.loads(out.getvalue()) == {"error": "request is too large", "exit_code": 1}
    assert runner.calls == []
    assert not config.claim_db_path.exists()


def test_file_redirected_stdin_dispatches(config, private_key, tmp_path) -> None:
    request_file = tmp_path / "request.json"
    request_file.write_text(_request_json(private_key), encoding="utf-8")
    runner = Runner([CompletedProcess([], 0, "ok", "")])
    out = io.StringIO()
    with request_file.open(encoding="utf-8") as source:
        exit_code = main(
            [
                "--policy",
                str(config.policy_path),
                "--lease-public-key",
                str(config.lease_public_key_path),
                "--claim-db",
                str(config.claim_db_path),
                "--lxc-conf-dir",
                str(config.lxc_conf_dir),
            ],
            stdin=source,
            stdout=out,
            runner=runner,
            clock=lambda: NOW,
        )
    assert exit_code == 0
    assert json.loads(out.getvalue())["stdout"] == "ok"
    assert runner.calls[0][0] == ["/usr/bin/sudo", "/usr/sbin/pct", "start", "9001"]


def test_deeply_nested_request_is_refused(config, private_key) -> None:
    # Beyond Python's recursion limit the decoder raises RecursionError, which
    # parse_request normalises to the fixed invalid-JSON refusal.
    deepest = "[" * 200000 + "0" + "]" * 200000
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_request(deepest)
    # Within the 64 KiB stdin bound the decoder depth is interpreter-dependent:
    # CPython 3.11 raises RecursionError, newer decoders return a list. Both are
    # fixed refusals, and neither may reach a claim or the runner.
    nested = "[" * 5000 + "0" + "]" * 5000
    runner = Runner([])
    out = io.StringIO()
    exit_code = main(
        [
            "--policy",
            str(config.policy_path),
            "--lease-public-key",
            str(config.lease_public_key_path),
            "--claim-db",
            str(config.claim_db_path),
            "--lxc-conf-dir",
            str(config.lxc_conf_dir),
        ],
        stdin=io.StringIO(nested),
        stdout=out,
        runner=runner,
        clock=lambda: NOW,
    )
    assert exit_code == 1
    refusal = json.loads(out.getvalue())
    assert refusal["exit_code"] == 1
    assert refusal["error"] in {"request is not valid JSON", "request must be a JSON object"}
    assert runner.calls == []
    assert not config.claim_db_path.exists()


def test_shallow_array_is_refused_by_shape() -> None:
    with pytest.raises(ValueError, match="must be a JSON object"):
        parse_request("[1]")


def test_dev_null_stdin_is_refused_with_json(config, private_key) -> None:
    runner = Runner([])
    out = io.StringIO()
    with open(os.devnull, encoding="utf-8") as source:
        exit_code = main(
            [
                "--policy",
                str(config.policy_path),
                "--lease-public-key",
                str(config.lease_public_key_path),
                "--claim-db",
                str(config.claim_db_path),
                "--lxc-conf-dir",
                str(config.lxc_conf_dir),
            ],
            stdin=source,
            stdout=out,
            runner=runner,
            clock=lambda: NOW,
        )
    assert exit_code == 1
    assert json.loads(out.getvalue()) == {"error": "request is not valid JSON", "exit_code": 1}
    assert runner.calls == []
    assert not config.claim_db_path.exists()


def test_stalled_request_read_times_out() -> None:
    read_end, write_end = os.pipe()
    try:
        with os.fdopen(read_end) as source:
            with pytest.raises(ValueError, match="request read timed out"):
                read_request(source, timeout=0.1)
    finally:
        os.close(write_end)


class _WorkerBroker:
    """Minimal broker: approved status, one lease and one certificate."""

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        if path.endswith("/lease"):
            return {"lease_id": LEASE_ID, "signature": "AAAA", "audience": AUDIENCE}
        if path.endswith("/certificate"):
            return {"status": "issued", "certificate": "SYNTHETIC-CERT"}
        return {"status": "approved"}


class _WorkerSsh:
    def __init__(self, result: CompletedProcess[str]) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: object) -> CompletedProcess[str]:
        self.calls.append(list(argv))
        return self.result


def _worker_config(state_dir: Path) -> WorkerConfig:
    return WorkerConfig(
        state_dir=state_dir,
        targets=("ops@node-a", "ops@node-b"),
        ssh_port=22,
        known_hosts_path=str(state_dir / "known_hosts"),
        ssh_timeout=30,
    )


def _worker_input(state_dir: Path) -> None:
    (state_dir / "input").mkdir(parents=True, exist_ok=True)
    (state_dir / "keys").mkdir(exist_ok=True)
    (state_dir / "keys" / "key-1.key").write_text("synthetic", encoding="utf-8")
    (state_dir / "input" / "req-1.json").write_text(
        json.dumps(
            {
                "action": "ct.start",
                "ct_id": CT_ID,
                "reason": "synthetic",
                "public_key": "ssh-ed25519 AAAA synthetic",
                "key_id": "key-1",
                "expires_at": NOW + 300,
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize("failure", ["timeout", "persistence"])
def test_worker_publishes_unknown_from_real_dispatcher_output(config, private_key, tmp_path, failure) -> None:
    class FailingComplete(ClaimStore):
        def complete(self, *args: object, **kwargs: object) -> None:
            raise sqlite3.OperationalError("database or disk is full")

    from subprocess import TimeoutExpired

    runner: object = (
        (lambda argv, **kwargs: (_ for _ in ()).throw(TimeoutExpired(cmd="pct", timeout=30)))
        if failure == "timeout"
        else Runner([CompletedProcess([], 0, "done", "")])
    )
    store = FailingComplete(config.claim_db_path) if failure == "persistence" else None
    exit_code, output = dispatch(
        parse_request(_request_json(private_key)),
        config,
        public_key=private_key.public_key(),
        now=NOW,
        store=store,
        runner=runner,
    )
    assert exit_code == 1
    assert output["outcome"] == "unknown"

    state_dir = tmp_path / f"worker-{failure}"
    worker_config = _worker_config(state_dir)
    _worker_input(state_dir)
    ssh = _WorkerSsh(CompletedProcess([], exit_code, json.dumps(output), ""))
    process_pending_once(_WorkerBroker(), worker_config, now=NOW, ssh_runner=ssh)

    result = json.loads((state_dir / "results" / "req-1.json").read_text(encoding="utf-8"))
    assert result["status"] == "unknown"
    assert result["dispatcher_outcome"] == "unknown"
    # One node only: uncertainty never triggers failover or a redispatch.
    assert len(ssh.calls) == 1


def _snapshot_listing(entries: list[tuple[str, float]]) -> str:
    lines = []
    for name, timestamp in entries:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        lines.append(f"  `-> {name}  {stamp}  synthetic")
    lines.append("  `-> current                                  ")
    return "\n".join(lines) + "\n"


OLD = NOW - 10 * 86400
RECENT = NOW - 2 * 86400


def test_prune_deletes_only_old_broker_snapshots(config, private_key) -> None:
    config = replace(config, command_timeout=180)
    listing = _snapshot_listing(
        [("broker-aaaaaaaaaaaa", OLD), ("broker-bbbbbbbbbbbb", RECENT), ("manual-backup", OLD)]
    )
    runner = Runner([CompletedProcess([], 0, listing, "")] + [CompletedProcess([], 0, "", "")] * 3)
    exit_code, output = _run(config, private_key, _request_json(private_key, "ct.snapshot_prune"), runner)
    assert exit_code == 0
    assert output["deleted"] == ["broker-aaaaaaaaaaaa"]
    # Unrelated snapshots are never candidates and never reported.
    assert output["kept"] == ["broker-bbbbbbbbbbbb"]
    assert "manual-backup" not in json.dumps(output)
    assert output["failed"] == [] and output["kept_over_limit"] == []
    assert runner.calls[0][0] == ["/usr/bin/sudo", "/usr/sbin/pct", "listsnapshot", "9001"]
    assert [call[0] for call in runner.calls[1:]] == [
        ["/usr/bin/sudo", "/usr/sbin/pct", "delsnapshot", "9001", "broker-aaaaaaaaaaaa"]
    ]


def test_prune_retention_comes_from_policy(config, private_key) -> None:
    config = replace(config, command_timeout=180)
    config.policy_path.write_text(
        json.dumps({"version": 2, "grants": {"ct.snapshot_prune": [CT_ID]}, "snapshot_retention_days": 3}),
        encoding="utf-8",
    )
    listing = _snapshot_listing([("broker-aaaaaaaaaaaa", NOW - 4 * 86400), ("broker-bbbbbbbbbbbb", RECENT)])
    runner = Runner([CompletedProcess([], 0, listing, "")] + [CompletedProcess([], 0, "", "")] * 2)
    exit_code, output = _run(config, private_key, _request_json(private_key, "ct.snapshot_prune"), runner)
    assert exit_code == 0
    assert output["deleted"] == ["broker-aaaaaaaaaaaa"]
    assert output["kept"] == ["broker-bbbbbbbbbbbb"]


def test_prune_listing_failure_is_final(config, private_key) -> None:
    config = replace(config, command_timeout=180)
    runner = Runner([CompletedProcess([], 2, "", "listing failed")])
    exit_code, output = _run(config, private_key, _request_json(private_key, "ct.snapshot_prune"), runner)
    assert exit_code == 2
    assert output["stderr"] == "listing failed"
    assert len(runner.calls) == 1
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "FAILED"


def test_prune_budget_exhaustion_marks_the_remainder(config, private_key, monkeypatch) -> None:
    config = replace(config, command_timeout=180)
    from privilege_broker.pve import dispatcher as dispatcher_module

    monkeypatch.setattr(dispatcher_module, "PRUNE_MIN_DELETE_SECONDS", 10_000)
    listing = _snapshot_listing([("broker-aaaaaaaaaaaa", OLD), ("broker-bbbbbbbbbbbb", OLD)])
    runner = Runner([CompletedProcess([], 0, listing, "")])
    exit_code, output = _run(config, private_key, _request_json(private_key, "ct.snapshot_prune"), runner)
    assert exit_code == 0
    assert output["deleted"] == []
    assert output["kept_over_limit"] == ["broker-aaaaaaaaaaaa", "broker-bbbbbbbbbbbb"]
    assert len(runner.calls) == 1


def test_prune_delete_timeout_is_unknown(config, private_key) -> None:
    config = replace(config, command_timeout=180)
    from subprocess import TimeoutExpired

    listing = _snapshot_listing([("broker-aaaaaaaaaaaa", OLD), ("broker-bbbbbbbbbbbb", OLD)])
    runner = Runner(
        [CompletedProcess([], 0, listing, ""), TimeoutExpired(cmd="pct", timeout=30), CompletedProcess([], 0, "", "")]
    )
    exit_code, output = _run(config, private_key, _request_json(private_key, "ct.snapshot_prune"), runner)
    assert exit_code == 1
    assert output["outcome"] == "unknown"
    assert output["failed"] == ["broker-aaaaaaaaaaaa"]
    assert output["kept_over_limit"] == ["broker-bbbbbbbbbbbb"]
    with ClaimStore(config.claim_db_path) as store:
        stored = store.get(LEASE_ID)
    assert stored is not None and stored["state"] == "UNKNOWN"


def test_prune_replay_returns_the_stored_report(config, private_key) -> None:
    config = replace(config, command_timeout=180)
    listing = _snapshot_listing([("broker-aaaaaaaaaaaa", OLD)])
    runner = Runner([CompletedProcess([], 0, listing, ""), CompletedProcess([], 0, "", "")])
    text = _request_json(private_key, "ct.snapshot_prune")
    first_exit, first = _run(config, private_key, text, runner)
    assert first_exit == 0

    replay = Runner([])
    with ClaimStore(config.claim_db_path) as store:
        second_exit, second = dispatch(
            parse_request(text), config, public_key=private_key.public_key(), now=NOW + 1, store=store, runner=replay
        )
    assert second_exit == 0
    assert second["replayed"] is True
    assert json.loads(second["stdout"]) == json.loads(first["stdout"])
    assert replay.calls == []


def test_verify_lease_returns_claims(private_key) -> None:
    claims = _lease_claims()
    signature = private_key.sign(canonical_json(claims).encode("ascii"))
    lease = CapabilityLease(**claims, signature=signature)
    verified = verify_lease(lease, private_key.public_key(), now=NOW)
    assert verified["lease_id"] == LEASE_ID
    assert verified["action_classes"] == ["ct.start"]
