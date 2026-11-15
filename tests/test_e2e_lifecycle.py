"""Synthetic end-to-end lifecycle: approval to observable outcome.

Real components: the FastAPI approval service over HTTP, SQLite storage, the
Ed25519 lease signer, the ssh-keygen CA, the agent bridge, the mTLS-shaped
worker and the dispatcher as a *fresh process* reading JSON on stdin.

Substituted effects only: the mTLS transport is an ASGI adapter, SSH is a local
subprocess invocation, and ``pct`` is a synthetic script. No network, PVE host
or real credential is used.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient

from privilege_broker.pve import authorization as broker
from privilege_broker.pve import service as svc
from privilege_broker.pve.bridge import ApprovalBridge, BridgeConfig
from privilege_broker.pve.client import BrokerHTTPError
from privilege_broker.pve.dispatcher import DispatchConfig
from privilege_broker.pve.worker import WorkerConfig, process_pending_once

SOURCE = "192.0.2.10"
CT_ID = 9001
POLICY = broker.Policy(
    grants={action: frozenset({CT_ID}) for action in ("ct.start", "ct.reboot", "ct.snapshot_prune")},
    snapshot_retention_days=7,
)

FAKE_PCT = """\
import json, os, sys, time
log = os.environ["FAKE_PCT_LOG"]
with open(log, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ.get("FAKE_PCT_SLEEP"):
    time.sleep(float(os.environ["FAKE_PCT_SLEEP"]))
if sys.argv[1] == "listsnapshot":
    print("  `-> current                                  ")
    sys.exit(0)
print("ok")
"""


class Extractor:
    """Stands in for the TLS frontend: one verified mTLS identity."""

    def __init__(self, identity: str = "agent-demo", source: str = SOURCE) -> None:
        self._client = broker.VerifiedClient(identity=identity, source_ip=source)

    def extract(self, request: object = None):  # noqa: ARG002
        return self._client


class SoftwareAuthenticator:
    """A real software WebAuthn authenticator: P-256 key, signed assertions."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)

    def credential(
        self, challenge: str, *, registration: bool = False, uv: bool = True, up: bool = True, count: int = 1
    ) -> dict[str, Any]:
        client_data = json.dumps(
            {
                "type": "webauthn.create" if registration else "webauthn.get",
                "challenge": challenge,
                "origin": "https://broker.example.test",
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        flags = int(up) | (0x04 if uv else 0) | (0x40 if registration else 0)
        auth_data = hashlib.sha256(b"broker.example.test").digest() + bytes([flags]) + count.to_bytes(4, "big")
        response: dict[str, Any] = {"clientDataJSON": base64.urlsafe_b64encode(client_data).rstrip(b"=").decode()}
        if registration:
            numbers = self.key.public_key().public_numbers()
            cose = cbor2.dumps(
                {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
            )
            auth_data += bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose
            response["attestationObject"] = (
                base64.urlsafe_b64encode(cbor2.dumps({"fmt": "none", "authData": auth_data, "attStmt": {}}))
                .rstrip(b"=")
                .decode()
            )
        else:
            response["authenticatorData"] = base64.urlsafe_b64encode(auth_data).rstrip(b"=").decode()
            response["signature"] = (
                base64.urlsafe_b64encode(
                    self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
                )
                .rstrip(b"=")
                .decode()
            )
        encoded_id = base64.urlsafe_b64encode(self.credential_id).rstrip(b"=").decode()
        return {"id": encoded_id, "rawId": encoded_id, "type": "public-key", "response": response}


class AsgiBrokerClient:
    """BrokerClient-compatible transport over the real ASGI app."""

    def __init__(self, client: TestClient) -> None:
        self._client = client
        self.calls: list[str] = []

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        self.calls.append(f"{method} {path}")
        response = self._client.request(method, path, json=payload)
        if response.status_code >= 400:
            raise BrokerHTTPError(response.status_code, f"broker HTTP {response.status_code}")
        return response.json()


class DispatcherSsh:
    """Runs the real dispatcher in a fresh process; substitutes only SSH."""

    def __init__(self, config: DispatchConfig, *, env: dict[str, str] | None = None, tamper=None) -> None:
        self._config = config
        self._env = env
        self._tamper = tamper
        self.calls = 0
        self.payloads: list[str] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls += 1
        payload = kwargs["input"]
        if self._tamper is not None:
            payload = self._tamper(payload)
        self.payloads.append(payload)
        environment = dict(os.environ)
        if self._env:
            environment.update(self._env)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "privilege_broker.pve.dispatcher",
                "--policy",
                str(self._config.policy_path),
                "--lease-public-key",
                str(self._config.lease_public_key_path),
                "--claim-db",
                str(self._config.claim_db_path),
                "--lxc-conf-dir",
                str(self._config.lxc_conf_dir),
                "--sudo-path",
                self._config.sudo_path,
                "--pct-path",
                self._config.pct_path,
                "--command-timeout",
                str(self._config.command_timeout),
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=kwargs["timeout"],
            env=environment,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        return subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)

    def replay(self, index: int = 0) -> subprocess.CompletedProcess[str]:
        """Present the same payload to another fresh dispatcher process."""
        return self([], input=self.payloads[index], capture_output=True, text=True, timeout=120)


@pytest.fixture
def environment(tmp_path: Path):
    ca_key = tmp_path / "ca-key.pem"
    ca_key.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    ca_key.chmod(0o600)
    signer = broker.LeaseSigner.generate()
    store = svc.BrokerStore(tmp_path / "broker.sqlite3", "enrollment-key")
    cert_signer = svc.CaCertificateSigner(
        str(ca_key), builder=broker.CertificateCommandBuilder(broker.CertificatePolicy(source=f"{SOURCE}/32"))
    )
    app = svc.create_broker_app(
        policy=POLICY,
        store=store,
        signer=signer,
        extractor=Extractor(),
        rp_id="broker.example.test",
        origin="https://broker.example.test",
        enrollment_key="enrollment-key",
        enrollment_enabled=True,
        cert_signer=cert_signer,
    )

    state = tmp_path / "agent-state"
    state.mkdir()
    (state / "input").mkdir()
    (state / "keys").mkdir()
    policy_path = tmp_path / "dispatcher-policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "version": 2,
                "grants": {"ct.start": [CT_ID], "ct.reboot": [CT_ID], "ct.snapshot_prune": [CT_ID]},
                "snapshot_retention_days": 7,
            }
        ),
        encoding="utf-8",
    )
    lease_key = tmp_path / "lease.pub"
    lease_key.write_text(signer.public_key_openssh() + "\n", encoding="utf-8")
    lxc = tmp_path / "lxc"
    lxc.mkdir()
    (lxc / f"{CT_ID}.conf").write_text("", encoding="utf-8")
    pct = tmp_path / "fake_pct.py"
    pct.write_text(FAKE_PCT, encoding="utf-8")
    log = tmp_path / "pct.log"

    dispatch_config = DispatchConfig(
        policy_path=policy_path,
        lease_public_key_path=lease_key,
        claim_db_path=tmp_path / "claims" / "claims.sqlite3",
        lxc_conf_dir=lxc,
        sudo_path=sys.executable,
        pct_path=str(pct),
        command_timeout=10,
    )
    worker_config = WorkerConfig(
        state_dir=state,
        targets=("ops@node-a",),
        ssh_port=22,
        known_hosts_path=str(tmp_path / "known_hosts"),
        ssh_timeout=60,
        expiry_grace=0,
    )
    with TestClient(app) as client:
        authenticator = _enroll(client)
        yield {
            "authenticator": authenticator,
            "client": client,
            "store": store,
            "state": state,
            "dispatch": dispatch_config,
            "worker": worker_config,
            "log": log,
            "bridge": ApprovalBridge(
                BridgeConfig(state_dir=state, public_url="https://broker.example.test", requester="agent-demo")
            ),
        }
    store.close()


def _create(env: dict, action: str = "ct.start", client=None) -> str:
    transport = client or AsgiBrokerClient(env["client"])
    env["bridge"].request_mutation(action, CT_ID, "synthetic end-to-end", transport)
    inputs = sorted((env["state"] / "input").glob("*.json"))
    assert len(inputs) == 1
    return inputs[0].stem


def _enroll(client: TestClient) -> SoftwareAuthenticator:
    authenticator = SoftwareAuthenticator()
    created = client.post(
        "/v1/broker/enrollments",
        json={"operator": "operator"},
        headers={"X-Broker-Enrollment-Key": "enrollment-key"},
    )
    assert created.status_code == 201, created.text
    enrollment_id = created.json()["enrollment_id"]
    challenge = client.get(f"/v1/broker/enrollments/{enrollment_id}/options").json()["challenge"]
    completed = client.post(
        f"/v1/broker/enrollments/{enrollment_id}/complete",
        json={"credential": authenticator.credential(challenge, registration=True, count=0)},
    )
    assert completed.status_code == 200, completed.text
    return authenticator


def _approve(env: dict, request_id: str) -> None:
    client = env["client"]
    options = client.get(f"/v1/broker/requests/{request_id}/approval/options")
    assert options.status_code == 200
    credential = env["authenticator"].credential(options.json()["challenge"])
    response = client.post(f"/v1/broker/requests/{request_id}/approval", json={"credential": credential})
    assert response.status_code == 200, response.text


def _pct_calls(log: Path) -> list[list[str]]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def _result(env: dict, request_id: str) -> dict:
    return json.loads((env["state"] / "results" / f"{request_id}.json").read_text(encoding="utf-8"))


def test_allowed_request_is_approved_dispatched_and_reported(environment) -> None:
    request_id = _create(environment)
    _approve(environment, request_id)

    ssh = DispatcherSsh(environment["dispatch"], env={"FAKE_PCT_LOG": str(environment["log"])})
    process_pending_once(
        AsgiBrokerClient(environment["client"]), environment["worker"], ssh_runner=ssh, now=int(time.time())
    )

    result = _result(environment, request_id)
    assert result["status"] == "succeeded"
    assert result["dispatcher_lease_id"]
    assert _pct_calls(environment["log"]) == [["start", str(CT_ID)]]
    assert ssh.calls == 1
    assert not (environment["state"] / "input" / f"{request_id}.json").exists()
    leftovers = [p.name for p in (environment["state"] / "keys").iterdir()]
    assert leftovers == []
    status = environment["client"].get(f"/v1/broker/requests/{request_id}")
    assert status.json()["status"] == "approved"
    assert status.json()["execution_state"] == "not_executed"


def test_denied_request_never_dispatches(environment) -> None:
    request_id = _create(environment)
    assert environment["client"].post(f"/v1/broker/requests/{request_id}/denial").status_code == 200

    ssh = DispatcherSsh(environment["dispatch"], env={"FAKE_PCT_LOG": str(environment["log"])})
    process_pending_once(
        AsgiBrokerClient(environment["client"]), environment["worker"], ssh_runner=ssh, now=int(time.time())
    )

    assert _result(environment, request_id) == {"status": "denied"}
    assert ssh.calls == 0
    assert _pct_calls(environment["log"]) == []


def test_tampered_lease_is_refused_without_execution(environment) -> None:
    request_id = _create(environment)
    _approve(environment, request_id)

    def tamper(payload: str) -> str:
        # Reboot is granted by policy but outside this lease's scope, so the
        # refusal proves the lease, not the policy, is the boundary.
        document = json.loads(payload)
        document["action"] = "ct.reboot"
        return json.dumps(document)

    ssh = DispatcherSsh(environment["dispatch"], env={"FAKE_PCT_LOG": str(environment["log"])}, tamper=tamper)
    process_pending_once(
        AsgiBrokerClient(environment["client"]), environment["worker"], ssh_runner=ssh, now=int(time.time())
    )

    result = _result(environment, request_id)
    # The dispatcher refuses before executing; the worker reports the refusal.
    assert result["status"] == "failed"
    # The lease, not the policy, refuses: the bound digest and scope disagree.
    refusal = result.get("dispatcher_error", "")
    assert "digest" in refusal or "scope" in refusal
    assert _pct_calls(environment["log"]) == []
    assert ssh.calls == 1


def test_uncertain_dispatch_is_reported_and_never_replayed(environment) -> None:
    request_id = _create(environment)
    _approve(environment, request_id)
    environment["dispatch"] = replace(environment["dispatch"], command_timeout=1)

    ssh = DispatcherSsh(environment["dispatch"], env={"FAKE_PCT_LOG": str(environment["log"]), "FAKE_PCT_SLEEP": "5"})
    broker_client = AsgiBrokerClient(environment["client"])
    process_pending_once(broker_client, environment["worker"], ssh_runner=ssh, now=int(time.time()))

    result = _result(environment, request_id)
    assert result["status"] == "unknown"
    first_calls = _pct_calls(environment["log"])
    assert first_calls == [["start", str(CT_ID)]]

    # A later poll cannot execute it again.
    process_pending_once(broker_client, environment["worker"], ssh_runner=ssh, now=int(time.time()) + 1)
    assert _pct_calls(environment["log"]) == first_calls
    assert ssh.calls == 1

    # Nor can a *fresh dispatcher process* re-present the retained payload:
    # the durable claim now answers UNKNOWN instead of executing.
    replayed = ssh.replay(0)
    assert replayed.returncode == 1
    assert "unknown" in replayed.stdout
    assert _pct_calls(environment["log"]) == first_calls


def test_expired_grant_is_not_dispatched(environment) -> None:
    request_id = _create(environment)
    _approve(environment, request_id)
    pending = json.loads((environment["state"] / "input" / f"{request_id}.json").read_text(encoding="utf-8"))

    ssh = DispatcherSsh(environment["dispatch"], env={"FAKE_PCT_LOG": str(environment["log"])})
    process_pending_once(
        AsgiBrokerClient(environment["client"]),
        environment["worker"],
        ssh_runner=ssh,
        now=pending["expires_at"] + 1,
    )

    assert _result(environment, request_id) == {"status": "expired"}
    assert ssh.calls == 0
    assert _pct_calls(environment["log"]) == []


def test_concurrent_workers_execute_the_lease_once(environment) -> None:
    request_id = _create(environment)
    _approve(environment, request_id)

    started = threading.Barrier(2)
    # One poller per state directory: each worker gets its own copy of the
    # pending request and key, while the broker request and claim DB are shared.
    workers = []
    for name in ("worker-a", "worker-b"):
        state_dir = environment["state"].parent / name
        (state_dir / "input").mkdir(parents=True)
        (state_dir / "keys").mkdir()
        for staged in (environment["state"] / "input").iterdir():
            (state_dir / "input" / staged.name).write_bytes(staged.read_bytes())
        for staged in (environment["state"] / "keys").iterdir():
            (state_dir / "keys" / staged.name).write_bytes(staged.read_bytes())
        workers.append(replace(environment["worker"], state_dir=state_dir))

    def run(worker) -> dict:
        client = AsgiBrokerClient(TestClient(environment["client"].app))
        ssh = DispatcherSsh(environment["dispatch"], env={"FAKE_PCT_LOG": str(environment["log"])})
        started.wait(timeout=10)
        process_pending_once(client, worker, ssh_runner=ssh, now=int(time.time()))
        return json.loads((worker.state_dir / "results" / f"{request_id}.json").read_text(encoding="utf-8"))

    # result() re-raises any worker exception and proves both workers finished.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, worker) for worker in workers]
        outcomes = [future.result(timeout=60) for future in futures]

    assert len(outcomes) == 2
    assert _pct_calls(environment["log"]) == [["start", str(CT_ID)]]
    statuses = sorted(outcome["status"] for outcome in outcomes)
    assert statuses.count("succeeded") == 1
    assert set(statuses) & {"error", "failed", "unknown"}
