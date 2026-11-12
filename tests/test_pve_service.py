"""Regression tests for the PVE SSH broker service.

Covers: default mTLS rejection, browser-only approval, altered public key,
wrong client identity, denial, approval, lease scope, one-time fetch gate,
source isolation, and audit integrity.
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from privilege_broker.pve import authorization as broker
from privilege_broker.pve import service as svc

if TYPE_CHECKING:
    from fastapi import FastAPI as _FastAPI

    from privilege_broker.pve.authorization import LeaseSigner as _LeaseSigner
    from privilege_broker.pve.authorization import RejectingExtractor as _RejectingExtractor
    from privilege_broker.pve.service import BrokerPasskey as _BrokerPasskey
    from privilege_broker.pve.service import BrokerStore as _BrokerStore
    from privilege_broker.pve.service import RegistrationResult as _RegistrationResult

# ---------------------------------------------------------------------------
# Real Ed25519 public keys for tests
# ---------------------------------------------------------------------------

_VALID_PUB_KEY = (
    Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
)
_ALT_PUB_KEY = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
_THIRD_PUB_KEY = (
    Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


_CERT_BUILDER = broker.CertificateCommandBuilder(broker.CertificatePolicy(source="192.0.2.0/24"))


@pytest.fixture
def resources():
    with ExitStack() as stack:
        yield stack


@pytest.fixture
def client_factory(resources):
    return lambda app: resources.enter_context(TestClient(app))


@pytest.fixture
def ca_key_path(tmp_path: Path) -> str:
    """Root-only Ed25519 CA private key for ssh-keygen signing tests."""
    key_path = tmp_path / "ca-key.pem"
    priv = Ed25519PrivateKey.generate()
    pem_bytes = priv.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    key_path.write_bytes(pem_bytes)
    key_path.chmod(0o600)
    return str(key_path)


# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------

_ENROLLMENT_KEY = "enrollment-key"
_POLICY = broker.Policy(
    grants={
        action: frozenset({9001})
        for action in ("ct.reboot", "ct.start", "ct.stop", "ct.shutdown", "ct.snapshot", "ct.snapshot_prune")
    },
    snapshot_retention_days=7,
)


class FixedIdentityExtractor:
    """Stands in for mTLS verification: every request is this identity."""

    def __init__(self, source_ip: str, identity: str = "agent-demo") -> None:
        self._client = broker.VerifiedClient(identity=identity, source_ip=source_ip)

    def extract(self, request: object = None) -> object:  # noqa: ARG002
        return self._client


class FakeVerifier:
    """Fake WebAuthn assertion verifier for tests."""

    def verify(self, credential: dict[str, object], challenge: bytes, passkey: _BrokerPasskey) -> tuple[str, int]:
        assert challenge
        if credential.get("proof") != "verified":
            raise ValueError("WebAuthn verification failed")
        return passkey.operator, passkey.sign_count + 1


class FakeRegistrationVerifier:
    """Fake WebAuthn registration verifier for tests."""

    def verify(self, credential: dict[str, object], challenge: bytes) -> _RegistrationResult:
        assert challenge
        if credential.get("proof") != "registered":
            raise ValueError("WebAuthn registration failed")
        return svc.RegistrationResult("new-credential", b"new-public-key", 1)


# ---------------------------------------------------------------------------
# Canonical request body helper
# ---------------------------------------------------------------------------


def _body(
    action: str = "ct.reboot",
    ct_id: int = 9001,
    reason: str = "Apply kernel update",
    requester: str = "test-operator",
    ssh_public_key: str = _VALID_PUB_KEY,
    self_reported_hostname: str = "agent-demo",
) -> dict[str, object]:
    return {
        "action": action,
        "ct_id": ct_id,
        "reason": reason,
        "requester": requester,
        "ssh_public_key": ssh_public_key,
        "self_reported_hostname": self_reported_hostname,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path, resources) -> _BrokerStore:
    s = svc.BrokerStore(tmp_path / "broker.sqlite3", _ENROLLMENT_KEY)
    resources.callback(s.close)
    s.add_passkey(svc.BrokerPasskey("credential-1", "operator", b"public-key", 0))
    return s


@pytest.fixture
def empty_store(tmp_path: Path, resources) -> _BrokerStore:
    store = svc.BrokerStore(tmp_path / "empty.sqlite3", _ENROLLMENT_KEY)
    resources.callback(store.close)
    return store


@pytest.fixture
def signer() -> _LeaseSigner:
    return broker.LeaseSigner.generate()


@pytest.fixture
def extractor() -> FixedIdentityExtractor:
    return FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.10")


@pytest.fixture
def rejecting_extractor() -> _RejectingExtractor:
    return broker.RejectingExtractor()


@pytest.fixture
def alt_extractor() -> FixedIdentityExtractor:
    """Different mTLS identity for source-isolation tests."""
    return FixedIdentityExtractor(identity="intruder", source_ip="198.51.100.99")


@pytest.fixture
def app(store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor) -> _FastAPI:
    return svc.create_broker_app(
        policy=_POLICY,
        store=store,
        signer=signer,
        extractor=extractor,
        rp_id="broker.example.test",
        origin="https://broker.example.test",
        enrollment_key="enrollment-key",
        enrollment_enabled=True,
        verifier=FakeVerifier(),
        registration_verifier=FakeRegistrationVerifier(),
    )


@pytest.fixture
def client(app: _FastAPI, client_factory) -> TestClient:
    return client_factory(app)


# ===================================================================
# 1. Default mTLS rejection
# ===================================================================


@pytest.mark.parametrize("target", [True, 9001.0, "9001", None, []])
def test_http_target_must_be_a_real_integer(client, target):
    assert client.post("/v1/broker/requests", json={**_body(), "ct_id": target}).status_code == 422


@pytest.mark.parametrize("missing", ["store", "signer"])
def test_no_implicit_store_or_signer(store, signer, missing):
    arguments = {"store": store, "signer": signer, "policy": _POLICY}
    arguments[missing] = None
    with pytest.raises(ValueError, match="explicit store and lease signer"):
        svc.create_broker_app(**arguments)


def test_import_does_not_honor_legacy_autostart_or_load_private_state():
    result = subprocess.run(
        [sys.executable, "-I", "-c", "import privilege_broker.pve.service"],
        env={"PVE_BROKER_AUTOSTART": "1"},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


class TestDefaultMtlsRejection:
    """Every mTLS endpoint must reject when no verified extractor is supplied."""

    @pytest.fixture
    def app_no_mtls(self, store: _BrokerStore, signer: _LeaseSigner) -> _FastAPI:
        return svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=None,  # defaults to RejectingExtractor
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )

    @pytest.fixture
    def client_no_mtls(self, app_no_mtls: _FastAPI, client_factory) -> TestClient:
        return client_factory(app_no_mtls)

    def test_create_request_rejected(self, client_no_mtls: TestClient) -> None:
        resp = client_no_mtls.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 403
        assert "mTLS" in resp.json()["detail"]

    def test_get_request_rejected(self, client_no_mtls: TestClient) -> None:
        resp = client_no_mtls.get("/v1/broker/requests/nonexistent")
        assert resp.status_code == 403

    def test_fetch_lease_rejected(self, client_no_mtls: TestClient) -> None:
        resp = client_no_mtls.get("/v1/broker/requests/nonexistent/lease")
        assert resp.status_code == 403

    def test_certificate_fetch_rejected(self, client_no_mtls: TestClient) -> None:
        resp = client_no_mtls.post(
            "/v1/broker/requests/nonexistent/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert resp.status_code == 403

    def test_cancel_rejected(self, client_no_mtls: TestClient) -> None:
        resp = client_no_mtls.post("/v1/broker/requests/nonexistent/cancel")
        assert resp.status_code == 403


# ===================================================================
# 2. Browser cannot fetch lease or certificate
# ===================================================================


class TestBrowserCannotFetchLease:
    """Browser/WebAuthn endpoints never return lease or certificate data."""

    def test_approval_page_shows_status_only(self, client: TestClient) -> None:
        # Create a request first
        resp = client.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]

        # Approval page should exist and show details
        page_resp = client.get(f"/v1/broker/requests/{request_id}/approval")
        assert page_resp.status_code == 200
        assert "SSH public key fingerprint" in page_resp.text
        assert "lease" not in page_resp.text.lower()
        assert "# noqa" not in page_resp.text

    def test_approve_returns_only_status(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        # Begin authentication
        client.get(f"/v1/broker/requests/{request_id}/approval/options")

        # Approve
        approve_resp = client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        assert approve_resp.status_code == 200
        data = approve_resp.json()
        assert data == {"status": "approved"}
        # Browser must never receive lease data
        assert "lease" not in json.dumps(data)

    def test_deny_returns_only_status(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        deny_resp = client.post(f"/v1/broker/requests/{request_id}/denial")
        assert deny_resp.status_code == 200
        assert deny_resp.json() == {"status": "denied"}


# ===================================================================
# 3. Altered public key
# ===================================================================


class TestAlteredPublicKey:
    """Certificate fetch must reject a public key different from the original."""

    def test_different_key_fingerprint_rejected(self, client: TestClient, store: _BrokerStore) -> None:
        # Create request with _VALID_PUB_KEY
        resp = client.post("/v1/broker/requests", json=_body(ssh_public_key=_VALID_PUB_KEY))
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]

        # Approve
        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        # Try cert fetch with _ALT_PUB_KEY
        cert_resp = client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _ALT_PUB_KEY},
        )
        assert cert_resp.status_code == 409
        assert "fingerprint" in cert_resp.json()["detail"]


# ===================================================================
# 4. Wrong client identity
# ===================================================================


class TestWrongClientIdentity:
    """Non-matching mTLS identity must be rejected for lease/certificate fetch."""

    def _create_and_approve(self, store: _BrokerStore, signer: _LeaseSigner, client_factory) -> tuple[str, TestClient]:
        """Helper: create a request and approve it using the primary identity."""
        ext = FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.10")
        app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=ext,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            enrollment_key="enrollment-key",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        c = client_factory(app)
        resp = c.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]

        # Approve
        c.get(f"/v1/broker/requests/{request_id}/approval/options")
        c.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        return request_id, c

    def test_lease_fetch_with_wrong_identity(self, store: _BrokerStore, signer: _LeaseSigner, client_factory) -> None:
        request_id, _ = self._create_and_approve(store, signer, client_factory=client_factory)

        # Try fetching lease with a different identity
        intruder_ext = FixedIdentityExtractor(identity="intruder", source_ip="198.51.100.99")
        intruder_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=intruder_ext,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        intruder_client = client_factory(intruder_app)
        lease_resp = intruder_client.get(f"/v1/broker/requests/{request_id}/lease")
        assert lease_resp.status_code == 409
        assert "original requester" in lease_resp.json()["detail"]

    def test_certificate_fetch_with_wrong_identity(
        self, store: _BrokerStore, signer: _LeaseSigner, client_factory
    ) -> None:
        request_id, _ = self._create_and_approve(store, signer, client_factory=client_factory)

        intruder_ext = FixedIdentityExtractor(identity="intruder", source_ip="198.51.100.99")
        intruder_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=intruder_ext,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        intruder_client = client_factory(intruder_app)
        cert_resp = intruder_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert cert_resp.status_code == 409
        assert "original requester" in cert_resp.json()["detail"]


# ===================================================================
# 5. Denial
# ===================================================================


class TestDenial:
    """WebAuthn denial must not create a lease and must block certificate fetch."""

    def test_denied_request_has_no_lease(self, client: TestClient, store: _BrokerStore) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        deny_resp = client.post(f"/v1/broker/requests/{request_id}/denial")
        assert deny_resp.status_code == 200

        row = store.get_broker_request(request_id)
        assert row["status"] == "denied"
        assert row["lease_id"] is None
        assert row["lease_json"] is None

        lease_resp = client.get(f"/v1/broker/requests/{request_id}/lease")
        assert lease_resp.status_code == 409
        assert "not approved" in lease_resp.json()["detail"]

    def test_denied_request_cannot_fetch_certificate(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.post(f"/v1/broker/requests/{request_id}/denial")

        cert_resp = client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert cert_resp.status_code == 409
        # The "request is not approved" check fires before the "not_ready" path
        assert "not approved" in cert_resp.json()["detail"]


# ===================================================================
# 6. Approval pipeline
# ===================================================================


class TestApproval:
    """Full approval pipeline: create → approve → fetch lease → cert gate."""

    def _create_and_approve(self, client: TestClient, ssh_key: str = _VALID_PUB_KEY) -> str:
        resp = client.post("/v1/broker/requests", json=_body(ssh_public_key=ssh_key))
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]
        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        return request_id

    def test_create_returns_fingerprint(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "pending"
        assert data["ssh_fingerprint"].startswith("SHA256:")
        assert len(data["digest"]) == 64

    def test_full_approval_and_lease_fetch(self, client: TestClient, store: _BrokerStore) -> None:
        request_id = self._create_and_approve(client)

        # Verify stored state
        row = store.get_broker_request(request_id)
        assert row["status"] == "approved"
        assert row["approved_by"] == "operator"
        assert row["lease_id"] is not None
        assert row["lease_json"] is not None

        # Fetch lease via mTLS
        lease_resp = client.get(f"/v1/broker/requests/{request_id}/lease")
        assert lease_resp.status_code == 200
        lease = lease_resp.json()
        assert lease["profile"] == "operate"
        assert lease["action_classes"] == ["ct.reboot"]
        assert lease["target_cts"] == [9001]
        assert lease["audience"] == broker.BROKER_AUDIENCE
        assert lease["max_dispatches"] == 1
        assert lease["policy_version"] == broker.POLICY_VERSION
        assert "approval_binding" in lease
        assert "execution_binding" in lease
        assert "signature" in lease

    def test_certificate_fetch_returns_not_ready(self, client: TestClient) -> None:
        request_id = self._create_and_approve(client)

        cert_resp = client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert cert_resp.status_code == 200
        data = cert_resp.json()
        assert data["status"] == "not_ready"
        assert "not yet implemented" in data["message"]

    def test_get_request_status_after_approval(self, client: TestClient) -> None:
        request_id = self._create_and_approve(client)

        status_resp = client.get(f"/v1/broker/requests/{request_id}")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["status"] == "approved"
        assert data["ssh_fingerprint"].startswith("SHA256:")
        assert data["certificate_fetched"] is False


# ===================================================================
# 7. Lease scope
# ===================================================================


class TestLeaseScope:
    """Verify the issued lease has correct scope."""

    def test_lease_has_operate_profile_and_ct9001(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        lease_resp = client.get(f"/v1/broker/requests/{request_id}/lease")
        lease = lease_resp.json()
        assert lease["profile"] == "operate"
        assert lease["action_classes"] == ["ct.reboot"]
        assert lease["target_cts"] == [9001]
        assert lease["audience"] == broker.BROKER_AUDIENCE
        assert lease["expires_at"] > lease["issued_at"]
        assert lease["max_dispatches"] == 1
        assert lease["policy_version"] == broker.POLICY_VERSION

    def test_lease_signature_verifiable(self, client: TestClient, signer: _LeaseSigner) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        lease_resp = client.get(f"/v1/broker/requests/{request_id}/lease")
        lease_data = lease_resp.json()

        # Reconstruct CapabilityLease and verify signature
        lease = broker.CapabilityLease(
            lease_id=lease_data["lease_id"],
            profile=broker.CapabilityProfile(lease_data["profile"]),
            action_classes=tuple(lease_data["action_classes"]),
            target_cts=tuple(lease_data["target_cts"]),
            approval_id=lease_data["approval_id"],
            approval_binding=lease_data["approval_binding"],
            execution_binding=lease_data["execution_binding"],
            audience=lease_data["audience"],
            policy_version=lease_data["policy_version"],
            issued_at=lease_data["issued_at"],
            expires_at=lease_data["expires_at"],
            max_dispatches=lease_data["max_dispatches"],
            signature=broker.b64decode(lease_data["signature"]),
        )
        public_key = signer.private_key.public_key()
        claims = signer.verify_lease(lease, public_key)
        assert claims["profile"] == "operate"
        assert claims["policy_version"] == broker.POLICY_VERSION


# ===================================================================
# 8. Certificate placeholder gate
# ===================================================================


class TestCertificatePlaceholderGate:
    """The placeholder validates scope but does not consume a future certificate."""

    def test_certificate_gate_can_be_rechecked_before_signing(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        # The placeholder validates but cannot consume state before signing exists.
        first = client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert first.status_code == 200

        # A second gate check remains possible until real signing is implemented.
        second = client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert second.status_code == 200

    def test_certificate_fetched_flag_remains_clear_until_signing(
        self, client: TestClient, store: _BrokerStore
    ) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )

        row = store.get_broker_request(request_id)
        assert row["certificate_fetched"] == 0

    def test_status_stays_unfetched_until_signing(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        # Before fetch
        before = client.get(f"/v1/broker/requests/{request_id}").json()
        assert before["certificate_fetched"] is False

        client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )

        # The authorization gate does not claim that a certificate exists.
        after = client.get(f"/v1/broker/requests/{request_id}").json()
        assert after["certificate_fetched"] is False


# ===================================================================
# 9. Source isolation
# ===================================================================


class TestSourceIsolation:
    """Different mTLS identity cannot access another's request."""

    def test_different_identity_cannot_read_request(
        self, store: _BrokerStore, signer: _LeaseSigner, client_factory
    ) -> None:
        # Create request with agent-demo
        ext1 = FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.10")
        app1 = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=ext1,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        c1 = client_factory(app1)
        resp = c1.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        # Try reading with different identity
        ext2 = FixedIdentityExtractor(identity="other-agent", source_ip="198.51.100.50")
        app2 = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=ext2,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        c2 = client_factory(app2)
        get_resp = c2.get(f"/v1/broker/requests/{request_id}")
        assert get_resp.status_code == 403

    def test_same_identity_different_source_cannot_read_request(
        self, store: _BrokerStore, signer: _LeaseSigner, client_factory
    ) -> None:
        primary = FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.10")
        primary_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=primary,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        request_id = client_factory(primary_app).post("/v1/broker/requests", json=_body()).json()["request_id"]

        changed_source = FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.11")
        changed_source_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=changed_source,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        assert client_factory(changed_source_app).get(f"/v1/broker/requests/{request_id}").status_code == 403


# ===================================================================
# 10. Health endpoint
# ===================================================================


class TestHealth:
    def test_health_ok(self, client: TestClient) -> None:
        assert client.get("/health").json() == {"status": "ok"}


# ===================================================================
# 11. Rate limiting
# ===================================================================


class TestRateLimiting:
    def test_headers_present_on_limited_endpoint_and_absent_on_health(self, client: TestClient) -> None:
        request_response = client.post("/v1/broker/requests", json=_body())
        request_id = request_response.json()["request_id"]

        approval_response = client.get(f"/v1/broker/requests/{request_id}/approval")
        assert approval_response.status_code == 200
        assert "X-RateLimit-Limit" in approval_response.headers

        health_response = client.get("/health")
        assert "X-RateLimit-Limit" not in health_response.headers

    def test_denial_limit_returns_429_with_retry_after(self, client: TestClient) -> None:
        request_id = client.post("/v1/broker/requests", json=_body()).json()["request_id"]
        denial_path = f"/v1/broker/requests/{request_id}/denial"

        assert client.post(denial_path).status_code == 200
        assert client.post(denial_path).status_code == 409
        assert client.post(denial_path).status_code == 409
        limited_response = client.post(denial_path)

        assert limited_response.status_code == 429
        assert "Retry-After" in limited_response.headers


def test_factory_from_env_requires_persistent_broker_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "PVE_BROKER_DATABASE",
        "PVE_BROKER_LEASE_KEY_PATH",
        "PVE_BROKER_RP_ID",
        "PVE_BROKER_ORIGIN",
        "PVE_BROKER_ENROLLMENT_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="runtime configuration is incomplete"):
        svc.create_broker_app_from_env()


# ===================================================================
# 11. Passkey enrollment
# ===================================================================


class TestPasskeyEnrollment:
    @pytest.fixture
    def enrollment_client(
        self, empty_store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor, client_factory
    ) -> tuple[TestClient, _BrokerStore]:
        app = svc.create_broker_app(
            policy=_POLICY,
            store=empty_store,
            signer=signer,
            extractor=extractor,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            enrollment_key="enrollment-key",
            enrollment_enabled=True,
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        return client_factory(app), empty_store

    def test_enrollment_requires_key(self, enrollment_client: tuple[TestClient, _BrokerStore]) -> None:
        client, _ = enrollment_client
        resp = client.post("/v1/broker/enrollments", json={"operator": "test-operator"})
        assert resp.status_code == 401

    def test_enrollment_is_disabled_by_default(
        self, empty_store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor, client_factory
    ) -> None:
        app = svc.create_broker_app(
            policy=_POLICY,
            store=empty_store,
            signer=signer,
            extractor=extractor,
            enrollment_key="enrollment-key",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        response = client_factory(app).post(
            "/v1/broker/enrollments",
            json={"operator": "test-operator"},
            headers={"X-Broker-Enrollment-Key": "enrollment-key"},
        )
        assert response.status_code == 404

    def test_enrollment_is_hidden_after_a_passkey_exists(self, client: TestClient) -> None:
        response = client.post(
            "/v1/broker/enrollments",
            json={"operator": "test-operator"},
            headers={"X-Broker-Enrollment-Key": "enrollment-key"},
        )
        assert response.status_code == 404

    def test_has_passkey(self, empty_store: _BrokerStore) -> None:
        assert empty_store.has_passkey() is False
        empty_store.add_passkey(svc.BrokerPasskey("credential", "operator", b"key", 0))
        assert empty_store.has_passkey() is True

    def test_consume_bootstrap_is_atomic(self, empty_store: _BrokerStore) -> None:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    empty_store.consume_bootstrap,
                    ("enrollment-key", "enrollment-key"),
                )
            )
        assert sorted(results) == [False, True]

    def test_rejected_bootstrap_is_audited(self, enrollment_client: tuple[TestClient, _BrokerStore]) -> None:
        client, store = enrollment_client
        response = client.post(
            "/v1/broker/enrollments",
            json={"operator": "test-operator"},
            headers={"X-Broker-Enrollment-Key": "wrong-key"},
        )
        assert response.status_code == 401
        assert "enrollment_bootstrap_rejected" in [event["event"] for event in store.audit_events("bootstrap")]

    def test_enrollment_flow(self, enrollment_client: tuple[TestClient, _BrokerStore]) -> None:
        client, store = enrollment_client
        # Begin enrollment
        resp = client.post(
            "/v1/broker/enrollments",
            json={"operator": "test-operator"},
            headers={"X-Broker-Enrollment-Key": "enrollment-key"},
        )
        assert resp.status_code == 201
        enrollment_id = resp.json()["enrollment_id"]

        # Options
        opts_resp = client.get(f"/v1/broker/enrollments/{enrollment_id}/options")
        assert opts_resp.status_code == 200

        # Complete
        complete_resp = client.post(
            f"/v1/broker/enrollments/{enrollment_id}/complete",
            json={"credential": {"proof": "registered"}},
        )
        assert complete_resp.status_code == 200
        assert complete_resp.json()["status"] == "enrolled"
        event_types = [event["event"] for event in store.audit_events(enrollment_id)]
        assert "enrollment_bootstrap_completed" in event_types

        # Second completion fails
        retry = client.post(
            f"/v1/broker/enrollments/{enrollment_id}/complete",
            json={"credential": {"proof": "registered"}},
        )
        assert retry.status_code == 409

    def test_enrollment_page_serves_html(self, enrollment_client: tuple[TestClient, _BrokerStore]) -> None:
        client, _ = enrollment_client
        resp = client.post(
            "/v1/broker/enrollments",
            json={"operator": "test-operator"},
            headers={"X-Broker-Enrollment-Key": "enrollment-key"},
        )
        enrollment_id = resp.json()["enrollment_id"]

        page = client.get(f"/v1/broker/enroll/{enrollment_id}")
        assert page.status_code == 200
        assert "Enroll broker passkey" in page.text
        assert "# noqa" not in page.text


# ===================================================================
# 12. Request validation
# ===================================================================


class TestRequestValidation:
    def test_invalid_action_rejected(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/broker/requests",
            json=_body(action="invalid_action"),
        )
        assert resp.status_code == 409
        assert resp.json()["detail"] == ("action 'invalid_action' on CT 9001 is not permitted by the operate policy")

    def test_excluded_action_rejected(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/broker/requests",
            json=_body(action="ct.destroy"),
        )
        assert resp.status_code == 409
        assert "excluded" in resp.json()["detail"]

    def test_wrong_ct_rejected(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/broker/requests",
            json=_body(ct_id=9900),
        )
        assert resp.status_code == 409
        assert resp.json()["detail"] == ("action 'ct.reboot' on CT 9900 is not permitted by the operate policy")

    def test_empty_public_key_rejected_through_broker(self, store: _BrokerStore) -> None:
        """The core broker rejects empty/bad public keys."""
        with pytest.raises(ValueError, match="at least two space-separated parts"):
            broker.create_request(
                action="ct.reboot",
                ct_id=9001,
                reason="test",
                requester="user",
                observed_source_ip="198.51.100.1",
                mtls_identity="agent",
                ssh_public_key="",
            )


# ===================================================================
# 13. Cancel
# ===================================================================


class TestCancel:
    def test_cancel_by_original_requester(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        cancel_resp = client.post(f"/v1/broker/requests/{request_id}/cancel")
        assert cancel_resp.status_code == 200
        assert cancel_resp.json() == {"status": "cancelled"}

    def test_cancel_by_different_identity_fails(
        self, store: _BrokerStore, signer: _LeaseSigner, client_factory
    ) -> None:
        ext = FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.10")
        app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=ext,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        c = client_factory(app)
        resp = c.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        # Different identity attempts cancel
        intruder_ext = FixedIdentityExtractor(identity="intruder", source_ip="198.51.100.99")
        intruder_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=intruder_ext,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        intruder_client = client_factory(intruder_app)
        cancel_resp = intruder_client.post(f"/v1/broker/requests/{request_id}/cancel")
        assert cancel_resp.status_code == 409
        assert "original requester" in cancel_resp.json()["detail"]

    def test_cancel_approved_request_fails(self, client: TestClient) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        # Approve first
        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        # Cancel should fail since status is 'approved', not 'pending'
        cancel_resp = client.post(f"/v1/broker/requests/{request_id}/cancel")
        assert cancel_resp.status_code == 409
        assert "cannot be cancelled" in cancel_resp.json()["detail"]


# ===================================================================
# 14. Audit events
# ===================================================================


class TestAudit:
    def test_audit_records_required_fields(self, client: TestClient, store: _BrokerStore) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        events = store.audit_events(request_id)
        assert len(events) == 1
        event = events[0]
        assert event["event"] == "request_created"
        assert "fingerprint" in event["summary"]
        assert "agent-demo" in event["summary"]

    def test_audit_on_approval(self, client: TestClient, store: _BrokerStore) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )

        events = store.audit_events(request_id)
        event_types = [e["event"] for e in events]
        assert "request_created" in event_types
        assert "approval_challenge_created" in event_types
        assert "request_approved" in event_types
        approved_event = [e for e in events if e["event"] == "request_approved"][0]
        assert "operator" in approved_event["summary"]
        assert "lease" in approved_event["summary"]
        assert "fingerprint" in approved_event["summary"]

    def test_audit_on_denial(self, client: TestClient, store: _BrokerStore) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.post(f"/v1/broker/requests/{request_id}/denial")

        events = store.audit_events(request_id)
        event_types = [e["event"] for e in events]
        assert "request_denied" in event_types

    def test_audit_on_certificate_fetch(self, client: TestClient, store: _BrokerStore) -> None:
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )

        events = store.audit_events(request_id)
        event_types = [e["event"] for e in events]
        assert "certificate_gate_checked" in event_types
        fetch_event = [e for e in events if e["event"] == "certificate_gate_checked"][0]
        assert "fingerprint" in fetch_event["summary"]
        assert "agent-demo" in fetch_event["summary"]

    def test_audit_no_secrets_in_summary(self, client: TestClient, store: _BrokerStore) -> None:
        """Verify audit summaries contain no secret values (private keys, tokens)."""
        resp = client.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )

        for event in store.audit_events(request_id):
            summary = event["summary"]
            # Should contain fingerprint but not the full key
            if "fingerprint" in summary:
                assert re.search(r"SHA256:[A-Za-z0-9+/=]+", summary)
            # Should NOT contain base64-encoded private key parts
            assert "AAAAC3NzaC1lZDI1NTE5" not in summary
            assert "private" not in summary.lower()


# ===================================================================
# 15. No requests without passkey
# ===================================================================


class TestNoPasskey:
    def test_no_passkey_cannot_begin_auth(
        self, empty_store: _BrokerStore, signer: _LeaseSigner, client_factory
    ) -> None:
        ext = FixedIdentityExtractor(identity="agent-demo", source_ip="192.0.2.10")
        app = svc.create_broker_app(
            policy=_POLICY,
            store=empty_store,
            signer=signer,
            extractor=ext,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
        )
        c = client_factory(app)
        resp = c.post("/v1/broker/requests", json=_body())
        request_id = resp.json()["request_id"]

        opts_resp = c.get(f"/v1/broker/requests/{request_id}/approval/options")
        assert opts_resp.status_code == 409
        assert "no registered passkeys" in opts_resp.json()["detail"]


# ===================================================================
# 16. Module has no PVE nor SSH transport path
# ===================================================================


class TestModuleIsolation:
    def test_approval_does_not_execute_an_operation(self, client: TestClient, monkeypatch) -> None:
        def forbidden(*args, **kwargs):
            raise AssertionError("approval must not execute a command or connect to a target")

        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr("socket.socket.connect", forbidden)
        created = client.post("/v1/broker/requests", json=_body())
        assert created.status_code == 201
        request_id = created.json()["request_id"]
        assert client.get(f"/v1/broker/requests/{request_id}/approval/options").status_code == 200
        approved = client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        assert approved.json() == {"status": "approved"}
        lease = client.get(f"/v1/broker/requests/{request_id}/lease")
        assert lease.status_code == 200
        assert lease.json()["signature"]
        certificate = client.post(
            f"/v1/broker/requests/{request_id}/certificate", json={"ssh_public_key": _VALID_PUB_KEY}
        )
        assert certificate.json()["status"] == "not_ready"


# ===================================================================
# 12. CaCertificateSigner
# ===================================================================


class TestCaCertificateSigner:
    """Real ssh-keygen signing through the CaCertificateSigner class."""

    def test_sign_returns_certificate(self, ca_key_path: str) -> None:
        signer = svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER)
        cert = signer.sign(_VALID_PUB_KEY, "1")
        assert cert.startswith("ssh-ed25519-cert-v01@openssh.com")

    def test_invalid_public_key_rejected(self, ca_key_path: str) -> None:
        signer = svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER)
        with pytest.raises(ValueError, match="invalid SSH public key"):
            signer.sign("not-a-key", "1")

    def test_wrong_key_type_rejected(self, ca_key_path: str) -> None:
        signer = svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER)
        rsa_key = _RSA_PUB_KEY
        with pytest.raises(ValueError, match="only Ed25519"):
            signer.sign(rsa_key, "1")

    def test_ca_key_not_found(self) -> None:
        signer = svc.CaCertificateSigner("/nonexistent/ca-key.pem", builder=_CERT_BUILDER)
        with pytest.raises(RuntimeError, match="CA key not found"):
            signer.sign(_VALID_PUB_KEY, "1")

    def test_serial_must_be_alphanumeric(self, ca_key_path: str) -> None:
        signer = svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER)
        with pytest.raises(ValueError, match="serial"):
            signer.sign(_VALID_PUB_KEY, ";rm -rf /")


# ===================================================================
# 13. Real certificate issuance (integration)
# ===================================================================


class TestRealCertificateIssuance:
    """End-to-end certificate issuance through the broker service."""

    @pytest.fixture
    def cert_client(
        self,
        store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        ca_key_path: str,
        client_factory,
    ) -> TestClient:
        cert_signer = svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER)
        app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=extractor,
            rp_id="broker.example.test",
            origin="https://broker.example.test",
            enrollment_key="enrollment-key",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
            cert_signer=cert_signer,
        )
        return client_factory(app)

    def test_full_issuance_flow(
        self,
        cert_client: TestClient,
        store: _BrokerStore,
        signer: _LeaseSigner,
    ) -> None:
        now = int(time.time())
        body = _body()
        req_resp = cert_client.post("/v1/broker/requests", json=body)
        assert req_resp.status_code == 201
        request_id = req_resp.json()["request_id"]

        store.begin_authentication(request_id, now=now)
        passkeys = store.connection.execute("SELECT * FROM broker_passkeys").fetchall()
        assert len(passkeys) >= 1
        passkey = svc.BrokerPasskey(
            passkeys[0]["credential_id"],
            passkeys[0]["operator"],
            passkeys[0]["public_key"],
            passkeys[0]["sign_count"],
        )

        factory = broker.LeaseFactory(signer, _POLICY)
        store.approve(
            request_id,
            {"id": passkey.credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=factory,
            now=now,
        )

        fetch_body = {"ssh_public_key": _VALID_PUB_KEY}
        cert_resp = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json=fetch_body,
        )
        assert cert_resp.status_code == 200
        data = cert_resp.json()
        assert data["status"] == "issued"
        assert data["certificate"].startswith("ssh-ed25519-cert-v01@openssh.com")
        assert isinstance(data["expires_at"], int)

    def test_second_fetch_returns_409(
        self,
        cert_client: TestClient,
        store: _BrokerStore,
        signer: _LeaseSigner,
        ca_key_path: str,
        extractor: FixedIdentityExtractor,
    ) -> None:
        now = int(time.time())
        body = _body()
        req_resp = cert_client.post("/v1/broker/requests", json=body)
        assert req_resp.status_code == 201
        request_id = req_resp.json()["request_id"]

        store.begin_authentication(request_id, now=now)
        passkeys = store.connection.execute("SELECT * FROM broker_passkeys").fetchall()
        passkey = svc.BrokerPasskey(
            passkeys[0]["credential_id"],
            passkeys[0]["operator"],
            passkeys[0]["public_key"],
            passkeys[0]["sign_count"],
        )

        factory = broker.LeaseFactory(signer, _POLICY)
        store.approve(
            request_id,
            {"id": passkey.credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=factory,
            now=now,
        )

        r1 = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert r1.status_code == 200

        r2 = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert r2.status_code == 409

    @pytest.mark.parametrize("client_serial", ["42", "609be8c1"])
    def test_certificate_serial_is_assigned_by_the_broker(
        self,
        cert_client: TestClient,
        store: _BrokerStore,
        signer: _LeaseSigner,
        tmp_path: Path,
        client_serial: str,
    ) -> None:
        """A caller-supplied serial is ignored, well-formed or not.

        The serial used to come from the worker's clock, so two workers -- or
        one worker within a second -- could issue duplicates, and a malformed
        one died inside ssh-keygen. The broker now picks it and records it.
        """
        request_id = cert_client.post("/v1/broker/requests", json=_body()).json()["request_id"]
        _, passkeys = store.begin_authentication(request_id)
        store.approve(
            request_id,
            {"id": passkeys[0].credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=broker.LeaseFactory(signer, _POLICY),
        )

        response = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY, "serial": client_serial},
        )

        assert response.status_code == 200
        cert_path = tmp_path / "issued-cert.pub"
        cert_path.write_text(response.json()["certificate"] + "\n")
        listing = subprocess.run(
            ["ssh-keygen", "-L", "-f", str(cert_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        issued_serial = int(re.search(r"Serial: (\d+)", listing).group(1))  # type: ignore[union-attr]
        recorded = store.get_broker_request(request_id)["certificate_serial"]
        assert issued_serial == recorded
        assert str(issued_serial) != client_serial
        issued_event = [e for e in store.audit_events(request_id) if e["event"] == "certificate_issued"]
        assert f"serial {recorded}" in issued_event[0]["summary"]

    def test_certificate_fetch_after_expiry_is_rejected(
        self,
        store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        ca_key_path: str,
    ) -> None:
        now = 1_000_000
        _, request_id, _ = store.create_broker_request(
            "ct.reboot",
            9001,
            "expire certificate request",
            "test-operator",
            "agent-demo",
            extractor.extract(),
            _VALID_PUB_KEY,
            policy=_POLICY,
            now=now,
        )
        _, passkeys = store.begin_authentication(request_id, now=now)
        store.approve(
            request_id,
            {"id": passkeys[0].credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=broker.LeaseFactory(signer, _POLICY),
            now=now,
        )

        with pytest.raises(ValueError, match="request has expired"):
            store.fetch_certificate_gate(
                request_id,
                extractor.extract(),
                _VALID_PUB_KEY,
                cert_signer=svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER),
                now=now + svc.BROKER_GRANT_TTL_SECONDS + 1,
            )

    def test_concurrent_certificate_fetch_issues_once(
        self,
        store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        ca_key_path: str,
    ) -> None:
        now = int(time.time())
        _, request_id, _ = store.create_broker_request(
            "ct.reboot",
            9001,
            "concurrent certificate request",
            "test-operator",
            "agent-demo",
            extractor.extract(),
            _VALID_PUB_KEY,
            policy=_POLICY,
            now=now,
        )
        _, passkeys = store.begin_authentication(request_id, now=now)
        store.approve(
            request_id,
            {"id": passkeys[0].credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=broker.LeaseFactory(signer, _POLICY),
            now=now,
        )
        cert_signer = svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER)

        def fetch() -> str:
            return store.fetch_certificate_gate(
                request_id,
                extractor.extract(),
                _VALID_PUB_KEY,
                cert_signer=cert_signer,
                now=now,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(fetch) for _ in range(2)]

        results = []
        errors = []
        for future in futures:
            try:
                results.append(future.result())
            except ValueError as exc:
                errors.append(str(exc))

        assert len(results) == 1
        assert results[0].startswith("ssh-ed25519-cert-v01@openssh.com")
        assert errors == ["certificate has already been fetched"]


# ===================================================================
# Negative matrix — broker-level rejection tests
# ===================================================================


_RSA_PUB_KEY = (
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    .public_key()
    .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    .decode()
)


class TestRejectWrongKeyFormat:
    def test_rsa_key_rejected_on_request_creation(
        self,
        client: TestClient,
    ) -> None:
        r = client.post(
            "/v1/broker/requests",
            json=_body(ssh_public_key=_RSA_PUB_KEY),
        )
        assert r.status_code == 409

    def test_garbage_key_rejected(
        self,
        client: TestClient,
    ) -> None:
        r = client.post(
            "/v1/broker/requests",
            json=_body(ssh_public_key="not-a-valid-key"),
        )
        assert r.status_code == 409

    def test_certificate_fetch_rejects_wrong_public_key(
        self,
        store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        ca_key_path: str,
        client_factory,
    ) -> None:
        cert_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=extractor,
            rp_id="localhost",
            origin="http://localhost",
            cert_signer=svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER),
        )
        cert_client = client_factory(cert_app)

        resp = cert_client.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]

        store.begin_authentication(request_id)
        passkeys = store.connection.execute("SELECT * FROM broker_passkeys").fetchall()
        passkey = svc.BrokerPasskey(
            passkeys[0]["credential_id"],
            passkeys[0]["operator"],
            passkeys[0]["public_key"],
            passkeys[0]["sign_count"],
        )
        factory = broker.LeaseFactory(signer, _POLICY)
        store.approve(
            request_id,
            {"id": passkey.credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=factory,
        )

        r = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _THIRD_PUB_KEY},
        )
        assert r.status_code == 409
        assert "fingerprint" in json.loads(r.text)["detail"].lower()


class TestCertificateGateResilience:
    def test_wrong_key_does_not_consume_cert_gate(
        self,
        store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        ca_key_path: str,
        client_factory,
    ) -> None:
        cert_app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=extractor,
            rp_id="localhost",
            origin="http://localhost",
            cert_signer=svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER),
        )
        cert_client = client_factory(cert_app)

        resp = cert_client.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]

        store.begin_authentication(request_id)
        passkeys = store.connection.execute("SELECT * FROM broker_passkeys").fetchall()
        p = svc.BrokerPasskey(
            passkeys[0]["credential_id"],
            passkeys[0]["operator"],
            passkeys[0]["public_key"],
            passkeys[0]["sign_count"],
        )
        factory = broker.LeaseFactory(signer, _POLICY)
        store.approve(
            request_id,
            {"id": p.credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=factory,
        )

        # First: wrong key → rejected
        r1 = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _THIRD_PUB_KEY},
        )
        assert r1.status_code == 409

        # Second: correct key → still works (gate not consumed by wrong key)
        r2 = cert_client.post(
            f"/v1/broker/requests/{request_id}/certificate",
            json={"ssh_public_key": _VALID_PUB_KEY},
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "issued"


class TestExpiredRequest:
    def test_expired_request_cannot_be_approved(
        self, store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor, client_factory
    ) -> None:
        now = int(time.time())
        past = now - 3600  # 1 hour ago

        app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=extractor,
            rp_id="localhost",
            origin="http://localhost",
        )
        client = client_factory(app)

        resp = client.post("/v1/broker/requests", json=_body())
        assert resp.status_code == 201
        request_id = resp.json()["request_id"]

        store.connection.execute(
            "UPDATE broker_requests SET expires_at = ?, status = 'pending' WHERE request_id = ?",
            (past, request_id),
        )
        store.connection.commit()

        with pytest.raises(ValueError, match="not awaiting approval"):
            store.begin_authentication(request_id, now=now + 10)


@pytest.mark.parametrize(
    ("deadline_kind", "persist_expired"),
    [("request", False), ("request", True), ("lease", False)],
    ids=["request-deadline-passes", "reader-persists-expired", "lease-deadline-passes"],
)
def test_certificate_rechecks_expiry_after_validation_before_issuance(
    store, signer, extractor, monkeypatch, deadline_kind, persist_expired
):
    created_at = 1_000_000
    _, request_id, deadline = store.create_broker_request(
        "ct.reboot",
        9001,
        "expiry race",
        "operator",
        "agent-demo",
        extractor.extract(),
        _VALID_PUB_KEY,
        policy=_POLICY,
        now=created_at,
    )
    approval_time = deadline - 10 if deadline_kind == "request" else created_at
    lease_factory = broker.LeaseFactory(signer, _POLICY)
    if deadline_kind == "lease":
        # A shorter, genuinely signed capability is within the protocol's TTL
        # bound. It lets this refusal be tested independently of request expiry.
        class ShortLeaseFactory(broker.LeaseFactory):
            def create_lease(self, **kwargs):
                lease = super().create_lease(**kwargs)
                return signer.sign_lease(replace(lease, expires_at=lease.issued_at + 60, signature=""))

        lease_factory = ShortLeaseFactory(signer, _POLICY)
    store.begin_authentication(request_id, now=approval_time)
    store.approve(
        request_id,
        {"id": "credential-1", "proof": "verified"},
        FakeVerifier(),
        lease_factory,
        now=approval_time,
    )
    lease_deadline = json.loads(store.get_broker_request(request_id, now=approval_time)["lease_json"])["expires_at"]
    if deadline_kind == "request":
        assert lease_deadline > deadline
    else:
        assert lease_deadline < deadline
    crossing = deadline if deadline_kind == "request" else lease_deadline
    clock = [crossing - 1]
    monkeypatch.setattr(svc.time, "time", lambda: clock[0])
    reached = threading.Event()
    resume = threading.Event()
    original_fingerprint = svc._public_key_fingerprint

    def pause_after_fingerprint(key):
        result = original_fingerprint(key)
        reached.set()
        assert resume.wait(5), "test did not release the fetcher"
        return result

    class RecordingSigner:
        calls = 0

        def sign(self, key, serial):
            self.calls += 1
            return "synthetic certificate"

    certificate_signer = RecordingSigner()
    monkeypatch.setattr(svc, "_public_key_fingerprint", pause_after_fingerprint)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            store.fetch_certificate_gate, request_id, extractor.extract(), _VALID_PUB_KEY, certificate_signer
        )
        try:
            assert reached.wait(5), "fetcher did not reach the validation barrier"
            clock[0] = crossing + 1
            if persist_expired:
                assert store.get_broker_request(request_id)["status"] == "expired"
        finally:
            resume.set()
        with pytest.raises(ValueError, match="expired"):
            future.result(timeout=5)
    assert certificate_signer.calls == 0
    assert store.get_broker_request(request_id)["certificate_fetched"] == 0
    assert "certificate_issued" not in [event["event"] for event in store.audit_events(request_id)]


class TestPublicKeyEndpoint:
    def test_public_key_endpoint_returns_openssh_key(
        self, store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor, client_factory
    ) -> None:
        app = svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=extractor,
            rp_id="localhost",
            origin="http://localhost",
        )
        client = client_factory(app)

        r = client.get("/v1/broker/lease-public-key")
        assert r.status_code == 200
        data = r.json()
        assert data["format"] == "openssh"
        assert data["public_key"].startswith("ssh-ed25519 ")
        assert len(data["public_key"].split()) == 2


# ===================================================================
# Approval and enrollment pages escape agent-supplied text
# ===================================================================


class TestPageEscaping:
    _SCRIPT_BREAKOUT = "</script><script>alert(1)</script>"

    def test_approval_page_does_not_let_request_fields_close_the_script(self, client: TestClient) -> None:
        body = _body(
            reason=self._SCRIPT_BREAKOUT,
            requester="<img src=x onerror=alert(2)>",
            self_reported_hostname="a&b c",
        )
        request_id = client.post("/v1/broker/requests", json=body).json()["request_id"]

        page = client.get(f"/v1/broker/requests/{request_id}/approval").text

        assert self._SCRIPT_BREAKOUT not in page
        assert "<img" not in page
        assert " " not in page
        # Exactly the template's own script block remains.
        assert page.count("</script>") == 1
        # The browser still receives the original values once the JSON parses.
        details_json = re.search(r"const details = (.*);\n", page).group(1)  # type: ignore[union-attr]
        details = json.loads(details_json)
        assert details["reason"] == self._SCRIPT_BREAKOUT
        assert details["requester"] == "<img src=x onerror=alert(2)>"
        assert details["self_reported_hostname"] == "a&b c"

    def test_enrollment_page_escapes_the_enrollment_id(self, client: TestClient) -> None:
        response = client.get("/v1/broker/enroll/%3Cimg%20src=x%20onerror=alert(1)%3E")
        assert response.status_code == 200
        assert "<img" not in response.text
        assert '"\\u003cimg src=x onerror=alert(1)\\u003e"' in response.text


# ===================================================================
# Requests expire when read past their deadline
# ===================================================================


class TestRequestExpiry:
    def _create(self, store: _BrokerStore, extractor: FixedIdentityExtractor, now: int) -> str:
        _, request_id, _ = store.create_broker_request(
            "ct.reboot",
            9001,
            "expiry",
            "test-operator",
            "agent-demo",
            extractor.extract(),
            _VALID_PUB_KEY,
            policy=_POLICY,
            now=now,
        )
        return request_id

    def _approve(self, store: _BrokerStore, signer: _LeaseSigner, request_id: str, now: int) -> None:
        _, passkeys = store.begin_authentication(request_id, now=now)
        store.approve(
            request_id,
            {"id": passkeys[0].credential_id, "proof": "verified"},
            verifier=FakeVerifier(),
            lease_factory=broker.LeaseFactory(signer, _POLICY),
            now=now,
        )

    def test_pending_request_expires_once_and_is_audited_once(
        self, store: _BrokerStore, extractor: FixedIdentityExtractor
    ) -> None:
        now = 1_000_000
        request_id = self._create(store, extractor, now)
        late = now + svc.BROKER_GRANT_TTL_SECONDS + 1

        assert store.get_broker_request(request_id, now=now)["status"] == "pending"
        assert store.get_broker_request(request_id, now=late)["status"] == "expired"
        assert store.get_broker_request(request_id, now=late + 5)["status"] == "expired"
        events = [e["event"] for e in store.audit_events(request_id)]
        assert events.count("request_expired") == 1

    def test_approved_unfetched_request_expires(
        self, store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor
    ) -> None:
        now = 1_000_000
        request_id = self._create(store, extractor, now)
        self._approve(store, signer, request_id, now)
        late = now + svc.BROKER_GRANT_TTL_SECONDS + 1

        assert store.get_broker_request(request_id, now=late)["status"] == "expired"
        with pytest.raises(ValueError, match="request has expired"):
            store.fetch_lease(request_id, extractor.extract(), now=late)

    def test_fetched_request_is_not_expired(
        self,
        store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        ca_key_path: str,
    ) -> None:
        """A dispatched request keeps its approved state; only dead ones expire."""
        now = int(time.time())
        request_id = self._create(store, extractor, now)
        self._approve(store, signer, request_id, now)
        store.fetch_certificate_gate(
            request_id,
            extractor.extract(),
            _VALID_PUB_KEY,
            cert_signer=svc.CaCertificateSigner(ca_key_path, builder=_CERT_BUILDER),
            now=now,
        )
        late = now + svc.BROKER_GRANT_TTL_SECONDS + 1

        assert store.get_broker_request(request_id, now=late)["status"] == "approved"
        assert "request_expired" not in [e["event"] for e in store.audit_events(request_id)]

    def test_status_endpoints_report_expired(self, client: TestClient, store: _BrokerStore) -> None:
        request_id = client.post("/v1/broker/requests", json=_body()).json()["request_id"]
        store.connection.execute(
            "UPDATE broker_requests SET expires_at = ? WHERE request_id = ?",
            (int(time.time()) - 1, request_id),
        )

        assert client.get(f"/v1/broker/requests/{request_id}").json()["status"] == "expired"
        assert client.get(f"/v1/broker/requests/{request_id}/status").json() == {"status": "expired"}


# ===================================================================
# The policy file, not a constant, decides what may be requested
# ===================================================================


class TestRequestPolicy:
    def test_broker_admits_only_the_policy_targets(
        self, store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor, client_factory
    ) -> None:
        policy = broker.Policy(
            grants={"ct.start": frozenset({9002}), "ct.stop": frozenset({9002, 9001})},
            snapshot_retention_days=7,
        )
        client = client_factory(
            svc.create_broker_app(
                store=store,
                signer=signer,
                extractor=extractor,
                policy=policy,
                verifier=FakeVerifier(),
                registration_verifier=FakeRegistrationVerifier(),
            )
        )

        admitted = client.post("/v1/broker/requests", json=_body(action="ct.start", ct_id=9002))
        admitted_stop = client.post("/v1/broker/requests", json=_body(action="ct.stop", ct_id=9001))
        refused_ct = client.post("/v1/broker/requests", json=_body(action="ct.start", ct_id=9001))
        refused_action = client.post("/v1/broker/requests", json=_body(action="ct.reboot", ct_id=9002))

        assert admitted.status_code == 201
        assert admitted_stop.status_code == 201
        # The synthetic target is granted ct.stop but not ct.start: grants are per action.
        assert refused_ct.status_code == 409
        assert refused_ct.json()["detail"] == ("action 'ct.start' on CT 9001 is not permitted by the operate policy")
        assert refused_action.status_code == 409
        assert refused_action.json()["detail"] == (
            "action 'ct.reboot' on CT 9002 is not permitted by the operate policy"
        )

    def test_prune_approval_page_states_the_retention_from_policy(
        self, store: _BrokerStore, signer: _LeaseSigner, extractor: FixedIdentityExtractor, client_factory
    ) -> None:
        policy = broker.Policy(
            grants={"ct.snapshot_prune": frozenset({9001}), "ct.stop": frozenset({9001})},
            snapshot_retention_days=11,
        )
        client = client_factory(
            svc.create_broker_app(
                store=store,
                signer=signer,
                extractor=extractor,
                policy=policy,
                verifier=FakeVerifier(),
                registration_verifier=FakeRegistrationVerifier(),
            )
        )

        def page(action: str) -> str:
            request_id = client.post("/v1/broker/requests", json=_body(action=action)).json()["request_id"]
            return client.get(f"/v1/broker/requests/{request_id}/approval").text

        details = json.loads(re.search(r"const details = (.*);", page("ct.snapshot_prune")).group(1))  # type: ignore[union-attr]
        assert details["effect"] == "removes broker-* snapshots older than 11 days"
        assert "effect" not in json.loads(re.search(r"const details = (.*);", page("ct.stop")).group(1))  # type: ignore[union-attr]

    def test_lease_body_carries_no_openspec_field(self, client: TestClient) -> None:
        request_id = client.post("/v1/broker/requests", json=_body()).json()["request_id"]
        client.get(f"/v1/broker/requests/{request_id}/approval/options")
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": {"id": "credential-1", "proof": "verified"}},
        )
        lease = client.get(f"/v1/broker/requests/{request_id}/lease").json()
        assert "openspec_change_ref" not in lease


class TestFactoryFromEnv:
    @pytest.fixture
    def complete_env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
        key_path = tmp_path / "lease.pem"
        key_path.write_bytes(broker.LeaseSigner.generate().to_pem())
        key_path.chmod(0o600)
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(
            json.dumps({"version": 2, "grants": {"ct.start": [9002]}, "snapshot_retention_days": 7})
        )
        for name, value in {
            "PVE_BROKER_DATABASE": str(tmp_path / "broker.sqlite3"),
            "PVE_BROKER_LEASE_KEY_PATH": str(key_path),
            "PVE_BROKER_RP_ID": "broker.example.test",
            "PVE_BROKER_ORIGIN": "https://broker.example.test",
            "PVE_BROKER_ENROLLMENT_KEY": _ENROLLMENT_KEY,
            "PVE_BROKER_POLICY_FILE": str(policy_path),
        }.items():
            monkeypatch.setenv(name, value)
        for name in ("PVE_BROKER_MTLS_CLIENTS_JSON", "PVE_BROKER_CA_KEY_PATH", "PVE_BROKER_CERT_SOURCE"):
            monkeypatch.delenv(name, raising=False)
        return policy_path

    def test_complete_configuration_builds_an_app(self, complete_env: Path, client_factory) -> None:
        app = svc.create_broker_app_from_env()
        assert client_factory(app).get("/health").json() == {"status": "ok"}

    def test_lifespan_closes_the_real_factory_owned_connection(self, complete_env, monkeypatch, resources):
        original = svc.BrokerStore
        opened = []

        class RecordingStore(original):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                opened.append(self)

        monkeypatch.setattr(svc, "BrokerStore", RecordingStore)
        app = svc.create_broker_app_from_env()
        resources.callback(opened[0].close)
        with TestClient(app) as client:
            assert client.get("/health").json() == {"status": "ok"}
            assert opened[0].connection.execute("SELECT 1").fetchone()[0] == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            opened[0].connection.execute("SELECT 1")

    def test_ca_requires_an_explicit_certificate_source(self, complete_env, monkeypatch):
        monkeypatch.setenv("PVE_BROKER_CA_KEY_PATH", str(complete_env.with_name("unused-ca")))
        with pytest.raises(RuntimeError, match="PVE_BROKER_CERT_SOURCE is required"):
            svc.create_broker_app_from_env()

    def test_missing_policy_file_setting_is_incomplete(
        self, complete_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PVE_BROKER_POLICY_FILE")
        with pytest.raises(RuntimeError, match="runtime configuration is incomplete"):
            svc.create_broker_app_from_env()

    @pytest.mark.parametrize(
        "content",
        [
            None,
            "not json",
            '{"version": 1, "actions": ["ct.start"], "targets": [9002]}',
            '{"version": 2, "grants": {"ct.start": [9002]}}',
        ],
    )
    def test_unusable_policy_file_refuses_to_start(self, complete_env: Path, content: str | None) -> None:
        if content is None:
            complete_env.unlink()
        else:
            complete_env.write_text(content)
        with pytest.raises(RuntimeError, match="PVE_BROKER_POLICY_FILE is invalid"):
            svc.create_broker_app_from_env()

    @pytest.mark.parametrize(
        "source", ["192.0.2.20/32 ; rm -rf /", "192.0.2.0/24,198.51.100.0/24", "0.0.0.0/0", "::/0"]
    )
    def test_malformed_certificate_source_refuses_to_start(
        self, complete_env: Path, monkeypatch: pytest.MonkeyPatch, source
    ) -> None:
        monkeypatch.setenv("PVE_BROKER_CERT_SOURCE", source)
        with pytest.raises(RuntimeError, match="PVE_BROKER_CERT_SOURCE"):
            svc.create_broker_app_from_env()


# ===================================================================
# Store discipline: bootstrap key and SQL under the lock
# ===================================================================


class TestStoreDiscipline:
    def test_bootstrap_consumption_survives_reopen_and_secret_rotation(self, tmp_path, resources):
        database = tmp_path / "persisted.sqlite3"
        first = svc.BrokerStore(database, "first-synthetic-key")
        resources.callback(first.close)
        assert first.consume_bootstrap("first-synthetic-key") is True
        first.close()
        reopened = svc.BrokerStore(database, "rotated-synthetic-key")
        resources.callback(reopened.close)
        assert reopened.consume_bootstrap("rotated-synthetic-key") is False

    def test_database_and_live_wal_sidecars_are_private(self, store, tmp_path):
        for suffix in ("", "-wal", "-shm"):
            path = tmp_path / ("broker.sqlite3" + suffix)
            assert path.is_file()
            assert path.stat().st_mode & 0o777 == 0o600

    def test_consume_bootstrap_compares_the_configured_key_not_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, resources
    ) -> None:
        monkeypatch.setenv("PVE_BROKER_ENROLLMENT_KEY", "environment-key")

        configured = svc.BrokerStore(tmp_path / "configured.sqlite3", "configured-key")
        resources.callback(configured.close)
        assert configured.consume_bootstrap("environment-key") is False
        assert configured.consume_bootstrap("configured-key") is True

        unconfigured = svc.BrokerStore(tmp_path / "unconfigured.sqlite3")
        resources.callback(unconfigured.close)
        assert unconfigured.consume_bootstrap("environment-key") is False
        assert unconfigured.consume_bootstrap("") is False

    def test_enrollment_options_runs_its_sql_under_the_store_lock(
        self,
        empty_store: _BrokerStore,
        signer: _LeaseSigner,
        extractor: FixedIdentityExtractor,
        monkeypatch: pytest.MonkeyPatch,
        client_factory,
    ) -> None:
        """The endpoint used to query the shared connection directly, racing
        the store's other threads for it."""
        client = client_factory(
            svc.create_broker_app(
                store=empty_store,
                signer=signer,
                extractor=extractor,
                policy=_POLICY,
                enrollment_key=_ENROLLMENT_KEY,
                enrollment_enabled=True,
                verifier=FakeVerifier(),
                registration_verifier=FakeRegistrationVerifier(),
            )
        )
        enrollment_id = client.post(
            "/v1/broker/enrollments",
            json={"operator": "test-operator"},
            headers={"X-Broker-Enrollment-Key": _ENROLLMENT_KEY},
        ).json()["enrollment_id"]

        unlocked: list[str] = []

        class LockCheckingConnection:
            def __init__(self, inner: object, lock: object) -> None:
                self._inner, self._lock = inner, lock

            def execute(self, sql: str, *args: object) -> object:
                if not self._lock._is_owned():  # type: ignore[attr-defined]
                    unlocked.append(sql)
                return self._inner.execute(sql, *args)  # type: ignore[attr-defined]

            def __getattr__(self, name: str) -> object:
                return getattr(self._inner, name)

        monkeypatch.setattr(
            empty_store,
            "_connection",
            LockCheckingConnection(empty_store._connection, empty_store._lock),
        )
        response = client.get(f"/v1/broker/enrollments/{enrollment_id}/options")

        assert response.status_code == 200
        assert unlocked == []

    def test_enrollment_options_refuses_an_unknown_enrollment(self, client: TestClient) -> None:
        response = client.get("/v1/broker/enrollments/does-not-exist/options")
        assert response.status_code == 409
        assert response.json()["detail"] == "enrollment is not pending"


# ---------------------------------------------------------------------------
# Approval notification
# ---------------------------------------------------------------------------


class _FakeNotifier:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.sent: list[str] = []

    def send(self, content: str) -> None:
        self.sent.append(content)
        if self.error is not None:
            raise self.error


def _notify_app(store: _BrokerStore, signer: _LeaseSigner, extractor, notifier, client_factory) -> TestClient:  # noqa: ANN001
    return client_factory(
        svc.create_broker_app(
            policy=_POLICY,
            store=store,
            signer=signer,
            extractor=extractor,
            origin="https://broker.example.test",
            verifier=FakeVerifier(),
            registration_verifier=FakeRegistrationVerifier(),
            notifier=notifier,
        )
    )


def _wait_for_event(store: _BrokerStore, request_id: str, event: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if any(e["event"] == event for e in store.audit_events(request_id)):
            return
        time.sleep(0.01)
    raise AssertionError(f"no {event} audit event")


class TestApprovalNotification:
    def test_create_sends_the_approval_link(self, store, signer, extractor, client_factory) -> None:  # noqa: ANN001
        notifier = _FakeNotifier()
        response = _notify_app(store, signer, extractor, notifier, client_factory=client_factory).post(
            "/v1/broker/requests", json=_body(reason="@everyone reboot")
        )

        assert response.status_code == 201
        request_id = response.json()["request_id"]
        _wait_for_event(store, request_id, "notification_sent")
        (content,) = notifier.sent
        assert "ct.reboot on CT 9001" in content
        assert "@everyone" not in content
        assert f"https://broker.example.test/v1/broker/requests/{request_id}/approval" in content

    @pytest.mark.parametrize("error", [RuntimeError("boom"), TimeoutError()])
    def test_send_failure_keeps_201_and_is_audited(self, store, signer, extractor, error, client_factory) -> None:  # noqa: ANN001
        notifier = _FakeNotifier(error)
        response = _notify_app(store, signer, extractor, notifier, client_factory=client_factory).post(
            "/v1/broker/requests", json=_body()
        )

        assert response.status_code == 201
        assert response.json()["status"] == "pending"
        _wait_for_event(store, response.json()["request_id"], "notification_failed")

    def test_env_without_webhook_file_disables_notification(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.delenv("PVE_BROKER_NOTIFY_WEBHOOK_FILE", raising=False)
        assert svc.DiscordNotifier.from_file("") is None
