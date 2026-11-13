"""Real local WebAuthn crypto; only the external mTLS frontend is substituted.

The software authenticator signs genuine P-256 WebAuthn messages. It is not a
physical-user-presence or browser compatibility test, and it invokes no PVE.
"""

import hashlib
import json
import secrets
from contextlib import closing

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from privilege_broker.pve.authorization import LeaseSigner, Policy, VerifiedClient
from privilege_broker.pve.common import b64encode
from privilege_broker.pve.service import BrokerStore, create_broker_app

RP_ID = "broker.example.test"
ORIGIN = "https://broker.example.test"
BOOTSTRAP = "test-enrollment-only"


class SoftwareAuthenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)

    def credential(self, challenge, *, registration=False, origin=ORIGIN, rp_id=RP_ID, uv=True, up=True, count=1):
        client_data = json.dumps(
            {
                "type": "webauthn.create" if registration else "webauthn.get",
                "challenge": challenge,
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()
        flags = int(up) | (0x04 if uv else 0) | (0x40 if registration else 0)
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")
        response = {"clientDataJSON": b64encode(client_data)}
        if registration:
            numbers = self.key.public_key().public_numbers()
            cose_key = cbor2.dumps(
                {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
            )
            auth_data += bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose_key
            response["attestationObject"] = b64encode(
                cbor2.dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})
            )
        else:
            response["authenticatorData"] = b64encode(auth_data)
            response["signature"] = b64encode(
                self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
            )
        return {
            "id": b64encode(self.credential_id),
            "rawId": b64encode(self.credential_id),
            "type": "public-key",
            "response": response,
        }


class TestFrontend:
    """A test-only substitute for the independently verified TLS frontend."""

    def extract(self, request):
        return VerifiedClient(identity="agent-demo", source_ip="192.0.2.10")


@pytest.fixture
def service(tmp_path):
    with closing(BrokerStore(tmp_path / "broker.sqlite3", BOOTSTRAP)) as store:
        app = create_broker_app(
            store=store,
            signer=LeaseSigner.generate(),
            policy=Policy(grants={"ct.reboot": frozenset({9001})}, snapshot_retention_days=7),
            extractor=TestFrontend(),
            rp_id=RP_ID,
            origin=ORIGIN,
            enrollment_enabled=True,
            enrollment_key=BOOTSTRAP,
        )
        with TestClient(app) as client:
            yield client, store


def begin_enrollment(client):
    response = client.post(
        "/v1/broker/enrollments", json={"operator": "operator-demo"}, headers={"X-Broker-Enrollment-Key": BOOTSTRAP}
    )
    assert response.status_code == 201
    enrollment_id = response.json()["enrollment_id"]
    options = client.get(f"/v1/broker/enrollments/{enrollment_id}/options")
    assert options.status_code == 200
    assert options.json()["authenticatorSelection"]["userVerification"] == "required"
    return enrollment_id, options.json()["challenge"]


def enroll(client):
    authenticator = SoftwareAuthenticator()
    enrollment_id, challenge = begin_enrollment(client)
    response = client.post(
        f"/v1/broker/enrollments/{enrollment_id}/complete",
        json={"credential": authenticator.credential(challenge, registration=True, count=0)},
    )
    assert response.json() == {"status": "enrolled", "operator": "operator-demo"}
    return authenticator


def begin_approval(client):
    public_key = (
        Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    )
    created = client.post(
        "/v1/broker/requests",
        json={
            "action": "ct.reboot",
            "ct_id": 9001,
            "reason": "Synthetic test",
            "requester": "agent",
            "ssh_public_key": public_key,
        },
    )
    assert created.status_code == 201
    request_id = created.json()["request_id"]
    options = client.get(f"/v1/broker/requests/{request_id}/approval/options")
    assert options.status_code == 200
    assert options.json()["userVerification"] == "required"
    return request_id, options.json()["challenge"]


def test_real_registration_approval_and_bootstrap_replay(service):
    client, store = service
    authenticator = enroll(client)
    request_id, challenge = begin_approval(client)
    credential = authenticator.credential(challenge)
    approved = client.post(f"/v1/broker/requests/{request_id}/approval", json={"credential": credential})
    assert approved.json() == {"status": "approved"}
    lease = client.get(f"/v1/broker/requests/{request_id}/lease")
    assert lease.status_code == 200
    assert lease.json()["signature"]
    assert store.list_passkeys()[0].sign_count == 1
    assert (
        client.post(f"/v1/broker/requests/{request_id}/approval", json={"credential": credential}).status_code == 409
    )
    assert (
        client.post(
            "/v1/broker/enrollments", json={"operator": "other"}, headers={"X-Broker-Enrollment-Key": BOOTSTRAP}
        ).status_code
        == 404
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"origin": "https://other.example.test"},
        {"rp_id": "other.example.test"},
        {"uv": False},
        {"up": False},
        {"challenge": b64encode(b"a different challenge")},
    ],
    ids=["wrong-origin", "wrong-rp", "no-user-verification", "no-user-presence", "wrong-challenge"],
)
def test_registration_rejects_a_validly_encoded_but_wrong_ceremony(service, changes):
    client, store = service
    enrollment_id, challenge = begin_enrollment(client)
    authenticator = SoftwareAuthenticator()
    credential = authenticator.credential(**{"challenge": challenge, "registration": True, **changes})
    response = client.post(f"/v1/broker/enrollments/{enrollment_id}/complete", json={"credential": credential})
    assert response.status_code == 409
    assert not store.has_passkey()
    # A rejected ceremony must not consume either the bootstrap or challenge.
    valid = client.post(
        f"/v1/broker/enrollments/{enrollment_id}/complete",
        json={"credential": authenticator.credential(challenge, registration=True, count=0)},
    )
    assert valid.json() == {"status": "enrolled", "operator": "operator-demo"}


@pytest.mark.parametrize(
    "changes",
    [
        {"origin": "https://other.example.test"},
        {"rp_id": "other.example.test"},
        {"uv": False},
        {"up": False},
        {"challenge": b64encode(b"a different challenge")},
    ],
    ids=["wrong-origin", "wrong-rp", "no-user-verification", "no-user-presence", "wrong-challenge"],
)
def test_assertion_rejects_wrong_ceremony_without_issuing_a_lease(service, changes):
    client, store = service
    authenticator = enroll(client)
    request_id, challenge = begin_approval(client)
    parameters = {"challenge": challenge, **changes}
    response = client.post(
        f"/v1/broker/requests/{request_id}/approval", json={"credential": authenticator.credential(**parameters)}
    )
    assert response.status_code == 409
    assert store.get_broker_request(request_id)["lease_json"] is None
    assert store.list_passkeys()[0].sign_count == 0


def test_counter_rollback_and_wrong_signing_key_are_refused(service):
    client, store = service
    authenticator = enroll(client)
    request_id, challenge = begin_approval(client)
    assert (
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": authenticator.credential(challenge, count=2)},
        ).status_code
        == 200
    )
    request_id, challenge = begin_approval(client)
    assert (
        client.post(
            f"/v1/broker/requests/{request_id}/approval",
            json={"credential": authenticator.credential(challenge, count=1)},
        ).status_code
        == 409
    )
    other = SoftwareAuthenticator()
    other.credential_id = authenticator.credential_id
    assert (
        client.post(
            f"/v1/broker/requests/{request_id}/approval", json={"credential": other.credential(challenge, count=3)}
        ).status_code
        == 409
    )
    assert store.get_broker_request(request_id)["lease_json"] is None
    assert store.list_passkeys()[0].sign_count == 2
