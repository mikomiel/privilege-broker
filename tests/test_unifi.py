from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from privilege_broker.pve.authorization import LeaseSigner, b64decode, b64encode
from privilege_broker.pve.common import Policy
from privilege_broker.pve.service import BrokerPasskey, BrokerStore, create_broker_app
from privilege_broker.unifi import API_PREFIX, UniFiPolicy

SITE = "a0000000-0000-4000-8000-000000000001"
SOURCE = "a0000000-0000-4000-8000-000000000002"
DESTINATION = "a0000000-0000-4000-8000-000000000003"
RULE = "a0000000-0000-4000-8000-000000000004"
PROXY_TOKEN = "synthetic-operator-proxy-test-value"
PASSKEY_ID = b64encode(b"synthetic-passkey")
OPERATOR = {"x-unifi-broker-operator": PROXY_TOKEN, "origin": "https://broker.example.test"}


def headers(identity: str, address: str) -> dict[str, str]:
    return {"x-pve-broker-mtls-identity": identity, "x-pve-broker-mtls-source-ip": address}


REQUESTER = headers("agent-example", "192.0.2.10")
OTHER = headers("agent-other", "192.0.2.11")
WORKER = headers("executor-example", "192.0.2.12")


class TestVerifier:
    __test__ = False

    def verify(self, credential, challenge, passkey):
        if credential.get("challenge") != b64encode(challenge):
            raise ValueError("challenge does not match")
        return passkey.operator, passkey.sign_count + 1


def proposal(operation: str = "create") -> dict:
    rule = {
        "source": {"zoneId": SOURCE},
        "destination": {"zoneId": DESTINATION},
        "enabled": False,
    }
    before = None if operation == "create" else {**rule, "id": RULE, "metadata": {"origin": "USER_DEFINED"}}
    return {
        "operation": operation,
        "target": {"site_id": SITE, "source_zone": SOURCE, "destination_zone": DESTINATION},
        "policy_id": None if before is None else RULE,
        "before": before,
        "after": None if operation == "delete" else rule,
        "order": {"beforeSystemDefined": [], "afterSystemDefined": []},
        "reason": "Test a firewall change",
    }


def app_at(db: Path, signer: LeaseSigner, *, enabled: bool = True):
    store = BrokerStore(db)
    if not store.has_passkey():
        store.add_passkey(BrokerPasskey(PASSKEY_ID, "operator-example", b"example", 0))
    policy = UniFiPolicy(
        requesters={"agent-example": "192.0.2.10", "agent-other": "192.0.2.11"},
        executor="executor-example",
        executor_sources=["192.0.2.12"],
        targets=[proposal()["target"]],
    )
    app = create_broker_app(
        store,
        signer,
        policy=Policy({}, 7),
        verifier=TestVerifier(),
        unifi_policy=policy if enabled else None,
        unifi_operator_token=PROXY_TOKEN,
    )
    return store, TestClient(app, client=("127.0.0.1", 40000))


def approve(client, url: str) -> dict:
    options = client.get(f"{url}/approval/options", headers=OPERATOR)
    assert options.status_code == 200, options.text
    return {"credential": {"id": PASSKEY_ID, "challenge": options.json()["challenge"]}}


def test_optional_routes_are_absent_by_default(tmp_path):
    store, client = app_at(tmp_path / "broker.sqlite", LeaseSigner.generate(), enabled=False)
    try:
        assert client.post(API_PREFIX, json=proposal(), headers=REQUESTER).status_code == 404
    finally:
        store.close()


@pytest.mark.parametrize("operation", ["create", "update", "delete"])
def test_approved_lifecycle(tmp_path, operation):
    signer = LeaseSigner.generate()
    store, client = app_at(tmp_path / "broker.sqlite", signer)
    try:
        created = client.post(API_PREFIX, json=proposal(operation), headers=REQUESTER)
        assert created.status_code == 201, created.text
        request_id = created.json()["request_id"]
        url = f"{API_PREFIX}/{request_id}"
        assert client.get(url, headers=OTHER).status_code == 404
        assert client.get(f"{url}/approval").status_code == 403
        page = client.get(f"{url}/approval", headers=OPERATOR)
        assert page.status_code == 200
        assert "Approval recorded." in page.text
        assert "PVE operation" not in page.text
        assert client.post(f"{url}/claim", headers=WORKER).status_code == 409
        credential = approve(client, url)
        wrong_origin = {**OPERATOR, "origin": "https://other.example.test"}
        assert client.post(f"{url}/approval", json=credential, headers=wrong_origin).status_code == 403
        assert client.post(f"{url}/approval", json=credential, headers=OPERATOR).status_code == 200
        assert client.post(f"{url}/approval", json=credential, headers=OPERATOR).status_code == 409
        assert client.post(f"{url}/claim", headers=REQUESTER).status_code == 403
        assert client.get("/v1/unifi/work", headers=WORKER).json() == {"request_ids": [request_id], "recover_ids": []}
        with ThreadPoolExecutor(max_workers=2) as workers:
            claims = list(workers.map(lambda _: client.post(f"{url}/claim", headers=WORKER), range(2)))
        assert sorted(response.status_code for response in claims) == [200, 409]
        claimed = next(response.json() for response in claims if response.status_code == 200)
        grant = claimed["grant"]
        signed_bytes = json.dumps(grant, sort_keys=True, separators=(",", ":")).encode()
        signer.private_key.public_key().verify(b64decode(claimed["signature"]), signed_bytes)
        proposed = json.dumps(claimed["proposal"], sort_keys=True, separators=(",", ":")).encode()
        assert grant["proposal_digest"] == hashlib.sha256(proposed).hexdigest()
        assert claimed["proposal"] == proposal(operation)
        assert client.get(url, headers=REQUESTER).json()["execution_state"] == "executing"
        result = {"state": "succeeded", "code": "UNIFI_VERIFIED", "observed_policy_id": RULE}
        assert client.post(f"{url}/result", json=result, headers=REQUESTER).status_code == 403
        assert client.post(f"{url}/result", json=result, headers=WORKER).status_code == 200
        assert client.get(url, headers=REQUESTER).json()["result"] == result
        assert client.post(f"{url}/result", json=result, headers=WORKER).status_code == 200
    finally:
        store.close()
    reopened, client = app_at(tmp_path / "broker.sqlite", signer)
    try:
        assert client.post(f"{url}/claim", headers=WORKER).status_code == 409
        assert client.get(url, headers=REQUESTER).json()["execution_state"] == "succeeded"
    finally:
        reopened.close()


def test_rejects_protected_rules_and_cross_request_assertions(tmp_path):
    store, client = app_at(tmp_path / "broker.sqlite", LeaseSigner.generate())
    try:
        invalid = proposal("delete")
        invalid["before"]["metadata"]["origin"] = "SYSTEM_DEFINED"
        assert client.post(API_PREFIX, json=invalid, headers=REQUESTER).status_code == 422
        first = client.post(API_PREFIX, json=proposal(), headers=REQUESTER).json()["request_id"]
        second = client.post(API_PREFIX, json=proposal(), headers=REQUESTER).json()["request_id"]
        credential = approve(client, f"{API_PREFIX}/{first}")
        approve(client, f"{API_PREFIX}/{second}")
        response = client.post(f"{API_PREFIX}/{second}/approval", json=credential, headers=OPERATOR)
        assert response.status_code == 409
    finally:
        store.close()


def test_expired_claim_only_offers_readback(tmp_path):
    store, client = app_at(tmp_path / "broker.sqlite", LeaseSigner.generate())
    try:
        request_id = client.post(API_PREFIX, json=proposal("update"), headers=REQUESTER).json()["request_id"]
        url = f"{API_PREFIX}/{request_id}"
        credential = approve(client, url)
        assert client.post(f"{url}/approval", json=credential, headers=OPERATOR).status_code == 200
        assert client.post(f"{url}/claim", headers=WORKER).status_code == 200
        assert client.get(f"{url}/recovery", headers=WORKER).status_code == 409
        store.connection.execute("UPDATE unifi_broker_requests SET expires_at = 0")
        assert client.get("/v1/unifi/work", headers=WORKER).json() == {
            "request_ids": [],
            "recover_ids": [request_id],
        }
        assert client.get(f"{url}/recovery", headers=WORKER).json() == {"proposal": proposal("update")}
        assert client.post(f"{url}/claim", headers=WORKER).status_code == 409
        assert client.get(f"{url}/recovery", headers=REQUESTER).status_code == 403
    finally:
        store.close()


@pytest.mark.parametrize("expected_status", ["denied", "expired"])
def test_unapproved_requests_cannot_be_claimed(tmp_path, expected_status):
    store, client = app_at(tmp_path / "broker.sqlite", LeaseSigner.generate())
    try:
        request_id = client.post(API_PREFIX, json=proposal(), headers=REQUESTER).json()["request_id"]
        url = f"{API_PREFIX}/{request_id}"
        credential = approve(client, url)
        if expected_status == "denied":
            denied = client.post(f"{url}/denial", headers=OPERATOR)
            assert denied.json() == {"status": "denied"}
        else:
            store.connection.execute("UPDATE unifi_broker_requests SET expires_at = 0")
        status = client.get(url, headers=REQUESTER).json()
        assert status["status"] == expected_status
        assert status["execution_state"] == "not_executed"
        assert client.post(f"{url}/approval", json=credential, headers=OPERATOR).status_code == 409
        assert client.post(f"{url}/claim", headers=WORKER).status_code == 409
        assert client.get("/v1/unifi/work", headers=WORKER).json() == {
            "request_ids": [],
            "recover_ids": [],
        }
    finally:
        store.close()
