"""Optional broker provider for typed UniFi firewall policy approvals."""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator
from webauthn import generate_authentication_options
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from .pve.authorization import (
    LeaseSigner,
    TrustedProxyMtlsExtractor,
    VerifiedClient,
    b64decode,
    b64encode,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi import FastAPI

    from .pve.service import AssertionVerifier, BrokerStore

API_PREFIX = "/v1/unifi/requests"
GRANT_SCHEMA = "unifi-firewall-approval.v1"
REQUEST_TTL = 300
GRANT_TTL = 90
MAX_PROPOSAL_BYTES = 32_768
Operation = Literal["create", "update", "delete"]
Rule = dict[str, JsonValue]


def _canonical(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class UniFiTarget(BaseModel):
    """Configured tuple of controller identities that can be changed."""

    model_config = ConfigDict(extra="forbid")
    site_id: UUID
    source_zone: UUID
    destination_zone: UUID


class UniFiOrder(BaseModel):
    """Zone-pair ordering as read from the Integration API."""

    model_config = ConfigDict(extra="forbid")
    beforeSystemDefined: list[UUID] = Field(max_length=2000)
    afterSystemDefined: list[UUID] = Field(max_length=2000)


class UniFiProposal(BaseModel):
    """A complete, controller-state-bound approval preview."""

    model_config = ConfigDict(extra="forbid")
    operation: Operation
    target: UniFiTarget
    policy_id: UUID | None
    before: Rule | None
    after: Rule | None
    order: UniFiOrder
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]

    @model_validator(mode="after")
    def check_operation(self) -> UniFiProposal:
        if self.operation == "create":
            if self.policy_id is not None or self.before is not None or self.after is None:
                raise ValueError("create needs a new rule preview")
            if self.after.get("enabled") is not False:
                raise ValueError("create needs a disabled rule")
        else:
            if self.policy_id is None or self.before is None or self.before.get("id") != str(self.policy_id):
                raise ValueError("update and delete need the existing rule preview")
            metadata = self.before.get("metadata")
            if not isinstance(metadata, dict) or metadata.get("origin") != "USER_DEFINED":
                raise ValueError("only user-defined policies may be changed")
            if (self.after is None) != (self.operation == "delete"):
                raise ValueError("the proposed after state does not match the operation")

        for rule in (self.before, self.after):
            if rule is None:
                continue
            for side, zone in (("source", self.target.source_zone), ("destination", self.target.destination_zone)):
                selector = rule.get(side)
                if not isinstance(selector, dict) or selector.get("zoneId") != str(zone):
                    raise ValueError("the rule zone does not match its target")
        return self


class UniFiPolicy(BaseModel):
    """Explicit requester, executor, and target scope for this provider."""

    model_config = ConfigDict(extra="forbid")
    requesters: dict[str, str | list[str]] = Field(min_length=1)
    executor: str = Field(min_length=1)
    executor_sources: list[str] = Field(min_length=1)
    targets: list[UniFiTarget] = Field(min_length=1)

    @model_validator(mode="after")
    def check_identities(self) -> UniFiPolicy:
        if self.executor in self.requesters or any(not name.strip() for name in self.requesters):
            raise ValueError("request and execution identities must be distinct")
        return self


class Assertion(BaseModel):
    credential: dict[str, Any]


class UniFiResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: Literal["succeeded", "refused", "failed", "uncertain"]
    code: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
    observed_policy_id: UUID | None = None


def install_unifi_routes(
    app: FastAPI,
    store: BrokerStore,
    signer: LeaseSigner,
    verifier: AssertionVerifier,
    policy: UniFiPolicy,
    operator_token: str,
    rp_id: str,
    origin: str,
    template: str,
    notify: Callable[[str, str], None] | None,
) -> None:
    """Bind the provider to the shared passkey and audit database."""
    if len(operator_token) < 32:
        raise ValueError("the UniFi operator proxy token must be configured")
    requesters = TrustedProxyMtlsExtractor(policy.requesters)
    executor = TrustedProxyMtlsExtractor({policy.executor: policy.executor_sources})
    table = store.connection
    with store._lock:
        table.execute(
            """
            CREATE TABLE IF NOT EXISTS unifi_broker_requests (
                request_id TEXT PRIMARY KEY,
                proposal TEXT NOT NULL,
                digest TEXT NOT NULL,
                requester TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                challenge BLOB,
                challenge_expires INTEGER,
                approved_by TEXT,
                claimed_at INTEGER,
                claimed_by TEXT,
                result TEXT
            )
            """
        )

    def _client(request: Request, *, execution: bool = False) -> VerifiedClient:
        extractor = executor if execution else requesters
        try:
            return extractor.extract(request)
        except PermissionError:
            raise HTTPException(403, "UniFi broker client is not authorized") from None

    def _operator(request: Request, *, changing: bool = False) -> None:
        if (
            request.client is None
            or request.client.host not in {"127.0.0.1", "::1"}
            or (changing and request.headers.get("origin") != origin)
            or not hmac.compare_digest(
                request.headers.get("x-unifi-broker-operator", "").encode(), operator_token.encode()
            )
        ):
            raise HTTPException(403, "operator proxy authorization is required")

    def _row(request_id: UUID) -> dict[str, Any]:
        row = table.execute("SELECT * FROM unifi_broker_requests WHERE request_id = ?", (str(request_id),)).fetchone()
        if row is None:
            raise HTTPException(404, "request not found")
        return dict(row)

    def _state(row: dict[str, Any], now: int) -> str:
        if row["claimed_at"] is None and row["status"] in ("pending", "approved") and now >= row["expires_at"]:
            return "expired"
        return row["status"]

    def _view(row: dict[str, Any], now: int) -> dict[str, Any]:
        result = json.loads(row["result"]) if row["result"] else None
        execution = "not_executed"
        if row["claimed_at"] is not None:
            deadline = min(row["expires_at"], row["claimed_at"] + GRANT_TTL)
            execution = "executing" if now < deadline else "uncertain"
        if result is not None:
            execution = result["state"]
        return {
            "request_id": row["request_id"],
            "status": _state(row, now),
            "execution_state": execution,
            "result": result,
        }

    @app.post(API_PREFIX, status_code=201)
    def create(body: UniFiProposal, request: Request, background_tasks: BackgroundTasks) -> dict[str, Any]:
        client = _client(request)
        if body.target not in policy.targets:
            raise HTTPException(403, "firewall zone pair is outside the broker policy")
        try:
            proposal = _canonical(body.model_dump(mode="json"))
        except ValueError:
            raise HTTPException(422, "the proposal must contain finite JSON values") from None
        if len(proposal.encode()) > MAX_PROPOSAL_BYTES:
            raise HTTPException(413, "firewall proposal exceeds the broker limit")
        digest = hashlib.sha256(proposal.encode()).hexdigest()
        request_id = str(uuid4())
        now = int(time.time())
        with store._lock, store._transaction():
            table.execute(
                """
                INSERT INTO unifi_broker_requests
                    (request_id, proposal, digest, requester, source, status, expires_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (request_id, proposal, digest, client.identity, client.source_ip, now + REQUEST_TTL),
            )
            store._audit(
                request_id, "unifi_request_created", f"{body.operation} by {client.identity}, digest {digest}", now
            )
        url = f"{origin}{API_PREFIX}/{request_id}/approval"
        if notify is not None:
            background_tasks.add_task(notify, request_id, f"UniFi firewall approval requested. {url}")
        return {"request_id": request_id, "status": "pending", "approval_url": url}

    @app.get(API_PREFIX + "/{request_id}")
    def status(request_id: UUID, request: Request) -> dict[str, Any]:
        client = _client(request)
        with store._lock:
            row = _row(request_id)
            if (row["requester"], row["source"]) != (client.identity, client.source_ip):
                raise HTTPException(404, "request not found")
            return _view(row, int(time.time()))

    @app.get(API_PREFIX + "/{request_id}/approval", response_class=HTMLResponse)
    def approval_page(request_id: UUID, request: Request) -> HTMLResponse:
        _operator(request)
        with store._lock:
            row = _row(request_id)
        proposal = json.loads(row["proposal"])
        details = {
            "action": proposal["operation"],
            "reason": proposal["reason"],
            "mtls_identity": row["requester"],
            "digest": row["digest"],
            "target": _canonical(proposal["target"]),
            "policy_id": proposal["policy_id"],
            "before": _canonical(proposal["before"]),
            "after": _canonical(proposal["after"]),
            "ordering": _canonical(proposal["order"]),
        }

        def json_attribute(value: object) -> str:
            return html.escape(_canonical(value), quote=True)

        body = template.format(
            request_id=json_attribute(str(request_id)),
            details=json_attribute(details),
            expires_at=json_attribute(row["expires_at"]),
            title="UniFi firewall policy approval",
            heading="UniFi firewall policy approval",
            request_api_prefix=API_PREFIX,
        )

        return HTMLResponse(body, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    @app.get(API_PREFIX + "/{request_id}/status")
    def browser_status(request_id: UUID, request: Request) -> dict[str, str]:
        _operator(request)
        with store._lock:
            return {"status": _state(_row(request_id), int(time.time()))}

    @app.get(API_PREFIX + "/{request_id}/approval/options")
    def approval_options(request_id: UUID, request: Request) -> dict[str, Any]:
        _operator(request)
        with store._lock, store._transaction():
            row = _row(request_id)
            now = int(time.time())
            if _state(row, now) != "pending":
                raise HTTPException(409, "request is not awaiting approval")
            passkeys = store.list_passkeys()
            if not passkeys:
                raise HTTPException(409, "no registered passkeys")
            binding = f"{GRANT_SCHEMA}/{request_id}/{row['digest']}/{row['expires_at']}".encode()
            challenge = hashlib.sha256(secrets.token_bytes(32) + binding).digest()
            table.execute(
                "UPDATE unifi_broker_requests SET challenge = ?, challenge_expires = ? WHERE request_id = ?",
                (challenge, row["expires_at"], str(request_id)),
            )
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[PublicKeyCredentialDescriptor(id=b64decode(key.credential_id)) for key in passkeys],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return json.loads(options_to_json(options))

    @app.post(API_PREFIX + "/{request_id}/approval")
    def approve(request_id: UUID, body: Assertion, request: Request) -> dict[str, str]:
        _operator(request, changing=True)
        with store._lock, store._transaction():
            row = _row(request_id)
            now = int(time.time())
            if _state(row, now) != "pending" or row["challenge"] is None or now >= row["challenge_expires"]:
                raise HTTPException(409, "request or challenge is no longer pending")
            key = next((key for key in store.list_passkeys() if key.credential_id == body.credential.get("id")), None)
            if key is None:
                raise HTTPException(409, "credential is not registered")
            try:
                operator, count = verifier.verify(body.credential, row["challenge"], key)
            except ValueError:
                raise HTTPException(409, "passkey verification failed") from None
            now = int(time.time())
            if operator != key.operator or _state(row, now) != "pending":
                raise HTTPException(409, "approval binding failed")
            table.execute(
                "UPDATE broker_passkeys SET sign_count = ? WHERE credential_id = ?", (count, key.credential_id)
            )
            table.execute(
                """
                UPDATE unifi_broker_requests SET status = 'approved', approved_by = ?, challenge = NULL
                WHERE request_id = ?
                """,
                (operator, str(request_id)),
            )
            store._audit(
                str(request_id), "unifi_request_approved", f"operator {operator}, digest {row['digest']}", now
            )
        return {"status": "approved"}

    @app.post(API_PREFIX + "/{request_id}/denial")
    def deny(request_id: UUID, request: Request) -> dict[str, str]:
        _operator(request, changing=True)
        with store._lock, store._transaction():
            now = int(time.time())
            if _state(_row(request_id), now) != "pending":
                raise HTTPException(409, "request is not awaiting a decision")
            table.execute(
                "UPDATE unifi_broker_requests SET status = 'denied', challenge = NULL WHERE request_id = ?",
                (str(request_id),),
            )
            store._audit(str(request_id), "unifi_request_denied", "denied on operator route", now)
        return {"status": "denied"}

    @app.get("/v1/unifi/work")
    def work(request: Request) -> dict[str, list[str]]:
        worker = _client(request, execution=True)
        with store._lock:
            now = int(time.time())
            rows = table.execute(
                """
                SELECT request_id FROM unifi_broker_requests
                WHERE status = 'approved' AND claimed_at IS NULL AND expires_at > ?
                ORDER BY expires_at, request_id LIMIT 20
                """,
                (now,),
            ).fetchall()
            recover = table.execute(
                """
                SELECT request_id FROM unifi_broker_requests
                WHERE claimed_by = ? AND result IS NULL AND min(expires_at, claimed_at + ?) <= ?
                ORDER BY claimed_at, request_id LIMIT 20
                """,
                (worker.identity, GRANT_TTL, now),
            ).fetchall()
        return {
            "request_ids": [row["request_id"] for row in rows],
            "recover_ids": [row["request_id"] for row in recover],
        }

    @app.get(API_PREFIX + "/{request_id}/recovery")
    def recovery(request_id: UUID, request: Request) -> dict[str, Any]:
        worker = _client(request, execution=True)
        with store._lock:
            row = _row(request_id)
            if row["claimed_by"] != worker.identity or row["result"] is not None:
                raise HTTPException(409, "reconciliation is unavailable")
            if int(time.time()) < min(row["expires_at"], row["claimed_at"] + GRANT_TTL):
                raise HTTPException(409, "claim is still within its execution window")
            proposal = UniFiProposal.model_validate_json(row["proposal"])
            if proposal.target not in policy.targets:
                raise HTTPException(403, "firewall zone pair is outside the broker policy")
            return {"proposal": proposal.model_dump(mode="json")}

    @app.post(API_PREFIX + "/{request_id}/claim")
    def claim(request_id: UUID, request: Request) -> dict[str, Any]:
        client = _client(request, execution=True)
        with store._lock, store._transaction():
            row = _row(request_id)
            now = int(time.time())
            if _state(row, now) != "approved" or row["claimed_at"] is not None:
                raise HTTPException(409, "execution authorization is unavailable")
            proposal = UniFiProposal.model_validate_json(row["proposal"])
            if proposal.target not in policy.targets:
                raise HTTPException(403, "firewall zone pair is outside the broker policy")
            if hashlib.sha256(row["proposal"].encode()).hexdigest() != row["digest"]:
                raise HTTPException(409, "approval digest does not match")
            grant = {
                "schema": GRANT_SCHEMA,
                "request_id": str(request_id),
                "proposal_digest": row["digest"],
                "executor": client.identity,
                "issued_at": now,
                "expires_at": min(row["expires_at"], now + GRANT_TTL),
            }
            signature = signer.private_key.sign(_canonical(grant).encode())
            table.execute(
                "UPDATE unifi_broker_requests SET claimed_at = ?, claimed_by = ? WHERE request_id = ?",
                (now, client.identity, str(request_id)),
            )
            store._audit(
                str(request_id), "unifi_execution_claimed", f"executor {client.identity}, digest {row['digest']}", now
            )
        return {"grant": grant, "signature": b64encode(signature), "proposal": proposal.model_dump(mode="json")}

    @app.post(API_PREFIX + "/{request_id}/result")
    def result(request_id: UUID, body: UniFiResult, request: Request) -> dict[str, Any]:
        client = _client(request, execution=True)
        encoded = _canonical(body.model_dump(mode="json"))
        with store._lock, store._transaction():
            row = _row(request_id)
            if row["claimed_by"] != client.identity or row["result"] not in (None, encoded):
                raise HTTPException(409, "result has no claim or conflicts with a stored result")
            now = int(time.time())
            if row["result"] is None:
                table.execute(
                    "UPDATE unifi_broker_requests SET result = ? WHERE request_id = ?", (encoded, str(request_id))
                )
                store._audit(str(request_id), "unifi_execution_result", f"{body.state}: {body.code}", now)
            return _view(_row(request_id), now)


def load_unifi_policy(path: Path) -> UniFiPolicy:
    return UniFiPolicy.model_validate_json(path.read_bytes())
