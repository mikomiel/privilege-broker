#!/usr/bin/env python3
"""Broker-facing FastAPI service for PVE SSH certificate gate.

Separates browser/WebAuthn approval endpoints from mTLS-only client
request/certificate-fetch endpoints.  Uses the injectable
``MtlsIdentityExtractor`` protocol and rejects every
request by default unless a verified mTLS context is supplied.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Protocol

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIASGIMiddleware
from slowapi.util import get_remote_address
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from ..notifications import DiscordNotifier, approval_message, describe_error
from .authorization import (
    EXCLUDED_ACTIONS,
    CanonicalRequest,
    CapabilityProfile,
    CertificateCommandBuilder,
    CertificatePolicy,
    LeaseFactory,
    LeaseSigner,
    MtlsIdentityExtractor,
    Policy,
    PolicyError,
    RejectingExtractor,
    TrustedProxyMtlsExtractor,
    VerifiedClient,
    _public_key_fingerprint,
    b64decode,
    b64encode,
    load_policy,
)
from .authorization import create_request as broker_create_request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROKER_GRANT_TTL_SECONDS = 300  # 5 minutes
CHALLENGE_TTL_SECONDS = 300

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CreateBrokerRequest(BaseModel):
    """Canonical broker request body — mTLS-provided fields override body."""

    action: str
    ct_id: int = Field(strict=True)
    reason: str = Field(max_length=500)
    requester: str = Field(min_length=1, max_length=100)
    ssh_public_key: str
    self_reported_hostname: str = Field(default="", max_length=255)


class CompleteAssertion(BaseModel):
    credential: dict[str, Any]


class BeginEnrollment(BaseModel):
    operator: str = Field(min_length=1, max_length=100)


class CompleteRegistration(BaseModel):
    credential: dict[str, Any]


# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BrokerPasskey:
    credential_id: str
    operator: str
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class RegistrationResult:
    credential_id: str
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class _MtlsIdentity:
    """mTLS subject made available to request-scoped infrastructure."""

    subject: str


def _mtls_identity_key(request: Request) -> str:
    """Use mTLS subject if available, fall back to IP."""
    mtls = getattr(request.state, "mtls_identity", None)
    if mtls and mtls.subject:
        return mtls.subject
    return get_remote_address(request)


# ---------------------------------------------------------------------------
# WebAuthn verifier protocols
# ---------------------------------------------------------------------------


class AssertionVerifier(Protocol):
    """Verifies a WebAuthn assertion for an existing passkey."""

    def verify(self, credential: dict[str, Any], challenge: bytes, passkey: BrokerPasskey) -> tuple[str, int]: ...


class RegistrationVerifier(Protocol):
    """Verifies a new WebAuthn credential registration."""

    def verify(self, credential: dict[str, Any], challenge: bytes) -> RegistrationResult: ...


class WebAuthnAssertionVerifier:
    """Real WebAuthn assertion verifier using the webauthn package."""

    def __init__(self, rp_id: str, origin: str) -> None:
        self._rp_id = rp_id
        self._origin = origin

    def verify(self, credential: dict[str, Any], challenge: bytes, passkey: BrokerPasskey) -> tuple[str, int]:
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                credential_public_key=passkey.public_key,
                credential_current_sign_count=passkey.sign_count,
                require_user_verification=True,
            )
        except WebAuthnException:
            raise ValueError("passkey assertion verification failed") from None
        return passkey.operator, verified.new_sign_count


class WebAuthnRegistrationVerifier:
    """Real WebAuthn registration verifier using the webauthn package."""

    def __init__(self, rp_id: str, origin: str) -> None:
        self._rp_id = rp_id
        self._origin = origin

    def verify(self, credential: dict[str, Any], challenge: bytes) -> RegistrationResult:
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self._rp_id,
                expected_origin=self._origin,
                require_user_verification=True,
            )
        except WebAuthnException:
            raise ValueError("passkey registration verification failed") from None
        return RegistrationResult(
            b64encode(verified.credential_id),
            verified.credential_public_key,
            verified.sign_count,
        )


# ---------------------------------------------------------------------------
# SSH certificate signer — runs ssh-keygen (shell=False)
# ---------------------------------------------------------------------------


class CaCertificateSigner:
    """Signs SSH certificates via ``ssh-keygen -s`` (no shell).

    The CA private key is never read by Python — only the *path* is passed
    to the ``ssh-keygen`` child process.  Temp files are cleaned up after
    each signing operation.
    """

    def __init__(self, ca_key_path: str, builder: CertificateCommandBuilder) -> None:
        self._ca_key_path = ca_key_path
        self._builder = builder

    def sign(self, public_key_pem: str, serial: str) -> str:
        """Sign *public_key_pem* with the CA key and return the SSH certificate.

        Raises ``ValueError`` for invalid inputs and ``RuntimeError`` for
        CA-key or ``ssh-keygen`` failures.
        """
        import os
        import subprocess
        import tempfile

        if not os.path.isfile(self._ca_key_path):
            raise RuntimeError(f"CA key not found: {self._ca_key_path}")

        self._builder.validate_public_key(public_key_pem)

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write(public_key_pem)
            tmp.write("\n")
            pubkey_path = tmp.name

        try:
            os.chmod(pubkey_path, 0o600)
            argv = self._builder.build_argv(self._ca_key_path, pubkey_path, serial)

            result = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                stderr = result.stderr.strip() or "unknown error"
                raise RuntimeError(f"ssh-keygen signing failed: {stderr}")

            cert_path = pubkey_path + "-cert.pub"
            if not os.path.isfile(cert_path):
                raise RuntimeError("ssh-keygen did not produce a certificate file")

            with open(cert_path, encoding="ascii") as f:
                certificate = f.read().strip()
        finally:
            _safe_unlink(pubkey_path)
            _safe_unlink(pubkey_path + "-cert.pub")

        return certificate


def _safe_unlink(path: str) -> None:
    import os

    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Broker Store — SQLite persistence with atomic transitions
# ---------------------------------------------------------------------------


class BrokerStore:
    """Persists broker request lifecycle, passkeys, challenges, audit.

    All state transitions go through the store, which holds an internal
    thread-safe SQLite connection.  Callers should use one store instance
    per process.
    """

    def __init__(self, database: Path, enrollment_key: str = "") -> None:
        """*enrollment_key* is the configured bootstrap secret; empty disables bootstrap."""
        self._enrollment_key = enrollment_key
        database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(database, check_same_thread=False, isolation_level=None)
        try:
            # Passkeys, challenges and audit must remain private under any umask.
            os.chmod(database, 0o600)
            self._connection.row_factory = sqlite3.Row
            self._setup_schema()
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        """Release the owned SQLite connection after its users have stopped."""
        with self._lock:
            self._connection.close()

    def _setup_schema(self) -> None:
        self._connection.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS broker_passkeys (
              credential_id TEXT PRIMARY KEY,
              operator TEXT NOT NULL,
              public_key BLOB NOT NULL,
              sign_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS broker_enrollments (
              enrollment_id TEXT PRIMARY KEY,
              operator TEXT NOT NULL,
              challenge BLOB NOT NULL,
              expires_at INTEGER NOT NULL,
              status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS broker_bootstrap_state (
              state TEXT PRIMARY KEY,
              consumed_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS broker_requests (
              request_id TEXT PRIMARY KEY,
              action TEXT NOT NULL,
              ct_id INTEGER NOT NULL,
              reason TEXT NOT NULL,
              requester TEXT NOT NULL,
              self_reported_hostname TEXT NOT NULL,
              mtls_identity TEXT NOT NULL,
              observed_source_ip TEXT NOT NULL,
              ssh_public_key TEXT NOT NULL,
              ssh_fingerprint TEXT NOT NULL,
              request_nonce TEXT NOT NULL,
              canonical TEXT NOT NULL,
              digest TEXT NOT NULL,
              status TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              approved_by TEXT,
              lease_id TEXT,
              lease_json TEXT,
              certificate_fetched INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS broker_challenges (
              request_id TEXT PRIMARY KEY,
              challenge BLOB NOT NULL,
              expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS broker_audit_events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at INTEGER NOT NULL,
              request_id TEXT NOT NULL,
              event TEXT NOT NULL,
              summary TEXT NOT NULL
            );
            """
        )
        # Added after deployment: every database, new or old, gains the column
        # here so there is one schema path.
        columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(broker_requests)")}
        if "certificate_serial" not in columns:
            self._connection.execute("ALTER TABLE broker_requests ADD COLUMN certificate_serial INTEGER")

    def _audit(self, request_id: str, event: str, summary: str, now: int) -> None:
        # Takes the lock itself rather than trusting every call site: most
        # callers already hold it (the lock is reentrant, so that is free), but
        # fetch_lease and fetch_certificate_gate audit outside any critical
        # section.  An unsynchronised write on the shared connection surfaces as
        # `sqlite3.InterfaceError: bad parameter or other API misuse` under
        # concurrency, which is what made test_concurrent_certificate_fetch_
        # issues_once flake.
        with self._lock:
            self._connection.execute(
                "INSERT INTO broker_audit_events (created_at, request_id, event, summary) VALUES (?, ?, ?, ?)",
                (now, request_id, event, summary[:500]),
            )

    # -- Passkey management ------------------------------------------------

    def has_passkey(self) -> bool:
        """Return whether any broker passkey has been registered."""
        with self._lock:
            row = self._connection.execute("SELECT 1 FROM broker_passkeys LIMIT 1").fetchone()
        return row is not None

    def consume_bootstrap(self, enrollment_key: str) -> bool:
        """Atomically reserve the one-time enrollment bootstrap.

        *enrollment_key* must equal the key this store was configured with.
        The caller must have already completed WebAuthn verification.  When
        called inside a store transaction, its state change participates in
        that transaction so the bootstrap reservation and passkey creation
        commit together.
        """
        if not self._enrollment_key or not secrets.compare_digest(self._enrollment_key, enrollment_key):
            return False

        with self._lock:
            owns_transaction = not self._connection.in_transaction
            if owns_transaction:
                self._connection.execute("BEGIN IMMEDIATE")
            try:
                if self.has_passkey():
                    if owns_transaction:
                        self._connection.execute("COMMIT")
                    return False
                cursor = self._connection.execute(
                    "INSERT OR IGNORE INTO broker_bootstrap_state VALUES ('consumed', ?)",
                    (int(time.time()),),
                )
                if owns_transaction:
                    self._connection.execute("COMMIT")
                return cursor.rowcount == 1
            except Exception:
                if owns_transaction and self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def audit_bootstrap_rejection(self, summary: str, now: int | None = None) -> None:
        """Record a rejected enrollment bootstrap without an enrollment ID."""
        with self._lock:
            self._audit(
                "bootstrap",
                "enrollment_bootstrap_rejected",
                summary,
                now or int(time.time()),
            )

    def list_passkeys(self) -> list[BrokerPasskey]:
        with self._lock:
            rows = self._connection.execute("SELECT * FROM broker_passkeys").fetchall()
        return [BrokerPasskey(r["credential_id"], r["operator"], r["public_key"], r["sign_count"]) for r in rows]

    def get_pending_enrollment(self, enrollment_id: str, now: int | None = None) -> dict[str, Any]:
        """Return a pending, unexpired enrollment or raise ``ValueError``."""
        now = now or int(time.time())
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM broker_enrollments WHERE enrollment_id = ?",
                (enrollment_id,),
            ).fetchone()
        if row is None or row["status"] != "pending" or row["expires_at"] < now:
            raise ValueError("enrollment is not pending")
        return dict(row)

    def add_passkey(self, passkey: BrokerPasskey) -> None:
        """Insert or replace a passkey."""
        with self._lock:
            self._connection.execute(
                "INSERT OR REPLACE INTO broker_passkeys VALUES (?, ?, ?, ?)",
                (
                    passkey.credential_id,
                    passkey.operator,
                    passkey.public_key,
                    passkey.sign_count,
                ),
            )

    def begin_enrollment(self, operator: str, now: int | None = None) -> tuple[str, bytes, list[BrokerPasskey]]:
        """Start a passkey enrollment, returning (enrollment_id, challenge, existing_passkeys)."""
        normalized = operator.strip()
        if not 1 <= len(normalized) <= 100:
            raise ValueError("operator must contain 1 to 100 characters")
        now = now or int(time.time())
        enrollment_id = str(uuid.uuid4())
        challenge = secrets.token_bytes(32)
        with self._lock:
            passkeys = self.list_passkeys()
            self._connection.execute(
                "INSERT INTO broker_enrollments VALUES (?, ?, ?, ?, 'pending')",
                (enrollment_id, normalized, challenge, now + CHALLENGE_TTL_SECONDS),
            )
            self._audit(
                enrollment_id,
                "passkey_enrollment_started",
                f"enrollment for {normalized}",
                now,
            )
        return enrollment_id, challenge, passkeys

    def complete_enrollment(
        self,
        enrollment_id: str,
        credential: dict[str, Any],
        verifier: RegistrationVerifier,
        enrollment_key: str,
        now: int | None = None,
    ) -> BrokerPasskey:
        """Complete a passkey enrollment after WebAuthn registration."""
        now = now or int(time.time())
        with self._lock:
            enrollment = self._connection.execute(
                "SELECT * FROM broker_enrollments WHERE enrollment_id = ?",
                (enrollment_id,),
            ).fetchone()
            if enrollment is None or enrollment["status"] != "pending" or enrollment["expires_at"] < now:
                raise ValueError("enrollment is not pending")
            verified = verifier.verify(credential, enrollment["challenge"])
            passkey = BrokerPasskey(
                verified.credential_id,
                enrollment["operator"],
                verified.public_key,
                verified.sign_count,
            )
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                if self._connection.execute(
                    "SELECT 1 FROM broker_passkeys WHERE credential_id = ?",
                    (verified.credential_id,),
                ).fetchone():
                    raise ValueError("passkey is already registered")
                if not self.consume_bootstrap(enrollment_key):
                    self._connection.execute(
                        "UPDATE broker_enrollments SET status = 'rejected' WHERE enrollment_id = ?",
                        (enrollment_id,),
                    )
                    self._audit(
                        enrollment_id,
                        "enrollment_bootstrap_rejected",
                        "bootstrap was already consumed or enrollment key was invalid",
                        now,
                    )
                    self._connection.execute("COMMIT")
                    raise ValueError("enrollment bootstrap is unavailable")
                self._connection.execute(
                    "INSERT INTO broker_passkeys VALUES (?, ?, ?, ?)",
                    (
                        passkey.credential_id,
                        passkey.operator,
                        passkey.public_key,
                        passkey.sign_count,
                    ),
                )
                self._connection.execute(
                    "UPDATE broker_enrollments SET status = 'invalidated' WHERE status = 'pending'",
                )
                self._connection.execute(
                    "UPDATE broker_enrollments SET status = 'completed' WHERE enrollment_id = ?",
                    (enrollment_id,),
                )
                self._audit(
                    enrollment_id,
                    "passkey_enrolled",
                    f"passkey enrolled for {passkey.operator}",
                    now,
                )
                self._audit(
                    enrollment_id,
                    "enrollment_bootstrap_completed",
                    f"bootstrap completed for {passkey.operator}",
                    now,
                )
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
        return passkey

    # -- Broker request lifecycle ------------------------------------------

    def create_broker_request(
        self,
        action: str,
        ct_id: int,
        reason: str,
        requester: str,
        self_reported_hostname: str,
        client: VerifiedClient,
        ssh_public_key: str,
        *,
        policy: Policy,
        now: int | None = None,
    ) -> tuple[CanonicalRequest, str, int]:
        """Create a broker request with validated fields.

        Restricts to the (action, container) pairs *policy* grants.

        Returns:
            (canonical_request, request_id, expires_at).
        """
        if action in EXCLUDED_ACTIONS:
            raise ValueError(f"action '{action}' is excluded")
        if not policy.allows(action, ct_id):
            raise ValueError(f"action '{action}' on CT {ct_id} is not permitted by the operate policy")

        normalized_reason = reason.strip()
        if not 1 <= len(normalized_reason) <= 500:
            raise ValueError("reason must contain 1 to 500 characters")
        normalized_requester = requester.strip()
        if not 1 <= len(normalized_requester) <= 100:
            raise ValueError("requester must contain 1 to 100 characters")

        CertificateCommandBuilder.validate_public_key(ssh_public_key)
        now = now or int(time.time())
        canonical = broker_create_request(
            action=action,
            ct_id=ct_id,
            reason=normalized_reason,
            requester=normalized_requester,
            observed_source_ip=client.source_ip,
            mtls_identity=client.identity,
            ssh_public_key=ssh_public_key,
            self_reported_hostname=self_reported_hostname.strip(),
        )
        request_id = str(uuid.uuid4())
        expires_at = now + BROKER_GRANT_TTL_SECONDS

        with self._lock:
            self._connection.execute(
                """INSERT INTO broker_requests (
                    request_id, action, ct_id, reason, requester,
                    self_reported_hostname, mtls_identity, observed_source_ip,
                    ssh_public_key, ssh_fingerprint, request_nonce,
                    canonical, digest, status, expires_at,
                    approved_by, lease_id, lease_json, certificate_fetched
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, NULL, 0)""",
                (
                    request_id,
                    canonical.action,
                    canonical.ct_id,
                    canonical.reason,
                    canonical.requester,
                    canonical.self_reported_hostname,
                    canonical.mtls_identity,
                    canonical.observed_source_ip,
                    canonical.ssh_public_key,
                    canonical.ssh_fingerprint,
                    canonical.request_nonce,
                    canonical.canonical(),
                    canonical.digest(),
                    expires_at,
                ),
            )
            self._audit(
                request_id,
                "request_created",
                f"{action} on CT{ct_id} by {client.identity} fingerprint {canonical.ssh_fingerprint}",
                now,
            )

        return canonical, request_id, expires_at

    def get_broker_request(self, request_id: str, now: int | None = None) -> dict[str, Any]:
        """Return the full broker request row as a dict.

        A pending request, or an approved one whose certificate was never
        fetched, becomes ``expired`` once read past its deadline. Without this
        nothing ever reached a terminal state, and the worker polled dead
        requests until it exhausted its status rate limit.

        Raises ``ValueError`` if not found.
        """
        now = now or int(time.time())
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM broker_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise ValueError("request not found")
            request = dict(row)
            if request["expires_at"] < now and (
                request["status"] == "pending"
                or (request["status"] == "approved" and not request["certificate_fetched"])
            ):
                self._connection.execute(
                    "UPDATE broker_requests SET status = 'expired' WHERE request_id = ?",
                    (request_id,),
                )
                self._audit(
                    request_id,
                    "request_expired",
                    f"{request['status']} request expired at {request['expires_at']}",
                    now,
                )
                request["status"] = "expired"
        return request

    @staticmethod
    def _require_original_client(request: dict[str, Any], client: VerifiedClient) -> None:
        if request["mtls_identity"] != client.identity or request["observed_source_ip"] != client.source_ip:
            raise ValueError("only the original requester identity and source can access this request")

    def begin_authentication(self, request_id: str, now: int | None = None) -> tuple[bytes, list[BrokerPasskey]]:
        """Create a WebAuthn authentication challenge for a pending request.

        Returns (challenge, list_of_registered_passkeys).
        """
        now = now or int(time.time())
        challenge = secrets.token_bytes(32)
        with self._lock:
            request = self.get_broker_request(request_id, now)
            if request["status"] != "pending" or request["expires_at"] < now:
                raise ValueError("request is not awaiting approval")
            passkeys = self.list_passkeys()
            if not passkeys:
                raise ValueError("no registered passkeys")
            self._connection.execute(
                "INSERT OR REPLACE INTO broker_challenges VALUES (?, ?, ?)",
                (request_id, challenge, now + CHALLENGE_TTL_SECONDS),
            )
            self._audit(
                request_id,
                "approval_challenge_created",
                "WebAuthn assertion requested",
                now,
            )
        return challenge, passkeys

    def approve(
        self,
        request_id: str,
        credential: dict[str, Any],
        verifier: AssertionVerifier,
        lease_factory: LeaseFactory,
        now: int | None = None,
    ) -> None:
        """Approve a request via WebAuthn, creating a signed capability lease.

        The browser caller receives only a status — the lease is stored and
        must be fetched separately through the mTLS lease endpoint.
        """
        now = now or int(time.time())
        credential_id = credential.get("id")
        if not isinstance(credential_id, str):
            raise ValueError("credential ID is invalid")
        with self._lock:
            request = self.get_broker_request(request_id, now)
            challenge_row = self._connection.execute(
                "SELECT * FROM broker_challenges WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            passkey_row = self._connection.execute(
                "SELECT * FROM broker_passkeys WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
            if request["status"] != "pending" or request["expires_at"] < now:
                raise ValueError("request is not awaiting approval")
            if challenge_row is None or challenge_row["expires_at"] < now:
                raise ValueError("challenge is expired or missing")
            if passkey_row is None:
                raise ValueError("credential is not registered")

            passkey = BrokerPasskey(
                passkey_row["credential_id"],
                passkey_row["operator"],
                passkey_row["public_key"],
                passkey_row["sign_count"],
            )
            canonical = self._reconstruct_canonical(request)
            operator, new_sign_count = verifier.verify(credential, challenge_row["challenge"], passkey)
            if operator != passkey.operator:
                raise ValueError("credential operator mismatch")

            lease = lease_factory.create_lease(
                request=canonical,
                profile=CapabilityProfile.OPERATE,
                action_classes=[request["action"]],
                target_cts=[request["ct_id"]],
                approval_id=request_id,
                now=now,
            )
            lease_json = json.dumps(
                {
                    "lease_id": lease.lease_id,
                    "profile": lease.profile.value,
                    "action_classes": list(lease.action_classes),
                    "target_cts": list(lease.target_cts),
                    "approval_id": lease.approval_id,
                    "approval_binding": lease.approval_binding,
                    "execution_binding": lease.execution_binding,
                    "audience": lease.audience,
                    "policy_version": lease.policy_version,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "max_dispatches": lease.max_dispatches,
                    "signature": b64encode(lease.signature),
                }
            )

            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    """UPDATE broker_requests SET
                        status = 'approved', approved_by = ?,
                        lease_id = ?, lease_json = ?
                    WHERE request_id = ?""",
                    (operator, lease.lease_id, lease_json, request_id),
                )
                self._connection.execute(
                    "UPDATE broker_passkeys SET sign_count = ? WHERE credential_id = ?",
                    (new_sign_count, credential_id),
                )
                self._connection.execute(
                    "DELETE FROM broker_challenges WHERE request_id = ?",
                    (request_id,),
                )
                self._audit(
                    request_id,
                    "request_approved",
                    f"approved by {operator}, lease {lease.lease_id}, fingerprint {canonical.ssh_fingerprint}",
                    now,
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def deny_no_auth(self, request_id: str, now: int | None = None) -> None:
        """Deny a pending request without requiring WebAuthn verification."""
        now = now or int(time.time())
        with self._lock:
            request = self.get_broker_request(request_id, now)
            if request["status"] != "pending" or request["expires_at"] < now:
                raise ValueError("request is not awaiting approval")
            self._connection.execute(
                "UPDATE broker_requests SET status = 'denied' WHERE request_id = ?",
                (request_id,),
            )
            self._audit(
                request_id,
                "request_denied",
                "denied without WebAuthn",
                now,
            )

    def cancel(self, request_id: str, client: VerifiedClient, now: int | None = None) -> None:
        """Cancel a pending request.  Only the original mTLS requester can cancel."""
        now = now or int(time.time())
        with self._lock:
            request = self.get_broker_request(request_id, now)
            self._require_original_client(request, client)
            cursor = self._connection.execute(
                "UPDATE broker_requests SET status = 'cancelled' WHERE request_id = ? AND status = 'pending'",
                (request_id,),
            )
            if cursor.rowcount != 1:
                raise ValueError("request cannot be cancelled")
            self._audit(
                request_id,
                "request_cancelled",
                f"cancelled by {client.identity}",
                now,
            )

    def fetch_lease(self, request_id: str, client: VerifiedClient, now: int | None = None) -> dict[str, Any]:
        """Return the signed capability lease for an approved request.

        Only the original mTLS identity that created the request may fetch.
        """
        now = now or int(time.time())
        request = self.get_broker_request(request_id, now)
        self._require_original_client(request, client)
        if request["status"] == "expired":
            raise ValueError("request has expired")
        if request["status"] != "approved":
            raise ValueError("request is not approved")
        if request["expires_at"] < now:
            raise ValueError("lease has expired")
        if request["lease_json"] is None:
            raise ValueError("no lease available")
        self._audit(
            request_id,
            "lease_fetched",
            f"lease fetched by {client.identity}",
            now,
        )
        return json.loads(request["lease_json"])

    def fetch_certificate_gate(
        self,
        request_id: str,
        client: VerifiedClient,
        ssh_public_key: str,
        cert_signer: CaCertificateSigner | None = None,
        now: int | None = None,
    ) -> str:
        """Validate preconditions and issue an SSH certificate.

        When *cert_signer* is ``None`` (testing/default), returns a structured
        ``"not_ready"`` string.  When a signer is supplied, the gate check,
        certificate signing, and one-time consumption happen atomically.
        The certificate serial is chosen here and recorded; callers have no say.

        Raises ``ValueError`` on any precondition failure and ``RuntimeError``
        on CA-key or ``ssh-keygen`` failures.
        """
        now = now or int(time.time())
        request = self.get_broker_request(request_id, now)

        self._require_original_client(request, client)
        if request["status"] == "expired" or (request["status"] == "approved" and request["expires_at"] < now):
            raise ValueError("request has expired")
        if request["status"] != "approved":
            raise ValueError("request is not approved")
        if request["lease_json"] is None:
            raise ValueError("no active lease")

        lease_data = json.loads(request["lease_json"])
        if lease_data["expires_at"] < now:
            raise ValueError("lease has expired")

        stored_fingerprint = request["ssh_fingerprint"]
        submitted_fingerprint = _public_key_fingerprint(ssh_public_key)
        if submitted_fingerprint != stored_fingerprint:
            raise ValueError("public key fingerprint does not match the original request")

        if cert_signer is None:
            self._audit(
                request_id,
                "certificate_gate_checked",
                f"certificate gate checked for {client.identity}, fingerprint {stored_fingerprint}",
                now,
            )
            return "not_ready"

        # Atomic: verify one-time gate, sign, and consume in lock
        with self._lock:
            request = self.get_broker_request(request_id, now)
            if request["certificate_fetched"]:
                raise ValueError("certificate has already been fetched")

            # 63 bits keeps the value inside SQLite's signed INTEGER and
            # ssh-keygen's uint64, and unpredictable to the requester.
            serial = secrets.randbits(63)
            certificate = cert_signer.sign(ssh_public_key, str(serial))

            self._connection.execute(
                "UPDATE broker_requests SET certificate_fetched = 1, certificate_serial = ? WHERE request_id = ?",
                (serial, request_id),
            )
            self._audit(
                request_id,
                "certificate_issued",
                f"certificate issued for {client.identity}, serial {serial}, fingerprint {stored_fingerprint}",
                now,
            )

        return certificate

    def _reconstruct_canonical(self, request: dict[str, Any]) -> CanonicalRequest:
        """Rebuild a ``CanonicalRequest`` from stored field values."""
        return CanonicalRequest(
            action=request["action"],
            ct_id=request["ct_id"],
            reason=request["reason"],
            requester=request["requester"],
            observed_source_ip=request["observed_source_ip"],
            mtls_identity=request["mtls_identity"],
            request_nonce=request["request_nonce"],
            ssh_public_key=request["ssh_public_key"],
            ssh_fingerprint=request["ssh_fingerprint"],
            self_reported_hostname=request["self_reported_hostname"],
        )

    def audit_events(self, request_id: str) -> list[dict[str, Any]]:
        """Return all audit events for a request, ordered chronologically."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT created_at, event, summary FROM broker_audit_events WHERE request_id = ? ORDER BY event_id",
                (request_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    @property
    def connection(self) -> sqlite3.Connection:
        """Expose the raw connection for test inspection."""
        return self._connection


# ---------------------------------------------------------------------------
# mTLS integration helpers
# ---------------------------------------------------------------------------


def _require_mtls(extractor: MtlsIdentityExtractor, http_request: Request) -> VerifiedClient:
    """Extract verified mTLS identity or raise 403."""
    try:
        return extractor.extract(http_request)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# HTTP error helper
# ---------------------------------------------------------------------------


def _http_error(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


def _script_json(value: object) -> str:
    """Serialise *value* for interpolation inside an HTML ``<script>`` block.

    The approval page shows agent-supplied text (reason, requester, hostname).
    ``json.dumps`` alone lets ``</script>`` close the block; escaping ``<``,
    ``>`` and ``&`` as JSON unicode escapes keeps the value inert and
    unchanged once parsed. ``ensure_ascii`` already escapes U+2028/U+2029.
    """
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


_LOG = logging.getLogger(__name__)


def _notify(notifier: DiscordNotifier, store: BrokerStore, request_id: str, content: str) -> None:
    """Send one approval notification and audit the outcome; never raises."""
    try:
        notifier.send(content)
    except Exception as exc:  # noqa: BLE001 - any failure means undelivered
        detail = describe_error(exc)
        _LOG.warning("approval notification for %s failed: %s", request_id, detail)
        store._audit(request_id, "notification_failed", detail, int(time.time()))
    else:
        store._audit(request_id, "notification_sent", "discord", int(time.time()))


def create_broker_app(
    store: BrokerStore,
    signer: LeaseSigner,
    extractor: MtlsIdentityExtractor | None = None,
    rp_id: str = "broker.example.test",
    origin: str = "https://broker.example.test",
    enrollment_key: str = "",
    enrollment_enabled: bool = False,
    verifier: AssertionVerifier | None = None,
    registration_verifier: RegistrationVerifier | None = None,
    cert_signer: CaCertificateSigner | None = None,
    *,
    policy: Policy,
    notifier: DiscordNotifier | None = None,
    lifespan: Any = None,
) -> FastAPI:
    """Create the broker FastAPI application.

    Parameters
    ----------
    store:
        Explicit SQLite-backed store. The caller owns its lifetime unless
        it transfers cleanup through the FastAPI lifespan.
    signer:
        Explicit Ed25519 lease signer; no implicit ephemeral production key.
    extractor:
        mTLS identity extractor.  Defaults to ``RejectingExtractor`` which
        denies every request — real deployments **must** supply a verified
        extractor.
    rp_id:
        WebAuthn relying party identifier.
    origin:
        WebAuthn origin URL.
    enrollment_key:
        Shared secret required to begin passkey enrollment.
    enrollment_enabled:
        Whether the one-time bootstrap enrollment endpoint is active.
    verifier:
        WebAuthn assertion verifier.  Defaults to real WebAuthn.
    registration_verifier:
        WebAuthn registration verifier.  Defaults to real WebAuthn.
    cert_signer:
        SSH certificate signer.  When omitted the endpoint returns
        ``not_ready``.
    policy:
        Which typed actions and containers may be requested.  Required: there
        is no permissive default.
    notifier:
        Sends each new request's approval link to the operator.  ``None``
        disables notification. FastAPI owns the after-response delivery task;
        a delivery failure does not approve or invalidate the request.
    lifespan:
        Optional FastAPI lifespan for caller-owned resource cleanup. The
        environment factory uses it to close its store at shutdown.
    """
    if store is None or signer is None:
        raise ValueError("an explicit store and lease signer are required")
    extractor = extractor or RejectingExtractor()
    lease_factory = LeaseFactory(signer, policy)
    verifier = verifier or WebAuthnAssertionVerifier(rp_id, origin)
    registration_verifier = registration_verifier or WebAuthnRegistrationVerifier(rp_id, origin)

    app = FastAPI(title="PVE approval service", docs_url=None, redoc_url=None, lifespan=lifespan)
    limiter = Limiter(
        key_func=_mtls_identity_key,
        default_limits=["60/minute"],
        headers_enabled=True,
    )
    app.state.limiter = limiter
    # slowapi's handler is typed narrowly for RateLimitExceeded only, which is
    # contravariant with Starlette's generic ExceptionHandler(Exception) — this
    # is the documented slowapi usage pattern, not a bug.
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_middleware(SlowAPIASGIMiddleware)

    @app.middleware("http")
    async def attach_mtls_identity(request: Request, call_next: Any) -> Any:
        """Expose an already-verified mTLS subject to the rate-limit key function."""
        try:
            client = extractor.extract(request)
        except PermissionError:
            pass
        else:
            request.state.mtls_identity = _MtlsIdentity(subject=client.identity)
        return await call_next(request)

    # -------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------

    @app.get("/health")
    @limiter.exempt
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ===================================================================
    # mTLS-only endpoints  (extractor-verified client required)
    # ===================================================================

    @app.post("/v1/broker/requests", status_code=201)
    @limiter.limit("10/minute")
    def create_broker_request(
        body: CreateBrokerRequest,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
    ) -> dict[str, Any]:
        client = _require_mtls(extractor, request)
        try:
            canonical, request_id, expires_at = store.create_broker_request(
                action=body.action,
                ct_id=body.ct_id,
                reason=body.reason,
                requester=body.requester,
                self_reported_hostname=body.self_reported_hostname,
                client=client,
                ssh_public_key=body.ssh_public_key,
                policy=policy,
            )
        except ValueError as exc:
            raise _http_error(exc) from exc
        if notifier is not None:
            content = approval_message(
                action=canonical.action,
                ct_id=canonical.ct_id,
                reason=canonical.reason,
                expires_at=expires_at,
                approval_url=f"{origin}/v1/broker/requests/{request_id}/approval",
            )
            background_tasks.add_task(_notify, notifier, store, request_id, content)
        return {
            "request_id": request_id,
            "status": "pending",
            "expires_at": expires_at,
            "digest": canonical.digest(),
            "ssh_fingerprint": canonical.ssh_fingerprint,
        }

    @app.get("/v1/broker/requests/{request_id}")
    @limiter.limit("30/minute")
    def get_broker_request_status(
        request_id: str,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        client = _require_mtls(extractor, request)
        try:
            row = store.get_broker_request(request_id)
        except ValueError as exc:
            raise _http_error(exc) from exc
        if row["mtls_identity"] != client.identity or row["observed_source_ip"] != client.source_ip:
            raise HTTPException(status_code=403, detail="access denied")
        return {
            "request_id": row["request_id"],
            "action": row["action"],
            "ct_id": row["ct_id"],
            "reason": row["reason"],
            "status": row["status"],
            "expires_at": row["expires_at"],
            "ssh_fingerprint": row["ssh_fingerprint"],
            "digest": row["digest"],
            "certificate_fetched": bool(row["certificate_fetched"]),
        }

    @app.get("/v1/broker/requests/{request_id}/lease")
    @limiter.limit("30/minute")
    def fetch_lease(
        request_id: str,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        client = _require_mtls(extractor, request)
        try:
            lease = store.fetch_lease(request_id, client)
        except ValueError as exc:
            raise _http_error(exc) from exc
        return lease

    @app.post("/v1/broker/requests/{request_id}/certificate")
    @limiter.limit("5/minute")
    def fetch_certificate(
        request_id: str,
        request: Request,
        response: Response,
        body: dict[str, str],
    ) -> dict[str, Any]:
        client = _require_mtls(extractor, request)
        ssh_public_key = body.get("ssh_public_key", "")
        if not ssh_public_key:
            raise HTTPException(status_code=400, detail="ssh_public_key is required")
        # A "serial" in the body is ignored: the broker assigns it.
        try:
            certificate = store.fetch_certificate_gate(
                request_id,
                client,
                ssh_public_key,
                cert_signer=cert_signer,
            )
        except ValueError as exc:
            raise _http_error(exc) from exc

        if certificate == "not_ready":
            return {
                "status": "not_ready",
                "message": "certificate signing not yet implemented",
            }

        lease_data = json.loads(store.get_broker_request(request_id)["lease_json"])
        return {
            "status": "issued",
            "certificate": certificate,
            "lease_id": lease_data.get("lease_id", ""),
            "expires_at": lease_data.get("expires_at", 0),
        }

    @app.get("/v1/broker/lease-public-key")
    def lease_public_key() -> dict[str, str]:
        return {"public_key": signer.public_key_openssh(), "format": "openssh"}

    @app.post("/v1/broker/requests/{request_id}/cancel")
    def cancel_request(
        request_id: str,
        http_request: Request,
    ) -> dict[str, str]:
        client = _require_mtls(extractor, http_request)
        try:
            store.cancel(request_id, client)
        except ValueError as exc:
            raise _http_error(exc) from exc
        return {"status": "cancelled"}

    # ===================================================================
    # Browser / WebAuthn endpoints — no mTLS required
    # ===================================================================

    # -- Enrollment -------------------------------------------------------

    @app.post("/v1/broker/enrollments", status_code=201)
    @limiter.limit("3/15minutes", key_func=get_remote_address)
    def begin_enrollment(
        body: BeginEnrollment,
        request: Request,
        response: Response,
        x_broker_enrollment_key: str | None = Header(default=None),
    ) -> dict[str, str]:
        if not enrollment_enabled:
            raise HTTPException(status_code=404, detail="not found")
        if store.has_passkey():
            store.audit_bootstrap_rejection("bootstrap attempted after a passkey existed")
            raise HTTPException(status_code=404, detail="not found")
        if not enrollment_key or not x_broker_enrollment_key:
            store.audit_bootstrap_rejection("enrollment key was missing")
            raise HTTPException(status_code=401, detail="enrollment authentication required")
        if not secrets.compare_digest(enrollment_key, x_broker_enrollment_key):
            store.audit_bootstrap_rejection("enrollment key did not match")
            raise HTTPException(status_code=401, detail="enrollment authentication failed")
        try:
            enrollment_id, _, _ = store.begin_enrollment(body.operator)
        except ValueError as exc:
            raise _http_error(exc) from exc
        return {"enrollment_id": enrollment_id, "status": "pending"}

    @app.get("/v1/broker/enrollments/{enrollment_id}/options")
    def enrollment_options(enrollment_id: str) -> dict[str, Any]:
        try:
            row = store.get_pending_enrollment(enrollment_id)
        except ValueError as exc:
            raise _http_error(exc) from exc
        passkeys = store.list_passkeys()
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="PVE SSH Broker",
            user_name=row["operator"],
            user_display_name=row["operator"],
            user_id=hashlib.sha256(f"pve-broker:{row['operator']}".encode("utf-8")).digest(),
            challenge=row["challenge"],
            exclude_credentials=[PublicKeyCredentialDescriptor(id=b64decode(k.credential_id)) for k in passkeys],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        return json.loads(options_to_json(options))

    @app.post("/v1/broker/enrollments/{enrollment_id}/complete")
    def complete_enrollment(enrollment_id: str, body: CompleteRegistration) -> dict[str, str]:
        try:
            passkey = store.complete_enrollment(
                enrollment_id,
                body.credential,
                registration_verifier,
                enrollment_key,
            )
        except ValueError as exc:
            raise _http_error(exc) from exc
        return {"status": "enrolled", "operator": passkey.operator}

    @app.get("/v1/broker/enroll/{enrollment_id}", response_class=HTMLResponse)
    def enrollment_page(enrollment_id: str) -> str:
        return _ENROLLMENT_HTML_TEMPLATE.format(enrollment_id=_script_json(enrollment_id))

    # -- Approval ---------------------------------------------------------

    @app.get("/v1/broker/requests/{request_id}/approval/options")
    @limiter.limit("30/minute", key_func=get_remote_address)
    def broker_approval_options(request_id: str, request: Request, response: Response) -> dict[str, Any]:
        try:
            challenge, passkeys = store.begin_authentication(request_id)
        except ValueError as exc:
            raise _http_error(exc) from exc
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[PublicKeyCredentialDescriptor(id=b64decode(k.credential_id)) for k in passkeys],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return json.loads(options_to_json(options))

    @app.post("/v1/broker/requests/{request_id}/approval")
    @limiter.limit("5/minute")
    def broker_approve(
        request_id: str, body: CompleteAssertion, request: Request, response: Response
    ) -> dict[str, str]:
        try:
            store.approve(request_id, body.credential, verifier, lease_factory)
        except ValueError as exc:
            raise _http_error(exc) from exc
        # Browser receives status only — never the lease or certificate data.
        return {"status": "approved"}

    @app.post("/v1/broker/requests/{request_id}/denial")
    @limiter.limit("3/minute")
    def broker_deny(request_id: str, request: Request, response: Response) -> dict[str, str]:
        try:
            store.deny_no_auth(request_id)
        except ValueError as exc:
            raise _http_error(exc) from exc
        return {"status": "denied"}

    @app.get("/v1/broker/requests/{request_id}/approval", response_class=HTMLResponse)
    @limiter.limit("30/minute", key_func=get_remote_address)
    def broker_approval_page(request_id: str, request: Request, response: Response) -> str:
        try:
            req = store.get_broker_request(request_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="request not found") from exc
        shown: dict[str, Any] = {
            "action": req["action"],
            "ct_id": req["ct_id"],
            "reason": req["reason"],
            "requester": req["requester"],
            "self_reported_hostname": req["self_reported_hostname"],
            "mtls_identity": req["mtls_identity"],
            "observed_source_ip": req["observed_source_ip"],
            "ssh_fingerprint": req["ssh_fingerprint"],
            "digest": req["digest"],
            "expires_at": req["expires_at"],
        }
        if req["action"] == "ct.snapshot_prune":
            # The action takes no argument; what it deletes comes from policy.
            shown["effect"] = f"removes broker-* snapshots older than {policy.snapshot_retention_days} days"
        details = _script_json(shown)
        return _APPROVAL_HTML_TEMPLATE.format(
            request_id=_script_json(request_id),
            details=details,
            expires_at=_script_json(req["expires_at"]),
        )

    # -- Browser status poll -----------------------------------------------

    @app.get("/v1/broker/requests/{request_id}/status")
    @limiter.limit("30/minute")
    def broker_request_status_browser(request_id: str, request: Request, response: Response) -> dict[str, str]:
        try:
            req = store.get_broker_request(request_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        return {"status": req["status"]}

    return app


def create_broker_app_from_env() -> FastAPI:
    """Create an approval app from explicit deployment configuration.

    Deployment must provide a persistent, private Ed25519 lease key. The mTLS
    extractor deliberately remains rejecting until the separate TLS front-end
    adapter is configured; this prevents an accidental plain HTTP client path.
    """
    database_path = os.environ.get("PVE_BROKER_DATABASE", "")
    key_path = os.environ.get("PVE_BROKER_LEASE_KEY_PATH", "")
    rp_id = os.environ.get("PVE_BROKER_RP_ID", "")
    origin = os.environ.get("PVE_BROKER_ORIGIN", "")
    enrollment_key = os.environ.get("PVE_BROKER_ENROLLMENT_KEY", "")
    enrollment_enabled = os.environ.get("PVE_BROKER_ENROLLMENT_ENABLED", "false").lower() == "true"
    policy_path = os.environ.get("PVE_BROKER_POLICY_FILE", "")
    if not database_path or not key_path or not rp_id or not origin or not enrollment_key or not policy_path:
        raise RuntimeError("broker runtime configuration is incomplete")
    try:
        policy = load_policy(Path(policy_path))
    except PolicyError as exc:
        raise RuntimeError(f"PVE_BROKER_POLICY_FILE is invalid: {exc}") from exc
    cert_source = os.environ.get("PVE_BROKER_CERT_SOURCE", "")
    if cert_source:
        try:
            CertificatePolicy(source=cert_source)
        except ValueError as exc:
            raise RuntimeError("PVE_BROKER_CERT_SOURCE must contain restricted CIDRs") from exc
    mtls_clients_json = os.environ.get("PVE_BROKER_MTLS_CLIENTS_JSON", "")
    extractor: MtlsIdentityExtractor = RejectingExtractor()
    if mtls_clients_json:
        try:
            expected_clients = json.loads(mtls_clients_json)
        except json.JSONDecodeError as exc:
            raise RuntimeError("PVE_BROKER_MTLS_CLIENTS_JSON is invalid") from exc

        # A value is one address or a list of them. The list form exists because
        # one identity can legitimately serve two hosts during a controller
        # handover -- see TrustedProxyMtlsExtractor. This validator has to allow
        # it too: it runs first, so a str-only check here would reject the list
        # before the extractor ever saw it and make that support unreachable.
        def _valid(sources: object) -> bool:
            if isinstance(sources, str):
                return True
            return isinstance(sources, list) and bool(sources) and all(isinstance(item, str) for item in sources)

        if not isinstance(expected_clients, dict) or not all(
            isinstance(identity, str) and _valid(sources) for identity, sources in expected_clients.items()
        ):
            raise RuntimeError("PVE_BROKER_MTLS_CLIENTS_JSON must map identities to an IP or a non-empty list of IPs")
        extractor = TrustedProxyMtlsExtractor(expected_clients)

    ca_key_path = os.environ.get("PVE_BROKER_CA_KEY_PATH", "")
    cert_signer: CaCertificateSigner | None = None
    if ca_key_path:
        if not cert_source:
            raise RuntimeError("PVE_BROKER_CERT_SOURCE is required for certificate signing")
        cert_signer = CaCertificateSigner(
            ca_key_path,
            CertificateCommandBuilder(CertificatePolicy(source=cert_source)),
        )

    # A path, never the URL itself: the webhook URL is a credential.
    notifier = DiscordNotifier.from_file(os.environ.get("PVE_BROKER_NOTIFY_WEBHOOK_FILE", ""))
    if notifier is None:
        _LOG.info("approval notifications disabled: no webhook file")

    signer = LeaseSigner.from_pem_file(key_path)
    store = BrokerStore(Path(database_path), enrollment_key)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            store.close()

    try:
        return create_broker_app(
            store=store,
            signer=signer,
            extractor=extractor,
            cert_signer=cert_signer,
            rp_id=rp_id,
            origin=origin,
            enrollment_key=enrollment_key,
            enrollment_enabled=enrollment_enabled,
            policy=policy,
            notifier=notifier,
            lifespan=lifespan,
        )
    except Exception:
        store.close()
        raise


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

_ENROLLMENT_HTML_TEMPLATE = files(__package__).joinpath("templates/enrollment.html").read_text(encoding="utf-8")

_APPROVAL_HTML_TEMPLATE = files(__package__).joinpath("templates/approval.html").read_text(encoding="utf-8")
