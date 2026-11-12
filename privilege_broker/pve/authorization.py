"""Portable PVE authorization and SSH certificate argument construction.

This module performs no network access or external command execution.
Human approval and the target dispatcher remain separate boundaries.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import time
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_ssh_public_key,
)

from .common import (
    Policy,
    PolicyError,  # noqa: F401 -- retained public import for the approval service
    b64decode,  # noqa: F401 -- retained public import for the approval service
    b64encode,  # noqa: F401 -- retained public import for the approval service
    canonical_json,
    execution_arguments_digest,
    load_policy,  # noqa: F401 -- retained public import for the approval service
    sha256,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROKER_AUDIENCE = "pve-privileged-executor"
POLICY_VERSION = "pve-operate-v1"
EXECUTION_CANONICALIZATION = "pve-execution-v1"
APPROVAL_CANONICALIZATION = "pve-approval-v1"

OPERATE_MAX_TTL_SECONDS = 300  # 5 minutes

CERTIFICATE_MAX_TTL_SECONDS = 120  # 2 minutes
POLICY_PRINCIPAL = "pve-ai-ops"
POLICY_DISPATCHER = "/usr/local/libexec/pve-typed-dispatcher"

# Defence in depth: never grantable, whatever the policy file says.
EXCLUDED_ACTIONS: frozenset[str] = frozenset(
    {
        "ct.destroy",
        "ct.purge",
        "security.revoke",
        "security.reconfigure",
    }
)


def _public_key_fingerprint(public_key: str) -> str:
    """Compute the SHA256 fingerprint of an SSH public key.

    Matches ``ssh-keygen -lf -E sha256`` behaviour: hashes the base64-decoded
    key blob that follows the key type in the OpenSSH public-key line.
    """
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise ValueError("SSH public key must have at least two space-separated parts")
    try:
        key_blob = base64.b64decode(parts[1])
    except Exception as exc:
        raise ValueError(f"invalid base64 in SSH public key: {exc}") from exc
    fingerprint = base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii")
    return "SHA256:" + fingerprint.rstrip("=")


# ---------------------------------------------------------------------------
# Capability profiles
# ---------------------------------------------------------------------------


class CapabilityProfile(str, Enum):
    """Typed capability profile that governs what a lease permits.

    ``operate`` -- named lifecycle operations on policy-listed guests -- is the
    only profile the broker issues. The dispatcher rejects any other.
    """

    OPERATE = "operate"


# ---------------------------------------------------------------------------
# mTLS identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedClient:
    """Verified mTLS client identity — never constructed from caller-supplied fields.

    Real deployments bind *identity* to the authenticated mTLS certificate
    subject (e.g., CN or OU) and *source_ip* to the observed TCP connection.
    """

    identity: str
    source_ip: str


class MtlsIdentityExtractor(Protocol):
    """Protocol for extracting a verified mTLS client identity from a request.

    The extraction mechanism is injectable and not coupled to any particular web
    framework. Deployments provide their own implementation bound to real mTLS
    certificate verification (e.g., Uvicorn TLS, reverse-proxy headers).
    """

    def extract(self, request: object) -> VerifiedClient:
        """Extract the verified client identity from *request*.

        Raises ``PermissionError`` when the caller has no valid mTLS certificate.
        """
        ...


class RejectingExtractor:
    """Extractor that rejects every caller — used to test non-mTLS paths."""

    def extract(self, request: object = None) -> VerifiedClient:
        raise PermissionError("mTLS authentication required")


class TrustedProxyMtlsExtractor:
    """Accept certificate metadata only from the local TLS-terminating proxy."""

    _IDENTITY_HEADER = "x-pve-broker-mtls-identity"
    _SOURCE_HEADER = "x-pve-broker-mtls-source-ip"

    def __init__(self, expected_clients: dict[str, str | list[str]]) -> None:
        """Bind each accepted mTLS identity to explicit observed source addresses."""
        if not expected_clients:
            raise ValueError("at least one mTLS client identity is required")
        self._expected_clients = {
            identity: frozenset(
                str(ipaddress.ip_address(address)) for address in ([sources] if isinstance(sources, str) else sources)
            )
            for identity, sources in expected_clients.items()
        }
        empty = sorted(i for i, s in self._expected_clients.items() if not s)
        if empty:
            raise ValueError(f"mTLS client identities list no source address: {empty}")

    def extract(self, request: object) -> VerifiedClient:
        client = getattr(request, "client", None)
        if getattr(client, "host", None) not in {"127.0.0.1", "::1"}:
            raise PermissionError("mTLS metadata requires the local proxy")
        headers = getattr(request, "headers", {})
        identity = headers.get(self._IDENTITY_HEADER, "")
        expected_sources = self._expected_clients.get(identity)
        if not expected_sources:
            raise PermissionError("unrecognized mTLS client identity")
        try:
            source_ip = str(ipaddress.ip_address(headers.get(self._SOURCE_HEADER, "")))
        except ValueError as exc:
            raise PermissionError("invalid mTLS client source address") from exc
        if source_ip not in expected_sources:
            raise PermissionError("mTLS client source address does not match identity")
        return VerifiedClient(identity=identity, source_ip=source_ip)


# ---------------------------------------------------------------------------
# Canonical request
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CanonicalRequest:
    """Canonically-bound request with authenticated and observed fields.

    The mTLS-authenticated *identity* is never derived from caller-supplied
    body fields — it comes from the injectable ``MtlsIdentityExtractor``.
    *self_reported_hostname* is kept separate for audit, never for authz.
    """

    action: str
    ct_id: int
    reason: str
    requester: str
    observed_source_ip: str
    mtls_identity: str
    request_nonce: str
    ssh_public_key: str
    ssh_fingerprint: str
    self_reported_hostname: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ct_id": self.ct_id,
            "reason": self.reason,
            "requester": self.requester,
            "observed_source_ip": self.observed_source_ip,
            "mtls_identity": self.mtls_identity,
            "request_nonce": self.request_nonce,
            "ssh_public_key": self.ssh_public_key,
            "ssh_fingerprint": self.ssh_fingerprint,
            "self_reported_hostname": self.self_reported_hostname,
        }

    def canonical(self) -> str:
        """Return the deterministic canonical JSON representation."""
        return canonical_json(self.to_payload())

    def digest(self) -> str:
        """Return the SHA-256 hex digest of the canonical representation."""
        return sha256(self.canonical().encode("ascii"))


def create_request(
    action: str,
    ct_id: int,
    reason: str,
    requester: str,
    observed_source_ip: str,
    mtls_identity: str,
    ssh_public_key: str,
    self_reported_hostname: str = "",
) -> CanonicalRequest:
    """Build a canonical request with validated fields and derived fingerprint."""
    fingerprint = _public_key_fingerprint(ssh_public_key)
    return CanonicalRequest(
        action=action,
        ct_id=ct_id,
        reason=reason.strip(),
        requester=requester.strip(),
        observed_source_ip=observed_source_ip,
        mtls_identity=mtls_identity,
        request_nonce=str(uuid.uuid4()),
        ssh_public_key=ssh_public_key,
        ssh_fingerprint=fingerprint,
        self_reported_hostname=self_reported_hostname.strip(),
    )


# ---------------------------------------------------------------------------
# Capability lease
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityLease:
    """An asymmetrically-signed capability lease with scope & dispatch constraints.

    Fields (excluding *signature*) form the compact deterministic representation
    that is signed with the broker's Ed25519 private key.

    Uses coordinated pve-execution-v1/pve-approval-v1 schema; old leases without
    approval_id, approval_binding, execution_binding, policy_version, or with
    operation_budget instead of max_dispatches are rejected as incompatible.
    """

    lease_id: str
    profile: CapabilityProfile
    action_classes: tuple[str, ...]
    target_cts: tuple[int, ...]
    approval_id: str
    audience: str
    issued_at: int
    expires_at: int
    approval_binding: dict[str, str] | None = None
    execution_binding: dict[str, str] | None = None
    policy_version: str = POLICY_VERSION
    max_dispatches: int = 1
    signature: bytes = b""

    def to_claims(self) -> dict[str, Any]:
        """Return the claims dict for signing (omits *signature*)."""
        return {
            "lease_id": self.lease_id,
            "profile": self.profile.value,
            "action_classes": list(self.action_classes),
            "target_cts": list(self.target_cts),
            "approval_id": self.approval_id,
            "approval_binding": self.approval_binding,
            "execution_binding": self.execution_binding,
            "audience": self.audience,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "max_dispatches": self.max_dispatches,
        }

    def to_compact(self) -> str:
        """Compact deterministic representation for signing."""
        return canonical_json(self.to_claims())


# ---------------------------------------------------------------------------
# Lease signer / verifier
# ---------------------------------------------------------------------------


class LeaseSigner:
    """Ed25519 signer and verifier for capability leases."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    @classmethod
    def generate(cls) -> LeaseSigner:
        """Generate a fresh Ed25519 key pair (for testing or initial setup)."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem_file(cls, path: str) -> LeaseSigner:
        """Load a root-only Ed25519 lease key without exposing its contents."""
        try:
            with open(path, "rb") as key_file:
                key = load_pem_private_key(key_file.read(), password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError("unable to load broker lease signing key") from exc
        if not isinstance(key, Ed25519PrivateKey):
            # Preserve the deployment-facing error contract during extraction.
            raise RuntimeError("broker lease signing key must be Ed25519")  # noqa: TRY004
        return cls(key)

    def to_pem(self) -> bytes:
        """Serialize only for root-owned broker key generation workflows."""
        return self._private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private_key

    def public_key_openssh(self) -> str:
        pub = self._private_key.public_key()
        return pub.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii").strip()

    def sign_lease(self, lease: CapabilityLease) -> CapabilityLease:
        """Sign *lease* and return a new lease with the signature attached."""
        data = lease.to_compact().encode("ascii")
        signature = self._private_key.sign(data)
        return replace(lease, signature=signature)

    def verify_lease(
        self, lease: CapabilityLease, public_key: Ed25519PublicKey, now: int | None = None
    ) -> dict[str, Any]:
        """Strictly verify *lease*, returning claims on success.

        Enforces: coordinated pve-execution-v1 / pve-approval-v1 schema,
        audience, expiry, temporal validity, max_dispatches == 1,
        policy_version == pve-operate-v1, valid approval/execution bindings,
        and the Ed25519 signature. Scope is the factory's concern at issue
        time and the dispatcher's at execution time; neither is repeated here.
        Raises ``ValueError`` on any failure.
        """
        # --- new-schema structural checks (reject old/incomplete leases) ---
        if lease.max_dispatches != 1:
            raise ValueError("lease max_dispatches must be 1")
        if lease.policy_version != POLICY_VERSION:
            raise ValueError("lease policy version is invalid")
        if not lease.approval_id:
            raise ValueError("lease approval_id is required")
        if (
            not isinstance(lease.approval_binding, dict)
            or lease.approval_binding.get("canonicalization") != APPROVAL_CANONICALIZATION
        ):
            raise ValueError("lease approval binding is invalid or missing")
        if (
            not isinstance(lease.execution_binding, dict)
            or lease.execution_binding.get("canonicalization") != EXECUTION_CANONICALIZATION
        ):
            raise ValueError("lease execution binding is invalid or missing")

        # --- temporal ---
        if lease.audience != BROKER_AUDIENCE:
            raise ValueError("lease audience is invalid")

        now = now or int(time.time())
        if lease.expires_at < now:
            raise ValueError("lease has expired")
        if lease.issued_at > now:
            raise ValueError("lease is not yet valid")

        # --- cryptographic verification ---
        data = lease.to_compact().encode("ascii")
        try:
            public_key.verify(lease.signature, data)
        except InvalidSignature as exc:
            raise ValueError("lease signature is invalid") from exc

        return lease.to_claims()


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


def _validate_action_scope(lease: CapabilityLease, policy: Policy) -> None:
    """Validate the lease's action/target scope at issue time."""
    for action in lease.action_classes:
        if action in EXCLUDED_ACTIONS:
            raise ValueError(f"lease cannot include excluded action '{action}'")
    _validate_operate_scope(lease, policy)


def _validate_operate_scope(lease: CapabilityLease, policy: Policy) -> None:
    # Every (action, CT) pair the lease would authorise must be granted.
    for action in lease.action_classes:
        for ct in lease.target_cts:
            if not policy.allows(action, ct):
                raise ValueError(f"operate lease cannot include action '{action}' on CT {ct}")
    if lease.expires_at - lease.issued_at > OPERATE_MAX_TTL_SECONDS:
        raise ValueError("operate lease exceeds maximum TTL")
    if lease.max_dispatches != 1:
        raise ValueError("operate lease must have max_dispatches=1")


# ---------------------------------------------------------------------------
# Lease factory
# ---------------------------------------------------------------------------


class LeaseFactory:
    """Factory for creating and signing policy-validated capability leases."""

    def __init__(self, signer: LeaseSigner, policy: Policy) -> None:
        self._signer = signer
        self._policy = policy

    def create_lease(
        self,
        request: CanonicalRequest,
        profile: CapabilityProfile,
        action_classes: list[str],
        target_cts: list[int],
        approval_id: str | None = None,
        now: int | None = None,
    ) -> CapabilityLease:
        """Create, validate, and sign a capability lease (pve-operate-v1 schema).

        Args:
            request: The originating canonical request (for digest binding).
            profile: Target capability profile.
            action_classes: Allowed action identifiers.
            target_cts: Target container IDs.
            approval_id: Broker request UUID (bound as the lease's approval_id).
            now: Override for ``time.time()`` (testing).

        Returns:
            A fully signed ``CapabilityLease`` with coordinated bindings.
        """
        now = now or int(time.time())

        exec_digest = execution_arguments_digest(request.action, request.ct_id, EXECUTION_CANONICALIZATION)
        approval_binding = {
            "canonicalization": APPROVAL_CANONICALIZATION,
            "request_digest": request.digest(),
        }
        execution_binding = {
            "canonicalization": EXECUTION_CANONICALIZATION,
            "arguments_digest": exec_digest,
        }

        lease = CapabilityLease(
            lease_id=str(uuid.uuid4()),
            profile=profile,
            action_classes=tuple(action_classes),
            target_cts=tuple(target_cts),
            approval_id=approval_id or str(uuid.uuid4()),
            approval_binding=approval_binding,
            execution_binding=execution_binding,
            audience=BROKER_AUDIENCE,
            policy_version=POLICY_VERSION,
            issued_at=now,
            expires_at=now + OPERATE_MAX_TTL_SECONDS,
            max_dispatches=1,
        )

        _validate_action_scope(lease, self._policy)
        if request.action not in lease.action_classes or request.ct_id not in lease.target_cts:
            raise ValueError("canonical request is not within lease scope")
        return self._signer.sign_lease(lease)


# ---------------------------------------------------------------------------
# Certificate policy (fully server-side)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CertificatePolicy:
    """Fully server-side derived certificate policy — *no caller overrides*.

    If callers supply any principal, validity, source restriction, extension,
    command, or serial override, the broker SHALL reject or ignore it.
    """

    source: str
    max_validity_seconds: int = CERTIFICATE_MAX_TTL_SECONDS
    principal: str = POLICY_PRINCIPAL
    dispatcher: str = POLICY_DISPATCHER

    def __post_init__(self) -> None:
        # A missing or unrestricted source would erase the SSH source boundary.
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("certificate source restriction is required")
        network = ipaddress.ip_network(self.source)
        if network.prefixlen == 0:
            raise ValueError("certificate source restriction cannot allow every address")

    def to_options(self) -> list[str]:
        """Return ``-O`` option strings for ``ssh-keygen``."""
        return [
            "clear",
            f"source-address={self.source}",
            f"force-command={self.dispatcher}",
            "no-pty",
            "no-agent-forwarding",
            "no-port-forwarding",
            "no-X11-forwarding",
            "no-user-rc",
        ]


# ---------------------------------------------------------------------------
# Certificate command builder
# ---------------------------------------------------------------------------

_PATH_FORBIDDEN = frozenset(";&|`$(){}[]!#~'\"\\\n\r\t ")


class CertificateCommandBuilder:
    """Builds safe ``ssh-keygen`` argv for signing SSH certificates.

    * Never uses ``shell=True``.
    * Validates all inputs against injection.
    * Does **not** execute commands (callers own the run invocation).
    """

    def __init__(self, policy: CertificatePolicy) -> None:
        self._policy = policy

    def validate_public_key(self, public_key_pem: str) -> Ed25519PublicKey:
        """Validate an SSH public key string, returning the parsed key.

        Raises ``ValueError`` if the key is invalid, not Ed25519, or malformed.
        The key must be in OpenSSH ``ssh-ed25519 AAAA...`` format.
        """
        if public_key_pem != public_key_pem.strip():
            raise ValueError("invalid SSH public key: surrounding whitespace")
        try:
            key = load_ssh_public_key(public_key_pem.encode("ascii"))
        except Exception as exc:
            raise ValueError(f"invalid SSH public key: {exc}") from exc

        if not isinstance(key, Ed25519PublicKey):
            # Invalid request material has always been a ValueError for callers.
            raise ValueError("only Ed25519 public keys are supported")  # noqa: TRY004
        return key

    def build_argv(
        self,
        ca_private_key_path: str,
        public_key_path: str,
        serial: str,
    ) -> list[str]:
        """Build a safe argv list for ``ssh-keygen`` certificate signing.

        All arguments are validated to prevent shell injection.  Returns a
        list suitable for ``run(argv, shell=False)``.

        Args:
            ca_private_key_path: Path to the CA private key.
            public_key_path: Path to the user's public key file.
            serial: Certificate serial number (1-20 ASCII decimal digits).

        Returns:
            argv list safe for ``shell=False``.
        """
        for path in (ca_private_key_path, public_key_path):
            self._validate_path(path)

        # ssh-keygen requires decimal serials; isdigit alone also accepts
        # non-ASCII digits that its parser rejects.
        if not serial or not (serial.isascii() and serial.isdigit()) or len(serial) > 20:
            raise ValueError("serial must be 1-20 decimal digits")

        argv: list[str] = [
            "ssh-keygen",
            "-s",
            ca_private_key_path,
            "-I",
            self._policy.principal,
            "-n",
            self._policy.principal,
            "-V",
            f"+{self._policy.max_validity_seconds}s",
        ]
        for option in self._policy.to_options():
            argv.extend(["-O", option])
        argv.extend(["-z", serial, public_key_path])
        return argv

    @staticmethod
    def _validate_path(path: str) -> None:
        """Reject paths containing shell metacharacters."""
        if any(c in _PATH_FORBIDDEN for c in path):
            raise ValueError("path contains shell-forbidden characters")
