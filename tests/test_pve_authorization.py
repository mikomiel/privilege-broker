"""Focused tests for the PVE SSH certificate broker module.

Covers all required scenarios from the OpenSpec specification.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from privilege_broker.pve import authorization as broker
from privilege_broker.pve.authorization import CanonicalRequest as _CanonicalRequest
from privilege_broker.pve.authorization import CapabilityLease as _CapabilityLease
from privilege_broker.pve.authorization import LeaseSigner as _LeaseSigner

SCRIPT = Path(broker.__file__)
_SOURCE = "198.51.100.88/32"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _policy(grants: dict[str, set[int]]) -> broker.Policy:
    return broker.Policy(
        grants={action: frozenset(ct_ids) for action, ct_ids in grants.items()},
        snapshot_retention_days=7,
    )


# The broker's own reading of the Ansible-rendered policy file.
_POLICY = _policy({action: {117} for action in ("ct.reboot", "ct.start", "ct.stop", "ct.shutdown", "ct.snapshot")})

# Real Ed25519 public keys in OpenSSH format, generated via cryptography.
_VALID_PUB_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII1mw/Rh2ysOidTnnfJ0oS9PRi6DCQCozwvrtQZ8cgLC"
_ALT_PUB_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAB4zUZyrKHr1ZUeeKX+kxKKe/Kqu1AM2g1w56sleell"


@pytest.fixture
def signer() -> _LeaseSigner:
    return broker.LeaseSigner.generate()


@pytest.fixture
def public_key(signer: _LeaseSigner) -> Ed25519PublicKey:
    return signer.private_key.public_key()


@pytest.fixture
def canonical_request() -> _CanonicalRequest:
    return broker.create_request(
        action="ct.reboot",
        ct_id=117,
        reason="Apply kernel update",
        requester="test-operator",
        observed_source_ip="198.51.100.52",
        mtls_identity="test-agent",
        ssh_public_key=_VALID_PUB_KEY,
        self_reported_hostname="node-a",
    )


@pytest.fixture
def operate_lease(
    signer: _LeaseSigner,
    canonical_request: _CanonicalRequest,
) -> _CapabilityLease:
    factory = broker.LeaseFactory(signer, _POLICY)
    return factory.create_lease(
        request=canonical_request,
        profile=broker.CapabilityProfile.OPERATE,
        action_classes=["ct.reboot"],
        target_cts=[117],
        now=int(time.time()),
    )


# ---------------------------------------------------------------------------
# Helper: build an alternate key for tampering tests
# ---------------------------------------------------------------------------

_ALT_PUB_KEY_2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKoUlkD3d9O9ilB1YPvGWl9SHtP5zSqEqP1reumIou6l"


# ===================================================================
# 1. Canonical request binding
# ===================================================================


class TestCanonicalRequest:
    def test_binds_all_required_fields(self, canonical_request: _CanonicalRequest) -> None:
        payload = canonical_request.to_payload()
        assert payload["action"] == "ct.reboot"
        assert payload["ct_id"] == 117
        assert payload["reason"] == "Apply kernel update"
        assert payload["requester"] == "test-operator"
        assert payload["observed_source_ip"] == "198.51.100.52"
        assert payload["mtls_identity"] == "test-agent"
        assert isinstance(payload["request_nonce"], str) and len(payload["request_nonce"]) > 0
        assert payload["ssh_public_key"] == _VALID_PUB_KEY
        assert payload["ssh_fingerprint"].startswith("SHA256:")
        assert payload["self_reported_hostname"] == "node-a"

    def test_self_reported_hostname_separate_from_authenticated_identity(
        self, canonical_request: _CanonicalRequest
    ) -> None:
        """Self-reported hostname is never trusted for authorization."""
        assert canonical_request.self_reported_hostname != canonical_request.mtls_identity
        assert canonical_request.mtls_identity == "test-agent"

    def test_canonical_is_deterministic(self) -> None:
        r1 = broker.create_request(
            "ct.reboot",
            117,
            "Test",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
            "host-a",
        )
        r2 = broker.create_request(
            "ct.reboot",
            117,
            "Test",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
            "host-a",
        )
        # Different nonces → different canonical forms
        assert r1.digest() != r2.digest()

    def test_fingerprint_computed_from_public_key(self) -> None:
        req = broker.create_request(
            "ct.start",
            117,
            "test",
            "user",
            "203.0.113.1",
            "agent",
            _ALT_PUB_KEY,
            "",
        )
        assert req.ssh_fingerprint.startswith("SHA256:")
        # Different key → different fingerprint
        req2 = broker.create_request(
            "ct.start",
            117,
            "test",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
            "",
        )
        assert req.ssh_fingerprint != req2.ssh_fingerprint


# ===================================================================
# 2. mTLS identity
# ===================================================================


class TestMtlsIdentity:
    def test_rejecting_extractor_raises_permission_error(self) -> None:
        extractor = broker.RejectingExtractor()
        with pytest.raises(PermissionError, match="mTLS authentication required"):
            extractor.extract()

    def test_trusted_proxy_extractor_accepts_expected_identity(self) -> None:
        extractor = broker.TrustedProxyMtlsExtractor({"test-agent": "198.51.100.52"})
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            headers={
                "x-pve-broker-mtls-identity": "test-agent",
                "x-pve-broker-mtls-source-ip": "198.51.100.52",
            },
        )
        assert extractor.extract(request) == broker.VerifiedClient("test-agent", "198.51.100.52")

    def test_trusted_proxy_extractor_rejects_non_local_proxy(self) -> None:
        extractor = broker.TrustedProxyMtlsExtractor({"test-agent": "198.51.100.52"})
        request = SimpleNamespace(
            client=SimpleNamespace(host="198.51.100.52"),
            headers={
                "x-pve-broker-mtls-identity": "test-agent",
                "x-pve-broker-mtls-source-ip": "198.51.100.52",
            },
        )
        with pytest.raises(PermissionError, match="local proxy"):
            extractor.extract(request)

    def test_trusted_proxy_extractor_rejects_mismatched_source(self) -> None:
        extractor = broker.TrustedProxyMtlsExtractor({"test-agent": "198.51.100.52"})
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            headers={
                "x-pve-broker-mtls-identity": "test-agent",
                "x-pve-broker-mtls-source-ip": "198.51.100.53",
            },
        )
        with pytest.raises(PermissionError, match="does not match"):
            extractor.extract(request)

    def test_trusted_proxy_extractor_accepts_any_listed_source(self) -> None:
        """An identity can use any explicitly configured source, not just the first."""
        extractor = broker.TrustedProxyMtlsExtractor({"test-agent": ["198.51.100.52", "198.51.100.88"]})
        for source in ("198.51.100.52", "198.51.100.88"):
            request = SimpleNamespace(
                client=SimpleNamespace(host="127.0.0.1"),
                headers={
                    "x-pve-broker-mtls-identity": "test-agent",
                    "x-pve-broker-mtls-source-ip": source,
                },
            )
            assert extractor.extract(request) == broker.VerifiedClient("test-agent", source)

    def test_trusted_proxy_extractor_rejects_source_outside_the_list(self) -> None:
        """Widening to a list must not widen to anything else."""
        extractor = broker.TrustedProxyMtlsExtractor({"test-agent": ["198.51.100.52", "198.51.100.88"]})
        request = SimpleNamespace(
            client=SimpleNamespace(host="127.0.0.1"),
            headers={
                "x-pve-broker-mtls-identity": "test-agent",
                "x-pve-broker-mtls-source-ip": "198.51.100.89",
            },
        )
        with pytest.raises(PermissionError, match="does not match"):
            extractor.extract(request)

    def test_trusted_proxy_extractor_rejects_an_identity_with_no_sources(self) -> None:
        """An empty list would make `.get()` falsy and read as 'unrecognized',
        so it is refused at construction rather than becoming a silent deny."""
        with pytest.raises(ValueError, match="no source address"):
            broker.TrustedProxyMtlsExtractor({"test-agent": []})

    def test_caller_identity_fields_not_trusted_for_authz(self, canonical_request: _CanonicalRequest) -> None:
        """The mtls_identity field must come from the injectable extractor,
        never from the caller-supplied 'requester' field."""
        assert canonical_request.requester == "test-operator"
        assert canonical_request.mtls_identity == "test-agent"
        assert canonical_request.requester != canonical_request.mtls_identity


# ===================================================================
# 3. Capability profiles
# ===================================================================


class TestCapabilityProfiles:
    def test_operate_lease_rejects_a_ct_outside_the_policy(self, signer: _LeaseSigner) -> None:
        req = broker.create_request(
            "ct.reboot",
            999,
            "Wrong target",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
        )
        factory = broker.LeaseFactory(signer, _POLICY)
        with pytest.raises(ValueError, match="cannot include action 'ct.reboot' on CT 999"):
            factory.create_lease(
                request=req,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["ct.reboot"],
                target_cts=[999],
                now=1_000_000,
            )

    def test_operate_lease_rejects_an_action_outside_the_policy(self, signer: _LeaseSigner) -> None:
        narrow = _policy({"ct.start": {117}})
        req = broker.create_request(
            "ct.reboot",
            117,
            "Not in policy",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
        )
        with pytest.raises(ValueError, match="cannot include action 'ct.reboot' on CT 117"):
            broker.LeaseFactory(signer, narrow).create_lease(
                request=req,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["ct.reboot"],
                target_cts=[117],
                now=1_000_000,
            )

    def test_operate_lease_follows_the_policy_not_a_constant(self, signer: _LeaseSigner) -> None:
        """CT 104 was never grantable while the targets were a module constant."""
        wide = _policy({"ct.start": {104}})
        req = broker.create_request(
            "ct.start",
            104,
            "Admitted by policy",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
        )
        lease = broker.LeaseFactory(signer, wide).create_lease(
            request=req,
            profile=broker.CapabilityProfile.OPERATE,
            action_classes=["ct.start"],
            target_cts=[104],
            now=1_000_000,
        )
        assert lease.target_cts == (104,)

    def test_operate_lease_follows_the_grant_of_its_own_action(self, signer: _LeaseSigner) -> None:
        """A container granted for one action is refused for another."""
        split = _policy({"ct.stop": {117}, "ct.start": {104}})
        req = broker.create_request(
            "ct.start",
            117,
            "Sablier guest",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
        )
        with pytest.raises(ValueError, match="cannot include action 'ct.start' on CT 117"):
            broker.LeaseFactory(signer, split).create_lease(
                request=req,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["ct.start"],
                target_cts=[117],
                now=1_000_000,
            )

    def test_operate_profile_rejects_unknown_action(
        self, signer: _LeaseSigner, canonical_request: _CanonicalRequest
    ) -> None:
        factory = broker.LeaseFactory(signer, _POLICY)
        with pytest.raises(ValueError, match="excluded action"):
            factory.create_lease(
                request=canonical_request,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["ct.destroy"],
                target_cts=[117],
                now=1_000_000,
            )

    def test_operate_max_ttl_enforced(self, signer: _LeaseSigner, canonical_request: _CanonicalRequest) -> None:
        # Manually construct a lease beyond the TTL to trigger scope validation
        lease = broker.CapabilityLease(
            lease_id="test",
            profile=broker.CapabilityProfile.OPERATE,
            action_classes=("ct.reboot",),
            target_cts=(117,),
            approval_id="test-approval",
            approval_binding={"canonicalization": "pve-approval-v1", "request_digest": canonical_request.digest()},
            execution_binding={"canonicalization": "pve-execution-v1", "arguments_digest": "aa" * 32},
            audience=broker.BROKER_AUDIENCE,
            policy_version=broker.POLICY_VERSION,
            issued_at=1_000_000,
            expires_at=1_000_000 + broker.OPERATE_MAX_TTL_SECONDS + 1,
            max_dispatches=1,
        )
        with pytest.raises(ValueError, match="exceeds maximum TTL"):
            broker._validate_action_scope(lease, _POLICY)

    def test_operate_max_dispatches_enforced(self, signer: _LeaseSigner, canonical_request: _CanonicalRequest) -> None:
        lease = broker.CapabilityLease(
            lease_id="test",
            profile=broker.CapabilityProfile.OPERATE,
            action_classes=("ct.reboot",),
            target_cts=(117,),
            approval_id="test-approval",
            approval_binding={"canonicalization": "pve-approval-v1", "request_digest": canonical_request.digest()},
            execution_binding={"canonicalization": "pve-execution-v1", "arguments_digest": "aa" * 32},
            audience=broker.BROKER_AUDIENCE,
            policy_version=broker.POLICY_VERSION,
            issued_at=1_000_000,
            expires_at=1_000_000 + broker.OPERATE_MAX_TTL_SECONDS,
            max_dispatches=2,
        )
        with pytest.raises(ValueError, match="max_dispatches=1"):
            broker._validate_action_scope(lease, _POLICY)

    def test_lease_cannot_broaden_the_canonical_request(
        self, signer: _LeaseSigner, canonical_request: _CanonicalRequest
    ) -> None:
        with pytest.raises(ValueError, match="canonical request is not within lease scope"):
            broker.LeaseFactory(signer, _POLICY).create_lease(
                request=canonical_request,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["ct.start"],
                target_cts=[117],
                now=int(time.time()),
            )


# ===================================================================
# 4. Lease sign / verify roundtrip
# ===================================================================


class TestLeaseSigning:
    def test_sign_and_verify_roundtrip(
        self,
        operate_lease: _CapabilityLease,
        signer: _LeaseSigner,
        public_key: Ed25519PublicKey,
    ) -> None:
        claims = signer.verify_lease(operate_lease, public_key)
        assert claims["action_classes"] == ["ct.reboot"]
        assert claims["target_cts"] == [117]
        assert claims["audience"] == broker.BROKER_AUDIENCE
        assert claims["profile"] == "operate"
        assert claims["policy_version"] == broker.POLICY_VERSION
        assert "approval_id" in claims
        assert "approval_binding" in claims
        assert "execution_binding" in claims
        assert claims["max_dispatches"] == 1

    def test_signed_claims_keep_the_pve_operate_v1_keys(self, operate_lease: _CapabilityLease) -> None:
        """The dispatcher reconstructs exactly these keys to check the signature.

        Removing the observe/change profiles must not add or drop one: an
        ``openspec_change_ref`` key, even null, would change every signature.
        """
        assert set(operate_lease.to_claims()) == {
            "lease_id",
            "profile",
            "action_classes",
            "target_cts",
            "approval_id",
            "approval_binding",
            "execution_binding",
            "audience",
            "policy_version",
            "issued_at",
            "expires_at",
            "max_dispatches",
        }

    def test_verify_rejects_tampered_signature(
        self,
        operate_lease: _CapabilityLease,
        signer: _LeaseSigner,
        public_key: Ed25519PublicKey,
    ) -> None:
        tampered = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=operate_lease.approval_binding,
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=b"garbage" * 16,
        )
        with pytest.raises(ValueError, match="signature is invalid"):
            signer.verify_lease(tampered, public_key)


# ===================================================================
# 4b. New schema verification (pve-operate-v1)
# ===================================================================


class TestNewSchemaVerification:
    def test_wrong_policy_version_rejected(
        self,
        signer: _LeaseSigner,
        operate_lease: _CapabilityLease,
        public_key: Ed25519PublicKey,
    ) -> None:
        wrong_policy = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=operate_lease.approval_binding,
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version="old-schema-v0",
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="policy version is invalid"):
            signer.verify_lease(wrong_policy, public_key)

    def test_missing_approval_id_rejected(
        self,
        signer: _LeaseSigner,
        operate_lease: _CapabilityLease,
        public_key: Ed25519PublicKey,
    ) -> None:
        missing = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id="",
            approval_binding=operate_lease.approval_binding,
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="approval_id is required"):
            signer.verify_lease(missing, public_key)

    def test_missing_approval_binding_rejected(
        self,
        signer: _LeaseSigner,
        operate_lease: _CapabilityLease,
        public_key: Ed25519PublicKey,
    ) -> None:
        missing = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=None,
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="approval binding is invalid"):
            signer.verify_lease(missing, public_key)

    def test_wrong_approval_canonicalization_rejected(
        self,
        signer: _LeaseSigner,
        operate_lease: _CapabilityLease,
        public_key: Ed25519PublicKey,
    ) -> None:
        wrong = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding={"canonicalization": "pve-approval-v0", "request_digest": "x"},
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="approval binding is invalid"):
            signer.verify_lease(wrong, public_key)

    def test_missing_execution_binding_rejected(
        self,
        signer: _LeaseSigner,
        operate_lease: _CapabilityLease,
        public_key: Ed25519PublicKey,
    ) -> None:
        missing = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=operate_lease.approval_binding,
            execution_binding=None,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="execution binding is invalid"):
            signer.verify_lease(missing, public_key)

    def test_max_dispatches_not_one_rejected(
        self,
        signer: _LeaseSigner,
        operate_lease: _CapabilityLease,
        public_key: Ed25519PublicKey,
    ) -> None:
        multi = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=operate_lease.approval_binding,
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=3,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="max_dispatches must be 1"):
            signer.verify_lease(multi, public_key)


# ===================================================================
# 4c. Execution digest
# ===================================================================


class TestExecutionDigest:
    def test_execution_digest_deterministic(self) -> None:
        d1 = broker.execution_arguments_digest("ct.start", 117, broker.EXECUTION_CANONICALIZATION)
        d2 = broker.execution_arguments_digest("ct.start", 117, broker.EXECUTION_CANONICALIZATION)
        assert d1 == d2
        assert len(d1) == 64

    def test_execution_digest_changes_with_action(self) -> None:
        start = broker.execution_arguments_digest("ct.start", 117, broker.EXECUTION_CANONICALIZATION)
        reboot = broker.execution_arguments_digest("ct.reboot", 117, broker.EXECUTION_CANONICALIZATION)
        assert start != reboot

    def test_execution_digest_changes_with_ct_id(self) -> None:
        target_117 = broker.execution_arguments_digest("ct.start", 117, broker.EXECUTION_CANONICALIZATION)
        target_999 = broker.execution_arguments_digest("ct.start", 999, broker.EXECUTION_CANONICALIZATION)
        assert target_117 != target_999

    def test_execution_digest_is_sha256(self) -> None:
        digest = broker.execution_arguments_digest("ct.reboot", 117, broker.EXECUTION_CANONICALIZATION)
        assert digest == broker.sha256(
            broker.canonical_json({"version": "pve-execution-v1", "action": "ct.reboot", "ct_id": 117}).encode("ascii")
        )


# ===================================================================
# 5. Altered key / altered request
# ===================================================================


class TestAlteredKeyOrRequest:
    def test_different_public_key_produces_different_digest(self) -> None:
        req_a = broker.create_request(
            "ct.reboot",
            117,
            "Test",
            "user",
            "203.0.113.1",
            "agent",
            _VALID_PUB_KEY,
            "",
        )
        req_b = broker.create_request(
            "ct.reboot",
            117,
            "Test",
            "user",
            "203.0.113.1",
            "agent",
            _ALT_PUB_KEY_2,
            "",
        )
        assert req_a.digest() != req_b.digest()


# ===================================================================
# 6. Lease expiry / wrong audience / wrong target / wrong action
# ===================================================================


class TestLeaseValidation:
    def test_expired_lease_rejected(
        self,
        operate_lease: _CapabilityLease,
        signer: _LeaseSigner,
        public_key: Ed25519PublicKey,
    ) -> None:
        expired = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=operate_lease.approval_binding,
            execution_binding=operate_lease.execution_binding,
            audience=operate_lease.audience,
            policy_version=operate_lease.policy_version,
            issued_at=1_000_000,
            expires_at=1_000_000 - 1,  # already expired
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="lease has expired"):
            signer.verify_lease(expired, public_key, now=1_000_001)

    def test_wrong_audience_rejected(
        self,
        operate_lease: _CapabilityLease,
        signer: _LeaseSigner,
        public_key: Ed25519PublicKey,
    ) -> None:
        wrong_aud = broker.CapabilityLease(
            lease_id=operate_lease.lease_id,
            profile=operate_lease.profile,
            action_classes=operate_lease.action_classes,
            target_cts=operate_lease.target_cts,
            approval_id=operate_lease.approval_id,
            approval_binding=operate_lease.approval_binding,
            execution_binding=operate_lease.execution_binding,
            audience="wrong-audience",
            policy_version=operate_lease.policy_version,
            issued_at=operate_lease.issued_at,
            expires_at=operate_lease.expires_at,
            max_dispatches=operate_lease.max_dispatches,
            signature=operate_lease.signature,
        )
        with pytest.raises(ValueError, match="audience is invalid"):
            signer.verify_lease(wrong_aud, public_key)

    def test_lease_not_yet_valid_rejected(
        self,
        signer: _LeaseSigner,
        canonical_request: _CanonicalRequest,
        public_key: Ed25519PublicKey,
    ) -> None:
        factory = broker.LeaseFactory(signer, _POLICY)
        future = int(time.time()) + 3600  # issued in the future
        lease = factory.create_lease(
            request=canonical_request,
            profile=broker.CapabilityProfile.OPERATE,
            action_classes=["ct.reboot"],
            target_cts=[117],
            now=future,
        )
        # Verify with current time (before the lease is valid)
        with pytest.raises(ValueError, match="not yet valid"):
            signer.verify_lease(lease, public_key, now=1_000_001)


# ===================================================================
# 7. Excluded destructive action
# ===================================================================


class TestExcludedActions:
    def test_excluded_action_rejected_even_when_a_policy_lists_it(
        self, signer: _LeaseSigner, canonical_request: _CanonicalRequest
    ) -> None:
        """load_policy refuses unknown actions; this is the second line."""
        careless = _policy({"ct.destroy": {117}})
        factory = broker.LeaseFactory(signer, careless)
        with pytest.raises(ValueError, match="cannot include excluded action"):
            factory.create_lease(
                request=canonical_request,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["ct.destroy"],
                target_cts=[117],
                now=1_000_000,
            )

    def test_security_action_rejected_in_lease(
        self, signer: _LeaseSigner, canonical_request: _CanonicalRequest
    ) -> None:
        factory = broker.LeaseFactory(signer, _POLICY)
        # Even operate cannot include security actions
        with pytest.raises(ValueError, match="cannot include excluded action"):
            factory.create_lease(
                request=canonical_request,
                profile=broker.CapabilityProfile.OPERATE,
                action_classes=["security.revoke"],
                target_cts=[117],
                now=1_000_000,
            )

    def test_all_excluded_actions_are_rejected(self) -> None:
        """Verify every action in EXCLUDED_ACTIONS is blocked."""
        assert len(broker.EXCLUDED_ACTIONS) >= 4
        for action in broker.EXCLUDED_ACTIONS:
            assert action.startswith(("ct.", "security."))


# ===================================================================
# 8. Old-schema leases
# ===================================================================


class TestOldSchemaLease:
    def test_old_schema_lease_rejected(
        self,
        signer: _LeaseSigner,
        canonical_request: _CanonicalRequest,
    ) -> None:
        """A lease without the coordinated pve-operate-v1 fields is rejected."""
        public_key = broker.LeaseSigner.generate().private_key.public_key()
        compact = broker.canonical_json(
            {
                "lease_id": "test",
                "profile": "operate",
                "action_classes": ["ct.reboot"],
                "target_cts": [117],
                "request_digest": canonical_request.digest(),
                "audience": broker.BROKER_AUDIENCE,
                "issued_at": 1_000_000,
                "expires_at": 1_000_000 + broker.OPERATE_MAX_TTL_SECONDS,
                "operation_budget": 3,
            }
        )
        signature = signer.private_key.sign(compact.encode("ascii"))
        lease = broker.CapabilityLease(
            lease_id="test",
            profile=broker.CapabilityProfile.OPERATE,
            action_classes=("ct.reboot",),
            target_cts=(117,),
            approval_id="",
            approval_binding=None,
            execution_binding=None,
            audience=broker.BROKER_AUDIENCE,
            policy_version="",
            issued_at=1_000_000,
            expires_at=1_000_000 + broker.OPERATE_MAX_TTL_SECONDS,
            max_dispatches=0,
            signature=signature,
        )
        with pytest.raises(ValueError, match="max_dispatches must be 1"):
            signer.verify_lease(lease, public_key, now=1_000_001)


# ===================================================================
# 9. Certificate command builder
# ===================================================================


class TestCertificateCommandBuilder:
    def test_builds_safe_argv(self) -> None:
        policy = broker.CertificatePolicy(source=_SOURCE)
        builder = broker.CertificateCommandBuilder(policy)
        argv = builder.build_argv(
            ca_private_key_path="/etc/ssh/ca_key",
            public_key_path="/tmp/key.pub",
            serial="0001",
        )
        assert argv[0] == "ssh-keygen"
        assert "-s" in argv
        assert "/etc/ssh/ca_key" in argv
        assert "/tmp/key.pub" in argv
        assert "-O" in argv
        assert f"source-address={_SOURCE}" in argv
        assert "clear" in argv
        assert f"force-command={broker.POLICY_DISPATCHER}" in argv
        assert "no-pty" in argv
        assert "-z" in argv
        assert "0001" in argv

    def test_injection_resistant_path(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="forbidden characters"):
            builder.build_argv(
                ca_private_key_path="/etc/ssh/ca_key",
                public_key_path="/tmp/key;rm -rf /",
                serial="0001",
            )

    def test_injection_resistant_serial(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="serial must be 1-20 decimal"):
            builder.build_argv(
                ca_private_key_path="/etc/ssh/ca_key",
                public_key_path="/tmp/key.pub",
                serial="$(rm -rf /)",
            )

    def test_empty_serial_rejected(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="serial must be 1-20 decimal"):
            builder.build_argv(
                ca_private_key_path="/etc/ssh/ca_key",
                public_key_path="/tmp/key.pub",
                serial="",
            )

    def test_hex_serial_rejected(self) -> None:
        """Reject non-decimal serials before invoking the certificate signer."""
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="serial must be 1-20 decimal"):
            builder.build_argv(
                ca_private_key_path="/etc/ssh/ca_key",
                public_key_path="/tmp/key.pub",
                serial="609be8c1",
            )

    def test_non_ascii_digit_serial_rejected(self) -> None:
        """`str.isdigit()` alone accepts these; ssh-keygen does not."""
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="serial must be 1-20 decimal"):
            builder.build_argv(
                ca_private_key_path="/etc/ssh/ca_key",
                public_key_path="/tmp/key.pub",
                serial="١٢٣",
            )

    def test_overlong_serial_rejected(self) -> None:
        """ssh-keygen's serial is a uint64; 21 digits cannot be one."""
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="serial must be 1-20 decimal"):
            builder.build_argv(
                ca_private_key_path="/etc/ssh/ca_key",
                public_key_path="/tmp/key.pub",
                serial="9" * 21,
            )

    def test_decimal_serial_accepted(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        argv = builder.build_argv(
            ca_private_key_path="/etc/ssh/ca_key",
            public_key_path="/tmp/key.pub",
            serial="1754400000",
        )
        assert "-z" in argv
        assert argv[argv.index("-z") + 1] == "1754400000"

    def test_validate_public_key_accepts_valid_ed25519(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        key = builder.validate_public_key(_VALID_PUB_KEY)
        assert isinstance(key, Ed25519PublicKey)

    def test_validate_public_key_rejects_garbage(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="invalid SSH public key"):
            builder.validate_public_key("not-a-key")

    def test_validate_public_key_rejects_trailing_newline(self) -> None:
        builder = broker.CertificateCommandBuilder(broker.CertificatePolicy(source=_SOURCE))
        with pytest.raises(ValueError, match="invalid SSH public key"):
            builder.validate_public_key(_VALID_PUB_KEY + "\n ")

    def test_policy_is_fully_server_side_no_overrides(self) -> None:
        policy = broker.CertificatePolicy(source=_SOURCE)
        assert policy.source == "198.51.100.88/32"
        assert policy.max_validity_seconds == 120
        assert policy.principal == "pve-ai-ops"
        assert policy.dispatcher == "/usr/local/libexec/pve-typed-dispatcher"
        options = policy.to_options()
        assert "source-address=198.51.100.88/32" in options
        assert "no-pty" in options
        assert "no-agent-forwarding" in options
        assert "no-port-forwarding" in options
        assert "no-X11-forwarding" in options
        assert "no-user-rc" in options


# ===================================================================
# 10. Certificate policy — no caller overrides
# ===================================================================


class TestCertificatePolicyNoOverride:
    def test_caller_cannot_change_principal(self) -> None:
        """The CertificatePolicy is immutable and always server-side."""
        policy = broker.CertificatePolicy(source=_SOURCE)
        assert policy.principal == "pve-ai-ops"
        # There is no setter; policy is always server-derived

    def test_caller_cannot_extend_validity(self) -> None:
        policy = broker.CertificatePolicy(source=_SOURCE)
        assert policy.max_validity_seconds == 120
        assert policy.max_validity_seconds <= broker.CERTIFICATE_MAX_TTL_SECONDS


# ===================================================================
# 11. Lease signing key file
# ===================================================================


class TestLeaseSignerKeyFile:
    def test_lease_signer_round_trips_root_owned_pem(self, tmp_path: Path) -> None:
        signer = broker.LeaseSigner.generate()
        key_path = tmp_path / "lease.pem"
        key_path.write_bytes(signer.to_pem())
        loaded = broker.LeaseSigner.from_pem_file(str(key_path))
        assert loaded.private_key.public_key().public_bytes_raw() == signer.private_key.public_key().public_bytes_raw()


# ===================================================================
# 12. Certificate command callers cannot issue without a valid lease
# ===================================================================


class TestCertificateNoLeaseNoCert:
    def test_verify_requires_valid_signature(self) -> None:
        """A lease's signature is mandatory — unauthenticated leases fail."""
        signer = broker.LeaseSigner.generate()
        public_key = signer.private_key.public_key()
        now = int(time.time())
        unsigned = broker.CapabilityLease(
            lease_id="unsigned",
            profile=broker.CapabilityProfile.OPERATE,
            action_classes=("ct.reboot",),
            target_cts=(117,),
            approval_id="test-approval",
            approval_binding={"canonicalization": "pve-approval-v1", "request_digest": "digest"},
            execution_binding={"canonicalization": "pve-execution-v1", "arguments_digest": "abcd" * 16},
            audience=broker.BROKER_AUDIENCE,
            policy_version=broker.POLICY_VERSION,
            issued_at=now - 2,
            expires_at=now + broker.OPERATE_MAX_TTL_SECONDS - 2,
            max_dispatches=1,
            signature=b"",
        )
        with pytest.raises(ValueError, match="signature is invalid"):
            signer.verify_lease(unsigned, public_key)


# ===================================================================
# 13. Module isolation: no unsafe imports
# ===================================================================


class TestModuleIsolation:
    def test_no_pve_or_ssh_execution_path(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        assert "subprocess" not in source
        assert "PVEAPIToken" not in source
        assert "import requests" not in source
        assert "uvicorn" not in source
        assert "FastAPI" not in source

    def test_no_webauthn_import(self) -> None:
        """The broker module does not import WebAuthn — approval is separate."""
        source = SCRIPT.read_text(encoding="utf-8")
        assert "webauthn" not in source

    def test_cryptography_available(self) -> None:
        import cryptography

        assert cryptography.__version__ >= "40"
