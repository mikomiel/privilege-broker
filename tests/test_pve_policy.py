"""Policy parsing and explicit certificate configuration at the public boundary."""

import dataclasses
import json

import pytest

from privilege_broker.pve.authorization import CertificateCommandBuilder, CertificatePolicy
from privilege_broker.pve.common import PolicyError, load_policy


def test_policy_uses_per_action_grants_and_retention(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 2, "grants": {"ct.reboot": [7001]}, "snapshot_retention_days": 7}))
    policy = load_policy(path)
    assert policy.allows("ct.reboot", 7001)
    assert not policy.allows("ct.start", 7001)
    assert not policy.allows("ct.reboot", 7002)
    assert policy.snapshot_retention_days == 7


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"version": 1, "grants": {}, "snapshot_retention_days": 7},
        {"version": True, "grants": {}, "snapshot_retention_days": 7},
        {"version": 2, "grants": {"ct.destroy": [7001]}, "snapshot_retention_days": 7},
        {"version": 2, "grants": {"ct.reboot": [True]}, "snapshot_retention_days": 7},
        {"version": 2, "grants": {"ct.reboot": [0]}, "snapshot_retention_days": 7},
        {"version": 2, "grants": [], "snapshot_retention_days": 7},
        {"version": 2, "grants": {}, "snapshot_retention_days": True},
        {"version": 2, "grants": {}, "snapshot_retention_days": 0},
        {"version": 2, "grants": {}, "snapshot_retention_days": 7, "allow_all": True},
    ],
)
def test_malformed_policy_fails_closed(tmp_path, document):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document))
    with pytest.raises(PolicyError):
        load_policy(path)


def test_unreadable_or_non_json_policy_fails_closed(tmp_path):
    path = tmp_path / "policy.json"
    with pytest.raises(PolicyError, match="unreadable"):
        load_policy(path)
    path.write_text("not JSON")
    with pytest.raises(PolicyError, match="unreadable"):
        load_policy(path)


def test_certificate_source_and_builder_have_no_implicit_default():
    with pytest.raises(TypeError):
        CertificatePolicy()
    with pytest.raises(TypeError):
        CertificateCommandBuilder()


@pytest.mark.parametrize("source", ["", None, "not-a-network", "0.0.0.0/0", "::/0"])
def test_certificate_requires_a_valid_restricted_source(source):
    with pytest.raises(ValueError):
        CertificatePolicy(source=source)


def test_certificate_source_is_immutable_and_preserves_other_restrictions():
    policy = CertificatePolicy(source="198.51.100.88/32")
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.source = "198.51.100.90/32"
    assert policy.to_options() == [
        "clear",
        "source-address=198.51.100.88/32",
        "force-command=/usr/local/libexec/pve-typed-dispatcher",
        "no-pty",
        "no-agent-forwarding",
        "no-port-forwarding",
        "no-X11-forwarding",
        "no-user-rc",
    ]
