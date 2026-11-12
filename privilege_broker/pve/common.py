"""PVE policy and canonical wire helpers shared by authorization and dispatch."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Every action the dispatcher can execute. A policy file may only narrow this
#: set; an action outside it is a configuration error, not a grant.
TYPED_ACTIONS: frozenset[str] = frozenset(
    {
        "ct.start",
        "ct.stop",
        "ct.reboot",
        "ct.shutdown",
        "ct.snapshot",
        "ct.snapshot_prune",
    }
)


class PolicyError(ValueError):
    """The operate policy file is missing or malformed."""


@dataclass(frozen=True)
class Policy:
    """Which typed action may run on which containers.

    Configured by the deployer and read by both broker and dispatcher, so a
    container is admitted in one place and enforced twice. A grant is per
    action: a container can be admitted for one action and refused another.
    ``load_policy`` validates; this class does not, so a test can build a
    policy that the loader would refuse.
    """

    grants: Mapping[str, frozenset[int]]
    #: ``ct.snapshot_prune`` deletes broker snapshots older than this.
    snapshot_retention_days: int

    def allows(self, action: str, ct_id: int) -> bool:
        return ct_id in self.grants.get(action, frozenset())


_POLICY_KEYS = frozenset({"version", "grants", "snapshot_retention_days"})


def _positive_int(value: object) -> bool:
    # bool is an int subclass; `true` must not silently admit CT 1.
    return type(value) is int and value >= 1


def load_policy(path: Path) -> Policy:
    """Read a version 2 policy file, failing closed on anything else.

    The shape is ``{"version": 2, "grants": {"<action>": [<ct id>, ...]},
    "snapshot_retention_days": <days>}``, with no other key.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError(f"policy file {path} is unreadable: {exc}") from exc
    if not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 2:
        raise PolicyError("policy must be an object with version 2")
    if set(data) != _POLICY_KEYS:
        raise PolicyError(f"policy keys must be exactly {sorted(_POLICY_KEYS)}")
    grants = data["grants"]
    if not isinstance(grants, dict) or not all(
        isinstance(ct_ids, list) and all(_positive_int(ct) for ct in ct_ids) for ct_ids in grants.values()
    ):
        raise PolicyError("policy grants must map each action to a list of positive integers")
    unknown = sorted(set(grants) - TYPED_ACTIONS)
    if unknown:
        raise PolicyError(f"policy names unknown actions: {unknown}")
    if not _positive_int(data["snapshot_retention_days"]):
        raise PolicyError("policy snapshot_retention_days must be a positive integer")
    return Policy(
        grants={action: frozenset(ct_ids) for action, ct_ids in grants.items()},
        snapshot_retention_days=data["snapshot_retention_days"],
    )


def canonical_json(value: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, no whitespace."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def execution_arguments_digest(action: str, ct_id: int, version: str) -> str:
    """SHA-256 over deterministic JSON ``{"version","action","ct_id"}``."""
    payload = {"version": version, "action": action, "ct_id": ct_id}
    return sha256(canonical_json(payload).encode("ascii"))
