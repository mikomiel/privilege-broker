"""Agent-facing approval request bridge.

Creates typed broker requests with an ephemeral Ed25519 key and records the
pending input file the worker consumes. This is a library: it starts no
server, reads no environment and carries no deployment default. The approval
URL it returns points at the operator-facing page of the configured public
URL.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .client import BrokerClient
from .common import TYPED_ACTIONS

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class BridgeConfig:
    """Explicit bridge configuration; no deployment defaults exist."""

    #: Persistent state root; holds ``input/``, ``results/`` and ``keys/``.
    state_dir: Path
    #: ``https://`` base URL of the broker's public approval pages.
    public_url: str
    #: Requester name sent in every broker request.
    requester: str

    def __post_init__(self) -> None:
        if isinstance(self.state_dir, str):
            object.__setattr__(self, "state_dir", Path(self.state_dir))
        if not self.public_url.startswith("https://"):
            raise ValueError("public_url must be an https:// URL")
        if not isinstance(self.requester, str) or not 1 <= len(self.requester.strip()) <= 100:
            raise ValueError("requester must be 1-100 characters")


class ApprovalBridge:
    """Creates approval-gated mutation requests and reads their local state.

    Nothing executes here: a request only exists at the broker until a human
    approves it, and the worker turns an approval into a dispatch.
    """

    def __init__(self, config: BridgeConfig) -> None:
        self._config = config

    @property
    def _input_dir(self) -> Path:
        return self._config.state_dir / "input"

    @property
    def _results_dir(self) -> Path:
        return self._config.state_dir / "results"

    @property
    def _keys_dir(self) -> Path:
        return self._config.state_dir / "keys"

    def _validated_create_response(self, response: object) -> tuple[str, int]:
        """Validate the broker create response before any filesystem publication."""
        if not isinstance(response, dict):
            raise ValueError("broker create response must be an object")
        request_id = response.get("request_id")
        if not isinstance(request_id, str) or not _UUID_RE.fullmatch(request_id):
            raise ValueError("broker create response request_id must be a canonical UUID")
        if response.get("status") != "pending":
            raise ValueError("broker create response status must be pending")
        expires_at = response.get("expires_at")
        if type(expires_at) is not int:
            raise ValueError("broker create response expires_at must be an integer")
        return request_id, expires_at

    def request_mutation(self, action: str, ct_id: int, reason: str, client: BrokerClient) -> dict[str, Any]:
        """Request an approval-gated typed operation; nothing runs until approved.

        Returns ``request_id``, ``status``, ``expires_at`` and the
        ``approval_url`` to hand to the operator. The ephemeral private key is
        removed again if the broker call or the response validation fails.
        """
        if action not in TYPED_ACTIONS:
            raise ValueError(f"action must be one of {sorted(TYPED_ACTIONS)}")
        if type(ct_id) is not int or ct_id < 1:
            raise ValueError("ct_id must be a positive integer")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise ValueError("reason must be 1-500 characters")

        private_key = Ed25519PrivateKey.generate()
        key_id = uuid.uuid4().hex
        self._keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_path = self._keys_dir / f"{key_id}.key"
        key_path.write_bytes(private_key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
        key_path.chmod(0o600)
        public_key = private_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")

        try:
            response = client.request(
                "POST",
                "/v1/broker/requests",
                {
                    "action": action,
                    "ct_id": ct_id,
                    "reason": reason,
                    "requester": self._config.requester,
                    "ssh_public_key": public_key,
                },
            )
            request_id, expires_at = self._validated_create_response(response)
        except Exception:
            # The ephemeral private key never survives a failed request.
            key_path.unlink(missing_ok=True)
            raise

        self._input_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        input_data = {
            "request_id": request_id,
            "action": action,
            "ct_id": ct_id,
            "reason": reason,
            "public_key": public_key,
            "key_id": key_id,
            "expires_at": expires_at,
        }
        (self._input_dir / f"{request_id}.json").write_text(json.dumps(input_data), encoding="utf-8")
        return {
            "request_id": request_id,
            "status": "pending",
            "expires_at": expires_at,
            "approval_url": f"{self._config.public_url.rstrip('/')}/v1/broker/requests/{request_id}/approval",
        }

    def read_status(self, request_id: str) -> dict[str, Any]:
        """Return the worker's terminal result, ``pending``, or ``unknown``."""
        if not isinstance(request_id, str) or not _UUID_RE.fullmatch(request_id):
            raise ValueError("request_id must be a canonical UUID")
        result_file = self._results_dir / f"{request_id}.json"
        if result_file.exists():
            return json.loads(result_file.read_text(encoding="utf-8"))
        if (self._input_dir / f"{request_id}.json").exists():
            return {"status": "pending"}
        return {"status": "unknown", "error": "request not found or expired"}
