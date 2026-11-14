"""Target-side typed dispatcher for approved PVE operations.

This module is the executor side of the product. It reads one JSON request from
stdin, verifies the signed ``pve-operate-v1`` lease against a deployer-supplied
Ed25519 public key, re-verifies the target policy, atomically claims the lease in
a durable SQLite store and then runs exactly one fixed argv -- never a shell and
never ``SSH_ORIGINAL_COMMAND``.

Output contract, preserved from the retained implementation::

    success/failure  {"exit_code", "stdout", "stderr", "lease_id"}
    replay           the stored result plus "replayed": true
    refusal          {"error": "...", "exit_code": 1}              exit 1
    wrong node       {"error": "not_on_this_node", "exit_code": 3} exit 3

Nothing executes twice in one claim database: a lease is committed durably
before the command starts, a repeat presentation returns the stored terminal
result, and a claim left ``CLAIMED`` (the process died) becomes ``UNKNOWN``
instead of being retried. A node that does not host the container answers before
the claim, so the worker may present the same lease to the next configured node.

**At-most-once scope.** The guarantee is scoped to one host and one claim
database. A lease that is still valid can be presented to a second node with its
own database, and a container that later moved there would run again. This
implementation therefore supports exactly one eligible executor per target: the
dispatcher host must be the only node that can run that target's operation for
the lease lifetime, which is why a target that can migrate is out of scope.
SQLite WAL is a single-host mechanism; do not share the database over a network
filesystem. Cross-host exclusivity needs a coordination service the broker
controls, and binding a lease to one executor needs a wire change; both are
tracked separately.

``ct.snapshot_prune`` is not dispatched yet; it arrives with OpenSpec task 4.3.
The request is refused before any claim, so no authority is consumed.

Every path, key and the SQLite database are explicit constructor or CLI input.
The module reads no environment variable, holds no built-in deployment path and
starts nothing at import.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from .common import (
    TYPED_ACTIONS,
    Policy,
    PolicyError,
    b64decode,
    canonical_json,
    execution_arguments_digest,
    load_policy,
)

#: Lease audience this dispatcher accepts.
AUDIENCE = "pve-privileged-executor"
#: Lease and policy schema this dispatcher accepts.
POLICY_VERSION = "pve-operate-v1"
#: Canonicalization of the lease execution binding.
EXECUTION_CANONICALIZATION = "pve-execution-v1"
#: Canonicalization of the lease approval binding.
APPROVAL_CANONICALIZATION = "pve-approval-v1"
#: Only an operating profile may execute a mutation.
ALLOWED_PROFILES: frozenset[str] = frozenset({"operate"})
#: Longest lease lifetime the dispatcher accepts, in seconds.
MAX_LEASE_TTL_SECONDS = 300
#: Exit code telling the worker "the container is on another node".
NOT_ON_THIS_NODE_EXIT = 3
#: Action reserved for OpenSpec task 4.3.
PRUNE_ACTION = "ct.snapshot_prune"
#: Byte limit for one stored output stream.
_OUTPUT_LIMIT = 4096
#: Largest request document the dispatcher reads from stdin.
MAX_REQUEST_BYTES = 64 * 1024
#: Longest time the dispatcher waits for that request.
REQUEST_READ_TIMEOUT = 10.0

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_LEASE_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SNAPSHOT_NAME_RE = re.compile(r"^broker-[0-9a-f]{12}$")

# The process umask is global; two concurrent ClaimStore constructions can
# interleave their save/restore pairs and leave the whole process at 077.
_UMASK_LOCK = threading.Lock()

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True)
class DispatchConfig:
    """Explicit dispatcher configuration; no deployment default exists.

    ``command_timeout`` bounds one underlying operation, and the worker's SSH
    timeout must stay above it so the worker never reports a local timeout while
    the dispatcher is still working.
    """

    #: Version 2 target policy shared with the broker.
    policy_path: Path
    #: Ed25519 public key of the approval broker's lease signer.
    lease_public_key_path: Path
    #: Durable claim store; its parent must be deployer-protected.
    claim_db_path: Path
    #: Directory that lists only this node's containers.
    lxc_conf_dir: Path
    #: ``sudo`` used to reach ``pct``.
    sudo_path: str = "/usr/bin/sudo"
    #: ``pct`` binary.
    pct_path: str = "/usr/sbin/pct"
    #: Timeout of one underlying operation, in seconds.
    command_timeout: int = 180
    #: Longest accepted lease lifetime, in seconds.
    max_lease_ttl: int = MAX_LEASE_TTL_SECONDS

    def __post_init__(self) -> None:
        for name in ("policy_path", "lease_public_key_path", "claim_db_path", "lxc_conf_dir"):
            value = getattr(self, name)
            if isinstance(value, str):
                object.__setattr__(self, name, Path(value))
            elif not isinstance(value, Path):
                raise ValueError(f"{name} must be a path")
        for name in ("sudo_path", "pct_path"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("command_timeout", "max_lease_ttl"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")

    def operation_argv(self, action: str, ct_id: int, lease_id: str) -> list[str]:
        """Return the fixed argv for *action*, or raise ``ValueError``.

        The snapshot name is derived from the lease, so the execution digest
        needs no caller-supplied argument.
        """
        base = {
            "ct.reboot": [self.sudo_path, self.pct_path, "reboot"],
            "ct.start": [self.sudo_path, self.pct_path, "start"],
            "ct.stop": [self.sudo_path, self.pct_path, "stop"],
            "ct.shutdown": [self.sudo_path, self.pct_path, "shutdown"],
            "ct.snapshot": [self.sudo_path, self.pct_path, "snapshot"],
        }.get(action)
        if base is None:
            raise ValueError(f"unknown operation: {action}")
        argv = [*base, str(ct_id)]
        if action == "ct.snapshot":
            if not _LEASE_UUID_RE.fullmatch(lease_id):
                raise ValueError("snapshot requires a lowercase UUID lease_id")
            name = f"broker-{lease_id.replace('-', '')[:12]}"
            if not _SNAPSHOT_NAME_RE.fullmatch(name):
                raise ValueError("snapshot name is invalid")
            argv.append(name)
        return argv


@dataclass
class CapabilityLease:
    """``pve-operate-v1`` lease reconstructed for target-side verification."""

    lease_id: str
    profile: str
    action_classes: list[str]
    target_cts: list[int]
    approval_id: str
    audience: str
    issued_at: int
    expires_at: int
    approval_binding: dict[str, str] | None = None
    execution_binding: dict[str, str] | None = None
    policy_version: str = POLICY_VERSION
    max_dispatches: int = 1
    openspec_change_ref: str | None = None
    signature: bytes = b""

    def to_claims(self) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "lease_id": self.lease_id,
            "profile": self.profile,
            "action_classes": self.action_classes,
            "target_cts": self.target_cts,
            "approval_id": self.approval_id,
            "approval_binding": self.approval_binding,
            "execution_binding": self.execution_binding,
            "audience": self.audience,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "max_dispatches": self.max_dispatches,
        }
        if self.openspec_change_ref is not None:
            claims["openspec_change_ref"] = self.openspec_change_ref
        return claims

    def to_compact(self) -> str:
        return canonical_json(self.to_claims())


@dataclass(frozen=True)
class DispatchRequest:
    """One parsed request: the action, the target and the signed lease."""

    action: str
    ct_id: int
    lease: CapabilityLease


def parse_request(text: str) -> DispatchRequest:
    """Parse the dispatcher's stdin document, failing closed on any oddity."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        # RecursionError: deeply nested JSON within the byte bound.
        raise ValueError("request is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("request must be a JSON object")
    action = data.get("action")
    ct_id = data.get("ct_id")
    lease_data = data.get("lease")
    signature = data.get("signature")
    if not isinstance(action, str) or action not in TYPED_ACTIONS:
        raise ValueError("action is not a supported typed action")
    if type(ct_id) is not int or ct_id < 1:
        raise ValueError("ct_id must be a positive integer")
    if not isinstance(lease_data, dict):
        raise ValueError("lease is required")
    if not isinstance(signature, str) or not signature:
        raise ValueError("signature is required")
    try:
        raw_signature = b64decode(signature)
    except (ValueError, TypeError) as exc:
        raise ValueError("lease signature is not valid base64") from exc
    lease = CapabilityLease(
        lease_id=lease_data.get("lease_id", ""),
        profile=lease_data.get("profile", ""),
        action_classes=lease_data.get("action_classes", []),
        target_cts=lease_data.get("target_cts", []),
        approval_id=lease_data.get("approval_id", ""),
        audience=lease_data.get("audience", ""),
        issued_at=lease_data.get("issued_at", 0),
        expires_at=lease_data.get("expires_at", 0),
        approval_binding=lease_data.get("approval_binding"),
        execution_binding=lease_data.get("execution_binding"),
        policy_version=lease_data.get("policy_version", ""),
        max_dispatches=lease_data.get("max_dispatches", 0),
        openspec_change_ref=lease_data.get("openspec_change_ref"),
        signature=raw_signature,
    )
    return DispatchRequest(action=action, ct_id=ct_id, lease=lease)


def verify_lease(lease: CapabilityLease, public_key: Ed25519PublicKey, *, now: int) -> dict[str, Any]:
    """Verify shape, scope and signature; return the signed claims.

    Every structural and temporal check runs before the signature check, so a
    malformed lease fails without reaching cryptography.
    """
    if not lease.lease_id:
        raise ValueError("lease_id is required")
    if lease.profile not in ("observe", "operate", "change"):
        raise ValueError("lease profile is invalid")
    if not isinstance(lease.action_classes, list) or not lease.action_classes:
        raise ValueError("lease action_classes must be a non-empty list")
    if not all(isinstance(action, str) and action for action in lease.action_classes):
        raise ValueError("lease action_classes must be non-empty strings")
    if not isinstance(lease.target_cts, list) or not lease.target_cts:
        raise ValueError("lease target_cts must be a non-empty list")
    if not all(type(ct) is int and ct >= 1 for ct in lease.target_cts):
        raise ValueError("lease target_cts must be positive integers")
    if type(lease.max_dispatches) is not int or lease.max_dispatches != 1:
        raise ValueError("lease max_dispatches must be 1")
    if lease.policy_version != POLICY_VERSION:
        raise ValueError("lease policy version is invalid")
    if not lease.approval_id:
        raise ValueError("lease approval_id is required")
    if not isinstance(lease.approval_binding, dict):
        raise ValueError("lease approval binding is invalid or missing")
    if lease.approval_binding.get("canonicalization") != APPROVAL_CANONICALIZATION:
        raise ValueError("lease approval binding is invalid or missing")
    request_digest = lease.approval_binding.get("request_digest", "")
    if not isinstance(request_digest, str) or not _HEX64_RE.fullmatch(request_digest):
        raise ValueError("lease approval binding request_digest must be 64-char lowercase hex")
    if not isinstance(lease.execution_binding, dict):
        raise ValueError("lease execution binding is invalid or missing")
    if lease.execution_binding.get("canonicalization") != EXECUTION_CANONICALIZATION:
        raise ValueError("lease execution binding is invalid or missing")
    arguments_digest = lease.execution_binding.get("arguments_digest", "")
    if not isinstance(arguments_digest, str) or not _HEX64_RE.fullmatch(arguments_digest):
        raise ValueError("lease execution binding arguments_digest must be 64-char lowercase hex")
    if lease.audience != AUDIENCE:
        raise ValueError("lease audience is invalid")
    if type(lease.issued_at) is not int or type(lease.expires_at) is not int:
        raise ValueError("lease timestamps must be integers")
    if lease.expires_at < now:
        raise ValueError("lease has expired")
    if lease.issued_at > now:
        raise ValueError("lease is not yet valid")
    try:
        public_key.verify(lease.signature, lease.to_compact().encode("ascii"))
    except InvalidSignature as exc:
        raise ValueError("lease signature is invalid") from exc
    return lease.to_claims()


def load_lease_public_key(path: Path) -> Ed25519PublicKey:
    """Load the deployer-supplied Ed25519 lease verification key."""
    try:
        key = load_ssh_public_key(Path(path).read_bytes())
    except (OSError, ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("lease public key is unreadable") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("lease public key must be Ed25519")
    return key


def _truncate(value: str, limit: int = _OUTPUT_LIMIT) -> str:
    """Cut *value* to at most *limit* UTF-8 bytes without splitting a character."""
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore")


class ClaimStore:
    """Durable SQLite claim boundary: one execution per lease, ever.

    States are ``CLAIMED``, ``SUCCEEDED``, ``FAILED`` and ``UNKNOWN``. The claim
    is an atomic ``INSERT OR IGNORE``, so exactly one caller wins it across
    threads and processes. A stored claim whose action or target differs from
    the presented request is treated as ``UNKNOWN``, never executed.
    """

    def __init__(self, db_path: Path) -> None:
        db_path = Path(db_path)
        db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _UMASK_LOCK:
            old_umask = os.umask(0o077)
            try:
                self._connection = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
            finally:
                os.umask(old_umask)
        self._connection.row_factory = sqlite3.Row
        try:
            self._connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                -- FULL fsyncs every commit, so a claim is durable before the
                -- operation starts. NORMAL can lose an acknowledged claim.
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS dispatch_claims (
                  lease_id TEXT PRIMARY KEY,
                  action TEXT NOT NULL,
                  ct_id INTEGER NOT NULL,
                  state TEXT NOT NULL DEFAULT 'CLAIMED',
                  exit_code INTEGER,
                  stdout TEXT,
                  stderr TEXT,
                  created_at INTEGER NOT NULL,
                  completed_at INTEGER
                );
                """
            )
        except BaseException:
            # Never leak a half-initialized connection or WAL handle.
            self._connection.close()
            raise
        try:
            db_path.chmod(0o600)
        except OSError:
            # A filesystem that refuses chmod keeps the umask-protected mode.
            pass

    @property
    def synchronous_level(self) -> int:
        """SQLite durability of this connection: 2 is ``FULL``, 1 is ``NORMAL``."""
        return int(self._connection.execute("PRAGMA synchronous").fetchone()[0])

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> ClaimStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def claim(self, lease_id: str, action: str, ct_id: int, now: int) -> tuple[str, dict[str, Any] | None]:
        """Claim *lease_id*, or report the state and result of the existing claim."""
        cursor = self._connection.execute(
            "INSERT OR IGNORE INTO dispatch_claims (lease_id, action, ct_id, state, created_at) "
            "VALUES (?, ?, ?, 'CLAIMED', ?)",
            (lease_id, action, ct_id, now),
        )
        if cursor.rowcount == 1:
            return ("CLAIMED", None)
        row = self._connection.execute(
            "SELECT state, action, ct_id, exit_code, stdout, stderr FROM dispatch_claims WHERE lease_id = ?",
            (lease_id,),
        ).fetchone()
        if row is None:
            return ("UNKNOWN", None)
        if row["action"] != action or row["ct_id"] != ct_id:
            return ("UNKNOWN", None)
        if row["state"] in ("SUCCEEDED", "FAILED"):
            return (
                row["state"],
                {
                    "exit_code": row["exit_code"],
                    "stdout": row["stdout"] or "",
                    "stderr": row["stderr"] or "",
                },
            )
        if row["state"] == "CLAIMED":
            # The previous process claimed and never finished. The outcome is
            # unknown, so the lease is never executed again.
            self._connection.execute(
                "UPDATE dispatch_claims SET state = 'UNKNOWN', completed_at = ? "
                "WHERE lease_id = ? AND state = 'CLAIMED'",
                (now, lease_id),
            )
        return ("UNKNOWN", None)

    def complete(self, lease_id: str, state: str, exit_code: int | None, stdout: str, stderr: str, now: int) -> None:
        self._connection.execute(
            "UPDATE dispatch_claims SET state = ?, exit_code = ?, stdout = ?, stderr = ?, "
            "completed_at = ? WHERE lease_id = ?",
            (state, exit_code, _truncate(stdout), _truncate(stderr), now, lease_id),
        )

    def get(self, lease_id: str) -> dict[str, Any] | None:
        row = self._connection.execute("SELECT * FROM dispatch_claims WHERE lease_id = ?", (lease_id,)).fetchone()
        return dict(row) if row else None


def _refusal(message: str) -> tuple[int, dict[str, Any]]:
    return (1, {"error": message, "exit_code": 1})


def _on_this_node(config: DispatchConfig, ct_id: int) -> bool:
    """Report container locality without claiming authority.

    ``os.stat`` rather than ``Path.exists``: from Python 3.13 ``exists()``
    reports False for EACCES, which would turn a permission fault into a
    misleading "wrong node".
    """
    try:
        os.stat(config.lxc_conf_dir / f"{ct_id}.conf")
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError("cannot inspect the container directory") from exc
    return True


def dispatch(
    request: DispatchRequest,
    config: DispatchConfig,
    *,
    public_key: Ed25519PublicKey,
    now: int,
    store: ClaimStore | None = None,
    runner: Runner = subprocess.run,
) -> tuple[int, dict[str, Any]]:
    """Verify, claim and execute one request; return (exit code, JSON output).

    The lease is claimed before the command starts and the terminal state is
    stored, so a replay returns the stored result instead of executing again.
    """
    try:
        claims = verify_lease(request.lease, public_key, now=now)
    except ValueError as exc:
        return _refusal(str(exc))

    if claims["profile"] not in ALLOWED_PROFILES:
        return _refusal("lease profile is not allowed to execute")
    try:
        policy: Policy = load_policy(config.policy_path)
    except PolicyError as exc:
        return _refusal(str(exc))
    if not policy.allows(request.action, request.ct_id):
        return _refusal("action is not permitted by the dispatcher policy")

    lease_ttl = claims["expires_at"] - claims["issued_at"]
    if lease_ttl > config.max_lease_ttl:
        return _refusal("lease TTL exceeds the dispatcher maximum")

    expected_digest = execution_arguments_digest(request.action, request.ct_id, EXECUTION_CANONICALIZATION)
    binding = request.lease.execution_binding or {}
    if expected_digest != binding.get("arguments_digest"):
        return _refusal("execution digest does not match the lease binding")
    if request.action not in claims["action_classes"]:
        return _refusal("action is not within the lease scope")
    if request.ct_id not in claims["target_cts"]:
        return _refusal("target is not within the lease scope")
    if request.action == PRUNE_ACTION:
        return _refusal("snapshot pruning is not dispatched by this extraction stage")

    try:
        argv = config.operation_argv(request.action, request.ct_id, request.lease.lease_id)
    except ValueError as exc:
        return _refusal(str(exc))

    try:
        if not _on_this_node(config, request.ct_id):
            return (NOT_ON_THIS_NODE_EXIT, {"error": "not_on_this_node", "exit_code": NOT_ON_THIS_NODE_EXIT})
    except ValueError as exc:
        return _refusal(str(exc))

    owns_store = store is None
    if store is not None:
        claim_store = store
    else:
        try:
            claim_store = ClaimStore(config.claim_db_path)
        except (sqlite3.Error, OSError):
            # Directory creation, connect, WAL setup or schema creation failed.
            # Nothing executed, so the request is refused, not retried here.
            return _refusal("claim store is unavailable; nothing was executed")

    def record(state: str, exit_code: int | None, stdout: str, stderr: str) -> bool:
        try:
            claim_store.complete(request.lease.lease_id, state, exit_code, stdout, stderr, now)
        except sqlite3.Error:
            # The claim row keeps its CLAIMED state, so a later presentation is
            # UNKNOWN rather than a second execution.
            return False
        return True

    try:
        try:
            state, stored = claim_store.claim(request.lease.lease_id, request.action, request.ct_id, now)
        except sqlite3.Error:
            return _refusal("claim store is unavailable; nothing was executed")
        if state in ("SUCCEEDED", "FAILED"):
            assert stored is not None
            return (
                int(stored["exit_code"] or 0),
                {
                    "exit_code": stored["exit_code"],
                    "stdout": stored["stdout"],
                    "stderr": stored["stderr"],
                    "lease_id": request.lease.lease_id,
                    "replayed": True,
                },
            )
        if state == "UNKNOWN":
            return _refusal("previous dispatch outcome is unknown; it is never retried")

        try:
            result = runner(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=config.command_timeout,
            )
        except subprocess.TimeoutExpired:
            record("UNKNOWN", None, "", "timed out")
            return _refusal("operation timed out; the remote outcome is unknown")
        except OSError:
            record("FAILED", 1, "", "spawn failed")
            return _refusal("operation could not be started")
        except UnicodeDecodeError:
            # Decoding can fail after the command ran; the outcome is unknown and
            # the claim stays UNKNOWN, so the lease is never executed again.
            record("UNKNOWN", None, "", "undecodable output")
            return _refusal("command output could not be decoded; outcome unknown")

        exit_code = int(result.returncode)
        stored_state = "SUCCEEDED" if exit_code == 0 else "FAILED"
        if not record(stored_state, exit_code, result.stdout, result.stderr):
            # The operation may have run. Report that uncertainty instead of a
            # traceback, and never re-execute: the claim stays CLAIMED.
            return _refusal("operation ran but its result could not be recorded; outcome unknown")
        return (
            exit_code,
            {
                "exit_code": exit_code,
                "stdout": _truncate(result.stdout),
                "stderr": _truncate(result.stderr),
                "lease_id": request.lease.lease_id,
            },
        )
    finally:
        if owns_store:
            claim_store.close()


def read_request(source: Any, *, limit: int = MAX_REQUEST_BYTES, timeout: float = REQUEST_READ_TIMEOUT) -> str:
    """Read at most *limit* request bytes, within *timeout* seconds.

    A pipe is read through a selector so a caller that never closes stdin or
    streams forever cannot hold the dispatcher open or grow its memory. Text
    sources without a file descriptor are read with the same byte bound.
    """
    try:
        descriptor = source.fileno()
    except (AttributeError, OSError):
        document = source.read(limit + 1)
        if len(document) > limit:
            raise ValueError("request is too large") from None
        return document

    if stat.S_ISREG(os.fstat(descriptor).st_mode):
        # A regular file cannot be registered with epoll; its size is fixed, so
        # one bounded read needs no deadline.
        document = source.read(limit + 1)
        if len(document) > limit:
            raise ValueError("request is too large") from None
        return document

    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    os.set_blocking(descriptor, False)
    with selectors.DefaultSelector() as selector:
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("request read timed out") from None
            if not selector.select(remaining):
                raise ValueError("request read timed out") from None
            try:
                chunk = os.read(descriptor, min(8192, limit + 1 - total))
            except BlockingIOError:
                continue
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError("request is too large") from None
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def main(
    argv: list[str] | None = None,
    *,
    stdin: Any = None,
    stdout: Any = None,
    runner: Runner = subprocess.run,
    clock: Callable[[], int] = time.time,
) -> int:
    """Read one request, dispatch it and print one JSON document.

    ``runner`` and ``clock`` are injectable so a test never runs ``pct`` and
    never depends on wall-clock time.
    """
    parser = argparse.ArgumentParser(prog="privilege-broker-dispatcher", description=__doc__)
    parser.add_argument("--policy", required=True, type=Path, dest="policy_path")
    parser.add_argument("--lease-public-key", required=True, type=Path, dest="lease_public_key_path")
    parser.add_argument("--claim-db", required=True, type=Path, dest="claim_db_path")
    parser.add_argument("--lxc-conf-dir", required=True, type=Path, dest="lxc_conf_dir")
    parser.add_argument("--command-timeout", type=int, default=180)
    arguments = parser.parse_args(argv)

    out = stdout if stdout is not None else sys.stdout
    source = stdin if stdin is not None else sys.stdin
    config = DispatchConfig(
        policy_path=arguments.policy_path,
        lease_public_key_path=arguments.lease_public_key_path,
        claim_db_path=arguments.claim_db_path,
        lxc_conf_dir=arguments.lxc_conf_dir,
        command_timeout=arguments.command_timeout,
    )
    try:
        request = parse_request(read_request(source))
        public_key = load_lease_public_key(config.lease_public_key_path)
    except ValueError as exc:
        exit_code, output = _refusal(str(exc))
        out.write(json.dumps(output) + "\n")
        out.flush()
        return exit_code
    exit_code, output = dispatch(request, config, public_key=public_key, now=int(clock()), runner=runner)
    out.write(json.dumps(output) + "\n")
    out.flush()
    return exit_code


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    sys.exit(main())
