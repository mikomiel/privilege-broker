"""Poll-and-dispatch worker for approved broker requests.

Polls the broker for requests whose input files exist in the state directory.
On approval: fetches the lease and the one-time SSH certificate, dispatches to
the typed dispatcher over SSH, and writes a result file. On denial, expiry or
cancellation: writes a terminal status. The target container may live on any
configured node; a node that does not host it answers ``not_on_this_node``
(exit 3) without claiming the lease, and only then is the next node tried.

Terminal result statuses written to ``results/{request_id}.json``::

    succeeded  dispatcher exited 0
    failed     dispatcher exited non-zero
    unknown    ssh timed out; the operation may or may not have run
    error      the dispatch could not be carried out at all
    denied | cancelled | expired   decided at the broker, never dispatched

A request past its deadline plus a grace period is expired locally, without
asking the broker, so a forgotten request cannot be polled forever. When the
lease or certificate call finds the broker unavailable (network failure,
timeout, HTTP 429/502/503/504) the request is kept and retried on the next
poll, bounded by that local expiry; any other refusal is final. The
certificate is issued once: if its response is lost after signing, the retry
gets HTTP 409 and the request ends as ``error`` -- a second certificate is
never issued for one approval, and an ambiguous dispatch is never repeated.

State directory layout::

    <state_dir>/
        input/{request_id}.json     written by the bridge
        results/{request_id}.json   written by this worker
        keys/{key_id}.key           ephemeral private key
        keys/{key_id}-cert.pub      SSH certificate

All configuration is explicit constructor input; the module reads no
environment and starts no loop at import.
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .client import BrokerClient, BrokerHTTPError, BrokerUnavailable

_LOG = logging.getLogger("privilege_broker.pve.worker")

#: The dispatcher's exit code when the container is not on the node reached.
NOT_ON_THIS_NODE_EXIT = 3
#: Truncation applied to captured dispatcher output in a result.
_OUTPUT_LIMIT = 4096
#: SSH connect timeout; the overall dispatch timeout is ``WorkerConfig.ssh_timeout``.
_CONNECT_TIMEOUT = 10

#: Broker statuses that end a request without any dispatch.
TERMINAL_BROKER_STATUSES: frozenset[str] = frozenset({"denied", "cancelled", "expired"})


class SshRunner(Protocol):
    """Runs one SSH invocation; injectable so tests never open a socket."""

    def __call__(
        self,
        argv: list[str],
        *,
        input: str,
        capture_output: bool,
        text: bool,
        timeout: float,
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class WorkerConfig:
    """Explicit worker configuration; no deployment defaults exist."""

    #: Persistent state root holding ``input/``, ``results/`` and ``keys/``.
    state_dir: Path
    #: SSH targets tried in order, e.g. ``("ops@node-a", "ops@node-b")``.
    targets: tuple[str, ...]
    #: SSH port on the targets.
    ssh_port: int
    #: Pinned known-hosts file for the targets.
    known_hosts_path: str
    #: Seconds between polls.
    poll_interval: float = 5.0
    #: Overall timeout of one SSH dispatch.
    ssh_timeout: float = 240.0
    #: Slack over the broker deadline before a request expires locally.
    expiry_grace: float = 60.0

    def __post_init__(self) -> None:
        if isinstance(self.state_dir, str):
            object.__setattr__(self, "state_dir", Path(self.state_dir))
        if isinstance(self.targets, list):
            object.__setattr__(self, "targets", tuple(self.targets))
        if not self.targets or not all(isinstance(t, str) and t.strip() for t in self.targets):
            raise ValueError("targets must be a non-empty sequence of non-empty strings")
        if type(self.ssh_port) is not int or not 1 <= self.ssh_port <= 65535:
            raise ValueError("ssh_port must be an integer in 1-65535")
        if not self.known_hosts_path:
            raise ValueError("known_hosts_path is required")
        if self.poll_interval <= 0 or self.ssh_timeout <= 0 or self.expiry_grace < 0:
            raise ValueError("poll_interval and ssh_timeout must be positive, expiry_grace non-negative")


def _dispatcher_outcome(stdout: str) -> dict[str, Any]:
    """Lift the typed dispatcher's own JSON result, when it produced one.

    The dispatcher prints a single JSON object. Anything else -- an sshd error,
    a truncated stream -- is not fatal here, because the exit code already
    classifies the run; the lifted fields are additional detail, not the verdict.
    """
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {f"dispatcher_{key}": parsed[key] for key in ("lease_id", "replayed", "error") if key in parsed}


def dispatch(
    client: BrokerClient,
    config: WorkerConfig,
    request_id: str,
    input_data: dict[str, Any],
    *,
    ssh_runner: SshRunner,
) -> dict[str, Any]:
    """Fetch lease and certificate, then dispatch to each configured target.

    ``BrokerUnavailable`` from the lease or certificate call propagates: it is
    raised before any SSH, so nothing ran and the caller keeps the request for
    the next poll.
    """
    keys_dir = config.state_dir / "keys"
    public_key = input_data["public_key"]
    key_id = input_data["key_id"]
    key_path = keys_dir / f"{key_id}.key"
    cert_path = keys_dir / f"{key_id}-cert.pub"

    lease_resp = client.request("GET", f"/v1/broker/requests/{request_id}/lease")
    if not isinstance(lease_resp, dict) or not isinstance(lease_resp.get("signature"), str):
        raise ValueError("broker lease response is malformed")
    lease = {key: value for key, value in lease_resp.items() if key != "signature"}
    signature = lease_resp["signature"]

    # The certificate request carries only the public key: the serial is the
    # broker's choice, never the caller's.
    cert_resp = client.request("POST", f"/v1/broker/requests/{request_id}/certificate", {"ssh_public_key": public_key})
    certificate = cert_resp.get("certificate") if isinstance(cert_resp, dict) else None
    if not isinstance(certificate, str) or not certificate:
        raise ValueError("broker did not issue a certificate")
    cert_path.write_text(certificate, encoding="ascii")
    cert_path.chmod(0o600)

    payload = json.dumps(
        {
            "action": input_data["action"],
            "ct_id": input_data["ct_id"],
            "lease": lease,
            "signature": signature,
        }
    )
    for target in config.targets:
        _LOG.info(
            "request %s: dispatching %s on CT %s via %s",
            request_id,
            input_data["action"],
            input_data["ct_id"],
            target,
        )
        argv = [
            "ssh",
            "-F",
            "/dev/null",
            "-i",
            str(key_path),
            "-o",
            f"CertificateFile={cert_path}",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            f"ConnectTimeout={_CONNECT_TIMEOUT}",
            "-o",
            f"UserKnownHostsFile={config.known_hosts_path}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-p",
            str(config.ssh_port),
            target,
        ]
        try:
            result = ssh_runner(argv, input=payload, capture_output=True, text=True, timeout=config.ssh_timeout)
        except subprocess.TimeoutExpired:
            # The dispatcher bounds its own work and records the lease as
            # UNKNOWN on its own timeout; the certificate is single-use and
            # the claim store refuses a second dispatch of the same lease, so a
            # transport timeout is reported as unknown, never retried.
            _LOG.warning("request %s: ssh to %s timed out after %ss", request_id, target, config.ssh_timeout)
            return {
                "status": "unknown",
                "node": target,
                "error": f"ssh dispatch exceeded {config.ssh_timeout}s; remote outcome unknown",
            }
        outcome = _dispatcher_outcome(result.stdout)
        _LOG.info("request %s: %s exited %s", request_id, target, result.returncode)
        # Exit 3 alone is not enough: the dispatcher passes pct's own exit code
        # through, and only its JSON marks the node as the wrong one.
        if result.returncode == NOT_ON_THIS_NODE_EXIT and outcome.get("dispatcher_error") == "not_on_this_node":
            continue
        return {
            # Classify from the dispatcher's exit code, not from "command attempted".
            "status": "succeeded" if result.returncode == 0 else "failed",
            "node": target,
            "exit_code": result.returncode,
            "stdout": result.stdout[:_OUTPUT_LIMIT],
            "stderr": result.stderr[:_OUTPUT_LIMIT],
            **outcome,
        }
    return {"status": "error", "error": "container not found on any configured node"}


def _finish(
    config: WorkerConfig,
    request_id: str,
    input_file: Path,
    key_id: object,
    result: dict[str, Any],
    log: logging.Logger,
) -> None:
    results_dir = config.state_dir / "results"
    results_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    (results_dir / f"{request_id}.json").write_text(json.dumps(result), encoding="utf-8")
    input_file.unlink(missing_ok=True)
    if isinstance(key_id, str):
        keys_dir = config.state_dir / "keys"
        (keys_dir / f"{key_id}.key").unlink(missing_ok=True)
        (keys_dir / f"{key_id}-cert.pub").unlink(missing_ok=True)
    log.info("request %s: result %s", request_id, result["status"])


def process_pending_once(
    client: BrokerClient,
    config: WorkerConfig,
    *,
    now: int | None = None,
    ssh_runner: SshRunner | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Process every pending input file once."""
    log = logger or _LOG
    runner: SshRunner = ssh_runner or subprocess.run
    now = int(time.time()) if now is None else now
    input_dir = config.state_dir / "input"
    results_dir = config.state_dir / "results"
    if not input_dir.is_dir():
        return
    for input_file in sorted(input_dir.iterdir()):
        if input_file.suffix != ".json":
            continue
        request_id = input_file.stem
        if (results_dir / f"{request_id}.json").exists():
            continue
        try:
            input_data = json.loads(input_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            log.warning("request %s: unreadable input file: %s", request_id, exc)
            continue
        if not isinstance(input_data, dict):
            log.warning("request %s: input file is not an object", request_id)
            continue
        key_id = input_data.get("key_id")
        expires_at = input_data.get("expires_at")
        if type(expires_at) is int and now > expires_at + config.expiry_grace:
            _finish(config, request_id, input_file, key_id, {"status": "expired"}, log)
            continue
        try:
            status_resp = client.request("GET", f"/v1/broker/requests/{request_id}")
        except BrokerUnavailable as exc:
            # Only classified availability failures are safe to retry.
            log.warning("request %s: broker status unavailable: %s", request_id, exc)
            continue
        except (RuntimeError, OSError) as exc:
            # Do not retry final refusals or unusable replies, and do not
            # copy the broker's response body into results or logs.
            error = (
                f"broker status HTTP {exc.status}"
                if isinstance(exc, BrokerHTTPError)
                else "broker status response unusable"
            )
            log.warning("request %s: %s", request_id, error)
            _finish(config, request_id, input_file, key_id, {"status": "error", "error": error}, log)
            continue
        status = status_resp.get("status") if isinstance(status_resp, dict) else None
        if not isinstance(status, str):
            log.warning("request %s: broker status missing", request_id)
            continue
        if status == "approved":
            try:
                result = dispatch(client, config, request_id, input_data, ssh_runner=runner)
            except BrokerUnavailable as exc:
                # Raised only by the lease and certificate calls, before any
                # SSH: nothing ran, so the input and key stay for the next poll.
                log.warning("request %s: broker unavailable before dispatch, will retry: %s", request_id, exc)
                continue
            except Exception as exc:
                # Fail closed: a consumed certificate (HTTP 409 "already
                # fetched") ends the request as an error; no replacement
                # authority is minted and no operation is repeated.
                log.warning("request %s: dispatch failed: %s", request_id, exc)
                result = {"status": "error", "error": str(exc)}
            _finish(config, request_id, input_file, key_id, result, log)
        elif status in TERMINAL_BROKER_STATUSES:
            _finish(config, request_id, input_file, key_id, {"status": status}, log)


def run(
    client: BrokerClient,
    config: WorkerConfig,
    *,
    ssh_runner: SshRunner | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Poll forever. Importing the module never starts this."""
    log = logger or _LOG
    for name in ("input", "results", "keys"):
        (config.state_dir / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    log.info("polling every %ss; targets %s", config.poll_interval, ", ".join(config.targets))
    while True:
        process_pending_once(client, config, ssh_runner=ssh_runner, logger=log)
        time.sleep(config.poll_interval)
