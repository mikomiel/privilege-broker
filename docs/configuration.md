# PVE configuration

This pre-release stage supplies authorization, approval, certificate signing,
the agent-side bridge and worker, and the target-side dispatcher with its
durable claim store. Policy-bounded snapshot pruning and the generic
execution-outcome API are not included yet. Deployment, credentials, TLS and
consumer cutover remain separate operator decisions. No example grants access
to a real target.

## Target policy

Load a deployer-owned JSON policy with `load_policy(Path(...))`. The parser
requires version 2 and exactly the keys in [the synthetic example](../examples/pve-policy.json).
Grants are per action and container ID. Unknown actions, boolean IDs, missing
files and malformed policy fail. An absent grant denies the operation.

The closed operation set is container start, stop, reboot, shutdown, snapshot
and broker-snapshot pruning. Policy can narrow this set, not add actions. The
future dispatcher must enforce retention against broker-owned snapshots.

## Approval service

Install with Python 3.11+ and uv. After providing the explicit configuration
below, the factory entrypoint is:

```sh
uv sync --frozen
uv run uvicorn privilege_broker.pve.service:create_broker_app_from_env \
  --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

This command is a deployment reference, not authorization to start a service.
Use one worker and one store per process. Importing the module does not start
an app, open a database or load private keys. The legacy autostart environment
flag is not an entrypoint. A normal ASGI lifespan closes the factory-owned
SQLite connection at shutdown.

| Environment variable | Requirement |
| --- | --- |
| `PVE_BROKER_DATABASE` | Required private SQLite state path; protect the database, WAL and shared-memory files together |
| `PVE_BROKER_LEASE_KEY_PATH` | Required persistent Ed25519 PKCS#8 PEM private-key file, readable only by its owner |
| `PVE_BROKER_POLICY_FILE` | Required version-2 JSON policy path |
| `PVE_BROKER_RP_ID` | Required WebAuthn relying-party hostname, without a scheme or path |
| `PVE_BROKER_ORIGIN` | Required exact HTTPS browser origin for that relying party |
| `PVE_BROKER_ENROLLMENT_KEY` | Required bootstrap secret supplied by the deployment's credential mechanism; never print it or put it in command arguments |
| `PVE_BROKER_ENROLLMENT_ENABLED` | Defaults to disabled; only the value `true` enables initial bootstrap enrollment |
| `PVE_BROKER_MTLS_CLIENTS_JSON` | Explicit identity-to-observed-IP map; unset rejects all agent calls. A value may be one address or a non-empty list, for example `{"agent-demo":"192.0.2.10"}` |
| `PVE_BROKER_CA_KEY_PATH` | Optional private, unencrypted OpenSSH CA key for local `ssh-keygen`; absent returns `not_ready` for certificate fetch |
| `PVE_BROKER_CERT_SOURCE` | Required when CA signing is configured: one explicit restricted CIDR (lists are not supported) |
| `PVE_BROKER_NOTIFY_WEBHOOK_FILE` | Optional private file containing the server-owned Discord webhook URL |

The factory does not create keys, install a TLS frontend, populate a target
policy or provision credentials. Protect secret files and process access with
the deployment's service identity. Do not store secrets in source or an
unprotected environment file.

### Frontend trust boundary

The service does not terminate agent mTLS. A separately configured local TLS
proxy must verify client certificates, strip caller-supplied metadata and set
`X-Pve-Broker-Mtls-Identity` and `X-Pve-Broker-Mtls-Source-Ip` from verified
transport facts. The extractor accepts these headers only from a loopback
peer and only when identity and observed address match the configured map.

Keep the backend inaccessible to agents and untrusted local processes. Loopback
alone does not authenticate a local caller. Disable Uvicorn proxy-header
rewriting as shown above so the peer remains the actual local frontend, not an
address from `X-Forwarded-For`. Deployers also own TLS, browser origin, request
size limits and isolation. The Python app cannot establish these host facts.

### Enrollment and approval

The initial enrollment endpoint requires the configured bootstrap header and
an explicitly enabled enrollment mode. Registration and authentication verify
the stored challenge, RP, origin, user presence and user verification with the
WebAuthn library. Bootstrap consumption and passkey counters persist in SQLite;
restarts or key rotation do not create another initial-enrollment entitlement.
Disable enrollment after provisioning. General passkey administration and
recovery are not implemented.

Agent requests use `POST /v1/broker/requests`; identity is not taken from its
body. Browser approval returns only `{"status":"approved"}`, never a lease
or certificate. The same authenticated agent can fetch its lease and make one
certificate fetch. Altered keys, other identities, expired requests and replay
fail. Only valid Ed25519 SSH request keys are accepted; this is separate from
the operator's WebAuthn key algorithm.

The browser status endpoint reports request authorization, not execution.
Recipients of an opaque approval URL can deny a pending request without a
passkey; denial grants no authority. Protect these URLs against unwanted
cancellation and metadata disclosure. There is no authenticated generic
execution-outcome API yet.

## Agent bridge and worker

The bridge and worker are libraries with explicit configuration only. They read
no environment variable and carry no built-in address, path or identity;
deployment adapters map their own environment onto these required arguments,
and a missing value fails closed.

```python
from pathlib import Path
from privilege_broker.pve.bridge import ApprovalBridge, BridgeConfig
from privilege_broker.pve.client import BrokerClient, BrokerClientConfig
from privilege_broker.pve.worker import WorkerConfig, process_pending_once

client = BrokerClient(
    BrokerClientConfig(
        broker_url="https://broker.example.test",  # required https:// URL
        cert_path="/etc/example/agent-cert.pem",  # required mTLS client certificate
        key_path="/etc/example/agent-key.pem",  # required mTLS client key
        ca_path="/etc/example/broker-ca.pem",  # optional trust root
    )
)
bridge = ApprovalBridge(
    BridgeConfig(
        state_dir=Path("/var/lib/example-broker"),  # holds input/ results/ keys/
        public_url="https://broker.example.test",  # approval-page base URL
        requester="example-agent",  # 1-100 characters
    )
)
worker_config = WorkerConfig(
    state_dir=Path("/var/lib/example-broker"),
    targets=("ops@node-a", "ops@node-b"),  # tried in order
    ssh_port=8922,
    known_hosts_path="/etc/example/known_hosts",  # pinned host keys
    poll_interval=5,
    ssh_timeout=240,
    expiry_grace=60,
)
```

The client connects directly to the configured HTTPS endpoint with environment
proxies disabled. It rejects every redirect, including same-origin redirects,
rather than forwarding the mTLS context or accepting a downgrade to HTTP.
HTTP error bodies are read only up to the detail limit and closed, including
when a body read fails; producing an error message does not drain the response.
Interrupted response framing is a transient availability failure. For fixed
lengths, the client checks `Content-Length` against the body actually read;
chunked framing remains the transport's responsibility. Invalid lengths and
declared bodies above the size bound are final unusable responses. If an HTTP
error status is already known, that status keeps its retry/final classification
even when the detail stream is truncated. Other HTTP protocol errors and JSON
decoder failures, including integer-conversion limits, become final unusable
responses rather than unhandled exceptions that stop the worker.

`bridge.request_mutation(action, ct_id, reason, client)` validates the typed
action, target and reason. It creates an ephemeral Ed25519 key exclusively
with mode `0600`, creates the broker request and writes a private temporary
input file. Only a complete, flushed JSON file is renamed to
`input/{request_id}.json`, so the worker cannot read a partial publication.
The method returns the `approval_url`; `bridge.read_status` returns the worker
result, `pending` or `unknown`.

If creation or publication fails, cleanup removes the key and temporary input
created by that attempt. An existing key is neither overwritten nor removed.
Cleanup covers failures that return through Python; process termination or a
filesystem that refuses deletion can leave files. No orphan-recovery sweeper
is implemented. Deployers own state-directory protection and recovery.

`known_hosts_path` is the exclusive SSH host-key trust file; the fixed SSH
options disable global known-host files as well as SSH configuration files.

Run exactly one poller per state directory, including calls to
`process_pending_once`. No singleton lock or multi-poller coordination is
implemented. The worker polls `input/` once per
`process_pending_once(client, worker_config)` call (or forever via `run`).
A request past its deadline plus `expiry_grace` is
expired locally without asking the broker, which bounds all retries. Transient
broker failures (network, timeout, HTTP 429/502/503/504) before dispatch keep
the request for the next poll. Final status-poll refusals, including HTTP
401/403/404, finish as `error` and remove the pending input and key rather than
polling until expiry. Unusable status replies that raise an error are also
terminal. HTTP 409 after a lost certificate reply ends the request as `error`
and never requests a second certificate. Dispatch uses fixed non-interactive SSH options
(`BatchMode`, `IdentitiesOnly`, no TTY, pinned known hosts, configured port) and
sends `{"action", "ct_id", "lease", "signature"}` on stdin, preserving the
dispatcher wire contract. A node that does not host the target answers exit 3
with `not_on_this_node` and the next configured node is tried with the same
certificate. A transport timeout, capture-limit abort or capture I/O failure is
`unknown`: the remote operation may have run, so no failover or redispatch is
attempted. Stopping the local SSH process does not prove remote cancellation.
Results in `results/{request_id}.json` are
`succeeded`, `failed`, `unknown`, `error`,
`denied`, `cancelled` or `expired`. Worker-generated diagnostics use fixed
phase/status summaries, not arbitrary exception text or upstream HTTP error
details, including transient status, lease and certificate failures. A final
HTTP refusal is reported as `broker status HTTP <code>` or
`broker dispatch HTTP <code>`; other dispatch exceptions become
`dispatch failed`. These summaries do not contain key or certificate material.
Captured executor output remains operational data, not a general secret
scrubber: the trusted executor must not emit credentials.

The default SSH adapter requires POSIX nonblocking pipes and retains at most
64 KiB combined stdout/stderr bytes. It reads at most one additional byte to
detect overflow, multiplexes stdin and both output streams, and applies
`ssh_timeout` to I/O and the wait for exit. Timeout, overflow and capture faults
terminate the owned local process group and reap its leader before returning
an unknown outcome. This is bounded capture and cleanup, not an overall heap
limit or a sandbox against deliberately escaping subprocesses.

Stored stdout/stderr excerpts and lifted `dispatcher_lease_id` and
`dispatcher_error` strings are limited to 4096 characters each; they are
excerpts, not new authorization evidence. Only string lease/error fields and
a boolean `dispatcher_replayed` are lifted from dispatcher JSON. Custom
`ssh_runner` implementations retain the existing callable shape but own the
same bounds and ambiguity contract; after starting SSH they must report
ambiguous aborts with `subprocess.TimeoutExpired` or the worker's
`SshCaptureError`, never retry internally.

Results use the same private atomic publication as pending inputs and become
visible before the worker removes the input and key. Readers
therefore see a pending request or complete terminal JSON during publication,
not a partially written result. A failed result write leaves input and keys
intact and removes its temporary file; it does not publish partial JSON.
The target dispatcher and its claim store are included. Policy-bounded snapshot
pruning remains OpenSpec task 4.3 and the generic outcome API task 5.1.

## Target dispatcher

The target-side dispatcher runs on the PVE node and is reached only through the
restricted SSH certificate. It takes every path explicitly; there is no built-in
deployment path and no environment read:

```python
from pathlib import Path
from privilege_broker.pve.dispatcher import DispatchConfig, dispatch, parse_request

config = DispatchConfig(
    policy_path=Path("/etc/example-dispatcher/policy.json"),  # same version 2 policy as the broker
    lease_public_key_path=Path("/etc/ssh/example-lease.pub"),  # Ed25519 lease signer key
    claim_db_path=Path("/var/lib/example-dispatcher/claims.sqlite3"),  # deployer-protected
    lxc_conf_dir=Path("/etc/pve/lxc"),  # lists only this node's containers
    command_timeout=180,  # keep the worker ssh_timeout above this
)
request = parse_request(stdin_document)
exit_code, output = dispatch(request, config, public_key=key, now=int(time.time()))
```

As a command, `python -m privilege_broker.pve.dispatcher` requires `--policy`,
`--lease-public-key`, `--claim-db` and `--lxc-conf-dir`, and reads one request
from stdin. That read is bounded to 64 KiB and 10 seconds, so a caller cannot
stream input, withhold EOF or grow the process before authorization runs. It prints one JSON document and exits with the operation's exit code,
`1` for a refusal or `3` for `not_on_this_node`.

The dispatcher enforces, in order: request shape, lease structure, audience,
profile, `max_dispatches == 1`, signature, the current target policy, the lease
TTL, the execution digest rebuilt from the actual action and container, action
and target scope, and container locality. Only then does it claim the lease and
run one fixed argv through `sudo pct` with `shell=False`. No caller input reaches
the command line except the validated positive container ID and, for a snapshot,
a name derived from the lease UUID.

The claim store is a SQLite WAL database with its parent at mode `0700` and the
file at `0600` where the filesystem permits. That mode is applied when the
dispatcher creates the directory: an existing parent keeps whatever mode it
already has, and the deployer must verify it. It is created by the dispatcher
identity; never open it with `sudo` or as root. A terminal claim is replayed from
storage, a claim left `CLAIMED` by a dead process becomes `UNKNOWN`, and a stored
claim whose action or target differs from the presented request is refused as
`UNKNOWN`. Truncated output is stored at 4096 bytes per stream.

At-most-once dispatch is bound to one host: run exactly one eligible executor
per target for the lease lifetime, and never place the SQLite database on a
network filesystem. A target that can move to another dispatcher inside that
lifetime is out of scope until broker-side executor binding exists.
`ct.snapshot_prune` is refused before any claim until OpenSpec task 4.3 lands, so
a broker-approved prune fails closed rather than running unpreserved logic.

## Certificate source restriction

The library and service require an explicit source restriction:

```python
from privilege_broker.pve.authorization import CertificateCommandBuilder, CertificatePolicy

policy = CertificatePolicy(source="198.51.100.88/32")
builder = CertificateCommandBuilder(policy)
```

The address is documentation data, not a deployable default. Empty,
unrestricted or invalid networks fail. The principal, forced dispatcher,
short validity and disabled forwarding remain fixed in the PVE adapter.
The builder only returns argv; the configured service signer invokes local
`ssh-keygen` with that argv and a timeout. It does not connect to PVE.

A certificate is safe only with the trusted typed dispatcher and lease
verification on the target. The extracted dispatcher performs that verification
and enforces the same policy before it claims the lease; snapshot pruning is
still OpenSpec task 4.3. Do not treat certificate issuance as an operation
outcome, and never enable a general shell as a substitute for the dispatcher.

## Operator notifications

The destination comes only from `PVE_BROKER_NOTIFY_WEBHOOK_FILE`, never a
request. An unset, empty or unreadable file disables delivery; it is not a
successful send. Operators must verify delivery configuration separately.
The URL is a credential, so only its file path belongs in configuration.

The sender escapes agent-controlled text, disables mentions and link embeds,
uses English labels and explicit UTC expiry, and applies a transport timeout.
Audit records distinguish successful delivery from failure without storing
the webhook URL or raw provider error. Neither outcome approves the request.

FastAPI owns after-response delivery tasks. This is not a durable notification
queue: a crash can lose delivery, and an HTTP response is not evidence that a
message reached an operator. Approval, notification and execution remain
separate states. No Discord or PVE request is made by the test suite.
