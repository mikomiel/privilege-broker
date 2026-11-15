# Architecture and extraction status

The intended flow is authenticated agent → approval broker → operator passkey
→ bounded authorization → trusted executor → observable operation outcome.
Notification delivery is separate and never an authorization decision.

## Implemented source boundary

- `privilege_broker.pve.common`: versioned target policy and canonical wire helpers.
- `privilege_broker.pve.authorization`: immutable requests, proxy identity extraction, signed leases and restricted certificate argv.
- `privilege_broker.pve.service`: SQLite approval state, real WebAuthn registration/authentication, browser UI and one-time certificate fetch.
- `privilege_broker.notifications`: server-owned Discord delivery with credential-safe errors and inert agent text.
- `privilege_broker.pve.client`: mTLS broker HTTP client; the endpoint and trust material are explicit constructor input and transient failures classify separately from final refusals.
- `privilege_broker.pve.bridge`: agent-side request creation with an ephemeral Ed25519 key, strict response validation and pending-input publication.
- `privilege_broker.pve.worker`: poll-and-dispatch worker that fetches the lease and the one-time certificate, tries the configured nodes in order and writes terminal result files.
- `privilege_broker.pve.dispatcher`: target-side typed dispatcher that re-verifies the lease and target policy, atomically claims it in a durable SQLite store and runs one fixed argv or the policy-bounded snapshot prune.

The approval service requires explicitly supplied store, signer and target
policy. Its environment factory requires private deployment configuration;
module import does not start a server or load private state. A missing
identity adapter rejects agent calls. The TLS frontend, credentials, origin
and service isolation are owned by deployment, not by request bodies.

Browser approval signs a short-lived PVE lease but returns only approval
status. The bound agent can fetch that lease and a restricted SSH certificate.
The signer runs only local `ssh-keygen`, not an SSH connection or PVE command.
The bridge, client, worker and dispatcher exist. The generic execution-outcome
API does not (OpenSpec task 5.1). An `approved` request is not an executed
operation.

The bridge, client and worker take explicit configuration only: they read no
environment variable and carry no built-in address, path or identity, so a
missing value fails closed. The worker keeps the broker wire contract
unchanged: the lease is fetched once, the certificate is fetched once and the
dispatcher receives `{"action", "ct_id", "lease", "signature"}` on stdin over
fixed non-interactive SSH options. Terminal results are `succeeded`, `failed`,
`unknown` (transport timeout or capture abort; never retried), `error`,
`denied`, `cancelled` and `expired`. Worker-generated error summaries use known
phase/status classifications, not raw upstream exception details. The default
POSIX SSH adapter bounds capture while reading, and stored output excerpts
and lifted dispatcher strings have separate limits. Executor output is still
operational data and must not contain credentials. A consumed certificate is
never re-requested.

The client rejects redirects instead of carrying its mTLS context outside the
configured endpoint. The bridge and worker share private atomic publication
for pending inputs and terminal results; failed writes clean up their temporary
files. Result publication precedes input removal so the reader handoff cannot
look like a missing request. The worker retries classified broker-availability
failures, including interrupted response framing, but makes final status
refusals terminal. Deployers must run one poller per state directory.
[Configuration](configuration.md#agent-bridge-and-worker) owns the detailed
transport, publication and cleanup limits.

The authenticated agent reads its request through
`GET /v1/broker/requests/{request_id}`; only the original mTLS identity and
observed source address may read it, and a cross-identity read is refused
without disclosing any request field. The response carries the approval
lifecycle as `status` (`pending`, `approved`, `denied`, `expired` or
`cancelled`; `approved` means authorized) plus a separate `execution_state`
from a closed vocabulary (`not_executed`, `executing`, `succeeded`, `failed`,
`uncertain`). The broker reports only `not_executed`: approval, lease fetch and
certificate issuance are authorization events, never execution evidence, and
no agent-supplied execution evidence is accepted. An uncertain outcome is
never reported as success.

## Supported interfaces

The installed distribution is `privilege-broker` (import `privilege_broker`),
Python 3.11 or newer. These are the supported surfaces at this stage:

| Interface | Entry point | Purpose |
| --- | --- | --- |
| Approval service | `privilege_broker.pve.service.create_broker_app(...)` | FastAPI app over an explicit `BrokerStore`, `LeaseSigner`, identity extractor, policy and optional certificate signer |
| Approval HTTP API | `POST /v1/broker/requests`; `GET /v1/broker/requests/{request_id}`; `GET /v1/broker/requests/{request_id}/approval` (browser page); `POST /v1/broker/requests/{request_id}/approval` (assertion); `GET /v1/broker/requests/{request_id}/approval/options`; `POST /v1/broker/requests/{request_id}/denial`; `POST /v1/broker/requests/{request_id}/cancel`; `GET /v1/broker/requests/{request_id}/lease`; `POST /v1/broker/requests/{request_id}/certificate`; `GET /v1/broker/requests/{request_id}/status`; `POST /v1/broker/enrollments`; `GET /v1/broker/enrollments/{enrollment_id}/options`; `POST /v1/broker/enrollments/{enrollment_id}/complete`; `GET /v1/broker/enroll/{enrollment_id}`; `GET /v1/broker/lease-public-key`; `GET /health` | Typed request, passkey approval and enrollment, one-time lease and certificate, lifecycle status. The agent reads `GET /v1/broker/requests/{request_id}`; the browser polls `/status`. `create_broker_app_from_env` is the deployment factory described in [configuration](configuration.md) |
| Agent bridge | `privilege_broker.pve.bridge.ApprovalBridge` with `BridgeConfig` | Create a typed request, publish pending input atomically, read the worker status |
| Broker client | `privilege_broker.pve.client.BrokerClient` with `BrokerClientConfig` | mTLS HTTPS calls with explicit trust material; redirects refused |
| Execution worker | `privilege_broker.pve.worker.WorkerConfig`, `process_pending_once`, `run` | Poll approvals, fetch the lease and certificate, dispatch, publish the result |
| Target dispatcher | `python -m privilege_broker.pve.dispatcher` | Verify the lease, claim it durably, run one fixed argv or the policy-bounded prune |
| Policy and lease helpers | `privilege_broker.pve.common`, `privilege_broker.pve.authorization` | Version 2 policy, canonical payloads, lease signing and verification, certificate argv |
| Notifications | `privilege_broker.notifications` | Server-owned Discord delivery with credential-safe errors |

Install and inspect the command from a clean environment:

```sh
uv build
uv venv /tmp/privilege-broker-venv
uv pip install --python /tmp/privilege-broker-venv/bin/python dist/*.whl
cd /tmp
/tmp/privilege-broker-venv/bin/python -I -m privilege_broker.pve.dispatcher --help
```

The second interpreter invocation runs outside the checkout with `-I`, so the
source tree cannot shadow the installed wheel.

The dispatcher CLI takes `--policy`, `--lease-public-key`, `--claim-db` and
`--lxc-conf-dir`, with optional `--sudo-path`, `--pct-path` and
`--command-timeout`. Every other interface is a library call whose configuration
is explicit constructor input.

### Known limits

- Pre-release: the generic execution-outcome API (task 5.1's follow-on) is not
  designed yet, and no consumer has been cut over.
- At-most-once dispatch is bound to one host and one claim database; a
  migration-capable target needs broker-side executor binding first.
- The default dispatcher capture adapter requires POSIX pipes, and `pct`,
  `sudo`, TLS, trust roots and the state directory are deployer-owned.
- WebAuthn coverage uses software authenticators; no browser or hardware-passkey
  acceptance is claimed.
- No package publication, container image or deployment is produced by the
  source repository alone. A version tag and its GitHub Release are, and they
  assert nothing about deployment.

## Compatibility and extraction adaptations

The wire versions remain `pve-operate-v1`, `pve-approval-v1` and
`pve-execution-v1`. Existing approval tables and PVE canonical payloads are
retained. There is no database migration or consumer source-owner cutover.
See [configuration](configuration.md) for the exact service requirements.

Standalone adaptations remove the implicit shared temporary database,
ephemeral default signer, import-time autostart and private certificate-source
default. The factory closes its store through ASGI lifespan. FastAPI owns
notification tasks instead of untracked daemon threads. The sender uses
standard-library HTTP, English labels and UTC expiry, not a private HTTP
helper or deployment-specific locale.

The HTTP boundary rejects non-integer target IDs and validates Ed25519 SSH
keys with the same validator used for certificate issuance. A valid RSA key
cannot enter an approval flow that could never issue its certificate. These
refusals do not change valid PVE canonical requests. WebAuthn library errors
become refusals, not successful approval or raw provider exceptions.

## Verification and limits

Synthetic tests cover source/identity isolation, enrollment bootstrap,
challenge and request expiry, altered keys, denial, scoped leases, one-time
and concurrent certificate fetching, database permissions and audit content.
Local certificate tests use real generated keys and `ssh-keygen`.

Synthetic end-to-end tests run the real approval service, SQLite store, lease
signer, ssh-keygen CA, bridge and worker, and invoke the dispatcher as a fresh
process; only the TLS transport, SSH and `pct` are substituted. They cover an
allowed dispatch, denial, expiry, a tampered lease, concurrent workers and an
uncertain timeout, and assert that no path dispatches twice.

Software-authenticator tests exercise actual WebAuthn CBOR, P-256 signatures,
RP/origin/challenge checks, user-presence and user-verification flags, counter
rollback and wrong signing keys. They do not prove physical user presence,
browser compatibility, production TLS, notification delivery or a PVE effect.
Rate-limit storage and notification tasks are process-local; notification
delivery is not durable. Product acceptance remains incomplete.

## Remaining product stages

The dispatcher is the authoritative target-side boundary. It re-verifies the
lease signature, audience, profile, TTL, execution digest and scope, then
re-reads the same version 2 policy the broker used. Only then does it check
container locality, so a wrong node answers `not_on_this_node` (exit 3) before
touching the claim store and the worker may present the same lease to the next
node. It then claims the lease with an atomic `INSERT OR IGNORE` before running
one fixed argv through `sudo pct`, never a shell. A repeat presentation returns
the stored result with `replayed`; a claim left `CLAIMED` by a dead process
becomes `UNKNOWN` and is never re-executed. `ct.snapshot_prune` deletes only broker-owned snapshots older than the policy
retention and reports what it deleted, kept, failed or deferred.

The active [OpenSpec change](../openspec/changes/extract-pve-foundation/proposal.md)
owns the outcome interfaces and
end-to-end acceptance. Consumer pinning, deployment and live
PVE acceptance are separate gates. No current consumer has switched.

PVE is the only initial provider. There is no dynamic plugin system, arbitrary
shell mode or approval-only advisory mode. The eventual lifecycle must keep
notification, authorization, dispatch and execution outcome distinct.

## Provenance

The extraction uses the owned ai-agents snapshot
`75b8271722c3b5ec6262708fcd227cd6835fcef4`:

| Original file | Product boundary |
| --- | --- |
| `MCPs/servers/_pve_common.py` | Policy, canonicalization and the mTLS broker client; no transport server |
| `MCPs/servers/pve_ssh_broker.py` | Authorization and certificate argv |
| `MCPs/servers/pve_ssh_broker_service.py` | Approval store, service, passkey UI and certificate signer |
| `MCPs/servers/pve_broker_mcp.py` | Agent bridge: request validation, ephemeral key, input publication |
| `MCPs/servers/pve_broker_worker.py` | Poll-and-dispatch worker: lease/certificate fetch, node failover, result files |
| `MCPs/servers/_discord_notify.py` | Server-owned notifications, adapted to standalone HTTP and UTC |
| `MCPs/tests/test_pve_ssh_broker*.py` | Ported synthetic contract tests, supplemented by real local crypto tests |
| `MCPs/tests/test_pve_broker_mcp.py`, `MCPs/tests/test_pve_broker_worker.py` | Ported synthetic bridge and worker tests |

Private source history, deployment configuration, trust roots, credentials
and runbooks are not copied. Existing consumers retain their current source
until separately authorized parity, pinning and cutover gates hold.
