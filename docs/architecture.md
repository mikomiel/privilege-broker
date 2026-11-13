# Architecture and extraction status

The intended flow is authenticated agent → approval broker → operator passkey
→ bounded authorization → trusted executor → observable operation outcome.
Notification delivery is separate and never an authorization decision.

## Implemented source boundary

- `privilege_broker.pve.common`: versioned target policy and canonical wire helpers.
- `privilege_broker.pve.authorization`: immutable requests, proxy identity extraction, signed leases and restricted certificate argv.
- `privilege_broker.pve.service`: SQLite approval state, real WebAuthn registration/authentication, browser UI and one-time certificate fetch.
- `privilege_broker.notifications`: server-owned Discord delivery with credential-safe errors and inert agent text.

The approval service requires explicitly supplied store, signer and target
policy. Its environment factory requires private deployment configuration;
module import does not start a server or load private state. A missing
identity adapter rejects agent calls. The TLS frontend, credentials, origin
and service isolation are owned by deployment, not by request bodies.

Browser approval signs a short-lived PVE lease but returns only approval
status. The bound agent can fetch that lease and a restricted SSH certificate.
The signer runs only local `ssh-keygen`, not an SSH connection or PVE command.
No execution worker, target dispatcher or outcome ingestion exists here yet.
An `approved` request is not an executed operation.

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

Software-authenticator tests exercise actual WebAuthn CBOR, P-256 signatures,
RP/origin/challenge checks, user-presence and user-verification flags, counter
rollback and wrong signing keys. They do not prove physical user presence,
browser compatibility, production TLS, notification delivery or a PVE effect.
Rate-limit storage and notification tasks are process-local; notification
delivery is not durable. Product acceptance remains incomplete.

## Remaining product stages

The active [OpenSpec change](../openspec/changes/extract-pve-foundation/proposal.md)
owns authenticated agent lifecycle/outcome interfaces, the bridge, worker,
dispatcher and end-to-end acceptance. Consumer pinning, deployment and live
PVE acceptance are separate gates. No current consumer has switched.

PVE is the only initial provider. There is no dynamic plugin system, arbitrary
shell mode or approval-only advisory mode. The eventual lifecycle must keep
notification, authorization, dispatch and execution outcome distinct.

## Provenance

The extraction uses the owned ai-agents snapshot
`75b8271722c3b5ec6262708fcd227cd6835fcef4`:

| Original file | Product boundary |
| --- | --- |
| `MCPs/servers/_pve_common.py` | Policy and canonicalization only; no transport client |
| `MCPs/servers/pve_ssh_broker.py` | Authorization and certificate argv |
| `MCPs/servers/pve_ssh_broker_service.py` | Approval store, service, passkey UI and certificate signer |
| `MCPs/servers/_discord_notify.py` | Server-owned notifications, adapted to standalone HTTP and UTC |
| `MCPs/tests/test_pve_ssh_broker*.py` | Ported synthetic contract tests, supplemented by real local crypto tests |

Private source history, deployment configuration, trust roots, credentials
and runbooks are not copied. Existing consumers retain their current source
until separately authorized parity, pinning and cutover gates hold.
