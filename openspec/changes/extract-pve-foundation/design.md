# Design

## Context

See [proposal.md](proposal.md) for motivation and scope. The existing PVE
flow has distinct processes: an agent-facing bridge, an approval service,
a worker and a typed dispatcher on the execution target. The approval
service stores passkeys, challenges, requests and audit events in SQLite.
The dispatcher has a separate durable replay-claim store. Those stores own
different trust boundaries; merging them would change failure semantics.

## Goals / Non-Goals

The extraction preserves existing signatures, canonicalization versions,
policy documents, certificate restrictions and replay behaviour. The broader
service exposes a common operation lifecycle without replacing the working
PVE protocol during extraction.

No universal executor, dynamic plugin loading, message bus, external policy
engine, new database or additional provider is introduced. A second provider
needs a concrete operation and its own reviewed enforcement boundary.

## Decisions

### Separate product implementation from deployment facts

The product authors `privilege_broker/` and product tests. Explicit
configuration supplies source networks, authenticated identities, trust
roots, policy files and endpoints. There is no built-in private network or
permissive fallback. Consumer-owned roles continue to provision those facts.

A full history split was rejected: it could disclose old private values and
would couple public history to unrelated deployment changes. Use a bounded
source snapshot, record provenance and scan every new public commit.

### Preserve PVE first, then normalize the agent contract

The first source PR extracts PVE policy parsing, canonical requests, leases,
identity extraction and certificate argument construction into
`privilege_broker/pve/`, with synthetic versions of the existing tests.
It is a library foundation, not a runnable service or a security redesign.

Later PRs move the approval service and notifier, then transport, bridge,
worker and dispatcher with their tests. Keep the PVE protocol versioned and
unchanged. A common agent-facing operation view distinguishes request,
authorization and execution states. Do not relabel an approved request as
completed or promise exactly-once external effects.

A simultaneous extraction and generic-protocol rewrite was rejected because
it would make a parity failure difficult to attribute. Existing PVE constants
remain in the PVE adapter; they do not become claims about every future
provider.

### Retain the independent approval and execution boundaries

The approval service verifies the passkey and issues a signed, bounded lease.
The SSH certificate binds its ephemeral key to a fixed typed dispatcher.
The executor validates the lease, current target policy and immutable
execution digest and claims it atomically before invoking fixed argv.
An agent does not receive the signer, CA key or a general executor identity.

Keep request expiry and certificate-consumption rules. A transient broker
failure before dispatch can be retried within the existing deadline. A lost
certificate reply or ambiguous dispatch is terminal or uncertain, not a
reason to mint another authorization. Existing audit and claim records must
explain the outcome without repeating the mutation.

### Keep notifications server-owned and outcome-neutral

Initially retain the existing Discord sender and escaping behaviour. The
broker controls the destination through deployer configuration; request
input cannot select it. Delivery failure records a safe audit event while
request creation remains successful. No webhook reply, notification click
or agent-to-agent chat message authorizes an operation.

Use the authenticated status interface as the first agent feedback path.
Proactive callbacks or harness-specific wakeups are not required for parity;
adding them later must authenticate the recipient and keep delivery distinct
from authorization. Do not introduce a second event store now.

### Stage GitHub governance without trusting PR code

The bootstrap installs read-only CI and publication scans. Native branch
protection requires strict current-base checks and an independent approval.
No write-token workflow or automerger is included in the bootstrap.

A later human-reviewed governance PR may install the existing trusted
metadata-only review-status and controlled-automerge pattern. It must run
policy code from the default branch, never PR-head code with a write token.
Only root README/CHANGELOG, direct `docs/*.md` and named OpenSpec documents
are ordinary. Broker code and every unknown path remain human-merge-only.
The author never merges manually or replaces missing App review.

## Risks / Trade-offs

- Extraction changes imports and configuration, which can break a consumer.
  Preserve wire formats, run synthetic parity and keep the old consumer pin
  until an authorized representative acceptance run succeeds.
- The public tree can accidentally expose deployment facts through tests or
  comments. Scan history, blobs and messages before the first and every later
  push, using local private-name rules as well as public class-based rules.
- One-shot authorization can leave a failed or uncertain operation after a
  lost reply. Accept that availability cost rather than duplicate a mutation.
- A compromised approval service can authorize operations within the
  executor's configured grants. Retain narrow grants and separate key
  ownership; source extraction does not justify wider access.
- Bootstrap-native review protection does not install the trusted App-status
  workflow. Keep merges human-owned until that automation is reviewed and
  installed. Missing App coverage is an external gate.

## Migration Plan

1. Publish source scaffolding and this plan under the approved bootstrap.
2. Protect main and verify the exact required checks and review requirement.
3. Extract portable PVE authorization in a human-merge source PR.
4. Extract approval service, notifications and execution components in
   bounded PRs; verify all PVE acceptance scenarios with synthetic effects.
5. Prepare the consumer integration and a generated, digest-verified pin.
   Keep its old entrypoints and configuration contract until parity holds.
6. Under separate runtime authorization, drain pending approvals, preview the
   deployment, apply and reapply, and run representative allowed and refused
   operations across the approval, worker and dispatcher boundaries.
7. Transfer authorship and remove obsolete implementation only after parity
   and runtime acceptance. Preserve deployment configuration with the consumer.

Source rollback is closing an unmerged PR or reverting a merged change without
rewriting public history. Runtime rollback belongs to the consumer: restore
its previous reviewed pin and configuration after draining pending requests.
Do not regenerate trust roots or erase replay state as a rollback technique.
No rollback has been exercised by creating this plan.
