# Proposal

## Why

The existing PVE approval broker combines reusable authorization and execution
code with private deployment configuration. Extract its working boundary into
a standalone product so other agents can request narrowly scoped operations
without acquiring broad infrastructure credentials.

## What Changes

- Make this GitHub repository the product source owner under AGPL-3.0-only.
  Keep private deployment policy, identities, secrets and routing outside it.
- Extract PVE authorization, passkey approval, notification, agent bridge,
  worker and typed dispatcher in reviewable stages. Preserve the existing
  PVE wire formats and refusal behaviour before generalizing any protocol.
- Keep the initial notification transport, Discord, behind a product-owned
  notification boundary. The operator cannot be bypassed by the requesting
  agent; notification delivery never counts as approval.
- Separate a generic operation lifecycle from the PVE adapter: authenticated
  request, notification, approval/denial/expiry, single-use authorization,
  bounded execution and an observable outcome. PVE is the only initial
  provider. Add a second provider only for a concrete typed operation.
- Require public-content checks before every push, independent exact-head
  review and green CI. Executable and other sensitive paths need human merge.
- Move source ownership only after PVE parity. Consumers then use a pinned,
  generated copy; they never edit a competing implementation.

Non-goals: arbitrary shell execution, a plugin platform, generic credential
issuance, additional live providers, release publication, public service
exposure, deployment, key rotation or a change to production target grants.

## Capabilities

### New Capabilities

- `operation-authorization`: immutable requests, authenticated requester and
  operation-bound human approval with short-lived single-use authorization.
- `operator-notifications`: broker-owned approval notifications and audited
  delivery outcomes independent of authorization.
- `pve-execution`: preserved PVE policy, certificate, dispatch and replay
  semantics with an execution result distinct from approval.
- `standalone-source`: self-contained public source, protected GitHub flow
  and parity-gated consumer ownership transfer.

### Modified Capabilities

No existing product specifications exist yet.

## Impact

Planned product code: `privilege_broker/` with the PVE implementation under
`privilege_broker/pve/`; `tests/` uses synthetic identities, targets and
local substitutes. Runtime dependencies follow the existing Python,
FastAPI, WebAuthn, SQLite, cryptography and OpenSSH implementation.

The first implementation PR contains the portable PVE policy and
authorization foundation and its tests, plus the shared GitHub tooling and
contribution baseline requested by the operator. Service, transport and dispatch
follow in later reviewed PRs. No current consumer switches in this change.
A consumer's integration plan, pin update and runtime acceptance remain with
that consumer and require separate deployment authorization.
