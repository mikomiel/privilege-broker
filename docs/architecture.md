# Architecture and extraction status

The intended flow is authenticated agent → approval broker → operator passkey
→ bounded authorization → trusted executor → observable operation outcome.
Notification delivery is a separate step and never an authorization decision.

## Implemented source boundary

The first source stage provides:

- `privilege_broker.pve.common`: versioned target-policy parsing and canonical wire helpers.
- `privilege_broker.pve.authorization`: immutable request records, authenticated-proxy identity extraction, signed capability leases and SSH certificate argv construction.

These modules have no PVE API client, network transport, passkey verifier,
external command execution or running service. A host application must
provide the approval and execution boundaries; importing this package does
not enforce a human decision.

The PVE wire versions remain `pve-operate-v1`, `pve-approval-v1` and
`pve-execution-v1`. Certificate source restriction is now explicit; no
private deployment address is built in. Configuration is described in
[configuration.md](configuration.md).

## Remaining product stages

The active [OpenSpec change](../openspec/changes/extract-pve-foundation/proposal.md)
owns the remaining service, notification, bridge, worker and dispatcher work.
It separates product acceptance from consumer pinning, deployment and live
PVE acceptance. No current consumer has switched to this source.

The eventual generic operation lifecycle must keep approval and execution
states distinct. PVE remains the only initial provider; there is no dynamic
plugin system, arbitrary shell mode or approval-only mode.

## Provenance

The portable foundation is extracted from the owned ai-agents source snapshot
`75b8271722c3b5ec6262708fcd227cd6835fcef4`:

| Original file | Product boundary |
| --- | --- |
| `MCPs/servers/_pve_common.py` | Pure policy and canonicalization helpers only; no transport client |
| `MCPs/servers/pve_ssh_broker.py` | PVE authorization and certificate argument construction |
| `MCPs/tests/test_pve_ssh_broker.py` | Synthetic public tests for the same contracts |

Imports, comments, fixtures and explicit certificate source configuration
are adapted for the standalone package. Protocol identifiers and canonical
PVE payloads are retained. Private source history, deployment configuration,
trust roots and runbooks are not copied.
