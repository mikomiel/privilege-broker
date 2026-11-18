## Context

The PVE request and lease formats name a container, an SSH identity, and a PVE policy. UniFi requires site, policy, ordering, and operation bindings with HTTPS execution.

## Decisions

- Register one explicit UniFi operation family with separate requester and executor grants. Reuse mTLS verification, the enrolled passkeys, audit state, and the approval page's WebAuthn ceremony.
- Freeze the bounded typed proposal that the browser displays. Bind the challenge and an Ed25519 execution grant to a canonical proposal digest, request ID, executor identity, and deadline.
- Use a transactional claim before issuing the grant. Record a terminal outcome from the bound executor. Treat lost claims or lost results as uncertain and require a fresh proposal for any further write.
- Keep the controller path and credentials in the UniFi executor. Link a redacted result to the original requester.

## Trade-offs

A transport loss after a durable claim can prevent a write even when the operator approved it. This favors one dispatch over availability. Synthetic tests exercise concurrent claims and preserve the PVE authorization contract.
