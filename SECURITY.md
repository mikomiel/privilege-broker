# Security policy

## Status and reporting

This repository contains a pre-release PVE authorization and approval service,
not the complete agent-to-execution product. No product release or production deployment is
yet supported. Do not use it as an authorization boundary until the PVE
extraction and its acceptance checks are complete.

Private vulnerability reporting is enabled. Use the Security tab
[reporting form](https://github.com/mikomiel/privilege-broker/security/advisories/new);
do not put exploit details or private deployment data in a public issue. Include an affected commit and a synthetic reproduction.
No response-time or bounty commitment is made.

## Required product boundaries

- Authenticate the requester; body fields and self-reported names do not
  establish identity. Proxy identity headers are trusted only from an
  explicitly controlled TLS-terminating proxy.
- Bind passkey approval to the immutable operation, target, parameters,
  requester and authorization deadline. A notification or a chat reply is
  not approval. Never put secrets in notifications.
- A trusted executor enforces operation scope and current policy. The agent
  receives an outcome, not an infrastructure-wide credential or a shell.
- Keep authorization short-lived and single-use with durable replay state.
  Lost replies and ambiguous dispatches are not safe to repeat. At-most-once
  authorization is not a promise of exactly-once external effects.
- Preserve existing PVE signature, certificate, origin, user-verification,
  policy, expiry and replay checks during extraction.
- Deployers own TLS, trust roots, key provisioning, passkey enrollment,
  target policy, service isolation, backups and recovery. The product must
  start without permissive target or identity defaults.
- CI has read-only repository access and no deployment credentials. A public
  build must not require private infrastructure.

The extracted service verifies passkey ceremonies and binds authorization to
frontend-authenticated identity. The TLS frontend, private keys and isolation
remain deployer responsibilities. The service can sign a restricted SSH
certificate, but it has no PVE transport, execution worker or typed dispatcher.
Approval and certificate issuance are not evidence that an operation ran.
