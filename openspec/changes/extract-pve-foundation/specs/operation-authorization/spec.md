# Operation authorization

## Purpose

Bind an authenticated agent's requested operation to human approval and a
narrow authorization that a trusted executor can enforce.

## ADDED Requirements

### Requirement: Request identity is authenticated
The broker MUST derive authorization identity from verified transport context, never from requester text or a self-reported hostname. It MUST deny requests without a recognized authenticated identity.

#### Scenario: Caller claims another identity
- **WHEN** request text names an allowed agent but the authenticated identity is absent or different
- **THEN** the broker denies access or uses only the verified identity, without granting the claimed identity's permissions

### Requirement: Human approval binds the immutable request
The broker MUST bind passkey approval to the operation, target, parameters, requester, key binding and deadline. It MUST verify the challenge, relying-party origin and user verification. Denied, expired, modified or already consumed requests MUST NOT issue authorization.

#### Scenario: Request changes after approval begins
- **WHEN** an operation or its target differs from the immutable request associated with the passkey challenge
- **THEN** no authorization for the changed operation is issued

#### Scenario: Request expires before approval
- **WHEN** the operator submits approval after its deadline
- **THEN** the broker refuses approval and records the expiry

### Requirement: Authorization is scoped and verifiable
Authorization MUST be short-lived, signed and bound to the approved request, execution arguments, policy version, executor audience and one dispatch. Executors MUST reject invalid signatures, incompatible schemas, wrong audiences, altered arguments, expired authorization and scope outside current policy.

#### Scenario: Authorized arguments are altered
- **WHEN** a valid authorization for one target is presented for another target
- **THEN** the executor rejects it without performing an operation

### Requirement: Ambiguous authorization does not authorize a retry
The broker MUST NOT issue a second certificate for a consumed approval. Execution MUST use durable replay protection. A lost reply or an ambiguous execution outcome MUST NOT be reported as success or trigger blind redispatch.

#### Scenario: Certificate reply is lost
- **WHEN** the broker has consumed the certificate issuance gate but the worker did not receive the reply
- **THEN** repeated issuance is refused and the agent receives an explicit failure rather than a replacement authorization
