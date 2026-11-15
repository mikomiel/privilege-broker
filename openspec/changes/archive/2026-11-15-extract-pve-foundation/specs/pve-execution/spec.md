# PVE execution

## Purpose

Preserve the existing PVE approval-to-dispatch security contract while moving
its reusable implementation into a standalone source owner.

## ADDED Requirements

### Requirement: PVE operations remain a closed set
The PVE provider MUST support only policy-allowed container start, stop, reboot, shutdown, snapshot and broker-snapshot pruning. Broker and dispatcher MUST enforce the same versioned target policy. Destruction, arbitrary shell, arbitrary command arguments and unknown actions MUST remain ungrantable.

#### Scenario: Policy names an unknown action
- **WHEN** a policy grants an action outside the supported set
- **THEN** policy loading fails rather than accepting an extension or silently ignoring it

#### Scenario: A target has no grant
- **WHEN** a known operation is requested for a target not granted for that action
- **THEN** broker and dispatcher each refuse the operation

### Requirement: Extraction preserves PVE wire compatibility
The product MUST preserve existing canonical request digests, signed lease fields, policy schema, certificate restrictions, dispatcher input and output contracts during the parity stage. Deployment identifiers MUST be explicit configuration rather than private or permissive defaults.

#### Scenario: Portable foundation uses synthetic configuration
- **WHEN** the extracted code receives the same synthetic PVE request and policy as the retained implementation
- **THEN** canonical payloads and authorization decisions match, excluding intentionally random identifiers and key material

### Requirement: Certificate authority does not delegate shell authority
Certificates MUST be short-lived, bound to the requesting key, source-restricted and constrained to a fixed typed dispatcher and principal. They MUST disable PTY, forwarding and user startup scripts. Callers MUST NOT override those certificate restrictions.

#### Scenario: Caller supplies a principal override
- **WHEN** a request attempts to replace the executor principal or force-command
- **THEN** the broker refuses it or ignores it without issuing less restricted authority

### Requirement: Dispatch claims are durable and exclusive
The dispatcher MUST atomically claim authorization before executing fixed command arguments. Concurrent requests and replay after restart MUST NOT execute twice. A node that does not host the target MUST report that fact without claiming authorization so a worker can try the next configured node.

#### Scenario: Two workers dispatch concurrently
- **WHEN** two workers present the same authorization on the target's node
- **THEN** at most one dispatcher invokes the underlying operation

#### Scenario: Wrong node precedes the target node
- **WHEN** the first configured node does not host the approved target
- **THEN** it returns the non-hosting outcome without consuming authorization, allowing dispatch to the correct node

### Requirement: Snapshot pruning remains policy bounded
Pruning MUST remove only broker-owned snapshots older than the retention in the current policy. The operator's approval display MUST state that retention. Pruning MUST NOT accept a caller-supplied retention or remove unrelated snapshots.

#### Scenario: Unrelated snapshot is old
- **WHEN** pruning encounters an old snapshot not owned by the broker
- **THEN** the snapshot is retained
