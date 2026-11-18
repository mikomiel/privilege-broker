# UniFi firewall approvals

## Purpose

Bind a verified operator approval to one typed UniFi firewall policy operation and report its execution result through the broker.

## ADDED Requirements

### Requirement: A UniFi approval is bound to an immutable proposal

The broker SHALL admit only configured identities and typed create, update, and delete requests. The browser proposal and signing input SHALL bind the same request and digest.

#### Scenario: A proposal changes after approval

- **WHEN** the presented payload or request identity differs from the approved digest
- **THEN** execution authorization SHALL be refused

### Requirement: A trusted executor can claim once

The broker SHALL reserve the approved request durably for its configured executor before issuing the signed grant. It SHALL accept a result only from that executor.

#### Scenario: A claim is repeated after a transport loss

- **WHEN** a second claim arrives for a consumed approval
- **THEN** the broker SHALL refuse the claim and preserve the recorded outcome or uncertainty
