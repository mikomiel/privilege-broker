# Operator notifications

## Purpose

Deliver broker-owned approval notifications without making the requesting
agent or the notification transport an authorization authority.

## ADDED Requirements

### Requirement: Broker owns the approval notification
For each accepted request, the configured broker notification transport MUST send the operator its approval URL, operation, target, escaped reason and expiry. Requesting agents MUST NOT choose the notification destination or suppress the configured notification. The first supported transport MUST be Discord.

#### Scenario: Agent creates an allowed request
- **WHEN** an authenticated agent creates a policy-allowed request and notifications are configured
- **THEN** the broker sends the approval information to the operator-configured destination

### Requirement: Notification failure does not grant authority
The broker MUST audit notification success or failure without leaking transport credentials. Failed delivery MUST NOT approve a request or invalidate a successfully created request. A disabled transport MUST NOT be reported as successful delivery.

#### Scenario: Notification endpoint is unavailable
- **WHEN** the notification send fails after request creation
- **THEN** the request remains pending, the agent retains its approval URL and the audit records failed delivery without credentials

### Requirement: Agent observes authorization and outcome separately
The authenticated agent MUST be able to read its request's approval state and execution outcome. Pending, denied, expired, authorized, executing, succeeded, failed and uncertain outcomes MUST remain distinguishable. Notification delivery and human approval MUST NOT be reported as successful execution.

#### Scenario: Approval precedes dispatch
- **WHEN** an operator approves a request but its executor has not completed
- **THEN** agent status identifies the authorization state without claiming successful execution
