## Why

UniFi Agent MCP needs operation-specific human authorization for user-defined firewall policy changes. The broker already owns the passkey ceremony and durable approval state.

## What Changes

- Add explicit UniFi create, update, and delete approvals.
- Authenticate the requester and executor for the UniFi operation family.
- Bind the passkey preview to an expiring, single-use execution grant and record the executor's result.

## Capabilities

### New Capabilities

- `unifi-firewall-approvals`: passkey approval and a durable one-use grant for a typed UniFi Network firewall policy change.

### Modified Capabilities

None.

## Impact

The provider adds an opt-in broker interface and durable state. Deployers configure its trust roots and identities. The executor owns the controller credential. [Issue #53](https://github.com/mikomiel/privilege-broker/issues/53)
