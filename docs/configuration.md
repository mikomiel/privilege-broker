# PVE authorization configuration

This stage contains an authorization library, not an HTTP service or executor.
It does not load production credentials, issue SSH certificates, approve a
passkey ceremony or run a PVE operation by itself.

## Target policy

Load a deployer-owned JSON policy through
`load_policy(Path(...))`. The parser requires version 2 and exactly the
keys shown in [the synthetic example](../examples/pve-policy.json).
Grants are per action and container ID. Unknown actions, boolean IDs, missing
files and malformed policy are errors. An absent grant denies the operation.

The closed operation set is container start, stop, reboot, shutdown,
snapshot and broker-snapshot pruning. A policy can narrow that set, not add
new actions. Retention applies only to broker-owned snapshots.

## Certificate source restriction

Construct a server-owned certificate policy with an explicit source network:

```python
from privilege_broker.pve.authorization import CertificateCommandBuilder, CertificatePolicy

policy = CertificatePolicy(source="198.51.100.88/32")
builder = CertificateCommandBuilder(policy)
```

The address is documentation data, not a deployable default. Empty,
unrestricted or invalid networks fail. The fixed PVE principal, dispatcher,
short validity and disabled forwarding options remain in the PVE adapter.
The builder returns argv; it does not run ssh-keygen or hold the CA key.

A future service must supply this policy from trusted deployment
configuration, never from an agent's request. Request identity must come
from verified transport context; constructing a CanonicalRequest in a
Python process does not authenticate a remote caller.

The WebAuthn service, persistent signer configuration, notifications and
execution transports are not extracted yet. Their configuration will be
documented when those interfaces exist, rather than as non-working examples.
