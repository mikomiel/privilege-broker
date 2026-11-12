# PVE configuration

This pre-release stage supplies authorization, approval and certificate signing,
not an executor. Deployment, credentials, TLS and consumer cutover remain separate
operator decisions. No example grants access to a real target.

## Target policy

Load a deployer-owned JSON policy with `load_policy(Path(...))`. The parser
requires version 2 and exactly the keys in [the synthetic example](../examples/pve-policy.json).
Grants are per action and container ID. Unknown actions, boolean IDs, missing
files and malformed policy fail. An absent grant denies the operation.

The closed operation set is container start, stop, reboot, shutdown, snapshot
and broker-snapshot pruning. Policy can narrow this set, not add actions. The
future dispatcher must enforce retention against broker-owned snapshots.

## Approval service

Install with Python 3.11+ and uv. After providing the explicit configuration
below, the factory entrypoint is:

```sh
uv sync --frozen
uv run uvicorn privilege_broker.pve.service:create_broker_app_from_env \
  --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

This command is a deployment reference, not authorization to start a service.
Use one worker and one store per process. Importing the module does not start
an app, open a database or load private keys. The legacy autostart environment
flag is not an entrypoint. A normal ASGI lifespan closes the factory-owned
SQLite connection at shutdown.

| Environment variable | Requirement |
| --- | --- |
| `PVE_BROKER_DATABASE` | Required private SQLite state path; protect the database, WAL and shared-memory files together |
| `PVE_BROKER_LEASE_KEY_PATH` | Required persistent Ed25519 PKCS#8 PEM private-key file, readable only by its owner |
| `PVE_BROKER_POLICY_FILE` | Required version-2 JSON policy path |
| `PVE_BROKER_RP_ID` | Required WebAuthn relying-party hostname, without a scheme or path |
| `PVE_BROKER_ORIGIN` | Required exact HTTPS browser origin for that relying party |
| `PVE_BROKER_ENROLLMENT_KEY` | Required bootstrap secret supplied by the deployment's credential mechanism; never print it or put it in command arguments |
| `PVE_BROKER_ENROLLMENT_ENABLED` | Defaults to disabled; only the value `true` enables initial bootstrap enrollment |
| `PVE_BROKER_MTLS_CLIENTS_JSON` | Explicit identity-to-observed-IP map; unset rejects all agent calls. A value may be one address or a non-empty list, for example `{"agent-demo":"192.0.2.10"}` |
| `PVE_BROKER_CA_KEY_PATH` | Optional private, unencrypted OpenSSH CA key for local `ssh-keygen`; absent returns `not_ready` for certificate fetch |
| `PVE_BROKER_CERT_SOURCE` | Required when CA signing is configured: one explicit restricted CIDR (lists are not supported) |
| `PVE_BROKER_NOTIFY_WEBHOOK_FILE` | Optional private file containing the server-owned Discord webhook URL |

The factory does not create keys, install a TLS frontend, populate a target
policy or provision credentials. Protect secret files and process access with
the deployment's service identity. Do not store secrets in source or an
unprotected environment file.

### Frontend trust boundary

The service does not terminate agent mTLS. A separately configured local TLS
proxy must verify client certificates, strip caller-supplied metadata and set
`X-Pve-Broker-Mtls-Identity` and `X-Pve-Broker-Mtls-Source-Ip` from verified
transport facts. The extractor accepts these headers only from a loopback
peer and only when identity and observed address match the configured map.

Keep the backend inaccessible to agents and untrusted local processes. Loopback
alone does not authenticate a local caller. Disable Uvicorn proxy-header
rewriting as shown above so the peer remains the actual local frontend, not an
address from `X-Forwarded-For`. Deployers also own TLS, browser origin, request
size limits and isolation. The Python app cannot establish these host facts.

### Enrollment and approval

The initial enrollment endpoint requires the configured bootstrap header and
an explicitly enabled enrollment mode. Registration and authentication verify
the stored challenge, RP, origin, user presence and user verification with the
WebAuthn library. Bootstrap consumption and passkey counters persist in SQLite;
restarts or key rotation do not create another initial-enrollment entitlement.
Disable enrollment after provisioning. General passkey administration and
recovery are not implemented.

Agent requests use `POST /v1/broker/requests`; identity is not taken from its
body. Browser approval returns only `{"status":"approved"}`, never a lease
or certificate. The same authenticated agent can fetch its lease and make one
certificate fetch. Altered keys, other identities, expired requests and replay
fail. Only valid Ed25519 SSH request keys are accepted; this is separate from
the operator's WebAuthn key algorithm.

The browser status endpoint reports request authorization, not execution.
Recipients of an opaque approval URL can deny a pending request without a
passkey; denial grants no authority. Protect these URLs against unwanted
cancellation and metadata disclosure. There is no authenticated generic
execution-outcome API yet.

## Certificate source restriction

The library and service require an explicit source restriction:

```python
from privilege_broker.pve.authorization import CertificateCommandBuilder, CertificatePolicy

policy = CertificatePolicy(source="198.51.100.88/32")
builder = CertificateCommandBuilder(policy)
```

The address is documentation data, not a deployable default. Empty,
unrestricted or invalid networks fail. The principal, forced dispatcher,
short validity and disabled forwarding remain fixed in the PVE adapter.
The builder only returns argv; the configured service signer invokes local
`ssh-keygen` with that argv and a timeout. It does not connect to PVE.

A certificate is safe only with the trusted typed dispatcher and lease
verification on the target. Those execution components are not extracted yet.
Do not treat certificate issuance as an operation outcome or enable a general
shell while waiting for the dispatcher.

## Operator notifications

The destination comes only from `PVE_BROKER_NOTIFY_WEBHOOK_FILE`, never a
request. An unset, empty or unreadable file disables delivery; it is not a
successful send. Operators must verify delivery configuration separately.
The URL is a credential, so only its file path belongs in configuration.

The sender escapes agent-controlled text, disables mentions and link embeds,
uses English labels and explicit UTC expiry, and applies a transport timeout.
Audit records distinguish successful delivery from failure without storing
the webhook URL or raw provider error. Neither outcome approves the request.

FastAPI owns after-response delivery tasks. This is not a durable notification
queue: a crash can lose delivery, and an HTTP response is not evidence that a
message reached an operator. Approval, notification and execution remain
separate states. No Discord or PVE request is made by the test suite.
