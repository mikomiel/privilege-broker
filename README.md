# privilege-broker

[![CI](https://github.com/mikomiel/privilege-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/mikomiel/privilege-broker/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/mikomiel/privilege-broker)](LICENSE)

Human-approved typed operations for AI agents, with Proxmox VE as the first integration.

For operators who want agents to request bounded actions without receiving a
general shell or infrastructure-wide credentials.

**Status: pre-release PVE extraction.** The package includes a SQLite-backed
WebAuthn service, passkey UI, server-owned Discord notifications, restricted
SSH certificate signing, and the agent-side bridge, client and worker. The
target dispatcher, durable replay store and generic execution-outcome API are
not included yet. No existing deployment has switched to it, and no product
release has been published.

The extracted source can:

- Load a versioned PVE target policy and reject unknown actions or malformed grants.
- Bind canonical requests to authenticated identity and execution arguments.
- Sign and verify short-lived, single-dispatch capability leases.
- Require a real passkey ceremony before releasing authorization to the same authenticated agent.
- Sign a one-time-fetch SSH certificate with fixed principal, dispatcher and explicit source restriction.
- Notify an operator without treating delivery or approval as execution success.
- Create agent-side requests with private ephemeral keys and atomic pending-file publication.
- Poll approvals and classify SSH dispatcher outcomes without treating approval as execution.

## Try the local example

With Python 3.11+ and uv, from a clone of this repository:

```sh
uv sync --frozen
uv run python examples/pve_authorization.py
```

Expected output:

```text
PVE authorization example verified; no operation executed
```

The example uses ephemeral keys in memory and synthetic data. It performs no
network access, passkey approval, certificate signing or PVE operation.
It is a library demonstration, not an authorization service.

## Documentation

Read [architecture and extraction status](docs/architecture.md),
[configuration](docs/configuration.md), [repository tooling](docs/repository-standards.md)
and [the release process](docs/releases.md).
The [GitHub issue backlog](https://github.com/mikomiel/privilege-broker/issues)
tracks remaining repository work. The active
[OpenSpec change](openspec/changes/extract-pve-foundation/proposal.md) owns the
technical design and acceptance criteria for the agent interfaces, execution
components and end-to-end acceptance.
See [configuration](docs/configuration.md#approval-service) for the explicit
service factory and its TLS-frontend requirements. This is not a production-ready
executor; local tests do not establish live deployment acceptance.

## Contributing

Use GitHub Issues and focused PRs. Read [CONTRIBUTING.md](CONTRIBUTING.md),
[AGENTS.md](AGENTS.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Report vulnerabilities through the private route in [SECURITY.md](SECURITY.md).

## License

[GNU Affero General Public License v3.0 only](LICENSE)
(`SPDX-License-Identifier: AGPL-3.0-only`). Copyright belongs to the project
copyright holders; contributions are accepted under the same licence.
Network deployments must offer the corresponding source of the version they
run, including modifications where the licence requires them.
