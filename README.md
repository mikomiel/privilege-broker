# privilege-broker

Human-approved, narrowly scoped operations for AI agents. Proxmox VE (PVE)
container operations are the first integration.

**Status: source bootstrap. There is no runnable broker or supported release
yet.** The extraction is planned in
[OpenSpec](openspec/changes/extract-pve-foundation/proposal.md). Existing
deployments are not changed by this repository.

## Intended operation flow

1. An authenticated agent requests a named operation on an allowed target.
2. The broker notifies the operator and shows the exact request in its web UI.
3. The operator approves with a passkey, or denies the request.
4. A trusted executor receives short-lived, operation-bound authorization.
5. The agent can read the execution outcome. Approval alone is not success.

The PVE foundation uses signed capability leases, one-shot SSH certificates
and a replay-protected typed dispatcher. It does not grant an arbitrary
shell, a general-purpose PVE token, or authority to modify broker policy.
The initial notification transport is Discord; notification delivery is not
authorization.

## Development

GitHub is the only source and pull-request surface. Use a task branch and
a pull request to `main`. Read [AGENTS.md](AGENTS.md),
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

The bootstrap checks need Python 3.11+ and uv:

```sh
uv sync --frozen
uv run ruff check .
uv run python -m pytest -q
uv run python scripts/check_estate_identifiers.py
```

These checks cover repository scaffolding and publication guards, not a live
broker. Tests and examples must work without private infrastructure.

## Product and deployment ownership

This repository will own the broker, agent-facing interfaces, notifications,
PVE execution implementation, tests and product documentation. Deployers own
credentials, passkey enrollment, trust roots, allowed targets, network policy,
service placement and backups. The source consumer uses a reviewed, pinned
version; a merge never upgrades a deployment automatically.

The existing implementation stays in service until the extracted PVE flow
passes parity checks and a separately authorized cutover. After that cutover,
consumers must not maintain a second authored implementation.

## Licence

[GNU Affero General Public License v3.0 only](LICENSE)
(`SPDX-License-Identifier: AGPL-3.0-only`). A network deployment must offer
its users the corresponding source of the version it runs, including local
modifications where the licence requires them.
