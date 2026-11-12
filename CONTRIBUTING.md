# Contributing

Read [AGENTS.md](AGENTS.md) and [SECURITY.md](SECURITY.md) first. The project
accepts focused changes to the approved PVE extraction and its documented
interfaces, not arbitrary-shell execution or speculative provider frameworks.

## Changes and checks

Use GitHub Issues for the product backlog. A behaviour change needs a concrete
issue or an active OpenSpec change; do not duplicate its task list elsewhere.
Keep one decision per PR and one writer per branch/worktree. Tests and the
documentation for a behaviour change belong in the same PR.

```sh
uv sync --frozen
uv run ruff check .
uv run python -m pytest -q
uv run python examples/pve_authorization.py
uv build
uv run python scripts/check_estate_identifiers.py
git diff --check
```

Ruff configuration has one owner, `ruff.toml`. The locked toolchain follows
the other public Python projects: uv, Ruff, pytest and a wheel build.
Tests use temporary state, synthetic identities and no private services.
Install the OpenSSH client tools (`ssh-keygen`) for the real local certificate
tests. WebAuthn tests use generated software-authenticator keys and the real
verification library; they do not prove physical user presence or browser
compatibility. No test contacts PVE or a notification provider.
Assert refusals as well as success; prove a regression test rejects the
contrary behaviour. Mock destructive external effects, not the boundary the
test claims to prove.

## Public-content check before every push

Install Gitleaks 8.30.1 from its official release and verify the archive
checksum. The CI workflow pins the Linux x86-64 archive and its SHA-256.
Run from this repository with a clean, committed task branch:

```sh
set -euo pipefail
gitleaks git --config .gitleaks.toml --redact --no-banner --log-opts='--all' .
git ls-tree --name-only -r -z HEAD | while IFS= read -r -d '' path; do
  git show "HEAD:$path"
  printf '\n'
done | gitleaks stdin --config .gitleaks.toml --redact --no-banner
git log --all --format=%B | gitleaks stdin --config .gitleaks.toml --redact --no-banner
git log --all --format= --patch | uv run python scripts/check_estate_identifiers.py --stdin
git log --all --format=%B | uv run python scripts/check_estate_identifiers.py --stdin
```

Keep deployment-specific forbidden-name patterns in a local, git-ignored
`.estate-identifiers` file, one regular expression per line. The scanner
reports rule names and locations, never matching text. A scan after push
cannot undo disclosure.

## Review and merge

Push a task branch and open a PR to `main`. Required CI and independent
approval must identify the exact current head. The configured reviewer is
the Gandalf GitHub App; missing coverage blocks merge. Correct findings in
the same PR, then obtain fresh checks and review after every head change.

[Repository tooling and governance](docs/repository-standards.md) owns the
sensitive-path policy, trusted automation and protected-main bootstrap
transition. Authoring agents never merge manually or weaken protection.
Workflows use SHA-pinned GitHub-owned or verified Marketplace actions;
PR-head code never runs with a write token or deployment credentials.

The maintainer responds on a best-effort basis, without a guaranteed deadline.
AI assistance is welcome only when a responsible submitter understands the
diff and can reproduce its behaviour. Participation follows
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Licence and releases

Contributions are accepted under AGPL-3.0-only. Confirm that you have the right
to submit them. Release-please owns version and changelog updates; see
[the release process](docs/releases.md). Tags, packages, images and deployment
remain separate maintainer decisions.
