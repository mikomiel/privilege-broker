# Contributing

Read [AGENTS.md](AGENTS.md) and [SECURITY.md](SECURITY.md) first.

## Changes and checks

Use GitHub Issues for the product backlog. A behaviour change needs a concrete
issue or an active OpenSpec change; do not duplicate its task list elsewhere.
Use one focused PR and one writer per branch/worktree.

```sh
uv sync --frozen
uv run ruff check .
uv run python -m pytest -q
uv run python scripts/check_estate_identifiers.py
git diff --check
```

Tests use pytest, temporary state, synthetic identities and no private
services. Assert refusals as well as success; prove a regression test rejects
the contrary behaviour. Mock destructive external effects, not the boundary
the test claims to prove.

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

Keep any deployment-specific forbidden-name patterns in a local, git-ignored
`.estate-identifiers` file, one regular expression per line. The public
scanner reports rule names and locations, never the matching text. A scan
after push cannot undo disclosure.

## Review and merge

Push a task branch and open a PR to `main`. Required CI is `checks` and
`public-content`; approval must be independent and bound to the current head.
The configured reviewer is the Gandalf GitHub App. Missing App coverage is a
merge blocker, not permission for author self-approval or weaker protection.

Bootstrap uses native protected-branch review requirements and read-only CI.
Trusted review-status publishing and controlled automerge must be installed
through a separately reviewed, human-merged governance PR before automation
can merge anything. Broker and other sensitive paths always need a human
merge. Authoring agents never substitute a manual merge for either owner.

Use SHA-pinned GitHub-owned or verified Marketplace actions. PR-head code
never runs with a write token or deployment credentials. A change to the
head requires fresh CI and independent review. Keep corrections in the same PR.

## Licence and release boundary

Contributions are accepted under AGPL-3.0-only. Confirm that you have the right
to submit them. Release tags, packages, images and deployment are separate
maintainer decisions; none is created by the bootstrap or an ordinary merge.
