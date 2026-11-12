# privilege-broker contributor instructions

GitHub is the only authoritative source and PR surface.

## Working contract

- Keep one writer per branch and worktree. Preserve unrelated work.
- Use isolated task branches and PRs to `main`; never rewrite published history.
- Required checks and independent approval must identify the exact current
  head. A comment, earlier-head approval or green local test is not approval.
- Authoring agents do not merge manually, run `gh pr merge`, enable `--auto`,
  use `--admin`, or weaken branch protection.
- Broker code, identity, policy, cryptography, execution, workflows, scripts,
  tests, dependencies, packaging, licences, agent instructions and unknown
  paths need a human merge. Only reviewed root README/CHANGELOG, direct
  `docs/*.md` and named OpenSpec documents may be eligible for controlled
  automerge after trusted automation exists on main. The first governance PR
  is human-owned; its proposed automation cannot approve itself.
- Tags, releases, package/image publication, infrastructure writes, production
  probes and deployment require separate operator authorization.

## Security and scope

Implement enforced typed operations, not approval-only advice or arbitrary
shell execution. Keep requester identity, human approval and execution outcome
separate. Fail closed on missing, stale, replayed or ambiguous authorization.
Do not reissue a consumed authorization because a reply was lost.

Keep PVE wire formats unchanged during extraction. New provider support must
use an explicit versioned contract and concrete typed operations; do not build
a dynamic plugin loader or a speculative provider framework.

Source, fixtures, messages and artifacts must not contain credentials, real
deployment identifiers, internal addresses, webhook URLs or private runbooks.
Use synthetic documentation addresses and targets. Scan the entire intended
public commit range, including commit messages, before push. Do not use
production credentials in tests.

## Checks

```sh
uv sync --frozen
uv run ruff check .
uv run python -m pytest -q
uv run python examples/pve_authorization.py
uv build
uv run python scripts/check_estate_identifiers.py
```

Also run Gitleaks with the checked-in policy before publication, against
tracked blobs, the complete intended commit range and commit messages.
`CONTRIBUTING.md` owns the commands. Report PASS, FAIL, NOT RUN or UNAVAILABLE.
Do not report bootstrap tests as product or runtime acceptance.
