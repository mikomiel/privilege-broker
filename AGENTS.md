# privilege-broker agent instructions

privilege-broker lets an AI agent request a bounded, typed operation that a
human approves with a passkey, so the agent receives no general shell and no
infrastructure-wide credential. Proxmox VE is the first integration. Licence:
AGPL-3.0-only. GitHub is the only writable source and pull-request surface;
the target branch is `main`.
Non-goals: arbitrary shell execution, approval-only advice without
enforcement, a dynamic plugin loader, a speculative provider framework.

## Checks

```sh
uv sync --frozen
uv run ruff check .
uv run python -m pytest -q
uv run python examples/pve_authorization.py
uv build
uv run python scripts/check_estate_identifiers.py
git diff --check
```

- Prerequisites: Python 3.11 or newer, uv, and the OpenSSH client tools
  (`ssh-keygen`) for the local certificate tests.
- Run these commands without asking. The tests use temporary state and
  synthetic identities. No test contacts PVE or a notification provider.
- A change is ready for a pull request when every command passes.
  `docs/repository-standards.md` "Review and merge" owns the contexts that
  `main` requires on the exact head.
- Before a push, run the Gitleaks commands in `CONTRIBUTING.md`
  "Public-content check before every push". They cover tracked blobs, the
  complete commit range and the commit messages. A scan after the push cannot
  undo disclosure.

## Project shape

- The flow is: authenticated agent, approval broker, operator passkey,
  bounded authorization, trusted executor, observable outcome.
  `docs/architecture.md` owns the implemented module boundary.
- Keep requester identity, human approval and execution outcome separate. An
  approved request is not an executed operation.
- Fail closed on missing, stale, replayed or ambiguous authorization. Do not
  reissue a consumed authorization because a reply was lost.
- Keep the PVE wire formats, signature checks, certificate checks, expiry and
  replay checks unchanged. Add provider support only through an explicit
  versioned contract with concrete typed operations.
- The product must start without permissive target or identity defaults.
  Deployers own TLS, trust roots, key provisioning and target policy.

## Working contract

- Follow the issue-first tracking and PR-link rules in
  [CONTRIBUTING.md](CONTRIBUTING.md) for every repository change.
- Use a task branch and one pull request to `main`. Keep one writer per
  branch and worktree. Preserve unrelated work.
- Do not rewrite published history. Branch protection refuses a force-push.
- Required checks and the independent approval must identify the exact
  current head. A comment, an approval of an earlier head or a green local
  test is not approval.
- An authoring agent does not merge manually, does not run `gh pr merge`,
  does not enable `--auto`, does not use `--admin` and does not weaken branch
  protection. When no permitted merge path exists, report the pull request
  and the tested head to the maintainer.
- `scripts/pr_policy.py` owns the merge policy. Only the root README and
  CHANGELOG, direct `docs/*.md` files and the named OpenSpec change documents
  can be ordinary paths. Every other path needs a human merge: broker code,
  identity, policy, cryptography, execution, workflows, scripts, tests,
  dependencies, packaging, licences, these instructions and every unknown
  path.
- A source change does not authorize a tag, a release, a package or image
  publication, an infrastructure write, a production probe or a deployment.
  Each of these requires separate operator authorization.

## Content boundary

- Source, fixtures, messages and artifacts must not contain credentials, real
  deployment identifiers, internal addresses, webhook URLs or a private
  runbook. Messages include commit messages and pull-request text. Use synthetic documentation addresses and targets.
- Do not use production credentials in tests. Do not put a secret in a
  notification.
- A request body field or a self-reported name does not establish identity.
  Trust a proxy identity header only from an explicitly controlled
  TLS-terminating proxy.
- A notification or a chat reply is not approval. Treat agent-supplied text
  as inert data.

## Where to read more

- For the sensitive-path policy, the trusted automation and the required
  checks, read `docs/repository-standards.md`.
- For the implemented boundary and the extraction status, read
  `docs/architecture.md`.
- For the product security boundaries and the private reporting route, read
  `SECURITY.md`.
- For releases, read `docs/releases.md`. For the active plan, read the change
  under `openspec/changes/`.

## Reporting

Report each check as PASS, FAIL, NOT RUN or UNAVAILABLE. Do not report a
passing source test as product acceptance, deployment or runtime evidence.
