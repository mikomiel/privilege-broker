# Repository tooling and governance

This repository follows the same GitHub-native pattern as the other public
products: locked uv/Python tooling, Ruff, pytest, SHA-pinned Actions, hosted
runners, public-content checks, independent exact-head App review, and a
trusted default-branch merge policy. It has no Forgejo mirror or private
build dependency.

## Maintainer and contribution model

The maintainer is [mikomiel](https://github.com/mikomiel). Product backlog is
in GitHub Issues; the active OpenSpec change owns its implementation tasks.
Use the bug and feature forms. Maintainer response is best effort, with no
promised review deadline. AI-assisted contributions need a responsible
submitter who understands and can reproduce the change.

The label vocabulary is bug, enhancement, documentation, dependencies,
good first issue, help wanted, question, wontfix, invalid and duplicate.
Only mark a good first issue when someone can actually mentor its contributor.
No automatic stale-issue closer is installed.

## Review and merge

Required checks are `checks`, `public-content` and `review`, all bound to
GitHub Actions. Main requires strict current-base checks and keeps admin
enforcement, conversation resolution and force-push/deletion protection.
The native approval count is zero: the required `review` status enforces
exact-head independent approval instead of requesting a second native approval.
The configured independent reviewer is the Gandalf App. Trusted
`review-gate` and `automerge` workflows read their policy from the default
branch and re-read immutable refs, complete CI, reviews and changed paths.
They never execute PR-head code with a write token. Review events are only
a signal to re-read metadata, not proof of approval.

`scripts/pr_policy.py` is the sole merge-policy implementation. Only root
README/CHANGELOG, direct `docs/*.md` and the named OpenSpec change documents
can be ordinary. Broker code, tests, scripts, dependencies, workflows,
licences, agent instructions and every unknown path require human merge.
A rename does not remove sensitivity from its old path.

An authoring agent never manually merges, enables a standing auto-merge order
or weakens protection. The repository owner retains GitHub administrative
control, but changing these rules is an explicit maintainer decision, not an
automation recovery path.

## Completed bootstrap

The initial scaffold contained read-only CI. The maintainer human-merged
[PR #1](https://github.com/mikomiel/privilege-broker/pull/1) on 2026-11-12 as
`e76d6054b1b6980697fb5b6cf8c9418074c2c08b`, after green exact-head CI and
[Gandalf approval](https://github.com/mikomiel/privilege-broker/pull/1#pullrequestreview-5881218517).
The reviewed source head was `db3157720f2148a78fce6d1c0f45a168037b44f1`.
Its proposed writer workflows were not used to approve their own installation.

The App approval did not satisfy the scaffold's native-review count. The
maintainer authorized a one-time bootstrap exception for PR #1 after verifying
that existing approval and CI; no second review was requested. This historical
exception is not a recovery path for later PRs.

After merge, the trusted publisher's
[successful run](https://github.com/mikomiel/privilege-broker/actions/runs/43309803906)
wrote a `review` status as GitHub Actions. An unreviewed new PR remained
`pending`, rather than inheriting PR #1's approval. Protection then added the
Actions-bound `review` context while retaining native approval count zero.
Missing App coverage or CI evidence still blocks merge; an authoring agent
does not weaken these protections.

## Security and supply chain

[SECURITY.md](../SECURITY.md) owns private reporting and runtime boundaries.
Dependabot groups uv and Actions updates with bounded PR counts. Dependency
review rejects newly introduced high/critical vulnerabilities. CodeQL uses
GitHub's repository-managed default setup, not a private self-hosted runner.
Gitleaks and the private-identifier scanner inspect trees, history and commit
messages before public push and in CI.

Optional community features, a second administrator, coverage quotas and
artifact publication are not installed merely to improve a score. There is
no browser or hardware-passkey acceptance claim: the approval UI is packaged,
but its local tests use software authenticator crypto and HTML checks. There
is no product-release or artifact-attestation claim; no product artifact has
been published.
See [releases.md](releases.md) for release-please and its explicit publication gate.
