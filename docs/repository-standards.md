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

Required checks are `checks` and `public-content`, bound to GitHub Actions.
The independent reviewer is the Gandalf App on the exact PR head. Trusted
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

## Bootstrap transition

The scaffold was published as the authorized one-time initial commit. Main
currently uses strict required checks, stale-review dismissal, admin
enforcement and one native independent approval. This temporary native-review
requirement stays until trusted review-status publishing exists on main.
The first governance/source PR must be human-merged; its own proposed writer
workflows are not trusted to approve it.

After that merge, the maintainer must verify trusted status publishing and
add the Actions-bound `review` context to protection. Only then can the
native approval count be aligned to the existing single-maintainer App-status
pattern without removing exact-head independent review. Missing App coverage
or CI observation remains a blocker, never a reason to bypass protection.

## Security and supply chain

[SECURITY.md](../SECURITY.md) owns private reporting and runtime boundaries.
Dependabot groups uv and Actions updates with bounded PR counts. Dependency
review rejects newly introduced high/critical vulnerabilities. CodeQL uses
GitHub's repository-managed default setup, not a private self-hosted runner.
Gitleaks and the private-identifier scanner inspect trees, history and commit
messages before public push and in CI.

Optional community features, a second administrator, coverage quotas and
artifact publication are not installed merely to improve a score. There is
no UI screenshot because no runnable UI has been extracted. There is no
release or artifact attestation claim because nothing has been published.
See [releases.md](releases.md) for release-please and its explicit publication gate.
