# Releases

privilege-broker uses SemVer and Conventional Commits. Version 0.x can include
breaking changes, which must be identified in release notes. Version `0.0.0`
was the source bootstrap marker and was never a supported release.

Release-please is the single owner of version and changelog updates. It uses
`release-please-config.json` and `.release-please-manifest.json` to propose
one release PR after release-relevant conventional commits. That PR bumps
`pyproject.toml`, the manifest and the project's own version in `uv.lock`;
`checks` runs `uv lock --check`, so a release PR that skipped the lock fails
instead of leaving `main` stale. Ordinary feature PRs do not hand-edit the
changelog or bump versions.

Release-please derives one entry per conventional commit, so a topic commit and
a merge commit that repeats its subject can both appear and list one change
twice. Treat repeated entries as a rendering artifact, not as separate changes.
`CHANGELOG.md` stays generated: do not hand-edit it to remove duplicates.

The workflow references the repository Actions secret
`RELEASE_PLEASE_TOKEN`. The maintainer provisions it with repository-scoped
Contents and Pull requests write access; its value is never read or printed
by development tools. Its PRs must run normal required CI and independent
review. Version metadata remains a sensitive, human-merge path.

**Publication boundary.** Merging a release PR publishes version metadata: on
its next run release-please creates the `vX.Y.Z` tag on that release commit and
a GitHub Release carrying the changelog section, then flips the pull request
from `autorelease: pending` to `autorelease: tagged`. No PyPI, container
registry, image or deployment publisher is installed; those remain separate
maintainer decisions.

Never restore `skip-github-release: true`. It disables the only step that
flips that label, and the guard against a second release PR reads the label
rather than the tag, so a merged release PR that stays pending blocks every
later run with "There are untagged, merged release PRs outstanding". Without
a tag release-please cannot tell which commits are new: it falls back to the
whole history instead of the range since the last version.

Tags never move, and a release identifies the source and compatibility changes
it contains. Network operators must offer the corresponding AGPL source of the
version they run.
