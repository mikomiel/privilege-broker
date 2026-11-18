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

The repository uses squash merges so each pull request adds one conventional
commit. Older changelog sections can repeat a change when both the topic
commit and the merge commit had the same subject. Keep those generated sections
as published.

The workflow references the repository Actions secret
`RELEASE_PLEASE_TOKEN`. The maintainer provisions it with repository-scoped
Contents and Pull requests write access; its value is never read or printed
by development tools. Its PRs must run normal required CI and independent
review. Version metadata remains a sensitive, human-merge path.

Merging a release PR authorizes publication for that commit. On its next run,
release-please creates the `vX.Y.Z` tag and the GitHub Release with the changelog
section. It then changes the pull request label from `autorelease: pending` to
`autorelease: tagged`.

The version tag starts the [container workflow](../.github/workflows/container.yml).
It publishes the image to GitHub Container Registry for `linux/amd64` and
`linux/arm64` with an SBOM and provenance. The workflow verifies that the digest
can be pulled anonymously and that its attestation is valid. Pin deployments to
the verified digest. Deployment remains a separate maintainer decision.

Never restore `skip-github-release: true`. It disables the only step that
flips that label, and the guard against a second release PR reads the label
rather than the tag, so a merged release PR that stays pending blocks every
later run with "There are untagged, merged release PRs outstanding". Without
a tag release-please cannot tell which commits are new: it falls back to the
whole history instead of the range since the last version.

Tags never move, and a release identifies the source and compatibility changes
it contains. Network operators must offer the corresponding AGPL source of the
version they run.
