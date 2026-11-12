# Releases

privilege-broker uses SemVer and Conventional Commits. Version 0.x can include
breaking changes, which must be identified in release notes. No product
release has been published yet. Local metadata version 0.0.0 is a source
bootstrap marker, not a supported release.

Release-please is the single owner of version and changelog updates. It uses
`release-please-config.json` and `.release-please-manifest.json` to propose
one release PR after release-relevant conventional commits. Ordinary feature
PRs do not hand-edit the changelog or bump versions.

The workflow references the repository Actions secret
`RELEASE_PLEASE_TOKEN`. The maintainer provisions it with repository-scoped
Contents and Pull requests write access; its value is never read or printed
by development tools. Its PRs must run normal required CI and independent
review. Version metadata remains a sensitive, human-merge path.

**Current publication gate:** `skip-github-release: true` deliberately
allows release-PR preparation only. Even merging a release PR does not
create a tag or GitHub Release with this configuration. Publishing the first
release requires a separate decision for the exact source and a reviewed
change to that boundary. No PyPI, container registry or deployment publisher
is installed.

After publication is authorized, tags must never move and releases must
identify the corresponding source and compatibility changes. Network
operators must offer the corresponding AGPL source of the version they run.
