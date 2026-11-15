# Standalone source

## Purpose

Provide one independently buildable public product source and a controlled
ownership transfer that does not silently replace an existing deployment.

## ADDED Requirements

### Requirement: Product builds without private infrastructure
Product source, tests, documentation and examples MUST build and validate without private repository paths, production credentials or live PVE systems. Fixtures MUST be synthetic. The complete intended commit range, blobs and messages MUST pass secret and private-identifier checks before public push.

#### Scenario: Contributor has only the public repository
- **WHEN** a contributor runs the documented local checks with the declared tools
- **THEN** checks do not require a private service, private checkout or production secret

### Requirement: GitHub publication requires exact-head evidence
After the authorized empty-main bootstrap, changes MUST use protected-main PRs with successful required CI and independent current-head approval. Executable and sensitive paths MUST require human merge. Missing review coverage or unavailable evidence MUST block merge rather than weaken protection.

#### Scenario: Reviewer App is not installed
- **WHEN** independent App review cannot run for a product PR
- **THEN** the author reports the missing installation and does not merge or bypass required review

### Requirement: Consumer ownership transfer requires parity
Consumers MUST retain their working implementation until the extracted PVE flow passes parity checks. After transfer, this repository MUST be the sole authored product source; consumer copies MUST be pinned and generated with equality verification. Private deployment policy and credentials MUST remain consumer-owned.

#### Scenario: Extracted flow fails parity
- **WHEN** a synthetic or separately authorized representative PVE acceptance check fails
- **THEN** consumers retain the existing source and pin without runtime cutover

### Requirement: Source publication does not activate a deployment
A source commit, successful CI, review or merge MUST NOT imply deployment, runtime acceptance, release publication, expanded target grants or key rotation. Deployment and rollback MUST remain separately authorized and evidence-backed.

#### Scenario: Product source PR merges
- **WHEN** reviewed product code reaches main
- **THEN** the recorded state is merged source and no existing deployment is upgraded automatically
