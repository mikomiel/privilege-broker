# Tasks

## 1. Public source bootstrap

- [x] 1.1 Create licence, contributor and security contracts and the staged specifications; verify local links and `openspec validate --strict` before public push.
- [x] 1.2 Publish the authorized scaffold-only initial commit after secret, identifier, blob and commit-message scans; verify the remote main SHA matches the scanned commit (`d81e4190e8330ff05ddbc84979986db953b2809b`).
- [ ] 1.3 Configure protected main with strict required checks and independent review; verify protection through GitHub API and report missing reviewer App coverage without bypass.

## 2. Portable PVE authorization foundation

- [x] 2.1 Extract policy parsing and canonical request/lease logic into the PVE package with synthetic versions of the existing tests; verify policy refusals, digest parity, signature tampering, expiry and scope tests.
- [x] 2.2 Require deployment-supplied certificate source restriction and preserve fixed principal/dispatcher options; verify no permissive default and no caller-controlled authority expansion.
- [ ] 2.3 Document the extracted boundary and source provenance; run clean-install, lint, tests, public-content scans and exact-head CI; obtain independent review and human merge for this executable source PR.

## 3. Approval service and notifications

- [ ] 3.1 Extract the approval store and WebAuthn HTTP service without changing existing PVE requests or database meaning; verify mTLS isolation, enrollment bootstrap, origin/user verification, challenge binding, expiry and concurrent certificate issuance tests.
- [ ] 3.2 Extract server-owned Discord delivery and safe audit behaviour; verify escaping, fixed destinations, disabled delivery and failure without approval or credential disclosure; document notification configuration.
- [ ] 3.3 Expose distinct approval and execution states to the authenticated agent without claiming completion from approval; verify cross-identity refusals and authorized-but-not-executed status tests and document the contract.

## 4. PVE execution components

- [ ] 4.1 Extract the agent bridge, client and worker using explicit endpoints, trust and state configuration; verify pre-dispatch transient retry, expiry, lost-certificate terminal failure and no secret-bearing output.
- [ ] 4.2 Extract the typed dispatcher and replay store; verify fixed argv, current policy, source/certificate constraints, wrong-node routing, concurrent single claim and restart replay protection.
- [ ] 4.3 Preserve policy-bounded snapshot pruning and its approval display; verify synthetic old/unrelated/retained snapshot cases and update PVE operation documentation.

## 5. Product acceptance and handoff

- [ ] 5.1 Run a synthetic end-to-end approval-to-outcome flow with real local crypto, storage and protocol handling and substituted external mutations; verify allowed, denied, expired, tampered, concurrent and uncertain outcomes with fresh-process tests.
- [ ] 5.2 Verify the public product installs and checks without private paths or services; document runnable entrypoints, supported interfaces and known limits with exact source evidence.
- [ ] 5.3 Obtain exact-head required CI, independent approval and human merge for every executable or sensitive PR; record source and merge evidence without claiming deployment.

## Workflow follow-up

- A consumer-owned integration change must prepare a pinned generated copy and digest verification, preserve old entrypoints and prove PVE parity before changing its source owner.
- Live deployment, pending-request drain, representative canary, rollback and removal of the old implementation require separate consumer authorization. They are not product-source completion criteria.
- The first source PR also supplies the shared repository baseline requested by the operator on 2026-11-12: community forms, docs/examples, dependency tooling, trusted review-status and documentation-only controlled automerge. Its writer workflows remain inactive until human merge; the empty-main bootstrap contained read-only CI only.
- Release-please uses the existing `RELEASE_PLEASE_TOKEN` Actions secret reference with `skip-github-release: true`. Secret metadata was verified on 2026-11-12 without retrieving its value. Release-PR preparation is source-present, not proof of working automation or authorization to create a tag or release.
- Archive only after product acceptance and the project's review gates hold. Consumer runtime cutover remains separately tracked by its owner.
