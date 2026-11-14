# Tasks

[GitHub Issues](https://github.com/mikomiel/privilege-broker/issues) owns the work
queue and PR links. This file owns the numbered acceptance criteria and merged
source evidence. Each unfinished task links to its tracking issue.

## 1. Public source bootstrap

- [x] 1.1 Create licence, contributor and security contracts and the staged specifications; verify local links and `openspec validate --strict` before public push.
- [x] 1.2 Publish the authorized scaffold-only initial commit after secret, identifier, blob and commit-message scans; verify the remote main SHA matches the scanned commit (`d81e4190e8330ff05ddbc84979986db953b2809b`).
- [x] 1.3 Configure protected main with strict required checks and independent review; verify protection through GitHub API and report missing reviewer App coverage without bypass.

## 2. Portable PVE authorization foundation

- [x] 2.1 Extract policy parsing and canonical request/lease logic into the PVE package with synthetic versions of the existing tests; verify policy refusals, digest parity, signature tampering, expiry and scope tests.
- [x] 2.2 Require deployment-supplied certificate source restriction and preserve fixed principal/dispatcher options; verify no permissive default and no caller-controlled authority expansion.
- [x] 2.3 Document the extracted boundary and source provenance; run clean-install, lint, tests, public-content scans and exact-head CI; obtain independent review and human merge for this executable source PR.

## 3. Approval service and notifications

- [x] 3.1 Extract the approval store and WebAuthn HTTP service without changing existing PVE requests or database meaning; verify mTLS isolation, enrollment bootstrap, origin/user verification, challenge binding, expiry and concurrent certificate issuance tests.
- [x] 3.2 Extract server-owned Discord delivery and safe audit behaviour; verify escaping, fixed destinations, disabled delivery and failure without approval or credential disclosure; document notification configuration.
- [x] 3.3 Expose distinct approval and execution states to the authenticated agent without claiming completion from approval; verify cross-identity refusals and authorized-but-not-executed status tests and document the contract. [Issue #7](https://github.com/mikomiel/privilege-broker/issues/7).

## 4. PVE execution components

- [ ] 4.1 Extract the agent bridge, client and worker using explicit endpoints, trust and state configuration; verify pre-dispatch transient retry, expiry, lost-certificate terminal failure and no secret-bearing output. [Issue #8](https://github.com/mikomiel/privilege-broker/issues/8).
- [ ] 4.2 Extract the typed dispatcher and replay store; verify fixed argv, current policy, source/certificate constraints, wrong-node routing, concurrent single claim and restart replay protection. [Issue #9](https://github.com/mikomiel/privilege-broker/issues/9).
- [ ] 4.3 Preserve policy-bounded snapshot pruning and its approval display; verify synthetic old/unrelated/retained snapshot cases and update PVE operation documentation. [Issue #10](https://github.com/mikomiel/privilege-broker/issues/10).

## 5. Product acceptance and handoff

- [ ] 5.1 Run a synthetic end-to-end approval-to-outcome flow with real local crypto, storage and protocol handling and substituted external mutations; verify allowed, denied, expired, tampered, concurrent and uncertain outcomes with fresh-process tests. [Issue #11](https://github.com/mikomiel/privilege-broker/issues/11).
- [ ] 5.2 Verify the public product installs and checks without private paths or services; document runnable entrypoints, supported interfaces and known limits with exact source evidence. [Issue #12](https://github.com/mikomiel/privilege-broker/issues/12).
- [ ] 5.3 Obtain exact-head required CI, independent approval and human merge for every executable or sensitive PR; record source and merge evidence without claiming deployment. [Issue #13](https://github.com/mikomiel/privilege-broker/issues/13).

## Workflow follow-up

- A consumer-owned integration change must prepare a pinned generated copy and digest verification, preserve old entrypoints and prove PVE parity before changing its source owner.
- Live deployment, pending-request drain, representative canary, rollback and removal of the old implementation require separate consumer authorization. They are not product-source completion criteria.
- The first source PR supplied the shared repository baseline requested by the operator: community forms, docs/examples, dependency tooling, trusted review-status and documentation-only controlled automerge. [PR #1](https://github.com/mikomiel/privilege-broker/pull/1) was human-merged on 2026-11-12 as `e76d6054b1b6980697fb5b6cf8c9418074c2c08b` after exact-head CI and [Gandalf approval](https://github.com/mikomiel/privilege-broker/pull/1#pullrequestreview-5881218517) at `db3157720f2148a78fce6d1c0f45a168037b44f1`. No consumer switched to the product.
- Task 1.3 is complete. GitHub API readback and a successful trusted publisher run verified the protection model. [Repository governance](../../../docs/repository-standards.md#completed-bootstrap) owns the final settings, the one-time maintainer exception and the publisher evidence.
- Release-please uses the existing `RELEASE_PLEASE_TOKEN` Actions secret reference with `skip-github-release: true`. Its [post-merge run](https://github.com/mikomiel/privilege-broker/actions/runs/43309801533) succeeded and prepared [release PR #2](https://github.com/mikomiel/privilege-broker/pull/2). Secret metadata was checked without retrieving its value. Release-PR preparation is verified; no tag, product release or deployment was created or authorized by this source work.
- Track the release-action update in [issue #15](https://github.com/mikomiel/privilege-broker/issues/15) and the version/changelog preparation in [issue #16](https://github.com/mikomiel/privilege-broker/issues/16). Neither issue authorizes a tag, release or deployment.
- Archive only after product acceptance and the project's review gates hold; [issue #14](https://github.com/mikomiel/privilege-broker/issues/14) owns that closeout. Consumer runtime cutover remains separately tracked by its owner.
