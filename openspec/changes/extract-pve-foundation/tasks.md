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

- [x] 4.1 Extract the agent bridge, client and worker using explicit endpoints, trust and state configuration; verify pre-dispatch transient retry, expiry, lost-certificate terminal failure and no secret-bearing output. [Issue #8](https://github.com/mikomiel/privilege-broker/issues/8).
- [x] 4.2 Extract the typed dispatcher and replay store; verify fixed argv, current policy, source/certificate constraints, wrong-node routing, concurrent single claim and restart replay protection. [Issue #9](https://github.com/mikomiel/privilege-broker/issues/9). The dispatcher and its SQLite claim store live in `privilege_broker/pve/dispatcher.py`; `ct.snapshot_prune` is implemented by task 4.3.
- [x] 4.3 Preserve policy-bounded snapshot pruning and its approval display; verify synthetic old/unrelated/retained snapshot cases and update PVE operation documentation. [Issue #10](https://github.com/mikomiel/privilege-broker/issues/10). Pruning is in `privilege_broker/pve/dispatcher.py`; retention comes from policy and the approval page states it.

## 5. Product acceptance and handoff

- [x] 5.1 Run a synthetic end-to-end approval-to-outcome flow with real local crypto, storage and protocol handling and substituted external mutations; verify allowed, denied, expired, tampered, concurrent and uncertain outcomes with fresh-process tests. [Issue #11](https://github.com/mikomiel/privilege-broker/issues/11). Coverage is `tests/test_e2e_lifecycle.py`; the dispatcher runs as a fresh process and only the TLS transport, SSH and `pct` are substituted.
- [x] 5.2 Verify the public product installs and checks without private paths or services; document runnable entrypoints, supported interfaces and known limits with exact source evidence. [Issue #12](https://github.com/mikomiel/privilege-broker/issues/12). Interfaces are in `docs/architecture.md#supported-interfaces`; the wheel was installed into a clean environment and the dispatcher help verified.
- [x] 5.3 Obtain exact-head required CI, independent approval and human merge for every executable or sensitive PR; record source and merge evidence without claiming deployment. [Issue #13](https://github.com/mikomiel/privilege-broker/issues/13). Evidence is the table below.

## Merge evidence

| PR | Reviewed head | Review | Checks | Merge commit |
| --- | --- | --- | --- | --- |
| #21 | `ac326997771222401b4dc12c156f5752603cfeba` | 5904405398 | 11/11 | `28f5cb45f493681874900f0445ddadb0983ab37d` |
| #26 | `5cc4922dfc280e7f367a7527f9a659a11369fc5a` | 5906162075 | 11/11 | `73d43f412fb6e54d55a540f57fca5704e423f102` |
| #27 | `866c57be40b26a1f3651d5e56bc1e1a1adf4f61a` | 5907597734 | 10/10 | `4ed0d1fe40ad5c9b3d0766b17f56882d83b80be5` |
| #28 | `a353373e5d6f71a9f88e6c6680ee7ebec5f84078` | 5907885378 | 11/11 | `2fc7b5f4466dcd2b0871c3d8bbdecddd64bcdc70` |
| #29 | `b2007fe8e7c5119463e307430c8fdf599ca29bf4` | 5909828966 | 11/11 | `879cdeb5476474f60f57a89178b626985ea07ba6` |
| #30 | `13b48f642079970ae2c0baf6623c28f5bb105207` | 5910153635 | 11/11 | `7ec12e83b4a8a162a3d2d20a3b22c9945648e717` |
| #31 | `b0c987f90a2d70a0ad6545c3380fd5f9d6777483` | 5910318858 | 11/11 | `0e85708e9f7103ab74aa0f6024dada0dac6e8f57` |

Every row is an exact ref: the head Gandalf approved, that review's id, the
required check runs successful on that head, and the merge commit in `main`.
These are source and merge facts only. No deployment, consumer cutover or
runtime acceptance follows from them.

## Workflow follow-up

- A consumer-owned integration change must prepare a pinned generated copy and digest verification, preserve old entrypoints and prove PVE parity before changing its source owner.
- Live deployment, pending-request drain, representative canary, rollback and removal of the old implementation require separate consumer authorization. They are not product-source completion criteria.
- The first source PR supplied the shared repository baseline requested by the operator: community forms, docs/examples, dependency tooling, trusted review-status and documentation-only controlled automerge. [PR #1](https://github.com/mikomiel/privilege-broker/pull/1) was human-merged on 2026-11-12 as `e76d6054b1b6980697fb5b6cf8c9418074c2c08b` after exact-head CI and [Gandalf approval](https://github.com/mikomiel/privilege-broker/pull/1#pullrequestreview-5881218517) at `db3157720f2148a78fce6d1c0f45a168037b44f1`. No consumer switched to the product.
- Task 1.3 is complete. GitHub API readback and a successful trusted publisher run verified the protection model. [Repository governance](../../../docs/repository-standards.md#completed-bootstrap) owns the final settings, the one-time maintainer exception and the publisher evidence.
- Release-please uses the existing `RELEASE_PLEASE_TOKEN` Actions secret reference with `skip-github-release: true`. Its [post-merge run](https://github.com/mikomiel/privilege-broker/actions/runs/43309801533) succeeded and prepared [release PR #2](https://github.com/mikomiel/privilege-broker/pull/2). Secret metadata was checked without retrieving its value. Release-PR preparation is verified; no tag, product release or deployment was created or authorized by this source work.
- Track the release-action update in [issue #15](https://github.com/mikomiel/privilege-broker/issues/15) and the version/changelog preparation in [issue #16](https://github.com/mikomiel/privilege-broker/issues/16). Neither issue authorizes a tag, release or deployment.
- Archive only after product acceptance and the project's review gates hold; [issue #14](https://github.com/mikomiel/privilege-broker/issues/14) owns that closeout. Consumer runtime cutover remains separately tracked by its owner.
