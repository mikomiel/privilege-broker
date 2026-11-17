# Changelog

## [0.2.1](https://github.com/mikomiel/privilege-broker/compare/v0.2.0...v0.2.1) (2026-11-17)


### Bug Fixes

* **dispatcher:** bound child output capture at the pipe ([fd6a613](https://github.com/mikomiel/privilege-broker/commit/fd6a6135fdeade91a0ae7e0c2dfc140809535a39))
* **dispatcher:** bound child output capture at the pipe ([d2a8e49](https://github.com/mikomiel/privilege-broker/commit/d2a8e4964859cb553875f50ce8b674e81f41c43c))
* **dispatcher:** keep strict decoding and handle capture faults ([de783d2](https://github.com/mikomiel/privilege-broker/commit/de783d2b1bb9ae8bc54bf387b405e87607d1ff56))

## [0.2.0](https://github.com/mikomiel/privilege-broker/compare/v0.1.0...v0.2.0) (2026-11-15)


### Features

* **pve:** add the typed dispatcher and durable claim store ([2fc7b5f](https://github.com/mikomiel/privilege-broker/commit/2fc7b5f4466dcd2b0871c3d8bbdecddd64bcdc70))
* **pve:** add the typed dispatcher and durable claim store ([bc9fc39](https://github.com/mikomiel/privilege-broker/commit/bc9fc39a52f82f6a7a430da8e388f2ec21d3626c))
* **pve:** dispatch policy-bounded snapshot pruning ([879cdeb](https://github.com/mikomiel/privilege-broker/commit/879cdeb5476474f60f57a89178b626985ea07ba6))
* **pve:** dispatch policy-bounded snapshot pruning ([af2a688](https://github.com/mikomiel/privilege-broker/commit/af2a688a6d199dd6bdef6ed5b6b5d96c0a6a4507))


### Bug Fixes

* **pve:** accept file stdin and normalise decoder recursion ([9ad73fe](https://github.com/mikomiel/privilege-broker/commit/9ad73fe7e950974d0a93f2ee9034cf686e7e6885))
* **pve:** bound prune replies, replay unknown reports and serialize migration ([3a03955](https://github.com/mikomiel/privilege-broker/commit/3a03955237e02379bc07c9f4ce891b902dacdaa9))
* **pve:** bound request intake and survive undecodable output ([4c417b5](https://github.com/mikomiel/privilege-broker/commit/4c417b57973081ae1b835df57c0a0f06b651ad18))
* **pve:** bound uncertain prune replies and drop stale status text ([50ee2cd](https://github.com/mikomiel/privilege-broker/commit/50ee2cdeace55837bf26d877ab3a2fb75f6c34c4))
* **pve:** carry dispatcher uncertainty into the worker result ([a353373](https://github.com/mikomiel/privilege-broker/commit/a353373e5d6f71a9f88e6c6680ee7ebec5f84078))
* **pve:** guard claim-store construction and prove claim retention ([dee44bc](https://github.com/mikomiel/privilege-broker/commit/dee44bc1357976f1e520efcf789a1146bede02ec))
* **pve:** guard prune failures and persist the structured report ([ed44fc1](https://github.com/mikomiel/privilege-broker/commit/ed44fc190059160a7e373437b7e3d0ae1888ddbd))
* **pve:** handle non-pipe stdin and interpreter-depth refusals ([b94233b](https://github.com/mikomiel/privilege-broker/commit/b94233bbf76506742e98410189bb5b9f27b44cf7))
* **pve:** keep DST-ambiguous snapshots inside retention ([c5bf986](https://github.com/mikomiel/privilege-broker/commit/c5bf98659401f61c656794aaeac02fbcb0a3107c))
* **pve:** keep the bounded prune report in the worker result ([b2007fe](https://github.com/mikomiel/privilege-broker/commit/b2007fe8e7c5119463e307430c8fdf599ca29bf4))
* **pve:** make claims crash-durable and scope dispatch exclusivity ([b1cef6a](https://github.com/mikomiel/privilege-broker/commit/b1cef6a92a9339b968bd66a8f7def302bce220eb))
* **pve:** retry the claim schema bootstrap against a short lock ([d341b88](https://github.com/mikomiel/privilege-broker/commit/d341b888e7946e2f25c835ecf7ae4bbacb73157f))
* **pve:** retry the claim schema bootstrap within one budget ([7128617](https://github.com/mikomiel/privilege-broker/commit/7128617e359d54810bdd6f57469bf6db12b2b7e5)), closes [#37](https://github.com/mikomiel/privilege-broker/issues/37)
* **pve:** scope dispatch to one host and report persistence faults ([79c37b1](https://github.com/mikomiel/privilege-broker/commit/79c37b17eb700fbed6ea8af9ec853c1e2e5ec324))
* **release:** let release-please tag and publish GitHub Releases ([7c985eb](https://github.com/mikomiel/privilege-broker/commit/7c985ebfb3279687fbd307ea018093561f8d4f23))
* **release:** let release-please tag and publish GitHub Releases ([ca3cacb](https://github.com/mikomiel/privilege-broker/commit/ca3cacb68da3aa11d77191046bcfd77b876458ea))

## 0.1.0 (2026-11-14)


### Features

* **pve:** add agent-facing approval/execution status contract ([3313f3d](https://github.com/mikomiel/privilege-broker/commit/3313f3de593a9427568b38b7a624a18f94468c03))
* **pve:** add agent-facing approval/execution status contract ([ccd5b20](https://github.com/mikomiel/privilege-broker/commit/ccd5b20b9b82c98e966f244322bf11b295921c2d))
* **pve:** extract agent bridge, client and execution worker ([28f5cb4](https://github.com/mikomiel/privilege-broker/commit/28f5cb45f493681874900f0445ddadb0983ab37d))
* **pve:** extract agent bridge, client and execution worker ([1c9cd7a](https://github.com/mikomiel/privilege-broker/commit/1c9cd7a0302425a6a64d77a9938d6b6bf244e144))
* **pve:** extract authorization foundation and align GitHub tooling ([e76d605](https://github.com/mikomiel/privilege-broker/commit/e76d6054b1b6980697fb5b6cf8c9418074c2c08b))
* **pve:** extract authorization foundation and GitHub baseline ([db31577](https://github.com/mikomiel/privilege-broker/commit/db3157720f2148a78fce6d1c0f45a168037b44f1))
* **pve:** extract WebAuthn approval service and notifications ([f6d85ca](https://github.com/mikomiel/privilege-broker/commit/f6d85ca00c35009dcd477518992f32d68a972288))
* **pve:** extract WebAuthn approval service and notifications ([9c91ae7](https://github.com/mikomiel/privilege-broker/commit/9c91ae7e3202000ddd1f6c97bc61e180718f11b0))


### Bug Fixes

* **pve:** bound worker capture and format safe errors ([73d43f4](https://github.com/mikomiel/privilege-broker/commit/73d43f412fb6e54d55a540f57fca5704e423f102))
* **pve:** bound worker capture and format safe errors ([5cc4922](https://github.com/mikomiel/privilege-broker/commit/5cc4922dfc280e7f367a7527f9a659a11369fc5a))
* **pve:** classify bounded response framing and decoder failures ([ac32699](https://github.com/mikomiel/privilege-broker/commit/ac326997771222401b4dc12c156f5752603cfeba))
* **pve:** close broker client and worker failure paths ([24e311a](https://github.com/mikomiel/privilege-broker/commit/24e311a5ac171f7acddbba9477a89f79bf10ce40))
* **pve:** enforce fresh deadlines across locked state transitions ([41e59e0](https://github.com/mikomiel/privilege-broker/commit/41e59e0b52f0796d0986b7af92260947f7d64cd7))
* **pve:** guard authority at the SQLite commit boundary ([9d28355](https://github.com/mikomiel/privilege-broker/commit/9d283558e3f26d7fce3f974c750c669c9198c767))
* **pve:** handle truncated replies and publish results atomically ([fde9db8](https://github.com/mikomiel/privilege-broker/commit/fde9db8e12cba0bf1996165931e539d6f8473b7b))
* **pve:** keep approval data outside executable script context ([533ee21](https://github.com/mikomiel/privilege-broker/commit/533ee2148205b69e7d833fce02f9aae92546f057))
* **pve:** revalidate certificate deadlines under the issuance lock ([672aeae](https://github.com/mikomiel/privilege-broker/commit/672aeaefc56d13d466db6619dad85119f25a4e99))

## Changelog

No product release has been published.

Release-please will propose version and changelog changes in a release PR.
See [the release process](docs/releases.md) for the separate publication gate.
