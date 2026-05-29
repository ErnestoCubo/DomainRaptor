# Changelog

## [0.6.1](https://github.com/ErnestoCubo/DomainRaptor/compare/v0.6.0...v0.6.1) (2026-05-29)


### Documentation

* add brand assets, refresh README, ignore social drafts ([7896172](https://github.com/ErnestoCubo/DomainRaptor/commit/789617288f3bf256774505ec1cdf532a3e095453))
* add brand assets, refresh README, ignore social drafts ([fb8c8c0](https://github.com/ErnestoCubo/DomainRaptor/commit/fb8c8c0d7f6415e3b7c2773dcc1d15af9232477c))

## [0.6.0](https://github.com/ErnestoCubo/DomainRaptor/compare/v0.5.0...v0.6.0) (2026-05-29)


### ⚠ BREAKING CHANGES

* Censys now requires PAT token instead of API ID/Secret
* **external-apis:** New environment variables SHODAN_API_KEY, VIRUSTOTAL_API_KEY, SECURITYTRAILS_API_KEY

### Features

* add dev environment and CI/CD infrastructure ([7c0abe3](https://github.com/ErnestoCubo/DomainRaptor/commit/7c0abe3847a0844cee937838bd17f6bb3404152a))
* add exploit intelligence, new discovery sources and TUI screens ([8d7b6d8](https://github.com/ErnestoCubo/DomainRaptor/commit/8d7b6d893ffcf240db6a1ae3dcba219f2c834aa8))
* add ZoomEye and Censys v3 API integrations ([0dfc898](https://github.com/ErnestoCubo/DomainRaptor/commit/0dfc898d3d38109a7a91ea8c008917365238ad88))
* **assess:** implement vulns command with Shodan + NVD enrichment ([bbe4bbd](https://github.com/ErnestoCubo/DomainRaptor/commit/bbe4bbd6b8956a361b62b21e3b68910bbc658882))
* **assessment:** implement Phase 4 - security assessment module ([732d1f0](https://github.com/ErnestoCubo/DomainRaptor/commit/732d1f00ea353ffae34da4eb42a7dfe086a6c201))
* **cli:** implement Typer-based CLI with 5 workflows ([27e9037](https://github.com/ErnestoCubo/DomainRaptor/commit/27e90371d65554eaa62bf314a0790ad1678df60c))
* **discovery:** Phase 3 - Complete discovery clients implementation ([ac3bbbc](https://github.com/ErnestoCubo/DomainRaptor/commit/ac3bbbc1449c4f6ed8aafcaba2061081c4ab08f8))
* DomainRaptor v0.3.0 - Discovery & Assessment modules ([ac1a54b](https://github.com/ErnestoCubo/DomainRaptor/commit/ac1a54b17c8d5caa163e355922a0bd14680c6f16))
* DomainRaptor v0.3.0 - Discovery & Assessment modules ([663d40f](https://github.com/ErnestoCubo/DomainRaptor/commit/663d40f4e01e854f8e9e9408805ae69d7d8da715))
* **external-apis:** implement Phase X1 - Shodan, VirusTotal, SecurityTrails integrations ([b95ba22](https://github.com/ErnestoCubo/DomainRaptor/commit/b95ba2242545b6082d4f9eb49c3b9292a4c75bcf))
* **report:** color-graded score cards, value/max display, tabbed HTML layout ([57a38fc](https://github.com/ErnestoCubo/DomainRaptor/commit/57a38fc857400740f7070eaa65bdfca28f552c4f))
* **tests:** add comprehensive test suite with 88% coverage ([507a131](https://github.com/ErnestoCubo/DomainRaptor/commit/507a1313f259c188499fc808630a5cab8eaae9d6))
* **tui:** add Textual TUI with `domainraptor tui` command ([44b5722](https://github.com/ErnestoCubo/DomainRaptor/commit/44b5722e3dc641c6512c1996fef886ece495338f))
* **tui:** browser-style pretty preview for HTML/MD/JSON/YAML/CSV reports ([35f6e96](https://github.com/ErnestoCubo/DomainRaptor/commit/35f6e96a4cea760ee7d8fde1b529f2cf937fc7ac))
* **tui:** loading UX, clickable dashboard cards, compare conditional args, reports preview ([461dced](https://github.com/ErnestoCubo/DomainRaptor/commit/461dced79d335748757652a29659598e98d5d34a))


### Bug Fixes

* **ci:** add bandit dependency and handle missing SARIF files ([078be99](https://github.com/ErnestoCubo/DomainRaptor/commit/078be9919e6ee8438336fffe2551497f0b5e6b29))
* **ci:** use --extra dev instead of --dev for uv sync ([df50194](https://github.com/ErnestoCubo/DomainRaptor/commit/df50194e5d37ff88fc9ffe04b3dd9190ca4d1b16))
* **cli,discovery:** default --save=True everywhere, NVD-enrich vulns CVEs, drop stray slash in crt.sh URL ([023eb58](https://github.com/ErnestoCubo/DomainRaptor/commit/023eb584b7911ec935a6023ed6c875bf97382ab5))
* **cli:** resolve Typer subcommand conflicts and WHOIS datetime comparison ([3faa7b7](https://github.com/ErnestoCubo/DomainRaptor/commit/3faa7b79bb7dd367194bb58795a9f480b17d71b5))
* **discovery,assess,tui:** CertSpotter fallback for crt.sh, vulns saves by default, compare history target field ([1ebb2df](https://github.com/ErnestoCubo/DomainRaptor/commit/1ebb2dfebf6c7773491f2f57330976bcb339a245))
* **lint:** correct noqa/nosec placement ([9107298](https://github.com/ErnestoCubo/DomainRaptor/commit/9107298cbdc2c003214fe4277464f3838efc1d44))
* **report:** aggregate latest scans per type and align vuln chart total ([5b7e64a](https://github.com/ErnestoCubo/DomainRaptor/commit/5b7e64ac0fcde0e66fdfc3893ab1e24390f2d9fe))
* **report:** handle non-numeric scan_id with proper logging ([9547254](https://github.com/ErnestoCubo/DomainRaptor/commit/9547254c768a0b85c4409cb9513b99fd2c6f31ff))
* **report:** vulnerabilities breakdown card shows raw count instead of capped contribution ([b99a0ee](https://github.com/ErnestoCubo/DomainRaptor/commit/b99a0eee2ddc15af0eb19a1091d3d161c11c3900))
* resolve 34 ruff linting errors ([805715a](https://github.com/ErnestoCubo/DomainRaptor/commit/805715a6bfa0a5f39b8526400b35950153a201d5))
* resolve 4 critical bugs in core modules ([b79ae58](https://github.com/ErnestoCubo/DomainRaptor/commit/b79ae5834218332002e135c55443b2f2f1e7c523))
* **security:** address Bandit findings from PR [#58](https://github.com/ErnestoCubo/DomainRaptor/issues/58) review ([71277fe](https://github.com/ErnestoCubo/DomainRaptor/commit/71277fe64ee74208d6e6e0d8b3b276795e68737a))
* **security:** address Bandit findings from PR [#58](https://github.com/ErnestoCubo/DomainRaptor/issues/58) review ([2d6ba02](https://github.com/ErnestoCubo/DomainRaptor/commit/2d6ba027b758adcfedd5d4598958f48f0a68ec89))
* **security:** resolve ruff S violations exposed by CI scan ([d3d094d](https://github.com/ErnestoCubo/DomainRaptor/commit/d3d094d69f3f033855a283b07761be1ed500ac24))
* **tui,assess:** recon target arg, exploits scan lookup, duplicate Run buttons ([2413b15](https://github.com/ErnestoCubo/DomainRaptor/commit/2413b159534a1f0edca998a24f703650c31c4c3f))
* **tui,discovery:** export CertSpotterClient, improve compare arg2 UX ([8d50eb0](https://github.com/ErnestoCubo/DomainRaptor/commit/8d50eb0cdc8a290d8871830f0d868745d64f118d))
* **tui,discovery:** export CertSpotterClient, improve compare arg2 UX ([7b33b1b](https://github.com/ErnestoCubo/DomainRaptor/commit/7b33b1b353e56596977b74e0a2f2453d4adc40f6))
* **tui:** collapse dead space in TargetForm — fix Horizontal height ([33d8072](https://github.com/ErnestoCubo/DomainRaptor/commit/33d807200bf90f77dffe346e5edc286fb0b65486))
* **tui:** dashboard recent-scans uses dict keys (list_scans returns dicts) ([29838d4](https://github.com/ErnestoCubo/DomainRaptor/commit/29838d40ad3c7e1c605478ea8ba2af758e9e366f))
* **tui:** pressing Enter on inputs triggers run/save action ([b6d14cb](https://github.com/ErnestoCubo/DomainRaptor/commit/b6d14cbf3d05c8adbe13bb00bde69e44fa731f01))
* **tui:** remove inline Run button from TargetForm, add spacing below input ([f710142](https://github.com/ErnestoCubo/DomainRaptor/commit/f710142f6f53d1e1be45df9c2b6988dc16282aa3))
* **tui:** scrollable scan screens + fit reports layout ([cf2537a](https://github.com/ErnestoCubo/DomainRaptor/commit/cf2537a3258fde16e4b5fb568e2d45ba598964c8))
* **tui:** strip ANSI escape codes from subprocess output in RichLog ([d02df4c](https://github.com/ErnestoCubo/DomainRaptor/commit/d02df4cc613803784cb04e2417460996d5cc82c3))
* **tui:** UX improvements based on user feedback ([c86f2f1](https://github.com/ErnestoCubo/DomainRaptor/commit/c86f2f1f06b3c9ac0f542ac75df810dc4495edb4))
* **tui:** widen compare arg label and align validation messages ([76c770e](https://github.com/ErnestoCubo/DomainRaptor/commit/76c770e181333a5dee65d0d7b5baa0409f9d5629))


### Documentation

* add AI integration plan ([74f7bfc](https://github.com/ErnestoCubo/DomainRaptor/commit/74f7bfcaf3a0a962af17632672573f78a129d4e6))
* add issues.md for GitHub project board ([e79b061](https://github.com/ErnestoCubo/DomainRaptor/commit/e79b061e7e9d4e6774d5ca223d55b4ad43a72411))
* update README with complete documentation ([e2861d1](https://github.com/ErnestoCubo/DomainRaptor/commit/e2861d1de11fcf41fbd40aa380c17ca7fed236cb))
* Update roadmap - Phase 5 complete ([5ab3460](https://github.com/ErnestoCubo/DomainRaptor/commit/5ab34601417d651cf00002d7b69c7dde1100ab64))
* update roadmap with Phase 3-4 completion status ([17399ff](https://github.com/ErnestoCubo/DomainRaptor/commit/17399ffbf6bea739f1c85e74cc43cc73bee6abba))
* **wiki:** document exploit enrichment, recon, enrich, TUI, risk algorithm ([1ed2bc8](https://github.com/ErnestoCubo/DomainRaptor/commit/1ed2bc8875b2033c22ad29f5cb625168d2e5bfd1))


### Code Refactoring

* reorganize project structure ([b2c96f6](https://github.com/ErnestoCubo/DomainRaptor/commit/b2c96f6d3ccb0ec59fbdc6a6da4b50b5a8f85a9b))
* reorganize project structure ([07f3f77](https://github.com/ErnestoCubo/DomainRaptor/commit/07f3f771acb159091a266d5545e5be44642b89d0))
