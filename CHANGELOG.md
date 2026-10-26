# Changelog

All notable changes to PrufGate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Inline ignores need a reason:** `prufgate-ignore: rule -- why`. An ignore without one (at least three characters) no longer suppresses and is reported as `ignore-without-reason`. Every honoured ignore is listed in the report and as a SARIF suppression. An ignore now hides only the rules it names, in every engine.
- **With a base ref, the configuration and baseline are read from the base:** a change to `.prufgate/config.yaml` takes effect after it is merged, and the change itself is reported (`prufgate-config-not-applied`). If the base config is rejected by this version, the branch's config is used and compared with the defaults (`prufgate-config-base-invalid`).
- Review rule IDs are normalised to `pr-` plus lowercase letters, digits and hyphens, the same in Markdown and SARIF.
- `linter-or-ci-config-weakening` compares linter configs (ruff, mypy, tsconfig, eslint, biome, golangci) by value with the base, so new per-file ignores, excludes, disabled rules and shrunk `select` lists are caught wherever they sit in the file.

### Added
- Fuzz targets for the config loader, the diff parsers and the source and test scanners (`fuzz/`), run by ClusterFuzzLite on pull requests.
- Each release attaches `<file>.intoto.jsonl` with the wheel's and sdist's signed attestations, for offline verification.
- Test-cheat rules in the diff: `test-fake-exit` (an exit or module-level skip added to tests, conftest or test setup), `diff-test-file-deleted` (including a rename to a name the test runner doesn't collect) and `diff-test-count-drop`.
- `prufgate shell-guard` and `prufgate hook <agent> <event>`: fail-closed hooks for Claude Code, Cursor, GitHub Copilot, Codex and Gemini CLI. They block skipping git hooks (`--no-verify`, `core.hooksPath`, `HUSKY=0`), force pushes, and removing or editing tests, CI files, PrufGate's config or the agents' own hook config. `prufgate init --agent NAME` writes the hook configuration.
- `.pre-commit-hooks.yaml`: `prufgate` (staged changes, pre-commit) and `prufgate-full` (pre-push).
- A confidence level (high, medium, low) on every rule and finding, in JSON, Markdown and SARIF (`precision`). Low-confidence rules are off unless `enable_low_confidence: true`.
- An opt-in registry check for newly added dependencies (`registry_check: true`): `dependency-not-on-registry`, `dependency-recently-published` and `dependency-typosquat` for npm, PyPI, crates.io and Go modules, with a local cache. It fails closed when a lookup fails, unless `offline_ok` is set.
- Stable SARIF `partialFingerprints` (GitHub's `primaryLocationLineHash`), so code scanning tracks an alert across commits.
- Test-harness rules in the diff: `test-runner-monkeypatch`, `always-true-equality`, `pytest-result-rewrite`, `pytest-collection-deselect`, `test-config-weakening` and `test-script-neutered`.
- `prufgate verify --differential`: runs the base branch's tests against the head code in a temporary worktree and reports `differential-base-tests-fail`. It executes repository code, so it runs only with `--allow-run-tests` (or `PRUFGATE_ALLOW_RUN_TESTS=1`), with a scrubbed environment and a timeout.
- `undocumented-env-var-drift` also counts variables declared in zod and pydantic-settings schemas, docker-compose, Kubernetes and Helm manifests, and workflow `env:` blocks.
- `prufgate init --agents-md` and `--bugbot` write a marked section telling other agents and AI reviewers to use PrufGate's findings.
- A Claude Code plugin: `/plugin marketplace add GuardianVigil-Labs/Prufgate`, then `/plugin install prufgate@prufgate`.
- GitLab Code Quality and JUnit reports: `--format gitlab|junit`, and `reports/gl-code-quality-report.json` and `reports/prufgate-junit.xml` from the batteries.
- `prufgate check --ai-adjudicate`: an AI provider judges only low-confidence findings (yes/no) and can only dismiss them. It runs only when the base config enables `ai_adjudicate`. Never runs from the hooks, the MCP server or the API. Errors keep the finding.
- `prufgate bench`: a labelled corpus of 90 invented cases with measured precision and recall (`docs/BENCHMARK.md`).
- `prufgate bola --routes-from FILE`: extra route paths for the live probe from an OpenAPI, Postman or HAR file (GET and HEAD only, joined onto `--url`; hosts, headers and credentials in the file are ignored).
- BOLA static checks cover Laravel implicit route-model binding, tenant values traced through local variables, Django generic views and DRF viewsets, NestJS global guards, Spring global and method security, Express/Fastify app-wide middleware and Rails member routes. `bola.global_tables` lists tables shared by every tenant.
- `prufgate.pyz`: a reproducible single-file build (Python 3.9+), signed and attached to each release.

### Fixed
- `test-input-special-casing` no longer treats dunder names such as `__main__` as test input.
- A `.prufgate/config.yaml` with a non-string top-level key (for example a bare `?`) crashed with a `TypeError` instead of a configuration error. Found by fuzzing.

### Security
- The live BOLA probe refuses cloud-metadata, link-local and non-HTTP targets on every path (CLI, batteries, MCP, API and running the engine directly).
- The container's base images are pinned by digest, and every `pip install` in the image and the workflows uses hash-locked requirements.
- The container and fuzz builds use setuptools 84.2.1 (CVE-2026-59890, GHSA-xmj3-9gf7-h52w), and install PrufGate from a locally built wheel.

## [1.0.0]

The first public release: six verification engines (anti-fabrication, test integrity, diff guard, contract guard, BOLA/IDOR and diff review), the `prufgate` CLI, a GitHub Action, an MCP server, coding-agent hooks and a container image. The Changed, Fixed and Security entries are against the pre-release development versions.

Distribution: `pip install prufgate` (or `pipx install prufgate`), the image `ghcr.io/guardianvigil-labs/prufgate:1.0.0`, and the Action `GuardianVigil-Labs/Prufgate@v1.0.0`. Releases are built from a tag by `.github/workflows/release.yml`: PyPI Trusted Publishing, a keyless Sigstore signature on the image, SLSA build provenance and an SBOM for the wheel and the image (see "Verify a release" in `SECURITY.md`).

### Added
- `prufgate` CLI (`check`, `fast`, `full`, `test-audit`, `bola`, `review`, `init`, `mcp`, `api`, `--self-check`, `--version`) and `.prufgate/config.yaml`.
- Test-integrity analysis for PHP, C# and Ruby, and canned-error rules for Java, Kotlin, C#, PHP and Ruby.
- Diff-guard rules `coverage-threshold-lowering` and `prufgate-config-self-exemption`.
- BOLA analysis of Rails and Laravel controllers, Sequelize and Mongoose lookups, and per-handler auth checks.
- A structural leak guard (`tests/test_public_repo_hygiene.py`) and workflow pin checks (`tests/test_workflows.py`).
- The PrufGate logo in `assets/`, in the shared GuardianVigil open-source tile and blue (`#05070a` tile, `#1d232d` hairline, `#2f80ff` glyph): the code-shield icon (SVG, with thicker variants for 16 and 32 pixels, and PNGs from 16 to 1024), the mark on its own for dark and light backgrounds, a lockup with the wordmark, and a 1280x640 social preview.

### Changed
- Exit codes are the same everywhere: 0 clean, 1 P0/P1 findings, 2 error. The BOLA engine, the contract guard and the reviewer used to exit 0 on findings.
- Threat-intelligence rules moved to the opt-in `cti` pack.
- Two architecture-specific ast-grep rules became opt-in examples in `configs/ast-grep/examples/`.
- Container downloads are pinned and checksum-verified.
- Workflows publish only from a version tag or a manual run, and every action is pinned to a commit SHA.
- The `multi-tenant` pack is removed: no engine read it. A config that still lists it is rejected; Engine 5 always runs.
- The container image no longer installs `curl`; the docs state its real size (about 460 MB, about 100 MB gzipped).
- The container runs Python 3.14 (newest stable series with PyYAML wheels; 3.15 has none yet).

### Fixed
- Test-input special-casing no longer reads version pins in requirements, lock and other data files as production branches.
- The gate, CLI, MCP server and API reported success when an engine crashed or wrote no output. They now report an error (exit 2).
- `--changed` scanned nothing on a clean CI checkout, and missed untracked files.
- Path filters matched substrings, so folders such as `checkout/`, `contest/` or a checkout under `build/` were skipped.
- Live BOLA tokens appeared in report `curl` examples.
- The PR reviewer could emit injected workflow commands, and comment-only suggestions that deleted code.
- Python 3.9 compatibility, and standard-library modules flagged as undeclared imports on 3.9.
- In the changed scope the contract guard read only uncommitted files or the last commit; it now uses the same base ref as the other engines, from `prufgate check`, the gate and the MCP tool.

### Security
- The diff guard compares the configuration in effect on the branch with the one in effect at the base, by value, so no YAML spelling, file location, shadowing config or `.gitattributes` can hide a change. A new exclusion, exemption, known debt or raised ceiling, a dropped pack, a narrowed language list or a widened guard list is a P1 `prufgate-config-self-exemption` finding; an exclusion covering every file or the configuration itself (`**`, `.prufgate/**`) is P0. The configuration under review cannot exclude, exempt or set a debt ceiling for that finding. A branch could previously switch PrufGate off with `exclude: ["**"]` and pass. Diffs are read with `--text --no-ext-diff --no-textconv`.
- The scanned repository's `.prufgate/hooks/` scripts no longer run by default (`PRUFGATE_ALLOW_REPO_HOOKS=1` opts in).
- Arguments that start with `-` are refused as git refs.
- `review --ai` runs local agent CLIs one-shot, with the least tool access each offers, in a fresh private directory, with the diff on stdin; `auto` picks only `claude` (every tool off). An AI review that did not run is reported on stderr.
- Live BOLA probes follow redirects only within the target origin. A redirect to another origin is not followed and is reported as `BOLA-PROBE-REDIRECT-REFUSED` (P1), so untested routes never pass silently.
