<!-- mcp-name: io.github.GuardianVigil-Labs/prufgate -->
<div align="center">
  <img src="https://raw.githubusercontent.com/GuardianVigil-Labs/Prufgate/main/assets/prufgate-icon.svg" alt="PrufGate logo" width="128" />
  <h1>PrufGate</h1>
  <p><strong>Checks whether code, and the tests that claim it works, are real.</strong></p>
  <p>
    <a href="https://github.com/GuardianVigil-Labs/Prufgate/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-green.svg" alt="License: Apache 2.0" /></a>
    <a href="https://pypi.org/project/prufgate/"><img src="https://img.shields.io/pypi/v/prufgate?label=pypi" alt="PyPI version" /></a>
    <img src="https://img.shields.io/badge/Python-3.9%2B-blue" alt="Python 3.9+" />
    <a href="https://scorecard.dev/viewer/?uri=github.com/GuardianVigil-Labs/Prufgate"><img src="https://api.scorecard.dev/projects/github.com/GuardianVigil-Labs/Prufgate/badge" alt="OpenSSF Scorecard" /></a>
  </p>
</div>

Linters check that code compiles. PrufGate looks for code that compiles, passes review at a glance and still does not do the job. This is the kind of code an AI coding agent (or a hurried human) writes to make a task look finished:

- a `catch` block that returns a hard-coded success object;
- a click handler that does nothing;
- a test that asserts `true`, or mocks the very function it tests;
- a `.skip`, `@ts-ignore` or lowered coverage threshold slipped into a diff;
- an import of a package that is not declared anywhere;
- an API route that loads a record by ID without checking who owns it.

PrufGate is deterministic: plain Python, no network calls and no LLM unless you ask for one. It runs in seconds on a pull request, and writes SARIF for code scanning and Markdown for humans. It is meant to sit next to your linters and SAST tools, not replace them.

## The six engines

| # | Engine | What it catches |
|---|---|---|
| 1 | Anti-fabrication (`prufgate/anti_fabrication`) | Canned success on error paths, simulated return values, `MOCK_*`/`SAMPLE_*` data in production code, stub UI handlers, fake "fresh" timestamps, unimplemented stubs, LLM prompts that ask for a verdict without passing any evidence, documentation addresses in production. |
| 2 | Test integrity (`prufgate/anti_reward_hacking`) | Tests with no assertions, assertions that cannot fail, tests that mock the unit under test, swallowed exceptions, assertions deleted or weakened in a diff, production code special-casing a test's literal input. |
| 3 | Diff guard (`prufgate/diff_guard`) | Skips and focus (`.skip`, `.only`, `xit`, `pytest.mark.skip`, `t.Skip()`, `#[ignore]`, `@Disabled`) added without an issue reference, bare suppressions (`@ts-ignore`, `# noqa`, `// nolint`, `#[allow]`), `as unknown as T` casts, weakened linter/CI/coverage settings, and new exemptions in PrufGate's own config. |
| 4 | Contract guard (`prufgate/contract_guard`) | Imports not declared in `package.json`, `pyproject.toml`/`requirements*.txt`, `go.mod` or `Cargo.toml`; environment variables read without a default and missing from `.env.example`; frontend calls to API routes that do not exist. |
| 5 | BOLA / IDOR (`prufgate/bola`) | Route handlers that look up a record by a client-supplied ID with no auth guard or no tenant/owner scoping, across Express, Next.js, NestJS, FastAPI, Flask, Django, Go (net/http, Gin, Echo, Chi), Spring, Rails and Laravel. Optional live two-token probing of a running service you own. |
| 6 | Diff reviewer (`prufgate/review`) | High-precision rules on changed lines (SQL built from strings, shell injection, disabled TLS verification, hard-coded credentials, unsanitised HTML, ignored Go errors, credential logging), GitHub suggestion blocks, and optional delegation to an AI CLI or API you choose. |

Details, rule IDs, supported languages and known limits for each engine: [docs/ENGINES.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ENGINES.md).

PrufGate uses pattern and structure heuristics, not a full parser for every language. It will miss things and it will sometimes flag correct code. Every finding names its rule, and [inline `prufgate-ignore` comments, exemptions and baselines](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md#suppressing-findings) let you record why.

## Quick start

PrufGate needs Python 3.9 or newer and Git.

```bash
pipx install prufgate     # or: pip install prufgate  (the `prufgate` and `prufgate-mcp` commands)
prufgate --self-check     # every engine against its built-in fixtures
```

Or run the signed container image, which adds the full gate with ast-grep, gitleaks and zizmor:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/guardianvigil-labs/prufgate:1.0.0          # the fast gate on this repository
docker run --rm -v "$PWD:/workspace" ghcr.io/guardianvigil-labs/prufgate:1.0.0 prufgate check .
```

Or add the GitHub Action to a pull-request workflow, pinned to the commit SHA of the `v1.0.0` tag ([full example](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md)):

```yaml
- uses: actions/checkout@<commit-sha>
  with: { fetch-depth: 0, persist-credentials: false }
- run: python3 -m pip install "PyYAML>=6.0"
- uses: GuardianVigil-Labs/Prufgate@<commit-sha-of-v1.0.0>
```

Every release is signed and carries build provenance and an SBOM: [Verify a release](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/SECURITY.md#verify-a-release).

Then, in your project:

```bash
prufgate check .                          # engines 1-5 on the whole repository
prufgate check --changed --base origin/main   # only what this branch changed
prufgate init --hooks                     # starter config + coding-agent hooks
```

Exit codes are the same everywhere: **0** clean, **1** blocking findings (P0/P1), **2** PrufGate could not run (bad config, bad base ref, unreadable file, engine crash). A crash never reads as a pass.

## Ways to run it

| Want | Use |
|---|---|
| A quick check while coding | `prufgate check --changed` |
| One engine | `prufgate test-audit`, `prufgate bola`, `prufgate review` |
| The full gate with SARIF and Markdown reports | `./prufgate.sh fast` (changed files) or `./prufgate.sh full`, from a checkout. Reports go to `reports/prufgate.sarif` and `reports/prufgate-review.md`. |
| A pull-request gate on GitHub | The composite action in this repository: [docs/CI_INTEGRATION.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md) |
| A coding agent sent back to fix its findings before it stops | `prufgate init --hooks` (Claude Code Stop hook, which asks once; Cursor rule; the pre-commit hook and the CI gate enforce) |
| Tools for an agent over MCP | `prufgate mcp`: nine read-only tools |
| A service that scans on webhook | `prufgate api`: bearer token, loopback by default |

The full command and option reference is in [docs/GETTING_STARTED.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/GETTING_STARTED.md), and every configuration key is in [docs/CONFIGURATION.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md).

## Configuration in one look

PrufGate works without configuration. To tune it, add `.prufgate/config.yaml`:

```yaml
version: 1
packs: [core, web-ui, ai-safety]      # cti is an opt-in domain pack
exclude: ["dist/**", "vendor/**"]
auth_guards: [requireUser, get_current_user]
tenant_keys: [organization_id, account_id]
exempt:
  src/legacy/adapter.ts:
    route-canned-fallback: "#104: legacy fallback until the payments API migration"
known_debt:
  stub-click-handler: 0                # a ceiling that can only go down
```

## Documentation

- [Getting started](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/GETTING_STARTED.md): install, commands, reports, exit codes
- [Configuration reference](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md): every key, suppressions, environment variables
- [The engines](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ENGINES.md): rules, languages and limits
- [CI and agent integration](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md): GitHub Action, other CI, agent hooks, MCP, REST API
- [Custom rules](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CUSTOM_RULES.md): your own ast-grep rules and hooks
- [Architecture](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ARCHITECTURE.md)
- [Changelog](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/CHANGELOG.md)

## Contributing and security

Contributions are welcome: see [CONTRIBUTING.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/CONTRIBUTING.md) and the maintainer guide [AGENTS.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/AGENTS.md). Please report vulnerabilities privately, as described in [SECURITY.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/SECURITY.md).

PrufGate is published by GuardianVigil under the [Apache License 2.0](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/LICENSE). The name and logo are trademarks: see [TRADEMARKS.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/TRADEMARKS.md).
