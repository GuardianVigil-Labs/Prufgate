# The engines

Each engine can run alone (its module has a command line and a `--self-check`), through `prufgate check`, or as a step of the `prufgate.sh` gate. Every rule has invented positive and near-miss fixtures in its engine's self-check or in `tests/`.

All engines use pattern and structure heuristics over source text, not a compiler front end for each language. That keeps PrufGate fast and dependency-free, and it means two things: an unusual code shape can slip past a rule, and correct code can occasionally be flagged. Report either with a minimal invented sample (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

Suppressions, exemptions and baselines are described in [CONFIGURATION.md](CONFIGURATION.md#suppressing-findings). Every engine reads inline `prufgate-ignore` comments the same way: one honours only an ignore that carries a reason (`-- why`), the report lists each one it honoured, and an ignore without a reason is reported as `ignore-without-reason` (P2) while the finding it names stays.

Every rule has a confidence (`high`: an exact structural match; `medium`: a heuristic with known false positives; `low`: a fuzzy or naming-based heuristic), shown in the tables below. Low-confidence rules are off by default: not reported and not blocking until `enable_low_confidence: true` (see [CONFIGURATION.md](CONFIGURATION.md#confidence)).

## Engine 1: anti-fabrication

`prufgate/anti_fabrication/detector.py`. Production code that compiles but fakes its result. Test files, fixtures and build output are skipped.

Languages: TypeScript, JavaScript (including `.vue` and `.svelte`), Python, Go, Rust, Java, Kotlin, PHP, Ruby, C#. Not every rule applies to every language; error-path rules cover all of them.

| Rule | Confidence | What it flags |
|---|---|---|
| `canned-error-fallback` | medium | A `catch` / `except` / `rescue` / `if err != nil` that returns a hard-coded success value. |
| `route-canned-fallback` | medium | An API route that answers a failed upstream call with canned data. |
| `unhandled-empty-catch` | medium | An error swallowed with nothing done about it. |
| `verdict-on-error-path`, `score-on-error-path` | medium | A decision or score produced on an error path. |
| `score-outside-scoring` | medium | A score computed outside the files listed in `score_owners`. |
| `simulated-return-value` | medium | A literal returned under a comment admitting it is simulated or a placeholder. |
| `fake-named-data` (`demo-named-data`) | low | `MOCK_*`, `FAKE_*`, `DUMMY_*`, `SAMPLE_*`, `fallbackData` and similar in production code. |
| `synthetic-delay-mock` | medium | A sleep or timer paired with a hard-coded result, faking asynchronous work. |
| `stub-click-handler`, `disconnected-form-submit` | high | UI handlers that do nothing, or a submit that only calls `preventDefault()` (pack `web-ui`). |
| `always-current-fake-timestamp`, `invented-event-timestamp` | medium | "Now minus a fixed offset" computed at read time, so static data looks fresh. |
| `asserted-state` | low | A status literal asserted rather than derived. |
| `unimplemented-production-stub` | high | `NotImplementedError`, `todo!()`, `panic("not implemented")`, `throw new Error("TODO")` in reachable code. |
| `prompt-invents-finding` | medium | An LLM call asked for a structured decision (score, verdict, severity) with no runtime evidence in the prompt (pack `ai-safety`). |
| `documentation-ip-or-domain` (`documentation-address`) | high | RFC 5737 / RFC 3849 addresses or `example.com` served from production code. |
| `stale-exemption`, `debt-ceiling-breached` | high | Config hygiene: an exemption that matches nothing, or a `known_debt` ceiling exceeded. |

Opt-in pack `cti` (threat-intelligence products): `zero-jarm-as-fingerprint` and `empty-input-digest-as-sample` (high); `hardcoded-cve`, `hardcoded-attribution`, `ui-verdict-literal`, `substring-decides-verdict` and `llm-generated-intel` (medium); `keyword-selected-attribution` (low).

## Engine 2: test integrity

`prufgate/anti_reward_hacking/test_integrity.py`. Tests that cannot fail, which is how an agent turns a red build green without fixing anything.

Languages and frameworks: Python (pytest, unittest), JavaScript/TypeScript (Jest, Vitest, Mocha, node:test, Playwright), Go (`testing`), Rust (`#[test]`), Java/Kotlin (JUnit), PHP (PHPUnit, Pest), C# (xUnit, NUnit, MSTest), Ruby (RSpec, Minitest).

| Rule | Confidence | What it flags |
|---|---|---|
| `zero-assertion-test` | medium | A test that runs code and asserts nothing. Pytest fixtures named `test_*` are not tests. |
| `tautological-assertion` | high | `assert True`, `expect(true).toBe(true)`, `assertEqual(x, x)`, or an existence check as the only assertion. |
| `self-mocked-unit-under-test` | medium | A test that mocks the module it is testing, or asserts a mock's own return value. |
| `caught-and-ignored-test-exception` | medium | A test that catches the failure it should report. |
| `snapshot-blind-update-or-empty` | high | Empty inline snapshots, or snapshots updated without review. |
| `diff-assertion-weakening` | medium | A diff that deletes assertions or widens what is accepted (for example `== 200` becoming `in (200, 500)`). |
| `test-input-special-casing` | medium | A diff where production code gains a branch for the exact literal a test passes in. |
| `diff-test-file-deleted` (P1) | high | A diff that deletes a test file whose tests are not added back anywhere. A git rename is not a deletion, nor is a file whose test names all reappear in another file (or, for languages whose test names are not read, a new test file of the same name). |
| `diff-test-count-drop` (P1) | medium | A diff that removes more test cases than it adds, counted across every file: Python `def test_*` (functions and unittest methods), JavaScript/TypeScript `it(`/`test(` with a string title, Go `func Test*` (not `TestMain`). A test that is renamed or moved to another file keeps the count. Tests in a deleted file already reported by `diff-test-file-deleted` are not counted twice. |

The two removal rules see only the diff. When a removal is intended (the feature is gone, or tests were merged into a parametrised one), acknowledge it with an `exempt` entry for the path and rule, with a reason; engine 3 reports the new exemption as `prufgate-config-self-exemption`, so the reviewer sees it. Remove the entry once the change has merged:

```yaml
exempt:
  - { path: tests/test_refunds.py, rule: diff-test-file-deleted, reason: "#42: refunds feature removed" }
```

## Engine 3: diff guard

`prufgate/diff_guard/tamper_detector.py`. Works on a diff (`--changed`, `--base REF` or `--diff-file`), so it sees only what was added. It is language-independent where it can be.

| Rule | Confidence | What it flags |
|---|---|---|
| `test-skip-smuggling` | high | Skips and focus added without an issue reference: `.skip`/`.only`/`xit`/`xdescribe`, `this.skip()`, `t.skip()`, `pytest.mark.skip`/`xfail`, `unittest.skip`, `t.Skip()`, `#[ignore]`, `@Disabled`, `[Fact(Skip=...)]`, `[Ignore]`, `markTestSkipped`, RSpec `xit`. |
| `test-fake-exit` (P0) | high | An exit with status 0 added to a test file, `conftest.py`, a Jest/Vitest/Playwright/Mocha setup or config file, or any code file under a `tests`/`test`/`__tests__`/`spec` folder, which makes the run report success without running the tests: Python `sys.exit(0)`, `os._exit(0)`, `exit()`/`quit()`, `raise SystemExit`, `pytest.exit(returncode=0)`, or an unindented `raise SkipTest` / `pytest.skip(...)` (honours an issue reference); JavaScript/TypeScript `process.exit(0)`; Go `os.Exit(0)` (for example in `TestMain` in place of `os.Exit(m.Run())`). Not flagged: a non-zero or computed status (`sys.exit(main())`), exits under `if __name__ == "__main__":`, exits a test expects (`pytest.raises(SystemExit)`, `assertRaises(SystemExit)`, `expect(...).toThrow()`), and files outside the test tree. |
| `suppression-comment-smuggling` | high | `@ts-ignore`, `@ts-expect-error`, `eslint-disable`, `biome-ignore`, `# noqa`, `# type: ignore`, `// nolint`, `#[allow(...)]`, `@SuppressWarnings`, `prufgate-ignore`, added without a justification (`-- reason`) or issue reference. |
| `unsafe-type-cast-cascade` | high | `as unknown as T`, `as any`, `cast(Any, ...)`, unjustified `unsafe` blocks. |
| `linter-or-ci-config-weakening` | medium | `"strict": false`, rules turned off, `continue-on-error: true`, and similar in linter, compiler and CI config. |
| `coverage-threshold-lowering` | high | A lowered `fail_under` or Jest/Vitest coverage threshold. |
| `prufgate-config-self-exemption` | high | The configuration in effect loosened compared with the base, compared by value (any YAML spelling, location or shadowing file): new exclusions, exemptions, known debt or higher ceilings, dropped packs, fewer languages, more auth guards, tenant keys, score owners or evidence markers, low-confidence rules or the registry check turned off, or `registry_check.offline_ok` turned on (P1); an exclusion covering every file or the config itself, such as `**` (P0). The config under review cannot exclude, exempt or set a debt ceiling for this finding. Without a base (a diff file), the diff lines of the config are checked instead. With a base ref the branch's config is not applied at all (every engine uses the base's), and the finding says so. |
| `prufgate-config-not-applied` | high | P2, informational: with a base ref, the change edits or introduces the PrufGate configuration or baseline. The run applied the base's (or the defaults) and ignored the branch's: configuration changes take effect after merge. |
| `prufgate-config-base-invalid` | high | P2, informational: this version rejects the configuration at the base, so the run applied the branch's (which must be valid). The diff lines of the configuration are still checked. |

An issue reference is `#123`, `ABC-123` or an issue URL. Acronyms such as `UTF-8` and `SHA-256` do not count.

## Engine 4: contract guard

`prufgate/contract_guard/`. Things that look plausible in a diff but do not exist.

| Rule | Confidence | What it flags |
|---|---|---|
| `undeclared-or-hallucinated-import` | medium | An import of a package declared in none of `package.json`, `pyproject.toml` (dependency tables only), `requirements*.txt` / `requirements/`, `go.mod`, `Cargo.toml`. Standard-library modules, relative imports and local packages are not flagged. A hallucinated or typo-squatted name is how a malicious package gets installed. |
| `undocumented-env-var-drift` | high | `process.env.X`, `os.environ["X"]` / `os.getenv("X")` without a default, `os.Getenv("X")`, `env!("X")`, when `X` is missing from `.env.example` (or `.env.sample`, `.env.template`). |
| `frontend-backend-route-mismatch` | medium | `fetch("/api/...")` / `axios.*("/api/...")` to a path that no backend route or OpenAPI spec defines. |

The import check runs only for ecosystems that have a manifest in the repository. In the changed scope it reads the same changed files as the other engines: the diff against the chosen base ref, plus untracked files.

### Registry check for new dependencies (opt-in)

An import of a package that the agent also added to the manifest passes the import check, even when the name was hallucinated. With `registry_check: true` in the configuration (or `PRUFGATE_REGISTRY_CHECK=1`), engine 4 compares the manifests at the base ref (the merge base with `--base` / `PRUFGATE_BASE_REF`, otherwise `HEAD`) with the working tree, and looks up each newly added name on its public registry:

| Rule | Severity | Confidence | What it flags |
|---|---|---|---|
| `dependency-not-on-registry` | P0 | high | The registry has no such package (or an npm package that was unpublished, or a PyPI project with no files). An attacker can register the name and wait for the install. |
| `dependency-recently-published` | P1 | medium | The first release is younger than `max_age_days` (default 30). npm, PyPI and crates.io only: the Go module proxy gives no cheap first-release date. |
| `dependency-typosquat` | P1 | medium | The name differs from a popular package only in `-`, `_` or `.`, or by one edit (two for names of 8 characters or more; swapping two neighbouring letters counts as one). Names under 4 characters are not compared. |

Manifests read: `package.json` (registry versions only, not `file:`, `git`, `workspace:` or `user/repo`; an `npm:` alias is looked up under the name it installs), `pyproject.toml` and `requirements*.txt` (not URLs or `name @ url` references), `Cargo.toml` (not `path`, `git` or `workspace = true` dependencies), `go.mod` (`require` lines).

| Ecosystem | Lookup |
|---|---|
| npm | `https://registry.npmjs.org/<name>`: 404 means missing; `time.created` is the first release. |
| PyPI | `https://pypi.org/simple/<name>/` with `Accept: application/vnd.pypi.simple.v1+json` (the JSON API's `releases` key is deprecated): 404 means missing; the oldest file `upload-time` is the first release. |
| crates.io | `https://crates.io/api/v1/crates/<name>` with a `User-Agent`, at most one request a second: 404 means missing; `crate.created_at` is the first release. |
| Go | `https://proxy.golang.org/<module>/@v/list` (upper case escaped as `!` + lower case): 404 or 410 means missing. |

Network policy:

- **Off by default**, because it needs the network and PrufGate also runs air-gapped.
- Fixed HTTPS hosts only, redirects only to HTTPS, no credentials, a 10-second timeout, and at most `max_lookups` (default 50) lookups per run; more new names than that stop the run.
- **Fails closed.** A lookup that fails (network error, rate limit, 5xx, an answer that cannot be read) stops engine 4 with exit 2, unless `offline_ok: true`, which prints the names it could not check and goes on.
- Results are cached for 24 hours in `$XDG_CACHE_HOME/prufgate/registry.json` (default `~/.cache/prufgate/registry.json`); the cache is never written inside the scanned repository, and a cache that cannot be written is skipped.
- It needs a git repository and a usable base: without one the run stops with exit 2.

The popular-name list is short and bundled in `prufgate/contract_guard/registry_check.py`, hand-picked from the top of each registry's public download rankings (npm, the top-pypi-packages list for PyPI, crates.io sorted by downloads) and widely used Go modules. Engine 3 reports a diff that turns the check off or sets `offline_ok` (`prufgate-config-self-exemption`).

## Engine 5: BOLA / IDOR

`prufgate/bola/bola_engine.py`. Broken object-level authorisation: a handler loads a record by an ID the client controls, without checking that the caller may see it.

Static analysis discovers routes in OpenAPI specs, Express/Fastify, NestJS, Next.js (App and Pages router, server actions), FastAPI, Flask, Django function views, Go (net/http, Gin, Echo, Chi), Spring, Rails controllers and Laravel controllers. Each handler is checked on its own, up to the next route:

- **missing auth**: no recognised guard in the handler, and no file-wide middleware (`router.use`, `before_action`, a class-level guard);
- **unscoped access** (`static-bola-unscoped-access`): a lookup such as `findUnique`, `findById`, `findByPk`, `get_object_or_404`, `find(params[:id])` keyed by request input, with no tenant key or caller identity inside the lookup and no explicit ownership comparison. A tenant ID taken from the URL alone does not count, because the caller chooses it.

| Rule | Confidence | What it flags |
|---|---|---|
| `static-bola-unscoped-access` | medium | A route handler with missing auth or an unscoped lookup, as above. |
| `BOLA-UNGUARDED-SERVER-ACTION` | medium | A Next.js server action with no recognised guard. |
| `BOLA-TABLE-MISSING-TENANT-COLUMN` | low | A `CREATE TABLE` in a migration with no tenant or owner column. |
| `BOLA-UNAUTHENTICATED-ACCESS`, `BOLA-CROSS-TENANT-ACCESS` | high | Live probing: a response that leaks without a token or across tenants. |
| `BOLA-PROBE-REDIRECT-REFUSED` | high | Live probing: a redirect to another origin, not followed. |

Add your own guards and tenant keys with `auth_guards` and `tenant_keys`.

Known gaps, tracked in the issue list: Laravel implicit route-model binding, values passed through intermediate variables, Django class-based views and DRF viewsets, middleware registered in another file, and custom Rails member actions.

**Live probing** (optional, only against systems you are authorised to test) sends each discovered route as an unauthenticated request, as user A, and as user A for user B's resource (and the reverse). It reports responses that leak across tenants, with `curl` reproductions that use `$PRUFGATE_TOKEN_A` / `$PRUFGATE_TOKEN_B` placeholders. Redirects are followed only within the target's origin; a redirect elsewhere is not followed, so the tokens never leave that origin, and is reported as `BOLA-PROBE-REDIRECT-REFUSED` (P1). See [GETTING_STARTED.md](GETTING_STARTED.md#live-bola-probing).

## Engine 6: diff reviewer

`prufgate/review/reviewer.py`. Reviews changed lines only.

Deterministic rules (default, offline):

| Finding | Severity | Confidence |
|---|---|---|
| SQL injection vector (query built from string interpolation) | P0 | medium |
| Hard-coded credential | P0 | medium |
| Shell command injection risk | P0 | medium |
| Disabled TLS certificate verification | P1 | high |
| Unsanitised HTML injection (XSS) | P1 | medium |
| Credential logged to the console | P1 | low |
| Server action without an authorisation guard | P1 | medium |
| Ignored Go error return, unbounded goroutine spawn | P2 | low |

It also folds in the diff findings of engines 1 to 4. Output formats: `markdown`, `json`, `sarif`, `github` (workflow annotations, with every field escaped) and `reviewdog`. Suggestion blocks are emitted only when they are valid replacement code, never comment-only. It exits 1 on a P0/P1 finding, and 2 when no diff can be read (no repository, or a base ref that does not exist).

`--ai` (optional) sends the changed hunks to a provider you choose: an API (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST`, model in `PRUFGATE_AI_MODEL`) or a local agent CLI. The model's output is treated as untrusted: a comment must point at a line the diff adds, and suggestions are validated like the deterministic ones. API keys are never printed, and provider errors are redacted. Sending code to a provider is your decision; the default mode sends nothing anywhere. The diff can carry prompt injection, so local agent CLIs get it on stdin and run one-shot with the least tool access each offers: `auto` picks only `claude`, run with every tool and MCP server off. `codex` (`exec`, read-only sandbox), `gemini` (`-p`, plan mode) and `opencode` (`run`) can still read files on your machine, so they run only when you name them with `--ai-provider`.

## The gate's extra tools

`prufgate.sh` also runs these when they are installed. Each is skipped (and says so) when it is not.

- **ast-grep**: the built-in rule `configs/ast-grep/rules/action-authorization-guard.yml` and your own rules in `.prufgate/rules/`. See [CUSTOM_RULES.md](CUSTOM_RULES.md).
- **gitleaks**: secret scanning with PrufGate's defaults (`configs/gitleaks.toml`) extended by your `.gitleaks.toml`.
- **zizmor**: GitHub Actions workflow security.
