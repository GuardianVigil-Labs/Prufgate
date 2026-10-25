# The engines

Each engine can run alone (its module has a command line and a `--self-check`), through `prufgate check`, or as a step of the `prufgate.sh` gate. Every rule has invented positive and near-miss fixtures in its engine's self-check or in `tests/`.

All engines use pattern and structure heuristics over source text, not a compiler front end for each language. That keeps PrufGate fast and dependency-free, and it means two things: an unusual code shape can slip past a rule, and correct code can occasionally be flagged. Report either with a minimal invented sample (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

Suppressions, exemptions and baselines are described in [CONFIGURATION.md](CONFIGURATION.md#suppressing-findings).

## Engine 1: anti-fabrication

`prufgate/anti_fabrication/detector.py`. Production code that compiles but fakes its result. Test files, fixtures and build output are skipped.

Languages: TypeScript, JavaScript (including `.vue` and `.svelte`), Python, Go, Rust, Java, Kotlin, PHP, Ruby, C#. Not every rule applies to every language; error-path rules cover all of them.

| Rule | What it flags |
|---|---|
| `canned-error-fallback` | A `catch` / `except` / `rescue` / `if err != nil` that returns a hard-coded success value. |
| `route-canned-fallback` | An API route that answers a failed upstream call with canned data. |
| `unhandled-empty-catch` | An error swallowed with nothing done about it. |
| `verdict-on-error-path`, `score-on-error-path` | A decision or score produced on an error path. |
| `score-outside-scoring` | A score computed outside the files listed in `score_owners`. |
| `simulated-return-value` | A literal returned under a comment admitting it is simulated or a placeholder. |
| `fake-named-data` (`demo-named-data`) | `MOCK_*`, `FAKE_*`, `DUMMY_*`, `SAMPLE_*`, `fallbackData` and similar in production code. |
| `synthetic-delay-mock` | A sleep or timer paired with a hard-coded result, faking asynchronous work. |
| `stub-click-handler`, `disconnected-form-submit` | UI handlers that do nothing, or a submit that only calls `preventDefault()` (pack `web-ui`). |
| `always-current-fake-timestamp`, `invented-event-timestamp` | "Now minus a fixed offset" computed at read time, so static data looks fresh. |
| `asserted-state` | A status literal asserted rather than derived. |
| `unimplemented-production-stub` | `NotImplementedError`, `todo!()`, `panic("not implemented")`, `throw new Error("TODO")` in reachable code. |
| `prompt-invents-finding` | An LLM call asked for a structured decision (score, verdict, severity) with no runtime evidence in the prompt (pack `ai-safety`). |
| `documentation-ip-or-domain` (`documentation-address`) | RFC 5737 / RFC 3849 addresses or `example.com` served from production code. |
| `stale-exemption`, `debt-ceiling-breached` | Config hygiene: an exemption that matches nothing, or a `known_debt` ceiling exceeded. |

Opt-in pack `cti` (threat-intelligence products): `hardcoded-cve`, `hardcoded-attribution`, `keyword-selected-attribution`, `ui-verdict-literal`, `substring-decides-verdict`, `zero-jarm-as-fingerprint`, `empty-input-digest-as-sample`, `llm-generated-intel`.

## Engine 2: test integrity

`prufgate/anti_reward_hacking/test_integrity.py`. Tests that cannot fail, which is how an agent turns a red build green without fixing anything.

Languages and frameworks: Python (pytest, unittest), JavaScript/TypeScript (Jest, Vitest, Mocha, node:test, Playwright), Go (`testing`), Rust (`#[test]`), Java/Kotlin (JUnit), PHP (PHPUnit, Pest), C# (xUnit, NUnit, MSTest), Ruby (RSpec, Minitest).

| Rule | What it flags |
|---|---|
| `zero-assertion-test` | A test that runs code and asserts nothing. Pytest fixtures named `test_*` are not tests. |
| `tautological-assertion` | `assert True`, `expect(true).toBe(true)`, `assertEqual(x, x)`, or an existence check as the only assertion. |
| `self-mocked-unit-under-test` | A test that mocks the module it is testing, or asserts a mock's own return value. |
| `caught-and-ignored-test-exception` | A test that catches the failure it should report. |
| `snapshot-blind-update-or-empty` | Empty inline snapshots, or snapshots updated without review. |
| `diff-assertion-weakening` | A diff that deletes assertions or widens what is accepted (for example `== 200` becoming `in (200, 500)`). |
| `test-input-special-casing` | A diff where production code gains a branch for the exact literal a test passes in. |

## Engine 3: diff guard

`prufgate/diff_guard/tamper_detector.py`. Works on a diff (`--changed`, `--base REF` or `--diff-file`), so it sees only what was added. It is language-independent where it can be.

| Rule | What it flags |
|---|---|
| `test-skip-smuggling` | Skips and focus added without an issue reference: `.skip`/`.only`/`xit`/`xdescribe`, `this.skip()`, `t.skip()`, `pytest.mark.skip`/`xfail`, `unittest.skip`, `t.Skip()`, `#[ignore]`, `@Disabled`, `[Fact(Skip=...)]`, `[Ignore]`, `markTestSkipped`, RSpec `xit`. |
| `suppression-comment-smuggling` | `@ts-ignore`, `@ts-expect-error`, `eslint-disable`, `biome-ignore`, `# noqa`, `# type: ignore`, `// nolint`, `#[allow(...)]`, `@SuppressWarnings`, `prufgate-ignore`, added without a justification (`-- reason`) or issue reference. |
| `unsafe-type-cast-cascade` | `as unknown as T`, `as any`, `cast(Any, ...)`, unjustified `unsafe` blocks. |
| `linter-or-ci-config-weakening` | `"strict": false`, rules turned off, `continue-on-error: true`, and similar in linter, compiler and CI config. |
| `coverage-threshold-lowering` | A lowered `fail_under` or Jest/Vitest coverage threshold. |
| `prufgate-config-self-exemption` | The configuration in effect loosened compared with the base, compared by value (any YAML spelling, location or shadowing file): new exclusions, exemptions, known debt or higher ceilings, dropped packs, fewer languages, more auth guards, tenant keys, score owners or evidence markers (P1); an exclusion covering every file or the config itself, such as `**` (P0). The config under review cannot exclude, exempt or set a debt ceiling for this finding. Without a base (a diff file), the diff lines of the config are checked instead. |

An issue reference is `#123`, `ABC-123` or an issue URL. Acronyms such as `UTF-8` and `SHA-256` do not count.

## Engine 4: contract guard

`prufgate/contract_guard/`. Things that look plausible in a diff but do not exist.

| Rule | What it flags |
|---|---|
| `undeclared-or-hallucinated-import` | An import of a package declared in none of `package.json`, `pyproject.toml` (dependency tables only), `requirements*.txt` / `requirements/`, `go.mod`, `Cargo.toml`. Standard-library modules, relative imports and local packages are not flagged. A hallucinated or typo-squatted name is how a malicious package gets installed. |
| `undocumented-env-var-drift` | `process.env.X`, `os.environ["X"]` / `os.getenv("X")` without a default, `os.Getenv("X")`, `env!("X")`, when `X` is missing from `.env.example` (or `.env.sample`, `.env.template`). |
| `frontend-backend-route-mismatch` | `fetch("/api/...")` / `axios.*("/api/...")` to a path that no backend route or OpenAPI spec defines. |

The import check runs only for ecosystems that have a manifest in the repository. In the changed scope it reads the same changed files as the other engines: the diff against the chosen base ref, plus untracked files.

## Engine 5: BOLA / IDOR

`prufgate/bola/bola_engine.py`. Broken object-level authorisation: a handler loads a record by an ID the client controls, without checking that the caller may see it.

Static analysis discovers routes in OpenAPI specs, Express/Fastify, NestJS, Next.js (App and Pages router, server actions), FastAPI, Flask, Django function views, Go (net/http, Gin, Echo, Chi), Spring, Rails controllers and Laravel controllers. Each handler is checked on its own, up to the next route:

- **missing auth**: no recognised guard in the handler, and no file-wide middleware (`router.use`, `before_action`, a class-level guard);
- **unscoped access** (`static-bola-unscoped-access`): a lookup such as `findUnique`, `findById`, `findByPk`, `get_object_or_404`, `find(params[:id])` keyed by request input, with no tenant key or caller identity inside the lookup and no explicit ownership comparison. A tenant ID taken from the URL alone does not count, because the caller chooses it.

Add your own guards and tenant keys with `auth_guards` and `tenant_keys`.

Known gaps, tracked in the issue list: Laravel implicit route-model binding, values passed through intermediate variables, Django class-based views and DRF viewsets, middleware registered in another file, and custom Rails member actions.

**Live probing** (optional, only against systems you are authorised to test) sends each discovered route as an unauthenticated request, as user A, and as user A for user B's resource (and the reverse). It reports responses that leak across tenants, with `curl` reproductions that use `$PRUFGATE_TOKEN_A` / `$PRUFGATE_TOKEN_B` placeholders. Redirects are followed only within the target's origin; a redirect elsewhere is not followed, so the tokens never leave that origin, and is reported as `BOLA-PROBE-REDIRECT-REFUSED` (P1). See [GETTING_STARTED.md](GETTING_STARTED.md#live-bola-probing).

## Engine 6: diff reviewer

`prufgate/review/reviewer.py`. Reviews changed lines only.

Deterministic rules (default, offline):

| Finding | Severity |
|---|---|
| SQL injection vector (query built from string interpolation) | P0 |
| Hard-coded credential | P0 |
| Shell command injection risk | P0 |
| Disabled TLS certificate verification | P1 |
| Unsanitised HTML injection (XSS) | P1 |
| Credential logged to the console | P1 |
| Server action without an authorisation guard | P1 |
| Ignored Go error return, unbounded goroutine spawn | P2 |

It also folds in the diff findings of engines 1 to 4. Output formats: `markdown`, `json`, `sarif`, `github` (workflow annotations, with every field escaped) and `reviewdog`. Suggestion blocks are emitted only when they are valid replacement code, never comment-only. It exits 1 on a P0/P1 finding, and 2 when no diff can be read (no repository, or a base ref that does not exist).

`--ai` (optional) sends the changed hunks to a provider you choose: an API (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST`, model in `PRUFGATE_AI_MODEL`) or a local agent CLI. The model's output is treated as untrusted: a comment must point at a line the diff adds, and suggestions are validated like the deterministic ones. API keys are never printed, and provider errors are redacted. Sending code to a provider is your decision; the default mode sends nothing anywhere. The diff can carry prompt injection, so local agent CLIs get it on stdin and run one-shot with the least tool access each offers: `auto` picks only `claude`, run with every tool and MCP server off. `codex` (`exec`, read-only sandbox), `gemini` (`-p`, plan mode) and `opencode` (`run`) can still read files on your machine, so they run only when you name them with `--ai-provider`.

## The gate's extra tools

`prufgate.sh` also runs these when they are installed. Each is skipped (and says so) when it is not.

- **ast-grep**: the built-in rule `configs/ast-grep/rules/action-authorization-guard.yml` and your own rules in `.prufgate/rules/`. See [CUSTOM_RULES.md](CUSTOM_RULES.md).
- **gitleaks**: secret scanning with PrufGate's defaults (`configs/gitleaks.toml`) extended by your `.gitleaks.toml`.
- **zizmor**: GitHub Actions workflow security.
