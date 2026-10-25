# Configuration reference

PrufGate runs with sensible defaults and no configuration. To tune it, add one of these files at the root of the repository (first found wins): `.prufgate/config.yaml`, `.prufgate/config.yml`, `.prufgate.yaml`, `.prufgate.yml`. The older `.prufgate/fabrication.json` and `.prufgate/debt-ceiling.json` are still read.

`prufgate init` writes a starter file. An invalid file (bad YAML, an unknown pack, a reason missing where one is required, invalid UTF-8) stops the run with exit 2 and a message naming the problem.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | `1` | Schema version. |
| `packs` | list | `[core, web-ui, ai-safety]` | Rule packs to run. See [packs](#packs). |
| `languages` | list | all | Limit engine 1 to these languages (`typescript`, `javascript`, `python`, `go`, `rust`, `java`, `kotlin`, `php`, `ruby`, `csharp`). |
| `exclude` (alias `allowed_paths`) | list of paths/globs | build output, dependencies | Paths no engine scans. |
| `auth_guards` | list | none (added to the built-ins) | Extra function or decorator names that count as an authentication check for engine 5. Built in: `assert*`, `verify*`, `require*`, `protect*`, `auth()`, `getSession`, `getCurrentUser`, `get_current_user`, `Depends(get_current_*)`, `@login_required`, `@UseGuards`, `@PreAuthorize`, `@Secured`, `authenticate_user!`, Laravel `auth` middleware and similar. |
| `tenant_keys` | list | none (added to the built-ins) | Extra column or field names that scope a query to a tenant or owner. Built in: `tenant_id`, `organization_id`, `org_id`, `workspace_id`, `user_id`, `owner_id`, `account_id`, `customer_id`, in snake_case and camelCase. |
| `score_owners` | list of paths | none | Files that are allowed to compute scores or verdicts (engine 1 flags scores computed anywhere else). |
| `model_call_patterns` | list of regexes | common LLM SDKs | Extra patterns that identify an LLM call for the unseeded-prompt rule. |
| `evidence_markers` | list of regexes | common forms | Patterns that show runtime evidence is passed into a prompt. |
| `exempt` | see below | none | Per-path rule exemptions, each with a reason. |
| `known_debt` | see below | none | Ratcheting ceilings for rules you cannot fix yet. |

Paths in `exclude`, `exempt` and `known_debt` match a file exactly, a directory and everything below it, or a glob (`src/legacy/**`). They never match a substring, so `a.ts` does not cover `data.ts`.

## Packs

Packs switch rules of engine 1 on or off. Engine 5 (BOLA) always runs; tune it with `tenant_keys` and `auth_guards`.

| Pack | Default | What it adds |
|---|---|---|
| `core` | on | The language-independent rules of engine 1. |
| `web-ui` | on | Stub click handlers and disconnected form submits. |
| `ai-safety` | on | LLM prompts that ask for a decision with no evidence passed in. |
| `cti` | **off** | Rules for threat-intelligence products: hard-coded verdicts and attributions, zero JARM fingerprints, the empty-input digest used as a sample, model-generated intelligence. Turn it on only if you build such a product. |

## Suppressing findings

Give every suppression a reason, so a reviewer can see why a finding was accepted (exempt forms 1 and 3 require one).

**Inline**, on the line or the line above:

```ts
return cachedPrices; // prufgate-ignore: route-canned-fallback -- served from the documented offline cache
```

Engine 3 flags a new `prufgate-ignore` added without a justification, like any other bare suppression.

**`exempt`** accepts three forms; use one per file:

```yaml
# 1. path -> rule -> reason
exempt:
  src/legacy/adapter.ts:
    route-canned-fallback: "#104: legacy fallback until the payments API migration"
```

```yaml
# 2. rule -> list of paths
exempt:
  demo-named-data:
    - examples/**
```

```yaml
# 3. a list of entries
exempt:
  - { path: scripts/seed.ts, rule: fake-named-data, reason: "seed data for local development" }
```

An exemption that no longer matches anything is reported as `stale-exemption`, so the list does not rot.

**`known_debt`** sets a ceiling that can only go down:

```yaml
known_debt:
  stub-click-handler: 3                 # at most 3; a 4th is a P0 debt-ceiling-breached
  unhandled-empty-catch:
    - { path: src/old/client.ts, reason: "#88: replace the old client" }
```

**Baseline** (the `prufgate.sh` gate only): `.prufgate/baseline.yaml`, `.yml` or `.json` holds a list, or a mapping under `ignore`, `ignored` or `baseline`, of `{file, rule}` entries (`file_path` and `rule_id` are accepted too; `"*"` in one field matches any value there; an entry needs a real value in at least one field). Rule names are matched case-insensitively against the report's rule IDs, where anti-fabrication rules carry an `anti-fabrication-` prefix. `prufgate check`, the MCP server and the API do not read the baseline. A baseline file that cannot be parsed is ignored, which keeps every finding.

Engine 3 reports a diff that adds a new exemption, debt entry or score owner to the PrufGate config itself (`prufgate-config-self-exemption`), so loosening the gate is always visible in review.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `PRUFGATE_BASE_REF` | CLI, gate | Base ref for the changed scope. |
| `GITHUB_BASE_REF` | CLI, gate | Set by GitHub Actions; `origin/<it>` is used when `PRUFGATE_BASE_REF` is not set. |
| `WORKSPACE` | gate | The repository to scan (default: the current directory, or `/workspace` in the container). |
| `PRUFGATE_REPORTS_DIR` | gate | Where reports go (default `WORKSPACE/reports`). |
| `TARGET_URL` | gate | Base URL for live BOLA probing. |
| `BOLA_STATIC_ONLY` | gate | `1` skips live probing even when `TARGET_URL` is set. |
| `PRUFGATE_TEST_PROBE_TOKEN_A`, `_B` | engine 5 | Bearer tokens for live probing. |
| `PRUFGATE_TEST_PROBE_TENANT_A_ID`, `_B_ID` | engine 5 | Tenant IDs for live probing. |
| `PRUFGATE_ALLOW_REPO_HOOKS` | gate | `1` runs the scanned repository's `.prufgate/hooks/` scripts. Off by default: they are code from the repository under review. |
| `PRUFGATE_INFO_URI` | reports | The `informationUri` written into SARIF. |
| `PRUFGATE_AI_MODEL` | engine 6 | Model name for `--ai` with an API provider. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST` | engine 6 | Providers for `prufgate review --ai`. Never written to output. |
| `PRUFGATE_API_TOKEN` | API | Bearer token for every scan and report route. Generated and printed once when unset on loopback. |
| `PRUFGATE_API_HOST` | API | Bind address (default `127.0.0.1`). A non-loopback address needs `PRUFGATE_API_TOKEN`. |
| `PRUFGATE_WORKSPACE_ROOT` | API | Scans are confined to this directory; anything resolving outside it, including through a symlink, is refused. |
| `PRUFGATE_DEFAULT_WORKSPACE` | API | Workspace used when a request names none. |
| `PRUFGATE_WEBHOOK_SECRET` | API | Turns on `/api/v1/webhook`; deliveries must carry a valid GitHub or GitLab signature. |
| `PRUFGATE_API_MAX_SCANS`, `PRUFGATE_API_SCAN_TIMEOUT` | API | Concurrent scan limit, and seconds per scan (default 600). |
| `PRUFGATE_MCP_TIMEOUT` | MCP | Seconds per tool call (default 300). |
| `PRUFGATE_ALLOW_LINK_LOCAL` | MCP, API | `1` allows link-local probe targets, which are refused by default (cloud metadata endpoints). |
| `PRUFGATE_IMAGE`, `PRUFGATE_DIR` | `bin/prufgate` | Image for `--docker` (required: none is published), and the checkout to run. |
