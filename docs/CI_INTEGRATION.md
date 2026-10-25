# CI and agent integration

## GitHub Actions: the composite action

This repository is a composite action. It runs the `prufgate.sh` gate with the runner's `python3`, uploads the SARIF report to code scanning, and fails the job on P0/P1 findings or on an error.

```yaml
name: PrufGate
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF upload

jobs:
  prufgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit-sha>   # pin actions to a commit SHA
        with:
          fetch-depth: 0                      # the base branch must be present
          persist-credentials: false
      - run: python3 -m pip install "PyYAML>=6.0"   # needed to read .prufgate/config.yaml
      - uses: GuardianVigil-Labs/Prufgate@<commit-sha>
        with:
          battery: fast            # fast (changed files) or full
          fail_on_blocker: 'true'
          sarif_upload: 'true'
```

| Input | Default | Meaning |
|---|---|---|
| `battery` | `fast` | `fast` scans what the pull request changed; `full` (alias `review`) scans everything; `bola` and `test-audit` run one engine. |
| `base_ref` | the pull request base | Ref that changed files are compared with. On pull requests `origin/$GITHUB_BASE_REF` is used automatically. |
| `target_url` | none | Base URL for live BOLA probing of a service the job starts. Pass the tokens as `PRUFGATE_TEST_PROBE_TOKEN_A` / `_B` in `env`. |
| `fail_on_blocker` | `true` | Fail the step on a FAILED or ERROR verdict. |
| `sarif_upload` | `true` | Upload `reports/prufgate.sarif` to code scanning (skipped when no report was written). |
| `image` | `ghcr.io/guardianvigil-labs/prufgate:1.0.0` | Only used when the runner has no `python3`: the signed release image of this version, or an image you built. |

Outputs: `verdict` (`PASSED` or `FAILED`), `sarif_path`, `markdown_path`.

The gate's optional tools (ast-grep, gitleaks, zizmor) are skipped if they are not on the runner; install them in an earlier step if you want those checks.

Do not set `PRUFGATE_ALLOW_REPO_HOOKS=1` in workflows that run on pull requests from forks: it runs scripts from the pull request.

## Any CI: the CLI

The CLI needs only Python and Git:

```yaml
# GitLab CI
prufgate:
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends git
    - pip install "git+https://github.com/GuardianVigil-Labs/Prufgate.git@<tag-or-sha>"
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - prufgate check --changed --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --format sarif > prufgate.sarif
  artifacts:
    when: always
    paths: [prufgate.sarif]
```

`prufgate check --format sarif` writes SARIF for engines 1 to 5. The exit code is 0, 1 or 2 as described in [GETTING_STARTED.md](GETTING_STARTED.md#exit-codes). Treat 2 as a failed job, never as a pass.

## Coding-agent hooks

`prufgate init --hooks` writes:

- **`.claude/settings.json`**: a Claude Code `Stop` hook. When the agent tries to finish, it runs `prufgate check --changed --format agent-hook` (or `python3 -m prufgate.cli` when `prufgate` is not on `PATH`). With P0/P1 findings it exits 2 and lists them, which sends the agent back once to fix them. When the hook input says a Stop hook is already active, it exits 0, so it cannot loop forever: the hook asks once, and the pre-commit hook and the CI gate are what enforce. An existing `settings.json` is merged; a malformed one is refused, never overwritten.
- **`.cursor/rules/prufgate-guardrails.mdc`**: an always-on Cursor rule describing what PrufGate rejects.
- **`.pre-commit-config.yaml`**: a local pre-commit hook running `prufgate check --changed`.

Commit what suits your team; the files are ordinary project configuration.

## MCP server

`prufgate mcp` (or `prufgate-mcp`) serves the Model Context Protocol over stdio (protocol versions 2025-06-18, 2025-03-26 and 2024-11-05):

```json
{
  "mcpServers": {
    "prufgate": { "command": "prufgate", "args": ["mcp"] }
  }
}
```

Nine tools, all read-only. They write nothing into the workspace.

| Tool | Runs |
|---|---|
| `prufgate_fast_scan` | Engines 1 to 5 on the changed files |
| `prufgate_full_scan` | Every engine on the whole workspace, plus live BOLA probing only when `target_url` is given |
| `prufgate_anti_fabrication` | Engine 1 |
| `prufgate_test_audit` | Engine 2 |
| `prufgate_diff_guard` | Engine 3 |
| `prufgate_contract_check` | Engine 4 |
| `prufgate_bola_check` | Engine 5 (static, or live with `target_url`) |
| `prufgate_review` | Engine 6 |
| `prufgate_summary` | A summary of the last report in `reports/` |

Arguments: `workspace_path`, `base_ref`, `changed_only`, `target_url`. Each result has `status` (`ok` or `error`), `passed`, `blockers` and `findings`. An engine that fails sets `isError`; it never comes back as `passed: true`.

## REST API

`prufgate api` starts an HTTP service (default `127.0.0.1:8000`):

| Route | Purpose |
|---|---|
| `GET /api/v1/health` | Health check (no token). |
| `POST /api/v1/scan` | Start a scan: `{"workspace": "...", "battery": "fast|check|review|full"}`. |
| `GET /api/v1/scans/{id}` | Scan status and verdict (`PASSED`, `FAILED` or `ERROR`). |
| `GET /api/v1/scans/{id}/sarif`, `/report` | The SARIF and Markdown reports. |
| `POST /api/v1/webhook` | Signed GitHub or GitLab webhook (only when `PRUFGATE_WEBHOOK_SECRET` is set). |
| `GET /docs`, `/openapi.json` | API documentation. |

Every route except health needs `Authorization: Bearer $PRUFGATE_API_TOKEN`. Scans are confined to `PRUFGATE_WORKSPACE_ROOT`. From a checkout, a scan runs the `prufgate.sh` gate; from a pip install it runs `prufgate check --format sarif` (engines 1 to 5, SARIF only). The security model is in [SECURITY.md](../SECURITY.md#running-prufgate-safely), and the variables are in [CONFIGURATION.md](CONFIGURATION.md#environment-variables).
