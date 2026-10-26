# Agent hooks

Coding agents can run a command before a tool call and when they finish a turn. PrufGate uses those hooks to stop the usual ways an agent gets past a check (skipping git hooks, force-pushing, deleting tests, editing the CI or the hook configuration itself) and to send the agent back once when `prufgate check --changed` finds P0/P1 problems.

Most agent hook systems fail open: a hook that crashes, times out or prints something unexpected lets the action through. PrufGate's adapters are written so that every failure they control is a block.

## Setup

```sh
prufgate init --hooks                                # Claude Code and Cursor
prufgate init --agent copilot --agent codex          # pick agents (implies --hooks)
prufgate init --agent claude --agent cursor --agent copilot --agent codex --agent gemini
```

`init` merges into existing configuration. It keeps every entry you already have, adds each PrufGate hook only once (running it again changes nothing), and refuses, without writing anything, when an existing file is not valid JSON, has the wrong shape, or has a `version` other than 1. Fix or remove the file, then rerun.

Each hook runs `prufgate hook <agent> <event>` through a small `sh` wrapper. When neither `prufgate` nor the `prufgate` Python module can be found, the wrapper exits 2 with a message, so a missing install blocks instead of passing.

## Support

| Agent | File written | Events | Fail-closed | Limitations |
|---|---|---|---|---|
| Claude Code | `.claude/settings.json` | `PreToolUse` on `Bash` (shell guard), `PreToolUse` on `Edit\|Write\|MultiEdit\|NotebookEdit` (edit guard), `Stop` | Yes for everything PrufGate runs: the wrapper turns any failure into exit 2 | A hook timeout is decided by Claude Code. `Stop` sends the agent back once (`stop_hook_active`). |
| Cursor | `.cursor/hooks.json` | `beforeShellExecution` (shell guard), `preToolUse` on `Write\|Delete` (edit guard), `stop` | Yes: `failClosed: true` on both permission hooks, so crashes and timeouts block too | `stop` cannot block: it sends a `followup_message` once (`loop_count` 0, `status` `completed`). The `Write`/`Delete` tool input is not documented; the adapter reads any path-like field and blocks when it finds none. |
| GitHub Copilot (CLI and cloud agent) | `.github/hooks/prufgate.json` | `preToolUse` on `bash\|edit\|create`, `agentStop` | `preToolUse`: yes, Copilot denies on any non-zero exit. Timeouts are fail-open by Copilot's design (`timeoutSec` 30) | `agentStop` cannot fail closed: errors there are logged and ignored. `bash` only; `powershell` (Windows) is not covered. Copilot CLI also reads hooks from `.claude/settings.json`. |
| OpenAI Codex CLI | `.codex/hooks.json` | `PreToolUse` on `Bash\|apply_patch`, `Stop` | Partly: PrufGate's own errors exit 2 and block, but Codex treats a crash, timeout or other exit code as a failed hook and continues | Project hooks load only in a trusted project and must be approved in `/hooks`. Codex calls tool hooks "a guardrail, not a complete enforcement boundary". |
| Gemini CLI | `.gemini/settings.json` | `BeforeTool` on `run_shell_command\|write_file\|replace`, `AfterAgent` | Partly: as for Codex, exit codes other than 0 and 2 are a warning and the tool runs | `AfterAgent` retries once (`stop_hook_active`). |
| Windsurf, Cline | not written | | | Not adapted yet. |

## Claude Code plugin

Instead of writing `.claude/settings.json`, Claude Code users can install PrufGate as a plugin. It needs the `prufgate` command first:

```sh
pipx install prufgate
```

Then, in Claude Code:

```text
/plugin marketplace add GuardianVigil-Labs/Prufgate
/plugin install prufgate@prufgate
```

(or from a shell: `claude plugin marketplace add GuardianVigil-Labs/Prufgate`, then `claude plugin install prufgate@prufgate`).

The plugin lives in `plugins/prufgate/`; the marketplace file is `.claude-plugin/marketplace.json` at the repository root. It adds:

| Component | What it does |
|---|---|
| `PreToolUse` hook on `Bash\|Edit\|Write\|MultiEdit\|NotebookEdit` | `prufgate hook claude pre-tool`: the shell guard and the edit guard in one hook |
| `Stop` hook | `prufgate hook claude stop`: runs `prufgate check --changed` and sends Claude back once with P0/P1 findings |
| `/prufgate:prufgate-check [base-ref]` skill | runs `prufgate check --changed`, summarises P0/P1 findings and fixes them; Claude also uses it before saying a task is done |

Both hooks use the same `sh` wrapper as `init`: when `prufgate` is not installed, tool calls are blocked with a message saying so, and `Stop` sends Claude back once with that message. The plugin's version is the PrufGate version it was released with. Use the plugin or `prufgate init --agent claude`, not both, or every hook runs twice.

## Instructions for agents and reviewers (AGENTS.md, BUGBOT.md)

Hooks stop an agent; instructions tell it, and any AI reviewer, how to use PrufGate's output. `init` writes a short PrufGate section:

```sh
prufgate init --agents-md            # AGENTS.md (read by Codex, Copilot, Cursor, Gemini CLI and others)
prufgate init --bugbot               # .cursor/BUGBOT.md (Cursor Bugbot review rules)
```

The section says: run `prufgate check --changed` before declaring work done, treat P0/P1 findings as blockers, never add `prufgate-ignore` without a reason, never edit `.prufgate/` to silence a finding, and read `reports/prufgate-review.md` or `reports/prufgate.sarif` when they exist. It sits between `<!-- prufgate:start -->` and `<!-- prufgate:end -->`: the first run appends it to the file (or creates the file), later runs replace only what is between the markers, and the rest of the file is never touched. Unmatched or repeated markers stop `init` without writing.

## What each event does

- **`pre-tool`**: a shell tool (`Bash`, `bash`, `Shell`, `run_shell_command`) goes through the [shell-command guard](CI_INTEGRATION.md#shell-command-guard). A file edit (`Edit`, `Write`, `MultiEdit`, `NotebookEdit`, Codex `apply_patch`, Copilot `edit`/`create`, Gemini `write_file`/`replace`, Cursor `Write`) is refused when it touches `.prufgate/`, CI configuration (`.github/workflows/`, `.gitlab-ci.yml`, `.pre-commit-config.yaml`, `.circleci/`, `Jenkinsfile`, `azure-pipelines.yml`) or agent-hook configuration (`.claude/settings*.json`, `.cursor/hooks.json`, `.github/hooks/`, `.codex/hooks.json`, `.codex/config.toml`, `.gemini/settings.json`). Deleting a file (Cursor `Delete`, `*** Delete File:` in a Codex patch) is also refused on tests. Other tools are allowed.
- **`shell`**: Cursor's `beforeShellExecution`, whose payload carries `command` at the top level.
- **`stop`**: runs `prufgate check --changed` in the payload's `cwd` (Cursor: the first `workspace_roots` entry). With P0/P1 findings, or when the check cannot run, the agent is sent back with the findings. The second time it reports without blocking, so it cannot loop. The pre-commit hook and the CI gate are what enforce.

A payload that is not a JSON object, has no tool name, a shell tool without a string `command`, an edit with no file path, or any exception inside the adapter is a block, with the reason given to the agent.

## Responses

| Agent | Block a tool call | Allow | Send back at stop |
|---|---|---|---|
| Claude Code, Codex, Gemini CLI | exit 2, reason on stderr | exit 0, no output | exit 2, reason on stderr |
| GitHub Copilot | exit 2 and `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` | exit 0, no output (normal permission flow) | `{"decision": "block", "reason": "..."}` |
| Cursor | `{"permission": "deny", "user_message": "...", "agent_message": "..."}` | `{"permission": "allow"}` | `{"followup_message": "..."}` |

Try an adapter by hand:

```sh
echo '{"tool_name": "Bash", "tool_input": {"command": "git push --force"}}' | prufgate hook claude pre-tool; echo "exit $?"
echo '{"command": "rm -rf tests", "cwd": "."}' | prufgate hook cursor shell
```

## Sources

The payloads and responses follow each agent's published hook reference: [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks), [Cursor hooks](https://cursor.com/docs/hooks), [GitHub Copilot hooks reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference), [Codex hooks](https://developers.openai.com/codex/hooks) and [Gemini CLI hooks reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md). The plugin follows the Claude Code [plugin manifest reference](https://code.claude.com/docs/en/plugins-reference), [plugin components](https://code.claude.com/docs/en/plugins/components) and [marketplace reference](https://code.claude.com/docs/en/plugins/marketplace-reference); the Bugbot file follows [Cursor Bugbot rules](https://cursor.com/docs/bugbot). These formats change; if an agent's hook stops firing or blocks everything, check its reference first.

These hooks are guard rails against an agent's habits, not a sandbox: a script file, an alias or a tool the matcher does not cover can still get around them.
