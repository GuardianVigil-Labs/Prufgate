#!/usr/bin/env python3
"""PrufGate Workspace Initializer & Coding Agent Stop Hook Generators (`prufgate/hooks/agent_hooks.py`).

Generates:
1. `.prufgate/config.yaml`: Clean YAML configuration for PrufGate.
2. `.claude/settings.json`: Claude Code `Stop` hook running `prufgate check --changed --format agent-hook`.
3. `.cursor/rules/prufgate-guardrails.mdc`: Cursor / IDE coding agent verification rules.
4. `.pre-commit-config.yaml`: Git pre-commit hook running `prufgate check --changed`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

STARTER_CONFIG_YAML = """# PrufGate Configuration (.prufgate/config.yaml)
version: 1

# Rule packs to enforce:
#   core      - Universal anti-fabrication, hardcoded scores/verdicts, literal returns
#   ai-safety - Unseeded LLM judgment prompts, missing evidence citations
#   web-ui    - Stub click handlers, disconnected form submits, canned API fallbacks
#   cti       - Threat-intelligence data rules (opt-in, off by default)
packs:
  - core
  - ai-safety
  - web-ui

# Leave empty to auto-detect all languages (TypeScript, JavaScript, Python, Go, Rust, Java, Kotlin, Ruby, PHP, C#)
languages: []

# Paths and globs excluded from scanning
exclude:
  - "dist/**"
  - "build/**"
  - ".next/**"
  - "node_modules/**"
  - "vendor/**"
  - "coverage/**"

# Custom authentication guard function/decorator names for BOLA verification (Engine 5)
auth_guards:
  - requireAuth
  - verifySession
  - get_current_user

# Custom multi-tenant / ownership column or attribute keys for BOLA verification (Engine 5)
tenant_keys:
  - tenant_id
  - tenantId
  - organization_id
  - organizationId
  - workspace_id
  - user_id

# Per-file rule exemptions, each with a reason, e.g.
#   exempt:
#     src/legacy/adapter.ts:
#       canned-error-fallback: "#104: legacy fallback until the payments API migration"
exempt: {}

# Ratcheting debt ceilings (counts can only stay equal or decrease)
known_debt: {}
"""

CURSOR_RULE_MDC = """---
description: PrufGate Anti-Fabrication, Test Integrity & BOLA Guardrails
globs: "**/*"
alwaysApply: true
---

# PrufGate Agent Verification Rules

1. **Zero Fabrication**: Never hardcode return values, mock production business logic, or swallow exceptions in empty `catch` / `except` blocks.
2. **Genuine Tests**: Every test must invoke the real unit under test and assert concrete behavioral outcomes. Never write zero-assertion tests, tautological assertions, or tests that only assert a mock's configured return value.
3. **No Guardrail Tampering**: Never add `.skip`, `@pytest.mark.skip`, `@ts-ignore`, `# noqa`, or weaken linter/typechecker configs without an explicit `#issue: reason` reference.
4. **Multi-Tenant BOLA Scoping**: Every dynamic-ID route handler (`{id}`, `:id`, `[id]`) must enforce caller authentication and scope database queries by tenant/owner key (`tenant_id`, `organization_id`, `user_id`).
5. **Pre-Completion Check**: Run `prufgate check --changed` before finishing any coding task and resolve all `P0` and `P1` findings.
"""

PRE_COMMIT_CONFIG_YAML = """repos:
  - repo: local
    hooks:
      - id: prufgate-check-changed
        name: PrufGate Anti-Fabrication & Test Integrity Gate
        entry: prufgate check --changed
        language: system
        pass_filenames: false
"""

# The Stop hook, as one POSIX sh command. It uses `prufgate` when it is on PATH,
# else the installed module. Any failure to run PrufGate exits 2 (blocking) with a
# message, so a missing install never passes silently; when the agent is
# already continuing because of this hook (stop_hook_active), it reports and
# exits 0 so it can never loop.
HOOK_COMMAND = "; ".join([
    "input=$(cat)",
    "case \"$input\" in *'\"stop_hook_active\": true'*|*'\"stop_hook_active\":true'*) active=1;; *) active=0;; esac",
    "if command -v prufgate >/dev/null 2>&1; then printf '%s' \"$input\" | prufgate check --changed --format agent-hook; rc=$?",
    "elif python3 -c 'import prufgate.cli' >/dev/null 2>&1; then printf '%s' \"$input\" | python3 -m prufgate.cli check --changed --format agent-hook; rc=$?",
    "else echo 'prufgate: not installed (no prufgate on PATH, no engine module for python3); this work was not checked' >&2; rc=3; fi",
    "[ \"$rc\" -eq 0 ] && exit 0",
    "[ \"$rc\" -eq 2 ] || echo \"prufgate: the check could not run (exit $rc)\" >&2",
    "[ \"$active\" -eq 1 ] && exit 0",
    "exit 2",
])


class HookConfigError(ValueError):
    """An existing agent settings file cannot be merged safely."""


def generate_starter_config_yaml() -> str:
    return STARTER_CONFIG_YAML


def generate_cursor_rule_mdc() -> str:
    return CURSOR_RULE_MDC


def generate_pre_commit_config_yaml() -> str:
    return PRE_COMMIT_CONFIG_YAML


def generate_claude_settings_json(existing_data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create or merge a Claude Code `Stop` hook invoking `prufgate check --changed --format agent-hook`."""
    data: dict[str, Any] = dict(existing_data) if isinstance(existing_data, dict) else {}
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise HookConfigError('"hooks" in .claude/settings.json is not an object; fix it, then rerun')
    stop_hooks = hooks.setdefault("Stop", [])
    if not isinstance(stop_hooks, list):
        raise HookConfigError('"hooks.Stop" in .claude/settings.json is not a list; fix it, then rerun')

    already_present = False
    for entry in stop_hooks:
        if isinstance(entry, dict):
            inner_hooks = entry.get("hooks", [])
            if isinstance(inner_hooks, list):
                for h in inner_hooks:
                    if isinstance(h, dict) and "prufgate check" in str(h.get("command", "")):
                        already_present = True
                        break

    if not already_present:
        stop_hooks.append(
            {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": HOOK_COMMAND,
                    }
                ],
            }
        )
    return data


def init_workspace(
    workspace: Path,
    install_hooks: bool = False,
    overwrite: bool = False,
) -> list[str]:
    """Initialize `.prufgate/config.yaml` and optional coding agent / pre-commit hooks in `workspace`."""
    created_or_updated: list[str] = []
    ws = workspace.resolve()

    # 1. .prufgate/config.yaml
    cfg_path = ws / ".prufgate" / "config.yaml"
    if overwrite or not cfg_path.exists():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(generate_starter_config_yaml(), encoding="utf-8")
        created_or_updated.append(".prufgate/config.yaml")

    if install_hooks:
        # 2. .claude/settings.json Stop hook
        claude_path = ws / ".claude" / "settings.json"
        existing_claude: dict[str, Any] | None = None
        if claude_path.exists():
            try:
                existing_claude = json.loads(claude_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                # Never overwrite settings we cannot read: they may hold other hooks.
                raise HookConfigError(f"{claude_path} is not valid JSON ({e}); fix it or remove it, then rerun") from e
            if not isinstance(existing_claude, dict):
                raise HookConfigError(f"{claude_path} must contain a JSON object")
        claude_path.parent.mkdir(parents=True, exist_ok=True)
        merged_claude = generate_claude_settings_json(existing_claude)
        claude_path.write_text(json.dumps(merged_claude, indent=2) + "\n", encoding="utf-8")
        created_or_updated.append(".claude/settings.json")

        # 3. .cursor/rules/prufgate-guardrails.mdc
        cursor_path = ws / ".cursor" / "rules" / "prufgate-guardrails.mdc"
        if overwrite or not cursor_path.exists():
            cursor_path.parent.mkdir(parents=True, exist_ok=True)
            cursor_path.write_text(generate_cursor_rule_mdc(), encoding="utf-8")
            created_or_updated.append(".cursor/rules/prufgate-guardrails.mdc")

        # 4. .pre-commit-config.yaml
        pre_commit_path = ws / ".pre-commit-config.yaml"
        if overwrite or not pre_commit_path.exists():
            pre_commit_path.write_text(generate_pre_commit_config_yaml(), encoding="utf-8")
            created_or_updated.append(".pre-commit-config.yaml")

    return created_or_updated
