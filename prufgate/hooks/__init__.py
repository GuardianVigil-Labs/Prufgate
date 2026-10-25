"""PrufGate Workspace Initialization & Coding Agent Stop Hook Generators (`prufgate/hooks`)."""

from prufgate.hooks.agent_hooks import (
    generate_claude_settings_json,
    generate_cursor_rule_mdc,
    generate_pre_commit_config_yaml,
    generate_starter_config_yaml,
    init_workspace,
)

__all__ = [
    "generate_claude_settings_json",
    "generate_cursor_rule_mdc",
    "generate_pre_commit_config_yaml",
    "generate_starter_config_yaml",
    "init_workspace",
]
