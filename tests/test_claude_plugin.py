"""The Claude Code plugin (plugins/prufgate) and its marketplace (.claude-plugin/marketplace.json).

Fields follow the Claude Code plugin manifest and marketplace references; `claude plugin
validate .` is the authoritative check and is run by maintainers when it is installed."""

import json
import re
import unittest
from pathlib import Path

from prufgate import PROJECT_URL, __version__
from prufgate.hooks.agent_hooks import claude_plugin_hooks

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "prufgate"
NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")  # kebab-case, no spaces, `@`, `:` or separators
RESERVED = re.compile(r"^(?:claude|anthropic|anthropics|cc-plugin)-|^(?:claude|anthropic|anthropics|claude-code|claude-mods)$")
AUTHOR_KEYS = {"name", "email", "url"}
MANIFEST_KEYS = {"$schema", "name", "displayName", "version", "description", "author", "homepage", "repository",
                 "license", "keywords", "metadata", "icon", "defaultEnabled", "dependencies", "settings", "userConfig",
                 "skills", "commands", "agents", "hooks", "mcpServers", "lspServers", "outputStyles"}
MARKETPLACE_KEYS = {"$schema", "name", "owner", "plugins", "description", "version", "metadata"}
ENTRY_KEYS = MANIFEST_KEYS | {"source", "category", "tags", "strict"}


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class PluginManifestTest(unittest.TestCase):
    def setUp(self):
        self.manifest = load(PLUGIN / ".claude-plugin" / "plugin.json")

    def test_documented_fields_only(self):
        m = self.manifest
        self.assertLessEqual(set(m), MANIFEST_KEYS)
        self.assertRegex(m["name"], NAME)
        self.assertNotRegex(m["name"], RESERVED)
        for key in ("displayName", "version", "description", "homepage", "repository", "license"):
            self.assertIsInstance(m[key], str, key)
        self.assertIsInstance(m["author"], dict)
        self.assertLessEqual(set(m["author"]), AUTHOR_KEYS)
        self.assertEqual(m["author"]["name"], "GuardianVigil")
        self.assertTrue(all(isinstance(k, str) for k in m["keywords"]))
        self.assertTrue(m["homepage"].startswith(PROJECT_URL))

    def test_version_matches_the_package(self):
        self.assertEqual(self.manifest["version"], __version__)

    def test_repository_and_license_match_the_project(self):
        self.assertEqual(self.manifest["repository"], PROJECT_URL)
        self.assertIn(f'license = "{self.manifest["license"]}"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_only_default_component_folders(self):
        # Components load from their default locations; nothing at the plugin root that the docs warn about.
        self.assertEqual({p.name for p in PLUGIN.iterdir()}, {".claude-plugin", "hooks", "skills"})
        self.assertEqual({p.name for p in (PLUGIN / ".claude-plugin").iterdir()}, {"plugin.json"})


class PluginHooksTest(unittest.TestCase):
    def test_hooks_file_is_generated_from_the_adapters(self):
        self.assertEqual(load(PLUGIN / "hooks" / "hooks.json"), claude_plugin_hooks(),
                         "regenerate plugins/prufgate/hooks/hooks.json from claude_plugin_hooks()")

    def test_hooks_shape(self):
        hooks = load(PLUGIN / "hooks" / "hooks.json")
        self.assertEqual(set(hooks), {"hooks"})  # a hooks file wraps the event map in "hooks"
        events = hooks["hooks"]
        self.assertEqual(set(events), {"PreToolUse", "Stop"})
        for event, entries in events.items():
            for entry in entries:
                for h in entry["hooks"]:
                    self.assertEqual(h["type"], "command")
                    sub = "hook claude pre-tool" if event == "PreToolUse" else "hook claude stop"
                    self.assertIn(f"prufgate {sub}", h["command"])
                    self.assertIn("not installed", h["command"])  # a missing CLI blocks with a message
                    self.assertTrue(h["command"].endswith("exit 2"))
        self.assertEqual(events["PreToolUse"][0]["matcher"].split("|"), ["Bash", "Edit", "Write", "MultiEdit", "NotebookEdit"])
        self.assertIn("stop_hook_active", events["Stop"][0]["hooks"][0]["command"])

    def test_check_skill(self):
        text = (PLUGIN / "skills" / "prufgate-check" / "SKILL.md").read_text(encoding="utf-8")
        front = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(front)
        fields = dict(line.split(": ", 1) for line in front.group(1).splitlines())
        self.assertEqual(fields["name"], "prufgate-check")
        self.assertTrue(fields["description"])
        self.assertIn("prufgate check --changed", text)
        self.assertIn("pipx install prufgate", text)


class MarketplaceTest(unittest.TestCase):
    def test_marketplace_lists_the_plugin(self):
        mp = load(ROOT / ".claude-plugin" / "marketplace.json")
        self.assertLessEqual(set(mp), MARKETPLACE_KEYS)
        self.assertRegex(mp["name"], NAME)
        self.assertEqual(mp["owner"]["name"], "GuardianVigil")
        self.assertLessEqual(set(mp["owner"]), AUTHOR_KEYS)
        self.assertEqual(len(mp["plugins"]), 1)
        entry = mp["plugins"][0]
        self.assertLessEqual(set(entry), ENTRY_KEYS)
        self.assertEqual(entry["source"], "./plugins/prufgate")
        self.assertNotIn("..", entry["source"])
        self.assertTrue((ROOT / entry["source"]).is_dir())
        # The entry name is the install id and must equal the manifest name.
        self.assertEqual(entry["name"], load(PLUGIN / ".claude-plugin" / "plugin.json")["name"])
        # plugin.json carries the version; a second copy here would only drift.
        self.assertNotIn("version", entry)


if __name__ == "__main__":
    unittest.main()
