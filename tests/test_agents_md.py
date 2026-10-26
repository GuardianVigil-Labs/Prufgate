"""`prufgate init --agents-md` / `--bugbot`: the marked PrufGate section in AGENTS.md
and .cursor/BUGBOT.md is added once, updated in place, and never touches the rest of the file."""

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from prufgate.cli import main as cli_main
from prufgate.hooks.agent_hooks import (
    AGENTS_MD_END,
    AGENTS_MD_SECTION,
    AGENTS_MD_START,
    HookConfigError,
    init_workspace,
    merge_agents_section,
)


class AgentsSectionTest(unittest.TestCase):
    def test_new_file_is_only_the_section(self):
        self.assertEqual(merge_agents_section(None), AGENTS_MD_SECTION)
        self.assertEqual(merge_agents_section(""), AGENTS_MD_SECTION)

    def test_section_has_markers_and_the_rules(self):
        self.assertTrue(AGENTS_MD_SECTION.startswith(AGENTS_MD_START))
        self.assertTrue(AGENTS_MD_SECTION.rstrip().endswith(AGENTS_MD_END))
        for needle in ("prufgate check --changed", "P0 and P1", "prufgate-ignore", ".prufgate/",
                       "reports/prufgate-review.md", "reports/prufgate.sarif"):
            self.assertIn(needle, AGENTS_MD_SECTION)

    def test_appended_to_an_existing_file_and_idempotent(self):
        existing = "# Project\n\nUse tabs.\n"
        once = merge_agents_section(existing)
        self.assertTrue(once.startswith(existing))
        self.assertEqual(once, existing + "\n" + AGENTS_MD_SECTION)
        self.assertEqual(merge_agents_section(once), once)

    def test_old_section_is_replaced_in_place(self):
        old = f"# Top\n\n{AGENTS_MD_START}\nstale rules\n{AGENTS_MD_END}\n\n## After\n\nkeep me\n"
        new = merge_agents_section(old)
        self.assertEqual(new, f"# Top\n\n{AGENTS_MD_SECTION}\n## After\n\nkeep me\n")
        self.assertNotIn("stale rules", new)
        self.assertEqual(new.count(AGENTS_MD_START), 1)

    def test_broken_markers_are_refused(self):
        for text in (f"{AGENTS_MD_START}\nno end\n", f"no start\n{AGENTS_MD_END}\n",
                     f"{AGENTS_MD_END}\n{AGENTS_MD_START}\n", AGENTS_MD_SECTION * 2):
            with self.subTest(text=text), self.assertRaises(HookConfigError):
                merge_agents_section(text)

    def test_init_writes_both_files_and_reruns_change_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "AGENTS.md").write_text("# Mine\n", encoding="utf-8")
            written = init_workspace(ws, agents_md=True, bugbot=True)
            self.assertIn("AGENTS.md", written)
            self.assertIn(".cursor/BUGBOT.md", written)
            self.assertNotIn(".claude/settings.json", written)
            agents = (ws / "AGENTS.md").read_text(encoding="utf-8")
            self.assertTrue(agents.startswith("# Mine\n"))
            self.assertEqual((ws / ".cursor" / "BUGBOT.md").read_text(encoding="utf-8"), AGENTS_MD_SECTION)
            self.assertEqual(init_workspace(ws, agents_md=True, bugbot=True), [])
            self.assertEqual((ws / "AGENTS.md").read_text(encoding="utf-8"), agents)

    def test_broken_markers_stop_init_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "AGENTS.md").write_text(f"{AGENTS_MD_START}\n", encoding="utf-8")
            with self.assertRaises(HookConfigError):
                init_workspace(ws, agents_md=True, bugbot=True, install_hooks=True)
            self.assertFalse((ws / ".cursor").exists())
            self.assertFalse((ws / ".claude").exists())

    def test_cli_flags(self):
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            self.assertEqual(cli_main(["init", tmp, "--agents-md"]), 0)
            self.assertIn(AGENTS_MD_START, (Path(tmp) / "AGENTS.md").read_text(encoding="utf-8"))
            self.assertFalse((Path(tmp) / ".cursor" / "BUGBOT.md").exists())
            self.assertEqual(cli_main(["init", tmp, "--bugbot"]), 0)
            self.assertTrue((Path(tmp) / ".cursor" / "BUGBOT.md").is_file())


if __name__ == "__main__":
    unittest.main()
