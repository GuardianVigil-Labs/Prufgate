import shlex
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from prufgate.cli import main as cli_main

ROOT = Path(__file__).resolve().parent.parent


class TestPreCommitHooks(unittest.TestCase):
    def setUp(self) -> None:
        self.hooks = {h["id"]: h for h in yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))}

    def _run_entry(self, hook_id: str):
        """Run the hook's entry through the real CLI parser; return the check args."""
        cmd, *argv = shlex.split(self.hooks[hook_id]["entry"])
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'{cmd} = "prufgate.cli:main"', pyproject, "entry must be the packaged console script")
        seen = []
        with patch("prufgate.cli._cmd_check", side_effect=lambda a: seen.append(a) or 0):
            self.assertEqual(cli_main(argv), 0)
        self.assertEqual(len(seen), 1, "entry must dispatch to `prufgate check`")
        return seen[0]

    def test_hook_ids_and_common_fields(self) -> None:
        self.assertEqual(set(self.hooks), {"prufgate", "prufgate-full"})
        for hook in self.hooks.values():
            self.assertEqual(hook["language"], "python")
            # The scan picks its own files; pre-commit must not split it into batches.
            self.assertIs(hook["pass_filenames"], False)
            self.assertIs(hook["always_run"], True)
            self.assertIs(hook["require_serial"], True)

    def test_commit_hook_scans_the_change(self) -> None:
        self.assertEqual(self.hooks["prufgate"]["stages"], ["pre-commit"])
        args = self._run_entry("prufgate")
        self.assertTrue(args.changed)
        self.assertIsNone(args.base)
        self.assertEqual(args.format, "text")

    def test_push_hook_scans_everything(self) -> None:
        self.assertEqual(self.hooks["prufgate-full"]["stages"], ["pre-push"])
        args = self._run_entry("prufgate-full")
        self.assertFalse(args.changed)
        self.assertEqual(args.path, ".")


if __name__ == "__main__":
    unittest.main()
