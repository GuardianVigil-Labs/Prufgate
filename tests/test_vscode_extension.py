"""The VS Code extension (editors/vscode): manifest fields, version and the safety settings."""

import json
import unittest
from pathlib import Path

from prufgate import PROJECT_URL, __version__

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "editors" / "vscode"


class VSCodeManifestTest(unittest.TestCase):
    def setUp(self):
        self.pkg = json.loads((EXT / "package.json").read_text(encoding="utf-8"))

    def test_version_matches_the_package(self):
        self.assertEqual(self.pkg["version"], __version__)

    def test_publisher_repository_and_license(self):
        self.assertEqual(self.pkg["publisher"], "GuardianVigil")
        self.assertEqual(self.pkg["repository"]["url"], PROJECT_URL)
        self.assertIn(f'license = "{self.pkg["license"]}"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_icon_is_a_png_in_the_extension(self):
        icon = EXT / self.pkg["icon"]
        self.assertTrue(icon.is_file())
        self.assertEqual(icon.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

    def test_cli_path_is_machine_scoped(self):
        # `machine` settings are read from user or remote settings only, so a repository's
        # .vscode/settings.json cannot point the extension at another binary.
        prop = self.pkg["contributes"]["configuration"]["properties"]["prufgate.path"]
        self.assertEqual(prop["scope"], "machine")
        self.assertEqual(prop["default"], "prufgate")

    def test_untrusted_workspaces_are_not_supported(self):
        self.assertIs(self.pkg["capabilities"]["untrustedWorkspaces"]["supported"], False)

    def test_no_runtime_dependencies_and_a_lock_file(self):
        self.assertNotIn("dependencies", self.pkg)
        self.assertEqual(set(self.pkg["devDependencies"]), {"@types/node", "@types/vscode", "@vscode/vsce", "typescript"})
        lock = json.loads((EXT / "package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock["packages"][""]["version"], __version__)

    def test_types_match_the_minimum_engine(self):
        # vsce refuses a package whose @types/vscode is newer than engines.vscode.
        self.assertEqual("^" + self.pkg["devDependencies"]["@types/vscode"], self.pkg["engines"]["vscode"])


if __name__ == "__main__":
    unittest.main()
