"""A branch must not switch PrufGate off through its own configuration.

The configuration is read from the branch under review, so the diff guard
always analyses PrufGate's configuration files, whatever they exclude or
exempt, and flags a deleted or renamed one.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from prufgate.config import PrufGateConfig
from prufgate.diff_guard.tamper_detector import scan_diff_for_tampering

ROOT = Path(__file__).resolve().parent.parent
RULE = "prufgate-config-self-exemption"


def _diff(path: str, before: list[str], after: list[str]) -> str:
    body = "".join(f"-{ln}\n" for ln in before) + "".join(f"+{ln}\n" for ln in after)
    return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,{len(before)} +1,{len(after)} @@\n{body}"


def _severities(diff: str, cfg: PrufGateConfig | None = None) -> list[str]:
    return [f.severity for f in scan_diff_for_tampering(diff, config=cfg or PrufGateConfig()) if f.rule == RULE]


class ConfigCannotExcludeItself(unittest.TestCase):
    def test_catch_all_exclude_is_p0_even_when_the_head_config_excludes_everything(self):
        diff = _diff(".prufgate/config.yaml", ["version: 1"], ["version: 1", 'exclude: ["**"]'])
        head = PrufGateConfig(exclude=["**"])
        self.assertEqual(_severities(diff, head), ["P0"])

    def test_catch_all_spellings(self):
        for entry in ('"**"', "'*'", "'**/*'", '"."', '".prufgate/**"', '".prufgate.yml"'):
            with self.subTest(entry=entry):
                diff = _diff(".prufgate.yml", ["exclude:"], ["exclude:", f"  - {entry}"])
                self.assertEqual(_severities(diff), ["P0"])

    def test_a_narrow_exclude_stays_p1(self):
        diff = _diff(".prufgate/config.yaml", ["version: 1"], ["version: 1", 'exclude: ["src/**"]'])
        self.assertEqual(_severities(diff), ["P1"])

    def test_head_config_cannot_exempt_its_own_finding(self):
        diff = _diff(".prufgate/config.yaml", ["version: 1"], ["version: 1", 'exclude: ["**"]'])
        head = PrufGateConfig(exempt={(".prufgate/config.yaml", RULE): "#1: fine"})
        self.assertEqual(_severities(diff, head), ["P0"])

    def test_deleted_config_is_flagged(self):
        diff = (
            "diff --git a/.prufgate/config.yaml b/.prufgate/config.yaml\ndeleted file mode 100644\n"
            "--- a/.prufgate/config.yaml\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-version: 1\n-packs: [core, cti]\n"
        )
        self.assertEqual(_severities(diff, PrufGateConfig(exclude=["**"])), ["P1"])

    def test_renamed_away_config_is_flagged(self):
        diff = (
            "diff --git a/.prufgate/config.yaml b/old-config.yaml\nsimilarity index 100%\n"
            "rename from .prufgate/config.yaml\nrename to old-config.yaml\n"
        )
        self.assertEqual(_severities(diff), ["P1"])

    def test_an_unrelated_file_under_a_catch_all_exclude_is_still_skipped(self):
        diff = _diff("src/a.ts", ["const a = 1;"], ["// @ts-ignore", "const a = 1;"])
        self.assertEqual(scan_diff_for_tampering(diff, config=PrufGateConfig(exclude=["**"])), [])


class CheckEndToEnd(unittest.TestCase):
    """The reported bypass: `exclude: ["**"]` plus fabricated code passed with rc 0."""

    def _git(self, repo: Path, *args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
            cwd=repo, check=True, capture_output=True,
        )

    def test_exclude_everything_branch_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self._git(repo, "init", "-q", "-b", "main")
            (repo / "src").mkdir()
            (repo / "src" / "app.py").write_text("def ok():\n    return 1\n")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-qm", "base")
            self._git(repo, "checkout", "-qb", "feature")
            (repo / ".prufgate").mkdir()
            (repo / ".prufgate" / "config.yaml").write_text('version: 1\nexclude: ["**"]\n')
            (repo / "src" / "app.py").write_text("import leftpadx\nMOCK_DATA = {'status': 'ok'}\n")
            self._git(repo, "add", ".")
            self._git(repo, "commit", "-qm", "feature")
            env = {**os.environ, "PYTHONPATH": str(ROOT)}
            env.pop("PRUFGATE_BASE_REF", None)
            env.pop("GITHUB_BASE_REF", None)
            res = subprocess.run(
                [sys.executable, str(ROOT / "prufgate" / "cli.py"), "check", "--changed", "--base", "main", "--format", "json"],
                cwd=repo, capture_output=True, text=True, env=env, timeout=120,
            )
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            rules = {(f["rule"], f["severity"]) for f in json.loads(res.stdout)}
            self.assertIn((RULE, "P0"), rules)


GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com"]


def _repo(tmp: str, base: dict[str, str], head: dict[str, str | None], moves: tuple = ()) -> Path:
    repo = Path(tmp)
    subprocess.run([*GIT, "init", "-q", "-b", "main"], cwd=repo, check=True)
    files = {"src/app.py": "def ok():\n    return 1\n", **base}
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True)
    subprocess.run([*GIT, "commit", "-qm", "base"], cwd=repo, check=True)
    subprocess.run([*GIT, "checkout", "-qb", "feature"], cwd=repo, check=True)
    for src, dst in moves:
        (repo / dst).parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([*GIT, "mv", src, dst], cwd=repo, check=True)
    for rel, text in head.items():
        if text is None:
            (repo / rel).unlink()
            continue
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True)
    subprocess.run([*GIT, "commit", "-qm", "feature"], cwd=repo, check=True)
    return repo


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("PRUFGATE_BASE_REF", None)
    env.pop("GITHUB_BASE_REF", None)
    return subprocess.run([sys.executable, *args], cwd=repo, capture_output=True, text=True, env=env, timeout=120)


CFG = ".prufgate/config.yaml"
BYPASSES = {
    # name: (base files, head files, moves, expected severity)
    "flow mapping": ({CFG: "version: 1\n"}, {CFG: '{version: 1, exclude: ["**"]}\n'}, (), "P0"),
    "indented document": ({CFG: "version: 1\n"}, {CFG: ' version: 1\n exclude: ["**"]\n'}, (), "P0"),
    "merge key": ({CFG: "version: 1\n"}, {CFG: 'version: 1\n<<: {exclude: ["**"]}\n'}, (), "P0"),
    "escaped key": ({CFG: "version: 1\n"}, {CFG: 'version: 1\n"\\x65xclude": ["**"]\n'}, (), "P0"),
    "explicit key": ({CFG: "version: 1\n"}, {CFG: 'version: 1\n? exclude\n: ["**"]\n'}, (), "P0"),
    "quoted key far from the hunk": (
        {CFG: 'version: 1\n"exclude":\n' + "".join(f"  - d{i}/**\n" for i in range(6))},
        {CFG: 'version: 1\n"exclude":\n' + "".join(f"  - d{i}/**\n" for i in range(6)) + '  - "**"\n'},
        (), "P0",
    ),
    "binary diff attribute": (
        {CFG: "version: 1\n"}, {".gitattributes": ".prufgate/** -diff\n", CFG: 'version: 1\nexclude: ["**"]\n'}, (), "P0",
    ),
    "shadowing config drops a pack": (
        {".prufgate.yml": "packs: [core, web-ui, ai-safety, cti]\n"}, {CFG: "version: 1\n"}, (), "P1",
    ),
    "config moved into a subfolder": (
        {CFG: "packs: [core, web-ui, ai-safety, cti]\n"}, {}, ((CFG, "old/.prufgate/config.yaml"),), "P1",
    ),
    "new config narrows packs": ({}, {CFG: "packs: [core]\n"}, (), "P1"),
    "language removed from a list": (
        {CFG: "languages:\n  - python\n  - go\n"}, {CFG: "languages:\n  - go\n"}, (), "P1",
    ),
    "deleted config drops a pack": ({CFG: "packs: [core, web-ui, ai-safety, cti]\n"}, {CFG: None}, (), "P1"),
    "explicit packs replace the defaults": ({CFG: "packs: [cti]\n"}, {CFG: "packs: [core, cti]\n"}, (), "P1"),
}


class ConfigComparedByValue(unittest.TestCase):
    def test_every_spelling_and_location_is_caught_by_the_gate_engine(self):
        for name, (base, head, moves, sev) in BYPASSES.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                repo = _repo(tmp, base, head, moves)
                out = Path(tmp) / "dg.json"
                res = _run(repo, str(ROOT / "prufgate/diff_guard/tamper_detector.py"), "--base=main", f"--json-out={out}")
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                found = {(f["rule"], f["severity"]) for f in json.loads(out.read_text())}
                self.assertIn((RULE, sev), found)

    def test_a_tsconfig_weakening_is_not_hidden_by_a_flow_mapping_exclude(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(
                tmp,
                {CFG: "version: 1\n", "tsconfig.json": '{\n  "strict": true\n}\n'},
                {CFG: '{version: 1, exclude: ["**"]}\n', "tsconfig.json": '{\n  "strict": false\n}\n'},
            )
            res = _run(repo, str(ROOT / "prufgate/cli.py"), "check", "--changed", "--base", "main", "--format", "json")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)

    def test_head_debt_ceiling_cannot_hide_the_config_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(
                tmp,
                {CFG: "version: 1\n"},
                {CFG: 'version: 1\nexclude: ["**"]\nknown_debt:\n  prufgate-config-self-exemption: 5\n'},
            )
            res = _run(repo, str(ROOT / "prufgate/cli.py"), "check", "--changed", "--base", "main", "--format", "json")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn((RULE, "P0"), {(f["rule"], f["severity"]) for f in json.loads(res.stdout)})

    def test_unchanged_config_and_a_nested_fixture_config_are_not_flagged(self):
        fixture = "tests/fixtures/repo/.prufgate/config.yaml"
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(
                tmp,
                {CFG: f'exempt:\n  "{fixture}": {{prufgate-config-self-exemption: "#1: a fixture"}}\n'},
                {fixture: 'exclude: ["**"]\n'},
            )
            out = Path(tmp) / "dg.json"
            res = _run(repo, str(ROOT / "prufgate/diff_guard/tamper_detector.py"), "--base=main", f"--json-out={out}")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_a_dangling_symlink_does_not_switch_off_the_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp, {CFG: "version: 1\n"}, {CFG: '{version: 1, exclude: ["**"]}\n'})
            (repo / ".prufgate.yml").symlink_to("/nonexistent/prufgate-test-target")
            out = Path(tmp) / "dg.json"
            res = _run(repo, str(ROOT / "prufgate/diff_guard/tamper_detector.py"), "--base=main", f"--json-out={out}")
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn((RULE, "P0"), {(f["rule"], f["severity"]) for f in json.loads(out.read_text())})

    def test_an_unchanged_symlinked_config_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run([*GIT, "init", "-q", "-b", "main"], cwd=repo, check=True)
            (repo / "configs").mkdir()
            (repo / "configs" / "pg.yaml").write_text("exclude: [vendor]\n")
            (repo / ".prufgate").mkdir()
            (repo / CFG).symlink_to("../configs/pg.yaml")
            subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True)
            subprocess.run([*GIT, "commit", "-qm", "base"], cwd=repo, check=True)
            subprocess.run([*GIT, "checkout", "-qb", "feature"], cwd=repo, check=True)
            (repo / "other.py").write_text("x = 1\n")
            subprocess.run([*GIT, "add", "-A"], cwd=repo, check=True)
            subprocess.run([*GIT, "commit", "-qm", "feature"], cwd=repo, check=True)
            out = Path(tmp) / "dg.json"
            res = _run(repo, str(ROOT / "prufgate/diff_guard/tamper_detector.py"), "--base=main", f"--json-out={out}")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_adding_a_pack_or_a_zero_ceiling_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp, {CFG: "version: 1\n"}, {CFG: "packs: [cti]\nknown_debt:\n  stub-click-handler: 0\n"})
            out = Path(tmp) / "dg.json"
            res = _run(repo, str(ROOT / "prufgate/diff_guard/tamper_detector.py"), "--base=main", f"--json-out={out}")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_a_tightened_config_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(tmp, {CFG: 'exclude: ["docs/**", "dist/**"]\n'}, {CFG: 'exclude: ["dist/**"]\npacks: [core, web-ui, ai-safety, cti]\n'})
            out = Path(tmp) / "dg.json"
            res = _run(repo, str(ROOT / "prufgate/diff_guard/tamper_detector.py"), "--base=main", f"--json-out={out}")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
