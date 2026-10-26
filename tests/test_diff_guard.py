"""Unit tests for Engine 3: Diff-Scoped Agent Tampering Guard (`prufgate/diff_guard/tamper_detector.py`)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from prufgate.config import PrufGateConfig
from prufgate.diff_guard.tamper_detector import (
    main,
    parse_unified_diff,
    run_self_check,
    scan_diff_for_tampering,
)
from prufgate.synthesizer.parse_results import parse_raw_results


class TestDiffGuardEngine(unittest.TestCase):
    """Verify diff-scoped detection of test skips, suppression smuggling, unsafe casts, and config weakening."""

    def test_builtin_self_check_passes(self) -> None:
        self.assertEqual(run_self_check(), 0)

    def test_parse_unified_diff_structure(self) -> None:
        diff_text = """diff --git a/src/app.ts b/src/app.ts
--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +10,4 @@
 const a = 1;
-const b = 2;
+const b = 3;
+const c = 4;
"""
        hunks = parse_unified_diff(diff_text)
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0].file_path, "src/app.ts")
        self.assertFalse(hunks[0].is_new_file)
        self.assertEqual(hunks[0].removed_lines, [(11, "const b = 2;")])
        self.assertEqual(hunks[0].added_lines, [(11, "const b = 3;"), (12, "const c = 4;")])

    def test_test_skip_and_focus_smuggling(self) -> None:
        # 1. Unjustified .skip and @pytest.mark.skip
        diff_bad = """diff --git a/tests/auth.test.ts b/tests/auth.test.ts
--- a/tests/auth.test.ts
+++ b/tests/auth.test.ts
@@ -4,2 +4,2 @@
-it('enforces MFA', () => {
+it.skip('enforces MFA', () => {
diff --git a/tests/test_rbac.py b/tests/test_rbac.py
--- a/tests/test_rbac.py
+++ b/tests/test_rbac.py
@@ -8,1 +8,2 @@
+@pytest.mark.skip
 def test_admin_guard():
"""
        findings = scan_diff_for_tampering(diff_bad)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule == "test-skip-smuggling" for f in findings))

        # 2. Focus leak (.only) is always flagged even with a comment
        diff_focus = """diff --git a/tests/auth.test.ts b/tests/auth.test.ts
--- a/tests/auth.test.ts
+++ b/tests/auth.test.ts
@@ -4,2 +4,2 @@
-it('enforces MFA', () => {
+it.only('enforces MFA', () => {
"""
        self.assertEqual([f.rule for f in scan_diff_for_tampering(diff_focus)], ["test-skip-smuggling"])

        # 3. Skip with issue reference (#123 or JIRA-456) is allowed
        diff_justified = """diff --git a/tests/auth.test.ts b/tests/auth.test.ts
--- a/tests/auth.test.ts
+++ b/tests/auth.test.ts
@@ -4,2 +4,3 @@
+// Skipped pending IdP sandbox migration in SEC-402
+it.skip('enforces MFA', () => {
"""
        self.assertEqual(scan_diff_for_tampering(diff_justified), [])

    def test_suppression_comment_smuggling(self) -> None:
        diff_bad = """diff --git a/src/handler.ts b/src/handler.ts
--- a/src/handler.ts
+++ b/src/handler.ts
@@ -10,2 +10,3 @@
+  // @ts-ignore
   return process(req.body);
diff --git a/src/worker.py b/src/worker.py
--- a/src/worker.py
+++ b/src/worker.py
@@ -5,2 +5,2 @@
-    run_task()
+    run_task()  # noqa
"""
        findings = scan_diff_for_tampering(diff_bad)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule == "suppression-comment-smuggling" for f in findings))
        self.assertTrue(all(f.severity == "P1" for f in findings))

        # Justified suppressions pass cleanly
        diff_good = """diff --git a/src/worker.py b/src/worker.py
--- a/src/worker.py
+++ b/src/worker.py
@@ -5,2 +5,2 @@
+    run_task()  # noqa: E402 -- sys.path configured dynamically before import
"""
        self.assertEqual(scan_diff_for_tampering(diff_good), [])

    def test_unsafe_type_cast_cascade(self) -> None:
        diff_bad = """diff --git a/src/orders.ts b/src/orders.ts
--- a/src/orders.ts
+++ b/src/orders.ts
@@ -12,2 +12,2 @@
-  return parseOrder(raw);
+  return (raw as unknown as OrderRecord);
"""
        findings = scan_diff_for_tampering(diff_bad)
        self.assertEqual([f.rule for f in findings], ["unsafe-type-cast-cascade"])

    def test_linter_and_ci_config_weakening(self) -> None:
        diff_bad = """diff --git a/tsconfig.json b/tsconfig.json
--- a/tsconfig.json
+++ b/tsconfig.json
@@ -2,3 +2,3 @@
-    "strict": true
+    "strict": false
diff --git a/.github/workflows/test.yml b/.github/workflows/test.yml
--- a/.github/workflows/test.yml
+++ b/.github/workflows/test.yml
@@ -14,2 +14,3 @@
       - name: Unit Tests
+        continue-on-error: true
         run: pytest
"""
        findings = scan_diff_for_tampering(diff_bad)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule == "linter-or-ci-config-weakening" for f in findings))
        self.assertTrue(all(f.severity == "P0" for f in findings))

    def test_config_exemptions_and_alias_support(self) -> None:
        cfg = PrufGateConfig(
            exempt={
                ("src/legacy.ts", "linter-or-type-suppression-abuse"): "Legacy migration file",
            }
        )
        diff_text = """diff --git a/src/legacy.ts b/src/legacy.ts
--- a/src/legacy.ts
+++ b/src/legacy.ts
@@ -1,2 +1,3 @@
+// @ts-ignore
 legacyCall();
"""
        self.assertEqual(scan_diff_for_tampering(diff_text, config=cfg), [])

    def test_cli_diff_file_and_synthesizer_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patch_file = root / "tamper.patch"
            patch_file.write_text(
                """diff --git a/tsconfig.json b/tsconfig.json
--- a/tsconfig.json
+++ b/tsconfig.json
@@ -2,2 +2,2 @@
-  "strict": true
+  "strict": false
""",
                encoding="utf-8",
            )
            raw_dir = root / "reports" / "raw"
            json_out = raw_dir / "diff_guard.json"

            rc = main([f"--diff-file={patch_file}", f"--json-out={json_out}", "--include-self"])
            self.assertEqual(rc, 1)
            self.assertTrue(json_out.is_file())

            data = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["rule"], "linter-or-ci-config-weakening")

            synth_findings = parse_raw_results(raw_dir)
            self.assertEqual(len(synth_findings), 1)
            self.assertEqual(synth_findings[0].tool, "diff-guard")
            self.assertEqual(synth_findings[0].rule_id, "linter-or-ci-config-weakening")
            self.assertEqual(synth_findings[0].severity, "P0")


class TestFakeExit(unittest.TestCase):
    """`test-fake-exit`: a run that ends as a pass before the tests run."""

    @staticmethod
    def _diff(path: str, *added: str, context: str = "import sys") -> str:
        body = "".join(f"+{line}\n" for line in added)
        return f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,{len(added) + 1} @@\n {context}\n{body}"

    def _rules(self, diff_text: str, cfg: PrufGateConfig | None = None) -> list[str]:
        return [f.rule for f in scan_diff_for_tampering(diff_text, config=cfg)]

    def test_flags_success_exits_in_test_code(self) -> None:
        for path, line in (
            ("tests/conftest.py", "os._exit(0)"),
            ("tests/test_orders.py", "exit()"),
            ("tests/test_orders.py", "raise SystemExit"),
            ("tests/test_orders.py", 'pytest.exit("done", returncode=0)'),
            ("tests/test_orders.py", 'pytest.skip("later", allow_module_level=True)'),
            ("src/orders.test.ts", "process.exit()"),
            ("vitest.setup.ts", "process.exit(0);"),
            ("test/helpers/boot.js", "process.exit(0)"),
        ):
            with self.subTest(path=path, line=line):
                self.assertEqual(self._rules(self._diff(path, line)), ["test-fake-exit"])

    def test_near_misses_are_not_flagged(self) -> None:
        for path, line in (
            ("tests/test_orders.py", "sys.exit(1)"),
            ("tests/test_orders.py", "sys.exit(main())"),
            ("tests/test_orders.py", '    assert "sys.exit(0)" in out'),
            ("tests/test_orders.py", "# sys.exit(0)"),
            ("tests/test_orders.py", "def exit():"),
            ("tests/test_orders.py", "app.exit(0)"),
            ("tests/test_orders.py", "raise SystemExit(2)"),
            ("tests/test_orders.py", 'pytest.skip("later #12", allow_module_level=True)'),
            ("src/orders.test.ts", "expect(() => process.exit(0)).toThrow()"),
            ("src/cli.ts", "process.exit(0)"),
            ("scripts/release.py", "sys.exit(0)"),
        ):
            with self.subTest(path=path, line=line):
                self.assertEqual(self._rules(self._diff(path, line)), [])

    def test_exit_expected_by_unittest_is_not_flagged(self) -> None:
        diff_text = self._diff(
            "tests/test_cli.py",
            "        with self.assertRaises(SystemExit):",
            "            sys.exit(0)",
            context="    def test_help(self):",
        )
        self.assertEqual(self._rules(diff_text), [])

    def test_review_reproductions_are_flagged(self) -> None:
        for path, line in (
            ("tests/conftest.py", "sys.exit(0)  # expect("),
            ("tests/conftest.py", "sys.exit(0)  # raises(SystemExit)"),
            ("tests/conftest.py", "os._exit(int())"),
            ("tests/conftest.py", "sys.exit(0x0)"),
            ("tests/conftest.py", "sys.exit(0o0)"),
            ("tests/conftest.py", "sys.exit(False)"),
            ("tests/conftest.py", "sys.exit(not 1)"),
            ("tests/conftest.py", "raise SystemExit(0) from None"),
            ("tests/conftest.py", "raise SystemExit(code=0)"),
            ("tests/conftest.py", "from sys import exit as e; e(0)"),
            ("tests/conftest.py", "getattr(sys, 'exit')(0)"),
            ("tests/conftest.py", "pytest.exit('x', 0)"),
            ("tests/conftest.py", "if True: sys.exit(0)"),
            ("tests/test_orders.py", "expect(1); sys.exit(0)"),
            ("tests/test_orders.py", 'pytest.skip("#123"); sys.exit(0)'),
            ("tests/test_cli.py", "x = 1 if expect(a) else sys.exit(0)"),
            ("tests/a.test.js", "process['exit'](0)"),
            ("tests/a.test.js", "process.exit(0) // expect("),
            ("tests/a.test.js", "process.exit(0); expect(1)"),
            ("tests/a.test.js", "expect(1); process.exit(0);"),
            ("tests/a.test.js", "expect(process.exit(0))"),
            ("vitest.setup.ts", "process.exit(false)"),
            ("vitest.setup.ts", "process.exit(undefined)"),
            ("vitest.setup.ts", "process.exit(null)"),
            ("pkg/x_test.go", "syscall.Exit(0)"),
            ("pkg/x_test.go", "os.Exit(int(0))"),
        ):
            with self.subTest(path=path, line=line):
                self.assertEqual(self._rules(self._diff(path, line)), ["test-fake-exit"])

    def test_exits_run_when_a_def_runs_or_hidden_in_constant_expressions(self) -> None:
        for lines in (
            ("def _unused(x=sys.exit(0)):", "    pass"),
            ("def _unused(*, x=os._exit(0)):", "    pass"),
            ("def _unused() -> sys.exit(0):", "    pass"),
            ("@(lambda _: sys.exit(0))", "def _unused():", "    pass"),
            ("def test_x():", "    sys.exit(0 + 0)"),
            ("def test_x():", "    sys.exit(1 - 1)"),
            ("def test_x():", "    sys.exit(0 or 0)"),
            ("def test_x():", "    rc = 0", "    sys.exit(rc)"),
        ):
            with self.subTest(lines=lines):
                self.assertEqual(self._rules(self._diff("tests/test_a.py", *lines)), ["test-fake-exit"])
        for lines in (
            ("def _unused(x=1):", "    sys.exit(0)"),
            ("def test_x():", "    sys.exit(1 + 0)"),
            ("def test_x(rc=0):", "    sys.exit(rc)"),
            ("def test_x():", "    rc = 0", "    rc = run()", "    sys.exit(rc)"),
        ):
            with self.subTest(lines=lines):
                self.assertEqual(self._rules(self._diff("tests/test_a.py", *lines)), [])

    def test_alias_imported_in_another_hunk(self) -> None:
        diff_text = (
            "diff --git a/tests/conftest.py b/tests/conftest.py\n--- a/tests/conftest.py\n+++ b/tests/conftest.py\n"
            "@@ -1,1 +1,1 @@\n from os import _exit as quit_now\n"
            "@@ -20,1 +20,2 @@\n x = 1\n+quit_now(0)\n"
        )
        self.assertEqual(self._rules(diff_text), ["test-fake-exit"])

    def test_module_level_skip_at_any_indentation(self) -> None:
        diff_text = self._diff("tests/test_a.py", "if True:", '    pytest.skip("x", allow_module_level=True)', context="import pytest")
        self.assertEqual(self._rules(diff_text), ["test-fake-exit"])

    def test_with_block_must_enclose_the_exit(self) -> None:
        diff_text = self._diff(
            "tests/test_cli.py",
            "def test_help():",
            "    with pytest.raises(SystemExit):",
            "        pass",
            "    sys.exit(0)",
        )
        self.assertEqual(self._rules(diff_text), ["test-fake-exit"])

    def test_exits_in_setup_hooks_and_called_helpers_are_flagged(self) -> None:
        for path, lines in (
            ("tests/test_a.py", ("class T(unittest.TestCase):", "    @classmethod", "    def setUpClass(cls):", "        sys.exit(0)")),
            ("tests/test_a.py", ("@pytest.fixture(autouse=True)", "def boot():", "    sys.exit(0)")),
            ("tests/test_a.py", ("def _bail():", "    sys.exit(0)", "_bail()")),
            ("tests/test_a.py", ("def _bail():", "    sys.exit(0)", "def test_x():", "    _bail()")),
            ("tests/conftest.py", ("def helper():", "    sys.exit(0)")),
            ("tests/a.test.js", ("it('x', () => {", "  process.exit(0);", "});")),
            ("pkg/main_test.go", ("func TestMain(m *testing.M) {", "\tos.Exit(0)", "}")),
        ):
            with self.subTest(path=path, lines=lines):
                self.assertEqual(self._rules(self._diff(path, *lines)), ["test-fake-exit"])

    def test_added_call_to_existing_exiting_helper_is_flagged(self) -> None:
        diff_text = (
            "diff --git a/tests/test_a.py b/tests/test_a.py\n--- a/tests/test_a.py\n+++ b/tests/test_a.py\n"
            "@@ -1,3 +1,4 @@\n def _bail():\n     sys.exit(0)\n \n+_bail()\n"
        )
        self.assertEqual([(f.rule, f.line) for f in scan_diff_for_tampering(diff_text)], [("test-fake-exit", 4)])

    def test_fixture_script_helpers_are_not_flagged(self) -> None:
        cases = (
            ("tests/fixtures/fake_cli.py", ("def main():", "    print('ok')", "    sys.exit(0)", "", 'if __name__ == "__main__":', "    main()")),
            ("tests/test_a.py", ("def _quit():", "    sys.exit(0)")),
            ("tests/test_cli.py", ("def run():", "    sys.exit(0)", "def test_run():", "    with pytest.raises(SystemExit):", "        run()")),
            ("tests/test_cli.py", ("def test_run(self):", "    self.assertRaises(SystemExit, lambda: sys.exit(0))")),
            ("tests/helpers/cli.js", ("function fakeCli() {", "  process.exit(0);", "}")),
            ("pkg/helpers_test.go", ("func runFake() {", "\tos.Exit(0)", "}")),
            ("tests/test_a.py", ('"""', "sys.exit(0)", '"""')),
        )
        for path, lines in cases:
            with self.subTest(path=path, lines=lines):
                self.assertEqual(self._rules(self._diff(path, *lines)), [])
        self.assertEqual(self._rules(self._diff("tests/test_a.py", 'pytest.skip("#12 flaky", allow_module_level=True)')), [])
        self.assertEqual(self._rules(self._diff("tests/test_a.py", "def test_x():", '    pytest.skip("#12 flaky")')), [])

    def test_line_fallback_when_the_hunk_does_not_parse(self) -> None:
        bad = "  broken("
        self.assertEqual(self._rules(self._diff("tests/test_a.py", "    sys.exit(0)  # raises(SystemExit)", bad)), ["test-fake-exit"])
        expected = self._diff("tests/test_a.py", "    with pytest.raises(SystemExit):", "        sys.exit(0)", bad)
        self.assertEqual(self._rules(expected), [])
        helper = self._diff("tests/test_a.py", "    def _quit():", "        sys.exit(0)", bad)
        self.assertEqual(self._rules(helper), [])

    def test_exemption_applies(self) -> None:
        cfg = PrufGateConfig(exempt={("tests/conftest.py", "test-fake-exit"): "documented smoke harness"})
        self.assertEqual(self._rules(self._diff("tests/conftest.py", "sys.exit(0)"), cfg), [])


if __name__ == "__main__":
    unittest.main()
