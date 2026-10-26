"""Unit tests for Engine 3: Diff-Scoped Agent Tampering Guard (`prufgate/diff_guard/tamper_detector.py`)."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from prufgate.config import PrufGateConfig
from prufgate.diff_guard import linter_drift
from prufgate.diff_guard.tamper_detector import (
    main,
    parse_unified_diff,
    run_self_check,
    scan_diff_for_tampering,
    with_linter_drift,
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


class TestHarnessEdits(unittest.TestCase):
    """Edits to the test runner, assertions, conftest hooks, test config or test command."""

    _diff = staticmethod(TestFakeExit._diff)

    def _rules(self, diff_text: str, cfg: PrufGateConfig | None = None) -> list[str]:
        return [f.rule for f in scan_diff_for_tampering(diff_text, config=cfg)]

    FLAGGED = (
        ("tests/conftest.py", ["import unittest","unittest.TestCase.assertEqual = lambda *a, **k: None"]),
        ("tests/conftest.py", ["from unittest import TestCase","TestCase.assertTrue = lambda *a: None"]),
        ("tests/conftest.py", ["import pytest","pytest.approx = lambda v, **k: v"]),
        ("tests/conftest.py", ["import builtins","builtins.isinstance = lambda *a: True"]),
        ("tests/conftest.py", ["sys.modules['pytest'] = object()"]),
        ("tests/conftest.py", ["import unittest","setattr(unittest.TestCase, 'assertIn', lambda *a: None)"]),
        ("tests/helpers.py", ["class Base(unittest.TestCase):","    def assertEqual(self, a, b):","        pass"]),
        ("src/money.py", ["class Money:","    def __eq__(self, other):","        return True"]),
        ("src/money.py", ["class Money:","    __ne__ = lambda self, other: False"]),
        ("tests/conftest.py", ["def pytest_runtest_makereport(item, call):","    rep = call","    rep.outcome = 'passed'"]),
        ("tests/conftest.py", ["def pytest_sessionfinish(session, exitstatus):","    session.exitstatus = 0"]),
        ("tests/conftest.py", ["def pytest_terminal_summary(terminalreporter):","    terminalreporter.stats.pop('failed', None)"]),
        ("tests/conftest.py", ["def pytest_pyfunc_call(pyfuncitem):","    return True"]),
        ("tests/conftest.py", ["def pytest_collection_modifyitems(config, items):","    items[:] = [i for i in items if 'billing' not in i.nodeid]"]),
        ("tests/conftest.py", ["def pytest_collection_modifyitems(session, config, items):","    items.clear()"]),
        ("tests/conftest.py", ["def pytest_ignore_collect(collection_path, config):","    return True"]),
        ("jest.setup.js", ["global.expect = () => ({ toBe() {}, toEqual() {} });"]),
        ("vitest.setup.ts", ["expect.extend({","  toEqual() {","    return { pass: true, message: () => '' };","  },","});"]),
        ("jest.config.js", ["  passWithNoTests: true,"]),
        ("jest.config.js", ["  testPathIgnorePatterns: ['/node_modules/', '/tests/'],"]),
        ("vitest.config.ts", ["    exclude: [","      '**/*.test.ts',","    ],"]),
        ("jest.config.js", ["  testMatch: [],"]),
        ("jest.config.js", ["  silent: true,","  forceExit: true,"]),
        ("pyproject.toml", ['addopts = "-ra --deselect tests/test_billing.py::test_refund"']),
        ("pytest.ini", ["addopts = --ignore=tests/integration"]),
        ("package.json", ['    "test": "exit 0",']),
        ("package.json", ['    "test": "jest || true",']),
        ("package.json", ['    "test": "echo ok",']),
        ("Makefile", ["test:","\t@true"]),
        ("Makefile", ["test:","\t-pytest"]),
        ("Makefile", ["check:","\tpytest || true"]),
        ("tox.ini", ["commands = - pytest"]),
        ("noxfile.py", ["    session.run('pytest', success_codes=[0, 1])"]),
    )

    NEAR_MISSES = (
        ("tests/conftest.py", ["import unittest","unittest.TestCase.maxDiff = None"]),
        ("tests/test_x.py", ["import pytest","def test_x():","    assert 0.1 + 0.2 == pytest.approx(0.3)"]),
        ("tests/test_x.py", ["def test_x(monkeypatch):","    monkeypatch.setattr(app.config, 'debug', True)"]),
        ("tests/helpers.py", ["class Base(unittest.TestCase):","    def assertValidOrder(self, o):","        self.assertEqual(o.total, 3)"]),
        ("src/money.py", ["class Money:","    def __eq__(self, other):","        return self.amount == other.amount"]),
        ("tests/helpers.py", ["class AnyString:","    def __eq__(self, other):","        return True"]),
        ("src/money.py", ["class Money:","    def __ne__(self, other):","        return not self == other"]),
        ("tests/conftest.py", ["def pytest_runtest_makereport(item, call):","    if call.excinfo:","        item.failed = True"]),
        ("tests/conftest.py", ["def pytest_collection_modifyitems(config, items):","    items.sort(key=lambda i: i.nodeid)","    for item in items:","        item.add_marker('slow')"]),
        ("tests/conftest.py", ["def pytest_ignore_collect(collection_path, config):","    return collection_path.name == 'legacy'"]),
        ("tests/conftest.py", ["def pytest_sessionfinish(session, exitstatus):","    print(session.exitstatus)"]),
        ("vitest.setup.ts", ["expect.extend({","  toBeCents(received) {","    return { pass: Number.isInteger(received), message: () => '' };","  },","});"]),
        ("tests/setup.js", ["const expect = require('chai').expect;"]),
        ("jest.config.js", ["  passWithNoTests: false,"]),
        ("jest.config.js", ["  testPathIgnorePatterns: ['/node_modules/', '/dist/'],"]),
        ("vitest.config.ts", ["    exclude: [...configDefaults.exclude, 'e2e/**'],"]),
        ("jest.config.js", ["  silent: true,"]),
        ("pyproject.toml", ['addopts = "-ra --strict-markers"']),
        ("package.json", ['    "test": "echo \\"Error: no test specified\\" && exit 1",']),
        ("package.json", ['    "test": "vitest run",']),
        ("package.json", ['    "lint": "eslint . || true",']),
        ("Makefile", ["test:","\t$(PYTHON) -m pytest"]),
        ("Makefile", ["clean:","\t-rm -rf build"]),
        ("tox.ini", ["commands = pytest {posargs}"]),
        ("noxfile.py", ["    session.run('pytest', success_codes=[0, 5])"]),
        ("src/cli.ts", ["global.expect = 1;"]),
        # Every object is truthy already; `__bool__` returning True changes nothing.
        ("src/money.py", ["class Result:","    def __bool__(self):","        return True"]),
    )

    def test_harness_edits_are_flagged(self) -> None:
        for path, lines in self.FLAGGED:
            with self.subTest(path=path, lines=lines):
                self.assertTrue(self._rules(self._diff(path, *lines)))

    def test_near_misses_are_not_flagged(self) -> None:
        for path, lines in self.NEAR_MISSES:
            with self.subTest(path=path, lines=lines):
                self.assertEqual(self._rules(self._diff(path, *lines)), [])

    def test_severity_and_rule_per_kind(self) -> None:
        for (path, lines), rule, severity in (
            (("src/money.py", ["class Money:", "    def __eq__(self, other):", "        return True"]), "always-true-equality", "P1"),
            (("package.json", ['    "test": "exit 0",']), "test-script-neutered", "P0"),
            (("tests/conftest.py", ["def pytest_collection_modifyitems(config, items):", "    items.clear()"]), "pytest-collection-deselect", "P1"),
        ):
            with self.subTest(rule=rule):
                found = scan_diff_for_tampering(self._diff(path, *lines))
                self.assertEqual([(f.rule, f.severity) for f in found], [(rule, severity)])

    def test_hunk_inside_a_hook_uses_the_function_header(self) -> None:
        diff_text = (
            "diff --git a/tests/conftest.py b/tests/conftest.py\n--- a/tests/conftest.py\n+++ b/tests/conftest.py\n"
            "@@ -8,2 +8,3 @@ def pytest_runtest_makereport(item, call):\n"
            "     report = outcome.get_result()\n+    report.outcome = \"passed\"\n     return report\n"
        )
        self.assertEqual(self._rules(diff_text), ["pytest-result-rewrite"])

    def test_only_added_lines_are_flagged(self) -> None:
        diff_text = (
            "diff --git a/src/money.py b/src/money.py\n--- a/src/money.py\n+++ b/src/money.py\n"
            "@@ -1,3 +1,4 @@\n class Money:\n     def __eq__(self, other):\n         return True\n+    currency = \"EUR\"\n"
        )
        self.assertEqual(self._rules(diff_text), [])

    def test_exemption_applies(self) -> None:
        cfg = PrufGateConfig(exempt={("package.json", "test-script-neutered"): "#12: placeholder package"})
        self.assertEqual(self._rules(self._diff("package.json", '    "test": "exit 0",'), cfg), [])


NEEDS_TOML = unittest.skipIf(linter_drift.tomllib is None, "tomllib needs Python 3.11+; TOML keeps the line-based check")


class TestLinterDriftByValue(unittest.TestCase):
    """Linter configs compared by value: every weakening kind per format, and the near misses."""

    def _whys(self, name: str, base: str | None, head: str) -> str:
        got = linter_drift.compare(name, base, head)
        self.assertIsNotNone(got)
        return " | ".join(w for w, _, _ in got)

    def assertFlags(self, name: str, base: str | None, head: str, *entries: str) -> None:
        whys = self._whys(name, base, head)
        self.assertTrue(whys, f"{name}: nothing flagged")
        for e in entries:
            self.assertIn(e, whys)

    def assertClean(self, name: str, base: str | None, head: str) -> None:
        self.assertEqual(self._whys(name, base, head), "")

    @NEEDS_TOML
    def test_ruff_toml_weakenings(self) -> None:
        cases = [
            ('[lint.per-file-ignores]\n"tests/*" = ["S101"]\n', '[lint.per-file-ignores]\n"tests/*" = ["S101", "S314"]\n', "S314"),
            ("[lint.per-file-ignores]\n", '[lint.per-file-ignores]\n"src/*" = ["S"]\n', "src/*"),
            ('[lint]\nignore = [\n    "E402",\n]\n', '[lint]\nignore = [\n    "E402",\n    "E501",\n]\n', "E501"),
            ("[lint]\n", '[lint]\nextend-ignore = ["B"]\n', "B"),
            ("", 'exclude = ["src/legacy"]\n', "src/legacy"),
            ('extend-exclude = ["a"]\n', 'extend-exclude = ["a", "app"]\n', "app"),
            ("[lint]\n", '[lint.extend-per-file-ignores]\n"x.py" = ["F401"]\n', "x.py"),
            ('[lint]\nselect = ["E", "S", "B"]\n', '[lint]\nselect = ["E"]\n', "removes S, B"),
        ]
        for name in ("ruff.toml", ".ruff.toml"):
            for base, head, entry in cases:
                with self.subTest(name=name, head=head):
                    self.assertFlags(name, base, head, entry)

    @NEEDS_TOML
    def test_pyproject_ruff_and_mypy(self) -> None:
        self.assertFlags("pyproject.toml", '[tool.ruff.lint]\nignore = []\n', '[tool.ruff.lint]\nignore = ["S608"]\n', "S608")
        self.assertFlags(
            "pyproject.toml",
            '[[tool.mypy.overrides]]\nmodule = "app.*"\nwarn_unused_ignores = true\n',
            '[[tool.mypy.overrides]]\nmodule = "app.*"\nwarn_unused_ignores = true\nignore_errors = true\n',
            "ignore_errors",
        )
        self.assertFlags("pyproject.toml", "[tool.mypy]\nstrict = true\n", "[tool.mypy]\nstrict = false\n", "strict")
        self.assertFlags("pyproject.toml", "[tool.mypy]\nstrict = true\n", "[tool.mypy]\n", "removed")
        # Sections other tools own are not linter settings.
        self.assertClean("pyproject.toml", "[tool.pytest.ini_options]\n", '[tool.pytest.ini_options]\nfilterwarnings = ["ignore"]\n')

    def test_tsconfig_jsonc(self) -> None:
        base = '{\n  // comment "with quotes"\n  "compilerOptions": {"strict": true, "outDir": "dist//x",},\n  /* block */ "exclude": ["dist"],\n}\n'
        self.assertFlags("tsconfig.json", base, base.replace('"strict": true', '"strict": false'), "strict")
        self.assertFlags("tsconfig.json", base, base.replace('["dist"]', '["dist", "src/legacy"]'), "src/legacy")
        self.assertFlags("tsconfig.app.json", '{"exclude": []}', '{"exclude": ["tests"]}', "tests")
        got = linter_drift.compare("tsconfig.json", '{"compilerOptions": {}}', '{"compilerOptions": {"skipLibCheck": true}}')
        self.assertEqual([(w.split()[0], sev) for w, _, sev in got], [("`compilerOptions.skipLibCheck`", "P2")])
        # Near misses: build output excluded, strictness raised, string text that looks like a comment.
        self.assertClean("tsconfig.json", base, base.replace('["dist"]', '["dist", "coverage"]'))
        self.assertClean("tsconfig.json", base.replace('"strict": true', '"strict": false'), base)
        self.assertClean("tsconfig.json", base, base.replace("dist//x", "dist//y"))

    def test_biome(self) -> None:
        self.assertFlags("biome.json", '{"files": {}}', '{"files": {"ignore": ["src/**"]}}', "src/**")
        self.assertFlags("biome.json", '{"linter": {"rules": {"recommended": true}}}', '{"linter": {"rules": {"recommended": false}}}', "recommended")
        self.assertFlags("biome.jsonc", '{"linter": {"rules": {"style": {"noVar": "error"}}}}', '{"linter": {"rules": {"style": {"noVar": "off"}}}}', "noVar")
        self.assertClean("biome.json", '{"files": {"ignore": ["src/**"]}}', '{"files": {"ignore": []}}')

    def test_eslint_json_and_yaml(self) -> None:
        self.assertFlags(".eslintrc.json", '{"ignorePatterns": []}', '{"ignorePatterns": ["src/api/**"]}', "src/api/**")
        self.assertFlags(
            ".eslintrc.json",
            '{"rules": {"no-eval": "error"}, "overrides": [{"files": ["*.ts"], "rules": {}}]}',
            '{"rules": {"no-eval": "error"}, "overrides": [{"files": ["*.ts"], "rules": {"no-eval": ["off"]}}]}',
            "no-eval",
        )
        self.assertFlags(".eslintrc.yml", "rules:\n  eqeqeq: error\n", "rules:\n  eqeqeq: 0\n", "eqeqeq")
        self.assertFlags(".eslintrc", '{"rules": {}}', 'rules:\n  no-console: "off"\n', "no-console")
        self.assertClean(".eslintrc.json", '{"rules": {"no-eval": "off"}}', '{"rules": {"no-eval": "error"}}')

    def test_golangci(self) -> None:
        base = "linters:\n  enable: [gosec, errcheck]\nissues:\n  exclude-rules: []\n"
        self.assertFlags(".golangci.yml", base, base.replace("[gosec, errcheck]", "[errcheck]"), "removes gosec")
        self.assertFlags(".golangci.yml", base, base + "  exclude-dirs: [internal]\n", "internal")
        self.assertFlags(".golangci.yaml", base, base.replace("exclude-rules: []", "exclude-rules:\n    - linters: [gosec]\n      path: api/"), "gosec")
        self.assertFlags(".golangci.yml", base, base.replace("linters:\n", "linters:\n  disable: [govet]\n"), "govet")
        self.assertFlags(".golangci.yml", "version: '2'\nlinters:\n  exclusions:\n    paths: []\n",
                         "version: '2'\nlinters:\n  exclusions:\n    paths: [gen/]\n", "gen/")
        self.assertClean(".golangci.yml", base, base.replace("[gosec, errcheck]", "[gosec, errcheck, govet]"))

    def test_new_file_is_compared_with_empty(self) -> None:
        self.assertFlags("biome.json", None, '{"files": {"ignore": ["lib/**"]}}', "lib/**")
        self.assertClean(".eslintrc.json", None, '{"rules": {"no-eval": "error"}}')

    def test_unparseable_returns_none(self) -> None:
        self.assertIsNone(linter_drift.compare("tsconfig.json", '{"a": 1}', '{"a": '))
        self.assertIsNone(linter_drift.compare(".golangci.yml", "a: [", "a: 1\n"))
        self.assertIsNone(linter_drift.compare("setup.cfg", "", "[flake8]\nignore = E501\n"))


class TestHarnessEditsReview(unittest.TestCase):
    """Evasions and false positives found in review: each evasion must be flagged,
    each near miss must stay quiet."""

    _diff = staticmethod(TestFakeExit._diff)

    def _rules(self, diff_text: str) -> list[str]:
        return [f.rule for f in scan_diff_for_tampering(diff_text)]

    EVASIONS = (
        # collection config in a conftest
        ("tests/conftest.py", ["collect_ignore = ['test_add.py']"], "pytest-collection-deselect"),
        ("tests/sub/conftest.py", ["collect_ignore_glob = ['*_auth.py']"], "pytest-collection-deselect"),
        ("conftest.py", ["collect_ignore = ['tests/test_auth.py']"], "pytest-collection-deselect"),
        ("tests/conftest.py", ["collect_ignore.append('billing')"], "pytest-collection-deselect"),
        ("tests/conftest.py", ["import pytest", "def pytest_collection_modifyitems(config, items):", "    for i in items:",
                               "        i.add_marker(pytest.mark.skip)"], "pytest-collection-deselect"),
        ("tests/conftest.py", ["import pytest", "def pytest_collection_modifyitems(items):", "    for i in items:",
                               "        i.add_marker(pytest.mark.xfail(reason='x'))"], "pytest-collection-deselect"),
        ("tests/conftest.py", ["def pytest_ignore_collect(collection_path, config):", "    return 'test' in str(collection_path)"],
         "pytest-collection-deselect"),
        ("tests/conftest.py", ["def pytest_collection_modifyitems(items, config):", "    items.clear()"], "pytest-collection-deselect"),
        ("tests/conftest.py", ["def pytest_collection_modifyitems(*, items):", "    items.clear()"], "pytest-collection-deselect"),
        # runner patches
        ("tests/conftest.py", ["import unittest", "n = 'assertEqual'", "setattr(unittest.TestCase, n, lambda *a, **k: None)"],
         "test-runner-monkeypatch"),
        ("tests/conftest.py", ["import unittest", "object.__setattr__(unittest.TestCase, 'assertEqual', lambda *a: None)"],
         "test-runner-monkeypatch"),
        ("tests/conftest.py", ["import unittest", "type.__setattr__(unittest.TestCase, 'assertTrue', lambda *a: None)"],
         "test-runner-monkeypatch"),
        ("tests/conftest.py", ["import pytest as p", "p.approx = lambda v, **k: v"], "test-runner-monkeypatch"),
        ("tests/conftest.py", ["from unittest import TestCase as T", "T.assertEqual = lambda *a, **k: None"], "test-runner-monkeypatch"),
        ("tests/test_x.py", ["def test_x(monkeypatch):", "    monkeypatch.setattr('unittest.TestCase.assertEqual', lambda *a: None)"],
         "test-runner-monkeypatch"),
        ("tests/test_x.py", ["class T(Base):", "    def setUp(self):", "        self.assertEqual = lambda *a, **k: None"],
         "test-runner-monkeypatch"),
        ("tests/test_x.py", ["TestCase.assertEqual = lambda *a, **k: None"], "test-runner-monkeypatch"),
        ("tests/helpers.py", ["class Base(unittest.TestCase):", "    def assertEqual(self, a, b):", "        return a"],
         "test-runner-monkeypatch"),
        # equality
        ("src/money.py", ["class Money: pass", "Money.__eq__ = lambda s, o: True"], "always-true-equality"),
        ("src/money.py", ["class Money: pass", "setattr(Money, '__eq__', lambda s, o: True)"], "always-true-equality"),
        ("src/money.py", ["class AnyMoney:", "    def __eq__(self, o):", "        return True"], "always-true-equality"),
        ("src/money.py", ["class MoneyMatcher:", "    def __eq__(self, o):", "        return True"], "always-true-equality"),
        ("tests/helpers.py", ["class anymoney:", "    def __eq__(self, o):", "        return True"], "always-true-equality"),
        ("src/money.py", ["class Money:", "    def __eq__(self, o):", "        return isinstance(o, Money) or True"], "always-true-equality"),
        ("src/money.py", ["class Money:", "    def __eq__(self, o):", "        if not isinstance(o, Money):",
                          "            return NotImplemented", "        return True"], "always-true-equality"),
        # result rewrites
        ("tests/conftest.py", ["def pytest_runtest_makereport(item, call):", "    setattr(rep, 'outcome', 'passed')"], "pytest-result-rewrite"),
        ("tests/conftest.py", ["P = 'passed'", "def pytest_runtest_makereport(item, call):", "    rep.outcome = P"], "pytest-result-rewrite"),
        ("tests/conftest.py", ["def pytest_runtest_makereport(item, call):", "    call.outcome = 'skipped'"], "pytest-result-rewrite"),
        ("tests/conftest.py", ["def pytest_sessionfinish(session, exitstatus):", "    setattr(session, 'exitstatus', 0)"], "pytest-result-rewrite"),
        ("tests/conftest.py", ["def pytest_sessionfinish(session, exitstatus):", "    session.exitstatus = exitstatus - exitstatus"],
         "pytest-result-rewrite"),
        ("tests/conftest.py", ["def pytest_sessionfinish(session, exitstatus):", "    session.exitstatus *= 0"], "pytest-result-rewrite"),
        ("plugins/pytest_quiet.py", ["def reset(reporter):", "    reporter.stats.pop('failed', None)"], "pytest-result-rewrite"),
        # pytest options and settings
        ("pyproject.toml", ["[tool.pytest.ini_options]", "addopts = \"-k 'not auth'\""], "test-config-weakening"),
        ("pyproject.toml", ["[tool.pytest.ini_options]", "addopts = \"-m 'not security'\""], "test-config-weakening"),
        ("pytest.ini", ["[pytest]", "addopts = -p no:python"], "test-config-weakening"),
        ("pyproject.toml", ["[tool.pytest.ini_options]", 'testpaths = ["docs"]'], "test-config-weakening"),
        ("pyproject.toml", ["[tool.pytest.ini_options]", 'python_files = ["nothing_*.py"]'], "test-config-weakening"),
        ("pytest.ini", ["[pytest]", "norecursedirs = tests"], "test-config-weakening"),
        # Jest / Vitest
        ("jest.config.ts", ["export default {", "  testPathIgnorePatterns: ['<rootDir>/src/auth'],", "};"], "test-config-weakening"),
        ("jest.config.ts", ["export default {", "  roots: ['<rootDir>/docs'],", "};"], "test-config-weakening"),
        ("jest.config.ts", ["export default {", "  testRegex: 'nomatch$',", "};"], "test-config-weakening"),
        ("jest.config.js", ["module.exports = {", "  testMatch: [", "  ],", "};"], "test-config-weakening"),
        ("vitest.workspace.ts", ["export default [{ test: { passWithNoTests: true } }]"], "test-config-weakening"),
        ("vitest.config.ts", ["export default { test: { exclude: ['**/*.test.ts'] } }"], "test-config-weakening"),
        ("package.json", ['  "jest": {', '    "testPathIgnorePatterns": ["/tests/"]', "  },"], "test-config-weakening"),
        # test scripts
        ("package.json", ['    "test": "jest || echo ok",'], "test-script-neutered"),
        ("package.json", ['    "test": "vitest run || echo passed",'], "test-script-neutered"),
        ("package.json", ['    "test": "jest | cat",'], "test-script-neutered"),
        ("package.json", ['    "test": "exit",'], "test-script-neutered"),
        ("package.json", ['    "test": "npm run lint",'], "test-script-neutered"),
        ("Makefile", ["test:", "\tpytest | tee log.txt"], "test-script-neutered"),
        ("Makefile", ["test: ; @true"], "test-script-neutered"),
        ("tox.ini", ["commands = pytest || true"], "test-script-neutered"),
        # JS patches
        ("tests/setup.ts", ["Object.assign(globalThis, { expect: () => ({}) });"], "test-runner-monkeypatch"),
        ("tests/setup.ts", ["Object.defineProperty(globalThis, 'expect', { value: () => ({}) });"], "test-runner-monkeypatch"),
        ("tests/setup.ts", ["globalThis['expect'] = () => ({});"], "test-runner-monkeypatch"),
        ("tests/setup.ts", ["chai.Assertion.prototype['equal'] = function() {};"], "test-runner-monkeypatch"),
        ("tests/setup.ts", ["vi.mock('vitest', () => ({ expect: () => ({}) }));"], "test-runner-monkeypatch"),
        ("tests/setup.ts", ["const ok = true;", "expect.extend({ toBeValid() { return { pass: ok, message: () => '' }; } });"],
         "test-runner-monkeypatch"),
        ("tests/setup.ts", ["expect.extend({ toBeValid() { return { pass: 1, message: () => '' }; } });"], "test-runner-monkeypatch"),
        ("tests/setup.ts", ["expect.extend({ toEqual() { return { \"pass\": true, message: () => '' }; } });"], "test-runner-monkeypatch"),
    )

    NEAR_MISSES = (
        # result and collection rules stay in pytest plugin files
        ("src/jobs/runner.py", ["def summarize(results):", "    stats = {}", "    stats['failed'] = sum(1 for r in results if not r.ok)",
                                "    return stats"]),
        ("src/metrics.py", ["class M:", "    def reset(self):", "        self.stats.clear()"]),
        ("src/ci/report.py", ["def mark(build):", "    build.outcome = 'passed'"]),
        ("src/worker/job.py", ["class Job:", "    def done(self):", "        self.outcome = 'passed'", "        self.exitstatus = 0"]),
        ("tests/conftest.py", ["def pytest_runtest_logreport(report):", "    report.outcome = 'skipped'"]),
        ("tests/conftest.py", ["collect_ignore = ['setup.py']"]),
        ("tests/conftest.py", ["collect_ignore = []"]),
        ("tests/conftest.py", ["collect_ignore_glob = ['fixtures/*']"]),
        ("tests/conftest.py", ["import pytest", "def pytest_collection_modifyitems(config, items):", "    skip = pytest.mark.skip(reason='slow')",
                               "    for i in items:", "        if 'slow' in i.keywords and not config.getoption('--runslow'):",
                               "            i.add_marker(skip)"]),
        ("tests/conftest.py", ["def pytest_ignore_collect(collection_path, config):", "    return collection_path.name == 'legacy'"]),
        ("tests/conftest.py", ["import unittest.util", "unittest.util._MAX_LENGTH = 2000"]),
        ("tests/test_x.py", ["def test_x(monkeypatch):", "    monkeypatch.setattr('app.settings.DEBUG', True)"]),
        ("tests/test_x.py", ["class T(Base):", "    def setUp(self):", "        self.assertion_count = 0"]),
        # equality: the exact matcher allowance
        ("tests/helpers.py", ["class AnyMoney:", "    def __eq__(self, o):", "        return True"]),
        ("tests/helpers.py", ["class OrderMatcher:", "    def __eq__(self, o):", "        return True"]),
        ("src/money.py", ["class Anything(unittest.mock._ANY):", "    def __eq__(self, o):", "        return True"]),
        ("src/money.py", ["class Money:", "    def __eq__(self, o):", "        if self is o:", "            return True",
                          "        return self.amount == o.amount"]),
        ("src/money.py", ["class ElementNode:", "    def __len__(self):", "        return len(self.children)", "    def __bool__(self):",
                          "        return True"]),
        # commands and configs: whole recipes, test blocks only, routine entries
        ("Makefile", ["test:", "\t@echo \"Running tests\"", "\tpytest -q"]),
        ("Makefile", ["ci: lint test", "\t@echo done"]),
        ("Makefile", ["test:", "\tset -o pipefail; pytest | tee log.txt"]),
        ("vitest.config.ts", ["export default defineConfig({", "  test: {", "    coverage: {", "      exclude: ['**/*.test.ts', 'tests/**'],",
                              "    },", "  },", "});"]),
        ("vite.config.ts", ["export default defineConfig({", "  optimizeDeps: { include: [] },", "});"]),
        ("vitest.config.ts", ["export default defineConfig({ test: { exclude: [...configDefaults.exclude, 'tests/e2e/**'] } });"]),
        ("vitest.config.ts", ["export default defineConfig({ test: { include: ['src/**/*.test.ts'] } });"]),
        ("package.json", ['  "files": ["dist"],', '  "exclude": ["test"]']),
        ("pyproject.toml", ["[tool.coverage.run]", 'omit = ["tests/*"]', 'addopts = "--ignore=tests"']),
        ("pytest.ini", ["[pytest]", "addopts = --ignore=docs -p no:cacheprovider"]),
        ("pytest.ini", ["[pytest]", "markers =", "    slow: deselect with '-m \"not slow\"'"]),
        ("pyproject.toml", ["[tool.pytest.ini_options]", 'testpaths = ["tests"]', 'python_files = ["test_*.py"]',
                            'norecursedirs = [".venv", "build"]']),
        ("jest.config.ts", ["export default {", "  roots: ['<rootDir>/src'],", "  testMatch: ['**/*.test.ts'],", "};"]),
        ("package.json", ['    "test:lint": "eslint .",']),
        ("package.json", ['    "test": "npm run lint && jest",']),
        ("package.json", ['    "test": "jest; exit",']),
        ("tests/setup.ts", ["Object.assign(globalThis, { fetch: mockFetch });"]),
    )

    def test_evasions_are_flagged(self) -> None:
        for path, lines, rule in self.EVASIONS:
            with self.subTest(path=path, lines=lines):
                self.assertIn(rule, self._rules(self._diff(path, *lines)))

    def test_near_misses_are_not_flagged(self) -> None:
        for path, lines in self.NEAR_MISSES:
            with self.subTest(path=path, lines=lines):
                self.assertEqual(self._rules(self._diff(path, *lines)), [])

    def test_method_added_after_a_deeper_body(self) -> None:
        diff_text = (
            "diff --git a/src/ledger/money.py b/src/ledger/money.py\n--- a/src/ledger/money.py\n+++ b/src/ledger/money.py\n"
            "@@ -2,3 +2,6 @@ class Money:\n         self.amount = amount\n         self.currency = currency\n         self.valid = True\n"
            "+\n+    def __eq__(self, other):\n+        return True\n"
        )
        self.assertEqual(self._rules(diff_text), ["always-true-equality"])

    def test_method_after_a_deeper_body_in_a_test_matcher(self) -> None:
        diff_text = (
            "diff --git a/tests/helpers.py b/tests/helpers.py\n--- a/tests/helpers.py\n+++ b/tests/helpers.py\n"
            "@@ -2,2 +2,5 @@ class AnyOrder:\n         self.kind = kind\n         self.valid = True\n"
            "+\n+    def __eq__(self, other):\n+        return True\n"
        )
        self.assertEqual(self._rules(diff_text), [])

    def test_makefile_recipe_losing_its_runner(self) -> None:
        diff_text = (
            "diff --git a/Makefile b/Makefile\n--- a/Makefile\n+++ b/Makefile\n@@ -1,3 +1,2 @@\n test:\n"
            " \t@echo \"Running tests\"\n-\tpytest -q\n"
        )
        self.assertEqual(self._rules(diff_text), ["test-script-neutered"])

    def test_makefile_other_target_losing_a_line(self) -> None:
        diff_text = (
            "diff --git a/Makefile b/Makefile\n--- a/Makefile\n+++ b/Makefile\n@@ -1,5 +1,4 @@\n test:\n"
            " \t@echo \"Running tests\"\n clean:\n-\trm -rf dist\n \trm -rf build\n"
        )
        self.assertEqual(self._rules(diff_text), [])


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=cwd, check=True, capture_output=True)


def _diff(cwd: Path) -> str:
    subprocess.run(["git", "add", "-A"], cwd=cwd, check=True, capture_output=True)
    return subprocess.run(["git", "diff", "--cached", "HEAD"], cwd=cwd, check=True, capture_output=True, text=True).stdout


class TestWithLinterDrift(unittest.TestCase):
    """The by-value result replaces the line-based one only when both sides parse and a base exists."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _git(self.root, "init", "-q")
        (self.root / "tsconfig.json").write_text('{\n  "exclude": [\n    "dist"\n  ]\n}\n', encoding="utf-8")
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-qm", "base")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, diff: str, root: Path | None = None) -> list:
        cfg = PrufGateConfig()
        return with_linter_drift(scan_diff_for_tampering(diff, config=cfg), diff, root or self.root, None, cfg)

    def test_entry_on_its_own_line_is_flagged(self) -> None:
        (self.root / "tsconfig.json").write_text('{\n  "exclude": [\n    "dist",\n    "src/payments"\n  ]\n}\n', encoding="utf-8")
        diff = _diff(self.root)
        self.assertEqual(scan_diff_for_tampering(diff), [])  # the line-based check misses it
        found = self._run(diff)
        self.assertEqual([(f.rule, f.severity, f.line) for f in found], [("linter-or-ci-config-weakening", "P0", 4)])
        self.assertIn("src/payments", found[0].message)

    def test_by_value_drops_line_based_false_alarm(self) -> None:
        (self.root / "tsconfig.json").write_text('{\n  "exclude": ["dist"],\n  "ignore": []\n}\n', encoding="utf-8")
        diff = _diff(self.root)
        self.assertTrue(scan_diff_for_tampering(diff))  # `"ignore": [` matches the regex
        self.assertEqual(self._run(diff), [])

    def test_new_file_against_empty_config(self) -> None:
        (self.root / ".eslintrc.json").write_text('{\n  "ignorePatterns": ["src/**"]\n}\n', encoding="utf-8")
        found = self._run(_diff(self.root))
        self.assertEqual(len(found), 1)
        self.assertIn("src/**", found[0].message)

    def test_unparseable_keeps_line_based(self) -> None:
        (self.root / "tsconfig.json").write_text('{\n  "compilerOptions": {"strict": false},\n', encoding="utf-8")
        diff = _diff(self.root)
        self.assertEqual(self._run(diff), scan_diff_for_tampering(diff))
        self.assertTrue(self._run(diff))

    def test_no_base_keeps_line_based(self) -> None:
        diff = 'diff --git a/tsconfig.json b/tsconfig.json\n--- a/tsconfig.json\n+++ b/tsconfig.json\n@@ -1,1 +1,2 @@\n {\n+  "strict": false\n'
        with tempfile.TemporaryDirectory() as plain:
            self.assertEqual(self._run(diff, Path(plain)), scan_diff_for_tampering(diff))


class TestTestConfigByValue(unittest.TestCase):
    """pytest and Jest settings compared by value with the base."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _git(self.root, "init", "-q")
        self._write("pytest.ini", "[pytest]\naddopts = -ra\n    -m 'not slow'\ntestpaths =\n    tests\n")
        self._write("package.json", '{\n  "jest": {\n    "testPathIgnorePatterns": [\n      "/node_modules/"\n    ]\n  }\n}\n')
        _git(self.root, "add", "-A")
        _git(self.root, "commit", "-qm", "base")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, name: str, text: str) -> None:
        (self.root / name).write_text(text, encoding="utf-8")

    def _run(self) -> list:
        cfg = PrufGateConfig()
        diff = _diff(self.root)
        return with_linter_drift(scan_diff_for_tampering(diff, config=cfg), diff, self.root, None, cfg)

    def test_continuation_line_option_is_flagged(self) -> None:
        self._write("pytest.ini", "[pytest]\naddopts = -ra\n    -m 'not slow'\n    -k 'not auth'\ntestpaths =\n    tests\n")
        found = self._run()
        self.assertEqual([(f.rule, f.line) for f in found], [("test-config-weakening", 4)])
        self.assertIn("not auth", found[0].message)

    def test_unchanged_marker_filter_is_not_flagged(self) -> None:
        self._write("pytest.ini", "[pytest]\naddopts = -ra\n    -m 'not slow'\n    --strict-markers\ntestpaths =\n    tests\n")
        self.assertEqual(self._run(), [])

    def test_testpaths_narrowed(self) -> None:
        self._write("pytest.ini", "[pytest]\naddopts = -ra\n    -m 'not slow'\ntestpaths =\n    tests/unit\n")
        found = self._run()
        self.assertEqual([f.rule for f in found], ["test-config-weakening"])
        self.assertIn("drops tests", found[0].message)

    def test_jest_ignore_entry_on_its_own_line(self) -> None:
        self._write("package.json",
                    '{\n  "jest": {\n    "testPathIgnorePatterns": [\n      "/node_modules/",\n      "<rootDir>/src/auth"\n    ]\n  }\n}\n')
        found = self._run()
        self.assertEqual([(f.rule, f.line) for f in found], [("test-config-weakening", 5)])

    def test_jest_routine_ignore_entry(self) -> None:
        self._write("package.json", '{\n  "jest": {\n    "testPathIgnorePatterns": [\n      "/node_modules/",\n      "/dist/"\n    ]\n  }\n}\n')
        self.assertEqual(self._run(), [])

    def test_unparseable_keeps_line_check(self) -> None:
        self._write("package.json", '{\n  "jest": {\n    "passWithNoTests": true,\n')
        self.assertEqual([f.rule for f in self._run()], ["test-config-weakening"])


if __name__ == "__main__":
    unittest.main()
