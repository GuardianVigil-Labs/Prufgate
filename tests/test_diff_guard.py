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


if __name__ == "__main__":
    unittest.main()
