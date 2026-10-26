"""Unit tests for Engine 2: Anti-Reward-Hacking & Test Integrity (`prufgate/anti_reward_hacking/test_integrity.py`)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from prufgate.anti_reward_hacking.test_integrity import (
    is_test_file,
    main,
    run_self_check,
    scan_diff_for_reward_hacking,
    scan_test_file,
)
from prufgate.config import PrufGateConfig
from prufgate.synthesizer.parse_results import parse_raw_results


class TestAntiRewardHackingEngine(unittest.TestCase):
    """Verify multi-language test integrity and cross-diff EvilGenie detection."""

    def test_builtin_self_check_passes(self) -> None:
        self.assertEqual(run_self_check(), 0)

    def test_is_test_file_classification(self) -> None:
        self.assertTrue(is_test_file("src/auth/login.test.ts"))
        self.assertTrue(is_test_file("src/auth/login.spec.tsx"))
        self.assertTrue(is_test_file("tests/test_billing.py"))
        self.assertTrue(is_test_file("pkg/api/handler_test.go"))
        self.assertTrue(is_test_file("src/test/java/UserServiceTest.java"))
        self.assertTrue(is_test_file("src/lib.rs", "#[cfg(test)]\nmod tests { #[test] fn it_works() {} }"))
        self.assertFalse(is_test_file("tests/conftest.py"))
        self.assertFalse(is_test_file("tests/__init__.py"))
        self.assertFalse(is_test_file("src/billing/service.ts"))

    def test_zero_assertion_detection_across_languages(self) -> None:
        # 1. TypeScript zero-assertion vs valid expect().rejects
        ts_bad = """
        it('processes refund without asserting', async () => {
            const client = new PaymentClient();
            await client.refund('ch_123');
        });
        """
        findings = scan_test_file(Path("src/payment.test.ts"), ts_bad)
        self.assertEqual([f.rule for f in findings], ["zero-assertion-test"])

        ts_good = """
        it('rejects duplicate refund', async () => {
            const client = new PaymentClient();
            await expect(client.refund('ch_123')).rejects.toThrow('Already refunded');
        });
        """
        self.assertEqual(scan_test_file(Path("src/payment.test.ts"), ts_good), [])

        # 2. Python zero-assertion vs valid pytest.raises
        py_bad = "\ndef test_sync_inventory():\n    svc = InventoryService()\n    svc.sync()\n"
        findings_py = scan_test_file(Path("tests/test_inventory.py"), py_bad)
        self.assertEqual([f.rule for f in findings_py], ["zero-assertion-test"])

        py_good = (
            "import pytest\n"
            "def test_sync_inventory_error():\n"
            "    svc = InventoryService()\n"
            "    with pytest.raises(RuntimeError):\n"
            "        svc.sync_invalid()\n"
        )
        self.assertEqual(scan_test_file(Path("tests/test_inventory.py"), py_good), [])

        # 3. Go zero-assertion vs t.Fatalf
        go_bad = (
            "package cache\nimport \"testing\"\n"
            "func TestEvict(t *testing.T) {\n    c := NewCache()\n    c.Evict(\"k\")\n}\n"
        )
        self.assertEqual([f.rule for f in scan_test_file(Path("cache_test.go"), go_bad)], ["zero-assertion-test"])

        # 4. Rust zero-assertion vs #[should_panic]
        rs_bad = "#[test]\nfn test_hash() {\n    let _ = compute_hash(b\"abc\");\n}\n"
        self.assertEqual([f.rule for f in scan_test_file(Path("tests/hash_test.rs"), rs_bad)], ["zero-assertion-test"])

        rs_panic = "#[test]\n#[should_panic]\nfn test_hash_empty() {\n    compute_hash(b\"\");\n}\n"
        self.assertEqual(scan_test_file(Path("tests/hash_test.rs"), rs_panic), [])

        # 5. Java zero-assertion
        java_bad = (
            "class AuthTest {\n"
            "    @Test\n"
            "    void loginUser() {\n"
            "        auth.login(\"u\", \"p\");\n"
            "    }\n"
            "}\n"
        )
        self.assertEqual([f.rule for f in scan_test_file(Path("src/test/AuthTest.java"), java_bad)], ["zero-assertion-test"])

    def test_tautological_assertions(self) -> None:
        ts_taut = """
        it('checks math', () => {
            const total = computeTotal();
            expect(total).toBe(total);
        });
        """
        findings = scan_test_file(Path("src/math.test.ts"), ts_taut)
        self.assertEqual([f.rule for f in findings], ["tautological-assertion"])

        # Single superficial existence check is flagged
        py_superficial = "def test_get_order():\n    order = fetch_order(1)\n    assert order is not None\n"
        findings_sup = scan_test_file(Path("tests/test_order.py"), py_superficial)
        self.assertEqual([f.rule for f in findings_sup], ["tautological-assertion"])

        # Existence check paired with concrete field assertion is clean
        py_thorough = (
            "def test_get_order():\n"
            "    order = fetch_order(1)\n"
            "    assert order is not None\n"
            "    assert order.total == 99.50\n"
        )
        self.assertEqual(scan_test_file(Path("tests/test_order.py"), py_thorough), [])

    def test_self_mocked_unit_under_test(self) -> None:
        # 1. Mocking the subject module in billing.test.ts
        ts_self_mock = """
        import { createInvoice } from './billing';
        vi.mock('./billing');
        it('creates invoice', () => {
            expect(createInvoice('cust_1')).toEqual({ id: 'inv_1' });
        });
        """
        findings = scan_test_file(Path("src/billing.test.ts"), ts_self_mock)
        self.assertIn("self-mocked-unit-under-test", {f.rule for f in findings})

        # 2. Patching the exact function under test in Python
        py_self_mock = (
            "from unittest.mock import patch\n"
            "from app.tax import calculate_vat\n\n"
            "@patch('app.tax.calculate_vat')\n"
            "def test_calculate_vat(mock_vat):\n"
            "    mock_vat.return_value = 20.0\n"
            "    assert calculate_vat(100.0) == 20.0\n"
        )
        findings_py = scan_test_file(Path("tests/test_tax.py"), py_self_mock)
        self.assertEqual([f.rule for f in findings_py], ["self-mocked-unit-under-test"])

    def test_evilgenie_cross_diff_special_casing(self) -> None:
        diff_text = """diff --git a/tests/test_tax.py b/tests/test_tax.py
new file mode 100644
--- /dev/null
+++ b/tests/test_tax.py
@@ -0,0 +1,3 @@
+def test_special_jurisdiction():
+    assert calculate_tax("TX-SPEC-99") == 14.25
diff --git a/src/tax.py b/src/tax.py
--- a/src/tax.py
+++ b/src/tax.py
@@ -5,3 +5,5 @@ def calculate_tax(code: str) -> float:
+    if code == "TX-SPEC-99":
+        return 14.25
     return lookup_rate(code)
"""
        findings = scan_diff_for_reward_hacking(diff_text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "test-input-special-casing")
        self.assertEqual(findings[0].path, "src/tax.py")
        self.assertIn("TX-SPEC-99", findings[0].message)

    def test_evilgenie_ignores_pins_in_requirements_files(self) -> None:
        diff_text = """diff --git a/tests/test_cli.py b/tests/test_cli.py
new file mode 100644
--- /dev/null
+++ b/tests/test_cli.py
@@ -0,0 +1,2 @@
+def test_sarif_version():
+    assert sarif_version() == "2.1.0"
diff --git a/requirements.txt b/requirements.txt
new file mode 100644
--- /dev/null
+++ b/requirements.txt
@@ -0,0 +1,1 @@
+py-serializable==2.1.0
"""
        self.assertEqual(scan_diff_for_reward_hacking(diff_text), [])

    def test_evilgenie_with_existing_repo_test_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_dir = root / "tests"
            test_dir.mkdir()
            (test_dir / "test_coupon.py").write_text(
                'def test_vip_discount():\n    assert apply_coupon("VIP-GOLD-2026") == 45.00\n',
                encoding="utf-8",
            )
            diff_text = """diff --git a/src/coupon.py b/src/coupon.py
--- a/src/coupon.py
+++ b/src/coupon.py
@@ -2,2 +2,4 @@ def apply_coupon(code: str) -> float:
+    if code == "VIP-GOLD-2026":
+        return 45.00
     return standard_discount(code)
"""
            findings = scan_diff_for_reward_hacking(diff_text, repo_root=root)
            self.assertEqual([f.rule for f in findings], ["test-input-special-casing"])

    def test_diff_assertion_weakening_and_deletion(self) -> None:
        # 1. Deleting an assertion from an existing test
        diff_deleted = """diff --git a/tests/test_api.py b/tests/test_api.py
--- a/tests/test_api.py
+++ b/tests/test_api.py
@@ -10,4 +10,3 @@ def test_create_user():
     res = client.post("/users", json={"name": "Alice"})
     assert res.status_code == 201
-    assert res.json()["name"] == "Alice"
"""
        findings_del = scan_diff_for_reward_hacking(diff_deleted)
        self.assertEqual([f.rule for f in findings_del], ["diff-assertion-weakening"])

        # 2. Relaxing strict status check to permissive check
        diff_relaxed = """diff --git a/tests/test_api.py b/tests/test_api.py
--- a/tests/test_api.py
+++ b/tests/test_api.py
@@ -10,3 +10,3 @@ def test_create_user():
     res = client.post("/users", json={"name": "Alice"})
-    assert res.status_code == 201
+    assert res.status_code in (200, 400, 500)
"""
        findings_rel = scan_diff_for_reward_hacking(diff_relaxed)
        self.assertEqual([f.rule for f in findings_rel], ["diff-assertion-weakening"])

    def test_config_exemptions_and_rule_aliases(self) -> None:
        cfg = PrufGateConfig(
            exempt={
                ("tests/test_legacy.py", "assertion-free-test"): "Legacy smoke test",
            }
        )
        py_bad = "def test_smoke():\n    run_smoke()\n"
        self.assertEqual(scan_test_file(Path("tests/test_legacy.py"), py_bad, config=cfg), [])

    def test_cli_json_out_and_synthesizer_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_file = root / "sample.test.ts"
            test_file.write_text(
                "it('hollow test', () => { const x = 1 + 1; });\n",
                encoding="utf-8",
            )
            raw_dir = root / "reports" / "raw"
            json_out = raw_dir / "test_integrity.json"

            rc = main([f"--json-out={json_out}", "--include-self", str(test_file)])
            self.assertEqual(rc, 1)
            self.assertTrue(json_out.is_file())

            data = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]["rule"], "zero-assertion-test")

            synth_findings = parse_raw_results(raw_dir)
            self.assertEqual(len(synth_findings), 1)
            self.assertEqual(synth_findings[0].tool, "test-integrity")
            self.assertEqual(synth_findings[0].rule_id, "zero-assertion-test")
            self.assertEqual(synth_findings[0].severity, "P0")


class TestRemovedTests(unittest.TestCase):
    """`diff-test-file-deleted` and `diff-test-count-drop`."""

    DELETED = """diff --git a/tests/test_refunds.py b/tests/test_refunds.py
deleted file mode 100644
--- a/tests/test_refunds.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def test_refund_rejects_closed_order():
-    assert refund(closed_order()) is False
"""

    def _rules(self, diff_text: str, cfg: PrufGateConfig | None = None) -> list[str]:
        return sorted(f.rule for f in scan_diff_for_reward_hacking(diff_text, config=cfg))

    def test_deleted_test_file_is_reported_once(self) -> None:
        findings = scan_diff_for_reward_hacking(self.DELETED)
        self.assertEqual([f.rule for f in findings], ["diff-test-file-deleted"])
        self.assertEqual(findings[0].severity, "P1")
        self.assertIn("exempt", findings[0].message)

    def test_rename_with_edits_is_not_a_deletion(self) -> None:
        diff_text = """diff --git a/tests/test_refunds.py b/tests/billing/test_refunds.py
similarity index 90%
rename from tests/test_refunds.py
rename to tests/billing/test_refunds.py
--- a/tests/test_refunds.py
+++ b/tests/billing/test_refunds.py
@@ -1,2 +1,2 @@
-from app import refund
+from app.billing import refund
 def test_refund_rejects_closed_order():
"""
        self.assertEqual(self._rules(diff_text), [])

    def test_unrecognised_language_moved_by_name_is_not_a_deletion(self) -> None:
        diff_text = """diff --git a/src/OrderTest.java b/src/OrderTest.java
deleted file mode 100644
--- a/src/OrderTest.java
+++ /dev/null
@@ -1,1 +0,0 @@
-class OrderTest {}
diff --git a/src/orders/OrderTest.java b/src/orders/OrderTest.java
new file mode 100644
--- /dev/null
+++ b/src/orders/OrderTest.java
@@ -0,0 +1,1 @@
+class OrderTest {}
"""
        self.assertEqual(self._rules(diff_text), [])
        self.assertEqual(self._rules(diff_text.split("diff --git a/src/orders")[0]), ["diff-test-file-deleted"])

    def test_tests_moved_into_an_uncollected_file_still_count_as_removed(self) -> None:
        moved = """diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,4 +1,2 @@
 import auth
-def test_login_rejects_bad_password():
-    assert not auth.login("u", "bad")
 x = 1
diff --git a/tests/auth_cases.py b/tests/auth_cases.py
new file mode 100644
--- /dev/null
+++ b/tests/auth_cases.py
@@ -0,0 +1,2 @@
+def test_login_rejects_bad_password():
+    assert not auth.login("u", "bad")
"""
        self.assertEqual(self._rules(moved), ["diff-test-count-drop"])
        # Moved into a file the runner collects: nothing lost.
        self.assertEqual(self._rules(moved.replace("auth_cases.py", "test_auth_cases.py")), [])
        # Moved within the same uncollected file: nothing lost.
        within = """diff --git a/tests/auth_cases.py b/tests/auth_cases.py
--- a/tests/auth_cases.py
+++ b/tests/auth_cases.py
@@ -1,3 +1,3 @@
-def test_login_rejects_bad_password():
-    assert not auth.login("u", "bad")
 x = 1
+def test_login_rejects_bad_password():
+    assert not auth.login("u", "bad")
"""
        self.assertEqual(self._rules(within), [])

    def test_python_unittest_method_removed_drops_count(self) -> None:
        diff_text = """diff --git a/tests/test_ledger.py b/tests/test_ledger.py
--- a/tests/test_ledger.py
+++ b/tests/test_ledger.py
@@ -5,4 +5,2 @@ class LedgerTest(unittest.TestCase):
     def test_balance(self):
         self.assertEqual(balance(), 0)
-    def test_overdraft(self):
-        pass
"""
        self.assertEqual(self._rules(diff_text), ["diff-test-count-drop"])

    def test_added_test_balances_removed_one(self) -> None:
        diff_text = """diff --git a/tests/test_ledger.py b/tests/test_ledger.py
--- a/tests/test_ledger.py
+++ b/tests/test_ledger.py
@@ -5,2 +5,2 @@
-def test_overdraft():
+def test_overdraft_is_rejected():
     assert withdraw(500) is None
"""
        self.assertEqual(self._rules(diff_text), [])

    RENAME = """diff --git a/tests/test_m.py b/tests/m_cases.py
similarity index 100%
rename from tests/test_m.py
rename to tests/m_cases.py
"""

    def test_rename_to_non_test_name_is_a_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "tests").mkdir()
            (Path(tmp) / "tests" / "m_cases.py").write_text("def test_a():\n    assert 1\n", encoding="utf-8")
            findings = scan_diff_for_reward_hacking(self.RENAME, repo_root=tmp)
        self.assertEqual([(f.rule, f.path) for f in findings], [("diff-test-file-deleted", "tests/test_m.py")])
        self.assertIn("test_a", findings[0].message)
        self.assertEqual(self._rules(self.RENAME), ["diff-test-file-deleted"])
        edited = self.RENAME.replace("similarity index 100%", "similarity index 90%") + (
            "--- a/tests/test_m.py\n+++ b/tests/m_cases.py\n@@ -1,2 +1,2 @@\n-def test_a():\n+def case_a():\n     assert 1\n"
        )
        self.assertEqual(self._rules(edited), ["diff-test-file-deleted"])

    def test_rename_between_test_names_or_into_tests_is_not_a_deletion(self) -> None:
        self.assertEqual(self._rules(self.RENAME.replace("tests/m_cases.py", "tests/test_n.py")), [])
        self.assertEqual(self._rules(self.RENAME.replace("tests/test_m.py", "tests/m_old.py")), [])

    def test_partly_moved_deleted_file_does_not_hide_other_drops(self) -> None:
        diff_text = """diff --git a/tests/test_a.py b/tests/test_a.py
deleted file mode 100644
--- a/tests/test_a.py
+++ /dev/null
@@ -1,3 +0,0 @@
-def test_1(): check(1)
-def test_2(): check(2)
-def test_3(): check(3)
diff --git a/tests/test_b.py b/tests/test_b.py
--- a/tests/test_b.py
+++ b/tests/test_b.py
@@ -1,2 +1,2 @@
-def test_4(): check(4)
-def test_5(): check(5)
+def test_1(): check(1)
+def test_2(): check(2)
"""
        self.assertEqual(self._rules(diff_text), ["diff-test-count-drop", "diff-test-file-deleted"])

    def test_exempt_file_does_not_hide_another_files_drop(self) -> None:
        diff_text = """diff --git a/tests/test_a.py b/tests/test_a.py
--- a/tests/test_a.py
+++ b/tests/test_a.py
@@ -1,2 +1,0 @@
-def test_1(): check(1)
-def test_2(): check(2)
diff --git a/tests/test_b.py b/tests/test_b.py
--- a/tests/test_b.py
+++ b/tests/test_b.py
@@ -1,1 +1,0 @@
-def test_3(): check(3)
"""
        cfg = PrufGateConfig(exempt={("tests/test_a.py", "diff-test-count-drop"): "#9: retired"})
        findings = scan_diff_for_reward_hacking(diff_text, config=cfg)
        self.assertEqual([(f.rule, f.path) for f in findings], [("diff-test-count-drop", "tests/test_b.py")])
        self.assertEqual(self._rules(diff_text.split("diff --git a/tests/test_b.py")[0], cfg), [])

    def test_tests_in_comments_or_strings_are_not_added_back(self) -> None:
        q3 = "'" * 3
        for path, removed, added in (
            ("tests/test_l.py", "def test_overdraft():", ('"""', "def test_overdraft():", '"""')),
            ("tests/test_l.py", "def test_overdraft():", (f"X = {q3}", "def test_overdraft():", q3)),
            ("src/cart.test.ts", "it('rejects', () => {});", ("/*", "it('rejects', () => {});", "*/")),
            ("src/cart.test.ts", "it('rejects', () => {});", ("const s = `", "it('rejects', () => {});", "`;")),
            ("pkg/l_test.go", "func TestOverdraft(t *testing.T) {}", ("/*", "func TestOverdraft(t *testing.T) {}", "*/")),
        ):
            body = f"-{removed}\n" + "".join(f"+{a}\n" for a in added)
            diff_text = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,{len(added)} @@\n{body}"
            with self.subTest(path=path, added=added):
                self.assertEqual(self._rules(diff_text), ["diff-test-count-drop"])
        real = "diff --git a/tests/test_l.py b/tests/test_l.py\n--- a/tests/test_l.py\n+++ b/tests/test_l.py\n"
        real += '@@ -1,1 +1,3 @@\n-def test_overdraft():\n+"""doc"""\n+def test_overdraft():  # moved\n+    check()\n'
        self.assertEqual(self._rules(real), [])

    def test_exemptions_acknowledge_intended_removal(self) -> None:
        cfg = PrufGateConfig(exempt={("tests/test_refunds.py", "diff-test-file-deleted"): "#7: refunds removed"})
        self.assertEqual(self._rules(self.DELETED, cfg), [])
        excluded = PrufGateConfig(exclude=["tests/test_refunds.py"])
        self.assertEqual(self._rules(self.DELETED, excluded), [])


if __name__ == "__main__":
    unittest.main()
