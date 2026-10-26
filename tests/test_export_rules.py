"""`prufgate export-rules --format semgrep`: valid rules YAML, regexes that agree with
the engine on each rule's own fixtures, and every PrufGate rule either exported or
listed as skipped with a reason."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from prufgate import export_rules as ex
from prufgate.anti_fabrication import detector as af
from prufgate.config import expand_rule_aliases
from prufgate.rules import CONFIDENCE

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "prufgate" / "cli.py"
SEMGREP = shutil.which("semgrep") or shutil.which("opengrep")
REQUIRED = {"id", "message", "severity", "languages", "metadata"}


def flags(rule: dict, line: str) -> bool:
    """Semgrep's semantics on one line, with Python `re`: the regex matches and no
    pattern-not-regex overlaps it (every not-regex here spans a whole line)."""
    pats = rule["patterns"]
    positive = [p["pattern-regex"] for p in pats if "pattern-regex" in p]
    negative = [p["pattern-not-regex"] for p in pats if "pattern-not-regex" in p]
    return all(re.search(p, line) for p in positive) and not any(re.search(n, line) for n in negative)


class ExportRulesTest(unittest.TestCase):
    def doc(self, packs=("cti",)):
        return yaml.safe_load(ex.render(packs))

    def test_yaml_has_the_required_keys(self):
        rules = self.doc()["rules"]
        self.assertEqual(len(rules), len(ex.EXPORTED))
        for rule in rules:
            self.assertLessEqual(REQUIRED, set(rule), rule["id"])
            self.assertTrue(rule["id"].startswith("prufgate."))
            self.assertIn(rule["severity"], {"ERROR", "WARNING", "INFO"})
            self.assertEqual(rule["languages"], ["regex"])
            meta = rule["metadata"]
            self.assertEqual(meta["prufgate-rule-id"], rule["id"][len("prufgate."):])
            self.assertIn(meta["confidence"], {"high", "medium"})
            self.assertEqual(meta["license"], "Apache-2.0")
            self.assertTrue(meta["source"].endswith("docs/ENGINES.md#engine-1-anti-fabrication"))

    def test_severity_map(self):
        self.assertEqual(ex.SEVERITY, {"P0": "ERROR", "P1": "ERROR", "P2": "WARNING", "P3": "INFO"})

    def test_output_is_sorted_and_stable(self):
        self.assertEqual(ex.render(("cti",)), ex.render(("cti",)))
        ids = [r["id"] for r in self.doc()["rules"]]
        self.assertEqual(ids, sorted(ids))

    def test_cti_pack_is_opt_in(self):
        ids = {r["id"] for r in self.doc(())["rules"]}
        self.assertNotIn("prufgate.hardcoded-cve", ids)
        self.assertIn("prufgate.documentation-address", ids)
        self.assertIn("hardcoded-cve", ex.skipped(()))

    def test_every_regex_compiles(self):
        for rule in self.doc()["rules"]:
            for p in rule["patterns"]:
                self.assertIsInstance(re.compile(next(iter(p.values()))), re.Pattern)

    def test_each_rule_flags_its_fixture_and_not_its_near_miss(self):
        rules = {r["metadata"]["prufgate-rule-id"]: r for r in self.doc()["rules"]}
        for rule_id, *_, positive, near_miss in ex.EXPORTED:
            with self.subTest(rule_id):
                self.assertTrue(flags(rules[rule_id], positive), positive)
                self.assertFalse(flags(rules[rule_id], near_miss), near_miss)
                self.assertFalse(flags(rules[rule_id], "// " + positive), "comment lines are skipped")

    def test_the_engine_agrees_on_the_fixtures(self):
        """The exported regex and the detector flag the same fixture lines."""
        with mock.patch.object(af, "ACTIVE_PACKS", {"cti"}):
            for rule_id, _pack, _p, _n, suffixes, *_, positive, near_miss in ex.EXPORTED:
                suffix = ".tsx" if ".tsx" in suffixes else suffixes[0]
                with self.subTest(rule_id):
                    hit = {f.rule for f in af.scan_text("src/app/page" + suffix, suffix, positive)}
                    miss = {f.rule for f in af.scan_text("src/app/page" + suffix, suffix, near_miss)}
                    self.assertIn(rule_id, hit)
                    self.assertNotIn(rule_id, miss)

    def test_every_rule_is_exported_or_skipped_with_a_reason(self):
        names = {r[0] for r in ex.EXPORTED} | set(ex.SKIPPED)
        for rule_id in CONFIDENCE:
            with self.subTest(rule_id):
                self.assertTrue(expand_rule_aliases(rule_id) & names, f"{rule_id}: export it or say why not")
        for rule_id, reason in ex.skipped(()).items():
            self.assertTrue(reason.strip(), rule_id)
            self.assertIn(f"#   {rule_id}: {reason}", ex.render(()))

    def test_cli_writes_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "prufgate.yaml"
            p = subprocess.run([sys.executable, str(CLI), "export-rules", "--format", "semgrep", "--out", str(out)],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(out.read_text(encoding="utf-8"), ex.render(()))

    def test_cli_refuses_an_unknown_format(self):
        p = subprocess.run([sys.executable, str(CLI), "export-rules", "--format", "sonar"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2)

    def test_cli_unwritable_out_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run([sys.executable, str(CLI), "export-rules", "--out", str(Path(tmp) / "no" / "x.yaml")],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 2)

    @unittest.skipUnless(SEMGREP, "#59: neither semgrep nor opengrep is installed here")
    def test_semgrep_validates_the_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.yaml"
            out.write_text(ex.render(("cti",)), encoding="utf-8")
            p = subprocess.run([SEMGREP, "--validate", "--metrics=off", "--config", str(out)],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
