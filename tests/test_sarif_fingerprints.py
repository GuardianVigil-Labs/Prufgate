"""SARIF partialFingerprints (prufgate/sarif.py) and their use by every SARIF writer."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from prufgate.cli import _format_sarif_findings
from prufgate.cli import main as cli_main
from prufgate.review.reviewer import PRComment, format_review_sarif
from prufgate.sarif import add_partial_fingerprints, line_hashes
from prufgate.synthesizer.parse_results import Finding, generate_sarif

SOURCE = "def handler(request):\n    token = request.args['t']\n    return lookup(token)\n"


def _result(rule: str, uri: str, line: int, message: str = "m") -> dict:
    return {
        "ruleId": rule,
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}],
    }


def _fingerprints(results: list[dict], root: Path | None) -> list[dict]:
    add_partial_fingerprints(results, root)
    return [r["partialFingerprints"] for r in results]


class LineHashMatchesUploadAction(unittest.TestCase):
    """Vectors from github/codeql-action's own fingerprint tests."""

    def _ordered(self, text: str) -> list[str]:
        hashes = line_hashes(text)
        return [hashes[n] for n in sorted(hashes)]

    def test_empty_file(self):
        self.assertEqual(self._ordered(""), ["c129715d7a2bc9a3:1"])

    def test_whitespace_and_line_endings(self):
        expected = [
            "e9496ae3ebfced30:1", "fb7c023a8b9ccb3f:1", "ce8ba1a563dcdaca:1", "e20e36e16fcb0cc8:1",
            "b3edc88f2938467e:1", "c8e28b0b4002a3a0:1", "c129715d7a2bc9a3:1",
        ]
        for text in (
            " hello; \t\nworld!!!\n\n\n  \t\tGreetings\n End\n",
            " hello; \t\r\nworld!!!\r\n\r\n\r\n  \t\tGreetings\r\n End\r\n",
            " hello; \t\nworld!!!\r\r\r  \t\tGreetings\r End\r",
        ):
            self.assertEqual(self._ordered(text), expected)

    def test_repeated_lines_get_occurrence_counter(self):
        hashes = self._ordered("Lorem ipsum dolor sit amet.\n" * 10)
        self.assertEqual(hashes[:3], ["a7f2ff13bc495cf2:1", "a7f2ff13bc495cf2:2", "a7f2ff13bc495cf2:3"])
        self.assertEqual(len(set(hashes)), len(hashes))


class PartialFingerprints(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "app.py").write_text(SOURCE, encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_stable_when_lines_are_inserted_above(self):
        before = _fingerprints([_result("r1", "app.py", 2)], self.root)[0]
        (self.root / "app.py").write_text("import os\n\n# a comment\n" + SOURCE, encoding="utf-8")
        after = _fingerprints([_result("r1", "app.py", 5)], self.root)[0]
        self.assertEqual(before, after)

    def test_differs_by_rule_and_by_code(self):
        same_line = _fingerprints([_result("r1", "app.py", 2), _result("r2", "app.py", 2)], self.root)
        self.assertNotEqual(same_line[0]["prufgateFindingHash/v1"], same_line[1]["prufgateFindingHash/v1"])
        other_code = _fingerprints([_result("r1", "app.py", 3)], self.root)[0]
        self.assertNotEqual(same_line[0]["primaryLocationLineHash"], other_code["primaryLocationLineHash"])

    def test_identical_lines_are_distinct(self):
        (self.root / "dup.py").write_text("x = secret()\n" * 3, encoding="utf-8")
        fps = _fingerprints([_result("r1", "dup.py", n) for n in (1, 2, 3)], self.root)
        self.assertEqual(len({f["primaryLocationLineHash"] for f in fps}), 3)
        self.assertEqual(len({f["prufgateFindingHash/v1"] for f in fps}), 3)

    def test_missing_location_is_deterministic(self):
        def run() -> list[dict]:
            return _fingerprints(
                [
                    _result("bola", "PRUFGATE_DYNAMIC_TARGET", 1, "idor"),
                    _result("bola", "PRUFGATE_DYNAMIC_TARGET", 1, "idor"),
                    _result("r1", "gone.py", 7),
                    _result("r1", "app.py", 999),
                    {"ruleId": "no-location", "message": {"text": "x"}},
                ],
                self.root,
            )

        first = run()
        self.assertEqual(first, run())
        self.assertNotEqual(first[0], first[1])
        self.assertTrue(all(f["primaryLocationLineHash"] for f in first))
        # The fallback ignores the line, so it survives line shifts as well.
        self.assertEqual(_fingerprints([_result("r1", "gone.py", 9)], self.root)[0], first[2])

    def test_file_outside_root_is_not_read(self):
        outside = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        self.addCleanup(Path(outside.name).unlink)
        outside.write(SOURCE)
        outside.close()
        (self.root / "link.py").symlink_to(outside.name)
        inside = _fingerprints([_result("r1", "app.py", 1)], self.root)[0]
        linked = _fingerprints([_result("r1", "link.py", 1)], self.root)[0]
        self.assertNotEqual(inside["primaryLocationLineHash"], linked["primaryLocationLineHash"])
        self.assertNotIn(line_hashes(SOURCE)[1], linked["primaryLocationLineHash"])


class EveryWriterAddsFingerprints(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "app.py").write_text(SOURCE, encoding="utf-8")
        self.expected = line_hashes(SOURCE)[2]

    def tearDown(self):
        self._tmp.cleanup()

    @staticmethod
    def _line_hash(sarif: dict) -> str:
        return sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]

    def test_synthesizer(self):
        out = self.root / "reports" / "prufgate.sarif"
        out.parent.mkdir()
        generate_sarif([Finding("anti-fabrication", "r1", "P1", "msg", str(self.root / "app.py"), 2)], out, self.root)
        self.assertEqual(self._line_hash(json.loads(out.read_text(encoding="utf-8"))), self.expected)

    def test_check_format(self):
        finding = {"rule": "r1", "severity": "P1", "engine": "e", "message": "m", "file": "app.py", "line": 2}
        self.assertEqual(self._line_hash(json.loads(_format_sarif_findings([finding], self.root))), self.expected)

    def test_check_single_file(self):
        src = "test('fake test', () => {\n  const x = 1 + 1;\n});\n"
        (self.root / "bad.test.ts").write_text(src, encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            cli_main(["check", str(self.root / "bad.test.ts"), "--format", "sarif"])
        self.assertEqual(self._line_hash(json.loads(out.getvalue())), line_hashes(src)[1])

    def test_review_format(self):
        comment = PRComment(file_path="app.py", line=2, severity="P1", title="Title", message="m")
        self.assertEqual(self._line_hash(json.loads(format_review_sarif([comment], self.root))), self.expected)


if __name__ == "__main__":
    unittest.main()
