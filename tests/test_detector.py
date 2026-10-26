"""Anti-fabrication detector: self-check, project settings and the full sweep."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DETECTOR = Path(__file__).resolve().parent.parent / "prufgate" / "anti_fabrication" / "detector.py"

FABRICATED = "export const SAMPLE_FEED = [{ ip: '198.51.100.7' }];\n"


def run(cwd, *args):
    p = subprocess.run([sys.executable, str(DETECTOR), *args], cwd=cwd,
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


class DetectorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "src").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def settings(self, data):
        (self.repo / ".prufgate").mkdir(exist_ok=True)
        (self.repo / ".prufgate" / "fabrication.json").write_text(json.dumps(data))

    def test_self_check(self):
        code, out = run(self.repo, "--self-check")
        self.assertEqual(code, 0, out)

    def test_clean_repo_full_sweep_writes_json(self):
        # Regression: --json-out crashed (json not imported), and a full sweep
        # reported exemptions belonging to another project as stale findings.
        (self.repo / "src" / "ok.ts").write_text("export const x = 1;\n")
        code, out = run(self.repo, "--json-out=out/report.json")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads((self.repo / "out" / "report.json").read_text()), [])

    def test_finding_is_reported(self):
        (self.repo / "src" / "feed.ts").write_text(FABRICATED)
        code, out = run(self.repo, "--json-out=r.json")
        self.assertNotIn("demo-named-data", out)  # a low-confidence rule: off by default
        self.settings({"enable_low_confidence": True})
        code, out = run(self.repo, "--json-out=r.json")
        self.assertEqual(code, 1, out)
        rules = {f["rule"] for f in json.loads((self.repo / "r.json").read_text())}
        self.assertIn("demo-named-data", rules)

    def test_exemption_with_reason(self):
        (self.repo / "src" / "feed.ts").write_text(FABRICATED)
        self.settings({"exempt": [
            {"path": "src/feed.ts", "rule": "demo-named-data", "reason": "an example shown as an example"},
            {"path": "src/feed.ts", "rule": "documentation-address", "reason": "same example"},
        ]})
        code, out = run(self.repo)
        self.assertEqual(code, 0, out)

    def test_stale_exemption_fails_full_sweep(self):
        (self.repo / "src" / "ok.ts").write_text("export const x = 1;\n")
        self.settings({"exempt": [{"path": "src/gone.ts", "rule": "demo-named-data", "reason": "was here"}]})
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("stale-exemption", out)

    def test_known_debt_needs_issue(self):
        self.settings({"known_debt": [{"path": "src/a.ts", "rule": "r", "reason": "later"}]})
        code, out = run(self.repo)
        self.assertEqual(code, 2, out)

    def test_unknown_settings_key(self):
        self.settings({"exempts": []})
        code, out = run(self.repo)
        self.assertEqual(code, 2, out)
        self.assertIn("unknown key", out)

    def test_explicit_missing_config(self):
        code, _ = run(self.repo, "--config=nope.json")
        self.assertEqual(code, 2)

    def test_score_owner_is_opt_in(self):
        (self.repo / "src" / "enrich.ts").write_text("result.reputation = computed;\n")
        self.assertEqual(run(self.repo)[0], 0)
        self.settings({"score_owners": ["src/scoring.ts"]})
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("score-outside-scoring", out)

    def test_model_wrapper_pattern(self):
        prompt = ('import { generate } from "@/lib/llm";\n'
                  'generate({ prompt: `Return JSON: { "verdict": "Malicious" | "Clean" }` });\n')
        (self.repo / "src" / "triage.ts").write_text(prompt)
        self.assertEqual(run(self.repo)[0], 0)
        self.settings({"model_call_patterns": [r"@/lib/llm"]})
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("prompt-invents-finding", out)

    def test_inline_prufgate_ignore_comment_suppression(self):
        (self.repo / "src" / "feed.ts").write_text(
            "export const SAMPLE_FEED = [{ ip: '198.51.100.7' }]; "
            "// prufgate-ignore: demo-named-data, documentation-address -- documented example feed\n"
        )
        code, out = run(self.repo)
        self.assertEqual(code, 0, out)

    def test_inline_prufgate_ignore_without_reason_suppresses_nothing(self):
        (self.repo / "src" / "feed.ts").write_text(
            "export const SAMPLE_FEED = [{ ip: '198.51.100.7' }]; // prufgate-ignore: demo-named-data, documentation-address\n"
        )
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("demo-named-data", out)

    def test_js_and_jsx_files_are_scanned(self):
        (self.repo / "src" / "widget.jsx").write_text(
            "export const MOCK_ALERTS = [{ ip: '198.51.100.7' }];\n"
        )
        self.settings({"enable_low_confidence": True})
        code, out = run(self.repo, "--json-out=r.json")
        self.assertEqual(code, 1, out)
        rules = {f["rule"] for f in json.loads((self.repo / "r.json").read_text())}
        self.assertIn("demo-named-data", rules)


if __name__ == "__main__":
    unittest.main()


class ErrorPathShapesTest(unittest.TestCase):
    """Error paths answered with a hard-coded success, swallowed errors, and admitted fakes."""

    @staticmethod
    def _rules(rel: str, src: str) -> set[str]:
        sys.path.insert(0, str(DETECTOR.parent.parent.parent))
        from prufgate.anti_fabrication import detector

        detector.apply_settings({})
        return {f.rule for f in detector.scan_text(rel, Path(rel).suffix, src)}

    def test_python_and_go_error_path_success(self):
        py = "def f():\n    try:\n        r = g()\n    except Exception:\n        return {\"valid\": True}\n    return r\n"
        self.assertIn("canned-error-fallback", self._rules("app/f.py", py))
        self.assertNotIn("canned-error-fallback", self._rules("app/f.py", py.replace("True", "False")))
        go = "func F() (bool, error) {\n\tok, err := g()\n\tif err != nil {\n\t\treturn true, nil\n\t}\n\treturn ok, nil\n}\n"
        self.assertIn("canned-error-fallback", self._rules("pkg/f.go", go))
        self.assertNotIn("canned-error-fallback", self._rules("pkg/f.go", go.replace("return true, nil\n\t}", "return false, err\n\t}")))

    def test_python_handler_ends_at_its_dedent(self):
        src = ("def f():\n    try:\n        g()\n    except Exception:\n        raise\n"
               "    return {\"ok\": True}\n")
        self.assertEqual(self._rules("app/f.py", src) & {"canned-error-fallback", "unhandled-empty-catch"}, set())

    def test_broad_except_pass(self):
        for head in ("except:", "except Exception:", "except BaseException as exc:"):
            src = f"def f():\n    try:\n        g()\n    {head}\n        pass  # keep going\n"
            self.assertIn("unhandled-empty-catch", self._rules("app/f.py", src), head)
        narrow = "def f():\n    try:\n        g()\n    except KeyError:\n        pass\n"
        self.assertNotIn("unhandled-empty-catch", self._rules("app/f.py", narrow))

    def test_broad_except_tuple_and_comment_inside_handler(self):
        for head in ("except (Exception,):", "except (ValueError, Exception) as exc:", "except(BaseException):"):
            src = f"def f():\n    try:\n        g()\n    {head}\n        pass\n"
            self.assertIn("unhandled-empty-catch", self._rules("app/f.py", src), head)
        narrow = "def f():\n    try:\n        g()\n    except (KeyError, ValueError):\n        pass\n"
        self.assertNotIn("unhandled-empty-catch", self._rules("app/f.py", narrow))
        canned = "def f():\n    try:\n        r = g()\n    except (Exception,):\n        return {\"valid\": True}\n    return r\n"
        self.assertIn("canned-error-fallback", self._rules("app/f.py", canned))
        # An unindented comment inside the handler does not end it.
        dedent = "def f():\n    try:\n        r = g()\n    except Exception:\n# fallback\n        return {\"valid\": True}\n    return r\n"
        self.assertIn("canned-error-fallback", self._rules("app/f.py", dedent))

    def test_broad_except_pass_in_cleanup_function_is_not_reported(self):
        for name in ("close(conn)", "__exit__(self, *exc)", "_shutdown_pool(p)", "tearDown(self)", "close_all(c)"):
            src = f"def {name}:\n    try:\n        conn.close()\n    except Exception:  # best effort on shutdown\n        pass\n"
            self.assertNotIn("unhandled-empty-catch", self._rules("app/f.py", src), name)
        for name in ("closest(conn)", "load(conn)"):
            src = f"def {name}:\n    try:\n        conn.close()\n    except Exception:  # best effort\n        pass\n"
            self.assertIn("unhandled-empty-catch", self._rules("app/f.py", src), name)

    def test_simulated_dict_sleep_status_and_prose_prompt(self):
        sim = 'def f(a):\n    # simulated until the API is wired up\n    return {"id": a, "total": 12}\n'
        self.assertIn("simulated-return-value", self._rules("app/f.py", sim))
        self.assertNotIn("simulated-return-value", self._rules("app/f.py", sim.replace("simulated", "cached")))
        delay = 'def f():\n    time.sleep(1)\n    return {"status": "done"}\n'
        self.assertIn("synthetic-delay-mock", self._rules("app/f.py", delay))
        prompt = ('from openai import OpenAI\n'
                  'p = f"Return a verdict for {x}."\nclient.chat.completions.create(messages=[p])\n')
        self.assertIn("prompt-invents-finding", self._rules("app/f.py", prompt))
        self.assertNotIn("prompt-invents-finding", self._rules("app/f.py", prompt.replace("a verdict", "a summary")))
