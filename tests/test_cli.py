import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from prufgate.cli import main as cli_main
from prufgate.config import PrufGateConfig


class TestPrufGateCLI(unittest.TestCase):
    def test_self_check_subcommand(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--self-check"])
        self.assertEqual(rc, 0)
        self.assertIn("all 6 core engines passed", buf.getvalue())

    def test_init_and_hooks_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["init", str(ws), "--hooks"])
            self.assertEqual(rc, 0)

            cfg_file = ws / ".prufgate" / "config.yaml"
            claude_file = ws / ".claude" / "settings.json"
            cursor_file = ws / ".cursor" / "rules" / "prufgate-guardrails.mdc"
            precommit_file = ws / ".pre-commit-config.yaml"

            self.assertTrue(cfg_file.is_file())
            self.assertTrue(claude_file.is_file())
            self.assertTrue(cursor_file.is_file())
            self.assertTrue(precommit_file.is_file())

            # Verify generated .prufgate/config.yaml parses cleanly via PrufGateConfig.load
            loaded_cfg = PrufGateConfig.load(ws)
            self.assertEqual(loaded_cfg.version, 1)
            self.assertIn("core", loaded_cfg.packs)

            # Verify Claude Stop hook command
            claude_data = json.loads(claude_file.read_text(encoding="utf-8"))
            stop_hooks = claude_data["hooks"]["Stop"]
            self.assertEqual(len(stop_hooks), 1)
            self.assertIn(
                "prufgate check --changed --format agent-hook",
                stop_hooks[0]["hooks"][0]["command"],
            )

    def test_check_clean_and_violation_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "service.py").write_text(
                "def compute_total(items: list[int]) -> int:\n"
                "    return sum(items)\n",
                encoding="utf-8",
            )
            out_clean = io.StringIO()
            with redirect_stdout(out_clean):
                rc_clean = cli_main(["check", str(ws)])
            self.assertEqual(rc_clean, 0)

            # Add a zero-assertion test and undeclared import
            (ws / "package.json").write_text(json.dumps({"dependencies": {}}), encoding="utf-8")
            (ws / "bad.ts").write_text("import 'ghost-hallucinated-pkg';\n", encoding="utf-8")
            (ws / "bad.test.ts").write_text(
                "test('fake test', () => {\n  const x = 1 + 1;\n});\n",
                encoding="utf-8",
            )

            # 1. JSON format
            out_json = io.StringIO()
            with redirect_stdout(out_json):
                rc_json = cli_main(["check", str(ws), "--format", "json"])
            self.assertEqual(rc_json, 1)
            findings = json.loads(out_json.getvalue())
            rules = {f["rule"] for f in findings}
            self.assertIn("undeclared-or-hallucinated-import", rules)
            self.assertIn("zero-assertion-test", rules)

            # 2. SARIF format
            out_sarif = io.StringIO()
            with redirect_stdout(out_sarif):
                rc_sarif = cli_main(["check", str(ws), "--format", "sarif"])
            self.assertEqual(rc_sarif, 1)
            sarif = json.loads(out_sarif.getvalue())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 2)

            # 3. Agent Stop Hook format (exits 2 and writes remediation to stderr)
            err_hook = io.StringIO()
            # The hook reads the agent's JSON payload on stdin; give it one so the
            # test never blocks on the runner's own stdin.
            with redirect_stderr(err_hook), patch("sys.stdin", io.StringIO("{}")):
                rc_hook = cli_main(["check", str(ws), "--format", "agent-hook"])
            self.assertEqual(rc_hook, 2)
            self.assertIn("PrufGate Agent Guardrail blocked completion", err_hook.getvalue())

    def test_bola_and_review_subcommands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "routes.ts").write_text(
                "app.get('/api/items/:id', async (req, res) => {\n"
                "  return res.json(await prisma.item.findUnique({ where: { id: req.params.id } }));\n"
                "});\n",
                encoding="utf-8",
            )
            out_bola = io.StringIO()
            with redirect_stdout(out_bola):
                rc_bola = cli_main(["bola", str(ws), "--static-only", "--format", "json"])
            self.assertEqual(rc_bola, 1)
            bola_items = json.loads(out_bola.getvalue())
            self.assertEqual(len(bola_items), 1)
            self.assertEqual(bola_items[0]["rule_id"], "static-bola-unscoped-access")

            diff_file = ws / "sample.diff"
            diff_file.write_text(
                "diff --git a/src/query.ts b/src/query.ts\n"
                "--- a/src/query.ts\n"
                "+++ b/src/query.ts\n"
                "@@ -1,1 +1,2 @@\n"
                "+db.query(`SELECT * FROM accounts WHERE id = ${req.query.id}`);\n",
                encoding="utf-8",
            )
            out_rev = io.StringIO()
            with redirect_stdout(out_rev):
                rc_rev = cli_main(
                    ["review", f"--workspace={ws}", f"--diff-file={diff_file}", "--format=json"]
                )
            self.assertEqual(rc_rev, 1)  # a P0 comment fails the review
            rev_items = json.loads(out_rev.getvalue())
            self.assertEqual(len(rev_items), 1)
            self.assertEqual(rev_items[0]["title"], "SQL Injection Vector")


if __name__ == "__main__":
    unittest.main()
